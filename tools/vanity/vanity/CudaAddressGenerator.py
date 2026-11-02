import multiprocessing
import os
import secrets
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from time import perf_counter

from mnemonic import Mnemonic
from symbolchain.Bip32 import Bip32
from symbolchain.CryptoTypes import PrivateKey

from .AddressGenerator import AddressGenerator
from .WalletScanner import scan_wallets, snapshot_search


class CudaAddressGenerator(AddressGenerator):
	"""Pipelines CUDA seed generation with independent CPU account scanning processes."""

	def __init__(self, facade, max_wallet_accounts, key_pair_acceptor, seed_generator):
		super().__init__(facade, max_wallet_accounts, key_pair_acceptor)
		self.seed_generator = seed_generator
		self.batch_size = 1024
		self.workers = os.cpu_count() or 1
		self.stats_monitor = None

	def match_all(self, matcher):
		"""Matches all patterns, keeping at most one additional seed batch in flight."""

		if self.batch_size <= 0 or self.workers <= 0:
			raise ValueError('batch size and worker count must be positive')
		if matcher.is_complete:
			return

		# Spawn fresh interpreters so CPU workers never inherit a live CUDA context.
		with ProcessPoolExecutor(max_workers=self.workers, mp_context=multiprocessing.get_context('spawn')) as executor:
			with ThreadPoolExecutor(max_workers=1) as producer:
				pending_batch = producer.submit(self._generate_batch)
				try:
					while not matcher.is_complete:
						started = perf_counter()
						mnemonics, seeds = pending_batch.result()
						seed_wait = perf_counter() - started
						pending_batch = producer.submit(self._generate_batch)
						self._scan_batch(executor, matcher, mnemonics, seeds)
						if self.stats_monitor:
							self.stats_monitor(
								f'CUDA batch: {len(seeds)} wallets; seed wait {seed_wait:.3f}s; '
								f'CPU scan {perf_counter() - started - seed_wait:.3f}s')
				finally:
					pending_batch.cancel()

	def _generate_batch(self):
		factory = Mnemonic('english')
		mnemonics = [factory.to_mnemonic(secrets.token_bytes(32)) for _ in range(self.batch_size)]
		seeds = self.seed_generator.generate(mnemonics)
		if len(seeds) != len(mnemonics):
			raise RuntimeError('CUDA returned an unexpected number of seeds')
		return mnemonics, seeds

	def _scan_batch(self, executor, matcher, mnemonics, seeds):
		configuration = (
			'symbol' if 'ed25519' == self.facade.BIP32_CURVE_NAME else 'nem', self.facade.network.name, self.max_wallet_accounts)
		search = snapshot_search(matcher)
		indexed_seeds = list(enumerate(seeds))
		futures = [
			executor.submit(scan_wallets, configuration, indexed_seeds[offset:offset + 64], search)
			for offset in range(0, len(seeds), 64)
		]
		try:
			for future in as_completed(futures):
				for wallet_index, account_index, private_key in future.result():
					key_pair = self.facade.KeyPair(PrivateKey(private_key))
					if matcher.accept(key_pair)[1]:
						self._export_verified(mnemonics[wallet_index], account_index, key_pair)
					if matcher.is_complete:
						return
		finally:
			for future in futures:
				future.cancel()

	def _export_verified(self, mnemonic, account_index, key_pair):
		# Recompute independently from the mnemonic on the CPU before exporting keys.
		root = Bip32(self.facade.BIP32_CURVE_NAME).from_mnemonic(mnemonic, '')
		verified = self.facade.bip32_node_to_key_pair(root.derive_path(self.facade.bip32_path(account_index)))
		if key_pair.private_key != verified.private_key or key_pair.public_key != verified.public_key:
			raise RuntimeError('CUDA result does not match the mnemonic-derived account')
		self.key_pair_acceptor(mnemonic, verified)
