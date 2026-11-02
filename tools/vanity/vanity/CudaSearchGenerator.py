import secrets
from collections import namedtuple
from time import perf_counter

from mnemonic import Mnemonic
from symbolchain.Bip32 import Bip32
from symbolchain.CryptoTypes import PublicKey

Candidate = namedtuple('Candidate', ['public_key'])


class CudaSearchGenerator:
	"""Searches entirely on CUDA, verifying and exporting only selected accounts on the CPU."""

	def __init__(self, facade, max_wallet_accounts, key_pair_acceptor, backend):
		self.facade = facade
		self.max_wallet_accounts = max_wallet_accounts
		self.key_pair_acceptor = key_pair_acceptor
		self.backend = backend
		self.batch_size = 16384
		self.stats_monitor = None

	def match_all(self, matcher):
		"""Runs GPU batches until every literal pattern has a verified account."""

		if self.batch_size <= 0:
			raise ValueError('batch size must be positive')
		factory = Mnemonic('english')
		while not matcher.is_complete:
			started = perf_counter()
			entropy = secrets.token_bytes(32 * self.batch_size)
			search = (matcher.max_offset, tuple(
				(descriptor.search_string, descriptor.best_match_size) for descriptor in matcher.descriptors if not descriptor.has_match))
			candidates = self.backend.search_entropy(entropy, self.facade, self.max_wallet_accounts, search)
			for wallet_index, account_index, public_key, address in candidates:
				if not 0 <= wallet_index < self.batch_size or not 0 <= account_index < self.max_wallet_accounts:
					raise RuntimeError('CUDA returned an invalid account index')
				candidate = Candidate(PublicKey(public_key))
				if str(self.facade.network.public_key_to_address(candidate.public_key)) != address:
					raise RuntimeError('CUDA address does not match the public key')
				if matcher.accept(candidate)[1]:
					mnemonic = factory.to_mnemonic(entropy[wallet_index * 32:(wallet_index + 1) * 32])
					self._export_verified(mnemonic, account_index, candidate)
				if matcher.is_complete:
					break
			if self.stats_monitor:
				elapsed = perf_counter() - started
				timing = self.backend.last_timings
				self.stats_monitor(
					f'CUDA batch: {self.batch_size} wallets; GPU prepare {timing.get("prepare", 0):.3f}s; GPU seed {timing["seed"]:.3f}s; '
					f'GPU derive {timing["derive"]:.3f}s; GPU scan {timing["scan"]:.3f}s; '
					f'total {elapsed:.3f}s; {self.batch_size * self.max_wallet_accounts / elapsed:.0f} addresses/s')

	def _export_verified(self, mnemonic, account_index, candidate):
		root = Bip32(self.facade.BIP32_CURVE_NAME).from_mnemonic(mnemonic, '')
		key_pair = self.facade.bip32_node_to_key_pair(root.derive_path(self.facade.bip32_path(account_index)))
		if key_pair.public_key != candidate.public_key:
			raise RuntimeError('CUDA result does not match the mnemonic-derived account')
		self.key_pair_acceptor(mnemonic, key_pair)
