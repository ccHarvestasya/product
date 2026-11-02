from pathlib import Path

from mnemonic import Mnemonic
from symbolchain.Bip32 import Bip32
from symbolchain.facade.NemFacade import NemFacade
from symbolchain.facade.SymbolFacade import SymbolFacade

from .CudaSeedGenerator import CudaSeedGenerator, prepare_hmac_keys


def search_kernel_source():
	"""Combines standalone CUDA sources in dependency order without external headers."""

	root = Path(__file__).parent
	return '\n'.join((root / name).read_text(encoding='utf8') for name in (
		'bip39.cu', 'bip39_words.cuh', 'mnemonic.cu', 'ed25519_table.cuh', 'ed25519.cu', 'address.cu', 'search.cu'))


class CudaSearchBackend(CudaSeedGenerator):
	"""Runs BIP39, SLIP10, Ed25519, address hashing and pattern filtering on CUDA."""

	def __init__(self, device_id=0):
		super().__init__(device_id)
		self.last_timings = {}
		try:
			with self.device:
				self.module = self.cupy.RawModule(code=search_kernel_source(), options=('--std=c++11',))
				self.module.compile()
				self.kernel = self.module.get_function('bip39_seeds')
				self.functions = {name: self.module.get_function(name) for name in ('entropy_to_keys', 'derive_accounts', 'scan_accounts')}
				self._self_test()
		except Exception as ex:
			raise RuntimeError(f'Cannot initialize CUDA address search on device {device_id}: {ex}') from ex

	def search(self, mnemonics, facade, max_accounts, search):
		"""Returns (wallet index, account index, public key, address) for GPU-selected candidates."""

		if not mnemonics or not search[1]:
			return []
		with self.device:
			buffers = self._allocate((len(mnemonics), max_accounts), search)
			try:
				buffers['keys'] = self._upload(prepare_hmac_keys(mnemonics))
				self._run(buffers, facade, (len(mnemonics), max_accounts), search)
				return self._collect(buffers, max_accounts)
			finally:
				self._clear(buffers)

	def search_entropy(self, entropy, facade, max_accounts, search):
		"""Converts bulk OS entropy to BIP39 passwords on CUDA, returning only candidate accounts."""

		if len(entropy) % 32:
			raise ValueError('entropy must contain whole 32-byte wallets')
		if not entropy or not search[1]:
			return []
		shape = (len(entropy) // 32, max_accounts)
		with self.device:
			buffers = self._allocate(shape, search)
			try:
				buffers['entropy'] = self._upload(entropy)
				buffers['keys'] = self.cupy.empty((shape[0], 128), dtype=self.cupy.uint8)
				self._run(buffers, facade, shape, search)
				return self._collect(buffers, max_accounts)
			finally:
				self._clear(buffers)

	def inspect_seeds(self, seeds, facade, max_accounts):
		"""Diagnostic path exposing all GPU outputs for CPU/GPU equivalence tests."""

		with self.device:
			buffers = self._allocate((len(seeds), max_accounts), (0, ()))
			try:
				buffers['seeds'].set(self.numpy.frombuffer(b''.join(seeds), dtype=self.numpy.uint8).reshape(-1, 64))  # pylint: disable=no-member
				self._run(buffers, facade, (len(seeds), max_accounts), (0, ()))
				return tuple(buffers[name].get().tobytes() for name in ('private', 'public', 'addresses'))  # pylint: disable=no-member
			finally:
				self._clear(buffers)

	def _upload(self, data):
		return self.cupy.asarray(self.numpy.frombuffer(data, dtype=self.numpy.uint8))

	def _allocate(self, shape, search):
		wallets, accounts = shape
		if not 0 < accounts < 0x80000000 or not 0 < wallets * accounts < 0x100000000:
			raise ValueError('CUDA batch account count must fit in a positive unsigned 32-bit integer')
		patterns = [(pattern.encode('ascii')[:40], min(41, best + 1)) for pattern, best in search[1]]
		return {
			'seeds': self.cupy.zeros((wallets, 64), dtype=self.cupy.uint8),
			'private': self.cupy.zeros((wallets * accounts, 32), dtype=self.cupy.uint8),
			'public': self.cupy.empty((wallets * accounts, 32), dtype=self.cupy.uint8),
			'addresses': self.cupy.empty((wallets * accounts, 40), dtype=self.cupy.uint8),
			'best': self.cupy.zeros(len(patterns), dtype=self.cupy.uint64),
			'patterns': self._upload(b''.join(pattern.ljust(40, b'\0') for pattern, _ in patterns)),
			'lengths': self.cupy.asarray(self.numpy.array([len(pattern) for pattern, _ in patterns], dtype=self.numpy.uint32)),
			'minimums': self.cupy.asarray(self.numpy.array([minimum for _, minimum in patterns], dtype=self.numpy.uint32))
		}

	def _run(self, buffers, facade, shape, search):
		wallets, accounts = shape
		nem = self.numpy.int32('ed25519-keccak' == facade.BIP32_CURVE_NAME)
		uint32 = self.numpy.uint32
		events = [self.cupy.cuda.Event() for _ in range(5)]
		events[0].record()
		if 'entropy' in buffers:
			self.functions['entropy_to_keys'](((wallets + 127) // 128,), (128,), (
				buffers['entropy'], buffers['keys'], uint32(wallets)))
		events[1].record()
		if 'keys' in buffers:
			self.kernel(((wallets + 127) // 128,), (128,), (buffers['keys'], buffers['seeds'], uint32(wallets)))
		events[2].record()
		self.functions['derive_accounts'](((wallets + 127) // 128,), (128,), (
			buffers['seeds'], buffers['private'], uint32(wallets), uint32(accounts), uint32(facade.bip32_path(0)[1]), nem))
		events[3].record()
		self.functions['scan_accounts'](((wallets * accounts + 127) // 128,), (128,), (
			buffers['private'], buffers['public'], buffers['addresses'], buffers['best'], buffers['patterns'],
			buffers['lengths'], buffers['minimums'], uint32(len(search[1])), uint32(wallets * accounts),
			self.numpy.int32(max(-1, min(search[0], 39))), self.numpy.int32(facade.network.identifier), nem))
		events[4].record()
		events[4].synchronize()
		self.last_timings = {
			name: self.cupy.cuda.get_elapsed_time(events[index], events[index + 1]) / 1000
			for index, name in enumerate(('prepare', 'seed', 'derive', 'scan'))
		}

	def _collect(self, buffers, accounts):
		indices = sorted({
			(0xFFFFFFFF - (int(score) & 0xFFFFFFFF)) ^ pattern
			for pattern, score in enumerate(buffers['best'].get()) if score
		})
		if not indices:
			return []
		if indices[-1] >= len(buffers['public']):
			raise RuntimeError('CUDA returned an invalid candidate index')
		selected = self.cupy.asarray(self.numpy.array(indices, dtype=self.numpy.int64))
		public_keys = buffers['public'][selected].get()
		addresses = buffers['addresses'][selected].get()
		return [
			(index // accounts, index % accounts, public_keys[offset].tobytes(), addresses[offset].tobytes().rstrip(b'\0').decode('ascii'))
			for offset, index in enumerate(indices)
		]

	def _clear(self, buffers):
		for name in ('entropy', 'keys', 'seeds', 'private'):
			if name in buffers:
				buffers[name].fill(0)
		self.cupy.cuda.get_current_stream().synchronize()

	def _self_test(self):
		mnemonic = Mnemonic('english').to_mnemonic(bytes(range(32)))
		seed = Mnemonic.to_seed(mnemonic, '')
		for facade_class in (SymbolFacade, NemFacade):
			for network in ('mainnet', 'testnet'):
				self._self_test_facade(mnemonic, seed, facade_class(network))

	def _self_test_facade(self, mnemonic, seed, facade):
		root = Bip32(facade.BIP32_CURVE_NAME).from_seed(seed)
		private, public, addresses = self.inspect_seeds([seed], facade, 10)
		for index in range(10):
			key_pair = facade.bip32_node_to_key_pair(root.derive_path(facade.bip32_path(index)))
			expected_private = key_pair.private_key.bytes if isinstance(facade, SymbolFacade) else key_pair.private_key.bytes[::-1]
			actual = (
				private[index * 32:(index + 1) * 32], public[index * 32:(index + 1) * 32],
				addresses[index * 40:(index + 1) * 40].rstrip(b'\0').decode('ascii')
			)
			expected = (expected_private, key_pair.public_key.bytes, str(facade.network.public_key_to_address(key_pair.public_key)))
			if actual != expected:
				raise RuntimeError(f'CUDA address self-test failed: {type(facade).__name__} {facade.network.name} account {index}')
		address = str(facade.network.public_key_to_address(key_pair.public_key))
		expected_candidate = (0, 9, key_pair.public_key.bytes, address)
		if self.search([mnemonic], facade, 10, (0, ((address, 0),))) != [expected_candidate]:
			raise RuntimeError(f'CUDA pattern self-test failed: {type(facade).__name__} {facade.network.name}')
		if self.search_entropy(bytes(range(32)), facade, 10, (0, ((address, 0),))) != [expected_candidate]:
			raise RuntimeError(f'CUDA entropy self-test failed: {type(facade).__name__} {facade.network.name}')
