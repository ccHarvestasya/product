import csv
import ctypes
import hashlib
import hmac
import io
import os
import shutil
import subprocess
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import sha3
from mnemonic import Mnemonic
from symbolchain.Bip32 import Bip32
from symbolchain.CryptoTypes import PrivateKey, PublicKey
from symbolchain.facade.NemFacade import NemFacade
from symbolchain.facade.SymbolFacade import SymbolFacade

from vanity.__main__ import main
from vanity.CudaSearchBackend import CudaSearchBackend, search_kernel_source
from vanity.CudaSeedGenerator import prepare_hmac_keys

BytePointer = ctypes.POINTER(ctypes.c_ubyte)
UIntPointer = ctypes.POINTER(ctypes.c_uint)


def reference_scores(addresses, patterns, offset):
	"""Computes the expected prefix winners using Python strings."""

	scores = []
	for pattern_index, (pattern, minimum) in enumerate(patterns):
		expected = 0
		for index, address in enumerate(addresses):
			matched = max((size for size in range(1, len(pattern) + 1) if 0 <= address.find(pattern[:size]) <= offset), default=0)
			if matched >= minimum and matched:
				expected = max(expected, (matched << 32) | (0xFFFFFFFF - (index ^ pattern_index)))
		scores.append(expected)
	return scores


def entropy_fixtures():
	"""Includes phrases on both sides of the 128-byte HMAC key boundary."""

	factory = Mnemonic('english')
	prefix = ''.join(f'{factory.wordlist.index(word):011b}' for word in ['abstract'] * 2 + ['able'] * 20)
	boundaries = {}
	for word in factory.wordlist:
		if len(word) != 4:
			continue
		for tail in range(8):
			entropy = int(prefix + f'{factory.wordlist.index(word):011b}{tail:03b}', 2).to_bytes(32, 'big')
			length = len(factory.to_mnemonic(entropy))
			if length in (127, 128, 129):
				boundaries[length] = entropy
		if len(boundaries) == 3:
			break
	if len(boundaries) != 3:
		raise AssertionError('missing HMAC boundary fixtures')
	return [bytes(32), bytes([255]) * 32, bytes(range(32)), *boundaries.values()] + [
		hashlib.sha256(index.to_bytes(4, 'big')).digest() for index in range(130)
	]


class CudaSearchArithmeticTest(unittest.TestCase):
	"""Compiles the same GPU source as C++ and checks each stage against the SDK."""

	@classmethod
	def setUpClass(cls):
		compiler = shutil.which('c++')
		if not compiler:
			raise unittest.SkipTest('C++ compiler is required for CUDA arithmetic tests')
		cls.directory = TemporaryDirectory()  # pylint: disable=consider-using-with
		cls.addClassCleanup(cls.directory.cleanup)
		source = Path(cls.directory.name) / 'search.cpp'
		source.write_text('''
#include <cstddef>
#define __constant__
#define __device__
#define __global__
struct Dimension { unsigned int x; };
Dimension blockIdx, blockDim, threadIdx;
unsigned long long atomicMax(unsigned long long* target, unsigned long long value) {
	unsigned long long previous = *target;
	if (value > previous) *target = value;
	return previous;
}
''' + search_kernel_source() + '''
extern "C" void test_public(const unsigned char* key, int nem, unsigned char* out) {
	public_key_from_private(key, nem, out);
}
extern "C" int test_mnemonic(const unsigned char* entropy, unsigned char* out) {
	return entropy_mnemonic(entropy, out);
}
extern "C" void test_entropy_keys(const unsigned char* entropy, unsigned char* out, unsigned int count) {
	blockDim.x = 128;
	for (unsigned int i = 0; i < count + 7; ++i) {
		blockIdx.x = i / 128; threadIdx.x = i % 128;
		entropy_to_keys(entropy, out, count);
	}
}
extern "C" void test_address(const unsigned char* key, int nem, int network, unsigned char* out) {
	address_from_public(key, nem, network, out);
}
extern "C" void test_keccak(const unsigned char* data, int length, int size, int domain, unsigned char* out) {
	keccak_short(data, length, out, size, domain);
}
extern "C" void test_hmac(const unsigned char* key, int size, const unsigned char* data, int length, unsigned char* out) {
	hmac_sha512_short(key, size, data, length, out);
}
extern "C" void test_derive(const unsigned char* seeds, unsigned int count, unsigned int accounts,
		unsigned int coin, int nem, unsigned char* out) {
	blockDim.x = 128;
	for (unsigned int i = 0; i < count + 7; ++i) {
		blockIdx.x = i / 128; threadIdx.x = i % 128;
		derive_accounts(seeds, out, count, accounts, coin, nem);
	}
}
extern "C" void test_scan(const unsigned char* keys, unsigned char* public_keys, unsigned char* addresses,
		unsigned long long* best, const unsigned char* patterns, const unsigned int* lengths,
		const unsigned int* minimums, unsigned int pattern_count, unsigned int account_count,
		int offset, int network, int nem) {
	blockDim.x = 128;
	for (unsigned int i = 0; i < account_count + 7; ++i) {
		blockIdx.x = i / 128; threadIdx.x = i % 128;
		scan_accounts(keys, public_keys, addresses, best, patterns, lengths, minimums,
			pattern_count, account_count, offset, network, nem);
	}
}
''', encoding='utf8')
		library_path = Path(cls.directory.name) / 'search.so'
		options = ['-fsanitize=undefined', '-fno-sanitize-recover=all'] if os.environ.get('VANITY_CUDA_SANITIZE') else []
		subprocess.run([compiler, '-std=c++11', '-O2', '-shared', '-fPIC', *options, str(source), '-o', str(library_path)], check=True)
		cls.library = ctypes.CDLL(str(library_path))
		cls.library.test_public.argtypes = [BytePointer, ctypes.c_int, BytePointer]
		cls.library.test_mnemonic.argtypes = [BytePointer, BytePointer]
		cls.library.test_mnemonic.restype = ctypes.c_int
		cls.library.test_entropy_keys.argtypes = [BytePointer, BytePointer, ctypes.c_uint]
		cls.library.test_address.argtypes = [BytePointer, ctypes.c_int, ctypes.c_int, BytePointer]
		cls.library.test_keccak.argtypes = [BytePointer, ctypes.c_int, ctypes.c_int, ctypes.c_int, BytePointer]
		cls.library.test_hmac.argtypes = [BytePointer, ctypes.c_int, BytePointer, ctypes.c_int, BytePointer]
		cls.library.test_derive.argtypes = [BytePointer, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.c_int, BytePointer]
		cls.library.test_scan.argtypes = [
			BytePointer, BytePointer, BytePointer, ctypes.POINTER(ctypes.c_ulonglong),
			BytePointer, UIntPointer, UIntPointer, ctypes.c_uint, ctypes.c_uint, ctypes.c_int, ctypes.c_int, ctypes.c_int
		]

	@staticmethod
	def _bytes(data):
		return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)

	def test_keccak_and_sha3_domains_and_output_sizes(self):
		for size in (32, 64):
			for length in (0, 21, 32, 64):
				data = bytes(range(length))
				for domain in (1, 6):
					with self.subTest(size=size, length=length, domain=domain):
						output = (ctypes.c_ubyte * size)()
						self.library.test_keccak(self._bytes(data), length, size, domain, output)
						module = sha3 if 1 == domain else hashlib
						function = getattr(module, f'{"keccak" if 1 == domain else "sha3"}_{size * 8}')
						self.assertEqual(function(data).digest(), bytes(output))

	def test_entropy_mnemonics_and_hmac_keys_match_reference(self):
		entropies = entropy_fixtures()
		factory = Mnemonic('english')
		for entropy in entropies:
			phrase = (ctypes.c_ubyte * 216)()
			length = self.library.test_mnemonic(self._bytes(entropy), phrase)
			self.assertEqual(factory.to_mnemonic(entropy).encode(), bytes(phrase[:length]))
		keys = (ctypes.c_ubyte * (len(entropies) * 128))()
		self.library.test_entropy_keys(self._bytes(b''.join(entropies)), keys, len(entropies))
		self.assertEqual(bytes(prepare_hmac_keys([factory.to_mnemonic(entropy) for entropy in entropies])), bytes(keys))

	def test_hmac_for_root_and_child_message_sizes(self):
		for key in (b'ed25519 seed', b'ed25519-keccak seed', bytes(range(32))):
			for length in (37, 64):
				output = (ctypes.c_ubyte * 64)()
				data = bytes(range(length))
				self.library.test_hmac(self._bytes(key), len(key), self._bytes(data), length, output)
				self.assertEqual(hmac.digest(key, data, 'sha512'), bytes(output))

	def test_public_keys_for_both_chains(self):
		keys = [bytes(32), bytes([255]) * 32, bytes(range(32))]
		keys += [hashlib.sha256(index.to_bytes(4, 'big')).digest() for index in range(64)]
		for nem, facade_class in ((0, SymbolFacade), (1, NemFacade)):
			for index, key in enumerate(keys):
				with self.subTest(nem=nem, index=index):
					output = (ctypes.c_ubyte * 32)()
					self.library.test_public(self._bytes(key), nem, output)
					expected = facade_class.KeyPair(PrivateKey(key[::-1] if nem else key))
					self.assertEqual(expected.public_key.bytes, bytes(output))

	def test_addresses_for_both_chains_and_networks(self):
		for nem, facade_class in ((0, SymbolFacade), (1, NemFacade)):
			for network in ('mainnet', 'testnet'):
				facade = facade_class(network)
				for index in range(20):
					public_key = hashlib.sha256(bytes([index])).digest()
					output = (ctypes.c_ubyte * 40)()
					self.library.test_address(self._bytes(public_key), nem, facade.network.identifier, output)
					self.assertEqual(str(facade.network.public_key_to_address(PublicKey(public_key))), bytes(output).rstrip(b'\0').decode())

	def test_hardened_derivation_for_both_chains_and_networks(self):
		seeds = [bytes(64), bytes(range(64)), bytes([255]) * 64]
		for nem, facade_class in ((0, SymbolFacade), (1, NemFacade)):
			for network in ('mainnet', 'testnet'):
				facade = facade_class(network)
				output = (ctypes.c_ubyte * (len(seeds) * 10 * 32))()
				self.library.test_derive(self._bytes(b''.join(seeds)), len(seeds), 10, facade.bip32_path(0)[1], nem, output)
				for wallet, seed in enumerate(seeds):
					root = Bip32(facade.BIP32_CURVE_NAME).from_seed(seed)
					for account in range(10):
						expected = root.derive_path(facade.bip32_path(account)).private_key.bytes
						index = wallet * 10 + account
						self.assertEqual(expected, bytes(output[index * 32:(index + 1) * 32]), (nem, network, wallet, account))

	def test_scan_matches_public_keys_addresses_and_best_prefixes(self):
		for nem, facade_class in ((0, SymbolFacade), (1, NemFacade)):
			for network in ('mainnet', 'testnet'):
				for offset in (0, 2, 100, -1):
					with self.subTest(nem=nem, network=network, offset=offset):
						self._assert_scan_matches_reference(nem, facade_class(network), offset)

	def _assert_scan_matches_reference(self, nem, facade, offset):
		keys = [hashlib.sha256(index.to_bytes(4, 'big')).digest() for index in range(17)]
		expected_keys = [facade.KeyPair(PrivateKey(key[::-1] if nem else key)).public_key.bytes for key in keys]
		expected_addresses = [str(facade.network.public_key_to_address(PublicKey(key))) for key in expected_keys]
		patterns = [
			(expected_addresses[5], 1), (expected_addresses[3][1:6], 2), ('AXE', 1), ('!', 1), ('', 1),
			(expected_addresses[4][-4:], 4), ('N', 2), (expected_addresses[0][0], 1), (expected_addresses[0][0], 1)
		]
		buffers = {
			'keys': (ctypes.c_ubyte * (len(keys) * 32))(),
			'addresses': (ctypes.c_ubyte * (len(keys) * 40))(),
			'best': (ctypes.c_ulonglong * len(patterns))(),
			'patterns': self._bytes(b''.join(pattern.encode().ljust(40, b'\0') for pattern, _ in patterns)),
			'lengths': (ctypes.c_uint * len(patterns))(*(len(pattern) for pattern, _ in patterns)),
			'minimums': (ctypes.c_uint * len(patterns))(*(minimum for _, minimum in patterns))
		}
		self.library.test_scan(
			self._bytes(b''.join(keys)), buffers['keys'], buffers['addresses'], buffers['best'], buffers['patterns'],
			buffers['lengths'], buffers['minimums'], len(patterns), len(keys), offset, facade.network.identifier, nem)
		self.assertEqual(b''.join(expected_keys), bytes(buffers['keys']))
		self.assertEqual(b''.join(address.encode().ljust(40, b'\0') for address in expected_addresses), bytes(buffers['addresses']))
		self.assertEqual(reference_scores(expected_addresses, patterns, offset), list(buffers['best']))


@unittest.skipUnless('1' == os.environ.get('VANITY_TEST_CUDA'), 'set VANITY_TEST_CUDA=1 to test on an NVIDIA GPU')
class CudaSearchDeviceTest(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		cls.backend = CudaSearchBackend(int(os.environ.get('VANITY_GPU_DEVICE', '0')))

	def test_gpu_pipeline_matches_sdk(self):
		# Thirteen wallets produce 130 accounts, crossing the 128-thread block boundary.
		seeds = [hashlib.sha512(index.to_bytes(4, 'big')).digest() for index in range(13)]
		for facade_class in (SymbolFacade, NemFacade):
			for network in ('mainnet', 'testnet'):
				with self.subTest(blockchain=facade_class.__name__, network=network):
					facade = facade_class(network)
					private, public, addresses = self.backend.inspect_seeds(seeds, facade, 10)
					for wallet, seed in enumerate(seeds):
						root = Bip32(facade.BIP32_CURVE_NAME).from_seed(seed)
						for account in range(10):
							index = wallet * 10 + account
							leaf = root.derive_path(facade.bip32_path(account))
							key_pair = facade.bip32_node_to_key_pair(leaf)
							self.assertEqual(leaf.private_key.bytes, private[index * 32:(index + 1) * 32])
							self.assertEqual(key_pair.public_key.bytes, public[index * 32:(index + 1) * 32])
							self.assertEqual(
								str(facade.network.public_key_to_address(key_pair.public_key)),
								addresses[index * 40:(index + 1) * 40].rstrip(b'\0').decode())

	def test_gpu_search_returns_reference_winners_for_multiple_patterns(self):
		mnemonics = [Mnemonic('english').to_mnemonic(index.to_bytes(32, 'big')) for index in range(13)]
		for facade_class in (SymbolFacade, NemFacade):
			for network in ('mainnet', 'testnet'):
				facade = facade_class(network)
				key_pairs = []
				for mnemonic in mnemonics:
					root = Bip32(facade.BIP32_CURVE_NAME).from_mnemonic(mnemonic, '')
					key_pairs.extend(facade.bip32_node_to_key_pair(root.derive_path(facade.bip32_path(index))) for index in range(10))
				addresses = [str(facade.network.public_key_to_address(key.public_key)) for key in key_pairs]
				patterns = [(addresses[-1], 1), (addresses[0][0], 1), (addresses[0][0], 1), (addresses[8][1:6], 2)]
				for offset in (0, 2, 100):
					with self.subTest(blockchain=facade_class.__name__, network=network, offset=offset):
						scores = reference_scores(addresses, patterns, offset)
						indices = sorted({(0xFFFFFFFF - (score & 0xFFFFFFFF)) ^ index for index, score in enumerate(scores) if score})
						expected = [(index // 10, index % 10, key_pairs[index].public_key.bytes, addresses[index]) for index in indices]
						search = (offset, tuple((pattern, minimum - 1) for pattern, minimum in patterns))
						self.assertEqual(expected, self.backend.search(mnemonics, facade, 10, search))
						self.assertEqual(expected, self.backend.search_entropy(
							b''.join(index.to_bytes(32, 'big') for index in range(len(mnemonics))), facade, 10, search))

	def test_gpu_entropy_passwords_and_seeds_match_reference_at_boundaries(self):
		entropies = entropy_fixtures()
		mnemonics = [Mnemonic('english').to_mnemonic(entropy) for entropy in entropies]
		backend = self.backend
		with backend.device:
			entropy = backend.cupy.asarray(backend.numpy.frombuffer(b''.join(entropies), dtype=backend.numpy.uint8))
			keys = backend.cupy.empty((len(entropies), 128), dtype=backend.cupy.uint8)
			seeds = backend.cupy.empty((len(entropies), 64), dtype=backend.cupy.uint8)
			try:
				grid = ((len(entropies) + 127) // 128,)
				backend.functions['entropy_to_keys'](grid, (128,), (entropy, keys, backend.numpy.uint32(len(entropies))))
				self.assertEqual(bytes(prepare_hmac_keys(mnemonics)), backend.cupy.asnumpy(keys).tobytes())
				backend.kernel(grid, (128,), (keys, seeds, backend.numpy.uint32(len(entropies))))
				self.assertEqual(b''.join(Mnemonic.to_seed(value, '') for value in mnemonics), backend.cupy.asnumpy(seeds).tobytes())
			finally:
				entropy.fill(0)
				keys.fill(0)
				seeds.fill(0)
				backend.cupy.cuda.get_current_stream().synchronize()

	def test_gpu_cli_exports_mnemonic_recoverable_account(self):
		with TemporaryDirectory() as directory:
			output = Path(directory) / 'accounts.csv'
			with patch('vanity.CudaSearchGenerator.secrets.token_bytes', return_value=bytes(range(32))):
				with redirect_stdout(io.StringIO()):
					main([
						'--backend', 'cuda', '--gpu-device', os.environ.get('VANITY_GPU_DEVICE', '0'),
						'--patterns', 'N', '--batch-size', '1', '--format', 'csv', '--suppress-console', '--out', str(output)
					])
			with output.open(encoding='utf8') as infile:
				accounts = list(csv.DictReader(infile))
		self.assertEqual(1, len(accounts))
		facade = SymbolFacade('mainnet')
		root = Bip32(facade.BIP32_CURVE_NAME).from_mnemonic(accounts[0]['mnemonic'], '')
		expected = facade.bip32_node_to_key_pair(root.derive_path(facade.bip32_path(0)))
		self.assertEqual(str(expected.private_key), accounts[0]['private key'])
		self.assertEqual(str(expected.public_key), accounts[0]['public key'])
		self.assertEqual(str(facade.network.public_key_to_address(expected.public_key)), accounts[0]['address'])
