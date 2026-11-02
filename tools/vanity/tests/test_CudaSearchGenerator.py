import unittest
from unittest.mock import Mock, patch

from mnemonic import Mnemonic
from symbolchain.Bip32 import Bip32
from symbolchain.CryptoTypes import PrivateKey
from symbolchain.facade.NemFacade import NemFacade
from symbolchain.facade.SymbolFacade import SymbolFacade

from vanity.CudaSearchGenerator import CudaSearchGenerator
from vanity.MultiAddressMatcher import MultiAddressMatcher


class CudaSearchGeneratorTest(unittest.TestCase):
	def test_gpu_candidates_export_recoverable_accounts_on_all_networks(self):
		for facade_class in (SymbolFacade, NemFacade):
			for network in ('mainnet', 'testnet'):
				with self.subTest(blockchain=facade_class.__name__, network=network):
					self._assert_recoverable_account(facade_class(network))

	def _assert_recoverable_account(self, facade):
		mnemonic = Mnemonic('english').to_mnemonic(bytes(range(32)))
		root = Bip32(facade.BIP32_CURVE_NAME).from_mnemonic(mnemonic, '')
		expected = facade.bip32_node_to_key_pair(root.derive_path(facade.bip32_path(9)))
		address = str(facade.network.public_key_to_address(expected.public_key))
		backend = Mock()
		backend.search_entropy.return_value = [(0, 9, expected.public_key.bytes, address)]
		backend.last_timings = {'seed': 0.1, 'derive': 0.01, 'scan': 0.05}
		acceptor = Mock()
		generator = CudaSearchGenerator(facade, 10, acceptor, backend)
		generator.batch_size = 1
		generator.stats_monitor = Mock()
		matcher = MultiAddressMatcher(facade.network, 0)
		matcher.add_search_pattern(address)
		with patch('vanity.CudaSearchGenerator.secrets.token_bytes', return_value=bytes(range(32))):
			generator.match_all(matcher)
		self.assertTrue(matcher.is_complete)
		acceptor.assert_called_once()
		self.assertEqual(mnemonic, acceptor.call_args.args[0])
		self.assertEqual(expected.private_key, acceptor.call_args.args[1].private_key)
		backend.search_entropy.assert_called_once_with(bytes(range(32)), facade, 10, (0, ((address, 0),)))
		backend.generate.assert_not_called()
		self.assertIn('GPU scan', generator.stats_monitor.call_args.args[0])
		self.assertIn('addresses/s', generator.stats_monitor.call_args.args[0])

	def test_rejects_incorrect_gpu_key_and_address_before_export(self):
		facade = SymbolFacade('mainnet')
		key_pair = facade.KeyPair(PrivateKey(bytes(32)))
		address = str(facade.network.public_key_to_address(key_pair.public_key))
		for candidate_address, error in ((address, 'mnemonic-derived'), ('N' * 39, 'public key')):
			with self.subTest(address=candidate_address):
				backend = Mock()
				backend.search_entropy.return_value = [(0, 0, key_pair.public_key.bytes, candidate_address)]
				acceptor = Mock()
				generator = CudaSearchGenerator(facade, 10, acceptor, backend)
				generator.batch_size = 1
				matcher = MultiAddressMatcher(facade.network, 0)
				matcher.add_search_pattern('N')
				with self.assertRaisesRegex(RuntimeError, error):
					generator.match_all(matcher)
				acceptor.assert_not_called()

	def test_rejects_invalid_indices_before_export(self):
		facade = SymbolFacade('mainnet')
		backend = Mock()
		backend.search_entropy.return_value = [(-1, 10, bytes(32), 'N' * 39)]
		acceptor = Mock()
		generator = CudaSearchGenerator(facade, 10, acceptor, backend)
		generator.batch_size = 1
		matcher = MultiAddressMatcher(facade.network, 0)
		matcher.add_search_pattern('N')
		with self.assertRaisesRegex(RuntimeError, 'invalid account index'):
			generator.match_all(matcher)
		acceptor.assert_not_called()

	def test_duplicate_patterns_keep_distinct_gpu_descriptors(self):
		facade = SymbolFacade('mainnet')
		mnemonic = Mnemonic('english').to_mnemonic(bytes(32))
		root = Bip32(facade.BIP32_CURVE_NAME).from_mnemonic(mnemonic, '')
		key_pairs = [facade.bip32_node_to_key_pair(root.derive_path(facade.bip32_path(index))) for index in range(2)]
		backend = Mock()
		backend.search_entropy.return_value = [
			(0, index, key_pair.public_key.bytes, str(facade.network.public_key_to_address(key_pair.public_key)))
			for index, key_pair in enumerate(key_pairs)
		]
		acceptor = Mock()
		generator = CudaSearchGenerator(facade, 10, acceptor, backend)
		generator.batch_size = 1
		matcher = MultiAddressMatcher(facade.network, 0)
		matcher.add_search_pattern('N')
		matcher.add_search_pattern('N')
		with patch('vanity.CudaSearchGenerator.secrets.token_bytes', return_value=bytes(32)):
			generator.match_all(matcher)
		self.assertEqual((0, (('N', 0), ('N', 0))), backend.search_entropy.call_args.args[3])
		self.assertEqual(2, acceptor.call_count)
		self.assertNotEqual(acceptor.call_args_list[0].args[1].public_key, acceptor.call_args_list[1].args[1].public_key)

	def test_complete_matcher_does_not_launch_gpu(self):
		facade = SymbolFacade('mainnet')
		backend = Mock()
		generator = CudaSearchGenerator(facade, 10, Mock(), backend)
		matcher = MultiAddressMatcher(facade.network, 0)
		generator.match_all(matcher)
		self.assertTrue(matcher.is_complete)
		backend.search_entropy.assert_not_called()

	def test_bulk_entropy_recovers_a_candidate_from_a_later_wallet(self):
		facade = SymbolFacade('mainnet')
		entropies = [bytes([index]) * 32 for index in range(3)]
		mnemonic = Mnemonic('english').to_mnemonic(entropies[2])
		root = Bip32(facade.BIP32_CURVE_NAME).from_mnemonic(mnemonic, '')
		expected = facade.bip32_node_to_key_pair(root.derive_path(facade.bip32_path(7)))
		address = str(facade.network.public_key_to_address(expected.public_key))
		backend = Mock()
		backend.search_entropy.return_value = [(2, 7, expected.public_key.bytes, address)]
		acceptor = Mock()
		generator = CudaSearchGenerator(facade, 10, acceptor, backend)
		generator.batch_size = 3
		matcher = MultiAddressMatcher(facade.network, 0)
		matcher.add_search_pattern(address)
		with patch('vanity.CudaSearchGenerator.secrets.token_bytes', return_value=b''.join(entropies)) as random_bytes:
			generator.match_all(matcher)
		random_bytes.assert_called_once_with(96)
		self.assertEqual(mnemonic, acceptor.call_args.args[0])
		self.assertEqual(expected.private_key, acceptor.call_args.args[1].private_key)
