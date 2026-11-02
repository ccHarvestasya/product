import unittest
from concurrent.futures import Future
from threading import Event
from unittest.mock import Mock, patch

from mnemonic import Mnemonic
from symbolchain.Bip32 import Bip32
from symbolchain.CryptoTypes import PrivateKey
from symbolchain.facade.NemFacade import NemFacade
from symbolchain.facade.SymbolFacade import SymbolFacade

from vanity.CudaAddressGenerator import CudaAddressGenerator
from vanity.MultiAddressMatcher import MultiAddressMatcher


class CudaAddressGeneratorTest(unittest.TestCase):
	def _test_matches_and_preserves_wallet(self, facade):
		mnemonic = Mnemonic('english').to_mnemonic(bytes(32))
		root = Bip32(facade.BIP32_CURVE_NAME).from_mnemonic(mnemonic, '')
		expected = facade.bip32_node_to_key_pair(root.derive_path(facade.bip32_path(2)))
		matcher = MultiAddressMatcher(facade.network, 0)
		matcher.add_search_pattern(str(facade.network.public_key_to_address(expected.public_key)))
		seed_generator = Mock()
		seed_generator.generate.side_effect = lambda mnemonics: [Mnemonic.to_seed(value, '') for value in mnemonics]
		acceptor = Mock()
		generator = CudaAddressGenerator(facade, 5, acceptor, seed_generator)
		generator.batch_size = 3
		with patch('vanity.CudaAddressGenerator.secrets.token_bytes', return_value=bytes(32)):
			generator.match_all(matcher)

		self.assertTrue(matcher.is_complete)
		acceptor.assert_called_once()
		self.assertEqual(mnemonic, acceptor.call_args[0][0])
		self.assertEqual(expected.private_key, acceptor.call_args[0][1].private_key)
		self.assertEqual(expected.public_key, acceptor.call_args[0][1].public_key)
		self.assertIn(seed_generator.generate.call_count, (1, 2))
		for call in seed_generator.generate.call_args_list:
			self.assertEqual(([mnemonic] * 3,), call.args)

	def test_matches_symbol_and_nem_on_both_networks(self):
		for facade_class in (SymbolFacade, NemFacade):
			for network in ('mainnet', 'testnet'):
				with self.subTest(blockchain=facade_class.__name__, network=network):
					self._test_matches_and_preserves_wallet(facade_class(network))

	def test_rejects_incorrect_seed_before_export(self):
		facade = SymbolFacade('testnet')
		seed_generator = Mock()
		seed_generator.generate.return_value = [bytes(64)]
		acceptor = Mock()
		generator = CudaAddressGenerator(facade, 1, acceptor, seed_generator)
		generator.batch_size = 1
		matcher = MultiAddressMatcher(facade.network, 0)
		matcher.add_search_pattern('T')
		with self.assertRaisesRegex(RuntimeError, 'does not match'):
			generator.match_all(matcher)
		acceptor.assert_not_called()

	def test_propagates_seed_generation_failure(self):
		seed_generator = Mock()
		seed_generator.generate.side_effect = RuntimeError('device failure')
		generator = CudaAddressGenerator(SymbolFacade('testnet'), 1, Mock(), seed_generator)
		generator.batch_size = 1
		matcher = MultiAddressMatcher(generator.facade.network, 0)
		matcher.add_search_pattern('T')
		with self.assertRaisesRegex(RuntimeError, 'device failure'):
			generator.match_all(matcher)
		seed_generator.generate.assert_called_once()
		self.assertFalse(matcher.is_complete)

	def test_complete_matcher_does_not_launch_gpu(self):
		seed_generator = Mock()
		generator = CudaAddressGenerator(SymbolFacade('testnet'), 1, Mock(), seed_generator)
		matcher = MultiAddressMatcher(generator.facade.network, 0)
		generator.match_all(matcher)
		self.assertTrue(matcher.is_complete)
		seed_generator.generate.assert_not_called()

	def test_worker_failure_propagates_and_pending_tasks_are_cancelled(self):
		facade = SymbolFacade('testnet')
		generator = CudaAddressGenerator(facade, 1, Mock(), Mock())
		matcher = MultiAddressMatcher(facade.network, 0)
		matcher.add_search_pattern('T')
		failed = Future()
		failed.set_exception(RuntimeError('worker failure'))
		pending = Future()
		executor = Mock()
		executor.submit.side_effect = [failed, pending]
		with self.assertRaisesRegex(RuntimeError, 'worker failure'):
			generator._scan_batch(executor, matcher, ['unused'] * 65, [bytes(64)] * 65)  # pylint: disable=protected-access
		self.assertTrue(pending.cancelled())

	def test_next_seed_batch_runs_while_cpu_is_scanning(self):
		facade = SymbolFacade('mainnet')
		prefetched = Event()
		seed_generator = Mock()

		def generate(mnemonics):
			if seed_generator.generate.call_count == 2:
				prefetched.set()
			return [Mnemonic.to_seed(value, '') for value in mnemonics]

		seed_generator.generate.side_effect = generate
		generator = CudaAddressGenerator(facade, 1, Mock(), seed_generator)
		generator.batch_size = 1
		generator.workers = 1
		generator.stats_monitor = Mock()
		matcher = MultiAddressMatcher(facade.network, 0)
		matcher.add_search_pattern('N')

		def scan(_executor, active_matcher, _mnemonics, _seeds):
			self.assertTrue(prefetched.wait(5), 'next seed batch was blocked by CPU scanning')
			active_matcher.accept(facade.KeyPair(PrivateKey(bytes(32))))

		with patch.object(generator, '_scan_batch', side_effect=scan):
			generator.match_all(matcher)
		self.assertEqual(2, seed_generator.generate.call_count)
		generator.stats_monitor.assert_called_once()
		self.assertIn('seed wait', generator.stats_monitor.call_args[0][0])
		self.assertIn('CPU scan', generator.stats_monitor.call_args[0][0])

	def test_repeated_patterns_export_distinct_accounts(self):
		facade = SymbolFacade('mainnet')
		seed_generator = Mock()
		seed_generator.generate.side_effect = lambda mnemonics: [Mnemonic.to_seed(value, '') for value in mnemonics]
		acceptor = Mock()
		generator = CudaAddressGenerator(facade, 3, acceptor, seed_generator)
		generator.batch_size = 1
		generator.workers = 1
		matcher = MultiAddressMatcher(facade.network, 0)
		matcher.add_search_pattern('N')
		matcher.add_search_pattern('N')
		generator.match_all(matcher)
		self.assertEqual(2, acceptor.call_count)
		self.assertNotEqual(acceptor.call_args_list[0].args[1].public_key, acceptor.call_args_list[1].args[1].public_key)
