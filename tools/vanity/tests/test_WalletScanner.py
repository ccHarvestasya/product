import unittest

from symbolchain.Bip32 import Bip32
from symbolchain.facade.NemFacade import NemFacade
from symbolchain.facade.SymbolFacade import SymbolFacade

from vanity.MultiAddressMatcher import MultiAddressMatcher
from vanity.WalletScanner import improves_pattern, scan_wallets, snapshot_search


class WalletScannerTest(unittest.TestCase):
	def test_derived_candidates_match_full_sdk_paths_on_all_networks(self):
		for blockchain, facade_class in (('symbol', SymbolFacade), ('nem', NemFacade)):
			for network in ('mainnet', 'testnet'):
				with self.subTest(blockchain=blockchain, network=network):
					facade = facade_class(network)
					seed = bytes(range(64))
					root = Bip32(facade.BIP32_CURVE_NAME).from_seed(seed)
					expected = [facade.bip32_node_to_key_pair(root.derive_path(facade.bip32_path(index))) for index in range(10)]
					patterns = [(str(facade.network.public_key_to_address(key_pair.public_key)), 0) for key_pair in expected]
					candidates = scan_wallets((blockchain, network, 10), [(42, seed)], (0, patterns))
					self.assertEqual([(42, index, key_pair.private_key.bytes) for index, key_pair in enumerate(expected)], candidates)

	def test_local_filter_preserves_progress_and_all_full_matches(self):
		best = {'AXE': 0}
		self.assertTrue(improves_pattern('NABBB', best, 2))
		self.assertEqual(1, best['AXE'])
		self.assertFalse(improves_pattern('NABCC', best, 2))
		self.assertTrue(improves_pattern('NAXBB', best, 2))
		self.assertEqual(2, best['AXE'])
		self.assertTrue(improves_pattern('NAXEB', best, 2))
		self.assertEqual(3, best['AXE'])
		self.assertTrue(improves_pattern('NCAXE', best, 2))
		self.assertFalse(improves_pattern('NCAAXE', best, 2))
		self.assertFalse(improves_pattern('NAXEB', best, 0))

	def test_filter_never_drops_full_matches_after_partial_progress(self):
		facade = SymbolFacade('testnet')
		root = Bip32(facade.BIP32_CURVE_NAME).from_seed(bytes(64))
		addresses = [str(facade.network.public_key_to_address(
			facade.bip32_node_to_key_pair(root.derive_path(facade.bip32_path(index))).public_key)) for index in range(10)]
		for offset in (0, 2, 100):
			for pattern in ('T', 'AXE', 'CAT', addresses[5][1:5], addresses[3][-4:]):
				best = {pattern: 0}
				for address in addresses:
					accepted = improves_pattern(address, best, offset)
					if 0 <= address.find(pattern) <= offset:
						self.assertTrue(accepted, (pattern, offset, address))

	def test_snapshot_retains_incomplete_duplicate_after_another_is_matched(self):
		facade = SymbolFacade('testnet')
		matcher = MultiAddressMatcher(facade.network, 2)
		matcher.add_search_pattern('T')
		matcher.add_search_pattern('T')
		key_pair = facade.bip32_node_to_key_pair(Bip32().from_seed(bytes(64)))
		matcher.accept(key_pair)
		self.assertEqual((2, (('T', 0),)), snapshot_search(matcher))
