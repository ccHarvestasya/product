import csv
import io
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from mnemonic import Mnemonic
from symbolchain.Bip32 import Bip32
from symbolchain.CryptoTypes import PrivateKey, PublicKey
from symbolchain.facade.NemFacade import NemFacade
from symbolchain.facade.SymbolFacade import SymbolFacade

from vanity.__main__ import main


class MainTest(unittest.TestCase):
	@staticmethod
	def _execute(blockchain, patterns, extra_args=None):
		with TemporaryDirectory() as temp_directory:
			tempfile_name = Path(temp_directory) / 'out.txt'
			main([
				'--blockchain', blockchain,
				'--network', 'mainnet',
				'--patterns', patterns,
				'--format', 'csv',
				'--out', str(tempfile_name)
			] + (extra_args or []))

			with open(tempfile_name, 'rt', encoding='utf8') as infile:
				csv_reader = csv.DictReader(infile, ['address', 'public key', 'private key', 'mnemonic'])
				next(csv_reader)  # skip header
				return list(row for row in csv_reader)

	def _test_can_generate_addresses(self, blockchain, facade_class):
		# Act:
		address_descriptors = self._execute(blockchain, 'AXE,CAT,BOT')

		# Assert:
		address_prefixes = []
		facade = facade_class('mainnet')
		for descriptor in address_descriptors:
			bip32_root_node = Bip32(facade.BIP32_CURVE_NAME).from_mnemonic(descriptor['mnemonic'], '')
			for i in range(10):
				bip32_path = facade.bip32_path(i)
				key_pair = facade.bip32_node_to_key_pair(bip32_root_node.derive_path(bip32_path))

				if PublicKey(descriptor['public key']) != key_pair.public_key:
					continue

				self.assertEqual(key_pair.public_key, PublicKey(descriptor['public key']))
				self.assertEqual(key_pair.private_key, PrivateKey(descriptor['private key']))
				self.assertEqual(facade.network.public_key_to_address(key_pair.public_key), facade.Address(descriptor['address']))

				address_prefixes.append(descriptor['address'][1:5])

		self.assertEqual(3, len(address_prefixes))
		for target in ['AXE', 'CAT', 'BOT']:
			self.assertTrue(any(prefix.startswith(target) or prefix.endswith(target) for prefix in address_prefixes), target)

	def test_can_generate_nem_addresses(self):
		self._test_can_generate_addresses('nem', NemFacade)

	def test_can_generate_symbol_addresses(self):
		self._test_can_generate_addresses('symbol', SymbolFacade)

	def test_hybrid_cuda_options_generate_recoverable_account(self):
		seed_generator = Mock()
		seed_generator.generate.side_effect = lambda mnemonics: [Mnemonic.to_seed(value, '') for value in mnemonics]
		with patch('vanity.CudaSeedGenerator.CudaSeedGenerator', return_value=seed_generator) as constructor:
			with redirect_stderr(io.StringIO()) as stderr:
				accounts = self._execute('symbol', 'N', [
					'--backend', 'cuda-hybrid', '--gpu-device', '2', '--batch-size', '1', '--workers', '1', '--stats'])
		self.assertIn('CPU scan', stderr.getvalue())
		constructor.assert_called_once_with(2)
		self.assertEqual(1, len(accounts))
		facade = SymbolFacade('mainnet')
		root = Bip32(facade.BIP32_CURVE_NAME).from_mnemonic(accounts[0]['mnemonic'], '')
		expected = facade.bip32_node_to_key_pair(root.derive_path(facade.bip32_path(0)))
		self.assertEqual(str(expected.private_key), accounts[0]['private key'])
		self.assertEqual(str(facade.network.public_key_to_address(expected.public_key)), accounts[0]['address'])

	def test_cuda_initialization_failure_preserves_output_file(self):
		with TemporaryDirectory() as directory:
			output = Path(directory) / 'out.csv'
			output.write_text('existing output', encoding='utf8')
			with patch('vanity.CudaSearchBackend.CudaSearchBackend', side_effect=RuntimeError('device unavailable')):
				with redirect_stderr(io.StringIO()) as stderr, self.assertRaises(SystemExit) as result:
					main(['--backend', 'cuda', '--patterns', 'N', '--out', str(output)])
			self.assertEqual(2, result.exception.code)
			self.assertIn('device unavailable', stderr.getvalue())
			self.assertEqual('existing output', output.read_text(encoding='utf8'))

	def test_full_cuda_options_generate_recoverable_account(self):
		backend = Mock()
		backend.last_timings = {'seed': 0.01, 'derive': 0.002, 'scan': 0.02}

		def search(entropy, facade, _max_accounts, _search):
			mnemonic = Mnemonic('english').to_mnemonic(entropy[:32])
			root = Bip32(facade.BIP32_CURVE_NAME).from_mnemonic(mnemonic, '')
			key_pair = facade.bip32_node_to_key_pair(root.derive_path(facade.bip32_path(0)))
			return [(0, 0, key_pair.public_key.bytes, str(facade.network.public_key_to_address(key_pair.public_key)))]

		backend.search_entropy.side_effect = search
		with patch('vanity.CudaSearchBackend.CudaSearchBackend', return_value=backend) as constructor:
			with redirect_stderr(io.StringIO()) as stderr:
				accounts = self._execute('symbol', 'N', ['--backend', 'cuda', '--gpu-device', '2', '--batch-size', '1', '--stats'])
		constructor.assert_called_once_with(2)
		self.assertIn('GPU scan', stderr.getvalue())
		self.assertIn('addresses/s', stderr.getvalue())
		self.assertEqual(1, len(accounts))
		backend.generate.assert_not_called()
		facade = SymbolFacade('mainnet')
		root = Bip32(facade.BIP32_CURVE_NAME).from_mnemonic(accounts[0]['mnemonic'], '')
		self.assertEqual(str(facade.bip32_node_to_key_pair(root.derive_path(facade.bip32_path(0))).private_key), accounts[0]['private key'])

	def test_rejects_invalid_cuda_options(self):
		for option, value in [('--batch-size', '0'), ('--batch-size', '-1'), ('--gpu-device', '-1'), ('--workers', '0')]:
			with self.subTest(option=option, value=value):
				with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
					main(['--patterns', 'N', option, value])
				self.assertEqual(2, result.exception.code)
