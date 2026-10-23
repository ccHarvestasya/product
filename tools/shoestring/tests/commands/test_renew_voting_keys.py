import os
import shutil
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from symbolchain.CryptoTypes import PrivateKey
from symbolchain.facade.SymbolFacade import SymbolFacade
from symbolchain.sc import Cosignature, LinkAction, Signature, TransactionFactory, TransactionType
from symbolchain.symbol.KeyPair import KeyPair
from symbolchain.symbol.Network import NetworkTimestamp
from symbolchain.symbol.VotingKeysGenerator import VotingKeysGenerator
from symbollightapi.model.Exceptions import NodeException

from shoestring.__main__ import main
from shoestring.internal.CertificateFactory import CertificateFactory
from shoestring.internal.NodeFeatures import NodeFeatures
from shoestring.internal.OpensslExecutor import OpensslExecutor
from shoestring.internal.PackageResolver import download_and_extract_package
from shoestring.internal.PeerDownloader import download_peers
from shoestring.internal.PemUtils import read_public_key_from_public_key_pem_file
from shoestring.internal.VoterConfigurator import inspect_voting_key_files

from ..test.ConfigurationTestUtils import prepare_shoestring_configuration
from ..test.LogTestUtils import assert_message_is_logged
from ..test.MockNodewatchServer import setup_mock_nodewatch_server
from ..test.TestPackager import prepare_testnet_package
from ..test.TransactionTestUtils import AggregateDescriptor, LinkDescriptor, assert_aggregate_transaction, assert_link_transaction

# region server fixture


@pytest.fixture
async def server(aiohttp_client):
	return await setup_mock_nodewatch_server(aiohttp_client, True)


# mock server is configured to return last finalized height as 2033136,
# which corresponds to the following epochs
# -----------------------------------------------
# current epoch = 1 + ceil(2033136 / 720) = 2825
# one epoch padding                       =    1
# grace period padding                    =    1
# -----------------------------------------------
# start epoch                             = 2827
# max voting key lifetime                 =  720
# start epoch inclusion adjustment        =   -1
#  -----------------------------------------------
# end epoch                               = 3546

# endregion


# region utils

class PytestAsserter:
	@staticmethod
	def assertEqual(expected, actual):  # pylint: disable=invalid-name
		assert expected == actual


async def _prepare_output_directory(package_directory, output_directory, node_features, nodewatch_url):
	# extract resources
	prepare_testnet_package(package_directory, 'resources.zip')
	await download_and_extract_package(f'file://{package_directory}/resources.zip', package_directory)
	(Path(package_directory) / 'shoestring.ini').unlink()  # remove template from package (configuration will be recreated later)

	resources_directory = output_directory / 'userconfig' / 'resources'
	shutil.copytree(package_directory / 'resources', resources_directory)
	await download_peers(nodewatch_url, resources_directory)

	# prepare CA pem file
	certificates_directory = output_directory / 'keys' / 'cert'
	certificates_directory.mkdir(parents=True)

	openssl_executor = OpensslExecutor(os.environ.get('OPENSSL_EXECUTABLE', 'openssl'))
	with CertificateFactory(openssl_executor, certificates_directory / 'ca.key.pem') as factory:
		factory.generate_random_ca_private_key()
		factory.export_ca()
		factory.extract_ca_public_key()
		factory.package(certificates_directory)

	# create voting keys directory
	if NodeFeatures.VOTER in node_features:
		(output_directory / 'keys' / 'voting').mkdir()


def _map_voting_key_descriptors_to_tuples(voting_key_descriptors):
	return [(descriptor.ordinal, descriptor.start_epoch, descriptor.end_epoch) for descriptor in voting_key_descriptors]


def _write_voting_keys_file(directory, ordinal, start_epoch, end_epoch):
	voting_key_pair = KeyPair(PrivateKey.random())
	voting_keys_generator = VotingKeysGenerator(voting_key_pair)
	voting_key_buffer = voting_keys_generator.generate(start_epoch, end_epoch)

	output_filepath = Path(directory) / f'private_key_tree{ordinal}.dat'
	with open(output_filepath, 'wb') as outfile:
		outfile.write(voting_key_buffer)

	return voting_key_pair.public_key


def _read_transaction(directory):
	with open(Path(directory) / 'renew_voting_keys_transaction.dat', 'rb') as infile:
		transaction_bytes = infile.read()
		return TransactionFactory.deserialize(transaction_bytes)


def _set_registered_voting_keys(mock_server, descriptors):
	mock_server.mock.voting_public_keys = [{
		'publicKey': str(descriptor.public_key), 'startEpoch': descriptor.start_epoch, 'endEpoch': descriptor.end_epoch
	} for descriptor in descriptors]


@pytest.fixture
async def renewal_context(server):  # pylint: disable=redefined-outer-name
	with tempfile.TemporaryDirectory() as output_directory:
		with tempfile.TemporaryDirectory() as package_directory:
			directory = Path(output_directory)
			await _prepare_output_directory(Path(package_directory), directory, NodeFeatures.VOTER, server.make_url(''))
			config_filepath = prepare_shoestring_configuration(package_directory, NodeFeatures.VOTER, server.make_url(''))
			yield SimpleNamespace(
				directory=directory,
				keys_directory=directory / 'keys' / 'voting',
				args=['renew-voting-keys', '--config', str(config_filepath), '--directory', output_directory])

# endregion


# pylint: disable=invalid-name


async def test_renew_voting_keys_fails_when_node_is_not_voter(server, caplog):  # pylint: disable=redefined-outer-name
	# Arrange:
	with tempfile.TemporaryDirectory() as output_directory:
		with tempfile.TemporaryDirectory() as package_directory:
			node_features = NodeFeatures.PEER | NodeFeatures.API | NodeFeatures.HARVESTER
			await _prepare_output_directory(Path(package_directory), Path(output_directory), node_features, server.make_url(''))
			config_filepath = prepare_shoestring_configuration(package_directory, node_features)

			# Act:
			await main([
				'renew-voting-keys',
				'--config', str(config_filepath),
				'--directory', output_directory
			])

			# Assert: error is raised
			assert_message_is_logged('node is not configured for voting, aborting', caplog)

			# - voting keys directory does not exist
			assert not (Path(output_directory) / 'keys' / 'voting').exists()

			# - no transaction is created
			assert not (Path(output_directory) / 'renew_voting_keys_transaction.dat').exists()


async def test_can_renew_voting_keys_when_none_are_present(server, caplog):  # pylint: disable=redefined-outer-name
	# Arrange:
	with tempfile.TemporaryDirectory() as output_directory:
		with tempfile.TemporaryDirectory() as package_directory:
			await _prepare_output_directory(Path(package_directory), Path(output_directory), NodeFeatures.VOTER, server.make_url(''))
			config_filepath = prepare_shoestring_configuration(package_directory, NodeFeatures.VOTER, server.make_url(''))

			# Act:
			await main([
				'renew-voting-keys',
				'--config', str(config_filepath),
				'--directory', output_directory
			])

			# Assert: warning is raised
			assert_message_is_logged('voting is enabled, but no existing voting key files were found', caplog)

			# - new voting keys file is created
			voting_key_descriptors = inspect_voting_key_files(Path(output_directory) / 'keys' / 'voting')
			assert [(1, 2827, 3546)] == _map_voting_key_descriptors_to_tuples(voting_key_descriptors)

			# - transaction is created
			transaction = _read_transaction(output_directory)
			ca_public_key = read_public_key_from_public_key_pem_file(Path(output_directory) / 'keys' / 'cert' / 'ca.pubkey.pem')
			assert_aggregate_transaction(PytestAsserter(), transaction, AggregateDescriptor(
				168 + 96,
				200,
				123456789 + 1 * 60 * 60 * 1000,
				ca_public_key))
			assert 1 == len(transaction.transactions)

			assert_link_transaction(PytestAsserter(), transaction.transactions[0], LinkDescriptor(
				TransactionType.VOTING_KEY_LINK,
				voting_key_descriptors[0].public_key,
				LinkAction.LINK,
				(2827, 3546)))


async def test_can_renew_voting_keys_when_some_are_present_and_active(server):  # pylint: disable=redefined-outer-name
	# Arrange:
	with tempfile.TemporaryDirectory() as output_directory:
		with tempfile.TemporaryDirectory() as package_directory:
			await _prepare_output_directory(Path(package_directory), Path(output_directory), NodeFeatures.VOTER, server.make_url(''))
			config_filepath = prepare_shoestring_configuration(package_directory, NodeFeatures.VOTER, server.make_url(''))

			voting_keys_directory = Path(output_directory) / 'keys' / 'voting'
			_write_voting_keys_file(voting_keys_directory, 1, 2800, 2899)
			_write_voting_keys_file(voting_keys_directory, 2, 2900, 2999)
			_set_registered_voting_keys(server, inspect_voting_key_files(voting_keys_directory))

			# Act:
			await main([
				'renew-voting-keys',
				'--config', str(config_filepath),
				'--directory', output_directory
			])

			# Assert: existing voting keys files are preserved and new voting keys file is created
			voting_key_descriptors = inspect_voting_key_files(voting_keys_directory)
			assert [
				(1, 2800, 2899),
				(2, 2900, 2999),
				(3, 3000, 3719)
			] == _map_voting_key_descriptors_to_tuples(voting_key_descriptors)

			# - transaction is created
			transaction = _read_transaction(output_directory)
			ca_public_key = read_public_key_from_public_key_pem_file(Path(output_directory) / 'keys' / 'cert' / 'ca.pubkey.pem')
			assert_aggregate_transaction(PytestAsserter(), transaction, AggregateDescriptor(
				168 + 96,
				200,
				123456789 + 1 * 60 * 60 * 1000,
				ca_public_key))
			assert 1 == len(transaction.transactions)

			assert_link_transaction(PytestAsserter(), transaction.transactions[0], LinkDescriptor(
				TransactionType.VOTING_KEY_LINK,
				voting_key_descriptors[-1].public_key,
				LinkAction.LINK,
				(3000, 3719)))


async def test_can_renew_voting_keys_when_some_are_present_and_inactive(server):  # pylint: disable=redefined-outer-name
	# Arrange:
	with tempfile.TemporaryDirectory() as output_directory:
		with tempfile.TemporaryDirectory() as package_directory:
			await _prepare_output_directory(Path(package_directory), Path(output_directory), NodeFeatures.VOTER, server.make_url(''))
			config_filepath = prepare_shoestring_configuration(package_directory, NodeFeatures.VOTER, server.make_url(''))

			voting_keys_directory = Path(output_directory) / 'keys' / 'voting'
			expired_root_voting_public_key_1 = _write_voting_keys_file(voting_keys_directory, 1, 2600, 2699)
			expired_root_voting_public_key_2 = _write_voting_keys_file(voting_keys_directory, 2, 2700, 2799)
			_write_voting_keys_file(voting_keys_directory, 3, 2800, 2825)  # last epoch matches current epoch
			_write_voting_keys_file(voting_keys_directory, 4, 2826, 2999)
			_set_registered_voting_keys(server, inspect_voting_key_files(voting_keys_directory))

			# Act:
			await main([
				'renew-voting-keys',
				'--config', str(config_filepath),
				'--directory', output_directory
			])

			# Assert: inactive voting keys files are deleted, active voting keys files are preserved and new voting keys file is created
			voting_key_descriptors = inspect_voting_key_files(voting_keys_directory)
			assert [
				(1, 2800, 2825),
				(2, 2826, 2999),
				(3, 3000, 3719),
			] == _map_voting_key_descriptors_to_tuples(voting_key_descriptors)

			# - transaction is created
			transaction = _read_transaction(output_directory)
			ca_public_key = read_public_key_from_public_key_pem_file(Path(output_directory) / 'keys' / 'cert' / 'ca.pubkey.pem')
			assert_aggregate_transaction(PytestAsserter(), transaction, AggregateDescriptor(
				168 + 3 * 96,
				200,
				123456789 + 1 * 60 * 60 * 1000,
				ca_public_key))
			assert 3 == len(transaction.transactions)

			assert_link_transaction(PytestAsserter(), transaction.transactions[0], LinkDescriptor(
				TransactionType.VOTING_KEY_LINK,
				expired_root_voting_public_key_1,
				LinkAction.UNLINK,
				(2600, 2699)))
			assert_link_transaction(PytestAsserter(), transaction.transactions[1], LinkDescriptor(
				TransactionType.VOTING_KEY_LINK,
				expired_root_voting_public_key_2,
				LinkAction.UNLINK,
				(2700, 2799)))
			assert_link_transaction(PytestAsserter(), transaction.transactions[2], LinkDescriptor(
				TransactionType.VOTING_KEY_LINK,
				voting_key_descriptors[-1].public_key,
				LinkAction.LINK,
				(3000, 3719)))


async def test_cannot_renew_voting_keys_when_max_keys_are_active(server, caplog):  # pylint: disable=redefined-outer-name
	# Arrange:
	with tempfile.TemporaryDirectory() as output_directory:
		with tempfile.TemporaryDirectory() as package_directory:
			await _prepare_output_directory(Path(package_directory), Path(output_directory), NodeFeatures.VOTER, server.make_url(''))
			config_filepath = prepare_shoestring_configuration(package_directory, NodeFeatures.VOTER, server.make_url(''))

			voting_keys_directory = Path(output_directory) / 'keys' / 'voting'
			_write_voting_keys_file(voting_keys_directory, 1, 2800, 2825)  # last epoch matches current epoch
			_write_voting_keys_file(voting_keys_directory, 2, 3100, 3199)
			_write_voting_keys_file(voting_keys_directory, 3, 3200, 3299)
			_set_registered_voting_keys(server, inspect_voting_key_files(voting_keys_directory))

			# Act:
			await main([
				'renew-voting-keys',
				'--config', str(config_filepath),
				'--directory', output_directory
			])

			# Assert: error is raised
			assert_message_is_logged('maximum number of voting keys are already registered for this account', caplog)

			# - no voting keys files are created or changed
			voting_key_descriptors = inspect_voting_key_files(voting_keys_directory)
			assert [
				(1, 2800, 2825),
				(2, 3100, 3199),
				(3, 3200, 3299)
			] == _map_voting_key_descriptors_to_tuples(voting_key_descriptors)

			# no transaction is created
			assert not (Path(output_directory) / 'renew_voting_keys_transaction.dat').exists()


# pylint: disable=redefined-outer-name


@pytest.mark.parametrize('has_expired_link', [False, True])
async def test_repeated_renewal_reuses_unregistered_key(renewal_context, server, has_expired_link):
	if has_expired_link:
		server.mock.voting_public_keys = [{
			'publicKey': str(KeyPair(PrivateKey.random()).public_key), 'startEpoch': 2700, 'endEpoch': 2799
		}]
	await main(renewal_context.args)
	original_keys = inspect_voting_key_files(renewal_context.keys_directory)
	original_files = {path.name: path.read_bytes() for path in renewal_context.keys_directory.iterdir()}

	await main(renewal_context.args)

	assert original_files == {path.name: path.read_bytes() for path in renewal_context.keys_directory.iterdir()}
	transaction = _read_transaction(renewal_context.directory)
	assert (2 if has_expired_link else 1) == len(transaction.transactions)
	assert original_keys[0].public_key.bytes == transaction.transactions[-1].linked_public_key.bytes
	assert 0o600 == (renewal_context.directory / 'renew_voting_keys_transaction.dat').stat().st_mode & 0o777

	# Once the previous key is registered, a subsequent renewal creates the next key.
	_set_registered_voting_keys(server, original_keys)
	await main(renewal_context.args)
	keys = inspect_voting_key_files(renewal_context.keys_directory)
	assert 2 == len(keys)
	assert original_keys[0].end_epoch + 1 == keys[1].start_epoch
	assert keys[0].public_key != keys[1].public_key


@pytest.mark.parametrize('has_expired_files', [False, True])
async def test_missing_registered_keys_still_fill_limit(renewal_context, server, caplog, has_expired_files):
	server.mock.voting_public_keys = [{
		'publicKey': str(KeyPair(PrivateKey.random()).public_key), 'startEpoch': start, 'endEpoch': start + 99
	} for start in (2800, 2900, 3000)]
	if has_expired_files:
		_write_voting_keys_file(renewal_context.keys_directory, 1, 2600, 2699)
		_write_voting_keys_file(renewal_context.keys_directory, 2, 2700, 2799)
	original_files = {path.name: path.read_bytes() for path in renewal_context.keys_directory.iterdir()}

	await main(renewal_context.args)

	assert_message_is_logged('maximum number of voting keys are already registered for this account', caplog)
	assert original_files == {path.name: path.read_bytes() for path in renewal_context.keys_directory.iterdir()}
	assert not (renewal_context.directory / 'renew_voting_keys_transaction.dat').exists()
	assert not any(url.endswith('/node/time') for url in server.mock.urls)


async def test_missing_future_key_is_preserved_and_followed(renewal_context, server, caplog):
	public_key = KeyPair(PrivateKey.random()).public_key
	server.mock.voting_public_keys = [{'publicKey': str(public_key), 'startEpoch': 2900, 'endEpoch': 2999}]
	await main(renewal_context.args)
	transaction = _read_transaction(renewal_context.directory)
	assert 1 == len(transaction.transactions)
	assert LinkAction.LINK == transaction.transactions[0].link_action
	assert 3000 == transaction.transactions[0].start_epoch.value
	assert str(public_key) in caplog.text


async def test_local_expired_keys_are_not_unlinked_without_registration(renewal_context):
	_write_voting_keys_file(renewal_context.keys_directory, 1, 2700, 2799)
	await main(renewal_context.args)
	transaction = _read_transaction(renewal_context.directory)
	assert 1 == len(transaction.transactions)
	assert LinkAction.LINK == transaction.transactions[0].link_action
	assert 2827 == transaction.transactions[0].start_epoch.value


async def test_multiple_pending_keys_preserve_files_and_output(renewal_context):
	await main(renewal_context.args)
	_write_voting_keys_file(renewal_context.keys_directory, 3, 3547, 3646)
	original_files = {path.name: path.read_bytes() for path in renewal_context.keys_directory.iterdir()}
	transaction_path = renewal_context.directory / 'renew_voting_keys_transaction.dat'
	original_transaction = transaction_path.read_bytes()

	with pytest.raises(RuntimeError, match='multiple'):
		await main(renewal_context.args)

	assert original_files == {path.name: path.read_bytes() for path in renewal_context.keys_directory.iterdir()}
	assert original_transaction == transaction_path.read_bytes()


@pytest.mark.parametrize('source', ['account_links', 'network_time'])
async def test_network_failure_precedes_file_changes(renewal_context, source):
	await main(renewal_context.args)
	original_files = {path.name: path.read_bytes() for path in renewal_context.keys_directory.iterdir()}
	transaction_path = renewal_context.directory / 'renew_voting_keys_transaction.dat'
	original_transaction = transaction_path.read_bytes()
	with patch(f'shoestring.commands.renew_voting_keys.SymbolConnector.{source}', side_effect=NodeException('unavailable')):
		with pytest.raises(NodeException):
			await main(renewal_context.args)
	assert original_files == {path.name: path.read_bytes() for path in renewal_context.keys_directory.iterdir()}
	assert original_transaction == transaction_path.read_bytes()


@pytest.mark.parametrize('has_output', [False, True])
async def test_save_failure_can_retry_without_new_keys(renewal_context, has_output):
	transaction_path = renewal_context.directory / 'renew_voting_keys_transaction.dat'
	if has_output:
		await main(renewal_context.args)
	original_transaction = transaction_path.read_bytes() if has_output else None
	with patch('shoestring.internal.VotingKeyRenewal.Path.replace', side_effect=OSError('save failed')):
		with pytest.raises(OSError, match='save failed'):
			await main(renewal_context.args)
	if has_output:
		assert original_transaction == transaction_path.read_bytes()
	else:
		assert not transaction_path.exists()
	assert not list(renewal_context.directory.glob('.renew_voting_keys_*.tmp'))
	original_keys = inspect_voting_key_files(renewal_context.keys_directory)

	await main(renewal_context.args)

	assert original_keys == inspect_voting_key_files(renewal_context.keys_directory)
	assert original_keys[0].public_key.bytes == _read_transaction(renewal_context.directory).transactions[-1].linked_public_key.bytes


@pytest.mark.parametrize('kind', [
	'signed', 'cosigned', 'corrupt', 'foreign_account', 'foreign_network', 'unrelated', 'empty',
	'foreign_embedded', 'foreign_embedded_network', 'nonaggregate', 'trailing'
])
async def test_existing_transaction_output_is_protected(renewal_context, kind):
	await main(renewal_context.args)
	transaction = _read_transaction(renewal_context.directory)
	if 'signed' == kind:
		transaction.signature = Signature(bytes([1]) * 64)
	elif 'cosigned' == kind:
		transaction.cosignatures = [Cosignature()]
	elif 'foreign_account' == kind:
		transaction.signer_public_key = type(transaction.signer_public_key)(bytes([1]) * 32)
	elif 'foreign_network' == kind:
		transaction.network = type(transaction.network).MAINNET
	elif 'unrelated' == kind:
		transaction.transactions[0].type_ = TransactionType.ACCOUNT_KEY_LINK
	elif 'empty' == kind:
		transaction.transactions = []
	elif 'foreign_embedded' == kind:
		transaction.transactions[0].signer_public_key = type(transaction.signer_public_key)(bytes([1]) * 32)
	elif 'foreign_embedded_network' == kind:
		transaction.transactions[0].network = type(transaction.network).MAINNET
	elif 'nonaggregate' == kind:
		transaction = SymbolFacade('testnet').transaction_factory.create({
			'type': 'voting_key_link_transaction_v1', 'signer_public_key': transaction.signer_public_key.bytes,
			'linked_public_key': transaction.transactions[0].linked_public_key.bytes,
			'start_epoch': 2827, 'end_epoch': 3546, 'link_action': 'link', 'deadline': 1
		})
	transaction_path = renewal_context.directory / 'renew_voting_keys_transaction.dat'
	payload = b'corrupt' if 'corrupt' == kind else transaction.serialize()
	if 'trailing' == kind:
		payload += b'extra data'
	transaction_path.write_bytes(payload)
	original_keys = inspect_voting_key_files(renewal_context.keys_directory)

	with pytest.raises(RuntimeError, match='cannot overwrite'):
		await main(renewal_context.args)

	assert payload == transaction_path.read_bytes()
	assert original_keys == inspect_voting_key_files(renewal_context.keys_directory)


async def test_reused_key_gets_a_new_transaction_deadline(renewal_context):
	await main(renewal_context.args)
	previous_transaction = _read_transaction(renewal_context.directory)
	previous_keys = inspect_voting_key_files(renewal_context.keys_directory)
	with patch('shoestring.commands.renew_voting_keys.SymbolConnector.network_time', return_value=NetworkTimestamp(123516789)):
		await main(renewal_context.args)
	assert previous_keys == inspect_voting_key_files(renewal_context.keys_directory)
	assert previous_transaction.deadline.value + 60000 == _read_transaction(renewal_context.directory).deadline.value


async def test_unsigned_bonded_output_can_be_regenerated(renewal_context):
	await main(renewal_context.args)
	previous_keys = inspect_voting_key_files(renewal_context.keys_directory)
	transaction = _read_transaction(renewal_context.directory)
	transaction.type_ = TransactionType.AGGREGATE_BONDED
	(renewal_context.directory / 'renew_voting_keys_transaction.dat').write_bytes(transaction.serialize())
	await main(renewal_context.args)
	assert previous_keys == inspect_voting_key_files(renewal_context.keys_directory)
