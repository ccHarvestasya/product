import json
import tempfile
from collections import namedtuple
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from symbolchain.CryptoTypes import PrivateKey
from symbolchain.symbol.KeyPair import KeyPair
from symbolchain.symbol.VotingKeysGenerator import VotingKeysGenerator
from symbollightapi.model.Exceptions import NodeException

from shoestring.commands.health import run_main
from shoestring.healthagents.voting_keys import NAME, should_run, validate
from shoestring.internal.ConfigurationManager import ConfigurationManager
from shoestring.internal.NodeFeatures import NodeFeatures
from shoestring.internal.Preparer import Preparer
from shoestring.internal.ShoestringConfiguration import NodeConfiguration, ServicesConfiguration, ShoestringConfiguration
from shoestring.internal.VoterConfigurator import inspect_voting_key_files

from ..test.LogTestUtils import LogLevel, assert_all_messages_are_logged, assert_max_log_level, assert_message_is_logged
from ..test.MockNodewatchServer import setup_mock_nodewatch_server

# region server fixture


@pytest.fixture
async def server(aiohttp_client):
	return await setup_mock_nodewatch_server(aiohttp_client, True)

# endregion


# pylint: disable=invalid-name


# region should_run

def test_should_run_for_voter_role():
	# Act + Assert:
	assert should_run(NodeConfiguration(NodeFeatures.VOTER, *([None] * 7)))

	for features in (NodeFeatures.PEER, NodeFeatures.API, NodeFeatures.HARVESTER):
		assert not should_run(NodeConfiguration(features, *([None] * 7))), str(features)

# endregion


# region validate

def _assert_all_messages_are_logged(expected_messages, caplog, directories, mock_server):
	assert_all_messages_are_logged([
		'detected last finalized height as 2033136',
		'detected current finalization epoch as 2825',
		f'loading api endpoints from {directories.resources / "peers-p2p.json"}\'',
		f'connecting to {mock_server.make_url("")}'
	] + expected_messages, caplog)


def _prepare_directory(output_directory, mock_server):
	directories = Preparer.DirectoryLocator(None, Path(output_directory))
	directories.resources.mkdir(parents=True)
	directories.voting_keys.mkdir(parents=True)
	directories.certificates.mkdir(parents=True)
	public_key = Ed25519PublicKey.from_public_bytes(KeyPair(PrivateKey.random()).public_key.bytes)
	(directories.certificates / 'ca.pubkey.pem').write_bytes(public_key.public_bytes(
		encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
	(directories.resources / 'peers-p2p.json').write_text(json.dumps({'knownPeers': [{
		'metadata': {'roles': 'Peer,Api'},
		'endpoint': {'host': mock_server.make_url('').host, 'api_port': mock_server.port}
	}]}), encoding='utf8')

	with open(directories.resources / 'config-network.properties', 'wt', encoding='utf8') as outfile:
		outfile.write('\n'.join([
			'[chain]',
			'',
			'votingSetGrouping = 720'
		]))

	return directories


def _write_voting_keys_file(directory, ordinal, start_epoch, end_epoch):
	voting_keys_generator = VotingKeysGenerator(KeyPair(PrivateKey.random()))
	voting_key_buffer = voting_keys_generator.generate(start_epoch, end_epoch)

	output_filepath = directory / f'private_key_tree{ordinal}.dat'
	with open(output_filepath, 'wb') as outfile:
		outfile.write(voting_key_buffer)

	output_filepath.chmod(0o600)


def _create_context(directories, mock_server):
	HealthAgentContext = namedtuple('HealthAgentContext', ['config_manager', 'directories', 'config'])
	return HealthAgentContext(
		ConfigurationManager(directories.resources),
		directories,
		ShoestringConfiguration(
			'testnet', None, ServicesConfiguration(mock_server.make_url('')), None, None,
			NodeConfiguration(NodeFeatures.VOTER, *([None] * 7))))


async def _dispatch_validate(directories, mock_server, registered_keys):
	mock_server.mock.voting_public_keys = None if registered_keys is None else [{
		'publicKey': str(key.public_key), 'startEpoch': key.start_epoch, 'endEpoch': key.end_epoch
	} for key in registered_keys]
	await validate(_create_context(directories, mock_server))


@pytest.fixture
def health_context(server):  # pylint: disable=redefined-outer-name
	with tempfile.TemporaryDirectory() as output_directory:
		yield _create_context(_prepare_directory(output_directory, server), server)


async def test_validate_fails_when_past_voting_keys_are_present(server, caplog):  # pylint: disable=redefined-outer-name
	# Arrange:
	with tempfile.TemporaryDirectory() as output_directory:
		directories = _prepare_directory(output_directory, server)
		_write_voting_keys_file(directories.voting_keys, 1, 2725, 2824)

		# Act:
		await _dispatch_validate(directories, server, inspect_voting_key_files(directories.voting_keys))

		# Assert:
		_assert_all_messages_are_logged([
			'expired voting keys discovered for epochs 2725 to 2824',
			'no locally available linked voting keys cover the current epoch 2825'
		], caplog, directories, server)
		assert_max_log_level(LogLevel.ERROR, caplog)


async def test_validate_warns_when_past_and_current_voting_keys_are_present(server, caplog):  # pylint: disable=redefined-outer-name
	# Arrange:
	with tempfile.TemporaryDirectory() as output_directory:
		directories = _prepare_directory(output_directory, server)
		_write_voting_keys_file(directories.voting_keys, 1, 2725, 2824)
		_write_voting_keys_file(directories.voting_keys, 2, 2825, 2924)

		# Act:
		await _dispatch_validate(directories, server, inspect_voting_key_files(directories.voting_keys))

		# Assert:
		_assert_all_messages_are_logged([
			'expired voting keys discovered for epochs 2725 to 2824',
			'active voting keys discovered for epochs 2825 to 2924',
			'locally available voting keys are linked from the current epoch 2825 until epoch 2924'
		], caplog, directories, server)
		assert_max_log_level(LogLevel.WARNING, caplog)


async def test_validate_passes_when_current_voting_keys_are_present(server, caplog):  # pylint: disable=redefined-outer-name
	# Arrange:
	with tempfile.TemporaryDirectory() as output_directory:
		directories = _prepare_directory(output_directory, server)
		_write_voting_keys_file(directories.voting_keys, 1, 2825, 2924)

		# Act:
		await _dispatch_validate(directories, server, inspect_voting_key_files(directories.voting_keys))

		# Assert:
		_assert_all_messages_are_logged([
			'active voting keys discovered for epochs 2825 to 2924',
			'locally available voting keys are linked from the current epoch 2825 until epoch 2924'
		], caplog, directories, server)
		assert_max_log_level(LogLevel.INFO, caplog)


async def test_validate_fails_when_future_voting_keys_are_present(server, caplog):  # pylint: disable=redefined-outer-name
	# Arrange:
	with tempfile.TemporaryDirectory() as output_directory:
		directories = _prepare_directory(output_directory, server)
		_write_voting_keys_file(directories.voting_keys, 1, 2925, 3024)

		# Act:
		await _dispatch_validate(directories, server, inspect_voting_key_files(directories.voting_keys))

		# Assert:
		_assert_all_messages_are_logged([
			'future voting keys discovered for epochs 2925 to 3024',
			'no locally available linked voting keys cover the current epoch 2825'
		], caplog, directories, server)
		assert_max_log_level(LogLevel.ERROR, caplog)


async def test_validate_passes_when_current_and_future_voting_keys_are_present(server, caplog):  # pylint: disable=redefined-outer-name
	# Arrange:
	with tempfile.TemporaryDirectory() as output_directory:
		directories = _prepare_directory(output_directory, server)
		_write_voting_keys_file(directories.voting_keys, 1, 2825, 2924)
		_write_voting_keys_file(directories.voting_keys, 2, 2925, 3024)

		# Act:
		await _dispatch_validate(directories, server, inspect_voting_key_files(directories.voting_keys))

		# Assert:
		_assert_all_messages_are_logged([
			'active voting keys discovered for epochs 2825 to 2924',
			'future voting keys discovered for epochs 2925 to 3024',
			'locally available voting keys are linked from the current epoch 2825 until epoch 3024'
		], caplog, directories, server)
		assert_max_log_level(LogLevel.INFO, caplog)


async def test_validate_fails_when_past_and_future_voting_keys_are_present(server, caplog):  # pylint: disable=redefined-outer-name
	# Arrange:
	with tempfile.TemporaryDirectory() as output_directory:
		directories = _prepare_directory(output_directory, server)
		_write_voting_keys_file(directories.voting_keys, 1, 2725, 2824)
		_write_voting_keys_file(directories.voting_keys, 2, 2925, 3024)

		# Act:
		await _dispatch_validate(directories, server, inspect_voting_key_files(directories.voting_keys))

		# Assert:
		_assert_all_messages_are_logged([
			'expired voting keys discovered for epochs 2725 to 2824',
			'future voting keys discovered for epochs 2925 to 3024',
			'no locally available linked voting keys cover the current epoch 2825'
		], caplog, directories, server)
		assert_max_log_level(LogLevel.ERROR, caplog)


async def test_validate_passes_when_current_and_future_voting_keys_are_present_gaps(server, caplog):  # pylint: disable=redefined-outer-name
	# Arrange:
	with tempfile.TemporaryDirectory() as output_directory:
		directories = _prepare_directory(output_directory, server)
		_write_voting_keys_file(directories.voting_keys, 1, 2825, 2924)
		_write_voting_keys_file(directories.voting_keys, 2, 2925, 3024)
		_write_voting_keys_file(directories.voting_keys, 3, 3026, 3124)  # note the gap
		_write_voting_keys_file(directories.voting_keys, 4, 3125, 3224)

		# Act:
		await _dispatch_validate(directories, server, inspect_voting_key_files(directories.voting_keys))

		# Assert:
		_assert_all_messages_are_logged([
			'active voting keys discovered for epochs 2825 to 2924',
			'future voting keys discovered for epochs 2925 to 3024',
			'future voting keys discovered for epochs 3026 to 3124',
			'future voting keys discovered for epochs 3125 to 3224',
			'locally available voting keys are linked from the current epoch 2825 until epoch 3024'
		], caplog, directories, server)
		assert_max_log_level(LogLevel.INFO, caplog)

# endregion


# pylint: disable=redefined-outer-name


def _snapshot_files(directory):
	return {path.relative_to(directory): path.read_bytes() for path in directory.rglob('*') if path.is_file()}


@pytest.mark.parametrize('start_epoch', [2825, 2925])
@pytest.mark.parametrize('mismatch', ['file_only', 'registration_only', 'public_key', 'start_epoch', 'end_epoch'])
async def test_unmatched_keys_do_not_extend_coverage(health_context, server, caplog, start_epoch, mismatch):
	directories = health_context.directories
	if start_epoch > 2825:
		_write_voting_keys_file(directories.voting_keys, 1, 2825, 2924)
	_write_voting_keys_file(directories.voting_keys, 2, start_epoch, start_epoch + 99)
	keys = inspect_voting_key_files(directories.voting_keys)
	registration = keys[-1]
	if 'registration_only' == mismatch:
		(directories.voting_keys / 'private_key_tree2.dat').unlink()
	elif 'public_key' == mismatch:
		registration = registration._replace(public_key=KeyPair(PrivateKey.random()).public_key)
	elif 'start_epoch' == mismatch:
		registration = registration._replace(start_epoch=start_epoch + 1)
	elif 'end_epoch' == mismatch:
		registration = registration._replace(end_epoch=start_epoch + 100)
	registrations = keys[:-1] + ([] if 'file_only' == mismatch else [registration])
	original_files = _snapshot_files(directories.output_directory)

	await _dispatch_validate(directories, server, registrations)

	assert original_files == _snapshot_files(directories.output_directory)
	assert_max_log_level(LogLevel.ERROR if 2825 == start_epoch else LogLevel.WARNING, caplog)
	if 'registration_only' != mismatch:
		assert 'local voting key private_key_tree2.dat is not linked' in caplog.text
	if 'file_only' != mismatch:
		assert 'registered voting key has no matching local file' in caplog.text
	if start_epoch > 2825:
		assert_message_is_logged('locally available voting keys are linked from the current epoch 2825 until epoch 2924', caplog)
	else:
		assert 'locally available voting keys are linked from' not in caplog.text
		assert_message_is_logged('no locally available linked voting keys cover the current epoch 2825', caplog)


@pytest.mark.parametrize('ranges, expected_end', [
	([(9, 2825, 2924), (1, 2925, 3024)], 3024),
	([(1, 2825, 3024), (2, 2800, 2924), (3, 3025, 3124)], 3124),
	([(1, 2800, 2825), (2, 2826, 2925)], 2925)
])
async def test_coverage_uses_epoch_order_and_merges_ranges(health_context, server, caplog, ranges, expected_end):
	for ordinal, start_epoch, end_epoch in ranges:
		_write_voting_keys_file(health_context.directories.voting_keys, ordinal, start_epoch, end_epoch)
	await _dispatch_validate(health_context.directories, server, inspect_voting_key_files(health_context.directories.voting_keys))
	assert_message_is_logged(
		f'locally available voting keys are linked from the current epoch 2825 until epoch {expected_end}', caplog)
	assert_max_log_level(LogLevel.INFO, caplog)


async def test_expired_missing_registration_is_not_an_error(health_context, server, caplog):
	directories = health_context.directories
	_write_voting_keys_file(directories.voting_keys, 1, 2825, 2924)
	keys = inspect_voting_key_files(directories.voting_keys)
	await _dispatch_validate(directories, server, keys + [keys[0]._replace(start_epoch=2700, end_epoch=2799)])
	assert_max_log_level(LogLevel.INFO, caplog)
	assert 'no matching local file' not in caplog.text


@pytest.mark.parametrize('account_exists', [False, True])
async def test_empty_registrations_do_not_validate_local_keys(health_context, server, caplog, account_exists):
	_write_voting_keys_file(health_context.directories.voting_keys, 1, 2825, 2924)
	await _dispatch_validate(health_context.directories, server, [] if account_exists else None)
	assert_max_log_level(LogLevel.ERROR, caplog)
	assert 'locally available voting keys are linked from' not in caplog.text


@pytest.mark.parametrize('failure', ['network', 'no_endpoints', 'missing_ca', 'invalid_ca', 'invalid_peers', 'invalid_response'])
async def test_verification_failures_preserve_files_and_report_unknown(health_context, server, caplog, failure):
	directories = health_context.directories
	_write_voting_keys_file(directories.voting_keys, 1, 2825, 2924)
	if 'no_endpoints' == failure:
		(directories.resources / 'peers-p2p.json').unlink()
	elif 'missing_ca' == failure:
		(directories.certificates / 'ca.pubkey.pem').unlink()
	elif 'invalid_ca' == failure:
		(directories.certificates / 'ca.pubkey.pem').write_bytes(b'invalid pem')
	elif 'invalid_peers' == failure:
		(directories.resources / 'peers-p2p.json').write_text('{invalid json', encoding='utf8')
	elif 'invalid_response' == failure:
		server.mock.voting_public_keys = [{'publicKey': str(KeyPair(PrivateKey.random()).public_key)}]
	original_files = _snapshot_files(directories.output_directory)
	if 'network' == failure:
		with patch('shoestring.healthagents.voting_keys.SymbolConnector.account_links', side_effect=NodeException('offline')):
			await validate(health_context)
	else:
		await validate(health_context)
	assert_max_log_level(LogLevel.ERROR, caplog)
	assert 'cannot verify voting keys' in caplog.text
	assert 'no locally available linked voting keys cover' not in caplog.text
	assert 'locally available voting keys are linked from' not in caplog.text
	assert original_files == _snapshot_files(directories.output_directory)


@pytest.mark.parametrize('start_epoch, end_epoch', [(None, 2924), (2825, '2924'), (0, 2924), (2925, 2924)])
async def test_invalid_registration_ranges_are_unverifiable(health_context, server, caplog, start_epoch, end_epoch):
	server.mock.voting_public_keys = [{
		'publicKey': str(KeyPair(PrivateKey.random()).public_key), 'startEpoch': start_epoch, 'endEpoch': end_epoch
	}]
	await validate(health_context)
	assert_max_log_level(LogLevel.ERROR, caplog)
	assert 'invalid voting key epoch range in REST response' in caplog.text
	assert 'locally available voting keys are linked from' not in caplog.text


async def test_health_continues_after_voting_lookup_failure(health_context, caplog):
	following_agent = SimpleNamespace(NAME='following agent', should_run=Mock(return_value=True), validate=AsyncMock())
	skipped_agent = SimpleNamespace(should_run=Mock(return_value=False))
	modules = {
		'voting_keys': SimpleNamespace(NAME=NAME, should_run=should_run, validate=validate),
		'rest_api': following_agent
	}
	with patch.multiple(
		'shoestring.commands.health',
		parse_shoestring_configuration=Mock(return_value=health_context.config),
		HealthAgentContext=Mock(return_value=health_context),
		importlib=SimpleNamespace(import_module=lambda name: modules.get(name.rsplit('.', 1)[-1], skipped_agent))
	):
		with patch('shoestring.healthagents.voting_keys.SymbolConnector.account_links', side_effect=NodeException('offline')):
			await run_main(SimpleNamespace(config='unused', directory=str(health_context.directories.output_directory)))
	following_agent.validate.assert_awaited_once_with(health_context)
	assert 'cannot verify voting keys' in caplog.text
