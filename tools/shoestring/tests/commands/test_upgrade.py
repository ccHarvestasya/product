import shutil
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from shoestring.__main__ import main
from shoestring.commands import upgrade as upgrade_command
from shoestring.internal.ConfigurationManager import ConfigurationManager
from shoestring.internal.NodeFeatures import NodeFeatures

from ..test.ConfigurationTestUtils import prepare_shoestring_configuration
from ..test.FileSystemTestUtils import assert_expected_files_and_permissions
from ..test.MockNodewatchServer import setup_mock_nodewatch_server
from ..test.TestPackager import prepare_testnet_package
from .test_setup import (
	API_OUTPUT_FILES,
	HARVESTER_OUTPUT_FILES,
	HTTPS_OUTPUT_FILES,
	LIGHT_API_OUTPUT_FILES,
	PEER_OUTPUT_FILES,
	STATE_CHANGE_OUTPUT_FILES,
	VOTER_OUTPUT_FILES
)

# region server fixture


@pytest.fixture
async def server(aiohttp_client):
	return await setup_mock_nodewatch_server(aiohttp_client, True)

# endregion


# region changed files

PEER_CHANGED_FILES = [
	'docker-compose-recovery.yaml',
	'docker-compose.yaml',
	'userconfig',
	'userconfig/resources',
	'userconfig/resources/config-extensions-recovery.properties',
	'userconfig/resources/config-extensions-server.properties',
	'userconfig/resources/config-finalization.properties',
	'userconfig/resources/config-inflation.properties',
	'userconfig/resources/config-logging-recovery.properties',
	'userconfig/resources/config-logging-server.properties',
	'userconfig/resources/config-network.properties',
	'userconfig/resources/config-node.properties',
	'userconfig/resources/config-task.properties',
	'userconfig/resources/config-timesync.properties',
	'userconfig/resources/config-user.properties',
	'userconfig/resources/peers-p2p.json'
]

HTTPS_CHANGED_FILES = [
	'https-proxy',  # metadata is changed due to delete and add of file
	'https-proxy/nginx.conf.erb'
]

API_CHANGED_FILES = [
	'mongo',
	'mongo/mongoDbDrop.js',
	'mongo/mongoDbPrepare.js',
	'mongo/mongoLockHashDbPrepare.js',
	'mongo/mongoLockSecretDbPrepare.js',
	'mongo/mongoMetadataDbPrepare.js',
	'mongo/mongoMosaicDbPrepare.js',
	'mongo/mongoMultisigDbPrepare.js',
	'mongo/mongoNamespaceDbPrepare.js',
	'mongo/mongoRestrictionAccountDbPrepare.js',
	'mongo/mongoRestrictionMosaicDbPrepare.js',
	'startup',
	'startup/delayrestapi.sh',
	'startup/mongors.sh',
	'startup/startBroker.sh',
	'startup/startRecovery.sh',
	'startup/startServer.sh',
	'startup/wait.sh',
	'userconfig/resources/config-database.properties',
	'userconfig/resources/config-extensions-broker.properties',
	'userconfig/resources/config-logging-broker.properties',
	'userconfig/resources/config-messaging.properties',
	'userconfig/resources/config-pt.properties',
	'userconfig/resources/peers-api.json',
	'userconfig/rest.json'
]

LIGHT_API_CHANGED_FILES = [
	'userconfig/rest.json'
]

HARVESTER_CHANGED_FILES = [
	'userconfig/resources/config-harvesting.properties'
]

# endregion


# region assert_can_upgrade_node

def _set_hostname_in_overrides(user_overrides_filepath, hostname, friendly_name):
	with open(user_overrides_filepath, 'wt', encoding='utf8') as outfile:
		outfile.write('\n'.join([
			'[node.localnode]',
			'',
			f'host = {hostname}',  # must be a name that resolves properly
			f'friendlyName = {friendly_name}'
		]))


def _prepare_overrides(directory, friendly_name):
	_set_hostname_in_overrides(Path(directory) / 'user_overrides.ini', 'localhost', friendly_name)


def _get_mtimes_map(output_directory):
	return {str(path.relative_to(output_directory)): path.stat().st_mtime for path in Path(output_directory).glob('**/*')}


def _get_tree_snapshot(output_directory):
	return {
		str(path.relative_to(output_directory)): (
			path.is_dir(),
			path.stat().st_mode & 0o777,
			None if path.is_dir() else path.read_bytes()
		)
		for path in Path(output_directory).glob('**/*')
	}


def _read_friendly_name(config_manager):
	return config_manager.lookup('config-node.properties', [('localnode', 'friendlyName')])[0]


def _read_harvester_private_keys(config_manager):
	return config_manager.lookup('config-harvesting.properties', [
		('harvesting', 'harvesterSigningPrivateKey'),
		('harvesting', 'harvesterVrfPrivateKey')
	])


def _get_changed_files(map1, map2):
	return sorted([key for key, value in map1.items() if value != map2[key]])


def _assert_changed_files(setup_mtimes_map, output_directory, expected_changed_files):
	upgrade_mtimes_map = _get_mtimes_map(output_directory)
	changed_files = _get_changed_files(setup_mtimes_map, upgrade_mtimes_map)
	assert expected_changed_files == changed_files


async def _assert_can_upgrade_node(
	server,  # pylint: disable=redefined-outer-name
	node_features,
	expected_output_files,
	expected_changed_files,
	api_https=False,
	light_api=False,
	files_to_remove=None
):  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
	# Arrange:
	with tempfile.TemporaryDirectory() as output_directory:
		with tempfile.TemporaryDirectory() as package_directory:
			prepare_shoestring_configuration(package_directory, node_features, server.make_url(''), api_https=api_https, light_api=light_api)
			_prepare_overrides(package_directory, 'name from setup')
			prepare_testnet_package(package_directory, 'resources.zip')

			common_args = [
				'--config', str(Path(package_directory) / 'sai.shoestring.ini'),
				'--package', f'file://{Path(package_directory) / "resources.zip"}',
				'--directory', output_directory,
				'--overrides', str(Path(package_directory) / 'user_overrides.ini')
			]

			with tempfile.TemporaryDirectory() as ca_directory:
				# - prepare directory by running initial setup command
				await main([
					'setup',
					'--security', 'insecure',
					'--ca-key-path', str(Path(ca_directory) / 'xyz.key.pem'),
				] + common_args)

				setup_mtimes_map = _get_mtimes_map(output_directory)

				config_manager = ConfigurationManager(Path(output_directory) / 'userconfig' / 'resources')
				if NodeFeatures.HARVESTER in node_features:
					setup_harvester_private_keys = _read_harvester_private_keys(config_manager)

				if isinstance(files_to_remove, list):
					for filename in files_to_remove:
						(Path(output_directory) / filename).unlink()

				# Sanity:
				assert 'name from setup' == _read_friendly_name(config_manager)

				# Act: upgrade (with different overrides)
				_prepare_overrides(package_directory, 'name from upgrade')
				await main(['upgrade'] + common_args)

				# Assert: spot check all expected output files and permissions
				assert_expected_files_and_permissions(output_directory, expected_output_files)

				# - check expected changed files are changed
				_assert_changed_files(setup_mtimes_map, output_directory, expected_changed_files)

				# - check latest config overrides are used during upgrade
				assert 'name from upgrade' == _read_friendly_name(config_manager)

				if NodeFeatures.HARVESTER in node_features:
					# - original harvesting private keys are retained
					upgrade_harvester_private_keys = _read_harvester_private_keys(config_manager)
					assert setup_harvester_private_keys == upgrade_harvester_private_keys

# endregion


# pylint: disable=invalid-name


# region feature variance

async def test_can_upgrade_peer_node(server):  # pylint: disable=redefined-outer-name
	await _assert_can_upgrade_node(server, NodeFeatures.PEER, PEER_OUTPUT_FILES, PEER_CHANGED_FILES)


async def test_can_upgrade_api_node(server):  # pylint: disable=redefined-outer-name
	expected_output_files = {**PEER_OUTPUT_FILES, **API_OUTPUT_FILES}
	expected_changed_files = sorted(PEER_CHANGED_FILES + API_CHANGED_FILES)
	await _assert_can_upgrade_node(server, NodeFeatures.API, expected_output_files, expected_changed_files)


async def test_can_upgrade_api_node_with_https(server):  # pylint: disable=redefined-outer-name
	expected_output_files = {**PEER_OUTPUT_FILES, **API_OUTPUT_FILES, **HTTPS_OUTPUT_FILES}
	expected_changed_files = sorted(PEER_CHANGED_FILES + API_CHANGED_FILES + HTTPS_CHANGED_FILES)
	await _assert_can_upgrade_node(server, NodeFeatures.API, expected_output_files, expected_changed_files, api_https=True)


async def test_can_upgrade_light_api_node(server):  # pylint: disable=redefined-outer-name
	expected_output_files = {**PEER_OUTPUT_FILES, **LIGHT_API_OUTPUT_FILES}
	expected_changed_files = sorted(PEER_CHANGED_FILES + LIGHT_API_CHANGED_FILES)
	await _assert_can_upgrade_node(server, NodeFeatures.API, expected_output_files, expected_changed_files, light_api=True)


async def test_can_upgrade_light_api_node_with_https(server):  # pylint: disable=redefined-outer-name
	expected_output_files = {**PEER_OUTPUT_FILES, **LIGHT_API_OUTPUT_FILES, **HTTPS_OUTPUT_FILES}
	expected_changed_files = sorted(PEER_CHANGED_FILES + LIGHT_API_CHANGED_FILES + HTTPS_CHANGED_FILES)
	await _assert_can_upgrade_node(server, NodeFeatures.API, expected_output_files, expected_changed_files, api_https=True, light_api=True)


async def test_can_upgrade_harvester_node(server):  # pylint: disable=redefined-outer-name
	expected_output_files = {**PEER_OUTPUT_FILES, **HARVESTER_OUTPUT_FILES, **STATE_CHANGE_OUTPUT_FILES}
	expected_changed_files = sorted(PEER_CHANGED_FILES + HARVESTER_CHANGED_FILES)
	await _assert_can_upgrade_node(server, NodeFeatures.HARVESTER, expected_output_files, expected_changed_files)


async def test_can_upgrade_voter_node(server):  # pylint: disable=redefined-outer-name
	expected_output_files = {**PEER_OUTPUT_FILES, **VOTER_OUTPUT_FILES, **STATE_CHANGE_OUTPUT_FILES}
	await _assert_can_upgrade_node(server, NodeFeatures.VOTER, expected_output_files, PEER_CHANGED_FILES)


async def test_can_upgrade_full_node(server):  # pylint: disable=redefined-outer-name
	node_features = NodeFeatures.API | NodeFeatures.HARVESTER | NodeFeatures.VOTER
	expected_output_files = {
		**PEER_OUTPUT_FILES, **API_OUTPUT_FILES, **HARVESTER_OUTPUT_FILES, **VOTER_OUTPUT_FILES, **STATE_CHANGE_OUTPUT_FILES
	}
	expected_changed_files = sorted(PEER_CHANGED_FILES + API_CHANGED_FILES + HARVESTER_CHANGED_FILES)
	await _assert_can_upgrade_node(server, node_features, expected_output_files, expected_changed_files)


async def test_can_upgrade_node_without_docker_recovery_file(server):  # pylint: disable=redefined-outer-name
	expected_output_files = {**PEER_OUTPUT_FILES, **API_OUTPUT_FILES}
	expected_changed_files = sorted(PEER_CHANGED_FILES + API_CHANGED_FILES)
	await _assert_can_upgrade_node(
		server,
		NodeFeatures.API,
		expected_output_files,
		expected_changed_files,
		files_to_remove=['docker-compose-recovery.yaml']
	)


async def test_upgrade_failure_preserves_existing_node(server, monkeypatch):  # pylint: disable=redefined-outer-name
	with tempfile.TemporaryDirectory() as output_directory:
		with tempfile.TemporaryDirectory() as package_directory:
			prepare_shoestring_configuration(package_directory, NodeFeatures.PEER, server.make_url(''), api_https=False)
			_prepare_overrides(package_directory, 'name from setup')
			prepare_testnet_package(package_directory, 'resources.zip')

			common_args = [
				'--config', str(Path(package_directory) / 'sai.shoestring.ini'),
				'--package', f'file://{Path(package_directory) / "resources.zip"}',
				'--directory', output_directory,
				'--overrides', str(Path(package_directory) / 'user_overrides.ini')
			]

			with tempfile.TemporaryDirectory() as ca_directory:
				await main([
					'setup',
					'--security', 'insecure',
					'--ca-key-path', str(Path(ca_directory) / 'xyz.key.pem'),
				] + common_args)

				before_upgrade = _get_tree_snapshot(output_directory)

				async def fail_upgrade(_args):
					raise RuntimeError('upgrade failed')

				monkeypatch.setattr(upgrade_command, 'run_setup_main', fail_upgrade)
				with pytest.raises(RuntimeError, match='upgrade failed'):
					await main(['upgrade'] + common_args)

				assert before_upgrade == _get_tree_snapshot(output_directory)


async def test_upgrade_retains_staging_when_rollback_fails(tmp_path, monkeypatch):
	with tempfile.TemporaryDirectory() as package_directory:
		config_filepath = prepare_shoestring_configuration(package_directory, NodeFeatures.PEER, api_https=False)
		output_directory = tmp_path / 'output'
		output_directory.mkdir()
		retained_staging_directory = []

		async def skip_setup(_args):
			return None

		def fail_commit(_output_directory, staging_directory, _relative_paths):
			retained_staging_directory.append(staging_directory)
			raise upgrade_command.UpgradeRollbackError(staging_directory)

		monkeypatch.setattr(upgrade_command, 'run_setup_main', skip_setup)
		monkeypatch.setattr(upgrade_command, '_commit_upgrade', fail_commit)
		with pytest.raises(upgrade_command.UpgradeRollbackError):
			await upgrade_command.run_main(SimpleNamespace(
				config=str(config_filepath),
				directory=str(output_directory),
				package='mainnet',
				overrides=None,
				rest_overrides=None))

		assert retained_staging_directory[0].is_dir()
		shutil.rmtree(retained_staging_directory[0])


def test_prepare_staging_directory_creates_https_proxy_when_missing(tmp_path):
	staging_directory = tmp_path / 'staging'
	staging_directory.mkdir()
	output_directories = upgrade_command.Preparer.DirectoryLocator(None, tmp_path / 'output')
	staging_directories = upgrade_command.Preparer.DirectoryLocator(None, staging_directory)
	config = SimpleNamespace(node=SimpleNamespace(api_https=True, features=NodeFeatures.API))

	upgrade_command._prepare_staging_directory(output_directories, staging_directories, config)

	assert (staging_directory / 'userconfig' / 'resources').is_dir()
	assert (staging_directory / 'https-proxy').is_dir()


def test_commit_upgrade_rejects_missing_staged_path(tmp_path):
	output_directory = tmp_path / 'output'
	staging_directory = tmp_path / 'staging'
	output_directory.mkdir()
	staging_directory.mkdir()

	with pytest.raises(RuntimeError, match='upgrade did not produce userconfig'):
		upgrade_command._commit_upgrade(output_directory, staging_directory, ['userconfig'])

	assert not (output_directory / 'userconfig').exists()


def test_commit_upgrade_restores_previous_paths_when_switch_fails(tmp_path, monkeypatch):
	output_directory = tmp_path / 'output'
	staging_directory = tmp_path / 'staging'
	old_userconfig = output_directory / 'userconfig'
	new_userconfig = staging_directory / 'userconfig'
	old_compose = output_directory / 'docker-compose.yaml'
	new_compose = staging_directory / 'docker-compose.yaml'
	output_directory.mkdir()
	staging_directory.mkdir()
	old_userconfig.mkdir()
	new_userconfig.mkdir()
	(old_userconfig / 'config.properties').write_text('old', encoding='utf8')
	(new_userconfig / 'config.properties').write_text('new', encoding='utf8')
	old_compose.write_text('old', encoding='utf8')
	new_compose.write_text('new', encoding='utf8')

	original_rename = Path.rename

	def fail_compose_switch(path, target):
		if path == new_compose:
			raise OSError('simulated switch failure')

		return original_rename(path, target)

	monkeypatch.setattr(Path, 'rename', fail_compose_switch)
	with pytest.raises(OSError, match='simulated switch failure'):
		upgrade_command._commit_upgrade(output_directory, staging_directory, ['userconfig', 'docker-compose.yaml'])

	assert (old_userconfig / 'config.properties').read_text(encoding='utf8') == 'old'
	assert old_compose.read_text(encoding='utf8') == 'old'


def test_commit_upgrade_preserves_active_path_when_backup_fails(tmp_path, monkeypatch):
	output_directory = tmp_path / 'output'
	staging_directory = tmp_path / 'staging'
	old_compose = output_directory / 'docker-compose.yaml'
	new_compose = staging_directory / 'docker-compose.yaml'
	backup_compose = staging_directory / '.backup' / 'docker-compose.yaml'
	output_directory.mkdir()
	staging_directory.mkdir()
	old_compose.write_text('old', encoding='utf8')
	new_compose.write_text('new', encoding='utf8')

	original_rename = Path.rename

	def fail_backup(path, target):
		if path == old_compose and target == backup_compose:
			raise OSError('simulated backup failure')

		return original_rename(path, target)

	monkeypatch.setattr(Path, 'rename', fail_backup)
	with pytest.raises(OSError, match='simulated backup failure'):
		upgrade_command._commit_upgrade(output_directory, staging_directory, ['docker-compose.yaml'])

	assert old_compose.read_text(encoding='utf8') == 'old'
	assert new_compose.read_text(encoding='utf8') == 'new'


def test_commit_upgrade_retains_staging_when_rollback_fails(tmp_path, monkeypatch):
	output_directory = tmp_path / 'output'
	staging_directory = tmp_path / 'staging'
	old_userconfig = output_directory / 'userconfig'
	new_userconfig = staging_directory / 'userconfig'
	old_compose = output_directory / 'docker-compose.yaml'
	new_compose = staging_directory / 'docker-compose.yaml'
	backup_compose = staging_directory / '.backup' / 'docker-compose.yaml'
	output_directory.mkdir()
	staging_directory.mkdir()
	old_userconfig.mkdir()
	new_userconfig.mkdir()
	(old_userconfig / 'config.properties').write_text('old', encoding='utf8')
	(new_userconfig / 'config.properties').write_text('new', encoding='utf8')
	old_compose.write_text('old', encoding='utf8')
	new_compose.write_text('new', encoding='utf8')

	original_rename = Path.rename

	def fail_rollback(path, target):
		if path == new_compose:
			raise OSError('simulated switch failure')
		if path == backup_compose and target == old_compose:
			raise OSError('simulated rollback failure')

		return original_rename(path, target)

	monkeypatch.setattr(Path, 'rename', fail_rollback)
	with pytest.raises(upgrade_command.UpgradeRollbackError, match='staging directory retained'):
		upgrade_command._commit_upgrade(output_directory, staging_directory, ['userconfig', 'docker-compose.yaml'])

	assert staging_directory.is_dir()
	assert backup_compose.is_file()
	assert not old_compose.exists()


def test_commit_upgrade_retains_staging_when_committed_rollback_fails(tmp_path, monkeypatch):
	output_directory = tmp_path / 'output'
	staging_directory = tmp_path / 'staging'
	old_userconfig = output_directory / 'userconfig'
	new_userconfig = staging_directory / 'userconfig'
	old_compose = output_directory / 'docker-compose.yaml'
	new_compose = staging_directory / 'docker-compose.yaml'
	backup_userconfig = staging_directory / '.backup' / 'userconfig'
	output_directory.mkdir()
	staging_directory.mkdir()
	old_userconfig.mkdir()
	new_userconfig.mkdir()
	(old_userconfig / 'config.properties').write_text('old', encoding='utf8')
	(new_userconfig / 'config.properties').write_text('new', encoding='utf8')
	old_compose.write_text('old', encoding='utf8')
	new_compose.write_text('new', encoding='utf8')

	original_rename = Path.rename

	def fail_committed_rollback(path, target):
		if path == old_compose:
			raise OSError('simulated backup failure')
		if path == output_directory / 'userconfig' and target == new_userconfig:
			raise OSError('simulated committed rollback failure')

		return original_rename(path, target)

	monkeypatch.setattr(Path, 'rename', fail_committed_rollback)
	with pytest.raises(upgrade_command.UpgradeRollbackError, match='staging directory retained'):
		upgrade_command._commit_upgrade(output_directory, staging_directory, ['userconfig', 'docker-compose.yaml'])

	assert staging_directory.is_dir()
	assert backup_userconfig.is_dir()
	assert (output_directory / 'userconfig').is_dir()

# endregion
