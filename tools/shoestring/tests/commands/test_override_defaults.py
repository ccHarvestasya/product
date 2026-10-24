import json
from pathlib import Path

import pytest

from shoestring.__main__ import main
from shoestring.internal.ConfigurationManager import ConfigurationManager
from shoestring.internal.NodeFeatures import NodeFeatures
from shoestring.wizard.ShoestringOperation import ShoestringOperation, build_shoestring_command

from ..test.ConfigurationTestUtils import prepare_shoestring_configuration
from ..test.MockNodewatchServer import setup_mock_nodewatch_server
from ..test.TestPackager import prepare_testnet_package

# pylint: disable=invalid-name


@pytest.fixture(name='deployment_args')
async def deployment_args_fixture(tmp_path, monkeypatch, aiohttp_client):
	server = await setup_mock_nodewatch_server(aiohttp_client, True)
	(tmp_path / 'custom').mkdir()
	(tmp_path / 'node').mkdir()
	prepare_shoestring_configuration(tmp_path / 'custom', NodeFeatures.API, server.make_url(''), api_https=False)
	prepare_testnet_package(tmp_path, 'resources.zip')
	monkeypatch.chdir(tmp_path)
	# Hostname validation is independent of override selection, including the legacy fallback hostname.
	monkeypatch.setattr('shoestring.commands.setup._resolve_hostname_and_configure_https', lambda _config, _preparer: 'localhost')
	return [
		'--config', 'custom/sai.shoestring.ini',
		'--package', f'file://{tmp_path / "resources.zip"}',
		'--directory', str(tmp_path / 'node')
	]


def _write_overrides(directory, friendly_name):
	directory.mkdir(exist_ok=True)
	(directory / 'overrides.ini').write_text(f'[node.localnode]\nhost = localhost\nfriendlyName = {friendly_name}\n', encoding='utf8')


def _write_rest_overrides(directory, animal):
	directory.mkdir(exist_ok=True)
	(directory / 'rest_overrides.json').write_text(json.dumps({'nodeMetadata': {'animal': animal}}), encoding='utf8')


@pytest.mark.parametrize('default_files', [(), ('ini',), ('json',), ('ini', 'json')])
@pytest.mark.parametrize('use_explicit', [False, True])
async def test_setup_and_upgrade_apply_override_defaults(deployment_args, default_files, use_explicit):
	# Config-adjacent files must not be selected implicitly.
	_write_overrides(Path('custom'), 'wrong directory')
	_write_rest_overrides(Path('custom'), 'wrong directory')
	_write_rest_overrides(Path('shoestring'), 'wrong working directory')
	_write_overrides(Path('shoestring'), 'wrong working directory')
	for command in ('setup', 'upgrade'):
		if 'ini' in default_files:
			_write_overrides(Path('node/shoestring'), f'{command} default')
		if 'json' in default_files:
			_write_rest_overrides(Path('node/shoestring'), f'{command} default')
		args = [command] + deployment_args
		if use_explicit:
			_write_overrides(Path('explicit'), f'{command} explicit')
			_write_rest_overrides(Path('explicit'), f'{command} explicit')
			args += ['--overrides', 'explicit/overrides.ini', '--rest-overrides', 'explicit/rest_overrides.json']
		if 'setup' == command:
			args += ['--security', 'insecure', '--ca-key-path', 'ca.key.pem']

		await main(args)

		expected_name = f'{command} explicit' if use_explicit else f'{command} default'
		config_manager = ConfigurationManager(Path('node/userconfig/resources'))
		friendly_name = config_manager.lookup('config-node.properties', [('localnode', 'friendlyName')])[0]
		assert (expected_name if use_explicit or 'ini' in default_files else 'read or ask 2') == friendly_name
		rest_config = json.loads(Path('node/userconfig/rest.json').read_text(encoding='utf8'))
		assert (expected_name if use_explicit or 'json' in default_files else None) == rest_config['nodeMetadata'].get('animal')


@pytest.mark.parametrize('command', ['setup', 'upgrade'])
@pytest.mark.parametrize('option, filename', [('--overrides', 'overrides.ini'), ('--rest-overrides', 'rest_overrides.json')])
@pytest.mark.parametrize('explicit_default_path', [False, True])
async def test_missing_explicit_overrides_fail_before_changes(tmp_path, monkeypatch, command, option, filename, explicit_default_path):
	# pylint: disable=too-many-arguments,too-many-positional-arguments
	config_filepath = prepare_shoestring_configuration(tmp_path, NodeFeatures.API, api_https=False)
	monkeypatch.chdir(tmp_path)
	resources = tmp_path / 'node/userconfig/resources'
	resources.mkdir(parents=True)
	marker = resources / 'keep.txt'
	marker.write_text('preserve resources', encoding='utf8')
	compose_path = tmp_path / 'node/docker-compose.yaml'
	compose_path.write_text('preserve compose', encoding='utf8')
	if explicit_default_path:
		missing_filepath = Path('node/shoestring') / filename
	else:
		_write_overrides(Path('node/shoestring'), 'default must not mask a missing explicit file')
		_write_rest_overrides(Path('node/shoestring'), 'default must not mask a missing explicit file')
		missing_filepath = Path('missing') / filename
	args = [command, '--config', str(config_filepath), '--directory', 'node', option, str(missing_filepath)]
	if 'setup' == command:
		args += ['--ca-key-path', 'ca.key.pem']

	with pytest.raises(FileNotFoundError) as exception:
		await main(args)

	assert str(missing_filepath) == exception.value.filename
	assert 'preserve compose' == compose_path.read_text(encoding='utf8')
	assert 'preserve resources' == marker.read_text(encoding='utf8')


@pytest.mark.parametrize('rest_settings', [None, {}, {'animal': 'destination node'}])
async def test_wizard_setup_reads_destination_rest_overrides(deployment_args, rest_settings):
	_write_rest_overrides(Path('shoestring'), 'unrelated working directory')
	Path('custom/shoestring.ini').write_bytes(Path('custom/sai.shoestring.ini').read_bytes())
	_write_overrides(Path('custom'), 'wizard node')
	destination_rest_path = Path('node/shoestring/rest_overrides.json')
	if rest_settings is not None:
		destination_rest_path.parent.mkdir()
		contents = {'nodeMetadata': rest_settings} if rest_settings else {}
		destination_rest_path.write_text(json.dumps(contents), encoding='utf8')
	args = build_shoestring_command(
		ShoestringOperation.SETUP,
		Path('node').absolute(),
		Path('custom').absolute(),
		str(Path('wizard-ca.key.pem').absolute()),
		deployment_args[3])
	assert '--rest-overrides' not in args

	await main(args)

	rest_config = json.loads(Path('node/userconfig/rest.json').read_text(encoding='utf8'))
	assert (rest_settings or {}).get('animal') == rest_config['nodeMetadata'].get('animal')
	if rest_settings is not None:
		assert contents == json.loads(destination_rest_path.read_text(encoding='utf8'))
	else:
		assert not destination_rest_path.exists()


async def test_setup_and_upgrade_use_all_destination_defaults(deployment_args):
	config_path = Path('node/shoestring/shoestring.ini')
	config_path.parent.mkdir()
	config_path.write_bytes(Path('custom/sai.shoestring.ini').read_bytes())
	Path('shoestring').mkdir()
	Path('shoestring/shoestring.ini').write_text('unrelated configuration', encoding='utf8')
	_write_overrides(Path('shoestring'), 'unrelated node')
	_write_rest_overrides(Path('shoestring'), 'unrelated node')
	for command in ('setup', 'upgrade'):
		_write_overrides(config_path.parent, f'{command} destination')
		_write_rest_overrides(config_path.parent, f'{command} destination')
		args = [command] + deployment_args[2:]
		if 'setup' == command:
			args += ['--security', 'insecure', '--ca-key-path', 'ca.key.pem']

		await main(args)

		manager = ConfigurationManager(Path('node/userconfig/resources'))
		assert [f'{command} destination'] == manager.lookup('config-node.properties', [('localnode', 'friendlyName')])
		rest_config = json.loads(Path('node/userconfig/rest.json').read_text(encoding='utf8'))
		assert f'{command} destination' == rest_config['nodeMetadata']['animal']
