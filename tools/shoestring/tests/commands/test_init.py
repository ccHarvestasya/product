import json
import os
import tempfile
from pathlib import Path

import pytest
from symbolchain.CryptoTypes import Hash256

from shoestring.__main__ import main
from shoestring.internal.ShoestringConfiguration import parse_shoestring_configuration

from ..test.TestPackager import prepare_testnet_package

EXPECTED_OVERRIDES = '''# Replace YOUR_* values before using this file.

[user.account]
enableDelegatedHarvestersAutoDetection = true

[harvesting.harvesting]
maxUnlockedAccounts = 10
beneficiaryAddress = YOUR_BENEFICIARY_ADDRESS

[node.node]
minFeeMultiplier = 100

[node.localnode]
host = YOUR_HOST_NAME
friendlyName = YOUR_FRIENDLY_NAME
'''


# pylint: disable=invalid-name


async def test_can_download_configuration_file_template():
	# Arrange:
	with tempfile.TemporaryDirectory() as package_directory:
		prepare_testnet_package(package_directory, 'resources.zip')

		with tempfile.TemporaryDirectory() as temp_directory:
			config_filepath = Path(temp_directory) / 'my.shoestring.ini'

			# Sanity:
			assert not config_filepath.exists()

			# Act:
			await main([
				'init',
				'--package', f'file://{Path(package_directory) / "resources.zip"}',
				str(config_filepath)
			])

			# Assert:
			assert config_filepath.exists()
			assert EXPECTED_OVERRIDES == (config_filepath.parent / 'overrides.ini').read_text(encoding='utf8')
			assert b'{}' == (config_filepath.parent / 'rest_overrides.json').read_bytes()

			config = parse_shoestring_configuration(config_filepath)
			assert Hash256('49D6E1CE276A85B70EAFE52349AACCA389302E7A9754BCF1221E79494FC665A4') == config.network.generation_hash_seed

			# - user and group ids are updated
			assert os.getuid() == config.node.user_id
			assert os.getgid() == config.node.group_id


@pytest.mark.parametrize('custom_path', [None, 'custom/nested/config.ini'])
@pytest.mark.parametrize('existing_files', [(), ('overrides.ini',), ('rest_overrides.json',), ('overrides.ini', 'rest_overrides.json')])
async def test_init_creates_missing_files_and_preserves_existing_overrides(tmp_path, monkeypatch, custom_path, existing_files):
	package_directory = tmp_path / 'package'
	package_directory.mkdir()
	prepare_testnet_package(package_directory, 'resources.zip')
	monkeypatch.chdir(tmp_path)
	config_filepath = tmp_path / (custom_path or 'shoestring/shoestring.ini')
	existing_contents = {'overrides.ini': '[node.localnode]\nhost = localhost\n', 'rest_overrides.json': ''}
	for filename in existing_files:
		config_filepath.parent.mkdir(parents=True, exist_ok=True)
		(config_filepath.parent / filename).write_text(existing_contents[filename], encoding='utf8')

	args = ['init', '--package', f'file://{package_directory / "resources.zip"}']
	if custom_path:
		args.append(custom_path)
	await main(args)

	config = parse_shoestring_configuration(config_filepath)
	assert os.getuid() == config.node.user_id
	assert os.getgid() == config.node.group_id
	for filename, default_contents in (('overrides.ini', EXPECTED_OVERRIDES), ('rest_overrides.json', '{}')):
		expected = existing_contents[filename] if filename in existing_files else default_contents
		assert expected == (config_filepath.parent / filename).read_text(encoding='utf8')
	if 'rest_overrides.json' not in existing_files:
		assert {} == json.loads((config_filepath.parent / 'rest_overrides.json').read_text(encoding='utf8'))
	if custom_path:
		assert not (tmp_path / 'shoestring').exists()


async def test_init_replaces_existing_configuration(tmp_path, monkeypatch):
	prepare_testnet_package(tmp_path, 'resources.zip')
	monkeypatch.chdir(tmp_path)
	config_filepath = tmp_path / 'shoestring/shoestring.ini'
	config_filepath.parent.mkdir()
	config_filepath.write_text('old configuration', encoding='utf8')

	await main(['init', '--package', f'file://{tmp_path / "resources.zip"}'])

	config = parse_shoestring_configuration(config_filepath)
	assert os.getuid() == config.node.user_id
