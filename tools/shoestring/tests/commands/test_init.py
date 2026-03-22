import os
import tempfile
from pathlib import Path

import pytest
from symbolchain.CryptoTypes import Hash256

from shoestring.__main__ import main
from shoestring.internal.ShoestringConfiguration import parse_shoestring_configuration

from ..test.TestPackager import prepare_testnet_package

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

			config = parse_shoestring_configuration(config_filepath)
			assert Hash256('49D6E1CE276A85B70EAFE52349AACCA389302E7A9754BCF1221E79494FC665A4') == config.network.generation_hash_seed

			# - user and group ids are updated
			assert os.getuid() == config.node.user_id
			assert os.getgid() == config.node.group_id


async def test_can_download_configuration_file_template_to_default_filename(monkeypatch):
	# Arrange:
	with tempfile.TemporaryDirectory() as package_directory:
		prepare_testnet_package(package_directory, 'resources.zip')

		with tempfile.TemporaryDirectory() as temp_directory:
			monkeypatch.setenv('SHOESTRING_HOME', temp_directory)
			previous_cwd = os.getcwd()
			try:
				os.chdir(temp_directory)
				config_filepath = Path(temp_directory) / 'shoestring' / 'shoestring.ini'

				# Sanity:
				assert not config_filepath.exists()
				assert not config_filepath.parent.exists()

				# Act:
				await main([
					'init',
					'--package', f'file://{Path(package_directory) / "resources.zip"}',
				])
			finally:
				os.chdir(previous_cwd)

			# Assert:
			assert config_filepath.exists()

			config = parse_shoestring_configuration(config_filepath)
			assert Hash256('49D6E1CE276A85B70EAFE52349AACCA389302E7A9754BCF1221E79494FC665A4') == config.network.generation_hash_seed

			# - user and group ids are updated
			assert os.getuid() == config.node.user_id
			assert os.getgid() == config.node.group_id


async def test_init_fails_when_default_parent_is_not_directory(monkeypatch):
	# Arrange:
	with tempfile.TemporaryDirectory() as package_directory:
		prepare_testnet_package(package_directory, 'resources.zip')

		with tempfile.TemporaryDirectory() as temp_directory:
			monkeypatch.setenv('SHOESTRING_HOME', temp_directory)
			previous_cwd = os.getcwd()
			try:
				os.chdir(temp_directory)
				(Path(temp_directory) / 'shoestring').write_text('not a directory', encoding='utf8')

				# Act + Assert:
				with pytest.raises(SystemExit) as exinfo:
					await main([
						'init',
						'--package', f'file://{Path(package_directory) / "resources.zip"}',
					])
				assert 1 == exinfo.value.code
				assert not (Path(temp_directory) / 'shoestring' / 'shoestring.ini').exists()
			finally:
				os.chdir(previous_cwd)
