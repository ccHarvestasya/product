import os
import shutil
import tempfile
from pathlib import Path

from zenlog import log

from shoestring.commands import DEFAULT_CONFIG_PATH
from shoestring.internal.ConfigurationManager import ConfigurationManager
from shoestring.internal.PackageResolver import download_and_extract_package

DEFAULT_OVERRIDES = '\n'.join([
	'# Replace YOUR_* values before using this file.',
	'',
	'[user.account]',
	'enableDelegatedHarvestersAutoDetection = true',
	'',
	'[harvesting.harvesting]',
	'maxUnlockedAccounts = 10',
	'beneficiaryAddress = YOUR_BENEFICIARY_ADDRESS',
	'',
	'[node.node]',
	'minFeeMultiplier = 100',
	'',
	'[node.localnode]',
	'host = YOUR_HOST_NAME',
	'friendlyName = YOUR_FRIENDLY_NAME',
	'',
])


async def prepare_configuration(package, config_filepath):
	"""Extracts a configuration template and updates the local user and group ids."""

	config_filepath = Path(config_filepath)
	with tempfile.TemporaryDirectory() as temp_directory:
		await download_and_extract_package(package, Path(temp_directory))

		template_filepath = Path(temp_directory) / 'shoestring.ini'
		log.info(_('general-copying-file').format(source_path=template_filepath, destination_path=config_filepath))
		config_filepath.parent.mkdir(parents=True, exist_ok=True)
		shutil.copy(template_filepath, config_filepath)

		ConfigurationManager(config_filepath.parent).patch(config_filepath.name, [
			('node', 'userId', os.getuid()),
			('node', 'groupId', os.getgid())
		])


async def run_main(args):
	config_filepath = Path(args.config)
	await prepare_configuration(args.package, config_filepath)

	for filename, contents in (('overrides.ini', DEFAULT_OVERRIDES), ('rest_overrides.json', '{}')):
		try:
			with open(config_filepath.parent / filename, 'xt', encoding='utf8') as outfile:
				outfile.write(contents)
		except FileExistsError:
			pass


def add_arguments(parser):
	parser.add_argument('--package', help=_('argument-help-setup-package'), default='mainnet')
	parser.add_argument('config', help=_('argument-help-config'), nargs='?', default=DEFAULT_CONFIG_PATH)
	parser.set_defaults(func=run_main)
