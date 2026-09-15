import copy
import shutil
import tempfile
from pathlib import Path

from zenlog import log

from shoestring.internal.ConfigurationManager import ConfigurationManager
from shoestring.internal.NodeFeatures import NodeFeatures
from shoestring.internal.Preparer import Preparer
from shoestring.internal.ShoestringConfiguration import parse_shoestring_configuration

from .setup import add_arguments as add_setup_arguments
from .setup import run_main as run_setup_main


def _path_exists(path):
	return path.exists() or path.is_symlink()


def _prepare_staging_directory(output_directories, staging_directories, config):
	staging_directories.userconfig.mkdir(mode=0o700)
	staging_directories.resources.mkdir(mode=0o700)

	if config.node.api_https and NodeFeatures.API in config.node.features:
		if output_directories.https_proxy.exists():
			shutil.copytree(output_directories.https_proxy, staging_directories.https_proxy)
		else:
			staging_directories.https_proxy.mkdir(mode=0o700)

		(staging_directories.https_proxy / 'nginx.conf.erb').unlink(missing_ok=True)


def _commit_upgrade(output_directory, staging_directory, relative_paths):
	backup_directory = staging_directory / '.backup'
	backup_directory.mkdir()
	operations = []

	for relative_path in relative_paths:
		staged_path = staging_directory / relative_path
		if not _path_exists(staged_path):
			raise RuntimeError(f'upgrade did not produce {relative_path}')

	try:
		for relative_path in relative_paths:
			current_path = output_directory / relative_path
			staged_path = staging_directory / relative_path
			backup_path = backup_directory / relative_path
			backup_path.parent.mkdir(parents=True, exist_ok=True)
			operation = (current_path, staged_path, backup_path)
			operations.append(operation)

			if _path_exists(current_path):
				if current_path.is_dir():
					log.info(_('upgrade-purging-directory').format(directory=current_path))
				current_path.rename(backup_path)

			if staged_path.is_dir():
				log.info(_('upgrade-recreating-directory').format(directory=current_path))
			staged_path.rename(current_path)
	except Exception:
		for current_path, staged_path, backup_path in reversed(operations):
			if _path_exists(current_path):
				current_path.rename(staged_path)

			if _path_exists(backup_path):
				backup_path.rename(current_path)

		raise


def _load_harvester_configuration_patches(config_manager):
	config_keys = [
		('harvesting', 'harvesterSigningPrivateKey'),
		('harvesting', 'harvesterVrfPrivateKey')
	]
	values = config_manager.lookup('config-harvesting.properties', config_keys)
	return [(*tuple[0], tuple[1]) for tuple in zip(config_keys, values)]


async def run_main(args):
	config = parse_shoestring_configuration(args.config)
	output_directory = Path(args.directory).absolute()
	directories = Preparer.DirectoryLocator(None, output_directory)

	config_manager = ConfigurationManager(directories.resources)
	if NodeFeatures.HARVESTER in config.node.features:
		harvester_config_patches = _load_harvester_configuration_patches(config_manager)

	with tempfile.TemporaryDirectory(
		dir=output_directory.parent,
		prefix=f'.{output_directory.name}.upgrade-') as staging_directory_name:
		staging_directory = Path(staging_directory_name)
		staging_directories = Preparer.DirectoryLocator(None, staging_directory)
		_prepare_staging_directory(directories, staging_directories, config)

		staged_args = copy.copy(args)
		staged_args.directory = str(staging_directory)
		await run_setup_main(staged_args)

		if NodeFeatures.HARVESTER in config.node.features:
			harvesting_properties_filepath = staging_directories.resources / 'config-harvesting.properties'
			harvesting_properties_filepath.chmod(0o600)
			ConfigurationManager(staging_directories.resources).patch(
				harvesting_properties_filepath.name,
				harvester_config_patches)
			harvesting_properties_filepath.chmod(0o400)

		relative_paths = ['userconfig']
		if config.node.full_api:
			relative_paths.extend(['startup', 'mongo'])
		if NodeFeatures.API in config.node.features and config.node.api_https:
			relative_paths.append('https-proxy')
		relative_paths.extend(['docker-compose.yaml', 'docker-compose-recovery.yaml'])
		_commit_upgrade(output_directory, staging_directory, relative_paths)


def add_arguments(parser):
	add_setup_arguments(parser, False)
	parser.set_defaults(func=run_main)
