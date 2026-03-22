import asyncio
import os
import shutil
import sys
import tempfile
from pathlib import Path

from zenlog import log

from shoestring.internal.ConfigurationManager import ConfigurationManager
from shoestring.internal.HomeResolver import resolve_home_path
from shoestring.internal.PackageResolver import download_and_extract_package


async def run_main(args):
	destination_path = Path(args.config)
	destination_preexisted = destination_path.exists()

	try:
		with tempfile.TemporaryDirectory() as temp_directory:
			await download_and_extract_package(args.package, Path(temp_directory))

			template_filepath = Path(temp_directory) / 'shoestring.ini'
			destination_path.parent.mkdir(parents=True, exist_ok=True)
			log.info(_('general-copying-file').format(source_path=template_filepath, destination_path=destination_path))
			shutil.copy(template_filepath, destination_path)

			ConfigurationManager(destination_path.parent).patch(destination_path.name, [
				('node', 'userId', os.getuid()),
				('node', 'groupId', os.getgid())
			])
	except asyncio.CancelledError:
		# Treat cancellation as an interrupt and exit quietly.
		sys.exit(130)
	except Exception as ex:  # pylint: disable=broad-exception-caught
		log.error(_('init-failed-to-create-config').format(destination_path=destination_path, error=ex))

		# best-effort rollback (only when we created a new file)
		if not destination_preexisted and destination_path.exists():
			try:
				destination_path.unlink()
			except OSError:
				pass

		sys.exit(1)


def add_arguments(parser):
	default_directory_path = resolve_home_path(Path.home() / 'shoestring')
	default_config_path = default_directory_path / 'shoestring' / 'shoestring.ini'

	parser.add_argument('--package', help=_('argument-help-setup-package'), default='mainnet')
	parser.add_argument(
		'config',
		help=_('argument-help-config').format(default_path=default_config_path),
		nargs='?',
		default=str(default_config_path))
	parser.set_defaults(func=run_main)
