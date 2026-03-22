from pathlib import Path

from shoestring.internal.HomeResolver import resolve_home_path


def resolve_default_paths():
	default_directory_path = resolve_home_path(Path.home() / 'shoestring')
	default_config_path = default_directory_path / 'shoestring' / 'shoestring.ini'
	default_ca_key_path = default_directory_path / 'ca.key.pem'
	return (default_directory_path, default_config_path, default_ca_key_path)


def add_config_argument(parser, default_config_path):
	parser.add_argument(
		'--config',
		help=_('argument-help-config').format(default_path=default_config_path),
		default=str(default_config_path))


def add_directory_argument(parser, default_directory_path):
	parser.add_argument(
		'--directory',
		help=_('argument-help-directory').format(default_path=default_directory_path),
		default=str(default_directory_path))


def add_ca_key_path_argument(parser, default_ca_key_path):
	parser.add_argument(
		'--ca-key-path',
		help=_('argument-help-ca-key-path').format(default_path=default_ca_key_path),
		default=str(default_ca_key_path))
