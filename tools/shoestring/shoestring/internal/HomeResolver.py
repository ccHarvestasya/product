import os
from pathlib import Path


def resolve_home_path(default_path):
	return Path(os.environ.get('SHOESTRING_HOME', str(default_path))).expanduser()


def resolve_and_create_home_path(default_path):
	home_path = resolve_home_path(default_path)

	try:
		home_path.mkdir(parents=True, exist_ok=True)
		return home_path
	except OSError:
		try:
			default_path.mkdir(parents=True, exist_ok=True)
			return default_path
		except OSError as ex:
			raise RuntimeError(f'failed to create home path: {default_path}') from ex
