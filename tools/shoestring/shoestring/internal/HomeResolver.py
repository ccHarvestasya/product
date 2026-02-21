import os
from pathlib import Path


def resolve_home_path(default_path):
	env_home = os.environ.get('SHOESTRING_HOME')
	path = Path(env_home) if env_home else Path(default_path)
	return path.expanduser()
