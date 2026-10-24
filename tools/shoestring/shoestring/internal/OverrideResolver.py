from pathlib import Path

from .ConfigurationPaths import DEFAULT_OVERRIDES_PATH, DEFAULT_REST_OVERRIDES_PATH


def resolve_override_paths(overrides, rest_overrides, directory):
	"""Resolves optional defaults and checks that explicitly specified files exist."""

	def resolve_path(explicit_path, default_path):
		if explicit_path is not None:
			Path(explicit_path).stat()
			return explicit_path

		return default_path if Path(default_path).exists() else None

	return (
		resolve_path(overrides, DEFAULT_OVERRIDES_PATH),
		resolve_path(rest_overrides, str(Path(directory) / DEFAULT_REST_OVERRIDES_PATH))
	)
