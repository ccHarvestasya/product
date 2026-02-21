import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from shoestring.internal.HomeResolver import resolve_and_create_home_path, resolve_home_path


class HomeResolverTest(unittest.TestCase):
	def test_can_resolve_home_path_from_environment_variable(self):
		# Arrange:
		default_path = Path('/tmp/default-home')

		# Act:
		with patch.dict(os.environ, {'SHOESTRING_HOME': '~/custom-shoestring-home'}, clear=False):
			home_path = resolve_home_path(default_path)

		# Assert:
		self.assertEqual(Path('~/custom-shoestring-home').expanduser(), home_path)

	def test_can_resolve_home_path_from_default_when_environment_variable_is_missing(self):
		# Arrange:
		default_path = Path('/tmp/default-home')

		# Act:
		with patch.dict(os.environ, {}, clear=False):
			os.environ.pop('SHOESTRING_HOME', None)
			home_path = resolve_home_path(default_path)

		# Assert:
		self.assertEqual(default_path, home_path)

	def test_can_create_resolved_home_path(self):
		# Arrange:
		with tempfile.TemporaryDirectory() as temp_directory:
			home_path = Path(temp_directory) / 'custom-home'
			default_path = Path(temp_directory) / 'default-home'

			# Act:
			with patch.dict(os.environ, {'SHOESTRING_HOME': str(home_path)}, clear=False):
				resolved_path = resolve_and_create_home_path(default_path)

			# Assert:
			self.assertEqual(home_path, resolved_path)
			self.assertEqual(True, home_path.exists())
			self.assertEqual(True, home_path.is_dir())

	def test_can_fallback_to_default_home_when_resolved_home_creation_fails(self):
		# Arrange:
		with tempfile.TemporaryDirectory() as temp_directory:
			uncreatable_home = Path('/tmp/non-creatable-home')
			default_path = Path(temp_directory) / 'default-home'

			def _mkdir_side_effect(self, parents=False, exist_ok=False):
				del parents
				del exist_ok
				if self == uncreatable_home:
					raise OSError('cannot create env home')

			# Act:
			with patch.dict(os.environ, {'SHOESTRING_HOME': str(uncreatable_home)}, clear=False):
				with patch('pathlib.Path.mkdir', new=_mkdir_side_effect):
					resolved_path = resolve_and_create_home_path(default_path)

			# Assert:
			self.assertEqual(default_path, resolved_path)

	def test_raises_runtime_error_when_both_home_creations_fail(self):
		# Arrange:
		with tempfile.TemporaryDirectory() as temp_directory:
			default_path = Path(temp_directory) / 'default-home'

			def _mkdir_side_effect(self, parents=False, exist_ok=False):
				del self
				del parents
				del exist_ok
				raise OSError('cannot create home path')

			# Act + Assert:
			with patch.dict(os.environ, {'SHOESTRING_HOME': '/tmp/non-creatable-home'}, clear=False):
				with patch('pathlib.Path.mkdir', new=_mkdir_side_effect):
					with self.assertRaises(RuntimeError) as ex:
						resolve_and_create_home_path(default_path)

			self.assertIn(f'failed to create home path: {default_path}', str(ex.exception))
