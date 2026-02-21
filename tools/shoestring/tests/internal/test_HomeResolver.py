import os
import unittest
from pathlib import Path
from unittest.mock import patch

from shoestring.internal.HomeResolver import resolve_home_path


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
