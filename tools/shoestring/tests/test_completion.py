import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize(('arguments', 'expected'), [
	('renew-', {'renew-certificates', 'renew-voting-keys'}),
	('setup --ca', {'--ca-key-path'}),
	('setup --security ', {'default', 'paranoid', 'insecure'}),
	('setup --config config', {'config.ini'})
])
def test_can_complete_module_invocation(tmp_path, arguments, expected):
	# Arrange:
	completion_path = tmp_path / 'completions'
	(tmp_path / 'config.ini').touch()
	command_line = f'{sys.executable} -m shoestring {arguments}'
	environment = {
		**os.environ,
		'PYTHONPATH': str(Path(__file__).resolve().parents[1]),
		'LC_MESSAGES': 'en',
		'COMP_LINE': command_line,
		'COMP_POINT': str(len(command_line)),
		'_ARGCOMPLETE': '3',
		'_ARGCOMPLETE_IFS': '\n',
		'_ARGCOMPLETE_STDOUT_FILENAME': str(completion_path)
	}

	# Act:
	result = subprocess.run(
		[sys.executable, '-m', 'shoestring'],
		cwd=tmp_path, env=environment, capture_output=True, text=True, check=False, timeout=30)

	# Assert:
	assert 0 == result.returncode, result.stderr
	assert expected == {candidate.rstrip() for candidate in completion_path.read_text(encoding='utf8').splitlines()}
