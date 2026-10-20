import os
import re
from subprocess import TimeoutExpired
from unittest.mock import patch

import pytest

from shoestring.internal.OpensslExecutor import OpensslExecutor


def _create_executor():
	return OpensslExecutor(os.environ.get('OPENSSL_EXECUTABLE', 'openssl'))


# pylint: disable=invalid-name


def test_can_retrieve_openssl_version():
	# Arrange:
	executor = _create_executor()

	# Act:
	version = executor.version()

	# Assert:
	assert re.match(r'3\.[0-6]\.*|1\.1\.1', version)


def test_can_dispatch_openssl_command_with_reflected_output(capfd):
	# Arrange:
	executor = _create_executor()

	# Act:
	output_lines = executor.dispatch(['rand', '-hex', 10])
	standard_output, standard_error = capfd.readouterr()

	# Assert:
	assert 1 == len(output_lines)
	assert re.match(r'^[a-f0-9]{20}\n$', output_lines[0])
	assert standard_output
	assert not standard_error


def test_can_dispatch_openssl_command_without_reflected_output(capfd):
	# Arrange:
	executor = _create_executor()

	# Act:
	output_lines = executor.dispatch(['rand', '-hex', 10], show_output=False)
	standard_output, standard_error = capfd.readouterr()

	# Assert:
	assert 1 == len(output_lines)
	assert re.match(r'^[a-f0-9]{20}\n$', output_lines[0])
	assert not standard_output
	assert not standard_error


def test_can_dispatch_openssl_command_with_additional_command_input(capfd):
	# Arrange:
	executor = _create_executor()

	# Act:
	output_lines = executor.dispatch(['s_client', '-connect', 'jenkins.symbolsyndicate.us:443'], command_input='Q')
	standard_output, standard_error = capfd.readouterr()
	subject_line = next(line for line in output_lines if line.startswith('subject='))

	# Assert:
	assert 0 != len(output_lines)
	assert re.fullmatch(r'subject=CN ?= ?jenkins\.symbolsyndicate\.us\n', subject_line)
	assert standard_output
	assert not standard_error


def test_can_propagate_dispatch_failure():
	# Arrange:
	executor = _create_executor()

	# Act + Assert: calling invalid command should result in error
	with pytest.raises(RuntimeError):
		executor.dispatch(['randy', '-hex', 10])


@pytest.mark.parametrize('option', ['-passin', '-passout', '-pass'])
@pytest.mark.parametrize('password', ['abc123', '', 'secret:with:colons', '日本語'])
def test_literal_passphrases_are_passed_through_private_pipes(option, password):
	args = ['pkey', option, f'pass:{password}']
	with patch('shoestring.internal.OpensslExecutor.Popen') as popen:
		process = popen.return_value.__enter__.return_value
		process.returncode = 0

		def communicate(**kwargs):
			assert b'command input' == kwargs['input']
			command_line = popen.call_args.args[0]
			assert ['openssl', 'pkey', option] == command_line[:3]
			assert command_line[3].startswith('fd:')
			password_fd = int(command_line[3][3:])
			assert (password_fd,) == popen.call_args.kwargs['pass_fds']
			assert password.encode('utf8') + b'\n' == os.read(password_fd, 4096)
			return b'ok\n', None

		process.communicate.side_effect = communicate
		assert ['ok\n'] == OpensslExecutor().dispatch(args, command_input='command input', show_output=False)
		assert ['pkey', option, f'pass:{password}'] == args
		with pytest.raises(OSError):
			os.fstat(popen.call_args.kwargs['pass_fds'][0])


@pytest.mark.parametrize('returncode', [0, 1])
def test_literal_passphrases_are_redacted_from_output_and_errors(capfd, returncode):
	with patch('shoestring.internal.OpensslExecutor.Popen') as popen:
		process = popen.return_value.__enter__.return_value
		process.returncode = returncode
		process.communicate.return_value = (b'diagnostic: secret-password\n', None)
		if returncode:
			with pytest.raises(RuntimeError) as error:
				OpensslExecutor().dispatch(['pkey', '-passin', 'pass:secret-password'])
			assert 'secret-password' not in str(error.value)
			assert '[REDACTED]' in str(error.value)
		else:
			assert ['diagnostic: secret-password\n'] == OpensslExecutor().dispatch(['pkey', '-passin', 'pass:secret-password'])

	stdout, stderr = capfd.readouterr()
	assert 'diagnostic: [REDACTED]\n' == stdout
	assert not stderr


def test_timeout_does_not_expose_partial_output():
	with patch('shoestring.internal.OpensslExecutor.Popen') as popen:
		process = popen.return_value.__enter__.return_value
		process.communicate.side_effect = [TimeoutExpired('openssl', 10, output=b'secret-password'), (b'', None)]
		with pytest.raises(RuntimeError, match='timed out') as error:
			OpensslExecutor().dispatch(['pkey', '-passin', 'pass:secret-password'])
		assert 'secret-password' not in str(error.value)
		assert error.value.__suppress_context__
		process.kill.assert_called_once()


@pytest.mark.parametrize('source', ['env:CA_PASSWORD', 'file:password.txt', 'fd:9', 'stdin'])
def test_nonliteral_passphrase_sources_are_preserved(source):
	with patch('shoestring.internal.OpensslExecutor.Popen') as popen:
		process = popen.return_value.__enter__.return_value
		process.returncode = 0
		process.communicate.return_value = (b'', None)
		OpensslExecutor().dispatch(['pkey', '-passin', source])
		assert ['openssl', 'pkey', '-passin', source] == popen.call_args.args[0]


@pytest.mark.parametrize('password', ['secret\npassword', 'secret\rpassword', 'secret\0password'])
def test_multiline_and_nul_passphrases_are_rejected_without_disclosing_them(password):
	with pytest.raises(ValueError) as error:
		OpensslExecutor().dispatch(['pkey', '-passin', f'pass:{password}'])
	assert password not in str(error.value)


def test_can_encrypt_and_decrypt_with_passphrases_and_command_input():
	executor = _create_executor()
	encrypted_key = ''.join(executor.dispatch([
		'genpkey', '-algorithm', 'ed25519', '-aes-256-cbc', '-pass', 'pass:original-password'
	], show_output=False))

	# Reencrypt a PEM from stdin using separate input and output passphrase pipes.
	reencrypted_key = ''.join(executor.dispatch([
		'pkey', '-aes-256-cbc', '-passin', 'pass:original-password', '-passout', 'pass:replacement-password'
	], command_input=encrypted_key, show_output=False))
	public_key = executor.dispatch([
		'pkey', '-pubout', '-passin', 'pass:replacement-password'
	], command_input=reencrypted_key, show_output=False)

	assert '-----BEGIN ENCRYPTED PRIVATE KEY-----\n' in reencrypted_key
	assert '-----BEGIN PUBLIC KEY-----\n' == public_key[0]


def test_failure_with_an_unread_large_passphrase_closes_the_pipe():
	password = 'secret-password' * 10000
	with pytest.raises(RuntimeError) as error:
		_create_executor().dispatch(['randy', '-passin', f'pass:{password}'], show_output=False)
	assert password not in str(error.value)
	assert 'pass:' not in str(error.value)


def test_process_start_failure_closes_the_passphrase_pipe():
	with patch('shoestring.internal.OpensslExecutor.Popen', side_effect=FileNotFoundError) as popen:
		with pytest.raises(FileNotFoundError):
			OpensslExecutor().dispatch(['pkey', '-passin', 'pass:secret-password'])
		with pytest.raises(OSError):
			os.fstat(popen.call_args.kwargs['pass_fds'][0])
