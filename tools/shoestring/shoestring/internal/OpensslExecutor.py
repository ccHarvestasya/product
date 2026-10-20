import os
import re
import sys
from contextlib import ExitStack, contextmanager
from subprocess import PIPE, STDOUT, Popen, TimeoutExpired
from threading import Thread


@contextmanager
def _passphrase_pipe(password):
	# A dedicated pipe leaves stdin available for command input and never stores the secret on disk.
	read_fd, write_fd = os.pipe()

	def write_password():
		try:
			with os.fdopen(write_fd, 'wb') as writer:
				writer.write(password)
		except BrokenPipeError:
			pass

	thread = Thread(target=write_password)
	thread.start()
	try:
		yield read_fd
	finally:
		os.close(read_fd)
		thread.join()


@contextmanager
def _prepare_passphrases(command_line):
	secrets = []
	with ExitStack() as stack:
		pass_fds = []
		for index in range(1, len(command_line) - 1):
			if command_line[index] not in ('-passin', '-passout', '-pass') or not command_line[index + 1].startswith('pass:'):
				continue

			password = command_line[index + 1][5:]
			if '\n' in password or '\r' in password or '\0' in password:
				raise ValueError('OpenSSL passphrases cannot contain newline or NUL characters')
			password_fd = stack.enter_context(_passphrase_pipe(password.encode('utf8') + b'\n'))
			pass_fds.append(password_fd)
			command_line[index + 1] = f'fd:{password_fd}'
			if password:
				secrets.append(password.encode('utf8'))

		yield tuple(pass_fds), secrets


def _redact(output, secrets):
	for password in sorted(secrets, key=len, reverse=True):
		output = output.replace(password, b'[REDACTED]')
	return output


class OpensslExecutor:
	"""Shim around the openssl executable."""

	def __init__(self, executable_path='openssl'):
		"""Creates an executor around the specified executable."""

		self.executable_path = executable_path
		self.version_regex = re.compile(r'^.*SSL +([^\s]*)')

	def version(self):
		"""Gets the version of the openssl executable."""

		version_output = ''.join(self.dispatch(['version', '-v'], False))
		match = self.version_regex.match(version_output)
		return match.group(1)

	def dispatch(self, args, command_input=None, show_output=True):
		"""Dispatches an openssl command, optionally showing output."""

		command_line = [self.executable_path] + [str(arg) for arg in args]
		all_lines = []
		with _prepare_passphrases(command_line) as (pass_fds, secrets):
			with Popen(command_line, stdout=PIPE, stderr=STDOUT, stdin=PIPE, pass_fds=pass_fds) as process:
				try:
					stdout_lines, _ = process.communicate(input=command_input.encode('ascii') if command_input else None, timeout=10)
				except TimeoutExpired:
					process.kill()
					process.communicate()
					# TimeoutExpired can contain partial, unsanitized subprocess output.
					raise RuntimeError(f'{" ".join(command_line)} timed out') from None

			for line_bin in stdout_lines.splitlines(keepends=True):
				line = line_bin.decode('ascii')
				all_lines.append(line)

				if show_output:
					sys.stdout.write(_redact(line_bin, secrets).decode('ascii'))
					sys.stdout.flush()

			if 0 != process.returncode:
				formatted_command_line = ' '.join(command_line)
				raise RuntimeError(f'{formatted_command_line} exited with {process.returncode}, stdout:\n{_redact(stdout_lines, secrets)}')

		return all_lines
