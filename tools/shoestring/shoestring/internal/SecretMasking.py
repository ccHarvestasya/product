"""Shared protection for diagnostic output. Operational values remain unchanged."""

import argparse
import asyncio
import configparser
import json
import logging
import re
import sys
import traceback
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps

_REDACTED = '[REDACTED]'
_secrets = set()
_show_secrets = ContextVar('shoestring_show_secrets', default=False)
_SENSITIVE_NAME = r'(?:[\w.-]*(?:password|passphrase|private[_ -]?key|secret|token|api[_ -]?key|access[_ -]?key)[\w.-]*)'
_assignment = re.compile(
	rf'''(?i)(["']?{_SENSITIVE_NAME}["']?\s*[:=]\s*)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\r\n,}}]+)''')
_ini_assignment = re.compile(rf'(?im)^[ \t]*{_SENSITIVE_NAME}[ \t]*=[ \t]*([^\r\n]+)')
_pem_private_key = re.compile(r'-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----.*?-----END (?:[A-Z]+ )*PRIVATE KEY-----', re.DOTALL)
_literal_passphrase = re.compile(r'''pass:[^\s'",}]+''')
_url_credentials = re.compile(r'(?i)([a-z][a-z0-9+.-]*://)[^\s/?#]*@')
_url_token = re.compile(rf'(?i)([?&]{_SENSITIVE_NAME}=)[^&#\s]+')


def register_secret(value):
	"""Remember a secret so subsequent diagnostics can remove literal occurrences."""

	if value:
		value = str(value)
		if value.startswith('pass:'):
			value = value[5:]
		if value:
			_secrets.add(value)


def register_config_secrets(text):
	"""Discover values before parsing, including syntactically invalid configuration."""

	values = [match.group(1).strip() for match in _ini_assignment.finditer(text)]
	for match in _assignment.finditer(text):
		value = match.group(2).strip()
		try:
			value = json.loads(value)
		except ValueError:
			value = value.strip('\"\'')
		if isinstance(value, str):
			values.append(value)
	for value in values:
		if not value.startswith(('env:', 'file:', 'fd:')) and value != 'stdin':
			register_secret(value)


def redact(value):
	"""Return a diagnostic string with secrets, assignments and URL credentials hidden."""

	text = str(value)
	for secret in sorted(_secrets.copy(), key=len, reverse=True):
		for representation in (secret, repr(secret)[1:-1]):
			text = text.replace(representation, _REDACTED)
	text = _pem_private_key.sub(_REDACTED, text)
	text = _literal_passphrase.sub('pass:[REDACTED]', text)
	text = _url_credentials.sub(r'\1[REDACTED]@', text)
	text = _url_token.sub(r'\1[REDACTED]', text)
	return _assignment.sub(lambda match: match.group(1) + _REDACTED, text)


@contextmanager
def explicit_secret_output():
	"""Allow output explicitly requested by the user, such as pemview --show-private."""

	token = _show_secrets.set(True)
	try:
		yield
	finally:
		_show_secrets.reset(token)


def _protect_log_method(method):
	@wraps(method)
	def wrapper(self, message, *args, **kwargs):
		if not _show_secrets.get():
			if args:
				# Format before redaction so a secret such as "%s" cannot corrupt the format string.
				message = logging.LogRecord('pythonConfig', 0, '', 0, message, args, None).getMessage()
				args = ()
			message = redact(message)
		return method(self, message, *args, **kwargs)

	return wrapper


def _install_zenlog_masking():
	# Zenlog splits messages before creating records, so protect the complete message first.
	from zenlog import Log  # pylint: disable=import-outside-toplevel

	if getattr(Log, 'shoestring_masking', False):
		return
	methods = (Log.critical, Log.error, Log.warn, Log.info, Log.debug)
	wrappers = {method: _protect_log_method(method) for method in methods}
	for name, method in vars(Log).copy().items():
		if callable(method) and method in wrappers:
			setattr(Log, name, wrappers[method])
	Log.shoestring_masking = True


def install_log_masking():
	"""Protect records before any handler, including third-party and exception logs."""

	_install_zenlog_masking()
	previous_factory = logging.getLogRecordFactory()
	if getattr(previous_factory, 'shoestring_masking', False):
		return

	def factory(*args, **kwargs):
		record = previous_factory(*args, **kwargs)
		if not _show_secrets.get():
			record.msg = redact(record.getMessage())
			record.args = ()
			if record.exc_info:
				record.exc_text = redact(''.join(traceback.format_exception(*record.exc_info)))
				record.exc_info = None
			if record.stack_info:
				record.stack_info = redact(record.stack_info)
		return record

	factory.shoestring_masking = True
	logging.setLogRecordFactory(factory)


def read_config(parser, filename):
	"""Register sensitive values before ConfigParser can include them in an error."""

	with open(filename, 'rt', encoding='utf8') as infile:
		text = infile.read()
	register_config_secrets(text)
	parser.read_string(text, source=str(filename))


def read_json_config(infile):
	"""Register JSON configuration secrets before parsing or merging settings."""

	text = infile.read()
	register_config_secrets(text)
	settings = json.loads(text)
	_register_json_secrets(settings)
	return settings


def _register_json_secrets(value, sensitive=False):
	# Match decoded names too: JSON permits escapes in property names at every nesting level.
	if isinstance(value, dict):
		for key, child in value.items():
			_register_json_secrets(child, sensitive or bool(re.fullmatch(_SENSITIVE_NAME, key, re.IGNORECASE)))
	elif isinstance(value, list):
		for child in value:
			_register_json_secrets(child, sensitive)
	elif sensitive and isinstance(value, str):
		register_secret(value)


def protect_config_errors(func):
	"""Prevent ConfigParser diagnostics from carrying raw values to callers."""

	@wraps(func)
	def wrapper(*args, **kwargs):
		try:
			return func(*args, **kwargs)
		except configparser.Error as error:
			# Parser errors may quote malformed or multiline values that cannot be discovered safely.
			location = getattr(error, 'source', None)
			line = getattr(error, 'lineno', None)
			details = f' in {location}' if location else ''
			if line:
				details += f' at line {line}'
			raise ValueError(redact(f'{type(error).__name__}: invalid configuration{details}; details [REDACTED]')) from None

	return wrapper


def run_cli(coroutine):
	"""Render the complete CLI traceback through the same diagnostic protection."""

	try:
		asyncio.run(coroutine)
	except Exception:  # pylint: disable=broad-except
		sys.stderr.write(redact(traceback.format_exc()))
		raise SystemExit(1) from None


class SecretArgumentParser(argparse.ArgumentParser):
	"""Protect argparse errors, which write directly to stderr before exiting."""

	def _print_message(self, message, file=None):
		if message:
			super()._print_message(redact(message), file)
