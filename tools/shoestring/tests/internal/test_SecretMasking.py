"""Regression coverage for secrets crossing diagnostic boundaries."""

import configparser
import io
import json
import logging
import os
import subprocess
import sys
from unittest.mock import patch

import pytest
from zenlog import log

from shoestring.internal import SecretMasking
from shoestring.internal.ConfigurationManager import load_patches_from_file
from shoestring.internal.OpensslExecutor import OpensslExecutor
from shoestring.internal.ShoestringConfiguration import NodeConfiguration

# pylint: disable=invalid-name


@pytest.fixture(autouse=True)
def isolate_secrets():
	previous = SecretMasking._secrets.copy()  # pylint: disable=protected-access
	yield
	SecretMasking._secrets.clear()  # pylint: disable=protected-access
	SecretMasking._secrets.update(previous)  # pylint: disable=protected-access


def test_configuration_repr_hides_password_without_changing_value():
	config = NodeConfiguration(0, 1000, 1000, 'pass:configuration-secret', False, False, 'CA', 'NODE')
	assert 'configuration-secret' not in repr(config)
	assert 'configuration-secret' not in str(config)
	assert '[REDACTED]' in repr(config)
	assert 'pass:configuration-secret' == config.ca_password


def test_registered_secrets_are_hidden_in_all_loggers_and_exception_chains(caplog):
	SecretMasking.register_secret('pass:registered-secret')
	with caplog.at_level(logging.INFO):
		log.info('password received: registered-secret')
		try:
			try:
				raise ValueError('registered-secret')
			except ValueError as error:
				raise RuntimeError('operation failed') from error
		except RuntimeError:
			logging.getLogger('third-party').exception('diagnostic %s', 'registered-secret')
	assert 'registered-secret' not in caplog.text
	assert 'operation failed' in caplog.text
	assert '[REDACTED]' in caplog.text


@pytest.mark.parametrize('message', [
	'https://user:url-secret@example.invalid/path',
	'https://example.invalid/?token=url-secret&height=10',
	'{"privateKey": "url-secret"}',
	'caPassword = pass:url-secret',
	'harvesterSigningPrivateKey = url-secret'
])
def test_unregistered_sensitive_fields_and_urls_are_masked(message):
	assert 'url-secret' not in SecretMasking.redact(message)
	assert '[REDACTED]' in SecretMasking.redact(message)


def test_explicit_private_output_is_scoped(caplog):
	SecretMasking.register_secret('explicit-private-secret')
	with caplog.at_level(logging.INFO):
		with SecretMasking.explicit_secret_output():
			log.info('explicit-private-secret')
		log.info('explicit-private-secret')
	assert ['explicit-private-secret', '[REDACTED]'] == [record.message for record in caplog.records]


@pytest.mark.parametrize('contents', [
	'[node]\ncaPassword = pass:parse-secret\nparse-secret\n',
	'[node]\ncaPassword = pass:%parse-secret\n'
])
def test_cli_configuration_errors_hide_secrets_and_exit_unsuccessfully(tmp_path, contents):
	path = tmp_path / 'config.ini'
	if '%' in contents:
		parser = configparser.ConfigParser(interpolation=None)
		parser.read('tests/resources/sai.shoestring.ini')
		parser['node']['caPassword'] = 'pass:%parse-secret'
		with path.open('w', encoding='utf8') as outfile:
			parser.write(outfile)
	else:
		path.write_text(contents, encoding='utf8')
	result = subprocess.run(
		[sys.executable, '-m', 'shoestring', 'health', '--config', str(path), '--directory', str(tmp_path)],
		capture_output=True, text=True, check=False, env={**os.environ, 'LC_MESSAGES': 'en'})
	assert 1 == result.returncode
	assert 'parse-secret' not in result.stdout + result.stderr
	assert '[REDACTED]' in result.stderr
	assert 'Traceback' in result.stderr


def test_invalid_overrides_do_not_expose_private_keys(tmp_path):
	path = tmp_path / 'overrides.ini'
	path.write_text('[harvesting.harvesting]\nharvesterSigningPrivateKey = %override-secret\n', encoding='utf8')
	with pytest.raises(ValueError) as error:
		load_patches_from_file(path)
	assert 'override-secret' not in str(error.value)
	assert error.value.__suppress_context__


@pytest.mark.parametrize('source', ['env:PASSWORD', 'file:password.txt', 'fd:9', 'stdin'])
@pytest.mark.parametrize('returncode', [0, 1])
def test_external_openssl_sources_hide_unknown_secret_diagnostics(capfd, source, returncode):
	with patch('shoestring.internal.OpensslExecutor.Popen') as popen:
		process = popen.return_value.__enter__.return_value
		process.returncode = returncode
		process.communicate.return_value = (b'unknown-source-secret\n', None)
		if returncode:
			with pytest.raises(RuntimeError) as error:
				OpensslExecutor().dispatch(['pkey', '-passin', source])
			assert 'unknown-source-secret' not in str(error.value)
		else:
			# The crypto parser still needs the original operational output.
			assert ['unknown-source-secret\n'] == OpensslExecutor().dispatch(['pkey', '-passin', source])
	stdout, stderr = capfd.readouterr()
	assert 'unknown-source-secret' not in stdout + stderr
	assert '[REDACTED]' in stdout


def test_argparse_errors_are_masked(capsys):
	parser = SecretMasking.SecretArgumentParser()
	with pytest.raises(SystemExit) as error:
		parser.parse_args(['--unknown', 'pass:argument-secret'])
	assert 2 == error.value.code
	assert 'argument-secret' not in capsys.readouterr().err


def test_multiline_private_key_output_is_hidden(capfd):
	private_key = b'-----BEGIN PRIVATE KEY-----\nprivate-body-secret\n-----END PRIVATE KEY-----\n'
	with patch('shoestring.internal.OpensslExecutor.Popen') as popen:
		process = popen.return_value.__enter__.return_value
		process.returncode = 1
		process.communicate.return_value = (private_key, None)
		with pytest.raises(RuntimeError) as error:
			OpensslExecutor().dispatch(['pkey'])
		assert 'private-body-secret' not in str(error.value)
	stdout, stderr = capfd.readouterr()
	assert 'private-body-secret' not in stdout + stderr
	assert '[REDACTED]' in stdout


def test_config_secrets_with_commas_are_registered():
	SecretMasking.register_config_secrets('caPassword = pass:comma,secret')
	SecretMasking.register_config_secrets('{"privateKey": "json,secret"}')
	assert 'comma,secret' not in SecretMasking.redact('diagnostic: comma,secret')
	assert 'json,secret' not in SecretMasking.redact('diagnostic: json,secret')
	assert 'json,secret' not in SecretMasking.redact('{"privateKey": "json,secret"}')


def test_json_settings_register_decoded_secret_values(caplog):
	secret = 'json,quote"secret'
	settings = SecretMasking.read_json_config(io.StringIO(json.dumps({'apiKey': secret, 'port': 3000})))
	assert secret == settings['apiKey']
	assert 3000 == settings['port']
	with caplog.at_level(logging.INFO):
		log.info(settings['apiKey'])
	assert secret not in caplog.text
	assert '[REDACTED]' in caplog.text


@pytest.mark.parametrize('contents', [
	'[harvesting.harvesting]\nharvesterSigningPrivateKey = %prefix\n  multiline-secret\n',
	'[harvesting.harvesting]\nmalformed-secret-line\n'
])
def test_parser_errors_hide_values_that_cannot_be_discovered(tmp_path, contents):
	path = tmp_path / 'overrides.ini'
	path.write_text(contents, encoding='utf8')
	with pytest.raises(ValueError) as error:
		load_patches_from_file(path)
	assert 'multiline-secret' not in str(error.value)
	assert 'malformed-secret-line' not in str(error.value)
	assert '[REDACTED]' in str(error.value)


@pytest.mark.parametrize('method', [
	'critical', 'crit', 'c', 'fatal', 'error', 'err', 'e', 'warn', 'warning', 'w',
	'info', 'inf', 'nfo', 'i', 'debug', 'dbg', 'd'
])
@pytest.mark.parametrize('registered', [False, True])
def test_zenlog_masks_private_keys_before_splitting_lines(caplog, method, registered):
	private_key = '-----BEGIN PRIVATE KEY-----\nzenlog-private-body\n-----END PRIVATE KEY-----'
	if registered:
		settings = SecretMasking.read_json_config(io.StringIO(json.dumps({'privateKey': private_key})))
		private_key = settings['privateKey']
	with caplog.at_level(logging.DEBUG):
		getattr(log, method)(private_key)
	assert 'zenlog-private-body' not in caplog.text
	assert '[REDACTED]' in caplog.text


def test_zenlog_explicit_multiline_output_stays_scoped(caplog):
	private_key = '-----BEGIN PRIVATE KEY-----\nexplicit-multiline-body\n-----END PRIVATE KEY-----'
	SecretMasking.register_secret(private_key)
	with caplog.at_level(logging.INFO):
		with SecretMasking.explicit_secret_output():
			log.info(private_key)
		log.info(private_key)
	assert ['-----BEGIN PRIVATE KEY-----', 'explicit-multiline-body', '-----END PRIVATE KEY-----', '[REDACTED]'] == [
		record.message for record in caplog.records]


@pytest.mark.parametrize('text', [
	r'{"api\u004bey":"decoded-key-secret"}',
	r'{"servers":[{"auth":{"api\u004bey":"decoded-key-secret"}}]}',
	r'{"api\u004bey":["decoded-key-secret"]}'
])
def test_json_escaped_sensitive_keys_register_values_recursively(caplog, text):
	settings = SecretMasking.read_json_config(io.StringIO(text))
	assert settings == json.loads(text)
	with caplog.at_level(logging.INFO):
		log.info('received: %s', 'decoded-key-secret')
	assert 'decoded-key-secret' not in caplog.text
	assert '[REDACTED]' in caplog.text


@pytest.mark.parametrize('userinfo', ['user:before@password-tail', 'user:before@@password-tail', 'user:before%40password-tail'])
def test_url_credentials_use_last_at_in_authority(userinfo):
	assert 'https://[REDACTED]@host.invalid:3000/path?height=10#fragment' == SecretMasking.redact(
		f'https://{userinfo}@host.invalid:3000/path?height=10#fragment')


@pytest.mark.parametrize('url', [
	'https://host.invalid/path@part',
	'https://host.invalid?email=user@example.invalid',
	'https://host.invalid#user@example.invalid',
	'https://[::1]:3000/path'
])
def test_url_redaction_preserves_at_outside_authority(url):
	assert url == SecretMasking.redact(url)


@pytest.mark.parametrize('args', [('format-secret',), {'value': 'format-secret'}])
def test_zenlog_formats_arguments_before_masking(caplog, args):
	SecretMasking.register_secret('format-secret')
	SecretMasking.register_secret('%s')
	message = 'received: %(value)s' if isinstance(args, dict) else 'received: %s'
	with caplog.at_level(logging.INFO):
		if isinstance(args, dict):
			log.info(message, args)
		else:
			log.info(message, *args)
	assert 'format-secret' not in caplog.text
	assert 'received: [REDACTED]' in caplog.text


def test_log_masking_installation_is_idempotent(caplog):
	SecretMasking.install_log_masking()
	SecretMasking.install_log_masking()
	with caplog.at_level(logging.INFO):
		log.info('-----BEGIN PRIVATE KEY-----\nidempotent-secret\n-----END PRIVATE KEY-----')
	assert 'idempotent-secret' not in caplog.text
	assert ['[REDACTED]'] == [record.message for record in caplog.records]


def test_zenlog_masks_registered_multiline_values_without_pem_headers(caplog):
	secret = 'multiline-first-part\nmultiline-second-part'
	SecretMasking.register_secret(secret)
	with caplog.at_level(logging.INFO):
		log.info(secret)
	assert 'multiline-first-part' not in caplog.text
	assert 'multiline-second-part' not in caplog.text
	assert ['[REDACTED]'] == [record.message for record in caplog.records]
