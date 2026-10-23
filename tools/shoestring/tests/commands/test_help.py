import pytest

from shoestring.__main__ import main, parse_args

# pylint: disable=invalid-name


async def _assert_can_run_help(capsys, args):
	# Act + Assert:
	with pytest.raises(SystemExit):
		await main(args)

	# Assert: spot check a few expected strings
	out = capsys.readouterr().out
	assert '\nShoestring Tool\n' in out
	assert '\nsubcommands:\n' in out


async def test_can_run_help_when_help_option_specified(capsys):
	await _assert_can_run_help(capsys, ['--help'])


async def test_can_run_help_when_no_command_provided(capsys):
	await _assert_can_run_help(capsys, [])


@pytest.mark.parametrize('command_args', [
	['announce-transaction', '--transaction', 'transaction.bin'],
	['health'],
	['import-bootstrap', '--bootstrap', 'bootstrap'],
	['import-harvesters', '--in-harvesters', 'harvesters.dat', '--in-pem', 'key.pem'],
	['min-cosignatures-count', '--ca-key-path', 'key.pem'],
	['renew-certificates', '--ca-key-path', 'key.pem'],
	['renew-voting-keys'],
	['reset-data'],
	['setup', '--ca-key-path', 'key.pem'],
	['signer', '--ca-key-path', 'key.pem', 'transaction.bin'],
	['upgrade']
])
@pytest.mark.parametrize('config_path', [None, 'custom/config.ini'])
def test_config_path_defaults_and_explicit_override(monkeypatch, command_args, config_path):
	monkeypatch.setattr('builtins._', lambda message: message, raising=False)
	args = command_args + (['--config', config_path] if config_path else [])

	parsed_args = parse_args(args)

	assert (config_path or 'shoestring/shoestring.ini') == parsed_args.config
