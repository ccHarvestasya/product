import csv
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from symbolchain.CryptoTypes import PrivateKey
from symbolchain.symbol.KeyPair import KeyPair
from symbolchain.symbol.VotingKeysGenerator import VotingKeysGenerator

from shoestring.__main__ import main

# pylint: disable=invalid-name


@pytest.fixture(name='temp_directory')
def _create_temp_directory():
	with TemporaryDirectory(prefix='votingview-') as directory:
		yield Path(directory)


@pytest.fixture(name='voting_directory')
def _create_voting_directory(temp_directory):
	directory = temp_directory / 'keys' / 'voting'
	directory.mkdir(parents=True)
	return directory


@pytest.mark.parametrize('format_args', [[], ['--format', 'pretty']])
async def test_can_display_voting_keys_in_descending_file_order(temp_directory, voting_directory, capsys, format_args):
	# Arrange:
	expected_blocks = {}
	for ordinal, start_epoch, end_epoch in [(2, 4394, 4395), (10, 5114, 5115), (3, 5000, 5001)]:
		key_pair = KeyPair(PrivateKey.random())
		filepath = voting_directory / f'private_key_tree{ordinal}.dat'
		filepath.write_bytes(VotingKeysGenerator(key_pair).generate(start_epoch, end_epoch))
		expected_blocks[ordinal] = (
			f'  publicKey:   {key_pair.public_key}\n'
			f'  StartEpoch:  {start_epoch}\n'
			f'  EndEpoch:    {end_epoch}\n'
			f'  filename:    {filepath}\n\n'
		)
	(voting_directory / 'private_key_tree_invalid.dat').write_bytes(b'ignored')
	(voting_directory / 'unrelated.dat').write_bytes(b'ignored')
	(temp_directory / 'private_key_tree99.dat').write_bytes(b'ignored')
	child_directory = voting_directory / 'child'
	child_directory.mkdir()
	(child_directory / 'private_key_tree1.dat').write_bytes(b'ignored')

	# Act:
	await main(['votingview', '--directory', str(temp_directory)] + format_args)

	# Assert:
	assert 'Voting keys:\n' + ''.join(expected_blocks[i] for i in (10, 3, 2)) == capsys.readouterr().out


@pytest.mark.parametrize('format_mode', ['csv', 'json'])
async def test_can_round_trip_structured_output(temp_directory, capsys, format_mode):
	directory = temp_directory / 'keys, "voting"'
	voting_directory = directory / 'keys' / 'voting'
	voting_directory.mkdir(parents=True)
	expected_records = []
	for ordinal, start_epoch in [(2, 4394), (10, 5114)]:
		key_pair = KeyPair(PrivateKey.random())
		filepath = voting_directory / f'private_key_tree{ordinal}.dat'
		filepath.write_bytes(VotingKeysGenerator(key_pair).generate(start_epoch, start_epoch + 1))
		expected_records.insert(0, {
			'publicKey': str(key_pair.public_key),
			'startEpoch': start_epoch,
			'endEpoch': start_epoch + 1,
			'filename': str(filepath)
		})

	await main(['votingview', '--directory', str(directory), '--format', format_mode])

	output = capsys.readouterr().out
	if 'json' == format_mode:
		assert expected_records == json.loads(output)
		assert all(isinstance(record['startEpoch'], int) and isinstance(record['endEpoch'], int) for record in json.loads(output))
	else:
		reader = csv.DictReader(io.StringIO(output))
		assert ['publicKey', 'startEpoch', 'endEpoch', 'filename'] == reader.fieldnames
		assert [{key: str(value) for key, value in record.items()} for record in expected_records] == list(reader)


@pytest.mark.parametrize('format_mode', ['pretty', 'csv', 'json'])
@pytest.mark.parametrize('filenames', [
	['private_key_tree01.dat'],
	['private_key_tree1.dat', 'private_key_tree01.dat']
])
async def test_preserves_original_filenames(temp_directory, voting_directory, capsys, format_mode, filenames):
	expected_records = {}
	for filename in filenames:
		key_pair = KeyPair(PrivateKey.random())
		filepath = voting_directory / filename
		filepath.write_bytes(VotingKeysGenerator(key_pair).generate(100, 101))
		expected_records[str(filepath)] = str(key_pair.public_key)

	await main(['votingview', '--directory', str(temp_directory), '--format', format_mode])

	output = capsys.readouterr().out
	if 'json' == format_mode:
		records = json.loads(output)
	elif 'csv' == format_mode:
		records = list(csv.DictReader(io.StringIO(output)))
	else:
		blocks = output.removeprefix('Voting keys:\n').strip().split('\n\n')
		records = [dict(line.strip().split(':', 1) for line in block.splitlines()) for block in blocks]
		records = [{key: value.strip() for key, value in record.items()} for record in records]

	assert len(filenames) == len(records)
	assert expected_records == {record['filename']: record['publicKey'] for record in records}


@pytest.mark.parametrize('format_mode,expected', [
	('csv', 'publicKey,startEpoch,endEpoch,filename\n'),
	('json', '[]\n')
])
@pytest.mark.usefixtures('voting_directory')
async def test_can_display_empty_structured_output(temp_directory, capsys, format_mode, expected):
	await main(['votingview', '--directory', str(temp_directory), '--format', format_mode])

	assert expected == capsys.readouterr().out


async def test_votingview_rejects_invalid_format(temp_directory):
	with pytest.raises(SystemExit) as exception:
		await main(['votingview', '--directory', str(temp_directory), '--format', 'xml'])

	assert 2 == exception.value.code


async def test_can_display_empty_directory(temp_directory, voting_directory, capsys):
	await main(['votingview', '--directory', str(temp_directory)])

	assert f'no voting key files found in {voting_directory}\n' == capsys.readouterr().out


async def test_cannot_display_missing_directory(temp_directory):
	with pytest.raises(FileNotFoundError, match='does not exist'):
		await main(['votingview', '--directory', str(temp_directory / 'missing')])


async def test_cannot_display_file_as_directory(temp_directory, voting_directory):
	voting_directory.rmdir()
	voting_directory.touch()

	with pytest.raises(NotADirectoryError, match='is not a directory'):
		await main(['votingview', '--directory', str(temp_directory)])


async def test_cannot_display_truncated_voting_file(temp_directory, voting_directory):
	(voting_directory / 'private_key_tree1.dat').write_bytes(b'')

	with pytest.raises(ValueError):
		await main(['votingview', '--directory', str(temp_directory)])


async def test_votingview_help(capsys):
	with pytest.raises(SystemExit) as exception:
		await main(['votingview', '--help'])

	assert 0 == exception.value.code
	output = capsys.readouterr().out
	assert '--directory DIRECTORY' in output
	assert '--format {pretty,csv,json}' in output


async def test_votingview_rejects_old_input(temp_directory):
	with pytest.raises(SystemExit) as exception:
		await main(['votingview', '--input', str(temp_directory)])

	assert 2 == exception.value.code


async def test_defaults_to_home_directory(temp_directory, voting_directory, monkeypatch, capsys):
	monkeypatch.setattr(Path, 'home', lambda: temp_directory)

	await main(['votingview'])

	assert f'no voting key files found in {voting_directory}\n' == capsys.readouterr().out
