import csv
import json
import sys
from pathlib import Path

from shoestring.internal.Preparer import Preparer
from shoestring.internal.VoterConfigurator import inspect_voting_key_files


def run_main(args):
	directory = Preparer.DirectoryLocator(None, Path(args.directory)).voting_keys
	if not directory.exists():
		raise FileNotFoundError(_('votingview-error-input-does-not-exist').format(filepath=directory))
	if not directory.is_dir():
		raise NotADirectoryError(_('votingview-error-input-not-directory').format(filepath=directory))

	descriptors = inspect_voting_key_files(directory)
	records = [{
		'publicKey': str(descriptor.public_key),
		'startEpoch': descriptor.start_epoch,
		'endEpoch': descriptor.end_epoch,
		'filename': str(descriptor.filepath)
	} for descriptor in reversed(descriptors)]

	if 'json' == args.format:
		print(json.dumps(records, indent=2))
	elif 'csv' == args.format:
		writer = csv.DictWriter(sys.stdout, fieldnames=('publicKey', 'startEpoch', 'endEpoch', 'filename'), lineterminator='\n')
		writer.writeheader()
		writer.writerows(records)
	elif not records:
		print(_('votingview-no-voting-keys').format(directory=directory))
	else:
		print('Voting keys:')
		for record in records:
			print(f'  publicKey:   {record["publicKey"]}')
			print(f'  StartEpoch:  {record["startEpoch"]}')
			print(f'  EndEpoch:    {record["endEpoch"]}')
			print(f'  filename:    {record["filename"]}')
			print()


def add_arguments(parser):
	parser.add_argument('--directory', help=_('argument-help-directory').format(default_path=Path.home()), default=str(Path.home()))
	parser.add_argument('--format', help=_('argument-help-votingview-format'), choices=('pretty', 'csv', 'json'), default='pretty')
	parser.set_defaults(func=run_main)
