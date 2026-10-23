import shutil
from pathlib import Path

from symbollightapi.connector.SymbolConnector import SymbolConnector
from zenlog import log

from shoestring.internal.ConfigurationManager import ConfigurationManager
from shoestring.internal.LinkTransactionBuilder import LinkTransactionBuilder
from shoestring.internal.NodeFeatures import NodeFeatures
from shoestring.internal.NodewatchClient import get_current_finalization_epoch
from shoestring.internal.PeerDownloader import load_api_endpoints
from shoestring.internal.PemUtils import read_public_key_from_public_key_pem_file
from shoestring.internal.Preparer import Preparer
from shoestring.internal.ShoestringConfiguration import parse_shoestring_configuration
from shoestring.internal.VoterConfigurator import VoterConfigurator, inspect_voting_key_files
from shoestring.internal.VotingKeyRenewal import (
	describe_voting_keys,
	plan_voting_key_renewal,
	validate_renewal_transaction,
	write_renewal_transaction
)


def _save_transaction(transaction_config, directories, transaction_builder, network_time):
	aggregate_transaction, transaction_hash = transaction_builder.build(
		network_time.add_hours(transaction_config.timeout_hours),
		transaction_config.fee_multiplier,
		transaction_config.min_cosignatures_count)

	log.info(_('general-created-aggregate-transaction').format(transaction_hash=transaction_hash))

	write_renewal_transaction(aggregate_transaction, directories.output_directory / 'renew_voting_keys_transaction.dat')


def _clean_up_voting_keys_files(voting_keys_directory, inactive_voting_key_descriptors):
	def _get_voting_keys_filepath(ordinal):
		return voting_keys_directory / f'private_key_tree{ordinal}.dat'

	# remove inactive voting keys files
	for descriptor in inactive_voting_key_descriptors:
		expired_voting_keys_filepath = _get_voting_keys_filepath(descriptor.ordinal)
		log.info(_('renew-voting-keys-removing-expired-voting-keys').format(filepath=expired_voting_keys_filepath))
		expired_voting_keys_filepath.unlink()

	# renumber active voting keys files
	next_ordinal = 1
	for descriptor in inspect_voting_key_files(voting_keys_directory):
		shutil.move(_get_voting_keys_filepath(descriptor.ordinal), _get_voting_keys_filepath(next_ordinal))
		next_ordinal += 1


def _link_voting_key(transaction_builder, plan, directories, config_manager, current_epoch):
	if plan.reusable_key:
		log.info(_('renew-voting-keys-reusing-key').format(keys=describe_voting_keys([plan.reusable_key])))
		transaction_builder.link_voting_public_key(
			plan.reusable_key.public_key, plan.reusable_key.start_epoch, plan.reusable_key.end_epoch)
	else:
		voter_configurator = VoterConfigurator(config_manager)
		epoch_range = voter_configurator.generate_voting_key_file(
			directories.voting_keys, current_epoch, minimum_start_epoch=plan.minimum_start_epoch)
		transaction_builder.link_voting_public_key(voter_configurator.voting_public_key, *epoch_range)


async def run_main(args):
	config = parse_shoestring_configuration(args.config)

	if NodeFeatures.VOTER not in config.node.features:
		log.error(_('renew-voting-keys-not-voting'))
		return

	directories = Preparer.DirectoryLocator(None, Path(args.directory))
	config_manager = ConfigurationManager(directories.resources)
	account_public_key = read_public_key_from_public_key_pem_file(directories.certificates / 'ca.pubkey.pem')
	validate_renewal_transaction(directories.output_directory / 'renew_voting_keys_transaction.dat', account_public_key, config.network)
	api_endpoints = load_api_endpoints(directories.resources)
	log.info(_('general-connecting-to-node').format(endpoint=api_endpoints[0]))
	connector = SymbolConnector(api_endpoints[0])

	# reconcile local files with the account's on-chain registrations
	current_finalization_epoch = await get_current_finalization_epoch(config.services.nodewatch, config_manager)
	registered_keys = (await connector.account_links(account_public_key)).voting_public_keys
	local_keys = inspect_voting_key_files(directories.voting_keys)
	plan = plan_voting_key_renewal(local_keys, registered_keys, current_finalization_epoch, config_manager)

	if not any(key.end_epoch >= current_finalization_epoch for key in local_keys):
		log.warning(_('renew-voting-keys-no-voting-keys-found'))
	if plan.missing_keys:
		log.warning(_('renew-voting-keys-missing-files').format(keys=describe_voting_keys(plan.missing_keys)))

	max_voting_keys_per_account = int(config_manager.lookup('config-network.properties', [('chain', 'maxVotingKeysPerAccount')])[0])
	if plan.projected_key_count > max_voting_keys_per_account:
		log.error(_('renew-voting-keys-maximum-already-registered'))
		return

	# finish network requests before generating a key or changing output
	network_time = await connector.network_time()
	transaction_builder = LinkTransactionBuilder(account_public_key, config.network)

	# remove expired root voting keys
	for descriptor in plan.expired_links:
		transaction_builder.unlink_voting_public_key(descriptor.public_key, descriptor.start_epoch, descriptor.end_epoch)

	_link_voting_key(transaction_builder, plan, directories, config_manager, current_finalization_epoch)

	# generate transaction
	_save_transaction(config.transaction, directories, transaction_builder, network_time)

	# clean up voting keys files
	_clean_up_voting_keys_files(directories.voting_keys, plan.expired_files)


def add_arguments(parser):
	parser.add_argument('--config', help=_('argument-help-config'), required=True)
	parser.add_argument('--directory', help=_('argument-help-directory').format(default_path=Path.home()), default=str(Path.home()))
	parser.set_defaults(func=run_main)
