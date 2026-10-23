from asyncio import TimeoutError as AsyncTimeoutError

from aiohttp import ClientError
from cryptography.exceptions import UnsupportedAlgorithm
from symbollightapi.connector.SymbolConnector import SymbolConnector
from symbollightapi.model.Exceptions import NodeException
from zenlog import log

from shoestring.internal.NodeFeatures import NodeFeatures
from shoestring.internal.NodewatchClient import get_current_finalization_epoch
from shoestring.internal.PeerDownloader import load_api_endpoints
from shoestring.internal.PemUtils import read_public_key_from_public_key_pem_file
from shoestring.internal.VoterConfigurator import inspect_voting_key_files

NAME = 'voting keys'


def should_run(node_config):
	return NodeFeatures.VOTER in node_config.features


async def validate(context):
	endpoint = '-'
	try:
		current_epoch = await get_current_finalization_epoch(context.config.services.nodewatch, context.config_manager)
		local_keys = inspect_voting_key_files(context.directories.voting_keys)
		endpoints = load_api_endpoints(context.directories.resources)
		if not endpoints:
			log.error(_('health-voting-keys-no-api-endpoints'))
			return

		endpoint = endpoints[0]
		log.info(_('general-connecting-to-node').format(endpoint=endpoint))
		public_key = read_public_key_from_public_key_pem_file(context.directories.certificates / 'ca.pubkey.pem')
		registered_keys = (await SymbolConnector(endpoint).account_links(public_key)).voting_public_keys
		for key in registered_keys:
			if not isinstance(key.start_epoch, int) or not isinstance(key.end_epoch, int):
				raise ValueError(_('health-voting-keys-invalid-registration'))
			if key.start_epoch < 1 or key.end_epoch < key.start_epoch:
				raise ValueError(_('health-voting-keys-invalid-registration'))
	except (NodeException, ClientError, AsyncTimeoutError, OSError, ValueError, KeyError, TypeError, IndexError, UnsupportedAlgorithm) as ex:
		log.error(_('health-voting-keys-unverifiable').format(endpoint=endpoint, reason=str(ex)))
		return

	_report_voting_keys(local_keys, registered_keys, current_epoch)


def _key_identity(key):
	return (key.public_key.bytes, key.start_epoch, key.end_epoch)


def _log_mismatch(message, key, current_epoch):
	log_message = log.error if key.start_epoch <= current_epoch else log.warning
	log_message(message.format(
		public_key=key.public_key,
		start_epoch=key.start_epoch,
		end_epoch=key.end_epoch,
		filename=f'private_key_tree{key.ordinal}.dat' if hasattr(key, 'ordinal') else ''))


def _report_voting_keys(local_keys, registered_keys, current_epoch):
	registered_identities = {_key_identity(key) for key in registered_keys}
	local_identities = {_key_identity(key) for key in local_keys}
	matched_keys = []

	for descriptor in local_keys:
		if descriptor.end_epoch < current_epoch:
			log.warning(_('health-voting-keys-expired').format(start_epoch=descriptor.start_epoch, end_epoch=descriptor.end_epoch))
		elif _key_identity(descriptor) not in registered_identities:
			_log_mismatch(_('health-voting-keys-not-linked'), descriptor, current_epoch)
		else:
			matched_keys.append(descriptor)
			if descriptor.start_epoch <= current_epoch:
				log.info(_('health-voting-keys-active').format(start_epoch=descriptor.start_epoch, end_epoch=descriptor.end_epoch))
			else:
				log.info(_('health-voting-keys-future').format(start_epoch=descriptor.start_epoch, end_epoch=descriptor.end_epoch))

	for key in registered_keys:
		if key.end_epoch >= current_epoch and _key_identity(key) not in local_identities:
			_log_mismatch(_('health-voting-keys-missing-file'), key, current_epoch)

	first_gap_epoch = current_epoch
	for descriptor in sorted(matched_keys, key=lambda key: (key.start_epoch, key.end_epoch)):
		if descriptor.start_epoch > first_gap_epoch:
			break
		first_gap_epoch = max(first_gap_epoch, descriptor.end_epoch + 1)

	if first_gap_epoch == current_epoch:
		log.error(_('health-voting-keys-not-registered').format(epoch=current_epoch))
	else:
		log.info(_('health-voting-keys-registered').format(
			start_epoch=current_epoch,
			end_epoch=first_gap_epoch - 1))
