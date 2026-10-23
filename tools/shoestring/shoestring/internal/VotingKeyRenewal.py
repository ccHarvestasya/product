from collections import namedtuple
from pathlib import Path
from tempfile import NamedTemporaryFile

from symbolchain.facade.SymbolFacade import SymbolFacade
from symbolchain.sc import TransactionFactory, TransactionType
from zenlog import log

VotingKeyRenewalPlan = namedtuple('VotingKeyRenewalPlan', [
	'expired_links', 'expired_files', 'reusable_key', 'minimum_start_epoch', 'missing_keys', 'projected_key_count'
])


def _key_identity(key):
	return (key.public_key.bytes, key.start_epoch, key.end_epoch)


def describe_voting_keys(keys):
	"""Describes voting keys, including filenames when available."""

	descriptions = []
	for key in keys:
		filename = f'private_key_tree{key.ordinal}.dat: ' if hasattr(key, 'ordinal') else ''
		descriptions.append(f'{filename}{key.public_key} [{key.start_epoch}, {key.end_epoch}]')
	return ', '.join(descriptions)


def plan_voting_key_renewal(local_keys, registered_keys, current_epoch, config_manager):
	"""Plans a renewal without generating keys or changing files."""

	expired_links = [key for key in registered_keys if key.end_epoch < current_epoch]
	remaining_links = [key for key in registered_keys if key.end_epoch >= current_epoch]
	expired_files = [key for key in local_keys if key.end_epoch < current_epoch]
	active_files = [key for key in local_keys if key.end_epoch >= current_epoch]
	registered_identities = {_key_identity(key) for key in registered_keys}
	local_identities = {_key_identity(key) for key in local_keys}
	candidates = [key for key in active_files if _key_identity(key) not in registered_identities]
	if len(candidates) > 1:
		raise RuntimeError(_('renew-voting-keys-multiple-unregistered').format(keys=describe_voting_keys(candidates)))

	reusable_key = candidates[0] if candidates else None
	if reusable_key:
		_validate_reusable_key(reusable_key, registered_keys, remaining_links, config_manager)

	minimum_start_epoch = 1 + max((key.end_epoch for key in active_files + remaining_links), default=current_epoch + 1)
	return VotingKeyRenewalPlan(
		expired_links,
		expired_files,
		reusable_key,
		minimum_start_epoch,
		[key for key in remaining_links if _key_identity(key) not in local_identities],
		len(registered_keys) - len(expired_links) + 1)


def _validate_reusable_key(key, registered_keys, remaining_links, config_manager):
	if any(link.public_key == key.public_key for link in registered_keys) or any(
		key.start_epoch <= link.end_epoch and link.start_epoch <= key.end_epoch for link in remaining_links):
		raise RuntimeError(_('renew-voting-keys-conflicting-local-key').format(keys=describe_voting_keys([key])))

	min_lifetime, max_lifetime = (int(value) for value in config_manager.lookup('config-network.properties', [
		('chain', 'minVotingKeyLifetime'), ('chain', 'maxVotingKeyLifetime')
	]))
	if key.start_epoch < 1 or not min_lifetime <= key.end_epoch - key.start_epoch + 1 <= max_lifetime:
		raise RuntimeError(_('renew-voting-keys-invalid-reusable-key').format(keys=describe_voting_keys([key])))


def validate_renewal_transaction(filepath, account_public_key, network):
	"""Protects signed, corrupt or unrelated transaction output from being overwritten."""

	if not filepath.exists():
		return

	error_message = _('renew-voting-keys-protected-transaction').format(filepath=filepath)
	try:
		payload = filepath.read_bytes()
		transaction = TransactionFactory.deserialize(payload)
	except (ValueError, IndexError, KeyError, AssertionError) as ex:
		raise RuntimeError(error_message) from ex

	if transaction.type_ not in (TransactionType.AGGREGATE_COMPLETE, TransactionType.AGGREGATE_BONDED):
		raise RuntimeError(error_message)

	if any(transaction.signature.bytes) or transaction.cosignatures:
		raise RuntimeError(error_message)
	if transaction.network.value != SymbolFacade(network).network.identifier:
		raise RuntimeError(error_message)
	if transaction.signer_public_key.bytes != account_public_key.bytes:
		raise RuntimeError(error_message)
	if not transaction.transactions or payload != transaction.serialize():
		raise RuntimeError(error_message)
	for embedded in transaction.transactions:
		if embedded.type_ != TransactionType.VOTING_KEY_LINK or embedded.network != transaction.network:
			raise RuntimeError(error_message)
		if embedded.signer_public_key.bytes != account_public_key.bytes:
			raise RuntimeError(error_message)


def write_renewal_transaction(transaction, filepath):
	"""Replaces transaction output only after the complete payload has been written."""

	payload = transaction.serialize()
	temporary_path = None
	try:
		with NamedTemporaryFile(dir=filepath.parent, prefix='.renew_voting_keys_', suffix='.tmp', delete=False) as outfile:
			temporary_path = Path(outfile.name)
			outfile.write(payload)
		temporary_path.replace(filepath)
	finally:
		if temporary_path:
			temporary_path.unlink(missing_ok=True)

	log.info(_('transaction-serializer-saved-file').format(filepath=filepath))
	log.info(transaction)
