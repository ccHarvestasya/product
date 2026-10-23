import tempfile
from pathlib import Path

import pytest
from symbolchain.CryptoTypes import PublicKey

from shoestring.internal.ConfigurationManager import ConfigurationManager
from shoestring.internal.VoterConfigurator import VotingFileDescriptor
from shoestring.internal.VotingKeyRenewal import plan_voting_key_renewal


@pytest.fixture
def config_manager():
	with tempfile.TemporaryDirectory() as directory:
		(Path(directory) / 'config-network.properties').write_text(
			'[chain]\nminVotingKeyLifetime = 28\nmaxVotingKeyLifetime = 720\n', encoding='utf8')
		yield ConfigurationManager(directory)


def _key(ordinal, start_epoch, end_epoch):
	return VotingFileDescriptor(ordinal, PublicKey(ordinal.to_bytes(32, 'little')), start_epoch, end_epoch)


# pylint: disable=invalid-name,redefined-outer-name


@pytest.mark.parametrize('local_keys, registered_keys, expected_count', [
	([], [_key(1, 100, 199), _key(2, 200, 299), _key(3, 300, 399)], 4),
	([_key(2, 1, 28), _key(3, 29, 56)], [_key(1, 100, 199)], 2),
	([], [_key(1, 1, 28), _key(2, 29, 56), _key(3, 100, 199)], 2),
	([], [_key(1, 1, 28), _key(2, 71, 100), _key(3, 101, 200)], 3)
])
def test_projected_count_uses_registrations(config_manager, local_keys, registered_keys, expected_count):
	plan = plan_voting_key_renewal(local_keys, registered_keys, 100, config_manager)
	assert expected_count == plan.projected_key_count


def test_expired_links_do_not_require_files(config_manager):
	registered_keys = [_key(1, 1, 28), _key(2, 71, 100)]
	plan = plan_voting_key_renewal([_key(3, 29, 56)], registered_keys, 100, config_manager)
	assert registered_keys[:1] == plan.expired_links
	assert [_key(3, 29, 56)] == plan.expired_files
	assert registered_keys[1:] == plan.missing_keys
	assert 101 == plan.minimum_start_epoch


def test_exact_registration_is_not_reused(config_manager):
	key = _key(1, 100, 199)
	plan = plan_voting_key_renewal([key], [key], 100, config_manager)
	assert plan.reusable_key is None
	assert not plan.missing_keys
	assert 200 == plan.minimum_start_epoch


def test_one_unregistered_key_is_reused(config_manager):
	key = _key(2, 200, 299)
	plan = plan_voting_key_renewal([key], [_key(1, 100, 199)], 100, config_manager)
	assert key == plan.reusable_key


def test_multiple_unregistered_keys_are_reported(config_manager):
	with pytest.raises(RuntimeError) as exc_info:
		plan_voting_key_renewal([_key(1, 100, 199), _key(2, 200, 299)], [], 100, config_manager)
	for ordinal in (1, 2):
		assert f'private_key_tree{ordinal}.dat' in str(exc_info.value)


@pytest.mark.parametrize('candidate', [_key(1, 200, 299), _key(2, 199, 298)])
def test_conflicting_keys_are_rejected(config_manager, candidate):
	with pytest.raises(RuntimeError, match='conflicts'):
		plan_voting_key_renewal([candidate], [_key(1, 100, 199)], 100, config_manager)


@pytest.mark.parametrize('candidate', [_key(1, 100, 126), _key(1, 100, 820), _key(1, 0, 100)])
def test_invalid_reusable_ranges_are_rejected(config_manager, candidate):
	with pytest.raises(RuntimeError, match='invalid'):
		plan_voting_key_renewal([candidate], [], 100, config_manager)


@pytest.mark.parametrize('local_keys', [[], [_key(1, 1, 28)]])
def test_initial_start_is_after_current_epoch(config_manager, local_keys):
	plan = plan_voting_key_renewal(local_keys, [], 100, config_manager)
	assert 102 == plan.minimum_start_epoch


def test_missing_future_registration_sets_start(config_manager):
	plan = plan_voting_key_renewal([], [_key(1, 500, 599)], 100, config_manager)
	assert 600 == plan.minimum_start_epoch
