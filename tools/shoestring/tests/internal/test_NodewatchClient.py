import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from symbollightapi.model.Exceptions import NodeException

from shoestring.internal.ConfigurationManager import ConfigurationManager
from shoestring.internal.NodewatchClient import NodewatchClient, get_current_finalization_epoch, get_verified_finalization_epoch

from ..test.MockNodewatchServer import setup_mock_nodewatch_server

# region server fixture


@pytest.fixture
async def server(aiohttp_client):
	return await setup_mock_nodewatch_server(aiohttp_client)

# endregion


@pytest.fixture
def config_manager():
	with tempfile.TemporaryDirectory() as output_directory:
		(Path(output_directory) / 'config-network.properties').write_text('[chain]\nvotingSetGrouping = 20\n', encoding='utf8')
		yield ConfigurationManager(output_directory)


# pylint: disable=invalid-name


@pytest.mark.parametrize('nodewatch_heights, rest_heights, expected_epoch', [
	([20], [20], 2),
	([17], [20], 2),
	([20], [17], 2),
	([20, 21], [21, 21], 3),
	([21, 21], [20, 21], 3)
])
async def test_can_verify_finalization_epoch(
	config_manager, nodewatch_heights, rest_heights, expected_epoch
):  # pylint: disable=redefined-outer-name
	# Arrange:
	connector = SimpleNamespace(endpoint='http://rest-node:3000', finalized_chain_height=AsyncMock(side_effect=rest_heights))
	with patch.object(NodewatchClient, 'symbol_finalized_height', side_effect=nodewatch_heights) as nodewatch_height:
		# Act:
		epoch = await get_verified_finalization_epoch('http://nodewatch', config_manager, connector)

		# Assert: retry both sources only on an epoch mismatch
		assert expected_epoch == epoch
		assert len(nodewatch_heights) == nodewatch_height.await_count
		assert len(rest_heights) == connector.finalized_chain_height.await_count


@pytest.mark.parametrize('nodewatch_height, rest_height', [(20, 21), (21, 20)])
async def test_cannot_verify_inconsistent_epochs(
	config_manager, nodewatch_height, rest_height, caplog
):  # pylint: disable=redefined-outer-name
	# Arrange:
	connector = SimpleNamespace(endpoint='http://rest-node:3000', finalized_chain_height=AsyncMock(return_value=rest_height))
	with patch.object(NodewatchClient, 'symbol_finalized_height', return_value=nodewatch_height) as get_height:
		# Act:
		with pytest.raises(RuntimeError, match='aborting') as exc_info:
			await get_verified_finalization_epoch('http://nodewatch', config_manager, connector)

		# Assert: both sources are fetched twice and the error identifies their states
		assert 2 == get_height.await_count
		assert 2 == connector.finalized_chain_height.await_count
		assert 'http://rest-node:3000' in str(exc_info.value)
		assert f'height {nodewatch_height}' in str(exc_info.value)
		assert f'height {rest_height}' in str(exc_info.value)
		assert 1 == sum(record.levelname == 'WARNING' for record in caplog.records)


@pytest.mark.parametrize('source', ['nodewatch', 'rest'])
async def test_verification_propagates_connection_errors(config_manager, source):  # pylint: disable=redefined-outer-name
	# Arrange:
	connector = SimpleNamespace(endpoint='http://rest-node:3000', finalized_chain_height=AsyncMock(return_value=20))
	with patch.object(NodewatchClient, 'symbol_finalized_height', return_value=20) as get_height:
		failing_method = get_height if 'nodewatch' == source else connector.finalized_chain_height
		failing_method.side_effect = NodeException('connection unavailable')

		# Act:
		with pytest.raises(NodeException, match='connection unavailable'):
			await get_verified_finalization_epoch('http://nodewatch', config_manager, connector)

		# Assert: connection failures do not trigger a retry
		assert 1 == get_height.await_count
		assert (0 if 'nodewatch' == source else 1) == connector.finalized_chain_height.await_count


@pytest.mark.parametrize('nodewatch_height, rest_height', [(0, 20), (-1, 20), (20, 0), (20, -1)])
async def test_verification_rejects_invalid_heights(config_manager, nodewatch_height, rest_height):  # pylint: disable=redefined-outer-name
	# Arrange:
	connector = SimpleNamespace(endpoint='http://rest-node:3000', finalized_chain_height=AsyncMock(return_value=rest_height))
	with patch.object(NodewatchClient, 'symbol_finalized_height', return_value=nodewatch_height) as get_height:
		# Act:
		with pytest.raises(ValueError, match='finalized heights must be positive'):
			await get_verified_finalization_epoch('http://nodewatch', config_manager, connector)

		# Assert:
		assert 1 == get_height.await_count
		assert 1 == connector.finalized_chain_height.await_count


# region symbol_finalized_height

async def test_can_get_symbol_finalized_height(server):  # pylint: disable=redefined-outer-name
	# Arrange:
	client = NodewatchClient(server.make_url(''))

	# Act:
	finalized_height = await client.symbol_finalized_height()

	# Assert:
	assert [f'{server.make_url("")}/api/symbol/height'] == server.mock.urls
	assert 2033136 == finalized_height

# endregion


# region symbol_finalized_height

async def test_can_get_current_finalization_epoch(server):  # pylint: disable=redefined-outer-name
	# Arrange:
	with tempfile.TemporaryDirectory() as output_directory:
		with open(Path(output_directory) / 'config-network.properties', 'wt', encoding='utf8') as outfile:
			outfile.write('\n'.join([
				'[chain]',
				'',
				'votingSetGrouping = 720'
			]))

		# Act:
		current_finalization_epoch = await get_current_finalization_epoch(server.make_url(''), ConfigurationManager(output_directory))

		# Assert:
		assert [f'{server.make_url("")}/api/symbol/height'] == server.mock.urls
		assert 2825 == current_finalization_epoch  # 1 + ceil(2033136 / 720) = 2825

# endregion
