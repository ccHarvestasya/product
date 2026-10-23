from aiohttp import ClientSession
from zenlog import log

from .HeightGrouping import calculate_finalization_epoch_for_height


class NodewatchClient:
	"""Client for connecting to the nodewatch service."""

	def __init__(self, endpoint):
		"""Creates a nodewatch client."""

		self.endpoint = endpoint

	async def _get_height(self, blockchain):
		async with ClientSession() as session:
			async with session.get(f'{self.endpoint}/api/{blockchain}/height') as response:
				response_json = await response.json()
				return response_json

	async def symbol_finalized_height(self):
		"""Gets current Symbol finalized height."""

		response = await self._get_height('symbol')
		return response['finalizedHeight']


async def get_current_finalization_epoch(nodewatch_endpoint, config_manager):
	"""Calculates the current finalization epoch."""

	nodewatch_client = NodewatchClient(nodewatch_endpoint)
	last_finalized_height = await nodewatch_client.symbol_finalized_height()
	log.info(_('nodewatch-client-detected-height').format(height=last_finalized_height))

	voting_set_grouping = int(config_manager.lookup('config-network.properties', [('chain', 'votingSetGrouping')])[0])
	current_finalization_epoch = calculate_finalization_epoch_for_height(last_finalized_height, voting_set_grouping)
	log.info(_('nodewatch-client-detected-epoch').format(epoch=current_finalization_epoch))

	return current_finalization_epoch


async def get_verified_finalization_epoch(nodewatch_endpoint, config_manager, connector):
	"""Calculates the current epoch and verifies it against a REST node, retrying one mismatch."""

	nodewatch_client = NodewatchClient(nodewatch_endpoint)
	voting_set_grouping = int(config_manager.lookup('config-network.properties', [('chain', 'votingSetGrouping')])[0])
	for attempt in range(2):
		nodewatch_height = await nodewatch_client.symbol_finalized_height()
		rest_height = await connector.finalized_chain_height()
		if nodewatch_height < 1 or rest_height < 1:
			raise ValueError('finalized heights must be positive')

		nodewatch_epoch = calculate_finalization_epoch_for_height(nodewatch_height, voting_set_grouping)
		rest_epoch = calculate_finalization_epoch_for_height(rest_height, voting_set_grouping)
		state = {
			'endpoint': connector.endpoint,
			'nodewatch_height': nodewatch_height,
			'nodewatch_epoch': nodewatch_epoch,
			'rest_height': rest_height,
			'rest_epoch': rest_epoch
		}
		if nodewatch_epoch == rest_epoch:
			log.info(_('nodewatch-client-verified-epoch').format(**state))
			return nodewatch_epoch

		if attempt:
			raise RuntimeError(_('nodewatch-client-inconsistent-epochs-aborting').format(**state))

		log.warning(_('nodewatch-client-inconsistent-epochs-retrying').format(**state))
