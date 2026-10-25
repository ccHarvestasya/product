import asyncio
import random
from urllib.parse import urlsplit

from aiohttp import ClientError, ClientSession, ClientTimeout, TCPConnector
from zenlog import log


def _parse_endpoint(endpoint):
	if not isinstance(endpoint, str) or not endpoint.startswith(('http://', 'https://')):
		return None
	if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in endpoint):
		return None
	try:
		url = urlsplit(endpoint)
		host, port = url.hostname, url.port
		if not host or port is None or not 0 < port <= 65535:
			return None
		if url.username is not None or url.password is not None or url.path or any(char in endpoint for char in ('?', '#', '\\')):
			return None
		return host, port
	except ValueError:
		return None


class NodeDownloader:
	"""Downloads and selects initial beacon nodes."""

	def __init__(self, endpoint):
		"""Creates a node downloader around an endpoint."""

		self.endpoint = endpoint

		self.nodes = []
		self.peer_ports = {}
		self.min_balance = 0
		self.max_output_nodes = 100

	async def download_peer_nodes(self):
		"""Downloads peer nodes."""

		await self._download_nodes('api/symbol/nodes/peer', 0x01)

	async def download_api_nodes(self):
		"""Downloads API nodes."""

		# Temporary workaround: NodeWatch's /api/symbol/nodes/api returns incorrect data.
		# Restore that endpoint once NodeWatch maintenance is complete; keep the API role filter.
		await self._download_nodes('api/symbol/nodes/peer', 0x02)

	async def _download_nodes(self, url_path, required_role):
		nodes_by_public_key = {node['mainPublicKey']: node for node in self.nodes}
		for node in await self._get(url_path):
			if not node['roles'] & required_role:
				continue
			if _parse_endpoint(node.get('endpoint')) is None:
				log.warning(f'skipping NodeWatch node {node["mainPublicKey"]}: invalid endpoint')
				continue
			nodes_by_public_key[node['mainPublicKey']] = node
		self.nodes = list(nodes_by_public_key.values())

	async def resolve_peer_ports(self):
		"""Resolves P2P ports for API nodes without changing their NodeWatch hosts."""

		endpoints = sorted({
			node['endpoint'] for node in self.nodes
			if self._is_node_eligible(node, 0x02) and node['endpoint'] not in self.peer_ports
		})
		semaphore = asyncio.Semaphore(10)
		async with ClientSession(connector=TCPConnector(limit=10)) as session:
			async def resolve(endpoint):
				async with semaphore:
					return await self._resolve_peer_port(session, endpoint)

			ports = await asyncio.gather(*(resolve(endpoint) for endpoint in endpoints))
			self.peer_ports.update(zip(endpoints, ports))

	@staticmethod
	async def _resolve_peer_port(session, endpoint):
		try:
			async with session.get(f'{endpoint}/node/info', timeout=ClientTimeout(total=10)) as response:
				response.raise_for_status()
				node_info = await response.json()
				port = node_info['port']
				if type(port) is not int or not 0 < port <= 65535:  # pylint: disable=unidiomatic-typecheck
					raise ValueError('invalid P2P port')
				return port
		except (ClientError, asyncio.TimeoutError, ValueError, KeyError, TypeError) as ex:
			log.warning(f'could not determine P2P port for {endpoint}: {ex}')
			return None

	def select_peer_nodes(self):
		"""Selects nodes and converts them to PEERS JSON format."""

		return self._select_nodes(0x01)

	def select_api_nodes(self):
		"""Selects api nodes and converts them to PEERS JSON format."""

		return self._select_nodes(0x02)

	def select_api_endpoints(self):
		"""Selects api node endpoints."""

		return self._select_nodes(0x02, lambda node: node['endpoint'])

	def _select_nodes(self, required_role, formatter=None):
		formatter = formatter or self._map_node_to_peers_format
		matching_nodes = [formatter(node) for node in self.nodes if self._is_node_eligible(node, required_role)]
		matching_nodes = [node for node in matching_nodes if node is not None]
		random.shuffle(matching_nodes)
		return matching_nodes[:self.max_output_nodes]

	def _is_node_eligible(self, node, required_role):
		return _parse_endpoint(node.get('endpoint')) is not None and node['balance'] >= self.min_balance and 0 != node['roles'] & required_role

	def _map_node_to_peers_format(self, node):
		parsed_endpoint = _parse_endpoint(node.get('endpoint'))
		if parsed_endpoint is None:
			return None
		host, endpoint_port = parsed_endpoint
		has_api = 0 != node['roles'] & 0x02
		peer_port = self.peer_ports.get(node['endpoint']) if has_api else endpoint_port
		if peer_port is None:
			return None

		node_json = {
			'publicKey': node['mainPublicKey'],
			'endpoint': {
				'host': host,
				'port': peer_port
			},
			'metadata': {
				'name': node['name'],
				'roles': self._stringify_roles(node['roles'])
			}
		}

		if has_api:
			node_json['endpoint']['api_port'] = endpoint_port

		return node_json

	@staticmethod
	def _stringify_roles(roles):
		role_parts = []
		for role in [(0x01, 'Peer'), (0x02, 'Api'), (0x04, 'Voting'), (0x40, 'IPv4'), (0x80, 'IPv6')]:
			if roles & role[0]:
				role_parts.append(role[1])

		return ','.join(role_parts)

	async def _get(self, url_path):
		"""Initiates a GET to the specified path and returns the desired property."""

		async with ClientSession() as session:
			async with session.get(f'{self.endpoint}/{url_path}') as response:
				response_json = await response.json()
				return response_json


async def detect_api_endpoints(nodewatch_endpoint, count=1):
	"""Uses nodewatch to detect up to the specified number of API endpoints."""

	downloader = NodeDownloader(nodewatch_endpoint)
	downloader.max_output_nodes = count
	await downloader.download_api_nodes()
	return downloader.select_api_endpoints()[:count]
