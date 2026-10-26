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

	async def resolve_peer_ports(self, required_roles=(0x01, 0x02), role_limits=None, prefer_api=False):
		"""Resolves enough P2P ports for each required role, replenishing failed candidates."""

		if prefer_api and 0x01 in required_roles:
			# Resolve dual-role peers first, even if peer-only nodes already fill the P2P quota.
			await self.resolve_peer_ports(required_roles=(0x03,), role_limits={0x03: (role_limits or {}).get(0x01, self.max_output_nodes)})

		counts, candidates = self._peer_port_requirements(required_roles)
		limits = {role: (role_limits or {}).get(role, self.max_output_nodes) for role in counts}
		if not candidates:
			return
		endpoints = list(candidates)
		random.shuffle(endpoints)
		candidates = {endpoint: candidates[endpoint] for endpoint in endpoints}
		async with ClientSession(connector=TCPConnector(limit=10)) as session:
			while candidates:
				batch = self._select_peer_port_batch(candidates, counts, limits)
				if not batch:
					break
				ports = await asyncio.gather(*(self._resolve_peer_port(session, endpoint) for endpoint in batch))
				for endpoint, port in zip(batch, ports):
					self.peer_ports[endpoint] = port
					if port is not None:
						for role, count in candidates[endpoint].items():
							counts[role] += count
					candidates.pop(endpoint)

	def _peer_port_requirements(self, required_roles):
		counts = dict.fromkeys(required_roles, 0)
		candidates = {}
		for node in self.nodes:
			roles = [role for role in counts if self._is_node_eligible(node, role)]
			if not roles:
				continue
			endpoint = node['endpoint']
			if not node['roles'] & 0x02 or self.peer_ports.get(endpoint) is not None:
				for role in roles:
					counts[role] += 1
			elif endpoint not in self.peer_ports:
				node_counts = candidates.setdefault(endpoint, dict.fromkeys(counts, 0))
				for role in roles:
					node_counts[role] += 1
		return counts, candidates

	@staticmethod
	def _select_peer_port_batch(candidates, counts, limits):
		reserved = counts.copy()
		batch = []
		for endpoint, node_counts in candidates.items():
			if not any(count and reserved[role] < limits[role] for role, count in node_counts.items()):
				continue
			batch.append(endpoint)
			# Reserve successful slots within this batch so we only replace failures in the next batch.
			for role, count in node_counts.items():
				reserved[role] += count
			if 10 == len(batch):
				break
		return batch

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
		"""Selects peers, prioritizing API-capable peers for later REST discovery."""

		return self._select_nodes(0x01, prefer_api=True)

	def select_api_nodes(self):
		"""Selects api nodes and converts them to PEERS JSON format."""

		return self._select_nodes(0x02)

	def select_api_endpoints(self):
		"""Selects api node endpoints."""

		return self._select_nodes(0x02, lambda node: node['endpoint'])

	def _select_nodes(self, required_role, formatter=None, prefer_api=False):
		formatter = formatter or self._map_node_to_peers_format
		matching_nodes = [formatter(node) for node in self.nodes if self._is_node_eligible(node, required_role)]
		matching_nodes = [node for node in matching_nodes if node is not None]
		random.shuffle(matching_nodes)
		if prefer_api:
			matching_nodes.sort(key=lambda node: 'api_port' not in node['endpoint'])
		return matching_nodes[:self.max_output_nodes]

	def _is_node_eligible(self, node, required_role):
		if _parse_endpoint(node.get('endpoint')) is None:
			return False
		return node['balance'] >= self.min_balance and required_role == node['roles'] & required_role

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
