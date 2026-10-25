import asyncio
import json
from unittest.mock import AsyncMock, Mock

import pytest
from aiohttp import ClientConnectionError, web

from shoestring.internal.NodeDownloader import NodeDownloader
from shoestring.internal.PeerDownloader import download_peers

# pylint: disable=invalid-name


def _make_node(endpoint, roles, public_key='api node'):
	return {
		'mainPublicKey': public_key,
		'endpoint': endpoint,
		'name': 'custom port node',
		'balance': 100,
		'roles': roles
	}


async def test_can_generate_peer_files_with_resolved_peer_ports(aiohttp_client, tmp_path):
	# Arrange:
	info_requests = []
	peer_nodes = []

	async def node_info(request):
		info_requests.append(request.path)
		return web.json_response({'port': 7903, 'host': 'different.example.com'})

	async def peers(request):
		info_requests.append(request.path)
		return web.json_response(peer_nodes)

	async def apis(request):
		info_requests.append(request.path)
		raise web.HTTPServiceUnavailable()

	app = web.Application()
	app.router.add_get('/api/symbol/nodes/peer', peers)
	app.router.add_get('/api/symbol/nodes/api', apis)
	app.router.add_get('/node/info', node_info)
	client = await aiohttp_client(app)
	endpoint = str(client.make_url('')).rstrip('/')
	peer_nodes.extend([
		_make_node(endpoint, 3),
		_make_node(endpoint, 3),
		_make_node(endpoint, 2, 'second api node'),
		_make_node('http://peer.example.com:7902', 1, 'peer node'),
		_make_node('not-a-url', 3, 'invalid URL'),
		_make_node({}, 3, 'invalid type'),
		{**_make_node('http://excluded.example.com:3000', 3, 'excluded node'), 'balance': 0}
	])

	# Act:
	api_endpoints = await download_peers(endpoint, tmp_path, True, min_balance=1)

	# Assert: download both lists first, deduplicate nodes, then resolve each REST endpoint once
	assert ['/api/symbol/nodes/peer', '/api/symbol/nodes/peer'] == info_requests[:2]
	assert ['/node/info'] == info_requests[2:]
	assert {endpoint} == set(api_endpoints)
	for peers_name, expected_ports in [('p2p', [7903, 7902]), ('api', [7903, 7903])]:
		peers_json = json.loads((tmp_path / f'peers-{peers_name}.json').read_text(encoding='utf8'))
		assert expected_ports == [node['endpoint']['port'] for node in peers_json['knownPeers']]
		assert '127.0.0.1' == peers_json['knownPeers'][0]['endpoint']['host']
		assert client.server.port == peers_json['knownPeers'][0]['endpoint']['api_port']


async def test_downloads_merge_nodes_by_public_key():
	# Arrange:
	downloader = NodeDownloader('')
	downloader._get = AsyncMock(side_effect=[  # pylint: disable=protected-access
		[_make_node('http://peer.example.com:7901', 1, 'peer node'), _make_node('http://old.example.com:3000', 3)],
		[_make_node('https://new.example.com:3001', 3), _make_node('http://api.example.com:3000', 2, 'second api node')]
	])

	# Act:
	await downloader.download_peer_nodes()
	await downloader.download_api_nodes()

	# Assert: the latest record replaces the same identity without losing distinct nodes
	assert ['peer node', 'api node', 'second api node'] == [node['mainPublicKey'] for node in downloader.nodes]
	assert 'https://new.example.com:3001' == downloader.nodes[1]['endpoint']
	assert ['https://new.example.com:3001', 'http://api.example.com:3000'] == sorted(
		downloader.select_api_endpoints(), reverse=True)


@pytest.mark.parametrize('download_method, expected_roles', [
	('download_peer_nodes', [1, 3, 5, 7]),
	('download_api_nodes', [2, 3, 6, 7])
])
async def test_downloads_filter_roles_from_peer_endpoint(download_method, expected_roles):
	# Arrange:
	downloader = NodeDownloader('')
	downloader._get = AsyncMock(return_value=[  # pylint: disable=protected-access
		_make_node('http://node.example.com:3000', roles, str(roles)) for roles in range(8)
	])

	# Act:
	await getattr(downloader, download_method)()

	# Assert: use the peer endpoint for both roles until NodeWatch's API endpoint is repaired
	downloader._get.assert_awaited_once_with('api/symbol/nodes/peer')  # pylint: disable=protected-access
	assert expected_roles == [node['roles'] for node in downloader.nodes]


@pytest.mark.parametrize('node_info, status', [
	({'port': 0}, 200),
	({'port': -1}, 200),
	({'port': 65536}, 200),
	({'port': '7901'}, 200),
	({'port': True}, 200),
	({}, 200),
	(None, 200),
	([], 200),
	({'port': 7901}, 503)
])
async def test_unresolved_api_nodes_are_excluded_from_peer_files(aiohttp_client, node_info, status, caplog):
	# Arrange:
	async def info(_):
		return web.json_response(node_info, status=status)

	app = web.Application()
	app.router.add_get('/node/info', info)
	client = await aiohttp_client(app)
	endpoint = str(client.make_url('')).rstrip('/')
	downloader = NodeDownloader('')
	downloader.nodes = [_make_node(endpoint, 3), _make_node('http://peer.example.com:7901', 1, 'peer node')]

	# Act:
	await downloader.resolve_peer_ports()

	# Assert: no guessed port or REST port is saved, and REST discovery is still available
	assert [] == downloader.select_api_nodes()
	assert [endpoint] == downloader.select_api_endpoints()
	assert [7901] == [node['endpoint']['port'] for node in downloader.select_peer_nodes()]
	assert 'could not determine P2P port' in caplog.text


@pytest.mark.parametrize('error', [asyncio.TimeoutError(), ClientConnectionError()])
async def test_cannot_resolve_peer_port_on_connection_failure(error):
	# Arrange:
	session = Mock()
	session.get.side_effect = error

	# Act:
	port = await NodeDownloader._resolve_peer_port(session, 'http://node.example.com:3000')  # pylint: disable=protected-access

	# Assert:
	assert port is None
	assert 10 == session.get.call_args.kwargs['timeout'].total
