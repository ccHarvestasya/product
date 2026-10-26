import asyncio
import json
from unittest.mock import AsyncMock

import pytest
from aiohttp import web

from shoestring.commands.renew_voting_keys import _get_network_time
from shoestring.internal.NodeDownloader import NodeDownloader
from shoestring.internal.PeerDownloader import download_peers, load_api_endpoints

# pylint: disable=invalid-name


def _node(index, roles=3):
	return {
		'mainPublicKey': f'{index:064X}',
		'endpoint': f'http://node{index}.example.com:3000',
		'name': 'node',
		'roles': roles,
		'balance': 100
	}


@pytest.fixture
def downloader(monkeypatch):
	monkeypatch.setattr('shoestring.internal.NodeDownloader.random.shuffle', lambda _: None)
	instance = NodeDownloader('')
	instance.max_output_nodes = 20
	instance.nodes = [_node(index) for index in range(60)]
	return instance


async def test_stops_after_enough_peers_are_resolved(downloader, monkeypatch):  # pylint: disable=redefined-outer-name
	# Arrange:
	resolver = AsyncMock(return_value=7900)
	monkeypatch.setattr(downloader, '_resolve_peer_port', resolver)

	# Act:
	await downloader.resolve_peer_ports()

	# Assert:
	assert 20 == resolver.await_count
	assert 20 == len(downloader.select_peer_nodes())
	assert 20 == len(downloader.select_api_nodes())


async def test_refills_failed_candidates_with_at_most_ten_concurrent_requests(
	downloader, monkeypatch
):  # pylint: disable=redefined-outer-name
	# Arrange:
	requests = []
	concurrency = [0, 0]

	async def resolve(_, endpoint):
		requests.append(endpoint)
		concurrency[0] += 1
		concurrency[1] = max(concurrency)
		await asyncio.sleep(0)
		concurrency[0] -= 1
		return None if endpoint in {f'http://node{index}.example.com:3000' for index in range(3)} else 7900

	monkeypatch.setattr(downloader, '_resolve_peer_port', resolve)

	# Act:
	await downloader.resolve_peer_ports()

	# Assert:
	assert 23 == len(requests)
	assert len(requests) == len(set(requests))
	assert 10 == concurrency[1]
	assert 20 == len(downloader.select_peer_nodes())
	assert 20 == len(downloader.select_api_nodes())


@pytest.mark.parametrize('required_roles, expected_requests', [((1,), 0), ((2,), 20), ((1, 2), 20)])
async def test_counts_peer_only_nodes_and_skips_unneeded_roles(
	downloader, monkeypatch, required_roles, expected_requests
):  # pylint: disable=redefined-outer-name
	# Arrange:
	downloader.nodes = [_node(index, 2) for index in range(60)] + [_node(index, 1) for index in range(60, 120)]
	resolver = AsyncMock(return_value=7900)
	monkeypatch.setattr(downloader, '_resolve_peer_port', resolver)

	# Act:
	await downloader.resolve_peer_ports(required_roles=required_roles)

	# Assert:
	assert expected_requests == resolver.await_count
	assert 20 == len(downloader.select_peer_nodes())
	assert expected_requests == len(downloader.select_api_nodes())


async def test_resolves_both_roles_when_api_only_candidates_fill_the_first_batches(
	downloader, monkeypatch
):  # pylint: disable=redefined-outer-name
	# Arrange:
	downloader.nodes = [_node(index, 2) for index in range(30)] + [_node(index, 3) for index in range(30, 60)]
	resolver = AsyncMock(return_value=7900)
	monkeypatch.setattr(downloader, '_resolve_peer_port', resolver)

	# Act:
	await downloader.resolve_peer_ports()

	# Assert: filling the API quota must not prevent filling the Peer quota
	assert 40 == resolver.await_count
	assert 20 == len(downloader.select_peer_nodes())
	assert 20 == len(downloader.select_api_nodes())


async def test_counts_cached_successes_and_never_retries_cached_failures(downloader, monkeypatch):  # pylint: disable=redefined-outer-name
	# Arrange:
	downloader.peer_ports = {f'http://node{index}.example.com:3000': 7900 for index in range(5)}
	downloader.peer_ports['http://node5.example.com:3000'] = None
	resolver = AsyncMock(return_value=7900)
	monkeypatch.setattr(downloader, '_resolve_peer_port', resolver)

	# Act:
	await downloader.resolve_peer_ports()
	await downloader.resolve_peer_ports()

	# Assert:
	assert 15 == resolver.await_count
	assert all('http://node5.example.com:3000' != call.args[1] for call in resolver.await_args_list)
	assert 20 == len(downloader.select_peer_nodes())


async def test_shared_endpoint_can_satisfy_multiple_node_slots(downloader, monkeypatch):  # pylint: disable=redefined-outer-name
	# Arrange:
	downloader.nodes = [{**_node(index), 'endpoint': 'http://shared.example.com:3000'} for index in range(20)]
	resolver = AsyncMock(return_value=7900)
	monkeypatch.setattr(downloader, '_resolve_peer_port', resolver)

	# Act:
	await downloader.resolve_peer_ports()

	# Assert:
	assert 1 == resolver.await_count
	assert 20 == len(downloader.select_peer_nodes())
	assert 20 == len(downloader.select_api_nodes())


async def test_ineligible_peer_only_nodes_do_not_fill_the_quota(downloader, monkeypatch):  # pylint: disable=redefined-outer-name
	# Arrange:
	downloader.min_balance = 50
	downloader.nodes = [{**_node(index, 1), 'balance': 0} for index in range(20)] + downloader.nodes[20:]
	resolver = AsyncMock(return_value=7900)
	monkeypatch.setattr(downloader, '_resolve_peer_port', resolver)

	# Act:
	await downloader.resolve_peer_ports(required_roles=(1,))

	# Assert:
	assert 20 == resolver.await_count
	assert 20 == len(downloader.select_peer_nodes())


@pytest.mark.parametrize('existing_files', [False, True])
@pytest.mark.parametrize('scenario', [
	('port-lookups', False, 'P2P'),
	('port-lookups', True, 'P2P'),
	('invalid-endpoints', False, 'P2P'),
	('no-api', True, 'API'),
	('api-only', True, 'P2P')
])
async def test_missing_peers_fail_before_any_files_are_written(
	tmp_path, monkeypatch, existing_files, scenario
):
	# Arrange:
	failure, save_api_nodes, missing_role = scenario
	nodes = [_node(0, {'no-api': 1, 'api-only': 2}.get(failure, 3))]
	if 'invalid-endpoints' == failure:
		nodes[0]['endpoint'] = 'invalid'
	monkeypatch.setattr(NodeDownloader, '_get', AsyncMock(return_value=nodes))
	monkeypatch.setattr(NodeDownloader, '_resolve_peer_port', AsyncMock(return_value=None if 'port-lookups' == failure else 7900))
	if existing_files:
		for name in ('p2p', 'api'):
			(tmp_path / f'peers-{name}.json').write_bytes(f'original {name}'.encode('utf8'))

	# Act + Assert:
	with pytest.raises(RuntimeError, match=f'no usable {missing_role} peer nodes'):
		await download_peers('http://nodewatch.example.com', tmp_path, save_api_nodes)
	if existing_files:
		for name in ('p2p', 'api'):
			assert f'original {name}'.encode('utf8') == (tmp_path / f'peers-{name}.json').read_bytes()
	else:
		assert not list(tmp_path.iterdir())


async def test_can_save_fewer_than_twenty_peers_when_candidates_are_exhausted(tmp_path, monkeypatch):
	# Arrange:
	monkeypatch.setattr('shoestring.internal.NodeDownloader.random.shuffle', lambda _: None)
	monkeypatch.setattr(NodeDownloader, '_get', AsyncMock(return_value=[_node(index) for index in range(3)]))
	resolver = AsyncMock(side_effect=[None, 7901, None])
	monkeypatch.setattr(NodeDownloader, '_resolve_peer_port', resolver)

	# Act:
	await download_peers('http://nodewatch.example.com', tmp_path, True)

	# Assert:
	assert 3 == resolver.await_count
	for name in ('p2p', 'api'):
		peers = json.loads((tmp_path / f'peers-{name}.json').read_text(encoding='utf8'))['knownPeers']
		assert 1 == len(peers)
		assert 7901 == peers[0]['endpoint']['port']


async def test_peer_file_retains_rest_endpoint_for_voting_key_renewal(aiohttp_client, tmp_path, monkeypatch):
	# Arrange:
	monkeypatch.setattr('shoestring.internal.NodeDownloader.random.shuffle', lambda _: None)
	nodes = [_node(index, 1) for index in range(20)]
	requests = []

	async def nodewatch(_):
		return web.json_response(nodes)

	async def node_info(request):
		requests.append(request.path)
		return web.json_response({'port': 7901})

	async def node_time(request):
		requests.append(request.path)
		return web.json_response({'communicationTimestamps': {'sendTimestamp': 123}})

	app = web.Application()
	app.router.add_get('/api/symbol/nodes/peer', nodewatch)
	app.router.add_get('/node/info', node_info)
	app.router.add_get('/node/time', node_time)
	client = await aiohttp_client(app)
	endpoint = str(client.make_url('')).rstrip('/')
	nodes.append({**_node(20), 'endpoint': endpoint})

	# Act: the renewal command must be able to reuse the REST endpoint from the saved peer file
	await download_peers(endpoint, tmp_path)
	network_time = await _get_network_time(tmp_path)

	# Assert:
	peers = json.loads((tmp_path / 'peers-p2p.json').read_text(encoding='utf8'))['knownPeers']
	assert 20 == len(peers)
	assert 1 == sum('api_port' in node['endpoint'] for node in peers)
	assert not (tmp_path / 'peers-api.json').exists()
	assert [endpoint] == load_api_endpoints(tmp_path)
	assert 123 == network_time.timestamp
	assert ['/node/info', '/node/time'] == requests


@pytest.mark.parametrize('save_api_nodes', [False, True])
async def test_save_prioritizes_api_peers_and_refills_failed_candidates(tmp_path, monkeypatch, save_api_nodes):
	# Arrange:
	monkeypatch.setattr('shoestring.internal.NodeDownloader.random.shuffle', lambda _: None)
	nodes = [_node(index, 1) for index in range(20)] + [_node(index, 3) for index in range(20, 80)]
	monkeypatch.setattr(NodeDownloader, '_get', AsyncMock(return_value=nodes))
	resolver = AsyncMock(side_effect=[None] + [7901] * 20)
	monkeypatch.setattr(NodeDownloader, '_resolve_peer_port', resolver)

	# Act:
	await download_peers('http://nodewatch.example.com', tmp_path, save_api_nodes)

	# Assert: stop after filling the output with API-capable peers, reusing the resolved ports for both files.
	assert 21 == resolver.await_count
	assert {f'http://node{index}.example.com:3000' for index in range(21, 41)} == set(load_api_endpoints(tmp_path))
	peers = json.loads((tmp_path / 'peers-p2p.json').read_text(encoding='utf8'))['knownPeers']
	assert 20 == len(peers)
	assert 20 == sum('api_port' in node['endpoint'] for node in peers)
	assert save_api_nodes == (tmp_path / 'peers-api.json').exists()


@pytest.mark.parametrize('limit', [0, 1, 20])
def test_prioritizing_api_peers_respects_limit_and_excludes_api_only_nodes(downloader, limit):  # pylint: disable=redefined-outer-name
	# Arrange:
	downloader.max_output_nodes = limit
	downloader.nodes = [_node(index, 1) for index in range(20)] + [_node(20, 2), _node(21, 3)]
	downloader.peer_ports = {f'http://node{index}.example.com:3000': 7900 for index in (20, 21)}

	# Act:
	peers = downloader.select_peer_nodes()

	# Assert:
	assert limit == len(peers)
	if limit:
		assert 1 == sum('api_port' in node['endpoint'] for node in peers)
		assert f'{21:064X}' in [node['publicKey'] for node in peers]
		assert f'{20:064X}' not in [node['publicKey'] for node in peers]


@pytest.mark.parametrize('api_count, expected_api_count', [(0, 0), (4, 3), (30, 20)])
async def test_api_priority_fills_shortfall_with_peer_only_nodes(tmp_path, monkeypatch, api_count, expected_api_count):
	# Arrange:
	nodes = [_node(index, 1) for index in range(20)] + [_node(index, 3) for index in range(20, 20 + api_count)]
	monkeypatch.setattr(NodeDownloader, '_get', AsyncMock(return_value=nodes))
	resolver = AsyncMock(side_effect=lambda _, endpoint: None if endpoint == 'http://node20.example.com:3000' else 7901)
	monkeypatch.setattr(NodeDownloader, '_resolve_peer_port', resolver)

	# Act:
	await download_peers('http://nodewatch.example.com', tmp_path)

	# Assert:
	peers = json.loads((tmp_path / 'peers-p2p.json').read_text(encoding='utf8'))['knownPeers']
	assert 20 == len(peers)
	assert expected_api_count == sum('api_port' in node['endpoint'] for node in peers)
	assert expected_api_count == len(load_api_endpoints(tmp_path))
	assert not (tmp_path / 'peers-api.json').exists()
	assert resolver.await_count <= min(api_count, 21)


@pytest.mark.parametrize('has_api_candidates', [False, True])
async def test_warns_and_saves_peer_only_nodes_without_usable_api_peers(tmp_path, monkeypatch, has_api_candidates):
	# Arrange:
	nodes = [_node(0, 1)] + ([_node(1, 3)] if has_api_candidates else [])
	monkeypatch.setattr(NodeDownloader, '_get', AsyncMock(return_value=nodes))
	monkeypatch.setattr(NodeDownloader, '_resolve_peer_port', AsyncMock(return_value=None))
	warnings = []
	monkeypatch.setattr('shoestring.internal.PeerDownloader.log.warning', warnings.append)

	# Act:
	await download_peers('http://nodewatch.example.com', tmp_path)

	# Assert:
	peers = json.loads((tmp_path / 'peers-p2p.json').read_text(encoding='utf8'))['knownPeers']
	assert [f'{0:064X}'] == [node['publicKey'] for node in peers]
	assert not load_api_endpoints(tmp_path)
	assert any('no API-capable P2P peers' in warning for warning in warnings)


async def test_priority_skips_ineligible_peers_and_reuses_cached_ports(downloader, monkeypatch):  # pylint: disable=redefined-outer-name
	# Arrange:
	downloader.min_balance = 50
	downloader.nodes = [_node(index, 2) for index in range(20)]
	downloader.nodes += [_node(20, 1), {**_node(21), 'balance': 0}, {**_node(22), 'endpoint': 'invalid'}]
	downloader.nodes += [_node(index) for index in range(23, 26)]
	downloader.peer_ports = {'http://node23.example.com:3000': 7901, 'http://node24.example.com:3000': None}
	resolver = AsyncMock(return_value=7901)
	monkeypatch.setattr(downloader, '_resolve_peer_port', resolver)

	# Act:
	await downloader.resolve_peer_ports(required_roles=(1,), prefer_api=True)
	await downloader.resolve_peer_ports(required_roles=(1,), prefer_api=True)
	peers = downloader.select_peer_nodes()

	# Assert:
	assert 1 == resolver.await_count
	assert 'http://node25.example.com:3000' == resolver.await_args.args[1]
	assert [f'{index:064X}' for index in (23, 25, 20)] == [node['publicKey'] for node in peers]


async def test_dual_role_peers_are_resolved_before_api_only_candidates(tmp_path, monkeypatch):
	# Arrange:
	monkeypatch.setattr('shoestring.internal.NodeDownloader.random.shuffle', lambda _: None)
	nodes = [_node(index, 2) for index in range(30)] + [_node(index, 3) for index in range(30, 60)]
	monkeypatch.setattr(NodeDownloader, '_get', AsyncMock(return_value=nodes))
	resolver = AsyncMock(return_value=7901)
	monkeypatch.setattr(NodeDownloader, '_resolve_peer_port', resolver)

	# Act:
	await download_peers('http://nodewatch.example.com', tmp_path, True)

	# Assert: the same twenty dual-role nodes satisfy both files without resolving any API-only nodes.
	assert [f'http://node{index}.example.com:3000' for index in range(30, 50)] == [
		call.args[1] for call in resolver.await_args_list
	]
	for name in ('p2p', 'api'):
		peers = json.loads((tmp_path / f'peers-{name}.json').read_text(encoding='utf8'))['knownPeers']
		assert [f'{index:064X}' for index in range(30, 50)] == [node['publicKey'] for node in peers]


def test_priority_preserves_random_order_within_each_group(downloader, monkeypatch):  # pylint: disable=redefined-outer-name
	# Arrange:
	downloader.nodes = [_node(0, 1), _node(1, 3), _node(2, 1), _node(3, 3)]
	downloader.peer_ports = {node['endpoint']: 7901 for node in downloader.nodes if node['roles'] & 2}
	monkeypatch.setattr('shoestring.internal.NodeDownloader.random.shuffle', lambda nodes: nodes.reverse())

	# Act:
	peers = downloader.select_peer_nodes()

	# Assert:
	assert [f'{index:064X}' for index in (3, 1, 2, 0)] == [node['publicKey'] for node in peers]
