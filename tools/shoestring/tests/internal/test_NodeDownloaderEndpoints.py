from unittest.mock import AsyncMock

import pytest

from shoestring.internal.NodeDownloader import NodeDownloader, detect_api_endpoints
from shoestring.internal.PeerDownloader import find_api_node

# pylint: disable=invalid-name

INVALID_ENDPOINTS = [
	None, False, 123, [], {}, '', 'not-a-url',
	'https://node.example.com', 'http://node.example.com:', 'http://:7900',
	'ftp://node.example.com:7900', 'http://node.example.com:0', 'http://node.example.com:65536',
	'http://node.example.com:-1', 'http://node.example.com:abc',
	'http://node.example.com:7900/', 'http://node.example.com:7900/path',
	'http://node.example.com:7900?', 'http://node.example.com:7900?query=1',
	'http://node.example.com:7900#', 'http://node.example.com:7900#fragment',
	'http://user:password@node.example.com:7900', 'http://@node.example.com:7900',
	'http://bad host:7900', ' http://node.example.com:7900',
	'http://node.example.com:7900\n', 'http://node.\texample.com:7900',
	'http://node.example.com:7900\x00', 'http://node.example.com:7900\x7f',
	'http://bad\\host:7900', 'http://[broken:7900', 'http://::1:7900'
]


def _make_node(endpoint, roles=3, public_key='healthy'):
	return {'mainPublicKey': public_key, 'endpoint': endpoint, 'roles': roles, 'balance': 100, 'name': 'node'}


@pytest.mark.parametrize('endpoint_fields', [{}, *[{'endpoint': endpoint} for endpoint in INVALID_ENDPOINTS]])
@pytest.mark.parametrize('roles', [1, 3])
async def test_invalid_endpoints_are_excluded_from_all_selection_paths(endpoint_fields, roles, monkeypatch):
	# Arrange:
	downloader = NodeDownloader('')
	downloader.nodes = [
		_make_node('http://node.example.com:7901', roles),
		{**_make_node(None, roles, 'invalid'), **endpoint_fields}
	]
	if not endpoint_fields:
		del downloader.nodes[1]['endpoint']
	resolver = AsyncMock(return_value=7902)
	monkeypatch.setattr(downloader, '_resolve_peer_port', resolver)

	# Act:
	await downloader.resolve_peer_ports()
	peer_nodes = downloader.select_peer_nodes()
	api_nodes = downloader.select_api_nodes()
	api_endpoints = downloader.select_api_endpoints()

	# Assert: invalid values never reach network requests or output formatters
	assert ['healthy'] == [node['publicKey'] for node in peer_nodes]
	assert (['http://node.example.com:7901'] if roles & 2 else []) == api_endpoints
	assert (['healthy'] if roles & 2 else []) == [node['publicKey'] for node in api_nodes]
	if roles & 2:
		assert 1 == resolver.await_count
		assert 'http://node.example.com:7901' == resolver.await_args.args[1]
	else:
		resolver.assert_not_awaited()


@pytest.mark.parametrize('download_method', ['download_peer_nodes', 'download_api_nodes'])
async def test_download_skips_bad_records_before_merging(download_method, monkeypatch, caplog):
	# Arrange:
	downloader = NodeDownloader('')
	healthy = _make_node('http://node.example.com:7900')
	downloader.nodes = [healthy]
	invalid_nodes = [_make_node(endpoint, public_key=str(index)) for index, endpoint in enumerate(INVALID_ENDPOINTS)]
	invalid_nodes += [{**healthy, 'endpoint': 'invalid'}, {key: value for key, value in healthy.items() if key != 'endpoint'}]
	monkeypatch.setattr(downloader, '_get', AsyncMock(return_value=invalid_nodes))

	# Act:
	await getattr(downloader, download_method)()

	# Assert: malformed updates cannot replace an existing valid node
	assert [healthy] == downloader.nodes
	assert len(invalid_nodes) == caplog.text.count('invalid endpoint')


@pytest.mark.parametrize('endpoint, expected_host, expected_port', [
	('http://node.example.com:1', 'node.example.com', 1),
	('https://node.example.com:65535', 'node.example.com', 65535),
	('http://127.0.0.1:80', '127.0.0.1', 80),
	('https://node.example.com:443', 'node.example.com', 443),
	('http://[::1]:7901', '::1', 7901),
	('https://[2001:db8::1]:3001', '2001:db8::1', 3001)
])
@pytest.mark.parametrize('roles', [1, 3])
def test_valid_endpoints_preserve_host_and_ports(endpoint, expected_host, expected_port, roles):
	# Arrange:
	downloader = NodeDownloader('')
	downloader.nodes = [_make_node(endpoint, roles)]
	downloader.peer_ports = {endpoint: 7902}

	# Act:
	nodes = downloader.select_peer_nodes()

	# Assert:
	expected = {'host': expected_host, 'port': 7902 if roles & 2 else expected_port}
	if roles & 2:
		expected['api_port'] = expected_port
	assert expected == nodes[0]['endpoint']
	assert ([endpoint] if roles & 2 else []) == downloader.select_api_endpoints()


async def test_all_invalid_candidates_produce_empty_discovery_and_clear_find_error(monkeypatch):
	# Arrange:
	monkeypatch.setattr(NodeDownloader, '_get', AsyncMock(return_value=[_make_node('invalid')]))

	# Act + Assert:
	assert [] == await detect_api_endpoints('http://nodewatch.example.com')
	with pytest.raises(RuntimeError, match='no REST API nodes are available'):
		await find_api_node('http://nodewatch.example.com')
