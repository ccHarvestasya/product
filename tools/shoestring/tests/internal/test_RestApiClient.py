import asyncio
from unittest.mock import AsyncMock

import pytest
from aiohttp import ClientConnectionError, web
from symbollightapi.model.Exceptions import HttpException, InsufficientBalanceException, NodeException

from shoestring.internal.RestApiClient import run_with_api_nodes

# pylint: disable=invalid-name


@pytest.mark.parametrize('error', [
	NodeException('connection failed'),
	ClientConnectionError('connection reset'),
	asyncio.TimeoutError(),
	HttpException('unavailable', 503),
	HttpException('request timeout', 408),
	HttpException('rate limited', 429),
	HttpException('unauthorized', 401),
	HttpException('forbidden', 403),
	HttpException('not found', 404)
])
async def test_can_try_next_distinct_node_on_communication_failure(error):
	# Arrange:
	operation = AsyncMock(side_effect=[error, 'result'])

	# Act:
	result = await run_with_api_nodes(['http://first:3000', 'http://first:3000', 'https://second:443'], operation)

	# Assert:
	assert 'result' == result
	assert ['http://first:3000', 'https://second:443'] == [call.args[0].endpoint for call in operation.await_args_list]
	assert all(10 == call.args[0].timeout_seconds for call in operation.await_args_list)


@pytest.mark.parametrize('error', [
	HttpException('invalid transaction', 400),
	InsufficientBalanceException('insufficient balance'),
	ValueError('invalid input'),
	asyncio.CancelledError()
])
async def test_does_not_retry_rejected_operations_or_cancellation(error):
	# Arrange:
	operation = AsyncMock(side_effect=error)

	# Act + Assert:
	with pytest.raises(type(error)) as exception_info:
		await run_with_api_nodes(['http://first:3000', 'http://second:3000'], operation)
	assert error is exception_info.value
	assert 1 == operation.await_count


async def test_all_failed_nodes_produce_error_with_last_failure_as_cause():
	# Arrange:
	error = NodeException('offline')
	operation = AsyncMock(side_effect=error)

	# Act + Assert:
	with pytest.raises(RuntimeError, match='failed on all available API nodes') as exception_info:
		await run_with_api_nodes(['http://first:3000', 'http://second:3000'], operation)
	assert error is exception_info.value.__cause__
	assert 2 == operation.await_count


async def test_no_candidates_produce_clear_error():
	# Arrange:
	operation = AsyncMock()

	# Act + Assert:
	with pytest.raises(RuntimeError, match='no REST API nodes are available'):
		await run_with_api_nodes([], operation)
	operation.assert_not_awaited()


@pytest.mark.parametrize('failure', [
	'offline', 'unavailable', 'invalid-json', 'unauthorized', 'forbidden', 'not-found',
	'missing-field', 'invalid-timestamp', 'invalid-type'
])
async def test_can_recover_from_actual_rest_connection_failures(aiohttp_client, failure):
	# Arrange:
	async def failing_time(_):
		if 'invalid-json' == failure:
			return web.Response(text='not json')
		if failure in ('unauthorized', 'forbidden', 'not-found'):
			return web.json_response({'message': 'node access error'}, status={
				'unauthorized': 401, 'forbidden': 403, 'not-found': 404
			}[failure])
		if 'missing-field' == failure:
			return web.json_response({})
		if 'invalid-timestamp' == failure:
			return web.json_response({'communicationTimestamps': {'sendTimestamp': 'invalid'}})
		if 'invalid-type' == failure:
			return web.json_response({'communicationTimestamps': None})
		return web.json_response({'message': 'unavailable'}, status=503)

	async def healthy_time(_):
		return web.json_response({'communicationTimestamps': {'sendTimestamp': 123456789}})

	failing_app = web.Application()
	failing_app.router.add_get('/node/time', failing_time)
	failing_client = await aiohttp_client(failing_app)
	failing_endpoint = str(failing_client.make_url('')).rstrip('/')
	if 'offline' == failure:
		await failing_client.close()

	healthy_app = web.Application()
	healthy_app.router.add_get('/node/time', healthy_time)
	healthy_client = await aiohttp_client(healthy_app)
	healthy_endpoint = str(healthy_client.make_url('')).rstrip('/')

	# Act:
	network_time = await run_with_api_nodes([failing_endpoint, healthy_endpoint], lambda connector: connector.network_time())

	# Assert:
	assert 123456789 == network_time.timestamp


@pytest.mark.parametrize('method, response', [
	('account_links', {}),
	('account_links', {'account': None}),
	('account_links', {'account': {'supplementalPublicKeys': {'linked': {'publicKey': 'invalid'}}}}),
	('account_multisig', {}),
	('account_multisig', {'multisig': None})
])
async def test_can_retry_invalid_account_responses(aiohttp_client, method, response):
	# Arrange:
	requests = []

	async def account(request):
		requests.append(request.path)
		if request.path.startswith('/bad/'):
			return web.json_response(response)
		return web.json_response({'code': 'ResourceNotFound'}, status=404)

	app = web.Application()
	app.router.add_get('/{path:.*}', account)
	client = await aiohttp_client(app)
	endpoint = str(client.make_url('')).rstrip('/')

	# Act:
	result = await run_with_api_nodes(
		[f'{endpoint}/bad', endpoint], lambda connector: getattr(connector, method)('account-id'))

	# Assert: a legitimate ResourceNotFound response remains a successful empty account result
	assert 2 == len(requests)
	if 'account_links' == method:
		assert result.linked_public_key is None
	else:
		assert 0 == result.min_approval


async def test_does_not_retry_local_error_after_successful_read(aiohttp_client):
	# Arrange:
	requests = []

	async def time(request):
		requests.append(request.path)
		return web.json_response({'communicationTimestamps': {'sendTimestamp': 123}})

	async def operation(connector):
		await connector.network_time()
		raise ValueError('invalid local input')

	app = web.Application()
	app.router.add_get('/{path:.*}', time)
	client = await aiohttp_client(app)
	endpoint = str(client.make_url('')).rstrip('/')

	# Act + Assert:
	with pytest.raises(ValueError, match='invalid local input'):
		await run_with_api_nodes([f'{endpoint}/first', f'{endpoint}/second'], operation)
	assert ['/first/node/time'] == requests


@pytest.mark.parametrize('status', [400, 409, 422])
@pytest.mark.parametrize('response', [{'message': 'transaction request rejected'}, None, 'invalid-json'])
async def test_does_not_retry_rejected_transaction_requests(aiohttp_client, status, response):
	# Arrange:
	requests = []

	async def announce(request):
		requests.append(request.path)
		if 'invalid-json' == response:
			return web.Response(text='not json', status=status)
		return web.json_response(response, status=status)

	app = web.Application()
	app.router.add_put('/{path:.*}', announce)
	client = await aiohttp_client(app)
	endpoint = str(client.make_url('')).rstrip('/')

	# Act + Assert:
	with pytest.raises(HttpException) as exception_info:
		await run_with_api_nodes(
			[f'{endpoint}/first', f'{endpoint}/second'], lambda connector: connector.put('transactions', {'payload': 'ABC'}))
	assert status == exception_info.value.http_status_code
	assert ['/first/transactions'] == requests


@pytest.mark.parametrize('method, path', [
	('announce_transaction', 'transactions'),
	('announce_partial_transaction', 'transactions/partial')
])
@pytest.mark.parametrize('status, response', [
	(401, {'message': 'restricted node'}),
	(403, {'message': 'restricted node'}),
	(404, {'message': 'missing route'}),
	(503, None),
	(503, 1),
	(503, []),
	(503, 'invalid-json')
])
async def test_can_retry_announcements_on_node_errors(aiohttp_client, method, path, status, response):
	# Arrange:
	requests = []

	async def announce(request):
		requests.append((request.path, await request.json()))
		if request.path.startswith('/first/'):
			if 'invalid-json' == response:
				return web.Response(text='not json', status=status)
			return web.json_response(response, status=status)
		return web.json_response({'message': 'accepted'}, status=202)

	app = web.Application()
	app.router.add_put('/{path:.*}', announce)
	client = await aiohttp_client(app)
	endpoint = str(client.make_url('')).rstrip('/')

	# Act:
	await run_with_api_nodes(
		[f'{endpoint}/first', f'{endpoint}/second'], lambda connector: getattr(connector, method)(b'\xAB'))

	# Assert: response parsing and access restrictions do not prevent retrying the same payload
	assert [(f'/first/{path}', {'payload': 'AB'}), (f'/second/{path}', {'payload': 'AB'})] == requests


@pytest.mark.parametrize('request_factory', [
	lambda connector: connector.put('transactions', {'payload': object()}),
	lambda connector: connector.announce_transaction(object())
])
async def test_does_not_retry_local_serialization_errors(request_factory):
	# Arrange:
	async def operation(connector):
		return await request_factory(connector)

	mock_operation = AsyncMock(side_effect=operation)

	# Act + Assert:
	with pytest.raises(TypeError):
		await run_with_api_nodes(['http://127.0.0.1:1', 'http://127.0.0.1:2'], mock_operation)
	assert 1 == mock_operation.await_count
