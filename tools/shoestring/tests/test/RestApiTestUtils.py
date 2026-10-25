from aiohttp import web


async def setup_rest_failover(server, aiohttp_client, monkeypatch):
	"""Makes discovery return a failing REST node followed by the healthy mock node."""

	requests = []

	async def fail(request):
		requests.append({'path': request.path, 'payload': await request.json() if request.can_read_body else None})
		if '/node/info' == request.path:
			return web.json_response({'port': 7900})
		if request.path.startswith('/accounts/'):
			return web.json_response({'code': 'ResourceNotFound'}, status=404)
		return web.json_response({'message': 'temporarily unavailable'}, status=503)

	app = web.Application()
	app.router.add_route('*', '/{path:.*}', fail)
	failing_client = await aiohttp_client(app)
	server.mock.endpoint = failing_client.make_url('')
	server.mock.additional_endpoints = [server.make_url('')]
	monkeypatch.setattr('shoestring.internal.NodeDownloader.random.shuffle', lambda _: None)
	return requests
