import asyncio

from aiohttp import ClientError, ClientSession, ClientTimeout, ContentTypeError
from symbollightapi.connector.SymbolConnector import SymbolConnector
from symbollightapi.model.Exceptions import CorruptDataException, HttpException, InsufficientBalanceException, NodeException
from zenlog import log


class _RestApiConnector(SymbolConnector):
	"""Normalizes failures while receiving and decoding REST responses."""

	async def _dispatch(self, action, url_path, property_name, not_found_as_error, **kwargs):
		# Request serialization happens outside the response parsing error handlers.
		async with ClientSession(timeout=ClientTimeout(total=self.timeout_seconds)) as session:
			async with getattr(session, action)(f'{self.endpoint}/{url_path}', **kwargs) as response:
				is_http_error = response.status >= 400 and (404 != response.status or not_found_as_error)
				try:
					response_json = await response.json()
				except (ContentTypeError, ValueError) as ex:
					if is_http_error:
						raise HttpException(f'HTTP request failed with code {response.status}', response.status) from ex
					raise CorruptDataException('invalid JSON response') from ex

				if is_http_error:
					# Error bodies are not guaranteed to be objects; preserve the HTTP status even for null or arrays.
					message = f'HTTP request failed with code {response.status}'
					if isinstance(response_json, dict):
						for key in ('code', 'message'):
							if key in response_json:
								message += f'\n{response_json[key]}'
					raise HttpException(message, response.status)

				try:
					return response_json if property_name is None else response_json[property_name]
				except (KeyError, TypeError) as ex:
					raise CorruptDataException(f'invalid REST response: {ex}') from ex

	@staticmethod
	async def _read(operation, *args):
		try:
			return await operation(*args)
		except (KeyError, TypeError, ValueError, AttributeError) as ex:
			# Keep response decoding errors separate from errors in the caller's operation.
			raise CorruptDataException(f'invalid REST response: {ex}') from ex

	async def network_time(self):
		"""Reads network time with retryable response validation."""

		return await self._read(super().network_time)

	async def account_links(self, account_id):
		"""Reads account links with retryable response validation."""

		return await self._read(super().account_links, account_id)

	async def account_multisig(self, address):
		"""Reads multisig information with retryable response validation."""

		return await self._read(super().account_multisig, address)


async def run_with_api_nodes(api_endpoints, operation):
	"""Runs a REST operation, trying each distinct node once on communication failures."""

	last_error = None
	for endpoint in dict.fromkeys(api_endpoints):
		log.info(_('general-connecting-to-node').format(endpoint=endpoint))
		connector = _RestApiConnector(endpoint)
		connector.timeout_seconds = 10
		try:
			return await operation(connector)
		except HttpException as http_error:
			if http_error.http_status_code < 500 and http_error.http_status_code not in (401, 403, 404, 408, 429):
				raise
			last_error = http_error
		except InsufficientBalanceException:
			raise
		except (NodeException, ClientError, asyncio.TimeoutError) as ex:
			last_error = ex
		log.warning(f'REST operation failed at {endpoint}: {last_error}')

	if last_error is None:
		raise RuntimeError('no REST API nodes are available')
	raise RuntimeError('REST operation failed on all available API nodes') from last_error
