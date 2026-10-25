from symbolchain import sc
from symbolchain.facade.SymbolFacade import SymbolFacade
from zenlog import log

from shoestring.internal.NodeDownloader import detect_api_endpoints
from shoestring.internal.RestApiClient import run_with_api_nodes
from shoestring.internal.ShoestringConfiguration import parse_shoestring_configuration


async def run_main(args):
	config = parse_shoestring_configuration(args.config)

	with open(args.transaction, 'rb') as infile:
		transaction_bytes = infile.read()
		transaction = sc.TransactionFactory.deserialize(transaction_bytes)

	transaction_type = transaction.type_
	transaction_hash = SymbolFacade(config.network).hash_transaction(transaction)
	log.info(_('announce-transaction-preparing-to-announce').format(transaction_hash=transaction_hash, transaction_type=transaction_type))

	async def announce(connector):
		if sc.TransactionType.AGGREGATE_BONDED == transaction_type:
			await connector.announce_partial_transaction(transaction)
		else:
			await connector.announce_transaction(transaction)

	api_endpoints = await detect_api_endpoints(config.services.nodewatch, 10)
	# Reuse the same signed transaction on every attempt so its payload and hash stay unchanged.
	await run_with_api_nodes(api_endpoints, announce)
	log.info(_('announce-transaction-announce-successful'))


def add_arguments(parser):
	parser.add_argument('--config', help=_('argument-help-config'), required=True)
	parser.add_argument('--transaction', help=_('argument-help-announce-transaction-transaction'), required=True)
	parser.set_defaults(func=run_main)
