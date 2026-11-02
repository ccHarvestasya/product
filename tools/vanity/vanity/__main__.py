import argparse
import sys

from symbolchain.facade.NemFacade import NemFacade
from symbolchain.facade.SymbolFacade import SymbolFacade

from .AccountPrinter import AccountPrinter
from .AddressGenerator import AddressGenerator
from .MultiAddressMatcher import MultiAddressMatcher

MAX_WALLET_ACCOUNTS = 10


def nonnegative_int(value):
	"""Parses a nonnegative integer argument."""

	parsed = int(value)
	if parsed < 0:
		raise argparse.ArgumentTypeError('must be nonnegative')
	return parsed


def positive_int(value):
	"""Parses a positive integer argument."""

	parsed = nonnegative_int(value)
	if not parsed:
		raise argparse.ArgumentTypeError('must be positive')
	return parsed


def create_printer(args, network):
	format_mode = AccountPrinter.FormatMode.CSV if 'csv' == args.format else AccountPrinter.FormatMode.PRETTY
	printer = AccountPrinter(network, format_mode)
	if args.out:
		printer.outfiles.append(open(args.out, 'wt', encoding='utf8'))  # pylint: disable=consider-using-with

	if not args.suppress_console:
		printer.outfiles.append(sys.stdout)

	return printer


def create_backend(args):
	"""Initializes the selected GPU backend before opening account output files."""

	if 'cpu' == args.backend:
		return None
	print(f'initializing {args.backend} device {args.gpu_device} (compiling kernels and running self-tests)...', file=sys.stderr, flush=True)
	if 'cuda' == args.backend:
		from .CudaSearchBackend import CudaSearchBackend  # pylint: disable=import-outside-toplevel

		return CudaSearchBackend(args.gpu_device)
	from .CudaSeedGenerator import CudaSeedGenerator  # pylint: disable=import-outside-toplevel

	return CudaSeedGenerator(args.gpu_device)


def create_generator(args, facade, printer, backend):
	"""Creates a generator and applies options for the selected backend."""

	if backend is None:
		return AddressGenerator(facade, MAX_WALLET_ACCOUNTS, printer.write_account)
	if 'cuda' == args.backend:
		from .CudaSearchGenerator import CudaSearchGenerator  # pylint: disable=import-outside-toplevel

		generator_class = CudaSearchGenerator
	else:
		from .CudaAddressGenerator import CudaAddressGenerator  # pylint: disable=import-outside-toplevel

		generator_class = CudaAddressGenerator
	generator = generator_class(facade, MAX_WALLET_ACCOUNTS, printer.write_account, backend)
	if args.batch_size is not None:
		generator.batch_size = args.batch_size
	if args.workers is not None:
		generator.workers = args.workers
	if args.stats:
		generator.stats_monitor = lambda message: print(message, file=sys.stderr, flush=True)
	return generator


def main(args):
	parser = argparse.ArgumentParser(
		prog=None if globals().get('__spec__') is None else f'python -m {__spec__.name.partition(".")[0]}',
		description='Symbol Vanity Address Generator'
	)
	parser.add_argument('--blockchain', help='blockchain to target', choices=('symbol', 'nem'), default='symbol')
	parser.add_argument('--network', help='network to target', choices=('testnet', 'mainnet'), default='mainnet')
	parser.add_argument('--patterns', help='patterns to match (comma delimited)', required=True)
	parser.add_argument('--max-offset', help='maximum offset of match start', default=2, type=int)
	parser.add_argument('--format', help='output format', choices=('pretty', 'csv'), default='pretty')
	parser.add_argument('--suppress-console', help='suppress printing matches to console', action='store_true')
	parser.add_argument('--out', help='output file')
	parser.add_argument('--backend', help='address search backend', choices=('cpu', 'cuda', 'cuda-hybrid'), default='cpu')
	parser.add_argument('--gpu-device', help='CUDA device index', type=nonnegative_int, default=0)
	parser.add_argument('--batch-size', help='wallets per batch (default: cuda 16384, cuda-hybrid 1024)', type=positive_int)
	parser.add_argument('--workers', help='CPU scanning processes for cuda-hybrid (default: CPU count)', type=positive_int)
	parser.add_argument('--stats', help='report CUDA batch timings to stderr', action='store_true')
	args = parser.parse_args(args)
	if args.workers is not None and 'cuda-hybrid' != args.backend:
		parser.error('--workers requires --backend cuda-hybrid; --backend cuda performs address scanning on the GPU')
	if 'cpu' == args.backend and args.stats:
		parser.error('--stats requires --backend cuda or cuda-hybrid')

	facade = (SymbolFacade if 'symbol' == args.blockchain else NemFacade)(args.network)

	try:
		backend = create_backend(args)
	except RuntimeError as ex:
		parser.error(str(ex))

	printer = create_printer(args, facade.network)
	try:
		printer.write_header()

		generator = create_generator(args, facade, printer, backend)

		matcher = MultiAddressMatcher(facade.network, args.max_offset, print)
		for pattern in args.patterns.split(','):
			matcher.add_search_pattern(pattern)

		print('generating accounts (this will take a while)...')
		generator.match_all(matcher)
	finally:
		for outfile in printer.outfiles:
			if '<stdout>' != outfile.name:
				outfile.close()


if '__main__' == __name__:
	main(sys.argv[1:])
