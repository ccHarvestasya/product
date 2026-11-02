from symbolchain.Bip32 import Bip32
from symbolchain.facade.NemFacade import NemFacade
from symbolchain.facade.SymbolFacade import SymbolFacade


def scan_wallets(configuration, indexed_seeds, search):
	"""Scans a chunk in a CPU process and returns only candidates improving a pattern."""

	return WalletScanner(configuration, search).scan(indexed_seeds)


def snapshot_search(matcher):
	"""Keeps the least advanced active descriptor for each distinct search string."""

	patterns = {}
	for descriptor in matcher.descriptors:
		if not descriptor.has_match:
			previous = patterns.get(descriptor.search_string, descriptor.best_match_size)
			patterns[descriptor.search_string] = min(previous, descriptor.best_match_size)
	return matcher.max_offset, tuple(patterns.items())


class WalletScanner:
	"""Scans independent wallets without a shared matcher or lock."""

	def __init__(self, configuration, search):
		blockchain, network, max_accounts = configuration
		self.facade = (SymbolFacade if 'symbol' == blockchain else NemFacade)(network)
		self.max_offset, patterns = search
		self.best_sizes = dict(patterns)
		self.paths = [self.facade.bip32_path(index) for index in range(max_accounts)]
		self.bip32 = Bip32(self.facade.BIP32_CURVE_NAME)

	def scan(self, indexed_seeds):
		"""Returns wallet/account indices and private keys only for potential matches."""

		if not self.paths:
			return []
		candidates = []
		for wallet_index, seed in indexed_seeds:
			# Symbol and NEM share the first two derivation steps across wallet accounts.
			account_root = self.bip32.from_seed(seed).derive_path(self.paths[0][:2])
			for account_index, path in enumerate(self.paths):
				key_pair = self.facade.bip32_node_to_key_pair(account_root.derive_path(path[2:]))
				address = str(self.facade.network.public_key_to_address(key_pair.public_key))
				if improves_pattern(address, self.best_sizes, self.max_offset):
					candidates.append((wallet_index, account_index, key_pair.private_key.bytes))
		return candidates


def improves_pattern(address, best_sizes, max_offset):
	"""Keeps local progress thresholds, while retaining every full match for duplicate patterns."""

	accepted = False
	for pattern, best_size in best_sizes.items():
		minimum_size = min(best_size + 1, len(pattern))
		if not minimum_size:
			continue
		# Most addresses can be rejected with a single prefix check per active pattern.
		match_index = address.find(pattern[:minimum_size])
		if -1 == match_index or match_index > max_offset:
			continue
		accepted = True
		while minimum_size < len(pattern):
			match_index = address.find(pattern[:minimum_size + 1])
			if -1 == match_index or match_index > max_offset:
				break
			minimum_size += 1
		best_sizes[pattern] = minimum_size
	return accepted
