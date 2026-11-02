__device__ void hmac_sha512_short(const unsigned char* key, int key_length, const unsigned char* message,
		int length, unsigned char output[64]) {
	Word inner[8], outer[8], block[16] = {0};
	initialize(inner); initialize(outer);
	for (int i = 0; i < key_length; ++i) block[i / 8] |= (Word)key[i] << (56 - 8 * (i % 8));
	for (int i = 0; i < 16; ++i) block[i] ^= 0x3636363636363636ULL;
	compress(inner, block);
	for (int i = 0; i < 16; ++i) block[i] ^= 0x3636363636363636ULL ^ 0x5c5c5c5c5c5c5c5cULL;
	compress(outer, block);
	for (int i = 0; i < 16; ++i) block[i] = 0;
	for (int i = 0; i < length; ++i) block[i / 8] |= (Word)message[i] << (56 - 8 * (i % 8));
	block[length / 8] |= 0x80ULL << (56 - 8 * (length % 8));
	block[15] = (128 + length) * 8;
	compress(inner, block);
	Word result[8];
	hash_digest(outer, inner, result);
	for (int i = 0; i < 64; ++i) output[i] = (unsigned char)(result[i / 8] >> (56 - 8 * (i % 8)));
}

__device__ void derive_child(const unsigned char node[64], unsigned int index, unsigned char child[64]) {
	unsigned char data[37] = {0};
	for (int i = 0; i < 32; ++i) data[i + 1] = node[i];
	index |= 0x80000000U;
	for (int i = 0; i < 4; ++i) data[33 + i] = (unsigned char)(index >> (24 - 8 * i));
	hmac_sha512_short(node + 32, 32, data, 37, child);
}

extern "C" __global__ void derive_accounts(const unsigned char* seeds, unsigned char* private_keys,
		unsigned int wallet_count, unsigned int accounts, unsigned int coin, int nem) {
	unsigned int wallet = blockIdx.x * blockDim.x + threadIdx.x;
	if (wallet >= wallet_count) return;
	unsigned char root[64], purpose[64], common[64], account[64], branch[64], leaf[64];
	const char* label = nem ? "ed25519-keccak seed" : "ed25519 seed";
	hmac_sha512_short((const unsigned char*)label, nem ? 19 : 12, seeds + (size_t)wallet * 64, 64, root);
	derive_child(root, 44, purpose);
	derive_child(purpose, coin, common);
	for (unsigned int i = 0; i < accounts; ++i) {
		derive_child(common, i, account); derive_child(account, 0, branch); derive_child(branch, 0, leaf);
		for (int j = 0; j < 32; ++j) private_keys[((size_t)wallet * accounts + i) * 32 + j] = leaf[j];
	}
}

extern "C" __global__ void scan_accounts(const unsigned char* private_keys, unsigned char* public_keys,
		unsigned char* addresses, unsigned long long* best, const unsigned char* patterns,
		const unsigned int* lengths, const unsigned int* minimums, unsigned int pattern_count,
		unsigned int account_count, int max_offset, int network, int nem) {
	unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
	if (index >= account_count) return;
	unsigned char public_key[32], address[40];
	public_key_from_private(private_keys + (size_t)index * 32, nem, public_key);
	address_from_public(public_key, nem, network, address);
	for (int i = 0; i < 32; ++i) public_keys[(size_t)index * 32 + i] = public_key[i];
	for (int i = 0; i < 40; ++i) addresses[(size_t)index * 40 + i] = address[i];
	int address_size = nem ? 40 : 39;
	for (unsigned int pattern = 0; pattern < pattern_count; ++pattern) {
		unsigned int matched = 0;
		for (int offset = 0; offset <= max_offset && offset < address_size; ++offset) {
			unsigned int size = 0;
			while (size < lengths[pattern] && offset + size < (unsigned int)address_size
					&& address[offset + size] == patterns[pattern * 40 + size]) ++size;
			if (size > matched) matched = size;
		}
		if (matched >= minimums[pattern] && matched > 0) {
			// Maximum progress first. XOR tie-breaking lets duplicate descriptors select different accounts.
			Word score = ((Word)matched << 32) | (0xffffffffU - (index ^ pattern));
			atomicMax(best + pattern, score);
		}
	}
}
