// Fixed-size BIP39: 256 bits of OS-provided entropy, eight checksum bits and 24 English words.
__constant__ unsigned int SHA256_ROUND[64] = {
	0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
	0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
	0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
	0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
	0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
	0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
	0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
	0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

__device__ unsigned int sha256_rotate(unsigned int value, int amount) {
	return (value >> amount) | (value << (32 - amount));
}

__device__ unsigned char entropy_checksum(const unsigned char entropy[32]) {
	unsigned int schedule[16] = {0};
	for (int i = 0; i < 32; ++i) schedule[i / 4] |= (unsigned int)entropy[i] << (24 - 8 * (i % 4));
	schedule[8] = 0x80000000U; schedule[15] = 256;
	unsigned int a = 0x6a09e667U, b = 0xbb67ae85U, c = 0x3c6ef372U, d = 0xa54ff53aU;
	unsigned int e = 0x510e527fU, f = 0x9b05688cU, g = 0x1f83d9abU, h = 0x5be0cd19U;
	for (int i = 0; i < 64; ++i) {
		if (i >= 16) {
			unsigned int x = schedule[(i - 15) & 15], y = schedule[(i - 2) & 15];
			schedule[i & 15] += (sha256_rotate(x, 7) ^ sha256_rotate(x, 18) ^ (x >> 3))
				+ schedule[(i - 7) & 15] + (sha256_rotate(y, 17) ^ sha256_rotate(y, 19) ^ (y >> 10));
		}
		unsigned int t1 = h + (sha256_rotate(e, 6) ^ sha256_rotate(e, 11) ^ sha256_rotate(e, 25))
			+ ((e & f) ^ (~e & g)) + SHA256_ROUND[i] + schedule[i & 15];
		unsigned int t2 = (sha256_rotate(a, 2) ^ sha256_rotate(a, 13) ^ sha256_rotate(a, 22))
			+ ((a & b) ^ (a & c) ^ (b & c));
		h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	}
	return (unsigned char)((a + 0x6a09e667U) >> 24);
}

__device__ int entropy_mnemonic(const unsigned char entropy[32], unsigned char phrase[216]) {
	unsigned char checksum = entropy_checksum(entropy);
	int length = 0;
	for (int word = 0; word < 24; ++word) {
		unsigned int index = 0;
		for (int bit = 0; bit < 11; ++bit) {
			int position = word * 11 + bit;
			unsigned char byte = position < 256 ? entropy[position / 8] : checksum;
			index = (index << 1) | ((byte >> (7 - position % 8)) & 1);
		}
		if (word) phrase[length++] = ' ';
		for (int letter = 0; BIP39_WORDS[index][letter]; ++letter) phrase[length++] = BIP39_WORDS[index][letter];
	}
	return length;
}

__device__ void mnemonic_hmac_key(const unsigned char entropy[32], unsigned char key[128]) {
	unsigned char phrase[216];
	int length = entropy_mnemonic(entropy, phrase);
	for (int i = 0; i < 128; ++i) key[i] = 0;
	if (length <= 128) {
		for (int i = 0; i < length; ++i) key[i] = phrase[i];
		return;
	}
	// English 24-word phrases have at most 215 bytes, so long passwords need exactly two SHA512 blocks.
	Word state[8], block[16] = {0};
	initialize(state);
	for (int i = 0; i < 128; ++i) block[i / 8] |= (Word)phrase[i] << (56 - 8 * (i % 8));
	compress(state, block);
	for (int i = 0; i < 16; ++i) block[i] = 0;
	for (int i = 128; i < length; ++i) block[(i - 128) / 8] |= (Word)phrase[i] << (56 - 8 * (i % 8));
	block[(length - 128) / 8] |= 0x80ULL << (56 - 8 * (length % 8));
	block[15] = (Word)length * 8;
	compress(state, block);
	for (int i = 0; i < 64; ++i) key[i] = (unsigned char)(state[i / 8] >> (56 - 8 * (i % 8)));
}

extern "C" __global__ void entropy_to_keys(const unsigned char* entropy, unsigned char* keys, unsigned int count) {
	unsigned int index = blockIdx.x * blockDim.x + threadIdx.x;
	if (index >= count) return;
	mnemonic_hmac_key(entropy + (size_t)index * 32, keys + (size_t)index * 128);
}
