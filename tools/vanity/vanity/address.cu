// Single-block hashes for fixed-size Symbol/NEM public keys and addresses.
__constant__ Word KECCAK_ROUND[24] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
	0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
	0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
	0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
	0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};
__constant__ int KECCAK_ROTATE[25] = {
	0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
};

__device__ Word rotate_left64(Word value, int count) {
	return count ? (value << count) | (value >> (64 - count)) : value;
}

__device__ void keccak_short(const unsigned char* input, int length, unsigned char* output, int output_size, int domain) {
	Word state[25] = {0}, columns[5], rotated[25];
	int rate = 200 - 2 * output_size;
	for (int i = 0; i < length; ++i) state[i / 8] ^= (Word)input[i] << (8 * (i % 8));
	state[length / 8] ^= (Word)domain << (8 * (length % 8));
	state[rate / 8 - 1] ^= 0x8000000000000000ULL;
	for (int round = 0; round < 24; ++round) {
		for (int x = 0; x < 5; ++x)
			columns[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
		for (int x = 0; x < 5; ++x) {
			Word delta = columns[(x + 4) % 5] ^ rotate_left64(columns[(x + 1) % 5], 1);
			for (int y = 0; y < 5; ++y) state[x + 5 * y] ^= delta;
		}
		for (int x = 0; x < 5; ++x)
			for (int y = 0; y < 5; ++y)
				rotated[y + 5 * ((2 * x + 3 * y) % 5)] = rotate_left64(state[x + 5 * y], KECCAK_ROTATE[x + 5 * y]);
		for (int x = 0; x < 5; ++x)
			for (int y = 0; y < 5; ++y)
				state[x + 5 * y] = rotated[x + 5 * y] ^ (~rotated[(x + 1) % 5 + 5 * y] & rotated[(x + 2) % 5 + 5 * y]);
		state[0] ^= KECCAK_ROUND[round];
	}
	for (int i = 0; i < output_size; ++i) output[i] = (unsigned char)(state[i / 8] >> (8 * (i % 8)));
}

__device__ void sha512_short(const unsigned char* input, int length, unsigned char output[64]) {
	Word state[8], block[16] = {0};
	initialize(state);
	for (int i = 0; i < length; ++i) block[i / 8] |= (Word)input[i] << (56 - 8 * (i % 8));
	block[length / 8] |= 0x80ULL << (56 - 8 * (length % 8));
	block[15] = (Word)length * 8;
	compress(state, block);
	for (int i = 0; i < 64; ++i) output[i] = (unsigned char)(state[i / 8] >> (56 - 8 * (i % 8)));
}

__device__ unsigned int rotate_left32(unsigned int value, int count) {
	return (value << count) | (value >> (32 - count));
}

__constant__ unsigned char RIPEMD_ORDER[2][80] = {
	{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
	 3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12, 1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
	 4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13},
	{5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12, 6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
	 15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13, 8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
	 12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11}
};
__constant__ unsigned char RIPEMD_ROTATE[2][80] = {
	{11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8, 7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
	 11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5, 11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
	 9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6},
	{8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6, 9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
	 9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5, 15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
	 8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11}
};
__constant__ unsigned int RIPEMD_K[2][5] = {
	{0, 0x5a827999U, 0x6ed9eba1U, 0x8f1bbcdcU, 0xa953fd4eU},
	{0x50a28be6U, 0x5c4dd124U, 0x6d703ef3U, 0x7a6d76e9U, 0}
};

__device__ unsigned int ripemd_function(int round, unsigned int x, unsigned int y, unsigned int z) {
	if (round == 0) return x ^ y ^ z;
	if (round == 1) return (x & y) | (~x & z);
	if (round == 2) return (x | ~y) ^ z;
	if (round == 3) return (x & z) | (y & ~z);
	return x ^ (y | ~z);
}

__device__ void ripemd160_32(const unsigned char input[32], unsigned char output[20]) {
	unsigned int block[16] = {0};
	for (int i = 0; i < 32; ++i) block[i / 4] |= (unsigned int)input[i] << (8 * (i % 4));
	block[8] = 0x80; block[14] = 256;
	unsigned int initial[5] = {0x67452301U, 0xefcdab89U, 0x98badcfeU, 0x10325476U, 0xc3d2e1f0U};
	unsigned int lanes[2][5];
	for (int lane = 0; lane < 2; ++lane)
		for (int i = 0; i < 5; ++i) lanes[lane][i] = initial[i];
	for (int step = 0; step < 80; ++step) {
		for (int lane = 0; lane < 2; ++lane) {
			unsigned int* p = lanes[lane];
			unsigned int value = p[0] + ripemd_function(lane ? 4 - step / 16 : step / 16, p[1], p[2], p[3]);
			value += block[RIPEMD_ORDER[lane][step]] + RIPEMD_K[lane][step / 16];
			value = rotate_left32(value, RIPEMD_ROTATE[lane][step]) + p[4];
			p[0] = p[4]; p[4] = p[3]; p[3] = rotate_left32(p[2], 10); p[2] = p[1]; p[1] = value;
		}
	}
	unsigned int result[5] = {
		initial[1] + lanes[0][2] + lanes[1][3], initial[2] + lanes[0][3] + lanes[1][4],
		initial[3] + lanes[0][4] + lanes[1][0], initial[4] + lanes[0][0] + lanes[1][1],
		initial[0] + lanes[0][1] + lanes[1][2]
	};
	for (int i = 0; i < 20; ++i) output[i] = (unsigned char)(result[i / 4] >> (8 * (i % 4)));
}

__device__ void public_key_from_private(const unsigned char private_key[32], int nem, unsigned char public_key[32]) {
	unsigned char hash[64];
	// Input is the unreversed BIP32 private key for both chains.
	if (nem) keccak_short(private_key, 32, hash, 64, 1);
	else sha512_short(private_key, 32, hash);
	hash[0] &= 248; hash[31] &= 127; hash[31] |= 64;
	ed25519_base(public_key, hash);
}

__device__ void address_from_public(const unsigned char public_key[32], int nem, int network, unsigned char encoded[40]) {
	unsigned char hash[32], decoded[25] = {0};
	keccak_short(public_key, 32, hash, 32, nem ? 1 : 6);
	decoded[0] = (unsigned char)network;
	ripemd160_32(hash, decoded + 1);
	keccak_short(decoded, 21, hash, 32, nem ? 1 : 6);
	for (int i = 0; i < (nem ? 4 : 3); ++i) decoded[21 + i] = hash[i];
	const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	int length = nem ? 40 : 39;
	for (int i = 0; i < length; ++i) {
		int value = 0;
		for (int bit = 0; bit < 5; ++bit) {
			int position = i * 5 + bit;
			value = (value << 1) | ((decoded[position / 8] >> (7 - position % 8)) & 1);
		}
		encoded[i] = (unsigned char)alphabet[value];
	}
	if (!nem) encoded[39] = 0;
}
