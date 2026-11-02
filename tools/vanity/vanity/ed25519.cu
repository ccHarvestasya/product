// Field arithmetic adapted from public-domain TweetNaCl (Bernstein et al.).
// https://tweetnacl.cr.yp.to/ ; see CUDA_NOTICES.md.
// Fixed-base signed radix-16 multiplication uses the reproducible ED_BASE table.
typedef long long Field[16];

__device__ void field_copy(Field out, const Field value) {
	for (int i = 0; i < 16; ++i) out[i] = value[i];
}

__device__ void field_carry(Field value) {
	for (int i = 0; i < 16; ++i) {
		value[i] += 65536;
		long long carry = value[i] >> 16;
		value[(i + 1) * (i < 15)] += carry - 1 + 37 * (carry - 1) * (i == 15);
		value[i] -= carry * 65536;
	}
}

__device__ void field_select(Field left, Field right, int select) {
	long long mask = -(long long)select;
	for (int i = 0; i < 16; ++i) {
		long long difference = mask & (left[i] ^ right[i]);
		left[i] ^= difference;
		right[i] ^= difference;
	}
}

__device__ void field_pack(unsigned char out[32], const Field value) {
	Field reduced, temporary;
	field_copy(reduced, value);
	field_carry(reduced); field_carry(reduced); field_carry(reduced);
	for (int round = 0; round < 2; ++round) {
		temporary[0] = reduced[0] - 0xffed;
		for (int i = 1; i < 15; ++i) {
			temporary[i] = reduced[i] - 0xffff - ((temporary[i - 1] >> 16) & 1);
			temporary[i - 1] &= 0xffff;
		}
		temporary[15] = reduced[15] - 0x7fff - ((temporary[14] >> 16) & 1);
		int borrow = (int)((temporary[15] >> 16) & 1);
		temporary[14] &= 0xffff;
		field_select(reduced, temporary, 1 - borrow);
	}
	for (int i = 0; i < 16; ++i) {
		out[2 * i] = (unsigned char)reduced[i];
		out[2 * i + 1] = (unsigned char)(reduced[i] >> 8);
	}
}

__device__ void field_add(Field out, const Field left, const Field right) {
	for (int i = 0; i < 16; ++i) out[i] = left[i] + right[i];
}

__device__ void field_subtract(Field out, const Field left, const Field right) {
	for (int i = 0; i < 16; ++i) out[i] = left[i] - right[i];
}

__device__ void field_multiply(Field out, const Field left, const Field right) {
	long long product[31] = {0};
	#pragma unroll
	for (int i = 0; i < 16; ++i)
		#pragma unroll
		for (int j = 0; j < 16; ++j)
			// Carried limbs and sums/differences fit in signed 32 bits: use a wide 32-bit multiply.
			product[i + j] += (long long)(int)left[i] * (int)right[j];
	for (int i = 0; i < 15; ++i) product[i] += 38 * product[i + 16];
	for (int i = 0; i < 16; ++i) out[i] = product[i];
	field_carry(out); field_carry(out);
}

__device__ void field_square_times(Field out, const Field value, int count) {
	field_copy(out, value);
	for (int i = 0; i < count; ++i) field_multiply(out, out, out);
}

__device__ void field_inverse(Field out, const Field value) {
	// Addition chain for p - 2 = 2**255 - 21: 254 squares and 11 multiplies.
	Field z2, z9, z11, power, t10, t50;
	field_multiply(z2, value, value);
	field_square_times(z9, z2, 2);
	field_multiply(z9, z9, value);
	field_multiply(z11, z9, z2);
	field_multiply(power, z11, z11);
	field_multiply(power, power, z9); // 2**5 - 1
	field_square_times(t10, power, 5);
	field_multiply(t10, t10, power);
	field_square_times(power, t10, 10);
	field_multiply(power, power, t10); // 2**20 - 1
	field_square_times(t50, power, 20);
	field_multiply(power, t50, power); // 2**40 - 1
	field_square_times(t50, power, 10);
	field_multiply(t50, t50, t10);
	field_square_times(power, t50, 50);
	field_multiply(power, power, t50); // 2**100 - 1
	field_square_times(t10, power, 100);
	field_multiply(power, t10, power); // 2**200 - 1
	field_square_times(power, power, 50);
	field_multiply(power, power, t50); // 2**250 - 1
	field_square_times(out, power, 5);
	field_multiply(out, out, z11);
}

__device__ void point_mixed_add(Field point[4], const Field cached[3]) {
	Field a, b, c, d, e, f, g, h;
	field_subtract(a, point[1], point[0]);
	field_multiply(a, a, cached[1]);
	field_add(b, point[1], point[0]);
	field_multiply(b, b, cached[0]);
	field_multiply(c, point[3], cached[2]);
	field_add(d, point[2], point[2]);
	field_subtract(e, b, a); field_subtract(f, d, c);
	field_add(g, d, c); field_add(h, b, a);
	field_multiply(point[0], e, f); field_multiply(point[1], g, h);
	field_multiply(point[2], f, g); field_multiply(point[3], e, h);
}

__device__ void point_double(Field point[4]) {
	Field a, b, c, d, e, f, g, h;
	field_multiply(a, point[0], point[0]);
	field_multiply(b, point[1], point[1]);
	field_multiply(c, point[2], point[2]); field_add(c, c, c);
	for (int i = 0; i < 16; ++i) d[i] = -a[i];
	field_add(e, point[0], point[1]); field_multiply(e, e, e);
	field_subtract(e, e, a); field_subtract(e, e, b);
	field_add(g, d, b); field_subtract(f, g, c); field_subtract(h, d, b);
	field_multiply(point[0], e, f); field_multiply(point[1], g, h);
	field_multiply(point[2], f, g); field_multiply(point[3], e, h);
}

__device__ void base_point_select(Field cached[3], int position, int digit) {
	int negative = digit < 0;
	int absolute = negative ? -digit : digit;
	for (int coordinate = 0; coordinate < 3; ++coordinate)
		for (int limb = 0; limb < 16; ++limb)
			cached[coordinate][limb] = (coordinate < 2 && limb == 0) ? 1 : 0;
	// Read all eight public entries, rather than indexing the table by secret digits.
	for (int entry = 1; entry <= 8; ++entry) {
		long long mask = -(long long)(absolute == entry);
		for (int coordinate = 0; coordinate < 3; ++coordinate)
			for (int limb = 0; limb < 16; ++limb)
				cached[coordinate][limb] ^= mask & (cached[coordinate][limb] ^ ED_BASE[position][entry - 1][coordinate][limb]);
	}
	field_select(cached[0], cached[1], negative);
	long long sign = 1 - 2 * negative;
	for (int limb = 0; limb < 16; ++limb) cached[2][limb] *= sign;
}

__device__ void ed25519_base(unsigned char public_key[32], const unsigned char scalar[32]) {
	int digits[64];
	for (int i = 0; i < 32; ++i) {
		digits[2 * i] = scalar[i] & 15;
		digits[2 * i + 1] = scalar[i] >> 4;
	}
	int carry = 0;
	for (int i = 0; i < 63; ++i) {
		digits[i] += carry;
		carry = (digits[i] + 8) >> 4;
		digits[i] -= carry * 16;
	}
	digits[63] += carry;
	Field point[4] = {{0}, {1}, {1}, {0}}, cached[3];
	for (int i = 1; i < 64; i += 2) {
		base_point_select(cached, i / 2, digits[i]);
		point_mixed_add(point, cached);
	}
	for (int i = 0; i < 4; ++i) point_double(point);
	for (int i = 0; i < 64; i += 2) {
		base_point_select(cached, i / 2, digits[i]);
		point_mixed_add(point, cached);
	}
	Field inverse, x, y;
	field_inverse(inverse, point[2]);
	field_multiply(x, point[0], inverse);
	field_multiply(y, point[1], inverse);
	unsigned char encoded_x[32];
	field_pack(encoded_x, x); field_pack(public_key, y);
	public_key[31] ^= (encoded_x[0] & 1) << 7;
}
