/*
 * Copyright (c) 2011 Wouter Coene <wouter@irdc.nl>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Number of rounds
 */
#undef THREEFISH_ROUNDS
#if SKEIN_BITS == 256 || SKEIN_BITS == 512
# define THREEFISH_ROUNDS	72
#elif SKEIN_BITS == 1024
# define THREEFISH_ROUNDS	80
#else
# error "Bad block size"
#endif

/*
 * Schedule constants
 */
static const uint8_t
THREEFISH(schedule)[] = {
#if SKEIN_BITS == 256
	 0,  1,  2,  3,
	 0,  3,  2,  1,
	 0,  1,  2,  3,
	 0,  3,  2,  1
#elif SKEIN_BITS == 512
	 0,  1,  2,  3,  4,  5,  6,  7,
	 2,  1,  4,  7,  6,  5,  0,  3,
	 4,  1,  6,  3,  0,  5,  2,  7,
	 6,  1,  0,  7,  2,  5,  4,  3
#elif SKEIN_BITS == 1024
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
	 0,  9,  2, 13,  6, 11,  4, 15, 10,  7, 12,  3, 14,  5,  8,  1,
	 0,  7,  2,  5,  4,  3,  6,  1, 12, 15, 14, 13,  8, 11, 10,  9,
	 0, 15,  2, 11,  6, 13,  4,  9, 14,  1,  8,  5, 10,  3, 12,  7
#else
# error "Bad block size"
#endif
};

/*
 * Rotation constants
 */
static const uint8_t
THREEFISH(rotate)[] = {
#if SKEIN_BITS == 256
	14, 16, 52, 57, 23, 40,  5, 37, 25, 33, 46, 12, 58, 22, 32, 32
#elif SKEIN_BITS == 512
	46, 36, 19, 37, 33, 27, 14, 42, 17, 49, 36, 39, 44,  9, 54, 56,
	39, 30, 34, 24, 13, 50, 10, 17, 25, 29, 39, 43,  8, 35, 56, 22
#elif SKEIN_BITS == 1024
	24, 13,  8, 47,  8, 17, 22, 37, 38, 19, 10, 55, 49, 18, 23, 52,
	33,  4, 51, 13, 34, 41, 59, 17,  5, 20, 48, 41, 47, 28, 16, 25,
	41,  9, 37, 31, 12, 47, 44, 30, 16, 34, 56, 51,  4, 53, 42, 41,
	31, 44, 47, 46, 19, 42, 44, 25,  9, 48, 35, 52, 23, 31, 37, 20
#else
# error "Bad block size"
#endif
};

/*
 * Encrypt a block
 */
void
THREEFISH(encrypt)(struct threefish *ctx, uint64_t *block)
{
	uint64_t	 key[SKEIN_WORDS + 1],
			 tweak[nitems(ctx->tweak) + 1],
			 x[SKEIN_WORDS];
	unsigned int	 i, r, s, a, b;

	/* determine key parity */
	memcpy(key, ctx->key, sizeof(ctx->key));
	key[nitems(key) - 1] = THREEFISH_KEY_PARITY;
	for (i = 0; i < nitems(key) - 1; i++)
		key[nitems(key) - 1] ^= key[i];

	/* determine tweak parity */
	memcpy(tweak, ctx->tweak, sizeof(ctx->tweak));
	tweak[2] = tweak[0] ^ tweak[1];

	/* perform first key injection */
	for (i = 0; i < nitems(x); i++)
		x[i] = key[i] + block[i];
	x[nitems(x) - 3] += tweak[0];
	x[nitems(x) - 2] += tweak[1];

	/* perform all rounds */
	for (r = 1, s = 0;
	     r <= THREEFISH_ROUNDS / 4;
	     r++, s ^= nitems(THREEFISH(rotate)) / 2) {
		/* perform rotations */
		for (i = 0; i < nitems(THREEFISH(schedule)) / 2; i++) {
			a = THREEFISH(schedule)[i * 2];
			b = THREEFISH(schedule)[i * 2 + 1];

			x[a] += x[b];
			x[b] = rotl64(x[b], THREEFISH(rotate)[i + s]);
			x[b] ^= x[a];
		}

		/* inject the key */
		for (i = 0; i < nitems(x); i++)
			x[i] += key[(r + i) % nitems(key)];
		x[nitems(x) - 3] += tweak[r % nitems(tweak)];
		x[nitems(x) - 2] += tweak[(r + 1) % nitems(tweak)];
		x[nitems(x) - 1] += r;
	}

	/* update context */
	for (i = 0; i < nitems(ctx->key); i++)
		ctx->key[i] = x[i] ^ block[i];

	memcpy(block, x, sizeof(x));
}

/*
 * Decrypt a block
 */
void
THREEFISH(decrypt)(struct threefish *ctx, uint64_t *block)
{
	uint64_t	 key[SKEIN_WORDS + 1],
			 tweak[nitems(ctx->tweak) + 1],
			 x[SKEIN_WORDS];
	unsigned int	 i, r, s, a, b;

	memcpy(x, block, sizeof(x));

	/* determine key parity */
	memcpy(key, ctx->key, sizeof(ctx->key));
	key[nitems(key) - 1] = THREEFISH_KEY_PARITY;
	for (i = 0; i < nitems(key) - 1; i++)
		key[nitems(key) - 1] ^= key[i];

	/* determine tweak parity */
	memcpy(tweak, ctx->tweak, sizeof(ctx->tweak));
	tweak[2] = tweak[0] ^ tweak[1];

	/* perform all rounds */
	for (r = THREEFISH_ROUNDS / 4, s = nitems(THREEFISH(rotate)) / 2;
	     r > 0;
	     r--, s ^= nitems(THREEFISH(rotate)) / 2) {
		/* remove the key */
		for (i = 0; i < nitems(x); i++)
			x[i] -= key[(r + i) % nitems(key)];
		x[nitems(x) - 3] -= tweak[r % nitems(tweak)];
		x[nitems(x) - 2] -= tweak[(r + 1) % nitems(tweak)];
		x[nitems(x) - 1] -= r;

		/* perform rotations */
		for (i = nitems(THREEFISH(schedule)) / 2; i > 0; i--) {
			a = THREEFISH(schedule)[(i - 1) * 2];
			b = THREEFISH(schedule)[(i - 1) * 2 + 1];

			x[b] = rotr64(x[a] ^ x[b], THREEFISH(rotate)[(i - 1) + s]);
			x[a] -= x[b];
		}
	}

	/* undo first key injection */
	for (i = 0; i < nitems(x); i++)
		x[i] -= key[i];
	x[nitems(x) - 3] -= tweak[0];
	x[nitems(x) - 2] -= tweak[1];

	/* update context */
	for (i = 0; i < nitems(ctx->key); i++)
		ctx->key[i] = x[i] ^ block[i];

	memcpy(block, x, sizeof(x));
}
