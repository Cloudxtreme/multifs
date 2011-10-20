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

#include "skein.h"
#include "bytesex.h"
#include <string.h>

#define nitems(arr)		(sizeof(arr) / sizeof((arr)[0]))
#define min(a, b)		((a) < (b)? (a) : (b))
#define CC_(a, b)		a ## b
#define CC(a, b)		CC_(a, b)

/*
 * Skein version
 */
#define SKEIN_VERSION		1
#define SKEIN_ID		0x33414853

/*
 * Block types
 */
#define SKEIN_BLOCK_CFG		((uint64_t)  4 << 56)
#define SKEIN_BLOCK_MSG		((uint64_t) 48 << 56)
#define SKEIN_BLOCK_OUT		((uint64_t) 63 << 56)

/*
 * Block flags
 */
#define SKEIN_FLAG_FIRST	((uint64_t) 1 << 62)
#define SKEIN_FLAG_LAST		((uint64_t) 1 << 63)

/*
 * Key schedule parity
 */
#define THREEFISH_KEY_PARITY	0x1bd11bdaa9fc1a22ULL

/*
 * Symbol names
 */
#define threefish		CC(threefish, SKEIN_BITS)
#define skein			CC(skein, SKEIN_BITS)
#define THREEFISH(n)		CC(CC(threefish, _), n)
#define SKEIN(n)		CC(CC(skein, _), n)

/*
 * Number of bytes and words per block
 */
#define SKEIN_BYTES		(SKEIN_BITS / 8)
#define SKEIN_WORDS		(SKEIN_BITS / (8 * sizeof(uint64_t)))

/*
 * Left rotation
 */
static inline uint64_t
rotl64(uint64_t val, int dist)
{
	dist &= 63;
	return (val << dist) | (val >> (64 - dist));
}

/*
 * Right rotation
 */
static inline uint64_t
rotr64(uint64_t val, int dist)
{
	dist &= 63;
	return (val >> dist) | (val << (64 - dist));
}

/*
 * Copy out hash bytes
 */
static void
copyout(uint8_t *dest, const uint64_t *src, size_t len)
{
	uint8_t	 buf[sizeof(uint64_t)];
	size_t	 l;

	while (len > 0) {
		/* perform endian conversion */
		le64put(buf, *src);

		/* copy as much bytes as will fit */
		l = min(len, sizeof(uint64_t));
		memcpy(dest, buf, l);

		dest += l;
		src++;
		len -= l;
	}
}

/*
 * Expand implementations
 */
#define SKEIN_BITS		256
#include "threefish.c"
#include "skein_impl.c"

#undef SKEIN_BITS
#define SKEIN_BITS		512
#include "threefish.c"
#include "skein_impl.c"

#undef SKEIN_BITS
#define SKEIN_BITS		1024
#include "threefish.c"
#include "skein_impl.c"
