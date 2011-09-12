#include "multifs.h"

#include <string.h>

/*
 * This is basically MurmurHash3 wrung through my own code readability
 * filter -- any bugs thus created are mine and mine alone
 */

static inline uint64_t
rotl64(uint64_t val, int dist)
{
	dist &= 63;
	return (val << dist) | (val >> (64 - dist));
}

static inline hashval_t
fetch(const uint8_t *buf)
{
	hashval_t val;

	memcpy(&val.high, buf, sizeof(val.high));
	memcpy(&val.low, buf + sizeof(val.high), sizeof(val.low));

	val.high = ntohll(val.high);
	val.low = ntohll(val.low);

	return val;
}

static inline void
mix(hashval_t *state, hashval_t *val, hashval_t *c)
{
	val->low *= c->low; 
	val->low  = rotl64(val->low, 23);
	val->low *= c->high;
	state->low ^= val->low;
	state->low += state->high;

	state->high = rotl64(state->high, 41);

	val->high *= c->high; 
	val->high  = rotl64(val->high, 23);
	val->high *= c->low;
	state->high ^= val->high;
	state->high += state->low;

	state->low = state->low * 3 + 0x52dce729LL;
	state->high = state->high * 3 + 0x38495ab5LL;

	c->low = c->low * 5 + 0x7b7d159cLL;
	c->high = c->high * 5 + 0x6bce6396LL;
}

static inline uint64_t
final(uint64_t val)
{
	val ^= val >> 33;
	val *= 0xff51afd7ed558ccdLL;
	val ^= val >> 33;
	val *= 0xc4ceb9fe1a85ec53LL;
	val ^= val >> 33;

	return val;
}

hashval_t
hash(const uint8_t *buf, const size_t len, const uint64_t seed)
{
	hashval_t c = { 0x87c37b91114253d5LL, 0x4cf5ad432745937fLL };
	hashval_t state = { 0x9368e53c2f6af274LL ^ seed, 0x586dcd208f7cd3fdLL ^ seed };
	const uint8_t *end;

	end = buf + len;

	/* process all blocks */
	while (buf + sizeof(hashval_t) <= end) {
		hashval_t val;

		val = fetch(buf);
		buf += sizeof(hashval_t);

		mix(&state, &val, &c);
	}

	/* process the tail */
	if (buf < end) {
		hashval_t val = { 0, 0 };

		switch((end - buf) & 15) {
		case 15: val.high ^= (uint64_t) buf[14] << 48;
		case 14: val.high ^= (uint64_t) buf[13] << 40;
		case 13: val.high ^= (uint64_t) buf[12] << 32;
		case 12: val.high ^= (uint64_t) buf[11] << 24;
		case 11: val.high ^= (uint64_t) buf[10] << 16;
		case 10: val.high ^= (uint64_t) buf[ 9] <<  8;
		case  9: val.high ^= (uint64_t) buf[ 8] <<  0;

		case  8: val.low ^= (uint64_t) buf[ 7] << 56;
		case  7: val.low ^= (uint64_t) buf[ 6] << 48;
		case  6: val.low ^= (uint64_t) buf[ 5] << 40;
		case  5: val.low ^= (uint64_t) buf[ 4] << 32;
		case  4: val.low ^= (uint64_t) buf[ 3] << 24;
		case  3: val.low ^= (uint64_t) buf[ 2] << 16;
		case  2: val.low ^= (uint64_t) buf[ 1] <<  8;
		case  1: val.low ^= (uint64_t) buf[ 0] <<  0;
		}

		mix(&state, &val, &c);
	}

	/* finalization */
	state.high ^= len;

	state.low += state.high;
	state.high += state.low;

	state.low = final(state.low);
	state.high = final(state.high);

	state.low += state.high;
	state.high += state.low;

	return state;
}
