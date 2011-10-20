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
 * Process multiple whole blocks
 */
static void
SKEIN(process)(struct skein *ctx, const uint8_t *buf, size_t blocks, size_t len)
{
	uint64_t block[SKEIN_WORDS];

	while (blocks-- > 0) {
		/* update length */
		ctx->tf.tweak[0] += len;

		/* get the block in host byteorder */
		mle64get(block, buf, nitems(block));
		buf += sizeof(block);

		/* process it */
		THREEFISH(encrypt)(&ctx->tf, block);

		/* clear the first flag */
		ctx->tf.tweak[1] &= ~SKEIN_FLAG_FIRST;
	}
}

/*
 * Initialise the hash context
 */
void
SKEIN(init)(struct skein *ctx, unsigned int hashlen)
{
	uint64_t config[SKEIN_WORDS];

	memset(ctx, '\0', sizeof(*ctx));
	ctx->hashlen = hashlen;

	/* set the configuration */
	memset(config, '\0', sizeof(config));
	config[0] = htole64(((uint64_t) SKEIN_VERSION << 32) + SKEIN_ID);
	config[1] = htole64(hashlen);

	/* process the configuration block */
	ctx->tf.tweak[0] = 0;
	ctx->tf.tweak[1] = SKEIN_BLOCK_CFG | SKEIN_FLAG_FIRST | SKEIN_FLAG_LAST;
	SKEIN(process)(ctx, (uint8_t *) config, 1, 32);

	/* start the message */
	ctx->tf.tweak[0] = 0;
	ctx->tf.tweak[1] = SKEIN_BLOCK_MSG | SKEIN_FLAG_FIRST;
}

/*
 * Hash data
 */
void
SKEIN(update)(struct skein *ctx, const uint8_t *buf, size_t len)
{
	size_t n;

	/* To understand the logic in this function, consider the following:
	 * the specification states that blocks are never padded except for
	 * the last one, that the first block in the input is hashed with
	 * the FIRST flag set in the tweak, and the very last block hashed
	 * with the LAST flag in the tweak.
	 *
	 * This is implemented by buffering a potentially final block in the
	 * hash context until we are sure it is not the final block. */

	/* finish previous partial block */
	if (ctx->buflen > 0 &&
	    ctx->buflen + len > SKEIN_BYTES) {
		/* add data from input */
		n = sizeof(ctx->buf) - ctx->buflen;
		if (n > 0) {
			memcpy(ctx->buf + ctx->buflen, buf, n);
			buf += n;
			len -= n;
		}

		/* process the buffer */
		SKEIN(process)(ctx, ctx->buf, 1, sizeof(ctx->buf));
		ctx->buflen = 0;
	}

	/* process remaining full blocks, except for the last */
	if (len > SKEIN_BYTES) {
		n = (len - 1) / SKEIN_BYTES;
		SKEIN(process)(ctx, buf, n, SKEIN_BYTES);
		buf += SKEIN_BYTES * n;
		len -= SKEIN_BYTES * n;
	}

	/* buffer the remainder */
	if (len > 0) {
		memcpy(ctx->buf + ctx->buflen, buf, len);
		ctx->buflen += len;
	}
}

/*
 * Finalize the hash context and return the hash value
 */
void
SKEIN(done)(struct skein *ctx, uint8_t *hash)
{
	uint64_t	 key[nitems(ctx->tf.key)];
	unsigned int	 i, bytes, n;

	/* output last block */
	if (ctx->buflen < sizeof(ctx->buf))
		memset(ctx->buf + ctx->buflen, '\0', sizeof(ctx->buf) - ctx->buflen);
	ctx->tf.tweak[1] |= SKEIN_FLAG_LAST;
	SKEIN(process)(ctx, ctx->buf, 1, ctx->buflen);

	/* determine how much bytes to generate */
	bytes = (ctx->hashlen + 7) / 8;

	/* generate the output using threefish in counter mode -- skein uses
	 * this mechanism to support generating output that is larger than
	 * the state size */
	memset(ctx->buf, '\0', sizeof(ctx->buf));
	memcpy(key, ctx->tf.key, sizeof(key));
	for (i = 0; i * SKEIN_BYTES < bytes; i++) {
		/* hash the counter */
		ctx->tf.tweak[0] = 0;
		ctx->tf.tweak[1] = SKEIN_BLOCK_OUT | SKEIN_FLAG_FIRST | SKEIN_FLAG_LAST;
		le64put(ctx->buf, i);
		SKEIN(process)(ctx, ctx->buf, 1, sizeof(uint64_t));

		/* get the resulting hash */
		n = min(bytes - i * SKEIN_BYTES, SKEIN_BYTES);
		copyout(hash, ctx->tf.key, n);
		hash += n;

		/* restore the key for the next loop */
		memcpy(ctx->tf.key, key, sizeof(ctx->tf.key));
	}
}

/*
 * Hash data
 */
void
SKEIN(hash)(unsigned int hashlen, const uint8_t *buf, size_t len, uint8_t *hash)
{
	struct skein ctx;

	SKEIN(init)(&ctx, hashlen);
	SKEIN(update)(&ctx, buf, len);
	SKEIN(done)(&ctx, hash);
}
