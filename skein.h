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

#ifndef SKEIN_H
#define SKEIN_H

#include <stddef.h>
#include <stdint.h>

/*
 * 256-bit threefish
 */
struct threefish256 {
	uint64_t		 key[256 / (sizeof(uint64_t) * 8) + 1];
	uint64_t		 tweak[3];
};

void	 threefish256_init(struct threefish256 *);
void	 threefish256_encrypt(const struct threefish256 *, const uint64_t *, uint64_t *);
void	 threefish256_decrypt(const struct threefish256 *, const uint64_t *, uint64_t *);

/*
 * 512-bit threefish
 */
struct threefish512 {
	uint64_t		 key[512 / (sizeof(uint64_t) * 8) + 1];
	uint64_t		 tweak[3];
};

void	 threefish512_init(struct threefish512 *);
void	 threefish512_encrypt(const struct threefish512 *, const uint64_t *, uint64_t *);
void	 threefish512_decrypt(const struct threefish512 *, const uint64_t *, uint64_t *);

/*
 * 1024-bit threefish
 */
struct threefish1024 {
	uint64_t		 key[1024 / (sizeof(uint64_t) * 8) + 1];
	uint64_t		 tweak[3];
};

void	 threefish1024_init(struct threefish1024 *);
void	 threefish1024_encrypt(const struct threefish1024 *, const uint64_t *, uint64_t *);
void	 threefish1024_decrypt(const struct threefish1024 *, const uint64_t *, uint64_t *);


/*
 * 256-bit skein
 */
struct skein256 {
	struct threefish256	 tf;
	unsigned int		 hashlen,
				 buflen;
	uint8_t			 buf[256 / 8];
};

void	 skein256_init(struct skein256 *, unsigned int);
void	 skein256_update(struct skein256 *, const uint8_t *, size_t);
void	 skein256_done(struct skein256 *, uint8_t *);
void	 skein256_hash(unsigned int, const uint8_t *, size_t, uint8_t *);

/*
 * 512-bit skein
 */
struct skein512 {
	struct threefish512	 tf;
	unsigned int		 hashlen,
				 buflen;
	uint8_t			 buf[512 / 8];
};

void	 skein512_init(struct skein512 *, unsigned int);
void	 skein512_update(struct skein512 *, const uint8_t *, size_t);
void	 skein512_done(struct skein512 *, uint8_t *);
void	 skein512_hash(unsigned int, const uint8_t *, size_t, uint8_t *);

/*
 * 1024-bit skein
 */
struct skein1024 {
	struct threefish1024	 tf;
	unsigned int		 hashlen,
				 buflen;
	uint8_t			 buf[1024 / 8];
};

void	 skein1024_init(struct skein1024 *, unsigned int);
void	 skein1024_update(struct skein1024 *, const uint8_t *, size_t);
void	 skein1024_done(struct skein1024 *, uint8_t *);
void	 skein1024_hash(unsigned int, const uint8_t *, size_t, uint8_t *);

#endif /* SKEIN_H */
