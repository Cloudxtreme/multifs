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

#ifndef BYTESEX_H
#define BYTESEX_H

#include <stdint.h>

/*
 * Select platform
 */
#if defined(__APPLE__)
# include <machine/endian.h>
# include <libkern/_OSByteOrder.h>
# define bswap16	__DARWIN_OSSwapInt16
# define bswap32	__DARWIN_OSSwapInt32
# define bswap64	__DARWIN_OSSwapInt64
#elif defined(__FreeBSD__) || \
      defined(__NetBSD__)
# include <sys/endian.h>
# define be16get	be16dec
# define be32get	be32dec
# define be64get	be64dec
# define le16get	le16dec
# define le32get	le32dec
# define le64get	le64dec

# define be16put	be16enc
# define be32put	be32enc
# define be64put	be64enc
# define le16put	le16enc
# define le32put	le32enc
# define le64put	le64enc
#elif defined(__OpenBSD__)
# include <sys/endian.h>
#elif defined(__linux__)
# include <endian.h>
# define bswap16	__bswap_16
# define bswap32	__bswap_32
# define bswap64	__bswap_64
#endif

#if BYTE_ORDER == BIG_ENDIAN
# if !defined(betoh16)
#  define betoh16(x)	(x)
#  define betoh32(x)	(x)
#  define betoh64(x)	(x)
#  define letoh16	bswap16
#  define letoh32	bswap32
#  define letoh64	bswap64
# endif

# if !defined(htobe16)
#  define htobe16(x)	(x)
#  define htobe32(x)	(x)
#  define htobe64(x)	(x)
#  define htole16	bswap16
#  define htole32	bswap32
#  define htole64	bswap64
# endif
#else
# if !defined(betoh16)
#  define betoh16	bswap16
#  define betoh32	bswap32
#  define betoh64	bswap64
#  define letoh16(x)	(x)
#  define letoh32(x)	(x)
#  define letoh64(x)	(x)
# endif

# if !defined(htobe16)
#  define htobe16	bswap16
#  define htobe32	bswap32
#  define htobe64	bswap64
#  define htole16(x)	(x)
#  define htole32(x)	(x)
#  define htole64(x)	(x)
# endif
#endif

#if !defined(ntoh16)
# define ntoh16		betoh16
# define ntoh32		betoh32
# define ntoh64		betoh64
# define hton16		htobe16
# define hton32		htobe32
# define hton64		htobe64
#endif

#ifndef be16get
static inline uint16_t
be16get(const void *ptr)
{
	const uint8_t *p = (uint8_t *) ptr;

	return ((uint16_t) p[0] << 8) | (uint16_t) p[1];
}

static inline void
be16put(void *ptr, uint16_t val)
{
	uint8_t *p = (uint8_t *) ptr;

	p[0] = val >> 8;
	p[1] = val;
}

static inline uint32_t
be32get(const void *ptr)
{
	return ((uint32_t) be16get(ptr) << 16) |
	       (uint32_t) be16get(ptr + sizeof(uint16_t));
}

static inline void
be32put(void *ptr, uint32_t val)
{
	be16put(ptr, val >> 16);
	be16put(ptr + sizeof(uint16_t), val);
}

static inline uint64_t
be64get(const void *ptr)
{
	return ((uint64_t) be32get(ptr) << 32) |
	       (uint64_t) be32get(ptr + sizeof(uint32_t));
}

static inline void
be64put(void *ptr, uint64_t val)
{
	be32put(ptr, val >> 32);
	be32put(ptr + sizeof(uint32_t), val);
}

static inline uint16_t
le16get(const void *ptr)
{
	const uint8_t *p = (uint8_t *) ptr;

	return (uint16_t) p[0] | ((uint16_t) p[1] << 8);
}

static inline void
le16put(void *ptr, uint16_t val)
{
	uint8_t *p = (uint8_t *) ptr;

	p[0] = val;
	p[1] = val >> 8;
}

static inline uint32_t
le32get(const void *ptr)
{
	return (uint32_t) le16get(ptr) |
	       ((uint32_t) le16get(ptr + sizeof(uint16_t)) << 16);
}

static inline void
le32put(void *ptr, uint32_t val)
{
	le16put(ptr, val);
	le16put(ptr + sizeof(uint16_t), val >> 16);
}

static inline uint64_t
le64get(const void *ptr)
{
	return (uint64_t) le32get(ptr) |
	       ((uint64_t) le32get(ptr + sizeof(uint32_t)) << 32);
}

static inline void
le64put(void *ptr, uint64_t val)
{
	le32put(ptr, val);
	le32put(ptr + sizeof(uint32_t), val >> 32);
}
#endif

#endif /* BYTESEX_H */
