/*
 * MultiFS Distributing Multicast Filesystem
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

#include "multifs.h"
#include "bytesex.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define be8get(p)	(*(const uint8_t *) (p))
#define be8put(p, v)	(*(uint8_t *) (p) = (v))

/***************************************************************************
 *** Pack ******************************************************************
 ***************************************************************************/

#define PACK(bits, val)                                                     \
	do {                                                                \
		uint ## bits ## _t tmp;                                     \
		tmp = (val);                                                \
		if (p + sizeof(tmp) <= end)                                 \
			be ## bits ## put(p, tmp);                          \
		p += sizeof(tmp);                                           \
	} while (0)

ssize_t
vpack(char *const buf, const size_t len, const char *fmt, va_list ap)
{
	char *p, *end;

	p = buf;
	end = buf + len;
	while (*fmt != '\0') {
		/* get operation */
		switch (*(fmt++)) {
		case 'b': PACK(8, va_arg(ap, int)); break;
		case 'w': PACK(16, va_arg(ap, int)); break;
		case 'd': PACK(32, va_arg(ap, int)); break;
		case 'q': PACK(64, va_arg(ap, uint64_t)); break;

		case 's': {	/* string (length followed by content) */
			size_t l;
			const char *s;

			/* get string and length */
			l = va_arg(ap, size_t);
			s = va_arg(ap, const char *);

			/* output length prefix */
			if (l < 128) {
				PACK(8, l);
			} else if (l < 32768) {
				PACK(16, l | (1 << 15));
			} else {
				errno = EFBIG;
				return -1;
			}

			/* output string */
			if (p + l <= end)
				memcpy(p, s, l);
			p += l;

			break;
		}

		case 'z': {	/* string (NUL-terminated) */
			size_t l;
			const char *s;

			/* get string and length */
			s = va_arg(ap, const char *);
			l = strlen(s);

			/* output string */
			if (p + l + 1 <= end)
				memcpy(p, s, l + 1);
			p += l + 1;

			break;
		}

		case '*': {	/* array */
			size_t l;
			const void *b;
			int stride;

			/* determine stride (element size) */
			switch (*(fmt++)) {
			case 'b': stride = sizeof(uint8_t); break;
			case 'w': stride = sizeof(uint16_t); break;
			case 'd': stride = sizeof(uint32_t); break;
			case 'q': stride = sizeof(uint64_t); break;
			default:
				errno = EINVAL;
				return -1;
			}

			/* get the size and pointer */
			l = va_arg(ap, size_t);
			b = va_arg(ap, const void *);

			/* perform the copy */
			if (p + l * stride <= end) {
				switch (stride) {
				case sizeof(uint8_t):  memcpy(p, b, l);  break;
				case sizeof(uint16_t): mbe16put(p, b, l); break;
				case sizeof(uint32_t): mbe32put(p, b, l); break;
				case sizeof(uint64_t): mbe64put(p, b, l); break;
				}
			}

			p += l * stride;

			break;
		}

		default:
			errno = EINVAL;
			return -1;
		}
	}

	return p - buf;
}

ssize_t
pack(char *const buf, const size_t len, const char *fmt, ...)
{
	va_list ap;
	ssize_t r;

	va_start(ap, fmt);
	r = vpack(buf, len, fmt, ap);
	va_end(ap);

	return r;
}


/***************************************************************************
 *** Unpack*****************************************************************
 ***************************************************************************/

#define UNPACK(bits, val)                                                   \
	do {                                                                \
		uint ## bits ## _t tmp = 0;                                 \
		if (p + sizeof(tmp) <= end)                                 \
			tmp = be ## bits ## get(p);                         \
		(val) = tmp;                                                \
		p += sizeof(tmp);                                           \
	} while (0)

#define UNPACKARG(bits)		UNPACK(bits, *va_arg(ap, uint ## bits ## _t *))

ssize_t
vunpack(const char *const buf, const size_t len, const char *fmt, va_list ap)
{
	const char *p, *end;

	p = buf;
	end = buf + len;
	while (*fmt != '\0') {
		/* get operation */
		switch (*(fmt++)) {
		case 'b': UNPACKARG(8); break;
		case 'w': UNPACKARG(16); break;
		case 'd': UNPACKARG(32); break;
		case 'q': UNPACKARG(64); break;

		case 's': {	/* string (length followed by content) */
			size_t *l, i;
			char *s;

			/* get buffer size and pointer */
			l = va_arg(ap, size_t *);
			s = va_arg(ap, char *);

			/* determine string length */
			UNPACK(8, i);
			if (i & 0x80) {
				p -= sizeof(uint8_t);
				UNPACK(16, i);
				i &= ~(1 << 15);
			}
			i = min(i, (size_t) (end - p));

			/* get the string */
			memcpy(s, p, min(*l, i));
			*l = i;
			p += i;

			break;
		}

		case 'z': {	/* string (NUL-terminated) */
			size_t *l, i;
			char *s;
			const char *e;

			/* get buffer size and pointer */
			l = va_arg(ap, size_t *);
			s = va_arg(ap, char *);

			/* determine string length */
			e = memchr(p, '\0', end - p);
			if (e != NULL)
				i = end - e + 1;
			else
				i = end - p;

			/* get the string */
			memcpy(s, p, min(*l, i));
			*l = i;
			p += i;

			break;
		}

		case '*': {	/* array */
			size_t l;
			void *b;
			int stride;

			/* determine stride (element size) */
			switch (*(fmt++)) {
			case 'b': stride = sizeof(uint8_t); break;
			case 'w': stride = sizeof(uint16_t); break;
			case 'd': stride = sizeof(uint32_t); break;
			case 'q': stride = sizeof(uint64_t); break;
			default:
				errno = EINVAL;
				return -1;
			}

			/* get the size and pointer */
			l = va_arg(ap, size_t);
			b = va_arg(ap, void *);

			/* perform the copy */
			if (p + l * stride <= end) {
				switch (stride) {
				case sizeof(uint8_t):  memcpy(b, p, l);  break;
				case sizeof(uint16_t): mbe16get(b, p, l); break;
				case sizeof(uint32_t): mbe32get(b, p, l); break;
				case sizeof(uint64_t): mbe64get(b, p, l); break;
				}
			}

			p += l * stride;

			break;
		}

		default:
			errno = EINVAL;
			return -1;
		}
	}

	return p - buf;
}

ssize_t
unpack(const char *const buf, size_t len, const char *fmt, ...)
{
	va_list ap;
	ssize_t r;

	va_start(ap, fmt);
	r = vunpack(buf, len, fmt, ap);
	va_end(ap);

	return r;
}