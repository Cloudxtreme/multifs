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

#ifndef MULTIFS_H
#define MULTIFS_H

#include "config.h"

#include <endian.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#if BYTE_ORDER == LITTLE_ENDIAN
# define htonll(x)		(((uint64_t) htonl(x) << 32LL) | (uint64_t) htonl((x) >> 32LL))
# define ntohll(x)		htonll(x)
#else
# define htonll(x)		(x)
# define ntohll(x)		(x)
#endif

#define nitems(arr)		(sizeof(arr) / sizeof((arr)[0]))
#define min(a, b)		((a) < (b)? (a) : (b))
#define max(a, b)		((a) < (b)? (b) : (a))

#if __STDC_VERSION__ < 199901L
# define restrict
#endif

#ifdef __GNUC__
# define noreturn	__attribute__ ((noreturn))
#else
# define noreturn
#endif

/* protocol version */
#define NET_VERSION	1

/* port number */
#define NET_PORT	14655	/* from random.org, so guaranteed to be random */

/* filesystem state */
struct multifs {
	bool		 foreground;
	bool		 debug;
	const char	*fsname;
	size_t		 fsnamelen;
	const char	*fsroot;
	size_t		 fsrootlen;
	pid_t		 netpid;
	int		 netfd;
};

/* network messages */
enum msg {
	/*
	 * Basics
	 */
	MSG_RESEND		= 0x00,	/* request that a packet be resent */

	/*
	 * Token negotiation
	 */	
	MSG_TOKEN_WHERE		= 0x20,	/* look for the token */
	MSG_TOKEN_HERE,			/* report where the token is */
	MSG_TOKEN_ASK,			/* ask for the token */
	MSG_TOKEN_GIVE		= 0x3f,	/* give the token away */

	/*
	 * File operations
	 */
	MSG_FILE_CREATE		= 0x40,
	MSG_FILE_LINK,
	MSG_FILE_UNLINK,
	MSG_FILE_LOCK,
	MSG_FILE_UNLOCK,
	MSG_FILE_FSYNC,
	MSG_FILE_WRITE,

	/*
	 * When to send sequence
	 */
	MSG_WITH_SEQUENCE	= MSG_TOKEN_GIVE
};

/* fuse.c */
int		 multifs_main(int, char *[], struct multifs *);
int		 multifs_process(struct multifs *, enum msg, const char *, size_t);

/* pack.c */
ssize_t		 vpack(char *, const size_t, const char *, va_list);
ssize_t		 pack(char *, const size_t, const char *, ...);
ssize_t		 vunpack(const char *, const size_t, const char *, va_list);
ssize_t		 unpack(const char *, const size_t, const char *, ...);

/* hash.c */
typedef struct {
	uint64_t high, low;
} hashval_t;

hashval_t	 hash(const uint8_t *, const size_t, const uint64_t);

/* net.c */
void		 net_init(struct multifs *);
int		 net_send(int, enum msg, const char *, ...);

/* err.c */
enum err {
	ERR_TRACE,
	ERR_WARN,
	ERR_ERR
};

void		 err_redirect(void (*)(const char *, size_t, enum err));

void		 vtrace(const char *, va_list);
void		 trace(const char *, ...);

void		 vwarnc(int, const char *, va_list);
void		 warnc(int, const char *, ...);
void		 vwarn(const char *, va_list);
void		 warn(const char *, ...);
void		 vwarnx(const char *, va_list);
void		 warnx(const char *, ...);

noreturn void	 verrc(int, int, const char *, va_list);
noreturn void	 errc(int, int, const char *, ...);
noreturn void	 verr(int, const char *, va_list);
noreturn void	 err(int, const char *, ...);
noreturn void	 verrx(int, const char *, va_list);
noreturn void	 errx(int, const char *, ...);

/* compat.c */
#ifndef HAVE_GETPROGNAME
const char	*getprogname(void);
#endif /* HAVE_GETPROGNAME */

#endif /* MULTIFS_H */
