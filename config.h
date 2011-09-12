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

#ifndef CONFIG_H
#define CONFIG_H

/*
 * It's like FreeBSD, except where it's not
 */
#if defined(__APPLE__)
# define __FreeBSD__	10
#endif

/*
 * Wether sockaddr has an sa_len member
 */
#if defined(__FreeBSD__) || \
	defined(__OpenBSD__) || \
	defined(__NetBSD__) || \
	defined(__APPLE__)
# define HAVE_SA_LEN
#endif

/*
 * Wether SO_REUSEADDR works like SO_REUSEPORT
 */
#if defined(__linux__)
# define HAVE_REUSEADDR_LIKE_REUSEPORT
#endif

/*
 * Wether we have getprogname()
 */
#if defined(__APPLE__) || defined(__FreeBSD__)
# define HAVE_GETPROGNAME
#endif

/*
 * Wether we have __progname
 */
#if defined(__OpenBSD__)
# define HAVE_PROGNAME
#endif

/*
 * Wether we have program_invocation_name
 */
#if defined(__linux__)
# define HAVE_PROGRAM_INVOCATION_NAME
#endif

/*
 * Wether we have <sys/select.h>
 */
#if defined(__linux__)
# define HAVE_SYS_SELECT
#endif

#endif /* CONFIG_H */
