#ifndef CONFIG_H
#define CONFIG_H

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

#endif /* CONFIG_H */
