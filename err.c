#include "multifs.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Configurable output
 */
static void	stdio(const char *, size_t, enum err);

static void
(*outfun)(const char *, size_t, enum err) = stdio;

void
err_redirect(void (*fun)(const char *, size_t, enum err))
{
	outfun = fun;
}

static void
stdio(const char *str, size_t len, enum err err)
{
	FILE *fd = err == ERR_TRACE? stdout : stderr;

	fprintf(fd, "%s: ", getprogname());
	fwrite(str, 1, len, fd);
	fprintf(fd, "\n");
}

/*
 * Output an error message
 */
static void
output(int code, const char *fmt, va_list ap, enum err err)
{
	static char buf[256];
	char *p, *end;

	p = buf;
	end = p + sizeof(buf);

	if (fmt != NULL) {
		p += vsnprintf(p, end - p, fmt, ap);
		if (code >= 0)
			p += snprintf(p, end - p, ": ");
	}

	if (code >= 0)
		p += snprintf(p, end - p, "%s", strerror(code));

	outfun(buf, p - buf, err);
}

/*
 * Tracing
 */
void
vtrace(const char *fmt, va_list ap)
{
	output(-1, fmt, ap, ERR_TRACE);
}

void
trace(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	output(-1, fmt, ap, ERR_TRACE);
	va_end(ap);
}

/*
 * Warnings
 */
void
vwarnc(int code, const char *fmt, va_list ap)
{
	output(code, fmt, ap, ERR_WARN);
}

void
warnc(int code, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	output(code, fmt, ap, ERR_WARN);
	va_end(ap);
}

void
vwarn(const char *fmt, va_list ap)
{
	output(errno, fmt, ap, ERR_WARN);
}

void
warn(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	output(-1, fmt, ap, ERR_WARN);
	va_end(ap);
}

void
vwarnx(const char *fmt, va_list ap)
{
	output(-1, fmt, ap, ERR_WARN);
}

void
warnx(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	output(-1, fmt, ap, ERR_WARN);
	va_end(ap);
}

/*
 * Errors
 */
void
verrc(int status, int code, const char *fmt, va_list ap)
{
	output(code, fmt, ap, ERR_ERR);
	exit(status);
}

void
errc(int status, int code, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verrc(status, code, fmt, ap);
	va_end(ap);
}

void
verr(int status, const char *fmt, va_list ap)
{
	verrc(status, errno, fmt, ap);
}

void
err(int status, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verrc(status, errno, fmt, ap);
	va_end(ap);
}

void
verrx(int status, const char *fmt, va_list ap)
{
	verrc(status, -1, fmt, ap);
}

void
errx(int status, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verrc(status, -1, fmt, ap);
	va_end(ap);
}
