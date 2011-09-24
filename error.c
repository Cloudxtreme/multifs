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

#include "error.h"
#include "compat.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Configurable output
 */
static void	stdio(const char *, size_t, enum error);

static void
(*outfun)(const char *, size_t, enum error) = stdio;

void
error_redirect(void (*fun)(const char *, size_t, enum error))
{
	outfun = fun;
}

static void
stdio(const char *str, size_t len, enum error error)
{
	FILE *fd = error == ERROR_TRACE? stdout : stderr;

	fprintf(fd, "%s: ", getprogname());
	fwrite(str, 1, len, fd);
	fprintf(fd, "\n");
}

/*
 * Output an error message
 */
static void
output(int code, const char *fmt, va_list ap, enum error error)
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

	outfun(buf, p - buf, error);
}

/*
 * Tracing
 */
void
vtrace(const char *fmt, va_list ap)
{
	output(-1, fmt, ap, ERROR_TRACE);
}

void
trace(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	output(-1, fmt, ap, ERROR_TRACE);
	va_end(ap);
}

/*
 * Warnings
 */
void
vwarningc(int code, const char *fmt, va_list ap)
{
	output(code, fmt, ap, ERROR_WARNING);
}

void
warningc(int code, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	output(code, fmt, ap, ERROR_WARNING);
	va_end(ap);
}

void
vwarning(const char *fmt, va_list ap)
{
	output(errno, fmt, ap, ERROR_WARNING);
}

void
warning(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	output(errno, fmt, ap, ERROR_WARNING);
	va_end(ap);
}

void
vwarningx(const char *fmt, va_list ap)
{
	output(-1, fmt, ap, ERROR_WARNING);
}

void
warningx(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	output(-1, fmt, ap, ERROR_WARNING);
	va_end(ap);
}

/*
 * Errors
 */
void
vfatalc(int status, int code, const char *fmt, va_list ap)
{
	output(code, fmt, ap, ERROR_WARNING);
	exit(status);
}

void
fatalc(int status, int code, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfatalc(status, code, fmt, ap);
	va_end(ap);
}

void
vfatal(int status, const char *fmt, va_list ap)
{
	vfatalc(status, errno, fmt, ap);
}

void
fatal(int status, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfatalc(status, errno, fmt, ap);
	va_end(ap);
}

void
vfatalx(int status, const char *fmt, va_list ap)
{
	vfatalc(status, -1, fmt, ap);
}

void
fatalx(int status, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfatalc(status, -1, fmt, ap);
	va_end(ap);
}
