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

#ifndef ERROR_H
#define ERROR_H

#include <stdarg.h>
#include <stddef.h>

#ifdef __GNUC__
# define NORETURN	__attribute__ ((noreturn))
#else
# define NORETURN
#endif

enum error {
	ERROR_TRACE,
	ERROR_WARNING,
	ERROR_FATAL
};

void		 error_redirect(void (*)(const char *, size_t, enum error));

void		 vtrace(const char *, va_list);
void		 trace(const char *, ...);

void		 vwarningc(int, const char *, va_list);
void		 warningc(int, const char *, ...);
void		 vwarning(const char *, va_list);
void		 warning(const char *, ...);
void		 vwarningx(const char *, va_list);
void		 warningx(const char *, ...);

NORETURN void	 vfatalc(int, int, const char *, va_list);
NORETURN void	 fatalc(int, int, const char *, ...);
NORETURN void	 vfatal(int, const char *, va_list);
NORETURN void	 fatal(int, const char *, ...);
NORETURN void	 vfatalx(int, const char *, va_list);
NORETURN void	 fatalx(int, const char *, ...);

#endif /* ERROR_H */
