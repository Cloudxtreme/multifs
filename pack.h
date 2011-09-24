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

#ifndef PACK_H
#define PACK_H

#include <unistd.h>
#include <stddef.h>
#include <stdarg.h>

ssize_t	 vpack(char *, const size_t, const char *, va_list);
ssize_t	 pack(char *, const size_t, const char *, ...);
ssize_t	 vunpack(const char *, const size_t, const char *, va_list);
ssize_t	 unpack(const char *, const size_t, const char *, ...);

#endif /* PACK_H */
