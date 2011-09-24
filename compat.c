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

#include "compat.h"

#ifndef HAVE_GETPROGNAME
const char *
getprogname(void)
{
# if defined(HAVE_PROGNAME)
	extern const char *__progname;
	return __progname;
# elif defined(HAVE_PROGRAM_INVOCATION_NAME)
	extern const char *program_invocation_short_name;
	return program_invocation_short_name;
# else
	return "(unknown)";
# endif /* HAVE___PROGNAME */
}
#endif /* HAVE_GETPROGNAME */
