#include "multifs.h"

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
