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

#include <fuse_opt.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

enum {
	KEY_VERSION,
	KEY_HELP,
	KEY_DEBUG,
	KEY_FOREGROUND
};

#define MULTIFS_OPT(o, f, d)	{ o, offsetof(struct multifs, f), (d) }

static const struct fuse_opt
multifs_opts[] = {
	FUSE_OPT_KEY("-v",		KEY_VERSION),
	FUSE_OPT_KEY("--version",	KEY_VERSION),
	FUSE_OPT_KEY("-h",		KEY_HELP),
	FUSE_OPT_KEY("--help",		KEY_HELP),
	FUSE_OPT_KEY("debug",		KEY_DEBUG),
	FUSE_OPT_KEY("-d",		KEY_DEBUG),
	FUSE_OPT_KEY("-f",		KEY_FOREGROUND),

	FUSE_OPT_END
};

/*
 * Display a friendly usage message
 */
noreturn static void
usage(void)
{
	struct fuse_args args;

	memset(&args, '\0', sizeof(args));
	fprintf(stderr,
		"usage: %s name datadir mountpoint [options]\n"
		"\n"
		"general options:\n"
		"    -o opt,[opt...]        mount options\n"
		"    -h   --help            print help\n"
		"    -v   --version         print version\n"
		"\n", getprogname());

	fuse_opt_add_arg(&args, getprogname());
	fuse_opt_add_arg(&args, "-ho");
	multifs_main(args.argc, args.argv, NULL);
	exit(1);
}

static int
opt_proc(void *data, const char *arg, int key,
         struct fuse_args *outargs)
{
	struct multifs *multifs = (struct multifs *) data;

	switch (key) {
	case FUSE_OPT_KEY_NONOPT:
		if (multifs->fsname == NULL) {
			multifs->fsname = strdup(arg);
			if (multifs->fsname == NULL)
				err(1, "strdup");
			multifs->fsnamelen = strlen(multifs->fsname);
			return 0;
		} else if (multifs->fsroot == NULL) {
			multifs->fsroot = realpath(arg, NULL);
			if (multifs->fsroot == NULL)
				err(1, "%s", arg);
			multifs->fsrootlen = strlen(multifs->fsroot);
			return 0;
		}

	case FUSE_OPT_KEY_OPT:
		return 1;

	case KEY_HELP:
		usage();

	case KEY_VERSION:
		fprintf(stderr, "multifs-" VERSION ", Copyright (c) 2011, Wouter Coene <wouter@irdc.nl>\n");
		fuse_opt_add_arg(outargs, "--version");
		multifs_main(outargs->argc, outargs->argv, NULL);
		exit(0);

	case KEY_DEBUG:
		multifs->debug = true;
	case KEY_FOREGROUND:
		multifs->foreground = true;
		return 0;
    	}

	errx(1, "internal error");
}

int
main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct multifs multifs;

	/* parse options */
	memset(&multifs, '\0', sizeof(multifs));
	if (fuse_opt_parse(&args, &multifs, multifs_opts, opt_proc) < 0)
		exit(1);

	/* pass on options */
	if (multifs.debug)
		fuse_opt_add_arg(&args, "-d");
	else if (multifs.foreground)
		fuse_opt_add_arg(&args, "-f");

	/* validate arguments */
	if (multifs.fsname == NULL)
		warnx("missing filesystem name");
	else if (multifs.fsroot == NULL)
		warnx("missing data directory");
	else
		return multifs_main(args.argc, args.argv, &multifs);

	usage();
}
