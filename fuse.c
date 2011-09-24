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

#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fuse/fuse.h>
#include <sys/param.h>

#define CHUNKSZ		32768

static char *
fullpath(struct multifs *multifs, const char *path)
{
	size_t pathlen;
	char *ret;

	/* prepend root to path */
	pathlen = strlen(path);
	ret = malloc(multifs->fsrootlen + pathlen + 1);
	if (ret != NULL) { 
		memcpy(ret, multifs->fsroot, multifs->fsrootlen);
		memcpy(ret + multifs->fsrootlen, path, pathlen);
		ret[multifs->fsrootlen + pathlen] = '\0';
	}

	return ret;
}

#define multifs		((struct multifs *) (fuse_get_context()->private_data))

static void *
multifs_init(struct fuse_conn_info *UNUSED(conn))
{
	/* create the networking helper */
	net_init(multifs);

	return multifs;
}

static void
multifs_destroy(void *UNUSED(data))
{
	/* terminate the networking worker */
	kill(multifs->netpid, SIGTERM);
}

static int
multifs_getattr(const char *path, struct stat *stbuf)
{
	int err;

	/* retrieve file attributes */
	path = fullpath(multifs, path);
	err = stat(path, stbuf);
	free((void *) path);

	if (err < 0)
		return -errno;

	return 0;
}

static int
multifs_open(const char *path, struct fuse_file_info *fi)
{
	/* attempt to open the file */
	path = fullpath(multifs, path);
	fi->fh = open(path, fi->flags);
	free((void *) path);

	if ((int) fi->fh < 0)
		return -errno;

	/* enable direct I/O if we're only reading */
	fi->direct_io = (fi->flags & O_ACCMODE) == O_RDONLY;

	return 0;
}

static int
multifs_read(const char *UNUSED(path), char *buf, size_t size, off_t offset,
              struct fuse_file_info *fi)
{
	ssize_t r;

	/* read from the file */
	r = pread(fi->fh, buf, size, offset);
	if (r < 0)
		return -errno;

	return (int) r;
}

static int
multifs_write(const char *path, const char *buf, size_t size, off_t offset,
              struct fuse_file_info *fi)
{
	ssize_t r;
	size_t i, s;

	/* transmit the write in chunks */
	for (i = 0; i < size; i += CHUNKSZ) {
		s = min(CHUNKSZ, size - i);
		net_send(multifs->netfd, MSG_FILE_WRITE, "sq*b", strlen(path), path,
		    (uint64_t) offset + i, s, buf + i);
	}

	/* write to the file */
	r = pwrite(fi->fh, buf, size, offset);
	if (r < 0)
		return -errno;

	return (int) r;
}

static int
multifs_opendir(const char *path, struct fuse_file_info *fi)
{
	/* attempt to open the directory */
	path = fullpath(multifs, path);
	fi->fh = (uintptr_t) opendir(path);
	free((void *) path);

	if (fi->fh == 0)
		return -errno;

	return 0;
}

static int
multifs_readdir(const char *UNUSED(path), void *buf, fuse_fill_dir_t filler,
                 off_t offset, struct fuse_file_info *fi)
{
	DIR *dir = (DIR *) fi->fh;
	struct dirent dirent, *result;

	/* position directory handle */
	seekdir(dir, offset);

	/* read from the directory */
	while (1) {
		if (readdir_r(dir, &dirent, &result) < 0)
			return -errno;

		/* end of directory reached */
		if (result == NULL)
			break;

		/* place it in the buffer */
		if (filler(buf, result->d_name, NULL, telldir(dir)) == 1)
			break;
	}

	return 0;
}

static int
multifs_releasedir(const char *UNUSED(path), struct fuse_file_info *fi)
{
	if (closedir((DIR *) fi->fh) < 0)
		return -errno;

	return 0;
}

static struct fuse_operations
multifs_ops = {
	.init		= multifs_init,
	.destroy	= multifs_destroy,
	.getattr	= multifs_getattr,
	.open		= multifs_open,
	.read		= multifs_read,
	.write		= multifs_write,
	.opendir	= multifs_opendir,
	.readdir	= multifs_readdir,
	.releasedir	= multifs_releasedir
};

#undef multifs

int
multifs_main(int argc, char *argv[], struct multifs *multifs)
{
	return fuse_main(argc, argv, &multifs_ops, multifs);
}

/*
 * Process an incoming packet from the networking layer
 */
int
multifs_process(struct multifs *multifs, enum msg msg, const char *buf, size_t len)
{
	char path[MAXPATHLEN];
	size_t pathlen;
	ssize_t r;

	/* decode the path */
	memcpy(path, multifs->fsroot, multifs->fsrootlen);
	pathlen = sizeof(path) - multifs->fsrootlen;
	r = unpack(buf, len, "s", &pathlen, path + multifs->fsrootlen);
	if (r < 0) 
		goto bad_unpack;
	buf += r;
	len -= r;

	switch (msg) {
	case MSG_FILE_WRITE: {
		uint64_t offset;
		int fd;

		/* get the offset */
		r = unpack(buf, len, "q", &offset);
		if (r < 0)
			goto bad_unpack;
		buf += r;
		len -= r;

		/* perform the write */
		fd = open(path, O_RDWR);
		if (fd >= 0) {
			r = pwrite(fd, buf, len, offset);
			close(fd);
		} else {
			r = -1;
		}

		break;
	}

	default:
		return 0;
	}

	/* report errors */
	if (r < 0) {
		warn("multifs_process(%*s)", (int) pathlen, path);
		return -1;
	}

	return 1;

bad_unpack:
	warn("multifs_process: unpack");
	return -1;
}
