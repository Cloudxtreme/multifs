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
#include <fuse.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <sys/time.h>

#ifndef TIMESPEC_TO_TIMEVAL
# define TIMESPEC_TO_TIMEVAL(tv, ts)                                        \
	do {                                                                \
		(tv)->tv_sec = (ts)->tv_sec;                                \
		(tv)->tv_usec = (ts)->tv_nsec / 1000;                       \
	} while (0)
#endif

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

static mode_t
canonmode(mode_t mode)
{
	return (mode & S_IFMT) |
	    S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH |
	    (mode & (S_IXUSR | S_IXGRP | S_IXOTH) || (mode & S_IFMT) == S_IFDIR?
	     S_IXUSR | S_IXGRP | S_IXOTH : 0);
}

#define multifs		((struct multifs *) (fuse_get_context()->private_data))

#define getfpid()	(fuse_get_context()->pid)
#define getfuid()	(fuse_get_context()->uid)
#define getfgid()	(fuse_get_context()->gid)


/***************************************************************************
 *** Initialisation and destruction ****************************************
 ***************************************************************************/

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
	int status;

	/* wait for the networking worker to terminate */
	close(multifs->netfd);
	if (waitpid(multifs->netpid, &status, 0) < 0)
		warning("waitpid");
}


/***************************************************************************
 *** Objects ***************************************************************
 ***************************************************************************/

static int
multifs_symlink(const char *to, const char *from)
{
	int err;

	/* broadcast message */
	net_send(multifs->netfd, MSG_OBJ_SYMLINK, "ss",
	    strlen(to), to, strlen(from), from);

	/* unlink here */
	to = fullpath(multifs, to);
	from = fullpath(multifs, from);
	err = symlink(to, from);
	free((void *) to);
	free((void *) from);

	if (err < 0)
		return -errno;

	return 0;
}

static int
multifs_getattr(const char *path, struct stat *st)
{
	int err;

	/* retrieve file attributes */
	path = fullpath(multifs, path);
	err = stat(path, st);
	free((void *) path);

	if (err < 0)
		return -errno;

	/* we don't need no steenkin' pur-missjuns */
	st->st_uid = getfuid();
	st->st_gid = getfuid();
	st->st_mode = canonmode(st->st_mode);

	return 0;
}

static int
multifs_chmod(const char *path, mode_t mode)
{
	int err;
	struct stat st;
	char *fp;

	fp = fullpath(multifs, path);

	/* retrieve current attributes */
	err = stat(fp, &st);
	if (err < 0)
		goto out;

	/* broadcast change */
	net_send(multifs->netfd, MSG_OBJ_SETATTR, "sbqq", strlen(path), path,
	    mode & (S_IXUSR | S_IXGRP | S_IXOTH)? 1 : 0,
	    (uint64_t) st.st_atime, (uint64_t) st.st_mtime);

	/* set mode */
	err = chmod(fp, canonmode(mode));

out:
	free((void *) fp);
	if (err < 0)
		return -errno;

	return 0;
}

static int
multifs_utimens(const char *path, const struct timespec ts[2])
{
	int err;
	struct stat st;
	struct timeval tv[2];
	char *fp;

	fp = fullpath(multifs, path);

	/* retrieve current attributes */
	err = stat(fp, &st);
	if (err < 0)
		goto out;

	/* broadcast change */
	net_send(multifs->netfd, MSG_OBJ_SETATTR, "sbqq", strlen(path), path,
	    st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)? 1 : 0,
	    (uint64_t) ts[0].tv_sec, (uint64_t) ts[1].tv_sec);

	/* set time -- only use second-resolution here because that's what
	 * we transport over the network as well */
	memset(tv, '\0', sizeof(tv));
	tv[0].tv_sec = ts[0].tv_sec;
	tv[1].tv_sec = ts[1].tv_sec;
	err = utimes(fp, tv);

out:
	free((void *) fp);
	if (err < 0)
		return -errno;

	return 0;
}

static int
multifs_rename(const char *from, const char *to)
{
	int err;

	/* broadcast message */
	net_send(multifs->netfd, MSG_OBJ_SYMLINK, "ss",
	    strlen(from), from, strlen(to), to);

	/* unlink here */
	from = fullpath(multifs, from);
	to = fullpath(multifs, to);
	err = rename(from, to);
	free((void *) from);
	free((void *) to);

	if (err < 0)
		return -errno;

	return 0;
}


/***************************************************************************
 *** Directories ***********************************************************
 ***************************************************************************/

static int
multifs_mkdir(const char *path, mode_t UNUSED(mode))
{
	int r;

	/* broadcast the change */
	net_send(multifs->netfd, MSG_DIR_CREATE, "s", strlen(path), path);

	/* create the directory */ 
	path = fullpath(multifs, path);
	r = mkdir(path, canonmode(S_IFDIR));
	free((void *) path);

	if (r < 0)
		return -errno;

	return 0;
}

static int
multifs_rmdir(const char *path)
{
	int r;

	/* broadcast the change */
	net_send(multifs->netfd, MSG_DIR_REMOVE, "s",
	    strlen(path), path);

	/* create the directory */ 
	path = fullpath(multifs, path);
	r = rmdir(path);
	free((void *) path);

	if (r < 0)
		return -errno;

	return 0;
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


/***************************************************************************
 *** Files *****************************************************************
 ***************************************************************************/

static int
multifs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	char *fp;

	fp = fullpath(multifs, path);

	/* attempt to create the file */
	fi->fh = open(fp, fi->flags | O_CREAT | O_EXCL, canonmode(mode));
	if ((int) fi->fh >= 0) {
		/* we've just created the file */
		net_send(multifs->netfd, MSG_FILE_CREATE, "sb",
		    strlen(path), path,
		    mode & (S_IXUSR | S_IXGRP | S_IXOTH)? 1 : 0);
		goto out;
	}

	/* just open the file */
	fi->fh = open(fp, fi->flags);

out:
	free((void *) fp);

	if ((int) fi->fh < 0)
		return -errno;

	/* enable direct I/O if we're only reading */
	fi->direct_io = (fi->flags & O_ACCMODE) == O_RDONLY;

	return 0;
}

static int
multifs_open(const char *path, struct fuse_file_info *fi)
{
	char *fp;

	assert(!(fi->flags & O_CREAT));

	/* does the file need to be truncated? */
	if (fi->flags & O_TRUNC)
		net_send(multifs->netfd, MSG_FILE_TRUNCATE, "sq",
		    strlen(path), path, (uint64_t) 0);

	/* just open the file */
	fp = fullpath(multifs, path);
	fi->fh = open(fp, fi->flags);
	free((void *) fp);

	if ((int) fi->fh < 0)
		return -errno;

	/* enable direct I/O if we're only reading */
	fi->direct_io = (fi->flags & O_ACCMODE) == O_RDONLY;

	return 0;
}

static int
multifs_truncate(const char *path, off_t length)
{
	int err;

	/* broadcast message */
	net_send(multifs->netfd, MSG_FILE_TRUNCATE, "sq",
	    strlen(path), path, (uint64_t) length);

	/* unlink here */
	path = fullpath(multifs, path);
	err = truncate(path, length);
	free((void *) path);

	if (err < 0)
		return -errno;

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
	size_t i, s, chunksz, pathlen;

	/* determine the chunk size */
	pathlen = strlen(path);
	chunksz = multifs->maxmsglen - pack(NULL, 0, "sq", pathlen,
	    path, (uint64_t) 0);

	/* transmit the write in chunks */
	for (i = 0; i < size; i += chunksz) {
		s = min(chunksz, size - i);
		net_send(multifs->netfd, MSG_FILE_WRITE, "sq*b", pathlen,
		    path, (uint64_t) offset + i, s, buf + i);
	}

	/* write to the file */
	r = pwrite(fi->fh, buf, size, offset);
	if (r < 0)
		return -errno;

	return (int) r;
}

static int
multifs_link(const char *to, const char *from)
{
	int err;

	/* broadcast message */
	net_send(multifs->netfd, MSG_FILE_LINK, "ss",
	    strlen(to), to, strlen(from), from);

	/* unlink here */
	to = fullpath(multifs, to);
	from = fullpath(multifs, from);
	err = link(to, from);
	free((void *) to);
	free((void *) from);

	if (err < 0)
		return -errno;

	return 0;
}

static int
multifs_unlink(const char *path)
{
	int err;

	/* broadcast message */
	net_send(multifs->netfd, MSG_FILE_UNLINK, "s", strlen(path), path);

	/* unlink here */
	path = fullpath(multifs, path);
	err = unlink(path);
	free((void *) path);

	if (err < 0)
		return -errno;

	return 0;
}

static int
multifs_lock(const char *UNUSED(path), struct fuse_file_info *UNUSED(fi),
             int UNUSED(cmd), struct flock *UNUSED(flock))
{
	return -ENOSYS;
}

static struct fuse_operations
multifs_ops = {
	/* initialisation and destruction */
	.init		= multifs_init,
	.destroy	= multifs_destroy,

	/* objects */
	.symlink	= multifs_symlink,
	.getattr	= multifs_getattr,
	.chmod		= multifs_chmod,
	.utimens	= multifs_utimens,
	.rename		= multifs_rename,

	/* directories */
	.mkdir		= multifs_mkdir,
	.rmdir		= multifs_rmdir,
	.opendir	= multifs_opendir,
	.readdir	= multifs_readdir,
	.releasedir	= multifs_releasedir,

	/* files */
	.create		= multifs_create,
	.open		= multifs_open,
	.truncate	= multifs_truncate,
	.link		= multifs_link,
	.unlink		= multifs_unlink,
	.lock		= multifs_lock,
	.read		= multifs_read,
	.write		= multifs_write
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
	pathlen = sizeof(path) - multifs->fsrootlen - 1;
	r = unpack(buf, len, "s", &pathlen, path + multifs->fsrootlen);
	if (r < 0)
		goto bad_unpack;
	buf += r;
	len -= r;
	path[multifs->fsrootlen + pathlen] = '\0';

	switch (msg) {
	case MSG_OBJ_SETATTR: {
		uint8_t exec;
		uint64_t atime, mtime;
		struct timeval tv[2];
		struct stat st;

		/* get the new attributes */
		memset(tv, '\0', sizeof(tv));
		r = unpack(buf, len, "bqq", &exec, &atime, &mtime);
		if (r < 0)
			goto bad_unpack;
		tv[0].tv_sec = atime;
		tv[1].tv_sec = mtime;

		/* get current attributes */
		r = stat(path, &st);
		if (r < 0)
			goto err;

		/* set new mode */
		if (exec)
			st.st_mode |= S_IXUSR | S_IXGRP | S_IXOTH;
		else
			st.st_mode &= ~(S_IXUSR | S_IXGRP | S_IXOTH);
		r = chmod(path, st.st_mode);
		if (r < 0)
			goto err;

		/* set time */
		r = utimes(path, tv);
		break;
	}

	case MSG_FILE_CREATE: {
		uint8_t exec;
		int fd;

		/* get the executable flag */
		r = unpack(buf, len, "b", &exec);
		if (r < 0)
			goto bad_unpack;

		/* create the file */
		fd = open(path, O_CREAT | O_EXCL | O_TRUNC,
		    canonmode(exec? S_IXUSR : 0));
		if (fd < 0)
			r = -1;
		else
			close(fd);
		break;
	}

	case MSG_FILE_TRUNCATE: {
		uint64_t length;

		/* get the new length */
		r = unpack(buf, len, "q", &length);
		if (r < 0)
			goto bad_unpack;

		/* truncate the file */
		r = truncate(path, length);
		break;
	}

	case MSG_OBJ_SYMLINK:
	case MSG_OBJ_RENAME:
	case MSG_FILE_LINK: {
		char newpath[MAXPATHLEN];

		/* get the new name */
		memcpy(newpath, multifs->fsroot, multifs->fsrootlen);
		pathlen = sizeof(newpath) - multifs->fsrootlen - 1;
		r = unpack(buf, len, "s", &pathlen, newpath + multifs->fsrootlen);
		if (r < 0) 
			goto bad_unpack;
		newpath[multifs->fsrootlen + pathlen] = '\0';

		/* do what we must */
		switch (msg) {
		case MSG_OBJ_SYMLINK:	r = symlink(path, newpath); break;
		case MSG_OBJ_RENAME:	r = rename(path, newpath); break;
		case MSG_FILE_LINK:	r = link(path, newpath); break;
		default:		fatalx(1, "can't happen");
		}
		break;
	}

	case MSG_DIR_CREATE: {
		/* create the directory */
		r = mkdir(path, canonmode(S_IFDIR) & ~S_IFMT);
		break;
	}

	case MSG_DIR_REMOVE:
		r = rmdir(path);
		break;

	case MSG_FILE_UNLINK:
		r = unlink(path);
		break;

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
err:
		warning("multifs_process(%s)", path);
		return -1;
	}

	return 1;

bad_unpack:
	warning("multifs_process: unpack");
	return -1;
}
