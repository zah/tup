/* vim: set ts=8 sw=8 sts=8 noet tw=78:
 *
 * tup - A file-based build system
 *
 * Copyright (C) 2010-2014  Mike Shal <marfey@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "dir_mutex.h"
#include "open_notify.h"

int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags)
{
	int rc;

        char cwd[PATH_MAX];
        _getcwd(cwd, PATH_MAX);

	dir_mutex_lock(dirfd);
	// No symlinks on windows...
	if(flags & AT_SYMLINK_NOFOLLOW) {
		//open_notify(ACCESS_READ, pathname);
#ifdef _WIN64
		rc = _stat64(pathname, buf);
#else
		rc = _stat32(pathname, buf);
#endif
	} else {
		//open_notify(ACCESS_READ, pathname);
#ifdef _WIN64
		rc = _stat64(pathname, buf);
#else
		rc = _stat32(pathname, buf);
#endif
	}
	chdir(cwd);
	dir_mutex_unlock();
	return rc;
}
