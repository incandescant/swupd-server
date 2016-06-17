/*
 *   Software Updater - server side
 *
 *      Copyright © 2012-2016 Intel Corporation.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, version 2 or later of the License.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *   Authors:
 *         Arjan van de Ven <arjan@linux.intel.com>
 *         Sebastien Boeuf <sebastien.boeuf@intel.com>
 *         Joshua Lock <joshua.g.lock@intel.com>
 *
 */

#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "swupd.h"

int inflate_manifest (char *manifestdir, char *manifespath)
{
	char *const tarcmd[] = { TAR_COMMAND, "-C", manifestdir, TAR_PERM_ATTR_ARGS_STRLIST, "-xf", manifespath, NULL };
	return system_argv(tarcmd);
}

int inflate_pack (char *packdir, char *packpath)
{
	char *const tarcmd[] = { TAR_COMMAND, "-C", packdir, TAR_WARN_ARGS, TAR_PERM_ATTR_ARGS_STRLIST, "-xf", packpath, NULL };
	return system_argv(tarcmd);
}

int archive_pack (char *packdir, char *packout, char *bundle_delta, char *mom_delta)
{
	char *const tarcmd[] = { TAR_COMMAND, "-C", packdir, TAR_PERM_ATTR_ARGS_STRLIST, "--numeric-owner", "-Jcf", packout, "delta", "staged", bundle_delta, mom_delta, NULL };
	return system_argv(tarcmd);
}

int compress_sign_manifest (char *manifestdir, char *manifestout, char *manifestfile, char *signedout)
{
	char *const tarcmd[] = { TAR_COMMAND, "-C", manifestdir, TAR_PERM_ATTR_ARGS_STRLIST, "-Jcf",
				 manifestout, manifestfile, signedout, NULL };
	return system_argv(tarcmd);
}

int compress_manifest (char *manifestdir, char *manifestout, char *manifestfile)
{
	char *const tarcmd[] = { TAR_COMMAND, "-C", manifestdir, TAR_PERM_ATTR_ARGS_STRLIST, "-Jcf",
				 manifestout, manifestfile, NULL };
	return system_argv(tarcmd);
}

int compress_fullfile_dir (char *fullfiledir, char *fullfileout, char *fullfile)
{
	char *const tarcmd[] = { TAR_COMMAND, "-C", fullfiledir, TAR_PERM_ATTR_ARGS_STRLIST, "-zcf", fullfileout, fullfile, NULL };
	return system_argv(tarcmd);
}

int compress_fullfile_xz (char *fullfiledir, char *fullfileout, char *fullfile)
{
	char *const tarlzmacmd[] = { TAR_COMMAND, "-C", fullfiledir, TAR_PERM_ATTR_ARGS_STRLIST, "-Jcf", fullfileout, fullfile, NULL };
	return system_argv(tarlzmacmd);
}

int compress_fullfile_gz (char *fullfiledir, char *fullfileout, char *fullfile)
{
	char *const targzipcmd[] = { TAR_COMMAND, "-C", fullfiledir, TAR_PERM_ATTR_ARGS_STRLIST, "-zcf", fullfileout, fullfile, NULL };
	return system_argv(targzipcmd);
}

int compress_fullfile_bz (char *fullfiledir, char *fullfileout, char *fullfile)
{
	char *const tarbzip2cmd[] = { TAR_COMMAND, "-C", fullfiledir, TAR_PERM_ATTR_ARGS_STRLIST, "-jcf", fullfileout, fullfile, NULL };
	return system_argv(tarbzip2cmd);
}

int copy_dir_with_attr (char *src, char *copydir, char *dest)
{
	char *param1;
	char *param2;
	int stderrfd;
	int ret;

	string_or_die(&param1, "--exclude=%s/?*", copydir);
	string_or_die(&param2, "./%s", copydir);
	char *const tarcfcmd[] = { TAR_COMMAND, "-C", src, TAR_PERM_ATTR_ARGS_STRLIST, "-cf", "-", param1, param2, NULL };
	char *const tarxfcmd[] = { TAR_COMMAND, "-C", dest, TAR_PERM_ATTR_ARGS_STRLIST, "-xf", "-", NULL };

	stderrfd = open("/dev/null", O_WRONLY);
	if (stderrfd == -1) {
		LOG(NULL, "Failed to open /dev/null", "");
		assert(0);
	}

	ret = system_argv_pipe(tarcfcmd, -1, stderrfd, tarxfcmd, -1, stderrfd);

	free(param1);
	free(param2);
	close(stderrfd);

	return ret;
}
