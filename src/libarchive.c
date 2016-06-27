/*
 *   Software Updater - server side
 *
 *      Copyright © 2016 Intel Corporation.
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
 *         Joshua Lock <joshua.g.lock@intel.com>
 *
 * NOTE: it's not possible to support GNU tar generated update artefacts with
 * the libarchive backend:
 * http://comments.gmane.org/gmane.comp.gnu.tar.bugs/5443
 */

#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>


#include <unistd.h>
#include <archive.h>
#include <archive_entry.h>

#include "swupd.h"

#if SWUPD_WITH_BSDTAR
#define TAR_COMMAND "bsdtar"
#define TAR_XATTR_ARGS ""
#define TAR_XATTR_ARGS_STRLIST
#define TAR_WARN_ARGS ""
#else
#define TAR_COMMAND "tar"
#define TAR_XATTR_ARGS "--xattrs --xattrs-include='*'"
#define TAR_XATTR_ARGS_STRLIST "--xattrs", "--xattrs-include='*'",
#define TAR_WARN_ARGS "--warning=no-timestamp"
#endif

#if SWUPD_WITH_SELINUX
#define TAR_PERM_ATTR_ARGS "--preserve-permissions --selinux " TAR_XATTR_ARGS
#define TAR_PERM_ATTR_ARGS_STRLIST TAR_XATTR_ARGS_STRLIST "--preserve-permissions", "--selinux"
#else
#define TAR_PERM_ATTR_ARGS "--preserve-permissions " TAR_XATTR_ARGS
#define TAR_PERM_ATTR_ARGS_STRLIST TAR_XATTR_ARGS_STRLIST "--preserve-permissions"
#endif

int copy_archive_data(struct archive *ar, struct archive *aw)
{
	int ret;
	const void *buff;
	size_t size;
	off_t offset;

	while (1) {
		ret = archive_read_data_block(ar, &buff, &size, &offset);
		if (ret == ARCHIVE_EOF) {
			return ARCHIVE_OK;
		}
		if (ret != ARCHIVE_OK) {
			return ret;
		}
		ret = archive_write_data_block(aw, buff, size, offset);
		if (ret != ARCHIVE_OK) {
			printf("Failed to write archive data %s", archive_error_string(aw));
			return ret;
		}
	}
}

int inflate_archive (char *inflatepath, char *archivepath, int inflateflags)
{
	int ret = -1;
	int err = -1;
	char *cwd = NULL;
	struct archive *a;
	struct archive *ext;
	struct archive_entry *entry;

	cwd = getcwd(NULL, 0);
	ret = chdir(inflatepath);
	if (ret != 0) {
		goto error;
	}

	a = archive_read_new();
	archive_read_support_format_all(a);
	archive_read_support_filter_all(a);
	ext = archive_write_disk_new();
	archive_write_disk_set_options(ext, inflateflags);

	ret = archive_read_open_filename(a, archivepath, 10240);
	if (ret != ARCHIVE_OK) {
		printf("Failed to open manifest archive: %s", archivepath);
		goto fail;
	}
	while (1) {
		ret = archive_read_next_header(a, &entry);
		if (ret == ARCHIVE_EOF) {
			break;
		}
		if (ret != ARCHIVE_OK) {
			printf("Failed to read archive: %s", archive_error_string(a));
			goto fail;
		}
		ret = archive_write_header(ext, entry);
		if (ret != ARCHIVE_OK) {
			printf("Failed to write archive %s", archive_error_string(ext));
			goto fail;
		}
		ret = copy_archive_data(a, ext);
		if (ret != ARCHIVE_OK) {
			printf("Failed to copy data %s", archive_error_string(ext));
			goto fail;
		}
		ret = archive_write_finish_entry(ext);
		if (ret != ARCHIVE_OK) {
			printf("Failed to finalise archive entry %s", archive_error_string(ext));
			goto fail;
		}
	}

fail:
	archive_read_close(a);
	archive_read_free(a);
	archive_write_close(ext);
	archive_write_free(ext);
error:
	err = chdir(cwd);
	if (err != 0) {
		printf("Failed to restore cwd to %s", cwd);
	}
	free(cwd);

	return ret;
}

int inflate_manifest (char *manifestdir, char *manifestpath)
{
	int flags = ARCHIVE_EXTRACT_TIME;
	flags |= ARCHIVE_EXTRACT_PERM;
	flags |= ARCHIVE_EXTRACT_ACL;
	flags |= ARCHIVE_EXTRACT_OWNER;
	flags |= ARCHIVE_EXTRACT_XATTR;

	return inflate_archive(manifestdir, manifestpath, flags);
}

int inflate_pack (char *packdir, char *packpath)
{
	int flags = ARCHIVE_EXTRACT_PERM;
	flags |= ARCHIVE_EXTRACT_ACL;
	flags |= ARCHIVE_EXTRACT_OWNER;
	flags |= ARCHIVE_EXTRACT_XATTR;

	return inflate_archive(packdir, packpath, flags);
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
