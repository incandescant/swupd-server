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


#include <string.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <archive.h>
#include <archive_entry.h>

#include "swupd.h"

typedef enum libarchive_filter_type {
	LIBARCHIVE_FILTER_BZ,
	LIBARCHIVE_FILTER_GZ,
	LIBARCHIVE_FILTER_XZ
} libarchive_filter_type;

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
		if (ret < ARCHIVE_OK) {
			return ret;
		}
		ret = archive_write_data_block(aw, buff, size, offset);
		if (ret < ARCHIVE_OK) {
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

int create_archive(char *archivedir, char *archivename, libarchive_filter_type filter, char *const contents[])
{
	int ret;
	int err;
	int fd;
	size_t len;
	char buff[8192];
	char *cwd = NULL;
	struct archive *a, *ar;
	struct archive_entry *entry;

	cwd = getcwd(NULL, 0);
	ret = chdir(archivedir);
	if (ret != 0) {
		goto error;
	}

	a = archive_write_new();
	switch (filter) {
		case LIBARCHIVE_FILTER_BZ:
			ret = archive_write_add_filter_bzip2(a);
		break;
		case LIBARCHIVE_FILTER_XZ:
			ret = archive_write_add_filter_xz(a);
		break;
		case LIBARCHIVE_FILTER_GZ:
		default:
			ret = archive_write_add_filter_gzip(a);
	}
	if (ret != ARCHIVE_OK) {
		printf("Failed to set archive compression filter: %s\n", archive_error_string(a));
		goto fail;
	}
	ret = archive_write_set_format_pax(a);
	if (ret != ARCHIVE_OK) {
		printf("Failed to set archive write format: %s\n", archive_error_string(a));
		goto fail;
	}
	ret = archive_write_open_filename(a, archivename);
	if (ret != ARCHIVE_OK) {
		printf("Failed to open file for writing(%s): %s\n", archivename,
			archive_error_string(a));
		goto fail;
	}

	ar = archive_read_disk_new();
	while (*contents) {
		entry = archive_entry_new();
		archive_entry_set_pathname(entry, *contents);
		// TODO: set uid/gid lookup appropriately to preserve numeric uid and gid
		ret = archive_read_disk_entry_from_file(ar, entry, -1, NULL);
		if (ret != ARCHIVE_OK) {
			printf("Failed to read entry info from file(%s): %s\n", *contents, archive_error_string(a));
			goto next;
		}

		ret = archive_write_header(a, entry);
		if (ret != ARCHIVE_OK) {
			printf("Failed to update archive: %s\n", archive_error_string(a));
			goto next;
		}
		fd = open(*contents, O_RDONLY);
		if (fd == -1) {
			printf("Failed to open %s for reading into archive\n", *contents);
			goto next;
		}
		len = read(fd, buff, sizeof(buff));
		while (len > 0) {
			archive_write_data(a, buff, len);
			len = read(fd, buff, sizeof(buff));
		}
		close(fd);
	next:
		archive_entry_clear(entry);
		contents++;
	}
	archive_read_close(ar);
	archive_read_free(ar);

fail:
	archive_write_close(a);
	archive_write_free(a);
error:
	err = chdir(cwd);
	if (err != 0) {
		printf("Failed to restore cwd to %s\n", cwd);
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
	char *const contents[] = { "delta", "staged", bundle_delta, mom_delta, NULL };
	return create_archive(packdir, packout, LIBARCHIVE_FILTER_XZ, contents);
}

int compress_sign_manifest (char *manifestdir, char *manifestout, char *manifestfile, char *signedout)
{
	char *const contents[] = { manifestfile, signedout, NULL };
	return create_archive(manifestdir, manifestout, LIBARCHIVE_FILTER_XZ, contents);
}

int compress_manifest (char *manifestdir, char *manifestout, char *manifestfile)
{
	char *const contents[] = { manifestfile, NULL };
	return create_archive(manifestdir, manifestout, LIBARCHIVE_FILTER_XZ, contents);
}

int compress_fullfile_dir (char *fullfiledir, char *fullfileout, char *fullfile)
{
	char *const contents[] = { fullfile, NULL };
	return create_archive(fullfiledir, fullfileout, LIBARCHIVE_FILTER_GZ,  contents);
}

int compress_fullfile_xz (char *fullfiledir, char *fullfileout, char *fullfile)
{
	char *const contents[] = { fullfile, NULL };
	return create_archive(fullfiledir, fullfileout, LIBARCHIVE_FILTER_XZ,  contents);
}

int compress_fullfile_gz (char *fullfiledir, char *fullfileout, char *fullfile)
{
	char *const contents[] = { fullfile, NULL };
	return create_archive(fullfiledir, fullfileout, LIBARCHIVE_FILTER_GZ,  contents);
}

int compress_fullfile_bz (char *fullfiledir, char *fullfileout, char *fullfile)
{
	char *const contents[] = { fullfile, NULL };
	return create_archive(fullfiledir, fullfileout, LIBARCHIVE_FILTER_BZ,  contents);
}

int copy_dir_with_attr (char *src, char *copydir, char *dest)
{
	char *tgt;
	int ret;
	struct stat sb;
	ssize_t buflen, keylen, vallen;
	char *buf, *key, *val;

	string_or_die(&tgt, "%s/%s", src, copydir);
	ret = stat(tgt, &sb);
	if (ret != 0) {
		printf("Error reading directory attributes from %s\n", tgt);
		goto error;
	}

	ret = mkdir(dest, sb.st_mode);
	if (ret != 0) {
		printf("Error making directory %s\n", dest);
		goto error;
	}
	ret = chown(dest, sb.st_uid, sb.st_gid);
	if (ret != 0) {
		printf("Error setting permissions of directory %s\n", dest);
		goto error;
	}

	// iterate the extended attributes on tgt and apply all those we can
	// read to dest
	buflen = listxattr(tgt, NULL, 0);
	if (buflen == -1) {
		printf("Error reading directory extended attributes from %s\n", tgt);
		goto error;
	}
	if (buflen != 0) {
		buf = malloc(buflen);
		if (buf == NULL) {
			printf("Failed to allocate memory!\n");
			goto error;
		}

		buflen = listxattr(tgt, buf, buflen);
		if (buflen == -1) {
			printf("Failed to list extended attributes of %s\n", tgt);
			free(buf);
			goto error;
		}

		key = buf;
		while (buflen > 0) {
			vallen = getxattr(tgt, key, NULL, 0);
			if (vallen == -1) {
				printf("Failed to read attribute %s of %s\n", key, tgt);
				goto next;
			}
			if (vallen > 0) {
				val = malloc(vallen + 1);
				if (val == NULL) {
					printf("Failed to allocate memory!\n");
					goto next;
				}
				vallen = getxattr(tgt, key, val, vallen);
				if (vallen == -1) {
					printf("Failed to get value of attribute %s of %s\n", key, tgt);
					goto next;
				}
				val[vallen] = 0;

				// have key:val -- set them
				ret = setxattr(dest, key, val, vallen, 0);
				if (ret == -1) {
					printf("Failed to set extended attribute (%s:%s) on %s\n", key, val, dest);
					goto next;
				}
			}

		next:
			keylen = strlen(key) + 1;
			buflen -= keylen;
			key += keylen;
		}
		free(buf);
	}

error:
	free(tgt);

	return ret;
}
