/*
 * Copyright (c) 2025 Ryan Moeller
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */ 

#include <sys/param.h>
#include <sys/disk.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <assert.h>
#include <fcntl.h>
#include <paths.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <geom/geom_disk.h>

#define NBDKIT_API_VERSION 2
#include <nbdkit-plugin.h>

#if NBDKIT_VERSION_MAJOR > 1 || (NBDKIT_VERSION_MAJOR == 1 && NBDKIT_VERSION_MINOR > 29)
#include <sys/sysctl.h>
#define WITH_BLOCK_SIZE
#endif

#define THREAD_MODEL NBDKIT_THREAD_MODEL_PARALLEL

#define disk_magic_config_key "dev"

/* TODO: serve all devices in a directory, like /dev/zvol/pool/vols/ */
#define disk_config_help \
    "[dev=]<FILENAME>	The device file to serve"

static char *filename;

static int
disk_config(const char *key, const char *value)
{
	if (strcmp(key, "dev") == 0) {
		assert(filename == NULL);
		filename = nbdkit_realpath(value);
		if (filename == NULL) {
			char devpath[PATH_MAX];
			int rv;

			rv = snprintf(devpath, sizeof(devpath), "%s%s",
			    _PATH_DEV, value);
			if (rv == -1 || rv >= sizeof(devpath))
				return -1;
			filename = nbdkit_realpath(devpath);
			if (filename == NULL)
				return -1;
		}
	} else {
		nbdkit_error("unknown parameter '%s'", key);
		return -1;
	}
	return 0;
}

static int
disk_config_complete(void)
{
	struct stat sb;

	if (filename == NULL) {
		nbdkit_error("you must supply [dev=]<FILENAME> parameter after "
		    "the plugin name on the command line");
		return -1;
	}
	if (stat(filename, &sb) == -1) {
		nbdkit_error("stat failed: %s", filename);
		return -1;
	}
	if (!S_ISCHR(sb.st_mode)) {
		nbdkit_error("dev is not character device: %s", filename);
		return -1;
	}
	return 0;
}

struct handle {
	int fd;
	bool readonly;
};

static void *
disk_open(int readonly)
{
	struct handle *h;
	int flags;

	h = malloc(sizeof(*h));
	if (h == NULL) {
		nbdkit_error("malloc: %m");
		return NULL;
	}
	h->readonly = !!readonly;

	flags = O_CLOEXEC | O_DIRECT;
	if (readonly)
		flags |= O_RDONLY;
	else
	 	flags |= O_RDWR;
	h->fd = open(filename, flags);
	if (h->fd == -1 && !readonly) {
		nbdkit_debug("open O_RDWR failed, falling back to read-only: "
		    "%s: %m", filename);
		h->readonly = true;
		flags = (flags & ~O_ACCMODE) | O_RDONLY;
		h->fd = open(filename, flags);
	}
	if (h->fd == -1) {
		nbdkit_error("open: %s: %m", filename);
		free(h);
		return NULL;
	}
	return h;
}

static void
disk_close(void *handle)
{
	struct handle *h = handle;

	close(h->fd);
	free(h);
}

static int
disk_can_write(void *handle)
{
	struct handle *h = handle;

	return !h->readonly;
}

static int
disk_can_multi_conn(void *handle __unused)
{
	return true;
}

static int
disk_can_trim(void *handle)
{
	struct diocgattr_arg arg;
	struct handle *h = handle;

	strlcpy(arg.name, "GEOM::candelete", sizeof(arg.name));
	arg.len = sizeof(arg.value.i);
	if (ioctl(h->fd, DIOCGATTR, &arg) == -1)
		return false;
	return arg.value.i != 0;
}

static int
disk_can_fua(void *handle __unused)
{
	return NBDKIT_FUA_NATIVE;
}

static int64_t
disk_get_size(void *handle)
{
	struct handle *h = handle;
	off_t mediasize;

	if (ioctl(h->fd, DIOCGMEDIASIZE, &mediasize) == -1) {
		nbdkit_error("ioctl: DIOCGMEDIASIZE failed, probably not a "
		    "disk: %s: %m", filename);
		return -1;
	}
	return mediasize;
}

static int
disk_is_rotational(void *handle)
{
	struct diocgattr_arg arg;
	struct handle *h = handle;

	strlcpy(arg.name, "GEOM::rotation_rate", sizeof(arg.name));
	arg.len = sizeof(arg.value.u16);

	if (ioctl(h->fd, DIOCGATTR, &arg) == -1) {
		nbdkit_debug("ioctl: DIOCGATTR failed for GEOM::rotation_rate: "
		    "%s: %m", filename);
		return 0;
	}
	if (arg.value.u16 == DISK_RR_UNKNOWN ||
	    arg.value.u16 == DISK_RR_NON_ROTATING)
		return 0;
	if (arg.value.u16 >= DISK_RR_MIN && arg.value.u16 <= DISK_RR_MAX)
		return arg.value.u16;
	nbdkit_debug("%s: Invalid GEOM::rotation_rate, falling back to 0",
	    filename);
	return 0;
}

#ifdef WITH_BLOCK_SIZE
static int
disk_block_size(void *handle, uint32_t *minimum, uint32_t *preferred,
    uint32_t *maximum)
{
	const int mib[] = { CTL_KERN, KERN_MAXPHYS };
	struct handle *h = handle;
	size_t len;
	off_t stripesize;
	u_long maxphys;
	u_int sectorsize;

	if (ioctl(h->fd, DIOCGSECTORSIZE, &sectorsize) == -1) {
		nbdkit_error("ioctl: DIOCGSECTORSIZE failed, probably not a "
		    "disk: %s: %m", filename);
		return -1;
	}
	*minimum = MAX(512, sectorsize);
	if (ioctl(h->fd, DIOCGSTRIPESIZE, &stripesize) == -1) {
		nbdkit_error("ioctl: DIOCGSTRIPESIZE failed, probably not a "
		    "disk: %s: %m", filename);
		return -1;
	}
	if (stripesize == 0) {
		stripesize = MAX(4096, sectorsize);
		nbdkit_debug("stripesize = 0, falling back to %jd", stripesize);
	}
	*preferred = MAX(*minimum, stripesize);
	len = sizeof(maxphys);
	if (sysctl(mib, sizeof(mib), &maxphys, &len, NULL, 0) == -1) {
		nbdkit_error("sysctl: failed to get kern.maxphys: %m");
		return -1;
	}
	*maximum = maxphys;
	return 0;
}
#endif

static int
disk_flush(void *handle, uint32_t flags __unused)
{
	struct handle *h = handle;

	if (fdatasync(h->fd) == -1) {
		nbdkit_error("fdatasync: %m");
		return -1;
	}
	return 0;
}

static int
disk_pread(void *handle, void *buf, uint32_t len, uint64_t offset,
    uint32_t flags __unused)
{
	struct handle *h = handle;

	while (len > 0) {
		/* XXX: Assume devfs_iosize_max_clamp is enabled (default). */
		ssize_t rv = pread(h->fd, buf, MIN(INT_MAX, len), offset);
		if (rv == -1) {
			nbdkit_error("pread: %m");
			return -1;
		}
		buf += rv;
		len -= rv;
		offset += rv;
	}
	return 0;
}

static int
disk_pwrite(void *handle, const void *buf, uint32_t len, uint64_t offset,
    uint32_t flags)
{
	struct handle *h = handle;

	while (len > 0) {
		/* XXX: Assume devfs_iosize_max_clamp is enabled (default). */
		ssize_t rv = pwrite(h->fd, buf, MIN(INT_MAX, len), offset);
		if (rv == -1) {
			nbdkit_error("pwrite: %m");
			return -1;
		}
		buf += rv;
		len -= rv;
		offset += rv;
	}
	if ((flags & NBDKIT_FLAG_FUA) != 0 && disk_flush(h, 0) == -1)
		return -1;
	return 0;
}

static int
disk_trim(void *handle, uint32_t len, uint64_t offset, uint32_t flags)
{
	struct handle *h = handle;
	off_t arg[2];

	arg[0] = offset;
	arg[1] = len;
	if (ioctl(h->fd, DIOCGDELETE, arg) == -1) {
		nbdkit_error("ioctl: DIOCGDELETE failed: %s: %m", filename);
		return -1;
	}
	if ((flags & NBDKIT_FLAG_FUA) != 0 && disk_flush(h, 0) == -1)
		return -1;
	return 0;
}

static struct nbdkit_plugin plugin = {
	.name = "disk",
	.longname = "nbdkit FreeBSD disk device plugin",
	.magic_config_key = disk_magic_config_key,
	.config_help = disk_config_help,
	.config = disk_config,
	.open = disk_open,
	.close = disk_close,
	.can_write = disk_can_write,
	.can_multi_conn = disk_can_multi_conn,
	.can_trim = disk_can_trim,
	.get_size = disk_get_size,
	.is_rotational = disk_is_rotational,
#ifdef WITH_BLOCK_SIZE
	.block_size = disk_block_size,
#endif
	.pread = disk_pread,
	.pwrite = disk_pwrite,
	.flush = disk_flush,
	.trim = disk_trim,
	.errno_is_preserved = 1,
};

NBDKIT_REGISTER_PLUGIN(plugin)
