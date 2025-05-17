/*
 * Copyright (c) 2025 Ryan Moeller
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/cnv.h>
#include <sys/disk.h>
#include <sys/dnv.h>
#include <sys/ioctl.h>
#include <sys/nv.h>
#include <sys/stat.h>
#include <assert.h>
#include <fcntl.h>
#include <paths.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>
#include <unistd.h>

#include <geom/geom_disk.h>

#define NBDKIT_API_VERSION 2
#include <nbdkit-plugin.h>

#if NBDKIT_VERSION_MAJOR > 1 || (NBDKIT_VERSION_MAJOR == 1 && NBDKIT_VERSION_MINOR > 29)
#include <sys/sysctl.h>
#define WITH_BLOCK_SIZE
#endif

static void *config_routine(void *);

#define THREAD_MODEL NBDKIT_THREAD_MODEL_PARALLEL

#define disks_magic_config_key "config"

#define disks_config_help \
    "[config=]<FILENAME>	The config file to use"

static const char *filename;			/* config file path */
static nvlist_t *current_config;		/* export => props dict */
static pthread_rwlock_t config_lock;		/* protects current_config */
static pthread_cond_t config_cond;		/* signal to reload config */
static bool exiting;				/* breaks config reload loop */
static pthread_mutex_t config_cond_lock;	/* protects config_cond */
static pthread_t config_thread;			/* reloads config on signal */

static void
sigusr1_handler(int signal __unused)
{
	int error;

	/*
	 * XXX: Not sure it's safe to reload config in async signal handler, so
	 * signal a thread to do it outside of the handler.
	 */
	error = pthread_cond_signal(&config_cond);
	assert(error == 0);
}

static void
disks_load(void)
{
	struct sigaction sa;
	int error;

	error = pthread_rwlock_init(&config_lock, NULL);
	assert(error == 0);
	error = pthread_cond_init(&config_cond, NULL);
	assert(error == 0);
	error = pthread_mutex_init(&config_cond_lock, NULL);
	assert(error == 0);
	error = pthread_create(&config_thread, NULL, config_routine, NULL);
	assert(error == 0);
	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = sigusr1_handler;
	error = sigaction(SIGUSR1, &sa, NULL);
	assert(error == 0);
}

static void
disks_unload(void)
{
	struct sigaction sa;
	int error;

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = SIG_DFL;
	error = sigaction(SIGUSR1, &sa, NULL);
	assert(error == 0);
	error = pthread_mutex_lock(&config_cond_lock);
	assert(error == 0);
	exiting = true;
	error = pthread_mutex_unlock(&config_cond_lock);
	assert(error == 0);
	error = pthread_cond_signal(&config_cond);
	assert(error == 0);
	error = pthread_join(config_thread, NULL);
	assert(error == 0);
	free(__DECONST(char *, filename));
	nvlist_destroy(current_config);
	error = pthread_cond_destroy(&config_cond);
	assert(error == 0);
	error = pthread_mutex_destroy(&config_cond_lock);
	assert(error == 0);
	error = pthread_rwlock_destroy(&config_lock);
	assert(error == 0);
}

typedef int (*prop_handler_t)(const ucl_object_t *, nvlist_t *);

static int
env_prop(const ucl_object_t *obj, nvlist_t *props)
{
	ucl_object_iter_t it;
	const ucl_object_t *value;
	const char *key, *val;
	nvlist_t *env;

	env = nvlist_create(0);
	if (env == NULL) {
		nbdkit_debug("could not allocate env nvlist");
		return -1;
	}
	it = NULL;
	while ((value = ucl_object_iterate(obj, &it, true)) != NULL) {
		key = ucl_object_key(value);
		val = ucl_object_tostring_forced(value);
		if (val == NULL) {
			nvlist_destroy(env);
			nbdkit_debug("could not force environment variable "
			    "'%s' value to a string", key);
			return -1;
		}
		nvlist_add_string(env, key, val);
	}
	nvlist_move_nvlist(props, "env", env);
	return 0;
}

static int
string_prop(const ucl_object_t *obj, nvlist_t *props)
{
	const char *key, *value;

	key = ucl_object_key(obj);
	value = ucl_object_tostring(obj);
	nvlist_add_string(props, key, value);
	return 0;
}

static int
parse_export_object(const ucl_object_t *obj, nvlist_t *props)
{
	const struct { const char *key; prop_handler_t handler; } handlers[] = {
		{ "env", env_prop },
		{ "path", string_prop },
		{ "list", string_prop },
		{ "open", string_prop },
		{ "close", string_prop },
		{ "description", string_prop },
	};
	ucl_object_iter_t it;
	const ucl_object_t *value;
	const char *key;
	bool handled;

	it = NULL;
	while ((value = ucl_object_iterate(obj, &it, true)) != NULL) {
		key = ucl_object_key(value);
		if (key == NULL) {
			nbdkit_debug("could not get key of an export property");
			return -1;
		}
		handled = false;
		for (int i = 0; i < nitems(handlers); i++) {
			if (strcmp(handlers[i].key, key) == 0) {
				if (handlers[i].handler(value, props) != 0) {
					nbdkit_debug("handler for property "
					    "'%s' failed", key);
					return -1;
				}
				handled = true;
				break;
			}
		}
		if (!handled) {
			nbdkit_debug("unknown property '%s'", key);
			return -1;
		}
	}
	/* TODO: properly validate required properties are present */
	if (nvlist_empty(props)) {
		nbdkit_debug("empty export object is invalid");
		return -1;
	}
	return 0;
}

static int
parse_export(const ucl_object_t *obj, nvlist_t *config)
{
	const char *name;
	nvlist_t *props;
	int error;

	props = nvlist_create(0);
	if (props == NULL) {
		nbdkit_error("could not allocate props nvlist");
		return -1;
	}
	name = ucl_object_key(obj);
	if (name == NULL) {
		nbdkit_error("invalid object in config");
		return -1;
	}
	switch (ucl_object_type(obj)) {
	case UCL_OBJECT:
		error = parse_export_object(obj, props);
		if (error != 0) {
			nvlist_destroy(props);
			nbdkit_error("invalid object '%s' in config", name);
			return error;
		}
		break;
	case UCL_STRING:
		nvlist_add_string(props, "path", ucl_object_tostring(obj));
		break;
	default:
		nvlist_destroy(props);
		nbdkit_error("invalid object '%s' in config", name);
		return -1;
	}
	nvlist_move_nvlist(config, name, props);
	return 0;
}

static nvlist_t *
parse_config(void)
{
	ucl_object_iter_t it;
	struct ucl_parser *parser;
	const ucl_object_t *obj;
	ucl_object_t *top;
	nvlist_t *config;
	const char *errmsg;
	int error;

	parser = ucl_parser_new(0);
	if (parser == NULL) {
		nbdkit_error("could not allocate config parser");
		return NULL;
	}
	/* TODO: filename "-" to read from stdin? */
	if (!ucl_parser_add_file(parser, filename)) {
		ucl_parser_free(parser);
		nbdkit_error("could not read '%s'", filename);
		return NULL;
	}
	errmsg = ucl_parser_get_error(parser);
	if (errmsg != NULL) {
		ucl_parser_free(parser);
		nbdkit_error("could not parse '%s': %s", filename, errmsg);
		return NULL;
	}
	config = nvlist_create(0);
	if (config == NULL) {
		ucl_parser_free(parser);
		nbdkit_error("could not allocate config nvlist");
		return NULL;
	}
	top = ucl_parser_get_object(parser);
	it = NULL;
	error = EINVAL;
	while ((obj = ucl_object_iterate(top, &it, true)) != NULL) {
		error = parse_export(obj, config);
		if (error != 0) {
			nvlist_destroy(config);
			config = NULL;
			break;
		}
	}
	ucl_object_unref(top);
	ucl_parser_free(parser);
	return config;
}

static void *
config_routine(void *arg)
{
	nvlist_t *config, *old_config;
	int error;

	error = pthread_mutex_lock(&config_cond_lock);
	assert(error == 0);
	for (;;) {
		error = pthread_cond_wait(&config_cond, &config_cond_lock);
		assert(error == 0);
		if (exiting) {
			nbdkit_debug("config thread exiting");
			break;
		}
		nbdkit_debug("reloading config");
		config = parse_config();
		if (config == NULL) {
			nbdkit_debug("failed to parse config");
			continue;
		}
		error = pthread_rwlock_wrlock(&config_lock);
		assert(error == 0);
		old_config = current_config;
		current_config = config;
		error = pthread_rwlock_unlock(&config_lock);
		assert(error == 0);
		nvlist_destroy(old_config);
	}
	error = pthread_mutex_unlock(&config_cond_lock);
	assert(error == 0);
	return NULL;
}

static int
disks_config(const char *key, const char *value)
{
	if (strcmp(key, "config") == 0) {
		if (filename != NULL) {
			nbdkit_error("duplicate 'config' parameter");
			return -1;
		}
		filename = strdup(value);
		current_config = parse_config();
		if (current_config == NULL) {
			/* nbdkit_error() already called by parse_config() */
			return -1;
		}
		return 0;
	}
	nbdkit_error("unknown parameter '%s'", key);
	return -1;
}

static int
disks_config_complete(void)
{
	if (current_config == NULL) {
		nbdkit_error("you must supply [config=]<FILENAME> parameter "
		    "after the plugin name on the command line");
		return -1;
	}
	return 0;
}

static void
apply_env(const nvlist_t *props)
{
	const nvlist_t *env;

	env = dnvlist_get_nvlist(props, "env", NULL);
	/* FIXME: don't modify current environment */
	if (env != NULL) {
		const char *var, *val;
		void *cookie;
		int type, error;

		cookie = NULL;
		while ((var = nvlist_next(env, &type, &cookie)) != NULL) {
			assert(type == NV_TYPE_STRING);
			val = cnvlist_get_string(cookie);
			/* XXX */
			error = setenv(var, val, 1);
			assert(error == 0);
		}
	}
}

static int
disks_list_exports(int readonly, int is_tls, struct nbdkit_exports *exports)
{
	/* XXX: NBD_MAX_STRING not exposed */
#define NBD_MAX_STRING 4096
	char buf[NBD_MAX_STRING + 1];
	const char *name, *desc, *cmd, *prop;
	const nvlist_t *props;
	void *cookie;
	char *p, *p1;
	FILE *fp;
	size_t len;
	int type, error, res;

	error = pthread_rwlock_rdlock(&config_lock);
	assert(error == 0);
	res = 0;
	cookie = NULL;
	while ((name = nvlist_next(current_config, &type, &cookie)) != NULL) {
		assert(type == NV_TYPE_NVLIST);
		props = cnvlist_get_nvlist(cookie);
		cmd = dnvlist_get_string(props, "list", NULL);
		if (cmd == NULL) {
			desc = dnvlist_get_string(props, "description", NULL);
			error = nbdkit_add_export(exports, name, desc);
			assert(error == 0);
			continue;
		}
		apply_env(props);
		fp = popen(cmd, "r+e");
		if (fp == NULL) {
			nbdkit_error("list command '%s' failed", cmd);
			res = -1;
			break;
		}
		error = fprintf(fp, "%s\n", name);
		if (error < 0) {
			nbdkit_error("list command '%s' failed", cmd);
			error = pclose(fp);
			assert(error != -1);
			res = -1;
			break;
		}
		/* XXX: splitting on newline is overly restrictive, but easy */
		while ((p = fgetln(fp, &len)) != NULL) {
			name = p;
			p1 = memchr(p, '\t', len);
			if (p1 == NULL) {
				desc = NULL;
			} else {
				*p1++ = '\0';
				desc = p1;
			}
			if (p[len - 1] == '\n') {
				p[len - 1] = '\0';
			} else {
				/*
				 * The end of the string is not a newline and
				 * we can't write past the end of the string,
				 * so we have to make a copy to terminate it.
				 * Which string do we need to terminate?
				 */
				if (desc == NULL) {
					prop = "name";
					name = buf;
				} else {
					p = p1;
					len = len - (desc - name);
					prop = "description";
					desc = buf;
				}
				if (len > NBD_MAX_STRING) {
					nbdkit_error("list command '%s' "
					    "produced invalid %s", cmd, prop);
					res = -1;
					break;
				}
				memcpy(buf, p, len);
				buf[len] = '\0';
			}
			error = nbdkit_add_export(exports, name, desc);
			if (error != 0) {
				res = -1;
				break;
			}
		}
		error = pclose(fp);
		assert(error != -1);
		if (res == -1) {
			break;
		}
	}
	error = pthread_rwlock_unlock(&config_lock);
	assert(error == 0);
	return res;
}

static void *
disks_open(int readonly)
{
	char buf[PATH_MAX];
	const char *name, *key, *cmd, *path;
	const nvlist_t *default_props, *export_props, *env;
	nvlist_t *h, *props;
	FILE *fp;
	size_t len;
	int type, flags, fd, error;

	name = nbdkit_export_name();
	if (name == NULL) {
		return NULL;
	}
	if (strcmp(name, "") == 0) {
		name = "default"; /* XXX: is this reasonable? */
	}
	/* TODO: pattern/prefix matching? */

	error = pthread_rwlock_rdlock(&config_lock);
	default_props = dnvlist_get_nvlist(current_config, "default", NULL);
	export_props = dnvlist_get_nvlist(current_config, name, default_props);
	props = export_props == NULL ? NULL : nvlist_clone(export_props);
	/* TODO: fill in missing fields with default props? */
	pthread_rwlock_unlock(&config_lock);
	if (props == NULL) {
		return NULL;
	}
	cmd = dnvlist_get_string(props, "open", NULL);
	if (cmd != NULL) {
		apply_env(props);
		fp = popen(cmd, "r+e");
		if (fp == NULL) {
			nbdkit_error("open command '%s' failed", cmd);
			nvlist_destroy(props);
			return NULL;
		}
		error = fprintf(fp, "%s\n", name);
		if (error < 0) {
			nbdkit_error("open command '%s' failed", cmd);
			error = pclose(fp);
			assert(error != -1);
			nvlist_destroy(props);
			return NULL;
		}
		path = fgetln(fp, &len);
		if (path != NULL && len <= PATH_MAX) {
			memcpy(buf, path, len);
			if (buf[len - 1] == '\n') {
				buf[len - 1] = '\0';
			} else {
				buf[len] = '\0';
			}
			path = buf;
		} else {
			path = NULL;
		}
		error = pclose(fp);
		assert(error != -1);
		if (path != NULL) {
			if (nvlist_exists_string(props, "path")) {
				nvlist_free_string(props, "path");
			}
			nvlist_add_string(props, "path", path);
		}
	} else {
		path = dnvlist_get_string(props, "path", NULL);
	}
	if (path == NULL) {
		nbdkit_error("could not determine path for export '%s'", name);
		nvlist_destroy(props);
		return NULL;
	}

	flags = O_CLOEXEC | O_DIRECT;
	if (readonly) {
		flags |= O_RDONLY;
	} else {
		flags |= O_RDWR;
	}
	fd = open(path, flags);
	if (fd == -1 && !readonly) {
		nbdkit_debug("open O_RDWR failed, falling back to read-only: "
		    "%s: %m", path);
		readonly = true;
		flags = (flags & ~O_ACCMODE) | O_RDONLY;
		fd = open(path, flags);
	}
	if (fd == -1) {
		nbdkit_error("open: %s: %m", path);
		nvlist_destroy(props);
		return NULL;
	}
	nvlist_add_bool(props, "readonly", readonly);
	nvlist_move_descriptor(props, "fd", fd);
	return props;
}

static void
disks_close(void *handle)
{
	nvlist_t *props = handle;
	const char *cmd, *name, *path;
	FILE *fp;
	int error;

	/* Close the descriptor *before* the hook runs. */
	nvlist_free_descriptor(props, "fd");
	cmd = dnvlist_get_string(props, "close", NULL);
	if (cmd != NULL) {
		name = nbdkit_export_name();
		assert(name != NULL);
		path = nvlist_get_string(props, "path");
		apply_env(props);
		fp = popen(cmd, "r+e");
		if (fp == NULL) {
			nbdkit_error("close command '%s' failed", cmd);
		} else if (fprintf(fp, "%s\n%s\n", name, path) < 0) {
			nbdkit_error("close command '%s' failed", cmd);
		}
		error = pclose(fp);
		assert(error != -1);
	}
	nvlist_destroy(props);
}

static int
disks_can_write(void *handle)
{
	nvlist_t *props = handle;

	return !nvlist_get_bool(props, "readonly");
}

static int
disks_can_multi_conn(void *handle __unused)
{
	return true;
}

static int
disks_can_trim(void *handle)
{
	struct diocgattr_arg arg;
	nvlist_t *props = handle;

	strlcpy(arg.name, "GEOM::candelete", sizeof(arg.name));
	arg.len = sizeof(arg.value.i);
	if (ioctl(nvlist_get_descriptor(props, "fd"), DIOCGATTR, &arg) == -1) {
		return false;
	}
	return arg.value.i != 0;
}

static int
disks_can_fua(void *handle __unused)
{
	return NBDKIT_FUA_NATIVE;
}

static int64_t
disks_get_size(void *handle)
{
	nvlist_t *props = handle;
	off_t mediasize;

	if (ioctl(nvlist_get_descriptor(props, "fd"), DIOCGMEDIASIZE,
	    &mediasize) == -1) {
		nbdkit_error("ioctl: DIOCGMEDIASIZE failed, probably not a "
		    "disk: %s: %m", nvlist_get_string(props, "path"));
		return -1;
	}
	return mediasize;
}

static int
disks_is_rotational(void *handle)
{
	struct diocgattr_arg arg;
	nvlist_t *props = handle;

	strlcpy(arg.name, "GEOM::rotation_rate", sizeof(arg.name));
	arg.len = sizeof(arg.value.u16);

	if (ioctl(nvlist_get_descriptor(props, "fd"), DIOCGATTR, &arg) == -1) {
		nbdkit_debug("ioctl: DIOCGATTR failed for GEOM::rotation_rate: "
		    "%s: %m", nvlist_get_string(props, "path"));
		return 0;
	}
	if (arg.value.u16 == DISK_RR_UNKNOWN ||
	    arg.value.u16 == DISK_RR_NON_ROTATING) {
		return 0;
	}
	if (arg.value.u16 >= DISK_RR_MIN && arg.value.u16 <= DISK_RR_MAX) {
		return arg.value.u16;
	}
	nbdkit_debug("%s: Invalid GEOM::rotation_rate, falling back to 0",
	    nvlist_get_string(props, "path"));
	return 0;
}

#ifdef WITH_BLOCK_SIZE
static int
disks_block_size(void *handle, uint32_t *minimum, uint32_t *preferred,
    uint32_t *maximum)
{
	const int mib[] = { CTL_KERN, KERN_MAXPHYS };
	nvlist_t *props = handle;
	size_t len;
	off_t stripesize;
	u_long maxphys;
	u_int sectorsize;
	int fd;

	fd = nvlist_get_descriptor(props, "fd");
	if (ioctl(fd, DIOCGSECTORSIZE, &sectorsize) == -1) {
		nbdkit_error("ioctl: DIOCGSECTORSIZE failed, probably not a "
		    "disk: %s: %m", nvlist_get_string(props, "path"));
		return -1;
	}
	*minimum = MAX(512, sectorsize);
	if (ioctl(fd, DIOCGSTRIPESIZE, &stripesize) == -1) {
		nbdkit_error("ioctl: DIOCGSTRIPESIZE failed, probably not a "
		    "disk: %s: %m", nvlist_get_string(props, "path"));
		return -1;
	}
	if (stripesize == 0) {
		stripesize = MAX(4096, sectorsize);
		nbdkit_debug("stripesize = 0, falling back to %jd", stripesize);
	}
	*preferred = MAX(*minimum, stripesize);
	len = sizeof(maxphys);
	if (sysctl(mib, nitems(mib), &maxphys, &len, NULL, 0) == -1) {
		nbdkit_error("sysctl: failed to get kern.maxphys: %m");
		return -1;
	}
	*maximum = maxphys;
	return 0;
}
#endif

static int
disks_flush(void *handle, uint32_t flags __unused)
{
	nvlist_t *props = handle;

	if (ioctl(nvlist_get_descriptor(props, "fd"), DIOCGFLUSH) == -1) {
		nbdkit_error("ioctl: DIOCGFLUSH failed: %m");
		return -1;
	}
	return 0;
}

static int
disks_pread(void *handle, void *buf, uint32_t len, uint64_t offset,
    uint32_t flags __unused)
{
	nvlist_t *props = handle;
	int fd;

	fd = nvlist_get_descriptor(props, "fd");
	while (len > 0) {
		/* XXX: Assume devfs_iosize_max_clamp is enabled (default). */
		ssize_t rv = pread(fd, buf, MIN(INT_MAX, len), offset);
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
disks_pwrite(void *handle, const void *buf, uint32_t len, uint64_t offset,
    uint32_t flags)
{
	nvlist_t *props = handle;
	int fd;

	fd = nvlist_get_descriptor(props, "fd");
	while (len > 0) {
		/* XXX: Assume devfs_iosize_max_clamp is enabled (default). */
		ssize_t rv = pwrite(fd, buf, MIN(INT_MAX, len), offset);
		if (rv == -1) {
			nbdkit_error("pwrite: %m");
			return -1;
		}
		buf += rv;
		len -= rv;
		offset += rv;
	}
	if ((flags & NBDKIT_FLAG_FUA) != 0 && fdatasync(fd) == -1) {
		nbdkit_error("fdatasync failed: %m");
		return -1;
	}
	return 0;
}

static int
disks_trim(void *handle, uint32_t len, uint64_t offset, uint32_t flags)
{
	nvlist_t *props = handle;
	off_t arg[2];
	int fd;

	fd = nvlist_get_descriptor(props, "fd");
	arg[0] = offset;
	arg[1] = len;
	if (ioctl(fd, DIOCGDELETE, arg) == -1) {
		nbdkit_error("ioctl: DIOCGDELETE failed: %s: %m",
		    nvlist_get_string(props, "path"));
		return -1;
	}
	if ((flags & NBDKIT_FLAG_FUA) != 0 && fdatasync(fd) == -1) {
		nbdkit_error("fdatasync failed: %m");
		return -1;
	}
	return 0;
}

static struct nbdkit_plugin plugin = {
	.name = "disks",
	.longname = "nbdkit FreeBSD disk devices configurable plugin",
	.load = disks_load,
	.unload = disks_unload,
	.magic_config_key = disks_magic_config_key,
	.config_help = disks_config_help,
	.config = disks_config,
	.config_complete = disks_config_complete,
	.list_exports = disks_list_exports,
	.open = disks_open,
	.close = disks_close,
	.can_write = disks_can_write,
	.can_multi_conn = disks_can_multi_conn,
	.can_trim = disks_can_trim,
	.get_size = disks_get_size,
	.is_rotational = disks_is_rotational,
#ifdef WITH_BLOCK_SIZE
	.block_size = disks_block_size,
#endif
	.pread = disks_pread,
	.pwrite = disks_pwrite,
	.flush = disks_flush,
	.trim = disks_trim,
	.errno_is_preserved = 1,
};

NBDKIT_REGISTER_PLUGIN(plugin)
