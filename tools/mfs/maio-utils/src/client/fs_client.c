// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2025 Huawei Technologies Co., Ltd
 */
#include "fs_client.h"
#include "mfs.h"
#include "inner.h"
#include "hashmap.h"
#include "hashfunc.h"
#include "stimer.h"
#include "atomic.h"
#include "log.h"
#include "list.h"
#include "spinlock.h"
#include "sysdef.h"
#include "securec.h"

#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define TIMER_CYCLE 10000  /* 10s */
#define FD_TMOUT 3600  /* 60s */

struct fs_client {
	int rootfd;
	hashmap_t *map;
	stimer_t *timer;
	list_head_t head;
	spinlock_t lock;
	uint64_t tmout;
};

struct fs_client g_client = {0};

typedef struct {
	uint32_t	plen;
	char		*path;
} fdkey_t;

typedef struct {
	fdkey_t		key;
	int		fd;
	int		ref;
	uint64_t	ts;
	list_head_t	link;
	hashlink_t	hash;
} fd_t;

static inline int fd_cmp(void *first, void *second)
{
	fdkey_t *key1 = (fdkey_t *)first;
	fdkey_t *key2 = (fdkey_t *)second;

	if (key1->plen != key2->plen)
		return -1;

	return strcmp(key1->path, key2->path);
}

static inline uint32_t fd_hash(void *args)
{
	fdkey_t *key = (fdkey_t *)args;
	uint64_t hash = hashstr(key->path, key->plen);

	return (uint32_t)hash;
}

static inline void fd_inc(void *args, hashlink_t *link)
{
	fd_t *f = container_of(link, fd_t, hash);
	int ref = atomic_s32_inc(&f->ref);
	if (ref <= 0) {
		log_error("fd(%d) for path(%s) with invalid ref(%d)",
			  f->fd, f->key.path, ref);
		sys_assert(0);
	}
}

static inline int fd_dec(void *args, hashlink_t *link)
{
	fd_t *f = container_of(link, fd_t, hash);
	int ref = atomic_s32_dec(&f->ref);

	if (ref < 0) {
		log_error("fd(%d) for path(%s) with invalid ref(%d)",
			  f->fd, f->key.path, ref);
		sys_assert(0);
	}
	/* update access timestamp for the last one */
	if (ref == 0)
		f->ts = _get_ts();
	return -1;
}

static inline int fd_expire(void *args, hashlink_t *link)
{
	fd_t *f = container_of(link, fd_t, hash);
	int ref = atomic_s32_fetch(&f->ref);
	uint64_t cur;

	if (ref > 0)
		return -1;
	if (ref < 0) {
		log_error("fd(%d) for path(%s) with invalid ref(%d)",
			  f->fd, f->key.path, ref);
		sys_assert(0);
	}
	cur = _get_ts();
	return ((cur - f->ts) >= g_client.tmout) ? 0 : -1;
}

static fd_t *fd_alloc(const char *path)
{
	fd_t *f = (fd_t *)malloc(sizeof(fd_t));
	if (!f) {
		log_error("alloc fd_t fail");
		return NULL;
	}

	f->key.path = strdup(path);
	if (!f->key.path) {
		log_error("strdup(%s) fail", path);
		free(f);
		return NULL;
	}

	f->key.plen = strlen(path) + 1;
	f->fd = -1;
	f->ref = 1;
	f->hash.key = &f->key;
	list_init(&f->link);
	return f;
}

static void fd_free(fd_t *f)
{
	if (f->fd > 0) {
		int ret = close(f->fd);
		if (ret != 0) {
			log_error("close(%d) fail, err(%s)", f->fd, strerror(errno));
		}
		f->fd = -1;
	}

	if (f->key.path) {
		free(f->key.path);
		f->key.path = NULL;
	}
	list_del(&f->link);
	free(f);
}

static int fd_fetch(const char *path, fd_t **f_res, int dirfd)
{
	fdkey_t key;
	key.plen = strlen(path) + 1;
	key.path = (char *)path;

	/* fd in cache */
	hashlink_t *data = NULL;
	if (EEXIST == hashmap_search(g_client.map, &key, &data, NULL, fd_inc)) {
		*f_res = container_of(data, fd_t, hash);
		(*f_res)->ts = _get_ts();
		return 0;
	}

	/* new fd */
	fd_t *f = fd_alloc(path);
	if (!f)
		return -ENOMEM;

	/* open file */
	if (dirfd > 0)
		f->fd = openat(dirfd, path, O_RDONLY, S_IRUSR | S_IRGRP);
	else
		f->fd = open(path, O_RDONLY, S_IRUSR | S_IRGRP);
	if (f->fd < 0) {
		if (errno != ENOENT)
			log_error("open(%d,%s) fail, err(%s)", dirfd, path, strerror(errno));
		fd_free(f);
		return errno;
	}

	/* add to fd cache */
	hashlink_t *old = NULL;
	if (EEXIST == hashmap_insert(g_client.map, &f->hash, &old, NULL, fd_inc)) {
		fd_free(f);
		f = container_of(old, fd_t, hash);
	}

	spinlock_lock(&g_client.lock);
	list_add_tail(&f->link, &g_client.head);
	spinlock_unlock(&g_client.lock);
	f->ts = _get_ts();
	*f_res = f;
	return 0;
}

static inline void fd_restore(fd_t *f)
{
	(void)hashmap_protect(g_client.map, &f->key, NULL, fd_dec);
}

static void _fd_gc(void *args)
{
	list_head_t head, *curr, *next;
	hashlink_t *data = NULL;

	list_init(&head);
	spinlock_lock(&g_client.lock);
	list_splice(&g_client.head, &head);
	spinlock_unlock(&g_client.lock);

	list_foreach_safe(curr, next, &head)
	{
		fd_t *f = container_of(curr, fd_t, link);
		if (atomic_s32_fetch(&f->ref) != 0)
			continue;
		/* try to destroy */
		if (0 != hashmap_delete(g_client.map, &f->key, &data, NULL, fd_expire))
			continue;
		list_del(&f->link);
		log_info("path:%s with fd:%d is expire.", f->key.path, f->fd);
		fd_free(f);
	}

	spinlock_lock(&g_client.lock);
	list_splice(&head, &g_client.head);
	spinlock_unlock(&g_client.lock);
}

int fs_evict_by_path(const char *path, uint64_t off, uint64_t len)
{
	int ret;
	fd_t *f;
	uint64_t step = 4096 * 4;

	ret = fd_fetch(path, &f, 0);
	if (ret)
		return ret;

	while (len) {
		if (step > len)
			step = len;
		ret = posix_fadvise(f->fd, off, len, POSIX_FADV_DONTNEED);
		if (ret < 0)
			break;
		len -= step;
		off += step;
	}

	fd_restore(f);
	return ret;
}

int fs_load_by_path(const char *path, uint64_t off, uint64_t len)
{
	int ret;
	fd_t *f;
	uint64_t step = 16 * 4096;
	char *buf = NULL;

	ret = fd_fetch(path, &f, 0);
	if (ret)
		return ret;

	buf = (char *)malloc(step);

	while (len) {
		if (step > len)
			step = len;
		ret = pread(f->fd, buf, step, off);
		if (ret <= 0)
			break;
		len -= step;
		off += step;
	}
	free(buf);
	fd_restore(f);
	return ret;
}

int fs_load_by_fd(int fd, uint64_t off, uint64_t len)
{
	struct mfs_ioc_ra ra;

	ra.off = off;
	ra.len = len;
	return ioctl(fd, MFS_IOC_RA, &ra);
}

int fs_sync_by_path(const char *path, void *buf, uint64_t off, uint64_t len)
{
	ssize_t rsize = 0, ret;
	uint64_t pos = 0;
	fd_t *f;

	ret = fd_fetch(path + 1, &f, g_client.rootfd);
	if (ret)
		return ret;

	do {
		ret = pread(f->fd, buf + pos, len - pos, off + pos);
		if (ret == 0)
			break;
		if (ret < 0) {
			log_error("failed to read:%s", strerror(errno));
			fd_restore(f);
			return -1;
		}
		pos += ret;
		rsize += ret;
	} while (rsize < len);
	fd_restore(f);
	return 0;
}

int fs_client_init(const char *source)
{
	int ret;

	g_client.rootfd = -1;
	if (source) {
		g_client.rootfd = open(source, O_RDONLY | O_DIRECTORY);
		if (g_client.rootfd <= 0) {
			log_error("open %s failed", source);
			return -1;
		}
	}
	ret = hashmap_create(1024, fd_cmp, fd_hash, &g_client.map);
	if (ret) {
		log_error("client fd map alloc failed");
		close(g_client.rootfd);
		return ret;
	}

	g_client.timer = stimer_create("LfsGc", TIMER_CYCLE, NULL, _fd_gc);
	if (!g_client.timer) {
		log_error("timer create failed");
		hashmap_destroy(g_client.map, NULL, NULL);
		close(g_client.rootfd);
		return -1;
	}
	list_init(&g_client.head);
	spinlock_init(&g_client.lock);
	g_client.tmout = FD_TMOUT;
	return 0;
}

void fs_client_exit(void)
{
	spinlock_destroy(&g_client.lock);
	stimer_destroy(g_client.timer);
	hashmap_destroy(g_client.map, NULL, NULL);
	close(g_client.rootfd);
}

