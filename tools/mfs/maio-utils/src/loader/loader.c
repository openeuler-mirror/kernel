// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2025 Huawei Technologies Co., Ltd
 */
#include "loader.h"

#include "fs_client.h"
#include "threadpool.h"
#include "log.h"
#include "atomic.h"
#include "inner.h"
#include "sysdef.h"

#include "securec.h"
#include "numa.h"
#include <errno.h>

struct loader_mgr {
	int numa_num;
	threadpool_t **numa_thp;
	uint64_t curseq;
};

struct loader_mgr g_local_mgr;

static threadpool_t *choose_worker_pool(struct io_context *ioctx)
{
	static uint64_t cid;
	int nid;

	if (ioctx->numaid == (uint16_t)-1)
		nid = cid++ % g_local_mgr.numa_num;
	else
		nid = ioctx->numaid % g_local_mgr.numa_num;
	return g_local_mgr.numa_thp[nid];
}

static void handle_io(void *args)
{
	struct io_context *ioctx = (struct io_context *)args;
	int ret;

	if (g_local_mgr.curseq > ioctx->seq) {
		if (ioctx->end_io)
			ioctx->end_io(0, ioctx->private);
		return;
	}
	ret = ioctx->path ? fs_load_by_path(ioctx->path, ioctx->off, ioctx->len)
			: fs_load_by_fd(ioctx->fd, ioctx->off, ioctx->len);
	if (ioctx->end_io)
		ioctx->end_io(ret, ioctx->private);
}

int loader_io_submit(struct io_context *ioctx)
{
	threadpool_t *worker_pools = choose_worker_pool(ioctx);

	threadpool_submit(worker_pools, ioctx, handle_io);
	return 0;
}

void loader_update_curseq(uint64_t seq)
{
	uint64_t curseq = atomic_u64_fetch(&g_local_mgr.curseq);
	uint64_t old;

	while (seq > curseq) {
		if (atomic_u64_cas(&g_local_mgr.curseq, curseq, seq, &old))
			break;
		curseq = old;
	}
}

static void handle_evict(void *args)
{
	struct io_context *ioctx = (struct io_context *)args;
	int ret;

	ret = ioctx->path ? fs_evict_by_path(ioctx->path, ioctx->off, ioctx->len) : 0;
	if (ioctx->end_io)
		ioctx->end_io(ret, ioctx->private);
}

int loader_evict_submit(struct io_context *ioctx)
{
	threadpool_t *worker_pools = choose_worker_pool(ioctx);

	threadpool_submit(worker_pools, ioctx, handle_evict);
	return 0;
}

static void _free_loader(void)
{
	int i;

	if (!g_local_mgr.numa_thp)
		return;

	for (i = 0; i < g_local_mgr.numa_num; i++)
		threadpool_destroy(g_local_mgr.numa_thp[i]);
	free(g_local_mgr.numa_thp);
	g_local_mgr.numa_thp = NULL;
}

int loader_init(void)
{
	int i, ret, wnum = 8;
	char name[THD_NAME + 1] = {0};

	if (numa_available() < 0) {
		log_error("Current system does not support NUAM api");
		return -1;
	}

	g_local_mgr.numa_num = numa_max_node() + 1;
	g_local_mgr.curseq = 0;
	ret = 0;
	do {
		g_local_mgr.numa_thp =
			calloc(g_local_mgr.numa_num, sizeof(threadpool_t *));
		if (!g_local_mgr.numa_thp) {
			log_error("alloc for numa threadpool failed");
			ret = -1;
			break;
		}
		for (i = 0; i < g_local_mgr.numa_num; i++) {
			sprintf_s(name, sizeof(name), "Loader-%d", i);
			g_local_mgr.numa_thp[i] = threadpool_create(name, wnum, i);
			if (!g_local_mgr.numa_thp[i]) {
				log_error("alloc Loader-%d failed", i);
				ret = -1;
				break;
			}
		}
	} while (0);

	if (ret != 0)
		_free_loader();
	return ret;
}

void loader_exit(void)
{
	_free_loader();
}
