// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2025 Huawei Technologies Co., Ltd
 */

#include "inner.h"
#include "log.h"
#include "mfs.h"
#include "policy.h"
#include "securec.h"
#include "threadpool.h"

#include <stdbool.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

struct parser_mgr {
	uint32_t fs_mode;
	uint32_t chunk_size;
	const char *mntpoint;
	threadpool_t *parser;
};

struct parser_mgr g_parser_mgr;

#define PARSER_NUM 8
#define MAX_PATH_SIZE 1024

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

bool is_power_of_2(unsigned long n)
{
	return (n != 0 && ((n & (n - 1)) == 0));
}

void ctx_cb(int ret, void *args)
{
	struct io_context *ctx = (struct io_context *)args;

	if (ctx->path)
		free(ctx->path);
	if (ctx->buf)
		free(ctx->buf);
	free(ctx);
}

void _submit_local_io(int fd, struct maio_entry *entry)
{
	struct io_context *ioctx;

	ioctx = calloc(1, sizeof(struct io_context));
	if (!ioctx) {
		log_error("ioctx alloc failed");
		return;
	}
	ioctx->off = entry->toff;
	ioctx->len = entry->tlen;
	ioctx->numaid = entry->tnuma;
	ioctx->fd = fd;
	ioctx->path = entry->fpath;
	ioctx->seq = entry->seq;
	ioctx->private = ioctx;
	ioctx->end_io = ctx_cb;
	loader_io_submit(ioctx);
}

char *get_file_path(int fd)
{
	struct mfs_ioc_rpath *rp;
	char *path;
	int ret;

	rp = malloc(sizeof(struct mfs_ioc_rpath) + MAX_PATH_SIZE);
	if (!rp) {
		log_error("rpath alloc failed");
		return NULL;
	}
	rp->max = MAX_PATH_SIZE;
	ret = ioctl(fd, MFS_IOC_RPATH, (unsigned long)rp);
	if (ret) {
		log_error("realpath failed for fd:%d, ret:%d", fd, ret);
		free(rp);
		return NULL;
	}
	rp->d[rp->len] = '\0';

	path = malloc(strlen(g_parser_mgr.mntpoint) + rp->len);
	if (!path) {
		log_error("malloc path %s %s failed", g_parser_mgr.mntpoint, (const char *)rp->d);
		return NULL;
	}
	sprintf(path, "%s%s", g_parser_mgr.mntpoint, (const char *)rp->d);
	free(rp);
	return path;
}

char *_get_fullpath(char *fpath, int fd)
{
	struct mfs_ioc_rpath *rp;
	char *path;
	int ret;

	if (fpath)
		return fpath;
	rp = malloc(sizeof(struct mfs_ioc_rpath) + MAX_PATH_SIZE);
	if (!rp) {
		log_error("rpath alloc failed");
		return NULL;
	}
	rp->max = MAX_PATH_SIZE;
	ret = ioctl(fd, MFS_IOC_RPATH, (unsigned long)rp);
	if (ret) {
		log_error("realpath failed for fd:%d, ret:%d", fd, ret);
		free(rp);
		return NULL;
	}
	rp->d[rp->len] = '\0';
	path = strdup((const char *)rp->d);
	if (!path)
		log_error("strdup path(%s) failed", (const char *)rp->d);
	free(rp);
	return path;
}

void maio_preload(struct maio *maio, int nio)
{
	struct maio_entry *entry;

	for (int i = 0; i < nio; ++i) {
		entry = &maio->entries[i];
		_submit_local_io(0, entry);
	}
}

uint8_t pid_to_numaid(int pid)
{
	return (uint8_t)-1;
}

void _process_read_io(uint32_t id, struct maio *maio, int nio)
{
	struct maio_entry *entry;
	int i;

	/* process the successor io */
	for (i = 0; i < nio; i++) {
		entry = &maio->entries[i];
		_submit_local_io(maio->fd, entry);
	}
}

void _submit_evict(struct maio_entry *entry)
{
	struct io_context *ioctx;

	ioctx = calloc(1, sizeof(struct io_context));
	if (!ioctx) {
		log_error("ioctx alloc failed");
		return;
	}
	ioctx->off = entry->toff;
	ioctx->len = entry->tlen;
	ioctx->numaid = -1;
	ioctx->path = entry->fpath;
	ioctx->private = ioctx;
	ioctx->end_io = ctx_cb;
	loader_evict_submit(ioctx);
}

void _process_evict(struct mfs_msg *msg)
{
	struct maio_entry *entry;
	struct mfs_read *read;
	uint64_t soff, eoff;
	struct maio *maio;
	int ret;

	if (g_parser_mgr.fs_mode != MFS_MODE_LOCAL)
		return;

	maio = calloc(1, sizeof(struct maio));
	if (!maio) {
		log_error("failed to alloc maio");
		return;
	}

	read = (void *)msg->data;
	maio->cksz = g_parser_mgr.chunk_size;
	soff = round_down(read->off, maio->cksz);
	eoff = round_up(read->off + read->len, maio->cksz);
	maio->fd = msg->fd;
	maio->off = read->off;
	maio->len = eoff - soff;
	maio->pid = read->pid;
	maio->op = msg->opcode;

	ret = policy_evict(&maio);
	if (ret <= 0)
		goto out;

	for (int i = 0; i < ret; ++i) {
		entry = &maio->entries[i];
		_submit_evict(entry);
	}
out:
	free(maio);
}

void _parse_read_req(struct mfs_msg *msg)
{
	struct mfs_read *read;
	struct maio *maio;
	uint64_t soff, eoff, ts;
	int ret, io_num = policy_max_io();

	_process_evict(msg);

	/* alloc maio slots */
	maio = calloc(1, sizeof(struct maio) + io_num * sizeof(struct maio_entry));
	if (!maio) {
		log_error("failed to alloc maio, num:%d", io_num);
		return;
	}
	read = (void *)msg->data;
	maio->cksz = g_parser_mgr.chunk_size;
	soff = round_down(read->off, maio->cksz);
	eoff = round_up(read->off + read->len, maio->cksz);
	ts = _get_ts();
	maio->fd = msg->fd;
	maio->off = soff;
	maio->len = eoff - soff;
	maio->pid = read->pid;
	maio->op = msg->opcode;
	maio->ts = ts;

	/* fill slots from policy */
	ret = policy_load(&maio);
	if (ret < 0) {
		char *path = _get_fullpath(NULL, maio->fd);
		if (path) {
			log_warn("io on path:%s%s offset:%lu length:%lu dropped",
				 g_parser_mgr.mntpoint, path, read->off, read->len);
			free(path);
		}
		free(maio);
		return;
	}

	if (maio->flags & MAIO_WITH_SEQ)
		loader_update_curseq(maio->curseq);

	/* keep the input parameter */
	maio->fd = msg->fd;
	maio->off = soff;
	maio->len = eoff - soff;
	maio->cksz = g_parser_mgr.chunk_size;
	maio->pid = read->pid;
	maio->op = msg->opcode;
	maio->ts = ts;

	/* process each maio in slots */
	_process_read_io(msg->id, maio, ret);
	free(maio);
}

void _parse_one_req(void *buf)
{
	struct mfs_msg *msg = (struct mfs_msg *)buf;

	if (msg->opcode == MFS_OP_READ || msg->opcode == MFS_OP_FAULT)
		_parse_read_req(msg);

	free(buf);
}

int maio_parse_req(void *buf, int size)
{
	struct mfs_msg *msg = (struct mfs_msg *)buf;

	if (msg->len != size)
		return -1;

	threadpool_submit(g_parser_mgr.parser, buf, _parse_one_req);
	return 0;
}

int parser_init(uint32_t fs_mode, const char *mntpoint)
{
	g_parser_mgr.fs_mode = fs_mode;
	g_parser_mgr.mntpoint = strdup(mntpoint);
	g_parser_mgr.chunk_size = 4096;
	if (!is_power_of_2(g_parser_mgr.chunk_size)) {
		log_error("chunk size must be power of 2");
		return -1;
	}
	g_parser_mgr.parser = threadpool_create("ReqParser", PARSER_NUM, -1);
	if (!g_parser_mgr.parser) {
		log_error("failed to alloc parser threadpool");
		return -1;
	}

	return 0;
}

void parser_destory(void)
{
	threadpool_destroy(g_parser_mgr.parser);
}
