// SPDX-License-Identifier: GPL-2.0
/*
 * NDS — a GDS-aligned userspace API for NPU HBM ↔ NVMe P2P I/O.
 *
 * NDS does not link against file_p2p_api; it shares p2p_common with file_p2p
 * for device open / topo / FIEMAP only. The two userspace APIs evolve
 * independently on top of the same kernel UAPI (linux/nds_p2p.h).
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <time.h>
#include <limits.h>
#include <stdint.h>

#include <linux/fiemap.h>

#include "nds_api_internal.h"
#include <linux/nds_p2p.h>
#include "p2p_common.h"

_Static_assert(sizeof(struct nds_io_vec) == sizeof(struct p2p_iov),
	       "nds_io_vec must match p2p_iov for zero-copy submission");
_Static_assert(NDS_IO_MAX_IO_CNT <= P2P_MAX_IO_NR,
	       "NDS submit size must fit the kernel batch ioctl");
_Static_assert(_Alignof(struct nds_io_vec) == _Alignof(struct p2p_iov),
	       "nds_io_vec alignment must match p2p_iov");
_Static_assert(offsetof(struct nds_io_vec, buf_addr) ==
		       offsetof(struct p2p_iov, addr) &&
	       offsetof(struct nds_io_vec, buf_len) ==
		       offsetof(struct p2p_iov, size) &&
	       offsetof(struct nds_io_vec, reserved) ==
		       offsetof(struct p2p_iov, reserved),
	       "nds_io_vec field layout must match p2p_iov");
_Static_assert(sizeof(struct nds_io_event) == sizeof(struct p2p_io_event),
	       "nds_io_event must match p2p_io_event for zero-copy getevents");
_Static_assert(sizeof(struct nds_io_event) == 48,
	       "nds_io_event / p2p_io_event are user_data + res + reserved[4]");
_Static_assert(offsetof(struct nds_io_event, user_data) ==
		       offsetof(struct p2p_io_event, user_data) &&
	       offsetof(struct nds_io_event, res) ==
		       offsetof(struct p2p_io_event, res) &&
	       offsetof(struct nds_io_event, reserved) ==
		       offsetof(struct p2p_io_event, reserved),
	       "nds_io_event field layout must match p2p_io_event");

struct nds_reg_entry {
	struct nds_reg_entry *next;
	void *addr;
	uint64_t size;
	uint64_t handle;
};

struct nds_state {
	int book_fd;
	int topo_fd;
	struct nds_reg_entry *regs;
	pthread_mutex_t reg_lock;
};

static struct nds_state g_state = {
	.book_fd = -1,
	.topo_fd = -1,
	.reg_lock = PTHREAD_MUTEX_INITIALIZER,
};

static int is_init(void)
{
	return g_state.book_fd >= 0 && g_state.topo_fd >= 0;
}

static int topo_fd_to_bdev(int32_t topo_fd, char *bdev, size_t bdev_size)
{
	char sys[64];
	char link[PATH_MAX];
	const char *base;
	struct stat st;
	dev_t target;
	ssize_t n;

	if (fstat(topo_fd, &st) < 0)
		return -errno;
	if (S_ISBLK(st.st_mode))
		target = st.st_rdev;
	else if (S_ISREG(st.st_mode))
		target = st.st_dev;
	else
		return -EINVAL;

	snprintf(sys, sizeof(sys), "/sys/dev/block/%u:%u",
		 major(target), minor(target));
	n = readlink(sys, link, sizeof(link) - 1);
	if (n < 0)
		return -errno;
	link[n] = '\0';
	base = strrchr(link, '/');
	base = base ? base + 1 : link;
	if (snprintf(bdev, bdev_size, "/dev/%s", base) >= (int)bdev_size)
		return -ENAMETOOLONG;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Public NDS API                                                     */
/* ------------------------------------------------------------------ */

int nds_init(struct nds_init_param *param)
{
	/* Not thread-safe: see nds_api.h. Concurrent init is undefined. */
	if (!param || param->flags || is_init() || param->reserved[0] ||
	    param->reserved[1] || param->reserved[2] || param->reserved[3])
		return -EINVAL;

	/* Keep memory registration and topology ownership on separate fds. */
	g_state.book_fd = p2p_open_dev();
	if (g_state.book_fd < 0)
		return g_state.book_fd;
	g_state.topo_fd = p2p_open_dev();
	if (g_state.topo_fd < 0) {
		int ret = g_state.topo_fd;

		close(g_state.book_fd);
		g_state.book_fd = -1;
		return ret;
	}
	g_state.regs = NULL;
	param->version = NDS_API_VERSION;
	return 0;
}

int nds_register_fs(const struct nds_fs_desc *desc)
{
	char bdev[PATH_MAX];
	uint32_t i;
	int ret;

	if (!desc || !desc->fs_fd || !desc->fs_fd_cnt || desc->reserved)
		return -EINVAL;

	/* Register every supplied topology for the lifetime of topo_fd. */
	for (i = 0; i < desc->fs_fd_cnt; i++) {
		ret = topo_fd_to_bdev(desc->fs_fd[i], bdev, sizeof(bdev));
		if (!ret)
			ret = p2p_add_topo(g_state.topo_fd, bdev);
		if (ret) {
			fprintf(stderr, "nds: add topology for fd %d failed %d\n",
				desc->fs_fd[i], ret);
			return ret;
		}
	}
	return 0;
}

int nds_unregister_fs(const struct nds_fs_desc *desc)
{
	(void)desc;
	return 0;
}

int nds_exit(void)
{
	struct nds_reg_entry *r, *next;

	pthread_mutex_lock(&g_state.reg_lock);
	r = g_state.regs;
	g_state.regs = NULL;
	pthread_mutex_unlock(&g_state.reg_lock);

	for (; r; r = next) {
		struct p2p_mem_unregister_param up = {
			.mem_handle = r->handle,
			.reserved = 0,
		};
		next = r->next;
		if (ioctl(g_state.book_fd, IOCTL_UNREGISTER_MEM, &up) < 0)
			fprintf(stderr,
				"nds: unregister memory addr=%p size=%llu handle=%llu failed %d\n",
				r->addr, (unsigned long long)r->size,
				(unsigned long long)r->handle, -errno);
		free(r);
	}

	close(g_state.topo_fd);
	g_state.topo_fd = -1;
	close(g_state.book_fd);
	g_state.book_fd = -1;
	return 0;
}

int nds_register_mem(void *addr, uint64_t size, int flags)
{
	struct p2p_mem_register_param p = { 0 };
	struct nds_reg_entry *r;
	int ret;

	/* addr may be 0 (stub CMB window starts at VA 0). */
	if (!size || flags)
		return -EINVAL;

	r = calloc(1, sizeof(*r));
	if (!r)
		return -ENOMEM;

	p.addr = (__u64)(uintptr_t)addr;
	p.size = size;
	if (ioctl(g_state.book_fd, IOCTL_REGISTER_MEM, &p) < 0) {
		ret = -errno;
		fprintf(stderr,
			"nds: register memory addr=%p size=%llu failed %d\n",
			addr, (unsigned long long)size, ret);
		free(r);
		return ret;
	}
	r->addr = addr;
	r->size = size;
	r->handle = p.mem_handle;
	pthread_mutex_lock(&g_state.reg_lock);
	r->next = g_state.regs;
	g_state.regs = r;
	pthread_mutex_unlock(&g_state.reg_lock);

	return 0;
}

int nds_unregister_mem(void *addr, uint64_t size, int flags)
{
	struct nds_reg_entry *r, **prev;
	struct p2p_mem_unregister_param up;
	int ret = 0;

	if (flags)
		return -EINVAL;

	pthread_mutex_lock(&g_state.reg_lock);
	for (prev = &g_state.regs; *prev; prev = &(*prev)->next) {
		if ((*prev)->addr == addr)
			break;
	}
	if (!*prev) {
		pthread_mutex_unlock(&g_state.reg_lock);
		return -ENOENT;
	}
	if ((*prev)->size != size) {
		fprintf(stderr,
			"nds: unregister memory addr=%p size=%llu does not match registered size=%llu\n",
			addr, (unsigned long long)size,
			(unsigned long long)(*prev)->size);
		pthread_mutex_unlock(&g_state.reg_lock);
		return -EINVAL;
	}

	r = *prev;
	*prev = r->next;
	pthread_mutex_unlock(&g_state.reg_lock);

	up.mem_handle = r->handle;
	up.reserved = 0;
	if (ioctl(g_state.book_fd, IOCTL_UNREGISTER_MEM, &up) < 0) {
		ret = -errno;
		fprintf(stderr,
			"nds: unregister memory addr=%p size=%llu handle=%llu failed %d\n",
			r->addr, (unsigned long long)r->size,
			(unsigned long long)r->handle, ret);
		pthread_mutex_lock(&g_state.reg_lock);
		r->next = g_state.regs;
		g_state.regs = r;
		pthread_mutex_unlock(&g_state.reg_lock);
		return ret;
	}
	free(r);
	return 0;
}

int nds_io_new_ctx(const struct nds_io_ctx_param *param, struct nds_io_ctx **ctx)
{
	struct nds_io_ctx *c;
	int fd;

	if (!param || !ctx)
		return -EINVAL;
	if (!param->max_io_cnt || param->max_io_cnt > NDS_IO_MAX_IO_CNT ||
	    param->flags ||
	    param->reserved)
		return -EINVAL;

	c = calloc(1, sizeof(*c));
	if (!c)
		return -ENOMEM;

	fd = p2p_open_dev();
	if (fd < 0) {
		free(c);
		return fd;
	}
	c->p2p_fd = fd;
	*ctx = c;
	return 0;
}

int nds_io_destroy_ctx(struct nds_io_ctx *ctx)
{
	int close_err = 0;
	int drain_err = 0;

	if (!ctx)
		return -EINVAL;
	/*
	 * Catches a closed-but-not-yet-freed ctx. A second destroy after
	 * free() is still use-after-free (caller bug / UB).
	 */
	if (ctx->p2p_fd < 0)
		return -EINVAL;

	/* Full-fd quiesce before close; not exposed as a public NDS API. */
	if (ioctl(ctx->p2p_fd, IOCTL_DRAIN_IO) < 0) {
		drain_err = -errno;
		fprintf(stderr, "nds: destroy_ctx drain failed %d\n",
			drain_err);
	}
	if (close(ctx->p2p_fd) < 0) {
		close_err = -errno;
		fprintf(stderr, "nds: destroy_ctx close failed %d\n", close_err);
	}
	ctx->p2p_fd = -1;
	free(ctx);
	/* Prefer the first failure; both are logged when both fail. */
	return drain_err ? drain_err : close_err;
}

static int find_registered_mem(const struct nds_io_vec *iov,
			       uint64_t *handle_out)
{
	struct nds_reg_entry *r;
	uint64_t addr = iov->buf_addr;
	uint64_t len = iov->buf_len;
	int ret = -EINVAL;

	pthread_mutex_lock(&g_state.reg_lock);
	for (r = g_state.regs; r; r = r->next) {
		uint64_t base = (uint64_t)(uintptr_t)r->addr;

		if (addr >= base && len <= r->size &&
		    addr - base <= r->size - len) {
			*handle_out = r->handle;
			ret = 0;
			break;
		}
	}
	pthread_mutex_unlock(&g_state.reg_lock);
	return ret;
}

static int validate_nds_iov(const struct nds_io_cb *cb, unsigned long *io_size)
{
	unsigned long size = 0;
	uint32_t i;

	if (!cb->iov || !cb->iov_cnt || cb->iov_cnt > NDS_IO_MAX_IOV)
		return -EINVAL;
	for (i = 0; i < cb->iov_cnt; i++) {
		if (!cb->iov[i].buf_len || cb->iov[i].reserved)
			return -EINVAL;
		if (__builtin_add_overflow(size, (unsigned long)cb->iov[i].buf_len, &size))
			return -EINVAL;
	}
	*io_size = size;
	return 0;
}

static int nds_iocb_to_io_param(const struct nds_io_cb *cb, int file_fd,
				struct p2p_io_param *io,
				struct fiemap **exts_out)
{
	struct fiemap *exts = NULL;
	struct stat file_stat;
	unsigned long io_size;
	unsigned long long total_size = 0;
	unsigned int ext_num = 0;
	uint64_t mem_handle = 0;
	int err;

	if (cb->opcode > NDS_IO_OP_PWRITE || (cb->rw_flags & ~NDS_IO_F_MASK))
		return -EOPNOTSUPP;

	err = validate_nds_iov(cb, &io_size);
	if (err)
		return err;
	if (cb->offset > ULONG_MAX ||
	    io_size > ULONG_MAX - (unsigned long)cb->offset)
		return -EOVERFLOW;

	if (cb->rw_flags & NDS_IO_F_REGISTERED_MEM) {
		if (cb->host_pid)
			return -EINVAL;
		err = find_registered_mem(&cb->iov[0], &mem_handle);
		if (err)
			return err;
	} else if (cb->host_pid < 0) {
		return -EINVAL;
	}

	if (fstat(file_fd, &file_stat) < 0) {
		err = -errno;
		fprintf(stderr, "nds: fstat fd %d failed, errno: %d\n",
			file_fd, err);
		return err;
	}

	err = p2p_prepare_io_extents(file_fd, &file_stat, cb->offset, io_size,
				     &exts, &ext_num, &total_size);
	if (err) {
		fprintf(stderr, "nds: prepare extents failed, errno: %d\n", err);
		return err;
	}
	if (!ext_num || total_size < io_size) {
		fprintf(stderr, "nds: extent size %llu < IOV size %lu\n",
			total_size, io_size);
		free(exts);
		return -ENODATA;
	}

	memset(io, 0, sizeof(*io));
	io->op = (cb->opcode == NDS_IO_OP_PWRITE) ? P2P_IO_WRITE : P2P_IO_READ;
	io->file_fd = file_fd;
	io->user_data = cb->user_data;
	io->iov = (uint64_t)(uintptr_t)cb->iov;
	io->iov_nr = cb->iov_cnt;
	io->ext_nr = ext_num;
	io->extents = (uint64_t)(uintptr_t)exts->fm_extents;

	if (cb->rw_flags & NDS_IO_F_REGISTERED_MEM) {
		io->flags = P2P_IO_F_REGISTERED_MEM;
		io->host_pid = 0;
		io->mem_handle = mem_handle;
	} else {
		io->flags = 0;
		io->host_pid = cb->host_pid ? cb->host_pid : getpid();
		io->mem_handle = 0;
	}

	*exts_out = exts;
	return 0;
}

static int nds_build_one_iocb(const struct nds_io_cb *cb,
			      struct p2p_io_param *param,
			      struct fiemap **exts_out)
{
	int file_fd = cb->obj.fd;
	int ret;

	if (cb->reserved[0] || cb->reserved[1] || cb->obj.reserved ||
	    file_fd < 0)
		return -EINVAL;

	ret = nds_iocb_to_io_param(cb, file_fd, param, exts_out);
	if (ret)
		fprintf(stderr, "nds: translate iocb failed %d\n", ret);
	return ret;
}

int nds_io_submit(struct nds_io_ctx *ctx, int nr,
		  const struct nds_io_cb *iocb)
{
	struct p2p_io_batch_param batch = { 0 };
	struct p2p_io_param *items;
	struct fiemap **exts;
	unsigned int built = 0;
	unsigned int i;
	int build_err = 0;
	int ret;

	if (!ctx || !iocb)
		return -EINVAL;
	if (nr < 0)
		return -EINVAL;
	if (!nr)
		return 0;
	if ((unsigned int)nr > NDS_IO_MAX_IO_CNT)
		return -EINVAL;

	items = calloc((size_t)nr, sizeof(*items));
	exts = calloc((size_t)nr, sizeof(*exts));
	if (!items || !exts) {
		free(exts);
		free(items);
		return -ENOMEM;
	}

	/*
	 * Build the valid prefix in iocb order, then submit its independent
	 * requests through one ioctl. Translation and kernel acceptance are both
	 * fail-stop: return the accepted prefix, or -errno if item zero fails.
	 */
	while (built < (unsigned int)nr) {
		build_err = nds_build_one_iocb(&iocb[built], &items[built],
					       &exts[built]);
		if (build_err)
			break;
		built++;
	}
	if (!built) {
		ret = build_err;
		goto out;
	}

	batch.nr = built;
	batch.items = (uint64_t)(uintptr_t)items;
	ret = ioctl(ctx->p2p_fd, IOCTL_SUBMIT_IO, &batch);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "nds: submit ioctl failed %d\n", ret);
	} else if (!ret) {
		ret = -EIO;
	}

out:
	for (i = 0; i < built; i++)
		free(exts[i]);
	free(exts);
	free(items);
	return ret;
}

int nds_io_getevents(struct nds_io_ctx *ctx, int min_nr,
		     int nr, struct nds_io_event *events,
		     struct timespec *timeout)
{
	struct p2p_getevents_param param = { 0 };
	int ret;

	if (!ctx)
		return -EINVAL;
	if (min_nr < 0 || nr < 0 || min_nr > nr)
		return -EINVAL;
	if (!nr)
		return 0;
	if (!events)
		return -EINVAL;

	/*
	 * nds_io_event is binary-identical to p2p_io_event (48B); pass the
	 * caller's buffer straight to the ioctl — no intermediate copy.
	 */
	param.min_nr = min_nr;
	param.max_nr = nr;
	if (timeout) {
		if (timeout->tv_sec < 0 || timeout->tv_nsec < 0 ||
		    timeout->tv_nsec >= 1000000000L ||
		    (uint64_t)timeout->tv_sec >
		    (uint64_t)(INT64_MAX - timeout->tv_nsec) /
		    UINT64_C(1000000000))
			return -EINVAL;
		param.timeout_ns = (__s64)timeout->tv_sec * 1000000000LL +
				   timeout->tv_nsec;
	} else {
		param.timeout_ns = -1;
	}
	param.events = (uint64_t)(uintptr_t)events;

	ret = ioctl(ctx->p2p_fd, IOCTL_GET_IO_EVENTS, &param);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "nds: getevents ioctl failed %d\n", ret);
		return ret;
	}
	return ret;
}
