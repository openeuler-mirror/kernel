/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NDS_API_H__
#define __NDS_API_H__

#include <stdint.h>
#include <sys/types.h>
#include <time.h>	/* struct timespec for nds_io_getevents */

/*
 * NDS — userspace API for NPU HBM ↔ NVMe P2P I/O (GDS-like, async).
 *
 * Typical usage:
 *
 *   1. Initialize NDS, then register each filesystem topology as it becomes
 *      available:
 *        struct nds_init_param ip = { 0 };
 *        int fds[] = { topo_fd };
 *        struct nds_fs_desc fs = {
 *            .fs_fd = fds,
 *            .fs_fd_cnt = 1,
 *        };
 *        nds_init(&ip);  // ip.version is the driver UAPI version
 *        nds_register_fs(&fs);
 *      Call nds_register_fs() again to add filesystems after initialization.
 *
 *   2. (Optional) Register HBM / CMB windows once:
 *        struct nds_mem_desc mem = { .ranges = ranges, .nr = nr };
 *        nds_register_mem(&mem);
 *      Later I/Os that use those VAs set NDS_IO_F_REGISTERED_MEM; the library
 *      passes its internal memory-table fd to the driver automatically.
 *
 *   3. Create an I/O context and submit work (Linux-AIO style):
 *        struct nds_io_ctx *ctx;
 *        nds_io_new_ctx(&(struct nds_io_ctx_param){ .max_io_cnt = N }, &ctx);
 *        struct nds_io_vec iov = {
 *            .buf_addr = ...,
 *            .buf_len  = ...,
 *        };
 *
 *        struct nds_io_cb cb = {
 *            .opcode   = NDS_IO_OP_PREAD,
 *            .obj      = { .fd = file_fd },
 *            .offset   = ...,
 *            .iov      = &iov,
 *            .iov_cnt  = 1,
 *            .rw_flags = 0,          // or NDS_IO_F_REGISTERED_MEM
 *            .host_pid = 0,          // must be 0 with REGISTERED_MEM
 *            .user_data = cookie,    // echoed in completion events
 *        };
 *        nds_io_submit(ctx, 1, &cb);
 *        nds_io_getevents(ctx, 1, 1, events, NULL);
 *
 *   4. Tear down: destroy ctx → unregister mem → nds_exit().
 *
 * Conventions:
 *   - All functions return 0 / positive count on success, or -errno on failure.
 *   - I/O is async only (no synchronous pread/pwrite helpers).
 *   - Targets are open file or block-device FDs. Paths are not accepted.
 *   - Offsets / lengths / buffer addresses must be sector-aligned (512 B).
 *   - reserved fields must be zero.
 */

#define NDS_IO_MAX_IO_CNT 1024u
#define NDS_IO_MAX_IOV 65536u

#define NDS_MEM_MAX_RANGES 8192u

struct nds_io_ctx;

struct nds_init_param {
	uint32_t flags;			/* must be 0 */
	uint32_t reserved1;		/* must be 0 */
	uint32_t version;		/* output: driver UAPI version (major << 8 | minor) */
	uint32_t reserved2;		/* must be 0 */
	uint64_t reserved3[4];		/* must be zero when unused */
};

/*
 * Filesystem topology registration descriptor.
 * v1: fs_fd_cnt must be at least 1. Every entry is a regular-file or
 * block-device fd whose underlying block device is registered via add_topo
 * for the process. Additional descriptors may be registered after nds_init.
 * Discovery uses the fd device ID and sysfs; no target /dev node is needed.
 * dm-linear discovery also requires access to /dev/mapper/control.
 */
struct nds_fs_desc {
	int32_t *fs_fd;
	uint32_t fs_fd_cnt;
	uint32_t reserved;
};

struct nds_mem_range {
	uint64_t addr;
	uint64_t size;
};

struct nds_mem_desc {
	const struct nds_mem_range *ranges;
	uint32_t nr;
	uint32_t flags;			/* must be 0 */
	uint64_t reserved[4];		/* must be zero */
};

/* max_io_cnt: v1 accepts 1..NDS_IO_MAX_IO_CNT as a queue-size hint but does
 * not enforce an outstanding-I/O budget in the library. flags and reserved
 * must be zero. */
struct nds_io_ctx_param {
	uint32_t max_io_cnt;
	uint32_t flags;
	uint64_t reserved;
};

/* I/O target. v1 supports only an open file or block-device fd. */
struct nds_io_obj {
	uint64_t reserved;          /* must be zero */
	union {
		uint64_t _data;
		int32_t fd;		/* open file / block-device fd */
	};
};

#define NDS_IO_OP_PREAD  0u	/* read one or more buffers */
#define NDS_IO_OP_PWRITE 1u /* write one or more buffers */

/* Buffer was previously registered with nds_register_mem(). */
#define NDS_IO_F_REGISTERED_MEM (1u << 0)
#define NDS_IO_F_MASK           NDS_IO_F_REGISTERED_MEM

struct nds_io_vec {
	uint64_t buf_addr;
	uint32_t buf_len;
	uint32_t reserved;		/* must be zero; layout matches p2p_iov */
};

/*
 * One async I/O request. Fill an array of these and pass to nds_io_submit().
 *
 * iov / iov_cnt describe the HBM (or CMB) VA windows for this transfer.
 * With NDS_IO_F_REGISTERED_MEM, every vector must fit within a single
 * registered range (-ERANGE otherwise, -ENOENT if no ranges are registered).
 * Otherwise buffers are one-shot.
 *
 * Regular writes preallocate before FIEMAP, even if later submission fails.
 * File I/O accesses raw extents, including unwritten extents, without cache
 * coherence or unwritten conversion. Only successfully XDS-written ranges
 * are valid for raw readback; normal file reads may still return zeros.
 * Callers must exclusively manage files and keep mappings stable through I/O.
 */
struct nds_io_cb {
	uint32_t opcode;		/* NDS_IO_OP_* */
	uint32_t rw_flags;		/* NDS_IO_F_* bitmask */
	struct nds_io_obj obj;
	uint64_t offset;		/* byte offset in the target object */
	uint64_t user_data;		/* opaque cookie, returned in events */
	const struct nds_io_vec *iov;
	uint32_t iov_cnt;
	/*
	 * Owner of one-shot HBM VAs. Only 0/current process is supported.
	 * Must be 0 when NDS_IO_F_REGISTERED_MEM is set.
	 */
	int32_t host_pid;
	uint64_t reserved[2];		/* must be zero */
};

/* One completion. Layout matches kernel struct p2p_io_event (48B).
 * res is success(==0) or -errno; reserved must be zero. */
struct nds_io_event {
	uint64_t user_data;
	int64_t res;
	uint64_t reserved[4];
};

/*
 * Process-wide initialization and teardown.
 * nds_init opens separate private NDS device fds for filesystem topology
 * ownership and memory-registration bookkeeping. It is not thread-safe or
 * re-entrant; call it once from one thread. Do not call nds_exit concurrently
 * with nds_register_fs() or any other NDS operation.
 */
int nds_init(struct nds_init_param *param);
int nds_exit(void);

/*
 * Register filesystem topologies after nds_init(). Call nds_register_fs()
 * once for the initial filesystem set and again whenever more filesystems
 * become available. Concurrent nds_register_fs() calls are thread-safe.
 *
 * nds_unregister_fs() removes the topology identified by each descriptor
 * from NDS's topology fd. A topology remains active if another registration
 * still pins the same top device.
 */
int nds_register_fs(const struct nds_fs_desc *desc);
int nds_unregister_fs(const struct nds_fs_desc *desc);

/*
 * Pin / unpin one or more separately allocated VA ranges (for example,
 * KV-cache blocks) into the process's registered-memory VA table.
 *
 * Ranges may be registered in one batch or incrementally across multiple
 * nds_register_mem() calls. One NDS_IO_F_REGISTERED_MEM iocb may scatter
 * across any registered ranges (each vector must fit within a single
 * registered range; -ERANGE otherwise). Any subset of registered ranges may
 * be unregistered in any order by exact (addr, size) match (-ENOENT if
 * missing, -EINVAL on size mismatch).
 *
 * desc->nr must be 1..NDS_MEM_MAX_RANGES. flags and reserved must be zero.
 */
int nds_register_mem(const struct nds_mem_desc *desc);
int nds_unregister_mem(const struct nds_mem_desc *desc);

/* Create / destroy a per-queue I/O context. Destroy drains outstanding I/O
 * and frees @ctx. The caller owns the pointer until destroy; double destroy
 * (or any use after destroy) is undefined behavior.
 * Do not call nds_io_getevents concurrently with destroy on the same ctx:
 * destroy holds the kernel harvest lock until all I/O completes. */
int nds_io_new_ctx(const struct nds_io_ctx_param *param,
		   struct nds_io_ctx **ctx);
int nds_io_destroy_ctx(struct nds_io_ctx *ctx);

/*
 * Submit nr control blocks. Returns the number accepted, or -errno.
 *
 * Each iocb is one logical I/O: its iov[] is scatter-gather on a single
 * obj.fd / offset and completes as one event (user_data). Different iocbs
 * may target different files; the library submits the valid prefix as
 * independent IOCTL_SUBMIT_IO items without cross-iocb merging.
 *
 * Fail-stop like Linux io_submit: on a mid-batch failure return the count
 * of iocbs already accepted (positive); the failed iocb's errno is not
 * returned. If nothing was accepted, return -errno. Accepted I/Os are not
 * rolled back — reap them with nds_io_getevents().
 */
int nds_io_submit(struct nds_io_ctx *ctx, int nr,
		  const struct nds_io_cb *iocb);

/*
 * Wait for at least min_nr completions, up to nr.
 * timeout NULL = wait forever; {0,0} = non-blocking.
 * On success returns the number of events filled (>= 0); on failure -errno.
 * When no I/Os are outstanding, returns 0 immediately even if min_nr > 0
 * (does not block until timeout like Linux AIO on an empty ctx).
 * Must not run concurrently with nds_io_destroy_ctx on the same ctx.
 */
int nds_io_getevents(struct nds_io_ctx *ctx, int min_nr,
		     int nr, struct nds_io_event *events,
		     struct timespec *timeout);

#endif
