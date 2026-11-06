/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2026. All rights reserved.
 */

#ifndef UAPI_OBMM_H
#define UAPI_OBMM_H

#include <linux/types.h>

#if defined(__cplusplus)
extern "C" {
#endif


#define OBMM_MAX_LOCAL_NUMA_NODES   16
#define MAX_NUMA_DIST               255
#define OBMM_MAX_PRIV_LEN           512
#define OBMM_MAX_VENDOR_LEN         128


#define OBMM_EXPORT_FLAG_ALLOW_MMAP 0x1UL
#define OBMM_EXPORT_FLAG_FAST       0x2UL
#define OBMM_EXPORT_FLAG_MASK       (OBMM_EXPORT_FLAG_ALLOW_MMAP | OBMM_EXPORT_FLAG_FAST)

struct obmm_cmd_export_pid {
	void *va;
	__u64 length;
	__u64 flags;
	__u64 uba;
	__u64 mem_id;
	__u32 tokenid;
	__s32 pid;
	__s32 pxm_numa;
	__u16 priv_len;
	__u16 vendor_len;
	__u8 deid[16];
	__u8 seid[16];
	const void *priv;
	const void *vendor_info;
} __attribute__((aligned(8)));

/* For ordinary register requests, @length and @flags are input arguments while
 * @tokenid, @uba and @mem_id are values set by obmm kernel module. For
 * register request, @length, @flags, @tokenid and @uba are input to obmm
 * kernel module. @mem_id is the only output.
 */
struct obmm_cmd_export {
	__u64 size[OBMM_MAX_LOCAL_NUMA_NODES];
	__u64 length;
	__u64 flags;
	__u64 uba;
	__u64 mem_id;
	__u32 tokenid;
	__s32 pxm_numa;
	__u16 priv_len;
	__u16 vendor_len;
	__u8 deid[16];
	__u8 seid[16];
	const void *vendor_info;
	const void *priv;
} __attribute__((aligned(8)));

#define OBMM_UNEXPORT_FLAG_MASK	(0UL)

struct obmm_cmd_unexport {
	__u64 mem_id;
	__u64 flags;
} __attribute__((aligned(8)));

enum obmm_query_key_type {
	OBMM_QUERY_BY_PA,
	OBMM_QUERY_BY_ID_OFFSET
};

struct obmm_cmd_addr_query {
	/* key type decides the input and output */
	enum obmm_query_key_type key_type;
	__u64 mem_id;
	__u64 offset;
	__u64 pa;
} __attribute__((aligned(8)));

#define OBMM_IMPORT_FLAG_ALLOW_MMAP	0x1UL
#define OBMM_IMPORT_FLAG_PREIMPORT	0x2UL
#define OBMM_IMPORT_FLAG_NUMA_REMOTE	0x4UL
#define OBMM_IMPORT_FLAG_MASK		(OBMM_IMPORT_FLAG_ALLOW_MMAP | \
					 OBMM_IMPORT_FLAG_PREIMPORT |  \
					 OBMM_IMPORT_FLAG_NUMA_REMOTE)


struct obmm_cmd_import {
	__u64 flags;
	__u64 mem_id;
	__u64 addr;
	__u64 length;
	__u32 tokenid;
	__u32 scna;
	__u32 dcna;
	__s32 numa_id;
	__u16 priv_len;
	__u8 base_dist;
	__u8 deid[16];
	__u8 seid[16];
	const void *priv;
} __attribute__((aligned(8)));

#define OBMM_UNIMPORT_FLAG_MASK	(0UL)

struct obmm_cmd_unimport {
	__u64 mem_id;
	__u64 flags;
} __attribute__((aligned(8)));


#define OBMM_CMD_EXPORT      _IOWR('x', 0, struct obmm_cmd_export)
#define OBMM_CMD_IMPORT      _IOWR('x', 1, struct obmm_cmd_import)
#define OBMM_CMD_UNEXPORT    _IOW('x', 2, struct obmm_cmd_unexport)
#define OBMM_CMD_UNIMPORT    _IOW('x', 3, struct obmm_cmd_unimport)
#define OBMM_CMD_ADDR_QUERY  _IOWR('x', 4, struct obmm_cmd_addr_query)
#define OBMM_CMD_EXPORT_PID  _IOWR('x', 5, struct obmm_cmd_export_pid)
#define OBMM_CMD_DECLARE_PREIMPORT   _IOWR('x', 6, struct obmm_cmd_preimport)
#define OBMM_CMD_UNDECLARE_PREIMPORT _IOW('x', 7, struct obmm_cmd_preimport)

/* 2bits */
#define OBMM_SHM_MEM_CACHE_RESV     0x0
#define OBMM_SHM_MEM_NORMAL         0x1
#define OBMM_SHM_MEM_NORMAL_NC      0x2
#define OBMM_SHM_MEM_DEVICE         0x3
#define OBMM_SHM_MEM_CACHE_MASK     0b11
/* 2bits */
#define OBMM_SHM_MEM_READONLY       0x0
#define OBMM_SHM_MEM_READEXEC       0x4
#define OBMM_SHM_MEM_READWRITE      0x8
#define OBMM_SHM_MEM_NO_ACCESS      0xc
#define OBMM_SHM_MEM_ACCESS_MASK    0b1100

/* cache maintenance operations (not states) */
/* no cache maintenance (nops) */
#define OBMM_SHM_CACHE_NONE             0x0
/* invalidate only (in-cache modifications may not be written back to DRAM) */
#define OBMM_SHM_CACHE_INVAL            0x1
/* write back and invalidate */
#define OBMM_SHM_CACHE_WB_INVAL         0x2
/* write back only */
#define OBMM_SHM_CACHE_WB_ONLY         0x3
/* Automatically choose the cache maintenance action depending on the memory
 * state. The resulting choice always make sure no data would be lost, and might
 * be more conservative than necessary.
 */
#define OBMM_SHM_CACHE_INFER            0x4

struct obmm_cmd_update_range {
	/* address range to manipulate: [start, end) */
	__u64 start;
	__u64 end;
	__u8  mem_state;
	__u8  cache_ops;
} __attribute__((aligned(8)));

#define OBMM_SHMDEV_UPDATE_RANGE	_IOW('X', 0, struct obmm_cmd_update_range)

struct obmm_cmd_preimport {
	__u64 pa;
	__u64 length;
	__u64 flags;
	__u32 scna;
	__u32 dcna;
	__s32 numa_id;
	__u16 priv_len;
	__u8 base_dist;
	__u8 deid[16];
	__u8 seid[16];
	const void *priv;
} __attribute__((aligned(16), packed));

#define OBMM_PREIMPORT_FLAG_MASK	(0UL)
#define OBMM_UNPREIMPORT_FLAG_MASK	(0UL)

/*
 * mmap offset flag bits, in the high nibble of the byte offset. mmap() only
 * builds the VMA: the first access faults the page in, and faults on a plain
 * mapping block (killable) while a switch gap is open. SWITCH_OLD/NEW are
 * gap-scoped dual-backend mappings, valid only in AWAIT_READY: they serve the
 * named backend instead of blocking, so userspace can migrate data before
 * switch_end; they are mutually exclusive and SWITCH_OLD also requires
 * KEEP_OLD_ALIVE. The scope lasts exactly one gap: once it closes - and in
 * any later gap - the VMA faults like a plain mapping, blocking while that
 * gap is open and then faulting through to the surviving backend, not
 * necessarily the one it was mapped for. HUGETLB_PMD freezes
 * the region at PMD granularity, installed as a PMD leaf where the physical
 * base is PMD_SIZE-aligned and as a PTE otherwise (the import PA is only
 * OBMM_BASIC_GRANU-aligned).
 */
#define OBMM_MMAP_FLAG_HUGETLB_PMD (1UL << 63)
#define OBMM_MMAP_FLAG_HUGETLB_PUD  (1UL << 62)	/* reserved: -EOPNOTSUPP */
#define OBMM_MMAP_FLAG_SWITCH_OLD   (1UL << 61)	/* switch_old backend, gap only */
#define OBMM_MMAP_FLAG_SWITCH_NEW   (1UL << 60)	/* current backend, gap only */

/*
 * Unified backend switch commands ('x', 8 and 9). One serialized userspace
 * controller owns each begin/end sequence: no generation cookie, so a stale
 * end after a later begin is undetectable. The gap has no kernel-side timeout
 * and stays open until switch_end; while open, faults block (killable), open
 * and plain mmap still succeed with the mapping populated on fault, and the
 * backend-touching ioctls return -EAGAIN (-EBUSY for unimport/unexport), so
 * an exiting controller parks the region in AWAIT_READY. Any privileged caller
 * may then close the gap with switch_end(success = 0), restoring the old
 * backend when kept alive -- best effort: a failed re-attach strands the
 * region, so poll switch_state afterwards; a restarted controller can then
 * choose between committing and aborting.
 *
 * Outside the gap, unimport/unexport accept either identity - the
 * creation ioctl or the live backend kind - since a switch changes the
 * backend but not created_as; a STRANDED region falls back to its
 * creation ioctl. A STRANDED region still accepts plain mmap (the
 * capability checks see no backend); the first touch then raises SIGBUS.
 *
 * errno - switch_begin: -EPERM, -EFAULT, -EINVAL, -ENOENT, -ENODEV, -ENOMEM,
 * -EEXIST, -EOPNOTSUPP, -EBUSY, -EIO, -EOVERFLOW, -ENOTRECOVERABLE (backend
 * creation failed -- import with an incomplete unwind, or export-pool
 * internal allocation; region unchanged). switch_end: -EPERM, -EINVAL,
 * -EFAULT, -ENOENT, -EAGAIN (transient state_mutex contention: a retry
 * re-evaluates the current state and may succeed in the same or a newer
 * gap), -ESTALE.
 * The same gating applies in flight to UPDATE_RANGE and ptrace (-EAGAIN
 * transitional, -EIO STRANDED); identity sysfs attributes return -EAGAIN
 * (shell scalars stay readable). Native-pointer ABI: no compat ioctls.
 */
enum obmm_switch_target_type {
	OBMM_SWITCH_TARGET_IMPORT        = 0,
	OBMM_SWITCH_TARGET_EXPORT_POOLED = 1,
};

/*
 * switch_state sysfs values (read-only, "%d"). The kernel-internal enum
 * matches these exactly (static_assert'ed in obmm_switch.c); they are
 * defined here so userspace can decode the attribute without
 * kernel-private headers.
 */
#define OBMM_SWITCH_STATE_IDLE		0
#define OBMM_SWITCH_STATE_SWAPPING	1
#define OBMM_SWITCH_STATE_AWAIT_READY	2
#define OBMM_SWITCH_STATE_FINISHING	3
#define OBMM_SWITCH_STATE_STRANDED	4

#define OBMM_SWITCH_FLAG_KEEP_OLD_ALIVE	0x1UL
#define OBMM_SWITCH_FLAG_MASK		(OBMM_SWITCH_FLAG_KEEP_OLD_ALIVE)

/*
 * OBMM_CMD_SWITCH_BEGIN swaps an existing region's backend (the "shell")
 * without changing its mem_id; @target_type selects the new target spec. The
 * old backend survives the gap when OBMM_SWITCH_FLAG_KEEP_OLD_ALIVE is set,
 * which also makes OBMM_MMAP_FLAG_SWITCH_OLD legal. @reserved, the @pad
 * arrays, @tokenid_pad, @pad2 and unused trailing @exp.size entries must be
 * zero. @exp's @tokenid and @uba are advisory outputs (the token exists only
 * from a successful begin and dies with the backend on abort): begin returns
 * 0 even if the copy-back faults, so pre-zero and verify, and never distribute
 * them before switch_end(success = 1); UMMU grants cannot be time-gated.
 */
struct obmm_cmd_switch_begin {
	__u64 mem_id;
	__u64 flags;
	__u8  target_type;	/* enum obmm_switch_target_type; picks an arm */
	__u8  reserved[7];	/* must be zero */
	union {
		struct {		/* OBMM_SWITCH_TARGET_IMPORT */
			/* 2MB (OBMM_BASIC_GRANU)-aligned PA, UBMEM-decodable
			 * over @new_scna; length equals the shell mem_size
			 */
			__u64 new_pa;
			__u32 new_scna;		/* registered UB controller CNA */
			__u32 new_dcna;
			__u8  new_seid[16];
			__u8  new_deid[16];
			__u8  base_dist;
			__u8  pad[7];		/* must be zero */
		} imp;
		struct {		/* OBMM_SWITCH_TARGET_EXPORT_POOLED */
			/*
			 * Per-node sizes: first @node_count used,
			 * trailing zero, sum = shell mem_size, each
			 * a multiple of OBMM_MEMSEG_SIZE
			 */
			__u64 size[OBMM_MAX_LOCAL_NUMA_NODES];
			__u32 node_count;	/* 1..OBMM_MAX_LOCAL_NUMA_NODES */
			__s32 pxm_numa;		/* as obmm_cmd_export.pxm_numa */
			/* subset of OBMM_EXPORT_FLAG_FAST; ALLOW_MMAP is
			 * shell-level and does not apply here
			 */
			__u64 export_flags;
			__u32 tokenid;		/* [out] UMMU token */
			__u32 tokenid_pad;	/* must be zero */
			__u64 uba;		/* [out] UBA base address */
			__u8  seid[16];		/* accepted and ignored, as obmm_cmd_export */
			__u8  deid[16];
			__u16 vendor_len;	/* <= OBMM_MAX_VENDOR_LEN, 0 legal */
			__u8  pad[6];
			const void *vendor_info;
		} exp;
	};
	__u16 priv_len;		/* <= OBMM_MAX_PRIV_LEN, 0 legal */
	__u8  pad2[6];		/* must be zero */
	const void *priv;	/* new backend private data; becomes the
				 * region's active priv once the switch
				 * finishes successfully -- concurrently
				 * with switch_end's return (ordered by its
				 * lock release); poll switch_state /
				 * priv_len for the committed value
				 */
} __attribute__((aligned(8)));

/*
 * OBMM_CMD_SWITCH_END closes the gap opened by switch_begin. @success = 1
 * finalizes the swap and destroys the old backend; 0 aborts, restoring the
 * old backend when kept alive -- best effort: a failed re-attach strands
 * the region (poll switch_state) -- else leaving the region without a
 * backend.
 * The fixed 16-byte shape keeps the _IOW size stable.
 */
struct obmm_cmd_switch_end {
	__u64 mem_id;
	__u32 success;		/* 1 = finalize, 0 = abort */
	__u32 reserved;		/* must be zero */
} __attribute__((aligned(8)));

#define OBMM_CMD_SWITCH_BEGIN	_IOWR('x', 8, struct obmm_cmd_switch_begin)
#define OBMM_CMD_SWITCH_END	_IOW('x', 9, struct obmm_cmd_switch_end)

#if defined(__cplusplus)
}
#endif

#endif /* UAPI_OBMM_H */
