/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef NDS_P2P_H_
#define NDS_P2P_H_

#include <linux/types.h>
#include <linux/fiemap.h>

#define P2P_UAPI_VERSION_MAJOR 0U
#define P2P_UAPI_VERSION_MINOR 1U
#define P2P_UAPI_VERSION ((P2P_UAPI_VERSION_MAJOR << 8) | P2P_UAPI_VERSION_MINOR)

struct p2p_iov {
	__u64 addr;
	__u32 size;
	__u32 reserved;
};

#define P2P_IO_F_REGISTERED_MEM (1U << 0)
#define P2P_IO_F_MASK P2P_IO_F_REGISTERED_MEM

#define P2P_IO_READ 0U
#define P2P_IO_WRITE 1U

/* Raw extent access; shared extents are permitted only for reads. */
#define P2P_FIEMAP_SUPPORTED_FLAGS \
	(FIEMAP_EXTENT_LAST | FIEMAP_EXTENT_MERGED | FIEMAP_EXTENT_UNWRITTEN | FIEMAP_EXTENT_SHARED)

/*
 * Fixed-size request; iov and extents are userspace pointers.
 * One batch item is one logical I/O covering all iov/extents and completing
 * as one event carrying user_data.
 */
struct p2p_io_param {
	unsigned int op;
	unsigned int flags;
	int file_fd;
	int host_pid;              /* calling process TGID; zero with registered memory */
	__s32 mem_fd;              /* VA-table fd; used with P2P_IO_F_REGISTERED_MEM */
	__u32 mem_reserved;        /* must be zero */
	__u64 user_data;          /* echo'd in the completion event */
	__u64 iov;                /* userspace pointer to struct p2p_iov[] */
	unsigned int iov_nr;
	unsigned int ext_nr;
	__u64 extents;            /* userspace pointer to struct fiemap_extent[] */
	__u64 reserved[3];           /* must be zero */
};

#define P2P_MAX_IO_NR 1024U

/*
 * Submit independent p2p_io_param records in array order. The ioctl stops at
 * the first item that cannot be accepted and returns the accepted prefix, or
 * a negative errno when the first item fails. Each accepted item produces one
 * completion event.
 */
struct p2p_io_batch_param {
	__u64 items;              /* userspace pointer to p2p_io_param[] */
	__u32 nr;
	__u32 reserved;
};

struct p2p_io_event {
	__u64 user_data;
	__s64 res;                /* 0 on success or -errno */
	__u64 reserved[4];
};

struct p2p_getevents_param {
	__s32 min_nr;
	__s32 max_nr;
	__s64 timeout_ns;       /* <0 infinite, 0 nonblock, >0 relative */
	__u64 events;           /* userspace pointer to struct p2p_io_event[] */
};

struct p2p_mem_range {
	__u64 addr;
	__u64 size;
};

#define P2P_MEM_MAX_RANGES 8192U

/*
 * Register 1..P2P_MEM_MAX_RANGES non-overlapping VA ranges into this fd's
 * VA->PA table. Ranges need not be sorted. Fails atomically if any range is
 * empty/overflows (-EINVAL/-EOVERFLOW), overlaps another range in this call
 * (-EINVAL), overlaps an existing range in this fd (-EEXIST), or exceeds the
 * per-fd total range limit (-E2BIG).
 */
struct p2p_mem_register_param {
	__u64 ranges;             /* userspace pointer to struct p2p_mem_range[] */
	__u32 nr;                 /* 1..P2P_MEM_MAX_RANGES */
	__u32 flags;              /* must be zero */
	__u64 reserved[4];        /* must be zero */
};

/*
 * Unregister 1..P2P_MEM_MAX_RANGES previously registered VA ranges from this
 * fd's VA->PA table. Each (addr, size) must exactly match an existing
 * registered range (no partial unpinning, no duplicates within the array).
 * Fails atomically (-ENOENT / -EINVAL) if any entry does not match.
 * Blocks until all in-flight I/Os referencing the removed ranges complete.
 */
struct p2p_mem_unregister_param {
	__u64 ranges;             /* userspace pointer to struct p2p_mem_range[] */
	__u32 nr;                 /* 1..P2P_MEM_MAX_RANGES */
	__u32 flags;              /* must be zero */
	__u64 reserved[4];        /* must be zero */
};

#define P2P_TOPO_NAME_LEN 32
#define P2P_TOPO_MAX_BDEVS 16
#define P2P_TOPO_MAX_EXTENTS 81920

struct topo_user_bdev {
	__u32 dev_id;
	__u32 reserved;
	/* [start_sector, start_sector + size_sector) */
	__u64 size_sector;
	__u64 start_sector;
};

/*
 * Extents are consecutive in loop-device sector order.
 *
 * extra[1] == 0: the extent is a range on bdevs[dev_index]. start_sector is
 * relative to that component's start_sector.
 *
 * extra[1] == chunk_sectors_shift + 1: bdevs[] is a RAID0 set. The extent is
 * a logical range on that set, dev_index is 0, and the kernel stripes it
 * onto a component at I/O time.
 */
/* Read as zeros. A write through this topology clears the range. */
#define P2P_TOPO_EXTENT_UNWRITTEN 1U

struct topo_user_extent {
	__u32 dev_index;
	__u32 reserved;		/* P2P_TOPO_EXTENT_UNWRITTEN or 0 */
	__u64 size_sector;
	__u64 start_sector;
};

struct topo_user_cfg {
	/*
	 * top_dev is the block device hosting the file system. For an nvme
	 * topology, it may be a whole namespace or a partition. Components may
	 * also be partitions, but their whole devices must be direct,
	 * non-multipath NVMe namespaces.
	 *
	 * nvme and linear require extra[] == 0. raid0 stores
	 * chunk_sectors_shift in extra[0] and requires extra[1] == 0. loop
	 * stores the extent count in extra[0]; extra[1] selects the loop
	 * extent encoding documented on topo_user_extent.
	 */
	char name[P2P_TOPO_NAME_LEN];
	__u32 top_dev;
	__u32 nr_devs;
	__u64 extra[2];
	struct topo_user_bdev bdevs[];
};

/* Loop extents immediately follow the nr_devs bdev entries. */
static inline struct topo_user_extent *topo_user_loop_extents(struct topo_user_cfg *cfg)
{
	return (struct topo_user_extent *)&cfg->bdevs[cfg->nr_devs];
}

/* Delete one topology pin from the fd receiving IOCTL_DEL_TOPO. */
struct topo_del_cfg {
	__u32 top_dev;
	__u32 reserved;
};

/* Output only. Feature flags and reserved fields are zero for version 0.1. */
struct p2p_device_info {
	__u32 version;            /* major in bits 15:8, minor in bits 7:0; upper bits zero */
	__u32 flags;
	__u64 reserved[3];
};

#define IOCTL_GET_INFO _IOR('k', 1, struct p2p_device_info)
#define IOCTL_REGISTER_MEM _IOW('k', 2, struct p2p_mem_register_param)
#define IOCTL_UNREGISTER_MEM _IOW('k', 3, struct p2p_mem_unregister_param)
#define IOCTL_SUBMIT_IO _IOWR('k', 4, struct p2p_io_batch_param)
#define IOCTL_GET_IO_EVENTS _IOWR('k', 5, struct p2p_getevents_param)

#define IOCTL_ADD_TOPO _IOW('k', 6, struct topo_user_cfg)
#define IOCTL_DEL_TOPO _IOW('k', 7, struct topo_del_cfg)
#define IOCTL_DRAIN_IO _IOC(_IOC_READ, 'k', 8, 0)

#endif
