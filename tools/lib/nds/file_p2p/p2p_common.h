/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __P2P_COMMON_H__
#define __P2P_COMMON_H__

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/fiemap.h>

#include <linux/nds_p2p.h>

/* Open /dev/p2p_device O_RDWR|O_CLOEXEC. Returns fd or -errno. */
int p2p_open_dev(void);

/*
 * Query IOCTL_GET_INFO, check the driver UAPI version, and store the full
 * version word in @version_out. Returns 0, -EPROTONOSUPPORT or another
 * negative errno.
 */
int p2p_check_uapi(int dev_fd, uint32_t *version_out);

/*
 * Discover nvme/linear/raid0/loop topology for block device ID @dev_id and
 * IOCTL_ADD_TOPO on @dev_fd. Requires sysfs and, for dm-linear,
 * /dev/mapper/control, but no target block device node. Returns 0 or -errno.
 */
int p2p_add_topo(int dev_fd, dev_t dev_id);

/*
 * Delete the topology identified by block device ID @dev_id from @dev_fd.
 * Requires no target device node or sysfs lookup. Returns 0 or -errno.
 */
int p2p_del_topo(int dev_fd, dev_t dev_id);

/*
 * Delete the topology identified by open file/block-device @topo_fd from
 * @dev_fd. Returns 0 or -errno.
 */
int p2p_del_topo_fd(int dev_fd, int topo_fd);

/* Build extents covering [offset, offset + size), preallocating regular writes.
 * Unwritten extents are raw storage: only previously XDS-written bytes are valid.
 * Caller frees *exts_out. Returns 0 or -errno. */
int p2p_prepare_io_extents(int file_fd, const struct stat *file_stat, unsigned int op,
			   unsigned long offset, unsigned long size, struct fiemap **exts_out,
			   unsigned int *ext_num_out, unsigned long long *total_size_out);

/* Sum iov[].size with sector-alignment checks. Returns 0 or -errno. */
int p2p_get_iov_size(const struct p2p_iov *iov, unsigned int iov_nr, unsigned long *size_out);

#endif
