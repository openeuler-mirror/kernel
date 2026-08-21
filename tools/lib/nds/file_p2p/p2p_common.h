/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __P2P_COMMON_H__
#define __P2P_COMMON_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <linux/fiemap.h>

#include <linux/nds_p2p.h>

/* Open /dev/p2p_device O_RDWR|O_CLOEXEC. Returns fd or -errno. */
int p2p_open_dev(void);

/* Discover nvme/linear/raid0 topology for block device path @dev and
 * IOCTL_ADD_TOPO on @dev_fd. Returns 0 or -errno. */
int p2p_add_topo(int dev_fd, const char *dev);

/* Build FIEMAP (or synthetic block-dev) extents covering [offset, size).
 * Caller frees *exts_out. Returns 0 or -errno. */
int p2p_prepare_io_extents(int file_fd, const struct stat *file_stat,
			   unsigned long offset, unsigned long size,
			   struct fiemap **exts_out, unsigned int *ext_num_out,
			   unsigned long long *total_size_out);

/* Sum iov[].size with sector-alignment checks. Returns 0 or -errno. */
int p2p_get_iov_size(const struct p2p_iov *iov, unsigned int iov_nr,
		     unsigned long *size_out);

#endif
