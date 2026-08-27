/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __FILE_P2P_API_H__
#define __FILE_P2P_API_H__

#include <stdint.h>

#include <linux/nds_p2p.h>

struct io_parameter {
	unsigned int op;
	const char *file_name;
	unsigned long file_offset;
	struct p2p_iov *iov;
	unsigned int iov_nr;
	unsigned int flags;
	int host_pid;
	uint64_t mem_handle;
};

int new_p2p_fd(void);
int close_p2p_fd(int dev_fd);
int add_topo(int dev_fd, const char *dev);
int register_mem(int dev_fd, struct p2p_mem_register_param *param);
int unregister_mem(int dev_fd, const struct p2p_mem_unregister_param *param);
int rw_file(int dev_fd, const struct io_parameter *param);
int drain_io(int dev_fd);

#endif
