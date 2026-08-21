/* SPDX-License-Identifier: GPL-2.0 */
#ifndef P2P_DEBUGFS_H_
#define P2P_DEBUGFS_H_

#include <linux/blk_types.h>
#include <linux/types.h>

void p2p_debugfs_init(void);
void p2p_debugfs_exit(void);

void p2p_stats_io_issued(u64 bytes);
void p2p_stats_io_issue_failed(void);
void p2p_stats_io_complete(blk_status_t status);

#endif
