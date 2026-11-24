/* SPDX-License-Identifier: GPL-2.0 */
#ifndef P2P_DEBUGFS_H_
#define P2P_DEBUGFS_H_

#include <linux/blk_types.h>
#include <linux/types.h>

#define P2P_IO_STATS_READ 0U
#define P2P_IO_STATS_WRITE 1U
#define P2P_IO_STATS_NR 2U

struct seq_file;

void p2p_debugfs_init(void);
void p2p_debugfs_exit(void);
int p2p_debugfs_memory_show(struct seq_file *seq, void *unused);
int p2p_debugfs_topo_show(struct seq_file *seq, void *unused);

void p2p_stats_io_issued(u32 op, u64 bytes);
void p2p_stats_io_issue_failed(u32 op);
void p2p_stats_io_complete(u32 op, blk_status_t status);

#endif
