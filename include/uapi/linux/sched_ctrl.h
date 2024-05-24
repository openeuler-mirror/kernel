/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _LINUX_SCHED_CTRL_H
#define _LINUX_SCHED_CTRL_H

#include <linux/types.h>


#define SCTL_IOC_MAGIC	'X'

/* get task relationship */
#define SCTL_GET_RSHIP		\
	_IOR(SCTL_IOC_MAGIC, 0, struct sctl_get_relationship_args)

#define SCTL_IOC_MAXNR	1

#define SCTL_MAX_NUMNODES 16
#define SCTL_STR_MAX 64
#define NR_TASK_FAULTS_TYPE 2

#define NO_RSHIP (-1)

struct grp_hdr {
	int gid;
	char preferred_nid[SCTL_STR_MAX];
	int nr_tasks;
};

struct sctl_net_relationship_info {
	int valid;
	struct grp_hdr grp_hdr;
	int nic_nid;
	int rx_dev_idx;
	int rx_dev_queue_idx;
	unsigned long rx_dev_netns_cookie;
	unsigned long rxtx_remote_bytes;
	unsigned long rxtx_bytes;
	unsigned long grp_rxtx_bytes;
};

struct sctl_mem_relationship_info {
	int valid;
	struct grp_hdr grp_hdr;
	int nodes_num;
	unsigned long total_faults;
	unsigned long grp_total_faults;
	unsigned long faults[SCTL_MAX_NUMNODES][NR_TASK_FAULTS_TYPE];
	unsigned long faults_cpu[SCTL_MAX_NUMNODES][NR_TASK_FAULTS_TYPE];
	unsigned long grp_faults[SCTL_MAX_NUMNODES][NR_TASK_FAULTS_TYPE];
	unsigned long grp_faults_cpu[SCTL_MAX_NUMNODES][NR_TASK_FAULTS_TYPE];
};

struct sctl_get_relationship_args {
	int tid;
	struct sctl_net_relationship_info nrsi;
	struct sctl_mem_relationship_info mrsi;
};
#endif /* _LINUX_SCHED_CTRL_H */
