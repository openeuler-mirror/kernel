/* SPDX-License-Identifier: GPL-2.0-only */
/* Internal definitions of the dynamic threaded NAPI scheduler */

#ifndef _NET_DYNTHREAD_H
#define _NET_DYNTHREAD_H

#include <linux/netdevice.h>

#define SCHED_MAX_NETDEV_NUM		8
#define MAX_DEV_RXQ_NUM			256

/**
 * struct sched_netdev_queue_info - IRQ information of one RX queue
 * @irq: Linux IRQ number of the queue
 * @affinity_cpu: CPU the IRQ was affined to when the module was loaded
 */
struct sched_netdev_queue_info {
	int irq;
	int affinity_cpu;
};

/**
 * struct sched_netdev - net device to monitor
 * @dev_name: interface name
 * @netdev: net device with a reference held by this module
 * @dev_tracker: tracker of the net device reference
 * @parent: parent device, with a reference held by this module
 * @rxq_num: number of RX queue IRQs recorded
 * @node_num: number of NUMA nodes the RX queue IRQs span
 * @rxq: IRQ information of the RX queues
 */
struct sched_netdev {
	char				dev_name[IFNAMSIZ];
	struct net_device		*netdev;
	netdevice_tracker		dev_tracker;
	struct device			*parent;
	int				rxq_num;
	int				node_num;
	struct sched_netdev_queue_info	rxq[MAX_DEV_RXQ_NUM];
};

#endif /* _NET_DYNTHREAD_H */
