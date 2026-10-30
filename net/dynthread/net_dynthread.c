// SPDX-License-Identifier: GPL-2.0-only
/* Dynamic threaded NAPI scheduler
 *
 * Record the RX queue IRQ information of the net devices configured
 * via the ifname module parameter, so that the IRQ placement can be
 * reworked at runtime.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/irq.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/topology.h>

#include "net_dynthread.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Dynamic threaded NAPI scheduler");

static char ifname[64];
module_param_string(ifname, ifname, sizeof(ifname), 0444);
MODULE_PARM_DESC(ifname, "net device names to monitor, separated by '#'");

static char irqname[64] = "comp";
module_param_string(irqname, irqname, sizeof(irqname), 0444);
MODULE_PARM_DESC(irqname, "substring of the NIC RX queue IRQ names, default comp");

static int sched_netdev_num;
static struct sched_netdev sched_netdev_table[SCHED_MAX_NETDEV_NUM];

static struct sched_netdev *get_sched_netdev(int index)
{
	if (index >= SCHED_MAX_NETDEV_NUM)
		return NULL;

	return &sched_netdev_table[index];
}

static struct sched_netdev *alloc_sched_netdev(void)
{
	if (sched_netdev_num >= SCHED_MAX_NETDEV_NUM)
		return NULL;

	return &sched_netdev_table[sched_netdev_num++];
}

/* Does @name contain @token as a whole name? Interface names may end in
 * a digit and be a prefix of another name (eth1 vs eth10) or be embedded
 * in another name (eth1 vs veth1), so the match must not be preceded or
 * followed by another alphanumeric character.
 */
static bool name_has_token(const char *name, const char *token)
{
	size_t len = strlen(token);
	const char *p = name;

	if (!len)
		return false;

	while ((p = strstr(p, token))) {
		if ((p == name || !isalnum(p[-1])) && !isalnum(p[len]))
			return true;
		p++;
	}

	return false;
}

/* Does @irq_name belong to an RX queue of @sched_dev? The default
 * patterns match the common NIC completion and RX queue IRQ names, the
 * user provided pattern is used as an additional match when not empty.
 */
static bool check_irq_name(const char *irq_name, struct sched_netdev *sched_dev)
{
	if (!strstr(irq_name, "TxRx") && !strstr(irq_name, "comp") &&
	    !strstr(irq_name, "rx") &&
	    (strlen(irqname) == 0 || !strstr(irq_name, irqname)))
		return false;

	if (name_has_token(irq_name, sched_dev->dev_name))
		return true;

	if (sched_dev->parent &&
	    name_has_token(irq_name, dev_name(sched_dev->parent)))
		return true;

	return false;
}

static void get_netdev_queue_info(struct sched_netdev *sched_dev)
{
	struct sched_netdev_queue_info *rxq_info;
	struct irq_desc *desc;
	struct irq_data *data;
	const struct cpumask *irq_mask;
	unsigned long flags;
	char name[64];
	int irq, cpu;

	/* irq descriptors are freed after an RCU grace period, so the
	 * lookup and the access to the descriptor must stay inside an
	 * RCU read-side critical section, like show_interrupts()
	 */
	rcu_read_lock();
	for (irq = 0; irq < nr_irqs; irq++) {
		data = irq_get_irq_data(irq);
		if (!data)
			continue;

		desc = irq_data_to_desc(data);
		cpu = nr_cpu_ids;
		name[0] = '\0';
		raw_spin_lock_irqsave(&desc->lock, flags);
		if (desc->action && desc->action->name &&
		    check_irq_name(desc->action->name, sched_dev)) {
			strscpy(name, desc->action->name, sizeof(name));
			irq_mask = irq_data_get_effective_affinity_mask(&desc->irq_data);
			cpu = cpumask_first(irq_mask);
		}
		raw_spin_unlock_irqrestore(&desc->lock, flags);

		/* unknown affinity, or the rxq array is full: skip */
		if (!name[0] || cpu >= nr_cpu_ids)
			continue;
		if (sched_dev->rxq_num >= MAX_DEV_RXQ_NUM)
			break;

		rxq_info = &sched_dev->rxq[sched_dev->rxq_num++];
		rxq_info->irq = irq;
		rxq_info->affinity_cpu = cpu;
	}
	rcu_read_unlock();
}

/* Drop the references taken on the devices and forget them. Used
 * both on module unload and to unwind a partially failed init.
 */
static void deinit_netdevinfo(void)
{
	struct sched_netdev *sched_dev;
	int id;

	for (id = 0; id < sched_netdev_num; id++) {
		sched_dev = get_sched_netdev(id);
		if (!sched_dev)
			continue;

		if (sched_dev->netdev)
			netdev_put(sched_dev->netdev, &sched_dev->dev_tracker);
		if (sched_dev->parent) {
			put_device(sched_dev->parent);
			sched_dev->parent = NULL;
		}
	}
	sched_netdev_num = 0;
}

/* count_sched_netdev_nodes - count the NUMA nodes of the RX queues */
static void count_sched_netdev_nodes(struct sched_netdev *sched_dev)
{
	nodemask_t nodes;
	int rxq_idx, node;

	nodes_clear(nodes);
	for (rxq_idx = 0; rxq_idx < sched_dev->rxq_num; rxq_idx++) {
		node = cpu_to_node(sched_dev->rxq[rxq_idx].affinity_cpu);
		if (node >= 0)
			node_set(node, nodes);
	}
	sched_dev->node_num = nodes_weight(nodes);
}

static int init_dev(const char *if_name, size_t length)
{
	struct sched_netdev *sched_dev;
	struct net_device *netdev;
	struct device *parent = NULL;
	netdevice_tracker dev_tracker;
	char dev_name[IFNAMSIZ];
	int ret;

	strscpy(dev_name, if_name, min_t(size_t, length + 1, IFNAMSIZ));
	netdev = netdev_get_by_name(&init_net, dev_name, &dev_tracker,
				    GFP_KERNEL);
	if (!netdev)
		return -ENODEV;

	/* Serialize with unregister_netdevice() and take a reference on
	 * the parent device, so its name stays valid while the IRQ names
	 * are matched against it.
	 */
	rtnl_lock();
	if (netdev->reg_state != NETREG_REGISTERED) {
		rtnl_unlock();
		ret = -ENODEV;
		goto err_dev_put;
	}
	if (netdev->dev.parent)
		parent = get_device(netdev->dev.parent);
	rtnl_unlock();

	if (!(netdev->flags & IFF_UP)) {
		ret = -ENETDOWN;
		goto err_parent_put;
	}

	if (netdev->flags & IFF_LOOPBACK) {
		ret = -EOPNOTSUPP;
		goto err_parent_put;
	}

	sched_dev = alloc_sched_netdev();
	if (!sched_dev) {
		ret = -ENOMEM;
		goto err_parent_put;
	}

	memcpy(sched_dev->dev_name, dev_name, IFNAMSIZ);
	sched_dev->netdev = netdev;
	sched_dev->dev_tracker = dev_tracker;
	sched_dev->parent = parent;
	get_netdev_queue_info(sched_dev);
	count_sched_netdev_nodes(sched_dev);

	return 0;

err_parent_put:
	if (parent)
		put_device(parent);
err_dev_put:
	netdev_put(netdev, &dev_tracker);
	return ret;
}

/* Parse the '#' separated list of net device names and record the RX
 * queue IRQ information of each device. The reference taken on each
 * net device is dropped on module unload.
 */
static int init_netdevinfo(const char *netdev_str)
{
	const char *start = netdev_str, *end;
	int err = -ENODEV;

	while (*start != '\0') {
		/* skip empty names */
		end = strchr(start, '#');
		if (end == start) {
			start++;
			continue;
		}

		/* the last name has no separator following it */
		if (!end) {
			err = init_dev(start, strlen(start));
			break;
		}

		err = init_dev(start, end - start);
		if (err)
			break;

		start = end + 1;
	}

	if (err)
		deinit_netdevinfo();

	return err;
}

static int __init dynthread_init(void)
{
	int ret;

	ret = init_netdevinfo(ifname);
	if (ret)
		return ret;

	return 0;
}

static void __exit dynthread_exit(void)
{
	deinit_netdevinfo();
}

module_init(dynthread_init);
module_exit(dynthread_exit);
