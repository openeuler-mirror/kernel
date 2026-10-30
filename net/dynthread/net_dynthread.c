// SPDX-License-Identifier: GPL-2.0-only
/* Dynamic threaded NAPI scheduler
 *
 * Monitor the scheduling behaviour of a target application and switch
 * the NAPI processing of the configured net devices between softirq
 * context and kernel threads, whose CPU affinity is adapted to the
 * measured load. The RX queue IRQ placement of the devices is
 * adjusted as well.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/rcupdate.h>
#include <linux/cpumask.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/irq.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/topology.h>
#include <linux/kernel_stat.h>

#include "net_dynthread.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Dynamic threaded NAPI scheduler");

static char ifname[64];
module_param_string(ifname, ifname, sizeof(ifname), 0444);
MODULE_PARM_DESC(ifname, "net device names to monitor, separated by '#'");

static char irqname[64] = "comp";
module_param_string(irqname, irqname, sizeof(irqname), 0444);
MODULE_PARM_DESC(irqname, "substring of the NIC RX queue IRQ names, default comp");

static char appname[64] = "mysqld";
module_param_string(appname, appname, sizeof(appname), 0644);
MODULE_PARM_DESC(appname, "name of the target application threads, default mysqld");

static uint dyn_threaded_nvcsw_per_limit = 95;
module_param(dyn_threaded_nvcsw_per_limit, uint, 0644);
MODULE_PARM_DESC(dyn_threaded_nvcsw_per_limit,
		 "max nvcsw percent for long running status, default 95");

static uint dyn_threaded_avg_runtime_limit = 350000;
module_param(dyn_threaded_avg_runtime_limit, uint, 0644);
MODULE_PARM_DESC(dyn_threaded_avg_runtime_limit,
		 "min avg runtime (ns) for long running status, default 350000");

static uint dyn_threaded_not_running_limit = 30000;
module_param(dyn_threaded_not_running_limit, uint, 0644);
MODULE_PARM_DESC(dyn_threaded_not_running_limit,
		 "max avg runtime (ns) for not running status, default 30000");

static uint dyn_threaded_interval = 1000;

static int dyn_threaded_interval_set(const char *val,
				     const struct kernel_param *kp)
{
	uint interval;
	int ret;

	ret = kstrtouint(val, 0, &interval);
	if (ret)
		return ret;

	/* a zero interval would divide by zero and spin the timer */
	if (!interval)
		return -EINVAL;

	*(uint *)kp->arg = interval;

	return 0;
}

static int dyn_threaded_interval_get(char *buffer,
				     const struct kernel_param *kp)
{
	return scnprintf(buffer, PAGE_SIZE, "%u\n", *(uint *)kp->arg);
}

static const struct kernel_param_ops dyn_threaded_interval_ops = {
	.set = dyn_threaded_interval_set,
	.get = dyn_threaded_interval_get,
};

module_param_cb(dyn_threaded_interval, &dyn_threaded_interval_ops,
		&dyn_threaded_interval, 0644);
MODULE_PARM_DESC(dyn_threaded_interval, "sample interval in ms, default 1000");

static uint dyn_threaded_avg_runtime_keep_per = 90;
module_param(dyn_threaded_avg_runtime_keep_per, uint, 0644);
MODULE_PARM_DESC(dyn_threaded_avg_runtime_keep_per,
		 "min percent of avg runtime kept in long running status, default 90");

static uint dyn_threaded_bindirq = 1;
/* the IRQs are at their original affinity, nothing to restore */
static bool dyn_threaded_bindirq_close;
static int dyn_threaded_bindirq_set(const char *val,
				    const struct kernel_param *kp)
{
	uint bindirq;
	int ret;

	ret = kstrtouint(val, 0, &bindirq);
	if (ret)
		return ret;

	if (!bindirq)
		dyn_threaded_bindirq_close = true;
	*(uint *)kp->arg = bindirq;

	return 0;
}

static int dyn_threaded_bindirq_get(char *buffer,
				     const struct kernel_param *kp)
{
	return scnprintf(buffer, PAGE_SIZE, "%u\n", *(uint *)kp->arg);
}

static const struct kernel_param_ops dyn_threaded_bindirq_ops = {
	.set = dyn_threaded_bindirq_set,
	.get = dyn_threaded_bindirq_get,
};

module_param_cb(dyn_threaded_bindirq, &dyn_threaded_bindirq_ops,
		&dyn_threaded_bindirq, 0644);
MODULE_PARM_DESC(dyn_threaded_bindirq, "bind the device irqs to spare cpus too, default 1");

static uint dyn_threaded_irq_cpucore_limit = 8;
module_param(dyn_threaded_irq_cpucore_limit, uint, 0644);
MODULE_PARM_DESC(dyn_threaded_irq_cpucore_limit,
		 "min number of cpus left for the irqs in the target node, default 8");

static uint dyn_threaded_irq_cpucore_per = 50;
module_param(dyn_threaded_irq_cpucore_per, uint, 0644);
MODULE_PARM_DESC(dyn_threaded_irq_cpucore_per,
		 "percent of rx queues to keep per NUMA node, default 50");

/* default number of cpus used by the napi threads, computed at init */
static u32 dyn_threaded_corenum_default;

static u32 dyn_threaded_corenum;
static u32 dyn_threaded_corenum_lower_limit = 4;
static u32 dyn_threaded_corenum_upper_limit = 32;
static DEFINE_SPINLOCK(dyn_threaded_corenum_lock);

static int dyn_threaded_corenum_set(const char *val,
				    const struct kernel_param *kp)
{
	u32 num;
	int ret;

	ret = kstrtou32(val, 0, &num);
	if (ret)
		return ret;
	/* a zero count would leave the napi threads without cpu */
	if (!num)
		return -EINVAL;

	if (num > dyn_threaded_corenum_upper_limit ||
		num < dyn_threaded_corenum_lower_limit)
		return -EINVAL;

	spin_lock(&dyn_threaded_corenum_lock);
	*(u32 *)kp->arg = num;
	spin_unlock(&dyn_threaded_corenum_lock);
	return 0;
}

static int dyn_threaded_corenum_get(char *buffer,
				    const struct kernel_param *kp)
{
	return scnprintf(buffer, PAGE_SIZE, "%u\n", *(u32 *)kp->arg);
}

static const struct kernel_param_ops dyn_threaded_corenum_ops = {
	.set = dyn_threaded_corenum_set,
	.get = dyn_threaded_corenum_get,
};

module_param_cb(dyn_threaded_corenum, &dyn_threaded_corenum_ops,
		&dyn_threaded_corenum, 0644);
MODULE_PARM_DESC(dyn_threaded_corenum,
		 "number of cpus used by the napi threads, computed by default");

/* keep dyn_threaded_corenum within the current limits; a zero value is
 * left alone, it is either not set yet or will be initialized from the
 * default by dynthread_init()
 */
static void clamp_dyn_threaded_corenum(void)
{
	u32 num;

	spin_lock(&dyn_threaded_corenum_lock);
	num = dyn_threaded_corenum;
	if (num) {
		if (num < dyn_threaded_corenum_lower_limit)
			num = dyn_threaded_corenum_lower_limit;
		else if (num > dyn_threaded_corenum_upper_limit)
			num = dyn_threaded_corenum_upper_limit;
		WRITE_ONCE(dyn_threaded_corenum, num);
	}
	spin_unlock(&dyn_threaded_corenum_lock);
}

static int dyn_threaded_corenum_lower_limit_set(const char *val,
						const struct kernel_param *kp)
{
	u32 num;
	int ret;

	ret = kstrtou32(val, 0, &num);
	if (ret)
		return ret;
	/* a zero limit would make set_default_dyn_threaded_corenum()
	 * collapse the napi thread cpus to zero
	 */
	if (!num || num > READ_ONCE(dyn_threaded_corenum_upper_limit))
		return -EINVAL;

	WRITE_ONCE(*(u32 *)kp->arg, num);
	clamp_dyn_threaded_corenum();
	return 0;
}

static int dyn_threaded_corenum_upper_limit_set(const char *val,
						const struct kernel_param *kp)
{
	u32 num;
	int ret;

	ret = kstrtou32(val, 0, &num);
	if (ret)
		return ret;
	if (!num || num < READ_ONCE(dyn_threaded_corenum_lower_limit))
		return -EINVAL;

	WRITE_ONCE(*(u32 *)kp->arg, num);
	clamp_dyn_threaded_corenum();
	return 0;
}

static const struct kernel_param_ops dyn_threaded_corenum_lower_limit_ops = {
	.set = dyn_threaded_corenum_lower_limit_set,
	.get = dyn_threaded_corenum_get,
};

static const struct kernel_param_ops dyn_threaded_corenum_upper_limit_ops = {
	.set = dyn_threaded_corenum_upper_limit_set,
	.get = dyn_threaded_corenum_get,
};

module_param_cb(dyn_threaded_corenum_lower_limit,
		&dyn_threaded_corenum_lower_limit_ops,
		&dyn_threaded_corenum_lower_limit, 0644);
MODULE_PARM_DESC(dyn_threaded_corenum_lower_limit,
		 "lower limit of napi thread cpus, default 4");

module_param_cb(dyn_threaded_corenum_upper_limit,
		&dyn_threaded_corenum_upper_limit_ops,
		&dyn_threaded_corenum_upper_limit, 0644);
MODULE_PARM_DESC(dyn_threaded_corenum_upper_limit,
		 "upper limit of napi thread cpus, default 32");

static u32 dyn_threaded_user_per_limit = 20;
module_param(dyn_threaded_user_per_limit, uint, 0644);
MODULE_PARM_DESC(dyn_threaded_user_per_limit,
		 "user percent of the napi cpus to shrink for, default 20");

static u32 dyn_threaded_cpuload_lower_limit = 70;
module_param(dyn_threaded_cpuload_lower_limit, uint, 0644);
MODULE_PARM_DESC(dyn_threaded_cpuload_lower_limit,
		 "napi cpu load percent to shrink for, default 70");

static u32 dyn_threaded_cpuload_upper_limit = 90;
module_param(dyn_threaded_cpuload_upper_limit, uint, 0644);
MODULE_PARM_DESC(dyn_threaded_cpuload_upper_limit,
		 "napi cpu load percent to grow for, default 90");

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

/* status of the last sample of the target tasks */
static struct sched_task_runtime_avg_info snapshot;

/* union of the CPU masks allowed to the target tasks */
static struct cpumask target_cpumask;
static u32 target_cpucnt;

/* Take a sample of the scheduling statistics of all threads whose name
 * matches @target_comm, and compute the union of their allowed CPU
 * masks. The info must be zeroed by the caller.
 */
static int sched_task_runtime_avg_snapshot(const char *target_comm,
					   struct sched_task_runtime_avg_info *infos)
{
	struct task_struct *g, *p;
	char comm[TASK_COMM_LEN];
	u64 nvcsw, nivcsw, switches;
	struct cpumask masks;

	if (!target_comm || !infos)
		return -EINVAL;

	cpumask_clear(&masks);
	strscpy(infos->comm, target_comm, sizeof(infos->comm));

	rcu_read_lock();
	for_each_process(g) {
		for_each_thread(g, p) {
			get_task_comm(comm, p);
			if (strcmp(comm, infos->comm))
				continue;

			cpumask_or(&masks, &masks, p->cpus_ptr);

			nvcsw = (u64)READ_ONCE(p->nvcsw);
			nivcsw = READ_ONCE(p->nivcsw);
			switches = nvcsw + nivcsw;

			infos->total_runtime_ns += READ_ONCE(p->se.sum_exec_runtime);
			infos->total_switches += switches;
			infos->total_nvcsw += nvcsw;
			infos->total_nivcsw += nivcsw;
			infos->thread_cnt++;
		}
	}
	rcu_read_unlock();

	cpumask_copy(&target_cpumask, &masks);
	WRITE_ONCE(target_cpucnt, cpumask_weight(&target_cpumask));

	return 0;
}

/* load of the target tasks over the CPUs allowed to them, in percent */
static inline u64 cal_target_task_cpuload(struct sched_task_runtime_avg_info *infos)
{
	return 100 * (infos->total_runtime_ns - snapshot.total_runtime_ns) /
	       DYN_THREAD_INTERVAL / READ_ONCE(target_cpucnt);
}

/* Compare the current sample with the previous one and judge the
 * status of the target tasks. A sample whose counters moved backwards
 * yields DATA_LOSS and is evaluated by the caller only.
 */
static void judge_target_task_status(struct sched_task_runtime_avg_info *info)
{
	u64 switches;

	if (info->total_switches < snapshot.total_switches ||
	    info->total_runtime_ns < snapshot.total_runtime_ns ||
	    info->total_nvcsw < snapshot.total_nvcsw ||
	    info->total_nivcsw < snapshot.total_nivcsw ||
	    strcmp(info->comm, snapshot.comm)) {
		info->status = DATA_LOSS;
		return;
	}

	if (info->thread_cnt == 0) {
		info->status = NO_TASK;
		return;
	}

	/* a sample may contain no context switch, in which case the
	 * runtime delta is the runtime of the whole sample; clamp the
	 * switch count to avoid a division by zero
	 */
	switches = info->total_switches - snapshot.total_switches;
	switches = max_t(u64, switches, 1);

	info->avg_runtime = (info->total_runtime_ns - snapshot.total_runtime_ns) /
			    switches;
	info->nvcsw_per = (info->total_nvcsw - snapshot.total_nvcsw) * 100 /
			  switches;
	info->cpuload = cal_target_task_cpuload(info);

	if (info->avg_runtime < dyn_threaded_not_running_limit) {
		info->status = NOT_RUNNING;
	} else if (info->avg_runtime >=
		   snapshot.avg_runtime * dyn_threaded_avg_runtime_keep_per / ONE_HUNDRED &&
		   snapshot.status == LONG_RUNNING_WITH_INTERRUPTS &&
		   snapshot.last_status != LONG_RUNNING_WITH_INTERRUPTS &&
		   snapshot.nvcsw_per <= dyn_threaded_nvcsw_per_limit) {
		/* the status was reached in the previous sample: keep the
		 * statistics that triggered it, because starting the
		 * threaded napi may perturb the target tasks for a sample.
		 * last_status marks the transition and keeps this hold-off
		 * active while the status does not change.
		 */
		info->status = LONG_RUNNING_WITH_INTERRUPTS;
		info->nvcsw_per = snapshot.nvcsw_per;
		info->avg_runtime = snapshot.avg_runtime;
	} else if (info->avg_runtime > dyn_threaded_avg_runtime_limit &&
		   info->nvcsw_per <= dyn_threaded_nvcsw_per_limit) {
		info->status = LONG_RUNNING_WITH_INTERRUPTS;
	} else {
		info->status = FRAGMENTATION;
	}
}

/* true once the RX queue IRQs have been bound to a single NUMA node */
static bool affinity_to_one_node;

/* select_napi_cpus - set the first @core_num CPUs of @allowed in @result
 * @core_num: desired weight of @result
 * @allowed: allowed CPUs
 * @result: resulting CPU mask
 */
static void select_napi_cpus(u32 core_num, const struct cpumask *allowed,
			     struct cpumask *result)
{
	int cpu;
	int count = 0;

	cpumask_clear(result);
	for_each_cpu(cpu, allowed) {
		if (count >= core_num)
			break;
		cpumask_set_cpu(cpu, result);
		count++;
	}
}

/* Bind @irq to the CPU chosen by round-robin position @index in @bind_mask. */
static void bind_irq_in_cpumask(int irq, int index, const struct cpumask *bind_mask)
{
	unsigned int len = cpumask_weight(bind_mask);
	int cpu;

	if (!len)
		return;

	cpu = cpumask_nth(index % len, bind_mask);
	if (cpu >= nr_cpu_ids)
		return;

	irq_set_affinity(irq, cpumask_of(cpu));
}

/* Spread the RX queue IRQs of every monitored device over the CPUs of
 * their NUMA node, round-robin over all queues of all devices. The
 * number of CPUs used per node comes from the number of RX queues,
 * reduced to dyn_threaded_irq_cpucore_per percent. Skipped when IRQ
 * binding is disabled or after the IRQs were bound to a single node.
 */
static void bind_irq(void)
{
	struct sched_netdev *sched_dev;
	const struct cpumask *irq_mask;
	const struct cpumask *node_mask;
	struct cpumask bind_mask;
	struct irq_desc *desc;
	struct irq_data *data;
	unsigned long flags;
	int id, rxq_idx, irq, affinity_cpu;
	u32 cpumask_idx = 0;
	u32 node_num;
	u32 num_per_numa;

	if (!dyn_threaded_bindirq || affinity_to_one_node)
		return;

	for (id = 0; id < sched_netdev_num; id++) {
		sched_dev = get_sched_netdev(id);
		if (!sched_dev)
			continue;

		node_num = sched_dev->node_num ? sched_dev->node_num : 1;
		num_per_numa = (sched_dev->rxq_num + node_num - 1) /
			       node_num * dyn_threaded_irq_cpucore_per /
			       ONE_HUNDRED;
		for (rxq_idx = 0; rxq_idx < sched_dev->rxq_num; rxq_idx++) {
			irq = sched_dev->rxq[rxq_idx].irq;

			/* the descriptor is rcu freed, keep the lookup and
			 * the access to it in an RCU read-side section
			 */
			affinity_cpu = nr_cpu_ids;
			rcu_read_lock();
			data = irq_get_irq_data(irq);
			if (data) {
				desc = irq_data_to_desc(data);
				/* the effective affinity is protected by
				 * desc->lock
				 */
				raw_spin_lock_irqsave(&desc->lock, flags);
				irq_mask = irq_data_get_effective_affinity_mask(data);
				if (irq_mask && !cpumask_empty(irq_mask))
					affinity_cpu = cpumask_first(irq_mask);
				raw_spin_unlock_irqrestore(&desc->lock, flags);
			}
			rcu_read_unlock();

			if (affinity_cpu >= nr_cpu_ids)
				node_mask = cpu_online_mask;
			else
				node_mask = cpu_cpu_mask(affinity_cpu);

			select_napi_cpus(num_per_numa, node_mask, &bind_mask);
			bind_irq_in_cpumask(irq, cpumask_idx++, &bind_mask);
		}
	}
}

/* Is the CPU mask, if not empty, contained in a single NUMA node? */
static inline bool cpumask_in_one_numa(const struct cpumask *mask)
{
	const struct cpumask *node_mask;
	int first_cpu;

	if (cpumask_empty(mask))
		return false;

	/* the mask is in one node if it is a subset of the node of its
	 * first CPU
	 */
	first_cpu = cpumask_first(mask);
	node_mask = cpu_cpu_mask(first_cpu);

	return cpumask_subset(mask, node_mask);
}

/* Move all RX queue IRQs to the CPUs of the NUMA node of the target
 * tasks that are not allowed to those tasks, spread by round-robin.
 * Only done if at least dyn_threaded_irq_cpucore_limit CPUs are left
 * for the IRQs in that node; on a failed binding the CPU is retried
 * with the next IRQ.
 */
static void set_irq_node_affinity(const struct cpumask *tasks_cpumask)
{
	struct sched_netdev *sched_dev;
	const struct cpumask *node_mask;
	struct cpumask irq_prefer_mask;
	int cpu;
	int dev_id, rxq_id;
	int cpu_idx, cpu_cnt;

	cpumask_clear(&irq_prefer_mask);
	if (cpumask_empty(tasks_cpumask))
		return;
	cpu = cpumask_first(tasks_cpumask);
	if (cpu >= nr_cpu_ids)
		return;
	node_mask = cpu_cpu_mask(cpu);

	/* candidates are the CPUs of the node without the target tasks' ones */
	cpumask_andnot(&irq_prefer_mask, node_mask, tasks_cpumask);
	if (cpumask_empty(&irq_prefer_mask) ||
	    cpumask_weight(&irq_prefer_mask) < dyn_threaded_irq_cpucore_limit)
		return;

	cpu = cpumask_first(&irq_prefer_mask);
	for (dev_id = 0; dev_id < sched_netdev_num; dev_id++) {
		sched_dev = get_sched_netdev(dev_id);
		for (rxq_id = 0; rxq_id < sched_dev->rxq_num; rxq_id++) {
			cpu_cnt = cpumask_weight(&irq_prefer_mask);
			for (cpu_idx = 0; cpu_idx < cpu_cnt; cpu_idx++) {
				if (!irq_set_affinity(sched_dev->rxq[rxq_id].irq,
						      cpumask_of(cpu)))
					break;

				cpu = cpumask_next(cpu, &irq_prefer_mask);
				if (cpu >= nr_cpu_ids)
					cpu = cpumask_first(&irq_prefer_mask);
			}
			/* set irq affinity to all irq_prefer_mask failed */
			if (cpu_idx == cpu_cnt)
				return;

			cpu = cpumask_next(cpu, &irq_prefer_mask);
			if (cpu >= nr_cpu_ids)
				cpu = cpumask_first(&irq_prefer_mask);
		}
	}

	affinity_to_one_node = true;
}

/* Restore the affinity the RX queue IRQs had when the module was
 * loaded, as changed by set_irq_node_affinity() or bind_irq().
 */
static void recover_irq_affinity(void)
{
	struct sched_netdev *sched_dev;
	int dev_id, rxq_id;

	/* clear the state even when the binding is disabled now, so
	 * that re-enabling it does not keep suppressing bind_irq()
	 */
	affinity_to_one_node = false;

	/* nothing was moved away and no restore is pending, so there
	 * is nothing to restore; while the binding is enabled the IRQs
	 * may have been moved by bind_irq() or set_irq_node_affinity()
	 */
	if (!dyn_threaded_bindirq_close && !dyn_threaded_bindirq)
		return;

	for (dev_id = 0; dev_id < sched_netdev_num; dev_id++) {
		sched_dev = get_sched_netdev(dev_id);
		for (rxq_id = 0; rxq_id < sched_dev->rxq_num; rxq_id++) {
			if (sched_dev->rxq[rxq_id].affinity_cpu >= nr_cpu_ids)
				continue;
			irq_set_affinity(sched_dev->rxq[rxq_id].irq,
					 cpumask_of(sched_dev->rxq[rxq_id].affinity_cpu));
		}
	}

	dyn_threaded_bindirq_close = false;
}

/* CPUs the napi threads of the monitored devices may run on */
static struct cpumask napi_cpumask;

/* bind_napi_threaded - bind the threaded NAPIs of @dev to CPUs
 *
 * The mask of each NAPI thread is derived from the NUMA node of its
 * queue IRQ:
 *
 *  - if none of the target task CPUs is in that node, the whole node
 *    mask is used
 *  - otherwise, if the node has CPUs the target tasks are not allowed
 *    to use, those CPUs are used
 *  - otherwise the first dyn_threaded_corenum CPUs of the node are
 *    used; if the thread is already bound to such a subset, its
 *    current mask is kept
 *
 * In the latter case, with dyn_threaded_bindirq set, the queue IRQ is
 * bound along with its NAPI thread, round-robin over the same mask.
 * The CPUs used by the threads are recorded in napi_cpumask for the
 * load evaluation.
 */
static void bind_napi_threaded(struct sched_netdev *sched_dev)
{
	struct net_device *dev = sched_dev->netdev;
	struct napi_struct *napi;
	struct cpumask bind_mask, check_mask, napi_allowed_mask;
	const struct cpumask *irq_mask, *node_mask;
	struct irq_desc *desc;
	struct irq_data *data;
	unsigned long flags;
	u32 idx = 0, napi_idx = 0;
	int irq, cpu;

	/* __netif_napi_add() inserts at the list head, so the forward
	 * walk visits the NAPIs in the reverse of their registration
	 * order. Walk backwards to visit them in registration (vector)
	 * order, which is the order get_netdev_queue_info() records the
	 * RX queue IRQs in.
	 */
	list_for_each_entry_reverse(napi, &dev->napi_list, dev_list) {
		if (!napi->thread) {
			napi_idx++;
			continue;
		}

		cpumask_clear(&bind_mask);

		irq = napi->irq;
		/* some drivers (e.g. hns3) do not publish the vector irq
		 * on the napi; the recorded RX queue IRQs follow the same
		 * vector order, so pair them with the napi list
		 */
		if (irq < 0 && napi_idx < sched_dev->rxq_num)
			irq = sched_dev->rxq[napi_idx].irq;
		napi_idx++;

		/* the node of the irq, cpu_online_mask if unknown. The
		 * descriptor is rcu freed, so keep the lookup and the
		 * access to it in an RCU read-side section
		 */
		cpu = nr_cpu_ids;
		if (irq >= 0) {
			rcu_read_lock();
			data = irq_get_irq_data(irq);
			if (data) {
				desc = irq_data_to_desc(data);
				raw_spin_lock_irqsave(&desc->lock, flags);
				irq_mask = irq_data_get_effective_affinity_mask(&desc->irq_data);
				cpu = cpumask_first(irq_mask);
				raw_spin_unlock_irqrestore(&desc->lock, flags);
			}
			rcu_read_unlock();
		}
		if (cpu >= nr_cpu_ids)
			node_mask = cpu_online_mask;
		else
			node_mask = cpu_cpu_mask(cpu);

		/* no target task cpu in this node: use the whole node */
		cpumask_and(&check_mask, node_mask, &target_cpumask);
		if (cpumask_empty(&check_mask)) {
			cpumask_or(&napi_cpumask, &napi_cpumask, node_mask);
			set_cpus_allowed_ptr(napi->thread, node_mask);
			continue;
		}

		/* preferred: the node's cpus without the target tasks' ones */
		cpumask_andnot(&napi_allowed_mask, node_mask, &target_cpumask);
		if (!cpumask_empty(&napi_allowed_mask)) {
			cpumask_or(&napi_cpumask, &napi_cpumask, &napi_allowed_mask);
			set_cpus_allowed_ptr(napi->thread, &napi_allowed_mask);
			continue;
		}

		/* no spare cpu in the node: fall back to the whole node, */
		cpumask_copy(&napi_allowed_mask, node_mask);

		/* already bound to a subset of the right size? keep it */
		if (cpumask_weight(napi->thread->cpus_ptr) == dyn_threaded_corenum &&
		    cpumask_subset(napi->thread->cpus_ptr, &napi_allowed_mask)) {
			cpumask_or(&napi_cpumask, &napi_cpumask, napi->thread->cpus_ptr);
			continue;
		}

		select_napi_cpus(dyn_threaded_corenum, &napi_allowed_mask, &bind_mask);
		if (cpumask_empty(&bind_mask))
			continue;

		cpumask_or(&napi_cpumask, &napi_cpumask, &bind_mask);
		set_cpus_allowed_ptr(napi->thread, &bind_mask);
		if (dyn_threaded_bindirq && irq >= 0)
			bind_irq_in_cpumask(irq, idx++, &bind_mask);
	}
}

static void set_all_napi_threaded(bool threaded)
{
	struct sched_netdev *sched_dev;
	int id;

	/* napi_list, dev_set_threaded() and set_cpus_allowed_ptr()
	 * are all handled under the sleepable rtnl lock
	 */
	rtnl_lock();
	for (id = 0; id < sched_netdev_num; id++) {
		sched_dev = get_sched_netdev(id);
		if (!sched_dev)
			continue;

		dev_set_threaded(sched_dev->netdev, threaded);
		if (threaded)
			bind_napi_threaded(sched_dev);
	}
	rtnl_unlock();
}

/* percentual load of the napi cpus before the last change */
static struct kernel_cpustat snapshot_napi_per;

/* raw load of the napi cpus of the previous period */
static struct kernel_cpustat snapshot_napi_cpustat;

/* dyn_threaded_corenum of the last change */
static u32 last_threaded_corenum;

/* damping state of change_dyn_threaded_corenum: true right after
 * the count changed, true if the previous period took no action
 */
static bool dynamic_corenum_changed = true;
static bool dynamic_corenum_keep;

/* avg_cpustat - compute the per-CPU average of kernel_cpustat over
 * the online CPUs of @mask
 * @mask: desired CPUs
 * @avg: result, zeroed if @mask contains no online CPU
 */
static void avg_cpustat(const struct cpumask *mask, struct kernel_cpustat *avg)
{
	struct kernel_cpustat sum = { { 0 } };
	int cpu, count = 0;
	int i;

	for_each_cpu_and(cpu, mask, cpu_online_mask) {
		struct kernel_cpustat *stat = &per_cpu(kernel_cpustat, cpu);

		for (i = 0; i < NR_STATS; i++)
			sum.cpustat[i] += stat->cpustat[i];
		count++;
	}

	if (!count) {
		memset(avg, 0, sizeof(*avg));
		return;
	}

	for (i = 0; i < NR_STATS; i++)
		avg->cpustat[i] = sum.cpustat[i] / count;
}

/* cal_cpustat_per - the increase of each kernel_cpustat field between
 * @start and @end, in percent of the total increase
 */
static void cal_cpustat_per(const struct kernel_cpustat *end,
			    const struct kernel_cpustat *start,
			    struct kernel_cpustat *per)
{
	struct kernel_cpustat delta;
	u64 total;
	int i;

	for (i = 0; i < NR_STATS; i++) {
		if (end->cpustat[i] > start->cpustat[i])
			delta.cpustat[i] = end->cpustat[i] - start->cpustat[i];
		else
			delta.cpustat[i] = 0;
	}

	total = delta.cpustat[CPUTIME_USER] + delta.cpustat[CPUTIME_NICE] +
		delta.cpustat[CPUTIME_SYSTEM] + delta.cpustat[CPUTIME_IDLE] +
		delta.cpustat[CPUTIME_IOWAIT] + delta.cpustat[CPUTIME_IRQ] +
		delta.cpustat[CPUTIME_SOFTIRQ] + delta.cpustat[CPUTIME_STEAL];

	/* no accounting delta, e.g. no online cpu in the mask: everything
	 * is zero, avoid the division by zero
	 */
	if (!total) {
		memset(per, 0, sizeof(*per));
		return;
	}

	for (i = 0; i < NR_STATS; i++)
		per->cpustat[i] = 100 * delta.cpustat[i] / total;
}

/* take the cpustat baseline of the currently bound napi cpus */
static void take_napi_cpustat_snapshot(void)
{
	struct kernel_cpustat napi_cpustat;

	avg_cpustat(&napi_cpumask, &napi_cpustat);
	snapshot_napi_cpustat = napi_cpustat;
}

/* change_dyn_threaded_corenum - resize dyn_threaded_corenum
 *
 * The load of the napi cpus is evaluated from the deltas of their
 * kernel_cpustat. The core count grows when the irq and softirq share
 * of the napi cpus reaches IRQ_LIMIT percent or when their total load
 * reaches dyn_threaded_cpuload_upper_limit percent; it shrinks when
 * their user share reaches dyn_threaded_user_per_limit percent or
 * their total load drops below dyn_threaded_cpuload_lower_limit
 * percent, but not right over a change grown out of the target count.
 *
 * Fluctuations are damped: an action right after a no-action period
 * is deferred for one period, and after a change the evaluation is
 * skipped once.
 */
static void change_dyn_threaded_corenum(void)
{
	struct kernel_cpustat napi_per;
	struct kernel_cpustat napi_cpustat;
	u64 irq_softirq, prev_irq_softirq;
	u32 corenum;
	int action = 0;

	avg_cpustat(&napi_cpumask, &napi_cpustat);

	if (dynamic_corenum_changed) {
		dynamic_corenum_changed = false;
		goto out;
	}

	/* percentual load of the napi cpus */
	cal_cpustat_per(&napi_cpustat, &snapshot_napi_cpustat, &napi_per);

	spin_lock(&dyn_threaded_corenum_lock);
	corenum = dyn_threaded_corenum;
	spin_unlock(&dyn_threaded_corenum_lock);

	irq_softirq = napi_per.cpustat[CPUTIME_SOFTIRQ] +
		      napi_per.cpustat[CPUTIME_IRQ];
	prev_irq_softirq = snapshot_napi_per.cpustat[CPUTIME_SOFTIRQ] +
			   snapshot_napi_per.cpustat[CPUTIME_IRQ];

	if (irq_softirq >= IRQ_LIMIT &&
	    (snapshot_napi_per.cpustat[CPUTIME_USER] < dyn_threaded_user_per_limit ||
	     last_threaded_corenum != corenum + 1)) {
		action = 1;
	} else if (napi_per.cpustat[CPUTIME_USER] >= dyn_threaded_user_per_limit &&
		   (prev_irq_softirq < IRQ_LIMIT ||
		    last_threaded_corenum != corenum - 1)) {
		action = -1;
	} else if (100 - napi_per.cpustat[CPUTIME_IDLE] < dyn_threaded_cpuload_lower_limit &&
		   (100 - snapshot_napi_per.cpustat[CPUTIME_IDLE] <
		    dyn_threaded_cpuload_upper_limit ||
		    last_threaded_corenum != corenum - 1)) {
		action = -1;
	} else if (100 - napi_per.cpustat[CPUTIME_IDLE] >= dyn_threaded_cpuload_upper_limit &&
		   (100 - snapshot_napi_per.cpustat[CPUTIME_IDLE] >=
		    dyn_threaded_cpuload_lower_limit ||
		    last_threaded_corenum != corenum + 1)) {
		action = 1;
	}

	if (action) {
		if (dynamic_corenum_keep) {
			dynamic_corenum_keep = false;
			goto out;
		}
		snapshot_napi_per = napi_per;

		/* re-read under the lock: a concurrent module parameter
		 * write may have changed the count since the decision
		 * above, so clamp the result to the limits
		 */
		spin_lock(&dyn_threaded_corenum_lock);
		last_threaded_corenum = dyn_threaded_corenum;
		if (action > 0 &&
		    dyn_threaded_corenum < dyn_threaded_corenum_upper_limit) {
			dyn_threaded_corenum++;
			dynamic_corenum_changed = true;
		} else if (action < 0 &&
			   dyn_threaded_corenum > dyn_threaded_corenum_lower_limit) {
			dyn_threaded_corenum--;
			dynamic_corenum_changed = true;
		}
		spin_unlock(&dyn_threaded_corenum_lock);
	} else {
		dynamic_corenum_keep = true;
	}

out:
	snapshot_napi_cpustat = napi_cpustat;
}

/* reset the state collected while NAPI was threaded */
static void clear_corenum_napi(void)
{
	memset(&snapshot_napi_per, 0, sizeof(snapshot_napi_per));
	memset(&snapshot_napi_cpustat, 0, sizeof(snapshot_napi_cpustat));
	last_threaded_corenum = dyn_threaded_corenum_default;
	dynamic_corenum_changed = true;
	dynamic_corenum_keep = false;
}

static int dynthreaded;
/* set once dynthread_init() has recorded the net devices */
static bool dynthreaded_ready;

/* serializes dynthreaded_set() and the worker start/stop */
static DEFINE_MUTEX(dynthreaded_lock);

static struct work_struct dyn_threaded_work;
static struct hrtimer dyn_threaded_timer;

/* periodic work, judge the load of the target tasks */
static void dyn_threaded_handler(struct work_struct *work)
{
	struct sched_task_runtime_avg_info info = { };

	/* take a sample and judge the current status */
	sched_task_runtime_avg_snapshot(appname, &info);
	judge_target_task_status(&info);

	/* bind the irqs to one node if the target tasks sit in one node
	 * and need to be kept free of irq work
	 */
	if (!affinity_to_one_node && cpumask_in_one_numa(&target_cpumask) &&
	    dyn_threaded_bindirq)
		set_irq_node_affinity(&target_cpumask);

	switch (info.status) {
	case NO_TASK:
		/* no target tasks: back to softirq mode and restore the
		 * original irq affinity
		 */
		set_all_napi_threaded(false);
		recover_irq_affinity();
		spin_lock(&dyn_threaded_corenum_lock);
		dyn_threaded_corenum = dyn_threaded_corenum_default;
		spin_unlock(&dyn_threaded_corenum_lock);
		clear_corenum_napi();
		break;
	case DATA_LOSS:
		/* invalid sample, reuse the previous status and statistics */
		info.status = snapshot.status;
		info.nvcsw_per = snapshot.nvcsw_per;
		info.avg_runtime = snapshot.avg_runtime;
		break;
	case NOT_RUNNING:
		/* target tasks barely running: softirq mode is fine */
		set_all_napi_threaded(false);
		/* and the original irq affinity can be restored */
		recover_irq_affinity();
		/* the napi thread cpu count goes back to the default */
		spin_lock(&dyn_threaded_corenum_lock);
		dyn_threaded_corenum = dyn_threaded_corenum_default;
		spin_unlock(&dyn_threaded_corenum_lock);
		clear_corenum_napi();
		break;
	case FRAGMENTATION:
		/* softirq mode is fine, irqs spread over their NUMA node */
		set_all_napi_threaded(false);
		bind_irq();
		clear_corenum_napi();
		break;
	case LONG_RUNNING_WITH_INTERRUPTS:
		/* adapt the number of thread cpus to the measured load */
		change_dyn_threaded_corenum();
		/* switch NAPI processing to threads bound away from
		 * the target task cpus
		 */
		cpumask_clear(&napi_cpumask);
		set_all_napi_threaded(true);
		/* the next delta must be measured over the mask that was
		 * just bound, not over a previous, different one
		 */
		take_napi_cpustat_snapshot();
		break;
	default:
		break;
	}

	/* remember the status preceding the current one */
	if (info.status == snapshot.status)
		info.last_status = snapshot.last_status;
	else
		info.last_status = snapshot.status;

	snapshot = info;
}

static enum hrtimer_restart dyn_threaded_hrtimer_callback(struct hrtimer *timer)
{
	if (!dynthreaded)
		return HRTIMER_NORESTART;

	schedule_work(&dyn_threaded_work);
	hrtimer_forward_now(timer, ms_to_ktime(dyn_threaded_interval));

	return HRTIMER_RESTART;
}

static void start_worker(void)
{
	ktime_t interval = ms_to_ktime(dyn_threaded_interval);

	/* reset the state left by a previous run and take the first
	 * sample as the baseline
	 */
	memset(&snapshot, 0, sizeof(snapshot));
	sched_task_runtime_avg_snapshot(appname, &snapshot);

	INIT_WORK(&dyn_threaded_work, dyn_threaded_handler);

	hrtimer_init(&dyn_threaded_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	dyn_threaded_timer.function = dyn_threaded_hrtimer_callback;
	hrtimer_start(&dyn_threaded_timer, interval, HRTIMER_MODE_REL);
}

static void stop_worker(void)
{
	hrtimer_cancel(&dyn_threaded_timer);
	cancel_work_sync(&dyn_threaded_work);
	set_all_napi_threaded(false);
	recover_irq_affinity();
	cpumask_clear(&napi_cpumask);
	clear_corenum_napi();
}

/* enable/disable the scheduler through the dynthreaded module parameter */
static int dynthreaded_set(const char *val, const struct kernel_param *kp)
{
	int new_val, ret;

	ret = kstrtoint(val, 10, &new_val);
	if (ret < 0)
		return ret;

	new_val = !!new_val;

	/* keep the module alive while the worker is (re)armed; this
	 * also rejects writes that arrive after mod->exit() has run
	 */
	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	mutex_lock(&dynthreaded_lock);
	if (new_val == dynthreaded)
		goto out;

	dynthreaded = new_val;

	/* module parameters are parsed before dynthread_init(), so the
	 * worker can only be armed once the net devices are recorded;
	 * dynthread_init() arms it when the load succeeds
	 */
	if (!dynthreaded_ready)
		goto out;

	if (new_val)
		start_worker();
	else
		stop_worker();

out:
	mutex_unlock(&dynthreaded_lock);
	module_put(THIS_MODULE);
	return 0;
}

/* stop the worker on module exit, when no new reference can be
 * taken anymore
 */
static void dynthreaded_stop(void)
{
	mutex_lock(&dynthreaded_lock);
	if (dynthreaded) {
		dynthreaded = 0;
		stop_worker();
	}
	mutex_unlock(&dynthreaded_lock);
}

static int dynthreaded_get(char *buffer, const struct kernel_param *kp)
{
	return scnprintf(buffer, PAGE_SIZE, "%d\n", dynthreaded);
}

static const struct kernel_param_ops dynthreaded_ops = {
	.set = dynthreaded_set,
	.get = dynthreaded_get,
};

module_param_cb(dynthreaded, &dynthreaded_ops, NULL, 0644);
MODULE_PARM_DESC(dynthreaded, "enable the scheduler, default 0");

/* set_default_dyn_threaded_corenum - compute the default napi thread cpu count
 *
 * The default is the number of RX queues of the busiest monitored device
 * divided by the number of NUMA nodes, clamped between the core number
 * lower and upper limits.
 */
static void set_default_dyn_threaded_corenum(void)
{
	struct sched_netdev *sched_dev;
	unsigned int max_rxq = 0;
	u32 num;
	int id;

	for (id = 0; id < sched_netdev_num; id++) {
		sched_dev = get_sched_netdev(id);
		if (sched_dev)
			max_rxq = max(max_rxq, sched_dev->netdev->real_num_rx_queues);
	}

	num = max_rxq / num_online_nodes();
	if (num < dyn_threaded_corenum_lower_limit)
		num = dyn_threaded_corenum_lower_limit;
	if (num > dyn_threaded_corenum_upper_limit)
		num = dyn_threaded_corenum_upper_limit;
	dyn_threaded_corenum_default = num;
}

static int __init dynthread_init(void)
{
	int ret;

	ret = init_netdevinfo(ifname);
	if (ret)
		return ret;

	set_default_dyn_threaded_corenum();
	if (!dyn_threaded_corenum)
		dyn_threaded_corenum = dyn_threaded_corenum_default;
	last_threaded_corenum = dyn_threaded_corenum;

	/* the module parameters were parsed before this function ran;
	 * arm the worker only now that the device information is ready
	 */
	mutex_lock(&dynthreaded_lock);
	dynthreaded_ready = true;
	if (dynthreaded)
		start_worker();
	mutex_unlock(&dynthreaded_lock);

	return 0;
}

static void __exit dynthread_exit(void)
{
	/* make sure the worker is stopped and the devices are back in
	 * softirq mode before releasing them
	 */
	dynthreaded_stop();
	set_all_napi_threaded(false);
	recover_irq_affinity();

	deinit_netdevinfo();
}

module_init(dynthread_init);
module_exit(dynthread_exit);
