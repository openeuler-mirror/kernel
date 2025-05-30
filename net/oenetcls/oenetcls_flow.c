// SPDX-License-Identifier: GPL-2.0-only
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <trace/hooks/oenetcls.h>
#include "oenetcls.h"

static u32 oecls_cpu_mask;
static struct oecls_sock_flow_table __rcu *oecls_sock_flow_table;
static DEFINE_MUTEX(oecls_sock_flow_mutex);
static DEFINE_SPINLOCK(oecls_dev_flow_lock);

bool is_oecls_config_netdev(const char *name)
{
	struct oecls_netdev_info *netdev_info;
	int netdev_loop;

	for_each_oecls_netdev(netdev_loop, netdev_info)
		if (strcmp(netdev_info->dev_name, name) == 0)
			return true;

	return false;
}

static void oecls_timeout(void *data, struct net_device *dev, u16 rxq_index,
			  u32 flow_id, u16 filter_id, bool *ret)
{
	struct netdev_rx_queue *rxqueue = dev->_rx + rxq_index;
	struct oecls_dev_flow_table *flow_table;
	struct oecls_dev_flow *rflow;
	bool expire = true;
	unsigned int cpu;

	rcu_read_lock();
	flow_table = rcu_dereference(rxqueue->oecls_ftb);
	if (flow_table && flow_id <= flow_table->mask) {
		rflow = &flow_table->flows[flow_id];
		cpu = READ_ONCE(rflow->cpu);
		oecls_debug("dev:%s, rxq:%d, flow_id:%u, filter_id:%d/%d, cpu:%d", dev->name,
			    rxq_index, flow_id, filter_id, rflow->filter, cpu);

		if (rflow->filter == filter_id && cpu < nr_cpu_ids) {
			if (time_before(jiffies, rflow->timeout + OECLS_TIMEOUT)) {
				expire = false;
			} else {
				rflow->isvalid = 0;
				WRITE_ONCE(rflow->cpu, OECLS_NO_CPU);
			}
		}
	}
	rcu_read_unlock();
	oecls_debug("%s, dev:%s, rxq:%d, flow_id:%u, filter_id:%d, expire:%d\n", __func__,
		    dev->name, rxq_index, flow_id, filter_id, expire);
	*ret = expire;
}

static void oecls_flow_update(void *data, struct sock *sk)
{
	struct oecls_sock_flow_table *tb;
	unsigned int hash, index;
	u32 val;
	u32 cpu = raw_smp_processor_id();

	if (sk->sk_state != TCP_ESTABLISHED)
		return;

	if (check_appname(current->comm))
		return;

	rcu_read_lock();
	tb = rcu_dereference(oecls_sock_flow_table);
	hash = READ_ONCE(sk->sk_rxhash);
	if (tb && hash) {
		index = hash & tb->mask;
		val = hash & ~oecls_cpu_mask;
		val |= cpu;

		if (READ_ONCE(tb->ents[index]) != val) {
			WRITE_ONCE(tb->ents[index], val);

			oecls_debug("[%s] sk:%p, hash:0x%x, index:0x%x, val:0x%x, cpu:%d\n",
				    current->comm, sk, hash, index, val, cpu);
		}
	}
	rcu_read_unlock();
}

static int flow_get_queue_idx(struct net_device *dev, int nid, struct sk_buff *skb)
{
	struct oecls_netdev_info *netdev_info;
	int netdev_loop;
	u32 hash, index;
	struct oecls_numa_info *numa_info;
	struct oecls_numa_bound_dev_info *bound_dev = NULL;
	int rxq_id, rxq_num, i;

	numa_info = get_oecls_numa_info(nid);
	if (!numa_info)
		return -1;

	for_each_oecls_netdev(netdev_loop, netdev_info) {
		if (strcmp(netdev_info->dev_name, dev->name) == 0) {
			bound_dev = &numa_info->bound_dev[netdev_loop];
			break;
		}
	}

	if (!bound_dev)
		return -1;
	rxq_num = bitmap_weight(bound_dev->bitmap_rxq, OECLS_MAX_RXQ_NUM_PER_DEV);
	if (rxq_num == 0)
		return -1;

	hash = skb_get_hash(skb);
	index = hash % rxq_num;

	i = 0;
	for_each_set_bit(rxq_id, bound_dev->bitmap_rxq, OECLS_MAX_RXQ_NUM_PER_DEV)
		if (index == i++)
			return rxq_id;

	return -1;
}

static void set_oecls_cpu(struct net_device *dev, struct sk_buff *skb,
			  struct oecls_dev_flow *old_rflow, int old_rxq_id, u16 next_cpu)
{
	struct netdev_rx_queue *rxqueue;
	struct oecls_dev_flow_table *dtb;
	struct oecls_dev_flow *rflow;
	u32 flow_id, hash;
	u16 rxq_index;
	int rc;

	if (!skb_rx_queue_recorded(skb) || !dev->rx_cpu_rmap ||
	    !(dev->features & NETIF_F_NTUPLE))
		return;

	rxq_index = flow_get_queue_idx(dev, cpu_to_node(next_cpu), skb);
	if (rxq_index == skb_get_rx_queue(skb) || rxq_index < 0)
		return;

	rxqueue = dev->_rx + rxq_index;
	dtb = rcu_dereference(rxqueue->oecls_ftb);
	if (!dtb)
		return;

	hash = skb_get_hash(skb);
	flow_id = hash & dtb->mask;
	rflow = &dtb->flows[flow_id];
	if (rflow->isvalid && rflow->cpu == next_cpu) {
		rflow->timeout = jiffies;
		return;
	}

	rc = dev->netdev_ops->ndo_rx_flow_steer(dev, skb, rxq_index, flow_id);
	oecls_debug("skb:%p, rxq:%d, hash:0x%x, flow_id:%u, old_rxq_id:%d, next_cpu:%d, rc:%d\n",
		    skb, rxq_index, hash, flow_id, old_rxq_id, next_cpu, rc);
	if (rc < 0)
		return;

	rflow->filter = rc;
	rflow->isvalid = 1;
	rflow->timeout = jiffies;
	if (old_rflow->filter == rflow->filter)
		old_rflow->filter = OECLS_NO_FILTER;
	rflow->cpu = next_cpu;
}

static void __oecls_set_cpu(struct sk_buff *skb, struct net_device *ndev,
			    struct oecls_sock_flow_table *tb, struct oecls_dev_flow_table *dtb,
			    int old_rxq_id)
{
	struct oecls_dev_flow *rflow;
	u32 last_recv_cpu, hash, val;
	u32 tcpu = 0;
	u32 cpu = raw_smp_processor_id();

	skb_reset_network_header(skb);
	hash = skb_get_hash(skb);
	if (!hash)
		return;

	val = READ_ONCE(tb->ents[hash & tb->mask]);
	last_recv_cpu = val & oecls_cpu_mask;
	rflow = &dtb->flows[hash & dtb->mask];
	tcpu = rflow->cpu;

	if ((val ^ hash) & ~oecls_cpu_mask)
		return;

	if (cpu_to_node(cpu) == cpu_to_node(last_recv_cpu))
		return;

	if (tcpu >= nr_cpu_ids)
		set_oecls_cpu(ndev, skb, rflow, old_rxq_id, last_recv_cpu);
}

static void oecls_set_cpu(void *data, struct sk_buff *skb)
{
	struct net_device *ndev = skb->dev;
	struct oecls_sock_flow_table *stb;
	struct oecls_dev_flow_table *dtb;
	struct netdev_rx_queue *rxqueue;
	int rxq_id = -1;

	if (!ndev)
		return;

	if (!is_oecls_config_netdev(ndev->name))
		return;

	rxqueue = ndev->_rx;
	if (skb_rx_queue_recorded(skb)) {
		rxq_id = skb_get_rx_queue(skb);
		if (rxq_id >= ndev->real_num_rx_queues) {
			oecls_debug("ndev:%s, rxq:%d, real_num:%d\n", ndev->name,
				    rxq_id, ndev->real_num_rx_queues);
			return;
		}
		rxqueue += rxq_id;
	}

	// oecls_debug("skb:%px, dev:%s, rxq_id:%d\n", skb, ndev->name, rxq_id);
	if (rxq_id < 0)
		return;

	rcu_read_lock();
	stb = rcu_dereference(oecls_sock_flow_table);
	dtb = rcu_dereference(rxqueue->oecls_ftb);
	if (stb && dtb)
		__oecls_set_cpu(skb, ndev, stb, dtb, rxq_id);

	rcu_read_unlock();
}

static void oecls_dev_flow_table_free(struct rcu_head *rcu)
{
	struct oecls_dev_flow_table *table = container_of(rcu,
			struct oecls_dev_flow_table, rcu);
	vfree(table);
}

static void oecls_dev_flow_table_cleanup(struct net_device *netdev, int qid)
{
	struct oecls_dev_flow_table *dtb;
	struct netdev_rx_queue *queue;
	int i;

	spin_lock(&oecls_dev_flow_lock);
	for (i = 0; i < qid; i++) {
		queue = netdev->_rx + i;
		dtb = rcu_dereference_protected(queue->oecls_ftb,
						lockdep_is_held(&oecls_dev_flow_lock));
		rcu_assign_pointer(queue->oecls_ftb, NULL);
	}
	spin_unlock(&oecls_dev_flow_lock);
	call_rcu(&dtb->rcu, oecls_dev_flow_table_free);
}

static int oecls_dev_flow_table_release(void)
{
	struct oecls_netdev_info *netdev_info;
	int netdev_loop;
	struct net_device *netdev;

	for_each_oecls_netdev(netdev_loop, netdev_info) {
		netdev = netdev_info->netdev;
		if (!netdev)
			continue;
		oecls_dev_flow_table_cleanup(netdev, netdev->num_rx_queues);
	}

	return 0;
}

static int _oecls_dev_flow_table_init(struct net_device *netdev)
{
	struct oecls_dev_flow_table *table;
	int size = OECLS_DEV_FLOW_TABLE_NUM;
	struct netdev_rx_queue *queue;
	int i, j, ret = 0;

	size = roundup_pow_of_two(size);
	oecls_debug("dev:%s, num_rx_queues:%d, mask:0x%x\n", netdev->name, netdev->num_rx_queues,
		    size - 1);

	for (i = 0; i < netdev->num_rx_queues; i++) {
		table = vmalloc(OECLS_DEV_FLOW_TABLE_SIZE(size));
		if (!table) {
			ret = -ENOMEM;
			goto fail;
		}

		table->mask = size - 1;
		for (j = 0; j < size; j++) {
			table->flows[j].cpu = OECLS_NO_CPU;
			table->flows[j].isvalid = 0;
		}

		queue = netdev->_rx + i;

		spin_lock(&oecls_dev_flow_lock);
		rcu_assign_pointer(queue->oecls_ftb, table);
		spin_unlock(&oecls_dev_flow_lock);
	}
	return ret;
fail:
	oecls_dev_flow_table_cleanup(netdev, i);
	return ret;
}

static int oecls_dev_flow_table_init(void)
{
	struct oecls_netdev_info *netdev_info;
	int netdev_loop;
	struct net_device *ndev;
	int i, err;

	for_each_oecls_netdev(netdev_loop, netdev_info) {
		ndev = netdev_info->netdev;
		if (!ndev)
			continue;
		err = _oecls_dev_flow_table_init(ndev);
		if (err)
			goto out;
	}

	return 0;
out:
	for (i = 0; i < netdev_loop; i++) {
		netdev_info = get_oecls_netdev_info(i);
		ndev = netdev_info->netdev;
		if (!ndev)
			continue;
		oecls_dev_flow_table_cleanup(ndev, ndev->num_rx_queues);
	}
	return err;
}

static int oecls_sock_flow_table_release(void)
{
	struct oecls_sock_flow_table *tb;

	mutex_lock(&oecls_sock_flow_mutex);
	tb = rcu_dereference_protected(oecls_sock_flow_table,
				       lockdep_is_held(&oecls_sock_flow_mutex));
	if (tb)
		rcu_assign_pointer(oecls_sock_flow_table, NULL);
	mutex_unlock(&oecls_sock_flow_mutex);
	synchronize_rcu();
	vfree(tb);

	unregister_trace_oecls_flow_update(&oecls_flow_update, NULL);
	unregister_trace_oecls_set_cpu(&oecls_set_cpu, NULL);
	unregister_trace_oecls_timeout(&oecls_timeout, NULL);
	return 0;
}

static int oecls_sock_flow_table_init(void)
{
	struct oecls_sock_flow_table *table;
	int size = OECLS_SOCK_FLOW_TABLE_NUM;
	int i;

	size = roundup_pow_of_two(size);
	table = vmalloc(OECLS_SOCK_FLOW_TABLE_SIZE(size));
	if (!table)
		return -ENOMEM;

	oecls_cpu_mask = roundup_pow_of_two(nr_cpu_ids) - 1;
	oecls_debug("nr_cpu_ids:%d, oecls_cpu_mask:0x%x\n", nr_cpu_ids, oecls_cpu_mask);

	table->mask = size - 1;
	for (i = 0; i < size; i++)
		table->ents[i] = OECLS_NO_CPU;

	mutex_lock(&oecls_sock_flow_mutex);
	rcu_assign_pointer(oecls_sock_flow_table, table);
	mutex_unlock(&oecls_sock_flow_mutex);

	register_trace_oecls_flow_update(oecls_flow_update, NULL);
	register_trace_oecls_set_cpu(&oecls_set_cpu, NULL);
	register_trace_oecls_timeout(&oecls_timeout, NULL);
	return 0;
}

void oecls_flow_res_init(void)
{
	oecls_sock_flow_table_init();
	oecls_dev_flow_table_init();
}

void oecls_flow_res_clean(void)
{
	oecls_sock_flow_table_release();
	oecls_dev_flow_table_release();
}
