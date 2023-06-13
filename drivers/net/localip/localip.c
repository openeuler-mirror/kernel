// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2023 Huawei Technologies Co., Ltd
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/device.h>
#include <linux/inetdevice.h>
#include <linux/spinlock.h>
#include <trace/events/net.h>

#define IN4_ADDR_HSIZE_SHIFT	8
#define IN4_ADDR_HSIZE		(1U << IN4_ADDR_HSIZE_SHIFT)

static struct hlist_head localip_lst[IN4_ADDR_HSIZE];

static DEFINE_SPINLOCK(localip_lock);

struct localipaddr {
	struct hlist_node node;
	struct rcu_head rcu;
	__u32 ipaddr;
};

static u32 localip_hash(__be32 addr)
{
	return hash_32(addr, IN4_ADDR_HSIZE_SHIFT);
}

static void localip_hash_insert(struct localipaddr *ip)
{
	u32 hash = localip_hash(ip->ipaddr);

	hlist_add_head_rcu(&ip->node, &localip_lst[hash]);
}

static void localip_hash_remove(struct localipaddr *ip)
{
	hlist_del_init_rcu(&ip->node);
}

static int is_local_ipaddr(uint32_t ipaddr)
{
	u32 hash = localip_hash(ipaddr);
	struct localipaddr *localip;

	rcu_read_lock();
	hlist_for_each_entry_rcu(localip, &localip_lst[hash], node) {
		if (localip->ipaddr == ipaddr) {
			rcu_read_unlock();
			return 1;
		}
	}
	rcu_read_unlock();

	return 0;
}

static int localip_event(struct notifier_block *this, unsigned long event,
			 void *ptr)
{
	struct in_ifaddr *ifa = ptr;
	struct net_device *event_netdev = ifa->ifa_dev->dev;
	struct localipaddr *localip;
	u32 hash;

	if (ipv4_is_loopback(ifa->ifa_local))
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UP:
		pr_debug("UP, dev:%s, ip:0x%x, mask:0x%x\n", event_netdev->name,
			 ifa->ifa_local, ifa->ifa_mask);
		localip = kzalloc(sizeof(struct localipaddr), GFP_KERNEL);
		if (!localip) {
			pr_err("kzalloc failed.\n");
			break;
		}
		localip->ipaddr = ifa->ifa_local;
		spin_lock(&localip_lock);
		localip_hash_insert(localip);
		spin_unlock(&localip_lock);
		break;
	case NETDEV_DOWN:
		pr_debug("DOWN, dev:%s, ip:0x%x, mask:0x%x\n", event_netdev->name,
			 ifa->ifa_local, ifa->ifa_mask);
		hash = localip_hash(ifa->ifa_local);
		spin_lock(&localip_lock);
		hlist_for_each_entry(localip, &localip_lst[hash], node) {
			if (localip->ipaddr == ifa->ifa_local) {
				localip_hash_remove(localip);
				kfree_rcu(localip, rcu);
				break;
			}
		}
		spin_unlock(&localip_lock);
		break;
	default:
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block localip_notifier = {
	.notifier_call  = localip_event,
};

static void is_local_ipaddr_trace(void *data, int *ret, uint32_t ipaddr)
{
	*ret = is_local_ipaddr(ipaddr);
}

static int localip_init(void)
{
	int i, err;

	for (i = 0; i < IN4_ADDR_HSIZE; i++)
		INIT_HLIST_HEAD(&localip_lst[i]);

	err = register_inetaddr_notifier(&localip_notifier);
	if (err)
		return err;

	err = register_trace_is_local_ipaddr(is_local_ipaddr_trace, NULL);
	if (err) {
		pr_err("Failed to connet probe to is_local_ipaddr.\n");
		unregister_inetaddr_notifier(&localip_notifier);
		return err;
	}
	return 0;
}

static void localip_cleanup(void)
{
	struct localipaddr *localip;
	struct hlist_node *n;
	int i;

	unregister_trace_is_local_ipaddr(is_local_ipaddr_trace, NULL);
	unregister_inetaddr_notifier(&localip_notifier);

	spin_lock(&localip_lock);
	for (i = 0; i < IN4_ADDR_HSIZE; i++) {
		hlist_for_each_entry_safe(localip, n, &localip_lst[i], node) {
			pr_debug("cleanup, hash:%i, ip:0x%x\n", i, localip->ipaddr);
			localip_hash_remove(localip);
			kfree_rcu(localip, rcu);
		}
	}
	spin_unlock(&localip_lock);
	synchronize_rcu();
}

module_init(localip_init);
module_exit(localip_cleanup);
MODULE_LICENSE("GPL");
