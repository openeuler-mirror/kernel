// SPDX-License-Identifier: GPL-2.0
/* Huawei IP notify Protocol Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#include <linux/timer.h>
#include <linux/types.h>

#include "ubl.h"
#include "network_mgmt.h"
#include "ip_notify.h"

static struct workqueue_struct *ip_notify_wq;
static int initialized;

static ssize_t good_ipv4_notify_tx_cnt_show(struct kobject *kobj,
					    struct kobj_attribute *attr,
					    char *buf)
{
	struct ub_nm_ip_notify_ctx *ipn_ctx;
	struct ip_notify_attrs *ipn_attrs;
	s64 good_ipv4_tx_cnt;

	ipn_attrs = container_of(attr, struct ip_notify_attrs,
				 good_ipv4_notify_tx_cnt);
	ipn_ctx = container_of(ipn_attrs, struct ub_nm_ip_notify_ctx, attrs);
	good_ipv4_tx_cnt = atomic64_read(&ipn_ctx->stats.good_ipv4_notify_tx_cnt);

	return sprintf(buf, "0x%llx\n", good_ipv4_tx_cnt);
}

static ssize_t bad_ipv4_notify_tx_cnt_show(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   char *buf)
{
	struct ub_nm_ip_notify_ctx *ipn_ctx;
	struct ip_notify_attrs *ipn_attrs;
	s64 bad_ipv4_tx_cnt;

	ipn_attrs = container_of(attr, struct ip_notify_attrs,
				 bad_ipv4_notify_tx_cnt);
	ipn_ctx = container_of(ipn_attrs, struct ub_nm_ip_notify_ctx, attrs);
	bad_ipv4_tx_cnt = atomic64_read(&ipn_ctx->stats.bad_ipv4_notify_tx_cnt);

	return sprintf(buf, "0x%llx\n", bad_ipv4_tx_cnt);
}

static ssize_t good_ipv6_notify_tx_cnt_show(struct kobject *kobj,
					    struct kobj_attribute *attr,
					    char *buf)
{
	struct ub_nm_ip_notify_ctx *ipn_ctx;
	struct ip_notify_attrs *ipn_attrs;
	s64 good_ipv6_tx_cnt;

	ipn_attrs = container_of(attr, struct ip_notify_attrs,
				 good_ipv6_notify_tx_cnt);
	ipn_ctx = container_of(ipn_attrs, struct ub_nm_ip_notify_ctx, attrs);
	good_ipv6_tx_cnt = atomic64_read(&ipn_ctx->stats.good_ipv6_notify_tx_cnt);

	return sprintf(buf, "0x%llx\n", good_ipv6_tx_cnt);
}

static ssize_t bad_ipv6_notify_tx_cnt_show(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   char *buf)
{
	struct ub_nm_ip_notify_ctx *ipn_ctx;
	struct ip_notify_attrs *ipn_attrs;
	s64 bad_ipv6_tx_cnt;

	ipn_attrs = container_of(attr, struct ip_notify_attrs,
				 bad_ipv6_notify_tx_cnt);
	ipn_ctx = container_of(ipn_attrs, struct ub_nm_ip_notify_ctx, attrs);
	bad_ipv6_tx_cnt = atomic64_read(&ipn_ctx->stats.bad_ipv6_notify_tx_cnt);

	return sprintf(buf, "0x%llx\n", bad_ipv6_tx_cnt);
}

static ssize_t print_ip_notify_pkt_en_show(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   char *buf)
{
	struct ub_nm_ip_notify_ctx *ipn_ctx;
	struct ip_notify_attrs *ipn_attrs;
	u32 status;

	ipn_attrs = container_of(attr, struct ip_notify_attrs,
				 print_ip_notify_pkt_en);
	ipn_ctx = container_of(ipn_attrs, struct ub_nm_ip_notify_ctx, attrs);
	status = ipn_ctx->ctls.print_ip_notify_pkt_en;

	return sprintf(buf, "%u\n", status);
}

static ssize_t print_ip_notify_pkt_en_store(struct kobject *kobj,
					    struct kobj_attribute *attr,
					    const char *buf, size_t count)
{
	struct ub_nm_ip_notify_ctx *ipn_ctx;
	struct ip_notify_attrs *ipn_attrs;
	u32 idata;
	int ret;

	ret = kstrtouint(buf, 0, &idata);
	if (ret != 0)
		return -EINVAL;

	ipn_attrs = container_of(attr, struct ip_notify_attrs,
				 print_ip_notify_pkt_en);
	ipn_ctx = container_of(ipn_attrs, struct ub_nm_ip_notify_ctx, attrs);
	ipn_ctx->ctls.print_ip_notify_pkt_en = idata;

	pr_info("ipn_ctx->ctls.print_ip_notify_pkt_en is %u",
		ipn_ctx->ctls.print_ip_notify_pkt_en);

	return count;
}

static int init_good_ipv4_tx_cnt(struct kobject *kobj,
				 struct kobj_attribute *kobj_attrs)
{
	sysfs_attr_init(&kobj_attrs->attr);
	kobj_attrs->attr.name = "good_ipv4_notify_tx_cnt";
	kobj_attrs->attr.mode = 0444;
	kobj_attrs->show = good_ipv4_notify_tx_cnt_show;
	return sysfs_create_file(kobj, &kobj_attrs->attr);
}

static int init_bad_ipv4_tx_cnt(struct kobject *kobj,
				struct kobj_attribute *kobj_attrs)
{
	sysfs_attr_init(&kobj_attrs->attr);
	kobj_attrs->attr.name = "bad_ipv4_notify_tx_cnt";
	kobj_attrs->attr.mode = 0444;
	kobj_attrs->show = bad_ipv4_notify_tx_cnt_show;

	return sysfs_create_file(kobj, &kobj_attrs->attr);
}

static int init_good_ipv6_tx_cnt(struct kobject *kobj,
				 struct kobj_attribute *kobj_attrs)
{
	sysfs_attr_init(&kobj_attrs->attr);
	kobj_attrs->attr.name = "good_ipv6_notify_tx_cnt";
	kobj_attrs->attr.mode = 0444;
	kobj_attrs->show = good_ipv6_notify_tx_cnt_show;

	return sysfs_create_file(kobj, &kobj_attrs->attr);
}

static int init_bad_ipv6_tx_cnt(struct kobject *kobj,
				struct kobj_attribute *kobj_attrs)
{
	sysfs_attr_init(&kobj_attrs->attr);
	kobj_attrs->attr.name = "bad_ipv6_notify_tx_cnt";
	kobj_attrs->attr.mode = 0444;
	kobj_attrs->show = bad_ipv6_notify_tx_cnt_show;

	return sysfs_create_file(kobj, &kobj_attrs->attr);
}

static int init_print_ipn_pkt_en(struct kobject *kobj,
				 struct kobj_attribute *kobj_attrs)
{
	sysfs_attr_init(&kobj_attrs->attr);
	kobj_attrs->attr.name = "print_ip_notify_pkt_en";
	kobj_attrs->attr.mode = 0666;
	kobj_attrs->show = print_ip_notify_pkt_en_show;
	kobj_attrs->store = print_ip_notify_pkt_en_store;

	return sysfs_create_file(kobj, &kobj_attrs->attr);
}

static void ip_notify_remove_ipv4(struct kobject *kobj,
				  struct ip_notify_attrs *ipn_attrs)
{
	sysfs_remove_file(kobj, &ipn_attrs->bad_ipv4_notify_tx_cnt.attr);
	sysfs_remove_file(kobj, &ipn_attrs->good_ipv4_notify_tx_cnt.attr);
}

static void ip_notify_remove_ipv6(struct kobject *kobj,
				  struct ip_notify_attrs *ipn_attrs)
{
	sysfs_remove_file(kobj, &ipn_attrs->bad_ipv6_notify_tx_cnt.attr);
	sysfs_remove_file(kobj, &ipn_attrs->good_ipv6_notify_tx_cnt.attr);
}

static int ip_notify_init_ipv4(struct kobject *kobj,
			       struct ip_notify_attrs *ipn_attrs)
{
	int ret;

	ret = init_good_ipv4_tx_cnt(kobj, &ipn_attrs->good_ipv4_notify_tx_cnt);
	if (ret) {
		pr_err("Failed to create good_ipv4_notify_tx_cnt, ret = %d\n",
		       ret);
		return ret;
	}

	ret = init_bad_ipv4_tx_cnt(kobj, &ipn_attrs->bad_ipv4_notify_tx_cnt);
	if (ret) {
		pr_err("Failed to create bad_ipv4_notify_tx_cnt, ret = %d\n",
		       ret);
		goto err_bad_ipv4_notify_tx_cnt;
	}

	return 0;

err_bad_ipv4_notify_tx_cnt:
	sysfs_remove_file(kobj, &ipn_attrs->bad_ipv4_notify_tx_cnt.attr);
	return ret;
}

static int ip_notify_init_ipv6(struct kobject *kobj,
			       struct ip_notify_attrs *ipn_attrs)
{
	int ret;

	ret = init_good_ipv6_tx_cnt(kobj, &ipn_attrs->good_ipv6_notify_tx_cnt);
	if (ret) {
		pr_err("Failed to create good_ipv6_notify_tx_cnt, ret = %d\n",
		       ret);
		return ret;
	}

	ret = init_bad_ipv6_tx_cnt(kobj, &ipn_attrs->bad_ipv6_notify_tx_cnt);
	if (ret) {
		pr_err("Failed to create bad_ipv6_notify_tx_cnt, ret = %d\n",
		       ret);
		goto err_bad_ipv6_notify_tx_cnt;
	}

	return 0;

err_bad_ipv6_notify_tx_cnt:
	sysfs_remove_file(kobj, &ipn_attrs->bad_ipv6_notify_tx_cnt.attr);
	return ret;
}

static int ip_notify_init_pkten(struct kobject *kobj,
				struct ip_notify_attrs *ipn_attrs)
{
	int ret;

	ret = init_print_ipn_pkt_en(kobj, &ipn_attrs->print_ip_notify_pkt_en);
	if (ret) {
		pr_err("Failed to create print_ip_notify_pkt_en, ret = %d\n",
		       ret);
		return ret;
	}

	return 0;
}

static int ip_notify_init_attrs(struct kobject *kobj,
				struct ip_notify_attrs *ipn_attrs)
{
	int ret;

	ret = ip_notify_init_ipv4(kobj, ipn_attrs);
	if (ret)
		return ret;

	ret = ip_notify_init_ipv6(kobj, ipn_attrs);
	if (ret)
		goto err_init_ipv6;

	ret = ip_notify_init_pkten(kobj, ipn_attrs);
	if (ret)
		goto err_pkt_en;

	return 0;

err_pkt_en:
	ip_notify_remove_ipv6(kobj, ipn_attrs);
err_init_ipv6:
	ip_notify_remove_ipv4(kobj, ipn_attrs);

	return ret;
}

static void ip_notify_init_stats(struct ip_notify_stats *ipn_stats)
{
	atomic64_set(&ipn_stats->bad_ipv4_notify_tx_cnt, 0);
	atomic64_set(&ipn_stats->bad_ipv6_notify_tx_cnt, 0);
	atomic64_set(&ipn_stats->good_ipv4_notify_tx_cnt, 0);
	atomic64_set(&ipn_stats->good_ipv6_notify_tx_cnt, 0);
}

static void ip_notify_remove_attrs(struct kobject *kobj,
				   struct ip_notify_attrs *ipn_attrs)
{
	sysfs_remove_file(kobj, &ipn_attrs->print_ip_notify_pkt_en.attr);
	sysfs_remove_file(kobj, &ipn_attrs->bad_ipv6_notify_tx_cnt.attr);
	sysfs_remove_file(kobj, &ipn_attrs->good_ipv6_notify_tx_cnt.attr);
	sysfs_remove_file(kobj, &ipn_attrs->bad_ipv4_notify_tx_cnt.attr);
	sysfs_remove_file(kobj, &ipn_attrs->good_ipv4_notify_tx_cnt.attr);
}

int ip_notify_sysfs_create(struct ub_nm_device *nm_dev)
{
	struct ub_nm_ip_notify_ctx *ip_notify_ctx = &nm_dev->sys_ctx.ip_notify_ctx;
	struct kobject *kobj = nm_dev->sys_ctx.nm_root;
	int ret;

	ip_notify_ctx->ip_notify_root = kobject_create_and_add("ip_notify",
							       kobj);
	if (!ip_notify_ctx->ip_notify_root) {
		pr_err("Failed to create ip_notify dir.\n");
		return -ENOMEM;
	}

	ret = ip_notify_init_attrs(ip_notify_ctx->ip_notify_root,
				   &ip_notify_ctx->attrs);
	if (ret) {
		pr_err("Failed to init ip notify attrs, ret = %d\n", ret);
		goto err_ip_notify_init_attrs;
	}

	ip_notify_init_stats(&ip_notify_ctx->stats);

	return 0;

err_ip_notify_init_attrs:
	kobject_put(ip_notify_ctx->ip_notify_root);
	return ret;
}

void ip_notify_sysfs_destroy(struct ub_nm_device *nm_dev)
{
	struct ub_nm_ip_notify_ctx *ip_notify_ctx = &nm_dev->sys_ctx.ip_notify_ctx;

	ip_notify_remove_attrs(ip_notify_ctx->ip_notify_root,
			       &ip_notify_ctx->attrs);
	kobject_put(ip_notify_ctx->ip_notify_root);
}

static void show_ip_notify_pkt_info(struct sk_buff *skb)
{
	struct list_head *dev_list = ub_nm_get_dev_list();
	struct ub_nm_device *nm_dev;
	unsigned int i;
	u32 enable;

	ub_nm_down_read();
	list_for_each_entry(nm_dev, dev_list, nm_dev_list)
		if (nm_dev->ndev == skb->dev)
			goto out;
	ub_nm_up_read();

	return;

out:
	enable = nm_dev->sys_ctx.ip_notify_ctx.ctls.print_ip_notify_pkt_en;
	if (enable) {
		pr_info("start print pkt info:\n");
		pr_info("len: %u, data_len: %u\n", skb->len, skb->data_len);
		pr_info("ptype: 0x%x\n", be16_to_cpu(skb->protocol));
		pr_info("data content start:\n\n");
		for (i = 0; i < skb->len; i++)
			pr_info("0x%02x ", skb->data[i]);
		pr_info("\n\ndata content end!\n\n");
	}
	ub_nm_up_read();
}

struct sk_buff *ub_ipv4_create_ip_notify_pkt(struct net_device *ndev,
					     __be32 src_ip, const u8 *src_hw,
					     __be32 netmask)
{
	int hlen = LL_RESERVED_SPACE(ndev);
	int tlen = ndev->needed_tailroom;
	struct ip_notify_hdr *ipn_hdr_v4;
	struct sk_buff *skb;
	u8 dest_hw[UBL_ALEN];

	skb = alloc_skb(ip_notify_hdr_len() + hlen + tlen, GFP_ATOMIC);
	if (!skb)
		return NULL;

	skb_reserve(skb, LL_RESERVED_SPACE(ndev));
	skb_reset_network_header(skb);
	ipn_hdr_v4 = (struct ip_notify_hdr *)skb_put(skb, ip_notify_hdr_len());
	memset(ipn_hdr_v4, 0, ip_notify_hdr_len());
	skb->dev = ndev;
	skb->protocol = htons(ETH_P_UB);
	src_hw = ndev->dev_addr;
	memset(dest_hw, 0xff, UBL_ALEN);

	/* fill the device header for the ipv4 notify frame */
	ipn_hdr_v4->cfg = UB_NOIP_CFG_TYPE;
	ipn_hdr_v4->protocol = htons(SUB_PROTOCOL_IP_NOTIFY);
	memcpy(ipn_hdr_v4->dest_guid, dest_hw, UBL_ALEN);
	memcpy(ipn_hdr_v4->src_guid, ndev->dev_addr, UBL_ALEN);
	ipn_hdr_v4->pdu.ver = UB_PROTO_IPV4 << VER_SHIFT_4; /* IPv4 */
	ipn_hdr_v4->pdu.mask = netmask;
	ipn_hdr_v4->pdu.ipv4.ip = src_ip;

	show_ip_notify_pkt_info(skb);

	return skb;
}

struct sk_buff *ub_ipv6_create_ip_notify_pkt(struct net_device *ndev,
					     u8 *src_ip, const u8 *src_hw,
					     __be32 netmask)
{
	int hlen = LL_RESERVED_SPACE(ndev);
	int tlen = ndev->needed_tailroom;
	struct ip_notify_hdr *ipn_hdr_v6;
	struct sk_buff *skb;
	u8 dest_hw[UBL_ALEN];

	skb = alloc_skb(ip_notify_hdr_len() + hlen + tlen, GFP_ATOMIC);
	if (!skb)
		return NULL;

	skb_reserve(skb, LL_RESERVED_SPACE(ndev));
	skb_reset_network_header(skb);
	ipn_hdr_v6 = (struct ip_notify_hdr *)skb_put(skb, ip_notify_hdr_len());
	memset(ipn_hdr_v6, 0, ip_notify_hdr_len());
	skb->dev = ndev;
	skb->protocol = htons(ETH_P_UB);
	src_hw = ndev->dev_addr;
	memset(dest_hw, 0xff, UBL_ALEN);

	/* fill the device header for the ip notify frame */
	ipn_hdr_v6->cfg = UB_NOIP_CFG_TYPE;
	ipn_hdr_v6->protocol = htons(SUB_PROTOCOL_IP_NOTIFY);
	memcpy(ipn_hdr_v6->dest_guid, dest_hw, UBL_ALEN);
	memcpy(ipn_hdr_v6->src_guid, ndev->dev_addr, UBL_ALEN);
	ipn_hdr_v6->pdu.ver = UB_PROTO_IPV6 << VER_SHIFT_4; /* IPv6 */
	ipn_hdr_v6->pdu.mask = netmask;
	memcpy(ipn_hdr_v6->pdu.ipv6.ip, src_ip, UBL_ALEN);

	show_ip_notify_pkt_info(skb);

	return skb;
}

static void ub_update_tx_stats(int ptype, struct sk_buff *skb, int rc)
{
	struct list_head *dev_list = ub_nm_get_dev_list();
	struct net_device *ndev = skb->dev;
	struct ub_nm_device *nm_dev;

	ub_nm_down_read();
	list_for_each_entry(nm_dev, dev_list, nm_dev_list)
		if (nm_dev->ndev == ndev)
			goto out;
	ub_nm_up_read();

	return;

out:
	switch (rc) {
	case NETDEV_TX_OK:
		if (ptype == UB_PROTO_IPV4)
			atomic64_inc(&nm_dev->sys_ctx.ip_notify_ctx.stats.good_ipv4_notify_tx_cnt);
		else
			atomic64_inc(&nm_dev->sys_ctx.ip_notify_ctx.stats.good_ipv6_notify_tx_cnt);
		break;
	case NET_XMIT_DROP:
	case NETDEV_TX_BUSY:
		if (ptype == UB_PROTO_IPV4)
			atomic64_inc(&nm_dev->sys_ctx.ip_notify_ctx.stats.bad_ipv4_notify_tx_cnt);
		else
			atomic64_inc(&nm_dev->sys_ctx.ip_notify_ctx.stats.bad_ipv6_notify_tx_cnt);
		break;
	default:
		break;
	}
	ub_nm_up_read();
}

static void ub_xmit_ip_notify_pkt(int ptype, struct sk_buff *skb)
{
	int rc;

	rc = dev_queue_xmit(skb);
	ub_update_tx_stats(ptype, skb, rc);
}

static void ub_ipv4_send_ip_notify(struct net_device *ndev,
				   struct in_ifaddr *ifa)
{
	__be32 netmask = ifa->ifa_prefixlen;
	const u8 *src_hw = ndev->dev_addr;
	__be32 src_ip = ifa->ifa_address;
	struct sk_buff *skb;

	skb = ub_ipv4_create_ip_notify_pkt(ndev, src_ip, src_hw, netmask);
	if (!skb) {
		netdev_err(ndev, "failed to create ip notify pkt.\n");
		return;
	}

	ub_xmit_ip_notify_pkt(UB_PROTO_IPV4, skb);
}

int ub_ipv4_notify_event(struct notifier_block *nb, unsigned long event,
			 void *ptr)
{
	struct net_device *event_ndev;
	struct in_device *in_dev;
	struct in_ifaddr *ifa;

	ifa = (struct in_ifaddr *)ptr;
	event_ndev = ifa->ifa_dev->dev;

	if (event_ndev->type != ARPHRD_UB)
		return NOTIFY_DONE;

	netdev_info(event_ndev, "ub_ipv4_event: 0x%lx\n", event);

	if (event != NETDEV_UP)
		return NOTIFY_DONE;

	in_dev = __in_dev_get_rtnl(event_ndev);
	if (!IN_DEV_ARP_NOTIFY(in_dev))
		return NOTIFY_DONE;

	if (event_ndev->flags & IFF_UP) {
		netdev_info(event_ndev, "ub_ipv4_send_ip_notify.\n");
		ub_ipv4_send_ip_notify(event_ndev, ifa);
	}

	return NOTIFY_DONE;
}

static void ub_ipv6_send_ip_notify(struct net_device *ndev,
				   struct inet6_ifaddr *ifa6)
{
	const u8 *src_hw = ndev->dev_addr;
	__be32 netmask = ifa6->prefix_len;
	struct sk_buff *skb;
	u8 src_ip[IPV6_ADDR_LEN];

	memcpy(src_ip, &ifa6->addr, IPV6_ADDR_LEN);
	skb = ub_ipv6_create_ip_notify_pkt(ndev, src_ip, src_hw, netmask);
	if (!skb) {
		netdev_err(ndev, "failed to create ipv6 notify pkt.\n");
		return;
	}

	ub_xmit_ip_notify_pkt(UB_PROTO_IPV6, skb);
}

int ub_ipv6_notify_event(struct notifier_block *nb, unsigned long event,
			 void *ptr)
{
	struct inet6_ifaddr *ifa6 = (struct inet6_ifaddr *)ptr;
	struct net_device *event_ndev = ifa6->idev->dev;

	if (event_ndev->type != ARPHRD_UB)
		return NOTIFY_DONE;

	netdev_info(event_ndev, "ub_ipv6_event: 0x%lx\n", event);

	if (event != NETDEV_UP)
		return NOTIFY_DONE;

	if (event_ndev->flags & IFF_UP) {
		netdev_info(event_ndev, "ub_ipv6_send_ip_notify.\n");
		ub_ipv6_send_ip_notify(event_ndev, ifa6);
	}

	return NOTIFY_DONE;
}

static void ub_send_ip_notify(struct net_device *ndev)
{
	struct inet6_dev *in6_dev;
	struct inet6_ifaddr *i6fa;
	struct in_device *in_dev;
	struct in_ifaddr *ifa;

	if (!ndev || !(ndev->flags & IFF_UP))
		return;

	in_dev = in_dev_get(ndev);
	if (in_dev) {
		if (IN_DEV_ARP_NOTIFY(in_dev))
			in_dev_for_each_ifa_rcu(ifa, in_dev)
				ub_ipv4_send_ip_notify(ndev, ifa);
		in_dev_put(in_dev);
	}

	in6_dev = in6_dev_get(ndev);
	if (!in6_dev)
		return;

	list_for_each_entry(i6fa, &in6_dev->addr_list, if_list)
		ub_ipv6_send_ip_notify(ndev, i6fa);
	in6_dev_put(in6_dev);
}

static int ip_notify_enable;
static int ip_notify_tx_hold = 1;
static int ip_notify_tx_hold_max = (INT_MAX / IP_NOTIFY_TIMEOUT_MS);

static struct ctl_table_header *sysctl_header;
static struct ctl_table ip_notify_sysctl[] = {
	{
		.procname	= "ip_notify_enable",
		.data		= &ip_notify_enable,
		.maxlen		= sizeof(ip_notify_enable),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "ip_notify_tx_hold",
		.data		= &ip_notify_tx_hold,
		.maxlen		= sizeof(ip_notify_tx_hold),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ONE,
		.extra2		= &ip_notify_tx_hold_max,
	},
	{ }
};

static const struct ctl_path ip_notify_sysctl_path[] = {
	{ .procname = "ub_network_mgmt", },
	{ .procname = "ip_notify", },
	{ }
};

static int ub_ip_notify_sysctl_init(void)
{
	sysctl_header = register_sysctl_paths(ip_notify_sysctl_path,
					      ip_notify_sysctl);
	if (sysctl_header)
		return 0;

	pr_warn("ip_notify sysctl init failed!\n");
	return 1;
}

static void ub_ip_notify_sysctl_uninit(void)
{
	unregister_sysctl_table(sysctl_header);
	sysctl_header = NULL;
}

static struct timer_list ip_notify_timer;

static void poll_ub_dev_list_send_pkt(struct work_struct *work)
{
	struct list_head *dev_list = ub_nm_get_dev_list();
	struct ub_nm_device *nm_dev;

	ub_nm_down_read();
	list_for_each_entry(nm_dev, dev_list, nm_dev_list)
		ub_send_ip_notify(nm_dev->ndev);
	ub_nm_up_read();

	kfree(work);
}

static void ub_ip_notify_handle_timeout(struct timer_list *timer)
{
	struct work_struct *ip_notify_work;

	if (!ip_notify_enable) {
		mod_timer(timer,
			  jiffies + msecs_to_jiffies(IP_NOTIFY_TIMEOUT_MS));
		return;
	}

	ip_notify_work = kzalloc(sizeof(*ip_notify_work), GFP_ATOMIC);
	if (!ip_notify_work)
		goto out;

	INIT_WORK(ip_notify_work, poll_ub_dev_list_send_pkt);
	queue_work(ip_notify_wq, ip_notify_work);

out:
	mod_timer(timer, jiffies + msecs_to_jiffies(ip_notify_tx_hold *
						    IP_NOTIFY_TIMEOUT_MS));
}

static void ub_ip_notify_timer_init(void)
{
	timer_setup(&ip_notify_timer, ub_ip_notify_handle_timeout, 0);
	ip_notify_timer.expires = jiffies + msecs_to_jiffies(IP_NOTIFY_TIMEOUT_MS);
	add_timer(&ip_notify_timer);
}

static void ub_ip_notify_timer_uninit(void)
{
	del_timer_sync(&ip_notify_timer);
}

int ub_ip_notify_init(struct ub_nm_device *nm_dev)
{
	int ret;

	if (initialized)
		goto sysfs_create;

	if (!ip_notify_wq) {
		ip_notify_wq = create_singlethread_workqueue("ip_notify_wq");
		if (!ip_notify_wq) {
			pr_err("failed to create ip_notify_wq.\n");
			return -ENOMEM;
		}
	}

	ub_ip_notify_timer_init();
	if (ub_ip_notify_sysctl_init())
		goto error;

	initialized = 1;

sysfs_create:
	ret = ip_notify_sysfs_create(nm_dev);
	if (ret) {
		netdev_err(nm_dev->ndev,
			   "failed to create ip notify sysfs, ret = %d\n", ret);
		return ret;
	}

	netdev_info(nm_dev->ndev, "ub ip notify init success.\n");

	return 0;

error:
	ub_ip_notify_timer_uninit();
	destroy_workqueue(ip_notify_wq);
	ip_notify_wq = NULL;
	return -ENOMEM;
}

void ub_ip_notify_uninit(struct ub_nm_device *nm_dev)
{
	struct list_head *dev_list = ub_nm_get_dev_list();

	ip_notify_sysfs_destroy(nm_dev);

	if (list_empty(dev_list)) {
		ub_ip_notify_timer_uninit();
		ub_ip_notify_sysctl_uninit();
		if (ip_notify_wq) {
			destroy_workqueue(ip_notify_wq);
			ip_notify_wq = NULL;
		}
		initialized = 0;
	}
}
