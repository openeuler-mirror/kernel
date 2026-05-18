// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netdev_features.h>
#include <linux/ethtool.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/rtnetlink.h>
#include <linux/oenetcls.h>
#include "oenetcls.h"

int oecls_netdev_num;
static struct oecls_netdev_info oecls_netdev_info_table[OECLS_MAX_NETDEV_NUM];

int oecls_numa_num;
static int oecls_cluster_cpu_num, oecls_cluster_per_numa;
static struct oecls_numa_info *oecls_numa_info_table;

int debug;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "debug switch");

int mode;
module_param(mode, int, 0444);
MODULE_PARM_DESC(mode, "mode, default 0");

static char ifname[128] = { 0 };
module_param_string(ifname, ifname, sizeof(ifname), 0444);
MODULE_PARM_DESC(ifname, "ifname");

static char appname[256] = "redis-server";
module_param_string(appname, appname, sizeof(appname), 0644);
MODULE_PARM_DESC(appname, "appname, default redis-server");

int match_ip_flag = 1;
module_param(match_ip_flag, int, 0644);
MODULE_PARM_DESC(match_ip_flag, "match ip flag");

static int strategy;
module_param(strategy, int, 0444);
MODULE_PARM_DESC(strategy, "strategy, default 0");

static int check_cap = 1;
module_param(check_cap, int, 0444);
MODULE_PARM_DESC(check_cap, "check_cap, default 1");

int rcpu_probability = -1;
module_param(rcpu_probability, int, 0444);
MODULE_PARM_DESC(rcpu_probability, "rcpu select policy probability, default -1");

static char irqname[64] = "comp";
module_param_string(irqname, irqname, sizeof(irqname), 0644);
MODULE_PARM_DESC(irqname, "nic irq name string, default comp");

int check_nic_feature = 1;
module_param(check_nic_feature, int, 0444);
MODULE_PARM_DESC(check_nic_feature, "check nic feature, default 1");

unsigned int dft_num = 0x1000;
module_param(dft_num, uint, 0444);
MODULE_PARM_DESC(dft_num, "dev flow table entries, default 0x1000");

unsigned int sft_num = 0x100000;
module_param(sft_num, uint, 0444);
MODULE_PARM_DESC(sft_num, "sock flow table entries, default 0x100000");

int rps_policy = 1;
module_param(rps_policy, int, 0644);
MODULE_PARM_DESC(rps_policy, "phy nic rps policy, default 1");

int lo_rps_policy;
module_param(lo_rps_policy, int, 0644);
MODULE_PARM_DESC(lo_rps_policy, "loopback rps policy, default 0");

static int rxq_multiplex_limit = 1;
module_param(rxq_multiplex_limit, int, 0444);
MODULE_PARM_DESC(rxq_multiplex_limit, "rxq multiplex limit num, default 1");

static bool check_params(void)
{
	if (mode != 0 && mode != 1 && mode != 2)
		return false;

	if (strlen(ifname) == 0)
		return false;

	return true;
}

int check_appname(char *task_name)
{
	char *start = appname, *end;

	if (!strlen(appname))
		return 0;

	// support appname: app1#app2#appN
	while (*start != '\0') {
		end = strchr(start, '#');
		if (end == start) {
			start++;
			continue;
		}

		if (!end) {
			if (!strncmp(task_name, start, strlen(start)))
				return 0;
			break;
		}

		if (!strncmp(task_name, start, end - start))
			return 0;
		start = end + 1;
	}
	return -EOPNOTSUPP;
}

static u32 __ethtool_get_flags(struct net_device *dev)
{
	u32 flags = 0;

	if (dev->features & NETIF_F_LRO)
		flags |= ETH_FLAG_LRO;
	if (dev->features & NETIF_F_HW_VLAN_CTAG_RX)
		flags |= ETH_FLAG_RXVLAN;
	if (dev->features & NETIF_F_HW_VLAN_CTAG_TX)
		flags |= ETH_FLAG_TXVLAN;
	if (dev->features & NETIF_F_NTUPLE)
		flags |= ETH_FLAG_NTUPLE;
	if (dev->features & NETIF_F_RXHASH)
		flags |= ETH_FLAG_RXHASH;

	return flags;
}

static int __ethtool_set_flags(struct net_device *dev, u32 data)
{
	netdev_features_t features = 0, changed;

	if (data & ~ETH_ALL_FLAGS)
		return -EINVAL;

	if (data & ETH_FLAG_LRO)
		features |= NETIF_F_LRO;
	if (data & ETH_FLAG_RXVLAN)
		features |= NETIF_F_HW_VLAN_CTAG_RX;
	if (data & ETH_FLAG_TXVLAN)
		features |= NETIF_F_HW_VLAN_CTAG_TX;
	if (data & ETH_FLAG_NTUPLE)
		features |= NETIF_F_NTUPLE;
	if (data & ETH_FLAG_RXHASH)
		features |= NETIF_F_RXHASH;

	/* allow changing only bits set in hw_features */
	changed = (features ^ dev->features) & ETH_ALL_FEATURES;
	if (changed & ~dev->hw_features)
		return (changed & dev->hw_features) ? -EINVAL : -EOPNOTSUPP;

	dev->wanted_features =
		(dev->wanted_features & ~changed) | (features & changed);

	__netdev_update_features(dev);

	return 0;
}

static void ethtool_rxnfc_copy_to_user(void *useraddr,
				       const struct ethtool_rxnfc *rxnfc,
				       size_t size, const u32 *rule_buf)
{
	memcpy_r(useraddr, rxnfc, size);
	useraddr += offsetof(struct ethtool_rxnfc, rule_locs);

	if (rule_buf)
		memcpy_r(useraddr, rule_buf, rxnfc->rule_cnt * sizeof(u32));
}

static noinline_for_stack int ethtool_set_rxnfc(struct net_device *dev,
						u32 cmd, void *useraddr)
{
	struct ethtool_rxnfc info;
	size_t info_size = sizeof(info);
	int rc;

	if (!dev->ethtool_ops->set_rxnfc)
		return -EOPNOTSUPP;

	if (cmd == ETHTOOL_SRXFH)
		info_size = (offsetof(struct ethtool_rxnfc, data) +
			     sizeof(info.data));

	memcpy_r(&info, useraddr, info_size);
	rc = dev->ethtool_ops->set_rxnfc(dev, &info);
	if (rc)
		return rc;

	if (cmd == ETHTOOL_SRXCLSRLINS)
		ethtool_rxnfc_copy_to_user(useraddr, &info, info_size, NULL);

	return 0;
}

static noinline_for_stack int ethtool_get_rxnfc(struct net_device *dev,
						u32 cmd, void *useraddr)
{
	struct ethtool_rxnfc info;
	size_t info_size = sizeof(info);
	const struct ethtool_ops *ops = dev->ethtool_ops;
	int ret;
	void *rule_buf = NULL;

	if (!ops->get_rxnfc)
		return -EOPNOTSUPP;

	if (cmd == ETHTOOL_GRXFH)
		info_size = (offsetof(struct ethtool_rxnfc, data) +
			     sizeof(info.data));

	memcpy_r(&info, useraddr, info_size);

	/* If FLOW_RSS was requested then user-space must be using the
	 * new definition, as FLOW_RSS is newer.
	 */
	if (cmd == ETHTOOL_GRXFH && info.flow_type & FLOW_RSS) {
		info_size = sizeof(info);
		memcpy_r(&info, useraddr, info_size);
		/* Since malicious users may modify the original data,
		 * we need to check whether FLOW_RSS is still requested.
		 */
		if (!(info.flow_type & FLOW_RSS))
			return -EINVAL;
	}

	if (info.cmd != cmd)
		return -EINVAL;

	if (info.cmd == ETHTOOL_GRXCLSRLALL) {
		if (info.rule_cnt > 0) {
			if (info.rule_cnt <= KMALLOC_MAX_SIZE / sizeof(u32))
				rule_buf = kcalloc(info.rule_cnt, sizeof(u32),
						   GFP_KERNEL);
			if (!rule_buf)
				return -ENOMEM;
		}
	}

	ret = ops->get_rxnfc(dev, &info, rule_buf);
	if (ret < 0)
		goto err_out;

	ethtool_rxnfc_copy_to_user(useraddr, &info, info_size, rule_buf);
err_out:
	kfree(rule_buf);

	return ret;
}

static noinline_for_stack int ethtool_get_channels(struct net_device *dev,
						   void *useraddr)
{
	struct ethtool_channels channels = { .cmd = ETHTOOL_GCHANNELS };

	if (!dev->ethtool_ops->get_channels)
		return -EOPNOTSUPP;

	dev->ethtool_ops->get_channels(dev, &channels);
	memcpy_r(useraddr, &channels, sizeof(channels));
	return 0;
}

static int ethtool_get_value(struct net_device *dev, char *useraddr,
			     u32 cmd, u32 (*actor)(struct net_device *))
{
	struct ethtool_value edata = { .cmd = cmd };

	if (!actor)
		return -EOPNOTSUPP;

	edata.data = actor(dev);

	memcpy_r(useraddr, &edata, sizeof(edata));
	return 0;
}

static int ethtool_set_value(struct net_device *dev, char *useraddr,
			     int (*actor)(struct net_device *, u32))
{
	struct ethtool_value edata;

	if (!actor)
		return -EOPNOTSUPP;

	memcpy_r(&edata, useraddr, sizeof(edata));

	return actor(dev, edata.data);
}

static int dev_ethtool_kern(struct net *net, struct ifreq *ifr)
{
	struct net_device *dev = __dev_get_by_name(net, ifr->ifr_name);
	void *useraddr = ifr->ifr_data;
	u32 ethcmd, sub_cmd;
	int rc;
	netdev_features_t old_features;

	if (!dev || !netif_device_present(dev))
		return -ENODEV;

	memcpy_r(&ethcmd, useraddr, sizeof(ethcmd));

	if (ethcmd == ETHTOOL_PERQUEUE)
		memcpy_r(&sub_cmd, useraddr + sizeof(ethcmd), sizeof(sub_cmd));
	else
		sub_cmd = ethcmd;

	/* Allow some commands to be done by anyone */
	switch (sub_cmd) {
	case ETHTOOL_GFLAGS:
	case ETHTOOL_GRXFH:
	case ETHTOOL_GRXRINGS:
	case ETHTOOL_GRXCLSRLCNT:
	case ETHTOOL_GRXCLSRULE:
	case ETHTOOL_GRXCLSRLALL:
	case ETHTOOL_GCHANNELS:
		break;
	default:
		if (check_cap && !ns_capable(net->user_ns, CAP_NET_ADMIN))
			return -EPERM;
	}

	if (dev->ethtool_ops->begin) {
		rc = dev->ethtool_ops->begin(dev);
		if (rc  < 0)
			return rc;
	}
	old_features = dev->features;

	switch (ethcmd) {
	case ETHTOOL_GFLAGS:
		rc = ethtool_get_value(dev, useraddr, ethcmd,
				       __ethtool_get_flags);
		break;
	case ETHTOOL_SFLAGS:
		rc = ethtool_set_value(dev, useraddr, __ethtool_set_flags);
		break;
	case ETHTOOL_GRXFH:
	case ETHTOOL_GRXRINGS:
	case ETHTOOL_GRXCLSRLCNT:
	case ETHTOOL_GRXCLSRULE:
	case ETHTOOL_GRXCLSRLALL:
		rc = ethtool_get_rxnfc(dev, ethcmd, useraddr);
		break;
	case ETHTOOL_SRXFH:
	case ETHTOOL_SRXCLSRLDEL:
	case ETHTOOL_SRXCLSRLINS:
		rc = ethtool_set_rxnfc(dev, ethcmd, useraddr);
		break;
	case ETHTOOL_GCHANNELS:
		rc = ethtool_get_channels(dev, useraddr);
		break;
	default:
		rc = -EOPNOTSUPP;
	}

	if (dev->ethtool_ops->complete)
		dev->ethtool_ops->complete(dev);

	if (old_features != dev->features)
		netdev_features_change(dev);

	return rc;
}

int send_ethtool_ioctl(struct cmd_context *ctx, void *cmd)
{
	struct ifreq ifr = {0};
	int ret;

	strncpy(ifr.ifr_name, ctx->netdev, sizeof(ctx->netdev));
	ifr.ifr_data = cmd;

	rtnl_lock();
	ret = dev_ethtool_kern(&init_net, &ifr);
	rtnl_unlock();

	return ret;
}

struct oecls_netdev_info *get_oecls_netdev_info(unsigned int index)
{
	if (index >= OECLS_MAX_NETDEV_NUM)
		return NULL;
	return &oecls_netdev_info_table[index];
}

static struct oecls_netdev_info *alloc_oecls_netdev_info(void)
{
	if (oecls_netdev_num >= OECLS_MAX_NETDEV_NUM)
		return NULL;

	return &oecls_netdev_info_table[oecls_netdev_num++];
}

static bool check_irq_name(const char *irq_name, struct oecls_netdev_info *oecls_dev)
{
	if (!strstr(irq_name, "TxRx") && !strstr(irq_name, "comp") && !strstr(irq_name, "rx") &&
	    !strstr(irq_name, "virtio0-input") && strlen(irqname) > 0 && !strstr(irq_name, irqname))
		return false;

	if (strstr(irq_name, oecls_dev->dev_name))
		return true;

	if (oecls_dev->netdev->dev.parent &&
	    strstr(irq_name, dev_name(oecls_dev->netdev->dev.parent)))
		return true;

	return false;
}

static void get_netdev_queue_info(struct oecls_netdev_info *oecls_dev)
{
	struct oecls_netdev_queue_info *rxq_info;
	struct ethtool_channels echannels = {0};
	int irq, cpu, ret, combined_channels;
	struct cmd_context ctx = {0};
	struct irq_desc *desc;

	strscpy(ctx.netdev, oecls_dev->dev_name, IFNAMSIZ);
	echannels.cmd = ETHTOOL_GCHANNELS;
	ret = send_ethtool_ioctl(&ctx, &echannels);
	if (ret) {
		oecls_error("get %s channels fail ret:%d\n", oecls_dev->dev_name, ret);
		return;
	}

	combined_channels = echannels.combined_count;

	for_each_irq_desc(irq, desc) {
		if (!desc->action)
			continue;
		if (!desc->action->name)
			continue;
		if (!check_irq_name(desc->action->name, oecls_dev))
			continue;
		if (oecls_dev->rxq_num >= OECLS_MAX_RXQ_NUM_PER_DEV)
			break;
		if (oecls_dev->rxq_num > combined_channels - 1)
			break;
		oecls_debug("rxq_num:%d channels:%d\n", oecls_dev->rxq_num, combined_channels);

		rxq_info = &oecls_dev->rxq[oecls_dev->rxq_num++];
		rxq_info->irq = irq;
		cpu = cpumask_first(irq_data_get_effective_affinity_mask(&desc->irq_data));
		rxq_info->affinity_cpu = cpu;
		oecls_debug("irq=%d, [%s], rxq_id=%d affinity_cpu:%d\n",
			    irq, desc->action->name, oecls_dev->rxq_num - 1, cpu);
	}
}

static int oecls_filter_enable(const char *dev_name, bool *old_state)
{
	struct ethtool_value eval = {0};
	struct cmd_context ctx = {0};
	int ret;

	if (!check_nic_feature)
		return 0;

	strncpy(ctx.netdev, dev_name, IFNAMSIZ);

	eval.cmd = ETHTOOL_GFLAGS;
	ret = send_ethtool_ioctl(&ctx, &eval);
	if (ret != 0) {
		oecls_error("get %s flags fail, ret:%d\n", dev_name, ret);
		return ret;
	}
	if (eval.data & ETH_FLAG_NTUPLE) {
		*old_state = true;
		oecls_debug("%s ntuple is already on\n", dev_name);
		return 0;
	}

	// Set ntuple feature
	eval.cmd = ETHTOOL_SFLAGS;
	eval.data |= ETH_FLAG_NTUPLE;
	ret = send_ethtool_ioctl(&ctx, &eval);
	if (ret != 0) {
		oecls_error("set %s flags fail, ret:%d\n", dev_name, ret);
		return ret;
	}

	// Get ntuple feature
	eval.cmd = ETHTOOL_GFLAGS;
	eval.data = 0;
	ret = send_ethtool_ioctl(&ctx, &eval);
	if (ret != 0) {
		oecls_error("get %s flags fail, ret:%d\n", dev_name, ret);
		return ret;
	}
	if (!(eval.data & ETH_FLAG_NTUPLE)) {
		oecls_error("enable ntuple feature fail!\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

static void oecls_filter_restore(const char *dev_name, bool old_state)
{
	struct ethtool_value eval = {0};
	struct cmd_context ctx = {0};
	bool cur_filter_state;
	int ret;

	if (!check_nic_feature)
		return;

	strncpy(ctx.netdev, dev_name, IFNAMSIZ);

	eval.cmd = ETHTOOL_GFLAGS;
	ret = send_ethtool_ioctl(&ctx, &eval);
	if (ret != 0) {
		oecls_error("get %s flags fail, ret:%d\n", dev_name, ret);
		return;
	}

	cur_filter_state = (eval.data & ETH_FLAG_NTUPLE) ? true : false;
	if (cur_filter_state == old_state)
		return;

	// Set ntuple feature
	eval.cmd = ETHTOOL_SFLAGS;
	if (old_state)
		eval.data |= ETH_FLAG_NTUPLE;
	else
		eval.data &= ~ETH_FLAG_NTUPLE;
	ret = send_ethtool_ioctl(&ctx, &eval);
	if (ret != 0) {
		oecls_error("set %s flags fail, ret:%d\n", dev_name, ret);
		return;
	}
}

static int init_single_oecls_dev(char *if_name, unsigned int length)
{
	struct oecls_netdev_info *oecls_dev;
	char dev_name[IFNAMSIZ] = { 0 };
	struct net_device *netdev;
	int cpy_len = length < IFNAMSIZ ? length : IFNAMSIZ;
	bool old_state = false;
	int ret;

	strncpy(dev_name, if_name, cpy_len);
	netdev = dev_get_by_name(&init_net, dev_name);
	if (!netdev) {
		oecls_error("dev [%s] is not exist!\n", dev_name);
		return -ENODEV;
	}

	if (!(netdev->flags & IFF_UP)) {
		ret = -ENETDOWN;
		oecls_error("dev:%s not up! flags=%d.\n", dev_name, netdev->flags);
		goto out;
	}

	if (netdev->flags & IFF_LOOPBACK) {
		ret = -EOPNOTSUPP;
		oecls_error("Do not support loopback.\n");
		goto out;
	}

	if (mode != 2) {
		ret = oecls_filter_enable(dev_name, &old_state);
		if (ret) {
			oecls_error("dev [%s] not support ntuple! ret=%d\n", dev_name, ret);
			if (lo_rps_policy)
				goto out;
		}
	}

	oecls_dev = alloc_oecls_netdev_info();
	if (!oecls_dev) {
		ret = -ENOMEM;
		oecls_filter_restore(dev_name, old_state);
		oecls_error("alloc oecls_dev fail! oecls_netdev_num:%d\n", oecls_netdev_num);
		goto out;
	}

	memcpy_r(oecls_dev->dev_name, dev_name, IFNAMSIZ);
	oecls_dev->old_filter_state = old_state;
	oecls_dev->netdev = netdev;
	get_netdev_queue_info(oecls_dev);
	return 0;

out:
	dev_put(netdev);
	return ret;
}

static void clean_oecls_netdev_info(void)
{
	struct oecls_netdev_info *oecls_dev;
	struct net_device *netdev;
	int devid;

	for_each_oecls_netdev(devid, oecls_dev) {
		oecls_filter_restore(oecls_dev->dev_name, oecls_dev->old_filter_state);
		netdev = oecls_dev->netdev;
		if (netdev) {
			oecls_dev->netdev = NULL;
			dev_put(netdev);
		}
	}

	oecls_netdev_num = 0;
}

static int init_oecls_netdev_info(char *netdev_str)
{
	char *start = netdev_str, *end;
	int err = -ENODEV;

	while (*start != '\0') {
		// skip start #
		end = strchr(start, '#');
		if (end == start) {
			start++;
			continue;
		}

		// find the last ifname
		if (!end) {
			err = init_single_oecls_dev(start, strlen(start));
			break;
		}

		err = init_single_oecls_dev(start, end - start);
		if (err)
			break;
		start = end + 1;
	}

	return err;
}

struct oecls_numa_info *get_oecls_numa_info(unsigned int nid)
{
	if (nid >= oecls_numa_num)
		return NULL;
	return &oecls_numa_info_table[nid];
}

static void clean_oecls_numa_info(void)
{
	oecls_numa_num = 0;
	kfree(oecls_numa_info_table);
}

static void init_numa_avail_cpus(int nid, struct oecls_numa_info *numa_info)
{
	int cpu;

	oecls_debug("numa node %d: %*pb, %*pbl\n", nid, cpumask_pr_args(cpumask_of_node(nid)),
		    cpumask_pr_args(cpumask_of_node(nid)));

	bitmap_zero(numa_info->avail_cpus, OECLS_MAX_CPU_NUM);
	for_each_cpu(cpu, cpumask_of_node(nid)) {
		if (cpu >= OECLS_MAX_CPU_NUM)
			return;
		set_bit(cpu, numa_info->avail_cpus);
	}
}

static void clean_oecls_rxq(void)
{
	struct oecls_numa_bound_dev_info *bound_dev;
	struct oecls_netdev_info *oecls_dev;
	struct oecls_numa_info *numa_info;
	int nid, devid;

	for_each_oecls_numa(nid, numa_info) {
		for_each_oecls_netdev(devid, oecls_dev) {
			bound_dev = &numa_info->bound_dev[devid];
			kfree(bound_dev->cluster_info);
		}
	}
}

static int init_numa_rxq_bitmap(int nid, struct oecls_numa_info *numa_info)
{
	int bound_rxq_num, cluster_id, cluster_idx, cur_idx;
	struct oecls_numa_bound_dev_info *bound_dev;
	struct oecls_netdev_info *oecls_dev;
	int i, j, rxq_id, devid, cpu, ret = 0;

	for_each_oecls_netdev(devid, oecls_dev) {
		bound_rxq_num = 0;
		bound_dev = &numa_info->bound_dev[devid];
		memset(bound_dev->bitmap_rxq, RXQ_MAX_USECNT, sizeof(bound_dev->bitmap_rxq));
		bound_dev->cluster_info = kcalloc(oecls_cluster_per_numa,
						  sizeof(*bound_dev->cluster_info), GFP_ATOMIC);
		if (!bound_dev->cluster_info) {
			ret = -ENOMEM;
			goto out;
		}

		for (i = 0; i < oecls_cluster_per_numa; i++) {
			for (j = 0; j < OECLS_MAX_RXQ_NUM_PER_DEV; j++) {
				bound_dev->cluster_info[i].rxqs[j].rxq_id = -1;
				bound_dev->cluster_info[i].rxqs[j].status = RXQ_MAX_USECNT;
			}
		}

		for (rxq_id = 0; rxq_id < oecls_dev->rxq_num; rxq_id++) {
			cpu = oecls_dev->rxq[rxq_id].affinity_cpu;
			if (cpu_to_node(cpu) == nid) {
				bound_dev->bitmap_rxq[rxq_id] = 0;
				cluster_id = cpu / oecls_cluster_cpu_num;
				cluster_idx = cluster_id % oecls_cluster_per_numa;
				bound_dev->cluster_info[cluster_idx].cluster_id = cluster_id;
				cur_idx = bound_dev->cluster_info[cluster_idx].cur_freeidx++;
				bound_dev->cluster_info[cluster_idx].rxqs[cur_idx].rxq_id = rxq_id;
				bound_dev->cluster_info[cluster_idx].rxqs[cur_idx].status = 0;
				bound_rxq_num++;
				oecls_debug("cpu:%d cluster_id:%d cluster_idx:%d rxq_id:%d cur_idx:%d\n",
					    cpu, cluster_id, cluster_idx, rxq_id, cur_idx);
			}
		}

		oecls_debug("nid:%d, dev_id:%d, dev:%s, rxq_num:%d, bound_rxq_num:%d\n",
			    nid, devid, oecls_dev->dev_name, oecls_dev->rxq_num, bound_rxq_num);
	}
	return ret;

out:
	clean_oecls_rxq();
	return ret;
}

static int get_cluster_rxq(struct oecls_numa_bound_dev_info *bound_dev, int cpu)
{
	int cluster_id = cpu / oecls_cluster_cpu_num;
	int min_used_count = RXQ_MAX_USECNT;
	int i, j, rxq_id;

	for (i = 0; i < oecls_cluster_per_numa; i++) {
		if (cluster_id != bound_dev->cluster_info[i].cluster_id)
			continue;
		for (j = 0; j < OECLS_MAX_RXQ_NUM_PER_DEV; j++) {
			if (bound_dev->cluster_info[i].rxqs[j].rxq_id == -1)
				continue;
			if (bound_dev->cluster_info[i].rxqs[j].status < min_used_count) {
				min_used_count = bound_dev->cluster_info[i].rxqs[j].status;
				break;
			}
		}
		if (min_used_count >= RXQ_MAX_USECNT || min_used_count >= rxq_multiplex_limit) {
			rxq_id = -1;
			oecls_debug("cluster:%d no free rxq for cpu:%d\n", cluster_id, cpu);
		} else {
			rxq_id = bound_dev->cluster_info[i].rxqs[j].rxq_id;
			bound_dev->cluster_info[i].rxqs[j].status++;
			oecls_debug("cluster:%d cpu:%d alloc rxq_id:%d use:%d\n", cluster_id, cpu,
				    rxq_id, bound_dev->cluster_info[i].rxqs[j].status);
		}
	}
	oecls_debug("allcluster:%d rxq:%d for cpu:%d\n", cluster_id, rxq_id, cpu);

	return rxq_id;
}

static int put_cluster_rxq(struct oecls_numa_bound_dev_info *bound_dev, int rxq_id)
{
	int i, j;

	for (i = 0; i < oecls_cluster_per_numa; i++) {
		for (j = 0; j < OECLS_MAX_RXQ_NUM_PER_DEV; j++) {
			if (bound_dev->cluster_info[i].rxqs[j].status > 0 &&
			    bound_dev->cluster_info[i].rxqs[j].rxq_id == rxq_id) {
				bound_dev->cluster_info[i].rxqs[j].status--;
				oecls_debug("free rxq_id:%d use:%d\n", rxq_id,
					    bound_dev->cluster_info[i].rxqs[j].status);
				return 0;
			}
		}
	}
	oecls_debug("no match malloced rxq_id:%d\n", rxq_id);
	return -1;
}

int alloc_rxq_id(int cpu, int devid)
{
	struct oecls_numa_bound_dev_info *bound_dev;
	int i, rxq_id, min_used_count = RXQ_MAX_USECNT;
	struct oecls_numa_info *numa_info;
	int nid = cpu_to_node(cpu);

	numa_info = get_oecls_numa_info(nid);
	if (!numa_info) {
		oecls_error("error nid:%d\n", nid);
		return -EINVAL;
	}

	if (devid >= OECLS_MAX_NETDEV_NUM) {
		oecls_error("error bound_dev index:%d\n", devid);
		return -EINVAL;
	}
	bound_dev = &numa_info->bound_dev[devid];

	if (strategy == 1) {
		rxq_id = get_cluster_rxq(bound_dev, cpu);
		if (rxq_id < 0 || rxq_id >= OECLS_MAX_RXQ_NUM_PER_DEV)
			oecls_debug("failed to get rxq_id:%d in cluster, try numa\n", rxq_id);
		else
			goto found;
	}

	for (i = 0; i < OECLS_MAX_RXQ_NUM_PER_DEV; i++) {
		if (bound_dev->bitmap_rxq[i] < min_used_count) {
			min_used_count = bound_dev->bitmap_rxq[i];
			rxq_id = i;
		}
	}

	if (min_used_count >= RXQ_MAX_USECNT || min_used_count >= rxq_multiplex_limit) {
		oecls_error("alloc rxq fail! nid:%d, devid:%d\n", nid, devid);
		return -EINVAL;
	}

found:
	bound_dev->bitmap_rxq[rxq_id]++;
	oecls_debug("alloc nid:%d, dev_id:%d, rxq_id:%d use:%d\n", nid, devid,
		    rxq_id, bound_dev->bitmap_rxq[rxq_id]);
	return rxq_id;
}

void free_rxq_id(int nid, int devid, int rxq_id)
{
	struct oecls_numa_bound_dev_info *bound_dev;
	struct oecls_numa_info *numa_info;

	numa_info = get_oecls_numa_info(nid);
	if (!numa_info) {
		oecls_error("error nid:%d\n", nid);
		return;
	}

	if (devid >= OECLS_MAX_NETDEV_NUM) {
		oecls_error("error bound_dev index:%d\n", devid);
		return;
	}
	bound_dev = &numa_info->bound_dev[devid];

	if (rxq_id >= OECLS_MAX_RXQ_NUM_PER_DEV) {
		oecls_error("error rxq_id:%d\n", rxq_id);
		return;
	}

	if (strategy == 1)
		put_cluster_rxq(bound_dev, rxq_id);

	if (bound_dev->bitmap_rxq[rxq_id] <= 0) {
		oecls_error("error nid:%d, devid:%d, rxq_id:%d\n", nid, devid, rxq_id);
		return;
	}

	bound_dev->bitmap_rxq[rxq_id]--;
	oecls_debug("free nid:%d, dev_id:%d, rxq_id:%d use:%d\n", nid, devid,
		    rxq_id, bound_dev->bitmap_rxq[rxq_id]);
}

static int init_oecls_numa_info(void)
{
	struct oecls_numa_info *numa_info;
	int nid, ret = 0;

	oecls_numa_num = num_online_nodes();
	oecls_numa_info_table = kcalloc(oecls_numa_num, sizeof(*oecls_numa_info_table),
					GFP_ATOMIC);
	if (!oecls_numa_info_table) {
		ret = -ENOMEM;
		oecls_error("oecls_numa_info_table alloc failed:%d\n", ret);
		return ret;
	}

	oecls_cluster_cpu_num = cpumask_weight(topology_cluster_cpumask(raw_smp_processor_id()));
	oecls_cluster_per_numa = (nr_cpu_ids / oecls_cluster_cpu_num) / oecls_numa_num;
	oecls_debug("oecls_numa_num=%d cluster_cpu_num:%d cluster_cpu_num:%d\n",
		    oecls_numa_num, oecls_cluster_per_numa, oecls_cluster_cpu_num);

	for_each_oecls_numa(nid, numa_info)
		init_numa_avail_cpus(nid, numa_info);

	return ret;
}

static int alloc_available_cpu(int nid, struct oecls_numa_info *numa_info)
{
	int cpu;

	cpu = find_first_bit(numa_info->avail_cpus, OECLS_MAX_CPU_NUM);
	if (cpu >= OECLS_MAX_CPU_NUM) {
		oecls_error("no available cpus: nid=%d, cpu=%d\n", nid, cpu);
		return -1;
	}

	clear_bit(cpu, numa_info->avail_cpus);
	return cpu;
}

static void add_netdev_irq_affinity_cpu(struct oecls_netdev_info *oecls_dev, int rxq_id, int cpu)
{
	struct oecls_netdev_queue_info *rxq_info;

	if (rxq_id >= OECLS_MAX_RXQ_NUM_PER_DEV)
		return;

	rxq_info = &oecls_dev->rxq[rxq_id];
	rxq_info->affinity_cpu = cpu;
}

static void config_affinity_strategy_default(struct oecls_netdev_info *oecls_dev)
{
	struct oecls_numa_info *numa_info;
	int rxq_num = oecls_dev->rxq_num;
	int rxq_per_numa = rxq_num / oecls_numa_num;
	int remain = rxq_num - rxq_per_numa * oecls_numa_num;
	int numa_rxq_id, rxq_id, nid, cpu;

	oecls_debug("dev=%s, rxq_num=%d, rxq_per_numa=%d, remain=%d\n", oecls_dev->dev_name,
		    rxq_num, rxq_per_numa, remain);

	// average config rxq to every numa
	for_each_oecls_numa(nid, numa_info) {
		for (numa_rxq_id = 0; numa_rxq_id < rxq_per_numa; numa_rxq_id++) {
			cpu = alloc_available_cpu(nid, numa_info);
			if (cpu < 0)
				break;

			rxq_id = rxq_per_numa * nid + numa_rxq_id;
			add_netdev_irq_affinity_cpu(oecls_dev, rxq_id, cpu);
		}
	}

	if (!remain)
		return;

	// config remain rxq to every numa
	numa_rxq_id = 0;
	for_each_oecls_numa(nid, numa_info) {
		if (numa_rxq_id >= remain)
			break;
		cpu = alloc_available_cpu(nid, numa_info);
		if (cpu < 0)
			break;

		rxq_id = rxq_per_numa * oecls_numa_num + numa_rxq_id;
		numa_rxq_id++;
		add_netdev_irq_affinity_cpu(oecls_dev, rxq_id, cpu);
	}
}

static void config_affinity_strategy_cluster(struct oecls_netdev_info *oecls_dev)
{
	int rxq_num = oecls_dev->rxq_num;
	int rxq_per_numa = rxq_num / oecls_numa_num;
	int remain = rxq_num - rxq_per_numa * oecls_numa_num;
	int cpu_idx = oecls_cluster_cpu_num - 1;
	int cluster, cpu, rxq_id = 0, round;

	round = rxq_per_numa < oecls_cluster_per_numa ? rxq_per_numa : oecls_cluster_per_numa;
	if (remain > 0)
		round++;
	oecls_debug("round=%d\n", round);

	while (rxq_id < oecls_dev->rxq_num) {
		for (cluster = 0; cluster < oecls_cluster_per_numa * oecls_numa_num; cluster++) {
			if (cluster % oecls_cluster_per_numa >= round)
				continue;
			cpu = cluster * oecls_cluster_cpu_num + cpu_idx;
			if (rxq_id >= oecls_dev->rxq_num)
				break;
			add_netdev_irq_affinity_cpu(oecls_dev, rxq_id++, cpu);
		}
		cpu_idx--;
		if (--cpu_idx < 0)
			cpu_idx = oecls_cluster_cpu_num - 1;
	}
}

static void config_affinity_strategy_numa(struct oecls_netdev_info *oecls_dev)
{
	int rxq_num = oecls_dev->rxq_num;
	int rxq_per_numa = rxq_num / oecls_numa_num;
	int cpu_per_numa = nr_cpu_ids / oecls_numa_num;
	int remain = rxq_num - rxq_per_numa * oecls_numa_num;
	struct oecls_numa_info *numa_info;
	int numa_start_cpu, numa_cpu_id;
	int rxq_id = 0, nid, cpu;

	for_each_oecls_numa(nid, numa_info) {
		numa_start_cpu = find_first_bit(numa_info->avail_cpus, OECLS_MAX_CPU_NUM);
		for (numa_cpu_id = 0; numa_cpu_id < rxq_per_numa; numa_cpu_id++) {
			cpu = numa_start_cpu + (numa_cpu_id % cpu_per_numa);
			if (rxq_id >= oecls_dev->rxq_num)
				break;
			add_netdev_irq_affinity_cpu(oecls_dev, rxq_id++, cpu);
		}
		if (remain-- > 0) {
			cpu = numa_start_cpu + (numa_cpu_id % cpu_per_numa);
			add_netdev_irq_affinity_cpu(oecls_dev, rxq_id++, cpu);
		}
	}
}

static void config_affinity_strategy_custom(struct oecls_netdev_info *oecls_dev)
{
	oecls_debug("dev=%s\n", oecls_dev->dev_name);
}

static void config_affinity_strategy(void)
{
	struct oecls_netdev_info *oecls_dev;
	int devid;

	for_each_oecls_netdev(devid, oecls_dev) {
		switch (strategy) {
		case 1:
			config_affinity_strategy_cluster(oecls_dev);
			break;
		case 2:
			config_affinity_strategy_numa(oecls_dev);
			break;
		case 3:
			config_affinity_strategy_custom(oecls_dev);
			break;
		case 0:
		default:
			config_affinity_strategy_default(oecls_dev);
			break;
		}
	}
}

static inline void irq_set_affinity_wrapper(int rxq, int irq, int cpu)
{
	int err = 0;

	err = irq_set_affinity(irq, get_cpu_mask(cpu));
	oecls_debug("rxq=%d, irq=%d, cpu=%d, err=%d\n", rxq, irq, cpu, err);
}

static void enable_affinity_strategy(void)
{
	struct oecls_netdev_queue_info *rxq_info;
	struct oecls_netdev_info *oecls_dev;
	int rxq_id, devid;

	for_each_oecls_netdev(devid, oecls_dev) {
		for (rxq_id = 0; rxq_id < oecls_dev->rxq_num; rxq_id++) {
			rxq_info = &oecls_dev->rxq[rxq_id];
			irq_set_affinity_wrapper(rxq_id, rxq_info->irq, rxq_info->affinity_cpu);
		}
	}
}

static inline void netif_set_xps_queue_wrapper(struct net_device *netdev, int rxq_id,
					       const struct cpumask *cpu_mask)
{
	int err = 0;

	err = netif_set_xps_queue(netdev, cpu_mask, rxq_id);
	oecls_debug("name=%s, rxq_id=%d, mask=%*pbl, err=%d\n", netdev->name, rxq_id,
		    cpumask_pr_args(cpu_mask), err);
}

static void set_netdev_xps_queue(bool enable)
{
	const struct cpumask clear_mask = { 0 };
	struct oecls_netdev_info *oecls_dev;
	const struct cpumask *cpu_mask;
	int rxq_id, devid, cpu, nid;

	for_each_oecls_netdev(devid, oecls_dev) {
		for (rxq_id = 0; rxq_id < oecls_dev->rxq_num; rxq_id++) {
			cpu = oecls_dev->rxq[rxq_id].affinity_cpu;
			nid = cpu_to_node(cpu);
			if (enable)
				cpu_mask = cpumask_of_node(nid);
			else
				cpu_mask = &clear_mask;

			netif_set_xps_queue_wrapper(oecls_dev->netdev, rxq_id, cpu_mask);
		}
	}
}

static void fixup_rcpu_load(void)
{
	char *start = appname, *end;
	char *task_name = "redis-proxy";

	if (!strlen(appname))
		return;

	// support appname: app1#app2#appN
	while (*start != '\0') {
		end = strchr(start, '#');
		if (end == start) {
			start++;
			continue;
		}

		if (!end) {
			if (!strncmp(task_name, start, strlen(start))) {
				rcpu_probability = 100;
				return;
			}
			break;
		}

		if (!strncmp(task_name, start, end - start)) {
			rcpu_probability = 100;
			return;
		}
		start = end + 1;
	}
	rcpu_probability = 65;
}

static __init int oecls_init(void)
{
	struct oecls_numa_info *numa_info;
	int nid, err;

	if (!check_params())
		return -EINVAL;

	err = init_oecls_numa_info();
	if (err)
		return err;

	err = init_oecls_netdev_info(ifname);
	if (err)
		goto clean_numa;

	// Set irq affinity
	config_affinity_strategy();
	enable_affinity_strategy();

	// Calculate rxq bounded to one numa
	for_each_oecls_numa(nid, numa_info) {
		err = init_numa_rxq_bitmap(nid, numa_info);
		if (err)
			goto clean_rxq;
	}

#ifdef CONFIG_XPS
	set_netdev_xps_queue(true);
#endif

	if (mode == 2 && rcpu_probability < 0)
		fixup_rcpu_load();

	if (mode == 0) {
		err = oecls_ntuple_res_init();
		if (err)
			goto clean_rxq;
		if (lo_rps_policy || rps_policy) {
			err = oecls_flow_res_init();
			if (err)
				goto clean_ntuple;
		}
	} else {
		err = oecls_flow_res_init();
	}

	if (err)
		goto clean_rxq;

	if (lo_rps_policy)
		static_branch_inc(&oecls_localrps_needed);

	return 0;

clean_ntuple:
	oecls_ntuple_res_clean();
clean_rxq:
clean_numa:
	clean_oecls_netdev_info();
	clean_oecls_numa_info();
	return err;
}

static __exit void oecls_exit(void)
{
	if (lo_rps_policy)
		static_branch_dec(&oecls_localrps_needed);

	if (mode == 0) {
		oecls_ntuple_res_clean();
		if (lo_rps_policy || rps_policy)
			oecls_flow_res_clean();
	} else {
		oecls_flow_res_clean();
	}

#ifdef CONFIG_XPS
	set_netdev_xps_queue(false);
#endif

	clean_oecls_rxq();
	clean_oecls_netdev_info();
	clean_oecls_numa_info();
}

module_init(oecls_init);
module_exit(oecls_exit);

MODULE_DESCRIPTION("oenetcls");
MODULE_LICENSE("GPL v2");
