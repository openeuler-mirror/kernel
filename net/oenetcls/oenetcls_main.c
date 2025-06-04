// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netdev_features.h>
#include <linux/ethtool.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/rtnetlink.h>
#include "oenetcls.h"

int oecls_netdev_num;
static struct oecls_netdev_info oecls_netdev_info_table[OECLS_MAX_NETDEV_NUM];

int oecls_numa_num;
static struct oecls_numa_info oecls_numa_info_table[OECLS_MAX_NUMA_NUM];

int debug;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "debug switch");

static int mode;
module_param(mode, int, 0444);
MODULE_PARM_DESC(mode, "mode, default 0");

static char ifname[64] = { 0 };
module_param_string(ifname, ifname, sizeof(ifname), 0444);
MODULE_PARM_DESC(ifname, "ifname");

static char appname[64] = "redis-server";
module_param_string(appname, appname, sizeof(appname), 0644);
MODULE_PARM_DESC(appname, "appname, default redis-server");

int match_ip_flag = 1;
module_param(match_ip_flag, int, 0644);
MODULE_PARM_DESC(match_ip_flag, "match ip flag");

static int strategy;
module_param(strategy, int, 0444);
MODULE_PARM_DESC(strategy, "strategy, default 0");

static bool check_params(void)
{
	if (mode != 0 && mode != 1)
		return false;

	if (strlen(ifname) == 0)
		return false;

	return true;
}

int check_appname(char *task_name)
{
	char *start = appname;
	char *end;

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
		if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
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
	if (!strstr(irq_name, "TxRx") && !strstr(irq_name, "comp") && !strstr(irq_name, "rx"))
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
	struct irq_desc *desc;
	int irq;

	for_each_irq_desc(irq, desc) {
		if (!desc->action)
			continue;
		if (!desc->action->name)
			continue;
		if (!check_irq_name(desc->action->name, oecls_dev))
			continue;

		oecls_debug("irq=%d, [%s], rxq_id=%d\n", irq, desc->action->name,
			    oecls_dev->rxq_num);

		if (oecls_dev->rxq_num >= OECLS_MAX_RXQ_NUM_PER_DEV)
			break;
		rxq_info = &oecls_dev->rxq[oecls_dev->rxq_num++];
		rxq_info->irq = irq;
	}
}

static int oecls_filter_enable(const char *dev_name, bool *old_state)
{
	struct ethtool_value eval = {0};
	struct cmd_context ctx = {0};
	int ret;

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

	ret = oecls_filter_enable(dev_name, &old_state);
	if (ret) {
		oecls_error("dev [%s] not support ntuple! ret=%d\n", dev_name, ret);
		goto out;
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
	char *start = netdev_str;
	char *end;
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
	if (nid >= OECLS_MAX_NUMA_NUM)
		return NULL;
	return &oecls_numa_info_table[nid];
}

static void clean_oecls_numa_info(void)
{
	oecls_numa_num = 0;
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

static void init_numa_rxq_bitmap(int nid, struct oecls_numa_info *numa_info)
{
	struct oecls_numa_bound_dev_info *bound_dev;
	struct oecls_netdev_info *oecls_dev;
	int bound_rxq_num;
	int rxq_id;
	int devid;
	int cpu;

	for_each_oecls_netdev(devid, oecls_dev) {
		bound_rxq_num = 0;
		bound_dev = &numa_info->bound_dev[devid];
		bitmap_zero(bound_dev->bitmap_rxq, OECLS_MAX_RXQ_NUM_PER_DEV);

		for (rxq_id = 0; rxq_id < oecls_dev->rxq_num; rxq_id++) {
			cpu = oecls_dev->rxq[rxq_id].affinity_cpu;
			if (cpu_to_node(cpu) == nid) {
				set_bit(rxq_id, bound_dev->bitmap_rxq);
				bound_rxq_num++;
			}
		}

		oecls_debug("nid:%d, dev_id:%d, dev:%s, rxq_num:%d, bit_num:%d, bitmap_rxq:%*pbl\n",
			    nid, devid, oecls_dev->dev_name, oecls_dev->rxq_num,
			    bound_rxq_num, OECLS_MAX_RXQ_NUM_PER_DEV, bound_dev->bitmap_rxq);
	}
}

int alloc_rxq_id(int nid, int devid)
{
	struct oecls_numa_bound_dev_info *bound_dev;
	struct oecls_numa_info *numa_info;
	int rxq_id;

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

	rxq_id = find_first_bit(bound_dev->bitmap_rxq, OECLS_MAX_RXQ_NUM_PER_DEV);
	if (rxq_id >= OECLS_MAX_RXQ_NUM_PER_DEV) {
		oecls_error("error rxq_id:%d\n", rxq_id);
		return -EINVAL;
	}

	clear_bit(rxq_id, bound_dev->bitmap_rxq);
	oecls_debug("alloc nid:%d, dev_id:%d, rxq_id:%d\n", nid, devid, rxq_id);
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

	if (test_bit(rxq_id, bound_dev->bitmap_rxq)) {
		oecls_error("error nid:%d, devid:%d, rxq_id:%d\n", nid, devid, rxq_id);
		return;
	}

	set_bit(rxq_id, bound_dev->bitmap_rxq);
	oecls_debug("free nid:%d, dev_id:%d, rxq_id:%d\n", nid, devid, rxq_id);
}

static void init_oecls_numa_info(void)
{
	struct oecls_numa_info *numa_info;
	unsigned int numa_num;
	int nid;

	numa_num = num_online_nodes();
	if (numa_num > OECLS_MAX_NUMA_NUM) {
		oecls_error("online numa num:%d is too much!\n", numa_num);
		numa_num = OECLS_MAX_NUMA_NUM;
	}
	oecls_numa_num = numa_num;
	oecls_debug("set oecls_numa_num=%d\n", numa_num);

	for_each_oecls_numa(nid, numa_info)
		init_numa_avail_cpus(nid, numa_info);
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
	int numa_rxq_id;
	int rxq_id;
	int nid;
	int cpu;

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
	int cluster_cpu_num = 8;
	int cluster_num = num_online_cpus() / cluster_cpu_num;
	int cluster_cpu_id = 0;
	int rxq_id = 0;
	int cluster;
	int cpu;

	// average config rxq to every cluster
	while (rxq_id < oecls_dev->rxq_num) {
		for (cluster = 0; cluster < cluster_num; cluster++) {
			cpu = cluster * cluster_cpu_num + cluster_cpu_id;
			if (rxq_id >= oecls_dev->rxq_num)
				break;
			add_netdev_irq_affinity_cpu(oecls_dev, rxq_id++, cpu);
		}
		cluster_cpu_id++;
	}
}

static void config_affinity_strategy_16cores(struct oecls_netdev_info *oecls_dev)
{
	struct oecls_numa_info *numa_info;
	int numa_start_cpu;
	int numa_cpu_id;
	int rxq_id = 0;
	int nid;
	int cpu;

	// only use 16 cores of one numa
	for_each_oecls_numa(nid, numa_info) {
		numa_start_cpu = find_first_bit(numa_info->avail_cpus, OECLS_MAX_CPU_NUM);
		for (numa_cpu_id = 0; numa_cpu_id < 16; numa_cpu_id++) {
			cpu = numa_start_cpu + numa_cpu_id;

			if (rxq_id >= oecls_dev->rxq_num)
				break;
			add_netdev_irq_affinity_cpu(oecls_dev, rxq_id++, cpu);
		}
	}
}

static void config_affinity_strategy(void)
{
	struct oecls_netdev_info *oecls_dev;
	int devid;

	for_each_oecls_netdev(devid, oecls_dev) {
		switch (strategy) {
		case 0:
			config_affinity_strategy_default(oecls_dev);
			break;
		case 1:
			config_affinity_strategy_cluster(oecls_dev);
			break;
		case 2:
			config_affinity_strategy_16cores(oecls_dev);
			break;
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
	int rxq_id;
	int devid;

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
	int rxq_id;
	int devid;
	int cpu;
	int nid;

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

static __init int oecls_init(void)
{
	struct oecls_numa_info *numa_info;
	int nid;
	int err;

	oecls_debug("[init] mode=%d, ifname=[%s]\n", mode, ifname);
	if (!check_params())
		return -EINVAL;

	init_oecls_l0_cache();
	init_oecls_numa_info();
	err = init_oecls_netdev_info(ifname);
	if (err)
		goto out;

	// Set irq affinity
	config_affinity_strategy();
	enable_affinity_strategy();

	// Calculate rxq bounded to one numa
	for_each_oecls_numa(nid, numa_info)
		init_numa_rxq_bitmap(nid, numa_info);

#ifdef CONFIG_XPS
	set_netdev_xps_queue(true);
#endif

	if (mode == 0)
		oecls_ntuple_res_init();
	else
		oecls_flow_res_init();

	return 0;
out:
	clean_oecls_netdev_info();
	clean_oecls_numa_info();
	clean_oecls_l0_cache();
	return err;
}

static __exit void oecls_exit(void)
{
	oecls_debug("[exit] mode=%d\n", mode);
	if (mode == 0)
		oecls_ntuple_res_clean();
	else
		oecls_flow_res_clean();

#ifdef CONFIG_XPS
	set_netdev_xps_queue(false);
#endif

	clean_oecls_netdev_info();
	clean_oecls_numa_info();
	clean_oecls_l0_cache();
}

module_init(oecls_init);
module_exit(oecls_exit);

MODULE_DESCRIPTION("oenetcls");
MODULE_LICENSE("GPL v2");
