// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/device.h>
#include <linux/ethtool.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/dcbnl.h>

#include "sphw_crm.h"
#include "spnic_nic_cfg.h"
#include "spnic_nic_dev.h"
#include "sphw_hw.h"
#include "spnic_rss.h"

static u16 num_qps;
module_param(num_qps, ushort, 0444);
MODULE_PARM_DESC(num_qps, "Number of Queue Pairs (default=0)");

#define MOD_PARA_VALIDATE_NUM_QPS(nic_dev, num_qps, out_qps)	do {	\
	if ((num_qps) > (nic_dev)->max_qps)				\
		nic_warn(&(nic_dev)->pdev->dev,				\
		"Module Parameter %s value %u is out of range, "        \
		"Maximum value for the device: %u, using %u\n",         \
		#num_qps, num_qps, (nic_dev)->max_qps,		        \
		(nic_dev)->max_qps);				        \
	if (!(num_qps) || (num_qps) > (nic_dev)->max_qps)		\
		(out_qps) = (nic_dev)->max_qps;				\
	else								\
		(out_qps) = (num_qps);					\
} while (0)

static void spnic_fillout_indir_tbl(struct spnic_nic_dev *nic_dev, u8 num_tcs, u32 *indir)
{
	u16 num_rss, tc_group_size;
	int i;

	if (num_tcs)
		tc_group_size = SPNIC_RSS_INDIR_SIZE / num_tcs;
	else
		tc_group_size = SPNIC_RSS_INDIR_SIZE;

	num_rss = nic_dev->q_params.num_rss;
	for (i = 0; i < SPNIC_RSS_INDIR_SIZE; i++)
		indir[i] = (i / tc_group_size) * num_rss + i % num_rss;
}

int spnic_rss_init(struct spnic_nic_dev *nic_dev)
{
	struct net_device *netdev = nic_dev->netdev;
	u8 cos, num_tc = 0;
	u8 prio_tc[SPNIC_DCB_UP_MAX] = {0};
	u8 max_cos = nic_dev->hw_dcb_cfg.max_cos;

	if (test_bit(SPNIC_DCB_ENABLE, &nic_dev->flags)) {
		num_tc = max_cos;
		for (cos = 0; cos < SPNIC_DCB_COS_MAX; cos++) {
			if (cos < SPNIC_DCB_COS_MAX - max_cos)
				prio_tc[cos] = max_cos - 1;
			else
				prio_tc[cos] = (SPNIC_DCB_COS_MAX - 1) - cos;
		}
	} else {
		num_tc = 0;
	}

	return spnic_set_hw_rss_parameters(netdev, 1, num_tc, prio_tc);
}

void spnic_rss_deinit(struct spnic_nic_dev *nic_dev)
{
	u8 prio_tc[SPNIC_DCB_UP_MAX] = {0};

	spnic_rss_cfg(nic_dev->hwdev, 0, 0, prio_tc, 1);
}

void spnic_init_rss_parameters(struct net_device *netdev)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);

	nic_dev->rss_hash_engine = SPNIC_RSS_HASH_ENGINE_TYPE_XOR;
	nic_dev->rss_type.tcp_ipv6_ext = 1;
	nic_dev->rss_type.ipv6_ext = 1;
	nic_dev->rss_type.tcp_ipv6 = 1;
	nic_dev->rss_type.ipv6 = 1;
	nic_dev->rss_type.tcp_ipv4 = 1;
	nic_dev->rss_type.ipv4 = 1;
	nic_dev->rss_type.udp_ipv6 = 1;
	nic_dev->rss_type.udp_ipv4 = 1;
}

void spnic_clear_rss_config(struct spnic_nic_dev *nic_dev)
{
	kfree(nic_dev->rss_hkey);
	nic_dev->rss_hkey = NULL;

	kfree(nic_dev->rss_indir);
	nic_dev->rss_indir = NULL;
}

void spnic_set_default_rss_indir(struct net_device *netdev)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);

	set_bit(SPNIC_RSS_DEFAULT_INDIR, &nic_dev->flags);
}

static void spnic_maybe_reconfig_rss_indir(struct net_device *netdev)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	int i;

	/* if dcb is enabled, user can not config rss indir table */
	if (test_bit(SPNIC_DCB_ENABLE, &nic_dev->flags)) {
		nicif_info(nic_dev, drv, netdev, "DCB is enabled, set default rss indir\n");
		goto discard_user_rss_indir;
	}

	for (i = 0; i < SPNIC_RSS_INDIR_SIZE; i++) {
		if (nic_dev->rss_indir[i] >= nic_dev->q_params.num_qps)
			goto discard_user_rss_indir;
	}

	return;

discard_user_rss_indir:
	spnic_set_default_rss_indir(netdev);
}

static void decide_num_qps(struct spnic_nic_dev *nic_dev)
{
	u16 tmp_num_qps = nic_dev->q_params.num_qps;
	u16 num_cpus = 0;
	int i, node;

	MOD_PARA_VALIDATE_NUM_QPS(nic_dev, num_qps, tmp_num_qps);

	/* To reduce memory footprint in ovs mode.
	 * VF can't get board info correctly with early pf driver.
	 */
	/* if ((spnic_get_func_mode(nic_dev->hwdev) == FUNC_MOD_NORMAL_HOST) &&
	 *  service_mode == SPNIC_WORK_MODE_OVS &&
	 *   sphw_func_type(nic_dev->hwdev) != TYPE_VF)
	 *  MOD_PARA_VALIDATE_NUM_QPS(nic_dev, ovs_num_qps,
	 *				 tmp_num_qps);
	 */

	for (i = 0; i < (int)num_online_cpus(); i++) {
		node = (int)cpu_to_node(i);
		if (node == dev_to_node(&nic_dev->pdev->dev))
			num_cpus++;
	}

	if (!num_cpus)
		num_cpus = (u16)num_online_cpus();

	nic_dev->q_params.num_qps = min_t(u16, tmp_num_qps, num_cpus);
}

static void copy_value_to_rss_hkey(struct spnic_nic_dev *nic_dev, const u8 *hkey)
{
	u32 i;
	u32 *rss_hkey = (u32 *)nic_dev->rss_hkey;

	memcpy(nic_dev->rss_hkey, hkey, SPNIC_RSS_KEY_SIZE);

	/* make a copy of the key, and convert it to Big Endian */
	for (i = 0; i < SPNIC_RSS_KEY_SIZE / sizeof(u32); i++)
		nic_dev->rss_hkey_be[i] = cpu_to_be32(rss_hkey[i]);
}

int alloc_rss_resource(struct spnic_nic_dev *nic_dev)
{
	u8 default_rss_key[SPNIC_RSS_KEY_SIZE] = {
		0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
		0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
		0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
		0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
		0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa};

	/* We request double spaces for the hash key,
	 * the second one holds the key of Big Edian
	 * format.
	 */
	nic_dev->rss_hkey =
		kzalloc(SPNIC_RSS_KEY_SIZE * SPNIC_RSS_KEY_RSV_NUM, GFP_KERNEL);
	if (!nic_dev->rss_hkey) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to alloc memory for rss_hkey\n");
		return -ENOMEM;
	}

	/* The second space is for big edian hash key */
	nic_dev->rss_hkey_be = (u32 *)(nic_dev->rss_hkey + SPNIC_RSS_KEY_SIZE);
	copy_value_to_rss_hkey(nic_dev, (u8 *)default_rss_key);

	nic_dev->rss_indir = kzalloc(sizeof(u32) * SPNIC_RSS_INDIR_SIZE, GFP_KERNEL);
	if (!nic_dev->rss_indir) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to alloc memory for rss_indir\n");
		kfree(nic_dev->rss_hkey);
		nic_dev->rss_hkey = NULL;
		return -ENOMEM;
	}

	set_bit(SPNIC_RSS_DEFAULT_INDIR, &nic_dev->flags);

	return 0;
}

void spnic_try_to_enable_rss(struct spnic_nic_dev *nic_dev)
{
	u8 prio_tc[SPNIC_DCB_UP_MAX] = {0};
	int err = 0;

	if (!nic_dev)
		return;

	nic_dev->max_qps = sphw_func_max_nic_qnum(nic_dev->hwdev);
	if (nic_dev->max_qps <= 1)
		goto set_q_params;

	err = alloc_rss_resource(nic_dev);
	if (err) {
		nic_dev->max_qps = 1;
		goto set_q_params;
	}

	err = spnic_rss_template_alloc(nic_dev->hwdev);
	if (err) {
		if (err == -ENOSPC)
			nic_err(&nic_dev->pdev->dev, "Failed to alloc template for rss, table is full\n");
		else
			nic_err(&nic_dev->pdev->dev, "Failed to alloc template for rss, can't enable rss for this function\n");
		spnic_clear_rss_config(nic_dev);
		nic_dev->max_qps = 1;
		goto set_q_params;
	}

	set_bit(SPNIC_RSS_ENABLE, &nic_dev->flags);
	nic_dev->max_qps = sphw_func_max_nic_qnum(nic_dev->hwdev);

	decide_num_qps(nic_dev);

	nic_dev->q_params.rss_limit = nic_dev->q_params.num_qps;
	nic_dev->q_params.num_rss = nic_dev->q_params.num_qps;

	spnic_init_rss_parameters(nic_dev->netdev);
	err = spnic_set_hw_rss_parameters(nic_dev->netdev, 0, 0, prio_tc);
	if (err) {
		nic_err(&nic_dev->pdev->dev, "Failed to set hardware rss parameters\n");

		spnic_clear_rss_config(nic_dev);
		err = spnic_rss_template_free(nic_dev->hwdev);
		if (err)
			return;
		nic_dev->max_qps = 1;
		goto set_q_params;
	}
	return;

set_q_params:
	clear_bit(SPNIC_RSS_ENABLE, &nic_dev->flags);
	nic_dev->q_params.rss_limit = nic_dev->max_qps;
	nic_dev->q_params.num_qps = nic_dev->max_qps;
	nic_dev->q_params.num_rss = nic_dev->max_qps;
}

static int spnic_config_rss_hw_resource(struct spnic_nic_dev *nic_dev, u32 *indir_tbl)
{
	int err;

	err = spnic_rss_set_indir_tbl(nic_dev->hwdev, indir_tbl);
	if (err)
		return err;

	err = spnic_set_rss_type(nic_dev->hwdev, nic_dev->rss_type);
	if (err)
		return err;

	return spnic_rss_set_hash_engine(nic_dev->hwdev, nic_dev->rss_hash_engine);
}

int spnic_set_hw_rss_parameters(struct net_device *netdev, u8 rss_en, u8 num_tc, u8 *prio_tc)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	int err;

	/* RSS key */
	err = spnic_rss_set_hash_key(nic_dev->hwdev, nic_dev->rss_hkey);
	if (err)
		return err;

	spnic_maybe_reconfig_rss_indir(netdev);

	if (test_bit(SPNIC_RSS_DEFAULT_INDIR, &nic_dev->flags))
		spnic_fillout_indir_tbl(nic_dev, num_tc, nic_dev->rss_indir);

	err = spnic_config_rss_hw_resource(nic_dev, nic_dev->rss_indir);
	if (err)
		return err;

	err = spnic_rss_cfg(nic_dev->hwdev, rss_en, num_tc, prio_tc, nic_dev->q_params.num_qps);
	if (err)
		return err;

	return 0;
}

/* for ethtool */
static int set_l4_rss_hash_ops(struct ethtool_rxnfc *cmd, struct nic_rss_type *rss_type)
{
	u8 rss_l4_en = 0;

	switch (cmd->data & (RXH_L4_B_0_1 | RXH_L4_B_2_3)) {
	case 0:
		rss_l4_en = 0;
		break;
	case (RXH_L4_B_0_1 | RXH_L4_B_2_3):
		rss_l4_en = 1;
		break;
	default:
		return -EINVAL;
	}

	switch (cmd->flow_type) {
	case TCP_V4_FLOW:
		rss_type->tcp_ipv4 = rss_l4_en;
		break;
	case TCP_V6_FLOW:
		rss_type->tcp_ipv6 = rss_l4_en;
		break;
	case UDP_V4_FLOW:
		rss_type->udp_ipv4 = rss_l4_en;
		break;
	case UDP_V6_FLOW:
		rss_type->udp_ipv6 = rss_l4_en;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int update_rss_hash_opts(struct spnic_nic_dev *nic_dev, struct ethtool_rxnfc *cmd,
				struct nic_rss_type *rss_type)
{
	int err;

	switch (cmd->flow_type) {
	case TCP_V4_FLOW:
	case TCP_V6_FLOW:
	case UDP_V4_FLOW:
	case UDP_V6_FLOW:
		err = set_l4_rss_hash_ops(cmd, rss_type);
		if (err)
			return err;

		break;
	case IPV4_FLOW:
		rss_type->ipv4 = 1;
		break;
	case IPV6_FLOW:
		rss_type->ipv6 = 1;
		break;
	default:
		nicif_err(nic_dev, drv, nic_dev->netdev, "Unsupported flow type\n");
		return -EINVAL;
	}

	return 0;
}

static int spnic_set_rss_hash_opts(struct spnic_nic_dev *nic_dev, struct ethtool_rxnfc *cmd)
{
	struct nic_rss_type *rss_type = &nic_dev->rss_type;
	int err;

	if (!test_bit(SPNIC_RSS_ENABLE, &nic_dev->flags)) {
		cmd->data = 0;
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "RSS is disable, not support to set flow-hash\n");
		return -EOPNOTSUPP;
	}

	/* RSS does not support anything other than hashing
	 * to queues on src and dst IPs and ports
	 */
	if (cmd->data & ~(RXH_IP_SRC | RXH_IP_DST | RXH_L4_B_0_1 |
	    RXH_L4_B_2_3))
		return -EINVAL;

	/* We need at least the IP SRC and DEST fields for hashing */
	if (!(cmd->data & RXH_IP_SRC) || !(cmd->data & RXH_IP_DST))
		return -EINVAL;

	err = spnic_get_rss_type(nic_dev->hwdev, rss_type);
	if (err) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to get rss type\n");
		return -EFAULT;
	}

	err = update_rss_hash_opts(nic_dev, cmd, rss_type);
	if (err)
		return err;

	err = spnic_set_rss_type(nic_dev->hwdev, *rss_type);
	if (err) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Failed to set rss type\n");
		return -EFAULT;
	}

	nicif_info(nic_dev, drv, nic_dev->netdev, "Set rss hash options success\n");

	return 0;
}

static void convert_rss_type(u8 rss_opt, struct ethtool_rxnfc *cmd)
{
	if (rss_opt)
		cmd->data |= RXH_L4_B_0_1 | RXH_L4_B_2_3;
}

static int spnic_convert_rss_type(struct spnic_nic_dev *nic_dev, struct nic_rss_type *rss_type,
				  struct ethtool_rxnfc *cmd)
{
	cmd->data = RXH_IP_SRC | RXH_IP_DST;
	switch (cmd->flow_type) {
	case TCP_V4_FLOW:
		convert_rss_type(rss_type->tcp_ipv4, cmd);
		break;
	case TCP_V6_FLOW:
		convert_rss_type(rss_type->tcp_ipv6, cmd);
		break;
	case UDP_V4_FLOW:
		convert_rss_type(rss_type->udp_ipv4, cmd);
		break;
	case UDP_V6_FLOW:
		convert_rss_type(rss_type->udp_ipv6, cmd);
		break;
	case IPV4_FLOW:
	case IPV6_FLOW:
		break;
	default:
		nicif_err(nic_dev, drv, nic_dev->netdev, "Unsupported flow type\n");
		cmd->data = 0;
		return -EINVAL;
	}

	return 0;
}

static int spnic_get_rss_hash_opts(struct spnic_nic_dev *nic_dev, struct ethtool_rxnfc *cmd)
{
	struct nic_rss_type rss_type = {0};
	int err;

	cmd->data = 0;

	if (!test_bit(SPNIC_RSS_ENABLE, &nic_dev->flags))
		return 0;

	err = spnic_get_rss_type(nic_dev->hwdev, &rss_type);
	if (err) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to get rss type\n");
		return err;
	}

	return spnic_convert_rss_type(nic_dev, &rss_type, cmd);
}

int spnic_get_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd, u32 *rule_locs)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	int err = 0;

	switch (cmd->cmd) {
	case ETHTOOL_GRXRINGS:
		cmd->data = nic_dev->q_params.num_qps;
		break;
	case ETHTOOL_GRXCLSRLCNT:
		cmd->rule_cnt = nic_dev->rx_flow_rule.tot_num_rules;
		break;
	case ETHTOOL_GRXCLSRULE:
		err = spnic_ethtool_get_flow(nic_dev, cmd, cmd->fs.location);
		break;
	case ETHTOOL_GRXCLSRLALL:
		err = spnic_ethtool_get_all_flows(nic_dev, cmd, rule_locs);
		break;
	case ETHTOOL_GRXFH:
		err = spnic_get_rss_hash_opts(nic_dev, cmd);
		break;
	default:
		err = -EOPNOTSUPP;
		break;
	}

	return err;
}

int spnic_set_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	int err = 0;

	switch (cmd->cmd) {
	case ETHTOOL_SRXFH:
		err = spnic_set_rss_hash_opts(nic_dev, cmd);
		break;
	case ETHTOOL_SRXCLSRLINS:
		err = spnic_ethtool_flow_replace(nic_dev, &cmd->fs);
		break;
	case ETHTOOL_SRXCLSRLDEL:
		err = spnic_ethtool_flow_remove(nic_dev, cmd->fs.location);
		break;
	default:
		err = -EOPNOTSUPP;
		break;
	}

	return err;
}

static u16 spnic_max_channels(struct spnic_nic_dev *nic_dev)
{
	u8 tcs = (u8)netdev_get_num_tc(nic_dev->netdev);

	return tcs ? nic_dev->max_qps / tcs : nic_dev->max_qps;
}

static u16 spnic_curr_channels(struct spnic_nic_dev *nic_dev)
{
	if (netif_running(nic_dev->netdev))
		return nic_dev->q_params.num_rss ? nic_dev->q_params.num_rss : 1;
	else
		return min_t(u16, spnic_max_channels(nic_dev),
			     nic_dev->q_params.rss_limit);
}

void spnic_get_channels(struct net_device *netdev, struct ethtool_channels *channels)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);

	channels->max_rx = 0;
	channels->max_tx = 0;
	channels->max_other = 0;
	/* report maximum channels */
	channels->max_combined = spnic_max_channels(nic_dev);
	channels->rx_count = 0;
	channels->tx_count = 0;
	channels->other_count = 0;
	/* report flow director queues as maximum channels */
	channels->combined_count = spnic_curr_channels(nic_dev);
}

void spnic_update_num_qps(struct net_device *netdev)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	u16 num_qps;
	u8 tcs;

	/* change num_qps to change counter in ethtool -S */
	tcs = (u8)netdev_get_num_tc(nic_dev->netdev);
	nic_dev->q_params.num_tc = tcs;
	num_qps = (u16)(nic_dev->q_params.rss_limit * (tcs ? tcs : 1));
	nic_dev->q_params.num_qps = min_t(u16, nic_dev->max_qps, num_qps);
}

static int spnic_validate_channel_parameter(struct net_device *netdev,
					    struct ethtool_channels *channels)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	u16 max_channel = spnic_max_channels(nic_dev);
	unsigned int count = channels->combined_count;

	if (!count) {
		nicif_err(nic_dev, drv, netdev, "Unsupported combined_count=0\n");
		return -EINVAL;
	}

	if (channels->tx_count || channels->rx_count || channels->other_count) {
		nicif_err(nic_dev, drv, netdev, "Setting rx/tx/other count not supported\n");
		return -EINVAL;
	}

	if (count > max_channel) {
		nicif_err(nic_dev, drv, netdev, "Combined count %u exceed limit %u\n",
			  count, max_channel);
		return -EINVAL;
	}

	return 0;
}

static void change_num_channel_reopen_handler(struct spnic_nic_dev *nic_dev, const void *priv_data)
{
	spnic_set_default_rss_indir(nic_dev->netdev);
}

int spnic_set_channels(struct net_device *netdev, struct ethtool_channels *channels)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	struct spnic_dyna_txrxq_params q_params = {0};
	unsigned int count = channels->combined_count;
	int err;

	if (spnic_validate_channel_parameter(netdev, channels))
		return -EINVAL;

	if (!test_bit(SPNIC_RSS_ENABLE, &nic_dev->flags)) {
		nicif_err(nic_dev, drv, netdev,
			  "This function don't support RSS, only support 1 queue pair\n");
		return -EOPNOTSUPP;
	}

	nicif_info(nic_dev, drv, netdev, "Set max combined queue number from %u to %u\n",
		   nic_dev->q_params.rss_limit, count);

	if (netif_running(netdev)) {
		q_params = nic_dev->q_params;
		q_params.rss_limit = (u16)count;
		q_params.txqs_res = NULL;
		q_params.rxqs_res = NULL;
		q_params.irq_cfg = NULL;

		nicif_info(nic_dev, drv, netdev, "Restarting channel\n");
		err = spnic_change_channel_settings(nic_dev, &q_params,
						    change_num_channel_reopen_handler, NULL);
		if (err) {
			nicif_err(nic_dev, drv, netdev, "Failed to change channel settings\n");
			return -EFAULT;
		}
	} else {
		/* Discard user configured rss */
		spnic_set_default_rss_indir(netdev);
		nic_dev->q_params.rss_limit = (u16)count;
		spnic_update_num_qps(netdev);
	}

	return 0;
}

static int set_rss_rxfh(struct net_device *netdev, const u32 *indir, const u8 *key)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	int err;

	if (indir) {
		err = spnic_rss_set_indir_tbl(nic_dev->hwdev, indir);
		if (err) {
			nicif_err(nic_dev, drv, netdev, "Failed to set rss indir table\n");
			return -EFAULT;
		}
		clear_bit(SPNIC_RSS_DEFAULT_INDIR, &nic_dev->flags);

		memcpy(nic_dev->rss_indir, indir,
		       sizeof(u32) * SPNIC_RSS_INDIR_SIZE);
		nicif_info(nic_dev, drv, netdev, "Change rss indir success\n");
	}

	if (key) {
		err = spnic_rss_set_hash_key(nic_dev->hwdev, key);
		if (err) {
			nicif_err(nic_dev, drv, netdev, "Failed to set rss key\n");
			return -EFAULT;
		}

		copy_value_to_rss_hkey(nic_dev, key);
		nicif_info(nic_dev, drv, netdev, "Change rss key success\n");
	}

	return 0;
}

u32 spnic_get_rxfh_indir_size(struct net_device *netdev)
{
	return SPNIC_RSS_INDIR_SIZE;
}

u32 spnic_get_rxfh_key_size(struct net_device *netdev)
{
	return SPNIC_RSS_KEY_SIZE;
}

int spnic_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key, u8 *hfunc)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	int err = 0;

	if (!test_bit(SPNIC_RSS_ENABLE, &nic_dev->flags)) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Rss is disable\n");
		return -EOPNOTSUPP;
	}

	if (hfunc)
		*hfunc = nic_dev->rss_hash_engine ?
			ETH_RSS_HASH_TOP : ETH_RSS_HASH_XOR;

	if (indir) {
		err = spnic_rss_get_indir_tbl(nic_dev->hwdev, indir);
		if (err)
			return -EFAULT;
	}

	if (key)
		memcpy(key, nic_dev->rss_hkey, SPNIC_RSS_KEY_SIZE);

	return err;
}

int spnic_set_rxfh(struct net_device *netdev, const u32 *indir, const u8 *key, const u8 hfunc)
{
	struct spnic_nic_dev *nic_dev = netdev_priv(netdev);
	int err = 0;

	if (!test_bit(SPNIC_RSS_ENABLE, &nic_dev->flags)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Not support to set rss parameters when rss is disable\n");
		return -EOPNOTSUPP;
	}

	if (test_bit(SPNIC_DCB_ENABLE, &nic_dev->flags) && indir) {
		nicif_err(nic_dev, drv, netdev, "Not support to set indir when DCB is enabled\n");
		return -EOPNOTSUPP;
	}

	if (hfunc != ETH_RSS_HASH_NO_CHANGE) {
		if (hfunc != ETH_RSS_HASH_TOP && hfunc != ETH_RSS_HASH_XOR) {
			nicif_err(nic_dev, drv, netdev, "Not support to set hfunc type except TOP and XOR\n");
			return -EOPNOTSUPP;
		}

		nic_dev->rss_hash_engine = (hfunc == ETH_RSS_HASH_XOR) ?
			SPNIC_RSS_HASH_ENGINE_TYPE_XOR :
			SPNIC_RSS_HASH_ENGINE_TYPE_TOEP;
		err = spnic_rss_set_hash_engine(nic_dev->hwdev, nic_dev->rss_hash_engine);
		if (err)
			return -EFAULT;

		nicif_info(nic_dev, drv, netdev, "Change hfunc to RSS_HASH_%s success\n",
			   (hfunc == ETH_RSS_HASH_XOR) ? "XOR" : "TOP");
	}
	err = set_rss_rxfh(netdev, indir, key);

	return err;
}
