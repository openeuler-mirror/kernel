// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_ethtool.h"

enum NBL_STATS_TYPE {
	NBL_NETDEV_STATS,
	NBL_ETH_STATS,
	NBL_STATS,
	NBL_PRIV_STATS,
	NBL_STATS_TYPE_MAX
};

struct nbl_ethtool_stats {
	char stat_string[ETH_GSTRING_LEN];
	int  type;
	int  sizeof_stat;
	int  stat_offset;
};

static const char nbl_gstrings_test[][ETH_GSTRING_LEN] = {
	"Register test  (offline)",
	"EEPROM test    (offline)",
	"Interrupt test (offline)",
	"Loopback test  (offline)",
	"Link test   (on/offline)",
};

enum nbl_ethtool_test_id {
	NBL_ETH_TEST_REG = 0,
	NBL_ETH_TEST_EEPROM,
	NBL_ETH_TEST_INTR,
	NBL_ETH_TEST_LOOP,
	NBL_ETH_TEST_LINK,
	NBL_ETH_TEST_MAX
};

#define NBL_TEST_LEN (sizeof(nbl_gstrings_test) / ETH_GSTRING_LEN)

#define NBL_NETDEV_STAT(_name, stat_m, stat_n) { \
	.stat_string	= _name, \
	.type		= NBL_NETDEV_STATS, \
	.sizeof_stat	= sizeof_field(struct rtnl_link_stats64, stat_m), \
	.stat_offset	= offsetof(struct rtnl_link_stats64, stat_n) \
}

#define NBL_STAT(_name, stat_m, stat_n) { \
	.stat_string	= _name, \
	.type		= NBL_STATS, \
	.sizeof_stat	= sizeof_field(struct nbl_stats, stat_m), \
	.stat_offset	= offsetof(struct nbl_stats, stat_n) \
}

#define NBL_PRIV_STAT(_name, stat_m, stat_n) { \
	.stat_string	= _name, \
	.type		= NBL_PRIV_STATS, \
	.sizeof_stat	= sizeof_field(struct nbl_priv_stats, stat_m), \
	.stat_offset	= offsetof(struct nbl_priv_stats, stat_n) \
}

static const struct nbl_ethtool_stats nbl_gstrings_stats[] = {
	NBL_NETDEV_STAT("rx_packets", rx_packets, rx_packets),
	NBL_NETDEV_STAT("tx_packets", tx_packets, tx_packets),
	NBL_NETDEV_STAT("rx_bytes", rx_bytes, rx_bytes),
	NBL_NETDEV_STAT("tx_bytes", tx_bytes, tx_bytes),
	NBL_STAT("tx_multicast", tx_multicast_packets, tx_multicast_packets),
	NBL_STAT("tx_unicast", tx_unicast_packets, tx_unicast_packets),
	NBL_STAT("rx_multicast", rx_multicast_packets, rx_multicast_packets),
	NBL_STAT("rx_unicast", rx_unicast_packets, rx_unicast_packets),
	NBL_NETDEV_STAT("rx_errors", rx_errors, rx_errors),
	NBL_NETDEV_STAT("tx_errors", tx_errors, tx_errors),
	NBL_NETDEV_STAT("rx_dropped", rx_dropped, rx_dropped),
	NBL_NETDEV_STAT("tx_dropped", tx_dropped, tx_dropped),
	NBL_NETDEV_STAT("eth_multicast", multicast, multicast),
	NBL_NETDEV_STAT("collisions", collisions, collisions),
	NBL_NETDEV_STAT("rx_over_errors", rx_over_errors, rx_over_errors),
	NBL_NETDEV_STAT("rx_crc_errors", rx_crc_errors, rx_crc_errors),
	NBL_NETDEV_STAT("rx_frame_errors", rx_frame_errors, rx_frame_errors),
	NBL_NETDEV_STAT("rx_fifo_errors", rx_fifo_errors, rx_fifo_errors),
	NBL_NETDEV_STAT("rx_missed_errors", rx_missed_errors, rx_missed_errors),
	NBL_NETDEV_STAT("tx_aborted_errors", tx_aborted_errors, tx_aborted_errors),
	NBL_NETDEV_STAT("tx_carrier_errors", tx_carrier_errors, tx_carrier_errors),
	NBL_NETDEV_STAT("tx_fifo_errors", tx_fifo_errors, tx_fifo_errors),
	NBL_NETDEV_STAT("tx_heartbeat_errors", tx_heartbeat_errors, tx_heartbeat_errors),

	NBL_STAT("tso_packets", tso_packets, tso_packets),
	NBL_STAT("tso_bytes", tso_bytes, tso_bytes),
	NBL_STAT("tx_csum_packets", tx_csum_packets, tx_csum_packets),
	NBL_STAT("rx_csum_packets", rx_csum_packets, rx_csum_packets),
	NBL_STAT("rx_csum_errors", rx_csum_errors, rx_csum_errors),
	NBL_STAT("tx_busy", tx_busy, tx_busy),
	NBL_STAT("tx_dma_busy", tx_dma_busy, tx_dma_busy),
	NBL_STAT("tx_skb_free", tx_skb_free, tx_skb_free),
	NBL_STAT("tx_desc_addr_err_cnt", tx_desc_addr_err_cnt, tx_desc_addr_err_cnt),
	NBL_STAT("tx_desc_len_err_cnt", tx_desc_len_err_cnt, tx_desc_len_err_cnt),
	NBL_STAT("rx_desc_addr_err_cnt", rx_desc_addr_err_cnt, rx_desc_addr_err_cnt),
	NBL_STAT("rx_alloc_buf_err_cnt", rx_alloc_buf_err_cnt, rx_alloc_buf_err_cnt),
	NBL_STAT("rx_cache_reuse", rx_cache_reuse, rx_cache_reuse),
	NBL_STAT("rx_cache_full", rx_cache_full, rx_cache_full),
	NBL_STAT("rx_cache_empty", rx_cache_empty, rx_cache_empty),
	NBL_STAT("rx_cache_busy", rx_cache_busy, rx_cache_busy),
	NBL_STAT("rx_cache_waive", rx_cache_waive, rx_cache_waive),

	NBL_PRIV_STAT("total_dvn_pkt_drop_cnt", total_dvn_pkt_drop_cnt, total_dvn_pkt_drop_cnt),
	NBL_PRIV_STAT("total_uvn_stat_pkt_drop", total_uvn_stat_pkt_drop, total_uvn_stat_pkt_drop),
};

#define NBL_GLOBAL_STATS_LEN ARRAY_SIZE(nbl_gstrings_stats)

struct nbl_priv_flags_info {
	u8 supported_by_capability;
	u8 supported_modify;
	enum nbl_fix_cap_type capability_type;
	char flag_name[ETH_GSTRING_LEN];
};

static const struct nbl_priv_flags_info nbl_gstrings_priv_flags[NBL_ADAPTER_FLAGS_MAX] = {
	{1, 0, NBL_P4_CAP,				"P4-default"},
	{0, 1, 0,					"link-down-on-close"},
	{0, 0, 0,					"mini-driver"},
};

#define NBL_PRIV_FLAG_ARRAY_SIZE	ARRAY_SIZE(nbl_gstrings_priv_flags)

static void nbl_get_drvinfo(struct net_device *netdev, struct ethtool_drvinfo *drvinfo)
{
	struct nbl_adapter *adapter;
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_netdev_priv *priv;
	struct nbl_driver_info driver_info;
	char firmware_version[ETHTOOL_FWVERS_LEN] = {' '};

	memset(&driver_info, 0, sizeof(driver_info));

	priv = netdev_priv(netdev);
	adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	disp_ops->get_firmware_version(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				       firmware_version, ETHTOOL_FWVERS_LEN);
	if (disp_ops->get_driver_info(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &driver_info))
		strscpy(drvinfo->version, driver_info.driver_version, sizeof(drvinfo->version));
	else
		strscpy(drvinfo->version, NBL_DRIVER_VERSION, sizeof(drvinfo->version));
	strscpy(drvinfo->fw_version, firmware_version, sizeof(drvinfo->fw_version));
	strscpy(drvinfo->driver, NBL_DRIVER_NAME, sizeof(drvinfo->driver));
	strscpy(drvinfo->bus_info, pci_name(adapter->pdev), sizeof(drvinfo->bus_info));

	drvinfo->regdump_len = 0;
}

static void nbl_stats_fill_strings(struct net_device *netdev, u8 *data)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info;
	char *p = (char *)data;
	unsigned int i;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];

	for (i = 0; i < NBL_GLOBAL_STATS_LEN; i++) {
		snprintf(p, ETH_GSTRING_LEN, "%s", nbl_gstrings_stats[i].stat_string);
		p += ETH_GSTRING_LEN;
	}

	for (i = 0; i < vsi_info->active_ring_num; i++) {
		snprintf(p, ETH_GSTRING_LEN, "tx_queue_%u_packets", i);
		p += ETH_GSTRING_LEN;
		snprintf(p, ETH_GSTRING_LEN, "tx_queue_%u_bytes", i);
		p += ETH_GSTRING_LEN;
		snprintf(p, ETH_GSTRING_LEN, "tx_queue_%u_descs", i);
		p += ETH_GSTRING_LEN;
		snprintf(p, ETH_GSTRING_LEN, "tx_queue_%u_dvn_pkt_drop_cnt", i);
		p += ETH_GSTRING_LEN;
		snprintf(p, ETH_GSTRING_LEN, "tx_queue_%u_tx_timeout_cnt", i);
		p += ETH_GSTRING_LEN;
	}

	for (i = 0; i < vsi_info->active_ring_num; i++) {
		snprintf(p, ETH_GSTRING_LEN, "rx_queue_%u_packets", i);
		p += ETH_GSTRING_LEN;
		snprintf(p, ETH_GSTRING_LEN, "rx_queue_%u_bytes", i);
		p += ETH_GSTRING_LEN;
		snprintf(p, ETH_GSTRING_LEN, "rx_queue_%u_descs", i);
		p += ETH_GSTRING_LEN;
		snprintf(p, ETH_GSTRING_LEN, "rx_queue_%u_uvn_stat_pkt_drop", i);
		p += ETH_GSTRING_LEN;
	}
	if (!common->is_vf)
		disp_ops->fill_private_stat_strings(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), p);
}

static void nbl_priv_flags_fill_strings(struct net_device *netdev, u8 *data)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	char *p = (char *)data;
	unsigned int i;

	for (i = 0; i < NBL_PRIV_FLAG_ARRAY_SIZE; i++) {
		enum nbl_fix_cap_type capability_type = nbl_gstrings_priv_flags[i].capability_type;

		if (nbl_gstrings_priv_flags[i].supported_by_capability) {
			if (!disp_ops->get_product_fix_cap(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
							   capability_type))
				continue;
		}
		snprintf(p, ETH_GSTRING_LEN, "%s", nbl_gstrings_priv_flags[i].flag_name);
		p += ETH_GSTRING_LEN;
	}
}

static void nbl_get_strings(struct net_device *netdev, u32 stringset, u8 *data)
{
	switch (stringset) {
	case ETH_SS_TEST:
		memcpy(data, nbl_gstrings_test, NBL_TEST_LEN * ETH_GSTRING_LEN);
		break;
	case ETH_SS_STATS:
		nbl_stats_fill_strings(netdev, data);
		break;
	case ETH_SS_PRIV_FLAGS:
		nbl_priv_flags_fill_strings(netdev, data);
		break;
	default:
		break;
	}
}

static int nbl_sset_fill_count(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info;
	u32 total_queues, private_len = 0, extra_per_queue_entry = 0;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];

	total_queues = vsi_info->active_ring_num * 2;
	if (!common->is_vf)
		disp_ops->get_private_stat_len(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &private_len);

	/* For dvn drop and tx_timeout */
	extra_per_queue_entry = total_queues + vsi_info->active_ring_num;

	return NBL_GLOBAL_STATS_LEN + total_queues *
		(sizeof(struct nbl_queue_stats) / sizeof(u64)) +
		extra_per_queue_entry + private_len;
}

static int nbl_sset_fill_priv_flags_count(struct net_device *netdev)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	unsigned int i;
	int count = 0;

	for (i = 0; i < NBL_PRIV_FLAG_ARRAY_SIZE; i++) {
		enum nbl_fix_cap_type capability_type = nbl_gstrings_priv_flags[i].capability_type;

		if (nbl_gstrings_priv_flags[i].supported_by_capability) {
			if (!disp_ops->get_product_fix_cap(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
							   capability_type))
				continue;
		}
		count++;
	}

	return count;
}

static int nbl_get_sset_count(struct net_device *netdev, int sset)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);

	switch (sset) {
	case ETH_SS_TEST:
		if (NBL_COMMON_TO_VF_CAP(common))
			return -EOPNOTSUPP;
		else
			return NBL_TEST_LEN;
	case ETH_SS_STATS:
		return nbl_sset_fill_count(netdev);
	case ETH_SS_PRIV_FLAGS:
		if (NBL_COMMON_TO_VF_CAP(common))
			return -EOPNOTSUPP;
		else
			return nbl_sset_fill_priv_flags_count(netdev);
	default:
		return -EOPNOTSUPP;
	}
}

void nbl_serv_adjust_interrpt_param(struct nbl_service_mgt *serv_mgt, bool ethtool)
{
	struct nbl_serv_net_resource_mgt *net_resource_mgt;
	struct nbl_serv_ring_mgt *ring_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct net_device *netdev;
	struct nbl_netdev_priv *net_priv;
	struct nbl_serv_ring_vsi_info *vsi_info;
	u64 last_tx_packets;
	u64 last_rx_packets;
	u64 last_get_stats_jiffies, time_diff;
	u64 tx_packets, rx_packets;
	u64 tx_rates, rx_rates, pkt_rates;
	u16 local_vector_id, vector_num;
	u16 intr_suppress_level;

	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	netdev = net_resource_mgt->netdev;
	net_priv = netdev_priv(netdev);
	ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];

	last_tx_packets = net_resource_mgt->stats.tx_packets;
	last_rx_packets = net_resource_mgt->stats.rx_packets;
	last_get_stats_jiffies = net_resource_mgt->get_stats_jiffies;
	disp_ops->get_net_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &net_resource_mgt->stats);
	/* ethtool -S don't adaptive interrupt suppression param */
	if (!vsi_info->itr_dynamic || ethtool)
		return;

	tx_packets = net_resource_mgt->stats.tx_packets;
	rx_packets = net_resource_mgt->stats.rx_packets;
	time_diff = jiffies - last_get_stats_jiffies;

	net_resource_mgt->get_stats_jiffies = jiffies;
	tx_rates = (tx_packets - last_tx_packets) / time_diff * HZ;
	rx_rates = (rx_packets - last_rx_packets) / time_diff * HZ;
	pkt_rates = max_t(u64, tx_rates, rx_rates);

	intr_suppress_level =
		disp_ops->get_intr_suppress_level(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), pkt_rates,
						  ring_mgt->vectors->intr_suppress_level);
	if (intr_suppress_level != ring_mgt->vectors->intr_suppress_level) {
		local_vector_id = ring_mgt->vectors[vsi_info->ring_offset].local_vector_id;
		vector_num = vsi_info->ring_num;
		disp_ops->set_intr_suppress_level(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						  local_vector_id, vector_num,
						  intr_suppress_level);
		ring_mgt->vectors->intr_suppress_level = intr_suppress_level;
	}
}

void nbl_serv_update_stats(struct nbl_service_mgt *serv_mgt, bool ethtool)
{
	struct nbl_serv_net_resource_mgt *net_resource_mgt;
	struct net_device *netdev;
	struct nbl_netdev_priv *net_priv;
	struct nbl_adapter *adapter;

	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	netdev = net_resource_mgt->netdev;
	net_priv = netdev_priv(netdev);
	adapter = NBL_NETDEV_TO_ADAPTER(netdev);

	if (!test_bit(NBL_RUNNING, adapter->state) ||
	    test_bit(NBL_RESETTING, adapter->state))
		return;

	nbl_serv_adjust_interrpt_param(serv_mgt, ethtool);
	netdev->stats.tx_packets = net_resource_mgt->stats.tx_packets;
	netdev->stats.tx_bytes = net_resource_mgt->stats.tx_bytes;

	netdev->stats.rx_packets = net_resource_mgt->stats.rx_packets;
	netdev->stats.rx_bytes = net_resource_mgt->stats.rx_bytes;

	/* net_device_stats */
	netdev->stats.rx_errors = 0;
	netdev->stats.tx_errors = 0;
	netdev->stats.rx_dropped = 0;
	netdev->stats.tx_dropped = 0;
	netdev->stats.multicast = 0;
	netdev->stats.rx_length_errors = 0;
}

static void
nbl_get_ethtool_stats(struct net_device *netdev, struct ethtool_stats *stats, u64 *data)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct rtnl_link_stats64 temp_stats;
	struct rtnl_link_stats64 *net_stats;
	struct nbl_stats *nbl_stats;
	struct nbl_priv_stats *nbl_priv_stats;
	struct nbl_queue_stats queue_stats = { 0 };
	struct nbl_queue_err_stats queue_err_stats = { 0 };
	struct nbl_serv_ring_vsi_info *vsi_info;
	u32 private_len = 0;
	char *p = NULL;
	int i, j, k;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];

	nbl_serv_update_stats(serv_mgt, true);
	net_stats = dev_get_stats(netdev, &temp_stats);
	nbl_stats = (struct nbl_stats *)((char *)net_resource_mgt +
				offsetof(struct nbl_serv_net_resource_mgt, stats));

	nbl_priv_stats = (struct nbl_priv_stats *)((char *)net_resource_mgt +
				offsetof(struct nbl_serv_net_resource_mgt, priv_stats));

	i = NBL_GLOBAL_STATS_LEN;
	nbl_priv_stats->total_dvn_pkt_drop_cnt = 0;
	nbl_priv_stats->total_uvn_stat_pkt_drop = 0;
	for (j = 0; j < vsi_info->active_ring_num; j++) {
		disp_ops->get_queue_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					  j, &queue_stats, true);
		disp_ops->get_queue_err_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					      j, &queue_err_stats, true);
		data[i] = queue_stats.packets;
		data[i + 1] = queue_stats.bytes;
		data[i + 2] = queue_stats.descs;
		data[i + 3] = queue_err_stats.dvn_pkt_drop_cnt;
		data[i + 4] = ring_mgt->tx_rings[vsi_info->ring_offset + j].tx_timeout_count;
		nbl_priv_stats->total_dvn_pkt_drop_cnt += queue_err_stats.dvn_pkt_drop_cnt;
		i += 5;
	}

	for (j = 0; j < vsi_info->active_ring_num; j++) {
		disp_ops->get_queue_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					  j, &queue_stats, false);
		disp_ops->get_queue_err_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					      j, &queue_err_stats, false);
		data[i] = queue_stats.packets;
		data[i + 1] = queue_stats.bytes;
		data[i + 2] = queue_stats.descs;
		data[i + 3] = queue_err_stats.uvn_stat_pkt_drop;
		nbl_priv_stats->total_uvn_stat_pkt_drop += queue_err_stats.uvn_stat_pkt_drop;
		i += 4;
	}

	for (k = 0; k < NBL_GLOBAL_STATS_LEN; k++) {
		switch (nbl_gstrings_stats[k].type) {
		case NBL_NETDEV_STATS:
			p = (char *)net_stats + nbl_gstrings_stats[k].stat_offset;
			break;
		case NBL_STATS:
			p = (char *)nbl_stats + nbl_gstrings_stats[k].stat_offset;
			break;
		case NBL_PRIV_STATS:
			p = (char *)nbl_priv_stats + nbl_gstrings_stats[k].stat_offset;
			break;
		default:
			data[k] = 0;
			continue;
		}
		data[k] = (nbl_gstrings_stats[k].sizeof_stat ==
			   sizeof(u64)) ? *(u64 *)p : *(u32 *)p;
	}

	if (!common->is_vf) {
		disp_ops->get_private_stat_len(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					       &private_len);
		disp_ops->get_private_stat_data(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						common->eth_id, &data[i],
						private_len * sizeof(u64));
	}
}

static int nbl_get_module_eeprom(struct net_device *netdev,
				 struct ethtool_eeprom *eeprom, u8 *data)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	int err;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	err = disp_ops->get_module_eeprom(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					  NBL_COMMON_TO_ETH_ID(serv_mgt->common), eeprom, data);

	return err;
}

static int nbl_get_module_info(struct net_device *netdev, struct ethtool_modinfo *info)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	int err;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	err = disp_ops->get_module_info(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					NBL_COMMON_TO_ETH_ID(serv_mgt->common), info);

	if (err)
		err = -EIO;

	return err;
}

int nbl_get_eeprom_length(struct net_device *netdev)
{
	return NBL_EEPROM_LENGTH;
}

int nbl_get_eeprom(struct net_device *netdev, struct ethtool_eeprom *eeprom, u8 *bytes)
{
	return -EINVAL;
}

static void nbl_get_channels(struct net_device *netdev, struct ethtool_channels *channels)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];

	channels->max_combined = vsi_info->ring_num;
	channels->combined_count = vsi_info->active_ring_num;
	channels->max_rx = 0;
	channels->max_tx = 0;
	channels->rx_count = 0;
	channels->tx_count = 0;
	channels->other_count = 0;
	channels->max_other = 0;
}

static int nbl_set_channels(struct net_device *netdev, struct ethtool_channels *channels)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_NETDEV_TO_COMMON(netdev);
	struct nbl_serv_ring_vsi_info *vsi_info;
	u16 queue_pairs = channels->combined_count;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];

	/* We don't support separate rx/tx channels.
	 * We don't allow setting 'other' channels.
	 */
	if (channels->rx_count || channels->tx_count || channels->other_count)
		return -EINVAL;

	if (queue_pairs > vsi_info->ring_num || queue_pairs == 0)
		return -EINVAL;

	vsi_info->active_ring_num = queue_pairs;

	netif_set_real_num_tx_queues(netdev, queue_pairs);
	netif_set_real_num_rx_queues(netdev, queue_pairs);

	disp_ops->setup_cqs(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				  NBL_COMMON_TO_VSI_ID(common), queue_pairs);

	return 0;
}

static u32 nbl_get_link(struct net_device *netdev)
{
	return netif_carrier_ok(netdev) ? 1 : 0;
}

static void nbl_link_modes_to_ethtool(u64 modes, unsigned long *ethtool_modes_map)
{
	if (modes & BIT(NBL_PORT_CAP_AUTONEG))
		__set_bit(ETHTOOL_LINK_MODE_Autoneg_BIT, ethtool_modes_map);

	if (modes & BIT(NBL_PORT_CAP_FEC_NONE))
		__set_bit(ETHTOOL_LINK_MODE_FEC_NONE_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_FEC_RS))
		__set_bit(ETHTOOL_LINK_MODE_FEC_RS_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_FEC_BASER))
		__set_bit(ETHTOOL_LINK_MODE_FEC_BASER_BIT, ethtool_modes_map);

	if ((modes & BIT(NBL_PORT_CAP_RX_PAUSE)) && (modes & BIT(NBL_PORT_CAP_TX_PAUSE))) {
		__set_bit(ETHTOOL_LINK_MODE_Pause_BIT, ethtool_modes_map);
	} else if ((modes & BIT(NBL_PORT_CAP_RX_PAUSE)) && !(modes & BIT(NBL_PORT_CAP_TX_PAUSE))) {
		__set_bit(ETHTOOL_LINK_MODE_Pause_BIT, ethtool_modes_map);
		__set_bit(ETHTOOL_LINK_MODE_Asym_Pause_BIT, ethtool_modes_map);
	} else if (!(modes & BIT(NBL_PORT_CAP_RX_PAUSE)) && (modes & BIT(NBL_PORT_CAP_TX_PAUSE))) {
		__set_bit(ETHTOOL_LINK_MODE_Asym_Pause_BIT, ethtool_modes_map);
	}

	if (modes & BIT(NBL_PORT_CAP_1000BASE_T)) {
		__set_bit(ETHTOOL_LINK_MODE_1000baseT_Full_BIT, ethtool_modes_map);
		__set_bit(ETHTOOL_LINK_MODE_1000baseT_Half_BIT, ethtool_modes_map);
	}
	if (modes & BIT(NBL_PORT_CAP_1000BASE_X))
		__set_bit(ETHTOOL_LINK_MODE_1000baseX_Full_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_10GBASE_T))
		__set_bit(ETHTOOL_LINK_MODE_1000baseX_Full_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_10GBASE_KR))
		__set_bit(ETHTOOL_LINK_MODE_10000baseKR_Full_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_10GBASE_SR))
		__set_bit(ETHTOOL_LINK_MODE_10000baseSR_Full_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_25GBASE_KR))
		__set_bit(ETHTOOL_LINK_MODE_25000baseKR_Full_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_25GBASE_SR))
		__set_bit(ETHTOOL_LINK_MODE_25000baseSR_Full_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_25GBASE_CR))
		__set_bit(ETHTOOL_LINK_MODE_25000baseCR_Full_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_50GBASE_KR2))
		__set_bit(ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_50GBASE_SR2))
		__set_bit(ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_50GBASE_CR2))
		__set_bit(ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_50G_AUI2))
		__set_bit(ETHTOOL_LINK_MODE_50000baseLR_ER_FR_Full_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_50GBASE_KR_PAM4))
		__set_bit(ETHTOOL_LINK_MODE_50000baseKR_Full_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_50GBASE_SR_PAM4))
		__set_bit(ETHTOOL_LINK_MODE_50000baseSR_Full_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_50G_AUI_PAM4))
		__set_bit(ETHTOOL_LINK_MODE_50000baseDR_Full_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_50GBASE_CR_PAM4))
		__set_bit(ETHTOOL_LINK_MODE_50000baseCR_Full_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_100GBASE_KR4))
		__set_bit(ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_100GBASE_SR4))
		__set_bit(ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_100GBASE_CR4))
		__set_bit(ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_100G_AUI4))
		__set_bit(ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_100G_CAUI4))
		__set_bit(ETHTOOL_LINK_MODE_100000baseLR2_ER2_FR2_Full_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_100GBASE_KR2_PAM4))
		__set_bit(ETHTOOL_LINK_MODE_100000baseKR2_Full_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_100GBASE_SR2_PAM4))
		__set_bit(ETHTOOL_LINK_MODE_100000baseSR2_Full_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_100GBASE_CR2_PAM4))
		__set_bit(ETHTOOL_LINK_MODE_100000baseCR2_Full_BIT, ethtool_modes_map);
	if (modes & BIT(NBL_PORT_CAP_100G_AUI2_PAM4))
		__set_bit(ETHTOOL_LINK_MODE_100000baseDR2_Full_BIT, ethtool_modes_map);
}

static int nbl_get_ksettings(struct net_device *netdev, struct ethtool_link_ksettings *cmd)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_port_state port_state = {0};
	u32 advertising_speed = 0;
	int ret = 0;

	ret = disp_ops->get_port_state(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				       NBL_COMMON_TO_ETH_ID(serv_mgt->common), &port_state);
	if (ret) {
		netdev_err(netdev, "Get port_state failed %d\n", ret);
		return -EIO;
	}

	if (!port_state.module_inplace) {
		cmd->base.autoneg = AUTONEG_DISABLE;
		cmd->base.speed = SPEED_UNKNOWN;
		cmd->base.duplex = DUPLEX_UNKNOWN;
		cmd->base.port = PORT_OTHER;
	} else {
		cmd->base.autoneg = (port_state.port_advertising & BIT(NBL_PORT_CAP_AUTONEG)) ?
				AUTONEG_ENABLE : AUTONEG_DISABLE;

		if (port_state.link_state) {
			cmd->base.speed = port_state.link_speed;
			cmd->base.duplex = DUPLEX_FULL;
		} else {
			cmd->base.speed = SPEED_UNKNOWN;
			cmd->base.duplex = DUPLEX_UNKNOWN;
		}

		advertising_speed = net_resource_mgt->configured_speed ?
				    net_resource_mgt->configured_speed : cmd->base.speed;

		switch (port_state.port_type) {
		case NBL_PORT_TYPE_UNKNOWN:
			cmd->base.port = PORT_OTHER;
			break;
		case NBL_PORT_TYPE_FIBRE:
			__set_bit(ETHTOOL_LINK_MODE_FIBRE_BIT, cmd->link_modes.advertising);
			cmd->base.port = PORT_FIBRE;
			break;
		case NBL_PORT_TYPE_COPPER:
			__set_bit(ETHTOOL_LINK_MODE_Backplane_BIT, cmd->link_modes.advertising);
			cmd->base.port = PORT_DA;
			break;
		default:
			cmd->base.port = PORT_OTHER;
		}
	}

	if (!cmd->base.autoneg) {
		port_state.port_advertising &= ~NBL_PORT_CAP_SPEED_MASK;
		switch (advertising_speed) {
		case SPEED_1000:
			port_state.port_advertising |= NBL_PORT_CAP_SPEED_1G_MASK;
			break;
		case SPEED_10000:
			port_state.port_advertising |= NBL_PORT_CAP_SPEED_10G_MASK;
			break;
		case SPEED_25000:
			port_state.port_advertising |= NBL_PORT_CAP_SPEED_25G_MASK;
			break;
		case SPEED_50000:
			port_state.port_advertising |= NBL_PORT_CAP_SPEED_50G_MASK;
			break;
		case SPEED_100000:
			port_state.port_advertising |= NBL_PORT_CAP_SPEED_100G_MASK;
			break;
		default:
			break;
		}
	}

	nbl_link_modes_to_ethtool(port_state.port_caps, cmd->link_modes.supported);
	nbl_link_modes_to_ethtool(port_state.port_advertising, cmd->link_modes.advertising);
	nbl_link_modes_to_ethtool(port_state.port_lp_advertising, cmd->link_modes.lp_advertising);

	__set_bit(ETHTOOL_LINK_MODE_FIBRE_BIT, cmd->link_modes.supported);
	__set_bit(ETHTOOL_LINK_MODE_Backplane_BIT, cmd->link_modes.supported);
	return 0;
}

static u32 nbl_conver_portrate_to_speed(u8 port_rate)
{
	switch (port_rate) {
	case NBL_PORT_MAX_RATE_1G:
		return SPEED_1000;
	case NBL_PORT_MAX_RATE_10G:
		return SPEED_10000;
	case NBL_PORT_MAX_RATE_25G:
		return SPEED_25000;
	case NBL_PORT_MAX_RATE_100G:
	case NBL_PORT_MAX_RATE_100G_PAM4:
		return SPEED_100000;
	default:
		return SPEED_25000;
	}

	/* default set 25G */
	return SPEED_25000;
}

static u32 nbl_conver_fw_rate_to_speed(u8 fw_port_max_speed)
{
	switch (fw_port_max_speed) {
	case NBL_FW_PORT_SPEED_10G:
		return SPEED_10000;
	case NBL_FW_PORT_SPEED_25G:
		return SPEED_25000;
	case NBL_FW_PORT_SPEED_50G:
		return SPEED_50000;
	case NBL_FW_PORT_SPEED_100G:
		return SPEED_100000;
	default:
		return SPEED_25000;
	}

	/* default set 25G */
	return SPEED_25000;
}

static int nbl_set_ksettings(struct net_device *netdev, const struct ethtool_link_ksettings *cmd)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_serv_net_resource_mgt *net_resource_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_phy_state *phy_state;
	struct nbl_phy_caps *phy_caps;
	struct nbl_port_state port_state = {0};
	struct nbl_port_advertising port_advertising = {0};
	u32 autoneg = 0;
	u32 speed, fw_speed, module_speed, max_speed;
	u64 speed_advert = 0;
	u8 active_fec = 0;
	int ret = 0;

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	phy_state = &net_resource_mgt->phy_state;
	phy_caps = &net_resource_mgt->phy_caps;

	ret = disp_ops->get_port_state(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				       NBL_COMMON_TO_ETH_ID(serv_mgt->common), &port_state);
	if (ret) {
		netdev_err(netdev, "Get port_state failed %d\n", ret);
		return -EIO;
	}

	if (!port_state.module_inplace) {
		netdev_err(netdev, "Optical module is not inplace\n");
		return -EINVAL;
	}

	if (cmd->base.autoneg) {
		if (!(port_state.port_caps & BIT(NBL_PORT_CAP_AUTONEG))) {
			netdev_err(netdev, "autoneg is not support\n");
			return -EOPNOTSUPP;
		}
	}

	if (cmd->base.duplex == DUPLEX_HALF) {
		netdev_err(netdev, "half duplex is not support\n");
		return -EOPNOTSUPP;
	}

	autoneg = (port_state.port_advertising & BIT(NBL_PORT_CAP_AUTONEG)) ?
		   AUTONEG_ENABLE : AUTONEG_DISABLE;

	speed = cmd->base.speed;
	fw_speed = nbl_conver_fw_rate_to_speed(port_state.fw_port_max_speed);
	module_speed = nbl_conver_portrate_to_speed(port_state.port_max_rate);
	max_speed = fw_speed > module_speed ? module_speed : fw_speed;
	if (speed == SPEED_UNKNOWN)
		speed = max_speed;

	if (speed > max_speed) {
		netdev_err(netdev, "speed %d is not support, exit\n", cmd->base.speed);
		return -EINVAL;
	}

	speed_advert = nbl_speed_to_link_mode(speed, cmd->base.autoneg);
	speed_advert &= port_state.port_caps;
	if (!speed_advert) {
		netdev_err(netdev, "speed %d is not support, exit\n", cmd->base.speed);
		return -EINVAL;
	}

	if (cmd->base.autoneg)
		speed = max_speed;

	if (cmd->base.autoneg) {
		switch (net_resource_mgt->configured_fec) {
		case ETHTOOL_FEC_OFF:
			active_fec = NBL_PORT_FEC_OFF;
			break;
		case ETHTOOL_FEC_BASER:
			active_fec = NBL_PORT_FEC_BASER;
			break;
		case ETHTOOL_FEC_RS:
			active_fec = NBL_PORT_FEC_RS;
			break;
		default:
			active_fec = NBL_PORT_FEC_AUTO;
		}
	} else {
		/* when change speed, we should set appropriate fec mode */
		switch (speed) {
		case SPEED_1000:
			active_fec = NBL_ETH_1G_DEFAULT_FEC_MODE;
			net_resource_mgt->configured_fec = ETHTOOL_FEC_OFF;
			break;
		case SPEED_10000:
			active_fec = NBL_ETH_10G_DEFAULT_FEC_MODE;
			net_resource_mgt->configured_fec = ETHTOOL_FEC_OFF;
			break;
		case SPEED_25000:
			active_fec = NBL_ETH_25G_DEFAULT_FEC_MODE;
			net_resource_mgt->configured_fec = ETHTOOL_FEC_RS;
			break;
		case SPEED_50000:
		case SPEED_100000:
			active_fec = NBL_ETH_100G_DEFAULT_FEC_MODE;
			net_resource_mgt->configured_fec = ETHTOOL_FEC_RS;
			break;
		default:
			active_fec = NBL_PORT_FEC_RS;
			net_resource_mgt->configured_fec = ETHTOOL_FEC_RS;
		}
	}

	port_advertising.eth_id = NBL_COMMON_TO_ETH_ID(serv_mgt->common);
	port_advertising.speed_advert = speed_advert;
	port_advertising.autoneg = cmd->base.autoneg;
	port_advertising.active_fec = active_fec;

	/* update speed */
	ret = disp_ops->set_port_advertising(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					  &port_advertising);
	if (ret) {
		netdev_err(netdev, "set autoneg %d speed %d failed %d\n",
			   cmd->base.autoneg, cmd->base.speed, ret);
		return -EIO;
	}

	net_resource_mgt->configured_speed = speed;

	return 0;
}

static void nbl_get_ringparam(struct net_device *netdev, struct ethtool_ringparam *ringparam,
			      struct kernel_ethtool_ringparam *k_ringparam,
			      struct netlink_ext_ack *extack)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dispatch_mgt *disp_mgt = NBL_ADAPTER_TO_DISP_MGT(adapter);
	struct nbl_dispatch_ops *disp_ops = NBL_ADAPTER_TO_DISP_OPS_TBL(adapter)->ops;
	u16 max_desc_num;

	max_desc_num = disp_ops->get_max_desc_num(disp_mgt);
	ringparam->tx_max_pending = max_desc_num;
	ringparam->rx_max_pending = max_desc_num;
	ringparam->tx_pending = disp_ops->get_tx_desc_num(disp_mgt, 0);
	ringparam->rx_pending = disp_ops->get_rx_desc_num(disp_mgt, 0);
}

static int nbl_check_set_ringparam(struct net_device *netdev,
				   struct ethtool_ringparam *ringparam,
				   u16 max_desc_num, u16 min_desc_num)
{
	/* check if tx_pending is out of range or power of 2 */
	if (ringparam->tx_pending > max_desc_num ||
	    ringparam->tx_pending < min_desc_num) {
		netdev_err(netdev, "Tx descriptors requested: %d, out of range[%d-%d]\n",
			   ringparam->tx_pending, min_desc_num, max_desc_num);
		return -EINVAL;
	}
	if (ringparam->tx_pending & (ringparam->tx_pending - 1)) {
		netdev_err(netdev, "Tx descriptors requested: %d is not power of 2\n",
			   ringparam->tx_pending);
		return -EINVAL;
	}

	/* check if rx_pending is out of range or power of 2 */
	if (ringparam->rx_pending > max_desc_num ||
	    ringparam->rx_pending < min_desc_num) {
		netdev_err(netdev, "Rx descriptors requested: %d, out of range[%d-%d]\n",
			   ringparam->rx_pending, min_desc_num, max_desc_num);
		return -EINVAL;
	}
	if (ringparam->rx_pending & (ringparam->rx_pending - 1)) {
		netdev_err(netdev, "Rx descriptors requested: %d is not power of 2\n",
			   ringparam->rx_pending);
		return -EINVAL;
	}

	if (ringparam->rx_jumbo_pending || ringparam->rx_mini_pending) {
		netdev_err(netdev, "rx_jumbo_pending or rx_mini_pending is not supported\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

static int nbl_pre_set_ringparam(struct net_device *netdev, struct ethtool_ringparam *ringparam)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dispatch_mgt *disp_mgt = NBL_ADAPTER_TO_DISP_MGT(adapter);
	struct nbl_dispatch_ops *disp_ops = NBL_ADAPTER_TO_DISP_OPS_TBL(adapter)->ops;
	int timeout = 50;

	if (ringparam->rx_pending == disp_ops->get_rx_desc_num(disp_mgt, 0) &&
	    ringparam->tx_pending == disp_ops->get_tx_desc_num(disp_mgt, 0)) {
		netdev_dbg(netdev, "Nothing to change, descriptor count is same as requested\n");
		return 0;
	}

	while (test_and_set_bit(NBL_RESETTING, adapter->state)) {
		timeout--;
		if (!timeout) {
			netdev_err(netdev, "Timeout while resetting in set ringparam\n");
			return -EBUSY;
		}
		usleep_range(1000, 2000);
	}

	/* configure params later */
	return 1;
}

static int nbl_set_ringparam(struct net_device *netdev, struct ethtool_ringparam *ringparam,
			     struct kernel_ethtool_ringparam *k_ringparam,
			     struct netlink_ext_ack *extack)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_dispatch_mgt *disp_mgt = NBL_ADAPTER_TO_DISP_MGT(adapter);
	struct nbl_dispatch_ops *disp_ops = NBL_ADAPTER_TO_DISP_OPS_TBL(adapter)->ops;
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info;
	u16 max_desc_num, min_desc_num;
	u16 new_tx_count, new_rx_count;
	int was_running;
	int i;
	int err;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];
	max_desc_num = disp_ops->get_max_desc_num(disp_mgt);
	min_desc_num = disp_ops->get_min_desc_num(disp_mgt);
	err = nbl_check_set_ringparam(netdev, ringparam, max_desc_num, min_desc_num);
	if (err < 0)
		return err;

	err = nbl_pre_set_ringparam(netdev, ringparam);
	/* if either error occur or nothing to change, return */
	if (err <= 0)
		return err;

	new_tx_count = ringparam->tx_pending;
	new_rx_count = ringparam->rx_pending;

	netdev_info(netdev, "set tx_desc_num:%d, rx_desc_num:%d\n", new_tx_count, new_rx_count);

	was_running = netif_running(netdev);

	if (was_running) {
		err = nbl_serv_netdev_stop(netdev);
		if (err) {
			netdev_err(netdev, "Netdev stop failed while setting ringparam\n");
			clear_bit(NBL_RESETTING, adapter->state);
			return err;
		}
	}

	ring_mgt->tx_desc_num = new_tx_count;
	ring_mgt->rx_desc_num = new_rx_count;

	for (i = vsi_info->ring_offset; i < vsi_info->ring_offset + vsi_info->ring_num; i++)
		disp_ops->set_tx_desc_num(disp_mgt, i, new_tx_count);

	for (i = vsi_info->ring_offset; i < vsi_info->ring_offset + vsi_info->ring_num; i++)
		disp_ops->set_rx_desc_num(disp_mgt, i, new_rx_count);

	if (was_running) {
		err = nbl_serv_netdev_open(netdev);
		if (err) {
			netdev_err(netdev, "Netdev open failed after setting ringparam\n");
			clear_bit(NBL_RESETTING, adapter->state);
			return err;
		}
	}

	clear_bit(NBL_RESETTING, adapter->state);

	return 0;
}

static int nbl_get_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd, u32 *rule_locs)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info;
	int ret = -EOPNOTSUPP;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];

	switch (cmd->cmd) {
	case ETHTOOL_GRXRINGS:
		cmd->data = vsi_info->active_ring_num;
		ret = 0;
		break;
	default:
		break;
	}

	return ret;
}

static u32 nbl_get_rxfh_indir_size(struct net_device *netdev)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_common_info *common;
	u32 rxfh_indir_size = 0;

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	common = NBL_SERV_MGT_TO_COMMON(serv_mgt);

	disp_ops->get_rxfh_indir_size(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				      NBL_COMMON_TO_VSI_ID(common), &rxfh_indir_size);

	return rxfh_indir_size;
}

static u32 nbl_get_rxfh_key_size(struct net_device *netdev)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;
	u32 rxfh_rss_key_size = 0;

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->get_rxfh_rss_key_size(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &rxfh_rss_key_size);

	return rxfh_rss_key_size;
}

static int nbl_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key, u8 *hfunc)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_common_info *common;
	u32 rxfh_key_size = 0;
	u32 rxfh_indir_size = 0;

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	common = NBL_SERV_MGT_TO_COMMON(serv_mgt);

	disp_ops->get_rxfh_rss_key_size(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &rxfh_key_size);
	disp_ops->get_rxfh_indir_size(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				      NBL_COMMON_TO_VSI_ID(common), &rxfh_indir_size);

	if (indir)
		disp_ops->get_rxfh_indir(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					 NBL_COMMON_TO_VSI_ID(common), indir, rxfh_indir_size);
	if (key)
		disp_ops->get_rxfh_rss_key(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), key, rxfh_key_size);
	if (hfunc)
		disp_ops->get_rxfh_rss_alg_sel(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					       hfunc, NBL_COMMON_TO_ETH_ID(serv_mgt->common));

	return 0;
}

static u32 nbl_get_msglevel(struct net_device *netdev)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	u32 debug_lvl = common->debug_lvl;

	if (debug_lvl)
		netdev_dbg(netdev, "nbl debug_lvl: 0x%08X\n", debug_lvl);

	return common->msg_enable;
}

static void nbl_set_msglevel(struct net_device *netdev, u32 msglevel)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);

	if (NBL_DEBUG_USER & msglevel)
		common->debug_lvl = msglevel;
	else
		common->msg_enable = msglevel;
}

static int nbl_get_regs_len(struct net_device *netdev)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	return disp_ops->get_reg_dump_len(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static void nbl_get_ethtool_dump_regs(struct net_device *netdev, struct ethtool_regs *regs, void *p)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->get_reg_dump(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), p, regs->len);
}

static int nbl_get_per_queue_coalesce(struct net_device *netdev,
				      u32 q_num, struct ethtool_coalesce *ec)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info;
	u16 local_vector_id, configured_usecs;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];

	if (q_num >= vsi_info->ring_offset + vsi_info->ring_num) {
		netdev_err(netdev, "q_num %d is too larger\n", q_num);
		return -EINVAL;
	}

	local_vector_id = ring_mgt->vectors[q_num + vsi_info->ring_offset].local_vector_id;
	configured_usecs = ring_mgt->vectors[q_num + vsi_info->ring_offset].intr_rate_usecs;
	disp_ops->get_coalesce(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), local_vector_id, ec);

	if (vsi_info->itr_dynamic) {
		ec->use_adaptive_tx_coalesce = 1;
		ec->use_adaptive_rx_coalesce = 1;
	} else {
		if (configured_usecs) {
			ec->tx_coalesce_usecs = configured_usecs;
			ec->rx_coalesce_usecs = configured_usecs;
		}
	}
	return 0;
}

static int __nbl_set_per_queue_coalesce(struct net_device *netdev,
					u32 q_num, struct ethtool_coalesce *ec)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info;
	struct ethtool_coalesce ec_local = {0};
	u16 local_vector_id, pnum, rate;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];

	if (q_num >= vsi_info->ring_offset + vsi_info->ring_num) {
		netdev_err(netdev, "q_num %d is too larger\n", q_num);
		return -EINVAL;
	}

	if (ec->rx_max_coalesced_frames > U16_MAX) {
		netdev_err(netdev, "rx_frames %d out of range: [0 - %d]\n",
			   ec->rx_max_coalesced_frames, U16_MAX);
		return -EINVAL;
	}

	if (ec->rx_coalesce_usecs > U16_MAX) {
		netdev_err(netdev, "rx_usecs %d out of range: [0 - %d]\n",
			   ec->rx_coalesce_usecs, U16_MAX);
		return -EINVAL;
	}

	if (ec->tx_max_coalesced_frames != ec->rx_max_coalesced_frames ||
	    ec->tx_coalesce_usecs != ec->rx_coalesce_usecs) {
		netdev_err(netdev, "tx and rx using the same interrupt, rx params should equal to tx params\n");
		return -EINVAL;
	}

	if (ec->use_adaptive_tx_coalesce != ec->use_adaptive_rx_coalesce)  {
		netdev_err(netdev, "rx and tx adaptive need configure as same value.\n");
		return -EINVAL;
	}

	if (vsi_info->itr_dynamic) {
		nbl_get_per_queue_coalesce(netdev, q_num, &ec_local);
		if (ec_local.rx_coalesce_usecs != ec->rx_coalesce_usecs ||
		    ec_local.rx_max_coalesced_frames != ec->rx_max_coalesced_frames) {
			netdev_err(netdev,
				   "interrupt throttling cannot be changged if adaptive is enable.\n");
			return -EINVAL;
		}
		return 0;
	}

	local_vector_id = ring_mgt->vectors[q_num + vsi_info->ring_offset].local_vector_id;
	pnum = (u16)ec->tx_max_coalesced_frames;
	rate = (u16)ec->tx_coalesce_usecs;
	ring_mgt->vectors[q_num + vsi_info->ring_offset].intr_rate_usecs = rate;

	disp_ops->set_coalesce(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), local_vector_id,
			       1, pnum, rate);
	return 0;
}

static int nbl_set_per_queue_coalesce(struct net_device *netdev,
				      u32 q_num, struct ethtool_coalesce *ec)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];

	if (vsi_info->itr_dynamic != (!!ec->use_adaptive_rx_coalesce)) {
		netdev_err(netdev, "modify interrupt adaptive by queue is not supported.\n");
		return -EINVAL;
	}

	return __nbl_set_per_queue_coalesce(netdev, q_num, ec);
}

static int nbl_get_coalesce(struct net_device *netdev, struct ethtool_coalesce *ec,
			    struct kernel_ethtool_coalesce *kernel_ec,
			    struct netlink_ext_ack *extack)
{
	u32 q_num = 0;

	return nbl_get_per_queue_coalesce(netdev, q_num, ec);
}

static int nbl_set_coalesce(struct net_device *netdev, struct ethtool_coalesce *ec,
			    struct kernel_ethtool_coalesce *kernel_ec,
			    struct netlink_ext_ack *extack)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info;
	struct ethtool_coalesce ec_local = {0};
	u16 local_vector_id;
	u16 intr_suppress_level;
	u16 q_num;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];

	if (ec->rx_max_coalesced_frames > U16_MAX) {
		netdev_err(netdev, "rx_frames %d out of range: [0 - %d]\n",
			   ec->rx_max_coalesced_frames, U16_MAX);
		return -EINVAL;
	}

	if (ec->rx_coalesce_usecs > U16_MAX) {
		netdev_err(netdev, "rx_usecs %d out of range: [0 - %d]\n",
			   ec->rx_coalesce_usecs, U16_MAX);
		return -EINVAL;
	}

	if (ec->rx_max_coalesced_frames != ec->tx_max_coalesced_frames) {
		netdev_err(netdev, "rx_frames and tx_frames need configure as same value.\n");
		return -EINVAL;
	}

	if (ec->rx_coalesce_usecs != ec->tx_coalesce_usecs) {
		netdev_err(netdev, "rx_usecs and tx_usecs need configure as same value.\n");
		return -EINVAL;
	}

	if (ec->use_adaptive_tx_coalesce != ec->use_adaptive_rx_coalesce)  {
		netdev_err(netdev, "rx and tx adaptive need configure as same value.\n");
		return -EINVAL;
	}

	if (vsi_info->itr_dynamic && ec->use_adaptive_rx_coalesce) {
		nbl_get_per_queue_coalesce(netdev, 0, &ec_local);
		if (ec_local.rx_coalesce_usecs != ec->rx_coalesce_usecs ||
		    ec_local.rx_max_coalesced_frames != ec->rx_max_coalesced_frames) {
			netdev_err(netdev,
				   "interrupt throttling cannont be changged if adaptive is enable.\n");
			return -EINVAL;
		}
	}

	if (ec->use_adaptive_rx_coalesce) {
		vsi_info->itr_dynamic = true;
		local_vector_id = ring_mgt->vectors[vsi_info->ring_offset].local_vector_id;
		intr_suppress_level = ring_mgt->vectors->intr_suppress_level;
		disp_ops->set_intr_suppress_level(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						  local_vector_id, vsi_info->ring_num,
						  intr_suppress_level);
	} else {
		vsi_info->itr_dynamic = false;
		for (q_num = 0; q_num < vsi_info->ring_num; q_num++)
			__nbl_set_per_queue_coalesce(netdev,
						     vsi_info->ring_offset + q_num,
						     ec);
	}

	return 0;
}

static u64 nbl_link_test(struct net_device *netdev)
{
	bool link_up;

	/* TODO will get from emp in later version */
	link_up = 0;

	return link_up;
}

static int nbl_loopback_setup_rings(struct nbl_adapter *adapter, struct net_device *netdev)
{
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);

	return nbl_serv_vsi_open(serv_mgt, netdev, NBL_VSI_DATA, 1, 0);
}

static void nbl_loopback_free_rings(struct nbl_adapter *adapter, struct net_device *netdev)
{
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);

	nbl_serv_vsi_stop(serv_mgt, NBL_VSI_DATA);
}

static void nbl_loopback_create_skb(struct sk_buff *skb, u32 size)
{
	if (!skb)
		return;

	memset(skb->data, NBL_SELF_TEST_PADDING_DATA_1, size);
	size >>= 1;
	memset(&skb->data[size], NBL_SELF_TEST_PADDING_DATA_2, size);
	skb->data[size + NBL_SELF_TEST_POS_2] = NBL_SELF_TEST_BYTE_1;
	skb->data[size + NBL_SELF_TEST_POS_3] = NBL_SELF_TEST_BYTE_2;
}

static s32 nbl_loopback_check_skb(struct sk_buff *skb, u32 size)
{
	size >>= 1;

	if (skb->data[NBL_SELF_TEST_POS_1] != NBL_SELF_TEST_PADDING_DATA_1 ||
	    skb->data[size + NBL_SELF_TEST_POS_2] != NBL_SELF_TEST_BYTE_1 ||
	    skb->data[size + NBL_SELF_TEST_POS_3] != NBL_SELF_TEST_BYTE_2)
		return -1;

	return 0;
}

static s32 nbl_loopback_run_test(struct net_device *netdev)
{
	struct nbl_netdev_priv *priv = netdev_priv(netdev);
	struct nbl_adapter *adapter = NBL_NETDEV_PRIV_TO_ADAPTER(priv);
	struct nbl_dispatch_ops *disp_ops = NBL_ADAPTER_TO_DISP_OPS_TBL(adapter)->ops;
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_resource_pt_ops *pt_ops = NBL_ADAPTER_TO_RES_PT_OPS(adapter);
	struct sk_buff *skb_tx[NBL_SELF_TEST_PKT_NUM] = {NULL}, *skb_rx;
	u32 size = NBL_SELF_TEST_BUFF_SIZE;
	u32 count;
	u32 tx_count = 0;
	s32 result = 0;
	int i;

	for (i = 0; i < NBL_SELF_TEST_PKT_NUM; i++) {
		skb_tx[i] = alloc_skb(size, GFP_KERNEL);
		if (!skb_tx[i])
			goto alloc_skb_faied;

		nbl_loopback_create_skb(skb_tx[i], size);
		skb_put(skb_tx[i], size);
		skb_tx[i]->queue_mapping = 0;
	}

	count = min_t(u16, serv_mgt->ring_mgt.tx_desc_num, NBL_SELF_TEST_PKT_NUM);
	count = min_t(u16, serv_mgt->ring_mgt.rx_desc_num, count);

	for (i = 0; i < count; i++) {
		skb_get(skb_tx[i]);
		if (pt_ops->self_test_xmit(skb_tx[i], netdev) != NETDEV_TX_OK)
			netdev_err(netdev, "Fail to tx lb skb %p", skb_tx[i]);
		else
			tx_count++;
	}

	if (tx_count < count) {
		for (i = 0; i < NBL_SELF_TEST_PKT_NUM; i++)
			kfree_skb(skb_tx[i]);
		result |= BIT(NBL_LB_ERR_TX_FAIL);
		return result;
	}

	/* Wait for rx packets loopback */
	msleep(1000);

	for (i = 0; i < tx_count; i++) {
		skb_rx = NULL;
		skb_rx = disp_ops->clean_rx_lb_test(NBL_ADAPTER_TO_DISP_MGT(adapter), 0);
		if (!skb_rx) {
			netdev_err(netdev, "Fail to rx lb skb, should rx %d but fail on %d",
				   tx_count, i);
			break;
		}
		if (nbl_loopback_check_skb(skb_rx, size)) {
			netdev_err(netdev, "Fail to check lb skb %d(%p)", i, skb_rx);
			kfree(skb_rx);
			break;
		}
		kfree(skb_rx);
	}

	if (i != tx_count)
		result |= BIT(NBL_LB_ERR_RX_FAIL);

	for (i = 0; i < NBL_SELF_TEST_PKT_NUM; i++)
		kfree_skb(skb_tx[i]);

	return result;

alloc_skb_faied:
	for (i = 0; i < NBL_SELF_TEST_PKT_NUM; i++) {
		if (skb_tx[i])
			kfree_skb(skb_tx[i]);
	}
	result |= BIT(NBL_LB_ERR_SKB_ALLOC);
	return result;
}

static u64 nbl_loopback_test(struct net_device *netdev)
{
	struct nbl_netdev_priv *priv = netdev_priv(netdev);
	struct nbl_adapter *adapter = NBL_NETDEV_PRIV_TO_ADAPTER(priv);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_ring_mgt *ring_mgt = &serv_mgt->ring_mgt;
	struct nbl_dispatch_ops *disp_ops = NBL_ADAPTER_TO_DISP_OPS_TBL(adapter)->ops;
	struct nbl_serv_ring_vsi_info *vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];
	u8 origin_num_txq, origin_num_rxq, origin_active_q;
	u64 result = 0;

	/* In loopback test, we only need one queue */
	origin_num_txq = ring_mgt->tx_ring_num;
	origin_num_rxq = ring_mgt->rx_ring_num;
	origin_active_q = vsi_info->active_ring_num;
	ring_mgt->tx_ring_num = NBL_SELF_TEST_Q_NUM;
	ring_mgt->rx_ring_num = NBL_SELF_TEST_Q_NUM;

	if (nbl_loopback_setup_rings(adapter, netdev)) {
		netdev_err(netdev, "Fail to setup rings");
		result |= BIT(NBL_LB_ERR_RING_SETUP);
		goto lb_setup_rings_failed;
	}

	if (disp_ops->set_eth_loopback(NBL_ADAPTER_TO_DISP_MGT(adapter), NBL_ETH_LB_ON)) {
		netdev_err(netdev, "Fail to setup lb on");
		result |= BIT(NBL_LB_ERR_LB_MODE_SETUP);
		goto set_eth_lb_failed;
	}

	result |= nbl_loopback_run_test(netdev);

	if (disp_ops->set_eth_loopback(NBL_ADAPTER_TO_DISP_MGT(adapter), NBL_ETH_LB_OFF)) {
		netdev_err(netdev, "Fail to setup lb off");
		result |= BIT(NBL_LB_ERR_LB_MODE_SETUP);
		goto set_eth_lb_failed;
	}

set_eth_lb_failed:
	nbl_loopback_free_rings(adapter, netdev);
lb_setup_rings_failed:
	ring_mgt->tx_ring_num = origin_num_txq;
	ring_mgt->rx_ring_num = origin_num_rxq;
	vsi_info->active_ring_num = origin_active_q;

	return result;
}

static u32 nbl_mailbox_check_active_vf(struct nbl_adapter *adapter)
{
	struct nbl_dispatch_ops_tbl *disp_ops_tbl = NBL_ADAPTER_TO_DISP_OPS_TBL(adapter);

	return disp_ops_tbl->ops->check_active_vf(NBL_ADAPTER_TO_DISP_MGT(adapter));
}

static void nbl_self_test(struct net_device *netdev, struct ethtool_test *eth_test, u64 *data)
{
	struct nbl_netdev_priv *priv = netdev_priv(netdev);
	struct nbl_adapter *adapter = NBL_NETDEV_PRIV_TO_ADAPTER(priv);
	bool if_running = netif_running(netdev);
	u32 active_vf;
	s64 cur_time = 0;
	int ret;

	cur_time = ktime_get_real_seconds();

	/* test too frequently will cause to fail */
	if (cur_time - priv->last_st_time < NBL_SELF_TEST_TIME_GAP) {
		/* pass by defalut */
		netdev_info(netdev, "Self test too fast, pass by default!");
		data[NBL_ETH_TEST_REG] = 0;
		data[NBL_ETH_TEST_EEPROM] = 0;
		data[NBL_ETH_TEST_INTR] = 0;
		data[NBL_ETH_TEST_LOOP] = 0;
		data[NBL_ETH_TEST_LINK] = 0;
		return;
	}

	if (eth_test->flags == ETH_TEST_FL_OFFLINE) {
		active_vf = nbl_mailbox_check_active_vf(adapter);

		if (active_vf) {
			netdev_err(netdev, "Cannot perform offline test when VFs are active");
			data[NBL_ETH_TEST_REG] = 1;
			data[NBL_ETH_TEST_EEPROM] = 1;
			data[NBL_ETH_TEST_INTR] = 1;
			data[NBL_ETH_TEST_LOOP] = 1;
			data[NBL_ETH_TEST_LINK] = 1;
			eth_test->flags |= ETH_TEST_FL_FAILED;
			return;
		}

		/* If online, take if offline */
		if (if_running) {
			ret = nbl_serv_netdev_stop(netdev);
			if (ret) {
				netdev_err(netdev, "Could not stop device %s, err %d\n",
					   pci_name(adapter->pdev), ret);
				goto netdev_stop_failed;
			}
		}

		set_bit(NBL_TESTING, adapter->state);

		data[NBL_ETH_TEST_LINK] = nbl_link_test(netdev);
		data[NBL_ETH_TEST_EEPROM] = 0;
		data[NBL_ETH_TEST_INTR] = 0;
		data[NBL_ETH_TEST_LOOP] = nbl_loopback_test(netdev);
		data[NBL_ETH_TEST_REG] = 0;

		if (data[NBL_ETH_TEST_LINK] ||
		    data[NBL_ETH_TEST_EEPROM] ||
		    data[NBL_ETH_TEST_INTR] ||
		    data[NBL_ETH_TEST_LOOP] ||
		    data[NBL_ETH_TEST_REG])
			eth_test->flags |= ETH_TEST_FL_FAILED;

		clear_bit(NBL_TESTING, adapter->state);
		if (if_running) {
			ret = nbl_serv_netdev_open(netdev);
			if (ret) {
				netdev_err(netdev, "Could not open device %s, err %d\n",
					   pci_name(adapter->pdev), ret);
			}
		}
	} else {
		/* Online test */
		data[NBL_ETH_TEST_LINK] = nbl_link_test(netdev);

		if (data[NBL_ETH_TEST_LINK])
			eth_test->flags |= ETH_TEST_FL_FAILED;
		/* Only test offlined; pass by default */
		data[NBL_ETH_TEST_EEPROM] = 0;
		data[NBL_ETH_TEST_INTR] = 0;
		data[NBL_ETH_TEST_LOOP] = 0;
		data[NBL_ETH_TEST_REG] = 0;
	}

netdev_stop_failed:
	priv->last_st_time = ktime_get_real_seconds();
}

static u32 nbl_get_priv_flags(struct net_device *netdev)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	u32 ret_flags = 0;
	unsigned int i;
	int count = 0;

	for (i = 0; i < NBL_PRIV_FLAG_ARRAY_SIZE; i++) {
		enum nbl_fix_cap_type capability_type = nbl_gstrings_priv_flags[i].capability_type;

		if (nbl_gstrings_priv_flags[i].supported_by_capability) {
			if (!disp_ops->get_product_fix_cap(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
							   capability_type))
				continue;
		}

		if (test_bit(i, serv_mgt->flags))
			ret_flags |= BIT(count);
		count++;
	}

	netdev_dbg(netdev, "get priv flag: 0x%08x, mgt flags: 0x%08x.\n",
		   ret_flags, *(u32 *)serv_mgt->flags);

	return ret_flags;
}

static int nbl_set_priv_flags(struct net_device *netdev, u32 priv_flags)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	unsigned int i;
	int count = 0;
	u32 new_flags = 0;

	for (i = 0; i < NBL_PRIV_FLAG_ARRAY_SIZE; i++) {
		enum nbl_fix_cap_type capability_type = nbl_gstrings_priv_flags[i].capability_type;

		if (nbl_gstrings_priv_flags[i].supported_by_capability) {
			if (!disp_ops->get_product_fix_cap(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
							   capability_type))
				continue;
		}

		if (!nbl_gstrings_priv_flags[i].supported_modify &&
		    (!((priv_flags & BIT(count))) != !test_bit(i, serv_mgt->flags))) {
			netdev_err(netdev, "set priv flag: 0x%08x, flag %s not support modify\n",
				   priv_flags, nbl_gstrings_priv_flags[i].flag_name);
			return -EOPNOTSUPP;
		}

		if (priv_flags & BIT(count))
			new_flags |= BIT(i);
		count++;
	}
	*serv_mgt->flags = new_flags;

	netdev_dbg(netdev, "set priv flag: 0x%08x, mgt flags: 0x%08x.\n",
		   priv_flags, *(u32 *)serv_mgt->flags);

	return 0;
}

static int nbl_set_pause_param(struct net_device *netdev, struct ethtool_pauseparam *param)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_serv_net_resource_mgt *net_resource_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_phy_state *phy_state;
	struct nbl_phy_caps *phy_caps;
	struct nbl_port_state port_state = {0};
	struct nbl_port_advertising port_advertising = {0};
	u32 autoneg = 0;
	/* cannot set default 0, 0 means pause donot change */
	u8 active_fc = NBL_PORT_TXRX_PAUSE_OFF;
	int ret = 0;

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	phy_state = &net_resource_mgt->phy_state;
	phy_caps = &net_resource_mgt->phy_caps;

	ret = disp_ops->get_port_state(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				       NBL_COMMON_TO_ETH_ID(serv_mgt->common), &port_state);
	if (ret) {
		netdev_err(netdev, "Get port_state failed %d\n", ret);
		return -EIO;
	}

	if (!port_state.module_inplace) {
		netdev_err(netdev, "Optical module is not inplace\n");
		return -EINVAL;
	}

	autoneg = (port_state.port_advertising & BIT(NBL_PORT_CAP_AUTONEG)) ?
		   AUTONEG_ENABLE : AUTONEG_DISABLE;

	if (param->autoneg == AUTONEG_ENABLE) {
		netdev_info(netdev, "pause autoneg is not support\n");
		return -EOPNOTSUPP;
	}

	/* check if the pause mode is changed */
	if (param->rx_pause == !!(port_state.active_fc & NBL_PORT_RX_PAUSE) &&
	    param->tx_pause == !!(port_state.active_fc & NBL_PORT_TX_PAUSE)) {
		netdev_info(netdev, "pause param is not changed\n");
		return 0;
	}

	if (param->rx_pause)
		active_fc |= NBL_PORT_RX_PAUSE;

	if (param->tx_pause)
		active_fc |= NBL_PORT_TX_PAUSE;

	port_advertising.eth_id = NBL_COMMON_TO_ETH_ID(serv_mgt->common);
	port_advertising.active_fc = active_fc;
	port_advertising.autoneg = autoneg;

	/* update pause mode */
	ret = disp_ops->set_port_advertising(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					  &port_advertising);
	if (ret) {
		netdev_err(netdev, "pause mode set failed %d\n", ret);
		return ret;
	}

	return 0;
}

static void nbl_get_pause_param(struct net_device *netdev, struct ethtool_pauseparam *param)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_port_state port_state = {0};
	int ret = 0;

	ret = disp_ops->get_port_state(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				       NBL_COMMON_TO_ETH_ID(serv_mgt->common), &port_state);
	if (ret) {
		netdev_err(netdev, "Get port_state failed %d\n", ret);
		return;
	}

	param->autoneg = AUTONEG_DISABLE;
	param->rx_pause = !!(port_state.active_fc & NBL_PORT_RX_PAUSE);
	param->tx_pause = !!(port_state.active_fc & NBL_PORT_TX_PAUSE);
}

static int nbl_set_fec_param(struct net_device *netdev, struct ethtool_fecparam *fec)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_serv_net_resource_mgt *net_resource_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_port_state port_state = {0};
	struct nbl_port_advertising port_advertising = {0};
	u32 fec_mode = fec->fec;
	u8 active_fec = 0;
	u8 autoneg;
	int ret = 0;

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);

	ret = disp_ops->get_port_state(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				       NBL_COMMON_TO_ETH_ID(serv_mgt->common), &port_state);
	if (ret) {
		netdev_err(netdev, "Get port_state failed %d\n", ret);
		return -EIO;
	}

	if (!port_state.module_inplace) {
		netdev_err(netdev, "Optical module is not inplace\n");
		return -EINVAL;
	}

	autoneg = (port_state.port_advertising & BIT(NBL_PORT_CAP_AUTONEG)) ?
		   AUTONEG_ENABLE : AUTONEG_DISABLE;

	if (fec_mode == ETHTOOL_FEC_OFF)
		fec_mode = ETHTOOL_FEC_NONE;

	/* check if the fec mode is supported */
	if (fec_mode == ETHTOOL_FEC_NONE) {
		active_fec = NBL_PORT_FEC_OFF;
		if (!(port_state.port_caps & BIT(NBL_PORT_CAP_FEC_NONE))) {
			netdev_err(netdev, "unsupported fec mode off\n");
			return -EOPNOTSUPP;
		}
	}
	if (fec_mode == ETHTOOL_FEC_RS) {
		active_fec = NBL_PORT_FEC_RS;
		if (!(port_state.port_caps & BIT(NBL_PORT_CAP_FEC_RS))) {
			netdev_err(netdev, "unsupported fec mode RS\n");
			return -EOPNOTSUPP;
		}
	}
	if (fec_mode == ETHTOOL_FEC_BASER) {
		active_fec = NBL_PORT_FEC_BASER;
		if (!(port_state.port_caps & BIT(NBL_PORT_CAP_FEC_BASER))) {
			netdev_err(netdev, "unsupported fec mode BaseR\n");
			return -EOPNOTSUPP;
		}
	}
	if (fec_mode == ETHTOOL_FEC_AUTO) {
		active_fec = NBL_PORT_FEC_AUTO;
		if (!autoneg) {
			netdev_err(netdev, "unsupported fec mode auto\n");
			return -EOPNOTSUPP;
		}
	}

	if (fec_mode == net_resource_mgt->configured_fec) {
		netdev_err(netdev, "fec mode is not changed\n");
		return 0;
	}

	if (fec_mode == ETHTOOL_FEC_RS) {
		if (port_state.link_speed == 10000) {
			netdev_err(netdev, "speed 10G cannot set fec RS, only can set fec baseR\n");
			return -EINVAL;
		}
	}

	net_resource_mgt->configured_fec = fec_mode;

	port_advertising.eth_id = NBL_COMMON_TO_ETH_ID(serv_mgt->common);
	port_advertising.active_fec = active_fec;
	port_advertising.autoneg = autoneg;

	/* update fec mode */
	ret = disp_ops->set_port_advertising(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					  &port_advertising);
	if (ret) {
		netdev_err(netdev, "fec mode set failed %d\n", ret);
		return ret;
	}

	return 0;
}

static int nbl_get_fec_param(struct net_device *netdev, struct ethtool_fecparam *fecparam)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_port_state port_state = {0};
	u32 fec = 0;
	u32 active_fec = 0;
	u8 autoneg = 0;
	int ret = 0;

	ret = disp_ops->get_port_state(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				       NBL_COMMON_TO_ETH_ID(serv_mgt->common), &port_state);
	if (ret) {
		netdev_err(netdev, "Get port_state failed %d\n", ret);
		return -EIO;
	}

	if (!port_state.module_inplace) {
		netdev_err(netdev, " Optical module is not inplace\n");
		return -EINVAL;
	}

	autoneg = (port_state.port_advertising & BIT(NBL_PORT_CAP_AUTONEG)) ?
		   AUTONEG_ENABLE : AUTONEG_DISABLE;

	if (port_state.active_fec == NBL_PORT_FEC_OFF)
		active_fec = ETHTOOL_FEC_OFF;
	if (port_state.active_fec ==  NBL_PORT_FEC_RS)
		active_fec = ETHTOOL_FEC_RS;
	if (port_state.active_fec ==  NBL_PORT_FEC_BASER)
		active_fec = ETHTOOL_FEC_BASER;

	if (net_resource_mgt->configured_fec)
		fec = net_resource_mgt->configured_fec;
	else
		fec = active_fec;

	fecparam->fec = fec;
	fecparam->active_fec = active_fec;

	return 0;
}

static int nbl_set_phys_id(struct net_device *netdev, enum ethtool_phys_id_state state)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;
	static u32 led_ctrl_reg;
	enum nbl_led_reg_ctrl led_ctrl_op;
	u8 eth_id;

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	eth_id = NBL_COMMON_TO_ETH_ID(serv_mgt->common);

	switch (state) {
	case ETHTOOL_ID_ACTIVE:
		led_ctrl_op = NBL_LED_REG_ACTIVE;
		break;
	case ETHTOOL_ID_ON:
		led_ctrl_op = NBL_LED_REG_ON;
		break;
	case ETHTOOL_ID_OFF:
		led_ctrl_op = NBL_LED_REG_OFF;
		break;
	case ETHTOOL_ID_INACTIVE:
		led_ctrl_op = NBL_LED_REG_INACTIVE;
		break;
	default:
		return 0;
	}
	return disp_ops->ctrl_port_led(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				       eth_id, led_ctrl_op, &led_ctrl_reg);
}

static int nbl_nway_reset(struct net_device *netdev)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_serv_net_resource_mgt *net_resource_mgt;
	struct nbl_port_state port_state = {0};
	int ret;
	u8 eth_id;

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	eth_id = NBL_COMMON_TO_ETH_ID(serv_mgt->common);
	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);

	ret = disp_ops->get_port_state(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				       NBL_COMMON_TO_ETH_ID(serv_mgt->common), &port_state);
	if (ret) {
		netdev_err(netdev, "Get port_state failed %d\n", ret);
		return -EIO;
	}

	if (!port_state.module_inplace) {
		netdev_err(netdev, "Optical module is not inplace\n");
		return -EOPNOTSUPP;
	}

	net_resource_mgt->configured_fec = 0;
	net_resource_mgt->configured_speed =
			nbl_conver_portrate_to_speed(port_state.port_max_rate);

	return disp_ops->nway_reset(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), eth_id);
}

/* NBL_SERV_ETHTOOL_OPS_TBL(ops_name, func)
 *
 * Use X Macros to reduce setup and remove codes.
 */
#define NBL_SERV_ETHTOOL_OPS_TBL								\
do {												\
	NBL_SERV_SET_ETHTOOL_OPS(get_drvinfo, nbl_get_drvinfo);					\
	NBL_SERV_SET_ETHTOOL_OPS(get_strings, nbl_get_strings);					\
	NBL_SERV_SET_ETHTOOL_OPS(get_sset_count, nbl_get_sset_count);				\
	NBL_SERV_SET_ETHTOOL_OPS(get_ethtool_stats, nbl_get_ethtool_stats);			\
	NBL_SERV_SET_ETHTOOL_OPS(get_module_eeprom, nbl_get_module_eeprom);			\
	NBL_SERV_SET_ETHTOOL_OPS(get_module_info, nbl_get_module_info);				\
	NBL_SERV_SET_ETHTOOL_OPS(get_eeprom_length, nbl_get_eeprom_length);			\
	NBL_SERV_SET_ETHTOOL_OPS(get_eeprom, nbl_get_eeprom);					\
	NBL_SERV_SET_ETHTOOL_OPS(get_channels, nbl_get_channels);				\
	NBL_SERV_SET_ETHTOOL_OPS(set_channels, nbl_set_channels);				\
	NBL_SERV_SET_ETHTOOL_OPS(get_link, nbl_get_link);					\
	NBL_SERV_SET_ETHTOOL_OPS(get_ksettings, nbl_get_ksettings);				\
	NBL_SERV_SET_ETHTOOL_OPS(set_ksettings, nbl_set_ksettings);				\
	NBL_SERV_SET_ETHTOOL_OPS(get_ringparam, nbl_get_ringparam);				\
	NBL_SERV_SET_ETHTOOL_OPS(set_ringparam, nbl_set_ringparam);				\
	NBL_SERV_SET_ETHTOOL_OPS(get_coalesce, nbl_get_coalesce);				\
	NBL_SERV_SET_ETHTOOL_OPS(set_coalesce, nbl_set_coalesce);				\
	NBL_SERV_SET_ETHTOOL_OPS(get_rxnfc, nbl_get_rxnfc);					\
	NBL_SERV_SET_ETHTOOL_OPS(get_rxfh_indir_size, nbl_get_rxfh_indir_size);			\
	NBL_SERV_SET_ETHTOOL_OPS(get_rxfh_key_size, nbl_get_rxfh_key_size);			\
	NBL_SERV_SET_ETHTOOL_OPS(get_rxfh, nbl_get_rxfh);					\
	NBL_SERV_SET_ETHTOOL_OPS(get_msglevel, nbl_get_msglevel);				\
	NBL_SERV_SET_ETHTOOL_OPS(set_msglevel, nbl_set_msglevel);				\
	NBL_SERV_SET_ETHTOOL_OPS(get_regs_len, nbl_get_regs_len);				\
	NBL_SERV_SET_ETHTOOL_OPS(get_ethtool_dump_regs, nbl_get_ethtool_dump_regs);		\
	NBL_SERV_SET_ETHTOOL_OPS(get_per_queue_coalesce, nbl_get_per_queue_coalesce);		\
	NBL_SERV_SET_ETHTOOL_OPS(set_per_queue_coalesce, nbl_set_per_queue_coalesce);		\
	NBL_SERV_SET_ETHTOOL_OPS(self_test, nbl_self_test);					\
	NBL_SERV_SET_ETHTOOL_OPS(get_priv_flags, nbl_get_priv_flags);				\
	NBL_SERV_SET_ETHTOOL_OPS(set_priv_flags, nbl_set_priv_flags);				\
	NBL_SERV_SET_ETHTOOL_OPS(set_pause_param, nbl_set_pause_param);				\
	NBL_SERV_SET_ETHTOOL_OPS(get_pause_param, nbl_get_pause_param);				\
	NBL_SERV_SET_ETHTOOL_OPS(set_fec_param, nbl_set_fec_param);				\
	NBL_SERV_SET_ETHTOOL_OPS(get_fec_param, nbl_get_fec_param);				\
	NBL_SERV_SET_ETHTOOL_OPS(get_ts_info, ethtool_op_get_ts_info);				\
	NBL_SERV_SET_ETHTOOL_OPS(set_phys_id, nbl_set_phys_id);					\
	NBL_SERV_SET_ETHTOOL_OPS(nway_reset, nbl_nway_reset);					\
} while (0)

void nbl_serv_setup_ethtool_ops(struct nbl_service_ops *serv_ops)
{
#define NBL_SERV_SET_ETHTOOL_OPS(name, func) do {serv_ops->NBL_NAME(name) = func; ; } while (0)
	NBL_SERV_ETHTOOL_OPS_TBL;
#undef  NBL_SERV_SET_ETHTOOL_OPS
}
