// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_ethtool.h"

#define DIAG_BLK_SZ(data_size) (sizeof(struct nbl_diag_blk) + (data_size))
#define DIAG_GET_NEXT_BLK(dump_hdr)			\
	({ typeof(dump_hdr) _dump_hdr = (dump_hdr);	\
	(struct nbl_diag_blk *)(_dump_hdr->dump + _dump_hdr->total_length); })

#define NBL_DIAG_DUMP_VERSION		1
#define NBL_DIAG_FLAG_PERFORMANCE	BIT(0)

#define NBL_DRV_VER_SZ			64
#define NBL_DEV_NAME_SZ			64

enum nbl_diag_type {
	NBL_DIAG_DRV_VERSION = 0,
	NBL_DIAG_DEVICE_NAME,
	NBL_DIAG_PERFORMANCE,
};

struct nbl_diag_blk {
	u32 type;
	u32 length;
	char data[];
} __packed;

struct nbl_diag_dump {
	u32 version;
	u32 flag;
	u32 num_blocks;
	u32 total_length;
	char dump[];
} __packed;

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

#define NBL_LEONIS_LANE_NUM		(4)

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
	NBL_NETDEV_STAT("rx_length_errors", rx_length_errors, rx_length_errors),
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
	NBL_STAT("tso_inner_packets", tso_inner_packets, tso_inner_packets),
	NBL_STAT("tso_inner_bytes", tso_inner_bytes, tso_inner_bytes),
	NBL_STAT("tx_csum_packets", tx_csum_packets, tx_csum_packets),
	NBL_STAT("tx_csum_inner_packets", tx_csum_inner_packets, tx_csum_inner_packets),
	NBL_STAT("rx_csum_packets", rx_csum_packets, rx_csum_packets),
	NBL_STAT("rx_csum_inner_packets", rx_csum_inner_packets, rx_csum_inner_packets),
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
	NBL_STAT("xdp_tx_packets", xdp_tx_packets, xdp_tx_packets),
	NBL_STAT("xdp_redirect_packets", xdp_redirect_packets, xdp_redirect_packets),
	NBL_STAT("xdp_drop_packets", xdp_drop_packets, xdp_drop_packets),
#if IS_ENABLED(CONFIG_TLS_DEVICE)
	NBL_STAT("tls_encrypted_packets", tls_encrypted_packets, tls_encrypted_packets),
	NBL_STAT("tls_encrypted_bytes", tls_encrypted_bytes, tls_encrypted_bytes),
	NBL_STAT("tls_ooo_packets", tls_ooo_packets, tls_ooo_packets),
	NBL_STAT("tls_decrypted_packets", tls_decrypted_packets, tls_decrypted_packets),
	NBL_STAT("tls_resync_req_num", tls_resync_req_num, tls_resync_req_num),
#endif

	NBL_STAT("tx_added_vlan_packets", tx_added_vlan_packets, tx_added_vlan_packets),
	NBL_STAT("rx_removed_vlan_packets", rx_removed_vlan_packets, rx_removed_vlan_packets),
	NBL_STAT("rx_rss_hash_packets", rx_rss_hash_packets, rx_rss_hash_packets),
	NBL_STAT("rx_oversize_pkts_sw_drop", rx_oversize_pkts_sw_drop, rx_oversize_pkts_sw_drop),
	NBL_STAT("total_fake_packets", total_fake_packets, total_fake_packets),
};

#define NBL_GLOBAL_STATS_LEN ARRAY_SIZE(nbl_gstrings_stats)

struct nbl_priv_flags_info {
	u8 supported_by_capability;
	u8 supported_modify;
	enum nbl_fix_cap_type capability_type;
	char flag_name[ETH_GSTRING_LEN];
	int (*post_func)(struct net_device *netdev, bool flag);
};

static int nbl_set_priv_flag_tx_port_fc_segregate_post(struct net_device *netdev, bool flag)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_event_param event_data;

	event_data.subevent = NBL_SUBEVENT_BOND_SHAPING;
	event_data.bond_shaping_dis = flag;
	nbl_event_notify(NBL_EVENT_RDMA_BOND_UPDATE, &event_data,
			 NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));

	return 0;
}

static int nbl_set_vlan_filtering_disable_post(struct net_device *netdev, bool flag)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->cfg_vlan_filtering(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), !flag);

	return 0;
}

static int nbl_set_priv_flag_reset_post(struct net_device *netdev, bool flag)
{
	int was_running;
	int ret;

	was_running = netif_running(netdev);
	if (!was_running)
		return 0;

	ret = nbl_serv_netdev_stop(netdev);
	if (ret) {
		netdev_info(netdev, "Failed to down netdev for set interleave seg disable.\n");
		return ret;
	}

	ret = nbl_serv_netdev_open(netdev);
	if (ret) {
		netdev_info(netdev, "Failed to open netdev for set interleave seg disable.\n");
		return ret;
	}

	return 0;
}

static int nbl_set_priv_flag_rx_csum_drop_post(struct net_device *netdev, bool flag)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->set_rx_csum_drop(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), flag);

	return 0;
}

static int nbl_set_priv_flag_xdp_enhance_post(struct net_device *netdev, bool flag)
{
	int was_running;
	int ret;
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	/* xdp headrom use 192B when xdp enhance to support one page rcv two pkts for mtu 1500 */
	disp_ops->set_xdp_enhance(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), flag);

	was_running = netif_running(netdev);
	if (!was_running)
		return 0;

	ret = nbl_serv_netdev_stop(netdev);
	if (ret) {
		netdev_info(netdev, "Failed to down netdev for set xdp enhance.\n");
		return ret;
	}

	ret = nbl_serv_netdev_open(netdev);
	if (ret) {
		netdev_info(netdev, "Failed to open netdev for set xdp enhance.\n");
		return ret;
	}

	return 0;
}

static const struct nbl_priv_flags_info nbl_gstrings_priv_flags[NBL_ADAPTER_FLAGS_MAX] = {
	{1, 0, NBL_P4_CAP,				"P4-default", NULL},
	{1, 1, NBL_LINK_DOWN_ON_CLOSE,			"link-down-on-close", NULL},
	{1, 1, NBL_ETH_SUPPORT_NRZ_RS_FEC_544,		"nrz-rs-fec-544", NULL},
	{1, 1, NBL_HIGH_THROUGHPUT_CAP,			"high-throughput", NULL},
	{1, 1, NBL_INTERLEAVE_SEG_DISABLE,		"interleave-seg-disable",
					nbl_set_priv_flag_reset_post},
	{1, 1, NBL_TX_FC_SEGREGATGE_ENABLE,		"tx-fc-segregate-enable",
					nbl_set_priv_flag_tx_port_fc_segregate_post},
	{1, 1, NBL_RX_CSUM_ERR_DROP_CAP,		"rx-csum-err-drop",
					nbl_set_priv_flag_rx_csum_drop_post},
	{1, 1, NBL_XDP_ENHANCE,				"xdp-enhance",
					nbl_set_priv_flag_xdp_enhance_post},
	{1, 1, NBL_RXQ_LARGE_BUF,			"rxq-large-buf",
					nbl_set_priv_flag_reset_post},
	{1, 1, NBL_VLAN_FILTERING_DISABLE_CAP,		"vlan-filtering-disable",
					nbl_set_vlan_filtering_disable_post},
};

#define NBL_PRIV_FLAG_ARRAY_SIZE	ARRAY_SIZE(nbl_gstrings_priv_flags)

static void nbl_get_drvinfo(struct net_device *netdev, struct ethtool_drvinfo *drvinfo)
{
	struct nbl_adapter *adapter;
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_netdev_priv *priv;
	struct nbl_driver_info driver_info;
	struct nbl_common_info *common;

	memset(&driver_info, 0, sizeof(driver_info));

	priv = netdev_priv(netdev);
	adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	common = NBL_SERV_MGT_TO_COMMON(serv_mgt);

	strscpy(drvinfo->version, NBL_DRIVER_VERSION, sizeof(drvinfo->version));
	strscpy(drvinfo->fw_version, common->firmware_version, sizeof(drvinfo->fw_version));
	if (!priv->rep) {
		strscpy(drvinfo->driver, NBL_DRIVER_NAME, sizeof(drvinfo->driver));
		strscpy(drvinfo->bus_info, pci_name(adapter->pdev), sizeof(drvinfo->bus_info));
	} else {
		strscpy(drvinfo->driver, NBL_REP_DRIVER_NAME, sizeof(drvinfo->driver));
	}

	drvinfo->regdump_len = 0;
}

static void nbl_stats_fill_strings(struct net_device *netdev, u8 *data)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info, *xdp_vsi_info;
	char *p = (char *)data;
	unsigned int i;
	u32 xdp_ring_num = 0;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];
	xdp_vsi_info = &ring_mgt->vsi_info[NBL_VSI_XDP];

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
	}

	if (xdp_vsi_info)
		xdp_ring_num = xdp_vsi_info->ring_num < num_online_cpus() ?
				xdp_vsi_info->ring_num : num_online_cpus();

	for (i = 0; i < xdp_ring_num; i++) {
		snprintf(p, ETH_GSTRING_LEN, "tx_queue_%u_xdp_packets", i);
		p += ETH_GSTRING_LEN;
		snprintf(p, ETH_GSTRING_LEN, "tx_queue_%u_xdp_bytes", i);
		p += ETH_GSTRING_LEN;
		snprintf(p, ETH_GSTRING_LEN, "tx_queue_%u_xdp_descs", i);
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
							   &capability_type))
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
	struct nbl_serv_ring_vsi_info *vsi_info, *xdp_vsi_info;
	u32 total_queues = 0, private_len = 0, extra_per_queue_entry = 0;
	u32 xdp_queue_num = 0;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];
	xdp_vsi_info = &ring_mgt->vsi_info[NBL_VSI_XDP];

	total_queues = vsi_info->active_ring_num * 2;
	if (!common->is_vf)
		disp_ops->get_private_stat_len(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &private_len);

	/* For tx_timeout */
	extra_per_queue_entry = vsi_info->active_ring_num;

	/* xdp queue stat */
	if (xdp_vsi_info)
		xdp_queue_num = xdp_vsi_info->ring_num < num_online_cpus() ?
				xdp_vsi_info->ring_num : num_online_cpus();
	total_queues += xdp_queue_num;

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
							   &capability_type))
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
		return nbl_sset_fill_priv_flags_count(netdev);
	default:
		return -EOPNOTSUPP;
	}
}

static void nbl_intr_set_suppress_level(struct nbl_service_mgt *serv_mgt,
					struct nbl_serv_ring_vsi_info *vsi_info,
					u16 intr_suppress_level)
{
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_set_intr_suppress_level_fast_param prm = {0};
	u16 qnum;
	u16 global_vector_id;

	prm.level = intr_suppress_level;
	for (qnum = 0; qnum < vsi_info->ring_num; qnum++) {
		global_vector_id = ring_mgt->vectors[vsi_info->ring_offset + qnum].global_vector_id;

		prm.global_vector_id = global_vector_id;
		disp_ops->set_intr_suppress_level_fast(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &prm);
	}
}

static void nbl_serv_adjust_interrpt_param(struct nbl_service_mgt *serv_mgt, bool ethtool)
{
	enum nbl_fix_cap_type cap_type = NBL_MSIX_FAST_RESTRAIN_CAP;
	struct nbl_serv_net_resource_mgt *net_resource_mgt;
	struct nbl_serv_ring_mgt *ring_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct net_device *netdev;
	struct nbl_netdev_priv *net_priv;
	struct nbl_serv_ring_vsi_info *vsi_info;
	struct nbl_common_info *common;
	u64 last_tx_packets;
	u64 last_rx_packets;
	u64 last_get_stats_jiffies, time_diff;
	u64 tx_packets, rx_packets;
	u64 tx_rates, rx_rates, pkt_rates, normalized_pkt_rates;
	u16 local_vector_id, vector_num;
	u16 intr_suppress_level;
	bool support_msix_fast_restrain;
	struct nbl_get_intr_suppress_level_param suppress_prm = {0};

	net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	netdev = net_resource_mgt->netdev;
	net_priv = netdev_priv(netdev);
	ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];

	last_tx_packets = net_resource_mgt->stats.tx_packets;
	last_rx_packets = net_resource_mgt->stats.rx_packets;
	last_get_stats_jiffies = net_resource_mgt->get_stats_jiffies;
	time_diff = jiffies - last_get_stats_jiffies;
	disp_ops->get_net_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &net_resource_mgt->stats);
	/* ethtool -S don't adaptive interrupt suppression param */
	if (!vsi_info->itr_dynamic || ethtool || !time_diff)
		return;

	tx_packets = net_resource_mgt->stats.tx_packets;
	rx_packets = net_resource_mgt->stats.rx_packets;

	net_resource_mgt->get_stats_jiffies = jiffies;
	tx_rates = div64_u64(tx_packets - last_tx_packets, time_diff) * HZ;
	rx_rates = div64_u64(rx_packets - last_rx_packets, time_diff) * HZ;
	pkt_rates = max_t(u64, tx_rates, rx_rates);
	if (netdev->mtu <= ETH_DATA_LEN || !ring_mgt->vectors->intr_suppress_level)
		normalized_pkt_rates = pkt_rates;
	else
		normalized_pkt_rates = (netdev->mtu / ETH_DATA_LEN) * pkt_rates;

	suppress_prm.rate = normalized_pkt_rates;
	suppress_prm.last_level = ring_mgt->vectors->intr_suppress_level;
	intr_suppress_level =
		disp_ops->get_intr_suppress_level(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						  &suppress_prm);
	support_msix_fast_restrain =
				disp_ops->get_product_fix_cap(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
							      &cap_type);
	if (intr_suppress_level != ring_mgt->vectors->intr_suppress_level) {
		local_vector_id = ring_mgt->vectors[vsi_info->ring_offset].local_vector_id;
		vector_num = vsi_info->ring_num;
		if (!support_msix_fast_restrain) {
			struct nbl_ch_prm_set_intr_suppress_level suppress_prm = {0};

			suppress_prm.sfid = NBL_COMMON_TO_MGT_PF(common);
			suppress_prm.local_vector_id = local_vector_id;
			suppress_prm.vector_num = vector_num;
			suppress_prm.level = intr_suppress_level;
			disp_ops->set_intr_suppress_level(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						  &suppress_prm);
		} else {
			nbl_intr_set_suppress_level(serv_mgt, vsi_info, intr_suppress_level);
		}
		ring_mgt->vectors->intr_suppress_level = intr_suppress_level;
	}
}

static int nbl_serv_update_uvn_stats(struct nbl_service_mgt *serv_mgt,
				     u64 last_rx_packets, u64 rx_packets)
{
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct device *dev = NBL_SERV_MGT_TO_DEV(serv_mgt);
	u16 vsi_id = NBL_COMMON_TO_VSI_ID(common);
	struct nbl_serv_ring_vsi_info *vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];
	u32 *uvn_stat_pkt_drop = NULL;
	u64 rx_rates;
	u64 time_diff;
	int i = 0;
	int ret = 0;

	if (time_after(jiffies,
		       net_resource_mgt->hw_stats_jiffies + net_resource_mgt->hw_stats_period)) {
		time_diff = jiffies - net_resource_mgt->hw_stats_jiffies;
		rx_rates = div64_u64(rx_packets - last_rx_packets, time_diff) * HZ;
		net_resource_mgt->hw_stats_jiffies = jiffies;
		if (!common->is_vf || rx_rates > NBL_HW_STATS_RX_RATE_THRESHOLD) {
			uvn_stat_pkt_drop = devm_kcalloc(dev, vsi_info->ring_num,
							 sizeof(*uvn_stat_pkt_drop), GFP_KERNEL);
			if (!uvn_stat_pkt_drop) {
				ret = -ENOMEM;
				goto alloc_uvn_stat_pkt_drop_fail;
			}
			ret = disp_ops->get_uvn_pkt_drop_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
							       vsi_id, vsi_info->ring_num,
							       uvn_stat_pkt_drop);
			if (ret)
				goto get_uvn_pkt_drop_stats_fail;
			for (i = 0; i < vsi_info->ring_num; i++)
				net_resource_mgt->hw_stats.total_uvn_stat_pkt_drop[i] +=
									uvn_stat_pkt_drop[i];
		}
	}

	if (uvn_stat_pkt_drop) {
		devm_kfree(dev, uvn_stat_pkt_drop);
		uvn_stat_pkt_drop = NULL;
	}
	return 0;

get_uvn_pkt_drop_stats_fail:
	if (uvn_stat_pkt_drop) {
		devm_kfree(dev, uvn_stat_pkt_drop);
		uvn_stat_pkt_drop = NULL;
	}
alloc_uvn_stat_pkt_drop_fail:
	return ret;
}

void nbl_serv_update_stats(struct nbl_service_mgt *serv_mgt, bool ethtool)
{
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_eth_abnormal_stats eth_abnormal_stats = { 0 };
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct net_device *netdev = net_resource_mgt->netdev;
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	u64 last_rx_packets = 0;
	u8 eth_id = NBL_COMMON_TO_ETH_ID(common);

	if (!test_bit(NBL_RUNNING, adapter->state) ||
	    test_bit(NBL_RESETTING, adapter->state))
		return;

	last_rx_packets = net_resource_mgt->stats.rx_packets;
	nbl_serv_adjust_interrpt_param(serv_mgt, ethtool);
	netdev->stats.tx_packets = net_resource_mgt->stats.tx_packets;
	netdev->stats.tx_bytes = net_resource_mgt->stats.tx_bytes;
	netdev->stats.rx_packets = net_resource_mgt->stats.rx_packets;
	netdev->stats.rx_bytes = net_resource_mgt->stats.rx_bytes;

	if (!common->is_vf)
		disp_ops->get_eth_abnormal_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						 &eth_id, &eth_abnormal_stats);

	nbl_serv_update_uvn_stats(serv_mgt, last_rx_packets,
				  net_resource_mgt->stats.rx_packets);
	/* net_device_stats */
	netdev->stats.multicast = 0;
	netdev->stats.rx_errors = 0;
	netdev->stats.tx_errors = 0;
	netdev->stats.rx_length_errors = eth_abnormal_stats.rx_length_errors;
	netdev->stats.rx_crc_errors = eth_abnormal_stats.rx_crc_errors;
	netdev->stats.rx_frame_errors = eth_abnormal_stats.rx_frame_errors;
	netdev->stats.rx_dropped = 0;
	netdev->stats.tx_dropped = 0;
}

static void
nbl_get_ethtool_stats(struct net_device *netdev, struct ethtool_stats *stats, u64 *data)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	void *priv = NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt);
	struct rtnl_link_stats64 temp_stats;
	struct rtnl_link_stats64 *net_stats;
	struct nbl_stats *nbl_stats;
	struct nbl_queue_stats queue_stats = { 0 };
	struct nbl_queue_err_stats queue_err_stats = { 0 };
	struct nbl_get_queue_stats_param q_stats_prm = {0};
	struct nbl_ch_prm_get_queue_err_stats q_err_prm = {0};
	struct nbl_serv_ring_vsi_info *vsi_info, *xdp_vsi_info;
	u32 private_len = 0;
	u32 xdp_ring_num = 0;
	char *p = NULL;
	int i, j, k;
	struct nbl_chan_param_drop_stats_resp drop_stats = {0};

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];
	xdp_vsi_info = &ring_mgt->vsi_info[NBL_VSI_XDP];

	nbl_serv_update_stats(serv_mgt, true);
	net_stats = dev_get_stats(netdev, &temp_stats);
	nbl_stats = (struct nbl_stats *)((char *)net_resource_mgt +
				offsetof(struct nbl_serv_net_resource_mgt, stats));
	i = NBL_GLOBAL_STATS_LEN;

	if (!common->is_vf) {
		disp_ops->get_total_pkt_drop_stats(priv, 0, STAT_TYPE_FAKE, &drop_stats);
		nbl_stats->total_fake_packets =
			drop_stats.rx_drop_packets - net_resource_mgt->hw_stats.start_fake_drop;
	}

	q_stats_prm.is_tx = true;
	q_err_prm.is_tx = true;
	q_err_prm.sfid = NBL_COMMON_TO_MGT_PF(common);
	for (j = 0; j < vsi_info->active_ring_num; j++) {
		q_stats_prm.queue_id = j;
		q_err_prm.queue_id = j;
		disp_ops->get_queue_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					  &q_stats_prm, &queue_stats);
		disp_ops->get_queue_err_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					      &q_err_prm, &queue_err_stats);
		data[i] = queue_stats.packets;
		data[i + 1] = queue_stats.bytes;
		data[i + 2] = queue_stats.descs;
		data[i + 3] = ring_mgt->tx_rings[vsi_info->ring_offset + j].tx_timeout_count;
		i += 4;
	}

	q_stats_prm.is_tx = false;
	q_err_prm.is_tx = false;
	for (j = 0; j < vsi_info->active_ring_num; j++) {
		q_stats_prm.queue_id = j;
		q_err_prm.queue_id = j;
		disp_ops->get_queue_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					  &q_stats_prm, &queue_stats);
		disp_ops->get_queue_err_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					      &q_err_prm, &queue_err_stats);
		data[i] = queue_stats.packets;
		data[i + 1] = queue_stats.bytes;
		data[i + 2] = queue_stats.descs;
		i += 3;
	}

	if (xdp_vsi_info)
		xdp_ring_num = xdp_vsi_info->ring_num < num_online_cpus() ?
				xdp_vsi_info->ring_num : num_online_cpus();

	q_stats_prm.is_tx = true;
	for (j = 0; j < xdp_ring_num; j++) {
		q_stats_prm.queue_id = ring_mgt->xdp_ring_offset + j;
		disp_ops->get_queue_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					  &q_stats_prm, &queue_stats);
		data[i] = queue_stats.packets;
		data[i + 1] = queue_stats.bytes;
		data[i + 2] = queue_stats.descs;
		i += 3;
	}

	for (k = 0; k < NBL_GLOBAL_STATS_LEN; k++) {
		switch (nbl_gstrings_stats[k].type) {
		case NBL_NETDEV_STATS:
			p = (char *)net_stats + nbl_gstrings_stats[k].stat_offset;
			break;
		case NBL_STATS:
			p = (char *)nbl_stats + nbl_gstrings_stats[k].stat_offset;
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

static int nbl_get_module_eeprom_by_page(struct net_device *netdev,
					 const struct ethtool_module_eeprom *page_data,
					 struct netlink_ext_ack *extack)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_ethtool_module_eeprom eeprom = {0};
	u8 *data = page_data->data;
	int ret;

	if (!page_data->length)
		return -EINVAL;

	eeprom.offset = page_data->offset;
	eeprom.length = page_data->length;
	eeprom.i2c_address = page_data->i2c_address;
	eeprom.bank = page_data->bank;
	eeprom.page = page_data->page;
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	ret = disp_ops->get_module_eeprom_by_page(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					  NBL_COMMON_TO_ETH_ID(serv_mgt->common), &eeprom, data);

	return ret;
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

static int nbl_get_eeprom_length(struct net_device *netdev)
{
	return NBL_EEPROM_LENGTH;
}

static int nbl_get_eeprom(struct net_device *netdev, struct ethtool_eeprom *eeprom, u8 *bytes)
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
	struct nbl_serv_tc_mgt *tc_mgt = NBL_SERV_MGT_TO_TC_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_NETDEV_TO_COMMON(netdev);
	struct nbl_serv_ring_vsi_info *vsi_info;
	u16 queue_pairs = channels->combined_count;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];

	if (tc_mgt->num_tc) {
		netdev_info(netdev, "Cannot set channels since mqprio is enabled.\n");
		return -EINVAL;
	}

	/* We don't support separate rx/tx channels.
	 * We don't allow setting 'other' channels.
	 */
	if (channels->rx_count || channels->tx_count || channels->other_count)
		return -EINVAL;

	if (queue_pairs > vsi_info->ring_num || queue_pairs == 0)
		return -EINVAL;

	vsi_info->active_ring_num = queue_pairs;

	nbl_serv_cpu_affinity_init(serv_mgt, queue_pairs);
	netif_set_real_num_tx_queues(netdev, queue_pairs);
	netif_set_real_num_rx_queues(netdev, queue_pairs);

	disp_ops->setup_cqs(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
			    NBL_COMMON_TO_VSI_ID(common), queue_pairs, true);

	return 0;
}

static u32 nbl_get_link(struct net_device *netdev)
{
	return netif_carrier_ok(netdev) ? 1 : 0;
}

struct nbl_ethtool_link_ext_state_opcode_mapping {
	u32 status_opcode;
	enum ethtool_link_ext_state link_ext_state;
	u8 link_ext_substate;
};

static const struct nbl_ethtool_link_ext_state_opcode_mapping nbl_link_ext_state_opcode_map[] = {
	/* States relating to the autonegotiation or issues therein */
	{10, ETHTOOL_LINK_EXT_STATE_AUTONEG, 0},
	{11, ETHTOOL_LINK_EXT_STATE_AUTONEG,
		ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED},
	{12, ETHTOOL_LINK_EXT_STATE_AUTONEG,
		ETHTOOL_LINK_EXT_SUBSTATE_AN_ACK_NOT_RECEIVED},
	{13, ETHTOOL_LINK_EXT_STATE_AUTONEG,
		ETHTOOL_LINK_EXT_SUBSTATE_AN_NEXT_PAGE_EXCHANGE_FAILED},
	{14, ETHTOOL_LINK_EXT_STATE_AUTONEG,
		ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED_FORCE_MODE},
	{15, ETHTOOL_LINK_EXT_STATE_AUTONEG,
		ETHTOOL_LINK_EXT_SUBSTATE_AN_FEC_MISMATCH_DURING_OVERRIDE},
	{16, ETHTOOL_LINK_EXT_STATE_AUTONEG,
		ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_HCD},

	/* Failure during link training */
	{20, ETHTOOL_LINK_EXT_STATE_LINK_TRAINING_FAILURE, 0},
	{21, ETHTOOL_LINK_EXT_STATE_LINK_TRAINING_FAILURE,
		ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_FRAME_LOCK_NOT_ACQUIRED},
	{22, ETHTOOL_LINK_EXT_STATE_LINK_TRAINING_FAILURE,
		ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_LINK_INHIBIT_TIMEOUT},
	{23, ETHTOOL_LINK_EXT_STATE_LINK_TRAINING_FAILURE,
		ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_LINK_PARTNER_DID_NOT_SET_RECEIVER_READY},
	{24, ETHTOOL_LINK_EXT_STATE_LINK_TRAINING_FAILURE,
		ETHTOOL_LINK_EXT_SUBSTATE_LT_REMOTE_FAULT},

	/* Logical mismatch in physical coding sublayer or forward error correction sublayer */
	{30, ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH, 0},
	{31, ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH,
		ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_BLOCK_LOCK},
	{32, ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH,
		ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_AM_LOCK},
	{33, ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH,
		ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_GET_ALIGN_STATUS},
	{34, ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH,
		ETHTOOL_LINK_EXT_SUBSTATE_LLM_FC_FEC_IS_NOT_LOCKED},
	{35, ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH,
		ETHTOOL_LINK_EXT_SUBSTATE_LLM_RS_FEC_IS_NOT_LOCKED},

	/* Signal integrity issues */
	{40, ETHTOOL_LINK_EXT_STATE_BAD_SIGNAL_INTEGRITY, 0},
	{41, ETHTOOL_LINK_EXT_STATE_BAD_SIGNAL_INTEGRITY,
		ETHTOOL_LINK_EXT_SUBSTATE_BSI_LARGE_NUMBER_OF_PHYSICAL_ERRORS},
	{42, ETHTOOL_LINK_EXT_STATE_BAD_SIGNAL_INTEGRITY,
		ETHTOOL_LINK_EXT_SUBSTATE_BSI_UNSUPPORTED_RATE},
	{43, ETHTOOL_LINK_EXT_STATE_BAD_SIGNAL_INTEGRITY,
		ETHTOOL_LINK_EXT_SUBSTATE_BSI_SERDES_REFERENCE_CLOCK_LOST},
	{44, ETHTOOL_LINK_EXT_STATE_BAD_SIGNAL_INTEGRITY,
		ETHTOOL_LINK_EXT_SUBSTATE_BSI_SERDES_ALOS},

	/* No cable connected */
	{50, ETHTOOL_LINK_EXT_STATE_NO_CABLE, 0},

	/* Failure is related to cable, e.g., unsupported cable */
	{60, ETHTOOL_LINK_EXT_STATE_CABLE_ISSUE, 0},
	{61, ETHTOOL_LINK_EXT_STATE_CABLE_ISSUE,
		ETHTOOL_LINK_EXT_SUBSTATE_CI_UNSUPPORTED_CABLE},
	{62, ETHTOOL_LINK_EXT_STATE_CABLE_ISSUE,
		ETHTOOL_LINK_EXT_SUBSTATE_CI_CABLE_TEST_FAILURE},

	/* Failure is related to EEPROM, e.g., failure during reading or parsing the data */
	{70, ETHTOOL_LINK_EXT_STATE_EEPROM_ISSUE, 0},

	/* Failure during calibration algorithm */
	{80, ETHTOOL_LINK_EXT_STATE_CALIBRATION_FAILURE, 0},

	/* The hardware is not able to provide the power required from cable or module */
	{90, ETHTOOL_LINK_EXT_STATE_POWER_BUDGET_EXCEEDED, 0},

	/* The module is overheated */
	{100, ETHTOOL_LINK_EXT_STATE_OVERHEAT, 0},

	/* module */
	{110, ETHTOOL_LINK_EXT_STATE_MODULE, 0},
	{111, ETHTOOL_LINK_EXT_STATE_MODULE, ETHTOOL_LINK_EXT_SUBSTATE_MODULE_CMIS_NOT_READY},
};

static void nbl_set_link_ext_state(struct nbl_ethtool_link_ext_state_opcode_mapping
				   link_ext_state_mapping,
				   struct ethtool_link_ext_state_info *link_ext_state_info)
{
	switch (link_ext_state_mapping.link_ext_state) {
	case ETHTOOL_LINK_EXT_STATE_AUTONEG:
		link_ext_state_info->autoneg = link_ext_state_mapping.link_ext_substate;
		break;
	case ETHTOOL_LINK_EXT_STATE_LINK_TRAINING_FAILURE:
		link_ext_state_info->link_training = link_ext_state_mapping.link_ext_substate;
		break;
	case ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH:
		link_ext_state_info->link_logical_mismatch =
			link_ext_state_mapping.link_ext_substate;
		break;
	case ETHTOOL_LINK_EXT_STATE_BAD_SIGNAL_INTEGRITY:
		link_ext_state_info->bad_signal_integrity =
			link_ext_state_mapping.link_ext_substate;
		break;
	case ETHTOOL_LINK_EXT_STATE_CABLE_ISSUE:
		link_ext_state_info->cable_issue = link_ext_state_mapping.link_ext_substate;
		break;
	default:
		break;
	}

	link_ext_state_info->link_ext_state = link_ext_state_mapping.link_ext_state;
}

static int nbl_get_link_ext_state(struct net_device *netdev,
				  struct ethtool_link_ext_state_info *link_ext_state_info)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_NETDEV_TO_COMMON(netdev);
	struct nbl_ethtool_link_ext_state_opcode_mapping link_ext_state_mapping;
	u32 status_opcode = 0;
	int i = 0;
	int ret = 0;

	if (netif_carrier_ok(netdev))
		return -ENODATA;

	ret = disp_ops->get_link_status_opcode(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					       NBL_COMMON_TO_ETH_ID(common), &status_opcode);
	if (ret) {
		netdev_err(netdev, "Get link stats opcode failed %d\n", ret);
		return ret;
	}

	for (i = 0; i < ARRAY_SIZE(nbl_link_ext_state_opcode_map); i++) {
		link_ext_state_mapping = nbl_link_ext_state_opcode_map[i];
		if (link_ext_state_mapping.status_opcode == status_opcode) {
			nbl_set_link_ext_state(link_ext_state_mapping, link_ext_state_info);
			return 0;
		}
	}

	return -ENODATA;
}

static void nbl_get_link_ext_stats(struct net_device *netdev, struct ethtool_link_ext_stats *stats)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	u8 eth_id = NBL_COMMON_TO_ETH_ID(serv_mgt->common);
	u64 link_down_count = 0;
	int ret = 0;

	ret = disp_ops->get_link_down_count(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					    eth_id, &link_down_count);
	if (ret)
		netdev_err(netdev, "Get link down count failed %d\n", ret);
	else
		stats->link_down_events = link_down_count;
}

static void nbl_link_modes_to_ethtool(u64 modes, unsigned long *ethtool_modes_map)
{
#define ADD_LINK_MODE(bit) \
	__set_bit(bit, ethtool_modes_map)

	if (modes & BIT(NBL_PORT_CAP_AUTONEG))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_Autoneg_BIT);

	if (modes & BIT(NBL_PORT_CAP_FEC_NONE))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_FEC_NONE_BIT);
	if (modes & BIT(NBL_PORT_CAP_FEC_RS))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_FEC_RS_BIT);
	if (modes & BIT(NBL_PORT_CAP_FEC_BASER))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_FEC_BASER_BIT);

	if ((modes & BIT(NBL_PORT_CAP_RX_PAUSE)) && (modes & BIT(NBL_PORT_CAP_TX_PAUSE))) {
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_Pause_BIT);
	} else if ((modes & BIT(NBL_PORT_CAP_RX_PAUSE)) && !(modes & BIT(NBL_PORT_CAP_TX_PAUSE))) {
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_Pause_BIT);
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_Asym_Pause_BIT);
	} else if (!(modes & BIT(NBL_PORT_CAP_RX_PAUSE)) && (modes & BIT(NBL_PORT_CAP_TX_PAUSE))) {
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_Asym_Pause_BIT);
	}

	if (modes & BIT(NBL_PORT_CAP_1000BASE_T)) {
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_1000baseT_Full_BIT);
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_1000baseT_Half_BIT);
	}
	if (modes & BIT(NBL_PORT_CAP_1000BASE_X))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_1000baseX_Full_BIT);
	if (modes & BIT_ULL(NBL_PORT_CAP_2500BASE_T))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_2500baseT_Full_BIT);
	if (modes & BIT_ULL(NBL_PORT_CAP_5GBASE_T))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_5000baseT_Full_BIT);
	if (modes & BIT(NBL_PORT_CAP_10GBASE_T))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_10000baseT_Full_BIT);
	if (modes & BIT(NBL_PORT_CAP_10GBASE_KR))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_10000baseKR_Full_BIT);
	if (modes & BIT(NBL_PORT_CAP_10GBASE_SR))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_10000baseSR_Full_BIT);
	if (modes & BIT(NBL_PORT_CAP_25GBASE_KR))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_25000baseKR_Full_BIT);
	if (modes & BIT(NBL_PORT_CAP_25GBASE_SR))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_25000baseSR_Full_BIT);
	if (modes & BIT(NBL_PORT_CAP_25GBASE_CR))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_25000baseCR_Full_BIT);
	if (modes & BIT(NBL_PORT_CAP_50GBASE_KR2))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT);
	if (modes & BIT(NBL_PORT_CAP_50GBASE_SR2))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT);
	if (modes & BIT(NBL_PORT_CAP_50GBASE_CR2))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT);
	if (modes & BIT(NBL_PORT_CAP_50G_AUI2))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_50000baseLR_ER_FR_Full_BIT);
	if (modes & BIT(NBL_PORT_CAP_50GBASE_KR_PAM4))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_50000baseKR_Full_BIT);
	if (modes & BIT(NBL_PORT_CAP_50GBASE_SR_PAM4))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_50000baseSR_Full_BIT);
	if (modes & BIT(NBL_PORT_CAP_50G_AUI_PAM4))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_50000baseDR_Full_BIT);
	if (modes & BIT(NBL_PORT_CAP_50GBASE_CR_PAM4))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_50000baseCR_Full_BIT);
	if (modes & BIT(NBL_PORT_CAP_100GBASE_KR4))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT);
	if (modes & BIT(NBL_PORT_CAP_100GBASE_SR4))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT);
	if (modes & BIT(NBL_PORT_CAP_100GBASE_CR4))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT);
	if (modes & BIT(NBL_PORT_CAP_100G_AUI4))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT);
	if (modes & BIT(NBL_PORT_CAP_100G_CAUI4))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_100000baseLR2_ER2_FR2_Full_BIT);
	if (modes & BIT(NBL_PORT_CAP_100GBASE_KR2_PAM4))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_100000baseKR2_Full_BIT);
	if (modes & BIT(NBL_PORT_CAP_100GBASE_SR2_PAM4))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_100000baseSR2_Full_BIT);
	if (modes & BIT(NBL_PORT_CAP_100GBASE_CR2_PAM4))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_100000baseCR2_Full_BIT);
	if (modes & BIT(NBL_PORT_CAP_100G_AUI2_PAM4))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_100000baseDR2_Full_BIT);
	if (modes & BIT_ULL(NBL_PORT_CAP_200GBASE_KR4))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_200000baseKR4_Full_BIT);
	if (modes & BIT_ULL(NBL_PORT_CAP_200GBASE_CR4))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_200000baseCR4_Full_BIT);
	if (modes & BIT_ULL(NBL_PORT_CAP_400GBASE_KR4))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_400000baseKR4_Full_BIT);
	if (modes & BIT_ULL(NBL_PORT_CAP_400GBASE_CR4))
		ADD_LINK_MODE(ETHTOOL_LINK_MODE_400000baseCR4_Full_BIT);
#undef ADD_LINK_MODE
}

static int nbl_serv_get_port_state(struct nbl_service_mgt *serv_mgt,
				   struct nbl_port_state *port_state)
{
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	int ret = 0;

	if (net_resource_mgt->port_state_update || !serv_mgt->common->is_vf) {
		net_resource_mgt->port_state_update = false;
		/* wmb */
		wmb();
		ret = disp_ops->get_port_state(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					NBL_COMMON_TO_ETH_ID(serv_mgt->common), port_state);
		memcpy(&net_resource_mgt->port_state, port_state, sizeof(*port_state));
	} else {
		memcpy(port_state, &net_resource_mgt->port_state, sizeof(*port_state));
	}

	if (port_state->module_repluged)
		net_resource_mgt->configured_fec = 0;

	return ret;
}

static int nbl_get_ksettings(struct net_device *netdev, struct ethtool_link_ksettings *cmd)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_port_state port_state = {0};
	u32 advertising_speed = 0;
	int ret = 0;

	if (test_bit(NBL_FATAL_ERR, adapter->state) ||
	    test_bit(NBL_PCI_ERR_RECOVERING, adapter->state))
		return -EIO;

	ret = nbl_serv_get_port_state(serv_mgt, &port_state);
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
			advertising_speed = port_state.link_speed;
		} else {
			cmd->base.speed = SPEED_UNKNOWN;
			cmd->base.duplex = DUPLEX_UNKNOWN;
			advertising_speed = net_resource_mgt->configured_speed ?
				    net_resource_mgt->configured_speed : cmd->base.speed;
		}

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
		case NBL_PORT_TYPE_TP:
			__set_bit(ETHTOOL_LINK_MODE_TP_BIT, cmd->link_modes.advertising);
			cmd->base.port = PORT_TP;
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
		case SPEED_2500:
			port_state.port_advertising |= NBL_PORT_CAP_SPEED_2_5G_MASK;
			break;
		case SPEED_5000:
			port_state.port_advertising |= NBL_PORT_CAP_SPEED_5G_MASK;
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
		case SPEED_200000:
			port_state.port_advertising |= NBL_PORT_CAP_SPEED_200G_MASK;
			break;
		case SPEED_400000:
			port_state.port_advertising |= NBL_PORT_CAP_SPEED_400G_MASK;
			break;
		default:
			break;
		}
	}

	nbl_link_modes_to_ethtool(port_state.port_caps, cmd->link_modes.supported);
	nbl_link_modes_to_ethtool(port_state.port_advertising, cmd->link_modes.advertising);
	nbl_link_modes_to_ethtool(port_state.port_lp_advertising, cmd->link_modes.lp_advertising);

	switch (port_state.port_type) {
	case NBL_PORT_TYPE_FIBRE:
		__set_bit(ETHTOOL_LINK_MODE_FIBRE_BIT, cmd->link_modes.supported);
		break;
	case NBL_PORT_TYPE_COPPER:
		__set_bit(ETHTOOL_LINK_MODE_Backplane_BIT, cmd->link_modes.supported);
		break;
	case NBL_PORT_TYPE_TP:
		__set_bit(ETHTOOL_LINK_MODE_TP_BIT, cmd->link_modes.supported);
		break;
	default:
		break;
	}
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
	case NBL_PORT_MAX_RATE_200G:
		return SPEED_200000;
	case NBL_PORT_MAX_RATE_400G:
		return SPEED_400000;
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
	phy_caps = &net_resource_mgt->phy_caps;

	ret = nbl_serv_get_port_state(serv_mgt, &port_state);
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

	if (cmd->base.autoneg == autoneg && cmd->base.speed == port_state.link_speed &&
	    port_state.link_state) {
		netdev_info(netdev, "eth configure is not changed\n");
		return 0;
	}

	if (autoneg == AUTONEG_ENABLE && cmd->base.autoneg == autoneg) {
		netdev_err(netdev, "unsupport to change eth configure when autoneg\n");
		return -EOPNOTSUPP;
	}

	speed = cmd->base.speed;
	fw_speed = nbl_conver_fw_rate_to_speed(port_state.fw_port_max_speed);
	module_speed = nbl_conver_portrate_to_speed(port_state.port_max_rate);
	max_speed = fw_speed > module_speed ? module_speed : fw_speed;
	if (speed == SPEED_UNKNOWN || cmd->base.autoneg)
		speed = max_speed;

	if (speed > max_speed) {
		netdev_err(netdev, "speed %d is not support, exit\n", cmd->base.speed);
		return -EINVAL;
	}

	speed_advert = nbl_speed_to_link_mode(speed, cmd->base.autoneg, port_state.port_type);
	speed_advert &= port_state.port_caps;
	if (!speed_advert) {
		netdev_err(netdev, "speed %d is not support, exit\n", cmd->base.speed);
		return -EINVAL;
	}

	if (cmd->base.autoneg) {
		/* when enable autoneg, set fec will not take effect,
		 * fec mode will be automatically negotiated.
		 */
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
		case SPEED_2500:
			active_fec = NBL_ETH_2_5G_DEFAULT_FEC_MODE;
			net_resource_mgt->configured_fec = ETHTOOL_FEC_OFF;
			break;
		case SPEED_5000:
			active_fec = NBL_ETH_5G_DEFAULT_FEC_MODE;
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
		net_resource_mgt->configured_fec = 0;
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
	struct nbl_netdev_priv *priv = netdev_priv(netdev);
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_dispatch_mgt *disp_mgt = NBL_ADAPTER_TO_DISP_MGT(adapter);
	struct nbl_dispatch_ops *disp_ops = NBL_ADAPTER_TO_DISP_OPS_TBL(adapter)->ops;
	u16 max_desc_num;

	if (!priv->rep) {
		max_desc_num = disp_ops->get_max_desc_num(disp_mgt);
		ringparam->tx_max_pending = max_desc_num;
		ringparam->rx_max_pending = max_desc_num;
		ringparam->tx_pending = ring_mgt->tx_desc_num;
		ringparam->rx_pending = ring_mgt->rx_desc_num;
	} else {
		ringparam->tx_max_pending = NBL_REP_QUEUE_MGT_DESC_MAX;
		ringparam->rx_max_pending = NBL_REP_QUEUE_MGT_DESC_MAX;
		ringparam->tx_pending = NBL_REP_QUEUE_MGT_DESC_NUM;
		ringparam->rx_pending = NBL_REP_QUEUE_MGT_DESC_NUM;
	}
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
	struct nbl_service_mgt *serv_mgt = NBL_ADAPTER_TO_SERV_MGT(adapter);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	int timeout = 50;

	if (ringparam->rx_pending == ring_mgt->rx_desc_num &&
	    ringparam->tx_pending == ring_mgt->tx_desc_num) {
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
	u16 old_tx_count, old_rx_count;
	int was_running;
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

	old_tx_count = ring_mgt->tx_desc_num;
	old_rx_count = ring_mgt->rx_desc_num;
	new_tx_count = ringparam->tx_pending;
	new_rx_count = ringparam->rx_pending;

	netdev_info(netdev, "set tx_desc_num:%d, rx_desc_num:%d\n", new_tx_count, new_rx_count);

	was_running = netif_running(netdev);

	if (was_running) {
		err = nbl_serv_netdev_stop(netdev);
		if (err && err != -EBUSY) {
			netdev_err(netdev, "Netdev stop failed while setting ringparam\n");
			clear_bit(NBL_RESETTING, adapter->state);
			return err;
		}
	}

	ring_mgt->tx_desc_num = new_tx_count;
	ring_mgt->rx_desc_num = new_rx_count;

	if (was_running) {
		err = nbl_serv_netdev_open(netdev);
		if (err) {
			netdev_err(netdev, "Netdev open failed after setting ringparam\n");
			clear_bit(NBL_RESETTING, adapter->state);
			ring_mgt->tx_desc_num = old_tx_count;
			ring_mgt->rx_desc_num = old_rx_count;
			return err;
		}
	}

	clear_bit(NBL_RESETTING, adapter->state);

	return 0;
}

static int nbl_fd_translate_cls_rule(u16 type, u16 length, u8 *val, void *data)
{
	struct ethtool_rxnfc *cmd = (struct ethtool_rxnfc *)(data);
	struct ethtool_rx_flow_spec *fs = &cmd->fs;
	u64 udf_val, udf_mask;
	u32 flow_type = fs->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT | FLOW_RSS);
	u16 ring, vf, vsi;

	switch (type) {
	case NBL_CHAN_FDIR_KEY_SRC_MAC:
		ether_addr_copy(fs->h_u.ether_spec.h_source, val);
		ether_addr_copy(fs->m_u.ether_spec.h_source, val + 6);
		break;
	case NBL_CHAN_FDIR_KEY_DST_MAC:
		if (flow_type == ETHER_FLOW) {
			ether_addr_copy(fs->h_u.ether_spec.h_dest, val);
			ether_addr_copy(fs->m_u.ether_spec.h_dest, val + 6);
		} else {
			ether_addr_copy(fs->h_ext.h_dest, val);
			ether_addr_copy(fs->m_ext.h_dest, val + 6);
			fs->flow_type |= FLOW_MAC_EXT;
		}
		break;
	case NBL_CHAN_FDIR_KEY_PROTO:
		if (flow_type == ETHER_FLOW) {
			fs->h_u.ether_spec.h_proto = *(u16 *)val;
			fs->m_u.ether_spec.h_proto = *(u16 *)(val + 2);
		}
		break;
	case NBL_CHAN_FDIR_KEY_SRC_IPv4:
		if (flow_type == IPV4_USER_FLOW) {
			fs->h_u.usr_ip4_spec.ip4src = *(u32 *)val;
			fs->m_u.usr_ip4_spec.ip4src = *(u32 *)(val + 4);
		} else {
			fs->h_u.tcp_ip4_spec.ip4src = *(u32 *)val;
			fs->m_u.tcp_ip4_spec.ip4src = *(u32 *)(val + 4);
		}
		break;
	case NBL_CHAN_FDIR_KEY_DST_IPv4:
		if (flow_type == IPV4_USER_FLOW) {
			fs->h_u.usr_ip4_spec.ip4dst = *(u32 *)val;
			fs->m_u.usr_ip4_spec.ip4dst = *(u32 *)(val + 4);
		} else {
			fs->h_u.tcp_ip4_spec.ip4dst = *(u32 *)val;
			fs->m_u.tcp_ip4_spec.ip4dst = *(u32 *)(val + 4);
		}
		break;
	case NBL_CHAN_FDIR_KEY_L4PROTO:
		if (flow_type == IPV4_USER_FLOW) {
			fs->h_u.usr_ip4_spec.proto = *(u8 *)val;
			fs->m_u.usr_ip4_spec.proto = *(u8 *)(val + 1);
		} else if (flow_type == IPV6_USER_FLOW) {
			fs->h_u.usr_ip6_spec.l4_proto = *(u8 *)val;
			fs->m_u.usr_ip6_spec.l4_proto = *(u8 *)(val + 1);
		}
		break;
	case NBL_CHAN_FDIR_KEY_SRC_IPv6:
		if (flow_type == IPV6_USER_FLOW) {
			memcpy(&fs->h_u.usr_ip6_spec.ip6src, val,
			       sizeof(fs->h_u.usr_ip6_spec.ip6src));
			memcpy(&fs->m_u.usr_ip6_spec.ip6src, val + 16,
			       sizeof(fs->m_u.usr_ip6_spec.ip6src));
		} else {
			memcpy(&fs->h_u.tcp_ip6_spec.ip6src, val,
			       sizeof(fs->h_u.tcp_ip6_spec.ip6src));
			memcpy(&fs->m_u.tcp_ip6_spec.ip6src, val + 16,
			       sizeof(fs->m_u.tcp_ip6_spec.ip6src));
		}
		break;
	case NBL_CHAN_FDIR_KEY_DST_IPv6:
		if (flow_type == IPV6_USER_FLOW) {
			memcpy(&fs->h_u.usr_ip6_spec.ip6dst, val,
			       sizeof(fs->h_u.usr_ip6_spec.ip6dst));
			memcpy(&fs->m_u.usr_ip6_spec.ip6dst, val + 16,
			       sizeof(fs->m_u.usr_ip6_spec.ip6dst));
		} else {
			memcpy(&fs->h_u.tcp_ip6_spec.ip6dst, val,
			       sizeof(fs->h_u.tcp_ip6_spec.ip6dst));
			memcpy(&fs->m_u.tcp_ip6_spec.ip6dst, val + 16,
			       sizeof(fs->m_u.tcp_ip6_spec.ip6dst));
		}
		break;
	case NBL_CHAN_FDIR_KEY_SPORT:
		if (flow_type == TCP_V4_FLOW || flow_type == UDP_V4_FLOW) {
			fs->h_u.tcp_ip4_spec.psrc = *(u16 *)val;
			fs->m_u.tcp_ip4_spec.psrc = *(u16 *)(val + 2);
		} else if (flow_type == TCP_V6_FLOW || flow_type == UDP_V6_FLOW) {
			fs->h_u.tcp_ip6_spec.psrc = *(u16 *)val;
			fs->m_u.tcp_ip6_spec.psrc = *(u16 *)(val + 2);
		}
		break;
	case NBL_CHAN_FDIR_KEY_DPORT:
		if (flow_type == TCP_V4_FLOW || flow_type == UDP_V4_FLOW) {
			fs->h_u.tcp_ip4_spec.pdst = *(u16 *)val;
			fs->m_u.tcp_ip4_spec.pdst = *(u16 *)(val + 2);
		} else if (flow_type == TCP_V6_FLOW || flow_type == UDP_V6_FLOW) {
			fs->h_u.tcp_ip6_spec.pdst = *(u16 *)val;
			fs->m_u.tcp_ip6_spec.pdst = *(u16 *)(val + 2);
		}
		break;
	case NBL_CHAN_FDIR_KEY_UDF:
		udf_val = cpu_to_be64p((u64 *)val);
		udf_mask = cpu_to_be64p((u64 *)(val + 8));

		memcpy(fs->h_ext.data, &udf_val, sizeof(udf_val));
		memcpy(fs->m_ext.data, &udf_mask, sizeof(udf_mask));
		fs->flow_type |= FLOW_EXT;
		break;
	case NBL_CHAN_FDIR_KEY_SVLAN:
		fs->h_ext.vlan_tci = *(u16 *)val;
		fs->m_ext.vlan_tci = *(u16 *)(val + 2);
		fs->flow_type |= FLOW_EXT;
		break;
	case NBL_CHAN_FDIR_ACTION_QUEUE:
		ring = *(u16 *)val;
		vf = *(u16 *)(val + 2);
		fs->ring_cookie = (u64)ring | (u64)vf << ETHTOOL_RX_FLOW_SPEC_RING_VF_OFF;
		break;
	case NBL_CHAN_FDIR_ACTION_VSI:
		vsi = *(u16 *)(val + 4);
		if (vsi == 0xFFFF)
			fs->ring_cookie = RX_CLS_FLOW_DISC;
		break;
	default:
		break;
	}

	return 0;
}

static void nbl_fd_flow_type_translate(enum nbl_chan_fdir_flow_type flow_type,
				       struct ethtool_rxnfc *cmd)
{
	switch (flow_type) {
	case NBL_CHAN_FDIR_FLOW_FULL:
	case NBL_CHAN_FDIR_FLOW_ETHER:
		cmd->fs.flow_type = ETHER_FLOW;
		break;
	case NBL_CHAN_FDIR_FLOW_IPv4:
		cmd->fs.flow_type = IPV4_USER_FLOW;
		cmd->fs.h_u.usr_ip4_spec.ip_ver = ETH_RX_NFC_IP4;
		cmd->fs.m_u.usr_ip4_spec.ip_ver = 0xFF;
		break;
	case NBL_CHAN_FDIR_FLOW_IPv6:
		cmd->fs.flow_type = IPV6_USER_FLOW;
		break;
	case NBL_CHAN_FDIR_FLOW_TCP_IPv4:
		cmd->fs.flow_type = TCP_V4_FLOW;
		break;
	case NBL_CHAN_FDIR_FLOW_TCP_IPv6:
		cmd->fs.flow_type = TCP_V6_FLOW;
		break;
	case NBL_CHAN_FDIR_FLOW_UDP_IPv4:
		cmd->fs.flow_type = UDP_V4_FLOW;
		break;
	case NBL_CHAN_FDIR_FLOW_UDP_IPv6:
		cmd->fs.flow_type = UDP_V6_FLOW;
		break;
	default:
		break;
	}
}

static int nbl_parse_flow_type(u32 flow_type)
{
	switch (flow_type) {
	case TCP_V4_FLOW:
		return NBL_FLOW_TYPE_TCPV4;
	case TCP_V6_FLOW:
		return NBL_FLOW_TYPE_TCPV6;
	case UDP_V4_FLOW:
		return NBL_FLOW_TYPE_UDPV4;
	case UDP_V6_FLOW:
		return NBL_FLOW_TYPE_UDPV6;
	case SCTP_V4_FLOW:
		return NBL_FLOW_TYPE_SCTPV4;
	case SCTP_V6_FLOW:
		return NBL_FLOW_TYPE_SCTPV6;
	default:
		return -EINVAL;
	}
}

static int nbl_get_rss_hash_opt(struct net_device *netdev, struct ethtool_rxnfc *nfc)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	u16 vsi_id = NBL_COMMON_TO_VSI_ID(common);
	int flow_type;
	u64 hash_fields = 0;
	int ret = 0;

	flow_type = nbl_parse_flow_type(nfc->flow_type);
	if (flow_type < 0)
		return -EOPNOTSUPP;

	ret = disp_ops->get_hash_fields(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					vsi_id, flow_type, &hash_fields);
	if (ret < 0)
		return ret;

	nfc->data = 0;
	if (hash_fields & NBL_HASH_FILED_SRC_IP)
		nfc->data |= RXH_IP_SRC;
	if (hash_fields & NBL_HASH_FILED_DST_IP)
		nfc->data |= RXH_IP_DST;
	if (hash_fields & NBL_HASH_FILED_L4_SPORT)
		nfc->data |= RXH_L4_B_0_1;
	if (hash_fields & NBL_HASH_FILED_L4_DPORT)
		nfc->data |= RXH_L4_B_2_3;

	return 0;
}

static int nbl_set_rss_hash_opt(struct net_device *netdev, struct ethtool_rxnfc *nfc)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	u16 vsi_id = NBL_COMMON_TO_VSI_ID(common);
	int flow_type;
	u64 hash_fields = 0;
	int ret = 0;

	flow_type = nbl_parse_flow_type(nfc->flow_type);
	if (flow_type < 0)
		return -EOPNOTSUPP;

	if (nfc->data & ~(RXH_IP_SRC | RXH_IP_DST | RXH_L4_B_0_1 | RXH_L4_B_2_3))
		return -EOPNOTSUPP;

	if (nfc->data & RXH_IP_SRC)
		hash_fields |= NBL_HASH_FILED_SRC_IP;
	if (nfc->data & RXH_IP_DST)
		hash_fields |= NBL_HASH_FILED_DST_IP;
	if (nfc->data & RXH_L4_B_0_1)
		hash_fields |= NBL_HASH_FILED_L4_SPORT;
	if (nfc->data & RXH_L4_B_2_3)
		hash_fields |= NBL_HASH_FILED_L4_DPORT;

	ret = disp_ops->set_hash_fields(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					vsi_id, flow_type, hash_fields);
	if (ret < 0)
		return ret;

	return 0;
}

static int nbl_get_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd, u32 *rule_locs)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info;
	struct nbl_chan_param_fdir_replace *info;
	struct nbl_chan_param_get_fd_flow_all param;
	u32 *locs_tmp = NULL;
	int ret = 0, start = 0, num = 0, total_num = 0, i;

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];

	switch (cmd->cmd) {
	case ETHTOOL_GRXRINGS:
		cmd->data = vsi_info->active_ring_num;
		break;
	case ETHTOOL_GRXCLSRLCNT:
		ret = disp_ops->get_fd_flow_cnt(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						NBL_CHAN_FDIR_RULE_NORMAL,
						NBL_COMMON_TO_VSI_ID(common));
		if (ret < 0)
			return ret;

		cmd->rule_cnt = ret;
		return 0;
	case ETHTOOL_GRXCLSRULE:
		info = kzalloc(NBL_CHAN_FDIR_FLOW_RULE_SIZE, GFP_KERNEL);
		if (!info)
			return -ENOMEM;
		ret = disp_ops->get_fd_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					    NBL_COMMON_TO_VSI_ID(common),
					    cmd->fs.location,
					    NBL_CHAN_FDIR_RULE_NORMAL,
					    info);
		if (!ret) {
			nbl_fd_flow_type_translate(info->flow_type, cmd);
			cmd->fs.location = info->location;
			nbl_flow_direct_parse_tlv_data(info->tlv, info->tlv_length,
						       nbl_fd_translate_cls_rule, cmd);
		}
		kfree(info);
		break;
	case ETHTOOL_GRXCLSRLALL:
		total_num = cmd->rule_cnt;

		locs_tmp = kcalloc(NBL_CHAN_GET_FD_LOCS_MAX, sizeof(*locs_tmp), GFP_KERNEL);
		if (!locs_tmp)
			return -ENOMEM;

		while (total_num > 0) {
			num = total_num > NBL_CHAN_GET_FD_LOCS_MAX ? NBL_CHAN_GET_FD_LOCS_MAX
								   : total_num;
			param.rule_type = NBL_CHAN_FDIR_RULE_NORMAL;
			param.start = start;
			param.num = num;
			param.vsi_id = NBL_COMMON_TO_VSI_ID(common);
			ret = disp_ops->get_fd_flow_all(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
							&param, locs_tmp);
			if (ret) {
				kfree(locs_tmp);
				return ret;
			}

			for (i = 0; i < num; i++)
				rule_locs[start + i] = locs_tmp[i];

			start += num;
			total_num -= num;
		}

		cmd->data = disp_ops->get_fd_flow_max(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
		kfree(locs_tmp);
		break;
	case ETHTOOL_GRXFH:
		ret = nbl_get_rss_hash_opt(netdev, cmd);
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}

	return ret;
}

static int nbl_format_flow_ext_rule(struct ethtool_rx_flow_spec *fs,
				    struct nbl_chan_param_fdir_replace *info,
				    int *offset)
{
	u64 udf_value = be64_to_cpup((__force __be64 *)fs->h_ext.data);
	u64 udf_mask = be64_to_cpup((__force __be64 *)fs->m_ext.data);
	u8 *tlv_start = info->tlv + *offset;
	u16 tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 16;

	if (fs->m_ext.vlan_etype)
		return -EINVAL;

	if (fs->m_ext.vlan_tci) {
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 4;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_SVLAN;
		*(u16 *)(tlv_start + 2) = 4;
		*(u16 *)(tlv_start + 4) = fs->h_ext.vlan_tci;
		*(u16 *)(tlv_start + 6) = fs->m_ext.vlan_tci;
		*offset += tlv_length;

		/* FLOW_EXT may carry VLAN and UDF matching at the same time. */
		if (!udf_mask)
			return 0;
	}

	tlv_start = info->tlv + *offset;
	tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 16;
	if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
		return -EINVAL;

	*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_UDF;
	*(u16 *)(tlv_start + 2) = 16;
	memcpy(tlv_start + 4, &udf_value, sizeof(udf_value));
	memcpy(tlv_start + 12, &udf_mask, sizeof(udf_mask));
	*offset += tlv_length;

	return 0;
}

static int nbl_format_flow_mac_ext_rule(struct ethtool_rx_flow_spec *fs,
					struct nbl_chan_param_fdir_replace *info,
					int *offset)
{
	u8 *tlv_start = info->tlv + *offset;
	u16 tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 2 * ETH_ALEN;

	if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
		return -EINVAL;

	*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_DST_MAC;
	*(u16 *)(tlv_start + 2) = 2 * ETH_ALEN;
	ether_addr_copy(tlv_start + 4, fs->h_ext.h_dest);
	ether_addr_copy(tlv_start + 10, fs->m_ext.h_dest);
	*offset += tlv_length;

	return 0;
}

static int nbl_format_ether_flow_rule(struct ethtool_rx_flow_spec *fs,
				      struct nbl_chan_param_fdir_replace *info,
				      int *offset)
{
	struct ethhdr *ether_spec = &fs->h_u.ether_spec;
	struct ethhdr *ether_mask = &fs->m_u.ether_spec;
	u8 *tlv_start;
	u16 tlv_length;

	if (!is_zero_ether_addr(ether_mask->h_dest)) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 2 * ETH_ALEN;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_DST_MAC;
		*(u16 *)(tlv_start + 2) = 2 * ETH_ALEN;
		ether_addr_copy(tlv_start + 4, ether_spec->h_dest);
		ether_addr_copy(tlv_start + 10, ether_mask->h_dest);
		*offset += tlv_length;
	}

	if (!is_zero_ether_addr(ether_mask->h_source)) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 2 * ETH_ALEN;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_SRC_MAC;
		*(u16 *)(tlv_start + 2) = 2 * ETH_ALEN;
		ether_addr_copy(tlv_start + 4, ether_spec->h_source);
		ether_addr_copy(tlv_start + 10, ether_mask->h_source);
		*offset += tlv_length;
	}

	if (ether_mask->h_proto) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 4;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_PROTO;
		*(u16 *)(tlv_start + 2) = 4;
		*(u16 *)(tlv_start + 4) = ether_spec->h_proto;
		*(u16 *)(tlv_start + 6) = ether_mask->h_proto;
		*offset += tlv_length;
	}

	return 0;
}

static int nbl_format_ipv4_flow_rule(struct ethtool_rx_flow_spec *fs,
				     struct nbl_chan_param_fdir_replace *info,
				     int *offset)
{
	struct ethtool_usrip4_spec *usr_ip4_spec = &fs->h_u.usr_ip4_spec;
	struct ethtool_usrip4_spec *usr_ip4_mask = &fs->m_u.usr_ip4_spec;
	u8 *tlv_start;
	u16 tlv_length;

	if (usr_ip4_mask->l4_4_bytes || usr_ip4_mask->tos ||
	    usr_ip4_spec->ip_ver != ETH_RX_NFC_IP4)
		return -EINVAL;

	if (usr_ip4_mask->ip4src) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 8;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_SRC_IPv4;
		*(u16 *)(tlv_start + 2) = 8;
		*(u32 *)(tlv_start + 4) = usr_ip4_spec->ip4src;
		*(u32 *)(tlv_start + 8) = usr_ip4_mask->ip4src;
		*offset += tlv_length;
	}

	if (usr_ip4_mask->ip4dst) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 8;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_DST_IPv4;
		*(u16 *)(tlv_start + 2) = 8;
		*(u32 *)(tlv_start + 4) = usr_ip4_spec->ip4dst;
		*(u32 *)(tlv_start + 8) = usr_ip4_mask->ip4dst;
		*offset += tlv_length;
	}

	if (usr_ip4_mask->proto) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 4;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_L4PROTO;
		*(u16 *)(tlv_start + 2) = 4;
		*(u8 *)(tlv_start + 4) = usr_ip4_spec->proto;
		*(u8 *)(tlv_start + 5) = usr_ip4_mask->proto;
		*offset += tlv_length;
	}

	tlv_start = info->tlv + *offset;
	tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 4;
	if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
		return -EINVAL;

	*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_PROTO;
	*(u16 *)(tlv_start + 2) = 4;
	*(u16 *)(tlv_start + 4) = htons(ETH_P_IP);
	*(u16 *)(tlv_start + 6) = 0xFFFF;
	*offset += tlv_length;
	return 0;
}

static int nbl_format_ipv6_flow_rule(struct ethtool_rx_flow_spec *fs,
				     struct nbl_chan_param_fdir_replace *info,
				     int *offset)
{
	struct ethtool_usrip6_spec *usr_ip6_spec = &fs->h_u.usr_ip6_spec;
	struct ethtool_usrip6_spec *usr_ip6_mask = &fs->m_u.usr_ip6_spec;
	u8 *tlv_start;
	u16 tlv_length;

	if (usr_ip6_mask->l4_4_bytes || usr_ip6_mask->tclass)
		return -EINVAL;

	if (!ipv6_addr_any((struct in6_addr *)usr_ip6_mask->ip6src)) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 32;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_SRC_IPv6;
		*(u16 *)(tlv_start + 2) = 32;
		memcpy(tlv_start + 4, usr_ip6_spec->ip6src, sizeof(usr_ip6_spec->ip6src));
		memcpy(tlv_start + 20, usr_ip6_mask->ip6src, sizeof(usr_ip6_mask->ip6src));
		*offset += tlv_length;
	}

	if (!ipv6_addr_any((struct in6_addr *)usr_ip6_mask->ip6dst)) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 32;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_DST_IPv6;
		*(u16 *)(tlv_start + 2) = 32;
		memcpy(tlv_start + 4, usr_ip6_spec->ip6dst, sizeof(usr_ip6_spec->ip6dst));
		memcpy(tlv_start + 20, usr_ip6_mask->ip6dst, sizeof(usr_ip6_mask->ip6dst));
		*offset += tlv_length;
	}

	if (usr_ip6_mask->l4_proto) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 4;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_L4PROTO;
		*(u16 *)(tlv_start + 2) = 4;
		*(u8 *)(tlv_start + 4) = usr_ip6_spec->l4_proto;
		*(u8 *)(tlv_start + 5) = usr_ip6_mask->l4_proto;
		*offset += tlv_length;
	}

	tlv_start = info->tlv + *offset;
	tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 4;
	if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
		return -EINVAL;

	*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_PROTO;
	*(u16 *)(tlv_start + 2) = 4;
	*(u16 *)(tlv_start + 4) = htons(ETH_P_IPV6);
	*(u16 *)(tlv_start + 6) = 0xFFFF;
	*offset += tlv_length;
	return 0;
}

static int nbl_format_tcpv4_flow_rule(struct ethtool_rx_flow_spec *fs,
				      struct nbl_chan_param_fdir_replace *info,
				      int *offset)
{
	struct ethtool_tcpip4_spec *tcp_ip4_spec = &fs->h_u.tcp_ip4_spec;
	struct ethtool_tcpip4_spec *tcp_ip4_mask = &fs->m_u.tcp_ip4_spec;
	u8 *tlv_start;
	u16 tlv_length;

	if (tcp_ip4_mask->tos)
		return -EINVAL;

	if (tcp_ip4_mask->ip4src) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 8;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_SRC_IPv4;
		*(u16 *)(tlv_start + 2) = 8;
		*(u32 *)(tlv_start + 4) = tcp_ip4_spec->ip4src;
		*(u32 *)(tlv_start + 8) = tcp_ip4_mask->ip4src;
		*offset += tlv_length;
	}

	if (tcp_ip4_mask->ip4dst) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 8;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_DST_IPv4;
		*(u16 *)(tlv_start + 2) = 8;
		*(u32 *)(tlv_start + 4) = tcp_ip4_spec->ip4dst;
		*(u32 *)(tlv_start + 8) = tcp_ip4_mask->ip4dst;
		*offset += tlv_length;
	}

	if (tcp_ip4_mask->psrc) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 4;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_SPORT;
		*(u16 *)(tlv_start + 2) = 4;
		*(u16 *)(tlv_start + 4) = tcp_ip4_spec->psrc;
		*(u16 *)(tlv_start + 6) = tcp_ip4_mask->psrc;
		*offset += tlv_length;
	}

	if (tcp_ip4_mask->pdst) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 4;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_DPORT;
		*(u16 *)(tlv_start + 2) = 4;
		*(u16 *)(tlv_start + 4) = tcp_ip4_spec->pdst;
		*(u16 *)(tlv_start + 6) = tcp_ip4_mask->pdst;
		*offset += tlv_length;
	}

	tlv_start = info->tlv + *offset;
	tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 4;
	if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
		return -EINVAL;

	*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_L4PROTO;
	*(u16 *)(tlv_start + 2) = 4;
	*(u8 *)(tlv_start + 4) = IPPROTO_TCP;
	*(u8 *)(tlv_start + 5) = 0xFF;
	*offset += tlv_length;

	tlv_start = info->tlv + *offset;
	tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 4;
	if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
		return -EINVAL;

	*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_PROTO;
	*(u16 *)(tlv_start + 2) = 4;
	*(u16 *)(tlv_start + 4) = htons(ETH_P_IP);
	*(u16 *)(tlv_start + 6) = 0xFFFF;
	*offset += tlv_length;

	return 0;
}

static int nbl_format_tcpv6_flow_rule(struct ethtool_rx_flow_spec *fs,
				      struct nbl_chan_param_fdir_replace *info,
				      int *offset)
{
	struct ethtool_tcpip6_spec *tcp_ip6_spec = &fs->h_u.tcp_ip6_spec;
	struct ethtool_tcpip6_spec *tcp_ip6_mask = &fs->m_u.tcp_ip6_spec;
	u8 *tlv_start;
	u16 tlv_length;

	if (tcp_ip6_mask->tclass)
		return -EINVAL;

	if (!ipv6_addr_any((struct in6_addr *)tcp_ip6_mask->ip6src)) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 32;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_SRC_IPv6;
		*(u16 *)(tlv_start + 2) = 32;
		memcpy(tlv_start + 4, tcp_ip6_spec->ip6src, sizeof(tcp_ip6_spec->ip6src));
		memcpy(tlv_start + 20, tcp_ip6_mask->ip6src, sizeof(tcp_ip6_mask->ip6src));
		*offset += tlv_length;
	}

	if (!ipv6_addr_any((struct in6_addr *)tcp_ip6_mask->ip6dst)) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 32;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_DST_IPv6;
		*(u16 *)(tlv_start + 2) = 32;
		memcpy(tlv_start + 4, tcp_ip6_spec->ip6dst, sizeof(tcp_ip6_spec->ip6dst));
		memcpy(tlv_start + 20, tcp_ip6_mask->ip6dst, sizeof(tcp_ip6_mask->ip6dst));
		*offset += tlv_length;
	}

	if (tcp_ip6_mask->psrc) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 4;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_SPORT;
		*(u16 *)(tlv_start + 2) = 4;
		*(u16 *)(tlv_start + 4) = tcp_ip6_spec->psrc;
		*(u16 *)(tlv_start + 6) = tcp_ip6_mask->psrc;
		*offset += tlv_length;
	}

	if (tcp_ip6_mask->pdst) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 4;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_DPORT;
		*(u16 *)(tlv_start + 2) = 4;
		*(u16 *)(tlv_start + 4) = tcp_ip6_spec->pdst;
		*(u16 *)(tlv_start + 6) = tcp_ip6_mask->pdst;
		*offset += tlv_length;
	}

	tlv_start = info->tlv + *offset;
	tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 4;
	if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
		return -EINVAL;

	*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_L4PROTO;
	*(u16 *)(tlv_start + 2) = 4;
	*(u8 *)(tlv_start + 4) = IPPROTO_TCP;
	*(u8 *)(tlv_start + 5) = 0xFF;
	*offset += tlv_length;

	tlv_start = info->tlv + *offset;
	tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 4;
	if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
		return -EINVAL;

	*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_PROTO;
	*(u16 *)(tlv_start + 2) = 4;
	*(u16 *)(tlv_start + 4) = htons(ETH_P_IPV6);
	*(u16 *)(tlv_start + 6) = 0xFFFF;
	*offset += tlv_length;

	return 0;
}

static int nbl_format_udpv4_flow_rule(struct ethtool_rx_flow_spec *fs,
				      struct nbl_chan_param_fdir_replace *info,
				      int *offset)
{
	struct ethtool_tcpip4_spec *udp_ip4_spec = &fs->h_u.udp_ip4_spec;
	struct ethtool_tcpip4_spec *udp_ip4_mask = &fs->m_u.udp_ip4_spec;
	u8 *tlv_start;
	u16 tlv_length;

	if (udp_ip4_mask->tos)
		return -EINVAL;

	if (udp_ip4_mask->ip4src) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 8;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_SRC_IPv4;
		*(u16 *)(tlv_start + 2) = 8;
		*(u32 *)(tlv_start + 4) = udp_ip4_spec->ip4src;
		*(u32 *)(tlv_start + 8) = udp_ip4_mask->ip4src;
		*offset += tlv_length;
	}

	if (udp_ip4_mask->ip4dst) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 8;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_DST_IPv4;
		*(u16 *)(tlv_start + 2) = 8;
		*(u32 *)(tlv_start + 4) = udp_ip4_spec->ip4dst;
		*(u32 *)(tlv_start + 8) = udp_ip4_mask->ip4dst;
		*offset += tlv_length;
	}

	if (udp_ip4_mask->psrc) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 4;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_SPORT;
		*(u16 *)(tlv_start + 2) = 4;
		*(u16 *)(tlv_start + 4) = udp_ip4_spec->psrc;
		*(u16 *)(tlv_start + 6) = udp_ip4_mask->psrc;
		*offset += tlv_length;
	}

	if (udp_ip4_mask->pdst) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 4;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_DPORT;
		*(u16 *)(tlv_start + 2) = 4;
		*(u16 *)(tlv_start + 4) = udp_ip4_spec->pdst;
		*(u16 *)(tlv_start + 6) = udp_ip4_mask->pdst;
		*offset += tlv_length;
	}

	tlv_start = info->tlv + *offset;
	tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 4;
	if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
		return -EINVAL;

	*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_L4PROTO;
	*(u16 *)(tlv_start + 2) = 4;
	*(u8 *)(tlv_start + 4) = IPPROTO_UDP;
	*(u8 *)(tlv_start + 5) = 0xFF;
	*offset += tlv_length;

	tlv_start = info->tlv + *offset;
	tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 4;
	if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
		return -EINVAL;

	*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_PROTO;
	*(u16 *)(tlv_start + 2) = 4;
	*(u16 *)(tlv_start + 4) = htons(ETH_P_IP);
	*(u16 *)(tlv_start + 6) = 0xFFFF;
	*offset += tlv_length;

	return 0;
}

static int nbl_format_udpv6_flow_rule(struct ethtool_rx_flow_spec *fs,
				      struct nbl_chan_param_fdir_replace *info,
				      int *offset)
{
	struct ethtool_tcpip6_spec *udp_ip6_spec = &fs->h_u.udp_ip6_spec;
	struct ethtool_tcpip6_spec *udp_ip6_mask = &fs->m_u.udp_ip6_spec;
	u8 *tlv_start;
	u16 tlv_length;

	if (udp_ip6_mask->tclass)
		return -EINVAL;

	if (!ipv6_addr_any((struct in6_addr *)udp_ip6_mask->ip6src)) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 32;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_SRC_IPv6;
		*(u16 *)(tlv_start + 2) = 32;
		memcpy(tlv_start + 4, udp_ip6_spec->ip6src, sizeof(udp_ip6_spec->ip6src));
		memcpy(tlv_start + 20, udp_ip6_mask->ip6src, sizeof(udp_ip6_mask->ip6src));
		*offset += tlv_length;
	}

	if (!ipv6_addr_any((struct in6_addr *)udp_ip6_mask->ip6dst)) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 32;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_DST_IPv6;
		*(u16 *)(tlv_start + 2) = 32;
		memcpy(tlv_start + 4, udp_ip6_spec->ip6dst, sizeof(udp_ip6_spec->ip6dst));
		memcpy(tlv_start + 20, udp_ip6_mask->ip6dst, sizeof(udp_ip6_mask->ip6dst));
		*offset += tlv_length;
	}

	if (udp_ip6_mask->psrc) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 4;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_SPORT;
		*(u16 *)(tlv_start + 2) = 4;
		*(u16 *)(tlv_start + 4) = udp_ip6_spec->psrc;
		*(u16 *)(tlv_start + 6) = udp_ip6_mask->psrc;
		*offset += tlv_length;
	}

	if (udp_ip6_mask->pdst) {
		tlv_start = info->tlv + *offset;
		tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 4;
		if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
			return -EINVAL;

		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_DPORT;
		*(u16 *)(tlv_start + 2) = 4;
		*(u16 *)(tlv_start + 4) = udp_ip6_spec->pdst;
		*(u16 *)(tlv_start + 6) = udp_ip6_mask->pdst;
		*offset += tlv_length;
	}

	tlv_start = info->tlv + *offset;
	tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 4;
	if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
		return -EINVAL;

	*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_L4PROTO;
	*(u16 *)(tlv_start + 2) = 4;
	*(u8 *)(tlv_start + 4) = IPPROTO_UDP;
	*(u8 *)(tlv_start + 5) = 0xFF;
	*offset += tlv_length;

	tlv_start = info->tlv + *offset;
	tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 4;
	if (*offset > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
		return -EINVAL;

	*(u16 *)(tlv_start) = NBL_CHAN_FDIR_KEY_PROTO;
	*(u16 *)(tlv_start + 2) = 4;
	*(u16 *)(tlv_start + 4) = htons(ETH_P_IPV6);
	*(u16 *)(tlv_start + 6) = 0xFFFF;
	*offset += tlv_length;

	return 0;
}

static struct nbl_chan_param_fdir_replace *nbl_format_fdir_rule(struct ethtool_rx_flow_spec *fs)
{
	struct nbl_chan_param_fdir_replace *info;
	int ret = 0, offset = 0;
	u32 flow_type = fs->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT | FLOW_RSS);

	info = kzalloc(NBL_CHAN_FDIR_FLOW_RULE_SIZE, GFP_KERNEL);
	if (!info)
		return NULL;

	if (fs->flow_type & FLOW_RSS) {
		ret = -EINVAL;
		goto check_failed;
	}

	if (fs->flow_type & FLOW_EXT) {
		ret = nbl_format_flow_ext_rule(fs, info, &offset);
		if (ret)
			goto check_failed;
	}

	if (fs->flow_type & FLOW_MAC_EXT) {
		ret = nbl_format_flow_mac_ext_rule(fs, info, &offset);
		if (ret)
			goto check_failed;
	}

	switch (flow_type) {
	case ETHER_FLOW:
		info->flow_type = NBL_CHAN_FDIR_FLOW_ETHER;
		ret = nbl_format_ether_flow_rule(fs, info, &offset);
		if (ret)
			goto check_failed;
		break;
	case IPV4_USER_FLOW:
		info->flow_type = NBL_CHAN_FDIR_FLOW_IPv4;
		ret = nbl_format_ipv4_flow_rule(fs, info, &offset);
		if (ret)
			goto check_failed;
		break;
	case IPV6_USER_FLOW:
		info->flow_type = NBL_CHAN_FDIR_FLOW_IPv6;
		ret = nbl_format_ipv6_flow_rule(fs, info, &offset);
		if (ret)
			goto check_failed;
		break;
	case TCP_V4_FLOW:
		info->flow_type = NBL_CHAN_FDIR_FLOW_TCP_IPv4;
		ret = nbl_format_tcpv4_flow_rule(fs, info, &offset);
		if (ret)
			goto check_failed;
		break;
	case TCP_V6_FLOW:
		info->flow_type = NBL_CHAN_FDIR_FLOW_TCP_IPv6;
		ret = nbl_format_tcpv6_flow_rule(fs, info, &offset);
		if (ret)
			goto check_failed;
		break;
	case UDP_V4_FLOW:
		info->flow_type = NBL_CHAN_FDIR_FLOW_UDP_IPv4;
		ret = nbl_format_udpv4_flow_rule(fs, info, &offset);
		if (ret)
			goto check_failed;
		break;
	case UDP_V6_FLOW:
		info->flow_type = NBL_CHAN_FDIR_FLOW_UDP_IPv6;
		ret = nbl_format_udpv6_flow_rule(fs, info, &offset);
		if (ret)
			goto check_failed;
		break;
	default:
		ret = -EOPNOTSUPP;
		goto check_failed;
	}

	info->rule_type = NBL_CHAN_FDIR_RULE_NORMAL;
	info->order = 1;
	info->tlv_length = offset;
	info->base_length = sizeof(*info);
	info->location = fs->location;
	return info;

check_failed:
	kfree(info);
	return NULL;
}

static int nbl_format_fdir_action(struct nbl_chan_param_fdir_replace *info,
				  u16 ring, u16 vf_id, u16 dport, u16 global_queue_id)
{
	u8 *tlv_start;
	u16 tlv_length = NBL_CHAN_FDIR_TLV_HEADER_LEN + 8;

	if (info->tlv_length > (NBL_CHAN_FDIR_FLOW_TLV_SIZE - tlv_length))
		return -EINVAL;

	tlv_start = info->tlv + info->tlv_length;
	if (dport != 0xFFFF)
		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_ACTION_QUEUE;
	else
		*(u16 *)(tlv_start) = NBL_CHAN_FDIR_ACTION_VSI;

	*(u16 *)(tlv_start + 2) = 8;
	*(u16 *)(tlv_start + 4) = info->ring = ring;
	*(u16 *)(tlv_start + 6) = info->vf = vf_id;
	*(u16 *)(tlv_start + 8) = info->dport = dport;
	*(u16 *)(tlv_start + 10) = info->global_queue_id = global_queue_id;

	info->tlv_length += tlv_length;
	return 0;
}

static int nbl_set_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_net_resource_mgt *net_resource_mgt =
					NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];
	struct nbl_chan_param_fdir_replace *info;
	u64 ring_cookie = cmd->fs.ring_cookie;
	int ret = -EOPNOTSUPP;
	u32 ring = 0;
	u16 vf = 0;
	u16 vsi_id = NBL_COMMON_TO_VSI_ID(common);
	u16 global_queue_id = NBL_INVALID_QUEUE_ID, dport = 0xFFFF;

	switch (cmd->cmd) {
	case ETHTOOL_SRXCLSRLINS:
		if (common->is_vf)
			return -EOPNOTSUPP;
		if (ring_cookie == RX_CLS_FLOW_WAKE)
			return -EINVAL;

		if (ring_cookie != RX_CLS_FLOW_DISC) {
			struct nbl_ch_prm_get_vsi_global_qid prm = {0};

			dport = vsi_id;
			ring = ethtool_get_flow_spec_ring(cmd->fs.ring_cookie);
			vf = ethtool_get_flow_spec_ring_vf(cmd->fs.ring_cookie);

			if (vf == 0 && (ring < vsi_info->ring_offset ||
					ring >= vsi_info->ring_offset + vsi_info->active_ring_num))
				return -EINVAL;

			/* vf = real_vf_idx + 1, 0 means direct to rx queue. */
			if (vf > net_resource_mgt->total_vfs)
				return -EINVAL;

			if (vf)
				dport = disp_ops->get_vf_vsi_id(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
								vsi_id, vf - 1);
			prm.vsi_id = dport;
			prm.local_qid = ring;

			global_queue_id = disp_ops->get_vsi_global_qid
					(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &prm);
		}

		info = nbl_format_fdir_rule(&cmd->fs);
		if (!info)
			return -EINVAL;

		info->vsi = vsi_id;
		ret = nbl_format_fdir_action(info, ring, vf, dport, global_queue_id);
		if (ret) {
			kfree(info);
			return ret;
		}
		ret = disp_ops->replace_fd_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), info);
		kfree(info);
		break;
	case ETHTOOL_SRXCLSRLDEL:
		if (common->is_vf)
			return -EOPNOTSUPP;
		ret = disp_ops->remove_fd_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					       NBL_CHAN_FDIR_RULE_NORMAL,
					       cmd->fs.location, vsi_id);
		break;
	case ETHTOOL_SRXFH:
		ret = nbl_set_rss_hash_opt(netdev, cmd);
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
				      &NBL_COMMON_TO_VSI_ID(common), &rxfh_indir_size);

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
	struct nbl_ch_prm_get_rxfh_rss_key key_prm = {0};
	struct nbl_ch_prm_get_rxfh_key rss_key;
	u32 rxfh_key_size = 0;
	u32 rxfh_indir_size = 0;

	memset(&rss_key, 0, sizeof(rss_key));
	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	common = NBL_SERV_MGT_TO_COMMON(serv_mgt);

	disp_ops->get_rxfh_rss_key_size(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &rxfh_key_size);
	disp_ops->get_rxfh_indir_size(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				      &NBL_COMMON_TO_VSI_ID(common), &rxfh_indir_size);
	key_prm.vsi_id = NBL_COMMON_TO_VSI_ID(common);
	key_prm.rss_key_size = rxfh_key_size;

	if (indir)
		disp_ops->get_rxfh_indir(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					 NBL_COMMON_TO_VSI_ID(common), indir, rxfh_indir_size);
	if (key) {
		disp_ops->get_rxfh_rss_key(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					   &key_prm, &rss_key);
		memcpy(key, rss_key.rss_key, rxfh_key_size);
	}
	if (hfunc)
		disp_ops->get_rxfh_rss_alg_sel(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					       &NBL_COMMON_TO_VSI_ID(common), hfunc);

	return 0;
}

static int nbl_set_rxfh(struct net_device *netdev, const u32 *indir, const u8 *key, const u8 hfunc)
{
	enum nbl_fix_cap_type cap_type = NBL_RXFH_KEY_SET_CAP;
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct device *dev = NBL_SERV_MGT_TO_DEV(serv_mgt);
	struct nbl_ch_prm_set_rxfh_rss_key key_prm;
	struct nbl_ch_prm_set_rxfh_rss_alg_sel alg_prm = {0};
	u32 rxfh_indir_size = 0;
	int ret = 0;

	memset(&key_prm, 0, sizeof(key_prm));
	if (indir && (netdev->features & NETIF_F_RXHASH)) {
		disp_ops->get_rxfh_indir_size(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					&NBL_COMMON_TO_VSI_ID(common), &rxfh_indir_size);
		ret = disp_ops->set_rxfh_indir(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					       NBL_COMMON_TO_VSI_ID(common),
					       indir, rxfh_indir_size);
		if (ret) {
			netdev_err(netdev, "set RSS indirection table failed %d\n", ret);
			return ret;
		}
		if (!ring_mgt->rss_indir_user) {
			ring_mgt->rss_indir_user = devm_kcalloc(dev, rxfh_indir_size,
								sizeof(u32), GFP_KERNEL);
			if (!ring_mgt->rss_indir_user)
				return -ENOMEM;
		}
		memcpy(ring_mgt->rss_indir_user, indir, rxfh_indir_size * sizeof(u32));
	}
	if (key) {
		if (disp_ops->get_product_fix_cap(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						  &cap_type)) {
			key_prm.vsi_id = NBL_COMMON_TO_VSI_ID(common);
			memcpy(key_prm.rss_key, key, NBL_EPRO_RSS_SK_SIZE);
			ret = disp_ops->set_rxfh_rss_key(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
							 &key_prm);
			if (ret) {
				netdev_err(netdev, "set RSS hash key failed %d\n", ret);
				return ret;
			}
		} else {
			netdev_err(netdev, "rss key donot support modify\n");
			return -EOPNOTSUPP;
		}
	}
	if (hfunc) {
		alg_prm.vsi_id = NBL_COMMON_TO_VSI_ID(common);
		alg_prm.rss_alg_sel = hfunc;
		ret = disp_ops->set_rxfh_rss_alg_sel(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &alg_prm);
		if (ret) {
			netdev_err(netdev, "set RSS hash function failed %d\n", ret);
			return ret;
		}
	}
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
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info;
	u16 local_vector_id, configured_usecs;
	struct nbl_ch_prm_get_coalesce coalesce_param = {0};
	struct nbl_ch_prm_get_coalesce_req coalesce_req = {0};

	vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];

	if (q_num >= vsi_info->ring_offset + vsi_info->ring_num) {
		netdev_err(netdev, "q_num %d is too larger\n", q_num);
		return -EINVAL;
	}

	local_vector_id = ring_mgt->vectors[q_num + vsi_info->ring_offset].local_vector_id;
	configured_usecs = ring_mgt->vectors[q_num + vsi_info->ring_offset].intr_rate_usecs;
	coalesce_req.vector_id = local_vector_id;
	coalesce_req.sfid = NBL_COMMON_TO_MGT_PF(common);
	disp_ops->get_coalesce(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
			       &coalesce_req, &coalesce_param);

	NBL_SET_INTR_COALESCE(ec, coalesce_param.tx_coalesce_usecs,
			      coalesce_param.tx_max_coalesced_frames,
			      coalesce_param.rx_coalesce_usecs,
			      coalesce_param.rx_max_coalesced_frames);

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
	enum nbl_fix_cap_type cap_type = NBL_MSIX_FAST_RESTRAIN_CAP;
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info;
	struct nbl_serv_vector *vector;
	struct ethtool_coalesce ec_local = {0};
	bool support_msix_fast_restrain;
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
	support_msix_fast_restrain =
				disp_ops->get_product_fix_cap(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
							      &cap_type);
	if (support_msix_fast_restrain) {
		struct nbl_set_msix_fast_restrain_param restrain_prm = {0};

		vector = &ring_mgt->vectors[q_num];
		restrain_prm.global_vector_id = vector->global_vector_id;
		restrain_prm.pnum = pnum;
		restrain_prm.rate = rate;
		disp_ops->set_msix_fast_restrain(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						 &restrain_prm);
	} else {
		struct nbl_ch_prm_set_coalesce coalesce_prm = {0};

		coalesce_prm.sfid = NBL_COMMON_TO_MGT_PF(common);
		coalesce_prm.local_vector_id = local_vector_id;
		coalesce_prm.vector_num = 1;
		coalesce_prm.rx_max_coalesced_frames = pnum;
		coalesce_prm.rx_coalesce_usecs = rate;
		disp_ops->set_coalesce(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &coalesce_prm);
	}
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
	enum nbl_fix_cap_type cap_type = NBL_MSIX_FAST_RESTRAIN_CAP;
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_serv_ring_mgt *ring_mgt = NBL_SERV_MGT_TO_RING_MGT(serv_mgt);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_serv_ring_vsi_info *vsi_info;
	struct ethtool_coalesce ec_local = {0};
	bool support_msix_fast_restrain;
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

	support_msix_fast_restrain =
				disp_ops->get_product_fix_cap(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
							      &cap_type);
	if (ec->use_adaptive_rx_coalesce) {
		vsi_info->itr_dynamic = true;
		local_vector_id = ring_mgt->vectors[vsi_info->ring_offset].local_vector_id;
		intr_suppress_level = ring_mgt->vectors->intr_suppress_level;
		if (!support_msix_fast_restrain) {
			struct nbl_ch_prm_set_intr_suppress_level suppress_prm = {0};

			suppress_prm.sfid = NBL_COMMON_TO_MGT_PF(common);
			suppress_prm.local_vector_id = local_vector_id;
			suppress_prm.vector_num = vsi_info->ring_num;
			suppress_prm.level = intr_suppress_level;
			disp_ops->set_intr_suppress_level(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
							  &suppress_prm);
		} else {
			nbl_intr_set_suppress_level(serv_mgt, vsi_info, intr_suppress_level);
		}
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

static void nbl_loopback_create_skb(struct net_device *netdev, struct sk_buff *skb, u32 size)
{
	struct ethhdr *eth_hdr;

	if (!skb)
		return;

	get_random_bytes(skb->data, size);
	ether_addr_copy(skb->data, netdev->dev_addr);
	eth_hdr = (struct ethhdr *)skb->data;
	eth_hdr->h_proto = cpu_to_be16(ETH_P_ARP);
	size >>= 1;
	memset(&skb->data[size], NBL_SELF_TEST_PADDING_DATA_2, size);
	skb->data[size + NBL_SELF_TEST_POS_2] = NBL_SELF_TEST_BYTE_1;
	skb->data[size + NBL_SELF_TEST_POS_3] = NBL_SELF_TEST_BYTE_2;
}

static s32 nbl_loopback_check_skb(struct net_device *netdev, struct sk_buff *skb_tx,
				  struct sk_buff *skb_rx, u32 size)
{
	if (!skb_tx || !skb_rx) {
		netdev_err(netdev, "Skb is NULL.");
		goto err_return;
	}
	if (skb_tx->len != skb_rx->len || skb_tx->len != size) {
		netdev_err(netdev, "Skb len mismatch, tx len %u, rx len %u, size %u.",
			   skb_tx->len, skb_rx->len, size);
		goto err_return;
	}
	if (skb_is_nonlinear(skb_tx) || skb_is_nonlinear(skb_rx)) {
		netdev_err(netdev, "Skb is error, tx len %u, tx data len %u, rx len %u, rx data len %u.",
			   skb_tx->len, skb_tx->data_len, skb_rx->len, skb_rx->data_len);
		goto err_return;
	}
	if (memcmp(skb_tx->data, skb_rx->data, size)) {
		netdev_err(netdev, "Skb data mismatch.");
		goto err_return;
	}

	return 0;

err_return:
	if (skb_tx)
		skb_dump("loop-test-tx:", skb_tx, true);
	if (skb_rx)
		skb_dump("loop-test-rx:", skb_rx, true);
	return -1;
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
	u32 ring_index = 0;
	s32 result = 0;
	int i;

	for (i = 0; i < NBL_SELF_TEST_PKT_NUM; i++) {
		skb_tx[i] = alloc_skb(size, GFP_KERNEL);
		if (!skb_tx[i])
			goto alloc_skb_faied;

		nbl_loopback_create_skb(netdev, skb_tx[i], size);
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

	msleep(1000);

	for (i = 0; i < tx_count; i++) {
		skb_rx = NULL;
		skb_rx = disp_ops->clean_rx_lb_test(NBL_ADAPTER_TO_DISP_MGT(adapter),
						    &ring_index);
		if (!skb_rx) {
			netdev_err(netdev, "Fail to rx lb skb, should rx %d but fail on %d",
				   tx_count, i);
			break;
		}
		if (nbl_loopback_check_skb(netdev, skb_tx[i], skb_rx, size)) {
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
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct device *dev = NBL_SERV_MGT_TO_DEV(serv_mgt);
	struct nbl_serv_ring_mgt *ring_mgt = &serv_mgt->ring_mgt;
	struct nbl_dispatch_ops *disp_ops = NBL_ADAPTER_TO_DISP_OPS_TBL(adapter)->ops;
	struct nbl_serv_ring_vsi_info *vsi_info = &ring_mgt->vsi_info[NBL_VSI_DATA];
	struct nbl_ch_prm_set_eth_loopback lb_prm = {0};
	u16 origin_num_txq, origin_num_rxq, origin_active_q;
	u64 result = 0;
	u32 rxfh_indir_size = 0;
	u32 *indir = NULL;
	int i = 0;

	/* In loopback test, we only need one queue */
	origin_num_txq = ring_mgt->tx_ring_num;
	origin_num_rxq = ring_mgt->rx_ring_num;
	origin_active_q = vsi_info->active_ring_num;
	ring_mgt->tx_ring_num = NBL_SELF_TEST_Q_NUM;
	ring_mgt->rx_ring_num = NBL_SELF_TEST_Q_NUM;

	disp_ops->get_rxfh_indir_size(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					&NBL_COMMON_TO_VSI_ID(common), &rxfh_indir_size);
	indir = devm_kcalloc(dev, rxfh_indir_size, sizeof(u32), GFP_KERNEL);
	if (!indir)
		return -ENOMEM;
	for (i = 0; i < rxfh_indir_size; i++)
		indir[i] = i % NBL_SELF_TEST_Q_NUM;
	disp_ops->set_rxfh_indir(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				 NBL_COMMON_TO_VSI_ID(common), indir, rxfh_indir_size);

	if (nbl_loopback_setup_rings(adapter, netdev)) {
		netdev_err(netdev, "Fail to setup rings");
		result |= BIT(NBL_LB_ERR_RING_SETUP);
		goto lb_setup_rings_failed;
	}

	lb_prm.eth_port_id = common->eth_id;
	lb_prm.enable = NBL_ETH_LB_ON;
	if (disp_ops->set_eth_loopback(NBL_ADAPTER_TO_DISP_MGT(adapter), &lb_prm)) {
		netdev_err(netdev, "Fail to setup lb on");
		result |= BIT(NBL_LB_ERR_LB_MODE_SETUP);
		goto set_eth_lb_failed;
	}

	result |= nbl_loopback_run_test(netdev);

	lb_prm.enable = NBL_ETH_LB_OFF;
	if (disp_ops->set_eth_loopback(NBL_ADAPTER_TO_DISP_MGT(adapter), &lb_prm)) {
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

	if (ring_mgt->rss_indir_user) {
		memcpy(indir, ring_mgt->rss_indir_user, rxfh_indir_size * sizeof(u32));
	} else {
		for (i = 0; i < rxfh_indir_size; i++)
			indir[i] = i % vsi_info->active_ring_num;
	}
	disp_ops->set_rxfh_indir(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				 NBL_COMMON_TO_VSI_ID(common), indir, rxfh_indir_size);
	devm_kfree(dev, indir);

	return result;
}

static u32 nbl_mailbox_check_active_vf(struct nbl_adapter *adapter)
{
	struct nbl_dispatch_ops_tbl *disp_ops_tbl = NBL_ADAPTER_TO_DISP_OPS_TBL(adapter);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	u16 pf_id = NBL_COMMON_TO_MGT_PF(common);

	return disp_ops_tbl->ops->check_active_vf(NBL_ADAPTER_TO_DISP_MGT(adapter), &pf_id);
}

static void nbl_self_test(struct net_device *netdev, struct ethtool_test *eth_test, u64 *data)
{
	struct nbl_netdev_priv *priv = netdev_priv(netdev);
	struct nbl_adapter *adapter = NBL_NETDEV_PRIV_TO_ADAPTER(priv);
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	bool if_running = netif_running(netdev);
	u32 active_vf;
	s64 cur_time = 0;
	int ret;

	cur_time = ktime_get_real_seconds();

	/* test too frequently will cause to fail */
	if (cur_time - net_resource_mgt->last_st_time < NBL_SELF_TEST_TIME_GAP) {
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
	net_resource_mgt->last_st_time = ktime_get_real_seconds();
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
							   &capability_type))
				continue;
		}

		if (test_bit(i, &serv_mgt->flags))
			ret_flags |= BIT(count);
		count++;
	}

	netdev_dbg(netdev, "get priv flag: 0x%08x, mgt flags: 0x%08lx.\n",
		   ret_flags, serv_mgt->flags);

	return ret_flags;
}

static int nbl_set_priv_flags(struct net_device *netdev, u32 priv_flags)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	unsigned int i;
	int count = 0;
	unsigned long new_flags = 0;
	bool flag_set;

	for (i = 0; i < NBL_PRIV_FLAG_ARRAY_SIZE; i++) {
		enum nbl_fix_cap_type capability_type = nbl_gstrings_priv_flags[i].capability_type;

		if (nbl_gstrings_priv_flags[i].supported_by_capability) {
			if (!disp_ops->get_product_fix_cap(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
							   &capability_type))
				continue;
		}

		if (!nbl_gstrings_priv_flags[i].supported_modify &&
		    (!((priv_flags & BIT(count))) != !test_bit(i, &serv_mgt->flags))) {
			netdev_err(netdev, "set priv flag: 0x%08x, flag %s not support modify\n",
				   priv_flags, nbl_gstrings_priv_flags[i].flag_name);
			return -EOPNOTSUPP;
		}

		flag_set = false;
		if (priv_flags & BIT(count)) {
			flag_set = true;
			new_flags |= BIT(i);
		}

		if ((serv_mgt->flags & BIT(i)) ^ (new_flags & BIT(i))) {
			serv_mgt->flags = (serv_mgt->flags & ~BIT(i)) | (new_flags & BIT(i));
			if (nbl_gstrings_priv_flags[i].post_func)
				nbl_gstrings_priv_flags[i].post_func(netdev, flag_set);
		}

		count++;
	}

	netdev_dbg(netdev, "set priv flag: 0x%08x, mgt flags: 0x%08lx.\n",
		   priv_flags, serv_mgt->flags);
	return 0;
}

static int nbl_set_pause_param(struct net_device *netdev, struct ethtool_pauseparam *param)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_serv_net_resource_mgt *net_resource_mgt;
	struct nbl_dispatch_ops *disp_ops;
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
	phy_caps = &net_resource_mgt->phy_caps;

	ret = nbl_serv_get_port_state(serv_mgt, &port_state);
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
	struct nbl_port_state port_state = {0};
	int ret = 0;

	ret = nbl_serv_get_port_state(serv_mgt, &port_state);
	if (ret) {
		netdev_err(netdev, "Get port_state failed %d\n", ret);
		return;
	}

	param->autoneg = AUTONEG_DISABLE;
	param->rx_pause = !!(port_state.active_fc & NBL_PORT_RX_PAUSE);
	param->tx_pause = !!(port_state.active_fc & NBL_PORT_TX_PAUSE);
}

static void nbl_get_eth_ctrl_stats(struct net_device *netdev,
				   struct ethtool_eth_ctrl_stats *eth_ctrl_stats)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_eth_ctrl_stats eth_ctrl_stats_info = {0};
	struct nbl_dispatch_ops *disp_ops;
	u32 eth_id = common->eth_id;
	int ret = 0;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	ret = disp_ops->get_eth_ctrl_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					   &eth_id, &eth_ctrl_stats_info);
	if (ret) {
		netdev_err(netdev, "Get eth_ctrl_stats failed %d\n", ret);
		return;
	}

	eth_ctrl_stats->MACControlFramesTransmitted =
				eth_ctrl_stats_info.macctrl_frames_txd_ok;
	eth_ctrl_stats->MACControlFramesReceived = eth_ctrl_stats_info.macctrl_frames_rxd;
	eth_ctrl_stats->UnsupportedOpcodesReceived =
				eth_ctrl_stats_info.unsupported_opcodes_rx;
}

static void nbl_get_pause_stats(struct net_device *netdev, struct ethtool_pause_stats *pause_stats)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_pause_stats pause_stats_info = {0};
	struct nbl_dispatch_ops *disp_ops;
	u32 eth_id = common->eth_id;
	int ret = 0;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	ret = disp_ops->get_pause_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					&eth_id, &pause_stats_info);
	if (ret) {
		netdev_err(netdev, "Get pause_stats failed %d\n", ret);
		return;
	}

	pause_stats->rx_pause_frames = pause_stats_info.rx_pause_frames;
	pause_stats->tx_pause_frames = pause_stats_info.tx_pause_frames;
}

static void nbl_get_eth_mac_stats(struct net_device *netdev,
				  struct ethtool_eth_mac_stats *eth_mac_stats)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_eth_mac_stats eth_mac_stats_info = {0};
	struct nbl_dispatch_ops *disp_ops;
	u32 eth_id = common->eth_id;
	int ret = 0;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	ret = disp_ops->get_eth_mac_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					  &eth_id, &eth_mac_stats_info);
	if (ret) {
		netdev_err(netdev, "Get eth_mac_stats failed %d\n", ret);
		return;
	}

	eth_mac_stats->FramesTransmittedOK = eth_mac_stats_info.frames_txd_ok;
	if (eth_mac_stats_info.frames_rxd_ok_is_valid)
		eth_mac_stats->FramesReceivedOK = eth_mac_stats_info.frames_rxd_ok;
	if (eth_mac_stats_info.octets_txd_ok_is_valid)
		eth_mac_stats->OctetsTransmittedOK = eth_mac_stats_info.octets_txd_ok;
	if (eth_mac_stats_info.octets_rxd_ok_is_valid)
		eth_mac_stats->OctetsReceivedOK = eth_mac_stats_info.octets_rxd_ok;
	eth_mac_stats->MulticastFramesXmittedOK = eth_mac_stats_info.multicast_frames_txd_ok;
	eth_mac_stats->BroadcastFramesXmittedOK = eth_mac_stats_info.broadcast_frames_txd_ok;
	eth_mac_stats->MulticastFramesReceivedOK = eth_mac_stats_info.multicast_frames_rxd_ok;
	eth_mac_stats->BroadcastFramesReceivedOK = eth_mac_stats_info.broadcast_frames_rxd_ok;
}

static void nbl_get_rmon_stats(struct net_device *netdev,
			       struct ethtool_rmon_stats *rmon_stats,
			       const struct ethtool_rmon_hist_range **range)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_rmon_stats rmon_stats_info = {0};
	struct nbl_dispatch_ops *disp_ops;
	const struct ethtool_rmon_hist_range *rmon_ranges = NULL;
	u64 *rx = rmon_stats_info.rmon_rx_range;
	u64 *tx = rmon_stats_info.rmon_tx_range;
	u32 eth_id = common->eth_id;
	u8 i = 0;
	u8 eth_stats_pkts_max = 0;
	int ret = 0;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	ret = disp_ops->get_rmon_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					  &eth_id, &rmon_stats_info);
	if (ret) {
		netdev_err(netdev, "Get eth_mac_stats failed %d\n", ret);
		return;
	}

	rmon_stats->undersize_pkts = rmon_stats_info.undersize_frames_rxd_goodfcs;
	rmon_stats->oversize_pkts = rmon_stats_info.oversize_frames_rxd_goodfcs;
	rmon_stats->fragments = rmon_stats_info.undersize_frames_rxd_badfcs;
	rmon_stats->jabbers = rmon_stats_info.oversize_frames_rxd_badfcs;

	if (rmon_stats_info.rmon_rx_range2048_is_valid)
		eth_stats_pkts_max = ETHER_STATS_PKTS_2048_TO_MAX_OCTETS;
	else
		eth_stats_pkts_max = ETHER_STATS_PKTS_1024_TO_MAX_OCTETS;

	for (i = ETHER_STATS_PKTS_64_OCTETS; i <= eth_stats_pkts_max; i++) {
		rmon_stats->hist[i] = rx[i];
		rmon_stats->hist_tx[i] = tx[i];
	}

	disp_ops->get_rmon_hist_range(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &rmon_ranges);
	*range = rmon_ranges;
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

	ret = nbl_serv_get_port_state(serv_mgt, &port_state);
	if (ret) {
		netdev_err(netdev, "Get port_state failed %d\n", ret);
		return -EIO;
	}

	if (!port_state.module_inplace) {
		netdev_err(netdev, "Optical module is not inplace\n");
		return -EINVAL;
	}

	if (port_state.port_advertising & BIT(NBL_PORT_CAP_AUTONEG)) {
		netdev_err(netdev, "unsupport to set fec mode when autoneg\n");
		return -EOPNOTSUPP;
	}

	autoneg = ((port_state.port_advertising & BIT(NBL_PORT_CAP_AUTONEG)) ||
		   (port_state.port_caps & BIT_ULL(NBL_PORT_CAP_FEC_AUTONEG))) ?
		   AUTONEG_ENABLE : AUTONEG_DISABLE;

	/* check if the fec mode is supported */
	if (fec_mode == ETHTOOL_FEC_OFF) {
		active_fec = NBL_PORT_FEC_OFF;
		if (!(port_state.port_caps & BIT(NBL_PORT_CAP_FEC_OFF))) {
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

	if (net_resource_mgt->configured_fec == fec_mode) {
		net_resource_mgt->user_configured_fec = fec_mode;
		netdev_err(netdev, "fec mode is not changed\n");
		return 0;
	}

	if (fec_mode == ETHTOOL_FEC_RS) {
		if ((port_state.link_speed == SPEED_10000 && port_state.link_state) ||
		    net_resource_mgt->configured_speed == SPEED_10000) {
			netdev_err(netdev, "speed 10G cannot set fec RS, only can set fec baseR\n");
			return -EINVAL;
		}
	}

	if (test_bit(NBL_FLAG_NRZ_RS_FEC_544_SUPPORT, &serv_mgt->flags))
		port_advertising.fec_sub_mode = NBL_PORT_NRZ_544;

	port_advertising.eth_id = NBL_COMMON_TO_ETH_ID(serv_mgt->common);
	port_advertising.active_fec = active_fec;
	port_advertising.autoneg = (port_state.port_advertising & BIT(NBL_PORT_CAP_AUTONEG)) ?
		   AUTONEG_ENABLE : AUTONEG_DISABLE;

	/* update fec mode */
	ret = disp_ops->set_port_advertising(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					     &port_advertising);
	if (ret) {
		netdev_err(netdev, "fec mode set failed %d\n", ret);
		return ret;
	}

	net_resource_mgt->configured_fec = fec_mode;
	net_resource_mgt->user_configured_fec = fec_mode;

	return 0;
}

static int nbl_get_fec_param(struct net_device *netdev, struct ethtool_fecparam *fecparam)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = NBL_SERV_MGT_TO_NET_RES_MGT(serv_mgt);
	struct nbl_port_state port_state = {0};
	u32 fec = 0;
	u32 active_fec = 0;
	u8 fec_autoneg = 0;
	int ret = 0;

	ret = nbl_serv_get_port_state(serv_mgt, &port_state);
	if (ret) {
		netdev_err(netdev, "Get port_state failed %d\n", ret);
		return -EIO;
	}

	if (!port_state.module_inplace) {
		netdev_err(netdev, "Optical module is not inplace\n");
		return -EINVAL;
	}

	fec_autoneg = (port_state.port_advertising & BIT_ULL(NBL_PORT_CAP_FEC_AUTONEG)) &&
		       (port_state.port_caps & BIT_ULL(NBL_PORT_CAP_FEC_AUTONEG));

	if (port_state.active_fec == NBL_PORT_FEC_OFF)
		active_fec = ETHTOOL_FEC_OFF;
	if (port_state.active_fec ==  NBL_PORT_FEC_RS)
		active_fec = ETHTOOL_FEC_RS;
	if (port_state.active_fec ==  NBL_PORT_FEC_BASER)
		active_fec = ETHTOOL_FEC_BASER;

	if (net_resource_mgt->user_configured_fec)
		fec = net_resource_mgt->user_configured_fec;
	else if (fec_autoneg)
		fec = ETHTOOL_FEC_AUTO;
	else
		fec = active_fec;

	fecparam->fec = fec;
	fecparam->active_fec = active_fec;

	return 0;
}

static void nbl_get_fec_stats(struct net_device *netdev, struct ethtool_fec_stats *fec_stats)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_fec_stats fec_stats_info = {0};
	unsigned int i;
	int ret;

	ret = disp_ops->get_fec_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				      NBL_COMMON_TO_ETH_ID(serv_mgt->common), &fec_stats_info);
	if (ret) {
		netdev_err(netdev, "Get fec state failed %d\n", ret);
		return;
	}
	fec_stats->corrected_blocks.total = fec_stats_info.corrected_blocks;
	fec_stats->uncorrectable_blocks.total = fec_stats_info.uncorrectable_blocks;
	fec_stats->corrected_bits.total = fec_stats_info.corrected_bits;

	for (i = 0; i < NBL_LEONIS_LANE_NUM; i++) {
		fec_stats->corrected_blocks.lanes[i] = fec_stats_info.corrected_lane[i];
		fec_stats->uncorrectable_blocks.lanes[i] = fec_stats_info.uncorrectable_lane[i];
		fec_stats->corrected_bits.lanes[i] = fec_stats_info.corrected_bits_lane[i];
	}
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

	ret = nbl_serv_get_port_state(serv_mgt, &port_state);
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

static void nbl_rep_stats_fill_strings(struct net_device *netdev, u8 *data)
{
	char *p = (char *)data;

	snprintf(p, ETH_GSTRING_LEN, "tx_packets");
	p += ETH_GSTRING_LEN;
	snprintf(p, ETH_GSTRING_LEN, "tx_bytes");
	p += ETH_GSTRING_LEN;
	snprintf(p, ETH_GSTRING_LEN, "rx_packets");
	p += ETH_GSTRING_LEN;
	snprintf(p, ETH_GSTRING_LEN, "rx_bytes");
	p += ETH_GSTRING_LEN;
	snprintf(p, ETH_GSTRING_LEN, "tx_dropped");
	p += ETH_GSTRING_LEN;
	snprintf(p, ETH_GSTRING_LEN, "rx_dropped");
	p += ETH_GSTRING_LEN;
}

static void nbl_rep_get_strings(struct net_device *netdev, u32 stringset, u8 *data)
{
	if (stringset == ETH_SS_STATS)
		nbl_rep_stats_fill_strings(netdev, data);
}

static int nbl_rep_get_sset_count(struct net_device *netdev, int sset)
{
	u32 total_queues = 0;

	if (sset == ETH_SS_STATS) {
		total_queues = NBL_REP_PER_VSI_QUEUE_NUM * 2;
		return total_queues * (sizeof(struct nbl_rep_stats) / sizeof(u64));
	} else {
		return -EOPNOTSUPP;
	}
}

static void
nbl_rep_get_ethtool_stats(struct net_device *netdev, struct ethtool_stats *stats, u64 *data)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_netdev_priv *priv = netdev_priv(netdev);
	struct nbl_rep_stats rep_stats = {0};
	struct nbl_get_rep_stats_param rep_stats_prm = {0};
	int i = 0;

	rep_stats_prm.rep_vsi_id = priv->rep->rep_vsi_id;
	rep_stats_prm.is_tx = true;
	disp_ops->get_rep_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &rep_stats_prm, &rep_stats);
	data[i++] = rep_stats.packets;
	data[i++] = rep_stats.bytes;
	rep_stats_prm.is_tx = false;
	disp_ops->get_rep_stats(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &rep_stats_prm, &rep_stats);
	data[i++] = rep_stats.packets;
	data[i++] = rep_stats.bytes;
	nbl_serv_get_rep_drop_stats(serv_mgt, priv->rep->rep_vsi_id, &rep_stats);
	data[i] = rep_stats.dropped;
}

static int nbl_flash_device(struct net_device *netdev, struct ethtool_flash *flash)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	const struct firmware *fw;
	int ret = 0;

	if (flash->region != ETHTOOL_FLASH_ALL_REGIONS)
		return -EOPNOTSUPP;

	if (!adapter->init_param.caps.has_ctrl)
		return -EOPNOTSUPP;

	ret = request_firmware_direct(&fw, flash->data, &netdev->dev);
	if (ret)
		return ret;

	dev_hold(netdev);
	rtnl_unlock();

	ret = nbl_serv_update_firmware(serv_mgt, fw, NULL);
	release_firmware(fw);

	rtnl_lock();
	dev_put(netdev);

	return ret;
}

static int nbl_diag_fill_device_name(struct nbl_service_mgt *serv_mgt, void *buff)
{
	struct nbl_common_info *info = serv_mgt->common;
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;

	snprintf(buff, NBL_DEV_NAME_SZ, "%s:%s", pci_name(info->pdev),
		 net_resource_mgt->netdev->name);

	return NBL_DEV_NAME_SZ;
}

static int nbl_get_dump_flag(struct net_device *netdev, struct ethtool_dump *dump)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	u32 extra_len = 0;

	if (!adapter->init_param.caps.has_ctrl)
		return -EOPNOTSUPP;

	dump->version = NBL_DIAG_DUMP_VERSION;
	dump->flag = serv_mgt->net_resource_mgt->dump_flag;

	if (dump->flag & NBL_DIAG_FLAG_PERFORMANCE) {
		u32 length = disp_ops->get_perf_dump_length(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));

		serv_mgt->net_resource_mgt->dump_perf_len = length;
		extra_len += length ? DIAG_BLK_SZ(length) : 0;
	}

	dump->len = sizeof(struct nbl_diag_dump) + DIAG_BLK_SZ(NBL_DRV_VER_SZ) +
		    DIAG_BLK_SZ(NBL_DEV_NAME_SZ) + extra_len;

	return 0;
}

static int nbl_get_dump_data(struct net_device *netdev, struct ethtool_dump *dump, void *buffer)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_serv_net_resource_mgt *net_resource_mgt = serv_mgt->net_resource_mgt;
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_diag_dump *dump_hdr = buffer;
	struct nbl_ch_prm_get_perf_dump_data param;
	struct nbl_diag_blk *dump_blk;

	if (!adapter->init_param.caps.has_ctrl)
		return -EOPNOTSUPP;

	memset(buffer, 0, dump->len);
	dump_hdr->version = NBL_DIAG_DUMP_VERSION;
	dump_hdr->flag = 0;
	dump_hdr->num_blocks = 0;
	dump_hdr->total_length = 0;

	/* Dump driver version */
	dump_blk = DIAG_GET_NEXT_BLK(dump_hdr);
	dump_blk->type = NBL_DIAG_DRV_VERSION;
	snprintf(dump_blk->data, NBL_DRV_VER_SZ, "%s", NBL_DRIVER_VERSION);
	dump_blk->length = NBL_DRV_VER_SZ;
	dump_hdr->total_length += DIAG_BLK_SZ(dump_blk->length);
	dump_hdr->num_blocks++;

	/* Dump device name */
	dump_blk = DIAG_GET_NEXT_BLK(dump_hdr);
	dump_blk->type = NBL_DIAG_DEVICE_NAME;
	dump_blk->length = nbl_diag_fill_device_name(serv_mgt, &dump_blk->data);
	dump_hdr->total_length += DIAG_BLK_SZ(dump_blk->length);
	dump_hdr->num_blocks++;

	/* Dump performance registers */
	if (net_resource_mgt->dump_flag & NBL_DIAG_FLAG_PERFORMANCE) {
		dump_blk = DIAG_GET_NEXT_BLK(dump_hdr);
		dump_blk->type = NBL_DIAG_PERFORMANCE;
		param.buffer = dump_blk->data;
		param.size = net_resource_mgt->dump_perf_len;
		dump_blk->length = disp_ops->get_perf_dump_data(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
								&param);
		dump_hdr->total_length += DIAG_BLK_SZ(dump_blk->length);
		dump_hdr->num_blocks++;
		dump_hdr->flag |= NBL_DIAG_FLAG_PERFORMANCE;
	}

	return 0;
}

static int nbl_set_dump(struct net_device *netdev, struct ethtool_dump *dump)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);

	if (!adapter->init_param.caps.has_ctrl)
		return -EOPNOTSUPP;

	serv_mgt->net_resource_mgt->dump_flag = dump->flag;

	return 0;
}

static void nbl_get_wol(struct net_device *netdev, struct ethtool_wolinfo *wol)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);

	if (adapter->init_param.caps.is_ocp) {
		wol->supported = WAKE_MAGIC;
		wol->wolopts = common->wol_ena ? WAKE_MAGIC : 0;
	} else {
		wol->supported = 0;
		wol->wolopts = 0;
	}
}

static int nbl_set_wol(struct net_device *netdev, struct ethtool_wolinfo *wol)
{
	struct nbl_adapter *adapter = NBL_NETDEV_TO_ADAPTER(netdev);
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);

	if (!adapter->init_param.caps.is_ocp)
		return -EOPNOTSUPP;

	if (wol->wolopts && wol->wolopts != WAKE_MAGIC)
		return -EOPNOTSUPP;

	if (common->wol_ena != !!wol->wolopts) {
		common->wol_ena = !!wol->wolopts;
		device_set_wakeup_enable(&common->pdev->dev, common->wol_ena);
		netdev_dbg(netdev, "Wol magic packet %sabled", common->wol_ena ? "en" : "dis");
	}

	return 0;
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
	NBL_SERV_SET_ETHTOOL_OPS(get_module_eeprom_by_page, nbl_get_module_eeprom_by_page);	\
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
	NBL_SERV_SET_ETHTOOL_OPS(set_rxnfc, nbl_set_rxnfc);					\
	NBL_SERV_SET_ETHTOOL_OPS(get_rxfh_indir_size, nbl_get_rxfh_indir_size);			\
	NBL_SERV_SET_ETHTOOL_OPS(get_rxfh_key_size, nbl_get_rxfh_key_size);			\
	NBL_SERV_SET_ETHTOOL_OPS(get_rxfh, nbl_get_rxfh);					\
	NBL_SERV_SET_ETHTOOL_OPS(set_rxfh, nbl_set_rxfh);					\
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
	NBL_SERV_SET_ETHTOOL_OPS(get_rep_strings, nbl_rep_get_strings);				\
	NBL_SERV_SET_ETHTOOL_OPS(get_rep_sset_count, nbl_rep_get_sset_count);			\
	NBL_SERV_SET_ETHTOOL_OPS(get_rep_ethtool_stats, nbl_rep_get_ethtool_stats);		\
	NBL_SERV_SET_ETHTOOL_OPS(flash_device, nbl_flash_device);				\
	NBL_SERV_SET_ETHTOOL_OPS(get_dump_flag, nbl_get_dump_flag);				\
	NBL_SERV_SET_ETHTOOL_OPS(get_dump_data, nbl_get_dump_data);				\
	NBL_SERV_SET_ETHTOOL_OPS(set_dump, nbl_set_dump);					\
	NBL_SERV_SET_ETHTOOL_OPS(set_wol, nbl_set_wol);						\
	NBL_SERV_SET_ETHTOOL_OPS(get_wol, nbl_get_wol);						\
} while (0)

void nbl_serv_setup_ethtool_ops(struct nbl_service_ops *serv_ops)
{
#define NBL_SERV_SET_ETHTOOL_OPS(name, func) do {serv_ops->NBL_NAME(name) = func; ; } while (0)
	NBL_SERV_ETHTOOL_OPS_TBL;
#undef  NBL_SERV_SET_ETHTOOL_OPS

	serv_ops->get_eth_ctrl_stats = nbl_get_eth_ctrl_stats;
	serv_ops->get_pause_stats = nbl_get_pause_stats;
	serv_ops->get_eth_mac_stats = nbl_get_eth_mac_stats;
	serv_ops->get_fec_stats = nbl_get_fec_stats;
	serv_ops->get_link_ext_state = nbl_get_link_ext_state;
	serv_ops->get_link_ext_stats = nbl_get_link_ext_stats;
	serv_ops->get_rmon_stats = nbl_get_rmon_stats;
}
