// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <net/page_pool/types.h>
#include <linux/debugfs.h>
#include <linux/time.h>
#include <ub/ubase/ubase_comm_cmd.h>
#include <ub/ubase/ubase_comm_mbx.h>

#include "unic_ctx_debugfs.h"
#include "unic_dev.h"
#include "unic_hw.h"
#include "unic_qos_debugfs.h"
#include "unic_entry_debugfs.h"
#include "unic_debugfs.h"

static int unic_dbg_dump_dev_info(struct seq_file *s, void *data)
{
	struct unic_dev *unic_dev = dev_get_drvdata(s->private);
	struct net_device *netdev = unic_dev->comdev.netdev;
	u16 max_frame_size;
	int ret;

	seq_printf(s, "%-25s", "DEV_NAME:");
	seq_printf(s, "%-12s\n", netdev->name);

	if (!unic_dev_ubl_supported(unic_dev)) {
		ret = unic_check_validate_dump_mtu(unic_dev, netdev->mtu,
						   &max_frame_size);
		if (!ret) {
			seq_printf(s, "%-25s", "MAX_FRAME_SIZE:");
			seq_printf(s, "%-12u\n", max_frame_size);
		}
	}

	return 0;
}

static int unic_dbg_dump_vport_buf(struct seq_file *s, void *data)
{
	struct unic_dev *unic_dev = dev_get_drvdata(s->private);

	seq_printf(s, "vport buffer num: %u\n", unic_dev->caps.vport_buf_num);
	seq_printf(s, "vport buffer size: %u\n", unic_dev->caps.vport_buf_size);
	return 0;
}

static void unic_dbg_fill_vport_ctx_content(struct unic_vport_ctx_cmd *resp,
					    struct seq_file *s)
{
	u32 i, j;

	for (i = 0; i < UNIC_VORT_CTX_DATA_NUM; i += UNIC_VORT_CTX_DATA_ALIGN) {
		seq_printf(s, "%08X: ", i * UNIC_VORT_CTX_DATA_ALIGN);
		for (j = 0; j < UNIC_VORT_CTX_DATA_ALIGN; j++) {
			if ((i + j) == UNIC_VORT_CTX_DATA_NUM)
				break;
			seq_printf(s, "%08X ", resp->data[i + j]);
		}
		seq_puts(s, "\n");
	}
}

static int unic_dbg_query_vport_ctx(struct seq_file *s)
{
	struct unic_dev *unic_dev = dev_get_drvdata(s->private);
	struct unic_vport_ctx_cmd resp;
	u16 offset = 0;
	int ret;

	do {
		memset(&resp, 0, sizeof(resp));
		ret = unic_query_vport_ctx(unic_dev, offset, &resp);
		if (ret)
			return ret;
		offset = resp.offset;

		unic_dbg_fill_vport_ctx_content(&resp, s);
	} while (resp.offset);

	return 0;
}

static int unic_dbg_dump_vport_ctx(struct seq_file *s, void *data)
{
	struct unic_dev *unic_dev = dev_get_drvdata(s->private);

	if (__unic_resetting(unic_dev))
		return -EBUSY;

	return unic_dbg_query_vport_ctx(s);
}

static const struct unic_dbg_cap_bit_info {
	const char *format;
	bool (*get_bit)(struct unic_dev *dev);
} unic_cap_bits[] = {
	{"\tsupport_ubl: %u\n", unic_dev_ubl_supported},
	{"\tsupport_pfc: %u\n", unic_dev_pfc_supported},
	{"\tsupport_ets: %u\n", unic_dev_ets_supported},
	{"\tsupport_fec: %u\n", unic_dev_fec_supported},
	{"\tsupport_pause: %u\n", unic_dev_pause_supported},
	{"\tsupport_eth: %u\n", unic_dev_eth_supported},
	{"\tsupport_tc_speed_limit: %u\n", unic_dev_tc_speed_limit_supported},
	{"\tsupport_tx_csum_offload: %u\n", unic_dev_tx_csum_offload_supported},
	{"\tsupport_rx_csum_offload: %u\n", unic_dev_rx_csum_offload_supported},
	{"\tsupport_app_lb: %u\n", unic_dev_app_lb_supported},
	{"\tsupport_external_lb: %u\n", unic_dev_external_lb_supported},
	{"\tsupport_serial_serdes_lb: %u\n", unic_dev_serial_serdes_lb_supported},
	{"\tsupport_parallel_serdes_lb: %u\n", unic_dev_parallel_serdes_lb_supported},
	{"\tsupport_fec_stats: %u\n", unic_dev_fec_stats_supported},
	{"\tsupport_cfg_mac: %u\n", unic_dev_cfg_mac_supported},
	{"\tsupport_cfg_vlan_filter: %u\n", unic_dev_cfg_vlan_filter_supported},
};

static void unic_dbg_dump_caps_bits(struct unic_dev *unic_dev,
				    struct seq_file *s)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(unic_cap_bits); i++)
		seq_printf(s, unic_cap_bits[i].format,
			   unic_cap_bits[i].get_bit(unic_dev));
}

static void unic_dbg_dump_caps(struct unic_dev *unic_dev, struct seq_file *s)
{
	struct unic_caps *unic_caps = &unic_dev->caps;
	struct unic_dbg_caps_info {
		const char *format;
		u32 caps_info;
	} unic_caps_info[] = {
		{"\ttotal_ip_tbl_size: %hu\n", unic_caps->total_ip_tbl_size},
		{"\tuc_mac_tbl_size: %u\n", unic_caps->uc_mac_tbl_size},
		{"\tmc_mac_tbl_size: %u\n", unic_caps->mc_mac_tbl_size},
		{"\tvlan_tbl_size: %u\n", unic_caps->vlan_tbl_size},
		{"\tmng_tbl_size: %u\n", unic_caps->mng_tbl_size},
		{"\tmax_trans_unit: %hu\n", unic_caps->max_trans_unit},
		{"\tmin_trans_unit: %hu\n", unic_caps->min_trans_unit},
		{"\tvport_buf_size: %u\n", unic_caps->vport_buf_size},
		{"\tvport_buf_num: %hhu\n", unic_caps->vport_buf_num},
		{"\tmax_int_ql: %hu\n", unic_caps->max_int_ql},
		{"\tmax_int_gl: %hu\n", unic_caps->max_int_gl},
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(unic_caps_info); i++)
		seq_printf(s, unic_caps_info[i].format,
			   unic_caps_info[i].caps_info);
}

static int unic_dbg_dump_caps_info(struct seq_file *s, void *data)
{
	struct unic_dev *unic_dev = dev_get_drvdata(s->private);

	seq_puts(s, "CAP_BITS:\n");
	unic_dbg_dump_caps_bits(unic_dev, s);
	seq_puts(s, "\nCAPS:\n");
	unic_dbg_dump_caps(unic_dev, s);

	return 0;
}

static void unic_dump_page_pool_info(struct page_pool *page_pool,
				     struct seq_file *s, u32 index)
{
#define UNIC_SIZE_1K	1024

	seq_printf(s, "%-10u", index);
	seq_printf(s, "%-14u", READ_ONCE(page_pool->pages_state_hold_cnt));
	seq_printf(s, "%-14d", atomic_read(&page_pool->pages_state_release_cnt));
	seq_printf(s, "%-21u", page_pool->p.pool_size);
	seq_printf(s, "%-7u", page_pool->p.order);
	seq_printf(s, "%-9d", page_pool->p.nid);
	seq_printf(s, "%uK\n", page_pool->p.max_len / UNIC_SIZE_1K);
}

static int unic_dbg_dump_page_pool_info(struct seq_file *s, void *data)
{
	struct unic_dev *unic_dev = dev_get_drvdata(s->private);
	struct unic_rq *rq;
	int ret = 0;
	u32 i;

	seq_puts(s, "QUEUE_ID  ALLOCATE_CNT  FREE_CNT      POOL_SIZE(PAGE_NUM)  ");
	seq_puts(s, "ORDER  NUMA_ID  MAX_LEN\n");

	if (!mutex_trylock(&unic_dev->channels.mutex))
		return -EBUSY;

	if (__unic_resetting(unic_dev) ||
	    !unic_dev->channels.c) {
		ret = -EBUSY;
		goto out;
	}

	for (i = 0; i < unic_dev->channels.num; i++) {
		rq = unic_dev->channels.c[i].rq;
		unic_dump_page_pool_info(rq->page_pool, s, i);
	}

out:
	mutex_unlock(&unic_dev->channels.mutex);
	return ret;
}

static int unic_dbg_dump_rss_cfg_hw(struct seq_file *s, void *data)
{
#define UNIC_RSS_CFG_ITEMS_NUM	6

	struct unic_dev *unic_dev = dev_get_drvdata(s->private);
	struct unic_cfg_rss_cmd resp = {0};
	u16 jfr_cnt;
	u16 i = 0;
	int ret;

	if (__unic_resetting(unic_dev))
		return -EBUSY;

	seq_puts(s, "TC_VAILD  TC_MODE  JFR_0  JFR_1  JFR_2  JFR_3\n");

	ret = unic_query_rss_cfg(unic_dev, &resp);
	if (ret)
		return ret;

	seq_printf(s, "%-10u", resp.tc_vaild);
	seq_printf(s, "%-9u", resp.tc_mode);
	jfr_cnt = min(le16_to_cpu(resp.jfr_reg_num), UNIC_RSS_MAX_CNT);
	jfr_cnt = min(UNIC_RSS_CFG_ITEMS_NUM, jfr_cnt);
	for (i = 0; i < jfr_cnt; i++)
		seq_printf(s, "%-7u", le16_to_cpu(resp.jfr_idx[i]));
	seq_puts(s, "\n");

	return 0;
}

static int unic_dbg_dump_promisc_cfg_hw(struct seq_file *s, void *data)
{
	struct unic_dev *unic_dev = dev_get_drvdata(s->private);
	struct unic_promisc_cfg_cmd resp = {0};
	int ret;

	if (__unic_resetting(unic_dev))
		return -EBUSY;

	ret = unic_get_promisc_mode(unic_dev, &resp);
	if (ret)
		return ret;

	seq_printf(s, "rx_uc_ip_en   : %-2u\n", resp.promisc_rx_uc_ip_en);
	seq_printf(s, "rx_uc_guid_en : %-2u\n", resp.promisc_rx_uc_guid_en);
	seq_printf(s, "rx_mc_en      : %-2u\n", resp.promisc_rx_mc_en);
	seq_printf(s, "rx_uc_mac_en  : %-2u\n", resp.promisc_rx_uc_mac_en);
	seq_printf(s, "rx_mc_mac_en  : %-2u\n", resp.promisc_rx_mc_mac_en);
	seq_printf(s, "rx_bc_en      : %-2u\n", resp.promisc_rx_bc_en);

	return 0;
}

static int unic_dbg_query_link_record(struct seq_file *s, void *data)
{
	struct unic_dev *unic_dev = dev_get_drvdata(s->private);
	struct unic_link_stats *record = &unic_dev->stats.link_record;
	u8 cnt = 1, stats_cnt;
	u64 total, idx;

	mutex_lock(&record->lock);

	seq_puts(s, "current time        : ");
	ubase_dbg_format_time(ktime_get_real_seconds(), s);
	seq_printf(s, "\nlink up count       : %llu\n", record->link_up_cnt);
	seq_printf(s, "link down count     : %llu\n", record->link_down_cnt);

	total = record->link_up_cnt + record->link_down_cnt;
	if (!total) {
		seq_puts(s, "link change records : NA\n");
		mutex_unlock(&record->lock);

		return 0;
	}

	seq_puts(s, "link change records :\n");
	seq_puts(s, "\tNo.\tTIME\t\t\t\tSTATUS\n");

	stats_cnt = min(total, LINK_STAT_MAX_IDX);
	while (cnt <= stats_cnt) {
		total--;
		idx = total % LINK_STAT_MAX_IDX;
		seq_printf(s, "\t%-2d\t", cnt);
		ubase_dbg_format_time(record->stats[idx].link_tv_sec, s);
		seq_printf(s, "\t%s\n",
			   record->stats[idx].link_status ? "LINK UP" : "LINK DOWN");
		cnt++;
	}

	mutex_unlock(&record->lock);

	return 0;
}

static int unic_dbg_clear_link_record(struct seq_file *s, void *data)
{
	struct unic_dev *unic_dev = dev_get_drvdata(s->private);
	struct unic_link_stats *record = &unic_dev->stats.link_record;

	mutex_lock(&record->lock);
	record->link_up_cnt = 0;
	record->link_down_cnt = 0;
	memset(record->stats, 0, sizeof(record->stats));
	mutex_unlock(&record->lock);

	seq_puts(s, "Link status records have been cleared!\n");

	return 0;
}

static bool unic_dbg_dentry_support(struct device *dev, u32 property)
{
	struct unic_dev *unic_dev = dev_get_drvdata(dev);

	return ubase_dbg_dentry_support(unic_dev->comdev.adev, property);
}

static struct ubase_dbg_dentry_info unic_dbg_dentry[] = {
	{
		.name = "ip_tbl",
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
	}, {
		.name = "context",
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
	}, {
		.name = "vport",
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
	}, {
		.name = "qos",
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
	}, {
		.name = "vlan_tbl",
		.property = UBASE_SUP_UNIC | UBASE_SUP_ETH,
		.support = unic_dbg_dentry_support,
	}, {
		.name = "mac_tbl",
		.property = UBASE_SUP_UNIC | UBASE_SUP_ETH,
		.support = unic_dbg_dentry_support,
	},
	/* keep unic at the bottom and add new directory above */
	{
		.name = "unic",
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
	},
};

static struct ubase_dbg_cmd_info unic_dbg_cmd[] = {
	{
		.name = "ip_tbl_spec",
		.dentry_index = UNIC_DBG_DENTRY_IP,
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_ip_tbl_spec,
	}, {
		.name = "ip_tbl_list",
		.dentry_index = UNIC_DBG_DENTRY_IP,
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_ip_tbl_list,
	}, {
		.name = "bond_ip_tbl_list",
		.dentry_index = UNIC_DBG_DENTRY_IP,
		.property = UBASE_SUP_UNIC | UBASE_SUP_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_bond_ip_tbl_list,
	}, {
		.name = "uc_mac_tbl_list",
		.dentry_index = UNIC_DBG_DENTRY_MAC,
		.property = UBASE_SUP_UNIC | UBASE_SUP_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_uc_mac_tbl_list,
	}, {
		.name = "mc_mac_tbl_list",
		.dentry_index = UNIC_DBG_DENTRY_MAC,
		.property = UBASE_SUP_UNIC | UBASE_SUP_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_mc_mac_tbl_list,
	}, {
		.name = "mac_tbl_spec",
		.dentry_index = UNIC_DBG_DENTRY_MAC,
		.property = UBASE_SUP_UNIC | UBASE_SUP_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_mac_tbl_spec,
	}, {
		.name = "jfs_context",
		.dentry_index = UNIC_DBG_DENTRY_CONTEXT,
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_jfs_ctx_sw,
	}, {
		.name = "jfr_context",
		.dentry_index = UNIC_DBG_DENTRY_CONTEXT,
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_jfr_ctx_sw,
	}, {
		.name = "sq_jfc_context",
		.dentry_index = UNIC_DBG_DENTRY_CONTEXT,
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_sq_jfc_ctx_sw,
	}, {
		.name = "rq_jfc_context",
		.dentry_index = UNIC_DBG_DENTRY_CONTEXT,
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_rq_jfc_ctx_sw,
	}, {
		.name = "sq_rq_cq_info",
		.dentry_index = UNIC_DBG_DENTRY_CONTEXT,
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_sq_rq_cq_info,
	}, {
		.name = "dev_info",
		.dentry_index = UNIC_DBG_DENTRY_ROOT,
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_dev_info,
	}, {
		.name = "vport_buf",
		.dentry_index = UNIC_DBG_DENTRY_VPORT,
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_vport_buf,
	}, {
		.name = "vport_ctx",
		.dentry_index = UNIC_DBG_DENTRY_VPORT,
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_vport_ctx,
	}, {
		.name = "caps_info",
		.dentry_index = UNIC_DBG_DENTRY_ROOT,
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_caps_info,
	}, {
		.name = "mac_tbl_list_hw",
		.dentry_index = UNIC_DBG_DENTRY_MAC,
		.property = UBASE_SUP_UNIC | UBASE_SUP_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_mac_tbl_list_hw,
	}, {
		.name = "mng_tbl_list_hw",
		.dentry_index = UNIC_DBG_DENTRY_MAC,
		.property = UBASE_SUP_UNIC | UBASE_SUP_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_mng_tbl_list_hw,
	}, {
		.name = "vlan_tbl_list_hw",
		.dentry_index = UNIC_DBG_DENTRY_VLAN,
		.property = UBASE_SUP_UNIC | UBASE_SUP_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_vlan_tbl_list_hw,
	}, {
		.name = "page_pool_info",
		.dentry_index = UNIC_DBG_DENTRY_ROOT,
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_page_pool_info,
	}, {
		.name = "jfs_context_hw",
		.dentry_index = UNIC_DBG_DENTRY_CONTEXT,
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_jfs_context_hw,
	}, {
		.name = "jfr_context_hw",
		.dentry_index = UNIC_DBG_DENTRY_CONTEXT,
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_jfr_context_hw,
	}, {
		.name = "sq_jfc_context_hw",
		.dentry_index = UNIC_DBG_DENTRY_CONTEXT,
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_sq_jfc_context_hw,
	}, {
		.name = "rq_jfc_context_hw",
		.dentry_index = UNIC_DBG_DENTRY_CONTEXT,
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_rq_jfc_context_hw,
	}, {
		.name = "vl_queue",
		.dentry_index = UNIC_DBG_DENTRY_QOS,
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_vl_queue,
	}, {
		.name = "rss_cfg_hw",
		.dentry_index = UNIC_DBG_DENTRY_ROOT,
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_rss_cfg_hw,
	}, {
		.name = "promisc_cfg_hw",
		.dentry_index = UNIC_DBG_DENTRY_ROOT,
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_promisc_cfg_hw,
	}, {
		.name = "dscp_vl_map",
		.dentry_index = UNIC_DBG_DENTRY_QOS,
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_dscp_vl_map,
	}, {
		.name = "prio_vl_map",
		.dentry_index = UNIC_DBG_DENTRY_QOS,
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_prio_vl_map,
	}, {
		.name = "pfc_info",
		.dentry_index = UNIC_DBG_DENTRY_QOS,
		.property = UBASE_SUP_UNIC | UBASE_SUP_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_pfc_param,
	}, {
		.name = "dscp_prio",
		.dentry_index = UNIC_DBG_DENTRY_QOS,
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_dump_dscp_prio,
	}, {
		.name = "link_status_record",
		.dentry_index = UNIC_DBG_DENTRY_ROOT,
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_query_link_record,
	}, {
		.name = "clear_link_status_record",
		.dentry_index = UNIC_DBG_DENTRY_ROOT,
		.property = UBASE_SUP_UNIC | UBASE_SUP_UBL_ETH,
		.support = unic_dbg_dentry_support,
		.init = ubase_dbg_seq_file_init,
		.read_func = unic_dbg_clear_link_record,
	},
};

int unic_dbg_init(struct auxiliary_device *adev)
{
	struct dentry *ubase_root_dentry = unic_get_ubase_root_dentry(adev);
	struct ubase_dbg_dentry_info dentry[UNIC_DBG_DENTRY_ROOT + 1] = {0};
	u8 dentry_num = ARRAY_SIZE(unic_dbg_dentry);
	struct device *dev = &adev->dev;
	struct unic_dev *unic_dev;
	int ret;

	unic_dev = (struct unic_dev *)dev_get_drvdata(dev);

	if (!ubase_root_dentry) {
		unic_err(unic_dev, "dbgfs root dentry does not exist.\n");
		return -ENOENT;
	}

	unic_dev->dbgfs.dentry = debugfs_create_dir(unic_dbg_dentry[dentry_num - 1].name,
						    ubase_root_dentry);
	if (IS_ERR(unic_dev->dbgfs.dentry)) {
		unic_err(unic_dev, "failed to create unic debugfs root dir.\n");
		return PTR_ERR(unic_dev->dbgfs.dentry);
	}

	memcpy(dentry, unic_dbg_dentry, sizeof(dentry));
	dentry[UNIC_DBG_DENTRY_ROOT].dentry = unic_dev->dbgfs.dentry;
	unic_dev->dbgfs.cmd_info = unic_dbg_cmd;
	unic_dev->dbgfs.cmd_info_size = ARRAY_SIZE(unic_dbg_cmd);

	ret = ubase_dbg_create_dentry(dev, &unic_dev->dbgfs, dentry,
				      ARRAY_SIZE(dentry) - 1);
	if (ret) {
		unic_err(unic_dev,
			 "failed to create unic debugfs dentry, ret = %d.\n",
			 ret);
		goto create_dentry_err;
	}

	return 0;

create_dentry_err:
	debugfs_remove_recursive(unic_dev->dbgfs.dentry);

	return ret;
}

void unic_dbg_uninit(struct auxiliary_device *adev)
{
	struct unic_dev *unic_dev = dev_get_drvdata(&adev->dev);

	debugfs_remove_recursive(unic_dev->dbgfs.dentry);
}
