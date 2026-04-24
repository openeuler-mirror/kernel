// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <ub/ubase/ubase_comm_debugfs.h>

#include "ubase_cmd.h"
#include "ubase_ctx_debugfs.h"
#include "ubase_dev.h"
#include "ubase_hw.h"
#include "ubase_mailbox.h"
#include "ubase_proxy_debugfs.h"
#include "ubase_qos_debugfs.h"
#include "ubase_stats.h"
#include "ubase_tp.h"
#include "ubase_debugfs.h"

static struct dentry *ubase_dbgfs_root;

static int ubase_dbg_dump_rst_info(struct seq_file *s, void *data)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);

	seq_printf(s, "ELR reset count: %u\n", udev->reset_stat.elr_reset_cnt);
	seq_printf(s, "port reset count: %u\n", udev->reset_stat.port_reset_cnt);
	seq_printf(s, "himac reset count: %u\n", udev->reset_stat.himac_reset_cnt);
	seq_printf(s, "reset done count: %u\n", udev->reset_stat.reset_done_cnt);
	seq_printf(s, "HW reset done count: %u\n", udev->reset_stat.hw_reset_done_cnt);
	seq_printf(s, "reset fail count: %u\n", udev->reset_stat.reset_fail_cnt);
	seq_printf(s, "udev state: 0x%lx\n", udev->state_bits);

	return 0;
}

static void ubase_dbg_dump_caps_bits(struct seq_file *s, struct ubase_dev *udev)
{
#define CAP_FMT(name) "\tsupport_" #name ": %d\n"
#define PRINT_CAP(name, func) seq_printf(s, CAP_FMT(name), func(udev))

	PRINT_CAP(ub_link, ubase_dev_ubl_supported);
	PRINT_CAP(ta_extdb_buffer_config, ubase_dev_ta_extdb_buf_supported);
	PRINT_CAP(ta_timer_buffer_config, ubase_dev_ta_timer_buf_supported);
	PRINT_CAP(err_handle, ubase_dev_err_handle_supported);
	PRINT_CAP(ctrlq, ubase_dev_ctrlq_supported);
	PRINT_CAP(eth_mac, ubase_dev_eth_mac_supported);
	PRINT_CAP(mac_stats, ubase_dev_mac_stats_supported);
	PRINT_CAP(mbx, ubase_dev_mbx_supported);
	PRINT_CAP(mbx_proxy, ubase_dev_mbx_proxy_supported);
	PRINT_CAP(prealloc, __ubase_dev_prealloc_supported);
	PRINT_CAP(udma, ubase_dev_udma_supported);
	PRINT_CAP(unic, ubase_dev_unic_supported);
	PRINT_CAP(uvb, ubase_dev_uvb_supported);
	PRINT_CAP(ip_over_urma, ubase_ip_over_urma_supported);
	if (ubase_ip_over_urma_supported(udev))
		PRINT_CAP(ip_over_urma_utp, ubase_ip_over_urma_utp_supported);
	PRINT_CAP(activate_proxy, ubase_activate_proxy_supported);
	PRINT_CAP(utp, ubase_utp_supported);
	PRINT_CAP(pmu_irq, ubase_pmu_irq_supported);
	PRINT_CAP(usc, ubase_dev_usc_supported);
	PRINT_CAP(ucp, ubase_ucp_supported);
}

static void ubase_dbg_dump_caps_info(struct seq_file *s, struct ubase_dev *udev)
{
	struct ubase_caps *dev_caps = &udev->caps.dev_caps;
	struct ubase_dbg_common_caps_info {
		const char *format;
		u64 caps_info;
	} ubase_common_caps_info[] = {
		{"\tnum_ceq_vectors: %u\n", dev_caps->num_ceq_vectors},
		{"\tnum_aeq_vectors: %u\n", dev_caps->num_aeq_vectors},
		{"\tnum_misc_vectors: %u\n", dev_caps->num_misc_vectors},
		{"\taeqe_size: %u\n", dev_caps->aeqe_size},
		{"\tceqe_size: %u\n", dev_caps->ceqe_size},
		{"\taeqe_depth: %u\n", dev_caps->aeqe_depth},
		{"\tceqe_depth: %u\n", dev_caps->ceqe_depth},
		{"\ttotal_ue_num: %u\n", dev_caps->total_ue_num},
		{"\tta_extdb_buf_size: %llu\n", udev->ta_ctx.extdb_buf.size},
		{"\tta_timer_buf_size: %llu\n", udev->ta_ctx.timer_buf.size},
		{"\tnode_type: %u\n", udev->node_type},
		{"\tpublic_jetty_cnt: %u\n", dev_caps->public_jetty_cnt},
		{"\tvl_num: %hhu\n", dev_caps->vl_num},
		{"\trsvd_jetty_cnt: %hu\n", dev_caps->rsvd_jetty_cnt},
		{"\tpacket_pattern_mode: %u\n", dev_caps->packet_pattern_mode},
		{"\tack_queue_num: %u\n", dev_caps->ack_queue_num},
		{"\toor_en: %u\n", dev_caps->oor_en},
		{"\treorder_queue_en: %u\n", dev_caps->reorder_queue_en},
		{"\ton_flight_size: %u\n", dev_caps->on_flight_size},
		{"\treorder_cap: %u\n", dev_caps->reorder_cap},
		{"\treorder_queue_shift: %u\n", dev_caps->reorder_queue_shift},
		{"\tat_times: %u\n", dev_caps->at_times},
		{"\tue_num: %u\n", dev_caps->ue_num},
		{"\tmac_stats_num: %u\n", dev_caps->mac_stats_num},
		{"\tlogic_port_bitmap: 0x%x\n", dev_caps->logic_port_bitmap},
		{"\tub_port_logic_id: %u\n", dev_caps->ub_port_logic_id},
		{"\tio_port_logic_id: %u\n", dev_caps->io_port_logic_id},
		{"\tio_port_id: %u\n", dev_caps->io_port_id},
		{"\tnl_port_id: %u\n", dev_caps->nl_port_id},
		{"\tchip_id: %u\n", dev_caps->chip_id},
		{"\tdie_id: %u\n", dev_caps->die_id},
		{"\tue_id: %u\n", dev_caps->ue_id},
		{"\tnl_id: %u\n", dev_caps->nl_id},
		{"\ttid: %u\n", dev_caps->tid},
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(ubase_common_caps_info); i++)
		seq_printf(s, ubase_common_caps_info[i].format,
			   ubase_common_caps_info[i].caps_info);

	seq_printf(s, "\tfw_version: %u.%u.%u.%u\n",
		   u32_get_bits(dev_caps->fw_version, UBASE_FW_VERSION_BYTE3_MASK),
		   u32_get_bits(dev_caps->fw_version, UBASE_FW_VERSION_BYTE2_MASK),
		   u32_get_bits(dev_caps->fw_version, UBASE_FW_VERSION_BYTE1_MASK),
		   u32_get_bits(dev_caps->fw_version, UBASE_FW_VERSION_BYTE0_MASK));
}

static void ubase_dbg_dump_common_caps(struct seq_file *s, struct ubase_dev *udev)
{
	struct ubase_caps *dev_caps = &udev->caps.dev_caps;

	ubase_dbg_dump_caps_info(s, udev);

	seq_puts(s, "\treq_vl:");
	ubase_dbg_dump_arr_info(s, dev_caps->req_vl, dev_caps->vl_num);

	seq_puts(s, "\tresp_vl:");
	ubase_dbg_dump_arr_info(s, dev_caps->resp_vl, dev_caps->vl_num);
}

static void ubase_dbg_dump_adev_caps(struct seq_file *s,
				     struct ubase_adev_caps *caps)
{
	struct ubase_dbg_adev_caps_info {
		const char *format;
		u32 caps_info;
	} ubase_adev_caps_info[] = {
		{"\tjfs_max_cnt: %u\n", caps->jfs.max_cnt},
		{"\tjfs_depth: %u\n", caps->jfs.depth},
		{"\tjfr_max_cnt: %u\n", caps->jfr.max_cnt},
		{"\tjfr_depth: %u\n", caps->jfr.depth},
		{"\tjfc_max_cnt: %u\n", caps->jfc.max_cnt},
		{"\tjfc_depth: %u\n", caps->jfc.depth},
		{"\ttpg_max_cnt: %u\n", caps->tpg.max_cnt},
		{"\tcqe_size: %hu\n", caps->cqe_size},
		{"\tjtg_max_cnt: %u\n", caps->jtg_max_cnt},
		{"\trc_max_cnt: %u\n", caps->rc_max_cnt},
		{"\trc_que_depth: %u\n", caps->rc_que_depth},
		{"\tprealloc_mem_dma_len: %llu\n", caps->pmem.dma_len},
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(ubase_adev_caps_info); i++)
		seq_printf(s, ubase_adev_caps_info[i].format,
			   ubase_adev_caps_info[i].caps_info);
}

static int ubase_dbg_dump_dev_caps(struct seq_file *s, void *data)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	struct ubase_dev_caps *udev_caps = &udev->caps;

	seq_puts(s, "CAP_BITS:\n");
	ubase_dbg_dump_caps_bits(s, udev);
	seq_puts(s, "\nCOMMON_CAPS:\n");
	ubase_dbg_dump_common_caps(s, udev);

	if (ubase_dev_pmu_supported(udev))
		return 0;

	seq_puts(s, "\nUNIC_CAPS:\n");
	ubase_dbg_dump_adev_caps(s, &udev_caps->unic_caps);

	if (ubase_dev_cdma_supported(udev))
		seq_puts(s, "\nCDMA_CAPS:\n");
	else
		seq_puts(s, "\nUDMA_CAPS:\n");
	ubase_dbg_dump_adev_caps(s, &udev_caps->udma_caps);

	return 0;
}

static int ubase_query_ubcl_config(struct ubase_dev *udev, u16 offset,
				   u16 is_query, u16 size,
				   struct ubase_ubcl_config_cmd *resp)
{
	struct ubase_ubcl_config_cmd req;
	struct ubase_cmd_buf in, out;
	int ret;

	memset(resp, 0, sizeof(*resp));
	memset(&req, 0, sizeof(req));
	req.offset = cpu_to_le16(offset);
	req.size = cpu_to_le16(size);
	req.is_query_size = cpu_to_le16(is_query);

	__ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_UBCL_CONFIG, true,
			       sizeof(req), &req);
	__ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_UBCL_CONFIG, true,
			       sizeof(*resp), resp);
	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret && ret != -EPERM)
		ubase_err(udev, "failed to query UBCL_config, ret = %d.\n", ret);

	if (ret == -EPERM)
		return -EOPNOTSUPP;

	return ret;
}

static void ubase_dbg_fill_ubcl_content(struct ubase_ubcl_config_cmd *resp,
					u32 *addr, struct seq_file *s)
{
	int i, j;

	for (i = 0; i < UBASE_UBCL_CFG_DATA_NUM; i += UBASE_UBCL_CFG_DATA_ALIGN) {
		seq_printf(s, "%08X: ", (*addr * UBASE_UBCL_CFG_DATA_ALIGN));
		for (j = 0; j < UBASE_UBCL_CFG_DATA_ALIGN; j++)
			seq_printf(s, "%08X ", resp->data[i + j]);
		seq_puts(s, "\n");

		*addr += UBASE_UBCL_CFG_DATA_ALIGN;
		if ((i * sizeof(u32)) >= resp->size)
			break;
	}
}

static int ubase_dbg_dump_ubcl_config(struct seq_file *s, void *data)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	struct ubase_ubcl_config_cmd resp = {0};
	u16 read_size = sizeof(resp.data);
	u16 offset = 0;
	u16 total_size;
	u32 addr = 0;
	int ret;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	    test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	ret = ubase_query_ubcl_config(udev, offset, 1, 0, &resp);
	if (ret)
		return ret;
	total_size = le16_to_cpu(resp.size);

	seq_puts(s, "UBCL_config:\n");
	seq_printf(s, "total_size: %u\n", total_size);
	while (offset < total_size) {
		read_size = min(read_size, total_size - offset);
		ret = ubase_query_ubcl_config(udev, offset, 0, read_size, &resp);
		if (ret)
			return ret;
		offset += le16_to_cpu(resp.size);

		ubase_dbg_fill_ubcl_content(&resp, &addr, s);
	}

	return 0;
}

static int ubase_dbg_dump_activate_record(struct seq_file *s, void *data)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	struct ubase_activate_dev_stats *record;
	u8 cnt = 1, stats_cnt;
	u64 total, idx;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	    test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	record = &udev->stats.activate_record;

	mutex_lock(&record->lock);

	seq_puts(s, "current time        : ");
	ubase_dbg_format_time(ktime_get_real_seconds(), s);
	seq_puts(s, "\n");
	seq_printf(s, "activate dev count    : %llu\n", record->act_cnt);
	seq_printf(s, "deactivate dev count  : %llu\n", record->deact_cnt);

	total = record->act_cnt + record->deact_cnt;
	if (!total) {
		seq_puts(s, "activate dev change records : NA\n");
		mutex_unlock(&record->lock);
		return 0;
	}

	seq_puts(s, "activate dev change records :\n");
	seq_puts(s, "\tNo.\tTIME\t\t\t\tSTATUS\t\tRESULT\n");

	stats_cnt = min(total, UBASE_ACT_STAT_MAX_NUM);
	while (cnt <= stats_cnt) {
		total--;
		idx = total % UBASE_ACT_STAT_MAX_NUM;
		seq_printf(s, "\t%-2d\t", cnt);
		ubase_dbg_format_time(record->stats[idx].time, s);
		seq_printf(s, "\t%s", record->stats[idx].activate ?
					  "activate" : "deactivate");
		seq_printf(s, "\t%d", record->stats[idx].result);
		seq_puts(s, "\n");
		cnt++;
	}

	mutex_unlock(&record->lock);
	return 0;
}

static void ubase_dbg_fill_single_port(struct seq_file *s,
				       struct ubase_perf_stats_result *stats)
{
	int i;

	seq_printf(s, "\tport_id: %u\n", stats->port_id);
	seq_printf(s, "\tport_tx_bw: %u(kbps)\n", le32_to_cpu(stats->tx_port_bw));
	seq_printf(s, "\tport_rx_bw: %u(kbps)\n", le32_to_cpu(stats->rx_port_bw));
	seq_printf(s, "\tport_tx_max_bw: %u(kbps)\n", le32_to_cpu(stats->tx_max_port_bw));
	seq_printf(s, "\tport_rx_max_bw: %u(kbps)\n", le32_to_cpu(stats->rx_max_port_bw));
	seq_puts(s, "\tvl   tx_bw(kbps)          rx_bw(kbps)\n");

	for (i = 0; i < UBASE_STATS_MAX_VL_NUM; i++) {
		seq_printf(s, "\t%-5d", i);
		seq_printf(s, "%-21u", le32_to_cpu(stats->tx_vl_bw[i]));
		seq_printf(s, "%-21u", le32_to_cpu(stats->rx_vl_bw[i]));
		seq_puts(s, "\n");
	}
	seq_puts(s, "\n");
}

static int ubase_dbg_dump_perf_stats_ub(struct seq_file *s,
					struct ubase_dev *udev)
{
#define UBASE_UB_PERF_STATS_PERIOD	100
#define UBASE_QUERY_ALL_BITMAP	0

	struct ubase_perf_stats_result *stats;
	struct device *dev = udev->dev;
	int ret, i;

	stats = devm_kcalloc(dev, UBASE_MAX_PORT_NUM,
			     sizeof(struct ubase_perf_stats_result), GFP_KERNEL);
	if (!stats)
		return -ENOMEM;

	ret = __ubase_perf_stats(udev, UBASE_QUERY_ALL_BITMAP,
				 UBASE_UB_PERF_STATS_PERIOD, stats,
				 UBASE_MAX_PORT_NUM);
	if (ret) {
		devm_kfree(dev, stats);
		return ret;
	}

	seq_printf(s, "perf_stats_period: %d(ms)\n", UBASE_UB_PERF_STATS_PERIOD);
	seq_puts(s, "port bandwidth info:\n");

	for (i = 0; i < UBASE_MAX_PORT_NUM; i++) {
		if (!stats[i].valid)
			break;
		ubase_dbg_fill_single_port(s, &stats[i]);
	}

	devm_kfree(dev, stats);

	return 0;
}

static int ubase_dbg_dump_perf_stats_eth(struct seq_file *s, struct ubase_dev *udev)
{
#define UBASE_ETH_PERF_STATS_PERIOD	1000

	struct ubase_eth_mac_stats old_data = {0};
	struct ubase_eth_mac_stats cur_data = {0};
	u64 port_tx_bw, port_rx_bw;
	int ret;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	     test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	ret = __ubase_get_eth_port_stats(udev, &old_data);
	if (ret) {
		ubase_err(udev,
			  "failed to get first eth stats, ret = %d.\n", ret);
		return ret;
	}

	msleep(UBASE_ETH_PERF_STATS_PERIOD);

	ret = __ubase_get_eth_port_stats(udev, &cur_data);
	if (ret) {
		ubase_err(udev,
			  "failed to get second eth stats, ret = %d.\n", ret);
		return ret;
	}

	port_tx_bw = (cur_data.tx_total_octets - old_data.tx_total_octets) *
		     BITS_PER_BYTE / UBASE_ETH_PERF_STATS_PERIOD;
	port_rx_bw = (cur_data.rx_total_octets - old_data.rx_total_octets) *
		     BITS_PER_BYTE / UBASE_ETH_PERF_STATS_PERIOD;

	seq_printf(s, "perf_stats_period: %d(ms)\n", UBASE_ETH_PERF_STATS_PERIOD);
	seq_printf(s, "port_tx_bw: %llu(kbps)\n", port_tx_bw);
	seq_printf(s, "port_rx_bw: %llu(kbps)\n", port_rx_bw);

	return 0;
}

static int ubase_dbg_dump_perf_stats(struct seq_file *s, void *data)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	int ret;

	if (ubase_dev_ubl_supported(udev))
		ret = ubase_dbg_dump_perf_stats_ub(s, udev);
	else
		ret = ubase_dbg_dump_perf_stats_eth(s, udev);

	return ret;
}

static int ubase_dbg_dump_prealloc_mem_info(struct seq_file *s, void *data)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	struct ubase_prealloc_mem_info *pmem_info = &udev->pmem_info;
	int status;

	status = test_bit(UBASE_STATE_PREALLOC_OK_B, &udev->state_bits);

	seq_printf(s, "status:%s\n", status ? "enabled" : "disabled");
	seq_printf(s, "comm_page_cnt:%u\n", pmem_info->comm.page_cnt);
	seq_printf(s, "udma_page_cnt:%u\n", pmem_info->udma.page_cnt);

	return 0;
}

static bool __ubase_dbg_dentry_support(struct device *dev, u32 property)
{
	struct ubase_dev *udev = dev_get_drvdata(dev);

	if (((property & UBASE_SUP_UNIC) && ubase_dev_unic_supported(udev)) ||
	    ((property & UBASE_SUP_UDMA) && ubase_dev_udma_supported(udev)) ||
	    ((property & UBASE_SUP_CDMA) && ubase_dev_cdma_supported(udev)) ||
	    ((property & UBASE_SUP_PMU) && ubase_dev_pmu_supported(udev))) {
		if (((property & UBASE_SUP_UBL) && ubase_dev_ubl_supported(udev)) ||
		    ((property & UBASE_SUP_ETH) && ubase_dev_eth_mac_supported(udev)))
			return true;
	}

	return false;
}

/**
 * ubase_dbg_dentry_support() - determine whether to create debugfs dentries and debugfs cmd files
 * @adev: auxiliary device
 * @property: property of debugfs dentry or debufs cmd file
 *
 * The function is used in the 'support' functions of 'struct ubase_dbg_cmd_info'
 * and 'struct ubase_dbg_cmd_info' to determine whether to create debugfs dentries
 * and debugfs cmd files.
 *
 * Context: Any context.
 * Return: true or false
 */
bool ubase_dbg_dentry_support(struct auxiliary_device *adev, u32 property)
{
	if (!adev)
		return false;

	return __ubase_dbg_dentry_support(__ubase_get_udev_by_adev(adev)->dev,
					  property);
}
EXPORT_SYMBOL(ubase_dbg_dentry_support);

static int __ubase_dbg_seq_file_init(struct device *dev,
				     struct ubase_dbg_dentry_info *dirs,
				     struct ubase_dbgfs *dbgfs, u32 idx)
{
	struct ubase_dbg_cmd_info *cmd_info = &dbgfs->cmd_info[idx];
	struct dentry *cur_dir;

	cur_dir = dirs[cmd_info->dentry_index].dentry;
	if (!cmd_info->read_func)
		return -EFAULT;

	debugfs_create_devm_seqfile(dev, cmd_info->name, cur_dir,
				    cmd_info->read_func);

	return 0;
}

/**
 * ubase_dbg_seq_file_init() - ubase init debugfs cmd file
 * @dev: the device
 * @dirs: ubase debugfs dentry information
 * @dbgfs: ubase debugfs data structure
 * @idx: index of dirs
 *
 * This function is used in the 'init' function within 'struct ubase_dbg_cmd_info'
 * to create a ubase debugfs cmd file.
 *
 * Context: Any context.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_dbg_seq_file_init(struct device *dev,
			    struct ubase_dbg_dentry_info *dirs,
			    struct ubase_dbgfs *dbgfs, u32 idx)
{
	if (!dev || !dirs || !dbgfs || !dbgfs->cmd_info)
		return -EINVAL;

	return __ubase_dbg_seq_file_init(dev, dirs, dbgfs, idx);
}
EXPORT_SYMBOL(ubase_dbg_seq_file_init);

static struct ubase_dbg_dentry_info ubase_dbg_dentry[] = {
	{
		.name = "context",
		.property = UBASE_SUP_URMA | UBASE_SUP_CDMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
	},
	{
		.name = "qos",
		.property = UBASE_SUP_URMA | UBASE_SUP_CDMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
	},
	/* ue debugfs top-level directory,
	 * "dev_name" refers to the ue name
	 */
	{
		.name = "dev_name",
		.property = UBASE_SUP_URMA | UBASE_SUP_CDMA | UBASE_SUP_PMU |
			    UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
	},
};

static struct ubase_dbg_cmd_info ubase_dbg_cmd[] = {
	{
		.name = "reset_info",
		.dentry_index = UBASE_DBG_DENTRY_ROOT,
		.property = UBASE_SUP_URMA | UBASE_SUP_CDMA | UBASE_SUP_PMU |
			    UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_rst_info,
	},
	{
		.name = "aeq_context",
		.dentry_index = UBASE_DBG_DENTRY_CONTEXT,
		.property = UBASE_SUP_URMA | UBASE_SUP_CDMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_aeq_context,
	},
	{
		.name = "ceq_context",
		.dentry_index = UBASE_DBG_DENTRY_CONTEXT,
		.property = UBASE_SUP_URMA | UBASE_SUP_CDMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_ceq_context,
	},
	{
		.name = "caps_info",
		.dentry_index = UBASE_DBG_DENTRY_ROOT,
		.property = UBASE_SUP_URMA | UBASE_SUP_CDMA | UBASE_SUP_PMU |
			    UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_dev_caps,
	},
	{
		.name = "UBCL_config",
		.dentry_index = UBASE_DBG_DENTRY_ROOT,
		.property = UBASE_SUP_URMA | UBASE_SUP_CDMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_ubcl_config,
	},
	{
		.name = "activate_record",
		.dentry_index = UBASE_DBG_DENTRY_ROOT,
		.property = UBASE_SUP_URMA | UBASE_SUP_CDMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_activate_record,
	},
	{
		.name = "tpg_context",
		.dentry_index = UBASE_DBG_DENTRY_CONTEXT,
		.property = UBASE_SUP_URMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_tpg_ctx,
	},
	{
		.name = "aeq_context_hw",
		.dentry_index = UBASE_DBG_DENTRY_CONTEXT,
		.property = UBASE_SUP_URMA | UBASE_SUP_CDMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_aeq_ctx_hw,
	},
	{
		.name = "ceq_context_hw",
		.dentry_index = UBASE_DBG_DENTRY_CONTEXT,
		.property = UBASE_SUP_URMA | UBASE_SUP_CDMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_ceq_ctx_hw,
	},
	{
		.name = "sl_vl_map",
		.dentry_index = UBASE_DBG_DENTRY_QOS,
		.property = UBASE_SUP_URMA | UBASE_SUP_CDMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_sl_vl_map,
	},
	{
		.name = "udma_dscp_vl_map",
		.dentry_index = UBASE_DBG_DENTRY_QOS,
		.property = UBASE_SUP_URMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_udma_dscp_vl_map,
	},
	{
		.name = "ets_tc",
		.dentry_index = UBASE_DBG_DENTRY_QOS,
		.property = UBASE_SUP_URMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_ets_tc_info,
	},
	{
		.name = "ets_tcg",
		.dentry_index = UBASE_DBG_DENTRY_QOS,
		.property = UBASE_SUP_URMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_ets_tcg_info,
	},
	{
		.name = "ets_port",
		.dentry_index = UBASE_DBG_DENTRY_QOS,
		.property = UBASE_SUP_URMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_ets_port_info,
	},
	{
		.name = "perf_stats",
		.dentry_index = UBASE_DBG_DENTRY_ROOT,
		.property = UBASE_SUP_URMA | UBASE_SUP_CDMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_perf_stats,
	},
	{
		.name = "vl_bitmap",
		.dentry_index = UBASE_DBG_DENTRY_QOS,
		.property = UBASE_SUP_URMA | UBASE_SUP_CDMA | UBASE_SUP_UBL,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_vl_bitmap,
	},
	{
		.name = "adev_qos",
		.dentry_index = UBASE_DBG_DENTRY_QOS,
		.property = UBASE_SUP_URMA | UBASE_SUP_CDMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_adev_qos_info,
	},
	{
		.name = "fst_fvt_rqmt_info",
		.dentry_index = UBASE_DBG_DENTRY_QOS,
		.property = UBASE_SUP_URMA | UBASE_SUP_CDMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_fsv_fvt_rqmt,
	},
	{
		.name = "tm_queue",
		.dentry_index = UBASE_DBG_DENTRY_QOS,
		.property = UBASE_SUP_URMA | UBASE_SUP_CDMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_tm_queue_info,
	},
	{
		.name = "tm_qset",
		.dentry_index = UBASE_DBG_DENTRY_QOS,
		.property = UBASE_SUP_URMA | UBASE_SUP_CDMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_tm_qset_info,
	},
	{
		.name = "tm_pri",
		.dentry_index = UBASE_DBG_DENTRY_QOS,
		.property = UBASE_SUP_URMA | UBASE_SUP_CDMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_tm_pri_info,
	},
	{
		.name = "tm_pg",
		.dentry_index = UBASE_DBG_DENTRY_QOS,
		.property = UBASE_SUP_URMA | UBASE_SUP_CDMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_tm_pg_info,
	},
	{
		.name = "tm_port",
		.dentry_index = UBASE_DBG_DENTRY_QOS,
		.property = UBASE_SUP_URMA | UBASE_SUP_CDMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_tm_port_info,
	},
	{
		.name = "ue_isolated_state",
		.dentry_index = UBASE_DBG_DENTRY_ROOT,
		.property = UBASE_SUP_URMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_ue_isolated_state,
	},
	{
		.name = "prealloc_mem_info",
		.dentry_index = UBASE_DBG_DENTRY_ROOT,
		.property = UBASE_SUP_URMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_prealloc_mem_info,
	},
	{
		.name = "initial_qset_info",
		.dentry_index = UBASE_DBG_DENTRY_QOS,
		.property = UBASE_SUP_URMA | UBASE_SUP_CDMA | UBASE_SUP_UBL_ETH,
		.support = __ubase_dbg_dentry_support,
		.init = __ubase_dbg_seq_file_init,
		.read_func = ubase_dbg_dump_initial_qset_info,
	},
};

static int ubase_dbg_create_dir(struct device *dev,
				struct ubase_dbg_dentry_info *dirs, u32 root_idx)
{
	u32 i;

	for (i = 0; i < root_idx; i++) {
		if (!dirs[i].support(dev, dirs[i].property))
			continue;

		dirs[i].dentry = debugfs_create_dir(dirs[i].name,
						    dirs[root_idx].dentry);
		if (IS_ERR(dirs[i].dentry)) {
			dev_err(dev, "failed to create %s dir.\n", dirs[i].name);
			return PTR_ERR(dirs[i].dentry);
		}
	}

	return 0;
}

static int ubase_dbg_create_file(struct device *dev, struct ubase_dbgfs *dbgfs,
				 struct ubase_dbg_dentry_info *dirs)
{
	struct ubase_dbg_cmd_info *cmd_info;
	int i, ret;

	cmd_info = dbgfs->cmd_info;
	for (i = 0; i < dbgfs->cmd_info_size; i++) {
		if (!cmd_info[i].support(dev, cmd_info[i].property))
			continue;

		ret = cmd_info[i].init(dev, dirs, dbgfs, i);
		if (ret) {
			dev_err(dev, "failed to init cmd %s, ret = %d.\n",
				cmd_info[i].name, ret);
			return ret;
		}
	}

	return 0;
}

/**
 * ubase_dbg_create_dentry() - ubase debugfs create dentry
 * @dev: the device
 * @dbgfs: ubase debugfs data structure
 * @dirs: ubase debugfs dentry information
 * @root_idx: index of the root dentry in dirs, and the root dentry must be the last one in the path
 *
 * This function is used to create a ubase debugfs cmd file.
 *
 * Context: Any context.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_dbg_create_dentry(struct device *dev, struct ubase_dbgfs *dbgfs,
			    struct ubase_dbg_dentry_info *dirs, u32 root_idx)
{
	int ret;

	if (!dev || !dbgfs || !dirs || !dbgfs->cmd_info)
		return -EINVAL;

	ret = ubase_dbg_create_dir(dev, dirs, root_idx);
	if (ret) {
		dev_err(dev,
			"failed to create ubase debugfs dirs, ret = %d.\n", ret);
		return ret;
	}

	ret = ubase_dbg_create_file(dev, dbgfs, dirs);
	if (ret)
		dev_err(dev,
			"failed to create ubase debugfs files, ret = %d.\n", ret);

	return ret;
}
EXPORT_SYMBOL(ubase_dbg_create_dentry);

int ubase_dbg_init(struct ubase_dev *udev)
{
	struct ubase_dbg_dentry_info dentry[UBASE_DBG_DENTRY_ROOT + 1] = {0};
	const char *name = dev_name(udev->dev);
	struct device *dev = udev->dev;
	int ret;

	udev->dbgfs.dentry = debugfs_create_dir(name, ubase_dbgfs_root);
	if (IS_ERR(udev->dbgfs.dentry)) {
		ubase_err(udev, "failed to create ubase debugfs root dir.\n");
		return PTR_ERR(udev->dbgfs.dentry);
	}

	memcpy(dentry, ubase_dbg_dentry, sizeof(dentry));
	dentry[UBASE_DBG_DENTRY_ROOT].dentry = udev->dbgfs.dentry;
	udev->dbgfs.cmd_info = ubase_dbg_cmd;
	udev->dbgfs.cmd_info_size = ARRAY_SIZE(ubase_dbg_cmd);

	ret = ubase_dbg_create_dentry(dev, &udev->dbgfs, dentry,
				      ARRAY_SIZE(dentry) - 1);
	if (ret) {
		ubase_err(udev,
			  "failed to create ubase debugfs dentry, ret = %d.\n",
			  ret);
		goto create_dentry_err;
	}

	return 0;

create_dentry_err:
	debugfs_remove_recursive(udev->dbgfs.dentry);

	return ret;
}

void ubase_dbg_uninit(struct ubase_dev *udev)
{
	debugfs_remove_recursive(udev->dbgfs.dentry);
}

int ubase_dbg_register_debugfs(void)
{
#define UBASE_DBGFS_ROOT	"ubase"

	ubase_dbgfs_root = debugfs_create_dir(UBASE_DBGFS_ROOT, NULL);
	if (IS_ERR(ubase_dbgfs_root))
		return PTR_ERR(ubase_dbgfs_root);

	return 0;
}

void ubase_dbg_unregister_debugfs(void)
{
	debugfs_remove_recursive(ubase_dbgfs_root);
}

/**
 * ubase_diag_debugfs_root() - get ubase debugfs root dentry
 * @adev: auxiliary device
 *
 * This function is used to get ubase debugfs root dentry.
 *
 * Context: Any context.
 * Return: NULL if the adev is empty, otherwise the pointer to struct dentry
 */
struct dentry *ubase_diag_debugfs_root(struct auxiliary_device *adev)
{
	if (!adev)
		return NULL;

	return __ubase_get_udev_by_adev(adev)->dbgfs.dentry;
}
EXPORT_SYMBOL(ubase_diag_debugfs_root);

/**
 * ubase_dbg_format_time() - formatted the time output to seq file
 * @time: time value
 * @s: seq_file
 *
 * The function outputs the time in the format of
 * 'week month day hour:minute:second year' to seq_file.
 *
 * Context: Any context.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_dbg_format_time(time64_t time, struct seq_file *s)
{
#define YEAR_OFFSET 1900
	const char week[7][4] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
	const char month[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
				   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
	struct tm t;

	if (!s)
		return -EINVAL;

	time64_to_tm(time, 0, &t);

	seq_printf(s, "%s %s %02d %02d:%02d:%02d %ld", week[t.tm_wday],
		   month[t.tm_mon], t.tm_mday, t.tm_hour, t.tm_min,
		   t.tm_sec, t.tm_year + YEAR_OFFSET);
	return 0;
}
EXPORT_SYMBOL(ubase_dbg_format_time);
