// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <linux/phy.h>
#include <ub/ubase/ubase_comm_cmd.h>
#include <ub/ubase/ubase_comm_stats.h>

#include "unic.h"
#include "unic_dev.h"
#include "unic_hw.h"
#include "unic_lb.h"
#include "unic_netdev.h"
#include "unic_stats.h"

static u32 cmdq_regs_addr[] = {
	UNIC_TX_CMDQ_DEPTH,
	UNIC_TX_CMDQ_TAIL,
	UNIC_TX_CMDQ_HEAD,
	UNIC_RX_CMDQ_DEPTH,
	UNIC_RX_CMDQ_TAIL,
	UNIC_RX_CMDQ_HEAD,
	UNIC_CMDQ_INT_GEN,
	UNIC_CMDQ_INT_SCR,
	UNIC_CMDQ_INT_MASK,
	UNIC_CMDQ_INT_STS,
};

static u32 ctrlq_regs_addr[] = {
	UNIC_TX_CTRLQ_DEPTH,
	UNIC_TX_CTRLQ_TAIL,
	UNIC_TX_CTRLQ_HEAD,
	UNIC_RX_CTRLQ_DEPTH,
	UNIC_RX_CTRLQ_TAIL,
	UNIC_RX_CTRLQ_HEAD,
	UNIC_CTRLQ_INT_GEN,
	UNIC_CTRLQ_INT_SCR,
	UNIC_CTRLQ_INT_MASK,
	UNIC_CTRLQ_INT_STS,
};

static const struct unic_res_regs_group unic_res_reg_arr[] = {
	{
		.tag = UNIC_TAG_CMDQ,
		.regs_addr = cmdq_regs_addr,
		.regs_count = ARRAY_SIZE(cmdq_regs_addr),
		.is_supported = NULL
	},
	{
		.tag = UNIC_TAG_CTRLQ,
		.regs_addr = ctrlq_regs_addr,
		.regs_count = ARRAY_SIZE(ctrlq_regs_addr),
		.is_supported = ubase_adev_ctrlq_supported
	},
};

static bool unic_dfx_reg_support(struct unic_dev *unic_dev, u32 property)
{
	if (((property & UBASE_SUP_UBL) && unic_dev_ubl_supported(unic_dev)) ||
	    ((property & UBASE_SUP_ETH) && unic_dev_eth_mac_supported(unic_dev)))
		return true;

	return false;
}

static struct unic_dfx_regs_group unic_dfx_reg_arr[] = {
	{
		.regs_idx = UNIC_REG_NUM_IDX_TA,
		.tag = UNIC_TAG_TA,
		.opcode = UBASE_OPC_DFX_TA_REG,
		.property = UBASE_SUP_UBL_ETH,
		.is_supported = unic_dfx_reg_support
	},
	{
		.regs_idx = UNIC_REG_NUM_IDX_TP,
		.tag = UNIC_TAG_TP,
		.opcode = UBASE_OPC_DFX_TP_REG,
		.property = UBASE_SUP_UBL_ETH,
		.is_supported = unic_dfx_reg_support
	},
	{
		.regs_idx = UNIC_REG_NUM_IDX_BA,
		.tag = UNIC_TAG_BA,
		.opcode = UBASE_OPC_DFX_BA_REG,
		.property = UBASE_SUP_UBL_ETH,
		.is_supported = unic_dfx_reg_support
	},
	{
		.regs_idx = UNIC_REG_NUM_IDX_NL,
		.tag = UNIC_TAG_NL,
		.opcode = UBASE_OPC_DFX_NL_REG,
		.property = UBASE_SUP_UBL,
		.is_supported = unic_dfx_reg_support
	},
	{
		.regs_idx = UNIC_REG_NUM_IDX_DL,
		.tag = UNIC_TAG_DL,
		.opcode = UBASE_OPC_DFX_DL_REG,
		.property = UBASE_SUP_UBL,
		.is_supported = unic_dfx_reg_support
	},
	{
		.regs_idx = UNIC_REG_NUM_IDX_HIMAC,
		.tag = UNIC_TAG_HIMAC,
		.opcode = UBASE_OPC_DFX_HIMAC_REG,
		.property = UBASE_SUP_ETH,
		.is_supported = unic_dfx_reg_support
	},
};

static const struct unic_stats_desc unic_sq_stats_str[] = {
	{"pad_err", UNIC_SQ_STATS_FIELD_OFFSET(pad_err)},
	{"packets", UNIC_SQ_STATS_FIELD_OFFSET(packets)},
	{"bytes", UNIC_SQ_STATS_FIELD_OFFSET(bytes)},
	{"busy", UNIC_SQ_STATS_FIELD_OFFSET(busy)},
	{"more", UNIC_SQ_STATS_FIELD_OFFSET(more)},
	{"restart_queue", UNIC_SQ_STATS_FIELD_OFFSET(restart_queue)},
	{"over_max_sge_num", UNIC_SQ_STATS_FIELD_OFFSET(over_max_sge_num)},
	{"csum_err", UNIC_SQ_STATS_FIELD_OFFSET(csum_err)},
	{"ci_mismatch", UNIC_SQ_STATS_FIELD_OFFSET(ci_mismatch)},
	{"vlan_err", UNIC_SQ_STATS_FIELD_OFFSET(vlan_err)},
	{"fd_cnt", UNIC_SQ_STATS_FIELD_OFFSET(fd_cnt)},
	{"drop_cnt", UNIC_SQ_STATS_FIELD_OFFSET(drop_cnt)},
	{"cfg5_drop_cnt", UNIC_SQ_STATS_FIELD_OFFSET(cfg5_drop_cnt)},
	{"polled_old_pi", UNIC_SQ_STATS_FIELD_OFFSET(polled_old_pi)},
	{"polled_skb_null", UNIC_SQ_STATS_FIELD_OFFSET(polled_skb_null)},
	{"pi_ci_over_depth", UNIC_SQ_STATS_FIELD_OFFSET(pi_ci_over_depth)}
};

static const struct unic_stats_desc unic_rq_stats_str[] = {
	{"alloc_skb_err", UNIC_RQ_STATS_FIELD_OFFSET(alloc_skb_err)},
	{"packets", UNIC_RQ_STATS_FIELD_OFFSET(packets)},
	{"bytes", UNIC_RQ_STATS_FIELD_OFFSET(bytes)},
	{"err_pkt_len_cnt", UNIC_RQ_STATS_FIELD_OFFSET(err_pkt_len_cnt)},
	{"doi_cnt", UNIC_RQ_STATS_FIELD_OFFSET(doi_cnt)},
	{"trunc_cnt", UNIC_RQ_STATS_FIELD_OFFSET(trunc_cnt)},
	{"multicast", UNIC_RQ_STATS_FIELD_OFFSET(multicast)},
	{"l2_err", UNIC_RQ_STATS_FIELD_OFFSET(l2_err)},
	{"l3_l4_csum_err", UNIC_RQ_STATS_FIELD_OFFSET(l3_l4_csum_err)},
	{"alloc_frag_err", UNIC_RQ_STATS_FIELD_OFFSET(alloc_frag_err)},
	{"csum_complete", UNIC_RQ_STATS_FIELD_OFFSET(csum_complete)},
};

static const struct unic_mac_stats_desc unic_eth_stats_str[] = {
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_pause_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_pfc_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_pri0_pfc_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_pri1_pfc_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_pri2_pfc_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_pri3_pfc_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_pri4_pfc_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_pri5_pfc_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_pri6_pfc_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_pri7_pfc_pkts),

	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_pause_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_pfc_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_pri0_pfc_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_pri1_pfc_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_pri2_pfc_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_pri3_pfc_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_pri4_pfc_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_pri5_pfc_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_pri6_pfc_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_pri7_pfc_pkts),

	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_64_octets_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_65_127_octets_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_128_255_octets_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_256_511_octets_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_512_1023_octets_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_1024_1518_octets_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_1519_2047_octets_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_2048_4095_octets_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_4096_8191_octets_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_8192_9216_octets_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_9217_12287_octets_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_12288_16383_octets_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_1519_max_octets_bad_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_1519_max_octets_good_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_oversize_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_jabber_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_bad_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_bad_octets),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_good_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_good_octets),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_total_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_total_octets),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_unicast_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_multicast_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_broadcast_pkts),

	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_fragment_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_undersize_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_undermin_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_mac_ctrl_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_unfilter_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_1588_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_err_all_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_from_app_good_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_from_app_bad_pkts),

	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_64_octets_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_65_127_octets_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_128_255_octets_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_256_511_octets_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_512_1023_octets_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_1024_1518_octets_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_1519_2047_octets_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_2048_4095_octets_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_4096_8191_octets_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_8192_9216_octets_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_9217_12287_octets_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_12288_16383_octets_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_1519_max_octets_bad_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_1519_max_octets_good_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_oversize_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_jabber_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_bad_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_bad_octets),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_good_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_good_octets),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_total_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_total_octets),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_unicast_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_multicast_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_broadcast_pkts),

	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_fragment_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_undersize_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_undermin_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_mac_ctrl_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_unfilter_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_symbol_err_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_fcs_err_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_send_app_good_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_send_app_bad_pkts),

	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_merge_frame_ass_error_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_merge_frame_ass_ok_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(tx_merge_frame_frag_count),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_merge_frame_ass_error_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_merge_frame_ass_ok_pkts),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_merge_frame_frag_count),
	UNIC_ETH_MAC_STATS_FLD_CAP_1(rx_merge_frame_smd_error_pkts),
};

static int unic_get_dfx_reg_num(struct unic_dev *unic_dev, u32 *reg_num,
				u32 reg_arr_size)
{
	struct ubase_cmd_buf in, out;
	int ret;

	ubase_fill_inout_buf(&in, UBASE_OPC_DFX_REG_NUM, true, 0, NULL);
	ubase_fill_inout_buf(&out, UBASE_OPC_DFX_REG_NUM, true,
			     reg_arr_size * sizeof(u32), reg_num);
	ret = ubase_cmd_send_inout(unic_dev->comdev.adev, &in, &out);
	if (ret)
		unic_err(unic_dev,
			 "failed to query dfx reg num, ret = %d.\n", ret);

	return ret;
}

static int unic_get_res_regs_len(struct unic_dev *unic_dev,
				 const struct unic_res_regs_group *reg_arr,
				 u32 reg_arr_size)
{
	u32 i, count = 0;

	for (i = 0; i < reg_arr_size; i++) {
		if (reg_arr[i].is_supported &&
		    !reg_arr[i].is_supported(unic_dev->comdev.adev))
			continue;

		count += reg_arr[i].regs_count * sizeof(u32) +
			 sizeof(struct unic_tlv_hdr);
	}

	return count;
}

static int unic_get_dfx_regs_len(struct unic_dev *unic_dev,
				 struct unic_dfx_regs_group *reg_arr,
				 u32 reg_arr_size, u32 *reg_num)
{
	u32 i, count = 0;

	for (i = 0; i < reg_arr_size; i++) {
		if (!reg_arr[i].is_supported(unic_dev, reg_arr[i].property))
			continue;

		if (!reg_num[reg_arr[i].regs_idx])
			continue;

		count += sizeof(struct unic_tlv_hdr) + sizeof(u32) *
			 reg_num[reg_arr[i].regs_idx];
	}

	return count;
}

int unic_get_regs_len(struct net_device *netdev)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	u32 reg_arr_size;
	int count = 0;
	u32 *reg_num;
	int ret;

	if (unic_resetting(netdev))
		return -EBUSY;

	count += unic_get_res_regs_len(unic_dev, unic_res_reg_arr,
				       ARRAY_SIZE(unic_res_reg_arr));
	reg_arr_size = ARRAY_SIZE(unic_dfx_reg_arr);
	reg_num = kcalloc(reg_arr_size, sizeof(u32), GFP_KERNEL);
	if (!reg_num)
		return -ENOMEM;

	ret = unic_get_dfx_reg_num(unic_dev, reg_num, reg_arr_size);
	if (ret) {
		kfree(reg_num);
		return -EBUSY;
	}

	count += unic_get_dfx_regs_len(unic_dev, unic_dfx_reg_arr,
				       reg_arr_size, reg_num);
	kfree(reg_num);
	return count;
}

static u16 unic_fetch_res_regs(struct unic_dev *unic_dev, u8 *data, u16 tag,
			       u32 *regs_addr_arr, u32 reg_num)
{
	struct unic_tlv_hdr *tlv = (struct unic_tlv_hdr *)data;
	u32 *reg = (u32 *)(data + sizeof(struct unic_tlv_hdr));
	u32 i;

	tlv->tag = tag;
	tlv->len = sizeof(struct unic_tlv_hdr) + reg_num * sizeof(u32);

	for (i = 0; i < reg_num; i++)
		*reg++ = unic_read_reg(unic_dev, regs_addr_arr[i]);

	return tlv->len;
}

static u32 unic_get_res_regs(struct unic_dev *unic_dev, u8 *data)
{
	u32 i, data_len = 0;

	for (i = 0; i < ARRAY_SIZE(unic_res_reg_arr); i++) {
		if (unic_res_reg_arr[i].is_supported &&
		    !unic_res_reg_arr[i].is_supported(unic_dev->comdev.adev))
			continue;

		data_len += unic_fetch_res_regs(unic_dev, data + data_len,
						unic_res_reg_arr[i].tag,
						unic_res_reg_arr[i].regs_addr,
						unic_res_reg_arr[i].regs_count);
	}

	return data_len;
}

static int unic_query_regs_data(struct unic_dev *unic_dev, u8 *data,
				u32 reg_num, u16 opcode)
{
	u32 *reg = (u32 *)(data + sizeof(struct unic_tlv_hdr));
	struct ubase_cmd_buf in, out;
	u32 *out_regs;
	int ret;
	u32 i;

	out_regs = kcalloc(reg_num, sizeof(u32), GFP_KERNEL);
	if (!out_regs)
		return -ENOMEM;

	ubase_fill_inout_buf(&in, opcode, true, 0, NULL);
	ubase_fill_inout_buf(&out, opcode, true, reg_num * sizeof(u32),
			     out_regs);
	ret = ubase_cmd_send_inout(unic_dev->comdev.adev, &in, &out);
	if (ret) {
		unic_err(unic_dev,
			 "failed to send getting reg cmd(0x%x), ret = %d.\n",
			 opcode, ret);
		goto err_send_cmd;
	}

	for (i = 0; i < reg_num; i++)
		*reg++ = le32_to_cpu(*(out_regs + i));

err_send_cmd:
	kfree(out_regs);

	return ret;
}

static int unic_get_dfx_regs(struct unic_dev *unic_dev, u8 *data,
			     struct unic_dfx_regs_group *reg_arr,
			     u32 reg_arr_size, u32 *reg_num)
{
	struct unic_tlv_hdr *tlv;
	u16 idx;
	int ret;
	u32 i;

	for (i = 0; i < reg_arr_size; i++) {
		if (!reg_arr[i].is_supported(unic_dev, reg_arr[i].property))
			continue;

		idx = reg_arr[i].regs_idx;
		if (!reg_num[idx])
			continue;

		ret = unic_query_regs_data(unic_dev, data, reg_num[idx],
					   reg_arr[i].opcode);
		if (ret) {
			unic_err(unic_dev,
				 "failed to query dfx regs, ret = %d.\n", ret);
			return ret;
		}

		tlv = (struct unic_tlv_hdr *)data;
		tlv->tag = reg_arr[i].tag;
		tlv->len = sizeof(*tlv) + reg_num[idx] * sizeof(u32);
		data += tlv->len;
	}

	return 0;
}

void unic_get_regs(struct net_device *netdev, struct ethtool_regs *cmd,
		   void *data)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	u8 *pdata = (u8 *)data;
	u32 reg_arr_size;
	u32 *reg_num;
	int ret;

	if (unic_resetting(netdev)) {
		unic_err(unic_dev, "dev resetting, could not get regs.\n");
		return;
	}

	reg_arr_size = ARRAY_SIZE(unic_dfx_reg_arr);
	reg_num = kcalloc(reg_arr_size, sizeof(u32), GFP_KERNEL);
	if (!reg_num) {
		unic_err(unic_dev, "failed to alloc reg num array.\n");
		return;
	}

	pdata += unic_get_res_regs(unic_dev, pdata);
	ret = unic_get_dfx_reg_num(unic_dev, reg_num, reg_arr_size);
	if (ret) {
		kfree(reg_num);
		return;
	}

	ret = unic_get_dfx_regs(unic_dev, pdata, unic_dfx_reg_arr,
				reg_arr_size, reg_num);
	if (ret)
		unic_err(unic_dev, "failed to get dfx regs, ret = %d.\n", ret);

	kfree(reg_num);
}

static u64 *unic_get_queues_stats(struct unic_dev *unic_dev,
				  const struct unic_stats_desc *stats,
				  u32 stats_size, enum unic_queue_type type,
				  u64 *data)
{
	struct unic_channel *c;
	u32 i, j;
	u8 *q;

	for (i = 0; i < unic_dev->channels.num; i++) {
		c = &unic_dev->channels.c[i];
		q = (type == UNIC_QUEUE_TYPE_SQ) ? (u8 *)c->sq : (u8 *)c->rq;
		for (j = 0; j < stats_size; j++) {
			*data = UNIC_STATS_READ(q, stats[j].offset);
			data++;
		}
	}

	return data;
}

static void unic_get_mac_stats(struct unic_dev *unic_dev, u64 *data)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct ubase_caps *caps = ubase_get_dev_caps(adev);
	const struct unic_mac_stats_desc *stats_desc;
	struct ubase_eth_mac_stats mac_stats = {0};
	u32 stats_num = caps->mac_stats_num;
	u32 i, stats_desc_num;
	u8 *stats;
	int ret;

	if (unic_dev_ubl_supported(unic_dev))
		return;

	stats_desc = unic_eth_stats_str;
	stats_desc_num = ARRAY_SIZE(unic_eth_stats_str);
	ret = ubase_get_eth_port_stats(adev, &mac_stats);
	if (ret)
		return;

	stats = (u8 *)&mac_stats;
	for (i = 0; i < stats_desc_num; i++) {
		if (stats_desc[i].stats_num > stats_num)
			continue;

		*data = UNIC_STATS_READ(stats, stats_desc[i].offset);
		data++;
	}
}

void unic_get_stats(struct net_device *netdev,
		    struct ethtool_stats *stats, u64 *data)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	u64 *p = data;

	if (unic_resetting(netdev) || !unic_dev->channels.c) {
		unic_err(unic_dev,
			 "dev resetting or channel is null, could not get stats.\n");
		return;
	}

	p = unic_get_queues_stats(unic_dev, unic_sq_stats_str,
				  ARRAY_SIZE(unic_sq_stats_str),
				  UNIC_QUEUE_TYPE_SQ, p);

	p = unic_get_queues_stats(unic_dev, unic_rq_stats_str,
				  ARRAY_SIZE(unic_rq_stats_str),
				  UNIC_QUEUE_TYPE_RQ, p);
	unic_get_mac_stats(unic_dev, p);
}

static u8 *unic_get_strings(u8 *data, const char *prefix, u32 num,
			    const struct unic_stats_desc *strs, u32 stats_size)
{
	u32 i, j;

	for (i = 0; i < num; i++) {
		for (j = 0; j < stats_size; j++) {
			data[ETH_GSTRING_LEN - 1] = '\0';

			if (prefix)
				scnprintf(data, ETH_GSTRING_LEN - 1, "%s%u_%s",
					  prefix, i, strs[j].desc);
			else
				scnprintf(data, ETH_GSTRING_LEN - 1, "%s",
					  strs[j].desc);

			data += ETH_GSTRING_LEN;
		}
	}

	return data;
}

static u8 *unic_get_queues_strings(struct unic_dev *unic_dev, u8 *data)
{
	u32 channel_num = unic_dev->channels.num;

	/* get desc for Tx */
	data = unic_get_strings(data, "txq", channel_num, unic_sq_stats_str,
				ARRAY_SIZE(unic_sq_stats_str));

	/* get desc for Rx */
	data = unic_get_strings(data, "rxq", channel_num, unic_rq_stats_str,
				ARRAY_SIZE(unic_rq_stats_str));

	return data;
}

static void
unic_get_mac_strings(struct unic_dev *unic_dev, u8 *data,
		     const struct unic_mac_stats_desc *strs, u32 size)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct ubase_caps *caps = ubase_get_dev_caps(adev);
	u32 stats_num = caps->mac_stats_num;
	u32 i;

	if (!ubase_adev_mac_stats_supported(adev))
		return;

	for (i = 0; i < size; i++) {
		if (strs[i].stats_num > stats_num)
			continue;

		snprintf(data, ETH_GSTRING_LEN, "%s", strs[i].desc);
		data += ETH_GSTRING_LEN;
	}
}

void unic_get_stats_strings(struct net_device *netdev, u32 stringset, u8 *data)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	char unic_test_strs[][ETH_GSTRING_LEN] = {
		"App      Loopback test ",
		"Serdes   serial Loopback test",
		"Serdes   parallel Loopback test",
		"External Loopback test",
	};
	u8 *p = data;

	switch (stringset) {
	case ETH_SS_STATS:
		p = unic_get_queues_strings(unic_dev, p);
		if (unic_dev_ubl_supported(unic_dev))
			break;

		unic_get_mac_strings(unic_dev, p, unic_eth_stats_str,
				     ARRAY_SIZE(unic_eth_stats_str));
		break;
	case ETH_SS_TEST:
		memcpy(data, unic_test_strs, sizeof(unic_test_strs));
		break;
	default:
		break;
	}
}

static int unic_get_mac_count(struct unic_dev *unic_dev,
			      const struct unic_mac_stats_desc strs[], u32 size)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct ubase_caps *caps = ubase_get_dev_caps(adev);
	u32 stats_num = caps->mac_stats_num;
	int count = 0;
	u32 i;

	if (!ubase_adev_mac_stats_supported(adev))
		return 0;

	for (i = 0; i < size; i++) {
		if (strs[i].stats_num <= stats_num)
			count++;
	}

	return count;
}

int unic_get_sset_count(struct net_device *netdev, int stringset)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);
	u32 channel_num = unic_dev->channels.num;
	int count;

	switch (stringset) {
	case ETH_SS_STATS:
		count = ARRAY_SIZE(unic_sq_stats_str) * channel_num;
		count += ARRAY_SIZE(unic_rq_stats_str) * channel_num;
		if (unic_dev_ubl_supported(unic_dev))
			break;

		count += unic_get_mac_count(unic_dev, unic_eth_stats_str,
					    ARRAY_SIZE(unic_eth_stats_str));
		break;
	case ETH_SS_TEST:
		count = unic_get_selftest_count(unic_dev);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return count;
}

static void unic_get_fec_stats_total(struct unic_dev *unic_dev, u8 stats_flags,
				     struct ethtool_fec_stats *fec_stats)
{
	struct unic_fec_stats_item *total = &unic_dev->stats.fec_stats.total;

	if (stats_flags & UNIC_FEC_CORR_BLOCKS)
		fec_stats->corrected_blocks.total = total->corr_blocks;
	if (stats_flags & UNIC_FEC_UNCORR_BLOCKS)
		fec_stats->uncorrectable_blocks.total = total->uncorr_blocks;
	if (stats_flags & UNIC_FEC_CORR_BITS)
		fec_stats->corrected_bits.total = total->corr_bits;
}

static void unic_get_fec_stats_lanes(struct unic_dev *unic_dev, u8 stats_flags,
				     struct ethtool_fec_stats *fec_stats)
{
	u8 lane_num = unic_dev->stats.fec_stats.lane_num;
	u8 i;

	if (lane_num == 0 || lane_num > UNIC_FEC_STATS_MAX_LANE) {
		unic_err(unic_dev,
			 "fec stats lane number is invalid, lane_num = %hhu.\n",
			 lane_num);
		return;
	}

	for (i = 0; i < lane_num; i++) {
		if (stats_flags & UNIC_FEC_CORR_BLOCKS)
			fec_stats->corrected_blocks.lanes[i] =
				unic_dev->stats.fec_stats.lane[i].corr_blocks;
		if (stats_flags & UNIC_FEC_UNCORR_BLOCKS)
			fec_stats->uncorrectable_blocks.lanes[i] =
				unic_dev->stats.fec_stats.lane[i].uncorr_blocks;
		if (stats_flags & UNIC_FEC_CORR_BITS)
			fec_stats->corrected_bits.lanes[i] =
				unic_dev->stats.fec_stats.lane[i].corr_bits;
	}
}

static void unic_get_ubl_fec_stats(struct unic_dev *unic_dev,
				   struct ethtool_fec_stats *fec_stats)
{
	u32 fec_mode = unic_dev->hw.mac.fec_mode;
	u8 stats_flags = 0;

	switch (fec_mode) {
	case ETHTOOL_FEC_RS:
		stats_flags = UNIC_FEC_UNCORR_BLOCKS | UNIC_FEC_CORR_BITS;
		unic_get_fec_stats_total(unic_dev, stats_flags, fec_stats);
		break;
	default:
		unic_err(unic_dev,
			 "fec stats is not supported in mode(0x%x).\n",
			 fec_mode);
		break;
	}
}

static void unic_get_eth_fec_stats(struct unic_dev *unic_dev,
				   struct ethtool_fec_stats *fec_stats)
{
	u32 fec_mode = unic_dev->hw.mac.fec_mode;
	u8 stats_flags = 0;

	switch (fec_mode) {
	case ETHTOOL_FEC_RS:
		stats_flags = UNIC_FEC_CORR_BLOCKS | UNIC_FEC_UNCORR_BLOCKS;
		unic_get_fec_stats_total(unic_dev, stats_flags, fec_stats);
		unic_get_fec_stats_lanes(unic_dev, UNIC_FEC_CORR_BITS, fec_stats);
		break;
	default:
		unic_err(unic_dev,
			 "fec stats is not supported in mode(0x%x).\n",
			 fec_mode);
		break;
	}
}

void unic_get_fec_stats(struct net_device *ndev,
			struct ethtool_fec_stats *fec_stats)
{
	struct unic_dev *unic_dev = netdev_priv(ndev);

	if (!unic_dev_fec_stats_supported(unic_dev) ||
	    unic_dev->hw.mac.fec_mode == ETHTOOL_FEC_OFF)
		return;

	if (unic_update_fec_stats(unic_dev))
		return;

	if (unic_dev_ubl_supported(unic_dev))
		unic_get_ubl_fec_stats(unic_dev, fec_stats);
	else
		unic_get_eth_fec_stats(unic_dev, fec_stats);
}
