// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2020-2022 Hisilicon Limited.

#include "core.h"

#include "hns3_cmdq.h"
#include "hns3_verbs.h"

int hns3_roh_set_eid(struct roh_device *rohdev, struct roh_eid_attr *eid_attr)
{
	struct hns3_roh_device *hroh_dev = to_hroh_dev(rohdev);
	struct hns3_roh_set_eid_info *req;
	struct hns3_roh_desc desc;
	int ret;

	hns3_roh_cmdq_setup_basic_desc(&desc, HNS3_ROH_OPC_SET_EID, false);

	req = (struct hns3_roh_set_eid_info *)desc.data;
	req->base_eid = cpu_to_le32(eid_attr->base);
	req->num_eid = cpu_to_le32(eid_attr->num);

	ret = hns3_roh_cmdq_send(hroh_dev, &desc, 1);
	if (ret) {
		dev_err(hroh_dev->dev, "failed to set eid, ret = %d\n", ret);
		return ret;
	}

	return 0;
}

static const char * const hns3_roh_hw_stats_name_public[] = {
	"mac_tx_packet_num",
	"mac_rx_packet_num",
	"reserved",
	"mac_tx_0_min_pkt_num",
	"mac_tx_min_64_pkt_num",
	"mac_tx_65_127_pkt_num",
	"mac_tx_128_255_pkt_num",
	"mac_tx_256_511_pkt_num",
	"mac_tx_512_1023_pkt_num",
	"mac_tx_1024_1518_pkt_num",
	"mac_tx_1519_2047_pkt_num",
	"mac_tx_2048_4095_pkt_num",
	"mac_tx_4096_max_pkt_num",
	"mac_tx_over_max_pkt_num",
	"mac_tx_err_pkt_num",
	"mac_tx_tc0_pkt_num",
	"mac_tx_tc1_pkt_num",
	"mac_tx_tc2_pkt_num",
	"mac_tx_tc3_pkt_num",
	"mac_tx_tc4_pkt_num",
	"mac_tx_tc5_pkt_num",
	"mac_tx_tc6_pkt_num",
	"mac_tx_tc7_pkt_num",
	"mac_tx_tc0_oct_num",
	"mac_tx_tc1_oct_num",
	"mac_tx_tc2_oct_num",
	"mac_tx_tc3_oct_num",
	"mac_tx_tc4_oct_num",
	"mac_tx_tc5_oct_num",
	"mac_tx_tc6_oct_num",
	"mac_tx_tc7_oct_num",
	"mac_tx_rdma_pkt_num",
	"mac_tx_ip_pkt_num",
	"mac_tx_udmp_eid_pkt_num",
	"mac_tx_udmp_dr_pkt_num",
	"mac_tx_rdma_oct_num",
	"mac_tx_ip_oct_num",
	"mac_tx_udmp_eid_oct_num",
	"mac_tx_udmp_dr_oct_num",
	"mac_tx_udmp_uap_pkt_num",
	"mac_tx_udmp_uap_oct_num",
	"mac_rx_udmp_uap_pkt_num",
	"mac_rx_udmp_uap_oct_num",
	"mac_rx_0_min_pkt_num",
	"mac_rx_min_64_pkt_num",
	"mac_rx_65_127_pkt_num",
	"mac_rx_128_255_pkt_num",
	"mac_rx_256_511_pkt_num",
	"mac_rx_512_1023_pkt_num",
	"mac_rx_1024_1518_pkt_num",
	"mac_rx_1519_2047_pkt_num",
	"mac_rx_2048_4095_pkt_num",
	"mac_rx_4096_max_pkt_num",
	"mac_rx_over_max_pkt_num",
	"mac_rx_err_pkt_num",
	"mac_rx_tc0_pkt_num",
	"mac_rx_tc1_pkt_num",
	"mac_rx_tc2_pkt_num",
	"mac_rx_tc3_pkt_num",
	"mac_rx_tc4_pkt_num",
	"mac_rx_tc5_pkt_num",
	"mac_rx_tc6_pkt_num",
	"mac_rx_tc7_pkt_num",
	"mac_rx_tc0_oct_num",
	"mac_rx_tc1_oct_num",
	"mac_rx_tc2_oct_num",
	"mac_rx_tc3_oct_num",
	"mac_rx_tc4_oct_num",
	"mac_rx_tc5_oct_num",
	"mac_rx_tc6_oct_num",
	"mac_rx_tc7_oct_num",
	"mac_rx_rdma_pkt_num",
	"mac_rx_ip_pkt_num",
	"mac_rx_udmp_eid_pkt_num",
	"mac_rx_udmp_dr_pkt_num",
	"mac_rx_rdma_oct_num",
	"mac_rx_ip_oct_num",
	"mac_rx_udmp_eid_oct_num",
	"mac_rx_udmp_dr_oct_num",
};

static const char * const hns3_roh_hw_stats_name_private[] = {
	"mac_tx_block_num",
	"mac_tx_flit_num",
	"mac_tx_icrd_vna_total_used",
	"mac_tx_icrd_vna_total_released",
	"mac_tx_tc0_icrd_vn_total_used",
	"mac_tx_tc1_icrd_vn_total_used",
	"mac_tx_tc2_icrd_vn_total_used",
	"mac_tx_tc3_icrd_vn_total_used",
	"mac_tx_tc4_icrd_vn_total_used",
	"mac_tx_tc5_icrd_vn_total_used",
	"mac_tx_tc6_icrd_vn_total_used",
	"mac_tx_tc7_icrd_vn_total_used",
	"mac_tx_tc0_icrd_vn_total_released",
	"mac_tx_tc1_icrd_vn_total_released",
	"mac_tx_tc2_icrd_vn_total_released",
	"mac_tx_tc3_icrd_vn_total_released",
	"mac_tx_tc4_icrd_vn_total_released",
	"mac_tx_tc5_icrd_vn_total_released",
	"mac_tx_tc6_icrd_vn_total_released",
	"mac_tx_tc7_icrd_vn_total_released",
	"mac_tx_rdma_inc_pkt_num",
	"mac_tx_rdma_inc_oct_num",
	"mac_rx_rdma_inc_pkt_num",
	"mac_rx_rdma_inc_oct_num",
	"mac_rx_block_num",
	"mac_rx_flit_num",
	"mac_rx_icrd_vna_total_used",
	"mac_rx_icrd_vna_total_released",
	"mac_rx_tc0_icrd_vn_total_used",
	"mac_rx_tc1_icrd_vn_total_used",
	"mac_rx_tc2_icrd_vn_total_used",
	"mac_rx_tc3_icrd_vn_total_used",
	"mac_rx_tc4_icrd_vn_total_used",
	"mac_rx_tc5_icrd_vn_total_used",
	"mac_rx_tc6_icrd_vn_total_used",
	"mac_rx_tc7_icrd_vn_total_used",
	"mac_rx_tc0_icrd_vn_total_released",
	"mac_rx_tc1_icrd_vn_total_released",
	"mac_rx_tc2_icrd_vn_total_released",
	"mac_rx_tc3_icrd_vn_total_released",
	"mac_rx_tc4_icrd_vn_total_released",
	"mac_rx_tc5_icrd_vn_total_released",
	"mac_rx_tc6_icrd_vn_total_released",
	"mac_rx_tc7_icrd_vn_total_released",
};

struct roh_mib_stats *hns3_roh_alloc_hw_stats(struct roh_device *rohdev, enum roh_mib_type mib_type)
{
	struct roh_mib_stats *stats = NULL;
	int num_counters;

	switch (mib_type) {
	case ROH_MIB_PUBLIC:
		num_counters = ARRAY_SIZE(hns3_roh_hw_stats_name_public);
		stats = kzalloc(sizeof(*stats) + num_counters * sizeof(u64), GFP_KERNEL);
		if (!stats)
			return NULL;
		stats->names = hns3_roh_hw_stats_name_public;
		stats->num_counters = num_counters;
		break;
	case ROH_MIB_PRIVATE:
		num_counters = ARRAY_SIZE(hns3_roh_hw_stats_name_private);
		stats = kzalloc(sizeof(*stats) + num_counters * sizeof(u64), GFP_KERNEL);
		if (!stats)
			return NULL;
		stats->names = hns3_roh_hw_stats_name_private;
		stats->num_counters = num_counters;
		break;
	default:
		break;
	}

	return stats;
}

int hns3_roh_get_hw_stats(struct roh_device *rohdev, struct roh_mib_stats *stats,
			  enum roh_mib_type mib_type)
{
	struct hns3_roh_device *hroh_dev = to_hroh_dev(rohdev);
	u64 *data = (u64 *)(stats->value);
	enum hns3_roh_opcode_type opcode;
	struct hns3_roh_desc *desc;
	int start, stats_num;
	__le64 *desc_data;
	u32 desc_num;
	int i, j;
	int ret;

	if (mib_type != ROH_MIB_PUBLIC && mib_type != ROH_MIB_PRIVATE) {
		ret = -EINVAL;
		goto err_out;
	}

	if (mib_type == ROH_MIB_PUBLIC)
		desc_num = 1 + DIV_ROUND_UP(stats->num_counters - HNS3_ROH_RD_FIRST_STATS_NUM,
			HNS3_ROH_RD_OTHER_STATS_NUM);
	else
		desc_num = 1 + DIV_ROUND_UP(stats->num_counters, HNS3_ROH_RD_OTHER_STATS_NUM);
	desc = kcalloc(desc_num, sizeof(struct hns3_roh_desc), GFP_KERNEL);
	if (!desc) {
		ret = -ENOMEM;
		goto err_out;
	}

	opcode = (mib_type == ROH_MIB_PUBLIC) ?
		HNS3_ROH_OPC_QUERY_MIB_PUBLIC : HNS3_ROH_OPC_QUERY_MIB_PRIVATE;
	hns3_roh_cmdq_setup_basic_desc(&desc[0], opcode, true);

	ret = hns3_roh_cmdq_send(hroh_dev, desc, desc_num);
	if (ret)
		goto err_send_cmd;

	start = (mib_type == ROH_MIB_PUBLIC) ? 0 : 1;
	for (i = start; i < desc_num; i++) {
		/* HNS3_ROH_OPC_QUERY_MIB_PUBLIC: only the first desc has the head
		 * HNS3_ROH_OPC_QUERY_MIB_PRIVATE: start from command1, no head
		 */
		if (i == 0) {
			desc_data = (__le64 *)(&desc[i].data[0]);
			stats_num = HNS3_ROH_RD_FIRST_STATS_NUM;
		} else {
			desc_data = (__le64 *)(&desc[i]);
			stats_num = HNS3_ROH_RD_OTHER_STATS_NUM;
		}

		for (j = 0; j < stats_num; j++) {
			*data = le64_to_cpu(*desc_data);
			data++;
			desc_data++;
		}
	}

err_send_cmd:
	kfree(desc);
err_out:
	return ret;
}
