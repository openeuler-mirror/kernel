// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_phy_leonis.h"
#include "nbl_hw/nbl_p4_actions.h"
#include "nbl_hw/nbl_hw_leonis/base/nbl_datapath.h"
#include "nbl_hw/nbl_hw_leonis/base/nbl_ppe.h"
#include "nbl_hw/nbl_hw_leonis/base/nbl_intf.h"
#include "nbl_hw/nbl_hw_leonis/base/nbl_datapath_dped.h"
#include "nbl_hw_leonis/base/nbl_ppe_pp1.h"
#include "nbl_phy_leonis_regs.h"

static int dvn_descreq_num_cfg = DEFAULT_DVN_DESCREQ_NUMCFG; /* default 8 and 8 */
module_param(dvn_descreq_num_cfg, int, 0);
MODULE_PARM_DESC(dvn_descreq_num_cfg, "bit[31:16]:split ring,support 8/16, bit[15:0]:packed ring, support 8/12/16/20/24/28/32");

static u32 nbl_phy_dump_registers[] = {
	NBL_UVN_DIF_DELAY_REQ,
	NBL_UVN_DIF_DELAY_TIME,
	NBL_UVN_DIF_DELAY_MAX,
	NBL_UVN_DESC_PRE_DESC_REQ_NULL,
	NBL_UVN_DESC_PRE_DESC_REQ_LACK,
	NBL_UVN_DESC_RD_DROP_DESC_LACK,
	NBL_DVN_DESCRD_L2_UNAVAIL_CNT,
	NBL_DVN_DESCRD_L2_NOAVAIL_CNT,
	NBL_USTORE_BUF_TOTAL_DROP_PKT,
	NBL_USTORE_BUF_TOTAL_TRUN_PKT
};

static u32 nbl_phy_get_quirks(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = priv;
	u32 quirks;

	nbl_hw_read_mbx_regs(phy_mgt, NBL_LEONIS_QUIRKS_OFFSET,
			     (u8 *)&quirks, sizeof(u32));

	if (quirks == NBL_LEONIS_ILLEGAL_REG_VALUE)
		return 0;

	return quirks;
}

static int nbl_send_kt_data(struct nbl_phy_mgt *phy_mgt, union nbl_fem_kt_acc_ctrl_u *kt_ctrl,
			    u8 *data, struct nbl_common_info *common)
{
	union nbl_fem_kt_acc_ack_u kt_ack = {.info = {0}};
	u32 times = 3;

	nbl_hw_write_regs(phy_mgt, NBL_FEM_KT_ACC_DATA, data, NBL_KT_PHY_L2_DW_LEN);
	nbl_debug(common, NBL_DEBUG_FLOW, "Set kt = %08x-%08x-%08x-%08x-%08x",
		  ((u32 *)data)[0], ((u32 *)data)[1], ((u32 *)data)[2],
		  ((u32 *)data)[3], ((u32 *)data)[4]);

	kt_ctrl->info.rw = NBL_ACC_MODE_WRITE;
	nbl_hw_write_regs(phy_mgt, NBL_FEM_KT_ACC_CTRL,
			  kt_ctrl->data, NBL_FEM_KT_ACC_CTRL_TBL_WIDTH);

	times = 3;
	do {
		nbl_hw_read_regs(phy_mgt, NBL_FEM_KT_ACC_ACK, kt_ack.data,
				 NBL_FEM_KT_ACC_ACK_TBL_WIDTH);
		if (!kt_ack.info.done) {
			times--;
			usleep_range(100, 200);
		} else {
			break;
		}
	} while (times);

	if (!times) {
		nbl_err(common, NBL_DEBUG_FLOW, "Config kt flowtale failed");
		return -EIO;
	}

	return 0;
}

static int nbl_send_ht_data(struct nbl_phy_mgt *phy_mgt, union nbl_fem_ht_acc_ctrl_u *ht_ctrl,
			    u8 *data, struct nbl_common_info *common)
{
	union nbl_fem_ht_acc_ack_u ht_ack = {.info = {0}};
	u32 times = 3;

	nbl_hw_write_regs(phy_mgt, NBL_FEM_HT_ACC_DATA, data, NBL_FEM_HT_ACC_DATA_TBL_WIDTH);
	nbl_debug(common, NBL_DEBUG_FLOW, "Set ht data = %x", *(u32 *)data);

	ht_ctrl->info.rw = NBL_ACC_MODE_WRITE;
	nbl_hw_write_regs(phy_mgt, NBL_FEM_HT_ACC_CTRL,
			  ht_ctrl->data, NBL_FEM_HT_ACC_CTRL_TBL_WIDTH);

	times = 3;
	do {
		nbl_hw_read_regs(phy_mgt, NBL_FEM_HT_ACC_ACK, ht_ack.data,
				 NBL_FEM_HT_ACC_ACK_TBL_WIDTH);
		if (!ht_ack.info.done) {
			times--;
			usleep_range(100, 200);
		} else {
			break;
		}
	} while (times);

	if (!times) {
		nbl_err(common, NBL_DEBUG_FLOW, "Config ht flowtale failed");
		return -EIO;
	}

	return 0;
}

static void nbl_check_kt_data(struct nbl_phy_mgt *phy_mgt, union nbl_fem_kt_acc_ctrl_u *kt_ctrl,
			      struct nbl_common_info *common)
{
	union nbl_fem_kt_acc_ack_u ack = {.info = {0}};
	u32 data[10] = {0};

	kt_ctrl->info.rw = NBL_ACC_MODE_READ;
	kt_ctrl->info.access_size = NBL_ACC_SIZE_320B;

	nbl_hw_write_regs(phy_mgt, NBL_FEM_KT_ACC_CTRL, kt_ctrl->data,
			  NBL_FEM_KT_ACC_CTRL_TBL_WIDTH);

	nbl_hw_read_regs(phy_mgt, NBL_FEM_KT_ACC_ACK, ack.data, NBL_FEM_KT_ACC_ACK_TBL_WIDTH);
	nbl_debug(common, NBL_DEBUG_FLOW, "Check kt done:%u status:%u.",
		  ack.info.done, ack.info.status);
	if (ack.info.done) {
		nbl_hw_read_regs(phy_mgt, NBL_FEM_KT_ACC_DATA, (u8 *)data, NBL_KT_PHY_L2_DW_LEN);
		nbl_debug(common, NBL_DEBUG_FLOW, "Check kt data:0x%x-%x-%x-%x-%x-%x-%x-%x-%x-%x.",
			  data[9], data[8], data[7], data[6], data[5],
			  data[4], data[3], data[2], data[1], data[0]);
	}
}

static void nbl_check_ht_data(struct nbl_phy_mgt *phy_mgt, union nbl_fem_ht_acc_ctrl_u *ht_ctrl,
			      struct nbl_common_info *common)
{
	union nbl_fem_ht_acc_ack_u ack = {.info = {0}};
	u32 data[4] = {0};

	ht_ctrl->info.rw = NBL_ACC_MODE_READ;
	ht_ctrl->info.access_size = NBL_ACC_SIZE_128B;

	nbl_hw_write_regs(phy_mgt, NBL_FEM_HT_ACC_CTRL, ht_ctrl->data,
			  NBL_FEM_HT_ACC_CTRL_TBL_WIDTH);

	nbl_hw_read_regs(phy_mgt, NBL_FEM_HT_ACC_ACK, ack.data, NBL_FEM_HT_ACC_ACK_TBL_WIDTH);
	nbl_debug(common, NBL_DEBUG_FLOW, "Check ht done:%u status:%u.",
		  ack.info.done, ack.info.status);
	if (ack.info.done) {
		nbl_hw_read_regs(phy_mgt, NBL_FEM_HT_ACC_DATA,
				 (u8 *)data, NBL_FEM_HT_ACC_DATA_TBL_WIDTH);
		nbl_debug(common, NBL_DEBUG_FLOW, "Check ht data:0x%x-%x-%x-%x.",
			  data[0], data[1], data[2], data[3]);
	}
}

static void nbl_phy_fem_set_bank(struct nbl_phy_mgt *phy_mgt)
{
	u32 bank_sel = 0;

	/* HT bank sel */
	bank_sel = HT_PORT0_BANK_SEL | HT_PORT1_BANK_SEL << NBL_8BIT
			| HT_PORT2_BANK_SEL << NBL_16BIT;
	nbl_hw_write_regs(phy_mgt, NBL_FEM_HT_BANK_SEL_BITMAP, (u8 *)&bank_sel, sizeof(bank_sel));

	/* KT bank sel */
	bank_sel = KT_PORT0_BANK_SEL | KT_PORT1_BANK_SEL << NBL_8BIT
		      | KT_PORT2_BANK_SEL << NBL_16BIT;
	nbl_hw_write_regs(phy_mgt, NBL_FEM_KT_BANK_SEL_BITMAP, (u8 *)&bank_sel, sizeof(bank_sel));

	/* AT bank sel */
	bank_sel = AT_PORT0_BANK_SEL | AT_PORT1_BANK_SEL << NBL_16BIT;
	nbl_hw_write_regs(phy_mgt, NBL_FEM_AT_BANK_SEL_BITMAP, (u8 *)&bank_sel, sizeof(bank_sel));
	bank_sel = AT_PORT2_BANK_SEL;
	nbl_hw_write_regs(phy_mgt, NBL_FEM_AT_BANK_SEL_BITMAP2, (u8 *)&bank_sel, sizeof(bank_sel));
}

static void nbl_phy_fem_clear_tcam_ad(struct nbl_phy_mgt *phy_mgt)
{
	union fem_em_tcam_table_u tcam_table;
	union fem_em_ad_table_u ad_table = {.info = {0}};
	int i;
	int j;

	memset(&tcam_table, 0, sizeof(tcam_table));

	for (i = 0; i < NBL_PT_LEN; i++) {
		for (j = 0; j < NBL_TCAM_TABLE_LEN; j++) {
			nbl_hw_write_regs(phy_mgt, NBL_FEM_EM_TCAM_TABLE_REG(i, j),
					  tcam_table.hash_key, sizeof(tcam_table));
			nbl_hw_write_regs(phy_mgt, NBL_FEM_EM_AD_TABLE_REG(i, j),
					  ad_table.hash_key, sizeof(ad_table));
			nbl_hw_rd32(phy_mgt, NBL_FEM_EM_TCAM_TABLE_REG(i, 1));
		}
	}
}

static int nbl_phy_set_ht(void *priv, u16 hash, u16 hash_other, u8 ht_table,
			  u8 bucket, u32 key_index, u8 valid)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common;
	union nbl_fem_ht_acc_data_u ht = {.info = {0}};
	union nbl_fem_ht_acc_ctrl_u ht_ctrl = {.info = {0}};

	common = NBL_PHY_MGT_TO_COMMON(phy_mgt);

	ht.info.vld = valid;
	ht.info.hash = hash_other;
	ht.info.kt_index = key_index;

	ht_ctrl.info.ht_id = ht_table == NBL_HT0 ? NBL_ACC_HT0 : NBL_ACC_HT1;
	ht_ctrl.info.entry_id = hash;
	ht_ctrl.info.bucket_id = bucket;
	ht_ctrl.info.port = NBL_PT_PP0;
	ht_ctrl.info.access_size = NBL_ACC_SIZE_32B;
	ht_ctrl.info.start = 1;

	if (nbl_send_ht_data(phy_mgt, &ht_ctrl, ht.data, common))
		return -EIO;

	nbl_check_ht_data(phy_mgt, &ht_ctrl, common);
	return 0;
}

static int nbl_phy_set_kt(void *priv, u8 *key, u32 key_index, u8 key_type)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common;
	union nbl_fem_kt_acc_ctrl_u kt_ctrl = {.info = {0}};

	common = NBL_PHY_MGT_TO_COMMON(phy_mgt);

	kt_ctrl.info.addr = key_index;
	kt_ctrl.info.access_size = key_type == NBL_KT_HALF_MODE ? NBL_ACC_SIZE_160B
								: NBL_ACC_SIZE_320B;
	kt_ctrl.info.start = 1;

	if (nbl_send_kt_data(phy_mgt, &kt_ctrl, key, common))
		return -EIO;

	nbl_check_kt_data(phy_mgt, &kt_ctrl, common);
	return 0;
}

static int nbl_phy_search_key(void *priv, u8 *key, u8 key_type)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common;
	union nbl_search_ctrl_u s_ctrl = {.info = {0}};
	union nbl_search_ack_u s_ack = {.info = {0}};
	u8 key_data[NBL_KT_BYTE_LEN] = {0};
	u8 search_key[NBL_FEM_SEARCH_KEY_LEN] = {0};
	u8 data[NBL_FEM_SEARCH_KEY_LEN] = {0};
	u8 times = 3;

	common = NBL_PHY_MGT_TO_COMMON(phy_mgt);

	if (key_type == NBL_KT_HALF_MODE)
		memcpy(key_data, key, NBL_KT_BYTE_HALF_LEN);
	else
		memcpy(key_data, key, NBL_KT_BYTE_LEN);

	key_data[0] &= KT_MASK_LEN32_ACTION_INFO;
	key_data[1] &= KT_MASK_LEN12_ACTION_INFO;
	if (key_type == NBL_KT_HALF_MODE)
		memcpy(&search_key[20], key_data, NBL_KT_BYTE_HALF_LEN);
	else
		memcpy(search_key, key_data, NBL_KT_BYTE_LEN);

	nbl_debug(common, NBL_DEBUG_FLOW, "Search key:0x%x-%x-%x-%x-%x-%x-%x-%x-%x-%x",
		  ((u32 *)search_key)[9], ((u32 *)search_key)[8],
		  ((u32 *)search_key)[7], ((u32 *)search_key)[6],
		  ((u32 *)search_key)[5], ((u32 *)search_key)[4],
		  ((u32 *)search_key)[3], ((u32 *)search_key)[2],
		  ((u32 *)search_key)[1], ((u32 *)search_key)[0]);
	nbl_hw_write_regs(phy_mgt, NBL_FEM_INSERT_SEARCH0_DATA, search_key, NBL_FEM_SEARCH_KEY_LEN);

	s_ctrl.info.start = 1;
	nbl_hw_write_regs(phy_mgt, NBL_FEM_INSERT_SEARCH0_CTRL, (u8 *)&s_ctrl,
			  NBL_SEARCH_CTRL_WIDTH);

	do {
		nbl_hw_read_regs(phy_mgt, NBL_FEM_INSERT_SEARCH0_ACK,
				 s_ack.data, NBL_SEARCH_ACK_WIDTH);
		nbl_debug(common, NBL_DEBUG_FLOW, "Search key ack:done:%u status:%u.",
			  s_ack.info.done, s_ack.info.status);

		if (!s_ack.info.done) {
			times--;
			usleep_range(100, 200);
		} else {
			nbl_hw_read_regs(phy_mgt, NBL_FEM_INSERT_SEARCH0_DATA,
					 data, NBL_FEM_SEARCH_KEY_LEN);
			nbl_debug(common, NBL_DEBUG_FLOW,
				  "Search key data:0x%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x.",
				  ((u32 *)data)[10], ((u32 *)data)[9],
				  ((u32 *)data)[8], ((u32 *)data)[7],
				  ((u32 *)data)[6], ((u32 *)data)[5],
				  ((u32 *)data)[4], ((u32 *)data)[3],
				  ((u32 *)data)[2], ((u32 *)data)[1],
				  ((u32 *)data)[0]);
			break;
		}
	} while (times);

	if (!times) {
		nbl_err(common, NBL_DEBUG_PHY, "Search ht/kt failed.");
		return -EAGAIN;
	}

	return 0;
}

static int nbl_phy_add_tcam(void *priv, u32 index, u8 *key, u32 *action, u8 key_type, u8 pp_type)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union fem_em_tcam_table_u tcam_table;
	union fem_em_tcam_table_u tcam_table_second;
	union fem_em_ad_table_u ad_table;

	memset(&tcam_table, 0, sizeof(tcam_table));
	memset(&tcam_table_second, 0, sizeof(tcam_table_second));
	memset(&ad_table, 0, sizeof(ad_table));

	memcpy(tcam_table.info.key, key, NBL_KT_BYTE_HALF_LEN);
	tcam_table.info.key_vld = 1;

	if (key_type == NBL_KT_FULL_MODE) {
		tcam_table.info.key_size = 1;
		memcpy(tcam_table_second.info.key, &key[5], NBL_KT_BYTE_HALF_LEN);
		tcam_table_second.info.key_vld = 1;
		tcam_table_second.info.key_size = 1;

		nbl_hw_write_regs(phy_mgt, NBL_FEM_EM_TCAM_TABLE_REG(pp_type, index + 1),
				  tcam_table_second.hash_key, NBL_FLOW_TCAM_TOTAL_LEN);
	}
	nbl_hw_write_regs(phy_mgt, NBL_FEM_EM_TCAM_TABLE_REG(pp_type, index),
			  tcam_table.hash_key, NBL_FLOW_TCAM_TOTAL_LEN);

	ad_table.info.action0 = action[0];
	ad_table.info.action1 = action[1];
	ad_table.info.action2 = action[2];
	ad_table.info.action3 = action[3];
	ad_table.info.action4 = action[4];
	ad_table.info.action5 = action[5];
	ad_table.info.action6 = action[6];
	ad_table.info.action7 = action[7];
	ad_table.info.action8 = action[8];
	ad_table.info.action9 = action[9];
	ad_table.info.action10 = action[10];
	ad_table.info.action11 = action[11];
	ad_table.info.action12 = action[12];
	ad_table.info.action13 = action[13];
	ad_table.info.action14 = action[14];
	ad_table.info.action15 = action[15];
	nbl_hw_write_regs(phy_mgt, NBL_FEM_EM_AD_TABLE_REG(pp_type, index),
			  ad_table.hash_key, NBL_FLOW_AD_TOTAL_LEN);

	return 0;
}

static void nbl_phy_del_tcam(void *priv, u32 index, u8 key_type, u8 pp_type)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union fem_em_tcam_table_u tcam_table;
	union fem_em_tcam_table_u tcam_table_second;
	union fem_em_ad_table_u ad_table;

	memset(&tcam_table, 0, sizeof(tcam_table));
	memset(&tcam_table_second, 0, sizeof(tcam_table_second));
	memset(&ad_table, 0, sizeof(ad_table));
	if (key_type == NBL_KT_FULL_MODE)
		nbl_hw_write_regs(phy_mgt, NBL_FEM_EM_TCAM_TABLE_REG(pp_type, index + 1),
				  tcam_table_second.hash_key, NBL_FLOW_TCAM_TOTAL_LEN);
	nbl_hw_write_regs(phy_mgt, NBL_FEM_EM_TCAM_TABLE_REG(pp_type, index),
			  tcam_table.hash_key, NBL_FLOW_TCAM_TOTAL_LEN);

	nbl_hw_write_regs(phy_mgt, NBL_FEM_EM_AD_TABLE_REG(pp_type, index),
			  ad_table.hash_key, NBL_FLOW_AD_TOTAL_LEN);
}

static int nbl_phy_add_mcc(void *priv, u16 mcc_id, u16 prev_mcc_id, u16 next_mcc_id,
			   u16 action, u8 eth_id, u16 vsi_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_mcc_tbl node = {0};

	node.vld = 1;
	if (next_mcc_id == NBL_MCC_ID_INVALID) {
		node.next_pntr = 0;
		node.tail = 1;
	} else {
		node.next_pntr = next_mcc_id;
		node.tail = 0;
	}

	node.stateid_filter = 1;
	node.flowid_filter = 1;
	node.dport_act = action;

	nbl_hw_write_regs(phy_mgt, NBL_MCC_LEAF_NODE_TABLE(mcc_id), (u8 *)&node, sizeof(node));
	if (prev_mcc_id != NBL_MCC_ID_INVALID) {
		nbl_hw_read_regs(phy_mgt, NBL_MCC_LEAF_NODE_TABLE(prev_mcc_id),
				 (u8 *)&node, sizeof(node));
		node.next_pntr = mcc_id;
		node.tail = 0;
		nbl_hw_write_regs(phy_mgt, NBL_MCC_LEAF_NODE_TABLE(prev_mcc_id),
				  (u8 *)&node, sizeof(node));
	}

	return 0;
}

static void nbl_phy_del_mcc(void *priv, u16 mcc_id, u16 prev_mcc_id, u16 next_mcc_id,
			    u8 eth_id, u16 vsi_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_mcc_tbl node = {0};

	if (prev_mcc_id != NBL_MCC_ID_INVALID) {
		nbl_hw_read_regs(phy_mgt, NBL_MCC_LEAF_NODE_TABLE(prev_mcc_id),
				 (u8 *)&node, sizeof(node));

		if (next_mcc_id != NBL_MCC_ID_INVALID) {
			node.next_pntr = next_mcc_id;
		} else {
			node.next_pntr = 0;
			node.tail = 1;
		}

		nbl_hw_write_regs(phy_mgt, NBL_MCC_LEAF_NODE_TABLE(prev_mcc_id),
				  (u8 *)&node, sizeof(node));
	}

	memset(&node, 0, sizeof(node));
	nbl_hw_write_regs(phy_mgt, NBL_MCC_LEAF_NODE_TABLE(mcc_id), (u8 *)&node, sizeof(node));
}

static void nbl_phy_update_mcc_next_node(void *priv, u16 mcc_id, u16 next_mcc_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_mcc_tbl node = {0};

	nbl_hw_read_regs(phy_mgt, NBL_MCC_LEAF_NODE_TABLE(mcc_id),
			 (u8 *)&node, sizeof(node));
	if (next_mcc_id != NBL_MCC_ID_INVALID) {
		node.next_pntr = next_mcc_id;
		node.tail = 0;
	} else {
		node.next_pntr = 0;
		node.tail = 1;
	}

	nbl_hw_write_regs(phy_mgt, NBL_MCC_LEAF_NODE_TABLE(mcc_id),
			  (u8 *)&node, sizeof(node));
}

static int nbl_phy_add_tnl_encap(void *priv, const u8 encap_buf[], u16 encap_idx,
				 union nbl_flow_encap_offset_tbl_u encap_idx_info)
{
	u8 id;
	u8 temp = 0;
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	u8 send_buf[NBL_FLOW_ACTION_ENCAP_TOTAL_LEN] = { 0 };

	memcpy(send_buf, encap_buf, NBL_FLOW_ACTION_ENCAP_MAX_LEN);

	for (id = 0; id < NBL_FLOW_ACTION_ENCAP_HALF_LEN; id++) {
		temp = send_buf[id];
		send_buf[id] = send_buf[NBL_FLOW_ACTION_ENCAP_MAX_LEN - 1 - id];
		send_buf[NBL_FLOW_ACTION_ENCAP_MAX_LEN - 1 - id] = temp;
	}

	memcpy(&send_buf[NBL_FLOW_ACTION_ENCAP_MAX_LEN],
	       encap_idx_info.data, NBL_FLOW_ACTION_ENCAP_OFFSET_LEN);

	nbl_hw_write_regs(phy_mgt, NBL_DPED_TAB_TNL_REG(encap_idx),
			  (u8 *)send_buf, NBL_FLOW_ACTION_ENCAP_TOTAL_LEN);

	return 0;
}

static void nbl_phy_del_tnl_encap(void *priv, u16 encap_idx)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	u8 send_buf[NBL_FLOW_ACTION_ENCAP_TOTAL_LEN] = { 0 };

	nbl_hw_write_regs(phy_mgt, NBL_DPED_TAB_TNL_REG(encap_idx),
			  (u8 *)send_buf, NBL_FLOW_ACTION_ENCAP_TOTAL_LEN);
}

static void nbl_phy_set_decap_set(void *priv, u8 *mac, u16 vlan_0, u16 vlan_1,
				  u8 vlan_layer, u8 idx, u8 is_add, u16 vsi_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union nbl_action_data set_dport;
	union ipro_udl_pkt_flt_action_u udl_act;
	union ipro_udl_pkt_flt_ctrl_u udl_ctrl;
	union ipro_udl_pkt_flt_vlan_u vlan;
	union ipro_udl_pkt_flt_dmac_u dmac;

	if (idx >= NBL_IPRO_UDL_PKT_FLT_DMAC_DEPTH) {
		nbl_debug(phy_mgt->common, NBL_DEBUG_FLOW, "nbl set decap_set idx exceed, idx:%u",
			  idx);
		return;
	}

	memset(&set_dport, 0, sizeof(set_dport));
	memset(&udl_act, 0, sizeof(udl_act));
	memset(&udl_ctrl, 0, sizeof(udl_ctrl));
	memset(&vlan, 0, sizeof(vlan));
	memset(&dmac, 0, sizeof(dmac));

	vlan.info.vlan_0 = vlan_0;
	vlan.info.vlan_1 = vlan_1;
	if (vlan_layer == 1)
		vlan.info.vlan_layer = 0x2;
	else if (vlan_layer == 2)
		vlan.info.vlan_layer = 0x3;
	memcpy(dmac.data, mac, sizeof(dmac));

	set_dport.dport.up.next_stg_sel = NEXT_STG_SEL_ACL_S0;
	set_dport.dport.up.upcall_flag = AUX_FWD_TYPE_UPCALL;
	set_dport.dport.up.port_type = SET_DPORT_TYPE_VSI_HOST;
	set_dport.dport.up.port_id = vsi_id;
	udl_act.info.set_dport_en = true;
	udl_act.info.set_dport = set_dport.data;

	nbl_hw_read_regs(phy_mgt, NBL_IPRO_UDL_PKT_FLT_CTRL_ADDR,
			 (u8 *)udl_ctrl.data, sizeof(udl_ctrl));
	if (is_add)
		udl_ctrl.info.vld |= 1 << idx;
	else
		udl_ctrl.info.vld &= ~(1 << idx);

	nbl_hw_write_regs(phy_mgt, NBL_IPRO_UDL_PKT_FLT_ACTION_ADDR,
			  (u8 *)udl_act.data, sizeof(udl_act));

	nbl_hw_write_regs(phy_mgt, NBL_IPRO_UDL_PKT_FLT_CTRL_ADDR,
			  (u8 *)udl_ctrl.data, sizeof(udl_ctrl));

	nbl_hw_write_regs(phy_mgt, NBL_IPRO_UDL_PKT_FLT_VLAN_REG(idx),
			  (u8 *)vlan.data, sizeof(vlan));

	nbl_hw_write_regs(phy_mgt, NBL_IPRO_UDL_PKT_FLT_DMAC_REG(idx),
			  (u8 *)dmac.data, sizeof(dmac));

	nbl_debug(phy_mgt->common, NBL_DEBUG_FLOW, "set decap set: is_add:%u, idx:%u, vlan0:%u, vlan1:%u, mac:0x%x-%x, vsi_id:%u",
		  is_add, idx, vlan_0, vlan_1, dmac.data[0], dmac.data[1], vsi_id);
}

static int nbl_phy_init_fem(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union nbl_fem_ht_size_table_u ht_size = {.info = {0}};
	u32 fem_start = NBL_FEM_INIT_START_KERN;
	int ret = 0;

	nbl_hw_write_regs(phy_mgt, NBL_FEM_INIT_START, (u8 *)&fem_start, sizeof(fem_start));

	nbl_phy_fem_set_bank(phy_mgt);

	ht_size.info.pp0_size = HT_PORT0_BTM;
	ht_size.info.pp1_size = HT_PORT1_BTM;
	ht_size.info.pp2_size = HT_PORT2_BTM;
	nbl_hw_write_regs(phy_mgt, NBL_FEM_HT_SIZE_REG, ht_size.data, NBL_FEM_HT_SIZE_TBL_WIDTH);

	nbl_phy_fem_clear_tcam_ad(phy_mgt);

	/*ret = nbl_phy_fem_em0_pt_init(phy_mgt);*/
	return ret;
}

static void nbl_configure_dped_checksum(struct nbl_phy_mgt *phy_mgt)
{
	union dped_l4_ck_cmd_40_u l4_ck_cmd_40;

	/* DPED dped_l4_ck_cmd_40 for sctp */
	nbl_hw_read_regs(phy_mgt, NBL_DPED_L4_CK_CMD_40_ADDR,
			 (u8 *)&l4_ck_cmd_40, sizeof(l4_ck_cmd_40));
	l4_ck_cmd_40.info.en = 1;
	nbl_hw_write_regs(phy_mgt, NBL_DPED_L4_CK_CMD_40_ADDR,
			  (u8 *)&l4_ck_cmd_40, sizeof(l4_ck_cmd_40));
}

static int nbl_dped_init(struct nbl_phy_mgt *phy_mgt)
{
	nbl_hw_wr32(phy_mgt, NBL_DPED_VLAN_OFFSET, 0xC);
	nbl_hw_wr32(phy_mgt, NBL_DPED_DSCP_OFFSET_0, 0x8);
	nbl_hw_wr32(phy_mgt, NBL_DPED_DSCP_OFFSET_1, 0x4);

	// dped checksum offload
	nbl_configure_dped_checksum(phy_mgt);

	return 0;
}

static int nbl_uped_init(struct nbl_phy_mgt *phy_mgt)
{
	struct ped_hw_edit_profile hw_edit;

	nbl_hw_read_regs(phy_mgt, NBL_UPED_HW_EDT_PROF_TABLE(5), (u8 *)&hw_edit, sizeof(hw_edit));
	hw_edit.l3_len = 0;
	nbl_hw_write_regs(phy_mgt, NBL_UPED_HW_EDT_PROF_TABLE(5), (u8 *)&hw_edit, sizeof(hw_edit));

	nbl_hw_read_regs(phy_mgt, NBL_UPED_HW_EDT_PROF_TABLE(6), (u8 *)&hw_edit, sizeof(hw_edit));
	hw_edit.l3_len = 1;
	nbl_hw_write_regs(phy_mgt, NBL_UPED_HW_EDT_PROF_TABLE(6), (u8 *)&hw_edit, sizeof(hw_edit));

	return 0;
}

static void nbl_phy_cfg_eth_shaping(void *priv, u8 eth_id, u32 speed)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_shaping_dport dport = {0};
	struct nbl_shaping_dvn_dport dvn_dport = {0};
	struct nbl_shaping_rdma_dport rdma_dport = {0};

	dport.cir = speed;
	dport.pir = speed;
	dport.depth = max(dport.cir * 2, NBL_LR_LEONIS_NET_BUCKET_DEPTH);
	dport.cbs = dport.depth;
	dport.pbs = dport.depth;
	dport.valid = 1;

	dvn_dport.cir = speed / 2;
	dvn_dport.pir = speed;
	dvn_dport.depth = dport.depth;
	dvn_dport.cbs = dvn_dport.depth;
	dvn_dport.pbs = dvn_dport.depth;
	dvn_dport.valid = 1;

	rdma_dport.cir = speed / 2;
	rdma_dport.pir = speed;
	rdma_dport.depth = dport.depth;
	rdma_dport.cbs = rdma_dport.depth;
	rdma_dport.pbs = rdma_dport.depth;
	rdma_dport.valid = 1;

	nbl_hw_write_regs(phy_mgt, NBL_SHAPING_DPORT_REG(eth_id), (u8 *)&dport, sizeof(dport));
	nbl_hw_write_regs(phy_mgt, NBL_SHAPING_DVN_DPORT_REG(eth_id),
			  (u8 *)&dvn_dport, sizeof(dvn_dport));
	nbl_hw_write_regs(phy_mgt, NBL_SHAPING_RDMA_DPORT_REG(eth_id),
			  (u8 *)&rdma_dport, sizeof(rdma_dport));
}

static void nbl_shaping_eth_init(struct nbl_phy_mgt *phy_mgt, u8 eth_id, u8 speed)
{
	u32 rate;

	switch (speed) {
	case NBL_FW_PORT_SPEED_100G:
		rate = NBL_SHAPING_DPORT_100G_RATE;
		break;
	case NBL_FW_PORT_SPEED_50G:
		rate = NBL_SHAPING_DPORT_50G_RATE;
		break;
	case NBL_FW_PORT_SPEED_25G:
		rate = NBL_SHAPING_DPORT_25G_RATE;
		break;
	case NBL_FW_PORT_SPEED_10G:
		rate = NBL_SHAPING_DPORT_10G_RATE;
		break;
	default:
		rate = NBL_SHAPING_DPORT_25G_RATE;
		break;
	}
	nbl_phy_cfg_eth_shaping(phy_mgt, eth_id, rate);
}

static int nbl_shaping_init(struct nbl_phy_mgt *phy_mgt, u8 speed)
{
	struct dsch_psha_en psha_en = {0};
	struct nbl_shaping_net net_shaping = {0};
	int num = 128;
	int i;

	for (i = 0; i < NBL_MAX_ETHERNET; i++)
		nbl_shaping_eth_init(phy_mgt, i, speed);

	psha_en.en = 0xF;
	nbl_hw_write_regs(phy_mgt, NBL_DSCH_PSHA_EN_ADDR, (u8 *)&psha_en, sizeof(psha_en));

	for (i = 0; i < NBL_MAX_FUNC; i++) {
		nbl_hw_write_regs(phy_mgt, NBL_SHAPING_NET_REG(i),
				  (u8 *)&net_shaping, sizeof(net_shaping));
		if ((i % num) == 0)
			nbl_hw_rd32(phy_mgt, NBL_HW_DUMMY_REG);
	}
	nbl_hw_rd32(phy_mgt, NBL_HW_DUMMY_REG);

	return 0;
}

static int nbl_dsch_qid_max_init(struct nbl_phy_mgt *phy_mgt)
{
	struct dsch_vn_quanta quanta = {0};

	quanta.h_qua = NBL_HOST_QUANTA;
	quanta.e_qua = NBL_ECPU_QUANTA;
	nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_QUANTA_ADDR,
			  (u8 *)&quanta, sizeof(quanta));
	nbl_hw_wr32(phy_mgt, NBL_DSCH_HOST_QID_MAX, NBL_MAX_QUEUE_ID);

	nbl_hw_wr32(phy_mgt, NBL_DVN_ECPU_QUEUE_NUM, 0);
	nbl_hw_wr32(phy_mgt, NBL_UVN_ECPU_QUEUE_NUM, 0);

	return 0;
}

static int nbl_ustore_init(struct nbl_phy_mgt *phy_mgt, u8 eth_num)
{
	struct ustore_pkt_len pkt_len;
	struct nbl_ustore_port_drop_th drop_th;
	int i;

	nbl_hw_read_regs(phy_mgt, NBL_USTORE_PKT_LEN_ADDR, (u8 *)&pkt_len, sizeof(pkt_len));
	/* min arp packet length 42 (14 + 28) */
	pkt_len.min = 42;
	nbl_hw_write_regs(phy_mgt, NBL_USTORE_PKT_LEN_ADDR, (u8 *)&pkt_len, sizeof(pkt_len));

	drop_th.en = 1;
	if (eth_num == 1)
		drop_th.disc_th = NBL_USTORE_SIGNLE_ETH_DROP_TH;
	else if (eth_num == 2)
		drop_th.disc_th = NBL_USTORE_DUAL_ETH_DROP_TH;
	else
		drop_th.disc_th = NBL_USTORE_QUAD_ETH_DROP_TH;

	for (i = 0; i < 4; i++)
		nbl_hw_write_regs(phy_mgt, NBL_USTORE_PORT_DROP_TH_REG_ARR(i),
				  (u8 *)&drop_th, sizeof(drop_th));

	for (i = 0; i < NBL_MAX_ETHERNET; i++) {
		nbl_hw_rd32(phy_mgt, NBL_USTORE_BUF_PORT_DROP_PKT(i));
		nbl_hw_rd32(phy_mgt, NBL_USTORE_BUF_PORT_TRUN_PKT(i));
	}

	return 0;
}

static int nbl_dstore_init(struct nbl_phy_mgt *phy_mgt, u8 speed)
{
	struct dstore_d_dport_fc_th fc_th;
	struct dstore_port_drop_th drop_th;
	struct dstore_disc_bp_th bp_th;
	int i;

	for (i = 0; i < 6; i++) {
		nbl_hw_read_regs(phy_mgt, NBL_DSTORE_PORT_DROP_TH_REG(i),
				 (u8 *)&drop_th, sizeof(drop_th));
		drop_th.en = 0;
		nbl_hw_write_regs(phy_mgt, NBL_DSTORE_PORT_DROP_TH_REG(i),
				  (u8 *)&drop_th, sizeof(drop_th));
	}

	nbl_hw_read_regs(phy_mgt, NBL_DSTORE_DISC_BP_TH,
			 (u8 *)&bp_th, sizeof(bp_th));
	bp_th.en = 1;
	nbl_hw_write_regs(phy_mgt, NBL_DSTORE_DISC_BP_TH,
			  (u8 *)&bp_th, sizeof(bp_th));

	for (i = 0; i < 4; i++) {
		nbl_hw_read_regs(phy_mgt, NBL_DSTORE_D_DPORT_FC_TH_REG(i),
				 (u8 *)&fc_th, sizeof(fc_th));
		if (speed == NBL_FW_PORT_SPEED_100G) {
			fc_th.xoff_th = NBL_DSTORE_DROP_XOFF_TH_100G;
			fc_th.xon_th = NBL_DSTORE_DROP_XON_TH_100G;
		} else {
			fc_th.xoff_th = NBL_DSTORE_DROP_XOFF_TH;
			fc_th.xon_th = NBL_DSTORE_DROP_XON_TH;
		}

		fc_th.fc_en = 1;
		nbl_hw_write_regs(phy_mgt, NBL_DSTORE_D_DPORT_FC_TH_REG(i),
				  (u8 *)&fc_th, sizeof(fc_th));
	}

	return 0;
}

static int nbl_ul4s_init(struct nbl_phy_mgt *phy_mgt)
{
	struct ul4s_sch_pad sch_pad;

	nbl_hw_read_regs(phy_mgt, NBL_UL4S_SCH_PAD_ADDR, (u8 *)&sch_pad, sizeof(sch_pad));
	sch_pad.en = 1;
	nbl_hw_write_regs(phy_mgt, NBL_UL4S_SCH_PAD_ADDR, (u8 *)&sch_pad, sizeof(sch_pad));

	return 0;
}

static void nbl_dvn_descreq_num_cfg(void *priv, u32 descreq_num)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_dvn_descreq_num_cfg descreq_num_cfg = { 0 };
	u32 packet_ring_prefect_num = descreq_num & 0xffff;
	u32 split_ring_prefect_num = (descreq_num >> 16) & 0xffff;

	packet_ring_prefect_num = packet_ring_prefect_num > 32 ? 32 : packet_ring_prefect_num;
	packet_ring_prefect_num = packet_ring_prefect_num < 8 ? 8 : packet_ring_prefect_num;
	descreq_num_cfg.packed_l1_num = (packet_ring_prefect_num - 8) / 4;

	split_ring_prefect_num = split_ring_prefect_num > 16 ? 16 : split_ring_prefect_num;
	split_ring_prefect_num = split_ring_prefect_num < 8 ? 8 : split_ring_prefect_num;
	descreq_num_cfg.avring_cfg_num = split_ring_prefect_num > 8 ? 1 : 0;

	nbl_hw_write_regs(phy_mgt, NBL_DVN_DESCREQ_NUM_CFG,
			  (u8 *)&descreq_num_cfg, sizeof(descreq_num_cfg));
}

static void nbl_dvn_descreq_num_dpdk_cfg(void *priv, u8 eth_speed, bool is_dpdk)
{
	u32 dvn_desc_req;

	if (is_dpdk) {
		dvn_desc_req = DPDK_DVN_25G_DESCREQ_NUMCFG;

		if (eth_speed == NBL_FW_PORT_SPEED_100G)
			dvn_desc_req = DPDK_DVN_100G_DESCREQ_NUMCFG;
	} else {
		dvn_desc_req = DEFAULT_DVN_DESCREQ_NUMCFG;
	}

	nbl_dvn_descreq_num_cfg(priv, dvn_desc_req);
}

static u32 nbl_dvn_descreq_num_get(void *priv)
{
	u16 split_req;
	u16 packed_req;
	struct nbl_dvn_descreq_num_cfg descreq_num_cfg = { 0 };
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_hw_read_regs(phy_mgt, NBL_DVN_DESCREQ_NUM_CFG,
			 (u8 *)&descreq_num_cfg, sizeof(descreq_num_cfg));

	split_req = (descreq_num_cfg.avring_cfg_num + 1) * 8;
	packed_req = descreq_num_cfg.packed_l1_num * 4 + 8;

	return (split_req << 16) + packed_req;
}

static void nbl_phy_cfg_dvn_bp_mask(struct dvn_back_pressure_mask *mask, u8 eth_id, bool enable)
{
	switch (eth_id) {
	case 0:
		mask->dstore_port0_flag = enable;
		break;
	case 1:
		mask->dstore_port1_flag = enable;
		break;
	case 2:
		mask->dstore_port2_flag = enable;
		break;
	case 3:
		mask->dstore_port3_flag = enable;
		break;
	default:
		return;
	}
}

static int nbl_dvn_init(struct nbl_phy_mgt *phy_mgt)
{
	struct nbl_dvn_desc_wr_merge_timeout timeout = {0};
	struct nbl_dvn_dif_req_rd_ro_flag ro_flag = {0};

	timeout.cfg_cycle = DEFAULT_DVN_DESC_WR_MERGE_TIMEOUT_MAX;
	nbl_hw_write_regs(phy_mgt, NBL_DVN_DESC_WR_MERGE_TIMEOUT,
			  (u8 *)&timeout, sizeof(timeout));

	ro_flag.rd_desc_ro_en = 1;
	ro_flag.rd_data_ro_en = 1;
	ro_flag.rd_avring_ro_en = 1;
	nbl_hw_write_regs(phy_mgt, NBL_DVN_DIF_REQ_RD_RO_FLAG,
			  (u8 *)&ro_flag, sizeof(ro_flag));

	nbl_dvn_descreq_num_cfg(phy_mgt, DEFAULT_DVN_DESCREQ_NUMCFG);

	return 0;
}

static int nbl_uvn_init(struct nbl_phy_mgt *phy_mgt)
{
	struct pci_dev *pdev;
	struct uvn_queue_err_mask mask = {0};
	struct uvn_dif_req_ro_flag flag = {0};
	struct uvn_desc_prefetch_init prefetch_init = {0};
	u32 timeout = 119760; /* 200us 200000/1.67 */
	u32 quirks;
	struct uvn_desc_wr_timeout desc_wr_timeout = {0};
	u16 wr_timeout = 0x12c;

	pdev = NBL_COMMON_TO_PDEV(phy_mgt->common);
	nbl_hw_wr32(phy_mgt, NBL_UVN_DESC_RD_WAIT, timeout);

	desc_wr_timeout.num = wr_timeout;
	nbl_hw_write_regs(phy_mgt, NBL_UVN_DESC_WR_TIMEOUT,
			  (u8 *)&desc_wr_timeout, sizeof(desc_wr_timeout));

	flag.avail_rd = 1;
	flag.desc_rd = 1;
	flag.pkt_wr = 1;
	flag.desc_wr = 0;
	nbl_hw_write_regs(phy_mgt, NBL_UVN_DIF_REQ_RO_FLAG, (u8 *)&flag, sizeof(flag));

	nbl_hw_read_regs(phy_mgt, NBL_UVN_QUEUE_ERR_MASK, (u8 *)&mask, sizeof(mask));
	mask.dif_err = 1;
	nbl_hw_write_regs(phy_mgt, NBL_UVN_QUEUE_ERR_MASK, (u8 *)&mask, sizeof(mask));

	prefetch_init.num = NBL_UVN_DESC_PREFETCH_NUM;
	prefetch_init.sel = 0;

	quirks = nbl_phy_get_quirks(phy_mgt);

	if (performance_mode & BIT(NBL_QUIRKS_UVN_PREFETCH_ALIGN) ||
	    !(quirks & BIT(NBL_QUIRKS_UVN_PREFETCH_ALIGN)))
		prefetch_init.sel = 1;

	nbl_hw_write_regs(phy_mgt, NBL_UVN_DESC_PREFETCH_INIT,
			  (u8 *)&prefetch_init, sizeof(prefetch_init));

	return 0;
}

static int nbl_uqm_init(struct nbl_phy_mgt *phy_mgt)
{
	struct nbl_uqm_que_type que_type = {0};
	u32 cnt = 0;
	int i;

	nbl_hw_write_regs(phy_mgt, NBL_UQM_FWD_DROP_CNT, (u8 *)&cnt, sizeof(cnt));

	nbl_hw_write_regs(phy_mgt, NBL_UQM_DROP_PKT_CNT, (u8 *)&cnt, sizeof(cnt));
	nbl_hw_write_regs(phy_mgt, NBL_UQM_DROP_PKT_SLICE_CNT, (u8 *)&cnt, sizeof(cnt));
	nbl_hw_write_regs(phy_mgt, NBL_UQM_DROP_PKT_LEN_ADD_CNT, (u8 *)&cnt, sizeof(cnt));
	nbl_hw_write_regs(phy_mgt, NBL_UQM_DROP_HEAD_PNTR_ADD_CNT, (u8 *)&cnt, sizeof(cnt));
	nbl_hw_write_regs(phy_mgt, NBL_UQM_DROP_WEIGHT_ADD_CNT, (u8 *)&cnt, sizeof(cnt));

	for (i = 0; i < NBL_UQM_PORT_DROP_DEPTH; i++) {
		nbl_hw_write_regs(phy_mgt, NBL_UQM_PORT_DROP_PKT_CNT + (sizeof(cnt) * i),
				  (u8 *)&cnt, sizeof(cnt));
		nbl_hw_write_regs(phy_mgt, NBL_UQM_PORT_DROP_PKT_SLICE_CNT + (sizeof(cnt) * i),
				  (u8 *)&cnt, sizeof(cnt));
		nbl_hw_write_regs(phy_mgt, NBL_UQM_PORT_DROP_PKT_LEN_ADD_CNT + (sizeof(cnt) * i),
				  (u8 *)&cnt, sizeof(cnt));
		nbl_hw_write_regs(phy_mgt, NBL_UQM_PORT_DROP_HEAD_PNTR_ADD_CNT + (sizeof(cnt) * i),
				  (u8 *)&cnt, sizeof(cnt));
		nbl_hw_write_regs(phy_mgt, NBL_UQM_PORT_DROP_WEIGHT_ADD_CNT + (sizeof(cnt) * i),
				  (u8 *)&cnt, sizeof(cnt));
	}

	for (i = 0; i < NBL_UQM_DPORT_DROP_DEPTH; i++)
		nbl_hw_write_regs(phy_mgt, NBL_UQM_DPORT_DROP_CNT + (sizeof(cnt) * i),
				  (u8 *)&cnt, sizeof(cnt));

	que_type.bp_drop = 0;
	nbl_hw_write_regs(phy_mgt, NBL_UQM_QUE_TYPE, (u8 *)&que_type, sizeof(que_type));

	return 0;
}

static int nbl_dp_init(struct nbl_phy_mgt *phy_mgt, u8 speed, u8 eth_num)
{
	nbl_dped_init(phy_mgt);
	nbl_uped_init(phy_mgt);
	nbl_shaping_init(phy_mgt, speed);
	nbl_dsch_qid_max_init(phy_mgt);
	nbl_ustore_init(phy_mgt, eth_num);
	nbl_dstore_init(phy_mgt, speed);
	nbl_ul4s_init(phy_mgt);
	nbl_dvn_init(phy_mgt);
	nbl_uvn_init(phy_mgt);
	nbl_uqm_init(phy_mgt);

	return 0;
}

static void nbl_epro_mirror_act_pri_init(struct nbl_phy_mgt *phy_mgt,
					 struct nbl_epro_mirror_act_pri *cfg)
{
	struct nbl_epro_mirror_act_pri epro_mirror_act_pri_def = {
		.car_idx_pri		= EPRO_MIRROR_ACT_CARIDX_PRI,
		.dqueue_pri		= EPRO_MIRROR_ACT_DQUEUE_PRI,
		.dport_pri		= EPRO_MIRROR_ACT_DPORT_PRI,
		.rsv			= 0
	};

	if (cfg)
		epro_mirror_act_pri_def = *cfg;

	nbl_hw_write_regs(phy_mgt, NBL_EPRO_MIRROR_ACT_PRI_REG, (u8 *)&epro_mirror_act_pri_def, 1);
}

static struct nbl_epro_action_filter_tbl epro_action_filter_tbl_def[NBL_FWD_TYPE_MAX] = {
	[NBL_FWD_TYPE_NORMAL]		= {
		BIT(NBL_MD_ACTION_MCIDX) | BIT(NBL_MD_ACTION_TABLE_INDEX) |
		BIT(NBL_MD_ACTION_MIRRIDX)},
	[NBL_FWD_TYPE_CPU_ASSIGNED]	= {
		BIT(NBL_MD_ACTION_MCIDX) | BIT(NBL_MD_ACTION_TABLE_INDEX) |
		BIT(NBL_MD_ACTION_MIRRIDX)
	},
	[NBL_FWD_TYPE_UPCALL]		= {0},
	[NBL_FWD_TYPE_SRC_MIRROR]	= {
			BIT(NBL_MD_ACTION_FLOWID0) | BIT(NBL_MD_ACTION_FLOWID1) |
			BIT(NBL_MD_ACTION_RSSIDX) | BIT(NBL_MD_ACTION_TABLE_INDEX) |
			BIT(NBL_MD_ACTION_MCIDX) | BIT(NBL_MD_ACTION_VNI0) |
			BIT(NBL_MD_ACTION_VNI1) | BIT(NBL_MD_ACTION_PRBAC_IDX) |
			BIT(NBL_MD_ACTION_L4S_IDX) | BIT(NBL_MD_ACTION_DP_HASH0) |
			BIT(NBL_MD_ACTION_DP_HASH1) | BIT(NBL_MD_ACTION_MDF_PRI) |
			BIT(NBL_MD_ACTION_FLOW_CARIDX) |
			((u64)0xffffffff << 32)},
	[NBL_FWD_TYPE_OTHER_MIRROR]	= {
			BIT(NBL_MD_ACTION_FLOWID0) | BIT(NBL_MD_ACTION_FLOWID1) |
			BIT(NBL_MD_ACTION_RSSIDX) | BIT(NBL_MD_ACTION_TABLE_INDEX) |
			BIT(NBL_MD_ACTION_MCIDX) | BIT(NBL_MD_ACTION_VNI0) |
			BIT(NBL_MD_ACTION_VNI1) | BIT(NBL_MD_ACTION_PRBAC_IDX) |
			BIT(NBL_MD_ACTION_L4S_IDX) | BIT(NBL_MD_ACTION_DP_HASH0) |
			BIT(NBL_MD_ACTION_DP_HASH1) | BIT(NBL_MD_ACTION_MDF_PRI)},
	[NBL_FWD_TYPE_MNG]		= {0},
	[NBL_FWD_TYPE_GLB_LB]		= {0},
	[NBL_FWD_TYPE_DROP]		= {0},
};

static void nbl_epro_action_filter_cfg(struct nbl_phy_mgt *phy_mgt, u32 fwd_type,
				       struct nbl_epro_action_filter_tbl *cfg)
{
	if (fwd_type >= NBL_FWD_TYPE_MAX) {
		pr_err("fwd_type %u exceed the max num %u.", fwd_type, NBL_FWD_TYPE_MAX);
		return;
	}

	nbl_hw_write_regs(phy_mgt, NBL_EPRO_ACTION_FILTER_TABLE(fwd_type),
			  (u8 *)cfg, sizeof(*cfg));
}

static int nbl_epro_init(struct nbl_phy_mgt *phy_mgt)
{
	union epro_action_priority_u act_pri_def = {.info = {0}};
	u32 fwd_type = 0;

	nbl_epro_mirror_act_pri_init(phy_mgt, NULL);

	for (fwd_type = 0; fwd_type < NBL_FWD_TYPE_MAX; fwd_type++)
		nbl_epro_action_filter_cfg(phy_mgt, fwd_type,
					   &epro_action_filter_tbl_def[fwd_type]);

	act_pri_def.info.dport = 0x3;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_ACTION_PRIORITY_ADDR,
			  (u8 *)act_pri_def.data, sizeof(act_pri_def));

	return 0;
}

static int nbl_ppe_init(struct nbl_phy_mgt *phy_mgt)
{
	nbl_epro_init(phy_mgt);

	return 0;
}

static int nbl_host_padpt_init(struct nbl_phy_mgt *phy_mgt)
{
	struct nbl_host_native_tx_p tx_p;
	u32 pd_th = 0x10080;

	nbl_hw_read_regs(phy_mgt, NBL_HOST_PADPT_HOST_NATIVE_TX_P, (u8 *)&tx_p, sizeof(tx_p));
	if (tx_p.ava_data_credits > 512)
		pd_th = 0x10080;
	else if (tx_p.ava_data_credits > 256)
		pd_th = 0x10040;
	else
		pd_th = 0x10030;

	nbl_hw_wr32(phy_mgt, NBL_HOST_PADPT_HOST_CFG_FC_CPLH_UP, 0x10400);
	nbl_hw_wr32(phy_mgt, NBL_HOST_PADPT_HOST_CFG_FC_PD_DN, pd_th);
	nbl_hw_wr32(phy_mgt, NBL_HOST_PADPT_HOST_CFG_FC_PH_DN, 0x10010);
	nbl_hw_wr32(phy_mgt, NBL_HOST_PADPT_HOST_CFG_FC_NPH_DN, 0x10010);

	return 0;
}

/* set padpt debug reg to cap for aged stop */
static void nbl_host_pcap_init(struct nbl_phy_mgt *phy_mgt)
{
	int addr;

	/* tx */
	nbl_hw_wr32(phy_mgt, 0x15a4204, 0x4);
	nbl_hw_wr32(phy_mgt, 0x15a4208, 0x10);

	for (addr = 0x15a4300; addr <= 0x15a4338; addr += 4)
		nbl_hw_wr32(phy_mgt, addr, 0x0);
	nbl_hw_wr32(phy_mgt, 0x15a433c, 0xdf000000);

	for (addr = 0x15a4340; addr <= 0x15a437c; addr += 4)
		nbl_hw_wr32(phy_mgt, addr, 0x0);

	/* rx */
	nbl_hw_wr32(phy_mgt, 0x15a4804, 0x4);
	nbl_hw_wr32(phy_mgt, 0x15a4808, 0x20);

	for (addr = 0x15a4940; addr <= 0x15a4978; addr += 4)
		nbl_hw_wr32(phy_mgt, addr, 0x0);
	nbl_hw_wr32(phy_mgt, 0x15a497c, 0x0a000000);

	for (addr = 0x15a4900; addr <= 0x15a4938; addr += 4)
		nbl_hw_wr32(phy_mgt, addr, 0x0);
	nbl_hw_wr32(phy_mgt, 0x15a493c, 0xbe000000);

	nbl_hw_wr32(phy_mgt, 0x15a420c, 0x1);
	nbl_hw_wr32(phy_mgt, 0x15a480c, 0x1);
	nbl_hw_wr32(phy_mgt, 0x15a420c, 0x0);
	nbl_hw_wr32(phy_mgt, 0x15a480c, 0x0);
	nbl_hw_wr32(phy_mgt, 0x15a4200, 0x1);
	nbl_hw_wr32(phy_mgt, 0x15a4800, 0x1);
}

static int nbl_intf_init(struct nbl_phy_mgt *phy_mgt)
{
	nbl_host_padpt_init(phy_mgt);
	nbl_host_pcap_init(phy_mgt);

	return 0;
}

static void nbl_rdma_init(struct nbl_phy_mgt *phy_mgt)
{
	u32 data;

	data = nbl_hw_rd32(phy_mgt, NBL_TOP_CTRL_LB_CLK);
	data |= NBL_TOP_CTRL_RDMA_LB_CLK;
	nbl_hw_wr32(phy_mgt, NBL_TOP_CTRL_LB_CLK, data);

	data = nbl_hw_rd32(phy_mgt, NBL_TOP_CTRL_LB_RST);
	data &= ~NBL_TOP_CTRL_RDMA_LB_RST;
	nbl_hw_wr32(phy_mgt, NBL_TOP_CTRL_LB_RST, data);
}

static void nbl_phy_set_driver_status(void *priv, bool active)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	u32 status = 0;

	status = nbl_hw_rd32(phy_mgt, NBL_DRIVER_STATUS_REG);

	status = (status & ~(1 << NBL_DRIVER_STATUS_BIT)) | (active << NBL_DRIVER_STATUS_BIT);

	nbl_hw_wr32(phy_mgt, NBL_DRIVER_STATUS_REG, status);
}

static void nbl_phy_cfg_pp1_ecn_profiles(struct nbl_phy_mgt *phy_mgt)
{
	union pp1_kgen_key_prf_u kgen_prof;
	union nbl_pp_kgen_cam_u kgen_cam;
	union nbl_pp_kgen_flag_ext1_u kgen_flag_ext;
	union nbl_fem_em1_profile_table_u profile_table;
	u8 profile_index = NBL_PP1_ECN_STAT_PID;

	memset(&kgen_cam, 0, sizeof(kgen_cam));
	memset(&kgen_prof, 0, sizeof(kgen_prof));
	memset(&kgen_flag_ext, 0, sizeof(kgen_flag_ext));
	memset(&profile_table, 0, sizeof(profile_table));

	/* read and write pp1 kgen flag ext1 */
	nbl_hw_read_regs(phy_mgt, NBL_PP1_KGEN_FLAG_EXT1_ADDR,
			 (u8 *)&kgen_flag_ext, sizeof(kgen_flag_ext));
	kgen_flag_ext.info.flag4_en = 1;
	kgen_flag_ext.info.flag4_oft = 0xa;
	nbl_hw_write_regs(phy_mgt, NBL_PP1_KGEN_FLAG_EXT1_ADDR,
			  (u8 *)&kgen_flag_ext, sizeof(kgen_flag_ext));

	/* write pp1 kgen tcam */
	kgen_cam.info.mask = 0xe8ff;
	kgen_cam.info.ptype = 0x0;
	kgen_cam.info.flag = 0x15;
	kgen_cam.info.valid = 1;
	nbl_hw_write_regs(phy_mgt, NBL_PP1_KGEN_CAM_REG(profile_index),
			  (u8 *)&kgen_cam, sizeof(kgen_cam));

	/* write pp1 kgen profile */
	kgen_prof.info.sp_4_en = 1;
	kgen_prof.info.sp_4_src_offset = 0;
	kgen_prof.info.sp_4_dst_offset = 1;
	kgen_prof.info.ext4_0_dst = 0;
	kgen_prof.info.ext4_0_src = 0x27F;
	kgen_prof.info.bts_en0 = 1;
	kgen_prof.info.bts_data0 = 0;
	kgen_prof.info.bts_des_offset0 = 0;
	kgen_prof.info.bts_en1 = 1;
	kgen_prof.info.bts_data1 = 0;
	kgen_prof.info.bts_des_offset1 = 1;
	nbl_hw_write_regs(phy_mgt, NBL_PP1_KGEN_PROFILE(profile_index),
			  (u8 *)&kgen_prof, sizeof(kgen_prof));

	/* write fem em1 profile table */
	profile_table.info.cmd = 0;
	profile_table.info.key_size = 0;
	profile_table.info.mask_btm0 = 0x3FFFFFFF;
	profile_table.info.mask_btm1 = 0xFFFFFFFF;
	profile_table.info.mask_btm2 = 0x7FF;
	profile_table.info.hash_sel0 = 0;
	profile_table.info.hash_sel1 = 3;
	profile_table.info.act_num = 1;
	profile_table.info.valid = 1;
	nbl_hw_write_regs(phy_mgt, NBL_FEM_EM1_PROFILE_TABLE_REG(profile_index),
			  (u8 *)&profile_table, sizeof(profile_table));
}

static void nbl_phy_cfg_tnl_offload_profile(void *priv, u8 mode)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union pp1_kgen_key_prf_u kgen_key_prf = {.info = {0}};
	u8 profile_index = 2;

	/* disable extraction of dmac for tunnel L2 profile */
	nbl_hw_read_regs(phy_mgt, NBL_PP1_KGEN_PROFILE(profile_index), (u8 *)&kgen_key_prf,
			 sizeof(kgen_key_prf));
	if (mode) {
		kgen_key_prf.info.ext32_1_src = 0;
		kgen_key_prf.info.ext16_0_src = 0;
	} else {
		kgen_key_prf.info.ext32_1_src = 0x48;
		kgen_key_prf.info.ext16_0_src = 0x92;
	}
	nbl_hw_write_regs(phy_mgt, NBL_PP1_KGEN_PROFILE(profile_index), (u8 *)&kgen_key_prf,
			  sizeof(kgen_key_prf));

	/* disable extraction of dmac for L2 profile */
	profile_index = 3;
	nbl_hw_read_regs(phy_mgt, NBL_PP1_KGEN_PROFILE(profile_index), (u8 *)&kgen_key_prf,
			 sizeof(kgen_key_prf));
	if (mode) {
		kgen_key_prf.info.ext32_0_src = 0;
		kgen_key_prf.info.ext16_0_src = 0;
	} else {
		kgen_key_prf.info.ext32_0_src = 0x48;
		kgen_key_prf.info.ext16_0_src = 0x92;
	}
	nbl_hw_write_regs(phy_mgt, NBL_PP1_KGEN_PROFILE(profile_index), (u8 *)&kgen_key_prf,
			  sizeof(kgen_key_prf));

	/* disable extraction of IPv4 L3 ttl & tos */
	profile_index = 0;
	nbl_hw_read_regs(phy_mgt, NBL_PP2_KGEN_PROFILE(profile_index), (u8 *)&kgen_key_prf,
			 sizeof(kgen_key_prf));
	if (mode) {
		kgen_key_prf.info.ext8_0_src = 0;
		kgen_key_prf.info.ext8_1_src = 0;
	} else {
		kgen_key_prf.info.ext8_0_src = 0x140;
		kgen_key_prf.info.ext8_1_src = 0x13f;
	}
	nbl_hw_write_regs(phy_mgt, NBL_PP2_KGEN_PROFILE(profile_index), (u8 *)&kgen_key_prf,
			  sizeof(kgen_key_prf));

	/* disable extraction of IPv6 L3 ttl & tos */
	profile_index = 1;
	nbl_hw_read_regs(phy_mgt, NBL_PP2_KGEN_PROFILE(profile_index), (u8 *)&kgen_key_prf,
			 sizeof(kgen_key_prf));
	if (mode) {
		kgen_key_prf.info.ext8_0_src = 0;
		kgen_key_prf.info.ext8_1_src = 0;
	} else {
		kgen_key_prf.info.ext8_0_src = 0x140;
		kgen_key_prf.info.ext8_1_src = 0x13f;
	}
	nbl_hw_write_regs(phy_mgt, NBL_PP2_KGEN_PROFILE(profile_index), (u8 *)&kgen_key_prf,
			  sizeof(kgen_key_prf));
}

static int nbl_phy_init_chip_module(void *priv, u8 eth_speed, u8 eth_num)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_info(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_PHY, "phy_chip_init");

	nbl_rdma_init(phy_mgt);
	nbl_dp_init(phy_mgt, eth_speed, eth_num);
	nbl_ppe_init(phy_mgt);
	nbl_intf_init(phy_mgt);

	/* init all p4 registers */
	nbl_write_all_regs(phy_mgt);
	nbl_phy_cfg_pp1_ecn_profiles(phy_mgt);

	phy_mgt->version = nbl_hw_rd32(phy_mgt, NBL_HW_DUMMY_REG);

	return 0;
}

static int nbl_phy_set_qid_map_table(void *priv, void *data, int qid_map_select)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct nbl_qid_map_param *param = (struct nbl_qid_map_param *)data;
	struct nbl_virtio_qid_map_table info = {0}, info_data = {0};
	struct nbl_queue_table_select select = {0};
	u64 reg;
	int i, j;

	if (phy_mgt->hw_status)
		return 0;

	for (i = 0; i < param->len; i++) {
		j = 0;

		info.local_qid = param->qid_map[i].local_qid;
		info.notify_addr_l = param->qid_map[i].notify_addr_l;
		info.notify_addr_h = param->qid_map[i].notify_addr_h;
		info.global_qid = param->qid_map[i].global_qid;
		info.ctrlq_flag = param->qid_map[i].ctrlq_flag;

		do {
			reg = NBL_PCOMPLETER_QID_MAP_REG_ARR(qid_map_select, param->start + i);
			nbl_hw_write_regs(phy_mgt, reg, (u8 *)(&info), sizeof(info));
			nbl_hw_read_regs(phy_mgt, reg, (u8 *)(&info_data), sizeof(info_data));
			if (likely(!memcmp(&info, &info_data, sizeof(info))))
				break;
			j++;
		} while (j < NBL_REG_WRITE_MAX_TRY_TIMES);

		if (j == NBL_REG_WRITE_MAX_TRY_TIMES)
			nbl_err(common, NBL_DEBUG_QUEUE, "Write to qid map table entry %d failed\n",
				param->start + i);
	}

	select.select = qid_map_select;
	nbl_hw_write_regs(phy_mgt, NBL_PCOMPLETER_QUEUE_TABLE_SELECT_REG,
			  (u8 *)&select, sizeof(select));

	return 0;
}

static int nbl_phy_set_qid_map_ready(void *priv, bool ready)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_queue_table_ready queue_table_ready = {0};

	queue_table_ready.ready = ready;
	nbl_hw_write_regs(phy_mgt, NBL_PCOMPLETER_QUEUE_TABLE_READY_REG,
			  (u8 *)&queue_table_ready, sizeof(queue_table_ready));

	return 0;
}

static int nbl_phy_cfg_ipro_queue_tbl(void *priv, u16 queue_id, u16 vsi_id, u8 enable)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_ipro_queue_tbl ipro_queue_tbl = {0};

	ipro_queue_tbl.vsi_en = enable;
	ipro_queue_tbl.vsi_id = vsi_id;

	nbl_hw_write_regs(phy_mgt, NBL_IPRO_QUEUE_TBL(queue_id),
			  (u8 *)&ipro_queue_tbl, sizeof(ipro_queue_tbl));

	return 0;
}

static int nbl_phy_cfg_ipro_dn_sport_tbl(void *priv, u16 vsi_id, u16 dst_eth_id,
					 u16 bmode, bool binit)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_ipro_dn_src_port_tbl dpsport = {0};

	if (binit) {
		dpsport.entry_vld = 1;
		dpsport.phy_flow = 1;
		dpsport.set_dport.dport.down.upcall_flag = AUX_FWD_TYPE_NML_FWD;
		dpsport.set_dport.dport.down.port_type = SET_DPORT_TYPE_ETH_LAG;
		dpsport.set_dport.dport.down.lag_vld = 0;
		dpsport.set_dport.dport.down.eth_vld = 1;
		dpsport.set_dport.dport.down.eth_id = dst_eth_id;
		dpsport.vlan_layer_num_1 = 3;
		dpsport.set_dport_en = 1;
	} else {
		nbl_hw_read_regs(phy_mgt, NBL_IPRO_DN_SRC_PORT_TABLE(vsi_id),
				 (u8 *)&dpsport, sizeof(struct nbl_ipro_dn_src_port_tbl));
	}

	if (bmode == BRIDGE_MODE_VEPA)
		dpsport.set_dport.dport.down.next_stg_sel = NEXT_STG_SEL_EPRO;
	else
		dpsport.set_dport.dport.down.next_stg_sel = NEXT_STG_SEL_NONE;

	nbl_hw_write_regs(phy_mgt, NBL_IPRO_DN_SRC_PORT_TABLE(vsi_id),
			  (u8 *)&dpsport, sizeof(struct nbl_ipro_dn_src_port_tbl));

	return 0;
}

static int nbl_phy_set_vnet_queue_info(void *priv, struct nbl_vnet_queue_info_param *param,
				       u16 queue_id)
{
	struct nbl_phy_mgt_leonis *phy_mgt_leonis = (struct nbl_phy_mgt_leonis *)priv;
	struct nbl_phy_mgt *phy_mgt = &phy_mgt_leonis->phy_mgt;
	struct nbl_host_vnet_qinfo host_vnet_qinfo = {0};

	host_vnet_qinfo.function_id = param->function_id;
	host_vnet_qinfo.device_id = param->device_id;
	host_vnet_qinfo.bus_id = param->bus_id;
	host_vnet_qinfo.valid = param->valid;
	host_vnet_qinfo.msix_idx = param->msix_idx;
	host_vnet_qinfo.msix_idx_valid = param->msix_idx_valid;
	if (phy_mgt_leonis->ro_enable) {
		host_vnet_qinfo.ido_en = 1;
		host_vnet_qinfo.rlo_en = 1;
	}

	nbl_hw_write_regs(phy_mgt, NBL_PADPT_HOST_VNET_QINFO_REG_ARR(queue_id),
			  (u8 *)&host_vnet_qinfo, sizeof(host_vnet_qinfo));

	return 0;
}

static int nbl_phy_clear_vnet_queue_info(void *priv, u16 queue_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_host_vnet_qinfo host_vnet_qinfo = {0};

	nbl_hw_write_regs(phy_mgt, NBL_PADPT_HOST_VNET_QINFO_REG_ARR(queue_id),
			  (u8 *)&host_vnet_qinfo, sizeof(host_vnet_qinfo));
	return 0;
}

static int nbl_phy_cfg_vnet_qinfo_log(void *priv, u16 queue_id, bool vld)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_host_vnet_qinfo host_vnet_qinfo = {0};

	nbl_hw_read_regs(phy_mgt, NBL_PADPT_HOST_VNET_QINFO_REG_ARR(queue_id),
			 (u8 *)&host_vnet_qinfo, sizeof(host_vnet_qinfo));
	host_vnet_qinfo.log_en = vld;
	nbl_hw_write_regs(phy_mgt, NBL_PADPT_HOST_VNET_QINFO_REG_ARR(queue_id),
			  (u8 *)&host_vnet_qinfo, sizeof(host_vnet_qinfo));

	return 0;
}

static int nbl_phy_reset_dvn_cfg(void *priv, u16 queue_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct nbl_dvn_queue_reset queue_reset = {0};
	struct nbl_dvn_queue_reset_done queue_reset_done = {0};
	int i = 0;

	queue_reset.dvn_queue_index = queue_id;
	queue_reset.vld = 1;
	nbl_hw_write_regs(phy_mgt, NBL_DVN_QUEUE_RESET_REG,
			  (u8 *)&queue_reset, sizeof(queue_reset));

	udelay(5);
	nbl_hw_read_regs(phy_mgt, NBL_DVN_QUEUE_RESET_DONE_REG,
			 (u8 *)&queue_reset_done, sizeof(queue_reset_done));
	while (!queue_reset_done.flag) {
		i++;
		if (!(i % 10)) {
			nbl_err(common, NBL_DEBUG_QUEUE, "Wait too long for tx queue reset to be done");
			break;
		}

		udelay(5);
		nbl_hw_read_regs(phy_mgt, NBL_DVN_QUEUE_RESET_DONE_REG,
				 (u8 *)&queue_reset_done, sizeof(queue_reset_done));
	}

	nbl_debug(common, NBL_DEBUG_QUEUE, "dvn:%u cfg reset succedd, wait %d 5ns\n", queue_id, i);
	return 0;
}

static int nbl_phy_reset_uvn_cfg(void *priv, u16 queue_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct nbl_uvn_queue_reset queue_reset = {0};
	struct nbl_uvn_queue_reset_done queue_reset_done = {0};
	int i = 0;

	queue_reset.index = queue_id;
	queue_reset.vld = 1;
	nbl_hw_write_regs(phy_mgt, NBL_UVN_QUEUE_RESET_REG,
			  (u8 *)&queue_reset, sizeof(queue_reset));

	udelay(5);
	nbl_hw_read_regs(phy_mgt, NBL_UVN_QUEUE_RESET_DONE_REG,
			 (u8 *)&queue_reset_done, sizeof(queue_reset_done));
	while (!queue_reset_done.flag) {
		i++;
		if (!(i % 10)) {
			nbl_err(common, NBL_DEBUG_QUEUE, "Wait too long for rx queue reset to be done");
			break;
		}

		udelay(5);
		nbl_hw_read_regs(phy_mgt, NBL_UVN_QUEUE_RESET_DONE_REG,
				 (u8 *)&queue_reset_done, sizeof(queue_reset_done));
	}

	nbl_debug(common, NBL_DEBUG_QUEUE, "uvn:%u cfg reset succedd, wait %d 5ns\n", queue_id, i);
	return 0;
}

static int nbl_phy_restore_dvn_context(void *priv, u16 queue_id, u16 split, u16 last_avail_index)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct dvn_queue_context cxt = {0};

	cxt.dvn_ring_wrap_counter = last_avail_index >> 15;
	if (split)
		cxt.dvn_avail_ring_read = last_avail_index;
	else
		cxt.dvn_L1_ring_read = last_avail_index & 0x7FFF;

	nbl_hw_write_regs(phy_mgt, NBL_DVN_QUEUE_CXT_TABLE_ARR(queue_id), (u8 *)&cxt, sizeof(cxt));
	nbl_info(common, NBL_DEBUG_QUEUE, "config tx ring: %u, last avail idx: %u\n",
		 queue_id, last_avail_index);

	return 0;
}

static int nbl_phy_restore_uvn_context(void *priv, u16 queue_id, u16 split, u16 last_avail_index)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct uvn_queue_cxt cxt = {0};

	cxt.wrap_count = last_avail_index >> 15;
	if (split)
		cxt.queue_head = last_avail_index;
	else
		cxt.queue_head = last_avail_index & 0x7FFF;

	nbl_hw_write_regs(phy_mgt, NBL_UVN_QUEUE_CXT_TABLE_ARR(queue_id), (u8 *)&cxt, sizeof(cxt));
	nbl_info(common, NBL_DEBUG_QUEUE, "config rx ring: %u, last avail idx: %u\n",
		 queue_id, last_avail_index);

	return 0;
}

static int nbl_phy_get_tx_queue_cfg(void *priv, void *data, u16 queue_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_queue_cfg_param *queue_cfg = (struct nbl_queue_cfg_param *)data;
	struct dvn_queue_table info = {0};

	nbl_hw_read_regs(phy_mgt, NBL_DVN_QUEUE_TABLE_ARR(queue_id), (u8 *)&info, sizeof(info));

	queue_cfg->desc = info.dvn_queue_baddr;
	queue_cfg->avail = info.dvn_avail_baddr;
	queue_cfg->used = info.dvn_used_baddr;
	queue_cfg->size = info.dvn_queue_size;
	queue_cfg->split = info.dvn_queue_type;
	queue_cfg->extend_header = info.dvn_extend_header_en;

	return 0;
}

static int nbl_phy_get_rx_queue_cfg(void *priv, void *data, u16 queue_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_queue_cfg_param *queue_cfg = (struct nbl_queue_cfg_param *)data;
	struct uvn_queue_table info = {0};

	nbl_hw_read_regs(phy_mgt, NBL_UVN_QUEUE_TABLE_ARR(queue_id), (u8 *)&info, sizeof(info));

	queue_cfg->desc = info.queue_baddr;
	queue_cfg->avail = info.avail_baddr;
	queue_cfg->used = info.used_baddr;
	queue_cfg->size = info.queue_size_mask_pow;
	queue_cfg->split = info.queue_type;
	queue_cfg->extend_header = info.extend_header_en;
	queue_cfg->half_offload_en = info.half_offload_en;
	queue_cfg->rxcsum = info.guest_csum_en;

	return 0;
}

static int nbl_phy_cfg_tx_queue(void *priv, void *data, u16 queue_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_queue_cfg_param *queue_cfg = (struct nbl_queue_cfg_param *)data;
	struct dvn_queue_table info = {0};

	info.dvn_queue_baddr = queue_cfg->desc;
	if (!queue_cfg->split && !queue_cfg->extend_header)
		queue_cfg->avail = queue_cfg->avail | 3;
	info.dvn_avail_baddr = queue_cfg->avail;
	info.dvn_used_baddr = queue_cfg->used;
	info.dvn_queue_size = ilog2(queue_cfg->size);
	info.dvn_queue_type = queue_cfg->split;
	info.dvn_queue_en = 1;
	info.dvn_extend_header_en = queue_cfg->extend_header;
	info.dvn_interleave_seg_disable = queue_cfg->interleave_seg_disable;

	nbl_hw_write_regs(phy_mgt, NBL_DVN_QUEUE_TABLE_ARR(queue_id), (u8 *)&info, sizeof(info));

	return 0;
}

static int nbl_phy_cfg_rx_queue(void *priv, void *data, u16 queue_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_queue_cfg_param *queue_cfg = (struct nbl_queue_cfg_param *)data;
	struct uvn_queue_table info = {0};

	info.queue_baddr = queue_cfg->desc;
	info.avail_baddr = queue_cfg->avail;
	info.used_baddr = queue_cfg->used;
	info.queue_size_mask_pow = ilog2(queue_cfg->size);
	info.queue_type = queue_cfg->split;
	info.extend_header_en = queue_cfg->extend_header;
	info.half_offload_en = queue_cfg->half_offload_en;
	info.guest_csum_en = queue_cfg->rxcsum;
	info.queue_enable = 1;

	nbl_hw_write_regs(phy_mgt, NBL_UVN_QUEUE_TABLE_ARR(queue_id), (u8 *)&info, sizeof(info));

	return 0;
}

static bool nbl_phy_check_q2tc(void *priv, u16 queue_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct dsch_vn_q2tc_cfg_tbl info;

	nbl_hw_read_regs(phy_mgt, NBL_DSCH_VN_Q2TC_CFG_TABLE_REG_ARR(queue_id),
			 (u8 *)&info, sizeof(info));
	return info.vld;
}

static int nbl_phy_cfg_q2tc_netid(void *priv, u16 queue_id, u16 netid, u16 vld)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct dsch_vn_q2tc_cfg_tbl info;

	nbl_hw_read_regs(phy_mgt, NBL_DSCH_VN_Q2TC_CFG_TABLE_REG_ARR(queue_id),
			 (u8 *)&info, sizeof(info));
	info.tcid = (info.tcid & 0x7) | (netid << 3);
	info.vld = vld;

	nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_Q2TC_CFG_TABLE_REG_ARR(queue_id),
			  (u8 *)&info, sizeof(info));
	return 0;
}

static int nbl_phy_cfg_q2tc_tcid(void *priv, u16 queue_id, u16 tcid)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct dsch_vn_q2tc_cfg_tbl info;

	nbl_hw_read_regs(phy_mgt, NBL_DSCH_VN_Q2TC_CFG_TABLE_REG_ARR(queue_id),
			 (u8 *)&info, sizeof(info));
	info.tcid = (info.tcid & 0xFFF8) | tcid;

	nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_Q2TC_CFG_TABLE_REG_ARR(queue_id),
			  (u8 *)&info, sizeof(info));
	return 0;
}

static int nbl_phy_set_tc_wgt(void *priv, u16 func_id, u8 *weight, u16 num_tc)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union dsch_vn_tc_wgt_cfg_tbl_u wgt_cfg = {.info = {0}};
	int i;

	for (i = 0; i < num_tc; i++)
		wgt_cfg.data[i] = weight[i];
	nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_TC_WGT_CFG_TABLE_REG_ARR(func_id),
			  wgt_cfg.data, sizeof(wgt_cfg));

	return 0;
}

static void nbl_phy_active_shaping(void *priv, u16 func_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_shaping_net shaping_net = {0};
	struct dsch_vn_sha2net_map_tbl sha2net = {0};
	struct dsch_vn_net2sha_map_tbl net2sha = {0};

	nbl_hw_read_regs(phy_mgt, NBL_SHAPING_NET(func_id),
			 (u8 *)&shaping_net, sizeof(shaping_net));

	if (!shaping_net.depth)
		return;

	sha2net.vld = 1;
	nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_SHA2NET_MAP_TABLE_REG_ARR(func_id),
			  (u8 *)&sha2net, sizeof(sha2net));

	shaping_net.valid = 1;
	nbl_hw_write_regs(phy_mgt, NBL_SHAPING_NET(func_id),
			  (u8 *)&shaping_net, sizeof(shaping_net));

	net2sha.vld = 1;
	nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_NET2SHA_MAP_TABLE_REG_ARR(func_id),
			  (u8 *)&net2sha, sizeof(net2sha));
}

static void nbl_phy_deactive_shaping(void *priv, u16 func_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_shaping_net shaping_net = {0};
	struct dsch_vn_sha2net_map_tbl sha2net = {0};
	struct dsch_vn_net2sha_map_tbl net2sha = {0};

	nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_NET2SHA_MAP_TABLE_REG_ARR(func_id),
			  (u8 *)&net2sha, sizeof(net2sha));

	nbl_hw_read_regs(phy_mgt, NBL_SHAPING_NET(func_id),
			 (u8 *)&shaping_net, sizeof(shaping_net));
	shaping_net.valid = 0;
	nbl_hw_write_regs(phy_mgt, NBL_SHAPING_NET(func_id),
			  (u8 *)&shaping_net, sizeof(shaping_net));

	nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_SHA2NET_MAP_TABLE_REG_ARR(func_id),
			  (u8 *)&sha2net, sizeof(sha2net));
}

static int nbl_phy_set_shaping(void *priv, u16 func_id, u64 total_tx_rate, u64 burst,
			       u8 vld, bool active)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_shaping_net shaping_net = {0};
	struct dsch_vn_sha2net_map_tbl sha2net = {0};
	struct dsch_vn_net2sha_map_tbl net2sha = {0};

	if (vld) {
		sha2net.vld = active;
		nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_SHA2NET_MAP_TABLE_REG_ARR(func_id),
				  (u8 *)&sha2net, sizeof(sha2net));
	} else {
		net2sha.vld = vld;
		nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_NET2SHA_MAP_TABLE_REG_ARR(func_id),
				  (u8 *)&net2sha, sizeof(net2sha));
	}

	/* cfg shaping cir/pir */
	if (vld) {
		shaping_net.valid = active;
		/* total_tx_rate unit Mb/s  */
		/* cir 1 default represents 1Mbps */
		shaping_net.cir = total_tx_rate;
		/* pir equal cir */
		shaping_net.pir = shaping_net.cir;
		if (burst)
			shaping_net.depth = burst;
		else
			shaping_net.depth = max(shaping_net.cir * 2,
						NBL_LR_LEONIS_NET_BUCKET_DEPTH);
		shaping_net.cbs = shaping_net.depth;
		shaping_net.pbs = shaping_net.depth;
	}

	nbl_hw_write_regs(phy_mgt, NBL_SHAPING_NET(func_id),
			  (u8 *)&shaping_net, sizeof(shaping_net));

	if (!vld) {
		sha2net.vld = vld;
		nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_SHA2NET_MAP_TABLE_REG_ARR(func_id),
				  (u8 *)&sha2net, sizeof(sha2net));
	} else {
		net2sha.vld = active;
		nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_NET2SHA_MAP_TABLE_REG_ARR(func_id),
				  (u8 *)&net2sha, sizeof(net2sha));
	}

	return 0;
}

static void nbl_phy_set_offload_shaping(struct nbl_phy_mgt *phy_mgt,
					struct nbl_chan_regs_info *reg_info, u32 *value)
{
	struct nbl_shaping_net *shaping_net;
	struct dsch_vn_sha2net_map_tbl *sha2net;
	struct dsch_vn_net2sha_map_tbl *net2sha;
	struct dsch_vn_n2g_cfg_tbl dsch_info = {0};

	nbl_hw_read_regs(phy_mgt, NBL_DSCH_VN_N2G_CFG_TABLE_REG_ARR(reg_info->depth),
			 (u8 *)&dsch_info, sizeof(dsch_info));

	switch (reg_info->tbl_name) {
	case NBL_FLOW_SHAPING_NET_REG:
		shaping_net = (struct nbl_shaping_net *)value;
		shaping_net->valid &= dsch_info.vld;
		nbl_hw_write_regs(phy_mgt, NBL_SHAPING_NET(reg_info->depth),
				  (u8 *)shaping_net, sizeof(*shaping_net));
		break;
	case NBL_FLOW_DSCH_VN_NET2SHA_MAP_TBL_REG:
		sha2net = (struct dsch_vn_sha2net_map_tbl *)value;
		sha2net->vld &= dsch_info.vld;
		nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_SHA2NET_MAP_TABLE_REG_ARR(reg_info->depth),
				  (u8 *)sha2net, sizeof(*sha2net));
		break;
	case NBL_FLOW_DSCH_VN_SHA2NET_MAP_TBL_REG:
		net2sha = (struct dsch_vn_net2sha_map_tbl *)value;
		net2sha->vld &= dsch_info.vld;
		nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_NET2SHA_MAP_TABLE_REG_ARR(reg_info->depth),
				  (u8 *)net2sha, sizeof(*net2sha));
		break;
	}
}

static int nbl_phy_set_ucar(void *priv, u16 vsi_id, u64 totel_rx_rate, u64 burst,
			    u8 vld)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	union ucar_flow_u ucar_flow = {.info = {0}};
	union epro_vpt_u epro_vpt = {.info = {0}};
	int car_id = 0;
	int index = 0;

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_VPT_REG(vsi_id),
			 (u8 *)&epro_vpt, sizeof(epro_vpt));
	if (vld) {
		if (epro_vpt.info.car_en) {
			car_id = epro_vpt.info.car_id;
		} else {
			epro_vpt.info.car_en = 1;
			for (; index < 1024; index++) {
				nbl_hw_read_regs(phy_mgt, NBL_UCAR_FLOW_REG(index),
						 (u8 *)&ucar_flow, sizeof(ucar_flow));
				if (ucar_flow.info.valid == 0) {
					car_id = index;
					break;
				}
			}
			if (car_id == 1024) {
				nbl_err(common, NBL_DEBUG_PHY, "Car ID exceeds the valid range!");
				return -ENOMEM;
			}
			epro_vpt.info.car_id = car_id;
			nbl_hw_write_regs(phy_mgt, NBL_EPRO_VPT_REG(vsi_id),
					  (u8 *)&epro_vpt, sizeof(epro_vpt));
		}
	} else {
		epro_vpt.info.car_en = 0;
		car_id = epro_vpt.info.car_id;
		epro_vpt.info.car_id = 0;
		nbl_hw_write_regs(phy_mgt, NBL_EPRO_VPT_REG(vsi_id),
				  (u8 *)&epro_vpt, sizeof(epro_vpt));
	}

	if (vld) {
		ucar_flow.info.valid = 1;
		ucar_flow.info.cir = totel_rx_rate;
		ucar_flow.info.pir = totel_rx_rate;
		if (burst)
			ucar_flow.info.depth = burst;
		else
			ucar_flow.info.depth = NBL_UCAR_MAX_BUCKET_DEPTH;
		ucar_flow.info.cbs = ucar_flow.info.depth;
		ucar_flow.info.pbs = ucar_flow.info.depth;
	}
	nbl_hw_write_regs(phy_mgt, NBL_UCAR_FLOW_REG(car_id),
			  (u8 *)&ucar_flow, sizeof(ucar_flow));

	return 0;
}

static void nbl_phy_set_shaping_dport_vld(void *priv, u8 eth_id, bool vld)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_shaping_net shaping_net = {0};

	nbl_hw_read_regs(phy_mgt, NBL_SHAPING_DPORT_REG(eth_id),
			 (u8 *)&shaping_net, sizeof(shaping_net));

	if (vld)
		shaping_net.valid = 1;
	else
		shaping_net.valid = 0;

	nbl_hw_write_regs(phy_mgt, NBL_SHAPING_DPORT_REG(eth_id),
			  (u8 *)&shaping_net, sizeof(shaping_net));
}

static void nbl_phy_set_dport_fc_th_vld(void *priv, u8 eth_id, bool vld)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct dstore_d_dport_fc_th fc_th = {0};

	nbl_hw_read_regs(phy_mgt, NBL_DSTORE_D_DPORT_FC_TH_REG(eth_id),
			 (u8 *)&fc_th, sizeof(fc_th));

	if (vld)
		fc_th.fc_en = 1;
	else
		fc_th.fc_en = 0;

	nbl_hw_write_regs(phy_mgt, NBL_DSTORE_D_DPORT_FC_TH_REG(eth_id),
			  (u8 *)&fc_th, sizeof(fc_th));
}

static int nbl_phy_cfg_dsch_net_to_group(void *priv, u16 func_id, u16 group_id, u16 vld)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct dsch_vn_n2g_cfg_tbl info = {0};

	info.grpid = group_id;
	info.vld = vld;
	nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_N2G_CFG_TABLE_REG_ARR(func_id),
			  (u8 *)&info, sizeof(info));
	return 0;
}

static int nbl_phy_cfg_epro_rss_ret(void *priv, u32 index, u16 size_unit, u8 size_type,
				    u32 q_num, u16 *queue_list, const u32 *indir)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct nbl_epro_rss_ret_tbl rss_ret = {0};
	u32 table_id, table_end, group_count, odd_num, queue_id = 0;

	group_count = NBL_EPRO_RSS_ENTRY_SIZE_UNIT << size_type;
	if (group_count > NBL_EPRO_RSS_ENTRY_MAX_COUNT) {
		nbl_err(common, NBL_DEBUG_QUEUE,
			"Rss group entry size type %u exceed the max value %u",
			size_type, NBL_EPRO_RSS_ENTRY_SIZE_256);
		return -EINVAL;
	}

	if (q_num > group_count) {
		nbl_err(common, NBL_DEBUG_QUEUE,
			"q_num %u exceed the rss group count %u\n", q_num, group_count);
		return -EINVAL;
	}
	if (index >= NBL_EPRO_RSS_RET_TBL_DEPTH ||
	    (index + group_count) > NBL_EPRO_RSS_RET_TBL_DEPTH) {
		nbl_err(common, NBL_DEBUG_QUEUE,
			"index %u exceed the max table entry %u, entry size: %u\n",
			index, NBL_EPRO_RSS_RET_TBL_DEPTH, group_count);
		return -EINVAL;
	}

	table_id = index / 2;
	table_end = (index + group_count) / 2;
	odd_num = index % 2;
	nbl_hw_read_regs(phy_mgt, NBL_EPRO_RSS_RET_TABLE(table_id),
			 (u8 *)&rss_ret, sizeof(rss_ret));

	if (indir) {
		if (odd_num) {
			rss_ret.vld1 = 1;
			rss_ret.dqueue1 = indir[queue_id++];
			nbl_hw_write_regs(phy_mgt, NBL_EPRO_RSS_RET_TABLE(table_id),
					  (u8 *)&rss_ret, sizeof(rss_ret));
			table_id++;
		}

		for (; table_id < table_end; table_id++) {
			rss_ret.vld0 = 1;
			rss_ret.dqueue0 = indir[queue_id++];
			rss_ret.vld1 = 1;
			rss_ret.dqueue1 = indir[queue_id++];
			nbl_hw_write_regs(phy_mgt, NBL_EPRO_RSS_RET_TABLE(table_id),
					  (u8 *)&rss_ret, sizeof(rss_ret));
		}

		nbl_hw_read_regs(phy_mgt, NBL_EPRO_RSS_RET_TABLE(table_id),
				 (u8 *)&rss_ret, sizeof(rss_ret));

		if (odd_num) {
			rss_ret.vld0 = 1;
			rss_ret.dqueue0 = indir[queue_id++];
			nbl_hw_write_regs(phy_mgt, NBL_EPRO_RSS_RET_TABLE(table_id),
					  (u8 *)&rss_ret, sizeof(rss_ret));
		}
	} else {
		if (odd_num) {
			rss_ret.vld1 = 1;
			rss_ret.dqueue1 = queue_list[queue_id++];
			nbl_hw_write_regs(phy_mgt, NBL_EPRO_RSS_RET_TABLE(table_id),
					  (u8 *)&rss_ret, sizeof(rss_ret));
			table_id++;
		}

		queue_id = queue_id % q_num;
		for (; table_id < table_end; table_id++) {
			rss_ret.vld0 = 1;
			rss_ret.dqueue0 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.vld1 = 1;
			rss_ret.dqueue1 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			nbl_hw_write_regs(phy_mgt, NBL_EPRO_RSS_RET_TABLE(table_id),
					  (u8 *)&rss_ret, sizeof(rss_ret));
		}

		nbl_hw_read_regs(phy_mgt, NBL_EPRO_RSS_RET_TABLE(table_id),
				 (u8 *)&rss_ret, sizeof(rss_ret));

		if (odd_num) {
			rss_ret.vld0 = 1;
			rss_ret.dqueue0 = queue_list[queue_id++];
			nbl_hw_write_regs(phy_mgt, NBL_EPRO_RSS_RET_TABLE(table_id),
					  (u8 *)&rss_ret, sizeof(rss_ret));
		}
	}

	return 0;
}

static struct nbl_epro_rss_key epro_rss_key_def = {
	.key0		= 0x6d5a6d5a6d5a6d5a,
	.key1		= 0x6d5a6d5a6d5a6d5a,
	.key2		= 0x6d5a6d5a6d5a6d5a,
	.key3		= 0x6d5a6d5a6d5a6d5a,
	.key4		= 0x6d5a6d5a6d5a6d5a,
};

static int nbl_phy_init_epro_rss_key(void *priv, u16 table_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_hw_write_regs(phy_mgt, NBL_EPRO_RSS_KEY_REG,
			  (u8 *)&epro_rss_key_def, sizeof(epro_rss_key_def));

	return 0;
}

static void nbl_phy_get_epro_rss_key(void *priv, u16 vsi_id, u8 *rss_key)
{
	nbl_hw_read_regs(priv, NBL_EPRO_RSS_KEY_REG,
			 rss_key, sizeof(struct nbl_epro_rss_key));
}

static int nbl_phy_set_epro_rss_key(void *priv, const u8 *rss_key, u16 table_id)
{
	nbl_hw_write_regs(priv, NBL_EPRO_RSS_KEY_REG,
			  rss_key, sizeof(struct nbl_epro_rss_key));

	return 0;
}

static void nbl_phy_read_rss_indir(void *priv, u16 vsi_id, u32 *rss_indir,
				   u16 rss_ret_base, u16 rss_entry_size)
{
	struct nbl_epro_rss_ret_tbl rss_ret = {0};
	int i = 0;
	u32 table_id, table_end, group_count, odd_num;

	group_count = NBL_EPRO_RSS_ENTRY_SIZE_UNIT << rss_entry_size;
	table_id = rss_ret_base / 2;
	table_end = (rss_ret_base + group_count) / 2;
	odd_num = rss_ret_base % 2;

	if (odd_num) {
		nbl_hw_read_regs(priv, NBL_EPRO_RSS_RET_TABLE(table_id),
				 (u8 *)&rss_ret, sizeof(rss_ret));
		rss_indir[i++] = rss_ret.dqueue1;
	}

	for (; table_id < table_end; table_id++) {
		nbl_hw_read_regs(priv, NBL_EPRO_RSS_RET_TABLE(table_id),
				 (u8 *)&rss_ret, sizeof(rss_ret));
		rss_indir[i++] = rss_ret.dqueue0;
		rss_indir[i++] = rss_ret.dqueue1;
	}

	if (odd_num) {
		nbl_hw_read_regs(priv, NBL_EPRO_RSS_RET_TABLE(table_id),
				 (u8 *)&rss_ret, sizeof(rss_ret));
		rss_indir[i++] = rss_ret.dqueue0;
	}
}

static void nbl_phy_get_rss_alg_sel(void *priv, u16 vsi_id, u8 eth_id, u8 *alg_sel)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_vpt_tbl epro_vpt_tbl = {0};

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_VPT_TABLE(vsi_id), (u8 *)&epro_vpt_tbl,
			 sizeof(epro_vpt_tbl));

	if (epro_vpt_tbl.rss_alg_sel == NBL_EPRO_RSS_ALG_TOEPLITZ_HASH)
		*alg_sel = ETH_RSS_HASH_TOP;
	else if (epro_vpt_tbl.rss_alg_sel == NBL_EPRO_RSS_ALG_CRC32)
		*alg_sel = ETH_RSS_HASH_CRC32;
}

static int nbl_phy_set_rss_alg_sel(void *priv, u16 vsi_id, u8 alg_sel)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_vpt_tbl epro_vpt_tbl = {0};

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_VPT_TABLE(vsi_id), (u8 *)&epro_vpt_tbl,
			 sizeof(epro_vpt_tbl));

	if (alg_sel == ETH_RSS_HASH_TOP)
		epro_vpt_tbl.rss_alg_sel = NBL_EPRO_RSS_ALG_TOEPLITZ_HASH;
	else if (alg_sel == ETH_RSS_HASH_CRC32)
		epro_vpt_tbl.rss_alg_sel = NBL_EPRO_RSS_ALG_CRC32;
	else
		return -EOPNOTSUPP;

	nbl_hw_write_regs(phy_mgt, NBL_EPRO_VPT_TABLE(vsi_id),
			  (u8 *)&epro_vpt_tbl,
			  sizeof(struct nbl_epro_vpt_tbl));
	return 0;
}

static int nbl_phy_init_epro_vpt_tbl(void *priv, u16 vsi_id, u16 bmode, bool binit,
				     u16 rss_key_range_oft)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_vpt_tbl epro_vpt_tbl = {0};

	if (binit) {
		epro_vpt_tbl.vld = 1;
		epro_vpt_tbl.fwd = NBL_EPRO_FWD_TYPE_DROP;
		epro_vpt_tbl.rss_alg_sel = NBL_EPRO_RSS_ALG_TOEPLITZ_HASH;
		epro_vpt_tbl.rss_key_type_ipv4	= NBL_EPRO_RSS_KEY_TYPE_IPV4_L4;
		epro_vpt_tbl.rss_key_type_ipv6	= NBL_EPRO_RSS_KEY_TYPE_IPV6_L4;

		nbl_hw_write_regs(phy_mgt, NBL_EPRO_VPT_TABLE(vsi_id),
				  (u8 *)&epro_vpt_tbl,
				  sizeof(struct nbl_epro_vpt_tbl));
	}

	return 0;
}

static int nbl_phy_set_epro_rss_default(void *priv, u16 vsi_id, u16 rss_key_range_oft)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_vpt_tbl epro_vpt_tbl = {0};

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_VPT_TABLE(vsi_id), (u8 *)&epro_vpt_tbl,
			 sizeof(epro_vpt_tbl));

	epro_vpt_tbl.rss_alg_sel = NBL_EPRO_RSS_ALG_TOEPLITZ_HASH;
	epro_vpt_tbl.rss_key_type_ipv4	= NBL_EPRO_RSS_KEY_TYPE_IPV4_L4;
	epro_vpt_tbl.rss_key_type_ipv6	= NBL_EPRO_RSS_KEY_TYPE_IPV6_L4;

	nbl_hw_write_regs(phy_mgt, NBL_EPRO_VPT_TABLE(vsi_id),
			  (u8 *)&epro_vpt_tbl,
			  sizeof(struct nbl_epro_vpt_tbl));
	return 0;
}

static int nbl_phy_set_epro_rss_pt(void *priv, u16 vsi_id, u16 rss_ret_base, u16 rss_entry_size)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_rss_pt_tbl epro_rss_pt_tbl = {0};
	struct nbl_epro_vpt_tbl epro_vpt_tbl;
	u16 entry_size;

	if (rss_entry_size > NBL_EPRO_RSS_ENTRY_MAX_SIZE)
		entry_size = NBL_EPRO_RSS_ENTRY_MAX_SIZE;
	else
		entry_size = rss_entry_size;

	epro_rss_pt_tbl.vld = 1;
	epro_rss_pt_tbl.entry_size = entry_size;
	epro_rss_pt_tbl.offset0_vld = 1;
	epro_rss_pt_tbl.offset0 = rss_ret_base;
	if (rss_entry_size > NBL_EPRO_RSS_ENTRY_MAX_SIZE) {
		epro_rss_pt_tbl.offset1_vld = 1;
		epro_rss_pt_tbl.offset1 =
				rss_ret_base + (NBL_EPRO_RSS_ENTRY_SIZE_UNIT << entry_size);
	} else {
		epro_rss_pt_tbl.offset1_vld = 0;
		epro_rss_pt_tbl.offset1 = 0;
	}

	nbl_hw_write_regs(phy_mgt, NBL_EPRO_RSS_PT_TABLE(vsi_id), (u8 *)&epro_rss_pt_tbl,
			  sizeof(epro_rss_pt_tbl));

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_VPT_TABLE(vsi_id), (u8 *)&epro_vpt_tbl,
			 sizeof(epro_vpt_tbl));
	epro_vpt_tbl.fwd = NBL_EPRO_FWD_TYPE_NORMAL;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_VPT_TABLE(vsi_id), (u8 *)&epro_vpt_tbl,
			  sizeof(epro_vpt_tbl));

	return 0;
}

static int nbl_phy_clear_epro_rss_pt(void *priv, u16 vsi_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_rss_pt_tbl epro_rss_pt_tbl = {0};
	struct nbl_epro_vpt_tbl epro_vpt_tbl;

	nbl_hw_write_regs(phy_mgt, NBL_EPRO_RSS_PT_TABLE(vsi_id), (u8 *)&epro_rss_pt_tbl,
			  sizeof(epro_rss_pt_tbl));

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_VPT_TABLE(vsi_id), (u8 *)&epro_vpt_tbl,
			 sizeof(epro_vpt_tbl));
	epro_vpt_tbl.fwd = NBL_EPRO_FWD_TYPE_DROP;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_VPT_TABLE(vsi_id), (u8 *)&epro_vpt_tbl,
			  sizeof(epro_vpt_tbl));

	return 0;
}

static int nbl_phy_disable_dvn(void *priv, u16 queue_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct dvn_queue_table info = {0};

	nbl_hw_read_regs(phy_mgt, NBL_DVN_QUEUE_TABLE_ARR(queue_id), (u8 *)&info, sizeof(info));
	info.dvn_queue_en = 0;
	nbl_hw_write_regs(phy_mgt, NBL_DVN_QUEUE_TABLE_ARR(queue_id), (u8 *)&info, sizeof(info));
	return 0;
}

static int nbl_phy_disable_uvn(void *priv, u16 queue_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct uvn_queue_table info = {0};

	nbl_hw_write_regs(phy_mgt, NBL_UVN_QUEUE_TABLE_ARR(queue_id), (u8 *)&info, sizeof(info));
	return 0;
}

static bool nbl_phy_is_txq_drain_out(struct nbl_phy_mgt *phy_mgt, u16 queue_id,
				     struct dsch_vn_tc_q_list_tbl *tc_q_list)
{
	nbl_hw_read_regs(phy_mgt, NBL_DSCH_VN_TC_Q_LIST_TABLE_REG_ARR(queue_id),
			 (u8 *)tc_q_list, sizeof(*tc_q_list));
	if (!tc_q_list->regi && !tc_q_list->fly)
		return true;

	return false;
}

static bool nbl_phy_is_rxq_drain_out(struct nbl_phy_mgt *phy_mgt, u16 queue_id)
{
	struct uvn_desc_cxt cache_ctx = {0};

	nbl_hw_read_regs(phy_mgt, NBL_UVN_DESC_CXT_TABLE_ARR(queue_id),
			 (u8 *)&cache_ctx, sizeof(cache_ctx));
	if (cache_ctx.cache_pref_num_prev == cache_ctx.cache_pref_num_post)
		return true;

	return false;
}

static void nbl_phy_lso_drain_time_out_debug(struct nbl_phy_mgt *phy_mgt, u16 queue_id)
{
	u32 addr, data;
	struct dsch_vn_q2tc_cfg_tbl info1 = {0};
	struct dsch_vn_n2g_cfg_tbl info2 = {0};
	struct dsch_vn_g2p_cfg_tbl info3 = {0};
	struct dsch_vn_tc_q_list_tbl tc_q_list = {0};
	struct nbl_dsch_vn_tc_q_list_attr_tbl tc_qlist_attr = {0};
	struct dvn_queue_context dvn_ctx = {0};
	struct nbl_dvn_lso_context lso_ctx = {0};
	struct nbl_dvn_stat_cnt dvn_stat_cnt = {0};

	nbl_hw_read_regs(phy_mgt, NBL_DSCH_VN_TC_Q_LIST_TABLE_REG_ARR(queue_id),
			 (u8 *)&tc_q_list, sizeof(tc_q_list));
	pr_err("queue_id %d tc_q_list regi %d fly %d vld %d",
	       queue_id, tc_q_list.regi, tc_q_list.fly, tc_q_list.vld);
	pr_err("nbl queue %u lso dsch drain\n", queue_id);
	pr_err("dsch debug register:\n");
	for (addr = 0x404900; addr < 0x404a00; addr += 4) {
		data = nbl_hw_rd32(phy_mgt, addr);
		pr_err("addr 0x%x: 0x%x\n", addr, data);
	}
	/*q2tc*/
	nbl_hw_read_regs(phy_mgt, NBL_DSCH_VN_Q2TC_CFG_TABLE_REG_ARR(queue_id),
			 (u8 *)&info1, sizeof(info1));
	nbl_hw_read_regs(phy_mgt, NBL_DSCH_VN_N2G_CFG_TABLE_REG_ARR((info1.tcid / 8)),
			 (u8 *)&info2, sizeof(info2));
	nbl_hw_read_regs(phy_mgt, NBL_DSCH_VN_N2G_CFG_TABLE_REG_ARR((info2.grpid)),
			 (u8 *)&info3, sizeof(info3));
	pr_err("tcid %d grp id %d port %d\n", info1.tcid, info2.grpid, info3.port);

	nbl_hw_read_regs(phy_mgt, NBL_DSCH_VN_TC_Q_LIST_ATTR_TABLE_REG_ARR((info1.tcid)),
			 (u8 *)&tc_qlist_attr, sizeof(tc_qlist_attr));
	pr_err("tcid %d tc_qlist head 0x%x tail 0x%x len %x\n",
	       info1.tcid, tc_qlist_attr.head, tc_qlist_attr.tail, tc_qlist_attr.len);

	for (addr = 0x514000; addr <= 0x514100; addr += 4) {
		data = nbl_hw_rd32(phy_mgt, addr);
		pr_err("addr 0x%x: 0x%x\n", addr, data);
	}
	data = nbl_hw_rd32(phy_mgt, 0x514034);
	pr_err("dvn pkt dif err cnt 0x%x\n", data);
	data = nbl_hw_rd32(phy_mgt, 0x51403C);
	pr_err("dvn desc dif err cnt 0x%x\n", data);
	for (addr = 0x514a00; addr <= 0x514a08; addr += 4) {
		data = nbl_hw_rd32(phy_mgt, addr);
		pr_err("addr 0x%x: 0x%x\n", addr, data);
	}
	data = nbl_hw_rd32(phy_mgt, 0x514a08);
	pr_err("dvn descrd_l1_rerr_cnt 0x%x\n", data);
	data = nbl_hw_rd32(phy_mgt, 0x514a14);
	pr_err("dvn descrd_l2_rerr_cnt 0x%x\n", data);
	data = nbl_hw_rd32(phy_mgt, 0x514a60);
	pr_err("dvn qcrd_schedul_cnt 0x%x\n", data);
	data = nbl_hw_rd32(phy_mgt, 0x514af0);
	pr_err("dvn seg_setdb_cnt 0x%x\n", data);

	nbl_hw_read_regs(phy_mgt, NBL_DVN_QUEUE_CXT_TABLE_ARR(queue_id),
			 (u8 *)&dvn_ctx, sizeof(dvn_ctx));
	pr_err("dvn queue ctx:\n");
	pr_err("dvn_DESCRD_NUM 0x%x dvn_Firstdescid 0x%x, dvn_Firstdesc 0x%x\n",
	       dvn_ctx.dvn_DESCRD_NUM, dvn_ctx.dvn_firstdescid, dvn_ctx.dvn_firstdesc);
	pr_err("dvn_indirect_len 0x%x dvn_indirect_addr 0x%llx, dvn_indirect_next 0x%x\n",
	       dvn_ctx.dvn_indirect_len, dvn_ctx.dvn_indirect_addr, dvn_ctx.dvn_indirect_next);

	pr_err("dvn_L1_ring_read 0x%x dvn_Avail_ring_read 0x%x, dvn_ring_wrap_counter 0x%x\n",
	       dvn_ctx.dvn_L1_ring_read,
	       dvn_ctx.dvn_avail_ring_read,
	       dvn_ctx.dvn_ring_wrap_counter);
	pr_err("dvn_LSO_ID 0x%x dvn_avail_ring_idx 0x%x, dvn_used_ring_idx 0x%x\n",
	       dvn_ctx.dvn_LSO_ID, dvn_ctx.dvn_avail_ring_idx, dvn_ctx.dvn_used_ring_idx);
	pr_err("dvn_indirect_left 0x%x dvn_Desc_left 0x%x, dvn_LSO_FLAG 0x%x\n",
	       dvn_ctx.dvn_indirect_left, dvn_ctx.dvn_desc_left, dvn_ctx.dvn_LSO_FLAG);
	pr_err("dvn_DESCRD_DISABLE 0x%x dvn_Queue_err 0x%x,dvn_LSO_Drop 0x%x,dvn_Protected_bit 0x%x\n",
	       dvn_ctx.dvn_DESCRD_DISABLE, dvn_ctx.dvn_queue_err,
	       dvn_ctx.dvn_lso_drop, dvn_ctx.dvn_protected_bit);
	nbl_hw_read_regs(phy_mgt, NBL_DVN_LSO_CONTEXT_TABLE_ARR(dvn_ctx.dvn_LSO_ID),
			 (u8 *)&lso_ctx, sizeof(lso_ctx));

	pr_err("dvn lso ctx:\n");
	pr_err("dvn_fwd 0x%x dvn_dport 0x%x, dvn_dport_id 0x%x dvn_dport_info 0x%x\n",
	       lso_ctx.dvn_fwd, lso_ctx.dvn_dport, lso_ctx.dvn_dport_id, lso_ctx.dvn_dport_info);
	pr_err("dvn_l4s_handle_ind 0x%x dvn_l4s_redun_head_ind 0x%x, dvn_l4s_redun_ind 0x%x\n",
	       lso_ctx.dvn_l4s_handle_ind,
	       lso_ctx.dvn_l4s_redun_head_ind, lso_ctx.dvn_l4s_redun_ind);
	pr_err("dvn_l4s_sync_ind 0x%x dvn_prbac 0x%x, dvn_l4s_SID_dvn_prbac_SA_Idx 0x%x\n",
	       lso_ctx.dvn_l4s_sync_ind, lso_ctx.dvn_prbac, lso_ctx.dvn_l4s_sid_dvn_prbac_sa_idx);
	pr_err("dvn_L4TUNLEN 0x%x dvn_L4TUNT 0x%x, dvn_EIPLEN 0x%x\n",
	       lso_ctx.dvn_L4TUNLEN, lso_ctx.dvn_L4TUNT, lso_ctx.dvn_EIPLEN);
	pr_err("dvn_EIPT 0x%x dvn_IIPT 0x%x, dvn_L4T 0x%x\n",
	       lso_ctx.dvn_EIPT, lso_ctx.dvn_IIPT, lso_ctx.dvn_L4T);
	pr_err("dvn_L4LEN 0x%x dvn_IPLEN 0x%x, dvn_MACLEN 0x%x\n",
	       lso_ctx.dvn_L4LEN, lso_ctx.dvn_IPLEN, lso_ctx.dvn_MACLEN);
	pr_err("dvn_Headerlen 0x%x dvn_Csum_start 0x%x, dvn_Tcp_sn_bias 0x%x\n",
	       lso_ctx.dvn_headerlen, lso_ctx.dvn_csum_start, lso_ctx.dvn_tcp_sn_bias);
	pr_err("dvn_MSS 0x%x dvn_L3_CS 0x%x, dvn_L4_CS 0x%x\n",
	       lso_ctx.dvn_MSS, lso_ctx.dvn_L3_CS, lso_ctx.dvn_L4_CS);
	pr_err("dvn_rss_lag 0x%x dvn_Lastdesc_flag 0x%x, dvn_Payaddr_left 0x%x\n",
	       lso_ctx.dvn_rss_lag, lso_ctx.dvn_lastdesc_flag, lso_ctx.dvn_payaddr_left);
	pr_err("dvn_Buflen_left_l 0x%x dvn_Buflen_left 0x%x, dvn_Buflen_left_h 0x%x\n",
	       lso_ctx.dvn_buflen_left_l, lso_ctx.dvn_buflen_left, lso_ctx.dvn_buflen_left_h);
	nbl_hw_read_regs(phy_mgt, NBL_DVN_STAT_CNT(queue_id),
			 (u8 *)&dvn_stat_cnt, sizeof(dvn_stat_cnt));

	pr_err("dvn stat_cnt:\n");
	pr_err("dvn_desc_fwd_cnt 0x%x dvn_desc_drop_cnt 0x%x\n",
	       dvn_stat_cnt.dvn_desc_fwd_cnt, dvn_stat_cnt.dvn_desc_drop_cnt);
	pr_err("dvn_pkt_fwd_cnt 0x%x dvn_pkt_drop_cnt 0x%x\n",
	       dvn_stat_cnt.dvn_pkt_fwd_cnt, dvn_stat_cnt.dvn_pkt_drop_cnt);

	data = nbl_hw_rd32(phy_mgt, 0x400110);
	pr_err("lb_ddp_dist_rd_dif_err 0x%x\n", data);
}

static int nbl_phy_lso_dsch_drain(void *priv, u16 queue_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct dsch_vn_tc_q_list_tbl tc_q_list = {0};
	struct dsch_vn_q2tc_cfg_tbl info;
	int i = 0;

	if (phy_mgt->hw_status)
		return 0;

	nbl_hw_read_regs(phy_mgt, NBL_DSCH_VN_Q2TC_CFG_TABLE_REG_ARR(queue_id),
			 (u8 *)&info, sizeof(info));
	info.vld = 0;
	nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_Q2TC_CFG_TABLE_REG_ARR(queue_id),
			  (u8 *)&info, sizeof(info));
	do {
		if (nbl_phy_is_txq_drain_out(phy_mgt, queue_id, &tc_q_list))
			break;

		usleep_range(10, 20);
	} while (++i < NBL_DRAIN_WAIT_TIMES);

	if (i >= NBL_DRAIN_WAIT_TIMES) {
		nbl_phy_lso_drain_time_out_debug(phy_mgt, queue_id);
		nbl_err(common, NBL_DEBUG_QUEUE, "nbl queue %u lso dsch drain, regi %u, fly %u, vld %u\n",
			queue_id, tc_q_list.regi, tc_q_list.fly, tc_q_list.vld);
		return -1;
	}

	return 0;
}

static int nbl_phy_rsc_cache_drain(void *priv, u16 queue_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	int i = 0;

	if (phy_mgt->hw_status)
		return 0;

	do {
		if (nbl_phy_is_rxq_drain_out(phy_mgt, queue_id))
			break;

		usleep_range(10, 20);
	} while (++i < NBL_DRAIN_WAIT_TIMES);

	if (i >= NBL_DRAIN_WAIT_TIMES) {
		nbl_err(common, NBL_DEBUG_QUEUE, "nbl queue %u rsc cache drain timeout\n",
			queue_id);
		return -1;
	}

	return 0;
}

static u64 nbl_phy_save_dvn_ctx(void *priv, u16 queue_id, u16 split)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct dvn_queue_context dvn_ctx = {0};

	nbl_hw_read_regs(phy_mgt, NBL_DVN_QUEUE_CXT_TABLE_ARR(queue_id),
			 (u8 *)&dvn_ctx, sizeof(dvn_ctx));

	nbl_debug(common, NBL_DEBUG_QUEUE, "DVNQ save ctx: %d packed: %08x %08x split: %08x\n",
		  queue_id, dvn_ctx.dvn_ring_wrap_counter, dvn_ctx.dvn_L1_ring_read,
		  dvn_ctx.dvn_avail_ring_idx);

	if (split)
		return (dvn_ctx.dvn_avail_ring_idx);
	else
		return (dvn_ctx.dvn_L1_ring_read & 0x7FFF) | (dvn_ctx.dvn_ring_wrap_counter << 15);
}

static u64 nbl_phy_save_uvn_ctx(void *priv, u16 queue_id, u16 split, u16 queue_size)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct uvn_queue_cxt queue_cxt = {0};
	struct uvn_desc_cxt desc_cxt = {0};
	u16 cache_diff, queue_head, wrap_count;

	nbl_hw_read_regs(phy_mgt, NBL_UVN_QUEUE_CXT_TABLE_ARR(queue_id),
			 (u8 *)&queue_cxt, sizeof(queue_cxt));
	nbl_hw_read_regs(phy_mgt, NBL_UVN_DESC_CXT_TABLE_ARR(queue_id),
			 (u8 *)&desc_cxt, sizeof(desc_cxt));

	nbl_debug(common, NBL_DEBUG_QUEUE,
		  "UVN save ctx: %d cache_tail: %08x cache_head %08x queue_head: %08x\n",
		  queue_id, desc_cxt.cache_tail, desc_cxt.cache_head, queue_cxt.queue_head);

	cache_diff = (desc_cxt.cache_tail - desc_cxt.cache_head + 64) & (0x3F);
	queue_head = (queue_cxt.queue_head - cache_diff + 65536) & (0xFFFF);
	if (queue_size)
		wrap_count = !((queue_head / queue_size) & 0x1);
	else
		return 0xffff;

	nbl_debug(common, NBL_DEBUG_QUEUE, "UVN save ctx: %d packed: %08x %08x split: %08x\n",
		  queue_id, wrap_count, queue_head, queue_head);

	if (split)
		return (queue_head);
	else
		return (queue_head & 0x7FFF) | (wrap_count << 15);
}

static void nbl_phy_get_rx_queue_err_stats(void *priv, u16 queue_id,
					   struct nbl_queue_err_stats *queue_err_stats)
{
	queue_err_stats->uvn_stat_pkt_drop =
		nbl_hw_rd32(priv, NBL_UVN_STATIS_PKT_DROP(queue_id));
}

static void nbl_phy_get_tx_queue_err_stats(void *priv, u16 queue_id,
					   struct nbl_queue_err_stats *queue_err_stats)
{
	struct nbl_dvn_stat_cnt dvn_stat_cnt;

	nbl_hw_read_regs(priv, NBL_DVN_STAT_CNT(queue_id),
			 (u8 *)&dvn_stat_cnt, sizeof(dvn_stat_cnt));
	queue_err_stats->dvn_pkt_drop_cnt = dvn_stat_cnt.dvn_pkt_drop_cnt;
}

static void nbl_phy_setup_queue_switch(void *priv, u16 eth_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_ipro_upsport_tbl upsport = {0};
	struct nbl_epro_ept_tbl ept_tbl = {0};
	struct dsch_vn_g2p_cfg_tbl info = {0};

	upsport.phy_flow = 1;
	upsport.entry_vld = 1;
	upsport.set_dport_en = 1;
	upsport.set_dport_pri = 0;
	upsport.vlan_layer_num_0 = 3;
	upsport.vlan_layer_num_1 = 3;
	/* default we close promisc */
	upsport.set_dport.data = 0xFFF;

	ept_tbl.vld = 1;
	ept_tbl.fwd = 1;

	info.vld = 1;
	info.port = (eth_id << 1);

	nbl_hw_write_regs(phy_mgt, NBL_IPRO_UP_SPORT_TABLE(eth_id),
			  (u8 *)&upsport, sizeof(upsport));

	nbl_hw_write_regs(phy_mgt, NBL_EPRO_EPT_TABLE(eth_id), (u8 *)&ept_tbl,
			  sizeof(struct nbl_epro_ept_tbl));

	nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_G2P_CFG_TABLE_REG_ARR(eth_id),
			  (u8 *)&info, sizeof(info));
}

static int nbl_phy_cfg_phy_flow(void *priv, u16 vsi_id, u16 count, u8 eth_id,
				bool status, u16 rss_key_range_oft)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_ipro_upsport_tbl upsport = {0};
	struct nbl_ipro_dn_src_port_tbl dpsport = {0};
	int i = 0;

	nbl_hw_read_regs(phy_mgt, NBL_IPRO_UP_SPORT_TABLE(eth_id), (u8 *)&upsport, sizeof(upsport));

	upsport.phy_flow = !status;
	upsport.set_dport_en = !status;
	if (!status) {
		upsport.entry_vld = 1;
		upsport.mirror_en = 0;
		upsport.car_en = 0;
	}

	nbl_hw_write_regs(phy_mgt, NBL_IPRO_UP_SPORT_TABLE(eth_id),
			  (u8 *)&upsport, sizeof(upsport));

	for (i = vsi_id; i < vsi_id + count; i++) {
		nbl_hw_read_regs(phy_mgt, NBL_IPRO_DN_SRC_PORT_TABLE(i),
				 (u8 *)&dpsport, sizeof(dpsport));

		dpsport.phy_flow = !status;
		dpsport.set_dport_en = !status;
		if (!status) {
			dpsport.entry_vld = 1;
			dpsport.mirror_en = 0;
			dpsport.dqueue_en = 0;
		}

		nbl_hw_write_regs(phy_mgt, NBL_IPRO_DN_SRC_PORT_TABLE(i),
				  (u8 *)&dpsport, sizeof(dpsport));
	}

	return 0;
}

static int nbl_phy_cfg_eth_port_priority_replace(void *priv, u8 eth_id, bool status)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_port_pri_mdf_en_cfg pri_mdf_en_cfg = {0};

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_PORT_PRI_MDF_EN, (u8 *)(&pri_mdf_en_cfg),
			 sizeof(pri_mdf_en_cfg));
	switch (eth_id) {
	case 0:
		pri_mdf_en_cfg.eth0 = status;
		break;
	case 1:
		pri_mdf_en_cfg.eth1 = status;
		break;
	case 2:
		pri_mdf_en_cfg.eth2 = status;
		break;
	case 3:
		pri_mdf_en_cfg.eth3 = status;
		break;
	default:
		break;
	}

	nbl_hw_write_regs(phy_mgt, NBL_EPRO_PORT_PRI_MDF_EN, (u8 *)(&pri_mdf_en_cfg),
			  sizeof(pri_mdf_en_cfg));
	return 0;
}

static void nbl_phy_init_pfc(void *priv, u8 eth_id, u8 ether_ports, u8 pfc_mode, u8 bp_mode)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_cos_map cos_map = {0};
	struct nbl_upa_pri_sel_conf sel_conf = {0};
	struct nbl_upa_pri_conf conf_table = {0};
	struct nbl_dqm_rxmac_tx_port_bp_en_cfg dqm_port_bp_en = {0};
	struct nbl_dqm_rxmac_tx_cos_bp_en_cfg dqm_cos_bp_en = {0};
	struct nbl_uqm_rx_cos_bp_en_cfg uqm_rx_cos_bp_en = {0};
	struct nbl_uqm_tx_cos_bp_en_cfg uqm_tx_cos_bp_en = {0};
	struct nbl_ustore_port_fc_th ustore_port_fc_th = {0};
	struct nbl_ustore_cos_fc_th ustore_cos_fc_th = {0};
	struct nbl_epro_port_pri_mdf_en_cfg pri_mdf_en_cfg = {0};
	int i, j;

	/* DQM */
	/* set default bp_mode: port */
	/* TX bp: dqm send received ETH RX pause to DSCH */
	/* dqm rxmac_tx_port_bp_en */
	dqm_port_bp_en.eth0 = 1;
	dqm_port_bp_en.eth1 = 1;
	dqm_port_bp_en.eth2 = 1;
	dqm_port_bp_en.eth3 = 1;
	nbl_hw_write_regs(phy_mgt, NBL_DQM_RXMAC_TX_PORT_BP_EN,
			  (u8 *)(&dqm_port_bp_en), sizeof(dqm_port_bp_en));

	/* TX bp: dqm donot send received ETH RX PFC to DSCH */
	/* dqm rxmac_tx_cos_bp_en */
	dqm_cos_bp_en.eth0 = 0;
	dqm_cos_bp_en.eth1 = 0;
	dqm_cos_bp_en.eth2 = 0;
	dqm_cos_bp_en.eth3 = 0;
	nbl_hw_write_regs(phy_mgt, NBL_DQM_RXMAC_TX_COS_BP_EN,
			  (u8 *)(&dqm_cos_bp_en), sizeof(dqm_cos_bp_en));

	/* UQM */
	/* RX bp: uqm receive loopback/emp/rdma_e/rdma_h/l4s_e/l4s_h port bp */
	/* uqm rx_port_bp_en_cfg is ok */
	/* RX bp: uqm receive loopback/emp/rdma_e/rdma_h/l4s_e/l4s_h port bp */
	/* uqm tx_port_bp_en_cfg is ok */

	/* RX bp: uqm receive loopback/emp/rdma_e/rdma_h/l4s_e/l4s_h cos bp */
	/* uqm rx_cos_bp_en */
	uqm_rx_cos_bp_en.vld_l = 0xFFFFFFFF;
	uqm_rx_cos_bp_en.vld_h = 0xFFFF;
	nbl_hw_write_regs(phy_mgt, NBL_UQM_RX_COS_BP_EN, (u8 *)(&uqm_rx_cos_bp_en),
			  sizeof(uqm_rx_cos_bp_en));

	/* RX bp: uqm send received loopback/emp/rdma_e/rdma_h/l4s_e/l4s_h cos bp to USTORE */
	/* uqm tx_cos_bp_en */
	uqm_tx_cos_bp_en.vld_l = 0xFFFFFFFF;
	uqm_tx_cos_bp_en.vld_l = 0xFF;
	nbl_hw_write_regs(phy_mgt, NBL_UQM_TX_COS_BP_EN, (u8 *)(&uqm_tx_cos_bp_en),
			  sizeof(uqm_tx_cos_bp_en));

	/* TX bp: DSCH dp0-3 response to DQM dp0-3 pfc/port bp */
	/* dsch_dpt_pfc_map_vnh default value is ok */
	/* TX bp: DSCH response to DQM cos bp, pkt_cos -> sch_cos map table */
	/* dsch vn_host_dpx_prixx_p2s_map_cfg is ok */

	/* downstream: enable modify packet pri */
	/* epro port_pri_mdf_en */
	pri_mdf_en_cfg.eth0 = 0;
	pri_mdf_en_cfg.eth1 = 0;
	pri_mdf_en_cfg.eth2 = 0;
	pri_mdf_en_cfg.eth3 = 0;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_PORT_PRI_MDF_EN, (u8 *)(&pri_mdf_en_cfg),
			  sizeof(pri_mdf_en_cfg));

	for (i = 0; i < ether_ports; i++) {
		/* set default bp_mode: port */
		/* RX bp: USTORE port bp th, enable send pause frame */
		/* ustore port_fc_th */
		ustore_port_fc_th.xoff_th = 0x190;
		ustore_port_fc_th.xon_th = 0x190;
		ustore_port_fc_th.fc_set = 0;
		ustore_port_fc_th.fc_en = 1;
		nbl_hw_write_regs(phy_mgt, NBL_USTORE_PORT_FC_TH_REG_ARR(i),
				  (u8 *)(&ustore_port_fc_th), sizeof(ustore_port_fc_th));

		for (j = 0; j < 8; j++) {
			/* RX bp: ustore cos bp th, disable send pfc frame */
			/* ustore cos_fc_th */
			ustore_cos_fc_th.xoff_th = 0x64;
			ustore_cos_fc_th.xon_th = 0x64;
			ustore_cos_fc_th.fc_set = 0;
			ustore_cos_fc_th.fc_en = 0;
			nbl_hw_write_regs(phy_mgt, NBL_USTORE_COS_FC_TH_REG_ARR(i * 8 + j),
					  (u8 *)(&ustore_cos_fc_th), sizeof(ustore_cos_fc_th));

			/* downstream: sch_cos->pkt_cos or sch_cos->dscp */
			/* epro sch_cos_map */
			cos_map.pkt_cos = j;
			cos_map.dscp = j << 3;
			nbl_hw_write_regs(phy_mgt, NBL_EPRO_SCH_COS_MAP_TABLE(i, j),
					  (u8 *)(&cos_map), sizeof(cos_map));
		}
	}

	/* upstream: pkt dscp/802.1p -> sch_cos */
	for (i = 0; i < ether_ports; i++) {
		/* upstream: when pfc_mode is 802.1p, vlan pri -> sch_cos map table */
		/* upa pri_conf_table */
		conf_table.pri0 = 0;
		conf_table.pri1 = 1;
		conf_table.pri2 = 2;
		conf_table.pri3 = 3;
		conf_table.pri4 = 4;
		conf_table.pri5 = 5;
		conf_table.pri6 = 6;
		conf_table.pri7 = 7;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_PRI_CONF_TABLE(i * 8),
				  (u8 *)(&conf_table), sizeof(conf_table));

		/* upstream: set default pfc_mode is 802.1p, use outer vlan */
		/* upa pri_sel_conf */
		sel_conf.pri_sel = (1 << 4 | 1 << 3);
		nbl_hw_write_regs(phy_mgt, NBL_UPA_PRI_SEL_CONF_TABLE(i),
				  (u8 *)(&sel_conf), sizeof(sel_conf));
	}
}

static void nbl_phy_configure_pfc(void *priv, u8 eth_id, u8 *pfc)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_dqm_rxmac_tx_port_bp_en_cfg dqm_port_bp_en = {0};
	struct nbl_dqm_rxmac_tx_cos_bp_en_cfg dqm_cos_bp_en = {0};
	struct nbl_ustore_port_fc_th ustore_port_fc_th = {0};
	struct nbl_ustore_cos_fc_th ustore_cos_fc_th = {0};
	struct nbl_epro_cos_map cos_map = {0};
	u32 enable = 0;
	u32 cos_en = 0;
	int i;

	for (i = 0; i < NBL_MAX_PFC_PRIORITIES; i++) {
		if (pfc[i])
			enable = 1;
		cos_en |= pfc[i] << i;
	}

	/* set rx */
	nbl_hw_read_regs(phy_mgt, NBL_DQM_RXMAC_TX_PORT_BP_EN,
			 (u8 *)(&dqm_port_bp_en), sizeof(dqm_port_bp_en));
	nbl_hw_read_regs(phy_mgt, NBL_DQM_RXMAC_TX_COS_BP_EN,
			 (u8 *)(&dqm_cos_bp_en), sizeof(dqm_cos_bp_en));

	switch (eth_id) {
	case 0:
		dqm_port_bp_en.eth0 = !enable;
		dqm_cos_bp_en.eth0 = cos_en;
		break;
	case 1:
		dqm_port_bp_en.eth1 = !enable;
		dqm_cos_bp_en.eth1 = cos_en;
		break;
	case 2:
		dqm_port_bp_en.eth2 = !enable;
		dqm_cos_bp_en.eth2 = cos_en;
		break;
	case 3:
		dqm_port_bp_en.eth3 = !enable;
		dqm_cos_bp_en.eth3 = cos_en;
		break;
	default:
		return;
	}

	nbl_hw_write_regs(phy_mgt, NBL_DQM_RXMAC_TX_PORT_BP_EN,
			  (u8 *)(&dqm_port_bp_en), sizeof(dqm_port_bp_en));
	nbl_hw_write_regs(phy_mgt, NBL_DQM_RXMAC_TX_COS_BP_EN,
			  (u8 *)(&dqm_cos_bp_en), sizeof(dqm_cos_bp_en));

	/* set tx */
	nbl_hw_read_regs(phy_mgt, NBL_USTORE_PORT_FC_TH_REG_ARR(eth_id),
			 (u8 *)(&ustore_port_fc_th), sizeof(ustore_port_fc_th));
	ustore_port_fc_th.fc_en = !enable;
	nbl_hw_write_regs(phy_mgt, NBL_USTORE_PORT_FC_TH_REG_ARR(eth_id),
			  (u8 *)(&ustore_port_fc_th), sizeof(ustore_port_fc_th));

	for (i = 0; i < NBL_MAX_PFC_PRIORITIES; i++) {
		nbl_hw_read_regs(phy_mgt, NBL_USTORE_COS_FC_TH_REG_ARR(eth_id * 8 + i),
				 (u8 *)(&ustore_cos_fc_th), sizeof(ustore_cos_fc_th));
		ustore_cos_fc_th.fc_en = pfc[i];
		nbl_hw_write_regs(phy_mgt, NBL_USTORE_COS_FC_TH_REG_ARR(eth_id * 8 + i),
				  (u8 *)(&ustore_cos_fc_th), sizeof(ustore_cos_fc_th));

		/* downstream: sch_cos->pkt_cos or sch_cos->dscp */
		/* epro sch_cos_map */
		cos_map.pkt_cos = i;
		cos_map.dscp = i << 3;
		nbl_hw_write_regs(phy_mgt, NBL_EPRO_SCH_COS_MAP_TABLE(eth_id, i),
				  (u8 *)(&cos_map), sizeof(cos_map));
	}
}

static void nbl_phy_configure_trust(void *priv, u8 eth_id, u8 trust, u8 *dscp2prio_map)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_upa_pri_sel_conf sel_conf = {0};
	struct nbl_upa_pri_conf conf_table = {0};
	struct nbl_epro_ept_tbl ept_tbl = {0};
	int i;

	if (trust) { /* dscp */
		nbl_hw_read_regs(phy_mgt, NBL_EPRO_EPT_TABLE(eth_id), (u8 *)&ept_tbl,
				 sizeof(struct nbl_epro_ept_tbl));
		ept_tbl.pfc_mode = 1;
		nbl_hw_write_regs(phy_mgt, NBL_EPRO_EPT_TABLE(eth_id), (u8 *)&ept_tbl,
				  sizeof(struct nbl_epro_ept_tbl));

		for (i = 0; i < NBL_MAX_PFC_PRIORITIES; i++) {
			conf_table.pri0 = dscp2prio_map[i * NBL_MAX_PFC_PRIORITIES];
			conf_table.pri1 = dscp2prio_map[i * NBL_MAX_PFC_PRIORITIES + 1];
			conf_table.pri2 = dscp2prio_map[i * NBL_MAX_PFC_PRIORITIES + 2];
			conf_table.pri3 = dscp2prio_map[i * NBL_MAX_PFC_PRIORITIES + 3];
			conf_table.pri4 = dscp2prio_map[i * NBL_MAX_PFC_PRIORITIES + 4];
			conf_table.pri5 = dscp2prio_map[i * NBL_MAX_PFC_PRIORITIES + 5];
			conf_table.pri6 = dscp2prio_map[i * NBL_MAX_PFC_PRIORITIES + 6];
			conf_table.pri7 = dscp2prio_map[i * NBL_MAX_PFC_PRIORITIES + 7];

			nbl_hw_write_regs(phy_mgt, NBL_UPA_PRI_CONF_TABLE(eth_id * 8 + i),
					  (u8 *)(&conf_table), sizeof(conf_table));
		}

		sel_conf.pri_sel = (1 << 3);
		nbl_hw_write_regs(phy_mgt, NBL_UPA_PRI_SEL_CONF_TABLE(eth_id),
				  (u8 *)(&sel_conf), sizeof(sel_conf));
	} else {
		/* upstream: when pfc_mode is 802.1p, vlan pri -> sch_cos map table */
		/* upa pri_conf_table */
		nbl_hw_read_regs(phy_mgt, NBL_EPRO_EPT_TABLE(eth_id), (u8 *)&ept_tbl,
				 sizeof(struct nbl_epro_ept_tbl));
		ept_tbl.pfc_mode = 0;
		nbl_hw_write_regs(phy_mgt, NBL_EPRO_EPT_TABLE(eth_id), (u8 *)&ept_tbl,
				  sizeof(struct nbl_epro_ept_tbl));
		conf_table.pri0 = 0;
		conf_table.pri1 = 1;
		conf_table.pri2 = 2;
		conf_table.pri3 = 3;
		conf_table.pri4 = 4;
		conf_table.pri5 = 5;
		conf_table.pri6 = 6;
		conf_table.pri7 = 7;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_PRI_CONF_TABLE(eth_id * 8),
				  (u8 *)(&conf_table), sizeof(conf_table));

		/* upstream: set default pfc_mode is 802.1p, use outer vlan */
		/* upa pri_sel_conf */
		sel_conf.pri_sel = (1 << 4 | 1 << 3);
		nbl_hw_write_regs(phy_mgt, NBL_UPA_PRI_SEL_CONF_TABLE(eth_id),
				  (u8 *)(&sel_conf), sizeof(sel_conf));
	}
}

static void nbl_phy_configure_rdma_bw(void *priv, u8 eth_id, int rdma_bw)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_shaping_dport dport = {0};
	struct nbl_shaping_dvn_dport dvn_dport = {0};
	struct nbl_shaping_rdma_dport rdma_dport = {0};
	u32 rate, rdma_rate, dvn_rate;

	nbl_hw_read_regs(phy_mgt, NBL_SHAPING_DPORT_REG(eth_id), (u8 *)&dport, sizeof(dport));

	rate = dport.cir;
	rdma_rate = rate * rdma_bw / 100;
	dvn_rate = rate - rdma_rate;

	nbl_hw_read_regs(phy_mgt, NBL_SHAPING_DVN_DPORT_REG(eth_id),
			 (u8 *)&dvn_dport, sizeof(dvn_dport));
	dvn_dport.cir = dvn_rate;
	dvn_dport.pir = rate;
	dvn_dport.depth = dport.depth;
	dvn_dport.cbs = dvn_dport.depth;
	dvn_dport.pbs = dvn_dport.depth;
	dvn_dport.valid = 1;

	nbl_hw_read_regs(phy_mgt, NBL_SHAPING_RDMA_DPORT_REG(eth_id),
			 (u8 *)&rdma_dport, sizeof(rdma_dport));
	rdma_dport.cir = rdma_rate;
	rdma_dport.pir = rate;
	rdma_dport.depth = dport.depth;
	rdma_dport.cbs = rdma_dport.depth;
	rdma_dport.pbs = rdma_dport.depth;
	rdma_dport.valid = 1;

	nbl_hw_write_regs(phy_mgt, NBL_SHAPING_DVN_DPORT_REG(eth_id),
			  (u8 *)&dvn_dport, sizeof(dvn_dport));
	nbl_hw_write_regs(phy_mgt, NBL_SHAPING_RDMA_DPORT_REG(eth_id),
			  (u8 *)&rdma_dport, sizeof(rdma_dport));
}

static void nbl_phy_configure_qos(void *priv, u8 eth_id, u8 *pfc, u8 trust, u8 *dscp2prio_map)
{
	nbl_phy_configure_pfc(priv, eth_id, pfc);
	nbl_phy_configure_trust(priv, eth_id, trust, dscp2prio_map);
}

static int nbl_phy_set_pfc_buffer_size(void *priv, u8 eth_id, u8 prio, int xoff, int xon)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_ustore_cos_fc_th ustore_cos_fc_th = {0};

	if (xoff > NBL_MAX_USTORE_COS_FC_TH || xon > NBL_MAX_USTORE_COS_FC_TH ||
	    xoff <= 0 || xon <= 0)
		return -EINVAL;

	nbl_hw_read_regs(phy_mgt, NBL_USTORE_COS_FC_TH_REG_ARR(eth_id * 8 + prio),
			 (u8 *)(&ustore_cos_fc_th), sizeof(ustore_cos_fc_th));
	ustore_cos_fc_th.xoff_th = xoff;
	ustore_cos_fc_th.xon_th = xon;
	nbl_hw_write_regs(phy_mgt, NBL_USTORE_COS_FC_TH_REG_ARR(eth_id * 8 + prio),
			  (u8 *)(&ustore_cos_fc_th), sizeof(ustore_cos_fc_th));

	return 0;
}

static void nbl_phy_get_pfc_buffer_size(void *priv, u8 eth_id, u8 prio, int *xoff, int *xon)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_ustore_cos_fc_th ustore_cos_fc_th = {0};

	nbl_hw_read_regs(phy_mgt, NBL_USTORE_COS_FC_TH_REG_ARR(eth_id * 8 + prio),
			 (u8 *)(&ustore_cos_fc_th), sizeof(ustore_cos_fc_th));
	*xoff = ustore_cos_fc_th.xoff_th;
	*xon = ustore_cos_fc_th.xon_th;
}

static void nbl_phy_set_rate_limit(void *priv, u16 func_id, enum nbl_traffic_type type, u32 rate)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_shaping_net net_shaping = {0};
	struct dsch_rdma_net2sha_map_tbl rdma_net2sha_map = {0};
	struct dsch_rdma_sha2net_map_tbl rdma_sha2net_map = {0};
	struct dsch_vn_sha2net_map_tbl sha2net = {0};
	struct dsch_vn_net2sha_map_tbl net2sha = {0};
	u64 addr;

	if (type == NBL_TRAFFIC_RDMA_TYPE) {
		nbl_hw_read_regs(phy_mgt, NBL_DSCH_RDMA_NET2SHA_MAP_TBL_REG(func_id),
				 (u8 *)&rdma_net2sha_map, sizeof(rdma_net2sha_map));
		rdma_sha2net_map.rdma_vf_id = func_id; /* only pf */
		rdma_sha2net_map.vld = 1;
		nbl_hw_read_regs(phy_mgt, NBL_DSCH_RDMA_SHA2NET_MAP_TBL_REG(func_id),
				 (u8 *)&rdma_sha2net_map, sizeof(rdma_sha2net_map));
		if (rdma_net2sha_map.vld)
			addr = NBL_SHAPING_NET_REG(rdma_net2sha_map.net_shaping_id);
		else
			addr = NBL_SHAPING_NET_REG(func_id + NBL_NET_SHAPING_RDMA_BASE_ID);
	} else {
		sha2net.vld = 1;
		nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_SHA2NET_MAP_TABLE_REG_ARR(func_id),
				  (u8 *)&sha2net, sizeof(sha2net));

		net2sha.vld = 1;
		nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_NET2SHA_MAP_TABLE_REG_ARR(func_id),
				  (u8 *)&net2sha, sizeof(net2sha));
		addr = NBL_SHAPING_NET_REG(func_id);
	}

	net_shaping.cir = rate;
	net_shaping.pir = rate;
	net_shaping.depth = max(net_shaping.cir * 2, NBL_LR_LEONIS_NET_BUCKET_DEPTH);
	net_shaping.cbs = net_shaping.depth;
	net_shaping.pbs = net_shaping.depth;
	net_shaping.valid = 1;

	nbl_hw_write_regs(phy_mgt, addr, (u8 *)&net_shaping, sizeof(net_shaping));
}

static void nbl_phy_enable_mailbox_irq(void *priv, u16 func_id, bool enable_msix,
				       u16 global_vector_id)
{
	struct nbl_mailbox_qinfo_map_table mb_qinfo_map = { 0 };

	nbl_hw_read_regs(priv, NBL_MAILBOX_QINFO_MAP_REG_ARR(func_id),
			 (u8 *)&mb_qinfo_map, sizeof(mb_qinfo_map));

	if (enable_msix) {
		mb_qinfo_map.msix_idx = global_vector_id;
		mb_qinfo_map.msix_idx_vaild = 1;
	} else {
		mb_qinfo_map.msix_idx = 0;
		mb_qinfo_map.msix_idx_vaild = 0;
	}

	nbl_hw_write_regs(priv, NBL_MAILBOX_QINFO_MAP_REG_ARR(func_id),
			  (u8 *)&mb_qinfo_map, sizeof(mb_qinfo_map));
}

static void nbl_abnormal_intr_init(struct nbl_phy_mgt *phy_mgt)
{
	struct nbl_fem_int_mask fem_mask = {0};
	struct nbl_epro_int_mask epro_mask = {0};
	u32 top_ctrl_mask = 0xFFFFFFFF;

	/* Mask and clear fem cfg_err */
	nbl_hw_read_regs(phy_mgt, NBL_FEM_INT_MASK, (u8 *)&fem_mask, sizeof(fem_mask));
	fem_mask.cfg_err = 1;
	nbl_hw_write_regs(phy_mgt, NBL_FEM_INT_MASK, (u8 *)&fem_mask, sizeof(fem_mask));

	memset(&fem_mask, 0, sizeof(fem_mask));
	fem_mask.cfg_err = 1;
	nbl_hw_write_regs(phy_mgt, NBL_FEM_INT_STATUS, (u8 *)&fem_mask, sizeof(fem_mask));

	nbl_hw_read_regs(phy_mgt, NBL_FEM_INT_MASK, (u8 *)&fem_mask, sizeof(fem_mask));

	/* Mask and clear epro cfg_err */
	nbl_hw_read_regs(phy_mgt, NBL_EPRO_INT_MASK, (u8 *)&epro_mask, sizeof(epro_mask));
	epro_mask.cfg_err = 1;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_INT_MASK, (u8 *)&epro_mask, sizeof(epro_mask));

	memset(&epro_mask, 0, sizeof(epro_mask));
	epro_mask.cfg_err = 1;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_INT_STATUS, (u8 *)&epro_mask, sizeof(epro_mask));

	/* Mask and clear all top_tcrl abnormal intrs.
	 * TODO: might not need this
	 */
	nbl_hw_write_regs(phy_mgt, NBL_TOP_CTRL_INT_MASK,
			  (u8 *)&top_ctrl_mask, sizeof(top_ctrl_mask));

	nbl_hw_write_regs(phy_mgt, NBL_TOP_CTRL_INT_STATUS,
			  (u8 *)&top_ctrl_mask, sizeof(top_ctrl_mask));
}

static void nbl_phy_enable_abnormal_irq(void *priv, bool enable_msix,
					u16 global_vector_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_abnormal_msix_vector abnormal_msix_vetcor = { 0 };
	u32 abnormal_timeout = 0x927C0; /* 600000, 1ms */
	u32 quirks;

	if (enable_msix) {
		abnormal_msix_vetcor.idx = global_vector_id;
		abnormal_msix_vetcor.vld = 1;
	}

	quirks = nbl_phy_get_quirks(phy_mgt);

	if (performance_mode & BIT(NBL_QUIRKS_NO_TOE) ||
	    !(quirks & BIT(NBL_QUIRKS_NO_TOE)))
		abnormal_timeout = 0x3938700; /* 1s */

	nbl_hw_write_regs(phy_mgt, NBL_PADPT_ABNORMAL_TIMEOUT,
			  (u8 *)&abnormal_timeout, sizeof(abnormal_timeout));

	nbl_hw_write_regs(phy_mgt, NBL_PADPT_ABNORMAL_MSIX_VEC,
			  (u8 *)&abnormal_msix_vetcor, sizeof(abnormal_msix_vetcor));

	nbl_abnormal_intr_init(phy_mgt);
}

static void nbl_phy_enable_msix_irq(void *priv, u16 global_vector_id)
{
	struct nbl_msix_notify msix_notify = { 0 };

	msix_notify.glb_msix_idx = global_vector_id;

	nbl_hw_write_regs(priv, NBL_PCOMPLETER_MSIX_NOTIRY_OFFSET,
			  (u8 *)&msix_notify, sizeof(msix_notify));
}

static u8 *nbl_phy_get_msix_irq_enable_info(void *priv, u16 global_vector_id,
					    u32 *irq_data, u32 *irq_mask_data)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_msix_notify msix_notify = { 0 };

	msix_notify.glb_msix_idx = global_vector_id;
	memcpy(irq_data, &msix_notify, sizeof(msix_notify));

	*irq_mask_data = 0;

	return (phy_mgt->hw_addr + NBL_PCOMPLETER_MSIX_NOTIRY_OFFSET);
}

static void nbl_phy_configure_msix_map(void *priv, u16 func_id, bool valid,
				       dma_addr_t dma_addr, u8 bus, u8 devid, u8 function)
{
	struct nbl_function_msix_map function_msix_map = { 0 };

	if (valid) {
		function_msix_map.msix_map_base_addr = dma_addr;
		/* use af's bdf, because dma memmory is alloc by af */
		function_msix_map.function = function;
		function_msix_map.devid = devid;
		function_msix_map.bus = bus;
		function_msix_map.valid = 1;
	}

	nbl_hw_write_regs(priv, NBL_PCOMPLETER_FUNCTION_MSIX_MAP_REG_ARR(func_id),
			  (u8 *)&function_msix_map, sizeof(function_msix_map));
}

static void nbl_phy_configure_msix_info(void *priv, u16 func_id, bool valid, u16 interrupt_id,
					u8 bus, u8 devid, u8 function, bool msix_mask_en)
{
	struct nbl_pcompleter_host_msix_fid_table host_msix_fid_table = { 0 };
	struct nbl_host_msix_info msix_info = { 0 };

	if (valid) {
		host_msix_fid_table.vld = 1;
		host_msix_fid_table.fid = func_id;

		msix_info.intrl_pnum = 0;
		msix_info.intrl_rate = 0;
		msix_info.function = function;
		msix_info.devid = devid;
		msix_info.bus = bus;
		msix_info.valid = 1;
		if (msix_mask_en)
			msix_info.msix_mask_en = 1;
	}

	nbl_hw_write_regs(priv, NBL_PADPT_HOST_MSIX_INFO_REG_ARR(interrupt_id),
			  (u8 *)&msix_info, sizeof(msix_info));
	nbl_hw_write_regs(priv, NBL_PCOMPLETER_HOST_MSIX_FID_TABLE(interrupt_id),
			  (u8 *)&host_msix_fid_table, sizeof(host_msix_fid_table));
}

static void nbl_phy_update_mailbox_queue_tail_ptr(void *priv, u16 tail_ptr, u8 txrx)
{
	/* local_qid 0 and 1 denote rx and tx queue respectively */
	u32 local_qid = txrx;
	u32 value = ((u32)tail_ptr << 16) | local_qid;

	/* write barrier to ensure queue writes are visible before notifying the emp */
	wmb();
	nbl_mbx_wr32(priv, NBL_MAILBOX_NOTIFY_ADDR, value);
}

static void nbl_phy_config_mailbox_rxq(void *priv, dma_addr_t dma_addr, int size_bwid)
{
	struct nbl_mailbox_qinfo_cfg_table qinfo_cfg_rx_table = { 0 };

	qinfo_cfg_rx_table.queue_rst = 1;
	nbl_hw_write_mbx_regs(priv, NBL_MAILBOX_QINFO_CFG_RX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_rx_table, sizeof(qinfo_cfg_rx_table));

	qinfo_cfg_rx_table.queue_base_addr_l = (u32)(dma_addr & 0xFFFFFFFF);
	qinfo_cfg_rx_table.queue_base_addr_h = upper_32_bits(dma_addr);
	qinfo_cfg_rx_table.queue_size_bwind = (u32)size_bwid;
	qinfo_cfg_rx_table.queue_rst = 0;
	qinfo_cfg_rx_table.queue_en = 1;
	nbl_hw_write_mbx_regs(priv, NBL_MAILBOX_QINFO_CFG_RX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_rx_table, sizeof(qinfo_cfg_rx_table));
}

static void nbl_phy_config_mailbox_txq(void *priv, dma_addr_t dma_addr, int size_bwid)
{
	struct nbl_mailbox_qinfo_cfg_table qinfo_cfg_tx_table = { 0 };

	qinfo_cfg_tx_table.queue_base_addr_l = (u32)(dma_addr & 0xFFFFFFFF);
	qinfo_cfg_tx_table.queue_base_addr_h = upper_32_bits(dma_addr);
	qinfo_cfg_tx_table.queue_size_bwind = (u32)size_bwid;
	qinfo_cfg_tx_table.queue_rst = 0;
	qinfo_cfg_tx_table.queue_en = 1;
	nbl_hw_write_mbx_regs(priv, NBL_MAILBOX_QINFO_CFG_TX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_tx_table, sizeof(qinfo_cfg_tx_table));
}

static void nbl_phy_config_mailbox_txq_rst(void *priv, dma_addr_t dma_addr, int size_bwid)
{
	struct nbl_mailbox_qinfo_cfg_table qinfo_cfg_tx_table = { 0 };

	qinfo_cfg_tx_table.queue_rst = 1;
	nbl_hw_write_mbx_regs(priv, NBL_MAILBOX_QINFO_CFG_TX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_tx_table, sizeof(qinfo_cfg_tx_table));

	qinfo_cfg_tx_table.queue_base_addr_l = (u32)(dma_addr & 0xFFFFFFFF);
	qinfo_cfg_tx_table.queue_base_addr_h = upper_32_bits(dma_addr);
	qinfo_cfg_tx_table.queue_size_bwind = (u32)size_bwid;
	qinfo_cfg_tx_table.queue_rst = 0;
	qinfo_cfg_tx_table.queue_en = 1;
	nbl_hw_write_mbx_regs(priv, NBL_MAILBOX_QINFO_CFG_TX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_tx_table, sizeof(qinfo_cfg_tx_table));
}

static void nbl_phy_stop_mailbox_rxq(void *priv)
{
	struct nbl_mailbox_qinfo_cfg_table qinfo_cfg_rx_table = { 0 };

	nbl_hw_write_mbx_regs(priv, NBL_MAILBOX_QINFO_CFG_RX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_rx_table, sizeof(qinfo_cfg_rx_table));
}

static void nbl_phy_stop_mailbox_txq(void *priv)
{
	struct nbl_mailbox_qinfo_cfg_table qinfo_cfg_tx_table = { 0 };

	nbl_hw_write_mbx_regs(priv, NBL_MAILBOX_QINFO_CFG_TX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_tx_table, sizeof(qinfo_cfg_tx_table));
}

static u16 nbl_phy_get_mailbox_rx_tail_ptr(void *priv)
{
	struct nbl_mailbox_qinfo_cfg_dbg_tbl cfg_dbg_tbl = { 0 };

	nbl_hw_read_mbx_regs(priv, NBL_MAILBOX_QINFO_CFG_DBG_TABLE_ADDR,
			     (u8 *)&cfg_dbg_tbl, sizeof(cfg_dbg_tbl));
	return cfg_dbg_tbl.rx_tail_ptr;
}

static bool nbl_phy_check_mailbox_dma_err(void *priv, bool tx)
{
	struct nbl_mailbox_qinfo_cfg_table qinfo_cfg_tbl = { 0 };
	u64 addr;

	if (tx)
		addr = NBL_MAILBOX_QINFO_CFG_TX_TABLE_ADDR;
	else
		addr = NBL_MAILBOX_QINFO_CFG_RX_TABLE_ADDR;

	nbl_hw_read_mbx_regs(priv, addr, (u8 *)&qinfo_cfg_tbl, sizeof(qinfo_cfg_tbl));

	if (qinfo_cfg_tbl.queue_base_addr_h != 0xFFFFFFFF &&
	    qinfo_cfg_tbl.queue_base_addr_l != 0xFFFFFFFF &&
	    qinfo_cfg_tbl.dif_err)
		return true;

	return false;
}

static u32 nbl_phy_get_host_pf_mask(void *priv, u8 func_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	u32 data;

	nbl_hw_read_regs(phy_mgt, NBL_PCIE_HOST_K_PF_MASK_REG, (u8 *)&data, sizeof(data));
	return data;
}

static u32 nbl_phy_get_host_pf_fid(void *priv, u8 func_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	u32 data;

	nbl_hw_read_regs(phy_mgt, NBL_PCIE_HOST_K_PF_FID(func_id), (u8 *)&data, sizeof(data));
	return data;
}

static u32 nbl_phy_get_real_bus(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	u32 data;

	data = nbl_hw_rd32(phy_mgt, NBL_PCIE_HOST_TL_CFG_BUSDEV);
	return data >> 5;
}

#define PF_CONFIGSPACE_SELECT_RETRY_CNT	3
static u64 nbl_phy_get_pf_bar_addr(void *priv, u16 func_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct pci_dev *pdev = NBL_COMMON_TO_PDEV(common);
	u64 addr;
	u32 val, selector, i;

	selector = NBL_LB_PF_CONFIGSPACE_SELECT_OFFSET +
		   func_id * NBL_LB_PF_CONFIGSPACE_SELECT_STRIDE;
	for (i = 0; i < PF_CONFIGSPACE_SELECT_RETRY_CNT; i++) {
		nbl_hw_wr32(phy_mgt, NBL_LB_PCIEX16_TOP_AHB, selector);
		val = nbl_hw_rd32(phy_mgt, NBL_LB_PCIEX16_TOP_AHB);
		if (val == selector)
			break;
	}

	if (i == PF_CONFIGSPACE_SELECT_RETRY_CNT)
		dev_err(&pdev->dev, "get pf bar addr failed, funcid %u, select 0x%x, val 0x%x\n",
			func_id, selector, val);

	val = nbl_hw_rd32(phy_mgt, NBL_LB_PF_CONFIGSPACE_BASE_ADDR + PCI_BASE_ADDRESS_0);
	addr = (u64)(val & PCI_BASE_ADDRESS_MEM_MASK);

	val = nbl_hw_rd32(phy_mgt, NBL_LB_PF_CONFIGSPACE_BASE_ADDR + PCI_BASE_ADDRESS_0 + 4);
	addr |= ((u64)val << 32);

	return addr;
}

static u64 nbl_phy_get_vf_bar_addr(void *priv, u16 func_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct pci_dev *pdev = NBL_COMMON_TO_PDEV(common);
	u64 addr;
	u32 val, selector, i;

	selector = NBL_LB_PF_CONFIGSPACE_SELECT_OFFSET +
		   func_id * NBL_LB_PF_CONFIGSPACE_SELECT_STRIDE;
	for (i = 0; i < PF_CONFIGSPACE_SELECT_RETRY_CNT; i++) {
		nbl_hw_wr32(phy_mgt, NBL_LB_PCIEX16_TOP_AHB, selector);
		val = nbl_hw_rd32(phy_mgt, NBL_LB_PCIEX16_TOP_AHB);
		if (val == selector)
			break;
	}

	if (i == PF_CONFIGSPACE_SELECT_RETRY_CNT)
		dev_err(&pdev->dev, "get vf bar addr failed, funcid %u, select 0x%x, val 0x%x\n",
			func_id, selector, val);

	val = nbl_hw_rd32(phy_mgt, NBL_LB_PF_CONFIGSPACE_BASE_ADDR +
			  NBL_SRIOV_CAPS_OFFSET + PCI_SRIOV_BAR);
	addr = (u64)(val & PCI_BASE_ADDRESS_MEM_MASK);

	val = nbl_hw_rd32(phy_mgt, NBL_LB_PF_CONFIGSPACE_BASE_ADDR +
			  NBL_SRIOV_CAPS_OFFSET + PCI_SRIOV_BAR + 4);
	addr |= ((u64)val << 32);

	return addr;
}

static void nbl_phy_cfg_mailbox_qinfo(void *priv, u16 func_id, u16 bus, u16 devid, u16 function)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_mailbox_qinfo_map_table mb_qinfo_map;

	memset(&mb_qinfo_map, 0, sizeof(mb_qinfo_map));
	mb_qinfo_map.function = function;
	mb_qinfo_map.devid = devid;
	mb_qinfo_map.bus = bus;
	mb_qinfo_map.msix_idx_vaild = 0;
	nbl_hw_write_regs(phy_mgt, NBL_MAILBOX_QINFO_MAP_REG_ARR(func_id),
			  (u8 *)&mb_qinfo_map, sizeof(mb_qinfo_map));
}

static void nbl_phy_update_tail_ptr(void *priv, struct nbl_notify_param *param)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	u8 __iomem *notify_addr = phy_mgt->hw_addr;
	u32 local_qid = param->notify_qid;
	u32 tail_ptr = param->tail_ptr;

	writel((((u32)tail_ptr << 16) | (u32)local_qid), notify_addr);
}

static u8 *nbl_phy_get_tail_ptr(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	return phy_mgt->hw_addr;
}

static void nbl_phy_set_promisc_mode(void *priv, u16 vsi_id, u16 eth_id, u16 mode)
{
	struct nbl_ipro_upsport_tbl upsport;

	nbl_hw_read_regs(priv, NBL_IPRO_UP_SPORT_TABLE(eth_id),
			 (u8 *)&upsport, sizeof(upsport));
	if (mode) {
		upsport.set_dport.dport.up.upcall_flag = AUX_FWD_TYPE_UPCALL;
		upsport.set_dport.dport.up.port_type = SET_DPORT_TYPE_VSI_HOST;
		upsport.set_dport.dport.up.port_id = vsi_id;
		upsport.set_dport.dport.up.next_stg_sel = NEXT_STG_SEL_NONE;
	} else {
		upsport.set_dport.data = 0xFFF;
	}
	nbl_hw_write_regs(priv, NBL_IPRO_UP_SPORT_TABLE(eth_id),
			  (u8 *)&upsport, sizeof(upsport));
}

static void nbl_phy_get_coalesce(void *priv, u16 interrupt_id, u16 *pnum, u16 *rate)
{
	struct nbl_host_msix_info msix_info = { 0 };

	nbl_hw_read_regs(priv, NBL_PADPT_HOST_MSIX_INFO_REG_ARR(interrupt_id),
			 (u8 *)&msix_info, sizeof(msix_info));

	*pnum = msix_info.intrl_pnum;
	*rate = msix_info.intrl_rate;
}

static void nbl_phy_set_coalesce(void *priv, u16 interrupt_id, u16 pnum, u16 rate)
{
	struct nbl_host_msix_info msix_info = { 0 };

	nbl_hw_read_regs(priv, NBL_PADPT_HOST_MSIX_INFO_REG_ARR(interrupt_id),
			 (u8 *)&msix_info, sizeof(msix_info));

	msix_info.intrl_pnum = pnum;
	msix_info.intrl_rate = rate;
	nbl_hw_write_regs(priv, NBL_PADPT_HOST_MSIX_INFO_REG_ARR(interrupt_id),
			  (u8 *)&msix_info, sizeof(msix_info));
}

static int nbl_phy_set_spoof_check_addr(void *priv, u16 vsi_id, u8 *mac)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_ipro_dn_src_port_tbl dpsport = {0};
	u8 reverse_mac[ETH_ALEN];

	nbl_hw_read_regs(phy_mgt, NBL_IPRO_DN_SRC_PORT_TABLE(vsi_id),
			 (u8 *)&dpsport, sizeof(struct nbl_ipro_dn_src_port_tbl));

	nbl_convert_mac(mac, reverse_mac);
		dpsport.smac_low = reverse_mac[0] | reverse_mac[1] << 8;
		memcpy(&dpsport.smac_high, &reverse_mac[2], sizeof(u32));

	nbl_hw_write_regs(phy_mgt, NBL_IPRO_DN_SRC_PORT_TABLE(vsi_id),
			  (u8 *)&dpsport, sizeof(struct nbl_ipro_dn_src_port_tbl));

	return 0;
}

static int nbl_phy_set_vsi_mtu(void *priv, u16 vsi_id, u16 mtu_sel)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_ipro_dn_src_port_tbl dpsport = {0};

	nbl_hw_read_regs(phy_mgt, NBL_IPRO_DN_SRC_PORT_TABLE(vsi_id),
			 (u8 *)&dpsport, sizeof(struct nbl_ipro_dn_src_port_tbl));
	dpsport.mtu_sel = mtu_sel;
	nbl_hw_write_regs(phy_mgt, NBL_IPRO_DN_SRC_PORT_TABLE(vsi_id),
			  (u8 *)&dpsport, sizeof(struct nbl_ipro_dn_src_port_tbl));

	return 0;
}

static int nbl_phy_set_spoof_check_enable(void *priv, u16 vsi_id, u8 enable)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_ipro_dn_src_port_tbl dpsport = {0};

	nbl_hw_read_regs(phy_mgt, NBL_IPRO_DN_SRC_PORT_TABLE(vsi_id),
			 (u8 *)&dpsport, sizeof(struct nbl_ipro_dn_src_port_tbl));

	dpsport.addr_check_en = enable;

	nbl_hw_write_regs(phy_mgt, NBL_IPRO_DN_SRC_PORT_TABLE(vsi_id),
			  (u8 *)&dpsport, sizeof(struct nbl_ipro_dn_src_port_tbl));

	return 0;
}

static void nbl_phy_config_adminq_rxq(void *priv, dma_addr_t dma_addr, int size_bwid)
{
	struct nbl_mailbox_qinfo_cfg_table qinfo_cfg_rx_table = { 0 };

	qinfo_cfg_rx_table.queue_rst = 1;
	nbl_hw_write_mbx_regs(priv, NBL_ADMINQ_QINFO_CFG_RX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_rx_table, sizeof(qinfo_cfg_rx_table));

	qinfo_cfg_rx_table.queue_base_addr_l = (u32)(dma_addr & 0xFFFFFFFF);
	qinfo_cfg_rx_table.queue_base_addr_h = upper_32_bits(dma_addr);
	qinfo_cfg_rx_table.queue_size_bwind = (u32)size_bwid;
	qinfo_cfg_rx_table.queue_rst = 0;
	qinfo_cfg_rx_table.queue_en = 1;
	nbl_hw_write_mbx_regs(priv, NBL_ADMINQ_QINFO_CFG_RX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_rx_table, sizeof(qinfo_cfg_rx_table));
}

static void nbl_phy_config_adminq_txq(void *priv, dma_addr_t dma_addr, int size_bwid)
{
	struct nbl_mailbox_qinfo_cfg_table qinfo_cfg_tx_table = { 0 };

	qinfo_cfg_tx_table.queue_rst = 1;
	nbl_hw_write_mbx_regs(priv, NBL_ADMINQ_QINFO_CFG_TX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_tx_table, sizeof(qinfo_cfg_tx_table));

	qinfo_cfg_tx_table.queue_base_addr_l = (u32)(dma_addr & 0xFFFFFFFF);
	qinfo_cfg_tx_table.queue_base_addr_h = upper_32_bits(dma_addr);
	qinfo_cfg_tx_table.queue_size_bwind = (u32)size_bwid;
	qinfo_cfg_tx_table.queue_rst = 0;
	qinfo_cfg_tx_table.queue_en = 1;
	nbl_hw_write_mbx_regs(priv, NBL_ADMINQ_QINFO_CFG_TX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_tx_table, sizeof(qinfo_cfg_tx_table));
}

static void nbl_phy_stop_adminq_rxq(void *priv)
{
	struct nbl_mailbox_qinfo_cfg_table qinfo_cfg_rx_table = { 0 };

	nbl_hw_write_mbx_regs(priv, NBL_ADMINQ_QINFO_CFG_RX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_rx_table, sizeof(qinfo_cfg_rx_table));
}

static void nbl_phy_stop_adminq_txq(void *priv)
{
	struct nbl_mailbox_qinfo_cfg_table qinfo_cfg_tx_table = { 0 };

	nbl_hw_write_mbx_regs(priv, NBL_ADMINQ_QINFO_CFG_TX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_tx_table, sizeof(qinfo_cfg_tx_table));
}

static void nbl_phy_cfg_adminq_qinfo(void *priv, u16 bus, u16 devid, u16 function)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_adminq_qinfo_map_table adminq_qinfo_map = {0};

	memset(&adminq_qinfo_map, 0, sizeof(adminq_qinfo_map));
	adminq_qinfo_map.function = function;
	adminq_qinfo_map.devid = devid;
	adminq_qinfo_map.bus = bus;

	nbl_hw_write_mbx_regs(phy_mgt, NBL_ADMINQ_MSIX_MAP_TABLE_ADDR,
			      (u8 *)&adminq_qinfo_map, sizeof(adminq_qinfo_map));
}

static void nbl_phy_enable_adminq_irq(void *priv, bool enable_msix, u16 global_vector_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct nbl_adminq_qinfo_map_table adminq_qinfo_map = { 0 };

	adminq_qinfo_map.bus = common->hw_bus;
	adminq_qinfo_map.devid = common->devid;
	adminq_qinfo_map.function = NBL_COMMON_TO_PCI_FUNC_ID(common);

	if (enable_msix) {
		adminq_qinfo_map.msix_idx = global_vector_id;
		adminq_qinfo_map.msix_idx_vaild = 1;
	} else {
		adminq_qinfo_map.msix_idx = 0;
		adminq_qinfo_map.msix_idx_vaild = 0;
	}

	nbl_hw_write_mbx_regs(priv, NBL_ADMINQ_MSIX_MAP_TABLE_ADDR,
			      (u8 *)&adminq_qinfo_map, sizeof(adminq_qinfo_map));
}

static void nbl_phy_update_adminq_queue_tail_ptr(void *priv, u16 tail_ptr, u8 txrx)
{
	/* local_qid 0 and 1 denote rx and tx queue respectively */
	u32 local_qid = txrx;
	u32 value = ((u32)tail_ptr << 16) | local_qid;

	/* write barrier to ensure queue writes are visible before notifying the emp */
	wmb();
	nbl_mbx_wr32(priv, NBL_ADMINQ_NOTIFY_ADDR, value);
}

static u16 nbl_phy_get_adminq_rx_tail_ptr(void *priv)
{
	struct nbl_adminq_qinfo_cfg_dbg_tbl cfg_dbg_tbl = { 0 };

	nbl_hw_read_mbx_regs(priv, NBL_ADMINQ_QINFO_CFG_DBG_TABLE_ADDR,
			     (u8 *)&cfg_dbg_tbl, sizeof(cfg_dbg_tbl));
	return cfg_dbg_tbl.rx_tail_ptr;
}

static bool nbl_phy_check_adminq_dma_err(void *priv, bool tx)
{
	struct nbl_mailbox_qinfo_cfg_table qinfo_cfg_tbl = { 0 };
	u64 addr;

	if (tx)
		addr = NBL_ADMINQ_QINFO_CFG_TX_TABLE_ADDR;
	else
		addr = NBL_ADMINQ_QINFO_CFG_RX_TABLE_ADDR;

	nbl_hw_read_mbx_regs(priv, addr, (u8 *)&qinfo_cfg_tbl, sizeof(qinfo_cfg_tbl));

	if (!qinfo_cfg_tbl.rsv1 && !qinfo_cfg_tbl.rsv2 && qinfo_cfg_tbl.dif_err)
		return true;

	return false;
}

static u8 __iomem *nbl_phy_get_hw_addr(void *priv, size_t *size)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	if (size)
		*size = (size_t)phy_mgt->hw_size;
	return phy_mgt->hw_addr;
}

static void nbl_phy_cfg_ktls_tx_keymat(void *priv, u32 index, u8 mode,
				       u8 *salt, u8 *key, u8 key_len)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_ktls_keymat keymat;
	u8 salt_len = 4;
	int i;

	memset(&keymat, 0, sizeof(keymat));

	keymat.ena = 1;
	keymat.mode = mode;

	for (i = 0; i < salt_len; i++)
		keymat.salt[salt_len - 1 - i] = salt[i];

	for (i = 0; i < key_len; i++)
		keymat.key[key_len - 1 - i] = key[i];

	nbl_hw_write_regs(phy_mgt, NBL_DL4S_KEY_SALT(index), (u8 *)&keymat, sizeof(keymat));
}

static void nbl_phy_cfg_ktls_rx_keymat(void *priv, u32 index, u8 mode,
				       u8 *salt, u8 *key, u8 key_len)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_ktls_keymat keymat;
	u8 salt_len = 4;
	int i;

	memset(&keymat, 0, sizeof(keymat));

	keymat.ena = 1;
	keymat.mode = mode;

	for (i = 0; i < salt_len; i++)
		keymat.salt[salt_len - 1 - i] = salt[i];

	for (i = 0; i < key_len; i++)
		keymat.key[key_len - 1 - i] = key[i];

	nbl_hw_write_regs(phy_mgt, NBL_UL4S_KEY_SALT(index), (u8 *)&keymat, sizeof(keymat));
}

static void nbl_phy_cfg_ktls_rx_record(void *priv, u32 index, u32 tcp_sn, u64 rec_num, bool init)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union nbl_ktls_sync_trig sync_trig = {0};

	if (init) {
		sync_trig.trig = 0;
		sync_trig.init_sync = 0;
	} else {
		sync_trig.trig = 0;
		sync_trig.init_sync = 1;
	}
	nbl_hw_wr32(phy_mgt, NBL_UL4S_SYNC_TRIG, sync_trig.data);

	nbl_hw_wr32(phy_mgt, NBL_UL4S_SYNC_SID, index);
	nbl_hw_wr32(phy_mgt, NBL_UL4S_SYNC_TCP_SN, tcp_sn);
	nbl_hw_write_regs(phy_mgt, NBL_UL4S_SYNC_REC_NUM, (u8 *)&rec_num, sizeof(u64));

	if (init) {
		sync_trig.trig = 1;
		sync_trig.init_sync = 0;
	} else {
		sync_trig.trig = 1;
		sync_trig.init_sync = 1;
	}
	nbl_hw_wr32(phy_mgt, NBL_UL4S_SYNC_TRIG, sync_trig.data);
}

static void nbl_phy_cfg_dipsec_nat(void *priv, u16 sport)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union nbl_dprbac_nat dprbac_nat = {.data = 0};

	dprbac_nat.sport = sport;
	nbl_hw_wr32(phy_mgt, NBL_DPRBAC_NAT, dprbac_nat.data);
}

static void nbl_phy_cfg_dipsec_sad_iv(void *priv, u32 index, u64 iv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_dprbac_sad_iv ipsec_iv = {0};

	ipsec_iv.iv = iv;
	nbl_hw_write_regs(phy_mgt, NBL_DPRBAC_SAD_IV(index), (u8 *)&ipsec_iv, sizeof(ipsec_iv));
}

static void nbl_phy_cfg_dipsec_sad_esn(void *priv, u32 index, u32 sn,
				       u32 esn, u8 wrap_en, u8 enable)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_dprbac_sad_esn ipsec_esn = {0};

	ipsec_esn.sn = sn;
	ipsec_esn.esn = esn;
	ipsec_esn.wrap_en = wrap_en;
	ipsec_esn.enable = enable;
	nbl_hw_write_regs(phy_mgt, NBL_DPRBAC_SAD_ESN(index), (u8 *)&ipsec_esn, sizeof(ipsec_esn));
}

static void nbl_phy_cfg_dipsec_sad_lifetime(void *priv, u32 index, u32 lft_cnt,
					    u32 lft_diff, u8 limit_enable, u8 limit_type)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_dprbac_sad_lifetime lifetime = {0};

	lifetime.cnt = lft_cnt;
	lifetime.diff = lft_diff;
	lifetime.enable = limit_enable;
	lifetime.unit = limit_type;
	nbl_hw_write_regs(phy_mgt, NBL_DPRBAC_SAD_LIFETIME(index),
			  (u8 *)&lifetime, sizeof(lifetime));
}

static void nbl_phy_cfg_dipsec_sad_crypto(void *priv, u32 index, u32 *key, u32 salt,
					  u32 crypto_type, u8 tunnel_mode, u8 icv_len)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_dprbac_sad_crypto_info crypto_info;

	memset(&crypto_info, 0, sizeof(crypto_info));

	memcpy(crypto_info.key, key, sizeof(crypto_info.key));
	crypto_info.salt = salt;
	crypto_info.crypto_type = crypto_type;
	crypto_info.tunnel_mode = tunnel_mode;
	crypto_info.icv_len = icv_len;
	nbl_hw_write_regs(phy_mgt, NBL_DPRBAC_SAD_CRYPTO_INFO(index),
			  (u8 *)&crypto_info, sizeof(crypto_info));
}

static void nbl_phy_cfg_dipsec_sad_encap(void *priv, u32 index, u8 nat_flag,
					 u16 dport, u32 spi, u32 *ip_data)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_dprbac_sad_encap_info encap_info;

	memset(&encap_info, 0, sizeof(encap_info));

	encap_info.nat_flag = nat_flag;
	encap_info.dport = dport;
	encap_info.spi = spi;
	memcpy(encap_info.dip_addr, ip_data, 16);
	memcpy(encap_info.sip_addr, ip_data + 4, 16);
	nbl_hw_write_regs(phy_mgt, NBL_DPRBAC_SAD_ENCAP_INFO(index),
			  (u8 *)&encap_info, sizeof(encap_info));
}

static u32 nbl_phy_read_dipsec_status(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	return nbl_hw_rd32(phy_mgt, NBL_DPRBAC_INT_STATUS);
}

static u32 nbl_phy_reset_dipsec_status(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	u32 dipsec_status;

	dipsec_status = nbl_hw_rd32(phy_mgt, NBL_DPRBAC_INT_STATUS);
	nbl_hw_wr32(phy_mgt, NBL_DPRBAC_INT_STATUS, dipsec_status);

	return dipsec_status;
}

static u32 nbl_phy_read_dipsec_lft_info(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	return nbl_hw_rd32(phy_mgt, NBL_DPRBAC_LIFETIME_INFO);
}

static void nbl_phy_cfg_dipsec_lft_info(void *priv, u32 index, u32 lifetime_diff,
					u32 flag_wen, u32 msb_wen)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union nbl_ipsec_lifetime_diff modify_liftime;

	memset(&modify_liftime, 0, sizeof(modify_liftime));

	modify_liftime.sad_index = index;
	if (flag_wen) {
		modify_liftime.lifetime_diff = lifetime_diff;
		nbl_hw_wr32(phy_mgt, NBL_DPRBAC_LIFETIME_DIFF, modify_liftime.data[1]);
		modify_liftime.flag_wen = 1;
		modify_liftime.flag_value = 1;
	}

	if (msb_wen) {
		modify_liftime.msb_wen = 1;
		modify_liftime.msb_value = 1;
	}
	nbl_hw_wr32(phy_mgt, NBL_DPRBAC_SAD_LIFEDIFF, modify_liftime.data[0]);
}

static void nbl_phy_init_dprbac(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union nbl_dprbac_enable dprbac_enable = {.data = 0};
	union nbl_dprbac_dbg_cnt_en dbg_cnt_en = {.data = 0};
	union nbl_dprbac_drop drop;

	dprbac_enable.prbac = 1;
	dprbac_enable.mf_fwd = 1;
	nbl_hw_wr32(phy_mgt, NBL_DPRBAC_ENABLE, dprbac_enable.data);

	dbg_cnt_en.total = 1;
	dbg_cnt_en.in_right_bypass = 1;
	dbg_cnt_en.in_drop_bypass = 1;
	dbg_cnt_en.in_drop_prbac = 1;
	dbg_cnt_en.out_drop_prbac = 1;
	dbg_cnt_en.out_right_prbac = 1;
	nbl_hw_wr32(phy_mgt, NBL_DPRBAC_DBG_CNT_EN, dbg_cnt_en.data);

	nbl_hw_read_regs(phy_mgt, NBL_DPRBAC_DROP, (u8 *)&drop, sizeof(drop));
	drop.prbac_bp = 0;
	nbl_hw_write_regs(phy_mgt, NBL_DPRBAC_DROP, (u8 *)&drop, sizeof(drop));
}

static void nbl_phy_cfg_uipsec_nat(void *priv, u8 nat_flag, u16 dport)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union nbl_uprbac_nat uprbac_nat = {.data = 0};

	uprbac_nat.enable = nat_flag;
	uprbac_nat.dport = dport;
	nbl_hw_wr32(phy_mgt, NBL_UPRBAC_NAT, uprbac_nat.data);
}

static void nbl_phy_cfg_uipsec_sad_esn(void *priv, u32 index, u32 sn,
				       u32 esn, u8 overlap, u8 enable)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_uprbac_sad_bottom ipsec_esn = {0};

	ipsec_esn.sn = sn;
	ipsec_esn.esn = esn;
	ipsec_esn.overlap = overlap;
	ipsec_esn.enable = enable;
	nbl_hw_write_regs(phy_mgt, NBL_UPRBAC_SAD_BOTTOM(index),
			  (u8 *)&ipsec_esn, sizeof(ipsec_esn));
}

static void nbl_phy_cfg_uipsec_sad_lifetime(void *priv, u32 index, u32 lft_cnt,
					    u32 lft_diff, u8 limit_enable, u8 limit_type)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_uprbac_sad_lifetime lifetime = {0};

	lifetime.cnt = lft_cnt;
	lifetime.diff = lft_diff;
	lifetime.enable = limit_enable;
	lifetime.unit = limit_type;
	nbl_hw_write_regs(phy_mgt, NBL_UPRBAC_SAD_LIFETIME(index),
			  (u8 *)&lifetime, sizeof(lifetime));
}

static void nbl_phy_cfg_uipsec_sad_crypto(void *priv, u32 index, u32 *key, u32 salt,
					  u32 crypto_type, u8 tunnel_mode, u8 icv_len)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_uprbac_sad_crypto_info crypto_info;

	memset(&crypto_info, 0, sizeof(crypto_info));

	memcpy(crypto_info.key, key, sizeof(crypto_info.key));
	crypto_info.salt = salt;
	crypto_info.crypto_type = crypto_type;
	crypto_info.tunnel_mode = tunnel_mode;
	crypto_info.icv_len = icv_len;
	nbl_hw_write_regs(phy_mgt, NBL_UPRBAC_SAD_CRYPTO_INFO(index),
			  (u8 *)&crypto_info, sizeof(crypto_info));
}

static void nbl_phy_cfg_uipsec_sad_window(void *priv, u32 index, u8 window_en, u8 option)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_uprbac_sad_slide_window slide_window;

	memset(&slide_window, 0, sizeof(slide_window));
	slide_window.enable = window_en;
	slide_window.option = option;
	nbl_hw_write_regs(phy_mgt, NBL_UPRBAC_SAD_SLIDE_WINDOW(index),
			  (u8 *)&slide_window, sizeof(slide_window));
}

static void nbl_phy_cfg_uipsec_em_tcam(void *priv, u16 tcam_index, u32 *data)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_uprbac_em_tcam em_tcam = {0};

	em_tcam.key_dat0 = data[0];
	em_tcam.key_dat1 = data[1];
	em_tcam.key_dat2 = data[2] >> 16;
	em_tcam.key_vld = 1;
	nbl_hw_write_regs(phy_mgt, NBL_UPRBAC_EM_TCAM(2 * tcam_index + 1),
			  (u8 *)&em_tcam, sizeof(em_tcam));

	em_tcam.key_dat0 = (data[2] << 16) + (data[3] >> 16);
	em_tcam.key_dat1 = (data[3] << 16) + (data[4] >> 16);
	em_tcam.key_dat2 = data[4];
	em_tcam.key_vld = 1;
	nbl_hw_write_regs(phy_mgt, NBL_UPRBAC_EM_TCAM(2 * tcam_index),
			  (u8 *)&em_tcam, sizeof(em_tcam));
}

static void nbl_phy_cfg_uipsec_em_ad(void *priv, u16 tcam_index, u32 index)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union nbl_uprbac_em_ad em_ad = {0};

	em_ad.sad_index = index;
	nbl_hw_wr32(phy_mgt, NBL_UPRBAC_EM_AD(2 * tcam_index), em_ad.data);
}

static void nbl_phy_clear_uipsec_tcam_ad(void *priv, u16 tcam_index)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_uprbac_em_tcam em_tcam = {0};
	union nbl_uprbac_em_ad em_ad = {0};

	nbl_hw_write_regs(phy_mgt, NBL_UPRBAC_EM_TCAM(2 * tcam_index + 1),
			  (u8 *)&em_tcam, sizeof(em_tcam));
	nbl_hw_write_regs(phy_mgt, NBL_UPRBAC_EM_TCAM(2 * tcam_index),
			  (u8 *)&em_tcam, sizeof(em_tcam));
	nbl_hw_wr32(phy_mgt, NBL_UPRBAC_EM_AD(2 * tcam_index), em_ad.data);
}

static void nbl_phy_cfg_uipsec_em_ht(void *priv, u32 index, u16 ht_table, u16 ht_index,
				     u16 ht_other_index, u16 ht_bucket)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union nbl_uprbac_ht uprbac_ht;

	memset(&uprbac_ht, 0, sizeof(uprbac_ht));

	nbl_hw_read_regs(phy_mgt, NBL_UPRBAC_HT(ht_table, ht_index), uprbac_ht.data, 16);
	if (ht_bucket == 0) {
		uprbac_ht.vld0 = 1;
		uprbac_ht.ht_other_index0 = ht_other_index;
		uprbac_ht.kt_index0 = index;
	}
	if (ht_bucket == 1) {
		uprbac_ht.vld1 = 1;
		uprbac_ht.ht_other_index1 = ht_other_index;
		uprbac_ht.kt_index1 = index;
	}
	if (ht_bucket == 2) {
		uprbac_ht.vld2 = 1;
		uprbac_ht.ht_other_index2 = ht_other_index;
		uprbac_ht.kt_index2 = index;
	}
	if (ht_bucket == 3) {
		uprbac_ht.vld3 = 1;
		uprbac_ht.ht_other_index3 = ht_other_index;
		uprbac_ht.kt_index3 = index;
	}
	nbl_hw_write_regs(phy_mgt, NBL_UPRBAC_HT(ht_table, ht_index), uprbac_ht.data, 16);
}

static void nbl_phy_cfg_uipsec_em_kt(void *priv, u32 index, u32 *data)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_uprbac_kt uprbac_kt;

	memset(&uprbac_kt, 0, sizeof(uprbac_kt));
	memcpy(uprbac_kt.key, data, 20);
	uprbac_kt.sad_index = index;
	nbl_hw_write_regs(phy_mgt, NBL_UPRBAC_KT(index), (u8 *)&uprbac_kt, sizeof(uprbac_kt));
}

static void nbl_phy_clear_uipsec_ht_kt(void *priv, u32 index, u16 ht_table,
				       u16 ht_index, u16 ht_bucket)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union nbl_uprbac_ht uprbac_ht;
	struct nbl_uprbac_kt uprbac_kt;

	memset(&uprbac_ht, 0, sizeof(uprbac_ht));
	memset(&uprbac_kt, 0, sizeof(uprbac_kt));
	nbl_hw_read_regs(phy_mgt, NBL_UPRBAC_HT(ht_table, ht_index), uprbac_ht.data, 16);
	if (ht_bucket == 0) {
		uprbac_ht.vld0 = 0;
		uprbac_ht.ht_other_index0 = 0;
		uprbac_ht.kt_index0 = 0;
	}
	if (ht_bucket == 1) {
		uprbac_ht.vld1 = 0;
		uprbac_ht.ht_other_index1 = 0;
		uprbac_ht.kt_index1 = 0;
	}
	if (ht_bucket == 2) {
		uprbac_ht.vld2 = 0;
		uprbac_ht.ht_other_index2 = 0;
		uprbac_ht.kt_index2 = 0;
	}
	if (ht_bucket == 3) {
		uprbac_ht.vld3 = 0;
		uprbac_ht.ht_other_index3 = 0;
		uprbac_ht.kt_index3 = 0;
	}
	nbl_hw_write_regs(phy_mgt, NBL_UPRBAC_HT(ht_table, ht_index), uprbac_ht.data, 16);

	nbl_hw_write_regs(phy_mgt, NBL_UPRBAC_KT(index), (u8 *)&uprbac_kt, sizeof(uprbac_kt));
}

static u32 nbl_phy_read_uipsec_status(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	return nbl_hw_rd32(phy_mgt, NBL_UPRBAC_INT_STATUS);
}

static u32 nbl_phy_reset_uipsec_status(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	u32 uipsec_status;

	uipsec_status = nbl_hw_rd32(phy_mgt, NBL_UPRBAC_INT_STATUS);
	nbl_hw_wr32(phy_mgt, NBL_UPRBAC_INT_STATUS, uipsec_status);

	return uipsec_status;
}

static void nbl_phy_cfg_uipsec_lft_info(void *priv, u32 index, u32 lifetime_diff,
					u32 flag_wen, u32 msb_wen)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union nbl_ipsec_lifetime_diff modify_liftime;

	memset(&modify_liftime, 0, sizeof(modify_liftime));

	modify_liftime.sad_index = index;
	if (flag_wen) {
		modify_liftime.lifetime_diff = lifetime_diff;
		nbl_hw_wr32(phy_mgt, NBL_UPRBAC_LIFETIME_DIFF, modify_liftime.data[1]);
		modify_liftime.flag_wen = 1;
		modify_liftime.flag_value = 1;
	}

	if (msb_wen) {
		modify_liftime.msb_wen = 1;
		modify_liftime.msb_value = 1;
	}
	nbl_hw_wr32(phy_mgt, NBL_UPRBAC_SAD_LIFEDIFF, modify_liftime.data[0]);
}

static u32 nbl_phy_read_uipsec_lft_info(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	return nbl_hw_rd32(phy_mgt, NBL_UPRBAC_LIFETIME_INFO);
}

static void nbl_phy_init_uprbac(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union nbl_uprbac_enable uprbac_enable = {0};
	union nbl_uprbac_dbg_cnt_en dbg_cnt_en = {0};
	struct nbl_uprbac_em_profile em_profile = {0};

	uprbac_enable.prbac = 1;
	uprbac_enable.padding_check = 1;
	uprbac_enable.pad_err = 1;
	uprbac_enable.icv_err = 1;
	nbl_hw_wr32(phy_mgt, NBL_UPRBAC_ENABLE, uprbac_enable.data);

	dbg_cnt_en.drop_prbac = 1;
	dbg_cnt_en.right_prbac = 1;
	dbg_cnt_en.replay = 1;
	dbg_cnt_en.right_misc = 1;
	dbg_cnt_en.error_misc = 1;
	dbg_cnt_en.xoff_drop = 1;
	dbg_cnt_en.intf_cell = 1;
	dbg_cnt_en.sad_miss = 1;
	nbl_hw_wr32(phy_mgt, NBL_UPRBAC_DBG_CNT_EN, dbg_cnt_en.data);

	em_profile.vld = 1;
	em_profile.hash_sel0 = 0;
	em_profile.hash_sel1 = 3;
	nbl_hw_write_regs(phy_mgt, LEONIS_UPRBAC_EM_PROFILE,
			  (u8 *)&em_profile, sizeof(em_profile));
}

static u32 nbl_phy_get_fw_ping(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	u32 ping;

	nbl_hw_read_mbx_regs(phy_mgt, NBL_FW_HEARTBEAT_PING, (u8 *)&ping, sizeof(ping));

	return ping;
}

static void nbl_phy_set_fw_ping(void *priv, u32 ping)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_hw_write_mbx_regs(phy_mgt, NBL_FW_HEARTBEAT_PING, (u8 *)&ping, sizeof(ping));
}

static u32 nbl_phy_get_fw_pong(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	u32 pong;

	nbl_hw_read_regs(phy_mgt, NBL_FW_HEARTBEAT_PONG, (u8 *)&pong, sizeof(pong));

	return pong;
}

static void nbl_phy_set_fw_pong(void *priv, u32 pong)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_hw_write_regs(phy_mgt, NBL_FW_HEARTBEAT_PONG, (u8 *)&pong, sizeof(pong));
}

static void nbl_phy_load_p4(void *priv, u32 addr, u32 size, u8 *data)
{
	nbl_hw_write_be_regs(priv, addr, data, size);
}

static void nbl_phy_ipro_chksum_err_ctrl(void *priv, u8 status)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union ipro_errcode_tbl_u errcode;
	u8 index = NBL_ERROR_CODE_L3_CHKSUM;

	nbl_hw_read_regs(phy_mgt, NBL_IPRO_ERRCODE_TBL_REG(index),
			 (u8 *)errcode.data, sizeof(errcode));
	errcode.info.vld = status;
	nbl_hw_write_regs(phy_mgt, NBL_IPRO_ERRCODE_TBL_REG(index),
			  (u8 *)errcode.data, sizeof(errcode));

	index = NBL_ERROR_CODE_L4_CHKSUM;
	nbl_hw_read_regs(phy_mgt, NBL_IPRO_ERRCODE_TBL_REG(index),
			 (u8 *)errcode.data, sizeof(errcode));
	errcode.info.vld = status;
	nbl_hw_write_regs(phy_mgt, NBL_IPRO_ERRCODE_TBL_REG(index),
			  (u8 *)errcode.data, sizeof(errcode));
}

static int nbl_phy_init_offload_fwd(void *priv, u16 vsi_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union epro_no_dport_redirect_u epro_no_dport = {.info = {0}};
	union nbl_action_data set_dport = {.data = 0};
	union epro_vpt_u vpt;

	memset(&vpt, 0, sizeof(vpt));

	set_dport.dport.up.upcall_flag = AUX_FWD_TYPE_UPCALL;
	set_dport.dport.up.port_type = SET_DPORT_TYPE_VSI_HOST;
	set_dport.dport.up.port_id = vsi_id;

	epro_no_dport.info.dport = set_dport.data;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_NO_DPORT_REDIRECT_ADDR,
			  (u8 *)epro_no_dport.data, sizeof(epro_no_dport));

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_VPT_REG(vsi_id), (u8 *)vpt.data,
			 NBL_EPRO_VPT_DWLEN * NBL_BYTES_IN_REG);
	vpt.info.rss_alg_sel = NBL_SYM_TOEPLITZ_INT;
	vpt.info.rss_key_type_btm = NBL_KEY_IP4_L4_RSS_BIT | NBL_KEY_IP6_L4_RSS_BIT;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_VPT_REG(vsi_id), (u8 *)vpt.data,
			  NBL_EPRO_VPT_DWLEN * NBL_BYTES_IN_REG);

	/* drop packets with wrong chksums, to prevent PED from correcting them */
	nbl_phy_ipro_chksum_err_ctrl(phy_mgt, 1);

	return 0;
}

static int nbl_phy_cmdq_init(void *priv, void *param, u16 func_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_chan_cmdq_init_info *cmdq_param =
		(struct nbl_chan_cmdq_init_info *)param;
	union pcompleter_host_cfg_funtion_id_cmdq_u cfg_func_id = {
		.info.dbg = func_id,
		.info.vld = 1,
	};
	u32 value = 0;

	/* dis-enable the queue, this will reset queue head to 0 */
	nbl_warn(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		 "CMDQ start init: size %u %llu %u\n",
		 cmdq_param->len, cmdq_param->pa, cmdq_param->bdf_num);
	nbl_hw_wr32(phy_mgt, NBL_CMDQ_HOST_CMDQ_EN_ADDR, value);

	/* write registers */
	value = 0;
	nbl_hw_wr32(phy_mgt, NBL_CMDQ_HOST_CMDQ_TAIL_ADDR, value);
	value = cmdq_param->len;
	nbl_hw_wr32(phy_mgt, NBL_CMDQ_HOST_CMDQ_SIZE_ADDR, value);
	value = NBL_CMDQ_HI_DWORD(cmdq_param->pa);
	nbl_hw_wr32(phy_mgt, NBL_CMDQ_HOST_CMDQ_BADDR_H_ADDR, value);
	value = NBL_CMDQ_LO_DWORD(cmdq_param->pa);
	nbl_hw_wr32(phy_mgt, NBL_CMDQ_HOST_CMDQ_BADDR_L_ADDR, value);

	nbl_hw_wr32(phy_mgt, NBL_PCOMPLETER_HOST_CFG_FUNTION_ID_CMDQ_ADDR,
		    *(u32 *)&cfg_func_id);

	/* enable the queue */
	value = 1;
	nbl_hw_wr32(phy_mgt, NBL_CMDQ_HOST_CMDQ_EN_ADDR, value);
	/* write dif registers (mode and bdf) for receive queue */
	nbl_hw_wr32(phy_mgt, NBL_CMDQ_HOST_CMDQ_DIF_BDF_ADDR,
		    cmdq_param->bdf_num);
	value = NBL_CMDQ_DIF_MODE_VALUE;
	nbl_hw_wr32(phy_mgt, NBL_CMDQ_HOST_CMDQ_DIF_MODE_ADDR, value);
	value = 0x1fffff;
	nbl_hw_wr32(phy_mgt, NBL_CMDQ_FLOW_EN_ADDR, value);
	return 0;
}

static int nbl_phy_cmdq_destroy(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	u32 value = 0;

	nbl_hw_wr32(phy_mgt, NBL_PCOMPLETER_HOST_CFG_FUNTION_ID_CMDQ_ADDR,
		    value);
	nbl_hw_wr32(phy_mgt, NBL_CMDQ_HOST_CMDQ_EN_ADDR, value);
	nbl_hw_wr32(phy_mgt, NBL_CMDQ_HOST_CMDQ_SIZE_ADDR, value);
	nbl_hw_wr32(phy_mgt, NBL_CMDQ_HOST_CMDQ_BADDR_H_ADDR, value);
	nbl_hw_wr32(phy_mgt, NBL_CMDQ_HOST_CMDQ_BADDR_L_ADDR, value);
	nbl_hw_wr32(phy_mgt, NBL_CMDQ_HOST_CMDQ_DIF_INT_ADDR, value);

	return NBL_OK;
}

static int nbl_phy_cmdq_reset(void *priv, void *param)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	u32 value = 0;
	u32 delay_count = 0;
	u32 r_head = 0;
	u32 r_tail = 0;

	/* disable the command queue */
	nbl_hw_wr32(phy_mgt, NBL_CMDQ_HOST_CMDQ_EN_ADDR, value);
	nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		  "CMDQ resetting now...\n");

	/* wait until tail equals head, then reset tail */
	while (true) {
		usleep_range(NBL_CMDQ_DELAY_200US, NBL_CMDQ_DELAY_300US);
		r_head = nbl_hw_rd32(phy_mgt, NBL_CMDQ_HOST_CMDQ_CURR_ADDR);
		r_tail = nbl_hw_rd32(phy_mgt, NBL_CMDQ_HOST_CMDQ_TAIL_ADDR);
		if (r_head == r_tail)
			break;

		delay_count++;
		if (delay_count >= NBL_CMDQ_RESET_MAX_WAIT)
			return -EBADRQC;
	}

	/* enable the queue, and resend the command */
	value = 0;
	nbl_hw_wr32(phy_mgt, NBL_CMDQ_HOST_CMDQ_TAIL_ADDR, value);
	value = 1;
	nbl_hw_wr32(phy_mgt, NBL_CMDQ_HOST_CMDQ_EN_ADDR, value);
	nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		  "CMDQ finished resetting!\n");
	return 0;
}

static void nbl_phy_update_cmdq_tail(void *priv, u32 doorbell)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_hw_wr32(phy_mgt, NBL_CMD_NOTIFY_ADDR, doorbell);
}

static int nbl_acl_set_act_pri(struct nbl_phy_mgt *phy_mgt)
{
	union acl_action_priority0_u act0_pri = {
		.info.action_id9_pri = 3,
	};

	union acl_action_priority4_u act4_pri = {
		.info.action_id9_pri = 3,
	};

	nbl_hw_write_regs(phy_mgt, NBL_ACL_ACTION_PRIORITY0_ADDR,
			  (u8 *)act0_pri.data, sizeof(act0_pri));
	nbl_hw_write_regs(phy_mgt, NBL_ACL_ACTION_PRIORITY4_ADDR,
			  (u8 *)act4_pri.data, sizeof(act4_pri));
	return NBL_OK;
}

static int nbl_acl_check_init(struct nbl_phy_mgt *phy_mgt)
{
	int ret = NBL_OK;
	union acl_init_done_u acl_init;

	nbl_hw_read_regs(phy_mgt, NBL_ACL_INIT_DONE_ADDR, (u8 *)acl_init.data,
			 sizeof(acl_init));
	if (!acl_init.info.done)
		ret = NBL_FAIL;
	if (ret == NBL_OK)
		nbl_info(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
			 "NBL ACL init start success");
	else
		nbl_info(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
			 "NBL ACL init start fail");

	return ret;
}

static int nbl_acl_flow_stat_on(struct nbl_phy_mgt *phy_mgt)
{
	union acl_flow_id_stat_act_u flow_id_act = {
		.info.flow_id_en = 1,
	};

	union acl_stat_id_act_u stat_id_act = {
		.info.act_en = 1,
		.info.act_id = NBL_ACT_SET_SPECIAL_FLOW_STAT,
	};

	nbl_hw_write_regs(phy_mgt, NBL_ACL_FLOW_ID_STAT_ACT_ADDR,
			  (u8 *)flow_id_act.data, sizeof(flow_id_act));

	nbl_hw_write_regs(phy_mgt, NBL_ACL_STAT_ID_ACT_ADDR,
			  (u8 *)stat_id_act.data, sizeof(stat_id_act));
	return NBL_OK;
}

static int nbl_acl_set_tcam_info_regs(struct nbl_phy_mgt *phy_mgt,
				      struct nbl_acl_cfg_param *acl_param)
{
	u8 *acl_key_cfg_ptr = (u8 *)(acl_param->tcam_cfg);
	u8 *act_cfg_ptr = (u8 *)(acl_param->action_cfg);

	nbl_hw_write_regs(phy_mgt,
			  NBL_ACL_TCAM_CFG_REG(acl_param->acl_stage),
			  acl_key_cfg_ptr, sizeof(union acl_tcam_cfg_u));
	nbl_hw_write_regs(phy_mgt,
			  NBL_ACL_ACTION_RAM_CFG_REG(acl_param->acl_stage),
			  act_cfg_ptr, sizeof(union acl_action_ram_cfg_u));

	return NBL_OK;
}

static int nbl_acl_set_tcam_info(struct nbl_phy_mgt *phy_mgt,
				 struct nbl_acl_cfg_param *acl_param)
{
	int ret = 0;

	ret = nbl_acl_set_tcam_info_regs(phy_mgt, acl_param);
	ret = nbl_acl_set_tcam_info_regs(phy_mgt, acl_param + 1);
	return ret;
}

static int nbl_acl_flow_stat_clear(struct nbl_phy_mgt *phy_mgt)
{
	union acl_flow_id_stat_glb_clr_u flow_stat_clear = {
		.info.glb_clr = 1,
	};
	union acl_stat_id_stat_glb_clr_u stat_stat_clear = {
		.info.glb_clr = 1,
	};
	union acl_flow_id_stat_done_u flow_done_info = {.info = {0}};
	u32 rd_retry = 0;

	nbl_hw_write_regs(phy_mgt, NBL_ACL_FLOW_ID_STAT_GLB_CLR_ADDR,
			  (u8 *)flow_stat_clear.data, sizeof(flow_stat_clear));
	nbl_hw_write_regs(phy_mgt, NBL_ACL_STAT_ID_STAT_GLB_CLR_ADDR,
			  (u8 *)stat_stat_clear.data, sizeof(stat_stat_clear));
	while (1) {
		nbl_hw_read_regs(phy_mgt, NBL_ACL_FLOW_ID_STAT_DONE_ADDR,
				 (u8 *)flow_done_info.data,
				 sizeof(flow_done_info));
		if (flow_done_info.info.glb_clr_done)
			break;
		if (rd_retry++ == NBL_ACL_RD_RETRY) {
			nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
				  "NBL ACL init start fail");
			return NBL_FAIL;
		}
		usleep_range(NBL_ACL_RD_WAIT_100US, NBL_ACL_RD_WAIT_200US);
	}

	return NBL_OK;
}

static int nbl_acl_flow_tcam_clear(struct nbl_phy_mgt *phy_mgt, u16 tcam_btm,
				   u16 tcam_start_idx, u16 tcam_end_idx)
{
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	union acl_indirect_ctrl_u indirect_ctrl = {
		.info.tcam_addr = 0,
		.info.cpu_acl_cfg_start = 1,
		.info.acc_btm = tcam_btm,
		.info.cpu_acl_cfg_rw = NBL_ACL_CPU_WRITE,
	};
	union acl_indirect_access_ack_u indirect_ack = {.info = {0}};
	/* set invalid in each tcam */
	union acl_valid_bit_u tcam_data_valid = {.info = {0}};
	int try_time = NBL_ACL_RD_RETRY;

	for (; tcam_start_idx < tcam_end_idx; ++tcam_start_idx) {
		nbl_hw_write_regs(phy_mgt, NBL_ACL_VALID_BIT_ADDR,
				  (u8 *)tcam_data_valid.data,
				  sizeof(tcam_data_valid));
		indirect_ctrl.info.tcam_addr = tcam_start_idx;
		nbl_hw_write_regs(phy_mgt, NBL_ACL_INDIRECT_CTRL_ADDR,
				  (u8 *)indirect_ctrl.data,
				  sizeof(indirect_ctrl));

		while (try_time--) {
			nbl_hw_read_regs(phy_mgt,
					 NBL_ACL_INDIRECT_ACCESS_ACK_ADDR,
					 (u8 *)indirect_ack.data,
					 sizeof(indirect_ack));
			if (indirect_ack.info.done)
				break;
			usleep_range(NBL_ACL_RD_WAIT_100US, NBL_ACL_RD_WAIT_200US);
		}

		if (!indirect_ack.info.done) {
			nbl_info(common, NBL_DEBUG_FLOW,  "indirect access failed(%u-%u), done: %u, status: %08x.",
				 tcam_start_idx, try_time + 1, 0, indirect_ack.info.status);
			return NBL_FAIL;
		}

		indirect_ack.info.done = 0;
		try_time = NBL_ACL_RD_RETRY;
	}
	nbl_debug(common, NBL_DEBUG_FLOW, "clear acl flow:idx(depth):%d(%d)\n",
		  tcam_start_idx, tcam_end_idx);
	return NBL_OK;
}

static int nbl_acl_init_regs(struct nbl_phy_mgt *phy_mgt,
			     struct nbl_chan_flow_init_info_leonis *param)
{
	/* set act priority */
	nbl_acl_set_act_pri(phy_mgt);

	/* read acl init done */
	if (nbl_acl_check_init(phy_mgt))
		return NBL_FAIL;

	/* set flow-stat enable */
	nbl_acl_flow_stat_on(phy_mgt);

	/* set tcam info */
	nbl_acl_set_tcam_info(phy_mgt, param->acl_cfg);

	/* clear flow stat */
	if (nbl_acl_flow_stat_clear(phy_mgt))
		return NBL_FAIL;

	/* clear key/mask/act tcam tab */
	if (nbl_acl_flow_tcam_clear(phy_mgt, NBL_ACL_FLUSH_FLOW_BTM, 0, NBL_ACL_TCAM_DEPTH))
		return NBL_FAIL;
	return NBL_OK;
}

static int nbl_phy_init_acl_stats(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	/* init acl stat */
	nbl_acl_flow_stat_on(phy_mgt);
	/* clear flow stat */
	if (nbl_acl_flow_stat_clear(phy_mgt))
		return NBL_FAIL;
	nbl_info(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW, "flow stat init: finished");
	return 0;
}

static int nbl_phy_acl_unset_upcall_rule(void *priv, u8 idx)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	return nbl_acl_flow_tcam_clear(phy_mgt, NBL_ACL_FLUSH_UPCALL_BTM, idx, idx * 2);
}

static void nbl_phy_acl_set_dport(int *action, u16 vsi_id)
{
	union nbl_action_data set_dport = {.data = 0};

	set_dport.dport.up.port_type = SET_DPORT_TYPE_VSI_HOST;
	set_dport.dport.up.upcall_flag = AUX_FWD_TYPE_UPCALL;
	set_dport.dport.up.next_stg_sel = NEXT_STG_SEL_NONE;
	set_dport.dport.up.port_id = vsi_id;

	*action = set_dport.data + (NBL_ACT_SET_DPORT << NBL_16BIT);
}

static int nbl_phy_acl_set_upcall_rule(void *priv, u8 idx, u16 vsi_id)
{
	int tcam_entry = idx << 1;
	int fwd_act = 0;
	int rd_retry = NBL_ACL_RD_RETRY;
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	union acl_action_ram15_u action_ram;
	union acl_indirect_ctrl_u indirect_ctrl = {
		.info.tcam_addr = tcam_entry,
		.info.cpu_acl_cfg_start = 1,
		.info.cpu_acl_cfg_rw = NBL_ACL_INDIRECT_ACCESS_WRITE,
		.info.acc_btm = NBL_ACL_FLUSH_UPCALL_BTM,
	};
	union acl_indirect_access_ack_u indirect_ack;
	union acl_valid_bit_u tcam_data_valid = {
		.info.valid_bit = NBL_ACL_FLUSH_UPCALL_BTM,
	};
	union nbl_acl_tcam_upcall_data_u eth_data = {
		.eth_pt_id = NBL_ACL_ETH_PF_UPCALL,
	};
	union nbl_acl_tcam_upcall_data_u eth_mask;
	union nbl_acl_tcam_upcall_data_u vsi_data = {
		.vsi_pt_id = NBL_ACL_VSI_PF_UPCALL,
	};
	union nbl_acl_tcam_upcall_data_u vsi_mask;

	memset(&action_ram, 0, sizeof(action_ram));
	memset(&indirect_ack, 0, sizeof(indirect_ack));
	nbl_info(common, NBL_DEBUG_FLOW, "set acl tcam_cfg and act_cfg:%d\n", idx);
	/* mask all fields default */
	memset(&eth_mask, 0xff, sizeof(eth_mask));
	eth_mask.eth_pt_id = 0;
	eth_mask.eth_id = 0;

	memset(&vsi_mask, 0xff, sizeof(vsi_mask));
	vsi_mask.sw_id = 0;
	vsi_mask.vsi_pt_id = 0;
	/* eth acl rule */
	nbl_phy_acl_set_dport(&fwd_act, NBL_GET_PF_VSI_ID(idx));
	NBL_ACL_GET_ACTION_DATA(fwd_act, action_ram.info.action0);
	indirect_ctrl.info.tcam_addr = tcam_entry;
	nbl_info(common, NBL_DEBUG_FLOW, "acl action addr:%d, size:%zu\n",
		 tcam_entry, sizeof(action_ram));
	nbl_hw_write_regs(phy_mgt, NBL_ACL_ACTION_RAM_TBL(NBL_ACL_TCAM_UPCALL_IDX, tcam_entry),
			  (u8 *)action_ram.data, sizeof(action_ram));

	eth_data.eth_id = NBL_GET_PF_ETH_ID(idx);
	nbl_info(common, NBL_DEBUG_FLOW, "acl entry key(mask): %d(%d), %d(%d)\n",
		 eth_data.eth_pt_id, eth_mask.eth_pt_id, eth_data.eth_id, eth_mask.eth_id);
	nbl_tcam_truth_value_convert(&eth_data.tcam_data, &eth_mask.tcam_data);
	nbl_hw_write_regs(phy_mgt, NBL_ACL_TCAM_DATA_X(NBL_ACL_TCAM_UPCALL_IDX),
			  eth_data.data, sizeof(eth_data));
	nbl_hw_write_regs(phy_mgt, NBL_ACL_TCAM_DATA_Y(NBL_ACL_TCAM_UPCALL_IDX),
			  eth_mask.data, sizeof(eth_mask));
	nbl_hw_write_regs(phy_mgt, NBL_ACL_VALID_BIT_ADDR,
			  (u8 *)&tcam_data_valid, sizeof(tcam_data_valid));
	nbl_hw_write_regs(phy_mgt, NBL_ACL_INDIRECT_CTRL_ADDR,
			  (u8 *)&indirect_ctrl, sizeof(indirect_ctrl));
	do {
		nbl_hw_read_regs(phy_mgt, NBL_ACL_INDIRECT_ACCESS_ACK_ADDR,
				 (u8 *)&indirect_ack, sizeof(indirect_ack));
		if (!indirect_ack.info.done) {
			rd_retry--;
			usleep_range(NBL_ACL_RD_WAIT_100US, NBL_ACL_RD_WAIT_200US);
		} else {
			break;
		}
	} while (rd_retry);

	if (!indirect_ack.info.done) {
		nbl_err(common, NBL_DEBUG_FLOW, "acl init flows error in pf%d\n", idx);
		return -EIO;
	}
	memset(indirect_ack.data, 0, sizeof(indirect_ack));

	/* vsi acl rule */
	nbl_phy_acl_set_dport(&fwd_act, vsi_id);
	NBL_ACL_GET_ACTION_DATA(fwd_act, action_ram.info.action0);
	indirect_ctrl.info.tcam_addr = ++tcam_entry;
	nbl_hw_write_regs(phy_mgt, NBL_ACL_ACTION_RAM_TBL(NBL_ACL_TCAM_UPCALL_IDX, tcam_entry),
			  (u8 *)&action_ram, sizeof(action_ram));

	vsi_data.sw_id = idx;
	nbl_info(common, NBL_DEBUG_FLOW,  "acl entry key(mask):%d(%d), %d(%d)\n",
		 vsi_data.vsi_pt_id, vsi_mask.vsi_pt_id, vsi_data.sw_id, vsi_mask.sw_id);
	nbl_tcam_truth_value_convert(&vsi_data.tcam_data, &vsi_mask.tcam_data);
	nbl_hw_write_regs(phy_mgt, NBL_ACL_TCAM_DATA_X(NBL_ACL_TCAM_UPCALL_IDX),
			  vsi_data.data, sizeof(vsi_data));
	nbl_hw_write_regs(phy_mgt, NBL_ACL_TCAM_DATA_Y(NBL_ACL_TCAM_UPCALL_IDX),
			  vsi_mask.data, sizeof(vsi_mask));
	nbl_hw_write_regs(phy_mgt, NBL_ACL_VALID_BIT_ADDR,
			  (u8 *)&tcam_data_valid, sizeof(tcam_data_valid));
	nbl_hw_write_regs(phy_mgt, NBL_ACL_INDIRECT_CTRL_ADDR,
			  (u8 *)&indirect_ctrl, sizeof(indirect_ctrl));
	do {
		nbl_hw_read_regs(phy_mgt, NBL_ACL_INDIRECT_ACCESS_ACK_ADDR,
				 (u8 *)&indirect_ack, sizeof(indirect_ack));
		if (!indirect_ack.info.done) {
			rd_retry--;
			usleep_range(NBL_ACL_RD_WAIT_100US, NBL_ACL_RD_WAIT_200US);
		} else {
			break;
		}
	} while (rd_retry);

	if (!indirect_ack.info.done) {
		nbl_err(common, NBL_DEBUG_FLOW, "acl init flows error in pf%d\n", idx);
		return -EIO;
	}

	return 0;
}

static void nbl_phy_uninit_acl(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	union acl_tcam_cfg_u acl_key_cfg;
	union acl_action_ram_cfg_u acl_act_cfg;
	union acl_loop_back_en_u loop_en;

	memset(&acl_key_cfg, 0, sizeof(acl_key_cfg));
	memset(&acl_act_cfg, 0, sizeof(acl_act_cfg));
	memset(&loop_en, 0, sizeof(loop_en));

	nbl_hw_write_regs(phy_mgt, NBL_ACL_LOOP_BACK_EN_ADDR, (u8 *)&loop_en,
			  sizeof(loop_en));
	nbl_hw_write_regs(phy_mgt, NBL_ACL_TCAM_CFG_REG(NBL_ACL_VSI_PF_UPCALL),
			  (u8 *)&acl_key_cfg, sizeof(union acl_tcam_cfg_u));
	nbl_hw_write_regs(phy_mgt, NBL_ACL_ACTION_RAM_CFG_REG(NBL_ACL_VSI_PF_UPCALL),
			  (u8 *)&acl_act_cfg, sizeof(union acl_action_ram_cfg_u));
	nbl_hw_write_regs(phy_mgt, NBL_ACL_TCAM_CFG_REG(NBL_ACL_ETH_PF_UPCALL),
			  (u8 *)&acl_key_cfg, sizeof(union acl_tcam_cfg_u));
	nbl_hw_write_regs(phy_mgt, NBL_ACL_ACTION_RAM_CFG_REG(NBL_ACL_ETH_PF_UPCALL),
			  (u8 *)&acl_act_cfg, sizeof(union acl_action_ram_cfg_u));
	nbl_info(common, NBL_DEBUG_FLOW, "nbl uninit acl done\n");
}

static void nbl_phy_init_acl(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	union acl_tcam_cfg_u acl_key_cfg = {
		.info.startcompare15 = 1,
		.info.startset15 = 1,
		.info.tcam15_enable = 1,
		.info.key_id15 = 0,
	};
	union acl_action_ram_cfg_u acl_act_cfg = {
		.info.action_ram15_enable = 1,
		.info.action_ram15_alloc_id = NBL_ACL_TCAM_UPCALL_IDX,
	};
	union acl_loop_back_en_u loop_en = {
		.info.loop_back_en = 1,
	};

	nbl_hw_write_regs(phy_mgt, NBL_ACL_LOOP_BACK_EN_ADDR, (u8 *)&loop_en,
			  sizeof(loop_en));
	nbl_hw_write_regs(phy_mgt, NBL_ACL_TCAM_CFG_REG(NBL_ACL_VSI_PF_UPCALL),
			  (u8 *)&acl_key_cfg, sizeof(union acl_tcam_cfg_u));
	nbl_hw_write_regs(phy_mgt, NBL_ACL_ACTION_RAM_CFG_REG(NBL_ACL_VSI_PF_UPCALL),
			  (u8 *)&acl_act_cfg, sizeof(union acl_action_ram_cfg_u));
	nbl_hw_write_regs(phy_mgt, NBL_ACL_TCAM_CFG_REG(NBL_ACL_ETH_PF_UPCALL),
			  (u8 *)&acl_key_cfg, sizeof(union acl_tcam_cfg_u));
	nbl_hw_write_regs(phy_mgt, NBL_ACL_ACTION_RAM_CFG_REG(NBL_ACL_ETH_PF_UPCALL),
			  (u8 *)&acl_act_cfg, sizeof(union acl_action_ram_cfg_u));
	nbl_info(common, NBL_DEBUG_FLOW, "nbl init acl done\n");
}

static int nbl_ipro_init_regs(struct nbl_phy_mgt *phy_mgt)
{
	/* write error code for smac-spoof and vlan check */
	union ipro_anti_fake_addr_errcode_u errcode_def = {
		.info.num		= NBL_ERROR_CODE_DN_SMAC,
		.info.rsv		= 0,
	};
	union ipro_anti_fake_addr_action_u default_drop = {
		.info.dqueue		= 0,
		.info.dqueue_en		= 0,
		.info.proc_done		= 1,
		.info.set_dport_en	= 1,
		.info.set_dport		= NBL_SET_DPORT(AUX_FWD_TYPE_UPCALL,
							NEXT_STG_SEL_BYPASS,
							SET_DPORT_TYPE_SP_PORT,
							PORT_TYPE_SP_DROP),
		.info.rsv		= 0,
	};

	nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		  "flow init: ipro errcode & actions");
	nbl_hw_write_regs(phy_mgt, NBL_IPRO_ANTI_FAKE_ADDR_ERRCODE_ADDR,
			  (u8 *)errcode_def.data, sizeof(errcode_def));
	errcode_def.info.num = NBL_ERROR_CODE_VLAN;
	nbl_hw_write_regs(phy_mgt, NBL_IPRO_VLAN_NUM_CHK_ERRCODE_ADDR,
			  (u8 *)errcode_def.data, sizeof(errcode_def));

	/* default drop for underlay pkt flt, smac-spoof and vlan check */
	nbl_hw_write_regs(phy_mgt, NBL_IPRO_UDL_PKT_FLT_ACTION_ADDR,
			  (u8 *)default_drop.data, sizeof(default_drop));
	nbl_hw_write_regs(phy_mgt, NBL_IPRO_ANTI_FAKE_ADDR_ACTION_ADDR,
			  (u8 *)default_drop.data, sizeof(default_drop));
	nbl_hw_write_regs(phy_mgt, NBL_IPRO_VLAN_NUM_CHK_ACTION_ADDR,
			  (u8 *)default_drop.data, sizeof(default_drop));

	return NBL_OK;
}

static int nbl_pp_init_regs(struct nbl_phy_mgt *phy_mgt)
{
	u32 action_dport_pri = 0x3000;

	nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		  "flow init: pp action priority");
	nbl_hw_write_regs(phy_mgt, NBL_PP0_ACTION_PRIORITY0_ADDR,
			  (u8 *)&action_dport_pri, sizeof(action_dport_pri));
	nbl_hw_write_regs(phy_mgt, NBL_PP0_ACTION_PRIORITY4_ADDR,
			  (u8 *)&action_dport_pri, sizeof(action_dport_pri));

	nbl_hw_write_regs(phy_mgt, NBL_PP1_ACTION_PRIORITY0_ADDR,
			  (u8 *)&action_dport_pri, sizeof(action_dport_pri));
	nbl_hw_write_regs(phy_mgt, NBL_PP1_ACTION_PRIORITY4_ADDR,
			  (u8 *)&action_dport_pri, sizeof(action_dport_pri));

	nbl_hw_write_regs(phy_mgt, NBL_PP2_ACTION_PRIORITY0_ADDR,
			  (u8 *)&action_dport_pri, sizeof(action_dport_pri));
	nbl_hw_write_regs(phy_mgt, NBL_PP2_ACTION_PRIORITY4_ADDR,
			  (u8 *)&action_dport_pri, sizeof(action_dport_pri));
	return NBL_OK;
}

static void nbl_fem_profile_table_action_set(struct nbl_phy_mgt *phy_mgt, u32 pp_id,
					     u32 pt_idx, u16 vsi_id, bool is_set_upcall)
{
	union fem_em0_profile_table_u em_pt_tbl;
	union fem_em0_profile_table_u em_pt_tbl_tmp;
	union nbl_action_data set_dport = {.data = 0};

	memset(&em_pt_tbl, 0, sizeof(em_pt_tbl));
	memset(&em_pt_tbl_tmp, 0, sizeof(em_pt_tbl_tmp));
	if (is_set_upcall) {
		set_dport.dport.up.next_stg_sel = NEXT_STG_SEL_ACL_S0;
		set_dport.dport.up.upcall_flag = AUX_FWD_TYPE_UPCALL;
		set_dport.dport.up.port_type = SET_DPORT_TYPE_VSI_HOST;
		set_dport.dport.up.port_id = vsi_id;
		em_pt_tbl_tmp.info.action0 = set_dport.data +
					     (NBL_ACT_SET_DPORT << NBL_ACT_DATA_BITS);
	}

	nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		  "flow init: pt upcall: %u %u %u", pp_id, pt_idx, vsi_id);
	/* read profile table configured with P4 ELF, set the upcall action */
	switch (pp_id) {
	case NBL_PP_TYPE_0:
		nbl_hw_read_regs(phy_mgt, NBL_FEM_EM0_PROFILE_TABLE_REG(pt_idx),
				 (u8 *)em_pt_tbl.data,
				 NBL_FEM_EM0_PROFILE_TABLE_DWLEN *
				 NBL_BYTES_IN_REG);
		em_pt_tbl.info.action0 = em_pt_tbl_tmp.info.action0;
		nbl_hw_write_regs(phy_mgt, NBL_FEM_EM0_PROFILE_TABLE_REG(pt_idx),
				  (u8 *)em_pt_tbl.data,
				  NBL_FEM_EM0_PROFILE_TABLE_DWLEN *
				  NBL_BYTES_IN_REG);
		break;
	case NBL_PP_TYPE_1:
		nbl_hw_read_regs(phy_mgt, NBL_FEM_EM1_PROFILE_TABLE_REG(pt_idx),
				 (u8 *)em_pt_tbl.data,
				 NBL_FEM_EM0_PROFILE_TABLE_DWLEN *
				 NBL_BYTES_IN_REG);
		em_pt_tbl.info.action0 = em_pt_tbl_tmp.info.action0;
		nbl_hw_write_regs(phy_mgt, NBL_FEM_EM1_PROFILE_TABLE_REG(pt_idx),
				  (u8 *)em_pt_tbl.data,
				  NBL_FEM_EM0_PROFILE_TABLE_DWLEN *
				  NBL_BYTES_IN_REG);
		break;
	case NBL_PP_TYPE_2:
		nbl_hw_read_regs(phy_mgt, NBL_FEM_EM2_PROFILE_TABLE_REG(pt_idx),
				 (u8 *)&em_pt_tbl.data,
				 NBL_FEM_EM0_PROFILE_TABLE_DWLEN *
				 NBL_BYTES_IN_REG);
		em_pt_tbl.info.action0 = em_pt_tbl_tmp.info.action0;
		nbl_hw_write_regs(phy_mgt, NBL_FEM_EM2_PROFILE_TABLE_REG(pt_idx),
				  (u8 *)em_pt_tbl.data,
				  NBL_FEM_EM0_PROFILE_TABLE_DWLEN *
				  NBL_BYTES_IN_REG);
		break;
	default:
		nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
			  "wrong pp id for this profile");
	}
}

static int nbl_fem_init_regs(struct nbl_phy_mgt *phy_mgt,
			     struct nbl_chan_flow_init_info_leonis *param)
{
	u8 i = 0;
	u32 bank_sel = 0;
	struct nbl_flow_prf_data *prf_data;
	union fem_ht_bank_sel_btm_u ht_bank_sel = {.info = {0}};

	/* HT bank sel */
	nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		  "flow init: fem bank selection");
	bank_sel = HT_PORT0_BANK_SEL | HT_PORT1_BANK_SEL << NBL_8BIT |
		   HT_PORT2_BANK_SEL << NBL_16BIT;
	nbl_hw_write_regs(phy_mgt, NBL_FEM_HT_BANK_SEL_BITMAP,
			  (u8 *)&bank_sel, sizeof(bank_sel));

	/* KT bank sel */
	bank_sel = KT_PORT0_BANK_SEL | KT_PORT1_BANK_SEL << NBL_8BIT |
		   KT_PORT2_BANK_SEL << NBL_16BIT;
	nbl_hw_write_regs(phy_mgt, NBL_FEM_KT_BANK_SEL_BITMAP,
			  (u8 *)&bank_sel, sizeof(bank_sel));

	/* AT bank sel */
	bank_sel = AT_PORT0_BANK_SEL | AT_PORT1_BANK_SEL << NBL_16BIT;
	nbl_hw_write_regs(phy_mgt, NBL_FEM_AT_BANK_SEL_BITMAP,
			  (u8 *)&bank_sel, sizeof(bank_sel));
	bank_sel = AT_PORT2_BANK_SEL;
	nbl_hw_write_regs(phy_mgt, NBL_FEM_AT_BANK_SEL_BITMAP2,
			  (u8 *)&bank_sel, sizeof(bank_sel));

	ht_bank_sel.info.port0_ht_depth = HT_PORT0_BTM;
	ht_bank_sel.info.port1_ht_depth = HT_PORT1_BTM;
	ht_bank_sel.info.port2_ht_depth = HT_PORT2_BTM;
	nbl_hw_write_regs(phy_mgt, NBL_FEM_HT_BANK_SEL_BTM_ADDR,
			  (u8 *)ht_bank_sel.data, sizeof(ht_bank_sel));

	for (i = 0; i < param->flow_cfg.item_cnt; i++) {
		prf_data = &param->flow_cfg.prf_data[i];
		nbl_fem_profile_table_action_set(phy_mgt, prf_data->pp_id,
						 prf_data->prf_id, param->vsi_id, true);
	}

	return NBL_OK;
}

static int nbl_mcc_init_regs(struct nbl_phy_mgt *phy_mgt)
{
	union mcc_action_priority_u act_pri = {
		.info.dport_act_pri = 3,
		.info.statidx_act_pri = 3,
		.info.dqueue_act_pri = 3,
	};

	nbl_hw_write_regs(phy_mgt, NBL_MCC_ACTION_PRIORITY_ADDR,
			  (u8 *)act_pri.data, sizeof(act_pri));
	return NBL_OK;
}

static void nbl_ped_vlan_type_init(struct nbl_phy_mgt *phy_mgt)
{
	union dped_vlan_type0_u vlan_type = {.info = {0}};

	nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		  "flow init: vlan type init");
	vlan_type.info.vau = RTE_ETHER_TYPE_VLAN;
	nbl_hw_write_regs(phy_mgt, NBL_UPED_VLAN_TYPE0_ADDR,
			  (u8 *)vlan_type.data, sizeof(vlan_type));
	nbl_hw_write_regs(phy_mgt, NBL_DPED_VLAN_TYPE0_ADDR,
			  (u8 *)vlan_type.data, sizeof(vlan_type));
	vlan_type.info.vau = RTE_ETHER_TYPE_QINQ;
	nbl_hw_write_regs(phy_mgt, NBL_UPED_VLAN_TYPE1_ADDR,
			  (u8 *)vlan_type.data, sizeof(vlan_type));
	nbl_hw_write_regs(phy_mgt, NBL_DPED_VLAN_TYPE1_ADDR,
			  (u8 *)vlan_type.data, sizeof(vlan_type));
	vlan_type.info.vau = RTE_ETHER_TYPE_QINQ1;
	nbl_hw_write_regs(phy_mgt, NBL_UPED_VLAN_TYPE2_ADDR,
			  (u8 *)vlan_type.data, sizeof(vlan_type));
	nbl_hw_write_regs(phy_mgt, NBL_DPED_VLAN_TYPE2_ADDR,
			  (u8 *)vlan_type.data, sizeof(vlan_type));
	vlan_type.info.vau = RTE_ETHER_TYPE_QINQ2;
	nbl_hw_write_regs(phy_mgt, NBL_UPED_VLAN_TYPE3_ADDR,
			  (u8 *)vlan_type.data, sizeof(vlan_type));
	nbl_hw_write_regs(phy_mgt, NBL_DPED_VLAN_TYPE3_ADDR,
			  (u8 *)vlan_type.data, sizeof(vlan_type));
}

static void nbl_ped_csum_cmd_init(struct nbl_phy_mgt *phy_mgt)
{
	union uped_l4_ck_cmd_50_u l4_ck_cmd_50 = {.info = {0}};
	union uped_l4_ck_cmd_51_u l4_ck_cmd_51 = {.info = {0}};
	union uped_l4_ck_cmd_60_u l4_ck_cmd_60 = {.info = {0}};
	union uped_l4_ck_cmd_61_u l4_ck_cmd_61 = {.info = {0}};

	l4_ck_cmd_50.info.len_in_oft = 0x2;
	l4_ck_cmd_50.info.len_phid = 0x2;
	l4_ck_cmd_50.info.data_vld = 0x1;
	l4_ck_cmd_50.info.in_oft = 0x2;
	l4_ck_cmd_50.info.phid = 0x3;
	l4_ck_cmd_50.info.en = 0x1;

	l4_ck_cmd_51.info.ck_start0 = 0xc;
	l4_ck_cmd_51.info.ck_phid0 = 0x2;
	l4_ck_cmd_51.info.ck_len0 = 0x8;
	l4_ck_cmd_51.info.ck_phid1 = 0x3;
	l4_ck_cmd_51.info.ck_vld1 = 0x1;

	l4_ck_cmd_60.info.value = 0x62;
	l4_ck_cmd_60.info.len_in_oft = 0x4;
	l4_ck_cmd_60.info.len_phid = 0x2;
	l4_ck_cmd_60.info.len_vld = 0x1;
	l4_ck_cmd_60.info.data_vld = 0x1;
	l4_ck_cmd_60.info.in_oft = 0x2;
	l4_ck_cmd_60.info.phid = 0x3;
	l4_ck_cmd_60.info.en = 0x1;

	l4_ck_cmd_61.info.ck_start0 = 0x8;
	l4_ck_cmd_61.info.ck_phid0 = 0x2;
	l4_ck_cmd_61.info.ck_len0 = 0x20;
	l4_ck_cmd_61.info.ck_vld0 = 0x1;
	l4_ck_cmd_61.info.ck_phid1 = 0x3;
	l4_ck_cmd_61.info.ck_vld1 = 0x1;

	nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		  "flow init: ped checksum commands");
	nbl_hw_write_regs(phy_mgt, NBL_UPED_L4_CK_CMD_50_ADDR,
			  (u8 *)l4_ck_cmd_50.data, sizeof(l4_ck_cmd_50));
	nbl_hw_write_regs(phy_mgt, NBL_UPED_L4_CK_CMD_51_ADDR,
			  (u8 *)l4_ck_cmd_51.data, sizeof(l4_ck_cmd_51));
	nbl_hw_write_regs(phy_mgt, NBL_UPED_L4_CK_CMD_60_ADDR,
			  (u8 *)l4_ck_cmd_60.data, sizeof(l4_ck_cmd_60));
	nbl_hw_write_regs(phy_mgt, NBL_UPED_L4_CK_CMD_61_ADDR,
			  (u8 *)l4_ck_cmd_61.data, sizeof(l4_ck_cmd_61));
	nbl_hw_write_regs(phy_mgt, NBL_DPED_L4_CK_CMD_50_ADDR,
			  (u8 *)l4_ck_cmd_50.data, sizeof(l4_ck_cmd_50));
	nbl_hw_write_regs(phy_mgt, NBL_DPED_L4_CK_CMD_51_ADDR,
			  (u8 *)l4_ck_cmd_51.data, sizeof(l4_ck_cmd_51));
	nbl_hw_write_regs(phy_mgt, NBL_DPED_L4_CK_CMD_60_ADDR,
			  (u8 *)l4_ck_cmd_60.data, sizeof(l4_ck_cmd_60));
	nbl_hw_write_regs(phy_mgt, NBL_DPED_L4_CK_CMD_61_ADDR,
			  (u8 *)l4_ck_cmd_61.data, sizeof(l4_ck_cmd_61));
}

static int nbl_ped_init_regs(struct nbl_phy_mgt *phy_mgt)
{
	nbl_ped_vlan_type_init(phy_mgt);
	nbl_ped_csum_cmd_init(phy_mgt);
	return NBL_OK;
}

static void nbl_flow_clear_tcam_ad(struct nbl_phy_mgt *phy_mgt)
{
	union fem_em0_tcam_table_u tcam_table;
	union fem_em0_ad_table_u ad_table;
	u8 *tcam_ptr = (u8 *)tcam_table.data;
	u8 *ad_ptr = (u8 *)ad_table.data;
	u16 i = 0;

	memset(&tcam_table, 0, sizeof(tcam_table));
	memset(&ad_table, 0, sizeof(ad_table));

	nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		  "flow init: to clear flow pp tcam");
	for (; i < NBL_FEM_TCAM_MAX_NUM; i++) {
		nbl_hw_write_regs(phy_mgt,
				  NBL_FEM_EM0_TCAM_TABLE_REG(i),
				  tcam_ptr, sizeof(tcam_table));
		nbl_hw_write_regs(phy_mgt,
				  NBL_FEM_EM0_AD_TABLE_REG(i),
				  ad_ptr, sizeof(ad_table));
		nbl_hw_write_regs(phy_mgt,
				  NBL_FEM_EM2_TCAM_TABLE_REG(i),
				  tcam_ptr, sizeof(tcam_table));
		nbl_hw_write_regs(phy_mgt,
				  NBL_FEM_EM2_AD_TABLE_REG(i),
				  ad_ptr, sizeof(ad_table));

		/* PP1 tcam last four entries reserved for ECN stats, skip clear */
		if (i > NBL_FEM_TCAM_MAX_NUM - 4) {
			nbl_hw_rd32(phy_mgt, NBL_FEM_EM2_AD_TABLE_REG(i));
			continue;
		}

		nbl_hw_write_regs(phy_mgt,
				  NBL_FEM_EM1_TCAM_TABLE_REG(i),
				  tcam_ptr, sizeof(tcam_table));
		nbl_hw_write_regs(phy_mgt,
				  NBL_FEM_EM1_AD_TABLE_REG(i),
				  ad_ptr, sizeof(ad_table));
		nbl_hw_rd32(phy_mgt, NBL_FEM_EM2_AD_TABLE_REG(i));
	}
}

static union __maybe_unused epro_aft_u aft_def[NBL_FWD_TYPE_MAX] = {
	[NBL_FWD_TYPE_NORMAL]		= {
		.data = BIT(NBL_ACT_SET_MCC) | BIT(NBL_ACT_SET_TAB_INDEX) |
		BIT(NBL_ACT_SET_MIRROR),
	},
	[NBL_FWD_TYPE_CPU_ASSIGNED]	= {
		.data = BIT(NBL_ACT_SET_MCC) | BIT(NBL_ACT_SET_TAB_INDEX) |
		BIT(NBL_ACT_SET_MIRROR),
	},
	[NBL_FWD_TYPE_UPCALL]		= {
		.data = BIT_ULL(NBL_ACT_SET_MCC) | BIT_ULL(NBL_ACT_SET_TAB_INDEX) |
		BIT_ULL(NBL_ACT_SET_MIRROR) | BIT_ULL(NBL_ACT_SET_VNI0) |
		BIT_ULL(NBL_ACT_SET_VNI1) | BIT_ULL(NBL_ACT_REP_IPV4_SIP) |
		BIT_ULL(NBL_ACT_REP_IPV4_DIP) | BIT_ULL(NBL_ACT_REP_IPV6_SIP) |
		BIT_ULL(NBL_ACT_REP_IPV6_DIP) | BIT_ULL(NBL_ACT_REP_DPORT) |
		BIT_ULL(NBL_ACT_REP_SPORT) | BIT_ULL(NBL_ACT_REP_DMAC) |
		BIT_ULL(NBL_ACT_REP_SMAC) | BIT_ULL(NBL_ACT_REP_IPV4_DSCP) |
		BIT_ULL(NBL_ACT_REP_IPV6_DSCP) | BIT_ULL(NBL_ACT_REP_IPV4_TTL) |
		BIT_ULL(NBL_ACT_REP_IPV6_TTL) | BIT_ULL(NBL_ACT_DEL_SVLAN) |
		BIT_ULL(NBL_ACT_DEL_CVLAN) | BIT_ULL(NBL_ACT_REP_SVLAN) |
		BIT_ULL(NBL_ACT_REP_CVLAN) | BIT_ULL(NBL_ACT_ADD_CVLAN) |
		BIT_ULL(NBL_ACT_ADD_SVLAN) | BIT_ULL(NBL_ACT_TNL_ENCAP) |
		BIT_ULL(NBL_ACT_TNL_DECAP) | BIT_ULL(NBL_ACT_REP_OUTER_SPORT) |
		BIT_ULL(NBL_ACT_SET_PRI_MDF0),
	},
	[NBL_FWD_TYPE_SRC_MIRROR]	= {
		.data = BIT(NBL_ACT_SET_FLOW_STAT0) | BIT(NBL_ACT_SET_FLOW_STAT1) |
		BIT(NBL_ACT_SET_RSS) | BIT(NBL_ACT_SET_TAB_INDEX) |
		BIT(NBL_ACT_SET_MCC) | BIT(NBL_ACT_SET_VNI0) |
		BIT(NBL_ACT_SET_VNI1) | BIT(NBL_ACT_SET_PRBAC) |
		BIT(NBL_ACT_SET_DP_HASH0) | BIT(NBL_ACT_SET_DP_HASH1) |
		BIT(NBL_ACT_SET_PRI_MDF0) | BIT(NBL_ACT_SET_FLOW_CAR) |
		((u64)0xffffffff << 32),
	},
	[NBL_FWD_TYPE_OTHER_MIRROR]	= {
		.data = BIT(NBL_ACT_SET_FLOW_STAT0) | BIT(NBL_ACT_SET_FLOW_STAT1) |
		BIT(NBL_ACT_SET_RSS) | BIT(NBL_ACT_SET_TAB_INDEX) |
		BIT(NBL_ACT_SET_MCC) | BIT(NBL_ACT_SET_VNI0) |
		BIT(NBL_ACT_SET_VNI1) | BIT(NBL_ACT_SET_PRBAC) |
		BIT(NBL_ACT_SET_DP_HASH0) | BIT(NBL_ACT_SET_DP_HASH1) |
		BIT(NBL_ACT_SET_PRI_MDF0),
	},
	[NBL_FWD_TYPE_MNG]		= {.data = 0,},
	[NBL_FWD_TYPE_GLB_LB]		= {.data = 0,},
	[NBL_FWD_TYPE_DROP]		= {.data = 0,},
};

static void nbl_epro_act_pri_cfg(struct nbl_phy_mgt *phy_mgt)
{
	union epro_action_priority_u act_pri = {
		.info.mirroridx		= EPRO_ACT_MIRRORIDX_PRI,
		.info.car		= EPRO_ACT_CARIDX_PRI,
		.info.dqueue		= EPRO_ACT_DQUEUE_PRI,
		.info.dport		= EPRO_ACT_DPORT_PRI,
		.info.pop_8021q		= EPRO_ACT_POP_IVLAN_PRI,
		.info.pop_qinq		= EPRO_ACT_POP_OVLAN_PRI,
		.info.replace_inner_vlan = EPRO_ACT_REPLACE_IVLAN_PRI,
		.info.replace_outer_vlan = EPRO_ACT_REPLACE_OVLAN_PRI,
		.info.push_inner_vlan	= EPRO_ACT_PUSH_IVLAN_PRI,
		.info.push_outer_vlan	= EPRO_ACT_PUSH_OVLAN_PRI,
		.info.outer_sport_mdf	= EPRO_ACT_OUTER_SPORT_MDF_PRI,
		.info.pri_mdf		= EPRO_ACT_PRI_MDF_PRI,
		.info.dp_hash0		= EPRO_ACT_DP_HASH0_PRI,
		.info.dp_hash1		= EPRO_ACT_DP_HASH1_PRI,
		.info.rsv		= 0,
	};
	union epro_mirror_action_priority_u mir_act_pri = {
		.info.car	= EPRO_MIRROR_ACT_CARIDX_PRI,
		.info.dqueue	= EPRO_MIRROR_ACT_DQUEUE_PRI,
		.info.dport	= EPRO_MIRROR_ACT_DPORT_PRI,
		.info.rsv	= 0,
	};

	nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		  "flow init: epro action priority");
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_ACTION_PRIORITY_ADDR,
			  (u8 *)act_pri.data, sizeof(act_pri));

	nbl_hw_write_regs(phy_mgt, NBL_EPRO_MIRROR_ACTION_PRIORITY_ADDR,
			  (u8 *)mir_act_pri.data, sizeof(mir_act_pri));
}

static void nbl_epro_act_sel_en_cfg(struct nbl_phy_mgt *phy_mgt)
{
	union epro_act_sel_en_u act_sel_en = {
		.info.rssidx_en		= 1,
		.info.dport_en		= 1,
		.info.mirroridx_en	= 1,
		.info.dqueue_en		= 1,
		.info.encap_en		= 1,
		.info.pop_8021q_en	= 1,
		.info.pop_qinq_en	= 1,
		.info.push_cvlan_en	= 1,
		.info.push_svlan_en	= 1,
		.info.replace_cvlan_en	= 1,
		.info.replace_svlan_en	= 1,
		.info.rsv		= 0,
	};

	nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		  "flow init: epro action enable");
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_ACT_SEL_EN_ADDR,
			  (u8 *)act_sel_en.data, sizeof(act_sel_en));
}

static void nbl_epro_act_cfg_init(struct nbl_phy_mgt *phy_mgt)
{
	union epro_am_act_id0_u am_act_id0 = {.info = {0}};
	union epro_am_act_id1_u am_act_id1 = {.info = {0}};
	union epro_am_act_id2_u am_act_id2 = {.info = {0}};
	union epro_am_act_id3_u am_act_id3 = {.info = {0}};

	nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		  "flow init: epro action id");
	am_act_id0.info.replace_cvlan = NBL_ACT_REP_CVLAN;
	am_act_id0.info.replace_svlan = NBL_ACT_REP_SVLAN;
	am_act_id0.info.push_cvlan = NBL_ACT_ADD_CVLAN;
	am_act_id0.info.push_svlan = NBL_ACT_ADD_SVLAN;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_AM_ACT_ID0_ADDR,
			  (u8 *)am_act_id0.data, sizeof(am_act_id0));
	am_act_id1.info.pop_qinq = NBL_ACT_DEL_CVLAN;
	am_act_id1.info.pop_8021q = NBL_ACT_DEL_SVLAN;
	am_act_id1.info.dport = NBL_ACT_SET_DPORT;
	am_act_id1.info.dqueue = NBL_ACT_SET_QUE_IDX;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_AM_ACT_ID1_ADDR,
			  (u8 *)am_act_id1.data, sizeof(am_act_id1));
	am_act_id2.info.rssidx = NBL_ACT_SET_RSS;
	am_act_id2.info.mirroridx = NBL_ACT_SET_MIRROR;
	am_act_id2.info.car = NBL_ACT_SET_CAR;
	am_act_id2.info.encap = NBL_ACT_TNL_ENCAP;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_AM_ACT_ID2_ADDR,
			  (u8 *)am_act_id2.data, sizeof(am_act_id2));
	am_act_id3.info.outer_sport_mdf = NBL_ACT_REP_OUTER_SPORT;
	am_act_id3.info.pri_mdf = NBL_ACT_SET_PRI_MDF0;
	am_act_id3.info.dp_hash0 = NBL_ACT_SET_DP_HASH0;
	am_act_id3.info.dp_hash1 = NBL_ACT_SET_DP_HASH1;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_AM_ACT_ID3_ADDR,
			  (u8 *)am_act_id3.data, sizeof(am_act_id3));

	nbl_epro_act_pri_cfg(phy_mgt);
	nbl_epro_act_sel_en_cfg(phy_mgt);
}

static int nbl_epro_init_regs(struct nbl_phy_mgt *phy_mgt)
{
	u32 fwd_type = 0;
	union epro_rss_sk_u rss_sk_def;

	nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		  "flow init: epro rss");
	/* init default rss toeplitz hash key */
	rss_sk_def.info.sk_arr[0] = NBL_EPRO_RSS_KEY_32;
	rss_sk_def.info.sk_arr[1] = NBL_EPRO_RSS_KEY_32;
	rss_sk_def.info.sk_arr[2] = NBL_EPRO_RSS_KEY_32;
	rss_sk_def.info.sk_arr[3] = NBL_EPRO_RSS_KEY_32;
	rss_sk_def.info.sk_arr[4] = NBL_EPRO_RSS_KEY_32;
	rss_sk_def.info.sk_arr[5] = NBL_EPRO_RSS_KEY_32;
	rss_sk_def.info.sk_arr[6] = NBL_EPRO_RSS_KEY_32;
	rss_sk_def.info.sk_arr[7] = NBL_EPRO_RSS_KEY_32;
	rss_sk_def.info.sk_arr[8] = NBL_EPRO_RSS_KEY_32;
	rss_sk_def.info.sk_arr[9] = NBL_EPRO_RSS_KEY_32;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_RSS_SK_ADDR, (u8 *)rss_sk_def.data,
			  sizeof(rss_sk_def));

	nbl_epro_act_cfg_init(phy_mgt);

	for (fwd_type = 0; fwd_type < NBL_FWD_TYPE_MAX; fwd_type++)
		nbl_hw_write_regs(phy_mgt, NBL_EPRO_AFT_REG(fwd_type),
				  (u8 *)&aft_def[fwd_type].data, sizeof(union epro_aft_u));

	return NBL_OK;
}

static int nbl_phy_flow_init(void *priv, void *param)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_chan_flow_init_info_leonis *info =
		(struct nbl_chan_flow_init_info_leonis *)param;

	nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		  "flow init: start");
	nbl_hw_wr32(phy_mgt, NBL_FEM_INIT_START_ADDR, NBL_FEM_INIT_START_VALUE);
	nbl_flow_clear_tcam_ad(phy_mgt);
	nbl_ipro_init_regs(phy_mgt);
	nbl_pp_init_regs(phy_mgt);
	nbl_fem_init_regs(phy_mgt, info);
	nbl_mcc_init_regs(phy_mgt);
	nbl_acl_init_regs(phy_mgt, info);
	nbl_epro_init_regs(phy_mgt);
	nbl_ped_init_regs(phy_mgt);
	nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		  "flow init: finished");

	return NBL_OK;
}

static void nbl_phy_clear_profile_table_action(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	u8 i = 0;
	u8 pp_id = 0;
	u8 prf_id = 0;

	for (i = NBL_PP1_PROFILE_ID_MIN; i <= NBL_PP2_PROFILE_ID_MAX; i++) {
		pp_id = i / NBL_PP_PROFILE_NUM;
		prf_id = i % NBL_PP_PROFILE_NUM;
		nbl_fem_profile_table_action_set(phy_mgt, pp_id,
						 prf_id, 0, false);
	}
}

static int nbl_phy_flow_deinit(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		  "flow deinit: start");

	nbl_phy_clear_profile_table_action(phy_mgt);
	// clear FEM & ACL tcams
	nbl_flow_clear_tcam_ad(phy_mgt);
	nbl_acl_flow_tcam_clear(phy_mgt, NBL_ACL_FLUSH_FLOW_BTM, 0, NBL_ACL_TCAM_DEPTH);

	nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		  "flow deinit: finished");
	return NBL_OK;
}

static int nbl_phy_flow_get_acl_switch(void *priv, u8 *acl_enable)
{
	union acl_init_done_u init_done;
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	init_done.data[0] = nbl_hw_rd32(phy_mgt, NBL_ACL_INIT_DONE_ADDR);
	*acl_enable = init_done.info.done;
	nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		  "acl switch: %u", *acl_enable);
	return 0;
}

static void nbl_phy_get_line_rate_info(void *priv, void *data, void *result)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_rep_line_rate_info *req = (struct nbl_rep_line_rate_info *)data;
	struct nbl_rep_line_rate_info *resp = (struct nbl_rep_line_rate_info *)result;
	u16 table_id = req->func_id;
	union epro_vpt_u *vpt = (union epro_vpt_u *)resp->data;

	struct dsch_vn_sha2net_map_tbl *sha2net =
		(struct dsch_vn_sha2net_map_tbl *)(resp->data + NBL_EPRO_VPT_DWLEN);

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_VPT_REG(req->vsi_id),
			 (u8 *)vpt->data,
			 NBL_EPRO_VPT_DWLEN * NBL_BYTES_IN_REG);
	nbl_hw_read_regs(phy_mgt, NBL_DSCH_VN_SHA2NET_MAP_TBL_REG(table_id),
			 (u8 *)sha2net,
			 NBL_DSCH_VN_SHA2NET_MAP_TBL_DWLEN * NBL_BYTES_IN_REG);
}

static void nbl_and_parsed_reg(u32 *ptr, u32 *value, u32 reg_len)
{
	u32 idx = 0;

	for (idx = 0; idx < reg_len; idx++) {
		*value = (*value) & (*ptr);
		value++;
		ptr++;
	}
}

static void nbl_or_parsed_reg(u32 *ptr, u32 *value, u32 reg_len)
{
	u32 idx = 0;

	for (idx = 0; idx < reg_len; idx++) {
		*value = (*value) | (*ptr);
		value++;
		ptr++;
	}
}

static void nbl_write_parsed_reg(struct nbl_phy_mgt *phy_mgt,
				 struct nbl_chan_regs_info *reg_info, u32 *value)
{
	u32 *ptr = (u32 *)reg_info->data;
	u32 reg_len = reg_info->data_len;

	if (reg_info->mode == NBL_FLOW_READ_OR_WRITE_MODE) {
		nbl_or_parsed_reg(ptr, value, reg_len);
	} else if (reg_info->mode == NBL_FLOW_READ_AND_WRITE_MODE) {
		nbl_and_parsed_reg(ptr, value, reg_len);
	} else if (reg_info->mode == NBL_FLOW_READ_OR_AND_WRITE_MODE) {
		reg_len = reg_len / 2;
		nbl_or_parsed_reg(ptr, value, reg_len);
		nbl_and_parsed_reg(ptr + reg_len, value, reg_len);
	} else {
		// point the value to mailbox received data
		value = reg_info->data;
	}

	nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		  "send regs to write(%u): size %u, depth %u, data %u",
		  reg_info->tbl_name, reg_len, reg_info->depth, reg_info->data[0]);

	switch (reg_info->tbl_name) {
	case NBL_FLOW_EPRO_ECPVPT_REG:
		nbl_hw_write_regs(phy_mgt, NBL_EPRO_ECPVPT_REG(reg_info->depth),
				  (u8 *)value, NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_EPRO_ECPIPT_REG:
		nbl_hw_write_regs(phy_mgt, NBL_EPRO_ECPIPT_REG(reg_info->depth),
				  (u8 *)value, NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_DPED_TAB_TNL_REG:
		nbl_hw_write_regs(phy_mgt,
				  NBL_DPED_TAB_TNL_REG(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_DPED_REPLACE:
		nbl_hw_write_regs(phy_mgt,
				  NBL_DPED_TAB_REPLACE_REG(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_UPED_REPLACE:
		nbl_hw_write_regs(phy_mgt,
				  NBL_UPED_TAB_REPLACE_REG(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_DPED_MIRROR_TABLE:
		nbl_hw_write_regs(phy_mgt,
				  NBL_DPED_TAB_MIR_REG(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_DPED_MIR_CMD_0_TABLE:
		nbl_hw_write_regs(phy_mgt,
				  NBL_DPED_MIR_CMD_0_TABLE(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_EPRO_MT_REG:
		nbl_hw_write_regs(phy_mgt, NBL_EPRO_MT_REG(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_EM0_TCAM_TABLE_REG:
		nbl_hw_write_regs(phy_mgt,
				  NBL_FEM_EM0_TCAM_TABLE_REG(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_EM1_TCAM_TABLE_REG:
		nbl_hw_write_regs(phy_mgt,
				  NBL_FEM_EM1_TCAM_TABLE_REG(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_EM2_TCAM_TABLE_REG:
		nbl_hw_write_regs(phy_mgt,
				  NBL_FEM_EM2_TCAM_TABLE_REG(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_EM0_AD_TABLE_REG:
		nbl_hw_write_regs(phy_mgt,
				  NBL_FEM_EM0_AD_TABLE_REG(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_EM1_AD_TABLE_REG:
		nbl_hw_write_regs(phy_mgt,
				  NBL_FEM_EM1_AD_TABLE_REG(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_EM2_AD_TABLE_REG:
		nbl_hw_write_regs(phy_mgt,
				  NBL_FEM_EM2_AD_TABLE_REG(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_IPRO_UDL_PKT_FLT_DMAC_REG:
		nbl_hw_write_regs(phy_mgt,
				  NBL_IPRO_UDL_PKT_FLT_DMAC_REG(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_IPRO_UDL_PKT_FLT_CTRL_REG:
		nbl_hw_write_regs(phy_mgt,
				  NBL_IPRO_UDL_PKT_FLT_CTRL_ADDR,
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_ACTION_RAM_TBL:
		nbl_hw_write_regs(phy_mgt,
				  NBL_ACL_ACTION_RAM_TBL(reg_info->ram_id,
							 reg_info->s_depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_MCC_TBL_REG:
		nbl_hw_write_regs(phy_mgt, NBL_MCC_TBL_REG(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_EPRO_EPT_REG:
		nbl_hw_write_regs(phy_mgt, NBL_EPRO_EPT_REG(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_IPRO_UP_SRC_PORT_TBL_REG:
		nbl_hw_write_regs(phy_mgt,
				  NBL_IPRO_UP_SRC_PORT_TBL_REG(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_UCAR_FLOW_REG:
		nbl_hw_write_regs(phy_mgt, NBL_UCAR_FLOW_REG(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_EPRO_VPT_REG:
		nbl_hw_write_regs(phy_mgt, NBL_EPRO_VPT_REG(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_UCAR_FLOW_TIMMING_ADD_ADDR:
		nbl_hw_write_regs(phy_mgt, NBL_UCAR_FLOW_TIMMING_ADD_ADDR,
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_SHAPING_GRP_TIMMING_ADD_ADDR:
		nbl_hw_write_regs(phy_mgt, NBL_SHAPING_GRP_TIMMING_ADD_ADDR,
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_SHAPING_GRP_REG:
		nbl_hw_write_regs(phy_mgt,
				  NBL_SHAPING_GRP_REG(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_DSCH_VN_SHA2GRP_MAP_TBL_REG:
		nbl_hw_write_regs(phy_mgt,
				  NBL_DSCH_VN_SHA2GRP_MAP_TBL_REG(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_DSCH_VN_GRP2SHA_MAP_TBL_REG:
		nbl_hw_write_regs(phy_mgt,
				  NBL_DSCH_VN_GRP2SHA_MAP_TBL_REG(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_SHAPING_DPORT_TIMMING_ADD_ADDR:
		nbl_hw_write_regs(phy_mgt, NBL_SHAPING_DPORT_TIMMING_ADD_ADDR,
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_SHAPING_DPORT_REG:
		nbl_hw_write_regs(phy_mgt, NBL_SHAPING_DPORT_REG(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_DSCH_PSHA_EN_ADDR:
		nbl_hw_write_regs(phy_mgt, NBL_DSCH_PSHA_EN_ADDR,
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_UCAR_FLOW_4K_REG:
		nbl_hw_write_regs(phy_mgt, NBL_UCAR_FLOW_4K_REG(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_UCAR_FLOW_4K_TIMMING_ADD_ADDR:
		nbl_hw_write_regs(phy_mgt, NBL_UCAR_FLOW_4K_TIMMING_ADD_ADDR,
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_SHAPING_NET_TIMMING_ADD_ADDR:
		nbl_hw_write_regs(phy_mgt, NBL_SHAPING_NET_TIMMING_ADD_ADDR,
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_SHAPING_NET_REG:
	case NBL_FLOW_DSCH_VN_NET2SHA_MAP_TBL_REG:
	case NBL_FLOW_DSCH_VN_SHA2NET_MAP_TBL_REG:
		nbl_phy_set_offload_shaping(phy_mgt, reg_info, value);
		break;
	case NBL_FLOW_UCAR_CAR_CTRL_ADDR:
		nbl_hw_write_regs(phy_mgt, NBL_UCAR_CAR_CTRL_ADDR,
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_UPED_VSI_TYPE_REG:
		nbl_hw_write_regs(phy_mgt, NBL_UPED_TAB_VSI_TYPE_REG(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_DPED_VSI_TYPE_REG:
		nbl_hw_write_regs(phy_mgt, NBL_DPED_TAB_VSI_TYPE_REG(reg_info->depth),
				  (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	default:
		nbl_err(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
			"send regs: unrecognized register(%u) to write, will not handle",
			reg_info->tbl_name);
		break;
	}
}

static void nbl_read_parsed_reg(struct nbl_phy_mgt *phy_mgt,
				struct nbl_chan_regs_info *reg_info, u32 *value)
{
	u32 reg_len = reg_info->data_len;

	// in this mode, both or-data and and-data are sent
	if (reg_info->mode == NBL_FLOW_READ_OR_AND_WRITE_MODE)
		reg_len = reg_len / 2;

	if (reg_len > NBL_CHAN_REG_MAX_LEN) {
		nbl_err(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
			"send regs: read length longer than data allocated");
		return;
	}

	nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		  "send regs to read(%u): size %u, depth %u, data %u",
		  reg_info->tbl_name, reg_len, reg_info->depth, reg_info->data[0]);

	switch (reg_info->tbl_name) {
	case NBL_FLOW_EPRO_ECPVPT_REG:
		nbl_hw_read_regs(phy_mgt, NBL_EPRO_ECPVPT_REG(reg_info->depth),
				 (u8 *)value, NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_EPRO_ECPIPT_REG:
		nbl_hw_read_regs(phy_mgt, NBL_EPRO_ECPIPT_REG(reg_info->depth),
				 (u8 *)value, NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_EPRO_EPT_REG:
		nbl_hw_read_regs(phy_mgt, NBL_EPRO_EPT_REG(reg_info->depth),
				 (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_IPRO_UP_SRC_PORT_TBL_REG:
		nbl_hw_read_regs(phy_mgt,
				 NBL_IPRO_UP_SRC_PORT_TBL_REG(reg_info->depth),
				 (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_EPRO_VPT_REG:
		nbl_hw_read_regs(phy_mgt, NBL_EPRO_VPT_REG(reg_info->depth),
				 (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_DSCH_PSHA_EN_ADDR:
		nbl_hw_read_regs(phy_mgt, NBL_DSCH_PSHA_EN_ADDR,
				 (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_UCAR_CAR_CTRL_ADDR:
		nbl_hw_read_regs(phy_mgt, NBL_UCAR_CAR_CTRL_ADDR,
				 (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_UCAR_GREEN_CELL_ADDR:
		nbl_hw_read_regs(phy_mgt,
				 (NBL_UCAR_GREEN_CELL_ADDR + reg_info->depth),
				 (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	case NBL_FLOW_UCAR_GREEN_PKT_ADDR:
		nbl_hw_read_regs(phy_mgt,
				 (NBL_UCAR_GREEN_PKT_ADDR + reg_info->depth),
				 (u8 *)value, reg_len * NBL_BYTES_IN_REG);
		break;
	default:
		nbl_err(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
			"send regs: unrecognized register(%u) to read, will not handle",
			reg_info->tbl_name);
		break;
	}
}

static int nbl_phy_offload_flow_rule(void *priv, void *param)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_chan_bulk_regs_info *hdr_info =
		(struct nbl_chan_bulk_regs_info *)param;
	struct nbl_chan_regs_info *reg_info =
		(struct nbl_chan_regs_info *)(hdr_info + 1);
	u8 regs_count = hdr_info->item_cnt;
	u32 value[NBL_CHAN_REG_MAX_LEN] = { 0 };
	u8 i;

	nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		  "send regs: flow regs received: to parse and read/write: regs info: count %u, total size %u, 1st reg: table %u, mode %u, size %u, depth %u, data %u",
		  hdr_info->item_cnt, hdr_info->data_len,
		  reg_info->tbl_name, reg_info->mode, reg_info->data_len,
		  reg_info->depth, reg_info->data[0]);

	if (reg_info->data_len == 0 || regs_count == 0) {
		nbl_err(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
			"send regs: reg count or data length invalid");
		return -1;
	}

	for (i = 0; i < regs_count; i++) {
		if (reg_info->mode == NBL_FLOW_READ_MODE) {
			nbl_read_parsed_reg(phy_mgt, reg_info, value);
		} else if (reg_info->mode == NBL_FLOW_WRITE_MODE) {
			nbl_write_parsed_reg(phy_mgt, reg_info, value);
		} else if (reg_info->mode == NBL_FLOW_READ_OR_WRITE_MODE ||
			   reg_info->mode == NBL_FLOW_READ_AND_WRITE_MODE ||
			   reg_info->mode == NBL_FLOW_READ_OR_AND_WRITE_MODE) {
			nbl_read_parsed_reg(phy_mgt, reg_info, value);
			nbl_write_parsed_reg(phy_mgt, reg_info, value);
		} else {
			nbl_err(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
				"failed parsing reg info: unrecognized mode: tab %u, mode %u, size %u, ",
				reg_info->tbl_name, reg_info->mode, reg_info->data_len);
		}

		reg_info = (struct nbl_chan_regs_info *)
			(reg_info + reg_info->data_len + 1);
	}

	return NBL_OK;
}

static void
nbl_repr_eth_dev_ipro_dn_init(struct nbl_phy_mgt *phy_mgt, u16 vsi_id)
{
	union ipro_dn_src_port_tbl_u dn_src_port = {.info = {0}};

	nbl_hw_read_regs(phy_mgt, NBL_IPRO_DN_SRC_PORT_TBL_REG(vsi_id),
			 (u8 *)dn_src_port.data,
			 NBL_IPRO_DN_SRC_PORT_TBL_DWLEN * NBL_BYTES_IN_REG);
	dn_src_port.info.phy_flow = 0;
	dn_src_port.info.set_dport_en = 0;
	nbl_hw_write_regs(phy_mgt, NBL_IPRO_DN_SRC_PORT_TBL_REG(vsi_id),
			  (u8 *)dn_src_port.data,
			  NBL_IPRO_DN_SRC_PORT_TBL_DWLEN * NBL_BYTES_IN_REG);
	nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		  "init rep: ipro dn src written");
}

static void
nbl_repr_eth_dev_ipro_up_src_init(struct nbl_phy_mgt *phy_mgt, u16 eth_id)
{
	union ipro_up_src_port_tbl_u up_src_port = {.info = {0}};

	nbl_hw_read_regs(phy_mgt, NBL_IPRO_UP_SRC_PORT_TBL_REG(eth_id),
			 (u8 *)up_src_port.data,
			 NBL_IPRO_UP_SRC_PORT_TBL_DWLEN * NBL_BYTES_IN_REG);
	up_src_port.info.phy_flow = 0;
	up_src_port.info.set_dport_en = 0;
	nbl_hw_write_regs(phy_mgt, NBL_IPRO_UP_SRC_PORT_TBL_REG(eth_id),
			  (u8 *)up_src_port.data,
			  NBL_IPRO_UP_SRC_PORT_TBL_DWLEN * NBL_BYTES_IN_REG);
	nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		  "init rep: ipro up src written");
}

static void
nbl_ped_port_vlan_type_cfg(struct nbl_phy_mgt *phy_mgt, u32 port_id,
			   enum nbl_ped_vlan_type_e type,
			   enum nbl_ped_vlan_tpid_e tpid)
{
	union nbl_ped_port_vlan_type_u cfg = {.info = {0}};

	if (port_id >= NBL_DPED_VLAN_TYPE_PORT_NUM || tpid >= PED_VLAN_TYPE_NUM) {
		nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
			  "port_id %u exceed the max num %u.",
			  port_id, NBL_DPED_VLAN_TYPE_PORT_NUM);
		return;
	}

	nbl_hw_read_regs(phy_mgt, NBL_DPED_TAB_VSI_TYPE_REG(port_id),
			 (u8 *)cfg.data, NBL_BYTES_IN_REG);
	switch (type) {
	case INNER_VLAN_TYPE:
		cfg.info.i_vlan_sel = tpid & 0b11;
		break;
	case OUTER_VLAN_TYPE:
		cfg.info.o_vlan_sel = tpid & 0b11;
		break;
	}
	nbl_hw_write_regs(phy_mgt, NBL_DPED_TAB_VSI_TYPE_REG(port_id),
			  (u8 *)cfg.data, NBL_BYTES_IN_REG);

	nbl_hw_read_regs(phy_mgt, NBL_UPED_TAB_VSI_TYPE_REG(port_id),
			 (u8 *)cfg.data, NBL_BYTES_IN_REG);
	switch (type) {
	case INNER_VLAN_TYPE:
		cfg.info.i_vlan_sel = tpid & 0b11;
		break;
	case OUTER_VLAN_TYPE:
		cfg.info.o_vlan_sel = tpid & 0b11;
		break;
	}
	nbl_hw_write_regs(phy_mgt, NBL_UPED_TAB_VSI_TYPE_REG(port_id),
			  (u8 *)cfg.data, NBL_BYTES_IN_REG);
}

static int nbl_phy_init_rep(void *priv, u16 vsi_id, u8 inner_type,
			    u8 outer_type, u8 rep_type, u16 rss_key_range_oft)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union epro_vpt_u vpt = {.info = {0}};

	nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
		  "init rep: vsi id %u, rep type %u", vsi_id, rep_type);
	if (rep_type == NBL_ETHDEV_PF_REP ||
	    rep_type == NBL_ETHDEV_VIRTIO_REP) {
		nbl_repr_eth_dev_ipro_dn_init(phy_mgt, vsi_id);
		/* configure vlan tpid type for vsi */
		nbl_ped_port_vlan_type_cfg(phy_mgt, vsi_id, INNER_VLAN_TYPE,
					   inner_type);
		nbl_ped_port_vlan_type_cfg(phy_mgt, vsi_id, OUTER_VLAN_TYPE,
					   outer_type);
	} else if (rep_type == NBL_ETHDEV_ETH_REP) {
		vsi_id = vsi_id - NBL_ETH_REP_INFO_BASE;
		nbl_repr_eth_dev_ipro_up_src_init(phy_mgt, vsi_id);
		/* configure vlan tpid type for eth */
		nbl_ped_port_vlan_type_cfg(phy_mgt,
					   (vsi_id + NBL_PED_VSI_TYPE_ETH_BASE),
					   INNER_VLAN_TYPE, inner_type);
		nbl_ped_port_vlan_type_cfg(phy_mgt,
					   (vsi_id + NBL_PED_VSI_TYPE_ETH_BASE),
					   OUTER_VLAN_TYPE, outer_type);
	}

	/* init rss l4 */
	if (rep_type == NBL_ETHDEV_PF_REP || rep_type == NBL_ETHDEV_VIRTIO_REP) {
		nbl_hw_read_regs(phy_mgt, NBL_EPRO_VPT_REG(vsi_id), (u8 *)vpt.data,
				 NBL_EPRO_VPT_DWLEN * NBL_BYTES_IN_REG);
		vpt.info.rss_alg_sel = NBL_SYM_TOEPLITZ_INT;
		vpt.info.rss_key_type_btm = NBL_KEY_IP4_L4_RSS_BIT | NBL_KEY_IP6_L4_RSS_BIT;
		nbl_hw_write_regs(phy_mgt, NBL_EPRO_VPT_REG(vsi_id), (u8 *)vpt.data,
				  NBL_EPRO_VPT_DWLEN * NBL_BYTES_IN_REG);
		nbl_debug(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_FLOW,
			  "init rep: epro rss written");
	}

	return NBL_OK;
}

static int nbl_phy_init_vdpaq(void *priv, u16 func_id, u16 bdf, u64 pa, u32 size)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union pcompleter_host_cfg_funtion_id_vdpa_net_u cfg_func_id = {
		.info.dbg = func_id,
		.info.vld = 1,
	};

	/* disable vdpa queue */
	nbl_hw_wr32(phy_mgt, NBL_VDPA_EN_ADDR, 0);

	/* cfg vdpa queue base */
	nbl_hw_wr32(phy_mgt, NBL_VDPA_RING_BASE_ADDR_L_ADDR, (u32)pa);
	nbl_hw_wr32(phy_mgt, NBL_VDPA_RING_BASE_ADDR_H_ADDR, (u32)(pa >> 32));

	/* cfg vdpa queue size */
	nbl_hw_wr32(phy_mgt, NBL_VDPA_RING_SIZE_MASK_ADDR, size - 1);
	nbl_hw_wr32(phy_mgt, NBL_VDPA_RING_TPNTR_ADDR, size);

	/* reset vdpa queue head */
	nbl_hw_wr32(phy_mgt, NBL_VDPA_RING_HPNTR_RST_ADDR, 1);

	/* cfg vdpa queue bdf */
	nbl_hw_wr32(phy_mgt, NBL_VDPA_DIF_BDF_ADDR, bdf);

	nbl_hw_write_regs(phy_mgt, NBL_PCOMPLETER_HOST_CFG_FUNTION_ID_VDPA_NET_ADDR,
			  (u8 *)&cfg_func_id, sizeof(cfg_func_id));

	/* all registers set, enable vdpa queue again */
	nbl_hw_wr32(phy_mgt, NBL_VDPA_EN_ADDR, 1);

	return 0;
}

static void nbl_phy_destroy_vdpaq(void *priv, u16 func_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_hw_wr32(phy_mgt, NBL_VDPA_RING_SIZE_MASK_ADDR, 0);
	nbl_hw_wr32(phy_mgt, NBL_VDPA_RING_BASE_ADDR_L_ADDR, 0);
	nbl_hw_wr32(phy_mgt, NBL_VDPA_RING_BASE_ADDR_H_ADDR, 0);

	/* reset the head */
	nbl_hw_wr32(phy_mgt, NBL_VDPA_RING_HPNTR_RST_ADDR, 1);
	nbl_hw_wr32(phy_mgt, NBL_VDPA_EN_ADDR, 0);
}

static const u32 nbl_phy_reg_dump_list[] = {
	NBL_TOP_CTRL_VERSION_INFO,
	NBL_TOP_CTRL_VERSION_DATE,
};

static void nbl_phy_get_reg_dump(void *priv, u32 *data, u32 len)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	int i;

	for (i = 0; i < ARRAY_SIZE(nbl_phy_reg_dump_list) && i < len; i++)
		nbl_hw_read_regs(phy_mgt, nbl_phy_reg_dump_list[i],
				 (u8 *)&data[i], sizeof(data[i]));
}

static int nbl_phy_get_reg_dump_len(void *priv)
{
	return ARRAY_SIZE(nbl_phy_reg_dump_list) * sizeof(u32);
}

/* return value need to convert to Mil degree Celsius(1/1000) */
static int nbl_phy_get_chip_temperature(void *priv, enum nbl_hwmon_type type, u32 senser_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	u32 temp = 0;

	switch (type) {
	case NBL_HWMON_TEMP_INPUT:
		temp = nbl_hw_rd32(phy_mgt, NBL_TOP_CTRL_TVSENSOR0);
		temp = (temp & 0x1ff) * 1000;
		break;
	case NBL_HWMON_TEMP_MAX:
		temp = NBL_LEONIS_TEMP_MAX * 1000;
		break;
	case NBL_HWMON_TEMP_CRIT:
		temp = NBL_LEONIS_TEMP_CRIT * 1000;
		break;
	case NBL_HWMON_TEMP_HIGHEST:
		temp = nbl_hw_rd32(phy_mgt, NBL_TOP_CTRL_TVSENSOR0);
		temp = (temp >> 16) * 1000;
		break;
	default:
		break;
	}
	return temp;
}

static struct nbl_phy_ped_tbl ped_tbl[NBL_FLOW_PED_RECORD_MAX] = {
	[NBL_FLOW_PED_UMAC_TYPE] = {.addr = NBL_UPED_TAB_REPLACE_ADDR,
				    .addr_len = NBL_UPED_TAB_REPLACE_DWLEN,},
	[NBL_FLOW_PED_DMAC_TYPE] = {.addr = NBL_DPED_TAB_REPLACE_ADDR,
				    .addr_len = NBL_DPED_TAB_REPLACE_DWLEN,},
	[NBL_FLOW_PED_UIP_TYPE] = {.addr = NBL_UPED_TAB_REPLACE_ADDR,
				    .addr_len = NBL_UPED_TAB_REPLACE_DWLEN,},
	[NBL_FLOW_PED_DIP_TYPE] = {.addr = NBL_DPED_TAB_REPLACE_ADDR,
				    .addr_len = NBL_DPED_TAB_REPLACE_DWLEN,},
	[NBL_FLOW_PED_UIP6_TYPE] = {.addr = NBL_UPED_TAB_REPLACE_ADDR,
				    .addr_len = NBL_UPED_TAB_REPLACE_DWLEN,},
	[NBL_FLOW_PED_DIP6_TYPE] = {.addr = NBL_DPED_TAB_REPLACE_ADDR,
				    .addr_len = NBL_DPED_TAB_REPLACE_DWLEN,},
};

static void nbl_phy_write_ped_tbl(void *priv, u8 *data, u16 idx, u32 ped_type)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	u64 reg;

#define NBL_PHY_PED_ADDR_REG(addr, idx, size) ((addr) + (idx) * (size) * 4)
	/* if ped type is ipv6 ,we need write ped_h */
	if (ped_type == NBL_FLOW_PED_UIP6_TYPE || ped_type == NBL_FLOW_PED_DIP6_TYPE) {
		/* write high 64-bit first then update data and idx for common write */
		data += ped_tbl[ped_type].addr_len * 4;
		reg =  NBL_PHY_PED_ADDR_REG(ped_tbl[ped_type].addr, idx,
					    ped_tbl[ped_type].addr_len);
		nbl_hw_write_regs(phy_mgt, reg, data, ped_tbl[ped_type].addr_len * 4);
		idx += NBL_TC_MAX_PED_H_IDX;
		data -= ped_tbl[ped_type].addr_len * 4;
	}

	reg = NBL_PHY_PED_ADDR_REG(ped_tbl[ped_type].addr, idx, ped_tbl[ped_type].addr_len);
	nbl_hw_write_regs(phy_mgt, reg, data, ped_tbl[ped_type].addr_len * 4);
}

static int nbl_phy_set_mtu(void *priv, u16 mtu_index, u16 mtu)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_ipro_mtu_sel ipro_mtu_sel = {0};

	nbl_hw_read_regs(phy_mgt, NBL_IPRO_MTU_SEL_REG(mtu_index / 2),
			 (u8 *)&ipro_mtu_sel, sizeof(ipro_mtu_sel));

	if (mtu_index % 2 == 0)
		ipro_mtu_sel.mtu_0 = mtu;
	else
		ipro_mtu_sel.mtu_1 = mtu;

	nbl_hw_write_regs(phy_mgt, NBL_IPRO_MTU_SEL_REG(mtu_index / 2),
			  (u8 *)&ipro_mtu_sel, sizeof(ipro_mtu_sel));

	return 0;
}

static u16 nbl_phy_get_mtu_index(void *priv, u16 vsi_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_ipro_dn_src_port_tbl ipro_dn_src_port_tbl = {0};

	nbl_hw_read_regs(phy_mgt, NBL_IPRO_DN_SRC_PORT_TBL_REG(vsi_id),
			 (u8 *)&ipro_dn_src_port_tbl, sizeof(ipro_dn_src_port_tbl));
	return ipro_dn_src_port_tbl.mtu_sel;
}

static void nbl_phy_cfg_vlan_filtering(void *priv, bool filter)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union pp1_kgen_key_prf_u kgen_key_prf = {.info = {0}};

	if (!filter) {
		nbl_hw_read_regs(phy_mgt, NBL_PP0_KGEN_KEY_PRF_REG(0), (u8 *)&kgen_key_prf,
				 sizeof(kgen_key_prf));
		kgen_key_prf.info.ext16_1_src = 0;
		nbl_hw_write_regs(phy_mgt, NBL_PP0_KGEN_KEY_PRF_REG(0), (u8 *)&kgen_key_prf,
				  sizeof(kgen_key_prf));

		nbl_hw_read_regs(phy_mgt, NBL_PP0_KGEN_KEY_PRF_REG(1), (u8 *)&kgen_key_prf,
				 sizeof(kgen_key_prf));
		kgen_key_prf.info.ext16_1_src = 0;
		nbl_hw_write_regs(phy_mgt, NBL_PP0_KGEN_KEY_PRF_REG(1), (u8 *)&kgen_key_prf,
				  sizeof(kgen_key_prf));

		nbl_hw_read_regs(phy_mgt, NBL_PP0_KGEN_KEY_PRF_REG(2), (u8 *)&kgen_key_prf,
				 sizeof(kgen_key_prf));
		kgen_key_prf.info.ext16_1_src = 0;
		nbl_hw_write_regs(phy_mgt, NBL_PP0_KGEN_KEY_PRF_REG(2), (u8 *)&kgen_key_prf,
				  sizeof(kgen_key_prf));
	} else {
		nbl_hw_read_regs(phy_mgt, NBL_PP0_KGEN_KEY_PRF_REG(0), (u8 *)&kgen_key_prf,
				 sizeof(kgen_key_prf));
		kgen_key_prf.info.ext16_1_src = 0xbe;
		nbl_hw_write_regs(phy_mgt, NBL_PP0_KGEN_KEY_PRF_REG(0), (u8 *)&kgen_key_prf,
				  sizeof(kgen_key_prf));

		nbl_hw_read_regs(phy_mgt, NBL_PP0_KGEN_KEY_PRF_REG(1), (u8 *)&kgen_key_prf,
				 sizeof(kgen_key_prf));
		kgen_key_prf.info.ext16_1_src = 0x98;
		nbl_hw_write_regs(phy_mgt, NBL_PP0_KGEN_KEY_PRF_REG(1), (u8 *)&kgen_key_prf,
				  sizeof(kgen_key_prf));

		nbl_hw_read_regs(phy_mgt, NBL_PP0_KGEN_KEY_PRF_REG(2), (u8 *)&kgen_key_prf,
				 sizeof(kgen_key_prf));
		kgen_key_prf.info.ext16_1_src = 0x98;
		nbl_hw_write_regs(phy_mgt, NBL_PP0_KGEN_KEY_PRF_REG(2), (u8 *)&kgen_key_prf,
				  sizeof(kgen_key_prf));
	}
}

static int nbl_phy_process_abnormal_queue(struct nbl_phy_mgt *phy_mgt, u16 queue_id, int type,
					  struct nbl_abnormal_details *detail)
{
	struct nbl_ipro_queue_tbl ipro_queue_tbl = {0};
	struct nbl_host_vnet_qinfo host_vnet_qinfo = {0};
	u32 qinfo_id = type == NBL_ABNORMAL_EVENT_DVN ? NBL_PAIR_ID_GET_TX(queue_id) :
							NBL_PAIR_ID_GET_RX(queue_id);

	if (type >= NBL_ABNORMAL_EVENT_MAX)
		return -EINVAL;

	nbl_hw_read_regs(phy_mgt, NBL_IPRO_QUEUE_TBL(queue_id),
			 (u8 *)&ipro_queue_tbl, sizeof(ipro_queue_tbl));

	detail->abnormal = true;
	detail->qid = queue_id;
	detail->vsi_id = ipro_queue_tbl.vsi_id;

	nbl_hw_read_regs(phy_mgt, NBL_PADPT_HOST_VNET_QINFO_REG_ARR(qinfo_id),
			 (u8 *)&host_vnet_qinfo, sizeof(host_vnet_qinfo));
	host_vnet_qinfo.valid = 1;
	nbl_hw_write_regs(phy_mgt, NBL_PADPT_HOST_VNET_QINFO_REG_ARR(qinfo_id),
			  (u8 *)&host_vnet_qinfo, sizeof(host_vnet_qinfo));

	return 0;
}

static int nbl_phy_process_abnormal_event(void *priv, struct nbl_abnormal_event_info *abnomal_info)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct device *dev = NBL_PHY_MGT_TO_DEV(phy_mgt);
	struct dvn_desc_dif_err_info desc_dif_err_info = {0};
	struct dvn_pkt_dif_err_info pkt_dif_err_info = {0};
	struct dvn_err_queue_id_get err_queue_id_get = {0};
	struct uvn_queue_err_info queue_err_info = {0};
	struct nbl_abnormal_details *detail;
	u32 int_status = 0, rdma_other_abn = 0, tlp_out_drop_cnt = 0;
	u32 desc_dif_err_cnt = 0, pkt_dif_err_cnt = 0;
	u32 queue_err_cnt;
	int ret = 0;

	nbl_hw_read_regs(phy_mgt, NBL_DVN_INT_STATUS, (u8 *)&int_status, sizeof(u32));
	if (int_status == U32_MAX)
		dev_info(dev, "dvn int_status:0x%x", int_status);

	if (int_status && int_status != U32_MAX) {
		if (int_status & BIT(NBL_DVN_INT_DESC_DIF_ERR)) {
			nbl_hw_read_regs(phy_mgt, NBL_DVN_DESC_DIF_ERR_CNT,
					 (u8 *)&desc_dif_err_cnt, sizeof(u32));
			nbl_hw_read_regs(phy_mgt, NBL_DVN_DESC_DIF_ERR_INFO,
					 (u8 *)&desc_dif_err_info,
					sizeof(struct dvn_desc_dif_err_info));
			dev_info(dev, "dvn int_status:0x%x, desc_dif_mf_cnt:%d, queue_id:%d\n",
				 int_status, desc_dif_err_cnt, desc_dif_err_info.queue_id);
			detail = &abnomal_info->details[NBL_ABNORMAL_EVENT_DVN];
			nbl_phy_process_abnormal_queue(phy_mgt, desc_dif_err_info.queue_id,
						       NBL_ABNORMAL_EVENT_DVN, detail);

			ret |= BIT(NBL_ABNORMAL_EVENT_DVN);
		}

		if (int_status & BIT(NBL_DVN_INT_PKT_DIF_ERR)) {
			nbl_hw_read_regs(phy_mgt, NBL_DVN_PKT_DIF_ERR_CNT,
					 (u8 *)&pkt_dif_err_cnt, sizeof(u32));
			nbl_hw_read_regs(phy_mgt, NBL_DVN_PKT_DIF_ERR_INFO,
					 (u8 *)&pkt_dif_err_info,
					 sizeof(struct dvn_pkt_dif_err_info));
			dev_info(dev, "dvn int_status:0x%x, pkt_dif_mf_cnt:%d, queue_id:%d\n",
				 int_status, pkt_dif_err_cnt, pkt_dif_err_info.queue_id);
		}

		/* clear dvn abnormal irq */
		nbl_hw_write_regs(phy_mgt, NBL_DVN_INT_STATUS,
				  (u8 *)&int_status, sizeof(int_status));

		/* enable new queue error irq */
		err_queue_id_get.desc_flag = 1;
		err_queue_id_get.pkt_flag = 1;
		nbl_hw_write_regs(phy_mgt, NBL_DVN_ERR_QUEUE_ID_GET,
				  (u8 *)&err_queue_id_get, sizeof(err_queue_id_get));
	}

	int_status = 0;
	nbl_hw_read_regs(phy_mgt, NBL_UVN_INT_STATUS, (u8 *)&int_status, sizeof(u32));
	if (int_status == U32_MAX)
		dev_info(dev, "uvn int_status:0x%x", int_status);
	if (int_status && int_status != U32_MAX) {
		nbl_hw_read_regs(phy_mgt, NBL_UVN_QUEUE_ERR_CNT,
				 (u8 *)&queue_err_cnt, sizeof(u32));
		nbl_hw_read_regs(phy_mgt, NBL_UVN_QUEUE_ERR_INFO,
				 (u8 *)&queue_err_info, sizeof(struct uvn_queue_err_info));
		dev_info(dev, "uvn int_status:%x queue_err_cnt: 0x%x qid 0x%x\n",
			 int_status, queue_err_cnt, queue_err_info.queue_id);

		if (int_status & BIT(NBL_UVN_INT_QUEUE_ERR)) {
			detail = &abnomal_info->details[NBL_ABNORMAL_EVENT_UVN];
			nbl_phy_process_abnormal_queue(phy_mgt, queue_err_info.queue_id,
						       NBL_ABNORMAL_EVENT_UVN, detail);

			ret |= BIT(NBL_ABNORMAL_EVENT_UVN);
		}

		/* clear uvn abnormal irq */
		nbl_hw_write_regs(phy_mgt, NBL_UVN_INT_STATUS,
				  (u8 *)&int_status, sizeof(int_status));
	}

	int_status = 0;
	nbl_hw_read_regs(phy_mgt, NBL_DSCH_INT_STATUS, (u8 *)&int_status, sizeof(u32));
	nbl_hw_read_regs(phy_mgt, NBL_DSCH_RDMA_OTHER_ABN, (u8 *)&rdma_other_abn, sizeof(u32));
	if (int_status == U32_MAX)
		dev_info(dev, "dsch int_status:0x%x", int_status);
	if (int_status && int_status != U32_MAX &&
	    (int_status != NBL_DSCH_RDMA_OTHER_ABN_BIT ||
	     rdma_other_abn != NBL_DSCH_RDMA_DPQM_DB_LOST)) {
		dev_info(dev, "dsch int_status:%x\n", int_status);

		/* clear dsch abnormal irq */
		nbl_hw_write_regs(phy_mgt, NBL_DSCH_INT_STATUS,
				  (u8 *)&int_status, sizeof(int_status));
	}

	int_status = 0;
	nbl_hw_read_regs(phy_mgt, NBL_PCOMPLETER_INT_STATUS, (u8 *)&int_status, sizeof(u32));
	if (int_status == U32_MAX)
		dev_info(dev, "pcomleter int_status:0x%x", int_status);
	if (int_status && int_status != U32_MAX) {
		nbl_hw_read_regs(phy_mgt, NBL_PCOMPLETER_TLP_OUT_DROP_CNT,
				 (u8 *)&tlp_out_drop_cnt, sizeof(u32));
		dev_info(dev, "pcomleter int_status:0x%x tlp_out_drop_cnt 0x%x\n",
			 int_status, tlp_out_drop_cnt);

		/* clear pcomleter abnormal irq */
		nbl_hw_write_regs(phy_mgt, NBL_PCOMPLETER_INT_STATUS,
				  (u8 *)&int_status, sizeof(int_status));
	}

	return ret;
}

static u32 nbl_phy_get_uvn_desc_entry_stats(void *priv)
{
	return nbl_hw_rd32(priv, NBL_UVN_DESC_RD_ENTRY);
}

static void nbl_phy_set_uvn_desc_wr_timeout(void *priv, u16 timeout)
{
	struct uvn_desc_wr_timeout wr_timeout = {0};

	wr_timeout.num = timeout;
	nbl_hw_write_regs(priv, NBL_UVN_DESC_WR_TIMEOUT, (u8 *)&wr_timeout, sizeof(wr_timeout));
}

static int nbl_phy_cfg_lag_hash_algorithm(void *priv, u16 eth_id, u16 lag_id,
					  enum netdev_lag_hash hash_type)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_ept_tbl ept_tbl = {0};
	u8 hw_hash_type = NBL_EPRO_LAG_ALG_L2_HASH;

	switch (hash_type) {
	case NETDEV_LAG_HASH_L23:
	case NETDEV_LAG_HASH_E23:
		hw_hash_type = NBL_EPRO_LAG_ALG_L23_HASH;
		break;
	case NETDEV_LAG_HASH_L34:
	case NETDEV_LAG_HASH_E34:
		hw_hash_type = NBL_EPRO_LAG_ALG_LINUX_L34_HASH;
		break;
	default:
		break;
	}

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_EPT_TABLE(lag_id + NBL_EPRO_EPT_LAG_OFFSET),
			 (u8 *)&ept_tbl, sizeof(struct nbl_epro_ept_tbl));
	ept_tbl.lag_alg_sel = hw_hash_type;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_EPT_TABLE(lag_id + NBL_EPRO_EPT_LAG_OFFSET),
			  (u8 *)&ept_tbl, sizeof(struct nbl_epro_ept_tbl));

	nbl_info(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_PHY,
		 "Nbl phy set lag hash type %d", hw_hash_type);
	return 0;
}

static int nbl_phy_cfg_lag_member_list(void *priv, struct nbl_lag_member_list_param *param)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_ept_tbl ept_tbl = {0};

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_EPT_TABLE(param->lag_id + NBL_EPRO_EPT_LAG_OFFSET),
			 (u8 *)&ept_tbl, sizeof(struct nbl_epro_ept_tbl));
	if (param->lag_num) {
		ept_tbl.fwd = 1;
		ept_tbl.vld = 1;
	} else {
		ept_tbl.fwd = 0;
		ept_tbl.vld = 0;
	}
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_EPT_TABLE(param->lag_id + NBL_EPRO_EPT_LAG_OFFSET),
			  (u8 *)&ept_tbl, sizeof(struct nbl_epro_ept_tbl));
	return 0;
}

static int nbl_phy_cfg_lag_member_fwd(void *priv, u16 eth_id, u16 lag_id, u8 fwd)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_ept_tbl ept_tbl = {0};
	struct nbl_ipro_upsport_tbl upsport = {0};
	u8 lag_btm = 0, lag_btm_new = 0;

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_EPT_TABLE(lag_id + NBL_EPRO_EPT_LAG_OFFSET),
			 (u8 *)&ept_tbl, sizeof(struct nbl_epro_ept_tbl));
	lag_btm = ept_tbl.lag_port_btm;
	lag_btm_new = fwd ? lag_btm | (1 << eth_id) : lag_btm & ~(1 << eth_id);

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_EPT_TABLE(lag_id + NBL_EPRO_EPT_LAG_OFFSET),
			 (u8 *)&ept_tbl, sizeof(struct nbl_epro_ept_tbl));
	ept_tbl.lag_port_btm = lag_btm_new;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_EPT_TABLE(lag_id + NBL_EPRO_EPT_LAG_OFFSET),
			  (u8 *)&ept_tbl, sizeof(struct nbl_epro_ept_tbl));

	nbl_hw_read_regs(phy_mgt, NBL_IPRO_UP_SPORT_TABLE(eth_id), (u8 *)&upsport, sizeof(upsport));

	upsport.lag_id = fwd ? lag_id : 0;
	upsport.lag_vld = fwd;

	nbl_hw_write_regs(phy_mgt, NBL_IPRO_UP_SPORT_TABLE(eth_id),
			  (u8 *)&upsport, sizeof(upsport));

	return 0;
}

static bool nbl_phy_get_lag_fwd(void *priv, u16 eth_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_ipro_upsport_tbl upsport = {0};

	nbl_hw_read_regs(phy_mgt, NBL_IPRO_UP_SPORT_TABLE(eth_id), (u8 *)&upsport, sizeof(upsport));
	return upsport.lag_vld;
}

static int nbl_phy_cfg_lag_member_up_attr(void *priv, u16 eth_id, u16 lag_id, bool enable)
{
	return 0;
}

static void nbl_phy_get_board_info(void *priv, struct nbl_board_port_info *board_info)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union nbl_fw_board_cfg_dw3 dw3 = {.info = {0}};

	nbl_hw_read_mbx_regs(phy_mgt, NBL_FW_BOARD_DW3_OFFSET, (u8 *)&dw3, sizeof(dw3));
	board_info->eth_num = dw3.info.port_num;
	board_info->eth_speed = dw3.info.port_speed;
	board_info->p4_version = dw3.info.p4_version;
	board_info->port_type = dw3.info.port_type;
}

static u32 nbl_phy_get_fw_eth_num(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union nbl_fw_board_cfg_dw3 dw3 = {.info = {0}};

	nbl_hw_read_mbx_regs(phy_mgt, NBL_FW_BOARD_DW3_OFFSET, (u8 *)&dw3, sizeof(dw3));
	return dw3.info.port_num;
}

static u32 nbl_phy_get_fw_eth_map(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union nbl_fw_board_cfg_dw6 dw6 = {.info = {0}};

	nbl_hw_read_mbx_regs(phy_mgt, NBL_FW_BOARD_DW6_OFFSET, (u8 *)&dw6, sizeof(dw6));
	return dw6.info.eth_bitmap;
}

static int nbl_phy_cfg_bond_shaping(void *priv, u8 eth_id, u8 speed, bool enable)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_shaping_dport dport = {0};
	struct nbl_shaping_dvn_dport dvn_dport = {0};
	struct nbl_shaping_rdma_dport rdma_dport = {0};
	u32 rate, dvn_rate, rdma_rate;

	if (!enable) {
		nbl_shaping_eth_init(phy_mgt, eth_id, speed);
		return 0;
	}

	if (speed == NBL_FW_PORT_SPEED_100G) {
		rate = NBL_SHAPING_DPORT_100G_RATE * 2;
		dvn_rate = NBL_SHAPING_DPORT_HALF_100G_RATE;
		rdma_rate = NBL_SHAPING_DPORT_100G_RATE;
	} else {
		rate = NBL_SHAPING_DPORT_25G_RATE * 2;
		dvn_rate = NBL_SHAPING_DPORT_HALF_25G_RATE;
		rdma_rate = NBL_SHAPING_DPORT_25G_RATE;
	}

	dport.cir = rate;
	dport.pir = rate;
	dport.depth = max(dport.cir * 2, NBL_LR_LEONIS_NET_BUCKET_DEPTH);
	dport.cbs = dport.depth;
	dport.pbs = dport.depth;
	dport.valid = 1;
	nbl_hw_write_regs(phy_mgt, NBL_SHAPING_DPORT_REG(eth_id), (u8 *)&dport, sizeof(dport));

	dvn_dport.cir = dvn_rate;
	dvn_dport.pir = dvn_rate;
	dvn_dport.depth = max(dvn_dport.cir * 2, NBL_LR_LEONIS_NET_BUCKET_DEPTH);
	dvn_dport.cbs = dvn_dport.depth;
	dvn_dport.pbs = dvn_dport.depth;
	dvn_dport.valid = 1;
	nbl_hw_write_regs(phy_mgt, NBL_SHAPING_DVN_DPORT_REG(eth_id),
			  (u8 *)&dvn_dport, sizeof(dvn_dport));

	rdma_dport.cir = rdma_rate;
	rdma_dport.pir = rdma_rate;
	rdma_dport.depth = max(rdma_dport.cir * 2, NBL_LR_LEONIS_NET_BUCKET_DEPTH);
	rdma_dport.cbs = rdma_dport.depth;
	rdma_dport.pbs = rdma_dport.depth;
	rdma_dport.valid = 1;
	nbl_hw_write_regs(phy_mgt, NBL_SHAPING_RDMA_DPORT_REG(eth_id),
			  (u8 *)&rdma_dport, sizeof(rdma_dport));

	return 0;
}

static void nbl_phy_set_bond_fc_th(struct nbl_phy_mgt *phy_mgt,
				   u8 main_eth_id, u8 other_eth_id, u8 speed)
{
	struct dstore_d_dport_fc_th fc_th = {0};

	nbl_hw_read_regs(phy_mgt, NBL_DSTORE_D_DPORT_FC_TH_REG(main_eth_id),
			 (u8 *)&fc_th, sizeof(fc_th));
	if (speed == NBL_FW_PORT_SPEED_100G) {
		fc_th.xoff_th = NBL_DSTORE_DROP_XOFF_TH_100G_BOND_MAIN;
		fc_th.xon_th = NBL_DSTORE_DROP_XON_TH_100G_BOND_MAIN;
	} else {
		fc_th.xoff_th = NBL_DSTORE_DROP_XOFF_TH_BOND_MAIN;
		fc_th.xon_th = NBL_DSTORE_DROP_XON_TH_BOND_MAIN;
	}
	nbl_hw_write_regs(phy_mgt, NBL_DSTORE_D_DPORT_FC_TH_REG(main_eth_id),
			  (u8 *)&fc_th, sizeof(fc_th));

	nbl_hw_read_regs(phy_mgt, NBL_DSTORE_D_DPORT_FC_TH_REG(other_eth_id),
			 (u8 *)&fc_th, sizeof(fc_th));
	if (speed == NBL_FW_PORT_SPEED_100G) {
		fc_th.xoff_th = NBL_DSTORE_DROP_XOFF_TH_100G_BOND_OTHER;
		fc_th.xon_th = NBL_DSTORE_DROP_XON_TH_100G_BOND_OTHER;
	} else {
		fc_th.xoff_th = NBL_DSTORE_DROP_XOFF_TH_BOND_OTHER;
		fc_th.xon_th = NBL_DSTORE_DROP_XON_TH_BOND_OTHER;
	}
	nbl_hw_write_regs(phy_mgt, NBL_DSTORE_D_DPORT_FC_TH_REG(other_eth_id),
			  (u8 *)&fc_th, sizeof(fc_th));
}

static void nbl_phy_remove_bond_fc_th(struct nbl_phy_mgt *phy_mgt,
				      u8 main_eth_id, u8 other_eth_id, u8 speed)
{
	struct dstore_d_dport_fc_th fc_th = {0};

	nbl_hw_read_regs(phy_mgt, NBL_DSTORE_D_DPORT_FC_TH_REG(main_eth_id),
			 (u8 *)&fc_th, sizeof(fc_th));
	if (speed == NBL_FW_PORT_SPEED_100G) {
		fc_th.xoff_th = NBL_DSTORE_DROP_XOFF_TH_100G;
		fc_th.xon_th = NBL_DSTORE_DROP_XON_TH_100G;
	} else {
		fc_th.xoff_th = NBL_DSTORE_DROP_XOFF_TH;
		fc_th.xon_th = NBL_DSTORE_DROP_XON_TH;
	}
	nbl_hw_write_regs(phy_mgt, NBL_DSTORE_D_DPORT_FC_TH_REG(main_eth_id),
			  (u8 *)&fc_th, sizeof(fc_th));

	nbl_hw_read_regs(phy_mgt, NBL_DSTORE_D_DPORT_FC_TH_REG(other_eth_id),
			 (u8 *)&fc_th, sizeof(fc_th));
	if (speed == NBL_FW_PORT_SPEED_100G) {
		fc_th.xoff_th = NBL_DSTORE_DROP_XOFF_TH_100G;
		fc_th.xon_th = NBL_DSTORE_DROP_XON_TH_100G;
	} else {
		fc_th.xoff_th = NBL_DSTORE_DROP_XOFF_TH;
		fc_th.xon_th = NBL_DSTORE_DROP_XON_TH;
	}
	nbl_hw_write_regs(phy_mgt, NBL_DSTORE_D_DPORT_FC_TH_REG(other_eth_id),
			  (u8 *)&fc_th, sizeof(fc_th));
}

static void nbl_phy_cfg_bgid_back_pressure(void *priv, u8 main_eth_id, u8 other_eth_id,
					   bool enable, u8 speed)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct dvn_back_pressure_mask mask = {0};

	nbl_hw_read_regs(phy_mgt, NBL_DVN_BACK_PRESSURE_MASK, (u8 *)&mask, sizeof(mask));
	nbl_phy_cfg_dvn_bp_mask(&mask, main_eth_id, enable);
	nbl_phy_cfg_dvn_bp_mask(&mask, other_eth_id, enable);
	nbl_hw_write_regs(phy_mgt, NBL_DVN_BACK_PRESSURE_MASK, (u8 *)&mask, sizeof(mask));

	if (enable)
		nbl_phy_set_bond_fc_th(phy_mgt, main_eth_id, other_eth_id, speed);
	else
		nbl_phy_remove_bond_fc_th(phy_mgt, main_eth_id, other_eth_id, speed);
}

static void nbl_phy_set_tc_kgen_cvlan_zero(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union pp1_kgen_key_prf_u kgen_key_prf = {.info = {0}};

	nbl_hw_read_regs(phy_mgt, NBL_PP1_KGEN_KEY_PRF_REG(2), (u8 *)&kgen_key_prf,
			 sizeof(kgen_key_prf));
	kgen_key_prf.info.ext16_2_src = 0x19;
	nbl_hw_write_regs(phy_mgt, NBL_PP1_KGEN_KEY_PRF_REG(2), (u8 *)&kgen_key_prf,
			  sizeof(kgen_key_prf));

	nbl_hw_read_regs(phy_mgt, NBL_PP1_KGEN_KEY_PRF_REG(3), (u8 *)&kgen_key_prf,
			 sizeof(kgen_key_prf));
	kgen_key_prf.info.ext16_2_src = 0x19;
	nbl_hw_write_regs(phy_mgt, NBL_PP1_KGEN_KEY_PRF_REG(3), (u8 *)&kgen_key_prf,
			  sizeof(kgen_key_prf));
}

static void nbl_phy_unset_tc_kgen_cvlan(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union pp1_kgen_key_prf_u kgen_key_prf = {.info = {0}};

	nbl_hw_read_regs(phy_mgt, NBL_PP1_KGEN_KEY_PRF_REG(2), (u8 *)&kgen_key_prf,
			 sizeof(kgen_key_prf));
	kgen_key_prf.info.ext16_2_src = 0x99;
	nbl_hw_write_regs(phy_mgt, NBL_PP1_KGEN_KEY_PRF_REG(2), (u8 *)&kgen_key_prf,
			  sizeof(kgen_key_prf));

	nbl_hw_read_regs(phy_mgt, NBL_PP1_KGEN_KEY_PRF_REG(3), (u8 *)&kgen_key_prf,
			 sizeof(kgen_key_prf));
	kgen_key_prf.info.ext16_2_src = 0x99;
	nbl_hw_write_regs(phy_mgt, NBL_PP1_KGEN_KEY_PRF_REG(3), (u8 *)&kgen_key_prf,
			  sizeof(kgen_key_prf));
}

static void nbl_phy_set_ped_tab_vsi_type(void *priv, u32 port_id, u16 eth_proto)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union dped_tab_vsi_type_u dped_vsi_type = {.info = {0}};
	union uped_tab_vsi_type_u uped_vsi_type = {.info = {0}};

	dped_vsi_type.info.sel = eth_proto;
	nbl_hw_write_regs(phy_mgt, NBL_DPED_TAB_VSI_TYPE_REG(port_id), (u8 *)&dped_vsi_type,
			  sizeof(dped_vsi_type));

	uped_vsi_type.info.sel = eth_proto;
	nbl_hw_write_regs(phy_mgt, NBL_UPED_TAB_VSI_TYPE_REG(port_id), (u8 *)&uped_vsi_type,
			  sizeof(uped_vsi_type));
}

static void nbl_phy_clear_acl(void *priv, u16 tcam_start_idx, u16 tcam_end_idx)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_acl_flow_tcam_clear(phy_mgt, NBL_ACL_FLUSH_FLOW_BTM, 0, NBL_ACL_TCAM_DEPTH);
}

static int nbl_phy_clr_fd_udf_l2(struct nbl_phy_mgt *phy_mgt)
{
	union upa_ext_conf_table_u clear = {{0}};
	u8 index[] = {0, 1, 2, 3, 4, 5};
	u8 entry[] = {2, 3, 12};
	u8 i = 0;
	u8 j = 0;

	for (i = 0; i < ARRAY_SIZE(index); i++)
		for (j = 0; j < ARRAY_SIZE(entry); j++)
			nbl_hw_write_regs(phy_mgt,
					  NBL_UPA_EXT_CONF_TABLE_REG(16 * index[i] + entry[j]),
					  (u8 *)&clear, sizeof(clear));

	return 0;
}

static int nbl_phy_clr_fd_udf_l3(struct nbl_phy_mgt *phy_mgt)
{
	union upa_ext_conf_table_u clear = {{0}};
	u8 index0[] = {8, 10};
	u8 entry0[] = {9, 10, 13};
	u8 index1[] = {9, 11, 12};
	u8 entry1[] = {9, 10, 11};
	u8 i = 0;
	u8 j = 0;

	for (i = 0; i < ARRAY_SIZE(index0); i++)
		for (j = 0; j < ARRAY_SIZE(entry0); j++)
			nbl_hw_write_regs(phy_mgt,
					  NBL_UPA_EXT_CONF_TABLE_REG(16 * index0[i] + entry0[j]),
					  (u8 *)&clear, sizeof(clear));

	for (i = 0; i < ARRAY_SIZE(index1); i++)
		for (j = 0; j < ARRAY_SIZE(entry1); j++)
			nbl_hw_write_regs(phy_mgt,
					  NBL_UPA_EXT_CONF_TABLE_REG(16 * index1[i] + entry1[j]),
					  (u8 *)&clear, sizeof(clear));

	return 0;
}

static int nbl_phy_clr_fd_udf_l4(struct nbl_phy_mgt *phy_mgt)
{
	union upa_ext_conf_table_u clear = {{0}};
	u8 index[] = {16, 17, 18, 19, 21, 22, 24};
	u8 entry[] = {2, 10, 11, 13};
	u8 entry1[] = {2, 10, 11, 7, 8, 9};  /* for index = 20 */
	u8 entry2[] = {2, 10, 11, 14, 15};  /* for index = 24 */
	u8 i = 0;
	u8 j = 0;

	for (i = 0; i < ARRAY_SIZE(index); i++)
		for (j = 0; j < ARRAY_SIZE(entry); j++)
			nbl_hw_write_regs(phy_mgt,
					  NBL_UPA_EXT_CONF_TABLE_REG(16 * index[i] + entry[j]),
					  (u8 *)&clear, sizeof(clear));

	i = 20;
	for (j = 0; j < ARRAY_SIZE(entry1); j++)
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * i + entry1[j]),
				  (u8 *)&clear, sizeof(clear));

	i = 25;
	for (j = 0; j < ARRAY_SIZE(entry2); j++)
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * i + entry2[j]),
				  (u8 *)&clear, sizeof(clear));

	return 0;
}

static int nbl_phy_clr_fd_udf(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_phy_clr_fd_udf_l2(phy_mgt);
	nbl_phy_clr_fd_udf_l3(phy_mgt);
	nbl_phy_clr_fd_udf_l4(phy_mgt);

	return 0;
}

static int nbl_phy_set_fd_udf_l2(struct nbl_phy_mgt *phy_mgt, u8 offset)
{
	union upa_ext_conf_table_u ext32 = {{0}};
	union upa_ext_conf_table_u ext32_0 = {{0}}; /* used for half length extraction */
	union upa_ext_conf_table_u ext32_1 = {{0}}; /* used for half length extraction */
	union upa_ext_conf_table_u ext8 = {{0}};
	u8 index = 0;  /* extractors profile index */
	u8 entry = 0;  /* extractor index */

	if (offset % 4 == 0) {
		/* use 4B extractor */
		ext32.info.dst_offset = 40;
		ext32.info.source_offset = offset / 4;
		ext32.info.mode_sel = 0;
		ext32.info.mode_start_off = 0;
		ext32.info.lx_sel = 1;
		ext32.info.op_en = 1;

		index = 0;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));
		index = 1;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));
		index = 2;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));
		index = 3;
		entry = 2;
		ext32.info.dst_offset = 44;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));
		index = 4;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));
		index = 5;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));
	} else if (offset % 4 == 2) {
		/* use 2 * 4B extractor, all use half length extraction mode */
		ext32_0.info.dst_offset = 40;
		ext32_0.info.source_offset = offset / 4;
		ext32_0.info.mode_sel = 1;
		ext32_0.info.mode_start_off = 0b10;  /* low-2-high */
		ext32_0.info.lx_sel = 1;
		ext32_0.info.op_en = 1;

		ext32_1.info.dst_offset = 40;
		ext32_1.info.source_offset = offset / 4 + 1;
		ext32_1.info.mode_sel = 1;
		ext32_1.info.mode_start_off = 0b01;    /* high-2-low */
		ext32_1.info.lx_sel = 1;
		ext32_1.info.op_en = 1;

		/* tunnel cases */
		index = 0;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32_0, sizeof(ext32_0));
		entry = 3;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32_1, sizeof(ext32_1));
		index = 1;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32_0, sizeof(ext32_0));
		entry = 3;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32_1, sizeof(ext32_1));
		index = 2;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32_0, sizeof(ext32_0));
		entry = 3;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32_1, sizeof(ext32_1));

		/* non-tunnel cases */
		ext32_0.info.dst_offset = 44;
		ext32_1.info.dst_offset = 44;
		index = 3;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32_0, sizeof(ext32_0));
		entry = 3;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32_1, sizeof(ext32_1));
		index = 4;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32_0, sizeof(ext32_0));
		entry = 3;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32_1, sizeof(ext32_1));
		index = 5;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32_0, sizeof(ext32_0));
		entry = 3;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32_1, sizeof(ext32_1));
	} else if (offset % 4 == 1 || offset % 4 == 3) {
		/* use 4B extractor & 1B extractor for overwritten */
		/* tunnel cases */
		ext32.info.dst_offset = 40;
		ext32.info.source_offset = (offset + 2) / 4;
		ext32.info.mode_sel = 0;
		ext32.info.mode_start_off = 0;
		ext32.info.lx_sel = 1;
		ext32.info.op_en = 1;

		ext8.info.dst_offset = (offset % 4 == 3) ? 43 : 40;
		ext8.info.source_offset = (offset % 4 == 3) ? offset : offset + 3;
		ext8.info.mode_sel = 0;
		ext8.info.mode_start_off = 0;
		ext8.info.lx_sel = 1;
		ext8.info.op_en = 1;

		index = 0;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));
		entry = 12;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext8, sizeof(ext8));
		index = 1;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));
		entry = 12;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext8, sizeof(ext8));
		index = 2;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));
		entry = 12;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext8, sizeof(ext8));

		/* non-tunnel cases */
		ext32.info.dst_offset = 44;
		ext8.info.dst_offset = (offset % 4 == 3) ? 47 : 44;
		index = 3;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));
		entry = 12;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext8, sizeof(ext8));
		index = 4;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));
		entry = 12;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext8, sizeof(ext8));
		index = 5;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));
		entry = 12;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext8, sizeof(ext8));
	}

	return 0;
}

static int nbl_phy_set_fd_udf_l3(struct nbl_phy_mgt *phy_mgt, u8 offset)
{
	union upa_ext_conf_table_u ext16_0 = {{0}};
	union upa_ext_conf_table_u ext16_1 = {{0}};
	union upa_ext_conf_table_u ext16_2 = {{0}};  /* used in half extraction mode */
	union upa_ext_conf_table_u ext8 = {{0}};  /* for overwritten 4B extraction */
	u8 index = 0;  /* extractors profile index */
	u8 entry = 0;  /* extractor index */

	if (offset % 4 == 0 || offset % 4 == 2) {
		/* tunnel cases */
		/* use 2 * 2B extractor */
		ext16_0.info.dst_offset = 40;
		ext16_0.info.source_offset = offset / 2;
		ext16_0.info.mode_sel = 0;
		ext16_0.info.mode_start_off = 0;
		ext16_0.info.lx_sel = 2;
		ext16_0.info.op_en = 1;
		ext16_1.info.dst_offset = 42;
		ext16_1.info.source_offset = offset / 2 + 1;
		ext16_1.info.mode_sel = 0;
		ext16_1.info.mode_start_off = 0;
		ext16_1.info.lx_sel = 2;
		ext16_1.info.op_en = 1;

		index = 8;
		entry = 9;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_0, sizeof(ext16_0));
		entry = 10;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_1, sizeof(ext16_1));

		index = 9;
		entry = 9;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_0, sizeof(ext16_0));
		entry = 10;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_1, sizeof(ext16_1));

		/* non-tunnel cases */
		ext16_0.info.dst_offset = 44;
		ext16_1.info.dst_offset = 46;
		index = 10;
		entry = 9;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_0, sizeof(ext16_0));
		entry = 10;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_1, sizeof(ext16_1));

		index = 11;
		entry = 9;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_0, sizeof(ext16_0));
		entry = 10;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_1, sizeof(ext16_1));

		index = 12;
		entry = 9;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_0, sizeof(ext16_0));
		entry = 10;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_1, sizeof(ext16_1));
	} else if (offset % 4 == 1) {
		/* tunnel cases */
		/* use 2*2B extractors & 1B extractor for overwritten */
		ext16_0.info.dst_offset = 42;
		ext16_0.info.source_offset = offset / 2 + 1;
		ext16_0.info.mode_sel = 0;
		ext16_0.info.mode_start_off = 0;
		ext16_0.info.lx_sel = 2;
		ext16_0.info.op_en = 1;

		/* half mode extractor */
		ext16_1.info.dst_offset = 40;
		ext16_1.info.source_offset = offset / 2;
		ext16_1.info.mode_sel = 1;
		ext16_1.info.mode_start_off = 0b11;  /* low-2-low */
		ext16_1.info.lx_sel = 2;
		ext16_1.info.op_en = 1;

		ext8.info.dst_offset = 40;
		ext8.info.source_offset = offset + 3;
		ext8.info.mode_sel = 0;
		ext8.info.mode_start_off = 0;
		ext8.info.lx_sel = 2;
		ext8.info.op_en = 1;

		/* half mode extractor */
		ext16_2.info.dst_offset = 40;
		ext16_2.info.source_offset = offset / 2 + 2;
		ext16_2.info.mode_sel = 1;
		ext16_2.info.mode_start_off = 0;  /* high-2-high */
		ext16_2.info.lx_sel = 2;
		ext16_2.info.op_en = 1;

		index = 8;
		entry = 9;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_0, sizeof(ext16_0));
		entry = 10;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_1, sizeof(ext16_1));
		entry = 13;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext8, sizeof(ext8));

		index = 9;
		entry = 9;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_0, sizeof(ext16_0));
		entry = 10;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_1, sizeof(ext16_1));
		entry = 11;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_2, sizeof(ext16_2));

		/* for non-tunnel cases */
		ext16_0.info.dst_offset = 46;
		ext16_1.info.dst_offset = 44;
		ext16_2.info.dst_offset = 44;
		ext8.info.dst_offset = 44;

		index = 10;
		entry = 9;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_0, sizeof(ext16_0));
		entry = 10;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_1, sizeof(ext16_1));
		entry = 13;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext8, sizeof(ext8));

		index = 11;
		entry = 9;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_0, sizeof(ext16_0));
		entry = 10;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_1, sizeof(ext16_1));
		entry = 11;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_2, sizeof(ext16_2));

		index = 12;
		entry = 9;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_0, sizeof(ext16_0));
		entry = 10;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_1, sizeof(ext16_1));
		entry = 11;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_2, sizeof(ext16_2));
	} else if (offset % 4 == 3) {
		/* tunnel cases */
		/* use 2*2B extractors & 1B extractor for overwritten */
		ext16_0.info.dst_offset = 40;
		ext16_0.info.source_offset = offset / 2 + 1;
		ext16_0.info.mode_sel = 0;
		ext16_0.info.mode_start_off = 0;
		ext16_0.info.lx_sel = 2;
		ext16_0.info.op_en = 1;

		ext16_1.info.dst_offset = 42;
		ext16_1.info.source_offset = offset / 2;
		ext16_1.info.mode_sel = 1;
		ext16_1.info.mode_start_off = 0b11;  /* low-2-low */
		ext16_1.info.lx_sel = 2;
		ext16_1.info.op_en = 1;

		ext8.info.dst_offset = 42;
		ext8.info.source_offset = offset + 3;
		ext8.info.mode_sel = 0;
		ext8.info.mode_start_off = 0;
		ext8.info.lx_sel = 2;
		ext8.info.op_en = 1;

		/* half mode extractor */
		ext16_2.info.dst_offset = 42;
		ext16_2.info.source_offset = offset / 2 + 2;
		ext16_2.info.mode_sel = 1;
		ext16_2.info.mode_start_off = 0b00;  /* high-2-high */
		ext16_2.info.lx_sel = 2;
		ext16_2.info.op_en = 1;

		index = 8;
		entry = 9;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_0, sizeof(ext16_0));
		entry = 10;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_1, sizeof(ext16_1));
		entry = 13;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext8, sizeof(ext8));

		index = 9;
		entry = 9;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_0, sizeof(ext16_0));
		entry = 10;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_1, sizeof(ext16_1));
		entry = 11;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_2, sizeof(ext16_2));

		/* for non-tunnel cases */
		ext16_0.info.dst_offset = 44;
		ext16_1.info.dst_offset = 46;
		ext16_2.info.dst_offset = 46;
		ext8.info.dst_offset = 46;

		index = 10;
		entry = 9;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_0, sizeof(ext16_0));
		entry = 10;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_1, sizeof(ext16_1));
		entry = 13;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext8, sizeof(ext8));

		index = 11;
		entry = 9;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_0, sizeof(ext16_0));
		entry = 10;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_1, sizeof(ext16_1));
		entry = 11;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_2, sizeof(ext16_2));

		index = 12;
		entry = 9;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_0, sizeof(ext16_0));
		entry = 10;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_1, sizeof(ext16_1));
		entry = 11;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_2, sizeof(ext16_2));
	}

	return 0;
}

static int nbl_phy_set_fd_udf_l4(struct nbl_phy_mgt *phy_mgt, u8 offset)
{
	union upa_ext_conf_table_u ext32 = {{0}};  /* entry = 2 */
	union upa_ext_conf_table_u ext16_0 = {{0}};  /* entry = 10 */
	union upa_ext_conf_table_u ext16_1 = {{0}};  /* entry = 11 */
	union upa_ext_conf_table_u ext16_2 = {{0}};  /* entry for 2B = 7 8 9 */
	union upa_ext_conf_table_u ext8 = {{0}};  /* entry = 12 */
	union upa_ext_conf_table_u ext4_0 = {{0}};  /* entry = 14 */
	union upa_ext_conf_table_u ext4_1 = {{0}};  /* entry = 15 */
	u8 index = 0;  /* extractors profile index */
	u8 entry = 0;  /* extractor index */

	if (offset % 4 == 0) {
		/* use 1 * 4B extractor */
		ext32.info.dst_offset = 40;
		ext32.info.source_offset = offset / 4 + 2;
		ext32.info.mode_sel = 0;
		ext32.info.mode_start_off = 0;
		ext32.info.lx_sel = 2;
		ext32.info.op_en = 1;

		/* tunnel vxlan & geneve case: plus UDP length 8B */
		index = 16;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));

		/* tunnel geneve-ovn case: plus UDP length 8B */
		index = 17;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));

		/* non-tunnel case */
		/* use 1 * 4B extractor */
		ext32.info.source_offset = offset / 4;
		ext32.info.dst_offset = 44;
		ext32.info.lx_sel = 3;
		index = 20;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));
		index = 21;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));
		index = 22;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));
		index = 24;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));
		index = 25;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));
	} else if (offset % 4 == 2) {
		/* use 2 * 2B extractors */
		ext16_0.info.dst_offset = 40;
		ext16_0.info.source_offset = offset / 2 + 4;
		ext16_0.info.mode_sel = 0;
		ext16_0.info.mode_start_off = 0;
		ext16_0.info.lx_sel = 2;
		ext16_0.info.op_en = 1;

		ext16_1.info.dst_offset = 42;
		ext16_1.info.source_offset = offset / 2 + 5;
		ext16_1.info.mode_sel = 0;
		ext16_1.info.mode_start_off = 0;
		ext16_1.info.lx_sel = 2;
		ext16_1.info.op_en = 1;

		/* tunnel vxlan & geneve case: plus UDP length 8B */
		index = 16;
		entry = 10;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_0, sizeof(ext16_0));
		entry = 11;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_1, sizeof(ext16_1));

		/* tunnel geneve-ovn case: plus UDP length 8B */
		index = 17;
		entry = 10;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_0, sizeof(ext16_0));
		entry = 11;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_1, sizeof(ext16_1));

		/* non-tunnel case */
		ext16_0.info.source_offset = offset / 2;
		ext16_1.info.source_offset = offset / 2 + 1;
		ext16_0.info.dst_offset = 44;
		ext16_1.info.dst_offset = 46;
		ext16_0.info.lx_sel = 3;
		ext16_1.info.lx_sel = 3;
		index = 20;
		entry = 10;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_0, sizeof(ext16_0));
		entry = 11;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_1, sizeof(ext16_1));

		index = 21;
		entry = 10;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_0, sizeof(ext16_0));
		entry = 11;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_1, sizeof(ext16_1));

		index = 22;
		entry = 10;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_0, sizeof(ext16_0));
		entry = 11;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_1, sizeof(ext16_1));

		index = 24;
		entry = 10;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_0, sizeof(ext16_0));
		entry = 11;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_1, sizeof(ext16_1));

		index = 25;
		entry = 10;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_0, sizeof(ext16_0));
		entry = 11;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_1, sizeof(ext16_1));
	} else if (offset % 4 == 1 || offset % 4 == 3) {
		/* use 4B extractor & 1B extractor for overwritten */
		ext32.info.dst_offset = 40;
		ext32.info.source_offset = 2 + (offset + 2) / 4;
		ext32.info.mode_sel = 0;
		ext32.info.mode_start_off = 0;
		ext32.info.lx_sel = 2;
		ext32.info.op_en = 1;

		ext8.info.dst_offset = (offset % 4 == 1) ? 40 : 43;
		ext8.info.source_offset = 8 + ((offset % 4 == 1) ? offset + 3 : offset);
		ext8.info.mode_sel = 0;
		ext8.info.mode_start_off = 0;
		ext8.info.lx_sel = 2;
		ext8.info.op_en = 1;

		/* tunnel vxlan & geneve case: plus UDP length 8B */
		index = 16;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));
		entry = 13;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext8, sizeof(ext8));

		/* tunnel geneve-ovn case: plus UDP length 8B */
		index = 17;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));
		entry = 13;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext8, sizeof(ext8));

		/* for non-tunnel cases */
		ext32.info.source_offset = (offset + 2) / 4;
		ext8.info.source_offset = (offset % 4 == 1) ? offset + 3 : offset;
		ext32.info.dst_offset = 44;
		ext8.info.dst_offset = (offset % 4 == 1) ? 44 : 47;
		ext32.info.lx_sel = 3;
		ext8.info.lx_sel = 3;

		index = 21;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));
		entry = 13;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext8, sizeof(ext8));

		index = 22;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));
		entry = 13;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext8, sizeof(ext8));

		index = 24;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));
		entry = 13;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext8, sizeof(ext8));

		/* non-tunnel for icmp: use 32bit & 4bit & 4bit extractors */
		/* currently disabled! */
		ext32.info.op_en = 0;
		ext4_0.info.dst_offset = (offset % 4 == 1) ? 44 : 47;
		ext4_0.info.source_offset = (offset % 4 == 1) ? offset + 3 : offset;
		ext4_0.info.mode_sel = 1;
		ext4_0.info.mode_start_off = 0b00;
		ext4_0.info.lx_sel = 3;
		ext4_0.info.op_en = 0;

		ext4_1.info.dst_offset = (offset % 4 == 1) ? 44 : 47;
		ext4_1.info.source_offset = (offset % 4 == 1) ? offset + 3 : offset;
		ext4_1.info.mode_sel = 1;
		ext4_1.info.mode_start_off = 0b11;
		ext4_1.info.lx_sel = 3;
		ext4_1.info.op_en = 0;

		index = 25;
		entry = 2;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext32, sizeof(ext32));
		entry = 14;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext4_0, sizeof(ext4_0));
		entry = 15;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext4_1, sizeof(ext4_1));

		/* non-tunnel for icmpv6: use 32bit & 4bit & 4bit extractors */
		/* currently disabled! */
		ext16_0.info.dst_offset = (offset % 4 == 1) ? 42 : 40;
		ext16_0.info.source_offset = offset / 2 + 1;
		ext16_0.info.mode_sel = 0;
		ext16_0.info.mode_start_off = 0;
		ext16_0.info.lx_sel = 3;
		ext16_0.info.op_en = 0;

		ext16_1.info.dst_offset = (offset % 4 == 1) ? 40 : 42;
		ext16_1.info.source_offset = offset / 2;
		ext16_1.info.mode_sel = 1;
		ext16_1.info.mode_start_off = 0b00;
		ext16_1.info.lx_sel = 3;
		ext16_1.info.op_en = 0;

		ext16_2.info.dst_offset = (offset % 4 == 1) ? 40 : 42;
		ext16_2.info.source_offset = offset / 2 + 2;
		ext16_2.info.mode_sel = 1;
		ext16_2.info.mode_start_off = 0b11;
		ext16_2.info.lx_sel = 3;
		ext16_2.info.op_en = 0;

		index = 20;
		entry = 7;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_0, sizeof(ext16_0));
		entry = 8;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_1, sizeof(ext16_1));
		entry = 9;
		nbl_hw_write_regs(phy_mgt, NBL_UPA_EXT_CONF_TABLE_REG(16 * index + entry),
				  (u8 *)&ext16_2, sizeof(ext16_2));
	}

	return 0;
}

static int nbl_phy_set_fd_udf(void *priv, u8 lxmode, u8 offset)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	int ret = 0;

	switch (lxmode) {
	case 0:
		ret = nbl_phy_set_fd_udf_l2(phy_mgt, offset);
		break;
	case 1:
		ret = nbl_phy_set_fd_udf_l3(phy_mgt, offset);
		break;
	case 2:
		ret = nbl_phy_set_fd_udf_l4(phy_mgt, offset);
		break;
	default:
		break;
	}

	return ret;
}

static int nbl_phy_set_fd_tcam_cfg_default(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union acl_tcam_cfg_u acl_key_cfg = {{0}};
	union acl_action_ram_cfg_u acl_action_cfg = {{0}};
	union acl_kgen_tcam_u acl_kgen_tcam = {{0}};
	int i;

	nbl_hw_read_regs(phy_mgt, NBL_ACL_ACTION_RAM_CFG_REG(NBL_FD_PROFILE_DEFAULT),
			 (u8 *)&acl_action_cfg, sizeof(acl_action_cfg));

	nbl_hw_read_regs(phy_mgt, NBL_ACL_TCAM_CFG_REG(NBL_FD_PROFILE_DEFAULT),
			 (u8 *)&acl_key_cfg, sizeof(acl_key_cfg));

	acl_key_cfg.info.startcompare0 = 1;
	acl_key_cfg.info.startset0 = 1;
	acl_key_cfg.info.key_id0 = 12;
	acl_key_cfg.info.tcam0_enable = 1;

	acl_key_cfg.info.startcompare1 = 0;
	acl_key_cfg.info.startset1 = 0;
	acl_key_cfg.info.key_id1 = 11;
	acl_key_cfg.info.tcam1_enable = 1;

	acl_key_cfg.info.startcompare2 = 0;
	acl_key_cfg.info.startset2 = 0;
	acl_key_cfg.info.key_id2 = 10;
	acl_key_cfg.info.tcam2_enable = 1;

	acl_key_cfg.info.startcompare3 = 0;
	acl_key_cfg.info.startset3 = 0;
	acl_key_cfg.info.key_id3 = 9;
	acl_key_cfg.info.tcam3_enable = 1;

	acl_key_cfg.info.startcompare4 = 0;
	acl_key_cfg.info.startset4 = 0;
	acl_key_cfg.info.key_id4 = 8;
	acl_key_cfg.info.tcam4_enable = 1;

	acl_key_cfg.info.startcompare5 = 0;
	acl_key_cfg.info.startset5 = 0;
	acl_key_cfg.info.key_id5 = 7;
	acl_key_cfg.info.tcam5_enable = 1;

	acl_key_cfg.info.startcompare6 = 0;
	acl_key_cfg.info.startset6 = 0;
	acl_key_cfg.info.key_id6 = 6;
	acl_key_cfg.info.tcam6_enable = 1;

	acl_key_cfg.info.startcompare7 = 0;
	acl_key_cfg.info.startset0 = 0;
	acl_key_cfg.info.key_id7 = 5;
	acl_key_cfg.info.tcam7_enable = 1;

	acl_key_cfg.info.startcompare8 = 0;
	acl_key_cfg.info.startset8 = 0;
	acl_key_cfg.info.key_id8 = 4;
	acl_key_cfg.info.tcam8_enable = 1;

	acl_key_cfg.info.startcompare9 = 0;
	acl_key_cfg.info.startset9 = 0;
	acl_key_cfg.info.key_id9 = 3;
	acl_key_cfg.info.tcam9_enable = 1;

	acl_key_cfg.info.startcompare10 = 0;
	acl_key_cfg.info.startset10 = 0;
	acl_key_cfg.info.key_id10 = 2;
	acl_key_cfg.info.tcam10_enable = 1;

	acl_key_cfg.info.startcompare11 = 0;
	acl_key_cfg.info.startset11 = 0;
	acl_key_cfg.info.key_id11 = 1;
	acl_key_cfg.info.tcam11_enable = 1;

	acl_key_cfg.info.startcompare12 = 0;
	acl_key_cfg.info.startset12 = 0;
	acl_key_cfg.info.key_id12 = 0;
	acl_key_cfg.info.tcam12_enable = 1;

	/* Although we don't use it, startcompare and startset must be 1, to indicate the end. */
	acl_key_cfg.info.startcompare13 = 1;
	acl_key_cfg.info.startset13 = 1;
	acl_key_cfg.info.key_id13 = 0;
	acl_key_cfg.info.tcam13_enable = 0;

	acl_key_cfg.info.startcompare14 = 0;
	acl_key_cfg.info.startset14 = 0;
	acl_key_cfg.info.key_id14 = 0;
	acl_key_cfg.info.tcam14_enable = 0;

	acl_key_cfg.info.startcompare15 = 0;
	acl_key_cfg.info.startset15 = 0;
	acl_key_cfg.info.key_id15 = 0;
	acl_key_cfg.info.tcam15_enable = 0;

	acl_action_cfg.info.action_ram0_enable = 1;
	acl_action_cfg.info.action_ram0_alloc_id = 12;

	nbl_hw_write_regs(phy_mgt, NBL_ACL_ACTION_RAM_CFG_REG(NBL_FD_PROFILE_DEFAULT),
			  (u8 *)&acl_action_cfg, sizeof(acl_action_cfg));
	nbl_hw_write_regs(phy_mgt, NBL_ACL_ACTION_RAM_CFG_REG(NBL_FD_PROFILE_DEFAULT + 1),
			  (u8 *)&acl_action_cfg, sizeof(acl_action_cfg));

	nbl_hw_write_regs(phy_mgt, NBL_ACL_TCAM_CFG_REG(NBL_FD_PROFILE_DEFAULT),
			  (u8 *)&acl_key_cfg, sizeof(acl_key_cfg));
	nbl_hw_write_regs(phy_mgt, NBL_ACL_TCAM_CFG_REG(NBL_FD_PROFILE_DEFAULT + 1),
			  (u8 *)&acl_key_cfg, sizeof(acl_key_cfg));

	for (i = NBL_FD_PROFILE_IPV4; i < NBL_FD_PROFILE_DEFAULT; i++) {
		nbl_hw_read_regs(phy_mgt, NBL_ACL_KGEN_TCAM_REG(i),
				 (u8 *)&acl_kgen_tcam, sizeof(acl_kgen_tcam));
		acl_kgen_tcam.info.valid_bit = 0;
		nbl_hw_write_regs(phy_mgt, NBL_ACL_KGEN_TCAM_REG(i),
				  (u8 *)&acl_kgen_tcam, sizeof(acl_kgen_tcam));
	}

	return 0;
}

static int nbl_phy_set_fd_tcam_cfg_lite(void *priv)
{
	return 0;
}

static int nbl_phy_set_fd_tcam_cfg_full(void *priv)
{
	return 0;
}

static int nbl_phy_set_fd_tcam_ram(void *priv, struct nbl_acl_tcam_param *data,
				   struct nbl_acl_tcam_param *mask, u16 ram_index, u32 depth_index)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	union acl_indirect_ctrl_u indirect_ctrl = {
		.info.cpu_acl_cfg_start = 1,
		.info.cpu_acl_cfg_rw = NBL_ACL_INDIRECT_ACCESS_WRITE,
	};
	union acl_valid_bit_u tcam_data_valid = {{0}};
	union acl_indirect_access_ack_u indirect_ack = {{0}};
	struct nbl_acl_tcam_common_data_u tcam_data = {{0}}, tcam_mask = {{0}};
	int i, rd_retry = NBL_ACL_RD_RETRY;

	for (i = 0; i < data->len / NBL_ACL_TCAM_KEY_LEN; i++) {
		memset(&tcam_data, 0, sizeof(tcam_data));
		memset(&tcam_mask, 0, sizeof(tcam_data));

		memcpy(&tcam_data.data, &data->info.key[i], sizeof(tcam_data.data));
		memcpy(&tcam_mask.data, &mask->info.key[i], sizeof(tcam_mask.data));

		*(u64 *)(&tcam_mask) = ~(*(u64 *)(&tcam_mask));

		nbl_tcam_truth_value_convert((u64 *)&tcam_data, (u64 *)&tcam_mask);

		indirect_ctrl.info.acc_btm |= 1 << (ram_index + i);
		tcam_data_valid.info.valid_bit |= 1 << (ram_index + i);

		nbl_debug(common, NBL_DEBUG_FLOW, "Set key tcam %d: 0x%02x%02x%02x%02x%02x",
			  ram_index + i, tcam_data.data[4], tcam_data.data[3], tcam_data.data[2],
			  tcam_data.data[1], tcam_data.data[0]);
		nbl_debug(common, NBL_DEBUG_FLOW, "Set key tcam mask %d: 0x%02x%02x%02x%02x%02x",
			  ram_index + i, tcam_mask.data[4], tcam_mask.data[3], tcam_mask.data[2],
			  tcam_mask.data[1], tcam_mask.data[0]);

		nbl_hw_write_regs(phy_mgt, NBL_ACL_TCAM_DATA_X(ram_index + i),
				  (u8 *)&tcam_data, sizeof(tcam_data));
		nbl_hw_write_regs(phy_mgt, NBL_ACL_TCAM_DATA_Y(ram_index + i),
				  (u8 *)&tcam_mask, sizeof(tcam_mask));
	}

	indirect_ctrl.info.tcam_addr = depth_index;

	nbl_debug(common, NBL_DEBUG_FLOW, "Set valid bit %08x", *(u32 *)&tcam_data_valid);
	nbl_debug(common, NBL_DEBUG_FLOW, "Set ctrl %08x", *(u32 *)&indirect_ctrl);

	nbl_hw_write_regs(phy_mgt, NBL_ACL_VALID_BIT_ADDR,
			  (u8 *)&tcam_data_valid, sizeof(tcam_data_valid));
	nbl_hw_write_regs(phy_mgt, NBL_ACL_INDIRECT_CTRL_ADDR,
			  (u8 *)&indirect_ctrl, sizeof(indirect_ctrl));
	do {
		nbl_hw_read_regs(phy_mgt, NBL_ACL_INDIRECT_ACCESS_ACK_ADDR,
				 (u8 *)&indirect_ack, sizeof(indirect_ack));
		if (!indirect_ack.info.done) {
			rd_retry--;
			usleep_range(NBL_ACL_RD_WAIT_100US, NBL_ACL_RD_WAIT_200US);
		} else {
			break;
		}
	} while (rd_retry);

	if (!indirect_ack.info.done) {
		nbl_err(common, NBL_DEBUG_FLOW, "Set fd acl tcam fail\n");
		return -EIO;
	}

	return 0;
}

static int nbl_phy_set_fd_action_ram(void *priv, u32 *action, u16 ram_index, u32 depth_index)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union acl_action_ram15_u acl_action_ram = {{0}};

	acl_action_ram.info.action0 = *action;

	nbl_hw_write_regs(phy_mgt, NBL_ACL_ACTION_RAM_TBL(ram_index, depth_index),
			  (u8 *)&acl_action_ram, sizeof(acl_action_ram));

	return 0;
}

static void nbl_phy_set_hw_status(void *priv, enum nbl_hw_status hw_status)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	phy_mgt->hw_status = hw_status;
}

static void nbl_phy_check_hw_status(void *priv)
{
	u32 val = U32_MAX;
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_hw_read_mbx_regs(priv, NBL_MAILBOX_QINFO_CFG_RX_TABLE_ADDR, (u8 *)&val, sizeof(val));
	if (val == U32_MAX)
		phy_mgt->hw_status = NBL_HW_PCIE_RESET_ERR;
}

static enum nbl_hw_status nbl_phy_get_hw_status(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	return phy_mgt->hw_status;
}

static u32 nbl_phy_get_perf_dump_length(void *priv)
{
	return sizeof(nbl_phy_dump_registers);
}

static u32 nbl_phy_get_perf_dump_data(void *priv, u8 *buffer, u32 length)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	u32 copy_len = min_t(u32, length, sizeof(nbl_phy_dump_registers));
	int i;

	for (i = 0; i < copy_len / 4; i++) {
		nbl_hw_read_regs(phy_mgt, nbl_phy_dump_registers[i], buffer, 4);
		buffer += 4;
	}

	return copy_len;
}

static int nbl_phy_get_mirror_table_id(void *priv, u16 vsi_id, int dir,
				       bool mirror_en, u8 *mt_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union ipro_dn_src_port_tbl_u ipro_dn_src_port_tbl = {{0}};
	union epro_vpt_u epro_vpt = {{0}};
	union epro_mt_u epro_mt = {{0}};
	int index = 0;

	if (dir == 0) {
		nbl_hw_read_regs(phy_mgt, NBL_IPRO_DN_SRC_PORT_TBL_REG(vsi_id),
				 (u8 *)&ipro_dn_src_port_tbl,
				 sizeof(ipro_dn_src_port_tbl));
		if (!mirror_en && !ipro_dn_src_port_tbl.info.mirror_en) {
			*mt_id = U8_MAX;
		} else if (!mirror_en && ipro_dn_src_port_tbl.info.mirror_en) {
			*mt_id = ipro_dn_src_port_tbl.info.mirror_id;
		} else if (mirror_en && ipro_dn_src_port_tbl.info.mirror_en) {
			*mt_id = ipro_dn_src_port_tbl.info.mirror_id;
		} else if (mirror_en && !ipro_dn_src_port_tbl.info.mirror_en) {
			for (; index < NBL_EPRO_MT_MAX; index++) {
				nbl_hw_read_regs(phy_mgt, NBL_EPRO_MT_REG(index),
						 (u8 *)&epro_mt, sizeof(epro_mt));
				if (epro_mt.info.vld == 0) {
					*mt_id = index;
					return 0;
				}
			}
			*mt_id = U8_MAX;
		}
	} else {
		nbl_hw_read_regs(phy_mgt, NBL_EPRO_VPT_REG(vsi_id),
				 (u8 *)&epro_vpt, sizeof(epro_vpt));
		if (!mirror_en && !epro_vpt.info.mirror_en) {
			*mt_id = U8_MAX;
		} else if (!mirror_en && epro_vpt.info.mirror_en) {
			*mt_id = epro_vpt.info.mirror_id;
		} else if (mirror_en && epro_vpt.info.mirror_en) {
			*mt_id = epro_vpt.info.mirror_id;
		} else if (mirror_en && !epro_vpt.info.mirror_en) {
			for (; index < NBL_EPRO_MT_MAX; index++) {
				nbl_hw_read_regs(phy_mgt, NBL_EPRO_MT_REG(index),
						 (u8 *)&epro_mt, sizeof(epro_mt));
				if (epro_mt.info.vld == 0) {
					*mt_id = index;
					return 0;
				}
			}
			*mt_id = U8_MAX;
		}
	}

	return 0;
}

static int nbl_phy_configure_mirror(void *priv, u16 vsi_id, bool mirror_en,
				    int dir, u8 mt_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union ipro_dn_src_port_tbl_u ipro_dn_src_port_tbl = {{0}};
	union epro_vpt_u epro_vpt = {{0}};

	if (!mirror_en) {
		if (dir == 0) {
			nbl_hw_read_regs(phy_mgt, NBL_IPRO_DN_SRC_PORT_TBL_REG(vsi_id),
					 (u8 *)&ipro_dn_src_port_tbl,
					 sizeof(ipro_dn_src_port_tbl));
			ipro_dn_src_port_tbl.info.mirror_en = 0;
			ipro_dn_src_port_tbl.info.mirror_pr = 0;
			ipro_dn_src_port_tbl.info.mirror_id = 0;
			nbl_hw_write_regs(phy_mgt, NBL_IPRO_DN_SRC_PORT_TBL_REG(vsi_id),
					  (u8 *)&ipro_dn_src_port_tbl,
					  sizeof(ipro_dn_src_port_tbl));
		} else {
			nbl_hw_read_regs(phy_mgt, NBL_EPRO_VPT_REG(vsi_id),
					 (u8 *)&epro_vpt, sizeof(epro_vpt));
			epro_vpt.info.mirror_en = 0;
			epro_vpt.info.mirror_id = 0;
			nbl_hw_write_regs(phy_mgt, NBL_EPRO_VPT_REG(vsi_id), (u8 *)&epro_vpt,
					  sizeof(epro_vpt));
		}
	} else {
		if (dir == 0) {
			nbl_hw_read_regs(phy_mgt, NBL_IPRO_DN_SRC_PORT_TBL_REG(vsi_id),
					 (u8 *)&ipro_dn_src_port_tbl, sizeof(ipro_dn_src_port_tbl));
			ipro_dn_src_port_tbl.info.mirror_en = mirror_en;
			ipro_dn_src_port_tbl.info.mirror_pr = 3;
			ipro_dn_src_port_tbl.info.mirror_id = mt_id;
			nbl_hw_write_regs(phy_mgt, NBL_IPRO_DN_SRC_PORT_TBL_REG(vsi_id),
					  (u8 *)&ipro_dn_src_port_tbl,
					  sizeof(ipro_dn_src_port_tbl));
		} else {
			nbl_hw_read_regs(phy_mgt, NBL_EPRO_VPT_REG(vsi_id),
					 (u8 *)&epro_vpt, sizeof(epro_vpt));
			epro_vpt.info.mirror_en = mirror_en;
			epro_vpt.info.mirror_id = mt_id;
			nbl_hw_write_regs(phy_mgt, NBL_EPRO_VPT_REG(vsi_id), (u8 *)&epro_vpt,
					  sizeof(epro_vpt));
		}
	}
	return 0;
}

static int nbl_phy_configure_mirror_table(void *priv, bool mirror_en,
					  u16 mirror_vsi_id, u16 mirror_queue_id, u8 mt_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union epro_mt_u epro_mt = {{0}};

	if (!mirror_en) {
		nbl_hw_read_regs(phy_mgt, NBL_EPRO_MT_REG(mt_id), (u8 *)&epro_mt,
				 sizeof(epro_mt));
		epro_mt.info.dport = 0;
		epro_mt.info.dqueue = 0;
		epro_mt.info.vld = mirror_en;
		nbl_hw_write_regs(phy_mgt, NBL_EPRO_MT_REG(mt_id), (u8 *)&epro_mt,
				  sizeof(epro_mt));
	} else {
		nbl_hw_read_regs(phy_mgt, NBL_EPRO_MT_REG(mt_id), (u8 *)&epro_mt,
				 sizeof(epro_mt));
		epro_mt.info.dport = mirror_vsi_id;
		epro_mt.info.dqueue = mirror_queue_id;
		epro_mt.info.vld = mirror_en;
		nbl_hw_write_regs(phy_mgt, NBL_EPRO_MT_REG(mt_id), (u8 *)&epro_mt,
				  sizeof(epro_mt));
	}

	return 0;
}

static int nbl_phy_clear_mirror_cfg(void *priv, u16 vsi_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union ipro_dn_src_port_tbl_u ipro_dn_src_port_tbl = {{0}};
	union epro_vpt_u epro_vpt = {{0}};
	union epro_mt_u epro_mt = {{0}};

	nbl_hw_read_regs(phy_mgt, NBL_IPRO_DN_SRC_PORT_TBL_REG(vsi_id),
			 (u8 *)&ipro_dn_src_port_tbl, sizeof(ipro_dn_src_port_tbl));
	if (ipro_dn_src_port_tbl.info.mirror_en) {
		nbl_hw_write_regs(phy_mgt, NBL_EPRO_MT_REG(ipro_dn_src_port_tbl.info.mirror_id),
				  (u8 *)&epro_mt, sizeof(epro_mt));
		ipro_dn_src_port_tbl.info.mirror_en = 0;
		ipro_dn_src_port_tbl.info.mirror_pr = 0;
		ipro_dn_src_port_tbl.info.mirror_id = 0;
		nbl_hw_write_regs(phy_mgt, NBL_IPRO_DN_SRC_PORT_TBL_REG(vsi_id),
				  (u8 *)&ipro_dn_src_port_tbl,
				  sizeof(ipro_dn_src_port_tbl));
	}

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_VPT_REG(vsi_id),
			 (u8 *)&epro_vpt, sizeof(epro_vpt));
	if (epro_vpt.info.mirror_en) {
		nbl_hw_write_regs(phy_mgt, NBL_EPRO_MT_REG(epro_vpt.info.mirror_id),
				  (u8 *)&epro_mt, sizeof(epro_mt));
		epro_vpt.info.mirror_en = 0;
		epro_vpt.info.mirror_id = 0;
		nbl_hw_write_regs(phy_mgt, NBL_EPRO_VPT_REG(vsi_id), (u8 *)&epro_vpt,
				  sizeof(epro_vpt));
	}

	return 0;
}

static int nbl_phy_get_dstat_vsi_stat(void *priv, u16 vsi_id, u64 *fwd_pkt, u64 *fwd_byte)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_dstat_vsi_stat dstat_vsi_stat = {0};

	nbl_hw_read_regs(phy_mgt, NBL_DSTAT_VSI_STAT(vsi_id),
			 (u8 *)&dstat_vsi_stat, sizeof(dstat_vsi_stat));

	*fwd_pkt = dstat_vsi_stat.fwd_pkt_cnt_low +
			((u64)(dstat_vsi_stat.fwd_pkt_cnt_high) << 32);
	*fwd_byte = dstat_vsi_stat.fwd_byte_cnt_low +
			((u64)(dstat_vsi_stat.fwd_byte_cnt_high) << 32);

	return 0;
}

static int nbl_phy_get_ustat_vsi_stat(void *priv, u16 vsi_id, u64 *fwd_pkt, u64 *fwd_byte)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_ustat_vsi_stat ustat_vsi_stat = {0};

	nbl_hw_read_regs(phy_mgt, NBL_USTAT_VSI_STAT(vsi_id),
			 (u8 *)&ustat_vsi_stat, sizeof(ustat_vsi_stat));

	*fwd_pkt = ustat_vsi_stat.fwd_pkt_cnt_low +
			((u64)(ustat_vsi_stat.fwd_pkt_cnt_high) << 32);
	*fwd_byte = ustat_vsi_stat.fwd_byte_cnt_low +
			((u64)(ustat_vsi_stat.fwd_byte_cnt_high) << 32);

	return 0;
}

static int nbl_phy_get_uvn_pkt_drop_stats(void *priv, u16 global_queue_id, u32 *uvn_stat_pkt_drop)
{
	*uvn_stat_pkt_drop = nbl_hw_rd32(priv, NBL_UVN_STATIS_PKT_DROP(global_queue_id));
	return 0;
}

static int nbl_phy_get_uvn_drop_queue_disable(void *priv, u32 *uvn_drop_queue_disable)
{
	*uvn_drop_queue_disable = nbl_hw_rd32(priv, NBL_UVN_DESC_RD_DROP_QUEUE_DISABLE);
	return 0;
}

static int nbl_phy_get_ustore_pkt_drop_stats(void *priv, u8 eth_id,
					     struct nbl_chan_param_drop_stats_resp *drop_stats)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	drop_stats->rx_drop_packets = nbl_hw_rd32(phy_mgt, NBL_USTORE_BUF_PORT_DROP_PKT(eth_id));
	drop_stats->rx_trun_packets = nbl_hw_rd32(phy_mgt, NBL_USTORE_BUF_PORT_TRUN_PKT(eth_id));

	return 0;
}

static u32 nbl_phy_get_fake_drop_stats(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union ipro_antifake_drop_u fake_drop;

	nbl_hw_read_regs(phy_mgt, NBL_IPRO_ANTIFAKE_DROP_ADDR,
			 (u8 *)&fake_drop, sizeof(fake_drop));
	return (u32)fake_drop.info.cnt;
}

static void nbl_phy_set_dpa_chksum_errcode(void *priv, bool flag)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_dpa_err_code errcode;

	nbl_hw_read_regs(phy_mgt, NBL_DPA_ERROR_CODE_ADDR,
			 (u8 *)&errcode, sizeof(errcode));
	/**
	 *  only drop rx csum err. Need disable dpa errcode, because ipro will drop tx && rx
	 * errcode packet at the same time.
	 */
	if (flag) {
		errcode.l4_csum_err = 0;
		errcode.l3_csum_err = 0;
	} else {
		errcode.l4_csum_err = NBL_ERROR_CODE_L4_CHKSUM;
		errcode.l3_csum_err = NBL_ERROR_CODE_L3_CHKSUM;
	}

	nbl_hw_write_regs(phy_mgt, NBL_DPA_ERROR_CODE_ADDR,
			  (u8 *)&errcode, sizeof(errcode));
}

static void nbl_phy_dump_abnormal_intr(void *priv, struct seq_file *m)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct dvn_desc_dif_err_info desc_dif_err_info = {0};
	struct dvn_pkt_dif_err_info pkt_dif_err_info = {0};
	struct uvn_queue_err_info queue_err_info = {0};
	u32 int_status = 0, rdma_other_abn = 0, tlp_out_drop_cnt = 0;
	u32 desc_dif_err_cnt = 0, pkt_dif_err_cnt = 0;
	u32 queue_err_cnt;
	/* dvn int info */
	nbl_hw_read_regs(phy_mgt, NBL_DVN_DESC_DIF_ERR_CNT,
			 (u8 *)&desc_dif_err_cnt, sizeof(u32));
	nbl_hw_read_regs(phy_mgt, NBL_DVN_DESC_DIF_ERR_INFO,
			 (u8 *)&desc_dif_err_info,
			 sizeof(struct dvn_desc_dif_err_info));
	seq_printf(m, "dvn_desc_dif_mf_cnt:%d, queue_id:%d\n",
		   desc_dif_err_cnt, desc_dif_err_info.queue_id);
	nbl_hw_read_regs(phy_mgt, NBL_DVN_PKT_DIF_ERR_CNT,
			 (u8 *)&pkt_dif_err_cnt, sizeof(u32));
	nbl_hw_read_regs(phy_mgt, NBL_DVN_PKT_DIF_ERR_INFO,
			 (u8 *)&pkt_dif_err_info,
			 sizeof(struct dvn_pkt_dif_err_info));
	seq_printf(m, "dvn_pkt_dif_mf_cnt:%d, queue_id:%d\n",
		   pkt_dif_err_cnt, pkt_dif_err_info.queue_id);

	nbl_hw_read_regs(phy_mgt, NBL_UVN_QUEUE_ERR_CNT,
			 (u8 *)&queue_err_cnt, sizeof(u32));
	nbl_hw_read_regs(phy_mgt, NBL_UVN_QUEUE_ERR_INFO,
			 (u8 *)&queue_err_info, sizeof(struct uvn_queue_err_info));
	seq_printf(m, "uvn_queue_err_cnt: 0x%x, qid:0x%x\n",
		   queue_err_cnt, queue_err_info.queue_id);

	nbl_hw_read_regs(phy_mgt, NBL_DSCH_RDMA_OTHER_ABN, (u8 *)&rdma_other_abn, sizeof(u32));
	nbl_hw_read_regs(phy_mgt, NBL_PCOMPLETER_TLP_OUT_DROP_CNT,
			 (u8 *)&tlp_out_drop_cnt, sizeof(u32));
	seq_printf(m, "dsch_rdma_other_abn:0x%x\n", rdma_other_abn);
	seq_printf(m, "pcompleter_tlp_out_drop_cnt:0x%x\n", tlp_out_drop_cnt);

	nbl_hw_read_regs(phy_mgt, NBL_HOST_PADPT_INT_STATUS, (u8 *)&int_status, sizeof(u32));
	seq_printf(m, "host_padpt_int_status:0x%x\n", int_status);
	nbl_hw_write_regs(phy_mgt, NBL_HOST_PADPT_INT_STATUS, (u8 *)&int_status,
			  sizeof(int_status));

	nbl_hw_read_regs(phy_mgt, NBL_MBX_INT_STATUS, (u8 *)&int_status, sizeof(u32));
	seq_printf(m, "mbx_int_status:0x%x\n", int_status);
	nbl_hw_write_regs(phy_mgt, NBL_MBX_INT_STATUS, (u8 *)&int_status, sizeof(int_status));
}

static void nbl_phy_get_qinfo_tx(void *priv, u16 func_id, dma_addr_t *dma_addr, u32 *size_bwind)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_mailbox_qinfo_cfg_table tx = {0};

	nbl_hw_read_regs(phy_mgt, NBL_MAILBOX_QINFO_CFG_TX_TABLE_REG(func_id),
			 (u8 *)&tx, sizeof(tx));

	*dma_addr = ((u64)tx.queue_base_addr_h << 32) | tx.queue_base_addr_l;
	*size_bwind = tx.queue_size_bwind;
}

static void nbl_phy_set_qinfo_tx(void *priv, u16 func_id, dma_addr_t dma_addr, u32 size_bwid)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_mailbox_qinfo_cfg_table tx = {0};

	if (dma_addr && size_bwid) {
		tx.queue_base_addr_l = (u32)(dma_addr & 0xFFFFFFFF);
		tx.queue_base_addr_h = upper_32_bits(dma_addr);
		tx.queue_size_bwind = (u32)size_bwid;
		tx.queue_rst = 0;
		tx.queue_en = 1;

		nbl_hw_write_regs(phy_mgt, NBL_MAILBOX_QINFO_CFG_TX_TABLE_REG(func_id),
				  (u8 *)&tx, sizeof(tx));
	}
}

static struct nbl_phy_ops phy_ops = {
	.init_chip_module		= nbl_phy_init_chip_module,
	.set_driver_status		= nbl_phy_set_driver_status,
	.set_qid_map_table		= nbl_phy_set_qid_map_table,
	.set_qid_map_ready		= nbl_phy_set_qid_map_ready,
	.cfg_ipro_queue_tbl		= nbl_phy_cfg_ipro_queue_tbl,
	.cfg_ipro_dn_sport_tbl		= nbl_phy_cfg_ipro_dn_sport_tbl,
	.set_vnet_queue_info		= nbl_phy_set_vnet_queue_info,
	.clear_vnet_queue_info		= nbl_phy_clear_vnet_queue_info,
	.cfg_vnet_qinfo_log		= nbl_phy_cfg_vnet_qinfo_log,
	.reset_dvn_cfg			= nbl_phy_reset_dvn_cfg,
	.reset_uvn_cfg			= nbl_phy_reset_uvn_cfg,
	.restore_dvn_context		= nbl_phy_restore_dvn_context,
	.restore_uvn_context		= nbl_phy_restore_uvn_context,
	.get_tx_queue_cfg		= nbl_phy_get_tx_queue_cfg,
	.get_rx_queue_cfg		= nbl_phy_get_rx_queue_cfg,
	.cfg_tx_queue			= nbl_phy_cfg_tx_queue,
	.cfg_rx_queue			= nbl_phy_cfg_rx_queue,
	.check_q2tc			= nbl_phy_check_q2tc,
	.cfg_q2tc_netid			= nbl_phy_cfg_q2tc_netid,
	.cfg_q2tc_tcid			= nbl_phy_cfg_q2tc_tcid,
	.set_tc_wgt			= nbl_phy_set_tc_wgt,
	.active_shaping			= nbl_phy_active_shaping,
	.deactive_shaping		= nbl_phy_deactive_shaping,
	.set_shaping			= nbl_phy_set_shaping,
	.set_ucar			= nbl_phy_set_ucar,
	.cfg_dsch_net_to_group		= nbl_phy_cfg_dsch_net_to_group,
	.init_epro_rss_key		= nbl_phy_init_epro_rss_key,
	.get_vsi_rss_key		= nbl_phy_get_epro_rss_key,
	.set_rss_key			= nbl_phy_set_epro_rss_key,
	.read_rss_indir			= nbl_phy_read_rss_indir,
	.get_rss_alg_sel		= nbl_phy_get_rss_alg_sel,
	.set_rss_alg_sel		= nbl_phy_set_rss_alg_sel,
	.init_epro_vpt_tbl		= nbl_phy_init_epro_vpt_tbl,
	.set_epro_rss_default		= nbl_phy_set_epro_rss_default,
	.cfg_epro_rss_ret		= nbl_phy_cfg_epro_rss_ret,
	.set_epro_rss_pt		= nbl_phy_set_epro_rss_pt,
	.clear_epro_rss_pt		= nbl_phy_clear_epro_rss_pt,
	.set_promisc_mode		= nbl_phy_set_promisc_mode,
	.disable_dvn			= nbl_phy_disable_dvn,
	.disable_uvn			= nbl_phy_disable_uvn,
	.lso_dsch_drain			= nbl_phy_lso_dsch_drain,
	.rsc_cache_drain		= nbl_phy_rsc_cache_drain,
	.save_dvn_ctx			= nbl_phy_save_dvn_ctx,
	.save_uvn_ctx			= nbl_phy_save_uvn_ctx,
	.get_rx_queue_err_stats		= nbl_phy_get_rx_queue_err_stats,
	.get_tx_queue_err_stats		= nbl_phy_get_tx_queue_err_stats,
	.setup_queue_switch		= nbl_phy_setup_queue_switch,
	.init_pfc			= nbl_phy_init_pfc,
	.cfg_phy_flow			= nbl_phy_cfg_phy_flow,
	.cfg_eth_port_priority_replace  = nbl_phy_cfg_eth_port_priority_replace,
	.get_chip_temperature		= nbl_phy_get_chip_temperature,
	.write_ped_tbl			= nbl_phy_write_ped_tbl,
	.set_vsi_mtu			= nbl_phy_set_vsi_mtu,
	.set_mtu			= nbl_phy_set_mtu,
	.get_mtu_index			= nbl_phy_get_mtu_index,
	.cfg_vlan_filtering		= nbl_phy_cfg_vlan_filtering,

	.configure_msix_map		= nbl_phy_configure_msix_map,
	.configure_msix_info		= nbl_phy_configure_msix_info,
	.get_coalesce			= nbl_phy_get_coalesce,
	.set_coalesce			= nbl_phy_set_coalesce,

	.set_ht				= nbl_phy_set_ht,
	.set_kt				= nbl_phy_set_kt,
	.search_key			= nbl_phy_search_key,
	.add_tcam			= nbl_phy_add_tcam,
	.del_tcam			= nbl_phy_del_tcam,
	.add_mcc			= nbl_phy_add_mcc,
	.del_mcc			= nbl_phy_del_mcc,
	.update_mcc_next_node		= nbl_phy_update_mcc_next_node,
	.add_tnl_encap			= nbl_phy_add_tnl_encap,
	.del_tnl_encap			= nbl_phy_del_tnl_encap,
	.set_decap_set			= nbl_phy_set_decap_set,
	.init_fem			= nbl_phy_init_fem,
	.init_acl			= nbl_phy_init_acl,
	.uninit_acl			= nbl_phy_uninit_acl,
	.set_upcall_rule		= nbl_phy_acl_set_upcall_rule,
	.unset_upcall_rule		= nbl_phy_acl_unset_upcall_rule,
	.set_shaping_dport_vld		= nbl_phy_set_shaping_dport_vld,
	.set_dport_fc_th_vld		= nbl_phy_set_dport_fc_th_vld,
	.init_acl_stats			= nbl_phy_init_acl_stats,

	.update_mailbox_queue_tail_ptr	= nbl_phy_update_mailbox_queue_tail_ptr,
	.config_mailbox_rxq		= nbl_phy_config_mailbox_rxq,
	.config_mailbox_txq		= nbl_phy_config_mailbox_txq,
	.config_mailbox_txq_rst		= nbl_phy_config_mailbox_txq_rst,
	.stop_mailbox_rxq		= nbl_phy_stop_mailbox_rxq,
	.stop_mailbox_txq		= nbl_phy_stop_mailbox_txq,
	.get_mailbox_rx_tail_ptr	= nbl_phy_get_mailbox_rx_tail_ptr,
	.check_mailbox_dma_err		= nbl_phy_check_mailbox_dma_err,
	.get_host_pf_mask		= nbl_phy_get_host_pf_mask,
	.get_host_pf_fid		= nbl_phy_get_host_pf_fid,
	.get_real_bus			= nbl_phy_get_real_bus,
	.get_pf_bar_addr		= nbl_phy_get_pf_bar_addr,
	.get_vf_bar_addr		= nbl_phy_get_vf_bar_addr,
	.cfg_mailbox_qinfo		= nbl_phy_cfg_mailbox_qinfo,
	.enable_mailbox_irq		= nbl_phy_enable_mailbox_irq,
	.enable_abnormal_irq		= nbl_phy_enable_abnormal_irq,
	.enable_msix_irq		= nbl_phy_enable_msix_irq,
	.get_msix_irq_enable_info	= nbl_phy_get_msix_irq_enable_info,

	.config_adminq_rxq		= nbl_phy_config_adminq_rxq,
	.config_adminq_txq		= nbl_phy_config_adminq_txq,
	.stop_adminq_rxq		= nbl_phy_stop_adminq_rxq,
	.stop_adminq_txq		= nbl_phy_stop_adminq_txq,
	.cfg_adminq_qinfo		= nbl_phy_cfg_adminq_qinfo,
	.enable_adminq_irq		= nbl_phy_enable_adminq_irq,
	.update_adminq_queue_tail_ptr	= nbl_phy_update_adminq_queue_tail_ptr,
	.get_adminq_rx_tail_ptr		= nbl_phy_get_adminq_rx_tail_ptr,
	.check_adminq_dma_err		= nbl_phy_check_adminq_dma_err,

	.update_tail_ptr		= nbl_phy_update_tail_ptr,
	.get_tail_ptr			= nbl_phy_get_tail_ptr,
	.set_spoof_check_addr		= nbl_phy_set_spoof_check_addr,
	.set_spoof_check_enable		= nbl_phy_set_spoof_check_enable,

	.get_hw_addr			= nbl_phy_get_hw_addr,

	.cfg_ktls_tx_keymat		= nbl_phy_cfg_ktls_tx_keymat,
	.cfg_ktls_rx_keymat		= nbl_phy_cfg_ktls_rx_keymat,
	.cfg_ktls_rx_record		= nbl_phy_cfg_ktls_rx_record,

	.cfg_dipsec_nat			= nbl_phy_cfg_dipsec_nat,
	.cfg_dipsec_sad_iv		= nbl_phy_cfg_dipsec_sad_iv,
	.cfg_dipsec_sad_esn		= nbl_phy_cfg_dipsec_sad_esn,
	.cfg_dipsec_sad_lifetime	= nbl_phy_cfg_dipsec_sad_lifetime,
	.cfg_dipsec_sad_crypto		= nbl_phy_cfg_dipsec_sad_crypto,
	.cfg_dipsec_sad_encap		= nbl_phy_cfg_dipsec_sad_encap,
	.read_dipsec_status		= nbl_phy_read_dipsec_status,
	.reset_dipsec_status		= nbl_phy_reset_dipsec_status,
	.read_dipsec_lft_info		= nbl_phy_read_dipsec_lft_info,
	.cfg_dipsec_lft_info		= nbl_phy_cfg_dipsec_lft_info,
	.init_dprbac			= nbl_phy_init_dprbac,
	.cfg_uipsec_nat			= nbl_phy_cfg_uipsec_nat,
	.cfg_uipsec_sad_esn		= nbl_phy_cfg_uipsec_sad_esn,
	.cfg_uipsec_sad_lifetime	= nbl_phy_cfg_uipsec_sad_lifetime,
	.cfg_uipsec_sad_crypto		= nbl_phy_cfg_uipsec_sad_crypto,
	.cfg_uipsec_sad_window		= nbl_phy_cfg_uipsec_sad_window,
	.cfg_uipsec_em_tcam		= nbl_phy_cfg_uipsec_em_tcam,
	.cfg_uipsec_em_ad		= nbl_phy_cfg_uipsec_em_ad,
	.clear_uipsec_tcam_ad		= nbl_phy_clear_uipsec_tcam_ad,
	.cfg_uipsec_em_ht		= nbl_phy_cfg_uipsec_em_ht,
	.cfg_uipsec_em_kt		= nbl_phy_cfg_uipsec_em_kt,
	.clear_uipsec_ht_kt		= nbl_phy_clear_uipsec_ht_kt,
	.read_uipsec_status		= nbl_phy_read_uipsec_status,
	.reset_uipsec_status		= nbl_phy_reset_uipsec_status,
	.read_uipsec_lft_info		= nbl_phy_read_uipsec_lft_info,
	.cfg_uipsec_lft_info		= nbl_phy_cfg_uipsec_lft_info,
	.init_uprbac			= nbl_phy_init_uprbac,

	.get_fw_ping			= nbl_phy_get_fw_ping,
	.set_fw_ping			= nbl_phy_set_fw_ping,
	.get_fw_pong			= nbl_phy_get_fw_pong,
	.set_fw_pong			= nbl_phy_set_fw_pong,

	.load_p4			= nbl_phy_load_p4,

	.configure_qos			= nbl_phy_configure_qos,
	.configure_rdma_bw		= nbl_phy_configure_rdma_bw,
	.set_pfc_buffer_size		= nbl_phy_set_pfc_buffer_size,
	.get_pfc_buffer_size		= nbl_phy_get_pfc_buffer_size,
	.set_rate_limit			= nbl_phy_set_rate_limit,

	.init_offload_fwd		= nbl_phy_init_offload_fwd,
	.init_cmdq			= nbl_phy_cmdq_init,
	.reset_cmdq			= nbl_phy_cmdq_reset,
	.destroy_cmdq			= nbl_phy_cmdq_destroy,
	.update_cmdq_tail		= nbl_phy_update_cmdq_tail,
	.init_flow			= nbl_phy_flow_init,
	.deinit_flow			= nbl_phy_flow_deinit,
	.get_flow_acl_switch		= nbl_phy_flow_get_acl_switch,
	.get_line_rate_info		= nbl_phy_get_line_rate_info,
	.offload_flow_rule		= nbl_phy_offload_flow_rule,
	.init_rep			= nbl_phy_init_rep,
	.clear_profile_table_action	= nbl_phy_clear_profile_table_action,
	.ipro_chksum_err_ctrl		= nbl_phy_ipro_chksum_err_ctrl,
	.set_dpa_chksum_errcode		= nbl_phy_set_dpa_chksum_errcode,
	.cfg_tnl_offload_profile	= nbl_phy_cfg_tnl_offload_profile,

	.init_vdpaq			= nbl_phy_init_vdpaq,
	.destroy_vdpaq			= nbl_phy_destroy_vdpaq,

	.get_reg_dump			= nbl_phy_get_reg_dump,
	.get_reg_dump_len		= nbl_phy_get_reg_dump_len,
	.process_abnormal_event		= nbl_phy_process_abnormal_event,
	.get_uvn_desc_entry_stats	= nbl_phy_get_uvn_desc_entry_stats,
	.set_uvn_desc_wr_timeout	= nbl_phy_set_uvn_desc_wr_timeout,

	.cfg_lag_hash_algorithm		= nbl_phy_cfg_lag_hash_algorithm,
	.cfg_lag_member_fwd		= nbl_phy_cfg_lag_member_fwd,
	.cfg_lag_member_list		= nbl_phy_cfg_lag_member_list,
	.cfg_lag_member_up_attr		= nbl_phy_cfg_lag_member_up_attr,
	.get_lag_fwd			= nbl_phy_get_lag_fwd,
	.cfg_bond_shaping		= nbl_phy_cfg_bond_shaping,
	.cfg_bgid_back_pressure		= nbl_phy_cfg_bgid_back_pressure,

	.get_fw_eth_num			= nbl_phy_get_fw_eth_num,
	.get_fw_eth_map			= nbl_phy_get_fw_eth_map,
	.get_board_info			= nbl_phy_get_board_info,
	.get_quirks			= nbl_phy_get_quirks,
	.set_tc_kgen_cvlan_zero		= nbl_phy_set_tc_kgen_cvlan_zero,
	.unset_tc_kgen_cvlan		= nbl_phy_unset_tc_kgen_cvlan,
	.set_ped_tab_vsi_type		= nbl_phy_set_ped_tab_vsi_type,

	.clear_acl			= nbl_phy_clear_acl,
	.set_fd_udf			= nbl_phy_set_fd_udf,
	.clear_fd_udf			= nbl_phy_clr_fd_udf,
	.set_fd_tcam_cfg_default	= nbl_phy_set_fd_tcam_cfg_default,
	.set_fd_tcam_cfg_lite		= nbl_phy_set_fd_tcam_cfg_lite,
	.set_fd_tcam_cfg_full		= nbl_phy_set_fd_tcam_cfg_full,
	.set_fd_tcam_ram		= nbl_phy_set_fd_tcam_ram,
	.set_fd_action_ram		= nbl_phy_set_fd_action_ram,
	.set_hw_status			= nbl_phy_set_hw_status,
	.check_hw_status		= nbl_phy_check_hw_status,
	.get_hw_status			= nbl_phy_get_hw_status,

	.get_perf_dump_length		= nbl_phy_get_perf_dump_length,
	.get_perf_dump_data		= nbl_phy_get_perf_dump_data,

	.get_mirror_table_id		= nbl_phy_get_mirror_table_id,
	.configure_mirror		= nbl_phy_configure_mirror,
	.configure_mirror_table		= nbl_phy_configure_mirror_table,
	.clear_mirror_cfg		= nbl_phy_clear_mirror_cfg,
	.set_dvn_desc_req		= nbl_dvn_descreq_num_cfg,
	.set_dvn_desc_req_dpdk		= nbl_dvn_descreq_num_dpdk_cfg,
	.get_dvn_desc_req		= nbl_dvn_descreq_num_get,
	.get_dstat_vsi_stat		= nbl_phy_get_dstat_vsi_stat,
	.get_ustat_vsi_stat		= nbl_phy_get_ustat_vsi_stat,
	.get_uvn_pkt_drop_stats		= nbl_phy_get_uvn_pkt_drop_stats,
	.get_ustore_pkt_drop_stats	= nbl_phy_get_ustore_pkt_drop_stats,
	.dump_abnormal_intr		= nbl_phy_dump_abnormal_intr,
	.get_fake_drop_stats		= nbl_phy_get_fake_drop_stats,
	.get_uvn_drop_queue_disable	= nbl_phy_get_uvn_drop_queue_disable,
	.set_qinfo_tx			= nbl_phy_set_qinfo_tx,
	.get_qinfo_tx			= nbl_phy_get_qinfo_tx,
	.cfg_eth_shaping		= nbl_phy_cfg_eth_shaping,
};

/* Structure starts here, adding an op should not modify anything below */
static int nbl_phy_setup_phy_mgt(struct nbl_common_info *common,
				 struct nbl_phy_mgt_leonis **phy_mgt_leonis)
{
	struct device *dev;

	dev = NBL_COMMON_TO_DEV(common);
	*phy_mgt_leonis = devm_kzalloc(dev, sizeof(struct nbl_phy_mgt_leonis), GFP_KERNEL);
	if (!*phy_mgt_leonis)
		return -ENOMEM;

	NBL_PHY_MGT_TO_COMMON(&(*phy_mgt_leonis)->phy_mgt) = common;

	return 0;
}

static void nbl_phy_remove_phy_mgt(struct nbl_common_info *common,
				   struct nbl_phy_mgt_leonis **phy_mgt_leonis)
{
	struct device *dev;

	dev = NBL_COMMON_TO_DEV(common);
	devm_kfree(dev, *phy_mgt_leonis);
	*phy_mgt_leonis = NULL;
}

static int nbl_phy_setup_ops(struct nbl_common_info *common, struct nbl_phy_ops_tbl **phy_ops_tbl,
			     struct nbl_phy_mgt_leonis *phy_mgt_leonis)
{
	struct device *dev;

	dev = NBL_COMMON_TO_DEV(common);
	*phy_ops_tbl = devm_kzalloc(dev, sizeof(struct nbl_phy_ops_tbl), GFP_KERNEL);
	if (!*phy_ops_tbl)
		return -ENOMEM;

	NBL_PHY_OPS_TBL_TO_OPS(*phy_ops_tbl) = &phy_ops;
	NBL_PHY_OPS_TBL_TO_PRIV(*phy_ops_tbl) = phy_mgt_leonis;

	return 0;
}

static void nbl_phy_remove_ops(struct nbl_common_info *common, struct nbl_phy_ops_tbl **phy_ops_tbl)
{
	struct device *dev;

	dev = NBL_COMMON_TO_DEV(common);
	devm_kfree(dev, *phy_ops_tbl);
	*phy_ops_tbl = NULL;
}

static void __maybe_unused nbl_phy_disable_rx_err_report(struct pci_dev *pdev)
{
#define  NBL_RX_ERR_BIT		0
#define  NBL_BAD_TLP_BIT	6
#define  NBL_BAD_DLLP_BIT	7
	u8 mask = 0;
	int aer_cap = 0;

	aer_cap = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_ERR);
	if (!aer_cap)
		return;

	pci_read_config_byte(pdev, aer_cap + PCI_ERR_COR_MASK, &mask);
	mask |= BIT(NBL_RX_ERR_BIT) | BIT(NBL_BAD_TLP_BIT) | BIT(NBL_BAD_DLLP_BIT);
	pci_write_config_byte(pdev, aer_cap + PCI_ERR_COR_MASK, mask);
}

int nbl_phy_init_leonis(void *p, struct nbl_init_param *param)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct nbl_common_info *common;
	struct pci_dev *pdev;
	struct nbl_phy_mgt_leonis **phy_mgt_leonis;
	struct nbl_phy_mgt *phy_mgt;
	struct nbl_phy_ops_tbl **phy_ops_tbl;
	int bar_mask;
	int ret = 0;

	common = NBL_ADAPTER_TO_COMMON(adapter);
	phy_mgt_leonis = (struct nbl_phy_mgt_leonis **)&NBL_ADAPTER_TO_PHY_MGT(adapter);
	phy_ops_tbl = &NBL_ADAPTER_TO_PHY_OPS_TBL(adapter);
	pdev = NBL_COMMON_TO_PDEV(common);

	ret = nbl_phy_setup_phy_mgt(common, phy_mgt_leonis);
	if (ret)
		goto setup_mgt_fail;

	phy_mgt = &(*phy_mgt_leonis)->phy_mgt;
	bar_mask = BIT(NBL_MEMORY_BAR) | BIT(NBL_MAILBOX_BAR);
	ret = pci_request_selected_regions(pdev, bar_mask, NBL_DRIVER_NAME);
	if (ret) {
		dev_err(&pdev->dev, "Request memory bar and mailbox bar failed, err = %d\n", ret);
		goto request_bar_region_fail;
	}

	if (param->caps.has_ctrl) {
		phy_mgt->hw_addr = ioremap(pci_resource_start(pdev, NBL_MEMORY_BAR),
					   pci_resource_len(pdev, NBL_MEMORY_BAR) -
					   NBL_RDMA_NOTIFY_OFF);
		if (!phy_mgt->hw_addr) {
			dev_err(&pdev->dev, "Memory bar ioremap failed\n");
			ret = -EIO;
			goto ioremap_err;
		}
		phy_mgt->hw_size = pci_resource_len(pdev, NBL_MEMORY_BAR) - NBL_RDMA_NOTIFY_OFF;
	} else {
		phy_mgt->hw_addr = ioremap(pci_resource_start(pdev, NBL_MEMORY_BAR),
					   NBL_RDMA_NOTIFY_OFF);
		if (!phy_mgt->hw_addr) {
			dev_err(&pdev->dev, "Memory bar ioremap failed\n");
			ret = -EIO;
			goto ioremap_err;
		}
		phy_mgt->hw_size = NBL_RDMA_NOTIFY_OFF;
	}

	phy_mgt->notify_offset = 0;
	phy_mgt->mailbox_bar_hw_addr = pci_ioremap_bar(pdev, NBL_MAILBOX_BAR);
	if (!phy_mgt->mailbox_bar_hw_addr) {
		dev_err(&pdev->dev, "Mailbox bar ioremap failed\n");
		ret = -EIO;
		goto mailbox_ioremap_err;
	}

	spin_lock_init(&phy_mgt->reg_lock);
	phy_mgt->should_lock = true;

	ret = nbl_phy_setup_ops(common, phy_ops_tbl, *phy_mgt_leonis);
	if (ret)
		goto setup_ops_fail;

	/* nbl_phy_disable_rx_err_report(pdev); */

	(*phy_mgt_leonis)->ro_enable = pcie_relaxed_ordering_enabled(pdev);

	return 0;

setup_ops_fail:
	iounmap(phy_mgt->mailbox_bar_hw_addr);
mailbox_ioremap_err:
	iounmap(phy_mgt->hw_addr);
ioremap_err:
	pci_release_selected_regions(pdev, bar_mask);
request_bar_region_fail:
	nbl_phy_remove_phy_mgt(common, phy_mgt_leonis);
setup_mgt_fail:
	return ret;
}

void nbl_phy_remove_leonis(void *p)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct nbl_common_info *common;
	struct nbl_phy_mgt_leonis **phy_mgt_leonis;
	struct nbl_phy_ops_tbl **phy_ops_tbl;
	struct pci_dev *pdev;
	u8 __iomem *hw_addr;
	u8 __iomem *mailbox_bar_hw_addr;
	int bar_mask = BIT(NBL_MEMORY_BAR) | BIT(NBL_MAILBOX_BAR);

	common = NBL_ADAPTER_TO_COMMON(adapter);
	phy_mgt_leonis = (struct nbl_phy_mgt_leonis **)&NBL_ADAPTER_TO_PHY_MGT(adapter);
	phy_ops_tbl = &NBL_ADAPTER_TO_PHY_OPS_TBL(adapter);
	pdev = NBL_COMMON_TO_PDEV(common);

	hw_addr = (*phy_mgt_leonis)->phy_mgt.hw_addr;
	mailbox_bar_hw_addr = (*phy_mgt_leonis)->phy_mgt.mailbox_bar_hw_addr;

	iounmap(mailbox_bar_hw_addr);
	iounmap(hw_addr);
	pci_release_selected_regions(pdev, bar_mask);
	nbl_phy_remove_phy_mgt(common, phy_mgt_leonis);

	nbl_phy_remove_ops(common, phy_ops_tbl);
}

