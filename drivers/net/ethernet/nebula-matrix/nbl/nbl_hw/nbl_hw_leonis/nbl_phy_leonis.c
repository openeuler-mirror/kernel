// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_phy_leonis.h"
#include "nbl_hw/nbl_p4_actions.h"

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

static int nbl_phy_fem_em0_pt_phy_l2_init(struct nbl_phy_mgt *phy_mgt, int pt_idx)
{
	union nbl_fem_profile_tbl_u em0_pt_tbl = {.info = {0}};

	em0_pt_tbl.info.pt_vld = 1;
	em0_pt_tbl.info.pt_hash_sel0 = 0;
	em0_pt_tbl.info.pt_hash_sel1 = 3;

	switch (pt_idx) {
	case NBL_EM0_PT_PHY_UP_TUNNEL_UNICAST_L2:
		em0_pt_tbl.info.pt_key_size = 0;
		em0_pt_tbl.info.pt_mask_bmap0 = NBL_EM_PT_MASK_LEN_0 >> 2;
		em0_pt_tbl.info.pt_mask_bmap1 = NBL_EM_PT_MASK1_LEN_12;
		em0_pt_tbl.info.pt_mask_bmap2 = NBL_EM_PT_MASK2_LEN_72;
		em0_pt_tbl.info.pt_act_num = 1;
	break;
	case NBL_EM0_PT_PHY_UP_UNICAST_L2:
		em0_pt_tbl.info.pt_key_size = 0;
		em0_pt_tbl.info.pt_mask_bmap0 = NBL_EM_PT_MASK_LEN_0 >> 2;
		em0_pt_tbl.info.pt_mask_bmap1 = NBL_EM_PT_MASK1_LEN_12;
		em0_pt_tbl.info.pt_mask_bmap2 = NBL_EM_PT_MASK2_LEN_72;
		em0_pt_tbl.info.pt_act_num = 1;
	break;
	case NBL_EM0_PT_PHY_DOWN_UNICAST_L2:
		em0_pt_tbl.info.pt_key_size = 0;
		em0_pt_tbl.info.pt_mask_bmap0 = NBL_EM_PT_MASK_LEN_0 >> 2;
		em0_pt_tbl.info.pt_mask_bmap1 = NBL_EM_PT_MASK1_LEN_4;
		em0_pt_tbl.info.pt_mask_bmap2 = NBL_EM_PT_MASK2_LEN_72;
		em0_pt_tbl.info.pt_act_num = 1;
	break;
	case NBL_EM0_PT_PHY_UP_MULTICAST_L2:
		em0_pt_tbl.info.pt_key_size = 0;
		em0_pt_tbl.info.pt_mask_bmap0 = NBL_EM_PT_MASK_LEN_0 >> 2;
		em0_pt_tbl.info.pt_mask_bmap1 = NBL_EM_PT_MASK1_LEN_0;
		em0_pt_tbl.info.pt_mask_bmap2 = NBL_EM_PT_MASK2_LEN_68;
		em0_pt_tbl.info.pt_act_num = 2;
	break;
	case NBL_EM0_PT_PHY_DOWN_MULTICAST_L2:
		em0_pt_tbl.info.pt_key_size = 0;
		em0_pt_tbl.info.pt_mask_bmap0 = NBL_EM_PT_MASK_LEN_0 >> 2;
		em0_pt_tbl.info.pt_mask_bmap1 = NBL_EM_PT_MASK1_LEN_0;
		em0_pt_tbl.info.pt_mask_bmap2 = NBL_EM_PT_MASK2_LEN_60;
		em0_pt_tbl.info.pt_act_num = 2;
	break;
	case NBL_EM0_PT_PHY_UP_MULTICAST_L3:
		em0_pt_tbl.info.pt_key_size = 0;
		em0_pt_tbl.info.pt_mask_bmap0 = NBL_EM_PT_MASK_LEN_0 >> 2;
		em0_pt_tbl.info.pt_mask_bmap1 = NBL_EM_PT_MASK1_LEN_0;
		em0_pt_tbl.info.pt_mask_bmap2 = NBL_EM_PT_MASK2_LEN_36;
		em0_pt_tbl.info.pt_act_num = 2;
	break;
	case NBL_EM0_PT_PHY_DOWN_MULTICAST_L3:
		em0_pt_tbl.info.pt_key_size = 0;
		em0_pt_tbl.info.pt_mask_bmap0 = NBL_EM_PT_MASK_LEN_0 >> 2;
		em0_pt_tbl.info.pt_mask_bmap1 = NBL_EM_PT_MASK1_LEN_0;
		em0_pt_tbl.info.pt_mask_bmap2 = NBL_EM_PT_MASK2_LEN_28;
		em0_pt_tbl.info.pt_act_num = 2;
	break;
	case NBL_EM0_PT_PHY_DPRBAC_IPV4:
		em0_pt_tbl.info.pt_key_size = 0;
		em0_pt_tbl.info.pt_mask_bmap0 = NBL_EM_PT_MASK_LEN_0 >> 2;
		em0_pt_tbl.info.pt_mask_bmap1 = NBL_EM_PT_MASK1_LEN_0;
		em0_pt_tbl.info.pt_mask_bmap2 = NBL_EM_PT_MASK2_SEC_72;
		em0_pt_tbl.info.pt_act_num = 1;
	break;
	case NBL_EM0_PT_PHY_DPRBAC_IPV6:
		em0_pt_tbl.info.pt_key_size = 1;
		em0_pt_tbl.info.pt_mask_bmap0 = NBL_EM_PT_MASK_LEN_64 >> 2;
		em0_pt_tbl.info.pt_mask_bmap1 = NBL_EM_PT_MASK1_LEN_128;
		em0_pt_tbl.info.pt_mask_bmap2 = NBL_EM_PT_MASK2_SEC_72;
		em0_pt_tbl.info.pt_act_num = 1;
	break;
	case NBL_EM0_PT_PHY_UL4S_IPV4:
		em0_pt_tbl.info.pt_key_size = 0;
		em0_pt_tbl.info.pt_mask_bmap0 = NBL_EM_PT_MASK_LEN_0 >> 2;
		em0_pt_tbl.info.pt_mask_bmap1 = NBL_EM_PT_MASK1_LEN_32;
		em0_pt_tbl.info.pt_mask_bmap2 = NBL_EM_PT_MASK2_SEC_72;
		em0_pt_tbl.info.pt_act_num = 1;
	break;
	case NBL_EM0_PT_PHY_UL4S_IPV6:
		em0_pt_tbl.info.pt_key_size = 1;
		em0_pt_tbl.info.pt_mask_bmap0 = NBL_EM_PT_MASK_LEN_0 >> 2;
		em0_pt_tbl.info.pt_mask_bmap1 = NBL_EM_PT_MASK1_LEN_112;
		em0_pt_tbl.info.pt_mask_bmap2 = NBL_EM_PT_MASK2_SEC_72;
		em0_pt_tbl.info.pt_act_num = 1;
	break;
	default:
		return -EOPNOTSUPP;
	}

	nbl_hw_write_regs(phy_mgt, NBL_FEM0_PROFILE_TABLE(pt_idx), em0_pt_tbl.data,
			  NBL_FEM_PROFILE_TBL_WIDTH);
	return 0;
}

static __maybe_unused int nbl_phy_fem_em0_pt_init(struct nbl_phy_mgt *phy_mgt)
{
	int i, ret = 0;

	for (i = NBL_EM0_PT_PHY_UP_TUNNEL_UNICAST_L2; i <= NBL_EM0_PT_PHY_UL4S_IPV6; i++) {
		ret = nbl_phy_fem_em0_pt_phy_l2_init(phy_mgt, i);
		if (ret)
			return ret;
	}

	return 0;
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

static int nbl_phy_add_mcc(void *priv, u16 mcc_id, u16 prev_mcc_id, u16 action)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_mcc_tbl node = {0};

	node.vld = 1;
	node.next_pntr = 0;
	node.tail = 1;
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

static void nbl_phy_del_mcc(void *priv, u16 mcc_id, u16 prev_mcc_id, u16 next_mcc_id)
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
	struct dped_l4_ck_cmd_40 l4_ck_cmd_40;

	/* DPED dped_l4_ck_cmd_40 for sctp */
	nbl_hw_read_regs(phy_mgt, NBL_DPED_L4_CK_CMD_40_ADDR,
			 (u8 *)&l4_ck_cmd_40, sizeof(l4_ck_cmd_40));
	l4_ck_cmd_40.en = 1;
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

static void nbl_shaping_eth_init(struct nbl_phy_mgt *phy_mgt, u8 eth_id, u8 speed)
{
	struct nbl_shaping_dport dport = {0};
	struct nbl_shaping_dvn_dport dvn_dport = {0};
	struct nbl_shaping_rdma_dport rdma_dport = {0};
	u32 rate, half_rate;

	if (speed == NBL_FW_PORT_SPEED_100G) {
		rate = NBL_SHAPING_DPORT_100G_RATE;
		half_rate = NBL_SHAPING_DPORT_HALF_100G_RATE;
	} else {
		rate = NBL_SHAPING_DPORT_25G_RATE;
		half_rate = NBL_SHAPING_DPORT_HALF_25G_RATE;
	}

	dport.cir = rate;
	dport.pir = rate;
	dport.depth = max(dport.cir * 2, NBL_LR_LEONIS_NET_BUCKET_DEPTH);
	dport.cbs = dport.depth;
	dport.pbs = dport.depth;
	dport.valid = 1;

	dvn_dport.cir = half_rate;
	dvn_dport.pir = rate;
	dvn_dport.depth = dport.depth;
	dvn_dport.cbs = dvn_dport.depth;
	dvn_dport.pbs = dvn_dport.depth;
	dvn_dport.valid = 1;

	rdma_dport.cir = half_rate;
	rdma_dport.pir = rate;
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

static int nbl_shaping_init(struct nbl_phy_mgt *phy_mgt, u8 speed)
{
	struct dsch_psha_en psha_en = {0};
	int i;

	for (i = 0; i < NBL_MAX_ETHERNET; i++)
		nbl_shaping_eth_init(phy_mgt, i, speed);

	psha_en.en = 0xF;
	nbl_hw_write_regs(phy_mgt, NBL_DSCH_PSHA_EN_ADDR, (u8 *)&psha_en, sizeof(psha_en));

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

static void nbl_dvn_descreq_num_cfg(struct nbl_phy_mgt *phy_mgt, u32 descreq_num)
{
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

static int nbl_dvn_init(struct nbl_phy_mgt *phy_mgt, u8 speed)
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

	if (speed == NBL_FW_PORT_SPEED_100G)
		nbl_dvn_descreq_num_cfg(phy_mgt, DEFAULT_DVN_100G_DESCREQ_NUMCFG);
	else
		nbl_dvn_descreq_num_cfg(phy_mgt, DEFAULT_DVN_DESCREQ_NUMCFG);

	return 0;
}

static int nbl_uvn_init(struct nbl_phy_mgt *phy_mgt)
{
	struct uvn_queue_err_mask mask = {0};
	struct uvn_dif_req_ro_flag flag = {0};
	u32 timeout = 119760; /* 200us 200000/1.67 */

	nbl_hw_wr32(phy_mgt, NBL_UVN_DESC_RD_WAIT, timeout);

	flag.avail_rd = 1;
	flag.desc_rd = 1;
	flag.pkt_wr = 1;
	flag.desc_wr = 0;
	nbl_hw_write_regs(phy_mgt, NBL_UVN_DIF_REQ_RO_FLAG, (u8 *)&flag, sizeof(flag));

	nbl_hw_read_regs(phy_mgt, NBL_UVN_QUEUE_ERR_MASK, (u8 *)&mask, sizeof(mask));
	mask.dif_err = 1;
	nbl_hw_write_regs(phy_mgt, NBL_UVN_QUEUE_ERR_MASK, (u8 *)&mask, sizeof(mask));

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
	nbl_dvn_init(phy_mgt, speed);
	nbl_uvn_init(phy_mgt);

	return 0;
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
	u32 fwd_type = 0;

	for (fwd_type = 0; fwd_type < NBL_FWD_TYPE_MAX; fwd_type++)
		nbl_epro_action_filter_cfg(phy_mgt, fwd_type,
					   &epro_action_filter_tbl_def[fwd_type]);

	return 0;
}

static int nbl_ppe_init(struct nbl_phy_mgt *phy_mgt)
{
	nbl_epro_init(phy_mgt);

	return 0;
}

static int nbl_host_padpt_init(struct nbl_phy_mgt *phy_mgt)
{
	/* padpt flow  control register */
	nbl_hw_wr32(phy_mgt, NBL_HOST_PADPT_HOST_CFG_FC_CPLH_UP, 0x10400);
	nbl_hw_wr32(phy_mgt, NBL_HOST_PADPT_HOST_CFG_FC_PD_DN, 0x10080);
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

static int nbl_phy_init_chip_module(void *priv, u8 eth_speed, u8 eth_num)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_info(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_PHY, "phy_chip_init");

	nbl_dp_init(phy_mgt, eth_speed, eth_num);
	nbl_ppe_init(phy_mgt);
	nbl_intf_init(phy_mgt);

	phy_mgt->version = nbl_hw_rd32(phy_mgt, 0x1300904);

	return 0;
}

static int nbl_phy_init_qid_map_table(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_virtio_qid_map_table info = {0}, info2 = {0};
	struct device *dev = NBL_PHY_MGT_TO_DEV(phy_mgt);
	u16 i, j, k;

	memset(&info, 0, sizeof(info));
	info.local_qid = 0x1FF;
	info.notify_addr_l = 0x7FFFFF;
	info.notify_addr_h = 0xFFFFFFFF;
	info.global_qid = 0xFFF;
	info.ctrlq_flag = 0X1;
	info.rsv1 = 0;
	info.rsv2 = 0;

	for (k = 0; k < 2; k++) { /* 0 is primary table , 1 is standby table */
		for (i = 0; i < NBL_QID_MAP_TABLE_ENTRIES; i++) {
			j = 0;
			do {
				nbl_hw_write_regs(phy_mgt, NBL_PCOMPLETER_QID_MAP_REG_ARR(k, i),
						  (u8 *)&info, sizeof(info));
				nbl_hw_read_regs(phy_mgt, NBL_PCOMPLETER_QID_MAP_REG_ARR(k, i),
						 (u8 *)&info2, sizeof(info2));
				if (likely(!memcmp(&info, &info2, sizeof(info))))
					break;
				j++;
			} while (j < NBL_REG_WRITE_MAX_TRY_TIMES);

			if (j == NBL_REG_WRITE_MAX_TRY_TIMES)
				dev_err(dev, "Write to qid map table entry %hu failed\n", i);
		}
	}

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
#ifndef NBL_DISABLE_RO
	if (phy_mgt_leonis->ro_enable) {
		host_vnet_qinfo.ido_en = 1;
		host_vnet_qinfo.rlo_en = 1;
	}
#endif

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
		cxt.dvn_l1_ring_read = last_avail_index & 0x7FFF;

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

static int nbl_phy_set_shaping(void *priv, u16 func_id, u64 total_tx_rate, u8 vld, bool active)
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
		shaping_net.depth = max(shaping_net.cir * 2, NBL_LR_LEONIS_NET_BUCKET_DEPTH);
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

static int nbl_phy_cfg_epro_rss_ret(void *priv, u32 index, u8 size_type, u32 q_num, u16 *queue_list)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct nbl_epro_rss_ret_tbl rss_ret = {0};
	u32 table_id, table_end, group_count, odd_num, queue_id = 0;

	group_count = NBL_EPRO_RSS_ENTRY_SIZE_UNIT << size_type;
	if (group_count > 256) {
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

	return 0;
}

static struct nbl_epro_rss_key epro_rss_key_def = {
	.key0		= 0x6d5a6d5a6d5a6d5a,
	.key1		= 0x6d5a6d5a6d5a6d5a,
	.key2		= 0x6d5a6d5a6d5a6d5a,
	.key3		= 0x6d5a6d5a6d5a6d5a,
	.key4		= 0x6d5a6d5a6d5a6d5a,
};

static int nbl_phy_init_epro_rss_key(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_hw_write_regs(phy_mgt, NBL_EPRO_RSS_KEY_REG,
			  (u8 *)&epro_rss_key_def, sizeof(epro_rss_key_def));

	return 0;
}

static void nbl_phy_read_epro_rss_key(void *priv, u8 *rss_key)
{
	nbl_hw_read_regs(priv, NBL_EPRO_RSS_KEY_REG,
			 rss_key, sizeof(struct nbl_epro_rss_key));
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

static void nbl_phy_get_rss_alg_sel(void *priv, u8 eth_id, u8 *alg_sel)
{
	struct nbl_epro_ept_tbl ept_tbl = {0};

	nbl_hw_read_regs(priv, NBL_EPRO_EPT_TABLE(eth_id), (u8 *)&ept_tbl,
			 sizeof(struct nbl_epro_ept_tbl));

	if (ept_tbl.lag_alg_sel == NBL_EPRO_RSS_ALG_TOEPLITZ_HASH)
		*alg_sel = ETH_RSS_HASH_TOP;
	else if (ept_tbl.lag_alg_sel == NBL_EPRO_RSS_ALG_CRC32)
		*alg_sel = ETH_RSS_HASH_CRC32;
}

static int nbl_phy_init_epro_vpt_tbl(void *priv, u16 vsi_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_vpt_tbl epro_vpt_tbl = {0};

	epro_vpt_tbl.vld = 1;
	epro_vpt_tbl.fwd = NBL_EPRO_FWD_TYPE_DROP;
	epro_vpt_tbl.rss_alg_sel = NBL_EPRO_RSS_ALG_TOEPLITZ_HASH;
	epro_vpt_tbl.rss_key_type_ipv4	= NBL_EPRO_RSS_KEY_TYPE_IPV4_L4;
	epro_vpt_tbl.rss_key_type_ipv6	= NBL_EPRO_RSS_KEY_TYPE_IPV6_L4;

	nbl_hw_write_regs(phy_mgt, NBL_EPRO_VPT_TABLE(vsi_id),
			  (u8 *)&epro_vpt_tbl,
			  sizeof(struct nbl_epro_vpt_tbl));

	return 0;
}

static int nbl_phy_set_epro_rss_default(void *priv, u16 vsi_id)
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

	epro_rss_pt_tbl.vld = 1;
	epro_rss_pt_tbl.entry_size = rss_entry_size;
	epro_rss_pt_tbl.offset0_vld = 1;
	epro_rss_pt_tbl.offset0 = rss_ret_base;
	epro_rss_pt_tbl.offset1_vld = 0;
	epro_rss_pt_tbl.offset1 = 0;

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

static bool nbl_phy_is_txq_drain_out(struct nbl_phy_mgt *phy_mgt, u16 queue_id)
{
	struct dsch_vn_tc_q_list_tbl tc_q_list = {0};

	nbl_hw_read_regs(phy_mgt, NBL_DSCH_VN_TC_Q_LIST_TABLE_REG_ARR(queue_id),
			 (u8 *)&tc_q_list, sizeof(tc_q_list));
	if (!tc_q_list.regi && !tc_q_list.fly && !tc_q_list.vld)
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

static int nbl_phy_lso_dsch_drain(void *priv, u16 queue_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	int i = 0;

	do {
		if (nbl_phy_is_txq_drain_out(phy_mgt, queue_id))
			break;

		usleep_range(10, 20);
	} while (++i < NBL_DRAIN_WAIT_TIMES);

	if (i >= NBL_DRAIN_WAIT_TIMES) {
		nbl_err(common, NBL_DEBUG_QUEUE, "nbl queue %u lso dsch drain\n", queue_id);
		return -1;
	}

	return 0;
}

static int nbl_phy_rsc_cache_drain(void *priv, u16 queue_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	int i = 0;

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

static u16 nbl_phy_save_dvn_ctx(void *priv, u16 queue_id, u16 split)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct dvn_queue_context dvn_ctx = {0};

	nbl_hw_read_regs(phy_mgt, NBL_DVN_QUEUE_CXT_TABLE_ARR(queue_id),
			 (u8 *)&dvn_ctx, sizeof(dvn_ctx));

	nbl_debug(common, NBL_DEBUG_QUEUE, "DVNQ save ctx: %d packed: %08x %08x split: %08x\n",
		  queue_id, dvn_ctx.dvn_ring_wrap_counter, dvn_ctx.dvn_l1_ring_read,
		  dvn_ctx.dvn_avail_ring_idx);

	if (split)
		return (dvn_ctx.dvn_avail_ring_idx);
	else
		return (dvn_ctx.dvn_l1_ring_read & 0x7FFF) | (dvn_ctx.dvn_ring_wrap_counter << 15);
}

static u16 nbl_phy_save_uvn_ctx(void *priv, u16 queue_id, u16 split, u16 queue_size)
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

static void nbl_phy_init_pfc(void *priv, u8 ether_ports)
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
	/* TX bp: dqm send received ETH RX Pause to DSCH */
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
	pri_mdf_en_cfg.eth0 = 1;
	pri_mdf_en_cfg.eth1 = 1;
	pri_mdf_en_cfg.eth2 = 1;
	pri_mdf_en_cfg.eth3 = 1;
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

	if (enable_msix) {
		abnormal_msix_vetcor.idx = global_vector_id;
		abnormal_msix_vetcor.vld = 1;
	}

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

static u8 *nbl_phy_get_msix_irq_enable_info(void *priv, u16 global_vector_id, u32 *irq_data)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_msix_notify msix_notify = { 0 };

	msix_notify.glb_msix_idx = global_vector_id;
	memcpy(irq_data, &msix_notify, sizeof(msix_notify));

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
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	/* local_qid 0 and 1 denote rx and tx queue respectively */
	u32 local_qid = txrx;
	u32 value = ((u32)tail_ptr << 16) | local_qid;

	/* wmb for doorbell */
	wmb();
	writel(value, phy_mgt->mailbox_bar_hw_addr + NBL_MAILBOX_NOTIFY_ADDR);
}

static void nbl_phy_config_mailbox_rxq(void *priv, dma_addr_t dma_addr, int size_bwid)
{
	struct nbl_mailbox_qinfo_cfg_table qinfo_cfg_rx_table = { 0 };

	qinfo_cfg_rx_table.queue_rst = 1;
	nbl_hw_write_mbx_regs(priv, NBL_MAILBOX_QINFO_CFG_RX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_rx_table, sizeof(qinfo_cfg_rx_table));

	qinfo_cfg_rx_table.queue_base_addr_l = (u32)(dma_addr & 0xFFFFFFFF);
	qinfo_cfg_rx_table.queue_base_addr_h = (u32)(dma_addr >> 32);
	qinfo_cfg_rx_table.queue_size_bwind = (u32)size_bwid;
	qinfo_cfg_rx_table.queue_rst = 0;
	qinfo_cfg_rx_table.queue_en = 1;
	nbl_hw_write_mbx_regs(priv, NBL_MAILBOX_QINFO_CFG_RX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_rx_table, sizeof(qinfo_cfg_rx_table));
}

static void nbl_phy_config_mailbox_txq(void *priv, dma_addr_t dma_addr, int size_bwid)
{
	struct nbl_mailbox_qinfo_cfg_table qinfo_cfg_tx_table = { 0 };

	qinfo_cfg_tx_table.queue_rst = 1;
	nbl_hw_write_mbx_regs(priv, NBL_MAILBOX_QINFO_CFG_TX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_tx_table, sizeof(qinfo_cfg_tx_table));

	qinfo_cfg_tx_table.queue_base_addr_l = (u32)(dma_addr & 0xFFFFFFFF);
	qinfo_cfg_tx_table.queue_base_addr_h = (u32)(dma_addr >> 32);
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
	return !!qinfo_cfg_tbl.dif_err;
}

static u32 nbl_phy_get_host_pf_mask(void *priv)
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
		upsport.set_dport.dport.up.upcall_flag = AUX_FWD_TYPE_NML_FWD;
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
	qinfo_cfg_rx_table.queue_base_addr_h = (u32)(dma_addr >> 32);
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
	qinfo_cfg_tx_table.queue_base_addr_h = (u32)(dma_addr >> 32);
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

	adminq_qinfo_map.bus = common->bus;
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
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	/* local_qid 0 and 1 denote rx and tx queue respectively */
	u32 local_qid = txrx;
	u32 value = ((u32)tail_ptr << 16) | local_qid;

	/* wmb for doorbell */
	wmb();
	writel(value, phy_mgt->mailbox_bar_hw_addr + NBL_ADMINQ_NOTIFY_ADDR);
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

static unsigned long nbl_phy_get_fw_ping(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	unsigned long ping;

	nbl_hw_read_mbx_regs(phy_mgt, NBL_FW_HEARTBEAT_PING, (u8 *)&ping, sizeof(ping));

	return ping;
}

static void nbl_phy_set_fw_ping(void *priv, unsigned long ping)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_hw_write_mbx_regs(phy_mgt, NBL_FW_HEARTBEAT_PING, (u8 *)&ping, sizeof(ping));
}

static unsigned long nbl_phy_get_fw_pong(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	unsigned long pong;

	nbl_hw_read_regs(phy_mgt, NBL_FW_HEARTBEAT_PONG, (u8 *)&pong, sizeof(pong));

	return pong;
}

static void nbl_phy_set_fw_pong(void *priv, unsigned long pong)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_hw_write_regs(phy_mgt, NBL_FW_HEARTBEAT_PONG, (u8 *)&pong, sizeof(pong));
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

static u32 nbl_phy_get_chip_temperature(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	return nbl_hw_rd32(phy_mgt, NBL_TOP_CTRL_TVSENSOR0);
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
	if (int_status) {
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
	if (int_status) {
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
	if (int_status && (int_status != NBL_DSCH_RDMA_OTHER_ABN_BIT ||
			   rdma_other_abn != NBL_DSCH_RDMA_DPQM_DB_LOST)) {
		dev_info(dev, "dsch int_status:%x\n", int_status);

		/* clear dsch abnormal irq */
		nbl_hw_write_regs(phy_mgt, NBL_DSCH_INT_STATUS,
				  (u8 *)&int_status, sizeof(int_status));
	}

	int_status = 0;
	nbl_hw_read_regs(phy_mgt, NBL_PCOMPLETER_INT_STATUS, (u8 *)&int_status, sizeof(u32));
	if (int_status) {
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

static void nbl_phy_get_board_info(void *priv, struct nbl_board_port_info *board_info)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union nbl_fw_board_cfg_dw3 dw3 = {.info = {0}};

	nbl_hw_read_mbx_regs(phy_mgt, NBL_FW_BOARD_DW3_OFFSET, (u8 *)&dw3, sizeof(dw3));
	board_info->eth_num = dw3.info.port_num;
	board_info->eth_speed = dw3.info.port_speed;
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

static struct nbl_phy_ops phy_ops = {
	.init_chip_module		= nbl_phy_init_chip_module,
	.init_qid_map_table		= nbl_phy_init_qid_map_table,
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
	.cfg_dsch_net_to_group		= nbl_phy_cfg_dsch_net_to_group,
	.init_epro_rss_key		= nbl_phy_init_epro_rss_key,
	.read_rss_key			= nbl_phy_read_epro_rss_key,
	.read_rss_indir			= nbl_phy_read_rss_indir,
	.get_rss_alg_sel		= nbl_phy_get_rss_alg_sel,
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
	.get_chip_temperature		= nbl_phy_get_chip_temperature,

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
	.init_fem			= nbl_phy_init_fem,

	.update_mailbox_queue_tail_ptr	= nbl_phy_update_mailbox_queue_tail_ptr,
	.config_mailbox_rxq		= nbl_phy_config_mailbox_rxq,
	.config_mailbox_txq		= nbl_phy_config_mailbox_txq,
	.stop_mailbox_rxq		= nbl_phy_stop_mailbox_rxq,
	.stop_mailbox_txq		= nbl_phy_stop_mailbox_txq,
	.get_mailbox_rx_tail_ptr	= nbl_phy_get_mailbox_rx_tail_ptr,
	.check_mailbox_dma_err		= nbl_phy_check_mailbox_dma_err,
	.get_host_pf_mask		= nbl_phy_get_host_pf_mask,
	.get_host_pf_fid		= nbl_phy_get_host_pf_fid,
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

	.get_fw_ping			= nbl_phy_get_fw_ping,
	.set_fw_ping			= nbl_phy_set_fw_ping,
	.get_fw_pong			= nbl_phy_get_fw_pong,
	.set_fw_pong			= nbl_phy_set_fw_pong,

	.get_reg_dump			= nbl_phy_get_reg_dump,
	.get_reg_dump_len		= nbl_phy_get_reg_dump_len,
	.process_abnormal_event		= nbl_phy_process_abnormal_event,
	.get_uvn_desc_entry_stats	= nbl_phy_get_uvn_desc_entry_stats,
	.set_uvn_desc_wr_timeout	= nbl_phy_set_uvn_desc_wr_timeout,

	.get_fw_eth_num			= nbl_phy_get_fw_eth_num,
	.get_fw_eth_map			= nbl_phy_get_fw_eth_map,
	.get_board_info			= nbl_phy_get_board_info,
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

static void nbl_phy_disable_rx_err_report(struct pci_dev *pdev)
{
#define  NBL_RX_ERR_BIT		0
#define  NBL_BAD_TLP_BIT	6
#define  NBL_BAD_DLLP_BIT	7
	u8 mask = 0;

	if (!pdev->aer_cap)
		return;

	pci_read_config_byte(pdev, pdev->aer_cap + PCI_ERR_COR_MASK, &mask);
	mask |= BIT(NBL_RX_ERR_BIT) | BIT(NBL_BAD_TLP_BIT) | BIT(NBL_BAD_DLLP_BIT);
	pci_write_config_byte(pdev, pdev->aer_cap + PCI_ERR_COR_MASK, mask);
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

	if (param->caps.has_ctrl || param->caps.has_factory_ctrl) {
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

	nbl_phy_disable_rx_err_report(pdev);

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
