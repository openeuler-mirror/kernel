// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2022, nebula-matrix Limited */

#include <linux/debugfs.h>

#include "grc.h"
#include "main.h"
#include "lag.h"
#include "dbgfs.h"

#define NBL_RDMA_QOS_DENTRY_LEN 256
#define NBL_RDMA_QOS_CFG_DEFAULT_DENTRY "/etc/nebulamatrix/rdma/qos_params/."
#define NBL_RDMA_QOS_CFG_DEV_DEFAULT_DENTRY                                    \
	"/etc/nebulamatrix/rdma/%s/qos_params/."

/*
 * ATTENTION: DON'T CHANGE ARRARY ORDER!
 */
const char *const nbl_dbg_qos_name[] = {
	/* global */
	"save",
	"tc2pri",
	"sq_pri_map",
	"raq_pri_map",
	"pri_imap",
	"pfc_imap",
	"db_to_csch_en",
	"sw_db_csch_th",
	"csch_qlen_th",
	"poll_wgt",
	/* function base */
	"sp_wrr",
	"tc_wgt",
	"set_pfc",
	"trust_dscp_en",
	"pfc_buf",
	"dscp_to_pri",
	"8021p_to_pri",
	/* global */
	"ets_en"
};

static void set_pri(union pkt_cos_map_table *table, u32 pri, u32 value)
{
	value &= 0x7;
	table->data[0] = (table->data[0] & ~(0x7 << (pri * 4))) | (value << (pri * 4));
}

static void set_pri_v2(union store_tbl_pri_conf *table, u32 pri, u32 value)
{
	value &= 0x7;
	table->data[0] = (table->data[0] & ~(0x7 << (pri * 4))) | (value << (pri * 4));
}

static u32 get_pri(union pkt_cos_map_table *table, u32 pri)
{
	return (table->data[0] >> (pri * 4)) & 0x7;
}

static u32 get_pri_v2(union store_tbl_pri_conf *table, u32 pri)
{
	return (table->data[0] >> (pri * 4)) & 0x7;
}

static int nbl_update_p2s_cfg_v2(struct nbl_device *dev, const u32 *p2s_map)
{
	struct nbl_pci_f *rf = dev->rf;
	struct nbl_core_export *core_info = rf->cdev;
	int ret = 0, i;

	if (!core_info->is_lag) {
		ret = nbl_grc_write_reg(
			rf, NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V2,
				NBL_DSCH_PRI03_P2S_MAP_OFF_V2(core_info->eth_id)),
			p2s_map[0]);
		ret += nbl_grc_write_reg(
			rf, NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V2,
				NBL_DSCH_PRI47_P2S_MAP_OFF_V2(core_info->eth_id)),
			p2s_map[1]);
	} else {
		for (i = 0; i < core_info->lag_info.mbr_num; i++) {
			u8 eth_id = core_info->lag_info.mbr[i].eth_id;

			ret += nbl_grc_write_reg(
				rf, NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V2,
					NBL_DSCH_PRI03_P2S_MAP_OFF_V2(eth_id)),
				p2s_map[0]);
			ret += nbl_grc_write_reg(
				rf, NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V2,
					NBL_DSCH_PRI47_P2S_MAP_OFF_V2(eth_id)),
				p2s_map[1]);
		}
	}

	return ret;
}

static int nbl_update_p2s_cfg_v3(struct nbl_device *dev, const u32 *p2s_map)
{
	int ret;

	ret = nbl_grc_write_reg(dev->rf,
			NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V3,
					  NBL_DSCH_PRI03_P2S_MAP_OFF_V3),
			p2s_map[0]);
	ret += nbl_grc_write_reg(dev->rf,
			 NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V3,
					   NBL_DSCH_PRI47_P2S_MAP_OFF_V3),
			 p2s_map[1]);

	return ret;
}

static int nbl_update_p2s_cfg(struct nbl_device *dev, bool is_dsch_en)
{
	struct nbl_pci_f *rf = dev->rf;
	union rdma_p2s_map_cfg p2s_map = {};
	int ret;

	p2s_map.pri0 = (1 << NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 0));
	p2s_map.pri1 = (1 << NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 1));
	p2s_map.pri2 = (1 << NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 2));
	p2s_map.pri3 = (1 << NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 3));
	p2s_map.pri4 = (1 << NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 4));
	p2s_map.pri5 = (1 << NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 5));
	p2s_map.pri6 = (1 << NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 6));
	p2s_map.pri7 = (1 << NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 7));
	if (!is_dsch_en)
		p2s_map.pri0 = 0xff;

	ret = dev->rf->product->qos_ops->update_p2s_cfg(dev, p2s_map.data);
	if (ret)
		nbl_pr_err("failed to set tc to prio\n");

	return ret;
}

static int nbl_set_tc_pri_v4(struct nbl_device *dev, u32 *var)
{
	struct nbl_pci_f *rf = dev->rf;
	int i;
	bool is_dsch_en = false;

	for (i = 0; i < NBL_PRI_NUM; i++)
		NBL_SET_PRI_TO_T2P(rf->sc_dev.tc2pri, i, var[i]);

	if (strncasecmp(rf->sc_dev.qos_dbgfs_params[NBL_CFG_TRUST_DSCP_EN], "1", 1) == 0)
		is_dsch_en = true;

	return nbl_update_p2s_cfg(dev, is_dsch_en);
}

static int nbl_set_tc_pri(struct nbl_device *dev, u32 *var)
{
	if (dev->rf->product->qos_ops->set_tc_pri)
		return dev->rf->product->qos_ops->set_tc_pri(dev, var);

	return 0;
}

static int nbl_set_pfc_en_v3(struct nbl_device *dev, u32 *var)
{
	u32 i, ret;
	u32 enable = 0;
	u32 cos_en = 0;
	bool flag0 = false;
	bool flag1 = false;
	u32 retry_quanta;
	struct nbl_pci_f *rf = dev->rf;
	struct nbl_core_export *core_info = (struct nbl_core_export *)rf->cdev;
	union cfg_qm_bp_en_table uqm_bp_en = {};
	union eth_pause_pfc_en_table eth_pause_pfc_en = {};

	for (i = 0; i < NBL_PRI_NUM; i++) {
		if (var[i])
			enable = 1;
		cos_en |= var[i] << i;
	}

	/* 1. uqm cfg_qm_bp_en */
	ret = nbl_grc_read_reg(dev->rf,
		NBL_UQM_REG_ADDR(NBL_REG_UQM_BASE_V3, NBL_UQM_CFG_QM_BP_EN_OFF),
		&uqm_bp_en.data[0]);
	if (ret) {
		nbl_pr_err("failed to read uqm_bp_en reg:%#x val:%#x\n",
			NBL_UQM_REG_ADDR(NBL_REG_UQM_BASE_V3,
				NBL_UQM_CFG_QM_BP_EN_OFF), uqm_bp_en.data[0]);
		return ret;
	}
	uqm_bp_en.cos_pause_en = cos_en;

	ret = nbl_grc_write_reg(dev->rf,
		NBL_UQM_REG_ADDR(NBL_REG_UQM_BASE_V3, NBL_UQM_CFG_QM_BP_EN_OFF),
		uqm_bp_en.data[0]);
	if (ret) {
		nbl_pr_err("failed to write uqm_bp_en into reg:%#x val:%#x\n",
			NBL_UQM_REG_ADDR(NBL_REG_UQM_BASE_V3,
				NBL_UQM_CFG_QM_BP_EN_OFF), uqm_bp_en.data[0]);
		return ret;
	}

	/* 2. eth pause_pfc_en retry_quanta */
	eth_pause_pfc_en.cfg_pause_en = !enable;
	eth_pause_pfc_en.cfg_pfc_en = enable;
	retry_quanta = enable ? NBL_VAL_RETRY_QUANTA_PFC : NBL_VAL_RETRY_QUANTA_DEFAULT;

	if (core_info->is_lag) {
		for (i = 0; i < core_info->lag_info.mbr_num; i++) {
			switch (core_info->lag_info.mbr[i].eth_id) {
			case 0:
				flag0 = true;
				break;
			case 1:
				flag1 = true;
				break;
			default:
				return 0;
			}
		}
	} else {
		switch (core_info->eth_id) {
		case 0:
			flag0 = true;
			break;
		case 1:
			flag1 = true;
			break;
		default:
			return 0;
		}
	}

	if (flag0) {
		ret = nbl_grc_write_reg(dev->rf, NBL_REG_ETH0_PAUSE_PFC_EN,
			eth_pause_pfc_en.data[0]);
		if (ret) {
			nbl_pr_err("failed to write eth0_pause_pfc_en into reg:%#x val:%#x\n",
				NBL_REG_ETH0_PAUSE_PFC_EN, eth_pause_pfc_en.data[0]);
			return ret;
		}

		ret = nbl_grc_write_reg(dev->rf, NBL_REG_ETH0_RETRY_QUANTA, retry_quanta);
		if (ret) {
			nbl_pr_err("failed to write eth0_retry_quanta into reg:%#x val:%#x\n",
				NBL_REG_ETH0_RETRY_QUANTA, retry_quanta);
			return ret;
		}
	}

	if (flag1) {
		ret = nbl_grc_write_reg(dev->rf, NBL_REG_ETH1_PAUSE_PFC_EN,
			eth_pause_pfc_en.data[0]);
		if (ret) {
			nbl_pr_err("failed to write eth1_pause_pfc_en into reg:%#x val:%#x\n",
				NBL_REG_ETH1_PAUSE_PFC_EN, eth_pause_pfc_en.data[0]);
			return ret;
		}

		ret = nbl_grc_write_reg(dev->rf, NBL_REG_ETH1_RETRY_QUANTA, retry_quanta);
		if (ret) {
			nbl_pr_err("failed to write eth1_retry_quanta into reg:%#x val:%#x\n",
				NBL_REG_ETH1_RETRY_QUANTA, retry_quanta);
			return ret;
		}
	}

	return 0;
}

static u32 nbl_eth_pause_pfc_en_reg_v4(u8 eth_id)
{
	switch (eth_id) {
	case 0:
		return NBL_REG_ETH0_PAUSE_PFC_EN_V4;
	case 1:
		return NBL_REG_ETH1_PAUSE_PFC_EN_V4;
	case 2:
		return NBL_REG_ETH2_PAUSE_PFC_EN_V4;
	case 3:
		return NBL_REG_ETH3_PAUSE_PFC_EN_V4;
	default:
		return 0;
	}
}

static int nbl_set_pfc_en_v4(struct nbl_device *dev, u32 *var)
{
	struct nbl_core_export *core_info = (struct nbl_core_export *)dev->rf->cdev;
	u32 i, ret;
	u32 enable = 0;
	u32 cos_en = 0;
	u32 reg;
	union cfg_qm_bp_en_table uqm_bp_en = {};
	union eth_fc_cfg_table_v4 eth_pause_pfc_en = {};

	for (i = 0; i < NBL_PRI_NUM; i++) {
		if (var[i])
			enable = 1;
		cos_en |= var[i] << i;
	}

	/* 1. uqm cfg_qm_bp_en */
	ret = nbl_grc_read_reg(dev->rf,
		NBL_UQM_REG_ADDR(NBL_REG_UQM_BASE_V3, NBL_UQM_CFG_QM_BP_EN_OFF),
		&uqm_bp_en.data[0]);
	if (ret) {
		nbl_pr_err("failed to read uqm_bp_en reg:%#x val:%#x\n",
			NBL_UQM_REG_ADDR(NBL_REG_UQM_BASE_V3,
				NBL_UQM_CFG_QM_BP_EN_OFF), uqm_bp_en.data[0]);
		return ret;
	}
	uqm_bp_en.cos_pause_en = cos_en;

	ret = nbl_grc_write_reg(dev->rf,
		NBL_UQM_REG_ADDR(NBL_REG_UQM_BASE_V3, NBL_UQM_CFG_QM_BP_EN_OFF),
		uqm_bp_en.data[0]);
	if (ret) {
		nbl_pr_err("failed to write uqm_bp_en into reg:%#x val:%#x\n",
			NBL_UQM_REG_ADDR(NBL_REG_UQM_BASE_V3,
				NBL_UQM_CFG_QM_BP_EN_OFF), uqm_bp_en.data[0]);
		return ret;
	}

	/* 2. eth pause_pfc_en */
	eth_pause_pfc_en.cfg_rx_pause_en = !enable;
	eth_pause_pfc_en.cfg_rx_pfc_en = enable;
	eth_pause_pfc_en.cfg_tx_pause_en = !enable;
	eth_pause_pfc_en.cfg_tx_pfc_en = enable;

	if (core_info->is_lag) {
		for (i = 0; i < core_info->lag_info.mbr_num; i++) {
			reg = nbl_eth_pause_pfc_en_reg_v4(core_info->lag_info.mbr[i].eth_id);
			if (!reg)
				return -EINVAL;
			ret = nbl_grc_write_reg(dev->rf, reg, eth_pause_pfc_en.data[0]);
			if (ret) {
				nbl_pr_err("failed to write eth%d_pause_pfc_en into reg:%#x val:%#x\n",
					core_info->lag_info.mbr[i].eth_id, reg,
					eth_pause_pfc_en.data[0]);
				return ret;
			}
		}
	} else {
		reg = nbl_eth_pause_pfc_en_reg_v4(core_info->eth_id);
		if (!reg)
			return -EINVAL;
		ret = nbl_grc_write_reg(dev->rf, reg, eth_pause_pfc_en.data[0]);
		if (ret) {
			nbl_pr_err("failed to write eth%d_pause_pfc_en into reg:%#x val:%#x\n",
				core_info->eth_id, reg, eth_pause_pfc_en.data[0]);
			return ret;
		}
	}

	return 0;
}

static int nbl_set_dport_pri_pfc_en(struct nbl_device *dev, u32 *var, u32 dport_id)
{
	u32 i, ret;
	union store_eth_cos_fc store_eth_cos_fc = {};

	for (i = 0; i < NBL_PRI_NUM; i++) {
		ret = nbl_grc_read_reg(dev->rf,
			NBL_STORE_ETH_COS_FC_V2(dport_id, i),
			&store_eth_cos_fc.data[0]);
		if (ret) {
			nbl_pr_err("failed to read store_eth_cos_fc into reg:%#x val:%#x\n",
				NBL_STORE_ETH_COS_FC_V2(dport_id, i),
				store_eth_cos_fc.data[0]);
			return ret;
		}
		store_eth_cos_fc.fc_en = var[i];
		ret = nbl_grc_write_reg(dev->rf,
			NBL_STORE_ETH_COS_FC_V2(dport_id, i),
			store_eth_cos_fc.data[0]);
		if (ret) {
			nbl_pr_err("failed to write store_eth_cos_fc into reg:%#x val:%#x\n",
				NBL_STORE_ETH_COS_FC_V2(dport_id, i),
				store_eth_cos_fc.data[0]);
			return ret;
		}
	}

	return 0;
}

static int nbl_set_pfc_en_v2(struct nbl_device *dev, u32 *var)
{
	u32 i, ret;
	u32 enable = 0;
	u32 cos_en = 0;
	u32 dport_id = dev->rf->sc_dev.dport_id;
	u32 qm_cos_bp_reg = NBL_QM_REG_ADDR(NBL_REG_QM_BASE_V2,
					    NBL_QM_TX_RXMAC_COS_BP_EN_OFF);
	union store_up_fc_mode store_up_fc_mode = {};
	union dqm_rxmac_tx_cos_bp_en_table cos_bp = {};
	struct nbl_core_export *core_info = (struct nbl_core_export *)dev->rf->cdev;

	for (i = 0; i < NBL_PRI_NUM; i++) {
		if (var[i])
			enable = 1;
		cos_en |= var[i] << i;
	}

	ret = nbl_grc_read_reg(dev->rf, qm_cos_bp_reg, &cos_bp.data[0]);
	if (ret) {
		nbl_pr_err("failed to read tx_rxmac_cos_bp_en reg:%#x val:%#x\n",
			qm_cos_bp_reg, cos_bp.data[0]);
		return ret;
	}

	switch (dport_id) {
	case 0:
		cos_bp.eth0 = cos_en;
		break;
	case 1:
		cos_bp.eth1 = cos_en;
		break;
	case 2:
		cos_bp.eth2 = cos_en;
		break;
	case 3:
		cos_bp.eth3 = cos_en;
		break;
	default:
		return 0;
	}

	ret = nbl_grc_write_reg(dev->rf, qm_cos_bp_reg, cos_bp.data[0]);
	if (ret) {
		nbl_pr_err("failed to write tx_rxmac_cos_bp_en reg:%#x val:%#x\n",
			qm_cos_bp_reg, cos_bp.data[0]);
		return ret;
	}

	ret = nbl_grc_read_reg(dev->rf,
			       NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V2,
						 NBL_DSCH_STORE_UP_FC_MODE_OFF_V2),
		&store_up_fc_mode.data[0]);
	if (ret) {
		nbl_pr_err("failed to read store_up_fc_mode reg:%#x val:%#x\n",
			NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V2,
					  NBL_DSCH_STORE_UP_FC_MODE_OFF_V2),
			store_up_fc_mode.data[0]);
		return ret;
	}
	store_up_fc_mode.pfc = enable;

	ret = nbl_grc_write_reg(dev->rf,
				NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V2,
						  NBL_DSCH_STORE_UP_FC_MODE_OFF_V2),
		store_up_fc_mode.data[0]);
	if (ret) {
		nbl_pr_err("failed to write store_up_fc_mode into reg:%#x val:%#x\n",
			NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V2,
					  NBL_DSCH_STORE_UP_FC_MODE_OFF_V2),
			store_up_fc_mode.data[0]);
		return ret;
	}

	if (!core_info->is_lag)
		ret = nbl_set_dport_pri_pfc_en(dev, var, dev->rf->sc_dev.dport_id);
	else {
		for (i = 0; i < core_info->lag_info.mbr_num; i++) {
			ret = nbl_set_dport_pri_pfc_en(dev, var,
				core_info->lag_info.mbr[i].eth_id);
			if (ret)
				return ret;
		}
	}

	//TODO: set eth pfc
	return 0;
}

static int nbl_set_pfc_en(struct nbl_device *dev, u32 *var)
{
	return dev->rf->product->qos_ops->set_pfc_en(dev, var);
}

static int nbl_check_spwrr_cfg(struct nbl_device *dev, u32 *var,
			       u64 spwrr_reg, u64 raq_pri_map_reg,
			       u64 pri03_map_cfg_reg, u64 pri47_map_cfg_reg)
{
	u32 new_spwrr = var[0];
	u32 ori_spwrr;
	int ret;

	ret = nbl_grc_read_reg(dev->rf, spwrr_reg, &ori_spwrr);
	if (ret) {
		nbl_pr_err("failed to read dsch spwrr reg:%llx val:%#x\n",
			spwrr_reg, ori_spwrr);
		return ret;
	}

	if (new_spwrr == 0 && ori_spwrr > 0) {
		/* set cfg to all wrr */
		nbl_grc_write_reg(
			dev->rf,
			raq_pri_map_reg,
			NBL_QOS_DEFAULT_RAQ_PRI_MAP);
		nbl_grc_write_reg(
			dev->rf,
			pri03_map_cfg_reg,
			NBL_QOS_DEFAULT_PRI03_MAP);
		nbl_grc_write_reg(
			dev->rf,
			pri47_map_cfg_reg,
			NBL_QOS_DEFAULT_PRI47_MAP);
	}

	if (new_spwrr > 0 && ori_spwrr == 0) {
		/* set cfg to sp */
		nbl_grc_write_reg(
			dev->rf,
			raq_pri_map_reg,
			NBL_QOS_DEFAULT_SP_RAQ_PRI_MAP);
		nbl_grc_write_reg(
			dev->rf,
			pri03_map_cfg_reg,
			NBL_QOS_DEFAULT_SP_PRI03_MAP);
		nbl_grc_write_reg(
			dev->rf,
			pri47_map_cfg_reg,
			NBL_QOS_DEFAULT_SP_PRI47_MAP);
	}

	return 0;
}

static int nbl_check_spwrr_cfg_v2(struct nbl_device *dev, u32 *var)
{
	return nbl_check_spwrr_cfg(dev, var,
		NBL_DSCH_TC_SPWRR_CFG_TBL_ADDR(NBL_REG_DSCH_BASE_V2,
						dev->rf->sc_dev.function_id),
		NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V2,
				  NBL_DSCH_RAQ_PRI_MAP_CFG_OFF_V2),
		NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V2,
				  NBL_DSCH_PRI03_MAP_CFG_OFF_V2),
		NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V2,
				  NBL_DSCH_PRI47_MAP_CFG_OFF_V2));
}

static int nbl_check_spwrr_cfg_v3(struct nbl_device *dev, u32 *var)
{
	return nbl_check_spwrr_cfg(dev, var,
		NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V3,
				  NBL_DSCH_TC_SPWRR_CFG_TBL_OFF),
		NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V3,
				  NBL_DSCH_RAQ_PRI_MAP_CFG_OFF_V3),
		NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V3,
				  NBL_DSCH_PRI03_MAP_CFG_OFF_V3),
		NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V3,
				  NBL_DSCH_PRI47_MAP_CFG_OFF_V3));
}

static int nbl_set_spwrr(struct nbl_device *dev, u32 *var)
{
	int ret = 0;
	u32 offset;

	/* check and set raq pi map, pri map, and imap */
	if (dev->rf->product->qos_ops->check_spwrr_cfg) {
		ret = dev->rf->product->qos_ops->check_spwrr_cfg(dev, var);
		if (ret != 0)
			return ret;
	}

	offset = dev->rf->product->qos_ops->get_reg_offset(dev->rf,
							 NBL_CFG_SPWRR);

	nbl_grc_write_reg(dev->rf, offset, var[0]);

	return 0;
}

static int nbl_set_pfc_buf_common(struct nbl_device *dev, u32 *var,
				     u32 tsh_offset)
{
	u32 ret;
	u32 reg_offset;
	union cfg_pfc_tsh_table uqm_pfc_buf = {};

	uqm_pfc_buf.xoff = var[NBL_PFC_CFG_XOFF_OFFSET];
	uqm_pfc_buf.xon = var[NBL_PFC_CFG_XON_OFFSET];

	reg_offset = NBL_UQM_CFG_COS_TSH_ADDR(NBL_REG_UQM_BASE_V3,
			tsh_offset, var[NBL_PFC_CFG_PRI_OFFSET]);

	ret = nbl_grc_write_reg(dev->rf, reg_offset, uqm_pfc_buf.data[0]);
	if (ret)
		nbl_pr_err("failed to write uqm_pfc_buf into reg:%#x val:%#x\n",
			reg_offset, uqm_pfc_buf.data[0]);

	return ret;
}

static int nbl_set_pfc_buf_v3(struct nbl_device *dev, u32 *var)
{
	return nbl_set_pfc_buf_common(dev, var,
					 NBL_UQM_CFG_COS_TSH_OFF_V3);
}

static int nbl_set_pfc_buf_v4(struct nbl_device *dev, u32 *var)
{
	return nbl_set_pfc_buf_common(dev, var,
					 NBL_UQM_CFG_COS_TSH_OFF_V4);
}

static int nbl_set_pfc_buf_v2(struct nbl_device *dev, u32 *var)
{
	u32 ret;
	union store_eth_cos_fc store_eth_cos_fc = {};

	store_eth_cos_fc.fc_en = 1;
	store_eth_cos_fc.xoff_th = var[NBL_PFC_CFG_XOFF_OFFSET];
	store_eth_cos_fc.xon_th = var[NBL_PFC_CFG_XON_OFFSET];

	ret = nbl_grc_write_reg(dev->rf,
		NBL_STORE_ETH_COS_FC_V2(dev->rf->sc_dev.dport_id, var[NBL_PFC_CFG_PRI_OFFSET]),
		store_eth_cos_fc.data[0]);
	if (ret)
		nbl_pr_err("failed to write NBL_STORE_ETH_COS_FC_V2 into reg:%#x val:%#x\n",
			NBL_STORE_ETH_COS_FC_V2(
				dev->rf->sc_dev.dport_id,
				var[NBL_PFC_CFG_PRI_OFFSET]),
			store_eth_cos_fc.data[0]);

	return ret;
}

static int nbl_set_pfc_buf(struct nbl_device *dev, u32 *var)
{
	return dev->rf->product->qos_ops->set_pfc_buf(dev, var);
}

static int nbl_set_pkt2pri_v3(struct nbl_device *dev, bool is_dscp, u32 *var, u32 dport_id)
{

	u32 ret;
	u32 idx;
	int pkt = var[NBL_PKT2PRI_CFG_PKT_OFFSET];
	int pri = var[NBL_PKT2PRI_CFG_PRI_OFFSET];
	u32 reg_offset;
	union pkt_cos_map_table pkt_cos_map = {};
	int up_dot1Q_cos_map_reg[NBL_ETH_MAX_V3] = {
		NBL_REG_UP_DOT1Q_COS_MAP_REG0,
		NBL_REG_UP_DOT1Q_COS_MAP_REG1,
	};
	int up_dscp_cos_map_reg[NBL_ETH_MAX_V3] = {
		NBL_REG_UP_DSCP_COS_MAP_REG0_V4,
		NBL_REG_UP_DSCP_COS_MAP_REG1_V4,
	};

	idx =  pkt / NBL_PRI_NUM;
	if (is_dscp) { /* set def dscp */
		reg_offset = up_dscp_cos_map_reg[dport_id] + 4 * idx;
	} else {
		reg_offset = up_dot1Q_cos_map_reg[dport_id];
	}

	ret = nbl_grc_read_reg(dev->rf, reg_offset, &pkt_cos_map.data[0]);
	if (ret) {
		nbl_pr_err("failed to read up_pkt_cos_map[%d] reg:%#x val:%#x\n",
			idx, reg_offset, pkt_cos_map.data[0]);
		return ret;
	}

	set_pri(&pkt_cos_map, pkt % NBL_PRI_NUM, pri);
	ret = nbl_grc_write_reg(dev->rf, reg_offset, pkt_cos_map.data[0]);
	if (ret) {
		nbl_pr_err("failed to write up_pkt_cos_map[%d] into reg:%#x val:%#x\n",
			idx, reg_offset, pkt_cos_map.data[0]);
		return ret;
	}

	return 0;
}

static int nbl_set_pkt2pri_v2(struct nbl_device *dev, bool is_dscp, u32 *var, u32 dport_id)
{
	u32 ret;
	u32 idx;
	int pkt = var[NBL_PKT2PRI_CFG_PKT_OFFSET];
	int pri = var[NBL_PKT2PRI_CFG_PRI_OFFSET];
	u32 reg_offset;
	union store_tbl_pri_conf store_tbl_pri_conf = {};

	idx =  pkt / NBL_PRI_NUM;

	if (is_dscp)
		reg_offset = NBL_REG_STORE_TBL_PRI_CONF_V2(dport_id) + 4 * idx;
	else
		reg_offset = NBL_REG_STORE_TBL_PRI_CONF_V2(dport_id);

	ret = nbl_grc_read_reg(dev->rf, reg_offset, &store_tbl_pri_conf.data[0]);
	if (ret) {
		nbl_pr_err("failed to read store_tbl_pri_conf[%d] reg:%#x val:%#x\n",
			idx, reg_offset, store_tbl_pri_conf.data[0]);
		return ret;
	}

	set_pri_v2(&store_tbl_pri_conf, pkt % NBL_PRI_NUM, pri);
	ret = nbl_grc_write_reg(dev->rf, reg_offset, store_tbl_pri_conf.data[0]);
	if (ret) {
		nbl_pr_err("failed to write store_tbl_pri_conf[%d] into reg:%#x val:%#x\n",
			idx, reg_offset, store_tbl_pri_conf.data[0]);
		return ret;
	}

	return 0;
}

static int nbl_set_pkt2pri_one(struct nbl_device *dev, bool is_dscp, u32 *var, u32 dport_id)
{
	if (dev->rf->product->qos_ops->set_pkt2pri)
		return dev->rf->product->qos_ops->set_pkt2pri(dev, is_dscp,
							    var, dport_id);

	return -EINVAL;
}

static int nbl_set_pkt2pri(struct nbl_device *dev, bool is_dscp, u32 *var)
{
	int i;
	int ret_val = 0;
	struct nbl_core_export *core_info = (struct nbl_core_export *)dev->rf->cdev;

	if (!core_info->is_lag)
		ret_val = nbl_set_pkt2pri_one(dev, is_dscp, var, dev->rf->sc_dev.dport_id);
	else {
		for (i = 0; i < core_info->lag_info.mbr_num; i++) {
			ret_val = nbl_set_pkt2pri_one(dev, is_dscp, var,
				core_info->lag_info.mbr[i].eth_id);
			if (ret_val)
				return ret_val;
		}
	}

	return ret_val;
}

static int nbl_get_eth_pfc_en_v3(struct nbl_device *dev,
	union eth_pause_pfc_en_table *eth_pause_pfc_en)
{
	int ret, i, eth_id;
	bool flags[2] = {false, false};
	struct nbl_pci_f *rf = dev->rf;
	struct nbl_core_export *core_info = (struct nbl_core_export *)rf->cdev;
	union eth_pause_pfc_en_table reg_values[2] = {};
	const u32 reg_addrs[2] = {NBL_REG_ETH0_PAUSE_PFC_EN, NBL_REG_ETH1_PAUSE_PFC_EN};

	/* 1. set flags */
	if (core_info->is_lag) {
		for (i = 0; i < core_info->lag_info.mbr_num; i++) {
			eth_id = core_info->lag_info.mbr[i].eth_id;
			if (eth_id >= 0 && eth_id <= 1)
				flags[eth_id] = true;
			else
				return -EINVAL;
			}
	} else {
		if (core_info->eth_id == 0 || core_info->eth_id == 1)
			flags[core_info->eth_id] = true;
		else
			return -EINVAL;
	}

	/* 2. read reg */
	for (i = 0; i < 2; i++) {
		if (!flags[i])
			continue;
		ret = nbl_grc_read_reg(rf, reg_addrs[i], &reg_values[i].data[0]);
		if (ret) {
			nbl_pr_err("Read reg 0x%X failed, val=0x%X\n",
				reg_addrs[i], reg_values[i].data[0]);
			return ret;
		}
	}

	/* 3. get result */
	if (core_info->is_lag)
		eth_pause_pfc_en->data[0] = reg_values[0].data[0] & reg_values[1].data[0];
	else
		*eth_pause_pfc_en = flags[0] ? reg_values[0] : reg_values[1];

	return 0;
}

static int nbl_get_pfc_cfg_v3(struct nbl_device *dev, char *lbuf)
{
	u32 i, ret, len;
	u32 reg_offset;
	u32 pfc_en[NBL_PRI_NUM] = {};
	union cfg_qm_bp_en_table uqm_bp_en = {};
	union cfg_pfc_tsh_table uqm_pfc_buf[NBL_PRI_NUM] = {};
	union eth_pause_pfc_en_table eth_pause_pfc_en = {};

	/* get uqm pfc en */
	ret = nbl_grc_read_reg(dev->rf,
		NBL_UQM_REG_ADDR(NBL_REG_UQM_BASE_V3, NBL_UQM_CFG_QM_BP_EN_OFF),
		&uqm_bp_en.data[0]);
	if (ret) {
		nbl_pr_err("failed to read uqm_bp_en reg:%#x val:%#x\n",
			NBL_UQM_REG_ADDR(NBL_REG_UQM_BASE_V3,
				NBL_UQM_CFG_QM_BP_EN_OFF), uqm_bp_en.data[0]);
		return ret;
	}
	for (i = 0; i < NBL_PRI_NUM; i++)
		pfc_en[i] = (uqm_bp_en.cos_pause_en & (1U << i)) != 0;

	/* get uqm xoff xon */
	for (i = 0; i < NBL_PRI_NUM; i++) {
		reg_offset = NBL_UQM_CFG_COS_TSH_ADDR(NBL_REG_UQM_BASE_V3,
			NBL_UQM_CFG_COS_TSH_OFF_V3, i);

		ret = nbl_grc_read_reg(dev->rf, reg_offset, &uqm_pfc_buf[i].data[0]);
		if (ret) {
			nbl_pr_err("failed to read uqm_pfc_buf[%d] form reg:%#x val:%#x\n",
				i, reg_offset, uqm_pfc_buf[i].data[0]);
			return ret;
		}
	}

	/* get eth pfc en */
	ret = nbl_get_eth_pfc_en_v3(dev, &eth_pause_pfc_en);
	if (ret) {
		nbl_pr_err("failed to read eth pfc en\n");
		return ret;
	}

	len = snprintf(lbuf, NBL_PARAM_LEN, "PFC configuration:\n");
	len += snprintf(lbuf + len, NBL_PARAM_LEN - len,
		"priority     0    1    2    3    4    5    6    7\n");
	len += snprintf(lbuf + len, NBL_PARAM_LEN - len,
		"enable   %5d%5d%5d%5d%5d%5d%5d%5d\n",
		pfc_en[0], pfc_en[1], pfc_en[2], pfc_en[3],
		pfc_en[4], pfc_en[5], pfc_en[6], pfc_en[7]);
	len += snprintf(lbuf + len, NBL_PARAM_LEN - len,
		"xoff     %5d%5d%5d%5d%5d%5d%5d%5d\n",
		uqm_pfc_buf[0].xoff, uqm_pfc_buf[1].xoff, uqm_pfc_buf[2].xoff, uqm_pfc_buf[3].xoff,
		uqm_pfc_buf[4].xoff, uqm_pfc_buf[5].xoff, uqm_pfc_buf[6].xoff, uqm_pfc_buf[7].xoff);
	len += snprintf(lbuf + len, NBL_PARAM_LEN - len,
		"xon      %5d%5d%5d%5d%5d%5d%5d%5d\n",
		uqm_pfc_buf[0].xon, uqm_pfc_buf[1].xon, uqm_pfc_buf[2].xon, uqm_pfc_buf[3].xon,
		uqm_pfc_buf[4].xon, uqm_pfc_buf[5].xon, uqm_pfc_buf[6].xon, uqm_pfc_buf[7].xon);

	len += snprintf(lbuf + len, NBL_PARAM_LEN - len, "eth_pfc_en:%1d eth_pause_en:%1d\n",
		eth_pause_pfc_en.cfg_pfc_en, eth_pause_pfc_en.cfg_pause_en);

	return len;
}

static int nbl_get_pfc_cfg_v4(struct nbl_device *dev, char *lbuf)
{
	struct nbl_core_export *core_info = (struct nbl_core_export *)dev->rf->cdev;
	u32 i, ret, len;
	u32 reg_offset;
	u32 reg;
	u32 pfc_en[NBL_PRI_NUM] = {};
	union cfg_qm_bp_en_table uqm_bp_en = {};
	union cfg_pfc_tsh_table uqm_pfc_buf[NBL_PRI_NUM] = {};
	union eth_fc_cfg_table_v4 eth_pause_pfc_en = {};

	/* get uqm pfc en */
	ret = nbl_grc_read_reg(dev->rf,
		NBL_UQM_REG_ADDR(NBL_REG_UQM_BASE_V3, NBL_UQM_CFG_QM_BP_EN_OFF),
		&uqm_bp_en.data[0]);
	if (ret) {
		nbl_pr_err("failed to read uqm_bp_en reg:%#x val:%#x\n",
			NBL_UQM_REG_ADDR(NBL_REG_UQM_BASE_V3,
				NBL_UQM_CFG_QM_BP_EN_OFF), uqm_bp_en.data[0]);
		return ret;
	}
	for (i = 0; i < NBL_PRI_NUM; i++)
		pfc_en[i] = (uqm_bp_en.cos_pause_en & (1U << i)) != 0;

	/* get uqm xoff xon */
	for (i = 0; i < NBL_PRI_NUM; i++) {
		reg_offset = NBL_UQM_CFG_COS_TSH_ADDR(NBL_REG_UQM_BASE_V3,
			NBL_UQM_CFG_COS_TSH_OFF_V4, i);
		ret = nbl_grc_read_reg(dev->rf, reg_offset, &uqm_pfc_buf[i].data[0]);
		if (ret) {
			nbl_pr_err("failed to read uqm_pfc_buf[%d] form reg:%#x val:%#x\n",
				i, reg_offset, uqm_pfc_buf[i].data[0]);
			return ret;
		}
	}

	/* get eth pfc en */
	if (core_info->is_lag) {
		if (!core_info->lag_info.mbr_num)
			return -EINVAL;
		reg = nbl_eth_pause_pfc_en_reg_v4(core_info->lag_info.mbr[0].eth_id);
	} else {
		reg = nbl_eth_pause_pfc_en_reg_v4(core_info->eth_id);
	}
	if (!reg)
		return -EINVAL;

	ret = nbl_grc_read_reg(dev->rf, reg, &eth_pause_pfc_en.data[0]);
	if (ret) {
		nbl_pr_err("failed to read fc_cfg_reg:%#x val:%#x\n",
			reg, eth_pause_pfc_en.data[0]);
		return ret;
	}

	len = snprintf(lbuf, NBL_PARAM_LEN, "PFC configuration:\n");
	len += snprintf(lbuf + len, NBL_PARAM_LEN - len,
		"priority     0    1    2    3    4    5    6    7\n");
	len += snprintf(lbuf + len, NBL_PARAM_LEN - len,
		"enable   %5d%5d%5d%5d%5d%5d%5d%5d\n",
		pfc_en[0], pfc_en[1], pfc_en[2], pfc_en[3],
		pfc_en[4], pfc_en[5], pfc_en[6], pfc_en[7]);
	len += snprintf(lbuf + len, NBL_PARAM_LEN - len,
		"xoff     %5d%5d%5d%5d%5d%5d%5d%5d\n",
		uqm_pfc_buf[0].xoff, uqm_pfc_buf[1].xoff, uqm_pfc_buf[2].xoff, uqm_pfc_buf[3].xoff,
		uqm_pfc_buf[4].xoff, uqm_pfc_buf[5].xoff, uqm_pfc_buf[6].xoff, uqm_pfc_buf[7].xoff);
	len += snprintf(lbuf + len, NBL_PARAM_LEN - len,
		"xon      %5d%5d%5d%5d%5d%5d%5d%5d\n",
		uqm_pfc_buf[0].xon, uqm_pfc_buf[1].xon, uqm_pfc_buf[2].xon, uqm_pfc_buf[3].xon,
		uqm_pfc_buf[4].xon, uqm_pfc_buf[5].xon, uqm_pfc_buf[6].xon, uqm_pfc_buf[7].xon);

	len += snprintf(lbuf + len, NBL_PARAM_LEN - len,
		"tx_pfc_en:%1d tx_pause_en:%1d rx_pfc_en:%1d rx_pause_en:%1d\n",
		eth_pause_pfc_en.cfg_tx_pfc_en, eth_pause_pfc_en.cfg_tx_pause_en,
		eth_pause_pfc_en.cfg_rx_pfc_en, eth_pause_pfc_en.cfg_rx_pause_en);

	return len;
}

static int nbl_get_pfc_cfg_v2(struct nbl_device *dev, char *lbuf)
{
	u32 i, ret, len;
	u32 reg_offset;
	union store_up_fc_mode store_up_fc_mode = {};
	union store_eth_cos_fc store_eth_cos_fc[NBL_PRI_NUM] = {};

	ret = nbl_grc_read_reg(dev->rf,
			       NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V2,
						 NBL_DSCH_STORE_UP_FC_MODE_OFF_V2),
		&store_up_fc_mode.data[0]);
	if (ret) {
		nbl_pr_err("failed to read store_up_fc_mode reg:%#x val:%#x\n",
			NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V2,
					  NBL_DSCH_STORE_UP_FC_MODE_OFF_V2),
			store_up_fc_mode.data[0]);
		return ret;
	}

	/* xoff, xon */
	for (i = 0; i < NBL_PRI_NUM; i++) {
		reg_offset = NBL_STORE_ETH_COS_FC_V2(dev->rf->sc_dev.dport_id, i);
		ret = nbl_grc_read_reg(dev->rf, reg_offset, &store_eth_cos_fc[i].data[0]);
		if (ret) {
			nbl_pr_err("failed to read store_eth_cos_fc reg:%#x val:%#x\n",
				reg_offset, store_eth_cos_fc[i].data[0]);
			return ret;
		}
	}

	len = snprintf(lbuf, NBL_PARAM_LEN, "PFC configuration:\n");
	len += snprintf(lbuf + len, NBL_PARAM_LEN - len,
		"priority     0    1    2    3    4    5    6    7\n");
	len += snprintf(lbuf + len, NBL_PARAM_LEN - len,
		"enable   %5d%5d%5d%5d%5d%5d%5d%5d\n",
		store_eth_cos_fc[0].fc_en, store_eth_cos_fc[1].fc_en,
		store_eth_cos_fc[2].fc_en, store_eth_cos_fc[3].fc_en,
		store_eth_cos_fc[4].fc_en, store_eth_cos_fc[5].fc_en,
		store_eth_cos_fc[6].fc_en, store_eth_cos_fc[7].fc_en);
	len += snprintf(lbuf + len, NBL_PARAM_LEN - len,
		"xoff     %5d%5d%5d%5d%5d%5d%5d%5d\n",
		store_eth_cos_fc[0].xoff_th, store_eth_cos_fc[1].xoff_th,
		store_eth_cos_fc[2].xoff_th, store_eth_cos_fc[3].xoff_th,
		store_eth_cos_fc[4].xoff_th, store_eth_cos_fc[5].xoff_th,
		store_eth_cos_fc[6].xoff_th, store_eth_cos_fc[7].xoff_th);
	len += snprintf(lbuf + len, NBL_PARAM_LEN - len,
		"xon      %5d%5d%5d%5d%5d%5d%5d%5d\n",
		store_eth_cos_fc[0].xon_th, store_eth_cos_fc[1].xon_th,
		store_eth_cos_fc[2].xon_th, store_eth_cos_fc[3].xon_th,
		store_eth_cos_fc[4].xon_th, store_eth_cos_fc[5].xon_th,
		store_eth_cos_fc[6].xon_th, store_eth_cos_fc[7].xon_th);

	len += snprintf(lbuf + len, NBL_PARAM_LEN - len,
		"tx_pfc_en:N/A tx_pause_en:N/A rx_pfc_en:N/A rx_pause_en:N/A\n");

	return len;
}

static int nbl_get_pfc_cfg(struct nbl_device *dev, char *lbuf)
{
	return dev->rf->product->qos_ops->get_pfc_cfg(dev, lbuf);
}

static int nbl_get_pkt2pri_cfg_v3(struct nbl_device *dev, char *lbuf)
{
	u32 i, cnt, ret, len;
	u32 reg_offset;
	bool is_dscp = false;
	u32 dport_id = dev->rf->sc_dev.dport_id;
	union eth_port_reg_table port_table = {};
	union pkt_cos_map_table pkt_cos_map[NBL_PRI_NUM] = {};
	int up_dot1Q_cos_map_reg[NBL_ETH_MAX_V3] = {
		NBL_REG_UP_DOT1Q_COS_MAP_REG0,
		NBL_REG_UP_DOT1Q_COS_MAP_REG1,
	};
	int up_dscp_cos_map_reg[NBL_ETH_MAX_V3] = {
		NBL_REG_UP_DSCP_COS_MAP_REG0_V4,
		NBL_REG_UP_DSCP_COS_MAP_REG1_V4,
	};

	ret = nbl_grc_read_reg(dev->rf, NBL_REG_UP_ETH_PORT_REG(dport_id), &port_table.data[0]);
	if (ret) {
		nbl_pr_err("failed to read up_eth_port_table[%d] reg:%#x val:%#x\n",
			dport_id, NBL_REG_UP_ETH_PORT_REG(dport_id), port_table.data[0]);
		return ret;
	}

	if (port_table.cos_map_mode == NBL_COS_MAP_MODE_DSCP) {
		len = snprintf(lbuf, NBL_PARAM_LEN, "priority trust state: dscp\n");
		reg_offset = up_dscp_cos_map_reg[dport_id];
		len += snprintf(lbuf+len, NBL_PARAM_LEN-len, "dscp pri\n");
		is_dscp = true;
	} else if (port_table.cos_map_mode == NBL_COS_MAP_MODE_8021P) {
		len = snprintf(lbuf, NBL_PARAM_LEN, "priority trust state: 8021p\n");
		reg_offset = up_dot1Q_cos_map_reg[dport_id];
		len += snprintf(lbuf+len, NBL_PARAM_LEN-len, "8021p pri\n");
	} else {
		len = snprintf(lbuf, NBL_PARAM_LEN, "priority trust state: default\n");
		return len;
	}

	cnt = is_dscp ? NBL_PRI_NUM : 1;
	for (i = 0; i < cnt; i++) {
		ret = nbl_grc_read_reg(dev->rf, reg_offset + 4 * i, &pkt_cos_map[i].data[0]);
		if (ret) {
			nbl_pr_err("failed to read up_pkt_cos_map[%d] reg:%#x val:%#x\n",
				i, reg_offset, pkt_cos_map[i].data[0]);
			return ret;
		}
	}

	cnt = is_dscp ? NBL_DSCP_NUM : NBL_PRI_NUM;
	for (i = 0; i < cnt; i++) {
		len += snprintf(lbuf + len, NBL_PARAM_LEN - len,
			"%-3d%1d\n", i,
			get_pri(&pkt_cos_map[i/NBL_PRI_NUM], i%NBL_PRI_NUM));
	}

	return len;
}

static int nbl_get_pkt2pri_cfg_v2(struct nbl_device *dev, char *lbuf)
{
	u32 i, cnt, ret, len;
	u32 reg_offset;
	bool is_dscp = false;
	u32 dport_id = dev->rf->sc_dev.dport_id;
	union store_pri_conf store_pri_conf = {};
	union store_tbl_pri_conf store_tbl_pri_conf[NBL_PRI_NUM] = {};

	ret = nbl_grc_read_reg(
		dev->rf,
		NBL_REG_STORE_PRI_CONF_V2(dport_id),
		&store_pri_conf.data[0]);
	if (ret) {
		nbl_pr_err("failed to read store_pri_conf[%d] reg:%#x val:%#x\n",
			dport_id, NBL_REG_STORE_PRI_CONF_V2(dport_id), store_pri_conf.data[0]);
		return ret;
	}

	if (store_pri_conf.sel == STORE_PRI_CONF_SEL_8021P) {
		len = snprintf(lbuf, NBL_PARAM_LEN, "priority trust state: dscp\n");
		reg_offset = NBL_REG_STORE_TBL_PRI_CONF_V2(dport_id);
		len += snprintf(lbuf+len, NBL_PARAM_LEN-len, "dscp pri\n");
		is_dscp = true;
	} else if (store_pri_conf.sel == STORE_PRI_CONF_SEL_DSCP) {
		len = snprintf(lbuf, NBL_PARAM_LEN, "priority trust state: 8021p\n");
		reg_offset = NBL_REG_STORE_TBL_PRI_CONF_V2(dport_id);
		len += snprintf(lbuf+len, NBL_PARAM_LEN-len, "8021p pri\n");
	} else {
		len = snprintf(lbuf, NBL_PARAM_LEN, "priority trust state: default\n");
		return len;
	}

	cnt = is_dscp ? NBL_PRI_NUM : 1;
	for (i = 0; i < cnt; i++) {
		ret = nbl_grc_read_reg(dev->rf, reg_offset + 4 * i, &store_tbl_pri_conf[i].data[0]);
		if (ret) {
			nbl_pr_err("failed to read store_tbl_pri_conf[%d] reg:%#x val:%#x\n",
				i, reg_offset + 4 * i, store_tbl_pri_conf[i].data[0]);
			return ret;
		}
	}

	cnt = is_dscp ? NBL_DSCP_NUM : NBL_PRI_NUM;
	for (i = 0; i < cnt; i++) {
		len += snprintf(lbuf + len, NBL_PARAM_LEN - len,
			"%-3d%1d\n", i,
			get_pri_v2(&store_tbl_pri_conf[i/NBL_PRI_NUM], i%NBL_PRI_NUM));
	}

	return len;
}

static int nbl_get_pkt2pri_cfg(struct nbl_device *dev, char *lbuf)
{
	if (dev->rf->product->qos_ops->get_pkt2pri_cfg)
		return dev->rf->product->qos_ops->get_pkt2pri_cfg(dev, lbuf);

	return -EINVAL;
}

static int nbl_trust_dscp_en_v3(struct nbl_device *dev, u32 enable, u32 dport_id)
{
	u32 ret;
	struct nbl_pci_f *rf = dev->rf;
	union pkt_cos_map_table pkt_cos_map = {};
	union eth_port_reg_table port_table = {};
	u32 cos_map_mode = enable ? NBL_COS_MAP_MODE_DSCP : NBL_COS_MAP_MODE_8021P;
	int up_dot1Q_cos_map_reg[NBL_ETH_MAX_V3] = {
		NBL_REG_UP_DOT1Q_COS_MAP_REG0,
		NBL_REG_UP_DOT1Q_COS_MAP_REG1,
	};
	int up_dscp_cos_map_reg[NBL_ETH_MAX_V3] = {
		NBL_REG_UP_DSCP_COS_MAP_REG0,
		NBL_REG_UP_DSCP_COS_MAP_REG1,
	};
	int dn_dot1Q_cos_map_reg[NBL_ETH_MAX_V3] = {
		NBL_REG_DN_DOT1Q_COS_MAP_REG0,
		NBL_REG_DN_DOT1Q_COS_MAP_REG1,
	};
	int dn_dscp_cos_map_reg[NBL_ETH_MAX_V3] = {
		NBL_REG_DN_DSCP_COS_MAP_REG0,
		NBL_REG_DN_DSCP_COS_MAP_REG1,
	};

	pkt_cos_map.data[0] = 0x76543210;

	port_table.data[0] = 0;
	ret = nbl_grc_read_reg(dev->rf, NBL_REG_UP_ETH_PORT_REG(dport_id), &port_table.data[0]);
	if (ret) {
		nbl_pr_err("failed to read up_eth_port_table[%d] reg:%#x val:%#x\n",
			dport_id, NBL_REG_UP_ETH_PORT_REG(dport_id), port_table.data[0]);
		return ret;
	}
	port_table.cos_map_mode = cos_map_mode;

	ret = nbl_grc_write_reg(dev->rf, NBL_REG_UP_ETH_PORT_REG(dport_id), port_table.data[0]);
	if (ret) {
		nbl_pr_err("failed to write up_eth_port_table[%d] into reg:%#x val:%#x\n",
			dport_id, NBL_REG_UP_ETH_PORT_REG(dport_id), port_table.data[0]);
		return ret;
	}

	port_table.data[0] = 0;
	ret = nbl_grc_read_reg(dev->rf, NBL_REG_VSI_PORT_REG(rf->vsi_id), &port_table.data[0]);
	if (ret) {
		nbl_pr_err("failed to read dn_vsi_port_table[%d] reg:%#x val:%#x\n",
			rf->vsi_id, NBL_REG_VSI_PORT_REG(rf->vsi_id), port_table.data[0]);
		return ret;
	}
	port_table.cos_map_mode = cos_map_mode;

	ret = nbl_grc_write_reg(dev->rf, NBL_REG_VSI_PORT_REG(rf->vsi_id), port_table.data[0]);
	if (ret) {
		nbl_pr_err("failed to write dn_vsi_port_table[%d] into reg:%#x val:%#x\n",
			rf->vsi_id, NBL_REG_VSI_PORT_REG(rf->vsi_id), port_table.data[0]);
		return ret;
	}

	if (enable) {
		wr32(&dev->rf->hw, up_dscp_cos_map_reg[dport_id], pkt_cos_map.data[0]);
		wr32(&dev->rf->hw, dn_dscp_cos_map_reg[dport_id], pkt_cos_map.data[0]);
		nbl_update_p2s_cfg(dev, true);
	} else {
		wr32(&dev->rf->hw, up_dot1Q_cos_map_reg[dport_id], pkt_cos_map.data[0]);
		wr32(&dev->rf->hw, dn_dot1Q_cos_map_reg[dport_id], pkt_cos_map.data[0]);
		nbl_update_p2s_cfg(dev, false);
	}

	return 0;
}

static int nbl_trust_dscp_en_v4(struct nbl_device *dev, u32 enable, u32 dport_id)
{
	u32 i, ret;
	struct nbl_pci_f *rf = dev->rf;
	union pkt_cos_map_table pkt_cos_map[NBL_PRI_NUM] = {};
	union eth_port_reg_table port_table = {};
	u32 cos_map_mode = enable ? NBL_COS_MAP_MODE_DSCP : NBL_COS_MAP_MODE_8021P;
	int up_dot1Q_cos_map_reg[NBL_ETH_MAX_V3] = {
		NBL_REG_UP_DOT1Q_COS_MAP_REG0,
		NBL_REG_UP_DOT1Q_COS_MAP_REG1,
	};
	int up_dscp_cos_map_reg[NBL_ETH_MAX_V3] = {
		NBL_REG_UP_DSCP_COS_MAP_REG0_V4,
		NBL_REG_UP_DSCP_COS_MAP_REG1_V4,
	};
	int dn_dot1Q_cos_map_reg[NBL_ETH_MAX_V3] = {
		NBL_REG_DN_DOT1Q_COS_MAP_REG0,
		NBL_REG_DN_DOT1Q_COS_MAP_REG1,
	};
	int dn_dscp_cos_map_reg[NBL_ETH_MAX_V3] = {
		NBL_REG_DN_DSCP_COS_MAP_REG0_V4,
		NBL_REG_DN_DSCP_COS_MAP_REG1_V4,
	};

	port_table.data[0] = 0;
	ret = nbl_grc_read_reg(dev->rf, NBL_REG_UP_ETH_PORT_REG(dport_id), &port_table.data[0]);
	if (ret) {
		nbl_pr_err("failed to read up_eth_port_table[%d] reg:%#x val:%#x\n",
			dport_id, NBL_REG_UP_ETH_PORT_REG(dport_id), port_table.data[0]);
		return ret;
	}
	port_table.cos_map_mode = cos_map_mode;

	ret = nbl_grc_write_reg(dev->rf, NBL_REG_UP_ETH_PORT_REG(dport_id), port_table.data[0]);
	if (ret) {
		nbl_pr_err("failed to write up_eth_port_table[%d] into reg:%#x val:%#x\n",
			dport_id, NBL_REG_UP_ETH_PORT_REG(dport_id), port_table.data[0]);
		return ret;
	}

	port_table.data[0] = 0;
	ret = nbl_grc_read_reg(dev->rf, NBL_REG_VSI_PORT_REG(rf->vsi_id), &port_table.data[0]);
	if (ret) {
		nbl_pr_err("failed to read dn_vsi_port_table[%d] reg:%#x val:%#x\n",
			rf->vsi_id, NBL_REG_VSI_PORT_REG(rf->vsi_id), port_table.data[0]);
		return ret;
	}
	port_table.cos_map_mode = cos_map_mode;

	ret = nbl_grc_write_reg(dev->rf, NBL_REG_VSI_PORT_REG(rf->vsi_id), port_table.data[0]);
	if (ret) {
		nbl_pr_err("failed to write dn_vsi_port_table[%d] into reg:%#x val:%#x\n",
			rf->vsi_id, NBL_REG_VSI_PORT_REG(rf->vsi_id), port_table.data[0]);
		return ret;
	}

	if (enable) { /* set def dscp */
		pkt_cos_map[0].data[0] = 0x00000000;
		pkt_cos_map[1].data[0] = 0x11111111;
		pkt_cos_map[2].data[0] = 0x22222222;
		pkt_cos_map[3].data[0] = 0x33333333;
		pkt_cos_map[4].data[0] = 0x44444444;
		pkt_cos_map[5].data[0] = 0x55555555;
		pkt_cos_map[6].data[0] = 0x66666666;
		pkt_cos_map[7].data[0] = 0x77777777;
		for (i = 0; i < NBL_PRI_NUM; i++) {
			writel(pkt_cos_map[i].data[0],
				dev->rf->hw.hw_addr + up_dscp_cos_map_reg[dport_id] + 4*i);
			writel(pkt_cos_map[i].data[0],
				dev->rf->hw.hw_addr + dn_dscp_cos_map_reg[dport_id] + 4*i);
		}
		nbl_update_p2s_cfg(dev, true);
	} else {
		pkt_cos_map[0].data[0] = 0x76543210;
		writel(pkt_cos_map[0].data[0],
			dev->rf->hw.hw_addr + up_dot1Q_cos_map_reg[dport_id]);
		writel(pkt_cos_map[0].data[0],
			dev->rf->hw.hw_addr + dn_dot1Q_cos_map_reg[dport_id]);
		nbl_update_p2s_cfg(dev, false);
	}

	return 0;
}

static int nbl_trust_dscp_en_v2(struct nbl_device *dev, u32 enable, u32 dport_id)
{
	u32 i, ret;
	union store_pri_conf store_pri_conf = {};
	union store_tbl_pri_conf store_tbl_pri_conf[NBL_PRI_NUM] = {};
	union qm_dn_cos_mapping_0 qm_dn_cos_mapping_0 = {};
	union qm_dn_cos_mapping_1 qm_dn_cos_mapping_1 = {};
	union qm_dn_cos_mapping_2 qm_dn_cos_mapping_2 = {};

	u32 sel = enable ? 0 : 1;

	/* Step 1. set store_pri_conf */
	store_pri_conf.data[0] = 0;
	ret = nbl_grc_read_reg(
		dev->rf,
		NBL_REG_STORE_PRI_CONF_V2(dport_id),
		&store_pri_conf.data[0]);
	if (ret) {
		nbl_pr_err("failed to read store_pri_conf[%d] reg:%#x val:%#x\n",
			dport_id, NBL_REG_STORE_PRI_CONF_V2(dport_id), store_pri_conf.data[0]);
		return ret;
	}
	store_pri_conf.sel = sel;
	ret = nbl_grc_write_reg(
		dev->rf,
		NBL_REG_STORE_PRI_CONF_V2(dport_id),
		store_pri_conf.data[0]);
	if (ret) {
		nbl_pr_err("failed to write store_pri_conf[%d] reg:%#x val:%#x\n",
			dport_id, NBL_REG_STORE_PRI_CONF_V2(dport_id), store_pri_conf.data[0]);
		return ret;
	}

	if (enable) {
		/* Step 2. set up reg */
		store_tbl_pri_conf[0].data[0] = 0x00000000;
		store_tbl_pri_conf[1].data[0] = 0x11111111;
		store_tbl_pri_conf[2].data[0] = 0x22222222;
		store_tbl_pri_conf[3].data[0] = 0x33333333;
		store_tbl_pri_conf[4].data[0] = 0x44444444;
		store_tbl_pri_conf[5].data[0] = 0x55555555;
		store_tbl_pri_conf[6].data[0] = 0x66666666;
		store_tbl_pri_conf[7].data[0] = 0x77777777;
		for (i = 0; i < NBL_PRI_NUM; i++) {
			ret = nbl_grc_write_reg(
				dev->rf,
				NBL_REG_STORE_TBL_PRI_CONF_V2(dport_id) + 4 * i,
				store_tbl_pri_conf[i].data[0]);
			if (ret) {
				nbl_pr_err("failed to write store_tbl_pri_conf[%d] reg:%#x val:%#x\n",
					dport_id,
					NBL_REG_STORE_TBL_PRI_CONF_V2(dport_id) + 4 * i,
					store_tbl_pri_conf[i].data[0]);
				return ret;
			}
		}
		/* Step 3. set down reg */
		qm_dn_cos_mapping_0.cos0 = 0x0;
		qm_dn_cos_mapping_0.cos1 = 0x0;
		qm_dn_cos_mapping_0.cos2 = 0x40;
		qm_dn_cos_mapping_1.cos3 = 0x40;
		qm_dn_cos_mapping_1.cos4 = 0x80;
		qm_dn_cos_mapping_1.cos5 = 0x80;
		qm_dn_cos_mapping_2.cos6 = 0x100;
		qm_dn_cos_mapping_2.cos7 = 0x100;
		ret = nbl_grc_write_reg(
			dev->rf,
			NBL_QM_DN_COS_MAPPING_0_ADDR(NBL_REG_QM_BASE_V2, dport_id),
			qm_dn_cos_mapping_0.data[0]);
		ret += nbl_grc_write_reg(
			dev->rf,
			NBL_QM_DN_COS_MAPPING_1_ADDR(NBL_REG_QM_BASE_V2, dport_id),
			qm_dn_cos_mapping_1.data[0]);
		ret += nbl_grc_write_reg(
			dev->rf,
			NBL_QM_DN_COS_MAPPING_2_ADDR(NBL_REG_QM_BASE_V2, dport_id),
			qm_dn_cos_mapping_2.data[0]);
		if (ret) {
			nbl_pr_err("failed to write qm_dn_cos_mapping\n");
			return ret;
		}
	} else {
		/* Step 2. set up reg */
		store_tbl_pri_conf[0].data[0] = 0x76543210;
		ret = nbl_grc_write_reg(dev->rf, NBL_REG_STORE_TBL_PRI_CONF_V2(dport_id),
			store_tbl_pri_conf[0].data[0]);
		if (ret) {
			nbl_pr_err("failed to write store_tbl_pri_conf[%d] reg:%#x val:%#x\n",
				dport_id, NBL_REG_STORE_TBL_PRI_CONF_V2(dport_id),
				store_tbl_pri_conf[0].data[0]);
			return ret;
		}
		/* Step 3. set down reg */
		qm_dn_cos_mapping_0.cos0 = 0x0;
		qm_dn_cos_mapping_0.cos1 = 0x48;
		qm_dn_cos_mapping_0.cos2 = 0x90;
		qm_dn_cos_mapping_1.cos3 = 0xD8;
		qm_dn_cos_mapping_1.cos4 = 0x120;
		qm_dn_cos_mapping_1.cos5 = 0x168;
		qm_dn_cos_mapping_2.cos6 = 0x1B0;
		qm_dn_cos_mapping_2.cos7 = 0x1F8;
		ret = nbl_grc_write_reg(
			dev->rf,
			NBL_QM_DN_COS_MAPPING_0_ADDR(NBL_REG_QM_BASE_V2, dport_id),
			qm_dn_cos_mapping_0.data[0]);
		ret += nbl_grc_write_reg(
			dev->rf,
			NBL_QM_DN_COS_MAPPING_1_ADDR(NBL_REG_QM_BASE_V2, dport_id),
			qm_dn_cos_mapping_1.data[0]);
		ret += nbl_grc_write_reg(
			dev->rf,
			NBL_QM_DN_COS_MAPPING_2_ADDR(NBL_REG_QM_BASE_V2, dport_id),
			qm_dn_cos_mapping_2.data[0]);
		if (ret) {
			nbl_pr_err("failed to write qm_dn_cos_mapping\n");
			return ret;
		}
	}

	return 0;
}

static int nbl_trust_dscp_en_one(struct nbl_device *dev, u32 enable, u32 dport_id)
{
	return dev->rf->product->qos_ops->trust_dscp_en(dev, enable,
							dport_id);
}

static int nbl_trust_dscp_en(struct nbl_device *dev, u32 enable)
{
	int i;
	int ret_val = 0;
	struct nbl_core_export *core_info = (struct nbl_core_export *)dev->rf->cdev;

	if (!core_info->is_lag)
		ret_val = nbl_trust_dscp_en_one(dev, enable, dev->rf->sc_dev.dport_id);
	else {
		for (i = 0; i < core_info->lag_info.mbr_num; i++) {
			ret_val = nbl_trust_dscp_en_one(dev, enable,
				core_info->lag_info.mbr[i].eth_id);
			if (ret_val)
				return ret_val;
		}
	}

	return ret_val;
}

static int nbl_ib_save_process(struct nbl_device *dev)
{
	int ret = 0;
	char src_dir[NBL_RDMA_DENTRY_LEN];
	char dst_dir[NBL_RDMA_DENTRY_LEN];
	struct dentry *dentry_path = NULL;

	/* 1. dst_dir */
	if (dev->ibdev.name[0] == '\0')
		return 0;

	dentry_path = dev->qos_params->qos_root;
	ret = snprintf(dst_dir, sizeof(dst_dir),
		       NBL_RDMA_QOS_CFG_DEV_DEFAULT_DENTRY, dev->ibdev.name);
	if (ret < 0)
		return ret;
	nbl_pr_info("dst_dir=%s\n", dst_dir);

	if (!nbl_dentry_is_exist(dst_dir)) {
		char *path = "/bin/mkdir";
		char *argv[4] = { path, "-p", dst_dir, NULL };
		char *envp[1] = { NULL };

		ret = call_usermodehelper(path, argv, envp, UMH_WAIT_PROC);
		if (ret) {
			nbl_pr_err("failed to mkdir dst_dir:%s, ret=%d\n",
				   dst_dir, ret);
			return ret;
		}
	}

	/* 2. src_dir */
	ret = nbl_ib_get_debugfs_absolute_path(dev, dentry_path, src_dir);
	if (ret < 0)
		return ret;
	nbl_pr_info("src_dir=%s\n", src_dir);

	/* 3. cp -r src_dir dst_dir */
	ret = nbl_ib_copy_dentry(src_dir, dst_dir);

	return ret;
}

static int nbl_load_qos_dev_cfg(struct nbl_device *dev)
{
	int ret;
	char func_default_dir[NBL_RDMA_DENTRY_LEN];
	char src_dir[NBL_RDMA_DENTRY_LEN];
	char dst_dir[NBL_RDMA_DENTRY_LEN];

	/* 1. src_dir */
	ret = snprintf(func_default_dir, sizeof(func_default_dir),
		       NBL_RDMA_QOS_CFG_DEV_DEFAULT_DENTRY, dev->ibdev.name);
	if (ret < 0)
		return ret;
	if (nbl_dentry_is_exist(func_default_dir))
		strscpy(src_dir, func_default_dir, sizeof(src_dir));
	else if (nbl_dentry_is_exist(NBL_RDMA_QOS_CFG_DEFAULT_DENTRY))
		strscpy(src_dir, NBL_RDMA_QOS_CFG_DEFAULT_DENTRY, sizeof(src_dir));
	else {
		nbl_pr_dbg("%s doesn't have default qos cfg.\n",
			   NBL_RDMA_QOS_CFG_DEFAULT_DENTRY);
		return -ENOTDIR;
	}
	nbl_pr_dbg("src_dir=%s\n", src_dir);

	/* 2. dst_dir */
	ret = nbl_ib_get_debugfs_absolute_path(dev, dev->qos_params->qos_root,
					       dst_dir);
	if (ret < 0)
		return ret;
	nbl_pr_dbg("dst_dir=%s\n", dst_dir);

	/* 3. cp -r src_dir dst_dir */
	ret = nbl_ib_copy_dentry(src_dir, dst_dir);

	return ret;
}

static u32 nbl_get_qos_reg_offset_v3(struct nbl_pci_f *rf, int offset)
{
	switch (offset) {
	case NBL_CFG_SQ_PRI_MAP:
		return NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V3, NBL_DSCH_SQ_PRI_MAP_CFG_OFF_V3);
	case NBL_CFG_RAQ_PRI_MAP:
		return NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V3, NBL_DSCH_RAQ_PRI_MAP_CFG_OFF_V3);
	case NBL_CFG_PRI_IMAP:
		return NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V3, NBL_DSCH_IMAP_CFG_OFF_V3);
	case NBL_CFG_PFC_IMAP:
		return NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V3, NBL_DSCH_PRI03_MAP_CFG_OFF_V3);
	case NBL_CFG_DB_TO_CSCH_EN:
		return NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V3, NBL_DSCH_DB_TO_CSCH_EN_OFF_V3);
	case NBL_CFG_SW_DB_CSCH_TH:
		return NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V3, NBL_DSCH_SW_DB_IN_CSCH_TH_OFF_V3);
	case NBL_CFG_CSCH_QLEN_TH:
		return NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V3, NBL_DSCH_CSCH_QLEN_TH_OFF_V3);
	case NBL_CFG_POLL_WGT:
		return NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V3, NBL_DSCH_POLL_WGT_OFF_V3);
	case NBL_CFG_DWRR_EN:
		return NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V3, NBL_DSCH_DWRR_EN_OFF_V3);
	case NBL_CFG_SPWRR:
		return NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V3, NBL_DSCH_TC_SPWRR_CFG_TBL_OFF);
	case NBL_CFG_TC_WGT:
		/* get the tc0 for base reg addr */
		return NBL_DSCH_TC_WGT_CFG_ADDR(NBL_REG_DSCH_BASE(&rf->hw),
						 rf->sc_dev.function_id, 0);
	default:
		return 0;
	}
}

static u32 nbl_get_qos_reg_offset_v2(struct nbl_pci_f *rf, int offset)
{
	switch (offset) {
	case NBL_CFG_SQ_PRI_MAP:
		return NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V2, NBL_DSCH_SQ_PRI_MAP_CFG_OFF_V2);
	case NBL_CFG_RAQ_PRI_MAP:
		return NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V2, NBL_DSCH_RAQ_PRI_MAP_CFG_OFF_V2);
	case NBL_CFG_PRI_IMAP:
		return NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V2, NBL_DSCH_IMAP_CFG_OFF_V2);
	case NBL_CFG_PFC_IMAP:
		return NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V2, NBL_DSCH_PRI03_MAP_CFG_OFF_V2);
	case NBL_CFG_DB_TO_CSCH_EN:
		return NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V2, NBL_DSCH_DB_TO_CSCH_EN_OFF_V2);
	case NBL_CFG_SW_DB_CSCH_TH:
		return NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V2, NBL_DSCH_SW_DB_IN_CSCH_TH_OFF_V2);
	case NBL_CFG_CSCH_QLEN_TH:
		return NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V2, NBL_DSCH_CSCH_QLEN_TH_OFF_V2);
	case NBL_CFG_POLL_WGT:
		return NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V2, NBL_DSCH_POLL_WGT_OFF_V2);
	case NBL_CFG_SPWRR:
		return NBL_DSCH_TC_SPWRR_CFG_TBL_ADDR(NBL_REG_DSCH_BASE_V2, rf->sc_dev.function_id);
	case NBL_CFG_TC_WGT:
		/* get the tc0 for base reg addr */
		return NBL_DSCH_TC_WGT_CFG_ADDR(NBL_REG_DSCH_BASE_V2, rf->sc_dev.function_id, 0);
	default:
		return 0;
	}
}

static int nbl_ib_check_qos_param_val(int offset, u32 *var_arr, int var_cnt)
{
	int ret = 0;
	int i;
	int pkt_max;

	switch (offset) {
	case NBL_CFG_TC_PRI:
		if (var_cnt != NBL_PRI_NUM) {
			nbl_pr_err("qos params %s var_cnt:%d is invalid.\n",
				   nbl_dbg_qos_name[offset], var_cnt);
			return -EINVAL;
		}
		for (i = 0; i < NBL_PRI_NUM; i++) {
			if (var_arr[i] > NBL_DSCH_NET_TC_MAX) {
				nbl_pr_err(
					"qos params %s val[%d]:%d(%#x) is invalid.\n",
					nbl_dbg_qos_name[offset], i, var_arr[i],
					var_arr[i]);
				return -EINVAL;
			}
		}
		break;
	case NBL_CFG_SQ_PRI_MAP:
	case NBL_CFG_RAQ_PRI_MAP:
	case NBL_CFG_PRI_IMAP:
	case NBL_CFG_TC_WGT:
	case NBL_CFG_PFC_IMAP:
		if (var_cnt != NBL_PRI_NUM) {
			nbl_pr_err("qos params %s var_cnt:%d is invalid.\n",
				   nbl_dbg_qos_name[offset], var_cnt);
			return -EINVAL;
		}
		for (i = 0; i < NBL_PRI_NUM; i++) {
			if (((offset == NBL_CFG_TC_WGT ||
			      offset == NBL_CFG_PFC_IMAP) &&
			     var_arr[i] > NBL_WGT_PFC_IMAP_MAX_VAL) ||
			    (offset != NBL_CFG_TC_WGT &&
			     offset != NBL_CFG_PFC_IMAP &&
			     var_arr[i] > NBL_PRI_MAX_VAL)) {
				nbl_pr_err(
					"qos params %s val[%d]:%d(%#x) is invalid.\n",
					nbl_dbg_qos_name[offset], i, var_arr[i],
					var_arr[i]);
				return -EINVAL;
			}
		}
		break;
	case NBL_CFG_DB_TO_CSCH_EN:
		if (var_arr[0] > NBL_DB_TO_CSCH_EN_MASK)
			return -EINVAL;
		break;
	case NBL_CFG_SW_DB_CSCH_TH:
	case NBL_CFG_CSCH_QLEN_TH:
		if (var_arr[0] > NBL_SW_DB_CSCH_TH_MAX)
			return -EINVAL;
		break;
	case NBL_CFG_POLL_WGT:
		if (var_cnt != NBL_POLL_WGT_NUM) {
			nbl_pr_err("qos params %s var_cnt:%d is invalid.\n",
				   nbl_dbg_qos_name[offset], var_cnt);
			return -EINVAL;
		}
		for (i = 0; i < NBL_POLL_WGT_NUM; i++) {
			if (var_arr[i] > NBL_WGT_PFC_IMAP_MAX_VAL) {
				nbl_pr_err(
					"qos params %s val[%d]:%d(%#x) is invalid.\n",
					nbl_dbg_qos_name[offset], i, var_arr[i],
					var_arr[i]);
				return -EINVAL;
			}
		}
		break;
	case NBL_CFG_DWRR_EN:
		if (var_arr[0] > NBL_ENABLE_MASK)
			return -EINVAL;
		break;
	case NBL_CFG_SPWRR:
		if (var_arr[0] > NBL_SPWRR_CFG_MAX)
			return -EINVAL;
		break;
	case NBL_CFG_SET_PFC:
		if (var_cnt != NBL_PRI_NUM) {
			nbl_pr_err("qos params %s var_cnt:%d is invalid.\n",
				   nbl_dbg_qos_name[offset], var_cnt);
			return -EINVAL;
		}
		for (i = 0; i < NBL_PRI_NUM; i++) {
			if (var_arr[i] > NBL_ENABLE_MASK) {
				nbl_pr_err(
					"qos params %s val[%d]:%d(%#x) is invalid.\n",
					nbl_dbg_qos_name[offset], i, var_arr[i],
					var_arr[i]);
				return -EINVAL;
			}
		}
		break;
	case NBL_CFG_TRUST_DSCP_EN:
		if (var_arr[0] > NBL_ENABLE_MASK)
			return -EINVAL;
		break;
	case NBL_CFG_SET_PFC_BUF:
		if (var_cnt != NBL_PFC_CFG_NUM) {
			nbl_pr_err("qos params %s var_cnt:%d is invalid.\n",
				   nbl_dbg_qos_name[offset], var_cnt);
			return -EINVAL;
		}

		if (var_arr[NBL_PFC_CFG_PRI_OFFSET] > NBL_PRI_NUM) {
			nbl_pr_err("qos params %s val[%d]:%d(%#x) is invalid.\n",
				nbl_dbg_qos_name[offset], NBL_PFC_CFG_PRI_OFFSET,
				var_arr[NBL_PFC_CFG_PRI_OFFSET], var_arr[NBL_PFC_CFG_PRI_OFFSET]);
			return -EINVAL;
		}

		if (var_arr[NBL_PFC_CFG_XOFF_OFFSET] < var_arr[NBL_PFC_CFG_XON_OFFSET]) {
			nbl_pr_err("qos params %s xoff[%d] < xon[%d] is invalid.\n",
				nbl_dbg_qos_name[offset], var_arr[NBL_PFC_CFG_XOFF_OFFSET],
				var_arr[NBL_PFC_CFG_XON_OFFSET]);
			return -EINVAL;
		}

		if (var_arr[NBL_PFC_CFG_XOFF_OFFSET] > NBL_PFC_BUF_MAX_VAL ||
			var_arr[NBL_PFC_CFG_XON_OFFSET] > NBL_PFC_BUF_MAX_VAL) {
			nbl_pr_err("qos params %s xoff or xon should be less than 1620.\n",
				nbl_dbg_qos_name[offset]);
			return -EINVAL;
		}
		break;
	case NBL_CFG_SET_DSCP_TO_PRI:
	case NBL_CFG_SET_8021P_TO_PRI:
		if (var_cnt != NBL_PKT2PRI_CFG_NUM) {
			nbl_pr_err("qos params %s var_cnt:%d is invalid.\n",
				   nbl_dbg_qos_name[offset], var_cnt);
			return -EINVAL;
		}

		pkt_max = offset == NBL_CFG_SET_DSCP_TO_PRI ? NBL_DSCP_NUM : NBL_PRI_NUM;
		if (var_arr[NBL_PKT2PRI_CFG_PKT_OFFSET] > pkt_max) {
			nbl_pr_err("qos params %s. the 1st param[%d] should be less than %d\n",
				nbl_dbg_qos_name[offset],
				var_arr[NBL_PKT2PRI_CFG_PRI_OFFSET], pkt_max);
			return -EINVAL;
		}

		if (var_arr[NBL_PKT2PRI_CFG_PRI_OFFSET] > NBL_PRI_NUM) {
			nbl_pr_err("qos params %s. the 2nd param[%d] should be less than %d\n",
				nbl_dbg_qos_name[offset],
				var_arr[NBL_PKT2PRI_CFG_PRI_OFFSET], NBL_PRI_NUM);
			return -EINVAL;
		}
		break;
	case NBL_CFG_QOS_SAVE:
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int nbl_ib_set_qos_param_into_reg(struct nbl_device *dev, int offset,
					 u32 *var)
{
	int ret;
	u32 reg_offset = 0;
	union rdma_sq_raq_pri_map_cfg pri_map;
	union rdma_tc_wgt_cfg_tbl tc_wgt_map;
	union rdma_pfc_imap_cfg pfc_imap;
	union rdma_poll_wgt_cfg poll_wgt;

	reg_offset = dev->rf->product->qos_ops->get_reg_offset(dev->rf,
							      offset);

	switch (offset) {
	case NBL_CFG_TC_PRI:
		ret = nbl_set_tc_pri(dev, var);
		break;
	case NBL_CFG_SQ_PRI_MAP:
	case NBL_CFG_RAQ_PRI_MAP:
	case NBL_CFG_PRI_IMAP:
		if (!reg_offset) {
			nbl_pr_err("reg address is invalid.\n");
			return -EINVAL;
		}
		pri_map.pri0 = var[0];
		pri_map.pri1 = var[1];
		pri_map.pri2 = var[2];
		pri_map.pri3 = var[3];
		pri_map.pri4 = var[4];
		pri_map.pri5 = var[5];
		pri_map.pri6 = var[6];
		pri_map.pri7 = var[7];
		ret = nbl_grc_write_reg(dev->rf, reg_offset, pri_map.data[0]);
		if (ret)
			nbl_pr_err(
				"failed to set qos params %s into reg:%#x val:%#x\n",
				nbl_dbg_qos_name[offset], reg_offset,
				pri_map.data[0]);
		break;

	case NBL_CFG_TC_WGT:
		if (!reg_offset) {
			nbl_pr_err("reg address is invalid.\n");
			return -EINVAL;
		}
		tc_wgt_map.tc0_wgt = var[0];
		tc_wgt_map.tc1_wgt = var[1];
		tc_wgt_map.tc2_wgt = var[2];
		tc_wgt_map.tc3_wgt = var[3];
		tc_wgt_map.tc4_wgt = var[4];
		tc_wgt_map.tc5_wgt = var[5];
		tc_wgt_map.tc6_wgt = var[6];
		tc_wgt_map.tc7_wgt = var[7];
		/* 64bit wide reg, split two write op */
		ret = nbl_grc_write_reg(dev->rf, reg_offset,
					tc_wgt_map.data[0]);
		ret += nbl_grc_write_reg(dev->rf, reg_offset + 4,
					 tc_wgt_map.data[1]);
		if (ret)
			nbl_pr_err(
				"failed to set qos params %s into reg:%#x val:%#x %#x\n",
				nbl_dbg_qos_name[offset], reg_offset,
				tc_wgt_map.data[0], tc_wgt_map.data[1]);
		break;
	case NBL_CFG_PFC_IMAP:
		if (!reg_offset) {
			nbl_pr_err("reg address is invalid.\n");
			return -EINVAL;
		}
		pfc_imap.pri0_map = var[0];
		pfc_imap.pri1_map = var[1];
		pfc_imap.pri2_map = var[2];
		pfc_imap.pri3_map = var[3];
		pfc_imap.pri4_map = var[4];
		pfc_imap.pri5_map = var[5];
		pfc_imap.pri6_map = var[6];
		pfc_imap.pri7_map = var[7];
		/* 64bit wide reg, split two write op */
		ret = nbl_grc_write_reg(dev->rf, reg_offset, pfc_imap.data[0]);
		ret += nbl_grc_write_reg(dev->rf, reg_offset + 4,
					 pfc_imap.data[1]);
		if (ret)
			nbl_pr_err(
				"failed to set qos params %s into reg:%#x val:%#x %#x\n",
				nbl_dbg_qos_name[offset], reg_offset,
				pfc_imap.data[0], pfc_imap.data[1]);
		break;
	case NBL_CFG_DB_TO_CSCH_EN:
	case NBL_CFG_SW_DB_CSCH_TH:
	case NBL_CFG_CSCH_QLEN_TH:
	case NBL_CFG_DWRR_EN:
		if (!reg_offset) {
			nbl_pr_err("reg address is invalid.\n");
			return -EINVAL;
		}
		ret = nbl_grc_write_reg(dev->rf, reg_offset, var[0]);
		if (ret)
			nbl_pr_err(
				"failed to set qos params %s into reg:%#x val:%#x\n",
				nbl_dbg_qos_name[offset], reg_offset, var[0]);
		break;
	case NBL_CFG_SPWRR:
		ret = nbl_set_spwrr(dev, var);
		break;
	case NBL_CFG_POLL_WGT:
		if (!reg_offset) {
			nbl_pr_err("reg address is invalid.\n");
			return -EINVAL;
		}
		poll_wgt.csch = var[0];
		poll_wgt.sch = var[1];
		poll_wgt.rnr = var[2];
		poll_wgt.rto = var[3];
		ret = nbl_grc_write_reg(dev->rf, reg_offset, poll_wgt.data[0]);
		if (ret)
			nbl_pr_err(
				"failed to set qos params %s into reg:%#x val:%#x\n",
				nbl_dbg_qos_name[offset], reg_offset,
				poll_wgt.data[0]);
		break;
	case NBL_CFG_SET_PFC:
		ret = nbl_set_pfc_en(dev, var);
		break;
	case NBL_CFG_TRUST_DSCP_EN:
		ret = nbl_trust_dscp_en(dev, var[0]);
		break;
	case NBL_CFG_SET_PFC_BUF:
		ret = nbl_set_pfc_buf(dev, var);
		break;
	case NBL_CFG_SET_DSCP_TO_PRI:
	case NBL_CFG_SET_8021P_TO_PRI:
		ret = nbl_set_pkt2pri(dev, (offset == NBL_CFG_SET_DSCP_TO_PRI), var);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int nbl_ib_set_qos_params(struct nbl_device *dev, int offset, u32 *var)
{
	int ret;

	/* does not work during initialization */
	if (offset == NBL_CFG_QOS_SAVE) {
		ret = nbl_ib_save_process(dev);
		if (ret)
			nbl_pr_err("failed to save qos params\n");
	} else {
		ret = nbl_ib_set_qos_param_into_reg(dev, offset, var);
		if (ret)
			nbl_pr_err("failed to set qos params into reg.\n");
	}

	return ret;
}

static ssize_t set_qos_param(struct file *filp, const char __user *buf,
			     size_t count, loff_t *pos)
{
	struct nbl_ib_dbg_param *param = filp->private_data;
	int offset = param->offset;
	char lbuf[NBL_PARAM_LEN] = {};
	char save_buf[NBL_PARAM_LEN] = {};
	char *s = lbuf;
	int ret;
	u32 var_arr[NBL_PRI_NUM];
	int var_cnt = 0;
	struct nbl_device *nbl_dev = param->dev;
	struct nbl_pci_f *rf = nbl_dev->rf;
	union rdma_tc_wgt_cfg_tbl *tc_wgt = &rf->sc_dev.tc_wgt;

	if (count > sizeof(lbuf))
		return -EINVAL;

	if (copy_from_user(lbuf, buf, count))
		return -EFAULT;

	nbl_pr_dbg("config qos param:%s val:%s count:%zu\n",
		   param->dentry->d_iname, lbuf, count);
strscpy(save_buf, lbuf, sizeof(save_buf));
	while (s && *s) {
		char *str = strsep(&s, ",");
		u32 var;

		if (!str)
			continue;

		if (kstrtou32(str, 0, &var))
			goto err;

		if (var_cnt >= NBL_PRI_NUM)
			goto err;

		var_arr[var_cnt] = var;
		nbl_pr_dbg("var[%d]:%d(%#x)\n", var_cnt, var, var);
		var_cnt++;
	}

	ret = nbl_ib_check_qos_param_val(offset, var_arr, var_cnt);
	if (ret) {
		nbl_pr_err(
			"config qos param:%s is invalid, please check the param.\n",
			param->dentry->d_iname);
		return ret;
	}

	ret = nbl_ib_set_qos_params(param->dev, offset, var_arr);
	if (ret != 0)
		return count;

	switch (offset) {
	case NBL_CFG_TC_WGT:
		tc_wgt->tc0_wgt = var_arr[0];
		tc_wgt->tc1_wgt = var_arr[1];
		tc_wgt->tc2_wgt = var_arr[2];
		tc_wgt->tc3_wgt = var_arr[3];
		tc_wgt->tc4_wgt = var_arr[4];
		tc_wgt->tc5_wgt = var_arr[5];
		tc_wgt->tc6_wgt = var_arr[6];
		tc_wgt->tc7_wgt = var_arr[7];
		break;
	default:
strscpy(rf->sc_dev.qos_dbgfs_params[offset], save_buf,
					sizeof(rf->sc_dev.qos_dbgfs_params[offset]));
		nbl_pr_dbg("save %s:%s\n", nbl_dbg_qos_name[offset],
			   rf->sc_dev.qos_dbgfs_params[offset]);
		break;
	}

	return ret ? ret : count;
err:
	nbl_pr_err("config qos param:%s is invalid, please check the param.\n",
		   param->dentry->d_iname);
	return -EINVAL;
}

static ssize_t get_qos_param(struct file *filp, char __user *buf, size_t count,
			     loff_t *pos)
{
	struct nbl_ib_dbg_param *param = filp->private_data;
	struct nbl_device *nbl_dev = param->dev;
	struct nbl_pci_f *rf = nbl_dev->rf;
	int offset = param->offset;
	union rdma_tc_wgt_cfg_tbl *tc_wgt;
	int ret;
	char lbuf[NBL_PARAM_LEN];

	switch (offset) {
	case NBL_CFG_TC_PRI:
		memset(lbuf, '\0', NBL_PARAM_LEN);
		ret = snprintf(lbuf, sizeof(lbuf),
				"%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",
				NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 0),
				NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 1),
				NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 2),
				NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 3),
				NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 4),
				NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 5),
				NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 6),
				NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 7));
		break;
	case NBL_CFG_TC_WGT:
		tc_wgt = &rf->sc_dev.tc_wgt;
		memset(lbuf, '\0', NBL_PARAM_LEN);
		ret = snprintf(lbuf, sizeof(lbuf), "%d,%d,%d,%d,%d,%d,%d,%d\n",
			       tc_wgt->tc0_wgt, tc_wgt->tc1_wgt,
			       tc_wgt->tc2_wgt, tc_wgt->tc3_wgt,
			       tc_wgt->tc4_wgt, tc_wgt->tc5_wgt,
			       tc_wgt->tc6_wgt, tc_wgt->tc7_wgt);
		break;
	case NBL_CFG_SET_PFC:
	case NBL_CFG_SET_PFC_BUF:
		ret = nbl_get_pfc_cfg(nbl_dev, lbuf);
		break;
	case NBL_CFG_SET_DSCP_TO_PRI:
	case NBL_CFG_SET_8021P_TO_PRI:
		ret = nbl_get_pkt2pri_cfg(nbl_dev, lbuf);
		break;
	default:
		ret = snprintf(lbuf, sizeof(lbuf), "%s",
			       rf->sc_dev.qos_dbgfs_params[offset]);
		break;
	}
	return simple_read_from_buffer(buf, count, pos, lbuf, ret);
}

ssize_t config_qos_param(struct nbl_device *nbldev, int offset, char *lbuf)
{
	char save_buf[NBL_PARAM_LEN] = {};
	char *s = lbuf;
	int ret;
	u32 var_arr[NBL_PRI_NUM];
	int var_cnt = 0;
	struct nbl_pci_f *rf = nbldev->rf;
	union rdma_tc_wgt_cfg_tbl *tc_wgt = &rf->sc_dev.tc_wgt;

strscpy(save_buf, lbuf, sizeof(save_buf));
	while (s && *s) {
		char *str = strsep(&s, ",");
		u32 var;

		if (!str)
			continue;

		if (kstrtou32(str, 0, &var))
			goto err;

		if (var_cnt >= NBL_PRI_NUM)
			goto err;

		var_arr[var_cnt] = var;
		nbl_pr_dbg("var[%d]:%d(%#x)\n", var_cnt, var, var);
		var_cnt++;
	}

	ret = nbl_ib_check_qos_param_val(offset, var_arr, var_cnt);
	if (ret) {
		nbl_pr_err(
			"config qos param:%s is invalid, please check the param.\n",
			nbl_dbg_qos_name[offset]);
		return ret;
	}

	ret = nbl_ib_set_qos_params(nbldev, offset, var_arr);
	if (ret != 0)
		return ret;

	switch (offset) {
	case NBL_CFG_TC_WGT:
		tc_wgt->tc0_wgt = var_arr[0];
		tc_wgt->tc1_wgt = var_arr[1];
		tc_wgt->tc2_wgt = var_arr[2];
		tc_wgt->tc3_wgt = var_arr[3];
		tc_wgt->tc4_wgt = var_arr[4];
		tc_wgt->tc5_wgt = var_arr[5];
		tc_wgt->tc6_wgt = var_arr[6];
		tc_wgt->tc7_wgt = var_arr[7];
		break;
	default:
strscpy(rf->sc_dev.qos_dbgfs_params[offset], save_buf,
					sizeof(rf->sc_dev.qos_dbgfs_params[offset]));
		nbl_pr_dbg("save %s:%s\n", nbl_dbg_qos_name[offset],
				rf->sc_dev.qos_dbgfs_params[offset]);
		break;
	}

	return ret;
err:
	nbl_pr_err("config qos param:%s is invalid, please check the param.\n",
		   nbl_dbg_qos_name[offset]);
	return -EINVAL;
}

int show_qos_param(struct nbl_device *nbldev, int offset, char *lbuf)
{
	struct nbl_pci_f *rf = nbldev->rf;
	union rdma_tc_wgt_cfg_tbl *tc_wgt;
	int ret;

	switch (offset) {
	case NBL_CFG_TC_PRI:
		memset(lbuf, '\0', NBL_PARAM_LEN);
		ret = snprintf(lbuf, NBL_PARAM_LEN,
				"%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",
				NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 0),
				NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 1),
				NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 2),
				NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 3),
				NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 4),
				NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 5),
				NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 6),
				NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 7));
		break;
	case NBL_CFG_TC_WGT:
		tc_wgt = &rf->sc_dev.tc_wgt;
		memset(lbuf, '\0', NBL_PARAM_LEN);
		ret = snprintf(lbuf, NBL_PARAM_LEN, "%d,%d,%d,%d,%d,%d,%d,%d\n",
			       tc_wgt->tc0_wgt, tc_wgt->tc1_wgt,
			       tc_wgt->tc2_wgt, tc_wgt->tc3_wgt,
			       tc_wgt->tc4_wgt, tc_wgt->tc5_wgt,
			       tc_wgt->tc6_wgt, tc_wgt->tc7_wgt);
		break;
	case NBL_CFG_SET_PFC:
	case NBL_CFG_SET_PFC_BUF:
		ret = nbl_get_pfc_cfg(nbldev, lbuf);
		break;
	case NBL_CFG_SET_DSCP_TO_PRI:
	case NBL_CFG_SET_8021P_TO_PRI:
		ret = nbl_get_pkt2pri_cfg(nbldev, lbuf);
		break;
	default:
		ret = snprintf(lbuf, NBL_PARAM_LEN, "%s",
			       rf->sc_dev.qos_dbgfs_params[offset]);
		break;
	}

	return ret;
}

static const struct file_operations dbg_qos_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = set_qos_param,
	.read = get_qos_param,
};

static void nbl_ib_cleanup_qos_debugfs(struct nbl_device *dev)
{
	if (!dev->func_dbg_dir || !dev->qos_params)
		return;

	debugfs_remove_recursive(dev->qos_params->qos_root);
	kfree(dev->qos_params);
}

static bool nbl_qos_debugfs_param_supported_v2(int offset)
{
	return offset != NBL_CFG_SET_PFC &&
		offset != NBL_CFG_TRUST_DSCP_EN &&
		offset != NBL_CFG_SET_PFC_BUF &&
		offset != NBL_CFG_SET_DSCP_TO_PRI &&
		offset != NBL_CFG_SET_8021P_TO_PRI;
}

static bool nbl_qos_debugfs_param_supported_v3(int offset)
{
	return offset != NBL_CFG_SET_DSCP_TO_PRI &&
		offset != NBL_CFG_SET_8021P_TO_PRI;
}

static bool nbl_qos_debugfs_param_supported_v4(int offset)
{
	return true;
}

static int nbl_ib_init_qos_debugfs(struct nbl_device *dev)
{
	struct nbl_ib_dbg_qos_params *qos_params;
	int i;

	if (!dev->func_dbg_dir)
		return -EINVAL;

	qos_params = kzalloc(sizeof(*qos_params), GFP_KERNEL);
	if (!qos_params) {
		dev->qos_params = NULL;
		goto err;
	}

	dev->qos_params = qos_params;
	qos_params->qos_root =
		debugfs_create_dir("qos_params", dev->func_dbg_dir);
	if (!qos_params->qos_root) {
		nbl_pr_err("init qos_params directory failed\n");
		goto err;
	}

	for (i = NBL_CFG_QOS_SAVE; i < NBL_CFG_QOS_TYPE_MAX; i++) {
		if (!dev->rf->product->qos_ops->debugfs_param_supported(i))
			continue;
		qos_params->params[i].offset = i;
		qos_params->params[i].dev = dev;
		qos_params->params[i].dentry = debugfs_create_file(
			nbl_dbg_qos_name[i], 0600, qos_params->qos_root,
			&qos_params->params[i], &dbg_qos_fops);
	}

	return 0;

err:
	nbl_ib_cleanup_qos_debugfs(dev);
	return -ENOMEM;
}

static void nbl_qos_default_cfg_v2(struct nbl_device *dev)
{
	/* PF Level QoS cfg init */
	nbl_update_p2s_cfg(dev, 1);
	nbl_grc_write_reg(
		dev->rf,
		NBL_DSCH_TC_WGT_CFG_ADDR(NBL_REG_DSCH_BASE_V2,
					 dev->rf->sc_dev.function_id, 0),
		NBL_QOS_DEFAULT_TC_WGT);
	nbl_grc_write_reg(
		dev->rf,
		NBL_DSCH_TC_WGT_CFG_ADDR(NBL_REG_DSCH_BASE_V2,
					 dev->rf->sc_dev.function_id, 4),
		NBL_QOS_DEFAULT_TC_WGT);
}

static void nbl_qos_default_cfg_v3_common(struct nbl_device *dev,
					  int (*set_pfc_en)(struct nbl_device *,
							    u32 *))
{
	u32 var_arr[NBL_PRI_NUM] = {1, 1, 1, 1, 1, 1, 1, 1};

	nbl_trust_dscp_en(dev, 1);
	set_pfc_en(dev, var_arr); /* default enable pfc */
	nbl_grc_write_reg(dev->rf,
			  NBL_DSCH_TC_WGT_CFG_ADDR(NBL_REG_DSCH_BASE(&dev->rf->hw),
						   dev->rf->sc_dev.function_id, 0),
		NBL_QOS_DEFAULT_TC_WGT_V3);
	nbl_grc_write_reg(dev->rf,
			  NBL_DSCH_TC_WGT_CFG_ADDR(NBL_REG_DSCH_BASE(&dev->rf->hw),
						   dev->rf->sc_dev.function_id, 4),
		NBL_QOS_DEFAULT_TC_WGT_V3);
	nbl_grc_write_reg(
		dev->rf,
		NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V3, NBL_DSCH_IMAP_CFG_OFF_V3),
		NBL_QOS_DEFAULT_PRI_IMAP);
	nbl_grc_write_reg(
		dev->rf,
		NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V3, NBL_DSCH_SQ_PRI_MAP_CFG_OFF_V3),
		NBL_QOS_DEFAULT_SQ_PRI_MAP);
	nbl_grc_write_reg(
		dev->rf,
		NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V3, NBL_DSCH_RAQ_PRI_MAP_CFG_OFF_V3),
		NBL_QOS_DEFAULT_RAQ_PRI_MAP);
	nbl_grc_write_reg(
		dev->rf,
		NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V3, NBL_DSCH_PRI03_MAP_CFG_OFF_V3),
		NBL_QOS_DEFAULT_PRI03_MAP);
	nbl_grc_write_reg(
		dev->rf,
		NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V3, NBL_DSCH_PRI47_MAP_CFG_OFF_V3),
		NBL_QOS_DEFAULT_PRI47_MAP);
	nbl_grc_write_reg(
		dev->rf,
		NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V3, NBL_DSCH_PRI03_P2S_MAP_OFF_V3),
		NBL_QOS_DEFAULT_PRI03_P2S_MAP);
	nbl_grc_write_reg(
		dev->rf,
		NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V3, NBL_DSCH_PRI47_P2S_MAP_OFF_V3),
		NBL_QOS_DEFAULT_PRI47_P2S_MAP);
}

static void nbl_qos_default_cfg_v3(struct nbl_device *dev)
{
	nbl_qos_default_cfg_v3_common(dev, nbl_set_pfc_en_v3);
}

static void nbl_qos_default_cfg_v4(struct nbl_device *dev)
{
	u32 var_pfc[NBL_PFC_CFG_NUM] = {0, 320, 288};
	u32 i;

	nbl_qos_default_cfg_v3_common(dev, nbl_set_pfc_en_v4);
	nbl_grc_write_reg(dev->rf,
			  NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE_V3,
					    NBL_DSCH_TC_GHOST_BITMAP_OFF_V3),
		NBL_QOS_TC_GHOST_BITMAP_DFT);
	/* UBM PFC TSH */
	nbl_grc_write_reg(dev->rf, NBL_UBM_PFC_TSH_ADDR(NBL_REG_UBM_BASE_V4),
		NBL_PFC_CFG_UBM_TSH_DEF_V4);
	/* UQM PFC TSH */
	for (i = 0; i < NBL_PRI_NUM; i++) {
		var_pfc[NBL_PFC_CFG_PRI_OFFSET] = i;
		nbl_set_pfc_buf(dev, var_pfc);
	}
}

static void nbl_qos_default_cfg(struct nbl_device *dev)
{
	dev->rf->product->qos_ops->default_cfg(dev);
}

const struct nbl_qos_ops nbl_df200_qos_ops = {
	.update_p2s_cfg = nbl_update_p2s_cfg_v3,
	.set_pfc_en = nbl_set_pfc_en_v3,
	.set_pfc_buf = nbl_set_pfc_buf_v3,
	.get_pfc_cfg = nbl_get_pfc_cfg_v3,
	.trust_dscp_en = nbl_trust_dscp_en_v3,
	.get_reg_offset = nbl_get_qos_reg_offset_v3,
	.debugfs_param_supported = nbl_qos_debugfs_param_supported_v3,
	.default_cfg = nbl_qos_default_cfg_v3,
};

const struct nbl_qos_ops nbl_draco_qos_ops = {
	.update_p2s_cfg = nbl_update_p2s_cfg_v2,
	.set_tc_pri = nbl_set_tc_pri_v4,
	.set_pfc_en = nbl_set_pfc_en_v2,
	.check_spwrr_cfg = nbl_check_spwrr_cfg_v2,
	.set_pfc_buf = nbl_set_pfc_buf_v2,
	.set_pkt2pri = nbl_set_pkt2pri_v2,
	.get_pfc_cfg = nbl_get_pfc_cfg_v2,
	.get_pkt2pri_cfg = nbl_get_pkt2pri_cfg_v2,
	.trust_dscp_en = nbl_trust_dscp_en_v2,
	.get_reg_offset = nbl_get_qos_reg_offset_v2,
	.debugfs_param_supported = nbl_qos_debugfs_param_supported_v2,
	.default_cfg = nbl_qos_default_cfg_v2,
};

const struct nbl_qos_ops nbl_rnic400_qos_ops = {
	.update_p2s_cfg = nbl_update_p2s_cfg_v3,
	.set_tc_pri = nbl_set_tc_pri_v4,
	.set_pfc_en = nbl_set_pfc_en_v4,
	.check_spwrr_cfg = nbl_check_spwrr_cfg_v3,
	.set_pfc_buf = nbl_set_pfc_buf_v4,
	.set_pkt2pri = nbl_set_pkt2pri_v3,
	.get_pfc_cfg = nbl_get_pfc_cfg_v4,
	.get_pkt2pri_cfg = nbl_get_pkt2pri_cfg_v3,
	.trust_dscp_en = nbl_trust_dscp_en_v4,
	.get_reg_offset = nbl_get_qos_reg_offset_v3,
	.debugfs_param_supported = nbl_qos_debugfs_param_supported_v4,
	.default_cfg = nbl_qos_default_cfg_v4,
};

void nbl_dbgfs_qos_init(struct nbl_device *dev)
{
	if (nbl_ib_init_qos_debugfs(dev)) {
		nbl_pr_err("nbl_ib_init_qos_debugfs failed.\n");
		return;
	}

	nbl_qos_default_cfg(dev);

	nbl_load_qos_dev_cfg(dev);
}

void nbl_dbgfs_qos_deinit(struct nbl_device *dev)
{
	nbl_ib_cleanup_qos_debugfs(dev);
}
