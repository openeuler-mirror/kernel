// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include <linux/bitfield.h>
#include <linux/bitops.h>
#include <linux/vmalloc.h>
#include "main.h"
#include "hw.h"
#include "aeq.h"
#include "ceq.h"
#include "debug.h"
#include "pble.h"
#include "cqp.h"
#include "hmc.h"
#include "grc.h"
#include "qp.h"
#include "counters.h"
#include "dump_fields.h"
#include "srq.h"
#include "fpga_ver.h"
#include "nbl_rdma_module.h"

static void nbl_set_sd_range_tbl(struct nbl_hw *hw, u16 function_id,
				 u32 sd_start, u32 sd_cnt, bool valid)
{
	union nbl_sd_range_tbl_reg sd_range_tbl = {};
	u64 reg_addr;
	u32 *value;
	u32 sd_range;

	reg_addr = NBL_CQPP_SDBASE_TBL_ADDR(NBL_REG_CQPP_BASE(hw), function_id);

	if (valid) {
		sd_range_tbl.sd_base_idx = sd_start;
		sd_range_tbl.sd_max_num = sd_cnt;
		value = (u32 *)&sd_range_tbl;
		sd_range_tbl.sd_base_info_vld = valid;
	} else {
		sd_range = rd32(hw, reg_addr);
		sd_range &= ~((u32)BIT(31));
		value = &sd_range;
	}

	wr32(hw, reg_addr, *value);
}

static void nbl_set_vf_enable_tbl(struct nbl_hw *hw, u16 function_id, u8 enable)
{
	u64 reg_addr;
	u32 value;
	u16 index;

	index = NBL_HDMA_VF_BITMAP_BIT(function_id);

	reg_addr = NBL_HDMA_VF_ENABLE_ADDR(NBL_REG_HDMA_BASE(hw), function_id);

	value = rd32(hw, reg_addr);
	nbl_pr_dbg("set vf enable,function_id=%u,enable=%u", function_id,
		   enable);

	if (enable) {
		value |= BIT(index);
		wr32(hw, reg_addr, value);

		reg_addr = NBL_HDMA_VF_CLEAR_ADDR(NBL_REG_HDMA_BASE(hw), function_id);

		value = rd32(hw, reg_addr);
		value |= BIT(index);
		wr32(hw, reg_addr, value);
	} else {
		value &= ~BIT(index);
		wr32(hw, reg_addr, value);
	}
}

/**
 * nbl_set_ecpu_notify - init ecpu notify for df200 ecpu
 * @hw:
 * @function_id: rdma function id for pf/vf
 * @enable: notify init flag,1:enable, 0:disable
 */
static void nbl_set_ecpu_notify(struct nbl_hw *hw, u16 function_id, u64 bar0_addr, u8 enable)
{
	u64 reg_addr = NBL_PCOMP_ECPU_QID_MAP_TABLE(function_id + NBL_PCOMP_RDMA_NOTIFY_OFFSET);
	union rdma_ecpu_qid_map_tbl_reg qid_map_tbl = {};

	qid_map_tbl.key.base_qid = function_id;
	qid_map_tbl.key.device_type = RDMA_ECPU_DEVICE_TYPE;
	qid_map_tbl.key.notify_bar_addr_l = (bar0_addr + NBL_ECPU_NOTIFY_OFFSET_v3) & 0xFFFF;
	qid_map_tbl.key.notify_bar_addr_h = (bar0_addr + NBL_ECPU_NOTIFY_OFFSET_v3) >> 16;
	qid_map_tbl.key.valid = enable;

	wr32_for_each(hw, reg_addr, qid_map_tbl.data, sizeof(qid_map_tbl));
}

static void nbl_set_cqp_reg(struct nbl_hw *hw, u16 function_id, u64 cqp_ba, u32 cqp_len, u8 enable)
{
	u64 regs_addr;
	union nbl_cqp_info_tbl_reg cqp_info_tbl_reg = {};
	u32 cqp_valid;
	u32 cqp_wait_time = 0;

	dev_dbg(hw->device, "cqp_ba=0x%llx,cqp_len=%u,function_id=%u,valid=%s",
		cqp_ba, cqp_len, function_id, enable ? "true" : "false");
	regs_addr = NBL_CQPP_CQPINFO_TBL_ADDR(NBL_REG_CQPP_BASE(hw), function_id);
	if (enable) {
		cqp_info_tbl_reg.key.cqp_base_addr_low =
			(u32)(cqp_ba & NBL_CQPP_CQPINFO_LOW_PA_MASK);
		cqp_info_tbl_reg.key.cqp_base_addr_high = (u32)(cqp_ba >> 32);

		cqp_info_tbl_reg.key.cqp_pi = 0;
		cqp_info_tbl_reg.key.cqp_pi_odd_even_flag = 0;

		cqp_info_tbl_reg.key.cqp_ci = 0;
		cqp_info_tbl_reg.key.cqp_ci_odd_even_flag = 0;
		cqp_info_tbl_reg.key.wqe_mem_type = 0;
		cqp_info_tbl_reg.key.cqp_info_vld = 1;

		wr32_for_each(hw, regs_addr, cqp_info_tbl_reg.data, sizeof(cqp_info_tbl_reg));

		regs_addr += NBL_CQPP_CQPINFO_VALID_DW_OFF;
		while (cqp_wait_time < NBL_CQP_MAX_WAIT_TIME) {
			cqp_valid = rd32(hw, regs_addr);
			if (cqp_valid & BIT(31))
				break;

			mdelay(NBL_CQP_WAIT_PERIOD);
			cqp_wait_time++;
			dev_warn(hw->device, "wait cqp_ram_info valid time=%u", cqp_wait_time);
		}
	} else {
		regs_addr += NBL_CQPP_CQPINFO_VALID_DW_OFF;
		cqp_valid = rd32(hw, regs_addr);
		cqp_valid &= ~BIT(31);
		wr32(hw, regs_addr, cqp_valid);
	}
}

static void nbl_set_vfid_vsi_map_tbl(struct nbl_hw *hw, u16 function_id, u16 vsi_id, bool enable)
{
	u64 reg_addr;
	union qm_vsi_mapping_tbl vsi_map = {};

	vsi_map.vf_id = function_id;
	vsi_map.valid = enable;

	reg_addr = NBL_QM_VSI_MAPPING_TBL_ADDR(NBL_REG_QM_BASE(hw), vsi_id);
	nbl_pr_dbg("QM_VSI_MAPPING_TBL addr=0x%llx for vsi_id=%u\n", reg_addr,
		   vsi_id);
	wr32(hw, reg_addr, vsi_map.data[0]);
}

static void nbl_set_rdma_net_en(struct nbl_hw *hw, u16 function_id,
				const struct nbl_dsch_layout *layout)
{
	u64 reg_addr;
	u32 rdma_net_en_val = 0;
	u32 index = function_id % NBL_DSCH_NET_EN_REG_BITS;

	reg_addr = NBL_REG_DSCH_BASE(hw) +
		layout->net_en_offset + 4 * (function_id / NBL_DSCH_NET_EN_REG_BITS);
	rdma_net_en_val = rd32(hw, reg_addr);
	rdma_net_en_val |= BIT(index);
	wr32(hw, reg_addr, rdma_net_en_val);
}

static void nbl_clear_rdma_net_en(struct nbl_hw *hw, u16 function_id,
				  const struct nbl_dsch_layout *layout)
{
	u64 reg_addr;
	u32 rdma_net_en_val = 0;
	u32 index = function_id % NBL_DSCH_NET_EN_REG_BITS;

	reg_addr = NBL_REG_DSCH_BASE(hw) +
		layout->net_en_offset + 4 * (function_id / NBL_DSCH_NET_EN_REG_BITS);
	rdma_net_en_val = rd32(hw, reg_addr);
	rdma_net_en_val &= ~BIT(index);
	wr32(hw, reg_addr, rdma_net_en_val);
}

static bool nbl_check_netnode_if_flush(struct nbl_hw *hw, u16 function_id)
{
	u64 reg_addr;
	bool rdma_tc_q_flush = true;
	bool rdma_dbq_flush = true;
	u16 net_tc;
	u32 attr_val;
	union rdma_tc_q_list_attr_tbl tc_q_list = {};

	reg_addr = NBL_DSCH_DBQ_ATTR_TBL_ADDR(NBL_REG_DSCH_BASE(hw), function_id);
	for (net_tc = 0; net_tc < NBL_DSCH_TC_NUM; net_tc++) {
		attr_val = rd32(hw, reg_addr + net_tc * NBL_DSCH_DBQ_ATTR_TC_STRIDE);
		if (attr_val & NBL_DSCH_DBQ_ATTR_TBL_NEMPTY) {
			rdma_dbq_flush = false;
			break;
		}
	}

	reg_addr = NBL_DSCH_TC_Q_LIST_ATTR_TBL_ADDR(NBL_REG_DSCH_BASE(hw), function_id);
	for (net_tc = 0; net_tc < NBL_DSCH_TC_NUM; net_tc++) {
		tc_q_list.data[0] = rd32(hw, reg_addr +
					 net_tc * NBL_DSCH_TC_Q_LIST_ATTR_TC_STRIDE);
		if (tc_q_list.fly || tc_q_list.rlen || tc_q_list.wlen) {
			rdma_tc_q_flush = false;
			break;
		}
	}

	if (!rdma_tc_q_flush || !rdma_dbq_flush) {
		dev_warn(hw->device, "func=%u,rdma_tc_q_flush=%u,rdma_dbq_flush=%u\n",
			 function_id, rdma_tc_q_flush, rdma_dbq_flush);
		return false;
	}

	return true;
}

static bool nbl_check_netnode_is_init(struct nbl_hw *hw, u16 net_id)
{
	u64 reg_addr;
	union rdma_grp_net_list_tbl net_list_tbl = {};

	reg_addr = NBL_DSCH_GRP_NET_LIST_TBL_ADDR(NBL_REG_DSCH_BASE(hw), net_id);
	net_list_tbl.data[0] = rd32(hw, reg_addr);
	if (net_list_tbl.valid || net_list_tbl.pfc || net_list_tbl.shaping_state)
		return false;

	return true;
}

static struct rdma_grp_node grp_list[NBL_DSCH_GRP_NODE_NUM];
static spinlock_t grp_list_lock;

static bool nbl_grp_node_if_need_disable(u16 grp_id)
{
	spin_lock(&grp_list_lock);
	if (grp_list[grp_id].count) {
		spin_unlock(&grp_list_lock);
		return false;
	}

	spin_unlock(&grp_list_lock);
	return true;
}

static bool nbl_check_grpnode_is_init(struct nbl_hw *hw, u16 grp_id)
{
	u64 reg_addr;
	union rdma_spt_grp_list_tbl grp_list_tbl = {};

	reg_addr = NBL_DSCH_SPT_GRP_LIST_TBL_ADDR(NBL_REG_DSCH_BASE(hw), grp_id);
	grp_list_tbl.data[0] = rd32(hw, reg_addr);
	if (grp_list_tbl.valid || grp_list_tbl.shaping_state)
		return false;

	return true;
}

static void nbl_disable_rdma_net(struct nbl_hw *hw, u16 function_id, bool vld,
				 const struct nbl_dsch_layout *layout)
{
	u64 reg_addr;
	union rdma_n2g_cfg_tbl n2g_map = {};
	u32 *value;
	bool net_flush_comp = false;
	bool net_init_state = false;
	bool need_check_flush = true;
	bool need_check_init = true;
	u16 grp_id = NBL_GET_DSCH_GRPID_BY_VFID(function_id);
	bool grp_flag = false;
	u16 retry_count = 0;

	/* 1) disable rdma_net_en */
	nbl_clear_rdma_net_en(hw, function_id, layout);

	do {
		mdelay(100);
		if (need_check_flush) {
			net_flush_comp = nbl_check_netnode_if_flush(hw, function_id);
			if (net_flush_comp)
				need_check_flush = false;
		}

		if (need_check_init) {
			net_init_state = nbl_check_netnode_is_init(hw, function_id);
			if (net_init_state)
				need_check_init = false;
		}

		if (net_flush_comp && net_init_state)
			break;

		nbl_pr_dbg("rdma%u netnode not init state(net_flush_comp=%u,init_state=%u),wait",
			   function_id, net_flush_comp, net_init_state);
		retry_count++;
	} while (retry_count < DSCH_RDMA_MAX_RETRY_COUNT);

	if (!net_flush_comp || !net_init_state)
		nbl_pr_err(
			"rdma%u netnode init timeout after 600ms ! final state: flush_comp=%u,init_state=%u",
			function_id, net_flush_comp, net_init_state);

	nbl_pr_dbg("clear n2g config for function=%u grp_id:%d", function_id,
		   grp_id);
	/* 2) disable net2grp */
	reg_addr = NBL_DSCH_N2G_CFG_TBL_ADDR(NBL_REG_DSCH_BASE(hw), function_id);
	value = (u32 *)&n2g_map;
	wr32(hw, reg_addr, *value);

	spin_lock(&grp_list_lock);
	clear_bit(function_id, grp_list[grp_id].net_id_list);
	grp_list[grp_id].count--;
	spin_unlock(&grp_list_lock);

	grp_flag = nbl_grp_node_if_need_disable(grp_id);
	if (grp_flag) {
		bool grp_init_state = false;

		retry_count = 0;
		do {
			mdelay(100);
			grp_init_state = nbl_check_grpnode_is_init(hw, grp_id);
			if (grp_init_state)
				break;
			nbl_pr_dbg("rdma%u grpnode not back to init state,waiting...",
				function_id);
			retry_count++;
		} while (retry_count < DSCH_RDMA_MAX_RETRY_COUNT);

		if (!grp_init_state)
			nbl_pr_err("rdma%u grpnode init timeout after 600ms!\n",
				function_id);
	}
}

/* Only Called by DF200 RNIC */
static void nbl_update_dsch_dport_id_direct(struct nbl_hw *hw, u16 function_id,
					    u32 host_id, u16 dport_id, u8 vld);
/* Only Called by DF200 RNIC */
static void nbl_enable_dsch(struct nbl_hw *hw, u16 function_id, u16 dport_id,
			    u32 host_id, bool vld,
			    const struct nbl_dsch_layout *layout)
{
	u64 reg_addr;
	union rdma_n2g_cfg_tbl n2g_map = {};
	union rdma_tc_wgt_cfg_tbl tc_wgt_map = {};
	union rdma_tc_spwrr_cfg_tbl tc_spwrr_map = {};
	union rdma_net2sha_map_tbl n2s_map = {};
	union rdma_grp2sha_map_tbl g2s_map = {};
	union rdma_sha2net_map_tbl s2n_map = {};
	union rdma_sha2grp_map_tbl s2g_map = {};
	u32 *value;

	nbl_pr_dbg(
		"enable rdma dsch regs for function_id=%u,host_id=%u,vld=%u\n",
		function_id, host_id, vld);

	/* 1) enable grp2port */
	nbl_update_dsch_dport_id_direct(hw, function_id, host_id, dport_id, vld);

	/* 2) enable net2grp */
	reg_addr = NBL_DSCH_N2G_CFG_TBL_ADDR(NBL_REG_DSCH_BASE(hw), function_id);
	n2g_map.vld = vld;
	n2g_map.grp_id = NBL_GET_DSCH_GRPID_BY_VFID(function_id);
	value = (u32 *)&n2g_map;
	wr32(hw, reg_addr, *value);

	/* 3) enable rdma_net_en */
	spin_lock(&grp_list_lock);
	set_bit(function_id, grp_list[n2g_map.grp_id].net_id_list);
	grp_list[n2g_map.grp_id].count++;
	spin_unlock(&grp_list_lock);
	nbl_set_rdma_net_en(hw, function_id, layout);

	reg_addr = NBL_DSCH_TC_WGT_CFG_TBL_ADDR(NBL_REG_DSCH_BASE(hw), function_id);
	value = &tc_wgt_map.data[0];
	wr32(hw, reg_addr, *value);
	value = &tc_wgt_map.data[1];
	wr32(hw, reg_addr + 4, *value);

	reg_addr = NBL_DSCH_TC_SPWRR_CFG_TBL_ADDR(NBL_REG_DSCH_BASE(hw), function_id);
	tc_spwrr_map.tc_spwrr = nbl_tm_algorithm_dwrr;
	value = (u32 *)&tc_spwrr_map;
	wr32(hw, reg_addr, *value);

	/* 4) enable sha2net,sha2grp */
	n2s_map.net_shaping_id = layout->min_net_shaping_id + function_id;
	reg_addr = NBL_DSCH_SHA2NET_MAP_TBL_ADDR(NBL_REG_DSCH_BASE(hw), n2s_map.net_shaping_id);
	s2n_map.vld = vld;
	s2n_map.rdma_vf_id = function_id;
	value = (u32 *)&s2n_map;
	wr32(hw, reg_addr, *value);

	g2s_map.grp_shaping_id = layout->min_grp_shaping_id +
		NBL_GET_DSCH_GRPID_BY_VFID(function_id);
	reg_addr = NBL_DSCH_SHA2GRP_MAP_TBL_ADDR(NBL_REG_DSCH_BASE(hw), g2s_map.grp_shaping_id);
	s2g_map.vld = vld;
	s2g_map.rdma_grp_id = n2g_map.grp_id;
	value = (u32 *)&s2g_map;
	wr32(hw, reg_addr, *value);

	/* 5) enable net2sha,grp2sha */
	reg_addr = NBL_DSCH_NET2SHA_MAP_TBL_ADDR(NBL_REG_DSCH_BASE(hw), function_id);
	n2s_map.vld = vld;
	n2s_map.net_shaping_id = layout->min_net_shaping_id + function_id;
	value = (u32 *)&n2s_map;
	wr32(hw, reg_addr, *value);

	reg_addr = NBL_DSCH_GRP2SHA_MAP_TBL_ADDR(NBL_REG_DSCH_BASE(hw), n2g_map.grp_id);
	g2s_map.vld = vld;
	g2s_map.grp_shaping_id = layout->min_grp_shaping_id + function_id;
	value = (u32 *)&g2s_map;
	wr32(hw, reg_addr, *value);
}

static void nbl_disable_dsch(struct nbl_hw *hw, u16 function_id, u32 host_id,
			     bool vld, const struct nbl_dsch_layout *layout)
{
	u64 reg_addr;
	union rdma_g2p_cfg_tbl g2p_map = {};
	union rdma_tc_wgt_cfg_tbl tc_wgt_map = {};
	union rdma_tc_spwrr_cfg_tbl tc_spwrr_map = {};
	union rdma_net2sha_map_tbl n2s_map = {};
	union rdma_grp2sha_map_tbl g2s_map = {};
	union rdma_sha2net_map_tbl s2n_map = {};
	union rdma_sha2grp_map_tbl s2g_map = {};
	u32 *value;
	bool grp_flag;
	u16 grp_id = NBL_GET_DSCH_GRPID_BY_VFID(function_id);

	nbl_pr_dbg(
		"disable rdma dsch regs for function_id=%u,host_id=%u, grp_id:%d vld=%u\n",
		function_id, host_id, grp_id, vld);

	nbl_disable_rdma_net(hw, function_id, vld, layout);

	reg_addr = NBL_DSCH_TC_WGT_CFG_TBL_ADDR(NBL_REG_DSCH_BASE(hw), function_id);
	value = &tc_wgt_map.data[0];
	wr32(hw, reg_addr, *value);
	value = &tc_wgt_map.data[1];
	wr32(hw, reg_addr + 4, *value);

	reg_addr = NBL_DSCH_TC_SPWRR_CFG_TBL_ADDR(NBL_REG_DSCH_BASE(hw), function_id);
	tc_spwrr_map.tc_spwrr = nbl_tm_algorithm_dwrr;
	value = (u32 *)&tc_spwrr_map;
	wr32(hw, reg_addr, *value);

	/* 3) disable sha2net */
	reg_addr = NBL_DSCH_NET2SHA_MAP_TBL_ADDR(NBL_REG_DSCH_BASE(hw), function_id);
	value = (u32 *)&n2s_map;
	*value = rd32(hw, reg_addr);

	reg_addr = NBL_DSCH_SHA2NET_MAP_TBL_ADDR(NBL_REG_DSCH_BASE(hw), n2s_map.net_shaping_id);
	value = (u32 *)&s2n_map;
	wr32(hw, reg_addr, *value);

	/* 4) disable net2sha */
	reg_addr = NBL_DSCH_NET2SHA_MAP_TBL_ADDR(NBL_REG_DSCH_BASE(hw), function_id);
	memset(&n2s_map, 0, sizeof(n2s_map));
	value = (u32 *)&n2s_map;
	wr32(hw, reg_addr, *value);

	/* 5) disable grp2port */
	reg_addr = NBL_DSCH_G2P_CFG_TBL_ADDR(NBL_REG_DSCH_BASE(hw), grp_id);
	value = (u32 *)&g2p_map;
	wr32(hw, reg_addr, *value);

	/* 6) disable sha2grp */
	reg_addr = NBL_DSCH_GRP2SHA_MAP_TBL_ADDR(NBL_REG_DSCH_BASE(hw), grp_id);
	value = (u32 *)&g2s_map;
	*value = rd32(hw, reg_addr);

	reg_addr = NBL_DSCH_SHA2GRP_MAP_TBL_ADDR(NBL_REG_DSCH_BASE(hw), g2s_map.grp_shaping_id);
	value = (u32 *)&s2g_map;
	grp_flag = nbl_grp_node_if_need_disable(grp_id);
	if (!vld && grp_flag)
		wr32(hw, reg_addr, *value);

	/* 7) disable grp2sha */
	reg_addr = NBL_DSCH_GRP2SHA_MAP_TBL_ADDR(NBL_REG_DSCH_BASE(hw), grp_id);
	memset(&g2s_map, 0, sizeof(g2s_map));
	value = (u32 *)&g2s_map;
	grp_flag = nbl_grp_node_if_need_disable(grp_id);
	if (!vld && grp_flag)
		wr32(hw, reg_addr, *value);
}

/* Only Called by DF200/RNIC400 */
static void nbl_pf_set_dsch_tbl(struct nbl_hw *hw, u16 function_id, u16 dport_id,
				u32 host_id, bool vld,
				const struct nbl_dsch_layout *layout)
{
	if (WARN_ON(!layout || (vld && !layout->direct_init)))
		return;

	if (layout->dport_table_depth && dport_id >= layout->dport_table_depth)
		/* dsch tbl depth is 2, 4 port bond no need configure pf2 and pf3 */
		return;

	if (vld)
		nbl_enable_dsch(hw, function_id, dport_id, host_id, vld, layout);
	else
		nbl_disable_dsch(hw, function_id, host_id, vld, layout);

	nbl_pr_dbg("setting dsch regs end function_id=%u,host_id=%u,valid=%u\n",
		     function_id, host_id, vld);
}

static void nbl_set_vf2vsi_map(struct nbl_hw *hw, u16 function_id, u16 vsi_id, bool valid)
{
	u64 reg_addr;
	union rdma_vf2vsi_cfg_tbl vf2vsi_map = {};

	vf2vsi_map.vsi_id = vsi_id;
	vf2vsi_map.valid = valid;

	reg_addr = NBL_DSCH_VF2VSI_CFG_TBL_ADDR(NBL_REG_DSCH_BASE(hw), function_id);
	wr32(hw, reg_addr, vf2vsi_map.data);
}

static void nbl_set_rnic_shaping(struct nbl_hw *hw,
				 union nbl_shaping_dpt_tbl *dpt_tbl,
				 u16 shaping_id, bool valid)
{
	u64 reg_addr;
	u32 value;
	int ix;

	if (valid) {
		reg_addr = NBL_SHAPING_DPT_TBL_ADDR(NBL_REG_SHAPING_BASE(hw), shaping_id);
		for (ix = 0; ix < NBL_SHAPING_DPT_TBL_DW_SIZE; ix++)
			writel(dpt_tbl->data[ix],
			       (hw->hw_addr + (reg_addr + 4 * ix)));

		reg_addr = NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE(hw), NBL_DSCH_PSHA_EN_OFF);
		value = readl(hw->hw_addr + reg_addr);
		value |= ((u32)BIT(shaping_id));
		writel(value, (hw->hw_addr + reg_addr));
	} else {
		reg_addr = NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE(hw), NBL_DSCH_PSHA_EN_OFF);
		value = readl(hw->hw_addr + reg_addr);
		value &= ~((u32)BIT(shaping_id));
		writel(value, (hw->hw_addr + reg_addr));
	}
}

static void nbl_set_hw_shaping_dpt(struct nbl_hw *hw, u16 shaping_id,
				   bool valid, bool is_lag, u8 pf_count)
{
	union nbl_shaping_dpt_tbl dpt_tbl = {};

	if (pf_count == 2) {
		if (is_lag) {
			dpt_tbl.cir = NBL_SHAPING_DPORT_DFT_CIR_RNIC2X200_LAG;
			dpt_tbl.pir = NBL_SHAPING_DPORT_DFT_PIR_RNIC2X200_LAG;
			dpt_tbl.cbs = NBL_SHAPING_DPORT_DFT_CBS_RNIC2X200_LAG;
			dpt_tbl.pbs = NBL_SHAPING_DPORT_DFT_PBS_RNIC2X200_LAG;
			dpt_tbl.cb_token =
				NBL_SHAPING_DPORT_DFT_CB_TOKEN_RNIC2X200_LAG;
			dpt_tbl.pb_token =
				NBL_SHAPING_DPORT_DFT_PB_TOKEN_RNIC2X200_LAG;
			dpt_tbl.valid = 1;
			nbl_set_rnic_shaping(hw, &dpt_tbl, shaping_id, valid);
		} else {
			dpt_tbl.cir = NBL_SHAPING_DPORT_DFT_CIR_RNIC2X200;
			dpt_tbl.pir = NBL_SHAPING_DPORT_DFT_PIR_RNIC2X200;
			dpt_tbl.cbs = NBL_SHAPING_DPORT_DFT_CBS_RNIC2X200;
			dpt_tbl.pbs = NBL_SHAPING_DPORT_DFT_PBS_RNIC2X200;
			dpt_tbl.cb_token = NBL_SHAPING_DPORT_DFT_CB_TOKEN_RNIC2X200;
			dpt_tbl.pb_token = NBL_SHAPING_DPORT_DFT_PB_TOKEN_RNIC2X200;
			dpt_tbl.valid = 1;
			nbl_set_rnic_shaping(hw, &dpt_tbl, shaping_id, valid);
		}
	} else {
		dpt_tbl.cir = NBL_SHAPING_DPORT_DFT_CIR;
		dpt_tbl.pir = NBL_SHAPING_DPORT_DFT_PIR;
		dpt_tbl.cbs = NBL_SHAPING_DPORT_DFT_CBS;
		dpt_tbl.pbs = NBL_SHAPING_DPORT_DFT_PBS;
		dpt_tbl.cb_token = NBL_SHAPING_DPORT_DFT_CB_TOKEN;
		dpt_tbl.pb_token = NBL_SHAPING_DPORT_DFT_PB_TOKEN;
		dpt_tbl.valid = 1;
		nbl_set_rnic_shaping(hw, &dpt_tbl, shaping_id, valid);
	}
}

static void nbl_update_dsch_dport_id_direct(struct nbl_hw *hw, u16 function_id,
					    u32 host_id, u16 dport_id, u8 vld)
{
	u64 reg_addr;
	union rdma_g2p_cfg_tbl g2p_map = {};
	u32 *value;

	reg_addr = NBL_DSCH_G2P_CFG_TBL_ADDR(NBL_REG_DSCH_BASE(hw),
					     NBL_GET_DSCH_GRPID_BY_VFID(function_id));

	g2p_map.vld = vld;
	g2p_map.cpu_type = (host_id == HOST_ID_TYPE_ECPU ? 1 : 0);
	g2p_map.port = dport_id;
	value = (u32 *)&g2p_map;

	wr32(hw, reg_addr, *value);
}

static void nbl_set_vsi_port_tbl(struct nbl_hw *hw, u16 vsi_id, u16 function_id, bool enable)
{
	u64 reg_addr;
	union uqm_vsi2vf_map_tbl vsi_map = {};

	vsi_map.vf_id = function_id;
	vsi_map.valid = enable;
	vsi_map.rdma_offload = 1;

	reg_addr = NBL_UQM_VSI2VF_MAP_TBL_ADDR(NBL_REG_QM_BASE(hw), vsi_id);
	nbl_pr_dbg(
		"UQM_VSI2VF_MAP_TBL addr=0x%llx for function_id:%d vsi_id:%d enable:%d\n",
		reg_addr, function_id, vsi_id, enable);
	wr32(hw, reg_addr, vsi_map.data[0]);
}

static void nbl_set_hdma_bdf_tbl(struct nbl_hw *hw, bool host_en, u16 function_id, u16 bdf_num)
{
	u64 reg_addr;
	union nbl_hdma_bdf_tbl_reg bdf_tbl = {};

	bdf_tbl.data[0] = bdf_num;
	bdf_tbl.key.host_en = host_en;
	reg_addr = NBL_HDMA_BDF_TBL_ADDR(NBL_REG_HDMA_BASE(hw), function_id);

	wr32(hw, reg_addr, bdf_tbl.data[0]);
}

static void nbl_set_pf_tbl(struct nbl_hw *hw, u16 function_id, u16 pf_id)
{
	u64 reg_addr;
	union nbl_hdma_pf_tbl_reg pf_tbl = {};

	pf_tbl.key.bdf_tbl_idx = pf_id;
	reg_addr = NBL_HDMA_PF_TBL_ADDR(NBL_REG_HDMA_BASE(hw), function_id);
	nbl_pr_dbg("func_id:%d pf_id:%d reg:%#llx\n", function_id, pf_id,
		   reg_addr);
	wr32(hw, reg_addr, pf_tbl.data[0]);
}

static void nbl_set_src_addr_info(struct nbl_hw *hw, const u8 *smac, const u8 *sip,
				  u16 src_addr_index, u8 seq_num)
{
	u64 reg_addr;
	union nbl_src_addr_info_tbl_reg info_tbl_reg = {};
	u32 write_num;
	int i, j;

	/* fill src addr info tbl seg */
	/*
	 * for srcmac of key, byte0 corresponds to low-order information,
	 * and byte5 corresponds to high-order information
	 */
	for (i = 0; i < NBL_SRC_MAC_SIZE; i++)
		info_tbl_reg.key.smac[i] = smac[NBL_SRC_MAC_SIZE - 1 - i];

	/*
	 * for sip of key, byte0 corresponds to low-order information,
	 * and byte15 corresponds to high-order information
	 */
	for (j = 0; j < NBL_SRC_IP_SIZE; j++)
		info_tbl_reg.key.sip[j] = sip[NBL_SRC_IP_SIZE - 1 - j];

	info_tbl_reg.key.seq_num = (seq_num & NBL_TXM_SRC_ADDR_SEQ_NUM_MASK);

	write_num = NBL_TXM_SRC_ADDR_TBL_DW_SIZE;
	reg_addr = NBL_TXM_SRC_ADDR_TBL_ADDR(NBL_REG_TXM_BASE(hw),
					     src_addr_index);
	nbl_pr_dbg("initial reg addr[0x%llx]\n", reg_addr);

	for (i = 0; i < write_num; i++) {
		wr32(hw, reg_addr + (i * 4), info_tbl_reg.data[i]);
		nbl_pr_dbg(
			"write src addr info table reg addr[0x%llx], val[0x%x]\n",
			(reg_addr + (i * 4)), info_tbl_reg.data[i]);
	};
}

static struct nbl_rdma_inst_info rdma_inst[NBL_INST_MAX] = {
	{ NBL_CQPP_INST_VFID_OFF, NBL_INST_VFID_SZ },
	{ NBL_CQPP_INST_SMAC_IP_OFF, NBL_INST_SMAC_IP_SZ },
	{ NBL_CQPP_INST_STAT_ID_OFF, NBL_INST_STAT_ID_SZ },
	{ NBL_CQPP_INST_CEQ_ID_OFF, NBL_INST_CEQ_ID_SZ },
};

static int nbl_get_hw_instance_id(struct nbl_hw *hw, u8 inst_type, u16 *inst_id)
{
	u64 reg_addr;
	u32 value;
	int i, j;
	u16 dw_sz;
	u32 instance_id;
	u32 offset;
	struct nbl_rdma_inst_info *inst;

	if (inst_type >= NBL_INST_MAX || !inst_id) {
		nbl_pr_err("invalid rdma instance type=%u,inst_id=%p\n", inst_type, inst_id);
		return -EINVAL;
	}

	inst = &rdma_inst[inst_type];
	dw_sz = DIV_ROUND_UP(inst->inst_size, NBL_INST_BM_BIT_SZ);

	reg_addr = NBL_REG_CQPP_BASE(hw) + inst->inst_base;
	for (i = 0; i < dw_sz; i++) {
		offset = i * NBL_INST_BM_DW_SZ;
		value = rd32(hw, reg_addr + offset);
		if (value == NBL_RDMA_FULL_INST_ID)
			continue;
		for (j = 0; j < NBL_INST_BM_BIT_SZ; j++) {
			if (unlikely(value & BIT(j)))
				continue;

			instance_id = i * NBL_INST_BM_BIT_SZ + j;
			if (unlikely(inst_type == NBL_INST_STAT_ID &&
					instance_id < NBL_RDMA_STAT_ID_START))
				continue;
			if (instance_id < inst->inst_size) {
				value |= BIT(j);
				*inst_id = instance_id;
				wr32(hw, reg_addr + offset, value);
				return 0;
			}

			break;
		}

		break;
	}

	nbl_pr_err("no available rdma instance, its type=%u\n", inst_type);
	return -ENOENT;
}

int df200_host_get_hw_func_id(struct nbl_hw *hw, u16 *inst_id)
{
	u64 reg_addr;
	u32 value;
	int i, j;
	u16 dw_sz;
	u32 instance_id;
	u32 offset;

	reg_addr = NBL_CQPP_REG_ADDR(NBL_REG_CQPP_BASE(hw), NBL_CQPP_INST_VFID_OFF);
	dw_sz = DIV_ROUND_UP(DF200_RDMA_TOTAL_FUNCTION_NUM, NBL_INST_BM_BIT_SZ);

	for (i = 0; i < dw_sz; i++) {
		offset = i * NBL_INST_BM_DW_SZ;
		value = rd32(hw, reg_addr + offset);
		if (value == NBL_RDMA_FULL_INST_ID)
			continue;
		for (j = 2; j < NBL_INST_BM_BIT_SZ; j++) {
			if (unlikely(value & BIT(j)))
				continue;

			instance_id = i * NBL_INST_BM_BIT_SZ + j;
			if (instance_id < DF200_RDMA_TOTAL_FUNCTION_NUM) {
				value |= BIT(j);
				*inst_id = instance_id;
				wr32(hw, reg_addr + offset, value);
				return 0;
			}
			break;
		}

		break;
	}

	nbl_pr_err("no available rdma vfid for df200\n");
	return -ENOENT;
}

void df200_host_put_hw_func_id(struct nbl_hw *hw, u16 inst_id)
{
	u32 value;
	u64 reg_addr;
	u32 dw_offset;

	dw_offset = (inst_id / NBL_INST_BM_BIT_SZ) * NBL_INST_BM_DW_SZ;
	reg_addr = NBL_CQPP_REG_ADDR(NBL_REG_CQPP_BASE(hw),
				     NBL_CQPP_INST_VFID_OFF) + dw_offset;

	value = rd32(hw, reg_addr);
	value &= ~BIT(inst_id % NBL_INST_BM_BIT_SZ);
	wr32(hw, reg_addr, value);
}

static int nbl_put_hw_instance_id(struct nbl_hw *hw, u8 inst_type, u16 inst_id)
{
	u64 reg_addr;
	u32 value;
	u32 dw_offset;
	struct nbl_rdma_inst_info *inst;

	if (inst_type >= NBL_INST_MAX) {
		nbl_pr_err("invalid rdma instance type=%u\n", inst_type);
		return -EINVAL;
	}

	inst = &rdma_inst[inst_type];
	if (inst_id >= inst->inst_size) {
		nbl_pr_err("invalid inst_id=%u,its type=%u\n", inst_id, inst_type);
		return -EINVAL;
	}

	dw_offset = (inst_id / NBL_INST_BM_BIT_SZ) * NBL_INST_BM_DW_SZ;
	reg_addr = NBL_REG_CQPP_BASE(hw) + inst->inst_base + dw_offset;

	value = rd32(hw, reg_addr);
	value &= ~BIT(inst_id % NBL_INST_BM_BIT_SZ);
	wr32(hw, reg_addr, value);

	return 0;
}

static void nbl_get_hw_stat_status(struct nbl_hw *hw, u32 *status)
{
	u64 reg_addr = NBL_STAT_REG_ADDR(NBL_REG_STAT_BASE(hw),
				     NBL_STAT_OP_INFO_OFF);

	*status = rd32(hw, reg_addr);
}

static void nbl_get_hw_stat(struct nbl_hw *hw, u32 op_info, u32 pa_l, u32 pa_h, u16 func_id)
{
	u64 stat_reg_base = NBL_REG_STAT_BASE(hw);

	wr32(hw, NBL_STAT_REG_ADDR(stat_reg_base, NBL_STAT_FUNC_ID_OFF), func_id);
	wr32(hw, NBL_STAT_REG_ADDR(stat_reg_base, NBL_STAT_OP_DMA_ADDR_L_OFF), pa_l);
	wr32(hw, NBL_STAT_REG_ADDR(stat_reg_base, NBL_STAT_OP_DMA_ADDR_H_OFF), pa_h);
	wr32(hw, NBL_STAT_REG_ADDR(stat_reg_base, NBL_STAT_OP_INFO_OFF), op_info);
}

static void nbl_set_hw_stat(struct nbl_hw *hw, u32 op_info)
{
	u64 reg_addr = NBL_STAT_REG_ADDR(NBL_REG_STAT_BASE(hw),
				     NBL_STAT_OP_INFO_OFF);

	wr32(hw, reg_addr, op_info);
}

static void nbl_enable_errcode_hw_stat(struct nbl_hw *hw, u32 enable)
{
	u64 reg_addr = NBL_STAT_REG_ADDR(NBL_REG_STAT_BASE(hw),
				     NBL_STAT_OP_ERR_OPCODE_EN_OFF);

	wr32(hw, reg_addr, enable);
}

static char *rdma_interrupt_module[NBL_HW_RDMA_MOD_NUM] = {
	"rdma_top",
	"cqpp",
	"hdma",
	"txp",
	"txmr",
	"txm",
	"rxp",
	"rxmr",
	"rxm",
	"raqp",
	"ceaq",
	"prob",
	"adpt",
	"qpcc",
	"cqcc",
	"mrtc",
	"pblc",
	"cc",
	"sqrqec",
	"irqec",
	"orqec",
	"unapec",
	"raqec",
	"tqp",
	"hdma_debug",
	"stat",
	"srqc",
	"pdc",
	"iorqec",
	"osqec",
	"ntfqp"
};

static void nbl_get_hw_abnormal_event(struct nbl_hw *hw, u32 rdma_top_offset)
{
	u64 reg_addr;
	u32 value;
	u32 sub_module_int;
	int i = 1;
	DECLARE_BITMAP(ab_events, NBL_HW_RDMA_MOD_NUM);

	value = readl(hw->hw_addr + NBL_REG_RDMA_TOP_BASE(hw) + rdma_top_offset);
	nbl_pr_dbg("1.rdma top interrupt=0x%x\n", value);
	ab_events[0] = value;
	i = (int)find_next_bit(ab_events, NBL_HW_RDMA_MOD_NUM, i);
	while (i < NBL_HW_RDMA_MOD_NUM) {
		reg_addr = NBL_REG_RDMA_TOP_BASE(hw) + (i << RDMA_SUBMODULE_BASE_SHIFT);
		if (i > NBL_STAT_MOD_INDEX)
			reg_addr += (NBL_STAT_MOD_REG_SIZE - BIT(RDMA_SUBMODULE_BASE_SHIFT));
		sub_module_int = readl(hw->hw_addr + reg_addr);

		nbl_dev_err(hw->device, "[rdma][submodule_%s] generated abnormal event=%#x\n",
			    rdma_interrupt_module[i], sub_module_int);

		wr32(hw, reg_addr, sub_module_int);
		i = (int)find_next_bit(ab_events, NBL_HW_RDMA_MOD_NUM, i + 1);
	}
}

static u32 nbl_get_hw_global_cfg_flag(struct nbl_hw *hw)
{
	u32 value;
	u64 reg_addr;
	u32 global_flag = 0;

	reg_addr = NBL_CQPP_REG_ADDR(NBL_REG_CQPP_BASE(hw),
				     NBL_CQPP_GLOBAL_CFG_FLAG_OFF);
	value = readl(hw->hw_addr + reg_addr);
	global_flag = value & NBL_CQPP_GLOBAL_CFG_ENABLE;

	if (!global_flag) {
		value |= NBL_CQPP_GLOBAL_CFG_ENABLE;
		wr32(hw, reg_addr, value);
	}

	nbl_pr_dbg("get hw rdma global cfg flag=0x%x", global_flag);
	return global_flag;
}

static const struct nbl_hw_error_code hw_err_table[] = {
	/* reg_off, drop norm_cqe abnorm_cqe ae err_code */
	{/* 0x1000 */ 1, 0, 0, 0, 0x0},
	{/* 0x1004 */ 1, 0, 0, 0, 0x1},
	{/* 0x1008 */ 1, 0, 0, 0, 0x2},
	{/* 0x100c */ 1, 0, 0, 0, 0x3},
	{/* 0x1010 */ 1, 0, 0, 0, 0x4},
	{/* 0x1014 */ 1, 0, 0, 0, 0x5},
	{/* 0x1018 */ 1, 0, 0, 0, 0x6},
	{/* 0x101c */ 1, 0, 0, 0, 0x7},
	{/* 0x1020 */ 1, 0, 0, 0, 0x8},
	{/* 0x1024 */ 1, 0, 0, 0, 0x9},
	{/* 0x1028 */ 1, 0, 0, 0, 0xA},
	{/* 0x102c */ 1, 0, 0, 0, 0xB},
	{/* 0x1030 */ 0, 0, 0, 1, 0xC},
	{/* 0x1034 */ 0, 0, 0, 1, 0xD},
	{/* 0x1038 */ 0, 0, 0, 1, 0xE},
	{/* 0x103c */ 0, 0, 0, 1, 0xF},
	{/* 0x1040 */ 0, 0, 0, 1, 0x10},
	{/* 0x1044 */ 0, 0, 0, 1, 0x11},
	{/* 0x1048 */ 0, 0, 0, 1, 0x12},
	{/* 0x104c */ 0, 0, 0, 1, 0x13},
	{/* 0x1050 */ 0, 0, 0, 1, 0x14},
	{/* 0x1054 */ 0, 0, 0, 1, 0x15},
	{/* 0x1058 */ 1, 0, 0, 0, 0x16},
	{/* 0x105c */ 1, 0, 0, 0, 0x17},
	{/* 0x1060 */ 0, 0, 0, 1, 0x18},
	{/* 0x1064 */ 1, 0, 0, 0, 0x19},
	{/* 0x1068 */ 0, 0, 1, 1, 0x1A},
	{/* 0x106c */ 0, 0, 1, 0, 0x1B},
	{/* 0x1070 */ 0, 0, 1, 1, 0x1C},
	{/* 0x1074 */ 0, 0, 1, 1, 0x1D},
	{/* 0x1078 */ 0, 0, 1, 1, 0x1E},
	{/* 0x107c */ 0, 0, 1, 1, 0x1F},
	{/* 0x1080 */ 1, 0, 0, 0, 0x20},
	{/* 0x1084 */ 1, 0, 0, 0, 0x21},
	{/* 0x1088 */ 1, 0, 0, 0, 0x22},
	{/* 0x108c */ 1, 0, 0, 0, 0x23},
	{/* 0x1090 */ 1, 0, 0, 0, 0x24},
	{/* 0x1094 */ 1, 0, 0, 0, 0x25},
	{/* 0x1098 */ 1, 0, 0, 0, 0x26},
	{/* 0x109c */ 1, 0, 0, 0, 0x27},
	{/* 0x10a0 */ 1, 0, 0, 0, 0x28},
	{/* 0x10a4 */ 1, 0, 0, 0, 0x29},
	{/* 0x10a8 */ 0, 1, 0, 0, 0x2A},
	{/* 0x10ac */ 0, 1, 0, 0, 0x2B},
	{/* 0x10b0 */ 1, 0, 0, 0, 0x2C},
	{/* 0x10b4 */ 0, 1, 0, 0, 0x2D},
	{/* 0x10b8 */ 0, 1, 0, 0, 0x2E},
	{/* 0x10bc */ 1, 0, 0, 0, 0x2F},
	{/* 0x10c0 */ 0, 0, 1, 1, 0x30},
	{/* 0x10c4 */ 0, 0, 1, 1, 0x31},
	{/* 0x10c8 */ 0, 0, 1, 1, 0x32},
	{/* 0x10cc */ 0, 0, 1, 1, 0x33},
	{/* 0x10d0 */ 0, 0, 1, 1, 0x34},
	{/* 0x10d4 */ 0, 0, 1, 1, 0x35},
	{/* 0X10d8 */ 0, 0, 1, 1, 0x36},
	{/* 0x10dc */ 1, 0, 0, 0, 0x37},
	{/* 0x10e0 */ 0, 0, 1, 1, 0x38},
	{/* 0x10e4 */ 0, 0, 1, 1, 0x39},
	{/* 0x10e8 */ 0, 0, 1, 1, 0x3A},
	{/* 0x10ec */ 0, 0, 1, 1, 0x3B},
	{/* 0x10f0 */ 0, 0, 1, 1, 0x3C},
	{/* 0x10f4 */ 0, 0, 1, 1, 0x3D},
	{/* 0x10f8 */ 0, 0, 1, 1, 0x3E},
	{/* 0x10fc */ 0, 0, 1, 1, 0x3F},
	{/* 0x1100 */ 0, 0, 1, 1, 0x40},
	{/* 0x1104 */ 1, 0, 0, 0, 0x41},
	{/* 0x1108 */ 1, 0, 0, 0, 0x42},
	{/* 0x110c */ 1, 0, 0, 0, 0x43},
	{/* 0x1110 */ 0, 0, 0, 0, 0x44},
	{/* 0x1114 */ 1, 0, 0, 0, 0x45},
	{/* 0x1118 */ 0, 0, 0, 1, 0x46},
	{/* 0x111c */ 1, 0, 0, 0, 0x47},
	{/* 0x1120 */ 1, 0, 0, 0, 0x48},
	{/* 0x1124 */ 1, 0, 0, 0, 0x49},
	{/* 0x1128 */ 0, 0, 1, 0, 0x4a},
	{/* 0x112c */ 0, 0, 1, 0, 0x4b},
	{/* 0x1130 */ 1, 0, 0, 0, 0x4c},
	{/* 0x1134 */ 1, 0, 0, 0, 0x4d},
	{/* 0x1138 */ 1, 0, 0, 0, 0x4e},
	{/* 0x113c */ 1, 0, 0, 0, 0x4f},
	{/* 0x1140 */ 1, 0, 0, 0, 0x50},
	{/* 0x1144 */ 1, 0, 0, 0, 0x51},
	{/* 0x1148 */ 1, 0, 0, 0, 0x52},
	{/* 0x114c */ 1, 0, 0, 0, 0x53},
	{/* 0x1150 */ 1, 0, 0, 0, 0x54},
	{/* 0x1154 */ 0, 0, 1, 1, 0x55},
	{/* 0x1158 */ 0, 0, 0, 1, 0x56},
	{/* 0x115c */ 0, 0, 1, 1, 0x57},
	{/* 0x1160 */ 1, 0, 0, 0, 0x58},
	{/* 0x1164 */ 0, 0, 0, 1, 0x59},
	{/* 0x1168 */ 0, 0, 0, 1, 0x5a},
	{/* 0x116c */ 0, 0, 1, 1, 0x5b},
	{/* 0x1170 */ 0, 0, 0, 1, 0x5c},
	{/* 0x1174 */ 1, 0, 0, 0, 0x5d},
	{/* 0x1178 */ 1, 0, 0, 0, 0x5e},
	{/* 0x117c */ 1, 0, 0, 0, 0x5f},
	{/* 0x1180 */ 0, 0, 1, 1, 0x60},
	{/* 0x1184 */ 0, 0, 1, 1, 0x61},
	{/* 0x1188 */ 0, 0, 1, 1, 0x62},
	{/* 0x118c */ 0, 0, 1, 1, 0x63},
	{/* 0x1190 */ 0, 0, 1, 1, 0x64},
	{/* 0x1194 */ 0, 0, 1, 1, 0x65},
	{/* 0x1198 */ 0, 0, 1, 1, 0x66},
	{/* 0x119c */ 0, 0, 1, 1, 0x67},
	{/* 0x11a0 */ 0, 0, 1, 1, 0x68},
	{/* 0x11a4 */ 0, 0, 1, 1, 0x69},
	{/* 0x11a8 */ 0, 0, 1, 1, 0x6A},
	{/* 0x11ac */ 0, 0, 1, 1, 0x6B},
	{/* 0x11b0 */ 0, 0, 1, 1, 0x6C},
	{/* 0x11b4 */ 0, 0, 1, 1, 0x6D},
	{/* 0x11b8 */ 0, 0, 1, 1, 0x6E},
	{/* 0x11bc */ 0, 0, 1, 1, 0x6F},
	{/* 0x11c0 */ 0, 0, 1, 1, 0x70},
	{/* 0x11c4 */ 0, 0, 1, 1, 0x71},
	{/* 0x11c8 */ 1, 0, 0, 0, 0x72},
	{/* 0x11cc */ 1, 0, 0, 0, 0x73},
	{/* 0x11d0 */ 1, 0, 0, 0, 0x74},
	{/* 0x11d4 */ 1, 0, 0, 0, 0x75},
	{/* 0x11d8 */ 0, 0, 1, 1, 0x76},
	{/* 0x11dc */ 0, 0, 0, 1, 0x77},
	{/* 0x11e0 */ 1, 0, 0, 0, 0x78},
	{/* 0x11e4 */ 0, 0, 0, 1, 0x79},
	{/* 0x11e8 */ 0, 0, 0, 1, 0x7a},
	{/* 0x11ec */ 1, 0, 0, 0, 0x7b},
	{/* 0x11f0 */ 1, 0, 0, 0, 0x7c},
	{/* 0x11f4 */ 1, 0, 0, 0, 0x7d},
	{/* 0x11f8 */ 1, 0, 0, 0, 0x7e},
	{/* 0x11fc */ 1, 0, 0, 0, 0x7f},

	{/* 0x1200 */ 1, 0, 0, 0, 0x80},
	{/* 0x1204 */ 1, 0, 0, 0, 0x81},
	{/* 0x1208 */ 1, 0, 0, 0, 0x82},
	{/* 0x120c */ 0, 0, 0, 1, 0x83},
	{/* 0x1210 */ 0, 0, 0, 1, 0x84},
	{/* 0x1214 */ 0, 0, 0, 1, 0x85},
	{/* 0x1218 */ 0, 0, 0, 1, 0x86},
	{/* 0x121c */ 1, 0, 0, 0, 0x87},
	{/* 0x1220 */ 1, 0, 0, 0, 0x88},
	{/* 0x1224 */ 1, 0, 0, 0, 0x89},
	{/* 0x1228 */ 1, 0, 0, 0, 0x8A},
	{/* 0x122c */ 1, 0, 0, 0, 0x8B},
	{/* 0x1230 */ 1, 0, 0, 0, 0x8C},
	{/* 0x1234 */ 1, 0, 0, 0, 0x8D},
	{/* 0x1238 */ 1, 0, 0, 0, 0x8E},
	{/* 0x123c */ 1, 0, 0, 0, 0x8F},
	{/* 0x1240 */ 0, 0, 1, 1, 0x90},
	{/* 0x1244 */ 0, 0, 1, 1, 0x91},
	{/* 0x1248 */ 0, 0, 1, 1, 0x92},
	{/* 0x124c */ 0, 0, 0, 1, 0x93},
	{/* 0x1250 */ 0, 0, 0, 1, 0x94},
	{/* 0x1254 */ 1, 0, 0, 0, 0x95},
	{/* 0x1258 */ 1, 0, 0, 0, 0x96},
	{/* 0x125c */ 1, 0, 0, 0, 0x97},
	{/* 0x1260 */ 1, 0, 0, 0, 0x98},
	{/* 0x1264 */ 1, 0, 0, 0, 0x99},
	{/* 0x1268 */ 1, 0, 0, 0, 0x9a},
	{/* 0x126c */ 1, 0, 0, 0, 0x9b},
	{/* 0x1270 */ 1, 0, 0, 0, 0x9c},
	{/* 0x1274 */ 1, 0, 0, 0, 0x9d},
	{/* 0x1278 */ 1, 0, 0, 0, 0x9e},
	{/* 0x127c */ 1, 0, 0, 0, 0x9f},
	{/* 0x1280 */ 1, 0, 0, 0, 0xa0},
	{/* 0x1284 */ 1, 0, 0, 0, 0xa1},
	{/* 0x1288 */ 0, 0, 0, 1, 0xa2},
	{/* 0x128c */ 0, 0, 0, 1, 0xa3},
	{/* 0x1290 */ 0, 0, 0, 1, 0xa4},
	{/* 0x1294 */ 0, 1, 0, 0, 0xa5},
	{/* 0x1298 */ 1, 0, 0, 0, 0xa6},
	{/* 0x129c */ 1, 0, 0, 0, 0xa7},
	{/* 0x12a0 */ 1, 0, 0, 0, 0xa8},
	{/* 0x12a4 */ 1, 0, 0, 0, 0xa9},
	{/* 0x12a8 */ 1, 0, 0, 0, 0xaa},
	{/* 0x12ac */ 1, 0, 0, 0, 0xab},
	{/* 0x12b0 */ 1, 0, 0, 0, 0xac},
	{/* 0x12b4 */ 1, 0, 0, 0, 0xad},
	{/* 0x12b8 */ 1, 0, 0, 0, 0xae},
	{/* 0x12bc */ 1, 0, 0, 0, 0xaf},
	{/* 0x12c0 */ 1, 0, 0, 0, 0xb0},
	{/* 0x12c4 */ 1, 0, 0, 0, 0xb1},
	{/* 0x12c8 */ 1, 0, 0, 0, 0xb2},
	{/* 0x12cc */ 1, 0, 0, 0, 0xb3},
	{/* 0x12d0 */ 1, 0, 0, 0, 0xb4},
	{/* 0x12d4 */ 1, 0, 0, 0, 0xb5},
	{/* 0X12d8 */ 1, 0, 0, 0, 0xb6},
	{/* 0x12dc */ 1, 0, 0, 0, 0xb7},
	{/* 0x12e0 */ 1, 0, 0, 0, 0xb8},
	{/* 0x12e4 */ 1, 0, 0, 0, 0xb9},
	{/* 0x12e8 */ 1, 0, 0, 0, 0xba},
	{/* 0x12ec */ 1, 0, 0, 0, 0xbb},
	{/* 0x12f0 */ 1, 0, 0, 0, 0xbc},
	{/* 0x12f4 */ 1, 0, 0, 0, 0xbd},
	{/* 0x12f8 */ 1, 0, 0, 0, 0xbe},
	{/* 0x12fc */ 1, 0, 0, 0, 0xbf},
	{/* 0x1300 */ 1, 0, 0, 0, 0xb0},
	{/* 0x1304 */ 1, 0, 0, 0, 0xc1},
	{/* 0x1308 */ 1, 0, 0, 0, 0xc2},
	{/* 0x130c */ 1, 0, 0, 0, 0xc3},
	{/* 0x1310 */ 1, 0, 0, 0, 0xc4},
	{/* 0x1314 */ 1, 0, 0, 0, 0xc5},
	{/* 0x1318 */ 1, 0, 0, 0, 0xc6},
	{/* 0x131c */ 1, 0, 0, 0, 0xc7},
	{/* 0x1320 */ 1, 0, 0, 0, 0xc8},
	{/* 0x1324 */ 1, 0, 0, 0, 0xc9},
	{/* 0x1328 */ 1, 0, 0, 0, 0xca},
	{/* 0x132c */ 1, 0, 0, 0, 0xcb},
	{/* 0x1330 */ 1, 0, 0, 0, 0xcc},
	{/* 0x1334 */ 1, 0, 0, 0, 0xcd},
	{/* 0x1338 */ 1, 0, 0, 0, 0xce},
	{/* 0x133c */ 1, 0, 0, 0, 0xcf},
	{/* 0x1340 */ 1, 0, 0, 0, 0xd0},
	{/* 0x1344 */ 1, 0, 0, 0, 0xd1},
	{/* 0x1348 */ 1, 0, 0, 0, 0xd2},
	{/* 0x134c */ 1, 0, 0, 0, 0xd3},
	{/* 0x1350 */ 1, 0, 0, 0, 0xd4},
	{/* 0x1354 */ 1, 0, 0, 0, 0xd5},
	{/* 0x1358 */ 1, 0, 0, 0, 0xd6},
	{/* 0x135c */ 1, 0, 0, 0, 0xd7},
	{/* 0x1360 */ 1, 0, 0, 0, 0xd8},
	{/* 0x1364 */ 1, 0, 0, 0, 0xd9},
	{/* 0x1368 */ 1, 0, 0, 0, 0xda},
	{/* 0x136c */ 1, 0, 0, 0, 0xdb},
	{/* 0x1370 */ 1, 0, 0, 0, 0xdc},
	{/* 0x1374 */ 1, 0, 0, 0, 0xdd},
	{/* 0x1378 */ 1, 0, 0, 0, 0xde},
	{/* 0x137c */ 1, 0, 0, 0, 0xdf},
	{/* 0x1380 */ 1, 0, 0, 0, 0xe0},
	{/* 0x1384 */ 1, 0, 0, 0, 0xe1},
	{/* 0x1388 */ 1, 0, 0, 0, 0xe2},
	{/* 0x138c */ 1, 0, 0, 0, 0xe3},
	{/* 0x1390 */ 1, 0, 0, 0, 0xe4},
	{/* 0x1394 */ 1, 0, 0, 0, 0xe5},
	{/* 0x1398 */ 1, 0, 0, 0, 0xe6},
	{/* 0x139c */ 1, 0, 0, 0, 0xe7},
	{/* 0x13a0 */ 1, 0, 0, 0, 0xe8},
	{/* 0x13a4 */ 1, 0, 0, 0, 0xe9},
	{/* 0x13a8 */ 1, 0, 0, 0, 0xea},
	{/* 0x13ac */ 1, 0, 0, 0, 0xeb},
	{/* 0x13b0 */ 1, 0, 0, 0, 0xec},
	{/* 0x13b4 */ 1, 0, 0, 0, 0xed},
	{/* 0x13b8 */ 1, 0, 0, 0, 0xee},
	{/* 0x13bc */ 1, 0, 0, 0, 0xef},
	{/* 0x13c0 */ 0, 0, 0, 1, 0xf0},
	{/* 0x13c4 */ 0, 0, 0, 1, 0xf1},
	{/* 0x13c8 */ 1, 0, 0, 0, 0xf2},
	{/* 0x13cc */ 1, 0, 0, 0, 0xf3},
	{/* 0x13d0 */ 1, 0, 0, 0, 0xf4},
	{/* 0x13d4 */ 1, 0, 0, 0, 0xf5},
	{/* 0x13d8 */ 1, 0, 0, 0, 0xf6},
	{/* 0x13dc */ 1, 0, 0, 0, 0xf7},
	{/* 0x13e0 */ 1, 0, 0, 0, 0xf8},
	{/* 0x13e4 */ 1, 0, 0, 0, 0xf9},
	{/* 0x13e8 */ 1, 0, 0, 0, 0xfa},
	{/* 0x13ec */ 1, 0, 0, 0, 0xfb},
	{/* 0x13f0 */ 1, 0, 0, 0, 0xfc},
	{/* 0x13f4 */ 1, 0, 0, 0, 0xfd},
	{/* 0x13f8 */ 1, 0, 0, 0, 0xfe},
	{/* 0x13fc */ 1, 0, 0, 0, 0xff},
};

/* Only Called by RNIC400 */
static void nbl_freq_init(struct nbl_hw *hw)
{
	u32 freq = NBL_RDMA_SYS_CLK_RNIC;
	union nbl_rxp_rnrtime_set_reg rnrtime_reg = {};
	u32 reg_addr = NBL_RXP_REG_ADDR(NBL_REG_RXP_BASE(hw),
					NBL_RXP_RNRTIME_SET_OFF);
	u32 val_time;

	if (freq > NBL_RXP_FREQ_200M)
		val_time = NBL_RXP_TIMEVAL_U200M;
	else if (freq > NBL_RXP_FREQ_100M)
		val_time = NBL_RXP_TIMEVAL_U100M;
	else if (freq > NBL_RXP_FREQ_30M)
		val_time = NBL_RXP_TIMEVAL_U30M;
	else if (freq > NBL_RXP_FREQ_20M)
		val_time = NBL_RXP_TIMEVAL_U20M;
	else if (freq > NBL_RXP_FREQ_10M)
		val_time = NBL_RXP_TIMEVAL_U10M;
	else if (freq > NBL_RXP_FREQ_5M)
		val_time = NBL_RXP_TIMEVAL_U5M;
	else
		val_time = NBL_RXP_TIMEVAL_U1M;

	nbl_pr_info("set rxp rnr timelsb=%u", val_time);
	rnrtime_reg.rnrtime_lsb = val_time;
	wr32(hw, reg_addr, rnrtime_reg.data);

	reg_addr = NBL_RDMA_TOP_REG_ADDR(NBL_REG_RDMA_TOP_BASE(hw),
					 NBL_RDMA_TOP_GLB_SYSTIME_1US_OFF);
	wr32(hw, reg_addr, freq);
}

static void nbl_set_cqp_max_function_id(struct nbl_hw *hw, u16 max_vfid, bool valid)
{
	union nbl_cqp_max_fun_id_reg max_fun_id_reg = {};
	u32 reg_addr = NBL_CQPP_REG_ADDR(NBL_REG_CQPP_BASE(hw),
					 NBL_CQPP_MAX_FUN_ID_OFF);

	max_fun_id_reg.max_fun_id = max_vfid;
	max_fun_id_reg.max_fun_id_vld = valid ? 1 : 0;

	nbl_pr_info("set cqpp_max_vfid=%u", max_vfid);
	wr32(hw, reg_addr, max_fun_id_reg.data);
}

static void nbl_ceaq_eot_init(struct nbl_hw *hw, bool valid)
{
	int depth = ARRAY_SIZE(hw_err_table);
	union nbl_eot_table_reg eot_reg = {};
	u32 reg_addr;
	int ix;

	if (valid) {
		for (ix = 0; ix < depth; ix++) {
			memset(&eot_reg, 0, sizeof(eot_reg));

			eot_reg.ae_flag = hw_err_table[ix].ae ? 1 : 0;
			eot_reg.abnorm_cqe_flag = hw_err_table[ix].abnormal_cqe ? 1 : 0;
			eot_reg.norm_cqe_flag = hw_err_table[ix].normal_cqe ? 1 : 0;
			eot_reg.drop_flag = hw_err_table[ix].drop ? 1 : 0;

			reg_addr = NBL_CEAQ_EOT_TBL_ADDR(NBL_REG_CEAQ_BASE(hw), ix);
			wr32(hw, reg_addr, eot_reg.data[0]);
		}
	} else {
		memset(&eot_reg, 0, sizeof(eot_reg));
		for (ix = 0; ix < depth; ix++) {
			reg_addr = NBL_CEAQ_EOT_TBL_ADDR(NBL_REG_CEAQ_BASE(hw), ix);
			wr32(hw, reg_addr, eot_reg.data[0]);
		}
	}
}

static void nbl_resv_ctrl_dev_num(struct nbl_hw *hw)
{
	struct nbl_pci_f *rf = container_of(hw, struct nbl_pci_f, hw);
	u32 ctrl_dev_mask = BIT(rf->sc_dev.pf_count) - 1;
	u32 reg_addr = NBL_CQPP_REG_ADDR(NBL_REG_CQPP_BASE(hw),
					 NBL_CQPP_INST_VFID_OFF);

	wr32(hw, reg_addr, ctrl_dev_mask);
}

/* Only Called by RNIC400 */
static void nbl_set_default_reg(struct nbl_hw *hw)
{
	union nbl_hdma_cpu_ctrl_reg cpu_ctrl = {};
	union nbl_rnic_dyn_version rnic_ver = {};
	union nbl_rdma_dyn_version rdma_ver = {};
	u32 reg_addr;
	u32 reg_data;

	/* set top subtype */
	reg_addr = NBL_TOP_DYN_VERSION_ADDR(NBL_REG_TOP_V4);
	rnic_ver.data[0] = readl(hw->hw_addr + reg_addr);
	rdma_ver.sub_type = rnic_ver.sub_type;
	reg_addr = NBL_RDMA_TOP_REG_ADDR(NBL_REG_RDMA_TOP_BASE(hw),
						NBL_RDMA_TOP_DYN_VERSION_OFF);
	wr32(hw, reg_addr, rdma_ver.data[0]);
	nbl_pr_info("set dyn version to 0x%x\n", rdma_ver.data[0]);
	/* bgid th reg */
	reg_addr = NBL_REG_DSTORE_BASE_V4 + NBL_DSTORE_CFG_BG_TH;
	reg_data = NBL_DSTORE_CFG_BG_TH_DFT_V4;
	wr32(hw, reg_addr, reg_data);
	/* txp bgid response reg */
	reg_addr = NBL_TXP_REG_ADDR(NBL_REG_TXP_BASE_V4,
					NBL_TXP_CELL_NUM_CFG_OFF);
	reg_data = NBL_TXP_CELL_NUM_CFG_DFT_V4;
	wr32(hw, reg_addr, reg_data);
	/*txp wqe cap */
	reg_addr = NBL_TXP_REG_ADDR(NBL_REG_TXP_BASE_V4,
					NBL_TXP_WQE_CAP_OFF);
	reg_data = NBL_REG_TXP_RAQE_CAP;
	wr32(hw, reg_addr, reg_data);
	/* padpt cfg fc up 8/10bit tag th */
	reg_addr = NBL_PADAPT_REG_ADDR(NBL_REG_PADPT_BASE_V4,
						NBL_PADAPT_CFG_FC_UP_8BTAG_TH_OFF);
	reg_data = NBL_PADPT_CFG_FC_UP_8BTAG_TH_VAL;
	wr32(hw, reg_addr, reg_data);
	reg_addr = NBL_PADAPT_REG_ADDR(NBL_REG_PADPT_BASE_V4,
						NBL_PADAPT_CFG_FC_UP_10BTAG_TH_OFF);
	reg_data = NBL_PADPT_CFG_FC_UP_10BTAG_TH_VAL;
	wr32(hw, reg_addr, reg_data);
	/* padpt tag age time reg */
	reg_addr = NBL_PADAPT_REG_ADDR(NBL_REG_PADPT_BASE_V4,
						NBL_PADAPT_CFG_AGE_TIME_OFF);
	reg_data = NBL_PADPT_CFG_AGE_TIME_DEFAULT;
	wr32(hw, reg_addr, reg_data);
	/* hdma retry 3 times */
	reg_addr = NBL_HDMA_REG_ADDR(NBL_REG_HDMA_BASE(hw),
						NBL_HDMA_CPU_CTRL_OFF);
	cpu_ctrl.data[0] = readl(hw->hw_addr + reg_addr);
	cpu_ctrl.key.retry_cnt = 3;
	wr32(hw, reg_addr, cpu_ctrl.data[0]);
	/* set srp tlp timer uint */
	reg_addr = NBL_TQP_REG_ADDR(NBL_REG_TQP_BASE(hw),
					NBL_TQP_SRP_TLP_TIMER_UNIT_OFF);
	reg_data = NBL_TQP_SRP_TLP_TIMER_UNIT_DFT_RNIC400;
	wr32(hw, reg_addr, reg_data);
}

/* Only Called by RNIC400 */
static void nbl_set_rdma_global_cfg(struct nbl_hw *hw, u8 max_function_id, bool valid)
{
	nbl_set_default_reg(hw);
	nbl_resv_ctrl_dev_num(hw);
	nbl_freq_init(hw);
	nbl_set_cqp_max_function_id(hw, max_function_id, valid);
	nbl_ceaq_eot_init(hw, valid);
}

void nbl_draco_reset_rdma(struct nbl_pci_f *rf)
{
	struct nbl_hw *hw = &rf->hw;

	wr32(hw, NBL_RDMA_LB_RST_ADDR_V2, NBL_RDMA_LB_RST_VALUE);
	wr32(hw, NBL_RDMA_LB_RST_ADDR_V2, NBL_RDMA_LB_RELEASE_VALUE);
}

void nbl_orion_reset_rdma(struct nbl_pci_f *rf)
{
	struct nbl_hw *hw = &rf->hw;

	wr32(hw, NBL_RDMA_LB_RST_ADDR_V2, NBL_RDMA_LB_RST_VALUE);
	wr32(hw, NBL_RDMA_LB_RST_ADDR_V2, NBL_RDMA_LB_RELEASE_VALUE);
}

void nbl_df200_reset_rdma(struct nbl_pci_f *rf)
{
	struct nbl_hw *hw = &rf->hw;

	/* reset rdma logic and cfg */
	writel(NBL_TOP_CLEAR_VALUE,
	       (void *)(hw->hw_addr + NBL_TOP_CLEAR_LOGIC_ADDR(NBL_REG_TOP_V3)));
	writel(NBL_TOP_CLEAR_VALUE,
	       (void *)(hw->hw_addr + NBL_TOP_CLEAR_CONFIG_ADDR(NBL_REG_TOP_V3)));
	/* re-init hps rdma cfg */
	writel(NBL_RDMA_INIT_CFG_HPS_ENABLE,
	       (void *)(hw->hw_addr + NBL_RDMA_INIT_CFG_HPS_REG_ADDR_V3));
	writel(NBL_INTERRUPT_ECPU2HPS_DISABLE,
	       (void *)(hw->hw_addr + NBL_INTERRUPT_ECPU2HPS_REG_ADDR_V3));
	writel(NBL_INTERRUPT_ECPU2HPS_ENABLE,
	       (void *)(hw->hw_addr + NBL_INTERRUPT_ECPU2HPS_REG_ADDR_V3));
}

void nbl_rnic400_reset_rdma(struct nbl_pci_f *rf)
{
	struct nbl_hw *hw = &rf->hw;

	/* reset rdma logic and cfg */
	writel(NBL_TOP_CLEAR_VALUE,
	       (void *)(hw->hw_addr + NBL_TOP_CLEAR_LOGIC_ADDR(NBL_REG_TOP_V4)));
	writel(NBL_TOP_CLEAR_VALUE,
	       (void *)(hw->hw_addr + NBL_TOP_CLEAR_CONFIG_ADDR(NBL_REG_TOP_V4)));
}

static int nbl_get_flush_status(struct nbl_hw *hw, u16 function_id, u32 check_offset)
{
	u64 reg_addr;
	u32 flush_status = 0;

	reg_addr = NBL_REG_CEAQ_BASE(hw) + check_offset;
	flush_status = rd32(hw, reg_addr);

	return (flush_status & (1 << (function_id % 32))) ? 1 : 0;
}

int nbl_df200_armcq_get_flush_status(struct nbl_pci_f *rf)
{
	return nbl_get_flush_status(&rf->hw, rf->sc_dev.function_id,
				    ARMCQ_FLUSH_STATUS);
}

int nbl_draco_armcq_get_flush_status(struct nbl_pci_f *rf)
{
	u32 check_offset = rf->sc_dev.function_id < 32 ?
			   ASIC_ARMCQ_FLUSH_STATUS_L : ASIC_ARMCQ_FLUSH_STATUS_H;

	return nbl_get_flush_status(&rf->hw, rf->sc_dev.function_id, check_offset);
}

int nbl_rnic400_armcq_get_flush_status(struct nbl_pci_f *rf)
{
	return nbl_get_flush_status(&rf->hw, rf->sc_dev.function_id,
				    ARMCQ_FLUSH_STATUS);
}

void nbl_armcq_db_flush(struct nbl_pci_f *rf)
{
	u64 arm_value;

	/* hw reset, no need to flush */
	if (rf->rdma_reset)
		return;

	arm_value = FIELD_PREP(NBL_REG_ARM_CQ_REG1_FLUSH_FLAG, 1);
	write64_reg(arm_value, rf->sc_dev.hw_regs[NBL_ARM_CQ]);
}

void nbl_rq_db_flush(struct nbl_pci_f *rf)
{
	struct nbl_hw *hw = &rf->hw;
	u16 function_id = rf->sc_dev.function_id;
	u64 rq_value;
	int flush_status;
	u32 retry_count = 0;

	/* hw reset, no need to flush */
	if (rf->rdma_reset)
		return;

	flush_status = nbl_get_flush_status(hw, function_id, RQDB_FLUSH_STATUS);

	rq_value = (FIELD_PREP(NBL_REG_RQ_DB_REG0_FLUSH_FLAG, 1) |
			FIELD_PREP(NBL_REG_RQ_DB_REG0_FLUSH_PFID, function_id));
	write64_reg(rq_value, rf->sc_dev.hw_regs[NBL_RQ_DB]);

	do {
		if (nbl_get_flush_status(hw, function_id, RQDB_FLUSH_STATUS) != flush_status)
			break;

		mdelay(100);
		retry_count++;
		nbl_pr_dbg("check rq db flush ready wait,function id:%d\n", function_id);
	} while (retry_count < CHECK_FLUSH_MAX_COUNT);

	if (unlikely(retry_count == CHECK_FLUSH_MAX_COUNT))
		nbl_pr_err("check rq db flush status timeout,function id:%d\n", function_id);
}

static bool nbl_hw_flush_tqp_conf(struct nbl_hw *hw, u16 function_id)
{
	u64 reg_addr;
	u16 retry_count = 0;
	u32 rdma_flush_tqp_val = 0;
	u32 tqp_flush_conf_base = NBL_TQP_FLUSH_CONF_OFF;

	reg_addr = NBL_REG_TQP_BASE(hw) + tqp_flush_conf_base;

	do {
		rdma_flush_tqp_val = rd32(hw, reg_addr);
		if ((rdma_flush_tqp_val >> NBL_TQP_FLUSH_VALID_SHIFT) == 0)
			break;

		mdelay(100);
		nbl_pr_dbg("check flush tqp vlid wait,func_id:%d\n", function_id);
		retry_count++;
	} while (retry_count < CHECK_FLUSH_MAX_COUNT);

	if (unlikely(retry_count == CHECK_FLUSH_MAX_COUNT)) {
		nbl_pr_err("check tqp conf reg val tiemout,function_id:%d\n", function_id);
		return false;
	}

	rdma_flush_tqp_val |=
		(function_id | (1 << NBL_TQP_FLUSH_VALID_SHIFT));
	wr32(hw, reg_addr, rdma_flush_tqp_val);

	return true;
}

static bool nbl_check_tqp_flush(struct nbl_hw *hw, u16 function_id)
{
	u64 reg_addr;
	u32 rdma_flush_tqp_done_val = 0;
	u32 tqp_flush_done_base = NBL_TQP_FLUSH_DONE_OFF;

	reg_addr = NBL_REG_TQP_BASE(hw) + tqp_flush_done_base;

	rdma_flush_tqp_done_val = rd32(hw, reg_addr);
	if ((rdma_flush_tqp_done_val & NBL_TQP_FLUSH_FUNCTION_ID_MASK) == function_id &&
	    (rdma_flush_tqp_done_val >> NBL_TQP_FLUSH_VALID_SHIFT) == 1) {
		return true;
	}

	return false;
}

void nbl_tqp_flush(struct nbl_pci_f *rf)
{
	struct nbl_hw *hw = &rf->hw;
	u16 function_id = rf->sc_dev.function_id;
	u16 retry_count = 0;

	if (!nbl_hw_flush_tqp_conf(hw, function_id))
		return;

	do {
		mdelay(100);

		if (nbl_check_tqp_flush(hw, function_id))
			break;
		nbl_pr_dbg("check flush tqp done wait,func_id:%d\n", function_id);
		retry_count++;
	} while (retry_count < CHECK_FLUSH_MAX_COUNT);

	if (unlikely(retry_count == CHECK_FLUSH_MAX_COUNT))
		nbl_pr_dbg("check flush tqp done timeout\n");
}

static struct nbl_hw_rdma_ops hw_rdma_ops = {
	.set_hw_sd_range = nbl_set_sd_range_tbl,
	.set_hw_vf_enable = nbl_set_vf_enable_tbl,
	.set_hw_ecpu_notify = nbl_set_ecpu_notify,
	.set_hw_cqp_reg = nbl_set_cqp_reg,
	.set_hw_vfid_vsi_map = nbl_set_vfid_vsi_map_tbl,
	.set_hw_dsch_init = nbl_pf_set_dsch_tbl,
	.set_hw_dsch_vf2vsi = nbl_set_vf2vsi_map,
	.update_hw_dsch_dport_id_direct = nbl_update_dsch_dport_id_direct,
	.set_hw_vsi_port_tbl = nbl_set_vsi_port_tbl,
	.set_hw_bdf_tbl = nbl_set_hdma_bdf_tbl,
	.set_hw_pf_tbl = nbl_set_pf_tbl,
	.set_src_addr_info = nbl_set_src_addr_info,
	.get_hw_inst_id = nbl_get_hw_instance_id,
	.put_hw_inst_id = nbl_put_hw_instance_id,
	.get_hw_stat_status = nbl_get_hw_stat_status,
	.get_hw_stat = nbl_get_hw_stat,
	.set_hw_stat = nbl_set_hw_stat,
	.enable_errcode_hw_stat = nbl_enable_errcode_hw_stat,
	.get_hw_abnormal_evt = nbl_get_hw_abnormal_event,
	.set_hw_cc_reg = nbl_set_hw_cc_reg,
	.set_hw_net_tc_tbl = nbl_set_hw_net_tc_tbl,
	.get_hw_global_cfg_flag = nbl_get_hw_global_cfg_flag,
	.set_hw_global_cfg = nbl_set_rdma_global_cfg,
	.set_hw_shaping_dpt = nbl_set_hw_shaping_dpt,
};

const struct nbl_register_layout rdma_base_v2 = {
	.rdma_top_base = NBL_REG_RDMA_TOP_V2,
	.cqpp_base = NBL_REG_CQPP_BASE_V2,
	.hdma_base = NBL_REG_HDMA_BASE_V2,
	.txp_base = NBL_REG_TXP_BASE_V2,
	.rxp_base = NBL_REG_RXP_BASE_V2,
	.txmr_base = NBL_REG_TXMR_BASE_V2,
	.txm_base = NBL_REG_TXM_BASE_V2,
	.ceaq_base = NBL_REG_CEAQ_BASE_V2,
	.stat_base = NBL_REG_STAT_BASE_V2,
	.dsch_base = NBL_REG_DSCH_BASE_V2,
	.host_pcompleter_base = NBL_REG_PCOMPLETER_HOST_BASE_V2,
	.qm_base = NBL_REG_QM_BASE_V2,
	.qpcc_base = NBL_REG_QPCC_V2,
	.cqcc_base = NBL_REG_CQCC_V2,
	.mrtc_base = NBL_REG_MRTC_V2,
	.pblc_base = NBL_REG_PBLC_V2,
	.sqrqec_base = NBL_REG_SQRQEC_V2,
	.unaqc_base = NBL_REG_UNAQC_V2,
	.srqc_base = NBL_REG_SRQC_V2,
	.pdc_base = NBL_REG_PDC_V2,
	.iorqec_base = NBL_REG_IORQEC_V2,
	.raqec_base = NBL_REG_RAQEC_V2,
	.cc_base = NBL_REG_CC_BASE_V2,
	.tqp_base = NBL_REG_TQP_BASE_V2,
	.raqp_base = NBL_REG_RAQP_BASE_V2,
};

const struct nbl_register_layout rdma_base_v3 = {
	.rdma_top_base = NBL_REG_RDMA_TOP_V3,
	.cqpp_base = NBL_REG_CQPP_BASE_V3,
	.hdma_base = NBL_REG_HDMA_BASE_V3,
	.txp_base = NBL_REG_TXP_BASE_V3,
	.txmr_base = NBL_REG_TXMR_BASE_V3,
	.txm_base = NBL_REG_TXM_BASE_V3,
	.ceaq_base = NBL_REG_CEAQ_BASE_V3,
	.stat_base = NBL_REG_STAT_BASE_V3,
	.dsch_base = NBL_REG_DSCH_BASE_V3,
	.shaping_base = NBL_REG_SHAPING_BASE_V3,
	.host_pcompleter_base = NBL_REG_PCOMPLETER_HOST_BASE_V3,
	.qm_base = NBL_REG_UQM_BASE_V3,
	.qpcc_base = NBL_REG_QPCC_V3,
	.cqcc_base = NBL_REG_CQCC_V3,
	.mrtc_base = NBL_REG_MRTC_V3,
	.pblc_base = NBL_REG_PBLC_V3,
	.sqrqec_base = NBL_REG_SQRQEC_V3,
	.unaqc_base = NBL_REG_UNAQC_V3,
	.srqc_base = NBL_REG_SRQC_V3,
	.pdc_base = NBL_REG_PDC_V3,
	.iorqec_base = NBL_REG_IORQEC_V3,
	.raqec_base = NBL_REG_RAQEC_V3,
	.cc_base = NBL_REG_CC_BASE_V3,
	.tqp_base = NBL_REG_TQP_BASE_V3,
	.raqp_base = NBL_REG_RAQP_BASE_V3,
	.uepro_base = NBL_REG_UEPRO_V3,
	.dipro_base = NBL_REG_DIPRO_V3,
	.depro_base = NBL_REG_DEPRO_V3,
};

const struct nbl_register_layout rdma_base_v4 = {
	.rdma_top_base = NBL_REG_RDMA_TOP_V4,
	.cqpp_base = NBL_REG_CQPP_BASE_V4,
	.hdma_base = NBL_REG_HDMA_BASE_V4,
	.txp_base = NBL_REG_TXP_BASE_V4,
	.rxp_base = NBL_REG_RXP_BASE_V4,
	.txmr_base = NBL_REG_TXMR_BASE_V4,
	.txm_base = NBL_REG_TXM_BASE_V4,
	.ceaq_base = NBL_REG_CEAQ_BASE_V4,
	.stat_base = NBL_REG_STAT_BASE_V4,
	.dsch_base = NBL_REG_DSCH_BASE_V4,
	.shaping_base = NBL_REG_SHAPING_BASE_V4,
	.qm_base = NBL_REG_UQM_BASE_V4,
	.qpcc_base = NBL_REG_QPCC_V4,
	.cqcc_base = NBL_REG_CQCC_V4,
	.mrtc_base = NBL_REG_MRTC_V4,
	.pblc_base = NBL_REG_PBLC_V4,
	.sqrqec_base = NBL_REG_SQRQEC_V4,
	.unaqc_base = NBL_REG_UNAQC_V4,
	.srqc_base = NBL_REG_SRQC_V4,
	.pdc_base = NBL_REG_PDC_V4,
	.iorqec_base = NBL_REG_IORQEC_V4,
	.raqec_base = NBL_REG_RAQEC_V4,
	.cc_base = NBL_REG_CC_BASE_V4,
	.tqp_base = NBL_REG_TQP_BASE_V4,
	.raqp_base = NBL_REG_RAQP_BASE_V4,
	.uepro_base = NBL_REG_UEPRO_BASE_V4,
	.dipro_base = NBL_REG_DIPRO_BASE_V4,
	.depro_base = NBL_REG_DEPRO_BASE_V4,
	.ddmux_base = NBL_REG_DDMUX_BASE_V4,
};

const struct nbl_register_layout rdma_base_v5 = {
	.rdma_top_base = NBL_REG_RDMA_TOP_V5,
	.cqpp_base = NBL_REG_CQPP_BASE_V5,
	.hdma_base = NBL_REG_HDMA_BASE_V5,
	.txp_base = NBL_REG_TXP_BASE_V5,
	.rxp_base = NBL_REG_RXP_BASE_V5,
	.txmr_base = NBL_REG_TXMR_BASE_V5,
	.txm_base = NBL_REG_TXM_BASE_V5,
	.ceaq_base = NBL_REG_CEAQ_BASE_V5,
	.stat_base = NBL_REG_STAT_BASE_V5,
	.dsch_base = NBL_REG_DSCH_BASE_V5,
	.host_pcompleter_base = NBL_REG_PCOMPLETER_HOST_BASE_V5,
	.qm_base = NBL_REG_UQM_BASE_V5,
	.qpcc_base = NBL_REG_QPCC_V5,
	.cqcc_base = NBL_REG_CQCC_V5,
	.mrtc_base = NBL_REG_MRTC_V5,
	.pblc_base = NBL_REG_PBLC_V5,
	.sqrqec_base = NBL_REG_SQRQEC_V5,
	.unaqc_base = NBL_REG_UNAQC_V5,
	.srqc_base = NBL_REG_SRQC_V5,
	.pdc_base = NBL_REG_PDC_V5,
	.iorqec_base = NBL_REG_IORQEC_V5,
	.raqec_base = NBL_REG_RAQEC_V5,
	.cc_base = NBL_REG_CC_BASE_V5,
	.tqp_base = NBL_REG_TQP_BASE_V5,
	.raqp_base = NBL_REG_RAQP_BASE_V5,
};

struct nbl_hw_rdma_ops *nbl_get_hw_rdma_ops(void)
{
	return &hw_rdma_ops;
}

void nbl_rdma_set_txm_sq_raq_separate(struct nbl_hw *hw, bool enable)
{
	void *reg_addr;

	reg_addr = hw->hw_addr +
		   NBL_TXM_REG_ADDR(NBL_REG_TXM_BASE(hw),
				     NBL_TXM_SQ_RAQ_SEPARATE_OFF);
	writel(enable, reg_addr);
}
