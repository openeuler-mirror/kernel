// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_phy_draco.h"
#include "nbl_def_common.h"
#include "nbl_hw.h"
#include "nbl_hw/nbl_p4_actions.h"
#include "nbl_hw/nbl_hw_draco/base/nbl_ppe.h"
#include "nbl_hw/nbl_hw_draco/base/nbl_datapath_qm.h"
#include "nbl_hw/nbl_hw_draco/base/nbl_datapath_ped.h"
#include "nbl_hw/nbl_hw_draco/base/nbl_datapath_dsch.h"
#include "nbl_hw/nbl_hw_draco/base/nbl_datapath_shaping.h"
#include "nbl_hw_draco/base/nbl_intf_pcompleter.h"
#include "nbl_hw_draco/base/nbl_intf_cmdq.h"
#include "nbl_hw/nbl_hw_draco/base/nbl_intf_mailbox.h"
#include "nbl_phy.h"
#include "nbl_flow_draco.h"
#include "nbl_tc_flow_draco.h"

static u32 nbl_phy_dump_registers[] = {
	NBL_UVN_DIF_DLY_ACC_NUM,
	NBL_UVN_DIFDLY0,
	NBL_UVN_DIFDLY0 + 4,	/* 64-bit high */
	NBL_UVN_DIFDLY1,
	NBL_UVN_DIFDLY2,
	NBL_UVN_DIFDLY3,
	NBL_UVN_DIFDLY3 + 4,	/* 64-bit high */
	NBL_UVN_DIFDLY4,
	NBL_UVN_DIFDLY5,
	NBL_UVN_DIFDLY6,
	NBL_UVN_DIFDLY6 + 4,	/* 64-bit high */
	NBL_UVN_DIFDLY7,
	NBL_UVN_DIFDLY8,
	NBL_UVN_DESC_PRE_DESC_REQ_NULL,
	NBL_UVN_DESC_PRE_DESC_REQ_LACK,
	NBL_UVN_DESC_RD_DROP_DESC_LACK,
	NBL_STORE_BUF_TOTAL_DROP_PKT,
	NBL_STORE_BUF_TOTAL_TRUN_PKT,
	NBL_PADPT_ROD_CH0_TAG_MAX_TIMES,
	NBL_PADPT_ROD_CH0_TAG_AVR_TIMES,
	NBL_PADPT_ROD_CH0_TAG_MIN_TIMES,
	NBL_PADPT_ROD_CH1_TAG_MAX_TIMES,
	NBL_PADPT_ROD_CH1_TAG_AVR_TIMES,
	NBL_PADPT_ROD_CH1_TAG_MIN_TIMES,
	NBL_PADPT_ROD_CH2_TAG_MAX_TIMES,
	NBL_PADPT_ROD_CH2_TAG_AVR_TIMES,
	NBL_PADPT_ROD_CH2_TAG_MIN_TIMES
};

static void nbl_phy_adapt_prototype_platform(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	u32 data;

	nbl_hw_read_regs(phy_mgt, NBL_TOP_CTRL_VERSION_DATE, (u8 *)&data, sizeof(data));

	/* if 1FPGA, set fem to low power consumption mode */
	if ((data & 0xFF00) == 0xF100) {
		nbl_hw_wr32(phy_mgt, NBL_TOP_CTRL_MDL_CLK_EN, 0xf);
		pr_info("1FPGE, set fem to low power consumption mode\n");
		nbl_hw_wr32(phy_mgt, NBL_TOP_CTRL_MDL_BYPASS_MODE, 0XB);
		pr_info("1FPGE, set top ctrl bypass mode\n");
	}
}

static void nbl_phy_cfg_eth_shaping(void *priv, u8 eth_id, u32 speed)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_shaping_dport dport = {0};
	struct nbl_shaping_dvn_dport dvn_dport = {0};
	struct nbl_shaping_rdma_dport rdma_dport = {0};

	dport.cir = speed;
	dport.pir = speed;
	dport.depth = max(dport.cir * 2, NBL_DRACO_NET_BUCKET_DEPTH);
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

	nbl_hw_write_regs(phy_mgt, NBL_SHAPING_DPORT(eth_id),
			  (u8 *)&dport, sizeof(dport));
	nbl_hw_write_regs(phy_mgt, NBL_SHAPING_DVN_DPORT(eth_id),
			  (u8 *)&dvn_dport, sizeof(dvn_dport));
	nbl_hw_write_regs(phy_mgt, NBL_SHAPING_RDMA_DPORT(eth_id),
			  (u8 *)&rdma_dport, sizeof(rdma_dport));
}

static void nbl_shaping_eth_init(struct nbl_phy_mgt *phy_mgt, u8 eth_id, u8 speed)
{
	u32 rate;

	switch (speed) {
	case NBL_FW_PORT_SPEED_25G:
		rate = NBL_SHAPING_DPORT_25G_RATE;
		break;
	case NBL_FW_PORT_SPEED_10G:
		rate = NBL_SHAPING_DPORT_10G_RATE;
		break;
	default:
		rate = NBL_SHAPING_DPORT_10G_RATE;
		break;
	}

	nbl_phy_cfg_eth_shaping(phy_mgt, eth_id, rate);
}

static int nbl_shaping_init(struct nbl_phy_mgt *phy_mgt, u8 speed)
{
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	u16 eth_id = NBL_COMMON_TO_ETH_ID(common);
	struct dsch_psha_en psha_en = {0};

	nbl_shaping_eth_init(phy_mgt, eth_id, speed);

	psha_en.en = 0xF;
	nbl_hw_write_regs(phy_mgt, NBL_DSCH_PSHA_EN_ADDR, (u8 *)&psha_en, sizeof(psha_en));

	return 0;
}

static int nbl_dsch_init(struct nbl_phy_mgt *phy_mgt, u8 speed)
{
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct pci_dev *pdev;
	struct dsch_vn_quanta quanta = {0};
	u16 lnkstat;

	pdev = NBL_COMMON_TO_PDEV(common);
	pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &lnkstat);
	if ((lnkstat & PCI_EXP_LNKSTA_CLS) == PCI_EXP_LNKSTA_CLS_16_0GB &&
	    speed == NBL_FW_PORT_SPEED_25G) {
		quanta.h_qua = NBL_HOST_QUANTA_FOR_GEN4;
		nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_QUANTA, (u8 *)&quanta, sizeof(quanta));
	}
	return 0;
}

static int nbl_dp_init(struct nbl_phy_mgt *phy_mgt, u8 speed, u8 eth_num)
{
	nbl_shaping_init(phy_mgt, speed);
	nbl_dsch_init(phy_mgt, speed);

	return 0;
}

static int nbl_ppe_init(struct nbl_phy_mgt *phy_mgt)
{
	/* FDIR UDF extraction */
	union pa_udf_ext_prof_u ext_prof;
	u8 index = 0;

	memset(&ext_prof, 0, sizeof(ext_prof));

	/* extractor index 8: extract L2 UDF 4B */
	index = 8;
	ext_prof.info.base = 1;  /* fd ether: offset start at l3 */
	ext_prof.info.oft = 0;  /* ethtool input, reserved as 0 */
	ext_prof.info.len = 0x1F;
	ext_prof.info.dst = 0x80;
	ext_prof.info.en = 1;
	nbl_hw_write_regs(phy_mgt, NBL_PA_UDF_EXT_PROF_REG(index),
			  (u8 *)&ext_prof.data, NBL_BYTES_IN_REG);

	/* extractor index 9: extract L3 UDF 4B */
	index = 9;
	ext_prof.info.base = 2;  /* l3oft */
	ext_prof.info.oft = 0;  /* ethtool input, reserved as 0 */
	ext_prof.info.len = 0x1F;
	ext_prof.info.dst = 0x80;
	ext_prof.info.en = 1;
	nbl_hw_write_regs(phy_mgt, NBL_PA_UDF_EXT_PROF_REG(index),
			  (u8 *)&ext_prof.data, NBL_BYTES_IN_REG);

	/* extractor index 10: extract L4 UDF 4B */
	index = 10;
	ext_prof.info.base = 3;  /* l4oft */
	ext_prof.info.oft = 0;  /* ethtool input, reserved as 0 */
	ext_prof.info.len = 0x1F;
	ext_prof.info.dst = 0x80;
	ext_prof.info.en = 1;
	nbl_hw_write_regs(phy_mgt, NBL_PA_UDF_EXT_PROF_REG(index),
			  (u8 *)&ext_prof.data, NBL_BYTES_IN_REG);

	return 0;
}

static int nbl_intf_init(struct nbl_phy_mgt *phy_mgt)
{
	return 0;
}

static int nbl_get_freq_ratio(struct nbl_phy_mgt *phy_mgt)
{
	return 1;
}

static int nbl_phy_init_hol(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union dmux_eth_hol_bp_u eth_hol_bp = {{0}};
	union store_qid_u store_qid = {{0}};
	union qm_hol_bp_mask_u qm_hol_mask = {{0}};
	union qm_hol_bp_u qm_hol_bp = {{0}};
	union ped_hol_timeout_th_u timeout_th = {{0}};
	union ped_hol_ctrl_u hol_ctrl = {{0}};
	union ped_hol_auto_ctrl_u hol_auto_ctrl = {{0}};
	union ped_hol_eth0_keep_active_th_u eth_active_th = {{0}};
	union dvn_hol_port_qid_response_cfg_u qid_response = {{0}};
	int i = 0;

	for (i = 0; i < NBL_DMUX_ETH_HOL_BP_DEPTH; ++i) {
		nbl_hw_read_regs(phy_mgt, NBL_DMUX_ETH_HOL_BP_REG(i),
				 (u8 *)&eth_hol_bp, sizeof(eth_hol_bp));
		eth_hol_bp.info.en = 1;
		eth_hol_bp.info.th = NBL_DMUX_ETH_HOL_BP_TH;
		nbl_hw_write_regs(phy_mgt, NBL_DMUX_ETH_HOL_BP_REG(i),
				  (u8 *)&eth_hol_bp, sizeof(eth_hol_bp));
	}

	store_qid.info.en = 1;
	nbl_hw_write_regs(phy_mgt, NBL_STORE_QID_ADDR, (u8 *)&store_qid, sizeof(store_qid));

	qm_hol_mask.info.en = 0;
	nbl_hw_write_regs(phy_mgt, NBL_QM_HOL_BP_MASK_ADDR, (u8 *)&qm_hol_mask,
			  sizeof(qm_hol_mask));
	qm_hol_bp.info.th = NBL_QM_HOL_BP_TH;
	for (i = 0; i < NBL_QM_HOL_BP_DEPTH; ++i)
		nbl_hw_write_regs(phy_mgt, NBL_QM_HOL_BP_REG(i), (u8 *)&qm_hol_bp,
				  sizeof(qm_hol_bp));

	timeout_th.info.num = NBL_PED_HOL_TIMEOUT_TH / nbl_get_freq_ratio(phy_mgt);
	nbl_hw_write_regs(phy_mgt, NBL_PED_HOL_TIMEOUT_TH_ADDR, (u8 *)&timeout_th,
			  sizeof(timeout_th));

	nbl_hw_read_regs(phy_mgt, NBL_PED_HOL_CTRL_ADDR, (u8 *)&hol_ctrl, sizeof(hol_ctrl));
	hol_ctrl.info.en = 1;
	hol_ctrl.info.keep_active_en = 1;
	nbl_hw_write_regs(phy_mgt, NBL_PED_HOL_CTRL_ADDR, (u8 *)&hol_ctrl, sizeof(hol_ctrl));

	nbl_hw_read_regs(phy_mgt, NBL_PED_HOL_AUTO_CTRL_ADDR,
			 (u8 *)&hol_auto_ctrl, sizeof(hol_auto_ctrl));
	hol_auto_ctrl.info.en = 1;
	nbl_hw_write_regs(phy_mgt, NBL_PED_HOL_AUTO_CTRL_ADDR,
			  (u8 *)&hol_auto_ctrl, sizeof(hol_auto_ctrl));

	qid_response.info.mask = 0;
	nbl_hw_write_regs(phy_mgt, NBL_DVN_HOL_PORT_QID_RESPONSE_CFG_ADDR,
			  (u8 *)&qid_response, sizeof(qid_response));

	eth_active_th.info.num = NBL_PED_HOL_ACTIVE_TH;
	nbl_hw_write_regs(phy_mgt, NBL_PED_HOL_ETH0_KEEP_ACTIVE_TH_ADDR,
			  (u8 *)&eth_active_th, sizeof(eth_active_th));
	nbl_hw_write_regs(phy_mgt, NBL_PED_HOL_ETH1_KEEP_ACTIVE_TH_ADDR,
			  (u8 *)&eth_active_th, sizeof(eth_active_th));
	nbl_hw_write_regs(phy_mgt, NBL_PED_HOL_ETH2_KEEP_ACTIVE_TH_ADDR,
			  (u8 *)&eth_active_th, sizeof(eth_active_th));
	nbl_hw_write_regs(phy_mgt, NBL_PED_HOL_ETH3_KEEP_ACTIVE_TH_ADDR,
			  (u8 *)&eth_active_th, sizeof(eth_active_th));
	nbl_hw_write_regs(phy_mgt, NBL_PED_HOL_LOOP_KEEP_ACTIVE_TH_ADDR,
			  (u8 *)&eth_active_th, sizeof(eth_active_th));

	return 0;
}

static struct nbl_phy_ped_epro_tbl ped_tbl[NBL_DRACO_PED_MAX] = {
	[NBL_DRACO_PED_UMAC_TYPE] = {.addr = NBL_PED_TBL_REP_MAC_ADDR,
				    .addr_len = NBL_PED_TBL_REP_MAC_DWLEN,},
	[NBL_DRACO_PED_UIP_TYPE] = {.addr = NBL_PED_TBL_REP_IP_ADDR,
				    .addr_len = NBL_PED_TBL_REP_IP_DWLEN,},
	[NBL_DRACO_PED_VLAN_TYPE] = {.addr = NBL_PED_TBL_VSI_TYPE_ADDR,
				    .addr_len = NBL_PED_TBL_VSI_TYPE_DWLEN,},
	[NBL_DRACO_PED_MCC_TYPE] = {.addr = NBL_MCC_GROUP_TABLE_ADDR,
				    .addr_len = NBL_MCC_GROUP_TABLE_DWLEN,},
	[NBL_DRACO_PED_TNL_TYPE] = {.addr = NBL_PED_TBL_ENCAP_ADDR,
				    .addr_len = NBL_PED_TBL_ENCAP_DWLEN,},
	[NBL_DRACO_PED_TNL_VTEP_TYPE] = {.addr = NBL_PED_TBL_ENCAP_VTEP_ADDR,
				    .addr_len = NBL_PED_TBL_ENCAP_VTEP_DWLEN,},
	[NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE] = {.addr = NBL_IPRO_DECAP_TCAM_ADDR,
				    .addr_len = NBL_IPRO_DECAP_TCAM_DWLEN,},
	[NBL_DRACO_PED_TNL_DECAP_ASSD_TYPE] = {.addr = NBL_IPRO_DECAP_ASSD_ADDR,
				    .addr_len = NBL_IPRO_DECAP_ASSD_DWLEN,},
	[NBL_DRACO_PED_MIRROR_TYPE] = {.addr = NBL_PED_TBL_MIRR_ENC_ADDR,
				    .addr_len = NBL_PED_TBL_MIRR_ENC_DWLEN,},
	[NBL_DRACO_EPRO_MIRROR_TYPE] = {.addr = NBL_EPRO_MIRROR_PROF_ADDR,
				    .addr_len = NBL_EPRO_MIRROR_PROF_DWLEN,},
};

static struct nbl_phy_ped_epro_tbl epro_tbl[NBL_DRACO_PED_MAX] = {
	[NBL_DRACO_PED_UMAC_TYPE] = {.addr = NBL_EPRO_TBL_REP_MAC_ADDR,
				    .addr_len = NBL_EPRO_TBL_REP_MAC_DWLEN,},
	[NBL_DRACO_PED_UIP_TYPE] = {.addr = NBL_EPRO_TBL_REP_IP_ADDR,
				    .addr_len = NBL_EPRO_TBL_REP_IP_DWLEN,},
};

#define NBL_PHY_PED_ADDR_REG(addr, idx, size) ((addr) + (idx) * (size) * 4)

static void nbl_phy_write_ped_tbl(void *priv, u8 *data, u16 idx, u32 ped_type)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_hw_write_regs(phy_mgt, NBL_PHY_PED_ADDR_REG(ped_tbl[ped_type].addr, idx,
							ped_tbl[ped_type].addr_len),
			  data, ped_tbl[ped_type].addr_len * 4);

	/* write epro replace tables */
	if (ped_type == NBL_DRACO_PED_UMAC_TYPE || ped_type == NBL_DRACO_PED_UIP_TYPE)
		nbl_hw_write_regs(phy_mgt, NBL_PHY_PED_ADDR_REG(epro_tbl[ped_type].addr, idx,
								epro_tbl[ped_type].addr_len),
				  data, epro_tbl[ped_type].addr_len * 4);
}

static void nbl_phy_set_driver_status(void *priv, bool active)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	u32 status = active;

	nbl_hw_write_mbx_regs(phy_mgt, NBL_REG_DRV_STATUS, (u8 *)&status, sizeof(status));
}

static void nbl_phy_set_pp_udf(void *priv, u8 udi_id, u32 value)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union pp_am_udf_prf_u udf_prf;

	memset(&udf_prf, 0, sizeof(udf_prf));

	udf_prf.data[0] = value;
	nbl_hw_write_regs(phy_mgt, NBL_PP_AM_UDF_PRF_ADDR + NBL_BYTES_IN_REG * udi_id,
			  (u8 *)&udf_prf, NBL_BYTES_IN_REG);
}

static void nbl_phy_set_epro_udf(void *priv, u8 udi_id, u32 value)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union epro_am_udf_prf_u udf_prf;

	memset(&udf_prf, 0, sizeof(udf_prf));

	udf_prf.data[0] = value;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_AM_UDF_PRF_ADDR + NBL_BYTES_IN_REG * udi_id,
			  (u8 *)&udf_prf, NBL_BYTES_IN_REG);
}

static void nbl_phy_set_acl_udf(void *priv, u8 udi_id, u32 value)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union acl_am_udf_prf_u udf_prf;

	memset(&udf_prf, 0, sizeof(udf_prf));

	udf_prf.data[0] = value;
	nbl_hw_write_regs(phy_mgt, NBL_ACL_AM_UDF_PRF_ADDR + NBL_BYTES_IN_REG * udi_id,
			  (u8 *)&udf_prf, NBL_BYTES_IN_REG);
}

static void nbl_draco_flow_udi_set_pp0_index(struct nbl_phy_mgt *phy_mgt)
{
	union nbl_udf_instruction_u inst;

	memset(&inst, 0, sizeof(inst));

	inst.prfs.p0.info.en = 1;
	inst.prfs.p0.info.sz = NBL_DRACO_UDF_SIZE_16B;
	inst.prfs.p0.info.oft = NBL_DRACO_UDF_PP0_IDX_OFT / NBL_DRACO_UDF_UNIT;
	nbl_phy_set_pp_udf(phy_mgt, NBL_DRACO_UDF_ID_SET_PP0_IDX - 1, inst.value);
}

static void nbl_draco_flow_udi_set_stat_car_mirr(struct nbl_phy_mgt *phy_mgt)
{
	union nbl_udf_instruction_u inst;

	memset(&inst, 0, sizeof(inst));

	/* flow stats & flow car */
	inst.prfs.p0.info.en = 1;
	inst.prfs.p0.info.sz = NBL_DRACO_UDF_SIZE_32B;
	inst.prfs.p0.info.oft = NBL_DRACO_UDF_FLOW_STAT_ID_OFT / NBL_DRACO_UDF_UNIT;

	/* mirror */
	inst.prfs.p1.info.en = 1;
	inst.prfs.p1.info.sz = NBL_DRACO_UDF_SIZE_8B;
	inst.prfs.p1.info.oft = NBL_DRACO_UDF_MIRR_ID_OFT / NBL_DRACO_UDF_UNIT;

	nbl_phy_set_pp_udf(phy_mgt, NBL_DRACO_UDF_ID_SET_STAT_CAR_MIRR - 1, inst.value);
}

static void nbl_draco_flow_udi_set_stat_car_mirr_flag(struct nbl_phy_mgt *phy_mgt)
{
	union nbl_udf_instruction_u inst;

	memset(&inst, 0, sizeof(inst));

	/* flow stats & flow car */
	inst.prfs.p0.info.en = 1;
	inst.prfs.p0.info.sz = NBL_DRACO_UDF_SIZE_32B;
	inst.prfs.p0.info.oft = NBL_DRACO_UDF_FLOW_STAT_ID_OFT / NBL_DRACO_UDF_UNIT;

	/* mirror */
	inst.prfs.p1.info.en = 1;
	inst.prfs.p1.info.sz = NBL_DRACO_UDF_SIZE_8B;
	inst.prfs.p1.info.oft = NBL_DRACO_UDF_MIRR_ID_OFT / NBL_DRACO_UDF_UNIT;

	nbl_phy_set_pp_udf(phy_mgt, NBL_DRACO_UDF_ID_SET_STAT_CAR_MIRR_FLAG - 1, inst.value);
}

static void nbl_draco_flow_udi_set_stat_car(struct nbl_phy_mgt *phy_mgt)
{
	union nbl_udf_instruction_u inst;

	memset(&inst, 0, sizeof(inst));

	/* flow stats & flow car */
	inst.prfs.p0.info.en = 1;
	inst.prfs.p0.info.sz = NBL_DRACO_UDF_SIZE_32B;
	inst.prfs.p0.info.oft = NBL_DRACO_UDF_FLOW_STAT_ID_OFT / NBL_DRACO_UDF_UNIT;

	nbl_phy_set_pp_udf(phy_mgt, NBL_DRACO_UDF_ID_SET_STAT_CAR - 1, inst.value);
}

static void nbl_draco_flow_udi_set_stat_car_flow_id(struct nbl_phy_mgt *phy_mgt)
{
	union nbl_udf_instruction_u inst;

	memset(&inst, 0, sizeof(inst));

	/* flow stats & flow car */
	inst.prfs.p0.info.en = 1;
	inst.prfs.p0.info.sz = NBL_DRACO_UDF_SIZE_32B;
	inst.prfs.p0.info.oft = NBL_DRACO_UDF_FLOW_STAT_ID_OFT / NBL_DRACO_UDF_UNIT;

	/* mirror */
	inst.prfs.p1.info.en = 1;
	inst.prfs.p1.info.sz = NBL_DRACO_UDF_SIZE_8B;
	inst.prfs.p1.info.oft = NBL_DRACO_UDF_MIRR_ID_OFT / NBL_DRACO_UDF_UNIT;

	/* flow_id */
	inst.prfs.p2.info.en = 1;
	inst.prfs.p2.info.sz = NBL_DRACO_UDF_SIZE_8B;
	inst.prfs.p2.info.oft = NBL_DRACO_UDF_NVGRE_FLOW_ID_OFT / NBL_DRACO_UDF_UNIT;

	nbl_phy_set_pp_udf(phy_mgt, NBL_DRACO_UDF_ID_SET_STAT_CAR_MIRR_FLOW_ID - 1, inst.value);
}

static void nbl_draco_flow_udi_set_epro_car(struct nbl_phy_mgt *phy_mgt)
{
	union nbl_udf_instruction_u inst;

	memset(&inst, 0, sizeof(inst));

	/* flow car first 8 bits */
	inst.prfs.p0.info.en = 1;
	inst.prfs.p0.info.sz = NBL_DRACO_UDF_SIZE_8B;
	inst.prfs.p0.info.oft = NBL_DRACO_UDF_FLOW_CAR_OFT / NBL_DRACO_UDF_UNIT;

	/* flow car next 4 bits, set with mask */
	inst.prfs.p1.info.en = 1;
	inst.prfs.p1.info.sz = NBL_DRACO_UDF_SIZE_8B_MASK;
	inst.prfs.p1.info.oft =
		(NBL_DRACO_UDF_FLOW_CAR_OFT + NBL_BITS_IN_U8) / NBL_DRACO_UDF_UNIT;

	nbl_phy_set_epro_udf(phy_mgt, NBL_DRACO_EPRO_UDF_ID_SET_CAR - 1, inst.value);
}

static void nbl_draco_acl_udi_set_acl0_index(struct nbl_phy_mgt *phy_mgt)
{
	union nbl_udf_instruction_u inst;

	memset(&inst, 0, sizeof(inst));

	inst.prfs.p0.info.en = 1;
	inst.prfs.p0.info.sz = NBL_DRACO_UDF_SIZE_8B_MASK;
	inst.prfs.p0.info.oft = 0; /* use mask to avoid overwrite UDF_FLAG */
	inst.prfs.p1.info.en = 1;
	inst.prfs.p1.info.sz = NBL_DRACO_UDF_SIZE_8B;
	inst.prfs.p1.info.oft = NBL_BITS_IN_U8 / NBL_DRACO_UDF_UNIT;
	nbl_phy_set_acl_udf(phy_mgt, NBL_DRACO_ACL_UDF_ID_SET_ACL0_IDX - 1, inst.value);
}

static void nbl_draco_acl_udi_set_car(struct nbl_phy_mgt *phy_mgt)
{
	union nbl_udf_instruction_u inst;

	memset(&inst, 0, sizeof(inst));

	/* flow car first 8 bits */
	inst.prfs.p0.info.en = 1;
	inst.prfs.p0.info.sz = NBL_DRACO_UDF_SIZE_8B;
	inst.prfs.p0.info.oft = NBL_DRACO_UDF_FLOW_CAR_OFT / NBL_DRACO_UDF_UNIT;

	/* flow car next 4 bits, set with mask */
	inst.prfs.p1.info.en = 1;
	inst.prfs.p1.info.sz = NBL_DRACO_UDF_SIZE_8B_MASK;
	inst.prfs.p1.info.oft =
		(NBL_DRACO_UDF_FLOW_CAR_OFT + NBL_BITS_IN_U8) / NBL_DRACO_UDF_UNIT;

	nbl_phy_set_acl_udf(phy_mgt, NBL_DRACO_ACL_UDF_ID_CAR - 1, inst.value);
}

static void nbl_draco_acl_udi_set_car_mirr(struct nbl_phy_mgt *phy_mgt)
{
	union nbl_udf_instruction_u inst;

	memset(&inst, 0, sizeof(inst));

	/* flow car first 8 bits */
	inst.prfs.p0.info.en = 1;
	inst.prfs.p0.info.sz = NBL_DRACO_UDF_SIZE_8B;
	inst.prfs.p0.info.oft = NBL_DRACO_UDF_FLOW_CAR_OFT / NBL_DRACO_UDF_UNIT;

	/* flow car next 4 bits, set with mask */
	inst.prfs.p1.info.en = 1;
	inst.prfs.p1.info.sz = NBL_DRACO_UDF_SIZE_8B_MASK;
	inst.prfs.p1.info.oft =
		(NBL_DRACO_UDF_FLOW_CAR_OFT + NBL_BITS_IN_U8) / NBL_DRACO_UDF_UNIT;

	/* mirror: 8 bits */
	inst.prfs.p2.info.en = 1;
	inst.prfs.p2.info.sz = NBL_DRACO_UDF_SIZE_8B;
	inst.prfs.p2.info.oft = NBL_DRACO_UDF_MIRR_ID_OFT / NBL_DRACO_UDF_UNIT;

	nbl_phy_set_acl_udf(phy_mgt, NBL_DRACO_ACL_UDF_ID_CAR_MIRR - 1, inst.value);
}

static void nbl_draco_acl_udi_set_car_mirr_flow_id(struct nbl_phy_mgt *phy_mgt)
{
	union nbl_udf_instruction_u inst;

	memset(&inst, 0, sizeof(inst));

	/* flow car first 8 bits */
	inst.prfs.p0.info.en = 1;
	inst.prfs.p0.info.sz = NBL_DRACO_UDF_SIZE_8B;
	inst.prfs.p0.info.oft = NBL_DRACO_UDF_FLOW_CAR_OFT / NBL_DRACO_UDF_UNIT;

	/* flow car next 4 bits, set with mask */
	inst.prfs.p1.info.en = 1;
	inst.prfs.p1.info.sz = NBL_DRACO_UDF_SIZE_8B_MASK;
	inst.prfs.p1.info.oft =
		(NBL_DRACO_UDF_FLOW_CAR_OFT + NBL_BITS_IN_U8) / NBL_DRACO_UDF_UNIT;

	/* mirror: 8 bits */
	inst.prfs.p2.info.en = 1;
	inst.prfs.p2.info.sz = NBL_DRACO_UDF_SIZE_8B;
	inst.prfs.p2.info.oft = NBL_DRACO_UDF_MIRR_ID_OFT / NBL_DRACO_UDF_UNIT;

	/* nvgre flow id: 8 bits */
	inst.prfs.p3.info.en = 1;
	inst.prfs.p3.info.sz = NBL_DRACO_UDF_SIZE_8B;
	inst.prfs.p3.info.oft = NBL_DRACO_UDF_NVGRE_FLOW_ID_OFT / NBL_DRACO_UDF_UNIT;

	nbl_phy_set_acl_udf(phy_mgt, NBL_DRACO_ACL_UDF_ID_CAR_MIRR_FLOW_ID - 1, inst.value);
}

static void nbl_draco_acl_udi_clear_stat_car_mirr(struct nbl_phy_mgt *phy_mgt)
{
	union nbl_udf_instruction_u inst;

	memset(&inst, 0, sizeof(inst));

	/* used to set flow_stat & car: 32bits */
	inst.prfs.p0.info.en = 1;
	inst.prfs.p0.info.sz = NBL_DRACO_UDF_SIZE_32B;
	inst.prfs.p0.info.oft = NBL_DRACO_UDF_FLOW_STAT_ID_OFT / NBL_DRACO_UDF_UNIT;

	/* used to set mirror 8bits */
	inst.prfs.p1.info.en = 1;
	inst.prfs.p1.info.sz = NBL_DRACO_UDF_SIZE_8B;
	inst.prfs.p1.info.oft = NBL_DRACO_UDF_MIRR_ID_OFT / NBL_DRACO_UDF_UNIT;

	nbl_phy_set_acl_udf(phy_mgt, NBL_DRACO_ACL_UDL_ID_STAT_CAR_MIRR - 1, inst.value);
}

static void nbl_draco_flow_init_udi(struct nbl_phy_mgt *phy_mgt)
{
	nbl_draco_flow_udi_set_pp0_index(phy_mgt);
	nbl_draco_flow_udi_set_stat_car_mirr(phy_mgt);
	nbl_draco_flow_udi_set_stat_car_mirr_flag(phy_mgt);
	nbl_draco_flow_udi_set_stat_car(phy_mgt);
	nbl_draco_flow_udi_set_stat_car_flow_id(phy_mgt);
	nbl_draco_flow_udi_set_epro_car(phy_mgt);
}

static void nbl_draco_acl_init_udi(struct nbl_phy_mgt *phy_mgt)
{
	nbl_draco_acl_udi_set_acl0_index(phy_mgt);
	nbl_draco_acl_udi_set_car(phy_mgt);
	nbl_draco_acl_udi_set_car_mirr(phy_mgt);
	nbl_draco_acl_udi_set_car_mirr_flow_id(phy_mgt);
	nbl_draco_acl_udi_clear_stat_car_mirr(phy_mgt);
}

static int nbl_phy_init_chip_module(void *priv, u8 eth_speed, u8 eth_num)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	int ret = 0;

	nbl_phy_adapt_prototype_platform(phy_mgt);
	nbl_dp_init(phy_mgt, eth_speed, eth_num);
	nbl_ppe_init(phy_mgt);
	nbl_intf_init(phy_mgt);
	nbl_phy_init_hol(phy_mgt);

	nbl_draco_flow_init_udi(phy_mgt);
	nbl_draco_acl_init_udi(phy_mgt);

	pr_info("nbl chip module init success\n");

	return ret;
}

static u32 nbl_phy_get_host_pf_mask(void *priv, u8 func_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	u32 data;

	nbl_hw_read_regs(phy_mgt, NBL_PCIE_K_PF_PCICONF_255_224(func_id),
			 (u8 *)&data, sizeof(data));
	return data;
}

static u32 nbl_phy_get_host_pf_fid(void *priv, u8 func_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	u32 data;

	nbl_hw_read_regs(phy_mgt, NBL_PCIE_K_PF_SRIOV_287_256(func_id), (u8 *)&data, sizeof(data));
	return data;
}

static int nbl_phy_capture_bdf(void *priv, u16 *func_id, u8 *mgt_pf, u16 *bdf)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_pcompleter_bdf_capture pcompleter_bdf_capture = { 0 };

	nbl_hw_read_regs(phy_mgt, NBL_PCOMPLETER_BDF_CAPTURE_OFFSET,
			 (u8 *)&pcompleter_bdf_capture, sizeof(pcompleter_bdf_capture));

	*func_id = pcompleter_bdf_capture.fid;
	*mgt_pf = pcompleter_bdf_capture.pf_num;
	*bdf = pcompleter_bdf_capture.bdf;

	return 0;
}

static u8 __iomem *nbl_phy_get_hw_addr(void *priv, size_t *size)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	if (size)
		*size = (size_t)phy_mgt->hw_size;
	return phy_mgt->hw_addr;
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

const struct nbl_chip_tempmap table[] = {
	{352, 125}, {360, 120}, {369, 115}, {377, 110}, {386, 105},
	{394, 100}, {403, 95}, {412, 90}, {420, 85}, {428, 80},
	{437, 75}, {446, 70}, {454, 65}, {463, 60}, {471, 55},
	{480, 50}, {488, 45}, {496, 40}, {505, 35}, {513, 30},
	{522, 25}, {530, 20}, {539, 15}, {547, 10}, {556, 5},
	{564, 0}, {572, -5}, {581, -10}, {589, -15}, {598, -20},
	{606, -25}, {615, -30}, {623, -35}, {631, -40}
};

static int nbl_phy_get_temperature(int input)
{
	u32 size = ARRAY_SIZE(table);
	int i, x0, x1, y0, y1;

	if (input <= table[0].val)
		return table[0].deg;
	if (input >= table[size - 1].val)
		return table[size - 1].deg;
	for (i = 0; i < size - 1; i++) {
		if (input >= table[i].val && input <= table[i + 1].val) {
			x0 = table[i].val;
			x1 = table[i + 1].val;
			y0 = table[i].deg;
			y1 = table[i + 1].deg;
			return y0 + (input - x0) * (y1 - y0) / (x1 - x0);
		}
	}
	return 0;
}

/* return value need to convert to Mil degree Celsius(1/1000) */
static int nbl_phy_get_chip_temperature(void *priv, enum nbl_hwmon_type type, u32 senser_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_top_ctrl_tvsensor0 sensor;
	int temp = 0;

	nbl_hw_read_regs(phy_mgt, NBL_TOP_CTRL_TVSENSOR0_VAU, (u8 *)&sensor, sizeof(sensor));

	switch (type) {
	case NBL_HWMON_TEMP_INPUT:
		temp = nbl_phy_get_temperature(sensor.temp) * 1000;
		break;
	case NBL_HWMON_TEMP_MAX:
		temp = NBL_DRACO_TEMP_MAX * 1000;
		break;
	case NBL_HWMON_TEMP_CRIT:
		temp = NBL_DRACO_TEMP_CRIT * 1000;
		break;
	case NBL_HWMON_TEMP_HIGHEST:
		temp = nbl_phy_get_temperature(sensor.max_temp) * 1000;
		break;
	default:
		break;
	}
	return temp;
}

static int nbl_phy_process_abnormal_event(void *priv,
					  struct nbl_abnormal_event_info *abnomal_info)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct device *dev = NBL_PHY_MGT_TO_DEV(phy_mgt);
	u32 int_status = 0;

	nbl_hw_read_regs(phy_mgt, NBL_DVN_INT_STATUS, (u8 *)&int_status, sizeof(u32));
	if (int_status) {
		dev_info(dev, "dvn int_status:%x\n", int_status);
		/* clear dvn abnormal irq */
		nbl_hw_write_regs(phy_mgt, NBL_DVN_INT_STATUS,
				  (u8 *)&int_status, sizeof(int_status));
	}

	int_status = 0;
	nbl_hw_read_regs(phy_mgt, NBL_DSCH_INT_STATUS, (u8 *)&int_status, sizeof(u32));
	if (int_status) {
		dev_info(dev, "dsch int_status:%x\n", int_status);
		/* clear dsch abnormal irq */
		nbl_hw_write_regs(phy_mgt, NBL_DSCH_INT_STATUS,
				  (u8 *)&int_status, sizeof(int_status));
	}

	return 0;
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

static void nbl_phy_config_mailbox_rxq(void *priv, dma_addr_t dma_addr, int size_bwid)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_mailbox_qinfo_cfg_table qinfo_cfg_rx_table = { 0 };

	qinfo_cfg_rx_table.queue_rst = 1;
	nbl_hw_write_mbx_regs(phy_mgt, NBL_MBX_QINFO_CFG_RX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_rx_table, sizeof(qinfo_cfg_rx_table));

	qinfo_cfg_rx_table.queue_base_addr_l = (u32)(dma_addr & 0xFFFFFFFF);
	qinfo_cfg_rx_table.queue_base_addr_h = upper_32_bits(dma_addr);
	qinfo_cfg_rx_table.queue_size_bwind = (u32)size_bwid;
	qinfo_cfg_rx_table.queue_rst = 0;
	qinfo_cfg_rx_table.queue_en = 1;
	nbl_hw_write_mbx_regs(phy_mgt, NBL_MBX_QINFO_CFG_RX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_rx_table, sizeof(qinfo_cfg_rx_table));
}

static void nbl_phy_config_mailbox_txq_rst(void *priv, dma_addr_t dma_addr, int size_bwid)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_mailbox_qinfo_cfg_table qinfo_cfg_tx_table = { 0 };

	qinfo_cfg_tx_table.queue_rst = 1;
	nbl_hw_write_mbx_regs(phy_mgt, NBL_MBX_QINFO_CFG_TX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_tx_table, sizeof(qinfo_cfg_tx_table));

	qinfo_cfg_tx_table.queue_base_addr_l = (u32)(dma_addr & 0xFFFFFFFF);
	qinfo_cfg_tx_table.queue_base_addr_h = upper_32_bits(dma_addr);
	qinfo_cfg_tx_table.queue_size_bwind = (u32)size_bwid;
	qinfo_cfg_tx_table.queue_rst = 0;
	qinfo_cfg_tx_table.queue_en = 1;
	nbl_hw_write_mbx_regs(phy_mgt, NBL_MBX_QINFO_CFG_TX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_tx_table, sizeof(qinfo_cfg_tx_table));
}

static void nbl_phy_config_mailbox_txq(void *priv, dma_addr_t dma_addr, int size_bwid)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_mailbox_qinfo_cfg_table qinfo_cfg_tx_table = { 0 };

	qinfo_cfg_tx_table.queue_base_addr_l = (u32)(dma_addr & 0xFFFFFFFF);
	qinfo_cfg_tx_table.queue_base_addr_h = upper_32_bits(dma_addr);
	qinfo_cfg_tx_table.queue_size_bwind = (u32)size_bwid;
	qinfo_cfg_tx_table.queue_rst = 0;
	qinfo_cfg_tx_table.queue_en = 1;
	nbl_hw_write_mbx_regs(phy_mgt, NBL_MBX_QINFO_CFG_TX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_tx_table, sizeof(qinfo_cfg_tx_table));
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

static void nbl_phy_stop_mailbox_rxq(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_mailbox_qinfo_cfg_table qinfo_cfg_rx_table = { 0 };

	nbl_hw_write_mbx_regs(phy_mgt, NBL_MBX_QINFO_CFG_RX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_rx_table, sizeof(qinfo_cfg_rx_table));
}

static void nbl_phy_stop_mailbox_txq(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_mailbox_qinfo_cfg_table qinfo_cfg_tx_table = { 0 };

	nbl_hw_write_mbx_regs(phy_mgt, NBL_MBX_QINFO_CFG_TX_TABLE_ADDR,
			      (u8 *)&qinfo_cfg_tx_table, sizeof(qinfo_cfg_tx_table));
}

static void nbl_phy_enable_mailbox_irq(void *priv, u16 func_id, bool enable_msix,
				       u16 global_vector_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_mailbox_qinfo_map_table mb_qinfo_map = { 0 };

	nbl_hw_read_regs(phy_mgt, NBL_MAILBOX_QINFO_MAP_REG_ARR(func_id),
			 (u8 *)&mb_qinfo_map, sizeof(mb_qinfo_map));

	if (enable_msix) {
		mb_qinfo_map.msix_idx = global_vector_id;
		mb_qinfo_map.msix_idx_vaild = 1;
	} else {
		mb_qinfo_map.msix_idx = 0;
		mb_qinfo_map.msix_idx_vaild = 0;
	}

	nbl_hw_write_regs(phy_mgt, NBL_MAILBOX_QINFO_MAP_REG_ARR(func_id),
			  (u8 *)&mb_qinfo_map, sizeof(mb_qinfo_map));
}

static void nbl_phy_update_mailbox_queue_tail_ptr(void *priv, u16 tail_ptr, u8 txrx)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	/* local_qid 0 and 1 denote rx and tx queue respectively */
	u32 local_qid = txrx;
	u32 value = ((u32)tail_ptr << 16) | local_qid;

	/* wmb */
	wmb();
	writel(value, phy_mgt->mailbox_bar_hw_addr + NBL_MAILBOX_NOTIFY_ADDR);
}

static bool nbl_phy_check_mailbox_dma_err(void *priv, bool tx)
{
	struct nbl_mailbox_qinfo_cfg_table qinfo_cfg_tbl = { 0 };
	u64 addr;

	if (tx)
		addr = NBL_MBX_QINFO_CFG_TX_TABLE_ADDR;
	else
		addr = NBL_MBX_QINFO_CFG_RX_TABLE_ADDR;

	nbl_hw_read_mbx_regs(priv, addr, (u8 *)&qinfo_cfg_tbl, sizeof(qinfo_cfg_tbl));
	return !!qinfo_cfg_tbl.dif_err;
}

static void nbl_phy_dump_mailbox_dbg(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_mailbox_qinfo_cfg_dbg_tbl cfg_dbg_tbl = { 0 };
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);

	nbl_hw_read_mbx_regs(priv, NBL_MBX_QINFO_CFG_DBG_TABLE_ADDR,
			     (u8 *)&cfg_dbg_tbl, sizeof(cfg_dbg_tbl));
	nbl_info(common, NBL_DEBUG_PHY, "qinfo_cfg_dbg_table, rx_pkt_drop:%x, rx_pkt_get:%x, tx_pkt_drop:%x, tx_pkt_out:%x, rx_queue_hd_ptr:%x, tx_queue_hd_ptr:%x, rx_queue_tail_ptr:%x, tx_queue_tail_ptr:%x\n",
		 cfg_dbg_tbl.rx_pkt_drop, cfg_dbg_tbl.rx_pkt_get, cfg_dbg_tbl.tx_pkt_drop,
		 cfg_dbg_tbl.tx_pkt_out, cfg_dbg_tbl.rx_queue_hd_ptr, cfg_dbg_tbl.tx_queue_hd_ptr,
		 cfg_dbg_tbl.rx_queue_tail_ptr, cfg_dbg_tbl.tx_queue_tail_ptr);
}

static void nbl_dvn_descreq_num_cfg(void *priv, u32 descreq_num)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_dvn_descreq_num_cfg descreq_num_cfg = { 0 };
	u32 packet_ring_prefect_num = descreq_num & 0xffff;

	packet_ring_prefect_num = packet_ring_prefect_num > 32 ? 32 : packet_ring_prefect_num;
	packet_ring_prefect_num = packet_ring_prefect_num < 8 ? 8 : packet_ring_prefect_num;
	descreq_num_cfg.descreq_num = (packet_ring_prefect_num - 8) / 4;

	nbl_hw_write_regs(phy_mgt, NBL_DVN_DESCREQ_NUM_CFG,
			  (u8 *)&descreq_num_cfg, sizeof(descreq_num_cfg));
}

static u32 nbl_dvn_descreq_num_get(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_dvn_descreq_num_cfg descreq_num_cfg = { 0 };

	nbl_hw_read_regs(phy_mgt, NBL_DVN_DESCREQ_NUM_CFG,
			 (u8 *)&descreq_num_cfg, sizeof(descreq_num_cfg));

	return descreq_num_cfg.descreq_num * 4 + 8;
}

static int nbl_phy_reset_dvn_cfg(void *priv, u16 queue_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct nbl_dvn_queue_reset queue_reset = {0};

	queue_reset.dvn_queue_index = queue_id;
	nbl_hw_write_regs(phy_mgt, NBL_DVN_QUEUE_RESET_REG,
			  (u8 *)&queue_reset, sizeof(queue_reset));

	udelay(5);
	nbl_debug(common, NBL_DEBUG_QUEUE, "dvn:%u cfg reset succedd\n", queue_id);

	return 0;
}

static int nbl_phy_reset_uvn_cfg(void *priv, u16 queue_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct nbl_uvn_queue_reset queue_reset = {0};

	queue_reset.index = queue_id;
	nbl_hw_write_regs(phy_mgt, NBL_UVN_QUEUE_RESET_REG,
			  (u8 *)&queue_reset, sizeof(queue_reset));

	udelay(5);
	nbl_debug(common, NBL_DEBUG_QUEUE, "uvn:%u cfg reset succedd\n", queue_id);

	return 0;
}

static int nbl_phy_restore_dvn_context(void *priv, u16 queue_id, u16 split, u16 last_avail_index)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct dvn_queue_context cxt = {0};

	cxt.dvn_ring_wrap_counter = last_avail_index >> 15;
	if (split)
		cxt.dvn_avail_read_ptr = last_avail_index;
	else
		cxt.dvn_ring_read_ptr = last_avail_index & 0x7FFF;

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

static u32 nbl_phy_get_fake_drop_stats(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union acl_flow_stats_u flow_stats;
	int flow_id = NBL_SMAC_SPOOF_STAT_ID;
	u32 cnt;

	memset(&flow_stats, 0, sizeof(flow_stats));
	nbl_hw_read_regs(phy_mgt, NBL_ACL_FLOW_STATS_REG(flow_id),
			 (u8 *)&flow_stats, sizeof(flow_stats));
	cnt = (flow_stats.info.cnt_arr[0] >> 24) + (flow_stats.info.cnt_arr[1] << 8);
	return cnt;
}

static int nbl_phy_get_uvn_drop_queue_disable(void *priv, u32 *uvn_drop_queue_disable)
{
	*uvn_drop_queue_disable = nbl_hw_rd32(priv, NBL_UVN_DESC_RD_DROP_QUEUE_DISABLE);
	return 0;
}

static int nbl_phy_get_tx_queue_cfg(void *priv, void *data, u16 queue_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_queue_cfg_param *queue_cfg = (struct nbl_queue_cfg_param *)data;
	struct dvn_queue_table info = {0};

	nbl_hw_read_regs(phy_mgt, NBL_DVN_QUEUE_TABLE_ARR(queue_id), (u8 *)&info, sizeof(info));

	queue_cfg->desc = info.queue_desc_baddr;
	queue_cfg->avail = info.queue_avail_baddr;
	queue_cfg->used = info.queue_used_baddr;
	queue_cfg->size = info.desc_ring_size;
	queue_cfg->split = info.queue_type;
	queue_cfg->extend_header = info.extend_header_en;

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

	info.queue_desc_baddr = queue_cfg->desc;
	if (!queue_cfg->split && !queue_cfg->extend_header)
		queue_cfg->avail = queue_cfg->avail | 3;
	info.queue_avail_baddr = queue_cfg->avail;
	info.queue_used_baddr = queue_cfg->used;
	info.desc_ring_size = ilog2(queue_cfg->size);
	info.queue_type = queue_cfg->split;
	info.extend_header_en = queue_cfg->extend_header;
	info.queue_en = 1;
	info.vsi_id = queue_cfg->vsi_id;

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
	/* prevent uvn notify reach before reset */
	nbl_hw_read_regs(phy_mgt, NBL_UVN_QUEUE_TABLE_ARR(queue_id), (u8 *)&info, sizeof(info));

	return 0;
}

static int nbl_phy_disable_dvn(void *priv, u16 queue_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct dvn_queue_table info = {0};

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

static u64 nbl_phy_save_dvn_ctx(void *priv, u16 queue_id, u16 split)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct dvn_queue_context dvn_ctx = {0};
	struct nbl_dvn_vdpa_idx dvn_idx = {0};
	u64 last_desc_idx;

	nbl_hw_read_regs(phy_mgt, NBL_DVN_QUEUE_CXT_TABLE_ARR(queue_id),
			 (u8 *)&dvn_ctx, sizeof(dvn_ctx));
	nbl_hw_read_regs(phy_mgt, NBL_DVN_VDPA_IDX_TABLE_ARR(queue_id),
			 (u8 *)&dvn_idx, sizeof(dvn_idx));

	nbl_debug(common, NBL_DEBUG_QUEUE, "DVNQ save ctx: %d packed: %08x %08x split: %08x\n",
		  queue_id, dvn_ctx.dvn_ring_wrap_counter, dvn_ctx.dvn_ring_read_ptr,
		  dvn_ctx.dvn_avail_ring_idx);

	last_desc_idx = dvn_idx.idx_vld_flag << 31 | dvn_idx.last_idx_offset;
	if (split)
		return last_desc_idx << 16 | dvn_ctx.dvn_avail_ring_idx;
	else
		return (last_desc_idx << 16) | (dvn_ctx.dvn_ring_read_ptr & 0x7FFF) |
			(dvn_ctx.dvn_ring_wrap_counter << 15);
}

static u64 nbl_phy_save_uvn_ctx(void *priv, u16 queue_id, u16 split, u16 queue_size)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct uvn_queue_cxt queue_cxt = {0};
	struct uvn_desc_cxt desc_cxt = {0};
	struct uvn_descwb_uidx descwb_uidx = {0};
	u16 cache_diff, queue_head, wrap_count;
	u64 last_desc_index;

	nbl_hw_read_regs(phy_mgt, NBL_UVN_QUEUE_CXT_TABLE_ARR(queue_id),
			 (u8 *)&queue_cxt, sizeof(queue_cxt));
	nbl_hw_read_regs(phy_mgt, NBL_UVN_DESC_CXT_TABLE_ARR(queue_id),
			 (u8 *)&desc_cxt, sizeof(desc_cxt));
	nbl_hw_read_regs(phy_mgt, NBL_UVN_DESCWB_UIDX(queue_id),
			 (u8 *)&descwb_uidx, sizeof(descwb_uidx));

	nbl_debug(common, NBL_DEBUG_QUEUE,
		  "UVN save ctx: %d cache_tail: %08x cache_head %08x queue_head: %08x\n",
		  queue_id, desc_cxt.cache_tail, desc_cxt.cache_head, queue_cxt.queue_head);

	last_desc_index = descwb_uidx.used_idx_valid << 31 | descwb_uidx.pkt_fst_descwb_used_idx;
	cache_diff = (desc_cxt.cache_tail - desc_cxt.cache_head + 64) & (0x3F);
	queue_head = (queue_cxt.queue_head - cache_diff + 65536) & (0xFFFF);
	if (!queue_size)
		return -1UL;

	wrap_count = !((queue_head / queue_size) & 0x1);

	nbl_debug(common, NBL_DEBUG_QUEUE, "UVN save ctx: %d packed: %08x %08x split: %08x\n",
		  queue_id, wrap_count, queue_head, queue_head);

	if (split)
		return (last_desc_index << 16 | queue_head);
	else
		return (last_desc_index << 16) | (queue_head & 0x7FFF) | (wrap_count << 15);
}

static bool nbl_phy_is_txq_drain_out(struct nbl_phy_mgt *phy_mgt, u16 queue_id,
				     struct dsch_vn_tc_q_list_tbl *tc_q_list)
{
	nbl_hw_read_regs(phy_mgt, NBL_DSCH_VN_TC_Q_LIST_TABLE_ADDR(queue_id),
			 (u8 *)tc_q_list, sizeof(*tc_q_list));
	if (!tc_q_list->regi && !tc_q_list->fly)
		return true;

	return false;
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

static void nbl_phy_lso_drain_time_out_debug(struct nbl_phy_mgt *phy_mgt, u16 queue_id)
{
	struct dsch_vn_tc_q_list_tbl tc_q_list = {0};

	nbl_hw_read_regs(phy_mgt, NBL_DSCH_VN_TC_Q_LIST_TABLE_ADDR(queue_id),
			 (u8 *)&tc_q_list, sizeof(tc_q_list));
	pr_err("queue_id %d tc_q_list regi %d fly %d vld %d",
	       queue_id, tc_q_list.regi, tc_q_list.fly, tc_q_list.vld);
}

static void nbl_phy_rsc_drain_time_out_debug(struct nbl_phy_mgt *phy_mgt, u16 queue_id)
{
	struct uvn_desc_cxt cache_ctx = {0};
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);

	nbl_hw_read_regs(phy_mgt, NBL_UVN_DESC_CXT_TABLE_ARR(queue_id),
			 (u8 *)&cache_ctx, sizeof(cache_ctx));
	nbl_info(common, NBL_DEBUG_QUEUE, "queue %u pref_num_prev %d pref_num_post %d\n",
		 queue_id, cache_ctx.cache_pref_num_prev, cache_ctx.cache_pref_num_post);
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

	nbl_hw_read_regs(phy_mgt, NBL_DSCH_VN_Q2TC_CFG_TABLE_ADDR(queue_id),
			 (u8 *)&info, sizeof(info));
	info.vld = 0;
	nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_Q2TC_CFG_TABLE_ADDR(queue_id),
			  (u8 *)&info, sizeof(info));
	do {
		if (nbl_phy_is_txq_drain_out(phy_mgt, queue_id, &tc_q_list))
			break;

		usleep_range(10, 20);
		i++;
	} while (++i < NBL_DRAIN_WAIT_TIMES);

	if (i >= NBL_DRAIN_WAIT_TIMES) {
		nbl_err(common, NBL_DEBUG_QUEUE, "queue %u lso dsch drain timeout, regi %u, fly %u, vld %u\n",
			queue_id, tc_q_list.regi, tc_q_list.fly, tc_q_list.vld);
		nbl_phy_lso_drain_time_out_debug(phy_mgt, queue_id);
		return -EIO;
	}

	return 0;
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
		nbl_phy_rsc_drain_time_out_debug(phy_mgt, queue_id);
		return -1;
	}

	return 0;
}

static void nbl_phy_get_tx_queue_err_stats(void *priv, u16 queue_id,
					   struct nbl_queue_err_stats *queue_err_stats)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_dvn_stat_cnt dvn_stat_cnt;

	nbl_hw_read_regs(phy_mgt, NBL_DVN_STAT_CNT(queue_id),
			 (u8 *)&dvn_stat_cnt, sizeof(dvn_stat_cnt));
	queue_err_stats->dvn_pkt_drop_cnt = dvn_stat_cnt.dvn_whole_req_pkt_cnt -
					    dvn_stat_cnt.dvn_pkt_fwd_cnt;
}

static void nbl_phy_get_rx_queue_err_stats(void *priv, u16 queue_id,
					   struct nbl_queue_err_stats *queue_err_stats)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	queue_err_stats->uvn_stat_pkt_drop =
		nbl_hw_rd32(phy_mgt, NBL_UVN_STATIS_PKT_DROP(queue_id));
}

static int nbl_phy_get_uvn_pkt_drop_stats(void *priv, u16 global_queue_id, u32 *uvn_stat_pkt_drop)
{
	*uvn_stat_pkt_drop = nbl_hw_rd32(priv, NBL_UVN_STATIS_PKT_DROP(global_queue_id));
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

static void nbl_phy_configure_msix_map(void *priv, u16 func_id, bool valid,
				       dma_addr_t dma_addr, u8 bus, u8 devid, u8 function)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_pcompleter_msix_map_table msix_map_table = { 0 };

	if (valid) {
		msix_map_table.msix_map_base_addr = dma_addr;
		/* use af's bdf, because dma memmory is alloc by af */
		msix_map_table.function = function;
		msix_map_table.devid = devid;
		msix_map_table.bus = bus;
		msix_map_table.valid = 1;
	}

	nbl_hw_write_regs(phy_mgt, NBL_PCOMPLETER_MSIX_MAP_TABLE_ADDR(func_id),
			  (u8 *)&msix_map_table, sizeof(msix_map_table));
}

static void nbl_phy_configure_msix_info(void *priv, u16 func_id, bool valid, u16 interrupt_id,
					u8 bus, u8 devid, u8 function, bool msix_mask_en)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_pcompleter_msix_fid_table msix_fid_table = { 0 };
	struct nbl_padpt_msix_info msix_info = { 0 };

	if (valid) {
		msix_fid_table.vld = 1;
		msix_fid_table.fid = func_id;

		msix_info.intrl_pnum = 0;
		msix_info.intrl_rate = 0;
		msix_info.function = function;
		msix_info.devid = devid;
		msix_info.bus = bus;
		msix_info.valid = 1;
		if (msix_mask_en)
			msix_info.pba_relimit_en = 1;
	}

	nbl_hw_write_regs(phy_mgt, NBL_PADPT_MSIX_INFO_TABLE_ADDR(interrupt_id),
			  (u8 *)&msix_info, sizeof(msix_info));
	nbl_hw_write_regs(phy_mgt, NBL_PCOMPLETER_MSIX_FID_TABLE_ADDR(interrupt_id),
			  (u8 *)&msix_fid_table, sizeof(msix_fid_table));
}

static void nbl_phy_enable_abnormal_irq(void *priv, bool enable_msix,
					u16 global_vector_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	u16 func_id = NBL_COMMON_TO_MGT_PF(common);
	struct nbl_top_ctrl_int_vector_en_table int_vector_en_table = { 0 };
	struct nbl_top_ctrl_int_vector_table int_vector_table = { 0 };

	if (enable_msix)
		int_vector_en_table.en = BIT(0);
	nbl_hw_write_regs(phy_mgt, NBL_TOP_CTRL_INT_VECTOR_EN(func_id),
			  (u8 *)&int_vector_en_table, sizeof(int_vector_en_table));

	if (enable_msix)
		int_vector_table.msix = global_vector_id;
	nbl_hw_write_regs(phy_mgt, NBL_TOP_CTRL_INT_VECTOR(func_id),
			  (u8 *)&int_vector_table, sizeof(int_vector_table));
}

static void nbl_phy_enable_msix_irq(void *priv, u16 global_vector_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_msix_notify msix_notify = { 0 };

	msix_notify.glb_msix_idx = global_vector_id;

	nbl_hw_write_regs(phy_mgt, NBL_PCOMPLETER_MSIX_NOTIRY_OFFSET,
			  (u8 *)&msix_notify, sizeof(msix_notify));
}

static u8 *nbl_phy_get_msix_irq_enable_info(void *priv, u16 global_vector_id,
					    u32 *irq_data, u32 *irq_mask_data)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_msix_notify msix_notify = { 0 };

	msix_notify.glb_msix_idx = global_vector_id;
	memcpy(irq_data, &msix_notify, sizeof(msix_notify));

	msix_notify.mask = 1;
	memcpy(irq_mask_data, &msix_notify, sizeof(msix_notify));

	return (phy_mgt->hw_addr + NBL_PCOMPLETER_MSIX_NOTIRY_OFFSET);
}

static void nbl_phy_get_coalesce(void *priv, u16 interrupt_id, u16 *pnum, u16 *rate)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_padpt_msix_info msix_info = { 0 };

	nbl_hw_read_regs(phy_mgt, NBL_PADPT_MSIX_INFO_TABLE_ADDR(interrupt_id),
			 (u8 *)&msix_info, sizeof(msix_info));

	*pnum = msix_info.intrl_pnum;
	*rate = msix_info.intrl_rate;
}

static void nbl_phy_set_coalesce(void *priv, u16 interrupt_id, u16 pnum, u16 rate)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_padpt_msix_info msix_info = { 0 };

	nbl_hw_read_regs(phy_mgt, NBL_PADPT_MSIX_INFO_TABLE_ADDR(interrupt_id),
			 (u8 *)&msix_info, sizeof(msix_info));

	msix_info.intrl_pnum = pnum;
	msix_info.intrl_rate = rate;
	nbl_hw_write_regs(phy_mgt, NBL_PADPT_MSIX_INFO_TABLE_ADDR(interrupt_id),
			  (u8 *)&msix_info, sizeof(msix_info));
}

static void nbl_phy_set_msix_fast_restrain(void *priv, u16 interrupt_id, u16 pnum, u16 rate)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_msix_fast_restrain fast_restrain_data = { 0 };
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);

	fast_restrain_data.glb_msix_idx = interrupt_id;
	fast_restrain_data.data = rate;
	nbl_hw_write_regs(phy_mgt, NBL_PCOMPLETER_MSIX_FAST_RATE,
			  (u8 *)&fast_restrain_data, sizeof(fast_restrain_data));
	fast_restrain_data.glb_msix_idx = interrupt_id;
	fast_restrain_data.data = pnum;
	nbl_hw_write_regs(phy_mgt, NBL_PCOMPLETER_MSIX_FAST_PNUM,
			  (u8 *)&fast_restrain_data, sizeof(fast_restrain_data));

	nbl_debug(common, NBL_DEBUG_PHY, "set msix fast restrain, global msix %u, pnum %u, rate %u.",
		  interrupt_id, pnum, rate);
}

static int nbl_phy_get_table_range(void *priv, u8 pf_id, u8 addr_id, u8 eth_num,
				   u32 *range_oft, u32 *range_size)
{
	int per_pf_msix_num = 0;
	int per_pf_queue_num = 0;

	if (addr_id == 0) {
		per_pf_msix_num = NBL_MAX_MSIX_NUM_DRACO / eth_num;
		*range_oft = pf_id * per_pf_msix_num;
		*range_size = per_pf_msix_num;
	}
	/* 4 pf queue range: [0, 127] [128, 255] [256, 383] [384, 511] */
	/* 2 pf queue range: [0, 255] [256, 511] */
	if (addr_id == 1) {
		per_pf_queue_num = NBL_MAX_QUEUEU_NUM_DRACO / eth_num;
		*range_oft = pf_id * per_pf_queue_num;
		*range_size = per_pf_queue_num;
	}

	return 0;
}

static void nbl_phy_set_net_qid_table(void *priv, u16 func_id, u16 global_queue_id,
				      u16 local_queue_id, u8 is_vf)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_pcompleter_net_qid_table qid_table = {0};
	u64 net_qid_addr;

	qid_table.vld = 1;
	qid_table.global_qid = global_queue_id;
	if (is_vf)
		net_qid_addr = NBL_PCOMPLETER_NET_QID_TABLE_VF(local_queue_id, func_id);
	else if (func_id < NBL_PF_NUM_DRACO)
		net_qid_addr = NBL_PCOMPLETER_NET_QID_TABLE_PF0_PF3(local_queue_id, func_id);
	else
		net_qid_addr = NBL_PCOMPLETER_NET_QID_TABLE_PF4_PF7(local_queue_id, func_id);

	nbl_hw_write_regs(phy_mgt, net_qid_addr, (u8 *)&qid_table, sizeof(qid_table));
}

static u8 *nbl_phy_get_tail_ptr(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	return phy_mgt->hw_addr;
}

static void nbl_phy_update_tail_ptr(void *priv, struct nbl_notify_param *param)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	u8 __iomem *notify_addr = phy_mgt->hw_addr;
	u32 local_qid = param->notify_qid;
	u32 tail_ptr = param->tail_ptr;

	writel((((u32)tail_ptr << 16) | (u32)local_qid), notify_addr);
}

static int nbl_phy_set_spoof_check_addr(void *priv, u16 vsi_id, u8 *mac)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_ipro_ivsi_tbl ivsi_tbl = {0};
	struct nbl_epro_evsi_tbl evsi_tbl = {0};
	u8 reverse_mac[ETH_ALEN];
	u64 data = 0;

	nbl_hw_read_regs(phy_mgt, NBL_IPRO_IVSI_TABLE(vsi_id),
			 (u8 *)&ivsi_tbl, sizeof(struct nbl_ipro_ivsi_tbl));

	nbl_convert_mac(mac, reverse_mac);
	memcpy(&data, reverse_mac, ETH_ALEN);
	ivsi_tbl.smac = data;

	nbl_hw_write_regs(phy_mgt, NBL_IPRO_IVSI_TABLE(vsi_id),
			  (u8 *)&ivsi_tbl, sizeof(struct nbl_ipro_ivsi_tbl));

	/* used for vepa smac prune */
	nbl_hw_read_regs(phy_mgt, NBL_EPRO_EVSI_TABLE(vsi_id),
			 (u8 *)&evsi_tbl, sizeof(evsi_tbl));
	evsi_tbl.port_mac = data;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_EVSI_TABLE(vsi_id),
			  (u8 *)&evsi_tbl, sizeof(evsi_tbl));

	return 0;
}

static int nbl_phy_set_spoof_check_enable(void *priv, u16 vsi_id, u8 enable)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_ipro_ivsi_tbl ivsi_tbl = {0};

	nbl_hw_read_regs(phy_mgt, NBL_IPRO_IVSI_TABLE(vsi_id),
			 (u8 *)&ivsi_tbl, sizeof(struct nbl_ipro_ivsi_tbl));
	ivsi_tbl.smac_vld = enable;
	nbl_hw_write_regs(phy_mgt, NBL_IPRO_IVSI_TABLE(vsi_id),
			  (u8 *)&ivsi_tbl, sizeof(struct nbl_ipro_ivsi_tbl));
	return 0;
}

static void nbl_phy_set_promisc_mode(void *priv, u16 vsi_id, u16 eth_id, u16 mode)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union nbl_base_action_bits base_ab = {.data = 0};
	union dport_action set_dport = {.data = 0};
	struct nbl_ipro_ieth_tbl ieth_tbl = {0};
	u8 base_ab_data = 0;
	u64 base_ad_data = 0;

	nbl_hw_read_regs(phy_mgt, NBL_IPRO_IETH_TABLE(eth_id),
			 (u8 *)&ieth_tbl, sizeof(struct nbl_ipro_ieth_tbl));
	if (mode) {
		base_ab.baseab.SET_DEST = 1;
		base_ab.baseab.SET_UDF = 0;
		base_ab.baseab.VLAN_OP = 0;

		set_dport.up.DQ_V = 0;
		set_dport.up.next_stg = 0;
		set_dport.up.vsi_id = vsi_id;

		/* when offload traffic, donot overwrite SET_UDF action and its action data */
		/* when has already set promisc mode, set action data of new vsi */
		if (ieth_tbl.base_ab & BIT(7)) {
			base_ab_data = ieth_tbl.base_ab;
			base_ad_data = ((ieth_tbl.base_ad) & 0xFFFFFFFFFFFF) |
					((u64)set_dport.data << 48);
		} else {
			base_ab_data = ieth_tbl.base_ab | base_ab.data;
			/* put SET_DEST action in highest 16 bits,
			 * SET_UDF action shift left 16 bits
			 */
			base_ad_data = (ieth_tbl.base_ad >> 16) | ((u64)set_dport.data << 48);
		}
	} else {
		/* when offload traffic, move SET_UDF action and its action data to highest bits */
		if (ieth_tbl.base_ab & BIT(7)) {
			base_ab_data &= ~BIT(7);
			/* put SET_UDF action in highest 16 bits */
			base_ad_data = ieth_tbl.base_ad << 16;
		} else {
			base_ab_data = ieth_tbl.base_ab;
			base_ad_data = ieth_tbl.base_ad;
		}
	}

	ieth_tbl.base_ab = base_ab_data;
	ieth_tbl.base_ad = base_ad_data;
	nbl_hw_write_regs(phy_mgt, NBL_IPRO_IETH_TABLE(eth_id),
			  (u8 *)&ieth_tbl, sizeof(struct nbl_ipro_ieth_tbl));
}

static int nbl_phy_cfg_ipro_queue_tbl(void *priv, u16 queue_id, u16 vsi_id, u8 enable)
{
	/* draco ipro delete ipro_queue_tbl */
	return 0;
}

static int nbl_phy_cfg_ipro_dn_sport_tbl(void *priv, u16 vsi_id, u16 dst_eth_id,
					 u16 bmode, bool binit)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_ipro_ivsi_tbl ivsi_tbl = {0};
	union nbl_base_action_bits base_ab = {.data = 0};
	union dport_action set_dport = {.data = 0};
	u64 base_ad = 0;

	base_ab.baseab.SET_DEST = 1;
	base_ab.baseab.SET_UDF = 0;
	base_ab.baseab.VLAN_OP = 0;

	set_dport.down.eth_id = dst_eth_id;
	set_dport.down.lag_id = 0;
	set_dport.down.lag_vld = 0;
	set_dport.down.other_type = DPORT_OTHER_TYPE_ETH;
	set_dport.down.dir = DPORT_DIR_OTHER;
	set_dport.down.strip_act = 0;
	if (bmode == BRIDGE_MODE_VEPA)
		set_dport.down.next_stg = NBL_NEXT_STAGE_EPRO;
	else
		set_dport.down.next_stg = NBL_NEXT_STAGE_INIT;
	base_ad = set_dport.data;

	if (binit) {
		ivsi_tbl.base_ad = (u64)(base_ad << 48);
		ivsi_tbl.base_ab = base_ab.data;
		ivsi_tbl.not_use0 = 0;
		ivsi_tbl.t_lx_sel = IVSI_USE_T_LX_OFT;
		ivsi_tbl.vlan_lmt = 3;
		ivsi_tbl.sw_id = dst_eth_id;
		ivsi_tbl.smac_vld = 0;
		ivsi_tbl.smac = 0;
		ivsi_tbl.mtu = 0;
		ivsi_tbl.cpu_nstg = NBL_NEXT_STAGE_ACL1;
		ivsi_tbl.cpu_bps = 1;
		ivsi_tbl.phy_flow = 1;
		ivsi_tbl.t_s3 = 4;
		ivsi_tbl.vld = 1;
	} else {
		nbl_hw_read_regs(phy_mgt, NBL_IPRO_IVSI_TABLE(vsi_id),
				 (u8 *)&ivsi_tbl, sizeof(struct nbl_ipro_ivsi_tbl));
		ivsi_tbl.base_ad = (u64)(base_ad << 48);
		ivsi_tbl.base_ab = base_ab.data;
	}

	nbl_hw_write_regs(phy_mgt, NBL_IPRO_IVSI_TABLE(vsi_id),
			  (u8 *)&ivsi_tbl, sizeof(struct nbl_ipro_ivsi_tbl));

	return 0;
}

static int nbl_phy_init_epro_vpt_tbl(void *priv, u16 vsi_id, u16 bmode, bool binit,
				     u16 rss_key_range_oft)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_evsi_tbl evsi_tbl = {0};
	struct nbl_epro_q_group_tbl q_group_tbl = {0};

	if (binit) {
		evsi_tbl.base_ad = 0;
		evsi_tbl.base_ab = 0;
		evsi_tbl.mtu = 0;
		evsi_tbl.act_mode = EVSI_ACT_MODE_BASE_ABAD;
		evsi_tbl.vld = 0;
	} else {
		nbl_hw_read_regs(phy_mgt, NBL_EPRO_EVSI_TABLE(vsi_id),
				 (u8 *)&evsi_tbl, sizeof(evsi_tbl));
	}

	if (bmode == BRIDGE_MODE_VEPA) {
		evsi_tbl.prune_mc = EVSI_PRUNE_MC_VSI_AND_SMAC_PRUNE;
		evsi_tbl.prune_uc = EVSI_PRUNE_UC_VSI_AND_SMAC_PRUNE;
	} else {
		evsi_tbl.prune_mc = EVSI_PRUNE_MC_DONOT_PRUNE;
		evsi_tbl.prune_uc = EVSI_PRUNE_UC_DONOT_PRUNE;
	}

	nbl_hw_write_regs(phy_mgt, NBL_EPRO_EVSI_TABLE(vsi_id),
			  (u8 *)&evsi_tbl, sizeof(evsi_tbl));

	q_group_tbl.sqg1_oft = 0;
	q_group_tbl.sqg1_sz = 0;
	q_group_tbl.sqg0_oft = 0;
	q_group_tbl.sqg0_sz = 0;
	q_group_tbl.alg = NBL_EPRO_RSS_ALG_TOEPLITZ;
	q_group_tbl.hash_key_sel = rss_key_range_oft;
	q_group_tbl.tmpt_sel_sctpv6_dp = 1;
	q_group_tbl.tmpt_sel_sctpv6_sp = 1;
	q_group_tbl.tmpt_sel_sctpv6_dip = 1;
	q_group_tbl.tmpt_sel_sctpv6_sip = 1;
	q_group_tbl.tmpt_sel_udpv6_dp = 1;
	q_group_tbl.tmpt_sel_udpv6_sp = 1;
	q_group_tbl.tmpt_sel_udpv6_dip = 1;
	q_group_tbl.tmpt_sel_udpv6_sip = 1;
	q_group_tbl.tmpt_sel_tcpv6_dp = 1;
	q_group_tbl.tmpt_sel_tcpv6_sp = 1;
	q_group_tbl.tmpt_sel_tcpv6_dip = 1;
	q_group_tbl.tmpt_sel_tcpv6_sip = 1;
	q_group_tbl.tmpt_sel_ipv6_dip = 1;
	q_group_tbl.tmpt_sel_ipv6_sip = 1;
	q_group_tbl.tmpt_sel_sctpv4_dp = 1;
	q_group_tbl.tmpt_sel_sctpv4_sp = 1;
	q_group_tbl.tmpt_sel_sctpv4_dip = 1;
	q_group_tbl.tmpt_sel_sctpv4_sip = 1;
	q_group_tbl.tmpt_sel_udpv4_dp = 1;
	q_group_tbl.tmpt_sel_udpv4_sp = 1;
	q_group_tbl.tmpt_sel_udpv4_dip = 1;
	q_group_tbl.tmpt_sel_udpv4_sip = 1;
	q_group_tbl.tmpt_sel_tcpv4_dp = 1;
	q_group_tbl.tmpt_sel_tcpv4_sp = 1;
	q_group_tbl.tmpt_sel_tcpv4_dip = 1;
	q_group_tbl.tmpt_sel_tcpv4_sip = 1;
	q_group_tbl.tmpt_sel_ipv4_dip = 1;
	q_group_tbl.tmpt_sel_ipv4_sip = 1;
	/* dft_qid = 0 means packet from eth, switch to corresponding pf's global queue 0.
	 * dft_qid = 0x27c means when tmpt_sel select hash template fail for example arp packet,
	 * use dft_qid's default hash template.
	 */
	q_group_tbl.dft_qid = 0x27c;
	q_group_tbl.t_ptype_sel = 0;
	q_group_tbl.pd_sel = 0;
	q_group_tbl.vld = 1;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_Q_GROUP_TABLE(vsi_id),
			  (u8 *)&q_group_tbl, sizeof(q_group_tbl));

	return 0;
}

static int nbl_phy_set_epro_rss_default(void *priv, u16 vsi_id, u16 rss_key_range_oft)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_q_group_tbl q_group_tbl = {0};

	q_group_tbl.sqg1_oft = 0;
	q_group_tbl.sqg1_sz = 0;
	q_group_tbl.sqg0_oft = 0;
	q_group_tbl.sqg0_sz = 0;
	q_group_tbl.alg = NBL_EPRO_RSS_ALG_TOEPLITZ;
	q_group_tbl.hash_key_sel = rss_key_range_oft;
	q_group_tbl.tmpt_sel_sctpv6_dp = 1;
	q_group_tbl.tmpt_sel_sctpv6_sp = 1;
	q_group_tbl.tmpt_sel_sctpv6_dip = 1;
	q_group_tbl.tmpt_sel_sctpv6_sip = 1;
	q_group_tbl.tmpt_sel_udpv6_dp = 1;
	q_group_tbl.tmpt_sel_udpv6_sp = 1;
	q_group_tbl.tmpt_sel_udpv6_dip = 1;
	q_group_tbl.tmpt_sel_udpv6_sip = 1;
	q_group_tbl.tmpt_sel_tcpv6_dp = 1;
	q_group_tbl.tmpt_sel_tcpv6_sp = 1;
	q_group_tbl.tmpt_sel_tcpv6_dip = 1;
	q_group_tbl.tmpt_sel_tcpv6_sip = 1;
	q_group_tbl.tmpt_sel_ipv6_dip = 1;
	q_group_tbl.tmpt_sel_ipv6_sip = 1;
	q_group_tbl.tmpt_sel_sctpv4_dp = 1;
	q_group_tbl.tmpt_sel_sctpv4_sp = 1;
	q_group_tbl.tmpt_sel_sctpv4_dip = 1;
	q_group_tbl.tmpt_sel_sctpv4_sip = 1;
	q_group_tbl.tmpt_sel_udpv4_dp = 1;
	q_group_tbl.tmpt_sel_udpv4_sp = 1;
	q_group_tbl.tmpt_sel_udpv4_dip = 1;
	q_group_tbl.tmpt_sel_udpv4_sip = 1;
	q_group_tbl.tmpt_sel_tcpv4_dp = 1;
	q_group_tbl.tmpt_sel_tcpv4_sp = 1;
	q_group_tbl.tmpt_sel_tcpv4_dip = 1;
	q_group_tbl.tmpt_sel_tcpv4_sip = 1;
	q_group_tbl.tmpt_sel_ipv4_dip = 1;
	q_group_tbl.tmpt_sel_ipv4_sip = 1;
	/* dft_qid = 0 means packet from eth, switch to corresponding pf's global queue 0.
	 * dft_qid = 0x27c means when tmpt_sel select hash template fail for example arp packet,
	 * use dft_qid's default hash template.
	 */
	q_group_tbl.dft_qid = 0x27c;
	q_group_tbl.t_ptype_sel = 0;
	q_group_tbl.pd_sel = 0;
	q_group_tbl.vld = 1;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_Q_GROUP_TABLE(vsi_id),
			  (u8 *)&q_group_tbl, sizeof(q_group_tbl));

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

	nbl_hw_write_regs(phy_mgt, NBL_EPRO_RSS_KEY_TABLE(table_id),
			  (u8 *)&epro_rss_key_def, sizeof(epro_rss_key_def));

	return 0;
}

static int nbl_phy_cfg_epro_rss_ret(void *priv, u32 index, u16 size_unit, u8 size_type,
				    u32 q_num, u16 *queue_list, const u32 *indir)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct nbl_epro_q_map_tbl rss_ret = {0};
	u32 table_id = 0, table_end = 0;
	u32 group_count = 0;
	u32 queue_id = 0;

	group_count = size_unit << size_type;
	if (group_count > 128) {
		nbl_err(common, NBL_DEBUG_QUEUE,
			"Rss group entry size type %u exceed the max value 128", size_type);
		return -EINVAL;
	}

	if (q_num > group_count) {
		nbl_err(common, NBL_DEBUG_QUEUE,
			"q_num %u exceed the rss group count %u\n", q_num, group_count);
		return -EINVAL;
	}

	if (index >= NBL_EPRO_RSS_RET_TBL_DEPTH_DRACO ||
	    (index + group_count) > NBL_EPRO_RSS_RET_TBL_DEPTH_DRACO) {
		nbl_err(common, NBL_DEBUG_QUEUE,
			"index %u exceed the max table entry %u, entry size: %u\n",
			index, NBL_EPRO_RSS_RET_TBL_DEPTH_DRACO, group_count);
		return -EINVAL;
	}

	table_id = index / NBL_EPRO_RSS_RET_TBL_SIZE_PER_Q_MAP_TBL;
	table_end = (index + group_count) / NBL_EPRO_RSS_RET_TBL_SIZE_PER_Q_MAP_TBL;

	pr_info("%s table_id:%d, table_end:%d\n", __func__, table_id, table_end);

	if (indir) {
		for (; table_id < table_end; table_id++) {
			memset(&rss_ret, 0, sizeof(rss_ret));

			rss_ret.glb_qid_0 = indir[queue_id++];
			rss_ret.glb_qid_1 = indir[queue_id++];
			rss_ret.glb_qid_2 = indir[queue_id++];
			rss_ret.glb_qid_3 = indir[queue_id++];
			rss_ret.glb_qid_4 = indir[queue_id++];
			rss_ret.glb_qid_5 = indir[queue_id++];
			rss_ret.glb_qid_6 = indir[queue_id++];
			rss_ret.glb_qid_7 = indir[queue_id++];
			rss_ret.glb_qid_8 = indir[queue_id++];
			rss_ret.glb_qid_9 = indir[queue_id++];
			rss_ret.glb_qid_10 = indir[queue_id++];
			rss_ret.glb_qid_11 = indir[queue_id++];
			rss_ret.glb_qid_12 = indir[queue_id++];
			rss_ret.glb_qid_13 = indir[queue_id++];
			rss_ret.glb_qid_14 = indir[queue_id++];
			rss_ret.glb_qid_15 = indir[queue_id++];
			rss_ret.glb_qid_16 = indir[queue_id++];
			rss_ret.glb_qid_17 = indir[queue_id++];
			rss_ret.glb_qid_18 = indir[queue_id++];
			rss_ret.glb_qid_19 = indir[queue_id++];
			rss_ret.glb_qid_20 = indir[queue_id++];
			rss_ret.glb_qid_21 = indir[queue_id++];
			rss_ret.glb_qid_22 = indir[queue_id++];
			rss_ret.glb_qid_23 = indir[queue_id++];
			rss_ret.glb_qid_24 = indir[queue_id++];
			rss_ret.glb_qid_25 = indir[queue_id++];
			rss_ret.glb_qid_26 = indir[queue_id++];
			rss_ret.glb_qid_27 = indir[queue_id++];
			rss_ret.glb_qid_28 = indir[queue_id++];
			rss_ret.glb_qid_29 = indir[queue_id++];
			rss_ret.glb_qid_30 = indir[queue_id++];
			rss_ret.glb_qid_31 = indir[queue_id++];

			rss_ret.vld = 1;
			nbl_hw_write_regs(phy_mgt, NBL_EPRO_Q_MAP_TABLE(table_id),
					  (u8 *)&rss_ret, sizeof(rss_ret));
		}
	} else {
		for (; table_id < table_end; table_id++) {
			memset(&rss_ret, 0, sizeof(rss_ret));

			rss_ret.glb_qid_0 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_1 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_2 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_3 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_4 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_5 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_6 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_7 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_8 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_9 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_10 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_11 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_12 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_13 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_14 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_15 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_16 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_17 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_18 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_19 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_20 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_21 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_22 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_23 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_24 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_25 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_26 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_27 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_28 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_29 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_30 = queue_list[queue_id++];
			queue_id = queue_id % q_num;
			rss_ret.glb_qid_31 = queue_list[queue_id++];
			queue_id = queue_id % q_num;

			rss_ret.vld = 1;
			nbl_hw_write_regs(phy_mgt, NBL_EPRO_Q_MAP_TABLE(table_id),
					  (u8 *)&rss_ret, sizeof(rss_ret));
		}
	}

	return 0;
}

static int nbl_phy_set_epro_rss_ret(void *priv, u32 index, u16 global_queue_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct nbl_epro_q_map_tbl rss_ret = {0};
	u32 table_id = 0;
	u16 local_queue_id = 0;
	int bit_offset, word_idx, shift, low_bits, high_bits;
	u64 *word;
	u64 mask, value;

	table_id = index / NBL_EPRO_RSS_RET_TBL_SIZE_PER_Q_MAP_TBL;
	local_queue_id = index % NBL_EPRO_RSS_RET_TBL_SIZE_PER_Q_MAP_TBL;

	nbl_debug(common, NBL_DEBUG_PHY, "index %d (table %d local_qid %d), global_queue_id %d\n",
		  index, table_id, local_queue_id, global_queue_id);

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_Q_MAP_TABLE(table_id),
			 (u8 *)&rss_ret, sizeof(rss_ret));

	bit_offset = local_queue_id * 9;
	word_idx = bit_offset / 64;
	shift = bit_offset % 64;
	word = (u64 *)(&rss_ret);
	mask = (1ULL << 9) - 1;
	value = global_queue_id & mask;

	if (shift + 9 <= 64) {
		word[word_idx] &= ~(mask << shift);
		word[word_idx] |= (value << shift);
	} else {
		low_bits = 64 - shift;
		high_bits = 9 - low_bits;

		word[word_idx] &= ~(mask << shift);
		word[word_idx] |= ((value & ((1ULL << low_bits) - 1)) << shift);
		word[word_idx + 1] &= ~((1ULL << high_bits) - 1);
		word[word_idx + 1] |= (value >> low_bits);
	}

	rss_ret.vld = 1;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_Q_MAP_TABLE(table_id),
			  (u8 *)&rss_ret, sizeof(rss_ret));

	return 0;
}

static int nbl_phy_get_epro_rss_ret(void *priv, u32 index, u16 size_unit, u8 size_type, u32 *indir)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_q_map_tbl rss_ret = {0};
	u32 group_count = 0;
	u32 table_id = 0, table_end = 0;
	u32 id = 0;

	group_count = size_unit << size_type;
	table_id = index / NBL_EPRO_RSS_RET_TBL_SIZE_PER_Q_MAP_TBL;
	table_end = (index + group_count) / NBL_EPRO_RSS_RET_TBL_SIZE_PER_Q_MAP_TBL;

	for (; table_id < table_end; table_id++) {
		memset(&rss_ret, 0, sizeof(rss_ret));
		nbl_hw_read_regs(phy_mgt, NBL_EPRO_Q_MAP_TABLE(table_id),
				 (u8 *)&rss_ret, sizeof(rss_ret));
		indir[id++] = rss_ret.glb_qid_0;
		indir[id++] = rss_ret.glb_qid_1;
		indir[id++] = rss_ret.glb_qid_2;
		indir[id++] = rss_ret.glb_qid_3;
		indir[id++] = rss_ret.glb_qid_4;
		indir[id++] = rss_ret.glb_qid_5;
		indir[id++] = rss_ret.glb_qid_6;
		indir[id++] = rss_ret.glb_qid_7;
		indir[id++] = rss_ret.glb_qid_8;
		indir[id++] = rss_ret.glb_qid_9;
		indir[id++] = rss_ret.glb_qid_10;
		indir[id++] = rss_ret.glb_qid_11;
		indir[id++] = rss_ret.glb_qid_12;
		indir[id++] = rss_ret.glb_qid_13;
		indir[id++] = rss_ret.glb_qid_14;
		indir[id++] = rss_ret.glb_qid_15;
		indir[id++] = rss_ret.glb_qid_16;
		indir[id++] = rss_ret.glb_qid_17;
		indir[id++] = rss_ret.glb_qid_18;
		indir[id++] = rss_ret.glb_qid_19;
		indir[id++] = rss_ret.glb_qid_20;
		indir[id++] = rss_ret.glb_qid_21;
		indir[id++] = rss_ret.glb_qid_22;
		indir[id++] = rss_ret.glb_qid_23;
		indir[id++] = rss_ret.glb_qid_24;
		indir[id++] = rss_ret.glb_qid_25;
		indir[id++] = rss_ret.glb_qid_26;
		indir[id++] = rss_ret.glb_qid_27;
		indir[id++] = rss_ret.glb_qid_28;
		indir[id++] = rss_ret.glb_qid_29;
		indir[id++] = rss_ret.glb_qid_30;
		indir[id++] = rss_ret.glb_qid_31;
	}

	return 0;
}

static int nbl_phy_set_epro_rss_pt(void *priv, u16 vsi_id, u16 rss_ret_base, u16 rss_entry_size)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_evsi_tbl evsi_tbl = {0};

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_EVSI_TABLE(vsi_id),
			 (u8 *)&evsi_tbl, sizeof(evsi_tbl));
	evsi_tbl.vld = 1;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_EVSI_TABLE(vsi_id),
			  (u8 *)&evsi_tbl, sizeof(evsi_tbl));
	return 0;
}

static int nbl_phy_clear_epro_rss_pt(void *priv, u16 vsi_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_evsi_tbl evsi_tbl = {0};

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_EVSI_TABLE(vsi_id),
			 (u8 *)&evsi_tbl, sizeof(evsi_tbl));
	evsi_tbl.vld = 0;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_EVSI_TABLE(vsi_id),
			  (u8 *)&evsi_tbl, sizeof(evsi_tbl));
	return 0;
}

static void nbl_phy_setup_queue_switch(void *priv, u16 eth_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_ipro_ieth_tbl ieth_tbl = {0};
	struct nbl_epro_eeth_tbl eeth_tbl = {0};
	struct dsch_vn_g2p_cfg_tbl info = {0};
	union nbl_base_action_bits base_ab = {.data = 0};
	union dport_action set_dport = {.data = 0};
	u64 base_ad = 0;

	base_ab.baseab.SET_DEST = 1;
	base_ab.baseab.SET_UDF = 0;
	base_ab.baseab.VLAN_OP = 0;

	/* packet from eth, switch to corresponding pf */
	/* todo: when add macvlan, default we close promisc, default drop all packets from eth */
	set_dport.up.vsi_id = eth_id;
	set_dport.up.DQ_V = 0;
	set_dport.up.dir = DPORT_DIR_RX;
	set_dport.up.strip_act = 0;
	set_dport.up.next_stg = 0;
	base_ad = set_dport.data;

	base_ab.data = 0;
	base_ad = 0;
	ieth_tbl.base_ad = (u64)(base_ad << 48);
	ieth_tbl.base_ab = base_ab.data;
	ieth_tbl.not_use0 = 0;
	ieth_tbl.t_lx_sel = IETH_USE_T_LX_OFT;
	ieth_tbl.sw_id = eth_id;
	ieth_tbl.lag_vld = 0;
	ieth_tbl.lag_id = 0;
	ieth_tbl.vlan_lmt = 3;
	ieth_tbl.decap_en = 0;
	ieth_tbl.phy_flow = 1;
	ieth_tbl.t_s3 = 4;
	ieth_tbl.vld = 1;

	eeth_tbl.base_ad = 0;
	eeth_tbl.base_ab = 0;
	eeth_tbl.def_cos = 0;
	eeth_tbl.pfc_mode = 0;
	eeth_tbl.pfc_en = 0;
	eeth_tbl.vld = 1;

	info.vld = 1;
	info.port = eth_id;

	nbl_hw_write_regs(phy_mgt, NBL_IPRO_IETH_TABLE(eth_id),
			  (u8 *)&ieth_tbl, sizeof(ieth_tbl));

	nbl_hw_write_regs(phy_mgt, NBL_EPRO_EETH_TABLE(eth_id),
			  (u8 *)&eeth_tbl, sizeof(eeth_tbl));

	nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_G2P_CFG_TABLE_ADDR(eth_id),
			  (u8 *)&info, sizeof(info));
}

static void nbl_phy_get_vsi_rss_key(void *priv, u16 vsi_id, u8 *rss_key)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_q_group_tbl q_group_tbl = {0};
	u16 hash_key_sel = 0;

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_Q_GROUP_TABLE(vsi_id),
			 (u8 *)&q_group_tbl, sizeof(q_group_tbl));

	hash_key_sel = q_group_tbl.hash_key_sel;

	nbl_hw_read_regs(priv, NBL_EPRO_RSS_KEY_TABLE(hash_key_sel),
			 rss_key, sizeof(struct nbl_epro_rss_key));
}

static int nbl_phy_get_rss_key(void *priv, u8 *rss_key, u16 table_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_RSS_KEY_TABLE(table_id),
			 rss_key, sizeof(struct nbl_epro_rss_key));
	return 0;
}

static int nbl_phy_set_rss_key(void *priv, const u8 *rss_key, u16 table_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_hw_write_regs(phy_mgt, NBL_EPRO_RSS_KEY_TABLE(table_id),
			  rss_key, sizeof(struct nbl_epro_rss_key));
	return 0;
}

static void nbl_phy_get_rss_hash_key_sel(void *priv, u16 vsi_id, u8 *rss_hash_key_sel)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_q_group_tbl q_group_tbl = {0};

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_Q_GROUP_TABLE(vsi_id),
			 (u8 *)&q_group_tbl, sizeof(q_group_tbl));
	*rss_hash_key_sel = q_group_tbl.hash_key_sel;
}

static int nbl_phy_set_rss_hash_key_sel(void *priv, u16 vsi_id, u8 rss_hash_key_sel)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_q_group_tbl q_group_tbl = {0};

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_Q_GROUP_TABLE(vsi_id),
			 (u8 *)&q_group_tbl, sizeof(q_group_tbl));
	q_group_tbl.hash_key_sel = rss_hash_key_sel;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_Q_GROUP_TABLE(vsi_id),
			  (u8 *)&q_group_tbl, sizeof(q_group_tbl));
	return 0;
}

static void nbl_phy_get_rss_alg_sel(void *priv, u16 vsi_id, u8 eth_id, u8 *alg_sel)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_q_group_tbl q_group_tbl = {0};

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_Q_GROUP_TABLE(vsi_id),
			 (u8 *)&q_group_tbl, sizeof(q_group_tbl));

	if (q_group_tbl.alg == NBL_EPRO_RSS_ALG_TOEPLITZ)
		*alg_sel = ETH_RSS_HASH_TOP;
	else if (q_group_tbl.alg == NBL_EPRO_RSS_ALG_CRC32)
		*alg_sel = ETH_RSS_HASH_CRC32;
	else if (q_group_tbl.alg == NBL_EPRO_RSS_ALG_XOR32)
		*alg_sel = ETH_RSS_HASH_XOR;
}

static int nbl_phy_set_rss_alg_sel(void *priv, u16 vsi_id, u8 alg_sel)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_q_group_tbl q_group_tbl = {0};

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_Q_GROUP_TABLE(vsi_id),
			 (u8 *)&q_group_tbl, sizeof(q_group_tbl));

	if (alg_sel == ETH_RSS_HASH_TOP)
		q_group_tbl.alg = NBL_EPRO_RSS_ALG_TOEPLITZ;
	else if (alg_sel == ETH_RSS_HASH_CRC32)
		q_group_tbl.alg = NBL_EPRO_RSS_ALG_CRC32;
	else if (alg_sel == ETH_RSS_HASH_XOR)
		q_group_tbl.alg = NBL_EPRO_RSS_ALG_XOR32;

	nbl_hw_write_regs(phy_mgt, NBL_EPRO_Q_GROUP_TABLE(vsi_id),
			  (u8 *)&q_group_tbl, sizeof(q_group_tbl));
	return 0;
}

static int nbl_phy_get_rss_hash_tmpt_sel(void *priv, u16 vsi_id, int flow_type, u64 *tempt_sel)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_q_group_tbl q_group_tbl = {0};

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_Q_GROUP_TABLE(vsi_id),
			 (u8 *)&q_group_tbl, sizeof(q_group_tbl));

	if (flow_type == NBL_FLOW_TYPE_TCPV4) {
		if (q_group_tbl.tmpt_sel_tcpv4_dp)
			*tempt_sel |= TMPT_SEL_TCPV4_DP;
		if (q_group_tbl.tmpt_sel_tcpv4_sp)
			*tempt_sel |= TMPT_SEL_TCPV4_SP;
		if (q_group_tbl.tmpt_sel_tcpv4_dip)
			*tempt_sel |= TMPT_SEL_TCPV4_DIP;
		if (q_group_tbl.tmpt_sel_tcpv4_sip)
			*tempt_sel |= TMPT_SEL_TCPV4_SIP;
	} else if (flow_type == NBL_FLOW_TYPE_TCPV6) {
		if (q_group_tbl.tmpt_sel_tcpv6_dp)
			*tempt_sel |= TMPT_SEL_TCPV6_DP;
		if (q_group_tbl.tmpt_sel_tcpv6_sp)
			*tempt_sel |= TMPT_SEL_TCPV6_SP;
		if (q_group_tbl.tmpt_sel_tcpv6_dip)
			*tempt_sel |= TMPT_SEL_TCPV6_DIP;
		if (q_group_tbl.tmpt_sel_tcpv6_sip)
			*tempt_sel |= TMPT_SEL_TCPV6_SIP;
	} else if (flow_type == NBL_FLOW_TYPE_UDPV4) {
		if (q_group_tbl.tmpt_sel_udpv4_dp)
			*tempt_sel |= TMPT_SEL_UDPV4_DP;
		if (q_group_tbl.tmpt_sel_udpv4_sp)
			*tempt_sel |= TMPT_SEL_UDPV4_SP;
		if (q_group_tbl.tmpt_sel_udpv4_dip)
			*tempt_sel |= TMPT_SEL_UDPV4_DIP;
		if (q_group_tbl.tmpt_sel_udpv4_sip)
			*tempt_sel |= TMPT_SEL_UDPV4_SIP;
	} else if (flow_type == NBL_FLOW_TYPE_UDPV6) {
		if (q_group_tbl.tmpt_sel_udpv6_dp)
			*tempt_sel |= TMPT_SEL_UDPV6_DP;
		if (q_group_tbl.tmpt_sel_udpv6_sp)
			*tempt_sel |= TMPT_SEL_UDPV6_SP;
		if (q_group_tbl.tmpt_sel_udpv6_dip)
			*tempt_sel |= TMPT_SEL_UDPV6_DIP;
		if (q_group_tbl.tmpt_sel_udpv6_sip)
			*tempt_sel |= TMPT_SEL_UDPV6_SIP;
	} else if (flow_type == NBL_FLOW_TYPE_SCTPV4) {
		if (q_group_tbl.tmpt_sel_sctpv4_dp)
			*tempt_sel |= TMPT_SEL_SCTPV4_DP;
		if (q_group_tbl.tmpt_sel_sctpv4_sp)
			*tempt_sel |= TMPT_SEL_SCTPV4_SP;
		if (q_group_tbl.tmpt_sel_sctpv4_dip)
			*tempt_sel |= TMPT_SEL_SCTPV4_DIP;
		if (q_group_tbl.tmpt_sel_sctpv4_sip)
			*tempt_sel |= TMPT_SEL_SCTPV4_SIP;
	} else if (flow_type == NBL_FLOW_TYPE_SCTPV6) {
		if (q_group_tbl.tmpt_sel_sctpv6_dp)
			*tempt_sel |= TMPT_SEL_SCTPV6_DP;
		if (q_group_tbl.tmpt_sel_sctpv6_sp)
			*tempt_sel |= TMPT_SEL_SCTPV6_SP;
		if (q_group_tbl.tmpt_sel_sctpv6_dip)
			*tempt_sel |= TMPT_SEL_SCTPV6_DIP;
		if (q_group_tbl.tmpt_sel_sctpv6_sip)
			*tempt_sel |= TMPT_SEL_SCTPV6_SIP;
	} else {
		return -EOPNOTSUPP;
	}

	return 0;
}

static int nbl_phy_set_rss_hash_tmpt_sel(void *priv, u16 vsi_id, int flow_type, u64 hash_fields)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_q_group_tbl q_group_tbl = {0};
	union epro_q_group_tbl_u q_group_tbl_hw = {{0}};
	u8 *ptr_group_tbl = (u8 *)&q_group_tbl;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_Q_GROUP_TABLE(vsi_id),
			 (u8 *)&q_group_tbl, sizeof(q_group_tbl));

	if (flow_type == NBL_FLOW_TYPE_TCPV4) {
		if (hash_fields & NBL_HASH_FILED_SRC_IP)
			q_group_tbl.tmpt_sel_tcpv4_sip = 1;
		else
			q_group_tbl.tmpt_sel_tcpv4_sip = 0;

		if (hash_fields & NBL_HASH_FILED_DST_IP)
			q_group_tbl.tmpt_sel_tcpv4_dip = 1;
		else
			q_group_tbl.tmpt_sel_tcpv4_dip = 0;

		if (hash_fields & NBL_HASH_FILED_L4_SPORT)
			q_group_tbl.tmpt_sel_tcpv4_sp = 1;
		else
			q_group_tbl.tmpt_sel_tcpv4_sp = 0;

		if (hash_fields & NBL_HASH_FILED_L4_DPORT)
			q_group_tbl.tmpt_sel_tcpv4_dp = 1;
		else
			q_group_tbl.tmpt_sel_tcpv4_dp = 0;
	} else if (flow_type == NBL_FLOW_TYPE_TCPV6) {
		if (hash_fields & NBL_HASH_FILED_SRC_IP)
			q_group_tbl.tmpt_sel_tcpv6_sip = 1;
		else
			q_group_tbl.tmpt_sel_tcpv6_sip = 0;

		if (hash_fields & NBL_HASH_FILED_DST_IP)
			q_group_tbl.tmpt_sel_tcpv6_dip = 1;
		else
			q_group_tbl.tmpt_sel_tcpv6_dip = 0;

		if (hash_fields & NBL_HASH_FILED_L4_SPORT)
			q_group_tbl.tmpt_sel_tcpv6_sp = 1;
		else
			q_group_tbl.tmpt_sel_tcpv6_sp = 0;

		if (hash_fields & NBL_HASH_FILED_L4_DPORT)
			q_group_tbl.tmpt_sel_tcpv6_dp = 1;
		else
			q_group_tbl.tmpt_sel_tcpv6_dp = 0;
	} else if (flow_type == NBL_FLOW_TYPE_UDPV4) {
		if (hash_fields & NBL_HASH_FILED_SRC_IP)
			q_group_tbl.tmpt_sel_udpv4_sip = 1;
		else
			q_group_tbl.tmpt_sel_udpv4_sip = 0;

		if (hash_fields & NBL_HASH_FILED_DST_IP)
			q_group_tbl.tmpt_sel_udpv4_dip = 1;
		else
			q_group_tbl.tmpt_sel_udpv4_dip = 0;

		if (hash_fields & NBL_HASH_FILED_L4_SPORT)
			q_group_tbl.tmpt_sel_udpv4_sp = 1;
		else
			q_group_tbl.tmpt_sel_udpv4_sp = 0;

		if (hash_fields & NBL_HASH_FILED_L4_DPORT)
			q_group_tbl.tmpt_sel_udpv4_dp = 1;
		else
			q_group_tbl.tmpt_sel_udpv4_dp = 0;
	} else if (flow_type == NBL_FLOW_TYPE_UDPV6) {
		if (hash_fields & NBL_HASH_FILED_SRC_IP)
			q_group_tbl.tmpt_sel_udpv6_sip = 1;
		else
			q_group_tbl.tmpt_sel_udpv6_sip = 0;

		if (hash_fields & NBL_HASH_FILED_DST_IP)
			q_group_tbl.tmpt_sel_udpv6_dip = 1;
		else
			q_group_tbl.tmpt_sel_udpv6_dip = 0;

		if (hash_fields & NBL_HASH_FILED_L4_SPORT)
			q_group_tbl.tmpt_sel_udpv6_sp = 1;
		else
			q_group_tbl.tmpt_sel_udpv6_sp = 0;

		if (hash_fields & NBL_HASH_FILED_L4_DPORT)
			q_group_tbl.tmpt_sel_udpv6_dp = 1;
		else
			q_group_tbl.tmpt_sel_udpv6_dp = 0;
	} else if (flow_type == NBL_FLOW_TYPE_SCTPV4) {
		if (hash_fields & NBL_HASH_FILED_SRC_IP)
			q_group_tbl.tmpt_sel_sctpv4_sip = 1;
		else
			q_group_tbl.tmpt_sel_sctpv4_sip = 0;

		if (hash_fields & NBL_HASH_FILED_DST_IP)
			q_group_tbl.tmpt_sel_sctpv4_dip = 1;
		else
			q_group_tbl.tmpt_sel_sctpv4_dip = 0;

		if (hash_fields & NBL_HASH_FILED_L4_SPORT)
			q_group_tbl.tmpt_sel_sctpv4_sp = 1;
		else
			q_group_tbl.tmpt_sel_sctpv4_sp = 0;

		if (hash_fields & NBL_HASH_FILED_L4_DPORT)
			q_group_tbl.tmpt_sel_sctpv4_dp = 1;
		else
			q_group_tbl.tmpt_sel_sctpv4_dp = 0;
	} else if (flow_type == NBL_FLOW_TYPE_SCTPV6) {
		if (hash_fields & NBL_HASH_FILED_SRC_IP)
			q_group_tbl.tmpt_sel_sctpv6_sip = 1;
		else
			q_group_tbl.tmpt_sel_sctpv6_sip = 0;

		if (hash_fields & NBL_HASH_FILED_DST_IP)
			q_group_tbl.tmpt_sel_sctpv6_dip = 1;
		else
			q_group_tbl.tmpt_sel_sctpv6_dip = 0;

		if (hash_fields & NBL_HASH_FILED_L4_SPORT)
			q_group_tbl.tmpt_sel_sctpv6_sp = 1;
		else
			q_group_tbl.tmpt_sel_sctpv6_sp = 0;

		if (hash_fields & NBL_HASH_FILED_L4_DPORT)
			q_group_tbl.tmpt_sel_sctpv6_dp = 1;
		else
			q_group_tbl.tmpt_sel_sctpv6_dp = 0;
	} else if (flow_type == NBL_FLOW_TYPE_OFFLOAD) {
		memcpy(&q_group_tbl_hw, ptr_group_tbl, sizeof(q_group_tbl));
		q_group_tbl_hw.info.alg = hash_fields >> NBL_DRACO_RSS_ALG_OFT;
		q_group_tbl_hw.info.tmpt_sel = hash_fields & NBL_DRACO_RSS_TMPT_MASK;
		ptr_group_tbl = (u8 *)&q_group_tbl_hw;
		nbl_info(common, NBL_DEBUG_PHY, "offload rss:%u-%u",
			 q_group_tbl_hw.info.alg, q_group_tbl_hw.info.tmpt_sel);
	} else {
		return -EOPNOTSUPP;
	}

	nbl_hw_write_regs(phy_mgt, NBL_EPRO_Q_GROUP_TABLE(vsi_id),
			  ptr_group_tbl, sizeof(q_group_tbl));

	return 0;
}

static void nbl_phy_config_udf_reg(struct nbl_phy_mgt *phy_mgt, int dir, bool enable)
{
	union ipro_am_udf_prf_u ipro_am_udf_prf;
	union epro_am_udf_prf_u epro_am_udf_prf;
	u8 udf_value = enable ? NBL_UDF_MIRROR_ENABLE : NBL_UDF_MIRROR_DISABLE;

	memset(&ipro_am_udf_prf, 0, sizeof(ipro_am_udf_prf));
	memset(&epro_am_udf_prf, 0, sizeof(epro_am_udf_prf));

	if (!dir) {
		nbl_hw_read_regs(phy_mgt, NBL_IPRO_AM_UDF_PRF_REG(NBL_UDF_PRF_ID_MIRROR),
				 (u8 *)&ipro_am_udf_prf, sizeof(ipro_am_udf_prf));
		ipro_am_udf_prf.info.set_udf0 = udf_value;
		nbl_hw_write_regs(phy_mgt, NBL_IPRO_AM_UDF_PRF_REG(NBL_UDF_PRF_ID_MIRROR),
				  (u8 *)&ipro_am_udf_prf, sizeof(ipro_am_udf_prf));
	} else {
		nbl_hw_read_regs(phy_mgt, NBL_EPRO_AM_UDF_PRF_REG(NBL_UDF_PRF_ID_MIRROR),
				 (u8 *)&epro_am_udf_prf, sizeof(epro_am_udf_prf));
		epro_am_udf_prf.info.set_udf0 = udf_value;
		nbl_hw_write_regs(phy_mgt, NBL_EPRO_AM_UDF_PRF_REG(NBL_UDF_PRF_ID_MIRROR),
				  (u8 *)&epro_am_udf_prf, sizeof(epro_am_udf_prf));
	}
}

static void nbl_phy_config_ivsi_or_evsi_table(struct nbl_phy_mgt *phy_mgt, int dir,
					      u16 vsi_id, u8 mt_id, bool enable)
{
	union nbl_base_action_bits base_ab = {.data = 0};
	struct nbl_ipro_ivsi_tbl ivsi_tbl = {0};
	struct nbl_epro_evsi_tbl evsi_tbl = {0};
	u8 base_ad = 0;

	if (!dir) {
		nbl_hw_read_regs(phy_mgt, NBL_IPRO_IVSI_TABLE(vsi_id),
				 (u8 *)&ivsi_tbl, sizeof(ivsi_tbl));

		ivsi_tbl.base_ad &= ~NBL_IPRO_UDF_ACTION_MASK;
		if (enable) {
			base_ad = NBL_MIRROR_ID_ENABLE + mt_id;
			ivsi_tbl.base_ad |= ((u64)base_ad << 40);
		}

		base_ab.data = ivsi_tbl.base_ab;
		base_ab.baseab.SET_UDF = enable ? BASE_ACTION_SET_IEPRO_UDF_MIRROR : 0;
		ivsi_tbl.base_ab = base_ab.data;

		nbl_hw_write_regs(phy_mgt, NBL_IPRO_IVSI_TABLE(vsi_id),
				  (u8 *)&ivsi_tbl, sizeof(ivsi_tbl));
	} else {
		nbl_hw_read_regs(phy_mgt, NBL_EPRO_EVSI_TABLE(vsi_id),
				 (u8 *)&evsi_tbl, sizeof(evsi_tbl));

		evsi_tbl.base_ad &= ~NBL_EPRO_UDF_ACTION_MASK;
		if (enable) {
			base_ad = NBL_MIRROR_ID_ENABLE + mt_id;
			evsi_tbl.base_ad |= ((u64)base_ad << 56);
		}

		base_ab.data = evsi_tbl.base_ab;
		base_ab.baseab.SET_UDF = enable ? BASE_ACTION_SET_IEPRO_UDF_MIRROR : 0;
		evsi_tbl.base_ab = base_ab.data;

		nbl_hw_write_regs(phy_mgt, NBL_EPRO_EVSI_TABLE(vsi_id),
				  (u8 *)&evsi_tbl, sizeof(evsi_tbl));
	}
}

static int nbl_phy_get_mirror_table_id(void *priv, u16 vsi_id, int dir,
				       bool mirror_en, u8 *mt_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	u8 pf_id = NBL_COMMON_TO_MGT_PF(common);

	if (dir != MIRROR_DIR_INGRESS && dir != MIRROR_DIR_EGRESS)
		return -EINVAL;

	*mt_id = NBL_MIRROR_ID_BASE + pf_id + dir * NBL_MIRROR_ID_OFFSET;

	return 0;
}

static int nbl_phy_configure_mirror(void *priv, u16 vsi_id, bool mirror_en,
				    int dir, u8 mt_id)
{	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_phy_config_ivsi_or_evsi_table(phy_mgt, dir, vsi_id, mt_id, mirror_en);

	if (!mirror_en)
		return 0;
	nbl_phy_config_udf_reg(phy_mgt, dir, mirror_en);

	return 0;
}

static int nbl_phy_configure_mirror_table(void *priv, bool mirror_en,
					  u16 mirror_vsi_id, u16 mirror_queue_id, u8 mt_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union epro_mirror_prof_u epro_mirror_prof;
	union ped_tbl_mirr_enc_u ped_tbl_mirr_enc;
	union nbl_base_action_bits base_ab = {.data = 0};
	union dport_action set_dport = {.data = 0};

	memset(&epro_mirror_prof, 0, sizeof(epro_mirror_prof));
	memset(&ped_tbl_mirr_enc, 0, sizeof(ped_tbl_mirr_enc));

	if (mirror_en) {
		nbl_hw_read_regs(phy_mgt, NBL_EPRO_MIRROR_PROF_REG(mt_id),
				 (u8 *)&epro_mirror_prof, sizeof(epro_mirror_prof));
		base_ab.baseab.SET_DEST = 1;
		epro_mirror_prof.info.base_ab = base_ab.data;

		epro_mirror_prof.info.base_ad_arr[0] = 0;
		set_dport.up.next_stg = NBL_NEXT_STAGE_EPRO;
		set_dport.up.vsi_id = mirror_vsi_id;
		epro_mirror_prof.info.base_ad_arr[1] &= ~NBL_EPRO_MIRROR_ACTION_MASK;
		epro_mirror_prof.info.base_ad_arr[1] |= ((u32)set_dport.data << 16);
		epro_mirror_prof.info.pfc_mode = 0;
		epro_mirror_prof.info.vld = 1;
	} else {
		return 0;
	}

	nbl_hw_write_regs(phy_mgt, NBL_EPRO_MIRROR_PROF_REG(mt_id),
			  (u8 *)&epro_mirror_prof, sizeof(epro_mirror_prof));
	nbl_hw_write_regs(phy_mgt, NBL_PED_TBL_MIRR_ENC_REG(mt_id),
			  (u8 *)&ped_tbl_mirr_enc, sizeof(ped_tbl_mirr_enc));

	return 0;
}

static int nbl_phy_clear_mirror_cfg(void *priv, u16 vsi_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union epro_mirror_prof_u epro_mirror_prof;
	union ped_tbl_mirr_enc_u ped_tbl_mirr_enc;
	u8 mt_id = 0;
	int dir = 0;

	for (dir = MIRROR_DIR_INGRESS; dir <= MIRROR_DIR_EGRESS; dir++) {
		nbl_phy_get_mirror_table_id(priv, vsi_id, dir, 0, &mt_id);
		nbl_phy_config_ivsi_or_evsi_table(phy_mgt, dir, vsi_id, mt_id, false);

		nbl_hw_read_regs(phy_mgt, NBL_EPRO_MIRROR_PROF_REG(mt_id),
				 (u8 *)&epro_mirror_prof, sizeof(epro_mirror_prof));

		if (epro_mirror_prof.info.vld == 0)
			continue;

		nbl_phy_config_udf_reg(phy_mgt, dir, false);

		memset(&epro_mirror_prof, 0, sizeof(epro_mirror_prof));
		memset(&ped_tbl_mirr_enc, 0, sizeof(ped_tbl_mirr_enc));
		nbl_hw_write_regs(phy_mgt, NBL_EPRO_MIRROR_PROF_REG(mt_id),
				  (u8 *)&epro_mirror_prof, sizeof(epro_mirror_prof));
		nbl_hw_write_regs(phy_mgt, NBL_PED_TBL_MIRR_ENC_REG(mt_id),
				  (u8 *)&ped_tbl_mirr_enc, sizeof(ped_tbl_mirr_enc));
	}
	return 0;
}

static int nbl_phy_cfg_q2tc_netid(void *priv, u16 queue_id, u16 netid, u16 vld)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct dsch_vn_q2tc_cfg_tbl info;

	nbl_hw_read_regs(phy_mgt, NBL_DSCH_VN_Q2TC_CFG_TABLE_ADDR(queue_id),
			 (u8 *)&info, sizeof(info));
	info.tcid = (info.tcid & 0x7) | (netid << 3);
	info.vld = vld;

	nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_Q2TC_CFG_TABLE_ADDR(queue_id),
			  (u8 *)&info, sizeof(info));
	return 0;
}

static int nbl_phy_cfg_q2tc_tcid(void *priv, u16 queue_id, u16 tcid)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct dsch_vn_q2tc_cfg_tbl info;

	nbl_hw_read_regs(phy_mgt, NBL_DSCH_VN_Q2TC_CFG_TABLE_ADDR(queue_id),
			 (u8 *)&info, sizeof(info));
	info.tcid = (info.tcid & 0xFFF8) | tcid;

	nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_Q2TC_CFG_TABLE_ADDR(queue_id),
			  (u8 *)&info, sizeof(info));
	return 0;
}

static int nbl_phy_cfg_dsch_net_to_group(void *priv, u16 func_id, u16 group_id, u16 vld)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct dsch_vn_n2g_cfg_tbl info = {0};

	info.grpid = group_id;
	info.vld = vld;
	nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_N2G_CFG_TABLE_ADDR(func_id),
			  (u8 *)&info, sizeof(info));
	return 0;
}

static int nbl_phy_set_tc_wgt(void *priv, u16 func_id, u8 *weight, u16 num_tc)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union dsch_vn_tc_wgt_cfg_tbl_u wgt_cfg = {.info = {0}};
	int i;

	for (i = 0; i < num_tc; i++) {
		switch (i) {
		case 0:
			wgt_cfg.info.tc0_wgt = weight[i];
			break;
		case 1:
			wgt_cfg.info.tc1_wgt = weight[i];
			break;
		case 2:
			wgt_cfg.info.tc2_wgt = weight[i];
			break;
		case 3:
			wgt_cfg.info.tc3_wgt = weight[i];
			break;
		case 4:
			wgt_cfg.info.tc4_wgt = weight[i];
			break;
		case 5:
			wgt_cfg.info.tc5_wgt = weight[i];
			break;
		case 6:
			wgt_cfg.info.tc6_wgt = weight[i];
			break;
		case 7:
			wgt_cfg.info.tc7_wgt = weight[i];
			break;
		default:
			break;
		}
	}
	nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_TC_WGT_CFG_TABLE_ADDR(func_id),
			  (u8 *)&wgt_cfg, sizeof(wgt_cfg));

	return 0;
}

static bool nbl_phy_check_q2tc(void *priv, u16 queue_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct dsch_vn_q2tc_cfg_tbl info;

	nbl_hw_read_regs(phy_mgt, NBL_DSCH_VN_Q2TC_CFG_TABLE_ADDR(queue_id),
			 (u8 *)&info, sizeof(info));
	return info.vld;
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
	nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_SHA2NET_MAP_TABLE_ADDR(func_id),
			  (u8 *)&sha2net, sizeof(sha2net));

	shaping_net.valid = 1;
	nbl_hw_write_regs(phy_mgt, NBL_SHAPING_NET(func_id),
			  (u8 *)&shaping_net, sizeof(shaping_net));

	net2sha.vld = 1;
	nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_NET2SHA_MAP_TABLE_ADDR(func_id),
			  (u8 *)&net2sha, sizeof(net2sha));
}

static void nbl_phy_deactive_shaping(void *priv, u16 func_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_shaping_net shaping_net = {0};
	struct dsch_vn_sha2net_map_tbl sha2net = {0};
	struct dsch_vn_net2sha_map_tbl net2sha = {0};

	nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_NET2SHA_MAP_TABLE_ADDR(func_id),
			  (u8 *)&net2sha, sizeof(net2sha));

	nbl_hw_read_regs(phy_mgt, NBL_SHAPING_NET(func_id),
			 (u8 *)&shaping_net, sizeof(shaping_net));
	shaping_net.valid = 0;
	nbl_hw_write_regs(phy_mgt, NBL_SHAPING_NET(func_id),
			  (u8 *)&shaping_net, sizeof(shaping_net));

	nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_SHA2NET_MAP_TABLE_ADDR(func_id),
			  (u8 *)&sha2net, sizeof(sha2net));
}

static int nbl_phy_init_vdpaq(void *priv, u16 func_id, u16 bdf, u64 pa, u32 size)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct log_info_table_ram log_ram = {0};
	struct log_info_table_cam log_cam = {0};

	log_ram.log_info_addr = pa;
	log_ram.log_info_size = size;

	log_cam.log_info_bdf = bdf;
	log_cam.log_info_vld = 1;

	nbl_hw_write_regs(phy_mgt, NBL_VDPA_LOG_INFO_TABLE_RAM(func_id),
			  (u8 *)&log_ram, sizeof(log_ram));
	nbl_hw_write_regs(phy_mgt, NBL_VDPA_LOG_INFO_TABLE_CAM(func_id),
			  (u8 *)&log_cam, sizeof(log_cam));

	return 0;
}

static void nbl_phy_destroy_vdpaq(void *priv, u16 func_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct log_info_table_cam log_cam = {0};
	struct log_info_dis_table_cam dis_log_cam = {0};
	u32 times = 50;
	u32 fifo_nafull;

	do {
		nbl_hw_read_regs(phy_mgt, NBL_VDPA_FIFO_NAFULL,
				 (u8 *)&fifo_nafull, sizeof(fifo_nafull));
		if (fifo_nafull & 0x4)
			break;

		times--;
		usleep_range(100, 200);
	} while (times);

	if (!times) {
		nbl_err(common, NBL_DEBUG_COMMON, "Vdpa fifo is full, timeout");
		return;
	}
	dis_log_cam.log_info_disable = 1;
	nbl_hw_write_regs(phy_mgt, NBL_VDPA_LOG_INFO_DIS_TABLE_CAM(func_id),
			  (u8 *)&dis_log_cam, sizeof(dis_log_cam));
	times = 50;
	do {
		nbl_hw_read_regs(phy_mgt, NBL_VDPA_LOG_INFO_TABLE_CAM(func_id),
				 (u8 *)&log_cam, sizeof(log_cam));
		if (!log_cam.log_info_vld)
			break;

		times--;
		usleep_range(100, 200);
	} while (times);

	if (!times) {
		nbl_err(common, NBL_DEBUG_COMMON, "Vdpa disable cam failed, timeout");
		return;
	}
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
		nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_SHA2NET_MAP_TABLE_ADDR(func_id),
				  (u8 *)&sha2net, sizeof(sha2net));
	} else {
		net2sha.vld = vld;
		nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_NET2SHA_MAP_TABLE_ADDR(func_id),
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
			shaping_net.depth = max(shaping_net.cir * 2, NBL_DRACO_NET_BUCKET_DEPTH);
		shaping_net.cbs = shaping_net.depth;
		shaping_net.pbs = shaping_net.depth;
	}

	nbl_hw_write_regs(phy_mgt, NBL_SHAPING_NET(func_id),
			  (u8 *)&shaping_net, sizeof(shaping_net));

	if (!vld) {
		sha2net.vld = vld;
		nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_SHA2NET_MAP_TABLE_ADDR(func_id),
				  (u8 *)&sha2net, sizeof(sha2net));
	} else {
		net2sha.vld = active;
		nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_NET2SHA_MAP_TABLE_ADDR(func_id),
				  (u8 *)&net2sha, sizeof(net2sha));
	}

	return 0;
}

static int nbl_phy_cfg_epro_errcode_11(void *priv, u16 dir, u16 type, u16 vsi_eth_id, bool mode)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	union nbl_action_bits_base base_ab = {{0}};
	union nbl_action_datas base_ad = {{0}};
	union ipro_epro_err_sel_array array = {{0}};
	union epro_errcode_tbl0_u epro_errcode_ab = {{0}};
	u8 id = common->mgt_pf + 1;

	base_ab.baseab.SET_DEST = 1;
	base_ab.baseab.SET_UDF = 0;
	base_ab.baseab.VLAN_OP = 0;
	epro_errcode_ab.info.ab = base_ab.data;

	if (dir == DPORT_DIR_OTHER) {
		base_ad.dport.down.dir = dir;
		/* DROP was handled */
		base_ad.dport.down.other_type = type;
		if (type == DPORT_OTHER_TYPE_ETH) {
			base_ad.dport.down.eth_id = vsi_eth_id;
			base_ad.dport.down.lag_id = 0;
			base_ad.dport.down.lag_vld = 0;
			base_ad.dport.down.strip_act = 0;
			base_ad.dport.down.next_stg = NBL_NEXT_STAGE_EPRO;
		}
	} else {
		base_ad.dport.up.dir = dir;
		base_ad.dport.up.vsi_id = vsi_eth_id;
		base_ad.dport.up.DQ_V = 0;
		base_ad.dport.up.next_stg = NBL_NEXT_STAGE_EPRO;
	}

	/* upcall based on {DIR, SWID} */
	nbl_hw_read_regs(phy_mgt, NBL_EPRO_ERRCODE_11_HDL_ADDR, (u8 *)&array,
			 NBL_BYTES_IN_REG);
	if (mode) {
		switch (id) {
		case 1:
			array.info.sel0 = 1;
			array.info.sel4 = 1;
			break;
		case 2:
			array.info.sel1 = 2;
			array.info.sel5 = 2;
			break;
		case 3:
			array.info.sel2 = 3;
			array.info.sel6 = 3;
			break;
		case 4:
			array.info.sel3 = 4;
			array.info.sel7 = 4;
			break;
		default:
			nbl_err(common, NBL_DEBUG_PHY, "invalid pf id %u", id);
			return -EINVAL;
		}
	} else {
		switch (id) {
		case 1:
			array.info.sel0 = 0xf;
			array.info.sel4 = 0xf;
			break;
		case 2:
			array.info.sel1 = 0xf;
			array.info.sel5 = 0xf;
			break;
		case 3:
			array.info.sel2 = 0xf;
			array.info.sel6 = 0xf;
			break;
		case 4:
			array.info.sel3 = 0xf;
			array.info.sel7 = 0xf;
			break;
		default:
			nbl_err(common, NBL_DEBUG_PHY, "invalid pf id %u", id);
			return -EINVAL;
		}
	}

	nbl_hw_write_regs(phy_mgt, NBL_EPRO_ERRCODE_11_HDL_ADDR, (u8 *)&array,
			  NBL_BYTES_IN_REG);
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_ERRCODE_TBL0_REG(id), (u8 *)&epro_errcode_ab,
			  NBL_BYTES_IN_REG);
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_ERRCODE_TBL1_REG(id), (u8 *)&base_ad.u32_arr[1],
			  NBL_BYTES_IN_REG);
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_ERRCODE_TBL2_REG(id), (u8 *)&base_ad.u32_arr[0],
			  NBL_BYTES_IN_REG);
	return 0;
}

static void nbl_phy_cfg_nodport_upcall(void *priv, u16 vsi_eth_id, bool mode)
{
	nbl_phy_cfg_epro_errcode_11(priv, DPORT_DIR_RX, 0, vsi_eth_id, mode);
}

static int nbl_phy_init_offload_fwd(void *priv, u16 vsi_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union epro_evsi_u evsi;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);

	memset(&evsi, 0, sizeof(union epro_evsi_u));
	nbl_info(common, NBL_DEBUG_PHY, "init offload fwd: vsi id %u\n", vsi_id);
	evsi.info.vld = 1;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_EVSI_REG(vsi_id), (u8 *)&evsi,
			  NBL_EPRO_EVSI_DWLEN * NBL_BYTES_IN_REG);
	return 0;
}

static int nbl_phy_cfg_ivsi_phy_flow(void *priv, u16 vsi_id, bool status, u8 eth_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union ipro_ivsi_u ivsi;
	union epro_evsi_u evsi;
	union nbl_action_bits_base base_ab = {{0}};
	union nbl_action_datas set_dport;

	memset(&ivsi, 0, sizeof(union ipro_ivsi_u));
	memset(&evsi, 0, sizeof(union epro_evsi_u));
	memset(&set_dport, 0, sizeof(union nbl_action_datas));
	nbl_hw_read_regs(phy_mgt, NBL_IPRO_IVSI_REG(vsi_id), (u8 *)&ivsi, sizeof(ivsi));
	nbl_hw_read_regs(phy_mgt, NBL_EPRO_EVSI_REG(vsi_id), (u8 *)&evsi, sizeof(evsi));

	ivsi.info.phy_flow = !status;
	if (!status) {
		base_ab.baseab.SET_DEST = 1;
		set_dport.dport.down.eth_id = eth_id;
		set_dport.dport.down.lag_id = 0;
		set_dport.dport.down.lag_vld = 0;
		set_dport.dport.down.other_type = DPORT_OTHER_TYPE_ETH;
		set_dport.dport.down.dir = DPORT_DIR_OTHER;
		set_dport.dport.down.strip_act = 0;
		set_dport.dport.down.next_stg = NBL_NEXT_STAGE_EPRO;

		ivsi.info.vld = 1;
		ivsi.info.cpu_bps = 1;
		ivsi.info.cpu_nstg = NBL_NEXT_STAGE_EPRO;
		ivsi.info.base_ab = base_ab.data;
		ivsi.info.base_ad_arr[0] = set_dport.u32_arr[0];
		ivsi.info.base_ad_arr[1] = set_dport.u32_arr[1];
		ivsi.info.sw_id = eth_id;
		ivsi.info.t_s3 = 0b100;
		ivsi.info.t_lx_sel = IVSI_USE_T_LX_OFT;
		ivsi.info.vlan_lmt = 3;
		evsi.info.vld = 1;
	} else {
		ivsi.info.vld = 1;
		ivsi.info.cpu_bps = 1;
		ivsi.info.cpu_nstg = NBL_NEXT_STAGE_EPRO;
		ivsi.info.base_ab = base_ab.data;
		ivsi.info.base_ad_arr[0] = set_dport.u32_arr[0];
		ivsi.info.base_ad_arr[1] = set_dport.u32_arr[1];
		ivsi.info.t_s3 = 0;
		ivsi.info.t_lx_sel = 0;
		ivsi.info.vlan_lmt = 3;
		evsi.info.vld = 1;
	}

	nbl_hw_write_regs(phy_mgt, NBL_IPRO_IVSI_REG(vsi_id), (u8 *)&ivsi, sizeof(ivsi));
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_EVSI_REG(vsi_id), (u8 *)&evsi, sizeof(evsi));

	return 0;
}

static int nbl_phy_cfg_ieth_phy_flow(void *priv, u16 eth_id, bool status)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	union ipro_ieth_u ieth;

	memset(&ieth, 0, sizeof(union ipro_ieth_u));
	nbl_hw_read_regs(phy_mgt, NBL_IPRO_IETH_REG(eth_id), (u8 *)&ieth, sizeof(ieth));

	ieth.info.phy_flow = !status;
	ieth.info.sw_id = NBL_COMMON_TO_MGT_PF(common);
	if (!status) {
		ieth.info.vld = 1;
		ieth.info.base_ab = 0;
		ieth.info.base_ad_arr[0] = 0;
		ieth.info.base_ad_arr[1] = 0;
		ieth.info.sw_id = eth_id;
		ieth.info.t_s3 = 0b100;
		ieth.info.t_lx_sel = IETH_USE_T_LX_OFT;
		ieth.info.decap_en = 0;
		ieth.info.vlan_lmt = 3;
	} else {
		ieth.info.vld = 1;
		ieth.info.base_ab = 0;
		ieth.info.base_ad_arr[0] = 0;
		ieth.info.base_ad_arr[1] = 0;
		ieth.info.sw_id = eth_id;
		ieth.info.t_s3 = 0;
		ieth.info.t_lx_sel = 0;
		ieth.info.decap_en = 1;
		ieth.info.vlan_lmt = 3;
	}

	nbl_hw_write_regs(phy_mgt, NBL_IPRO_IETH_REG(eth_id), (u8 *)&ieth, sizeof(ieth));

	return 0;
}

static void nbl_phy_cfg_epro_eeth(void *priv, u8 eth_id, u8 enable)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union epro_eeth_u eeth;

	memset(&eeth, 0, sizeof(union epro_eeth_u));
	eeth.info.vld = !!enable;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_EETH_REG(eth_id), (u8 *)&eeth,
			  sizeof(eeth));
}

static void nbl_phy_cfg_vlan_type(struct nbl_phy_mgt *phy_mgt, u16 vsi_id, u8 rep_type)
{
	/* sel = 1 ===> [1:0] is 1(88a8), [3:2] is 0(8100) */
	union ped_tbl_vsi_type_u vsi_type = {.info.sel = 1,};

	if (rep_type == NBL_ETHDEV_ETH_REP)
		vsi_id += NBL_DRACO_BASE_ETH_PORT_ID;

	nbl_hw_write_regs(phy_mgt, NBL_PED_TBL_VSI_TYPE_REG(vsi_id), (u8 *)&vsi_type,
			  sizeof(vsi_type));
}

static void nbl_phy_clear_ipro_decap(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union ipro_decap_tcam_u decap_tcam;
	union ipro_decap_assd_u decap_assd = {{0}};
	int idx = 0;

	memset(&decap_tcam, 0, sizeof(union ipro_decap_tcam_u));
	/* clear decap tcam */
	for (idx = 0; idx < NBL_IPRO_DECAP_ASSD_DEPTH; ++idx) {
		nbl_hw_write_regs(phy_mgt, NBL_IPRO_DECAP_TCAM_REG(idx), (u8 *)&decap_tcam.data,
				  NBL_IPRO_DECAP_TCAM_DWLEN * NBL_BYTES_IN_REG);
		nbl_hw_write_regs(phy_mgt, NBL_IPRO_DECAP_ASSD_REG(idx), (u8 *)&decap_assd.data,
				  NBL_IPRO_DECAP_ASSD_DWLEN * NBL_BYTES_IN_REG);
	}
}

static int nbl_phy_init_rep(void *priv, u16 vsi_id, u8 inner_type,
			    u8 outer_type, u8 rep_type, u16 rss_key_range_oft)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);

	if (rep_type == NBL_ETHDEV_PF_REP ||
	    rep_type == NBL_ETHDEV_VIRTIO_REP) {
		nbl_phy_cfg_ivsi_phy_flow(phy_mgt, vsi_id, 1, 0);
		nbl_phy_init_epro_vpt_tbl(phy_mgt, vsi_id, BRIDGE_MODE_VEB, 0, rss_key_range_oft);
	} else if (rep_type == NBL_ETHDEV_ETH_REP) {
		vsi_id = vsi_id - 1024;
		nbl_phy_cfg_ieth_phy_flow(phy_mgt, vsi_id, 1);
		nbl_phy_cfg_epro_eeth(priv, vsi_id, 1);
	} else {
		nbl_info(common, NBL_DEBUG_PHY, "error rep type %u for vsi:%u",
			 rep_type, vsi_id);
	}

	nbl_phy_cfg_vlan_type(phy_mgt, vsi_id, rep_type);
	/* set vlan type for eth as the eth vsi_type tbl will not be set when not in uplink-mode */
	nbl_phy_cfg_vlan_type(phy_mgt, common->eth_id, NBL_ETHDEV_ETH_REP);
	nbl_info(common, NBL_DEBUG_PHY, "init rep: eth id %u, vsi id %u, rep type %u\n",
		 common->eth_id, vsi_id, rep_type);

	/* init rss l4 */
	if (rep_type == NBL_ETHDEV_PF_REP || rep_type == NBL_ETHDEV_VIRTIO_REP)
		nbl_phy_set_epro_rss_default(priv, vsi_id, rss_key_range_oft);

	return 0;
}

static void nbl_phy_acl_clear_tcam(struct nbl_phy_mgt *phy_mgt, u16 tcam_btm)
{
	u8 pfid = NBL_COMMON_TO_MGT_PF(NBL_PHY_MGT_TO_COMMON(phy_mgt));
	union acl_indir_ctrl_u indir_ctrl =  {{0}};
	union acl_indir_access_ack_u ack = {{0}};
	union acl_valid_bit_u valid = {{0}};
	union acl_tcam_data_u data = {{0}};
	u16 entry_idx = NBL_ACL_TCAM_DEPTH / NBL_PF_NUM_DRACO * pfid;
	u16 end_entry_idx = entry_idx + NBL_ACL_TCAM_DEPTH / NBL_PF_NUM_DRACO;
	int try_count = NBL_ACL_RD_RETRY;
	u8 index = 0;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);

	indir_ctrl.info.tcam_addr = 0;
	indir_ctrl.info.acc_btm = tcam_btm;
	indir_ctrl.info.rw = 0;
	indir_ctrl.info.start = 1;

	/* cfg data regs to be written to tcam data */
	for (index = 0; index < NBL_ACL_FD_DATA_DEPTH; index++)
		nbl_hw_write_regs(phy_mgt, NBL_ACL_TCAM_DATA_REG(index),
				  (u8 *)&data, NBL_BYTES_IN_REG);

	/* clear tcam entries of this management PF */
	for (; entry_idx < end_entry_idx; ++entry_idx) {
		nbl_hw_write_regs(phy_mgt, NBL_ACL_VALID_BIT_ADDR,
				  (u8 *)valid.data, sizeof(valid));
		indir_ctrl.info.tcam_addr = entry_idx;
		nbl_hw_write_regs(phy_mgt, NBL_ACL_INDIR_CTRL_ADDR,
				  (u8 *)indir_ctrl.data, sizeof(indir_ctrl));

		while (try_count--) {
			nbl_hw_read_regs(phy_mgt, NBL_ACL_INDIR_ACCESS_ACK_ADDR,
					 (u8 *)ack.data, sizeof(ack));
			if (ack.info.done)
				break;

			usleep_range(NBL_ACL_DELAY_US, NBL_ACL_DELAY_US + 100);
		}

		if (!ack.info.done)
			nbl_err(common, NBL_DEBUG_PHY,
				"acl indirect access failed (%d), tried %d, status %08x",
				entry_idx, NBL_ACL_RD_RETRY - try_count, ack.info.status);

		ack.info.done = 0;
		try_count = NBL_ACL_RD_RETRY;
	}

	nbl_info(common, NBL_DEBUG_PHY, "clear acl flow, idx %d, depth %d",
		 entry_idx, end_entry_idx);
}

static void nbl_phy_acl_set_tcam_info(struct nbl_phy_mgt *phy_mgt,
				      struct nbl_acl_cfg_param_full *acl_param,
				      u8 profile_id)
{
	union nbl_acl_tcam_config *tcam_cfg;
	union nbl_acl_act_config *act_cfg;
	union acl_tct_u tct = {{0}};
	union acl_act_u act;
	u64 key_id_vec = 0;
	u64 act_id_vec = 0;
	u16 enabled = 0;
	u8 item_id;

	memset(&act, 0, sizeof(union acl_act_u));
	tcam_cfg = (union nbl_acl_tcam_config *)&acl_param->tcam_cfg;
	act_cfg = (union nbl_acl_act_config *)&acl_param->action_cfg;
	for (item_id = 0; item_id < NBL_ACL_TCAM_CFG_NUM; item_id++) {
		tct.info.start_cmp_vec |= (tcam_cfg[item_id].info.start_compare << item_id);
		tct.info.start_set_vec |= (tcam_cfg[item_id].info.start_set << item_id);
		tct.info.tcam_en_vec |= (tcam_cfg[item_id].info.enable << item_id);
		key_id_vec |= ((long long)(tcam_cfg[item_id].info.tcam_id) << (item_id * 4));

		act.info.at_en_vec |= (act_cfg[item_id].info.enable << item_id);
		act_id_vec |= ((long long)(act_cfg[item_id].info.act_id) << (item_id * 4));
	}

	tct.info.key_id_vec_l = key_id_vec & 0xFFFF;
	tct.info.key_id_vec = (key_id_vec >> 16) & 0xFFFFFFFF;
	tct.info.key_id_vec_h = (key_id_vec >> 48) & 0xFFFF;
	act.info.at_alloc_id_vec_arr[0] = act_id_vec & 0xFFFFFFFF;
	act.info.at_alloc_id_vec_arr[1] = act_id_vec >> 32;

	/* update on tct start_cmp_vec & start_set_vec */
	enabled = tct.info.tcam_en_vec;
	tct.info.start_cmp_vec |= (~enabled);
	tct.info.start_set_vec |= (~enabled);
	nbl_hw_write_regs(phy_mgt, NBL_ACL_TCT_REG(profile_id), (u8 *)&tct, sizeof(tct));
	nbl_hw_write_regs(phy_mgt, NBL_ACL_ACT_REG(profile_id), (u8 *)&act, sizeof(act));
}

static void nbl_phy_acl_set_default_action(struct nbl_phy_mgt *phy_mgt, u8 profile_id)
{
	struct nbl_draco_acl_dft_acts action;

	memset(&action, 0, sizeof(struct nbl_draco_acl_dft_acts));
	/* clear all acl default actions */
	nbl_hw_write_regs(phy_mgt, NBL_ACL_DFLT_AT_REG(profile_id),
			  (u8 *)&action, sizeof(action));
}

static int nbl_phy_init_acl(void *priv, void *p)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_chan_flow_init_info_draco *param = (struct nbl_chan_flow_init_info_draco *)p;
	/* acl stat enable*/
	union acl_stat_en_u stat_en = {{0}};
	union acl_loop_back_u loop = {{0}};
	u8 profile_id = 0;

	stat_en.info.flow_en = 1;
	stat_en.info.spec_en = 1;
	nbl_hw_write_regs(phy_mgt, NBL_ACL_STAT_EN_ADDR, (u8 *)&stat_en, sizeof(stat_en));

	loop.info.en = 1;
	nbl_hw_write_regs(phy_mgt, NBL_ACL_LOOP_BACK_ADDR, (u8 *)&loop, sizeof(loop));

	/* acl flow stats not cleared here */
	nbl_phy_acl_clear_tcam(phy_mgt, NBL_ACL_FLUSH_ALL_BTM);
	for (profile_id = 0; profile_id < NBL_ACL_PROFILE_NUM; profile_id++) {
		/* only write tct & act of enabled profiles */
		if (param->acl_cfg[profile_id].acl_enable) {
			nbl_phy_acl_set_tcam_info(phy_mgt, &param->acl_cfg[profile_id], profile_id);
			nbl_phy_acl_set_default_action(phy_mgt, profile_id);
		}
	}

	return 0;
}

static int nbl_phy_init_ofld_ipro(void *priv, u16 vsi_id, u8 eth_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union ipro_ptype_assd_u assd;
	union ipro_ptype_tcam_u tcam = {{0}};
	union nbl_action_datas *act = (union nbl_action_datas *)&assd.info.base_ad_arr;
	union nbl_draco_sport_simple_u sport = {{0}};
	union nbl_draco_sport_simple_u sport_mask = {{0}};
	union nbl_draco_ptype_u ptype = {{0}};
	union nbl_draco_ptype_u ptype_mask = {{0}};

	/* no longer upcall tx icmpv6, simply set valid = 0 */
	memset(&assd, 0, sizeof(union ipro_ptype_assd_u));
	sport.tx.phy_flow = 0;
	sport.tx.dir = NBL_DRACO_SPORT_DIR_TX;
	sport.tx.cpu = 0;
	sport_mask.data = 0x3f;
	sport_mask.tx.cpu = 0;
	sport_mask.tx.sw_id = 0;
	sport_mask.tx.dir = 0;
	sport_mask.tx.phy_flow = 0;
	ptype.nontnl.tnl = 0;
	ptype.nontnl.l3 = 0b01;
	ptype.nontnl.l4 = 0b10;
	ptype.nontnl.nxt_proto = 0b001;
	ptype_mask.data = 0xffff;
	ptype_mask.nontnl.tnl = 0b0;
	ptype_mask.nontnl.l3 = 0b00;
	ptype_mask.nontnl.l4 = 0b00;
	ptype_mask.nontnl.nxt_proto = 0b000;
	tcam.info.data = (sport.data << 16) + ptype.data;
	tcam.info.mask = (sport_mask.data << 16) + ptype_mask.data;
	tcam.info.valid_bit = 0;

	assd.info.vld = 1;
	act->dport.up.dir = 0;
	act->dport.up.next_stg = NBL_NEXT_STAGE_EPRO;
	act->dport.up.DQ_V = 0;
	assd.info.base_ab = 0x80;

	sport.tx.sw_id = eth_id;
	act->dport.up.vsi_id = vsi_id;
	nbl_hw_write_regs(phy_mgt, NBL_IPRO_PTYPE_ASSD_REG(eth_id), (u8 *)&assd.data,
			  NBL_IPRO_PTYPE_ASSD_DWLEN * NBL_BYTES_IN_REG);
	nbl_hw_write_regs(phy_mgt, NBL_IPRO_PTYPE_TCAM_REG(eth_id), (u8 *)&tcam.data,
			  NBL_IPRO_PTYPE_TCAM_DWLEN * NBL_BYTES_IN_REG);

	return 0;
}

static void nbl_phy_epro_ofld(void *priv, u16 vsi_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union epro_mhash_upcall_u mhash_upcall = {.info.en = 1,
						.info.mod = 1};
	union epro_evsi_vlan_ofld_u vlan_ofld = {.info.bps = 1};
	struct nbl_ped_tbl_udf_ext udf_ped = {.en0 = 1,};

	nbl_hw_write_regs(phy_mgt, NBL_EPRO_MHASH_UPCALL_REG(vsi_id), (u8 *)&mhash_upcall,
			  NBL_EPRO_MHASH_UPCALL_DWLEN * NBL_BYTES_IN_REG);
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_EVSI_VLAN_OFLD_ADDR, (u8 *)&vlan_ofld,
			  sizeof(vlan_ofld));
	nbl_hw_write_regs(phy_mgt, NBL_PED_TBL_UDF_EXT(vsi_id), (u8 *)&udf_ped,
			  sizeof(udf_ped));
}

static int nbl_phy_clear_em(void *priv, u8 pf_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union fem_pf0_em_clr_u clr = {{0}};
	int i = 0;

	clr.info.en = 1;
	nbl_hw_write_regs(phy_mgt, NBL_FEM_PF0_EM_CLR_ADDR + NBL_BYTES_IN_REG * pf_id,
			  (u8 *)&clr, NBL_FEM_PF0_EM_CLR_DWLEN * NBL_BYTES_IN_REG);

	while (++i < NBL_EM_MAX_WAIT_TIMES) {
		/* TODO: reduce sleep time */
		usleep_range(100, 200);
		nbl_hw_read_regs(phy_mgt, NBL_FEM_PF0_EM_CLR_ADDR + NBL_BYTES_IN_REG * pf_id,
				 (u8 *)&clr, NBL_FEM_PF0_EM_CLR_DWLEN * NBL_BYTES_IN_REG);
		if (!clr.info.en)
			break;
	}

	return 0;
}

static int nbl_phy_get_acl_flow_stat_width(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	union acl_flow_stat_width_u flow_stat_width;

	memset(&flow_stat_width, 0, sizeof(flow_stat_width));
	nbl_hw_read_regs(phy_mgt, NBL_ACL_FLOW_STAT_WIDTH_ADDR,
			 (u8 *)&flow_stat_width, sizeof(flow_stat_width));

	nbl_info(common, NBL_DEBUG_FLOW, "get acl flow_stat_width:%u",
		 flow_stat_width.info.width_sel);

	return flow_stat_width.info.width_sel;
}

static int nbl_phy_cmdq_init(void *priv, void *param, u16 func_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct nbl_chan_cmdq_init_info *cmdq_param = (struct nbl_chan_cmdq_init_info *)param;
	u8 f_id = common->mgt_pf;
	union pcompleter_cfg_fid0_cmdq_u cfg_func_id = {
		.info.dbg = f_id,
		.info.vld = 1,
	};
	union cmdq_qinfo_table_u qinfo;
	u32 en = 0;

	memset(&qinfo, 0, sizeof(qinfo));

	/* use bus for draco as hw_bus only set in snic */
	cmdq_param->bdf_num = (u16)(common->bus << 8 | common->devid << 3 |
			      NBL_COMMON_TO_PCI_FUNC_ID(common));

	qinfo.info.dif_bdf = cmdq_param->bdf_num;
	qinfo.info.base_addr_h = NBL_HI_DWORD(cmdq_param->pa);
	qinfo.info.base_addr_l = NBL_LO_DWORD(cmdq_param->pa);
	qinfo.info.size_mask = cmdq_param->len - 1;
	qinfo.info.dif_mode = NBL_CMDQ_DIF_MODE_VALUE;

	/* write registers */
	nbl_hw_write_regs(phy_mgt, NBL_PCOMPLETER_CFG_FID0_CMDQ_ADDR + f_id * NBL_BYTES_IN_REG,
			  (u8 *)&cfg_func_id, NBL_BYTES_IN_REG);
	/* make sure cmdq is disabled before configuration */
	nbl_hw_write_regs(phy_mgt, NBL_DRACO_CMDQ_EN(f_id), (u8 *)&en, NBL_BYTES_IN_REG);
	nbl_hw_write_regs(phy_mgt, NBL_CMDQ_QINFO_TABLE_REG(f_id),
			  (u8 *)&qinfo, NBL_BYTES_IN_REG * NBL_CMDQ_QINFO_TABLE_DWLEN);
	en = 1;
	nbl_hw_write_regs(phy_mgt, NBL_DRACO_CMDQ_EN(f_id), (u8 *)&en, NBL_BYTES_IN_REG);

	nbl_info(common, NBL_DEBUG_FLOW, "phy init cmdq: f_id:%u, len:%u, bdf:0x%x\n",
		 f_id, cmdq_param->len, cmdq_param->bdf_num);

	return 0;
}

static int nbl_phy_cmdq_destroy(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	u8 func_id = NBL_PHY_MGT_TO_COMMON(phy_mgt)->mgt_pf;
	union cmdq_qinfo_table_u qinfo;
	u32 en = 0;

	memset(&qinfo, 0, sizeof(qinfo));

	qinfo.info.en = 0;
	nbl_hw_write_regs(phy_mgt, NBL_DRACO_CMDQ_EN(func_id), (u8 *)&en, NBL_BYTES_IN_REG);
	udelay(NBL_CMDQ_FLIGHT_DELAY);
	qinfo.info.dif_mode = NBL_CMDQ_DIF_MODE_VALUE;
	nbl_hw_write_regs(phy_mgt, NBL_CMDQ_QINFO_TABLE_REG(func_id),
			  (u8 *)&qinfo, NBL_BYTES_IN_REG * NBL_CMDQ_QINFO_TABLE_DWLEN);

	return NBL_OK;
}

static int nbl_phy_cmdq_reset(void *priv, void *param)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	u8 func_id = NBL_PHY_MGT_TO_COMMON(phy_mgt)->mgt_pf;
	union cmdq_qinfo_table_u qinfo;
	u16 delay_count = 0;

	memset(&qinfo, 0, sizeof(qinfo));

	nbl_debug(common, NBL_DEBUG_FLOW, "CMDQ resetting now...\n");

	/* wait until tail equals head, then reset tail */
	while (true) {
		nbl_hw_read_regs(phy_mgt, NBL_CMDQ_QINFO_TABLE_REG(func_id),
				 (u8 *)&qinfo, NBL_BYTES_IN_REG * NBL_CMDQ_QINFO_TABLE_DWLEN);
		if (qinfo.info.hpntr == qinfo.info.tpntr)
			break;

		delay_count++;
		if (delay_count >= NBL_CMDQ_RESET_MAX_WAIT)
			return -EBADRQC;
		usleep_range(NBL_CMDQ_DELAY_200US, NBL_CMDQ_DELAY_300US);
	}

	nbl_phy_cmdq_init(priv, param, func_id);

	return 0;
}

static void nbl_phy_update_cmdq_tail(void *priv, u32 doorbell)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_hw_wr32(phy_mgt, NBL_CMD_NOTIFY_ADDR, doorbell);
}

static void nbl_phy_set_tc_kgen_cvlan_zero(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);

	nbl_info(common, NBL_DEBUG_FLOW, "draco todo: set cvlan to zero");
}

static void nbl_phy_unset_tc_kgen_cvlan(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);

	nbl_info(common, NBL_DEBUG_FLOW, "draco todo: unset cvlan to zero");
}

static void nbl_phy_ipro_chksum_err_ctrl(void *priv, u8 status)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union ipro_errcode_tbl_u ipro_errcode_tbl;
	union nbl_action_bits_base base_ab;
	union nbl_action_datas base_ad;
	u8 id = NBL_IPRO_ERROR_CODE_CSUM_ERR;

	memset(&ipro_errcode_tbl, 0, sizeof(ipro_errcode_tbl));
	memset(&base_ab, 0, sizeof(base_ab));
	memset(&base_ad, 0, sizeof(base_ad));

	base_ab.baseab.SET_DEST = 1;
	base_ab.baseab.SET_UDF = 0;
	base_ab.baseab.VLAN_OP = 0;
	base_ad.dport.down.dir = DPORT_DIR_OTHER;
	base_ad.dport.down.other_type = DPORT_OTHER_TYPE_DROP;

	ipro_errcode_tbl.info.base_ab = base_ab.data;
	ipro_errcode_tbl.info.base_ad_arr[0] = base_ad.u32_arr[0];
	ipro_errcode_tbl.info.base_ad_arr[1] = base_ad.u32_arr[1];

	nbl_hw_write_regs(phy_mgt, NBL_IPRO_ERRCODE_TBL_REG(id), (u8 *)&ipro_errcode_tbl,
			  NBL_IPRO_ERRCODE_TBL_DWLEN * NBL_BYTES_IN_REG);
}

static void nbl_phy_ipro_chksum_err_select(void *priv, u8 status, u8 dir)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	union ipro_errcode_3_hdl_u ipro_errcode_3_hdl;
	u8 sw_id = common->eth_id;
	u32 md_base = (dir == NBL_CSUM_ERR_DIR_RX) ?
		      NBL_IPRO_ERRCODE_3_HDL_RX_MD_BASE :
		      NBL_IPRO_ERRCODE_3_HDL_TX_MD_BASE;
	u32 md_shift = NBL_IPRO_ERRCODE_3_HDL_BITS_PER_MD * (md_base + sw_id);
	u32 md_mask = NBL_IPRO_ERRCODE_3_HDL_PF_MASK << md_shift;

	nbl_hw_read_regs(phy_mgt, NBL_IPRO_ERRCODE_3_HDL_ADDR, (u8 *)&ipro_errcode_3_hdl,
			 NBL_IPRO_ERRCODE_3_HDL_DWLEN * NBL_BYTES_IN_REG);

	if (status)
		ipro_errcode_3_hdl.info.csum_err |= md_mask;
	else
		ipro_errcode_3_hdl.info.csum_err &= ~md_mask;

	nbl_hw_write_regs(phy_mgt, NBL_IPRO_ERRCODE_3_HDL_ADDR, (u8 *)&ipro_errcode_3_hdl,
			  NBL_IPRO_ERRCODE_3_HDL_DWLEN * NBL_BYTES_IN_REG);
}

static void nbl_phy_pa_chksum_err_report(void *priv, u8 status, u8 dir)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union pa_err_report_u pa_err_report;
	u8 l3_csum_err_mask = (dir == NBL_CSUM_ERR_DIR_RX) ? BIT(2) : BIT(9);
	u8 l4_csum_err_mask = (dir == NBL_CSUM_ERR_DIR_RX) ? BIT(3) : BIT(10);
	u16 mask = l3_csum_err_mask | l4_csum_err_mask;

	nbl_hw_read_regs(phy_mgt, NBL_PA_ERR_REPORT_ADDR, (u8 *)&pa_err_report,
			 NBL_PA_ERR_REPORT_DWLEN * NBL_BYTES_IN_REG);

	if (status) {
		if ((pa_err_report.info.en & mask) == mask)
			return;
		pa_err_report.info.en |= mask;
	} else {
		if (dir == NBL_CSUM_ERR_DIR_RX || !(pa_err_report.info.en & mask))
			return;
		pa_err_report.info.en &= ~mask;
	}

	nbl_hw_write_regs(phy_mgt, NBL_PA_ERR_REPORT_ADDR, (u8 *)&pa_err_report,
			  NBL_PA_ERR_REPORT_DWLEN * NBL_BYTES_IN_REG);
}

static int nbl_phy_acl_set_upcall_rule(void *priv, u8 idx, u16 vsi_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);

	nbl_info(common, NBL_DEBUG_FLOW, "draco todo:phy-acl-set-upcall-rule");
	return 0;
}

static int nbl_phy_acl_unset_upcall_rule(void *priv, u8 idx)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);

	nbl_info(common, NBL_DEBUG_FLOW, "draco todo:phy-acl-unset-upcall-rule");
	return 0;
}

static int nbl_phy_set_fd_udf(void *priv, u8 lxmode, u8 offset)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union pa_udf_ext_tcam_key_u ptype_key;
	union pa_udf_ext_tcam_mask_u ptype_mask;
	union pa_udf_ext_prof_u ext_prof;
	union nbl_pa_udf_ext_idxs ext_idxs;
	union nbl_draco_ptype_u ptype;
	union nbl_draco_ptype_u mask;
	u8 index = 0;
	u8 ext_index = 0;

	memset(&ext_prof, 0, sizeof(ext_prof));
	memset(&ext_idxs, 0, sizeof(ext_idxs));
	memset(&ptype_key, 0, sizeof(ptype_key));
	memset(&ptype_mask, 0, sizeof(ptype_mask));
	memset(&ptype, 0, sizeof(ptype));
	memset(&mask, 0, sizeof(mask));

	/* fallback ptype configs: use the last tcam entry */
	index = 15;
	switch (lxmode) {
	case 0:
		mask.data = 0xFFFF;
		break;
	case 1:
		mask.data = 0xFFFF;
		mask.nontnl.l3 = 0b01;  /* ipv4 or ipv6 */
		ptype.nontnl.l3 = 0b00;
		break;
	case 2:
		mask.data = 0xFFFF;
		mask.nontnl.l4 = 0b01; /* tcp4 or tcp6 or udp4 or udp6 */
		ptype.nontnl.l4 = 0b00;
		break;
	default:
		return -EINVAL;
	}

	ptype_key.info.ptype = ptype.data;
	ptype_key.info.vld = 1;
	ptype_mask.info.mask = mask.data;
	nbl_hw_write_regs(phy_mgt, NBL_PA_UDF_EXT_TCAM_KEY_REG(index),
			  (u8 *)&ptype_key.data, sizeof(ptype_key));
	nbl_hw_write_regs(phy_mgt, NBL_PA_UDF_EXT_TCAM_MASK_REG(index),
			  (u8 *)&ptype_mask, sizeof(ptype_mask));
	nbl_hw_read_regs(phy_mgt, NBL_PA_UDF_EXT_IDX_REG(index),
			 (u8 *)&ext_idxs, sizeof(ext_idxs));
	ext_idxs.info.idx0 = lxmode + 8;
	ext_idxs.info.vld0 = 1;
	nbl_hw_write_regs(phy_mgt, NBL_PA_UDF_EXT_IDX_REG(index),
			  (u8 *)&ext_idxs, sizeof(ext_idxs));

	/* config offset */
	ext_index = lxmode + 8;
	nbl_hw_read_regs(phy_mgt, NBL_PA_UDF_EXT_PROF_REG(ext_index),
			 (u8 *)&ext_prof.data, NBL_BYTES_IN_REG);
	ext_prof.info.oft = offset * 8;
	nbl_hw_write_regs(phy_mgt, NBL_PA_UDF_EXT_PROF_REG(ext_index),
			  (u8 *)&ext_prof.data, NBL_BYTES_IN_REG);

	/* config ptype tcam index */
	index = 0;  /* IPv4 RoCEv2 */
	nbl_hw_read_regs(phy_mgt, NBL_PA_UDF_EXT_IDX_REG(index),
			 (u8 *)&ext_idxs, sizeof(ext_idxs));
	ext_idxs.info.idx2 = ext_index;
	ext_idxs.info.vld2 = 1;
	nbl_hw_write_regs(phy_mgt, NBL_PA_UDF_EXT_IDX_REG(index),
			  (u8 *)&ext_idxs, sizeof(ext_idxs));
	index = 1;  /* IPv6 RoCEv2 */
	nbl_hw_read_regs(phy_mgt, NBL_PA_UDF_EXT_IDX_REG(index),
			 (u8 *)&ext_idxs, sizeof(ext_idxs));
	ext_idxs.info.idx2 = ext_index;
	ext_idxs.info.vld2 = 1;
	nbl_hw_write_regs(phy_mgt, NBL_PA_UDF_EXT_IDX_REG(index),
			  (u8 *)&ext_idxs, sizeof(ext_idxs));
	index = 2;  /* GENEVE-OVN & TCP */
	nbl_hw_read_regs(phy_mgt, NBL_PA_UDF_EXT_IDX_REG(index),
			 (u8 *)&ext_idxs, sizeof(ext_idxs));
	ext_idxs.info.idx2 = ext_index;
	ext_idxs.info.vld2 = 1;
	nbl_hw_write_regs(phy_mgt, NBL_PA_UDF_EXT_IDX_REG(index),
			  (u8 *)&ext_idxs, sizeof(ext_idxs));
	index = 3;  /* GENEVE-OVN */
	nbl_hw_read_regs(phy_mgt, NBL_PA_UDF_EXT_IDX_REG(index),
			 (u8 *)&ext_idxs, sizeof(ext_idxs));
	ext_idxs.info.idx1 = ext_index;
	ext_idxs.info.vld1 = 1;
	nbl_hw_write_regs(phy_mgt, NBL_PA_UDF_EXT_IDX_REG(index),
			  (u8 *)&ext_idxs, sizeof(ext_idxs));
	index = 4;  /* TCP */
	nbl_hw_read_regs(phy_mgt, NBL_PA_UDF_EXT_IDX_REG(index),
			 (u8 *)&ext_idxs, sizeof(ext_idxs));
	ext_idxs.info.idx1 = ext_index;
	ext_idxs.info.vld1 = 1;
	nbl_hw_write_regs(phy_mgt, NBL_PA_UDF_EXT_IDX_REG(index),
			  (u8 *)&ext_idxs, sizeof(ext_idxs));
	return 0;
}

static int nbl_phy_clr_fd_udf(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union nbl_pa_udf_ext_idxs ext_idxs;
	u8 index = 0;

	memset(&ext_idxs, 0, sizeof(ext_idxs));

	/* config ptype tcam index */
	index = 0;  /* IPv4 RoCEv2 */
	nbl_hw_read_regs(phy_mgt, NBL_PA_UDF_EXT_IDX_REG(index),
			 (u8 *)&ext_idxs, sizeof(ext_idxs));
	ext_idxs.info.vld2 = 0;
	nbl_hw_write_regs(phy_mgt, NBL_PA_UDF_EXT_IDX_REG(index),
			  (u8 *)&ext_idxs, sizeof(ext_idxs));
	index = 1;  /* IPv6 RoCEv2 */
	nbl_hw_read_regs(phy_mgt, NBL_PA_UDF_EXT_IDX_REG(index),
			 (u8 *)&ext_idxs, sizeof(ext_idxs));
	ext_idxs.info.vld2 = 0;
	nbl_hw_write_regs(phy_mgt, NBL_PA_UDF_EXT_IDX_REG(index),
			  (u8 *)&ext_idxs, sizeof(ext_idxs));
	index = 2;  /* GENEVE-OVN & TCP */
	nbl_hw_read_regs(phy_mgt, NBL_PA_UDF_EXT_IDX_REG(index),
			 (u8 *)&ext_idxs, sizeof(ext_idxs));
	ext_idxs.info.vld2 = 0;
	nbl_hw_write_regs(phy_mgt, NBL_PA_UDF_EXT_IDX_REG(index),
			  (u8 *)&ext_idxs, sizeof(ext_idxs));
	index = 3;  /* GENEVE-OVN */
	nbl_hw_read_regs(phy_mgt, NBL_PA_UDF_EXT_IDX_REG(index),
			 (u8 *)&ext_idxs, sizeof(ext_idxs));
	ext_idxs.info.vld1 = 0;
	nbl_hw_write_regs(phy_mgt, NBL_PA_UDF_EXT_IDX_REG(index),
			  (u8 *)&ext_idxs, sizeof(ext_idxs));
	index = 4;  /* TCP */
	nbl_hw_read_regs(phy_mgt, NBL_PA_UDF_EXT_IDX_REG(index),
			 (u8 *)&ext_idxs, sizeof(ext_idxs));
	ext_idxs.info.vld1 = 0;
	nbl_hw_write_regs(phy_mgt, NBL_PA_UDF_EXT_IDX_REG(index),
			  (u8 *)&ext_idxs, sizeof(ext_idxs));
	index = 15;  /* Last fallback */
	nbl_hw_read_regs(phy_mgt, NBL_PA_UDF_EXT_IDX_REG(index),
			 (u8 *)&ext_idxs, sizeof(ext_idxs));
	ext_idxs.info.vld0 = 0;
	nbl_hw_write_regs(phy_mgt, NBL_PA_UDF_EXT_IDX_REG(index),
			  (u8 *)&ext_idxs, sizeof(ext_idxs));

	return 0;
}

static int nbl_phy_flow_init(void *priv, void *param)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct nbl_chan_flow_init_info_draco *info =
		(struct nbl_chan_flow_init_info_draco *)param;
	u16 pf_id = NBL_COMMON_TO_MGT_PF(common);

	nbl_info(common, NBL_DEBUG_PHY, "init flow start:%u-%u\n", info->vsi_id, info->eth_id);
	nbl_phy_init_ofld_ipro(priv, info->vsi_id, info->eth_id);
	nbl_phy_epro_ofld(priv, info->vsi_id);
	nbl_phy_init_acl(priv, param);
	nbl_phy_clear_em(priv, pf_id);

	return 0;
}

static void nbl_phy_set_slave_swd_id(void *priv, u16 vf_start, u16 vf_cnt,
				     u16 swd_id, u16 pf_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	union ipro_ivsi_u ivsi;
	union ipro_ieth_u ieth;
	int idx = 0;

	memset(&ivsi, 0, sizeof(union ipro_ivsi_u));
	memset(&ieth, 0, sizeof(union ipro_ieth_u));
	nbl_info(common, NBL_DEBUG_PHY, "set slave {%u} and vf {%u-%u} swd to %u\n",
		 pf_id, vf_start, vf_start + vf_cnt, swd_id);
	for (idx = vf_start; idx < vf_start + vf_cnt; ++idx) {
		nbl_hw_read_regs(phy_mgt, NBL_IPRO_IVSI_REG(idx), (u8 *)&ivsi, sizeof(ivsi));
		ivsi.info.sw_id = swd_id;
		nbl_hw_write_regs(phy_mgt, NBL_IPRO_IVSI_REG(idx), (u8 *)&ivsi, sizeof(ivsi));
	}

	nbl_hw_read_regs(phy_mgt, NBL_IPRO_IETH_REG(pf_id), (u8 *)&ieth, sizeof(ieth));
	ieth.info.sw_id = swd_id;
	nbl_hw_write_regs(phy_mgt, NBL_IPRO_IETH_REG(pf_id), (u8 *)&ieth, sizeof(ieth));
}

static int nbl_phy_set_vnet_queue_info(void *priv, struct nbl_vnet_queue_info_param *param,
				       u16 queue_id)
{
	struct nbl_phy_mgt_draco *phy_mgt_draco = (struct nbl_phy_mgt_draco *)priv;
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_padpt_vnet_qinfo vnet_qinfo = {0};

	vnet_qinfo.function_id = param->function_id;
	vnet_qinfo.device_id = param->device_id;
	vnet_qinfo.bus_id = param->bus_id;
	vnet_qinfo.valid = param->valid;
	vnet_qinfo.msix_idx = param->msix_idx;
	vnet_qinfo.msix_idx_valid = param->msix_idx_valid;
	if (phy_mgt_draco->ro_enable) {
		vnet_qinfo.ido_en = 1;
		vnet_qinfo.rlo_en = 1;
	}

	nbl_hw_write_regs(phy_mgt, NBL_PADPT_VNET_QINFO_TABLE_ADDR(queue_id),
			  (u8 *)&vnet_qinfo, sizeof(vnet_qinfo));

	return 0;
}

static int nbl_phy_clear_vnet_queue_info(void *priv, u16 queue_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_padpt_vnet_qinfo vnet_qinfo = {0};

	nbl_hw_write_regs(phy_mgt, NBL_PADPT_VNET_QINFO_TABLE_ADDR(queue_id),
			  (u8 *)&vnet_qinfo, sizeof(vnet_qinfo));
	return 0;
}

static int nbl_phy_cfg_vnet_qinfo_log(void *priv, u16 queue_id, bool vld)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_padpt_vnet_qinfo vnet_qinfo = {0};

	nbl_hw_read_regs(phy_mgt, NBL_PADPT_VNET_QINFO_TABLE_ADDR(queue_id),
			 (u8 *)&vnet_qinfo, sizeof(vnet_qinfo));
	vnet_qinfo.log_en = vld;
	nbl_hw_write_regs(phy_mgt, NBL_PADPT_VNET_QINFO_TABLE_ADDR(queue_id),
			  (u8 *)&vnet_qinfo, sizeof(vnet_qinfo));

	return 0;
}

static void nbl_phy_init_pfc(void *priv, u8 eth_id, u8 ether_ports, u8 pfc_mode, u8 bp_mode)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_eeth_tbl eeth_tbl = {0};
	struct nbl_qm_dn_cos_mapping_0 qm_dn_cos_mapping_0 = {0};
	struct nbl_qm_dn_cos_mapping_1 qm_dn_cos_mapping_1 = {0};
	struct nbl_qm_dn_cos_mapping_2 qm_dn_cos_mapping_2 = {0};
	struct nbl_store_pri_conf store_pri_conf = {0};
	struct nbl_store_tbl_pri_conf store_tbl_pri_conf = {0};
	struct nbl_store_eth_port_fc store_eth_port_fc = {0};
	struct nbl_store_eth_cos_fc store_eth_cos_fc = {0};
	struct nbl_store_up_fc_mode store_up_fc_mode = {0};
	u32 qm_rxmac_port_bp_en = 0;
	u32 qm_rxmac_cos_bp_en = 0;
	u32 qm_tx_rxmac_port_bp_en = {0};
	u32 qm_tx_rxmac_cos_bp_en = {0};
	int i;

	/* pfc_mode, 0: 802.1p, 1: dscp */
	if (!pfc_mode) {
		/* TX: enable pfc_rmk, set pfc mode to 802.1q */
		nbl_hw_read_regs(phy_mgt, NBL_EPRO_EETH_TABLE(eth_id),
				 (u8 *)&eeth_tbl, sizeof(eeth_tbl));
		eeth_tbl.pfc_mode = EETH_PFC_MODE_8021P;
		nbl_hw_write_regs(phy_mgt, NBL_EPRO_EETH_TABLE(eth_id),
				  (u8 *)&eeth_tbl, sizeof(eeth_tbl));
		/* TX: set sch_cos -> pkt_cos (vlan prio and dscp) map table */
		qm_dn_cos_mapping_0.cos0 = 0;
		qm_dn_cos_mapping_0.cos1 = (1 << 6 | 8);
		qm_dn_cos_mapping_0.cos2 = (2 << 6 | 16);
		qm_dn_cos_mapping_1.cos3 = (3 << 6 | 24);
		qm_dn_cos_mapping_1.cos4 = (4 << 6 | 32);
		qm_dn_cos_mapping_1.cos5 = (5 << 6 | 40);
		qm_dn_cos_mapping_2.cos6 = (6 << 6 | 48);
		qm_dn_cos_mapping_2.cos7 = (7 << 6 | 56);
		nbl_hw_write_regs(phy_mgt, NBL_QM_DN_COS_MAPPING_0(eth_id),
				  (u8 *)&qm_dn_cos_mapping_0, sizeof(qm_dn_cos_mapping_0));
		nbl_hw_write_regs(phy_mgt, NBL_QM_DN_COS_MAPPING_1(eth_id),
				  (u8 *)&qm_dn_cos_mapping_1, sizeof(qm_dn_cos_mapping_1));
		nbl_hw_write_regs(phy_mgt, NBL_QM_DN_COS_MAPPING_2(eth_id),
				  (u8 *)&qm_dn_cos_mapping_2, sizeof(qm_dn_cos_mapping_2));

		/* RX: enable pri extract, set pri extract mode to 802.1q */
		store_pri_conf.en = 1;
		store_pri_conf.sel = STORE_PRI_CONF_RX_PRI_MODE_8021P;
		store_pri_conf.cpu_set = 0;
		nbl_hw_write_regs(phy_mgt, NBL_STORE_PRI_CONF(eth_id),
				  (u8 *)&store_pri_conf, sizeof(store_pri_conf));
		/* RX: set pkt_cos (vlan prio) -> sch_cos map table */
		store_tbl_pri_conf.pri0 = 0;
		store_tbl_pri_conf.pri1 = 1;
		store_tbl_pri_conf.pri2 = 2;
		store_tbl_pri_conf.pri3 = 3;
		store_tbl_pri_conf.pri4 = 4;
		store_tbl_pri_conf.pri5 = 5;
		store_tbl_pri_conf.pri6 = 6;
		store_tbl_pri_conf.pri7 = 7;
		nbl_hw_write_regs(phy_mgt, NBL_STORE_TBL_PRI_CONF(eth_id * 8),
				  (u8 *)&store_tbl_pri_conf, sizeof(store_tbl_pri_conf));
	} else {
		/* TX: enable pfc_rmk, set pfc mode to dscp */
		nbl_hw_read_regs(phy_mgt, NBL_EPRO_EETH_TABLE(eth_id),
				 (u8 *)&eeth_tbl, sizeof(eeth_tbl));
		eeth_tbl.pfc_mode = EETH_PFC_MODE_DSCP;
		nbl_hw_write_regs(phy_mgt, NBL_EPRO_EETH_TABLE(eth_id),
				  (u8 *)&eeth_tbl, sizeof(eeth_tbl));
		/* TX: set sch_cos -> pkt_cos (vlan prio and dscp) map table */
		qm_dn_cos_mapping_0.cos0 = 0;
		qm_dn_cos_mapping_0.cos1 = (1 << 6 | 8);
		qm_dn_cos_mapping_0.cos2 = (2 << 6 | 16);
		qm_dn_cos_mapping_1.cos3 = (3 << 6 | 24);
		qm_dn_cos_mapping_1.cos4 = (4 << 6 | 32);
		qm_dn_cos_mapping_1.cos5 = (5 << 6 | 40);
		qm_dn_cos_mapping_2.cos6 = (6 << 6 | 48);
		qm_dn_cos_mapping_2.cos7 = (7 << 6 | 56);
		nbl_hw_write_regs(phy_mgt, NBL_QM_DN_COS_MAPPING_0(eth_id),
				  (u8 *)&qm_dn_cos_mapping_0, sizeof(qm_dn_cos_mapping_0));
		nbl_hw_write_regs(phy_mgt, NBL_QM_DN_COS_MAPPING_1(eth_id),
				  (u8 *)&qm_dn_cos_mapping_1, sizeof(qm_dn_cos_mapping_1));
		nbl_hw_write_regs(phy_mgt, NBL_QM_DN_COS_MAPPING_2(eth_id),
				  (u8 *)&qm_dn_cos_mapping_2, sizeof(qm_dn_cos_mapping_2));

		/* RX: enable pri extract, set pri extract mode to dscp */
		store_pri_conf.en = 1;
		store_pri_conf.sel = STORE_PRI_CONF_RX_PRI_MODE_DSCP;
		store_pri_conf.cpu_set = 0;
		nbl_hw_write_regs(phy_mgt, NBL_STORE_PRI_CONF(eth_id),
				  (u8 *)&store_pri_conf, sizeof(store_pri_conf));
		/* RX: set pkt_cos (dscp) -> sch_cos map table */
		for (i = 0; i < 8; i++) {
			store_tbl_pri_conf.pri0 = i;
			store_tbl_pri_conf.pri1 = i;
			store_tbl_pri_conf.pri2 = i;
			store_tbl_pri_conf.pri3 = i;
			store_tbl_pri_conf.pri4 = i;
			store_tbl_pri_conf.pri5 = i;
			store_tbl_pri_conf.pri6 = i;
			store_tbl_pri_conf.pri7 = i;
			nbl_hw_write_regs(phy_mgt, NBL_STORE_TBL_PRI_CONF(eth_id * 8 + i),
					  (u8 *)(&store_tbl_pri_conf), sizeof(store_tbl_pri_conf));
		}
	}

	/* bp_mode, 0: port, 1: pfc */
	/* RX: default port_fc, when reach eth port threshold, trigger pause frame */
	nbl_hw_read_regs(phy_mgt, NBL_STORE_ETH_PORT_FC(eth_id),
			 (u8 *)&store_eth_port_fc, sizeof(store_eth_port_fc));
	store_eth_port_fc.fc_en = !bp_mode;
	nbl_hw_write_regs(phy_mgt, NBL_STORE_ETH_PORT_FC(eth_id),
			  (u8 *)&store_eth_port_fc, sizeof(store_eth_port_fc));
	for (i = 0; i < 8; i++) {
		nbl_hw_read_regs(phy_mgt, NBL_STORE_ETH_COS_FC(eth_id * 8 + i),
				 (u8 *)&store_eth_cos_fc, sizeof(store_eth_cos_fc));
		store_eth_cos_fc.fc_en = bp_mode;
		nbl_hw_write_regs(phy_mgt, NBL_STORE_ETH_COS_FC(eth_id * 8 + i),
				  (u8 *)&store_eth_cos_fc, sizeof(store_eth_cos_fc));
	}
	store_up_fc_mode.pfc = 1;
	store_up_fc_mode.link = 1;
	nbl_hw_write_regs(phy_mgt, NBL_STORE_UP_FC_MODE,
			  (u8 *)&store_up_fc_mode, sizeof(store_up_fc_mode));

	/* TX: default port_fc, when receive pause frame, QM response and send it to DSCH */
	if (!bp_mode) {
		/* TX: qm response to pause, donot response to PFC */
		nbl_hw_read_regs(phy_mgt, NBL_QM_RXMAC_PORT_BP_EN,
				 (u8 *)&qm_rxmac_port_bp_en, sizeof(qm_rxmac_port_bp_en));
		qm_rxmac_port_bp_en |= BIT(eth_id);
		nbl_hw_write_regs(phy_mgt, NBL_QM_RXMAC_PORT_BP_EN,
				  (u8 *)&qm_rxmac_port_bp_en, sizeof(qm_rxmac_port_bp_en));

		nbl_hw_read_regs(phy_mgt, NBL_QM_RXMAC_COS_BP_EN,
				 (u8 *)&qm_rxmac_cos_bp_en, sizeof(qm_rxmac_cos_bp_en));
		qm_rxmac_cos_bp_en &= ~(0xFF << eth_id * 8);
		nbl_hw_write_regs(phy_mgt, NBL_QM_RXMAC_COS_BP_EN,
				  (u8 *)&qm_rxmac_cos_bp_en, sizeof(qm_rxmac_cos_bp_en));

		/* TX: qm send pause to DSCH, donot send PFC to DSCH */
		nbl_hw_read_regs(phy_mgt, NBL_QM_TX_RXMAC_PORT_BP_EN,
				 (u8 *)&qm_tx_rxmac_port_bp_en, sizeof(qm_tx_rxmac_port_bp_en));
		qm_tx_rxmac_port_bp_en |= BIT(eth_id);
		nbl_hw_write_regs(phy_mgt, NBL_QM_TX_RXMAC_PORT_BP_EN,
				  (u8 *)&qm_tx_rxmac_port_bp_en, sizeof(qm_tx_rxmac_port_bp_en));

		nbl_hw_read_regs(phy_mgt, NBL_QM_TX_RXMAC_COS_BP_EN,
				 (u8 *)&qm_tx_rxmac_cos_bp_en, sizeof(qm_tx_rxmac_cos_bp_en));
		qm_tx_rxmac_cos_bp_en &= ~(0xFF << eth_id * 8);
		nbl_hw_write_regs(phy_mgt, NBL_QM_TX_RXMAC_COS_BP_EN,
				  (u8 *)&qm_tx_rxmac_cos_bp_en, sizeof(qm_tx_rxmac_cos_bp_en));
	} else {
		/* TX: qm response to PFC, donot response to pause */
		nbl_hw_read_regs(phy_mgt, NBL_QM_RXMAC_PORT_BP_EN,
				 (u8 *)&qm_rxmac_port_bp_en, sizeof(qm_rxmac_port_bp_en));
		qm_rxmac_port_bp_en &= ~BIT(eth_id);
		nbl_hw_write_regs(phy_mgt, NBL_QM_RXMAC_PORT_BP_EN,
				  (u8 *)&qm_rxmac_port_bp_en, sizeof(qm_rxmac_port_bp_en));

		nbl_hw_read_regs(phy_mgt, NBL_QM_RXMAC_COS_BP_EN,
				 (u8 *)&qm_rxmac_cos_bp_en, sizeof(qm_rxmac_cos_bp_en));
		qm_rxmac_cos_bp_en |= (0xFF << eth_id * 8);
		nbl_hw_write_regs(phy_mgt, NBL_QM_RXMAC_COS_BP_EN,
				  (u8 *)&qm_rxmac_cos_bp_en, sizeof(qm_rxmac_cos_bp_en));

		/* TX: qm send PFC to DSCH, donot send pause to DSCH */
		nbl_hw_read_regs(phy_mgt, NBL_QM_TX_RXMAC_PORT_BP_EN,
				 (u8 *)&qm_tx_rxmac_port_bp_en, sizeof(qm_tx_rxmac_port_bp_en));
		qm_tx_rxmac_port_bp_en &= ~BIT(eth_id);
		nbl_hw_write_regs(phy_mgt, NBL_QM_TX_RXMAC_PORT_BP_EN,
				  (u8 *)&qm_tx_rxmac_port_bp_en, sizeof(qm_tx_rxmac_port_bp_en));

		nbl_hw_read_regs(phy_mgt, NBL_QM_TX_RXMAC_COS_BP_EN,
				 (u8 *)&qm_tx_rxmac_cos_bp_en, sizeof(qm_tx_rxmac_cos_bp_en));
		qm_tx_rxmac_cos_bp_en |= (0xFF << eth_id * 8);
		nbl_hw_write_regs(phy_mgt, NBL_QM_TX_RXMAC_COS_BP_EN,
				  (u8 *)&qm_tx_rxmac_cos_bp_en, sizeof(qm_tx_rxmac_cos_bp_en));
	}
	/* TX: DSCH dp0-3 response to DQM dp0-3 pfc/port bp */
	/* dsch_dpt_pfc_map_vnh default value is ok */
	/* TX: DSCH response to DQM cos bp, pkt_cos -> sch_cos map table */
	/* dsch vn_host_dpx_prixx_p2s_map_cfg is ok */
}

static void nbl_phy_configure_pfc(void *priv, u8 eth_id, u8 *pfc)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	u32 enable = 0;
	u32 cos_en = 0;
	struct nbl_qm_rxmac_port_bp_en qm_rxmac_port_bp_en = {0};
	struct nbl_qm_rxmac_cos_bp_en qm_rxmac_cos_bp_en = {0};
	struct nbl_qm_tx_rxmac_port_bp_en qm_tx_rxmac_port_bp_en = {0};
	struct nbl_qm_tx_rxmac_cos_bp_en qm_tx_rxmac_cos_bp_en = {0};
	struct nbl_store_eth_port_fc store_eth_port_fc = {0};
	struct nbl_store_eth_cos_fc store_eth_cos_fc = {0};
	int i;

	for (i = 0; i < NBL_MAX_PFC_PRIORITIES; i++) {
		if (pfc[i])
			enable = 1;
		cos_en |= pfc[i] << i;
	}

	nbl_hw_read_regs(phy_mgt, NBL_QM_RXMAC_PORT_BP_EN,
			 (u8 *)(&qm_rxmac_port_bp_en), sizeof(qm_rxmac_port_bp_en));
	nbl_hw_read_regs(phy_mgt, NBL_QM_RXMAC_COS_BP_EN,
			 (u8 *)(&qm_rxmac_cos_bp_en), sizeof(qm_rxmac_cos_bp_en));
	nbl_hw_read_regs(phy_mgt, NBL_QM_TX_RXMAC_PORT_BP_EN,
			 (u8 *)(&qm_tx_rxmac_port_bp_en), sizeof(qm_tx_rxmac_port_bp_en));
	nbl_hw_read_regs(phy_mgt, NBL_QM_TX_RXMAC_COS_BP_EN,
			 (u8 *)(&qm_tx_rxmac_cos_bp_en), sizeof(qm_tx_rxmac_cos_bp_en));
	switch (eth_id) {
	case 0:
		qm_rxmac_port_bp_en.eth0 = !enable;
		qm_rxmac_cos_bp_en.eth0 = cos_en;
		qm_tx_rxmac_port_bp_en.eth0 = !enable;
		qm_tx_rxmac_cos_bp_en.eth0 = cos_en;
		break;
	case 1:
		qm_rxmac_port_bp_en.eth1 = !enable;
		qm_rxmac_cos_bp_en.eth1 = cos_en;
		qm_tx_rxmac_port_bp_en.eth1 = !enable;
		qm_tx_rxmac_cos_bp_en.eth1 = cos_en;
		break;
	case 2:
		qm_rxmac_port_bp_en.eth2 = !enable;
		qm_rxmac_cos_bp_en.eth2 = cos_en;
		qm_tx_rxmac_port_bp_en.eth2 = !enable;
		qm_tx_rxmac_cos_bp_en.eth2 = cos_en;
		break;
	case 3:
		qm_rxmac_port_bp_en.eth3 = !enable;
		qm_rxmac_cos_bp_en.eth3 = cos_en;
		qm_tx_rxmac_port_bp_en.eth3 = !enable;
		qm_tx_rxmac_cos_bp_en.eth3 = cos_en;
		break;
	default:
		return;
	}

	nbl_hw_read_regs(phy_mgt, NBL_STORE_ETH_PORT_FC(eth_id),
			 (u8 *)&store_eth_port_fc, sizeof(store_eth_port_fc));
	store_eth_port_fc.fc_en = !enable;
	nbl_hw_write_regs(phy_mgt, NBL_STORE_ETH_PORT_FC(eth_id),
			  (u8 *)&store_eth_port_fc, sizeof(store_eth_port_fc));
	for (i = 0; i < NBL_MAX_PFC_PRIORITIES; i++) {
		nbl_hw_read_regs(phy_mgt, NBL_STORE_ETH_COS_FC(eth_id * 8 + i),
				 (u8 *)&store_eth_cos_fc, sizeof(store_eth_cos_fc));
		store_eth_cos_fc.fc_en = pfc[i];
		nbl_hw_write_regs(phy_mgt, NBL_STORE_ETH_COS_FC(eth_id * 8 + i),
				  (u8 *)&store_eth_cos_fc, sizeof(store_eth_cos_fc));
	}
	nbl_hw_write_regs(phy_mgt, NBL_QM_RXMAC_PORT_BP_EN,
			  (u8 *)(&qm_rxmac_port_bp_en), sizeof(qm_rxmac_port_bp_en));
	nbl_hw_write_regs(phy_mgt, NBL_QM_RXMAC_COS_BP_EN,
			  (u8 *)(&qm_rxmac_cos_bp_en), sizeof(qm_rxmac_cos_bp_en));

	nbl_hw_write_regs(phy_mgt, NBL_QM_TX_RXMAC_PORT_BP_EN,
			  (u8 *)(&qm_tx_rxmac_port_bp_en), sizeof(qm_tx_rxmac_port_bp_en));
	nbl_hw_write_regs(phy_mgt, NBL_QM_TX_RXMAC_COS_BP_EN,
			  (u8 *)(&qm_tx_rxmac_cos_bp_en), sizeof(qm_tx_rxmac_cos_bp_en));
}

static void nbl_phy_configure_trust(void *priv, u8 eth_id, u8 trust, u8 *dscp2prio_map)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_eeth_tbl eeth_tbl = {0};
	struct nbl_store_pri_conf store_pri_conf = {0};
	struct nbl_store_tbl_pri_conf store_tbl_pri_conf = {0};
	int i;

	if (trust) { /* dscp */
		nbl_hw_read_regs(phy_mgt, NBL_EPRO_EETH_TABLE(eth_id), (u8 *)&eeth_tbl,
				 sizeof(eeth_tbl));
		eeth_tbl.pfc_mode = EETH_PFC_MODE_DSCP;
		nbl_hw_write_regs(phy_mgt, NBL_EPRO_EETH_TABLE(eth_id), (u8 *)&eeth_tbl,
				  sizeof(eeth_tbl));

		/* RX: enable pri extract, set pri extract mode to dscp */
		store_pri_conf.en = 1;
		store_pri_conf.sel = STORE_PRI_CONF_RX_PRI_MODE_DSCP;
		store_pri_conf.cpu_set = 0;
		nbl_hw_write_regs(phy_mgt, NBL_STORE_PRI_CONF(eth_id),
				  (u8 *)&store_pri_conf, sizeof(store_pri_conf));
		/* RX: set pkt_cos (dscp) -> sch_cos map table */
		for (i = 0; i < 8; i++) {
			store_tbl_pri_conf.pri0 = dscp2prio_map[i * NBL_MAX_PFC_PRIORITIES];
			store_tbl_pri_conf.pri1 = dscp2prio_map[i * NBL_MAX_PFC_PRIORITIES + 1];
			store_tbl_pri_conf.pri2 = dscp2prio_map[i * NBL_MAX_PFC_PRIORITIES + 2];
			store_tbl_pri_conf.pri3 = dscp2prio_map[i * NBL_MAX_PFC_PRIORITIES + 3];
			store_tbl_pri_conf.pri4 = dscp2prio_map[i * NBL_MAX_PFC_PRIORITIES + 4];
			store_tbl_pri_conf.pri5 = dscp2prio_map[i * NBL_MAX_PFC_PRIORITIES + 5];
			store_tbl_pri_conf.pri6 = dscp2prio_map[i * NBL_MAX_PFC_PRIORITIES + 6];
			store_tbl_pri_conf.pri7 = dscp2prio_map[i * NBL_MAX_PFC_PRIORITIES + 7];
			nbl_hw_write_regs(phy_mgt, NBL_STORE_TBL_PRI_CONF(eth_id * 8 + i),
					  (u8 *)(&store_tbl_pri_conf), sizeof(store_tbl_pri_conf));
		}
	} else {
		/* TX: enable pfc_rmk, set pfc mode to 802.1q */
		nbl_hw_read_regs(phy_mgt, NBL_EPRO_EETH_TABLE(eth_id),
				 (u8 *)&eeth_tbl, sizeof(eeth_tbl));
		eeth_tbl.pfc_mode = EETH_PFC_MODE_8021P;
		nbl_hw_write_regs(phy_mgt, NBL_EPRO_EETH_TABLE(eth_id),
				  (u8 *)&eeth_tbl, sizeof(eeth_tbl));

		/* RX: enable pri extract, set pri extract mode to 802.1q */
		store_pri_conf.en = 1;
		store_pri_conf.sel = STORE_PRI_CONF_RX_PRI_MODE_8021P;
		store_pri_conf.cpu_set = 0;
		nbl_hw_write_regs(phy_mgt, NBL_STORE_PRI_CONF(eth_id),
				  (u8 *)&store_pri_conf, sizeof(store_pri_conf));
		/* RX: set pkt_cos (vlan prio) -> sch_cos map table */
		store_tbl_pri_conf.pri0 = 0;
		store_tbl_pri_conf.pri1 = 1;
		store_tbl_pri_conf.pri2 = 2;
		store_tbl_pri_conf.pri3 = 3;
		store_tbl_pri_conf.pri4 = 4;
		store_tbl_pri_conf.pri5 = 5;
		store_tbl_pri_conf.pri6 = 6;
		store_tbl_pri_conf.pri7 = 7;
		nbl_hw_write_regs(phy_mgt, NBL_STORE_TBL_PRI_CONF(eth_id * 8),
				  (u8 *)&store_tbl_pri_conf, sizeof(store_tbl_pri_conf));
	}
}

static void nbl_phy_configure_rdma_bw(void *priv, u8 eth_id, int rdma_bw)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_shaping_dport dport = {0};
	struct nbl_shaping_dvn_dport dvn_dport = {0};
	struct nbl_shaping_rdma_dport rdma_dport = {0};
	u32 rate, rdma_rate, dvn_rate;

	nbl_hw_read_regs(phy_mgt, NBL_SHAPING_DPORT(eth_id), (u8 *)&dport, sizeof(dport));

	rate = dport.cir;
	rdma_rate = rate * rdma_bw / 100;
	dvn_rate = rate - rdma_rate;

	nbl_hw_read_regs(phy_mgt, NBL_SHAPING_DVN_DPORT(eth_id),
			 (u8 *)&dvn_dport, sizeof(dvn_dport));
	dvn_dport.cir = dvn_rate;
	dvn_dport.pir = rate;
	dvn_dport.depth = dport.depth;
	dvn_dport.cbs = dvn_dport.depth;
	dvn_dport.pbs = dvn_dport.depth;
	dvn_dport.valid = 1;

	nbl_hw_read_regs(phy_mgt, NBL_SHAPING_RDMA_DPORT(eth_id),
			 (u8 *)&rdma_dport, sizeof(rdma_dport));
	rdma_dport.cir = rdma_rate;
	rdma_dport.pir = rate;
	rdma_dport.depth = dport.depth;
	rdma_dport.cbs = rdma_dport.depth;
	rdma_dport.pbs = rdma_dport.depth;
	rdma_dport.valid = 1;

	nbl_hw_write_regs(phy_mgt, NBL_SHAPING_DVN_DPORT(eth_id),
			  (u8 *)&dvn_dport, sizeof(dvn_dport));
	nbl_hw_write_regs(phy_mgt, NBL_SHAPING_RDMA_DPORT(eth_id),
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
	struct nbl_store_eth_cos_fc store_eth_cos_fc = {0};

	if (xoff > NBL_MAX_STORE_COS_FC_TH || xon > NBL_MAX_STORE_COS_FC_TH ||
	    xoff <= 0 || xon <= 0)
		return -EINVAL;

	nbl_hw_read_regs(phy_mgt, NBL_STORE_ETH_COS_FC(eth_id * 8 + prio),
			 (u8 *)(&store_eth_cos_fc), sizeof(store_eth_cos_fc));
	store_eth_cos_fc.xoff_th = xoff;
	store_eth_cos_fc.xon_th = xon;
	nbl_hw_write_regs(phy_mgt, NBL_STORE_ETH_COS_FC(eth_id * 8 + prio),
			  (u8 *)(&store_eth_cos_fc), sizeof(store_eth_cos_fc));

	return 0;
}

static void nbl_phy_get_pfc_buffer_size(void *priv, u8 eth_id, u8 prio, int *xoff, int *xon)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_store_eth_cos_fc store_eth_cos_fc = {0};

	nbl_hw_read_regs(phy_mgt, NBL_STORE_ETH_COS_FC(eth_id * 8 + prio),
			 (u8 *)(&store_eth_cos_fc), sizeof(store_eth_cos_fc));
	*xoff = store_eth_cos_fc.xoff_th;
	*xon = store_eth_cos_fc.xon_th;
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
		nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_SHA2NET_MAP_TABLE_ADDR(func_id),
				  (u8 *)&sha2net, sizeof(sha2net));

		net2sha.vld = 1;
		nbl_hw_write_regs(phy_mgt, NBL_DSCH_VN_NET2SHA_MAP_TABLE_ADDR(func_id),
				  (u8 *)&net2sha, sizeof(net2sha));
		addr = NBL_SHAPING_NET_REG(func_id);
	}

	net_shaping.cir = rate;
	net_shaping.pir = rate;
	net_shaping.depth = max(net_shaping.cir * 2, NBL_DRACO_NET_BUCKET_DEPTH);
	net_shaping.cbs = net_shaping.depth;
	net_shaping.pbs = net_shaping.depth;
	net_shaping.valid = 1;

	nbl_hw_write_regs(phy_mgt, addr, (u8 *)&net_shaping, sizeof(net_shaping));
}

static int nbl_phy_init_fem(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct device *dev = NBL_PHY_MGT_TO_DEV(phy_mgt);

	dev_info(dev, "nbl phy_init_fem\n");

	return 0;
}

static int nbl_send_fem_cmd(struct nbl_phy_mgt *phy_mgt, u8 pf_id,
			    u8 *cmd_head, u8 *cmd_param, u8 *resp_head, u8 *resp_data)
{
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct nbl_fem_pf_cmd_req cmd_req = {0};
	u32 times = 10;

	if (phy_mgt->hw_status)
		return -EIO;

	nbl_hw_write_regs(phy_mgt, NBL_FEM_PF_CMD_HEAD(pf_id),
			  cmd_head, NBL_FEM_PF_CMD_HEAD_TBL_WIDTH);
	nbl_hw_write_regs(phy_mgt, NBL_FEM_PF_CMD_PARAM(pf_id),
			  cmd_param, NBL_FEM_PF_CMD_PARAM_TBL_WIDTH);
	cmd_req.en = 1;
	nbl_hw_write_regs(phy_mgt, NBL_FEM_PF_CMD_REQ(pf_id), (u8 *)&cmd_req, sizeof(cmd_req));

	nbl_debug(common, NBL_DEBUG_FLOW, "Send fec cmd, req_head = %08x-%08x, req_param = %08x-%08x-%08x-%08x|%08x-%08x-%08x-%08x|%08x-%08x-%08x-%08x|%08x-%08x-%08x-%08x\n",
		  ((u32 *)cmd_head)[0], ((u32 *)cmd_head)[1],
		  ((u32 *)cmd_param)[0], ((u32 *)cmd_param)[1], ((u32 *)cmd_param)[2],
		  ((u32 *)cmd_param)[3], ((u32 *)cmd_param)[4], ((u32 *)cmd_param)[5],
		  ((u32 *)cmd_param)[6], ((u32 *)cmd_param)[7], ((u32 *)cmd_param)[8],
		  ((u32 *)cmd_param)[9], ((u32 *)cmd_param)[10], ((u32 *)cmd_param)[11],
		  ((u32 *)cmd_param)[12], ((u32 *)cmd_param)[13], ((u32 *)cmd_param)[14],
		  ((u32 *)cmd_param)[15]);

	times = 50;
	do {
		nbl_hw_read_regs(phy_mgt, NBL_FEM_PF_CMD_REQ(pf_id),
				 (u8 *)&cmd_req, sizeof(cmd_req));
		if (cmd_req.en) {
			times--;
			usleep_range(100, 200);
		} else {
			nbl_hw_read_regs(phy_mgt, NBL_FEM_PF_CMD_HEAD(pf_id),
					 resp_head, NBL_FEM_PF_CMD_HEAD_TBL_WIDTH);
			nbl_hw_read_regs(phy_mgt, NBL_FEM_PF_CMD_PARAM(pf_id),
					 resp_data, NBL_FEM_PF_CMD_PARAM_TBL_WIDTH);
			break;
		}
	} while (times);

	if (!times) {
		nbl_err(common, NBL_DEBUG_FLOW, "Send fem cmd failed, timeout");
		return -EIO;
	}

	return 0;
}

static int nbl_phy_alloc_kt(void *priv, u8 pf_id, u8 *req_head, u8 *req_param,
			    u8 *resp_head, u8 *resp_data)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	if (nbl_send_fem_cmd(phy_mgt, pf_id, req_head, req_param, resp_head, resp_data))
		return -EIO;

	return 0;
}

static int nbl_phy_free_kt(void *priv, u8 pf_id, u8 *req_head, u8 *req_param,
			   u8 *resp_head, u8 *resp_data)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	if (nbl_send_fem_cmd(phy_mgt, pf_id, req_head, req_param, resp_head, resp_data))
		return -EIO;

	return 0;
}

static int nbl_phy_set_kt(void *priv, u8 *key, u32 key_index, u8 key_type)
{
	return 0;
}

static int nbl_phy_set_ht(void *priv, u16 hash, u16 hash_other, u8 ht_table,
			  u8 bucket, u32 key_index, u8 valid)
{
	return 0;
}

static int nbl_phy_add_kt(void *priv, u8 pf_id, u8 *req_head, u8 *req_param,
			  u8 *resp_head, u8 *resp_data)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	if (nbl_send_fem_cmd(phy_mgt, pf_id, req_head, req_param, resp_head, resp_data))
		return -EIO;

	/* todo */
	/* nbl_check_kt_data(phy_mgt, &kt_ctrl, common); */

	return 0;
}

static int nbl_phy_del_ht_oft(void *priv, u8 pf_id, u8 *req_head, u8 *req_param,
			      u8 *resp_head, u8 *resp_data)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	if (nbl_send_fem_cmd(phy_mgt, pf_id, req_head, req_param, resp_head, resp_data))
		return -EIO;

	return 0;
}

static int nbl_phy_lookup_key(void *priv, u8 pf_id, u8 *req_head, u8 *req_param,
			      u8 *resp_head, u8 *resp_data)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	if (nbl_send_fem_cmd(phy_mgt, pf_id, req_head, req_param, resp_head, resp_data))
		return -EIO;

	return 0;
}

static int nbl_phy_read_fem_tbl(void *priv, u8 pf_id, u8 *req_head, u8 *req_param,
				u8 *resp_head, u8 *resp_data)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	if (nbl_send_fem_cmd(phy_mgt, pf_id, req_head, req_param, resp_head, resp_data))
		return -EIO;

	return 0;
}

static int nbl_phy_write_fem_tbl(void *priv, u8 pf_id, u8 *req_head, u8 *req_param,
				 u8 *resp_head, u8 *resp_data)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	if (nbl_send_fem_cmd(phy_mgt, pf_id, req_head, req_param, resp_head, resp_data))
		return -EIO;

	return 0;
}

static int nbl_phy_init_mcc(void *priv, u16 mcc_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_mcc_group_table mcc_group_table = {0};

	mcc_group_table.vld = 1;

	nbl_hw_write_regs(phy_mgt, NBL_MCC_GROUP_TABLE(mcc_id),
			  (u8 *)&mcc_group_table, sizeof(mcc_group_table));

	return 0;
}

static void nbl_phy_clear_mcc(void *priv, u16 mcc_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_mcc_group_table mcc_group_table = {0};

	nbl_hw_write_regs(phy_mgt, NBL_MCC_GROUP_TABLE(mcc_id),
			  (u8 *)&mcc_group_table, sizeof(mcc_group_table));
}

static int nbl_phy_add_mcc(void *priv, u16 mcc_id, u16 prev_mcc_id, u16 next_mcc_id,
			   u16 action, u8 eth_id, u16 vsi_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_mcc_group_table mcc_group_table = {0};

	nbl_hw_read_regs(phy_mgt, NBL_MCC_GROUP_TABLE(mcc_id),
			 (u8 *)&mcc_group_table, sizeof(mcc_group_table));
	if (eth_id != U8_MAX)
		mcc_group_table.leaf_dport_eth |= BIT(eth_id);
	if (vsi_id != U16_MAX) {
		if (vsi_id >= 0 && vsi_id <= 56)
			mcc_group_table.leaf_dport_vsi_0_56 |= BIT(vsi_id);
		else if (vsi_id >= 57 && vsi_id <= 120)
			mcc_group_table.leaf_dport_vsi_57_120 |= BIT(vsi_id - 57);
		else if (vsi_id >= 121 && vsi_id <= 184)
			mcc_group_table.leaf_dport_vsi_121_184 |= BIT(vsi_id - 121);
		else if (vsi_id >= 185 && vsi_id <= 248)
			mcc_group_table.leaf_dport_vsi_185_248 |= BIT(vsi_id - 185);
		else if (vsi_id >= 249 && vsi_id <= 277)
			mcc_group_table.leaf_dport_vsi_249_277 |= BIT(vsi_id - 249);
	}
	nbl_hw_write_regs(phy_mgt, NBL_MCC_GROUP_TABLE(mcc_id),
			  (u8 *)&mcc_group_table, sizeof(mcc_group_table));

	return 0;
}

static void nbl_phy_del_mcc(void *priv, u16 mcc_id, u16 prev_mcc_id, u16 next_mcc_id,
			    u8 eth_id, u16 vsi_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_mcc_group_table mcc_group_table = {0};

	nbl_hw_read_regs(phy_mgt, NBL_MCC_GROUP_TABLE(mcc_id),
			 (u8 *)&mcc_group_table, sizeof(mcc_group_table));
	if (eth_id != U8_MAX)
		mcc_group_table.leaf_dport_eth &= ~BIT(eth_id);
	if (vsi_id != U16_MAX) {
		if (vsi_id >= 0 && vsi_id <= 56)
			mcc_group_table.leaf_dport_vsi_0_56 &= ~BIT(vsi_id);
		else if (vsi_id >= 57 && vsi_id <= 120)
			mcc_group_table.leaf_dport_vsi_57_120 &= ~BIT(vsi_id - 57);
		else if (vsi_id >= 121 && vsi_id <= 184)
			mcc_group_table.leaf_dport_vsi_121_184 &= ~BIT(vsi_id - 121);
		else if (vsi_id >= 185 && vsi_id <= 248)
			mcc_group_table.leaf_dport_vsi_185_248 &= ~BIT(vsi_id - 185);
		else if (vsi_id >= 249 && vsi_id <= 277)
			mcc_group_table.leaf_dport_vsi_249_277 &= ~BIT(vsi_id - 249);
	}
	nbl_hw_write_regs(phy_mgt, NBL_MCC_GROUP_TABLE(mcc_id),
			  (u8 *)&mcc_group_table, sizeof(mcc_group_table));
}

static int nbl_phy_cfg_lag_mcc(void *priv, u16 mcc_id, u16 action)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_mcc_group_table mcc_group_table = {0};
	union nbl_mcc_lag_param param = {{0}};

	param.data = action;

	nbl_hw_read_regs(phy_mgt, NBL_MCC_GROUP_TABLE(mcc_id),
			 (u8 *)&mcc_group_table, sizeof(mcc_group_table));

	if (param.info.enable) {
		mcc_group_table.leaf_dport_lag = 1 << param.info.id;
		mcc_group_table.leaf_dport_eth = 0;
	} else {
		mcc_group_table.leaf_dport_lag = 0;
		mcc_group_table.leaf_dport_eth = 1 << param.info.id;
	}

	nbl_hw_write_regs(phy_mgt, NBL_MCC_GROUP_TABLE(mcc_id),
			  (u8 *)&mcc_group_table, sizeof(mcc_group_table));

	return 0;
}

static int nbl_phy_cfg_rx_vlan_parse(void *priv, u16 vsi_id, u16 enable, u16 rx_vlan_mode)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_evsi_tbl evsi_tbl = {0};
	struct nbl_ped_udf_ext ped_udf_ext = {0};
	struct nbl_ped_tbl_udf_ext ped_tbl_udf_ext = {0};
	u16 action_mode = rx_vlan_mode - 1;

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_EVSI_TABLE(vsi_id),
			 (u8 *)&evsi_tbl, sizeof(evsi_tbl));
	nbl_hw_read_regs(phy_mgt, NBL_PED_TBL_UDF_EXT(vsi_id),
			 (u8 *)&ped_tbl_udf_ext, sizeof(ped_tbl_udf_ext));

	if (enable) {
		evsi_tbl.act_mode = action_mode;

		ped_tbl_udf_ext.en1 = 1;
		ped_tbl_udf_ext.sel1 = 1;
	} else {
		evsi_tbl.act_mode = EVSI_ACT_MODE_BASE_ABAD;
		ped_tbl_udf_ext.en1 = 0;
		ped_tbl_udf_ext.sel1 = 0;
	}

	ped_udf_ext.st = 40;
	ped_udf_ext.len = 4;

	nbl_hw_write_regs(phy_mgt, NBL_EPRO_EVSI_TABLE(vsi_id),
			  (u8 *)&evsi_tbl, sizeof(evsi_tbl));
	nbl_hw_write_regs(phy_mgt, NBL_PED_UDF_EXT_TABLE(1),
			  (u8 *)&ped_udf_ext, sizeof(ped_udf_ext));
	nbl_hw_write_regs(phy_mgt, NBL_PED_TBL_UDF_EXT(vsi_id),
			  (u8 *)&ped_tbl_udf_ext, sizeof(ped_tbl_udf_ext));

	return 0;
}

static int nbl_phy_cfg_rss_hash(void *priv, u16 vsi_id, u16 rss_hash_mode)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_mhash_upcall_tbl mhash_upcall_tbl = {0};
	struct nbl_ped_udf_ext ped_udf_ext = {0};
	struct nbl_ped_tbl_udf_ext ped_tbl_udf_ext = {0};

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_MHASH_UPCALL_TABLE(vsi_id),
			 (u8 *)&mhash_upcall_tbl, sizeof(mhash_upcall_tbl));
	nbl_hw_read_regs(phy_mgt, NBL_PED_TBL_UDF_EXT(vsi_id),
			 (u8 *)&ped_tbl_udf_ext, sizeof(ped_tbl_udf_ext));

	if (rss_hash_mode - 1) {
		mhash_upcall_tbl.mod = NBL_EPRO_MASH_UPCALL_RSS;
		mhash_upcall_tbl.en = NBL_EPRO_MASH_UPCALL_ENABLE;
	} else {
		mhash_upcall_tbl.mod = NBL_EPRO_MASH_UPCALL_RSS;
		mhash_upcall_tbl.en = NBL_EPRO_MASH_UPCALL_DISABLE;
	}

	ped_tbl_udf_ext.en0 = 1;
	ped_tbl_udf_ext.sel0 = 0;

	ped_udf_ext.st = 32;
	ped_udf_ext.len = 8;

	nbl_hw_write_regs(phy_mgt, NBL_EPRO_MHASH_UPCALL_TABLE(vsi_id),
			  (u8 *)&mhash_upcall_tbl, sizeof(mhash_upcall_tbl));
	nbl_hw_write_regs(phy_mgt, NBL_PED_UDF_EXT_TABLE(0),
			  (u8 *)&ped_udf_ext, sizeof(ped_udf_ext));
	nbl_hw_write_regs(phy_mgt, NBL_PED_TBL_UDF_EXT(vsi_id),
			  (u8 *)&ped_tbl_udf_ext, sizeof(ped_tbl_udf_ext));

	return 0;
}

static int nbl_phy_cfg_lag_hash_algorithm(void *priv, u16 eth_id, u16 lag_id,
					  enum netdev_lag_hash hash_type)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_lag_map_cfg lag_map_cfg = {0};
	u8 hw_hash_type = NBL_EPRO_LAG_ALG_LINUX_L2_HASH;

	switch (hash_type) {
	case NETDEV_LAG_HASH_L23:
	case NETDEV_LAG_HASH_E23:
		hw_hash_type = NBL_EPRO_LAG_ALG_LINUX_L23_HASH;
		break;
	case NETDEV_LAG_HASH_L34:
	case NETDEV_LAG_HASH_E34:
		hw_hash_type = NBL_EPRO_LAG_ALG_LINUX_L34_HASH;
		break;
	default:
		break;
	}

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_LAG_MAP_CFG(lag_id),
			 (u8 *)&lag_map_cfg, sizeof(lag_map_cfg));
	lag_map_cfg.alg = hw_hash_type;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_LAG_MAP_CFG(lag_id),
			  (u8 *)&lag_map_cfg, sizeof(lag_map_cfg));

	nbl_info(NBL_PHY_MGT_TO_COMMON(phy_mgt), NBL_DEBUG_PHY,
		 "Nbl phy set lag hash type %d", hw_hash_type);
	return 0;
}

static int nbl_phy_cfg_lag_member_list(void *priv, struct nbl_lag_member_list_param *param)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_lag_map_cfg lag_map_cfg = {0};
	struct nbl_epro_eeth_tbl eeth_tbl = {0};

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_LAG_MAP_CFG(param->lag_id),
			 (u8 *)&lag_map_cfg, sizeof(lag_map_cfg));
	if (param->lag_num) {
		lag_map_cfg.dft_alg = NBL_EPRO_LAG_ALG_LINUX_L2_HASH;
		lag_map_cfg.vld = 1;
	} else {
		lag_map_cfg.vld = 0;
	}
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_LAG_MAP_CFG(param->lag_id),
			  (u8 *)&lag_map_cfg, sizeof(lag_map_cfg));

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_EETH_TABLE(NBL_EPRO_EETH_LAG_OFFSET + param->lag_id),
			 (u8 *)&eeth_tbl, sizeof(eeth_tbl));
	if (param->lag_num)
		eeth_tbl.vld = 1;
	else
		eeth_tbl.vld = 0;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_EETH_TABLE(NBL_EPRO_EETH_LAG_OFFSET + param->lag_id),
			  (u8 *)&eeth_tbl, sizeof(eeth_tbl));

	return 0;
}

static int nbl_phy_cfg_lag_member_fwd(void *priv, u16 eth_id, u16 lag_id, u8 fwd)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_epro_lag_map_cfg lag_map_cfg = {0};
	struct nbl_ipro_ieth_tbl ieth_tbl = {0};
	u8 lag_btm = 0, lag_btm_new = 0;

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_LAG_MAP_CFG(lag_id),
			 (u8 *)&lag_map_cfg, sizeof(lag_map_cfg));
	lag_btm = lag_map_cfg.eth_btm;
	lag_btm_new = fwd ? lag_btm | (1 << eth_id) : lag_btm & ~(1 << eth_id);

	lag_map_cfg.eth_btm = lag_btm_new;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_LAG_MAP_CFG(lag_id),
			  (u8 *)&lag_map_cfg, sizeof(lag_map_cfg));

	nbl_hw_read_regs(phy_mgt, NBL_IPRO_IETH_TABLE(eth_id), (u8 *)&ieth_tbl, sizeof(ieth_tbl));

	ieth_tbl.lag_id = fwd ? lag_id : 0;
	ieth_tbl.lag_vld = fwd;

	nbl_hw_write_regs(phy_mgt, NBL_IPRO_IETH_TABLE(eth_id),
			  (u8 *)&ieth_tbl, sizeof(ieth_tbl));

	return 0;
}

static bool nbl_phy_get_lag_fwd(void *priv, u16 eth_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_ipro_ieth_tbl ieth_tbl = {0};

	nbl_hw_read_regs(phy_mgt, NBL_IPRO_IETH_TABLE(eth_id),
			 (u8 *)&ieth_tbl, sizeof(ieth_tbl));

	nbl_debug(phy_mgt->common, NBL_DEBUG_PHY, "eth_id: %u, lag_vld: %u",
		  eth_id, ieth_tbl.lag_vld);
	return ieth_tbl.lag_vld;
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

	if (speed == NBL_FW_PORT_SPEED_10G) {
		rate = NBL_SHAPING_DPORT_10G_RATE * 2;
		dvn_rate = NBL_SHAPING_DPORT_10G_RATE;
		rdma_rate = NBL_SHAPING_DPORT_10G_RATE;
	} else {
		rate = NBL_SHAPING_DPORT_25G_RATE * 2;
		dvn_rate = NBL_SHAPING_DPORT_25G_RATE;
		rdma_rate = NBL_SHAPING_DPORT_25G_RATE;
	}

	dport.cir = rate;
	dport.pir = rate;
	dport.depth = max(dport.cir * 2, NBL_DRACO_NET_BUCKET_DEPTH);
	dport.cbs = dport.depth;
	dport.pbs = dport.depth;
	dport.valid = 1;
	nbl_hw_write_regs(phy_mgt, NBL_SHAPING_DPORT_REG(eth_id), (u8 *)&dport, sizeof(dport));

	dvn_dport.cir = dvn_rate;
	dvn_dport.pir = dvn_rate;
	dvn_dport.depth = max(dvn_dport.cir * 2, NBL_DRACO_NET_BUCKET_DEPTH);
	dvn_dport.cbs = dvn_dport.depth;
	dvn_dport.pbs = dvn_dport.depth;
	dvn_dport.valid = 1;
	nbl_hw_write_regs(phy_mgt, NBL_SHAPING_DVN_DPORT_REG(eth_id),
			  (u8 *)&dvn_dport, sizeof(dvn_dport));

	rdma_dport.cir = rdma_rate;
	rdma_dport.pir = rdma_rate;
	rdma_dport.depth = max(rdma_dport.cir * 2, NBL_DRACO_NET_BUCKET_DEPTH);
	rdma_dport.cbs = rdma_dport.depth;
	rdma_dport.pbs = rdma_dport.depth;
	rdma_dport.valid = 1;
	nbl_hw_write_regs(phy_mgt, NBL_SHAPING_RDMA_DPORT_REG(eth_id),
			  (u8 *)&rdma_dport, sizeof(rdma_dport));

	return 0;
}

static int nbl_phy_set_mtu(void *priv, u16 vsi_id, u16 mtu)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_ipro_ivsi_tbl ivsi = {0};
	struct nbl_epro_evsi_tbl evsi = {0};

	nbl_hw_read_regs(phy_mgt, NBL_IPRO_IVSI_TABLE(vsi_id),
			 (u8 *)&ivsi, sizeof(ivsi));
	ivsi.mtu = mtu;
	nbl_hw_write_regs(phy_mgt, NBL_IPRO_IVSI_TABLE(vsi_id),
			  (u8 *)&ivsi, sizeof(ivsi));

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_EVSI_TABLE(vsi_id),
			 (u8 *)&evsi, sizeof(evsi));
	evsi.mtu = mtu;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_EVSI_TABLE(vsi_id),
			  (u8 *)&evsi, sizeof(evsi));

	return 0;
}

static void nbl_phy_get_rx_prio_stats(void *priv, u16 eth_id, u16 prio,
				      struct nbl_prio_stats *prio_stats)
{
	struct nbl_store_rcv_cos_pkt rcv_cos_pkt = {0};
	struct nbl_store_rcv_cos_byte rcv_cos_byte = {0};
	struct nbl_store_rcv_drop_pkt rcv_drop_pkt = {0};
	struct nbl_store_rcv_trun_pkt rcv_trun_pkt = {0};

	nbl_hw_read_regs(priv, NBL_STORE_RCV_COS_PKT(eth_id * 8 + prio),
			 (u8 *)&rcv_cos_pkt, sizeof(rcv_cos_pkt));
	prio_stats->packets = rcv_cos_pkt.cnt;

	nbl_hw_read_regs(priv, NBL_STORE_RCV_COS_BYTE(eth_id * 8 + prio),
			 (u8 *)&rcv_cos_byte, sizeof(rcv_cos_byte));
	prio_stats->bytes = rcv_cos_byte.cnt & 0xffffffffffff;

	nbl_hw_read_regs(priv, NBL_STORE_RCV_COS_DROP_PKT(eth_id * 8 + prio),
			 (u8 *)&rcv_drop_pkt, sizeof(rcv_drop_pkt));
	nbl_hw_read_regs(priv, NBL_STORE_RCV_COS_TRUN_PKT(eth_id * 8 + prio),
			 (u8 *)&rcv_trun_pkt, sizeof(rcv_trun_pkt));
	prio_stats->drop_packets = rcv_drop_pkt.cnt + rcv_trun_pkt.cnt;
}

static void nbl_phy_get_tx_prio_stats(void *priv, u16 eth_id, u16 prio,
				      struct nbl_prio_stats *prio_stats)
{
	struct nbl_qm_que_pkt_cnt_tbl que_pkt_cnt = {0};
	struct nbl_qm_outque_que_pkt_byte_cnt que_pkt_byte = {0};

	nbl_hw_read_regs(priv, NBL_QM_QUE_PKT_CNT_TBL(144 + eth_id * 8 + prio),
			 (u8 *)&que_pkt_cnt, sizeof(que_pkt_cnt));
	prio_stats->packets = que_pkt_cnt.cnt;

	nbl_hw_read_regs(priv, NBL_QM_QUE_PKT_CNT_TBL(72 + eth_id * 8 + prio),
			 (u8 *)&que_pkt_cnt, sizeof(que_pkt_cnt));
	prio_stats->drop_packets = que_pkt_cnt.cnt;

	nbl_hw_read_regs(priv, NBL_QM_OUTQUE_QUE_PKT_BYTE_CNT(eth_id * 8 + prio),
			 (u8 *)&que_pkt_byte, sizeof(que_pkt_byte));
	prio_stats->bytes = que_pkt_byte.cnt & 0xffffffffffff;
}

static int nbl_phy_get_dstat_vsi_stat(void *priv, u16 vsi_id, u64 *fwd_pkt, u64 *fwd_byte)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_qm_stat_s_vsi_tbl qm_stat_s_vsi = {0};

	nbl_hw_read_regs(phy_mgt, NBL_QM_STAT_S_VSI(vsi_id),
			 (u8 *)&qm_stat_s_vsi, sizeof(qm_stat_s_vsi));

	*fwd_pkt = qm_stat_s_vsi.pkt_cnt_low + ((u64)(qm_stat_s_vsi.pkt_cnt_high) << 32);
	*fwd_byte = qm_stat_s_vsi.byte_cnt_low + ((u64)(qm_stat_s_vsi.byte_cnt_high) << 32);

	return 0;
}

static int nbl_phy_get_ustat_vsi_stat(void *priv, u16 vsi_id, u64 *fwd_pkt, u64 *fwd_byte)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_qm_stat_d_vsi_tbl qm_stat_d_vsi = {0};

	nbl_hw_read_regs(phy_mgt, NBL_QM_STAT_D_VSI(vsi_id),
			 (u8 *)&qm_stat_d_vsi, sizeof(qm_stat_d_vsi));

	*fwd_pkt = qm_stat_d_vsi.pkt_cnt_low + ((u64)(qm_stat_d_vsi.pkt_cnt_high) << 32);
	*fwd_byte = qm_stat_d_vsi.byte_cnt_low + ((u64)(qm_stat_d_vsi.byte_cnt_high) << 32);

	return 0;
}

static int nbl_phy_set_ucar(void *priv, u16 vsi_id, u64 total_rx_rate, u64 burst,
			    u8 vld)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union qm_car_vsi_tbl_u car_vsi;

	memset(&car_vsi, 0, sizeof(union qm_car_vsi_tbl_u));
	nbl_hw_read_regs(phy_mgt, NBL_QM_CAR_VSI_TBL_REG(vsi_id),
			 (u8 *)&car_vsi, sizeof(car_vsi));
	if (vld) {
		car_vsi.info.valid = 1;
		car_vsi.info.cir = total_rx_rate;
		car_vsi.info.pir = total_rx_rate;
		if (burst)
			car_vsi.info.depth = burst;
		else
			car_vsi.info.depth = NBL_UCAR_MAX_BUCKET_DEPTH;
		car_vsi.info.cbs = car_vsi.info.depth;
		car_vsi.info.pbs = car_vsi.info.depth;
	} else {
		car_vsi.info.valid = 0;
	}
	nbl_hw_write_regs(phy_mgt, NBL_QM_CAR_VSI_TBL_REG(vsi_id),
			  (u8 *)&car_vsi, sizeof(car_vsi));

	return 0;
}

static int nbl_phy_cfg_phy_flow(void *priv, u16 vsi_id, u16 count, u8 eth_id,
				bool status, u16 rss_key_range_oft)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_ipro_ieth_tbl ieth_tbl = {0};
	struct nbl_ipro_ivsi_tbl ivsi_tbl = {0};
	struct nbl_epro_eeth_tbl eeth_tbl = {0};
	int i = 0;

	nbl_hw_read_regs(phy_mgt, NBL_IPRO_IETH_TABLE(eth_id), (u8 *)&ieth_tbl, sizeof(ieth_tbl));
	if (status) {
		ieth_tbl.phy_flow = 0;
		ieth_tbl.sw_id = eth_id;
		ieth_tbl.t_s3 = 0;
		ieth_tbl.t_lx_sel = 0;
		ieth_tbl.decap_en = 1;
	} else {
		ieth_tbl.phy_flow = 1;
		ieth_tbl.sw_id = eth_id;
		ieth_tbl.t_s3 = 4;
		ieth_tbl.t_lx_sel = IETH_USE_T_LX_OFT;
		ieth_tbl.decap_en = 0;
	}
	nbl_hw_write_regs(phy_mgt, NBL_IPRO_IETH_TABLE(eth_id), (u8 *)&ieth_tbl, sizeof(ieth_tbl));

	for (i = vsi_id; i < vsi_id + count; i++) {
		if (status) {
			nbl_hw_read_regs(phy_mgt, NBL_IPRO_IVSI_TABLE(i),
					 (u8 *)&ivsi_tbl, sizeof(ivsi_tbl));
			ivsi_tbl.phy_flow = 0;
			nbl_hw_write_regs(phy_mgt, NBL_IPRO_IVSI_TABLE(i),
					  (u8 *)&ivsi_tbl, sizeof(ivsi_tbl));
			nbl_phy_cfg_ivsi_phy_flow(phy_mgt, i, 1, eth_id);
			nbl_phy_init_epro_vpt_tbl(phy_mgt, i, BRIDGE_MODE_VEB, 0,
						  rss_key_range_oft);
			nbl_phy_cfg_vlan_type(phy_mgt, i, NBL_ETHDEV_VIRTIO_REP);
		} else {
			nbl_phy_cfg_ipro_dn_sport_tbl(priv, i, eth_id, BRIDGE_MODE_VEB, true);
		}
	}

	if (status) {
		if (ieth_tbl.lag_vld) {
			struct nbl_epro_lag_map_cfg lag_map_cfg = {0};
			unsigned long eth_btm;
			u8 member_eth_id;

			nbl_hw_read_regs(phy_mgt, NBL_EPRO_LAG_MAP_CFG(ieth_tbl.lag_id),
					 (u8 *)&lag_map_cfg, sizeof(lag_map_cfg));
			eth_btm = lag_map_cfg.eth_btm;
			for_each_set_bit(member_eth_id, &eth_btm, NBL_MAX_ETHERNET)
				nbl_phy_cfg_vlan_type(phy_mgt, member_eth_id, NBL_ETHDEV_ETH_REP);
		} else {
			nbl_phy_cfg_vlan_type(phy_mgt, eth_id, NBL_ETHDEV_ETH_REP);
		}
	}

	nbl_hw_read_regs(phy_mgt, NBL_EPRO_EETH_TABLE(eth_id), (u8 *)&eeth_tbl, sizeof(eeth_tbl));

	/* when not in uplink mode, eeth not be configured by dpdk, so set eeth_tbl.vld=1 always */
	eeth_tbl.vld = 1;
	nbl_hw_write_regs(phy_mgt, NBL_EPRO_EETH_TABLE(eth_id), (u8 *)&eeth_tbl, sizeof(eeth_tbl));

	return 0;
}

/* lldp_or_lacp for offload: 0 for LLDP, 1 for LACP; note only LACP would be disabled dynamically */
static void nbl_phy_cfg_lacp_lldp(void *priv, bool lldp_or_lacp, bool enable, u16 vsi_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	union ipro_ptype_assd_u assd;
	union ipro_ptype_tcam_u tcam;
	union nbl_base_action_bits ab;
	union nbl_draco_sport_simple_u sport = {{0}};
	union nbl_draco_sport_simple_u sport_mask = {{0}};
	union nbl_draco_ptype_u ptype = {{0}};
	union nbl_draco_ptype_u ptype_mask = {{0}};
	union nbl_base_action_data *act = (union nbl_base_action_data *)&assd.info.base_ad_arr;
	int start_id = (lldp_or_lacp) ? NBL_PTYPE_LACP_START_ID : NBL_PTYPE_LLDP_START_ID;
	int pf_id = common->mgt_pf;

	memset(&tcam, 0, sizeof(union ipro_ptype_tcam_u));
	memset(&assd, 0, sizeof(union ipro_ptype_assd_u));
	/* disable upcall, set tcam entry to 0 */
	if (!enable) {
		nbl_hw_write_regs(phy_mgt, NBL_IPRO_PTYPE_TCAM_REG(start_id + pf_id),
				  (u8 *)&tcam.data, NBL_IPRO_PTYPE_TCAM_DWLEN * NBL_BYTES_IN_REG);
		return;
	}

	/* upcall physical LLDP/LACP packets to PF of that switch domain */
	ab.data = 0;
	ab.baseab.SET_DEST = 1;
	sport_mask.data = 0x3F;
	ptype_mask.data = 0xFFFF;
	sport.rx.phy_flow = 0;  /* rules only apply to offload-network */
	sport.rx.sw_id = pf_id;
	if (common->eth_mode == NBL_TWO_ETHERNET_PORT)
		sport.rx.sw_id = 2 * pf_id;
	sport.rx.dir = NBL_DRACO_SPORT_DIR_RX;
	sport_mask.rx.phy_flow = 0;
	sport_mask.rx.sw_id = 0;
	sport_mask.rx.dir = 0;
	ptype.nontnl.tnl = 0;
	ptype.nontnl.nxt_proto = (lldp_or_lacp) ? 0b10 : 0b11;
	ptype.nontnl.l3 = 2;
	ptype_mask.nontnl.tnl = 0;
	ptype_mask.nontnl.nxt_proto = 0;
	ptype_mask.nontnl.l3 = 0;

	tcam.info.data = (sport.data << 16) + ptype.data;
	tcam.info.mask = (sport_mask.data << 16) + ptype_mask.data;
	tcam.info.valid_bit = 1;
	assd.info.vld = 1;
	assd.info.base_ab = ab.data;
	act->dport.up.dir = 0;
	act->dport.up.DQ_V = 0;
	act->dport.up.next_stg = NBL_NEXT_STAGE_EPRO;
	act->dport.up.vsi_id = vsi_id;
	nbl_hw_write_regs(phy_mgt, NBL_IPRO_PTYPE_ASSD_REG(start_id + pf_id), (u8 *)&assd.data,
			  NBL_IPRO_PTYPE_ASSD_DWLEN * NBL_BYTES_IN_REG);
	nbl_hw_write_regs(phy_mgt, NBL_IPRO_PTYPE_TCAM_REG(start_id + pf_id), (u8 *)&tcam.data,
			  NBL_IPRO_PTYPE_TCAM_DWLEN * NBL_BYTES_IN_REG);
}

static void nbl_phy_cfg_ktls_tx_keymat(void *priv, u32 index, u8 mode,
				       u8 *salt, u8 *key, u8 key_len)
{
}

static void nbl_phy_cfg_ktls_rx_keymat(void *priv, u32 index, u8 mode,
				       u8 *salt, u8 *key, u8 key_len)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_ktls_keymat keymat = {{0}};
	u8 salt_len = 4;
	int i;

	keymat.ena = 1;
	keymat.mode = mode;

	for (i = 0; i < salt_len; i++)
		keymat.salt[salt_len - 1 - i] = salt[i];

	for (i = 0; i < key_len; i++)
		keymat.key[key_len - 1 - i] = key[i];

	nbl_hw_write_regs(phy_mgt, NBL_UTLS_KEY_SALT(index), (u8 *)&keymat, sizeof(keymat));
}

static void nbl_phy_cfg_ktls_rx_record(void *priv, u32 index, u32 tcp_sn, u64 rec_num, bool init)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	union nbl_ktls_sync_trig sync_trig = {0};
	u16 eth_id = NBL_COMMON_TO_ETH_ID(common);

	if (init) {
		sync_trig.trig = 0;
		sync_trig.init_sync = 0;
	} else {
		sync_trig.trig = 0;
		sync_trig.init_sync = 1;
	}
	nbl_hw_wr32(phy_mgt, NBL_UTLS_SYNC_TRIG(eth_id), sync_trig.data);

	nbl_hw_wr32(phy_mgt, NBL_UTLS_SYNC_SID(eth_id), index);
	nbl_hw_wr32(phy_mgt, NBL_UTLS_SYNC_TCP_SN(eth_id), tcp_sn);
	nbl_hw_wr32(phy_mgt, NBL_UTLS_SYNC_REC_NUMH(eth_id), rec_num >> 32);
	nbl_hw_wr32(phy_mgt, NBL_UTLS_SYNC_REC_NUML(eth_id), rec_num);

	if (init) {
		sync_trig.trig = 1;
		sync_trig.init_sync = 0;
	} else {
		sync_trig.trig = 1;
		sync_trig.init_sync = 1;
	}
	nbl_hw_wr32(phy_mgt, NBL_UTLS_SYNC_TRIG(eth_id), sync_trig.data);
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
	return 0;
}

static u32 nbl_phy_reset_dipsec_status(void *priv)
{
	return 0;
}

static u32 nbl_phy_read_dipsec_lft_info(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	return nbl_hw_rd32(phy_mgt, NBL_DPRBAC_LIFETIME_INFO(0));
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

static void nbl_phy_cfg_uipsec_em_cmd(void *priv, u8 *data)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	u16 pf_id = NBL_COMMON_TO_MGT_PF(common);

	nbl_hw_write_regs(phy_mgt, NBL_UPRBAC_CMD_HEAD(pf_id), data, 32);
	nbl_hw_wr32(phy_mgt, NBL_UPRBAC_CMD_REQ(pf_id), 1);

	while (nbl_hw_rd32(phy_mgt, NBL_UPRBAC_CMD_REQ(pf_id)))
		usleep_range(100, 200);

	nbl_hw_read_regs(phy_mgt, NBL_UPRBAC_CMD_HEAD(pf_id), data, 32);
}

static u32 nbl_phy_read_uipsec_status(void *priv)
{
	return 0;
}

static u32 nbl_phy_reset_uipsec_status(void *priv)
{
	return 0;
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

	return nbl_hw_rd32(phy_mgt, NBL_UPRBAC_LIFETIME_INFO(0));
}

static void nbl_phy_init_dprbac(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union nbl_dprbac_dbg_cnt_en dbg_cnt_en = {.data = 0};
	struct nbl_dprbac_drop dprbac_drop = {0};

	dbg_cnt_en.total = 1;
	dbg_cnt_en.in_right_bypass = 1;
	dbg_cnt_en.in_drop_bypass = 1;
	dbg_cnt_en.in_drop_prbac = 1;
	dbg_cnt_en.out_drop_prbac = 1;
	dbg_cnt_en.out_right_prbac = 1;
	nbl_hw_wr32(phy_mgt, NBL_DPRBAC_DBG_CNT_EN, dbg_cnt_en.data);

	nbl_hw_wr32(phy_mgt, NBL_DPRBAC_ENABLE, 0x39);
	nbl_hw_wr32(phy_mgt, NBL_DMACSEC_MODE, 4);

	nbl_hw_wr32(phy_mgt, NBL_DMACSEC_ID0_EN, 0x10000);
	nbl_hw_wr32(phy_mgt, NBL_DMACSEC_ID1_EN, 0x10000);
	nbl_hw_wr32(phy_mgt, NBL_DMACSEC_ID2_EN, 0x10000);
	nbl_hw_wr32(phy_mgt, NBL_DMACSEC_ID3_EN, 0x10000);

	nbl_hw_wr32(phy_mgt, NBL_UMACSEC_EN, 1);
	nbl_hw_wr32(phy_mgt, NBL_UMACSEC_ETH_EN, 0xF);
	nbl_hw_wr32(phy_mgt, NBL_UMACSEC_ETH_CNT, 4);

	nbl_hw_read_regs(phy_mgt, NBL_DPRBAC_DROP, (u8 *)&dprbac_drop, sizeof(dprbac_drop));
	dprbac_drop.prbac_bp = 0;
	nbl_hw_write_regs(phy_mgt, NBL_DPRBAC_DROP, (u8 *)&dprbac_drop, sizeof(dprbac_drop));
}

struct nbl_phy_tbl_write {
	u64 opcode : 4;
	u64 tbl_type : 4;
	u64 pf_id : 2;
	u64 tbl_addr : 12;
	u64 key_mask : 40;
	u64 port_mask : 1;
	u64 hash_sel0l : 1;
	u64 hash_sel0h : 1;
	u64 hash_sel1 : 2;
	u64 slot_alg_sel : 1;
	u64 vld : 1;
	u64 rsv1 : 59;
	u64 rsv2[2];
};

struct nbl_phy_tbl_write_rsp {
	u32 opcode : 4;
	u32 tbl_type : 4;
	u32 status : 2;
	u32 errcode : 4;
	u32 rsv1 : 18;
	u32 rsv2[7];
};

#define NBL_PP_LOOP_EN		(0x520200)
#define NBL_PP_AM_UDF_PRF(_i)	(0x520280 + (_i) * 4)

union nbl_phy_udf_prf {
	u32 data;
	struct {
		u32 set_udf0_oft : 5;
		u32 set_udf0_sz : 2;
		u32 set_udf0_en : 1;
		u32 rsv : 24;
	};
};

static void nbl_phy_init_uprbac(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	struct device *dev = NBL_PHY_MGT_TO_DEV(phy_mgt);
	struct nbl_phy_tbl_write tbl_write = {0};
	struct nbl_phy_tbl_write_rsp *tbl_write_rsp;
	union nbl_phy_udf_prf udf_prf = {0};
	u16 pf_id = NBL_COMMON_TO_MGT_PF(common);
	int try_time = 10;

	nbl_hw_wr32(phy_mgt, NBL_PP_LOOP_EN, 1);
	nbl_hw_wr32(phy_mgt, NBL_UPRBAC_ENABLE, 0x33);
	nbl_hw_wr32(phy_mgt, NBL_UPRBAC_DBG_CNT_EN, 0xffff);

	udf_prf.set_udf0_oft = 4;
	udf_prf.set_udf0_sz = 2;
	udf_prf.set_udf0_en = 1;
	nbl_hw_wr32(phy_mgt, NBL_PP_AM_UDF_PRF(5), udf_prf.data);

	tbl_write.opcode = 4;
	tbl_write.pf_id = pf_id;
	tbl_write.hash_sel0l = 0;
	tbl_write.hash_sel1 = 3;
	tbl_write.vld = 1;
	nbl_hw_write_regs(phy_mgt, NBL_UPRBAC_CMD_HEAD(pf_id), (u8 *)&tbl_write, 32);
	nbl_hw_wr32(phy_mgt, NBL_UPRBAC_CMD_REQ(pf_id), 1);

	while (try_time-- && nbl_hw_rd32(phy_mgt, NBL_UPRBAC_CMD_REQ(pf_id)))
		usleep_range(100, 200);

	nbl_hw_read_regs(phy_mgt, NBL_UPRBAC_CMD_HEAD(pf_id), (u8 *)&tbl_write, 32);
	tbl_write_rsp = (struct nbl_phy_tbl_write_rsp *)&tbl_write;
	if (try_time < 0 || tbl_write_rsp->status != 0) {
		dev_err(dev, "nbl phy add %u ipsec fem fail\n", pf_id);
		return;
	}
	dev_info(dev, "nbl phy add %u ipsec fem success\n", pf_id);
}

static void nbl_phy_cfg_macsec_fs(void *priv, u32 index, struct nbl_macsec_fs *macsec_fs)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_hw_write_regs(phy_mgt, NBL_DMACSEC_FS(index), (u8 *)macsec_fs, 32);
}

static void nbl_phy_cfg_macsec_txsc(void *priv, u32 index, struct nbl_macsec_tx_sc *tx_sc)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_hw_write_regs(phy_mgt, NBL_DMACSEC_SC(index), (u8 *)tx_sc, 4);
}

static void nbl_phy_cfg_macsec_rxsc(void *priv, u32 index, struct nbl_macsec_rx_sc *rx_sc)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_hw_write_regs(phy_mgt, NBL_UMACSEC_SC(index), (u8 *)rx_sc, 16);
}

static void nbl_phy_cfg_macsec_sa(void *priv, u32 index, struct nbl_macsec_sa *sa, bool is_tx)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	if (is_tx) {
		nbl_hw_write_regs(phy_mgt, NBL_DMACSEC_SA(index), (u8 *)sa, 64);
		nbl_hw_write_regs(phy_mgt, NBL_DMACSEC_SA_PN(index), (u8 *)&sa->sa_pn, 8);
	} else {
		nbl_hw_write_regs(phy_mgt, NBL_UMACSEC_SA(index), (u8 *)sa, 64);
		nbl_hw_write_regs(phy_mgt, NBL_UMACSEC_SA_PN(index), (u8 *)&sa->sa_pn, 8);
	}
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
	u8 func_id = NBL_PHY_MGT_TO_COMMON(phy_mgt)->function;
	u32 pong;

	nbl_hw_read_regs(phy_mgt, NBL_FW_HEARTBEAT_PONG(func_id), (u8 *)&pong, sizeof(pong));

	return pong;
}

static void nbl_phy_set_fw_pong(void *priv, u32 pong)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	u8 func_id = NBL_PHY_MGT_TO_COMMON(phy_mgt)->function;

	nbl_hw_write_regs(phy_mgt, NBL_FW_HEARTBEAT_PONG(func_id), (u8 *)&pong, sizeof(pong));
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

	nbl_hw_read_mbx_regs(priv, NBL_MBX_QINFO_CFG_RX_TABLE_ADDR, (u8 *)&val, sizeof(val));
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

#define NBL_NUM_PPORT_PRIO				(8)

static void nbl_phy_get_prio_stat_data(void *priv, u32 eth_id, u64 *data, u32 *data_len)
{
	struct nbl_prio_stats rx_prio_stats = {0};
	struct nbl_prio_stats tx_prio_stats = {0};
	int prio;
	int idx = 0;

	for (prio = 0; prio < NBL_NUM_PPORT_PRIO; prio++) {
		nbl_phy_get_rx_prio_stats(priv, eth_id, prio, &rx_prio_stats);
		nbl_phy_get_tx_prio_stats(priv, eth_id, prio, &tx_prio_stats);

		data[idx++] = rx_prio_stats.packets;
		data[idx++] = rx_prio_stats.bytes;
		data[idx++] = rx_prio_stats.drop_packets;
		data[idx++] = tx_prio_stats.packets;
		data[idx++] = tx_prio_stats.bytes;
		data[idx++] = tx_prio_stats.drop_packets;
	}
	*data_len = idx;
}

static int nbl_acl_flow_tcam_clear(struct nbl_phy_mgt *phy_mgt, u16 tcam_btm,
				   u16 tcam_start_idx, u16 tcam_end_idx)
{
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	union acl_indir_ctrl_u indir_ctrl = {
		.info.tcam_addr = 0,
		.info.start = 1,
		.info.acc_btm = tcam_btm,
		.info.rw = 0,	/* 0 write, 1 read */
	};
	union acl_indir_access_ack_u indir_access_ack = {.info = {0}};
	/* set invalid in each tcam */
	union acl_valid_bit_u tcam_data_valid_bit = {.info = {0}};
	int try_time = NBL_ACL_RD_RETRY;

	nbl_debug(common, NBL_DEBUG_FLOW,
		  "tcam clear, tcam_btm:%x, tcam_start_idx:%d, tcam_end_idx:%d\n",
		  tcam_btm, tcam_start_idx, tcam_end_idx);

	for (; tcam_start_idx < tcam_end_idx; ++tcam_start_idx) {
		nbl_hw_write_regs(phy_mgt, NBL_ACL_VALID_BIT_ADDR,
				  (u8 *)tcam_data_valid_bit.data, sizeof(tcam_data_valid_bit));
		indir_ctrl.info.tcam_addr = tcam_start_idx;
		nbl_hw_write_regs(phy_mgt, NBL_ACL_INDIR_CTRL_ADDR,
				  (u8 *)indir_ctrl.data, sizeof(indir_ctrl));

		while (try_time--) {
			nbl_hw_read_regs(phy_mgt, NBL_ACL_INDIR_ACCESS_ACK_ADDR,
					 (u8 *)indir_access_ack.data, sizeof(indir_access_ack));
			if (indir_access_ack.info.done)
				break;
			usleep_range(NBL_ACL_RD_WAIT_100US, NBL_ACL_RD_WAIT_200US);
		}

		if (!indir_access_ack.info.done) {
			nbl_err(common, NBL_DEBUG_FLOW, "indirect access failed(%u-%u), done: %u, status: %08x.",
				tcam_start_idx, try_time + 1, 0, indir_access_ack.info.status);
			return NBL_FAIL;
		}

		indir_access_ack.info.done = 0;
		try_time = NBL_ACL_RD_RETRY;
	}
	nbl_debug(common, NBL_DEBUG_FLOW, "clear acl flow:idx(depth):%d(%d)\n",
		  tcam_start_idx, tcam_end_idx);
	return NBL_OK;
}

static void nbl_phy_clear_acl(void *priv, u16 tcam_start_idx, u16 tcam_end_idx)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_acl_flow_tcam_clear(phy_mgt, NBL_ACL_FLUSH_FLOW_BTM, tcam_start_idx, tcam_end_idx);
}

static void nbl_phy_clear_acl_rdma(void *priv, u16 tcam_start_idx, u16 tcam_end_idx)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;

	nbl_acl_flow_tcam_clear(phy_mgt, NBL_ACL_FLUSH_RDMA_BTM, tcam_start_idx, tcam_end_idx);
}

static int nbl_phy_set_fd_tcam_cfg_default(void *priv)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union acl_act_u acl_act;
	union acl_tct_u acl_tct;
	union acl_kgen_tcam_u acl_kgen_tcam;
	int i;

	memset(&acl_tct, 0, sizeof(union acl_tct_u));
	memset(&acl_act, 0, sizeof(union acl_act_u));
	memset(&acl_kgen_tcam, 0, sizeof(union acl_kgen_tcam_u));

	/* cfg action_ram_cfg */
	for (i = NBL_FD_PROFILE_DEFAULT; i <= (NBL_FD_PROFILE_DEFAULT + 1); i++) {
		nbl_hw_read_regs(phy_mgt, NBL_ACL_ACT_REG(i), (u8 *)&acl_act, sizeof(acl_act));
		acl_act.info.at_en_vec = BIT(0);
		acl_act.info.at_alloc_id_vec_arr[0] = 12;
		nbl_hw_write_regs(phy_mgt, NBL_ACL_ACT_REG(i), (u8 *)&acl_act, sizeof(acl_act));
	}

	/* cfg tcam */
	nbl_hw_read_regs(phy_mgt, NBL_ACL_TCT_REG(NBL_FD_PROFILE_DEFAULT),
			 (u8 *)&acl_tct, sizeof(acl_tct));
	acl_tct.info.start_cmp_vec = 0xE001;
	acl_tct.info.start_set_vec = 0xE001;
	acl_tct.info.tcam_en_vec = 0x1FFF;
	acl_tct.info.key_id_vec_l = 12 + (11 << 4 * 1) + (10 << 4 * 2) + (9 << 4 * 3);
	acl_tct.info.key_id_vec = (8 << 4 * 0) + (7 << 4 * 1) + (6 << 4 * 2) + (5 << 4 * 3) +
				(4 << 4 * 4) + (3 << 4 * 5) + (2 << 4 * 6) + (1 << 4 * 7);
	acl_tct.info.key_id_vec_h = 0;
	nbl_hw_write_regs(phy_mgt, NBL_ACL_TCT_REG(NBL_FD_PROFILE_DEFAULT),
			  (u8 *)&acl_tct, sizeof(acl_tct));
	nbl_hw_write_regs(phy_mgt, NBL_ACL_TCT_REG(NBL_FD_PROFILE_DEFAULT + 1),
			  (u8 *)&acl_tct, sizeof(acl_tct));

	/* cfg kgen tcam */
	for (i = NBL_FD_PROFILE_IPV4; i < NBL_FD_PROFILE_DEFAULT; i++) {
		nbl_hw_read_regs(phy_mgt, NBL_ACL_KGEN_TCAM_REG(i),
				 (u8 *)&acl_kgen_tcam, sizeof(acl_kgen_tcam));
		acl_kgen_tcam.info.valid_bit = 0;
		nbl_hw_write_regs(phy_mgt, NBL_ACL_KGEN_TCAM_REG(i),
				  (u8 *)&acl_kgen_tcam, sizeof(acl_kgen_tcam));
	}

	return 0;
}

static int nbl_phy_set_rdma_tcam_cfg_default(void *priv, u8 profile_id, u8 tcam_id)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	union acl_act_u acl_act;
	union acl_tct_u acl_tct;
	union acl_kgen_tcam_u acl_kgen_tcam;

	memset(&acl_tct, 0, sizeof(union acl_tct_u));
	memset(&acl_act, 0, sizeof(union acl_act_u));
	memset(&acl_kgen_tcam, 0, sizeof(union acl_kgen_tcam_u));

	/* cfg action_ram_cfg */
	nbl_hw_read_regs(phy_mgt, NBL_ACL_ACT_REG(profile_id),
			 (u8 *)&acl_act, sizeof(acl_act));
	acl_act.info.at_en_vec = BIT(tcam_id);
	acl_act.info.at_alloc_id_vec_arr[1] = tcam_id << 28;
	nbl_hw_write_regs(phy_mgt, NBL_ACL_ACT_REG(profile_id),
			  (u8 *)&acl_act, sizeof(acl_act));

	/* cfg tcam */
	nbl_hw_read_regs(phy_mgt, NBL_ACL_TCT_REG(profile_id),
			 (u8 *)&acl_tct, sizeof(acl_tct));
	acl_tct.info.start_cmp_vec = 0x8000;
	acl_tct.info.start_set_vec = 0x8000;
	acl_tct.info.tcam_en_vec = 0x8000;
	acl_tct.info.key_id_vec_l = 0;
	acl_tct.info.key_id_vec = 0;
	nbl_hw_write_regs(phy_mgt, NBL_ACL_TCT_REG(profile_id),
			  (u8 *)&acl_tct, sizeof(acl_tct));

	nbl_hw_read_regs(phy_mgt, NBL_ACL_KGEN_TCAM_REG(profile_id),
			 (u8 *)&acl_kgen_tcam, sizeof(acl_kgen_tcam));
	acl_kgen_tcam.info.valid_bit = 1;
	nbl_hw_write_regs(phy_mgt, NBL_ACL_KGEN_TCAM_REG(profile_id),
			  (u8 *)&acl_kgen_tcam, sizeof(acl_kgen_tcam));

	return 0;
}

static int nbl_phy_set_fd_tcam_cfg_full(void *priv)
{
	return 0;
}

static int nbl_phy_set_fd_tcam_cfg_lite(void *priv)
{
	return 0;
}

static int nbl_phy_set_rdma_tcam_ram(void *priv, struct nbl_acl_tcam_param *data,
				     struct nbl_acl_tcam_param *mask, u16 ram_index,
				     u32 depth_index)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	union acl_indir_ctrl_u acl_indir_ctrl = {
		.info.start = 1,
		.info.rw = NBL_ACL_INDIR_CTRL_WRITE,
	};
	union acl_valid_bit_u acl_valid_bit = {{0}};
	union acl_indir_access_ack_u acl_indir_access_ack = {{0}};
	struct nbl_acl_tcam_common_data tcam_data = {{0}}, tcam_mask = {{0}};
	int i, rd_retry = NBL_ACL_RD_RETRY;

	acl_indir_ctrl.info.acc_btm |= 1 << (ram_index);
	acl_valid_bit.info.valid_bit |= 1 << (ram_index);

	for (i = 0; i < 2; i++) {
		memset(&tcam_data, 0, sizeof(tcam_data));
		memset(&tcam_mask, 0, sizeof(tcam_data));
		if (i == 0) {
			memcpy(&tcam_data.data[3],  &data->info.data[0], 1);
			memcpy(&tcam_mask.data[3],  &mask->info.data[0], 1);
		} else {
			memcpy(&tcam_data.data,  &data->info.data[1], 4);
			memcpy(&tcam_mask.data,  &mask->info.data[1], 4);
		}

		*(u32 *)(&tcam_mask) = ~(*(u32 *)(&tcam_mask));

		nbl_tcam_truth_value_convert_u32((u32 *)&tcam_data, (u32 *)&tcam_mask);

		nbl_info(common, NBL_DEBUG_FLOW, "key data: 0x%02x%02x%02x%02x",
			 tcam_data.data[3], tcam_data.data[2],
			 tcam_data.data[1], tcam_data.data[0]);
		nbl_info(common, NBL_DEBUG_FLOW, "key mask: 0x%02x%02x%02x%02x",
			 tcam_mask.data[3], tcam_mask.data[2],
			 tcam_mask.data[1], tcam_mask.data[0]);

		nbl_hw_write_regs(phy_mgt, NBL_ACL_TCAM_DATA_REG(18 + i),
				  (u8 *)&tcam_data, sizeof(tcam_data.data));
		nbl_hw_write_regs(phy_mgt, NBL_ACL_TCAM_MSK_REG(18 + i),
				  (u8 *)&tcam_mask, sizeof(tcam_mask.data));
	}
	acl_indir_ctrl.info.tcam_addr = depth_index;

	nbl_debug(common, NBL_DEBUG_FLOW, "Set valid bit %08x", *(u32 *)&acl_valid_bit);
	nbl_debug(common, NBL_DEBUG_FLOW, "Set ctrl %08x", *(u32 *)&acl_indir_ctrl);

	nbl_hw_write_regs(phy_mgt, NBL_ACL_VALID_BIT_ADDR,
			  (u8 *)&acl_valid_bit, sizeof(acl_valid_bit));
	nbl_hw_write_regs(phy_mgt, NBL_ACL_INDIR_CTRL_ADDR,
			  (u8 *)&acl_indir_ctrl, sizeof(acl_indir_ctrl));
	do {
		nbl_hw_read_regs(phy_mgt, NBL_ACL_INDIR_ACCESS_ACK_ADDR,
				 (u8 *)&acl_indir_access_ack, sizeof(acl_indir_access_ack));
		if (!acl_indir_access_ack.info.done) {
			rd_retry--;
			usleep_range(NBL_ACL_RD_WAIT_100US, NBL_ACL_RD_WAIT_200US);
		} else {
			break;
		}
	} while (rd_retry);

	if (!acl_indir_access_ack.info.done) {
		nbl_err(common, NBL_DEBUG_FLOW, "Set acl tcam fail, status: %d\n",
			acl_indir_access_ack.info.status);
		return -EIO;
	}

	return 0;
}

static int nbl_phy_set_fd_tcam_ram(void *priv, struct nbl_acl_tcam_param *data,
				   struct nbl_acl_tcam_param *mask, u16 ram_index, u32 depth_index)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	union acl_indir_ctrl_u acl_indir_ctrl = {
		.info.start = 1,
		.info.rw = NBL_ACL_INDIR_CTRL_WRITE,
	};
	union acl_valid_bit_u acl_valid_bit = {{0}};
	union acl_indir_access_ack_u acl_indir_access_ack = {{0}};
	struct nbl_acl_tcam_common_data tcam_data = {{0}}, tcam_mask = {{0}};
	int i, rd_retry = NBL_ACL_RD_RETRY;

	for (i = 0; i < data->len / NBL_ACL_TCAM_KEY_LEN; i++) {
		acl_indir_ctrl.info.acc_btm |= 1 << (ram_index + i);
		acl_valid_bit.info.valid_bit |= 1 << (ram_index + i);
	}

	for (i = 0; i < data->len / (NBL_ACL_TCAM_DATA_DWLEN * 4); i++) {
		memset(&tcam_data, 0, sizeof(tcam_data));
		memset(&tcam_mask, 0, sizeof(tcam_data));

		memcpy(&tcam_data.data, &data->info.data[i * NBL_ACL_TCAM_DATA_DWLEN * 4],
		       sizeof(tcam_data.data));
		memcpy(&tcam_mask.data, &mask->info.data[i * NBL_ACL_TCAM_DATA_DWLEN * 4],
		       sizeof(tcam_mask.data));

		*(u32 *)(&tcam_mask) = ~(*(u32 *)(&tcam_mask));

		nbl_tcam_truth_value_convert_u32((u32 *)&tcam_data, (u32 *)&tcam_mask);

		nbl_debug(common, NBL_DEBUG_FLOW, "Set %d key data: 0x%02x%02x%02x%02x",
			  i, tcam_data.data[3], tcam_data.data[2],
			  tcam_data.data[1], tcam_data.data[0]);
		nbl_debug(common, NBL_DEBUG_FLOW, "Set %d key mask: 0x%02x%02x%02x%02x",
			  i, tcam_mask.data[3], tcam_mask.data[2],
			  tcam_mask.data[1], tcam_mask.data[0]);

		nbl_hw_write_regs(phy_mgt, NBL_ACL_TCAM_DATA_REG(i),
				  (u8 *)&tcam_data, sizeof(tcam_data.data));
		nbl_hw_write_regs(phy_mgt, NBL_ACL_TCAM_MSK_REG(i),
				  (u8 *)&tcam_mask, sizeof(tcam_mask.data));
	}

	acl_indir_ctrl.info.tcam_addr = depth_index;

	nbl_debug(common, NBL_DEBUG_FLOW, "Set valid bit %08x", *(u32 *)&acl_valid_bit);
	nbl_debug(common, NBL_DEBUG_FLOW, "Set ctrl %08x", *(u32 *)&acl_indir_ctrl);

	nbl_hw_write_regs(phy_mgt, NBL_ACL_VALID_BIT_ADDR,
			  (u8 *)&acl_valid_bit, sizeof(acl_valid_bit));
	nbl_hw_write_regs(phy_mgt, NBL_ACL_INDIR_CTRL_ADDR,
			  (u8 *)&acl_indir_ctrl, sizeof(acl_indir_ctrl));
	do {
		nbl_hw_read_regs(phy_mgt, NBL_ACL_INDIR_ACCESS_ACK_ADDR,
				 (u8 *)&acl_indir_access_ack, sizeof(acl_indir_access_ack));
		if (!acl_indir_access_ack.info.done) {
			rd_retry--;
			usleep_range(NBL_ACL_RD_WAIT_100US, NBL_ACL_RD_WAIT_200US);
		} else {
			break;
		}
	} while (rd_retry);

	if (!acl_indir_access_ack.info.done) {
		nbl_err(common, NBL_DEBUG_FLOW, "Set acl tcam fail, status: %d\n",
			acl_indir_access_ack.info.status);
		return -EIO;
	}

	return 0;
}

static int nbl_phy_set_fd_action_ram(void *priv, u32 *action, u16 ram_index, u32 depth_index)
{
	struct nbl_phy_mgt *phy_mgt = (struct nbl_phy_mgt *)priv;
	struct nbl_common_info *common = NBL_PHY_MGT_TO_COMMON(phy_mgt);
	union acl_at0_u acl_at0 = {{0}};

	/* draco action is 88 bit */
	memcpy(&acl_at0, action, 11);
	nbl_hw_write_regs(phy_mgt, NBL_ACL_ACTION_RAM_TBL(ram_index, depth_index),
			  (u8 *)&acl_at0, sizeof(acl_at0));
	nbl_debug(common, NBL_DEBUG_FLOW, "Set ram_index %d depth_index %d action: 0x%08x-%08x-%08x",
		  ram_index, depth_index, action[2], action[1], action[0]);

	return 0;
}

static struct nbl_phy_ops phy_ops = {
	.init_chip_module		= nbl_phy_init_chip_module,
	.set_driver_status		= nbl_phy_set_driver_status,
	.get_host_pf_mask		= nbl_phy_get_host_pf_mask,
	.get_host_pf_fid		= nbl_phy_get_host_pf_fid,
	.capture_bdf			= nbl_phy_capture_bdf,
	.get_table_range		= nbl_phy_get_table_range,
	.get_hw_addr			= nbl_phy_get_hw_addr,
	.get_reg_dump			= nbl_phy_get_reg_dump,
	.get_reg_dump_len		= nbl_phy_get_reg_dump_len,
	.process_abnormal_event		= nbl_phy_process_abnormal_event,
	.get_tail_ptr			= nbl_phy_get_tail_ptr,
	.update_tail_ptr		= nbl_phy_update_tail_ptr,
	.set_spoof_check_addr		= nbl_phy_set_spoof_check_addr,
	.set_spoof_check_enable		= nbl_phy_set_spoof_check_enable,
	.set_promisc_mode		= nbl_phy_set_promisc_mode,
	.set_ucar			= nbl_phy_set_ucar,

	/* offload */
	.init_offload_fwd		= nbl_phy_init_offload_fwd,
	.init_rep			= nbl_phy_init_rep,
	.init_flow			= nbl_phy_flow_init,
	.set_slave_swd_id		= nbl_phy_set_slave_swd_id,
	.clear_ipro_decap		= nbl_phy_clear_ipro_decap,
	.cfg_nodport_upcall		= nbl_phy_cfg_nodport_upcall,

	/* flow */
	.init_fem			= nbl_phy_init_fem,
	.alloc_kt			= nbl_phy_alloc_kt,
	.free_kt			= nbl_phy_free_kt,
	.set_kt				= nbl_phy_set_kt,
	.set_ht				= nbl_phy_set_ht,
	.add_kt				= nbl_phy_add_kt,
	.del_ht_oft			= nbl_phy_del_ht_oft,
	.read_fem_tbl			= nbl_phy_read_fem_tbl,
	.write_fem_tbl			= nbl_phy_write_fem_tbl,
	.lookup_key			= nbl_phy_lookup_key,
	.init_mcc			= nbl_phy_init_mcc,
	.clear_mcc			= nbl_phy_clear_mcc,
	.add_mcc			= nbl_phy_add_mcc,
	.del_mcc			= nbl_phy_del_mcc,
	.cfg_lag_mcc			= nbl_phy_cfg_lag_mcc,
	.clear_em			= nbl_phy_clear_em,

	.get_acl_flow_stat_width	= nbl_phy_get_acl_flow_stat_width,
	.init_cmdq			= nbl_phy_cmdq_init,
	.reset_cmdq			= nbl_phy_cmdq_reset,
	.destroy_cmdq			= nbl_phy_cmdq_destroy,
	.update_cmdq_tail		= nbl_phy_update_cmdq_tail,
	.set_tc_kgen_cvlan_zero		= nbl_phy_set_tc_kgen_cvlan_zero,
	.unset_tc_kgen_cvlan		= nbl_phy_unset_tc_kgen_cvlan,
	.ipro_chksum_err_ctrl		= nbl_phy_ipro_chksum_err_ctrl,
	.ipro_chksum_err_select		= nbl_phy_ipro_chksum_err_select,
	.pa_chksum_err_report		= nbl_phy_pa_chksum_err_report,
	.set_upcall_rule		= nbl_phy_acl_set_upcall_rule,
	.unset_upcall_rule		= nbl_phy_acl_unset_upcall_rule,
	.set_pp_udf			= nbl_phy_set_pp_udf,
	.set_epro_udf			= nbl_phy_set_epro_udf,
	.set_acl_udf			= nbl_phy_set_acl_udf,
	.init_hol			= nbl_phy_init_hol,
	.write_ped_tbl			= nbl_phy_write_ped_tbl,

	/* mailbox */
	.cfg_mailbox_qinfo		= nbl_phy_cfg_mailbox_qinfo,
	.config_mailbox_rxq		= nbl_phy_config_mailbox_rxq,
	.config_mailbox_txq_rst		= nbl_phy_config_mailbox_txq_rst,
	.config_mailbox_txq		= nbl_phy_config_mailbox_txq,
	.stop_mailbox_rxq		= nbl_phy_stop_mailbox_rxq,
	.stop_mailbox_txq		= nbl_phy_stop_mailbox_txq,
	.enable_mailbox_irq		= nbl_phy_enable_mailbox_irq,
	.update_mailbox_queue_tail_ptr	= nbl_phy_update_mailbox_queue_tail_ptr,
	.check_mailbox_dma_err		= nbl_phy_check_mailbox_dma_err,
	.dump_mailbox_dbg		= nbl_phy_dump_mailbox_dbg,

	/* uvn dvn */
	.reset_dvn_cfg			= nbl_phy_reset_dvn_cfg,
	.reset_uvn_cfg			= nbl_phy_reset_uvn_cfg,
	.restore_dvn_context		= nbl_phy_restore_dvn_context,
	.restore_uvn_context		= nbl_phy_restore_uvn_context,
	.get_tx_queue_cfg		= nbl_phy_get_tx_queue_cfg,
	.get_rx_queue_cfg		= nbl_phy_get_rx_queue_cfg,
	.cfg_tx_queue			= nbl_phy_cfg_tx_queue,
	.cfg_rx_queue			= nbl_phy_cfg_rx_queue,
	.disable_dvn			= nbl_phy_disable_dvn,
	.disable_uvn			= nbl_phy_disable_uvn,
	.save_dvn_ctx			= nbl_phy_save_dvn_ctx,
	.save_uvn_ctx			= nbl_phy_save_uvn_ctx,
	.lso_dsch_drain			= nbl_phy_lso_dsch_drain,
	.rsc_cache_drain		= nbl_phy_rsc_cache_drain,
	.get_tx_queue_err_stats		= nbl_phy_get_tx_queue_err_stats,
	.get_rx_queue_err_stats		= nbl_phy_get_rx_queue_err_stats,
	.get_uvn_pkt_drop_stats		= nbl_phy_get_uvn_pkt_drop_stats,
	.get_uvn_desc_entry_stats	= nbl_phy_get_uvn_desc_entry_stats,
	.set_uvn_desc_wr_timeout	= nbl_phy_set_uvn_desc_wr_timeout,
	.get_fake_drop_stats		= nbl_phy_get_fake_drop_stats,
	.get_uvn_drop_queue_disable	= nbl_phy_get_uvn_drop_queue_disable,
	.set_dvn_desc_req		= nbl_dvn_descreq_num_cfg,
	.get_dvn_desc_req		= nbl_dvn_descreq_num_get,

	/* store, qm */
	.get_ustore_pkt_drop_stats	= nbl_phy_get_ustore_pkt_drop_stats,
	.get_rx_prio_stats		= nbl_phy_get_rx_prio_stats,
	.get_tx_prio_stats		= nbl_phy_get_tx_prio_stats,
	.get_dstat_vsi_stat		= nbl_phy_get_dstat_vsi_stat,
	.get_ustat_vsi_stat		= nbl_phy_get_ustat_vsi_stat,

	/* irq */
	.configure_msix_map		= nbl_phy_configure_msix_map,
	.configure_msix_info		= nbl_phy_configure_msix_info,
	.enable_abnormal_irq		= nbl_phy_enable_abnormal_irq,
	.enable_msix_irq		= nbl_phy_enable_msix_irq,
	.get_msix_irq_enable_info	= nbl_phy_get_msix_irq_enable_info,
	.get_coalesce			= nbl_phy_get_coalesce,
	.set_coalesce			= nbl_phy_set_coalesce,
	.set_msix_fast_restrain		= nbl_phy_set_msix_fast_restrain,
	.set_net_qid_table		= nbl_phy_set_net_qid_table,

	/* ipro, epro */
	.cfg_ipro_queue_tbl		= nbl_phy_cfg_ipro_queue_tbl,
	.cfg_ipro_dn_sport_tbl		= nbl_phy_cfg_ipro_dn_sport_tbl,
	.init_epro_vpt_tbl		= nbl_phy_init_epro_vpt_tbl,
	.set_epro_rss_default		= nbl_phy_set_epro_rss_default,
	.init_epro_rss_key		= nbl_phy_init_epro_rss_key,
	.cfg_epro_rss_ret		= nbl_phy_cfg_epro_rss_ret,
	.set_epro_rss_ret		= nbl_phy_set_epro_rss_ret,
	.get_epro_rss_ret		= nbl_phy_get_epro_rss_ret,
	.set_epro_rss_pt		= nbl_phy_set_epro_rss_pt,
	.clear_epro_rss_pt		= nbl_phy_clear_epro_rss_pt,
	.setup_queue_switch		= nbl_phy_setup_queue_switch,
	.get_vsi_rss_key		= nbl_phy_get_vsi_rss_key,
	.get_rss_key			= nbl_phy_get_rss_key,
	.set_rss_key			= nbl_phy_set_rss_key,
	.get_rss_hash_key_sel		= nbl_phy_get_rss_hash_key_sel,
	.set_rss_hash_key_sel		= nbl_phy_set_rss_hash_key_sel,
	.get_rss_alg_sel		= nbl_phy_get_rss_alg_sel,
	.set_rss_alg_sel		= nbl_phy_set_rss_alg_sel,
	.get_rss_hash_tmpt_sel		= nbl_phy_get_rss_hash_tmpt_sel,
	.set_rss_hash_tmpt_sel		= nbl_phy_set_rss_hash_tmpt_sel,
	.cfg_rx_vlan_parse		= nbl_phy_cfg_rx_vlan_parse,
	.cfg_rss_hash			= nbl_phy_cfg_rss_hash,
	.cfg_lag_hash_algorithm		= nbl_phy_cfg_lag_hash_algorithm,
	.cfg_lag_member_fwd		= nbl_phy_cfg_lag_member_fwd,
	.cfg_lag_member_list		= nbl_phy_cfg_lag_member_list,
	.get_lag_fwd			= nbl_phy_get_lag_fwd,
	.cfg_bond_shaping		= nbl_phy_cfg_bond_shaping,
	.set_mtu			= nbl_phy_set_mtu,
	.cfg_phy_flow			= nbl_phy_cfg_phy_flow,
	.cfg_lacp_lldp			= nbl_phy_cfg_lacp_lldp,
	.get_chip_temperature		= nbl_phy_get_chip_temperature,
	.set_qinfo_tx			= nbl_phy_set_qinfo_tx,
	.get_qinfo_tx			= nbl_phy_get_qinfo_tx,
	.cfg_eth_shaping		= nbl_phy_cfg_eth_shaping,
	.get_mirror_table_id		= nbl_phy_get_mirror_table_id,
	.configure_mirror		= nbl_phy_configure_mirror,
	.configure_mirror_table		= nbl_phy_configure_mirror_table,
	.clear_mirror_cfg		= nbl_phy_clear_mirror_cfg,

	/* dsch */
	.cfg_q2tc_netid			= nbl_phy_cfg_q2tc_netid,
	.cfg_q2tc_tcid			= nbl_phy_cfg_q2tc_tcid,
	.cfg_dsch_net_to_group		= nbl_phy_cfg_dsch_net_to_group,
	.set_tc_wgt			= nbl_phy_set_tc_wgt,
	.check_q2tc			= nbl_phy_check_q2tc,
	.set_shaping			= nbl_phy_set_shaping,
	.active_shaping			= nbl_phy_active_shaping,
	.deactive_shaping		= nbl_phy_deactive_shaping,

	/* vdpa */
	.init_vdpaq			= nbl_phy_init_vdpaq,
	.destroy_vdpaq			= nbl_phy_destroy_vdpaq,

	/* pfc */
	.init_pfc			= nbl_phy_init_pfc,
	.configure_qos			= nbl_phy_configure_qos,
	.configure_rdma_bw		= nbl_phy_configure_rdma_bw,
	.set_pfc_buffer_size		= nbl_phy_set_pfc_buffer_size,
	.get_pfc_buffer_size		= nbl_phy_get_pfc_buffer_size,
	.set_rate_limit			= nbl_phy_set_rate_limit,
	/* padpt */
	.set_vnet_queue_info		= nbl_phy_set_vnet_queue_info,
	.clear_vnet_queue_info		= nbl_phy_clear_vnet_queue_info,
	.cfg_vnet_qinfo_log		= nbl_phy_cfg_vnet_qinfo_log,

	/* TLS */
	.cfg_ktls_tx_keymat		= nbl_phy_cfg_ktls_tx_keymat,
	.cfg_ktls_rx_keymat		= nbl_phy_cfg_ktls_rx_keymat,
	.cfg_ktls_rx_record		= nbl_phy_cfg_ktls_rx_record,

	/* IPSEC */
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
	.cfg_uipsec_em_cmd		= nbl_phy_cfg_uipsec_em_cmd,
	.read_uipsec_status		= nbl_phy_read_uipsec_status,
	.reset_uipsec_status		= nbl_phy_reset_uipsec_status,
	.read_uipsec_lft_info		= nbl_phy_read_uipsec_lft_info,
	.cfg_uipsec_lft_info		= nbl_phy_cfg_uipsec_lft_info,
	.init_uprbac			= nbl_phy_init_uprbac,

	/* MACSEC */
	.cfg_macsec_fs			= nbl_phy_cfg_macsec_fs,
	.cfg_macsec_txsc		= nbl_phy_cfg_macsec_txsc,
	.cfg_macsec_rxsc		= nbl_phy_cfg_macsec_rxsc,
	.cfg_macsec_sa			= nbl_phy_cfg_macsec_sa,

	/* FW */
	.get_fw_eth_num			= nbl_phy_get_fw_eth_num,
	.get_fw_eth_map			= nbl_phy_get_fw_eth_map,
	.get_board_info			= nbl_phy_get_board_info,
	.get_fw_ping			= nbl_phy_get_fw_ping,
	.set_fw_ping			= nbl_phy_set_fw_ping,
	.get_fw_pong			= nbl_phy_get_fw_pong,
	.set_fw_pong			= nbl_phy_set_fw_pong,

	/* high temperature protection */
	.set_hw_status			= nbl_phy_set_hw_status,
	.check_hw_status		= nbl_phy_check_hw_status,
	.get_hw_status			= nbl_phy_get_hw_status,
	.get_perf_dump_length		= nbl_phy_get_perf_dump_length,
	.get_perf_dump_data		= nbl_phy_get_perf_dump_data,
	.get_prio_stat_data		= nbl_phy_get_prio_stat_data,

	/* flow director */
	.clear_acl			= nbl_phy_clear_acl,
	.clear_acl_rdma			= nbl_phy_clear_acl_rdma,
	.set_fd_tcam_cfg_default	= nbl_phy_set_fd_tcam_cfg_default,
	.set_rdma_tcam_cfg_default	= nbl_phy_set_rdma_tcam_cfg_default,
	.set_fd_tcam_cfg_full		= nbl_phy_set_fd_tcam_cfg_full,
	.set_fd_tcam_cfg_lite		= nbl_phy_set_fd_tcam_cfg_lite,
	.set_fd_udf			= nbl_phy_set_fd_udf,
	.clear_fd_udf			= nbl_phy_clr_fd_udf,
	.set_rdma_tcam_ram		= nbl_phy_set_rdma_tcam_ram,
	.set_fd_tcam_ram		= nbl_phy_set_fd_tcam_ram,
	.set_fd_action_ram		= nbl_phy_set_fd_action_ram,
};

/* Structure starts here, adding an op should not modify anything below */
static int nbl_phy_setup_phy_mgt(struct nbl_common_info *common,
				 struct nbl_phy_mgt_draco **phy_mgt_draco)
{
	struct device *dev;

	dev = NBL_COMMON_TO_DEV(common);
	*phy_mgt_draco = devm_kzalloc(dev, sizeof(struct nbl_phy_mgt_draco), GFP_KERNEL);
	if (!*phy_mgt_draco)
		return -ENOMEM;

	NBL_PHY_MGT_TO_COMMON(&(*phy_mgt_draco)->phy_mgt) = common;

	return 0;
}

static void nbl_phy_remove_phy_mgt(struct nbl_common_info *common,
				   struct nbl_phy_mgt_draco **phy_mgt_draco)
{
	struct device *dev;

	dev = NBL_COMMON_TO_DEV(common);
	devm_kfree(dev, *phy_mgt_draco);
	*phy_mgt_draco = NULL;
}

static int nbl_phy_setup_ops(struct nbl_common_info *common, struct nbl_phy_ops_tbl **phy_ops_tbl,
			     struct nbl_phy_mgt_draco *phy_mgt_draco)
{
	struct device *dev;

	dev = NBL_COMMON_TO_DEV(common);
	*phy_ops_tbl = devm_kzalloc(dev, sizeof(struct nbl_phy_ops_tbl), GFP_KERNEL);
	if (!*phy_ops_tbl)
		return -ENOMEM;

	NBL_PHY_OPS_TBL_TO_OPS(*phy_ops_tbl) = &phy_ops;
	NBL_PHY_OPS_TBL_TO_PRIV(*phy_ops_tbl) = phy_mgt_draco;

	return 0;
}

static void nbl_phy_remove_ops(struct nbl_common_info *common, struct nbl_phy_ops_tbl **phy_ops_tbl)
{
	struct device *dev;

	dev = NBL_COMMON_TO_DEV(common);
	devm_kfree(dev, *phy_ops_tbl);
	*phy_ops_tbl = NULL;
}

int nbl_phy_init_draco(void *p, struct nbl_init_param *param)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct nbl_common_info *common;
	struct pci_dev *pdev;
	struct nbl_phy_mgt_draco **phy_mgt_draco;
	struct nbl_phy_mgt *phy_mgt;
	struct nbl_phy_ops_tbl **phy_ops_tbl;
	int bar_mask;
	int ret = 0;

	common = NBL_ADAPTER_TO_COMMON(adapter);
	phy_mgt_draco = (struct nbl_phy_mgt_draco **)&NBL_ADAPTER_TO_PHY_MGT(adapter);
	phy_ops_tbl = &NBL_ADAPTER_TO_PHY_OPS_TBL(adapter);
	pdev = NBL_COMMON_TO_PDEV(common);

	ret = nbl_phy_setup_phy_mgt(common, phy_mgt_draco);
	if (ret)
		goto setup_mgt_fail;

	phy_mgt = &(*phy_mgt_draco)->phy_mgt;
	bar_mask = BIT(NBL_MEMORY_BAR) | BIT(NBL_MAILBOX_BAR);
	ret = pci_request_selected_regions(pdev, bar_mask, NBL_DRIVER_NAME);
	if (ret) {
		dev_err(&pdev->dev, "Request memory bar and mailbox bar failed, err = %d\n", ret);
		goto request_bar_region_fail;
	}

	if (param->caps.has_ctrl) {
		phy_mgt->hw_addr = ioremap(pci_resource_start(pdev, NBL_MEMORY_BAR),
					   pci_resource_len(pdev, NBL_MEMORY_BAR) -
					   NBL_RDMA_NOTIFY_OFF_PF_DRACO);
		if (!phy_mgt->hw_addr) {
			dev_err(&pdev->dev, "Memory bar ioremap failed\n");
			ret = -EIO;
			goto ioremap_err;
		}
		phy_mgt->hw_size = pci_resource_len(pdev, NBL_MEMORY_BAR)
					- NBL_RDMA_NOTIFY_OFF_PF_DRACO;
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
	mutex_init(&phy_mgt->mutex_lock);
	phy_mgt->should_lock = true;
	(*phy_mgt_draco)->ro_enable = pcie_relaxed_ordering_enabled(pdev);

	ret = nbl_phy_setup_ops(common, phy_ops_tbl, *phy_mgt_draco);
	if (ret)
		goto setup_ops_fail;

	return 0;

setup_ops_fail:
	iounmap(phy_mgt->mailbox_bar_hw_addr);
mailbox_ioremap_err:
	iounmap(phy_mgt->hw_addr);
ioremap_err:
	pci_release_selected_regions(pdev, bar_mask);
request_bar_region_fail:
	nbl_phy_remove_phy_mgt(common, phy_mgt_draco);
setup_mgt_fail:
	return ret;
}

void nbl_phy_remove_draco(void *p)
{
	struct nbl_adapter *adapter = (struct nbl_adapter *)p;
	struct nbl_common_info *common;
	struct nbl_phy_mgt_draco **phy_mgt_draco;
	struct nbl_phy_ops_tbl **phy_ops_tbl;
	struct pci_dev *pdev;
	u8 __iomem *hw_addr;
	u8 __iomem *mailbox_bar_hw_addr;
	int bar_mask = BIT(NBL_MEMORY_BAR) | BIT(NBL_MAILBOX_BAR);

	common = NBL_ADAPTER_TO_COMMON(adapter);
	phy_mgt_draco = (struct nbl_phy_mgt_draco **)&NBL_ADAPTER_TO_PHY_MGT(adapter);
	phy_ops_tbl = &NBL_ADAPTER_TO_PHY_OPS_TBL(adapter);
	pdev = NBL_COMMON_TO_PDEV(common);

	hw_addr = (*phy_mgt_draco)->phy_mgt.hw_addr;
	mailbox_bar_hw_addr = (*phy_mgt_draco)->phy_mgt.mailbox_bar_hw_addr;

	iounmap(mailbox_bar_hw_addr);
	iounmap(hw_addr);
	pci_release_selected_regions(pdev, bar_mask);
	nbl_phy_remove_phy_mgt(common, phy_mgt_draco);

	nbl_phy_remove_ops(common, phy_ops_tbl);
}
