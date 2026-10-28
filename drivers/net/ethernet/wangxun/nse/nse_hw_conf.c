// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse.h"
#include "nse_type.h"
#include "nse_hw_conf.h"
#include "nse_adminq_cmd.h"

bool nse_is_hw_static_fea_set(struct nse_hw *hw, unsigned int f)
{
	if (f > NSE_HW_STATIC_FEA_FLAGS_NBITS)
		return false;

	return test_bit(f, hw->hw_conf.hw_static_fea);
}

bool nse_is_hw_dyn_fea_set(struct nse_hw *hw, unsigned int f)
{
	if (f > NSE_HW_DYN_FEA_FLAGS_NBITS)
		return false;

	return test_bit(f, hw->hw_conf.hw_dyn_fea);
}

static void nse_init_hw_conf_amber_common(struct nse_hw *hw)
{
	struct nse_hw_conf *conf = &hw->hw_conf;

	clear_bit(NSE_HW_STATIC_FEA_TDM_ONLY_CQ_WB, conf->hw_static_fea);
	set_bit(NSE_HW_STATIC_FEA_TDM_SUPPORT_TNL_CSUM, conf->hw_static_fea);
	set_bit(NSE_HW_STATIC_FEA_TDM_SUPPORT_TNL_TSO, conf->hw_static_fea);
	set_bit(NSE_HW_STATIC_FEA_TDM_SUPPORT_UP_ENFORCE, conf->hw_static_fea);
	set_bit(NSE_HW_STATIC_FEA_TDM_SUPPORT_PVID, conf->hw_static_fea);
	clear_bit(NSE_HW_STATIC_FEA_TDM_ONLY_HANDLE_L2TAG1, conf->hw_static_fea);

	set_bit(NSE_HW_STATIC_FEA_RDM_HAVE_RSC, conf->hw_static_fea);
	set_bit(NSE_HW_STATIC_FEA_RDM_SUPPORT_FLEX_RXDID, conf->hw_static_fea);

	set_bit(NSE_HW_STATIC_FEA_RCF_HAVE_FDIR, conf->hw_static_fea);

	set_bit(NSE_HW_STATIC_FEA_DB_HAVE_TRT, conf->hw_static_fea);
	clear_bit(NSE_HW_STATIC_FEA_DB_RPB_SHARED_BY_MULTI_PORTS, conf->hw_static_fea);

	set_bit(NSE_HW_STATIC_FEA_PSR_SUPPORT_TNL, conf->hw_static_fea);

	set_bit(NSE_HW_STATIC_FEA_SWITCH_FLEX, conf->hw_static_fea);
	clear_bit(NSE_HW_STATIC_FEA_SWITCH_LEGACY, conf->hw_static_fea);
	clear_bit(NSE_HW_STATIC_FEA_SWITCH_ONLY_VEPA, conf->hw_static_fea);

	set_bit(NSE_HW_STATIC_FEA_PTP_SUPPORT_FINE_MODE, conf->hw_static_fea);

	set_bit(NSE_HW_STATIC_FEA_MISC_SUPPORT_HW_LAG, conf->hw_static_fea);

	set_bit(NSE_HW_STATIC_FEA_MISC_SUPPORT_VIRTIO, conf->hw_static_fea);

	set_bit(NSE_HW_STATIC_FEA_MISC_SUPPORT_SIOV, conf->hw_static_fea);

	set_bit(NSE_HW_STATIC_FEA_MISC_SUPPORT_SCTP_CRC, conf->hw_static_fea);

	/*  FPGA, ASIC (nse_palladium_debug), and all current NSE_DEV_ID_AMBER_XXX does not support
	 * WOL
	 */
	clear_bit(NSE_HW_STATIC_FEA_MISC_SUPPORT_WOL, conf->hw_static_fea);

	set_bit(NSE_HW_DYN_FEA_BAR2_MAPPED_FOR_FWMNG_FLASH, conf->hw_dyn_fea);
	clear_bit(NSE_HW_DYN_FEA_BAR2_MAPPED_FOR_PE, conf->hw_dyn_fea);

	if (conf->hw_platform == NSE_HW_PLATFORM_ASIC) {
		if (nse_palladium_debug ||
			hw->device_id == NSE_DEV_ID_AMBER_FDBTACRX ||
			hw->device_id == NSE_DEV_ID_AMBER_DDATACRX ||
			hw->device_id == NSE_DEV_ID_AMBER_DDATAIRX ||
			hw->device_id == NSE_DEV_ID_AMBER_FQATACRX)

			set_bit(NSE_HW_DYN_FEA_SUPPORT_RDMA, conf->hw_dyn_fea);

	} else {	/* AMBER_FPGA */

		set_bit(NSE_HW_DYN_FEA_SUPPORT_RDMA, conf->hw_dyn_fea);
	}

	conf->hw_lmac_type = NSE_HW_LMAC_TYPE_1;

	if (conf->hw_platform == NSE_HW_PLATFORM_ASIC) {
		if (nse_palladium_debug) {
			conf->hw_lpcs_type = NSE_HW_LPCS_TYPE_UNKNOWN;
			conf->hw_lphy_internal_type = NSE_HW_LPHY_INTERNAL_TYPE_UNKNOWN;
		} else {
			conf->hw_lpcs_type = NSE_HW_LPCS_TYPE_1;
			conf->hw_lphy_internal_type = NSE_HW_LPHY_INTERNAL_TYPE_1;
		}

	} else {	/* FPGA */

		conf->hw_lpcs_type = NSE_HW_LPCS_TYPE_UNKNOWN;
		conf->hw_lphy_internal_type = NSE_HW_LPHY_INTERNAL_TYPE_UNKNOWN;
	}
}

/* asic or pldm */
static void nse_init_hw_conf_amber_asic(struct nse_hw *hw)
{
	struct nse_hw_conf *conf = &hw->hw_conf;

	conf->hw_platform = NSE_HW_PLATFORM_ASIC;

	if (hw->device_id == NSE_DEV_ID_AMBER_DQATACXX)
		conf->main_clock_freq = NSE_AMBER_ASIC_MAIN_CLOCK_FREQ_250MHZ;
	else
		conf->main_clock_freq = NSE_AMBER_ASIC_MAIN_CLOCK_FREQ_500MHZ;

	conf->ptp_ref_clock_freq = conf->main_clock_freq;	/* 500 MHz or 250 MHz */

	conf->max_pf_per_lan_channel = NSE_AMBER_ASIC_MAX_PF_PER_LAN_CHANNEL;

	if (hw->device_id == NSE_DEV_ID_AMBER_FDBTACXX ||	/* 2x100 */
		hw->device_id == NSE_DEV_ID_AMBER_FDBTACRX) {
		conf->max_bandwidth_per_lan_channel =
			NSE_AMBER_ASIC_MAX_BANDWIDTH_PER_LAN_CHANNEL_100G;

	} else if (hw->device_id == NSE_DEV_ID_AMBER_FQATACRX) {	/* 4x25 */

		conf->max_bandwidth_per_lan_channel =
			NSE_AMBER_ASIC_MAX_BANDWIDTH_PER_LAN_CHANNEL_50G;

	} else if (hw->device_id == NSE_DEV_ID_AMBER_DDATACRX ||	/* 2x25 */
			hw->device_id == NSE_DEV_ID_AMBER_DDATAIRX) {
		conf->max_bandwidth_per_lan_channel =
			NSE_AMBER_ASIC_MAX_BANDWIDTH_PER_LAN_CHANNEL_25G;

	} else if (hw->device_id == NSE_DEV_ID_AMBER_DQATACXX) {
		conf->max_bandwidth_per_lan_channel =
			NSE_AMBER_ASIC_MAX_BANDWIDTH_PER_LAN_CHANNEL_20G;

	} else  {
		conf->max_bandwidth_per_lan_channel =
			NSE_AMBER_ASIC_MAX_BANDWIDTH_PER_LAN_CHANNEL_100G;
	}

	conf->max_vsi_space = NSE_AMBER_ASIC_MAX_VSI_SPACE;
	conf->max_irq_space = NSE_AMBER_ASIC_MAX_IRQ_SPACE;
	conf->max_lan_rxq_space = NSE_AMBER_ASIC_MAX_LAN_RXQ_SPACE;
	conf->max_lan_txq_space = NSE_AMBER_ASIC_MAX_LAN_TXQ_SPACE;
	conf->max_lan_txcq_space = NSE_AMBER_ASIC_MAX_LAN_TXCQ_SPACE;

	conf->max_rdma_qset_space = NSE_AMBER_ASIC_MAX_RDMA_QSET_SPACE;

	conf->fdir_table_size = NSE_AMBER_ASIC_FDIR_TABLE_SIZE;
	conf->fdir_max_num_pfilter = NSE_AMBER_ASIC_FDIR_MAX_NUM_PFILTER;
	conf->fdir_max_num_sfilter = NSE_AMBER_ASIC_FDIR_MAX_NUM_SFILTER;

	conf->max_tc_allowed = 8;

	conf->rpb_pb_total_size_per_lan = NSE_AMBER_ASIC_RPB_PB_TOTAL_SIZE_PER_LAN;
	conf->rpb_pb_total_size_per_lan_channel = NSE_AMBER_ASIC_RPB_PB_TOTAL_SIZE_PER_LAN_CHANNEL;

	conf->tdb_pb_sz_total = NSE_AMBER_ASIC_TDB_PB_SZ_TOTAL;

	conf->trt_pb_sz_total = NSE_AMBER_ASIC_TRT_PB_SZ_TOTAL;
	conf->trt_pb_sz_per_lan_dedicated_dflt = NSE_AMBER_ASIC_TRT_PB_SZ_PER_LAN_DEDICATE_DFLT;
	conf->trt_pb_sz_tmp_buf_size_dflt = NSE_AMBER_ASIC_TRT_PB_SZ_TMP_BUF_SIZE_DFLT;

	conf->meter_tick_ns = NSE_AMBER_ASIC_METER_TICK_NS;

	conf->sched_se_table_size = NSE_AMBER_ASIC_SCHED_SE_TABLE_SIZE;
	conf->sched_node_table_size = NSE_AMBER_ASIC_SCHED_NODE_TABLE_SIZE;
	conf->sched_qid2lnid_table_size = NSE_AMBER_ASIC_SCHED_QID2LNID_TABLE_SIZE;
	conf->sched_qid2lnid_table_tdm_pe_boundary_offset =
		NSE_AMBER_ASIC_SCHED_QID2LNID_TABLE_TDM_PE_BOUNDARY_OFFSET;
	conf->sched_node_table_initial_tree_size =
		NSE_AMBER_ASIC_SCHED_NODE_TABLE_INITIAL_TREE_SIZE;
	conf->sched_node_table_available_size = NSE_AMBER_ASIC_SCHED_NODE_TABLE_AVAILABLE_SIZE;
}

static void nse_init_hw_conf_amber_fpga(struct nse_hw *hw)
{
	struct nse_hw_conf *conf = &hw->hw_conf;

	conf->hw_platform = NSE_HW_PLATFORM_FPGA;

	conf->main_clock_freq = NSE_AMBER_FPGA_MAIN_CLOCK_FREQ;

	conf->ptp_ref_clock_freq = conf->main_clock_freq;	/* 25 MHz*/

	conf->max_pf_per_lan_channel = NSE_AMBER_FPGA_MAX_PF_PER_LAN_CHANNEL;

	conf->max_bandwidth_per_lan_channel = NSE_AMBER_FPGA_MAX_BANDWIDTH_PER_LAN_CHANNEL;

	conf->max_vsi_space = NSE_AMBER_FPGA_MAX_VSI_SPACE;
	conf->max_irq_space = NSE_AMBER_FPGA_MAX_IRQ_SPACE;
	conf->max_lan_rxq_space = NSE_AMBER_FPGA_MAX_LAN_RXQ_SPACE;
	conf->max_lan_txq_space = NSE_AMBER_FPGA_MAX_LAN_TXQ_SPACE;
	conf->max_lan_txcq_space = NSE_AMBER_FPGA_MAX_LAN_TXCQ_SPACE;

	conf->max_rdma_qset_space = NSE_AMBER_FPGA_MAX_RDMA_QSET_SPACE;

	conf->fdir_table_size = NSE_AMBER_FPGA_FDIR_TABLE_SIZE;
	conf->fdir_max_num_pfilter = NSE_AMBER_FPGA_FDIR_MAX_NUM_PFILTER;
	conf->fdir_max_num_sfilter = NSE_AMBER_FPGA_FDIR_MAX_NUM_SFILTER;

	if (nse_qos_db_use_share)
		conf->max_tc_allowed = 8;
	else
		conf->max_tc_allowed = 4;

	conf->rpb_pb_total_size_per_lan = NSE_AMBER_FPGA_RPB_PB_TOTAL_SIZE_PER_LAN;
	conf->rpb_pb_total_size_per_lan_channel = NSE_AMBER_FPGA_RPB_PB_TOTAL_SIZE_PER_LAN_CHANNEL;

	conf->tdb_pb_sz_total = NSE_AMBER_FPGA_TDB_PB_SZ_TOTAL;

	conf->trt_pb_sz_total = NSE_AMBER_FPGA_TRT_PB_SZ_TOTAL;
	conf->trt_pb_sz_per_lan_dedicated_dflt = NSE_AMBER_FPGA_TRT_PB_SZ_PER_LAN_DEDICATE_DFLT;
	conf->trt_pb_sz_tmp_buf_size_dflt = NSE_AMBER_FPGA_TRT_PB_SZ_TMP_BUF_SIZE_DFLT;

	conf->meter_tick_ns = NSE_AMBER_FPGA_METER_TICK_NS;

	conf->sched_se_table_size = NSE_AMBER_FPGA_SCHED_SE_TABLE_SIZE;
	conf->sched_node_table_size = NSE_AMBER_FPGA_SCHED_NODE_TABLE_SIZE;
	conf->sched_qid2lnid_table_size = NSE_AMBER_FPGA_SCHED_QID2LNID_TABLE_SIZE;
	conf->sched_qid2lnid_table_tdm_pe_boundary_offset =
		NSE_AMBER_FPGA_SCHED_QID2LNID_TABLE_TDM_PE_BOUNDARY_OFFSET;
	conf->sched_node_table_initial_tree_size =
		NSE_AMBER_FPGA_SCHED_NODE_TABLE_INITIAL_TREE_SIZE;
	conf->sched_node_table_available_size = NSE_AMBER_FPGA_SCHED_NODE_TABLE_AVAILABLE_SIZE;
}

static void nse_init_hw_conf_moonstone(struct nse_hw *hw)
{
	struct nse_hw_conf *conf = &hw->hw_conf;

	conf->hw_platform = NSE_HW_PLATFORM_FPGA;

	conf->main_clock_freq = NSE_MOONSTONE_MAIN_CLOCK_FREQ;

	conf->ptp_ref_clock_freq = 200000000;		/* 200 MHz */

	conf->max_pf_per_lan_channel = NSE_MOONSTONE_MAX_PF_PER_LAN_CHANNEL;

	conf->max_bandwidth_per_lan_channel = NSE_MOONSTONE_MAX_BANDWIDTH_PER_LAN_CHANNEL;

	conf->max_vsi_space = NSE_MOONSTONE_MAX_VSI_SPACE;
	conf->max_irq_space = NSE_MOONSTONE_MAX_IRQ_SPACE;
	conf->max_lan_rxq_space = NSE_MOONSTONE_MAX_LAN_RXQ_SPACE;
	conf->max_lan_txq_space = NSE_MOONSTONE_MAX_LAN_TXQ_SPACE;
	conf->max_lan_txcq_space = NSE_MOONSTONE_MAX_LAN_TXCQ_SPACE;

	conf->max_rdma_qset_space = NSE_MOONSTONE_MAX_RDMA_QSET_SPACE;

	conf->max_tc_allowed = 8;

	conf->rpb_pb_total_size_per_lan = NSE_MOONSTONE_RPB_PB_TOTAL_SIZE_PER_LAN;
	conf->rpb_pb_total_size_per_lan_channel = NSE_MOONSTONE_RPB_PB_TOTAL_SIZE_PER_LAN_CHANNEL;

	conf->tdb_pb_sz_total = NSE_MOONSTONE_TDB_PB_SZ_TOTAL;

	conf->sched_se_table_size = NSE_MOONSTONE_SCHED_SE_TABLE_SIZE;
	conf->sched_node_table_size = NSE_MOONSTONE_SCHED_NODE_TABLE_SIZE;
	conf->sched_qid2lnid_table_size = NSE_MOONSTONE_SCHED_QID2LNID_TABLE_SIZE;
	conf->sched_qid2lnid_table_tdm_pe_boundary_offset =
		NSE_MOONSTONE_SCHED_QID2LNID_TABLE_TDM_PE_BOUNDARY_OFFSET;
	conf->sched_node_table_initial_tree_size = NSE_MOONSTONE_SCHED_NODE_TABLE_INITIAL_TREE_SIZE;
	conf->sched_node_table_available_size = NSE_MOONSTONE_SCHED_NODE_TABLE_AVAILABLE_SIZE;

	set_bit(NSE_HW_STATIC_FEA_TDM_ONLY_CQ_WB, conf->hw_static_fea);
	clear_bit(NSE_HW_STATIC_FEA_TDM_SUPPORT_TNL_CSUM, conf->hw_static_fea);
	clear_bit(NSE_HW_STATIC_FEA_TDM_SUPPORT_TNL_TSO, conf->hw_static_fea);
	clear_bit(NSE_HW_STATIC_FEA_TDM_SUPPORT_UP_ENFORCE, conf->hw_static_fea);
	clear_bit(NSE_HW_STATIC_FEA_TDM_SUPPORT_PVID, conf->hw_static_fea);
	set_bit(NSE_HW_STATIC_FEA_TDM_ONLY_HANDLE_L2TAG1, conf->hw_static_fea);

	clear_bit(NSE_HW_STATIC_FEA_RDM_HAVE_RSC, conf->hw_static_fea);
	clear_bit(NSE_HW_STATIC_FEA_RDM_SUPPORT_FLEX_RXDID, conf->hw_static_fea);

	clear_bit(NSE_HW_STATIC_FEA_RCF_HAVE_FDIR, conf->hw_static_fea);

	clear_bit(NSE_HW_STATIC_FEA_DB_HAVE_TRT, conf->hw_static_fea);
	clear_bit(NSE_HW_STATIC_FEA_DB_RPB_SHARED_BY_MULTI_PORTS, conf->hw_static_fea);

	clear_bit(NSE_HW_STATIC_FEA_PSR_SUPPORT_TNL, conf->hw_static_fea);

	clear_bit(NSE_HW_STATIC_FEA_SWITCH_FLEX, conf->hw_static_fea);
	set_bit(NSE_HW_STATIC_FEA_SWITCH_LEGACY, conf->hw_static_fea);
	set_bit(NSE_HW_STATIC_FEA_SWITCH_ONLY_VEPA, conf->hw_static_fea);

	clear_bit(NSE_HW_STATIC_FEA_PTP_SUPPORT_FINE_MODE, conf->hw_static_fea);

	clear_bit(NSE_HW_STATIC_FEA_MISC_SUPPORT_HW_LAG, conf->hw_static_fea);

	clear_bit(NSE_HW_STATIC_FEA_MISC_SUPPORT_VIRTIO, conf->hw_static_fea);

	clear_bit(NSE_HW_STATIC_FEA_MISC_SUPPORT_SIOV, conf->hw_static_fea);

	clear_bit(NSE_HW_STATIC_FEA_MISC_SUPPORT_SCTP_CRC, conf->hw_static_fea);

	clear_bit(NSE_HW_STATIC_FEA_MISC_SUPPORT_WOL, conf->hw_static_fea);

	clear_bit(NSE_HW_DYN_FEA_BAR2_MAPPED_FOR_FWMNG_FLASH, conf->hw_dyn_fea);
	set_bit(NSE_HW_DYN_FEA_BAR2_MAPPED_FOR_PE, conf->hw_dyn_fea);

	set_bit(NSE_HW_DYN_FEA_SUPPORT_RDMA, conf->hw_dyn_fea);

	conf->hw_lmac_type = NSE_HW_LMAC_TYPE_2;
}

enum nse_status nse_init_hw_conf(struct nse_hw *hw)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_hw_func_caps *func_caps = &hw->func_caps;
	struct nse_hw_conf *conf = &hw->hw_conf;

	if (hw->mac_type == NSE_MAC_TYPE_AMBER) {
		nse_init_hw_conf_amber_fpga(hw);

		if (func_caps->hw_platform_valid &&
			func_caps->hw_platform == NSE_HW_PLATFORM_ASIC) {
			nse_init_hw_conf_amber_asic(hw);
		}

		nse_init_hw_conf_amber_common(hw);

	} else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE) {
		nse_init_hw_conf_moonstone(hw);
	}

	/* some sanity check
	 */
	if (conf->hw_lmac_type == NSE_HW_LMAC_TYPE_UNKNOWN) {
		dev_err(dev, "[%s] BAD: lmac_type unknown\n", __func__);
		return NSE_ERR_NOT_SUPPORTED;
	}

	return NSE_SUCCESS;
}

