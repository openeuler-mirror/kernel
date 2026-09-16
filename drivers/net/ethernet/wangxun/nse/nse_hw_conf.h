/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_HW_CONF_H
#define _NSE_HW_CONF_H

#include <linux/kernel.h>
#include <linux/types.h>

#include "nse_hw_conf_amber_asic.h"
#include "nse_hw_conf_amber_fpga.h"
#include "nse_hw_conf_moonstone.h"

enum nse_hw_platform {
	NSE_HW_PLATFORM_ASIC,
	NSE_HW_PLATFORM_FPGA,

	NSE_HW_PLATFORM_MAX,
};

enum nse_hw_static_fea_flags {
	NSE_HW_STATIC_FEA_TDM_ONLY_CQ_WB,

	NSE_HW_STATIC_FEA_TDM_SUPPORT_TNL_CSUM,

	NSE_HW_STATIC_FEA_TDM_SUPPORT_TNL_TSO,

	NSE_HW_STATIC_FEA_TDM_SUPPORT_UP_ENFORCE,

	NSE_HW_STATIC_FEA_TDM_SUPPORT_PVID,

	NSE_HW_STATIC_FEA_TDM_ONLY_HANDLE_L2TAG1,

	NSE_HW_STATIC_FEA_RDM_HAVE_RSC,

	NSE_HW_STATIC_FEA_RDM_SUPPORT_FLEX_RXDID,

	NSE_HW_STATIC_FEA_RCF_HAVE_FDIR,

	NSE_HW_STATIC_FEA_DB_HAVE_TRT,

	NSE_HW_STATIC_FEA_DB_RPB_SHARED_BY_MULTI_PORTS,

	NSE_HW_STATIC_FEA_PSR_SUPPORT_TNL,

	NSE_HW_STATIC_FEA_SWITCH_FLEX,

	NSE_HW_STATIC_FEA_SWITCH_LEGACY,

	NSE_HW_STATIC_FEA_SWITCH_ONLY_VEPA,

	NSE_HW_STATIC_FEA_PTP_SUPPORT_FINE_MODE,

	NSE_HW_STATIC_FEA_MISC_SUPPORT_HW_LAG,

	NSE_HW_STATIC_FEA_MISC_SUPPORT_VIRTIO,

	NSE_HW_STATIC_FEA_MISC_SUPPORT_SIOV,

	NSE_HW_STATIC_FEA_MISC_SUPPORT_SCTP_CRC,

	NSE_HW_STATIC_FEA_MISC_SUPPORT_WOL,

	NSE_HW_STATIC_FEA_FLAGS_NBITS	/* must be last */
};

enum nse_hw_dyn_fea_flags {
	NSE_HW_DYN_FEA_BAR2_MAPPED_FOR_FWMNG_FLASH,
	NSE_HW_DYN_FEA_BAR2_MAPPED_FOR_PE,

	NSE_HW_DYN_FEA_SUPPORT_RDMA,

	NSE_HW_DYN_FEA_FLAGS_NBITS	/* must be last */
};

struct nse_hw_conf {
	enum nse_hw_platform hw_platform;	/* ASIC/PLDM, or FPGA */

	unsigned int main_clock_freq;		/* in HZ */

	unsigned int ptp_ref_clock_freq;	/* in HZ */

	unsigned int max_pf_per_lan_channel;

	unsigned int max_bandwidth_per_lan_channel;

	unsigned short max_vsi_space;	/* NSE_MAX_VSI is max-max */
	unsigned short max_irq_space;
	unsigned short max_lan_rxq_space;
	unsigned short max_lan_txq_space;
	unsigned short max_lan_txcq_space;

	unsigned short max_rdma_qset_space;

	unsigned int fdir_table_size;
	unsigned int fdir_max_num_pfilter;
	unsigned int fdir_max_num_sfilter;

	unsigned int max_tc_allowed;

	unsigned int rpb_pb_total_size_per_lan;
	unsigned int rpb_pb_total_size_per_lan_channel;

	unsigned int tdb_pb_sz_total;

	unsigned int trt_pb_sz_total;
	unsigned int trt_pb_sz_per_lan_dedicated_dflt;
	unsigned int trt_pb_sz_tmp_buf_size_dflt;

	unsigned int meter_tick_ns;

	unsigned int sched_se_table_size;
	unsigned int sched_node_table_size;
	unsigned int sched_qid2lnid_table_size;
	unsigned int sched_qid2lnid_table_tdm_pe_boundary_offset;
	unsigned int sched_node_table_initial_tree_size;
	unsigned int sched_node_table_available_size;

	unsigned int hw_lmac_type;
#define NSE_HW_LMAC_TYPE_UNKNOWN	0x0
#define NSE_HW_LMAC_TYPE_1			0x1
#define NSE_HW_LMAC_TYPE_2			0x2

	unsigned int hw_lpcs_type;
#define NSE_HW_LPCS_TYPE_UNKNOWN	0x0
#define NSE_HW_LPCS_TYPE_1			0x1

	unsigned int hw_lphy_internal_type;
#define NSE_HW_LPHY_INTERNAL_TYPE_UNKNOWN	0x0
#define NSE_HW_LPHY_INTERNAL_TYPE_1			0x1

	/* shortcut to nse_lmac_phy_info->ephy_info.ephy_type: NSE_AQC_ETYPE_TYPE_XXX */
	unsigned int hw_lphy_external_type;

	DECLARE_BITMAP(hw_static_fea, NSE_HW_STATIC_FEA_FLAGS_NBITS);
	DECLARE_BITMAP(hw_dyn_fea, NSE_HW_DYN_FEA_FLAGS_NBITS);
};

/* Some common items are defined here, not differentiate between ASIC and FPGA
 */
#define NSE_SCHED_INITIAL_SE_ROOT_SEID		0	// (0 >> 1)
#define NSE_SCHED_INITIAL_NODE_ROOT_TNID			0

#endif	/* _NSE_HW_CONF_H */

