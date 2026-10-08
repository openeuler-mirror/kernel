/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef _GRC_HW_RDMA_H_
#define _GRC_HW_RDMA_H_
#include <linux/delay.h>
#include "grc_main.h"
#include "regs_v2/nbl_reg_base.h"
#include "regs_v2/nbl_reg_ceaq.h"
#include "regs_v2/nbl_reg_cc.h"
#include "regs_v2/nbl_reg_cqcc.h"
#include "regs_v2/nbl_reg_dsch.h"
#include "regs_v2/nbl_reg_epro.h"
#include "regs_v2/nbl_reg_hdma.h"
#include "regs_v2/nbl_reg_ipro.h"
#include "regs_v2/nbl_reg_pcompleter.h"
#include "regs_v2/nbl_reg_mrtc.h"
#include "regs_v2/nbl_reg_ntfqp.h"
#include "regs_v2/nbl_reg_padapt.h"
#include "regs_v2/nbl_reg_ped.h"
#include "regs_v2/nbl_reg_qpcc.h"
#include "regs_v2/nbl_reg_qm.h"
#include "regs_v2/nbl_reg_raqp.h"
#include "regs_v2/nbl_reg_rdma_top.h"
#include "regs_v2/nbl_reg_rxp.h"
#include "regs_v2/nbl_reg_sqrqec.h"
#include "regs_v2/nbl_reg_srqc.h"
#include "regs_v2/nbl_reg_stat.h"
#include "regs_v2/nbl_reg_top_ctrl.h"
#include "regs_v2/nbl_reg_txp.h"
#include "regs_v2/nbl_reg_txm.h"
#include "regs_v2/nbl_reg_txmr.h"

#define NBL_RW_RDMA_REG 1 /* set to 1 when on board */

#define NBL_RDMA_CQP_HW_TIMEOUT 200 /* cqp timeout 200ms */
#define NBL_RDMA_SYS_CLK 600 /* 600M clock in real asic */
#define NBL_RDMA_CQP_CLK_MULTIPLY 1000 /* calc cqp timeout cnt */

/* Now nbl_v2 GRC Draco default, TODO: V3-Orion need hw version to base addr
 * Draco reg base addr define Begin
 */
#define NBL_REG_RDMA_TOP 0x01000000 /* lb_rdma_top base addr */
#define NBL_REG_CQPP_BASE 0x01010000 /* cqpp base addr */
#define NBL_REG_HDMA_BASE 0x01020000 /* hdma base addr */
#define NBL_REG_TXMR_BASE 0x01040000 /* txmr module base addr */
#define NBL_REG_TXM_BASE 0x01050000 /* txm module base addr */
#define NBL_REG_CEAQ_BASE 0x010a0000 /* ceaq module base addr */
#define NBL_REG_STAT_BASE 0x01190000 /* stat base addr */
#define NBL_REG_TXP_BASE 0x01030000 /* txp base addr */
#define NBL_REG_CC_BASE 0x01110000 /* cc base addr */
#define NBL_REG_QPCC_BASE 0x010d0000 /* qpc cache base addr */
#define NBL_REG_CQCC_BASE 0x010e0000 /* cqc cache base addr */
#define NBL_REG_MRTC_BASE 0x010f0000 /* mrte cache base addr */
#define NBL_REG_SRQC_BASE 0x01200000 /* mrte cache base addr */
#define NBL_REG_SQRQEC_BASE 0x01120000 /* sqrqe cache base addr */
#define NBL_REG_RXP_BASE  0x01060000 /* rxp base addr */
#define NBL_REG_RAQP_BASE 0x01090000 /* raqp base addr */
#define NBL_REG_NTFQP_BASE 0x01240000 /* ntfqp base addr */

#define NBL_GRC_DSCH_BASE 0x00100000 /* rdma scheduler base addr */
#define NBL_GRC_UQM_BASE 0x00034000 /* Draco UQM and QM is same */
#define NBL_GRC_PCOMP_BASE	0x00F20000 /* Pcompleter base addr */
#define NBL_GRC_PED_BASE 0x74000 /* PED module base addr */
#define NBL_GRC_EPRO_BASE 0x00e40000 /* EPRO module base addr */
#define NBL_GRC_IPRO_BASE 0x00510000 /* IPRO module base addr */

/* common define */
enum nbl_ib_dbg_cc_param_types {
	/* golbal */
	NBL_CFG_CC_MODE,
	NBL_CFG_CC_EN,
	/* nbl-cc */
	NBL_CFG_CC_SAVE,
	NBL_CFG_CC_OAMREQ_TC_EN,
	NBL_CFG_CC_OAMREQ_NET_TC,
	NBL_CFG_CC_OAMACK_TC_EN,
	NBL_CFG_CC_OAMACK_NET_TC,
	NBL_CFG_CC_OAMACK_BLK_TH,
	NBL_CFG_CC_TARGETWIN_MIN,
	NBL_CFG_CC_PKT_NUM_EN,

	NBL_CFG_CC_HIGH_RTT_FRACTION,
	NBL_CFG_CC_LOW_RTT_FRACTION,
	NBL_CFG_CC_INC_TARWINTH,
	NBL_CFG_CC_DEC_TARWINTH,
	NBL_CFG_CC_TARGETWIN,
	NBL_CFG_CC_RTT_OFFSET,
	NBL_CFG_CC_RTT_PROBE_INVL,
	NBL_CFG_CC_HIGH_PRI_RTT_INVL,
	NBL_CFG_CC_HIGH_PRI_RTT_EN,
	NBL_CFG_CC_RST_WIN_HIGH,
	NBL_CFG_CC_RST_WIN_EN,
	NBL_CFG_CC_RST_WIN_LOW,
	NBL_CFG_CC_RST_WIN_RTT_INT,
	NBL_CFG_CC_RST_WIN_RTT_FRACTION,
	NBL_CFG_CC_DYN_RTT_OFFSET_EN,
	NBL_CFG_CC_REMOVE_REMOTE_TIME,
	NBL_CFG_CC_HIGH_RTT_INT,
	NBL_CFG_CC_LOW_RTT_INT,
	NBL_CFG_CC_RDMA_TIME_SEL,
	NBL_CFG_CC_CMP_RTT_QP_MULT,
	NBL_CFG_CC_LOW_RTT_OFFSET,
	NBL_CFG_CC_HIGH_RTT_OFFSET,
	NBL_CFG_CC_RST_WIN_RTT_OFFSET,
	NBL_CFG_CC_TARGET_RTTMIN,
	NBL_CFG_CC_TXP_SENDREQ_DB_CFG,
	/* nbl-qcn */
	NBL_CFG_CC_QCN_SAVE,
	NBL_CFG_QCN_RR_MODE,
	NBL_CFG_QCN_MID_SENDBLK_TH_HIGH,
	NBL_CFG_QCN_MID_SENDBLK_TH_LOW,
	NBL_CFG_QCN_MID_SENDTIME_TH_HIGH,
	NBL_CFG_QCN_MID_SENDTIME_TH_LOW,
	NBL_CFG_QCN_RR_TH,
	NBL_CFG_QCN_AI_RP,
	NBL_CFG_QCN_HAI_RP,
	NBL_CFG_QCN_MIN_RATE_RP,
	NBL_CFG_QCN_MAX_RATE_RP,
	NBL_CFG_QCN_QUICK_START_FLAG,
	NBL_CFG_QCN_SENDCNP_FLAG,
	NBL_CFG_QCN_SENDCNP_TIME_TH,
	NBL_CFG_QCN_START_RATE,
	NBL_CFG_QCN_EXTRA_QUANTA,
	NBL_CFG_QCN_FAST_REDUCE_MODE,
	NBL_CFG_QCN_REDUCE_COE,
	NBL_CFG_QCN_TIME_ACCUM,
	NBL_CFG_QCN_USE_HAI_EN,
	NBL_CFG_QCN_QUANTA_CC2TXP,
	NBL_CFG_CC_TYPE_MAX,
};

#define NBL_RQDB_DROP_INT_MASK BIT(11)

#define NBL_SD_REG_VALID_LEN 1
#define NBL_SD_REG_START_LEN 11
#define NBL_SD_REG_CNT_LEN 12
#define NBL_BDF_TBL_HOST_EN_LEN 1

struct nbl_hw_error_code {
	bool drop;
	bool normal_cqe; /* send normal cqe */
	bool abnormal_cqe; /* send error cqe */
	bool ae; /* send ae */
	u8 err_code;
};

#define DSCH_RDMA_MAX_RETRY_COUNT 20
#define DSCH_RDMA_DISABLE_DELAY_TIME 100

#define NBL_RDMA_MAX_FUNCTION_ID 63

#define NBL_RDMA_SYS_CLK_EMU 1
#define NBL_RDMA_SYS_CLK_S2C 28
#define NBL_RDMA_SYS_CLK_S2C_90M 90
#define NBL_RDMA_SYS_CLK_4P 9
#define NBL_PROTO_ENV_EMU 0xE20F
#define NBL_PROTO_ENV_4FPGA 0xF4AF
#define NBL_PROTO_ENV_1FPGA 0xF120
#define NBL_PROTO_ENV_1FPGA_HP 0xF121
#define NBL_RROTO_CQPP_TIMEOUT 3 /* 1024 ms */
#define NBL_RDMA_SYS_CLK_SNIC_V2 450 /* ASIC_V2R1 defaut rdma freq MHz */

#define MIRROR_NEXT_STG_ID BIT(15)
#define MIRROR_SET_DEST_ENABLE BIT(7)
#define MIRROR_RDMA_FLAG BIT(6)
#define MIRROR_RDMA_FLAG_MASK BIT(6)
#define MIRROR_QPN_UDI_ID 6 /* udi index for get rdma dump dest qpn from udf */
#define MIRROR_ID_UDI_ID 7 /* udi index for get mirror_id from udf */
#define MIRROR_ID_VLD BIT(7)

/*Global*/
/*CFG*/
#define NBL_QOS_DEFAULT_SQ_PRI_MAP 0xd10 /* 0,2,4,6,0,0,0,0 */
#define NBL_QOS_DEFAULT_RAQ_PRI_MAP 0xf59 /* 1,3,5,7,0,0,0,0 */
#define NBL_QOS_DEFAULT_PRI_IMAP 0x006d2240 /* 0x3,0x0c,0x30,0xc0,0,0,0,0 */
#define NBL_QOS_DEFAULT_PFC03_MAP 0xc0300c03
#define NBL_QOS_DEFAULT_PFC47_MAP 0
#define NBL_QOS_DEFAULT_CSCH_QLEN_TH 0x100
#define NBL_QOS_DEFAULT_DB_TOCSCH_EN 0x0
#define NBL_QOS_DEFAULT_SW_DB_IN_CSCH_TH 0x80
#define NBL_QOS_DEFAULT_PRI03_P2S_MAP 0x02020101
#define NBL_QOS_DEFAULT_PRI47_P2S_MAP 0x08080404

#endif /* _GRC_HW_RDMA_H_ */
