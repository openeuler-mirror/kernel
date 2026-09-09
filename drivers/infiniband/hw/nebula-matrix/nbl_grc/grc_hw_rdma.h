/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef _GRC_HW_RDMA_H_
#define _GRC_HW_RDMA_H_
#include <linux/delay.h>
#include "grc_main.h"

#define NBL_RW_RDMA_REG 1 /* set to 1 when on board */

#define NBL_RDMA_CQP_HW_TIMEOUT 200 /* cqp timeout 200ms */
#define NBL_RDMA_SYS_CLK 600 /* 600M clock in real asic */
#define NBL_RDMA_CQP_CLK_MULTIPLY 1000 /* calc cqp timeout cnt */

#define NBL_REG_RDMA_TOP 0x01100000 /* lb_rdma_top base addr */
#define NBL_REG_CQPP_BASE 0x01110000 /* cqpp base addr */
#define NBL_REG_HDMA_BASE 0x01120000 /* hdma base addr */
#define NBL_REG_TXMR_BASE 0x01140000 /* txmr module base addr */
#define NBL_REG_TXM_BASE 0x01150000 /* txm module base addr */
#define NBL_REG_CEAQ_BASE 0x011a0000 /* ceaq module base addr */
#define NBL_REG_STAT_BASE 0x01290000 /* stat base addr */
#define NBL_REG_TXP_BASE 0x01130000 /* txp base addr */
#define NBL_REG_CC_BASE 0x01210000 /* cc base addr */
#define NBL_REG_QPCC_BASE 0x011d0000 /* qpc cache base addr */
#define NBL_REG_CQCC_BASE 0x011e0000 /* cqc cache base addr */
#define NBL_REG_MRTC_BASE 0x011f0000 /* mrte cache base addr */
#define NBL_REG_SQRQEC_BASE 0x01220000 /* sqrqe cache base addr */
#define NBL_REG_RDMA_TOP 0x01100000 /* rdma top */
#define NBL_RDMA_MAX_MODULES 25

#define NBL_REG_QPC_IDLE_BLOCK_FIFO_THR_HIGH (NBL_REG_QPCC_BASE + 0x00b4)
#define NBL_REG_QPC_IDLE_BLOCK_FIFO_THR_LOW (NBL_REG_QPCC_BASE + 0x00b8)
#define NBL_REG_QPC_CACHE_DEPTH 512
#define NBL_REG_CQC_IDLE_BLOCK_FIFO_THR_HIGH (NBL_REG_CQCC_BASE + 0x00b4)
#define NBL_REG_CQC_IDLE_BLOCK_FIFO_THR_LOW (NBL_REG_CQCC_BASE + 0x00b8)
#define NBL_REG_CQC_CACHE_DEPTH 512
#define NBL_REG_MRTE_IDLE_BLOCK_FIFO_THR_HIGH (NBL_REG_MRTC_BASE + 0x00b4)
#define NBL_REG_MRTE_IDLE_BLOCK_FIFO_THR_LOW (NBL_REG_MRTC_BASE + 0x00b8)
#define NBL_REG_MRTE_CACHE_DEPTH 512
#define NBL_REG_SQRQE_IDLE_BLOCK_FIFO_THR_HIGH (NBL_REG_SQRQEC_BASE + 0x00b4)
#define NBL_REG_SQRQE_IDLE_BLOCK_FIFO_THR_LOW (NBL_REG_SQRQEC_BASE + 0x00b8)
#define NBL_REG_SQRQE_CACHE_DEPTH 512
#define NBL_RDMA_TOP_HDMA_DIF_VFID (NBL_REG_RDMA_TOP + 0x00000024)
#define NBL_RDMA_STATS_OP_INFO (NBL_REG_STAT_BASE + 0x0040)
#define NBL_RDMA_STATS_OP_DMA_ADDR_L (NBL_REG_STAT_BASE + 0x0044)
#define NBL_RDMA_STATS_OP_DMA_ADDR_H (NBL_REG_STAT_BASE + 0x0048)
#define NBL_RDMA_STATS_FUNC_ID (NBL_REG_STAT_BASE + 0x004c)
#define NBL_RDMA_STATS_OP_ERR_OPCODE_EN (NBL_REG_STAT_BASE + 0x0050)

#define NBL_REG_CQPP_CTRL (NBL_REG_CQPP_BASE + 0x0108)
#define NBL_REG_CQPP_MAX_FUN_ID (NBL_REG_CQPP_BASE + 0x010c)
#define NBL_REG_CQPP_TIMEOUT_CNT (NBL_REG_CQPP_BASE + 0x011c)
#define NBL_REG_SRC_ADDR_TBL_BASE (NBL_REG_TXM_BASE + 0x1000)
#define NBL_REG_CQPP_INTRRUPT_MASK (NBL_REG_CQPP_BASE + 0x0004)

#define NBL_REG_CC_TXP_SENDREQ_DB_CFG		(NBL_REG_TXP_BASE + 0X0414)

#define NBL_REG_CC_RTTMINTH_COE				(NBL_REG_CC_BASE + 0x0100)
#define NBL_REG_CC_INC_TARGET_WIN_TH		(NBL_REG_CC_BASE + 0x0104)
#define NBL_REG_CC_DEC_TARGET_WIN_TH		(NBL_REG_CC_BASE + 0x0108)

#define NBL_REG_CC_RTT_OFFSET				(NBL_REG_CC_BASE + 0x0110)
#define NBL_REG_CC_RTT_PROBE_INVL			(NBL_REG_CC_BASE + 0x011c)
#define NBL_REG_CC_HIGH_PRI_RTT_INVL		(NBL_REG_CC_BASE + 0x0120)
#define NBL_REG_CC_HIGH_RPI_RTT_EN			(NBL_REG_CC_BASE + 0x0124)
#define NBL_REG_CC_RST_WIN_H				(NBL_REG_CC_BASE + 0x0128)
#define NBL_REG_CC_RST_WIN_EN				(NBL_REG_CC_BASE + 0x012c)
#define NBL_REG_CC_RST_WIN_L				(NBL_REG_CC_BASE + 0x0130)
#define NBL_REG_CC_RST_TARGETWIN_RTTCOE		(NBL_REG_CC_BASE + 0x0134)
#define NBL_REG_CC_DYN_RTT_OFFET_EN			(NBL_REG_CC_BASE + 0x0138)
#define NBL_REG_CC_REMOVE_REMOTE_TIME		(NBL_REG_CC_BASE + 0x013c)
#define NBL_REG_CC_AI_LESS_RTTMINTH			(NBL_REG_CC_BASE + 0x0140)
#define NBL_REG_CC_AI_MORE_RTTMINTH			(NBL_REG_CC_BASE + 0x0144)
#define NBL_REG_CC_AI_RST_WIN_RTTMINTH		(NBL_REG_CC_BASE + 0x0148)
#define NBL_REG_CC_RDMA_TIME_SEL			(NBL_REG_TXM_BASE + 0x0068)

#define NBL_REG_CC_EN						(NBL_REG_CC_BASE + 0x0200)
#define NBL_REG_QCN_RR_MODE					(NBL_REG_CC_BASE + 0x0204)
#define NBL_REG_QCN_MID_SENDBLK_TH_HIGH		(NBL_REG_CC_BASE + 0x0208)
#define NBL_REG_QCN_MID_SENDBLK_TH_LOW		(NBL_REG_CC_BASE + 0x020c)
#define NBL_REG_QCN_MID_SENDTIME_TH_HIGH	(NBL_REG_CC_BASE + 0x0210)
#define NBL_REG_QCN_MID_SENDTIME_TH_LOW		(NBL_REG_CC_BASE + 0x0214)
#define NBL_REG_QCN_RR_TH					(NBL_REG_CC_BASE + 0x0218)
#define NBL_REG_QCN_AI_RP					(NBL_REG_CC_BASE + 0x021c)
#define NBL_REG_QCN_HAI_RP					(NBL_REG_CC_BASE + 0x0220)
#define NBL_REG_QCN_MIN_RATE_RP				(NBL_REG_CC_BASE + 0x0224)
#define NBL_REG_QCN_MAX_RATE_RP				(NBL_REG_CC_BASE + 0x0228)
#define NBL_REG_QCN_QUICK_START_FLAG		(NBL_REG_CC_BASE + 0x022c)
#define NBL_REG_QCN_SENDCNP_FLAG			(NBL_REG_CC_BASE + 0x0230)
#define NBL_REG_QCN_SENDCNP_TIME_TH			(NBL_REG_CC_BASE + 0x0234)
#define NBL_REG_QCN_EXTRA_QUANTA			(NBL_REG_CC_BASE + 0x023c)
#define NBL_REG_QCN_FAST_REDUCE_MODE		(NBL_REG_CC_BASE + 0x0244)
#define NBL_REG_QCN_REDUCE_COE				(NBL_REG_CC_BASE + 0x0248)

#define NBL_REG_NET_TC_TBL_BASE (NBL_REG_TXM_BASE + 0x0500)

#define NBL_REG_TXMR_FMR_NOFENCE		(NBL_REG_TXMR_BASE + 0x00a8)

#define NBL_TXMR_NOFENCE_BIT0 1 /*bit0 txmr nofence*/
#define NBL_TXMR_READ_RESP_NOCHECK_BIT2 4 /*bit2 read resp no check*/

#define NBL_REG_ACL_BASE (0x00B64000)
#define NBL_REG_FLOW_STAT_BASE (NBL_REG_ACL_BASE + 0x30000)
#define NBL_REG_ECN_CNT(flow_id) ((NBL_REG_FLOW_STAT_BASE) + \
	(flow_id) * sizeof(union nbl_ecn_stat_tbl))

union nbl_ecn_stat_tbl {
	struct {
		u64 byte_cnt : 48;
		u64 pkt_cnt_low : 16;
		u64 pkt_cnt_high : 24;
		u64 rsv : 40;
	};
	u64 data[2];
};

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
	NBL_CFG_CC_TYPE_MAX,
};

union nbl_cqp_max_fun_id_reg {
	struct cqp_max_fun_id_key {
		u32 max_fun_id : 6;
		u32 rsv0 : 25;
		u32 max_fun_id_vld : 1;
	} key;
	u32 data;
};

#define NBL_REG_CQPINFO_TBL_RAM (NBL_REG_CQPP_BASE + 0x1000) /* cqp info table ram */
#define NBL_REG_CQPINFO_PI_INDEX 1
union nbl_cqp_info_tbl_reg {
	struct cqp_info_tbl_key {
		u32 cqp_ci : 5;
		u32 cqp_ci_odd_even_flag : 1;
		u32 rsv0 : 26;

		u32 cqp_pi : 5;
		u32 cqp_pi_odd_even_flag : 1;
		u32 rsv1 : 26;

		u32 cqp_len : 6;
		u32 rsv2 : 25;
		u32 cqp_info_vld : 1;

		u32 cqp_base_addr_low : 32;
		u32 cqp_base_addr_high : 32;
	} key;
#define CQP_INFO_TBL_KEY_REG_DW_SIZE (sizeof(struct cqp_info_tbl_key) / sizeof(u32))
	u32 data[CQP_INFO_TBL_KEY_REG_DW_SIZE];
};

#define NBL_REG_CQPINFO_TBL_RAM_ADDR(t) \
	(NBL_REG_CQPINFO_TBL_RAM + (CQP_INFO_TBL_KEY_REG_DW_SIZE * 4 * (t)))
#define NBL_RQDB_DROP_INT_MASK BIT(11)

#define NBL_REG_SDBASE_TBL_RAM (NBL_REG_CQPP_BASE + 0x2000) /* global sd base tbl ram */
#define NBL_REG_HDMA_BDF_TBL (NBL_REG_HDMA_BASE + 0x1000) /* hdma bdf table */

#define NBL_SD_REG_VALID_LEN 1
#define NBL_SD_REG_START_LEN 11
#define NBL_SD_REG_CNT_LEN 12
#define NBL_BDF_TBL_HOST_EN_LEN 1

/* HOST NOTIFY, pcompleter host */
#define RDMA_HOST_NOTIFY_OFFSET 0x00002000 /* host notify offset begin from bar0 */
#define NBL_PCOMP_HOST_PFID_MASTER_TBL_BASE 0
#define NBL_PCOMP_HOST_PFID_SLAVE_TBL_BASE 64
#define NBL_PCOMP_HOST_PFID_MAX_TBL_ENTRY 128

union nbl_sd_range_tbl_reg {
	u32 data[1];
	struct {
		u32 sd_max_num : 12;
		u32 rsv1 : 4;
		u32 sd_base_idx : 11;
		u32 rsv2 : 4;
		u32 sd_base_info_vld : 1;
	};
};

union nbl_hdma_bdf_tbl_reg {
	u32 data[1];
	struct {
		u32 function_id : 3;
		u32 device_id : 5;
		u32 bus_id : 8;
		u32 host_en : 1;
		u32 rsv : 15;
	};
};

/* Hardware Error Codes(all in one),
 * TODO, check each error code and change to NBL_ERR_
 */
#define NBL_ERR_DEST_QPN 0x2
#define NBL_ERR_CACHE_FLAG 0x3
#define NBL_ERR_INV_QPC 0x4
#define NBL_ERR_PDPA 0x5
#define NBL_ERR_TVER 0x8
#define NBL_ERR_SERVICE_TYPE 0x9
#define NBL_ERR_QPC_STATE 0xA
#define NBL_ERR_RX_PKT_QPC_MR_ERR 0xB
#define NBL_ERR_RX_PKT_ERR_RC_OPCODE 0xC
#define NBL_ERR_RX_PKT_ERR_UD_OPCODE 0xD
#define NBL_ERR_RX_PKT_ERR_ATOMIC_BYTE_ALIGN 0xE
#define NBL_ERR_RX_PKT_ERR_OAQ_PI_CI 0xF
#define NBL_ERR_RX_PKT_ERR_RESPONER_SEND_REQ_OPCODE 0x10
#define NBL_ERR_RX_PKT_ERR_WRITE_OPCODE 0x11
#define NBL_ERR_RX_PKT_ERR_SEND_REQ_OPCODE 0x12
#define NBL_ERR_RX_PKT_ERR_WRITE_REQ_OPCODE 0x13
#define NBL_ERR_RX_PKT_ERR_WRITE_PKT_LEN 0x14
#define NBL_ERR_RX_PKT_ERR_PKT_LEN 0x15
#define NBL_ERR_RX_PKT_ERR_HW_FLAG 0x16
#define NBL_ERR_RX_PKT_RECV_OPCODE_IN_RNR 0x17
#define NBL_ERR_RX_PKT_REQ_PKT_LEN_ERR 0x1A
#define NBL_ERR_RX_PKT_READ_RESP_PKT_LEN_OVERFLOW 0x1C
#define NBL_ERR_RX_PKT_READ_RESP_PKT_LEN_ILLEGAL 0x1D
#define NBL_ERR_RX_PKT_READ_RESP_PKT_LEN_TOOLONG 0x1E
#define NBL_ERR_RX_PKT_READ_RESP_OPCODE_OUT_ORDER 0x1F
#define NBL_ERR_RX_PKT_SEND_WRITE_REPEAT 0x20
#define NBL_ERR_RX_PKT_READ_ATOMIC_REPEAT_WITH_ACK 0x21
#define NBL_ERR_RX_PKT_READ_ATOMIC_REPEAT_NO_ACK 0x22
#define NBL_ERR_RX_PKT_LOST_REQ 0x23
#define NBL_ERR_RX_PKT_ERR_GOST_ACK 0x28
#define NBL_ERR_RX_PKT_REPEAT_RESP 0x29
#define NBL_ERR_RX_PKT_RECV_ACK_NEED_RAQ 0x2A
#define NBL_ERR_RX_PKT_LOST_RSP_NEED_RAQ 0x2B
#define NBL_ERR_RX_PKT_RECV_NACK_PSN_ERR_NEED_RAQ 0x2D
#define NBL_ERR_RX_PKT_RECV_NACK_RNR_NAK_NEED_RAQ 0x2E
#define NBL_ERR_RX_PKT_OUT_OF_ORDER 0x2F
#define NBL_ERR_RX_RESP_RECV_NOT_PSN_SEQ_ERR_NAK 0x30

#define NBL_ERR_RX_MR_INDEX_ILLEGAL 0x38
#define NBL_ERR_RX_MR_INVALID 0x39
#define NBL_ERR_RX_MR_KEY_ILLEGAL 0x3A
#define NBL_ERR_RX_PD_MISS_MATCH 0x3B
#define NBL_ERR_RX_ACCESS_RIGHT_CHECK_ERR 0x3C
#define NBL_ERR_RX_BOUNDARY_CHECK_ERR 0x3D
#define NBL_ERR_RX_REMOTE_INV_PERMISSION_CHK_ERR 0x3E
#define NBL_ERR_RX_REMOTE_INV_WITH_MW_STILL_BIND 0x3F
#define NBL_ERR_RX_REMOTE_INV_TO_TYPE1_MW 0x40
#define NBL_ERR_RX_MR_REQ_ERR 0x41
#define NBL_ERR_RX_MR_RESP_ERR 0x42
#define NBL_ERR_RX_MR_MRTC_ERR 0x43
#define NBL_ERR_RX_MR_PBLC_INV 0x44

#define NBL_ERR_RAQ_OVERFLOW 0x48
#define NBL_ERR_CQ_OVERFLOW 0x4A
#define NBL_ERR_CEQ_OVERFLOW 0x4B
#define NBL_ERR_AEQ_OVERFLOW 0x4C

#define NBL_ERR_TX_MR_INDEX_ILLEGAL 0x60
#define NBL_ERR_TX_MR_INVALID 0x61
#define NBL_ERR_TX_MR_KEY_ILLEGAL 0x62
#define NBL_ERR_TX_PD_MISS_MATCH 0x63
#define NBL_ERR_TX_ACCESS_RIGHT_CHECK_ERR 0x64
#define NBL_ERR_TX_BOUNDARY_CHECK_ERR 0x65
#define NBL_ERR_TX_LOCAL_INV_TO_TYPE1_MW 0x66
#define NBL_ERR_TX_REMOTE_INV_WITH_MW_STILL_BIND 0x67
#define NBL_ERR_TX_MR_BIND_INV_MR 0x68
#define NBL_ERR_TX_MR_BIND_INV_MW 0x69
#define NBL_ERR_TX_MR_BIND_KEY_BUT_FIND_MW 0x6A
#define NBL_ERR_TX_MR_BIND_KEY_BUT_FIND_MR 0x6B
#define NBL_ERR_TX_MR_BIND_INV_MR_TYPE 0x6C
#define NBL_ERR_TX_MR_BIND_INV_MW_TYPE 0x6D
#define NBL_ERR_TX_MR_BIND_MR_ZERO_BASE 0x6E
#define NBL_ERR_TX_MR_BIND_PD_INV 0x6F
#define NBL_ERR_TX_MR_BIND_RIGHT_INV 0x70
#define NBL_ERR_TX_MR_BIND_BOUNDARY_INV 0x71
#define NBL_ERR_TX_MR_REQ_ERR 0x72
#define NBL_ERR_TX_MR_RESP_ERR 0x73
#define NBL_ERR_TX_MR_MRTC_ERR 0x74
#define NBL_ERR_TX_MR_PBLC_INV 0x75

#define NBL_ERR_TXP_SQ_OP_INV 0x52
#define NBL_ERR_TXP_SQ_INV_OPCODE 0x53
#define NBL_ERR_TXP_SQ_WQE_INV 0x54
#define NBL_ERR_TXP_RAQ_TIMEOUT 0x55
#define NBL_ERR_TXP_RNR_TIMEOUT 0x56
/* HW error code end */

#define NBL_REG_CEAQ_EOT_BASE (NBL_REG_CEAQ_BASE + 0x1000)
union nbl_eot_table_reg {
	u32 data[1];
	struct eot_tbl_key {
		u32 ae_flag : 1;
		u32 abnorm_cqe_flag : 1;
		u32 norm_cqe_flag : 1;
		u32 drop_flag : 1;
		u32 rsv : 28;
	} key;
};

#define NBL_REG_EOT_TBL_ADDR(t) \
	(NBL_REG_CEAQ_EOT_BASE + (4 * (t)))

struct nbl_hw_error_code {
	bool msb;
	bool drop;
	bool normal_cqe; /* send normal cqe */
	bool abnormal_cqe; /* send error cqe */
	bool ae; /* send ae */
	u8 err_code;
};

#define RDMA_HDMA_BASE 0x01120000
#define RDMA_REG_HDMA_CPU_CTRL (RDMA_HDMA_BASE + 0x0804)
#define RDMA_HDMA_DIF_VF_EN BIT(2)

#define RDMA_DSCH_BASE 0x00404000
#define RDMA_N2G_CFG (RDMA_DSCH_BASE + 0x00080000)
#define RDMA_N2G_CFG_TBL(vf_id) (RDMA_N2G_CFG + 4 * (vf_id))
#define RDMA_G2P_CFG (RDMA_DSCH_BASE + 0x00084000)
#define RDMA_G2P_CFG_TBL(grp_id) (RDMA_G2P_CFG + 4 * (grp_id))
#define RDMA_TC_WGT_CFG (RDMA_DSCH_BASE + 0x00088000)
#define RDMA_TC_WGT_CFG_TBL(vf_id) (RDMA_TC_WGT_CFG + 8 * (vf_id))
#define RDMA_TC_SPWRR_CFG (RDMA_DSCH_BASE + 0x0008C000)
#define RDMA_TC_SPWRR_CFG_TBL(vf_id) (RDMA_TC_SPWRR_CFG + 4 * (vf_id))
#define RDMA_NET2SHA_MAP (RDMA_DSCH_BASE + 0x00090000)
#define RDMA_NET2SHA_MAP_TBL(vf_id) (RDMA_NET2SHA_MAP + 4 * (vf_id))
#define RDMA_GRP2SHA_MAP (RDMA_DSCH_BASE + 0x00094000)
#define RDMA_GRP2SHA_MAP_TBL(grp_id) (RDMA_GRP2SHA_MAP + 4 * (grp_id))
#define RDMA_SHA2NET_MAP (RDMA_DSCH_BASE + 0x00098000)
#define RDMA_SHA2NET_MAP_TBL(shaping_id) (RDMA_SHA2NET_MAP + 4 * (shaping_id))
#define RDMA_SHA2GRP_MAP (RDMA_DSCH_BASE + 0x0009C000)
#define RDMA_SHA2GRP_MAP_TBL(shaping_id) (RDMA_SHA2GRP_MAP + 4 * (shaping_id))

#define NBL_REG_DSCH_CSCH_QLEN_TH (RDMA_DSCH_BASE + 0x124)
#define NBL_REG_DSCH_POLL_WGT (RDMA_DSCH_BASE + 0x128)
#define NBL_REG_DSCH_DB_TO_CSCH_EN (RDMA_DSCH_BASE + 0x144)
#define NBL_REG_DSCH_SQ_PRI_MAP_CFG (RDMA_DSCH_BASE + 0x150)
#define NBL_REG_DSCH_RAQ_PRI_MAP_CFG (RDMA_DSCH_BASE + 0x154)
#define NBL_REG_DSCH_PRI03_MAP_CFG (RDMA_DSCH_BASE + 0x158)
#define NBL_REG_DSCH_PRI47_MAP_CFG (RDMA_DSCH_BASE + 0x15C)
#define NBL_REG_DSCH_IMAP_CFG (RDMA_DSCH_BASE + 0x160)
#define NBL_REG_DSCH_SW_DB_IN_CSCH_TH (RDMA_DSCH_BASE + 0x188)

#define DSCH_RDMA_NET_TC_SIZE 8
#define DSCH_RDMA_LNET_EN (RDMA_DSCH_BASE + 0x00000300)
#define DSCH_RDMA_HNET_EN (RDMA_DSCH_BASE + 0x00000304)
#define DSCH_RDMA_NET_EN_REGS_SIZE 32
#define DSCH_RDMA_DBQ_ATTR_TBL(vf_id) (RDMA_DSCH_BASE + 0x000C4000 + \
				       DSCH_RDMA_NET_TC_SIZE * 8 * (vf_id))
#define DSCH_RDMA_TC_Q_LIST_ATTR_TBL(vf_id) (RDMA_DSCH_BASE + 0x000C8000 + \
					     DSCH_RDMA_NET_TC_SIZE * 4 * (vf_id))
#define DSCH_RDMA_DBQ_ATTR_SIZE 8
#define DSCH_RDMA_TC_Q_LIST_ATTR_SIZE 4
#define DSCH_RDMA_DBQ_ATTR_TBL_NEMPTY BIT(31)
#define DSCH_RDMA_GRP_NET_LIST_TBL(net_id) (RDMA_DSCH_BASE + 0x000E0000 + 4 * (net_id))
#define DSCH_RDMA_SPT_GRP_LIST_TBL(grp_id)                                     \
	(RDMA_DSCH_BASE + 0x000D8000 + 4 * (grp_id))
#define DSCH_RDMA_MAX_RETRY_COUNT 20
#define DSCH_RDMA_DISABLE_DELAY_TIME 100
#define DSCH_RDMA_OTHER_ABN_INFO (RDMA_DSCH_BASE + 0x00000080)
#define DSCH_RDMA_OTHER_ABN BIT(14)
#define DSCH_RDMA_SW_DB_FULL 2
#define DSCH_RDMA_OTHER_ABN_INFO_MASK 0x1f

#define NBL_QOS_DEFAULT_SQ_PRI_MAP 0xd10 /* 0,2,4,6,0,0,0,0 */
#define NBL_QOS_DEFAULT_RAQ_PRI_MAP 0xf59 /* 1,3,5,7,0,0,0,0 */
#define NBL_QOS_DEFAULT_PRI_IMAP 0x006d2240 /* 0x3,0x0c,0x30,0xc0,0,0,0,0 */
#define NBL_QOS_DEFAULT_PFC03_MAP 0xc0300c03
#define NBL_QOS_DEFAULT_PFC47_MAP 0
#define NBL_QOS_DEFAULT_CSCH_QLEN_TH 0x100
#define NBL_QOS_DEFAULT_POLL_WGT 0x01010104
#define NBL_QOS_DEFAULT_SW_DB_IN_CSCH_TH 0x80

union rdma_n2g_cfg_tbl {
	u32 data[1];
	struct {
		u32 grp_id : 6;
		u32 rsv : 25;
		u32 vld : 1;
	};
};

union rdma_g2p_cfg_tbl {
	u32 data[1];
	struct {
		u32 cpu_type : 1;
		u32 port : 2;
		u32 rsv : 28;
		u32 vld : 1;
	};
};

union rdma_tc_wgt_cfg_tbl {
	u32 data[2];
	struct {
		u32 tc0_wgt : 8;
		u32 tc1_wgt : 8;
		u32 tc2_wgt : 8;
		u32 tc3_wgt : 8;
		u32 tc4_wgt : 8;
		u32 tc5_wgt : 8;
		u32 tc6_wgt : 8;
		u32 tc7_wgt : 8;
	};
};

union rdma_tc_spwrr_cfg_tbl {
	u32 data[1];
	struct {
		u32 tc_spwrr : 8;
		u32 rsv : 24;
	};
};

union rdma_net2sha_map_tbl {
	u32 data[1];
	struct {
		u32 net_shaping_id : 9;
		u32 rsv: 22;
		u32 vld: 1;
	};
};

union rdma_grp2sha_map_tbl {
	u32 data[1];
	struct {
		u32 grp_shaping_id : 8;
		u32 rsv : 23;
		u32 vld : 1;
	};
};

union rdma_sha2net_map_tbl {
	u32 data[1];
	struct {
		u32 rdma_vf_id : 6;
		u32 rsv : 25;
		u32 vld : 1;
	};
};

union rdma_sha2grp_map_tbl {
	u32 data[1];
	struct {
		u32 rdma_grp_id : 6;
		u32 rsv : 25;
		u32 vld : 1;
	};
};

union rdma_tc_q_list_attr_tbl {
	u32 data[1];
	struct {
		u32 rptr : 4;
		u32 rsv1 : 4;
		u32 rlen : 5;
		u32 rsv : 3;
		u32 wptr : 3;
		u32 rsv2 : 5;
		u32 wlen : 4;
		u32 rsv3 : 3;
		u32 fly : 1;
	};
};

union rdma_grp_net_list_tbl {
	u32 data[1];
	struct {
		u32 next : 6;
		u32 rsv3 : 6;
		u32 pre : 6;
		u32 rsv2 : 6;
		u32 sst : 2;
		u32 pfc : 1;
		u32 valid : 1;
		u32 rsv1: 4;
	};
};

union rdma_spt_grp_list_tbl {
	u32 data[1];
	struct {
		u32 next : 6;
		u32 rsv3 : 6;
		u32 pre : 6;
		u32 rsv2 : 6;
		u32 sst : 2;
		u32 valid : 1;
		u32 rsv1 : 5;
	};
};

union nbl_src_addr_info_tbl_reg {
	struct src_addr_info_tbl_key {
		u8 smac[6];
		u8 sip[16];
		u16 ipv4_valid : 1;
		u16 vlan_vlaid : 1;
		u16 rsv : 14;
	} key;
#define SRC_ADDR_INFO_TBL_KEY_REG_DW_SIZE (sizeof(struct src_addr_info_tbl_key) / sizeof(u32))
	u32 data[SRC_ADDR_INFO_TBL_KEY_REG_DW_SIZE];
};

#define NBL_PCOMP_HOST_BASE            (0x00F08000)
#define NBL_PCOMP_HOST_RDMA_TBL_READY  (NBL_PCOMP_HOST_BASE + 0x00001114)
#define NBL_PCOMP_HOST_RDMA_TBL_SEL    (NBL_PCOMP_HOST_BASE + 0x00001118)
#define NBL_PCOMP_HOST_RDMA_PFID_MAP_TABLE(t) (NBL_PCOMP_HOST_BASE + 0x00030000 + 16 * (t))
#define NBL_PCOMP_HOST_BAR_ADDR_MASK 0xFFFFFFFFFFFFE000

union nbl_rdma_tbl_ready_reg {
	u32 data[1];
	struct {
		u32 rdma_tbl_ready : 1;
		u32 rsv : 31;
	};
};

union nbl_rdma_tbl_sel_reg {
	u32 data[1];
	struct {
		u32 rdma_tbl_sel : 1;
		u32 rsv : 31;
	};
};

union nbl_rdma_pfid_map_tbl_reg {
	struct rdma_pfid_map_tbl_key {
		u64 rsv1 : 13;
		u64 bar_addr : 51;
		u64 pfid : 6;
		u64 rsv : 58;
	} key;
#define RDMA_PFID_MAP_TBL_KEY_REG_DW_SIZE (sizeof(struct rdma_pfid_map_tbl_key) / sizeof(u32))
	u32 data[RDMA_PFID_MAP_TBL_KEY_REG_DW_SIZE];
	u64 ddata;
};

struct rdma_host_notify {
	u32 pfid_map_tbl_sel;
	int pfid_map_tbl_entries;
	union nbl_rdma_pfid_map_tbl_reg pfid_map_tbl[NBL_PCOMP_HOST_PFID_MAX_TBL_ENTRY / 2];
};

#define HDMA_VF_ENABLE (NBL_REG_HDMA_BASE + 0x0848)
#define HDMA_VF_CLEAR (NBL_REG_HDMA_BASE + 0x0828)
#define HDMA_VF_ENABLE_SIZE 32 /* dif_vf_enable size 32bit */
#define HDMA_VF_CLEAR_SIZE 32 /* dif_vf_clr size 32bit */

#define UQM_BASE 0x00114000
#define UQM_VSI_MAPPING_TBL(vsi_id) (UQM_BASE + 0x00005000 + (vsi_id) * 4)
#define PP0_BASE 0x00B14000
#define PP_RDMA_VSI_BTM (PP0_BASE + 0x00000454)
#define PP_RDMA_VSI_BTM_ENTRY_SZ 32

#define NBL_REG_EPRO_BASE 0x00e74000
#define EPRO_INT_MASK (NBL_REG_EPRO_BASE + 0x00000004)
#define EPRO_INT_MASK_CFG_ERR 5
#define SW_DB_WQE_CAP (NBL_REG_TXP_BASE + 0x0000041c)
union txp_sw_db_wqe_cap {
	u32 data[1];
	struct {
		u32 sw_db_wqe_cap : 5;
		u32 rsv1 : 3;
		u32 recheck_db_wqe_cap : 5;
		u32 rsv2 : 19;
	};
};

union uqm_vsi_vfid_map_tbl {
	u32 data[1];
	struct {
		u32 vf_id : 6;
		u32 valid : 1;
		u32 rsv : 25;
	};
};

#define HOST_PADAPT_BASE 0x00F4C000
#define HOST_MSIX_INFO_TBL(global_idx) (HOST_PADAPT_BASE + 0x10000 + 8 * (global_idx))
#define HOST_MSIX_CTRL_TBL(global_idx) (HOST_PADAPT_BASE + 0x20000 + 16 * (global_idx))

union padapt_host_msix_info {
	struct {
		u32 intrl_pnum : 16;
		u32 intrl_rate : 16;
		u32 function_id : 3;
		u32 device_id : 5;
		u32 bus_id : 8;
		u32 valid : 1;
		u32 rsv : 15;
	};
	u32 data[2];
};

enum nbl_cqp_cache_type {
	NBL_CACHE_QPCC,
	NBL_CACHE_CQCC,
	NBL_CACHE_MRTC,
	NBL_CACHE_IRQEC,
	NBL_CACHE_ORQEC,
	NBL_CACHE_SQRQEC,
	NBL_CACHE_RAQEC,
	NBL_CACHE_PBLC,
	NBL_CACHE_UNAQC,
};

void nbl_set_fmr_nofence(struct nbl_grc *grc, u8 enable);
void grc_query_fmr_nofnece_info(struct nbl_grc *grc, struct nbl_chan_rdma_resp *mbx_resp);
#define RDMA_SUBMODULE_BASE_SHIFT 16
#endif /* _GRC_HW_RDMA_H_ */
