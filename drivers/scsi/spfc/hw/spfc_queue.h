/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPFC_QUEUE_H
#define SPFC_QUEUE_H

#include "unf_type.h"
#include "spfc_wqe.h"
#include "spfc_cqm_main.h"
#define SPFC_MIN_WP_NUM (2)
#define SPFC_EXTEND_WQE_OFFSET (128)
#define SPFC_SQE_SIZE (256)
#define WQE_MARKER_0 (0x0)
#define WQE_MARKER_6B (0x6b)

/* PARENT SQ & Context defines */
#define SPFC_MAX_MSN (65535)
#define SPFC_MSN_MASK (0xffff000000000000LL)
#define SPFC_SQE_TS_SIZE (72)
#define SPFC_SQE_FIRST_OBIT_DW_POS (0)
#define SPFC_SQE_SECOND_OBIT_DW_POS (30)
#define SPFC_SQE_OBIT_SET_MASK_BE (0x80)
#define SPFC_SQE_OBIT_CLEAR_MASK_BE (0xffffff7f)
#define SPFC_MAX_SQ_TASK_TYPE_CNT (128)
#define SPFC_SQ_NUM_PER_QPC (3)
#define SPFC_SQ_QID_START_PER_QPC 0
#define SPFC_SQ_SPACE_OFFSET (64)
#define SPFC_MAX_SSQ_NUM  (SPFC_SQ_NUM_PER_QPC * 63 + 1) /* must be a multiple of 3 */
#define SPFC_DIRECTWQE_SQ_INDEX (SPFC_MAX_SSQ_NUM - 1)

/* Note: if the location of flush done bit changes, the definition must be
 * modifyed again
 */
#define SPFC_CTXT_FLUSH_DONE_DW_POS (58)
#define SPFC_CTXT_FLUSH_DONE_MASK_BE (0x4000)
#define SPFC_CTXT_FLUSH_DONE_MASK_LE (0x400000)

#define SPFC_PCIE_TEMPLATE (0)
#define SPFC_DMA_ATTR_OFST (0)

/*
 *When driver assembles WQE SGE, the GPA parity bit is multiplexed as follows:
 * {rsvd'2,zerocopysoro'2,zerocopy_dmaattr_idx'6,pcie_template'6}
 */
#define SPFC_PCIE_TEMPLATE_OFFSET 0
#define SPFC_PCIE_ZEROCOPY_DMAATTR_IDX_OFFSET 6
#define SPFC_PCIE_ZEROCOPY_SO_RO_OFFSET 12
#define SPFC_PCIE_RELAXED_ORDERING (1)
#define SPFC_ZEROCOPY_PCIE_TEMPLATE_VALUE                                \
	(SPFC_PCIE_RELAXED_ORDERING << SPFC_PCIE_ZEROCOPY_SO_RO_OFFSET | \
	 SPFC_DMA_ATTR_OFST << SPFC_PCIE_ZEROCOPY_DMAATTR_IDX_OFFSET |   \
	 SPFC_PCIE_TEMPLATE)

#define SPFC_GET_SQ_HEAD(sq)                                            \
	list_entry(UNF_OS_LIST_NEXT(&(sq)->list_linked_list_sq), \
			  struct spfc_wqe_page, entry_wpg)
#define SPFC_GET_SQ_TAIL(sq)                                            \
	list_entry(UNF_OS_LIST_PREV(&(sq)->list_linked_list_sq), \
			  struct spfc_wqe_page, entry_wpg)
#define SPFC_SQ_IO_STAT(ssq, io_type) \
	(atomic_inc(&(ssq)->io_stat[io_type]))
#define SPFC_SQ_IO_STAT_READ(ssq, io_type) \
	(atomic_read(&(ssq)->io_stat[io_type]))
#define SPFC_GET_QUEUE_CMSN(ssq) \
	((u32)(be64_to_cpu(((((ssq)->queue_header)->ci_record) & SPFC_MSN_MASK))))
#define SPFC_GET_WP_END_CMSN(head_start_cmsn, wqe_num_per_buf)      \
	((u16)(((u32)(head_start_cmsn) + (u32)(wqe_num_per_buf) - 1) % (SPFC_MAX_MSN + 1)))
#define SPFC_MSN_INC(msn) (((SPFC_MAX_MSN) == (msn)) ? 0 : ((msn) + 1))
#define SPFC_MSN_DEC(msn) (((msn) == 0) ? (SPFC_MAX_MSN) : ((msn) - 1))
#define SPFC_QUEUE_MSN_OFFSET(start_cmsn, end_cmsn)                      \
	((u32)((((u32)(end_cmsn) + (SPFC_MAX_MSN)) - (u32)(start_cmsn)) % (SPFC_MAX_MSN + 1)))
#define SPFC_MSN32_ADD(msn, inc) (((msn) + (inc)) % (SPFC_MAX_MSN + 1))

/*
 *SCQ defines
 */
#define SPFC_INT_NUM_PER_QUEUE (1)
#define SPFC_SCQ_INT_ID_MAX (2048) /* 11BIT */
#define SPFC_SCQE_SIZE (64)
#define SPFC_CQE_GPA_SHIFT (4)
#define SPFC_NEXT_CQE_GPA_SHIFT (12)
/* 1-Update Ci by Tile, 0-Update Ci by Hardware */
#define SPFC_PMSN_CI_TYPE_FROM_HOST (0)
#define SPFC_PMSN_CI_TYPE_FROM_UCODE (1)
#define SPFC_ARMQ_IDLE (0)
#define SPFC_CQ_INT_MODE (2)
#define SPFC_CQ_HEADER_OWNER_SHIFT (15)

/* SCQC_CQ_DEPTH 0-256, 1-512, 2-1k, 3-2k, 4-4k, 5-8k, 6-16k, 7-32k.
 *  include LinkWqe
 */
#define SPFC_CMD_SCQ_DEPTH (4096)
#define SPFC_STS_SCQ_DEPTH (8192)

#define SPFC_CMD_SCQC_CQ_DEPTH (spfc_log2n(SPFC_CMD_SCQ_DEPTH >> 8))
#define SPFC_STS_SCQC_CQ_DEPTH (spfc_log2n(SPFC_STS_SCQ_DEPTH >> 8))
#define SPFC_STS_SCQ_CI_TYPE SPFC_PMSN_CI_TYPE_FROM_HOST

#define SPFC_CMD_SCQ_CI_TYPE SPFC_PMSN_CI_TYPE_FROM_UCODE

#define SPFC_SCQ_INTR_LOW_LATENCY_MODE 0
#define SPFC_SCQ_INTR_POLLING_MODE 1
#define SPFC_SCQ_PROC_CNT_PER_SECOND_THRESHOLD (30000)

#define SPFC_CQE_MAX_PROCESS_NUM_PER_INTR (128)
#define SPFC_SESSION_SCQ_NUM (16)

/* SCQ[0, 2, 4 ...]CMD SCQ,SCQ[1, 3, 5 ...]STS
 * SCQ,SCQ[SPFC_TOTAL_SCQ_NUM-1]Defaul SCQ
 */
#define SPFC_CMD_SCQN_START (0)
#define SPFC_STS_SCQN_START (1)
#define SPFC_SCQS_PER_SESSION (2)

#define SPFC_TOTAL_SCQ_NUM (SPFC_SESSION_SCQ_NUM + 1)

#define SPFC_SCQ_IS_STS(scq_index)                \
	(((scq_index) % SPFC_SCQS_PER_SESSION) || ((scq_index) == SPFC_SESSION_SCQ_NUM))
#define SPFC_SCQ_IS_CMD(scq_index) (!SPFC_SCQ_IS_STS(scq_index))
#define SPFC_RPORTID_TO_CMD_SCQN(rport_index) \
	(((rport_index) * SPFC_SCQS_PER_SESSION) % SPFC_SESSION_SCQ_NUM)
#define SPFC_RPORTID_TO_STS_SCQN(rport_index) \
	((((rport_index) * SPFC_SCQS_PER_SESSION) + 1) % SPFC_SESSION_SCQ_NUM)

/*
 *SRQ defines
 */
#define SPFC_SRQE_SIZE (32)
#define SPFC_SRQ_INIT_LOOP_O (1)
#define SPFC_QUEUE_RING (1)
#define SPFC_SRQ_ELS_DATA_NUM (1)
#define SPFC_SRQ_ELS_SGE_LEN (256)
#define SPFC_SRQ_ELS_DATA_DEPTH (31750) /* depth should Divide 127 */

#define SPFC_IRQ_NAME_MAX (30)

/* Support 2048 sessions(xid) */
#define SPFC_CQM_XID_MASK (0x7ff)

#define SPFC_QUEUE_FLUSH_DOING (0)
#define SPFC_QUEUE_FLUSH_DONE (1)
#define SPFC_QUEUE_FLUSH_WAIT_TIMEOUT_MS (2000)
#define SPFC_QUEUE_FLUSH_WAIT_MS (2)

/*
 *RPort defines
 */
#define SPFC_RPORT_OFFLOADED(prnt_qinfo) \
	((prnt_qinfo)->offload_state == SPFC_QUEUE_STATE_OFFLOADED)
#define SPFC_RPORT_NOT_OFFLOADED(prnt_qinfo) \
	((prnt_qinfo)->offload_state != SPFC_QUEUE_STATE_OFFLOADED)
#define SPFC_RPORT_FLUSH_NOT_NEEDED(prnt_qinfo)                           \
	(((prnt_qinfo)->offload_state == SPFC_QUEUE_STATE_INITIALIZED) || \
	 ((prnt_qinfo)->offload_state == SPFC_QUEUE_STATE_OFFLOADING) ||  \
	 ((prnt_qinfo)->offload_state == SPFC_QUEUE_STATE_FREE))
#define SPFC_CHECK_XID_MATCHED(sq_xid, sqe_xid) \
	(((sq_xid) & SPFC_CQM_XID_MASK) == ((sqe_xid) & SPFC_CQM_XID_MASK))
#define SPFC_PORT_MODE_TGT (0) /* Port mode */
#define SPFC_PORT_MODE_INI (1)
#define SPFC_PORT_MODE_BOTH (2)

/*
 *Hardware Reserved Queue Info defines
 */
#define SPFC_HRQI_SEQ_ID_MAX (255)
#define SPFC_HRQI_SEQ_INDEX_MAX (64)
#define SPFC_HRQI_SEQ_INDEX_SHIFT (6)
#define SPFC_HRQI_SEQ_SEPCIAL_ID (3)
#define SPFC_HRQI_SEQ_INVALID_ID (~0LL)

enum spfc_session_reset_mode {
	SPFC_SESS_RST_DELETE_IO_ONLY = 1,
	SPFC_SESS_RST_DELETE_CONN_ONLY = 2,
	SPFC_SESS_RST_DELETE_IO_CONN_BOTH = 3,
	SPFC_SESS_RST_MODE_BUTT
};

/* linkwqe */
#define CQM_LINK_WQE_CTRLSL_VALUE 2
#define CQM_LINK_WQE_LP_VALID 1
#define CQM_LINK_WQE_LP_INVALID 0

/* bit mask */
#define SPFC_SCQN_MASK 0xfffff
#define SPFC_SCQ_CTX_CI_GPA_MASK 0xfffffff
#define SPFC_SCQ_CTX_C_EQN_MSI_X_MASK 0x7
#define SPFC_PARITY_MASK 0x1
#define SPFC_KEYSECTION_XID_H_MASK 0xf
#define SPFC_KEYSECTION_XID_L_MASK 0xffff
#define SPFC_SRQ_CTX_rqe_dma_attr_idx_MASK 0xf
#define SPFC_SSQ_CTX_MASK 0xfffff
#define SPFC_KEY_WD3_SID_2_MASK 0x00ff0000
#define SPFC_KEY_WD3_SID_1_MASK 0x00ff00
#define SPFC_KEY_WD3_SID_0_MASK 0x0000ff
#define SPFC_KEY_WD4_DID_2_MASK 0x00ff0000
#define SPFC_KEY_WD4_DID_1_MASK 0x00ff00
#define SPFC_KEY_WD4_DID_0_MASK 0x0000ff
#define SPFC_LOCAL_LW_WD1_DUMP_MSN_MASK 0x7fff
#define SPFC_PMSN_MASK 0xff
#define SPFC_QOS_LEVEL_MASK 0x3
#define SPFC_DB_VAL_MASK 0xFFFFFFFF
#define SPFC_MSNWD_L_MASK 0xffff
#define SPFC_MSNWD_H_MASK 0x7fff
#define SPFC_DB_WD0_PI_H_MASK 0xf
#define SPFC_DB_WD0_PI_L_MASK 0xfff

#define SPFC_DB_C_BIT_DATA_TYPE 0
#define SPFC_DB_C_BIT_CONTROL_TYPE 1

#define SPFC_OWNER_DRIVER_PRODUCT (1)

#define SPFC_256BWQE_ENABLE (1)
#define SPFC_DB_ARM_DISABLE (0)

#define SPFC_CNTX_SIZE_T_256B (0)
#define SPFC_CNTX_SIZE_256B (256)

#define SPFC_SERVICE_TYPE_FC (12)
#define SPFC_SERVICE_TYPE_FC_SQ (13)

#define SPFC_PACKET_COS_FC_CMD (0)
#define SPFC_PACKET_COS_FC_DATA (1)

#define SPFC_QUEUE_LINK_STYLE (0)
#define SPFC_QUEUE_RING_STYLE (1)

#define SPFC_NEED_DO_OFFLOAD (1)
#define SPFC_QID_SQ (0)

/*
 *SCQ defines
 */
struct spfc_scq_info {
	struct cqm_queue *cqm_scq_info;
	u32 wqe_num_per_buf;
	u32 wqe_size;
	u32 scqc_cq_depth; /* 0-256, 1-512, 2-1k, 3-2k, 4-4k, 5-8k, 6-16k, 7-32k */
	u16 scqc_ci_type;
	u16 valid_wqe_num; /* ScQ depth include link wqe */
	u16 ci;
	u16 ci_owner;
	u32 queue_id;
	u32 scqn;
	char irq_name[SPFC_IRQ_NAME_MAX];
	u16 msix_entry_idx;
	u32 irq_id;
	struct tasklet_struct tasklet;
	atomic_t flush_stat;
	void *hba;
	u32 reserved;
	struct task_struct *delay_task;
	bool task_exit;
	u32 intr_mode;
};

struct spfc_srq_ctx {
	/* DW0 */
	u64 pcie_template : 6;
	u64 rsvd0 : 2;
	u64 parity : 8;
	u64 cur_rqe_usr_id : 16;
	u64 cur_rqe_msn : 16;
	u64 last_rq_pmsn : 16;

	/* DW1 */
	u64 cur_rqe_gpa;

	/* DW2 */
	u64 ctrl_sl : 1;
	u64 cf : 1;
	u64 csl : 2;
	u64 cr : 1;
	u64 bdsl : 4;
	u64 pmsn_type : 1;
	u64 cur_wqe_o : 1;
	u64 consant_sge_len : 17;
	u64 cur_sge_id : 4;
	u64 cur_sge_remain_len : 17;
	u64 ceqn_msix : 11;
	u64 int_mode : 2;
	u64 cur_sge_l : 1;
	u64 cur_sge_v : 1;

	/* DW3 */
	u64 cur_sge_gpa;

	/* DW4 */
	u64 cur_pmsn_gpa;

	/* DW5 */
	u64 rsvd3 : 5;
	u64 ring : 1;
	u64 loop_o : 1;
	u64 rsvd2 : 1;
	u64 rqe_dma_attr_idx : 6;
	u64 rq_so_ro : 2;
	u64 cqe_dma_attr_idx : 6;
	u64 cq_so_ro : 2;
	u64 rsvd1 : 7;
	u64 arm_q : 1;
	u64 cur_cqe_cnt : 8;
	u64 cqe_max_cnt : 8;
	u64 prefetch_max_masn : 16;

	/* DW6~DW7 */
	u64 rsvd4;
	u64 rsvd5;
};

struct spfc_drq_buff_entry {
	u16 buff_id;
	void *buff_addr;
	dma_addr_t buff_dma;
};

enum spfc_clean_state { SPFC_CLEAN_DONE, SPFC_CLEAN_DOING, SPFC_CLEAN_BUTT };
enum spfc_srq_type { SPFC_SRQ_ELS = 1, SPFC_SRQ_IMMI, SPFC_SRQ_BUTT };

struct spfc_srq_info {
	enum spfc_srq_type srq_type;

	struct cqm_queue *cqm_srq_info;
	u32 wqe_num_per_buf; /* Wqe number per buf, dont't inlcude link wqe */
	u32 wqe_size;
	u32 valid_wqe_num; /* valid wqe number, dont't include link wqe */
	u16 pi;
	u16 pi_owner;
	u16 pmsn;
	u16 ci;
	u16 cmsn;
	u32 srqn;

	dma_addr_t first_rqe_recv_dma;

	struct spfc_drq_buff_entry *els_buff_entry_head;
	struct buf_describe buf_list;
	spinlock_t srq_spin_lock;
	bool spin_lock_init;
	bool enable;
	enum spfc_clean_state state;

	atomic_t ref;

	struct delayed_work del_work;
	u32 del_retry_time;
	void *hba;
};

/*
 * The doorbell record keeps PI of WQE, which will be produced next time.
 * The PI is 15 bits width o-bit
 */
struct db_record {
	u64 pmsn : 16;
	u64 dump_pmsn : 16;
	u64 rsvd0 : 32;
};

/*
 * The ci record keeps CI of WQE, which will be consumed next time.
 * The ci is 15 bits width with 1 o-bit
 */
struct ci_record {
	u64 cmsn : 16;
	u64 dump_cmsn : 16;
	u64 rsvd0 : 32;
};

/* The accumulate data in WQ header */
struct accumulate {
	u64 data_2_uc;
	u64 data_2_drv;
};

/* The WQ header structure */
struct wq_header {
	struct db_record db_record;
	struct ci_record ci_record;
	struct accumulate soft_data;
};

/* Link list Sq WqePage Pool */
/* queue header struct */
struct spfc_queue_header {
	u64 door_bell_record;
	u64 ci_record;
	u64 rsv1;
	u64 rsv2;
};

/* WPG-WQEPAGE, LLSQ-LINKED LIST SQ */
struct spfc_wqe_page {
	struct list_head entry_wpg;

	/* Wqe Page virtual addr */
	void *wpg_addr;

	/* Wqe Page physical addr */
	u64 wpg_phy_addr;
};

struct spfc_sq_wqepage_pool {
	u32 wpg_cnt;
	u32 wpg_size;
	u32 wqe_per_wpg;

	/* PCI DMA Pool */
	struct dma_pool *wpg_dma_pool;
	struct spfc_wqe_page *wpg_pool_addr;
	struct list_head list_free_wpg_pool;
	spinlock_t wpg_pool_lock;
	atomic_t wpg_in_use;
};

#define SPFC_SQ_DEL_STAGE_TIMEOUT_MS (3 * 1000)
#define SPFC_SRQ_DEL_STAGE_TIMEOUT_MS (10 * 1000)
#define SPFC_SQ_WAIT_FLUSH_DONE_TIMEOUT_MS (10 * 1000)
#define SPFC_SQ_WAIT_FLUSH_DONE_TIMEOUT_CNT (3)

#define SPFC_SRQ_PROCESS_DELAY_MS (20)

/* PLOGI parameters */
struct spfc_plogi_copram {
	u32 seq_cnt : 1;
	u32 ed_tov : 1;
	u32 rsvd : 14;
	u32 tx_mfs : 16;
	u32 ed_tov_time;
};

struct spfc_delay_sqe_ctrl_info {
	bool valid;
	u32 rport_index;
	u32 time_out;
	u64 start_jiff;
	u32 sid;
	u32 did;
	u32 xid;
	u16 ssqn;
	struct spfc_sqe sqe;
};

struct spfc_suspend_sqe_info {
	void *hba;
	u32 magic_num;
	u8 old_offload_sts;
	struct unf_frame_pkg pkg;
	struct spfc_sqe sqe;
	struct delayed_work timeout_work;
	struct list_head list_sqe_entry;
};

struct spfc_delay_destroy_ctrl_info {
	bool valid;
	u32 rport_index;
	u32 time_out;
	u64 start_jiff;
	struct unf_port_info rport_info;
};

/* PARENT SQ Info */
struct spfc_parent_sq_info {
	void *hba;
	spinlock_t parent_sq_enqueue_lock;
	u32 rport_index;
	u32 context_id;
	/* Fixed value,used for Doorbell */
	u32 sq_queue_id;
	/* When a session is offloaded, tile will return the CacheId to the
	 * driver,which is used for Doorbell
	 */
	u32 cache_id;
	/* service type, fc or fc */
	u32 service_type;
	/* OQID */
	u16 oqid_rd;
	u16 oqid_wr;
	u32 local_port_id;
	u32 remote_port_id;
	u32 sqn_base;
	bool port_in_flush;
	bool sq_in_sess_rst;
	atomic_t sq_valid;
	/* Used by NPIV QoS */
	u8 vport_id;
	/* Used by NPIV QoS */
	u8 cs_ctrl;
	struct delayed_work del_work;
	struct delayed_work flush_done_timeout_work;
	u64 del_start_jiff;
	dma_addr_t srq_ctx_addr;
	atomic_t sq_cached;
	atomic_t flush_done_wait_cnt;
	struct spfc_plogi_copram plogi_co_parms;
	/* dif control info for immi */
	struct unf_dif_control_info sirt_dif_control;
	struct spfc_delay_sqe_ctrl_info delay_sqe;
	struct spfc_delay_destroy_ctrl_info destroy_sqe;
	struct list_head suspend_sqe_list;
	atomic_t io_stat[SPFC_MAX_SQ_TASK_TYPE_CNT];
	u8 need_offloaded;
};

/* parent context doorbell */
struct spfc_parent_sq_db {
	struct {
		u32 xid : 20;
		u32 cntx_size : 2;
		u32 arm : 1;
		u32 c : 1;
		u32 cos : 3;
		u32 service_type : 5;
	} wd0;

	struct {
		u32 pi_hi : 8;
		u32 sm_data : 20;
		u32 qid : 4;
	} wd1;
};

#define IWARP_FC_DDB_TYPE 3

/* direct wqe doorbell */
struct spfc_direct_wqe_db {
	struct {
		u32 xid : 20;
		u32 cntx_size : 2;
		u32 pi_hi : 4;
		u32 c : 1;
		u32 cos : 3;
		u32 ddb : 2;
	} wd0;

	struct {
		u32 pi_lo : 12;
		u32 sm_data : 20;
	} wd1;
};

struct spfc_parent_cmd_scq_info {
	u32 cqm_queue_id;
	u32 local_queue_id;
};

struct spfc_parent_st_scq_info {
	u32 cqm_queue_id;
	u32 local_queue_id;
};

struct spfc_parent_els_srq_info {
	u32 cqm_queue_id;
	u32 local_queue_id;
};

enum spfc_parent_queue_state {
	SPFC_QUEUE_STATE_INITIALIZED = 0,
	SPFC_QUEUE_STATE_OFFLOADING = 1,
	SPFC_QUEUE_STATE_OFFLOADED = 2,
	SPFC_QUEUE_STATE_DESTROYING = 3,
	SPFC_QUEUE_STATE_FREE = 4,
	SPFC_QUEUE_STATE_BUTT
};

struct spfc_parent_ctx {
	dma_addr_t parent_ctx_addr;
	void *parent_ctx;
	struct cqm_qpc_mpt *cqm_parent_ctx_obj;
};

struct spfc_parent_queue_info {
	spinlock_t parent_queue_state_lock;
	struct spfc_parent_ctx parent_ctx;
	enum spfc_parent_queue_state offload_state;
	struct spfc_parent_sq_info parent_sq_info;
	struct spfc_parent_cmd_scq_info parent_cmd_scq_info;
	struct spfc_parent_st_scq_info
	    parent_sts_scq_info;
	struct spfc_parent_els_srq_info parent_els_srq_info;
	u8 queue_vport_id;
	u8 queue_data_cos;
};

struct spfc_parent_ssq_info {
	void *hba;
	spinlock_t parent_sq_enqueue_lock;
	atomic_t wqe_page_cnt;
	u32 context_id;
	u32 cache_id;
	u32 sq_queue_id;
	u32 sqn;
	u32 service_type;
	u32 max_sqe_num; /* SQ depth */
	u32 wqe_num_per_buf;
	u32 wqe_size;
	u32 accum_wqe_cnt;
	u32 wqe_offset;
	u16 head_start_cmsn;
	u16 head_end_cmsn;
	u16 last_pmsn;
	u16 last_pi_owner;
	u32 queue_style;
	atomic_t sq_valid;
	void *queue_head_original;
	struct spfc_queue_header *queue_header;
	dma_addr_t queue_hdr_phy_addr_original;
	dma_addr_t queue_hdr_phy_addr;
	struct list_head list_linked_list_sq;
	atomic_t sq_db_cnt;
	atomic_t sq_wqe_cnt;
	atomic_t sq_cqe_cnt;
	atomic_t sqe_minus_cqe_cnt;
	atomic_t io_stat[SPFC_MAX_SQ_TASK_TYPE_CNT];
};

struct spfc_parent_shared_queue_info {
	struct spfc_parent_ctx parent_ctx;
	struct spfc_parent_ssq_info parent_ssq_info;
};

struct spfc_parent_queue_mgr {
	struct spfc_parent_queue_info parent_queue[UNF_SPFC_MAXRPORT_NUM];
	struct spfc_parent_shared_queue_info shared_queue[SPFC_MAX_SSQ_NUM];
	struct buf_describe parent_sq_buf_list;
};

#define SPFC_SRQC_BUS_ROW 8
#define SPFC_SRQC_BUS_COL 19
#define SPFC_SQC_BUS_ROW 8
#define SPFC_SQC_BUS_COL 13
#define SPFC_HW_SCQC_BUS_ROW 6
#define SPFC_HW_SCQC_BUS_COL 10
#define SPFC_HW_SRQC_BUS_ROW 4
#define SPFC_HW_SRQC_BUS_COL 15
#define SPFC_SCQC_BUS_ROW 3
#define SPFC_SCQC_BUS_COL 29

#define SPFC_QUEUE_INFO_BUS_NUM 4
struct spfc_queue_info_bus {
	u64 bus[SPFC_QUEUE_INFO_BUS_NUM];
};

u32 spfc_free_parent_resource(void *handle, struct unf_port_info *rport_info);
u32 spfc_alloc_parent_resource(void *handle, struct unf_port_info *rport_info);
u32 spfc_alloc_parent_queue_mgr(void *handle);
void spfc_free_parent_queue_mgr(void *handle);
u32 spfc_create_common_share_queues(void *handle);
u32 spfc_create_ssq(void *handle);
void spfc_destroy_common_share_queues(void *v_pstHba);
u32 spfc_alloc_parent_sq_wqe_page_pool(void *handle);
void spfc_free_parent_sq_wqe_page_pool(void *handle);
struct spfc_parent_queue_info *
spfc_find_parent_queue_info_by_pkg(void *handle, struct unf_frame_pkg *pkg);
struct spfc_parent_sq_info *
spfc_find_parent_sq_by_pkg(void *handle, struct unf_frame_pkg *pkg);
u32 spfc_root_cmdq_enqueue(void *handle, union spfc_cmdqe *cmdqe, u16 cmd_len);
void spfc_process_scq_cqe(ulong scq_info);
u32 spfc_process_scq_cqe_entity(ulong scq_info, u32 proc_cnt);
void spfc_post_els_srq_wqe(struct spfc_srq_info *srq_info, u16 buf_id);
void spfc_process_aeqe(void *handle, u8 event_type, u8 *event_val);
u32 spfc_parent_sq_enqueue(struct spfc_parent_sq_info *sq, struct spfc_sqe *io_sqe,
			   u16 ssqn);
u32 spfc_parent_ssq_enqueue(struct spfc_parent_ssq_info *ssq,
			    struct spfc_sqe *io_sqe, u8 wqe_type);
void spfc_free_sq_wqe_page(struct spfc_parent_ssq_info *ssq, u32 cur_cmsn);
u32 spfc_reclaim_sq_wqe_page(void *handle, union spfc_scqe *scqe);
void spfc_set_rport_flush_state(void *handle, bool in_flush);
u32 spfc_clear_fetched_sq_wqe(void *handle);
u32 spfc_clear_pending_sq_wqe(void *handle);
void spfc_free_parent_queues(void *handle);
void spfc_free_ssq(void *handle, u32 free_sq_num);
void spfc_enalbe_queues_dispatch(void *handle);
void spfc_queue_pre_process(void *handle, bool clean);
void spfc_queue_post_process(void *handle);
void spfc_free_parent_queue_info(void *handle, struct spfc_parent_queue_info *parent_queue_info);
u32 spfc_send_session_rst_cmd(void *handle,
			      struct spfc_parent_queue_info *parent_queue_info,
			      enum spfc_session_reset_mode mode);
u32 spfc_send_nop_cmd(void *handle, struct spfc_parent_sq_info *parent_sq_info,
		      u32 magic_num, u16 sqn);
void spfc_build_session_rst_wqe(void *handle, struct spfc_parent_sq_info *sq,
				struct spfc_sqe *sqe,
				enum spfc_session_reset_mode mode, u32 scqn);
void spfc_wq_destroy_els_srq(struct work_struct *work);
void spfc_destroy_els_srq(void *handle);
u32 spfc_push_delay_sqe(void *hba,
			struct spfc_parent_queue_info *offload_parent_queue,
			struct spfc_sqe *sqe, struct unf_frame_pkg *pkg);
void spfc_push_destroy_parent_queue_sqe(void *hba,
					struct spfc_parent_queue_info *offloading_parent_queue,
					struct unf_port_info *rport_info);
void spfc_pop_destroy_parent_queue_sqe(void *handle,
				       struct spfc_delay_destroy_ctrl_info *destroy_sqe_info);
struct spfc_parent_queue_info *spfc_find_offload_parent_queue(void *handle,
							      u32 local_id,
							      u32 remote_id,
							      u32 rport_index);
u32 spfc_flush_ini_resp_queue(void *handle);
void spfc_rcvd_els_from_srq_timeout(struct work_struct *work);
u32 spfc_send_aeq_info_via_cmdq(void *hba, u32 aeq_error_type);
u32 spfc_parent_sq_ring_doorbell(struct spfc_parent_ssq_info *sq, u8 qos_level,
				 u32 c);
void spfc_sess_resource_free_sync(void *handle,
				  struct unf_port_info *rport_info);
u32 spfc_suspend_sqe_and_send_nop(void *handle,
				  struct spfc_parent_queue_info *parent_queue,
				  struct spfc_sqe *sqe, struct unf_frame_pkg *pkg);
u32 spfc_pop_suspend_sqe(void *handle,
			 struct spfc_parent_queue_info *parent_queue,
			 struct spfc_suspend_sqe_info *suspen_sqe);
#endif
