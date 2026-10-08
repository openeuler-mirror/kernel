/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_MAIN_V2_H
#define NBL_MAIN_V2_H

#include <linux/auxiliary_bus.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <rdma/uverbs_ioctl.h>
#include <rdma/ib_verbs.h>
#include <linux/pci.h>

#include "nbl_core_common.h"
#include "grc_common_v2.h"
#include "debug.h"
#include "hmc.h"
#include "hw.h"
#include "type.h"
#include "device.h"
#include "verbs.h"
#include "defs.h"
#include "gid.h"
#include "nbl_adapt.h"
#include "product.h"

#define NBL_MAX_PORT 1
#define NBL_HEX_DUMP_ROW 16
#define NBL_HEX_DUMP_GRP 1
#define NBL_HEX_DUMP_BUF_MAX 256

#define NBL_ETH_MAX_NUM 4

#define NBL_IB_QPT_REG_UMR IB_QPT_RESERVED1
#define NBL_IB_QPT_SRP IB_QPT_DRIVER

#define NBL_RDMA_PSN_OST_MIN 0x1
#define NBL_RDMA_PSN_OST_MAX 0x800000

#define NBL_SRP_EPSN_RTH_MAX 63

#define NBL_RDMA_DPORT_MIN 0x1
#define NBL_RDMA_DPORT_MAX 0xffff
#define NBL_RDMA_DPORT_DFT 0x12b7

#define NBL_GRC_WQ_MAX_NAME 32
#define NBL_TLP_WQ_MAX_NAME 32
#define NBL_MBX_WQ_MAX_NAME 32
#define NBL_DMA_ADDRESS_SIZE 8
#define NBL_MAX_RQWQE_SGE 6
#define NBL_MIN_RQWQE_SGE 2
#define NBL_MAX_WQE_QUANATA_V2 8
#define NBL_MAX_INLINE_V2 465
#define NBL_MAX_RC_INLINE_V2 465
#define NBL_MAX_UD_INLINE_V2 434
#define NBL_MAX_QP_WR 32768 /* 32k wqe cnt*/
#define NBL_MIN_QP_DEPTH 32768
#define DF200_RDMA_TOTAL_FUNCTION_NUM 4
#define NBL_DEFAULT_MAX_SGE_V2 30
#define NBL_HW_FLUSH_CNT 4096

#define NBL_MAX_SRQ_WR (1 << 15)

#define NBL_RDMA_DSCH_VALID 1
#define NBL_RDMA_DSCH_INVALID 0

#define NBL_TLP_TIMEOUT_MSEC 60 /* time for tlp to finish a request,4fpga 30 */

#define VOA_TBL_STR_LEN 600
#define VOA_TBL_ENTRY_FORMAT_NEW ("\nvoa_ent[%u]:vld=%u,obj_base_ba=0x%x,obj_max_num=0x%x," \
	"obj_idx_start=0x%x,obj_sz=%u,page_sz=%u,page_mode=%u\n")
#define NBL_VOA_CQP_CMD_OFFSET 4
#define NBL_GET_BDF_NUM(bus, dev, function) ((bus) << 8 | (dev) << 3 | (function))
#define NBL_RDMA_VF_CNT_PER_PF	15

#define WAIT_RDMA_EMPTY_TIME 1000 /* after reset, wait rdma path empty */
#define WAIT_RDMA_EMPTY_MAX_TIME 2000

enum init_completion_state {
	INVALID_STATE = 0,
	INITIAL_STATE,
	NOTIFY_INITIALIZED,
	CQP_CREATED,
	HMC_OBJS_CREATED,
	HW_RSRC_INITIALIZED,
	QP_INITED,
	CEQS_CREATED,
	AEQ_CREATED,
	PBLE_CHUNK_MEM,
	CLEANUP_WQ_CREAT,
	GLOBAL_Q_INITED,
};

enum nbl_resource_profile {
	PF_ONLY,
	PF_VF_EVEN_DISTRIBUTION,
};

enum nbl_qp_limits_enum {
	SZ_128_QP = 0,
	SZ_4K_QP,
	SZ_32K_QP,
	SZ_64K_QP,
	SZ_128K_QP,
	SZ_MAX_QP
};

enum nbl_status_code {
	NBL_SUCCESS = 0,
	NBL_ERR_ALLOCMEM_FAILED = -1,
	NBL_ERR_CFG = -2,
	NBL_ERR_NO_INTR = -3,
	NBL_ERR_NO_ENOUGH_ONLINE_CPUS = -4,
	NBL_ERR_NO_MEMORY = -5,
	NBL_ERR_SPEC_ERROR = -6,
	NBL_ERR_AEID_NOTSUPPORT = -7,
	NBL_ERR_AEINFO_ERR = -8,
	NBL_ERR_GET_QP_NULL = -9,
	NBL_ERR_BUSY = -10,
	NBL_ERR_GET_CQ_NULL = -11,
	NBL_ERR_GET_CEQ_NULL = -12,
	NBL_ERR_GET_SRQ_NULL = -13,
	NBL_ERR_Q_EMPTY = -22,
	NBL_ERR_Q_SRQNULL = -24,
	NBL_ERR_SGE_NOTSUPPORTED = -49,
	NBL_ERR_CQ_COMPL_ERROR = -67,
	NBL_ERR_Q_DESTROYED = -68,
	NBL_ERR_Q_DRIVER_CE = -69,
	NBL_ERR_Q_RESIZE = -70,
};


enum nbl_srp_config {
	NBL_SRP_CONFIG_EPSN_RTH,
	NBL_SRP_CONFIG_BITMAP_EN
};

struct nbl_sc_aeq {
	struct nbl_sc_aeqe *aeqe_base; /* virtual address from RDMA alloc */
	u32 size; /* size of aeq entry, (bytes) */
	u64 aeq_elem_pa; /* Physical memory address from DMA alloc */
	struct nbl_sc_dev *dev; /* RDMA device */
	u32 elem_cnt; /* actual aeqe numbers to be used to alloc memory */
	struct nbl_ring
		aeq_ring; /* Used to maintain the head/tail Pointers and size of AEQ */
	u32 msix_idx; /* Interrupt number for AEQ */
	u8 polarity; /* polarity of AEQ */
	u32 aeq_pg_num;
	bool pa_continuous; /* Assign physical addresses continuously or not */
};

struct nbl_ceq {
	struct nbl_sc_ceq sc_ceq;
	struct nbl_dma_mem kmem;
	bool pa_continuous;
	u32 irq;
	u32 msix_idx;
	u32 ceq_id;
	struct nbl_pci_f *rf;
	struct tasklet_struct dpc_tasklet;
	struct nbl_frag_buf buf;
};

struct nbl_aeq {
	struct nbl_sc_aeq sc_aeq; /* AEQ details */
	struct nbl_dma_mem kmem; /* DMA Mem */
	bool pa_continuous; /* Assign physical addresses continuously or not */
	struct nbl_frag_buf buf;
	u32 ae_stat[NBL_ERR_MAX_AEID];
};

struct nbl_sc_pd {
	struct nbl_sc_dev *dev;
	u32 pd_id;
};

struct rdma_uds_client {
	struct socket *sock;
};

struct nbl_grc {
	struct mutex grc_mlock;
	u8 seq_num;

	char wq_name[NBL_GRC_WQ_MAX_NAME];
	struct workqueue_struct *wq;
	struct rdma_uds_client client;
};

struct nbl_tlp {
	struct mutex tlp_mlock;
	u8 seq_num;
	char wq_name[NBL_TLP_WQ_MAX_NAME];
	struct workqueue_struct *wq;
};

struct nbl_mbx {
	struct mutex mbx_mlock;
	u8 seq_num;
	char wq_name[NBL_MBX_WQ_MAX_NAME];
	struct workqueue_struct *wq;
};

struct nbl_cmd {
	void *cmd_alloc_buf;
	dma_addr_t alloc_dma;
	int alloc_size;
	void *cmd_buf;
	dma_addr_t dma;
	spinlock_t alloc_lock; /* protect command queue tail/head */
	char wq_name[NBL_CMD_WQ_MAX_NAME];
	struct workqueue_struct *wq;
#if NBL_CMD_INT_USE_WQ
	char cmpl_wq_name[NBL_CMD_WQ_MAX_NAME];
	struct workqueue_struct *cmpl_wq; /* interrupt mode use, wq to save time */
#endif
	struct semaphore sem;
	struct nbl_cmd_work_ent *ent_arr[NBL_CMD_ENTRY_MAX_NUM];
	struct nbl_sc_dev *dev;
	unsigned long *bit_mask; /* cmd put back use */
	u32 cmd_max_num; /* cmd entry max num      , 32   */
	u32 cmd_tail; /* cmd queue tail pointer , 0-31 */
	u32 cmd_head; /* cmd queue head pointer , 0-31 */
	u32 cmd_entry_size; /* cmd entry size in bytes, 128B */
	int mode;
	u8 cmd_entry_size_log; /* cmd entry size in log2 , 7 */
	u8 valid_val; /* 0 for first circle, wqe_valid should set */
	u8 rsvd[2]; /* 4B match */

	/* CQP statis */
	struct mutex cmd_stat_lock; /* lock protect static */
	u64 cmd_total; /* cqp cmd total num   */
	u64 cmd_succ; /* cqp cmd back success */
	u64 cmd_fail; /* cqp cmd back failed  */
};

struct nbl_msix_vector {
	u32 idx;
	u32 irq;
	u32 cpu_affinity;
	char name[NBL_MAX_IRQ_NAME];
	cpumask_t mask;
};

union nbl_hmc_voa_entry_v2 {
	struct nbl_hmc_voa_entry_key {
		u32 page_mode : 1;
		u32 page_sz : 1;
		u32 obj_idx_start : 29; /* object global index start num */
		u32 rsv : 1;

		u32 obj_max_cnt : 29; /* max object num per function */
		u32 rsv2 : 3;

		u32 obj_ba : 23;
		u32 obj_sz : 4;
		u32 rsv1 : 4;
		u32 valid : 1;
	} key;

#define VOA_TBL_KEY_REG_DW_SIZE (sizeof(struct nbl_hmc_voa_entry_key) / sizeof(u32))
	u32 data[VOA_TBL_KEY_REG_DW_SIZE];
};

/* common define*/
enum nbl_ib_cc_mode_types {
	NBL_CC = 1,
	NBL_QCN = 2,
	NBL_SWCC = 3,
	NBL_PCC = 4,
};

#define NBL_QOS_DEFAULT_TC_WGT 0x04010401 /* SQ:RAQ = 1:4:1:4 */
#define NBL_QOS_DEFAULT_TC_WGT_V3 0x04040404 /* 4:4:4:4   */
#define NBL_QOS_DEFAULT_SQ_WGT 4
#define NBL_QOS_DEFAULT_RAQ_WGT 4
#define NBL_QOS_TC_GHOST_BITMAP_DFT 0x55
#define NBL_QOS_DEFAULT_PRI03_P2S_MAP 0x02020101
#define NBL_QOS_DEFAULT_PRI47_P2S_MAP 0x08080404
#define NBL_QOS_DEFAULT_PRI_IMAP 0x6D2240
#define NBL_QOS_DEFAULT_SQ_PRI_MAP 0xD10
#define NBL_QOS_DEFAULT_RAQ_PRI_MAP 0xF59
#define NBL_QOS_DEFAULT_PRI03_MAP 0xC0300C03
#define NBL_QOS_DEFAULT_PRI47_MAP 0
#define NBL_QOS_DEFAULT_TC2PRI 0x6D2240
/* RNIC SP QOS default cfg */
#define NBL_QOS_DEFAULT_SP_RAQ_PRI_MAP 0xFFFFFF
#define NBL_QOS_DEFAULT_SP_PRI03_MAP 0xC0908481
#define NBL_QOS_DEFAULT_SP_PRI47_MAP 0

#define NBL_DEF_CC_MODE 2
#define NBL_DEF_CC_EN 1
#define NBL_DEF_CC_OAMREQ_TC_EN 0
#define NBL_DEF_CC_OAMREQ_NET_TC 6
#define NBL_DEF_CC_OAMACK_TC_EN 1
#define NBL_DEF_CC_OAMACK_NET_TC 6
#define NBL_DEF_CC_OAMACK_BLK_TH 256
#define NBL_DEF_CC_TARGETWIN_MIN 1
#define NBL_DEF_CC_PKT_NUM_EN 0
#define NBL_DEF_CC_HIGH_RTT_FRACTION 0
#define NBL_DEF_CC_LOW_RTT_FRACTION 0
#define NBL_DEF_CC_INC_TARGET_WIN_TH 256
#define NBL_DEF_CC_DEC_TARGET_WIN_TH 64
#define NBL_DEF_CC_TARGETWIN 256
#define NBL_DEF_CC_RTT_OFFSET 230
#define NBL_DEF_CC_RTT_PROBE_INVL 5
#define NBL_DEF_CC_HIGH_PRI_RTT_INVL 32
#define NBL_DEF_CC_HIGH_RPI_RTT_EN 0
#define NBL_DEF_CC_RST_WIN_H 128
#define NBL_DEF_CC_RST_WIN_EN 0
#define NBL_DEF_CC_RST_WIN_L 64
#define NBL_DEF_CC_RST_WIN_RTT_INT 0
#define NBL_DEF_CC_RST_WIN_RTT_FRACTION 15
#define NBL_DEF_CC_DYN_RTT_OFFSET_EN 1
#define NBL_DEF_CC_REMOVE_REMOTE_TIME 1
#define NBL_DEF_CC_HIGH_RTT_INT 2
#define NBL_DEF_CC_LOW_RTT_INT 1
#define NBL_DEF_CC_RDMA_TIME_SEL 3
#define NBL_DEF_CC_CMP_RTT_QP_MULT 0
#define NBL_DEF_CC_LOW_RTT_OFFSET 0
#define NBL_DEF_CC_HIGH_RTT_OFFSET 0
#define NBL_DEF_CC_RST_WIN_RTT_OFFSET 0
#define NBL_DEF_CC_TARGET_RTTMIN_CFG 500 /* unit 40ns, 20 us */
#define NBL_DEF_CC_TXP_SENDREQ_DB_CFG 128

/* ASIC V2 */
#define NBL_DEF_QCN_MAX_RATE_RP_V2 32000
#define NBL_DEF_QCN_SET_START_RATE_V2 25000
#define NBL_DEF_QCN_MID_SENDBLK_TH_HIGH_V2 1024
#define NBL_DEF_QCN_MID_SENDBLK_TH_LOW_V2 128
#define NBL_DEF_QCN_MID_SENDTIME_TH_HIGH_V2 1000
#define NBL_DEF_QCN_MID_SENDTIME_TH_LOW_V2 1000
#define NBL_DEF_QCN_EXTRA_QUANTA_V2 2 /* quanta=8K */
#define NBL_DEF_QCN_FAST_REDUCE_MODE_V2 0

/* DF200 */
#define NBL_DEF_QCN_MAX_RATE_RP 128000
#define NBL_DEF_QCN_MIN_RATE_RP 0
#define NBL_DEF_QCN_SET_START_RATE 100
#define NBL_DEF_QCN_RR_MODE 3
#define NBL_DEF_QCN_MID_SENDBLK_TH_HIGH 1024
#define NBL_DEF_QCN_MID_SENDBLK_TH_LOW 128
#define NBL_DEF_QCN_MID_SENDTIME_TH_HIGH 8192
#define NBL_DEF_QCN_MID_SENDTIME_TH_LOW 4096
#define NBL_DEF_QCN_AI_RP 1
#define NBL_DEF_QCN_HAI_RP 1
#define NBL_DEF_QCN_FAST_REDUCE_MODE 1
#define NBL_DEF_QCN_REDUCE_COE 1
#define NBL_DEF_QCN_SENDCNP_FLAG 1
#define NBL_DEF_QCN_SENDCNP_TIME_TH 25
#define NBL_DEF_QCN_EXTRA_QUANTA 8
#define NBL_DEF_QCN_CC2TXP_QUANTA 0
#define NBL_DEF_QCN_QUICK_START_FLAG 0
#define NBL_DEF_QCN_RR_TH 5
#define NBL_DEF_QCN_TIME_ACCUM 1
#define NBL_DEF_QCN_USE_HAI_EN 1

/* RNIC */
#define NBL_DEF_QCN_MAX_RATE_RP_400G_V4 512000
#define NBL_DEF_QCN_MAX_RATE_RP_200G_V4 256000
#define NBL_DEF_QCN_SET_START_RATE_400G_V4 400000
#define NBL_DEF_QCN_SET_START_RATE_200G_V4 200000
#define NBL_DEF_QCN_AI_RP_V4 3
#define NBL_DEF_QCN_HAI_RP_V4 6
#define NBL_DEF_QCN_MID_SENDBLK_TH_HIGH_V4 32768
#define NBL_DEF_QCN_MID_SENDBLK_TH_LOW_V4 32768
#define NBL_DEF_QCN_MID_SENDTIME_TH_HIGH_V4 1000
#define NBL_DEF_QCN_MID_SENDTIME_TH_LOW_V4 1000
#define NBL_DEF_QCN_FAST_REDUCE_MODE_V4 1
#define NBL_DEF_QCN_REDUCE_COE_V4 0
#define NBL_DEF_QCN_SENDCNP_TIME_TH_V4 500
#define NBL_DEF_QCN_ALPHA_G_V4 4
#define NBL_DEF_QCN_ALPHA_T_V4 600
#define NBL_DEF_QCN_ALPHA_RPG_RD_V4 11
#define NBL_DEF_QCN_ECN_MODE_V4 0
#define NBL_DEF_QCN_SMOOTH_PERIOD_V4 5000
#define NBL_DEF_QCN_SMOOTH_WEIGHT_V4  64
#define NBL_DEF_QCN_ECN_KMIN_V4 500
#define NBL_DEF_QCN_ECN_KMAX_V4 1012
#define NBL_DEF_QCN_ECN_PMAX_V4 256
#define NBL_DEF_QCN_EXTRA_QUANTA_V4 256
#define NBL_DEF_QCN_USE_HAI_EN_V4 0
#define NBL_DEF_QCN_CC2TXP_QUANTA_V4 1024
#define NBL_DEF_QCN_DB_TIMEOUT_V4 0x1000000
#define NBL_DEF_QCN_RR_TH_V4 1
#define NBL_DEF_QCN_NIC_SENDCNP_EN 0
#define NBL_DEF_QCN_RP_PROC_CNP_TIME 0x4e2
#define NBL_DEF_QCN_TXP_R_CNP_INVL_EN 1
#define NBL_DEF_QCN_TXP_R_CNP_INVL 0x1b1
#define NBL_DEF_QCN_TXP_R_CNP_INVL_DISABLE 0
#define NBL_DEF_QCN_TXP_R_CNP_FIFO 0x01f40003
#define NBL_DEF_QCN_TXP_R_CNP_FIFO_DISABLE 0x00030003
#define NBL_DEF_QCN_CNP_ACCOMPANIED_EN 1
#define NBL_DEF_QCN_CNP_ACCOMPANIED_EN_VALUE 9
#define NBL_DEF_QCN_CNP_ACCOMPANIED_DISABLE_VALUE 1
#define NBL_DEF_QCN_BTH_REDUCE_FLAG 1

#define NBL_PFC_CFG_NUM 3
#define NBL_PFC_CFG_PRI_OFFSET 0
#define NBL_PFC_CFG_XOFF_OFFSET 1
#define NBL_PFC_CFG_XON_OFFSET 2
#define NBL_PFC_CFG_XOFF_DEF_V4 320
#define NBL_PFC_CFG_XON_DEF_V4 288
#define NBL_PFC_CFG_UBM_TSH_DEF_V4 0x08000600
#define NBL_PFC_BUF_MAX_VAL 0x654

#define NBL_DSCP_NUM 64
#define NBL_PKT2PRI_CFG_NUM 2
#define NBL_PKT2PRI_CFG_PKT_OFFSET 0
#define NBL_PKT2PRI_CFG_PRI_OFFSET 1

#define NBL_POLL_WGT_NUM 4
#define NBL_PRI_NUM 8
#define NBL_PRI_MAX_VAL 7
#define NBL_WGT_PFC_IMAP_MAX_VAL 255
#define NBL_SPWRR_CFG_MAX 0xff
#define NBL_DB_TO_CSCH_EN_MASK 0x1f
#define NBL_SW_DB_CSCH_TH_MAX 4096
#define NBL_DSCP_MAX 63

struct nbl_ib_dbg_param {
	int			offset;
	struct nbl_device	*dev;
	struct dentry		*dentry;
};

struct nbl_ib_dbg_cc_params {
	struct dentry			*cc_root;
	struct dentry			*qcn_root;
	struct nbl_ib_dbg_param	params[NBL_CFG_CC_TYPE_MAX];
	bool has_init;
};

struct nbl_ib_dbg_qos_params {
	struct dentry *qos_root;
	struct nbl_ib_dbg_param params[NBL_CFG_QOS_TYPE_MAX];
};

struct nbl_ib_dbg_fun_params {
	struct dentry			*root;
	struct nbl_ib_dbg_param	params[NBL_FUN_DBG_TYPE_MAX];
};

struct nbl_arm_control {
	atomic_t used;
	int free;
	u32 arm_cnt;
	u32 fifo_rdcnt;
	u32 fifo_nz;
	u32 fifo_quarter;
	bool limit_reached; /* fifo reach limit last time */
};

struct nbl_stats_reg_info {
	union nbl_stats_op_info {
		struct {
			u32 op_status : 1;
			u32 op_err_warn : 1;
			u32 op_rc : 1; /* read /clear */
			u32 op_table_sel : 4;
			u32 op_id : 9;
			u32 op_len : 7;
			u32 op_addr_sel : 9;
		} v2;

		u32 data;
	} op_info;

	struct nbl_dma_mem *mem;
};

struct nbl_rdma_dev_ops {
	int (*get_init_params)(struct nbl_pci_f *rf);
	void (*init_cqp_reg)(struct nbl_pci_f *rf, bool enable);
	void (*dsch_init)(struct nbl_pci_f *rf, bool valid);
	void (*update_dsch_dport)(struct nbl_pci_f *rf, u16 dport_id, u8 valid);
	int (*stat_read)(struct nbl_pci_f *rf, struct nbl_stats_reg_info *reg_info);
	int (*stat_clear)(struct nbl_pci_f *rf, struct nbl_stats_reg_info *reg_info);
	int (*hw_stat_errcode_enable)(struct nbl_pci_f *rf, bool enable);
	int (*set_cc_glb_cfg)(struct nbl_pci_f *rf, u32 offset, u32 var);
	void (*set_net_tc_tbl)(struct nbl_pci_f *rf);
	void (*tqp_flush)(struct nbl_pci_f *rf);
	void (*rq_db_flush)(struct nbl_pci_f *rf);
	void (*armcq_db_flush)(struct nbl_pci_f *rf);
	int (*get_armcq_flush_status)(struct nbl_pci_f *rf);
};

/* get_obj_sz can be NULL
 * set_voa_tbl/get_voa_tbl can be NULL
 * set_sd_range/get_sd_range can be NULL, if set this two must in pairs
 * global_sd_init/global_sd_deinit can be NULL, if set this two must in pairs
 * obj_sd_init can not be NULL
 */
struct nbl_resource_ops {
	void (*set_vf_enable)(struct nbl_pci_f *rf, u16 function_id, u8 enable);
	u16 (*get_obj_sz)(u8 obj_type);
	int (*set_voa_tbl)(struct nbl_pci_f *rf, u16 function_id, bool valid);
	void (*set_sd_range)(struct nbl_pci_f *rf, bool valid);
	void (*get_sd_range)(void);
	void (*get_voa_tbl)(struct nbl_pci_f *rf);
	void (*set_vfid_vsi_map)(struct nbl_pci_f *rf, bool valid, u16 vsi_id);
	int (*global_sd_init)(struct nbl_pci_f *rf);
	void (*global_sd_deinit)(struct nbl_pci_f *rf);
	int (*obj_sd_init)(struct nbl_pci_f *rf, enum nbl_hmc_rsrc_type obj_type,
			   struct nbl_hmc_obj_sd_info *obj_sd_info, u8 obj_type_max);
	void (*set_vf_pf_map)(struct nbl_pci_f *rf);
};

struct nbl_cqp_ops {
	int (*cqp_create_cq)(struct nbl_pci_f *rf, struct nbl_sc_cq *sc_cq);
	int (*cqp_destroy_cq)(struct nbl_pci_f *rf, struct nbl_sc_cq *cq);
	int (*cqp_cq_ref_add)(struct nbl_pci_f *rf, struct nbl_sc_cq *sc_cq);
	int (*cqp_cq_ref_sub)(struct nbl_pci_f *rf, struct nbl_sc_cq *sc_cq);
	int (*cqp_cq_resize)(struct nbl_pci_f *rf, struct nbl_sc_cq *sc_cq,
				struct nbl_modify_cq_info *info);
	int (*cqp_dbg_create_cq)(struct nbl_pci_f *rf, u32 cqn_input);
	int (*cqp_dbg_destroy_cq)(struct nbl_pci_f *rf, u32 cqn_input);
};

struct nbl_obj_cnt {
	u32 qp_num;
	u32 cq_num;
	u32 pble_num;
	u32 mr_num;
	u32 srq_num;
};

union nbl_grc_init_reg {
	u32 data[1];
	struct grc_init_key {
		u32 sd_addr_mode : 2;
		u32 resource_profile : 1;
		u32 qp_limits_sel : 3;
		u32 function_num : 4;
		u32 obj_mem_mode : 2; /* hmc, ddr with 1M qp, ddr with 512k qp */
		u32 grc_stat : 1;
		u32 resv : 19;
	} key;

};

struct nbl_pf_init_param {
	u32 qpn_start;
	u32 qpn_end;
	u8 addr_mode;
	u8 res_profile;
	u16 vf_cnt;
	u32 total_qp_cnt;
	u32 qp_per_vf;
};

struct nbl_hbf_entry {
	u32 host_id;
	u32 bdf_num;
	u16 func_id;
	bool valid;
};

struct nbl_hbf_tbl {
	struct nbl_hbf_entry entries[NBL_RDMA_TOTAL_FUNCTION_NUM];
};

/* radix for resource */
struct nbl_res_table {
	spinlock_t lock; /* protect radix tree */
	struct radix_tree_root tree;
};

struct devx_umem;
struct nbl_pci_f {
	const struct nbl_product_desc *product;
	struct nbl_product_runtime_info product_runtime;
	u64 effective_caps;
	u8 addr_mode;
	u8 *mem_rsrc;
	u8 *hmc_info_mem;
	u32 max_mr;
	u32 max_qp;
	u32 max_cq;
	u32 max_ah;
	u32 max_pd;
	u32 max_srq;
	u32 max_xrcd;
	u32 max_dpage;
	u32 max_devx_umem;
	u32 next_pd;
	u32 next_ah;
	u32 ceqs_count;
	u32 msix_count;
	u16 msix_ceq_base_id;
	u32 max_cqe;
	u32 next_cq;
	u32 next_qp;
	u32 next_srq;
	u32 next_dpage;
	u32 start_dpage;
	u32 next_devx_umem;

	u32 used_pds;
	u32 used_cqs;
	u32 used_qps;
	atomic_t used_mrs_a;

	unsigned long *allocated_qps;
	unsigned long *allocated_mrs;
	unsigned long *allocated_pds;
	unsigned long *allocated_ahs;
	unsigned long *allocated_cqs;
	unsigned long *allocated_srq;
	unsigned long *allocated_xrcd;
	unsigned long *allocated_dpage;
	unsigned long *allocated_devx_umem;
	struct nbl_sc_dev sc_dev;
	struct pci_dev *pcidev;
	struct nbl_cmd cmd;
	struct nbl_grc grc;
	struct nbl_tlp tlp;
	struct nbl_mbx mbx;

	struct nbl_aeq aeq;
	struct nbl_ceq *ceqlist;

	struct nbl_msix_vector *nbl_msixtbl;
	struct msix_entry *msix_entries;

	struct tasklet_struct dpc_tasklet;
	enum init_completion_state init_state;
	spinlock_t rsrc_lock; /* protect HW resource array access */
	spinlock_t qptable_lock; /*protect QP table access*/
	spinlock_t srqtable_lock;
	spinlock_t devx_umem_table_lock;
	spinlock_t cq_arm_lock; /* cq arm lock */
	spinlock_t hw_stat_lock; /* protect stat hw opcode */
	struct nbl_qp **qp_table;
	struct nbl_res_table cq_table;
	struct nbl_srq **srq_table;
	struct devx_umem **devx_umem_table;
	struct nbl_hmc_pble_rsrc *pble_rsrc;

	struct nbl_hw hw;
	struct nbl_hmc_obj_sd_info *qp_sd_info;
	struct nbl_hmc_obj_sd_info *cq_sd_info;
	struct nbl_hmc_obj_sd_info *pbl_sd_info;
	struct nbl_hmc_obj_sd_info *mrt_sd_info;
	struct nbl_hmc_obj_sd_info *srq_sd_info;
	int *qp_seq_table;
	u64 *qp_return_ts; /* QPN come back time, us */
	struct semaphore qp_flush_sem;
	struct workqueue_struct *dump_wq; /* dump ae err */
	struct workqueue_struct *flush_wq;
	struct workqueue_struct *cleanup_wq;
	struct workqueue_struct *abnormal_evt_wq;
	struct work_struct abnormal_task;
	struct nbl_hmc_sd_range hmc_sd_range[NBL_RDMA_TOTAL_FUNCTION_NUM];
	struct nbl_init_params init_params;
	union nbl_hmc_voa_entry_v2 voa_tbl_v2[NBL_RDMA_TOTAL_FUNCTION_NUM][NBL_HMC_MAX];
	void *cdev;
	u16 vsi_id;
	u16 rx_vlan_vsi_id[4];
	u32 tlp_timeout;

	struct nbl_arm_control armc; /* only V1R1 */
	const struct nbl_rdma_dev_ops *dev_ops;
	const struct nbl_cqp_ops *cqp_ops;
	union nbl_grc_init_reg grc_init_reg;
	struct nbl_obj_cnt dev_objs[NBL_RDMA_TOTAL_FUNCTION_NUM];
	struct nbl_adev *adev;
	struct nbl_pf_init_param pf_param;
	struct nbl_hbf_tbl hbf_tbl;

	u8 *srq_seq_table;
	struct nbl_src_addr_rsrc src_addr_rsrc; /* pf use only */
	spinlock_t addr_tbl_lock;
	struct list_head src_addr_list; /* src addr local buf */

	int rdma_reset;
	u32 internal_cfg;
};

struct nbl_lag_ops {
	int (*nbl_holb_set)(struct nbl_pci_f *rf, bool muti_active_port);
};

enum nbl_cqp_cache_hit_type {
	NBL_CACHE_HIT_QPCC,
	NBL_CACHE_HIT_CQCC,
	NBL_CACHE_HIT_MRTC,
	NBL_CACHE_HIT_PBLC,
	NBL_CACHE_HIT_SQRQEC,
	NBL_CACHE_HIT_UNAQC,
	NBL_CACHE_HIT_SRQC,
	NBL_CACHE_HIT_PDC,
	NBL_CACHE_HIT_IORQEC,
	NBL_CACHE_HIT_RAQEC,
	NBL_CACHE_HIT_MAX,
};

struct nbl_ib_dbg_cache_hit_params {
	struct dentry *cache_hit_root;
	struct nbl_ib_dbg_param params[NBL_CACHE_HIT_MAX];
};

struct nbl_cache_hit_stats {
	u64 total_stats;
	u64 miss_stats;
};

struct cache_hit_work {
	struct work_struct work;
	struct nbl_device *nbl_dev;
};

struct nbl_cache_hit_info {
	struct nbl_device *nbldev;
	struct workqueue_struct *cache_hit_wq;
	struct cache_hit_work *cachework;
	struct timer_list cache_hit_timer;
	struct nbl_cache_hit_stats result[NBL_CACHE_HIT_MAX];
	bool enable;
};

struct umr_wr {
	u8 opcode; /* NBL_UMR_OP_REVOKE or others */
	u32 mkey; /* 32bit mkey */
};

struct umr_common {
	struct ib_pd *pd;
	struct ib_cq *cq;
	struct ib_qp *qp;
	struct semaphore sem;
	unsigned int state;
};

struct nbl_tc_data {
	struct mutex lock;
	bool initialized;
	int val;
	struct kobject kobj;
	struct nbl_device *nbldev;
};

enum {
	NBL_CONG_PROTOCOL_ROCE_RP,
	NBL_CONG_PROTOCOL_ROCE_NP,
	NBL_CONG_PROTOCOL_NUM,
};

struct nbl_ecn_rp_attributes {
	struct nbl_device	*nbldev;
	/* ATTRIBUTES */
	struct kobj_attribute	qcn_rr_th;
	struct kobj_attribute	qcn_quick_start_flag;
	struct kobj_attribute	qcn_ai_rp;
	struct kobj_attribute	qcn_hai_rp;
	struct kobj_attribute	qcn_max_rate_rp;
	struct kobj_attribute	qcn_min_rate_rp;
	struct kobj_attribute	qcn_start_rate;
	struct kobj_attribute	qcn_rr_mode;
	struct kobj_attribute	qcn_mid_sendblk_th_high;
	struct kobj_attribute	qcn_mid_sendblk_th_low;
	struct kobj_attribute	qcn_mid_sendtime_th_high;
	struct kobj_attribute	qcn_mid_sendtime_th_low;
	struct kobj_attribute	qcn_extra_quanta;
	struct kobj_attribute	qcn_fast_reduce_mode;
	struct kobj_attribute	qcn_reduce_coe;
	struct kobj_attribute	qcn_clamp_rt;
	struct kobj_attribute	qcn_alpha_g;
	struct kobj_attribute	qcn_alpha_t;
};

struct nbl_ecn_np_attributes {
	struct nbl_device	*nbldev;
	/* ATTRIBUTES */
	struct kobj_attribute	qcn_sendcnp_flag;
	struct kobj_attribute	qcn_sendcnp_time_th;
};

union nbl_ecn_attributes {
	struct nbl_ecn_rp_attributes rp_attr;
	struct nbl_ecn_np_attributes np_attr;
};

struct nbl_ecn_ctx {
	struct kobject *ecn_proto_kobj;
	union nbl_ecn_attributes ecn_attr;
};

struct nbl_sysfs_cc_params {
	struct nbl_device	*nbldev;
	struct kobject		*cc_root_kobj;
	struct kobj_attribute	cc_mode;
	struct kobj_attribute	cc_en;
	struct kobj_attribute	cc_oamreq_tc_en;
	struct kobj_attribute	cc_oamreq_net_tc;
	struct kobj_attribute	cc_oamack_tc_en;
	struct kobj_attribute	cc_oamack_net_tc;
	struct kobj_attribute	cc_oamack_blk_th;
	struct kobj_attribute	cc_targetwin_min;
	struct kobj_attribute	cc_pkt_num_en;
	struct kobj_attribute	cc_high_rtt_fraction;
	struct kobj_attribute	cc_low_rtt_fraction;
	struct kobj_attribute	cc_inc_tarwinth;
	struct kobj_attribute	cc_dec_tarwinth;
	struct kobj_attribute	cc_targetwin;
	struct kobj_attribute	cc_rtt_offset;
	struct kobj_attribute	cc_rtt_probe_invl;
	struct kobj_attribute	cc_high_pri_rtt_invl;
	struct kobj_attribute	cc_high_pri_rtt_en;
	struct kobj_attribute	cc_rst_win_high;
	struct kobj_attribute	cc_rst_win_en;
	struct kobj_attribute	cc_rst_win_low;
	struct kobj_attribute	cc_rst_win_rtt_int;
	struct kobj_attribute	cc_rst_win_rtt_fraction;
	struct kobj_attribute	cc_dyn_rtt_offset_en;
	struct kobj_attribute	cc_remove_remote_time;
	struct kobj_attribute	cc_high_rtt_int;
	struct kobj_attribute	cc_low_rtt_int;
	struct kobj_attribute	cc_rdma_time_sel;
	struct kobj_attribute	cc_cmp_rtt_qp_mult;
	struct kobj_attribute	cc_low_rtt_offset;
	struct kobj_attribute	cc_high_rtt_offset;
	struct kobj_attribute	cc_rst_win_rtt_offset;
	struct kobj_attribute	cc_txp_sendreq_db_cfg;
};

struct nbl_sysfs_qos_info {
	int	offset;
	struct nbl_device	*nbldev;
	struct kobj_attribute kobj_attr;
};

struct nbl_sysfs_qos_params {
	struct kobject	*qos_root_kobj;
	struct nbl_sysfs_qos_info params[NBL_CFG_QOS_TYPE_MAX];
};

struct nbl_sysfs_stats_params {
	struct nbl_device	*nbldev;
	struct kobject	*stats_root_kobj;
	struct bin_attribute stats;
	struct mutex lock;
};

struct nbl_device {
	struct ib_device ibdev;
	struct nbl_pci_f *rf;
	struct net_device *netdev;
	struct nbl_sc_pd sc_pd;
	u32 device_cap_flags;
	enum init_completion_state init_state;
	u8 status;
	u8 active_speed;
	u8 active_width;
	u8 init_create_qp_num;
	struct umr_common umrc;
	char qos_eth_dbgfs_params[NBL_ETH_MAX_NUM][NBL_CFG_QOS_TYPE_MAX][NBL_PARAM_LEN];
	/* debugfs */
	struct dentry *func_dbg_dir;
	struct nbl_rdma_stat *func_stat;
	struct nbl_dump_info *func_dump_info;
	struct nbl_ib_dbg_cc_params *dbg_cc_params;
	struct nbl_ib_dbg_fun_params *dbg_fun_params;
	struct nbl_ib_dbg_qos_params *qos_params;
	struct nbl_ib_dbg_param *pt_params;
	struct dentry *pt_root;
	struct nbl_ib_dbg_cache_hit_params *cache_hit_params;
	struct nbl_cache_hit_info *cache_hit_info;
	struct dentry *qp_debugfs;
	/* sysfs */
	struct kobject	*tc_kobj;
	struct nbl_tc_data tcd[NBL_MAX_PORT];
	struct kobject	*ecn_root_kobj;
	struct kobj_attribute	cc_en;
	struct kobj_attribute	cc_mode;
	struct nbl_ecn_ctx ecn_ctx[NBL_CONG_PROTOCOL_NUM];
	struct nbl_sysfs_cc_params sysfs_cc_params;
	struct nbl_sysfs_qos_params sysfs_qos_params;
	struct nbl_sysfs_stats_params sysfs_stats_params[NBL_MAX_PORT];
	struct notifier_block nb;
	struct notifier_block mtu_nb;
	struct notifier_block lag_mbr_nb;
	struct notifier_block ovs_offld_nb;
	struct notifier_block grc_abn_nb;
	struct notifier_block qos_cfg_nb;
	struct notifier_block qos_show_nb;
	struct notifier_block ecpu_bond_nb;
};

struct grc_cache_msg_header {
	uint8_t rsv;
	uint8_t op_code;
	uint8_t payload_len;
};

#define NBL_GET_GRC_INIT_PARAM_RETRY_CNT 5
#define NBL_GET_INIT_PARAM_TIME_INTERVAL 100 /* 100ms */
#define NBL_GRC_INIT_PARAM_REG 0xffff
#define NBL_GRC_STAT_READY 1
#define NBL_RDMA_VERSION_SZ 4

enum nbl_obj_mem_mode {
	OBJ_INVALID_MODE,
	OBJ_IN_DDR,
	OBJ_IN_MINI_DDR,
	OBJ_IN_HMC,
	OBJ_MODE_MAX,
};

/* rdma reset work */
extern struct workqueue_struct *reset_wq;

#define NBL_RESET_WORK_DELAY_MS 100

static inline struct nbl_cq *to_nbl_cq(struct ib_cq *ibcq)
{
	return container_of(ibcq, struct nbl_cq, ibcq);
}

static inline struct nbl_srq *to_nbl_srq(struct ib_srq *ibsrq)
{
	return container_of(ibsrq, struct nbl_srq, ibsrq);
}

static inline struct nbl_device *to_nbl_dev(struct ib_device *ibdev)
{
	return container_of(ibdev, struct nbl_device, ibdev);
}

static inline struct nbl_xrcd *to_nbl_xrcd(struct ib_xrcd *ibxrcd)
{
	return container_of(ibxrcd, struct nbl_xrcd, ibxrcd);
}

/**
 * nbl_alloc_resource - allocate a resource
 * @lock: lock pointer
 * @resource_array: resource bit array:
 * @max_resources: maximum resource number
 * @req_resources_num: Allocated resource number
 * @next: next free id
 **/
static inline int nbl_alloc_rsrc(spinlock_t *lock, unsigned long *rsrc_array,
				 u32 max_rsrc, u32 *req_rsrc_num, u32 *next)
{
	u32 rsrc_num;
	unsigned long flags;

	spin_lock_irqsave(lock, flags);
	rsrc_num = find_next_zero_bit(rsrc_array, max_rsrc, *next);
	if (rsrc_num >= max_rsrc) {
		rsrc_num = find_first_zero_bit(rsrc_array, max_rsrc);
		if (rsrc_num >= max_rsrc) {
			nbl_pr_err(
				"find_first_zero_bit failed, the rsrc_num is %u, max_rsrc:%u\n",
				rsrc_num, max_rsrc);
			spin_unlock_irqrestore(lock, flags);
			return -EOVERFLOW;
		}
	}
	__set_bit(rsrc_num, rsrc_array);
	*next = rsrc_num + 1;
	if (*next == max_rsrc)
		*next = 0;
	*req_rsrc_num = rsrc_num;
	spin_unlock_irqrestore(lock, flags);

	return 0;
}

static inline int nbl_alloc_dpage_rsrc(spinlock_t *lock, unsigned long *rsrc_array,
				       u32 max_rsrc, u32 *req_rsrc_num, u32 *next, u32 start)
{
	u32 rsrc_num;
	unsigned long flags;

	spin_lock_irqsave(lock, flags);
	rsrc_num = find_next_zero_bit(rsrc_array, max_rsrc, *next);
	if (rsrc_num >= max_rsrc) {
		rsrc_num = find_next_zero_bit(rsrc_array, max_rsrc, start);
		if (rsrc_num >= max_rsrc) {
			nbl_pr_dbg(
				"find_first_zero_bit failed, the rsrc_num is %u, max_rsrc:%u\n",
				rsrc_num, max_rsrc);
			spin_unlock_irqrestore(lock, flags);
			return -EOVERFLOW;
		}
	}
	__set_bit(rsrc_num, rsrc_array);
	*next = rsrc_num + 1;
	if (*next == max_rsrc)
		*next = start;
	*req_rsrc_num = rsrc_num;
	spin_unlock_irqrestore(lock, flags);

	return 0;
}

static inline void nbl_free_rsrc(spinlock_t *lock, unsigned long *rsrc_array,
				 u32 rsrc_num)
{
	unsigned long flags;

	spin_lock_irqsave(lock, flags);
	__clear_bit(rsrc_num, rsrc_array);
	spin_unlock_irqrestore(lock, flags);
}

static inline u64 get_current_time_us(void)
{
	return ktime_to_us(ktime_get_boottime());
}

/* QPN default alloc interval in us */
#define QPN_INTERVAL 2000000

static inline int nbl_alloc_qpn_rsrc(struct nbl_pci_f *rf, u32 *req_rsrc_num, u32 *next)
{
	u32 rsrc_num;
	u32 next_find = *next;
	u64 now;
	bool find = false;
	unsigned long flags;

	spin_lock_irqsave(&rf->rsrc_lock, flags);

	now = get_current_time_us(); /* get time now in us */

	/* check offset <---> end */
	while ((rsrc_num = find_next_zero_bit(rf->allocated_qps, rf->max_qp, next_find))
			< rf->max_qp) {
		if ((rf->sc_dev.qpn_interval == 0) ||
			((now - rf->qp_return_ts[rsrc_num]) > rf->sc_dev.qpn_interval)) {
			find = true;
			break;
		}
		next_find = (rsrc_num + 1);
	}

	/* check start <---> offset */
	if (!find && *next != 0) {
		next_find = 0;
		while ((rsrc_num = find_next_zero_bit(rf->allocated_qps, *next, next_find))
				< *next) {
			if ((rf->sc_dev.qpn_interval == 0) ||
				((now - rf->qp_return_ts[rsrc_num]) > rf->sc_dev.qpn_interval)) {
				find = true;
				break;
			}
			next_find = (rsrc_num + 1);
		}
	}

	if (!find) {
		nbl_pr_err(
			"find qpn with time %u us failed, max qp num:%u\n",
			QPN_INTERVAL, rf->max_qp);
		spin_unlock_irqrestore(&rf->rsrc_lock, flags);
		return -EOVERFLOW;
	}

	__set_bit(rsrc_num, rf->allocated_qps);
	*next = rsrc_num + 1;
	if (*next == rf->max_qp)
		*next = 0;
	*req_rsrc_num = rsrc_num;
	spin_unlock_irqrestore(&rf->rsrc_lock, flags);

	return 0;
}

static inline void nbl_free_qpn_rsrc(struct nbl_pci_f *rf, u32 rsrc_num)
{
	unsigned long flags;

	spin_lock_irqsave(&rf->rsrc_lock, flags);
	__clear_bit(rsrc_num, rf->allocated_qps);
	rf->qp_return_ts[rsrc_num] = get_current_time_us();
	spin_unlock_irqrestore(&rf->rsrc_lock, flags);
}

enum nbl_status_code nbl_ctrl_init_hw(struct nbl_pci_f *rf);

static inline struct nbl_ucontext *to_ucontext(struct ib_ucontext *ibucontext)
{
	return container_of(ibucontext, struct nbl_ucontext, ibucontext);
}

static inline u32 nbl_get_sd_alignment(struct nbl_pci_f *rf)
{
	return rf->addr_mode == LEVEL0_WITH_SZ_4K ? SZ_4K : SZ_2M;
}

void nbl_deinit_qps(struct nbl_pci_f *rf);
enum nbl_status_code nbl_init_qps(struct nbl_pci_f *rf);
enum nbl_status_code nbl_initialize_hw_rsrc(struct nbl_pci_f *rf);
enum nbl_status_code nbl_rt_init_hw(struct nbl_device *nbl_dev);
void nbl_rt_deinit_hw(struct nbl_device *nbl_dev);
void nbl_ctrl_deinit_hw(struct nbl_pci_f *rf);
int nbl_hmc_setup(struct nbl_pci_f *rf);
int nbl_setup_voa(struct nbl_pci_f *rf);
int nbl_destroy_voa(struct nbl_pci_f *rf);
int nbl_flush_pdc_cache(struct nbl_pci_f *rf, u16 flush_vfid);
void nbl_hmc_destroy(struct nbl_pci_f *rf);
int nbl_get_obj_sd_addr(struct nbl_pci_f *rf, enum nbl_hmc_rsrc_type obj_type,
			struct nbl_hmc_obj_sd_info *obj_sd_info);
void nbl_free_obj_sd_addr(struct nbl_hmc_obj_sd_info *obj_sd_info);
int nbl_exec_cmd(struct nbl_pci_f *rf, void *in, int in_size, void *out, int out_size);
int nbl_dbg_mem_read(struct nbl_device *nbl_dev, u64 pa);
int nbl_dump_hw_cache(struct nbl_device *nbl_dev, u32 dump_mask, enum nbl_cqp_cache_type type);
void nbl_clear_hw_cache(struct nbl_pci_f *rf, enum nbl_cqp_cache_type cache_type);
int nbl_dump_hmc_qpc(struct nbl_device *nbl_dev, u32 dump_mask);
int nbl_dump_hmc_cqc(struct nbl_device *nbl_dev, u32 dump_mask);
int nbl_dump_hmc_pble(struct nbl_pci_f *rf, u32 dump_mask);
int nbl_dump_hmc_mrt(struct nbl_device *nbl_dev, u32 dump_mask);
void nbl_dump_sqe(struct nbl_device *nbl_dev, u32 dump_mask);
int nbl_query_voa(char __user *buf, size_t count, loff_t *pos, struct nbl_pci_f *rf);
void nbl_dump_hex(struct nbl_pci_f *rf, u8 *buf, int len);
void nbl_hmc_query_sd(struct nbl_pci_f *rf, u32 dump_mask);
void nbl_query_global_sd(struct nbl_pci_f *rf, u32 dump_mask);
int nbl_dbg_create_qp(struct nbl_pci_f *rf, u32 qpn_input);
int nbl_dbg_destroy_qp(struct nbl_pci_f *rf, u32 qpn_input);
int nbl_dbg_v2_create_cq(struct nbl_pci_f *rf, u32 cqn_input);
int nbl_dbg_v2_destroy_cq(struct nbl_pci_f *rf, u32 cqn_input);
int nbl_dump_pble_cnt(struct nbl_pci_f *rf);

void nbl_rdma_update_dsch_info(struct nbl_pci_f *rf);
void nbl_set_sd_range(struct nbl_pci_f *rf, bool valid);
int nbl_notify_set_direct(struct nbl_pci_f *rf, bool valid);
int nbl_set_notify_bar_addr(struct nbl_pci_f *rf, bool valid);
int nbl_notify_set_via_channel(struct nbl_pci_f *rf, bool valid);
int nbl_notify_set(struct nbl_pci_f *rf, bool valid);
int nbl_global_sd_init(struct nbl_pci_f *rf);
void nbl_global_sd_deinit(struct nbl_pci_f *rf);
int nbl_global_q_init(struct nbl_pci_f *rf);
void nbl_global_q_deinit(struct nbl_pci_f *rf);
int nbl_obj_sd_init_v2(struct nbl_pci_f *rf, enum nbl_hmc_rsrc_type obj_type,
		       struct nbl_hmc_obj_sd_info *obj_sd_info, u8 obj_type_max);
void nbl_direct_set_vf_pf_map(struct nbl_pci_f *rf);
void nbl_set_vf_pf_map(struct nbl_pci_f *rf);
void nbl_get_pf_voa_tbl_v2(struct nbl_pci_f *rf);
int nbl_set_qm_vfid_vsi_map(struct nbl_pci_f *rf, u8 is_valid);
void nbl_rdma_get_psn_ost(struct nbl_device *nbl_dev, u32 *psn_ost);
void nbl_rdma_rxm_write_atomic_fence(struct nbl_device *nbl_dev, bool enable);
void nbl_rdma_set_psn_ost(struct nbl_device *nbl_dev, u32 psn_ost);
void nbl_rdma_get_rdma_dport(struct nbl_device *nbl_dev, u32 *rdma_dport);
void nbl_rdma_set_rdma_dport(struct nbl_device *nbl_dev, u32 rdma_dport);
void nbl_rdma_set_llc(struct nbl_device *nbl_dev, u32 enable);
void nbl_init_sd_range(struct nbl_pci_f *rf, u16 function_id);
void nbl_set_default_fwd(struct nbl_pci_f *rf);
int nbl_set_cc_glb_cfg(struct nbl_pci_f *rf, u32 offset, u32 var);
int nbl_set_hw_cc_reg(struct nbl_hw *hw, u32 offset, u32 var);
void nbl_set_net_tc_tbl(struct nbl_pci_f *rf);
void nbl_set_hw_net_tc_tbl(struct nbl_hw *hw);
int nbl_set_mtu(int mtu, struct nbl_device *nbl_dev);
void nbl_reset_same_pci_dev(struct nbl_device *nbl_dev);
void nbl_sched_qp_flush_work(struct nbl_qp *qp);
void nbl_set_srp_cfg(struct nbl_device *nbl_dev, u32 value, u8 offset_code);
void nbl_ibdev_set_dim(struct ib_device *ibdev, u8 use_dim);
void nbl_init_src_addr(struct nbl_pci_f *rf);
void nbl_deinit_src_addr(struct nbl_pci_f *rf);
int nbl_flush_s2_cache(struct nbl_pci_f *rf, u16 flush_vfid);

/* sysfs */
u32 show_cc_param(struct nbl_device *dev, int offset);
int config_cc_param(struct nbl_device *dev, int offset, u32 var);
int show_qos_param(struct nbl_device *nbldev, int offset, char *lbuf);
ssize_t config_qos_param(struct nbl_device *nbldev, int offset, char *lbuf);
ssize_t config_stats_param(struct nbl_device *nbl_dev, char *lbuf, size_t count);
void nbl_sysfs_init(struct nbl_device *nbldev);
void nbl_sysfs_exit(struct nbl_device *nbldev);
ssize_t nbl_qos_cfg_store_v2(struct nbl_device *nbl_dev, int offset,
			     const char *buf, size_t count);
ssize_t nbl_qos_cfg_show_v2(struct nbl_device *nbl_dev, int offset,
			    char *buf);

/* qp dbg */
int nbl_debug_qp_add(struct nbl_device *dev, struct nbl_qp *qp);
void nbl_debug_qp_remove(struct nbl_device *dev, struct nbl_qp *qp);

#endif /* NBL_MAIN_H */
