/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_MAIN_H
#define NBL_MAIN_H

#include <linux/auxiliary_bus.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <rdma/uverbs_ioctl.h>
#include <rdma/ib_verbs.h>
#include <linux/pci.h>
#include <linux/if_vlan.h>

#include "rdma_common.h"
#include "grc_common.h"
#include "debug.h"
#include "hmc.h"
#include "hw.h"
#include "type.h"
#include "device.h"
#include "verbs.h"
#include "defs.h"
#include "nbl_adapt.h"

#define RDMA_DRIVER_NBLPRIV 41

#define NBL_MAX_PORT 1
#define NBL_HEX_DUMP_ROW 16
#define NBL_HEX_DUMP_GRP 1
#define NBL_HEX_DUMP_BUF_MAX 256

#define NBL_ETH_MAX_NUM 4

#define NBL_GET_PRI_FROM_T2P(_t2p, _pri)  (((_t2p) >> (3 * (_pri))) & 0x7)
#define NBL_SET_PRI_TO_T2P(_t2p, _tc, _pri) \
	do {	\
		u64 __mask = ~(0x7 << ((_tc) * 3));	\
		(_t2p) = ((_t2p) & __mask) | (((_pri) & 0x7) << ((_tc) * 3));	\
	} while (0)

#define NBL_SRC_IP_SIZE 16

#define NBL_RESERVE_START_IOVA 0x1000
#define NBL_RESERVE_END_IOVA 0x10000
#define NBL_RESERVE_RANGE_IOVA (NBL_RESERVE_END_IOVA - NBL_RESERVE_START_IOVA)

#define NBL_ADAPTER_PAGE_SHIFT 12
#define NBL_ADAPTER_PAGE_SIZE (1 << NBL_ADAPTER_PAGE_SHIFT)

#define NBL_CMD_ENTRY_SIZE 128
#define NBL_CMD_ENTRY_SIZE_LOG 7
#define NBL_CMD_ENTRY_MAX_NUM (NBL_ADAPTER_PAGE_SIZE / NBL_CMD_ENTRY_SIZE)
#define NBL_CMD_WQ_MAX_NAME 32
#define NBL_CMD_INT_USE_WQ 1 /* 1- use wq when interrupt mode, save time, 0- not use wq */

#define NBL_GRC_WQ_MAX_NAME 32
#define NBL_TLP_WQ_MAX_NAME 32
#define NBL_MBX_WQ_MAX_NAME 32
#define NBL_DMA_ADDRESS_SIZE 8
#define NBL_MAX_RQWQE_SGE 6
#define NBL_MIN_RQWQE_SGE 2
#define NBL_MAX_RQ_QUANATA 128
#define NBL_MIN_RQ_QUANATA 64
#define NBL_MAX_SEND_INLINE 48
#define NBL_MAX_WRITE_INLINE 32
#define NBL_MAX_QP_WR 32768
#define NBL_MIN_QP_DEPTH 32768
#define NBL_RQ_RSVD 1
#define NBL_SQ_RSVD 256
#define NBL_RDMA_TOTAL_FUNCTION_NUM 64
#define NBL_RDMA_FIRST_FUNCTION_ID 0
#define NBL_DEFAULT_MAX_SGE 6
#define NBL_HW_FLUSH_CNT 4096
#define NBL_HMC_MAX_OBJ_LOG_SZ 9   /* qpc log size (1 << 9) */

#define NBL_RDMA_DSCH_VALID 1
#define NBL_RDMA_DSCH_INVALID 0

#define NBL_TLP_TIMEOUT_MSEC 60 /* time for tlp to finish a request,4fpga 30 */

#define VOA_QPC_OFFSET 32
#define VOA_ENT_SIZE 8
#define VOA_TBL_STR_LEN 512
#define VOA_TBL_ENTRY_FORMAT                                                   \
	("voa_ent[%u]:vld=%u,obj_base_ba=0x%x,obj_max_num=0x%x,"               \
	 "obj_sz=%u,page_sz=%u,page_mode=%u\n")

#define NBL_INVAILD_VIS_ID	0xffff

enum nbl_event_type {
	NBL_EVENT_LAG_EN,
	NBL_EVENT_LINK_CHNG,
	NBL_EVENT_NBITS		/* must be last */
};

union nbl_event_info {
	bool lag_en;
};
struct nbl_event {
	DECLARE_BITMAP(type, NBL_EVENT_NBITS);
	union nbl_event_info info;
};
struct nbl_auxiliary_drv {
	struct auxiliary_driver adrv;
	void (*event_handler)(struct nbl_core_dev_info *cdev_info,
			      struct nbl_event *event);
};

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
	NBL_ERR_Q_EMPTY = -22,
	NBL_ERR_CQ_COMPL_ERROR = -67,
	NBL_ERR_Q_DESTROYED = -68,
	NBL_ERR_SGE_NOTSUPPORTED = -49,
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
	char name[NBL_MAX_IRQ_NAME];
	u32 ceq_id;
	struct nbl_pci_f *rf;
	struct tasklet_struct dpc_tasklet;
	/* sync cq destroy with cq completion event notification */
	spinlock_t ce_lock;
	spinlock_t ce_reslock;
	struct nbl_frag_buf buf;
	refcount_t refcnt;
	bool ceq_valid;
	struct completion ceq_comp;
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
	u32 ceq_id;
	char name[NBL_MAX_IRQ_NAME];
	cpumask_t mask;
};

struct nbl_hmc_voa_entry {
	u64 addr_mode : 1;
	u64 page_sz : 1;
	u64 obj_sz : 4;
	u64 rsv : 5;
	u64 obj_max_cnt : 29;
	u64 obj_ba : 23;
	u64 valid : 1;
};

/* common define*/
enum nbl_ib_cc_mode_types {
	NBL_CC = 1,
	NBL_QCN = 2,
};

#define NBL_DEF_CC_MODE 0
#define NBL_DEF_CC_EN 1
#define NBL_DEF_CC_OAMREQ_TC_EN 0
#define NBL_DEF_CC_OAMREQ_NET_TC 6
#define NBL_DEF_CC_OAMACK_TC_EN 1
#define NBL_DEF_CC_OAMACK_NET_TC 6
#define NBL_DEF_CC_OAMACK_BLK_TH 64
#define NBL_DEF_CC_TARGETWIN_MIN 1
#define NBL_DEF_CC_PKT_NUM_EN 0
#define NBL_DEF_CC_HIGH_RTT_FRACTION 0
#define NBL_DEF_CC_LOW_RTT_FRACTION 0
#define NBL_DEF_CC_INC_TARGET_WIN_TH 64
#define NBL_DEF_CC_DEC_TARGET_WIN_TH 128
#define NBL_DEF_CC_TARGETWIN 64
#define NBL_DEF_CC_RTT_OFFSET 130
#define NBL_DEF_CC_RTT_PROBE_INVL 2
#define NBL_DEF_CC_HIGH_PRI_RTT_INVL 32
#define NBL_DEF_CC_HIGH_RPI_RTT_EN 1
#define NBL_DEF_CC_RST_WIN_H 128
#define NBL_DEF_CC_RST_WIN_EN 1
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
#define NBL_DEF_CC_TXP_SENDREQ_DB_CFG 128
#define NBL_DEF_QCN_RR_MODE 3
#define NBL_DEF_QCN_MID_SENDBLK_TH_HIGH 1024
#define NBL_DEF_QCN_MID_SENDBLK_TH_LOW 200
#define NBL_DEF_QCN_MID_SENDTIME_TH_HIGH 8192
#define NBL_DEF_QCN_MID_SENDTIME_TH_LOW 4096
#define NBL_DEF_QCN_RR_TH 5
#define NBL_DEF_QCN_AI_RP 1
#define NBL_DEF_QCN_HAI_RP 1
#define NBL_DEF_QCN_MIN_RATE_RP 0
#define NBL_DEF_QCN_MAX_RATE_RP 140000
#define NBL_DEF_QCN_QUICK_START_FLAG 0
#define NBL_DEF_QCN_SENDCNP_FLAG 1
#define NBL_DEF_QCN_SENDCNP_TIME_TH 10
#define NBL_DEF_QCN_SET_START_RATE 100
#define NBL_DEF_QCN_EXTRA_QUANTA 0
#define NBL_DEF_QCN_FAST_REDUCE_MODE 1
#define NBL_DEF_QCN_REDUCE_COE 1

#define NBL_QOS_DEFAULT_SQ_WGT 1
#define NBL_QOS_DEFAULT_RAQ_WGT 0
#define NBL_POLL_WGT_NUM 4
#define NBL_PRI_NUM 8
#define NBL_PRI_MAX_VAL 7
#define NBL_SPWRR_CFG_MAX 0xff
#define NBL_WGT_PFC_IMAP_MAX_VAL 255
#define NBL_DB_TO_CSCH_EN_MASK 0x1f
#define NBL_SW_DB_CSCH_TH_MAX 4096
#define NBL_ENABLE_MASK 1


#define NBL_DSCP_NUM 64
#define NBL_PKT2PRI_CFG_NUM 2
#define NBL_PKT2PRI_CFG_PKT_OFFSET 0
#define NBL_PKT2PRI_CFG_PRI_OFFSET 1

#define NBL_PFC_CFG_NUM 3
#define NBL_PFC_CFG_PRI_OFFSET 0
#define NBL_PFC_CFG_XOFF_OFFSET 1
#define NBL_PFC_CFG_XON_OFFSET 2
#define NBL_PFC_BUF_MAX_VAL 0x654

#define SNIC_RDMA_PF_START_DEVICE_ID	0x3403
#define SNIC_RDMA_PF_END_DEVICE_ID		0x3412
#define SNIC_RDMA_VF_DEVICE_ID		0x3413
#define DPU_ECPU_PF2_DEVICE_ID		0x3002
#define DPU_ECPU_PF3_DEVICE_ID		0x3003
#define DPU_ECPU_PF4_DEVICE_ID		0x3004
#define DPU_ECPU_PF5_DEVICE_ID		0x3005
#define DPU_HOST_RDMA_DEVICE_ID		0x1043

enum host_id_type {
	HOST_ID_TYPE_HOST = 1,
	HOST_ID_TYPE_ECPU = 2,
	HOST_ID_TYPE_MAX,
};

enum nbl_product_type {
	PRODUCT_TYPE_SNIC = 0,
	PRODUCT_TYPE_DPU = 1,
	PRODUCT_TYPE_MAX,
};

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

enum nbl_ib_dbg_fun_param_types {
	NBL_FUN_DBG_QUERY_VOA,
	NBL_FUN_DBG_CACHE_QPC,
	NBL_FUN_DBG_CACHE_CQC,
	NBL_FUN_DBG_CACHE_MRTE,
	NBL_FUN_DBG_CACHE_PBLE,
	NBL_FUN_DBG_CACHE_SQRQE,
	NBL_FUN_DBG_CACHE_IRQE,
	NBL_FUN_DBG_CACHE_RAQE,
	NBL_FUN_DBG_HMC_QPC,
	NBL_FUN_DBG_HMC_CQC,
	NBL_FUN_DBG_HMC_SD,
	NBL_FUN_DBG_HMC_PBLE,
	NBL_FUN_DBG_HMC_MRT,
	NBL_FUN_DBG_QUERY_AEQ,
	NBL_FUN_DBG_QUERY_CEQ,
	NBL_FUN_DBG_CREATE_QP,
	NBL_FUN_DBG_DESTROY_QP,
	NBL_FUN_DBG_CREATE_CQ,
	NBL_FUN_DBG_DESTROY_CQ,
	NBL_FUN_DBG_QUERY_AEQE,
	NBL_FUN_DBG_QUERY_CEQE0,
	NBL_FUN_DBG_QUERY_CEQE1,
	NBL_FUN_DBG_QUERY_VSI,
	NBL_FUN_DBG_SET_FWD,
	NBL_FUN_DBG_SET_DPORT,
	NBL_FUN_DBG_SET_DPORT_ID,
	NBL_FUN_DBG_SET_STAT_ID,
	NBL_FUN_DBG_LAG_EN,
	NBL_FUN_DBG_TUNNEL_EN,
	NBL_FUN_DBG_ACKREQ_TH,
	NBL_FUN_DBG_QUERY_PBLE_CNT,
	NBL_FUN_DBG_GET_ARM_QUTR,
	NBL_FUN_DBG_GET_ARM_LIMT,
	NBL_FUN_DBG_GET_ARM_FIFONZ,
	NBL_FUN_DBG_GET_ARM_FIFORD,
	NBL_FUN_DBG_QUERY_FMR_NOFENCE,
	NBL_FUN_DBG_SET_DWQE_EN,
	NBL_FUN_DBG_SET_DEBUG_ERRCODE,
	NBL_FUN_DBG_BATCH_WQE_TH,
	NBL_FUN_SET_DIF_VF_EN,
	NBL_UMR_REVOKE,
	NBL_FUN_DBG_QPN_ALLOC_INTERVAL,
	NBL_FUN_DBG_CLEAR_CACHE_QPC,
	NBL_FUN_DBG_CLEAR_CACHE_CQC,
	NBL_FUN_DBG_CLEAR_CACHE_MRTE,
	NBL_FUN_DBG_CLEAR_CACHE_SQRQE,
	NBL_FUN_DBG_TYPE_MAX,
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

struct nbl_pci_f {
	u8 reset : 1;
	u8 addr_mode;
	u8 *mem_rsrc;
	u8 *hmc_info_mem;
	u32 max_mr;
	u32 max_qp;
	u32 max_cq;
	u32 max_ah;
	u32 max_pd;
	u32 next_pd;
	u32 next_ah;
	u32 ceqs_count;
	u32 msix_count;
	u32 max_cqe;
	u32 next_cq;
	u32 next_qp;

	u32 used_pds;
	u32 used_cqs;
	u32 used_qps;
	atomic_t used_mrs_a;

	u8 maxsge_limit;
	unsigned long *allocated_qps;
	unsigned long *allocated_mrs;
	unsigned long *allocated_pds;
	unsigned long *allocated_ahs;
	unsigned long *allocated_cqs;
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
	spinlock_t cqtable_lock; /*protect CQ table access*/
	spinlock_t mrtable_lock; /*protect MR table access*/
	spinlock_t cq_arm_lock; /* cq arm lock */
	struct nbl_qp **qp_table;
	struct nbl_cq **cq_table;
	struct nbl_mr **mr_table;
	struct nbl_hmc_pble_rsrc *pble_rsrc;

	struct nbl_hw hw;
	struct nbl_hmc_obj_sd_info *qp_sd_info;
	struct nbl_hmc_obj_sd_info *cq_sd_info;
	struct nbl_hmc_obj_sd_info *pbl_sd_info;
	struct nbl_hmc_obj_sd_info *mrt_sd_info;
	int *qp_seq_table;
	u64 *qp_return_ts; /* QPN come back time, us */
	struct semaphore qp_flush_sem;
	struct workqueue_struct *flush_wq;
	struct workqueue_struct *updatestat_wq;
	struct workqueue_struct *query_qpc_wq;
	struct stat_work *swork;
	struct nbl_hmc_sd_range hmc_sd_range;
	struct nbl_init_params init_params;
	struct nbl_hmc_voa_entry voa_tbl[NBL_HMC_MAX];
	void *cdev;
	u16 vsi_id;
	u32 tlp_timeout;

	struct nbl_arm_control armc;
	u8 nbl_actual_rd_atom; /* cfg ost rd atomic */
	spinlock_t addr_tbl_lock;
	struct list_head src_addr_list;
	char qos_eth_dbgfs_params[NBL_ETH_MAX_NUM][NBL_CFG_QOS_TYPE_MAX][NBL_PARAM_LEN];

	u16 lag_bsport; /* lag use begin udp sport */
};

struct nbl_irq_ops {
	void (*nbl_dis_irq)(struct nbl_pci_f *rf, u32 idx);
	void (*nbl_en_irq)(struct nbl_pci_f *rf, u32 idx);
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

struct umr_common {
	unsigned int state;
	struct ib_cq *cq;
};

struct nbl_device {
	struct ib_device ibdev;
	struct nbl_pci_f *rf;
	struct net_device *netdev;
	struct nbl_sc_pd sc_pd;
	u32 device_cap_flags;
	enum ib_atomic_cap atomic_cap;
	enum init_completion_state init_state;
	u8 status;
	/* debugfs */
	struct dentry *func_dbg_dir;
	struct nbl_rdma_stat *func_stat;
	struct nbl_dump_info *func_dump_info;
	struct nbl_ib_dbg_cc_params *dbg_cc_params;
	struct nbl_ib_dbg_fun_params *dbg_fun_params;
	struct nbl_ib_dbg_qos_params *qos_params;
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

	struct umr_common umrc;
	struct notifier_block nb;
	struct netdev_net_notifier netdevice_nn;
	u16 active_speed;
	u8 active_width;
};

struct nbl_user_mmap_entry {
	struct rdma_user_mmap_entry rdma_entry;
	u64 bar_offset;
	u8 mmap_flag;
};

struct grc_cache_msg_header {
	uint8_t rsv;
	uint8_t op_code;
	uint8_t payload_len;
};

extern u8 host_id;
extern u8 product_type;

static inline struct nbl_cq *to_nblcq(struct ib_cq *ibcq)
{
	return container_of(ibcq, struct nbl_cq, ibcq);
}

static inline struct nbl_device *to_nbl_dev(struct ib_device *ibdev)
{
	return container_of(ibdev, struct nbl_device, ibdev);
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
			"find qpn with time %llu us failed, max qp num:%u\n",
			rf->sc_dev.qpn_interval, rf->max_qp);
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
	return rf->addr_mode == NBL_HMC_PROFILE_LOW_SPEC_HIGH_EFFICIENCY ?
		       SZ_4K :
		       SZ_2M;
}

int nbl_get_hw_msix_id(struct nbl_pci_f *rf, u32 host_vector, u16 *hw_msix_id);
void nbl_deinit_qps(struct nbl_pci_f *rf);
enum nbl_status_code nbl_init_qps(struct nbl_pci_f *rf);
int nbl_init_hw(struct nbl_sc_dev *sc_dev);
enum nbl_status_code nbl_initialize_hw_rsrc(struct nbl_pci_f *rf);
enum nbl_status_code nbl_rt_init_hw(struct nbl_device *nbl_dev);
void nbl_rt_deinit_hw(struct nbl_device *nbl_dev);
void nbl_ctrl_deinit_hw(struct nbl_pci_f *rf);
int nbl_hmc_setup(struct nbl_pci_f *rf);
void nbl_hmc_sdres_deinit(struct nbl_pci_f *rf);
int nbl_setup_voa(struct nbl_pci_f *rf);
int nbl_destroy_voa(struct nbl_pci_f *rf);
void nbl_hmc_destroy(struct nbl_pci_f *rf);
int nbl_get_obj_sd_addr(struct nbl_pci_f *rf, enum nbl_hmc_rsrc_type obj_type,
			struct nbl_hmc_obj_sd_info *obj_sd_info);
void nbl_free_obj_sd_addr(struct nbl_hmc_obj_sd_info *obj_sd_info);
int nbl_exec_cmd(struct nbl_pci_f *rf, void *in, int in_size, void *out, int out_size);
int nbl_dump_hw_cache(struct nbl_device *nbl_dev, u32 dump_mask, enum nbl_cqp_cache_type type);
void nbl_clear_hw_cache(struct nbl_pci_f *rf, enum nbl_cqp_cache_type cache_type);
void nbl_set_fmr_nofence(struct nbl_pci_f *rf, __u32 var);
int nbl_dump_hmc_qpc(struct nbl_device *nbl_dev, u32 dump_mask);
int nbl_dump_hmc_cqc(struct nbl_pci_f *rf, u32 dump_mask);
int nbl_dump_hmc_pble(struct nbl_pci_f *rf, u32 dump_mask);
int nbl_dump_hmc_mrt(struct nbl_device *nbl_dev, u32 dump_mask);
int nbl_query_voa(char __user *buf, size_t count, loff_t *pos, struct nbl_pci_f *rf);
void nbl_dump_hex(struct nbl_pci_f *rf, u8 *buf, int len);
void nbl_hmc_query_sd(struct nbl_pci_f *rf, u32 dump_mask);
int nbl_dbg_create_qp(struct nbl_pci_f *rf, u32 qpn_input);
int nbl_dbg_destroy_qp(struct nbl_pci_f *rf, u32 qpn_input);
int nbl_dbg_create_cq(struct nbl_pci_f *rf, u32 cqn_input);
int nbl_dbg_destroy_cq(struct nbl_pci_f *rf, u32 cqn_input);
int nbl_dump_pble_cnt(struct nbl_pci_f *rf);
void nbl_destroy_pble_prm(struct nbl_hmc_pble_rsrc *pble_rsrc);
int nbl_init_pble_prm(struct nbl_hmc_obj_sd_info *pbl_sd_info,
	struct nbl_hmc_pble_rsrc *pble_rsrc);

void nbl_rdma_update_dsch_info(struct nbl_pci_f *rf);
int nbl_set_vfid_vsi_map(struct nbl_pci_f *rf, u8 is_valid);
int nbl_set_dif_vf_en(struct nbl_pci_f *rf, bool is_off);
void nbl_sched_qp_flush_work(struct nbl_qp *qp);

/* sysfs */
u32 show_cc_param(struct nbl_device *dev, int offset);
int config_cc_param(struct nbl_device *dev, int offset, u32 var);
int show_qos_param(struct nbl_device *nbldev, int offset, char *lbuf);
ssize_t config_qos_param(struct nbl_device *nbldev, int offset, char *lbuf);
ssize_t config_stats_param(struct nbl_device *nbl_dev, char *lbuf, size_t count);
void nbl_sysfs_init(struct nbl_device *nbldev);
void nbl_sysfs_exit(struct nbl_device *nbldev);
ssize_t nbl_qos_cfg_store(struct auxiliary_device *adev, int offset, const char *buf, size_t count);
ssize_t nbl_qos_cfg_show(struct auxiliary_device *adev, int offset, char *buf);

#endif /* NBL_MAIN_H */
