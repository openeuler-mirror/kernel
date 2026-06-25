/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rdma_common.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_DRV_RDMA_COMMON_H__
#define __SXE2_DRV_RDMA_COMMON_H__

#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/wait.h>
#include <linux/interrupt.h>
#include <linux/refcount.h>
#include <linux/if_ether.h>
#include <linux/err.h>
#include <linux/notifier.h>
#include <linux/pci.h>
#include <linux/in.h>
#include <linux/in6.h>

#include <rdma/ib_umem.h>
#include <rdma/ib_verbs.h>
#include <linux/kernel.h>

#include "sxe2_compat.h"
#include "sxe2_rdma_ifc.h"

#include "sxe2_drv_rdma_inject.h"

#include "sxe2_drv_aux.h"
#include "sxe2_cmd.h"

#define SXE2_MQ_WAIT_POLL_REGS 1
#define SXE2_MQ_WAIT_POLL_CQ   2
#define SXE2_MQ_WAIT_EVENT     3
#define SXE2_MQ_WAIT_CQE       4

#define SXE2_RDMA_MIN_RNR_NAK_DEFAULT 2

#define SQ_CQ 1
#define RQ_CQ 2

#define SXE2_PRINT_HEX_BYTE_PER_ROW 16
#define SXE2_PRINT_HEX_BREAK_PER_BYTE                                          \
	8
#define SXE2_PRINT_HEX_MUL_BYTE_8 8

#define SXE2_CQ_DBNOTE_ARMCI GENMASK_ULL(23, 0)
#define SXE2_CQ_DBNOTE_CMD   BIT_ULL(31)
#define SXE2_CQ_DBNOTE_CMDSN GENMASK_ULL(30, 29)

#define SXE2_RDMA_IRQ_NAME_STR_LEN	  64
#define SXE2_RDMA_VCHNL_MAX_MSG_SIZE	  512
#define IB_DEVICE_NAME_MAX		  64
#define SXE2_RCMS_MAX_UPDATE_FPTE_ENTRIES 35
#define SXE2_RCMS_VF_MAX_UPDATE_FPTE_ENTRIES 35

#define SXE2_RDMA_DB_PAGE_SHIFT (12)
#define SXE2_RDMA_DB_PAGE_SIZE	(4096)

#define MQ_CRIERR_MAJ_ERRCODE (0xFFFF)

#define MQ_CRIERR_MQC_NOT_CREATED  (0x8030)
#define MQ_CRIERR_MQ_BASE_ERR	   (0x8031)
#define MQ_CRIERR_MQC_ECC_ERR	   (0x8032)
#define MQ_CRIERR_QP_DESTROY_ABORT (0x8034)

#define SXE2_LAG_PRIMARY_IDX   (0)
#define SXE2_LAG_SECONDARY_IDX (1)

#define OFFSET_TPH_CONTROL    (8)
#define OFFSET_TPH_CAPABILITY (4)

#define OFFSET_TPHENABLE_IN_TPH_CONTROL                                        \
	(8)
#define TPH_GET_CPU() raw_smp_processor_id()

#define SXE2_KERNEL_TPH_EN_DEFAULT (1)

#define TPH_CPUID_MASK 0xFF

#define SXE2_PCI_EXP_DEVCAP2_TPH_COMP_MASK (0x1000)
#define SXE2_PCI_EXP_DEVCAP2_TPH_COMP_SHIFT (12)

#define SXE2_PCI_EXP_EXT_TPH_REQ_ST_DEVICE_MODE_MASK (0x2)

#define SXE2_PCI_EXP_EXT_TPH_REQ_ENABLE_MASK (0x100)

#define SXE2_MAX_ACK_TIMEOUT_VAL 28

enum { PH_BI_DIRECTIONAL = 0x0,
		PH_DXDX		 = 0x1,
		PH_DWHR = 0x2,
		PH_HWDR = 0x2,
};

enum { MODE_NO_ST	     = 0x0,
		MODE_INTERRUPT_VECTOR = 0x1,
		MODE_DEVICE_SPECIFIC  = 0x2,
};

enum sxe2_rdma_vers {
	SXE2_RDMA_GEN_RSVD = 0,
	SXE2_RDMA_GEN_1	   = 1,
	SXE2_RDMA_GEN_MAX  = SXE2_RDMA_GEN_1,
};

enum sxe2_cmpl_status {
	SXE2_COMPL_STATUS_SUCCESS = 0,
	SXE2_COMPL_STATUS_FLUSHED,
	SXE2_COMPL_STATUS_INVALID_WQE,
	SXE2_COMPL_STATUS_QP_CATASTROPHIC,
	SXE2_COMPL_STATUS_REMOTE_TERMINATION,
	SXE2_COMPL_STATUS_INVALID_STAG,
	SXE2_COMPL_STATUS_BASE_BOUND_VIOLATION,
	SXE2_COMPL_STATUS_ACCESS_VIOLATION,
	SXE2_COMPL_STATUS_INVALID_PD_ID,
	SXE2_COMPL_STATUS_WRAP_ERROR,
	SXE2_COMPL_STATUS_STAG_INVALID_PDID,
	SXE2_COMPL_STATUS_RDMA_READ_ZERO_ORD,
	SXE2_COMPL_STATUS_QP_NOT_PRIVLEDGED,
	SXE2_COMPL_STATUS_STAG_NOT_INVALID,
	SXE2_COMPL_STATUS_INVALID_PHYS_BUF_SIZE,
	SXE2_COMPL_STATUS_INVALID_PHYS_BUF_ENTRY,
	SXE2_COMPL_STATUS_INVALID_FBO,
	SXE2_COMPL_STATUS_INVALID_LEN,
	SXE2_COMPL_STATUS_INVALID_ACCESS,
	SXE2_COMPL_STATUS_PHYS_BUF_LIST_TOO_LONG,
	SXE2_COMPL_STATUS_INVALID_VIRT_ADDRESS,
	SXE2_COMPL_STATUS_INVALID_REGION,
	SXE2_COMPL_STATUS_INVALID_WINDOW,
	SXE2_COMPL_STATUS_INVALID_TOTAL_LEN,
	SXE2_COMPL_STATUS_UNKNOWN,
};

enum sxe2_arm_type {
	SXE2_CQ_ARM_NEXT      = 0,
	SXE2_CQ_ARM_SOLICITED = 1,
};

enum sxe2_qp_caps {
	SXE2_WRITE_WITH_IMM = 1,
	SXE2_SEND_WITH_IMM  = 2,
	SXE2_ROCE	    = 4,
	SXE2_PUSH_MODE	    = 8,
};

struct sxe2_rcms_update_fpt_entry {
	u64 cmd;
	u64 data;
};
struct sxe2_rcms_update_fptes_info {
	u32 cnt;
	u16 rcms_fn_id;
	struct sxe2_rcms_update_fpt_entry
		entry[SXE2_RCMS_MAX_UPDATE_FPTE_ENTRIES];
};

struct sxe2_rcms_vf_update_fptes_info {
	u32 cnt;
	bool set;
	struct sxe2_rcms_update_fpt_entry
		entry[SXE2_RCMS_VF_MAX_UPDATE_FPTE_ENTRIES];
};

enum sxe2_rcms_init_mode {
	SXE2_RCMS_FIRST_INIT_MODE =
		1,
	SXE2_RCMS_SECOND_INIT_MODE =
		2,
	SXE2_RCMS_INIT_MODE_MAX,
};

enum sxe2_rdma_feature_type {
	SXE2_RDMA_HW_MQ_MAJOR_VERSION =
		0,
	SXE2_RDMA_HW_MQ_MINOR_VERSION =
		1,
	SXE2_RDMA_HW_MODEL_VERSION_USED =
		2,
	SXE2_RDMA_ENDPT_TRK_EN = 3,
	SXE2_RDMA_QSETS_MAX_NUMBER = 4,
	SXE2_RDMA_FW_MAIN_VERSION  = 5,
	SXE2_RDMA_FW_SUB_VERSION   = 6,
	SXE2_RDMA_FW_FIX_VERSION   = 7,
	SXE2_RDMA_FW_BUILD_NUMBER  = 8,
	SXE2_RDMA_MAX_FEATURES	   = 9,
};

enum sxe2_rdma_hygon_en_type {
	SXE2_RDMA_HYGON_DEFAULT = 0,
	SXE2_RDMA_HYGON_FORCE_ENABLE = 1,
	SXE2_RDMA_HYGON_FORCE_DISABLE = 2,
};

union sxe2_sockaddr {
	struct sockaddr_in saddr_in;
	struct sockaddr_in6 saddr_in6;
};

struct sxe2_av {
	struct rdma_ah_attr attrs;
	union sxe2_sockaddr sgid_addr;
	union sxe2_sockaddr dgid_addr;
	u8 net_type;
};

#define SXE2_HW_MAJVER_GEN_1 0

#define SXE2_GET_CURRENT_CQ_ELEM(_cq)                                          \
	(((struct sxe2_cqe                                                     \
		   *)((_cq)->cq_base))[SXE2_RING_CURRENT_HEAD((_cq)->cq_ring)] \
		 .buf)

#define SXE2_RING_INIT(_ring, _size)                                           \
	{                                                                      \
		(_ring).head = 0;                                              \
		(_ring).tail = 0;                                              \
		(_ring).size = (_size);                                        \
	}
#define SXE2_RING_SIZE(_ring)	      ((_ring).size)
#define SXE2_RING_CURRENT_HEAD(_ring) ((_ring).head)
#define SXE2_RING_CURRENT_TAIL(_ring) ((_ring).tail)

#define SXE2_RING_MOVE_HEAD(_ring, _retcode)                                   \
	{                                                                      \
		u32 size;                                                      \
		size = (_ring).size;                                           \
		if (!SXE2_RING_FULL_ERR(_ring)) {                              \
			(_ring).head = ((_ring).head + 1) % size;              \
			(_retcode)   = 0;                                      \
		} else {                                                       \
			(_retcode) = -ENOMEM;                                  \
		}                                                              \
	}
#define SXE2_RING_MOVE_HEAD_BY_COUNT(_ring, _count, _retcode)                  \
	{                                                                      \
		u32 size;                                                      \
		size = (_ring).size;                                           \
		if ((SXE2_RING_USED_QUANTA(_ring) + (_count)) < size) {        \
			(_ring).head = ((_ring).head + (_count)) % size;       \
			(_retcode)   = 0;                                      \
		} else {                                                       \
			(_retcode) = -ENOMEM;                                  \
		}                                                              \
	}
#define SXE2_SQ_RING_MOVE_HEAD(_ring, _retcode)                                \
	{                                                                      \
		u32 size;                                                      \
		size = (_ring).size;                                           \
		if (!SXE2_SQ_RING_FULL_ERR(_ring)) {                           \
			(_ring).head = ((_ring).head + 1) % size;              \
			(_retcode)   = 0;                                      \
		} else {                                                       \
			(_retcode) = -ENOMEM;                                  \
		}                                                              \
	}
#define SXE2_SQ_RING_MOVE_HEAD_BY_COUNT(_ring, _count, _retcode)               \
	{                                                                      \
		u32 size;                                                      \
		size = (_ring).size;                                           \
		if ((SXE2_RING_USED_QUANTA(_ring) + (_count)) < (size - 1)) {  \
			(_ring).head = ((_ring).head + (_count)) % size;       \
			(_retcode)   = 0;                                      \
		} else {                                                       \
			(_retcode) = -ENOMEM;                                  \
		}                                                              \
	}
#define SXE2_RING_MOVE_HEAD_BY_COUNT_NOCHECK(_ring, _count)                    \
	(_ring).head = ((_ring).head + (_count)) % (_ring).size

#define SXE2_RING_MOVE_TAIL(_ring)                                             \
	(_ring).tail = ((_ring).tail + 1) % (_ring).size

#define SXE2_RING_MOVE_HEAD_NOCHECK(_ring)                                     \
	(_ring).head = ((_ring).head + 1) % (_ring).size

#define SXE2_RING_MOVE_TAIL_BY_COUNT(_ring, _count)                            \
	(_ring).tail = ((_ring).tail + (_count)) % (_ring).size

#define SXE2_RING_SET_TAIL(_ring, _pos) (_ring).tail = (_pos) % (_ring).size

#define SXE2_RING_FULL_ERR(_ring)                                              \
	((SXE2_RING_USED_QUANTA(_ring) == ((_ring).size - 1)))

#define SXE2_SQ_RING_FULL_ERR(_ring)                                           \
	((SXE2_RING_USED_QUANTA(_ring) == ((_ring).size - 1)))

#define SXE2_RING_MORE_WORK(_ring) ((SXE2_RING_USED_QUANTA(_ring) != 0))

#define SXE2_RING_MORE_WORK_PAD(_ring) ((SXE2_RING_USED_QUANTA_PAD(_ring) != 0))

#define SXE2_RING_USED_QUANTA(_ring)                                           \
	((((_ring).head + (_ring).size - (_ring).tail) % (_ring).size))

#define SXE2_RING_USED_QUANTA_PAD(_ring)                                           \
		((((_ring).head + (_ring).size - (_ring).tail - 1) % (_ring).size))

#define SXE2_RING_FREE_QUANTA(_ring)                                           \
	(((_ring).size - SXE2_RING_USED_QUANTA(_ring) - 1))

#define SXE2_SQ_RING_FREE_QUANTA(_ring)                                        \
	(((_ring).size - SXE2_RING_USED_QUANTA(_ring) - 1))

#define SXE2_ATOMIC_RING_MOVE_HEAD(_ring, index, _retcode)                     \
	{                                                                      \
		index = SXE2_RING_CURRENT_HEAD(_ring);                         \
		SXE2_RING_MOVE_HEAD(_ring, _retcode);                          \
	}

#define LS_64_1(val, bits) ((u64)(uintptr_t)(val) << (bits))
#define RS_64_1(val, bits) ((u64)(uintptr_t)(val) >> (bits))
#define LS_32_1(val, bits) ((u32)((val) << (bits)))
#define RS_32_1(val, bits) ((u32)((val) >> (bits)))

#define SXE2_RDMA_MAX_STATS_16 0xffffULL
#define SXE2_RDMA_MAX_STATS_24 0xffffffULL
#define SXE2_RDMA_MAX_STATS_32 0xffffffffULL
#define SXE2_RDMA_MAX_STATS_48 0xffffffffffffULL
#define SXE2_RDMA_MAX_STATS_56 0xffffffffffffffULL
#define SXE2_RDMA_MAX_STATS_64 0xffffffffffffffffULL

enum sxe2_sw_mq_op {
	MQ_OP_CREATE_QP	     = 0,
	MQ_OP_MODIFY_QP	     = 1,
	MQ_OP_DESTROY_QP     = 2,
	MQ_OP_CREATE_CQ	     = 3,
	MQ_OP_MODIFY_CQ	     = 4,
	MQ_OP_DESTROY_CQ     = 5,
	MQ_OP_ALLOC_MR_KEY   = 6,
	MQ_OP_ALLOC_MW	     = 7,
	MQ_OP_REG_MR	     = 8,
	MQ_OP_QUERY_MR_KEY   = 9,
	MQ_OP_DEALLOC_MR_KEY = 10,
	MQ_OP_MANAGE_PBLE_BP = 11,
	MQ_OP_QUERY_QP	     = 12,
	MQ_OP_MANAGE_RCMS_PM_FUNC_TABLE = 13,
	MQ_OP_CREATE_CEQ		= 14,
	MQ_OP_DESTROY_CEQ		= 15,
	MQ_OP_CREATE_AEQ		= 16,
	MQ_OP_DESTROY_AEQ		= 17,
	MQ_OP_CREATE_ADDR_HANDLE	= 18,
	MQ_OP_MODIFY_ADDR_HANDLE	= 19,
	MQ_OP_DESTROY_ADDR_HANDLE	= 20,
	MQ_OP_UPDATE_FPT		= 21,
	MQ_OP_QUERY_FPM_VAL		= 22,
	MQ_OP_COMMIT_FPM_VAL		= 23,
	MQ_OP_NOP			= 24,
	MQ_OP_GATHER_STATS		= 25,
	MQ_OP_CREATE_SRQ		= 26,
	MQ_OP_MODIFY_SRQ		= 27,
	MQ_OP_DESTROY_SRQ		= 28,
	MQ_OP_DEREGISTER_MR		= 29,
	MQ_OP_MODIFY_CEQ		= 30,
	MQ_OP_QUERY_CEQ			= 31,
	MQ_OP_MODIFY_AEQ		= 32,
	MQ_OP_QUERY_AEQ			= 33,
	MQ_OP_QUERY_CQ			= 34,
	MQ_OP_QUERY_SRQ			= 35,
	MQ_OP_QUERY_MR			= 36,
	MQ_MAX_OPS,
};

enum sxe2_alignment {
	SXE2_MQ_ALIGNMENT	   = 0x200,
	SXE2_AEQ_ALIGNMENT	   = 0x100,
	SXE2_CEQ_ALIGNMENT	   = 0x100,
	SXE2_MCQ_ALIGNMENT	   = 0x100,
	SXE2_FPT_BUF_ALIGNMENT	   = 0x200,
	SXE2_FEATURE_BUF_ALIGNMENT = 0x10,
};

enum sxe2_queue_type {
	SXE2_QUEUE_TYPE_SQ_RQ = 0,
	SXE2_QUEUE_TYPE_MQ,
	SXE2_QUEUE_TYPE_SRQ,
};

struct sxe2_ring {
	__u32 head;
	__u32 tail;
	__u32 size;
};

enum sxe2_pbl_obj_type {
	PBL_OBJ_QP  = 0,
	PBL_OBJ_SRQ = 1,
	PBL_OBJ_CQ  = 2,
	PBL_OBJ_EQ  = 3,
	PBL_OBJ_MR  = 4,
};

enum sxe2_addressing_type {
	SXE2_ADDR_TYPE_ZERO_BASED = 0,
	SXE2_ADDR_TYPE_VA_BASED	  = 1,
};

enum sxe2_qp_event_type {
	SXE2_QP_EVENT_CATASTROPHIC,
	SXE2_QP_EVENT_ACCESS_ERR,
	SXE2_QP_EVENT_REQ_ERR,
	SXE2_QP_EVENT_COMM_EST,
	SXE2_QP_EVENT_QP_LASTWQE_REACHED,
};

enum sxe2_pbl_init_mode {
	SXE2_PBL_SECOND_INIT_MODE = 1,
	SXE2_PBL_THIRD_INIT_MODE  = 2,
	SXE2_PBL_INIT_MODE_MAX,
};

struct sxe2_common_attrs {
	u64 feature_flags;
	u32 max_hw_wq_frags;
	u32 max_hw_read_sges;
	u32 max_hw_inline;
	u32 max_hw_rq_quanta;
	u32 max_hw_wq_quanta;
	u32 min_hw_cq_size;
	u32 max_hw_cq_size;
	u16 max_hw_push_len;
	u16 max_hw_sq_chunk;
	u16 min_hw_wq_size;
	u8 hw_rev;
	u8 rsv;
	u32 max_hw_srq_quanta;
	u32 max_hw_srq_wr;
};

enum drv_rdma_dbg_rsc_type {
	SXE2_DBG_RSC_QP,
	SXE2_DBG_RSC_AEQ,
	SXE2_DBG_RSC_CEQ,
	SXE2_DBG_RSC_MCQ,
	SXE2_DBG_RSC_CQ,
	SXE2_DBG_RSC_MR,
	SXE2_DBG_RSC_SRQ,
	SXE2_DBG_RSC_MQ,
	SXE2_DBG_RSC_RCMS,
	SXE2_DBG_RSC_AH,
	SXE2_DBG_RSC_MAX,
};

struct sxe2_rdma_device;

typedef u64 (*sxe2_drv_rdma_debugfs_read)(struct sxe2_rdma_device *dev,
					  void *data,
					  enum drv_rdma_dbg_rsc_type type,
					  char *buf);
typedef int (*sxe2_drv_rdma_debugfs_write)(struct sxe2_rdma_device *dev,
					   void *data,
					   enum drv_rdma_dbg_rsc_type type,
					   char *buf);

struct sxe2_rdma_debugfs_handle {
	sxe2_drv_rdma_debugfs_read read_func;
	sxe2_drv_rdma_debugfs_write write_func;
};

struct sxe2_rdma_rsc_debug {
	struct sxe2_rdma_device *dev;
	void *object;
	enum drv_rdma_dbg_rsc_type type;
	struct dentry *root;
	struct sxe2_rdma_debugfs_handle func_tab;
};

struct sxe2_rdma_dma_mem {
	void *va;
	dma_addr_t pa;
	u32 size;
} __packed;

struct sxe2_rdma_virt_mem {
	void *va;
	u32 size;
} __packed;

struct sxe2_rcms_cp {
	enum sxe2_rcms_fpt_entry_type entry_type;
	struct sxe2_rdma_dma_mem page_addr;
	u32 fpt_spt_index;
	u32 use_cnt;
};

struct sxe2_rcms_spt_entry {
	struct sxe2_rcms_cp cp;
	u32 fpt_index;
	bool valid;
};

struct sxe2_rcms_spt {
	struct sxe2_rdma_dma_mem spt_page_addr;
	struct sxe2_rcms_spt_entry *spte;
	struct sxe2_rdma_virt_mem spte_virt_mem;
	u32 use_cnt;
	u32 fpt_index;
};

struct sxe2_rcms_fpt_entry {
	enum sxe2_rcms_fpt_entry_type entry_type;
	bool valid;
	union {
		struct sxe2_rcms_spt spt;
		struct sxe2_rcms_cp cp;
	} u;
};

struct sxe2_rcms_fpt {
	struct sxe2_rdma_virt_mem addr;
	u32 fpte_cnt;
	u32 use_cnt;
	struct sxe2_rcms_fpt_entry *fpte;
};

enum sxe2_rcms_creat_table_mode {
	FIRST_PAGE_TABLE  = 1,
	SECOND_PAGE_TABLE = 2,
};

struct sxe2_rcms_read_fpte_debugfs_input {
	u32 fpte_idx;
	u32 fpte_cnt;
	u32 spte_idx;
	u64 liner_base;
};

struct sxe2_rcms_read_spte_debugfs_input {
	u32 fpte_idx;
	u32 spte_idx;
	u32 spte_cnt;
};

struct sxe2_rcms_read_liner_addr_input {
	u64 liner_addr;
	u32 size;
};

struct sxe2_rcms_read_obj_ctx_input {
	u32 obj_type;
	u32 obj_num;
};

struct sxe2_rcms_num_to_liner_addr_input {
	u32 obj_type;
	u32 obj_num;
};

struct sxe2_rcms_info {
	u16 rcms_fn_id;
	u32 first_fpte_index;
	u32 max_fpte_index;
	u32 max_fpte_cnt;
	u32 max_cc_qp_cnt;
	u32 fpte_needed;
	u32 first_page_fpte;
	u8 irrl_ost_num;
	u8 ssnt_ost_num;
	u8 resp_ost_num;
	u32 max_ceqs;
	u32 max_db_page_num;
	u32 db_bar_addr;
	enum sxe2_rcms_creat_table_mode create_mode;
	struct sxe2_rcms_obj_info *rcms_obj;
	struct sxe2_rcms_fpt fpt;
	u16 fpte_indexes[SXE2_RCMS_MAX_FPT_COUNT];
	u16 pmf_index;
	u32 pf_max_ceqs;
#ifdef SXE2_CFG_DEBUG
	struct sxe2_rcms_read_fpte_debugfs_input
		read_fpte_input;
	struct sxe2_rcms_read_spte_debugfs_input
		read_spte_input;
	struct sxe2_rcms_read_liner_addr_input
		read_liner_addr_input;
	struct sxe2_rcms_read_obj_ctx_input
		read_obj_ctx_input;
	struct sxe2_rcms_num_to_liner_addr_input
		num_to_la_input;
#endif
};

struct sxe2_rdma_hw {
	u8 __iomem *hw_addr;
	u8 __iomem *priv_hw_addr;
	struct device *device;
	struct sxe2_rcms_info rcms;
};

#define SXE2_ROCE_CWND_DEFAULT	       0x400
#define SXE2_ROCE_ACKCREDS_DEFAULT     0x1E
#define SXE2_CM_DEFAULT_RCV_WND_SCALED 0x3FFFC
#define SXE2_CM_DEFAULT_RCV_WND_SCALE  2
#define SXE2_DEFAULT_UP_UP_MAP	       0x0706050403020100l
#define SXE2_Q_INVALID_IDX	       0xffff
#ifndef SXE2_MAX_USER_PRIORITY
#define SXE2_MAX_USER_PRIORITY	       8
#else
#undef SXE2_MAX_USER_PRIORITY
#define SXE2_MAX_USER_PRIORITY	       8
#endif
#define SXE2_DSCP_NUM_VAL	       64
#define SXE2_AUX_DSCP_PFC_MODE	       0x1
#define IEEE_8021QAZ_MAX_TCS	       8
#define SXE2_QSET_PER_USER_PRI	       1
#define SXE2_QSET_PER_USER_PRI_BOND    2

enum sxe2_rdma_obj_mem_alignment {
	SXE2_AEQ_ALIGNMENT_M		= (256 - 1),
	SXE2_CEQ_ALIGNMENT_M		= (256 - 1),
	SXE2_CQ0_ALIGNMENT_M		= (256 - 1),
	SXE2_HOST_CTX_ALIGNMENT_M	= (4 - 1),
	SXE2_SHADOW_AREA_M		= (128 - 1),
	SXE2_FPM_QUERY_BUF_ALIGNMENT_M	= (4 - 1),
	SXE2_FPM_COMMIT_BUF_ALIGNMENT_M = (4 - 1),
};

enum sxe2_dyn_idx_t {
	SXE2_IDX_ITR0  = 0,
	SXE2_IDX_ITR1  = 1,
	SXE2_IDX_ITR2  = 2,
	SXE2_IDX_NOITR = 3,
};

enum sxe2_protocol_used {
	SXE2_ROCE_PROTOCOL_ONLY = 2,
};

enum sxe2_mq_rcms_profile {
	SXE2_RCMS_PROFILE_DEFAULT  = 1,
	SXE2_RCMS_PROFILE_FAVOR_VF = 2,
	SXE2_RCMS_PROFILE_EQUAL	   = 3,
};

struct sxe2_rdma_qos_tc_info {
	u64 tc_ctx;
	u8 rel_bw;
	u8 prio_type;
	u8 egress_virt_up;
	u8 ingress_virt_up;
};

struct sxe2_rdma_l2params {
	struct sxe2_rdma_qos_tc_info tc_info[SXE2_MAX_USER_PRIORITY];
	u32 num_apps;
	u16 qs_handle_list[SXE2_MAX_USER_PRIORITY];
	u16 mtu;
	u8 up2tc[SXE2_MAX_USER_PRIORITY];
	u8 dscp_map[SXE2_DSCP_NUM_VAL];
	u8 num_tc;
	u8 vsi_rel_bw;
	u8 vsi_prio_type;
	bool mtu_changed : 1;
	bool tc_changed : 1;
	bool dscp_mode : 1;
};

#define SXE2_MCQ_SIZE		  (4096)
#define SXE2_DB_NOTE_M		  (128 - 1)
#define INVALID_U32		  0xFFFFFFFF
#define SXE2_IRQ_NAME_STR_LEN	  (64)
#define SXE2_MAX_UESER_PRIORITY	  8
#define SXE2_LE_32_TO_HOST(value) ((u32) le32_to_cpu(value))
#define SXE2_HOST_32_TO_LE(value) ((u32) cpu_to_le32(value))

#define SXE2_BAR_READ_32(addr)	     SXE2_LE_32_TO_HOST(readl(addr))
#define SXE2_BAR_WRITE_32(val, addr) writel(SXE2_HOST_32_TO_LE(val), addr)

struct sxe2_rdma_hw_attrs {
	struct sxe2_common_attrs uk_attrs;
	u64 max_hw_outbound_msg_size;
	u64 max_hw_inbound_msg_size;
	u64 max_mr_size;
	u64 page_size_cap;
	u32 min_hw_qp_id;
	u32 min_hw_aeq_size;
	u32 max_hw_aeq_size;
	u32 min_hw_ceq_size;
	u32 max_hw_ceq_size;
	u32 max_hw_device_pages;
	u32 max_hw_vf_fpm_id;
	u32 first_hw_vf_fpm_id;
	u32 max_rra;
	int max_sra;
	u32 max_hw_wqes;
	u32 max_hw_pds;
	u32 max_hw_ena_vf_count;
	u32 max_qp_wr;
	u32 max_pe_ready_count;
	u32 max_done_count;
	u32 max_sleep_count;
	u32 max_mq_compl_wait_time_ms;
	u32 min_hw_srq_id;
	u16 max_stat_inst;
	u16 max_stat_idx;
};

enum init_completion_state {
	INVALID_STATE = 0,
	INITIAL_STATE,
	MQ_CREATED,
	HMC_OBJS_CREATED,
	HW_RSRC_INITIALIZED,
	CCQ_CREATED,
	CEQ0_CREATED,
	ILQ_CREATED,
	IEQ_CREATED,
	REM_ENDPOINT_TRK_CREATED,
	CEQS_CREATED,
	PBLE_CHUNK_MEM,
	AEQ_CREATED,
	IP_ADDR_REGISTERED,
};

struct sxe2_rdma_vchnl_rdma_caps {
	u8 hw_rev;
	u16 cqp_timeout_s;
	u16 cqp_def_timeout_s;
	u16 max_hw_push_len;
};

enum sxe2_rdma_vm_vf_type {
	SXE2_VF_TYPE = 0,
	SXE2_VM_TYPE,
	SXE2_PF_TYPE,
};

struct sxe2_rdma_config_check {
	bool config_ok : 1;
	bool lfc_set : 1;
	bool pfc_set : 1;
	u8 traffic_class;
	u16 qs_handle;
};

struct sxe2_rdma_qset {
	u32 qset_num;
	u16 qset_id;
	u16 teid;
	u32 qset_qp_cnt;
	u16 vsi_index;
	u8 traffic_class;
	u8 user_pri;
	struct list_head qp_list;
	u8 pf_id;
	u8 active_port;
	bool register_flag : 1;
};

struct sxe2_rdma_qos {
	struct mutex qos_mutex;
	struct sxe2_rdma_qset qset[SXE2_QSET_PER_USER_PRI_BOND];
	u32 teid[SXE2_QSET_PER_USER_PRI_BOND];
	u8 rel_bw[SXE2_QSET_PER_USER_PRI_BOND];
	u8 prio_type[SXE2_QSET_PER_USER_PRI_BOND];
	u32 qp_cnt;
	bool valid : 1;
};

struct sxe2_rdma_hw_stat_map {
	u16 byteoff;
	u8 bitoff;
	u64 bitmask;
};

struct sxe2_rdma_dev_hw_stats {
	u64 stats_val[SXE2_GATHER_STATS_BUF_SIZE / sizeof(u64)];
};

struct sxe2_rdma_stats_gather_info {
	bool use_rdma_fcn_index : 1;
	bool use_stats_inst : 1;
	u16 rcms_fcn_index;
	u16 stats_inst_index;
	struct sxe2_rdma_dma_mem stats_buff_mem;
	void *gather_stats_va;
};

struct sxe2_rdma_vsi_pestat {
	struct sxe2_rdma_hw *hw;
	struct sxe2_rdma_dev_hw_stats hw_stats;
	struct sxe2_rdma_stats_gather_info
		gather_info;
	struct timer_list stats_timer;
	u32 timer_delay;
	struct sxe2_rdma_ctx_vsi *vsi;
	struct work_struct work;
	struct workqueue_struct *stats_wq;
	struct mutex stats_lock;
};

struct sxe2_rdma_ctx_vsi {
	u16 vsi_idx;
	struct sxe2_rdma_ctx_dev *dev;
	struct sxe2_rdma_vchnl_dev *vc_dev;
	void *back_vsi;
	u32 exception_lan_q;
	u16 mtu;
	u16 vf_id;
	enum sxe2_rdma_vm_vf_type vm_vf_type;
	bool tc_change_pending : 1;
	bool mtu_change_pending : 1;
	bool failover_pending : 1;
	struct sxe2_rdma_vsi_pestat *pestat;
	atomic_t qp_suspend_reqs;
	int (*register_qsets)(struct sxe2_rdma_ctx_vsi *vsi,
			      struct sxe2_rdma_qset *qset1,
			      struct sxe2_rdma_qset *qset2);
	void (*unregister_qsets)(struct sxe2_rdma_ctx_vsi *vsi,
				 struct sxe2_rdma_qset *qset1,
				 struct sxe2_rdma_qset *qset2);
	struct sxe2_rdma_config_check cfg_check[1];
	bool tc_print_warning[SXE2_MAX_USER_PRIORITY];
	u8 qos_rel_bw[SXE2_QSET_PER_USER_PRI_BOND];
	u8 qos_prio_type[SXE2_QSET_PER_USER_PRI_BOND];
	u16 stats_idx;
	u8 dscp_map[SXE2_QSET_PER_USER_PRI_BOND][SXE2_DSCP_NUM_VAL];
	struct sxe2_rdma_qos qos[SXE2_MAX_USER_PRIORITY];
	bool dscp_mode[SXE2_QSET_PER_USER_PRI_BOND];
	bool lag_aa : 1;
	bool lag_backup : 1;
	u8 lag_ports[2];
	u8 lag_port_bitmap;

	u32 primary_port_node_ids
		[SXE2_MAX_USER_PRIORITY];
	u32 secondary_port_node_ids
		[SXE2_MAX_USER_PRIORITY];
	atomic_t port1_qp_cnt;
	atomic_t port2_qp_cnt;
	bool primary_port_migrated;
	bool secondary_port_migrated;
};

struct sxe2_rdma_ctx_dev {
	struct list_head mq_cmd_head;
	spinlock_t  mq_lock;
	struct sxe2_rdma_dma_mem vf_fpm_query_buf[SXE2_MAX_PE_ENA_VF_COUNT];
	u64 fpm_query_buf_pa;
	u64 fpm_commit_buf_pa;
	__le32 *fpm_query_buf;
	__le32 *fpm_commit_buf;
	struct sxe2_rdma_hw *hw;
	u32 __iomem *wqe_alloc_db;
	u32 __iomem *hw_regs[SXE2_MAX_BAR_REGS];
	u32 ceq_itr;
	const struct sxe2_rdma_hw_stat_map *hw_stats_map;
	u64 hw_masks[10];
	u8 hw_shifts[10];
	u32 feature_info[SXE2_RDMA_MAX_FEATURES];
	u32 fw_ver;
	u64 mq_post_stats[SXE2_MQ_OP_MAX];
	u64 mq_cmd_stats[SXE2_MQ_OP_MAX];
	struct sxe2_rdma_hw_attrs hw_attrs;
	struct sxe2_rcms_info *rcms_info;
	struct sxe2_rdma_vchnl_if *vchnl_if;
	struct sxe2_rdma_vchnl_rdma_caps vc_caps;
	u8 vc_recv_buf[SXE2_VCHNL_MAX_MSG_SIZE];
	u16 vc_recv_len;
	struct sxe2_rdma_vchnl_dev *vc_dev[SXE2_MAX_PE_ENA_VF_COUNT];
	spinlock_t vc_dev_lock;
	struct workqueue_struct *vchnl_wq;
	struct sxe2_mq_ctx *mq;
	struct sxe2_rdma_ctx_aeq *aeq;
	struct sxe2_rdma_ctx_ceq *ceq[SXE2_RDMA_CEQ_MAX_COUNT];
	struct sxe2_rdma_ctx_cq *mcq;
	const struct sxe2_rdma_irq_ops *irq_ops;
	struct aux_ver_info fw_version;
	u16 num_vfs;
	u16 rcms_fn_id;
	u8 vf_id;
	bool privileged : 1;
	bool vchnl_up : 1;
	bool ceq_valid : 1;
	bool double_vlan_en : 1;
	struct mutex vchnl_mutex;
	struct sxe2_rdma_dma_mem vf_gather_stats_buf[SXE2_MAX_PE_ENA_VF_COUNT];
	u8 pf_cnt;
	struct mutex lag_mutex;
};

struct sxe2_rdma_irq_ops {
	void (*sxe2_rdma_cfg_aeq)(struct sxe2_rdma_ctx_dev *dev, u32 idx,
				  bool enable);
	void (*sxe2_rdma_cfg_ceq)(struct sxe2_rdma_ctx_dev *dev, u32 ceq_id,
				  u32 idx, bool enable);
	void (*sxe2_rdma_dis_irq)(struct sxe2_rdma_ctx_dev *dev, u32 idx);
	void (*sxe2_rdma_en_irq)(struct sxe2_rdma_ctx_dev *dev, u32 idx);
};

struct sxe2_rdma_vchnl_if {
	int (*vchnl_recv)(struct sxe2_rdma_ctx_dev *dev, u16 vf_id, u8 *msg,
			  u16 len, u64 session_id);
};

struct sxe2_rdma_handler {
	struct list_head list;
	struct sxe2_rdma_device *dev;
#ifdef SXE2_CFG_DEBUG
	struct dentry *db_debugfs;
	struct dentry *stats_debugfs;
#endif
	struct dentry *sxe2_rdma_dbg_dentry;
	struct dentry *qp_debugfs;
	struct dentry *cq_debugfs;
	struct dentry *eq_debugfs;
	struct dentry *ceq_debugfs;
	struct dentry *aeq_debugfs;
	struct dentry *srq_debugfs;
	struct dentry *mq_debugfs;
	struct dentry *rcms_debugfs;
	struct dentry *mr_debugfs;
#ifdef SXE2_CFG_DEBUG
	struct dentry *ah_debugfs;
#endif
	struct dentry *aeq_codes_err_debugfs;
	struct dentry *mq_err_debugfs;
	struct dentry *mq_err_cqe_debugfs;
	struct dentry *qos_debugfs;
	struct dentry *mq_op_failed_debugfs;

	struct dentry *cc_debugfs;
	struct dentry *common_debugfs;
	struct list_head ucontext_list;
	spinlock_t uctx_list_lock;
	bool shared_res_created;
};

enum sxe2_cmpl_notify {
	SXE2_RDMA_CQ_COMPL_EVENT     = 0,
	SXE2_RDMA_CQ_COMPL_SOLICITED = 1,
};

struct sxe2_rdma_cq_uk {
	__le64 *cqe_alloc_db;
	struct sxe2_cqe *cq_base;
	__le32 *doorbell_note;
	__u32 cq_id;
	u32 arm_sn;
	__u32 ncqe;
	struct sxe2_ring cq_ring;
	__u8 polarity;
};

struct sxe2_rdma_ctx_cq {
	struct sxe2_rdma_cq_uk cq_uk;
	u64 cq_pa;
	u64 db_pa;
	struct sxe2_rdma_ctx_dev *dev;
	struct sxe2_rdma_ctx_vsi *vsi;
	void *back_cq;
	u8 cq_type;
	struct drv_rdma_soft_cqc cqc;
};

struct sxe2_rdma_ctx_ceq {
	u32 size;
	u32 cons_index;
	u32 __iomem *doorbell;
	struct sxe2_rdma_ctx_dev *dev;
	struct sxe2_eqe *ceqe_base;
	struct sxe2_eqe_hygon *ceqe_hygon_base;
	u32 ceq_id;
	struct sxe2_ring ceq_ring;
	u8 polarity;
	struct sxe2_rdma_ctx_vsi *vsi;
	struct drv_rdma_soft_eqc eqc;
};

enum sxe2_pbl_qp_srq_mode {
	QP_SRQ_PA_FIRST_MODE  = 0,
	QP_SRQ_PA_SECOND_MODE = 1,
};

struct sxe2_pbl_pble_info {
	u64 liner_addr;
	u32 pble_idx;
};

struct sxe2_pbl_pble_alloc_info {
	u32 total_pble_cnt;
	u32 needed_pble_cnt;
	u64 pbl_index;
	bool mr_first_page_flags;
	union {
		enum sxe2_pbl_qp_srq_mode qp_srq_mode;
		enum sxe2_pbl_cq_eq_mode cq_eq_mode;
		enum sxe2_pbl_mr_mode mr_mode;
		u32 mode;
	} pbl_mode;
	struct sxe2_pbl_pble_info pble_info;
};

struct sxe2_ceq_pble_buf {
	void *buf;
	dma_addr_t map;
};

struct sxe2_rdma_ceq {
	struct sxe2_rdma_ctx_ceq ctx_ceq;
	struct sxe2_rdma_dma_mem mem;
	u32 irq;
	u32 msix_idx;
	struct sxe2_rdma_pci_f *rf;
	struct tasklet_struct dpc_tasklet;
	spinlock_t ce_lock;
	struct sxe2_rdma_rsc_debug *dbg_node;

	struct sxe2_pbl_pble_alloc_info palloc;
	bool pble_map;
	struct sxe2_ceq_pble_buf *pble_buf;
};

struct sxe2_pbl_buddy {
	unsigned long **bits;
	u32 *num_free;
	u32 max_order;
	spinlock_t buddy_lock;
	struct sxe2_rdma_ctx_dev *dev;
};

struct sxe2_pbl_first_page_bitmap {
	unsigned long *fpte_bits;
	spinlock_t bitmap_lock;
	u32 max_fpte_cnt;
	u32 first_fpte_idx;
	struct sxe2_rdma_ctx_dev *dev;
};

enum sxe2_pbl_create_mode {
	PBL_FIRST_PAGE_TABLE  = 1,
	PBL_SECOND_PAGE_TABLE = 2,
	PBL_THIRD_PAGE_TABLE  = 3,
};

struct sxe2_pbl_pble_rsrc {
	enum sxe2_pbl_create_mode init_mode;
	u32 unallocated_pble;
	u32 allocated_pbles;
	struct mutex pble_mutex_lock;
	struct sxe2_rdma_ctx_dev *dev;
	struct sxe2_pbl_buddy buddy;
	bool first_page_en;
	struct sxe2_pbl_first_page_bitmap first_page_bitmap;
	u16 fpte_indexes[SXE2_RCMS_MAX_FPT_COUNT];
	u32 spte_indexes[SXE2_RCMS_SPT_ENTRY_CNT];
	u32 add_fpte_cnt;
	u32 add_spte_cnt;
	u64 pble_base_addr;
	u64 alloc_pble_base_addr;
	u32 unallocated_first_type_fpte_cnt;
	u32 allocated_first_type_fpte_cnt;
	u32 second_type_fpte_cnt;
	u32 third_type_fpte_cnt;
};

struct sxe2_rdma_ctx_aeq {
	u32 size;
	u32 cons_index;
	u32 __iomem *doorbell;
	struct sxe2_rdma_ctx_dev *dev;
	struct sxe2_eqe *aeqe_base;
	struct sxe2_eqe_hygon *aeqe_hygon_base;
	void *pbl_list;
	struct sxe2_ring aeq_ring;
	u32 irq;
	u32 msix_idx;
	u8 polarity;
	bool virtual_map : 1;
	struct sxe2_rdma_ctx_vsi *vsi;
	struct drv_rdma_soft_eqc eqc;
};

struct sxe2_aeq_pble_buf {
	void *buf;
	dma_addr_t map;
};

struct sxe2_rdma_aeq {
	struct sxe2_rdma_ctx_aeq ctx_aeq;
	struct sxe2_rdma_dma_mem mem;
	struct sxe2_pbl_pble_alloc_info palloc;
	bool pble_map;
	struct sxe2_aeq_pble_buf *pble_buf;
	struct sxe2_rdma_rsc_debug *dbg_node;
	struct dentry *debugfs_cnt;
};

struct sxe2_sq_common_wr_trk_info {
	__u64 wrid;
	__u32 wr_len;
	__u16 quanta;
	__u8 reserved[2];
};

struct sxe2_qp_quanta {
	__le64 elem[SXE2_WQE_SIZE];
};

struct sxe2_cqe {
	__le64 buf[SXE2_CQE_SIZE];
};
union sxe2_ah_info {
	struct {
		u16 rsv1;
		u8 dest_mac[ETH_ALEN];

		u64 vlan_tag : 16;
		u64 rsv2 : 16;
		u64 tc_tos : 8;
		u64 rsv3 : 6;
		u64 pd_idx : 18;

		u64 flow_label : 20;
		u64 rsv4 : 12;
		u64 hop_ttl : 8;
		u64 rsv5 : 8;
		u64 arp_index : 16;

		u64 ah_idx : 17;
		u64 rsv6 : 15;
		u64 op : 6;
		u64 rsv7 : 4;
		u64 rsv8 : 17;
		u64 ipv4_valid : 1;
		u64 insert_vlan_tag : 1;
		u64 rsv9 : 1;
		u64 do_lpbk : 1;
		u64 wqe_valid : 1;
		u32 dest_ip_addr[4];
		u32 src_ip_addr[4];
	} field;
	__u64 buf[SXE2_MQ_WQE_SIZE];
};

struct sxe2_ctx_ah {
	struct sxe2_rdma_ctx_dev *dev;
	struct sxe2_mq_request *mq_request;
	union sxe2_ah_info ah_info;
	bool ah_valid : 1;
};

struct sxe2_ah {
	struct ib_ah ibah;
	struct sxe2_ctx_ah ctx_ah;
	struct sxe2_av av;
	struct hlist_node list;
	refcount_t refcnt;
	struct sxe2_ah *parent_ah;
#ifdef SXE2_CFG_DEBUG
	struct sxe2_rdma_rsc_debug *dbg_node;
#endif
};

struct sxe2_srq_drv {
	struct sxe2_qp_quanta *srq_base;
	struct sxe2_common_attrs *common_attrs;
	__le64 *db_note;
	struct sxe2_ring srq_ring;
	u32 srq_id;
	u32 srq_size;
	u32 max_srq_frag_cnt;
	u8 srq_polarity;
	u8 wqe_size;
	u8 wqe_size_multiplier;
	u32 srq_buf_size;
};

struct sxe2_umode_srq {
	struct ib_umem *srq_umem;
	struct ib_umem *db_note_umem;
	u8 wqe_access_mod;
	u64 pbl_pointer;
	struct sxe2_pbl_pble_alloc_info *pble_alloc_info;
};

struct sxe2_kmode_srq {
	struct sxe2_rdma_dma_mem srq_buf_mem;
	struct sxe2_rdma_dma_mem
		srq_db_note_mem;
	u64 *srq_wrid_array;
	u8 *srqe_array;
};

struct sxe2_rdma_srq_ctx {
	struct sxe2_rdma_ctx_dev *dev;
	struct sxe2_rdma_ctx_vsi *vsi;
	struct sxe2_rdma_ctx_pd *pd;
	struct sxe2_srq_drv srq_drv;
	struct sxe2_umode_srq usrq_rsc;
	struct sxe2_kmode_srq ksrq_rsc;
	u64 srq_pa;
	u64 db_note_pa;
	u32 hw_srq_size;
	u16 srq_limit;
	bool user_mode : 1;
	u32 log_page_size;
	u64 srq_cmpl_ctx;
};

struct sxe2_rdma_srq {
	struct ib_srq ibsrq;
	struct sxe2_rdma_srq_ctx srq_ctx;
	struct completion free_srq;
	refcount_t refcnt;
	spinlock_t lock;
	u32 srq_id;
	u32 max_wr;
	u32 max_sge;
	struct sxe2_rdma_rsc_debug *dbg_node;
	struct sxe2_rdma_pd *pd;
};

struct sxe2_io_info {
	u32 total_sqe_cnt;
	u32 total_rqe_cnt;
	u32 finished_sqe_cnt;
	u32 finished_rqe_cnt;
	u32 finished_rqe_insrq_cnt;
	u32 flushed_sq_cnt;
	u32 flushed_rq_cnt;
	u32 cleaned_sq_cnt;
	u32 cleaned_rq_cnt;
	u32 cleaned_flushsq_cnt;
	u32 cleaned_flushrq_cnt;
	u32 total_signal_cnt;
	u32 send_cnt;
	u32 send_inv_cnt;
	u32 read_cnt;
	u32 write_cnt;
	u32 local_inv_cnt;
	u32 bind_mw_cnt;
	u32 fast_regmr_cnt;
	u64 last_send_sqwrid;
	u64 last_rcvd_sqwrid;
	u64 last_send_rqwrid;
	u64 last_rcvd_rqwrid;
};

struct sxe2_qp_common {
	struct sxe2_qp_quanta *sq_base;
	struct sxe2_qp_quanta *rq_base;
	struct sxe2_srq_drv *srq;
	struct sxe2_common_attrs *common_attrs;
	u32 __iomem *qp_db_no_llwqe;
	struct sxe2_sq_common_wr_trk_info *sq_wrtrk_array;
	u64 *rq_wrid_array;
	__le32 *doorbell_note;
	__le32 *push_db;
	__le64 *push_wqe;
	struct sxe2_llwqe *llwqe;
	struct sxe2_ring sq_ring;
	struct sxe2_ring rq_ring;
	struct sxe2_ring initial_ring;
	u32 qpn;
	u32 qp_caps;
	u32 sq_size;
	u32 rq_size;
	u32 max_sq_sge_cnt;
	u32 max_rq_sge_cnt;
	u32 max_inline_data;
	u8 qp_type;
	u8 swqe_polarity;
	u8 rwqe_polarity;
	u8 rq_wqe_size;
	u8 rq_wqe_size_multiplier;
	u8 rd_fence_rate;
	u16 ord_cnt;
	bool llwqe_mode : 1;
	bool push_dropped : 1;
	void *back_qp;
	bool destroy_pending : 1;
	spinlock_t *lock;
	u8 dbg_rq_flushed;
	struct sxe2_io_info statistics;
};

struct sxe2_rdma_ctx_qp {
	struct sxe2_qp_common qp_common;
	u64 sq_pa;
	u64 rq_pa;
	u64 hw_host_ctx_pa;
	u32 *shadow_area_va;
	u64 shadow_area_pa;
	struct sxe2_rdma_ctx_dev *dev;
	struct sxe2_rdma_ctx_vsi *vsi;
	struct sxe2_rdma_ctx_pd *pd;
	__le64 *hw_host_ctx;
	u64 qp_compl_ctx;
	u32 llwqe_page_index;
	u16 push_offset;
	u8 qp_state;
	u8 hw_sq_size;
	u8 hw_rq_size;
	u8 qp_buff_page_offset;
	bool on_qoslist : 1;
	bool flush_sq : 1;
	bool flush_rq : 1;
	enum sxe2_qp_event_type event_type;
	u8 user_pri;
	struct list_head list;
	u8 sq_flush_polarity;
	u8 qset_idx;
};
struct sxe2_roce_offload_info {
	u16 p_key;
	u32 err_rq_idx;
	u32 qkey;
	u32 dest_qp;
	u8 err_rq_idx_valid;
	u32 pd_id;
	u16 log_rra_max;
	u16 log_sra_max;
	bool is_qp1 : 1;
	bool udprivcq_en : 1;
	bool flush_mr : 1;
	bool fw_cc_enable : 1;
	bool use_stats_inst : 1;
	bool bind_en : 1;
	u8 loacl_ack_timeout;
	u16 t_high;
	u16 t_low;
	u8 last_byte_sentl;
	u8 state_rate;
	u8 mac_addr[ETH_ALEN];
	u8 dest_mac_addr[ETH_ALEN];
};
struct sxe2_udp_offload_info {
	bool ipv4 : 1;
	bool insert_vlan_tag : 1;
	u8 ttl;
	u8 dscp;
	u8 ecn;
	u16 src_port;
	u16 dst_port;
	u32 dest_ip_addr[4];
	u32 pmtu;
	u16 vlan_tag;
	u32 flow_label;
	u8 udp_state;
	u32 sq_psn;
	u32 rq_psn;
	u32 local_ipaddr[4];
	u8 retry_cnt;
	u8 rnr_retry;
	u8 min_rnr_timer;
	u8 ack_timeout;
};
struct sxe2_qp_host_ctx_info {
	u64 qp_compl_ctx;
	struct sxe2_udp_offload_info *udp_info;
	struct sxe2_roce_offload_info *roce_info;
	u32 send_cq_num;
	u32 rcv_cq_num;
	u32 srqn;
	u16 stats_idx;
	bool srq_valid : 1;
	bool stats_idx_valid : 1;
	u8 user_pri;
	u32 llwqe_page_index;
	u8 llwqe_mod_enable;
	u8 log_msg_max;
	u8 fl;
	u32 src_vsi;
	u8 retry_mode;
	u8 credit_en;
	u16 rqe_lwm;
	u8 retry_resp_op_sel;
	u8 log_rtm;
	u8 ack_mode;
	u8 log_ack_req_freq;
	u16 dispatch_min_unit;
	u8 dispatch_mode;
	u8 qp_bucket_type;
};
struct sxe2_qp_kmode {
	struct sxe2_rdma_dma_mem dma_mem;
	struct sxe2_sq_common_wr_trk_info *sq_wrid_mem;
	u64 *rq_wrid_mem;
};

enum sxe2_qp_wqe_access_mod {
	SXE2_QP_WQE_ACCESS_MOD_0 = 0x0,
	SXE2_QP_WQE_ACCESS_MOD_1 = 0x1,
};

struct sxe2_rdma_qp {
	struct ib_qp ibqp;
	struct sxe2_rdma_ctx_qp qp_ctx;
	struct sxe2_rdma_device *dev;
	struct sxe2_rdma_cq *send_cq;
	struct sxe2_rdma_cq *recv_cq;
	struct sxe2_rdma_pd *pd;
	struct sxe2_qp_host_ctx_info ctx_info;
	struct sxe2_roce_offload_info roce_info;
	struct sxe2_udp_offload_info
		udp_info;
	struct sxe2_ah roce_ah;
	refcount_t refcnt;
	struct delayed_work dwork_flush;
	enum ib_qp_state ibqp_state;
	u32 max_send_wr;
	u32 max_recv_wr;
	spinlock_t lock;
	u8 sig_all : 1;
	struct sxe2_qp_kmode kqp;
	struct sxe2_rdma_dma_mem host_ctx;
	struct completion free_qp;
	struct ib_umem *qp_umem;
	struct ib_umem *db_note_umem;
	u64 pbl_pointer;
	u8 log_page_size;
	u8 wqe_access_mod;
	struct sxe2_pbl_pble_alloc_info *pble_alloc_info;
	u8 suspend_pending : 1;
	bool user_mod : 1;
	u8 flush_issued : 1;
	struct sxe2_rdma_rsc_debug *dbg_node;
	u8 gsi_flag : 1;
	u8 state_rate_other_flag : 1;
	u8 sw_cc_enable;
	u32 sw_cc_idx;
	bool alloc_db_page;
};

struct sxe2_cqe_info {
	__u64 wr_id;
	__u32 bytes;
	union {
		struct {
			__u64 payload_len : 32;
			__u64 packet_seq : 24;
			__u64 rsvd1 : 8;
			__u64 qpc;
			__u64 l_r_key : 32;
			__u64 qp_id : 18;
			__u64 rsvd2 : 14;
			__u64 minor_err : 16;
			__u64 major_err : 16;
			__u64 wq_desc_idx : 15;
			__u64 rsvd3 : 3;
			__u64 extended_cqe : 1;
			__u64 push_dropped : 1;
			__u64 ipv4 : 1;
			__u64 stag_or_lrkey : 1;
			__u64 solicited_evt : 1;
			__u64 error : 1;
			__u64 op : 6;
			__u64 qp_type : 1;
			__u64 rsvd4 : 1;
			__u64 imme_data : 32;
			__u64 srqn : 18;
			__u64 is_srq : 1;
			__u64 rsvd5 : 13;
			__u64 cqe_timestamp;
			__u64 ud_smac : 48;
			__u64 ud_vlan_tag : 16;
			__u64 ud_src_qpn : 24;
			__u64 rsvd6 : 8;
			__u64 rsvd7 : 6;
			__u64 vsi_index : 10;
			__u64 rsvd8 : 12;
			__u64 vlan_tag_flag : 1;
			__u64 ud_smac_valid : 1;
			__u64 imm_data_flag : 1;
			__u64 cqe_valid : 1;
		} field;
		__u64 buf[SXE2_CQE_SIZE];
	} info;
};

struct sxe2_flushed_cqe {
	struct list_head list;
	struct sxe2_cqe_info cqeinfo;
};

struct sxe2_rdma_cq {
	struct ib_cq ibcq;
	struct sxe2_rdma_ctx_cq cq_ctx;
	u16 cq_head;
	u32 cq_num;
	bool user_mode;
	atomic_t armed;
	enum sxe2_arm_type arm_type;
	struct sxe2_rdma_dma_mem kmem;
	struct sxe2_rdma_dma_mem kmem_db;
	struct ib_umem *
		cq_umem;
	struct ib_umem *
		db_umem;
	struct completion free_cq;
	refcount_t refcnt;
	spinlock_t lock;
	struct sxe2_pbl_pble_alloc_info palloc;
	struct sxe2_cqe_info cur_cqe;
	struct list_head cmpl_generated;
	struct sxe2_rdma_rsc_debug *dbg_node;
};

struct sxe2_cq_cmpl_gen {
	struct list_head list;
	struct sxe2_cqe_info cur_cqe;
};

struct sxe2_rdma_ctx_pd {
	struct sxe2_rdma_ctx_dev *dev;
	u32 pd_id;
	int abi_ver;
};

struct sxe2_rdma_pd {
	struct ib_pd ibpd;
	struct sxe2_rdma_ctx_pd pd_ctx;
};

struct sxe2_rdma_mcq {
	struct sxe2_rdma_ctx_cq ctx_cq;
	struct sxe2_rdma_dma_mem mem_cq;
	struct sxe2_rdma_dma_mem mem_db_note;
	struct sxe2_rdma_rsc_debug *dbg_node;
};

struct sxe2_rdma_msix_vector {
	u32 idx;
	u32 irq;
	u32 cpu_affinity;
	u32 ceq_id;
	u32 ceq_abs_id;
	cpumask_t mask;
	char name[SXE2_RDMA_IRQ_NAME_STR_LEN];
};

struct sxe2_rdma_qv_info {
	u32 v_idx;
	u16 ceq_idx;
	u16 aeq_idx;
	u8 itr_idx;
};

struct sxe2_rdma_qvlist_info {
	u32 num_vectors;
	struct sxe2_rdma_qv_info qv_info[];
};

struct sxe2_rdma_vchnl_dev {
	struct sxe2_rdma_ctx_dev *pf_dev;
	struct sxe2_rdma_ctx_vsi *vf_vsi;
	u8 *rcms_info_mem;
	u8 vchnl_msg_buf[SXE2_RDMA_VCHNL_MAX_MSG_SIZE];
	struct sxe2_rcms_info rcms_info;
	u64 fpm_query_buf_pa;
	u64 *fpm_query_buf;
	refcount_t refcnt;
	u16 pmf_index;
	u16 vf_id;
	u16 vf_idx;
	u8 protocol_used;
	bool pf_rcms_initialized : 1;
	bool reset_en : 1;
	bool port_vlan_en : 1;
	bool stats_initialized : 1;
	struct sxe2_rdma_stats_gather_info gather_stats_info;
	struct sxe2_rdma_dma_mem gather_stats_buf;
};

struct sxe2_rdma_gen_ops {
	void (*request_reset)(struct sxe2_rdma_pci_f *rf);
	int (*register_qsets)(struct sxe2_rdma_ctx_vsi *vsi,
			      struct sxe2_rdma_qset *qset1,
			      struct sxe2_rdma_qset *qset2);
	void (*unregister_qsets)(struct sxe2_rdma_ctx_vsi *vsi,
				 struct sxe2_rdma_qset *qset1,
				 struct sxe2_rdma_qset *qset2);
};

struct sxe2_rdma_cc_dcqcn_params {
	u16 t_interval;
	u32 b;
	u8 f;
	u8 rai_factor;
	u8 rhai_factor;
	u32 rreduce_mperiod;
	u8 min_dec_factor;
	u8 min_rate;
	u16 k;
	u8 bc;
	u8 tc;
	u32 g;
	u32 rt;
	u32 rc;
	u32 alpha;
	u16 rreduce_next_node_info;
	u16 t_next_node_info;
	u32 byte_counter;
	u8 decrease_rate_valid;
	u8 func_id;
};

struct sxe2_rdma_cc_timely_params {
	u16 min_rtt;
	u16 tlow;
	u16 thigh;
	u8 rai_factor;
	u16 pre_rtt;
	u32 beta;
	u32 alpha;
	u16 rtt_diff;
};

struct sxe2_rdma_cc_params {
	bool dcqcn_enable;
	bool dcqcn_cfg_valid;
	struct sxe2_rdma_cc_dcqcn_params dcqcn_params;
	bool timely_enable;
	bool timely_cfg_valid;
	struct sxe2_rdma_cc_timely_params timely_params;
	u8 ecn;
	u8 cnp_ecn;
	u32 cc_qp_idx;
};

struct sxe2_cc_refcount {
	atomic_t cc_qp_refcount;
	struct mutex refcount_lock;
};

struct rcms_page_table_mode {
	enum sxe2_rcms_init_mode ctx_mode;
	enum sxe2_pbl_init_mode pbl_mode;
};

struct sxe2_db_llwqe_head {
	struct mutex lock;
	struct list_head list;
};

struct sxe2_llwqe {
	void __iomem *wqe_addr;
	void __iomem *db_addr;
	struct sxe2_db_page *db_page;
	bool wc;
	u32 index;
	spinlock_t lock;
};

struct sxe2_db_mmap_entry_head {
	struct mutex lock;
	struct list_head list;
};

struct sxe2_mq_ctx {
	u32 size;
	u64 mq_buf_pa;
	u64 mq_ctx_pa;
	struct sxe2_rdma_ctx_dev *dev;
	int (*process_mq_fpt)(struct sxe2_rdma_ctx_dev *dev,
			      struct sxe2_rcms_update_fptes_info
				      *info);
	struct sxe2_rdma_dma_mem fptebuf;
	struct sxe2_ring mq_ring;
	struct sxe2_mq_quanta *mq_buf_va;
	__le64 *mq_ctx_va;
	u64 *scratch_array;
	u64 requested_ops;
	atomic64_t completed_ops;
	u32 mqe_count;
	u32 hw_mq_size;
	u16 hw_maj_ver;
	u16 hw_min_ver;
	u8 struct_ver;
	u8 polarity;
	u8 rcms_profile;
	u8 ena_vf_count;
	u8 ceqs_per_vf;
	bool rocev2_rto_policy : 1;
	bool en_rem_endpoint_trk : 1;
	enum sxe2_protocol_used protocol_used;
};

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
enum mq_wqe_err_code {
	MQ_WQE_ERR_DEBUGFS_CLR	  = 0x0,
	QPN_DEBUGFS		  = 0x1,
	CQN_DEBUGFS		  = 0x2,
	SRQN_DEBUGFS		  = 0x3,
	CEQN_DEBUGFS		  = 0x4,
	AEQN_DEBUGFS		  = 0x5,
	QPC_SRQN_DEBUGFS	  = 0x6,
	QPC_SEND_CQN_DEBUGFS	  = 0x7,
	QPC_RECV_CQN_DEBUGFS	  = 0x8,
	CQC_CEQN_DEBUGFS	  = 0x9,
	QPC_SW_STATE_DEBUGFS	  = 0xA,
	CQC_SW_STATE_DEBUGFS	  = 0xB,
	SRQC_SW_STATE_DEBUGFS	  = 0xC,
	CEQC_SW_STATE_DEBUGFS	  = 0xD,
	AEQC_SW_STATE_DEBUGFS	  = 0xE,
	QPC_TYPE_DEBUGFS	  = 0xF,
	QPC_PMTU_DEBUGFS	  = 0x10,
	QPC_SQ_SIZE_DEBUGFS	  = 0x11,
	QPC_RQ_SIZE_DEBUGFS	  = 0x12,
	CQC_SIZE_DEBUGFS	  = 0x13,
	SRQC_SIZE_DEBUGFS	  = 0x14,
	CEQC_SIZE_DEBUGFS	  = 0x15,
	AEQC_SIZE_DEBUGFS	  = 0x16,
	QPC_RQ_TYPE_DEBUGFS	  = 0x17,
	QPC_PAGE_SIZE_DEBUGFS	  = 0x18,
	QPC_SW_STATE_JUMP_DEBUGFS = 0x19,
	FPTE_CNT_DEBUGFS	  = 0x1A,
	AH_ID_DEBUGFS		  = 0x1B,
	MR_ID_DEBUGFS		  = 0x1C,
	MR_ACCESS_RIGHT_DEBUGFS	  = 0x1D,
	MR_TYPE_DEBUGFS		  = 0x1E,
	MR_PAGE_SIZE_DEBUGFS	  = 0x1F,
	QP_CTX_PA_DEBUGFS	  = 0x20,
	QP_CREATE_OP_DEBUGFS	  = 0x21,
	MQ_DEBUGFS_INJECT_ERR_MAX = 0x22,
};

enum {
	MQ_MNG_PBL_WQE_ERR_CLR	  = 0x0,
	MQ_MNG_PBL_SPTE_CNT	  = 0x1,
	MQ_MNG_PBL_FIRST_SPTE_IDX = 0x2,
	MQ_MNG_PBL_FPTE_IDX	  = 0x3,
	MQ_MNG_PBL_OPCODE	  = 0x4,
};

struct sxe2_mq_err_dbg_val {
	bool mqc_addr_vld;
	u64 mqc_addr;
	bool mqc_size_vld;
	u64 mqc_size;
	bool mqc_base_vld;
	u64 mqc_base;
	u32 mqc_ignore_vld;
};

struct sxe2_mq_err_mcqe_dbg_val {
	u32 fpte_rsc_type;
	u32 fpte_err_type;
	u32 rsc_wqe_err_type;
	u64 rsc_wqe_err_val;
	bool commit_wqe_err_vld;
	u32 commit_wqe_err_type;
	u32 commit_wqe_err_val;
	bool manage_pbl_wqe_err_vld;
	u32 manage_pbl_wqe_err_type;
	u64 manage_pbl_wqe_err_val;
};
#endif

struct sxe2_mq {
	struct sxe2_mq_ctx mq;
	spinlock_t req_lock;
	spinlock_t cmpl_lock;
	wait_queue_head_t remove_wq;
	struct sxe2_rdma_dma_mem mq_buf;
	struct sxe2_rdma_dma_mem mq_ctx;
	u64 *scratch_array;
	struct sxe2_mq_request *mq_requests;
	struct list_head mq_avail_reqs;
	struct sxe2_rdma_rsc_debug *dbg_node;
	bool mcqe_ignore;
#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)
	struct sxe2_mq_err_dbg_val err_val;
	struct sxe2_mq_err_mcqe_dbg_val err_cqe_val;
	bool ops_failed[MQ_MAX_OPS];
#endif
};

union sxe2_hw_ahc {
	struct {
		u16 rsv1;
		u8 dest_mac[ETH_ALEN];

		u64 vlan_tag : 16;
		u64 rsv2 : 16;
		u64 tc_tos : 8;
		u64 rsv3 : 6;
		u64 pd_idx : 18;

		u64 flow_label : 20;
		u64 rsv4 : 12;
		u64 hop_ttl : 8;
		u64 rsv5 : 8;
		u64 rsv10 : 16;

		u64 ah_idx : 17;
		u64 rsv6 : 15;
		u64 op : 6;
		u64 rsv7 : 4;
		u64 rsv8 : 17;
		u64 ipv4_valid : 1;
		u64 insert_vlan_tag : 1;
		u64 ah_valid : 1;
		u64 do_lpbk : 1;
		u64 wqe_valid : 1;
		u32 dest_ip_addr[4];
		u32 src_ip_addr[4];
	} field;
	__u64 buf[SXE2_MQ_WQE_SIZE];
};

union sxe2_alloc_key_info {
	struct {
		u64 rsv1 : 7;
		u64 rsv2 : 1;
		u64 pbl_mode : 2;
		u64 rsv4 : 5;
		u64 rsv5 : 1;
		u64 mw_type : 1;
		u64 rsv6 : 7;
		u64 access_mode : 5;
		u64 mr_type : 1;
		u64 rsv8 : 1;
		u64 rsv9 : 1;
		u64 rsv10 : 8;
		u64 rsv11 : 18;
		u64 rsv12 : 6;

		u64 rsv13 : 24;
		u64 rsv14 : 8;
		u64 pd : 18;
		u64 rsv15 : 1;
		u64 rsv16 : 1;
		u64 rsv17 : 12;
		u64 rsv18;
		u64 mr_idx : 22;
		u64 rsv19 : 10;
		u64 op : 6;
		u64 rsv20 : 25;
		u64 wqe_valid : 1;
		u64 rsv21;
		u64 len;
		u64 pbl_idx;
		u64 log_entity_size : 5;
		u64 rsv22 : 27;
		u64 rsv23 : 32;
	} field;
	__u64 buf[SXE2_MQ_WQE_SIZE];
};

union sxe2_dalloc_key_info {
	struct {
		u64 rsv1 : 7;
		u64 rsv2 : 1;
		u64 rsv3 : 2;
		u64 rsv4 : 5;
		u64 rsv5 : 1;
		u64 rsv6 : 1;
		u64 rsv7 : 7;
		u64 rsv8 : 5;
		u64 mr_type : 1;
		u64 rsv9 : 1;
		u64 rsv10 : 1;
		u64 rsv11 : 8;
		u64 rsv12 : 18;
		u64 rsv13 : 6;

		u64 rsv14 : 24;
		u64 rsv15 : 8;
		u64 pd : 18;
		u64 rsv16 : 1;
		u64 rsv17 : 1;
		u64 rsv18 : 12;
		u64 rsv19;
		u64 mr_idx : 22;
		u64 rsv20 : 10;
		u64 op : 6;
		u64 rsv21 : 25;
		u64 wqe_valid : 1;
		u64 rsv22;
		u64 rsv23;
		u64 rsv24;
		u64 rsv25;
	} field;
	__u64 buf[SXE2_MQ_WQE_SIZE];
};
struct sxe2_create_qp_info {
};
struct sxe2_modify_qp_info {
};
struct sxe2_destroy_qp_info {
};
struct sxe2_query_qp_info {
};

struct sxe2_rcms_fcn_info {
	u32 vf_id;
	u8 protocol_used;
	u8 free_fcn;
};

struct sxe2_pbl_manage_pble_info {
	u32 fpte_idx;
	u16 first_spte_idx;
	u16 spte_cnt;
	u8 invalidate_spte_cnt;
	u64 first_spte_pa;
};

struct mq_info {
	union {
		struct {
			struct sxe2_mq_ctx *mq;
			struct sxe2_rdma_stats_gather_info info;
			u64 scratch;
		} stats_gather;

		struct {
			struct sxe2_rdma_ctx_cq *cq;
			u64 scratch;
			bool check_overflow;
		} cq_create;

		struct {
			struct sxe2_rdma_ctx_cq *cq;
			struct sxe2_rdma_cqc *cqc;
			u64 scratch;
		} cq_modify;

		struct {
			struct sxe2_rdma_ctx_cq *cq;
			u64 query_pa;
			u64 scratch;
		} cq_query;

		struct {
			struct sxe2_rdma_ctx_cq *cq;
			u64 scratch;
		} cq_destroy;

		struct {
			struct sxe2_rdma_ctx_ceq *ceq;
			u64 scratch;
		} ceq_ops;

		struct {
			struct sxe2_rdma_ctx_ceq *ceq;
			u64 query_pa;
			u64 scratch;
		} ceq_query;

		struct {
			struct sxe2_rdma_ctx_ceq *ceq;
			struct sxe2_rdma_eqc *ceqc;
			u64 scratch;
		} ceq_modify;

		struct {
			struct sxe2_rdma_ctx_aeq *aeq;
			u64 scratch;
		} aeq_ops;

		struct {
			struct sxe2_rdma_ctx_aeq *aeq;
			u64 query_pa;
			u64 scratch;
		} aeq_query;

		struct {
			struct sxe2_rdma_ctx_aeq *aeq;
			struct sxe2_rdma_eqc *aeqc;
			u64 scratch;
		} aeq_modify;

		struct {
			struct sxe2_rdma_ctx_dev *ctx_dev;
			union sxe2_reg_mr_info info;
			u64 scratch;
		} reg_mr;

		struct {
			struct sxe2_rdma_ctx_dev *ctx_dev;
			union sxe2_query_mr_info info;
			u64 scratch;
		} query_mr;

		struct {
			struct sxe2_rdma_ctx_dev *ctx_dev;
			union sxe2_dereg_mr_info info;
			u64 scratch;
		} dereg_mr;

		struct {
			struct sxe2_rdma_ctx_dev *ctx_dev;
			union sxe2_alloc_key_info info;
			u64 scratch;
		} alloc_key;

		struct {
			struct sxe2_rdma_ctx_dev *ctx_dev;
			union sxe2_dalloc_key_info info;
			u64 scratch;
		} dalloc_key;

		struct {
			struct sxe2_rdma_ctx_dev *ctx_dev;
			union sxe2_ah_info info;
			u64 scratch;
		} ah_info;

		struct {
			struct sxe2_mq_ctx *mq;
			void *fpm_val_va;
			u64 fpm_val_pa;
			u16 rcms_fn_id;
			u64 scratch;
		} query_fpm_val;

		struct {
			struct sxe2_mq_ctx *mq;
			void *fpm_val_va;
			u64 fpm_val_pa;
			u16 rcms_fn_id;
			u64 scratch;
		} commit_fpm_val;

		struct {
			struct sxe2_rdma_ctx_dev *dev;
			struct sxe2_rcms_update_fptes_info info;
			u64 scratch;
		} update_pe_fptes;
		struct {
			struct sxe2_rdma_ctx_qp *qp;
			struct sxe2_create_qp_info info;
			u64 scratch;
		} qp_create;
		struct {
			struct sxe2_rdma_ctx_qp *qp;
			struct sxe2_modify_qp_info info;
			u64 scratch;
		} qp_modify;
		struct {
			struct sxe2_rdma_ctx_qp *qp;
			struct sxe2_destroy_qp_info info;
			u64 scratch;
		} qp_destroy;
		struct {
			struct sxe2_rdma_ctx_qp *qp;
			struct sxe2_query_qp_info info;
			u64 scratch;
		} qp_query;
		struct {
			struct sxe2_mq_ctx *mq;
			u64 scratch;
			u32 wait_type;
		} nop;

		struct {
			struct sxe2_rdma_ctx_dev *dev;
			struct sxe2_rcms_fcn_info info;
			u64 scratch;
		} manage_rcms_pm;

		struct {
			struct sxe2_mq_ctx *mq;
			struct sxe2_pbl_manage_pble_info info;
			u64 scratch;
		} manage_pble_bp;

		struct {
			struct sxe2_rdma_srq_ctx *srq;
			u64 scratch;
		} srq_create;

		struct {
			struct sxe2_rdma_srq_ctx *srq;
			u64 query_pa;
			u64 scratch;
		} srq_query;

		struct {
			struct sxe2_rdma_srq_ctx *srq;
			struct sxe2_rdma_srqc *srqc;
			u64 scratch;
		} srq_modify;

		struct {
			struct sxe2_rdma_srq_ctx *srq;
			u64 scratch;
		} srq_destroy;
	} u;
};
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
struct sxe2_rdma_aeq_codes_inject {
	u8 cq_sw_status_err : 1;
	u8 ceq_sw_status_err : 1;
	u8 db_ceqn_err : 1;
	u8 ceq_ci_noupdate : 2;
	u8 aeq_ci_noupdate : 1;
	u8 tmo_fpte_valid_0 : 1;
	u8 tmo_fpte_flag : 1;
	u8 cq_db_no_update : 1;
	u8 srq_limit_flag : 1;
	u8 llwqe_flag : 1;
};
#endif

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
struct sxe2_rdma_qos_inject {
	u8 apply_qset_err_code;
	u8 release_qset_err_code;
	u8 qp_bind_qset_err_code;
};
#endif

struct sxe2_rdma_pci_f {
	bool reset : 1;
	bool rsrc_created : 1;
	bool msix_shared : 1;
	bool ftype : 1;
	u8 rsrc_profile;
	u16 max_rdma_vfs;
	u8 *rcms_info_mem;
	u8 *mem_rsrc;
	u8 rdma_ver;
	u8 rst_to;
	u8 pf_id;
	u8 fragcnt_limit;
	enum sxe2_protocol_used protocol_used;
	bool en_rem_endpoint_trk : 1;
	u32 sd_type;
	u32 msix_count;
	u32 max_mr;
	u32 max_qp;
	u32 max_cq;
	u32 max_ah;
	u32 next_ah;
	u32 max_pd;
	u32 next_qp;
	u32 next_cq;
	u32 next_pd;
	u32 max_mr_size;
	u32 max_cqe;
	u32 mr_stagmask;
	u32 used_pds;
	u32 used_cqs;
	u32 used_mrs;
	u32 used_qps;
	u32 used_srqs;
	u32 arp_table_size;
	u32 next_arp_index;
	u32 ceqs_count;
	u32 limits_sel;
	u32 max_qsets;
	u32 next_qset;
	u32 max_srq;
	u32 next_srq;
	u32 max_dbs;
	u32 next_db;
	u32 max_cc_qp_cnt;
	unsigned long *allocated_qset;
	unsigned long *allocated_qps;
	unsigned long *allocated_cqs;
	unsigned long *allocated_mrs;
	unsigned long *allocated_pds;
	unsigned long *allocated_ahs;
	unsigned long *allocated_arps;
	unsigned long *allocated_dbs;
	unsigned long *allocated_srqs;
	enum init_completion_state init_state;
	struct sxe2_rdma_ctx_dev ctx_dev;
	struct sxe2_rdma_handler *hdl;
	struct pci_dev *pcidev;
	void *cdev;
	struct sxe2_rdma_hw hw;
	struct sxe2_mq mq;
	struct sxe2_rdma_mcq mcq;
	struct sxe2_rdma_aeq aeq;
	struct sxe2_rdma_ceq *ceqlist;
	struct sxe2_pbl_pble_rsrc *pble_rsrc;
	spinlock_t rsrc_lock;
	spinlock_t qptable_lock;
	spinlock_t cqtable_lock;
	spinlock_t srqtable_lock;
	struct sxe2_rdma_qp **qp_table;
	struct sxe2_rdma_cq **cq_table;
	struct sxe2_rdma_srq **srq_table;
	spinlock_t qh_list_lock;
	struct sxe2_rdma_msix_vector *sxe2_msixtbl;
	struct sxe2_rdma_qvlist_info *sxe2_qvlist;
	struct tasklet_struct dpc_tasklet;
	struct msix_entry *msix_entries;
	struct sxe2_rdma_dma_mem obj_mem;
	struct sxe2_rdma_dma_mem obj_next;
	atomic64_t push_cnt;
	atomic_t vchnl_msgs;
	wait_queue_head_t vchnl_waitq;
	struct workqueue_struct *mq_cmpl_wq;
	struct work_struct mq_cmpl_work;
	struct workqueue_struct *vchnl_wq;
	struct sxe2_rdma_ctx_vsi default_vsi;
	void *back_fcn;
	struct sxe2_rdma_gen_ops gen_ops;
	void (*check_fc)(struct sxe2_rdma_ctx_vsi *vsi,
			 struct sxe2_rdma_ctx_qp *ctx_qp);
	struct sxe2_cc_refcount cc_refcount;
	struct sxe2_rdma_cc_params cc_params;
	struct sxe2_rdma_device *rdma_dev;
	u8 vlan_parse_en;
	phys_addr_t bar_db_addr;
	struct sxe2_db_page *db;
	struct sxe2_db_llwqe_head db_head;
	struct sxe2_llwqe llwqe;
	struct sxe2_db_mmap_entry_head db_mmap_entry_head;
	struct rcms_page_table_mode rcms_mode;
	u8 ack_mode : 1;
	u8 oi : 1;
	u8 scqe_break_moderation_en : 1;
	u8 log_ack_req_freq : 4;
	u8 UDPriv_CQEnable : 1;
	u8 aeq_pble_en : 1;
	u8 hygon_cpu_en;
	u8 app_mod_all_flush;
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	struct sxe2_rdma_aeq_codes_inject inject_aeq;
#endif
	u16 vfid_base;
	u8 pf_cnt;
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	u32 inject_sleep_time;
	struct sxe2_inject_mem inject_mem;
	struct sxe2_inject_debug inject_dbg;
	struct sxe2_rdma_qos_inject inject_qos;
#endif
	atomic_t aeq_created;
};

struct sxe2_b300_test_debugfs {
	bool mac_loopback_en;
	u32 dest_ip_addr;
	u32 src_ip_addr;
};

#define MAX_RESET_INFO_CNT 10
#define MAX_VF_FUNC_CNT	   32
#define MAX_BDF_SIZE	   16
#define MAX_TIME_BUF_SIZE  40

enum sxe2_reset_type {
	FUNC_REQUEST_RESET = 0,
	FUNC_WARNING_RESET = 1,
};

struct sxe2_reset_debug_info {
	s8 time[40];
	enum sxe2_reset_type reset_type;
};

struct sxe2_reset_debug_func_info {
	u32 reset_cnt;
	s8 bdf[16];
	u8 reset_info_idx;
	struct sxe2_reset_debug_info reset_info[MAX_RESET_INFO_CNT];
	bool valid;
};

struct sxe2_reset_debug_pf_info {
	struct sxe2_reset_debug_func_info pf_reset_info;
	struct sxe2_reset_debug_func_info vf_info[32];
};

struct sxe2_reset_debug {
	struct mutex reset_debug_mutex;
	struct sxe2_reset_debug_pf_info pf_info[8];
};

enum sxe2_lag_type {
	SXE2_LAG_NONE,
	SXE2_LAG_ACTIVE_PASSIVE,
	SXE2_LAG_ACTIVE_ACTIVE
};

struct sxe2_rdma_device {
	struct ib_device ibdev;
	struct sxe2_rdma_pci_f *rdma_func;
	struct net_device *netdev;
	struct notifier_block nb_netdevice_event;
	struct notifier_block nb_net_event;
	struct notifier_block nb_inet6addr_event;
	struct notifier_block nb_inetaddr_event;
	struct auxiliary_device *aux_dev;
	struct sxe2_rdma_handler *hdl;
	const struct sxe2_rdma_profile *profile;
	struct workqueue_struct *cleanup_wq;
	struct sxe2_rdma_ctx_vsi vsi;
	u32 cm_core;
	DECLARE_HASHTABLE(ah_hash_tbl, 8);
	struct mutex ah_tbl_lock;

#ifdef CONFIG_DEBUG_FS
	u64 ah_reused;
#endif
	u32 ah_list_cnt;
	u32 ah_list_hwm;
	u32 roce_cwnd;
	u32 roce_ackcreds;
	u32 vendor_id;
	u32 vendor_part_id;
	u32 rcv_wnd;
	u16 mac_ip_table_idx;
	u16 vsi_num;
	u8 rcv_wscale;
	u8 iw_status;
	u8 roce_rtomin;
	u8 rd_fence_rate;
	bool override_rcv_wnd : 1;
	bool override_cwnd : 1;
	bool override_ackcreds : 1;
	bool override_ooo : 1;
	bool override_rd_fence_rate : 1;
	bool override_rtomin : 1;
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
	u64 up_up_map;
	u8 cnp_up_override;
	u8 iwarp_rtomin;
	u32 ceq_intrl;
	bool up_map_en : 1;
	bool iwarp_dctcp_en : 1;
	bool iwarp_timely_en : 1;
	bool iwarp_bolt_en : 1;
	bool iwarp_ecn_en : 1;
	bool roce_ecn_en : 1;
	bool roce_timely_en : 1;
	bool roce_no_icrc_en : 1;
	bool roce_dctcp_en : 1;
	bool kernel_llwqe_mode : 1;
	bool roce_enable_tph : 1;
#endif
	bool roce_mode : 1;
	bool roce_dcqcn_en : 1;
	bool dcb_vlan_mode : 1;
	bool iw_ooo : 1;
	bool cache_line_64_en : 1;
	enum init_completion_state init_state;
	enum sxe2_lag_type lag_mode;
	s8 bdf[16];
	wait_queue_head_t suspend_wq;
	char ib_devname[IB_DEVICE_NAME_MAX];
	int numa_node;
	bool rdma_dump_pcap;
#ifdef SXE2_CFG_DEBUG
	struct sxe2_reset_debug_func_info *reset_func_info;
#endif
	struct aux_ver_info fw_ver;
};

struct sxe2_rdma_kcontext {
	struct ib_ucontext ibucontext;
	struct sxe2_rdma_device *rdma_dev;
#ifndef RDMA_MMAP_DB_NOT_SUPPORT
	struct rdma_user_mmap_entry
		*db_mmap_entry;
#else
	struct sxe2_user_mmap_entry *db_mmap_entry;
	DECLARE_HASHTABLE(mmap_hash_tbl, 6);
	spinlock_t mmap_tbl_lock;
#endif
	struct list_head cq_reg_mem_list;
	spinlock_t cq_reg_mem_list_lock;
	struct list_head qp_reg_mem_list;
	spinlock_t qp_reg_mem_list_lock;
	struct list_head uctx_list;
	int abi_ver;
	struct list_head vma_list;
	struct mutex vma_list_mutex;
};

struct sxe2_rdma_up_info {
	u8 map[8];
	u8 cnp_up_override;
	u16 hmc_fcn_idx;
	bool use_vlan : 1;
	bool use_cnp_up_override : 1;
};

struct sxe2_user_mmap_entry {
#ifndef RDMA_MMAP_DB_NOT_SUPPORT
	struct rdma_user_mmap_entry rdma_entry;
#else
	struct sxe2_rdma_kcontext *ucontext;
	struct hlist_node hlist;
	u64 pgoff_key;
#endif

	u8 mmap_flag;
	u64 address;
	u32 page_idx;
};

struct sxe2_mr {
	union {
		struct ib_mr ibmr;
		struct ib_mw ibmw;
	};
	struct ib_umem *region;
	int access;
	u8 is_hwreg;
	u8 acc_mode;
	u8 alloced_pble;
	u8 alloced_key;
	bool is_mw;
	u8 is_len64;
	u16 rsv2;
	u32 page_cnt;
	u64 page_size;
	u64 page_msk;
	u32 npages;
	u32 stag;
	u64 len;
	u64 pgaddrmem;
	struct sxe2_pbl_pble_alloc_info pble_alloc;
	struct sxe2_rdma_rsc_debug *dbg_node;
};

static inline struct sxe2_ah *ibah_to_vendor_ah(struct ib_ah *ibah)
{
	return container_of(ibah, struct sxe2_ah, ibah);
}

static inline struct sxe2_mr *ibmr_to_vendor_mr(struct ib_mr *ibmr)
{
	return container_of(ibmr, struct sxe2_mr, ibmr);
}

static inline struct sxe2_mr *ibmw_to_vendor_mw(struct ib_mw *ibmw)
{
	return container_of(ibmw, struct sxe2_mr, ibmw);
}

static inline struct sxe2_rdma_cq *ibcq_to_vendor_cq(struct ib_cq *ibcq)
{
	return container_of(ibcq, struct sxe2_rdma_cq, ibcq);
}

static inline struct sxe2_rdma_pci_f *
ctxdev_to_rf(struct sxe2_rdma_ctx_dev *dev)
{
	return container_of(dev, struct sxe2_rdma_pci_f, ctx_dev);
}

static inline ulong log_page_size_2_bitmap(u32 log_pgsz_bits, u32 pgsz_shift)
{
	u32 largest_pg_shift =
		min_t(ulong, (1ULL << log_pgsz_bits) - 1 + pgsz_shift,
		      BITS_PER_LONG - 1);

	pgsz_shift = max_t(u32, PAGE_SHIFT, pgsz_shift);

	return GENMASK(largest_pg_shift, pgsz_shift);
}

#define sxe2_umem_find_best_pgsz(umem, pgsz_width, pgsz_shift, iova)           \
	ib_umem_find_best_pgsz(                                                \
		umem, log_page_size_2_bitmap(pgsz_width, pgsz_shift), iova)

static inline struct sxe2_rdma_pd *to_kpd(struct ib_pd *ibpd)
{
	return container_of(ibpd, struct sxe2_rdma_pd, ibpd);
}

static inline struct sxe2_rdma_kcontext *
to_rdma_kcontext(struct ib_ucontext *ibucontext)
{
	return container_of(ibucontext, struct sxe2_rdma_kcontext, ibucontext);
}

static inline struct sxe2_rdma_device *to_dev(struct ib_device *ibdev)
{
	return container_of(ibdev, struct sxe2_rdma_device, ibdev);
}

static inline struct sxe2_rdma_kcontext *
ibuctxto_kctx(struct ib_ucontext *ibucontext)
{
	return container_of(ibucontext, struct sxe2_rdma_kcontext, ibucontext);
}

static inline struct sxe2_rdma_device *to_rdmadev(struct sxe2_rdma_ctx_dev *dev)
{
	return (container_of(dev, struct sxe2_rdma_pci_f, ctx_dev))->rdma_dev;
}
#ifndef RDMA_MMAP_DB_NOT_SUPPORT
static inline struct sxe2_user_mmap_entry *
to_mmap(struct rdma_user_mmap_entry *rdma_entry)
{
	return container_of(rdma_entry, struct sxe2_user_mmap_entry,
			    rdma_entry);
}
#endif
static inline struct sxe2_rdma_pci_f *to_rdmafunc(struct sxe2_rdma_ctx_dev *dev)
{
	return container_of(dev, struct sxe2_rdma_pci_f, ctx_dev);
}

int sxe2_kget_aligned_mem(struct sxe2_rdma_pci_f *rdma_func,
			  struct sxe2_rdma_dma_mem *memptr, u32 size, u32 mask);

u8 sxe2_kget_encoded_wqe_size(u32 wqsize, enum sxe2_queue_type queue_type);

static inline void set_64bit_val(__le64 *wqe_words, u32 byte_index, u64 val)
{
	wqe_words[byte_index >> 3] = cpu_to_le64(val);
}

static inline void set_32bit_val(__le32 *wqe_words, u32 byte_index, u32 val)
{
	wqe_words[byte_index >> 2] = cpu_to_le32(val);
}

static inline void get_64bit_val(__le64 *wqe_words, u32 byte_index, u64 *val)
{
	*val = le64_to_cpu(wqe_words[byte_index >> 3]);
}

static inline void get_32bit_val(__le32 *wqe_words, u32 byte_index, u32 *val)
{
	*val = le32_to_cpu(wqe_words[byte_index >> 2]);
}

static inline void sxe2_write64(void __iomem *dest, __le32 val[2])
{
#if BITS_PER_LONG == 64
	__raw_writeq(*(u64 *)val, dest);
#else
	__raw_writel((__force u32)val[0], dest);
	__raw_writel((__force u32)val[1], dest + 4);
#endif
}

static inline void sxe2_memcpy_x64(void *dest, const void *src, size_t bytecnt)
{
	__le64 *dst_p = dest;

	const __le64 *src_p = src;

	do {
		sxe2_write64(dst_p++, (__le32 *)src_p++);
		bytecnt -= sizeof(*dst_p);
	} while (bytecnt > 0);
}

int sxe2_kalloc_rsrc(struct sxe2_rdma_pci_f *rf, unsigned long *rsrc_array,
		     u32 max_rsrc, u32 *req_rsrc_num, u32 *next);

void sxe2_kfree_rsrc(struct sxe2_rdma_pci_f *rf, unsigned long *rsrc_array,
		     u32 rsrc_num);

int sxe2_ucount_bitmap_zero_bits(unsigned long *bitmap, u32 max);

u32 sxe2_round_up_pow_2(u32 value);

void sxe2_copy_ip_ntohl(u32 *dst, __be32 *src);

void sxe2_copy_ip_htonl(__be32 *dst, u32 *src);

void sxe2_qp_add_ref(struct ib_qp *ibqp);
void sxe2_qp_rem_ref(struct ib_qp *ibqp);
static inline struct sxe2_rdma_qp *to_qp(struct ib_qp *ibqp)
{
	return container_of(ibqp, struct sxe2_rdma_qp, ibqp);
}
static inline struct sxe2_rdma_pd *to_pd(struct ib_pd *ibpd)
{
	return container_of(ibpd, struct sxe2_rdma_pd, ibpd);
}

static inline struct sxe2_rdma_srq *to_srq(struct ib_srq *ibsrq)
{
	return container_of(ibsrq, struct sxe2_rdma_srq, ibsrq);
}

void sxe2_clean_cqes(struct sxe2_rdma_qp *rdma_qp, struct sxe2_rdma_cq *rdma_cq,
		     int cq_type);

void sxe2_flush_wqe_worker(struct work_struct *work);

void sxe2_sched_qp_flush_work(struct sxe2_rdma_qp *rdma_qp);
#ifdef QUERY_PKEY_V1
int sxe2_query_pkey(struct ib_device *ibdev, u8 port, u16 index, u16 *pkey);
#else
int sxe2_query_pkey(struct ib_device *ibdev, u32 port, u16 index, u16 *pkey);
#endif

void sxe2_sched_qp_flush_work(struct sxe2_rdma_qp *qp);

void sxe2_generate_flush_completions(struct sxe2_rdma_qp *rdma_qp);

bool sxe2_get_hw_rsrc_clean_flag(struct sxe2_rdma_ctx_dev *dev);

bool sxe2_drv_core_is_tph_enable(struct sxe2_rdma_device *rdma_dev,
				 bool is_user_enable, u32 *st_mode);

bool check_bridge_tph_is_support(struct sxe2_rdma_device *rdma_dev);

int pci_dev_set_tph_request_cap(struct sxe2_rdma_device *rdma_dev, bool enable);
int sxe2_rdma_adminq_send(struct aux_core_dev_info *cdev_info,
				 int opcode,
			     u8 *msg, u16 len, u8 *recv_msg, u16 recv_len);

#endif
