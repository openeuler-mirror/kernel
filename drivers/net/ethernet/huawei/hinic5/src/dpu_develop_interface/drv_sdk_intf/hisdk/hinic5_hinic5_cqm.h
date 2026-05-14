/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_hinic5_cqm.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_HINIC5_CQM_H
#define HINIC5_HINIC5_CQM_H

#include <linux/types.h>
#include <linux/completion.h>

#include "hinic5_crm.h"
#include "hinic5_hinic5_cqm_adpt.h"
#include "hinic5_hinic5_vram_api.h"

#define HINIC5_CQM_SUCCESS                     0       /* Success result code */
#define HINIC5_CQM_FAIL                        (-1)    /* Failure result code */
#define HINIC5_CQM_CONTINUE                    1       /* Continue result code */

#define HINIC5_CQM_WQE_WF_NORMAL               0       /* Normal WQE Format */
#define HINIC5_CQM_WQE_WF_LINK                 1       /* Link WQE format */

#define HINIC5_CQM_QUEUE_LINK_MODE             0       /* Linked queue mode */
#define HINIC5_CQM_QUEUE_RING_MODE             1       /* Ring queue mode */
#define HINIC5_CQM_QUEUE_TOE_SRQ_LINK_MODE     2       /* SRQ queue mode */
#define HINIC5_CQM_QUEUE_RDMA_QUEUE_MODE       3       /* RDMA queue mode */

/**
 * @brief Link WQE common structure
 */
typedef struct tag_hinic5_cqm_linkwqe {
	u32 rsv1 : 14;              /* Reserved */
	u32 wf : 1;                 /* WQE format */
	u32 rsv2 : 14;              /* Reserved */
	u32 ctrlsl : 2;             /* Length of the control segment */
	u32 o : 1;                  /* Owner bit */

	u32 rsv3 : 31;              /* Reserved */
	u32 lp : 1;                 /* Loop Back valid */

	u32 next_page_gpa_h;        /* High 32 bits of next page physical address, used by chip */
	u32 next_page_gpa_l;        /* Low 32 bits of next page physical address, used by chip */

	u32 next_buffer_addr_h;     /* High 32 bits of next page virtual address, used by driver */
	u32 next_buffer_addr_l;     /* Low 32 bits of next page virtual address, used by driver */
} hinic5_cqm_linkwqe_s;

/**
 * @brief SRQ Link WQE structure
 * @note  WQE size must not exceed normal RQE size
 */
typedef struct tag_hinic5_cqm_srq_linkwqe {
	hinic5_cqm_linkwqe_s linkwqe;	/* Link WQE common data */
	u32 current_buffer_gpa_h;	/* High 32 bits of current page physical address,
					 * used when driver releases container and unmaps
					 */
	u32 current_buffer_gpa_l;	/* Low 32 bits of current page physical address,
					 * used when driver releases container and unmaps
					 */
	u32 current_buffer_addr_h;	/* High 32 bits of current page virtual address,
					 * used when driver releases container
					 */
	u32 current_buffer_addr_l;	/* Low 32 bits of current page virtual address,
					 * used when driver releases container
					 */

	u32 fast_link_page_addr_h;	/* High 32 bits of fastlink page virtual address where container resides,
					 * used when driver releases fastlink
					 */
	u32 fast_link_page_addr_l;	/* Low 32 bits of fastlink page virtual address where container resides,
					 * used when driver releases fastlink
					 */

	u32 fixed_next_buffer_addr_h;	/* High 32 bits of next container virtual address,
					 * for driver resource release, cannot be modified by driver
					 */
	u32 fixed_next_buffer_addr_l;	/* Low 32 bits of next container virtual address,
					 * for driver resource release, cannot be modified by driver
					 */
} hinic5_cqm_srq_linkwqe_s;

/**
 * @brief First 64B of standard 128B WQE
 */
typedef union tag_hinic5_cqm_linkwqe_first64B {
	hinic5_cqm_linkwqe_s basic_linkwqe;        /* Link WQE common data */
	hinic5_cqm_srq_linkwqe_s toe_srq_linkwqe;  /* SRQ linkwqe structure */
	u32 value[16];                      /* Reserved fields */
} hinic5_cqm_linkwqe_first64B_s;

/**
 * @brief Second 64B of standard 128B WQE
 */
typedef struct tag_hinic5_cqm_linkwqe_second64B {
	u32 rsvd0[4];               /* First 16B, Reserved */
	u32 rsvd1[4];               /* Second 16B, Reserved */

	union {
		struct {
			u32 rsvd0[3];       /* Reserved */
			u32 rsvd1 : 29;     /* Reserved */
			u32 toe_o : 1;      /* TOE owner bit */
			u32 resvd2 : 2;     /* Reserved */
		} bs;
		u32 value[4];
	} third_16B;                /* Third 16B */

	union {
		struct {
			u32 rsvd0[2];       /* Reserved */
			u32 rsvd1 : 31;     /* Reserved */
			u32 ifoe_o : 1;     /* IFoE onwer bit */
			u32 rsvd2;          /* Reserved */
		} bs;
		u32 value[4];
	} forth_16B;                /* Fourth 16B */
} hinic5_cqm_linkwqe_second64B_s;

/**
 * @brief Standard 128B WQE structure
 */
typedef struct tag_hinic5_cqm_linkwqe_128B {
	hinic5_cqm_linkwqe_first64B_s  first64B;   /* First 64B of standard 128B WQE */
	hinic5_cqm_linkwqe_second64B_s second64B;  /* Second 64B of standard 128B WQE */
} hinic5_cqm_linkwqe_128B_s;

/**
 * @brief AEQ type definition
 */
typedef enum {
	HINIC5_CQM_AEQ_BASE_T_NIC = 0,      /* NIC: 15 events 0~14 */
	HINIC5_CQM_AEQ_BASE_T_DMMU = 15,    /* DMMU: 1 event 15 */
	HINIC5_CQM_AEQ_BASE_T_ROCE = 16,    /* ROCE: 32 events 16~47 */
	HINIC5_CQM_AEQ_BASE_T_FC = 48,      /* FC: 8 events 48~55 */
	HINIC5_CQM_AEQ_BASE_T_IOE = 56,     /* IOE: 8 events 56~63 */
	HINIC5_CQM_AEQ_BASE_T_TOE = 64,     /* TOE: 16 events 64~79 */
	HINIC5_CQM_AEQ_BASE_T_UB = 80,      /* UB: 16 events 80~95 */
	HINIC5_CQM_AEQ_BASE_T_VBS = 96,     /* VBS: 16 events 96~111 */
	HINIC5_CQM_AEQ_BASE_T_IPSEC = 112,  /* IPSEC: 16 events 112~127 */
	HINIC5_CQM_AEQ_BASE_T_MAX = 128     /* Maximum 128 event types */
} hinic5_cqm_aeq_event_type_e;

/**
 * @brief HINIC5_CQM service extension description
 */
typedef struct tag_service_register_template {
	u32 service_type;	/* Service type */
	u32 srq_ctx_size;	/* SRQ context size */
	u32 scq_ctx_size;	/* SCQ context size */
	void *service_handle;	/* Pointer passed to service driver in ceq/aeq callback */
	/* CEQ callback: shared CQ */
	void (*shared_cq_ceq_callback)(void *service_handle, u32 cqn, void *cq_priv);
	/* CEQ callback: embedded CQ */
	void (*embedded_cq_ceq_callback)(void *service_handle, u32 xid, void *qpc_priv);
	/* CEQ callback: no CQ */
	void (*no_cq_ceq_callback)(void *service_handle, u32 xid, u32 qid, void *qpc_priv);
	u8 (*aeq_level_callback)(void *service_handle, u8 event_type, u8 *val);	/* AEQ level callback */
	void (*aeq_callback)(void *service_handle, u8 event_type, u8 *val);	/* AEQ callback */
} service_register_template_s;

/**
 * @brief HINIC5_CQM object type
 */
typedef enum hinic5_cqm_object_type {
	HINIC5_CQM_OBJECT_ROOT_CTX = 0,              /* Root context. Reserved for future root ctx management */
	HINIC5_CQM_OBJECT_SERVICE_CTX,               /* QPC, Service context, connection management object */
	HINIC5_CQM_OBJECT_MPT,                       /* RDMA Memory Protection Table */

	HINIC5_CQM_OBJECT_NONRDMA_EMBEDDED_RQ = 10,  /* Non-RDMA RQ, managed by LINKWQE */
	HINIC5_CQM_OBJECT_NONRDMA_EMBEDDED_SQ,       /* Non-RDMA SQ, managed by LINKWQE */
	HINIC5_CQM_OBJECT_NONRDMA_SRQ,               /* Non-RDMA SRQ, managed by MTT,
						      * but HINIC5_CQM allocates MTT itself
						      */
	HINIC5_CQM_OBJECT_NONRDMA_EMBEDDED_CQ,       /* Non-RDMA embedded CQ, managed by LINKWQE */
	HINIC5_CQM_OBJECT_NONRDMA_SCQ,               /* Non-RDMA SCQ, managed by LINKWQE */

	HINIC5_CQM_OBJECT_RESV = 20,                 /* Reserved */

	HINIC5_CQM_OBJECT_RDMA_QP = 30,              /* RDMA Queue Pair */
	HINIC5_CQM_OBJECT_RDMA_SRQ,                  /* RDMA Shared Receive Queue */
	HINIC5_CQM_OBJECT_RDMA_SCQ,                  /* RDMA Shared Completion Queue */

	HINIC5_CQM_OBJECT_MTT = 50,                  /* RDMA Memory Translation Table */
	HINIC5_CQM_OBJECT_RDMARC,                    /* RDMA Reliable Connection */
} hinic5_cqm_object_type_e;

/**
 * @brief BITMAP table allocation failure return value
 */
#define HINIC5_CQM_INDEX_INVALID ~(0U)

/**
 * @brief New field definition compatible with XID=0xFFFFFFFF default XID allocation rule. Macro naming is low 3bit comparison bits
 */
#define HINIC5_CQM_XID_LOW_BIT_1_1_1          0x0  /* mask is 0x7 */
#define HINIC5_CQM_XID_LOW_BIT_0_1_1          0x4  /* mask is 0x3 */
#define HINIC5_CQM_XID_LOW_BIT_0_1_0          0x5  /* mask is 0x2 */
#define HINIC5_CQM_XID_LOW_BIT_0_0_1          0x6  /* mask is 0x1 */
#define HINIC5_CQM_XID_LOW_BIT_NONE           0x7  /* mask is 0x0 */
#define HINIC5_CQM_XID_SEARCH_RANGE           0x0
#define HINIC5_CQM_XID_SEARCH_ALL             0x1

#define HINIC5_CQM_XID_SEARCH_MODE_SHIFT      27
#define HINIC5_CQM_XID_LB_MODE_SHIFT          24
#define HINIC5_CQM_XID_LOW_BITS_SHIFT         21
#define HINIC5_CQM_XID_SEARCH_MODE_MASK       0x1
#define HINIC5_CQM_XID_LB_MODE_MASK           0x7
#define HINIC5_CQM_XID_LOW_BITS_MASK          0x7
#define HINIC5_CQM_DYNAMIC_XID_MASK           0x1FFFFF

/**
 * @brief Construct XID
 * @param[in]  search_mode  Search mode
 * @param[in]  lb_mode      Load balance mode
 * @param[in]  xid_low      Low 2 bits of XID
 *
 * @details search_mode: 0---search in specified XID range [bp_start, bp_end); 1---search in entire dynamic area
 *          lb_mode:
 *          0--When dynamically allocating XID, select xid[2:0]=xid_low[2:0]
 *          4--When dynamically allocating XID, select xid[1:0]=xid_low[1:0]
 *          5--When dynamically allocating XID, select xid[0]=xid_low[0]
 *          6--When dynamically allocating XID, select xid[1]=xid_low[1]
 *          7--All xids can be allocated
 *          xid_low: xid_low[2:0] used for matching
 *
 * @return Constructed XID
 */
#define HINIC5_CQM_DYNAMIC_XID_MOD(search_mode, lb_mode, xid_low) \
	((((search_mode) & HINIC5_CQM_XID_SEARCH_MODE_MASK) << HINIC5_CQM_XID_SEARCH_MODE_SHIFT) | \
	 (((lb_mode) & HINIC5_CQM_XID_LB_MODE_MASK) << HINIC5_CQM_XID_LB_MODE_SHIFT) | \
	 (((xid_low) & HINIC5_CQM_XID_LOW_BITS_MASK) << HINIC5_CQM_XID_LOW_BITS_SHIFT) | \
	 HINIC5_CQM_DYNAMIC_XID_MASK)

#define HINIC5_CQM_RDMA_Q_ROOM_1 (1)           /* First Q buffer space for ROCE Q buffer resize */
#define HINIC5_CQM_RDMA_Q_ROOM_2 (2)           /* Second Q buffer space for ROCE Q buffer resize */

#define HINIC5_CQM_HARDWARE_DOORBELL (1)       /* Current Q doorbell mode: hardware doorbell */
#define HINIC5_CQM_SOFTWARE_DOORBELL (2)       /* Current Q doorbell mode: software doorbell */
#define HINIC5_CQM_SECURE_BUFFER_EN  (1)       /* Flag indicating buffer is allocated from secure memory */

/**
 * @brief HINIC5_CQM buffer single node structure
 */
typedef struct tag_hinic5_cqm_buf_list {
	void *va;                   /* Virtual address */
	dma_addr_t pa;              /* Physical address */
	u32 refcount;               /* Buffer reference count, for internal buffer management */
} hinic5_cqm_buf_list_s;

/**
 * @brief HINIC5_CQM buffer single node structure, for WIN adaptation
 */
struct huge_buf_addr {
	void *huge_buf_vaddr;       /* Virtual address */
	dma_addr_t huge_buf_paddr;  /* Physical address */
	u32 huge_buf_size;          /* Single node buffer size */
};

/**
 * @brief HINIC5_CQM buffers management structure
 */
typedef struct tag_hinic5_cqm_buf {
	hinic5_cqm_buf_list_s *buf_list;   /* Buffer linked list */
	hinic5_cqm_buf_list_s direct;      /* Re-mapped buf_list as contiguous virtual address, only va member is valid */
	u32 page_number;            /* Total physical page number */
	u32 buf_number;             /* Buffer linked list length */
	u32 buf_size;               /* Buffer size */
#ifdef __WIN__
	struct huge_buf_addr *bufs_addr;    /* Buffer linked list */
	u32 huge_buf_number;                /* Buffer linked list node count */
#endif
	u32 secure_mem_flag;        /* Secure memory flag, default 0 (not using secure memory) */
	struct hinic5_vram_buf_info buf_info;
} hinic5_cqm_buf_s;

/**
 * @brief HINIC5_CQM object structure, abstraction of context/queue/table
 */
typedef struct tag_hinic5_cqm_object {
	u32 service_type;           /* Service type */
	u32 object_type;            /* Object type, such as context, queue, mpt, mtt, etc. */
	u32 object_size;            /* Object size,
					 For non-RDMA queues, this is queue depth;
					 For queue/ctx/MPT, unit is Byte;
					 For MTT/RDMARC, unit is entry count;
					 For container, unit is container count */
	atomic_t refcount;          /* Reference count */
	struct completion free;     /* Free completion */
	void *hinic5_cqm_handle;           /* hinic5_cqm_handle */
} hinic5_cqm_object_s;

/**
 * @brief QPC/MPT object
 */
typedef struct tag_hinic5_cqm_qpc_mpt {
	hinic5_cqm_object_s object;        /* Object base class */
	u32 xid;                    /* XID.
					 When xid[20:0] < 1M, indicates statically allocated xid;
					 When xid[20:0] = all 1s, indicates dynamically allocated;
					 xid[22:21] specifies low 2 bits;
					 xid[24:23] is lb_mode;
					 xid[25] is search_mode */
	dma_addr_t paddr;           /* QPC/MTT memory physical address */
	void *priv;                 /* Service driver's private info for this object */
	u8 *vaddr;                  /* QPC/MTT memory virtual address */
} hinic5_cqm_qpc_mpt_s;

/**
 * @brief Queue header structure
 */
typedef struct tag_hinic5_cqm_queue_header {
	u64 doorbell_record;        /* SQ/RQ doorbell content */
	u64 ci_record;              /* CQ doorbell content */
	u64 rsv1;                   /* Custom area for driver and firmware information exchange */
	u64 rsv2;                   /* Custom area for driver and firmware information exchange */
} hinic5_cqm_queue_header_s;

/**
 * @brief Queue management structure
 * @details For non-RDMA services, embedded queues use linkwqe management, SRQ and SCQ use MTT management, MTT is allocated by HINIC5_CQM;
 *          For RDMA services, queues use MTT management
 */
typedef struct tag_hinic5_cqm_queue {
	hinic5_cqm_object_s object;	/* Object base class */
	u32 index;			/* Embedded queues and QP have no index, SRQ and SCQ have */
	void *priv;			/* Service driver's private info for this object */
	u32 current_q_doorbell;		/* Current queue doorbell type, roce QP uses both HW/SW */
	u32 current_q_room;		/* roce: currently valid room buf */
	hinic5_cqm_buf_s q_room_buf_1;	/* nonrdma: can only select q_room_buf_1 as q_room_buf */
	hinic5_cqm_buf_s q_room_buf_2;	/* RDMA CQ will reallocate queue room size */
	hinic5_cqm_queue_header_s *q_header_vaddr;	/* Queue header virtual address */
	dma_addr_t q_header_paddr;	/* Queue header physical address */
	u8 *q_ctx_vaddr;		/* SRQ and SCQ ctx virtual address */
	dma_addr_t q_ctx_paddr;		/* SRQ and SCQ ctx physical address */
	u32 valid_wqe_num;		/* Number of validWQEs created successfully */
	u8 *tail_container;		/* SRQ container tail pointer */
	u8 *head_container;		/* SRQ container head pointer */
	u8 queue_link_mode;		/* Queue link mode determined at creation: link, ring, etc. */
} hinic5_cqm_queue_s;

/**
 * @brief MTT/RDMARC management structure
 */
typedef struct tag_hinic5_cqm_mtt_rdmarc {
	hinic5_cqm_object_s object;	/* Object base class */
	u32 index_base;			/* index_base */
	u32 index_number;		/* index_number */
	u8 *vaddr;			/* Buffer virtual address */
} hinic5_cqm_mtt_rdmarc_s;

/**
 * @brief Command buffer structure
 */
typedef struct tag_hinic5_cqm_cmd_buf {
	void *buf;                  /* Command buffer virtual address */
	dma_addr_t dma;             /* Command buffer physical address */
	u16 size;                   /* Command buffer size */
} hinic5_cqm_cmd_buf_s;

/**
 * @brief ACK sending method definition
 */
typedef enum {
	HINIC5_CQM_CMD_ACK_TYPE_CMDQ = 0,       /* ACK writeback to cmdq */
	HINIC5_CQM_CMD_ACK_TYPE_SHARE_CQN = 1,  /* ACK reported via root ctx SCQ */
	HINIC5_CQM_CMD_ACK_TYPE_APP_CQN = 2     /* ACK reported via service SCQ */
} hinic5_cqm_cmd_ack_type_e;

/**
 * @brief HINIC5_CQM initialization
 * @param[in]  ex_handle        Device handle
 *
 * @return Success or failure
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 hinic5_cqm3_init(void *ex_handle);

/**
 * @brief HINIC5_CQM uninitialization
 * @param[in]  ex_handle        Device handle
 */
void hinic5_cqm3_uninit(void *ex_handle);

/**
 * @brief HINIC5_CQM initialize specified Fake VF
 * @param[in]  ex_handle        Device handle
 * @param[in]  vf_id            Function id to initialize
 *
 * @return Success or failure
 *     @retval  0       success
 *     @retval -1       failure
 *     @retval -EINVAL  Invalid argument
 */
int hinic5_cqm3_init_fake_vf(void *ex_handle, u32 vf_id);

/**
 * @brief Register service extension capability
 * @param[in]  ex_handle        Device handle
 * @param[in]  service_template Service extension description
 *
 * @return Success or failure
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 hinic5_cqm3_service_register(void *ex_handle, service_register_template_s *service_template);

/**
 * @brief Unregister service extension capability
 * @param[in]  ex_handle        Device handle
 * @param[in]  service_type     Service type
 */
void hinic5_cqm3_service_unregister(void *ex_handle, u32 service_type);

/**
 * @brief Declare number of Fake VFs managed by device
 * @param[in]  ex_handle        Device handle
 * @param[in]  fake_vf_num_cfg  Fake VF number, must not exceed device maximum
 *
 * @return Success or failure
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 hinic5_cqm3_fake_vf_num_set(void *ex_handle, u16 fake_vf_num_cfg);

/**
 * @brief Create FC SRQ
 * @param[in]  ex_handle        Device handle
 * @param[in]  service_type     Service type
 * @param[in]  object_type      Object type
 * @param[in]  wqe_number       WQE number
 * @param[in]  wqe_size         WQE size
 * @param[in]  object_priv      Object private data pointer
 *
 * @details Number of validWQEs in queue must meet the specified WQE count.
 *          Since linkwqe can only be placed at page tail, actual valid count exceeds requirement, service needs to be informed of extra created count
 *
 * @return Queue structure pointer
 */
hinic5_cqm_queue_s *hinic5_cqm3_object_fc_srq_create(void *ex_handle, u32 service_type,
						     hinic5_cqm_object_type_e object_type,
						     u32 wqe_number, u32 wqe_size,
						     void *object_priv);

/**
 * @brief Create RQ
 * @param[in]  ex_handle        Device handle
 * @param[in]  service_type     Service type
 * @param[in]  object_type      Object type
 * @param[in]  init_rq_num      Container number
 * @param[in]  container_size   Container size
 * @param[in]  wqe_size         WQE size
 * @param[in]  object_priv      Object private data pointer
 *
 * @details RQ queue creation when using SRQ
 *
 * @return Queue structure pointer
 */
hinic5_cqm_queue_s *hinic5_cqm3_object_recv_queue_create(void *ex_handle, u32 service_type,
							 hinic5_cqm_object_type_e object_type,
							 u32 init_rq_num, u32 container_size,
							 u32 wqe_size, void *object_priv);

/**
 * @brief Create TOE SRQ
 * @param[in]  ex_handle        Device handle
 * @param[in]  service_type     Service type
 * @param[in]  object_type      Object type
 * @param[in]  container_number Container number
 * @param[in]  container_size   Container size
 * @param[in]  wqe_size         WQE size
 *
 * @return Queue structure pointer
 */
hinic5_cqm_queue_s *hinic5_cqm3_object_share_recv_queue_create(void *ex_handle, u32 service_type,
							       hinic5_cqm_object_type_e object_type,
							       u32 container_number,
							       u32 container_size, u32 wqe_size);

/**
 * @brief Create QPC/MPT
 * @param[in]  ex_handle        Device handle
 * @param[in]  service_type     Service type
 * @param[in]  object_type      Object type
 * @param[in]  object_size      Object size in Byte
 * @param[in]  object_priv      Object private data pointer
 * @param[in]  index            QPN to reserve based on this value, fill HINIC5_CQM_INDEX_INVALID for auto allocation
 * @param[in]  bitmap_start     Start index for range XID allocation
 * @param[in]  bitmap_end       End index for range XID allocation
 *
 * @attention This interface may sleep
 *
 * @return QPC/MPT structure pointer
 */
hinic5_cqm_qpc_mpt_s *hinic5_cqm3_object_qpc_mpt_create(void *ex_handle, u32 service_type,
							hinic5_cqm_object_type_e object_type,
							u32 object_size, void *object_priv,
							u32 index, u32 bitmap_start, u32 bitmap_end);

/**
 * @brief Create non-RDMA service queue
 * @param[in]  ex_handle        Device handle
 * @param[in]  service_type     Service type
 * @param[in]  object_type      Object type
 * @param[in]  wqe_number       Number of linkWQEs included
 * @param[in]  wqe_size         Fixed size, value is 2^n
 * @param[in]  object_priv      Object private data pointer
 *
 * @attention This interface may sleep
 *
 * @return Queue structure pointer
 */
hinic5_cqm_queue_s *hinic5_cqm3_object_nonrdma_queue_create(void *ex_handle, u32 service_type,
							    hinic5_cqm_object_type_e object_type,
							    u32 wqe_number, u32 wqe_size,
							    void *object_priv);

/**
 * @brief Create RDMA service queue
 * @param[in]  ex_handle        Device handle
 * @param[in]  service_type     Service type
 * @param[in]  object_type      Object type
 * @param[in]  object_size      Object size
 * @param[in]  object_priv      Object private data pointer
 * @param[in]  room_header_alloc Whether to allocate queue room and header space
 * @param[in]  xid              QPN to reserve based on this value, fill HINIC5_CQM_INDEX_INVALID for auto allocation
 * @param[in]  bitmap_start     Start index for range XID allocation
 * @param[in]  bitmap_end       End index for range XID allocation
 *
 * @attention This interface may sleep
 *
 * @return Queue structure pointer
 */
hinic5_cqm_queue_s *hinic5_cqm3_object_rdma_queue_create(void *ex_handle, u32 service_type,
							 hinic5_cqm_object_type_e object_type,
							 u32 object_size, void *object_priv,
							 bool room_header_alloc, u32 xid,
							 u32 bitmap_start, u32 bitmap_end);

/**
 * @brief Create RDMA service MTT/RDMARC
 * @param[in]  ex_handle        Device handle
 * @param[in]  service_type     Service type
 * @param[in]  object_type      Object type
 * @param[in]  index_base       Starting index number
 * @param[in]  index_number     Index count
 *
 * @return MTT/RDMARC structure pointer
 */
hinic5_cqm_mtt_rdmarc_s *hinic5_cqm3_object_rdma_table_get(void *ex_handle, u32 service_type,
							   hinic5_cqm_object_type_e object_type,
							   u32 index_base, u32 index_number);

/**
 * @brief Allocate a cmd buffer
 * @param[in]  ex_handle        Device handle
 *
 * @attention Buffer size is fixed at 2K, buffer content is not cleared, service needs to clear it
 *
 * @return Cmd buffer pointer
 */
hinic5_cqm_cmd_buf_s *hinic5_cqm3_cmd_alloc(void *ex_handle);

/**
 * @brief Free a cmd buffer
 * @param[in]  ex_handle        Device handle
 * @param[in]  cmd_buf          Cmd buffer pointer to free
 */
void hinic5_cqm3_cmd_free(void *ex_handle, hinic5_cqm_cmd_buf_s *cmd_buf);

/**
 * @brief Send cmd
 * @param[in]  ex_handle        Device handle
 * @param[in]  mod              Module
 * @param[in]  cmd              Command code
 * @param[in]  buf_in           Input command buffer
 * @param[out] buf_out          Output command buffer
 * @param[out] out_param        Udata (user data) returned by command
 * @param[in]  timeout          Command timeout in ms
 * @param[in]  channel          Caller channel id
 *
 * @details Send a cmdq cmd in box mode
 *
 * @attention This interface will block on completion, causing sleep
 *
 * @return Success or failure
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 hinic5_cqm3_send_cmd_box(void *ex_handle, u8 mod, u8 cmd,
			     hinic5_cqm_cmd_buf_s *buf_in, hinic5_cqm_cmd_buf_s *buf_out,
			     u64 *out_param, u32 timeout, u16 channel);

/**
 * @brief Send cmd
 * @param[in]  ex_handle        Device handle
 * @param[in]  mod              Module
 * @param[in]  cmd              Command code
 * @param[in]  cos_id           CMDQ queue
 * @param[in]  buf_in           Input command buffer
 * @param[out] buf_out          Output command buffer
 * @param[out] out_param        Udata (user data) returned by command
 * @param[in]  timeout          Command timeout in ms
 * @param[in]  channel          Caller channel id
 *
 * @details Send a cmdq cmd in box mode with specified CMDQ queue
 *
 * @attention This interface will block on completion, causing sleep
 *
 * @return Success or failure
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 hinic5_cqm3_lb_send_cmd_box(void *ex_handle, u8 mod, u8 cmd, u8 cos_id,
				hinic5_cqm_cmd_buf_s *buf_in, hinic5_cqm_cmd_buf_s *buf_out,
				u64 *out_param, u32 timeout, u16 channel);

/**
 * @brief Send cmd
 * @param[in]  ex_handle        Device handle
 * @param[in]  mod              Module
 * @param[in]  cmd              Command code
 * @param[in]  buf_in           Input command buffer
 * @param[out] out_param        Udata (user data) returned by command
 * @param[in]  timeout          Command timeout in ms
 * @param[in]  channel          Caller channel id
 *
 * @details Send a cmdq cmd in imm mode
 *
 * @attention This interface will block on completion, causing sleep
 *
 * @return Success or failure
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 hinic5_cqm3_send_cmd_imm(void *ex_handle, u8 mod, u8 cmd,
			     hinic5_cqm_cmd_buf_s *buf_in,
			     u64 *out_param, u32 timeout, u16 channel);

/**
 * @brief Allocate hardware doorbell and dwqe
 * @param[in]  ex_handle        Device handle
 * @param[out] db_addr          Doorbell physical address
 * @param[out] dwqe_addr        Dwqe physical address
 *
 * @details Allocate one page of hardware doorbell and dwqe with same index, both are physical addresses, each function has maximum 1K
 *
 * @return Success or failure
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 hinic5_cqm3_db_addr_alloc(void *ex_handle, void __iomem **db_addr, void __iomem **dwqe_addr);

/**
 * @brief Free hardware doorbell and dwqe
 * @param[in]  ex_handle        Device handle
 * @param[in]  db_addr          Doorbell physical address
 * @param[in]  dwqe_addr        Dwqe physical address
 */
void hinic5_cqm3_db_addr_free(void *ex_handle, const void __iomem *db_addr, void __iomem *dwqe_addr);

/**
 * @brief Get hardware doorbell virtual address
 * @param[in]  ex_handle        Device handle
 * @param[in]  service_type     Service type
 *
 * @return Doorbell virtual address
 */

void *hinic5_cqm3_get_db_addr(void *ex_handle, u32 service_type);

/**
 * @brief Get hardware doorbell physical address
 * @param[in]  ex_handle        Device handle
 * @param[out] addr             Pointer to store doorbell physical address
 * @param[in]  service_type     Service type
 *
 * @details Get hardware doorbell physical address
 *
 * @return Doorbell address
 */
s32 hinic5_cqm3_get_hardware_db_addr(void *ex_handle, u64 *addr, enum hinic5_service_type service_type);

/**
 * @brief Ring a hardware DB
 * @param[in]  ex_handle        Device handle
 * @param[in]  service_type     Service type
 * @param[in]  db_count         PI[7:0] in doorbell that exceeds 64b
 * @param[in]  db               The content of hardware doorbell
 *
 * @return Success or failure
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 hinic5_cqm3_ring_hardware_db(void *ex_handle, u32 service_type, u8 db_count, u64 db);

/**
 * @brief Ring a direct wqe hardware DB to chip
 * @param[in]  ex_handle        Device handle
 * @param[in]  service_type     Service type
 * @param[in]  db_count         The bit[7:0] of PI can't be store in 64-bit db
 * @param[in]  direct_wqe       The content of direct_wqe
 *
 * @return Success or failure
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 hinic5_cqm3_ring_direct_wqe_db(void *ex_handle, u32 service_type, u8 db_count, void *direct_wqe);

/**
 * @brief Ring a software DB
 * @param[in]  ex_handle        device handle
 * @param[in]  object           Object pointer
 * @param[in]  db_record        The content of software doorbell
 *
 * @return Success or failure
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 hinic5_cqm3_ring_software_db(hinic5_cqm_object_s *object, u64 db_record);

/**
 * @brief Bloom filter increase reference count
 * @param[in]  ex_handle        Device handle
 * @param[in]  func_id          Function id
 * @param[in]  id               Bloom filter id
 *
 * @details Set API when transitioning from 0 -> 1
 *
 * @attention This interface may sleep
 *
 * @return Success or failure
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 hinic5_cqm3_bloomfilter_inc(void *ex_handle, u16 func_id, u64 id);

/**
 * @brief Bloom filter decrease reference count
 * @param[in]  ex_handle        Device handle
 * @param[in]  func_id          Function id
 * @param[in]  id               Bloom filter id
 *
 * @details Clear API when transitioning to 0
 *
 * @attention This interface may sleep
 *
 * @return Success or failure
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 hinic5_cqm3_bloomfilter_dec(void *ex_handle, u16 func_id, u64 id);

/**
 * @brief Get SMF Timer spoke list base address
 * @param[in]  ex_handle        Device handle
 *
 * @return Virtual address
 */
void *hinic5_cqm3_timer_base(void *ex_handle);

/**
 * @brief Clear SMF Timer spoke list
 * @param[in]  ex_handle        Device handle
 * @param[in]  function_id      Function id
 */
void hinic5_cqm3_function_timer_clear(void *ex_handle, u32 function_id);

/**
 * @brief Clear hash buffer
 * @param[in]  ex_handle        Device handle
 * @param[in]  global_funcid    Function id
 */
void hinic5_cqm3_function_hash_buf_clear(void *ex_handle, s32 global_funcid);

/**
 * @brief SRQ allocate new container, ready for linking after creation
 * @param[in]  common           Queue structure pointer
 *
 * @return Success or failure
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 hinic5_cqm3_object_share_recv_queue_add_container(hinic5_cqm_queue_s *common);

/**
 * @brief SRQ allocate new container, not linked after creation, service completes linking
 * @param[in]  common           Queue structure pointer
 * @param[out] container_addr   Returned container address
 *
 * @return Success or failure
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 hinic5_cqm3_object_srq_add_container_free(hinic5_cqm_queue_s *common, u8 **container_addr);

/**
 * @brief Get object by index
 * @param[in]  ex_handle        Device handle
 * @param[in]  object_type      Object type
 * @param[in]  index            Index supports qpn, mptn, scqn, srqn
 * @param[in]  bh               Whether to disable interrupt bottom half
 *
 * @return Object pointer
 */
hinic5_cqm_object_s *hinic5_cqm3_object_get(void *ex_handle, hinic5_cqm_object_type_e object_type,
					    u32 index, bool bh);

/**
 * @brief Put (release) object
 * @param[in]  object           Object pointer
 */
void hinic5_cqm3_object_put(hinic5_cqm_object_s *object);

/**
 * @brief Delete object
 * @param[in]  object           Object pointer
 *
 * @details Delete created object, this function will sleep until all operations on this object are complete before returning
 *
 * @attention This interface may sleep
 */
void hinic5_cqm3_object_delete(hinic5_cqm_object_s *object);

/**
 * @brief Get function ID that owns the object
 * @param[in]  object           Object pointer
 *
 * @return
 *      @retval >=0 function ID
 *      @retval -1 failure
 */
s32 hinic5_cqm3_object_funcid(hinic5_cqm_object_s *object);

/**
 * @brief Allocate new space for object
 * @param[in]  object           Object pointer
 * @param[in]  object_size      New buffer size
 *
 * @details Currently only useful for roce service, adjusts CQ buffer size but cqn and cqc remain unchanged,
 *          allocates new buffer space, does not free old buffer space, current valid buffer is still old buffer
 *
 * @return Success or failure
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 hinic5_cqm3_object_resize_alloc_new(hinic5_cqm_object_s *object, u32 object_size);

/**
 * @brief Free newly allocated buffer space for object
 * @param[in]  object           Object pointer
 *
 * @details This function frees newly allocated buffer space, used for service exception handling
 */
void hinic5_cqm3_object_resize_free_new(hinic5_cqm_object_s *object);

/**
 * @brief Free old buffer space for object
 * @param[in]  object           Object pointer
 *
 * @details This function frees old buffer and sets current valid buffer to new buffer
 */
void hinic5_cqm3_object_resize_free_old(hinic5_cqm_object_s *object);

/**
 * @brief Release container
 * @param[in]  object           Object pointer
 * @param[in]  container        Container pointer to release
 *
 * @details Release container
 */
void hinic5_cqm3_srq_used_rq_container_delete(hinic5_cqm_object_s *object, u8 *container);

/**
 * @brief Get physical and virtual address at specified offset in object buffer
 * @param[in]  object           Object pointer
 * @param[in]  offset           For rdma table, offset is absolute index number
 * @param[out] paddr            Only returns physical address for rdma table
 *
 * @details Only supports rdma table lookup, gets physical and virtual address at specified offset in object buffer
 *
 * @return u8 * Virtual address at specified offset in buffer
 */
u8 *hinic5_cqm3_object_offset_addr(hinic5_cqm_object_s *object, u32 offset, dma_addr_t *paddr);

/**
 * @brief Create DTOE SRQ
 * @param[in]  ex_handle        Device handle
 * @param[in]  context_size     Context size
 * @param[out] index_count      Number of indices allocated
 * @param[out] index            Starting index allocated
 *
 * @return Success or failure
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 hinic5_cqm3_dtoe_share_recv_queue_create(void *ex_handle, u32 context_size,
				      u32 *index_count, u32 *index);

/**
 * @brief Free DTOE SRQ bitmap
 * @param[in]  ex_handle        Device handle
 * @param[in]  index_count      Number of indices to free
 * @param[in]  index            Starting index to free
 */
void hinic5_cqm3_dtoe_free_srq_bitmap_index(void *ex_handle, u32 index_count, u32 index);

#endif /* HINIC5_HINIC5_CQM_H */
