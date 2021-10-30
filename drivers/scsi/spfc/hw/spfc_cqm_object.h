/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPFC_CQM_OBJECT_H
#define SPFC_CQM_OBJECT_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#define CQM_SUCCESS                 0
#define CQM_FAIL                    (-1)
/* Ignore the return value and continue */
#define CQM_CONTINUE                1

/* type of WQE is LINK WQE */
#define CQM_WQE_WF_LINK             1

/* chain queue mode */
#define CQM_QUEUE_LINK_MODE         0
/* RING queue mode */
#define CQM_QUEUE_RING_MODE         1

#define CQM_CQ_DEPTH_MAX           32768
#define CQM_CQ_DEPTH_MIN           256

/* linkwqe */
#define CQM_LINK_WQE_CTRLSL_VALUE  2
#define CQM_LINK_WQE_LP_VALID      1
#define CQM_LINK_WQE_LP_INVALID    0
#define CQM_LINK_WQE_OWNER_VALID   1
#define CQM_LINK_WQE_OWNER_INVALID 0

#define CQM_ADDR_HI(addr) ((u32)((u64)(addr) >> 32))
#define CQM_ADDR_LW(addr) ((u32)((u64)(addr) & 0xffffffff))

#define CQM_QPC_LAYOUT_TABLE_SIZE  16

#define CQM_MOD_CQM 8

/* generic linkwqe structure */
struct cqm_linkwqe {
	u32 rsv1   : 14;        /* <reserved field */
	u32 wf     : 1;         /* <wf */
	u32 rsv2   : 14;        /* <reserved field */
	u32 ctrlsl : 2;         /* <ctrlsl */
	u32 o      : 1;         /* <o bit */

	u32 rsv3   : 31;        /* <reserved field */
	u32 lp     : 1;       /* The lp field determines whether the o-bit meaning is reversed. */
	u32 next_page_gpa_h;
	u32 next_page_gpa_l;
	u32 next_buffer_addr_h;
	u32 next_buffer_addr_l;
};

/* SRQ linkwqe structure. The wqe size must not exceed the common RQE size. */
struct cqm_srq_linkwqe {
	struct cqm_linkwqe linkwqe; /* <generic linkwqe structure */
	u32 current_buffer_gpa_h;
	u32 current_buffer_gpa_l;
	u32 current_buffer_addr_h;
	u32 current_buffer_addr_l;

	u32 fast_link_page_addr_h;
	u32 fast_link_page_addr_l;

	u32 fixed_next_buffer_addr_h;
	u32 fixed_next_buffer_addr_l;
};

#define CQM_LINKWQE_128B 128

/* first 64B of standard 128B WQE */
union cqm_linkwqe_first64B {
	struct cqm_linkwqe basic_linkwqe;       /* <generic linkwqe structure */
	u32 value[16];			        /* <reserved field */
};

/* second 64B of standard 128B WQE */
struct cqm_linkwqe_second64B {
	u32 rsvd0[4];                      /* <first 16B reserved field */
	u32 rsvd1[4];                      /* <second 16B reserved field */
	u32 rsvd2[4];

	union {
		struct {
			u32 rsvd0[2];
			u32 rsvd1     : 31;
			u32 ifoe_o    : 1; /* <o bit of ifoe */
			u32 rsvd2;
		} bs;
		u32 value[4];
	} forth_16B;                       /* <fourth 16B */
};

/* standard 128B WQE structure */
struct cqm_linkwqe_128B {
	union cqm_linkwqe_first64B first64B;    /* <first 64B of standard 128B WQE */
	struct cqm_linkwqe_second64B second64B; /* <back 64B of standard 128B WQE */
};

/* AEQ type definition */
enum cqm_aeq_event_type {
	CQM_AEQ_BASE_T_FC = 48,     /* <FC consists of 8 events:48~55 */
	CQM_AEQ_MAX_T_FC = 56
};

/* service registration template */
struct service_register_template {
	u32 service_type;           /* <service type */
	u32 srq_ctx_size;           /* <SRQ context size */
	u32 scq_ctx_size;           /* <SCQ context size */
	void *service_handle;
	u8 (*aeq_level_callback)(void *service_handle, u8 event_type, u8 *val);
	void (*aeq_callback)(void *service_handle, u8 event_type, u8 *val);
};

/* object operation type definition */
enum cqm_object_type {
	CQM_OBJECT_ROOT_CTX = 0, /* <0:root context, which is compatible with root CTX management */
	CQM_OBJECT_SERVICE_CTX,  /* <1:QPC, connection management object */
	CQM_OBJECT_NONRDMA_EMBEDDED_RQ = 10, /* <10:RQ of non-RDMA services, managed by LINKWQE */
	CQM_OBJECT_NONRDMA_EMBEDDED_SQ,     /* <11:SQ of non-RDMA services, managed by LINKWQE */
	/* <12:SRQ of non-RDMA services, managed by MTT, but the CQM  needs to apply for MTT. */
	CQM_OBJECT_NONRDMA_SRQ,
	/* <13:Embedded CQ for non-RDMA services, managed by LINKWQE */
	CQM_OBJECT_NONRDMA_EMBEDDED_CQ,
	CQM_OBJECT_NONRDMA_SCQ, /* <14:SCQ of non-RDMA services, managed by LINKWQE  */
};

/* return value of the failure to apply for the BITMAP table */
#define CQM_INDEX_INVALID     (~(0U))

/* doorbell mode selected by the current Q, hardware doorbell */
#define CQM_HARDWARE_DOORBELL 1

/* single-node structure of the CQM buffer */
struct cqm_buf_list {
	void *va;                 /* <virtual address */
	dma_addr_t pa;            /* <physical address */
	u32 refcount; /* <reference count of the buf, which is used for internal buf management. */
};

/* common management structure of the CQM buffer */
struct cqm_buf {
	struct cqm_buf_list *buf_list;  /* <buffer list */
	/* <map the discrete buffer list to a group of consecutive addresses */
	struct cqm_buf_list direct;
	u32 page_number;        /* <buf_number in quantity of page_number=2^n */
	u32 buf_number;         /* <number of buf_list nodes */
	u32 buf_size;           /* <PAGE_SIZE in quantity of buf_size=2^n */
};

/* CQM object structure, which can be considered
 * as the base class abstracted from all queues/CTX.
 */
struct cqm_object {
	u32 service_type;       /* <service type */
	u32 object_type;        /* <object type, such as context, queue, mpt, and mtt, etc */
	u32 object_size;        /* <object Size, for queue/CTX/MPT, the unit is Byte*/
	atomic_t refcount;      /* <reference counting */
	struct completion free; /* <release completed quantity */
	void *cqm_handle;       /* <cqm_handle */
};

/* structure of the QPC and MPT objects of the CQM */
struct cqm_qpc_mpt {
	struct cqm_object object;
	u32 xid;
	dma_addr_t paddr; /* <physical address of the QPC/MTT memory */
	void *priv;       /* <private information about the object of the service driver. */
	u8 *vaddr;        /* <virtual address of the QPC/MTT memory */
};

/* queue header structure */
struct cqm_queue_header {
	u64 doorbell_record;    /* <SQ/RQ DB content */
	u64 ci_record;          /* <CQ DB content */
	u64 rsv1;
	u64 rsv2;
};

/* queue management structure: for queues of non-RDMA services, embedded queues
 * are managed by LinkWQE, SRQ and SCQ are managed by MTT, but MTT needs to be
 * applied by CQM; the queue of the RDMA service is managed by the MTT.
 */
struct cqm_queue {
	struct cqm_object object;       /* <object base class */
	/* <The embedded queue and QP do not have indexes, but the SRQ and SCQ do. */
	u32 index;
	/* <private information about the object of the service driver */
	void *priv;
	/* <doorbell type selected by the current queue. HW/SW are used for the roce QP. */
	u32 current_q_doorbell;
	u32 current_q_room;
	struct cqm_buf q_room_buf_1;    /* <nonrdma:only q_room_buf_1 can be set to q_room_buf */
	struct cqm_buf q_room_buf_2; /* <The CQ of RDMA reallocates the size of the queue room. */
	struct cqm_queue_header *q_header_vaddr; /* <queue header virtual address */
	dma_addr_t q_header_paddr;                   /* <physical address of the queue header */
	u8 *q_ctx_vaddr;	                     /* <CTX virtual addresses of SRQ and SCQ */
	dma_addr_t q_ctx_paddr;                      /* <CTX physical addresses of SRQ and SCQ */
	u32 valid_wqe_num;             /* <number of valid WQEs that are successfully created */
	u8 *tail_container;                          /* <tail pointer of the SRQ container */
	u8 *head_container;                          /* <head pointer of SRQ container */
	/* <Determine the connection mode during queue creation, such as link and ring. */
	u8 queue_link_mode;
};

struct cqm_qpc_layout_table_node {
	u32 type;
	u32 size;
	u32 offset;
	struct cqm_object *object;
};

struct cqm_qpc_mpt_info {
	struct cqm_qpc_mpt common;
	/* Different service has different QPC.
	 * The large QPC/mpt will occupy some continuous indexes in bitmap.
	 */
	u32 index_count;
	struct cqm_qpc_layout_table_node qpc_layout_table[CQM_QPC_LAYOUT_TABLE_SIZE];
};

struct cqm_nonrdma_qinfo {
	struct cqm_queue common;
	u32 wqe_size;
	/* Number of WQEs in each buffer (excluding link WQEs)
	 * For SRQ, the value is the number of WQEs contained in a container.
	 */
	u32 wqe_per_buf;
	u32 q_ctx_size;
	/* When different services use CTXs of different sizes,
	 * a large CTX occupies multiple consecutive indexes in the bitmap.
	 */
	u32 index_count;
	/* add for srq */
	u32 container_size;
};

/* sending command structure */
struct cqm_cmd_buf {
	void *buf;
	dma_addr_t dma;
	u16 size;
};

struct cqm_queue *cqm3_object_fc_srq_create(void *ex_handle, u32 service_type,
					    enum cqm_object_type object_type,
					    u32 wqe_number, u32 wqe_size,
					    void *object_priv);
struct cqm_qpc_mpt *cqm3_object_qpc_mpt_create(void *ex_handle, u32 service_type,
					       enum cqm_object_type object_type,
					       u32 object_size, void *object_priv,
					       u32 index);
struct cqm_queue *cqm3_object_nonrdma_queue_create(void *ex_handle, u32 service_type,
						   enum cqm_object_type object_type,
						   u32 wqe_number, u32 wqe_size,
						   void *object_priv);
void cqm3_object_delete(struct cqm_object *object);
struct cqm_object *cqm3_object_get(void *ex_handle, enum cqm_object_type object_type,
				   u32 index, bool bh);
void cqm3_object_put(struct cqm_object *object);

s32 cqm3_ring_hardware_db_fc(void *ex_handle, u32 service_type, u8 db_count,
			     u8 pagenum, u64 db);
s32 cqm_ring_direct_wqe_db(void *ex_handle, u32 service_type, u8 db_count, void *direct_wqe);
s32 cqm_ring_direct_wqe_db_fc(void *ex_handle, u32 service_type, void *direct_wqe);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* SPFC_CQM_OBJECT_H */
