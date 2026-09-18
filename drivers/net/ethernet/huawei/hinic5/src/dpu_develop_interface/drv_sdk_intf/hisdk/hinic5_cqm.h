/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_cqm.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : CQM (Context Queue Management) interface definitions
 */

#ifndef HINIC5_CQM_H
#define HINIC5_CQM_H

#include <linux/types.h>
#include <linux/completion.h>

#include "hinic5_crm.h"
#include "hinic5_cqm_adpt.h"
#include "hinic5_vram_api.h"

#define CQM_SUCCESS                     0       /**< Success result code */
#define CQM_FAIL                        (-1)    /**< Failure result code */
#define CQM_CONTINUE                    1       /**< Continue result code */

#define CQM_WQE_WF_NORMAL               0       /**< Normal WQE Format */
#define CQM_WQE_WF_LINK                 1       /**< Link WQE format */

#define CQM_QUEUE_LINK_MODE             0       /**< Link-based queue mode */
#define CQM_QUEUE_RING_MODE             1       /**< RING-based queue mode */
#define CQM_QUEUE_TOE_SRQ_LINK_MODE     2       /**< SRQ queue mode */
#define CQM_QUEUE_RDMA_QUEUE_MODE       3       /**< RDMA queue mode */

/**
 * @brief Link WQE common structure
 */
typedef struct tag_cqm_linkwqe {
	u32 rsv1 : 14;              /**< Reserved */
	u32 wf : 1;                 /**< WQE format */
	u32 rsv2 : 14;              /**< Reserved */
	u32 ctrlsl : 2;             /**< Length of the control segment */
	u32 o : 1;                  /**< Owner bit */

	u32 rsv3 : 31;              /**< Reserved */
	u32 lp : 1;                 /**< Loop Back valid */

	u32 next_page_gpa_h;        /**< Record the high 32 bits of the physical address of the next page, for chip use */
	u32 next_page_gpa_l;        /**< Record the low 32 bits of the physical address of the next page, for chip use */

	u32 next_buffer_addr_h;     /**< Record the high 32 bits of the virtual address of the next page, for driver use */
	u32 next_buffer_addr_l;     /**< Record the low 32 bits of the virtual address of the next page, for driver use */
} cqm_linkwqe_s;

/**
 * @brief SRQ Link WQE structure
 * @note  wqe size must not exceed the normal RQE size
 */
typedef struct tag_cqm_srq_linkwqe {
	cqm_linkwqe_s linkwqe;      /**< Link WQE common data */
	u32 current_buffer_gpa_h;   /**< Record the high 32 bits of the physical address of the current page, used when driver releases container and unmaps */
	u32 current_buffer_gpa_l;   /**< Record the low 32 bits of the physical address of the current page, used when driver releases container and unmaps */
	u32 current_buffer_addr_h;  /**< Record the high 32 bits of the virtual address of the current page, used when driver releases container */
	u32 current_buffer_addr_l;  /**< Record the low 32 bits of the virtual address of the current page, used when driver releases container */

	u32 fast_link_page_addr_h;  /**< Record the high 32 bits of the virtual address of the fastlink page where the container address is located, used when driver releases fastlink */
	u32 fast_link_page_addr_l;  /**< Record the low 32 bits of the virtual address of the fastlink page where the container address is located, used when driver releases fastlink */

	u32 fixed_next_buffer_addr_h;  /**< Record the high 32 bits of the virtual address of the next container, used for driver resource release, driver cannot modify */
	u32 fixed_next_buffer_addr_l;  /**< Record the low 32 bits of the virtual address of the next container, used for driver resource release, driver cannot modify */
} cqm_srq_linkwqe_s;

/**
 * @brief First 64B of standard 128B WQE
 */
typedef union tag_cqm_linkwqe_first64B {
	cqm_linkwqe_s basic_linkwqe;        /**< Link WQE common data */
	cqm_srq_linkwqe_s toe_srq_linkwqe;  /**< srq linkwqe struct */
	u32 value[16];                      /**< Reserved field */
} cqm_linkwqe_first64B_s;

/**
 * @brief Last 64B of standard 128B WQE
 */
typedef struct tag_cqm_linkwqe_second64B {
	u32 rsvd0[4];               /**< First 16B, Reserved */
	u32 rsvd1[4];               /**< Second 16B, Reserved */

	union {
	struct {
		u32 rsvd0[3];       /**< Reserved */
		u32 rsvd1 : 29;     /**< Reserved */
		u32 toe_o : 1;      /**< TOE owner bit */
		u32 resvd2 : 2;     /**< Reserved */
	} bs;
	u32 value[4];
	} third_16B;                /**< Third 16B */

	union {
	struct {
		u32 rsvd0[2];       /**< Reserved */
		u32 rsvd1 : 31;     /**< Reserved */
		u32 ifoe_o : 1;     /**< IFoE onwer bit */
		u32 rsvd2;          /**< Reserved */
	} bs;
	u32 value[4];
	} forth_16B;                /**< Fourth 16B */
} cqm_linkwqe_second64B_s;

/**
 * @brief Standard 128B WQE structure
 */
typedef struct tag_cqm_linkwqe_128B {
	cqm_linkwqe_first64B_s  first64B;   /**< First 64B of standard 128B WQE */
	cqm_linkwqe_second64B_s second64B;  /**< Last 64B of standard 128B WQE */
} cqm_linkwqe_128B_s;

/**
 * @brief AEQ type definition
 */
typedef enum {
	CQM_AEQ_BASE_T_NIC = 0,      /**< NIC has 15 events: 0~14 */
	CQM_AEQ_BASE_T_DMMU = 15,    /**< DMMU has 1 event: 15 */
	CQM_AEQ_BASE_T_ROCE = 16,    /**< ROCE has 32 events: 16~47 */
	CQM_AEQ_BASE_T_FC = 48,      /**< FC has 8 events: 48~55 */
	CQM_AEQ_BASE_T_IOE = 56,     /**< IOE has 8 events: 56~63 */
	CQM_AEQ_BASE_T_TOE = 64,     /**< TOE has 16 events: 64~79 */
	CQM_AEQ_BASE_T_UB = 80,      /**< UB has 16 events: 80~95 */
	CQM_AEQ_BASE_T_VBS = 96,     /**< VBS has 16 events: 96~111 */
	CQM_AEQ_BASE_T_IPSEC = 112,  /**< IPSEC has 16 events: 112~127 */
	CQM_AEQ_BASE_T_MAX = 128     /**< Maximum 128 event types defined */
} cqm_aeq_event_type_e;

/**
 * @brief CQM service extension description
 */
typedef struct tag_service_register_template {
	u32 service_type;      /**< Service type */
	u32 srq_ctx_size;      /**< srq context size */
	u32 scq_ctx_size;      /**< scq context size */
	void *service_handle;  /**< Pointer passed to service driver during ceq/aeq callback */
	void (*shared_cq_ceq_callback)(void *service_handle, u32 cqn, void *cq_priv);        /**< ceq callback: shared cq */
	void (*embedded_cq_ceq_callback)(void *service_handle, u32 xid, void *qpc_priv);     /**< ceq callback: embedded cq */
	void (*no_cq_ceq_callback)(void *service_handle, u32 xid, u32 qid, void *qpc_priv);  /**< ceq callback: no cq */
	u8 (*aeq_level_callback)(void *service_handle, u8 event_type, u8 *val);              /**< aeq level callback */
	void (*aeq_callback)(void *service_handle, u8 event_type, u8 *val);                  /**< aeq callback */
} service_register_template_s;

/**
 * @brief CQM object type
 */
typedef enum cqm_object_type {
	CQM_OBJECT_ROOT_CTX = 0,              /**< Root context. Reserved for future root ctx management compatibility */
	CQM_OBJECT_SERVICE_CTX,               /**< QPC, Service context, connection management object */
	CQM_OBJECT_MPT,                       /**< RDMA Memory Protection Table */

	CQM_OBJECT_NONRDMA_EMBEDDED_RQ = 10,  /**< RQ for non-RDMA service, managed by LINKWQE */
	CQM_OBJECT_NONRDMA_EMBEDDED_SQ,       /**< SQ for non-RDMA service, managed by LINKWQE */
	CQM_OBJECT_NONRDMA_SRQ,               /**< SRQ for non-RDMA service, managed by MTT, but CQM applies for MTT itself */
	CQM_OBJECT_NONRDMA_EMBEDDED_CQ,       /**< Embedded CQ for non-RDMA service, managed by LINKWQE */
	CQM_OBJECT_NONRDMA_SCQ,               /**< SCQ for non-RDMA service, managed by LINKWQE */

	CQM_OBJECT_RESV = 20,                 /**< Reserved */

	CQM_OBJECT_RDMA_QP = 30,              /**< RDMA Queue Pair */
	CQM_OBJECT_RDMA_SRQ,                  /**< RDMA Shared Receive Queue */
	CQM_OBJECT_RDMA_SCQ,                  /**< RDMA Shared Completion Queue */

	CQM_OBJECT_MTT = 50,                  /**< RDMA Memory Translation Table */
	CQM_OBJECT_RDMARC,                    /**< RDMA Reliable Connection */
} cqm_object_type_e;

/**
 * @brief Failure return value for BITMAP table allocation
 */
#define CQM_INDEX_INVALID ~(0U)

/**
 * @brief Definition of new field compatible with default XID allocation rule for XID=0xFFFFFFFF, macro named as low 3-bit comparison bits
 */
#define CQM_XID_LOW_BIT_1_1_1          0x0  /**< mask is 0x7 */
#define CQM_XID_LOW_BIT_0_1_1          0x4  /**< mask is 0x3 */
#define CQM_XID_LOW_BIT_0_1_0          0x5  /**< mask is 0x2 */
#define CQM_XID_LOW_BIT_0_0_1          0x6  /**< mask is 0x1 */
#define CQM_XID_LOW_BIT_NONE           0x7  /**< mask is 0x0 */
#define CQM_XID_SEARCH_RANGE           0x0
#define CQM_XID_SEARCH_ALL             0x1

#define CQM_XID_SEARCH_MODE_SHIFT      27
#define CQM_XID_LB_MODE_SHIFT          24
#define CQM_XID_LOW_BITS_SHIFT         21
#define CQM_XID_SEARCH_MODE_MASK       0x1
#define CQM_XID_LB_MODE_MASK           0x7
#define CQM_XID_LOW_BITS_MASK          0x7
#define CQM_DYNAMIC_XID_MASK           0x1FFFFF

/**
 * @brief Construct XID
 * @param[in]  search_mode Search mode
 * @param[in]  lb_mode Load balancing mode
 * @param[in]  xid_low Low two bits of XID
 *
 * @details search_mode: 0---Specify XID range search, range is [bp_start, bp_end); 1---Search entire dynamic area
 *          lb_mode:
 *          0--When dynamically allocating XID, select xid[2:0]=xid_low[2:0]
 *          4--When dynamically allocating XID, select xid[1:0]=xid_low[1:0]
 *          5--When dynamically allocating XID, select xid[0]=xid_low[0]
 *          6--When dynamically allocating XID, select xid[1]=xid_low[1]
 *          7--All xid can be applied
 *          xid_low: xid_low[2:0] for matching
 *
 * @return Returns the generated XID
 */
#define CQM_DYNAMIC_XID_MOD(search_mode, lb_mode, xid_low) \
	((((search_mode) & CQM_XID_SEARCH_MODE_MASK) << CQM_XID_SEARCH_MODE_SHIFT) | \
	(((lb_mode) & CQM_XID_LB_MODE_MASK) << CQM_XID_LB_MODE_SHIFT) | \
	(((xid_low) & CQM_XID_LOW_BITS_MASK) << CQM_XID_LOW_BITS_SHIFT) | CQM_DYNAMIC_XID_MASK)

#define CQM_RDMA_Q_ROOM_1 (1)           /**< To support ROCE Q buffer resize, the first Q buffer space */
#define CQM_RDMA_Q_ROOM_2 (2)           /**< To support ROCE Q buffer resize, the second Q buffer space */

#define CQM_HARDWARE_DOORBELL (1)       /**< Doorbell mode selected by current Q, hardware doorbell */
#define CQM_SOFTWARE_DOORBELL (2)       /**< Doorbell mode selected by current Q, software doorbell */
#define CQM_SECURE_BUFFER_EN  (1)       /**< Indicates Buffer is allocated from secure memory */

/**
 * @brief CQM buffer single node structure
 */
typedef struct tag_cqm_buf_list {
	void *va;                   /**< Virtual address */
	dma_addr_t pa;              /**< Physical address */
	u32 refcount;               /**< buf reference count, for internal buf management */
} cqm_buf_list_s;

/**
 * @brief CQM buffer single node structure, adapted for WIN
 */
struct huge_buf_addr {
	void *huge_buf_vaddr;       /**< Virtual address */
	dma_addr_t huge_buf_paddr;  /**< Physical address */
	u32 huge_buf_size;          /**< Single node buffer size */
};

/**
 * @brief CQM buffers management structure
 */
typedef struct tag_cqm_buf {
	cqm_buf_list_s *buf_list;   /**< buffer list */
	cqm_buf_list_s direct;      /**< Remap buf_list as contiguous virtual address, only va is valid for its members */
	u32 page_number;            /**< Total physical page count */
	u32 buf_number;             /**< buffer list length */
	u32 buf_size;               /**< buffer size */
#ifdef __WIN__
	struct huge_buf_addr *bufs_addr;    /**< buffer list */
	u32 huge_buf_number;                /**< buffer list node count */
#endif
	u32 secure_mem_flag;        /**< Secure memory flag, default is 0 (not using secure memory) */
	struct vram_buf_info buf_info;
} cqm_buf_s;

/**
 * @brief CQM object structure, abstraction of context/queue/table
 */
typedef struct tag_cqm_object {
	u32 service_type;           /**< Service type */
	u32 object_type;            /**< Object type, such as context, queue, mpt, mtt, etc. */
	u32 object_size;            /**< Object size,
					for non-RDMA queues, it is the queue depth;
					for queue/ctx/MPT, unit is Byte;
					for MTT/RDMARC, unit is entry count;
					for container, unit is container count */
	atomic_t refcount;          /**< Reference count */
	struct completion free;     /**< Free completion */
	void *cqm_handle;           /**< cqm_handle */
} cqm_object_s;

/**
 * @brief QPC/MPT object
 */
typedef struct tag_cqm_qpc_mpt {
	cqm_object_s object;        /**< Object base class */
	u32 xid;                    /**< XID.
					xid[20:0] < 1M, indicates statically allocated xid;
					xid[20:0] all 1s is dynamically allocated;
					xid[22:21] specifies low 2 bits;
					xid[24:23] is lb_mode;
					xid[25] is search_mode */
	dma_addr_t paddr;           /**< Physical address of QPC/MTT memory */
	void *priv;                 /**< Private information of this object for service driver */
	u8 *vaddr;                  /**< Virtual address of QPC/MTT memory */
} cqm_qpc_mpt_s;

/**
 * @brief queue header structure
 */
typedef struct tag_cqm_queue_header {
	u64 doorbell_record;        /**< SQ/RQ db content */
	u64 ci_record;              /**< CQ db content */
	u64 rsv1;                   /**< This area is a custom area for driver and microcode to exchange information */
	u64 rsv2;                   /**< This area is a custom area for driver and microcode to exchange information */
} cqm_queue_header_s;

/**
 * @brief Queue management structure
 * @details For non-RDMA service, embedded queues are managed by linkwqe, SRQ and SCQ are managed by MTT, MTT is applied by CQM;
 *          Queues for RDMA service are managed by MTT
 */
typedef struct tag_cqm_queue {
	cqm_object_s object;                 /**< Object base class */
	u32 index;                           /**< Embedded queue and QP have no index, SRQ and SCQ have */
	void *priv;                          /**< Private information of this object for service driver */
	u32 current_q_doorbell;              /**< Doorbell type selected by current queue, roce QP uses both HW/SW */
	u32 current_q_room;                  /**< roce: current valid room buf */
	cqm_buf_s q_room_buf_1;              /**< nonrdma: only q_room_buf_1 can be selected as q_room_buf */
	cqm_buf_s q_room_buf_2;              /**< RDMA CQ will reallocate queue room size */
	cqm_queue_header_s *q_header_vaddr;  /**< queue header virtual address */
	dma_addr_t q_header_paddr;           /**< queue header physical address */
	u8 *q_ctx_vaddr;                     /**< ctx virtual address of SRQ and SCQ */
	dma_addr_t q_ctx_paddr;              /**< ctx physical address of SRQ and SCQ */
	u32 valid_wqe_num;                   /**< Valid wqe count successfully created */
	u8 *tail_container;                  /**< Tail pointer of SRQ container */
	u8 *head_container;                  /**< Head pointer of SRQ container */
	u8 queue_link_mode;                  /**< Connection mode determined at queue creation: link, ring, etc. */
} cqm_queue_s;

/**
 * @brief MTT/RDMARC management structure
 */
typedef struct tag_cqm_mtt_rdmarc {
	cqm_object_s object;        /**< Object base class */
	u32 index_base;             /**< index_base */
	u32 index_number;           /**< index_number */
	u8 *vaddr;                  /**< buffer virtual address */
} cqm_mtt_rdmarc_s;

/**
 * @brief Send command structure
 */
typedef struct tag_cqm_cmd_buf {
	void *buf;                  /**< Command buf virtual address */
	dma_addr_t dma;             /**< Command buf physical address */
	u16 size;                   /**< Command buf size */
} cqm_cmd_buf_s;

/**
 * @brief Send ACK method definition
 */
typedef enum {
	CQM_CMD_ACK_TYPE_CMDQ = 0,       /**< ack written back to cmdq */
	CQM_CMD_ACK_TYPE_SHARE_CQN = 1,  /**< ack reported through root ctx's scq */
	CQM_CMD_ACK_TYPE_APP_CQN = 2     /**< ack reported through service's scq */
} cqm_cmd_ack_type_e;

/**
 * @brief CQM initialize
 * @param[in]  ex_handle        Device handle
 *
 * @return Whether successful
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 cqm5_init(void *ex_handle);

/**
 * @brief CQM deinitialize
 * @param[in]  ex_handle        Device handle
 */
void cqm5_uninit(void *ex_handle);

/**
 * @brief CQM initialize specified Fake VF
 * @param[in]  ex_handle        Device handle
 * @param[in]  vf_id            Function id to be initialized
 *
 * @return Whether successful
 *     @retval  0       success
 *     @retval -1       failure
 *     @retval -EINVAL  Invalid argument
 */
int cqm5_init_fake_vf(void *ex_handle, u32 vf_id);

/**
 * @brief Register service extension capability
 * @param[in]  ex_handle        Device handle
 * @param[in]  service_template Service extension description
 *
 * @return Whether successful
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 cqm5_service_register(void *ex_handle, service_register_template_s *service_template);

/**
 * @brief Unregister service extension capability
 * @param[in]  ex_handle        Device handle
 * @param[in]  service_type     Service type
 */
void cqm5_service_unregister(void *ex_handle, u32 service_type);

/**
 * @brief Declare the number of Fake VFs managed by the device
 * @param[in]  ex_handle        Device handle
 * @param[in]  fake_vf_num_cfg  Fake VF count, this value cannot exceed the maximum supported by the device
 *
 * @return Whether successful
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 cqm5_fake_vf_num_set(void *ex_handle, u16 fake_vf_num_cfg);

/**
 * @brief Create FC SRQ
 * @param[in]  ex_handle        Device handle
 * @param[in]  service_type     Service type
 * @param[in]  object_type      Object type
 * @param[in]  wqe_number       wqe count
 * @param[in]  wqe_size         wqe size
 * @param[in]  object_priv      Object private data pointer
 *
 * @details The number of valid wqe in the queue must satisfy the passed wqe count.
 *          Because linkwqe can only be filled at the page tail, the actual valid count exceeds the requirement,
 *          the service needs to be informed of the extra created count
 *
 * @return Queue structure pointer
 */
cqm_queue_s *cqm5_object_fc_srq_create(void *ex_handle, u32 service_type,
					cqm_object_type_e object_type,
					u32 wqe_number, u32 wqe_size,
					void *object_priv);

/**
 * @brief Create RQ
 * @param[in]  ex_handle        Device handle
 * @param[in]  service_type     Service type
 * @param[in]  object_type      Object type
 * @param[in]  init_rq_num      container count
 * @param[in]  container_size   container size
 * @param[in]  wqe_size         wqe size
 * @param[in]  object_priv      Object private data pointer
 *
 * @details RQ queue creation when using SRQ
 *
 * @return Queue structure pointer
 */
cqm_queue_s *cqm5_object_recv_queue_create(void *ex_handle, u32 service_type,
						cqm_object_type_e object_type,
						u32 init_rq_num, u32 container_size,
						u32 wqe_size, void *object_priv);

/**
 * @brief Create TOE SRQ
 * @param[in]  ex_handle        Device handle
 * @param[in]  service_type     Service type
 * @param[in]  object_type      Object type
 * @param[in]  container_number container count
 * @param[in]  container_size   container size
 * @param[in]  wqe_size         wqe size
 *
 * @return Queue structure pointer
 */
cqm_queue_s *cqm5_object_share_recv_queue_create(void *ex_handle, u32 service_type,
							cqm_object_type_e object_type,
							u32 container_number,
							u32 container_size, u32 wqe_size);

/**
 * @brief Create QPC/MPT
 * @param[in]  ex_handle        Device handle
 * @param[in]  service_type     Service type
 * @param[in]  object_type      Object type
 * @param[in]  object_size      Object size, unit Byte
 * @param[in]  object_priv      Object private data pointer
 * @param[in]  index            Apply for reserved qpn based on this value, fill CQM_INDEX_INVALID for auto allocation
 * @param[in]  bitmap_start     Start index for range xid allocation
 * @param[in]  bitmap_end       End index for range xid allocation
 *
 * @attention This interface may sleep
 *
 * @return QPC/MPT structure pointer
 */
cqm_qpc_mpt_s *cqm5_object_qpc_mpt_create(void *ex_handle, u32 service_type,
						cqm_object_type_e object_type,
						u32 object_size, void *object_priv,
						u32 index, u32 bitmap_start, u32 bitmap_end);

/**
 * @brief Create queue for non-RDMA service
 * @param[in]  ex_handle        Device handle
 * @param[in]  service_type     Service type
 * @param[in]  object_type      Object type
 * @param[in]  wqe_number       Number of wqe including link wqe
 * @param[in]  wqe_size         Fixed length, size is 2^n
 * @param[in]  object_priv      Object private data pointer
 *
 * @attention This interface may sleep
 *
 * @return Queue structure pointer
 */
cqm_queue_s *cqm5_object_nonrdma_queue_create(void *ex_handle, u32 service_type,
						cqm_object_type_e object_type,
						u32 wqe_number, u32 wqe_size,
						void *object_priv);

/**
 * @brief Create queue for RDMA service
 * @param[in]  ex_handle        Device handle
 * @param[in]  service_type     Service type
 * @param[in]  object_type      Object type
 * @param[in]  object_size      Object size
 * @param[in]  object_priv      Object private data pointer
 * @param[in]  room_header_alloc Whether to allocate queue room and header space
 * @param[in]  xid              Apply for reserved qpn based on this value, fill CQM_INDEX_INVALID for auto allocation
 * @param[in]  bitmap_start     Start index for range xid allocation
 * @param[in]  bitmap_end       End index for range xid allocation
 *
 * @attention This interface may sleep
 *
 * @return Queue structure pointer
 */
cqm_queue_s *cqm5_object_rdma_queue_create(void *ex_handle, u32 service_type,
						cqm_object_type_e object_type,
						u32 object_size, void *object_priv,
						bool room_header_alloc, u32 xid,
						u32 bitmap_start, u32 bitmap_end);

/**
 * @brief Create MTT/RDMARC for RDMA service
 * @param[in]  ex_handle        Device handle
 * @param[in]  service_type     Service type
 * @param[in]  object_type      Object type
 * @param[in]  index_base       Start index number
 * @param[in]  index_number     index count
 *
 * @return MTT/RDMARC structure pointer
 */
cqm_mtt_rdmarc_s *cqm5_object_rdma_table_get(void *ex_handle, u32 service_type,
						cqm_object_type_e object_type,
						u32 index_base, u32 index_number);

/**
 * @brief Allocate a cmd buffer
 * @param[in]  ex_handle        Device handle
 *
 * @attention buffer size is fixed 2K, buffer content is not zeroed, service needs to zero it
 *
 * @return cmd buffer pointer
 */
cqm_cmd_buf_s *cqm5_cmd_alloc(void *ex_handle);

/**
 * @brief Free a cmd buffer
 * @param[in]  ex_handle        Device handle
 * @param[in]  cmd_buf          Pointer to the cmd buffer to be freed
 */
void cqm5_cmd_free(void *ex_handle, cqm_cmd_buf_s *cmd_buf);

/**
 * @brief Send cmd
 * @param[in]  ex_handle        Device handle
 * @param[in]  mod              Module
 * @param[in]  cmd              Command word
 * @param[in]  buf_in           Input command buffer
 * @param[out] buf_out          Output command buffer
 * @param[out] out_param        udata (user data) returned by command
 * @param[in]  timeout          Command timeout, unit ms
 * @param[in]  channel          Caller channel id
 *
 * @details Send a cmdq cmd in box mode
 *
 * @attention This interface will hang on completion, causing sleep
 *
 * @return Whether successful
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 cqm5_send_cmd_box(void *ex_handle, u8 mod, u8 cmd,
			cqm_cmd_buf_s *buf_in, cqm_cmd_buf_s *buf_out,
			u64 *out_param, u32 timeout, u16 channel);

/**
 * @brief Send cmd
 * @param[in]  ex_handle        Device handle
 * @param[in]  mod              Module
 * @param[in]  cmd              Command word
 * @param[in]  cos_id           CMDQ queue
 * @param[in]  buf_in           Input command buffer
 * @param[out] buf_out          Output command buffer
 * @param[out] out_param        udata (user data) returned by command
 * @param[in]  timeout          Command timeout, unit ms
 * @param[in]  channel          Caller channel id
 *
 * @details Specify CMDQ queue and send a cmdq cmd in box mode
 *
 * @attention This interface will hang on completion, causing sleep
 *
 * @return Whether successful
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 cqm5_lb_send_cmd_box(void *ex_handle, u8 mod, u8 cmd, u8 cos_id,
				cqm_cmd_buf_s *buf_in, cqm_cmd_buf_s *buf_out,
				u64 *out_param, u32 timeout, u16 channel);

/**
 * @brief Send cmd
 * @param[in]  ex_handle        Device handle
 * @param[in]  mod              Module
 * @param[in]  cmd              Command word
 * @param[in]  buf_in           Input command buffer
 * @param[out] out_param        udata (user data) returned by command
 * @param[in]  timeout          Command timeout, unit ms
 * @param[in]  channel          Caller channel id
 *
 * @details Send a cmdq cmd in imm mode
 *
 * @attention This interface will hang on completion, causing sleep
 *
 * @return Whether successful
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 cqm5_send_cmd_imm(void *ex_handle, u8 mod, u8 cmd,
			cqm_cmd_buf_s *buf_in,
			u64 *out_param, u32 timeout, u16 channel);

/**
 * @brief Allocate hardware doorbell and dwqe
 * @param[in]  ex_handle        Device handle
 * @param[out] db_addr          doorbell physical address
 * @param[out] dwqe_addr        dwqe physical address
 *
 * @details Allocate one page of hardware doorbell and dwqe with the same index, both are physical addresses, each function has at most 1K
 *
 * @return Whether successful
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 cqm5_db_addr_alloc(void *ex_handle, void __iomem **db_addr, void __iomem **dwqe_addr);

/**
 * @brief Free hardware doorbell and dwqe
 * @param[in]  ex_handle        Device handle
 * @param[in]  db_addr          doorbell physical address
 * @param[in]  dwqe_addr        dwqe physical address
 */
void cqm5_db_addr_free(void *ex_handle, const void __iomem *db_addr, void __iomem *dwqe_addr);

/**
 * @brief Get hardware doorbell virtual address
 * @param[in]  ex_handle        Device handle
 * @param[in]  service_type     Service type
 *
 * @return doorbell virtual address
 */

void *cqm5_get_db_addr(void *ex_handle, u32 service_type);

/**
 * @brief Get hardware doorbell physical address
 * @param[in]  ex_handle        Device handle
 * @param[out] addr             Pointer to save doorbell physical address
 * @param[in]  service_type     Service type
 *
 * @details Get hardware doorbell physical address
 *
 * @return doorbell address
 */
s32 cqm5_get_hardware_db_addr(void *ex_handle, u64 *addr, enum hinic5_service_type service_type);

/**
 * @brief Ring a hardware DB
 * @param[in]  ex_handle        Device handle
 * @param[in]  service_type     Service type
 * @param[in]  db_count         PI[7:0] in doorbell exceeding 64b
 * @param[in]  db               The content of hardware doorbell
 *
 * @return Whether successful
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 cqm5_ring_hardware_db(void *ex_handle, u32 service_type, u8 db_count, u64 db);

/**
 * @brief Ring a direct wqe hardware DB to chip
 * @param[in]  ex_handle        Device handle
 * @param[in]  service_type     Service type
 * @param[in]  db_count         The bit[7:0] of PI can't be store in 64-bit db
 * @param[in]  direct_wqe       The content of direct_wqe
 *
 * @return Whether successful
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 cqm5_ring_direct_wqe_db(void *ex_handle, u32 service_type, u8 db_count, void *direct_wqe);

/**
 * @brief Ring a software DB
 * @param[in]  ex_handle        Device handle
 * @param[in]  object           Object pointer
 * @param[in]  db_record        The content of software doorbell
 *
 * @return Whether successful
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 cqm5_ring_software_db(cqm_object_s *object, u64 db_record);

/**
 * @brief bloom filter increase reference count
 * @param[in]  ex_handle        Device handle
 * @param[in]  id               bloom filter id
 *
 * @details Sends API to set bit when going from 0 -> 1
 *
 * @attention This interface may sleep
 *
 * @return Whether successful
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 cqm5_bloomfilter_inc(void *ex_handle, u16 func_id, u64 id);

/**
 * @brief bloom filter decrease reference count
 * @param[in]  ex_handle        Device handle
 * @param[in]  id               bloom filter id
 *
 * @details Sends API to clear when decremented to 0
 *
 * @attention This interface may sleep
 *
 * @return Whether successful
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 cqm5_bloomfilter_dec(void *ex_handle, u16 func_id, u64 id);

/**
 * @brief Get the base address of SMF Timer spoke list
 * @param[in]  ex_handle        Device handle
 *
 * @return Virtual address
 */
void *cqm5_timer_base(void *ex_handle);

/**
 * @brief Clear SMF Timer spoke list
 * @param[in]  ex_handle        Device handle
 * @param[in]  function_id      function id
 */
void cqm5_function_timer_clear(void *ex_handle, u32 function_id);

/**
 * @brief Clear hash buffer
 * @param[in]  ex_handle        Device handle
 * @param[in]  global_funcid    function id
 */
void cqm5_function_hash_buf_clear(void *ex_handle, s32 global_funcid);

/**
 * @brief SRQ applies for new container, chain linking after creation
 * @param[in]  common           Queue structure pointer
 *
 * @return Whether successful
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 cqm5_object_share_recv_queue_add_container(cqm_queue_s *common);

/**
 * @brief SRQ applies for new container, no chain linking after creation, service completes chain linking
 * @param[in]  common           Queue structure pointer
 * @param[out] container_addr   Returned container address
 *
 * @return Whether successful
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 cqm5_object_srq_add_container_free(cqm_queue_s *common, u8 **container_addr);

/**
 * @brief Get object by index
 * @param[in]  ex_handle        Device handle
 * @param[in]  object_type      Object type
 * @param[in]  index            index supports qpn, mptn, scqn, srqn
 * @param[in]  bh               Whether to disable interrupt bottom half
 *
 * @return Object pointer
 */
cqm_object_s *cqm5_object_get(void *ex_handle, cqm_object_type_e object_type,
				u32 index, bool bh);

/**
 * @brief Release object
 * @param[in]  object           Object pointer
 */
void cqm5_object_put(cqm_object_s *object);

/**
 * @brief Delete object
 * @param[in]  object           Object pointer
 *
 * @details Delete the created object, this function will sleep waiting for all operations on this object to complete before returning
 *
 * @attention This interface may sleep
 */
void cqm5_object_delete(cqm_object_s *object);

/**
 * @brief Get the owning function ID of the object
 * @param[in]  object           Object pointer
 *
 * @return
 *      @retval >=0 function ID
 *      @retval -1 failure
 */
s32 cqm5_object_funcid(cqm_object_s *object);

/**
 * @brief Allocate new space for the object
 * @param[in]  object           Object pointer
 * @param[in]  object_size      New buffer size
 *
 * @details Currently only useful for roce service, adjust CQ buffer size, but cqn and cqc remain unchanged,
 *          allocate new buffer space, do not free old buffer space, current valid buffer is still old buffer
 *
 * @return Whether successful
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 cqm5_object_resize_alloc_new(cqm_object_s *object, u32 object_size);

/**
 * @brief Free the newly allocated buffer space for the object
 * @param[in]  object           Object pointer
 *
 * @details This function frees the newly allocated buffer space, used for service exception handling branch
 */
void cqm5_object_resize_free_new(cqm_object_s *object);

/**
 * @brief Free old buffer space for the object
 * @param[in]  object           Object pointer
 *
 * @details This function frees the old buffer and sets the current valid buffer to the new buffer
 */
void cqm5_object_resize_free_old(cqm_object_s *object);

/**
 * @brief Release container
 * @param[in]  object           Object pointer
 * @param[in]  container        Pointer to the container to be released
 *
 * @details Release container
 */
void cqm5_srq_used_rq_container_delete(cqm_object_s *object, u8 *container);

/**
 * @brief Get the physical address and virtual address at the specified offset of the object buffer
 * @param[in]  object           Object pointer
 * @param[in]  offset           For rdma table, offset is the absolute index number
 * @param[out] paddr            Only returns physical address for rdma table
 *
 * @details Only supports rdma table lookup, get the physical address and virtual address at the specified offset of the object buffer
 *
 * @return u8 * Virtual address at the specified offset of the buffer
 */
u8 *cqm5_object_offset_addr(cqm_object_s *object, u32 offset, dma_addr_t *paddr);

/**
 * @brief Create DTOE SRQ
 * @param[in]  ex_handle        Device handle
 * @param[in]  contex_size      Context size
 * @param[out] index_count      Number of applied index
 * @param[out] index            Start of applied index
 *
 * @return Whether successful
 *     @retval  0 success
 *     @retval -1 failure
 */
s32 cqm5_dtoe_share_recv_queue_create(void *ex_handle, u32 contex_size,
				      u32 *index_count, u32 *index);

/**
 * @brief Release DTOE SRQ bitmap
 * @param[in]  ex_handle        Device handle
 * @param[in]  index_count      Number of released index
 * @param[in]  index            Start of released index
 */
void cqm5_dtoe_free_srq_bitmap_index(void *ex_handle, u32 index_count, u32 index);

#endif /* HINIC5_CQM_H */
