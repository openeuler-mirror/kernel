/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_cqm_object.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_CQM_OBJECT_H
#define HINIC5_CQM_OBJECT_H

#include "comm_defs.h"
#include "hinic5_hinic5_cqm.h"

#define HINIC5_CQM_LINKWQE_128B 128
#define HINIC5_CQM_MOD_TOE	HINIC5_MOD_TOE
#define HINIC5_CQM_MOD_HINIC5_CQM	HINIC5_MOD_HINIC5_CQM

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

/**
 * @brief: create FC SRQ.
 * @details: The number of valid WQEs in the queue must meet the number of
 *	     transferred WQEs. Linkwqe can only be filled at the end of the
 *	     page. The actual number of valid links exceeds the requirement.
 *	     The service needs to be informed of the number of extra links to
 *	     be created.
 * @param ex_handle: device pointer that represents the PF
 * @param service_type: service type
 * @param object_type: object type
 * @param wqe_number: number of WQEs
 * @param wqe_size: wqe size
 * @param object_priv: pointer to object private information
 * @retval struct tag_hinic5_cqm_queue*: queue structure pointer
 * @date: 2019-5-4
 */
struct tag_hinic5_cqm_queue *hinic5_cqm_object_fc_srq_create(void *ex_handle, u32 service_type,
					       enum hinic5_cqm_object_type object_type,
					       u32 wqe_number, u32 wqe_size,
					       void *object_priv);

/**
 * @brief: create RQ.
 * @details: When SRQ is used, the RQ queue is created.
 * @param ex_handle: device pointer that represents the PF
 * @param service_type: service type
 * @param object_type: object type
 * @param init_rq_num: number of containers
 * @param container_size: container size
 * @param wqe_size: wqe size
 * @param object_priv: pointer to object private information
 * @retval struct tag_hinic5_cqm_queue*: queue structure pointer
 * @date: 2019-5-4
 */
struct tag_hinic5_cqm_queue *hinic5_cqm_object_recv_queue_create(void *ex_handle, u32 service_type,
						   enum hinic5_cqm_object_type object_type,
						   u32 init_rq_num, u32 container_size,
						   u32 wqe_size, void *object_priv);

/**
 * @brief: SRQ applies for a new container and is linked after the container
 *	   is created.
 * @details: SRQ applies for a new container and is linked after the container
 *	     is created.
 * @param common: queue structure pointer
 * @retval 0: success
 * @retval -1: fail
 * @date: 2019-5-4
 */
s32 hinic5_cqm_object_share_recv_queue_add_container(struct tag_hinic5_cqm_queue *common);

/**
 * @brief: SRQ applies for a new container. After the container is created,
 *	   no link is attached to the container. The service is attached to
 *	   the container.
 * @details: SRQ applies for a new container. After the container is created,
 *	     no link is attached to the container. The service is attached to
 *	     the container.
 * @param common: queue structure pointer
 * @param container_addr: returned container address
 * @retval 0: success
 * @retval -1: fail
 * @date: 2019-5-4
 */
s32 hinic5_cqm_object_srq_add_container_free(struct tag_hinic5_cqm_queue *common, u8 **container_addr);

/**
 * @brief: create SRQ for TOE services.
 * @details: create SRQ for TOE services.
 * @param ex_handle: device pointer that represents the PF
 * @param service_type: service type
 * @param object_type: object type
 * @param container_number: number of containers
 * @param container_size: container size
 * @param wqe_size: wqe size
 * @retval struct tag_hinic5_cqm_queue*: queue structure pointer
 * @date: 2019-5-4
 */
struct tag_hinic5_cqm_queue *hinic5_cqm_object_share_recv_queue_create(void *ex_handle,
							 u32 service_type,
							 enum hinic5_cqm_object_type object_type,
							 u32 container_number,
							 u32 container_size,
							 u32 wqe_size);

/**
 * @brief: create QPC and MPT.
 * @details: When QPC and MPT are created, the interface sleeps.
 * @param ex_handle: device pointer that represents the PF
 * @param service_type: service type
 * @param object_type: object type
 * @param object_size: object size, in bytes.
 * @param object_priv: private structure of the service layer.
 *		       The value can be NULL.
 * @param index: apply for reserved qpn based on the value. If automatic
 *		 allocation is required, fill HINIC5_CQM_INDEX_INVALID.
 * @param bitmap_start: start index of bitmap when range search.
 * @param bitmap_end: end index of bitmap when range search.
 * @retval struct tag_hinic5_cqm_qpc_mpt *: pointer to the QPC/MPT structure
 * @date: 2019-5-4
 */
struct tag_hinic5_cqm_qpc_mpt *hinic5_cqm_object_qpc_mpt_create(void *ex_handle, u32 service_type,
						  enum hinic5_cqm_object_type object_type,
						  u32 object_size, void *object_priv,
						  u32 index, u32 bitmap_start, u32 bitmap_end);

/**
 * @brief: create a queue for non-RDMA services.
 * @details: create a queue for non-RDMA services. The interface sleeps.
 * @param ex_handle: device pointer that represents the PF
 * @param service_type: service type
 * @param object_type: object type
 * @param wqe_number: number of Link WQEs
 * @param wqe_size: fixed length, size 2^n
 * @param object_priv: private structure of the service layer.
 *		       The value can be NULL.
 * @retval struct tag_hinic5_cqm_queue *: queue structure pointer
 * @date: 2019-5-4
 */
struct tag_hinic5_cqm_queue *hinic5_cqm_object_nonrdma_queue_create(void *ex_handle, u32 service_type,
						      enum hinic5_cqm_object_type object_type,
						      u32 wqe_number, u32 wqe_size,
						      void *object_priv);

/**
 * @brief: create a RDMA service queue.
 * @details: create a queue for the RDMA service. The interface sleeps.
 * @param ex_handle: device pointer that represents the PF
 * @param service_type: service type
 * @param object_type: object type
 * @param object_size: object size
 * @param object_priv: private structure of the service layer.
 *		       The value can be NULL.
 * @param room_header_alloc: whether to apply for the queue room and header
 *			     space
 * @param xid: apply for reserved qpn based on the value. If automatic
 *		 allocation is required, fill HINIC5_CQM_INDEX_INVALID.
 * @param bitmap_start: start index of bitmap when range search.
 * @param bitmap_end: end index of bitmap when range search.
 * @retval struct tag_hinic5_cqm_queue *: queue structure pointer
 * @date: 2019-5-4
 */
struct tag_hinic5_cqm_queue *hinic5_cqm_object_rdma_queue_create(void *ex_handle, u32 service_type,
						   enum hinic5_cqm_object_type object_type,
						   u32 object_size, void *object_priv,
						   bool room_header_alloc, u32 xid,
						   u32 bitmap_start, u32 bitmap_end);

/**
 * @brief: create the MTT and RDMARC of the RDMA service.
 * @details: create the MTT and RDMARC of the RDMA service.
 * @param ex_handle: device pointer that represents the PF
 * @param service_type: service type
 * @param object_type: object type
 * @param index_base: start index number
 * @param index_number: index number
 * @retval struct tag_hinic5_cqm_mtt_rdmarc *: pointer to the MTT/RDMARC structure
 * @date: 2019-5-4
 */
struct tag_hinic5_cqm_mtt_rdmarc *hinic5_cqm_object_rdma_table_get(void *ex_handle, u32 service_type,
						     enum hinic5_cqm_object_type object_type,
						     u32 index_base, u32 index_number);

/**
 * @brief: delete created objects.
 * @details: delete the created object. This function does not return until all
 *	     operations on the object are complete.
 * @param object: object pointer
 * @retval: void
 * @date: 2019-5-4
 */
void hinic5_cqm_object_delete(struct tag_hinic5_cqm_object *object);

/**
 * @brief: obtains the physical address and virtual address at the specified
 *	   offset of the object buffer.
 * @details: Only RDMA table query is supported to obtain the physical address
 *	     and virtual address at the specified offset of the object buffer.
 * @param object: object pointer
 * @param offset: for a rdma table, offset is the absolute index number.
 * @param paddr: The physical address is returned only for the rdma table.
 * @retval u8 *: buffer specify the virtual address at the offset
 * @date: 2019-5-4
 */
u8 *hinic5_cqm_object_offset_addr(struct tag_hinic5_cqm_object *object, u32 offset, dma_addr_t *paddr);

/**
 * @brief: obtain object according index.
 * @details: obtain object according index.
 * @param ex_handle: device pointer that represents the PF
 * @param object_type: object type
 * @param index: support qpn,mptn,scqn,srqn
 * @param bh: whether to disable the bottom half of the interrupt
 * @retval struct tag_hinic5_cqm_object *: object pointer
 * @date: 2019-5-4
 */
struct tag_hinic5_cqm_object *hinic5_cqm_object_get(void *ex_handle, enum hinic5_cqm_object_type object_type,
				      u32 index, bool bh);

/**
 * @brief: object reference counting release
 * @details: After the function hinic5_cqm_object_get is invoked, this API must be put.
 *	     Otherwise, the object cannot be released.
 * @param object: object pointer
 * @retval: void
 * @date: 2019-5-4
 */
void hinic5_cqm_object_put(struct tag_hinic5_cqm_object *object);

/**
 * @brief: obtain the ID of the function where the object resides.
 * @details: obtain the ID of the function where the object resides.
 * @param object: object pointer
 * @retval >=0: ID of function
 * @retval -1: fail
 * @date: 2020-4-15
 */
s32 hinic5_cqm_object_funcid(struct tag_hinic5_cqm_object *object);

/**
 * @brief: apply for a new space for an object.
 * @details: Currently, this parameter is valid only for the ROCE service.
 *	     The CQ buffer size is adjusted, but the CQN and CQC remain
 *	     unchanged. New buffer space is applied for, and the old buffer
 *	     space is not released. The current valid buffer is still the old
 *	     buffer.
 * @param object: object pointer
 * @param object_size: new buffer size
 * @retval 0: success
 * @retval -1: fail
 * @date: 2019-5-4
 */
s32 hinic5_cqm_object_resize_alloc_new(struct tag_hinic5_cqm_object *object, u32 object_size);

/**
 * @brief: release the newly applied buffer space for the object.
 * @details: This function is used to release the newly applied buffer space for
 *	     service exception handling.
 * @param object: object pointer
 * @retval: void
 * @date: 2019-5-4
 */
void hinic5_cqm_object_resize_free_new(struct tag_hinic5_cqm_object *object);

/**
 * @brief: release old buffer space for objects.
 * @details: This function releases the old buffer and sets the current valid
 *	     buffer to the new buffer.
 * @param object: object pointer
 * @retval: void
 * @date: 2019-5-4
 */
void hinic5_cqm_object_resize_free_old(struct tag_hinic5_cqm_object *object);

/**
 * @brief: release container.
 * @details: release container.
 * @param object: object pointer
 * @param container: container pointer to be released
 * @retval: void
 * @date: 2019-5-4
 */
void hinic5_cqm_srq_used_rq_container_delete(struct tag_hinic5_cqm_object *object, u8 *container);

void *hinic5_cqm_get_db_addr(void *ex_handle, u32 service_type);

s32 hinic5_cqm_ring_hardware_db_fc(void *ex_handle, u32 service_type, u8 db_count,
			    u8 pagenum, u64 db);

/**
 * @brief: provide the interface of knocking on doorbell.
 *	   The HINIC5_CQM converts the pri to cos.
 * @details: provide interface of knocking on doorbell for the HINIC5_CQM to convert
 *	     the pri to cos. The doorbell transferred by the service must be the
 *	     host sequence. This interface converts the network sequence.
 * @param ex_handle: device pointer that represents the PF
 * @param service_type: Each kernel-mode service is allocated a hardware
 *			doorbell page.
 * @param db_count: PI[7:0] beyond 64b in the doorbell
 * @param db: The doorbell content is organized by the service. If there is
 *	      endian conversion, the service needs to complete the conversion.
 * @retval 0: success
 * @retval -1: fail
 * @date: 2019-5-4
 */
s32 hinic5_cqm_ring_hardware_db_update_pri(void *ex_handle, u32 service_type,
				    u8 db_count, u64 db);

/**
 * @brief: knock on software doorbell.
 * @details: knock on software doorbell.
 * @param object: object pointer
 * @param db_record: software doorbell content. If there is big-endian
 *		     conversion, the service needs to complete the conversion.
 * @retval 0: success
 * @retval -1: fail
 * @date: 2019-5-4
 */
s32 hinic5_cqm_ring_software_db(struct tag_hinic5_cqm_object *object, u64 db_record);

/**
 * @brief: reference counting is added to the bloom filter ID.
 * @details: reference counting is added to the bloom filter ID. When the ID
 *	     changes from 0 to 1, the sending API is set to 1.
 *	     This interface sleeps.
 * @param ex_handle: device pointer that represents the PF
 * @param id: id
 * @retval 0: success
 * @retval -1: fail
 * @date: 2019-5-4
 */
void *hinic5_cqm_gid_base(void *ex_handle);

/**
 * @brief: obtain the base virtual address of the timer.
 * @details: obtain the base virtual address of the timer.
 * @param ex_handle: device pointer that represents the PF
 * @retval void *: base virtual address of the timer
 * @date: 2020-5-21
 */
void *hinic5_cqm_timer_base(void *ex_handle);

/**
 * @brief: clear timer buffer.
 * @details: clear the timer buffer based on the function ID. Function IDs start
 *	     from 0, and timer buffers are arranged by function ID.
 * @param ex_handle: device pointer that represents the PF
 * @param function_id: function id
 * @retval: void
 * @date: 2019-5-4
 */
void hinic5_cqm_function_timer_clear(void *ex_handle, u32 function_id);

/**
 * @brief: clear hash buffer.
 * @details: clear the hash buffer based on the function ID.
 * @param ex_handle: device pointer that represents the PF
 * @param global_funcid
 * @retval: void
 * @date: 2019-5-4
 */
void hinic5_cqm_function_hash_buf_clear(void *ex_handle, s32 global_funcid);

s32 hinic5_cqm_ring_direct_wqe_db(void *ex_handle, u32 service_type, u8 db_count,
			   void *direct_wqe);

/**
 * @brief: Knock direct wqe db for fc
 * @details: Knock direct wqe db for fc
 * @param ex_handle: device pointer that represents the PF
 * @param service_type: service type
 * @param direct_wqe: direct wqe to write
 * @retval: s32, 0 success, others failure
 */
s32 hinic5_cqm_ring_direct_wqe_db_fc(void *ex_handle, u32 service_type,
			      void *direct_wqe);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* HINIC5_CQM_OBJECT_H */
