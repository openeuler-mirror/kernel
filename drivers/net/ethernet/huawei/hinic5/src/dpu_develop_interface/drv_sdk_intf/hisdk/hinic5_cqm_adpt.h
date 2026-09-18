/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_cqm_adpt.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : CQM adaptation definitions
 */

#ifndef HINIC5_CQM_ADPT_H
#define HINIC5_CQM_ADPT_H

#define cqm5_init	cqm5_init       /**< Initialize CQM */
#define cqm5_uninit	cqm5_uninit     /**< Deinitialize CQM */
#define cqm5_init_fake_vf	cqm5_init_fake_vf     /**< CQM initialize specified Fake VF */
#define cqm5_service_register	cqm5_service_register       /**< Register service */
#define cqm5_service_unregister	cqm5_service_unregister     /**< Unregister service */
#define cqm5_bloomfilter_dec	cqm5_bloomfilter_dec    /**< Decrease bloom filter count */
#define cqm5_bloomfilter_inc	cqm5_bloomfilter_inc    /**< Increase bloom filter count */
#define cqm5_cmd_alloc	cqm5_cmd_alloc              /**< Allocate command */
#define cqm5_get_hardware_db_addr cqm5_get_hardware_db_addr  /**< Get hardware database address */
#define cqm5_cmd_free	cqm5_cmd_free               /**< Free command */
#define cqm5_send_cmd_box	cqm5_send_cmd_box       /**< Send command box */
#define cqm5_lb_send_cmd_box	cqm5_lb_send_cmd_box    /**< Send load balancing command box */
#define cqm5_send_cmd_imm	cqm5_send_cmd_imm       /**< Send immediate command */
#define cqm5_db_addr_alloc	cqm5_db_addr_alloc      /**< Allocate database address */
#define cqm5_db_addr_free	cqm5_db_addr_free       /**< Free database address */
#define cqm5_ring_hardware_db	cqm5_ring_hardware_db       /**< Ring hardware database */
#define cqm5_ring_software_db	cqm5_ring_software_db       /**< Ring software database */
#define cqm5_object_fc_srq_create	cqm5_object_fc_srq_create       /**< Create FC SRQ object */
#define cqm5_object_share_recv_queue_create	cqm5_object_share_recv_queue_create     /**< Create shared receive queue object */
#define cqm5_object_share_recv_queue_add_container	cqm5_object_share_recv_queue_add_container  /**< Add container to shared receive queue */
#define cqm5_object_srq_add_container_free	cqm5_object_srq_add_container_free      /**< Free SRQ add container */
#define cqm5_object_recv_queue_create	cqm5_object_recv_queue_create   /**< Create receive queue object */
#define cqm5_object_qpc_mpt_create	cqm5_object_qpc_mpt_create      /**< Create QPC MPT object */
#define cqm5_object_nonrdma_queue_create	cqm5_object_nonrdma_queue_create    /**< Create non-RDMA queue object */
#define cqm5_object_rdma_queue_create	cqm5_object_rdma_queue_create       /**< Create RDMA queue object */
#define cqm5_object_rdma_table_get	cqm5_object_rdma_table_get      /**< Get RDMA table */
#define cqm5_object_delete	cqm5_object_delete          /**< Delete object */
#define cqm5_object_offset_addr	cqm5_object_offset_addr /**< Get offset address */
#define cqm5_object_get	cqm5_object_get         /**< Get object */
#define cqm5_object_put	cqm5_object_put         /**< Put object */
#define cqm5_object_funcid	cqm5_object_funcid  /**< Get function ID */
#define cqm5_object_resize_alloc_new	cqm5_object_resize_alloc_new        /**< Reallocate object with new size */
#define cqm5_object_resize_free_new	cqm5_object_resize_free_new         /**< Free object with new size */
#define cqm5_object_resize_free_old	cqm5_object_resize_free_old         /**< Free object with old size */
#define cqm5_function_timer_clear	cqm5_function_timer_clear           /**< Clear function timer */
#define cqm5_function_hash_buf_clear	cqm5_function_hash_buf_clear        /**< Clear function hash buffer */
#define cqm5_srq_used_rq_container_delete	cqm5_srq_used_rq_container_delete   /**< Delete used RQ container */
#define cqm5_timer_base cqm5_timer_base      /**< Timer base */
#define cqm5_dtoe_free_srq_bitmap_index cqm5_dtoe_free_srq_bitmap_index      /**< Free SRQ bitmap index */
#define cqm5_dtoe_share_recv_queue_create cqm5_dtoe_share_recv_queue_create  /**< Create shared receive queue */
#define cqm5_get_db_addr                    cqm5_get_db_addr             /**< Get database address */
#define cqm5_ring_direct_wqe_db             cqm5_ring_direct_wqe_db      /**< Ring direct WQE database */
#define cqm5_fake_vf_num_set                cqm5_fake_vf_num_set         /**< Set fake VF count */

#endif
