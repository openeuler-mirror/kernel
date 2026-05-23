/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_hinic5_cqm_adpt.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_HINIC5_CQM_ADPT_H
#define HINIC5_HINIC5_CQM_ADPT_H

#define hinic5_cqm_init	hinic5_cqm3_init       /**< Initialize HINIC5_CQM */
#define hinic5_cqm_uninit	hinic5_cqm3_uninit     /**< Uninitialize HINIC5_CQM */
#define hinic5_cqm_init_fake_vf	hinic5_cqm3_init_fake_vf     /**< Initialize specified Fake VF for HINIC5_CQM */
#define hinic5_cqm_service_register	hinic5_cqm3_service_register       /**< Register service */
#define hinic5_cqm_service_unregister	hinic5_cqm3_service_unregister     /**< Unregister service */
#define hinic5_cqm_bloomfilter_dec	hinic5_cqm3_bloomfilter_dec    /**< Decrease bloom filter counter */
#define hinic5_cqm_bloomfilter_inc	hinic5_cqm3_bloomfilter_inc    /**< Increase bloom filter counter */
#define hinic5_cqm_cmd_alloc	hinic5_cqm3_cmd_alloc              /**< Allocate command */
#define hinic5_cqm_get_hardware_db_addr hinic5_cqm3_get_hardware_db_addr  /**< Get hardware database address */
#define hinic5_cqm_cmd_free	hinic5_cqm3_cmd_free               /**< Free command */
#define hinic5_cqm_send_cmd_box	hinic5_cqm3_send_cmd_box       /**< Send command box */
#define hinic5_cqm_lb_send_cmd_box	hinic5_cqm3_lb_send_cmd_box    /**< Send load balanced command box */
#define hinic5_cqm_send_cmd_imm	hinic5_cqm3_send_cmd_imm       /**< Send immediate command */
#define hinic5_cqm_db_addr_alloc	hinic5_cqm3_db_addr_alloc      /**< Allocate database address */
#define hinic5_cqm_db_addr_free	hinic5_cqm3_db_addr_free      /**< Free database address */
#define hinic5_cqm_ring_hardware_db	hinic5_cqm3_ring_hardware_db       /**< Ring hardware database */
#define hinic5_cqm_ring_software_db	hinic5_cqm3_ring_software_db       /**< Ring software database */
#define hinic5_cqm_object_fc_srq_create	hinic5_cqm3_object_fc_srq_create       /**< Create FC SRQ object */
#define hinic5_cqm_object_share_recv_queue_create	hinic5_cqm3_object_share_recv_queue_create     /**< Create shared receive queue object */
#define hinic5_cqm_object_share_recv_queue_add_container	hinic5_cqm3_object_share_recv_queue_add_container  /**< Add container to shared receive queue */
#define hinic5_cqm_object_srq_add_container_free	hinic5_cqm3_object_srq_add_container_free      /**< Free SRQ add container */
#define hinic5_cqm_object_recv_queue_create	hinic5_cqm3_object_recv_queue_create   /**< Create receive queue object */
#define hinic5_cqm_object_qpc_mpt_create	hinic5_cqm3_object_qpc_mpt_create      /**< Create QPC MPT object */
#define hinic5_cqm_object_nonrdma_queue_create	hinic5_cqm3_object_nonrdma_queue_create    /**< Create non-RDMA queue object */
#define hinic5_cqm_object_rdma_queue_create	hinic5_cqm3_object_rdma_queue_create       /**< Create RDMA queue object */
#define hinic5_cqm_object_rdma_table_get	hinic5_cqm3_object_rdma_table_get      /**< Get RDMA table */
#define hinic5_cqm_object_delete	hinic5_cqm3_object_delete          /**< Delete object */
#define hinic5_cqm_object_offset_addr	hinic5_cqm3_object_offset_addr /**< Get offset address */
#define hinic5_cqm_object_get	hinic5_cqm3_object_get         /**< Get object */
#define hinic5_cqm_object_put	hinic5_cqm3_object_put         /**< Put object */
#define hinic5_cqm_object_funcid	hinic5_cqm3_object_funcid  /**< Get function ID */
#define hinic5_cqm_object_resize_alloc_new	hinic5_cqm3_object_resize_alloc_new        /**< Reallocate object with new size */
#define hinic5_cqm_object_resize_free_new	hinic5_cqm3_object_resize_free_new         /**< Free object with new size */
#define hinic5_cqm_object_resize_free_old	hinic5_cqm3_object_resize_free_old         /**< Free object with old size */
#define hinic5_cqm_function_timer_clear	hinic5_cqm3_function_timer_clear           /**< Clear function timer */
#define hinic5_cqm_function_hash_buf_clear	hinic5_cqm3_function_hash_buf_clear        /**< Clear function hash buffer */
#define hinic5_cqm_srq_used_rq_container_delete	hinic5_cqm3_srq_used_rq_container_delete   /**< Delete used RQ container */
#define hinic5_cqm_timer_base hinic5_cqm3_timer_base      /**< Timer base */
#define hinic5_cqm_dtoe_free_srq_bitmap_index hinic5_cqm3_dtoe_free_srq_bitmap_index      /**< Free SRQ bitmap index */
#define hinic5_cqm_dtoe_share_recv_queue_create hinic5_cqm3_dtoe_share_recv_queue_create  /**< Create shared receive queue */
#define hinic5_cqm_get_db_addr                    hinic5_cqm3_get_db_addr             /**< Get database address */
#define hinic5_cqm_ring_direct_wqe_db             hinic5_cqm3_ring_direct_wqe_db      /**< Direct ring WQE database */
#define hinic5_cqm_fake_vf_num_set                hinic5_cqm3_fake_vf_num_set         /**< Set fake VF number */

#endif
