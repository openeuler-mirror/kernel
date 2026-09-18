/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : cqm_define.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : CQM definitions header
 */

#ifndef CQM_DEFINE_H
#define CQM_DEFINE_H

#define cqm5_init                           cqm5_init
#define cqm5_uninit                         cqm5_uninit
#define cqm5_service_register               cqm5_service_register
#define cqm5_service_unregister             cqm5_service_unregister
#define cqm5_bloomfilter_dec                cqm5_bloomfilter_dec
#define cqm5_bloomfilter_inc                cqm5_bloomfilter_inc
#define cqm5_cmd_alloc                      cqm5_cmd_alloc
#define cqm5_get_hardware_db_addr           cqm5_get_hardware_db_addr
#define cqm5_cmd_free                       cqm5_cmd_free
#define cqm5_send_cmd_box                   cqm5_send_cmd_box
#define cqm5_lb_send_cmd_box                cqm5_lb_send_cmd_box
#define cqm5_send_cmd_imm                   cqm5_send_cmd_imm
#define cqm5_db_addr_alloc                  cqm5_db_addr_alloc
#define cqm5_db_addr_free                   cqm5_db_addr_free
#define cqm5_ring_hardware_db               cqm5_ring_hardware_db
#define cqm5_ring_software_db               cqm5_ring_software_db
#define cqm5_object_fc_srq_create           cqm5_object_fc_srq_create
#define cqm5_object_share_recv_queue_create cqm5_object_share_recv_queue_create
#define cqm5_object_share_recv_queue_add_container \
	cqm5_object_share_recv_queue_add_container
#define cqm5_object_srq_add_container_free  cqm5_object_srq_add_container_free
#define cqm5_object_recv_queue_create       cqm5_object_recv_queue_create
#define cqm5_object_qpc_mpt_create          cqm5_object_qpc_mpt_create
#define cqm5_object_nonrdma_queue_create    cqm5_object_nonrdma_queue_create
#define cqm5_object_rdma_queue_create       cqm5_object_rdma_queue_create
#define cqm5_object_rdma_table_get          cqm5_object_rdma_table_get
#define cqm5_object_delete                  cqm5_object_delete
#define cqm5_object_offset_addr             cqm5_object_offset_addr
#define cqm5_object_get                     cqm5_object_get
#define cqm5_object_put                     cqm5_object_put
#define cqm5_object_funcid                  cqm5_object_funcid
#define cqm5_object_resize_alloc_new        cqm5_object_resize_alloc_new
#define cqm5_object_resize_free_new         cqm5_object_resize_free_new
#define cqm5_object_resize_free_old         cqm5_object_resize_free_old
#define cqm5_function_timer_clear           cqm5_function_timer_clear
#define cqm5_function_hash_buf_clear        cqm5_function_hash_buf_clear
#define cqm5_srq_used_rq_container_delete   cqm5_srq_used_rq_container_delete
#define cqm5_timer_base                     cqm5_timer_base
#define cqm5_dtoe_free_srq_bitmap_index     cqm5_dtoe_free_srq_bitmap_index
#define cqm5_dtoe_share_recv_queue_create   cqm5_dtoe_share_recv_queue_create
#define cqm5_get_db_addr                    cqm5_get_db_addr
#define cqm5_ring_direct_wqe_db             cqm5_ring_direct_wqe_db
#define cqm5_fake_vf_num_set                cqm5_fake_vf_num_set

#endif
