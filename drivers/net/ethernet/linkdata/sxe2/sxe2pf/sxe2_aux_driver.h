/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_aux_driver.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_AUX_DRIVER_H__
#define __SXE2_AUX_DRIVER_H__

#include "sxe2_drv_aux.h"

#define SXE2_RDMA_NAME "roce"

struct sxe2_adapter;
struct sxe2_rdma_mac_entry {
	struct list_head list_entry;
	u8 mac_addr[ETH_ALEN];
};

struct sxe2_rdma_aux_context {
	struct aux_core_dev_info cdev_info;
	int aux_idx;

	/* in order to protect the data */
	struct mutex adev_mutex;
	bool init;
};

u8 sxe2_rdma_aux_get_qset_tc(struct sxe2_adapter *adapter,
			     struct aux_rdma_qset_params *qset);

struct sxe2_auxiliary_drv *
sxe2_rdma_aux_drv_get(struct aux_core_dev_info *cdev_info);

int sxe2_rdma_aux_init(struct sxe2_adapter *adapter);

void sxe2_rdma_aux_deinit(struct sxe2_adapter *adapter);
int sxe2_rdma_aux_add(struct sxe2_adapter *adapter);

void sxe2_rdma_aux_delete(struct aux_core_dev_info *cdev_info);

s32 sxe2_rdma_aux_rebuild(struct sxe2_adapter *adapter);

void sxe2_rdma_aux_send_reset_event(struct sxe2_adapter *adapter);

int sxe2_rdma_aux_send_mtu_changed_event(struct sxe2_adapter *adapter);

int sxe2_rdma_aux_send_vf_reset_event(struct sxe2_adapter *adapter, u16 vf_id);

int sxe2_rdma_aux_send_aeq_overflow_event(struct sxe2_adapter *adapter);

void sxe2_aux_aeq_overflow_handler(struct sxe2_adapter *adapter);

int sxe2_rdma_msg_send(struct sxe2_adapter *adapter,
		       enum sxe2_drv_cmd_opcode opcode, u8 *msg, u16 len,
		       u8 *recv_msg, u16 recv_len);
int sxe2_rdma_aux_send_failover_event(struct sxe2_adapter *adapter);

int sxe2_rdma_aux_send_tc_change_event(struct sxe2_adapter *adapter);

#endif
