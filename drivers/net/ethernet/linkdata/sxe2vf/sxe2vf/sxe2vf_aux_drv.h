/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_aux_drv.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2VF_AUX_DRV_H__
#define __SXE2VF_AUX_DRV_H__

#include "sxe2_drv_aux.h"
#include "sxe2_mbx_public.h"

#define MAX_RDMA_MSG_SIZE 4096
#define SXE2VF_RDMA_NAME  "roce"
struct sxe2vf_adapter;

enum sxe2vf_rdma_op_state {
	RDMA_OP_IDLE,
	RDMA_OP_WORKING,
	RDMA_OP_SUCCESS,
	RDMA_OP_FAILED,
};

struct sxe2vf_rdma_msg {
	struct list_head list;
	u8 opcode;
	u16 msglen;
	u8 msg[];
};

struct sxe2vf_rdma_mac_entry {
	struct list_head list_entry;
	u8 mac_addr[ETH_ALEN];
};

struct sxe2vf_aux_context {
	struct aux_core_dev_info cdev_info;
	struct sxe2vf_adapter *vfadapter;
	u32 num_msix;
	int aux_idx;
	struct delayed_work init_task;
	/* in order to protect the data */
	struct mutex adev_mutex;
	bool init;
};

void sxe2vf_aux_init_task(struct work_struct *work);
void sxe2vf_auxdrv_init(struct sxe2vf_adapter *adapter);
void sxe2vf_auxdrv_deinit(struct sxe2vf_adapter *adapter);

void sxe2vf_auxdrv_send_reset_event(struct sxe2vf_adapter *adapter);

int sxe2vf_rdma_aux_send_mtu_changed_event(struct sxe2vf_adapter *adapter);

#endif
