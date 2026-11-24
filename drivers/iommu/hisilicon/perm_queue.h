/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: UMMU permission queue implement.
 */

#ifndef __UMMU_PERM_QUEUE_H__
#define __UMMU_PERM_QUEUE_H__
#include "ummu.h"

#define UMMU_INVALID_QID ((u32)-1)

#define PCMDQ_ENT_BYTES 16U
#define PCPLQ_ENT_BYTES 4U

int ummu_device_init_permqs(struct ummu_device *ummu);
void ummu_device_uninit_permqs(struct ummu_device *ummu);
int ummu_device_init_permq_ctrl_page(struct ummu_device *ummu);
int ummu_get_permq_resource(struct ummu_device *ummu, u32 qid,
			    struct queue_args *queue);
void ummu_release_permq_resource(struct ummu_domain *domain);
int ummu_domain_config_permq(struct ummu_domain *domain);
void ummu_device_set_permq_ctxtbl(struct ummu_device *ummu);
int ummu_get_tid_res(struct tid_args *args);

#endif /* __UMMU_PERM_QUEUE_H__ */
