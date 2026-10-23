/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2026, NEBULARMATRIX */

#ifndef NBL_RDMA_MODULE_H
#define NBL_RDMA_MODULE_H

#include <linux/auxiliary_bus.h>
#include "nbl_compat.h"

int nbl_probe_v1(struct auxiliary_device *aux_dev,
		 const struct auxiliary_device_id *id);
int nbl_probe_v2(struct auxiliary_device *aux_dev,
		 const struct auxiliary_device_id *id);
void nbl_remove_v1(struct auxiliary_device *adev);
void nbl_remove_v2(struct auxiliary_device *adev);

int nbl_grc_probe_v1(struct auxiliary_device *aux_dev,
		     const struct auxiliary_device_id *id);
int nbl_grc_probe_v2(struct auxiliary_device *aux_dev,
		     const struct auxiliary_device_id *id);
void nbl_grc_remove_v1(struct auxiliary_device *adev);
void nbl_grc_remove_v2(struct auxiliary_device *adev);

void nbl_debugfs_init(void);
void nbl_debugfs_exit(void);
int nbl_df200_host_notify_init(void);
void nbl_df200_host_notify_deinit(void);
int nbl_reset_init(void);
void nbl_reset_deinit(void);

#endif /* NBL_RDMA_MODULE_H */
