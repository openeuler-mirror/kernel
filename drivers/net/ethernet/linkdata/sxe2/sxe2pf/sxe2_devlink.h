/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_devlink.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_DEVLINK_H__
#define __SXE2_DEVLINK_H__

struct sxe2_adapter *sxe2_adapter_create(struct pci_dev *pdev);
void sxe2_adapter_free(void *devlink_ptr);
void sxe2_devlink_register(struct sxe2_adapter *adapter);
void sxe2_devlink_unregister(struct sxe2_adapter *adapter);

#ifdef ESWITCH_MODE_SET_NEED_TWO_PRAMS
int sxe2_eswitch_mode_set(struct devlink *devlink, u16 mode);
#else
int sxe2_eswitch_mode_set(struct devlink *devlink, u16 mode,
			  struct netlink_ext_ack *extack);
#endif

int sxe2_eswitch_mode_get(struct devlink *devlink, u16 *mode);

#endif
