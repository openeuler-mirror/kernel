/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_host_cli.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_HOST_CLI_H__
#define __SXE2_HOST_CLI_H__

#include <linux/device.h>
#include <linux/pci.h>
#include <linux/cdev.h>

#include "sxe2.h"
#include "sxe2_cdev.h"

#define SXE2_CHRDEV_NAME "sxe2-cli"
#define SXE2_MAX_DEVICES_NUM BIT(MINORBITS)
#define SXE2_CHRDEV_CLASS_NAME SXE2_CHRDEV_NAME

s32 sxe2_cli_cdev_register(void);

void sxe2_cli_cdev_unregister(void);

s32 sxe2_cli_cdev_create(struct sxe2_adapter *adapter);

void sxe2_cli_cdev_delete(struct sxe2_adapter *adapter);

struct sxe2_cli_dev_mgr *sxe2_cdev_mgr_get(void);
#endif
