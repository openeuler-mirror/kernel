/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_debugfs.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_DEBUGFS_H__
#define __SXE2_DEBUGFS_H__

struct sxe2_debugfs_command {
	s8 string[50];
	void (*debugfs_cb)(struct sxe2_adapter *adapter);
};

void sxe2_debugfs_init(void);

void sxe2_debugfs_exit(void);

void sxe2_debugfs_create_common_file(struct sxe2_adapter *adapter);

void sxe2_debugfs_create_drv_mode_file(struct sxe2_adapter *adapter);

void sxe2_debugfs_pf_init(struct sxe2_adapter *adapter);

void sxe2_debugfs_pf_exit(struct sxe2_adapter *adapter);

void sxe2_debugfs_pf_init(struct sxe2_adapter *adapter);

void sxe2_etype_rx_rule_add(struct sxe2_adapter *adapter);

void sxe2_etype_rx_rule_del(struct sxe2_adapter *adapter);

#endif
