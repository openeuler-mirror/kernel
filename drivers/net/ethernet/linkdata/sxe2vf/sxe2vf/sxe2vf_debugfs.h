/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_debugfs.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2VF_DEBUGFS_H__
#define __SXE2VF_DEBUGFS_H__

struct sxe2vf_debugfs_command {
	s8 string[50];
	void (*debugfs_cb)(struct sxe2vf_adapter *adapter);
};

void sxe2vf_debugfs_init(void);

void sxe2vf_debugfs_exit(void);

void sxe2vf_debugfs_create_common_file(struct sxe2vf_adapter *adapter);

void sxe2vf_debugfs_create_drv_mode_file(struct sxe2vf_adapter *adapter);

void sxe2vf_debugfs_vf_init(struct sxe2vf_adapter *adapter);

void sxe2vf_debugfs_vf_exit(struct sxe2vf_adapter *adapter);

void sxe2vf_debugfs_destroy_files(struct sxe2vf_adapter *adapter);

void sxe2vf_info_dump(struct sxe2vf_adapter *adapter);

void sxe2vf_vsi_dump(struct sxe2vf_adapter *adapter);

#endif
