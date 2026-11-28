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

#define SXE2VF_DEBUGFS_ARG_MAX		4
#define SXE2VF_DEBUGFS_STR_MAX_LEN	32
#define SXE2_DEBUGFS_ONOFF_MAX_LEN	3
enum sxe2vf_debugfs_arg_type {
	SXE2VF_DEBUGFS_ARG_NUM,
	SXE2VF_DEBUGFS_ARG_STR,
	SXE2VF_DEBUGFS_ARG_ONOFF,
};

struct sxe2vf_debugfs_arg_val {
	long num;
	const char *str;
	bool on;
};

struct sxe2vf_debugfs_command_arg {
	s8 string[50];
	u32 argc;
	enum sxe2vf_debugfs_arg_type argt[SXE2VF_DEBUGFS_ARG_MAX];
	void (*debugfs_cb)(struct sxe2vf_adapter *adapter,
			   const struct sxe2vf_debugfs_arg_val *argv);
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
