/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_com_ioctl.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_COM_IOCTL_H__
#define __SXE2_COM_IOCTL_H__

#include "sxe2vf.h"

struct sxe2vf_ioctl_cmd_table {
	u32 opcode;
	s32 (*func)(struct sxe2vf_adapter *adapter, struct sxe2_obj *obj,
		    struct sxe2_drv_cmd_params *param);
};

s32 sxe2vf_com_cmd_send(void *adapter, struct sxe2_obj *obj,
			struct sxe2_drv_cmd_params *param);

static inline void *sxe2vf_com_req_data_copy_to_kernel(struct sxe2_drv_cmd_params *param)
{
	void *k_buffer = NULL;

	k_buffer = kmalloc(param->req_len, GFP_KERNEL);
	if (!k_buffer || copy_from_user(k_buffer, param->req_data, param->req_len))
		goto l_end;

l_end:
	return k_buffer;
};

#endif
