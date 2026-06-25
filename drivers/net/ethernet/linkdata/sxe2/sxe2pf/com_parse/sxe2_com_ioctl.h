/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_com_ioctl.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_COM_IOCTL_H__
#define __SXE2_COM_IOCTL_H__

#include "sxe2.h"

struct sxe2_drv_cmd_params;

struct sxe2_ioctl_cmd_table {
	u32 opcode;
	s32 (*func)(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
		    struct sxe2_drv_cmd_params *param);
};

static inline void *sxe2_com_req_data_copy_to_kernel(struct sxe2_drv_cmd_params *param,
						     struct sxe2_obj *obj)
{
	void *k_buffer = NULL;

	if (param->req_len > 0) {
		k_buffer = kzalloc(param->req_len, GFP_KERNEL);
		if (!k_buffer)
			goto l_end;
		if (obj->func_type == SXE2_PF) {
			if (copy_from_user(k_buffer, param->req_data, param->req_len)) {
				kfree(k_buffer);
				return NULL;
			}
		} else {
			memcpy(k_buffer, param->req_data, param->req_len);
		}
	}

l_end:
	return k_buffer;
}

static inline s32 sxe2_com_resp_copy_to_user(struct sxe2_drv_cmd_params *param,
					     void *k_buffer, u32 copy_len,
					     struct sxe2_obj *obj)
{
	if (!param || !k_buffer || param->resp_len < copy_len)
		return -EINVAL;

	if (obj->func_type == SXE2_PF) {
		if (copy_to_user(param->resp_data, k_buffer, copy_len))
			return -EFAULT;
	} else {
		memcpy(param->resp_data, k_buffer, copy_len);
	}

	return 0;
}

s32 sxe2_com_cmd_send(void *ad, struct sxe2_obj *obj, struct sxe2_drv_cmd_params *param);

s32 sxe2_dpdk_q_map_resource_release(struct sxe2_adapter *adapter, struct sxe2_obj *obj);

#endif
