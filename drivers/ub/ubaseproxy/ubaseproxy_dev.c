// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#include <ub/ubase/ubase_comm_cmd.h>

#include "ubaseproxy_event.h"
#include "ubaseproxy_dev.h"

static int debug;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "enable ubaseproxy debug log: 0:disable, others:enable, default:0");

int ubaseproxy_dbg_log(void)
{
	return debug;
}

static void ubaseproxy_parse_ue_res(struct ubaseproxy_dev *udev,
				    struct ubaseproxy_query_ue_res_cmd *resp)
{
	struct ubaseproxy_ue_caps *ue_caps = &udev->caps.ue_caps;

	ue_caps->aeq_vector_num = resp->aeq_vector_num;
	ue_caps->ceq_vector_num = resp->ceq_vector_num;
	ue_caps->aeqe_depth = le32_to_cpu(resp->aeqe_depth);
	ue_caps->ceqe_depth = le32_to_cpu(resp->ceqe_depth);
	ue_caps->jfs_max_cnt = le32_to_cpu(resp->jfs_max_cnt);
	ue_caps->jfs_depth = le32_to_cpu(resp->jfs_depth);
	ue_caps->jfr_max_cnt = le32_to_cpu(resp->jfr_max_cnt);
	ue_caps->jfr_depth = le32_to_cpu(resp->jfr_depth);
	ue_caps->jfc_max_cnt = le32_to_cpu(resp->jfc_max_cnt);
	ue_caps->jfc_depth = le32_to_cpu(resp->jfc_depth);
	ue_caps->rc_max_cnt = le32_to_cpu(resp->rc_max_cnt);
	ue_caps->rc_depth = le32_to_cpu(resp->rc_depth);
	ue_caps->jtg_max_cnt = le32_to_cpu(resp->jtg_max_cnt);
}

static void ubaseproxy_set_dev_gfp(struct ubaseproxy_dev *udev)
{
	struct auxiliary_device *adev = udev->comdev.adev;

	udev->gfp = ubase_adev_non_mirror_mem_supported(adev) ?
		    GFP_HIGHUSER_MOVABLE : GFP_KERNEL;
}

static int ubaseproxy_query_dev_res(struct ubaseproxy_dev *udev)
{
	struct ubaseproxy_query_ue_res_cmd resp = {0};
	struct ubase_cmd_buf in, out;
	int ret;

	ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_UE_TA_RSRC, true, 0,
			     NULL);
	ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_UE_TA_RSRC, false,
			     sizeof(resp), &resp);

	ret = ubase_cmd_send_inout(udev->comdev.adev, &in, &out);
	if (ret) {
		ubaseproxy_err(udev, "failed to query ubaseproxy ue res, ret = %d.\n",
			       ret);
		return ret;
	}

	ubaseproxy_parse_ue_res(udev, &resp);
	ubaseproxy_set_dev_gfp(udev);

	return ret;
}

static const struct ubaseproxy_func_map ubaseproxy_dev_func_map[] = {
	{
		"query ue res", ubaseproxy_query_dev_res, NULL
	},
	{
		"register event", ubaseproxy_register_event,
		ubaseproxy_unregister_event
	},
};

int ubaseproxy_dev_init(struct ubaseproxy_dev *udev)
{
	int i, ret = 0;

	for (i = 0; i < ARRAY_SIZE(ubaseproxy_dev_func_map); i++) {
		if (ubaseproxy_dev_func_map[i].init_func) {
			ret = ubaseproxy_dev_func_map[i].init_func(udev);
			if (ret) {
				ubaseproxy_err(udev, "failed to %s, ret = %d\n",
					       ubaseproxy_dev_func_map[i].err_msg, ret);
				goto err_init;
			}
		}
	}

	return ret;

err_init:
	for (i -= 1; i >= 0; i--) {
		if (ubaseproxy_dev_func_map[i].uninit_func)
			ubaseproxy_dev_func_map[i].uninit_func(udev);
	}

	return ret;
}

void ubaseproxy_dev_uninit(struct ubaseproxy_dev *udev)
{
	int i;

	for (i = ARRAY_SIZE(ubaseproxy_dev_func_map) - 1; i >= 0; i--) {
		if (ubaseproxy_dev_func_map[i].uninit_func)
			ubaseproxy_dev_func_map[i].uninit_func(udev);
	}
}
