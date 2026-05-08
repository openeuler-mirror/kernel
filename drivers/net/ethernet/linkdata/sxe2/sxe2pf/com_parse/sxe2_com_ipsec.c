// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_com_ipsec.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_com_ioctl.h"
#include "sxe2_ioctl_chnl.h"
#include "sxe2_cmd.h"
#include "sxe2_log.h"
#include "sxe2_drv_cmd.h"
#include "sxe2_com_cdev.h"
#include "sxe2_com_ipsec.h"
#include "sxe2_ipsec.h"

s32 sxe2_ipsec_cap_get(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
		       struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_fwc_ipsec_capa_resq resp;
	s32 ret = 0;

	memset(&resp, 0, sizeof(resp));

	LOG_INFO_BDF("ipsec capacity get\n");
	ret = sxe2_ipsec_fwc_get_ipsec_capa(adapter, &resp);
	if (ret) {
		LOG_ERROR_BDF("failed to get ipsec capacity, ret=%d\n", ret);
		ret = -EFAULT;
		goto l_end;
	}

	if (sxe2_com_resp_copy_to_user(cmd_buf, &resp, sizeof(resp), obj) != 0) {
		ret = -EFAULT;
		goto l_end;
	}
	cmd_buf->resp_len = sizeof(resp);

l_end:
	return ret;
}

s32 sxe2_ipsec_resource_clear(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			      struct sxe2_drv_cmd_params *cmd_buf)
{
	s32 ret = 0;

	LOG_INFO_BDF("ipsec resource clear.\n");
	ret = sxe2_dpdk_ipsec_resource_release(adapter, obj);
	if (ret) {
		LOG_ERROR_BDF("failed to get ipsec capacity, ret=%d\n", ret);
		ret = -EFAULT;
		goto l_end;
	}

l_end:
	return ret;
}

s32 sxe2_ipsec_txsa_add(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_fwc_ipsec_txsa_add_req *req = (struct sxe2_fwc_ipsec_txsa_add_req *)
			sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	struct sxe2_fwc_ipsec_txsa_add_resp resp;
	s32 ret = 0;

	if (!req) {
		LOG_ERROR_BDF("copy_from_user failed, len=%lu\n", sizeof(*req));
		ret = -EFAULT;
		goto l_end;
	}
	memset(&resp, 0, sizeof(resp));

	LOG_INFO_BDF("ipsec tx sa add.");

	req->func_type = obj->func_type;
	req->drv_id = (u8)((obj->drv_type << 6) | obj->drv_id);
	req->func_id = (obj->func_type == SXE2_VF ? obj->vf_id : obj->pf_id);
	ret = sxe2_fwc_ipsec_tx_sa_add(adapter, req, &resp);
	if (ret) {
		LOG_ERROR_BDF("failed to add tx sa, ret=%d\n", ret);
		ret = -EFAULT;
		goto l_end;
	}

	if (sxe2_com_resp_copy_to_user(cmd_buf, &resp, sizeof(resp), obj) != 0) {
		ret = -EFAULT;
		goto l_end;
	}

	cmd_buf->resp_len = sizeof(resp);

l_end:
	kfree(req);
	return ret;
}

s32 sxe2_ipsec_txsa_del(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_fwc_ipsec_txsa_del_req *req = (struct sxe2_fwc_ipsec_txsa_del_req *)
			sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	s32 ret = 0;

	if (!req) {
		LOG_ERROR_BDF("copy_from_user failed, len=%lu\n", sizeof(*req));
		ret = -EFAULT;
		goto l_end;
	}
	LOG_INFO_BDF("ipsec tx sa del, id=%u.", req->sa_idx);

	req->func_type = obj->func_type;
	req->drv_id = (u8)((obj->drv_type << 6) | obj->drv_id);
	req->func_id = (obj->func_type == SXE2_VF ? obj->vf_id : obj->pf_id);
	ret = sxe2_fwc_ipsec_tx_sa_del(adapter, req);
	if (ret) {
		LOG_ERROR_BDF("failed to add tx sa, ret=%d\n", ret);
		ret = -EFAULT;
	}

l_end:
	kfree(req);
	return ret;
}

s32 sxe2_ipsec_rxsa_add(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_fwc_ipsec_rxsa_add_req *req = (struct sxe2_fwc_ipsec_rxsa_add_req *)
			sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	struct sxe2_fwc_ipsec_rxsa_add_resp resp;
	s32 ret = 0;

	if (!req) {
		LOG_ERROR_BDF("copy_from_user failed, len=%lu\n", sizeof(*req));
		ret = -EFAULT;
		goto l_end;
	}
	memset(&resp, 0, sizeof(resp));

	req->func_type = obj->func_type;
	req->drv_id = (u8)((obj->drv_type << 6) | obj->drv_id);
	req->func_id = (obj->func_type == SXE2_VF ? obj->vf_id : obj->pf_id);
	ret = sxe2_fwc_ipsec_rx_sa_add(adapter, req, &resp);
	if (ret) {
		LOG_ERROR_BDF("failed to add rx sa, ret=%d\n", ret);
		ret = -EFAULT;
		goto l_end;
	}

	if (sxe2_com_resp_copy_to_user(cmd_buf, &resp, sizeof(resp), obj) != 0) {
		ret = -EFAULT;
		goto l_end;
	}

	cmd_buf->resp_len = sizeof(resp);

l_end:
	kfree(req);
	return ret;
}

s32 sxe2_ipsec_rxsa_del(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_fwc_ipsec_rxsa_del_req *req = (struct sxe2_fwc_ipsec_rxsa_del_req *)
			sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	s32 ret = 0;

	if (!req) {
		LOG_ERROR_BDF("copy_from_user failed, len=%lu\n", sizeof(*req));
		ret = -EFAULT;
		goto l_end;
	}
	LOG_DEBUG_BDF("ipsec rx sa del, id=%u.", req->sa_idx);

	req->func_type = obj->func_type;
	req->drv_id = (u8)((obj->drv_type << 6) | obj->drv_id);
	req->func_id = (obj->func_type == SXE2_VF ? obj->vf_id : obj->pf_id);
	ret = sxe2_fwc_ipsec_rx_sa_del(adapter, req);
	if (ret) {
		LOG_ERROR_BDF("failed to add tx sa, ret=%d\n", ret);
		ret = -EFAULT;
		goto l_end;
	}

l_end:
	kfree(req);
	return ret;
}
