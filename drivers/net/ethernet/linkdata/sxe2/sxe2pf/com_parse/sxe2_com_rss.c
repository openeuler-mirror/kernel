// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_com_rss.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_com_ioctl.h"
#include "sxe2_ioctl_chnl.h"
#include "sxe2_vsi.h"
#include "sxe2_drv_cmd.h"
#include "sxe2_com_cdev.h"
#include "sxe2_common.h"
#include "sxe2_rss.h"
#include "sxe2_com_rss.h"

s32 sxe2_com_rss_key_set(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			 struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_vsi *vsi = NULL;
	struct sxe2_rss_key_req *req = NULL;
	s32 ret = 0;

	req = (struct sxe2_rss_key_req *)sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req) {
		LOG_ERROR_BDF("sxe2_com_req_data_copy_to_kernel failed\n");
		ret = -EFAULT;
		goto l_end;
	}

	if (req->key_size != SXE2_RSS_HASH_KEY_SIZE) {
		LOG_ERROR_BDF("rss hash key len err %u != %u\n", req->key_size,
			      SXE2_RSS_HASH_KEY_SIZE);
		ret = -EINVAL;
		goto l_end;
	}

	mutex_lock(&adapter->vsi_ctxt.lock);
	vsi = sxe2_vsi_get_by_idx(adapter, req->vsi_id);
	if (!vsi) {
		LOG_ERROR_BDF("failed to get vsi[%u]\n", req->vsi_id);
		ret = -EINVAL;
		goto l_unlock;
	}

	ret = sxe2_fwc_rss_hkey_set(vsi, req->key);
	LOG_DEBUG_BDF("vsi[%u] rss hkey set ret[%d]\n", req->vsi_id, ret);

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
l_end:
	kfree(req);
	return ret;
}

s32 sxe2_com_rss_lut_set(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			 struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_vsi *vsi = NULL;
	struct sxe2_rss_lut_req *req = NULL;
	s32 ret = 0;

	req = (struct sxe2_rss_lut_req *)sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req) {
		LOG_ERROR_BDF("sxe2_com_req_data_copy_to_kernel failed\n");
		ret = -EFAULT;
		goto l_end;
	}

	mutex_lock(&adapter->vsi_ctxt.lock);
	vsi = sxe2_vsi_get_by_idx(adapter, req->vsi_id);
	if (!vsi) {
		LOG_ERROR_BDF("failed to get vsi[%u]\n", req->vsi_id);
		ret = -EINVAL;
		goto l_unlock;
	}

	if (vsi->rss_ctxt.lut_size != req->lut_size) {
		LOG_ERROR_BDF("vsi[%u] lut size[%u] not [%u].\n", req->vsi_id,
			      vsi->rss_ctxt.lut_size, req->lut_size);
		ret = -EINVAL;
		goto l_unlock;
	}

	ret = sxe2_fwc_rss_lut_set(vsi, req->lut, req->lut_size);
	LOG_DEBUG_BDF("vsi[%u] rss lut[%u] set ret[%d]\n", req->vsi_id, req->lut_size,
		      ret);

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);

l_end:
	kfree(req);
	return ret;
}

s32 sxe2_com_rss_func_set(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			  struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_vsi *vsi = NULL;
	struct sxe2_rss_func_req *req = NULL;
	s32 ret = 0;
	u8 hash_type_old;

	req = (struct sxe2_rss_func_req *)sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req) {
		LOG_ERROR_BDF("sxe2_com_req_data_copy_to_kernel failed\n");
		ret = -EFAULT;
		goto l_end;
	}

	mutex_lock(&adapter->vsi_ctxt.lock);
	vsi = sxe2_vsi_get_by_idx(adapter, req->vsi_id);
	if (!vsi) {
		LOG_ERROR_BDF("failed to get vsi[%u]\n", req->vsi_id);
		ret = -EINVAL;
		goto l_unlock;
	}

	hash_type_old = vsi->rss_ctxt.hash_type;
	vsi->rss_ctxt.hash_type = req->func;
	ret = sxe2_fwc_rss_hash_ctrl_set(vsi);
	if (ret != 0)
		vsi->rss_ctxt.hash_type = hash_type_old;

	LOG_DEBUG_BDF("vsi[%u] rss hash type[%u] set ret[%d]\n", req->vsi_id, req->func,
		      ret);

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);

l_end:
	kfree(req);
	return ret;
}

STATIC void sxe2_com_rss_hf_req_convert_hash_cfg(struct sxe2_adapter *adapter,
						 struct sxe2_rss_hash_cfg *hash_cfg,
						 struct sxe2_rss_hf_req *req)
{
	u32 tmp_headers[BITS_TO_U32(SXE2_FLOW_HDR_MAX)];
	u32 tmp_flds[BITS_TO_U32(SXE2_FLOW_FLD_ID_MAX)];
	u32 i = 0;

	(void)memset(hash_cfg, 0, sizeof(*hash_cfg));
	for (i = 0; i < BITS_TO_U32(SXE2_FLOW_HDR_MAX); i++)
		tmp_headers[i] = le32_to_cpu(req->headers[i]);

	bitmap_from_arr32(hash_cfg->headers, tmp_headers, SXE2_FLOW_HDR_MAX);

	for (i = 0; i < BITS_TO_U32(SXE2_FLOW_FLD_ID_MAX); i++)
		tmp_flds[i] = le32_to_cpu(req->hash_flds[i]);

	bitmap_from_arr32(hash_cfg->hash_flds, tmp_flds, SXE2_FLOW_FLD_ID_MAX);

	hash_cfg->hdr_type = le32_to_cpu(req->hdr_type);
	hash_cfg->symm = req->symm == 1 ? true : false;
}

STATIC s32 sxe2_com_rss_hf_cfg(struct sxe2_adapter *adapter, struct sxe2_rss_hf_req *req,
			       bool add)
{
	struct sxe2_vsi *vsi = NULL;
	struct sxe2_rss_hash_cfg cfg;
	s32 ret = SXE2_VF_ERR_SUCCESS;

	if (sxe2_is_safe_mode(adapter)) {
		LOG_ERROR_BDF("sxe2 rss is in safe mode, not support.\n");
		ret = -EPERM;
		goto l_end;
	}

	mutex_lock(&adapter->vsi_ctxt.lock);
	vsi = sxe2_vsi_get_by_idx(adapter, req->vsi_id);
	if (!vsi) {
		LOG_ERROR_BDF("failed to get vsi[%u]\n", req->vsi_id);
		ret = -EINVAL;
		goto l_unlock;
	}

	sxe2_com_rss_hf_req_convert_hash_cfg(adapter, &cfg, req);

	if (bitmap_empty(cfg.headers, SXE2_FLOW_HDR_MAX)) {
		LOG_ERROR_BDF("invalid header type! vsi type: %u, idx: %u\n", vsi->type,
			      vsi->id_in_pf);
		ret = -EINVAL;
		goto l_unlock;
	}

	if (bitmap_empty(cfg.hash_flds, SXE2_FLOW_FLD_ID_MAX)) {
		LOG_ERROR_BDF("invalid flds type! vsi type: %u, idx: %u\n", vsi->type,
			      vsi->id_in_pf);
		ret = -EINVAL;
		goto l_unlock;
	}

	if (add) {
		ret = sxe2_add_rss_flow(&adapter->rss_flow_ctxt, vsi->id_in_pf, &cfg);
	} else {
		ret = sxe2_rss_rem_cfg(&adapter->rss_flow_ctxt, vsi->id_in_pf, &cfg);
		if (ret == -ENOENT) {
			ret = 0;
			LOG_INFO_BDF("rss cfg not found\n");
		}
	}
	if (ret != 0) {
		LOG_ERROR_BDF("Failed to cfg[%u] rss cfg vsi type: %u, idx: %u\n",
			      vsi->type, vsi->id_in_pf, vsi->idx_in_dev);
	}

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);

l_end:
	return ret;
}

s32 sxe2_com_rss_hf_add(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_rss_hf_req *req = NULL;
	s32 ret = 0;

	req = (struct sxe2_rss_hf_req *)sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req) {
		LOG_ERROR_BDF("sxe2_com_req_data_copy_to_kernel failed\n");
		ret = -EFAULT;
		goto l_end;
	}

	ret = sxe2_com_rss_hf_cfg(adapter, req, true);
	LOG_DEBUG_BDF("vsi[%u] add rss hf cfg, ret[%d].\n", req->vsi_id, ret);

l_end:
	kfree(req);
	return ret;
}

s32 sxe2_com_rss_hf_del(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_rss_hf_req *req = NULL;
	s32 ret = 0;

	req = (struct sxe2_rss_hf_req *)sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	if (!req) {
		LOG_ERROR_BDF("sxe2_com_req_data_copy_to_kernel failed\n");
		ret = -EFAULT;
		goto l_end;
	}

	ret = sxe2_com_rss_hf_cfg(adapter, req, false);
	LOG_DEBUG_BDF("vsi[%u] del rss hf cfg, ret[%d].\n", req->vsi_id, ret);

l_end:
	kfree(req);
	return ret;
}

s32 sxe2_com_rss_hf_clear(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			  struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_vsi *vsi = NULL;
	s32 ret = 0;

	mutex_lock(&adapter->vsi_ctxt.lock);
	vsi = sxe2_vsi_get_by_idx(adapter, cmd_buf->vsi_id);
	if (!vsi) {
		LOG_ERROR_BDF("failed to get vsi[%u]\n", cmd_buf->vsi_id);
		ret = -EINVAL;
		goto l_unlock;
	}

	sxe2_rss_vsi_flow_clean(vsi);
	LOG_DEBUG_BDF("vsi[%u] rss hf clear.\n", cmd_buf->vsi_id);

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
	return ret;
}
