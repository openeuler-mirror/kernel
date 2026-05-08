// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_com_switchdev.c
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
#include "sxe2_com_switchdev.h"
#include "sxe2_eswitch.h"
#include "sxe2_sriov.h"

s32 sxe2_com_switch_uplink(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			   struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_switchdev_uplink_info switchdev_repr_info_req = {0};
	s32 ret = 0;
	u8 pf_id;
	u8 is_set;

	if (sizeof(struct sxe2_switchdev_uplink_info) != cmd_buf->req_len) {
		LOG_ERROR_BDF("cmd len err %lu != %u\n",
			      sizeof(struct sxe2_switchdev_uplink_info),
			      cmd_buf->req_len);
		ret = -EFAULT;
		goto l_end;
	}

	if (copy_from_user(&switchdev_repr_info_req, cmd_buf->req_data,
			   cmd_buf->req_len)) {
		LOG_ERROR_BDF("copy_from_user failed, len=%u\n", cmd_buf->req_len);
		ret = -EFAULT;
		goto l_end;
	}

	is_set = switchdev_repr_info_req.is_set;
	pf_id = switchdev_repr_info_req.pf_id;

	if (pf_id != adapter->pf_idx)
		goto l_end;

	ret = sxe2_eswitch_ucmd_uplink_set(adapter, is_set);
	if (ret) {
		LOG_ERROR_BDF("user driver %s uplink pf %d fail, ret=%d\n",
			      is_set ? "set" : "clear", pf_id, ret);
	} else {
		LOG_DEBUG_BDF("user driver %s uplink pf %d\n", is_set ? "set" : "clear",
			      pf_id);
	}
l_end:
	return ret;
}

s32 sxe2_com_switch_repr(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			 struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_vf_node *vf_node;
	struct sxe2_vsi *esw_vsi;
	struct sxe2_switchdev_repr_info switchdev_repr_info_req = {0};
	s32 ret = 0;
	u8 pf_id;
	u16 cp_vsi_id;
	u16 repr_vf_id;
	u16 repr_pf_id;
	u8 is_set;

	if (sizeof(struct sxe2_switchdev_repr_info) != cmd_buf->req_len) {
		LOG_ERROR_BDF("cmd len err %lu != %u\n",
			      sizeof(struct sxe2_switchdev_repr_info), cmd_buf->req_len);
		ret = -EFAULT;
		goto l_end;
	}

	if (copy_from_user(&switchdev_repr_info_req, cmd_buf->req_data,
			   cmd_buf->req_len)) {
		LOG_ERROR_BDF("copy_from_user failed, len=%u\n", cmd_buf->req_len);
		ret = -EFAULT;
		goto l_end;
	}

	is_set = switchdev_repr_info_req.is_set;
	pf_id = switchdev_repr_info_req.pf_id;
	cp_vsi_id = le16_to_cpu(switchdev_repr_info_req.cp_vsi_id);
	repr_vf_id = le16_to_cpu(switchdev_repr_info_req.repr_vf_id);
	repr_pf_id = le16_to_cpu(switchdev_repr_info_req.repr_pf_id);

	vf_node = sxe2_vf_node_get(adapter, repr_vf_id);
	if (!vf_node)
		goto l_end;

	mutex_lock(SXE2_VF_NODE_LOCK(adapter, repr_vf_id));
	esw_vsi = vf_node->adapter->eswitch_ctxt.user_esw_vsi;
	if (!esw_vsi) {
		LOG_ERROR_BDF("esw vsi null\n");
		goto l_unlock;
	}

	if (cp_vsi_id != esw_vsi->idx_in_dev) {
		LOG_ERROR_BDF("esw vsi is not cp vsi\n");
		goto l_unlock;
	}

	if (pf_id != adapter->pf_idx)
		goto l_unlock;

	if (repr_pf_id != adapter->pf_idx)
		goto l_unlock;

	ret = sxe2_eswitch_ucmd_repr_cfg(vf_node, is_set);

l_unlock:
	mutex_unlock(SXE2_VF_NODE_LOCK(adapter, repr_vf_id));
	if (ret) {
		LOG_ERROR_BDF("user driver %s repr vf %d fail, ret=%d\n",
			      is_set ? "set" : "clear", repr_vf_id, ret);
	} else {
		LOG_DEBUG_BDF("user driver %s repr vf %d\n", is_set ? "set" : "clear",
			      repr_vf_id);
	}
l_end:
	return ret;
}

s32 sxe2_com_switch_mode(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			 struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_switchdev_mode_info switchdev_mode_req = {0};
	struct sxe2_switchdev_mode_info switchdev_mode_resp = {0};
	s32 ret = 0;
	u8 pf_id;
	bool is_switchdev = false;

	if (sizeof(struct sxe2_switchdev_mode_info) != cmd_buf->req_len) {
		LOG_ERROR_BDF("cmd len err %lu != %u\n",
			      sizeof(struct sxe2_switchdev_mode_info), cmd_buf->req_len);
		ret = -EFAULT;
		goto l_end;
	}

	if (sizeof(struct sxe2_switchdev_mode_info) != cmd_buf->resp_len) {
		LOG_ERROR_BDF("cmd resp len err %lu != %u\n",
			      sizeof(struct sxe2_switchdev_mode_info), cmd_buf->resp_len);
		ret = -EFAULT;
		goto l_end;
	}

	if (copy_from_user(&switchdev_mode_req, cmd_buf->req_data, cmd_buf->req_len)) {
		LOG_ERROR_BDF("copy_from_user failed, len=%u\n", cmd_buf->req_len);
		ret = -EFAULT;
		goto l_end;
	}

	pf_id = switchdev_mode_req.pf_id;
	if (pf_id != adapter->pf_idx)
		goto l_end;

	ret = sxe2_eswitch_ucmd_mode_get(adapter, &is_switchdev);
	if (ret) {
		LOG_ERROR_BDF("user driver get pf %d fail, ret=%d\n", pf_id, ret);
	} else {
		switchdev_mode_resp.pf_id = pf_id;
		switchdev_mode_resp.is_switchdev = (u8)is_switchdev;
		LOG_DEBUG_BDF("user driver get pf %d\n", pf_id);
		if (sxe2_com_resp_copy_to_user(cmd_buf, &switchdev_mode_resp,
					       cmd_buf->resp_len, obj) != 0) {
			ret = -EFAULT;
			LOG_ERROR_BDF("copy_to_user failed, len=%u\n", cmd_buf->resp_len);
		}
	}
l_end:
	return ret;
}

s32 sxe2_com_switch_cp_vsi(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			   struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_switchdev_cpvsi_info switchdev_cpvsi_resp = {0};
	s32 ret = 0;
	u16 cp_vsi = 0xFFFF;

	if (sizeof(struct sxe2_switchdev_cpvsi_info) != cmd_buf->resp_len) {
		LOG_ERROR_BDF("cmd resp len err %lu != %u\n",
			      sizeof(struct sxe2_switchdev_cpvsi_info),
			      cmd_buf->resp_len);
		ret = -EFAULT;
		goto l_end;
	}

	ret = sxe2_eswitch_ucmd_eswvsi_get(adapter, &cp_vsi);
	if (ret) {
		LOG_ERROR_BDF("user driver get pf %d fail, ret=%d\n", adapter->pf_idx,
			      ret);
	} else {
		switchdev_cpvsi_resp.cp_vsi_id = cpu_to_le16(cp_vsi);
		LOG_DEBUG_BDF("user driver get pf %d cp vsi %d.\n", adapter->pf_idx,
			      cp_vsi);
		if (sxe2_com_resp_copy_to_user(cmd_buf, &switchdev_cpvsi_resp,
					       cmd_buf->resp_len, obj) != 0) {
			ret = -EFAULT;
			LOG_ERROR_BDF("copy_to_user failed, len=%u\n", cmd_buf->resp_len);
		}
	}
l_end:
	return ret;
}
