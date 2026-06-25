// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_com_vlan.c
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
#include "sxe2_com_vlan.h"
#include "sxe2_switch.h"
#include "sxe2_sriov.h"
#include "sxe2_netdev.h"
#include "sxe2_hw.h"

STATIC s32 sxe2_user_vlan_offload_set_outer_strip(struct sxe2_hw *hw, u16 vsi,
						  u8 outer_strip)
{
	u32 val;

	if (outer_strip & ~(SXE2_DPDK_OFFLOAD_OUTER_STRIP_MASK))
		return -SXE2_HW_ERR_INVAL;

	val = sxe2_read_reg(hw, SXE2_VSI_TSR(vsi));
	val &= ~(SXE2_DPDK_OFFLOAD_OUTER_STRIP_MASK |
		 (SXE2_DPDK_OFFLOAD_OUTER_STRIP_MASK << SXE2_DPDK_OFFLOAD_STRIP_OFFSET));
	val = val | outer_strip | (outer_strip << SXE2_DPDK_OFFLOAD_STRIP_OFFSET);
	sxe2_write_reg(hw, SXE2_VSI_TSR(vsi), val);
	return 0;
}

STATIC s32 sxe2_user_vlan_offload_set_inner_strip(struct sxe2_hw *hw, u16 vsi,
						  u8 inner_strip)
{
	u32 val;

	if (inner_strip & ~SXE2_DPDK_OFFLOAD_INNER_STRIP_QINQ1)
		return -SXE2_HW_ERR_INVAL;

	val = sxe2_read_reg(hw, SXE2_VSI_TSR(vsi));
	val &= ~(SXE2_DPDK_OFFLOAD_INNER_STRIP_QINQ1 |
		 (SXE2_DPDK_OFFLOAD_INNER_STRIP_QINQ1 << SXE2_DPDK_OFFLOAD_STRIP_OFFSET));
	val = val | inner_strip | (inner_strip << SXE2_DPDK_OFFLOAD_STRIP_OFFSET);
	sxe2_write_reg(hw, SXE2_VSI_TSR(vsi), val);

	return 0;
}

s32 sxe2_user_vlan_offload_strip_paramcheck(struct sxe2_user_vlan_offload_cfg *vlan_cfg,
					    bool port_vlan_exist)
{
	u8 outer_strip = vlan_cfg->outer_strip;
	u8 inner_strip = vlan_cfg->inner_strip;

	if (outer_strip & ~(SXE2_DPDK_OFFLOAD_OUTER_STRIP_MASK))
		return -SXE2_HW_ERR_INVAL;

	if (inner_strip & ~SXE2_DPDK_OFFLOAD_INNER_STRIP_QINQ1)
		return -SXE2_HW_ERR_INVAL;

	if ((outer_strip & SXE2_DPDK_OFFLOAD_OUTER_STRIP_MASK) == 0 &&
	    (inner_strip & SXE2_DPDK_OFFLOAD_INNER_STRIP_QINQ1)) {
		if (port_vlan_exist)
			return 0;
		else
			return -SXE2_HW_ERR_INVAL;
	}

	return 0;
}

STATIC s32 sxe2_user_vlan_offload_set_insert(struct sxe2_hw *hw, struct sxe2_vsi *vsi,
					     u8 outer_insert, u8 inner_insert)
{
	u32 tmpval = 0;
	u32 val;
	u32 vall2tagsen;
	s32 ret = SXE2_VF_ERR_SUCCESS;
	u16 vsi_id = vsi->idx_in_dev;
	struct sxe2_adapter *adapter = vsi->adapter;
	u8 portid = adapter->port_idx;

	val = sxe2_read_reg(hw, SXE2_VSI_L2TAGSTXVALID(vsi_id));
	if (!(outer_insert & SXE2_DPDK_OFFLOAD_INSERT_ENABLE) &&
	    !(inner_insert & SXE2_DPDK_OFFLOAD_INSERT_ENABLE)) {
		tmpval = val & (~((SXE2_DPDK_OFFLOAD_INSERT_ENABLE << 4) |
				  SXE2_DPDK_OFFLOAD_INSERT_ENABLE));
		sxe2_write_reg(hw, SXE2_VSI_L2TAGSTXVALID(vsi_id), tmpval);
	} else if ((outer_insert & SXE2_DPDK_OFFLOAD_INSERT_ENABLE) &&
		   (inner_insert & SXE2_DPDK_OFFLOAD_INSERT_ENABLE)) {
		if (((outer_insert & SXE2_DPDK_OFFLOAD_FIELD) ==
		     (inner_insert & SXE2_DPDK_OFFLOAD_FIELD)) ||
		    ((inner_insert & SXE2_DPDK_OFFLOAD_TAGID_FIELD) !=
		     SXE2_DPDK_OFFLOAD_OUTER_INSERT_VLAN) ||
		    (((outer_insert & SXE2_DPDK_OFFLOAD_TAGID_FIELD) !=
		      SXE2_DPDK_OFFLOAD_OUTER_INSERT_8021AD) &&
		     ((outer_insert & SXE2_DPDK_OFFLOAD_TAGID_FIELD) !=
		      SXE2_DPDK_OFFLOAD_OUTER_INSERT_QINQ1) &&
		     ((outer_insert & SXE2_DPDK_OFFLOAD_TAGID_FIELD) !=
		      SXE2_DPDK_OFFLOAD_OUTER_INSERT_8021Q))) {
			LOG_ERROR_BDF("vlan insert set failed vsi[%u], inner:%u, outer:%u\n",
				      vsi_id, inner_insert, outer_insert);
			ret = -SXE2_VF_ERR_PARAM;
		} else if ((((outer_insert & SXE2_DPDK_OFFLOAD_TAGID_FIELD) ==
			     SXE2_DPDK_OFFLOAD_OUTER_INSERT_8021AD) ||
			    ((outer_insert & SXE2_DPDK_OFFLOAD_TAGID_FIELD) ==
			     SXE2_DPDK_OFFLOAD_OUTER_INSERT_QINQ1))) {
			tmpval = (inner_insert & SXE2_DPDK_OFFLOAD_FIELD) |
				 ((outer_insert & SXE2_DPDK_OFFLOAD_FIELD) << 4);

			sxe2_write_reg(hw, SXE2_VSI_L2TAGSTXVALID(vsi_id), tmpval);
		} else if (((outer_insert & SXE2_DPDK_OFFLOAD_TAGID_FIELD) ==
			    SXE2_DPDK_OFFLOAD_OUTER_INSERT_8021Q)) {
			vall2tagsen = sxe2_read_reg(hw, SXE2_PFP_L2TAGSEN(portid));
			if (!((vall2tagsen >> 8) & BIT(2))) {
				vall2tagsen |= (BIT(2) << 8);
				sxe2_write_reg(hw, SXE2_PFP_L2TAGSEN(portid),
					       vall2tagsen);
			}
			tmpval = (inner_insert & SXE2_DPDK_OFFLOAD_FIELD) |
				 ((outer_insert & SXE2_DPDK_OFFLOAD_FIELD) << 4);

			sxe2_write_reg(hw, SXE2_VSI_L2TAGSTXVALID(vsi_id), tmpval);
		} else {
			LOG_ERROR_BDF("failed to insert, vsi:%u, inner:%u, outer:%u\n",
				      vsi_id, inner_insert, outer_insert);
			ret = -SXE2_VF_ERR_PARAM;
		}
	} else if (inner_insert & SXE2_DPDK_OFFLOAD_INSERT_ENABLE) {
		if (vsi->user_vlan.port_vlan_exsit ||
		    (vsi->vf_node && vsi->vf_node->vlan_info.port_vlan_exsit)) {
			val |= (SXE2_VSI_L2TAGSTXVALID_ID_VLAN
				<< SXE2_VSI_L2TAGSTXVALID_L2TAG1_ID_S);
			val |= SXE2_VSI_L2TAGSTXVALID_L2TAG1_VALID;
			sxe2_write_reg(hw, SXE2_VSI_L2TAGSTXVALID(vsi_id), val);
		} else {
			LOG_ERROR_BDF("failed to insert, vsi:%u, set inner but not set outer\n",
				      vsi_id);
			ret = -SXE2_VF_ERR_PARAM;
		}
	} else {
		if (((outer_insert & SXE2_DPDK_OFFLOAD_TAGID_FIELD) ==
		     SXE2_DPDK_OFFLOAD_OUTER_INSERT_8021Q) ||
		    ((outer_insert & SXE2_DPDK_OFFLOAD_TAGID_FIELD) ==
		     SXE2_DPDK_OFFLOAD_OUTER_INSERT_8021AD) ||
		    ((outer_insert & SXE2_DPDK_OFFLOAD_TAGID_FIELD) ==
		     SXE2_DPDK_OFFLOAD_OUTER_INSERT_QINQ1) ||
		    ((outer_insert & SXE2_DPDK_OFFLOAD_TAGID_FIELD) ==
		     SXE2_DPDK_OFFLOAD_OUTER_INSERT_VLAN)) {
			tmpval = ((val & (~(SXE2_DPDK_OFFLOAD_INSERT_ENABLE << 4))) |
				  outer_insert);
			sxe2_write_reg(hw, SXE2_VSI_L2TAGSTXVALID(vsi_id), tmpval);
		} else {
			LOG_ERROR_BDF("failed to insert, vsi[%u], outer param :%u\n",
				      vsi_id, outer_insert);
			ret = -SXE2_VF_ERR_PARAM;
		}
	}

	return ret;
}

STATIC s32 sxe2_vlan_hw_sync_and_update(struct sxe2_hw *hw, struct sxe2_vsi *vsi,
					struct sxe2_user_vlan_offload_cfg *new_cfg,
					struct sxe2_user_vlan_offload_cfg *curr_cfg,
					bool is_port_vlan_check)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = hw->adapter;

	if (new_cfg->inner_insert != curr_cfg->inner_insert ||
	    new_cfg->outer_insert != curr_cfg->outer_insert) {
		ret = sxe2_user_vlan_offload_set_insert(hw, vsi, new_cfg->outer_insert,
							new_cfg->inner_insert);
		if (ret) {
			LOG_ERROR_BDF("Failed to set vlan offload insert, vsi_id:%d\n",
				      vsi->idx_in_dev);
			ret = -EINVAL;
			goto l_end;
		}

		curr_cfg->inner_insert = new_cfg->inner_insert;
		curr_cfg->outer_insert = new_cfg->outer_insert;
	}

	ret = sxe2_user_vlan_offload_strip_paramcheck(new_cfg, is_port_vlan_check);
	if (ret) {
		LOG_ERROR_BDF("Failed to check vlan strip, vsi_id:%d\n", vsi->idx_in_dev);
		ret = -EINVAL;
		goto l_end;
	}

	if (new_cfg->outer_strip != curr_cfg->outer_strip) {
		ret = sxe2_user_vlan_offload_set_outer_strip(hw, vsi->idx_in_dev,
							     new_cfg->outer_strip);
		if (ret) {
			LOG_ERROR_BDF("Failed to set vlan outer strip, vsi_id:%d\n",
				      vsi->idx_in_dev);
			ret = -EINVAL;
			goto l_end;
		}
		curr_cfg->outer_strip = new_cfg->outer_strip;
	}

	if (new_cfg->inner_strip != curr_cfg->inner_strip) {
		ret = sxe2_user_vlan_offload_set_inner_strip(hw, vsi->idx_in_dev,
							     new_cfg->inner_strip);
		if (ret) {
			LOG_ERROR_BDF("Failed to set vlan inner strip, vsi_id:%d\n",
				      vsi->idx_in_dev);
			ret = -EINVAL;
			goto l_end;
		}
		curr_cfg->inner_strip = new_cfg->inner_strip;
	}

l_end:
	return ret;
}

STATIC s32
sxe2_user_vlan_offload_cfg_common_handle(struct sxe2_vsi *vsi,
					 struct sxe2_user_vlan_offload_cfg *vlan_cfg)
{
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_hw *hw = &adapter->hw;
	struct sxe2_vf_node *vf = vsi->vf_node;
	s32 ret;

	if (vf) {
		ret = sxe2_check_vf_ready_for_cfg(vf);
		if (ret) {
			LOG_ERROR_BDF("VF %u not ready for VLAN cfg.\n", vf->vf_idx);
			goto l_vf_unlock;
		}

		if (sxe2_port_vlan_is_exist(vf)) {
			if (vlan_cfg->outer_insert != 0 || vlan_cfg->outer_strip != 0) {
				LOG_ERROR_BDF("VF %u, vsi_id: %u Port enabled, outer forbidden.\n",
					      vf->vf_idx, vsi->idx_in_dev);
				ret = -EINVAL;
				goto l_vf_unlock;
			}
		}

		ret = sxe2_vlan_hw_sync_and_update(hw, vsi, vlan_cfg,
						   &vf->vlan_info.vlan_offload, true);
		if (ret) {
			LOG_ERROR_BDF("Failed to sync vlan offload, vsi_id:%d\n",
				      vsi->idx_in_dev);
			goto l_vf_unlock;
		}

l_vf_unlock:
		return ret;
	}

	return sxe2_vlan_hw_sync_and_update(hw, vsi, vlan_cfg,
					    &vsi->user_vlan.vlan_offload, false);
}

s32 sxe2_com_vlan_offload_cfg(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			      struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_drv_vlan_offload_cfg_req *vlan_offload =
			(struct sxe2_drv_vlan_offload_cfg_req *)
					sxe2_com_req_data_copy_to_kernel(cmd_buf, obj);
	struct sxe2_vsi *vsi = NULL;
	struct sxe2_user_vlan_offload_cfg vlan_cfg = {0};
	s32 ret = 0;
	u16 idx = 0;

	if (!vlan_offload) {
		LOG_ERROR_BDF("vlan offload cfg req is NULL\n");
		ret = -EINVAL;
		goto l_end;
	}

	idx = vlan_offload->vsi_id;
	mutex_lock(&adapter->vsi_ctxt.lock);
	vsi = sxe2_vsi_get_by_idx(adapter, idx);
	if (!vsi) {
		LOG_ERROR_BDF("vsi is NULL\n");
		ret = -EINVAL;
		goto l_unlock;
	}

	vlan_cfg.outer_insert = vlan_offload->outer_insert;
	vlan_cfg.outer_strip = vlan_offload->outer_strip;
	vlan_cfg.inner_insert = vlan_offload->inner_insert;
	vlan_cfg.inner_strip = vlan_offload->inner_strip;
	ret = sxe2_user_vlan_offload_cfg_common_handle(vsi, &vlan_cfg);
	if (ret != 0) {
		LOG_ERROR_BDF("failed to cfg vlan, ret:%d\n", ret);
		ret = -EINVAL;
		goto l_unlock;
	}

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);

l_end:
	kfree(vlan_offload);
	return ret;
}

STATIC s32 sxe2_user_vlan_cfg_query_common_handle(struct sxe2_vsi *vsi,
						  enum sxe2_func_type func_type,
						  struct sxe2_drv_vlan_cfg_query_resp *vlan_cfg)
{
	struct sxe2_vf_node *vf = vsi->vf_node;
	struct sxe2_user_vlan_offload_cfg vlan_offload = {0};
	struct sxe2_vlan port_vlan = {0};

	if (vf) {
		memcpy(&vlan_offload, &vf->vlan_info.vlan_offload, sizeof(vlan_offload));
		memcpy(&port_vlan, &vf->vlan_info.port_vlan, sizeof(port_vlan));
	} else {
		memcpy(&vlan_offload, &vsi->user_vlan.vlan_offload, sizeof(vlan_offload));
		memcpy(&port_vlan, &vsi->user_vlan.port_vlan, sizeof(port_vlan));
	}

	vlan_cfg->outer_insert = vlan_offload.outer_insert;
	vlan_cfg->outer_strip = vlan_offload.outer_strip;
	vlan_cfg->inner_insert = vlan_offload.inner_insert;
	vlan_cfg->inner_strip = vlan_offload.inner_strip;

	vlan_cfg->port_vlan_exist = (port_vlan.vid != 0 || port_vlan.prio != 0) ? 1 : 0;

	vlan_cfg->tpid = port_vlan.tpid;
	vlan_cfg->vid = port_vlan.vid;

	return 0;
}

s32 sxe2_com_vlan_cfg_query(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			    struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_drv_vlan_cfg_query_resp resp;
	u16 vsi_id = cmd_buf->vsi_id;
	struct sxe2_vsi *vsi = NULL;
	s32 ret = 0;

	mutex_lock(&adapter->vsi_ctxt.lock);
	vsi = sxe2_vsi_get_by_idx(adapter, vsi_id);
	if (!vsi) {
		mutex_unlock(&adapter->vsi_ctxt.lock);
		LOG_ERROR_BDF("vsi is NULL\n");
		ret = -EINVAL;
		goto l_end;
	}

	(void)sxe2_user_vlan_cfg_query_common_handle(vsi, obj->func_type, &resp);
	mutex_unlock(&adapter->vsi_ctxt.lock);

	if (sxe2_com_resp_copy_to_user(cmd_buf, &resp, sizeof(resp), obj)) {
		ret = -EFAULT;
		goto l_end;
	}

l_end:
	return ret;
}

s32 sxe2_user_vlan_destroy(struct sxe2_vsi *vsi)
{
	struct sxe2_user_vlan_offload_cfg vlan_cfg = {0};
	struct sxe2_adapter *adapter = vsi->adapter;
	s32 ret = 0;

	ret = sxe2_user_vlan_offload_cfg_common_handle(vsi, &vlan_cfg);
	if (ret) {
		LOG_ERROR_BDF("Failed to clean vlan offload cfg, vsi_id:%d\n",
			      vsi->idx_in_dev);
		ret = -EINVAL;
		goto l_end;
	}

l_end:
	return ret;
}
