// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_com_l2_filter.c
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
#include "sxe2_com_l2_filter.h"
#include "sxe2_switch.h"

s32 sxe2_com_switch_filter_uc(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			      struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_mac_filter_cfg_req mac_filter_cfg_req = {0};
	s32 ret = 0;
	s32 i;
	u16 vsi_id;
	u8 addr[ETH_ALEN];
	u8 is_add;

	if (sizeof(struct sxe2_mac_filter_cfg_req) != cmd_buf->req_len) {
		LOG_ERROR_BDF("cmd len err %lu != %u\n",
			      sizeof(struct sxe2_mac_filter_cfg_req), cmd_buf->req_len);
		ret = -EFAULT;
		goto l_end;
	}

	if (copy_from_user(&mac_filter_cfg_req, cmd_buf->req_data, cmd_buf->req_len)) {
		LOG_ERROR_BDF("copy_from_user failed, len=%u\n", cmd_buf->req_len);
		ret = -EFAULT;
		goto l_end;
	}

	vsi_id = le16_to_cpu(mac_filter_cfg_req.vsi_id);
	is_add = mac_filter_cfg_req.is_add;
	for (i = 0; i < ETH_ALEN; i++)
		addr[i] = mac_filter_cfg_req.addr[i];

	if (is_add)
		ret = sxe2_ucmd_unicast_mac_add(adapter, vsi_id, addr);
	else
		ret = sxe2_ucmd_unicast_mac_del(adapter, vsi_id, addr);

	if (ret) {
		LOG_ERROR_BDF("user driver(vsi=%u) %s unicast mac addr:%pM fail, ret=%d\n",
			      vsi_id, is_add ? "add" : "del", addr, ret);
	} else {
		LOG_DEBUG_BDF("user driver(vsi=%u) %s unicast mac addr:%pM\n", vsi_id,
			      is_add ? "add" : "del", addr);
	}

l_end:
	return ret;
}

s32 sxe2_com_switch_filter_mc(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			      struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_mac_filter_cfg_req mac_filter_cfg_req = {0};
	s32 ret = 0;
	s32 i;
	u16 vsi_id;
	u8 addr[ETH_ALEN];
	u8 is_add;

	if (sizeof(struct sxe2_mac_filter_cfg_req) != cmd_buf->req_len) {
		LOG_ERROR_BDF("cmd len err %lu != %u\n",
			      sizeof(struct sxe2_mac_filter_cfg_req), cmd_buf->req_len);
		ret = -EFAULT;
		goto l_end;
	}

	if (copy_from_user(&mac_filter_cfg_req, cmd_buf->req_data, cmd_buf->req_len)) {
		LOG_ERROR_BDF("copy_from_user failed, len=%u\n", cmd_buf->req_len);
		ret = -EFAULT;
		goto l_end;
	}

	vsi_id = le16_to_cpu(mac_filter_cfg_req.vsi_id);
	is_add = mac_filter_cfg_req.is_add;
	for (i = 0; i < ETH_ALEN; i++)
		addr[i] = mac_filter_cfg_req.addr[i];

	if (is_add)
		ret = sxe2_ucmd_multi_broad_mac_add(adapter, vsi_id, addr);
	else
		ret = sxe2_ucmd_multi_broad_mac_del(adapter, vsi_id, addr);

	if (ret)
		LOG_ERROR_BDF("user driver(vsi=%u) %s multi mac addr:%pM fail, ret=%d\n",
			      vsi_id, is_add ? "add" : "del", addr, ret);
	else
		LOG_DEBUG_BDF("user driver(vsi=%u) %s multi mac addr:%pM\n", vsi_id,
			      is_add ? "add" : "del", addr);
l_end:
	return ret;
}

s32 sxe2_com_switch_filter_vlan_control(struct sxe2_adapter *adapter,
					struct sxe2_obj *obj,
					struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_vlan_filter_switch_req vlan_filter_switch_req = {0};
	s32 ret = 0;
	u16 vsi_id;
	bool is_oper_enable;

	if (sizeof(struct sxe2_vlan_filter_switch_req) != cmd_buf->req_len) {
		LOG_ERROR_BDF("cmd len err %lu != %u\n",
			      sizeof(struct sxe2_vlan_filter_switch_req),
			      cmd_buf->req_len);
		ret = -EFAULT;
		goto l_end;
	}

	if (copy_from_user(&vlan_filter_switch_req, cmd_buf->req_data,
			   cmd_buf->req_len)) {
		LOG_ERROR_BDF("copy_from_user failed, len=%u\n", cmd_buf->req_len);
		ret = -EFAULT;
		goto l_end;
	}

	vsi_id = le16_to_cpu(vlan_filter_switch_req.vsi_id);
	is_oper_enable = (bool)vlan_filter_switch_req.is_oper_enable;
	ret = sxe2_ucmd_vlan_filter_control(adapter, vsi_id, is_oper_enable);
	if (ret) {
		LOG_ERROR_BDF("user driver(vsi=%u) %s vlan filter control fail, ret=%d\n",
			      vsi_id, is_oper_enable ? "enable" : "disable", ret);
	} else {
		LOG_DEBUG_BDF("user driver(vsi=%u) %s vlan filter control.\n", vsi_id,
			      is_oper_enable ? "enable" : "disable");
	}
l_end:
	return ret;
}

s32 sxe2_com_switch_filter_vlan_rule(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				     struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_vlan_filter_cfg_req vlan_filter_cfg_req = {0};
	struct sxe2_vlan vlan = {0};
	s32 ret = 0;
	u16 vsi_id;
	u8 is_add;

	if (sizeof(struct sxe2_vlan_filter_cfg_req) != cmd_buf->req_len) {
		LOG_ERROR_BDF("cmd len err %lu != %u\n",
			      sizeof(struct sxe2_vlan_filter_cfg_req), cmd_buf->req_len);
		ret = -EFAULT;
		goto l_end;
	}

	if (copy_from_user(&vlan_filter_cfg_req, cmd_buf->req_data, cmd_buf->req_len)) {
		LOG_ERROR_BDF("copy_from_user failed, len=%u\n", cmd_buf->req_len);
		ret = -EFAULT;
		goto l_end;
	}

	vsi_id = le16_to_cpu(vlan_filter_cfg_req.vsi_id);
	vlan.vid = le16_to_cpu(vlan_filter_cfg_req.vlan_id);
	vlan.tpid = le16_to_cpu(vlan_filter_cfg_req.tpid_id);
	vlan.prio = vlan_filter_cfg_req.prio;
	is_add = vlan_filter_cfg_req.is_add;
	ret = sxe2_ucmd_vlan_rule_process(adapter, vsi_id, &vlan, is_add);
	if (ret)
		LOG_ERROR_BDF("user driver(vsi=%u) %s vlan tpid:%u vid:%u prio:%u fail, ret=%d\n",
			      vsi_id, is_add ? "add" : "del", vlan.tpid, vlan.vid, vlan.prio, ret);
	else
		LOG_DEBUG_BDF("user driver(vsi=%u) %s vlan tpid:%u vid:%u prio:%u\n",
			      vsi_id, is_add ? "add" : "del", vlan.tpid, vlan.vid, vlan.prio);

l_end:
	return ret;
}

s32 sxe2_com_switch_filter_promisc(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				   struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_promisc_filter_cfg_req promisc_filter_cfg_req = {0};
	s32 ret = 0;
	u16 vsi_id;
	u8 is_add;

	if (sizeof(struct sxe2_promisc_filter_cfg_req) != cmd_buf->req_len) {
		LOG_ERROR_BDF("cmd len err %lu != %u\n",
			      sizeof(struct sxe2_promisc_filter_cfg_req),
			      cmd_buf->req_len);
		ret = -EFAULT;
		goto l_end;
	}

	if (copy_from_user(&promisc_filter_cfg_req, cmd_buf->req_data,
			   cmd_buf->req_len)) {
		LOG_ERROR_BDF("copy_from_user failed, len=%u\n", cmd_buf->req_len);
		ret = -EFAULT;
		goto l_end;
	}

	vsi_id = le16_to_cpu(promisc_filter_cfg_req.vsi_id);
	is_add = promisc_filter_cfg_req.is_add;
	if (is_add)
		ret = sxe2_ucmd_promisc_rule_add(adapter, vsi_id);
	else
		ret = sxe2_ucmd_promisc_rule_del(adapter, vsi_id);

	if (ret)
		LOG_ERROR_BDF("user driver(vsi=%u) %s promisc fail, ret=%d\n", vsi_id,
			      is_add ? "set" : "clear", ret);
	else
		LOG_DEBUG_BDF("user driver(vsi=%u) %s promisc.\n", vsi_id,
			      is_add ? "set" : "clear");
l_end:
	return ret;
}

s32 sxe2_com_switch_filter_allmulti(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
				    struct sxe2_drv_cmd_params *cmd_buf)
{
	struct sxe2_promisc_filter_cfg_req promisc_filter_cfg_req = {0};
	s32 ret = 0;
	u16 vsi_id;
	u8 is_add;

	if (sizeof(struct sxe2_promisc_filter_cfg_req) != cmd_buf->req_len) {
		LOG_ERROR_BDF("cmd len err %lu != %u\n",
			      sizeof(struct sxe2_promisc_filter_cfg_req),
			      cmd_buf->req_len);
		ret = -EFAULT;
		goto l_end;
	}

	if (copy_from_user(&promisc_filter_cfg_req, cmd_buf->req_data,
			   cmd_buf->req_len)) {
		LOG_ERROR_BDF("copy_from_user failed, len=%u\n", cmd_buf->req_len);
		ret = -EFAULT;
		goto l_end;
	}

	vsi_id = le16_to_cpu(promisc_filter_cfg_req.vsi_id);
	is_add = promisc_filter_cfg_req.is_add;
	if (is_add)
		ret = sxe2_ucmd_allmulti_rule_add(adapter, vsi_id);
	else
		ret = sxe2_ucmd_allmulti_rule_del(adapter, vsi_id);

	if (ret)
		LOG_ERROR_BDF("user driver(vsi=%u) %s promisc fail, ret=%d\n", vsi_id,
			      is_add ? "set" : "clear", ret);
	else
		LOG_DEBUG_BDF("user driver(vsi=%u) %s promisc.\n", vsi_id,
			      is_add ? "set" : "clear");
l_end:
	return ret;
}
