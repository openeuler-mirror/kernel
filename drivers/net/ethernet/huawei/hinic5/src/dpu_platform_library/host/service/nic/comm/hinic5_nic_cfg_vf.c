/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_nic_cfg_vf.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/ethtool.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/module.h>

#include "comm_defs.h"
#include "ossl_knl.h"
#include "hinic5_crm.h"
#include "hinic5_hw.h"
#include "hinic5_nic_io.h"
#include "hinic5_nic_cfg.h"
#include "hinic5_srv_nic.h"
#include "hinic5_nic.h"
#include "hinic5_nic_cmdq.h"
#include "nic_mpu_cmd.h"
#include "hinic5_nic_cfg_vf.h"

static unsigned char set_vf_link_state;
module_param(set_vf_link_state, byte, 0444);
MODULE_PARM_DESC(set_vf_link_state, "Set vf link state, 0: link auto, 1: link always up, 2: link always down (default=0)");

static int hinic5_set_vlan_ctx(struct hinic5_nic_io *nic_io, u16 func_id,
			       u16 vlan_tag, u16 q_id, bool add)
{
	struct hinic5_cmd_buf *cmd_buf = NULL;
	u64 out_param = 0;
	int err;
	u8 cmd, vlan_mode;

	cmd_buf = hinic5_alloc_cmd_buf(nic_io->hwdev);
	if (!cmd_buf) {
		nic_err(nic_io->dev_hdl, "Failed to allocate cmd buf\n");
		return -ENOMEM;
	}

	vlan_mode = add ?  NIC_QINQ_INSERT_ENABLE : NIC_CVLAN_INSERT_ENABLE;

	cmd = nic_io->cmdq_ops->prepare_cmd_buf_modify_svlan(cmd_buf, func_id,
		vlan_tag, q_id, vlan_mode);

	err = hinic5_cmdq_direct_resp(nic_io->hwdev, HINIC5_MOD_L2NIC,
				      cmd, cmd_buf, &out_param, 0, HINIC5_CHANNEL_NIC);

	hinic5_free_cmd_buf(nic_io->hwdev, cmd_buf);

	if (err != 0 || out_param != 0) {
		nic_err(nic_io->dev_hdl, "Failed to set vlan context, err: %d, out_param: 0x%llx\n",
			err, out_param);
		return -EFAULT;
	}

	return err;
}

int hinic5_cfg_vf_vlan(struct hinic5_nic_io *nic_io, u8 opcode, u16 vid,
		       u8 qos, int vf_id)
{
	struct hinic5_cmd_vf_vlan_config vf_vlan;
	u16 out_size = sizeof(vf_vlan);
	u16 glb_func_id;
	int err;
	u16 vlan_tag;

	/* VLAN 0 is a special case, don't allow it to be removed */
	if (vid == 0 && opcode == HINIC5_CMD_OP_DEL)
		return 0;

	memset(&vf_vlan, 0, sizeof(vf_vlan));

	vf_vlan.opcode = opcode;
	vf_vlan.func_id = hinic5_glb_pf_vf_offset(nic_io->hwdev) + (u16)vf_id;
	vf_vlan.vlan_id = vid;
	vf_vlan.qos = qos;

	err = hinic5_l2nic_msg_to_mgmt_sync(nic_io->hwdev, HINIC5_NIC_CMD_CFG_VF_VLAN,
				     &vf_vlan, sizeof(vf_vlan),
				     &vf_vlan, &out_size);
	if (err != 0 || out_size == 0 || vf_vlan.msg_head.status != 0) {
		nic_err(nic_io->dev_hdl, "Failed to set VF %d vlan, err: %d, status: 0x%x,out size: 0x%x\n",
			HW_VF_ID_TO_OS(vf_id), err, vf_vlan.msg_head.status,
			out_size);
		return -EFAULT;
	}

	vlan_tag = vid + (u16)(qos << VLAN_PRIO_SHIFT);

	glb_func_id = hinic5_glb_pf_vf_offset(nic_io->hwdev) + (u16)vf_id;
	err = hinic5_set_vlan_ctx(nic_io, glb_func_id, vlan_tag,
				  NIC_CONFIG_ALL_QUEUE_VLAN_CTX,
				  opcode == HINIC5_CMD_OP_ADD);
	if (err != 0) {
		nic_err(nic_io->dev_hdl, "Failed to set VF %d vlan ctx, err: %d\n",
			HW_VF_ID_TO_OS(vf_id), err);

		/* rollback vlan config */
		if (opcode == HINIC5_CMD_OP_DEL)
			vf_vlan.opcode = HINIC5_CMD_OP_ADD;
		else
			vf_vlan.opcode = HINIC5_CMD_OP_DEL;
		hinic5_l2nic_msg_to_mgmt_sync(nic_io->hwdev,
				       HINIC5_NIC_CMD_CFG_VF_VLAN, &vf_vlan,
				       sizeof(vf_vlan), &vf_vlan, &out_size);
		return err;
	}

	return 0;
}

/*
 * this function just be called by hinic5_ndo_set_vf_mac,
 * others are not permitted.
 */
int hinic5_set_vf_mac(void *hwdev, int vf_id, const unsigned char *mac_addr)
{
	struct vf_data_storage *vf_info = NULL;
	struct hinic5_nic_io *nic_io = NULL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	vf_info = HW_VF_ID_TO_OS_CO(nic_io->vf_infos, vf_id);
#ifndef __VMWARE__
	/* duplicate request, so just return success */
	if (ether_addr_equal(vf_info->user_mac_addr, mac_addr))
		return 0;

#else
	if (ether_addr_equal(vf_info->user_mac_addr, mac_addr))
		return 0;
#endif
	ether_addr_copy(vf_info->user_mac_addr, mac_addr);

	return 0;
}

int hinic5_add_vf_vlan(void *hwdev, int vf_id, u16 vlan, u8 qos)
{
	struct hinic5_nic_io *nic_io = NULL;
	int err;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	err = hinic5_cfg_vf_vlan(nic_io, HINIC5_CMD_OP_ADD, vlan, qos, vf_id);
	if (err != 0)
		return err;

	nic_io->vf_infos[HW_VF_ID_TO_OS(vf_id)].pf_vlan = vlan;
	nic_io->vf_infos[HW_VF_ID_TO_OS(vf_id)].pf_qos = qos;

	nic_info(nic_io->dev_hdl, "Setting VLAN %u, QOS 0x%x on VF %d\n",
		 vlan, qos, HW_VF_ID_TO_OS(vf_id));

	return 0;
}

int hinic5_kill_vf_vlan(void *hwdev, int vf_id)
{
	struct vf_data_storage *vf_infos = NULL;
	struct hinic5_nic_io *nic_io = NULL;
	int err;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	vf_infos = nic_io->vf_infos;

	err = hinic5_cfg_vf_vlan(nic_io, HINIC5_CMD_OP_DEL,
				 vf_infos[HW_VF_ID_TO_OS(vf_id)].pf_vlan,
				 vf_infos[HW_VF_ID_TO_OS(vf_id)].pf_qos, vf_id);
	if (err != 0)
		return err;

	nic_info(nic_io->dev_hdl, "Remove VLAN %u on VF %d\n",
		 vf_infos[HW_VF_ID_TO_OS(vf_id)].pf_vlan,
		 HW_VF_ID_TO_OS(vf_id));

	vf_infos[HW_VF_ID_TO_OS(vf_id)].pf_vlan = 0;
	vf_infos[HW_VF_ID_TO_OS(vf_id)].pf_qos = 0;

	return 0;
}

u16 hinic5_vf_info_vlanprio(void *hwdev, int vf_id)
{
	struct hinic5_nic_io *nic_io = NULL;
	u16 pf_vlan, vlanprio;
	u8 pf_qos;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;
	pf_vlan = nic_io->vf_infos[HW_VF_ID_TO_OS(vf_id)].pf_vlan;
	pf_qos = nic_io->vf_infos[HW_VF_ID_TO_OS(vf_id)].pf_qos;
	vlanprio = (u16)(pf_vlan | (pf_qos << HINIC5_VLAN_PRIORITY_SHIFT));

	return vlanprio;
}

int hinic5_set_vf_link_state(void *hwdev, u16 vf_id, int link)
{
	u8 link_status = 0;
	struct vf_data_storage *vf_infos = NULL;
	struct hinic5_nic_io *nic_io =
		hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;
	vf_infos = nic_io->vf_infos;

	switch (link) {
	case HINIC5_IFLA_VF_LINK_STATE_AUTO:
		vf_infos[HW_VF_ID_TO_OS(vf_id)].link_forced = false;
		vf_infos[HW_VF_ID_TO_OS(vf_id)].link_up = (nic_io->link_status != 0) ?
			true : false;
		link_status = nic_io->link_status;
		break;
	case HINIC5_IFLA_VF_LINK_STATE_ENABLE:
		vf_infos[HW_VF_ID_TO_OS(vf_id)].link_forced = true;
		vf_infos[HW_VF_ID_TO_OS(vf_id)].link_up = true;
		link_status = HINIC5_LINK_UP;
		break;
	case HINIC5_IFLA_VF_LINK_STATE_DISABLE:
		vf_infos[HW_VF_ID_TO_OS(vf_id)].link_forced = true;
		vf_infos[HW_VF_ID_TO_OS(vf_id)].link_up = false;
		link_status = HINIC5_LINK_DOWN;
		break;
	default:
		return -EINVAL;
	}

	/* Notify the VF of its new link state */
	hinic5_notify_vf_link_status(nic_io, vf_id, link_status);

	return 0;
}

int hinic5_set_vf_spoofchk(void *hwdev, u16 vf_id, bool spoofchk)
{
	struct hinic5_cmd_spoofchk_set spoofchk_cfg;
	struct vf_data_storage *vf_infos = NULL;
	u16 out_size = sizeof(spoofchk_cfg);
	struct hinic5_nic_io *nic_io = NULL;
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	vf_infos = nic_io->vf_infos;

	memset(&spoofchk_cfg, 0, sizeof(spoofchk_cfg));

	spoofchk_cfg.func_id = hinic5_glb_pf_vf_offset(hwdev) + vf_id;
	spoofchk_cfg.state = spoofchk ? 1 : 0;
	err = hinic5_l2nic_msg_to_mgmt_sync(hwdev, HINIC5_NIC_CMD_SET_SPOOFCHK_STATE,
				     &spoofchk_cfg,
				     sizeof(spoofchk_cfg), &spoofchk_cfg,
				     &out_size);
	if (err != 0 || out_size == 0 || spoofchk_cfg.msg_head.status != 0) {
		nic_err(nic_io->dev_hdl, "Failed to set VF(%d) spoofchk, err: %d, status: 0x%x, out size: 0x%x\n",
			HW_VF_ID_TO_OS(vf_id), err,
			spoofchk_cfg.msg_head.status, out_size);
		err = -EINVAL;
	}

	vf_infos[HW_VF_ID_TO_OS(vf_id)].spoofchk = spoofchk;

	return err;
}

bool hinic5_vf_info_spoofchk(void *hwdev, int vf_id)
{
	struct hinic5_nic_io *nic_io = NULL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return false;

	return nic_io->vf_infos[HW_VF_ID_TO_OS(vf_id)].spoofchk;
}

#ifdef HAVE_NDO_SET_VF_TRUST
int hinic5_set_vf_trust(void *hwdev, u16 vf_id, bool trust)
{
	struct hinic5_nic_io *nic_io = NULL;
	struct hinic5_cmd_vf_trust_config vf_trust = {0};
	u16 out_size = sizeof(vf_trust);
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io || vf_id > nic_io->max_vfs)
		return -EINVAL;

	vf_trust.func_id = hinic5_glb_pf_vf_offset(nic_io->hwdev) + vf_id;
	vf_trust.trust = (u8)trust;

	nic_io->vf_infos[HW_VF_ID_TO_OS(vf_id)].trust = trust;

	err = hinic5_l2nic_msg_to_mgmt_sync(nic_io->hwdev,
				     HINIC5_NIC_CMD_CFG_VF_TRUST,
				     &vf_trust, out_size, &vf_trust,
				     &out_size);
	if (vf_trust.msg_head.status == NIC_VF_TRUST_UNSUPPORT && err == 0) {
		nic_info(nic_io->dev_hdl, "Succeeded to set vf trust to driver, did not set vf trust to chip\n");
		return 0;
	}
	if (err != 0 || out_size == 0 || vf_trust.msg_head.status != 0)
		nic_warn(nic_io->dev_hdl, "Failed to set vf trust, err: %d, out_size: 0x%x, status:0x%x\n",
			 err, out_size, vf_trust.msg_head.status);

	return 0;
}

bool hinic5_get_vf_trust(void *hwdev, int vf_id)
{
	struct hinic5_nic_io *nic_io = NULL;

	if (!hwdev)
		return false;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io || vf_id > nic_io->max_vfs)
		return false;

	return nic_io->vf_infos[HW_VF_ID_TO_OS(vf_id)].trust;
}
#endif

static int hinic5_set_vf_tx_rate_max_min(struct hinic5_nic_io *nic_io,
					 u16 vf_id, u32 max_rate, u32 min_rate)
{
	struct hinic5_cmd_rate_cfg rate_cfg;
	struct hinic5_cmd_rate_cfg_ret rate_cfg_ret = {0};
	u16 out_size = sizeof(rate_cfg_ret);
	int err;

	memset(&rate_cfg, 0, sizeof(rate_cfg));

	rate_cfg.func_id = hinic5_glb_pf_vf_offset(nic_io->hwdev) + vf_id;
	rate_cfg.pir = max_rate;
	rate_cfg.cir = min_rate;
	rate_cfg.direct = NIC_RATE_DIRECT_TX_BW;
	rate_cfg.cfg_mode = NIC_RATE_OP_SET;
	err = hinic5_l2nic_msg_to_mgmt_sync(nic_io->hwdev,
				     HINIC5_NIC_CMD_SET_MAX_MIN_RATE,
				     &rate_cfg, sizeof(rate_cfg), &rate_cfg_ret,
				     &out_size);
	if (rate_cfg_ret.msg_head.status != 0 || err != 0 || out_size == 0) {
		nic_err(nic_io->dev_hdl, "Failed to set VF %d max rate %u, min rate %u, err: %d, status: 0x%x, out size: 0x%x\n",
			HW_VF_ID_TO_OS(vf_id), max_rate, min_rate, err,
			rate_cfg_ret.msg_head.status, out_size);
		return -EIO;
	}

	return 0;
}

int hinic5_set_vf_tx_rate(void *hwdev, u16 vf_id, u32 max_rate, u32 min_rate)
{
	struct hinic5_nic_io *nic_io = NULL;
	int err;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;
	if (!HINIC5_SUPPORT_RATE_LIMIT(hwdev)) {
		nic_err(nic_io->dev_hdl, "Current function doesn't support to set vf rate limit\n");
		return -EOPNOTSUPP;
	}

	err = hinic5_set_vf_tx_rate_max_min(nic_io, vf_id, max_rate, min_rate);
	if (err != 0)
		return err;

	nic_io->vf_infos[HW_VF_ID_TO_OS(vf_id)].max_rate = max_rate;
	nic_io->vf_infos[HW_VF_ID_TO_OS(vf_id)].min_rate = min_rate;

	return 0;
}

void hinic5_get_vf_config(void *hwdev, u16 vf_id, struct ifla_vf_info *ivi)
{
	struct vf_data_storage *vfinfo = NULL;
	struct hinic5_nic_io *nic_io = NULL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return;

	vfinfo = HW_VF_ID_TO_OS_CO(nic_io->vf_infos, vf_id);
	if (!vfinfo)
		return;

	ivi->vf = HW_VF_ID_TO_OS(vf_id);
	ether_addr_copy(ivi->mac, vfinfo->user_mac_addr);
	ivi->vlan = vfinfo->pf_vlan;
	ivi->qos = vfinfo->pf_qos;

#ifdef HAVE_VF_SPOOFCHK_CONFIGURE
	ivi->spoofchk = vfinfo->spoofchk;
#endif

#ifdef HAVE_NDO_SET_VF_TRUST
	ivi->trusted = vfinfo->trust;
#endif

#ifdef HAVE_NDO_SET_VF_MIN_MAX_TX_RATE
	ivi->max_tx_rate = vfinfo->max_rate;
	ivi->min_tx_rate = vfinfo->min_rate;
#else
	ivi->tx_rate = vfinfo->max_rate;
#endif /* HAVE_NDO_SET_VF_MIN_MAX_TX_RATE */

#ifdef HAVE_NDO_SET_VF_LINK_STATE
	if (!vfinfo->link_forced)
		ivi->linkstate = IFLA_VF_LINK_STATE_AUTO;
	else if (vfinfo->link_up)
		ivi->linkstate = IFLA_VF_LINK_STATE_ENABLE;
	else
		ivi->linkstate = IFLA_VF_LINK_STATE_DISABLE;
#endif
}

static int hinic5_init_vf_infos(struct hinic5_nic_io *nic_io, u16 vf_id)
{
	struct vf_data_storage *vf_infos = nic_io->vf_infos;
	u8 vf_link_state;

	if (set_vf_link_state > HINIC5_IFLA_VF_LINK_STATE_DISABLE) {
		nic_warn(nic_io->dev_hdl, "Module Parameter set_vf_link_state value %u is out of range, resetting to %d\n",
			 set_vf_link_state, HINIC5_IFLA_VF_LINK_STATE_AUTO);
		set_vf_link_state = HINIC5_IFLA_VF_LINK_STATE_AUTO;
	}

	vf_link_state = set_vf_link_state;

	switch (vf_link_state) {
	case HINIC5_IFLA_VF_LINK_STATE_AUTO:
		vf_infos[vf_id].link_forced = false;
		break;
	case HINIC5_IFLA_VF_LINK_STATE_ENABLE:
		vf_infos[vf_id].link_forced = true;
		vf_infos[vf_id].link_up = true;
		break;
	case HINIC5_IFLA_VF_LINK_STATE_DISABLE:
		vf_infos[vf_id].link_forced = true;
		vf_infos[vf_id].link_up = false;
		break;
	default:
		nic_err(nic_io->dev_hdl, "Input parameter set_vf_link_state error: %u\n",
			vf_link_state);
		return -EINVAL;
	}

	return 0;
}

static int vf_func_register(struct hinic5_nic_io *nic_io)
{
	struct hinic5_cmd_register_vf register_info;
	u16 out_size = sizeof(register_info);
	int err;

	err = hinic5_register_vf_mbox_cb(nic_io->hwdev, HINIC5_MOD_L2NIC,
					 nic_io->hwdev, hinic5_vf_event_handler);
	if (err != 0)
		return err;

	err = hinic5_register_vf_mbox_cb(nic_io->hwdev, HINIC5_MOD_HILINK,
					 nic_io->hwdev, hinic5_vf_mag_event_handler);
	if (err != 0)
		goto reg_hilink_err;

	if (hinic5_is_slave_host(nic_io->hwdev)) {
		nic_info(nic_io->dev_hdl, "The VF(slave host) does not need to register with the PF.");
		return 0;
	}

	if (hinic5_is_vf_isolation(nic_io->hwdev)) {
		nic_info(nic_io->dev_hdl, "The isolated VF does not need to register with the PF.");
		return 0;
	}

	memset(&register_info, 0, sizeof(register_info));
	register_info.op_register = 1;
	register_info.support_extra_feature = 0;
	err = hinic5_mbox_to_pf(nic_io->hwdev, HINIC5_MOD_L2NIC,
				HINIC5_NIC_CMD_VF_REGISTER,
				&register_info, sizeof(register_info),
				&register_info, &out_size, 0,
				HINIC5_CHANNEL_NIC);
	if (err != 0 || out_size == 0 || register_info.msg_head.status != 0) {
		nic_err(nic_io->dev_hdl, "Failed to register VF, err: %d, status: 0x%x, out size: 0x%x\n",
			err, register_info.msg_head.status, out_size);
		err = -EIO;
		goto register_err;
	}

	return 0;

register_err:
	hinic5_unregister_vf_mbox_cb(nic_io->hwdev, HINIC5_MOD_HILINK);

reg_hilink_err:
	hinic5_unregister_vf_mbox_cb(nic_io->hwdev, HINIC5_MOD_L2NIC);

	return err;
}

static int pf_init_vf_infos(struct hinic5_nic_io *nic_io)
{
	u32 size;
	int err;
	u16 i;

	nic_io->max_vfs = hinic5_func_max_vf(nic_io->hwdev);
	size = sizeof(*nic_io->vf_infos) * nic_io->max_vfs;
	if (size == 0)
		return 0;

	nic_io->vf_infos = kzalloc(size, GFP_KERNEL);
	if (!nic_io->vf_infos)
		return -ENOMEM;

	for (i = 0; i < nic_io->max_vfs; i++) {
		err = hinic5_init_vf_infos(nic_io, i);
		if (err != 0)
			goto init_vf_infos_err;
	}

	err = hinic5_register_pf_mbox_cb(nic_io->hwdev, HINIC5_MOD_L2NIC,
					 nic_io->hwdev, hinic5_pf_mbox_handler);
	if (err != 0)
		goto register_pf_mbox_cb_err;

	err = hinic5_register_pf_mbox_cb(nic_io->hwdev, HINIC5_MOD_HILINK,
					 nic_io->hwdev, hinic5_pf_mag_mbox_handler);
	if (err != 0)
		goto register_pf_mag_mbox_cb_err;

	return 0;

register_pf_mag_mbox_cb_err:
	hinic5_unregister_pf_mbox_cb(nic_io->hwdev, HINIC5_MOD_L2NIC);

register_pf_mbox_cb_err:
init_vf_infos_err:
	kfree(nic_io->vf_infos);

	return err;
}

int hinic5_vf_func_init(struct hinic5_nic_io *nic_io)
{
	int err;

	err = hinic5_register_mgmt_msg_cb(nic_io->hwdev, HINIC5_MOD_L2NIC,
					  nic_io->hwdev, hinic5_mgmt_event_handler);
	if (err != 0)
		return err;

	if (hinic5_func_type(nic_io->hwdev) == TYPE_VF)
		return vf_func_register(nic_io);

	err = hinic5_register_mgmt_msg_cb(nic_io->hwdev, HINIC5_MOD_HILINK,
					  nic_io->hwdev, hinic5_pf_mag_event_handler);
	if (err != 0)
		goto register_mgmt_msg_cb_err;

	err = pf_init_vf_infos(nic_io);
	if (err != 0)
		goto pf_init_vf_infos_err;

	return 0;

pf_init_vf_infos_err:
	hinic5_unregister_mgmt_msg_cb(nic_io->hwdev, HINIC5_MOD_HILINK);
register_mgmt_msg_cb_err:
	hinic5_unregister_mgmt_msg_cb(nic_io->hwdev, HINIC5_MOD_L2NIC);

	return err;
}

void hinic5_vf_func_free(struct hinic5_nic_io *nic_io)
{
	struct hinic5_cmd_register_vf unregister;
	u16 out_size = sizeof(unregister);
	int err;

	memset(&unregister, 0, sizeof(unregister));
	unregister.op_register = 0;
	if (hinic5_func_type(nic_io->hwdev) == TYPE_VF) {
		do {
			if (hinic5_is_slave_host(nic_io->hwdev)) {
				nic_info(nic_io->dev_hdl, "The VF(slave host) does not need to unregister with the PF.");
				break;
			}
			if (hinic5_is_vf_isolation(nic_io->hwdev)) {
				nic_info(nic_io->dev_hdl, "The isolated VF does not need to unregister with the PF.");
				break;
			}
			err = hinic5_mbox_to_pf(nic_io->hwdev, HINIC5_MOD_L2NIC,
						HINIC5_NIC_CMD_VF_REGISTER,
						&unregister, sizeof(unregister),
						&unregister, &out_size, 0,
						HINIC5_CHANNEL_NIC);
			if (err != 0 || out_size == 0 || unregister.msg_head.status != 0) {
				nic_err(nic_io->dev_hdl, "Failed to unregister VF, err: %d, status: 0x%x, out_size: 0x%x\n",
					err, unregister.msg_head.status, out_size);
			}
		} while (0);
		hinic5_unregister_vf_mbox_cb(nic_io->hwdev, HINIC5_MOD_HILINK);
		hinic5_unregister_vf_mbox_cb(nic_io->hwdev, HINIC5_MOD_L2NIC);
	} else {
		if (nic_io->vf_infos) {
			hinic5_unregister_pf_mbox_cb(nic_io->hwdev, HINIC5_MOD_HILINK);
			hinic5_unregister_pf_mbox_cb(nic_io->hwdev, HINIC5_MOD_L2NIC);
			hinic5_clear_vfs_info(nic_io->hwdev, 0, nic_io->max_vfs);
			kfree(nic_io->vf_infos);
			nic_io->vf_infos = NULL;
		}
		hinic5_unregister_mgmt_msg_cb(nic_io->hwdev, HINIC5_MOD_HILINK);
		hinic5_unregister_mgmt_msg_cb(nic_io->hwdev, HINIC5_MOD_L2NIC);
	}
}

static void clear_vf_infos(void *hwdev, u16 vf_id)
{
	struct vf_data_storage *vf_infos = NULL;
	struct hinic5_nic_io *nic_io = NULL;
	u16 func_id;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io) {
		pr_err("Nic io is null\n");
		return;
	}

	func_id = hinic5_glb_pf_vf_offset(hwdev) + vf_id;
	vf_infos = HW_VF_ID_TO_OS_CO(nic_io->vf_infos, vf_id);
	if (vf_infos->use_specified_mac)
		hinic5_del_mac(hwdev, vf_infos->drv_mac_addr,
			       vf_infos->pf_vlan, func_id, HINIC5_CHANNEL_NIC);

	if (hinic5_vf_info_vlanprio(hwdev, vf_id) != 0)
		hinic5_kill_vf_vlan(hwdev, vf_id);

	if (vf_infos->max_rate != 0)
		hinic5_set_vf_tx_rate(hwdev, vf_id, 0, 0);

	if (vf_infos->spoofchk)
		hinic5_set_vf_spoofchk(hwdev, vf_id, false);

#ifdef HAVE_NDO_SET_VF_TRUST
	if (vf_infos->trust)
		hinic5_set_vf_trust(hwdev, vf_id, false);
#endif

	memset(vf_infos, 0, sizeof(*vf_infos));
	/* set vf_infos to default */
	hinic5_init_vf_infos(nic_io, HW_VF_ID_TO_OS(vf_id));
}

void hinic5_clear_vfs_info(void *hwdev, u32 start_vf_id, u32 end_vf_id)
{
	struct hinic5_nic_io *nic_io =
			hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	u16 i;

	if (!nic_io) {
		pr_err("Nic io is null\n");
		return;
	}

	for (i = 0; i < nic_io->max_vfs; i++)
		clear_vf_infos(hwdev, OS_VF_ID_TO_HW(i));
}
