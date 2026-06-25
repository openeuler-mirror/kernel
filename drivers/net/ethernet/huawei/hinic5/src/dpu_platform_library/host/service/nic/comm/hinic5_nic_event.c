/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_nic_event.c
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
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/dma-mapping.h>
#include <linux/spinlock.h>
#ifndef __UEFI__
#include <linux/cpumask.h>
#endif

#include "comm_defs.h"
#include "ossl_knl.h"
#include "hinic5_crm.h"
#include "hinic5_hw.h"
#include "hinic5_nic_io.h"
#include "hinic5_nic_cfg.h"
#include "hinic5_srv_nic.h"
#include "hinic5_nic.h"
#include "nic_mpu_cmd.h"
#include "hinic5_nic_event.h"

enum hinic5_aeq_cb_state {
	HINIC5_NIC_AEQ_SW_CB_REG,
	HINIC5_NIC_AEQ_SW_CB_RUNNING,
};

#define AEQ_USLEEP_LOW_BOUND		900
#define AEQ_USLEEP_HIG_BOUND		1000

static int hinic5_init_vf_config(struct hinic5_nic_io *nic_io, u16 vf_id)
{
	struct vf_data_storage *vf_info = NULL;
	u16 func_id;
	int err = 0;

	vf_info = HW_VF_ID_TO_OS_CO(nic_io->vf_infos, vf_id);
	ether_addr_copy(vf_info->drv_mac_addr, vf_info->user_mac_addr);
	if (!is_zero_ether_addr(vf_info->drv_mac_addr)) {
		vf_info->use_specified_mac = true;
		func_id = hinic5_glb_pf_vf_offset(nic_io->hwdev) + vf_id;

		err = hinic5_set_mac(nic_io->hwdev, vf_info->drv_mac_addr,
				     vf_info->pf_vlan, func_id,
				     HINIC5_CHANNEL_NIC);
		if (err != 0) {
			nic_err(nic_io->dev_hdl, "Failed to set VF %d MAC\n",
				HW_VF_ID_TO_OS(vf_id));
			return err;
		}
	} else {
		vf_info->use_specified_mac = false;
	}

	if (hinic5_vf_info_vlanprio(nic_io->hwdev, vf_id) != 0) {
		err = hinic5_cfg_vf_vlan(nic_io, HINIC5_CMD_OP_ADD,
					 vf_info->pf_vlan, vf_info->pf_qos,
					 vf_id);
		if (err != 0) {
			nic_err(nic_io->dev_hdl, "Failed to add VF %d VLAN_QOS\n",
				HW_VF_ID_TO_OS(vf_id));
			return err;
		}
	}

	if (vf_info->max_rate != 0) {
		err = hinic5_set_vf_tx_rate(nic_io->hwdev, vf_id,
					    vf_info->max_rate,
					    vf_info->min_rate);
		if (err != 0) {
			nic_err(nic_io->dev_hdl, "Failed to set VF %d max rate %u, min rate %u\n",
				HW_VF_ID_TO_OS(vf_id), vf_info->max_rate,
				vf_info->min_rate);
			return err;
		}
	}

	return 0;
}

static int register_vf_msg_handler(struct hinic5_nic_io *nic_io, u16 vf_id)
{
	int err;

	if (vf_id > nic_io->max_vfs) {
		nic_err(nic_io->dev_hdl, "Register VF id %d exceed limit[0-%d]\n",
			HW_VF_ID_TO_OS(vf_id), HW_VF_ID_TO_OS(nic_io->max_vfs));
		return -EFAULT;
	}

	err = hinic5_init_vf_config(nic_io, vf_id);
	if (err != 0)
		return err;

	nic_io->vf_infos[HW_VF_ID_TO_OS(vf_id)].registered = true;

	return 0;
}

static int unregister_vf_msg_handler(struct hinic5_nic_io *nic_io, u16 vf_id)
{
	struct vf_data_storage *vf_info =
		HW_VF_ID_TO_OS_CO(nic_io->vf_infos, vf_id);
	struct hinic5_port_mac_set mac_info;
	u16 out_size = sizeof(mac_info);
	int err;

	if (vf_id > nic_io->max_vfs)
		return -EFAULT;

	vf_info->registered = false;

	memset(&mac_info, 0, sizeof(mac_info));
	mac_info.func_id = hinic5_glb_pf_vf_offset(nic_io->hwdev) + (u16)vf_id;
	mac_info.vlan_id = vf_info->pf_vlan;
	ether_addr_copy(mac_info.mac, vf_info->drv_mac_addr);

	if (vf_info->use_specified_mac || vf_info->pf_vlan != 0) {
		err = hinic5_l2nic_msg_to_mgmt_sync(nic_io->hwdev,
					     HINIC5_NIC_CMD_DEL_MAC,
					     &mac_info, sizeof(mac_info),
					     &mac_info, &out_size);
		if (err != 0 || out_size == 0)
			goto ERR_DEL_MAC;

		switch (mac_info.msg_head.status) {
		case 0:
			break;
		case HINIC5_DEL_MAC_NO_MATCH:
			nic_warn(nic_io->dev_hdl, "Del mac no match, Ignore delete operation.\n");
			break;
		default:
			goto ERR_DEL_MAC;
		}
	}

	memset(vf_info->drv_mac_addr, 0, ETH_ALEN);

	return 0;

ERR_DEL_MAC:
	nic_err(nic_io->dev_hdl, "Failed to delete VF %d MAC, err: %d, status: 0x%x, out size: 0x%x\n",
		HW_VF_ID_TO_OS(vf_id), err,
		mac_info.msg_head.status, out_size);
	return -EFAULT;
}

static int hinic5_register_vf_msg_handler(struct hinic5_nic_io *nic_io,
					  u16 vf_id, void *buf_in, u16 in_size,
					  void *buf_out, u16 *out_size)
{
	struct hinic5_cmd_register_vf *register_vf = buf_in;
	struct hinic5_cmd_register_vf *register_info = buf_out;
	struct vf_data_storage *vf_info = HW_VF_ID_TO_OS_CO(nic_io->vf_infos, vf_id);
	int err;

	if (!vf_info)
		return -EINVAL;

	if (register_vf->op_register != 0) {
		vf_info->support_extra_feature = register_vf->support_extra_feature;
		err = register_vf_msg_handler(nic_io, vf_id);
	} else {
		err = unregister_vf_msg_handler(nic_io, vf_id);
		vf_info->support_extra_feature = 0;
	}

	if (err != 0)
		register_info->msg_head.status = EFAULT;

	*out_size = sizeof(*register_info);

	return 0;
}

void hinic5_unregister_vf(struct hinic5_nic_io *nic_io, u16 vf_id)
{
	struct vf_data_storage *vf_info = HW_VF_ID_TO_OS_CO(nic_io->vf_infos, vf_id);

	if (!vf_info)
		return;
	unregister_vf_msg_handler(nic_io, vf_id);
	vf_info->support_extra_feature = 0;
}

static int hinic5_get_vf_cos_msg_handler(struct hinic5_nic_io *nic_io,
					 u16 vf_id, void *buf_in,
					 u16 in_size, void *buf_out,
					 u16 *out_size)
{
	struct hinic5_cmd_vf_dcb_state *dcb_state = buf_out;

	memcpy(&dcb_state->state, &nic_io->dcb_state, sizeof(nic_io->dcb_state));
	dcb_state->msg_head.status = 0;
	*out_size = sizeof(*dcb_state);
	return 0;
}

static int hinic5_get_vf_mac_msg_handler(struct hinic5_nic_io *nic_io, u16 vf,
					 void *buf_in, u16 in_size,
					 void *buf_out, u16 *out_size)
{
	struct vf_data_storage *vf_info = HW_VF_ID_TO_OS_CO(nic_io->vf_infos, vf);
	struct hinic5_port_mac_set *mac_in = (struct hinic5_port_mac_set *)buf_in;
	struct hinic5_port_mac_set *mac_info = buf_out;
	int err;

	if (!mac_info || !vf_info)
		return -EINVAL;

	mac_in->func_id = vf + hinic5_glb_pf_vf_offset(nic_io->hwdev);

	if (HINIC5_SUPPORT_VF_MAC(nic_io->hwdev) != 0) {
		err = hinic5_l2nic_msg_to_mgmt_sync(nic_io->hwdev, HINIC5_NIC_CMD_GET_MAC, buf_in,
					     in_size, buf_out, out_size);
		if (err == 0) {
			if (is_zero_ether_addr(mac_info->mac))
				ether_addr_copy(mac_info->mac, vf_info->drv_mac_addr);
		}
		return err;
	}

	ether_addr_copy(mac_info->mac, vf_info->drv_mac_addr);
	mac_info->msg_head.status = 0;
	*out_size = sizeof(*mac_info);

	return 0;
}

static int hinic5_set_vf_mac_msg_handler(struct hinic5_nic_io *nic_io, u16 vf,
					 void *buf_in, u16 in_size,
					 void *buf_out, u16 *out_size)
{
	struct vf_data_storage *vf_info = HW_VF_ID_TO_OS_CO(nic_io->vf_infos, vf);
	struct hinic5_port_mac_set *mac_in = buf_in;
	struct hinic5_port_mac_set *mac_out = buf_out;
	int err;

	if (!vf_info)
		return -EINVAL;

	mac_in->func_id = vf + hinic5_glb_pf_vf_offset(nic_io->hwdev);

	if (vf_info->use_specified_mac && !vf_info->trust &&
	    is_valid_ether_addr(mac_in->mac)) {
		nic_warn(nic_io->dev_hdl, "PF has already set VF %d MAC address, and vf trust is off.\n",
			 HW_VF_ID_TO_OS(vf));
		mac_out->msg_head.status = HINIC5_PF_SET_VF_ALREADY;
		*out_size = sizeof(*mac_out);
		return 0;
	}

	if (is_valid_ether_addr(mac_in->mac))
		mac_in->vlan_id = vf_info->pf_vlan;

	err = hinic5_l2nic_msg_to_mgmt_sync(nic_io->hwdev, HINIC5_NIC_CMD_SET_MAC,
				     buf_in, in_size, buf_out, out_size);
	if (err != 0 || (*out_size) == 0) {
		nic_err(nic_io->dev_hdl, "Failed to set VF %d MAC address, err: %d,status: 0x%x, out size: 0x%x\n",
			HW_VF_ID_TO_OS(vf), err, mac_out->msg_head.status,
			*out_size);
		return -EFAULT;
	}

	if (is_valid_ether_addr(mac_in->mac) && mac_out->msg_head.status == 0)
		ether_addr_copy(vf_info->drv_mac_addr, mac_in->mac);

	return err;
}

static int hinic5_del_vf_mac_msg_handler(struct hinic5_nic_io *nic_io, u16 vf,
					 void *buf_in, u16 in_size,
					 void *buf_out, u16 *out_size)
{
	struct vf_data_storage *vf_info = HW_VF_ID_TO_OS_CO(nic_io->vf_infos, vf);
	struct hinic5_port_mac_set *mac_in = buf_in;
	struct hinic5_port_mac_set *mac_out = buf_out;
	int err;

	if (!vf_info)
		return -EINVAL;

	mac_in->func_id = vf + hinic5_glb_pf_vf_offset(nic_io->hwdev);

	if (vf_info->use_specified_mac && !vf_info->trust &&
	    is_valid_ether_addr(mac_in->mac)) {
		nic_warn(nic_io->dev_hdl, "PF has already set VF %d MAC address, and vf trust is off.\n",
			 HW_VF_ID_TO_OS(vf));
		mac_out->msg_head.status = HINIC5_PF_SET_VF_ALREADY;
		*out_size = sizeof(*mac_out);
		return 0;
	}

	if (is_valid_ether_addr(mac_in->mac))
		mac_in->vlan_id = vf_info->pf_vlan;

	err = hinic5_l2nic_msg_to_mgmt_sync(nic_io->hwdev, HINIC5_NIC_CMD_DEL_MAC,
				     buf_in, in_size, buf_out, out_size);
	if (err != 0 || (*out_size) == 0)
		goto ERR_DEL_MAC;

	switch (mac_out->msg_head.status) {
	case 0:
		break;
	case HINIC5_DEL_MAC_NO_MATCH:
		nic_warn(nic_io->dev_hdl, "Del mac no match, Ignore delete operation.\n");
		break;
	default:
		goto ERR_DEL_MAC;
	}

	if (is_valid_ether_addr(mac_in->mac))
		eth_zero_addr(vf_info->drv_mac_addr);

	return err;

ERR_DEL_MAC:
	nic_err(nic_io->dev_hdl, "Failed to delete VF %d MAC, err: %d, status: 0x%x, out size: 0x%x\n",
		HW_VF_ID_TO_OS(vf), err, mac_out->msg_head.status,
		*out_size);
	return -EFAULT;
}

static int hinic5_update_vf_mac_msg_handler(struct hinic5_nic_io *nic_io,
					    u16 vf, void *buf_in, u16 in_size,
					    void *buf_out, u16 *out_size)
{
	struct vf_data_storage *vf_info = HW_VF_ID_TO_OS_CO(nic_io->vf_infos, vf);
	struct hinic5_port_mac_update *mac_in = buf_in;
	struct hinic5_port_mac_update *mac_out = buf_out;
	int err;

	if (!vf_info)
		return -EINVAL;
	if (!is_valid_ether_addr(mac_in->new_mac)) {
		nic_err(nic_io->dev_hdl, "Update VF MAC is invalid.\n");
		return -EINVAL;
	}

	mac_in->func_id = vf + hinic5_glb_pf_vf_offset(nic_io->hwdev);

#ifndef __VMWARE__
	if (vf_info->use_specified_mac && !vf_info->trust) {
		nic_warn(nic_io->dev_hdl, "PF has already set VF %d MAC address, and vf trust is off.\n",
			 HW_VF_ID_TO_OS(vf));
		mac_out->msg_head.status = HINIC5_PF_SET_VF_ALREADY;
		*out_size = sizeof(*mac_out);
		return 0;
	}
#else
	err = hinic_config_vf_request(((struct hinic5_hwdev *)nic_io->hwdev)->pcidev_hdl,
				      HW_VF_ID_TO_OS(vf),
				      HINIC_CFG_VF_MAC_CHANGED,
				      (void *)mac_in->new_mac);
	if (err != 0) {
		nic_err(nic_io->dev_hdl, "Failed to config VF %d MAC request, err: %d\n",
			HW_VF_ID_TO_OS(vf), err);
		return err;
	}
#endif
	mac_in->vlan_id = vf_info->pf_vlan;
	err = hinic5_l2nic_msg_to_mgmt_sync(nic_io->hwdev, HINIC5_NIC_CMD_UPDATE_MAC,
				     buf_in, in_size, buf_out, out_size);
	if (err != 0 || (*out_size) == 0) {
		nic_warn(nic_io->dev_hdl, "Failed to update VF %d MAC, err: %d,status: 0x%x, out size: 0x%x\n",
			 HW_VF_ID_TO_OS(vf), err, mac_out->msg_head.status,
			 *out_size);
		return -EFAULT;
	}

	if (mac_out->msg_head.status == 0)
		ether_addr_copy(vf_info->drv_mac_addr, mac_in->new_mac);

	return err;
}

const struct vf_msg_handler hinic5_vf_cmd_handler[] = {
	{
		.cmd = HINIC5_NIC_CMD_VF_REGISTER,
		.handler = hinic5_register_vf_msg_handler,
	},

	{
		.cmd = HINIC5_NIC_CMD_GET_MAC,
		.handler = hinic5_get_vf_mac_msg_handler,
	},

	{
		.cmd = HINIC5_NIC_CMD_SET_MAC,
		.handler = hinic5_set_vf_mac_msg_handler,
	},

	{
		.cmd = HINIC5_NIC_CMD_DEL_MAC,
		.handler = hinic5_del_vf_mac_msg_handler,
	},

	{
		.cmd = HINIC5_NIC_CMD_UPDATE_MAC,
		.handler = hinic5_update_vf_mac_msg_handler,
	},

	{
		.cmd = HINIC5_NIC_CMD_VF_COS,
		.handler = hinic5_get_vf_cos_msg_handler
	},
};

static int _hinic5_l2nic_msg_to_mgmt_sync(void *hwdev, u16 cmd, void *buf_in,
				   u16 in_size, void *buf_out, u16 *out_size,
				   u16 channel)
{
	int i, cmd_cnt = ARRAY_LEN(hinic5_vf_cmd_handler);

	if (hinic5_func_type(hwdev) == TYPE_VF && (!hinic5_is_slave_host(hwdev))
				       && (!hinic5_is_vf_isolation(hwdev))) {
		for (i = 0; i < cmd_cnt; i++) {
			if (cmd == hinic5_vf_cmd_handler[i].cmd)
				return hinic5_mbox_to_pf(hwdev, HINIC5_MOD_L2NIC, cmd, buf_in,
					in_size, buf_out, out_size, 0, channel);
		}
	}

	return hinic5_msg_to_mgmt_sync(hwdev, HINIC5_MOD_L2NIC, cmd, buf_in,
				       in_size, buf_out, out_size, 0, channel);
}

int hinic5_l2nic_msg_to_mgmt_sync(void *hwdev, u16 cmd, void *buf_in, u16 in_size,
			   void *buf_out, u16 *out_size)
{
	return _hinic5_l2nic_msg_to_mgmt_sync(hwdev, cmd, buf_in, in_size, buf_out,
				       out_size, HINIC5_CHANNEL_NIC);
}

int hinic5_l2nic_msg_to_mgmt_sync_ch(void *hwdev, u16 cmd, void *buf_in, u16 in_size,
			      void *buf_out, u16 *out_size, u16 channel)
{
	return _hinic5_l2nic_msg_to_mgmt_sync(hwdev, cmd, buf_in, in_size, buf_out,
				       out_size, channel);
}

/* pf/ppf handler mbox msg from vf */
int hinic5_pf_mbox_handler(void *hwdev,
			   u16 vf_id, u16 cmd, void *buf_in, u16 in_size,
			   void *buf_out, u16 *out_size)
{
	int index, cmd_size = ARRAY_LEN(hinic5_vf_cmd_handler);
	struct hinic5_nic_io *nic_io = NULL;

	if (!hwdev)
		return -EFAULT;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	for (index = 0; index < cmd_size; index++) {
		if (cmd == hinic5_vf_cmd_handler[index].cmd)
			return hinic5_vf_cmd_handler[index].handler(nic_io, vf_id,
							     buf_in, in_size,
							     buf_out, out_size);
	}

	nic_warn(nic_io->dev_hdl, "NO handler for nic cmd(%u) received from vf id: %u\n",
		 cmd, vf_id);

	return -EINVAL;
}

void hinic5_notify_dcb_state_event(struct hinic5_nic_io *nic_io,
				   struct hinic5_dcb_state *dcb_state)
{
	struct hinic5_event_info event_info = {0};
	int i;

	if (dcb_state->trust == HINIC5_DCB_PCP) {
		/* This is 8 user priority to cos mapping relationships */
		nic_info(nic_io->dev_hdl, "DCB %s, default cos %u, pcp2cos %u%u%u%u%u%u%u%u\n",
			 (dcb_state->dcb_on != 0) ? "on" : "off", dcb_state->default_cos,
			 dcb_state->pcp2cos[ARRAY_INDEX_0], dcb_state->pcp2cos[ARRAY_INDEX_1],
			 dcb_state->pcp2cos[ARRAY_INDEX_2], dcb_state->pcp2cos[ARRAY_INDEX_3],
			 dcb_state->pcp2cos[ARRAY_INDEX_4], dcb_state->pcp2cos[ARRAY_INDEX_5],
			 dcb_state->pcp2cos[ARRAY_INDEX_6], dcb_state->pcp2cos[ARRAY_INDEX_7]);
	} else {
		for (i = 0; i < NIC_DCB_DSCP_NUM; i++) {
			nic_info(nic_io->dev_hdl,
				 "DCB %s, default cos %u, dscp2cos %u%u%u%u%u%u%u%u\n",
				 (dcb_state->dcb_on != 0) ? "on" : "off", dcb_state->default_cos,
				 dcb_state->dscp2cos[ARRAY_INDEX_0 + i * NIC_DCB_DSCP_NUM],
				 dcb_state->dscp2cos[ARRAY_INDEX_1 + i * NIC_DCB_DSCP_NUM],
				 dcb_state->dscp2cos[ARRAY_INDEX_2 + i * NIC_DCB_DSCP_NUM],
				 dcb_state->dscp2cos[ARRAY_INDEX_3 + i * NIC_DCB_DSCP_NUM],
				 dcb_state->dscp2cos[ARRAY_INDEX_4 + i * NIC_DCB_DSCP_NUM],
				 dcb_state->dscp2cos[ARRAY_INDEX_5 + i * NIC_DCB_DSCP_NUM],
				 dcb_state->dscp2cos[ARRAY_INDEX_6 + i * NIC_DCB_DSCP_NUM],
				 dcb_state->dscp2cos[ARRAY_INDEX_7 + i * NIC_DCB_DSCP_NUM]);
		}
	}
	/* Saved in sdk for stateful module */
	hinic5_save_dcb_state(nic_io, dcb_state);

	event_info.service = EVENT_SRV_NIC;
	event_info.type = EVENT_NIC_DCB_STATE_CHANGE;
	memcpy((void *)event_info.event_data, dcb_state, sizeof(*dcb_state));
	hinic5_event_callback(nic_io->hwdev, &event_info);
}

static void tx_pause_excp_event_handler(void *hwdev, void *buf_in, u16 in_size,
					void *buf_out, u16 *out_size)
{
	struct nic_cmd_tx_pause_notice *excp_info = buf_in;
	struct hinic5_nic_io *nic_io = NULL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io) {
		pr_err("Nic io is null\n");
		return;
	}

	if (in_size != sizeof(*excp_info)) {
		nic_err(nic_io->dev_hdl, "Invalid in_size: %u, should be %lu\n",
			in_size, sizeof(*excp_info));
		return;
	}

	nic_warn(nic_io->dev_hdl, "Receive tx pause exception event, excp: %u, level: %u\n",
		 excp_info->tx_pause_except, excp_info->except_level);

	hinic5_fault_event_report(hwdev, HINIC5_FAULT_SRC_TX_PAUSE_EXCP,
				  (u16)excp_info->except_level);
}

static void bond_active_event_handler(void *hwdev, void *buf_in, u16 in_size,
				      void *buf_out, u16 *out_size)
{
	struct hinic5_bond_active_report_info *active_info = buf_in;
	struct hinic5_nic_io *nic_io = NULL;
	struct hinic5_event_info event_info = {0};

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io) {
		pr_err("Nic io is null\n");
		return;
	}

	if (in_size != sizeof(*active_info)) {
		nic_err(nic_io->dev_hdl, "Invalid in_size: %u, should be %lu\n",
			in_size, sizeof(*active_info));
		return;
	}

	event_info.service = EVENT_SRV_NIC;
	event_info.type = HINIC5_NIC_CMD_BOND_ACTIVE_NOTICE;
	memcpy((void *)event_info.event_data, active_info, sizeof(*active_info));

	hinic5_event_callback(nic_io->hwdev, &event_info);
}

int bond_link_event_handler(struct hinic5_nic_io *nic_io, struct hinic5_bond_link_info *bond_info)
{
	int err;
	u8 link_state;
	struct mag_port_info port_info = {0};
	struct hinic5_event_info event_info = {0};
	struct hinic5_event_link_info *link_info = (void *)event_info.event_data;

	/* After bond is deleted, need to get link status from mag */
	event_info.service = EVENT_SRV_NIC;
	if (bond_info->bond_en != 0) {
		nic_info(nic_io->dev_hdl, "bond link event, link_status: %u\n",
			 bond_info->link_status);
		nic_io->feature_cap |= NIC_F_HALF_BOND_OFFLOAD;
		event_info.type = (bond_info->link_status != 0) ?
			EVENT_NIC_LINK_UP : EVENT_NIC_LINK_DOWN;
	} else {
		nic_io->feature_cap &= ~NIC_F_HALF_BOND_OFFLOAD;
		err = hinic5_get_link_state(nic_io->hwdev, &link_state);
		if (err != 0)
			return err;
		event_info.type = (link_state != 0) ? EVENT_NIC_LINK_UP : EVENT_NIC_LINK_DOWN;
	}

	err = hinic5_get_port_info(nic_io->hwdev, &port_info, HINIC5_CHANNEL_NIC);
	if (err != 0) {
		nic_warn(nic_io->dev_hdl, "Failed to get port info\n");
		return err;
	}
	link_info->valid = 1;
	link_info->autoneg_cap = port_info.autoneg_cap;
	link_info->port_type = port_info.port_type;
	link_info->duplex = port_info.duplex;
	link_info->speed = port_info.speed;
	link_info->autoneg_state = port_info.autoneg_state;

	hinic5_event_callback(nic_io->hwdev, &event_info);

	return 0;
}

void half_bond_link_event_handler(void *hwdev, void *buf_in, u16 in_size,
				  void *buf_out, u16 *out_size)
{
	int err;
	struct hinic5_bond_link_info *bond_info = buf_in;
	struct hinic5_nic_io *nic_io = NULL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io) {
		pr_err("Nic io is null\n");
		return;
	}

	if (in_size != sizeof(struct hinic5_bond_link_info)) {
		nic_err(nic_io->dev_hdl, "Invalid in_size: %u, should be %lu\n",
			in_size, sizeof(struct hinic5_bond_link_info));
		return;
	}

	err = bond_link_event_handler(nic_io, bond_info);
	if (err != 0)
		nic_err(nic_io->dev_hdl, "Failed to handle bond pf link event\n");
}

void macsec_pn_expired_msg_handler(void *hwdev, void *buf_in, u16 in_size,
				   void *buf_out, u16 *out_size)
{
	struct macsec_pn_expired_report_cmd *cmd_in = (struct macsec_pn_expired_report_cmd *)buf_in;
	struct hinic5_nic_io *nic_io = NULL;
	u8 index = 0;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io) {
		pr_err("Nic io is null\n");
		return;
	}

	if (!buf_in) {
		nic_err(nic_io->dev_hdl, "MACsec event process error, in buf is null");
		return;
	}

	if (in_size != sizeof(struct macsec_pn_expired_report_cmd)) {
		nic_err(nic_io->dev_hdl, "MACsec event process error, in size(0x%x) is invalid",
			in_size);
		return;
	}

	for (; index < cmd_in->info.pn_expired_size; index++) {
		nic_info(nic_io->dev_hdl, "MACsec pn exceeding threshold, sci=0x%llx, an=0x%x",
			 cmd_in->info.sci[index], cmd_in->info.an[index]);
		/* TODO: Report to MKA software */
	}
}

void offload_bond_cfg_event_handler(void *hwdev, void *buf_in, u16 in_size,
				    void *buf_out, u16 *out_size)
{
	struct hinic5_cmd_cfg_bond *bond_info = buf_in;
	struct hinic5_nic_io *nic_io = NULL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io) {
		pr_err("Nic io is null\n");
		return;
	}

	if (in_size != sizeof(struct hinic5_cmd_cfg_bond)) {
		nic_err(nic_io->dev_hdl, "Invalid in_size: %u, should be %lu\n",
			in_size, sizeof(struct hinic5_cmd_cfg_bond));
		return;
	}

	/* Get the enable status of offload bond arp dual send */
	if (bond_info->arp_en != 0)
		nic_io->feature_cap |= NIC_F_ARP_DUAL;
	else
		nic_io->feature_cap &= ~NIC_F_ARP_DUAL;

	nic_info(nic_io->dev_hdl, "Arp dual status: %s\n",
		 (bond_info->arp_en != 0) ? "Enable" : "Disable");
}

static const struct nic_event_handler nic_cmd_handler[] = {
	{
		.cmd = HINIC5_NIC_CMD_TX_PAUSE_EXCP_NOTICE,
		.handler = tx_pause_excp_event_handler,
	},

	{
		.cmd = HINIC5_NIC_CMD_BOND_ACTIVE_NOTICE,
		.handler = bond_active_event_handler,
	},

	{
		.cmd = HINIC5_NIC_CMD_BOND_LINK_INFO_GET,
		.handler = half_bond_link_event_handler,
	},

	{
		.cmd = HINIC5_NIC_CMD_MACSEC_PN_EXPIRED_NOTICE,
		.handler = macsec_pn_expired_msg_handler,
	},

	{
		.cmd = HINIC5_NIC_CMD_BOND_DEV_CFG,
		.handler = offload_bond_cfg_event_handler,
	},
};

static int _event_handler(void *hwdev, u16 cmd, void *buf_in, u16 in_size,
			  void *buf_out, u16 *out_size)
{
	struct hinic5_nic_io *nic_io = NULL;
	u32 size = sizeof(nic_cmd_handler) / sizeof(struct nic_event_handler);
	u32 i;

	if (!hwdev)
		return -EINVAL;

	*out_size = 0;
	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	for (i = 0; i < size; i++) {
		if (cmd == nic_cmd_handler[i].cmd) {
			nic_cmd_handler[i].handler(hwdev, buf_in, in_size,
						   buf_out, out_size);
			return 0;
		}
	}

	/* can't find this event cmd */
	nic_warn(nic_io->dev_hdl, "Unsupported nic event, cmd: %u\n", cmd);
	*out_size = sizeof(struct mgmt_msg_head);
	((struct mgmt_msg_head *)buf_out)->status = HINIC5_MGMT_CMD_UNSUPPORTED;

	return 0;
}

/* vf handler mbox msg from ppf/pf */
/* vf link change event
 * vf fault report event, TBD
 */
int hinic5_vf_event_handler(void *hwdev,
			    u16 cmd, void *buf_in, u16 in_size,
			    void *buf_out, u16 *out_size)
{
	return _event_handler(hwdev, cmd, buf_in, in_size, buf_out, out_size);
}

/* pf/ppf handler mgmt cpu report nic event */
void hinic5_mgmt_event_handler(void *hwdev, u16 cmd,
			       void *buf_in, u16 in_size,
			       void *buf_out, u16 *out_size)
{
	_event_handler(hwdev, cmd, buf_in, in_size, buf_out, out_size);
}

/**
 * hinic5_nic_sw_aeqe_cnt_handler - count ucode aeq callback for sw event
 * @dev: the pointer to nic_io
 * @event: soft event for the handler
 * @data: cqe data
 **/
u8 hinic5_nic_sw_aeqe_cnt_handler(void *dev, u8 event, u8 *data)
{
	struct hinic5_nic_io *nic_io = NULL;

	if (!dev)
		return -EINVAL;

	nic_io = (struct hinic5_nic_io *)dev;
	return hinic5_nic_sw_aeqe_stats(nic_io->hwdev, event, data);
}

/**
 * hinic5_nic_aeq_register_swe_cb - register nic aeq callback for sw event
 * @hwdev: the pointer to hwdev
 * @pri_handle: the pointer to private handler
 * @event: soft event for the handler
 * @sw_cb: callback function
 **/
int hinic5_nic_aeq_register_swe_cb(void *hwdev, void *pri_handle,
				   enum hinic5_ucode_event_type event,
				   hinic5_aeq_swe_cb nic_aeq_swe_cb)
{
	struct hinic5_nic_aeqs *nic_aeqs = NULL;
	struct hinic5_nic_io *nic_io = NULL;

	if (!hwdev || !pri_handle || !nic_aeq_swe_cb || event >= HINIC5_NIC_FATAL_ERROR_MAX)
		return -EINVAL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	nic_aeqs = nic_io->nic_aeqs;
	if (!nic_aeqs) {
		nic_err(nic_io->dev_hdl, "nic_aeqs is null\n");
		return -EINVAL;
	}

	nic_aeqs->nic_aeq_swe_cb[event] = nic_aeq_swe_cb;
	nic_aeqs->nic_aeq_swe_data[event] = pri_handle;

	set_bit(HINIC5_NIC_AEQ_SW_CB_REG, &nic_aeqs->nic_aeq_sw_cb_state[event]);

	return 0;
}

/**
 * hinic5_nic_aeq_unregister_swe_cb - unregister the nic aeq callback for sw event
 * @hwdev: the pointer to hwdev
 * @event: soft event for the handler
 **/
void hinic5_nic_aeq_unregister_swe_cb(void *hwdev, enum hinic5_ucode_event_type event)
{
	struct hinic5_nic_aeqs *nic_aeqs = NULL;
	struct hinic5_nic_io *nic_io = NULL;

	if (!hwdev || event >= HINIC5_NIC_FATAL_ERROR_MAX)
		return;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return;

	nic_aeqs = nic_io->nic_aeqs;
	if (!nic_aeqs)
		return;

	clear_bit(HINIC5_NIC_AEQ_SW_CB_REG, &nic_aeqs->nic_aeq_sw_cb_state[event]);

	while (test_bit(HINIC5_NIC_AEQ_SW_CB_RUNNING,
			&nic_aeqs->nic_aeq_sw_cb_state[event]))
		usleep_range(AEQ_USLEEP_LOW_BOUND, AEQ_USLEEP_HIG_BOUND);

	nic_aeqs->nic_aeq_swe_cb[event] = NULL;
}

/**
 * hinic5_nic_aeqe_handler -  callback for nic aeqe event
 * @hwdev: the pointer to hwdev
 * @event: soft event for the handler
 * @data: cqe data
 **/
u8 hinic5_nic_aeqe_handler(void *hwdev, u8 event, u8 *data)
{
	struct hinic5_nic_aeqs *nic_aeqs = NULL;
	struct hinic5_nic_io *nic_io = NULL;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	nic_aeqs = nic_io->nic_aeqs;

	if (!nic_aeqs) {
		nic_err(nic_io->dev_hdl, "nic_aeqs is null\n");
		return -EINVAL;
	}

	set_bit(HINIC5_NIC_AEQ_SW_CB_RUNNING,
		&nic_aeqs->nic_aeq_sw_cb_state[event]);
	if (test_bit(HINIC5_NIC_AEQ_SW_CB_REG, &nic_aeqs->nic_aeq_sw_cb_state[event]))
		nic_aeqs->nic_aeq_swe_cb[event](nic_aeqs->nic_aeq_swe_data[event], event, data);

	clear_bit(HINIC5_NIC_AEQ_SW_CB_RUNNING, &nic_aeqs->nic_aeq_sw_cb_state[event]);

	return 0;
}

/**
 * hinic5_nic_aeqs_init - init all the nic_aeqs
 * @nic_io: the pointer to nic_io
 * Return: 0 - Success, Negative - failure
 **/
int hinic5_nic_aeqs_init(struct hinic5_nic_io *nic_io)
{
	struct hinic5_nic_aeqs *nic_aeqs = NULL;
	int err;

	if (!nic_io)
		return -EINVAL;

	nic_aeqs = kzalloc(sizeof(*nic_aeqs), GFP_KERNEL);
	if (!nic_aeqs)
		return -ENOMEM;

	nic_io->nic_aeqs = nic_aeqs;

	err = hinic5_nic_aeq_register_swe_cb(nic_io->hwdev, nic_io,
					     HINIC5_INTERNAL_OTHER_FATAL_ERROR,
					     hinic5_nic_sw_aeqe_cnt_handler);
	if (err != 0) {
		nic_err(nic_io->dev_hdl, "Failed to register HINIC5_INTERNAL_OTHER_FATAL_ERROR\n");
		goto err_out;
	}
	err = hinic5_nic_aeq_register_swe_cb(nic_io->hwdev, nic_io, HINIC5_CHANNEL_BUSY,
					     hinic5_nic_sw_aeqe_cnt_handler);
	if (err != 0) {
		nic_err(nic_io->dev_hdl, "Failed to register HINIC5_CHANNEL_BUSY\n");
		goto err_out;
	}

	err = hinic5_register_stateless_aeqs(nic_io->hwdev, nic_io->hwdev,
					     (hinic5_aeq_swe_cb)hinic5_nic_aeqe_handler);
	if (err != 0) {
		nic_err(nic_io->dev_hdl, "Failed to register stateless aeqs\n");
		goto err_out;
	}

	return 0;

err_out:
	hinic5_nic_aeqs_free(nic_io);

	return err;
}

/**
 * hinic5_nic_aeqs_free - free all the nic_aeqs
 * @nic_io: the pointer to nic_io
 **/
void hinic5_nic_aeqs_free(struct hinic5_nic_io *nic_io)
{
	struct hinic5_nic_aeqs *nic_aeqs = NULL;
	u32 stateless_aeq_event;

	if (!nic_io)
		return;

	hinic5_unregister_stateless_aeqs(nic_io->hwdev);

	stateless_aeq_event = (u32)HINIC5_INTERNAL_OTHER_FATAL_ERROR;
	nic_aeqs = nic_io->nic_aeqs;

	if (!nic_aeqs)
		return;

	for (; stateless_aeq_event < (u32)HINIC5_NIC_FATAL_ERROR_MAX; stateless_aeq_event++)
		hinic5_nic_aeq_unregister_swe_cb(nic_io->hwdev,
						 (enum hinic5_ucode_event_type)stateless_aeq_event);

	kfree(nic_aeqs);
}
