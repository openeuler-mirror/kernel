// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/ethtool.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/module.h>

#include "sphw_crm.h"
#include "sphw_hw.h"
#include "spnic_nic_io.h"
#include "spnic_nic_cfg.h"
#include "spnic_nic.h"
#include "spnic_nic_cmd.h"

static int spnic_init_vf_config(struct spnic_nic_cfg *nic_cfg, u16 vf_id)
{
	struct vf_data_storage *vf_info;
	u16 func_id;
	int err = 0;

	vf_info = nic_cfg->vf_infos + HW_VF_ID_TO_OS(vf_id);
	ether_addr_copy(vf_info->drv_mac_addr, vf_info->user_mac_addr);
	if (!is_zero_ether_addr(vf_info->drv_mac_addr)) {
		vf_info->use_specified_mac = true;
		func_id = sphw_glb_pf_vf_offset(nic_cfg->hwdev) + vf_id;

		err = spnic_set_mac(nic_cfg->hwdev, vf_info->drv_mac_addr,
				    vf_info->pf_vlan, func_id, SPHW_CHANNEL_NIC);
		if (err) {
			nic_err(nic_cfg->dev_hdl, "Failed to set VF %d MAC\n",
				HW_VF_ID_TO_OS(vf_id));
			return err;
		}
	} else {
		vf_info->use_specified_mac = false;
	}

	if (spnic_vf_info_vlanprio(nic_cfg->hwdev, vf_id)) {
		err = spnic_cfg_vf_vlan(nic_cfg, SPNIC_CMD_OP_ADD,
					vf_info->pf_vlan, vf_info->pf_qos, vf_id);
		if (err) {
			nic_err(nic_cfg->dev_hdl, "Failed to add VF %d VLAN_QOS\n",
				HW_VF_ID_TO_OS(vf_id));
			return err;
		}
	}

	if (vf_info->max_rate) {
		err = spnic_set_vf_tx_rate(nic_cfg->hwdev, vf_id, vf_info->max_rate,
					   vf_info->min_rate);
		if (err) {
			nic_err(nic_cfg->dev_hdl, "Failed to set VF %d max rate %u, min rate %u\n",
				HW_VF_ID_TO_OS(vf_id), vf_info->max_rate,
				vf_info->min_rate);
			return err;
		}
	}

	return 0;
}

static int register_vf_msg_handler(struct spnic_nic_cfg *nic_cfg, u16 vf_id)
{
	int err;

	if (vf_id > nic_cfg->max_vfs) {
		nic_err(nic_cfg->dev_hdl, "Register VF id %d exceed limit[0-%d]\n",
			HW_VF_ID_TO_OS(vf_id), HW_VF_ID_TO_OS(nic_cfg->max_vfs));
		return -EFAULT;
	}

	err = spnic_init_vf_config(nic_cfg, vf_id);
	if (err)
		return err;

	nic_cfg->vf_infos[HW_VF_ID_TO_OS(vf_id)].registered = true;

	return 0;
}

static int unregister_vf_msg_handler(struct spnic_nic_cfg *nic_cfg, u16 vf_id)
{
	struct vf_data_storage *vf_info =
		nic_cfg->vf_infos + HW_VF_ID_TO_OS(vf_id);
	struct spnic_port_mac_set mac_info;
	u16 out_size = sizeof(mac_info);
	int err;

	if (vf_id > nic_cfg->max_vfs)
		return -EFAULT;

	vf_info->registered = false;

	memset(&mac_info, 0, sizeof(mac_info));
	mac_info.func_id = sphw_glb_pf_vf_offset(nic_cfg->hwdev) + (u16)vf_id;
	mac_info.vlan_id = vf_info->pf_vlan;
	ether_addr_copy(mac_info.mac, vf_info->drv_mac_addr);

	if (vf_info->use_specified_mac || vf_info->pf_vlan) {
		err = l2nic_msg_to_mgmt_sync(nic_cfg->hwdev, SPNIC_NIC_CMD_DEL_MAC,
					     &mac_info, sizeof(mac_info), &mac_info, &out_size);
		if (err || mac_info.msg_head.status || !out_size) {
			nic_err(nic_cfg->dev_hdl, "Failed to delete VF %d MAC, err: %d, status: 0x%x, out size: 0x%x\n",
				HW_VF_ID_TO_OS(vf_id), err,
				mac_info.msg_head.status, out_size);
			return -EFAULT;
		}
	}

	memset(vf_info->drv_mac_addr, 0, ETH_ALEN);

	return 0;
}

static int spnic_register_vf_msg_handler(struct spnic_nic_cfg *nic_cfg,
					 u16 vf_id, void *buf_in, u16 in_size,
					 void *buf_out, u16 *out_size)
{
	struct spnic_cmd_register_vf *register_vf = buf_in;
	struct spnic_cmd_register_vf *register_info = buf_out;
	int err;

	if (register_vf->op_register)
		err = register_vf_msg_handler(nic_cfg, vf_id);
	else
		err = unregister_vf_msg_handler(nic_cfg, vf_id);

	if (err)
		register_info->msg_head.status = EFAULT;

	*out_size = sizeof(*register_info);

	return 0;
}

static int spnic_get_vf_cos_msg_handler(struct spnic_nic_cfg *nic_cfg, u16 vf_id, void *buf_in,
					u16 in_size, void *buf_out, u16 *out_size)
{
	struct spnic_cmd_vf_dcb_state *dcb_state = buf_out;

	memcpy(&dcb_state->state, &nic_cfg->dcb_state,
	       sizeof(nic_cfg->dcb_state));

	dcb_state->msg_head.status = 0;
	*out_size = sizeof(*dcb_state);
	return 0;
}

static int spnic_get_vf_mac_msg_handler(struct spnic_nic_cfg *nic_cfg, u16 vf,
					void *buf_in, u16 in_size, void *buf_out, u16 *out_size)
{
	struct vf_data_storage *vf_info = nic_cfg->vf_infos + HW_VF_ID_TO_OS(vf);
	struct spnic_port_mac_set *mac_info = buf_out;

	int err;

	if (sphw_support_ovs(nic_cfg->hwdev, NULL)) {
		err = l2nic_msg_to_mgmt_sync(nic_cfg->hwdev, SPNIC_NIC_CMD_GET_MAC, buf_in,
					     in_size, buf_out, out_size);
		if (!err) {
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

static int spnic_set_vf_mac_msg_handler(struct spnic_nic_cfg *nic_cfg, u16 vf,
					void *buf_in, u16 in_size, void *buf_out, u16 *out_size)
{
	struct vf_data_storage *vf_info = nic_cfg->vf_infos + HW_VF_ID_TO_OS(vf);
	struct spnic_port_mac_set *mac_in = buf_in;
	struct spnic_port_mac_set *mac_out = buf_out;
	int err;

	if (vf_info->use_specified_mac && !vf_info->trust &&
	    is_valid_ether_addr(mac_in->mac)) {
		nic_warn(nic_cfg->dev_hdl, "PF has already set VF %d MAC address, and vf trust is off.\n",
			 HW_VF_ID_TO_OS(vf));
		mac_out->msg_head.status = SPNIC_PF_SET_VF_ALREADY;
		*out_size = sizeof(*mac_out);
		return 0;
	}

	if (is_valid_ether_addr(mac_in->mac))
		mac_in->vlan_id = vf_info->pf_vlan;

	err = l2nic_msg_to_mgmt_sync(nic_cfg->hwdev, SPNIC_NIC_CMD_SET_MAC,
				     buf_in, in_size, buf_out, out_size);
	if (err || !(*out_size)) {
		nic_err(nic_cfg->dev_hdl, "Failed to set VF %d MAC address, err: %d,status: 0x%x, out size: 0x%x\n",
			HW_VF_ID_TO_OS(vf), err, mac_out->msg_head.status,
			*out_size);
		return -EFAULT;
	}

	if (is_valid_ether_addr(mac_in->mac) && !mac_out->msg_head.status)
		ether_addr_copy(vf_info->drv_mac_addr, mac_in->mac);

	return err;
}

static int spnic_del_vf_mac_msg_handler(struct spnic_nic_cfg *nic_cfg, u16 vf,
					void *buf_in, u16 in_size, void *buf_out, u16 *out_size)
{
	struct vf_data_storage *vf_info = nic_cfg->vf_infos + HW_VF_ID_TO_OS(vf);
	struct spnic_port_mac_set *mac_in = buf_in;
	struct spnic_port_mac_set *mac_out = buf_out;
	int err;

	if (vf_info->use_specified_mac && !vf_info->trust &&
	    is_valid_ether_addr(mac_in->mac)) {
		nic_warn(nic_cfg->dev_hdl, "PF has already set VF %d MAC address, and vf trust is off.\n",
			 HW_VF_ID_TO_OS(vf));
		mac_out->msg_head.status = SPNIC_PF_SET_VF_ALREADY;
		*out_size = sizeof(*mac_out);
		return 0;
	}

	if (is_valid_ether_addr(mac_in->mac))
		mac_in->vlan_id = vf_info->pf_vlan;

	err = l2nic_msg_to_mgmt_sync(nic_cfg->hwdev, SPNIC_NIC_CMD_DEL_MAC,
				     buf_in, in_size, buf_out, out_size);
	if (err || !(*out_size)) {
		nic_err(nic_cfg->dev_hdl, "Failed to delete VF %d MAC, err: %d, status: 0x%x, out size: 0x%x\n",
			HW_VF_ID_TO_OS(vf), err, mac_out->msg_head.status,
			*out_size);
		return -EFAULT;
	}

	if (is_valid_ether_addr(mac_in->mac) && !mac_out->msg_head.status)
		eth_zero_addr(vf_info->drv_mac_addr);

	return err;
}

static int spnic_update_vf_mac_msg_handler(struct spnic_nic_cfg *nic_cfg,
					   u16 vf, void *buf_in, u16 in_size,
					   void *buf_out, u16 *out_size)
{
	struct vf_data_storage *vf_info = nic_cfg->vf_infos + HW_VF_ID_TO_OS(vf);
	struct spnic_port_mac_update *mac_in = buf_in;
	struct spnic_port_mac_update *mac_out = buf_out;
	int err;

	if (!is_valid_ether_addr(mac_in->new_mac)) {
		nic_err(nic_cfg->dev_hdl, "Update VF MAC is invalid.\n");
		return -EINVAL;
	}

	if (vf_info->use_specified_mac && !vf_info->trust) {
		nic_warn(nic_cfg->dev_hdl, "PF has already set VF %d MAC address, and vf trust is off.\n",
			 HW_VF_ID_TO_OS(vf));
		mac_out->msg_head.status = SPNIC_PF_SET_VF_ALREADY;
		*out_size = sizeof(*mac_out);
		return 0;
	}

	mac_in->vlan_id = vf_info->pf_vlan;
	err = l2nic_msg_to_mgmt_sync(nic_cfg->hwdev, SPNIC_NIC_CMD_UPDATE_MAC,
				     buf_in, in_size, buf_out, out_size);
	if (err || !(*out_size)) {
		nic_warn(nic_cfg->dev_hdl, "Failed to update VF %d MAC, err: %d,status: 0x%x, out size: 0x%x\n",
			 HW_VF_ID_TO_OS(vf), err, mac_out->msg_head.status,
			 *out_size);
		return -EFAULT;
	}

	if (!mac_out->msg_head.status)
		ether_addr_copy(vf_info->drv_mac_addr, mac_in->new_mac);

	return err;
}

const struct vf_msg_handler vf_cmd_handler[] = {
	{
		.cmd = SPNIC_NIC_CMD_VF_REGISTER,
		.handler = spnic_register_vf_msg_handler,
	},

	{
		.cmd = SPNIC_NIC_CMD_GET_MAC,
		.handler = spnic_get_vf_mac_msg_handler,
	},

	{
		.cmd = SPNIC_NIC_CMD_SET_MAC,
		.handler = spnic_set_vf_mac_msg_handler,
	},

	{
		.cmd = SPNIC_NIC_CMD_DEL_MAC,
		.handler = spnic_del_vf_mac_msg_handler,
	},

	{
		.cmd = SPNIC_NIC_CMD_UPDATE_MAC,
		.handler = spnic_update_vf_mac_msg_handler,
	},

	{
		.cmd = SPNIC_NIC_CMD_VF_COS,
		.handler = spnic_get_vf_cos_msg_handler
	},
};

static int _l2nic_msg_to_mgmt_sync(void *hwdev, u16 cmd, void *buf_in,
				   u16 in_size, void *buf_out, u16 *out_size, u16 channel)
{
	u32 i, cmd_cnt = ARRAY_LEN(vf_cmd_handler);
	bool cmd_to_pf = false;

	if (sphw_func_type(hwdev) == TYPE_VF) {
		for (i = 0; i < cmd_cnt; i++) {
			if (cmd == vf_cmd_handler[i].cmd)
				cmd_to_pf = true;
		}
	}

	if (cmd_to_pf)
		return sphw_mbox_to_pf(hwdev, SPHW_MOD_L2NIC, cmd, buf_in, in_size, buf_out,
				       out_size, 0, channel);

	return sphw_msg_to_mgmt_sync(hwdev, SPHW_MOD_L2NIC, cmd, buf_in, in_size, buf_out,
				     out_size, 0, channel);
}

int l2nic_msg_to_mgmt_sync(void *hwdev, u16 cmd, void *buf_in, u16 in_size,
			   void *buf_out, u16 *out_size)
{
	return _l2nic_msg_to_mgmt_sync(hwdev, cmd, buf_in, in_size, buf_out,
				       out_size, SPHW_CHANNEL_NIC);
}

int l2nic_msg_to_mgmt_sync_ch(void *hwdev, u16 cmd, void *buf_in, u16 in_size,
			      void *buf_out, u16 *out_size, u16 channel)
{
	return _l2nic_msg_to_mgmt_sync(hwdev, cmd, buf_in, in_size, buf_out, out_size, channel);
}

/* pf/ppf handler mbox msg from vf */
int spnic_pf_mbox_handler(void *hwdev, void *pri_handle,
			  u16 vf_id, u16 cmd, void *buf_in, u16 in_size,
			  void *buf_out, u16 *out_size)
{
	u32 index, cmd_size = ARRAY_LEN(vf_cmd_handler);
	struct spnic_nic_cfg *nic_cfg = NULL;

	if (!hwdev)
		return -EFAULT;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	for (index = 0; index < cmd_size; index++) {
		if (cmd == vf_cmd_handler[index].cmd)
			return vf_cmd_handler[index].handler(nic_cfg, vf_id, buf_in, in_size,
							     buf_out, out_size);
	}

	nic_warn(nic_cfg->dev_hdl, "NO handler for nic cmd(%u) received from vf id: %u\n",
		 cmd, vf_id);

	return -EINVAL;
}

void spnic_notify_dcb_state_event(struct spnic_nic_cfg *nic_cfg, struct spnic_dcb_state *dcb_state)
{
	struct sphw_event_info event_info = {0};

	/* This is 8 user priority to cos mapping relationships */
	sdk_info(nic_cfg->dev_hdl, "DCB %s, default cos %u, up2cos %u%u%u%u%u%u%u%u\n",
		 dcb_state->dcb_on ? "on" : "off", dcb_state->default_cos,
		 dcb_state->up_cos[0], dcb_state->up_cos[1],
		 dcb_state->up_cos[2], dcb_state->up_cos[3],
		 dcb_state->up_cos[4], dcb_state->up_cos[5],
		 dcb_state->up_cos[6], dcb_state->up_cos[7]);

	/* Saved in sdk for statefull module */
	spnic_save_dcb_state(nic_cfg, dcb_state);

	event_info.type = SPHW_EVENT_DCB_STATE_CHANGE;
	memcpy(&event_info.dcb_state, dcb_state, sizeof(event_info.dcb_state));

	sphw_event_callback(nic_cfg->hwdev, &event_info);
}

void dcb_state_event(void *hwdev, void *buf_in, u16 in_size,
		     void *buf_out, u16 *out_size)
{
	struct spnic_cmd_vf_dcb_state *vf_dcb;
	struct spnic_nic_cfg *nic_cfg;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	vf_dcb = buf_in;
	if (!vf_dcb)
		return;

	spnic_notify_dcb_state_event(nic_cfg, &vf_dcb->state);
}

void tx_pause_excp_event_handler(void *hwdev, void *buf_in, u16 in_size,
				 void *buf_out, u16 *out_size)
{
	struct nic_cmd_tx_pause_notice *excp_info = buf_in;
	struct spnic_nic_cfg *nic_cfg = NULL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	if (in_size != sizeof(*excp_info)) {
		nic_err(nic_cfg->dev_hdl, "Invalid in_size: %u, should be %ld\n",
			in_size, sizeof(*excp_info));
		return;
	}

	nic_warn(nic_cfg->dev_hdl, "Receive tx pause exception event, excp: %u, level: %u\n",
		 excp_info->tx_pause_except, excp_info->except_level);

	sphw_fault_event_report(hwdev, SPHW_FAULT_SRC_TX_PAUSE_EXCP, (u16)excp_info->except_level);
}

struct nic_event_handler nic_cmd_handler[] = {
	{
		.cmd = SPNIC_NIC_CMD_VF_COS,
		.handler = dcb_state_event,
	},
	{
		.cmd = SPNIC_NIC_CMD_TX_PAUSE_EXCP_NOTICE,
		.handler = tx_pause_excp_event_handler,
	},
};

static void _event_handler(void *hwdev, u16 cmd, void *buf_in, u16 in_size,
			   void *buf_out, u16 *out_size)
{
	struct spnic_nic_cfg *nic_cfg = NULL;
	u32 size = sizeof(nic_cmd_handler) / sizeof(struct nic_event_handler);
	u32 i;

	if (!hwdev)
		return;

	*out_size = 0;
	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	for (i = 0; i < size; i++) {
		if (cmd == nic_cmd_handler[i].cmd) {
			nic_cmd_handler[i].handler(hwdev, buf_in, in_size, buf_out, out_size);
			break;
		}
	}

	/* can't find this event cmd */
	if (i == size)
		sdk_warn(nic_cfg->dev_hdl, "Unsupported event cmd(%u) to process\n",
			 cmd);
}

/* vf handler mbox msg from ppf/pf */
/* vf link change event
 * vf fault report event, TBD
 */
int spnic_vf_event_handler(void *hwdev, void *pri_handle, u16 cmd, void *buf_in, u16 in_size,
			   void *buf_out, u16 *out_size)
{
	_event_handler(hwdev, cmd, buf_in, in_size, buf_out, out_size);
	return 0;
}

/* pf/ppf handler mgmt cpu report nic event*/
void spnic_pf_event_handler(void *hwdev, void *pri_handle, u16 cmd, void *buf_in, u16 in_size,
			    void *buf_out, u16 *out_size)
{
	_event_handler(hwdev, cmd, buf_in, in_size, buf_out, out_size);
}

u8 spnic_nic_sw_aeqe_handler(void *hwdev, u8 event, u8 *data)
{
	struct spnic_nic_cfg *nic_cfg = NULL;

	if (!hwdev)
		return 0;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	nic_err(nic_cfg->dev_hdl, "Received nic ucode aeq event type: 0x%x, data: 0x%llx\n",
		event, *((u64 *)data));

	return 0;
}
