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
#include "sphw_common.h"

int spnic_set_ci_table(void *hwdev, struct spnic_sq_attr *attr)
{
	struct spnic_cmd_cons_idx_attr cons_idx_attr;
	u16 out_size = sizeof(cons_idx_attr);
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	if (!hwdev || !attr)
		return -EINVAL;

	memset(&cons_idx_attr, 0, sizeof(cons_idx_attr));

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	cons_idx_attr.func_idx = sphw_global_func_id(hwdev);

	cons_idx_attr.dma_attr_off  = attr->dma_attr_off;
	cons_idx_attr.pending_limit = attr->pending_limit;
	cons_idx_attr.coalescing_time  = attr->coalescing_time;

	if (attr->intr_en) {
		cons_idx_attr.intr_en = attr->intr_en;
		cons_idx_attr.intr_idx = attr->intr_idx;
	}

	cons_idx_attr.l2nic_sqn = attr->l2nic_sqn;
	cons_idx_attr.ci_addr = attr->ci_dma_base;

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_NIC_CMD_SQ_CI_ATTR_SET,
				     &cons_idx_attr, sizeof(cons_idx_attr),
				     &cons_idx_attr, &out_size);
	if (err || !out_size || cons_idx_attr.msg_head.status) {
		sdk_err(nic_cfg->dev_hdl,
			"Failed to set ci attribute table, err: %d, status: 0x%x, out_size: 0x%x\n",
			err, cons_idx_attr.msg_head.status, out_size);
		return -EFAULT;
	}

	return 0;
}

static int spnic_check_mac_info(u8 status, u16 vlan_id)
{
	if (status && status != SPNIC_MGMT_STATUS_EXIST && status != SPNIC_PF_SET_VF_ALREADY)
		return -EINVAL;

	return 0;
}

#define SPNIC_VLAN_ID_MASK	0x7FFF

int spnic_set_mac(void *hwdev, const u8 *mac_addr, u16 vlan_id, u16 func_id, u16 channel)
{
	struct spnic_port_mac_set mac_info;
	u16 out_size = sizeof(mac_info);
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	if (!hwdev || !mac_addr)
		return -EINVAL;

	memset(&mac_info, 0, sizeof(mac_info));

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	if ((vlan_id & SPNIC_VLAN_ID_MASK) >= VLAN_N_VID) {
		nic_err(nic_cfg->dev_hdl, "Invalid VLAN number: %d\n",
			vlan_id & SPNIC_VLAN_ID_MASK);
		return -EINVAL;
	}

	mac_info.func_id = func_id;
	mac_info.vlan_id = vlan_id;
	ether_addr_copy(mac_info.mac, mac_addr);

	err = l2nic_msg_to_mgmt_sync_ch(hwdev, SPNIC_NIC_CMD_SET_MAC,
					&mac_info, sizeof(mac_info),
					&mac_info, &out_size, channel);
	if (err || !out_size || spnic_check_mac_info(mac_info.msg_head.status, mac_info.vlan_id)) {
		nic_err(nic_cfg->dev_hdl,
			"Failed to update MAC, err: %d, status: 0x%x, out size: 0x%x, channel: 0x%x\n",
			err, mac_info.msg_head.status, out_size, channel);
		return -EINVAL;
	}

	if (mac_info.msg_head.status == SPNIC_PF_SET_VF_ALREADY) {
		nic_warn(nic_cfg->dev_hdl, "PF has already set VF mac, Ignore set operation\n");
		return SPNIC_PF_SET_VF_ALREADY;
	}

	if (mac_info.msg_head.status == SPNIC_MGMT_STATUS_EXIST) {
		nic_warn(nic_cfg->dev_hdl, "MAC is repeated. Ignore update operation\n");
		return 0;
	}

	return 0;
}

int spnic_del_mac(void *hwdev, const u8 *mac_addr, u16 vlan_id, u16 func_id, u16 channel)
{
	struct spnic_port_mac_set mac_info;
	u16 out_size = sizeof(mac_info);
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	if (!hwdev || !mac_addr)
		return -EINVAL;

	memset(&mac_info, 0, sizeof(mac_info));

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	if ((vlan_id & SPNIC_VLAN_ID_MASK) >= VLAN_N_VID) {
		nic_err(nic_cfg->dev_hdl, "Invalid VLAN number: %d\n",
			(vlan_id & SPNIC_VLAN_ID_MASK));
		return -EINVAL;
	}

	mac_info.func_id = func_id;
	mac_info.vlan_id = vlan_id;
	ether_addr_copy(mac_info.mac, mac_addr);

	err = l2nic_msg_to_mgmt_sync_ch(hwdev, SPNIC_NIC_CMD_DEL_MAC,
					&mac_info, sizeof(mac_info), &mac_info,
					&out_size, channel);
	if (err || !out_size ||
	    (mac_info.msg_head.status && mac_info.msg_head.status !=
	     SPNIC_PF_SET_VF_ALREADY)) {
		nic_err(nic_cfg->dev_hdl,
			"Failed to delete MAC, err: %d, status: 0x%x, out size: 0x%x, channel: 0x%x\n",
			err, mac_info.msg_head.status, out_size, channel);
		return -EINVAL;
	}

	if (mac_info.msg_head.status == SPNIC_PF_SET_VF_ALREADY) {
		nic_warn(nic_cfg->dev_hdl, "PF has already set VF mac, Ignore delete operation.\n");
		return SPNIC_PF_SET_VF_ALREADY;
	}

	return 0;
}

int spnic_update_mac(void *hwdev, u8 *old_mac, u8 *new_mac, u16 vlan_id, u16 func_id)
{
	struct spnic_port_mac_update mac_info;
	u16 out_size = sizeof(mac_info);
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	if (!hwdev || !old_mac || !new_mac)
		return -EINVAL;

	memset(&mac_info, 0, sizeof(mac_info));

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	if ((vlan_id & SPNIC_VLAN_ID_MASK) >= VLAN_N_VID) {
		nic_err(nic_cfg->dev_hdl, "Invalid VLAN number: %d\n",
			vlan_id & SPNIC_VLAN_ID_MASK);
		return -EINVAL;
	}

	mac_info.func_id = func_id;
	mac_info.vlan_id = vlan_id;
	ether_addr_copy(mac_info.old_mac, old_mac);
	ether_addr_copy(mac_info.new_mac, new_mac);

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_NIC_CMD_UPDATE_MAC,
				     &mac_info, sizeof(mac_info),
				     &mac_info, &out_size);
	if (err || !out_size || spnic_check_mac_info(mac_info.msg_head.status, mac_info.vlan_id)) {
		nic_err(nic_cfg->dev_hdl,
			"Failed to update MAC, err: %d, status: 0x%x, out size: 0x%x\n",
			err, mac_info.msg_head.status, out_size);
		return -EINVAL;
	}

	if (mac_info.msg_head.status == SPNIC_PF_SET_VF_ALREADY) {
		nic_warn(nic_cfg->dev_hdl, "PF has already set VF MAC. Ignore update operation\n");
		return SPNIC_PF_SET_VF_ALREADY;
	}

	if (mac_info.msg_head.status == SPNIC_MGMT_STATUS_EXIST) {
		nic_warn(nic_cfg->dev_hdl, "MAC is repeated. Ignore update operation\n");
		return 0;
	}

	return 0;
}

int spnic_get_default_mac(void *hwdev, u8 *mac_addr)
{
	struct spnic_port_mac_set mac_info;
	u16 out_size = sizeof(mac_info);
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	if (!hwdev || !mac_addr)
		return -EINVAL;

	memset(&mac_info, 0, sizeof(mac_info));

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	mac_info.func_id = sphw_global_func_id(hwdev);

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_NIC_CMD_GET_MAC, &mac_info, sizeof(mac_info),
				     &mac_info, &out_size);
	if (err || !out_size || mac_info.msg_head.status) {
		nic_err(nic_cfg->dev_hdl,
			"Failed to get mac, err: %d, status: 0x%x, out size: 0x%x\n",
			err, mac_info.msg_head.status, out_size);
		return -EINVAL;
	}

	ether_addr_copy(mac_addr, mac_info.mac);

	return 0;
}

static int spnic_config_vlan(struct spnic_nic_cfg *nic_cfg, u8 opcode, u16 vlan_id, u16 func_id)
{
	struct spnic_cmd_vlan_config vlan_info;
	u16 out_size = sizeof(vlan_info);
	int err;

	memset(&vlan_info, 0, sizeof(vlan_info));
	vlan_info.opcode = opcode;
	vlan_info.func_id = func_id;
	vlan_info.vlan_id = vlan_id;

	err = l2nic_msg_to_mgmt_sync(nic_cfg->hwdev, SPNIC_NIC_CMD_CFG_FUNC_VLAN,
				     &vlan_info, sizeof(vlan_info),
				     &vlan_info, &out_size);
	if (err || !out_size || vlan_info.msg_head.status) {
		nic_err(nic_cfg->dev_hdl,
			"Failed to %s vlan, err: %d, status: 0x%x, out size: 0x%x\n",
			opcode == SPNIC_CMD_OP_ADD ? "add" : "delete",
			err, vlan_info.msg_head.status, out_size);
		return -EINVAL;
	}

	return 0;
}

int spnic_add_vlan(void *hwdev, u16 vlan_id, u16 func_id)
{
	struct spnic_nic_cfg *nic_cfg = NULL;

	if (!hwdev)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	return spnic_config_vlan(nic_cfg, SPNIC_CMD_OP_ADD, vlan_id, func_id);
}

int spnic_del_vlan(void *hwdev, u16 vlan_id, u16 func_id)
{
	struct spnic_nic_cfg *nic_cfg = NULL;

	if (!hwdev)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	return spnic_config_vlan(nic_cfg, SPNIC_CMD_OP_DEL, vlan_id, func_id);
}

int spnic_set_vport_enable(void *hwdev, u16 func_id, bool enable, u16 channel)
{
	struct spnic_vport_state en_state;
	u16 out_size = sizeof(en_state);
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	if (!hwdev)
		return -EINVAL;

	memset(&en_state, 0, sizeof(en_state));

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	en_state.func_id = func_id;
	en_state.state = enable ? 1 : 0;

	err = l2nic_msg_to_mgmt_sync_ch(hwdev, SPNIC_NIC_CMD_SET_VPORT_ENABLE,
					&en_state, sizeof(en_state),
					&en_state, &out_size, channel);
	if (err || !out_size || en_state.msg_head.status) {
		nic_err(nic_cfg->dev_hdl, "Failed to set vport state, err: %d, status: 0x%x, out size: 0x%x, channel: 0x%x\n",
			err, en_state.msg_head.status, out_size, channel);
		return -EINVAL;
	}

	return 0;
}

int spnic_set_dcb_state(void *hwdev, struct spnic_dcb_state *dcb_state)
{
	struct vf_data_storage *vf_infos = NULL;
	struct spnic_cmd_vf_dcb_state vf_dcb;
	struct spnic_nic_cfg *nic_cfg = NULL;
	u16 vf_id, out_size = 0;
	int err;

	if (!hwdev || !dcb_state)
		return -EINVAL;

	memset(&vf_dcb, 0, sizeof(vf_dcb));

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	if (!memcmp(&nic_cfg->dcb_state, dcb_state, sizeof(nic_cfg->dcb_state)))
		return 0;

	memcpy(&vf_dcb.state, dcb_state, sizeof(vf_dcb.state));
	/* save in sdk, vf will get dcb state when probing */
	spnic_save_dcb_state(nic_cfg, dcb_state);

	/* notify statefull in pf, than notify all vf */
	spnic_notify_dcb_state_event(nic_cfg, dcb_state);

	/* not vf supported, don't need to notify vf */
	if (!nic_cfg->vf_infos)
		return 0;

	vf_infos = nic_cfg->vf_infos;
	for (vf_id = 0; vf_id < nic_cfg->max_vfs; vf_id++) {
		if (vf_infos[vf_id].registered) {
			vf_dcb.msg_head.status = 0;
			out_size = sizeof(vf_dcb);
			err = sphw_mbox_to_vf(hwdev, OS_VF_ID_TO_HW(vf_id), SPHW_MOD_L2NIC,
					      SPNIC_NIC_CMD_VF_COS, &vf_dcb, sizeof(vf_dcb),
					      &vf_dcb, &out_size, 0, SPHW_CHANNEL_NIC);
			if (MSG_TO_MGMT_SYNC_RETURN_ERR(err, vf_dcb.msg_head.status, out_size))
				nic_err(nic_cfg->dev_hdl,
					"Failed to notify dcb state to VF %u, err: %d, status: 0x%x, out size: 0x%x\n",
					vf_id, err, vf_dcb.msg_head.status, out_size);
		}
	}

	return 0;
}

int spnic_get_dcb_state(void *hwdev, struct spnic_dcb_state *dcb_state)
{
	struct spnic_nic_cfg *nic_cfg = NULL;

	if (!hwdev || !dcb_state)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	memcpy(dcb_state, &nic_cfg->dcb_state, sizeof(*dcb_state));

	return 0;
}

int spnic_save_dcb_state(struct spnic_nic_cfg *nic_cfg, struct spnic_dcb_state *dcb_state)
{
	memcpy(&nic_cfg->dcb_state, dcb_state, sizeof(*dcb_state));

	return 0;
}

int spnic_get_pf_dcb_state(void *hwdev, struct spnic_dcb_state *dcb_state)
{
	struct spnic_cmd_vf_dcb_state vf_dcb;
	struct spnic_nic_cfg *nic_cfg = NULL;
	u16 out_size = sizeof(vf_dcb);
	int err;

	if (!hwdev || !dcb_state)
		return -EINVAL;

	memset(&vf_dcb, 0, sizeof(vf_dcb));

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	if (sphw_func_type(hwdev) != TYPE_VF) {
		nic_err(nic_cfg->dev_hdl, "Only vf need to get pf dcb state\n");
		return -EINVAL;
	}

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_NIC_CMD_VF_COS, &vf_dcb,
				     sizeof(vf_dcb), &vf_dcb, &out_size);
	if (err || !out_size || vf_dcb.msg_head.status) {
		nic_err(nic_cfg->dev_hdl, "Failed to get vf default cos, err: %d, status: 0x%x, out size: 0x%x\n",
			err, vf_dcb.msg_head.status, out_size);
		return -EFAULT;
	}

	memcpy(dcb_state, &vf_dcb.state, sizeof(*dcb_state));
	/* Save dcb_state in hw for statefull module */
	spnic_save_dcb_state(nic_cfg, dcb_state);

	return 0;
}

static int spnic_cfg_hw_pause(struct spnic_nic_cfg *nic_cfg, u8 opcode,
			      struct nic_pause_config *nic_pause)
{
	struct spnic_cmd_pause_config pause_info;
	u16 out_size = sizeof(pause_info);
	int err;

	memset(&pause_info, 0, sizeof(pause_info));

	pause_info.port_id = sphw_physical_port_id(nic_cfg->hwdev);
	pause_info.opcode = opcode;
	if (opcode == SPNIC_CMD_OP_SET) {
		pause_info.auto_neg = nic_pause->auto_neg;
		pause_info.rx_pause = nic_pause->rx_pause;
		pause_info.tx_pause = nic_pause->tx_pause;
	}

	err = l2nic_msg_to_mgmt_sync(nic_cfg->hwdev, SPNIC_NIC_CMD_CFG_PAUSE_INFO,
				     &pause_info, sizeof(pause_info),
				     &pause_info, &out_size);
	if (err || !out_size || pause_info.msg_head.status) {
		nic_err(nic_cfg->dev_hdl, "Failed to %s pause info, err: %d, status: 0x%x, out size: 0x%x\n",
			opcode == SPNIC_CMD_OP_SET ? "set" : "get",
			err, pause_info.msg_head.status, out_size);
		return -EINVAL;
	}

	if (opcode == SPNIC_CMD_OP_GET) {
		nic_pause->auto_neg = pause_info.auto_neg;
		nic_pause->rx_pause = pause_info.rx_pause;
		nic_pause->tx_pause = pause_info.tx_pause;
	}

	return 0;
}

int spnic_set_pause_info(void *hwdev, struct nic_pause_config nic_pause)
{
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	down(&nic_cfg->cfg_lock);

	err = spnic_cfg_hw_pause(nic_cfg, SPNIC_CMD_OP_SET, &nic_pause);
	if (err) {
		up(&nic_cfg->cfg_lock);
		return err;
	}

	nic_cfg->pfc_en = 0;
	nic_cfg->pfc_bitmap = 0;
	nic_cfg->pause_set = true;
	nic_cfg->nic_pause.auto_neg = nic_pause.auto_neg;
	nic_cfg->nic_pause.rx_pause = nic_pause.rx_pause;
	nic_cfg->nic_pause.tx_pause = nic_pause.tx_pause;

	up(&nic_cfg->cfg_lock);

	return 0;
}

int spnic_get_pause_info(void *hwdev, struct nic_pause_config *nic_pause)
{
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err = 0;

	if (!hwdev || !nic_pause)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	err = spnic_cfg_hw_pause(nic_cfg, SPNIC_CMD_OP_GET, nic_pause);
	if (err)
		return err;

	if (nic_cfg->pause_set || !nic_pause->auto_neg) {
		nic_pause->rx_pause = nic_cfg->nic_pause.rx_pause;
		nic_pause->tx_pause = nic_cfg->nic_pause.tx_pause;
	}

	return 0;
}

static int spnic_dcb_set_hw_pfc(struct spnic_nic_cfg *nic_cfg, u8 pfc_en, u8 pfc_bitmap)
{
	struct spnic_cmd_set_pfc pfc;
	u16 out_size = sizeof(pfc);
	int err;

	memset(&pfc, 0, sizeof(pfc));

	pfc.port_id = sphw_physical_port_id(nic_cfg->hwdev);
	pfc.pfc_bitmap = pfc_bitmap;
	pfc.pfc_en = pfc_en;

	err = l2nic_msg_to_mgmt_sync(nic_cfg->hwdev, SPNIC_NIC_CMD_SET_PFC,
				     &pfc, sizeof(pfc), &pfc, &out_size);
	if (err || pfc.msg_head.status || !out_size) {
		nic_err(nic_cfg->dev_hdl, "Failed to set pfc, err: %d, status: 0x%x, out size: 0x%x\n",
			err, pfc.msg_head.status, out_size);
		return -EINVAL;
	}

	return 0;
}

int spnic_dcb_set_pfc(void *hwdev, u8 pfc_en, u8 pfc_bitmap)
{
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	down(&nic_cfg->cfg_lock);

	err = spnic_dcb_set_hw_pfc(nic_cfg, pfc_en, pfc_bitmap);
	if (err) {
		up(&nic_cfg->cfg_lock);
		return err;
	}

	nic_cfg->pfc_en = pfc_en;
	nic_cfg->pfc_bitmap = pfc_bitmap;

	/* pause settings is opposite from pfc */
	nic_cfg->nic_pause.rx_pause = pfc_en ? 0 : 1;
	nic_cfg->nic_pause.tx_pause = pfc_en ? 0 : 1;

	up(&nic_cfg->cfg_lock);

	return 0;
}

int spnic_dcb_set_ets(void *hwdev, u8 *cos_tc, u8 *cos_bw, u8 *cos_prio,
		      u8 *tc_bw, u8 *tc_prio)
{
	struct spnic_up_ets_cfg ets;
	struct spnic_nic_cfg *nic_cfg = NULL;
	u16 out_size = sizeof(ets);
	u16 cos_bw_t = 0;
	u8 tc_bw_t = 0;
	int i, err;

	memset(&ets, 0, sizeof(ets));

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	for (i = 0; i < SPNIC_DCB_COS_MAX; i++) {
		cos_bw_t += *(cos_bw + i);
		tc_bw_t += *(tc_bw + i);

		if (*(cos_tc + i) > SPNIC_DCB_TC_MAX) {
			nic_err(nic_cfg->dev_hdl, "Invalid cos %d mapping tc: %u\n",
				i, *(cos_tc + i));
			return -EINVAL;
		}
	}

	/* The sum of all TCs must be 100%, and the same for cos */
	if ((tc_bw_t != 100 && tc_bw_t != 0) || (cos_bw_t % 100) != 0) {
		nic_err(nic_cfg->dev_hdl,
			"Invalid pg_bw: %u or up_bw: %u\n", tc_bw_t, cos_bw_t);
		return -EINVAL;
	}

	ets.port_id = sphw_physical_port_id(hwdev);
	memcpy(ets.cos_tc, cos_tc, SPNIC_DCB_COS_MAX);
	memcpy(ets.cos_bw, cos_bw, SPNIC_DCB_COS_MAX);
	memcpy(ets.cos_prio, cos_prio, SPNIC_DCB_COS_MAX);
	memcpy(ets.tc_bw, tc_bw, SPNIC_DCB_TC_MAX);
	memcpy(ets.tc_prio, tc_prio, SPNIC_DCB_TC_MAX);

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_NIC_CMD_SET_ETS,
				     &ets, sizeof(ets), &ets, &out_size);
	if (err || ets.msg_head.status || !out_size) {
		nic_err(nic_cfg->dev_hdl,
			"Failed to set ets, err: %d, status: 0x%x, out size: 0x%x\n",
			err, ets.msg_head.status, out_size);
		return -EINVAL;
	}

	return 0;
}

int spnic_dcb_set_cos_up_map(void *hwdev, u8 cos_valid_bitmap, u8 *cos_up, u8 max_cos_num)
{
	struct spnic_cos_up_map map;
	struct spnic_nic_cfg *nic_cfg = NULL;
	u16 out_size = sizeof(map);
	int err;

	if (!hwdev || !cos_up)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	memset(&map, 0, sizeof(map));

	map.port_id = sphw_physical_port_id(hwdev);
	map.cos_valid_mask = cos_valid_bitmap;
	memcpy(map.map, cos_up, sizeof(map.map));

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_NIC_CMD_SETUP_COS_MAPPING,
				     &map, sizeof(map), &map, &out_size);
	if (err || map.msg_head.status || !out_size) {
		nic_err(nic_cfg->dev_hdl,
			"Failed to set cos2up map, err: %d, status: 0x%x, out size: 0x%x\n",
			err, map.msg_head.status, out_size);
		return -EFAULT;
	}

	return 0;
}

int spnic_flush_qps_res(void *hwdev)
{
	struct spnic_cmd_clear_qp_resource sq_res;
	u16 out_size = sizeof(sq_res);
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	memset(&sq_res, 0, sizeof(sq_res));

	sq_res.func_id = sphw_global_func_id(hwdev);

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_NIC_CMD_CLEAR_QP_RESOURCE,
				     &sq_res, sizeof(sq_res), &sq_res,
				     &out_size);
	if (err || !out_size || sq_res.msg_head.status) {
		nic_err(nic_cfg->dev_hdl, "Failed to clear sq resources, err: %d, status: 0x%x, out size: 0x%x\n",
			err, sq_res.msg_head.status, out_size);
		return -EINVAL;
	}

	return 0;
}

int spnic_get_vport_stats(void *hwdev, struct spnic_vport_stats *stats)
{
	struct spnic_port_stats_info stats_info;
	struct spnic_cmd_vport_stats vport_stats;
	u16 out_size = sizeof(vport_stats);
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	if (!hwdev || !stats)
		return -EINVAL;

	memset(&stats_info, 0, sizeof(stats_info));
	memset(&vport_stats, 0, sizeof(vport_stats));

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	stats_info.func_id = sphw_global_func_id(hwdev);

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_NIC_CMD_GET_VPORT_STAT,
				     &stats_info, sizeof(stats_info),
				     &vport_stats, &out_size);
	if (err || !out_size || vport_stats.msg_head.status) {
		nic_err(nic_cfg->dev_hdl,
			"Failed to get function statistics, err: %d, status: 0x%x, out size: 0x%x\n",
			err, vport_stats.msg_head.status, out_size);
		return -EFAULT;
	}

	memcpy(stats, &vport_stats.stats, sizeof(*stats));

	return 0;
}

int spnic_set_function_table(struct spnic_nic_cfg *nic_cfg, u32 cfg_bitmap,
			     struct spnic_func_tbl_cfg *cfg)
{
	struct spnic_cmd_set_func_tbl cmd_func_tbl;
	u16 out_size = sizeof(cmd_func_tbl);
	int err;

	memset(&cmd_func_tbl, 0, sizeof(cmd_func_tbl));
	cmd_func_tbl.func_id = sphw_global_func_id(nic_cfg->hwdev);
	cmd_func_tbl.cfg_bitmap = cfg_bitmap;
	cmd_func_tbl.tbl_cfg = *cfg;

	err = l2nic_msg_to_mgmt_sync(nic_cfg->hwdev, SPNIC_NIC_CMD_SET_FUNC_TBL,
				     &cmd_func_tbl, sizeof(cmd_func_tbl),
				     &cmd_func_tbl, &out_size);
	if (err || cmd_func_tbl.msg_head.status || !out_size) {
		nic_err(nic_cfg->dev_hdl,
			"Failed to set func table, bitmap: 0x%x, err: %d, status: 0x%x, out size: 0x%x\n",
			cfg_bitmap, err, cmd_func_tbl.msg_head.status, out_size);
		return -EFAULT;
	}

	return 0;
}

int spnic_init_function_table(struct spnic_nic_cfg *nic_cfg)
{
	struct spnic_func_tbl_cfg func_tbl_cfg = {0};
	u32 cfg_bitmap = BIT(FUNC_CFG_INIT) | BIT(FUNC_CFG_MTU) |
			BIT(FUNC_CFG_RX_BUF_SIZE);

	func_tbl_cfg.mtu = 0x3FFF;	/* default, max mtu */
	func_tbl_cfg.rx_wqe_buf_size = nic_cfg->rx_buff_len;

	return spnic_set_function_table(nic_cfg, cfg_bitmap, &func_tbl_cfg);
}

int spnic_set_port_mtu(void *hwdev, u16 new_mtu)
{
	struct spnic_func_tbl_cfg func_tbl_cfg = {0};
	struct spnic_nic_cfg *nic_cfg = NULL;

	if (!hwdev)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	if (new_mtu < SPNIC_MIN_MTU_SIZE) {
		nic_err(nic_cfg->dev_hdl, "Invalid mtu size: %ubytes, mtu size < %ubytes",
			new_mtu, SPNIC_MIN_MTU_SIZE);
		return -EINVAL;
	}

	if (new_mtu > SPNIC_MAX_JUMBO_FRAME_SIZE) {
		nic_err(nic_cfg->dev_hdl, "Invalid mtu size: %ubytes, mtu size > %ubytes",
			new_mtu, SPNIC_MAX_JUMBO_FRAME_SIZE);
		return -EINVAL;
	}

	func_tbl_cfg.mtu = new_mtu;
	return spnic_set_function_table(nic_cfg, BIT(FUNC_CFG_MTU), &func_tbl_cfg);
}

static int nic_feature_nego(void *hwdev, u8 opcode, u64 *s_feature, u16 size)
{
	struct spnic_nic_cfg *nic_cfg = NULL;
	struct spnic_cmd_feature_nego feature_nego;
	u16 out_size = sizeof(feature_nego);
	int err;

	if (!hwdev || !s_feature || size > NIC_MAX_FEATURE_QWORD)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	memset(&feature_nego, 0, sizeof(feature_nego));
	feature_nego.func_id = sphw_global_func_id(hwdev);
	feature_nego.opcode = opcode;
	if (opcode == SPNIC_CMD_OP_SET)
		memcpy(feature_nego.s_feature, s_feature, size * sizeof(u64));

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_NIC_CMD_FEATURE_NEGO,
				     &feature_nego, sizeof(feature_nego),
				     &feature_nego, &out_size);
	if (err || !out_size || feature_nego.msg_head.status) {
		nic_err(nic_cfg->dev_hdl, "Failed to negotiate nic feature, err:%d, status: 0x%x, out_size: 0x%x\n",
			err, feature_nego.msg_head.status, out_size);
		return -EIO;
	}

	if (opcode == SPNIC_CMD_OP_GET)
		memcpy(s_feature, feature_nego.s_feature, size * sizeof(u64));

	return 0;
}

int spnic_get_nic_feature(void *hwdev, u64 *s_feature, u16 size)
{
	return nic_feature_nego(hwdev, SPNIC_CMD_OP_GET, s_feature, size);
}

int spnic_set_nic_feature(void *hwdev, u64 *s_feature, u16 size)
{
	return nic_feature_nego(hwdev, SPNIC_CMD_OP_SET, s_feature, size);
}

static inline int init_nic_hwdev_param_valid(void *hwdev, void *pcidev_hdl, void *dev_hdl)
{
	if (!hwdev || !pcidev_hdl || !dev_hdl)
		return -EINVAL;

	return 0;
}

/* spnic_init_nic_hwdev - init nic hwdev
 * @hwdev: pointer to hwdev
 * @pcidev_hdl: pointer to pcidev or handler
 * @dev_hdl: pointer to pcidev->dev or handler, for sdk_err() or dma_alloc()
 * @rx_buff_len: rx_buff_len is receive buffer length
 */
int spnic_init_nic_hwdev(void *hwdev, void *pcidev_hdl, void *dev_hdl, u16 rx_buff_len)
{
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	if (init_nic_hwdev_param_valid(hwdev, pcidev_hdl, dev_hdl))
		return -EINVAL;

	nic_cfg = kzalloc(sizeof(*nic_cfg), GFP_KERNEL);
	if (!nic_cfg)
		return -ENOMEM;

	nic_cfg->dev_hdl = dev_hdl;
	nic_cfg->pcidev_hdl = pcidev_hdl;
	nic_cfg->hwdev = hwdev;

	sema_init(&nic_cfg->cfg_lock, 1);
	mutex_init(&nic_cfg->sfp_mutex);

	err = sphw_register_service_adapter(hwdev, nic_cfg, SERVICE_T_NIC);
	if (err) {
		nic_err(nic_cfg->dev_hdl, "Failed to register service adapter\n");
		goto register_sa_err;
	}

	err = spnic_init_function_table(nic_cfg);
	if (err) {
		nic_err(nic_cfg->dev_hdl, "Failed to init function table\n");
		goto init_func_tbl_err;
	}

	err = spnic_get_nic_feature(hwdev, &nic_cfg->feature_cap, 1);
	if (err) {
		nic_err(nic_cfg->dev_hdl, "Failed to get nic features\n");
		goto get_feature_err;
	}

	sdk_info(dev_hdl, "nic features: 0x%llx\n", nic_cfg->feature_cap);

	err = sphw_aeq_register_swe_cb(hwdev, SPHW_STATELESS_EVENT, spnic_nic_sw_aeqe_handler);
	if (err) {
		nic_err(nic_cfg->dev_hdl,
			"Failed to register sw aeqe handler\n");
		goto register_sw_aeqe_err;
	}

	err = spnic_vf_func_init(nic_cfg);
	if (err) {
		nic_err(nic_cfg->dev_hdl, "Failed to init vf info\n");
		goto vf_init_err;
	}

	nic_cfg->rx_buff_len = rx_buff_len;

	return 0;

vf_init_err:
	sphw_aeq_unregister_swe_cb(hwdev, SPHW_STATELESS_EVENT);

register_sw_aeqe_err:
get_feature_err:
init_func_tbl_err:
	sphw_unregister_service_adapter(hwdev, SERVICE_T_NIC);

register_sa_err:
	kfree(nic_cfg);

	return err;
}

void spnic_free_nic_hwdev(void *hwdev)
{
	struct spnic_nic_cfg *nic_cfg = NULL;

	if (!hwdev)
		return;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_cfg)
		return;

	spnic_vf_func_free(nic_cfg);

	sphw_aeq_unregister_swe_cb(hwdev, SPHW_STATELESS_EVENT);

	sphw_unregister_service_adapter(hwdev, SERVICE_T_NIC);

	kfree(nic_cfg);
}

/* to do : send cmd to MPU to drop nic tx pkt*/
int spnic_force_drop_tx_pkt(void *hwdev)
{
	return 0;
}

int spnic_set_rx_mode(void *hwdev, u32 enable)
{
	struct spnic_nic_cfg *nic_cfg = NULL;
	struct spnic_rx_mode_config rx_mode_cfg;
	u16 out_size = sizeof(rx_mode_cfg);
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	memset(&rx_mode_cfg, 0, sizeof(rx_mode_cfg));
	rx_mode_cfg.func_id = sphw_global_func_id(hwdev);
	rx_mode_cfg.rx_mode = enable;

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_NIC_CMD_SET_RX_MODE,
				     &rx_mode_cfg, sizeof(rx_mode_cfg),
				     &rx_mode_cfg, &out_size);
	if (err || !out_size || rx_mode_cfg.msg_head.status) {
		nic_err(nic_cfg->dev_hdl, "Failed to set rx mode, err: %d, status: 0x%x, out size: 0x%x\n",
			err, rx_mode_cfg.msg_head.status, out_size);
		return -EINVAL;
	}

	return 0;
}

int spnic_set_rx_vlan_offload(void *hwdev, u8 en)
{
	struct spnic_nic_cfg *nic_cfg = NULL;
	struct spnic_cmd_vlan_offload vlan_cfg;
	u16 out_size = sizeof(vlan_cfg);
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	memset(&vlan_cfg, 0, sizeof(vlan_cfg));
	vlan_cfg.func_id = sphw_global_func_id(hwdev);
	vlan_cfg.vlan_offload = en;

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_NIC_CMD_SET_RX_VLAN_OFFLOAD,
				     &vlan_cfg, sizeof(vlan_cfg),
				     &vlan_cfg, &out_size);
	if (err || !out_size || vlan_cfg.msg_head.status) {
		nic_err(nic_cfg->dev_hdl, "Failed to set rx vlan offload, err: %d, status: 0x%x, out size: 0x%x\n",
			err, vlan_cfg.msg_head.status, out_size);
		return -EINVAL;
	}

	return 0;
}

int spnic_update_mac_vlan(void *hwdev, u16 old_vlan, u16 new_vlan, int vf_id)
{
	struct vf_data_storage *vf_info = NULL;
	struct spnic_nic_cfg *nic_cfg = NULL;
	u16 func_id;
	int err;

	if (!hwdev || old_vlan >= VLAN_N_VID || new_vlan >= VLAN_N_VID)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	vf_info = nic_cfg->vf_infos + HW_VF_ID_TO_OS(vf_id);

	if (!nic_cfg->vf_infos || is_zero_ether_addr(vf_info->drv_mac_addr))
		return 0;

	func_id = sphw_glb_pf_vf_offset(nic_cfg->hwdev) + (u16)vf_id;

	err = spnic_del_mac(nic_cfg->hwdev, vf_info->drv_mac_addr,
			    old_vlan, func_id, SPHW_CHANNEL_NIC);
	if (err) {
		nic_err(nic_cfg->dev_hdl, "Failed to delete VF %d MAC %pM vlan %u\n",
			HW_VF_ID_TO_OS(vf_id), vf_info->drv_mac_addr, old_vlan);
		return err;
	}

	err = spnic_set_mac(nic_cfg->hwdev, vf_info->drv_mac_addr,
			    new_vlan, func_id, SPHW_CHANNEL_NIC);
	if (err) {
		nic_err(nic_cfg->dev_hdl, "Failed to add VF %d MAC %pM vlan %u\n",
			HW_VF_ID_TO_OS(vf_id), vf_info->drv_mac_addr, new_vlan);
		spnic_set_mac(nic_cfg->hwdev, vf_info->drv_mac_addr,
			      old_vlan, func_id, SPHW_CHANNEL_NIC);
		return err;
	}

	return 0;
}

static int spnic_set_rx_lro(void *hwdev, u8 ipv4_en, u8 ipv6_en, u8 lro_max_pkt_len)
{
	struct spnic_nic_cfg *nic_cfg = NULL;
	struct spnic_cmd_lro_config lro_cfg;
	u16 out_size = sizeof(lro_cfg);
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	memset(&lro_cfg, 0, sizeof(lro_cfg));
	lro_cfg.func_id = sphw_global_func_id(hwdev);
	lro_cfg.opcode = SPNIC_CMD_OP_SET;
	lro_cfg.lro_ipv4_en = ipv4_en;
	lro_cfg.lro_ipv6_en = ipv6_en;
	lro_cfg.lro_max_pkt_len = lro_max_pkt_len;

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_NIC_CMD_CFG_RX_LRO,
				     &lro_cfg, sizeof(lro_cfg),
				     &lro_cfg, &out_size);
	if (err || !out_size || lro_cfg.msg_head.status) {
		nic_err(nic_cfg->dev_hdl, "Failed to set lro offload, err: %d, status: 0x%x, out size: 0x%x\n",
			err, lro_cfg.msg_head.status, out_size);
		return -EINVAL;
	}

	return 0;
}

static int spnic_set_rx_lro_timer(void *hwdev, u32 timer_value)
{
	struct spnic_nic_cfg *nic_cfg = NULL;
	struct spnic_cmd_lro_timer lro_timer;
	u16 out_size = sizeof(lro_timer);
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	memset(&lro_timer, 0, sizeof(lro_timer));
	lro_timer.opcode = SPNIC_CMD_OP_SET;
	lro_timer.timer = timer_value;

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_NIC_CMD_CFG_LRO_TIMER,
				     &lro_timer, sizeof(lro_timer),
				     &lro_timer, &out_size);
	if (err || !out_size || lro_timer.msg_head.status) {
		nic_err(nic_cfg->dev_hdl, "Failed to set lro timer, err: %d, status: 0x%x, out size: 0x%x\n",
			err, lro_timer.msg_head.status, out_size);

		return -EINVAL;
	}

	return 0;
}

int spnic_set_rx_lro_state(void *hwdev, u8 lro_en, u32 lro_timer, u32 lro_max_pkt_len)
{
	struct spnic_nic_cfg *nic_cfg = NULL;
	u8 ipv4_en = 0, ipv6_en = 0;
	int err;

	if (!hwdev)
		return -EINVAL;

	ipv4_en = lro_en ? 1 : 0;
	ipv6_en = lro_en ? 1 : 0;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	nic_info(nic_cfg->dev_hdl, "Set LRO max coalesce packet size to %uK\n",
		 lro_max_pkt_len);

	err = spnic_set_rx_lro(hwdev, ipv4_en, ipv6_en, (u8)lro_max_pkt_len);
	if (err)
		return err;

	/* we don't set LRO timer for VF */
	if (sphw_func_type(hwdev) == TYPE_VF)
		return 0;

	nic_info(nic_cfg->dev_hdl, "Set LRO timer to %u\n", lro_timer);

	return spnic_set_rx_lro_timer(hwdev, lro_timer);
}

int spnic_set_vlan_fliter(void *hwdev, u32 vlan_filter_ctrl)
{
	struct spnic_nic_cfg *nic_cfg = NULL;
	struct spnic_cmd_set_vlan_filter vlan_filter;
	u16 out_size = sizeof(vlan_filter);
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	memset(&vlan_filter, 0, sizeof(vlan_filter));
	vlan_filter.func_id = sphw_global_func_id(hwdev);
	vlan_filter.vlan_filter_ctrl = vlan_filter_ctrl;

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_NIC_CMD_SET_VLAN_FILTER_EN,
				     &vlan_filter, sizeof(vlan_filter),
				     &vlan_filter, &out_size);
	if (err || !out_size || vlan_filter.msg_head.status) {
		nic_err(nic_cfg->dev_hdl, "Failed to set vlan filter, err: %d, status: 0x%x, out size: 0x%x\n",
			err, vlan_filter.msg_head.status, out_size);
		return -EINVAL;
	}

	return 0;
}

u64 spnic_get_feature_cap(void *hwdev)
{
	struct spnic_nic_cfg *nic_cfg = NULL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	return nic_cfg->feature_cap;
}

int spnic_add_tcam_rule(void *hwdev, struct nic_tcam_cfg_rule *tcam_rule)
{
	u16 out_size = sizeof(struct nic_cmd_fdir_add_rule);
	struct nic_cmd_fdir_add_rule tcam_cmd;
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	if (!hwdev || !tcam_rule)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (tcam_rule->index >= SPNIC_MAX_TCAM_RULES_NUM) {
		nic_err(nic_cfg->dev_hdl, "Tcam rules num to add is invalid\n");
		return -EINVAL;
	}

	memset(&tcam_cmd, 0, sizeof(struct nic_cmd_fdir_add_rule));
	memcpy((void *)&tcam_cmd.rule, (void *)tcam_rule,
	       sizeof(struct nic_tcam_cfg_rule));
	tcam_cmd.func_id = sphw_global_func_id(hwdev);

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_NIC_CMD_ADD_TC_FLOW,
				     &tcam_cmd, sizeof(tcam_cmd),
				     &tcam_cmd, &out_size);
	if (err || tcam_cmd.head.status || !out_size) {
		nic_err(nic_cfg->dev_hdl,
			"Add tcam rule failed, err: %d, status: 0x%x, out size: 0x%x\n",
			err, tcam_cmd.head.status, out_size);
		return -EIO;
	}

	return 0;
}

int spnic_del_tcam_rule(void *hwdev, u32 index)
{
	u16 out_size = sizeof(struct nic_cmd_fdir_del_rules);
	struct nic_cmd_fdir_del_rules tcam_cmd;
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (index >= SPNIC_MAX_TCAM_RULES_NUM) {
		nic_err(nic_cfg->dev_hdl, "Tcam rules num to del is invalid\n");
		return -EINVAL;
	}

	memset(&tcam_cmd, 0, sizeof(struct nic_cmd_fdir_del_rules));
	tcam_cmd.index_start = index;
	tcam_cmd.index_num = 1;
	tcam_cmd.func_id = sphw_global_func_id(hwdev);

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_NIC_CMD_DEL_TC_FLOW,
				     &tcam_cmd, sizeof(tcam_cmd),
				     &tcam_cmd, &out_size);
	if (err || tcam_cmd.head.status || !out_size) {
		nic_err(nic_cfg->dev_hdl, "Del tcam rule failed, err: %d, status: 0x%x, out size: 0x%x\n",
			err, tcam_cmd.head.status, out_size);
		return -EIO;
	}

	return 0;
}

/**
 * spnic_mgmt_tcam_block - alloc or free tcam block for IO packet.
 *
 * @param hwdev
 *   The hardware interface of a nic device.
 * @param alloc_en
 *   1 alloc block.
 *   0 free block.
 * @param index
 *   block index from firmware.
 * @return
 *   0 on success,
 *   negative error value otherwise.
 */
static int spnic_mgmt_tcam_block(void *hwdev, u8 alloc_en, u16 *index)
{
	struct nic_cmd_ctrl_tcam_block_out tcam_block_info;
	u16 out_size = sizeof(struct nic_cmd_ctrl_tcam_block_out);
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	if (!hwdev || !index)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	memset(&tcam_block_info, 0, sizeof(struct nic_cmd_ctrl_tcam_block_out));

	tcam_block_info.func_id = sphw_global_func_id(hwdev);
	tcam_block_info.alloc_en = alloc_en;
	tcam_block_info.tcam_type = SPNIC_TCAM_BLOCK_NORMAL_TYPE;
	tcam_block_info.tcam_block_index = *index;

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_NIC_CMD_CFG_TCAM_BLOCK,
				     &tcam_block_info, sizeof(tcam_block_info),
				     &tcam_block_info, &out_size);
	if (err || tcam_block_info.head.status || !out_size) {
		nic_err(nic_cfg->dev_hdl,
			"Set tcam block failed, err: %d, status: 0x%x, out size: 0x%x\n",
			err, tcam_block_info.head.status, out_size);
		return -EIO;
	}

	if (alloc_en)
		*index = tcam_block_info.tcam_block_index;

	return 0;
}

int spnic_alloc_tcam_block(void *hwdev, u16 *index)
{
	return spnic_mgmt_tcam_block(hwdev, SPNIC_TCAM_BLOCK_ENABLE, index);
}

int spnic_free_tcam_block(void *hwdev, u16 *index)
{
	return spnic_mgmt_tcam_block(hwdev, SPNIC_TCAM_BLOCK_DISABLE, index);
}

int spnic_set_fdir_tcam_rule_filter(void *hwdev, bool enable)
{
	struct nic_cmd_set_tcam_enable port_tcam_cmd;
	u16 out_size = sizeof(port_tcam_cmd);
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	memset(&port_tcam_cmd, 0, sizeof(port_tcam_cmd));
	port_tcam_cmd.func_id = sphw_global_func_id(hwdev);
	port_tcam_cmd.tcam_enable = (u8)enable;

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_NIC_CMD_ENABLE_TCAM,
				     &port_tcam_cmd, sizeof(port_tcam_cmd),
				     &port_tcam_cmd, &out_size);
	if (err || port_tcam_cmd.head.status || !out_size) {
		nic_err(nic_cfg->dev_hdl, "Set fdir tcam filter failed, err: %d, status: 0x%x, out size: 0x%x, enable: 0x%x\n",
			err, port_tcam_cmd.head.status, out_size,
			enable);
		return -EIO;
	}

	return 0;
}

int spnic_flush_tcam_rule(void *hwdev)
{
	struct nic_cmd_flush_tcam_rules tcam_flush;
	u16 out_size = sizeof(struct nic_cmd_flush_tcam_rules);
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	memset(&tcam_flush, 0, sizeof(struct nic_cmd_flush_tcam_rules));
	tcam_flush.func_id = sphw_global_func_id(hwdev);

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_NIC_CMD_FLUSH_TCAM,
				     &tcam_flush,
				     sizeof(struct nic_cmd_flush_tcam_rules),
				     &tcam_flush, &out_size);
	if (err || tcam_flush.head.status || !out_size) {
		nic_err(nic_cfg->dev_hdl,
			"Flush tcam fdir rules failed, err: %d, status: 0x%x, out size: 0x%x\n",
			err, tcam_flush.head.status, out_size);
		return -EIO;
	}

	return 0;
}
