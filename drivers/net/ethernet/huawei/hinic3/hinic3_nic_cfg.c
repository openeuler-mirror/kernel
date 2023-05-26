// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Huawei Technologies Co., Ltd */

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

#include "ossl_knl.h"
#include "hinic3_crm.h"
#include "hinic3_hw.h"
#include "hinic3_nic_io.h"
#include "hinic3_srv_nic.h"
#include "hinic3_nic.h"
#include "hinic3_nic_cmd.h"
#include "hinic3_common.h"
#include "hinic3_nic_cfg.h"

int hinic3_set_ci_table(void *hwdev, struct hinic3_sq_attr *attr)
{
	struct hinic3_cmd_cons_idx_attr cons_idx_attr;
	u16 out_size = sizeof(cons_idx_attr);
	struct hinic3_nic_io *nic_io = NULL;
	int err;

	if (!hwdev || !attr)
		return -EINVAL;

	memset(&cons_idx_attr, 0, sizeof(cons_idx_attr));

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);

	cons_idx_attr.func_idx = hinic3_global_func_id(hwdev);

	cons_idx_attr.dma_attr_off  = attr->dma_attr_off;
	cons_idx_attr.pending_limit = attr->pending_limit;
	cons_idx_attr.coalescing_time  = attr->coalescing_time;

	if (attr->intr_en) {
		cons_idx_attr.intr_en = attr->intr_en;
		cons_idx_attr.intr_idx = attr->intr_idx;
	}

	cons_idx_attr.l2nic_sqn = attr->l2nic_sqn;
	cons_idx_attr.ci_addr = attr->ci_dma_base;

	err = l2nic_msg_to_mgmt_sync(hwdev, HINIC3_NIC_CMD_SQ_CI_ATTR_SET,
				     &cons_idx_attr, sizeof(cons_idx_attr),
				     &cons_idx_attr, &out_size);
	if (err || !out_size || cons_idx_attr.msg_head.status) {
		sdk_err(nic_io->dev_hdl,
			"Failed to set ci attribute table, err: %d, status: 0x%x, out_size: 0x%x\n",
			err, cons_idx_attr.msg_head.status, out_size);
		return -EFAULT;
	}

	return 0;
}

#define PF_SET_VF_MAC(hwdev, status)	\
		(hinic3_func_type(hwdev) == TYPE_VF && \
		(status) == HINIC3_PF_SET_VF_ALREADY)

static int hinic3_check_mac_info(void *hwdev, u8 status, u16 vlan_id)
{
	if ((status && status != HINIC3_MGMT_STATUS_EXIST) ||
	    ((vlan_id & CHECK_IPSU_15BIT) &&
	     status == HINIC3_MGMT_STATUS_EXIST)) {
		if (PF_SET_VF_MAC(hwdev, status))
			return 0;

		return -EINVAL;
	}

	return 0;
}

#define HINIC_VLAN_ID_MASK	0x7FFF

int hinic3_set_mac(void *hwdev, const u8 *mac_addr, u16 vlan_id, u16 func_id,
		   u16 channel)
{
	struct hinic3_port_mac_set mac_info;
	u16 out_size = sizeof(mac_info);
	struct hinic3_nic_io *nic_io = NULL;
	int err;

	if (!hwdev || !mac_addr)
		return -EINVAL;

	memset(&mac_info, 0, sizeof(mac_info));

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	if ((vlan_id & HINIC_VLAN_ID_MASK) >= VLAN_N_VID) {
		nic_err(nic_io->dev_hdl, "Invalid VLAN number: %d\n",
			(vlan_id & HINIC_VLAN_ID_MASK));
		return -EINVAL;
	}

	mac_info.func_id = func_id;
	mac_info.vlan_id = vlan_id;
	ether_addr_copy(mac_info.mac, mac_addr);

	err = l2nic_msg_to_mgmt_sync_ch(hwdev, HINIC3_NIC_CMD_SET_MAC,
					&mac_info, sizeof(mac_info),
					&mac_info, &out_size, channel);
	if (err || !out_size ||
	    hinic3_check_mac_info(hwdev, mac_info.msg_head.status,
				  mac_info.vlan_id)) {
		nic_err(nic_io->dev_hdl,
			"Failed to update MAC, err: %d, status: 0x%x, out size: 0x%x, channel: 0x%x\n",
			err, mac_info.msg_head.status, out_size, channel);
		return -EIO;
	}

	if (PF_SET_VF_MAC(hwdev, mac_info.msg_head.status)) {
		nic_warn(nic_io->dev_hdl, "PF has already set VF mac, Ignore set operation\n");
		return HINIC3_PF_SET_VF_ALREADY;
	}

	if (mac_info.msg_head.status == HINIC3_MGMT_STATUS_EXIST) {
		nic_warn(nic_io->dev_hdl, "MAC is repeated. Ignore update operation\n");
		return 0;
	}

	return 0;
}
EXPORT_SYMBOL(hinic3_set_mac);

int hinic3_del_mac(void *hwdev, const u8 *mac_addr, u16 vlan_id, u16 func_id,
		   u16 channel)
{
	struct hinic3_port_mac_set mac_info;
	u16 out_size = sizeof(mac_info);
	struct hinic3_nic_io *nic_io = NULL;
	int err;

	if (!hwdev || !mac_addr)
		return -EINVAL;

	memset(&mac_info, 0, sizeof(mac_info));

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);

	if ((vlan_id & HINIC_VLAN_ID_MASK) >= VLAN_N_VID) {
		nic_err(nic_io->dev_hdl, "Invalid VLAN number: %d\n",
			(vlan_id & HINIC_VLAN_ID_MASK));
		return -EINVAL;
	}

	mac_info.func_id = func_id;
	mac_info.vlan_id = vlan_id;
	ether_addr_copy(mac_info.mac, mac_addr);

	err = l2nic_msg_to_mgmt_sync_ch(hwdev, HINIC3_NIC_CMD_DEL_MAC,
					&mac_info, sizeof(mac_info), &mac_info,
					&out_size, channel);
	if (err || !out_size ||
	    (mac_info.msg_head.status && !PF_SET_VF_MAC(hwdev, mac_info.msg_head.status))) {
		nic_err(nic_io->dev_hdl,
			"Failed to delete MAC, err: %d, status: 0x%x, out size: 0x%x, channel: 0x%x\n",
			err, mac_info.msg_head.status, out_size, channel);
		return -EIO;
	}

	if (PF_SET_VF_MAC(hwdev, mac_info.msg_head.status)) {
		nic_warn(nic_io->dev_hdl, "PF has already set VF mac, Ignore delete operation.\n");
		return HINIC3_PF_SET_VF_ALREADY;
	}

	return 0;
}
EXPORT_SYMBOL(hinic3_del_mac);

int hinic3_update_mac(void *hwdev, u8 *old_mac, u8 *new_mac, u16 vlan_id,
		      u16 func_id)
{
	struct hinic3_port_mac_update mac_info;
	u16 out_size = sizeof(mac_info);
	struct hinic3_nic_io *nic_io = NULL;
	int err;

	if (!hwdev || !old_mac || !new_mac)
		return -EINVAL;

	memset(&mac_info, 0, sizeof(mac_info));

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);

	if ((vlan_id & HINIC_VLAN_ID_MASK) >= VLAN_N_VID) {
		nic_err(nic_io->dev_hdl, "Invalid VLAN number: %d\n",
			(vlan_id & HINIC_VLAN_ID_MASK));
		return -EINVAL;
	}

	mac_info.func_id = func_id;
	mac_info.vlan_id = vlan_id;
	ether_addr_copy(mac_info.old_mac, old_mac);
	ether_addr_copy(mac_info.new_mac, new_mac);

	err = l2nic_msg_to_mgmt_sync(hwdev, HINIC3_NIC_CMD_UPDATE_MAC,
				     &mac_info, sizeof(mac_info),
				     &mac_info, &out_size);
	if (err || !out_size ||
	    hinic3_check_mac_info(hwdev, mac_info.msg_head.status,
				  mac_info.vlan_id)) {
		nic_err(nic_io->dev_hdl,
			"Failed to update MAC, err: %d, status: 0x%x, out size: 0x%x\n",
			err, mac_info.msg_head.status, out_size);
		return -EIO;
	}

	if (PF_SET_VF_MAC(hwdev, mac_info.msg_head.status)) {
		nic_warn(nic_io->dev_hdl, "PF has already set VF MAC. Ignore update operation\n");
		return HINIC3_PF_SET_VF_ALREADY;
	}

	if (mac_info.msg_head.status == HINIC3_MGMT_STATUS_EXIST) {
		nic_warn(nic_io->dev_hdl, "MAC is repeated. Ignore update operation\n");
		return 0;
	}

	return 0;
}

int hinic3_get_default_mac(void *hwdev, u8 *mac_addr)
{
	struct hinic3_port_mac_set mac_info;
	u16 out_size = sizeof(mac_info);
	struct hinic3_nic_io *nic_io = NULL;
	int err;

	if (!hwdev || !mac_addr)
		return -EINVAL;

	memset(&mac_info, 0, sizeof(mac_info));

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);

	mac_info.func_id = hinic3_global_func_id(hwdev);

	err = l2nic_msg_to_mgmt_sync(hwdev, HINIC3_NIC_CMD_GET_MAC,
				     &mac_info, sizeof(mac_info),
		&mac_info, &out_size);
	if (err || !out_size || mac_info.msg_head.status) {
		nic_err(nic_io->dev_hdl,
			"Failed to get mac, err: %d, status: 0x%x, out size: 0x%x\n",
			err, mac_info.msg_head.status, out_size);
		return -EINVAL;
	}

	ether_addr_copy(mac_addr, mac_info.mac);

	return 0;
}

static int hinic3_config_vlan(struct hinic3_nic_io *nic_io, u8 opcode,
			      u16 vlan_id, u16 func_id)
{
	struct hinic3_cmd_vlan_config vlan_info;
	u16 out_size = sizeof(vlan_info);
	int err;

	memset(&vlan_info, 0, sizeof(vlan_info));
	vlan_info.opcode = opcode;
	vlan_info.func_id = func_id;
	vlan_info.vlan_id = vlan_id;

	err = l2nic_msg_to_mgmt_sync(nic_io->hwdev,
				     HINIC3_NIC_CMD_CFG_FUNC_VLAN,
				     &vlan_info, sizeof(vlan_info),
				     &vlan_info, &out_size);
	if (err || !out_size || vlan_info.msg_head.status) {
		nic_err(nic_io->dev_hdl,
			"Failed to %s vlan, err: %d, status: 0x%x, out size: 0x%x\n",
			opcode == HINIC3_CMD_OP_ADD ? "add" : "delete",
			err, vlan_info.msg_head.status, out_size);
		return -EINVAL;
	}

	return 0;
}

int hinic3_add_vlan(void *hwdev, u16 vlan_id, u16 func_id)
{
	struct hinic3_nic_io *nic_io = NULL;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	return hinic3_config_vlan(nic_io, HINIC3_CMD_OP_ADD, vlan_id, func_id);
}

int hinic3_del_vlan(void *hwdev, u16 vlan_id, u16 func_id)
{
	struct hinic3_nic_io *nic_io = NULL;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	return hinic3_config_vlan(nic_io, HINIC3_CMD_OP_DEL, vlan_id, func_id);
}

int hinic3_set_vport_enable(void *hwdev, u16 func_id, bool enable, u16 channel)
{
	struct hinic3_vport_state en_state;
	u16 out_size = sizeof(en_state);
	struct hinic3_nic_io *nic_io = NULL;
	int err;

	if (!hwdev)
		return -EINVAL;

	memset(&en_state, 0, sizeof(en_state));

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	en_state.func_id = func_id;
	en_state.state = enable ? 1 : 0;

	err = l2nic_msg_to_mgmt_sync_ch(hwdev, HINIC3_NIC_CMD_SET_VPORT_ENABLE,
					&en_state, sizeof(en_state),
					&en_state, &out_size, channel);
	if (err || !out_size || en_state.msg_head.status) {
		nic_err(nic_io->dev_hdl, "Failed to set vport state, err: %d, status: 0x%x, out size: 0x%x, channel: 0x%x\n",
			err, en_state.msg_head.status, out_size, channel);
		return -EINVAL;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(hinic3_set_vport_enable);

int hinic3_set_dcb_state(void *hwdev, struct hinic3_dcb_state *dcb_state)
{
	struct hinic3_nic_io *nic_io = NULL;

	if (!hwdev || !dcb_state)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!memcmp(&nic_io->dcb_state, dcb_state, sizeof(nic_io->dcb_state)))
		return 0;

	/* save in sdk, vf will get dcb state when probing */
	hinic3_save_dcb_state(nic_io, dcb_state);

	/* notify stateful in pf, than notify all vf */
	hinic3_notify_dcb_state_event(nic_io, dcb_state);

	return 0;
}

int hinic3_get_dcb_state(void *hwdev, struct hinic3_dcb_state *dcb_state)
{
	struct hinic3_nic_io *nic_io = NULL;

	if (!hwdev || !dcb_state)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	memcpy(dcb_state, &nic_io->dcb_state, sizeof(*dcb_state));

	return 0;
}
EXPORT_SYMBOL(hinic3_get_dcb_state);

int hinic3_get_cos_by_pri(void *hwdev, u8 pri, u8 *cos)
{
	struct hinic3_nic_io *nic_io = NULL;

	if (!hwdev || !cos)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	if (pri >= NIC_DCB_UP_MAX && nic_io->dcb_state.trust == HINIC3_DCB_PCP)
		return -EINVAL;

	if (pri >= NIC_DCB_IP_PRI_MAX && nic_io->dcb_state.trust == HINIC3_DCB_DSCP)
		return -EINVAL;

/*lint -e662*/
/*lint -e661*/
	if (nic_io->dcb_state.dcb_on) {
		if (nic_io->dcb_state.trust == HINIC3_DCB_PCP)
			*cos = nic_io->dcb_state.pcp2cos[pri];
		else
			*cos = nic_io->dcb_state.dscp2cos[pri];
	} else {
		*cos = nic_io->dcb_state.default_cos;
	}
/*lint +e662*/
/*lint +e661*/
	return 0;
}
EXPORT_SYMBOL(hinic3_get_cos_by_pri);

int hinic3_save_dcb_state(struct hinic3_nic_io *nic_io,
			  struct hinic3_dcb_state *dcb_state)
{
	memcpy(&nic_io->dcb_state, dcb_state, sizeof(*dcb_state));

	return 0;
}

int hinic3_get_pf_dcb_state(void *hwdev, struct hinic3_dcb_state *dcb_state)
{
	struct hinic3_cmd_vf_dcb_state vf_dcb;
	struct hinic3_nic_io *nic_io = NULL;
	u16 out_size = sizeof(vf_dcb);
	int err;

	if (!hwdev || !dcb_state)
		return -EINVAL;

	memset(&vf_dcb, 0, sizeof(vf_dcb));

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	if (hinic3_func_type(hwdev) != TYPE_VF) {
		nic_err(nic_io->dev_hdl, "Only vf need to get pf dcb state\n");
		return -EINVAL;
	}

	err = l2nic_msg_to_mgmt_sync(hwdev, HINIC3_NIC_CMD_VF_COS, &vf_dcb,
				     sizeof(vf_dcb), &vf_dcb, &out_size);
	if (err || !out_size || vf_dcb.msg_head.status) {
		nic_err(nic_io->dev_hdl, "Failed to get vf default cos, err: %d, status: 0x%x, out size: 0x%x\n",
			err, vf_dcb.msg_head.status, out_size);
		return -EFAULT;
	}

	memcpy(dcb_state, &vf_dcb.state, sizeof(*dcb_state));
	/* Save dcb_state in hw for stateful module */
	hinic3_save_dcb_state(nic_io, dcb_state);

	return 0;
}
EXPORT_SYMBOL(hinic3_get_pf_dcb_state);

#define UNSUPPORT_SET_PAUSE 0x10
static int hinic3_cfg_hw_pause(struct hinic3_nic_io *nic_io, u8 opcode,
			       struct nic_pause_config *nic_pause)
{
	struct hinic3_cmd_pause_config pause_info;
	u16 out_size = sizeof(pause_info);
	int err;

	memset(&pause_info, 0, sizeof(pause_info));

	pause_info.port_id = hinic3_physical_port_id(nic_io->hwdev);
	pause_info.opcode = opcode;
	if (opcode == HINIC3_CMD_OP_SET) {
		pause_info.auto_neg = nic_pause->auto_neg;
		pause_info.rx_pause = nic_pause->rx_pause;
		pause_info.tx_pause = nic_pause->tx_pause;
	}

	err = l2nic_msg_to_mgmt_sync(nic_io->hwdev,
				     HINIC3_NIC_CMD_CFG_PAUSE_INFO,
				     &pause_info, sizeof(pause_info),
				     &pause_info, &out_size);
	if (err || !out_size || pause_info.msg_head.status) {
		if (pause_info.msg_head.status == UNSUPPORT_SET_PAUSE) {
			err = -EOPNOTSUPP;
			nic_err(nic_io->dev_hdl, "Can not set pause when pfc is enable\n");
		} else {
			err = -EFAULT;
			nic_err(nic_io->dev_hdl, "Failed to %s pause info, err: %d, status: 0x%x, out size: 0x%x\n",
				opcode == HINIC3_CMD_OP_SET ? "set" : "get",
				err, pause_info.msg_head.status, out_size);
		}
		return err;
	}

	if (opcode == HINIC3_CMD_OP_GET) {
		nic_pause->auto_neg = pause_info.auto_neg;
		nic_pause->rx_pause = pause_info.rx_pause;
		nic_pause->tx_pause = pause_info.tx_pause;
	}

	return 0;
}

int hinic3_set_pause_info(void *hwdev, struct nic_pause_config nic_pause)
{
	struct hinic3_nic_cfg *nic_cfg = NULL;
	struct hinic3_nic_io *nic_io = NULL;
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);

	nic_cfg = &nic_io->nic_cfg;

	down(&nic_cfg->cfg_lock);

	err = hinic3_cfg_hw_pause(nic_io, HINIC3_CMD_OP_SET, &nic_pause);
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

int hinic3_get_pause_info(void *hwdev, struct nic_pause_config *nic_pause)
{
	struct hinic3_nic_cfg *nic_cfg = NULL;
	struct hinic3_nic_io *nic_io = NULL;
	int err = 0;

	if (!hwdev || !nic_pause)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	nic_cfg = &nic_io->nic_cfg;

	err = hinic3_cfg_hw_pause(nic_io, HINIC3_CMD_OP_GET, nic_pause);
	if (err)
		return err;

	if (nic_cfg->pause_set || !nic_pause->auto_neg) {
		nic_pause->rx_pause = nic_cfg->nic_pause.rx_pause;
		nic_pause->tx_pause = nic_cfg->nic_pause.tx_pause;
	}

	return 0;
}

int hinic3_sync_dcb_state(void *hwdev, u8 op_code, u8 state)
{
	struct hinic3_cmd_set_dcb_state dcb_state;
	struct hinic3_nic_io *nic_io = NULL;
	u16 out_size = sizeof(dcb_state);
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);

	memset(&dcb_state, 0, sizeof(dcb_state));

	dcb_state.op_code = op_code;
	dcb_state.state = state;
	dcb_state.func_id = hinic3_global_func_id(hwdev);

	err = l2nic_msg_to_mgmt_sync(hwdev, HINIC3_NIC_CMD_QOS_DCB_STATE,
				     &dcb_state, sizeof(dcb_state), &dcb_state, &out_size);
	if (err || dcb_state.head.status || !out_size) {
		nic_err(nic_io->dev_hdl,
			"Failed to set dcb state, err: %d, status: 0x%x, out size: 0x%x\n",
			err, dcb_state.head.status, out_size);
		return -EFAULT;
	}

	return 0;
}

int hinic3_dcb_set_rq_iq_mapping(void *hwdev, u32 num_rqs, u8 *map,
				 u32 max_map_num)
{
	return 0;
}
EXPORT_SYMBOL(hinic3_dcb_set_rq_iq_mapping);

int hinic3_flush_qps_res(void *hwdev)
{
	struct hinic3_cmd_clear_qp_resource sq_res;
	u16 out_size = sizeof(sq_res);
	struct hinic3_nic_io *nic_io = NULL;
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	memset(&sq_res, 0, sizeof(sq_res));

	sq_res.func_id = hinic3_global_func_id(hwdev);

	err = l2nic_msg_to_mgmt_sync(hwdev, HINIC3_NIC_CMD_CLEAR_QP_RESOURCE,
				     &sq_res, sizeof(sq_res), &sq_res,
				     &out_size);
	if (err || !out_size || sq_res.msg_head.status) {
		nic_err(nic_io->dev_hdl, "Failed to clear sq resources, err: %d, status: 0x%x, out size: 0x%x\n",
			err, sq_res.msg_head.status, out_size);
		return -EINVAL;
	}

	return 0;
}
EXPORT_SYMBOL(hinic3_flush_qps_res);

int hinic3_cache_out_qps_res(void *hwdev)
{
	struct hinic3_cmd_cache_out_qp_resource qp_res;
	u16 out_size = sizeof(qp_res);
	struct hinic3_nic_io *nic_io = NULL;
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	memset(&qp_res, 0, sizeof(qp_res));

	qp_res.func_id = hinic3_global_func_id(hwdev);

	err = l2nic_msg_to_mgmt_sync(hwdev, HINIC3_NIC_CMD_CACHE_OUT_QP_RES,
				     &qp_res, sizeof(qp_res), &qp_res, &out_size);
	if (err || !out_size || qp_res.msg_head.status) {
		nic_err(nic_io->dev_hdl, "Failed to cache out qp resources, err: %d, status: 0x%x, out size: 0x%x\n",
			err, qp_res.msg_head.status, out_size);
		return -EIO;
	}

	return 0;
}

int hinic3_get_fpga_phy_port_stats(void *hwdev, struct hinic3_phy_fpga_port_stats *stats)
{
	struct hinic3_port_stats *port_stats = NULL;
	struct hinic3_port_stats_info stats_info;
	u16 out_size = sizeof(*port_stats);
	struct hinic3_nic_io *nic_io = NULL;
	int err;

	port_stats = kzalloc(sizeof(*port_stats), GFP_KERNEL);
	if (!port_stats)
		return -ENOMEM;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	memset(&stats_info, 0, sizeof(stats_info));

	err = l2nic_msg_to_mgmt_sync(hwdev, HINIC3_NIC_CMD_GET_PORT_STAT,
				     &stats_info, sizeof(stats_info),
				     port_stats, &out_size);
	if (err || !out_size || port_stats->msg_head.status) {
		nic_err(nic_io->dev_hdl,
			"Failed to get port statistics, err: %d, status: 0x%x, out size: 0x%x\n",
			err, port_stats->msg_head.status, out_size);
		err = -EIO;
		goto out;
	}

	memcpy(stats, &port_stats->stats, sizeof(*stats));

out:
	kfree(port_stats);

	return err;
}
EXPORT_SYMBOL(hinic3_get_fpga_phy_port_stats);

int hinic3_get_vport_stats(void *hwdev, u16 func_id, struct hinic3_vport_stats *stats)
{
	struct hinic3_port_stats_info stats_info;
	struct hinic3_cmd_vport_stats vport_stats;
	u16 out_size = sizeof(vport_stats);
	struct hinic3_nic_io *nic_io = NULL;
	int err;

	if (!hwdev || !stats)
		return -EINVAL;

	memset(&stats_info, 0, sizeof(stats_info));
	memset(&vport_stats, 0, sizeof(vport_stats));

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);

	stats_info.func_id = func_id;

	err = l2nic_msg_to_mgmt_sync(hwdev, HINIC3_NIC_CMD_GET_VPORT_STAT,
				     &stats_info, sizeof(stats_info),
				     &vport_stats, &out_size);
	if (err || !out_size || vport_stats.msg_head.status) {
		nic_err(nic_io->dev_hdl,
			"Failed to get function statistics, err: %d, status: 0x%x, out size: 0x%x\n",
			err, vport_stats.msg_head.status, out_size);
		return -EFAULT;
	}

	memcpy(stats, &vport_stats.stats, sizeof(*stats));

	return 0;
}

static int hinic3_set_function_table(struct hinic3_nic_io *nic_io, u32 cfg_bitmap,
				     const struct hinic3_func_tbl_cfg *cfg)
{
	struct hinic3_cmd_set_func_tbl cmd_func_tbl;
	u16 out_size = sizeof(cmd_func_tbl);
	int err;

	memset(&cmd_func_tbl, 0, sizeof(cmd_func_tbl));
	cmd_func_tbl.func_id = hinic3_global_func_id(nic_io->hwdev);
	cmd_func_tbl.cfg_bitmap = cfg_bitmap;
	cmd_func_tbl.tbl_cfg = *cfg;

	err = l2nic_msg_to_mgmt_sync(nic_io->hwdev,
				     HINIC3_NIC_CMD_SET_FUNC_TBL,
				     &cmd_func_tbl, sizeof(cmd_func_tbl),
				     &cmd_func_tbl, &out_size);
	if (err || cmd_func_tbl.msg_head.status || !out_size) {
		nic_err(nic_io->dev_hdl,
			"Failed to set func table, bitmap: 0x%x, err: %d, status: 0x%x, out size: 0x%x\n",
			cfg_bitmap, err, cmd_func_tbl.msg_head.status,
			out_size);
		return -EFAULT;
	}

	return 0;
}

static int hinic3_init_function_table(struct hinic3_nic_io *nic_io)
{
	struct hinic3_func_tbl_cfg func_tbl_cfg = {0};
	u32 cfg_bitmap = BIT(FUNC_CFG_INIT) | BIT(FUNC_CFG_MTU) |
			BIT(FUNC_CFG_RX_BUF_SIZE);

	func_tbl_cfg.mtu = 0x3FFF; /* default, max mtu */
	func_tbl_cfg.rx_wqe_buf_size = nic_io->rx_buff_len;

	return hinic3_set_function_table(nic_io, cfg_bitmap, &func_tbl_cfg);
}

int hinic3_set_port_mtu(void *hwdev, u16 new_mtu)
{
	struct hinic3_func_tbl_cfg func_tbl_cfg = {0};
	struct hinic3_nic_io *nic_io = NULL;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);

	if (new_mtu < HINIC3_MIN_MTU_SIZE) {
		nic_err(nic_io->dev_hdl,
			"Invalid mtu size: %ubytes, mtu size < %ubytes",
			new_mtu, HINIC3_MIN_MTU_SIZE);
		return -EINVAL;
	}

	if (new_mtu > HINIC3_MAX_JUMBO_FRAME_SIZE) {
		nic_err(nic_io->dev_hdl, "Invalid mtu size: %ubytes, mtu size > %ubytes",
			new_mtu, HINIC3_MAX_JUMBO_FRAME_SIZE);
		return -EINVAL;
	}

	func_tbl_cfg.mtu = new_mtu;
	return hinic3_set_function_table(nic_io, BIT(FUNC_CFG_MTU),
					 &func_tbl_cfg);
}

static int nic_feature_nego(void *hwdev, u8 opcode, u64 *s_feature, u16 size)
{
	struct hinic3_nic_io *nic_io = NULL;
	struct hinic3_cmd_feature_nego feature_nego;
	u16 out_size = sizeof(feature_nego);
	int err;

	if (!hwdev || !s_feature || size > NIC_MAX_FEATURE_QWORD)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	memset(&feature_nego, 0, sizeof(feature_nego));
	feature_nego.func_id = hinic3_global_func_id(hwdev);
	feature_nego.opcode = opcode;
	if (opcode == HINIC3_CMD_OP_SET)
		memcpy(feature_nego.s_feature, s_feature, size * sizeof(u64));

	err = l2nic_msg_to_mgmt_sync(hwdev, HINIC3_NIC_CMD_FEATURE_NEGO,
				     &feature_nego, sizeof(feature_nego),
				     &feature_nego, &out_size);
	if (err || !out_size || feature_nego.msg_head.status) {
		nic_err(nic_io->dev_hdl, "Failed to negotiate nic feature, err:%d, status: 0x%x, out_size: 0x%x\n",
			err, feature_nego.msg_head.status, out_size);
		return -EIO;
	}

	if (opcode == HINIC3_CMD_OP_GET)
		memcpy(s_feature, feature_nego.s_feature, size * sizeof(u64));

	return 0;
}

static int hinic3_get_bios_pf_bw_limit(void *hwdev, u32 *pf_bw_limit)
{
	struct hinic3_nic_io *nic_io = NULL;
	struct nic_cmd_bios_cfg cfg = {{0}};
	u16 out_size = sizeof(cfg);
	int err;

	if (!hwdev || !pf_bw_limit)
		return -EINVAL;

	if (hinic3_func_type(hwdev) == TYPE_VF || !HINIC3_SUPPORT_RATE_LIMIT(hwdev))
		return 0;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	cfg.bios_cfg.func_id = (u8)hinic3_global_func_id(hwdev);
	cfg.bios_cfg.func_valid = 1;
	cfg.op_code = 0 | NIC_NVM_DATA_PF_SPEED_LIMIT;

	err = l2nic_msg_to_mgmt_sync(hwdev, HINIC3_NIC_CMD_BIOS_CFG, &cfg, sizeof(cfg),
				     &cfg, &out_size);
	if (err || !out_size || cfg.head.status) {
		nic_err(nic_io->dev_hdl,
			"Failed to get bios pf bandwidth limit, err: %d, status: 0x%x, out size: 0x%x\n",
			err, cfg.head.status, out_size);
		return -EIO;
	}

	/* check data is valid or not */
	if (cfg.bios_cfg.signature != BIOS_CFG_SIGNATURE)
		nic_warn(nic_io->dev_hdl, "Invalid bios configuration data, signature: 0x%x\n",
			 cfg.bios_cfg.signature);

	if (cfg.bios_cfg.pf_bw > MAX_LIMIT_BW) {
		nic_err(nic_io->dev_hdl, "Invalid bios cfg pf bandwidth limit: %u\n",
			cfg.bios_cfg.pf_bw);
		return -EINVAL;
	}

	*pf_bw_limit = cfg.bios_cfg.pf_bw;

	return 0;
}

int hinic3_set_pf_rate(void *hwdev, u8 speed_level)
{
	struct hinic3_cmd_tx_rate_cfg rate_cfg = {{0}};
	struct hinic3_nic_io *nic_io = NULL;
	u16 out_size = sizeof(rate_cfg);
	u32 pf_rate;
	int err;
	u32 speed_convert[PORT_SPEED_UNKNOWN] = {
		0, 10, 100, 1000, 10000, 25000, 40000, 50000, 100000, 200000
	};

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	if (speed_level >= PORT_SPEED_UNKNOWN) {
		nic_err(nic_io->dev_hdl, "Invalid speed level: %hhu\n", speed_level);
		return -EINVAL;
	}

	if (nic_io->nic_cfg.pf_bw_limit == MAX_LIMIT_BW) {
		pf_rate = 0;
	} else {
		/* divided by 100 to convert to percentage */
		pf_rate = (speed_convert[speed_level] / 100) * nic_io->nic_cfg.pf_bw_limit;
		/* bandwidth limit is very small but not unlimit in this case */
		if (pf_rate == 0 && speed_level != PORT_SPEED_NOT_SET)
			pf_rate = 1;
	}

	rate_cfg.func_id = hinic3_global_func_id(hwdev);
	rate_cfg.min_rate = 0;
	rate_cfg.max_rate = pf_rate;

	err = l2nic_msg_to_mgmt_sync(hwdev, HINIC3_NIC_CMD_SET_MAX_MIN_RATE, &rate_cfg,
				     sizeof(rate_cfg), &rate_cfg, &out_size);
	if (err || !out_size || rate_cfg.msg_head.status) {
		nic_err(nic_io->dev_hdl, "Failed to set rate(%u), err: %d, status: 0x%x, out size: 0x%x\n",
			pf_rate, err, rate_cfg.msg_head.status, out_size);
		return rate_cfg.msg_head.status ? rate_cfg.msg_head.status : -EIO;
	}

	return 0;
}

static int hinic3_get_nic_feature_from_hw(void *hwdev, u64 *s_feature, u16 size)
{
	return nic_feature_nego(hwdev, HINIC3_CMD_OP_GET, s_feature, size);
}

int hinic3_set_nic_feature_to_hw(void *hwdev)
{
	struct hinic3_nic_io *nic_io = NULL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);

	return nic_feature_nego(hwdev, HINIC3_CMD_OP_SET, &nic_io->feature_cap, 1);
}

u64 hinic3_get_feature_cap(void *hwdev)
{
	struct hinic3_nic_io *nic_io = NULL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);

	return nic_io->feature_cap;
}

void hinic3_update_nic_feature(void *hwdev, u64 s_feature)
{
	struct hinic3_nic_io *nic_io = NULL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	nic_io->feature_cap = s_feature;

	nic_info(nic_io->dev_hdl, "Update nic feature to 0x%llx\n", nic_io->feature_cap);
}

static inline int init_nic_hwdev_param_valid(const void *hwdev, const void *pcidev_hdl,
					     const void *dev_hdl)
{
	if (!hwdev || !pcidev_hdl || !dev_hdl)
		return -EINVAL;

	return 0;
}

static int hinic3_init_nic_io(void *hwdev, void *pcidev_hdl, void *dev_hdl,
			      struct hinic3_nic_io **nic_io)
{
	if (init_nic_hwdev_param_valid(hwdev, pcidev_hdl, dev_hdl))
		return -EINVAL;

	*nic_io = kzalloc(sizeof(**nic_io), GFP_KERNEL);
	if (!(*nic_io))
		return -ENOMEM;

	(*nic_io)->dev_hdl = dev_hdl;
	(*nic_io)->pcidev_hdl = pcidev_hdl;
	(*nic_io)->hwdev = hwdev;

	sema_init(&((*nic_io)->nic_cfg.cfg_lock), 1);
	mutex_init(&((*nic_io)->nic_cfg.sfp_mutex));

	(*nic_io)->nic_cfg.rt_cmd.mpu_send_sfp_abs = false;
	(*nic_io)->nic_cfg.rt_cmd.mpu_send_sfp_info = false;

	return 0;
}

/* *
 * hinic3_init_nic_hwdev - init nic hwdev
 * @hwdev: pointer to hwdev
 * @pcidev_hdl: pointer to pcidev or handler
 * @dev_hdl: pointer to pcidev->dev or handler, for sdk_err() or dma_alloc()
 * @rx_buff_len: rx_buff_len is receive buffer length
 */
int hinic3_init_nic_hwdev(void *hwdev, void *pcidev_hdl, void *dev_hdl,
			  u16 rx_buff_len)
{
	struct hinic3_nic_io *nic_io = NULL;
	int err;

	err = hinic3_init_nic_io(hwdev, pcidev_hdl, dev_hdl, &nic_io);
	if (err)
		return err;

	err = hinic3_register_service_adapter(hwdev, nic_io, SERVICE_T_NIC);
	if (err) {
		nic_err(nic_io->dev_hdl, "Failed to register service adapter\n");
		goto register_sa_err;
	}

	err = hinic3_set_func_svc_used_state(hwdev, SVC_T_NIC, 1, HINIC3_CHANNEL_NIC);
	if (err) {
		nic_err(nic_io->dev_hdl, "Failed to set function svc used state\n");
		goto set_used_state_err;
	}

	err = hinic3_init_function_table(nic_io);
	if (err) {
		nic_err(nic_io->dev_hdl, "Failed to init function table\n");
		goto err_out;
	}

	err = hinic3_get_nic_feature_from_hw(hwdev, &nic_io->feature_cap, 1);
	if (err) {
		nic_err(nic_io->dev_hdl, "Failed to get nic features\n");
		goto err_out;
	}

	sdk_info(dev_hdl, "nic features: 0x%llx\n", nic_io->feature_cap);

	err = hinic3_get_bios_pf_bw_limit(hwdev, &nic_io->nic_cfg.pf_bw_limit);
	if (err) {
		nic_err(nic_io->dev_hdl, "Failed to get pf bandwidth limit\n");
		goto err_out;
	}

	err = hinic3_vf_func_init(nic_io);
	if (err) {
		nic_err(nic_io->dev_hdl, "Failed to init vf info\n");
		goto err_out;
	}

	nic_io->rx_buff_len = rx_buff_len;

	return 0;

err_out:
	hinic3_set_func_svc_used_state(hwdev, SVC_T_NIC, 0, HINIC3_CHANNEL_NIC);

set_used_state_err:
	hinic3_unregister_service_adapter(hwdev, SERVICE_T_NIC);

register_sa_err:
	mutex_deinit(&nic_io->nic_cfg.sfp_mutex);
	sema_deinit(&nic_io->nic_cfg.cfg_lock);

	kfree(nic_io);

	return err;
}
EXPORT_SYMBOL(hinic3_init_nic_hwdev);

void hinic3_free_nic_hwdev(void *hwdev)
{
	struct hinic3_nic_io *nic_io = NULL;

	if (!hwdev)
		return;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return;

	hinic3_vf_func_free(nic_io);

	hinic3_set_func_svc_used_state(hwdev, SVC_T_NIC, 0, HINIC3_CHANNEL_NIC);

	hinic3_unregister_service_adapter(hwdev, SERVICE_T_NIC);

	mutex_deinit(&nic_io->nic_cfg.sfp_mutex);
	sema_deinit(&nic_io->nic_cfg.cfg_lock);

	kfree(nic_io);
}
EXPORT_SYMBOL(hinic3_free_nic_hwdev);

int hinic3_force_drop_tx_pkt(void *hwdev)
{
	struct hinic3_nic_io *nic_io = NULL;
	struct hinic3_force_pkt_drop pkt_drop;
	u16 out_size = sizeof(pkt_drop);
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);

	memset(&pkt_drop, 0, sizeof(pkt_drop));
	pkt_drop.port = hinic3_physical_port_id(hwdev);
	err = l2nic_msg_to_mgmt_sync(hwdev, HINIC3_NIC_CMD_FORCE_PKT_DROP,
				     &pkt_drop, sizeof(pkt_drop),
				     &pkt_drop, &out_size);
	if ((pkt_drop.msg_head.status != HINIC3_MGMT_CMD_UNSUPPORTED &&
	     pkt_drop.msg_head.status) || err || !out_size) {
		nic_err(nic_io->dev_hdl,
			"Failed to set force tx packets drop, err: %d, status: 0x%x, out size: 0x%x\n",
			err, pkt_drop.msg_head.status, out_size);
		return -EFAULT;
	}

	return pkt_drop.msg_head.status;
}

int hinic3_set_rx_mode(void *hwdev, u32 enable)
{
	struct hinic3_nic_io *nic_io = NULL;
	struct hinic3_rx_mode_config rx_mode_cfg;
	u16 out_size = sizeof(rx_mode_cfg);
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);

	memset(&rx_mode_cfg, 0, sizeof(rx_mode_cfg));
	rx_mode_cfg.func_id = hinic3_global_func_id(hwdev);
	rx_mode_cfg.rx_mode = enable;

	err = l2nic_msg_to_mgmt_sync(hwdev, HINIC3_NIC_CMD_SET_RX_MODE,
				     &rx_mode_cfg, sizeof(rx_mode_cfg),
				     &rx_mode_cfg, &out_size);
	if (err || !out_size || rx_mode_cfg.msg_head.status) {
		nic_err(nic_io->dev_hdl, "Failed to set rx mode, err: %d, status: 0x%x, out size: 0x%x\n",
			err, rx_mode_cfg.msg_head.status, out_size);
		return -EINVAL;
	}

	return 0;
}

int hinic3_set_rx_vlan_offload(void *hwdev, u8 en)
{
	struct hinic3_nic_io *nic_io = NULL;
	struct hinic3_cmd_vlan_offload vlan_cfg;
	u16 out_size = sizeof(vlan_cfg);
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);

	memset(&vlan_cfg, 0, sizeof(vlan_cfg));
	vlan_cfg.func_id = hinic3_global_func_id(hwdev);
	vlan_cfg.vlan_offload = en;

	err = l2nic_msg_to_mgmt_sync(hwdev, HINIC3_NIC_CMD_SET_RX_VLAN_OFFLOAD,
				     &vlan_cfg, sizeof(vlan_cfg),
				     &vlan_cfg, &out_size);
	if (err || !out_size || vlan_cfg.msg_head.status) {
		nic_err(nic_io->dev_hdl, "Failed to set rx vlan offload, err: %d, status: 0x%x, out size: 0x%x\n",
			err, vlan_cfg.msg_head.status, out_size);
		return -EINVAL;
	}

	return 0;
}

int hinic3_update_mac_vlan(void *hwdev, u16 old_vlan, u16 new_vlan, int vf_id)
{
	struct vf_data_storage *vf_info = NULL;
	struct hinic3_nic_io *nic_io = NULL;
	u16 func_id;
	int err;

	if (!hwdev || old_vlan >= VLAN_N_VID || new_vlan >= VLAN_N_VID)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	vf_info = nic_io->vf_infos + HW_VF_ID_TO_OS(vf_id);
	if (!nic_io->vf_infos || is_zero_ether_addr(vf_info->drv_mac_addr))
		return 0;

	func_id = hinic3_glb_pf_vf_offset(nic_io->hwdev) + (u16)vf_id;

	err = hinic3_del_mac(nic_io->hwdev, vf_info->drv_mac_addr,
			     old_vlan, func_id, HINIC3_CHANNEL_NIC);
	if (err) {
		nic_err(nic_io->dev_hdl, "Failed to delete VF %d MAC %pM vlan %u\n",
			HW_VF_ID_TO_OS(vf_id), vf_info->drv_mac_addr, old_vlan);
		return err;
	}

	err = hinic3_set_mac(nic_io->hwdev, vf_info->drv_mac_addr,
			     new_vlan, func_id, HINIC3_CHANNEL_NIC);
	if (err) {
		nic_err(nic_io->dev_hdl, "Failed to add VF %d MAC %pM vlan %u\n",
			HW_VF_ID_TO_OS(vf_id), vf_info->drv_mac_addr, new_vlan);
		hinic3_set_mac(nic_io->hwdev, vf_info->drv_mac_addr,
			       old_vlan, func_id, HINIC3_CHANNEL_NIC);
		return err;
	}

	return 0;
}

static int hinic3_set_rx_lro(void *hwdev, u8 ipv4_en, u8 ipv6_en,
			     u8 lro_max_pkt_len)
{
	struct hinic3_nic_io *nic_io = NULL;
	struct hinic3_cmd_lro_config lro_cfg;
	u16 out_size = sizeof(lro_cfg);
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);

	memset(&lro_cfg, 0, sizeof(lro_cfg));
	lro_cfg.func_id = hinic3_global_func_id(hwdev);
	lro_cfg.opcode = HINIC3_CMD_OP_SET;
	lro_cfg.lro_ipv4_en = ipv4_en;
	lro_cfg.lro_ipv6_en = ipv6_en;
	lro_cfg.lro_max_pkt_len = lro_max_pkt_len;

	err = l2nic_msg_to_mgmt_sync(hwdev, HINIC3_NIC_CMD_CFG_RX_LRO,
				     &lro_cfg, sizeof(lro_cfg),
				     &lro_cfg, &out_size);
	if (err || !out_size || lro_cfg.msg_head.status) {
		nic_err(nic_io->dev_hdl, "Failed to set lro offload, err: %d, status: 0x%x, out size: 0x%x\n",
			err, lro_cfg.msg_head.status, out_size);
		return -EINVAL;
	}

	return 0;
}

static int hinic3_set_rx_lro_timer(void *hwdev, u32 timer_value)
{
	struct hinic3_nic_io *nic_io = NULL;
	struct hinic3_cmd_lro_timer lro_timer;
	u16 out_size = sizeof(lro_timer);
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);

	memset(&lro_timer, 0, sizeof(lro_timer));
	lro_timer.opcode = HINIC3_CMD_OP_SET;
	lro_timer.timer = timer_value;

	err = l2nic_msg_to_mgmt_sync(hwdev, HINIC3_NIC_CMD_CFG_LRO_TIMER,
				     &lro_timer, sizeof(lro_timer),
				     &lro_timer, &out_size);
	if (err || !out_size || lro_timer.msg_head.status) {
		nic_err(nic_io->dev_hdl, "Failed to set lro timer, err: %d, status: 0x%x, out size: 0x%x\n",
			err, lro_timer.msg_head.status, out_size);

		return -EINVAL;
	}

	return 0;
}

int hinic3_set_rx_lro_state(void *hwdev, u8 lro_en, u32 lro_timer,
			    u32 lro_max_pkt_len)
{
	struct hinic3_nic_io *nic_io = NULL;
	u8 ipv4_en = 0, ipv6_en = 0;
	int err;

	if (!hwdev)
		return -EINVAL;

	ipv4_en = lro_en ? 1 : 0;
	ipv6_en = lro_en ? 1 : 0;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);

	nic_info(nic_io->dev_hdl, "Set LRO max coalesce packet size to %uK\n",
		 lro_max_pkt_len);

	err = hinic3_set_rx_lro(hwdev, ipv4_en, ipv6_en, (u8)lro_max_pkt_len);
	if (err)
		return err;

	/* we don't set LRO timer for VF */
	if (hinic3_func_type(hwdev) == TYPE_VF)
		return 0;

	nic_info(nic_io->dev_hdl, "Set LRO timer to %u\n", lro_timer);

	return hinic3_set_rx_lro_timer(hwdev, lro_timer);
}

int hinic3_set_vlan_fliter(void *hwdev, u32 vlan_filter_ctrl)
{
	struct hinic3_nic_io *nic_io = NULL;
	struct hinic3_cmd_set_vlan_filter vlan_filter;
	u16 out_size = sizeof(vlan_filter);
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);

	memset(&vlan_filter, 0, sizeof(vlan_filter));
	vlan_filter.func_id = hinic3_global_func_id(hwdev);
	vlan_filter.vlan_filter_ctrl = vlan_filter_ctrl;

	err = l2nic_msg_to_mgmt_sync(hwdev, HINIC3_NIC_CMD_SET_VLAN_FILTER_EN,
				     &vlan_filter, sizeof(vlan_filter),
				     &vlan_filter, &out_size);
	if (err || !out_size || vlan_filter.msg_head.status) {
		nic_err(nic_io->dev_hdl, "Failed to set vlan filter, err: %d, status: 0x%x, out size: 0x%x\n",
			err, vlan_filter.msg_head.status, out_size);
		return -EINVAL;
	}

	return 0;
}

int hinic3_set_func_capture_en(void *hwdev, u16 func_id, bool cap_en)
{
	// struct hinic_hwdev *dev = hwdev;
	struct nic_cmd_capture_info cap_info = {{0}};
	u16 out_size = sizeof(cap_info);
	int err;

	if (!hwdev)
		return -EINVAL;

	/* 2 function capture types */
	// cap_info.op_type = UP_UCAPTURE_OP_TYPE_FUNC;
	cap_info.is_en_trx = cap_en;
	cap_info.func_port = func_id;

	err = l2nic_msg_to_mgmt_sync(hwdev, HINIC3_NIC_CMD_SET_UCAPTURE_OPT,
				     &cap_info, sizeof(cap_info),
				     &cap_info, &out_size);
	if (err || !out_size || cap_info.msg_head.status)
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL(hinic3_set_func_capture_en);

int hinic3_add_tcam_rule(void *hwdev, struct nic_tcam_cfg_rule *tcam_rule)
{
	u16 out_size = sizeof(struct nic_cmd_fdir_add_rule);
	struct nic_cmd_fdir_add_rule tcam_cmd;
	struct hinic3_nic_io *nic_io = NULL;
	int err;

	if (!hwdev || !tcam_rule)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (tcam_rule->index >= HINIC3_MAX_TCAM_RULES_NUM) {
		nic_err(nic_io->dev_hdl, "Tcam rules num to add is invalid\n");
		return -EINVAL;
	}

	memset(&tcam_cmd, 0, sizeof(struct nic_cmd_fdir_add_rule));
	memcpy((void *)&tcam_cmd.rule, (void *)tcam_rule,
	       sizeof(struct nic_tcam_cfg_rule));
	tcam_cmd.func_id = hinic3_global_func_id(hwdev);
	tcam_cmd.type = TCAM_RULE_FDIR_TYPE;

	err = l2nic_msg_to_mgmt_sync(hwdev, HINIC3_NIC_CMD_ADD_TC_FLOW,
				     &tcam_cmd, sizeof(tcam_cmd),
				     &tcam_cmd, &out_size);
	if (err || tcam_cmd.head.status || !out_size) {
		nic_err(nic_io->dev_hdl,
			"Add tcam rule failed, err: %d, status: 0x%x, out size: 0x%x\n",
			err, tcam_cmd.head.status, out_size);
		return -EIO;
	}

	return 0;
}

int hinic3_del_tcam_rule(void *hwdev, u32 index)
{
	u16 out_size = sizeof(struct nic_cmd_fdir_del_rules);
	struct nic_cmd_fdir_del_rules tcam_cmd;
	struct hinic3_nic_io *nic_io = NULL;
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (index >= HINIC3_MAX_TCAM_RULES_NUM) {
		nic_err(nic_io->dev_hdl, "Tcam rules num to del is invalid\n");
		return -EINVAL;
	}

	memset(&tcam_cmd, 0, sizeof(struct nic_cmd_fdir_del_rules));
	tcam_cmd.index_start = index;
	tcam_cmd.index_num = 1;
	tcam_cmd.func_id = hinic3_global_func_id(hwdev);
	tcam_cmd.type = TCAM_RULE_FDIR_TYPE;

	err = l2nic_msg_to_mgmt_sync(hwdev, HINIC3_NIC_CMD_DEL_TC_FLOW,
				     &tcam_cmd, sizeof(tcam_cmd),
				     &tcam_cmd, &out_size);
	if (err || tcam_cmd.head.status || !out_size) {
		nic_err(nic_io->dev_hdl,
			"Del tcam rule failed, err: %d, status: 0x%x, out size: 0x%x\n",
			err, tcam_cmd.head.status, out_size);
		return -EIO;
	}

	return 0;
}

/**
 * hinic3_mgmt_tcam_block - alloc or free tcam block for IO packet.
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
static int hinic3_mgmt_tcam_block(void *hwdev, u8 alloc_en, u16 *index)
{
	struct nic_cmd_ctrl_tcam_block_out tcam_block_info;
	u16 out_size = sizeof(struct nic_cmd_ctrl_tcam_block_out);
	struct hinic3_nic_io *nic_io = NULL;
	int err;

	if (!hwdev || !index)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	memset(&tcam_block_info, 0,
	       sizeof(struct nic_cmd_ctrl_tcam_block_out));

	tcam_block_info.func_id = hinic3_global_func_id(hwdev);
	tcam_block_info.alloc_en = alloc_en;
	tcam_block_info.tcam_type = NIC_TCAM_BLOCK_TYPE_LARGE;
	tcam_block_info.tcam_block_index = *index;

	err = l2nic_msg_to_mgmt_sync(hwdev, HINIC3_NIC_CMD_CFG_TCAM_BLOCK,
				     &tcam_block_info, sizeof(tcam_block_info),
				     &tcam_block_info, &out_size);
	if (err || tcam_block_info.head.status || !out_size) {
		nic_err(nic_io->dev_hdl,
			"Set tcam block failed, err: %d, status: 0x%x, out size: 0x%x\n",
			err, tcam_block_info.head.status, out_size);
		return -EIO;
	}

	if (alloc_en)
		*index = tcam_block_info.tcam_block_index;

	return 0;
}

int hinic3_alloc_tcam_block(void *hwdev, u16 *index)
{
	return hinic3_mgmt_tcam_block(hwdev, HINIC3_TCAM_BLOCK_ENABLE, index);
}

int hinic3_free_tcam_block(void *hwdev, u16 *index)
{
	return hinic3_mgmt_tcam_block(hwdev, HINIC3_TCAM_BLOCK_DISABLE, index);
}

int hinic3_set_fdir_tcam_rule_filter(void *hwdev, bool enable)
{
	struct nic_cmd_set_tcam_enable port_tcam_cmd;
	u16 out_size = sizeof(port_tcam_cmd);
	struct hinic3_nic_io *nic_io = NULL;
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	memset(&port_tcam_cmd, 0, sizeof(port_tcam_cmd));
	port_tcam_cmd.func_id = hinic3_global_func_id(hwdev);
	port_tcam_cmd.tcam_enable = (u8)enable;

	err = l2nic_msg_to_mgmt_sync(hwdev, HINIC3_NIC_CMD_ENABLE_TCAM,
				     &port_tcam_cmd, sizeof(port_tcam_cmd),
				     &port_tcam_cmd, &out_size);
	if (err || port_tcam_cmd.head.status || !out_size) {
		nic_err(nic_io->dev_hdl, "Set fdir tcam filter failed, err: %d, status: 0x%x, out size: 0x%x, enable: 0x%x\n",
			err, port_tcam_cmd.head.status, out_size,
			enable);
		return -EIO;
	}

	return 0;
}

int hinic3_flush_tcam_rule(void *hwdev)
{
	struct nic_cmd_flush_tcam_rules tcam_flush;
	u16 out_size = sizeof(struct nic_cmd_flush_tcam_rules);
	struct hinic3_nic_io *nic_io = NULL;
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	memset(&tcam_flush, 0, sizeof(struct nic_cmd_flush_tcam_rules));
	tcam_flush.func_id = hinic3_global_func_id(hwdev);

	err = l2nic_msg_to_mgmt_sync(hwdev, HINIC3_NIC_CMD_FLUSH_TCAM,
				     &tcam_flush,
				     sizeof(struct nic_cmd_flush_tcam_rules),
				     &tcam_flush, &out_size);
	if (err || tcam_flush.head.status || !out_size) {
		nic_err(nic_io->dev_hdl,
			"Flush tcam fdir rules failed, err: %d, status: 0x%x, out size: 0x%x\n",
			err, tcam_flush.head.status, out_size);
		return -EIO;
	}

	return 0;
}

int hinic3_get_rxq_hw_info(void *hwdev, struct rxq_check_info *rxq_info, u16 num_qps, u16 wqe_type)
{
	struct hinic3_cmd_buf *cmd_buf = NULL;
	struct hinic3_nic_io *nic_io = NULL;
	struct hinic3_rxq_hw *rxq_hw = NULL;
	struct rxq_check_info *rxq_info_out = NULL;
	int err;
	u16 i;

	if (!hwdev || !rxq_info)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	cmd_buf = hinic3_alloc_cmd_buf(hwdev);
	if (!cmd_buf) {
		nic_err(nic_io->dev_hdl, "Failed to allocate cmd_buf.\n");
		return -ENOMEM;
	}

	rxq_hw = cmd_buf->buf;
	rxq_hw->func_id = hinic3_global_func_id(hwdev);
	rxq_hw->num_queues = num_qps;

	hinic3_cpu_to_be32(rxq_hw, sizeof(struct hinic3_rxq_hw));

	cmd_buf->size = sizeof(struct hinic3_rxq_hw);

	err = hinic3_cmdq_detail_resp(hwdev, HINIC3_MOD_L2NIC, HINIC3_UCODE_CMD_RXQ_INFO_GET,
				      cmd_buf, cmd_buf, NULL, 0, HINIC3_CHANNEL_NIC);
	if (err)
		goto get_rxq_info_failed;

	rxq_info_out = cmd_buf->buf;
	for (i = 0; i < num_qps; i++) {
		rxq_info[i].hw_pi = rxq_info_out[i].hw_pi >> wqe_type;
		rxq_info[i].hw_ci = rxq_info_out[i].hw_ci >> wqe_type;
	}

get_rxq_info_failed:
	hinic3_free_cmd_buf(hwdev, cmd_buf);

	return err;
}

int hinic3_pf_set_vf_link_state(void *hwdev, bool vf_link_forced, bool link_state)
{
	struct hinic3_nic_io *nic_io = NULL;
	struct vf_data_storage *vf_infos = NULL;
	int vf_id;

	if (!hwdev) {
		pr_err("hwdev is null.\n");
		return -EINVAL;
	}

	if (hinic3_func_type(hwdev) == TYPE_VF)
		return -EINVAL;

	nic_io = hinic3_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io) {
		pr_err("nic_io is null.\n");
		return -EINVAL;
	}

	vf_infos = nic_io->vf_infos;
	for (vf_id = 0; vf_id < nic_io->max_vfs; vf_id++) {
		vf_infos[vf_id].link_up = link_state;
		vf_infos[vf_id].link_forced = vf_link_forced;
	}

	return 0;
}
EXPORT_SYMBOL(hinic3_pf_set_vf_link_state);
