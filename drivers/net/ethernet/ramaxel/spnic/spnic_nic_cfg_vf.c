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

static unsigned char set_vf_link_state;
module_param(set_vf_link_state, byte, 0444);
MODULE_PARM_DESC(set_vf_link_state, "Set vf link state, 0 represents link auto, 1 represents link always up, 2 represents link always down. - default is 0.");

/* In order to adapt different linux version */
enum {
	SPNIC_IFLA_VF_LINK_STATE_AUTO,	/* link state of the uplink */
	SPNIC_IFLA_VF_LINK_STATE_ENABLE,	/* link always up */
	SPNIC_IFLA_VF_LINK_STATE_DISABLE,	/* link always down */
};

#define NIC_CVLAN_INSERT_ENABLE 0x1
#define NIC_QINQ_INSERT_ENABLE  0X3
static int spnic_set_vlan_ctx(struct spnic_nic_cfg *nic_cfg, u16 func_id,
			      u16 vlan_tag, u16 q_id, bool add)
{
	struct nic_vlan_ctx *vlan_ctx = NULL;
	struct sphw_cmd_buf *cmd_buf = NULL;
	u64 out_param = 0;
	int err;

	cmd_buf = sphw_alloc_cmd_buf(nic_cfg->hwdev);
	if (!cmd_buf) {
		nic_err(nic_cfg->dev_hdl, "Failed to allocate cmd buf\n");
		return -ENOMEM;
	}

	cmd_buf->size = sizeof(struct nic_vlan_ctx);
	vlan_ctx = (struct nic_vlan_ctx *)cmd_buf->buf;

	vlan_ctx->func_id = func_id;
	vlan_ctx->qid = q_id;
	vlan_ctx->vlan_tag = vlan_tag;
	vlan_ctx->vlan_sel = 0; /* TPID0 in IPSU */
	vlan_ctx->vlan_mode = add ?
		NIC_QINQ_INSERT_ENABLE : NIC_CVLAN_INSERT_ENABLE;

	sphw_cpu_to_be32(vlan_ctx, sizeof(struct nic_vlan_ctx));

	err = sphw_cmdq_direct_resp(nic_cfg->hwdev, SPHW_MOD_L2NIC, SPNIC_UCODE_CMD_MODIFY_VLAN_CTX,
				    cmd_buf, &out_param, 0, SPHW_CHANNEL_NIC);

	sphw_free_cmd_buf(nic_cfg->hwdev, cmd_buf);

	if (err || out_param != 0) {
		nic_err(nic_cfg->dev_hdl, "Failed to set vlan context, err: %d, out_param: 0x%llx\n",
			err, out_param);
		return -EFAULT;
	}

	return err;
}

int spnic_cfg_vf_vlan(struct spnic_nic_cfg *nic_cfg, u8 opcode, u16 vid, u8 qos, int vf_id)
{
	struct spnic_cmd_vf_vlan_config vf_vlan;
	u16 out_size = sizeof(vf_vlan);
	u16 glb_func_id;
	int err;
	u16 vlan_tag;

	/* VLAN 0 is a special case, don't allow it to be removed */
	if (!vid && opcode == SPNIC_CMD_OP_DEL)
		return 0;

	memset(&vf_vlan, 0, sizeof(vf_vlan));

	vf_vlan.opcode = opcode;
	vf_vlan.func_id = sphw_glb_pf_vf_offset(nic_cfg->hwdev) + (u16)vf_id;
	vf_vlan.vlan_id = vid;
	vf_vlan.qos = qos;

	err = l2nic_msg_to_mgmt_sync(nic_cfg->hwdev, SPNIC_NIC_CMD_CFG_VF_VLAN,
				     &vf_vlan, sizeof(vf_vlan), &vf_vlan, &out_size);
	if (err || !out_size || vf_vlan.msg_head.status) {
		nic_err(nic_cfg->dev_hdl, "Failed to set VF %d vlan, err: %d, status: 0x%x,out size: 0x%x\n",
			HW_VF_ID_TO_OS(vf_id), err, vf_vlan.msg_head.status, out_size);
		return -EFAULT;
	}

	vlan_tag = vid + (u16)(qos << VLAN_PRIO_SHIFT);

	glb_func_id = sphw_glb_pf_vf_offset(nic_cfg->hwdev) + (u16)vf_id;
	err = spnic_set_vlan_ctx(nic_cfg, glb_func_id, vlan_tag, NIC_CONFIG_ALL_QUEUE_VLAN_CTX,
				 opcode == SPNIC_CMD_OP_ADD);
	if (err) {
		nic_err(nic_cfg->dev_hdl, "Failed to set VF %d vlan ctx, err: %d\n",
			HW_VF_ID_TO_OS(vf_id), err);

		/* rollback vlan config */
		if (opcode == SPNIC_CMD_OP_DEL)
			vf_vlan.opcode = SPNIC_CMD_OP_ADD;
		else
			vf_vlan.opcode = SPNIC_CMD_OP_DEL;
		l2nic_msg_to_mgmt_sync(nic_cfg->hwdev, SPNIC_NIC_CMD_CFG_VF_VLAN, &vf_vlan,
				       sizeof(vf_vlan), &vf_vlan, &out_size);
		return err;
	}

	return 0;
}

/* this function just be called by spnic_ndo_set_vf_mac,
 * others are not permitted.
 */
int spnic_set_vf_mac(void *hwdev, int vf, unsigned char *mac_addr)
{
	struct vf_data_storage *vf_info;
	struct spnic_nic_cfg *nic_cfg;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	vf_info = nic_cfg->vf_infos + HW_VF_ID_TO_OS(vf);

	/* duplicate request, so just return success */
	if (ether_addr_equal(vf_info->user_mac_addr, mac_addr))
		return 0;

	ether_addr_copy(vf_info->user_mac_addr, mac_addr);

	return 0;
}

int spnic_add_vf_vlan(void *hwdev, int vf_id, u16 vlan, u8 qos)
{
	struct spnic_nic_cfg *nic_cfg;
	int err;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	err = spnic_cfg_vf_vlan(nic_cfg, SPNIC_CMD_OP_ADD, vlan, qos, vf_id);
	if (err)
		return err;

	nic_cfg->vf_infos[HW_VF_ID_TO_OS(vf_id)].pf_vlan = vlan;
	nic_cfg->vf_infos[HW_VF_ID_TO_OS(vf_id)].pf_qos = qos;

	nic_info(nic_cfg->dev_hdl, "Setting VLAN %u, QOS 0x%x on VF %d\n",
		 vlan, qos, HW_VF_ID_TO_OS(vf_id));

	return 0;
}

int spnic_kill_vf_vlan(void *hwdev, int vf_id)
{
	struct vf_data_storage *vf_infos;
	struct spnic_nic_cfg *nic_cfg;
	int err;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	vf_infos = nic_cfg->vf_infos;

	err = spnic_cfg_vf_vlan(nic_cfg, SPNIC_CMD_OP_DEL, vf_infos[HW_VF_ID_TO_OS(vf_id)].pf_vlan,
				vf_infos[HW_VF_ID_TO_OS(vf_id)].pf_qos, vf_id);
	if (err)
		return err;

	nic_info(nic_cfg->dev_hdl, "Remove VLAN %u on VF %d\n",
		 vf_infos[HW_VF_ID_TO_OS(vf_id)].pf_vlan, HW_VF_ID_TO_OS(vf_id));

	vf_infos[HW_VF_ID_TO_OS(vf_id)].pf_vlan = 0;
	vf_infos[HW_VF_ID_TO_OS(vf_id)].pf_qos = 0;

	return 0;
}

u16 spnic_vf_info_vlanprio(void *hwdev, int vf_id)
{
	struct spnic_nic_cfg *nic_cfg;
	u16 pf_vlan, vlanprio;
	u8 pf_qos;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	pf_vlan = nic_cfg->vf_infos[HW_VF_ID_TO_OS(vf_id)].pf_vlan;
	pf_qos = nic_cfg->vf_infos[HW_VF_ID_TO_OS(vf_id)].pf_qos;
	vlanprio = (u16)(pf_vlan | pf_qos << SPNIC_VLAN_PRIORITY_SHIFT);

	return vlanprio;
}

int spnic_set_vf_link_state(void *hwdev, u16 vf_id, int link)
{
	struct spnic_nic_cfg *nic_cfg =
		sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	struct vf_data_storage *vf_infos = nic_cfg->vf_infos;
	u8 link_status = 0;

	switch (link) {
	case SPNIC_IFLA_VF_LINK_STATE_AUTO:
		vf_infos[HW_VF_ID_TO_OS(vf_id)].link_forced = false;
		vf_infos[HW_VF_ID_TO_OS(vf_id)].link_up = nic_cfg->link_status ? true : false;
		link_status = nic_cfg->link_status;
		break;
	case SPNIC_IFLA_VF_LINK_STATE_ENABLE:
		vf_infos[HW_VF_ID_TO_OS(vf_id)].link_forced = true;
		vf_infos[HW_VF_ID_TO_OS(vf_id)].link_up = true;
		link_status = SPNIC_LINK_UP;
		break;
	case SPNIC_IFLA_VF_LINK_STATE_DISABLE:
		vf_infos[HW_VF_ID_TO_OS(vf_id)].link_forced = true;
		vf_infos[HW_VF_ID_TO_OS(vf_id)].link_up = false;
		link_status = SPNIC_LINK_DOWN;
		break;
	default:
		return -EINVAL;
	}

	/* Notify the VF of its new link state */
	spnic_notify_vf_link_status(nic_cfg, vf_id, link_status);

	return 0;
}

int spnic_set_vf_spoofchk(void *hwdev, u16 vf_id, bool spoofchk)
{
	struct spnic_cmd_spoofchk_set spoofchk_cfg;
	struct vf_data_storage *vf_infos = NULL;
	u16 out_size = sizeof(spoofchk_cfg);
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	vf_infos = nic_cfg->vf_infos;

	memset(&spoofchk_cfg, 0, sizeof(spoofchk_cfg));

	spoofchk_cfg.func_id = sphw_glb_pf_vf_offset(hwdev) + vf_id;
	spoofchk_cfg.state = spoofchk ? 1 : 0;
	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_NIC_CMD_SET_SPOOPCHK_STATE,
				     &spoofchk_cfg, sizeof(spoofchk_cfg), &spoofchk_cfg, &out_size);
	if (err || !out_size || spoofchk_cfg.msg_head.status) {
		nic_err(nic_cfg->dev_hdl, "Failed to set VF(%d) spoofchk, err: %d, status: 0x%x, out size: 0x%x\n",
			HW_VF_ID_TO_OS(vf_id), err, spoofchk_cfg.msg_head.status, out_size);
		err = -EINVAL;
	}

	vf_infos[HW_VF_ID_TO_OS(vf_id)].spoofchk = spoofchk;

	return err;
}

bool spnic_vf_info_spoofchk(void *hwdev, int vf_id)
{
	struct spnic_nic_cfg *nic_cfg;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	return nic_cfg->vf_infos[HW_VF_ID_TO_OS(vf_id)].spoofchk;
}

int spnic_set_vf_trust(void *hwdev, u16 vf_id, bool trust)
{
	struct spnic_nic_cfg *nic_cfg = NULL;

	if (!hwdev)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (vf_id > nic_cfg->max_vfs)
		return -EINVAL;

	nic_cfg->vf_infos[HW_VF_ID_TO_OS(vf_id)].trust = trust;

	return 0;
}

bool spnic_get_vf_trust(void *hwdev, int vf_id)
{
	struct spnic_nic_cfg *nic_cfg = NULL;

	if (!hwdev)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (vf_id > nic_cfg->max_vfs)
		return -EINVAL;

	return nic_cfg->vf_infos[HW_VF_ID_TO_OS(vf_id)].trust;
}

static int spnic_cfg_vf_qps(struct spnic_nic_cfg *nic_cfg, u8 opcode, u16 vf_id, u16 num_qps)
{
	struct spnic_cmd_cfg_qps qps_info;
	u16 out_size = sizeof(qps_info);
	int err;

	memset(&qps_info, 0, sizeof(qps_info));

	qps_info.func_id = sphw_glb_pf_vf_offset(nic_cfg->hwdev) + vf_id;
	qps_info.opcode = opcode;
	qps_info.num_qps = num_qps;
	err = l2nic_msg_to_mgmt_sync(nic_cfg->hwdev, SPNIC_NIC_CMD_CFG_FLEX_QUEUE, &qps_info,
				     sizeof(qps_info), &qps_info, &out_size);
	if (err || !out_size || qps_info.msg_head.status) {
		nic_err(nic_cfg->dev_hdl, "Failed to %s VF(%d) qps, err: %d, status: 0x%x, out size: 0x%x\n",
			opcode == SPNIC_CMD_OP_ALLOC ? "alloc" : "free",
			HW_VF_ID_TO_OS(vf_id), err, qps_info.msg_head.status, out_size);
		return -EFAULT;
	}

	return 0;
}

int spnic_alloc_vf_qps(void *hwdev, u16 vf_id, u16 num_qps)
{
	struct vf_data_storage *vf_infos = NULL;
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (vf_id > nic_cfg->max_vfs)
		return -EINVAL;

	err = spnic_cfg_vf_qps(nic_cfg, SPNIC_CMD_OP_ALLOC, vf_id, num_qps);
	if (err)
		return err;

	vf_infos = nic_cfg->vf_infos;
	vf_infos[HW_VF_ID_TO_OS(vf_id)].num_qps = num_qps;

	return 0;
}

int spnic_free_vf_qps(void *hwdev, u16 vf_id)
{
	struct vf_data_storage *vf_infos = NULL;
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (vf_id > nic_cfg->max_vfs)
		return -EINVAL;

	vf_infos = nic_cfg->vf_infos;
	err = spnic_cfg_vf_qps(nic_cfg, SPNIC_CMD_OP_FREE, vf_id,
			       vf_infos[HW_VF_ID_TO_OS(vf_id)].num_qps);
	if (err)
		return err;

	vf_infos[HW_VF_ID_TO_OS(vf_id)].num_qps = 0;

	return 0;
}

static int spnic_set_vf_tx_rate_max_min(struct spnic_nic_cfg *nic_cfg, u16 vf_id,
					u32 max_rate, u32 min_rate)
{
	struct spnic_cmd_tx_rate_cfg rate_cfg;
	u16 out_size = sizeof(rate_cfg);
	int err;

	memset(&rate_cfg, 0, sizeof(rate_cfg));

	rate_cfg.func_id = sphw_glb_pf_vf_offset(nic_cfg->hwdev) + vf_id;
	rate_cfg.max_rate = max_rate;
	rate_cfg.min_rate = min_rate;
	err = l2nic_msg_to_mgmt_sync(nic_cfg->hwdev, SPNIC_NIC_CMD_SET_MAX_MIN_RATE,
				     &rate_cfg, sizeof(rate_cfg), &rate_cfg, &out_size);
	if (rate_cfg.msg_head.status || err || !out_size) {
		nic_err(nic_cfg->dev_hdl, "Failed to set VF %d max rate %u, min rate %u, err: %d, status: 0x%x, out size: 0x%x\n",
			HW_VF_ID_TO_OS(vf_id), max_rate, min_rate, err,
			rate_cfg.msg_head.status, out_size);
		return -EIO;
	}

	return 0;
}

int spnic_set_vf_tx_rate(void *hwdev, u16 vf_id, u32 max_rate, u32 min_rate)
{
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	err = spnic_set_vf_tx_rate_max_min(nic_cfg, vf_id, max_rate, min_rate);
	if (err)
		return err;

	nic_cfg->vf_infos[HW_VF_ID_TO_OS(vf_id)].max_rate = max_rate;
	nic_cfg->vf_infos[HW_VF_ID_TO_OS(vf_id)].min_rate = min_rate;

	return 0;
}

void spnic_get_vf_config(void *hwdev, u16 vf_id, struct ifla_vf_info *ivi)
{
	struct vf_data_storage *vfinfo;
	struct spnic_nic_cfg *nic_cfg;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	vfinfo = nic_cfg->vf_infos + HW_VF_ID_TO_OS(vf_id);

	ivi->vf = HW_VF_ID_TO_OS(vf_id);
	ether_addr_copy(ivi->mac, vfinfo->user_mac_addr);
	ivi->vlan = vfinfo->pf_vlan;
	ivi->qos = vfinfo->pf_qos;

	ivi->spoofchk = vfinfo->spoofchk;

	ivi->trusted = vfinfo->trust;

	ivi->max_tx_rate = vfinfo->max_rate;
	ivi->min_tx_rate = vfinfo->min_rate;

	if (!vfinfo->link_forced)
		ivi->linkstate = IFLA_VF_LINK_STATE_AUTO;
	else if (vfinfo->link_up)
		ivi->linkstate = IFLA_VF_LINK_STATE_ENABLE;
	else
		ivi->linkstate = IFLA_VF_LINK_STATE_DISABLE;
}

static int spnic_init_vf_infos(struct spnic_nic_cfg *nic_cfg, u16 vf_id)
{
	struct vf_data_storage *vf_infos = nic_cfg->vf_infos;
	u8 vf_link_state;

	if (set_vf_link_state > SPNIC_IFLA_VF_LINK_STATE_DISABLE) {
		nic_warn(nic_cfg->dev_hdl, "Module Parameter set_vf_link_state value %u is out of range, resetting to %d\n",
			 set_vf_link_state, SPNIC_IFLA_VF_LINK_STATE_AUTO);
		set_vf_link_state = SPNIC_IFLA_VF_LINK_STATE_AUTO;
	}

	vf_link_state = set_vf_link_state;

	switch (vf_link_state) {
	case SPNIC_IFLA_VF_LINK_STATE_AUTO:
		vf_infos[vf_id].link_forced = false;
		break;
	case SPNIC_IFLA_VF_LINK_STATE_ENABLE:
		vf_infos[vf_id].link_forced = true;
		vf_infos[vf_id].link_up = true;
		break;
	case SPNIC_IFLA_VF_LINK_STATE_DISABLE:
		vf_infos[vf_id].link_forced = true;
		vf_infos[vf_id].link_up = false;
		break;
	default:
		nic_err(nic_cfg->dev_hdl, "Input parameter set_vf_link_state error: %u\n",
			vf_link_state);
		return -EINVAL;
	}

	return 0;
}

static int vf_func_register(struct spnic_nic_cfg *nic_cfg)
{
	struct spnic_cmd_register_vf register_info;
	u16 out_size = sizeof(register_info);
	int err;

	err = sphw_register_vf_mbox_cb(nic_cfg->hwdev, SPHW_MOD_L2NIC, nic_cfg,
				       spnic_vf_event_handler);
	if (err)
		return err;

	err = sphw_register_vf_mbox_cb(nic_cfg->hwdev, SPHW_MOD_HILINK, nic_cfg,
				       spnic_vf_mag_event_handler);
	if (err)
		goto reg_hilink_err;

	memset(&register_info, 0, sizeof(register_info));
	register_info.op_register = 1;
	err = sphw_mbox_to_pf(nic_cfg->hwdev, SPHW_MOD_L2NIC, SPNIC_NIC_CMD_VF_REGISTER,
			      &register_info, sizeof(register_info), &register_info, &out_size, 0,
			      SPHW_CHANNEL_NIC);
	if (err || !out_size || register_info.msg_head.status) {
		nic_err(nic_cfg->dev_hdl, "Failed to register VF, err: %d, status: 0x%x, out size: 0x%x\n",
			err, register_info.msg_head.status, out_size);
		err = -EIO;
		goto register_err;
	}

	return 0;

register_err:
	sphw_unregister_vf_mbox_cb(nic_cfg->hwdev, SPHW_MOD_HILINK);

reg_hilink_err:
	sphw_unregister_vf_mbox_cb(nic_cfg->hwdev, SPHW_MOD_L2NIC);

	return err;
}

static int pf_init_vf_infos(struct spnic_nic_cfg *nic_cfg)
{
	u32 size;
	int err;
	u16 i;

	nic_cfg->max_vfs = sphw_func_max_vf(nic_cfg->hwdev);
	size = sizeof(*nic_cfg->vf_infos) * nic_cfg->max_vfs;
	if (!size)
		return 0;

	nic_cfg->vf_infos = kzalloc(size, GFP_KERNEL);
	if (!nic_cfg->vf_infos)
		return -ENOMEM;

	for (i = 0; i < nic_cfg->max_vfs; i++) {
		err = spnic_init_vf_infos(nic_cfg, i);
		if (err)
			goto init_vf_infos_err;
	}

	err = sphw_register_mgmt_msg_cb(nic_cfg->hwdev, SPHW_MOD_L2NIC, nic_cfg,
					spnic_pf_event_handler);
	if (err)
		goto register_mgmt_cb_err;

	err = sphw_register_pf_mbox_cb(nic_cfg->hwdev, SPHW_MOD_L2NIC, nic_cfg,
				       spnic_pf_mbox_handler);
	if (err)
		goto register_pf_mbox_cb_err;

	err = sphw_register_mgmt_msg_cb(nic_cfg->hwdev, SPHW_MOD_HILINK, nic_cfg,
					spnic_pf_mag_event_handler);
	if (err)
		goto register_mgmt_cb_err;

	err = sphw_register_pf_mbox_cb(nic_cfg->hwdev, SPHW_MOD_HILINK, nic_cfg,
				       spnic_pf_mag_mbox_handler);
	if (err)
		goto register_pf_mag_mbox_cb_err;

	return 0;

register_pf_mag_mbox_cb_err:
	sphw_unregister_pf_mbox_cb(nic_cfg->hwdev, SPHW_MOD_L2NIC);
register_pf_mbox_cb_err:
	sphw_unregister_mgmt_msg_cb(nic_cfg->hwdev, SPHW_MOD_L2NIC);
register_mgmt_cb_err:
init_vf_infos_err:
	kfree(nic_cfg->vf_infos);

	return err;
}

int spnic_vf_func_init(struct spnic_nic_cfg *nic_cfg)
{
	if (sphw_func_type(nic_cfg->hwdev) == TYPE_VF)
		return vf_func_register(nic_cfg);

	return pf_init_vf_infos(nic_cfg);
}

void spnic_vf_func_free(struct spnic_nic_cfg *nic_cfg)
{
	struct spnic_cmd_register_vf unregister;
	u16 out_size = sizeof(unregister);
	int err;

	memset(&unregister, 0, sizeof(unregister));
	unregister.op_register = 0;
	if (sphw_func_type(nic_cfg->hwdev) == TYPE_VF) {
		err = sphw_mbox_to_pf(nic_cfg->hwdev, SPHW_MOD_L2NIC, SPNIC_NIC_CMD_VF_REGISTER,
				      &unregister, sizeof(unregister), &unregister, &out_size, 0,
				      SPHW_CHANNEL_NIC);
		if (err || !out_size || unregister.msg_head.status)
			nic_err(nic_cfg->dev_hdl, "Failed to unregister VF, err: %d, status: 0x%x, out_size: 0x%x\n",
				err, unregister.msg_head.status, out_size);

		sphw_unregister_vf_mbox_cb(nic_cfg->hwdev, SPHW_MOD_L2NIC);
	} else {
		if (nic_cfg->vf_infos) {
			sphw_unregister_mgmt_msg_cb(nic_cfg->hwdev, SPHW_MOD_L2NIC);
			sphw_unregister_pf_mbox_cb(nic_cfg->hwdev, SPHW_MOD_L2NIC);
			spnic_clear_vfs_info(nic_cfg->hwdev);
			kfree(nic_cfg->vf_infos);
		}
	}
}

static void clear_vf_infos(void *hwdev, u16 vf_id)
{
	struct vf_data_storage *vf_infos;
	struct spnic_nic_cfg *nic_cfg;
	u16 func_id;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	func_id = sphw_glb_pf_vf_offset(hwdev) + vf_id;
	vf_infos = nic_cfg->vf_infos + HW_VF_ID_TO_OS(vf_id);
	if (vf_infos->use_specified_mac)
		spnic_del_mac(hwdev, vf_infos->drv_mac_addr, vf_infos->pf_vlan,
			      func_id, SPHW_CHANNEL_NIC);

	if (spnic_vf_info_vlanprio(hwdev, vf_id))
		spnic_kill_vf_vlan(hwdev, vf_id);

	if (vf_infos->max_rate)
		spnic_set_vf_tx_rate(hwdev, vf_id, 0, 0);

	if (vf_infos->spoofchk)
		spnic_set_vf_spoofchk(hwdev, vf_id, false);

	if (vf_infos->trust)
		spnic_set_vf_trust(hwdev, vf_id, false);

	memset(vf_infos, 0, sizeof(*vf_infos));
	/* set vf_infos to default */
	spnic_init_vf_infos(nic_cfg, HW_VF_ID_TO_OS(vf_id));
}

void spnic_clear_vfs_info(void *hwdev)
{
	struct spnic_nic_cfg *nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	u16 i;

	for (i = 0; i < nic_cfg->max_vfs; i++)
		clear_vf_infos(hwdev, OS_VF_ID_TO_HW(i));
}
