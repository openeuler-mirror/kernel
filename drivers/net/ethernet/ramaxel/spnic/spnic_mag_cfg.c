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
#include "spnic_mag_cmd.h"
#include "spnic_nic_io.h"
#include "spnic_nic_cfg.h"
#include "spnic_nic.h"
#include "sphw_common.h"

static int mag_msg_to_mgmt_sync(void *hwdev, u16 cmd, void *buf_in, u16 in_size,
				void *buf_out, u16 *out_size);
static int mag_msg_to_mgmt_sync_ch(void *hwdev, u16 cmd, void *buf_in,
				   u16 in_size, void *buf_out, u16 *out_size,
				   u16 channel);

int spnic_set_port_enable(void *hwdev, bool enable, u16 channel)
{
	struct mag_cmd_set_port_enable en_state;
	u16 out_size = sizeof(en_state);
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	if (!hwdev)
		return -EINVAL;

	if (sphw_func_type(hwdev) == TYPE_VF)
		return 0;

	memset(&en_state, 0, sizeof(en_state));

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	en_state.function_id = sphw_global_func_id(hwdev);
	en_state.state = enable ? MAG_CMD_TX_ENABLE | MAG_CMD_RX_ENABLE :
				MAG_CMD_PORT_DISABLE;

	err = mag_msg_to_mgmt_sync_ch(hwdev, MAG_CMD_SET_PORT_ENABLE, &en_state,
				      sizeof(en_state), &en_state, &out_size, channel);
	if (err || !out_size || en_state.head.status) {
		nic_err(nic_cfg->dev_hdl, "Failed to set port state, err: %d, status: 0x%x, out size: 0x%x, channel: 0x%x\n",
			err, en_state.head.status, out_size, channel);
		return -EIO;
	}

	return 0;
}

int spnic_get_phy_port_stats(void *hwdev, struct mag_cmd_port_stats *stats)
{
	struct mag_cmd_get_port_stat *port_stats = NULL;
	struct mag_cmd_port_stats_info stats_info;
	u16 out_size = sizeof(*port_stats);
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	port_stats = kzalloc(sizeof(*port_stats), GFP_KERNEL);
	if (!port_stats)
		return -ENOMEM;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	memset(&stats_info, 0, sizeof(stats_info));
	stats_info.port_id = sphw_physical_port_id(hwdev);

	err = mag_msg_to_mgmt_sync(hwdev, MAG_CMD_GET_PORT_STAT,
				   &stats_info, sizeof(stats_info),
				   port_stats, &out_size);
	if (err || !out_size || port_stats->head.status) {
		nic_err(nic_cfg->dev_hdl,
			"Failed to get port statistics, err: %d, status: 0x%x, out size: 0x%x\n",
			err, port_stats->head.status, out_size);
		err = -EIO;
		goto out;
	}

	memcpy(stats, &port_stats->counter, sizeof(*stats));

out:
	kfree(port_stats);

	return err;
}

int spnic_set_port_funcs_state(void *hwdev, bool enable)
{
	return 0;
}

int spnic_reset_port_link_cfg(void *hwdev)
{
	return 0;
}

int spnic_force_port_relink(void *hwdev)
{
	return 0;
}

int spnic_set_autoneg(void *hwdev, bool enable)
{
	/* TODO */

	return 0;
}

static int spnic_cfg_loopback_mode(struct spnic_nic_cfg *nic_cfg, u8 opcode, u8 *mode, u8 *enable)
{
	struct mag_cmd_cfg_loopback_mode lp;
	u16 out_size = sizeof(lp);
	int err;

	memset(&lp, 0, sizeof(lp));
	lp.port_id = sphw_physical_port_id(nic_cfg->hwdev);
	lp.opcode = opcode;
	if (opcode == MGMT_MSG_CMD_OP_SET) {
		lp.lp_mode = *mode;
		lp.lp_en = *enable;
	}

	err = mag_msg_to_mgmt_sync(nic_cfg->hwdev, MAG_CMD_CFG_LOOPBACK_MODE,
				   &lp, sizeof(lp), &lp, &out_size);
	if (err || !out_size || lp.head.status) {
		nic_err(nic_cfg->dev_hdl,
			"Failed to %s loopback mode, err: %d, status: 0x%x, out size: 0x%x\n",
			opcode == MGMT_MSG_CMD_OP_SET ? "set" : "get",
			err, lp.head.status, out_size);
		return -EIO;
	}

	if (opcode == MGMT_MSG_CMD_OP_GET) {
		*mode = lp.lp_mode;
		*enable = lp.lp_en;
	}

	return 0;
}

int spnic_get_loopback_mode(void *hwdev, u8 *mode, u8 *enable)
{
	struct spnic_nic_cfg *nic_cfg = NULL;

	if (!hwdev || !mode || !enable)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	return spnic_cfg_loopback_mode(nic_cfg, MGMT_MSG_CMD_OP_GET, mode, enable);
}

#define LOOP_MODE_MIN 1
#define LOOP_MODE_MAX 6
int spnic_set_loopback_mode(void *hwdev, u8 mode, u8 enable)
{
	struct spnic_nic_cfg *nic_cfg = NULL;

	if (!hwdev)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	if (mode < LOOP_MODE_MIN || mode > LOOP_MODE_MAX) {
		nic_err(nic_cfg->dev_hdl, "Invalid loopback mode %u to set\n",
			mode);
		return -EINVAL;
	}

	return spnic_cfg_loopback_mode(nic_cfg, MGMT_MSG_CMD_OP_GET, &mode, &enable);
}

int spnic_set_led_status(void *hwdev, enum mag_led_type type, enum mag_led_mode mode)
{
	struct spnic_nic_cfg *nic_cfg = NULL;
	struct mag_cmd_set_led_cfg led_info;
	u16 out_size = sizeof(led_info);
	int err;

	if (!hwdev)
		return -EFAULT;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	memset(&led_info, 0, sizeof(led_info));

	led_info.function_id = sphw_global_func_id(hwdev);
	led_info.type = type;
	led_info.mode = mode;

	err = mag_msg_to_mgmt_sync(hwdev, MAG_CMD_SET_LED_CFG, &led_info,
				   sizeof(led_info), &led_info, &out_size);
	if (err || led_info.head.status || !out_size) {
		nic_err(nic_cfg->dev_hdl, "Failed to set led status, err: %d, status: 0x%x, out size: 0x%x\n",
			err, led_info.head.status, out_size);
		return -EIO;
	}

	return 0;
}

int spnic_get_port_info(void *hwdev, struct nic_port_info *port_info, u16 channel)
{
	struct mag_cmd_get_port_info port_msg;
	u16 out_size = sizeof(port_msg);
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	if (!hwdev || !port_info)
		return -EINVAL;

	memset(&port_msg, 0, sizeof(port_msg));

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	port_msg.port_id = sphw_physical_port_id(hwdev);

	err = mag_msg_to_mgmt_sync_ch(hwdev, MAG_CMD_GET_PORT_INFO, &port_msg,
				      sizeof(port_msg), &port_msg, &out_size,
				      channel);
	if (err || !out_size || port_msg.head.status) {
		nic_err(nic_cfg->dev_hdl,
			"Failed to get port info, err: %d, status: 0x%x, out size: 0x%x, channel: 0x%x\n",
			err, port_msg.head.status, out_size, channel);
		return -EIO;
	}

	port_info->autoneg_cap = port_msg.an_support;
	port_info->autoneg_state = port_msg.an_en;
	port_info->duplex = port_msg.duplex;
	port_info->port_type = port_msg.wire_type;
	port_info->speed = port_msg.speed;
	port_info->fec = port_msg.fec;
	port_info->supported_mode = port_msg.supported_mode;
	port_info->advertised_mode = port_msg.advertised_mode;

	return 0;
}

int spnic_get_speed(void *hwdev, enum mag_cmd_port_speed *speed, u16 channel)
{
	struct nic_port_info port_info = {0};
	int err;

	if (!hwdev || !speed)
		return -EINVAL;

	err = spnic_get_port_info(hwdev, &port_info, channel);
	if (err)
		return err;

	*speed = port_info.speed;

	return 0;
}

int spnic_set_link_settings(void *hwdev, struct spnic_link_ksettings *settings)
{
	struct mag_cmd_set_port_cfg info;
	u16 out_size = sizeof(info);
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	if (!hwdev || !settings)
		return -EINVAL;

	memset(&info, 0, sizeof(info));

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	info.port_id = sphw_physical_port_id(hwdev);
	info.config_bitmap = settings->valid_bitmap;
	info.autoneg = settings->autoneg;
	info.speed = settings->speed;
	info.fec = settings->fec;

	err = mag_msg_to_mgmt_sync(hwdev, MAG_CMD_SET_PORT_CFG, &info,
				   sizeof(info), &info, &out_size);
	if (err || !out_size || info.head.status) {
		nic_err(nic_cfg->dev_hdl, "Failed to set link settings, err: %d, status: 0x%x, out size: 0x%x\n",
			err, info.head.status, out_size);
		return -EIO;
	}

	return info.head.status;
}

int spnic_get_link_state(void *hwdev, u8 *link_state)
{
	struct mag_cmd_get_link_status get_link;
	u16 out_size = sizeof(get_link);
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	if (!hwdev || !link_state)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	memset(&get_link, 0, sizeof(get_link));
	get_link.port_id = sphw_physical_port_id(hwdev);

	err = mag_msg_to_mgmt_sync(hwdev, MAG_CMD_GET_LINK_STATUS, &get_link,
				   sizeof(get_link), &get_link, &out_size);
	if (err || !out_size || get_link.head.status) {
		nic_err(nic_cfg->dev_hdl, "Failed to get link state, err: %d, status: 0x%x, out size: 0x%x\n",
			err, get_link.head.status, out_size);
		return -EIO;
	}

	*link_state = get_link.status;

	return 0;
}

void spnic_notify_vf_link_status(struct spnic_nic_cfg *nic_cfg, u16 vf_id, u8 link_status)
{
	struct mag_cmd_get_link_status link;
	struct vf_data_storage *vf_infos = nic_cfg->vf_infos;
	u16 out_size = sizeof(link);
	int err;

	memset(&link, 0, sizeof(link));
	if (vf_infos[HW_VF_ID_TO_OS(vf_id)].registered) {
		link.status = link_status;
		link.port_id = sphw_physical_port_id(nic_cfg->hwdev);
		err = sphw_mbox_to_vf(nic_cfg->hwdev, vf_id, SPHW_MOD_HILINK,
				      MAG_CMD_GET_LINK_STATUS, &link, sizeof(link), &link,
				      &out_size, 0, SPHW_CHANNEL_NIC);
		if (err || !out_size || link.head.status)
			nic_err(nic_cfg->dev_hdl,
				"Send link change event to VF %d failed, err: %d, status: 0x%x, out_size: 0x%x\n",
				HW_VF_ID_TO_OS(vf_id), err,
				link.head.status, out_size);
	}
}

void spnic_notify_all_vfs_link_changed(void *hwdev, u8 link_status)
{
	struct spnic_nic_cfg *nic_cfg = NULL;
	u16 i;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	nic_cfg->link_status = link_status;
	for (i = 1; i <= nic_cfg->max_vfs; i++) {
		if (!nic_cfg->vf_infos[HW_VF_ID_TO_OS(i)].link_forced)
			spnic_notify_vf_link_status(nic_cfg, i, link_status);
	}
}

static int spnic_get_vf_link_status_msg_handler(struct spnic_nic_cfg *nic_cfg, u16 vf_id,
						void *buf_in, u16 in_size, void *buf_out,
						u16 *out_size)
{
	struct vf_data_storage *vf_infos = nic_cfg->vf_infos;
	struct mag_cmd_get_link_status *get_link = buf_out;
	bool link_forced, link_up;

	link_forced = vf_infos[HW_VF_ID_TO_OS(vf_id)].link_forced;
	link_up = vf_infos[HW_VF_ID_TO_OS(vf_id)].link_up;

	if (link_forced)
		get_link->status = link_up ? SPNIC_LINK_UP : SPNIC_LINK_DOWN;
	else
		get_link->status = nic_cfg->link_status;

	get_link->head.status = 0;
	*out_size = sizeof(*get_link);

	return 0;
}

int spnic_refresh_nic_cfg(void *hwdev, struct nic_port_info *port_info)
{
	/*TO DO */
	return 0;
}

static void get_port_info(void *hwdev, struct mag_cmd_get_link_status *link_status,
			  struct sphw_event_link_info *link_info)
{
	struct nic_port_info port_info = {0};
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (sphw_func_type(hwdev) != TYPE_VF &&
	    link_status->status == SPHW_EVENT_LINK_UP) {
		err = spnic_get_port_info(hwdev, &port_info, SPHW_CHANNEL_NIC);
		if (err) {
			nic_warn(nic_cfg->dev_hdl, "Failed to get port info\n");
		} else {
			link_info->valid = 1;
			link_info->port_type = port_info.port_type;
			link_info->autoneg_cap = port_info.autoneg_cap;
			link_info->autoneg_state = port_info.autoneg_state;
			link_info->duplex = port_info.duplex;
			link_info->speed = port_info.speed;
			spnic_refresh_nic_cfg(hwdev, &port_info);
		}
	}
}

static void link_status_event_handler(void *hwdev, void *buf_in,
				      u16 in_size, void *buf_out, u16 *out_size)
{
	struct mag_cmd_get_link_status *link_status = NULL;
	struct mag_cmd_get_link_status *ret_link_status = NULL;
	struct sphw_event_info event_info = {0};
	struct sphw_event_link_info *link_info = &event_info.link_info;
	struct spnic_nic_cfg *nic_cfg = NULL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	link_status = buf_in;
	sdk_info(nic_cfg->dev_hdl, "Link status report received, func_id: %u, status: %u\n",
		 sphw_global_func_id(hwdev), link_status->status);

	sphw_link_event_stats(hwdev, link_status->status);

	/* link event reported only after set vport enable */
	get_port_info(hwdev, link_status, link_info);

	event_info.type = link_status->status ? SPHW_EVENT_LINK_UP : SPHW_EVENT_LINK_DOWN;

	sphw_event_callback(hwdev, &event_info);

	if (sphw_func_type(hwdev) != TYPE_VF) {
		spnic_notify_all_vfs_link_changed(hwdev, link_status->status);
		ret_link_status = buf_out;
		ret_link_status->head.status = 0;
		*out_size = sizeof(*ret_link_status);
	}
}

static void cable_plug_event(void *hwdev, void *buf_in, u16 in_size, void *buf_out, u16 *out_size)
{
	struct mag_cmd_wire_event *plug_event = buf_in;
	struct spnic_port_routine_cmd *rt_cmd = NULL;
	struct spnic_nic_cfg *nic_cfg = NULL;
	struct sphw_event_info event_info;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	rt_cmd = &nic_cfg->rt_cmd;

	mutex_lock(&nic_cfg->sfp_mutex);
	rt_cmd->mpu_send_sfp_abs = false;
	rt_cmd->mpu_send_sfp_info = false;
	mutex_unlock(&nic_cfg->sfp_mutex);

	memset(&event_info, 0, sizeof(event_info));
	event_info.type = SPHW_EVENT_PORT_MODULE_EVENT;
	event_info.module_event.type = plug_event->status ?
				SPHW_PORT_MODULE_CABLE_PLUGGED :
				SPHW_PORT_MODULE_CABLE_UNPLUGGED;

	*out_size = sizeof(*plug_event);
	plug_event = buf_out;
	plug_event->head.status = 0;

	sphw_event_callback(hwdev, &event_info);
}

static void port_sfp_info_event(void *hwdev, void *buf_in, u16 in_size,
				void *buf_out, u16 *out_size)
{
	struct mag_cmd_get_xsfp_info *sfp_info = buf_in;
	struct spnic_port_routine_cmd *rt_cmd = NULL;
	struct spnic_nic_cfg *nic_cfg = NULL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (in_size != sizeof(*sfp_info)) {
		sdk_err(nic_cfg->dev_hdl, "Invalid sfp info cmd, length: %u, should be %ld\n",
			in_size, sizeof(*sfp_info));
		return;
	}

	rt_cmd = &nic_cfg->rt_cmd;
	mutex_lock(&nic_cfg->sfp_mutex);
	memcpy(&rt_cmd->std_sfp_info, sfp_info,
	       sizeof(struct mag_cmd_get_xsfp_info));
	rt_cmd->mpu_send_sfp_info = true;
	mutex_unlock(&nic_cfg->sfp_mutex);
}

static void port_sfp_abs_event(void *hwdev, void *buf_in, u16 in_size,
			       void *buf_out, u16 *out_size)
{
	struct mag_cmd_get_xsfp_present *sfp_abs = buf_in;
	struct spnic_port_routine_cmd *rt_cmd = NULL;
	struct spnic_nic_cfg *nic_cfg = NULL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (in_size != sizeof(*sfp_abs)) {
		sdk_err(nic_cfg->dev_hdl, "Invalid sfp absent cmd, length: %u, should be %ld\n",
			in_size, sizeof(*sfp_abs));
		return;
	}

	rt_cmd = &nic_cfg->rt_cmd;
	mutex_lock(&nic_cfg->sfp_mutex);
	memcpy(&rt_cmd->abs, sfp_abs, sizeof(struct mag_cmd_get_xsfp_present));
	rt_cmd->mpu_send_sfp_abs = true;
	mutex_unlock(&nic_cfg->sfp_mutex);
}

static bool spnic_if_sfp_absent(void *hwdev)
{
	struct spnic_nic_cfg *nic_cfg = NULL;
	struct spnic_port_routine_cmd *rt_cmd = NULL;
	struct mag_cmd_get_xsfp_present sfp_abs;
	u8 port_id = sphw_physical_port_id(hwdev);
	u16 out_size = sizeof(sfp_abs);
	int err;
	bool sfp_abs_status;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	memset(&sfp_abs, 0, sizeof(sfp_abs));

	rt_cmd = &nic_cfg->rt_cmd;
	mutex_lock(&nic_cfg->sfp_mutex);
	if (rt_cmd->mpu_send_sfp_abs) {
		if (rt_cmd->abs.head.status) {
			mutex_unlock(&nic_cfg->sfp_mutex);
			return true;
		}

		sfp_abs_status = (bool)rt_cmd->abs.abs_status;
		mutex_unlock(&nic_cfg->sfp_mutex);
		return sfp_abs_status;
	}
	mutex_unlock(&nic_cfg->sfp_mutex);

	sfp_abs.port_id = port_id;
	err = mag_msg_to_mgmt_sync(hwdev, MAG_CMD_GET_XSFP_PRESENT,
				   &sfp_abs, sizeof(sfp_abs), &sfp_abs,
				   &out_size);
	if (sfp_abs.head.status || err || !out_size) {
		nic_err(nic_cfg->dev_hdl,
			"Failed to get port%u sfp absent status, err: %d, status: 0x%x, out size: 0x%x\n",
			port_id, err, sfp_abs.head.status, out_size);
		return true;
	}

	return (sfp_abs.abs_status == 0 ? false : true);
}

int spnic_get_sfp_eeprom(void *hwdev, u8 *data, u32 len)
{
	struct spnic_nic_cfg *nic_cfg = NULL;
	struct spnic_port_routine_cmd *rt_cmd = NULL;
	struct mag_cmd_get_xsfp_info sfp_info;
	u16 out_size = sizeof(sfp_info);
	int err;

	if (!hwdev || !data)
		return -EINVAL;

	if (spnic_if_sfp_absent(hwdev))
		return -ENXIO;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	memset(&sfp_info, 0, sizeof(sfp_info));

	rt_cmd = &nic_cfg->rt_cmd;
	mutex_lock(&nic_cfg->sfp_mutex);
	if (rt_cmd->mpu_send_sfp_info) {
		if (rt_cmd->std_sfp_info.head.status) {
			mutex_unlock(&nic_cfg->sfp_mutex);
			return -EIO;
		}

		memcpy(data, rt_cmd->std_sfp_info.sfp_info, len);
		mutex_unlock(&nic_cfg->sfp_mutex);
		return 0;
	}
	mutex_unlock(&nic_cfg->sfp_mutex);

	sfp_info.port_id = sphw_physical_port_id(hwdev);
	err = mag_msg_to_mgmt_sync(hwdev, MAG_CMD_GET_XSFP_INFO, &sfp_info,
				   sizeof(sfp_info), &sfp_info, &out_size);
	if (sfp_info.head.status || err || !out_size) {
		nic_err(nic_cfg->dev_hdl,
			"Failed to get port%u sfp eeprom information, err: %d, status: 0x%x, out size: 0x%x\n",
			sphw_physical_port_id(hwdev), err,
			sfp_info.head.status, out_size);
		return -EIO;
	}

	memcpy(data, sfp_info.sfp_info, len);

	return  0;
}

int spnic_get_sfp_type(void *hwdev, u8 *sfp_type, u8 *sfp_type_ext)
{
	struct spnic_nic_cfg *nic_cfg = NULL;
	struct spnic_port_routine_cmd *rt_cmd = NULL;
	u8 sfp_data[STD_SFP_INFO_MAX_SIZE];
	int err;

	if (!hwdev || !sfp_type || !sfp_type_ext)
		return -EINVAL;

	if (spnic_if_sfp_absent(hwdev))
		return -ENXIO;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	rt_cmd = &nic_cfg->rt_cmd;

	mutex_lock(&nic_cfg->sfp_mutex);
	if (rt_cmd->mpu_send_sfp_info) {
		if (rt_cmd->std_sfp_info.head.status) {
			mutex_unlock(&nic_cfg->sfp_mutex);
			return -EIO;
		}

		*sfp_type = rt_cmd->std_sfp_info.sfp_info[0];
		*sfp_type_ext = rt_cmd->std_sfp_info.sfp_info[1];
		mutex_unlock(&nic_cfg->sfp_mutex);
		return 0;
	}
	mutex_unlock(&nic_cfg->sfp_mutex);

	err = spnic_get_sfp_eeprom(hwdev, (u8 *)sfp_data, STD_SFP_INFO_MAX_SIZE);
	if (err)
		return err;

	*sfp_type = sfp_data[0];
	*sfp_type_ext = sfp_data[1];

	return 0;
}

static const struct vf_msg_handler vf_mag_cmd_handler[] = {
	{
		.cmd = MAG_CMD_GET_LINK_STATUS,
		.handler = spnic_get_vf_link_status_msg_handler,
	},
};

/* pf/ppf handler mbox msg from vf */
int spnic_pf_mag_mbox_handler(void *hwdev, void *pri_handle, u16 vf_id,
			      u16 cmd, void *buf_in, u16 in_size,
			      void *buf_out, u16 *out_size)
{
	u32 index, cmd_size = ARRAY_LEN(vf_mag_cmd_handler);
	struct spnic_nic_cfg *nic_cfg = NULL;
	const struct vf_msg_handler *handler = NULL;

	if (!hwdev)
		return -EFAULT;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	for (index = 0; index < cmd_size; index++) {
		handler = &vf_mag_cmd_handler[index];
		if (cmd == handler->cmd)
			return handler->handler(nic_cfg, vf_id, buf_in, in_size,
						buf_out, out_size);
	}

	nic_warn(nic_cfg->dev_hdl, "NO handler for mag cmd: %u received from vf id: %u\n",
		 cmd, vf_id);

	return -EINVAL;
}

static struct nic_event_handler mag_cmd_handler[] = {
	{
		.cmd = MAG_CMD_GET_LINK_STATUS,
		.handler = link_status_event_handler,
	},

	{
		.cmd = MAG_CMD_WIRE_EVENT,
		.handler = cable_plug_event,
	},

	{
		.cmd = MAG_CMD_GET_XSFP_INFO,
		.handler = port_sfp_info_event,
	},

	{
		.cmd = MAG_CMD_GET_XSFP_PRESENT,
		.handler = port_sfp_abs_event,
	},
};

int spnic_mag_event_handler(void *hwdev, void *pri_handle, u16 cmd, void *buf_in, u16 in_size,
			    void *buf_out, u16 *out_size)
{
	struct spnic_nic_cfg *nic_cfg = NULL;
	u32 size = ARRAY_LEN(mag_cmd_handler);
	u32 i;

	if (!hwdev)
		return -EINVAL;

	*out_size = 0;
	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	for (i = 0; i < size; i++) {
		if (cmd == mag_cmd_handler[i].cmd) {
			mag_cmd_handler[i].handler(hwdev, buf_in, in_size,
						   buf_out, out_size);
			break;
		}
	}

	/* can't find this event cmd */
	if (i == size)
		sdk_warn(nic_cfg->dev_hdl, "Unsupported mag event, cmd: %u\n",
			 cmd);

	return 0;
}

int spnic_vf_mag_event_handler(void *hwdev, void *pri_handle, u16 cmd, void *buf_in, u16 in_size,
			       void *buf_out, u16 *out_size)
{
	return spnic_mag_event_handler(hwdev, pri_handle, cmd, buf_in, in_size, buf_out, out_size);
}

/* pf/ppf handler mgmt cpu report hilink event*/
void spnic_pf_mag_event_handler(void *hwdev, void *pri_handle, u16 cmd,
				void *buf_in, u16 in_size, void *buf_out, u16 *out_size)
{
	spnic_mag_event_handler(hwdev, pri_handle, cmd, buf_in, in_size, buf_out, out_size);
}

static int _mag_msg_to_mgmt_sync(void *hwdev, u16 cmd, void *buf_in, u16 in_size,
				 void *buf_out, u16 *out_size, u16 channel)
{
	u32 i, cmd_cnt = ARRAY_LEN(vf_mag_cmd_handler);
	bool cmd_to_pf = false;

	if (sphw_func_type(hwdev) == TYPE_VF) {
		for (i = 0; i < cmd_cnt; i++) {
			if (cmd == vf_mag_cmd_handler[i].cmd) {
				cmd_to_pf = true;
				break;
			}
		}
	}

	if (cmd_to_pf)
		return sphw_mbox_to_pf(hwdev, SPHW_MOD_HILINK, cmd, buf_in, in_size, buf_out,
				       out_size, 0, channel);

	return sphw_msg_to_mgmt_sync(hwdev, SPHW_MOD_HILINK, cmd, buf_in,
				     in_size, buf_out, out_size, 0, channel);
}

static int mag_msg_to_mgmt_sync(void *hwdev, u16 cmd, void *buf_in, u16 in_size,
				void *buf_out, u16 *out_size)
{
	return _mag_msg_to_mgmt_sync(hwdev, cmd, buf_in, in_size, buf_out,
				     out_size, SPHW_CHANNEL_NIC);
}

static int mag_msg_to_mgmt_sync_ch(void *hwdev, u16 cmd, void *buf_in,
				   u16 in_size, void *buf_out, u16 *out_size,
				   u16 channel)
{
	return _mag_msg_to_mgmt_sync(hwdev, cmd, buf_in, in_size, buf_out,
				     out_size, channel);
}
