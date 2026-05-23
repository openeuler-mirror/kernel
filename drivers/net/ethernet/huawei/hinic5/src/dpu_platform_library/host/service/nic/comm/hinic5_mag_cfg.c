/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_mag_cfg.c
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

#include "ossl_knl.h"
#include "comm_defs.h"
#include "hinic5_crm.h"
#include "hinic5_hw.h"
#include "hinic5_nic_io.h"
#include "hinic5_nic_cfg.h"
#include "hinic5_srv_nic.h"
#include "hinic5_nic.h"
#include "cfm_cmd.h"
#include "hinic5_common.h"
#include "mag_mpu_cmd.h"
#include "nic_mpu_cmd.h"
#include "hinic5_nic_event.h"
#include "mag_mpu_cmd_defs.h"
#include "inband_mpu_cmd_defs.h"
#include "hinic5_mag_cfg.h"

static int mag_msg_to_mgmt_sync(void *hwdev, u16 cmd, void *buf_in, u16 in_size,
				void *buf_out, u16 *out_size);
static int mag_msg_to_mgmt_sync_ch(void *hwdev, u16 cmd, void *buf_in,
				   u16 in_size, void *buf_out, u16 *out_size,
				   u16 channel);

int hinic5_set_port_enable(void *hwdev, bool enable, u16 channel)
{
	struct mag_cmd_set_port_enable en_state;
	u16 out_size = sizeof(en_state);
	struct hinic5_nic_io *nic_io = NULL;
	int err;

	if (!hwdev)
		return -EINVAL;

	if (hinic5_func_type(hwdev) == TYPE_VF)
		return 0;

	memset(&en_state, 0, sizeof(en_state));

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	en_state.function_id = hinic5_global_func_id(hwdev);
	en_state.state = enable ? MAG_CMD_TX_ENABLE | MAG_CMD_RX_ENABLE :
				MAG_CMD_PORT_DISABLE;

	err = mag_msg_to_mgmt_sync_ch(hwdev, MAG_CMD_SET_PORT_ENABLE, &en_state,
				      sizeof(en_state), &en_state, &out_size,
				      channel);
	if (err != 0 || out_size == 0 || en_state.head.status != 0) {
		nic_err(nic_io->dev_hdl, "Failed to set port state, err: %d, status: 0x%x, out size: 0x%x, channel: 0x%x\n",
			err, en_state.head.status, out_size, channel);
		return -EIO;
	}

	return 0;
}

int hinic5_get_phy_port_stats(void *hwdev, struct mag_cmd_port_stats *stats)
{
	struct mag_cmd_get_port_stat *port_stats = NULL;
	struct mag_cmd_port_stats_info stats_info;
	u16 out_size = sizeof(*port_stats);
	struct hinic5_nic_io *nic_io = NULL;
	int err;

	if (!hwdev || !stats)
		return -ENOMEM;

	port_stats = kzalloc(sizeof(*port_stats), GFP_KERNEL);
	if (!port_stats)
		return -ENOMEM;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io) {
		err = -EINVAL;
		goto out;
	}

	memset(&stats_info, 0, sizeof(stats_info));
	stats_info.port_id = hinic5_physical_port_id(hwdev);

	err = mag_msg_to_mgmt_sync(hwdev, MAG_CMD_GET_PORT_STAT,
				   &stats_info, sizeof(stats_info),
				   port_stats, &out_size);
	if (err != 0 || out_size == 0 || port_stats->head.status != 0) {
		nic_err(nic_io->dev_hdl,
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
EXPORT_SYMBOL(hinic5_get_phy_port_stats);

int hinic5_set_port_funcs_state(void *hwdev, bool enable)
{
	return 0;
}

int hinic5_reset_port_link_cfg(void *hwdev)
{
	return 0;
}

int hinic5_force_port_relink(void *hwdev)
{
	return 0;
}

int hinic5_set_autoneg(void *hwdev, bool enable)
{
	struct hinic5_link_ksettings settings = {0};
	struct hinic5_nic_io *nic_io = NULL;
	u32 set_settings = 0;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	set_settings |= HILINK_LINK_SET_AUTONEG;
	settings.valid_bitmap = set_settings;
	settings.autoneg = enable ? PORT_CFG_AN_ON : PORT_CFG_AN_OFF;

	return hinic5_set_link_settings(hwdev, &settings);
}

static int hinic5_cfg_loopback_mode(struct hinic5_nic_io *nic_io, u8 opcode,
				    u8 *mode, u8 *enable)
{
	struct mag_cmd_cfg_loopback_mode lp;
	u16 out_size = sizeof(lp);
	int err;

	memset(&lp, 0, sizeof(lp));
	lp.port_id = hinic5_physical_port_id(nic_io->hwdev);
	lp.opcode = opcode;
	if (opcode == MGMT_MSG_CMD_OP_SET) {
		lp.lp_mode = *mode;
		lp.lp_en = *enable;
	}

	err = mag_msg_to_mgmt_sync(nic_io->hwdev, MAG_CMD_CFG_LOOPBACK_MODE,
				   &lp, sizeof(lp), &lp, &out_size);
	if (err != 0 || out_size == 0 || lp.head.status != 0) {
		nic_err(nic_io->dev_hdl,
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

int hinic5_get_loopback_mode(void *hwdev, u8 *mode, u8 *enable)
{
	struct hinic5_nic_io *nic_io = NULL;

	if (!hwdev || !mode || !enable)
		return -EINVAL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	return hinic5_cfg_loopback_mode(nic_io, MGMT_MSG_CMD_OP_GET, mode,
					enable);
}

int hinic5_set_loopback_mode(void *hwdev, u8 mode, u8 enable)
{
	struct hinic5_nic_io *nic_io = NULL;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	if (mode < LOOP_MODE_MIN || mode > LOOP_MODE_MAX) {
		nic_err(nic_io->dev_hdl, "Invalid loopback mode %u to set\n",
			mode);
		return -EINVAL;
	}

	return hinic5_cfg_loopback_mode(nic_io, MGMT_MSG_CMD_OP_SET, &mode,
					&enable);
}

int hinic5_set_led_status(void *hwdev, enum mag_led_type type,
			  enum mag_led_mode mode)
{
	struct hinic5_nic_io *nic_io = NULL;
	struct mag_cmd_set_led_cfg led_info;
	u16 out_size = sizeof(led_info);
	int err;

	if (!hwdev)
		return -EFAULT;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	memset(&led_info, 0, sizeof(led_info));

	led_info.function_id = hinic5_global_func_id(hwdev);
	led_info.type = type;
	led_info.mode = mode;

	err = mag_msg_to_mgmt_sync(hwdev, MAG_CMD_SET_LED_CFG, &led_info,
				   sizeof(led_info), &led_info, &out_size);
	if (err != 0 || led_info.head.status != 0 || out_size == 0) {
		nic_err(nic_io->dev_hdl, "Failed to set led status, err: %d, status: 0x%x, out size: 0x%x\n",
			err, led_info.head.status, out_size);
		return -EIO;
	}

	return 0;
}

int hinic5_set_link_settings(void *hwdev,
			     struct hinic5_link_ksettings *settings)
{
	struct mag_cmd_set_port_cfg info;
	u16 out_size = sizeof(info);
	struct hinic5_nic_io *nic_io = NULL;
	int err;

	if (!hwdev || !settings)
		return -EINVAL;

	memset(&info, 0, sizeof(info));

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	info.port_id = hinic5_physical_port_id(hwdev);
	info.config_bitmap = settings->valid_bitmap;
	info.autoneg = settings->autoneg;
	info.speed = settings->speed;
	info.fec = settings->fec;

	err = mag_msg_to_mgmt_sync(hwdev, MAG_CMD_SET_PORT_CFG, &info,
				   sizeof(info), &info, &out_size);
	if (err != 0 || out_size == 0 || info.head.status != 0) {
		nic_err(nic_io->dev_hdl, "Failed to set link settings, err: %d, status: 0x%x, out size: 0x%x\n",
			err, info.head.status, out_size);
		return -EIO;
	}

	return info.head.status;
}

int hinic5_get_bond_link_state(void *hwdev, struct hinic5_nic_io *nic_io, u8 *link_state)
{
	int err;
	struct hinic5_bond_link_info bond_info = {0};
	u16 out_size = sizeof(bond_info);

	bond_info.port_id = hinic5_physical_port_id(hwdev);

	err = hinic5_msg_to_mgmt_sync(hwdev, HINIC5_MOD_CFM,
				      CFM_MPU_CMD_BOND_LINK_INFO_GET, &bond_info,
				      sizeof(bond_info), &bond_info, &out_size,
				      HINIC5_BOND_MSG_TIMEOUT_MS,
				      HINIC5_CHANNEL_NIC);
	if (err != 0 || out_size == 0 || bond_info.head.status != 0) {
		nic_err(nic_io->dev_hdl, "Failed to get bond link state, err: %d, status: 0x%x, out size: 0x%x\n",
			err, bond_info.head.status, out_size);
		return -EIO;
	}

	*link_state = bond_info.link_status;

	return 0;
}

int hinic5_get_link_state(void *hwdev, u8 *link_state)
{
	struct mag_cmd_get_link_status get_link;
	u16 out_size = sizeof(get_link);
	struct hinic5_nic_io *nic_io = NULL;
	int err;

	if (!hwdev || !link_state)
		return -EINVAL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	/* If this device has half-offload bond enabled, need to get status from bond */
	if ((nic_io->feature_cap & NIC_F_HALF_BOND_OFFLOAD) != 0)
		return hinic5_get_bond_link_state(hwdev, nic_io, link_state);

	memset(&get_link, 0, sizeof(get_link));
	get_link.port_id = hinic5_physical_port_id(hwdev);

	err = mag_msg_to_mgmt_sync(hwdev, MAG_CMD_GET_LINK_STATUS, &get_link,
				   sizeof(get_link), &get_link, &out_size);
	if (err != 0 || out_size == 0 || get_link.head.status != 0) {
		nic_err(nic_io->dev_hdl, "Failed to get link state, err: %d, status: 0x%x, out size: 0x%x\n",
			err, get_link.head.status, out_size);
		return -EIO;
	}

	*link_state = get_link.status;

	return 0;
}

void hinic5_notify_vf_link_status(struct hinic5_nic_io *nic_io,
				  u16 vf_id, u8 link_status)
{
	struct mag_cmd_get_link_status link;
	struct vf_data_storage *vf_infos = nic_io->vf_infos;
	u16 out_size = sizeof(link);
	int err;

	memset(&link, 0, sizeof(link));
	if (vf_infos[HW_VF_ID_TO_OS(vf_id)].registered) {
		link.status = link_status;
		link.port_id = hinic5_physical_port_id(nic_io->hwdev);
		err = hinic5_mbox_to_vf_without_ack(nic_io->hwdev, vf_id, HINIC5_MOD_HILINK,
						    MAG_CMD_GET_LINK_STATUS, &link,
						    sizeof(link), HINIC5_CHANNEL_NIC);
		if (err == MBOX_ERRCODE_UNKNOWN_DES_FUNC) {
			nic_warn(nic_io->dev_hdl, "VF%d not initialized, disconnect it\n",
				 HW_VF_ID_TO_OS(vf_id));
			hinic5_unregister_vf(nic_io, vf_id);
			return;
		}
		if (err != 0 || out_size == 0 || link.head.status != 0)
			nic_err(nic_io->dev_hdl,
				"Send link change event to VF %d failed, err: %d, status: 0x%x, out_size: 0x%x\n",
				HW_VF_ID_TO_OS(vf_id), err, link.head.status, out_size);
	}
}

void hinic5_notify_all_vfs_link_changed(void *hwdev, u8 link_status)
{
	struct hinic5_nic_io *nic_io = NULL;
	u16 i;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return;

	nic_io->link_status = link_status;
	for (i = 1; i <= nic_io->max_vfs; i++) {
		if (!nic_io->vf_infos[HW_VF_ID_TO_OS(i)].link_forced)
			hinic5_notify_vf_link_status(nic_io, i, link_status);
	}
}

static char *g_hw_to_char_fec[HILINK_FEC_MAX_TYPE] = {"not set", "rsfec", "basefec",
						      "nofec", "llrsfec"};
static char *g_hw_to_speed_info[PORT_SPEED_UNKNOWN] = {"not set", "10MB", "100MB", "1GB", "10GB",
						       "25GB", "40GB", "50GB", "100GB", "200GB",
						       "400GB", "800GB"};
static char *g_hw_to_an_state_info[PORT_CFG_AN_OFF + 1] = {"not set", "on", "off"};

struct port_type_table {
	u32 port_type;
	char *port_type_name;
};

static const struct port_type_table port_optical_type_table_s[] = {
	{LINK_PORT_UNKNOWN,	"UNKNOWN"},
	{LINK_PORT_OPTICAL_MM,	"optical_sr"},
	{LINK_PORT_OPTICAL_SM,	"optical_lr"},
	{LINK_PORT_PAS_COPPER,	"copper"},
	{LINK_PORT_ACC,		"ACC"},
	{LINK_PORT_BASET,	"baset"},
	{LINK_PORT_AOC,		"AOC"},
	{LINK_PORT_ELECTRIC,	"electric"},
	{LINK_PORT_BACKBOARD_INTERFACE,	"interface"},
};

static char *get_port_type_name(u32 type)
{
	int i;

	for (i = 0; i < ARRAY_LEN(port_optical_type_table_s); i++) {
		if (type == port_optical_type_table_s[i].port_type)
			return port_optical_type_table_s[i].port_type_name;
	}
	return "UNKNOWN TYPE";
}

static void get_port_type(struct hinic5_nic_io *nic_io,
			  struct mag_cmd_event_port_info *info, char **port_type)
{
	if (info->port_type <= LINK_PORT_BACKBOARD_INTERFACE)
		*port_type = get_port_type_name(info->port_type);
	else
		nic_info(nic_io->dev_hdl, "Unknown port type: %u\n", info->port_type);
}

static const char *const sfp_type_list[] = { "sfp", "Qsfp", "OSFP", "DSFP"};

static int get_port_temperature_power(const struct mag_cmd_event_port_info *info,
				      char *str, u16 str_len)
{
	char arr[CAP_INFO_MAX_LEN] = {0};
	int err = 0;

	if (info->sfp_type < SFP_TYPE_COUNT) {
		err = snprintf(arr, CAP_INFO_MAX_LEN, "%s, %s, Temperature: %u",
				str, sfp_type_list[info->sfp_type], info->cable_temp);
	}

	switch (info->sfp_type) {
	case SFP_TYPE_SFP:
	case SFP_TYPE_DSFP:
		err = snprintf(str, CAP_INFO_MAX_LEN, "%s, rx power: %uuW, tx power: %uuW",
			       arr, info->power[POWER_CHANNEL_INDEX_0],
			       info->power[POWER_CHANNEL_INDEX_1]);
			break;
	case SFP_TYPE_QSFP:
		err = snprintf(str, CAP_INFO_MAX_LEN, "%s, rx power: %uuW %uuW %uuW %uuW",
			       arr, info->power[POWER_CHANNEL_INDEX_0],
			       info->power[POWER_CHANNEL_INDEX_1],
			       info->power[POWER_CHANNEL_INDEX_2],
			       info->power[POWER_CHANNEL_INDEX_3]);
			break;
	case SFP_TYPE_OSFP:
		err = snprintf(str, CAP_INFO_MAX_LEN, "%s, rx power: %uuW %uuW %uuW %uuW",
			       arr, info->power[POWER_CHANNEL_INDEX_0],
			       info->power[POWER_CHANNEL_INDEX_1],
			       info->power[POWER_CHANNEL_INDEX_2],
			       info->power[POWER_CHANNEL_INDEX_3]);
		err = snprintf(str, CAP_INFO_MAX_LEN, "%s, %uuW %uuW %uuW %uuW",
			       arr, info->osfp_power[POWER_CHANNEL_INDEX_0],
			       info->osfp_power[POWER_CHANNEL_INDEX_1],
			       info->osfp_power[POWER_CHANNEL_INDEX_2],
			       info->osfp_power[POWER_CHANNEL_INDEX_3]);
		break;
	default:
		err = snprintf(str, CAP_INFO_MAX_LEN, "%s, Invalid SFP TYPE! ", arr);
		break;
	}

	if (err < 0)
		return err;

	return 0;
}

struct speed_mode_map_s speed_mode_map[] = {
	{PORT_SPEED_MODE_400G, PORT_SPEED_400G},
	{PORT_SPEED_MODE_800G, PORT_SPEED_800G},
};

u32 get_real_port_speed_from_inner_speed(u8 speed)
{
	u32 i;

	if (speed <= PORT_SPEED_MODE_START) { /* Speed <= 200G is not mapped */
		return speed;
	}

	for (i = 0; i < ARRAY_SIZE(speed_mode_map); i++)
		if (speed_mode_map[i].speed_mode == speed)
			return speed_mode_map[i].real_speed;

	pr_err("unsupported port speed mode: 0x%x\n", speed);
	return speed;
}

static void print_cable_info(struct hinic5_nic_io *nic_io, struct mag_cmd_event_port_info *info)
{
	char tmp_str[CAP_INFO_MAX_LEN] = {0};
	char tmp_vendor[VENDOR_MAX_LEN] = {0};
	char tmp_vendor_sn[VENDOR_MAX_LEN] = {0};
	char *port_type = "Unknown port type";
	int i;
	int err = 0;

	if (info->gpio_insert != 0) {
		nic_info(nic_io->dev_hdl, "Cable unpresent\n");
		return;
	}

	get_port_type(nic_io, info, &port_type);

	for (i = (int)sizeof(info->vendor_name) - 1; i >= 0; i--) {
		if (info->vendor_name[i] == ' ')
			info->vendor_name[i] = '\0';
		else
			break;
	}

	memcpy(tmp_vendor, info->vendor_name, sizeof(info->vendor_name));
	memcpy(tmp_vendor_sn, info->vendor_sn, sizeof(info->vendor_sn));

	err = snprintf(tmp_str, CAP_INFO_MAX_LEN,
		       "Vendor: %s, %s, %s, length: %um, max_speed: %uGbps",
		       tmp_vendor, tmp_vendor_sn, port_type, info->cable_length,
		       get_real_port_speed_from_inner_speed(info->max_speed));
	if (err <= 0) {
		nic_info(nic_io->dev_hdl, "Print vendor failed.\n");
		return;
	}

	if (info->port_type == LINK_PORT_OPTICAL_MM || info->port_type == LINK_PORT_OPTICAL_SM ||
	    info->port_type == LINK_PORT_AOC) {
		err = get_port_temperature_power(info, tmp_str, CAP_INFO_MAX_LEN);
		if (err != 0)
			return;
	}

	nic_info(nic_io->dev_hdl, "Cable information: %s\n", tmp_str);
}

static void print_link_info(struct hinic5_nic_io *nic_io,
			    const struct mag_cmd_event_port_info *info,
			    enum hinic5_nic_event_type type)
{
	char *fec = "None";
	char *speed = "None";
	char *an_state = "None";

	if (info->fec < HILINK_FEC_MAX_TYPE)
		fec = g_hw_to_char_fec[info->fec];
	else
		nic_info(nic_io->dev_hdl, "Unknown fec type: %u\n", info->fec);

	if (info->an_state > PORT_CFG_AN_OFF) {
		nic_info(nic_io->dev_hdl, "an_state %u is invalid", info->an_state);
		return;
	}

	an_state = g_hw_to_an_state_info[info->an_state];

	if (info->speed >= PORT_SPEED_UNKNOWN) {
		nic_info(nic_io->dev_hdl, "speed %u is invalid", info->speed);
		return;
	}

	speed = g_hw_to_speed_info[info->speed];
	nic_info(nic_io->dev_hdl, "Link information: speed %s, %s, autoneg %s",
		 speed, fec, an_state);
}

static void print_serdes_txrx_para_1872(struct hinic5_nic_io *nic_io,
					struct mag_cmd_event_port_info *info)
{
	u8 (*sds_txrx_para)[10] = info->sds_txrx_para;
	u32 ds_mask = info->ds_mask;
	u32 ds_id = 0;
	for (ds_id = 0; ds_id < 8U; ds_id++) { /* 1872 has 1 macro with 8 lanes */
		if (((ds_mask >> ds_id) & 0x1) == 0x0) {
			continue;
		}
		nic_info(nic_io->dev_hdl,
			 "ds_id: %u, TX pre2: %d, pre1 %d, main %u, post1: %d, post2: %d, RX cur_boost_index: %u, cur_gain_index: %u\n",
			 ds_id, (s8)sds_txrx_para[ds_id][0], (s8)sds_txrx_para[ds_id][1],
			 sds_txrx_para[ds_id][2], (s8)sds_txrx_para[ds_id][3],
			 (s8)sds_txrx_para[ds_id][4], sds_txrx_para[ds_id][5],
			 sds_txrx_para[ds_id][6]);
	}
}

void hinic5_print_port_info(struct hinic5_nic_io *nic_io, struct mag_cmd_event_port_info *port_info,
		     enum hinic5_nic_event_type type)
{
	print_cable_info(nic_io, port_info);

	print_link_info(nic_io, port_info, type);

	if (type == EVENT_NIC_LINK_UP)
		return;

	nic_info(nic_io->dev_hdl, "PMA ctrl: %s, tx %s, rx %s, PMA fifo reg: 0x%x, PMA signal ok reg: 0x%x, RF/LF status reg: 0x%x\n",
		 port_info->pma_ctrl == 1 ? "off" : "on",
		 (port_info->tx_enable != 0) ? "enable" : "disable",
		 (port_info->rx_enable != 0) ? "enable" : "disable", port_info->pma_fifo_reg,
		 port_info->pma_signal_ok_reg, port_info->rf_lf);
	nic_info(nic_io->dev_hdl, "alos: 0x%x, rx_los: %u, PCS 64 66b reg: 0x%x, PCS link: 0x%x, MAC link: 0x%x PCS_err_cnt: 0x%x\n",
		 port_info->alos, port_info->rx_los, port_info->pcs_64_66b_reg,
		 port_info->pcs_link, port_info->pcs_mac_link, port_info->pcs_err_cnt);
	nic_info(nic_io->dev_hdl, "his_link_machine_state = 0x%08x, cur_link_machine_state = 0x%08x\n",
		 port_info->his_link_machine_state, port_info->cur_link_machine_state);
	if (HINIC5_SUPPORT_FEATURE(nic_io->hwdev, HTN_CMDQ)) { /* 1872 */
		print_serdes_txrx_para_1872(nic_io, port_info);
	}
}

static int hinic5_get_vf_link_status_msg_handler(struct hinic5_nic_io *nic_io,
						 u16 vf_id, void *buf_in,
						 u16 in_size, void *buf_out,
						 u16 *out_size)
{
	struct vf_data_storage *vf_infos = nic_io->vf_infos;
	struct mag_cmd_get_link_status *get_link = buf_out;
	bool link_forced, link_up;

	link_forced = vf_infos[HW_VF_ID_TO_OS(vf_id)].link_forced;
	link_up = vf_infos[HW_VF_ID_TO_OS(vf_id)].link_up;

	if (link_forced)
		get_link->status = link_up ?
					HINIC5_LINK_UP : HINIC5_LINK_DOWN;
	else
		get_link->status = nic_io->link_status;

	get_link->head.status = 0;
	*out_size = sizeof(*get_link);

	return 0;
}

int hinic5_refresh_nic_cfg(void *hwdev, struct mag_port_info *port_info)
{
	int err = 0;
	struct hinic5_nic_io *nic_io = NULL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io) {
		pr_err("Nic io is null\n");
		return -ENODEV;
	}

	if (HINIC5_SUPPORT_RATE_LIMIT(hwdev)) {
		err = hinic5_set_pf_rate(hwdev, port_info->speed);
		if (err != 0) {
			nic_err(nic_io->dev_hdl, "Failed to refresh tx pf bandwidth limit\n");
			return err;
		}
	}

	return err;
}

static void get_port_info(void *hwdev,
			  const struct mag_cmd_get_link_status *link_status,
			  struct hinic5_event_link_info *link_info)
{
	struct mag_port_info port_info = {0};
	struct hinic5_nic_io *nic_io = NULL;
	int err;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io) {
		pr_err("Nic io is null\n");
		return;
	}
	if ((hinic5_func_type(hwdev) != TYPE_VF) && link_status->status != 0) {
		err = hinic5_get_port_info(hwdev, &port_info, HINIC5_CHANNEL_NIC);
		if (err != 0) {
			nic_warn(nic_io->dev_hdl, "Failed to get port info\n");
		} else {
			link_info->valid = 1;
			link_info->port_type = port_info.port_type;
			link_info->autoneg_cap = port_info.autoneg_cap;
			link_info->autoneg_state = port_info.autoneg_state;
			link_info->duplex = port_info.duplex;
			link_info->speed = port_info.speed;
			hinic5_refresh_nic_cfg(hwdev, &port_info);
		}
	}
}

static void link_status_event_handler(void *hwdev, void *buf_in,
				      u16 in_size, void *buf_out, u16 *out_size)
{
	struct mag_cmd_get_link_status *link_status = buf_in;
	struct mag_cmd_get_link_status *ret_link_status = NULL;
	struct hinic5_event_info event_info = {0};
	struct hinic5_event_link_info *link_info = (void *)event_info.event_data;
	struct hinic5_nic_io *nic_io = NULL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	 /* After bond is enabled, bond will notify link status */
	if (!nic_io || ((nic_io->feature_cap & NIC_F_HALF_BOND_OFFLOAD) != 0))
		return;

	if (in_size != sizeof(*link_status)) {
		nic_err(nic_io->dev_hdl, "Invalid link status event cmd, length: %u, should be %lu\n",
			in_size, sizeof(*link_status));
		return;
	}

	nic_info(nic_io->dev_hdl, "Link status report received, func_id: %u, status: %u\n",
		 hinic5_global_func_id(hwdev), link_status->status);

	hinic5_link_event_stats(hwdev, link_status->status);

	/* link event reported only after set vport enable */
	get_port_info(hwdev, link_status, link_info);

	event_info.service = EVENT_SRV_NIC;
	event_info.type = (link_status->status != 0) ?
			EVENT_NIC_LINK_UP : EVENT_NIC_LINK_DOWN;

	hinic5_event_callback(hwdev, &event_info);

	if (hinic5_func_type(hwdev) != TYPE_VF) {
		hinic5_notify_all_vfs_link_changed(hwdev, link_status->status);
		ret_link_status = buf_out;
		ret_link_status->head.status = 0;
		*out_size = sizeof(*ret_link_status);
	}
}

static void port_info_event_printf(void *hwdev, void *buf_in, u16 in_size,
				   void *buf_out, u16 *out_size)
{
	struct mag_cmd_event_port_info *port_info = buf_in;
	struct hinic5_nic_io *nic_io = NULL;
	struct hinic5_event_info event_info;
	enum hinic5_nic_event_type type;

	if (!hwdev) {
		pr_err("hwdev is NULL\n");
		return;
	}

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io) {
		pr_err("Nic io is null\n");
		return;
	}
	if (in_size != sizeof(*port_info)) {
		nic_info(nic_io->dev_hdl, "Invalid port info message size %u, should be %lu\n",
			 in_size, sizeof(*port_info));
		return;
	}

	/* If bond is enabled, skip processing */
	if ((nic_io->feature_cap & NIC_F_HALF_BOND_OFFLOAD) != 0) {
		nic_info(nic_io->dev_hdl, "bond enable ignore port event type: %d\n",
			 port_info->event_type);
		return;
	}

	((struct mag_cmd_event_port_info *)buf_out)->head.status = 0;

	type = port_info->event_type;
	if (type < EVENT_NIC_LINK_DOWN || type > EVENT_NIC_LINK_UP) {
		nic_info(nic_io->dev_hdl, "Invalid hilink info report, type: %d\n",
			 type);
		return;
	}

	hinic5_print_port_info(nic_io, port_info, type);

	memset(&event_info, 0, sizeof(event_info));
	event_info.service = EVENT_SRV_NIC;
	event_info.type = type;

	*out_size = sizeof(*port_info);

	hinic5_event_callback(hwdev, &event_info);
}

static void cable_plug_event(void *hwdev, void *buf_in, u16 in_size,
			     void *buf_out, u16 *out_size)
{
	struct mag_cmd_wire_event *plug_event = buf_in;
	struct hinic5_port_routine_cmd *rt_cmd = NULL;
	struct hinic5_port_routine_cmd_extern *rt_cmd_ext = NULL;
	struct hinic5_nic_io *nic_io = NULL;
	struct hinic5_event_info event_info;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return;

	if (in_size != sizeof(*plug_event)) {
		nic_err(nic_io->dev_hdl, "Invalid cable plug cmd, length: %u, should be %lu\n",
			in_size, sizeof(*plug_event));
		return;
	}

	/* If bond is enabled, skip processing */
	if ((nic_io->feature_cap & NIC_F_HALF_BOND_OFFLOAD) != 0) {
		nic_info(nic_io->dev_hdl, "bond enable ignore cable plug event\n");
		return;
	}

	rt_cmd = &nic_io->nic_cfg.rt_cmd;
	rt_cmd_ext = &nic_io->nic_cfg.rt_cmd_ext;

	mutex_lock(&nic_io->nic_cfg.sfp_mutex);
	rt_cmd->mpu_send_sfp_abs = false;
	rt_cmd->mpu_send_sfp_info = false;
	rt_cmd_ext->mpu_send_xsfp_tlv_info = false;
	mutex_unlock(&nic_io->nic_cfg.sfp_mutex);

	memset(&event_info, 0, sizeof(event_info));
	event_info.service = EVENT_SRV_NIC;
	event_info.type = EVENT_NIC_PORT_MODULE_EVENT;
	((struct hinic5_port_module_event *)(void *)event_info.event_data)->type =
		(plug_event->status != 0) ? HINIC5_PORT_MODULE_CABLE_PLUGGED :
			HINIC5_PORT_MODULE_CABLE_UNPLUGGED;

	*out_size = sizeof(*plug_event);
	plug_event = buf_out;
	plug_event->head.status = 0;

	hinic5_event_callback(hwdev, &event_info);
}

static void port_sfp_info_event(void *hwdev, void *buf_in, u16 in_size,
				void *buf_out, u16 *out_size)
{
	struct mag_cmd_get_xsfp_info *sfp_info = buf_in;
	struct hinic5_port_routine_cmd *rt_cmd = NULL;
	struct hinic5_port_routine_cmd_extern *rt_cmd_ext = NULL;
	struct hinic5_nic_io *nic_io = NULL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return;
	if (in_size != sizeof(*sfp_info)) {
		nic_err(nic_io->dev_hdl, "Invalid sfp info cmd, length: %u, should be %lu\n",
			in_size, sizeof(*sfp_info));
		return;
	}

	rt_cmd = &nic_io->nic_cfg.rt_cmd;
	rt_cmd_ext = &nic_io->nic_cfg.rt_cmd_ext;
	mutex_lock(&nic_io->nic_cfg.sfp_mutex);
	memcpy(&rt_cmd->std_sfp_info, sfp_info, sizeof(struct mag_cmd_get_xsfp_info));
	rt_cmd->mpu_send_sfp_info = true;
	rt_cmd_ext->mpu_send_xsfp_tlv_info = false;
	mutex_unlock(&nic_io->nic_cfg.sfp_mutex);
}

#define xsfp_tlv_pre_info_len 4
static void port_xsfp_tlv_info_event(void *hwdev, void *buf_in, u16 in_size,
				     void *buf_out, const u16 *out_size)
{
	struct tag_mag_cmd_get_xsfp_tlv_rsp  *xsfp_tlv_info = buf_in;
	struct hinic5_port_routine_cmd *rt_cmd = NULL;
	struct hinic5_port_routine_cmd_extern *rt_cmd_ext = NULL;
	struct hinic5_nic_io *nic_io = NULL;
	size_t cpy_len = in_size - sizeof(struct mgmt_msg_head) - xsfp_tlv_pre_info_len;

	if (in_size <= sizeof(struct mgmt_msg_head) + xsfp_tlv_pre_info_len)
		return;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return;

	rt_cmd = &nic_io->nic_cfg.rt_cmd;
	rt_cmd_ext = &nic_io->nic_cfg.rt_cmd_ext;
	mutex_lock(&nic_io->nic_cfg.sfp_mutex);
	rt_cmd_ext->std_xsfp_tlv_info.port_id = xsfp_tlv_info->port_id;

	memcpy(rt_cmd_ext->std_xsfp_tlv_info.tlv_buf, xsfp_tlv_info->tlv_buf, cpy_len);

	rt_cmd->mpu_send_sfp_info = false;
	rt_cmd_ext->mpu_send_xsfp_tlv_info = true;
	mutex_unlock(&nic_io->nic_cfg.sfp_mutex);
}

static void port_sfp_abs_event(void *hwdev, void *buf_in, u16 in_size,
			       void *buf_out, u16 *out_size)
{
	struct mag_cmd_get_xsfp_present *sfp_abs = buf_in;
	struct hinic5_port_routine_cmd *rt_cmd = NULL;
	struct hinic5_nic_io *nic_io = NULL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return;
	if (in_size != sizeof(*sfp_abs)) {
		nic_err(nic_io->dev_hdl, "Invalid sfp absent cmd, length: %u, should be %lu\n",
			in_size, sizeof(*sfp_abs));
		return;
	}

	rt_cmd = &nic_io->nic_cfg.rt_cmd;
	mutex_lock(&nic_io->nic_cfg.sfp_mutex);
	memcpy(&rt_cmd->abs, sfp_abs, sizeof(struct mag_cmd_get_xsfp_present));
	rt_cmd->mpu_send_sfp_abs = true;
	mutex_unlock(&nic_io->nic_cfg.sfp_mutex);
}

bool hinic5_if_sfp_absent(void *hwdev)
{
	struct hinic5_nic_io *nic_io = NULL;
	struct hinic5_port_routine_cmd *rt_cmd = NULL;
	struct mag_cmd_get_xsfp_present sfp_abs;
	u8 port_id = hinic5_physical_port_id(hwdev);
	u16 out_size = sizeof(sfp_abs);
	int err;
	bool sfp_abs_status = 0;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return true;

	memset(&sfp_abs, 0, sizeof(sfp_abs));

	rt_cmd = &nic_io->nic_cfg.rt_cmd;
	mutex_lock(&nic_io->nic_cfg.sfp_mutex);
	if (rt_cmd->mpu_send_sfp_abs) {
		if (rt_cmd->abs.head.status != 0) {
			mutex_unlock(&nic_io->nic_cfg.sfp_mutex);
			return true;
		}

		sfp_abs_status = (bool)rt_cmd->abs.abs_status;
		mutex_unlock(&nic_io->nic_cfg.sfp_mutex);
		return sfp_abs_status;
	}
	mutex_unlock(&nic_io->nic_cfg.sfp_mutex);

	sfp_abs.port_id = port_id;
	err = mag_msg_to_mgmt_sync(hwdev, MAG_CMD_GET_XSFP_PRESENT,
				   &sfp_abs, sizeof(sfp_abs), &sfp_abs,
				   &out_size);
	if (sfp_abs.head.status != 0 || err != 0 || out_size == 0) {
		nic_err(nic_io->dev_hdl,
			"Failed to get port%u sfp absent status, err: %d, status: 0x%x, out size: 0x%x\n",
			port_id, err, sfp_abs.head.status, out_size);
		return true;
	}

	return (sfp_abs.abs_status == 0 ? false : true);
}

int hinic5_get_sfp_tlv_info(void *hwdev, struct drv_tag_mag_cmd_get_xsfp_tlv_rsp *sfp_tlv_info,
			    const struct tag_mag_cmd_get_xsfp_tlv_req *sfp_tlv_info_req)
{
	struct hinic5_nic_io *nic_io = NULL;
	struct hinic5_port_routine_cmd_extern *rt_cmd_ext = NULL;
	u16 out_size = sizeof(*sfp_tlv_info);
	int err;

	if (!hwdev || !sfp_tlv_info)
		return -EINVAL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	rt_cmd_ext = &nic_io->nic_cfg.rt_cmd_ext;
	mutex_lock(&nic_io->nic_cfg.sfp_mutex);
	if (rt_cmd_ext->mpu_send_xsfp_tlv_info) {
		if (rt_cmd_ext->std_xsfp_tlv_info.head.status != 0) {
			mutex_unlock(&nic_io->nic_cfg.sfp_mutex);
			return -EIO;
		}

		memcpy(sfp_tlv_info, &rt_cmd_ext->std_xsfp_tlv_info, sizeof(*sfp_tlv_info));
		mutex_unlock(&nic_io->nic_cfg.sfp_mutex);
		return 0;
	}

	mutex_unlock(&nic_io->nic_cfg.sfp_mutex);

	err = mag_msg_to_mgmt_sync(hwdev, MAG_CMD_GET_XSFP_TLV_INFO, (void *)sfp_tlv_info_req,
				   sizeof(*sfp_tlv_info_req), sfp_tlv_info, &out_size);
	if (sfp_tlv_info->head.status != 0 || err != 0 || out_size == 0) {
		nic_err(nic_io->dev_hdl,
			"Failed to get port%u sfp eeprom information, err: %d, status: 0x%x, out size: 0x%x\n",
			hinic5_physical_port_id(hwdev), err,
			sfp_tlv_info->head.status, out_size);
		return -EIO;
	}

	return 0;
}

int hinic5_get_sfp_info(void *hwdev, struct mag_cmd_get_xsfp_info *sfp_info)
{
	struct hinic5_nic_io *nic_io = NULL;
	struct hinic5_port_routine_cmd *rt_cmd = NULL;
	u16 out_size = sizeof(*sfp_info);
	int err = 0;

	if (!hwdev || !sfp_info)
		return -EINVAL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;
	rt_cmd = &nic_io->nic_cfg.rt_cmd;
	mutex_lock(&nic_io->nic_cfg.sfp_mutex);
	if (rt_cmd->mpu_send_sfp_info) {
		if (rt_cmd->std_sfp_info.head.status != 0) {
			mutex_unlock(&nic_io->nic_cfg.sfp_mutex);
			return -EIO;
		}

		memcpy(sfp_info, &rt_cmd->std_sfp_info, sizeof(*sfp_info));
		mutex_unlock(&nic_io->nic_cfg.sfp_mutex);
		return (err == 0) ? 0 : -ENOMEM;
	}
	mutex_unlock(&nic_io->nic_cfg.sfp_mutex);

	sfp_info->port_id = hinic5_physical_port_id(hwdev);
	err = mag_msg_to_mgmt_sync(hwdev, MAG_CMD_GET_XSFP_INFO, sfp_info,
				   sizeof(*sfp_info), sfp_info, &out_size);

	if (sfp_info->head.status == HINIC5_MGMT_CMD_UNSUPPORTED)
		return -EOPNOTSUPP;

	if (sfp_info->head.status != 0 || err != 0 || out_size == 0) {
		nic_err(nic_io->dev_hdl,
			"Failed to get port%u sfp eeprom information, err: %d, status: 0x%x, out size: 0x%x\n",
			hinic5_physical_port_id(hwdev), err,
			sfp_info->head.status, out_size);
		return -EIO;
	}

	return 0;
}

int hinic5_get_sfp_eeprom(void *hwdev, u8 *data, u32 len, u32 offset)
{
	struct mag_cmd_get_xsfp_info sfp_info;
	int err = 0;

	if (!hwdev || !data || len > PAGE_SIZE)
		return -EINVAL;

	if (hinic5_if_sfp_absent(hwdev))
		return -ENXIO;

	memset(&sfp_info, 0, sizeof(sfp_info));

	err = hinic5_get_sfp_info(hwdev, &sfp_info);
	if (err != 0)
		return err;

	memcpy(data, sfp_info.sfp_info + offset, len);

	return (err == 0) ? 0 : -ENOMEM;
}

static void hinic5_prase_cmis_tlp_info(u8 *data, u32 len, u8 *sfp_tlv_info, u32 offset)
{
	struct mgmt_tlv_info *tlv_info = NULL;
	u8 *tlv_buf = sfp_tlv_info;
	bool need_continue = true;
	u8 temp_tlv_info[XSFP_CMIS_INFO_MAX_SIZE];
	u32 temp_offset = 0;

	while (need_continue) {
		tlv_info = (struct mgmt_tlv_info *)tlv_buf;
		switch (tlv_info->type) {
		case MAG_XSFP_TYPE_PAGE:
			if (tlv_info->length < MGMT_TLV_U32_SIZE ||
			    tlv_info->length >= XSFP_CMIS_INFO_MAX_SIZE) {
				need_continue = false;
				break;
			}

			memcpy(temp_tlv_info + temp_offset,
			       tlv_buf + MGMT_TLV_U32_SIZE + sizeof(struct mgmt_tlv_info),
			       tlv_info->length - MGMT_TLV_U32_SIZE);
			temp_offset += tlv_info->length - MGMT_TLV_U32_SIZE;

		case MAG_XSFP_TYPE_WIRE_TYPE:
			break;
		case MAG_XSFP_TYPE_END:
		default:
			need_continue = false;
			break;
		}

		tlv_buf += (sizeof(struct mgmt_tlv_info) + tlv_info->length);
	}
	memcpy(data, temp_tlv_info + offset, len);
}

int hinic5_get_cmis_eeprom(void *hwdev, u8 *data, u32 len, u32 offset)
{
	struct drv_tag_mag_cmd_get_xsfp_tlv_rsp sfp_tlv_info;
	struct tag_mag_cmd_get_xsfp_tlv_req sfp_tlv_info_req;
	int err;

	if (!hwdev)
		return -EINVAL;

	if (hinic5_if_sfp_absent(hwdev))
		return -ENXIO;

	memset(&sfp_tlv_info, 0, sizeof(sfp_tlv_info));
	memset(&sfp_tlv_info_req, 0, sizeof(sfp_tlv_info_req));

	sfp_tlv_info_req.port_id = hinic5_physical_port_id(hwdev);
	sfp_tlv_info_req.rsp_buf_len = XSFP_CMIS_INFO_MAX_SIZE;

	err = hinic5_get_sfp_tlv_info(hwdev, &sfp_tlv_info, &sfp_tlv_info_req);
	if (err != 0)
		return err;
	hinic5_prase_cmis_tlp_info(data, len, sfp_tlv_info.tlv_buf, offset);

	return err;
}

u8 support_page[CMIS_MAX_PAGES] = {
		HINIC5_PAGE_L00_H00_OFFSET, HINIC5_PAGE_H01_OFFSET,
		HINIC5_PAGE_H02_OFFSET, HINIC5_PAGE_INVALID_OFFSET,
		HINIC5_PAGE_INVALID_OFFSET, HINIC5_PAGE_INVALID_OFFSET,
		HINIC5_PAGE_INVALID_OFFSET, HINIC5_PAGE_INVALID_OFFSET,
		HINIC5_PAGE_INVALID_OFFSET, HINIC5_PAGE_INVALID_OFFSET,
		HINIC5_PAGE_INVALID_OFFSET, HINIC5_PAGE_INVALID_OFFSET,
		HINIC5_PAGE_INVALID_OFFSET, HINIC5_PAGE_INVALID_OFFSET,
		HINIC5_PAGE_INVALID_OFFSET, HINIC5_PAGE_INVALID_OFFSET,
		HINIC5_PAGE_H10_OFFSET, HINIC5_PAGE_H11_OFFSET
};

int hinic5_eeprom_page_check(u8 page_id, u32 offset, u32 len)
{
	u8 page_offset;

	if (page_id >= CMIS_MAX_PAGES)
		return -EINVAL;

	page_offset = support_page[page_id];

	if (page_offset == HINIC5_PAGE_INVALID_OFFSET)
		return -EOPNOTSUPP;

	if (len == 0 ||
	    page_offset * QSFP_CMIS_PAGE_SIZE + offset + len >= XSFP_CMIS_INFO_MAX_SIZE)
		return -EINVAL;

	return 0;
}

int hinic5_get_cmis_eeprom_by_page(void *hwdev, u8 page_id, u32 offset, u8 *data, u32 len)
{
	u32 data_offset;

	data_offset = support_page[page_id] * QSFP_CMIS_PAGE_SIZE + offset;

	return hinic5_get_cmis_eeprom(hwdev, data, len, data_offset);
}

#define CMIS_UPPER_PAGE_00H_EXT_ID_OFFSET 0x81
static void process_sfp_data(u8 *sfp_data, u8 *sfp_type, u8 *sfp_type_ext)
{
	*sfp_type = sfp_data[0x0];

	if (*sfp_type == MODULE_TYPE_SFF8024_ID_QSFP_PLUS_CMIS)
		*sfp_type_ext = sfp_data[CMIS_UPPER_PAGE_00H_EXT_ID_OFFSET];
	else
		*sfp_type_ext = sfp_data[0x1];
}

int hinic5_get_sfp_cmis_type(void *hwdev, u8 *sfp_type, u8 *sfp_type_ext)
{
	struct hinic5_nic_io *nic_io = NULL;
	struct hinic5_port_routine_cmd_extern *rt_cmd_ext = NULL;
	u8 sfp_data[XSFP_CMIS_INFO_MAX_SIZE] = {0};
	int err;

	if (!hwdev || !sfp_type || !sfp_type_ext)
		return -EINVAL;

	if (hinic5_if_sfp_absent(hwdev))
		return -ENXIO;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;
	rt_cmd_ext = &nic_io->nic_cfg.rt_cmd_ext;

	mutex_lock(&nic_io->nic_cfg.sfp_mutex);
	if (rt_cmd_ext->mpu_send_xsfp_tlv_info) {
		if (rt_cmd_ext->std_xsfp_tlv_info.head.status != 0) {
			mutex_unlock(&nic_io->nic_cfg.sfp_mutex);
			return -EIO;
		}

		hinic5_prase_cmis_tlp_info(sfp_data, XSFP_CMIS_INFO_MAX_SIZE,
					   rt_cmd_ext->std_xsfp_tlv_info.tlv_buf, 0);
		process_sfp_data(sfp_data, sfp_type, sfp_type_ext);

		mutex_unlock(&nic_io->nic_cfg.sfp_mutex);
		return 0;
	}

	mutex_unlock(&nic_io->nic_cfg.sfp_mutex);

	err = hinic5_get_cmis_eeprom(hwdev, (u8 *)sfp_data,
				     CMIS_UPPER_PAGE_00H_EXT_ID_OFFSET, 0);
	if (err != 0)
		return err;

	process_sfp_data(sfp_data, sfp_type, sfp_type_ext);

	return 0;
}

int hinic5_get_sfp_type(void *hwdev, u8 *sfp_type, u8 *sfp_type_ext)
{
	struct hinic5_nic_io *nic_io = NULL;
	struct hinic5_port_routine_cmd *rt_cmd = NULL;
	u8 sfp_data[STD_SFP_INFO_MAX_SIZE];
	int err;

	if (!hwdev || !sfp_type || !sfp_type_ext)
		return -EINVAL;

	if (hinic5_if_sfp_absent(hwdev))
		return -ENXIO;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;
	rt_cmd = &nic_io->nic_cfg.rt_cmd;

	mutex_lock(&nic_io->nic_cfg.sfp_mutex);
	if (rt_cmd->mpu_send_sfp_info) {
		if (rt_cmd->std_sfp_info.head.status != 0) {
			mutex_unlock(&nic_io->nic_cfg.sfp_mutex);
			return -EIO;
		}

		*sfp_type = rt_cmd->std_sfp_info.sfp_info[0];
		*sfp_type_ext = rt_cmd->std_sfp_info.sfp_info[1];
		mutex_unlock(&nic_io->nic_cfg.sfp_mutex);
		return 0;
	}
	mutex_unlock(&nic_io->nic_cfg.sfp_mutex);

	err = hinic5_get_sfp_eeprom(hwdev, (u8 *)sfp_data,
				    STD_SFP_INFO_MAX_SIZE, 0);
	if (err != 0)
		return err;

	*sfp_type = sfp_data[0];
	*sfp_type_ext = sfp_data[1];

	return 0;
}

int hinic5_set_link_status_follow(void *hwdev, enum hinic5_link_follow_status status)
{
	struct mag_cmd_set_link_follow follow;
	struct hinic5_nic_io *nic_io = NULL;
	u16 out_size = sizeof(follow);
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	if (status >= HINIC5_LINK_FOLLOW_STATUS_MAX) {
		nic_err(nic_io->dev_hdl, "Invalid link follow status: %d\n", status);
		return -EINVAL;
	}

	memset(&follow, 0, sizeof(follow));
	follow.function_id = hinic5_global_func_id(hwdev);
	follow.follow = status;

	err = mag_msg_to_mgmt_sync(hwdev, MAG_CMD_SET_LINK_FOLLOW, &follow,
				   sizeof(follow), &follow, &out_size);
	if ((follow.head.status != HINIC5_MGMT_CMD_UNSUPPORTED && follow.head.status != 0) ||
	    err != 0 || out_size == 0) {
		nic_err(nic_io->dev_hdl, "Failed to set link status follow port status, err: %d, status: 0x%x, out size: 0x%x\n",
			err, follow.head.status, out_size);
		return -EFAULT;
	}

	return follow.head.status;
}

int hinic5_update_pf_bw(void *hwdev)
{
	struct mag_port_info port_info = {0};
	struct hinic5_nic_io *nic_io = NULL;
	int err;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	if (hinic5_func_type(hwdev) == TYPE_VF || !HINIC5_SUPPORT_RATE_LIMIT(hwdev)) {
		nic_err(nic_io->dev_hdl, "Current function doesn't support to set rate limit\n");
		return -EINVAL;
	}

	err = hinic5_get_port_info(hwdev, &port_info, HINIC5_CHANNEL_NIC);
	if (err != 0) {
		nic_err(nic_io->dev_hdl, "Failed to get port info\n");
		return -EIO;
	}

	err = hinic5_set_pf_rate(hwdev, port_info.speed);
	if (err != 0) {
		nic_err(nic_io->dev_hdl, "Failed to set pf bandwidth\n");
		return err;
	}

	return 0;
}

int hinic5_set_pf_bw_limit(void *hwdev, u32 bw_limit)
{
	struct hinic5_nic_io *nic_io = NULL;
	u32 old_bw_limit;
	u8 link_state = 0;
	int err;

	if (!hwdev)
		return -EINVAL;

	if (hinic5_func_type(hwdev) == TYPE_VF)
		return 0;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	if (bw_limit > MAX_LIMIT_BW) {
		nic_err(nic_io->dev_hdl, "Invalid bandwidth: %u\n", bw_limit);
		return -EINVAL;
	}

	err = hinic5_get_link_state(hwdev, &link_state);
	if (err != 0) {
		nic_err(nic_io->dev_hdl, "Failed to get link state\n");
		return -EIO;
	}

	if (link_state == 0) {
		nic_err(nic_io->dev_hdl, "Link status must be up when setting pf tx rate\n");
		return -EINVAL;
	}

	old_bw_limit = nic_io->nic_cfg.pf_bw_limit;
	nic_io->nic_cfg.pf_bw_limit = bw_limit;

	err = hinic5_update_pf_bw(hwdev);
	if (err != 0) {
		nic_io->nic_cfg.pf_bw_limit = old_bw_limit;
		return err;
	}

	return 0;
}

int hinic5_get_pf_bw_limit(void *hwdev, u32 *bw_limit)
{
	struct hinic5_nic_io *nic_io = NULL;

	if (!hwdev || !bw_limit)
		return -EINVAL;

	if (hinic5_func_type(hwdev) == TYPE_VF)
		return 0;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	*bw_limit = nic_io->nic_cfg.pf_bw_limit;

	return 0;
}

static const struct vf_msg_handler vf_mag_cmd_handler[] = {
	{
		.cmd = MAG_CMD_GET_LINK_STATUS,
		.handler = hinic5_get_vf_link_status_msg_handler,
	},
};

/* pf/ppf handler mbox msg from vf */
int hinic5_pf_mag_mbox_handler(void *hwdev, u16 vf_id,
			       u16 cmd, void *buf_in, u16 in_size,
			       void *buf_out, u16 *out_size)
{
	int index, cmd_size = ARRAY_LEN(vf_mag_cmd_handler);
	struct hinic5_nic_io *nic_io = NULL;
	const struct vf_msg_handler *handler = NULL;

	if (!hwdev)
		return -EFAULT;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EFAULT;

	for (index = 0; index < cmd_size; index++) {
		handler = &vf_mag_cmd_handler[index];
		if (cmd == handler->cmd)
			return handler->handler(nic_io, vf_id, buf_in, in_size,
						buf_out, out_size);
	}

	nic_warn(nic_io->dev_hdl, "NO handler for mag cmd: %u received from vf id: %u\n",
		 cmd, vf_id);

	return -EINVAL;
}

static struct nic_event_handler mag_cmd_handler[] = {
	{
		.cmd = MAG_CMD_GET_LINK_STATUS,
		.handler = link_status_event_handler,
	},

	{
		.cmd = MAG_CMD_EVENT_PORT_INFO,
		.handler = port_info_event_printf,
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

	{
		.cmd = MAG_CMD_GET_XSFP_TLV_INFO,
		.handler = (void (*)(void *hwdev, void *buf_in, u16 in_size,
			void *buf_out, u16 *out_size))port_xsfp_tlv_info_event,
	},
};

static int hinic5_mag_event_handler(void *hwdev, u16 cmd,
				    void *buf_in, u16 in_size, void *buf_out,
				    u16 *out_size)
{
	struct hinic5_nic_io *nic_io = NULL;
	int size = ARRAY_LEN(mag_cmd_handler);
	int i;

	if (!hwdev)
		return -EINVAL;

	*out_size = 0;
	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EFAULT;
	for (i = 0; i < size; i++) {
		if (cmd == mag_cmd_handler[i].cmd) {
			mag_cmd_handler[i].handler(hwdev, buf_in, in_size,
						   buf_out, out_size);
			return 0;
		}
	}

	/* can't find this event cmd */
	nic_warn(nic_io->dev_hdl, "Unsupported mag event, cmd: %u\n", cmd);
	*out_size = sizeof(struct mgmt_msg_head);
	((struct mgmt_msg_head *)buf_out)->status = HINIC5_MGMT_CMD_UNSUPPORTED;

	return 0;
}

int hinic5_vf_mag_event_handler(void *hwdev, u16 cmd,
				void *buf_in, u16 in_size, void *buf_out,
				u16 *out_size)
{
	return hinic5_mag_event_handler(hwdev, cmd, buf_in, in_size,
					buf_out, out_size);
}

/* pf/ppf handler mgmt cpu report hilink event */
void hinic5_pf_mag_event_handler(void *pri_handle, u16 cmd,
				 void *buf_in, u16 in_size, void *buf_out,
				 u16 *out_size)
{
	hinic5_mag_event_handler(pri_handle, cmd, buf_in, in_size,
				 buf_out, out_size);
}

static int _mag_msg_to_mgmt_sync(void *hwdev, u16 cmd, void *buf_in,
				 u16 in_size, void *buf_out, u16 *out_size,
				 u16 channel)
{
	int i, cmd_cnt = ARRAY_LEN(vf_mag_cmd_handler);

	if (hinic5_func_type(hwdev) == TYPE_VF && (!hinic5_is_slave_host(hwdev)) &&
	    (!hinic5_is_vf_isolation(hwdev))) {
		for (i = 0; i < cmd_cnt; i++) {
			if (cmd == vf_mag_cmd_handler[i].cmd) {
				return hinic5_mbox_to_pf(hwdev, HINIC5_MOD_HILINK, cmd, buf_in,
					in_size, buf_out, out_size, 0, channel);
			}
		}
	}

	return hinic5_msg_to_mgmt_sync(hwdev, HINIC5_MOD_HILINK, cmd, buf_in,
				       in_size, buf_out, out_size, 0, channel);
}

static int mag_msg_to_mgmt_sync(void *hwdev, u16 cmd, void *buf_in, u16 in_size,
				void *buf_out, u16 *out_size)
{
	return _mag_msg_to_mgmt_sync(hwdev, cmd, buf_in, in_size, buf_out,
				     out_size, HINIC5_CHANNEL_NIC);
}

static int mag_msg_to_mgmt_sync_ch(void *hwdev, u16 cmd, void *buf_in,
				   u16 in_size, void *buf_out, u16 *out_size,
				   u16 channel)
{
	return _mag_msg_to_mgmt_sync(hwdev, cmd, buf_in, in_size, buf_out,
				     out_size, channel);
}

int hinic5_set_fec(void *hwdev, u8 advertised_fec)
{
	struct mag_cmd_cfg_fec_mode fec_msg = {0};
	struct hinic5_nic_io *nic_io = NULL;
	u16 out_size = sizeof(fec_msg);
	int err;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	fec_msg.opcode = MAG_CMD_OPCODE_SET;
	fec_msg.port_id = hinic5_physical_port_id(hwdev);
	fec_msg.advertised_fec = advertised_fec;
	err = mag_msg_to_mgmt_sync_ch(hwdev, MAG_CMD_CFG_FEC_MODE, &fec_msg, sizeof(fec_msg),
				      &fec_msg, &out_size, HINIC5_CHANNEL_NIC);
	if (err != 0 || fec_msg.head.status != 0 || out_size == 0) {
		nic_err(nic_io->dev_hdl, "Set FEC mode failed, err: %d, status: 0x%x, out size: 0x%x\n",
			err, fec_msg.head.status, out_size);
		return -EINVAL;
	}
	return 0;
}

int hinic5_get_fec(void *hwdev, u8 *advertised_fec, u8 *supported_fec)
{
	struct mag_cmd_cfg_fec_mode fec_msg = {0};
	struct hinic5_nic_io *nic_io = NULL;
	u16 out_size = sizeof(fec_msg);
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	fec_msg.opcode = MAG_CMD_OPCODE_GET;
	fec_msg.port_id = hinic5_physical_port_id(hwdev);
	err = mag_msg_to_mgmt_sync_ch(hwdev, MAG_CMD_CFG_FEC_MODE, &fec_msg, sizeof(fec_msg),
				      &fec_msg, &out_size, HINIC5_CHANNEL_NIC);
	if (err != 0 || fec_msg.head.status != 0 || out_size == 0) {
		nic_err(nic_io->dev_hdl, "Get FEC mode failed, err: %d, status: 0x%x, out size: 0x%x\n",
			err, fec_msg.head.status, out_size);
		return -EINVAL;
	}

	*advertised_fec = fec_msg.advertised_fec;
	*supported_fec = fec_msg.supported_fec;

	return 0;
}
