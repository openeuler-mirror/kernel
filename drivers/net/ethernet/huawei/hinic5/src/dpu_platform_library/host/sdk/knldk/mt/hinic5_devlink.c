/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_devlink.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/netlink.h>
#include <linux/firmware.h>

#include "hinic5_devlink.h"
#ifdef HAVE_DEVLINK_FLASH_UPDATE_PARAMS
#include "mpu_inband_cmd.h"
#include "hinic5_common.h"
#include "hinic5_api_cmd.h"
#include "hinic5_mgmt.h"
#include "hinic5_hw.h"
#include "ossl_knl.h"
#include "fw_typedef.h"

#ifdef HAVE_DEVLINK_FLASH_UPDATE_METHOD
static bool check_image_valid(struct hinic5_hwdev *hwdev, const u8 *buf,
			      u32 size, struct host_image *host_image)
{
	struct firmware_image *fw_image = NULL;
	u32 len = 0;
	u32 i, n;

	fw_image = (struct firmware_image *)buf;
	if (fw_image->fw_magic != FW_MAGIC_NUM) {
		sdk_err(hwdev->dev_hdl, "Wrong fw magic read from file, fw_magic: 0x%x\n",
			fw_image->fw_magic);
		return false;
	}

	if (fw_image->fw_info.section_cnt > FW_TYPE_MAX_NUM) {
		sdk_err(hwdev->dev_hdl, "Wrong fw type number read from file, fw_type_num: 0x%x\n",
			fw_image->fw_info.section_cnt);
		return false;
	}

	for (i = 0, n = 0; i < fw_image->fw_info.section_cnt; i++) {
		if (fw_image->section_info[i].section_type == UP_FW_UPDATE_L0FW) {
			len += fw_image->section_info[i].section_len;
			memcpy(&host_image->section_info[n++], &fw_image->section_info[i],
			       sizeof(struct firmware_section));
			break;
		}
	}

	for (i = 0; i < fw_image->fw_info.section_cnt; i++) {
		if (fw_image->section_info[i].section_type == UP_FW_UPDATE_L0FW)
			continue;
		len += fw_image->section_info[i].section_len;
		memcpy(&host_image->section_info[n++], &fw_image->section_info[i],
		       sizeof(struct firmware_section));
	}

	if (len != fw_image->fw_len ||
	    (u32)(fw_image->fw_len + FW_IMAGE_HEAD_SIZE) != size) {
		sdk_err(hwdev->dev_hdl, "Wrong data size read from file\n");
		return false;
	}

	host_image->image_info.total_len = fw_image->fw_len;
	host_image->image_info.fw_version = fw_image->fw_version;
	host_image->type_num = fw_image->fw_info.section_cnt;
	host_image->device_id = fw_image->device_id;

	return true;
}

static bool check_image_device_type(struct hinic5_hwdev *hwdev, u32 device_type)
{
	struct comm_cmd_board_info board_info;

	/* Cold upgrade takes firmware type as default value 0 */
	if (device_type == FW_DEFAULT_TYPE_COLD_UPDATE)
		return true;

	memset(&board_info, 0, sizeof(board_info));
	if (hinic5_get_board_info(hwdev, &board_info.info, HINIC5_CHANNEL_COMM) != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to get board info\n");
		return false;
	}

	if (device_type == board_info.info.board_type)
		return true;

	sdk_err(hwdev->dev_hdl, "The image device type: 0x%x doesn't match the firmware device type: 0x%x\n",
		device_type, board_info.info.board_type);

	return false;
}

static void encapsulate_update_cmd(struct hinic5_cmd_update_firmware *msg,
				   struct firmware_section *section_info,
				   const int *remain_len, u32 *send_len, const u32 *send_pos)
{
	memset(msg->data, 0, sizeof(msg->data));
	msg->ctl_info.sf = (*remain_len == section_info->section_len) ? true : false;
	msg->section_info.section_crc = section_info->section_crc;
	msg->section_info.section_type = section_info->section_type;
	msg->section_version = section_info->section_version;
	msg->section_len = section_info->section_len;
	msg->section_offset = *send_pos;
	msg->ctl_info.bit_signed = section_info->section_flag & 0x1;

	if (*remain_len <= FW_FRAGMENT_MAX_LEN) {
		msg->ctl_info.sl = true;
		msg->ctl_info.fragment_len = (u32)(*remain_len);
		*send_len += section_info->section_len;
	} else {
		msg->ctl_info.sl = false;
		msg->ctl_info.fragment_len = FW_FRAGMENT_MAX_LEN;
		*send_len += FW_FRAGMENT_MAX_LEN;
	}
}

static int hinic5_flash_firmware(struct hinic5_hwdev *hwdev, const u8 *data,
				 struct host_image *image)
{
	u32 send_pos, send_len, section_offset, i;
	struct hinic5_cmd_update_firmware *update_msg = NULL;
	u16 out_size = sizeof(*update_msg);
	bool total_flag = false;
	int remain_len, err;

	update_msg = kzalloc(sizeof(*update_msg), GFP_KERNEL);
	if (!update_msg)
		return -ENOMEM;

	for (i =  0; i < image->type_num; i++) {
		section_offset = image->section_info[i].section_offset;
		remain_len = (int)(image->section_info[i].section_len);
		send_len = 0;
		send_pos = 0;

		while (remain_len > 0) {
			if (!total_flag) {
				update_msg->total_len = image->image_info.total_len;
				total_flag = true;
			} else {
				update_msg->total_len = 0;
			}

			encapsulate_update_cmd(update_msg, &image->section_info[i],
					       &remain_len, &send_len, &send_pos);

			memcpy(update_msg->data,
			       ((data + FW_IMAGE_HEAD_SIZE) + section_offset) + send_pos,
			       update_msg->ctl_info.fragment_len);

			err = hinic5_msg_to_mgmt_sync(hwdev, HINIC5_MOD_COMM,
						      COMM_MGMT_CMD_UPDATE_FW,
						      update_msg, sizeof(*update_msg),
						      update_msg, &out_size,
						      FW_UPDATE_MGMT_TIMEOUT, 0);
			if (err != 0 || out_size == 0 || update_msg->msg_head.status != 0) {
				sdk_err(hwdev->dev_hdl, "Failed to update firmware, err: %d, \
					status: 0x%x, out size: 0x%x\n",
					err, update_msg->msg_head.status, out_size);
				err = (update_msg->msg_head.status != 0) ?
				      update_msg->msg_head.status : -EIO;
				kfree(update_msg);
				return err;
			}

			send_pos = send_len;
			remain_len = (int)(image->section_info[i].section_len - send_len);
		}
	}

	kfree(update_msg);

	return 0;
}

static int hinic5_flash_update_notify(struct devlink *devlink, const struct firmware *fw,
				      struct host_image *image, struct netlink_ext_ack *extack)
{
	struct hinic5_devlink *devlink_dev = devlink_priv(devlink);
	struct hinic5_hwdev *hwdev = devlink_dev->hwdev;
	int err;

#ifdef HAVE_DEVLINK_FLASH_UPDATE_BEGIN_END_NOTIFY
	devlink_flash_update_begin_notify(devlink);
#endif
	devlink_flash_update_status_notify(devlink, "Flash firmware begin", NULL, 0, 0);
	sdk_info(hwdev->dev_hdl, "Flash firmware begin\n");
	err = hinic5_flash_firmware(hwdev, fw->data, image);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to flash firmware, err: %d\n", err);
		NL_SET_ERR_MSG_MOD(extack, "Flash firmware failed");
		devlink_flash_update_status_notify(devlink, "Flash firmware failed", NULL, 0, 0);
	} else {
		err = hinic5_activate_firmware(hwdev, 0);
		if (err != 0) {
			sdk_err(hwdev->dev_hdl, " Failed to activate firmware, err: %d\n", err);
			devlink_flash_update_status_notify(devlink,
							   "Activate firmware failed", NULL, 0, 0);
		} else {
			sdk_info(hwdev->dev_hdl, "Flash firmware end\n");
			devlink_flash_update_status_notify(devlink,
							   "Flash firmware end", NULL, 0, 0);
		}
	}
#ifdef HAVE_DEVLINK_FLASH_UPDATE_BEGIN_END_NOTIFY
	devlink_flash_update_end_notify(devlink);
#endif

	return err;
}

#ifdef HAVE_DEVLINK_OPS_FLASH_UPDATE_HAVE_PARAMS
static int hinic5_devlink_flash_update(struct devlink *devlink,
				       struct devlink_flash_update_params *params,
				       struct netlink_ext_ack *extack)
#else
static int hinic5_devlink_flash_update(struct devlink *devlink, const char *file_name,
				       const char *component, struct netlink_ext_ack *extack)
#endif
{
	struct hinic5_devlink *devlink_dev = devlink_priv(devlink);
	struct hinic5_hwdev *hwdev = devlink_dev->hwdev;
#ifndef HAVE_DEVLINK_FLASH_UPDATE_PARAMS_FW
	const struct firmware *fw = NULL; // fw and file_name are mutually exclusive
#else
	const struct firmware *fw = params->fw;
#endif
	struct host_image *image = NULL;
	int err;

	image = kzalloc(sizeof(*image), GFP_KERNEL);
	if (!image) {
		sdk_err(hwdev->dev_hdl, "Failed to alloc host image\n");
		err = -ENOMEM;
		goto devlink_param_reset;
	}

#ifndef HAVE_DEVLINK_FLASH_UPDATE_PARAMS_FW
#ifdef HAVE_DEVLINK_OPS_FLASH_UPDATE_HAVE_PARAMS
#ifdef HAVE_DEVLINK_FLASH_UPDATE_PARAMS_FILE_NAME
	err = request_firmware_direct(&fw, params->file_name, hwdev->dev_hdl);
#else
	// This scenario theoretically does not exist
	kfree(image);
	err = -EINVAL;
	goto devlink_param_reset;
#endif
#else
	err = request_firmware_direct(&fw, file_name, hwdev->dev_hdl);
#endif
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to request firmware\n");
		goto devlink_request_fw_err;
	}
#endif

	if (!check_image_valid(hwdev, fw->data, (u32)(fw->size), image) ||
	    !check_image_device_type(hwdev, image->device_id)) {
		sdk_err(hwdev->dev_hdl, "Failed to check image\n");
		NL_SET_ERR_MSG_MOD(extack, "Check image failed");
		err = -EINVAL;
		goto devlink_update_out;
	}

	err = hinic5_flash_update_notify(devlink, fw, image, extack);

devlink_update_out:
#ifndef HAVE_DEVLINK_FLASH_UPDATE_PARAMS_FW
	release_firmware(fw);

devlink_request_fw_err:
#endif
	kfree(image);

devlink_param_reset:
	/* reset activate_fw and switch_cfg after flash update operation */
	devlink_dev->activate_fw = FW_CFG_DEFAULT_INDEX;
	devlink_dev->switch_cfg = FW_CFG_DEFAULT_INDEX;

	return err;
}

static int hinic5_devlink_info_get(struct devlink *dl,
				   struct devlink_info_req *req,
				   struct netlink_ext_ack *extack)
{
	struct hinic5_devlink *devlink_dev = devlink_priv(dl);
	struct hinic5_hwdev *hwdev = devlink_dev->hwdev;
	u8 mgmt_ver[HINIC5_MGMT_VERSION_MAX_LEN] = {0};
	int err;

#ifdef HAVE_DEVLINK_INFO_DRIVER_NAME_PUT
	err = devlink_info_driver_name_put(req, HINIC5_DRV_NAME);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to set driver name\n");
		return err;
	};
#endif

	/* Firmware version */
	err = hinic5_get_mgmt_version(hwdev, mgmt_ver, sizeof(mgmt_ver), HINIC5_CHANNEL_COMM);
	if (err != 0) {
		sdk_info(hwdev->dev_hdl, "Failed to get firmware versions\n");
		return err;
	}

	err = devlink_info_version_stored_put(req, "fw.version", (char *)&mgmt_ver[0]);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to set stored fw version\n");
		return err;
	}

	err = devlink_info_version_running_put(req, "fw.version", (char *)&mgmt_ver[0]);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to set running fw version\n");
		return err;
	}

	return 0;
}
#endif

static const struct devlink_ops hinic5_devlink_ops = {
#ifdef HAVE_DEVLINK_FLASH_UPDATE_METHOD
	.flash_update = hinic5_devlink_flash_update,
#endif
	.info_get = hinic5_devlink_info_get,
};

static int hinic5_devlink_get_activate_firmware_config(struct devlink *devlink, u32 id,
						       struct devlink_param_gset_ctx *ctx)
{
	struct hinic5_devlink *devlink_dev = devlink_priv(devlink);

	ctx->val.vu8 = devlink_dev->activate_fw;

	return 0;
}

#ifdef HAVE_DEVLINK_PARAM_SET_EXTACK
static int hinic5_devlink_set_activate_firmware_config(struct devlink *devlink, u32 id,
						       struct devlink_param_gset_ctx *ctx,
							   struct netlink_ext_ack *extack)
#else
static int hinic5_devlink_set_activate_firmware_config(struct devlink *devlink, u32 id,
						       struct devlink_param_gset_ctx *ctx)
#endif
{
	struct hinic5_devlink *devlink_dev = devlink_priv(devlink);
	struct hinic5_hwdev *hwdev = devlink_dev->hwdev;
	int err;

	devlink_dev->activate_fw = ctx->val.vu8;
	sdk_info(hwdev->dev_hdl, "Activate firmware begin\n");

	err = hinic5_activate_firmware(hwdev, devlink_dev->activate_fw);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to activate firmware, err: %d\n", err);
		return err;
	}

	sdk_info(hwdev->dev_hdl, "Activate firmware end\n");

	return 0;
}

static int hinic5_devlink_get_switch_config(struct devlink *devlink, u32 id,
					    struct devlink_param_gset_ctx *ctx)
{
	struct hinic5_devlink *devlink_dev = devlink_priv(devlink);

	ctx->val.vu8 = devlink_dev->switch_cfg;

	return 0;
}

#ifdef HAVE_DEVLINK_PARAM_SET_EXTACK
static int hinic5_devlink_set_switch_config(struct devlink *devlink, u32 id,
					    struct devlink_param_gset_ctx *ctx,
						struct netlink_ext_ack *extack)
#else
static int hinic5_devlink_set_switch_config(struct devlink *devlink, u32 id,
					    struct devlink_param_gset_ctx *ctx)
#endif
{
	struct hinic5_devlink *devlink_dev = devlink_priv(devlink);
	struct hinic5_hwdev *hwdev = devlink_dev->hwdev;
	int err;

	devlink_dev->switch_cfg = ctx->val.vu8;
	sdk_info(hwdev->dev_hdl, "Switch cfg begin");

	err = hinic5_switch_config(hwdev, devlink_dev->switch_cfg);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to switch cfg, err: %d\n", err);
		return err;
	}

	sdk_info(hwdev->dev_hdl, "Switch cfg end\n");

	return 0;
}

static int hinic5_devlink_firmware_config_validate(struct devlink *devlink, u32 id,
						   union devlink_param_value val,
						   struct netlink_ext_ack *extack)
{
	struct hinic5_devlink *devlink_dev = devlink_priv(devlink);
	struct hinic5_hwdev *hwdev = devlink_dev->hwdev;
	u8 cfg_index = val.vu8;

	if (cfg_index > FW_CFG_MAX_INDEX) {
		sdk_err(hwdev->dev_hdl, "Firmware cfg index out of range [0,7]\n");
		NL_SET_ERR_MSG_MOD(extack, "Firmware cfg index out of range [0,7]");
		return -ERANGE;
	}

	return 0;
}

static const struct devlink_param hinic5_devlink_params[] = {
	DEVLINK_PARAM_DRIVER(HINIC5_DEVLINK_PARAM_ID_ACTIVATE_FW,
			     "activate_fw", DEVLINK_PARAM_TYPE_U8,
			     BIT(DEVLINK_PARAM_CMODE_PERMANENT),
			     hinic5_devlink_get_activate_firmware_config,
			     hinic5_devlink_set_activate_firmware_config,
			     hinic5_devlink_firmware_config_validate),
	DEVLINK_PARAM_DRIVER(HINIC5_DEVLINK_PARAM_ID_SWITCH_CFG,
			     "switch_cfg", DEVLINK_PARAM_TYPE_U8,
			     BIT(DEVLINK_PARAM_CMODE_PERMANENT),
			     hinic5_devlink_get_switch_config,
			     hinic5_devlink_set_switch_config,
			     hinic5_devlink_firmware_config_validate),
};

int hinic5_init_devlink(struct hinic5_hwdev *hwdev)
{
	struct device *dev = (struct device *)hwdev->dev_hdl;
	struct devlink *devlink = NULL;
	int err;

	devlink = ossl_devlink_alloc(&hinic5_devlink_ops,
				     sizeof(struct hinic5_devlink), dev);
	if (!devlink) {
		sdk_err(hwdev->dev_hdl, "Failed to alloc devlink\n");
		return -ENOMEM;
	}

	hwdev->devlink_dev = devlink_priv(devlink);
	hwdev->devlink_dev->hwdev = hwdev;
	hwdev->devlink_dev->activate_fw = FW_CFG_DEFAULT_INDEX;
	hwdev->devlink_dev->switch_cfg = FW_CFG_DEFAULT_INDEX;

	err = ossl_devlink_register(devlink, dev);
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to register devlink\n");
		goto register_devlink_err;
	}

	err = devlink_params_register(devlink, hinic5_devlink_params,
				      ARRAY_SIZE(hinic5_devlink_params));
	if (err != 0) {
		sdk_err(hwdev->dev_hdl, "Failed to register devlink params\n");
		goto register_devlink_params_err;
	}

	devlink_params_publish(devlink);

	return 0;

register_devlink_params_err:
	devlink_unregister(devlink);

register_devlink_err:
	devlink_free(devlink);

	return -EFAULT;
}

void hinic5_uninit_devlink(struct hinic5_hwdev *hwdev)
{
	struct devlink *devlink = priv_to_devlink(hwdev->devlink_dev);

	devlink_params_unpublish(devlink);
	devlink_params_unregister(devlink, hinic5_devlink_params,
				  ARRAY_SIZE(hinic5_devlink_params));
	devlink_unregister(devlink);
	devlink_free(devlink);
}
#endif
