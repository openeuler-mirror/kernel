/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_macsec_mgmt.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : macsec configuration distribution
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [MACsec]" fmt

#include <linux/types.h>

#include "macsec_mpu_cmd.h"
#include "macsec_mpu_cmd_defs.h"
#include "hinic5_hw.h"
#include "comm_defs.h"
#include "hinic5_macsec_dev.h"
#include "hinic5_macsec_dfx.h"
#include "hinic5_macsec_api.h"
#include "hinic5_macsec_common.h"

int himacsec_cmd_exec_get_feature_nego(struct hinic5_lld_dev *lld_dev,
				       u64 *feature_bitmap, u32 feature_size)
{
	int ret;
	u16 out_size = sizeof(macsec_feature_nego_cmd_s);
	macsec_feature_nego_cmd_s feature_nego = {0};

	if (!feature_bitmap) {
		macsec_err(lld_dev->dev, "MACsec get feature nego invalid param, feature bitmap is NULL");
		return -EINVAL;
	}

	if (feature_size > MACSEC_MAX_FEATURE_QWORD) {
		macsec_err(lld_dev->dev, "MACsec get feature nego invalid param, feature_size(0x%x) is greater than 0x%x",
			   feature_size, MACSEC_MAX_FEATURE_QWORD);
		return -EINVAL;
	}

	feature_nego.op_code = MACSEC_FEATURE_NEGO_OPCODE_GET;
	ret = hinic5_msg_to_mgmt_sync(lld_dev->hwdev, HINIC5_MOD_MACSEC,
				      MACSEC_CMD_FEATURE_NEGO_OP, &feature_nego,
				      sizeof(macsec_feature_nego_cmd_s),
				      &feature_nego, &out_size, 0,
				      HINIC5_CHANNEL_MACSEC);
	if (ret != 0 || feature_nego.head.status != 0 ||
	    out_size != (u32)sizeof(feature_nego)) {
		macsec_err(lld_dev->dev, "MACsec get feature nego status(0x%x) incorrect, out size(0x%x) not equals 0x%x",
			   feature_nego.head.status, out_size, (u32)sizeof(feature_nego));
		return -EINVAL;
	}

	memcpy(feature_bitmap, feature_nego.s_feature, feature_size * sizeof(u64));

	return 0;
}

/* TODO(B998): Get chip specifications, port number, max supported SC count per port,
 * AT&Productization consider getting from config file, currently FT solidified
 */
int himacsec_cmd_exec_get_spec(void *hwdev, struct himacsec_spec *spec)
{
	spec->macsec_support = 1;
	spec->max_port = 0x4;
	spec->max_port_sc = 1;
	spec->max_sa = 0x4;
	return 0;
}

int himacsec_cmd_exec_macsec_enable(struct hinic5_lld_dev *lld_dev,
				    macsec_mbox_service_op_cmd_e op_code, u8 *macsec_flag)
{
	macsec_cmd_service_operation_s macsec_cfg = {0};
	u16 out_size = sizeof(macsec_cmd_service_operation_s);
	int ret;

	/* MACsec global switch is only configured on PPF device */
	if (hinic5_func_type(lld_dev->hwdev) != TYPE_PPF) {
		if (macsec_flag)
			*macsec_flag = MACSEC_GLOBAL_SWITCH_IS_ENABLE;
		return 0;
	}

	macsec_cfg.op_code = op_code;

	ret = hinic5_msg_to_mgmt_sync(lld_dev->hwdev, HINIC5_MOD_MACSEC,
				      MACSEC_CMD_SERVICE_OP, &macsec_cfg,
				      sizeof(macsec_cmd_service_operation_s),
				      &macsec_cfg, &out_size, 0,
				      HINIC5_CHANNEL_MACSEC);
	if (ret != 0 || out_size != sizeof(macsec_cmd_service_operation_s) ||
	    macsec_cfg.head.status != 0) {
		macsec_err(lld_dev->dev, "Failed to exec service init cmd, err=0x%x, status=0x%x, out size:0x%x, enable:0x%x",
			   ret, macsec_cfg.head.status, out_size, macsec_cfg.op_code);
		return -EINVAL;
	}
	if (macsec_flag)
		*macsec_flag = MACSEC_GLOBAL_SWITCH_IS_ENABLE;

	return 0;
}

int himacsec_cmd_exec_sc_op(struct hinic5_lld_dev *lld_dev, macsec_sc_info_s *sc_info,
			    macsec_mbox_sc_op_cmd_e opcode)
{
	u16 out_size = sizeof(macsec_cmd_sc_operation_s);
	macsec_cmd_sc_operation_s macsec_cfg = {0};
	int ret;

	memcpy(&macsec_cfg.sc_info, sc_info, sizeof(macsec_sc_info_s));
	macsec_cfg.op_code = opcode;

	// HINIC5_CHANNEL_MACSEC scenario:
	// Need to intercept all features using this channel to MPU requests
	ret = hinic5_msg_to_mgmt_sync(lld_dev->hwdev, HINIC5_MOD_MACSEC,
				      MACSEC_CMD_SC_OP, &macsec_cfg,
				      sizeof(macsec_cmd_sc_operation_s),
				      &macsec_cfg, &out_size, 0,
				      HINIC5_CHANNEL_MACSEC);
	if (ret != 0 || out_size != sizeof(macsec_cmd_sc_operation_s) ||
	    macsec_cfg.head.status != 0) {
		macsec_err(lld_dev->dev, "Failed to exec sc cmd, err=0x%x, status=0x%x, out size:0x%x",
			   ret, macsec_cfg.head.status, out_size);
		return -EINVAL;
	}

	// buf result
	if (opcode == MACSEC_CMD_ENC_SC_GET_INFO || opcode == MACSEC_CMD_DEC_SC_GET_INFO)
		memcpy(sc_info, &macsec_cfg.sc_info, sizeof(macsec_sc_info_s));
	return 0;
}

int himacsec_cmd_exec_sa_op(struct hinic5_lld_dev *lld_dev, macsec_sa_info_s *sa_info,
			    macsec_mbox_sa_op_cmd_e opcode)
{
	/* out_size in driver->mpu flow represents the buf size for receiving mailbox return message
	 * out_size in mpu->driver flow represents the actual size of mailbox return message,
	 * copied by sdk to out_buf
	 */
	u16 out_size = sizeof(macsec_cmd_sa_operation_s);
	macsec_cmd_sa_operation_s macsec_cfg = {0};
	int ret;

	memcpy(&macsec_cfg.sa_info, sa_info, sizeof(macsec_sa_info_s));
	macsec_cfg.op_code = opcode;

	ret = hinic5_msg_to_mgmt_sync(lld_dev->hwdev, HINIC5_MOD_MACSEC,
				      MACSEC_CMD_SA_OP, &macsec_cfg,
				      sizeof(macsec_cmd_sa_operation_s),
				      &macsec_cfg, &out_size, 0,
				      HINIC5_CHANNEL_MACSEC);
	memset(macsec_cfg.sa_info.sak, 0, HIMACSEC_MAX_SAK_KEY_LEN);
	if (ret != 0 || out_size != sizeof(macsec_cmd_sa_operation_s) ||
	    macsec_cfg.head.status != 0) {
		macsec_err(lld_dev->dev, "Failed to exec sa cmd, err=0x%x, status=0x%x, out size:0x%x",
			   ret, macsec_cfg.head.status, out_size);
		return -EINVAL;
	}

	// buf result
	if (opcode == MACSEC_CMD_ENC_SA_GET_INFO || opcode == MACSEC_CMD_DEC_SA_GET_INFO)
		memcpy(sa_info, &macsec_cfg.sa_info, sizeof(macsec_sa_info_s));
	return 0;
}

int himacsec_cmd_exec_mib_port(struct hinic5_lld_dev *lld_dev, struct himacsec_cmd_mib_out *cmd_out)
{
	macsec_cmd_port_mib_operation_s macsec_cfg = {0};
	u16 out_size = sizeof(macsec_cmd_port_mib_operation_s);
	int ret;

	ret = hinic5_msg_to_mgmt_sync(lld_dev->hwdev, HINIC5_MOD_MACSEC,
				      MACSEC_CMD_GET_PORT_MIB, &macsec_cfg,
				      sizeof(macsec_cmd_port_mib_operation_s),
				      &macsec_cfg, &out_size, 0,
				      HINIC5_CHANNEL_MACSEC);
	if (ret != 0 || out_size != sizeof(macsec_cmd_port_mib_operation_s) ||
	    macsec_cfg.head.status != 0) {
		macsec_err(lld_dev->dev, "Failed to exec port mib cmd, err=0x%x, status=0x%x, out size:0x%x",
			   ret, macsec_cfg.head.status, out_size);
		return -EINVAL;
	}

	// Copy result to out_buf
	memcpy(cmd_out->mib_buf, &macsec_cfg.port_mib, sizeof(macsec_cfg.port_mib));

	return 0;
}

int himacsec_cmd_exec_mib_sc(struct hinic5_lld_dev *lld_dev,
			     struct himacsec_cmd_mib_out *out_buf, u64 sci)
{
	macsec_cmd_sc_mib_operation_s macsec_cfg = {0};
	u16 out_size = sizeof(macsec_cmd_sc_mib_operation_s);
	int ret;

	macsec_cfg.sci = sci;
	ret = hinic5_msg_to_mgmt_sync(lld_dev->hwdev, HINIC5_MOD_MACSEC,
				      MACSEC_CMD_GET_SC_MIB, &macsec_cfg,
				      sizeof(macsec_cmd_sc_mib_operation_s),
				      &macsec_cfg, &out_size, 0,
				      HINIC5_CHANNEL_MACSEC);
	if (ret != 0 || out_size != sizeof(macsec_cmd_sc_mib_operation_s) ||
	    macsec_cfg.head.status != 0) {
		macsec_err(lld_dev->dev, "Failed to exec sc mib cmd, err=0x%x, status=0x%x, out size:0x%x",
			   ret, macsec_cfg.head.status, out_size);
		return -EINVAL;
	}

	out_buf->num = 1;
	memcpy(out_buf->mib_buf, &macsec_cfg.sc_mib, sizeof(macsec_sc_mib_info_s));

	return 0;
}

int himacsec_cmd_exec_flush(struct hinic5_lld_dev *lld_dev, tag_macsec_flush_cmd_s *flush_info)
{
	u16 out_size = sizeof(tag_macsec_flush_cmd_s);
	int ret;

	ret = hinic5_msg_to_mgmt_sync(lld_dev->hwdev, HINIC5_MOD_MACSEC,
				      MACSEC_CMD_FLUSH_OP, flush_info,
				      sizeof(tag_macsec_flush_cmd_s), flush_info,
				      &out_size, 0, HINIC5_CHANNEL_MACSEC);
	if (ret != 0 || out_size != sizeof(tag_macsec_flush_cmd_s) ||
	    flush_info->head.status != 0) {
		macsec_err(lld_dev->dev, "Failed to exec flush cmd, err=0x%x, status=0x%x, out size:0x%x",
			   ret, flush_info->head.status, out_size);
		return -EINVAL;
	}

	return 0;
}
