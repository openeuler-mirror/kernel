// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_cli_drv_priv.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/rtnetlink.h>

#include "sxe2_common.h"
#include "sxe2_log.h"
#include "sxe2.h"
#include "sxe2_cli_drv_priv.h"
#include "sxe2_cli_drv_msg.h"

STATIC s32 sxe2_cli_get_netdev_name_handler(struct sxe2_adapter *adapter,
					    struct sxe2_cmd_trans_info *param)
{
	struct drv_msg_info *rsp_hdr = SXE2_CLI_DRV_RSP_MSG_HDR(param);
	struct sxe2_cli_drv_get_pname_rsp_msg *dev_name_rsp_msg =
			(struct sxe2_cli_drv_get_pname_rsp_msg *)&rsp_hdr->body[0];
	u32 rsp_len = SXE2_DRV_MSG_INFO_SIZE +
		      sizeof(struct sxe2_cli_drv_get_pname_rsp_msg);

	if ((param->resp_len - SXE2_DRV_MSG_INFO_SIZE) <
	    sizeof(struct sxe2_cli_drv_get_pname_rsp_msg)) {
		LOG_ERROR_BDF("params is invalid.\n");
		return -EINVAL;
	}

	memset(dev_name_rsp_msg->netdev_name, 0,
	       sizeof(dev_name_rsp_msg->netdev_name));

	rtnl_lock();
	strscpy(dev_name_rsp_msg->netdev_name,
		adapter->vsi_ctxt.main_vsi->netdev->name, IFNAMSIZ);
	rtnl_unlock();

	rsp_hdr->ack_length = rsp_len;
	return SXE2_CLI_DRV_SUCCESS;
}

STATIC struct sxe2_cmd_handler_info sxe2_cli_drv_cmd_map[] = {
		{SXE2_CLI_CMD_GET_NETDEV_NAME, sxe2_cli_get_netdev_name_handler},
};

STATIC s32 sxe2_cmd_cli_drv_params_chk(struct sxe2_adapter *adapter,
				       struct sxe2_cmd_params *cmd_params,
				       struct sxe2_cmd_trans_info *cmd_ctxt)
{
	s32 ret = SXE2_CLI_DRV_SUCCESS;
	struct drv_msg_info *req_hdr;
	struct sxe2_cmd_trans_info *trans_info = cmd_ctxt;

	if (!cmd_params->resp_data || !cmd_params->req_data) {
		ret = -EINVAL;
		goto end;
	}

	if (cmd_params->req_len < SXE2_DRV_MSG_INFO_SIZE ||
	    cmd_params->resp_len < SXE2_DRV_MSG_INFO_SIZE ||
	    cmd_params->req_len > SXE2_DRV_MSG_MAX_SIZE ||
	    cmd_params->resp_len > SXE2_DRV_MSG_MAX_SIZE) {
		ret = -EINVAL;
		goto end;
	}

	trans_info->req_len = cmd_params->req_len;
	trans_info->resp_len = cmd_params->resp_len;

	trans_info->req_buff = kzalloc(trans_info->req_len, GFP_KERNEL);
	if (!trans_info->req_buff) {
		LOG_ERROR_BDF("malloc failed: size %u.\n", trans_info->req_len);
		ret = -ENOMEM;
		trans_info->req_len = 0;
		trans_info->resp_len = 0;
		goto end;
	}
	if (copy_from_user(trans_info->req_buff, cmd_params->req_data,
			   cmd_params->req_len)) {
		ret = -ENOMEM;
		LOG_ERROR_BDF("req copy failed: size %u.\n", trans_info->req_len);
		goto l_copy_failed;
	}

	trans_info->resp_buff = kzalloc(trans_info->resp_len, GFP_KERNEL);
	if (!trans_info->resp_buff) {
		ret = -ENOMEM;
		trans_info->resp_len = 0;
		LOG_ERROR_BDF("malloc failed: size %u.\n", trans_info->resp_len);
		goto l_copy_failed;
	}

	req_hdr = SXE2_CLI_DRV_REQ_MSG_HDR(trans_info);
	if (req_hdr->magic != SXE2_DRV_MSG_MAGIC_CODE) {
		ret = -EINVAL;
		LOG_ERROR_BDF("magic inval %x. opcode inval %x trace:%lld\n",
			      req_hdr->magic, req_hdr->opcode, req_hdr->trace_id);
		goto l_magic_failed;
	}

	req_hdr->ack_length = cmd_params->resp_len;
	goto end;

l_magic_failed:
	kfree(trans_info->resp_buff);
	trans_info->resp_buff = NULL;
	trans_info->resp_len = 0;

l_copy_failed:
	kfree(trans_info->req_buff);
	trans_info->req_buff = NULL;
	trans_info->req_len = 0;

end:
	return ret;
}

STATIC void sxe2_cmd_cli_fill_rsp_hdr(struct drv_msg_info *rsp_hdr,
				      struct drv_msg_info *req_hdr, s32 rc)
{
	rsp_hdr->magic = SXE2_DRV_MSG_MAGIC_CODE;
	rsp_hdr->error = (u32)rc;
	rsp_hdr->trace_id = req_hdr->trace_id;
}

STATIC s32 sxe2_cmd_free_trans_info(struct sxe2_adapter *adapter,
				    struct sxe2_cmd_trans_info *trans_info,
				    struct sxe2_cmd_params *params)
{
	s32 ret = 0;

	kfree(trans_info->req_buff);
	trans_info->req_buff = NULL;
	trans_info->req_len = 0;

	if (trans_info->resp_buff) {
		if (trans_info->resp_len) {
			if (copy_to_user((void __user *)params->resp_data,
					 trans_info->resp_buff,
					 trans_info->resp_len)) {
				LOG_ERROR_BDF("cmd trace_id=0x%llx copy to user\t"
					      "err\n",
					      params->trace_id);
				ret = -ENOMEM;
			}
		}
		kfree(trans_info->resp_buff);
		trans_info->resp_buff = NULL;
		trans_info->resp_len = 0;
	}

	return ret;
}

s32 sxe2_cmd_cli_drv_exec(struct sxe2_adapter *adapter,
			  struct sxe2_cmd_params *cmd_params)
{
	u32 i;
	sxe2_cb_func cb = NULL;
	s32 rc;
	struct drv_msg_info *rsp_hdr;
	struct drv_msg_info *req_hdr;
	u32 table_cnt = (sizeof(sxe2_cli_drv_cmd_map) /
			 sizeof(struct sxe2_cmd_handler_info));
	struct sxe2_cmd_trans_info trans_info = {0};

	rc = sxe2_cmd_cli_drv_params_chk(adapter, cmd_params, &trans_info);
	if (rc) {
		LOG_INFO_BDF("cli cmd params check failed.(%d)\n", rc);
		goto end;
	}

	req_hdr = SXE2_CLI_DRV_REQ_MSG_HDR((&trans_info));
	for (i = 0; i < table_cnt; i++) {
		if (sxe2_cli_drv_cmd_map[i].opcode == req_hdr->opcode)
			cb = sxe2_cli_drv_cmd_map[i].handler;
	}

	if (cb) {
		rsp_hdr = SXE2_CLI_DRV_RSP_MSG_HDR((&trans_info));
		rc = cb(adapter, &trans_info);
		sxe2_cmd_cli_fill_rsp_hdr(rsp_hdr, req_hdr, rc);

		if (rc)
			LOG_INFO_BDF("cli cmd failed!.(%d)\n", rc);
	} else {
		rc = -EINVAL;
		LOG_INFO_BDF("cli cmd is not support.(%d)\n", rc);
	}

end:
	if (sxe2_cmd_free_trans_info(adapter, &trans_info, cmd_params))
		rc = -ENOMEM;

	return rc;
}
