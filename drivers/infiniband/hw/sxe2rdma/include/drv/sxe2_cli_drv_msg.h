/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_cli_drv_msg.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_CLI_DRV_MSG_H__
#define __SXE2_CLI_DRV_MSG_H__

#include <linux/types.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define SXE2_DRV_MSG_MAX_SIZE              (8192)
#define SXE2_DRV_MSG_MAGIC_CODE            (0x56781234)
#define SXE2_MAX_NETDEV_NAME_SIZE          (128)

#define SXE2_CLI_DRV_SUCCESS               (0)
#define SXE2_MOD_DRV                       (1)
#define SXE2_SUB_MOD_DEV                   (1)

#define MODULE_ID_SHIFT                     (24)
#define SUB_MODULE_ID_SHIFT                 (16)
#define ERROR_INDEX_MASK                    (0xFFFF0000)
#define SXE2_MAKE_ERR_CODE_INDEX(module, sub_module)                                         \
	((((u32)((module) << MODULE_ID_SHIFT)) | ((u32)((sub_module) << SUB_MODULE_ID_SHIFT))) & \
	 ERROR_INDEX_MASK)

enum sxe2_priv_drv_err_code {
	SXE2_ERR_DRV_DEV = SXE2_MAKE_ERR_CODE_INDEX(SXE2_MOD_DRV, SXE2_SUB_MOD_DEV),
	SXE2_ERR_DRV_DEV_PARAMS_INVAL,
	SXE2_ERR_DRV_DEV_NULL_PTR,
	SXE2_ERR_DRV_DEV_NOT_FOUND,
	SXE2_ERR_DRV_DEV_NOT_SUPPORT,
	SXE2_ERR_DRV_DEV_NO_MEM,
	SXE2_ERR_DRV_DEV_FAULT,
	SXE2_ERR_DRV_DEV_MAGIC_INVAL,
};

enum sxe2_cli_drv_cmd_opcode {
	SXE2_CLI_CMD_GET_NETDEV_NAME = 0,
	SXE2_CLI_CMD_MAX = 0xFFFF,
};

struct drv_msg_info {
	u32 magic;
	u32 opcode;
	u32 error;
	u32 timeout;
	u32 runver;
	u32 req_length;
	u32 ack_length;
	u16 hdr_len;
	u8  reserved[2];
	u64 trace_id;
	u8  pad[8];
	u8  body[];
};

struct sxe2_cli_drv_get_pname_rsp_msg {
	char netdev_name[SXE2_MAX_NETDEV_NAME_SIZE];
};

#if defined(__cplusplus)
}
#endif

#endif
