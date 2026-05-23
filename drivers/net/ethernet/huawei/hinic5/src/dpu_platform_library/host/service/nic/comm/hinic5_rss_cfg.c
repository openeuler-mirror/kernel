/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_rss_cfg.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt

#include <linux/kernel.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/dcbnl.h>

#include "comm_defs.h"
#include "ossl_knl.h"
#include "hinic5_crm.h"
#include "hinic5_nic_cfg.h"
#include "nic_mpu_cmd.h"
#include "nic_npu_cmd.h"
#include "hinic5_hw.h"
#include "hinic5_nic.h"
#include "hinic5_nic_cmdq.h"
#include "hinic5_common.h"

static int hinic5_rss_cfg_hash_key(struct hinic5_nic_io *nic_io, u8 opcode,
				   u8 *key, u16 key_size)
{
	struct hinic5_cmd_rss_hash_key hash_key;
	u16 out_size = sizeof(hash_key);
	int err;

	memset(&hash_key, 0, out_size);
	hash_key.func_id = hinic5_global_func_id(nic_io->hwdev);
	hash_key.opcode = opcode;

	if (opcode == HINIC5_CMD_OP_SET)
		memcpy(hash_key.key, key, key_size);

	err = hinic5_l2nic_msg_to_mgmt_sync(nic_io->hwdev,
				     HINIC5_NIC_CMD_CFG_RSS_HASH_KEY,
				     &hash_key, sizeof(hash_key),
				     &hash_key, &out_size);
	if (err != 0 || out_size == 0 || hash_key.msg_head.status != 0) {
		nic_err(nic_io->dev_hdl, "Failed to %s hash key, err: %d, status: 0x%x, out size: 0x%x\n",
			opcode == HINIC5_CMD_OP_SET ? "set" : "get",
			err, hash_key.msg_head.status, out_size);
		return -EINVAL;
	}

	if (opcode == HINIC5_CMD_OP_GET)
		memcpy(key, hash_key.key, NIC_RSS_KEY_SIZE);

	return 0;
}

int hinic5_rss_set_hash_key(void *hwdev, const u8 *key)
{
	struct hinic5_nic_io *nic_io = NULL;
	u8 hash_key[NIC_RSS_KEY_SIZE];

	if (!hwdev || !key)
		return -EINVAL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	memcpy(hash_key, key, NIC_RSS_KEY_SIZE);
	return hinic5_rss_cfg_hash_key(nic_io, HINIC5_CMD_OP_SET, hash_key, NIC_RSS_KEY_SIZE);
}

int hinic5_rss_get_hash_key(void *hwdev, u8 *key)
{
	struct hinic5_nic_io *nic_io = NULL;

	if (!hwdev || !key)
		return -EINVAL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	return hinic5_rss_cfg_hash_key(nic_io, HINIC5_CMD_OP_GET, key, NIC_RSS_KEY_SIZE);
}

int hinic5_rss_set_indir_tbl(void *hwdev, const u32 *indir_table)
{
	struct hinic5_cmd_buf *cmd_buf = NULL;
	struct hinic5_nic_io *nic_io = NULL;
	u8 cmd;
	u64 out_param = 0;
	int err;

	if (!hwdev || !indir_table)
		return -EINVAL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	cmd_buf = hinic5_alloc_cmd_buf(hwdev);
	if (!cmd_buf) {
		nic_err(nic_io->dev_hdl, "Failed to allocate cmd buf\n");
		return -ENOMEM;
	}

	cmd = nic_io->cmdq_ops->prepare_cmd_buf_set_rss_indir_table(nic_io, indir_table, cmd_buf);

	err = hinic5_cmdq_direct_resp(hwdev, HINIC5_MOD_L2NIC,
				      cmd, cmd_buf, &out_param, 0, HINIC5_CHANNEL_NIC);
	if (err != 0 || out_param != 0) {
		nic_err(nic_io->dev_hdl, "Failed to set rss indir table\n");
		err = -EFAULT;
	}

	hinic5_free_cmd_buf(hwdev, cmd_buf);
	return err;
}

static int hinic5_cmdq_set_rss_type(void *hwdev, struct nic_rss_type rss_type)
{
	struct nic_rss_context_tbl *ctx_tbl = NULL;
	struct hinic5_cmd_buf *cmd_buf = NULL;
	struct hinic5_nic_io *nic_io = NULL;
	u32 ctx = 0;
	u64 out_param = 0;
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;
	cmd_buf = hinic5_alloc_cmd_buf(hwdev);
	if (!cmd_buf) {
		nic_err(nic_io->dev_hdl, "Failed to allocate cmd buf\n");
		return -ENOMEM;
	}

	ctx |= HINIC5_RSS_TYPE_SET(1, VALID) |
	       HINIC5_RSS_TYPE_SET(rss_type.ipv4, IPV4) |
	       HINIC5_RSS_TYPE_SET(rss_type.ipv6, IPV6) |
	       HINIC5_RSS_TYPE_SET(rss_type.ipv6_ext, IPV6_EXT) |
	       HINIC5_RSS_TYPE_SET(rss_type.tcp_ipv4, TCP_IPV4) |
	       HINIC5_RSS_TYPE_SET(rss_type.tcp_ipv6, TCP_IPV6) |
	       HINIC5_RSS_TYPE_SET(rss_type.tcp_ipv6_ext, TCP_IPV6_EXT) |
	       HINIC5_RSS_TYPE_SET(rss_type.udp_ipv4, UDP_IPV4) |
	       HINIC5_RSS_TYPE_SET(rss_type.udp_ipv6, UDP_IPV6);

	cmd_buf->size = sizeof(struct nic_rss_context_tbl);
	ctx_tbl = (struct nic_rss_context_tbl *)cmd_buf->buf;
	memset(ctx_tbl, 0, sizeof(*ctx_tbl));
	ctx_tbl->ctx = cpu_to_be32(ctx);

	/* cfg the rss context table by command queue */
	err = hinic5_cmdq_direct_resp(hwdev, HINIC5_MOD_L2NIC,
				      HINIC5_UCODE_CMD_SET_RSS_CONTEXT_TABLE,
				      cmd_buf, &out_param, 0,
				      HINIC5_CHANNEL_NIC);

	hinic5_free_cmd_buf(hwdev, cmd_buf);

	if (err != 0 || out_param != 0) {
		nic_err(nic_io->dev_hdl, "cmdq set  set rss context table failed, err: %d\n",
			err);
		return -EFAULT;
	}

	return 0;
}

static int hinic5_mgmt_set_rss_type(void *hwdev, struct nic_rss_type rss_type)
{
	struct hinic5_nic_io *nic_io = NULL;
	struct hinic5_rss_context_table ctx_tbl;
	u32 ctx = 0;
	u16 out_size = sizeof(ctx_tbl);
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;
	memset(&ctx_tbl, 0, sizeof(ctx_tbl));
	ctx_tbl.func_id = hinic5_global_func_id(hwdev);
	ctx |= HINIC5_RSS_TYPE_SET(1, VALID) |
	       HINIC5_RSS_TYPE_SET(rss_type.ipv4, IPV4) |
	       HINIC5_RSS_TYPE_SET(rss_type.ipv6, IPV6) |
	       HINIC5_RSS_TYPE_SET(rss_type.ipv6_ext, IPV6_EXT) |
	       HINIC5_RSS_TYPE_SET(rss_type.tcp_ipv4, TCP_IPV4) |
	       HINIC5_RSS_TYPE_SET(rss_type.tcp_ipv6, TCP_IPV6) |
	       HINIC5_RSS_TYPE_SET(rss_type.tcp_ipv6_ext, TCP_IPV6_EXT) |
	       HINIC5_RSS_TYPE_SET(rss_type.udp_ipv4, UDP_IPV4) |
	       HINIC5_RSS_TYPE_SET(rss_type.udp_ipv6, UDP_IPV6);
	ctx_tbl.context = ctx;
	err = hinic5_l2nic_msg_to_mgmt_sync(hwdev, HINIC5_NIC_CMD_SET_RSS_CTX_TBL_INTO_FUNC,
				     &ctx_tbl, sizeof(ctx_tbl),
				     &ctx_tbl, &out_size);

	if (ctx_tbl.msg_head.status == HINIC5_MGMT_CMD_UNSUPPORTED) {
		return HINIC5_MGMT_CMD_UNSUPPORTED;
	} else if ((err != 0) || (out_size == 0) || (ctx_tbl.msg_head.status != 0)) {
		nic_err(nic_io->dev_hdl, "mgmt Failed to set rss context offload, err: %d, status: 0x%x, out size: 0x%x\n",
			err, ctx_tbl.msg_head.status, out_size);
		return -EINVAL;
	}

	return 0;
}

int hinic5_set_rss_type(void *hwdev, struct nic_rss_type rss_type)
{
	int err;

	err = hinic5_mgmt_set_rss_type(hwdev, rss_type);
	if (err == HINIC5_MGMT_CMD_UNSUPPORTED)
		err = hinic5_cmdq_set_rss_type(hwdev, rss_type);

	return err;
}

int hinic5_get_rss_type(void *hwdev, struct nic_rss_type *rss_type)
{
	struct hinic5_rss_context_table ctx_tbl;
	u16 out_size = sizeof(ctx_tbl);
	struct hinic5_nic_io *nic_io = NULL;
	int err;

	if (!hwdev || !rss_type)
		return -EINVAL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	memset(&ctx_tbl, 0, out_size);
	ctx_tbl.func_id = hinic5_global_func_id(hwdev);

	err = hinic5_l2nic_msg_to_mgmt_sync(hwdev, HINIC5_NIC_CMD_GET_RSS_CTX_TBL,
				     &ctx_tbl, sizeof(ctx_tbl),
				     &ctx_tbl, &out_size);
	if (err != 0 || out_size == 0 || ctx_tbl.msg_head.status != 0) {
		nic_err(nic_io->dev_hdl, "Failed to get hash type, err: %d, status: 0x%x, out size: 0x%x\n",
			err, ctx_tbl.msg_head.status, out_size);
			return -EINVAL;
	}

	rss_type->ipv4	       = HINIC5_RSS_TYPE_GET(ctx_tbl.context, IPV4);
	rss_type->ipv6	       = HINIC5_RSS_TYPE_GET(ctx_tbl.context, IPV6);
	rss_type->ipv6_ext     = HINIC5_RSS_TYPE_GET(ctx_tbl.context, IPV6_EXT);
	rss_type->tcp_ipv4     = HINIC5_RSS_TYPE_GET(ctx_tbl.context, TCP_IPV4);
	rss_type->tcp_ipv6     = HINIC5_RSS_TYPE_GET(ctx_tbl.context, TCP_IPV6);
	rss_type->tcp_ipv6_ext = HINIC5_RSS_TYPE_GET(ctx_tbl.context,
						     TCP_IPV6_EXT);
	rss_type->udp_ipv4     = HINIC5_RSS_TYPE_GET(ctx_tbl.context, UDP_IPV4);
	rss_type->udp_ipv6     = HINIC5_RSS_TYPE_GET(ctx_tbl.context, UDP_IPV6);

	return 0;
}

static int hinic5_rss_cfg_hash_engine(struct hinic5_nic_io *nic_io, u8 opcode,
				      u8 *type)
{
	struct hinic5_cmd_rss_engine_type hash_type;
	u16 out_size = sizeof(hash_type);
	int err;

	if (!nic_io)
		return -EINVAL;

	memset(&hash_type, 0, out_size);

	hash_type.func_id = hinic5_global_func_id(nic_io->hwdev);
	hash_type.opcode = opcode;

	if (opcode == HINIC5_CMD_OP_SET)
		hash_type.hash_engine = *type;

	err = hinic5_l2nic_msg_to_mgmt_sync(nic_io->hwdev,
				     HINIC5_NIC_CMD_CFG_RSS_HASH_ENGINE,
				     &hash_type, sizeof(hash_type),
				     &hash_type, &out_size);
	if (err != 0 || out_size == 0 || hash_type.msg_head.status != 0) {
		nic_err(nic_io->dev_hdl, "Failed to %s hash engine, err: %d, status: 0x%x, out size: 0x%x\n",
			opcode == HINIC5_CMD_OP_SET ? "set" : "get",
			err, hash_type.msg_head.status, out_size);
		return -EIO;
	}

	if (opcode == HINIC5_CMD_OP_GET)
		*type = hash_type.hash_engine;

	return 0;
}

int hinic5_rss_set_hash_engine(void *hwdev, u8 type)
{
	struct hinic5_nic_io *nic_io = NULL;

	if (!hwdev)
		return -EINVAL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;
	return hinic5_rss_cfg_hash_engine(nic_io, HINIC5_CMD_OP_SET, &type);
}

int hinic5_rss_get_hash_engine(void *hwdev, u8 *type)
{
	struct hinic5_nic_io *nic_io = NULL;

	if (!hwdev || !type)
		return -EINVAL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;
	return hinic5_rss_cfg_hash_engine(nic_io, HINIC5_CMD_OP_GET, type);
}

int hinic5_rss_cfg(void *hwdev, u8 rss_en, u8 cos_num, u8 *prio_tc, u16 num_qps)
{
	struct hinic5_cmd_rss_config rss_cfg;
	u16 out_size = sizeof(rss_cfg);
	struct hinic5_nic_io *nic_io = NULL;
	int err;

	/* micro code required: number of TC should be power of 2 */
	if (!hwdev || !prio_tc || ((cos_num & (cos_num - 1)) != 0))
		return -EINVAL;

	nic_io = hinic5_get_service_adapter(hwdev, SERVICE_T_NIC);
	if (!nic_io)
		return -EINVAL;

	memset(&rss_cfg, 0, out_size);
	rss_cfg.func_id = hinic5_global_func_id(hwdev);
	rss_cfg.rss_en = rss_en;
	rss_cfg.rq_priority_number = (cos_num != 0) ? (u8)ilog2(cos_num) : 0;
	rss_cfg.num_qps = num_qps;

	memcpy(rss_cfg.prio_tc, prio_tc, NIC_DCB_UP_MAX);

	err = hinic5_l2nic_msg_to_mgmt_sync(hwdev, HINIC5_NIC_CMD_RSS_CFG,
				     &rss_cfg, sizeof(rss_cfg),
				     &rss_cfg, &out_size);
	if (err != 0 || out_size == 0 || rss_cfg.msg_head.status != 0) {
		nic_err(nic_io->dev_hdl, "Failed to set rss cfg, err: %d, status: 0x%x, out size: 0x%x\n",
			err, rss_cfg.msg_head.status, out_size);
		return -EINVAL;
	}

	return 0;
}

