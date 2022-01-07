// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt

#include <linux/kernel.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/dcbnl.h>

#include "sphw_crm.h"
#include "spnic_nic_cfg.h"
#include "sphw_hw.h"
#include "spnic_nic.h"
#include "sphw_common.h"

static int spnic_rss_cfg_hash_key(struct spnic_nic_cfg *nic_cfg, u8 opcode, u8 *key)
{
	struct spnic_cmd_rss_hash_key hash_key;
	u16 out_size = sizeof(hash_key);
	int err;

	memset(&hash_key, 0, sizeof(struct spnic_cmd_rss_hash_key));
	hash_key.func_id = sphw_global_func_id(nic_cfg->hwdev);
	hash_key.opcode = opcode;

	if (opcode == SPNIC_CMD_OP_SET)
		memcpy(hash_key.key, key, SPNIC_RSS_KEY_SIZE);

	err = l2nic_msg_to_mgmt_sync(nic_cfg->hwdev,
				     SPNIC_NIC_CMD_CFG_RSS_HASH_KEY,
				     &hash_key, sizeof(hash_key),
				     &hash_key, &out_size);
	if (err || !out_size || hash_key.msg_head.status) {
		nic_err(nic_cfg->dev_hdl, "Failed to %s hash key, err: %d, status: 0x%x, out size: 0x%x\n",
			opcode == SPNIC_CMD_OP_SET ? "set" : "get",
			err, hash_key.msg_head.status, out_size);
		return -EINVAL;
	}

	if (opcode == SPNIC_CMD_OP_GET)
		memcpy(key, hash_key.key, SPNIC_RSS_KEY_SIZE);

	return 0;
}

int spnic_rss_set_hash_key(void *hwdev, const u8 *key)
{
	struct spnic_nic_cfg *nic_cfg = NULL;
	u8 hash_key[SPNIC_RSS_KEY_SIZE];

	if (!hwdev || !key)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	memcpy(hash_key, key, SPNIC_RSS_KEY_SIZE);
	return spnic_rss_cfg_hash_key(nic_cfg, SPNIC_CMD_OP_SET, hash_key);
}

int spnic_rss_get_hash_key(void *hwdev, u8 *key)
{
	struct spnic_nic_cfg *nic_cfg = NULL;

	if (!hwdev || !key)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	return spnic_rss_cfg_hash_key(nic_cfg, SPNIC_CMD_OP_GET, key);
}

int spnic_rss_get_indir_tbl(void *hwdev, u32 *indir_table)
{
	struct sphw_cmd_buf *cmd_buf = NULL;
	struct spnic_nic_cfg *nic_cfg = NULL;
	u16 *indir_tbl = NULL;
	int err, i;

	if (!hwdev || !indir_table)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	cmd_buf = sphw_alloc_cmd_buf(hwdev);
	if (!cmd_buf) {
		nic_err(nic_cfg->dev_hdl, "Failed to allocate cmd_buf.\n");
		return -ENOMEM;
	}

	cmd_buf->size = sizeof(struct nic_rss_indirect_tbl);
	err = sphw_cmdq_detail_resp(hwdev, SPHW_MOD_L2NIC, SPNIC_UCODE_CMD_GET_RSS_INDIR_TABLE,
				    cmd_buf, cmd_buf, NULL, 0, SPHW_CHANNEL_NIC);
	if (err) {
		nic_err(nic_cfg->dev_hdl, "Failed to get rss indir table\n");
		goto get_indir_tbl_failed;
	}

	indir_tbl = (u16 *)cmd_buf->buf;
	for (i = 0; i < SPNIC_RSS_INDIR_SIZE; i++)
		indir_table[i] = *(indir_tbl + i);

get_indir_tbl_failed:
	sphw_free_cmd_buf(hwdev, cmd_buf);

	return err;
}

int spnic_rss_set_indir_tbl(void *hwdev, const u32 *indir_table)
{
	struct nic_rss_indirect_tbl *indir_tbl = NULL;
	struct sphw_cmd_buf *cmd_buf = NULL;
	struct spnic_nic_cfg *nic_cfg = NULL;
	u32 *temp = NULL;
	u32 i, size;
	u64 out_param = 0;
	int err;

	if (!hwdev || !indir_table)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	cmd_buf = sphw_alloc_cmd_buf(hwdev);
	if (!cmd_buf) {
		nic_err(nic_cfg->dev_hdl, "Failed to allocate cmd buf\n");
		return -ENOMEM;
	}

	cmd_buf->size = sizeof(struct nic_rss_indirect_tbl);
	indir_tbl = (struct nic_rss_indirect_tbl *)cmd_buf->buf;
	memset(indir_tbl, 0, sizeof(*indir_tbl));

	for (i = 0; i < SPNIC_RSS_INDIR_SIZE; i++)
		indir_tbl->entry[i] = (u16)(*(indir_table + i));

	size = sizeof(indir_tbl->entry) / sizeof(u32);
	temp = (u32 *)indir_tbl->entry;
	for (i = 0; i < size; i++)
		temp[i] = cpu_to_be32(temp[i]);

	err = sphw_cmdq_direct_resp(hwdev, SPHW_MOD_L2NIC, SPNIC_UCODE_CMD_SET_RSS_INDIR_TABLE,
				    cmd_buf, &out_param, 0, SPHW_CHANNEL_NIC);
	if (err || out_param != 0) {
		nic_err(nic_cfg->dev_hdl, "Failed to set rss indir table\n");
		err = -EFAULT;
	}

	sphw_free_cmd_buf(hwdev, cmd_buf);
	return err;
}

#define SPNIC_RSS_TYPE_VALID_SHIFT 23
#define SPNIC_RSS_TYPE_TCP_IPV6_EXT_SHIFT 24
#define SPNIC_RSS_TYPE_IPV6_EXT_SHIFT 25
#define SPNIC_RSS_TYPE_TCP_IPV6_SHIFT 26
#define SPNIC_RSS_TYPE_IPV6_SHIFT 27
#define SPNIC_RSS_TYPE_TCP_IPV4_SHIFT 28
#define SPNIC_RSS_TYPE_IPV4_SHIFT 29
#define SPNIC_RSS_TYPE_UDP_IPV6_SHIFT 30
#define SPNIC_RSS_TYPE_UDP_IPV4_SHIFT 31
#define SPNIC_RSS_TYPE_SET(val, member) (((u32)(val) & 0x1) << SPNIC_RSS_TYPE_##member##_SHIFT)

#define SPNIC_RSS_TYPE_GET(val, member) (((u32)(val) >> SPNIC_RSS_TYPE_##member##_SHIFT) & 0x1)

int spnic_set_rss_type(void *hwdev, struct nic_rss_type rss_type)
{
	struct nic_rss_context_tbl *ctx_tbl = NULL;
	struct sphw_cmd_buf *cmd_buf = NULL;
	struct spnic_nic_cfg *nic_cfg = NULL;
	u32 ctx = 0;
	u64 out_param = 0;
	int err;

	if (!hwdev)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	cmd_buf = sphw_alloc_cmd_buf(hwdev);
	if (!cmd_buf) {
		nic_err(nic_cfg->dev_hdl, "Failed to allocate cmd buf\n");
		return -ENOMEM;
	}

	ctx |= SPNIC_RSS_TYPE_SET(1, VALID) |
	       SPNIC_RSS_TYPE_SET(rss_type.ipv4, IPV4) |
	       SPNIC_RSS_TYPE_SET(rss_type.ipv6, IPV6) |
	       SPNIC_RSS_TYPE_SET(rss_type.ipv6_ext, IPV6_EXT) |
	       SPNIC_RSS_TYPE_SET(rss_type.tcp_ipv4, TCP_IPV4) |
	       SPNIC_RSS_TYPE_SET(rss_type.tcp_ipv6, TCP_IPV6) |
	       SPNIC_RSS_TYPE_SET(rss_type.tcp_ipv6_ext, TCP_IPV6_EXT) |
	       SPNIC_RSS_TYPE_SET(rss_type.udp_ipv4, UDP_IPV4) |
	       SPNIC_RSS_TYPE_SET(rss_type.udp_ipv6, UDP_IPV6);

	cmd_buf->size = sizeof(struct nic_rss_context_tbl);
	ctx_tbl = (struct nic_rss_context_tbl *)cmd_buf->buf;
	memset(ctx_tbl, 0, sizeof(*ctx_tbl));
	ctx_tbl->ctx = cpu_to_be32(ctx);

	/* cfg the rss context table by command queue */
	err = sphw_cmdq_direct_resp(hwdev, SPHW_MOD_L2NIC, SPNIC_UCODE_CMD_SET_RSS_CONTEXT_TABLE,
				    cmd_buf, &out_param, 0, SPHW_CHANNEL_NIC);

	sphw_free_cmd_buf(hwdev, cmd_buf);

	if (err || out_param != 0) {
		nic_err(nic_cfg->dev_hdl, "Failed to set rss context table, err: %d\n",
			err);
		return -EFAULT;
	}

	return 0;
}

int spnic_get_rss_type(void *hwdev, struct nic_rss_type *rss_type)
{
	struct spnic_rss_context_table ctx_tbl;
	u16 out_size = sizeof(ctx_tbl);
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	if (!hwdev || !rss_type)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);

	memset(&ctx_tbl, 0, sizeof(struct spnic_rss_context_table));
	ctx_tbl.func_id = sphw_global_func_id(hwdev);

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_NIC_CMD_GET_RSS_CTX_TBL,
				     &ctx_tbl, sizeof(ctx_tbl),
				     &ctx_tbl, &out_size);
	if (err || !out_size || ctx_tbl.msg_head.status) {
		nic_err(nic_cfg->dev_hdl, "Failed to get hash type, err: %d, status: 0x%x, out size: 0x%x\n",
			err, ctx_tbl.msg_head.status, out_size);
			return -EINVAL;
	}

	rss_type->ipv4	       = SPNIC_RSS_TYPE_GET(ctx_tbl.context, IPV4);
	rss_type->ipv6	       = SPNIC_RSS_TYPE_GET(ctx_tbl.context, IPV6);
	rss_type->ipv6_ext     = SPNIC_RSS_TYPE_GET(ctx_tbl.context, IPV6_EXT);
	rss_type->tcp_ipv4     = SPNIC_RSS_TYPE_GET(ctx_tbl.context, TCP_IPV4);
	rss_type->tcp_ipv6     = SPNIC_RSS_TYPE_GET(ctx_tbl.context, TCP_IPV6);
	rss_type->tcp_ipv6_ext = SPNIC_RSS_TYPE_GET(ctx_tbl.context, TCP_IPV6_EXT);
	rss_type->udp_ipv4     = SPNIC_RSS_TYPE_GET(ctx_tbl.context, UDP_IPV4);
	rss_type->udp_ipv6     = SPNIC_RSS_TYPE_GET(ctx_tbl.context, UDP_IPV6);

	return 0;
}

static int spnic_rss_cfg_hash_engine(struct spnic_nic_cfg *nic_cfg, u8 opcode, u8 *type)
{
	struct spnic_cmd_rss_engine_type hash_type;
	u16 out_size = sizeof(hash_type);
	int err;

	memset(&hash_type, 0, sizeof(struct spnic_cmd_rss_engine_type));

	hash_type.func_id = sphw_global_func_id(nic_cfg->hwdev);
	hash_type.opcode = opcode;

	if (opcode == SPNIC_CMD_OP_SET)
		hash_type.hash_engine = *type;

	err = l2nic_msg_to_mgmt_sync(nic_cfg->hwdev, SPNIC_NIC_CMD_CFG_RSS_HASH_ENGINE,
				     &hash_type, sizeof(hash_type),
				     &hash_type, &out_size);
	if (err || !out_size || hash_type.msg_head.status) {
		nic_err(nic_cfg->dev_hdl, "Failed to %s hash engine, err: %d, status: 0x%x, out size: 0x%x\n",
			opcode == SPNIC_CMD_OP_SET ? "set" : "get",
			err, hash_type.msg_head.status, out_size);
		return -EIO;
	}

	if (opcode == SPNIC_CMD_OP_GET)
		*type = hash_type.hash_engine;

	return 0;
}

int spnic_rss_set_hash_engine(void *hwdev, u8 type)
{
	struct spnic_nic_cfg *nic_cfg = NULL;

	if (!hwdev)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	return spnic_rss_cfg_hash_engine(nic_cfg, SPNIC_CMD_OP_SET, &type);
}

int spnic_rss_get_hash_engine(void *hwdev, u8 *type)
{
	struct spnic_nic_cfg *nic_cfg = NULL;

	if (!hwdev || !type)
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	return spnic_rss_cfg_hash_engine(nic_cfg, SPNIC_CMD_OP_GET, type);
}

int spnic_rss_cfg(void *hwdev, u8 rss_en, u8 tc_num, u8 *prio_tc, u16 num_qps)
{
	struct spnic_cmd_rss_config rss_cfg;
	u16 out_size = sizeof(rss_cfg);
	struct spnic_nic_cfg *nic_cfg = NULL;
	int err;

	/* micro code required: number of TC should be power of 2 */
	if (!hwdev || !prio_tc || (tc_num & (tc_num - 1)))
		return -EINVAL;

	nic_cfg = sphw_get_service_adapter(hwdev, SERVICE_T_NIC);
	memset(&rss_cfg, 0, sizeof(struct spnic_cmd_rss_config));
	rss_cfg.func_id = sphw_global_func_id(hwdev);
	rss_cfg.rss_en = rss_en;
	rss_cfg.rq_priority_number = tc_num ? (u8)ilog2(tc_num) : 0;
	rss_cfg.num_qps = num_qps;

	memcpy(rss_cfg.prio_tc, prio_tc, SPNIC_DCB_UP_MAX);
	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_NIC_CMD_RSS_CFG,
				     &rss_cfg, sizeof(rss_cfg),
				     &rss_cfg, &out_size);
	if (err || !out_size || rss_cfg.msg_head.status) {
		nic_err(nic_cfg->dev_hdl, "Failed to set rss cfg, err: %d, status: 0x%x, out size: 0x%x\n",
			err, rss_cfg.msg_head.status, out_size);
		return -EINVAL;
	}

	return 0;
}
