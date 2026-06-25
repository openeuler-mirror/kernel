/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_hw_mt.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#include <asm/byteorder.h>
#include "ossl_knl.h"
#include "hinic5_mt.h"
#include "hinic5_crm.h"
#include "hinic5_hw.h"
#include "comm_defs.h"
#include "mpu_inband_cmd.h"
#include "hinic5_fw_update.h"
#include "hinic5_hw_mt.h"

#define	HINIC5_CMDQ_BUF_MAX_SIZE		2048U
#define DW_WIDTH 4

#define MSG_MAX_IN_SIZE		(2048 * 1024)
#define MSG_MAX_OUT_SIZE	(2048 * 1024)
#define API_CSR_MAX_RD_LEN (4 * 1024 * 1024)

/* completion timeout interval, unit is millisecond */
#define MGMT_MSG_UPDATE_TIMEOUT		200000
#define EMU_TIMEOUT_MULTIPLE        2 // emu scenario timeout multiplier

void hinic5_free_buff_in(void *hwdev, const struct msg_module *nt_msg, void *buf_in)
{
	if (!buf_in)
		return;

	if (nt_msg->module == SEND_TO_NPU)
		hinic5_free_cmd_buf(hwdev, buf_in);
	else
		kfree(buf_in);
}

void hinic5_free_buff_out(void *hwdev, const struct msg_module *nt_msg,
		   void *buf_out)
{
	if (!buf_out)
		return;

	if (nt_msg->module == SEND_TO_NPU &&
	    nt_msg->npu_cmd.direct_resp == 0)
		hinic5_free_cmd_buf(hwdev, buf_out);
	else
		kfree(buf_out);
}

int hinic5_alloc_buff_in(void *hwdev, const struct msg_module *nt_msg,
		  u32 in_size, void **buf_in)
{
	void *msg_buf = NULL;

	if (in_size == 0)
		return 0;

	if (nt_msg->module == SEND_TO_NPU) {
		struct hinic5_cmd_buf *cmd_buf = NULL;

		if (in_size > HINIC5_CMDQ_BUF_MAX_SIZE) {
			pr_err("Cmdq in size(%u) more than 2KB\n", in_size);
			return -ENOMEM;
		}

		cmd_buf = hinic5_alloc_cmd_buf(hwdev);
		if (!cmd_buf) {
			pr_err("Alloc cmdq cmd buffer failed in %s\n",
			       __func__);
			return -ENOMEM;
		}
		msg_buf = cmd_buf->buf;
		*buf_in = (void *)cmd_buf;
		cmd_buf->size = (u16)in_size;
	} else {
		if (in_size > MSG_MAX_IN_SIZE) {
			pr_err("In size(%u) more than 2M\n", in_size);
			return -ENOMEM;
		}
		msg_buf = kzalloc(in_size, GFP_KERNEL);
		*buf_in = msg_buf;
	}
	if (!(*buf_in)) {
		pr_err("Alloc buffer in failed\n");
		return -ENOMEM;
	}

	if (copy_from_user(msg_buf, nt_msg->in_buf, in_size) != 0) {
		pr_err("%s:%d: Copy from user failed\n",
		       __func__, __LINE__);
		hinic5_free_buff_in(hwdev, nt_msg, *buf_in);
		return -EFAULT;
	}

	return 0;
}

int hinic5_alloc_buff_out(void *hwdev, const struct msg_module *nt_msg,
		   u32 out_size, void **buf_out)
{
	if (out_size == 0)
		return 0;

	if (nt_msg->module == SEND_TO_NPU &&
	    nt_msg->npu_cmd.direct_resp == 0) {
		struct hinic5_cmd_buf *cmd_buf = NULL;

		if (out_size > HINIC5_CMDQ_BUF_MAX_SIZE) {
			pr_err("Cmdq out size(%u) more than 2KB\n", out_size);
			return -ENOMEM;
		}

		cmd_buf = hinic5_alloc_cmd_buf(hwdev);
		*buf_out = (void *)cmd_buf;
	} else {
		if (out_size > MSG_MAX_OUT_SIZE) {
			pr_err("out size(%u) more than 2M\n", out_size);
			return -ENOMEM;
		}
		*buf_out = kzalloc(out_size, GFP_KERNEL);
	}
	if (!(*buf_out)) {
		pr_err("Alloc buffer out failed\n");
		return -ENOMEM;
	}

	return 0;
}

int hinic5_copy_buf_out_to_user(const struct msg_module *nt_msg,
			 u32 out_size, void *buf_out)
{
	int ret = 0;
	void *msg_out = NULL;

	if (nt_msg->module == SEND_TO_NPU &&
	    nt_msg->npu_cmd.direct_resp == 0)
		msg_out = ((struct hinic5_cmd_buf *)buf_out)->buf;
	else
		msg_out = buf_out;

	if (copy_to_user(nt_msg->out_buf, msg_out, out_size) != 0)
		ret = -EFAULT;

	return ret;
}

int hinic5_get_func_type(struct hinic5_lld_dev *lld_dev, const void *buf_in, u32 in_size,
		  void *buf_out, const u32 *out_size)
{
	u16 func_type;

	if (*out_size != sizeof(u16) || !buf_out) {
		pr_err("Unexpect out buf size from user :%u, expect: %lu\n",
		       *out_size, sizeof(u16));
		return -EFAULT;
	}

	func_type = hinic5_func_type(hinic5_get_sdk_hwdev_by_lld(lld_dev));

	*(u16 *)buf_out = func_type;
	return 0;
}

int hinic5_get_func_id(struct hinic5_lld_dev *lld_dev, const void *buf_in, u32 in_size,
		void *buf_out, const u32 *out_size)
{
	u16 func_id;

	if (*out_size != sizeof(u16) || !buf_out) {
		pr_err("Unexpect out buf size from user :%u, expect: %lu\n",
		       *out_size, sizeof(u16));
		return -EFAULT;
	}

	func_id = hinic5_global_func_id(hinic5_get_sdk_hwdev_by_lld(lld_dev));
	*(u16 *)buf_out = func_id;

	return 0;
}

int hinic5_get_hw_driver_stats(struct hinic5_lld_dev *lld_dev, const void *buf_in, u32 in_size,
			void *buf_out, const u32 *out_size)
{
	return hinic5_dbg_get_hw_stats(hinic5_get_sdk_hwdev_by_lld(lld_dev),
		buf_out, out_size);
}

int hinic5_clear_hw_driver_stats(struct hinic5_lld_dev *lld_dev, const void *buf_in, u32 in_size,
			  void *buf_out, const u32 *out_size)
{
	u16 size;

	size = hinic5_dbg_clear_hw_stats(hinic5_get_sdk_hwdev_by_lld(lld_dev));
	if (*out_size != size) {
		pr_err("Unexpect out buf size from user :%u, expect: %u\n",
		       *out_size, size);
		return -EFAULT;
	}

	return 0;
}

int hinic5_get_self_test_result(struct hinic5_lld_dev *lld_dev, const void *buf_in, u32 in_size,
			 void *buf_out, const u32 *out_size)
{
	u32 result;

	if (*out_size != sizeof(u32)  || !buf_out) {
		pr_err("Unexpect out buf size from user :%u, expect: %lu\n",
		       *out_size, sizeof(u32));
		return -EFAULT;
	}

	result = hinic5_hinic5_get_self_test_result(hinic5_get_sdk_hwdev_by_lld(lld_dev));
	*(u32 *)buf_out = result;

	return 0;
}

int hinic5_get_chip_faults_stats(struct hinic5_lld_dev *lld_dev, const void *buf_in, u32 in_size,
			  void *buf_out, const u32 *out_size)
{
	u32 offset = 0;
	struct nic_cmd_chip_fault_stats *fault_info = NULL;

	if (!buf_in || !buf_out || *out_size != sizeof(*fault_info) ||
	    in_size != sizeof(*fault_info)) {
		pr_err("Unexpect out buf size from user: %u, expect: %lu\n",
		       *out_size, sizeof(*fault_info));
		return -EFAULT;
	}
	fault_info = (struct nic_cmd_chip_fault_stats *)buf_in;
	offset = fault_info->offset;

	fault_info = (struct nic_cmd_chip_fault_stats *)buf_out;
	hinic5_get_chip_fault_stats(hinic5_get_sdk_hwdev_by_lld(lld_dev),
				    fault_info->chip_fault_stats, offset);

	return 0;
}

static u32 get_mgmt_cmd_default_timeout(void *hwdev, u8 mod, u16 cmd)
{
	u8 hw_type = hinic5_get_hw_type(hwdev);
	u32 timeout = 0; /* default mbox/apichain timeout time */

	if (mod == HINIC5_MOD_COMM &&
	    (cmd == COMM_MGMT_CMD_UPDATE_FW ||
	     cmd == COMM_MGMT_CMD_UPDATE_BIOS ||
	     cmd == COMM_MGMT_CMD_ACTIVE_FW ||
	     cmd == COMM_MGMT_CMD_SWITCH_CFG ||
	     cmd == COMM_MGMT_CMD_HOT_ACTIVE_FW))
		timeout = MGMT_MSG_UPDATE_TIMEOUT;

	if (unlikely(hw_type == HINIC5_HW_TYPE_EMU))
		timeout *= EMU_TIMEOUT_MULTIPLE;

	return timeout;
}

static int api_csr_read(void *hwdev, struct msg_module *nt_msg,
			void *buf_in, u32 in_size, void *buf_out, u32 *out_size)
{
	struct up_log_msg_st *up_log_msg = (struct up_log_msg_st *)buf_in;
	int ret = 0;
	u32 rd_cnt = 0;
	u32 offset = 0;
	u8 node_id;
	u32 i;

	if (!buf_in || !buf_out || in_size < sizeof(*up_log_msg) ||
	    *out_size < up_log_msg->rd_len || up_log_msg->rd_len % DW_WIDTH != 0)
		return -EINVAL;

	node_id = (u8)nt_msg->mpu_cmd.mod;

	rd_cnt = up_log_msg->rd_len / DW_WIDTH;

	for (i = 0; i < rd_cnt; i++) {
		ret = hinic5_api_csr_rd32(hwdev, node_id,
					  up_log_msg->addr + offset,
					  (u32 *)((u8 *)buf_out + offset));
		if (ret != 0) {
			pr_err("Csr rd fail, err: %d, node_id: %u, csr addr: 0x%08x\n",
			       ret, node_id, up_log_msg->addr + offset);
			return ret;
		}
		offset += DW_WIDTH;
	}
	*out_size = up_log_msg->rd_len;

	return ret;
}

static int api_csr_write(void *hwdev, struct msg_module *nt_msg,
			 void *buf_in, u32 in_size, void *buf_out,
			 u32 *out_size)
{
	struct csr_write_st *csr_write_msg = (struct csr_write_st *)buf_in;
	int ret = 0;
	u32 rd_cnt = 0;
	u32 offset = 0;
	u8 node_id;
	u32 i;
	u8 *data = NULL;

	if (!buf_in || in_size < sizeof(*csr_write_msg) || csr_write_msg->rd_len == 0 ||
	    csr_write_msg->rd_len > API_CSR_MAX_RD_LEN || csr_write_msg->rd_len % DW_WIDTH != 0)
		return -EINVAL;

	node_id = (u8)nt_msg->mpu_cmd.mod;

	rd_cnt = csr_write_msg->rd_len / DW_WIDTH;

	data = kzalloc(csr_write_msg->rd_len, GFP_KERNEL);
	if (!data) {
		return -ENOMEM;
	}
	if (copy_from_user(data, (void *)csr_write_msg->data, csr_write_msg->rd_len) != 0) {
		pr_err("Copy information from user failed\n");
		kfree(data);
		return -EFAULT;
	}

	for (i = 0; i < rd_cnt; i++) {
		ret = hinic5_api_csr_wr32(hwdev, node_id,
					  csr_write_msg->addr + offset,
					  *((u32 *)(data + offset)));
		if (ret != 0) {
			pr_err("Csr wr fail, ret: %d, node_id: %u, csr addr: 0x%08x\n",
			       ret, csr_write_msg->addr + offset, node_id);
			kfree(data);
			return ret;
		}
		offset += DW_WIDTH;
	}

	*out_size = 0;
	kfree(data);
	return ret;
}

int hinic5_fw_update_cmd(void *hwdev, struct hinic5_mt_cmd_info *cmd_info)
{
	if (cmd_info->cmd == COMM_MGMT_CMD_UPDATE_FW)
		return hinic5_fw_update_cmd_update(hwdev, cmd_info);

	return hinic5_fw_update_cmd_hot_active(hwdev, cmd_info);
}

int send_mbox_to_mgmt(void *hwdev, u8 mod, u16 cmd, void *buf_in, u16 in_size,
		      void *buf_out, u16 *out_size, u32 timeout)
{
	struct hinic5_mt_cmd_info cmd_info = { 0 };

	if (mod == HINIC5_MOD_COMM && (cmd == COMM_MGMT_CMD_UPDATE_FW ||
	    cmd == COMM_MGMT_CMD_HOT_ACTIVE_FW)) {
		cmd_info.mod = mod;
		cmd_info.cmd = cmd;
		cmd_info.buf_in = buf_in;
		cmd_info.in_size = in_size;
		cmd_info.buf_out = buf_out;
		cmd_info.out_size = out_size;
		cmd_info.timeout = timeout;

		return hinic5_fw_update_cmd(hwdev, &cmd_info);
	}

	return hinic5_msg_to_mgmt_sync(hwdev, mod, cmd, buf_in, in_size,
				       buf_out, out_size, timeout,
				       HINIC5_CHANNEL_DEFAULT);
}

int hinic5_send_to_mpu(void *hwdev, struct msg_module *nt_msg,
		void *buf_in, u32 in_size, void *buf_out, u32 *out_size)
{
	enum mt_api_type api_type;
	enum hinic5_mod_type mod;
	u32 timeout;
	int ret = 0;
	u16 cmd;
	u16 temp_out_size;

	if (*out_size <= UINT16_MAX)
		temp_out_size = (u16)*out_size;
	else
		return -EINVAL;

	api_type = (enum mt_api_type)nt_msg->mpu_cmd.api_type;
	mod = (enum hinic5_mod_type)nt_msg->mpu_cmd.mod;
	cmd = nt_msg->mpu_cmd.cmd;
	timeout = nt_msg->timeout;
	if (timeout == 0)
		timeout = get_mgmt_cmd_default_timeout(hwdev, mod, cmd);

	switch (api_type) {
	case API_TYPE_MBOX:
		ret = send_mbox_to_mgmt(hwdev, mod, cmd, buf_in, (u16)in_size,
					buf_out, &temp_out_size, timeout);
		*out_size = temp_out_size;
		break;
	case API_TYPE_CLP:
		ret = hinic5_clp_to_mgmt(hwdev, mod, cmd, buf_in, (u16)in_size,
					 buf_out, &temp_out_size);
		*out_size = temp_out_size;
		break;
	case API_TYPE_API_CHAIN_BYPASS:
		if (nt_msg->mpu_cmd.cmd == API_CSR_WRITE) {
			ret = api_csr_write(hwdev, nt_msg, buf_in, in_size,
					    buf_out, out_size);
		} else {
			ret = api_csr_read(hwdev, nt_msg, buf_in, in_size,
					   buf_out, out_size);
		}
		break;
	case API_TYPE_API_CHAIN_TO_MPU:
		ret = hinic5_msg_to_mgmt_sync(hwdev, mod, cmd, buf_in, (u16)in_size,
					      buf_out, &temp_out_size, timeout,
					      HINIC5_CHANNEL_DEFAULT);
		*out_size = temp_out_size;
		break;
	default:
		pr_err("Unsupported api_type %u\n", api_type);
		return -EINVAL;
	}

	if (ret != 0)
		pr_err("Message to mgmt cpu return fail, api_type: %d, mod: %d, cmd: %u\n",
		       api_type, mod, cmd);
	return ret;
}

int hinic5_send_to_npu(void *hwdev, const struct msg_module *nt_msg,
		void *buf_in, u32 in_size, void *buf_out, u32 *out_size)
{
	int ret = 0;
	u8 cmd;
	enum hinic5_mod_type mod;
	u32 timeout;

	mod = (enum hinic5_mod_type)nt_msg->npu_cmd.mod;
	cmd = nt_msg->npu_cmd.cmd;
	timeout = nt_msg->timeout;

	if (nt_msg->npu_cmd.direct_resp != 0) {
		ret = hinic5_cmdq_direct_resp(hwdev, mod, cmd,
					      buf_in, buf_out, timeout,
					      HINIC5_CHANNEL_DEFAULT);
		if (ret != 0)
			pr_err("Send direct cmdq failed, err: %d\n", ret);
	} else {
		ret = hinic5_cmdq_detail_resp(hwdev, mod, cmd, buf_in, buf_out,
					      NULL, timeout, HINIC5_CHANNEL_DEFAULT);
		if (ret != 0)
			pr_err("Send detail cmdq failed, err: %d\n", ret);
	}

	return ret;
}

static int sm_rd16(void *hwdev, u32 id, u8 instance,
		   u8 node, struct sm_out_st *buf_out)
{
	u16 val1;
	int ret;

	ret = hinic5_sm_ctr_rd16(hwdev, node, instance, id, &val1);
	if (ret != 0) {
		pr_err("Get sm ctr information (16 bits)failed!\n");
		val1 = 0xffff;
	}

	buf_out->val1 = val1;

	return ret;
}

static int sm_rd32(void *hwdev, u32 id, u8 instance,
		   u8 node, struct sm_out_st *buf_out)
{
	u32 val1;
	int ret;

	ret = hinic5_sm_ctr_rd32(hwdev, node, instance, id, &val1);
	if (ret != 0) {
		pr_err("Get sm ctr information (32 bits)failed!\n");
		val1 = ~0;
	}

	buf_out->val1 = val1;

	return ret;
}

static int sm_rd32_clear(void *hwdev, u32 id, u8 instance,
			 u8 node, struct sm_out_st *buf_out)
{
	u32 val1;
	int ret;

	ret = hinic5_sm_ctr_rd32_clear(hwdev, node, instance, id, &val1);
	if (ret != 0) {
		pr_err("Get sm ctr clear information(32 bits) failed!\n");
		val1 = ~0;
	}

	buf_out->val1 = val1;

	return ret;
}

static int sm_rd64_pair(void *hwdev, u32 id, u8 instance,
			u8 node, struct sm_out_st *buf_out)
{
	u64 val1 = 0, val2 = 0;
	int ret;

	ret = hinic5_sm_ctr_rd64_pair(hwdev, node, instance, id, &val1, &val2);
	if (ret != 0) {
		pr_err("Get sm ctr information (64 bits pair)failed!\n");
		val1 = ~0;
		val2 = ~0;
	}

	buf_out->val1 = val1;
	buf_out->val2 = val2;

	return ret;
}

static int sm_rd64_pair_clear(void *hwdev, u32 id, u8 instance,
			      u8 node, struct sm_out_st *buf_out)
{
	u64 val1 = 0;
	u64 val2 = 0;
	int ret;

	ret = hinic5_sm_ctr_rd64_pair_clear(hwdev, node, instance, id, &val1,
					    &val2);
	if (ret != 0) {
		pr_err("Get sm ctr clear information(64 bits pair) failed!\n");
		val1 = ~0;
		val2 = ~0;
	}

	buf_out->val1 = val1;
	buf_out->val2 = val2;

	return ret;
}

static int sm_rd64(void *hwdev, u32 id, u8 instance,
		   u8 node, struct sm_out_st *buf_out)
{
	u64 val1;
	int ret;

	ret = hinic5_sm_ctr_rd64(hwdev, node, instance, id, &val1);
	if (ret != 0) {
		pr_err("Get sm ctr information (64 bits)failed!\n");
		val1 = ~0;
	}
	buf_out->val1 = val1;

	return ret;
}

static int sm_rd64_clear(void *hwdev, u32 id, u8 instance,
			 u8 node, struct sm_out_st *buf_out)
{
	u64 val1;
	int ret;

	ret = hinic5_sm_ctr_rd64_clear(hwdev, node, instance, id, &val1);
	if (ret != 0) {
		pr_err("Get sm ctr clear information(64 bits) failed!\n");
		val1 = ~0;
	}
	buf_out->val1 = val1;

	return ret;
}

typedef int (*sm_module)(void *hwdev, u32 id, u8 instance,
			 u8 node, struct sm_out_st *buf_out);

struct sm_module_handle {
	enum sm_cmd_type	sm_cmd_name;
	sm_module		sm_func;
};

const struct sm_module_handle hinic5_sm_module_cmd_handle[] = {
	{SM_CTR_RD16,		 sm_rd16},
	{SM_CTR_RD32,		 sm_rd32},
	{SM_CTR_RD64_PAIR,	 sm_rd64_pair},
	{SM_CTR_RD64,		 sm_rd64},
	{SM_CTR_RD32_CLEAR,	 sm_rd32_clear},
	{SM_CTR_RD64_PAIR_CLEAR, sm_rd64_pair_clear},
	{SM_CTR_RD64_CLEAR,	 sm_rd64_clear}
};

int hinic5_send_to_sm(void *hwdev, const struct msg_module *nt_msg,
	       void *buf_in, u32 in_size, void *buf_out, u32 *out_size)
{
	struct sm_in_st *sm_in = buf_in;
	struct sm_out_st *sm_out = buf_out;
	u32 msg_formate = nt_msg->msg_formate;
	int index, num_cmds = ARRAY_LEN(hinic5_sm_module_cmd_handle);
	int ret = 0;

	if (!buf_in || !buf_out || in_size != sizeof(*sm_in) || *out_size != sizeof(*sm_out)) {
		pr_err("Unexpect out buf size :%u, in buf size: %u\n",
		       *out_size, in_size);
		return -EINVAL;
	}

	for (index = 0; index < num_cmds; index++) {
		if (msg_formate != hinic5_sm_module_cmd_handle[index].sm_cmd_name)
			continue;

		ret = hinic5_sm_module_cmd_handle[index].sm_func(hwdev, (u32)sm_in->id,
							  (u8)sm_in->instance,
							  (u8)sm_in->node, sm_out);
		break;
	}

	if (index == num_cmds) {
		pr_err("Can't find callback for %d\n", msg_formate);
		return -EINVAL;
	}

	if (ret != 0)
		pr_err("Get sm information fail, id:%d, instance:%d, node:%d\n",
		       sm_in->id, sm_in->instance, sm_in->node);

	*out_size = sizeof(struct sm_out_st);

	return ret;
}
