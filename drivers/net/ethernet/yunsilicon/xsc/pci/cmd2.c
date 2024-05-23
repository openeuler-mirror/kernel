// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifdef HAVE_GENERIC_KMAP_TYPE
#include <asm-generic/kmap_types.h>
#endif
#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/kthread.h>
#include <linux/io-mapping.h>
#include "common/driver.h"
#include <linux/debugfs.h>
#include "common/xsc_hsi.h"
#include "common/xsc_core.h"
#include "tmp_cmdq_defines.h"

enum {
	CMD_IF_REV = 3,
};

enum {
	CMD_MODE_POLLING,
	CMD_MODE_EVENTS
};

enum {
	NUM_LONG_LISTS	  = 2,
	NUM_MED_LISTS	  = 64,
	LONG_LIST_SIZE	  = (2ULL * 1024 * 1024 * 1024 / PAGE_SIZE) * 8 + 16 +
				XSC_CMD_DATA_BLOCK_SIZE,
	MED_LIST_SIZE	  = 16 + XSC_CMD_DATA_BLOCK_SIZE,
};

enum {
	XSC_CMD_DELIVERY_STAT_OK			= 0x0,
	XSC_CMD_DELIVERY_STAT_SIGNAT_ERR		= 0x1,
	XSC_CMD_DELIVERY_STAT_TOK_ERR			= 0x2,
	XSC_CMD_DELIVERY_STAT_BAD_BLK_NUM_ERR		= 0x3,
	XSC_CMD_DELIVERY_STAT_OUT_PTR_ALIGN_ERR	= 0x4,
	XSC_CMD_DELIVERY_STAT_IN_PTR_ALIGN_ERR		= 0x5,
	XSC_CMD_DELIVERY_STAT_FW_ERR			= 0x6,
	XSC_CMD_DELIVERY_STAT_IN_LENGTH_ERR		= 0x7,
	XSC_CMD_DELIVERY_STAT_OUT_LENGTH_ERR		= 0x8,
	XSC_CMD_DELIVERY_STAT_RES_FLD_NOT_CLR_ERR	= 0x9,
	XSC_CMD_DELIVERY_STAT_CMD_DESCR_ERR		= 0x10,
};

enum {
	XSC_CMD_STAT_OK			= 0x0,
	XSC_CMD_STAT_INT_ERR			= 0x1,
	XSC_CMD_STAT_BAD_OP_ERR		= 0x2,
	XSC_CMD_STAT_BAD_PARAM_ERR		= 0x3,
	XSC_CMD_STAT_BAD_SYS_STATE_ERR		= 0x4,
	XSC_CMD_STAT_BAD_RES_ERR		= 0x5,
	XSC_CMD_STAT_RES_BUSY			= 0x6,
	XSC_CMD_STAT_LIM_ERR			= 0x8,
	XSC_CMD_STAT_BAD_RES_STATE_ERR		= 0x9,
	XSC_CMD_STAT_IX_ERR			= 0xa,
	XSC_CMD_STAT_NO_RES_ERR		= 0xf,
	XSC_CMD_STAT_BAD_INP_LEN_ERR		= 0x50,
	XSC_CMD_STAT_BAD_OUTP_LEN_ERR		= 0x51,
	XSC_CMD_STAT_BAD_QP_STATE_ERR		= 0x10,
	XSC_CMD_STAT_BAD_PKT_ERR		= 0x30,
	XSC_CMD_STAT_BAD_SIZE_OUTS_CQES_ERR	= 0x40,
};

static struct xsc_cmd_work_ent *alloc_cmd(struct xsc_cmd *cmd,
					  struct xsc_cmd_msg *in,
					  struct xsc_rsp_msg *out)
{
	struct xsc_cmd_work_ent *ent;

	ent = kzalloc(sizeof(*ent), GFP_KERNEL);
	if (!ent)
		return ERR_PTR(-ENOMEM);

	ent->in		= in;
	ent->out	= out;
	ent->cmd	= cmd;

	return ent;
}

static u8 alloc_token(struct xsc_cmd *cmd)
{
	u8 token;

	spin_lock(&cmd->token_lock);
	token = cmd->token++ % 255 + 1;
	spin_unlock(&cmd->token_lock);

	return token;
}

static int alloc_ent(struct xsc_cmd *cmd)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&cmd->alloc_lock, flags);
	ret = find_first_bit(&cmd->bitmask, cmd->max_reg_cmds);
	if (ret < cmd->max_reg_cmds)
		clear_bit(ret, &cmd->bitmask);
	spin_unlock_irqrestore(&cmd->alloc_lock, flags);

	return ret < cmd->max_reg_cmds ? ret : -ENOMEM;
}

static void free_ent(struct xsc_cmd *cmd, int idx)
{
	unsigned long flags;

	spin_lock_irqsave(&cmd->alloc_lock, flags);
	set_bit(idx, &cmd->bitmask);
	spin_unlock_irqrestore(&cmd->alloc_lock, flags);
}

static struct xsc_cmd_layout *get_inst(struct xsc_cmd *cmd, int idx)
{
	return cmd->cmd_buf + (idx << cmd->log_stride);
}

static struct xsc_rsp_layout *get_cq_inst(struct xsc_cmd *cmd, int idx)
{
	return cmd->cq_buf + (idx << cmd->log_stride);
}

static u8 xor8_buf(void *buf, int len)
{
	u8 *ptr = buf;
	u8 sum = 0;
	int i;

	for (i = 0; i < len; i++)
		sum ^= ptr[i];

	return sum;
}

static int verify_block_sig(struct xsc_cmd_prot_block *block)
{
	if (xor8_buf(block->rsvd0, sizeof(*block) - sizeof(block->data) - 1) != 0xff)
		return -EINVAL;

	if (xor8_buf(block, sizeof(*block)) != 0xff)
		return -EINVAL;

	return 0;
}

static void calc_block_sig(struct xsc_cmd_prot_block *block, u8 token)
{
	block->token = token;
	block->ctrl_sig = ~xor8_buf(block->rsvd0, sizeof(*block) - sizeof(block->data) - 2);
	block->sig = ~xor8_buf(block, sizeof(*block) - 1);
}

static void calc_chain_sig(struct xsc_cmd_mailbox *head, u8 token)
{
	struct xsc_cmd_mailbox *next = head;

	while (next) {
		calc_block_sig(next->buf, token);
		next = next->next;
	}
}

static void set_signature(struct xsc_cmd_work_ent *ent)
{
	ent->lay->sig = ~xor8_buf(ent->lay, sizeof(*ent->lay));
	calc_chain_sig(ent->in->next, ent->token);
	calc_chain_sig(ent->out->next, ent->token);
}

static void free_cmd(struct xsc_cmd_work_ent *ent)
{
	kfree(ent);
}

static int verify_signature(struct xsc_cmd_work_ent *ent)
{
	struct xsc_cmd_mailbox *next = ent->out->next;
	int err;
	u8 sig;

	sig = xor8_buf(ent->rsp_lay, sizeof(*ent->rsp_lay));
	if (sig != 0xff)
		return -EINVAL;

	while (next) {
		err = verify_block_sig(next->buf);
		if (err)
			return err;

		next = next->next;
	}

	return 0;
}

static void dump_buf(void *buf, int size, int offset)
{
	__be32 *p = buf;
	int i;

	for (i = 0; i < size; i += 16) {
		xsc_pr_debug("%03x: %08x %08x %08x %08x\n", offset, be32_to_cpu(p[0]),
			     be32_to_cpu(p[1]), be32_to_cpu(p[2]), be32_to_cpu(p[3]));
		p += 4;
		offset += 16;
	}
	xsc_pr_debug("\n");
}

const char *xsc_command_str(int command)
{
	switch (command) {
	case XSC_CMD_OP_QUERY_HCA_CAP:
		return "QUERY_HCA_CAP";

	case XSC_CMD_OP_ENABLE_HCA:
		return "ENABLE_HCA";

	case XSC_CMD_OP_DISABLE_HCA:
		return "DISABLE_HCA";

	case XSC_CMD_OP_MODIFY_HCA:
		return "MODIFY_HCA";

	case XSC_CMD_OP_QUERY_CMDQ_VERSION:
		return "QUERY_CMDQ_VERSION";

	case XSC_CMD_OP_QUERY_MSIX_TBL_INFO:
		return "QUERY_MSIX_TBL_INFO";

	case XSC_CMD_OP_FUNCTION_RESET:
		return "FUNCTION_RESET";

	case XSC_CMD_OP_DUMMY:
		return "DUMMY_CMD";

	case XSC_CMD_OP_SET_DEBUG_INFO:
		return "SET_DEBUG_INFO";

	case XSC_CMD_OP_CREATE_MKEY:
		return "CREATE_MKEY";

	case XSC_CMD_OP_QUERY_MKEY:
		return "QUERY_MKEY";

	case XSC_CMD_OP_DESTROY_MKEY:
		return "DESTROY_MKEY";

	case XSC_CMD_OP_QUERY_SPECIAL_CONTEXTS:
		return "QUERY_SPECIAL_CONTEXTS";

	case XSC_CMD_OP_SET_MPT:
		return "SET_MPT";

	case XSC_CMD_OP_SET_MTT:
		return "SET_MTT";

	case XSC_CMD_OP_CREATE_EQ:
		return "CREATE_EQ";

	case XSC_CMD_OP_DESTROY_EQ:
		return "DESTROY_EQ";

	case XSC_CMD_OP_QUERY_EQ:
		return "QUERY_EQ";

	case XSC_CMD_OP_CREATE_CQ:
		return "CREATE_CQ";

	case XSC_CMD_OP_DESTROY_CQ:
		return "DESTROY_CQ";

	case XSC_CMD_OP_QUERY_CQ:
		return "QUERY_CQ";

	case XSC_CMD_OP_MODIFY_CQ:
		return "MODIFY_CQ";

	case XSC_CMD_OP_CREATE_QP:
		return "CREATE_QP";

	case XSC_CMD_OP_DESTROY_QP:
		return "DESTROY_QP";

	case XSC_CMD_OP_RST2INIT_QP:
		return "RST2INIT_QP";

	case XSC_CMD_OP_INIT2RTR_QP:
		return "INIT2RTR_QP";

	case XSC_CMD_OP_RTR2RTS_QP:
		return "RTR2RTS_QP";

	case XSC_CMD_OP_RTS2RTS_QP:
		return "RTS2RTS_QP";

	case XSC_CMD_OP_SQERR2RTS_QP:
		return "SQERR2RTS_QP";

	case XSC_CMD_OP_2ERR_QP:
		return "2ERR_QP";

	case XSC_CMD_OP_RTS2SQD_QP:
		return "RTS2SQD_QP";

	case XSC_CMD_OP_SQD2RTS_QP:
		return "SQD2RTS_QP";

	case XSC_CMD_OP_2RST_QP:
		return "2RST_QP";

	case XSC_CMD_OP_QUERY_QP:
		return "QUERY_QP";

	case XSC_CMD_OP_CONF_SQP:
		return "CONF_SQP";

	case XSC_CMD_OP_MAD_IFC:
		return "MAD_IFC";

	case XSC_CMD_OP_INIT2INIT_QP:
		return "INIT2INIT_QP";

	case XSC_CMD_OP_SQD2SQD_QP:
		return "SQD2SQD_QP";

	case XSC_CMD_OP_QUERY_QP_FLUSH_STATUS:
		return "QUERY_QP_FLUSH_STATUS";

	case XSC_CMD_OP_ALLOC_PD:
		return "ALLOC_PD";

	case XSC_CMD_OP_DEALLOC_PD:
		return "DEALLOC_PD";

	case XSC_CMD_OP_ACCESS_REG:
		return "ACCESS_REG";

	case XSC_CMD_OP_MODIFY_RAW_QP:
		return "MODIFY_RAW_QP";

	case XSC_CMD_OP_ENABLE_NIC_HCA:
		return "ENABLE_NIC_HCA";

	case XSC_CMD_OP_DISABLE_NIC_HCA:
		return "DISABLE_NIC_HCA";

	case XSC_CMD_OP_MODIFY_NIC_HCA:
		return "MODIFY_NIC_HCA";

	case XSC_CMD_OP_QUERY_NIC_VPORT_CONTEXT:
		return "QUERY_NIC_VPORT_CONTEXT";

	case XSC_CMD_OP_MODIFY_NIC_VPORT_CONTEXT:
		return "MODIFY_NIC_VPORT_CONTEXT";

	case XSC_CMD_OP_QUERY_VPORT_STATE:
		return "QUERY_VPORT_STATE";

	case XSC_CMD_OP_MODIFY_VPORT_STATE:
		return "MODIFY_VPORT_STATE";

	case XSC_CMD_OP_QUERY_HCA_VPORT_CONTEXT:
		return "QUERY_HCA_VPORT_CONTEXT";

	case XSC_CMD_OP_MODIFY_HCA_VPORT_CONTEXT:
		return "MODIFY_HCA_VPORT_CONTEXT";

	case XSC_CMD_OP_QUERY_HCA_VPORT_GID:
		return "QUERY_HCA_VPORT_GID";

	case XSC_CMD_OP_QUERY_HCA_VPORT_PKEY:
		return "QUERY_HCA_VPORT_PKEY";

	case XSC_CMD_OP_QUERY_VPORT_COUNTER:
		return "QUERY_VPORT_COUNTER";

	case XSC_CMD_OP_QUERY_PRIO_STATS:
		return "QUERY_PRIO_STATS";

	case XSC_CMD_OP_QUERY_PHYPORT_STATE:
		return "QUERY_PHYPORT_STATE";

	case XSC_CMD_OP_QUERY_EVENT_TYPE:
		return "QUERY_EVENT_TYPE";

	case XSC_CMD_OP_QUERY_LINK_INFO:
		return "QUERY_LINK_INFO";

	case XSC_CMD_OP_MODIFY_LINK_INFO:
		return "MODIFY_LINK_INFO";

	case XSC_CMD_OP_MODIFY_FEC_PARAM:
		return "MODIFY_FEC_PARAM";

	case XSC_CMD_OP_QUERY_FEC_PARAM:
		return "QUERY_FEC_PARAM";

	case XSC_CMD_OP_LAG_CREATE:
		return "LAG_CREATE";

	case XSC_CMD_OP_LAG_MODIFY:
		return "LAG_MODIFY";

	case XSC_CMD_OP_LAG_DESTROY:
		return "LAG_DESTROY";

	case XSC_CMD_OP_LAG_SET_QOS:
		return "LAG_SET_QOS";

	case XSC_CMD_OP_ENABLE_MSIX:
		return "ENABLE_MSIX";

	case XSC_CMD_OP_IOCTL_FLOW:
		return "CFG_FLOW_TABLE";

	case XSC_CMD_OP_IOCTL_SET_DSCP_PMT:
		return "SET_DSCP_PMT";

	case XSC_CMD_OP_IOCTL_GET_DSCP_PMT:
		return "GET_DSCP_PMT";

	case XSC_CMD_OP_IOCTL_SET_TRUST_MODE:
		return "SET_TRUST_MODE";

	case XSC_CMD_OP_IOCTL_GET_TRUST_MODE:
		return "GET_TRUST_MODE";

	case XSC_CMD_OP_IOCTL_SET_PCP_PMT:
		return "SET_PCP_PMT";

	case XSC_CMD_OP_IOCTL_GET_PCP_PMT:
		return "GET_PCP_PMT";

	case XSC_CMD_OP_IOCTL_SET_DEFAULT_PRI:
		return "SET_DEFAULT_PRI";

	case XSC_CMD_OP_IOCTL_GET_DEFAULT_PRI:
		return "GET_DEFAULT_PRI";

	case XSC_CMD_OP_IOCTL_SET_PFC:
		return "SET_PFC";

	case XSC_CMD_OP_IOCTL_GET_PFC:
		return "GET_PFC";

	case XSC_CMD_OP_IOCTL_SET_RATE_LIMIT:
		return "SET_RATE_LIMIT";

	case XSC_CMD_OP_IOCTL_GET_RATE_LIMIT:
		return "GET_RATE_LIMIT";

	case XSC_CMD_OP_IOCTL_SET_SP:
		return "SET_SP";

	case XSC_CMD_OP_IOCTL_GET_SP:
		return "GET_SP";

	case XSC_CMD_OP_IOCTL_SET_WEIGHT:
		return "SET_WEIGHT";

	case XSC_CMD_OP_IOCTL_GET_WEIGHT:
		return "GET_WEIGHT";

	case XSC_CMD_OP_IOCTL_DPU_SET_PORT_WEIGHT:
		return "DPU_SET_PORT_WEIGHT";

	case XSC_CMD_OP_IOCTL_DPU_GET_PORT_WEIGHT:
		return "DPU_GET_PORT_WEIGHT";

	case XSC_CMD_OP_IOCTL_DPU_SET_PRIO_WEIGHT:
		return "DPU_SET_PRIO_WEIGHT";

	case XSC_CMD_OP_IOCTL_DPU_GET_PRIO_WEIGHT:
		return "DPU_GET_PRIO_WEIGHT";

	case XSC_CMD_OP_IOCTL_SET_ENABLE_RP:
		return "ENABLE_RP";

	case XSC_CMD_OP_IOCTL_SET_ENABLE_NP:
		return "ENABLE_NP";

	case XSC_CMD_OP_IOCTL_SET_INIT_ALPHA:
		return "SET_INIT_ALPHA";

	case XSC_CMD_OP_IOCTL_SET_G:
		return "SET_G";

	case XSC_CMD_OP_IOCTL_SET_AI:
		return "SET_AI";

	case XSC_CMD_OP_IOCTL_SET_HAI:
		return "SET_HAI";

	case XSC_CMD_OP_IOCTL_SET_TH:
		return "SET_TH";

	case XSC_CMD_OP_IOCTL_SET_BC_TH:
		return "SET_BC_TH";

	case XSC_CMD_OP_IOCTL_SET_CNP_OPCODE:
		return "SET_CNP_OPCODE";

	case XSC_CMD_OP_IOCTL_SET_CNP_BTH_B:
		return "SET_CNP_BTH_B";

	case XSC_CMD_OP_IOCTL_SET_CNP_BTH_F:
		return "SET_CNP_BTH_F";

	case XSC_CMD_OP_IOCTL_SET_CNP_ECN:
		return "SET_CNP_ECN";

	case XSC_CMD_OP_IOCTL_SET_DATA_ECN:
		return "SET_DATA_ECN";

	case XSC_CMD_OP_IOCTL_SET_CNP_TX_INTERVAL:
		return "SET_CNP_TX_INTERVAL";

	case XSC_CMD_OP_IOCTL_SET_EVT_PERIOD_RSTTIME:
		return "SET_EVT_PERIOD_RSTTIME";

	case XSC_CMD_OP_IOCTL_SET_CNP_DSCP:
		return "SET_CNP_DSCP";

	case XSC_CMD_OP_IOCTL_SET_CNP_PCP:
		return "SET_CNP_PCP";

	case XSC_CMD_OP_IOCTL_SET_EVT_PERIOD_ALPHA:
		return "SET_EVT_PERIOD_ALPHA";

	case XSC_CMD_OP_IOCTL_GET_CC_CFG:
		return "GET_CC_CFG";

	case XSC_CMD_OP_IOCTL_GET_CC_STAT:
		return "GET_CC_STAT";

	case XSC_CMD_OP_IOCTL_SET_CLAMP_TGT_RATE:
		return "SET_CLAMP_TGT_RATE";

	case XSC_CMD_OP_IOCTL_SET_MAX_HAI_FACTOR:
		return "SET_MAX_HAI_FACTOR";

	case XSC_CMD_OP_IOCTL_SET_HWC:
		return "SET_HWCONFIG";

	case XSC_CMD_OP_IOCTL_GET_HWC:
		return "GET_HWCONFIG";

	case XSC_CMD_OP_SET_MTU:
		return "SET_MTU";

	case XSC_CMD_OP_QUERY_ETH_MAC:
		return "QUERY_ETH_MAC";

	case XSC_CMD_OP_QUERY_HW_STATS:
		return "QUERY_HW_STATS";

	case XSC_CMD_OP_QUERY_PAUSE_CNT:
		return "QUERY_PAUSE_CNT";

	case XSC_CMD_OP_SET_RTT_EN:
		return "SET_RTT_EN";

	case XSC_CMD_OP_GET_RTT_EN:
		return "GET_RTT_EN";

	case XSC_CMD_OP_SET_RTT_QPN:
		return "SET_RTT_QPN";

	case XSC_CMD_OP_GET_RTT_QPN:
		return "GET_RTT_QPN";

	case XSC_CMD_OP_SET_RTT_PERIOD:
		return "SET_RTT_PERIOD";

	case XSC_CMD_OP_GET_RTT_PERIOD:
		return "GET_RTT_PERIOD";

	case XSC_CMD_OP_GET_RTT_RESULT:
		return "GET_RTT_RESULT";

	case XSC_CMD_OP_GET_RTT_STATS:
		return "ET_RTT_STATS";

	case XSC_CMD_OP_SET_LED_STATUS:
		return "SET_LED_STATUS";

	case XSC_CMD_OP_AP_FEAT:
		return "AP_FEAT";

	case XSC_CMD_OP_PCIE_LAT_FEAT:
		return "PCIE_LAT_FEAT";

	case XSC_CMD_OP_USER_EMU_CMD:
		return "USER_EMU_CMD";

	case XSC_CMD_OP_QUERY_PFC_PRIO_STATS:
		return "QUERY_PFC_PRIO_STATS";

	default: return "unknown command opcode";
	}
}

static void dump_command(struct xsc_core_device *xdev, struct xsc_cmd_mailbox *next,
			 struct xsc_cmd_work_ent *ent, int input, int len)
{
	u16 op = be16_to_cpu(((struct xsc_inbox_hdr *)(ent->lay->in))->opcode);
	int offset = 0;

	if (!(xsc_debug_mask & (1 << XSC_CMD_DATA)))
		return;

	xsc_core_dbg(xdev, "dump command %s(0x%x) %s\n", xsc_command_str(op), op,
		     input ? "INPUT" : "OUTPUT");

	if (input) {
		dump_buf(ent->lay, sizeof(*ent->lay), offset);
		offset += sizeof(*ent->lay);
	} else {
		dump_buf(ent->rsp_lay, sizeof(*ent->rsp_lay), offset);
		offset += sizeof(*ent->rsp_lay);
	}

	while (next && offset < len) {
		xsc_core_dbg(xdev, "command block:\n");
		dump_buf(next->buf, sizeof(struct xsc_cmd_prot_block), offset);
		offset += sizeof(struct xsc_cmd_prot_block);
		next = next->next;
	}
}

static void cmd_work_handler(struct work_struct *work)
{
	struct xsc_cmd_work_ent *ent = container_of(work, struct xsc_cmd_work_ent, work);
	struct xsc_cmd *cmd = ent->cmd;
	struct xsc_core_device *xdev = container_of(cmd, struct xsc_core_device, cmd);
	struct xsc_cmd_layout *lay;
	struct semaphore *sem;
	unsigned long flags;

	sem = &cmd->sem;
	down(sem);
	ent->idx = alloc_ent(cmd);
	if (ent->idx < 0) {
		xsc_core_err(xdev, "failed to allocate command entry\n");
		up(sem);
		return;
	}

	ent->token = alloc_token(cmd);
	cmd->ent_arr[ent->idx] = ent;

	spin_lock_irqsave(&cmd->doorbell_lock, flags);
	lay = get_inst(cmd, cmd->cmd_pid);
	ent->lay = lay;
	memset(lay, 0, sizeof(*lay));
	memcpy(lay->in, ent->in->first.data, sizeof(lay->in));
	if (ent->in->next)
		lay->in_ptr = cpu_to_be64(ent->in->next->dma);
	lay->inlen = cpu_to_be32(ent->in->len);
	if (ent->out->next)
		lay->out_ptr = cpu_to_be64(ent->out->next->dma);
	lay->outlen = cpu_to_be32(ent->out->len);
	lay->type = XSC_PCI_CMD_XPORT;
	lay->token = ent->token;
	lay->idx = ent->idx;
	if (!cmd->checksum_disabled)
		set_signature(ent);
	else
		lay->sig = 0xff;
	dump_command(xdev, ent->in->next, ent, 1, ent->in->len);

	ktime_get_ts64(&ent->ts1);

	/* ring doorbell after the descriptor is valid */
	wmb();

	cmd->cmd_pid = (cmd->cmd_pid + 1) % (1 << cmd->log_sz);
	writel(cmd->cmd_pid, REG_ADDR(xdev, cmd->reg.req_pid_addr));
	mmiowb();
	spin_unlock_irqrestore(&cmd->doorbell_lock, flags);

#ifdef XSC_DEBUG
	xsc_core_dbg(xdev, "write 0x%x to command doorbell, idx %u\n", cmd->cmd_pid, ent->idx);
#endif
}

static const char *deliv_status_to_str(u8 status)
{
	switch (status) {
	case XSC_CMD_DELIVERY_STAT_OK:
		return "no errors";
	case XSC_CMD_DELIVERY_STAT_SIGNAT_ERR:
		return "signature error";
	case XSC_CMD_DELIVERY_STAT_TOK_ERR:
		return "token error";
	case XSC_CMD_DELIVERY_STAT_BAD_BLK_NUM_ERR:
		return "bad block number";
	case XSC_CMD_DELIVERY_STAT_OUT_PTR_ALIGN_ERR:
		return "output pointer not aligned to block size";
	case XSC_CMD_DELIVERY_STAT_IN_PTR_ALIGN_ERR:
		return "input pointer not aligned to block size";
	case XSC_CMD_DELIVERY_STAT_FW_ERR:
		return "firmware internal error";
	case XSC_CMD_DELIVERY_STAT_IN_LENGTH_ERR:
		return "command input length error";
	case XSC_CMD_DELIVERY_STAT_OUT_LENGTH_ERR:
		return "command output length error";
	case XSC_CMD_DELIVERY_STAT_RES_FLD_NOT_CLR_ERR:
		return "reserved fields not cleared";
	case XSC_CMD_DELIVERY_STAT_CMD_DESCR_ERR:
		return "bad command descriptor type";
	default:
		return "unknown status code";
	}
}

static u16 msg_to_opcode(struct xsc_cmd_msg *in)
{
	struct xsc_inbox_hdr *hdr = (struct xsc_inbox_hdr *)(in->first.data);

	return be16_to_cpu(hdr->opcode);
}

static int wait_func(struct xsc_core_device *xdev, struct xsc_cmd_work_ent *ent)
{
	unsigned long timeout = msecs_to_jiffies(XSC_CMD_TIMEOUT_MSEC);
	int err;
	struct xsc_cmd *cmd = &xdev->cmd;

	if (!wait_for_completion_timeout(&ent->done, timeout))
		err = -ETIMEDOUT;
	else
		err = ent->ret;

	if (err == -ETIMEDOUT) {
		cmd->cmd_status = XSC_CMD_STATUS_TIMEDOUT;
		xsc_core_warn(xdev, "wait for %s(0x%x) response timeout!\n",
			      xsc_command_str(msg_to_opcode(ent->in)),
			      msg_to_opcode(ent->in));
	} else if (err) {
		xsc_core_dbg(xdev, "err %d, delivery status %s(%d)\n", err,
			     deliv_status_to_str(ent->status), ent->status);
	}

	return err;
}

/*  Notes:
 *    1. Callback functions may not sleep
 *    2. page queue commands do not support asynchrous completion
 */
static int xsc_cmd_invoke(struct xsc_core_device *xdev, struct xsc_cmd_msg *in,
			  struct xsc_rsp_msg *out, u8 *status)
{
	struct xsc_cmd *cmd = &xdev->cmd;
	struct xsc_cmd_work_ent *ent;
	ktime_t t1, t2, delta;
	struct xsc_cmd_stats *stats;
	int err = 0;
	s64 ds;
	u16 op;
	struct semaphore *sem;

	ent = alloc_cmd(cmd, in, out);
	if (IS_ERR(ent))
		return PTR_ERR(ent);

	init_completion(&ent->done);
	INIT_WORK(&ent->work, cmd_work_handler);
	if (!queue_work(cmd->wq, &ent->work)) {
		xsc_core_warn(xdev, "failed to queue work\n");
		err = -ENOMEM;
		goto out_free;
	}

	err = wait_func(xdev, ent);
	if (err == -ETIMEDOUT)
		goto out;
	t1 = timespec64_to_ktime(ent->ts1);
	t2 = timespec64_to_ktime(ent->ts2);
	delta = ktime_sub(t2, t1);
	ds = ktime_to_ns(delta);
	op = be16_to_cpu(((struct xsc_inbox_hdr *)in->first.data)->opcode);
	if (op < ARRAY_SIZE(cmd->stats)) {
		stats = &cmd->stats[op];
		spin_lock(&stats->lock);
		stats->sum += ds;
		++stats->n;
		spin_unlock(&stats->lock);
	}
	xsc_core_dbg_mask(xdev, 1 << XSC_CMD_TIME,
			  "fw exec time for %s is %lld nsec\n",
			  xsc_command_str(op), ds);
	*status = ent->status;
	free_cmd(ent);

	return err;

out:
	sem = &cmd->sem;
	up(sem);
out_free:
	free_cmd(ent);
	return err;
}

static ssize_t dbg_write(struct file *filp, const char __user *buf,
			 size_t count, loff_t *pos)
{
	struct xsc_core_device *xdev = filp->private_data;
	struct xsc_cmd_debug *dbg = &xdev->cmd.dbg;
	char lbuf[3];
	int err;

	if (!dbg->in_msg || !dbg->out_msg)
		return -ENOMEM;

	if (copy_from_user(lbuf, buf, sizeof(lbuf)))
		return -EPERM;

	lbuf[sizeof(lbuf) - 1] = 0;

	if (strcmp(lbuf, "go"))
		return -EINVAL;

	err = xsc_cmd_exec(xdev, dbg->in_msg, dbg->inlen, dbg->out_msg, dbg->outlen);

	return err ? err : count;
}

static const struct file_operations fops = {
	.owner	= THIS_MODULE,
	.open	= simple_open,
	.write	= dbg_write,
};

static int xsc_copy_to_cmd_msg(struct xsc_cmd_msg *to, void *from, int size)
{
	struct xsc_cmd_prot_block *block;
	struct xsc_cmd_mailbox *next;
	int copy;

	if (!to || !from)
		return -ENOMEM;

	copy = min_t(int, size, sizeof(to->first.data));
	memcpy(to->first.data, from, copy);
	size -= copy;
	from += copy;

	next = to->next;
	while (size) {
		if (!next) {
			/* this is a BUG */
			return -ENOMEM;
		}

		copy = min_t(int, size, XSC_CMD_DATA_BLOCK_SIZE);
		block = next->buf;
		memcpy(block->data, from, copy);
		block->owner_status = 0;
		from += copy;
		size -= copy;
		next = next->next;
	}

	return 0;
}

static int xsc_copy_from_rsp_msg(void *to, struct xsc_rsp_msg *from, int size)
{
	struct xsc_cmd_prot_block *block;
	struct xsc_cmd_mailbox *next;
	int copy;

	if (!to || !from)
		return -ENOMEM;

	copy = min_t(int, size, sizeof(from->first.data));
	memcpy(to, from->first.data, copy);
	size -= copy;
	to += copy;

	next = from->next;
	while (size) {
		if (!next) {
			/* this is a BUG */
			return -ENOMEM;
		}

		copy = min_t(int, size, XSC_CMD_DATA_BLOCK_SIZE);
		block = next->buf;
		if (block->owner_status != 1) {
			mdelay(10);
			continue;
		}

		memcpy(to, block->data, copy);
		to += copy;
		size -= copy;
		next = next->next;
	}

	return 0;
}

static struct xsc_cmd_mailbox *alloc_cmd_box(struct xsc_core_device *xdev,
					     gfp_t flags)
{
	struct xsc_cmd_mailbox *mailbox;

	mailbox = kmalloc(sizeof(*mailbox), flags);
	if (!mailbox)
		return ERR_PTR(-ENOMEM);

	mailbox->buf = dma_pool_alloc(xdev->cmd.pool, flags,
				      &mailbox->dma);
	if (!mailbox->buf) {
		xsc_core_dbg(xdev, "failed allocation\n");
		kfree(mailbox);
		return ERR_PTR(-ENOMEM);
	}
	memset(mailbox->buf, 0, sizeof(struct xsc_cmd_prot_block));
	mailbox->next = NULL;

	return mailbox;
}

static void free_cmd_box(struct xsc_core_device *xdev,
			 struct xsc_cmd_mailbox *mailbox)
{
	dma_pool_free(xdev->cmd.pool, mailbox->buf, mailbox->dma);
	kfree(mailbox);
}

static struct xsc_cmd_msg *xsc_alloc_cmd_msg(struct xsc_core_device *xdev,
					     gfp_t flags, int size)
{
	struct xsc_cmd_mailbox *tmp, *head = NULL;
	struct xsc_cmd_prot_block *block;
	struct xsc_cmd_msg *msg;
	int blen;
	int err;
	int n;
	int i;

	msg = kzalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return ERR_PTR(-ENOMEM);

	blen = size - min_t(int, sizeof(msg->first.data), size);
	n = (blen + XSC_CMD_DATA_BLOCK_SIZE - 1) / XSC_CMD_DATA_BLOCK_SIZE;

	for (i = 0; i < n; i++) {
		tmp = alloc_cmd_box(xdev, flags);
		if (IS_ERR(tmp)) {
			xsc_core_warn(xdev, "failed allocating block\n");
			err = PTR_ERR(tmp);
			goto err_alloc;
		}

		block = tmp->buf;
		tmp->next = head;
		block->next = cpu_to_be64(tmp->next ? tmp->next->dma : 0);
		block->block_num = cpu_to_be32(n - i - 1);
		head = tmp;
	}
	msg->next = head;
	msg->len = size;
	return msg;

err_alloc:
	while (head) {
		tmp = head->next;
		free_cmd_box(xdev, head);
		head = tmp;
	}
	kfree(msg);

	return ERR_PTR(err);
}

static void xsc_free_cmd_msg(struct xsc_core_device *xdev,
			     struct xsc_cmd_msg *msg)
{
	struct xsc_cmd_mailbox *head = msg->next;
	struct xsc_cmd_mailbox *next;

	while (head) {
		next = head->next;
		free_cmd_box(xdev, head);
		head = next;
	}
	kfree(msg);
}

static struct xsc_rsp_msg *xsc_alloc_rsp_msg(struct xsc_core_device *xdev,
					     gfp_t flags, int size)
{
	struct xsc_cmd_mailbox *tmp, *head = NULL;
	struct xsc_cmd_prot_block *block;
	struct xsc_rsp_msg *msg;
	int blen;
	int err;
	int n;
	int i;

	msg = kzalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return ERR_PTR(-ENOMEM);

	blen = size - min_t(int, sizeof(msg->first.data), size);
	n = (blen + XSC_CMD_DATA_BLOCK_SIZE - 1) / XSC_CMD_DATA_BLOCK_SIZE;

	for (i = 0; i < n; i++) {
		tmp = alloc_cmd_box(xdev, flags);
		if (IS_ERR(tmp)) {
			xsc_core_warn(xdev, "failed allocating block\n");
			err = PTR_ERR(tmp);
			goto err_alloc;
		}

		block = tmp->buf;
		tmp->next = head;
		block->next = cpu_to_be64(tmp->next ? tmp->next->dma : 0);
		block->block_num = cpu_to_be32(n - i - 1);
		head = tmp;
	}
	msg->next = head;
	msg->len = size;
	return msg;

err_alloc:
	while (head) {
		tmp = head->next;
		free_cmd_box(xdev, head);
		head = tmp;
	}
	kfree(msg);

	return ERR_PTR(err);
}

static void xsc_free_rsp_msg(struct xsc_core_device *xdev,
			     struct xsc_rsp_msg *msg)
{
	struct xsc_cmd_mailbox *head = msg->next;
	struct xsc_cmd_mailbox *next;

	while (head) {
		next = head->next;
		free_cmd_box(xdev, head);
		head = next;
	}
	kfree(msg);
}

static ssize_t data_write(struct file *filp, const char __user *buf,
			  size_t count, loff_t *pos)
{
	struct xsc_core_device *xdev = filp->private_data;
	struct xsc_cmd_debug *dbg = &xdev->cmd.dbg;
	void *ptr;
	int err;

	if (*pos != 0)
		return -EINVAL;

	kfree(dbg->in_msg);
	dbg->in_msg = NULL;
	dbg->inlen = 0;

	ptr = kzalloc(count, GFP_KERNEL);
	if (!ptr)
		return -ENOMEM;

	if (copy_from_user(ptr, buf, count)) {
		err = -EPERM;
		goto out;
	}
	dbg->in_msg = ptr;
	dbg->inlen = count;

	*pos = count;

	return count;

out:
	kfree(ptr);
	return err;
}

static ssize_t data_read(struct file *filp, char __user *buf, size_t count,
			 loff_t *pos)
{
	struct xsc_core_device *xdev = filp->private_data;
	struct xsc_cmd_debug *dbg = &xdev->cmd.dbg;
	int copy;

	if (*pos)
		return 0;

	if (!dbg->out_msg)
		return -ENOMEM;

	copy = min_t(int, count, dbg->outlen);
	if (copy_to_user(buf, dbg->out_msg, copy))
		return -EPERM;

	*pos += copy;

	return copy;
}

static const struct file_operations dfops = {
	.owner	= THIS_MODULE,
	.open	= simple_open,
	.write	= data_write,
	.read	= data_read,
};

static ssize_t outlen_read(struct file *filp, char __user *buf, size_t count,
			   loff_t *pos)
{
	struct xsc_core_device *xdev = filp->private_data;
	struct xsc_cmd_debug *dbg = &xdev->cmd.dbg;
	char outlen[8];
	int err;

	if (*pos)
		return 0;

	err = snprintf(outlen, sizeof(outlen), "%d", dbg->outlen);
	if (err < 0)
		return err;

	if (copy_to_user(buf, &outlen, err))
		return -EPERM;

	*pos += err;

	return err;
}

static ssize_t outlen_write(struct file *filp, const char __user *buf,
			    size_t count, loff_t *pos)
{
	struct xsc_core_device *xdev = filp->private_data;
	struct xsc_cmd_debug *dbg = &xdev->cmd.dbg;
	char outlen_str[8];
	int outlen;
	void *ptr;
	int err;

	if (*pos != 0 || count > 6)
		return -EINVAL;

	kfree(dbg->out_msg);
	dbg->out_msg = NULL;
	dbg->outlen = 0;

	if (copy_from_user(outlen_str, buf, count))
		return -EPERM;

	outlen_str[7] = 0;

	err = kstrtoint(outlen_str, 10, &outlen);
	if (err < 0)
		return err;

	ptr = kzalloc(outlen, GFP_KERNEL);
	if (!ptr)
		return -ENOMEM;

	dbg->out_msg = ptr;
	dbg->outlen = outlen;

	*pos = count;

	return count;
}

static const struct file_operations olfops = {
	.owner	= THIS_MODULE,
	.open	= simple_open,
	.write	= outlen_write,
	.read	= outlen_read,
};

static void set_wqname(struct xsc_core_device *xdev)
{
	struct xsc_cmd *cmd = &xdev->cmd;

	snprintf(cmd->wq_name, sizeof(cmd->wq_name), "xsc_cmd_%s",
		 dev_name(&xdev->pdev->dev));
}

static void clean_debug_files(struct xsc_core_device *xdev)
{
	struct xsc_cmd_debug *dbg = &xdev->cmd.dbg;

	if (!xsc_debugfs_root)
		return;

	xsc_cmdif_debugfs_cleanup(xdev);
	debugfs_remove_recursive(dbg->dbg_root);
}

static int create_debugfs_files(struct xsc_core_device *xdev)
{
	struct xsc_cmd_debug *dbg = &xdev->cmd.dbg;
	int err = -ENOMEM;

	if (!xsc_debugfs_root)
		return 0;

	dbg->dbg_root = debugfs_create_dir("cmd", xdev->dev_res->dbg_root);
	if (!dbg->dbg_root)
		return err;

	dbg->dbg_in = debugfs_create_file("in", 0400, dbg->dbg_root,
					  xdev, &dfops);
	if (!dbg->dbg_in)
		goto err_dbg;

	dbg->dbg_out = debugfs_create_file("out", 0200, dbg->dbg_root,
					   xdev, &dfops);
	if (!dbg->dbg_out)
		goto err_dbg;

	dbg->dbg_outlen = debugfs_create_file("out_len", 0600, dbg->dbg_root,
					      xdev, &olfops);
	if (!dbg->dbg_outlen)
		goto err_dbg;

	debugfs_create_u8("status", 0600, dbg->dbg_root, &dbg->status);
	dbg->dbg_run = debugfs_create_file("run", 0200, dbg->dbg_root, xdev, &fops);
	if (!dbg->dbg_run)
		goto err_dbg;

	xsc_cmdif_debugfs_init(xdev);

	return 0;

err_dbg:
	clean_debug_files(xdev);
	return err;
}

void xsc_cmd_use_events(struct xsc_core_device *xdev)
{
	struct xsc_cmd *cmd = &xdev->cmd;
	int i;

	for (i = 0; i < cmd->max_reg_cmds; i++)
		down(&cmd->sem);

	flush_workqueue(cmd->wq);

	cmd->mode = CMD_MODE_EVENTS;

	while (cmd->cmd_pid != cmd->cq_cid)
		msleep(20);
	kthread_stop(cmd->cq_task);
	cmd->cq_task = NULL;

	for (i = 0; i < cmd->max_reg_cmds; i++)
		up(&cmd->sem);
}

static int cmd_cq_polling(void *data);
void xsc_cmd_use_polling(struct xsc_core_device *xdev)
{
	struct xsc_cmd *cmd = &xdev->cmd;
	int i;

	for (i = 0; i < cmd->max_reg_cmds; i++)
		down(&cmd->sem);

	flush_workqueue(cmd->wq);
	cmd->mode = CMD_MODE_POLLING;
	cmd->cq_task = kthread_create(cmd_cq_polling, (void *)xdev, "xsc_cmd_cq_polling");
	if (cmd->cq_task)
		wake_up_process(cmd->cq_task);

	for (i = 0; i < cmd->max_reg_cmds; i++)
		up(&cmd->sem);
}

static int status_to_err(u8 status)
{
	return status ? -1 : 0; /* TBD more meaningful codes */
}

static struct xsc_cmd_msg *alloc_msg(struct xsc_core_device *xdev, int in_size)
{
	struct xsc_cmd_msg *msg = ERR_PTR(-ENOMEM);
	struct xsc_cmd *cmd = &xdev->cmd;
	struct cache_ent *ent = NULL;

	if (in_size > MED_LIST_SIZE && in_size <= LONG_LIST_SIZE)
		ent = &cmd->cache.large;
	else if (in_size > 16 && in_size <= MED_LIST_SIZE)
		ent = &cmd->cache.med;

	if (ent) {
		spin_lock(&ent->lock);
		if (!list_empty(&ent->head)) {
			msg = list_entry(ent->head.next, typeof(*msg), list);
			/* For cached lists, we must explicitly state what is
			 * the real size
			 */
			msg->len = in_size;
			list_del(&msg->list);
		}
		spin_unlock(&ent->lock);
	}

	if (IS_ERR(msg))
		msg = xsc_alloc_cmd_msg(xdev, GFP_KERNEL, in_size);

	return msg;
}

static void free_msg(struct xsc_core_device *xdev, struct xsc_cmd_msg *msg)
{
	if (msg->cache) {
		spin_lock(&msg->cache->lock);
		list_add_tail(&msg->list, &msg->cache->head);
		spin_unlock(&msg->cache->lock);
	} else {
		xsc_free_cmd_msg(xdev, msg);
	}
}

static int dummy_work(struct xsc_core_device *xdev, struct xsc_cmd_msg *in,
		      struct xsc_rsp_msg *out, u16 dummy_cnt, u16 dummy_start_pid)
{
	struct xsc_cmd *cmd = &xdev->cmd;
	struct xsc_cmd_work_ent **dummy_ent_arr;
	struct xsc_cmd_layout *lay;
	struct semaphore *sem;
	int err = 0;
	u16 i;
	u16 free_cnt = 0;
	u16 temp_pid = dummy_start_pid;

	sem = &cmd->sem;

	dummy_ent_arr = kcalloc(dummy_cnt, sizeof(struct xsc_cmd_work_ent *), GFP_KERNEL);
	if (!dummy_ent_arr) {
		err = -ENOMEM;
		goto alloc_ent_arr_err;
	}

	for (i = 0; i < dummy_cnt; i++) {
		dummy_ent_arr[i] = alloc_cmd(cmd, in, out);
		if (IS_ERR(dummy_ent_arr[i])) {
			xsc_core_err(xdev, "failed to alloc cmd buffer\n");
			err = -ENOMEM;
			free_cnt = i;
			goto alloc_ent_err;
		}

		down(sem);

		dummy_ent_arr[i]->idx = alloc_ent(cmd);
		if (dummy_ent_arr[i]->idx < 0) {
			xsc_core_err(xdev, "failed to allocate command entry\n");
			err = -1;
			free_cnt = i;
			goto get_cmd_ent_idx_err;
		}
		dummy_ent_arr[i]->token = alloc_token(cmd);
		cmd->ent_arr[dummy_ent_arr[i]->idx] = dummy_ent_arr[i];
		init_completion(&dummy_ent_arr[i]->done);

		lay = get_inst(cmd, temp_pid);
		dummy_ent_arr[i]->lay = lay;
		memset(lay, 0, sizeof(*lay));
		memcpy(lay->in, dummy_ent_arr[i]->in->first.data, sizeof(dummy_ent_arr[i]->in));
		lay->inlen = cpu_to_be32(dummy_ent_arr[i]->in->len);
		lay->outlen = cpu_to_be32(dummy_ent_arr[i]->out->len);
		lay->type = XSC_PCI_CMD_XPORT;
		lay->token = dummy_ent_arr[i]->token;
		lay->idx = dummy_ent_arr[i]->idx;
		if (!cmd->checksum_disabled)
			set_signature(dummy_ent_arr[i]);
		else
			lay->sig = 0xff;
		temp_pid = (temp_pid + 1) % (1 << cmd->log_sz);
	}

	/* ring doorbell after the descriptor is valid */
	wmb();
	writel(cmd->cmd_pid, REG_ADDR(xdev, cmd->reg.req_pid_addr));
	if (readl(REG_ADDR(xdev, cmd->reg.interrupt_stat_addr)) != 0)
		writel(0xF, REG_ADDR(xdev, cmd->reg.interrupt_stat_addr));

	mmiowb();
	xsc_core_dbg(xdev, "write 0x%x to command doorbell, idx %u ~ %u\n", cmd->cmd_pid,
		     dummy_ent_arr[0]->idx, dummy_ent_arr[dummy_cnt - 1]->idx);

	if (wait_for_completion_timeout(&dummy_ent_arr[dummy_cnt - 1]->done,
					msecs_to_jiffies(3000)) == 0) {
		xsc_core_err(xdev, "dummy_cmd %d ent timeout, cmdq fail\n", dummy_cnt - 1);
		err = -ETIMEDOUT;
	} else {
		xsc_core_dbg(xdev, "%d ent done\n", dummy_cnt);
	}

	for (i = 0; i < dummy_cnt; i++)
		free_cmd(dummy_ent_arr[i]);

	kfree(dummy_ent_arr);
	return err;

get_cmd_ent_idx_err:
	free_cmd(dummy_ent_arr[free_cnt]);
	up(sem);
alloc_ent_err:
	for (i = 0; i < free_cnt; i++) {
		free_ent(cmd, dummy_ent_arr[i]->idx);
		up(sem);
		free_cmd(dummy_ent_arr[i]);
	}
	kfree(dummy_ent_arr);
alloc_ent_arr_err:
	return err;
}

static int xsc_dummy_cmd_exec(struct xsc_core_device *xdev, void *in, int in_size, void *out,
			      int out_size, u16 dmmy_cnt, u16 dummy_start)
{
	struct xsc_cmd_msg *inb;
	struct xsc_rsp_msg *outb;
	int err;

	inb = alloc_msg(xdev, in_size);
	if (IS_ERR(inb)) {
		err = PTR_ERR(inb);
		return err;
	}

	err = xsc_copy_to_cmd_msg(inb, in, in_size);
	if (err) {
		xsc_core_warn(xdev, "err %d\n", err);
		goto out_in;
	}

	outb = xsc_alloc_rsp_msg(xdev, GFP_KERNEL, out_size);
	if (IS_ERR(outb)) {
		err = PTR_ERR(outb);
		goto out_in;
	}

	err = dummy_work(xdev, inb, outb, dmmy_cnt, dummy_start);

	if (err)
		goto out_out;

	err = xsc_copy_from_rsp_msg(out, outb, out_size);

out_out:
	xsc_free_rsp_msg(xdev, outb);

out_in:
	free_msg(xdev, inb);
	return err;
}

static int xsc_send_dummy_cmd(struct xsc_core_device *xdev, u16 gap, u16 dummy_start)
{
	struct xsc_cmd_dummy_mbox_out *out;
	struct xsc_cmd_dummy_mbox_in in;
	int err;

	out = kzalloc(sizeof(*out), GFP_KERNEL);
	if (!out) {
		err = -ENOMEM;
		goto no_mem_out;
	}

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DUMMY);
	in.hdr.opmod = cpu_to_be16(0x1);

	err = xsc_dummy_cmd_exec(xdev, &in, sizeof(in), out, sizeof(*out), gap, dummy_start);
	if (err)
		goto out_out;

	if (out->hdr.status) {
		err = xsc_cmd_status_to_err(&out->hdr);
		goto out_out;
	}

out_out:
	kfree(out);
no_mem_out:
	return err;
}

static int request_pid_cid_mismatch_restore(struct xsc_core_device *xdev)
{
	struct xsc_cmd *cmd = &xdev->cmd;
	u16 req_pid, req_cid;
	u16 gap;

	int err;

	req_pid = readl(REG_ADDR(xdev, cmd->reg.req_pid_addr));
	req_cid = readl(REG_ADDR(xdev, cmd->reg.req_cid_addr));
	if (req_pid >= (1 << cmd->log_sz) || req_cid >= (1 << cmd->log_sz)) {
		xsc_core_err(xdev, "req_pid %d, req_cid %d, out of normal range!!! max value is %d\n",
			     req_pid, req_cid, (1 << cmd->log_sz));
		return -1;
	}

	if (req_pid == req_cid)
		return 0;

	gap = (req_pid > req_cid) ? (req_pid - req_cid) : ((1 << cmd->log_sz) + req_pid - req_cid);
	xsc_core_info(xdev, "Cmdq req_pid %d, req_cid %d, send %d dummy cmds\n",
		      req_pid, req_cid, gap);

	err = xsc_send_dummy_cmd(xdev, gap, req_cid);
	if (err) {
		xsc_core_err(xdev, "Send dummy cmd failed\n");
		goto send_dummy_fail;
	}

send_dummy_fail:
	return err;
}

int _xsc_cmd_exec(struct xsc_core_device *xdev, void *in, int in_size, void *out,
		  int out_size)
{
	struct xsc_cmd_msg *inb;
	struct xsc_rsp_msg *outb;
	int err;
	u8 status = 0;
	struct xsc_cmd *cmd = &xdev->cmd;

	if (cmd->cmd_status == XSC_CMD_STATUS_TIMEDOUT)
		return -ETIMEDOUT;

	inb = alloc_msg(xdev, in_size);
	if (IS_ERR(inb)) {
		err = PTR_ERR(inb);
		return err;
	}

	err = xsc_copy_to_cmd_msg(inb, in, in_size);
	if (err) {
		xsc_core_warn(xdev, "err %d\n", err);
		goto out_in;
	}

	outb = xsc_alloc_rsp_msg(xdev, GFP_KERNEL, out_size);
	if (IS_ERR(outb)) {
		err = PTR_ERR(outb);
		goto out_in;
	}

	err = xsc_cmd_invoke(xdev, inb, outb, &status);
	if (err)
		goto out_out;

	if (status) {
		xsc_core_err(xdev, "opcode:%#x, err %d, status %d\n",
			     msg_to_opcode(inb), err, status);
		err = status_to_err(status);
		goto out_out;
	}

	err = xsc_copy_from_rsp_msg(out, outb, out_size);

out_out:
	xsc_free_rsp_msg(xdev, outb);

out_in:
	free_msg(xdev, inb);
	return err;
}
EXPORT_SYMBOL(_xsc_cmd_exec);

static void destroy_msg_cache(struct xsc_core_device *xdev)
{
	struct xsc_cmd *cmd = &xdev->cmd;
	struct xsc_cmd_msg *msg;
	struct xsc_cmd_msg *n;

	list_for_each_entry_safe(msg, n, &cmd->cache.large.head, list) {
		list_del(&msg->list);
		xsc_free_cmd_msg(xdev, msg);
	}

	list_for_each_entry_safe(msg, n, &cmd->cache.med.head, list) {
		list_del(&msg->list);
		xsc_free_cmd_msg(xdev, msg);
	}
}

static int create_msg_cache(struct xsc_core_device *xdev)
{
	struct xsc_cmd *cmd = &xdev->cmd;
	struct xsc_cmd_msg *msg;
	int err;
	int i;

	spin_lock_init(&cmd->cache.large.lock);
	INIT_LIST_HEAD(&cmd->cache.large.head);
	spin_lock_init(&cmd->cache.med.lock);
	INIT_LIST_HEAD(&cmd->cache.med.head);

	for (i = 0; i < NUM_LONG_LISTS; i++) {
		msg = xsc_alloc_cmd_msg(xdev, GFP_KERNEL, LONG_LIST_SIZE);
		if (IS_ERR(msg)) {
			err = PTR_ERR(msg);
			goto ex_err;
		}
		msg->cache = &cmd->cache.large;
		list_add_tail(&msg->list, &cmd->cache.large.head);
	}

	for (i = 0; i < NUM_MED_LISTS; i++) {
		msg = xsc_alloc_cmd_msg(xdev, GFP_KERNEL, MED_LIST_SIZE);
		if (IS_ERR(msg)) {
			err = PTR_ERR(msg);
			goto ex_err;
		}
		msg->cache = &cmd->cache.med;
		list_add_tail(&msg->list, &cmd->cache.med.head);
	}

	return 0;

ex_err:
	destroy_msg_cache(xdev);
	return err;
}

static void xsc_cmd_comp_handler(struct xsc_core_device *xdev, u8 idx, struct xsc_rsp_layout *rsp)
{
	struct xsc_cmd *cmd = &xdev->cmd;
	struct xsc_cmd_work_ent *ent;
	struct xsc_inbox_hdr *hdr;

	if (idx > cmd->max_reg_cmds || (cmd->bitmask & (1 << idx))) {
		xsc_core_err(xdev, "idx[%d] exceed max cmds, or has no relative request.\n", idx);
		return;
	}
	ent = cmd->ent_arr[idx];
	ent->rsp_lay = rsp;
	ktime_get_ts64(&ent->ts2);

	memcpy(ent->out->first.data, ent->rsp_lay->out, sizeof(ent->rsp_lay->out));
	dump_command(xdev, ent->out->next, ent, 0, ent->out->len);
	if (!cmd->checksum_disabled)
		ent->ret = verify_signature(ent);
	else
		ent->ret = 0;
	ent->status = 0;

	hdr = (struct xsc_inbox_hdr *)ent->in->first.data;
	xsc_core_dbg(xdev, "delivery status:%s(%d), rsp status=%d, opcode %#x, idx:%d,%d, ret=%d\n",
		     deliv_status_to_str(ent->status), ent->status,
		     ((struct xsc_outbox_hdr *)ent->rsp_lay->out)->status,
		     __be16_to_cpu(hdr->opcode), idx, ent->lay->idx, ent->ret);
	free_ent(cmd, ent->idx);
	complete(&ent->done);
	up(&cmd->sem);
}

static int cmd_cq_polling(void *data)
{
	struct xsc_core_device *xdev = data;
	struct xsc_cmd *cmd = &xdev->cmd;
	struct xsc_rsp_layout *rsp;
	u32 cq_pid;

	while (!kthread_should_stop()) {
		if (need_resched())
			schedule();
		cq_pid = readl(REG_ADDR(xdev, cmd->reg.rsp_pid_addr));
		if (cmd->cq_cid == cq_pid) {
#ifdef COSIM
			mdelay(1000);
#endif
			continue;
		}

		//get cqe
		rsp = get_cq_inst(cmd, cmd->cq_cid);
		if (!cmd->ownerbit_learned) {
			cmd->ownerbit_learned = 1;
			cmd->owner_bit = rsp->owner_bit;
		}
		if (cmd->owner_bit != rsp->owner_bit) {
			//hw update cq doorbell but buf may not ready
			xsc_core_err(xdev, "hw update cq doorbell but buf not ready %u %u\n",
				     cmd->cq_cid, cq_pid);
			continue;
		}

		xsc_cmd_comp_handler(xdev, rsp->idx, rsp);

		cmd->cq_cid = (cmd->cq_cid + 1) % (1 << cmd->log_sz);

		writel(cmd->cq_cid, REG_ADDR(xdev, cmd->reg.rsp_cid_addr));
		if (cmd->cq_cid == 0)
			cmd->owner_bit = !cmd->owner_bit;
	}
	return 0;
}

int xsc_cmd_err_handler(struct xsc_core_device *xdev)
{
	union interrupt_stat {
		struct {
			u32	hw_read_req_err:1;
			u32	hw_write_req_err:1;
			u32	req_pid_err:1;
			u32	rsp_cid_err:1;
		};
		u32	raw;
	} stat;
	int err = 0;
	int retry = 0;

	stat.raw = readl(REG_ADDR(xdev, xdev->cmd.reg.interrupt_stat_addr));
	while (stat.raw != 0) {
		err++;
		if (stat.hw_read_req_err) {
			retry = 1;
			stat.hw_read_req_err = 0;
			xsc_core_err(xdev, "hw report read req from host failed!\n");
		} else if (stat.hw_write_req_err) {
			retry = 1;
			stat.hw_write_req_err = 0;
			xsc_core_err(xdev, "hw report write req to fw failed!\n");
		} else if (stat.req_pid_err) {
			stat.req_pid_err = 0;
			xsc_core_err(xdev, "hw report unexpected req pid!\n");
		} else if (stat.rsp_cid_err) {
			stat.rsp_cid_err = 0;
			xsc_core_err(xdev, "hw report unexpected rsp cid!\n");
		} else {
			stat.raw = 0;
			xsc_core_err(xdev, "ignore unknown interrupt!\n");
		}
	}

	if (retry)
		writel(xdev->cmd.cmd_pid, REG_ADDR(xdev, xdev->cmd.reg.req_pid_addr));

	if (err)
		writel(0xf, REG_ADDR(xdev, xdev->cmd.reg.interrupt_stat_addr));

	return err;
}

void xsc_cmd_resp_handler(struct xsc_core_device *xdev)
{
	struct xsc_cmd *cmd = &xdev->cmd;
	struct xsc_rsp_layout *rsp;
	u32 cq_pid;
	const int budget = 32;
	int count = 0;

	while (count < budget) {
		cq_pid = readl(REG_ADDR(xdev, cmd->reg.rsp_pid_addr));
		if (cq_pid == cmd->cq_cid)
			return;

		rsp = get_cq_inst(cmd, cmd->cq_cid);
		if (!cmd->ownerbit_learned) {
			cmd->ownerbit_learned = 1;
			cmd->owner_bit = rsp->owner_bit;
		}
		if (cmd->owner_bit != rsp->owner_bit) {
			xsc_core_err(xdev, "hw update cq doorbell but buf not ready %u %u\n",
				     cmd->cq_cid, cq_pid);
			return;
		}

		xsc_cmd_comp_handler(xdev, rsp->idx, rsp);

		cmd->cq_cid = (cmd->cq_cid + 1) % (1 << cmd->log_sz);
		writel(cmd->cq_cid, REG_ADDR(xdev, cmd->reg.rsp_cid_addr));
		if (cmd->cq_cid == 0)
			cmd->owner_bit = !cmd->owner_bit;

		count++;
	}
}

static void xsc_cmd_handle_rsp_before_reload
(struct xsc_cmd *cmd, struct xsc_core_device *xdev)
{
	u32 rsp_pid, rsp_cid;

	rsp_pid = readl(REG_ADDR(xdev, cmd->reg.rsp_pid_addr));
	rsp_cid = readl(REG_ADDR(xdev, cmd->reg.rsp_cid_addr));
	if (rsp_pid == rsp_cid)
		return;

	cmd->cq_cid = rsp_pid;

	writel(cmd->cq_cid, REG_ADDR(xdev, cmd->reg.rsp_cid_addr));
}

int xsc_cmd_init(struct xsc_core_device *xdev)
{
	int size = sizeof(struct xsc_cmd_prot_block);
	int align = roundup_pow_of_two(size);
	struct xsc_cmd *cmd = &xdev->cmd;
	u32 cmd_h, cmd_l;
	u32 err_stat;
	int err;
	int i;

	//sriov need adapt for this process.
	//now there is 544 cmdq resource, soc using from id 514
	if (xsc_core_is_pf(xdev)) {
		cmd->reg.req_pid_addr = HIF_CMDQM_HOST_REQ_PID_MEM_ADDR;
		cmd->reg.req_cid_addr = HIF_CMDQM_HOST_REQ_CID_MEM_ADDR;
		cmd->reg.rsp_pid_addr = HIF_CMDQM_HOST_RSP_PID_MEM_ADDR;
		cmd->reg.rsp_cid_addr = HIF_CMDQM_HOST_RSP_CID_MEM_ADDR;
		cmd->reg.req_buf_h_addr = HIF_CMDQM_HOST_REQ_BUF_BASE_H_ADDR_MEM_ADDR;
		cmd->reg.req_buf_l_addr = HIF_CMDQM_HOST_REQ_BUF_BASE_L_ADDR_MEM_ADDR;
		cmd->reg.rsp_buf_h_addr = HIF_CMDQM_HOST_RSP_BUF_BASE_H_ADDR_MEM_ADDR;
		cmd->reg.rsp_buf_l_addr = HIF_CMDQM_HOST_RSP_BUF_BASE_L_ADDR_MEM_ADDR;
		cmd->reg.msix_vec_addr = HIF_CMDQM_VECTOR_ID_MEM_ADDR;
		cmd->reg.element_sz_addr = HIF_CMDQM_Q_ELEMENT_SZ_REG_ADDR;
		cmd->reg.q_depth_addr = HIF_CMDQM_HOST_Q_DEPTH_REG_ADDR;
		cmd->reg.interrupt_stat_addr = HIF_CMDQM_HOST_VF_ERR_STS_MEM_ADDR;
	} else {
		cmd->reg.req_pid_addr = CMDQM_HOST_REQ_PID_MEM_ADDR;
		cmd->reg.req_cid_addr = CMDQM_HOST_REQ_CID_MEM_ADDR;
		cmd->reg.rsp_pid_addr = CMDQM_HOST_RSP_PID_MEM_ADDR;
		cmd->reg.rsp_cid_addr = CMDQM_HOST_RSP_CID_MEM_ADDR;
		cmd->reg.req_buf_h_addr = CMDQM_HOST_REQ_BUF_BASE_H_ADDR_MEM_ADDR;
		cmd->reg.req_buf_l_addr = CMDQM_HOST_REQ_BUF_BASE_L_ADDR_MEM_ADDR;
		cmd->reg.rsp_buf_h_addr = CMDQM_HOST_RSP_BUF_BASE_H_ADDR_MEM_ADDR;
		cmd->reg.rsp_buf_l_addr = CMDQM_HOST_RSP_BUF_BASE_L_ADDR_MEM_ADDR;
		cmd->reg.msix_vec_addr = CMDQM_VECTOR_ID_MEM_ADDR;
		cmd->reg.element_sz_addr = CMDQM_Q_ELEMENT_SZ_REG_ADDR;
		cmd->reg.q_depth_addr = CMDQM_HOST_Q_DEPTH_REG_ADDR;
		cmd->reg.interrupt_stat_addr = CMDQM_HOST_VF_ERR_STS_MEM_ADDR;
	}

	cmd->pool = dma_pool_create("xsc_cmd", &xdev->pdev->dev, size, align, 0);
	if (!cmd->pool)
		return -ENOMEM;

	cmd->cmd_buf = (void *)__get_free_pages(GFP_ATOMIC, 0);
	if (!cmd->cmd_buf) {
		err = -ENOMEM;
		goto err_free_pool;
	}
	cmd->cq_buf = (void *)__get_free_pages(GFP_ATOMIC, 0);
	if (!cmd->cq_buf) {
		err = -ENOMEM;
		goto err_free_cmd;
	}

	cmd->dma = dma_map_single(&xdev->pdev->dev, cmd->cmd_buf, PAGE_SIZE,
				  DMA_BIDIRECTIONAL);
	if (dma_mapping_error(&xdev->pdev->dev, cmd->dma)) {
		err = -ENOMEM;
		goto err_free;
	}

	cmd->cq_dma = dma_map_single(&xdev->pdev->dev, cmd->cq_buf, PAGE_SIZE,
				     DMA_BIDIRECTIONAL);
	if (dma_mapping_error(&xdev->pdev->dev, cmd->cq_dma)) {
		err = -ENOMEM;
		goto err_map_cmd;
	}

	cmd->cmd_pid = readl(REG_ADDR(xdev, cmd->reg.req_pid_addr));
	cmd->cq_cid = readl(REG_ADDR(xdev, cmd->reg.rsp_cid_addr));
	cmd->ownerbit_learned = 0;

	xsc_cmd_handle_rsp_before_reload(cmd, xdev);

#define ELEMENT_SIZE_LOG 6 //64B
#define Q_DEPTH_LOG	5 //32

	cmd->log_sz = Q_DEPTH_LOG;
	cmd->log_stride = readl(REG_ADDR(xdev, cmd->reg.element_sz_addr));
	writel(1 << cmd->log_sz, REG_ADDR(xdev, cmd->reg.q_depth_addr));
	if (cmd->log_stride != ELEMENT_SIZE_LOG) {
		dev_err(&xdev->pdev->dev, "firmware failed to init cmdq, log_stride=(%d, %d)\n",
			cmd->log_stride, ELEMENT_SIZE_LOG);
		err = -ENODEV;
		goto err_map;
	}

	if (1 << cmd->log_sz > XSC_MAX_COMMANDS) {
		dev_err(&xdev->pdev->dev, "firmware reports too many outstanding commands %d\n",
			1 << cmd->log_sz);
		err = -EINVAL;
		goto err_map;
	}

	if (cmd->log_sz + cmd->log_stride > PAGE_SHIFT) {
		dev_err(&xdev->pdev->dev, "command queue size overflow\n");
		err = -EINVAL;
		goto err_map;
	}

	cmd->checksum_disabled = 1;
	cmd->max_reg_cmds = (1 << cmd->log_sz) - 1;
	cmd->bitmask = (1 << cmd->max_reg_cmds) - 1;

	spin_lock_init(&cmd->alloc_lock);
	spin_lock_init(&cmd->token_lock);
	spin_lock_init(&cmd->doorbell_lock);
	for (i = 0; i < ARRAY_SIZE(cmd->stats); i++)
		spin_lock_init(&cmd->stats[i].lock);

	sema_init(&cmd->sem, cmd->max_reg_cmds);

	cmd_h = (u32)((u64)(cmd->dma) >> 32);
	cmd_l = (u32)(cmd->dma);
	if (cmd_l & 0xfff) {
		dev_err(&xdev->pdev->dev, "invalid command queue address\n");
		err = -ENOMEM;
		goto err_map;
	}

	writel(cmd_h, REG_ADDR(xdev, cmd->reg.req_buf_h_addr));
	writel(cmd_l, REG_ADDR(xdev, cmd->reg.req_buf_l_addr));

	cmd_h = (u32)((u64)(cmd->cq_dma) >> 32);
	cmd_l = (u32)(cmd->cq_dma);
	if (cmd_l & 0xfff) {
		dev_err(&xdev->pdev->dev, "invalid command queue address\n");
		err = -ENOMEM;
		goto err_map;
	}
	writel(cmd_h, REG_ADDR(xdev, cmd->reg.rsp_buf_h_addr));
	writel(cmd_l, REG_ADDR(xdev, cmd->reg.rsp_buf_l_addr));

	/* Make sure firmware sees the complete address before we proceed */
	wmb();

	xsc_core_dbg(xdev, "descriptor at dma 0x%llx 0x%llx\n",
		     (unsigned long long)(cmd->dma), (unsigned long long)(cmd->cq_dma));

	cmd->mode = CMD_MODE_POLLING;
	cmd->cmd_status = XSC_CMD_STATUS_NORMAL;

	err = create_msg_cache(xdev);
	if (err) {
		dev_err(&xdev->pdev->dev, "failed to create command cache\n");
		goto err_map;
	}

	set_wqname(xdev);
	cmd->wq = create_singlethread_workqueue(cmd->wq_name);
	if (!cmd->wq) {
		dev_err(&xdev->pdev->dev, "failed to create command workqueue\n");
		err = -ENOMEM;
		goto err_cache;
	}

	cmd->cq_task = kthread_create(cmd_cq_polling, (void *)xdev, "xsc_cmd_cq_polling");
	if (!cmd->cq_task) {
		dev_err(&xdev->pdev->dev, "failed to create cq task\n");
		err = -ENOMEM;
		goto err_wq;
	}
	wake_up_process(cmd->cq_task);

	err = create_debugfs_files(xdev);
	if (err) {
		err = -ENOMEM;
		goto err_task;
	}

	err = request_pid_cid_mismatch_restore(xdev);
	if (err) {
		dev_err(&xdev->pdev->dev, "request pid,cid wrong, restore failed\n");
		goto err_req_restore;
	}

	// clear abnormal state to avoid the impact of previous error
	err_stat = readl(REG_ADDR(xdev, xdev->cmd.reg.interrupt_stat_addr));
	if (err_stat) {
		xsc_core_warn(xdev, "err_stat 0x%x when initializing, clear it\n", err_stat);
		writel(0xf, REG_ADDR(xdev, xdev->cmd.reg.interrupt_stat_addr));
	}

	return 0;

err_req_restore:
err_task:
	kthread_stop(cmd->cq_task);

err_wq:
	destroy_workqueue(cmd->wq);

err_cache:
	destroy_msg_cache(xdev);

err_map:
	dma_unmap_single(&xdev->pdev->dev, cmd->cq_dma, PAGE_SIZE,
			 DMA_BIDIRECTIONAL);

err_map_cmd:
	dma_unmap_single(&xdev->pdev->dev, cmd->dma, PAGE_SIZE,
			 DMA_BIDIRECTIONAL);
err_free:
	free_pages((unsigned long)cmd->cq_buf, 0);

err_free_cmd:
	free_pages((unsigned long)cmd->cmd_buf, 0);

err_free_pool:
	dma_pool_destroy(cmd->pool);

	return err;
}
EXPORT_SYMBOL(xsc_cmd_init);

void xsc_cmd_cleanup(struct xsc_core_device *xdev)
{
	struct xsc_cmd *cmd = &xdev->cmd;

	clean_debug_files(xdev);
	destroy_workqueue(cmd->wq);
	if (cmd->cq_task)
		kthread_stop(cmd->cq_task);
	destroy_msg_cache(xdev);
	dma_unmap_single(&xdev->pdev->dev, cmd->dma, PAGE_SIZE,
			 DMA_BIDIRECTIONAL);
	free_pages((unsigned long)cmd->cq_buf, 0);
	dma_unmap_single(&xdev->pdev->dev, cmd->cq_dma, PAGE_SIZE,
			 DMA_BIDIRECTIONAL);
	free_pages((unsigned long)cmd->cmd_buf, 0);
	dma_pool_destroy(cmd->pool);
}
EXPORT_SYMBOL(xsc_cmd_cleanup);

static const char *cmd_status_str(u8 status)
{
	switch (status) {
	case XSC_CMD_STAT_OK:
		return "OK";
	case XSC_CMD_STAT_INT_ERR:
		return "internal error";
	case XSC_CMD_STAT_BAD_OP_ERR:
		return "bad operation";
	case XSC_CMD_STAT_BAD_PARAM_ERR:
		return "bad parameter";
	case XSC_CMD_STAT_BAD_SYS_STATE_ERR:
		return "bad system state";
	case XSC_CMD_STAT_BAD_RES_ERR:
		return "bad resource";
	case XSC_CMD_STAT_RES_BUSY:
		return "resource busy";
	case XSC_CMD_STAT_LIM_ERR:
		return "limits exceeded";
	case XSC_CMD_STAT_BAD_RES_STATE_ERR:
		return "bad resource state";
	case XSC_CMD_STAT_IX_ERR:
		return "bad index";
	case XSC_CMD_STAT_NO_RES_ERR:
		return "no resources";
	case XSC_CMD_STAT_BAD_INP_LEN_ERR:
		return "bad input length";
	case XSC_CMD_STAT_BAD_OUTP_LEN_ERR:
		return "bad output length";
	case XSC_CMD_STAT_BAD_QP_STATE_ERR:
		return "bad QP state";
	case XSC_CMD_STAT_BAD_PKT_ERR:
		return "bad packet (discarded)";
	case XSC_CMD_STAT_BAD_SIZE_OUTS_CQES_ERR:
		return "bad size too many outstanding CQEs";
	default:
		return "unknown status";
	}
}

int xsc_cmd_status_to_err(struct xsc_outbox_hdr *hdr)
{
	if (!hdr->status)
		return 0;

	pr_warn("command failed, status %s(0x%x), syndrome 0x%x\n",
		cmd_status_str(hdr->status), hdr->status,
		be32_to_cpu(hdr->syndrome));

	switch (hdr->status) {
	case XSC_CMD_STAT_OK:				return 0;
	case XSC_CMD_STAT_INT_ERR:			return -EIO;
	case XSC_CMD_STAT_BAD_OP_ERR:			return -EINVAL;
	case XSC_CMD_STAT_BAD_PARAM_ERR:		return -EINVAL;
	case XSC_CMD_STAT_BAD_SYS_STATE_ERR:		return -EIO;
	case XSC_CMD_STAT_BAD_RES_ERR:			return -EINVAL;
	case XSC_CMD_STAT_RES_BUSY:			return -EBUSY;
	case XSC_CMD_STAT_LIM_ERR:			return -EINVAL;
	case XSC_CMD_STAT_BAD_RES_STATE_ERR:		return -EINVAL;
	case XSC_CMD_STAT_IX_ERR:			return -EINVAL;
	case XSC_CMD_STAT_NO_RES_ERR:			return -EAGAIN;
	case XSC_CMD_STAT_BAD_INP_LEN_ERR:		return -EIO;
	case XSC_CMD_STAT_BAD_OUTP_LEN_ERR:		return -EIO;
	case XSC_CMD_STAT_BAD_QP_STATE_ERR:		return -EINVAL;
	case XSC_CMD_STAT_BAD_PKT_ERR:			return -EINVAL;
	case XSC_CMD_STAT_BAD_SIZE_OUTS_CQES_ERR:	return -EINVAL;
	default:					return -EIO;
	}
}

