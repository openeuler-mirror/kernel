// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <ub/ubase/ubase_comm_debugfs.h>

#include "ubase_debugfs.h"
#include "ubase_hw.h"
#include "ubase_mailbox.h"
#include "ubase_proxy.h"
#include "ubase_tp.h"
#include "ubase_ctx_debugfs.h"

static void ubase_dump_eq_ctx(struct seq_file *s, struct ubase_eq *eq)
{
	seq_printf(s, "%-5u", eq->eqn);
	seq_printf(s, "%-13u", eq->entries_num);
	seq_printf(s, "%-7u", eq->state);
	seq_printf(s, "%-8u", eq->arm_st);
	seq_printf(s, "%-10u", eq->eqe_size);
	seq_printf(s, "%-11u", eq->eq_period);
	seq_printf(s, "%-14u", eq->coalesce_cnt);
	seq_printf(s, "%-6d", eq->irqn);
	seq_printf(s, "%-10u", eq->eqc_irqn);
	seq_printf(s, "%-12u", eq->cons_index);
	seq_puts(s, "\n");
}

static void ubase_eq_ctx_titles_print(struct seq_file *s)
{
	seq_puts(s, "EQN  ENTRIES_NUM  STATE  ARM_ST  EQE_SIZE  EQ_PERIOD  ");
	seq_puts(s, "COALESCE_CNT  IRQN  EQC_IRQN  CONS_INDEX\n");
}

static void ubase_dump_aeq_ctx(struct seq_file *s, struct ubase_dev *udev, u32 idx)
{
	struct ubase_aeq *aeq = &udev->irq_table.aeq;
	struct ubase_eq *eq = &aeq->eq;

	ubase_dump_eq_ctx(s, eq);
}

static void ubase_dump_ceq_ctx(struct seq_file *s, struct ubase_dev *udev, u32 idx)
{
	struct ubase_ceq *ceq = &udev->irq_table.ceqs.ceq[idx];
	struct ubase_eq *eq = &ceq->eq;

	ubase_dump_eq_ctx(s, eq);
}

static void ubase_tpg_ctx_titles_print(struct seq_file *s)
{
	seq_puts(s, "CHANNEL_ID  TPGN     TP_SHIFT  VALID_TP  ");
	seq_puts(s, "START_TPN  TPG_STATE  TP_CNT\n");
}

static void ubase_dump_tpg_ctx(struct seq_file *s, struct ubase_dev *udev, u32 idx)
{
	struct ubase_tpg *tpg = &udev->tp_ctx.tpg[idx];

	seq_printf(s, "%-12u", idx);
	seq_printf(s, "%-9u", tpg->mb_tpgn);
	seq_printf(s, "%-10u", tpg->tp_shift);
	seq_printf(s, "%-10lu", tpg->valid_tp);
	seq_printf(s, "%-11u", tpg->start_tpn);
	seq_printf(s, "%-11u", tpg->tpg_state);
	seq_printf(s, "%-8u", tpg->tp_cnt);
	seq_puts(s, "\n");
}

enum ubase_dbg_ctx_type {
	UBASE_DBG_AEQ_CTX = 0,
	UBASE_DBG_CEQ_CTX,
	UBASE_DBG_TPG_CTX,
};

static u32 ubase_get_ctx_num(struct ubase_dev *udev,
			     enum ubase_dbg_ctx_type ctx_type)
{
	struct ubase_adev_caps *unic_caps = &udev->caps.unic_caps;
	u32 ctx_num = 0;

	switch (ctx_type) {
	case UBASE_DBG_AEQ_CTX:
		ctx_num = udev->caps.dev_caps.num_aeq_vectors;
		break;
	case UBASE_DBG_CEQ_CTX:
		ctx_num = udev->irq_table.ceqs.num;
		break;
	case UBASE_DBG_TPG_CTX:
		ctx_num = unic_caps->tpg.max_cnt;
		break;
	default:
		ubase_err(udev, "failed to get ctx num, ctx_type = %u.\n",
			  ctx_type);
		break;
	}

	return ctx_num;
}

static int ubase_dbg_dump_context(struct seq_file *s,
				  enum ubase_dbg_ctx_type ctx_type)
{
	struct ubase_dbg_ctx {
		void (*print_ctx_titles)(struct seq_file *s);
		void (*get_ctx)(struct seq_file *s, struct ubase_dev *udev,
				u32 idx);
	} dbg_ctx[] = {
		{
			.print_ctx_titles = ubase_eq_ctx_titles_print,
			.get_ctx = ubase_dump_aeq_ctx,
		},
		{
			.print_ctx_titles = ubase_eq_ctx_titles_print,
			.get_ctx = ubase_dump_ceq_ctx,
		},
		{
			.print_ctx_titles = ubase_tpg_ctx_titles_print,
			.get_ctx = ubase_dump_tpg_ctx,
		},
	};
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	u32 i;

	dbg_ctx[ctx_type].print_ctx_titles(s);

	for (i = 0; i < ubase_get_ctx_num(udev, ctx_type); i++)
		dbg_ctx[ctx_type].get_ctx(s, udev, i);

	return 0;
}

struct ubase_ctx_info {
	u32 start_idx;
	u32 ctx_size;
	u8 op;
	const char *ctx_name;
};

static void ubase_get_ctx_info(struct ubase_dev *udev,
			       enum ubase_dbg_ctx_type ctx_type,
			       struct ubase_ctx_info *ctx_info)
{
	switch (ctx_type) {
	case UBASE_DBG_AEQ_CTX:
		ctx_info->start_idx = 0;
		ctx_info->ctx_size = UBASE_AEQ_CTX_SIZE;
		ctx_info->op = UBASE_MB_QUERY_AEQ_CONTEXT;
		ctx_info->ctx_name = "aeq";
		break;
	case UBASE_DBG_CEQ_CTX:
		ctx_info->start_idx = 0;
		ctx_info->ctx_size = UBASE_CEQ_CTX_SIZE;
		ctx_info->op = UBASE_MB_QUERY_CEQ_CONTEXT;
		ctx_info->ctx_name = "ceq";
		break;
	default:
		ubase_err(udev, "failed to get ctx info, ctx_type = %u.\n",
			  ctx_type);
		break;
	}
}

static void ubase_mask_eq_ctx_key_words(void *buf)
{
	struct ubase_eq_ctx *eq = (struct ubase_eq_ctx *)buf;

	eq->eqe_base_addr_l = 0;
	eq->eqe_base_addr_h = 0;
	eq->eqe_token_value = 0;
}

static void ubase_mask_ctx_key_words(void *buf,
				     enum ubase_dbg_ctx_type ctx_type)
{
	switch (ctx_type) {
	case UBASE_DBG_AEQ_CTX:
	case UBASE_DBG_CEQ_CTX:
		ubase_mask_eq_ctx_key_words(buf);
		break;
	default:
		break;
	}
}

static void __ubase_print_context_hw(struct seq_file *s, void *ctx_addr,
				     u32 ctx_len)
{
	__le32 *p = (__le32 *)ctx_addr;
	u32 i;

	ctx_len = ctx_len / sizeof(u32);
	for (i = 0; i < ctx_len; i++, p++) {
		seq_printf(s, "%lu\t", (i + 1) * sizeof(u32));
		seq_printf(s, "%08x\n", le32_to_cpu(*p));
	}
}

/**
 * ubase_print_context_hw() - formatted the context output to seq file
 * @s: seq_file
 * @ctx_addr: context address
 * @ctx_len: context length
 *
 * This function outputs the contents of 'ctx_addr' to a seq_file according to
 * the specified format.
 * Each line in the file is 32 bits, and the number of lines is 'ctx_len / sizeof(u32)'.
 * If 'ctx_len' is not an integer multiple of 4, there will be truncation at the end.
 *
 * Context: Any context.
 */
void ubase_print_context_hw(struct seq_file *s, void *ctx_addr, u32 ctx_len)
{
	if (!s || !ctx_addr)
		return;

	__ubase_print_context_hw(s, ctx_addr, ctx_len);
}
EXPORT_SYMBOL(ubase_print_context_hw);

static int ubase_dbg_dump_ctx_hw(struct seq_file *s, void *data,
				 enum ubase_dbg_ctx_type ctx_type)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	struct ubase_ctx_info ctx_info = {0};
	struct ubase_cmd_mailbox *mailbox;
	struct ubase_mbx_attr attr;
	int ret = 0;
	u32 ctxn;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits) ||
	    test_bit(UBASE_STATE_RST_HANDLING_B, &udev->state_bits))
		return -EBUSY;

	if (!ubase_dev_mbx_supported(udev))
		return -EOPNOTSUPP;

	mailbox = __ubase_alloc_cmd_mailbox(udev);
	if (IS_ERR_OR_NULL(mailbox)) {
		ubase_err(udev,
			  "failed to alloc mailbox for dump hw context.\n");
		return -ENOMEM;
	}

	ubase_get_ctx_info(udev, ctx_type, &ctx_info);
	for (ctxn = 0; ctxn < ubase_get_ctx_num(udev, ctx_type); ctxn++) {
		ubase_fill_mbx_attr(&attr, ctxn + ctx_info.start_idx,
				    ctx_info.op, 0);

		ret = ubase_dev_mbx_supported(udev) ?
		      __ubase_hw_upgrade_ctx_ex(udev, &attr, mailbox) :
		      ubase_hw_upgrade_ctx_over_cmdq(udev, &attr, mailbox);
		if (ret) {
			ubase_err(udev,
				  "failed to post query %s ctx mbx, ret = %d.\n",
				  ctx_info.ctx_name, ret);
			goto upgrade_ctx_err;
		}

		seq_printf(s, "offset\t%s%u\n", ctx_info.ctx_name,
			   ctxn + ctx_info.start_idx);
		ubase_mask_ctx_key_words(mailbox->buf, ctx_type);
		__ubase_print_context_hw(s, mailbox->buf, ctx_info.ctx_size);
		seq_puts(s, "\n");
	}

upgrade_ctx_err:
	__ubase_free_cmd_mailbox(udev, mailbox);

	return ret;
}

int ubase_dbg_dump_aeq_context(struct seq_file *s, void *data)
{
	return ubase_dbg_dump_context(s, UBASE_DBG_AEQ_CTX);
}

int ubase_dbg_dump_ceq_context(struct seq_file *s, void *data)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	int ret;

	if (!mutex_trylock(&udev->irq_table.ceq_lock))
		return -EBUSY;

	if (!udev->irq_table.ceqs.ceq) {
		mutex_unlock(&udev->irq_table.ceq_lock);
		return -EBUSY;
	}

	ret = ubase_dbg_dump_context(s, UBASE_DBG_CEQ_CTX);
	mutex_unlock(&udev->irq_table.ceq_lock);

	return ret;
}

int ubase_dbg_dump_tpg_ctx(struct seq_file *s, void *data)
{
	struct ubase_dev *udev = dev_get_drvdata(s->private);
	int ret;

	if (!test_bit(UBASE_STATE_INITED_B, &udev->state_bits))
		return -EBUSY;

	if (!ubase_get_ctx_num(udev, UBASE_DBG_TPG_CTX))
		return -EOPNOTSUPP;

	if (!spin_trylock(&udev->tp_ctx.tpg_lock))
		return -EBUSY;

	if (!udev->tp_ctx.tpg) {
		spin_unlock(&udev->tp_ctx.tpg_lock);
		return -EBUSY;
	}

	ret = ubase_dbg_dump_context(s, UBASE_DBG_TPG_CTX);
	spin_unlock(&udev->tp_ctx.tpg_lock);

	return ret;
}

int ubase_dbg_dump_aeq_ctx_hw(struct seq_file *s, void *data)
{
	return ubase_dbg_dump_ctx_hw(s, data, UBASE_DBG_AEQ_CTX);
}

int ubase_dbg_dump_ceq_ctx_hw(struct seq_file *s, void *data)
{
	return ubase_dbg_dump_ctx_hw(s, data, UBASE_DBG_CEQ_CTX);
}
