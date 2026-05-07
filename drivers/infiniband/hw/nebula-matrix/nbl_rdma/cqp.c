// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include <linux/semaphore.h>
#include <linux/bitfield.h>
#include "cqp.h"
#include "grc.h"
#include "debug.h"
#include "mem.h"

static void nbl_cmd_comp_handler(struct nbl_cmd *cmd, u32 idx,
				 enum nbl_comp_t comp_type);

static void nbl_cqp_wqe_dump(u32 cmd_idx, bool input, u8 *buf, u32 len)
{
	char cqp_des[NBL_CMD_DEBUG_HEAD_LEN];

	pr_debug("%d\n",
		 snprintf(cqp_des, NBL_CMD_DEBUG_HEAD_LEN,
			  "cqp(%u)_%s: ", cmd_idx, input ? "_in" : "out"));
	print_hex_dump_debug(cqp_des, DUMP_PREFIX_NONE,
		NBL_CMD_DEBUG_ROW_SIZE, NBL_CMD_DEBUG_GROUP_SIZE, buf, len, false);
}

static void nbl_cmd_kick_stat(struct nbl_cmd *cmd, int ret)
{
	mutex_lock(&cmd->cmd_stat_lock);
	if (ret)
		cmd->cmd_fail++;
	else
		cmd->cmd_succ++;
	cmd->cmd_total++;

	nbl_ib_dbg(cmd->dev, "[CQP] stat, total(%llu), succ(%llu), fail(%llu)\n",
		cmd->cmd_total, cmd->cmd_succ, cmd->cmd_fail);

	mutex_unlock(&cmd->cmd_stat_lock);
}

static struct nbl_cmd_work_ent *cmd_alloc_ent(struct nbl_cmd *cmd, void *in,
					      int in_size, void *out,
					      int out_size)
{
	struct nbl_cmd_work_ent *ent;

	ent = kzalloc(sizeof(*ent), GFP_KERNEL);
	if (!ent)
		return ERR_PTR(-ENOMEM);

	ent->in = in;
	ent->in_size = in_size;
	ent->out = out;
	ent->out_size = out_size;
	ent->cmd = cmd;

	return ent;
}

static void cmd_free_ent(struct nbl_cmd_work_ent *ent)
{
	kfree(ent);
}

/**
 * cmd_get_next_entry - get next entry to use, and move the tail
 * @cmd:        in  parameter, command structure
 * @idx_p:      out parameter, the index which entry we will used to write command
 * @cur_tail_p: out parameter, the tail after we get a command entry
 * Return:      return 0 is success, other value if fail
 */
static int cmd_get_next_entry(struct nbl_cmd *cmd, u32 *idx_p, u32 *cur_tail_p)
{
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&cmd->alloc_lock, flags);
	if ((cmd->cmd_tail + 1) % cmd->cmd_max_num ==
	    cmd->cmd_head) /* cmd queue is full */
		ret = -ENOMEM;
	else {
		if (!cmd->cmd_tail) /* polarity change */
			cmd->valid_val ^= 1;
		*idx_p = cmd->cmd_tail;
		cmd->cmd_tail = (cmd->cmd_tail + 1) % cmd->cmd_max_num;
		*cur_tail_p = cmd->cmd_tail;
	}
	spin_unlock_irqrestore(&cmd->alloc_lock, flags);
	return ret;
}

/**
 * cmd_put_back_entry - after command finish, move the head
 * @cmd:   in parameter, command structure
 * @idx:   in parameter, the index which entry we put back
 * Return: return 0 is success, other value if fail
 */
static void cmd_put_back_entry(struct nbl_cmd *cmd, u32 idx)
{
	unsigned long flags;
	bool idx_pass = false;

	spin_lock_irqsave(&cmd->alloc_lock, flags);

	/* idx judgement */
	if (cmd->cmd_tail > cmd->cmd_head) {
		if (idx >= cmd->cmd_head && idx < cmd->cmd_tail)
			idx_pass = true;
	} else if (cmd->cmd_tail < cmd->cmd_head) {
		if ((idx >= cmd->cmd_head && idx < cmd->cmd_max_num)
			|| idx < cmd->cmd_tail)
			idx_pass = true;
	}

	if (idx_pass) {
		set_bit(idx, cmd->bit_mask); /* set idx bit, means idx already come back */
		while (cmd->cmd_head != cmd->cmd_tail) {
			/* if cmd_head bit in bit_mask is set, means already come back, move head,
			 * but attention, maybe a cmd come late(some later cmd already come back)
			 * so here need loop check bit_mast till one bit is not set(cmd not back)
			 */
			if (test_and_clear_bit(cmd->cmd_head, cmd->bit_mask))
				cmd->cmd_head = (cmd->cmd_head + 1) % cmd->cmd_max_num;
			else
				break;
		}
		nbl_ib_dbg(
			cmd->dev,
			"after handle(index %u, head %u, tail %u, bitmap 0x%lx)",
			idx, cmd->cmd_head, cmd->cmd_tail, *cmd->bit_mask);
	} else {
		nbl_ib_err(
			cmd->dev,
			"cmd finish index err(index %u, head %u, tail %u, bitmap 0x%lx)",
			idx, cmd->cmd_head, cmd->cmd_tail, *cmd->bit_mask);
	}
	spin_unlock_irqrestore(&cmd->alloc_lock, flags);
}

static int cmd_check_entry(struct nbl_cmd *cmd, u32 idx)
{
	unsigned long flags;
	int ret = -EINVAL;

	spin_lock_irqsave(&cmd->alloc_lock, flags);
	if (cmd->cmd_tail > cmd->cmd_head) {
		if (idx >= cmd->cmd_head && idx < cmd->cmd_tail)
			ret = 0;
	} else if (cmd->cmd_tail < cmd->cmd_head) {
		if ((idx >= cmd->cmd_head && idx < cmd->cmd_max_num)
			|| idx < cmd->cmd_tail)
			ret = 0;
	}
	spin_unlock_irqrestore(&cmd->alloc_lock, flags);

	return ret;
}

static void cmd_ent_put(struct nbl_cmd_work_ent *ent)
{
	cmd_free_ent(ent);
}

static int alloc_cmd_page(struct nbl_pci_f *rf, struct nbl_cmd *cmd)
{
	struct nbl_sc_dev *dev = &rf->sc_dev;

	cmd->cmd_alloc_buf =
		nbl_dma_alloc_coherent(dev->hw->device, NBL_ADAPTER_PAGE_SIZE,
				   &cmd->alloc_dma, GFP_KERNEL);
	if (!cmd->cmd_alloc_buf)
		return -ENOMEM;

	/* make sure it is aligned to 4K */
	if (!((uintptr_t)cmd->cmd_alloc_buf & (NBL_ADAPTER_PAGE_SIZE - 1))) {
		cmd->cmd_buf = cmd->cmd_alloc_buf;
		cmd->dma = cmd->alloc_dma;
		cmd->alloc_size = NBL_ADAPTER_PAGE_SIZE;
		return 0;
	}

	dma_free_coherent(dev->hw->device, NBL_ADAPTER_PAGE_SIZE,
			  cmd->cmd_alloc_buf, cmd->alloc_dma);
	cmd->cmd_alloc_buf = nbl_dma_alloc_coherent(dev->hw->device,
						2 * NBL_ADAPTER_PAGE_SIZE - 1,
						&cmd->alloc_dma, GFP_KERNEL);
	if (!cmd->cmd_alloc_buf)
		return -ENOMEM;

	cmd->cmd_buf = PTR_ALIGN(cmd->cmd_alloc_buf, NBL_ADAPTER_PAGE_SIZE);
	cmd->dma = ALIGN(cmd->alloc_dma, NBL_ADAPTER_PAGE_SIZE);
	cmd->alloc_size = 2 * NBL_ADAPTER_PAGE_SIZE - 1;
	return 0;
}

static void free_cmd_page(struct nbl_pci_f *rf, struct nbl_cmd *cmd)
{
	struct nbl_sc_dev *dev = &rf->sc_dev;

	dma_free_coherent(dev->hw->device, cmd->alloc_size, cmd->cmd_alloc_buf,
			  cmd->alloc_dma);
}

static void poll_timeout(struct nbl_cmd_work_ent *ent)
{
	unsigned long poll_end =
		jiffies + msecs_to_jiffies(NBL_CMD_TIMEOUT_MSEC);
	u8 done, done_val;

	done_val = ent->valid_val ? NBL_CMD_OUT_WQEDONE_BIT : 0;
	do {
		done = READ_ONCE(ent->lay->out.detail.wqe_done);
		if ((done & NBL_CMD_OUT_WQEDONE_BIT) == done_val) {
			ent->ret = 0;
			return;
		}
		cond_resched();
	} while (time_before(jiffies, poll_end));

	ent->ret = -ETIMEDOUT;
}

static void poll_hw_done(struct nbl_cmd_work_ent *ent)
{
	u8 done, done_val;

	done_val = ent->valid_val ? NBL_CMD_OUT_WQEDONE_BIT : 0;
	done = READ_ONCE(ent->lay->out.detail.wqe_done);
	if ((done & NBL_CMD_OUT_WQEDONE_BIT) == done_val)
		ent->ret = 0;
	else
		ent->ret = -EINTR;
}

static struct nbl_cmd_layout *get_inst(struct nbl_cmd *cmd, u32 idx)
{
	return cmd->cmd_buf + (idx << cmd->cmd_entry_size_log);
}

static void nbl_cmd_comp_handler(struct nbl_cmd *cmd, u32 idx,
				 enum nbl_comp_t comp_type)
{
	struct nbl_cmd_work_ent *ent;

	/* make sure the idx is legal, here is very important, because in the
	 * interrupt mode, the interrupt maybe come very late, so we need to check the idx
	 * but there maybe come a idx just seems legal, should we add seqNum check , TODO
	 */
	if (cmd_check_entry(cmd, idx) != 0) {
		nbl_ib_err(
			cmd->dev,
			"command completed whit index 0x%x is out of order\n",
			idx);
		return;
	}

	ent = cmd->ent_arr[idx];

	/* there is need to check if we already completed the command */
	if (!test_and_clear_bit(NBL_CMD_ENT_STATE_PENDING_COMP, &ent->state)) {
		nbl_ib_err(
			cmd->dev,
			"command whit index 0x%x is completed again, give up\n",
			idx);
		return;
	}

	if (comp_type == NBL_CMD_COMP_TYPE_EVENT) {
		if (cmd->mode == CMD_MODE_POLLING || ent->polling) {
			/* get cmd finish event from ae when polling mode, must something wrong */
			nbl_ib_err(
				cmd->dev,
				"command(%u) complete with ae event when polling mode\n",
				idx);
			return;
		}
		poll_hw_done(ent); /* check hw done state when event mode */
	}

	ent->ts2 = ktime_get_ns();

	if (!ent->ret) {
		if (ent->out) /* maybe user is not care about out */
			memcpy(ent->out, ent->lay->out.general.cmd_out, ent->out_size);
		ent->status =
			ent->lay->out.detail.wqe_done & NBL_CMD_OUT_ERRFLAG_BIT ?
			NBL_CMD_ENT_STATUS_ERR_VAL : 0;
		nbl_ib_dbg(
			cmd->dev,
			"command completed. ret 0x%x, delivery status (0x%x)\n",
			ent->ret, ent->status);
	}

	if (ent->lay->out.detail.wqe_done & NBL_CMD_OUT_ERRFLAG_BIT) {
		nbl_ib_err(cmd->dev,
			"[CQP] cmd(%u), type(%s), result(%d), time(%lld)\n",
			idx, NBM_CMD_TYPE2STR(comp_type),
			ent->ret, (ent->ts2 - ent->ts1));
		nbl_ib_err(cmd->dev,
			"[CQP] cmd(%u), done(0x%02x), errcode(0x%02x), ci(0x%02x), cmdcode(0x%02x)\n",
			idx, ent->lay->out.detail.wqe_done,
			ent->lay->out.detail.err_code,
			ent->lay->out.detail.consumer_index,
			ent->lay->out.detail.cmd_code);
	}

	nbl_cqp_wqe_dump(idx, false, (u8 *)(&ent->lay->out), NBL_CMD_OUTPUT_SIZE);

	cmd_put_back_entry(ent->cmd, idx);
	complete(&ent->done);
	up(&cmd->sem);
}

static void cmd_work_handler(struct work_struct *work)
{
	struct nbl_cmd_work_ent *ent =
		container_of(work, struct nbl_cmd_work_ent, work);
	struct nbl_cmd *cmd = ent->cmd;
	struct nbl_sc_dev *sc_dev = cmd->dev;
	struct nbl_cmd_layout *lay;
	bool poll_cmd = ent->polling;
	u64 cqp_pi_val;
	u32 entry_get = 0;
	u32 cur_tail = 0;
	u8 pi_db_odd;
	int cmd_mode, ret;

	complete(&ent->handling);
	down(&cmd->sem);

	ret = cmd_get_next_entry(cmd, &entry_get, &cur_tail);
	if (ret != 0) {
		nbl_ib_err(cmd->dev, "cqp full err\n");
		ent->ret = -EAGAIN;
		complete(&ent->done);
		up(&cmd->sem);
		return;
	}

	cmd_mode = cmd->mode;
	ent->valid_val = cmd->valid_val;
	ent->idx = entry_get;
	cmd->ent_arr[ent->idx] = ent;
	lay = get_inst(cmd, ent->idx);
	ent->lay = lay;
	/* here out can not be clear for hw reason */
	memcpy(lay->in.general.cmd_in, ent->in, sizeof(lay->in.general.cmd_in));
	if (ent->valid_val)
		lay->in.detail.valid_interrupt |= NBL_CMD_IN_WQEVALID_BIT;
	else
		lay->in.detail.valid_interrupt &= (~NBL_CMD_IN_WQEVALID_BIT);
	if (cmd_mode == CMD_MODE_POLLING || poll_cmd)
		lay->in.detail.valid_interrupt &= (~NBL_CMD_IN_WQEINTERUPT_BIT);
	else
		lay->in.detail.valid_interrupt |= NBL_CMD_IN_WQEINTERUPT_BIT;

	ent->ts1 = ktime_get_ns();

	set_bit(NBL_CMD_ENT_STATE_PENDING_COMP, &ent->state);

	nbl_ib_dbg(cmd->dev, "[CQP] cmd handle get index(%u), cur tail(%u), cmd mode(%s), cmd polo(%u)\n",
		entry_get, cur_tail,
		cmd->mode == CMD_MODE_POLLING ? "polling" : "interrupt",
		cmd->valid_val);
	nbl_ib_dbg(cmd->dev, "      IN valid_interrupt=0x%x\n", lay->in.detail.valid_interrupt);

	nbl_cqp_wqe_dump(entry_get, true, (u8 *)(&lay->in), NBL_CMD_INPUT_SIZE);

	/* CQP PI doorbell */
	wmb();

	pi_db_odd = cmd->valid_val;
	if (cur_tail != 0)
		pi_db_odd ^= 1;
	cqp_pi_val = (FIELD_PREP(NBL_REG_CQPP_INFO_TABLE_RAM_PI_ODD, pi_db_odd) |
					FIELD_PREP(NBL_REG_CQPP_INFO_TABLE_RAM_PI, cur_tail));

	nbl_ib_dbg(cmd->dev, "writing (tail %u, odd %u) to command doorbell reg val(0x%llx)\n",
		cur_tail, pi_db_odd, cqp_pi_val);

	write64_reg(cqp_pi_val, sc_dev->hw_regs[NBL_CQP_PI]);

	if (cmd_mode == CMD_MODE_POLLING || poll_cmd) {
		poll_timeout(ent);
		rmb(); /* barrier write pi */
		nbl_cmd_comp_handler(cmd, ent->idx,
				     ent->ret == -ETIMEDOUT ?
					     NBL_CMD_COMP_TYPE_FORCED :
					     NBL_CMD_COMP_TYPE_POLLING);
	}
}

static void wait_func_handle_exec_timeout(struct nbl_cmd_work_ent *ent)
{
	unsigned long timeout = msecs_to_jiffies(NBL_CMD_TIMEOUT_MSEC);

	/* Maybe here need some recover AEQ work, TODO */

	/* Re-wait a few time, maybe success */
	if (wait_for_completion_timeout(&ent->done, timeout)) {
		nbl_ib_warn(ent->cmd->dev, "cmd[%d]: finished after timeout\n",
			    ent->idx);
		return;
	}

	/* finally cmd is timeout */
	nbl_ib_warn(ent->cmd->dev, "cmd[%u]: Not done completion\n", ent->idx);
	ent->ret = -ETIMEDOUT;
	nbl_cmd_comp_handler(ent->cmd, ent->idx, NBL_CMD_COMP_TYPE_FORCED);
}

static int wait_func(struct nbl_cmd_work_ent *ent)
{
	unsigned long timeout_sch = msecs_to_jiffies(NBL_CMD_TIMEOUT_SCHEDULE);
	unsigned long timeout = msecs_to_jiffies(NBL_CMD_TIMEOUT_MSEC);
	struct nbl_cmd *cmd = ent->cmd;

	if (!wait_for_completion_timeout(&ent->handling, timeout_sch) &&
	    cancel_work_sync(&ent->work)) {
		ent->ret = -ECANCELED;
		goto out_err;
	}
	if (cmd->mode == CMD_MODE_POLLING || ent->polling)
		wait_for_completion(&ent->done);
	else if (!wait_for_completion_timeout(&ent->done, timeout))
		wait_func_handle_exec_timeout(ent);

out_err:
	return ent->ret;
}

static int nbl_cmd_invoke(struct nbl_pci_f *rf, void *in, int in_size,
			  void *out, int out_size, u8 *status,
			  bool force_polling)
{
	struct nbl_cmd *cmd = &rf->cmd;
	struct nbl_cmd_work_ent *ent;
	int err = 0;
	s64 ds;

	ent = cmd_alloc_ent(cmd, in, in_size, out, out_size);
	if (IS_ERR(ent))
		return PTR_ERR(ent);

	ent->polling = force_polling;

	init_completion(&ent->handling);
	init_completion(&ent->done);

	/* if we allow cmd more time(wait for interrupt), here we need add a delayed work */
	INIT_WORK(&ent->work, cmd_work_handler);

	if (!queue_work(cmd->wq, &ent->work)) {
		nbl_ib_warn(&rf->sc_dev, "failed to queue work\n");
		err = -ENOMEM;
		goto out_free;
	}

	err = wait_func(ent);
	if (err != 0)
		goto out_free;

	ds = ent->ts2 - ent->ts1;
	nbl_ib_dbg(&rf->sc_dev, "fw exec cmd time is %lld nsec\n", ds);
	*status = ent->status;

out_free:
	cmd_ent_put(ent);

	return err;
}

static int cmd_exec(struct nbl_pci_f *rf, void *in, int in_size, void *out,
		    int out_size, bool force_polling)
{
	int err;
	u8 status = 0;

	/* in should not be NULL, in_size must big enough to cover */
	if (!in || in_size < NBL_CMD_INPUT_SIZE)
		return -EINVAL;
	/* maybe out is not NULL, and we should check the out_size */
	if (out && out_size < NBL_CMD_OUTPUT_SIZE)
		return -EINVAL;

	err = nbl_cmd_invoke(rf, in, in_size, out, out_size, &status,
			     force_polling);
	if (err)
		goto out_out;

	if (status)
		err = -EFAULT;

out_out:
	return err;
}

static void nbl_cmd_change_mod(struct nbl_pci_f *rf, int mode)
{
	struct nbl_cmd *cmd = &rf->cmd;
	int i;

	for (i = 0; i < (cmd->cmd_max_num - 1); i++)
		down(&cmd->sem);

	cmd->mode = mode;

	for (i = 0; i < (cmd->cmd_max_num - 1); i++)
		up(&cmd->sem);
}

#if NBL_CMD_INT_USE_WQ
static void nbl_cmd_comp_worker(struct work_struct *work)
{
	struct cmpl_work *cwork = container_of(work, struct cmpl_work, work);
	struct nbl_cmd *cmd = cwork->cmd;
	u32 cmd_index = cwork->cmd_index;

	kfree(cwork);
	nbl_cmd_comp_handler(cmd, cmd_index, NBL_CMD_COMP_TYPE_EVENT);
}
#endif

static int nbl_cmd_reg_init(struct nbl_pci_f *rf, bool enable)
{
	struct nbl_cmd *cmd = &rf->cmd;
	u8 in[NBL_GRC_INPUT_SIZE];
	u8 out[NBL_GRC_OUTPUT_SIZE];
	int data_len = 0;
	struct cqp_init_req req = {0};
	int ret_val;
	struct grc_cache_msg_header *head;

	head = (struct grc_cache_msg_header *)in;
	if (sizeof(req) > NBL_GRC_INPUT_PAYLOAD_SIZE) {
		nbl_pr_err("cqp init grc with invalid payload length\n");
		return -EINVAL;
	}

	req.function_id = rf->sc_dev.function_id;
	req.enable = enable;
	req.phys_addr = cmd->dma;
	req.cmd_max_num = cmd->cmd_max_num;

	head->op_code = GRC_MSG_OP_CQP_INIT;
	head->payload_len = sizeof(struct cqp_init_req);
	data_len += sizeof(struct grc_cache_msg_header);

	memcpy(in + data_len, &req, sizeof(req));
	data_len += sizeof(req);

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val) {
		nbl_pr_err("cqp init grc cmd err=%d", ret_val);
		return ret_val;
	}

	return 0;
}

/**
 * nbl_cmd_comp_notifier - called by AEQ only, AEQ call this when recv cmd finish interrupt
 * @rf: pointer to the pci_f structure
 * @cmd_index: cmd index in AEAE, AEQ get this field from AEQE
 */
void nbl_cmd_comp_notifier(struct nbl_pci_f *rf, u32 cmd_index)
{
	struct nbl_cmd *cmd = &rf->cmd;
#if NBL_CMD_INT_USE_WQ
	struct cmpl_work *cwork;

	cwork = kzalloc(sizeof(*cwork), GFP_ATOMIC);
	if (!cwork)
		return;
	cwork->cmd = cmd;
	cwork->cmd_index = cmd_index;
	INIT_WORK(&cwork->work, nbl_cmd_comp_worker);
	queue_work(cmd->cmpl_wq, &cwork->work);
#else
	nbl_cmd_comp_handler(cmd, cmd_index, NBL_CMD_COMP_TYPE_EVENT);
#endif
}

/**
 * nbl_cmd_use_events - called by AEQ only, when AEQ is ready call this change to event mode
 * @rf: pointer to the pci_f structure
 */
void nbl_cmd_use_events(struct nbl_pci_f *rf)
{
	nbl_cmd_change_mod(rf, CMD_MODE_EVENTS);
}

/**
 * nbl_cmd_use_polling - called by AEQ only, when AEQ is destroyed call this change to polling mode
 * @rf: pointer to the pci_f structure
 */
void nbl_cmd_use_polling(struct nbl_pci_f *rf)
{
	nbl_cmd_change_mod(rf, CMD_MODE_POLLING);
}

/**
 * nbl_cmd_exec - cmd execute and return the cmd execute result
 * @rf: pointer to the pci_f structure
 * @in: cmd input, It's caller's responsibility to make sure the cmd input is Big Engine
 * @in_size: cmd input size, must be 64B
 * @out: cmd output, must use as Big Engine
 * @out_size: cmd output size, must be 64B
 * Return: return 0 for success,      out is filled.
 *         return -EFAULT for failed, out is filled.
 *                cmd is done but err is back from HW, check out for detail.
 *         return other for failed,   out is NOT filled.
 *                cmd is not done(maybe timeout), attention out is NOT filled.
 */
int nbl_cmd_exec(struct nbl_pci_f *rf, void *in, int in_size, void *out,
		 int out_size)
{
	int err;

	if (rf->sc_dev.has_high_temp_alarm)
		return 0;

	err = cmd_exec(rf, in, in_size, out, out_size, false);
	nbl_cmd_kick_stat(&rf->cmd, err);
	return err;
}

int nbl_cmd_exec_polling(struct nbl_pci_f *rf, void *in, int in_size, void *out,
			 int out_size)
{
	int err;

	err = cmd_exec(rf, in, in_size, out, out_size, true);
	nbl_cmd_kick_stat(&rf->cmd, err);
	return err;
}

int nbl_cmd_init(struct nbl_pci_f *rf)
{
	struct nbl_cmd *cmd = &rf->cmd;
	struct nbl_sc_dev *dev = &rf->sc_dev;
	u32 cmd_h, cmd_l;
	u32 bit_mask_size;
	int err;

	memset(cmd, 0, sizeof(*cmd));

	err = alloc_cmd_page(rf, cmd);
	if (err) {
		nbl_ib_err(dev, "failed to alloc cmd page\n");
		return err;
	}

	cmd->cmd_max_num = NBL_CMD_ENTRY_MAX_NUM;
	bit_mask_size = sizeof(unsigned long) * BITS_TO_LONGS(NBL_CMD_ENTRY_MAX_NUM);
	cmd->bit_mask = kzalloc(bit_mask_size, GFP_KERNEL);
	if (!cmd->bit_mask) {
		err = -ENOMEM;
		nbl_ib_err(dev, "failed to alloc bit mask\n");
		goto err_free_page;
	}

	cmd->cmd_tail = 0;
	cmd->cmd_head = 0;
	cmd->cmd_entry_size = NBL_CMD_ENTRY_SIZE;
	cmd->cmd_entry_size_log = NBL_CMD_ENTRY_SIZE_LOG;
	cmd->valid_val = NBL_CMD_VALID_VAL_INIT;

	spin_lock_init(&cmd->alloc_lock);
	sema_init(&cmd->sem, (cmd->cmd_max_num - 1));

	cmd_h = (u32)((u64)(cmd->dma) >> NBL_HALF_ADDR_SIZE_BITS);
	cmd_l = (u32)(cmd->dma);
	if (cmd_l & 0xfff) {
		nbl_ib_err(dev, "invalid command queue address\n");
		err = -ENOMEM;
		goto err_free_bitmask;
	}

	cmd->mode = CMD_MODE_POLLING;

	cmd->dev = &rf->sc_dev;

	/* hw reg init */
	err = nbl_cmd_reg_init(rf, true);
	if (err) {
		nbl_ib_err(dev, "failed to init cqp reg\n");
		goto err_free_bitmask;
	}

	snprintf(cmd->wq_name, sizeof(cmd->wq_name), "nbl_cmd");
	cmd->wq = create_singlethread_workqueue(cmd->wq_name);
	if (!cmd->wq) {
		nbl_ib_err(dev, "failed to create command workqueue\n");
		err = -ENOMEM;
		goto err_clr_reg;
	}

#if NBL_CMD_INT_USE_WQ
	snprintf(cmd->cmpl_wq_name, sizeof(cmd->cmpl_wq_name), "cqp_cmpl");
	cmd->cmpl_wq = create_singlethread_workqueue(cmd->cmpl_wq_name);
	if (!cmd->cmpl_wq) {
		nbl_ib_err(dev, "failed to create cqp interrupt workqueue\n");
		err = -ENOMEM;
		goto err_free_wq;
	}
#endif

	cmd->cmd_total = 0;
	cmd->cmd_succ = 0;
	cmd->cmd_fail = 0;
	mutex_init(&cmd->cmd_stat_lock);

	return 0;

#if NBL_CMD_INT_USE_WQ
err_free_wq:
	destroy_workqueue(cmd->wq);
#endif
err_clr_reg:
	nbl_cmd_reg_init(rf, false);
err_free_bitmask:
	kfree(cmd->bit_mask);
err_free_page:
	free_cmd_page(rf, cmd);

	return err;
}

void nbl_cmd_cleanup(struct nbl_pci_f *rf)
{
	struct nbl_cmd *cmd = &rf->cmd;
#if NBL_CMD_INT_USE_WQ
	destroy_workqueue(cmd->cmpl_wq);
#endif
	destroy_workqueue(cmd->wq);
	nbl_cmd_reg_init(rf, false);
	kfree(cmd->bit_mask);
	free_cmd_page(rf, cmd);
}
