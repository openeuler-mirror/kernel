// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include <linux/semaphore.h>
#include <linux/bitfield.h>
#include "grc_cqp.h"
#include "grc_main.h"

static void nbl_cmd_comp_handler(struct nbl_cmd *cmd, u32 idx,
				 enum nbl_comp_t comp_type);

static void nbl_cmd_kick_stat(struct nbl_cmd *cmd, int ret)
{
	mutex_lock(&cmd->cmd_stat_lock);
	if (ret)
		cmd->cmd_fail++;
	else
		cmd->cmd_succ++;
	cmd->cmd_total++;

	grc_pr_debug("[CQP] stat, total(%llu), succ(%llu), fail(%llu)\n",
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
	int ret = 0;

	spin_lock(&cmd->alloc_lock);
	if ((cmd->cmd_tail + 1) % cmd->cmd_max_num ==
	    cmd->cmd_head) { /* cmd queue is full */
		ret = -ENOMEM;
	} else {
		if (!cmd->cmd_tail) /* polarity change */
			cmd->valid_val ^= 1;
		*idx_p = cmd->cmd_tail;
		cmd->cmd_tail = (cmd->cmd_tail + 1) % cmd->cmd_max_num;
		*cur_tail_p = cmd->cmd_tail;
	}
	spin_unlock(&cmd->alloc_lock);
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
	bool idx_pass = false;

	spin_lock(&cmd->alloc_lock);

	/* idx judgement */
	if (cmd->cmd_tail > cmd->cmd_head) {
		if (idx >= cmd->cmd_head && idx < cmd->cmd_tail)
			idx_pass = true;
	} else if (cmd->cmd_tail < cmd->cmd_head) {
		if ((idx >= cmd->cmd_head && idx < cmd->cmd_max_num) || idx < cmd->cmd_tail)
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
		grc_pr_debug("after handle(index %u, head %u, tail %u, bitmap 0x%lx)",
			     idx, cmd->cmd_head, cmd->cmd_tail, *cmd->bit_mask);
	} else {
		grc_pr_err("cmd finish index err(index %u, head %u, tail %u, bitmap 0x%lx)",
			   idx, cmd->cmd_head, cmd->cmd_tail, *cmd->bit_mask);
	}
	spin_unlock(&cmd->alloc_lock);
}

static int cmd_check_entry(struct nbl_cmd *cmd, u32 idx)
{
	int ret = -EINVAL;

	spin_lock(&cmd->alloc_lock);
	if (cmd->cmd_tail > cmd->cmd_head) {
		if (idx >= cmd->cmd_head && idx < cmd->cmd_tail)
			ret = 0;
	} else if (cmd->cmd_tail < cmd->cmd_head) {
		if ((idx >= cmd->cmd_head && idx < cmd->cmd_max_num) || idx < cmd->cmd_tail)
			ret = 0;
	}
	spin_unlock(&cmd->alloc_lock);

	return ret;
}

static void cmd_ent_put(struct nbl_cmd_work_ent *ent)
{
	cmd_free_ent(ent);
}

static int alloc_cmd_page(struct nbl_core_dev_info *core_dev, struct nbl_cmd *cmd)
{
	struct device *dma_dev = NBL_COREDEV_TO_DMA_DEV(core_dev);

	cmd->cmd_alloc_buf =
		dma_alloc_coherent(dma_dev, NBL_ADAPTER_PAGE_SIZE,
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

	dma_free_coherent(dma_dev, NBL_ADAPTER_PAGE_SIZE,
			  cmd->cmd_alloc_buf, cmd->alloc_dma);
	cmd->cmd_alloc_buf = dma_alloc_coherent(dma_dev,
						2 * NBL_ADAPTER_PAGE_SIZE - 1,
						&cmd->alloc_dma, GFP_KERNEL);
	if (!cmd->cmd_alloc_buf)
		return -ENOMEM;

	cmd->cmd_buf = PTR_ALIGN(cmd->cmd_alloc_buf, NBL_ADAPTER_PAGE_SIZE);
	cmd->dma = ALIGN(cmd->alloc_dma, NBL_ADAPTER_PAGE_SIZE);
	cmd->alloc_size = 2 * NBL_ADAPTER_PAGE_SIZE - 1;
	return 0;
}

static void free_cmd_page(struct nbl_core_dev_info *core_dev, struct nbl_cmd *cmd)
{
	struct device *dma_dev = NBL_COREDEV_TO_DMA_DEV(core_dev);

	dma_free_coherent(dma_dev, cmd->alloc_size, cmd->cmd_alloc_buf,
			  cmd->alloc_dma);
}

static void poll_timeout(struct nbl_cmd_work_ent *ent)
{
	unsigned long poll_end =
		jiffies + msecs_to_jiffies(2 * NBL_CMD_TIMEOUT_MSEC);
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

static char *nbl_cmd_type2str(enum nbl_comp_t comp_type)
{
	switch (comp_type) {
	case NBL_CMD_COMP_TYPE_EVENT:
		return "event";
	case NBL_CMD_COMP_TYPE_FORCED:
		return "force";
	default:
		return "polling";
	}
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
		grc_pr_err("command completed whit index 0x%x is out of order\n", idx);
		return;
	}

	ent = cmd->ent_arr[idx];

	/* there is need to check if we already completed the command */
	if (!test_and_clear_bit(NBL_CMD_ENT_STATE_PENDING_COMP, &ent->state)) {
		grc_pr_err("command whit index 0x%x is completed again, give up\n", idx);
		return;
	}

	if (comp_type == NBL_CMD_COMP_TYPE_EVENT) /* check hw done state when event mode */
		poll_hw_done(ent);

	ent->ts2 = ktime_get_ns();

	if (!ent->ret) {
		if (ent->out) /* maybe user is not care about out */
			memcpy(ent->out, ent->lay->out.general.cmd_out, ent->out_size);
		ent->status =
			ent->lay->out.detail.wqe_done & NBL_CMD_OUT_ERRFLAG_BIT ?
			NBL_CMD_ENT_STATUS_ERR_VAL : 0;
		grc_pr_debug
			("command completed. ret 0x%x, delivery status (0x%x)\n",
			ent->ret, ent->status);
	}

	grc_pr_debug
		("[CQP] cmd(%u), type(%s), result(%d), time(%lld), 0x%02x-0x%02x-0x%02x-0x%02x\n",
		idx, nbl_cmd_type2str(comp_type),
		ent->ret, (ent->ts2 - ent->ts1),
		ent->lay->out.detail.wqe_done,
		ent->lay->out.detail.err_code,
		ent->lay->out.detail.consumer_index,
		ent->lay->out.detail.cmd_code);

	cmd_put_back_entry(ent->cmd, idx);
	complete(&ent->done);
	up(&cmd->sem);
}

static void cmd_work_handler(struct work_struct *work)
{
	struct nbl_cmd_work_ent *ent =
		container_of(work, struct nbl_cmd_work_ent, work);
	struct nbl_cmd *cmd = ent->cmd;
	struct nbl_cmd_layout *lay;
	bool poll_cmd = ent->polling;
	u32 entry_get = 0, cur_tail = 0, cqp_pi_val;
	u8 pi_db_odd;
	int cmd_mode, ret;
	struct nbl_grc *grc = cmd->grc;

	complete(&ent->handling);
	down(&cmd->sem);

	ret = cmd_get_next_entry(cmd, &entry_get, &cur_tail);
	if (ret != 0) {
		grc_pr_err("cqp full err\n");
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

	grc_pr_debug("[CQP] cmd handle get index(%u), cur tail(%u), cmd mode(%s), cmd polo(%u)\n",
		     entry_get, cur_tail, cmd->mode == CMD_MODE_POLLING ? "polling" : "interrupt",
		     cmd->valid_val);
	grc_pr_debug("      IN valid_interrupt=0x%x\n", lay->in.detail.valid_interrupt);

	grc_pr_debug("[CQP] write cqp wqe(%u) buf 0x%02x-0x%02x-0x%02x-0x%02x 0x%02x-0x%02x-0x%02x-0x%02x\n",
		     entry_get,
		     lay->in.detail.valid_interrupt,
		     lay->in.detail.cmd_code,
		     lay->in.detail.input_cmd_depend0[0],
		     lay->in.detail.input_cmd_depend0[1],
		     lay->in.detail.input_cmd_depend0[2],
		     lay->in.detail.input_cmd_depend0[3],
		     lay->in.detail.input_cmd_depend0[4],
		     lay->in.detail.input_cmd_depend0[5]);

	/* CQP PI doorbell */
	wmb();

	pi_db_odd = cmd->valid_val;
	if (cur_tail != 0)
		pi_db_odd ^= 1;
	cqp_pi_val = (u32)(FIELD_PREP(NBL_REG_CQPP_INFO_TABLE_RAM_PI_ODD, pi_db_odd) |
					FIELD_PREP(NBL_REG_CQPP_INFO_TABLE_RAM_PI, cur_tail));

	grc_pr_debug("writing (tail %u, odd %u) to command doorbell reg val(0x%x)\n",
		     cur_tail, pi_db_odd, cqp_pi_val);

	grc->ops->set_cqp_pi(&grc->core_dev, cur_tail, pi_db_odd);

	if (cmd_mode == CMD_MODE_POLLING || poll_cmd) {
		poll_timeout(ent);
		/* CQP PI doorbell */
		rmb();
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
		grc_pr_warn("cmd[%d]: finished after timeout\n",
			    ent->idx);
		return;
	}

	/* finally cmd is timeout */
	grc_pr_warn("cmd[%u]: Not done completion\n", ent->idx);
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

static int nbl_cmd_invoke(struct nbl_grc *grc, void *in, int in_size,
			  void *out, int out_size, u8 *status,
			  bool force_polling)
{
	struct nbl_cmd *cmd = &grc->cmd;
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
		grc_pr_warn("failed to queue work\n");
		err = -ENOMEM;
		goto out_free;
	}

	err = wait_func(ent);
	if (err != 0)
		goto out_free;

	ds = ent->ts2 - ent->ts1;
	grc_pr_debug("fw exec cmd time is %lld nsec\n", ds);
	*status = ent->status;

out_free:
	cmd_ent_put(ent);

	return err;
}

static int cmd_exec(struct nbl_grc *grc, void *in, int in_size, void *out,
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

	err = nbl_cmd_invoke(grc, in, in_size, out, out_size, &status,
			     force_polling);
	if (err)
		goto out_out;

	if (status)
		err = -EFAULT;

out_out:
	return err;
}

static void nbl_cmd_change_mod(struct nbl_grc *grc, int mode)
{
	struct nbl_cmd *cmd = &grc->cmd;
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

static int nbl_cmd_reg_init(struct nbl_grc *grc, bool enable)
{
	struct nbl_cmd *cmd = &grc->cmd;

	if (grc->has_high_temp_alarm)
		return 0;

	if (enable) {
		/* Write CQP info table reg */
		grc->ops->set_cqp_info(&grc->core_dev, NBL_RDMA_ADMIN_CQP_FUNCTION_NUM,
				cmd->dma, cmd->cmd_max_num, true);
		/* Write CQP base reg */
		grc->ops->set_cqp_base_reg(&grc->core_dev, NBL_RDMA_CQP_MAX_FUN_ID);
	} else {
		grc->ops->set_cqp_info(&grc->core_dev, NBL_RDMA_ADMIN_CQP_FUNCTION_NUM,
				cmd->dma, cmd->cmd_max_num, false);
	}

	return 0;
}

/**
 * grc_cmd_comp_notifier - called by AEQ only, AEQ call this when recv cmd finish interrupt
 * @grc: pointer to the nbl_grc structure
 * @cmd_index: cmd index in AEAE, AEQ get this field from AEQE
 */
void grc_cmd_comp_notifier(struct nbl_grc *grc, u32 cmd_index)
{
	struct nbl_cmd *cmd = &grc->cmd;
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
 * grc_cmd_use_events - called by AEQ only, when AEQ is ready call this change to event mode
 * @grc: pointer to the nbl_grc structure
 */
void grc_cmd_use_events(struct nbl_grc *grc)
{
	nbl_cmd_change_mod(grc, CMD_MODE_EVENTS);
}

/**
 * grc_cmd_use_polling - called by AEQ only, when AEQ is destroyed call this change to polling mode
 * @grc: pointer to the nbl_grc structure
 */
void grc_cmd_use_polling(struct nbl_grc *grc)
{
	nbl_cmd_change_mod(grc, CMD_MODE_POLLING);
}

/**
 * grc_cmd_exec - cmd execute and return the cmd execute result
 * @grc: pointer to the nbl_grc structure
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
int grc_cmd_exec(struct nbl_grc *grc, void *in, int in_size, void *out, int out_size)
{
	int err;

	if (grc->has_high_temp_alarm)
		return 0;

	err = cmd_exec(grc, in, in_size, out, out_size, false);
	nbl_cmd_kick_stat(&grc->cmd, err);
	return err;
}

int grc_cqp_init(struct nbl_grc *grc)
{
	struct nbl_cmd *cmd = &grc->cmd;
	u32 bit_mask_size;
	int err;

	memset(cmd, 0, sizeof(*cmd));
	cmd->grc = grc;
	err = alloc_cmd_page(&grc->core_dev, cmd);
	if (err) {
		grc_pr_err("failed to alloc cmd page\n");
		return err;
	}

	cmd->cmd_max_num = NBL_CMD_ENTRY_MAX_NUM;
	bit_mask_size = sizeof(unsigned long) * BITS_TO_LONGS(NBL_CMD_ENTRY_MAX_NUM);
	cmd->bit_mask = kzalloc(bit_mask_size, GFP_KERNEL);
	if (!cmd->bit_mask) {
		err = -ENOMEM;
		grc_pr_err("failed to alloc bit mask\n");
		goto err_free_page;
	}

	cmd->cmd_tail = 0;
	cmd->cmd_head = 0;
	cmd->cmd_entry_size = NBL_CMD_ENTRY_SIZE;
	cmd->cmd_entry_size_log = NBL_CMD_ENTRY_SIZE_LOG;
	cmd->valid_val = NBL_CMD_VALID_VAL_INIT;

	spin_lock_init(&cmd->alloc_lock);
	sema_init(&cmd->sem, (cmd->cmd_max_num - 1));

	cmd->mode = CMD_MODE_POLLING;

	/* hw reg init */
	err = nbl_cmd_reg_init(grc, true);
	if (err) {
		grc_pr_err("failed to init cqp reg\n");
		goto err_free_bitmask;
	}

	snprintf(cmd->wq_name, sizeof(cmd->wq_name), "nbl_cmd");
	cmd->wq = create_singlethread_workqueue(cmd->wq_name);
	if (!cmd->wq) {
		grc_pr_err("failed to create command workqueue\n");
		err = -ENOMEM;
		goto err_free_bitmask;
	}

#if NBL_CMD_INT_USE_WQ
	snprintf(cmd->cmpl_wq_name, sizeof(cmd->cmpl_wq_name), "cqp_cmpl");
	cmd->cmpl_wq = create_singlethread_workqueue(cmd->cmpl_wq_name);
	if (!cmd->cmpl_wq) {
		grc_pr_err("failed to create cqp interrupt workqueue\n");
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
err_free_bitmask:
	kfree(cmd->bit_mask);
err_free_page:
	free_cmd_page(&grc->core_dev, cmd);

	return err;
}

void grc_cqp_cleanup(struct nbl_grc *grc)
{
	struct nbl_cmd *cmd = &grc->cmd;
#if NBL_CMD_INT_USE_WQ
	destroy_workqueue(cmd->cmpl_wq);
#endif
	destroy_workqueue(cmd->wq);
	nbl_cmd_reg_init(grc, false);
	kfree(cmd->bit_mask);
	free_cmd_page(&grc->core_dev, cmd);
}
