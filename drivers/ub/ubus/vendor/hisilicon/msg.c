// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt) "ubus hisi msg: " fmt

#include <linux/delay.h>

#include "../../ubus.h"
#include "../../msg.h"
#include "../../enum.h"
#include "vdm.h"
#include "hisi-msg.h"

#define MSGQ_INT1 1
#define to_ub_bus_controller(d) container_of(d, struct ub_bus_controller, dev)

struct hi_msg_sqe_pld {
	char packet[HI_MSG_SQE_PLD_SIZE];
};

struct timeout_msg_info {
	struct list_head node;
	u16 msn;
	u8 task_type;
	u8 age;
};
#define TIMEOUT_MSG_INFO_SZ sizeof(struct timeout_msg_info)

struct hi_message_device {
	struct hi_msg_core hmc;
	struct timer_list poll_timer;
	struct timer_list timeout_msg_timer;
	struct list_head timeout_msg_list;
	spinlock_t timeout_msg_lock;
	struct hi_cqe_state *cqe_state;
	atomic_t msg_in_flight_cnt;
	struct message_device mdev;
};

#define to_hi_message_device(dev) \
	container_of(dev, struct hi_message_device, mdev)

enum hi_cq_sw_state { CQ_SW_INIT, CQ_SW_HANDLED };

struct hi_cqe_state {
	u8 state;
	u8 age;
};
#define HI_CQE_STATE_SZ sizeof(struct hi_cqe_state)

static inline void cqe_state_set(struct hi_message_device *hmd, int idx,
				 u8 state)
{
	hmd->cqe_state[idx].state = state;
	hmd->cqe_state[idx].age = 0;
}
#define cqe_state_get(hmd, idx) ((hmd)->cqe_state[idx].state)
#define cqe_age_inc(hmd, idx) (((hmd)->cqe_state[idx].age)++)
#define cqe_age_get(hmd, idx) ((hmd)->cqe_state[idx].age)

#define HI_MSG_CQ_POLL_PERIOD		100
#define HI_TIMEOUT_MSG_POLL_PERIOD	500
#define HI_MSG_AGING_PERIOD		2
#define MAX_CQ_POLL_PER_TIME		64

#define MSG_MAX (HI_SQ_CFG_DEPTH - 1)
#define q_left_cnt(q) ((q)->depth - q_used_cnt((q)) - 1)
#define sq_sw_left(hmd) (MSG_MAX - atomic_read(&(hmd)->msg_in_flight_cnt))
#define sq_pld_entry_off(hmd, idx) \
	((HI_MSG_SQE_SIZE * HI_SQ_CFG_DEPTH) + (HI_MSG_SQE_PLD_SIZE * (idx)))
#define sq_pld_entry_sw(hmd, idx)                                   \
	((void *)&((hmd)->hmc.queue[MSG_SQ].sqe[HI_SQ_CFG_DEPTH]) + \
	 (HI_MSG_SQE_PLD_SIZE * (idx)))

#define MSGQ_TIMEOUT (HZ * msg_wait / 1000)

#define MSN_SIZE 65535
DEFINE_SPINLOCK(msn_msg_lock);
DECLARE_BITMAP(msn_msg, MSN_SIZE);
DEFINE_SPINLOCK(msn_enum_lock);
DECLARE_BITMAP(msn_enum, MSN_SIZE);
DEFINE_SPINLOCK(msn_private_lock);
DECLARE_BITMAP(msn_private, MSN_SIZE);

/* Return 0 represents failure, return 1-65535 represents success */
static u16 hi_msn_get(int type)
{
	unsigned long flags, find, tmp, size, *addr;
	static u16 msn[TASK_TYPE_NUM] = {};
	spinlock_t *lock;
	u16 ret;

	find = msn[type];

	if (type == PROTOCOL_MSG) {
		addr = msn_msg;
		lock = &msn_msg_lock;
	} else if (type == PROTOCOL_ENUM) {
		addr = msn_enum;
		lock = &msn_enum_lock;
	} else { /* hisi private */
		addr = msn_private;
		lock = &msn_private_lock;
	}

	spin_lock_irqsave(lock, flags);
	if (unlikely(test_bit(find, addr))) {
		size = MSN_SIZE;
		tmp = find;
		find = find_next_zero_bit(addr, size, find);
		if (unlikely(find == size)) {
			size = tmp;
			find = find_next_zero_bit(addr, size, 0);
			if (unlikely(find == size)) {
				ret = 0;
				goto out;
			}
		}
	}

	set_bit(find, addr);
	msn[type] = (find + 1) % MSN_SIZE;
	ret = find + 1; /* find bit is 0~65534, ret use 1~65535 */
out:
	spin_unlock_irqrestore(lock, flags);
	return ret;
}

static void hi_msn_put(int type, u16 msn)
{
	unsigned long flags, *addr;
	spinlock_t *lock;

	if (msn == 0 || type >= TASK_TYPE_NUM) {
		pr_warn("invalid msn or type\n");
		return;
	}

	if (type == PROTOCOL_MSG) {
		addr = msn_msg;
		lock = &msn_msg_lock;
	} else if (type == PROTOCOL_ENUM) {
		addr = msn_enum;
		lock = &msn_enum_lock;
	} else { /* hisi private */
		addr = msn_private;
		lock = &msn_private_lock;
	}

	spin_lock_irqsave(lock, flags);
	clear_bit(msn - 1, addr);
	spin_unlock_irqrestore(lock, flags);
}

static void hi_msgq_hw_status(struct hi_msg_core *hmc)
{
	dev_err_ratelimited(
		hmc->dev, "sq pi=%#04x, ci=%#04x\ncq pi=%#04x, ci=%#04x\nrq pi=%#04x, ci=%#04x\n",
		hi_msg_reg_read(hmc, SQ_PI), hi_msg_reg_read(hmc, SQ_CI),
		hi_msg_reg_read(hmc, CQ_PI), hi_msg_reg_read(hmc, CQ_CI),
		hi_msg_reg_read(hmc, RQ_PI), hi_msg_reg_read(hmc, RQ_CI));
}

static void hi_msgq_sw_status(struct hi_message_device *hmd)
{
	dev_err_ratelimited(hmd->hmc.dev, "sq in flight msg:%d\n",
			    atomic_read(&hmd->msg_in_flight_cnt));
}

static void hi_msgq_status(struct hi_message_device *hmd)
{
	hi_msgq_hw_status(&hmd->hmc);
	hi_msgq_sw_status(hmd);
}

static int hi_msg_get_sq_idle_num(struct hi_message_device *hmd, int num,
				  bool tx)
{
	struct hi_msg_queue *sq = &hmd->hmc.queue[MSG_SQ];
	int real, sw_left, hw_left;

	hw_left = q_left_cnt(sq);
	sw_left = sq_sw_left(hmd);
	real = num;

	/* Assure message in flight not overflow, just tx need check */
	if (tx && real > sw_left)
		real = sw_left;

	/* If not enough, update ci by read hardware */
	if (real > hw_left) {
		sq->ci = hi_msg_reg_read(&hmd->hmc, SQ_CI);
		hw_left = q_left_cnt(sq);
		if (real > hw_left)
			real = hw_left;
	}

	return real;
}

static int hi_msg_sq_submit(struct hi_message_device *hmd,
			    struct hi_msg_sqe *sqe, struct hi_msg_sqe_pld *pld,
			    int num, bool wait)
{
	struct hi_msg_queue *sq = &hmd->hmc.queue[MSG_SQ];
	struct hi_msg_core *hmc = &hmd->hmc;
	struct hi_msg_sqe *tar_sqe;
	unsigned long flags;
	int i, real;
	u16 sqe_idx;

	spin_lock_irqsave(&sq->lock, flags);

	real = hi_msg_get_sq_idle_num(hmd, num, wait);
	if (!real) {
		spin_unlock_irqrestore(&sq->lock, flags);
		return 0;
	}

	for (i = 0; i < real; i++) {
		sqe_idx = q_ptr_idx(sq, pi, i);
		tar_sqe = sq->sqe + sqe_idx;
		(sqe + i)->p_addr = sq_pld_entry_off(hmd, sqe_idx);
		memcpy(tar_sqe, sqe + i, HI_MSG_SQE_SIZE);
		memcpy(sq_pld_entry_sw(hmd, sqe_idx), pld[i].packet,
		       (sqe + i)->p_len);
	}

	sq->pi = q_ptr_idx(sq, pi, real);
	wmb(); /* Ensure the register is written correctly. */
	hi_msg_reg_write(hmc, SQ_PI, sq->pi);
	if (wait)
		atomic_add(real, &hmd->msg_in_flight_cnt);

	spin_unlock_irqrestore(&sq->lock, flags);

	return real;
}

static int hi_msg_sync_wait(struct hi_message_device *hmd, int task_type,
			    u16 msn, u64 duration, bool flag)
{
#define SLEEP_MIN_US 1000
#define SLEEP_MAX_US 2000
	u64 end_time = get_jiffies_64() + duration;
	struct timeout_msg_info *timeout_msg;
	struct hi_msg_core *hmc = &hmd->hmc;
	unsigned long flags;
	int idx;

	do {
		idx = hi_msg_cq_poll(hmc, task_type, msn);
		if (idx >= 0)
			return idx;

		if (flag)
			usleep_range(SLEEP_MIN_US, SLEEP_MAX_US);
	} while (!time_after64(get_jiffies_64(), end_time));

	timeout_msg = kzalloc(TIMEOUT_MSG_INFO_SZ, GFP_ATOMIC);
	if (!timeout_msg)
		return -ENOMEM;

	timeout_msg->task_type = task_type;
	timeout_msg->msn = msn;
	spin_lock_irqsave(&hmd->timeout_msg_lock, flags);
	list_add_tail(&timeout_msg->node, &hmd->timeout_msg_list);
	spin_unlock_irqrestore(&hmd->timeout_msg_lock, flags);
	dev_err(hmc->dev, "task %d msn %#x wait cqe timeout\n", task_type, msn);
	return -ETIMEDOUT;
}

static bool hi_msg_has_rx(struct hi_message_device *hmd, int ci, int pi)
{
	struct hi_msg_queue *cq = &hmd->hmc.queue[MSG_CQ];
	struct hi_msg_core *hmc = &hmd->hmc;
	struct hi_msg_cqe *cqe;
	int depth, cnt, i, idx;

	depth = hmc->queue[MSG_CQ].depth;
	cnt = (pi + depth - ci) % depth;

	for (i = 0; i < cnt; i++) {
		idx = q_ptr_idx(cq, ci, i);
		cqe = cq_entry(hmc, idx);
		if (cqe_state_get(hmd, idx) != CQ_SW_HANDLED &&
		    cqe->task_type == PROTOCOL_MSG && cqe->type == MSG_REQ)
			return true;
	}

	return false;
}

static void hi_msg_cq_update(struct hi_message_device *hmd)
{
	struct hi_msg_queue *cq = &hmd->hmc.queue[MSG_CQ];
	struct hi_msg_core *hmc = &hmd->hmc;
	int i, cnt, idx, release_cnt = 0;
	struct hi_msg_cqe *cqe;
	unsigned long flags;
	u32 cq_pi;

	spin_lock_irqsave(&cq->lock, flags);
	if (cq->ci == cq->pi) {
		spin_unlock_irqrestore(&cq->lock, flags);
		return;
	}

	cnt = q_used_cnt(cq);
	for (i = 0; i < cnt; i++) {
		idx = q_ptr_idx(cq, ci, i);
		if (cqe_state_get(hmd, idx) != CQ_SW_HANDLED)
			break;

		cqe = cq_entry(hmc, idx);
		if (cqe->task_type != PROTOCOL_MSG || cqe->type == MSG_RSP) {
			hi_msn_put(cqe->task_type, cqe->msn);
			release_cnt++;
		}

		cqe_state_set(hmd, idx, CQ_SW_INIT);
	}
	if (i == 0) {
		spin_unlock_irqrestore(&cq->lock, flags);
		return;
	}

	hi_msg_rq_update(hmc, q_ptr_idx(cq, ci, i - 1));

	cq->ci = q_ptr_idx(cq, ci, i);
	wmb(); /* Ensure the register is written correctly. */
	hi_msg_reg_write(hmc, CQ_CI, cq->ci);
	atomic_sub(release_cnt, &hmd->msg_in_flight_cnt);

	if (atomic_read(&hmc->cq_int_mask)) {
		/* Get newest pi, but not store in cq->pi */
		cq_pi = hi_msg_reg_read(hmc, CQ_PI);
		/* Check really need open interrupt */
		if (cq_pi == cq->ci || hi_msg_has_rx(hmd, cq->ci, cq_pi)) {
			hi_msg_reg_write(hmc, CQ_INT_STATUS, 0x1);
			/* spi line interrupt, unmask during _irqsave no impact */
			hi_msg_reg_write(hmc, CQ_INT_MASK, 0x0);
			atomic_set(&hmc->cq_int_mask, 0);
		}
	}

	spin_unlock_irqrestore(&cq->lock, flags);
}

static int hi_msg_cq_poller(struct hi_message_device *hmd)
{
	struct ub_bus_controller *ubc = to_ub_bus_controller(hmd->hmc.dev);
	struct hi_msg_queue *cq = &hmd->hmc.queue[MSG_CQ];
	int cqe_cnt, i, idx, ret, handled_cnt = 0;
	struct hi_msg_core *hmc = &hmd->hmc;
	struct hi_msg_cqe *cqe;
	unsigned long flags;

	spin_lock_irqsave(&cq->lock, flags);
	cq->pi = hi_msg_reg_read(hmc, CQ_PI);
	if (cq->pi == cq->ci) {
		spin_unlock_irqrestore(&cq->lock, flags);
		return -EAGAIN;
	}

	cqe_cnt = q_used_cnt(cq);
	for (i = 0; i < cqe_cnt; i++) {
		idx = q_ptr_idx(cq, ci, i);
		cqe = cq_entry(hmc, idx);

		if (cqe_state_get(hmd, idx) == CQ_SW_HANDLED)
			continue;

		/* Now, just msg type has rx */
		if (cqe->task_type != PROTOCOL_MSG || cqe->type != MSG_REQ)
			continue;

		if (cqe->p_len > HI_MSG_RQE_SIZE) {
			dev_err(hmc->dev, "poller cqe p_len invalid\n");
			ub_msg_dump_cq(cqe, NULL);
			goto handled;
		}

		ret = message_rx_handler(ubc, rq_entry(hmc, cqe->rq_pi),
					 cqe->p_len);
		if (ret) {
			dev_err(hmc->dev, "poller rx msg failed, ret=%d\n", ret);
			ub_msg_dump_cq(cqe, rq_entry(hmc, cqe->rq_pi));
		}
handled:
		cqe_state_set(hmd, idx, CQ_SW_HANDLED);
		handled_cnt++;
		if (handled_cnt == MAX_CQ_POLL_PER_TIME)
			break;
	}

	spin_unlock_irqrestore(&cq->lock, flags);
	return handled_cnt;
}

static void hi_msg_cq_handle_poll_timer(struct timer_list *timer)
{
	struct hi_message_device *hmd;

	hmd = container_of(timer, struct hi_message_device, poll_timer);
	if (hi_msg_cq_poller(hmd) > 0)
		hi_msg_cq_update(hmd);
	mod_timer(timer, jiffies + msecs_to_jiffies(HI_MSG_CQ_POLL_PERIOD));
}

static void hi_msg_cq_poller_init(struct hi_message_device *hmd)
{
	if (hmd->hmc.virq)
		return;

	struct timer_list *poll_timer = &hmd->poll_timer;

	timer_setup(poll_timer, hi_msg_cq_handle_poll_timer, 0);
	poll_timer->expires = jiffies + msecs_to_jiffies(HI_MSG_CQ_POLL_PERIOD);
	add_timer(poll_timer);
}

static void hi_msg_cq_poller_uninit(struct hi_message_device *hmd)
{
	if (hmd->hmc.virq)
		return;

	struct timer_list *poll_timer = &hmd->poll_timer;

	timer_shutdown_sync(poll_timer);
}

static int hi_msg_queue_init(struct hi_message_device *hmd)
{
	struct hi_msg_core *hmc = &hmd->hmc;
	size_t size;
	int ret;

	size = HI_CQE_STATE_SZ * HI_CQ_CFG_DEPTH;
	hmd->cqe_state = kzalloc(size, GFP_KERNEL);
	if (!hmd->cqe_state) {
		dev_err(hmc->dev, "cqe state memory failed\n");
		return -ENOMEM;
	}

	ret = hi_msg_core_init(hmc, MSGQ_USER_BUS_DRV);
	if (ret) {
		kfree(hmd->cqe_state);
		hmd->cqe_state = NULL;
		return ret;
	}

	hi_msg_cq_poller_init(hmd);

	return 0;
}

static void hi_msg_queue_uninit(struct hi_message_device *hmd)
{
	hi_msg_cq_poller_uninit(hmd);
	hi_msg_core_uninit(&hmd->hmc);
	kfree(hmd->cqe_state);
}

static bool pkt_plen_valid(void *pkt, u16 pkt_size, int task_type)
{
	struct msg_pkt_header *header = (struct msg_pkt_header *)pkt;

	if (pkt_size > HI_MSG_SQE_PLD_SIZE) {
		pr_err("pkt_size %#x over\n", pkt_size);
		return false;
	}

	if (task_type == PROTOCOL_MSG &&
	    ((pkt_size < MSG_PKT_HEADER_SIZE) ||
	     (header->msgetah.plen > PLD_SIZE_MAX) ||
	     (header->msgetah.plen != (pkt_size - MSG_PKT_HEADER_SIZE)))) {
		pr_err("msg plen %#x, pkt_size %#x invalid\n",
		       header->msgetah.plen, pkt_size);
		return false;
	}

	if (task_type == PROTOCOL_ENUM &&
	    ((pkt_size < ENUM_PKT_HEADER_SIZE) ||
	     (pkt_size - ENUM_PKT_HEADER_SIZE > PLD_SIZE_MAX))) {
		pr_err("enum pkt_size %#x invalid\n", pkt_size);
		return false;
	}

	return true;
}

static int hi_message_sync(struct message_device *mdev, struct msg_info *info,
			   int task_type, u8 code, bool flag)
{
	struct hi_message_device *hmd = to_hi_message_device(mdev);
	struct hi_msg_core *hmc = &hmd->hmc;
	struct hi_msg_sqe sqe = {};
	struct hi_msg_cqe *cqe;
	int ret, msn, cnt;
	int cq_idx;

	if (!pkt_plen_valid(info->req_packet, info->req_pkt_size, task_type))
		return -EINVAL;

	msn = hi_msn_get(task_type);
	if (msn == 0) {
		dev_err(hmc->dev, "task type %d alloc msn failed\n", task_type);
		return -ENOSPC;
	}

	hi_msg_sqe_init(&sqe, msn, info, task_type, code);
	hi_msg_set_pkt_msn(info, task_type, msn, hmc->user);

	cnt = hi_msg_sq_submit(
		hmd, &sqe, (struct hi_msg_sqe_pld *)info->req_packet, 1, true);
	if (cnt != 1) {
		dev_err(hmc->dev, "sq submit failed\n");
		hi_msgq_status(hmd);
		hi_msn_put(task_type, msn);
		return -ENOSPC;
	}

	cq_idx = hi_msg_sync_wait(hmd, task_type, msn, MSGQ_TIMEOUT, flag);
	if (cq_idx < 0) {
		if (cq_idx == -ENOMEM)
			hi_msn_put(task_type, msn);
		ub_msg_dump_sq(&sqe, info->req_packet);
		return cq_idx;
	}

	cqe = cq_entry(hmc, cq_idx);
	ret = hi_message_cqe_check(hmc->dev, &sqe, cqe, info->rsp_pkt_size);
	if (!ret) {
		hi_msg_rqe_get(hmc, info->rsp_packet, cqe);
		info->actual_rsp_size = cqe->p_len;
	} else {
		ub_msg_dump_sq(&sqe, info->req_packet);
		ub_msg_dump_cq(cqe, NULL);
	}

	cqe_state_set(hmd, cq_idx, CQ_SW_HANDLED);
	hi_msg_cq_update(hmd);
	return ret;
}

int hi_message_sync_request(struct message_device *mdev, struct msg_info *info,
			    u8 code)
{
	return hi_message_sync(mdev, info, PROTOCOL_MSG, code, false);
}

static int hi_message_sync_enum(struct message_device *mdev,
				struct msg_info *info, u8 cmd)
{
	return hi_message_sync(mdev, info, PROTOCOL_ENUM, cmd, false);
}

static int hi_message_response(struct message_device *mdev,
			       struct msg_info *info, u8 code)
{
	struct hi_message_device *hmd = to_hi_message_device(mdev);
	struct hi_msg_sqe sqe = {};
	struct msg_pkt_header *header;
	void *pkt = info->req_packet;
	int cnt;

	if (!pkt_plen_valid(info->req_packet, info->req_pkt_size, PROTOCOL_MSG))
		return -EINVAL;

	header = (struct msg_pkt_header *)pkt;
	hi_msg_sqe_init(&sqe, header->src_tassn, info, PROTOCOL_MSG, code);

	cnt = hi_msg_sq_submit(
		hmd, &sqe, (struct hi_msg_sqe_pld *)info->req_packet, 1, false);
	if (cnt != 1) {
		dev_err(hmd->hmc.dev, "rsp sq submit failed\n");
		return -ENOSPC;
	}

	return 0;
}

static int hi_message_send(struct message_device *mdev, struct msg_info *info,
			   u8 code)
{
	struct hi_message_device *hmd = to_hi_message_device(mdev);
	struct hi_msg_core *hmc = &hmd->hmc;
	struct hi_msg_sqe sqe = {};
	int msn, cnt;
	int ret = 0;

	if (!pkt_plen_valid(info->req_packet, info->req_pkt_size, PROTOCOL_MSG))
		return -EINVAL;

	msn = hi_msn_get(PROTOCOL_MSG);
	if (msn == 0) {
		dev_err(hmc->dev, "alloc msn failed\n");
		return -ENOSPC;
	}

	hi_msg_sqe_init(&sqe, msn, info, PROTOCOL_MSG, code);
	hi_msg_set_pkt_msn(info, PROTOCOL_MSG, msn, hmc->user);

	cnt = hi_msg_sq_submit(
		hmd, &sqe, (struct hi_msg_sqe_pld *)info->req_packet, 1, false);
	if (cnt != 1) {
		dev_err(hmc->dev, "sq submit failed\n");
		hi_msgq_status(hmd);
		ret = -ENOSPC;
	}

	hi_msn_put(PROTOCOL_MSG, msn);
	return ret;
}

/* For some special message need sleep, work in non-atomic context */
int hi_message_sync_request_sched(struct message_device *mdev,
				  struct msg_info *info, u8 code)
{
	return hi_message_sync(mdev, info, PROTOCOL_MSG, code, true);
}

int hi_message_private(struct message_device *mdev, struct msg_info *info,
		       u8 opcode)
{
	int ret, i = 1;

	while (1) {
		ret = hi_message_sync(mdev, info, HISI_PRIVATE, opcode, false);
		if (ret != -ETIMEDOUT)
			return ret;

		i++;

		if (!msg_retry || i > RETRY_COUNT)
			return -ETIMEDOUT;
	}
}

static struct message_ops hi_message_ops = {
	.sync_request = hi_message_sync_request,
	.response = hi_message_response,
	.sync_enum = hi_message_sync_enum,
	.send = hi_message_send,
	.vdm_rx_handler = hi_vdm_rx_msg_handler,
};

static void hi_bus_drv_msg_irq_handler(struct hi_msg_core *hmc)
{
	struct hi_message_device *hmd =
		container_of(hmc, struct hi_message_device, hmc);
	if (hi_msg_cq_poller(hmd) > 0)
		hi_msg_cq_update(hmd);
}

static void hi_timeout_msg_ageing(struct hi_message_device *hmd)
{
	struct timeout_msg_info *msg, *tmp;

	list_for_each_entry_safe(msg, tmp, &hmd->timeout_msg_list, node) {
		if (msg->age >= HI_MSG_AGING_PERIOD) {
			hi_msn_put(msg->task_type, msg->msn);
			atomic_sub(1, &hmd->msg_in_flight_cnt);
			list_del(&msg->node);
			dev_err(hmd->hmc.dev,
				"release aged timeout type=%u msn=%#x\n",
				msg->task_type, msg->msn);
			kfree(msg);
			continue;
		}
		msg->age++;
	}
}

static bool hi_cqe_ageing(struct hi_message_device *hmd, int idx)
{
	struct hi_msg_core *hmc = &hmd->hmc;
	struct ub_bus_controller *ubc;
	struct hi_msg_cqe *cqe;
	int ret;

	if (cqe_state_get(hmd, idx) == CQ_SW_HANDLED)
		return false;

	if (cqe_age_get(hmd, idx) < HI_MSG_AGING_PERIOD) {
		cqe_age_inc(hmd, idx);
		return false;
	}

	cqe = cq_entry(hmc, idx);
	if (cqe->task_type == PROTOCOL_MSG && cqe->type == MSG_REQ) {
		ubc = to_ub_bus_controller(hmc->dev);

		if (cqe->p_len > HI_MSG_RQE_SIZE) {
			dev_err(hmc->dev, "ageing cqe p_len invalid\n");
			ub_msg_dump_cq(cqe, NULL);
			return true;
		}

		ret = message_rx_handler(ubc, rq_entry(hmc, cqe->rq_pi),
					 cqe->p_len);
		if (ret) {
			dev_err(hmc->dev, "rx msg failed, ret=%d\n", ret);
			ub_msg_dump_cq(cqe, rq_entry(hmc, cqe->rq_pi));
		}

		dev_warn(hmc->dev, "interrupt dont up, process unhandled cqe, idx=%d type=%u msn=%#x opcode=%#x\n",
			 idx, cqe->task_type, cqe->msn, cqe->opcode);
	} else {
		dev_err(hmc->dev, "reset unhandled cqe, idx=%d type=%u msn=%#x\n",
			idx, cqe->task_type, cqe->msn);
		ub_msg_dump_cq(cqe, rq_entry(hmc, cqe->rq_pi));
	}

	return true;
}

static bool hi_is_timeout_msg(struct hi_message_device *hmd, int idx)
{
	struct timeout_msg_info *msg, *tmp;
	struct hi_msg_core *hmc = &hmd->hmc;
	struct hi_msg_cqe *cqe;

	cqe = cq_entry(hmc, idx);

	list_for_each_entry_safe(msg, tmp, &hmd->timeout_msg_list, node) {
		if (cqe->msn == msg->msn && cqe->task_type == msg->task_type &&
		    (cqe->task_type != PROTOCOL_MSG || cqe->type == MSG_RSP)) {
			list_del(&msg->node);
			dev_err(hmc->dev,
				"Timeout Message Processed, task=%u msn=%#x\n",
				msg->task_type, msg->msn);
			kfree(msg);
			return true;
		}
	}
	return false;
}

static int hi_msg_timeout_poller(struct hi_message_device *hmd)
{
	unsigned long cq_flags, timeout_msg_flags;
	struct hi_msg_queue *cq;
	int handled_cnt = 0;
	int cqe_cnt, i, idx;

	cq = &hmd->hmc.queue[MSG_CQ];
	spin_lock_irqsave(&cq->lock, cq_flags);
	spin_lock_irqsave(&hmd->timeout_msg_lock, timeout_msg_flags);
	cq->pi = hi_msg_reg_read(&hmd->hmc, CQ_PI);

	hi_timeout_msg_ageing(hmd);

	if (cq->pi == cq->ci) {
		spin_unlock_irqrestore(&hmd->timeout_msg_lock,
				       timeout_msg_flags);
		spin_unlock_irqrestore(&cq->lock, cq_flags);
		return 0;
	}

	cqe_cnt = q_used_cnt(cq);
	for (i = 0; i < cqe_cnt; i++) {
		idx = q_ptr_idx(cq, ci, i);
		if (hi_cqe_ageing(hmd, idx) || hi_is_timeout_msg(hmd, idx)) {
			cqe_state_set(hmd, idx, CQ_SW_HANDLED);
			handled_cnt++;
			if (handled_cnt == MAX_CQ_POLL_PER_TIME)
				break;
		}
	}

	spin_unlock_irqrestore(&hmd->timeout_msg_lock, timeout_msg_flags);
	spin_unlock_irqrestore(&cq->lock, cq_flags);
	return handled_cnt;
}

static void hi_timeout_msg_handle(struct timer_list *timer)
{
	struct hi_message_device *hmd;

	hmd = container_of(timer, struct hi_message_device, timeout_msg_timer);
	if (hi_msg_timeout_poller(hmd) > 0)
		hi_msg_cq_update(hmd);
	mod_timer(timer,
		  jiffies + msecs_to_jiffies(HI_TIMEOUT_MSG_POLL_PERIOD));
}

static void hi_timeout_msg_poller_init(struct hi_message_device *hmd)
{
	struct timer_list *timer = &hmd->timeout_msg_timer;

	INIT_LIST_HEAD(&hmd->timeout_msg_list);
	spin_lock_init(&hmd->timeout_msg_lock);
	timer_setup(timer, hi_timeout_msg_handle, 0);
	timer->expires = jiffies + msecs_to_jiffies(HI_TIMEOUT_MSG_POLL_PERIOD);
	add_timer(timer);
}

static void hi_timeout_msg_poller_uninit(struct hi_message_device *hmd)
{
	struct timer_list *timer = &hmd->timeout_msg_timer;
	struct timeout_msg_info *time_out_msg, *tmp;

	timer_shutdown_sync(timer);
	list_for_each_entry_safe(time_out_msg, tmp, &hmd->timeout_msg_list,
				 node) {
		list_del(&time_out_msg->node);
		kfree(time_out_msg);
	}
}

int hi_msg_device_probe(struct ub_bus_controller *ubc)
{
	struct device *dev = &ubc->dev;
	struct hi_message_device *hmd;
	struct hi_msg_core *hmc;
	int ret;

	hmd = kzalloc(sizeof(*hmd), GFP_KERNEL);
	if (!hmd)
		return -ENOMEM;

	hmc = &hmd->hmc;
	hmc->dev = dev;
	hmc->q_addr = ubc->attr.queue_addr;
	hmc->q_size = HI_MSGQ_SIZE;
	hmc->virq = ubc->queue_virq;
	hmc->intx = MSGQ_INT1;
	hmc->irq_handler = hi_bus_drv_msg_irq_handler;
	snprintf(hmc->queue_name, HI_MSG_INT_NAME_LEN, "hi_msgq%u-%d",
		 ubc->ctl_no, MSGQ_USER_BUS_DRV);


	ret = hi_msg_queue_init(hmd);
	if (ret) {
		dev_err(dev, "init message queue failed\n");
		goto queue_init_fail;
	}

	hi_timeout_msg_poller_init(hmd);

	message_device_set_ops(&hmd->mdev, &hi_message_ops);
	message_device_set_fwnode(&hmd->mdev, dev->fwnode);

	ret = message_device_register(&hmd->mdev);
	if (ret) {
		dev_err(dev, "register message device failed\n");
		goto mdev_reg_fail;
	}

	ubc->mdev = &hmd->mdev;

	return 0;

mdev_reg_fail:
	hi_timeout_msg_poller_uninit(hmd);
	hi_msg_queue_uninit(hmd);
queue_init_fail:
	kfree(hmd);
	return ret;
}

void hi_msg_device_remove(struct ub_bus_controller *ubc)
{
	struct hi_message_device *hmd = to_hi_message_device(ubc->mdev);

	ubc->mdev = NULL;
	message_device_unregister(&hmd->mdev);
	hi_timeout_msg_poller_uninit(hmd);
	hi_msg_queue_uninit(hmd);
	kfree(hmd);
}
