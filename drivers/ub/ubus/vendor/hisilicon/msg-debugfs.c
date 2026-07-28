// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubus hisi msg-d: " fmt

#include <linux/debugfs.h>
#include "../../ubus.h"
#include "../../msg.h"
#include "../../enum.h"
#include "hisi-msg.h"
#include "hisi-ubus.h"

#define REG_NAME_LEN 16
struct hi_msg_reg_info_s {
	char name[REG_NAME_LEN];
	u16 offset;
};

static struct hi_msg_reg_info_s hi_msg_reg_info[] = {
	{"sq_pi", SQ_PI},
	{"sq_ci", SQ_CI},
	{"sq_depth", SQ_DEPTH},
	{"sq_int_mask", SQ_INT_MSK},
	{"rq_pi", RQ_PI},
	{"rq_ci", RQ_CI},
	{"rq_depth", RQ_DEPTH},
	{"rq_entry_size", RQ_ENTRY_SIZE},
	{"cq_pi", CQ_PI},
	{"cq_ci", CQ_CI},
	{"cq_depth", CQ_DEPTH},
	{"cq_int_mask", CQ_INT_MASK},
	{"cq_int_status", CQ_INT_STATUS},
	{"cq_int_ro", CQ_INT_RO},
	{"q_int_sel", MSGQ_INT_SEL}
};

static ssize_t hi_msg_reg_info_read(struct file *file, char __user *ubuf,
				    size_t size, loff_t *loff)
{
	struct hi_msg_core *hmc =
		(struct hi_msg_core *)file->f_inode->i_private;
	struct hi_msg_reg_info_s *reg;
	size_t len = 0;
	int ret, i;
	char *buf;

	buf = kzalloc(SZ_4K, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	reg = hi_msg_reg_info;
	for (i = 0; i < ARRAY_SIZE(hi_msg_reg_info); i++) {
		len += (size_t)scnprintf(buf + len, SZ_4K - len, "%s:%#x\n",
					 reg->name,
					 hi_msg_reg_read(hmc, reg->offset));
		reg++;
	}

	ret = simple_read_from_buffer(ubuf, size, loff, buf, len);
	kfree(buf);
	return ret;
}

static const struct file_operations hi_msg_reg_info_ops = {
	.read = hi_msg_reg_info_read,
};

static int q_num;
static u32 q_idx;
static DEFINE_MUTEX(q_lock);

static size_t hi_msg_buf_assemble(char *buf, size_t size, u32 *addr, int count)
{
	int i, len = 0;

#define DW_EACH_LINE 4
	for (i = 0; i < count; i++) {
		if (i % DW_EACH_LINE == 0)
			len += scnprintf(buf + len, size - len, "\n");
		len += scnprintf(buf + len, size - len, " %08x", *(addr + i));
	}

	len += scnprintf(buf + len, size - len, "\n");

	return len;
}

static ssize_t hi_msg_q_entry_info_read(struct file *file, char __user *ubuf,
					size_t size, loff_t *loff)
{
	struct hi_msg_core *hmc =
		(struct hi_msg_core *)file->f_inode->i_private;
	int ret, num, entry_size;
	struct hi_msg_sqe *sqe;
	struct hi_msg_cqe *cqe;
	u32 *entry, idx;
	size_t len = 0;
	char *buf;

	buf = kzalloc(SZ_8K, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	mutex_lock(&q_lock);
	num = q_num;
	idx = q_idx;
	mutex_unlock(&q_lock);

	switch (num) {
	case MSG_SQ:
		sqe = &hmc->queue[num].sqe[idx];

		entry = (u32 *)sqe;
		entry_size = HI_MSG_SQE_SIZE;
		break;
	case MSG_CQ:
	default:
		cqe = &hmc->queue[num].cqe[idx];

		entry = (u32 *)cqe;
		entry_size = HI_MSG_CQE_SIZE;
		break;
	}

	len += (size_t)scnprintf(buf + len, SZ_8K - len, "%s[%#x]:",
				 (num == MSG_CQ) ? "cq" : "sq", idx);
	len += hi_msg_buf_assemble(buf + len, SZ_8K - len, entry,
				   entry_size / sizeof(u32));

	ret = simple_read_from_buffer(ubuf, size, loff, buf, len);
	kfree(buf);
	return ret;
}

static ssize_t hi_msg_q_entry_info_write(struct file *file,
					 const char __user *ubuf,
					 size_t size, loff_t *loff)
{
	struct hi_msg_core *hmc =
		(struct hi_msg_core *)file->f_inode->i_private;
#define BUF_SIZE 32
	int len, num, fields;
	char buf[BUF_SIZE];
	u32 idx;

	if (*loff != 0)
		return 0;

	if (size >= BUF_SIZE)
		return -ENOSPC;

	len = simple_write_to_buffer(buf, BUF_SIZE - 1, loff, ubuf, size);
	if (len < 0)
		return len;

	buf[len] = '\0';
	fields = sscanf(buf, "%d %x", &num, &idx);
	if (fields != 2)
		return -EINVAL;

	if ((num != MSG_SQ && num != MSG_CQ) || idx >= hmc->queue[num].depth) {
		pr_err("msgq num %d or queue entry idx %#x is invalid\n",
		       num, idx);
		return -EINVAL;
	}

	mutex_lock(&q_lock);
	q_num = num;
	q_idx = idx;
	mutex_unlock(&q_lock);
	return size;
}

static const struct file_operations hi_msg_q_entry_info_ops = {
	.read = hi_msg_q_entry_info_read,
	.write = hi_msg_q_entry_info_write,
};

void hi_msg_debugfs_init(struct hi_msg_core *hmc)
{
	struct ub_bus_controller *ubc = container_of(hmc->dev, struct ub_bus_controller,
						 dev);
	struct dentry *dir;

	dir = debugfs_create_dir(hmc->queue_name, ubc->debug_root);
	debugfs_create_file("reg_info", 0400, dir, hmc,
			    &hi_msg_reg_info_ops);
	debugfs_create_file("q_entry_info", 0600, dir,
			    hmc, &hi_msg_q_entry_info_ops);
}

void hi_msg_debugfs_uninit(struct hi_msg_core *hmc)
{
	struct ub_bus_controller *ubc = container_of(hmc->dev, struct ub_bus_controller,
						 dev);

	debugfs_lookup_and_remove(hmc->queue_name, ubc->debug_root);
}

static void hi_msg_sqe_dump(struct hi_msg_sqe *sqe)
{
	pr_err_ratelimited("sqe:\n");
	pr_err_ratelimited("type=%u local=%u dev=%u icrc=%u len=%#x msn=%#x off=%#x\n",
			   sqe->task_type, sqe->local, sqe->dev_type,
			   sqe->icrc, sqe->p_len, sqe->msn, sqe->p_addr);

	if (sqe->task_type == PROTOCOL_MSG)
		pr_err_ratelimited("code=%#x sub=%#x rsp=%u\n", sqe->msg_code,
				   sqe->sub_msg_code, sqe->type);
	else
		pr_err_ratelimited("opcode=%#x\n", sqe->opcode);
}

static void hi_msg_cqe_dump(struct hi_msg_cqe *cqe)
{
	pr_err_ratelimited("cqe:\n");
	pr_err_ratelimited("type=%u plen=%#x msn=%#x pi=%#x s=%u\n",
			   cqe->task_type, cqe->p_len, cqe->msn, cqe->rq_pi,
			   cqe->status);

	if (cqe->task_type == PROTOCOL_MSG)
		pr_err_ratelimited("code=%#x sub=%#x rsp=%u\n", cqe->msg_code,
				   cqe->sub_msg_code, cqe->type);
	else
		pr_err_ratelimited("opcode=%#x\n", cqe->opcode);
}

static void hi_msg_header_dump(void *buf)
{
	struct msg_pkt_header *h = (struct msg_pkt_header *)buf;
	struct msg_extended_header *eh = &h->msgetah;
	struct compact_network_header *nh = &h->nth;
	struct ub_link_header *lh = &h->ulh;

	pr_err_ratelimited("msg header:\n");
	pr_err_ratelimited("cfg=%u dcna=%#x scna=%#x nlp=%u mgmt=%u\n",
			   lh->cfg, nh->dcna, nh->scna, nh->nth_nlp, nh->mgmt);
	pr_err_ratelimited("tp_opcode=%u tp_nlp=%u upi=%#x seid=%#x deid=%#x\n",
			   h->tp_opcode, h->ctph_nlp, h->upi,
			   eid_gen(h->seid_h, h->seid_l), h->deid);
	pr_err_ratelimited("msn=%#x ta_opcode=%#x msgq_id=%u\n", h->src_tassn,
			   h->ta_opcode, h->msgq_id);
	pr_err_ratelimited("code=%#x sub=%#x rsp=%u plen=%#x s=%u\n",
			   eh->msg_code, eh->sub_msg_code, eh->type, eh->plen,
			   eh->rsp_status);
}

static void hi_enum_header_dump(void *buf)
{
	struct enum_pkt_header *h = (struct enum_pkt_header *)buf;
	struct compact_network_header *nh = &h->cnth;
	struct ub_link_header *lh = &h->ulh;

	pr_err_ratelimited("enum header:\n");
	pr_err_ratelimited("cfg=%u dcna=%#x scna=%#x nlp=%u mgmt=%u upi=%#x\n",
			   lh->cfg, nh->dcna, nh->scna, nh->nth_nlp, nh->mgmt,
			   h->upi);
}

static void hi_msg_pld_dump(void *buf, int task_type, int len)
{
	switch (task_type) {
	case PROTOCOL_MSG:
		if (len < MSG_PKT_HEADER_SIZE)
			return;
		hi_msg_header_dump(buf);
		break;
	case PROTOCOL_ENUM:
		if (len < ENUM_PKT_HEADER_SIZE)
			return;
		hi_enum_header_dump(buf);
		break;
	case HISI_PRIVATE:
		/* Don't print */
		break;
	default:
		pr_err_ratelimited("bad task_type:%d\n", task_type);
	}
}

void ub_msg_dump_sq(struct hi_msg_sqe *sqe, void *sq_pld)
{
	if (sqe)
		hi_msg_sqe_dump(sqe);

	if (sq_pld && sqe)
		hi_msg_pld_dump(sq_pld, sqe->task_type, sqe->p_len);
}

void ub_msg_dump_cq(struct hi_msg_cqe *cqe, void *rqe)
{
	if (cqe)
		hi_msg_cqe_dump(cqe);

	if (rqe && cqe)
		hi_msg_pld_dump(rqe, cqe->task_type, cqe->p_len);
}
