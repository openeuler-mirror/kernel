// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/if_bridge.h>
#include <linux/dinghai/driver.h>
#include <linux/dinghai/dh_cmd.h>
#include "cmd/msg_chan_priv.h"
#include "cmd/msg_chan_lock.h"
#include "en_aux/en_aux_cmd.h"
#include "msg_common.h"

int debug_print;

module_param(debug_print, int, 0644);

u8 subchan_id_tbl[BAR_MSG_SRC_NUM][BAR_MSG_DST_NUM] = {
	{ BAR_SUBCHAN_INDEX_SEND, BAR_SUBCHAN_INDEX_SEND, BAR_SUBCHAN_INDEX_SEND },
	{ BAR_SUBCHAN_INDEX_SEND, BAR_SUBCHAN_INDEX_SEND, BAR_SUBCHAN_INDEX_RECV },
	{ BAR_SUBCHAN_INDEX_SEND, BAR_SUBCHAN_INDEX_RECV, BAR_SUBCHAN_INDEX_RECV }
};

u8 chan_id_tbl[BAR_MSG_SRC_NUM][BAR_MSG_DST_NUM] = {
	{ BAR_INDEX_TO_RISC, BAR_INDEX_MPF_TO_PFVF, BAR_INDEX_MPF_TO_MPF },
	{ BAR_INDEX_TO_RISC, BAR_INDEX_PF_TO_VF, BAR_INDEX_PFVF_TO_MPF },
	{ BAR_INDEX_TO_RISC, BAR_INDEX_PF_TO_VF, BAR_INDEX_PFVF_TO_MPF }
};

void *internal_addr;

bool is_mpf_scaned = FALSE;

static struct msgid_ring g_msgid_ring;

zxdh_bar_chan_msg_recv_callback msg_recv_func_tbl[MSG_MODULE_NUM];

void bar_chan_check_chan_stats(int ret, u64 addr)
{
	struct bar_msg_header *hdr = (struct bar_msg_header *)(uintptr_t)addr;

	if (!ret)
		return;
	/* check bar msg_header*/
	BAR_LOG_ERR(
		"bar msg err, ret: %d, valid: %u, msg_id: %u, event_id: %u, ack: %u, src_pcieid: 0x%x, dst_pcieid: 0x%x, chan_addr: 0x%llx.\n",
		ret, hdr->valid, hdr->msg_id, hdr->event_id, hdr->ack, hdr->src_pcieid,
		hdr->dst_pcieid, addr);
}

u16 bar_msg_src_parse(struct zxdh_pci_bar_msg *in)
{
	if (!in)
		return BAR_MSG_ERR_NULL;

	if (in->src == MSG_CHAN_END_MPF) {
		if (!is_mpf_scaned)
			return BAR_MSG_ERR_MPF_NOT_SCANED;
		in->virt_addr = (u64)(uintptr_t)internal_addr + BAR_MSG_OFFSET;
		in->src_pcieid = PF0_PCIEID;
	}
	return BAR_MSG_OK;
}

void bar_chan_sync_fill_header(u32 msg_id, struct zxdh_pci_bar_msg *in,
			       struct bar_msg_header *msg_header)
{
	memset(msg_header, 0, sizeof(*msg_header));
	msg_header->sync = BAR_CHAN_MSG_SYNC;
	msg_header->event_id = in->event_id;
	msg_header->len = in->payload_len;
	msg_header->msg_id = msg_id;
	msg_header->dst_pcieid = in->dst_pcieid;
	msg_header->src_pcieid = in->src_pcieid;
}

int bar_chan_msgid_allocate(u16 *msgid)
{
	int ret = BAR_MSG_OK;
	u16 msg_id = 0;
	struct msgid_reps_info *msgid_reps_info = NULL;
	u16 count = 0;

	spin_lock(&g_msgid_ring.lock);
	msg_id = g_msgid_ring.msg_id;
	do {
		count++;
		++msg_id;
		msg_id %= MAX_MSG_BUFF_NUM;
		msgid_reps_info = &g_msgid_ring.reps_info_tbl[msg_id];

	} while (msgid_reps_info->flag != REPS_INFO_FLAG_USABLE && (count < MAX_MSG_BUFF_NUM));

	if (count >= MAX_MSG_BUFF_NUM) {
		ret = -1;
		goto out;
	}

	msgid_reps_info->flag = REPS_INFO_FLAG_USED;
	g_msgid_ring.msg_id = msg_id;
	*msgid = msg_id;

out:
	spin_unlock(&g_msgid_ring.lock);
	return ret;
}

u16 bar_chan_save_recv_info(struct zxdh_msg_recviver_mem *result, u16 *msg_id)
{
	int ret = 0;
	struct msgid_reps_info *reps_info = NULL;

	ret = bar_chan_msgid_allocate(msg_id);
	if (ret == -1)
		return BAR_MSG_ERR_MSGID;
	reps_info = &g_msgid_ring.reps_info_tbl[*msg_id];
	reps_info->reps_buffer = result->recv_buffer;
	reps_info->buffer_len = result->buffer_len;

	return BAR_MSG_OK;
}

void bar_chan_msgid_free(u16 msg_id)
{
	struct msgid_reps_info *msgid_reps_info = NULL;

	if (msg_id >= MAX_MSG_BUFF_NUM)
		return;
	msgid_reps_info = &g_msgid_ring.reps_info_tbl[msg_id];
	spin_lock(&g_msgid_ring.lock);
	msgid_reps_info->flag = REPS_INFO_FLAG_USABLE;
	spin_unlock(&g_msgid_ring.lock);
}

u8 bar_msg_row_index_trans(u8 src)
{
	u8 src_index = 0;

	switch (src) {
	case MSG_CHAN_END_MPF: {
		src_index = BAR_MSG_SRC_MPF;
		break;
	}
	case MSG_CHAN_END_PF: {
		src_index = BAR_MSG_SRC_PF;
		break;
	}
	case MSG_CHAN_END_VF: {
		src_index = BAR_MSG_SRC_VF;
		break;
	}
	default: {
		src_index = BAR_MSG_SRC_ERR;
		break;
	}
	}
	return src_index;
}

u8 bar_msg_col_index_trans(u8 dst)
{
	u8 dst_index = 0;

	switch (dst) {
	case MSG_CHAN_END_MPF: {
		dst_index = BAR_MSG_DST_MPF;
		break;
	}
	case MSG_CHAN_END_PF: {
		dst_index = BAR_MSG_DST_PFVF;
		break;
	}
	case MSG_CHAN_END_VF: {
		dst_index = BAR_MSG_DST_PFVF;
		break;
	}
	case MSG_CHAN_END_RISC: {
		dst_index = BAR_MSG_DST_RISC;
		break;
	}
	default: {
		dst_index = BAR_MSG_SRC_ERR;
		break;
	}
	}
	return dst_index;
}

int bar_chan_send_para_check(struct zxdh_pci_bar_msg *in, struct zxdh_msg_recviver_mem *result)
{
	u8 src_index = 0;
	u8 dst_index = 0;

	if (!in || !result) {
		BAR_LOG_ERR("send para ERR: null para.\n");
		return BAR_MSG_ERR_NULL_PARA;
	}

	src_index = bar_msg_row_index_trans((u8)in->src);
	dst_index = bar_msg_col_index_trans((u8)in->dst);
	if (src_index == BAR_MSG_SRC_ERR || dst_index == BAR_MSG_DST_ERR) {
		BAR_LOG_ERR("send para ERR: chan doesn't exist.\n");
		return BAR_MSG_ERR_TYPE;
	}
	if (in->event_id > MSG_MODULE_NUM) {
		BAR_LOG_ERR("send para ERR: invalid event_id: %d.\n", in->event_id);
		return BAR_MSG_ERR_MODULE;
	}
	if (!in->payload_addr) {
		BAR_LOG_ERR("send para ERR: null message.\n");
		return BAR_MSG_ERR_BODY_NULL;
	}
	if (in->payload_len > BAR_MSG_PAYLOAD_MAX_LEN) {
		BAR_LOG_ERR("send para ERR: len %x is too long.\n", in->payload_len);
		return BAR_MSG_ERR_LEN;
	}
	if (in->virt_addr == 0 || !result->recv_buffer) {
		BAR_LOG_ERR("send para ERR: virt_addr or recv_buffer is NULL.\n");
		return BAR_MSG_ERR_VIRTADDR_NULL;
	}
	if (result->buffer_len < REPS_HEADER_PAYLOAD_OFFSET) {
		BAR_LOG_ERR("recv buffer's len: %d is short than mininal 4 bytes\n",
			    result->buffer_len);
	}
	return BAR_MSG_OK;
}

void bar_chan_subchan_addr_get(struct zxdh_pci_bar_msg *in, u64 *subchan_addr)
{
	u8 src_index, dst_index;
	u16 chan_id, subchan_id;

	src_index = bar_msg_row_index_trans((u8)in->src);
	dst_index = bar_msg_col_index_trans((u8)in->dst);

	if (src_index == BAR_MSG_SRC_ERR || dst_index == BAR_MSG_DST_ERR)
		return;

	chan_id = chan_id_tbl[src_index][dst_index];
	subchan_id = subchan_id_tbl[src_index][dst_index];
	*subchan_addr = in->virt_addr + (2 * chan_id + subchan_id) * BAR_MSG_ADDR_CHAN_INTERVAL;
}

int bar_chan_reg_write(u64 subchan_addr, u32 offset, u32 data)
{
	u32 algin_offset = (offset & BAR_ALIGN_WORD_MASK);

	if (algin_offset >= BAR_MSG_ADDR_CHAN_INTERVAL)
		return -EADDRNOTAVAIL;

	writel(data, (void *)(uintptr_t)(subchan_addr + algin_offset));
	return 0;
}

int bar_chan_reg_read(u64 subchan_addr, u32 offset, u32 *pdata)
{
	u32 algin_offset = (offset & BAR_ALIGN_WORD_MASK);

	if (algin_offset >= BAR_MSG_ADDR_CHAN_INTERVAL)
		return -EADDRNOTAVAIL;

	*pdata = readl((const void *)(uintptr_t)(subchan_addr + algin_offset));
	return 0;
}

u16 bar_chan_msg_header_set(u64 subchan_addr, struct bar_msg_header *msg_header)
{
	u32 *data = (u32 *)msg_header;
	u16 idx = 0;

	for (idx = 0; idx < (BAR_MSG_PLAYLOAD_OFFSET >> 2); idx++)
		bar_chan_reg_write(subchan_addr, idx * 4, *(data + idx));

	return BAR_MSG_OK;
}

u16 bar_chan_msg_header_get(u64 subchan_addr, struct bar_msg_header *msg_header)
{
	u32 *data = (u32 *)msg_header;
	u16 idx = 0;

	for (idx = 0; idx < (BAR_MSG_PLAYLOAD_OFFSET >> 2); idx++)
		bar_chan_reg_read(subchan_addr, idx * 4, data + idx);

	return BAR_MSG_OK;
}

u16 bar_chan_msg_payload_set(u64 subchan_addr, u8 *msg, u16 len)
{
	u32 *data = (u32 *)msg;
	u32 count = (len / sizeof(u32));
	u32 remain = (len % sizeof(u32));
	u32 ix = 0, remain_data = 0;

	for (ix = 0; ix < count; ix++)
		bar_chan_reg_write(subchan_addr, 4 * ix + BAR_MSG_PLAYLOAD_OFFSET, *(data + ix));

	for (ix = 0; ix < remain; ix++)
		remain_data |= *((u8 *)(msg + (len - remain + ix))) << (8 * ix);

	bar_chan_reg_write(subchan_addr, 4 * count + BAR_MSG_PLAYLOAD_OFFSET, remain_data);

	return BAR_MSG_OK;
}

u16 bar_chan_msg_payload_get(u64 subchan_addr, u8 *msg, u16 len)
{
	u32 *data = (u32 *)msg;
	u32 count = (len / sizeof(u32));
	u32 remain = (len % sizeof(u32));
	u32 ix = 0, remain_data = 0;

	for (ix = 0; ix < count; ix++)
		bar_chan_reg_read(subchan_addr, 4 * ix + BAR_MSG_PLAYLOAD_OFFSET, (data + ix));

	bar_chan_reg_read(subchan_addr, 4 * count + BAR_MSG_PLAYLOAD_OFFSET, &remain_data);
	for (ix = 0; ix < remain; ix++)
		*((u8 *)(msg + (len - remain + ix))) = remain_data >> (8 * ix);

	return BAR_MSG_OK;
}

u16 bar_chan_msg_valid_set(u64 subchan_addr, u8 valid_label)
{
	u32 data = 0;

	bar_chan_reg_read(subchan_addr, BAR_MSG_VALID_OFFSET, &data);
	data &= (~BAR_MSG_VALID_MASK);
	data |= (u32)valid_label;
	bar_chan_reg_write(subchan_addr, BAR_MSG_VALID_OFFSET, data);

	return BAR_MSG_OK;
}

u16 bar_msg_valid_stat_get(u64 subchan_addr)
{
	u32 data = 0;

	bar_chan_reg_read(subchan_addr, BAR_MSG_VALID_OFFSET, &data);
	if (BAR_MSG_CHAN_USABLE == (data & BAR_MSG_VALID_MASK))
		return BAR_MSG_CHAN_USABLE;

	return BAR_MSG_CHAN_USED;
}

u16 bar_chan_msg_poltag_set(u64 subchan_addr, u8 label)
{
	u32 data = 0;

	bar_chan_reg_read(subchan_addr, BAR_MSG_VALID_OFFSET, &data);
	data &= (~(u32)BAR_MSG_POL_MASK);
	data |= ((u32)label << BAR_MSG_POL_OFFSET);
	bar_chan_reg_write(subchan_addr, BAR_MSG_VALID_OFFSET, data);

	return BAR_MSG_OK;
}

static u8 payload_temp_buf[BAR_MSG_ADDR_CHAN_INTERVAL] = { 0 };
u16 bar_chan_msg_send(u64 subchan_addr, void *payload_addr, u16 payload_len,
		      struct bar_msg_header *msg_header)
{
	u8 *msg = (u8 *)(payload_addr);
	struct bar_msg_header hdr_read = { 0 };
	u16 valid = 0;

	bar_chan_msg_header_set(subchan_addr, msg_header);
	bar_chan_msg_header_get(subchan_addr, &hdr_read);

	bar_chan_msg_payload_set(subchan_addr, msg, payload_len);
	bar_chan_msg_payload_get(subchan_addr, payload_temp_buf, payload_len);

	bar_chan_msg_valid_set(subchan_addr, BAR_MSG_CHAN_USED);
	valid = bar_msg_valid_stat_get(subchan_addr);

	return BAR_MSG_OK;
}

int bar_chan_recv_func_check(u16 check)
{
	if (check == CHECK_STATE_OK)
		return BAR_MSG_OK;

	BAR_LOG_ERR("recv func check failed, check field: 0x%x", check);
	return BAR_MSG_ERR_USR_RET_ERR;
}

int bar_chan_sync_msg_reps_get(u64 subchan_addr, u64 recv_buffer, u16 buffer_len, u16 send_msg_id,
			       u16 op_code)
{
	int ret = BAR_MSG_OK;
	u16 recv_msg_id = 0;
	u16 recv_len = 0;
	u8 *recv_msg = (u8 *)(uintptr_t)recv_buffer;
	struct bar_msg_header msg_header;
	struct msgid_reps_info *reps_info = NULL;

	memset(&msg_header, 0, sizeof(msg_header));
	bar_chan_msg_header_get(subchan_addr, &msg_header);
	recv_len = msg_header.len;
	recv_msg_id = msg_header.msg_id;

	if (recv_msg_id != send_msg_id) {
		BAR_LOG_ERR("send msg id: %d, but get reply msg id: %d.\n", send_msg_id,
			    recv_msg_id);
		ret = BAR_MSG_ERR_REPLY;
		goto out;
	}

	reps_info = &g_msgid_ring.reps_info_tbl[recv_msg_id];
	if (reps_info->flag != REPS_INFO_FLAG_USED) {
		BAR_LOG_ERR("msg_id: %d is release", recv_msg_id);
		ret = BAR_MSG_ERR_REPLY;
		goto out;
	}

	if ((op_code < ZXDH_GET_SW_STATS) && (recv_len > ZXDH_REPS_MAX_SIZE_BEFORE57))
		recv_len = ZXDH_REPS_MAX_SIZE_BEFORE57;

	if (recv_len > buffer_len - REPS_HEADER_PAYLOAD_OFFSET) {
		BAR_LOG_ERR("reps_buf_len is %d, but reps_msg_len is %d", buffer_len, recv_len + 4);
		ret = BAR_MSG_ERR_REPSBUFF_LEN;
		goto out;
	}

	bar_chan_msg_payload_get(subchan_addr, recv_msg + REPS_HEADER_PAYLOAD_OFFSET, recv_len);

	ret = bar_chan_recv_func_check(msg_header.check);
	if (ret != BAR_MSG_OK)
		goto out;

	*(u16 *)(recv_msg + REPS_HEADER_LEN_OFFSET) = recv_len;

	*recv_msg = REPS_HEADER_REPLYED;

out:
	return ret;
}

u64 subchan_addr_cal(u64 virt_addr, u8 chan_id, u8 subchan_id)
{
	return virt_addr + (2 * chan_id + subchan_id) * BAR_MSG_ADDR_CHAN_INTERVAL;
}

u64 recv_addr_get(u8 src_type, u8 dst_type, u64 virt_addr)
{
	u8 chan_id = 0;
	u8 subchan_id = 0;
	u8 src = bar_msg_col_index_trans(src_type);
	u8 dst = bar_msg_row_index_trans(dst_type);

	if (src >= BAR_MSG_SRC_NUM || dst >= BAR_MSG_DST_NUM)
		return 0;

	chan_id = chan_id_tbl[dst][src];

	subchan_id = (!!subchan_id_tbl[dst][src]) ? BAR_SUBCHAN_INDEX_SEND : BAR_SUBCHAN_INDEX_RECV;
	return subchan_addr_cal(virt_addr, chan_id, subchan_id);
}

u64 reply_addr_get(u8 sync, u8 src_type, u8 dst_type, u64 virt_addr)
{
	u8 chan_id = 0;
	u8 subchan_id = 0;
	u64 recv_rep_addr = 0;
	u8 src = bar_msg_col_index_trans(src_type);
	u8 dst = bar_msg_row_index_trans(dst_type);

	if (src == BAR_MSG_SRC_ERR || dst == BAR_MSG_DST_ERR)
		return 0;

	chan_id = chan_id_tbl[dst][src];
	subchan_id = (!!subchan_id_tbl[dst][src]) ? BAR_SUBCHAN_INDEX_SEND : BAR_SUBCHAN_INDEX_RECV;
	if (sync == BAR_CHAN_MSG_SYNC)
		recv_rep_addr = subchan_addr_cal(virt_addr, chan_id, subchan_id);
	else
		recv_rep_addr = subchan_addr_cal(virt_addr, chan_id, 1 - subchan_id);

	return recv_rep_addr;
}

u16 bar_chan_msg_header_check(struct bar_msg_header *msg_header)
{
	u8 event_id = 0;
	u16 len = 0;

	if (!msg_header)
		return BAR_MSG_ERR_NULL;
	if (msg_header->valid != BAR_MSG_CHAN_USED) {
		BAR_LOG_ERR("recv header ERR: valid label is not used.\n");
		return BAR_MSG_ERR_MODULE;
	}
	event_id = msg_header->event_id;
	if (event_id >= (u8)MSG_MODULE_NUM) {
		BAR_LOG_ERR("recv header ERR: invalid event_id: %d.\n", event_id);
		return BAR_MSG_ERR_MODULE;
	}
	len = msg_header->len;
	if (len > BAR_MSG_PAYLOAD_MAX_LEN) {
		BAR_LOG_ERR("recv header ERR: invalid mesg len: %d.\n", len);
		return BAR_MSG_ERR_LEN;
	}
	if (msg_header->ack == BAR_CHAN_MSG_NO_ACK && !msg_recv_func_tbl[msg_header->event_id]) {
		BAR_LOG_DEBUG("recv header ERR: module:%d  doesn't register", event_id);
		return BAR_MSG_ERR_MODULE_NOEXIST;
	}
	return BAR_MSG_OK;
}

void bar_msg_sync_msg_proc(u64 reply_addr, struct bar_msg_header *msg_header, u8 *reciver_buff,
			   void *dev)
{
	u16 reps_len = 0;
	u8 *reps_buffer = NULL;
	zxdh_bar_chan_msg_recv_callback recv_func = NULL;

	reps_buffer = kmalloc(BAR_MSG_PAYLOAD_MAX_LEN, GFP_KERNEL);
	if (!reps_buffer)
		return;

	recv_func = msg_recv_func_tbl[msg_header->event_id];
	recv_func(reciver_buff, msg_header->len, reps_buffer, &reps_len, dev);
	msg_header->ack = BAR_CHAN_MSG_ACK;
	msg_header->len = reps_len;

	bar_chan_msg_header_set(reply_addr, msg_header);
	bar_chan_msg_payload_set(reply_addr, reps_buffer, reps_len);
	bar_chan_msg_valid_set(reply_addr, BAR_MSG_CHAN_USABLE);

	BAR_KFREE_PTR(reps_buffer);
}

zxdh_usr_msg_cache_callback msg_cache_func = NULL;
spinlock_t cache_func_lock;
void zxdh_usr_msg_cache_func_register(zxdh_usr_msg_cache_callback func)
{
	spin_lock(&cache_func_lock);
	BAR_LOG_INFO("register push func success.\n");
	msg_cache_func = func;
	spin_unlock(&cache_func_lock);
}
EXPORT_SYMBOL(zxdh_usr_msg_cache_func_register);

void bar_cache_msg_to_usr_queue(u16 event_id, void *msg, u16 msg_len)
{
	spin_lock(&cache_func_lock);
	if (msg_cache_func)
		msg_cache_func(event_id, msg, msg_len);
	spin_unlock(&cache_func_lock);
}

int zxdh_bar_irq_recv(u8 src, u8 dst, u64 virt_addr, void *dev)
{
	u64 recv_addr = 0;
	u64 reps_addr = 0;
	struct bar_msg_header msg_header = { 0 };
	u8 *recved_msg = NULL;
	u16 ret = 0;

	recv_addr = recv_addr_get(src, dst, virt_addr);
	if (recv_addr == 0) {
		BAR_LOG_ERR("invalid driver type");
		return BAR_MSG_ERR_NULL;
	}

	bar_chan_msg_header_get(recv_addr, &msg_header);
	ret = bar_chan_msg_header_check(&msg_header);
	if (ret != BAR_MSG_OK) {
		bar_chan_check_chan_stats(ret, recv_addr);
		return ret;
	}

	recved_msg = kmalloc(msg_header.len, GFP_KERNEL);
	if (!recved_msg) {
		BAR_LOG_ERR("create temp buff failed");
		return BAR_MSG_ERR_NULL;
	}
	bar_chan_msg_payload_get(recv_addr, recved_msg, msg_header.len);

	if (msg_header.usr == 0) {
		/* risc send msg to kernel*/
		reps_addr = reply_addr_get(msg_header.sync, src, dst, virt_addr);
		bar_msg_sync_msg_proc(reps_addr, &msg_header, recved_msg, dev);
		goto out;
	} else {
		/* risc send msg to user*/
		bar_cache_msg_to_usr_queue(msg_header.event_id, recved_msg, msg_header.len);
		msg_header.len = 0;
		msg_header.ack = 1;
		bar_chan_msg_header_set(recv_addr, &msg_header);
	}

	bar_chan_msg_poltag_set(recv_addr, 0);
	bar_chan_msg_valid_set(recv_addr, BAR_MSG_CHAN_USABLE);

out:
	kfree(recved_msg);
	return BAR_MSG_OK;
}
EXPORT_SYMBOL(zxdh_bar_irq_recv);

s32 call_msg_recv_func_tbl(u16 event_id, void *pay_load, u16 len, void *reps_buffer, u16 *reps_len,
			   void *dev)
{
	zxdh_bar_chan_msg_recv_callback recv_func = NULL;

	recv_func = msg_recv_func_tbl[event_id];
	if (unlikely(!recv_func)) {
		BAR_LOG_ERR("event_id[%d] unregister\n", event_id);
		return BAR_MSG_ERR_MODULE_NOEXIST;
	}

	return recv_func(pay_load, len, reps_buffer, reps_len, dev);
}
EXPORT_SYMBOL(call_msg_recv_func_tbl);

static void bar_chan_reset_flag_normal(u64 subchan_addr, u8 dst)
{
	if (dst != MSG_CHAN_END_RISC)
		bar_chan_msg_valid_set(subchan_addr, BAR_MSG_CHAN_USABLE);
}

#define VALID_FLAG_DETECT_SPAN_MS (10)
#define VALID_FLAG_DETECT_TIMEOUT_MS (6000)
#define US_NUMS_PER_MS (1000)

static int bar_chan_sync_wait(u64 subchan_addr, u8 dst, u32 *wait_reps_retry_times)
{
	u8 valid = 0;
	int retry_cnt = 0;
	u32 timeout_th_res_ms = 0;
	int max_retries = VALID_FLAG_DETECT_TIMEOUT_MS / VALID_FLAG_DETECT_SPAN_MS / 2;

	if (dst != MSG_CHAN_END_RISC) {
		*wait_reps_retry_times = BAR_MSG_TIMEOUT_TH;
		return 0;
	}

	for (retry_cnt = 0; retry_cnt < max_retries; retry_cnt++) {
		valid = bar_msg_valid_stat_get(subchan_addr);
		if (valid == BAR_MSG_CHAN_USABLE) {
			timeout_th_res_ms = VALID_FLAG_DETECT_TIMEOUT_MS -
					    retry_cnt * VALID_FLAG_DETECT_SPAN_MS;
			*wait_reps_retry_times =
				timeout_th_res_ms * US_NUMS_PER_MS / BAR_MSG_POLLING_SPAN_US;
			return 0;
		}
		msleep(VALID_FLAG_DETECT_SPAN_MS);
	}
	return -1;
}

int zxdh_bar_chan_sync_msg_send(struct zxdh_pci_bar_msg *in, struct zxdh_msg_recviver_mem *result)
{
	int ret = 0;
	u16 valid = 0;
	u16 time_out_cnt = 0;
	u32 wait_reps_retry_times = 0;
	u16 msg_id = 0;
	u64 subchan_addr = 0;
	u16 op_code = 0;
	struct bar_msg_header msg_header = { 0 };

	ret = bar_msg_src_parse(in);
	if (ret != BAR_MSG_OK)
		return ret;

	ret = bar_chan_send_para_check(in, result);
	if (ret != BAR_MSG_OK) {
		BAR_LOG_ERR("para check failed, %d.", ret);
		return ret;
	}

	ret = bar_chan_save_recv_info(result, &msg_id);
	if (ret != BAR_MSG_OK) {
		BAR_LOG_ERR("msg_id allocated failed.");
		return ret;
	}

	bar_chan_subchan_addr_get(in, &subchan_addr);
	if (*(u32 *)(uintptr_t)subchan_addr == 0xffffffff) {
		BAR_LOG_ERR("pcie bar abnormal.\n");
		ret = BAR_MSG_ERR_BAR_ABNORMAL;
		bar_chan_msgid_free(msg_id);
		return ret;
	}

	bar_chan_sync_fill_header(msg_id, in, &msg_header);

	ret = bar_chan_lock(in->src, in->dst, in->src_pcieid, in->virt_addr);
	if (ret != BAR_MSG_OK) {
		bar_chan_msgid_free(msg_id);
		return ret;
	}

	ret = bar_chan_sync_wait(subchan_addr, in->dst, &wait_reps_retry_times);
	if (ret != 0) {
		BAR_LOG_ERR("chan valid flag is used while send msg-%u.\n", msg_id);
		goto free_chan;
	}
	BAR_LOG_DEBUG("pcie_id-0x%x  src-%u, dst-%u get     lock.\n", in->src_pcieid, in->src,
		      in->dst);

	op_code = *(u8 *)(in->payload_addr);

	bar_chan_msg_send(subchan_addr, in->payload_addr, in->payload_len, &msg_header);

	do {
		usleep_range(BAR_MSG_POLLING_SPAN_US, BAR_MSG_POLLING_SPAN_US + 10);
		valid = bar_msg_valid_stat_get(subchan_addr);
		time_out_cnt++;
	} while (time_out_cnt < wait_reps_retry_times && valid == BAR_MSG_CHAN_USED);

	if (wait_reps_retry_times == time_out_cnt && valid != BAR_MSG_CHAN_USABLE) {
		bar_chan_reset_flag_normal(subchan_addr, in->dst);
		bar_chan_msg_poltag_set(subchan_addr, 0);
		BAR_LOG_ERR("BAR MSG ERR: msg_id: %d time out.\n", msg_header.msg_id);
		ret = BAR_MSG_ERR_TIME_OUT;
	} else {
		ret = bar_chan_sync_msg_reps_get(subchan_addr, (u64)(uintptr_t)result->recv_buffer,
						 result->buffer_len, msg_id, op_code);
	}
free_chan:
	bar_chan_msgid_free(msg_id);

	bar_chan_check_chan_stats(ret, subchan_addr);
	BAR_LOG_DEBUG("pcie_id-0x%x  src-%u, dst-%u release lock.\n", in->src_pcieid, in->src,
		      in->dst);
	bar_chan_unlock((u8)in->src, (u8)in->dst, in->src_pcieid, in->virt_addr);
	return ret;
}
EXPORT_SYMBOL(zxdh_bar_chan_sync_msg_send);

static int bar_chan_callback_register_check(u8 event_id, zxdh_bar_chan_msg_recv_callback callback)
{
	if (event_id >= (u8)MSG_MODULE_NUM) {
		BAR_LOG_ERR("register ERR: invalid event_id: %d.\n", event_id);
		return BAR_MSG_ERR_MODULE;
	}
	if (!callback) {
		BAR_LOG_ERR("register ERR: null callback.\n");
		return BAR_MEG_ERR_NULL_FUNC;
	}
	if (msg_recv_func_tbl[event_id]) {
		BAR_LOG_ERR("register ERR: repeat register.\n");
		return BAR_MSG_ERR_REPEAT_REGISTER;
	}
	return BAR_MSG_OK;
}

int zxdh_bar_chan_msg_recv_register(u8 event_id, zxdh_bar_chan_msg_recv_callback callback)
{
	int ret = 0;

	ret = bar_chan_callback_register_check(event_id, callback);

	if (ret == BAR_MSG_OK) {
		msg_recv_func_tbl[event_id] = callback;
		BAR_LOG_DEBUG("register module: %d success.\n", event_id);
	}

	return ret;
}
EXPORT_SYMBOL(zxdh_bar_chan_msg_recv_register);

int zxdh_bar_chan_msg_recv_unregister(u8 event_id)
{
	if (event_id >= (u8)MSG_MODULE_NUM) {
		BAR_LOG_ERR("unregister ERR: invalid event_id :%d.\n", event_id);
		return BAR_MSG_ERR_MODULE;
	}
	if (!msg_recv_func_tbl[event_id]) {
		BAR_LOG_ERR("unregister ERR: null proccess func.\n");
		return BAR_MSG_ERR_UNGISTER;
	}
	msg_recv_func_tbl[event_id] = NULL;
	BAR_LOG_DEBUG("unregister module %d success.\n", event_id);
	return BAR_MSG_OK;
}
EXPORT_SYMBOL(zxdh_bar_chan_msg_recv_unregister);

int zxdh_bar_callback_register_state(u16 event_id)
{
	if (event_id >= (u16)MSG_MODULE_NUM) {
		BAR_LOG_ERR("unregister ERR: invalid event_id :%hu.\n", event_id);
		return BAR_MSG_ERR_MODULE;
	}
	if (!msg_recv_func_tbl[event_id]) {
		BAR_LOG_ERR("unregister ERR: null proccess func.\n");
		return BAR_MSG_ERR_UNGISTER;
	}
	return BAR_MSG_OK;
}
EXPORT_SYMBOL(zxdh_bar_callback_register_state);

#ifdef BAR_MSG_TEST
int bar_mpf_addr_ioremap(void)
{
	u64 addr;
	u64 len;
	struct pci_dev *pdev = NULL;

	pdev = pci_get_device(MPF_VENDOR_ID, MPF_DEVICE_ID, NULL);

	if (!pdev) {
		BAR_LOG_DEBUG("not found device: deviceID %x, VendorID: %x", MPF_DEVICE_ID,
			      MPF_VENDOR_ID);
		return -EINVAL;
	}

	addr = pci_resource_start(pdev, 0);
	len = pci_resource_len(pdev, 0);
	if (addr == 0 || len == 0) {
		BAR_LOG_ERR("pci resource addr or len is 0\n");
		return -EINVAL;
	}

	internal_addr = ioremap(addr, len);
	if (IS_ERR_OR_NULL(internal_addr)) {
		BAR_LOG_ERR("ioremap failed, internal_addr=0x%p\n", internal_addr);
		return -ENOMEM;
	}
	is_mpf_scaned = TRUE;

	return BAR_MSG_OK;
}

void bar_mpf_addr_iounmap(void)
{
	if (internal_addr)
		iounmap(internal_addr);
	internal_addr = NULL;
	is_mpf_scaned = FALSE;
}
#endif

int bar_msgid_ring_init(void)
{
	u16 msg_id = 0;
	struct msgid_reps_info *reps_info = NULL;

	spin_lock_init(&cache_func_lock);
	spin_lock_init(&g_msgid_ring.lock);
	for (msg_id = 0; msg_id < MAX_MSG_BUFF_NUM; msg_id++) {
		reps_info = &(g_msgid_ring.reps_info_tbl[msg_id]);
		reps_info->id = msg_id;
		reps_info->flag = REPS_INFO_FLAG_USABLE;
	}
	return BAR_MSG_OK;
}

void bar_msgid_ring_free(void)
{
	u16 msg_id = 0;
	struct msgid_reps_info *reps_info = NULL;

	for (msg_id = 0; msg_id < MAX_MSG_BUFF_NUM; msg_id++) {
		reps_info = &g_msgid_ring.reps_info_tbl[msg_id];
		del_timer_sync(&reps_info->id_timer);
	}
}

extern u16 test_sync_send(void);
int zxdh_bar_msg_chan_init(void)
{
#ifdef BAR_MSG_TEST
	int ret = 0;

	ret = bar_mpf_addr_ioremap();
	if (ret != BAR_MSG_OK)
		BAR_LOG_DEBUG("mpf do not exit, but do not impact the msg chan.\n");

	test_sync_send();
#endif
	bar_init_lock_arr();
	bar_msgid_ring_init();

	return BAR_MSG_OK;
}

void bar_chan_timer_callback(struct timer_list *timer)
{
	struct msgid_reps_info *reps_info = NULL;

	reps_info = container_of(timer, struct msgid_reps_info, id_timer);
	if (reps_info->flag == REPS_INFO_FLAG_USED) {
		reps_info->reps_buffer = NULL;
		reps_info->buffer_len = 0;
		reps_info->flag = REPS_INFO_FLAG_USABLE;
		BAR_LOG_ERR("RECV ERR: get async reply time out, free msg_id: %u.\n",
			    reps_info->id);
	} else {
		BAR_LOG_DEBUG("RECV NOTICE: get async reply message success.\n");
	}
}

int zxdh_bar_msg_chan_remove(void)
{
	bar_msgid_ring_free();

#ifdef BAR_MSG_TEST
	bar_mpf_addr_iounmap();
#endif

	BAR_LOG_DEBUG("zxdh_msg_chan_bar remove success");

	return 0;
}

u16 bar_get_sum(u8 *ptr, u8 len)
{
	int idx = 0;
	u64 sum = 0;

	for (idx = 0; idx < len; idx++)
		sum += *(ptr + idx);
	return (u16)sum;
}

int zxdh_bar_enable_chan(struct msix_para *_msix_para, u16 *vport)
{
	int ret = 0;
	u8 recv_buf[12] = { 0 };
	u16 check_token, sum_res;
	struct msix_msg msix_msg = { 0 };
	struct zxdh_pci_bar_msg in = { 0 };
	struct zxdh_msg_recviver_mem result = { 0 };

	if (!_msix_para || !_msix_para->pdev)
		return -BAR_MSG_ERR_NULL;
	msix_msg.pcie_id = _msix_para->pcie_id;
	msix_msg.vector_risc = _msix_para->vector_risc;
	msix_msg.vector_pfvf = _msix_para->vector_pfvf;
	msix_msg.vector_mpf = _msix_para->vector_mpf;

	in.payload_addr = &msix_msg;
	in.payload_len = sizeof(msix_msg);
	in.virt_addr = _msix_para->virt_addr;
	in.src = _msix_para->driver_type;
	in.dst = MSG_CHAN_END_RISC;
	in.event_id = MODULE_MSIX;
	in.src_pcieid = _msix_para->pcie_id;

	result.recv_buffer = recv_buf;
	result.buffer_len = sizeof(recv_buf);

	ret = zxdh_bar_chan_sync_msg_send(&in, &result);
	if (ret != BAR_MSG_OK)
		return -ret;

	check_token = *(u16 *)(recv_buf + 6);
	sum_res = bar_get_sum((u8 *)&msix_msg, sizeof(msix_msg));
	if (check_token != sum_res) {
		BAR_LOG_DEBUG("expect token: 0x%x, get token: 0x%x.\n", sum_res, check_token);
		return -BAR_MSG_ERR_NOT_MATCH;
	}
	*vport = *(u16 *)(recv_buf + 8);
	BAR_LOG_DEBUG("vport of %s get success.\n", pci_name(_msix_para->pdev));
	return BAR_MSG_OK;
}
EXPORT_SYMBOL(zxdh_bar_enable_chan);

int zxdh_get_bar_offset(struct bar_offset_params *paras, struct bar_offset_res *res)
{
	int ret = 0;
	u16 check_token, sum_res;
	struct offset_get_msg send_msg = { 0 };
	struct bar_recv_msg *recv_msg = NULL;

	struct zxdh_pci_bar_msg in = { 0 };
	struct zxdh_msg_recviver_mem result = { 0 };

	if (!paras || !res)
		return BAR_MSG_ERR_NULL;

	send_msg.pcie_id = paras->pcie_id;
	send_msg.type = paras->type;

	in.payload_addr = &send_msg;
	in.payload_len = sizeof(send_msg);
	in.virt_addr = paras->virt_addr;
	in.src = MSG_CHAN_END_PF;
	in.dst = MSG_CHAN_END_RISC;
	in.event_id = MODULE_OFFSET_GET;
	in.src_pcieid = paras->pcie_id;

	recv_msg = kzalloc(sizeof(struct bar_recv_msg), GFP_KERNEL);
	if (!recv_msg) {
		LOG_ERR("NULL ptr\n");
		return -1;
	}
	result.recv_buffer = recv_msg;
	result.buffer_len = sizeof(struct bar_recv_msg);

	ret = zxdh_bar_chan_sync_msg_send(&in, &result);
	if (ret != BAR_MSG_OK) {
		ret = -ret;
		goto free_msg;
	}

	check_token = recv_msg->offset_reps.check;
	sum_res = bar_get_sum((u8 *)&send_msg, sizeof(send_msg));
	if (check_token != sum_res) {
		BAR_LOG_ERR("expect token: 0x%x, get token: 0x%x.\n", sum_res, check_token);
		ret = -BAR_MSG_ERR_NOT_MATCH;
		goto free_msg;
	}
	res->bar_offset = recv_msg->offset_reps.offset;
	res->bar_length = recv_msg->offset_reps.length;

free_msg:
	kfree(recv_msg);
	return ret;
}
EXPORT_SYMBOL(zxdh_get_bar_offset);

void zxdh_bar_reset_valid(u64 subchan_addr)
{
	struct bar_msg_header msg_header = { 0 };

	bar_chan_msg_header_get(subchan_addr, &msg_header);

	subchan_addr += BAR_MSG_ADDR_CHAN_INTERVAL;
	bar_chan_msg_valid_set(subchan_addr, BAR_MSG_CHAN_USABLE);
	bar_chan_msg_poltag_set(subchan_addr, 0);
}
EXPORT_SYMBOL(zxdh_bar_reset_valid);

u16 zxdh_get_event_id(u64 subchan_addr, u8 src_type, u8 dst_type)
{
	u8 subchan_id = 0;
	struct bar_msg_header msg_header = { 0 };
	u8 src = bar_msg_col_index_trans(src_type);
	u8 dst = bar_msg_row_index_trans(dst_type);

	if (src == BAR_MSG_SRC_ERR || dst == BAR_MSG_DST_ERR)
		return 0;

	subchan_id = (!!subchan_id_tbl[dst][src]) ? BAR_SUBCHAN_INDEX_SEND : BAR_SUBCHAN_INDEX_RECV;
	subchan_addr += subchan_id * BAR_MSG_ADDR_CHAN_INTERVAL;
	bar_chan_msg_header_get(subchan_addr, &msg_header);
	return msg_header.event_id;
}
EXPORT_SYMBOL(zxdh_get_event_id);

s32 zxdh_send_command(u64 vaddr, u16 pcie_id, u16 module_id, void *msg, void *ack, bool is_sync_msg)
{
	struct zxdh_pci_bar_msg in = { 0 };
	struct zxdh_msg_recviver_mem result = { 0 };
	struct bar_recv_msg *bar_reps = NULL;
	s32 ret = 0;

	if ((!msg) || (!ack)) {
		LOG_ERR("NULL ptr\n");
		return -1;
	}

	in.payload_addr = msg;
	in.payload_len = sizeof(union zxdh_msg);

	if (((pcie_id >> PFVF_FLAG_OFFSET) & 1) == 1)
		in.src = MSG_CHAN_END_PF;
	else
		in.src = MSG_CHAN_END_VF;

	bar_reps = kzalloc(BAR_MSG_PAYLOAD_MAX_LEN, GFP_KERNEL);
	if (!bar_reps) {
		LOG_ERR("NULL ptr\n");
		return -1;
	}
	in.dst = MSG_CHAN_END_RISC;
	in.event_id = module_id;
	in.virt_addr = vaddr;
	in.src_pcieid = pcie_id;
	result.recv_buffer = bar_reps;
	result.buffer_len = sizeof(union zxdh_msg) + REPS_HEADER_PAYLOAD_OFFSET;

	switch (module_id) {
	case MODULE_VF_BAR_MSG_TO_PF: {
		in.dst = MSG_CHAN_END_PF;
		in.dst_pcieid = FIND_PF_PCIE_ID(pcie_id);
		in.virt_addr += ZXDH_BAR_PFVF_MSG_OFFSET;
		break;
	}
	case MODULE_PF_BAR_MSG_TO_VF: {
		in.dst = MSG_CHAN_END_VF;
		in.dst_pcieid = ((struct zxdh_msg_info *)msg)->hdr_vf.dst_pcie_id;
		in.virt_addr += ZXDH_BAR_PFVF_MSG_OFFSET;
		break;
	}
	case MODULE_TBL: {
		in.payload_len =
			MSG_STRUCT_HD_LEN + ((struct zxdh_msg_info *)msg)->hdr_to_cmn.write_bytes;
		break;
	}
	case MODULE_PF_TIMER_TO_RISC_MSG: {
		in.payload_len =
			MSG_STRUCT_HD_LEN + ((struct zxdh_msg_info *)msg)->hdr_to_cmn.write_bytes;
		break;
	}
	case MODULE_PHYPORT_QUERY: {
		in.payload_len = sizeof(struct zxdh_port_msg);
		break;
	}
	case MODULE_NPSDK: {
		in.payload_len = sizeof(struct zxdh_cfg_np_msg);
		break;
	}
	}

	ret = zxdh_bar_chan_sync_msg_send(&in, &result);
	if (ret != ZXDH_NET_ACK_OK) {
		ret = -ret;
		goto free_reps;
	}

	if (is_sync_msg && bar_reps->replied != BAR_MSG_REPS_OK) {
		LOG_ERR("reps get failed\n");
		ret = -1;
		goto free_reps;
	}

	if (bar_reps->reps_len > (BAR_MSG_PAYLOAD_MAX_LEN - REPS_HEADER_PAYLOAD_OFFSET)) {
		LOG_ERR("reps len too long\n");
		ret = -1;
		goto free_reps;
	}
	memcpy(ack, bar_reps->data, bar_reps->reps_len);

free_reps:
	kfree(bar_reps);
	return ret;
}
EXPORT_SYMBOL(zxdh_send_command);

int zxdh_bar_send_without_reps_hdr(struct zxdh_pci_bar_msg *in,
				   struct zxdh_msg_recviver_mem *result)
{
	int ret = 0;
	struct zxdh_msg_recviver_mem res_with_hdr = { 0 };
	u8 *temp_recv_buff = NULL;

	temp_recv_buff = kmalloc(result->buffer_len + REPS_HEADER_PAYLOAD_OFFSET, GFP_KERNEL);
	if (!temp_recv_buff) {
		BAR_LOG_ERR("malloc temp buffer failed.\n");
		return -1;
	}

	res_with_hdr.recv_buffer = temp_recv_buff;
	res_with_hdr.buffer_len = result->buffer_len + REPS_HEADER_PAYLOAD_OFFSET;

	ret = zxdh_bar_chan_sync_msg_send(in, &res_with_hdr);
	if (ret != 0)
		goto out;

	memcpy(result->recv_buffer, temp_recv_buff + REPS_HEADER_PAYLOAD_OFFSET,
	       result->buffer_len);

out:
	kfree(temp_recv_buff);
	return ret;
}
EXPORT_SYMBOL(zxdh_bar_send_without_reps_hdr);

s32 zxdh_vqm_queue_cfg(u64 virt_addr, u16 pcie_id, u32 phy_queue_idx)
{
	s32 ret = 0;
	struct zxdh_pci_bar_msg in = { 0 };
	struct zxdh_msg_recviver_mem result = { 0 };

	struct OVS_TO_VQM_MSG msg = { 0 };
	struct VQM_RSP_OVS_DATA reps = { 0 };

	msg.q_reset_msg.qid = phy_queue_idx;
	msg.cmd = VQM_QUEUE_RSET;

	in.virt_addr = virt_addr + ZXDH_BAR_MSG_OFFSET;
	in.payload_addr = &msg;
	in.payload_len = sizeof(msg);
	in.src_pcieid = pcie_id;
	in.src = MSG_CHAN_END_PF;
	in.dst = MSG_CHAN_END_RISC;
	in.event_id = VCQ_NOTIFY_EVENT_ID;

	result.recv_buffer = &reps;
	result.buffer_len = sizeof(reps);
	ret = zxdh_bar_chan_sync_msg_send(&in, &result);
	if (ret != BAR_MSG_OK)
		return -ret;

	if (reps.check_result != VQM_REPS_SUCCESS) {
		BAR_LOG_ERR("check result failed.reps.check_result: 0x%x\n", reps.check_result);
		return -1;
	}
	return BAR_MSG_OK;
}
EXPORT_SYMBOL(zxdh_vqm_queue_cfg);
