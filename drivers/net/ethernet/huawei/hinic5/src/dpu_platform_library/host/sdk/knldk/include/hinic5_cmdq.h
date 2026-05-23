/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_cmdq.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_CMDQ_H
#define HINIC5_CMDQ_H

#include <linux/types.h>
#include <linux/completion.h>
#include <linux/spinlock.h>

#include "mpu_inband_cmd_defs.h"
#include "hinic5_cmdq_enhance.h"
#include "hinic5_hw.h"
#include "hinic5_wq.h"
#include "hinic5_common.h"
#include "ossl_knl.h"
#include "hinic5_hwdev.h"

#define HINIC5_SCMD_DATA_LEN		16

#define	HINIC5_CMDQ_DEPTH		4096
#define	HINIC5_CMDQ_MAX_BUF_SIZE	2048U
#define	HINIC5_CMDQ_MIN_BUF_SIZE	4U
#define	HINIC5_CMDQ_BUF_ALIGN		2048U

#define HINIC5_CMDQ_CQE_DW0_ERR_CODE_SHIFT	29
#define HINIC5_CMDQ_CQE_DW0_ERR_CODE_MASK	0x3
#define HINIC5_CMDQ_CQE_DW0_ERR_STATUS_MASK	0x1fffffff   /* 29 bits */

enum hinic5_cmdq_mode {
	HINIC5_NORMAL_CMDQ,
	HINIC5_ENHANCE_CMDQ,
};

enum hinic5_cmdq_type {
	HINIC5_CMDQ_SYNC,
	HINIC5_CMDQ_ASYNC,
	HINIC5_CMDQ_FAST_MSG,
	HINIC5_MAX_CMDQ_TYPES = 4
};

enum hinic5_db_src_type {
	HINIC5_DB_SRC_CMDQ_TYPE,
	HINIC5_DB_SRC_L2NIC_SQ_TYPE,
};

enum hinic5_cmdq_db_type {
	HINIC5_DB_SQ_RQ_TYPE,
	HINIC5_DB_CMDQ_TYPE,
};

enum bufdesc_len {
	BUFDESC_LCMD_LEN = 2,
	BUFDESC_SCMD_LEN = 3,
	BUFDESC_ENHANCE_CMD_LEN = 3,  /* 64B aligned */
};

/* hardware define: cmdq wqe */
struct hinic5_cmdq_header {
	u32	header_info;
	u32	saved_data;
};

struct hinic5_scmd_bufdesc {
	u32	buf_len;
	u32	rsvd;
	u8	data[HINIC5_SCMD_DATA_LEN];
};

struct hinic5_lcmd_bufdesc {
	struct hinic5_sge	sge;
	u32			rsvd1;
	u64			saved_async_buf;
	u64			rsvd3;
};

struct hinic5_cmdq_db {
	u32	db_head;
	u32	db_info;
};

struct hinic5_status {
	u32	status_info;
};

struct hinic5_ctrl {
	u32	ctrl_info;
};

struct hinic5_sge_resp {
	struct hinic5_sge sge;
	u32		rsvd;
};

struct hinic5_cmdq_completion {
	union {
		struct hinic5_sge_resp	sge_resp;
		u64			direct_resp;
	};
};

struct hinic5_cmdq_wqe_scmd {
	struct hinic5_cmdq_header	header;
	u64				rsvd;
	struct hinic5_status		status;
	struct hinic5_ctrl		ctrl;
	struct hinic5_cmdq_completion	completion;
	struct hinic5_scmd_bufdesc	buf_desc;
};

struct hinic5_cmdq_wqe_lcmd {
	struct hinic5_cmdq_header	header;
	struct hinic5_status		status;
	struct hinic5_ctrl		ctrl;
	struct hinic5_cmdq_completion	completion;
	struct hinic5_lcmd_bufdesc	buf_desc;
};

struct hinic5_cmdq_inline_wqe {
	struct hinic5_cmdq_wqe_scmd	wqe_scmd;
};

struct hinic5_cmdq_wqe {
	union {
		struct hinic5_cmdq_inline_wqe	inline_wqe;
		struct hinic5_cmdq_wqe_lcmd	wqe_lcmd;
		struct hinic5_enhanced_cmdq_wqe	enhanced_cmdq_wqe;
	};
};

struct hinic5_cmdq_arm_bit {
	u32	q_type;
	u32	q_id;
};

enum hinic5_cmdq_status {
	HINIC5_CMDQ_ENABLE = BIT(0),
};

enum hinic5_cmdq_cmd_type {
	HINIC5_CMD_TYPE_NONE,
	HINIC5_CMD_TYPE_SET_ARM,
	HINIC5_CMD_TYPE_DIRECT_RESP,
	HINIC5_CMD_TYPE_SGE_RESP,
	HINIC5_CMD_TYPE_ASYNC,
	HINIC5_CMD_TYPE_FAKE_TIMEOUT,
	HINIC5_CMD_TYPE_TIMEOUT,
	HINIC5_CMD_TYPE_FORCE_STOP,
	HINIC5_CMD_TYPE_INLINE_DATA,
};

enum data_format {
	DATA_SGE,
	DATA_DIRECT,
};

#define	WQ_BLOCK_PFN_SHIFT		9
#define CMDQ_PFN_SHIFT			12
#define CMDQ_PFN(addr)			((addr) >> CMDQ_PFN_SHIFT)
#define WQ_BLOCK_PFN(addr)		((addr) >> WQ_BLOCK_PFN_SHIFT)

struct hinic5_cmdq_cmd_info {
	enum hinic5_cmdq_cmd_type	cmd_type;
	u16				channel;
	u16				rsvd1;
	u16				wqebb_use_num;

	struct completion		*done;
	int				*errcode;
	int				*cmpt_code;
	u64				*direct_resp;
	u64				cmdq_msg_id;

	struct hinic5_cmd_buf		*buf_in;
	struct hinic5_cmd_buf		*buf_out;
};

struct hinic5_cmdq {
	struct hinic5_wq		wq;

	enum hinic5_cmdq_type		cmdq_type;
	int				wrapped;

	/* spinlock for send cmdq commands */
	spinlock_t			cmdq_lock;

	struct cmdq_ctxt_info		cmdq_ctxt;
	struct enhance_cmdq_ctxt_info	cmdq_enhance_ctxt;

	struct hinic5_cmdq_cmd_info	*cmd_infos;

	struct hinic5_hwdev		*hwdev;
	struct hinic5_cmdqs		*cmdqs;
	u64				rsvd1[2];
};

struct hinic5_cmdqs {
	struct hinic5_hwdev *hwdev;

	struct dma_pool *cmd_buf_pool;
	/* doorbell area */
	u8 __iomem *cmdqs_db_base;

	/* All cmdq's CLA of a VF occupy a PAGE when cmdq wq is 1-level CLA */
	dma_addr_t wq_block_paddr;
	void *wq_block_vaddr;
	struct hinic5_cmdq cmdq[HINIC5_MAX_CMDQ_TYPES];

	u32 status;
	u32 disable_flag;

	bool lock_channel_en;
	ulong channel_stop;
	u8 cmdq_num;
	u8 cmdq_mode;
	u8 wqebb_size;
	u8 wqebb_use_num;
	u8 rsvd1;
	u64 rsvd2;
	u32 cmd_buf_size;
	bool poll; /* use polling mode or int mode */
};

void hinic5_cmdq_ceq_handler(void *handle, u32 ceqe_data);

int hinic5_reinit_cmdq_ctxts(struct hinic5_hwdev *hwdev);

bool hinic5_cmdq_idle(struct hinic5_cmdq *cmdq);

int hinic5_cmdqs_init(struct hinic5_hwdev *hwdev);

void hinic5_cmdqs_free(struct hinic5_hwdev *hwdev);

void hinic5_cmdq_flush_cmd(struct hinic5_hwdev *hwdev,
			   struct hinic5_cmdq *cmdq);

int hinic5_cmdq_set_channel_status(struct hinic5_hwdev *hwdev, u16 channel,
				   bool enable);

void hinic5_cmdq_enable_channel_lock(struct hinic5_hwdev *hwdev, bool enable);

void hinic5_cmdq_flush_sync_cmd(struct hinic5_hwdev *hwdev);

void hinic5_enhanced_cmdq_set_wqe(struct hinic5_cmdq_wqe *wqe,
			   enum hinic5_cmdq_cmd_type cmd_type,
			   const struct hinic5_cmdq_cmd_param *cmd_buf,
			   int wrapped);
void hinic5_enhanced_cmdq_init_queue_ctxt(struct hinic5_cmdqs *cmdqs, struct hinic5_cmdq *cmdq);
void hinic5_cmdqs_param_init(struct hinic5_hwdev *hwdev, struct hinic5_cmdqs *cmdqs);
int hinic5_send_fast_msg_need_resp(void *hwdev, u8 mod, u8 cmd,
				   struct hinic5_cmd_buf *buf_in,
				   u64 *out_param);
int hinic5_cos_id_direct_resp(void *hwdev, u8 mod, u8 cmd, u16 cos_id,
			      struct hinic5_cmd_buf *buf_in, u64 *out_param,
			      u32 timeout, u16 channel);
#endif

