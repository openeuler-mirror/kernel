/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPHW_CMDQ_H
#define SPHW_CMDQ_H

#include "sphw_comm_msg_intf.h"

#define SPHW_SCMD_DATA_LEN		16

#define	SPHW_CMDQ_DEPTH		4096

enum sphw_cmdq_type {
	SPHW_CMDQ_SYNC,
	SPHW_CMDQ_ASYNC,
	SPHW_MAX_CMDQ_TYPES,
};

enum sphw_db_src_type {
	SPHW_DB_SRC_CMDQ_TYPE,
	SPHW_DB_SRC_L2NIC_SQ_TYPE,
};

enum sphw_cmdq_db_type {
	SPHW_DB_SQ_RQ_TYPE,
	SPHW_DB_CMDQ_TYPE,
};

/*hardware define: cmdq wqe*/
struct sphw_cmdq_header {
	u32	header_info;
	u32	saved_data;
};

struct sphw_scmd_bufdesc {
	u32	buf_len;
	u32	rsvd;
	u8	data[SPHW_SCMD_DATA_LEN];
};

struct sphw_lcmd_bufdesc {
	struct sphw_sge		sge;
	u32			rsvd1;
	u64			saved_async_buf;
	u64			rsvd3;
};

struct sphw_cmdq_db {
	u32	db_head;
	u32	db_info;
};

struct sphw_status {
	u32	status_info;
};

struct sphw_ctrl {
	u32	ctrl_info;
};

struct sphw_sge_resp {
	struct sphw_sge	sge;
	u32		rsvd;
};

struct sphw_cmdq_completion {
	union {
		struct sphw_sge_resp	sge_resp;
		u64			direct_resp;
	};
};

struct sphw_cmdq_wqe_scmd {
	struct sphw_cmdq_header		header;
	u64				rsvd;
	struct sphw_status		status;
	struct sphw_ctrl		ctrl;
	struct sphw_cmdq_completion	completion;
	struct sphw_scmd_bufdesc	buf_desc;
};

struct sphw_cmdq_wqe_lcmd {
	struct sphw_cmdq_header		header;
	struct sphw_status		status;
	struct sphw_ctrl		ctrl;
	struct sphw_cmdq_completion	completion;
	struct sphw_lcmd_bufdesc	buf_desc;
};

struct sphw_cmdq_inline_wqe {
	struct sphw_cmdq_wqe_scmd	wqe_scmd;
};

struct sphw_cmdq_wqe {
	union {
		struct sphw_cmdq_inline_wqe	inline_wqe;
		struct sphw_cmdq_wqe_lcmd	wqe_lcmd;
	};
};

struct sphw_cmdq_arm_bit {
	u32	q_type;
	u32	q_id;
};

enum sphw_cmdq_status {
	SPHW_CMDQ_ENABLE = BIT(0),
};

enum sphw_cmdq_cmd_type {
	SPHW_CMD_TYPE_NONE,
	SPHW_CMD_TYPE_SET_ARM,
	SPHW_CMD_TYPE_DIRECT_RESP,
	SPHW_CMD_TYPE_SGE_RESP,
	SPHW_CMD_TYPE_ASYNC,
	SPHW_CMD_TYPE_FAKE_TIMEOUT,
	SPHW_CMD_TYPE_TIMEOUT,
	SPHW_CMD_TYPE_FORCE_STOP,
};

struct sphw_cmdq_cmd_info {
	enum sphw_cmdq_cmd_type		cmd_type;
	u16				channel;

	struct completion		*done;
	int				*errcode;
	int				*cmpt_code;
	u64				*direct_resp;
	u64				cmdq_msg_id;

	struct sphw_cmd_buf		*buf_in;
	struct sphw_cmd_buf		*buf_out;
};

struct sphw_cmdq {
	struct sphw_wq			wq;

	enum sphw_cmdq_type		cmdq_type;
	int				wrapped;

	/* spinlock for send cmdq commands */
	spinlock_t			cmdq_lock;

	/* doorbell area */
	u8 __iomem			*db_base;

	struct cmdq_ctxt_info		cmdq_ctxt;

	struct sphw_cmdq_cmd_info	*cmd_infos;

	struct sphw_hwdev		*hwdev;
};

struct sphw_cmdqs {
	struct sphw_hwdev		*hwdev;

	struct pci_pool			*cmd_buf_pool;

	/* All cmdq's CLA of a VF occupy a PAGE when cmdq wq is 1-level CLA */
	dma_addr_t			wq_block_paddr;
	void				*wq_block_vaddr;
	struct sphw_cmdq		cmdq[SPHW_MAX_CMDQ_TYPES];

	u32				status;
	u32				disable_flag;

	bool				lock_channel_en;
	unsigned long			channel_stop;
};

enum sphw_set_arm_type {
	SPHW_SET_ARM_CMDQ,
	SPHW_SET_ARM_SQ,
	SPHW_SET_ARM_TYPE_NUM,
};

int sphw_set_arm_bit(void *hwdev, enum sphw_set_arm_type q_type, u16 q_id);

void sphw_cmdq_ceq_handler(void *hwdev, u32 ceqe_data);

int sphw_reinit_cmdq_ctxts(struct sphw_hwdev *hwdev);

bool sphw_cmdq_idle(struct sphw_cmdq *cmdq);

int sphw_cmdqs_init(struct sphw_hwdev *hwdev);

void sphw_cmdqs_free(struct sphw_hwdev *hwdev);

void sphw_cmdq_flush_cmd(struct sphw_hwdev *hwdev, struct sphw_cmdq *cmdq);

int sphw_cmdq_set_channel_status(struct sphw_hwdev *hwdev, u16 channel, bool enable);

void sphw_cmdq_enable_channel_lock(struct sphw_hwdev *hwdev, bool enable);

#endif
