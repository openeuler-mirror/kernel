/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPHW_MGMT_H
#define SPHW_MGMT_H

#define SPHW_MGMT_WQ_NAME			"sphw_mgmt"

#define SPHW_CLP_REG_GAP			0x20
#define SPHW_CLP_INPUT_BUF_LEN_HOST		4096UL
#define SPHW_CLP_DATA_UNIT_HOST		4UL

enum clp_data_type {
	SPHW_CLP_REQ_HOST = 0,
	SPHW_CLP_RSP_HOST = 1
};

enum clp_reg_type {
	SPHW_CLP_BA_HOST = 0,
	SPHW_CLP_SIZE_HOST = 1,
	SPHW_CLP_LEN_HOST = 2,
	SPHW_CLP_START_REQ_HOST = 3,
	SPHW_CLP_READY_RSP_HOST = 4
};

#define SPHW_CLP_REQ_SIZE_OFFSET		0
#define SPHW_CLP_RSP_SIZE_OFFSET		16
#define SPHW_CLP_BASE_OFFSET			0
#define SPHW_CLP_LEN_OFFSET			0
#define SPHW_CLP_START_OFFSET			31
#define SPHW_CLP_READY_OFFSET			31
#define SPHW_CLP_OFFSET(member)		(SPHW_CLP_##member##_OFFSET)

#define SPHW_CLP_SIZE_MASK			0x7ffUL
#define SPHW_CLP_BASE_MASK			0x7ffffffUL
#define SPHW_CLP_LEN_MASK			0x7ffUL
#define SPHW_CLP_START_MASK			0x1UL
#define SPHW_CLP_READY_MASK			0x1UL
#define SPHW_CLP_MASK(member)			(SPHW_CLP_##member##_MASK)

#define SPHW_CLP_DELAY_CNT_MAX		200UL
#define SPHW_CLP_SRAM_SIZE_REG_MAX		0x3ff
#define SPHW_CLP_SRAM_BASE_REG_MAX		0x7ffffff
#define SPHW_CLP_LEN_REG_MAX			0x3ff
#define SPHW_CLP_START_OR_READY_REG_MAX	0x1

struct sphw_recv_msg {
	void			*msg;

	u16			msg_len;
	enum sphw_mod_type	mod;
	u16			cmd;
	u8			seq_id;
	u16			msg_id;
	int			async_mgmt_to_pf;

	struct completion	recv_done;
};

struct sphw_msg_head {
	u8	status;
	u8	version;
	u8	resp_aeq_num;
	u8	rsvd0[5];
};

enum comm_pf_to_mgmt_event_state {
	SEND_EVENT_UNINIT = 0,
	SEND_EVENT_START,
	SEND_EVENT_SUCCESS,
	SEND_EVENT_FAIL,
	SEND_EVENT_TIMEOUT,
	SEND_EVENT_END,
};

enum sphw_mgmt_msg_cb_state {
	SPHW_MGMT_MSG_CB_REG = 0,
	SPHW_MGMT_MSG_CB_RUNNING,
};

struct sphw_clp_pf_to_mgmt {
	struct semaphore	clp_msg_lock;
	void			*clp_msg_buf;
};

struct sphw_msg_pf_to_mgmt {
	struct sphw_hwdev		*hwdev;

	/* Async cmd can not be scheduling */
	spinlock_t			async_msg_lock;
	struct semaphore		sync_msg_lock;

	struct workqueue_struct		*workq;

	void				*async_msg_buf;
	void				*sync_msg_buf;
	void				*mgmt_ack_buf;

	struct sphw_recv_msg		recv_msg_from_mgmt;
	struct sphw_recv_msg		recv_resp_msg_from_mgmt;

	u16				async_msg_id;
	u16				sync_msg_id;
	struct sphw_api_cmd_chain	*cmd_chain[SPHW_API_CMD_MAX];

	sphw_mgmt_msg_cb		recv_mgmt_msg_cb[SPHW_MOD_HW_MAX];
	void				*recv_mgmt_msg_data[SPHW_MOD_HW_MAX];
	unsigned long			mgmt_msg_cb_state[SPHW_MOD_HW_MAX];

	void				*async_msg_cb_data[SPHW_MOD_HW_MAX];

	/* lock when sending msg */
	spinlock_t			sync_event_lock;
	enum comm_pf_to_mgmt_event_state event_flag;
};

struct sphw_mgmt_msg_handle_work {
	struct work_struct	work;
	struct sphw_msg_pf_to_mgmt *pf_to_mgmt;

	void			*msg;
	u16			msg_len;

	enum sphw_mod_type	mod;
	u16			cmd;
	u16			msg_id;

	int			async_mgmt_to_pf;
};

void sphw_mgmt_msg_aeqe_handler(void *handle, u8 *header, u8 size);

int sphw_pf_to_mgmt_init(struct sphw_hwdev *hwdev);

void sphw_pf_to_mgmt_free(struct sphw_hwdev *hwdev);

int sphw_pf_to_mgmt_sync(void *hwdev, u8 mod, u16 cmd, void *buf_in,
			 u16 in_size, void *buf_out, u16 *out_size, u32 timeout);
int sphw_pf_to_mgmt_async(void *hwdev, u8 mod, u16 cmd, const void *buf_in, u16 in_size);

int sphw_pf_msg_to_mgmt_sync(void *hwdev, u8 mod, u16 cmd, void *buf_in,
			     u16 in_size, void *buf_out, u16 *out_size, u32 timeout);

int sphw_api_cmd_read_ack(void *hwdev, u8 dest, const void *cmd, u16 size,
			  void *ack, u16 ack_size);

int sphw_api_cmd_write_nack(void *hwdev, u8 dest, const void *cmd, u16 size);

int sphw_pf_clp_to_mgmt(void *hwdev, u8 mod, u16 cmd, const void *buf_in,
			u16 in_size, void *buf_out, u16 *out_size);

int sphw_clp_pf_to_mgmt_init(struct sphw_hwdev *hwdev);

void sphw_clp_pf_to_mgmt_free(struct sphw_hwdev *hwdev);

#endif
