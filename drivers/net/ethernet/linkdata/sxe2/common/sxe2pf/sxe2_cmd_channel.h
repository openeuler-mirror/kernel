/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_cmd_channel.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_CMD_CHANNEL_H__
#define __SXE2_CMD_CHANNEL_H__

#include <linux/wait.h>
#include <linux/mutex.h>
#include <linux/hashtable.h>
#include <linux/workqueue.h>

#include "sxe2_cmd.h"
#include "sxe2_spec.h"

struct sxe2_adapter;
struct sxe2_hw;

#define SXE2_CMD_HASH_TABLE_ORDER 8

#define SXE2_DEPTH_FW_TQ 256
#define SXE2_DEPTH_FW_RQ 256
#define SXE2_DEPTH_MBX_TQ 64
#define SXE2_DEPTH_MBX_RQ 512

#define SXE2_CMD_ATQ_SEND_MAX_LEN (512)
#define SXE2_CMD_ARQ_RECV_MAX_LEN (352)

#define SXE2_CMD_ATQ_SEND_APP_MAX_LEN (SXE2_CMD_ATQ_SEND_MAX_LEN - SXE2_CMD_HDR_SIZE)
#define SXE2_CMD_ARQ_RECV_APP_MAX_LEN (SXE2_CMD_ARQ_RECV_MAX_LEN - SXE2_CMD_HDR_SIZE)

#define SXE2_DRV_CMD_DFLT_TIMEOUT (30)

#define LOG_DEBUG_TRACEID(fmt, ...) LOG_DEBUG_BDF("[trace id 0x%llx] " fmt, trace_id, ##__VA_ARGS__)
#define LOG_INFO_TRACEID(fmt, ...) LOG_INFO_BDF("[trace id 0x%llx] " fmt, trace_id, ##__VA_ARGS__)
#define LOG_WARN_TRACEID(fmt, ...) LOG_WARN_BDF("[trace id 0x%llx] " fmt, trace_id, ##__VA_ARGS__)
#define LOG_ERROR_TRACEID(fmt, ...) LOG_ERROR_BDF("[trace id 0x%llx] " fmt, trace_id, ##__VA_ARGS__)

union sxe2_trace_info {
	u64 id;
	struct {
		u64 count : 50;
		u64 cpu_id : 10;
		u64 type : 4;
	} sxe2_trace_id_param;
};

enum sxe2_cmd_channel_type {
	SXE2_CHNL_FW = 0,
	SXE2_CHNL_MBX,
	SXE2_CMD_CHANNEL_MAX,
};

enum sxe2_cmd_queue_type {
	SXE2_CMD_TQ = 0,
	SXE2_CMD_RQ,
	SXE2_CMD_QUEUE_MAX,
};

enum sxe2_cmd_state {
	SXE2_CMD_STATE_WAITING = 0,
	SXE2_CMD_STATE_DONE,
	SXE2_CMD_STATE_CANCELED,
	SXE2_CMD_STATE_FAULT,
};

enum sxe2_cmd_channel_mode {
	SXE2_CMD_POLLING = 0,
	SXE2_CMD_NOTIFY,
};

struct sxe2_dma_mem {
	void *va;
	dma_addr_t pa;
	size_t size;
};

struct sxe2_cmd_queue_operations {
	s32 (*enable)(struct sxe2_hw *hw, u16 depth, dma_addr_t addr);
	void (*disable)(struct sxe2_hw *hw);
	s32 (*is_idle)(struct sxe2_hw *hw);
	void (*write_tail)(struct sxe2_hw *hw, u32 value);
	u32 (*read_head)(struct sxe2_hw *hw);
	u32 (*get_error)(struct sxe2_hw *hw);
};

struct sxe2_recv_cache_buff {
	u16 buf_offset;
	bool finish;
	u8 res;
	u8 *buf;
};

struct sxe2_cmd_queue {
	u16 depth;
	u16 buf_size;
	u16 ntu;
	u16 ntc;
	u8 is_enable;
	struct sxe2_dma_mem desc;
	struct sxe2_dma_mem *buf;
	/* in order to protect the data */
	struct mutex lock;
	struct sxe2_cmd_queue_operations ops;
	struct sxe2_recv_cache_buff cache_buff;
};

struct sxe2_recv_msg {
	struct list_head node;
	u16 buf_len;
	struct sxe2_cmd_desc desc;
	u8 buf[];
};

struct sxe2_cmd_wait_task {
	struct hlist_node entry;
	u64 session_id;
	enum sxe2_cmd_state state;
	u16 resp_len;
	void *resp_data;
};

struct sxe2_cmd_wait_queue {
	/* in order to protect the data */
	spinlock_t lock;
	wait_queue_head_t wq;
	DECLARE_HASHTABLE(table, SXE2_CMD_HASH_TABLE_ORDER);
};

struct sxe2_cmd_channel {
	struct sxe2_cmd_queue queue[SXE2_CMD_QUEUE_MAX];
	struct sxe2_cmd_wait_queue wq;
	enum sxe2_cmd_channel_type chnl_type;
	/* in order to protect the data */
	struct mutex lock;
	u8 is_enable;
};

struct sxe2_cmd_channel_context {
	enum sxe2_cmd_channel_mode mode;
	struct work_struct recv_work;
	unsigned long recv_work_state;
	struct work_struct handle_work;
	unsigned long handle_work_state;
	/* in order to protect the data */
	spinlock_t recv_work_lock;
	/* in order to protect the data */
	spinlock_t handle_work_lock;
	struct list_head head;
	/* in order to protect the data */
	struct mutex lock;
	struct sxe2_cmd_channel channel[SXE2_CMD_CHANNEL_MAX];
	/* in order to protect the data */
	struct mutex event_lock;
};

struct sxe2_cmd_params {
	u64 trace_id;
	s32 err_code;
	u16 vf_idx;
	u8 is_interruptible;
	bool no_resp;
	u32 timeout;
	u32 opcode;
	u64 session_id;
	u16 req_len;
	u16 resp_len;
	void *req_data;
	void *resp_data;
};

struct sxe2_cmd_trans_info {
	u16 req_len;
	u16 resp_len;
	void *req_buff;
	void *resp_buff;
};

struct sxe2_cmd_context {
	struct sxe2_adapter *adapter;
	enum sxe2_cmd_type type;
	enum sxe2_cmd_channel_type chnl_type;
	u16 cancelable;
	u64 session_id;
	u64 expired_time;
	struct sxe2_cmd_params *params;
	struct sxe2_cmd_wait_task wait_task;
	struct sxe2_cmd_trans_info trans_info;
};

s32 sxe2_cmd_channels_init(struct sxe2_adapter *adapter);

void sxe2_cmd_channels_deinit(struct sxe2_adapter *adapter);

s32 sxe2_cmd_channels_enable(struct sxe2_adapter *adapter);

void sxe2_cmd_channels_disable(struct sxe2_adapter *adapter);

void sxe2_cmd_params_fill(struct sxe2_cmd_params *cmd,
			  enum sxe2_drv_cmd_opcode opc,
			  void *req_data, u32 req_len,
			  void *resp_data, u32 resp_len,
			  u32 timeout,
			  bool is_interruptible,
			  bool no_resp);

void sxe2_cmd_params_no_interruptible_fill(struct sxe2_cmd_params *cmd,
					   enum sxe2_drv_cmd_opcode opc,
					   void *req_data,
					   u32 req_len,
					   void *resp_data,
					   u32 resp_len);

void sxe2_cmd_params_dflt_fill(struct sxe2_cmd_params *cmd,
			       enum sxe2_drv_cmd_opcode opc,
			       void *in_data, u32 in_len,
			       void *out_data, u32 out_len);
s32 sxe2_cmd_fw_exec(struct sxe2_adapter *adapter, struct sxe2_cmd_params *cmd_params);

s32 sxe2_cmd_mbx_reply(struct sxe2_adapter *adapter, struct sxe2_cmd_params *cmd_params);

s32 sxe2_cmd_mbx_exec(struct sxe2_adapter *adapter, struct sxe2_cmd_params *cmd_params);

s32 sxe2_cmd_cli_exec(struct sxe2_adapter *adapter, struct sxe2_cmd_params *cmd_params);

void sxe2_wait_task_cancel(struct sxe2_cmd_channel *channel);

void sxe2_wait_task_cancel_all(struct sxe2_adapter *adapter);

bool sxe2_cmd_channel_work(struct sxe2_adapter *adapter, enum sxe2_cmd_channel_type chnl_type);

bool sxe2_cmd_rq_pending(struct sxe2_adapter *adapter, enum sxe2_cmd_channel_type chnl_type);

void sxe2_rq_recv_work_schedule(struct sxe2_adapter *adapter);

s32 sxe2_cmd_work_create(void);

void sxe2_cmd_work_destroy(void);

s32 sxe2_cmd_strip_hdr(struct sxe2_cmd_context *cmd_ctxt);

void sxe2_trace_id_alloc(u64 *trace_id);

bool sxe2_mbx_channel_work(struct sxe2_adapter *adapter);

s32 sxe2_err_code_trans_fw(struct sxe2_adapter *adapter, u64 trace_id, s32 err);

struct mutex *sxe2_cmd_channel_get_event_lock(struct sxe2_adapter *adapter);

void sxe2_mbx_channel_disable(struct sxe2_adapter *adapter);

s32 sxe2_mbx_channel_enable(struct sxe2_adapter *adapter);

#endif
