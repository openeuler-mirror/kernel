/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_DFX_CAP_H
#define ROCE_DFX_CAP_H

#include <linux/types.h>

#include "hinic3_rdma.h"

#include "roce_sysfs.h"
#include "roce.h"

#define CAP_PKT_ITEM_SIZE 128

#define CAP_NUM_PER_BLOCK 255

#define CAP_SKB_LEN 120

#define CAP_HDR_OFFSET 4

#define FILL_CAP_CFG_PKT_NUM 8192

#define CAP_LOOP 255

#define CLEAR_MAX_TRY_TIME 10

#define CLEAR_SLEEP_TIME 2

#define CAP_STOP_SLEEP_TIME 50

#define CAP_COUNTER_TWO 2

#define CAP_PA_TBL_ENTRY_NUM 255

#define CAP_ADDR_COMBIN_SHIFT 32

#define CLEAR_CAP_TRYING_TIMES 10

#define ROCE_CAP_COUNTER_INDEX 0x39ff

union roce3_cap_hdr {
	struct {
		u32 rsvd : 16;
		u32 pad : 8;
		u32 rsvd0 : 2;
		u32 col_num : 4;
		u32 tx_rx : 1;
		u32 vld : 1;
	} cap_ctrl_info;
	u32 value;
};

struct roce3_dfx_cap_pa_entry {
	u32 wr_init_pc_h32;
	u32 wr_init_pc_l32;
};

struct roce3_dfx_cap_tbl {
	roce3_dfx_cap_pa_entry_s pa[2];
};

struct roce3_dfx_cap_cfg_tbl {
	u32 ci_index;

	union {
		struct {
			/*
			 * Driver configurate bit offset by the number of per
			 * pa block, for example, 7 means 128, 8 means 256
			 */
			u8 cap_block_num_shift;
			u8 cap_mode; /* Packet Capture mode */
			u8 qp_mode;  /* according to qp Packet Capture */
			u8 rsvd;	 /* reserved */
		} bs;
		u32 value;
	} dw1;

	union {
		struct {
			u32 state : 8; /* Packet Capture rate control */
			u32 rsvd : 8;
			u32 cap_func : 16; /* Packet Capture function */
		} bs;
		u32 value;
	} dw2;

	u32 maxnum;
};

struct roce3_qp_cap_pkt_list {
	u32 xid;
	struct list_head list;
};

struct roce3_cap_block_num_attr {
	u32 block_num_idx;
	u32 shift;
	u32 num;
};

struct sdk_thread_info {
	struct task_struct *thread_obj;
	char *name;
	void (*thread_fn)(void *unused);
	void *thread_event;
	void *data;
};

struct roce3_pkt_cap_info {
	struct roce3_device *rdev;
	u32 func_id;
	u32 poll_ci;
	u32 cap_mode;	/* 0 : drop mode 1: overwrite mode */
	u32 mode;	/* 0 : func mode 1: qp mode */
	u32 cap_status; /* 0 : stopped 1: running */
	u32 block_num_idx;
	u32 block_num_per_entry;
	u32 maxnum;
	struct sdk_thread_info task;
	char thread_name[20];
	u64 que_addr[2][2][256];
	struct list_head qp_list_head; /* Based on qp Packet Capture linked list */
	u32 qp_list_cnt;
};

#define ROCE_DFX_MAX_CAPTURE_QP_NUM 511

struct roce3_qp_cap_pkt {
	__be32 xid;
};

struct roce3_dfx_capture_inbuf {
	u32 cmd_type;
	u32 mode;
	u32 qpn;
};

struct roce3_dfx_capture_info {
	u32 cap_status;
	u32 cap_mode;
	u32 qp_mode;
	u32 cap_block_num_shift;
	u32 cap_func;
	u32 cap_state;
	u32 cap_max_num;
	u32 cap_pi;
	u32 cap_ci;
	u32 cap_total;
};

struct roce3_dfx_qp_capture_info {
	u32 qp_num;
	u32 qpn[ROCE_DFX_MAX_CAPTURE_QP_NUM];
};

union roce3_dfx_capture_outbuf {
	struct roce3_dfx_capture_info capture_info;
	struct roce3_dfx_qp_capture_info qp_capture_info;
};

enum roce3_dfx_capture_mode {
	ROCE_CAPTURE_MODE_CAP_FUNC = 0,
	ROCE_CAPTURE_MODE_CAP_QP,
};

enum roce3_dfx_capture_state {
	ROCE_CAPTURE_START = 0,
	ROCE_CAPTURE_STOP,
};

extern int hinic3_set_func_capture_en(void *hwdev, u16 func_id, bool cap_en);

int roce3_adm_dfx_capture(struct roce3_device *rdev, const void *buf_in, u32 in_size,
	void *buf_out, u32 *out_size);
int roce3_dfx_stop_cap_pkt(struct roce3_device *rdev, const struct roce3_dfx_capture_inbuf *inbuf,
	union roce3_dfx_capture_outbuf *outbuf);
static DEFINE_MUTEX(cap_mutex);

#endif /* ROCE_DFX_CAP_H */
