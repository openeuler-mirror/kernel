/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __QPTS_H__
#define __QPTS_H__

struct __packed xsc_qp_trace {
	u16 main_ver;
	u16 sub_ver;
	u32 pid;
	u16 qp_type;
	u16 af_type;
	union {
		u32 s_addr4;
		u8  s_addr6[16];
	} s_addr;
	union {
		u32 d_addr4;
		u8  d_addr6[16];
	} d_addr;
	u16 s_port;
	u16 d_port;
	u32 affinity_idx;
	u64 timestamp;
	u32 lqpn;
	u32 rqpn;
};

struct __packed qpt_update_affinity {
	u32 aff_new;
	u32 aff_old;
};

struct __packed qpt_update_sport {
	u16 port_new;
	u16 port_old;
};

struct __packed qpt_update_data {
	u64 timestamp;
	u32 qpn;
	u32 bus;
	u32 dev;
	u32 fun;
	union {
		struct qpt_update_affinity affinity;
		struct qpt_update_sport sport;
	} update;
};

struct __packed xsc_qpt_update_msg {
	u16 main_ver;
	u16 sub_ver;
	u32 type; //0:UPDATE_TYPE_SPORT; 1:UPDATE_TYPE_AFFINITY
	struct qpt_update_data data;
};

enum {
	YS_QPTRACE_UPDATE_TYPE_SPORT = 0,
	YS_QPTRACE_UPDATE_TYPE_AFFINITY,
};

#define YS_QPTRACE_VER_MAJOR    2
#define YS_QPTRACE_VER_MINOR    0

int qpts_init(void);
void qpts_fini(void);
int qpts_write_one_msg(struct xsc_qpt_update_msg *msg);

#endif
