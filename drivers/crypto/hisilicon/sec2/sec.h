/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2018-2019 HiSilicon Limited. */

#ifndef HISI_SEC_H
#define HISI_SEC_H

#include <linux/list.h>
#include "../qm.h"
#include "sec_usr_if.h"

#undef pr_fmt
#define pr_fmt(fmt)	"hisi_sec: " fmt

#define FUSION_LIMIT_DEF	1
#define FUSION_LIMIT_MAX	64
#define FUSION_TMOUT_NSEC_DEF	(400 * 1000)

enum sec_endian {
	SEC_LE = 0,
	SEC_32BE,
	SEC_64BE
};

struct hisi_sec_ctrl;

struct hisi_sec_dfx {
	u64 send_cnt;
	u64 send_by_tmout;
	u64 send_by_full;
	u64 recv_cnt;
	u64 get_task_cnt;
	u64 put_task_cnt;
	u64 gran_task_cnt;
	u64 thread_cnt;
	u64 fake_busy_cnt;
	u64 busy_comp_cnt;
};

struct hisi_sec {
	struct hisi_qm qm;
	struct hisi_sec_dfx sec_dfx;
	struct hisi_sec_ctrl *ctrl;
	int ctx_q_num;
	int fusion_limit;
	int fusion_tmout_nsec;
};

void sec_destroy_qps(struct hisi_qp **qps, int qp_num);
struct hisi_qp **sec_create_qps(void);
struct hisi_sec *find_sec_device(int node);

#endif
