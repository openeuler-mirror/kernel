/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_DFX_H
#define ROCE_DFX_H

#include <linux/types.h>

#include "hinic3_rdma.h"

#include "roce_sysfs.h"
#include "roce.h"
#include "roce_verbs_cmd.h"
#include "rdma_context_format.h"

#ifdef ROCE_PKT_CAP_EN
#include "roce_dfx_cap.h"
#endif

#define MR_KEY_2_INDEX_SHIFT 8

#define ROCE_IO_DFX_CFG_VADDR_ID 0
#define ROCE_IO_DFX_CFG_PADDR_ID 1
#define ROCE_IO_DFX_CFG_ADDR_NUM 2

struct roce3_mpt_query_outbuf {
	struct roce_mpt_context mpt_entry;
};

#define roce3_dfx_print pr_info

struct roce3_dfx_query_inbuf {
	u32 cmd_type;
	/*lint -e658*/
	union {
		u32 qpn;
		u32 cqn;
		u32 srqn;
		u32 mpt_key;
		u32 gid_index;
		struct {
			u32 qpn;
			u32 cqn;
		} query_pi_ci;
	};
	/*lint +e658*/
};

struct roce3_dfx_pi_ci {
	u32 qpc_sq_pi_on_chip;
	u32 qpc_sq_pi;
	u32 qpc_sq_load_pi;
	u32 qpc_rq_pi_on_chip;
	u32 qpc_rq_load_pi;
	u32 qpc_rq_pi;
	u32 qpc_rc_pi;
	u32 qpc_sq_ci;
	u32 qpc_sq_wqe_prefetch_ci;
	u32 qpc_sq_mtt_prefetch_wqe_ci;
	u32 qpc_sqa_ci;
	u32 qpc_sqa_wqe_prefetch_ci;
	u32 qpc_rq_ci;
	u32 qpc_rq_wqe_prefetch_ci;
	u32 qpc_rq_mtt_prefetch_wqe_ci;
	u32 qpc_rq_base_ci;
	u32 qpc_rc_ci;
	u32 qpc_rc_prefetch_ci;
	u32 cq_ci_on_chip;
	u32 cq_ci;
	u32 cq_load_ci;
	u64 cq_ci_record_gpa_at_hop_num;
	u32 cq_last_solicited_pi;
	u32 cq_pi;
	u32 cq_last_notified_pi;
};

struct roce3_dfx_qp_count {
	u32 qp_alloced;
	u32 qp_deleted;
	u32 qp_alive;
};

union roce3_dfx_query_outbuf {
	struct roce_qp_context qp_ctx;
	struct roce_cq_context cq_ctx;
	struct roce_srq_context srq_ctx;
	struct roce_mpt_context mpt;
	struct rdma_gid_entry gid_entry;
	struct roce3_dfx_pi_ci pi_ci;
	struct roce3_dfx_qp_count qp_count;
	u32 algo_type;
};

enum roce3_bw_ctrl_cmd_e {
	ROCE_BW_CTRL_DIS,
	ROCE_BW_CTRL_EN,
	ROCE_BW_CTRL_RESET
};
struct rdma_gid_query_outbuf {
	struct rdma_gid_entry gid_entry;
};

struct roce3_bw_ctrl_inbuf {
	u32 cmd_type;
	struct {
		u32 cir;
		u32 pir;
		u32 cnp;
	} ctrl_param;
};

struct roce3_bw_ctrl_param {
	u8 color_type;
	u16 ptype;
	u8 hw_wred_mode;

	u32 cir;
	u32 pir;
	u32 cbs;
	u32 xbs;
	u32 cnp;
	u32 enable;
};

struct roce3_bw_ctrl_outbuf {
	struct roce3_bw_ctrl_param bw_ctrl_param;
};

enum roce3_dfx_io_cmd_type {
	ROCE_IO_CTRL_DIS,
	ROCE_IO_CTRL_EN
};

struct roce3_dfx_io_alarm {
	enum roce3_dfx_io_cmd_type en_flag;
	u16 pf_id;
	u16 rsvd;
	u16 io_latency_thd;
	u16 exec_time;
	u32 exp_qpn;
	void *rcd_uaddr;
	struct timespec64 start;
	struct mutex io_alarm_mutex;
};

struct roce3_dfx_io_inbuf {
	u32 cmd_type;
	struct roce3_dfx_io_alarm io_alarm;
};

struct roce3_dfx_io_outbuf {
	struct roce3_dfx_io_alarm io_alarm;
};

int roce3_get_drv_version(struct roce3_device *rdev, const void *buf_in, u32 in_size,
	void *buf_out, u32 *out_size);
int roce3_adm_dfx_query(struct roce3_device *rdev, const void *buf_in, u32 in_size,
	void *buf_out, u32 *out_size);
int roce3_adm_dfx_bw_ctrl(struct roce3_device *rdev, const void *buf_in, u32 in_size,
	void *buf_out, u32 *out_size);
void roce3_dfx_clean_up(struct roce3_device *rdev);

void *global_roce3_io_alarm_va_get(void);

void global_roce3_io_alarm_va_set(u64 va);

void global_roce3_io_alarm_pa_set(dma_addr_t pa);

dma_addr_t global_roce3_io_alarm_pa_get(void);

int roce3_dfx_cmd_query_qp(struct roce3_device *rdev, u32 qpn, struct roce_qp_context *qp_ctx);

int roce3_dfx_cmd_query_cq(struct roce3_device *rdev, u32 cqn, struct roce_cq_context *cq_ctx);

int roce3_dfx_cmd_query_srq(struct roce3_device *rdev, u32 srqn, struct roce_srq_context *srq_ctx);

#endif // __ROCE_DFX_H__
