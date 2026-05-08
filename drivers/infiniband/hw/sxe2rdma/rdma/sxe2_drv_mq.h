/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_mq.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef SXE2_DRV_MQ_H
#define SXE2_DRV_MQ_H

#include "sxe2_drv_rdma_common.h"
#include "sxe2_drv_hw.h"
#include <linux/bitfield.h>

#define MQ_BITS_PER_INT		(32)
#define SXE2_MQC_SQ_BASE_OFFSET (9)
#define SXE2_MQC_ADDR_VLD_SET	(1)

#define SXE2_WQEALLOC_WQE_DESC_INDEX                                           \
	GENMASK(31, 20)
#define SXE2_MQTAIL_WQTAIL	      GENMASK(10, 0)
#define SXE2_MQTAIL_MQ_OP_ERR	      BIT(11)
#define SXE2_MQERRCODES_MQ_MINOR_CODE GENMASK(15, 0)
#define SXE2_MQERRCODES_MQ_MAJOR_CODE GENMASK(31, 16)

#define SXE2_RDMA_MQ_STATUS_DONE    BIT(0)
#define SXE2_RDMA_MQ_STATUS_ERR	    BIT(31)
#define SXE2_RDMA_MQ_STATUS_ERRCODE GENMASK(30, 27)

#define SXE2_MQE_COUNT_4	  4
#define SXE2_MQE_COUNT_2048	  2048
#define SXE2_UPDATE_FPT_BUFF_SIZE 512

enum sxe2_mq_shifts {
	SXE2_MQ_STATUS_DONE_S,
	SXE2_MQ_STATUS_ERR_S,
	SXE2_MQ_MAX_SHIFTS,
};

enum sxe2_mq_masks {
	SXE2_MQ_STATUS_DONE_M,
	SXE2_MQ_STATUS_ERR_M,
	SXE2_MQ_MAX_MASKS,
};

#pragma pack(1)
struct mq_wqe_nop {
	u64 rsv0[3];
	u64 rsv1 : 32;
	u64 op : 6;
	u64 rsv2 : 25;
	u64 wqe_valid : 1;
	u64 rsv3[4];
};
#pragma pack(0)

struct sxe2_mq_context {
	__le64 buf[SXE2_MQ_CTX_SIZE];
};

struct sxe2_mq_wqe {
	__le64 buf[SXE2_MQ_WQE_SIZE];
};

struct sxe2_mq_quanta {
	__le64 elem[SXE2_MQ_WQE_SIZE];
};

struct sxe2_mq_init_info {
	u64 mq_ctx_pa;
	u64 mq_buf_pa;
	struct sxe2_rdma_ctx_dev *dev;
	struct sxe2_mq_quanta *mq_buf_va;
	__le64 *mq_ctx_va;
	u64 *scratch_array;
	u32 mqe_count;
	u16 hw_maj_ver;
	u16 hw_min_ver;
	u8 struct_ver;
	u8 rcms_profile;
	u8 ena_vf_count;
	u8 ceqs_per_vf;
	bool rocev2_rto_policy : 1;
	bool en_rem_endpoint_trk : 1;
	enum sxe2_protocol_used protocol_used;
};

struct sxe2_mq_ctx_err_code {
	u32 err;
	const char *desc;
};

struct sxe2_mq_err_info {
	u16 maj;
	u16 min;
	const char *desc;
};

struct sxe2_mq_cmpl_info {
	u32 op_ret_val;
	u16 maj_err_code;
	u16 min_err_code;
	bool error;
	u8 op_code;
};

struct sxe2_mcq_cqe_info {
	struct sxe2_mq_ctx *mq;
	u64 scratch;
	u32 op_ret_val;
	u16 maj_err_code;
	u16 min_err_code;
	u8 op_code;
	bool error : 1;
};

struct sxe2_mq_timeout {
	u64 cmpl_mq_cmds;
	u32 count;
};

struct mq_cmds_info {
	struct list_head mq_cmd_entry;
	u8 mq_cmd;
	u8 post_mq;
	struct mq_info in;
	bool destroy;
};

struct sxe2_mq_request {
	struct mq_cmds_info info;
	wait_queue_head_t waitq;
	struct list_head list;
	refcount_t refcnt;
	void (*callback_fcn)(
		struct sxe2_mq_request *mq_request);
	void *param;
	struct sxe2_mq_cmpl_info cmpl_info;
	bool request_done;
	bool waiting : 1;
	bool dynamic : 1;
};

__le64 *sxe2_kget_next_mq_wqe_idx(struct sxe2_mq_ctx *mq, u64 scratch,
				  u32 *wqe_idx);

static inline __le64 *sxe2_kget_next_mq_wqe(struct sxe2_mq_ctx *mq, u64 scratch)
{
	u32 wqe_idx;

	return sxe2_kget_next_mq_wqe_idx(mq, scratch, &wqe_idx);
}

static inline void sxe2_kget_mq_request(struct sxe2_mq_request *mq_request)
{
	refcount_inc(&mq_request->refcnt);
}

static inline void sxe2_kget_mq_reg_info(struct sxe2_mq_ctx *mq, u32 *val,
					 u32 *tail, u32 *error)
{
	*val   = SXE2_BAR_READ_32(mq->dev->hw_regs[MQ_WQE_DONE]);
	*tail  = FIELD_GET(SXE2_MQTAIL_WQTAIL, *val);
	*error = FIELD_GET(SXE2_MQTAIL_MQ_OP_ERR, *val);
}

void sxe2_kpost_mq(struct sxe2_mq_ctx *mq);

struct sxe2_mq_request *sxe2_kalloc_and_get_mq_request(struct sxe2_mq *mq,
						       bool wait);

int sxe2_knop(struct sxe2_mq_ctx *mq, u64 scratch, bool post_sq, u8 wait_type);

int mq_kexec_cmd(struct sxe2_rdma_ctx_dev *dev, struct mq_cmds_info *pcmdinfo);

void sxe2_khandler_mcqe(struct sxe2_rdma_pci_f *rdma_func,
			struct sxe2_rdma_ctx_cq *mcq, bool flag);

int sxe2_kwait_event(struct sxe2_rdma_pci_f *rdma_func,
		     struct sxe2_mq_request *mq_request);

void sxe2_kput_mq_request(struct sxe2_mq *mq,
			  struct sxe2_mq_request *mq_request);

int sxe2_khandle_mq_cmd(struct sxe2_rdma_pci_f *rdma_func,
			struct sxe2_mq_request *mq_request);

int sxe2_kpoll_mq_registers(struct sxe2_mq_ctx *mq, u32 tail, u32 count);

int sxe2_kpoll_mcq(struct sxe2_mq_ctx *mq, u8 op_code,
		   struct sxe2_mcq_cqe_info *cmpl_info);

void sxe2_kwork_mq_cmpl(struct work_struct *work);

int sxe2_mq_kexec_nop_op(struct sxe2_rdma_device *rdma_dev, bool post,
			 u32 wait);
int mq_kcreate_context(struct sxe2_mq_ctx *mq);

int sxe2_kcreate_mq(struct sxe2_rdma_device *rdma_dev);

void sxe2_kdestroy_mq(struct sxe2_rdma_device *rdma_dev);

void sxe2_kuninit_mq_handler(struct sxe2_rdma_device *rdma_dev);

int sxe2_kinit_mq_handler(struct sxe2_rdma_device *rdma_dev);
int sxe2_hw_set_mq_wqe(struct sxe2_rdma_ctx_dev *dev,
		       struct mq_cmds_info *pcmdinfo);
int sxe2_ah_set_mq_wqe(struct sxe2_rdma_ctx_dev *dev,
		       struct mq_cmds_info *pcmdinfo);
bool mq_kcheck_cqe_err(struct sxe2_rdma_ctx_dev *dev, u8 mq_cmd, bool error,
		       u16 maj_err_code, u16 min_err_code);
int mq_kget_mcqe_info(struct sxe2_rdma_ctx_cq *mcq,
		      struct sxe2_mcq_cqe_info *info);
int mq_kprocess_remaining_cmd(struct sxe2_rdma_ctx_dev *dev);
void mq_karm_mcq(struct sxe2_rdma_ctx_cq *mcq);
void mq_kcheck_progress(struct sxe2_mq_timeout *timeout,
			struct sxe2_rdma_ctx_dev *dev);
void mq_kfree_mq_request(struct sxe2_mq *mq,
			 struct sxe2_mq_request *mq_request);

#endif
