/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_QP_H
#define ROCE_QP_H

#include <linux/types.h>

#include <rdma/ib_verbs.h>

#include "hinic3_rdma.h"
#include "hinic3_cqm.h"

#include "roce.h"
#include "roce_cq.h"
#include "roce_db.h"
#include "roce_pd.h"

#include "rdma_context_format.h"

#define ROCE_RQ_MIN_SGE 4
#define ROCE_RQ_MID_SGE 8
#define ROCE_RQ_MAX_SGE 16

#define ROCE_WQE_NEXT_SGE_INVALID (1UL << 31)

#define ROCE_QP_TIMER_CHECK_VALUE 0xce
#define ROCE_QP_DESTROY_CHECK_VALUE 0xffffffff
#define ROCE_RDMARC_DESTROY_CHECK_VALUE 0xcece5a5a
#define ROCE_CACHE_LINE_SIZE 256
#define RDMARC_NUM_PER_CACHELINE 8
#define RDMARC_TABLE_ENTRY_SIZE 32
#define ROCE_STATIC_RDMARC_NUM 65536
#define ROCE_QP_MAX_PFETCH_MTT_LAYER 3
#define ROCE_QP_MAX_TIMER_NUM 5

#define ROCE_QP_SMI_QP_NUM 0x0
#define ROCE_QP_GSI_QP_NUM 0x1
#define ROCE_QP_INVLID_QP_NUM CQM_INDEX_INVALID

#define ROCE_QP_MAX_DWQE_SIZE 256
#define ROCE_QP_DEFAULT_WQE_SHIFT 6

#define ROCE_QP_MODIFY_CMD_OUT_BUF_SIZE 512

#define ROCE_QP_STATE_MEM_INIT 0xa

#define ROCE_UD_MAX_INLINE_LEN_SUB (40)

#define ROCE_QP_GPA_SIG_LEN 3
#define ROCE_WR_MIN_NUM 2

#define ROCE_QPC_PMTU_TRANSLATE(pmtu) ((1U << ((pmtu) - 1)) - 1)

#define ROCE_QP_OPTPAR_ALT_ADDR_PATH (1 << 0)
#define ROCE_QP_OPTPAR_RRE (1 << 1)
#define ROCE_QP_OPTPAR_RAE (1 << 2)
#define ROCE_QP_OPTPAR_RWE (1 << 3)
#define ROCE_QP_OPTPAR_PKEY_INDEX (1 << 4)
#define ROCE_QP_OPTPAR_Q_KEY (1 << 5)
#define ROCE_QP_OPTPAR_RNR_TIMEOUT (1 << 6)
#define ROCE_QP_OPTPAR_PRIMARY_ADDR_PATH (1 << 7)
#define ROCE_QP_OPTPAR_SRA_MAX (1 << 8)
#define ROCE_QP_OPTPAR_RRA_MAX (1 << 9)
#define ROCE_QP_OPTPAR_PM_STATE (1 << 10)
#define ROCE_QP_OPTPAR_RETRY_COUNT (1 << 11)
#define ROCE_QP_OPTPAR_RNR_RETRY (1 << 12)
#define ROCE_QP_OPTPAR_ACK_TIMEOUT (1 << 13)
#define ROCE_QP_OPTPAR_SCHED_QUEUE (1 << 14)
#define ROCE_QP_OPTPAR_COUNTER_INDEX (1 << 15)

#define ROCE3_LB1_MASK 0x3
#define ROCE3_QPN_BIT_INDEX 29U
#define ROCE3_QPN_CTRL_BIT_NUM 3U

#define ROCE_VLAN_DIS 0xFFFF

enum roce_qp_state {
	ROCE_QP_STATE_RST = 0,
	ROCE_QP_STATE_INIT = 1,
	ROCE_QP_STATE_RTR = 2,
	ROCE_QP_STATE_RTS = 3,
	ROCE_QP_STATE_SQER = 4,
	ROCE_QP_STATE_SQD = 5,
	ROCE_QP_STATE_ERR = 6,
	ROCE_QP_STATE_SQ_DRAINING = 7,
	ROCE_QP_STATE_NUM
};

enum roce_fake_vf_start_e {
	ROCE_VLD_PF_NUM_10 = 10,
	ROCE_VLD_PF_NUM_11 = 11,
	ROCE_VLD_PF_NUM_12 = 12
};

enum {
	ROCE_QP_PM_MIGRATED = 0x3,
	ROCE_QP_PM_ARMED = 0x0,
	ROCE_QP_PM_REARM = 0x1
};

enum {
	ROCE_QP_ST_RC = 0x0,  /* 000 */
	ROCE_QP_ST_UC = 0x1,  /* 001 */
	ROCE_QP_ST_RD = 0x2,  /* 010 */
	ROCE_QP_ST_UD = 0x3,  /* 011 */
	ROCE_QP_ST_XRC = 0x6, /* 110 */
	ROCE_QP_ST_PRIV = 0x7 /* 111 */
};

enum {
	ROCE_QP_NO_SRQ,
	ROCE_QP_HAS_SRQ
};

enum {
	ROCE_QP = 0,
	ROCE_QP_EXT
};

struct roce3_wq {
	u64 *wrid;
	spinlock_t lock;
	u32 wqebb_cnt;
	u32 max_post;
	u32 max_sge;
	u32 offset;
	u32 wqe_shift;
	u32 head;
	u32 tail;
};

struct roce3_qp {
	struct ib_qp ibqp;
	u32 qpn;
	struct roce3_db db;
	struct tag_cqm_queue *qp_buf_info;
	struct tag_cqm_qpc_mpt *qpc_info;
	struct roce3_wq rq;
	u32 sq_signal_bits;
	unsigned int sq_next_wqe;
	u32 sq_max_wqes_per_wr;
	struct roce3_wq sq;
	struct ib_umem *umem;
	struct rdma_mtt mtt;
	struct roce3_buf buf;
	int buf_size;
	struct mutex mutex;
	u32 xrcdn;
	u8 port;
	u8 atomic_rd_en;
	u8 qp_state;
	u8 qp_ext;
	u32 qp_type;
	u32 max_inline_data;
	int max_dwqe_size;
	struct rdma_rdmarc rdmarc;
	u16 rsp_depth;
	u8 sl;
	bool has_rq;
	u8 *sq_head_addr;
	u8 *sq_tail_addr;
	bool signature_en;
	u8 double_sgl_mode;
	u8 ext_mtu;
	u8 ext_mtu_mode;

	u8 db_sgid_index;
	u8 db_path_mtu;

	u32 qid;
	u32 local_comm_id; /* used by NOF AA to reuse qpn when disconnection happens */
	u32 remote_comm_id;

	/* hot-plug record */
	struct list_head qps_list;
	struct list_head cq_recv_list;
	struct list_head cq_send_list;
#if defined(ROCE_VBS_EN) || defined(ROCE_EXTEND)
	void *vbs_qp_ptr;
#endif
#ifdef ROCE_BONDING_EN
	u32 tx_hash_value;
#endif
};

struct roce3_sqp {
	struct roce3_qp qp;
	int pkey_index;
	u32 qkey;
	u32 send_psn;
};

static inline struct roce3_qp *to_roce3_qp(const struct ib_qp *ibqp)
{
	return container_of(ibqp, struct roce3_qp, ibqp);
}

static inline struct roce3_qp *cqmobj_to_roce_qp(const struct tag_cqm_object *object)
{
	struct tag_cqm_qpc_mpt *qpc_info;

	qpc_info = container_of(object, struct tag_cqm_qpc_mpt, object);
	return (struct roce3_qp *)qpc_info->priv;
}

static inline struct roce3_sqp *to_roce3_sqp(const struct roce3_qp *rqp)
{
	return container_of(rqp, struct roce3_sqp, qp);
}

struct roce3_qp_query_outbuf {
	struct roce_qp_context qpc;
};

void roce3_qp_async_event(struct roce3_device *rdev, struct roce3_qp *qp, int type);
u8 roce3_get_db_cos_from_vlan_pri(struct roce3_device *rdev, u8 vlan_pri);

void roce3_free_opt_rdmarc(struct roce3_qp *rqp);
void roce3_get_cqs(struct roce3_qp *rqp, struct roce3_cq **send_cq, struct roce3_cq **recv_cq);
int roce3_qp_modify_2rst_cmd(struct roce3_device *rdev, u32 qpn);
int roce3_qp_cache_out_cmd(struct roce3_device *rdev, struct roce3_qp *rqp);
struct roce3_pd *roce3_get_pd(struct roce3_qp *rqp);
int roce3_sqp_check(const struct roce3_qp *qp);
void *roce3_get_wqe(struct roce3_qp *rqp, u32 offset);
int roce3_wq_overflow(struct roce3_wq *wq, u32 wr_num, struct ib_cq *ibcq);
void roce3_set_data_seg(struct roce3_wqe_data_seg *dseg, struct ib_sge *sge);
void roce3_qpc_to_be(struct tag_roce_verbs_qp_attr *qp_attr, struct roce3_qp *rqp, u32 *be_ctx);
void roce3_qp_rst2init(struct roce3_qp *rqp, const struct ib_qp_attr *attr,
	struct tag_roce_verbs_qp_attr *qp_attr);
struct ib_qp *roce3_create_qp_common(struct ib_pd *ibpd, struct ib_qp_init_attr *init_attr,
	struct ib_udata *udata, int qp_ext);
int roce3_send_qp_lb_cmd(u32 qpn, struct roce3_device *rdev, u8 cmd,
	struct tag_cqm_cmd_buf *buf_in, struct tag_cqm_cmd_buf *buf_out, u32 timeout);

int roce3_qp_query(struct roce3_device *rdev, u32 qpn, u32 *context, int qpc_size);
int roce3_post_send_standard(struct ib_qp *ibqp, const struct ib_send_wr *wr,
	const struct ib_send_wr **bad_wr);
void qpc_seg_to_le32(struct roce_qp_context *be_ctx, struct roce_qp_context *le_ctx, u32 srq_vld);
void roce3_be32_2_le32(void *context, u32 *le_ctx, u32 ctx_size);

#define IB_QP_CREATE_SIGNATURE_EN IB_QP_CREATE_INTEGRITY_EN

#endif // ROCE_QP_H
