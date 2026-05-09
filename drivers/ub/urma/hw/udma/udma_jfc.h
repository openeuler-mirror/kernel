/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#ifndef __UDMA_JFC_H__
#define __UDMA_JFC_H__

#include "udma_dev.h"
#include "udma_ctx.h"
#include "udma_common.h"

#define UDMA_JFC_DEPTH_MIN 64
#define UDMA_JFC_DEPTH_SHIFT_BASE 6

#define CQE_VA_L_OFFSET 12
#define CQE_VA_H_OFFSET 32

#define UDMA_DB_L_OFFSET 6
#define UDMA_DB_H_OFFSET 38

#define UDMA_STARS_SWITCH 1

#define UDMA_JFC_DB_CI_IDX_M GENMASK(21, 0)
#define UDMA_CQE_INV_TOKEN_ID GENMASK(19, 0)

#define UDMA_INIT_JFC_ID -1

enum udma_jfc_state {
	UDMA_JFC_STATE_INVALID,
	UDMA_JFC_STATE_VALID,
	UDMA_JFC_STATE_ERROR,
};

enum udma_armed_jfc {
	UDMA_CTX_NO_ARMED,
	UDMA_CTX_ALWAYS_ARMED,
	UDMA_CTX_REG_NEXT_CEQE,
	UDMA_CTX_REG_NEXT_SOLICITED_CEQE,
};

enum udma_record_db {
	UDMA_NO_RECORD_EN,
	UDMA_RECORD_EN,
};

enum udma_cq_cnt_mode {
	UDMA_CQE_CNT_MODE_BY_COUNT,
	UDMA_CQE_CNT_MODE_BY_CI_PI_GAP,
};

enum udma_jfc_bind_type {
	UDMA_UNOCP_JFC,
	UDMA_SEND_JFC,
	UDMA_RECV_JFC,
};

struct udma_jfc {
	struct ubcore_jfc base;
	struct udma_context *ctx;
	uint32_t jfcn;
	uint32_t ceqn;
	uint32_t tid;
	struct udma_buf buf;
	struct udma_sw_db db;
	uint32_t ci;
	uint32_t arm_sn; /* only kernel mode use */
	spinlock_t lock;
	refcount_t event_refcount;
	struct completion event_comp;
	uint32_t lock_free;
	uint32_t inline_en;
	uint32_t mode;
	uint64_t stars_chnl_addr;
	bool stars_en;
	uint32_t cq_shift;
	enum udma_jfc_bind_type bind_type;
	refcount_t bind_refcount;
	bool dtu_en;
	struct udma_dtu_pg_info dtu_pg_info;
	struct sg_table *sgt;
};

struct udma_jfc_ctx {
	/* DW0 */
	uint32_t state : 2;
	uint32_t arm_st : 2;
	uint32_t shift : 4;
	uint32_t cqe_size : 1;
	uint32_t record_db_en : 1;
	uint32_t jfc_type : 1;
	uint32_t inline_en : 1;
	uint32_t cqe_va_l : 20;
	/* DW1 */
	uint32_t cqe_va_h;
	/* DW2 */
	uint32_t cqe_token_id : 20;
	uint32_t cq_cnt_mode : 1;
	uint32_t rsv0 : 3;
	uint32_t ceqn : 8;
	/* DW3 */
	uint32_t cqe_token_value : 24;
	uint32_t rsv1 : 8;
	/* DW4 */
	uint32_t pi : 22;
	uint32_t cqe_coalesce_cnt : 10;
	/* DW5 */
	uint32_t ci : 22;
	uint32_t cqe_coalesce_period : 3;
	uint32_t rsv2 : 7;
	/* DW6 */
	uint32_t record_db_addr_l;
	/* DW7 */
	uint32_t record_db_addr_h : 26;
	uint32_t rsv3 : 6;
	/* DW8 */
	uint32_t push_usi_en : 1;
	uint32_t push_cqe_en : 1;
	uint32_t token_en : 1;
	uint32_t rsv4 : 9;
	uint32_t tpn : 20;
	/* DW9 ~ DW12 */
	uint32_t rmt_eid[4];
	/* DW13 */
	uint32_t seid_idx : 10;
	uint32_t rmt_token_id : 20;
	uint32_t rsv5 : 2;
	/* DW14 */
	uint32_t remote_token_value;
	/* DW15 */
	uint32_t int_vector : 16;
	uint32_t stars_en : 1;
	uint32_t rsv6 : 15;
	/* DW16 */
	uint32_t poll : 1;
	uint32_t cqe_report_timer : 24;
	uint32_t se : 1;
	uint32_t arm_sn : 2;
	uint32_t rsv7 : 4;
	/* DW17 */
	uint32_t se_cqe_idx : 24;
	uint32_t rsv8 : 8;
	/* DW18 */
	uint32_t wr_cqe_idx : 22;
	uint32_t rsv9 : 10;
	/* DW19 */
	uint32_t cqe_cnt : 24;
	uint32_t rsv10 : 8;
	/* DW20 ~ DW31 */
	uint32_t rsv11[12];
};

struct udma_jfc_cqe {
	/* DW0 */
	uint32_t s_r : 1;
	uint32_t is_jetty : 1;
	uint32_t owner : 1;
	uint32_t inline_en : 1;
	uint32_t opcode : 3;
	uint32_t fd : 1;
	uint32_t rsv : 8;
	uint32_t substatus : 8;
	uint32_t status : 8;
	/* DW1 */
	uint32_t entry_idx : 16;
	uint32_t local_num_l : 16;
	/* DW2 */
	uint32_t local_num_h : 4;
	uint32_t rmt_idx : 20;
	uint32_t rsv1 : 8;
	/* DW3 */
	uint32_t tpn : 24;
	uint32_t rsv2 : 8;
	/* DW4 */
	uint32_t byte_cnt;
	/* DW5 ~ DW6 */
	uint32_t user_data_l;
	uint32_t user_data_h;
	/* DW7 ~ DW10 */
	uint32_t rmt_eid[4];
	/* DW11 ~ DW12 */
	uint32_t data_l;
	uint32_t data_h;
	/* DW13 ~ DW15 */
	uint32_t inline_data[3];
};

struct udma_inv_tid {
	uint32_t tid;
	struct list_head list;
};

static inline struct udma_jfc *to_udma_jfc(struct ubcore_jfc *jfc)
{
	return container_of(jfc, struct udma_jfc, base);
}

struct ubcore_jfc *udma_create_jfc(struct ubcore_device *ubcore_dev,
				   struct ubcore_jfc_cfg *cfg,
				   struct ubcore_udata *udata);
int udma_destroy_jfc(struct ubcore_jfc *jfc);
int udma_jfc_completion(struct notifier_block *nb, unsigned long jfcn,
			void *data);
int udma_modify_jfc(struct ubcore_jfc *ubcore_jfc, struct ubcore_jfc_attr *attr,
		    struct ubcore_udata *udata);
int udma_rearm_jfc(struct ubcore_jfc *jfc, bool solicited_only);
int udma_poll_jfc(struct ubcore_jfc *jfc, int cr_cnt, struct ubcore_cr *cr);
int udma_check_jfc_cfg(struct udma_dev *dev, struct udma_jfc *jfc,
		       struct ubcore_jfc_cfg *cfg);
void udma_init_jfc_param(struct ubcore_jfc_cfg *cfg, struct udma_jfc *jfc);
int udma_post_create_jfc_mbox(struct udma_dev *dev, struct udma_jfc *jfc);
void udma_clean_jfc(struct ubcore_jfc *jfc, uint32_t jetty_id, struct udma_dev *udma_dev);
int udma_alloc_jfc(struct ubcore_device *ubcore_dev, struct ubcore_jfc_cfg *cfg,
		   struct ubcore_jfc **ubcore_jfc,
		   struct ubcore_udata *udata);
int udma_active_jfc(struct ubcore_jfc *ubcore_jfc, struct ubcore_udata *udata);
int udma_set_jfc_opt(struct ubcore_jfc *jfc, uint64_t opt, void *buf, uint32_t len,
		     struct ubcore_udata *udata);
int udma_get_jfc_opt(struct ubcore_jfc *jfc, uint64_t opt, void *buf, uint32_t len,
		     struct ubcore_udata *udata);
int udma_deactive_jfc(struct ubcore_jfc *ubcore_jfc, struct ubcore_udata *udata);
int udma_free_jfc(struct ubcore_jfc *ubcore_jfc, struct ubcore_udata *udata);
int udma_bind_jfc(struct udma_dev *dev, uint32_t jfc_id, enum udma_jfc_bind_type type);
void udma_unbind_jfc(struct udma_dev *dev, uint32_t jfc_id, enum udma_jfc_bind_type type);
int udma_jetty_bind_jfc(struct udma_dev *dev, uint32_t send_jfc_id, uint32_t recv_jfc_id);
void udma_jetty_unbind_jfc(struct udma_dev *dev, uint32_t send_jfc_id);

#endif /* __UDMA_JFC_H__ */
