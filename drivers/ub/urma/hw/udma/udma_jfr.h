/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#ifndef __UDMA_JFR_H__
#define __UDMA_JFR_H__

#include "udma_dev.h"
#include "udma_ctx.h"
#include "udma_common.h"
#include "udma_jetty.h"

#define RQE_VA_L_PAGE_4K_OFFSET 12U
#define RQE_VA_L_VALID_BIT GENMASK(19, 0)
#define RQE_VA_H_OFFSET 20
#define RQE_VA_H_PAGE_4K_OFFSET (RQE_VA_H_OFFSET + RQE_VA_L_PAGE_4K_OFFSET)
#define RQE_VA_H_VALID_BIT GENMASK(31, 0)

#define RQE_TOKEN_ID_L_MASK GENMASK(13, 0)
#define RQE_TOKEN_ID_H_OFFSET 14U
#define RQE_TOKEN_ID_H_MASK GENMASK(5, 0)

#define JFR_IDX_VA_L_PAGE_4K_OFFSET 12U
#define JFR_IDX_VA_L_VALID_BIT GENMASK(31, 0)
#define JFR_IDX_VA_H_OFFSET 32
#define JFR_IDX_VA_H_PAGE_4K_OFFSET \
	(JFR_IDX_VA_H_OFFSET + JFR_IDX_VA_L_PAGE_4K_OFFSET)
#define JFR_IDX_VA_H_VALID_BIT GENMASK(19, 0)

#define JFR_DB_VA_L_PAGE_64_OFFSET 6U
#define JFR_DB_VA_L_VALID_BIT GENMASK(23, 0)
#define JFR_DB_VA_M_OFFSET 24
#define JFR_DB_VA_M_PAGE_64_OFFSET \
	(JFR_DB_VA_M_OFFSET + JFR_DB_VA_L_PAGE_64_OFFSET)
#define JFR_DB_VA_M_VALID_BIT GENMASK(31, 0)
#define JFR_DB_VA_H_OFFSET 32
#define JFR_DB_VA_H_PAGE_64_OFFSET \
	(JFR_DB_VA_H_OFFSET + JFR_DB_VA_M_PAGE_64_OFFSET)
#define JFR_DB_VA_H_VALID_BIT GENMASK(1, 0)

#define JFR_JFCN_L_VALID_BIT GENMASK(11, 0)
#define JFR_JFCN_H_OFFSET 12U
#define JFR_JFCN_H_VALID_BIT GENMASK(7, 0)

#define UDMA_JFR_DB_PI_M GENMASK(15, 0)

#define JFR_PLD_TOKEN_ID_MASK GENMASK(19, 0)

#define UDMA_MIN_JFR_DEPTH 64
#define UDMA_SGE_SIZE 16U
#define UDMA_IDX_QUE_ENTRY_SZ 4
#define UDMA_RNR_MAX 19

#define UDMA_DEF_JFR_SLEEP_TIME 1000
#define UDMA_SLEEP_DELAY_TIME 10

enum jfr_state {
	UDMA_JFR_STATE_RESET = 0,
	UDMA_JFR_STATE_READY,
	UDMA_JFR_STATE_ERROR,
	JFR_STATE_NUM,
};

enum udma_rx_limit_wl {
	UDMA_RX_LIMIT_WL_0 = 0,
	UDMA_RX_LIMIT_WL_64,
	UDMA_RX_LIMIT_WL_512,
	UDMA_RX_LIMIT_WL_4096
};

enum {
	LIMIT_WL_0_V = 0,
	LIMIT_WL_64_V = 64,
	LIMIT_WL_512_V = 512,
	LIMIT_WL_4096_V = 4096
};

struct udma_jfr_idx_que {
	struct udma_buf buf;
	struct udma_table jfr_idx_table;
};

struct udma_jfr {
	struct ubcore_jfr ubcore_jfr;
	struct udma_jetty_queue rq;
	struct udma_jfr_idx_que idx_que;
	struct udma_sw_db sw_db;
	struct udma_sw_db jfr_sleep_buf;
	struct udma_context *udma_ctx;
	uint32_t rx_threshold;
	uint32_t wqe_cnt;
	uint64_t jetty_addr;
	enum ubcore_jfr_state state;
	uint32_t max_sge;
	spinlock_t lock;
	refcount_t ae_refcount;
	struct completion ae_comp;
	bool buff_non_pin;
};

struct udma_wqe_sge {
	uint32_t length;
	uint32_t token_id;
	uint64_t va;
};

struct udma_jfr_ctx {
	/* DW0 */
	uint32_t state : 2;
	uint32_t limit_wl : 2;
	uint32_t rqe_size_shift : 3;
	uint32_t token_en : 1;
	uint32_t rqe_shift : 4;
	uint32_t rnr_timer : 5;
	uint32_t record_db_en : 1;
	uint32_t rqe_token_id_l : 14;
	/* DW1 */
	uint32_t rqe_token_id_h : 6;
	uint32_t type : 3;
	uint32_t rsv : 2;
	uint32_t jfr_type : 1;
	uint32_t rqe_base_addr_l : 20;
	/* DW2 */
	uint32_t rqe_base_addr_h;
	/* DW3 */
	uint32_t rqe_position : 1;
	uint32_t pld_position : 1;
	uint32_t pld_token_id : 20;
	uint32_t rsv1 : 10;
	/* DW4 */
	uint32_t token_value;
	/* DW5 */
	uint32_t user_data_l;
	/* DW6 */
	uint32_t user_data_h;
	/* DW7 */
	uint32_t pi : 16;
	uint32_t ci : 16;
	/* DW8 */
	uint32_t idx_que_addr_l;
	/* DW9 */
	uint32_t idx_que_addr_h : 20;
	uint32_t jfcn_l : 12;
	/* DW10 */
	uint32_t jfcn_h : 8;
	uint32_t record_db_addr_l : 24;
	/* DW11 */
	uint32_t record_db_addr_m;
	/* DW12 */
	uint32_t record_db_addr_h : 2;
	uint32_t cqeie : 1;
	uint32_t cqesz : 1;
	uint32_t rsv2 : 28;
	/* padding */
	uint32_t reserved[3];
};

/* stub UBCORE */

enum udma_k_set_get_jfr_opt_perm {
	PERM_READ = 1,
	PERM_WRITE = 1 << 1,
};

struct udma_jfr_opt_info {
	uint64_t opt;
	uint32_t buf_len;
	enum udma_k_set_get_jfr_opt_perm perm;
	enum udma_set_get_jetty_opt_ignore_attr attr;
};

static inline struct udma_jfr *to_udma_jfr(struct ubcore_jfr *jfr)
{
	return container_of(jfr, struct udma_jfr, ubcore_jfr);
}

static inline bool udma_jfrwq_overflow(struct udma_jfr *jfr)
{
	return (jfr->rq.pi - jfr->rq.ci) >= jfr->wqe_cnt;
}

static inline void set_data_of_sge(struct udma_wqe_sge *sge, struct ubcore_sge *sg)
{
	sge->va = cpu_to_le64(sg->addr);
	sge->length = cpu_to_le32(sg->len);
}

static inline struct udma_jfr *to_udma_jfr_from_queue(struct udma_jetty_queue *queue)
{
	return container_of(queue, struct udma_jfr, rq);
}

int udma_modify_jfr(struct ubcore_jfr *jfr, struct ubcore_jfr_attr *attr,
		    struct ubcore_udata *udata);
struct ubcore_jfr *udma_create_jfr(struct ubcore_device *dev, struct ubcore_jfr_cfg *cfg,
				   struct ubcore_udata *udata);
int udma_destroy_jfr(struct ubcore_jfr *jfr);
int udma_destroy_jfr_batch(struct ubcore_jfr **jfr_arr, int jfr_num, int *bad_jfr_index);
int udma_unimport_jfr(struct ubcore_tjetty *tjfr);
int udma_post_jfr_wr(struct ubcore_jfr *ubcore_jfr, struct ubcore_jfr_wr *wr,
		     struct ubcore_jfr_wr **bad_wr);
struct ubcore_tjetty *udma_import_jfr_ex(struct ubcore_device *dev,
					 struct ubcore_tjetty_cfg *cfg,
					 struct ubcore_active_tp_cfg *active_tp_cfg,
					 struct ubcore_udata *udata);
int udma_alloc_jfr(struct ubcore_device *dev, struct ubcore_jfr_cfg *cfg, struct ubcore_jfr **jfr,
		   struct ubcore_udata *udata);
int udma_active_jfr(struct ubcore_jfr *jfr, struct ubcore_udata *udata);
int udma_set_jfr_opt(struct ubcore_jfr *jfr, uint64_t opt, void *buf, uint32_t len,
		     struct ubcore_udata *udata);
int udma_get_jfr_opt(struct ubcore_jfr *jfr, uint64_t opt, void *buf, uint32_t len,
		     struct ubcore_udata *udata);
int udma_deactive_jfr(struct ubcore_jfr *jfr, struct ubcore_udata *udata);
int udma_free_jfr(struct ubcore_jfr *jfr, struct ubcore_udata *udata);
#endif /* __UDMA_JFR_H__ */
