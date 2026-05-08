/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_eq.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_DRV_EQ_H__
#define __SXE2_DRV_EQ_H__

#include "sxe2_compat.h"
#include "sxe2_drv_rdma_common.h"

#define SXE2_INJECT_EQ_AEQ_VALUE  (1)
#define SXE2_INJECT_EQ_CEQ0_VALUE (1)
#define SXE2_INJECT_EQ_CEQS_VALUE (2)

#define SXE2_INVALID_CQ_IDX 0xffffffff

#define SXE2_MIN_EQ_SIZE 4
#define SXE2_MAX_EQ_SIZE 262144

#define SXE2_CEQE_CQID	GENMASK(18, 0)
#define SXE2_CEQE_VALID BIT_ULL(63)

#define SXE2_AEQE_QPCQID_L   GENMASK(18, 0)
#define SXE2_AEQE_WQDESCIDX  GENMASK(33, 19)
#define SXE2_AEQE_OVERFLOW   GENMASK(34, 34)
#define SXE2_AEQE_AECODE     GENMASK(46, 35)
#define SXE2_AEQE_QPCQID_H   GENMASK(47, 47)
#define SXE2_AEQE_AESRC	     GENMASK(53, 50)
#define SXE2_AEQE_RDMA_STATE GENMASK(56, 54)
#define SXE2_AEQE_VALID	     BIT_ULL(63)

#define SXE2_EQE_SIZE	    (4)
#define SXE2_EQE_SIZE_HYGON (8)

#define SXE2_DB_EQN_MASK  (0X3FF)
#define SXE2_DB_CI_OFFSET (10)

#define SXE2_GET_CURRENT_AEQ_ELEM(_aeq)                                        \
	((_aeq)->aeqe_base[SXE2_RING_CURRENT_TAIL((_aeq)->aeq_ring)].buf)

#define SXE2_GET_CURRENT_AEQ_ELEM_HYGON(_aeq)                                  \
	((_aeq)->aeqe_hygon_base[SXE2_RING_CURRENT_TAIL((_aeq)->aeq_ring)].buf)

#define SXE2_GET_CURRENT_CEQ_ELEM(_ceq)                                        \
	((_ceq)->ceqe_base[SXE2_RING_CURRENT_TAIL((_ceq)->ceq_ring)].buf)

#define SXE2_GET_CURRENT_CEQ_ELEM_HYGON(_ceq)                                  \
	((_ceq)->ceqe_hygon_base[SXE2_RING_CURRENT_TAIL((_ceq)->ceq_ring)].buf)

#define SXE2_GET_CEQ_ELEM_AT_POS(_ceq, _pos) ((_ceq)->ceqe_base[_pos].buf)

#define SXE2_GET_CEQ_ELEM_AT_POS_HYGON(_ceq, _pos)                             \
	((_ceq)->ceqe_hygon_base[_pos].buf)

#define SXE2_RING_GET_NEXT_TAIL(_ring, _idx)                                   \
	(((_ring).tail + (_idx)) % (_ring).size)

enum { SXE2_EQ_POLLING_BUDGET = 128,
};

struct sxe2_ae_desc {
	u16 id;
	const char *name;
	u64 count;
	const char *desc;
};

struct sxe2_aeqe_info {
	u64 compl_ctx;
	u32 qp_cq_id;
	u32 wqe_idx;
	u16 ae_code;
	u8 rdma_state;
	u8 ae_source;
	bool qp : 1;
	bool cq : 1;
	bool sq : 1;
	bool rq : 1;
	bool srq : 1;
	bool db : 1;
	bool tmo : 1;
	bool cc : 1;
	bool aeqe_overflow;
	u8 err_rq_idx_valid;
};

struct sxe2_ceq_init_info {
	u64 ceqe_pa;
	u32 __iomem *doorbell;
	struct sxe2_rdma_ctx_dev *dev;
	struct sxe2_eqe *ceqe_base;
	struct sxe2_eqe_hygon *ceqe_hygon_base;
	u32 ceq_id;
	u32 ceq_size;
	struct sxe2_rdma_ctx_vsi *vsi;
	struct drv_rdma_soft_eqc eqc;
	bool pble_map : 1;
	u64 pbl_count;
	u64 pbl[];
};

struct sxe2_eqe {
	__le64 buf[SXE2_EQE_SIZE];
};

struct sxe2_eqe_hygon {
	__le64 buf[SXE2_EQE_SIZE_HYGON];
};

struct sxe2_aeq_init_info {
	u64 aeq_elem_pa;
	u32 __iomem *doorbell;
	struct sxe2_rdma_ctx_dev *dev;
	struct sxe2_eqe *aeqe_base;
	struct sxe2_eqe_hygon *aeqe_hygon_base;
	void *pbl_list;
	bool pble_map : 1;
	u32 irq;
	u32 msix_idx;
	u32 aeq_size;
	struct sxe2_rdma_ctx_vsi *vsi;
	struct drv_rdma_soft_eqc eqc;
	u64 pbl_count;
	u64 pbl[];
};

int sxe2_drv_aeq_create(struct sxe2_rdma_ctx_aeq *aeq, u64 scratch,
			bool post_sq);
int sxe2_drv_aeq_destroy(struct sxe2_rdma_ctx_aeq *aeq, u64 scratch,
			 bool post_sq);
int sxe2_drv_aeq_modify(struct sxe2_rdma_ctx_aeq *aeq,
			struct sxe2_rdma_eqc *aeqc, u64 scratch, bool post_sq);
int sxe2_drv_aeq_query(struct sxe2_rdma_ctx_aeq *aeq, u64 query_pa, u64 scratch,
		       bool post_sq);

int sxe2_drv_ceq_create(struct sxe2_rdma_ctx_ceq *ceq, u64 scratch,
			bool post_sq);
int sxe2_drv_ceq_destroy(struct sxe2_rdma_ctx_ceq *ceq, u64 scratch,
			 bool post_sq);
int sxe2_drv_ceq_modify(struct sxe2_rdma_ctx_ceq *ceq,
			struct sxe2_rdma_eqc *ceqc, u64 scratch, bool post_sq);
int sxe2_drv_ceq_query(struct sxe2_rdma_ctx_ceq *ceq, u64 query_pa, u64 scratch,
		       bool post_sq);

int sxe2_drv_ceq_query_op(struct sxe2_rdma_device *rdma_dev,
			  struct sxe2_rdma_ctx_ceq *ceq, u64 query_pa);
int sxe2_drv_ceq_modify_op(struct sxe2_rdma_device *rdma_dev,
			   struct sxe2_rdma_ctx_ceq *ceq,
			   struct sxe2_rdma_eqc *ceqc);
int sxe2_drv_aeq_query_op(struct sxe2_rdma_device *rdma_dev,
			  struct sxe2_rdma_ctx_aeq *aeq, u64 query_pa);
int sxe2_drv_aeq_modify_op(struct sxe2_rdma_device *rdma_dev,
			   struct sxe2_rdma_ctx_aeq *aeq,
			   struct sxe2_rdma_eqc *aeqc);

int sxe2_setup_aeq(struct sxe2_rdma_device *rdma_dev);
void sxe2_del_aeq(struct sxe2_rdma_device *rdma_dev);
int sxe2_setup_ceqs(struct sxe2_rdma_device *rdma_dev);
int sxe2_setup_mceq(struct sxe2_rdma_device *rdma_dev);
void sxe2_del_ceqs(struct sxe2_rdma_device *rdma_dev);
void sxe2_del_mceq(struct sxe2_rdma_device *rdma_dev);

void sxe2_rdma_comp_handler(struct sxe2_rdma_ctx_cq *cq_ctx);

struct sxe2_ae_desc *sxe2_get_ae_desc_list(void);
int sxe2_get_ae_desc_list_size(void);

const char *sxe2_get_ae_desc(u16 ae_code);
void sxe2_set_ae_count(u16 ae_code);

#ifndef NO_HAVE_TASKLET_SETUP
irqreturn_t sxe2_eq_handler(int irq, void *data);

irqreturn_t sxe2_ceq_handler(int irq, void *data);

void sxe2_ceq_cb(struct tasklet_struct *t);
#endif
#endif
