/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rdma_qos.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef SXE2_DRV_RDMA_QOS_H
#define SXE2_DRV_RDMA_QOS_H

#include "sxe2_drv_rdma_common.h"

#define READ_BIT(val, mask, shift)  ((u32)(((val) & (mask)) >> (shift)))
#define WRITE_BIT(val, mask, shift) (((val) << (shift)) & (mask))

#define SXE2_OK			       0
#define SXE2_FUNC_MAX_QSET_ID	       512
#define SXE2_FUNC_MAX_QPN	       262144
#define QOS_APPLY_QSET_REQ_PULL	       10
#define QOS_QUERY_QSET_REQ_PULL	       10
#define QOS_RELEASE_QSET_REQ_PULL      10
#define QOS_QP_BIND_QSET_REQ_PULL      10
#define QOS_QP_BIND_QSET_CMD	       1
#define QOS_QP_UNBIND_QSET_CMD	       0
#define QOS_QUERY_QSET_INVALID_FUNC_ID 0xFFFFFFFF
#define QOS_MAX_TC		       8
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
#define QOS_BAR_APPLY_INJECT_VAL   0x600
#define QOS_BAR_RELEASE_INJECT_VAL 0x3
#define QOS_BAR_QP_BIND_INJECT_VAL 0x3
#endif

#define QOS_QSET_IDX_0 0
#define QOS_QSET_IDX_1 1
#define QOS_MAX_QSET_NUM_PER_USER_PRI 2
#define QOS_IS_BOND_AA 1
#define QOS_MAX_PORT_NUM_LAG_0 0
#define QOS_MAX_PORT_NUM_LAG_1 1

#define APPLY_QSET_REQ_REG_VLD_S 0
#define APPLY_QSET_REQ_REG_VLD_M BIT(0)
#define APPLY_QSET_RESP_DONE_S 9
#define APPLY_QSET_RESP_DONE_M BIT(9)

#define APPLY_QSET_RESP_ERR_S 10
#define APPLY_QSET_RESP_ERR_M BIT(10)

#define APPLY_QSET_RESP_QSET_ID_S 0
#define APPLY_QSET_RESP_QSET_ID_M GENMASK(8, 0)

#define APPLY_QSET_RESP_ERR_CODE_S 2
#define APPLY_QSET_RESP_ERR_CODE_M GENMASK(12, 11)
#define QUERY_QSET_REQ_QSET_ID_S 0
#define QUERY_QSET_REQ_QSET_ID_M GENMASK(8, 0)

#define QUERY_QSET_REQ_VLD_S 9
#define QUERY_QSET_REQ_VLD_M BIT(9)
#define QUERY_QSET_RESP_FUNC_ID_S 0
#define QUERY_QSET_RESP_FUNC_ID_M GENMASK(5, 0)

#define QUERY_QSET_RESP_DONE_S 6
#define QUERY_QSET_RESP_DONE_M BIT(6)

#define QUERY_QSET_RESP_ERR_S 7
#define QUERY_QSET_RESP_ERR_M BIT(7)
#define RELEASE_QSET_REQ_QSET_ID_S 0
#define RELEASE_QSET_REQ_QSET_ID_M GENMASK(8, 0)

#define RELEASE_QSET_REQ_VLD_S 9
#define RELEASE_QSET_REQ_VLD_M BIT(9)
#define RELEASE_QSET_RESP_DONE_S 0
#define RELEASE_QSET_RESP_DONE_M BIT(0)

#define RELEASE_QSET_RESP_ERR_S 1
#define RELEASE_QSET_RESP_ERR_M BIT(1)

#define RELEASE_QSET_RESP_ERR_CODE_S 2
#define RELEASE_QSET_RESP_ERR_CODE_M GENMASK(3, 2)
#define QP_BIND_QSET_REQ_QPN_S 0
#define QP_BIND_QSET_REQ_QPN_M GENMASK(17, 0)

#define QP_BIND_QSET_REQ_QSET_ID_S 18
#define QP_BIND_QSET_REQ_QSET_ID_M GENMASK(26, 18)

#define QP_BIND_QSET_REQ_CMD_S 27
#define QP_BIND_QSET_REQ_CMD_M BIT(27)

#define QP_BIND_QSET_REQ_VLD_S 28
#define QP_BIND_QSET_REQ_VLD_M BIT(28)
#define QP_BIND_QSET_RESP_DONE_S 0
#define QP_BIND_QSET_RESP_DONE_M BIT(0)

#define QP_BIND_QSET_RESP_ERR_S 1
#define QP_BIND_QSET_RESP_ERR_M BIT(1)

#define QP_BIND_QSET_RESP_ERR_CODE_S 2
#define QP_BIND_QSET_RESP_ERR_CODE_M GENMASK(5, 2)

#define QSET_INVALID_CODE 0xFF
#define QSET_MAX_IDX	  1

enum qos_apply_qset_err_code {
	NO_FREE_QSET		       = 1,
	FUNCTION_EXCEED_MAX_LIMIT_QSET = 2,
};

enum qos_release_qset_err_code {
	QSET_NOT_ALLOCED    = 1ul,
	QSET_FUNC_NOT_MATCH = 1ul << 1,
};

struct qos_qset_bind_tc_info {
	u32 func_id;
	u32 is_pf;
	u32 qset_id;
	u32 tc;
	u32 func_id2;
	u32 qset_id2;
	u32 tc_id2;
	u32 is_bond_aa;
};

enum qos_qp_bind_qset_err_code {
	BIND_QP_NOT_BIND_THIS_FUNCTION	    = 1,
	BIND_QSET_NOT_BIND_THIS_FUNCTION    = 2,
	BIND_QP_QSET_NOT_BIND_THIS_FUNCTION = 3,

	UNBIND_QP_NOT_BIND_THIS_FUNCTION      = 4,
	UNBIND_QSET_NOT_BIND_THIS_FUNCTION    = 5,
	UNBIND_QP_QSET_NOT_BIND_THIS_FUNCTION = 6,
	UNBIND_QP_UNBIND		      = 7,
	UNBIND_QP_NOT_BIND_THIS_QSET	      = 8,
};

struct sxe2_err_code {
	char *err_mean;
	u8 err_code;
};

int sxe2_qos_lan_register_qsets(struct sxe2_rdma_ctx_vsi *vsi,
				struct sxe2_rdma_qset *qset1,
				struct sxe2_rdma_qset *qset2);

void sxe2_qos_lan_unregister_qsets(struct sxe2_rdma_ctx_vsi *vsi,
				   struct sxe2_rdma_qset *qset1,
				   struct sxe2_rdma_qset *qset2);

int sxe2_qos_register_qset(struct sxe2_rdma_ctx_vsi *vsi, u8 user_pri);

int sxe2_qos_register_qset_bond(struct sxe2_rdma_ctx_vsi *vsi, u8 user_pri);

void sxe2_qos_unregister_qset(struct sxe2_rdma_ctx_vsi *vsi, u8 user_pri);

void sxe2_qos_unregister_qset_bond(struct sxe2_rdma_ctx_vsi *vsi, u8 user_pri);

int sxe2_qos_query_qset_bind_func(struct sxe2_rdma_ctx_vsi *vsi, u32 qset_id,
				  u32 *func_id);

int sxe2_qos_qp_add_qos(struct sxe2_rdma_ctx_vsi *vsi,
			struct sxe2_rdma_ctx_qp *qp);

int sxe2_qos_qp_add_qos_bond(struct sxe2_rdma_ctx_vsi *vsi,
			     struct sxe2_rdma_ctx_qp *qp);

int sxe2_qos_qp_rem_qos(struct sxe2_rdma_ctx_vsi *vsi,
			struct sxe2_rdma_ctx_qp *qp);

void sxe2_qos_remove_all_qset(struct sxe2_rdma_ctx_vsi *vsi);

int sxe2_qos_qset_bind_pf_tc(struct sxe2_rdma_ctx_vsi *vsi, u32 qset_id, u8 tc,
			     bool is_pf, u32 func_id);

int sxe2_qos_qset_bind_pf_tc_bond(struct sxe2_rdma_ctx_vsi *vsi, u32 qset1_id,
				  u32 qset2_id, u8 tc_idx0, u8 tc_idx1, bool is_pf,
				  u32 qset1_pf_id, u32 qset2_pf_id);

void sxe2_rdma_qos_failover_complete(struct sxe2_rdma_device *rdma_dev);

void sxe2_rdma_update_qos_info(struct sxe2_rdma_ctx_vsi *vsi,
			       struct sxe2_rdma_l2params *l2p);
void sxe2_rdma_qos_move_qset(struct sxe2_rdma_ctx_vsi *vsi,
			     struct sxe2_rdma_l2params *l2params);
u8 get_pf_num_by_bitmap(u8 qset_pf);

void sxe2_rdma_qos_remove_qsets(struct sxe2_rdma_ctx_vsi *vsi, bool *change_list,
					struct sxe2_rdma_l2params *l2params);

void sxe2_rdma_qos_add_qsets(struct sxe2_rdma_ctx_vsi *vsi, bool *change_list,
					struct sxe2_rdma_l2params *l2params);

#endif
