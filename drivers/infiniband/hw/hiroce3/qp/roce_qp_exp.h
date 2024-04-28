/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_QP_EXP_H
#define ROCE_QP_EXP_H

#include <linux/io-mapping.h>
#include <linux/list.h>
#include <linux/cdev.h>

#include <rdma/ib_verbs.h>

#include "hinic3_rdma.h"
#include "hinic3_cqm.h"

#include "rdma_context_format.h"

#include "roce.h"
#include "roce_db.h"
#include "roce_cq.h"
#include "roce_qp.h"

#define EXP_OK (0)
#define EXP_PARAM_ERR (1)
#define EXP_FUNC_ERR (2)

#define QPC_MIN_SIZE (512)
#define CONTX_SZ (sizeof(struct roce_qp_context) / QPC_MIN_SIZE)

#define BUFFER_SZ (sizeof(struct roce_qp_context) / sizeof(u32))

#define TYPE_LEN (8)
#define DEV_NUM (32)
#define QPN_MAX (0xFFFFF)
#define QPN_MIN (0)
#define IB_QP_EXP_CMD (1 << 23)
#define ROCE_OPTPAR_EXP (1 << 16)
#define VA_OFFSET (8)

struct roce3_device_list {
	struct ib_device *ib_dev[DEV_NUM];
	int ib_dev_num;
	struct mutex mutex;
};

struct ib_qp_info {
	dma_addr_t sq_pg_base_addr[64];
	dma_addr_t hw_doorbell_addr;
	dma_addr_t sw_doorbell_addr;

	u32 sq_depth;
	u32 qpn;
	u8 sq_pg_cnt;
	u8 qp_cos;
	u8 cntx_sz;
	u8 sq_wqe_size;
};

struct ib_qp_attr_data {
	u32 data_type; // plog:1
	u32 data_len;
	u8 *data_buf;
};

struct ib_qp_attr_exp {
	struct ib_qp_attr qp_attr;
	struct ib_qp_attr_data qp_attr_data;
};

struct roce3_device_list *roce3_get_plog_device_info(void);

int ib_get_qp_info(char *dev_name, int qpn, struct ib_qp_info *qp_info);
struct ib_qp *ib_get_qp(const char *dev_name, int qpn);
int ib_put_qp(struct ib_qp *ibqp);
int roce3_qp_modify_exp(struct roce3_device *rdev, struct roce3_qp *rqp,
	struct ib_qp_attr *attr, int attr_mask, enum ib_qp_state cur_state,
	enum ib_qp_state new_state, u16 vlan_id);
int roce3_modify_extend_qp(struct ib_qp_attr *attr, int attr_mask, struct ib_qp *ibqp);

#endif // ROCE_QP_EXP_H
