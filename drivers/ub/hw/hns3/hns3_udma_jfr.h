/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#ifndef _UDMA_JFR_H
#define _UDMA_JFR_H

#include "hns3_udma_common.h"
#include "hns3_udma_qp.h"

struct udma_jfr_idx_que {
	struct udma_mtr		mtr;
	int			entry_shift;
	uint32_t		head;
	uint32_t		tail;
};

struct udma_jfr {
	struct ubcore_jfr		ubcore_jfr;
	uint32_t		jfrn;
	uint32_t		srqn;
	uint32_t		wqe_cnt;
	uint32_t		max_sge;
	uint32_t		wqe_shift;
	uint32_t		offset;
	struct udma_jfr_idx_que	idx_que;
	struct udma_mtr		buf_mtr;
	struct udma_db		db;
	struct udma_qp		*um_qp;
	struct xarray		tp_table_xa;

	refcount_t		refcount;
	struct completion	free;

	struct udma_qpn_bitmap	qpn_map;
	void (*event)(struct udma_jfr *jfr, enum udma_event event_type);
	uint32_t		jfr_caps;
	struct udma_jfc		*jfc;
	uint32_t		qpn;
	enum ubcore_transport_mode tp_mode;
	bool			share_jfr;
	struct udma_ucontext	*udma_uctx;
};

struct udma_jfr_context {
	uint32_t data[16];
};

#define SRQC_FIELD_LOC(h, l) ((uint64_t)(h) << 32 | (l))

#define SRQC_SRQ_ST SRQC_FIELD_LOC(1, 0)
#define SRQC_WQE_HOP_NUM SRQC_FIELD_LOC(3, 2)
#define SRQC_SHIFT SRQC_FIELD_LOC(7, 4)
#define SRQC_SRQN SRQC_FIELD_LOC(31, 8)
#define SRQC_LIMIT_WL SRQC_FIELD_LOC(47, 32)
#define SRQC_XRCD SRQC_FIELD_LOC(87, 64)
#define SRQC_WQE_BT_BA_L SRQC_FIELD_LOC(159, 128)
#define SRQC_WQE_BT_BA_H SRQC_FIELD_LOC(188, 160)
#define SRQC_SRQ_TYPE SRQC_FIELD_LOC(191, 191)
#define SRQC_PD SRQC_FIELD_LOC(215, 192)
#define SRQC_RQWS SRQC_FIELD_LOC(219, 216)
#define SRQC_IDX_BT_BA_L SRQC_FIELD_LOC(255, 224)
#define SRQC_IDX_BT_BA_H SRQC_FIELD_LOC(284, 256)
#define SRQC_IDX_CUR_BLK_ADDR_L SRQC_FIELD_LOC(319, 288)
#define SRQC_IDX_CUR_BLK_ADDR_H SRQC_FIELD_LOC(339, 320)
#define SRQC_IDX_HOP_NUM SRQC_FIELD_LOC(343, 342)
#define SRQC_IDX_BA_PG_SZ SRQC_FIELD_LOC(347, 344)
#define SRQC_IDX_BUF_PG_SZ SRQC_FIELD_LOC(351, 348)
#define SRQC_IDX_NXT_BLK_ADDR_L SRQC_FIELD_LOC(383, 352)
#define SRQC_IDX_NXT_BLK_ADDR_H SRQC_FIELD_LOC(403, 384)
#define SRQC_XRC_RSV SRQC_FIELD_LOC(439, 416)
#define SRQC_WQE_BA_PG_SZ SRQC_FIELD_LOC(443, 440)
#define SRQC_WQE_BUF_PG_SZ SRQC_FIELD_LOC(447, 444)
#define SRQC_RECORD_DB_EN SRQC_FIELD_LOC(448, 448)
#define SRQC_RECORD_DB_ADDR_L SRQC_FIELD_LOC(479, 449)
#define SRQC_RECORD_DB_ADDR_H SRQC_FIELD_LOC(511, 480)

static inline struct udma_jfr *to_udma_jfr(struct ubcore_jfr *ubcore_jfr)
{
	return container_of(ubcore_jfr, struct udma_jfr, ubcore_jfr);
}

struct ubcore_jfr *udma_create_jfr(struct ubcore_device *dev, struct ubcore_jfr_cfg *cfg,
				   struct ubcore_udata *udata);
int udma_destroy_jfr(struct ubcore_jfr *jfr);
struct udma_jfr *get_udma_jfr(struct ubcore_device *dev, uint32_t jfr_id);
struct ubcore_tjetty *udma_import_jfr(struct ubcore_device *dev,
				      struct ubcore_tjetty_cfg *cfg,
				      struct ubcore_udata *udata);
int udma_unimport_jfr(struct ubcore_tjetty *tjfr);
int udma_modify_jfr(struct ubcore_jfr *jfr, struct ubcore_jfr_attr *attr,
		    struct ubcore_udata *udata);
void udma_jfr_event(struct udma_dev *udma_dev, uint32_t jfrn, int event_type);

#endif /* _UDMA_JFR_H */
