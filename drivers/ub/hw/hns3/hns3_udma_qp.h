/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei HNS3_UDMA Linux driver
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

#ifndef _HNS3_UDMA_QP_H
#define _HNS3_UDMA_QP_H

#include <linux/bitmap.h>
#include "urma/ubcore_types.h"
#include "hns3_udma_device.h"

#define HNS3_UDMA_GID_SIZE 16
#define SGEN_INI_VALUE 3
#define QP_TIMEOUT_MAX 31
#define WQE_SGE_BA_OFFSET 3
#define H_ADDR_OFFSET 32
#define MAX_LP_MSG_LEN 16384
#define QPC_DMAC_H_IDX 4
#define UDP_RANGE_BASE 8
#define HNS3_UDMA_SQ_WQE_SHIFT 6
#define RETRY_MSG_PSN_H_OFFSET 16
#define HNS3_UDMA_MTU_VAL_256 256
#define HNS3_UDMA_MTU_VAL_512 512
#define HNS3_UDMA_MTU_VAL_1024 1024
#define HNS3_UDMA_MTU_VAL_2048 2048
#define HNS3_UDMA_MTU_VAL_4096 4096
#define HNS3_UDMA_DIRECT_WQE_MAX 524288

#define CQ_BANKID_MASK GENMASK(1, 0)

struct hns3_udma_qp_context_ex {
	uint32_t data[64];
};

struct hns3_udma_qp_context {
	uint32_t qpc_context1;
	uint32_t wqe_sge_ba;
	uint32_t qpc_context2[5];
	uint8_t  dgid[HNS3_UDMA_GID_SIZE];
	uint32_t dmac;
	uint32_t qpc_context3[3];
	uint32_t qkey_xrcd;
	uint32_t qpc_context4[11];
	uint32_t rq_rnr_timer;
	uint32_t qpc_context5[36];
	struct hns3_udma_qp_context_ex ext;
};

#define QPC_FIELD_LOC(h, l) ((uint64_t)(h) << 32 | (l))

#define QPC_TST QPC_FIELD_LOC(2, 0)
#define QPC_SGE_SHIFT QPC_FIELD_LOC(7, 3)
#define QPC_WQE_SGE_BA_L QPC_FIELD_LOC(63, 32)
#define QPC_WQE_SGE_BA_H QPC_FIELD_LOC(92, 64)
#define QPC_SQ_HOP_NUM QPC_FIELD_LOC(94, 93)
#define QPC_WQE_SGE_BA_PG_SZ QPC_FIELD_LOC(99, 96)
#define QPC_WQE_SGE_BUF_PG_SZ QPC_FIELD_LOC(103, 100)
#define QPC_RQ_HOP_NUM QPC_FIELD_LOC(129, 128)
#define QPC_SGE_HOP_NUM QPC_FIELD_LOC(131, 130)
#define QPC_RQWS QPC_FIELD_LOC(135, 132)
#define QPC_SQ_SHIFT QPC_FIELD_LOC(139, 136)
#define QPC_RQ_SHIFT QPC_FIELD_LOC(143, 140)
#define QPC_GMV_IDX QPC_FIELD_LOC(159, 144)
#define QPC_HOPLIMIT QPC_FIELD_LOC(167, 160)
#define QPC_DSCP QPC_FIELD_LOC(172, 168)
#define QPC_VLAN_ID QPC_FIELD_LOC(187, 176)
#define QPC_MTU QPC_FIELD_LOC(191, 188)
#define QPC_FL QPC_FIELD_LOC(211, 192)
#define QPC_SL QPC_FIELD_LOC(215, 212)
#define QPC_AT QPC_FIELD_LOC(223, 219)
#define QPC_DMAC_L QPC_FIELD_LOC(383, 352)
#define QPC_DMAC_H QPC_FIELD_LOC(399, 384)
#define QPC_UDPSPN QPC_FIELD_LOC(415, 400)
#define QPC_DQPN QPC_FIELD_LOC(439, 416)
#define QPC_LP_PKTN_INI QPC_FIELD_LOC(447, 444)
#define QPC_CONGEST_ALGO_TMPL_ID QPC_FIELD_LOC(455, 448)
#define QPC_QP_ST QPC_FIELD_LOC(479, 477)
#define QPC_RQ_RECORD_EN QPC_FIELD_LOC(512, 512)
#define QPC_RQ_DB_RECORD_ADDR_L QPC_FIELD_LOC(543, 513)
#define QPC_RQ_DB_RECORD_ADDR_H QPC_FIELD_LOC(575, 544)
#define QPC_SRQN QPC_FIELD_LOC(599, 576)
#define QPC_SRQ_EN QPC_FIELD_LOC(600, 600)
#define QPC_RRE QPC_FIELD_LOC(601, 601)
#define QPC_RWE QPC_FIELD_LOC(602, 602)
#define QPC_RX_CQN QPC_FIELD_LOC(631, 608)
#define QPC_XRC_QP_TYPE QPC_FIELD_LOC(632, 632)
#define QPC_CQEIE QPC_FIELD_LOC(633, 633)
#define QPC_MIN_RNR_TIME QPC_FIELD_LOC(639, 635)
#define QPC_RQ_CUR_BLK_ADDR_L QPC_FIELD_LOC(703, 672)
#define QPC_RQ_CUR_BLK_ADDR_H QPC_FIELD_LOC(723, 704)
#define QPC_RQ_NXT_BLK_ADDR_L QPC_FIELD_LOC(799, 768)
#define QPC_RQ_NXT_BLK_ADDR_H QPC_FIELD_LOC(819, 800)
#define QPC_FLUSH_EN QPC_FIELD_LOC(821, 821)
#define QPC_AW_EN QPC_FIELD_LOC(822, 822)
#define QPC_WN_EN QPC_FIELD_LOC(823, 823)
#define QPC_INV_CREDIT QPC_FIELD_LOC(832, 832)
#define QPC_RX_REQ_EPSN QPC_FIELD_LOC(863, 840)
#define QPC_RR_MAX QPC_FIELD_LOC(1102, 1100)
#define QPC_RAQ_PSN QPC_FIELD_LOC(1207, 1184)
#define QPC_SQ_PRODUCER_IDX QPC_FIELD_LOC(1263, 1248)
#define QPC_SQ_CONSUMER_IDX QPC_FIELD_LOC(1279, 1264)
#define QPC_SQ_CUR_BLK_ADDR_L QPC_FIELD_LOC(1311, 1280)
#define QPC_SQ_CUR_BLK_ADDR_H QPC_FIELD_LOC(1331, 1312)
#define QPC_LP_SGEN_INI QPC_FIELD_LOC(1335, 1334)
#define QPC_ACK_REQ_FREQ QPC_FIELD_LOC(1349, 1344)
#define QPC_SQ_CUR_PSN QPC_FIELD_LOC(1375, 1352)
#define QPC_SQ_CUR_SGE_BLK_ADDR_L QPC_FIELD_LOC(1439, 1408)
#define QPC_SQ_CUR_SGE_BLK_ADDR_H QPC_FIELD_LOC(1459, 1440)
#define QPC_OWNER_MODE QPC_FIELD_LOC(1536, 1536)
#define QPC_DCA_MODE QPC_FIELD_LOC(1542, 1542)
#define QPC_SQ_MAX_PSN QPC_FIELD_LOC(1567, 1544)
#define QPC_RMT_E2E QPC_FIELD_LOC(1660, 1660)
#define QPC_RETRY_NUM_INIT QPC_FIELD_LOC(1690, 1688)
#define QPC_RETRY_CNT QPC_FIELD_LOC(1695, 1693)
#define QPC_RETRY_MSG_MSN QPC_FIELD_LOC(1743, 1728)
#define QPC_RETRY_MSG_PSN_L QPC_FIELD_LOC(1759, 1744)
#define QPC_RETRY_MSG_PSN_H QPC_FIELD_LOC(1767, 1760)
#define QPC_RETRY_MSG_FPKT_PSN QPC_FIELD_LOC(1791, 1768)
#define QPC_RX_SQ_CUR_BLK_ADDR_L QPC_FIELD_LOC(1823, 1792)
#define QPC_RX_SQ_CUR_BLK_ADDR_H QPC_FIELD_LOC(1843, 1824)
#define QPC_RX_ACK_EPSN QPC_FIELD_LOC(1943, 1920)
#define QPC_RNR_NUM_INIT QPC_FIELD_LOC(1946, 1944)
#define QPC_RNR_CNT QPC_FIELD_LOC(1949, 1947)
#define QPC_TX_CQN QPC_FIELD_LOC(2007, 1984)
#define QPC_SIG_TYPE QPC_FIELD_LOC(2008, 2008)

#define QPCEX_FIELD_LOC(h, l) ((uint64_t)(h) << 32 | (l))

#define QPCEX_ON_FLIGHT_SIZE_H_SHIFT 3
#define QPCEX_REORDER_CQ_ADDR_SHIFT 12
#define QPCEX_DATA_UDP_SRCPORT_H_SHIFT 11
#define QPCEX_RTT_INIT 100
#define QPCEX_P_TYPE_HNS3_UDMA 0x1
#define MAX_SERVICE_LEVEL 0x7

#define QPCEX_CONGEST_ALG_SEL QPCEX_FIELD_LOC(0, 0)
#define QPCEX_CONGEST_ALG_SUB_SEL QPCEX_FIELD_LOC(1, 1)
#define QPCEX_DIP_CTX_IDX_VLD QPCEX_FIELD_LOC(2, 2)
#define QPCEX_DIP_CTX_IDX QPCEX_FIELD_LOC(22, 3)
#define QPCEX_SQ_RQ_NOT_FORBID_EN QPCEX_FIELD_LOC(23, 23)
#define QPCEX_RTT QPCEX_FIELD_LOC(81, 66)
#define QPCEX_AR_EN QPCEX_FIELD_LOC(112, 112)
#define QPCEX_UDP_SRCPORT_RANGE QPCEX_FIELD_LOC(116, 113)
#define QPCEX_DATA_UDP_SRCPORT_L QPCEX_FIELD_LOC(127, 117)
#define QPCEX_DATA_UDP_SRCPORT_H QPCEX_FIELD_LOC(132, 128)
#define QPCEX_ACK_UDP_SRCPORT QPCEX_FIELD_LOC(148, 133)
#define QPCEX_REORDER_CAP QPCEX_FIELD_LOC(155, 153)
#define QPCEX_ON_FLIGHT_SIZE_L QPCEX_FIELD_LOC(159, 157)
#define QPCEX_ON_FLIGHT_SIZE_H QPCEX_FIELD_LOC(172, 160)
#define QPCEX_OOR_EN QPCEX_FIELD_LOC(266, 266)
#define QPCEX_P_TYPE QPCEX_FIELD_LOC(268, 268)
#define QPCEX_DYN_AT QPCEX_FIELD_LOC(272, 269)
#define QPCEX_DEID_H QPCEX_FIELD_LOC(319, 288)
#define QPCEX_REORDER_CQ_EN QPCEX_FIELD_LOC(427, 427)
#define QPCEX_REORDER_CQ_ADDR_L QPCEX_FIELD_LOC(447, 428)
#define QPCEX_REORDER_CQ_ADDR_H QPCEX_FIELD_LOC(479, 448)
#define QPCEX_REORDER_CQ_SHIFT QPCEX_FIELD_LOC(483, 480)
#define UDP_SRCPORT_RANGE_BASE 7
#define UDP_SRCPORT_RANGE_SIZE_MASK 0xF

struct hns3_udma_modify_tp_attr {
	uint8_t				dmac[UBCORE_MAC_BYTES];
	uint32_t			dest_qp_num;
	uint8_t				retry_cnt;
	uint8_t				rnr_retry;
	uint8_t				priority;
	uint8_t				ack_timeout;
	uint32_t			sq_psn;
	uint32_t			rq_psn;
	uint8_t				max_dest_rd_atomic;
	uint8_t				max_rd_atomic;
	uint8_t				min_rnr_timer;
	uint32_t			qkey;
	uint8_t				dgid[HNS3_UDMA_GID_SIZE];
	uint8_t				dipv4[4];
	uint8_t				sgid_index;
	uint16_t			data_udp_start;
	uint16_t			ack_udp_start;
	uint16_t			udp_range;
	uint32_t			ar_en;
	enum hns3_udma_cong_type	cong_alg;
};

struct hns3_udma_qp_cap {
	uint32_t	max_send_wr;
	uint32_t	max_recv_wr;
	uint32_t	max_send_sge;
	uint32_t	max_recv_sge;
	uint32_t	max_inline_data;
	uint8_t		retry_cnt;
	uint8_t		rnr_retry;
	uint8_t		min_rnr_timer;
	uint8_t		ack_timeout;
};

struct hns3_udma_qpn_bitmap {
	uint32_t		qpn_prefix;
	uint32_t		jid;
	uint32_t		qpn_shift;
	struct hns3_udma_bank	bank[HNS3_UDMA_QP_BANK_NUM];
	struct mutex		bank_mutex;
};

struct hns3_udma_qp_attr {
	bool				is_jetty;
	bool				is_tgt;
	struct ubcore_ucontext		*uctx;
	struct hns3_udma_jfc		*send_jfc;
	struct hns3_udma_jfc		*recv_jfc;
	struct hns3_udma_jfs		*jfs;
	struct hns3_udma_jfr		*jfr;
	struct hns3_udma_jetty		*jetty;
	struct hns3_udma_qp_cap		cap;
	enum hns3_udma_qp_type		qp_type;
	uint32_t			pdn;
	struct hns3_udma_qpn_bitmap	*qpn_map;
	void				*reorder_cq_page;
	int				reorder_cq_size;
	dma_addr_t			reorder_cq_addr;
	union ubcore_eid		remote_eid;
	union ubcore_eid		local_eid;
	int				tgt_id;
	uint8_t				priority;
	uint32_t			eid_index;
	enum ubcore_transport_mode	tp_mode;
};

struct hns3_udma_wq {
	uint32_t		wqe_cnt; /* WQE num */
	uint32_t		max_gs;
	uint32_t		offset;
	uint32_t		wqe_offset;
	int			wqe_shift; /* WQE size */
	uint32_t		head;
};

struct hns3_udma_qp_sge {
	uint32_t		sge_cnt; /* SGE num */
	uint32_t		offset;
	int			sge_shift; /* SGE size */
	uint32_t		wqe_offset;
};

struct hns3_udma_dca_cfg {
	spinlock_t		lock;
	uint32_t		attach_count;
	uint32_t		buf_id;
	uint32_t		dcan;
	void			**buf_list;
	uint32_t		npages;
	uint32_t		sq_idx;
	bool			aging_enable;
	struct list_head	aging_node;
};

struct hns3_udma_qp {
	struct hns3_udma_dev		*udma_device;
	struct hns3_udma_ucontext	*hns3_udma_uctx;
	enum hns3_udma_qp_type		qp_type;
	struct hns3_udma_qp_attr	qp_attr;
	struct hns3_udma_wq		sq;
	struct hns3_udma_wq		rq;
	struct hns3_udma_db		sdb;
	struct hns3_udma_jfc		*send_jfc;
	struct hns3_udma_jfc		*recv_jfc;
	uint64_t			en_flags;
	enum hns3_udma_sig_type		sq_signal_bits;
	struct hns3_udma_mtr		mtr;
	struct hns3_udma_dca_cfg	dca_cfg;
	struct hns3_udma_dca_ctx	*dca_ctx;
	uint32_t			buff_size;
	enum hns3_udma_qp_state		state;
	uint32_t			atomic_rd_en;
	void (*event)(struct hns3_udma_qp	*qp,
		      enum hns3_udma_event	event_type);
	uint64_t			qpn;

	refcount_t			refcount;
	struct completion		free;
	struct hns3_udma_qp_sge		sge;
	enum hns3_udma_mtu		path_mtu;
	enum ubcore_mtu			ubcore_path_mtu;
	uint32_t			max_inline_data;
	uint8_t				sl;
	struct list_head		node; /* all qps are on a list */
	struct list_head		rq_node; /* all recv qps are on a list */
	struct list_head		sq_node; /* all send qps are on a list */
	uint8_t				rnr_retry;
	uint8_t				ack_timeout;
	uint8_t				min_rnr_timer;
	uint8_t				priority;
	bool				no_free_wqe_buf;
	bool				force_free_wqe_buf;
	int64_t				dip_idx;
	struct hns3_udma_modify_tp_attr m_attr;
	struct hns3_udma_dip		*dip;
	enum hns3_udma_cong_type	congest_type;
};

struct hns3_udma_congestion_algorithm {
	uint8_t congest_type;
	uint8_t alg_sel;
	uint8_t alg_sub_sel;
	uint8_t dip_vld;
	uint8_t wnd_mode_sel;
};

struct hns3_udma_dip {
	uint8_t dgid[HNS3_UDMA_GID_SIZE];
	uint32_t dip_idx;
	uint32_t qp_cnt;
	struct list_head node; /* all dips are on a list */
};

#define HNS3_UDMA_INVALID_LOAD_QPNUM 0xFFFFFFFF

#define HNS3_UDMA_CONGEST_SIZE 64
#define HNS3_UDMA_SCC_DIP_INVALID_IDX (-1)

enum {
	CONGEST_DCQCN,
	CONGEST_LDCP,
	CONGEST_HC3,
	CONGEST_DIP,
};

enum {
	DCQCN_ALG,
	WINDOW_ALG,
};

enum {
	UNSUPPORT_CONGEST_DEGREE,
	SUPPORT_CONGEST_DEGREE,
};

enum {
	DIP_INVALID,
	DIP_VALID,
};

enum {
	SUB_ALG_LDCP,
	SUB_ALG_HC3,
};

enum {
	WND_LIMIT,
	WND_UNLIMIT,
};

enum {
	QP_IS_USER = 1 << 0,
	QP_DCA_EN = 1 << 1,
};

#define gen_qpn(high, mid, low) ((high) | (mid) | (low))

bool is_rc_jetty(struct hns3_udma_qp_attr *qp_attr);
bool is_rq_jetty(struct hns3_udma_qp_attr *qp_attr);
int hns3_udma_modify_qp_common(struct hns3_udma_qp *qp,
			       struct ubcore_tp_attr *attr,
			       union ubcore_tp_attr_mask ubcore_mask,
			       enum hns3_udma_qp_state curr_state,
			       enum hns3_udma_qp_state new_state);
int hns3_udma_fill_qp_attr(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp_attr *qp_attr,
			   struct ubcore_tp_cfg *cfg, struct ubcore_udata *udata);
int hns3_udma_create_qp_common(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp,
			       struct ubcore_udata *udata);
void hns3_udma_destroy_qp_common(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp,
				 struct ubcore_tp *fail_ret_tp);
int hns3_udma_flush_cqe(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *hns3_udma_qp,
			uint32_t sq_pi);
void hns3_udma_qp_event(struct hns3_udma_dev *udma_dev, uint32_t qpn, int event_type);
int hns3_udma_set_dca_buf(struct hns3_udma_dev *dev, struct hns3_udma_qp *qp);
int hns3_udma_init_qpc(struct hns3_udma_dev *udma_dev, struct hns3_udma_qp *qp);
int alloc_common_qpn(struct hns3_udma_dev *udma_dev, struct hns3_udma_jfc *jfc,
		     uint32_t *qpn);
void free_common_qpn(struct hns3_udma_dev *udma_dev, uint32_t qpn);

static inline uint8_t get_affinity_cq_bank(uint8_t qp_bank)
{
	return (qp_bank >> 1) & CQ_BANKID_MASK;
}

#endif /* _HNS3_UDMA_QP_H */
