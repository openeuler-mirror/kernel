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

#ifndef _UDMA_DEVICE_H
#define _UDMA_DEVICE_H

#include "hns3_udma_sw_res.h"

#define CQ_BANKID_MASK GENMASK(1, 0)

#define CQC_FIELD_LOC(h, l) ((uint64_t)(h) << 32 | (l))

#define CQC_CQE_BA_L_OFFSET 3
#define CQC_CQE_BA_H_OFFSET 35

#define CQC_CQ_ST CQC_FIELD_LOC(1, 0)
#define CQC_NOTIFY_MODE CQC_FIELD_LOC(4, 4)
#define CQC_ARM_ST CQC_FIELD_LOC(7, 6)
#define CQC_SHIFT CQC_FIELD_LOC(12, 8)
#define CQC_NOTIFY_ADDR_0 CQC_FIELD_LOC(31, 24)
#define CQC_CQN CQC_FIELD_LOC(55, 32)
#define CQC_POE_EN CQC_FIELD_LOC(56, 56)
#define CQC_POE_NUM CQC_FIELD_LOC(58, 57)
#define CQC_CQE_SIZE CQC_FIELD_LOC(60, 59)
#define CQC_NOTIFY_DEVICE_EN CQC_FIELD_LOC(62, 62)
#define CQC_CQE_CUR_BLK_ADDR_L CQC_FIELD_LOC(95, 64)
#define CQC_CQE_CUR_BLK_ADDR_H CQC_FIELD_LOC(115, 96)
#define CQC_POE_QID CQC_FIELD_LOC(125, 116)
#define CQC_CQE_HOP_NUM CQC_FIELD_LOC(127, 126)
#define CQC_CQE_NEX_BLK_ADDR_L CQC_FIELD_LOC(159, 128)
#define CQC_CQE_NEX_BLK_ADDR_H CQC_FIELD_LOC(179, 160)
#define CQC_NOTIFY_ADDR_2 CQC_FIELD_LOC(183, 180)
#define CQC_CQE_BAR_PG_SZ CQC_FIELD_LOC(187, 184)
#define CQC_CQE_BUF_PG_SZ CQC_FIELD_LOC(191, 188)
#define CQC_NOTIFY_ADDR_3 CQC_FIELD_LOC(223, 216)
#define CQC_NOTIFY_ADDR_4 CQC_FIELD_LOC(255, 248)
#define CQC_CQE_BA_L CQC_FIELD_LOC(287, 256)
#define CQC_CQE_BA_H CQC_FIELD_LOC(316, 288)
#define CQC_DB_RECORD_EN CQC_FIELD_LOC(320, 320)
#define CQC_CQE_DB_RECORD_ADDR_L CQC_FIELD_LOC(351, 321)
#define CQC_CQE_DB_RECORD_ADDR_H CQC_FIELD_LOC(383, 352)
#define CQC_CQE_CNT CQC_FIELD_LOC(407, 384)
#define CQC_NOTIFY_ADDR_5 CQC_FIELD_LOC(415, 408)
#define CQC_CQ_MAX_CNT CQC_FIELD_LOC(431, 416)
#define CQC_CQ_PERIOD CQC_FIELD_LOC(447, 432)
#define CQC_NOTIFY_ADDR_6 CQC_FIELD_LOC(509, 504)
#define CQC_NOTIFY_EN CQC_FIELD_LOC(510, 510)

enum {
	NO_ARMED = 0x0
};

enum {
	CQE_SIZE_64B = 0x1
};

enum udma_reset_stage {
	UDMA_STATE_RST_DOWN = 2,
	UDMA_STATE_RST_UNINIT,
	UDMA_STATE_RST_INIT,
	UDMA_STATE_RST_INITED,
};

enum udma_instance_state {
	UDMA_STATE_NON_INIT,
	UDMA_STATE_INIT,
	UDMA_STATE_INITED,
	UDMA_STATE_UNINIT,
};

#define UDMA_IS_RESETTING	1

enum {
	UDMA_RST_DIRECT_RETURN = 0,
};

enum udma_event {
	UDMA_EVENT_TYPE_COMM_EST		= 0x03,
	UDMA_EVENT_TYPE_WQ_CATAS_ERROR		= 0x05,
	UDMA_EVENT_TYPE_INV_REQ_LOCAL_WQ_ERROR	= 0x06,
	UDMA_EVENT_TYPE_LOCAL_WQ_ACCESS_ERROR	= 0x07,
	UDMA_EVENT_TYPE_JFR_LIMIT_REACH		= 0x08,
	UDMA_EVENT_TYPE_JFR_LAST_WQE_REACH	= 0x09,
	UDMA_EVENT_TYPE_JFC_ACCESS_ERROR	= 0x0b,
	UDMA_EVENT_TYPE_JFC_OVERFLOW		= 0x0c,
	UDMA_EVENT_TYPE_MB			= 0x13,
};

enum udma_mtu {
	UDMA_MTU_256				= 1,
	UDMA_MTU_512				= 2,
	UDMA_MTU_1024				= 3,
	UDMA_MTU_2048				= 4,
	UDMA_MTU_4096				= 5
};

enum {
	/* discard BIT(2), reserved for compatibility */
	UDMA_CAP_FLAG_CQ_RECORD_DB		= BIT(3),
	UDMA_CAP_FLAG_QP_RECORD_DB		= BIT(4),
	UDMA_CAP_FLAG_SRQ			= BIT(5),
	UDMA_CAP_FLAG_QP_FLOW_CTRL		= BIT(9),
	UDMA_CAP_FLAG_DIRECT_WQE		= BIT(12),
	UDMA_CAP_FLAG_SDI_MODE			= BIT(14),
	UDMA_CAP_FLAG_DCA_MODE			= BIT(15),
	UDMA_CAP_FLAG_WRITE_NOTIFY		= BIT(16),
	UDMA_CAP_FLAG_STASH			= BIT(17),
	UDMA_CAP_FLAG_CQE_INLINE		= BIT(19),
	UDMA_CAP_FLAG_SRQ_RECORD_DB		= BIT(22),
	UDMA_CAP_FLAG_OOR			= BIT(25),
	UDMA_CAP_FLAG_AR			= BIT(26),
	UDMA_CAP_FLAG_POE			= BIT(27),
};

enum {
	TYPE_CSQ = 1
};

enum udma_cong_type {
	UDMA_CONG_TYPE_DCQCN,
	UDMA_CONG_TYPE_LDCP,
	UDMA_CONG_TYPE_HC3,
	UDMA_CONG_TYPE_DIP,
	UDMA_CONG_TYPE_TOTAL,
};

enum udma_cong_sel {
	UDMA_CONG_SEL_DCQCN = 1 << UDMA_CONG_TYPE_DCQCN,
	UDMA_CONG_SEL_LDCP = 1 << UDMA_CONG_TYPE_LDCP,
	UDMA_CONG_SEL_HC3 = 1 << UDMA_CONG_TYPE_HC3,
	UDMA_CONG_SEL_DIP = 1 << UDMA_CONG_TYPE_DIP,
};

enum udma_sig_type {
	SIGNAL_REQ_WR = 1,
};

enum udma_qp_type {
	QPT_RC,
	QPT_UD = 0x3,
};

enum udma_qp_state {
	QPS_RESET,
	QPS_RTR = 2,
	QPS_RTS,
	QPS_ERR = 6,
};

enum udma_eq_dfx {
	UDMA_DFX_AEQE,
	UDMA_DFX_CEQE,
	UDMA_DFX_EQ_TOTAL
};

enum {
	UDMA_BUF_DIRECT = BIT(0),
	UDMA_BUF_NOSLEEP = BIT(1),
	UDMA_BUF_NOFAIL = BIT(2),
};

static inline enum ubcore_mtu udma_mtu_int_to_enum(int mtu)
{
	if (mtu >= MTU_VAL_4096)
		return UBCORE_MTU_4096;
	else if (mtu >= MTU_VAL_2048)
		return UBCORE_MTU_2048;
	else if (mtu >= MTU_VAL_1024)
		return UBCORE_MTU_1024;
	else if (mtu >= MTU_VAL_512)
		return UBCORE_MTU_512;
	else
		return UBCORE_MTU_256;
}

struct udma_work {
	struct udma_dev		*udma_dev;
	struct work_struct	work;
	int			event_type;
	int			sub_type;
	struct udma_aeqe	aeqe;
	uint32_t		queue_num;
	uint32_t		eq_ci;
	int			eqn;
};

struct udma_netdev {
	struct net_device	*netdevs[UDMA_MAX_PORTS];
};

enum udma_device_state {
	UDMA_DEVICE_STATE_RST_DOWN = 1,
	UDMA_DEVICE_STATE_UNINIT,
};

struct udma_reset_state {
	uint32_t reset_state; /* stored to use in user space */
};

struct udma_cmq {
	struct udma_cmq_ring	csq;
	uint16_t tx_timeout;
};

struct udma_priv {
	struct hnae3_handle	*handle;
	struct udma_cmq		cmq;
	struct udma_link_table	ext_llm;
};

struct udma_hw {
	int (*cmq_init)(struct udma_dev *udma_dev);
	void (*cmq_exit)(struct udma_dev *udma_dev);
	int (*hw_profile)(struct udma_dev *udma_dev);
	int (*hw_init)(struct udma_dev *udma_dev);
	void (*hw_exit)(struct udma_dev *udma_dev);
	int (*post_mbox)(struct udma_dev *udma_dev, struct udma_cmq_desc *desc,
			 uint16_t token, int event);
	int (*poll_mbox_done)(struct udma_dev *udma_dev,
			      uint32_t timeout);
	bool (*chk_mbox_avail)(struct udma_dev *udma_dev, bool *is_busy);
	int (*set_hem)(struct udma_dev *udma_dev,
		       struct udma_hem_table *table, int obj, int step_idx);
	int (*clear_hem)(struct udma_dev *udma_dev,
			 struct udma_hem_table *table, int obj,
			 int step_idx);
	int (*init_eq)(struct udma_dev *udma_dev);
	void (*cleanup_eq)(struct udma_dev *udma_dev);
};

struct udma_caps {
	uint64_t		fw_ver;
	uint8_t			num_qp_en;
	uint8_t			cnp_en;
	uint8_t			num_ports;
	int			pkey_table_len[UDMA_MAX_PORTS];
	int			local_ca_ack_delay;
	int			num_uars;
	uint32_t		phy_num_uars;
	uint32_t		max_sq_sg;
	uint32_t		max_sq_inline;
	uint32_t		max_rq_sg;
	uint32_t		max_extend_sg;
	uint32_t		num_qps;
	uint32_t		num_qps_shift;
	uint32_t		num_pi_qps;
	uint32_t		reserved_qps;
	int			num_qpc_timer;
	int			num_srqs;
	uint32_t		max_wqes;
	uint32_t		max_srq_wrs;
	uint32_t		max_srq_sges;
	uint32_t		max_sq_desc_sz;
	uint32_t		max_rq_desc_sz;
	uint32_t		max_srq_desc_sz;
	int			max_qp_init_rdma;
	int			max_qp_dest_rdma;
	uint32_t		num_cqs;
	uint32_t		max_cqes;
	uint32_t		min_cqes;
	uint32_t		min_wqes;
	uint32_t		reserved_cqs;
	int			reserved_srqs;
	int			num_aeq_vectors;
	int			num_comp_vectors;
	int			num_other_vectors;
	uint32_t		num_mtpts;
	uint32_t		num_mtt_segs;
	uint32_t		num_srqwqe_segs;
	uint32_t		num_idx_segs;
	int			reserved_mrws;
	int			reserved_uars;
	int			num_pds;
	int			reserved_pds;
	uint32_t		num_xrcds;
	uint32_t		reserved_xrcds;
	uint32_t		mtt_entry_sz;
	uint32_t		cqe_sz;
	uint32_t		page_size_cap;
	uint32_t		reserved_lkey;
	int			mtpt_entry_sz;
	int			qpc_sz;
	int			irrl_entry_sz;
	int			trrl_entry_sz;
	int			cqc_entry_sz;
	int			scc_ctx_sz;
	int			qpc_timer_entry_sz;
	int			cqc_timer_entry_sz;
	int			srqc_entry_sz;
	int			idx_entry_sz;
	uint32_t		pbl_ba_pg_sz;
	uint32_t		pbl_buf_pg_sz;
	uint32_t		pbl_hop_num;
	int			aeqe_depth;
	int			ceqe_depth;
	uint32_t		aeqe_size;
	uint32_t		ceqe_size;
	enum ubcore_mtu		max_mtu;
	uint32_t		qpc_bt_num;
	uint32_t		qpc_timer_bt_num;
	uint32_t		srqc_bt_num;
	uint32_t		cqc_bt_num;
	uint32_t		cqc_timer_bt_num;
	uint32_t		mpt_bt_num;
	uint32_t		eqc_bt_num;
	uint32_t		smac_bt_num;
	uint32_t		sgid_bt_num;
	uint32_t		sccc_bt_num;
	uint32_t		gmv_bt_num;
	uint32_t		qpc_ba_pg_sz;
	uint32_t		qpc_buf_pg_sz;
	uint32_t		qpc_hop_num;
	uint32_t		srqc_ba_pg_sz;
	uint32_t		srqc_buf_pg_sz;
	uint32_t		srqc_hop_num;
	uint32_t		cqc_ba_pg_sz;
	uint32_t		cqc_buf_pg_sz;
	uint32_t		cqc_hop_num;
	uint32_t		mpt_ba_pg_sz;
	uint32_t		mpt_buf_pg_sz;
	uint32_t		mpt_hop_num;
	uint32_t		mtt_ba_pg_sz;
	uint32_t		mtt_buf_pg_sz;
	uint32_t		mtt_hop_num;
	uint32_t		wqe_sq_hop_num;
	uint32_t		wqe_sge_hop_num;
	uint32_t		wqe_rq_hop_num;
	uint32_t		sccc_ba_pg_sz;
	uint32_t		sccc_buf_pg_sz;
	uint32_t		sccc_hop_num;
	uint32_t		qpc_timer_ba_pg_sz;
	uint32_t		qpc_timer_buf_pg_sz;
	uint32_t		qpc_timer_hop_num;
	uint32_t		cqc_timer_ba_pg_sz;
	uint32_t		cqc_timer_buf_pg_sz;
	uint32_t		cqc_timer_hop_num;
	uint32_t		cqe_ba_pg_sz;
	uint32_t		cqe_buf_pg_sz;
	uint32_t		cqe_hop_num;
	uint32_t		srqwqe_ba_pg_sz;
	uint32_t		srqwqe_buf_pg_sz;
	uint32_t		srqwqe_hop_num;
	uint32_t		idx_ba_pg_sz;
	uint32_t		idx_buf_pg_sz;
	uint32_t		idx_hop_num;
	uint32_t		eqe_ba_pg_sz;
	uint32_t		eqe_buf_pg_sz;
	uint32_t		eqe_hop_num;
	uint32_t		gmv_entry_num;
	uint32_t		gmv_entry_sz;
	uint32_t		gmv_ba_pg_sz;
	uint32_t		gmv_buf_pg_sz;
	uint32_t		gmv_hop_num;
	uint32_t		sl_num;
	uint32_t		llm_buf_pg_sz;
	uint32_t		llm_ba_idx;
	uint32_t		llm_ba_num;
	uint32_t		chunk_sz; /* chunk size in non multihop mode */
	uint64_t		flags;
	uint16_t		default_ceq_max_cnt;
	uint16_t		default_ceq_period;
	uint16_t		default_aeq_max_cnt;
	uint16_t		default_aeq_period;
	uint16_t		default_aeq_arm_st;
	uint16_t		default_ceq_arm_st;
	uint8_t			cong_type;
	uint8_t			oor_en;
	uint8_t			reorder_cq_buffer_en;
	uint8_t			reorder_cap;
	uint8_t			reorder_cq_shift;
	uint32_t		onflight_size;
	uint8_t			dynamic_ack_timeout;
	uint32_t		num_jfc;
	uint32_t		num_jfs;
	uint32_t		num_jfr;
	uint32_t		num_jetty;
	uint8_t			poe_ch_num;
	uint32_t		speed;
	uint32_t		max_eid_cnt;
};

struct udma_scc_param {
	uint32_t		param[UDMA_SCC_PARAM_SIZE];
	uint32_t		lifespan;
	uint64_t		timestamp;
	enum udma_cong_type	algo_type;
	struct delayed_work	scc_cfg_dwork;
	struct udma_dev		*udma_dev;
	uint8_t			port_num;
	bool			configured;
};

struct udma_cnp_param {
	uint32_t		attr_sel;
	uint32_t		tmp_attr_sel;
	uint32_t		dscp;
	uint32_t		tmp_dscp;
	struct udma_dev		*udma_dev;
	uint64_t		timestamp;
	struct delayed_work	cnp_cfg_dwork;
	bool			cnp_param_inited;
};

struct udma_port {
	struct udma_dev		*udma_dev;
	uint8_t			port_num;
	struct kobject		kobj;
	struct udma_scc_param	*scc_param;
	struct udma_cnp_param	cnp_param;
};

struct udma_dev {
	struct ubcore_device		ub_dev;
	struct pci_dev			*pci_dev;
	struct device			*dev;

	bool				is_reset;
	bool				dis_db;
	uint64_t			reset_cnt;
	struct udma_netdev		uboe;

	uint8_t __iomem			*reg_base;
	struct udma_caps		caps;

	int				irq_num;
	int				irq[UDMA_MAX_IRQ_NUM];
	const char			*irq_names[UDMA_MAX_IRQ_NUM];
	char				dev_name[UBCORE_MAX_DEV_NAME];
	struct udma_cmdq		cmd;
	int				cmd_mod;
	struct page			*reset_page; /* store reset state */
	void				*reset_kaddr; /* addr of reset page */
	const struct udma_hw		*hw;
	void				*priv;
	struct workqueue_struct		*irq_workq;
	struct work_struct		ecc_work;
	uint8_t				chip_id;
	uint8_t				die_id;
	uint16_t			func_id;
	uint32_t			func_num;
	uint32_t			cong_algo_tmpl_id;

	struct udma_ida			uar_ida;
	struct udma_jfs_table		jfs_table;
	struct udma_jfr_table		jfr_table;
	struct udma_jetty_table		jetty_table;
	struct udma_seg_table		seg_table;
	struct udma_jfc_table		jfc_table;
	struct udma_qp_table		qp_table;
	struct udma_eq_table		eq_table;
	struct udma_hem_table		qpc_timer_table;
	struct udma_hem_table		cqc_timer_table;
	struct udma_hem_table		gmv_table;
	struct xarray			eid_table;
	uint64_t			dwqe_page;
	uint64_t			dfx_cnt[UDMA_DFX_EQ_TOTAL];
	/* record the stored qp under this device */
	struct list_head		qp_list;
	spinlock_t			qp_list_lock;
	struct list_head		dip_list;
	spinlock_t			dip_list_lock;
	struct udma_port		port_data[UDMA_MAX_PORTS];
	struct udma_dev_debugfs		*dbgfs;
	uint64_t			notify_addr;
	struct udma_bank		bank[UDMA_QP_BANK_NUM];
	struct udma_num_qp		num_qp;
};

struct udma_seg {
	struct ubcore_target_seg		ubcore_seg;
	uint64_t		iova;
	uint64_t		size;
	uint32_t		key;
	uint32_t		pd;
	uint32_t		access;
	int			enabled;
	uint32_t		pbl_hop_num;
	struct udma_mtr		pbl_mtr;
	uint32_t		npages;
	struct udma_ucontext	*ctx;
};

static inline void *udma_buf_offset(struct udma_buf *buf,
				    uint32_t offset)
{
	return (char *)(buf->trunk_list[offset >> buf->trunk_shift].buf) +
			(offset & ((1 << buf->trunk_shift) - 1));
}

static inline uint64_t to_hr_hw_page_addr(uint64_t addr)
{
	return addr >> UDMA_HW_PAGE_SHIFT;
}

static inline uint32_t to_hr_hw_page_shift(uint32_t page_shift)
{
	return page_shift - UDMA_HW_PAGE_SHIFT;
}

static inline uint32_t to_udma_hem_hopnum(uint32_t hopnum, uint32_t count)
{
	if (count > 0)
		return hopnum == UDMA_HOP_NUM_0 ? 0 : hopnum;

	return 0;
}

static inline struct udma_ucontext
			*to_udma_ucontext(struct ubcore_ucontext *uctx)
{
	return container_of(uctx, struct udma_ucontext, uctx);
}

static inline struct udma_dev *to_udma_dev(struct ubcore_device *ubcore_dev)
{
	return container_of(ubcore_dev, struct udma_dev, ub_dev);
}

static inline struct udma_seg *to_udma_seg(struct ubcore_target_seg *seg)
{
	return container_of(seg, struct udma_seg, ubcore_seg);
}

static inline uint32_t to_udma_hem_entries_size(uint32_t count,
						uint32_t buf_shift)
{
	return UDMA_HW_PAGE_ALIGN(count << buf_shift);
}

static inline uint32_t to_hem_entries_size_by_page(uint32_t count,
						uint32_t buf_shift)
{
	return UDMA_PAGE_ALIGN(count << buf_shift);
}

static inline uint32_t to_udma_hw_page_shift(uint32_t page_shift)
{
	return page_shift - UDMA_HW_PAGE_SHIFT;
}

static inline uint32_t to_udma_hem_entries_count(uint32_t count,
						 uint32_t buf_shift)
{
	return UDMA_HW_PAGE_ALIGN(count << buf_shift) >> buf_shift;
}

static inline uint32_t to_udma_hem_entries_shift(uint32_t count,
						 uint32_t buf_shift)
{
	if (!count)
		return 0;

	return ilog2(to_udma_hem_entries_count(count, buf_shift));
}

static inline uint64_t to_udma_hw_page_addr(uint64_t addr)
{
	return addr >> UDMA_HW_PAGE_SHIFT;
}

static inline dma_addr_t udma_buf_dma_addr(struct udma_buf *buf,
					   uint32_t offset)
{
	return buf->trunk_list[offset >> buf->trunk_shift].map +
			(offset & ((1 << buf->trunk_shift) - 1));
}

static inline dma_addr_t udma_buf_page(struct udma_buf *buf, uint32_t idx)
{
	return udma_buf_dma_addr(buf, idx << buf->page_shift);
}

int udma_cmd_init(struct udma_dev *udma_dev);
void udma_cmd_cleanup(struct udma_dev *udma_dev);
int udma_cmd_use_events(struct udma_dev *udma_dev);
void udma_cmd_use_polling(struct udma_dev *udma_dev);
int udma_cmq_send(struct udma_dev *udma_dev,
		  struct udma_cmq_desc *desc, int num);
int udma_hnae_client_init(struct udma_dev *udma_dev);
void udma_hnae_client_exit(struct udma_dev *udma_dev);
int udma_mtr_create(struct udma_dev *udma_dev, struct udma_mtr *mtr,
		    struct udma_buf_attr *buf_attr, uint32_t ba_page_shift,
		    uint64_t user_addr, bool is_user);
void udma_mtr_destroy(struct udma_dev *udma_dev, struct udma_mtr *mtr);
int udma_init_qp_table(struct udma_dev *udma_dev);
void udma_cleanup_qp_table(struct udma_dev *udma_dev);
void udma_cleanup_common_hem(struct udma_dev *udma_dev);
int udma_init_common_hem(struct udma_dev *udma_dev);

#endif /* _UDMA_DEVICE_H */
