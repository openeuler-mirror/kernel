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

#include <linux/idr.h>
#include <linux/kernel.h>
#include "hns3_udma_hw.h"
#include "hns3_udma_common.h"

#define UDMA_MAX_PORTS				6
#define UDMA_INVALID_ID				0xffff
#define UDMA_MAX_IRQ_NUM			128
#define UDMA_CAP_FLAGS_EX_SHIFT			12

#define UDMA_CMQ_TX_TIMEOUT			30000
#define UDMA_CMQ_DESC_NUM_S			3
#define UDMA_CMD_CSQ_DESC_NUM			1024

#define UDMA_TX_CMQ_BASEADDR_L_REG		0x07000
#define UDMA_TX_CMQ_BASEADDR_H_REG		0x07004
#define UDMA_TX_CMQ_DEPTH_REG			0x07008
#define UDMA_TX_CMQ_PI_REG			0x07010
#define UDMA_TX_CMQ_CI_REG			0x07014

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

enum {
	TYPE_CSQ = 1
};

struct udma_cmd_context {
	struct completion	done;
	int			result;
	int			next;
	uint64_t		out_param;
	uint16_t		token;
	uint16_t		busy;
};

struct udma_cmq_desc {
	uint16_t opcode;
	uint16_t flag;
	uint16_t retval;
	uint16_t rsv;
	uint32_t data[6];
};

enum udma_cmdq_state {
	UDMA_CMDQ_STATE_HEAD_TAIL_ERR = 1,
	UDMA_CMDQ_STATE_FATAL_ERR,
};

struct udma_cmq_ring {
	dma_addr_t		desc_dma_addr;
	struct udma_cmq_desc	*desc;
	uint32_t		head;
	uint16_t		desc_num;
	uint8_t			flag;
	struct mutex		lock;
};

struct udma_cmdq {
	struct dma_pool		*pool;
	struct semaphore	poll_sem;
	struct semaphore	event_sem;
	int			max_cmds;
	spinlock_t		ctx_lock;
	int			free_head;
	struct udma_cmd_context	*context;
	/*
	 * Process whether use event mode, init default non-zero
	 * After the event queue of cmd event ready,
	 * can switch into event mode
	 * close device, switch into poll mode(non event mode)
	 */
	uint8_t			use_events;
	struct rw_semaphore	udma_mb_rwsem;
	enum udma_cmdq_state	state;
};

struct udma_cmd_mailbox {
	void		       *buf;
	dma_addr_t		dma;
};

struct udma_netdev {
	spinlock_t		lock;
	struct net_device	*netdevs[UDMA_MAX_PORTS];
};

enum udma_device_state {
	UDMA_DEVICE_STATE_RST_DOWN = 1,
	UDMA_DEVICE_STATE_UNINIT,
};

struct udma_cmq {
	struct udma_cmq_ring	csq;
	uint16_t tx_timeout;
};

struct udma_priv {
	struct hnae3_handle	*handle;
	struct udma_cmq		cmq;
};

struct udma_dev;
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
};

struct udma_caps {
	uint64_t		fw_ver;
	uint8_t			num_ports;
	int			gid_table_len[UDMA_MAX_PORTS];
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
	uint32_t		num_jfc_shift;
	uint32_t		num_jfs_shift;
	uint32_t		num_jfr_shift;
	uint32_t		num_jetty_shift;
	uint8_t			poe_ch_num;
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
	char				dev_name[UBCORE_MAX_DEV_NAME];
	uint64_t			sys_image_guid;
	struct udma_cmdq		cmd;
	int				cmd_mod;
	const struct udma_hw		*hw;
	void				*priv;
	uint16_t			func_id;
	uint32_t			func_num;
	uint32_t			cong_algo_tmpl_id;
};

int udma_cmd_init(struct udma_dev *udma_dev);
void udma_cmd_cleanup(struct udma_dev *udma_dev);
int udma_cmd_use_events(struct udma_dev *udma_dev);
void udma_cmd_use_polling(struct udma_dev *udma_dev);
int udma_cmq_send(struct udma_dev *udma_dev,
		  struct udma_cmq_desc *desc, int num);
int udma_hnae_client_init(struct udma_dev *udma_dev);
void udma_hnae_client_exit(struct udma_dev *udma_dev);

#endif /* _UDMA_DEVICE_H */
