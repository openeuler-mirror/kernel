/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei HNS3_UDMA Linux driver
 * Copyright (c) 2024-2024 Hisilicon Limited.
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

#ifndef HNS3_UDMA_SW_RESOURCE_H
#define HNS3_UDMA_SW_RESOURCE_H

#include <linux/idr.h>
#include <linux/kernel.h>
#include "hns3_udma_hw.h"
#include "hns3_udma_common.h"

#define DRV_NAME "hns3_udma"

#define HNS3_UDMA_MAX_PORTS			6

#define BA_BYTE_LEN				8

#ifndef ETH_ALEN
#define ETH_ALEN				6
#endif

#define HNS3_UDMA_INVALID_ID			0xffff

/* Configure to HW for PAGE_SIZE larger than 4KB */
#define PG_SHIFT_OFFSET				(PAGE_SHIFT - 12)

#define CQ_BANKID_SHIFT				2

#define HNS3_UDMA_MAX_IRQ_NUM			128

#define MTT_MIN_COUNT				2

#define HNS3_UDMA_CNP_EN			0x8
#define HNS3_UDMA_NUM_QP_EN			0x2
#define HNS3_UDMA_QP_BANK_NUM			8
#define QP_BANKID_SHIFT				3
#define QP_BANKID_MASK				GENMASK(2, 0)
#define HNS3_UDMA_QPC_SZ			512
#define HNS3_UDMA_CQE_SZ			64
#define HNS3_UDMA_SCCC_SZ			64
#define HNS3_UDMA_GMV_ENTRY_SZ			32
#define HNS3_UDMA_SCC_PARAM_SIZE		4

#define HNS3_UDMA_CQ_BANK_NUM			4

#define HNS3_UDMA_SGE_IN_WQE			2
#define HNS3_UDMA_SGE_SHIFT			4
#define HNS3_UDMA_SGE_SIZE			16
#define HNS3_UDMA_IDX_QUE_ENTRY_SZ		4

#define HNS3_UDMA_DWQE_SIZE			65536
#define HNS3_UDMA_DWQE_MMAP_QP_NUM		1024

#define HNS3_UDMA_HOP_NUM_0			0xff
#define HNS3_UDMA_HOP_NUM_1			1
#define HNS3_UDMA_HOP_NUM_2			2
#define HNS3_UDMA_HOP_NUM_3			3
#define HNS3_UDMA_CAP_FLAGS_EX_SHIFT		12

#define HNS3_UDMA_STEP_IDX_0			0
#define HNS3_UDMA_STEP_IDX_1			1

#define HNS3_UDMA_MAX_EID_NUM			1024

#define HNS3_UDMA_CMQ_TX_TIMEOUT		30000
#define HNS3_UDMA_CMQ_DESC_NUM_S		3
#define HNS3_UDMA_CMD_CSQ_DESC_NUM		1024

#define HNS3_UDMA_TX_CMQ_BASEADDR_L_REG		0x07000
#define HNS3_UDMA_TX_CMQ_BASEADDR_H_REG		0x07004
#define HNS3_UDMA_TX_CMQ_DEPTH_REG		0x07008
#define HNS3_UDMA_TX_CMQ_PI_REG			0x07010
#define HNS3_UDMA_TX_CMQ_CI_REG			0x07014

#define HNS3_UDMA_MAX_MSG_LEN			0x80000000

#define HNS3_UDMA_MAX_BT_REGION			3
#define HNS3_UDMA_MAX_BT_LEVEL			3

#define CQ_STATE_VALID				1

#define HNS3_UDMA_CQ_DEFAULT_BURST_NUM		0x0
#define HNS3_UDMA_CQ_DEFAULT_INTERVAL		0x0

#define EQ_ENABLE				1
#define EQ_DISABLE				0
#define HNS3_UDMA_CEQ				0
#define HNS3_UDMA_AEQ				1
#define HNS3_UDMA_AEQ_DEFAULT_BURST_NUM		0x0
#define HNS3_UDMA_AEQ_DEFAULT_INTERVAL		0x0
#define HNS3_UDMA_CEQ_DEFAULT_BURST_NUM		0x0
#define HNS3_UDMA_CEQ_DEFAULT_INTERVAL		0x0
#define HNS3_UDMA_VF_EQ_DB_CFG0_REG		0x238
#define HNS3_UDMA_VF_ABN_INT_CFG_REG		0x13000
#define HNS3_UDMA_VF_ABN_INT_ST_REG		0x13004
#define HNS3_UDMA_VF_ABN_INT_EN_REG		0x13008
#define HNS3_UDMA_VF_EVENT_INT_EN_REG		0x1300c
#define EQ_REG_OFFSET				0x4
#define MTU_VAL_256				256
#define MTU_VAL_512				512
#define MTU_VAL_1024				1024
#define MTU_VAL_2048				2048
#define MTU_VAL_4096				4096
#define HNS3_UDMA_DEFAULT_MAX_JETTY_X_SHIFT	8

#define HNS3_UDMA_DB_ADDR_OFFSET		0x230
#define HNS3_UDMA_DEV_START_OFFSET		2
#define HNS3_UDMA_DEV_EX_START_OFFSET		4

#define HNS3_UDMA_MIN_JFS_DEPTH			64

#define HNS3_UDMA_DCA_BITS_PER_STATUS		1
#define DCA_BITS_HALF				2

#define TRACE_AEQE_LEN_MAX			64

struct hns3_udma_uar {
	uint64_t	pfn;
	uint64_t	logic_idx;
};

struct hns3_udma_ida {
	struct ida	ida;
	uint32_t	min; /* Lowest ID to allocate.  */
	uint32_t	max; /* Highest ID to allocate. */
};

struct hns3_udma_bank {
	struct ida ida;
	uint32_t inuse; /* Number of IDs allocated */
	uint32_t min; /* Lowest ID to allocate.  */
	uint32_t max; /* Highest ID to allocate. */
	uint32_t next; /* Next ID to allocate. */
};

struct hns3_udma_buf_region {
	uint32_t	offset; /* page offset */
	uint32_t	count; /* page count */
	int		hopnum; /* addressing hop num */
};

struct hns3_udma_hem_list {
	struct list_head	root_bt;
	/* link all bt dma mem by hop config */
	struct list_head	mid_bt[HNS3_UDMA_MAX_BT_REGION][HNS3_UDMA_MAX_BT_LEVEL];
	struct list_head	btm_bt; /* link all bottom bt in @mid_bt */
	dma_addr_t		root_ba; /* pointer to the root ba table */
};

struct hns3_udma_buf_attr {
	struct {
		size_t		size;  /* region size */
		int		hopnum; /* multi-hop addressing hop num */
	} region[HNS3_UDMA_MAX_BT_REGION];
	uint32_t		region_count; /* valid region count */
	uint32_t		page_shift;  /* buffer page shift */
	/* only alloc buffer-required MTT memory */
	bool			mtt_only;
};

struct hns3_udma_buf_list {
	void		*buf;
	dma_addr_t	map;
};

struct hns3_udma_hem_cfg {
	dma_addr_t			root_ba; /* root BA table's address */
	bool				is_direct; /* addressing without BA table */
	uint32_t			ba_pg_shift; /* BA table page shift */
	uint32_t			buf_pg_shift; /* buffer page shift */
	uint32_t			buf_pg_count;  /* buffer page count */
	struct hns3_udma_buf_region	region[HNS3_UDMA_MAX_BT_REGION];
	uint32_t			region_count;
};

struct hns3_udma_buf {
	struct hns3_udma_buf_list	*trunk_list;
	uint32_t			ntrunks;
	uint32_t			npages;
	uint32_t			trunk_shift;
	uint32_t			page_shift;
};

struct hns3_udma_link_table {
	struct hns3_udma_buf_list	table;
	struct hns3_udma_buf		*buf;
};

/* memory translate region */
struct hns3_udma_mtr {
	struct hns3_udma_hem_list	hem_list; /* multi-hop addressing resource */
	struct ubcore_umem		*umem; /* user space buffer */
	struct hns3_udma_buf		*kmem; /* kernel space buffer */
	struct hns3_udma_hem_cfg	hem_cfg; /* config for hardware addressing */
};

struct hns3_udma_user_db_page {
	struct list_head	list;
	struct ubcore_umem	*umem;
	uint64_t		user_virt;
	refcount_t		refcount;
};

struct hns3_udma_ceqe {
	uint32_t	comp;
	uint32_t	rsv[15];
};

struct hns3_udma_aeqe {
	uint32_t			asyn;
	union {
		struct {
			uint32_t	num;
			uint32_t	rsv0;
			uint32_t	rsv1;
		} queue_event;

		struct {
			uint64_t	out_param;
			uint16_t	token;
			uint8_t		status;
			uint8_t		rsv0;
		} __packed cmd;
	 } event;
	uint32_t			rsv[12];
};

struct hns3_udma_db {
	uint32_t			*db_record;
	struct hns3_udma_user_db_page	*user_page;
	dma_addr_t			dma;
	void				*virt_addr;
};

struct hns3_udma_dca_ctx {
	struct list_head	pool; /* all DCA mems link to @pool */
	spinlock_t		pool_lock; /* protect @pool */
	uint32_t		free_mems; /* free mem num in pool */
	size_t			free_size; /* free mem size in pool */
	size_t			total_size; /* total size in pool */
	size_t			max_size; /* max size the pool can expand to */
	size_t			min_size; /* shrink if @free_size > @min_size */
	uint32_t		unit_size; /* unit size per DCA mem */

	uint32_t		max_qps;
	uint32_t		status_npage;
	struct ida		ida;

	uintptr_t		*buf_status;
	uintptr_t		*sync_status;

	bool			exit_aging;
	struct list_head	aging_proc_list;
	struct list_head	aging_new_list;
	spinlock_t		aging_lock;
	struct delayed_work	aging_dwork;
};

struct hns3_udma_ucontext {
	struct ubcore_ucontext		uctx;
	struct hns3_udma_uar		uar;
	uint64_t			pdn;
	struct hns3_udma_dca_ctx	dca_ctx;
	void				*dca_dbgfs;
	uint32_t			eid_index;
	struct list_head		pgdir_list;
	struct mutex			pgdir_mutex;
	uint8_t				cq_bank_id;
};

struct hns3_udma_cmd_context {
	struct completion	done;
	int			result;
	int			next;
	uint64_t		out_param;
	uint16_t		token;
	uint16_t		busy;
};

#define HNS3_UDMA_CMQ_DESC_DATA_0 0
#define HNS3_UDMA_CMQ_DESC_DATA_1 1
#define HNS3_UDMA_CMQ_DESC_DATA_2 2
#define HNS3_UDMA_CMQ_DESC_DATA_3 3
#define HNS3_UDMA_CMQ_DESC_DATA_4 4
#define HNS3_UDMA_CMQ_DESC_DATA_5 5

struct hns3_udma_cmq_desc {
	uint16_t opcode;
	uint16_t flag;
	uint16_t retval;
	uint16_t rsv;
	uint32_t data[6];
};

enum hns3_udma_cmdq_state {
	HNS3_UDMA_CMDQ_STATE_HEAD_TAIL_ERR = 1,
	HNS3_UDMA_CMDQ_STATE_FATAL_ERR,
};

struct hns3_udma_cmq_ring {
	dma_addr_t			desc_dma_addr;
	struct hns3_udma_cmq_desc	*desc;
	uint32_t			head;
	uint16_t			desc_num;
	uint8_t				flag;
	struct mutex			lock;
};

struct hns3_udma_cmdq {
	struct dma_pool			*pool;
	struct semaphore		poll_sem;
	struct semaphore		event_sem;
	int				max_cmds;
	spinlock_t			ctx_lock;
	int				free_head;
	struct hns3_udma_cmd_context	*context;
	/*
	 * Process whether use event mode, init default non-zero
	 * After the event queue of cmd event ready,
	 * can switch into event mode
	 * close device, switch into poll mode(non event mode)
	 */
	uint8_t				use_events;
	struct rw_semaphore		udma_mb_rwsem;
	enum hns3_udma_cmdq_state	state;
};

struct hns3_udma_cmd_mailbox {
	void			*buf;
	dma_addr_t		dma;
};

struct hns3_udma_hem_table {
	/* HEM type: 0 = qpc, 1 = mtpt, 2 = cqc, 3 = srqc, 4 = sccc,
	 * 5 = qpc_timer, 6 = cqc_timer, 7 = gmv
	 */
	uint32_t		type;
	/* HEM array elment num */
	uint64_t		num_hem;
	/* Single obj size */
	uint64_t		obj_size;
	uint64_t		table_chunk_size;
	struct mutex		mutex;
	struct hns3_udma_hem	**hem;
	uint64_t		**bt_l1;
	dma_addr_t		*bt_l1_dma_addr;
	uint64_t		**bt_l0;
	dma_addr_t		*bt_l0_dma_addr;
};

struct hns3_udma_idx_table {
	unsigned long *qpn_bitmap;
	unsigned long *dip_idx_bitmap;
};

struct hns3_udma_eq {
	struct hns3_udma_dev		*udma_dev;
	void __iomem			*db_reg;

	int				type_flag; /* Aeq:1 ceq:0 */
	int				eqn;
	uint32_t			entries;
	int				eqe_size;
	int				irq;
	uint32_t			cons_index;
	int				over_ignore;
	int				coalesce;
	int				arm_st;
	int				hop_num;
	struct hns3_udma_mtr		mtr;
	uint16_t			eq_max_cnt;
	uint32_t			eq_period;
	int				shift;
	int				event_type;
	int				sub_type;
};

struct hns3_udma_qp_table {
	struct xarray			xa;
	struct hns3_udma_hem_table	qp_table;
	struct hns3_udma_hem_table	sccc_table;
	struct hns3_udma_bank		bank[HNS3_UDMA_QP_BANK_NUM];
	struct mutex			bank_mutex;
	struct hns3_udma_idx_table	idx_table;
};

struct hns3_udma_eq_table {
	uint32_t		*idx_table;
	struct hns3_udma_eq	*eq;
};

struct hns3_udma_jfc_table {
	struct xarray			xa;
	struct hns3_udma_hem_table	table;
	struct hns3_udma_bank		bank[HNS3_UDMA_CQ_BANK_NUM];
	struct mutex			bank_mutex;
	uint32_t			ctx_num[HNS3_UDMA_CQ_BANK_NUM];
};

struct hns3_udma_jfs_table {
	struct xarray			xa;
	struct hns3_udma_ida		jfs_ida;
};

struct hns3_udma_jfr_table {
	struct xarray			xa;
	struct hns3_udma_hem_table	table;
	struct hns3_udma_ida		jfr_ida;
};

struct hns3_udma_jetty_table {
	struct xarray			xa;
	struct hns3_udma_ida		jetty_ida;
};

struct hns3_udma_seg_table {
	struct hns3_udma_ida		seg_ida;
	struct hns3_udma_hem_table	table;
};

struct hns3_udma_num_qp {
	struct attribute attr;
	ssize_t (*show)(struct kobject *kobj,
			struct hns3_udma_num_qp *attr,
			char *buf);
	ssize_t (*store)(struct kobject *kobj,
			struct hns3_udma_num_qp *attr,
			const char *buf, size_t count);
};

#endif
