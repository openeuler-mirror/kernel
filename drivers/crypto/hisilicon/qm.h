/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2018 Hisilicon Limited. */
#ifndef HISI_ACC_QM_H
#define HISI_ACC_QM_H

#include <linux/dmapool.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>

#ifdef CONFIG_CRYPTO_DEV_HISI_SPIMDEV
#include <linux/vfio_spimdev.h>
#endif
/* default queue depth for sq/cq/eq */
#define QM_Q_DEPTH			1024UL

/* qm user domain */
#define QM_ARUSER_M_CFG_1		0x100088
#define QM_ARUSER_M_CFG_ENABLE		0x100090
#define QM_AWUSER_M_CFG_1		0x100098
#define QM_AWUSER_M_CFG_ENABLE		0x1000a0
#define QM_WUSER_M_CFG_ENABLE		0x1000a8

/* qm cache */
#define QM_CACHE_CTL			0x100050
#define QM_AXI_M_CFG			0x1000ac
#define QM_AXI_M_CFG_ENABLE		0x1000b0
#define QM_PEH_AXUSER_CFG		0x1000cc
#define QM_PEH_AXUSER_CFG_ENABLE	0x1000d0

#define QP_SQE_ADDR(qp) ((qp)->scqe.addr)
#define _GET_DMA_PAGES		_IOW('d', 3, unsigned long long)
#define _PUT_DMA_PAGES		_IOW('d', 4, unsigned long long)
#define HACC_QM_SET_OPTYPE	_IOW('d', 5, unsigned long long)

#define QM_DFX_MB_CNT_VF		0x104010
#define QM_DFX_DB_CNT_VF		0x104020

#define QM_AXI_RRESP			BIT(0)
#define QM_AXI_BRESP			BIT(1)
#define QM_ECC_MBIT			BIT(2)
#define QM_ECC_1BIT			BIT(3)
#define QM_ACC_GET_TASK_TIMEOUT		BIT(4)
#define QM_ACC_DO_TASK_TIMEOUT		BIT(5)
#define QM_ACC_WB_NOT_READY_TIMEOUT	BIT(6)
#define QM_SQ_CQ_VF_INVALID		BIT(7)
#define QM_CQ_VF_INVALID		BIT(8)
#define QM_SQ_VF_INVALID		BIT(9)
#define QM_DB_TIMEOUT			BIT(10)
#define QM_OF_FIFO_OF			BIT(11)
#define QM_DB_RANDOM_INVALID		BIT(12)

#define QM_BASE_NFE	(QM_AXI_RRESP | QM_AXI_BRESP | QM_ECC_MBIT | \
			 QM_ACC_GET_TASK_TIMEOUT | QM_ACC_DO_TASK_TIMEOUT | \
			 QM_DB_TIMEOUT | QM_OF_FIFO_OF)
#define QM_BASE_CE			QM_ECC_1BIT

/* tmp fix to let hpre driver pass compiling */
enum qm_type {
	ZIP = 1,
	HPRE,
	SEC,
};

enum qm_state {
	QM_RESET,
};

enum qp_state {
	QP_STOP,
	QP_FULL,
};

enum qm_hw_ver {
	QM_HW_UNKNOWN = -1,
	QM_HW_V1 = 1,
	QM_HW_V2,
};

enum qm_fun_type {
	QM_HW_PF,
	QM_HW_VF,
};

enum qm_debug_file {
	CURRENT_Q,
	CLEAR_ENABLE,
	DEBUG_FILE_NUM,
};

struct qm_dma_buffer {
	int size;
	void *addr;
	dma_addr_t dma;
};

struct debugfs_file {
	enum qm_debug_file index;
	struct mutex lock;
	struct qm_debug *debug;
};

struct qm_debug {
	struct dentry *debug_root;
	struct dentry *qm_d;
	struct debugfs_file files[DEBUG_FILE_NUM];
};

struct hisi_qm {
	enum qm_hw_ver ver;
	enum qm_fun_type fun_type;
	const char *dev_name;
	struct pci_dev *pdev;
	void __iomem *io_base;
	struct module *parent;
	u32 sqe_size;
	u32 qp_base;
	u32 qp_num;
	unsigned long flags;

	struct qm_dma_buffer sqc, cqc, eqc, eqe, aeqc, aeqe;

	u32 eq_head;
	u32 aeq_head;

	rwlock_t qps_lock;
	unsigned long *qp_bitmap;
	struct hisi_qp **qp_array;

	struct mutex mailbox_lock;

	const struct hisi_qm_hw_ops *ops;

	struct qm_debug debug;

	u32 error_mask;
	u32 msi_mask;

	/* tmp fix to let hpre driver pass compiling */
	enum qm_type type;
	u32 free_qp;
#ifdef CONFIG_CRYPTO_DEV_HISI_SPIMDEV
	resource_size_t phys_base;
	struct vfio_spimdev spimdev;
	const struct attribute_group **mdev_dev_groups;
#endif
};

struct hisi_qp_status {
	atomic_t used;
	u16 sq_tail;
	u16 sq_head;
	u16 cq_head;
	bool cqc_phase;
	unsigned long flags;
};

struct hisi_qp_ops {
	int (*fill_sqe)(void *sqe, void *q_parm, void *d_parm);
};

#ifdef CONFIG_CRYPTO_DEV_HISI_SPIMDEV
struct qp_phy_pages {
	u64 size;
	int order;
	int node_id;
	u64 phy_addr;
};
#endif

struct hisi_qp {
	u32 qp_id;
	u8 alg_type;
	u8 req_type;

	struct qm_dma_buffer sqc;
	struct qm_dma_buffer cqc;
	struct qm_dma_buffer scqe;

	struct hisi_qp_status qp_status;
	struct completion completion;
	struct hisi_qp_ops *hw_ops;
	void *qp_ctx;
	void (*req_cb)(struct hisi_qp *qp, void *data);

	struct hisi_qm *qm;
#ifdef CONFIG_CRYPTO_DEV_HISI_SPIMDEV
	struct vfio_spimdev_queue *spimdev_q;
	struct qp_phy_pages udma_buf; /* For user space */
	void (*event_cb)(struct hisi_qp *qp);
#endif
};

int hisi_qm_init(struct hisi_qm *qm);
void hisi_qm_uninit(struct hisi_qm *qm);
int hisi_qm_mem_init(struct hisi_qm *qm);
void hisi_qm_mem_uninit(struct hisi_qm *qm);
int hisi_qm_start(struct hisi_qm *qm);
int hisi_qm_stop(struct hisi_qm *qm);
int hisi_qm_mem_start(struct hisi_qm *qm);
struct hisi_qp *hisi_qm_create_qp(struct hisi_qm *qm, u8 alg_type);
int hisi_qm_start_qp(struct hisi_qp *qp, unsigned long arg);
int hisi_qm_stop_qp(struct hisi_qp *qp);
void hisi_qm_release_qp(struct hisi_qp *qp);
int hisi_qp_send(struct hisi_qp *qp, void *msg);
int hisi_qp_wait(struct hisi_qp *qp);
int hisi_qm_get_vft(struct hisi_qm *qm, u32 *base, u32 *number);
int hisi_qm_set_vft(struct hisi_qm *qm, u32 fun_num, u32 base, u32 number);
int hisi_qm_debug_init(struct hisi_qm *qm);
void hisi_qm_hw_error_init(struct hisi_qm *qm, u32 ce, u32 nfe, u32 fe,
			   u32 msi);
int hisi_qm_hw_error_handle(struct hisi_qm *qm);
void hisi_qm_clear_queues(struct hisi_qm *qm);
enum qm_hw_ver hisi_qm_get_hw_version(struct hisi_qm *qm);
#endif
