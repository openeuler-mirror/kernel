/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2018-2019 HiSilicon Limited. */
#ifndef HISI_ACC_QM_H
#define HISI_ACC_QM_H

#include <linux/bitfield.h>
#include <linux/dmapool.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#ifdef CONFIG_CRYPTO_QM_UACCE
#include <linux/uacce.h>
#endif

#include "qm_usr_if.h"

#define QNUM_V1				4096
#define QNUM_V2				1024
#define QM_MAX_VFS_NUM			63
/* qm user domain */
#define QM_ARUSER_M_CFG_1		0x100088
#define AXUSER_SNOOP_ENABLE		BIT(30)
#define AXUSER_CMD_TYPE			GENMASK(14, 12)
#define AXUSER_CMD_SMMU_NORMAL		1
#define AXUSER_NS			BIT(6)
#define AXUSER_NO			BIT(5)
#define AXUSER_FP			BIT(4)
#define AXUSER_SSV			BIT(0)
#define AXUSER_BASE			(AXUSER_SNOOP_ENABLE |		\
					FIELD_PREP(AXUSER_CMD_TYPE,	\
					AXUSER_CMD_SMMU_NORMAL) |	\
					AXUSER_NS | AXUSER_NO | AXUSER_FP)
#define QM_ARUSER_M_CFG_ENABLE		0x100090
#define ARUSER_M_CFG_ENABLE		0xfffffffe
#define QM_AWUSER_M_CFG_1		0x100098
#define QM_AWUSER_M_CFG_ENABLE		0x1000a0
#define AWUSER_M_CFG_ENABLE		0xfffffffe
#define QM_WUSER_M_CFG_ENABLE		0x1000a8
#define WUSER_M_CFG_ENABLE		0xffffffff

/* qm cache */
#define QM_CACHE_CTL			0x100050
#define SQC_CACHE_ENABLE		BIT(0)
#define CQC_CACHE_ENABLE		BIT(1)
#define SQC_CACHE_WB_ENABLE		BIT(4)
#define SQC_CACHE_WB_THRD		GENMASK(10, 5)
#define CQC_CACHE_WB_ENABLE		BIT(11)
#define CQC_CACHE_WB_THRD		GENMASK(17, 12)
#define QM_AXI_M_CFG			0x1000ac
#define AXI_M_CFG			0xffff
#define QM_AXI_M_CFG_ENABLE		0x1000b0
#define AM_CFG_SINGLE_PORT_MAX_TRANS	0x300014
#define AXI_M_CFG_ENABLE		0xffffffff
#define QM_PEH_AXUSER_CFG		0x1000cc
#define QM_PEH_AXUSER_CFG_ENABLE	0x1000d0
#define PEH_AXUSER_CFG			0x400801
#define PEH_AXUSER_CFG_ENABLE		0xffffffff

#define QM_DFX_MB_CNT_VF		0x104010
#define QM_DFX_DB_CNT_VF		0x104020

#define QM_DFX_SQE_CNT_VF_SQN		0x104030
#define QM_DFX_CQE_CNT_VF_CQN		0x104040

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
			 QM_ACC_GET_TASK_TIMEOUT | QM_DB_TIMEOUT | \
			 QM_OF_FIFO_OF)
#define QM_BASE_CE			QM_ECC_1BIT

#define HISI_ACC_SGL_SGE_NR_MAX		255
#define QM_DFX_QN_SHIFT			16

#define CURRENT_FUN_MASK		GENMASK(5, 0)
#define CURRENT_Q_MASK                  GENMASK(31, 16)

#define PCI_BAR_2			2

enum qm_stop_reason {
	QM_NORMAL,
	QM_SOFT_RESET,
	QM_FLR,
};
enum qm_state {
	QM_INIT = 0,
	QM_START,
	QM_CLOSE,
	QM_STOP,
};

enum qp_state {
	QP_INIT = 1,
	QP_START,
	QP_STOP,
	QP_CLOSE,
};

enum qm_hw_ver {
	QM_HW_UNKNOWN = -1,
	QM_HW_V1 = 0x20,
	QM_HW_V2 = 0x21,
};

enum qm_fun_type {
	QM_HW_PF,
	QM_HW_VF,
};

enum qm_debug_file {
	CURRENT_Q,
	CLEAR_ENABLE,
	QM_STATE,
	DEBUG_FILE_NUM,
};

struct debugfs_file {
	enum qm_debug_file index;
	struct mutex lock;
	struct qm_debug *debug;
};

struct qm_debug {
	u32 curr_qm_qp_num;
	struct dentry *debug_root;
	struct dentry *qm_d;
	struct debugfs_file files[DEBUG_FILE_NUM];
};

struct qm_cqe {
	__le32 rsvd0;
	__le16 cmd_id;
	__le16 rsvd1;
	__le16 sq_head;
	__le16 sq_num;
	__le16 rsvd2;
	__le16 w7;
};

struct qm_eqe {
	__le32 dw0;
};

struct qm_aeqe {
	__le32 dw0;
};

struct qm_sqc {
	__le16 head;
	__le16 tail;
	__le32 base_l;
	__le32 base_h;
	__le32 dw3;
	__le16 w8;
	__le16 rsvd0;
	__le16 pasid;
	__le16 w11;
	__le16 cq_num;
	__le16 w13;
	__le32 rsvd1;
};

struct qm_cqc {
	__le16 head;
	__le16 tail;
	__le32 base_l;
	__le32 base_h;
	__le32 dw3;
	__le16 w8;
	__le16 rsvd0;
	__le16 pasid;
	__le16 w11;
	__le32 dw6;
	__le32 rsvd1;
};

struct qm_eqc {
	__le16 head;
	__le16 tail;
	__le32 base_l;
	__le32 base_h;
	__le32 dw3;
	__le32 rsvd[2];
	__le32 dw6;
};

struct qm_aeqc {
	__le16 head;
	__le16 tail;
	__le32 base_l;
	__le32 base_h;
	__le32 dw3;
	__le32 rsvd[2];
	__le32 dw6;
};

struct qm_mailbox {
	__le16 w0;
	__le16 queue_num;
	__le32 base_l;
	__le32 base_h;
	__le32 rsvd;
};

struct qm_doorbell {
	__le16 queue_num;
	__le16 cmd;
	__le16 index;
	__le16 priority;
};

struct qm_dma {
	void *va;
	dma_addr_t dma;
	size_t size;
};

struct hisi_qm_status {
	u32 eq_head;
	bool eqc_phase;
	u32 aeq_head;
	bool aeqc_phase;
	atomic_t flags;
	int stop_reason;
};

struct hisi_qm_hw_error {
	u32 int_msk;
	const char *msg;
};

struct hisi_qm;

struct hisi_qm_err_info {
	char *acpi_rst;
	u32 msi_wr_port;
	u32 ecc_2bits_mask;
	u32 is_qm_ecc_mbit;
	u32 is_dev_ecc_mbit;
	u32 ce;
	u32 nfe;
	u32 fe;
	u32 msi;
};

struct hisi_qm_err_ini {
	u32 (*get_dev_hw_err_status)(struct hisi_qm *qm);
	void (*clear_dev_hw_err_status)(struct hisi_qm *qm, u32 err_sts);
	void (*hw_err_enable)(struct hisi_qm *qm);
	void (*hw_err_disable)(struct hisi_qm *qm);
	int (*set_usr_domain_cache)(struct hisi_qm *qm);
	void (*log_dev_hw_err)(struct hisi_qm *qm, u32 err_sts);
	void (*open_axi_master_ooo)(struct hisi_qm *qm);
	void (*close_axi_master_ooo)(struct hisi_qm *qm);
	struct hisi_qm_err_info err_info;
};

struct hisi_qm_list {
	struct mutex lock;
	struct list_head list;
	bool (*check)(struct hisi_qm *qm);
};

struct hisi_qm {
	enum qm_hw_ver ver;
	enum qm_fun_type fun_type;
	const char *dev_name;
	struct pci_dev *pdev;
	void __iomem *io_base;
	u32 sqe_size;
	u32 qp_base;
	u32 qp_num;
	u32 ctrl_q_num;
	u32 vfs_num;
	struct list_head list;
	struct hisi_qm_list *qm_list;
	struct qm_dma qdma;
	struct qm_sqc *sqc;
	struct qm_cqc *cqc;
	struct qm_eqe *eqe;
	struct qm_aeqe *aeqe;
	dma_addr_t sqc_dma;
	dma_addr_t cqc_dma;
	dma_addr_t eqe_dma;
	dma_addr_t aeqe_dma;

	struct hisi_qm_status status;
	struct hisi_qm_err_ini err_ini;
	struct rw_semaphore qps_lock;
	unsigned long *qp_bitmap;
	struct hisi_qp **qp_array;

	struct mutex mailbox_lock;

	const struct hisi_qm_hw_ops *ops;

	struct qm_debug debug;

	u32 error_mask;
	u32 msi_mask;
	unsigned long hw_status;
	bool use_uacce;		/* register to uacce */
	bool use_sva;

#ifdef CONFIG_CRYPTO_QM_UACCE
	resource_size_t phys_base;
	resource_size_t size;
	struct uacce uacce;
	const char *algs;
	void *reserve;
	int uacce_mode;
	dma_addr_t reserve_dma;
#endif
	struct workqueue_struct *wq;
	struct work_struct work;
	/* design for module not support aer, such as rde */
	int (*abnormal_fix)(struct hisi_qm *qm);
};

struct hisi_qp_status {
	atomic_t used;
	u16 sq_tail;
	u16 sq_head;
	u16 cq_head;
	bool cqc_phase;
	atomic_t flags;
};

struct hisi_qp_ops {
	int (*fill_sqe)(void *sqe, void *q_parm, void *d_parm);
};

struct hisi_qp {
	u32 qp_id;
	u8 alg_type;
	u8 req_type;
	u8 c_flag;

	struct qm_dma qdma;
	void *sqe;
	struct qm_cqe *cqe;
	dma_addr_t sqe_dma;
	dma_addr_t cqe_dma;

	struct hisi_qp_status qp_status;
	struct completion completion;
	struct hisi_qp_ops *hw_ops;
	void *qp_ctx;
	void (*req_cb)(struct hisi_qp *qp, void *data);
	void (*event_cb)(struct hisi_qp *qp);

	struct hisi_qm *qm;
	bool is_resetting;
	bool is_in_kernel;

#ifdef CONFIG_CRYPTO_QM_UACCE
	u16 pasid;
	struct uacce_queue *uacce_q;
#endif
};

static inline int q_num_set(const char *val, const struct kernel_param *kp,
			    unsigned int device)
{
	struct pci_dev *pdev = pci_get_device(PCI_VENDOR_ID_HUAWEI,
					      device, NULL);
	u32 n, q_num;
	u8 rev_id;
	int ret;

	if (!val)
		return -EINVAL;

	if (!pdev) {
		q_num = min_t(u32, QNUM_V1, QNUM_V2);
		pr_info("No device found currently, suppose queue number is %d\n",
			q_num);
	} else {
		rev_id = pdev->revision;
		switch (rev_id) {
		case QM_HW_V1:
			q_num = QNUM_V1;
			break;
		case QM_HW_V2:
			q_num = QNUM_V2;
			break;
		default:
			return -EINVAL;
		}
	}

	ret = kstrtou32(val, 10, &n);
	if (ret || !n || n > q_num)
		return -EINVAL;

	return param_set_int(val, kp);
}

static inline int vf_num_set(const char *val, const struct kernel_param *kp)
{
	u32 n;
	int ret;

	if (!val)
		return -EINVAL;

	ret = kstrtou32(val, 10, &n);
	if (ret < 0)
		return ret;

	if (n > QM_MAX_VFS_NUM)
		return -ERANGE;

	return param_set_int(val, kp);
}

#ifdef CONFIG_CRYPTO_QM_UACCE
static inline int mode_set(const char *val, const struct kernel_param *kp)
{
	u32 n;
	int ret;

	if (!val)
		return -EINVAL;

	ret = kstrtou32(val, 10, &n);
	if (ret != 0 || (n != UACCE_MODE_NOIOMMU &&
			 n != UACCE_MODE_NOUACCE))
		return -EINVAL;

	return param_set_int(val, kp);
}
#endif

static inline void hisi_qm_add_to_list(struct hisi_qm *qm,
				       struct hisi_qm_list *qm_list)
{
	mutex_lock(&qm_list->lock);
	list_add_tail(&qm->list, &qm_list->list);
	mutex_unlock(&qm_list->lock);
}

static inline void hisi_qm_del_from_list(struct hisi_qm *qm,
					 struct hisi_qm_list *qm_list)
{
	mutex_lock(&qm_list->lock);
	list_del(&qm->list);
	mutex_unlock(&qm_list->lock);
}

static inline int hisi_qm_pre_init(struct hisi_qm *qm,
				   u32 pf_q_num, u32 def_q_num)
{
	struct pci_dev *pdev = qm->pdev;

	switch (pdev->revision) {
	case QM_HW_V1:
	case QM_HW_V2:
		qm->ver = pdev->revision;
		break;
	default:
		pci_err(pdev, "hardware version err!\n");
		return -ENODEV;
	}

	pci_set_drvdata(pdev, qm);

#ifdef CONFIG_CRYPTO_QM_UACCE
	switch (qm->uacce_mode) {
	case UACCE_MODE_NOUACCE:
		qm->use_uacce = false;
		break;
	case UACCE_MODE_NOIOMMU:
		qm->use_uacce = true;
		break;
	default:
		pci_err(pdev, "uacce mode error!\n");
		return -EINVAL;
	}
#else
	qm->use_uacce = false;
#endif
	if (qm->fun_type == QM_HW_PF) {
		qm->qp_base = def_q_num;
		qm->qp_num = pf_q_num;
		qm->debug.curr_qm_qp_num = pf_q_num;
	}

	return 0;
}

void hisi_qm_free_qps(struct hisi_qp **qps, int qp_num);
int hisi_qm_alloc_qps_node(int node, struct hisi_qm_list *qm_list,
			   struct hisi_qp **qps, int qp_num, u8 alg_type);
int hisi_qm_init(struct hisi_qm *qm);
void hisi_qm_uninit(struct hisi_qm *qm);
void hisi_qm_dev_shutdown(struct pci_dev *pdev);
void hisi_qm_remove_wait_delay(struct hisi_qm *qm,
			       struct hisi_qm_list *qm_list);
int hisi_qm_start(struct hisi_qm *qm);
int hisi_qm_stop(struct hisi_qm *qm, enum qm_stop_reason r);
struct hisi_qp *hisi_qm_create_qp(struct hisi_qm *qm, u8 alg_type);
int hisi_qm_start_qp(struct hisi_qp *qp, unsigned long arg);
int hisi_qm_stop_qp(struct hisi_qp *qp);
void hisi_qm_release_qp(struct hisi_qp *qp);
int hisi_qp_send(struct hisi_qp *qp, const void *msg);
int hisi_qp_wait(struct hisi_qp *qp);
int hisi_qm_get_free_qp_num(struct hisi_qm *qm);
int hisi_qm_get_vft(struct hisi_qm *qm, u32 *base, u32 *number);
void hisi_qm_debug_regs_clear(struct hisi_qm *qm);
int hisi_qm_debug_init(struct hisi_qm *qm);
int hisi_qm_restart(struct hisi_qm *qm);
int hisi_qm_sriov_enable(struct pci_dev *pdev, int max_vfs);
int hisi_qm_sriov_disable(struct pci_dev *pdev, struct hisi_qm_list *qm_list);
void hisi_qm_dev_err_init(struct hisi_qm *qm);
void hisi_qm_dev_err_uninit(struct hisi_qm *qm);
pci_ers_result_t hisi_qm_dev_err_detected(struct pci_dev *pdev,
					  pci_channel_state_t state);
pci_ers_result_t hisi_qm_dev_slot_reset(struct pci_dev *pdev);
void hisi_qm_reset_prepare(struct pci_dev *pdev);
void hisi_qm_reset_done(struct pci_dev *pdev);
pci_ers_result_t hisi_qm_process_dev_error(struct pci_dev *pdev);
int hisi_qm_controller_reset(struct hisi_qm *qm);

struct hisi_acc_sgl_pool;
struct hisi_acc_hw_sgl *hisi_acc_sg_buf_map_to_hw_sgl(struct device *dev,
	struct scatterlist *sgl, struct hisi_acc_sgl_pool *pool,
	u32 index, dma_addr_t *hw_sgl_dma);
void hisi_acc_sg_buf_unmap(struct device *dev, struct scatterlist *sgl,
			   struct hisi_acc_hw_sgl *hw_sgl);
struct hisi_acc_sgl_pool *hisi_acc_create_sgl_pool(struct device *dev,
						   u32 count, u32 sge_nr);
void hisi_acc_free_sgl_pool(struct device *dev,
			    struct hisi_acc_sgl_pool *pool);
#endif
