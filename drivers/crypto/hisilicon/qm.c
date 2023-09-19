// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018-2019 HiSilicon Limited. */
#include <asm/page.h>
#include <linux/acpi.h>
#include <linux/aer.h>
#include <linux/bitmap.h>
#include <linux/debugfs.h>
#include <linux/dma-mapping.h>
#include <linux/idr.h>
#include <linux/io.h>
#include <linux/irqreturn.h>
#include <linux/log2.h>
#include <linux/seq_file.h>
#include "qm.h"

/* eq/aeq irq enable */
#define QM_VF_AEQ_INT_SOURCE		0x0
#define QM_VF_AEQ_INT_MASK		0x4
#define QM_VF_EQ_INT_SOURCE		0x8
#define QM_VF_EQ_INT_MASK		0xc
#define QM_IRQ_NUM_V1			1
#define QM_IRQ_NUM_PF_V2		4
#define QM_IRQ_NUM_VF_V2		2

/* mailbox */
#define QM_MB_CMD_SQC			0x0
#define QM_MB_CMD_CQC			0x1
#define QM_MB_CMD_EQC			0x2
#define QM_MB_CMD_AEQC			0x3
#define QM_MB_CMD_SQC_BT		0x4
#define QM_MB_CMD_CQC_BT		0x5
#define QM_MB_CMD_SQC_VFT_V2		0x6

#define QM_MB_CMD_SEND_BASE		0x300
#define QM_MB_EVENT_SHIFT		8
#define QM_MB_BUSY_SHIFT		13
#define QM_MB_OP_SHIFT			14
#define QM_MB_CMD_DATA_ADDR_L		0x304
#define QM_MB_CMD_DATA_ADDR_H		0x308

/* sqc shift */
#define QM_SQ_HOP_NUM_SHIFT		0
#define QM_SQ_PAGE_SIZE_SHIFT		4
#define QM_SQ_BUF_SIZE_SHIFT		8
#define QM_SQ_SQE_SIZE_SHIFT		12
#define QM_SQ_PRIORITY_SHIFT		0
#define QM_SQ_ORDERS_SHIFT		4
#define QM_SQ_TYPE_SHIFT		8

#define QM_SQ_TYPE_MASK			0xf

#define QM_SQ_TAIL_IDX(sqc)		((le16_to_cpu((sqc)->w11) >> 6) & 0x1)

/* cqc shift */
#define QM_CQ_HOP_NUM_SHIFT		0
#define QM_CQ_PAGE_SIZE_SHIFT		4
#define QM_CQ_BUF_SIZE_SHIFT		8
#define QM_CQ_CQE_SIZE_SHIFT		12
#define QM_CQ_PHASE_SHIFT		0
#define QM_CQ_FLAG_SHIFT		1

#define QM_CQE_PHASE(cqe)		(le16_to_cpu((cqe)->w7) & 0x1)

#define QM_QC_CQE_SIZE			4

#define QM_CQ_TAIL_IDX(cqc)		((le16_to_cpu((cqc)->w11) >> 6) & 0x1)

/* eqc shift */
#define QM_EQE_AEQE_SIZE		(2UL << 12)
#define QM_EQC_PHASE_SHIFT		16

#define QM_EQE_PHASE(eqe)		((le32_to_cpu((eqe)->dw0) >> 16) & 0x1)
#define QM_EQE_CQN_MASK			0xffff

#define QM_AEQE_PHASE(aeqe)		((le32_to_cpu((aeqe)->dw0) >> 16) & 0x1)
#define QM_AEQE_TYPE_SHIFT		17

#define QM_DOORBELL_CMD_SQ		0
#define QM_DOORBELL_CMD_CQ		1
#define QM_DOORBELL_CMD_EQ		2
#define QM_DOORBELL_CMD_AEQ		3

#define QM_DOORBELL_BASE_V1		0x340
#define QM_DOORBELL_SQ_CQ_BASE_V2	0x1000
#define QM_DOORBELL_EQ_AEQ_BASE_V2	0x2000

#define QM_MEM_START_INIT		0x100040
#define QM_MEM_INIT_DONE		0x100044
#define QM_VFT_CFG_RDY			0x10006c
#define QM_VFT_CFG_OP_WR		0x100058
#define QM_VFT_CFG_TYPE			0x10005c
#define QM_SQC_VFT			0x0
#define QM_CQC_VFT			0x1
#define QM_VFT_CFG_ADDRESS		0x100060
#define QM_VFT_CFG_OP_ENABLE		0x100054

#define QM_VFT_CFG_DATA_L		0x100064
#define QM_VFT_CFG_DATA_H		0x100068
#define QM_SQC_VFT_BUF_SIZE		(7ULL << 8)
#define QM_SQC_VFT_SQC_SIZE		(5ULL << 12)
#define QM_SQC_VFT_INDEX_NUMBER		(1ULL << 16)
#define QM_SQC_VFT_START_SQN_SHIFT	28
#define QM_SQC_VFT_VALID		(1ULL << 44)
#define QM_SQC_VFT_SQN_SHIFT		45
#define QM_CQC_VFT_BUF_SIZE		(7ULL << 8)
#define QM_CQC_VFT_SQC_SIZE		(5ULL << 12)
#define QM_CQC_VFT_INDEX_NUMBER		(1ULL << 16)
#define QM_CQC_VFT_VALID		(1ULL << 28)

#define QM_SQC_VFT_BASE_SHIFT_V2	28
#define QM_SQC_VFT_BASE_MASK_V2		0x3ff
#define QM_SQC_VFT_NUM_SHIFT_V2		45
#define QM_SQC_VFT_NUM_MASK_v2		0x3ff

#define QM_DFX_CNT_CLR_CE		0x100118
#define QM_IN_IDLE_ST_REG        0x1040e4

#define QM_ABNORMAL_INT_SOURCE		0x100000
#define QM_ABNORMAL_INT_MASK		0x100004
#define QM_HW_ERROR_IRQ_DISABLE		GENMASK(12, 0)
#define QM_ABNORMAL_INT_STATUS		0x100008
#define QM_PF_ABNORMAL_INT_SET		0x10000c
#define QM_ABNORMAL_INF00		0x100010
#define QM_FIFO_OVERFLOW_TYPE		0xc0
#define QM_FIFO_OVERFLOW_VF		0x3f
#define QM_ABNORMAL_INF01		0x100014
#define QM_DB_TIMEOUT_TYPE		0xc0
#define QM_DB_TIMEOUT_VF		0x3f
#define QM_RAS_CE_ENABLE		0x1000ec
#define QM_RAS_FE_ENABLE		0x1000f0
#define QM_RAS_NFE_ENABLE		0x1000f4
#define QM_RAS_CE_THRESHOLD		0x1000f8
#define QM_RAS_MSI_INT_SEL		0x1040f4
#define QM_ABNORMAL_INT_SOURCE_CLR	GENMASK(12, 0)

#define QM_PEH_VENDOR_ID		0x1000d8
#define VENDOR_ID_TEST_VALUE		0x5a5a
#define QM_PEH_DFX_INFO0		0x1000FC
#define PEH_SRIOV_CTRL_VF_MSE_SHIFT	3
#define PEH_MSI_DISABLE			GENMASK(31, 0)

#define QM_CACHE_WB_START		0x204
#define QM_CACHE_WB_DONE		0x208
#define QM_V2_BASE_OFFSET		0x1000

#define QM_DB_CMD_SHIFT_V1		16
#define QM_DB_INDEX_SHIFT_V1		32
#define QM_DB_PRIORITY_SHIFT_V1		48
#define QM_DB_CMD_SHIFT_V2		12
#define QM_DB_RAND_SHIFT_V2		16
#define QM_DB_INDEX_SHIFT_V2		32
#define QM_DB_PRIORITY_SHIFT_V2		48

#define QM_EQ_EVENT_IRQ_VECTOR		0
#define QM_AEQ_EVENT_IRQ_VECTOR		1
#define QM_ABNORMAL_EVENT_IRQ_VECTOR	3

#define QM_ABNORMAL_INT_MASK_VALUE	0x1fff

#define QM_SQE_DATA_ALIGN_MASK		0x7f

#define POLL_PERIOD			10
#define POLL_TIMEOUT			1000
#define TEMPBUFFER_LEN			22

#define QM_DB_TIMEOUT_TYPE_SHIFT	6
#define QM_FIFO_OVERFLOW_TYPE_SHIFT	6

#define TASK_TIMEOUT			10000

#define WAIT_PERIOD			20
#define WAIT_PERIOD_US_MAX		200
#define WAIT_PERIOD_US_MIN		100
#define REMOVE_WAIT_DELAY		10
#define MAX_WAIT_COUNTS			10000
#define QM_DEV_RESET_STATUS		0
#define QM_RESET_WAIT_TIMEOUT		400
#define QM_PCI_COMMAND_INVALID		0xFFFFFFFF
#define MASTER_GLOBAL_CTRL_SHUTDOWN	0x1
#define MASTER_TRANS_RETURN_RW		3
#define MASTER_TRANS_RETURN		0x300150
#define MASTER_GLOBAL_CTRL		0x300000
#define QM_REG_RD_INTVRL_US		10
#define QM_REG_RD_TMOUT_US		1000
#define AM_CFG_PORT_RD_EN		0x300018
#define AM_CFG_PORT_WR_EN		0x30001C
#define QM_RAS_NFE_MBIT_DISABLE		~QM_ECC_MBIT
#define AM_ROB_ECC_INT_STS		0x300104
#define ROB_ECC_ERR_MULTPL		BIT(1)

#define QM_RESET_STOP_TX_OFFSET 1
#define QM_RESET_STOP_RX_OFFSET 2

#define QM_DBG_READ_LEN 256
#define QM_DBG_WRITE_LEN 1024
#define QM_DBG_SHOW_SHIFT 16

#define QM_MK_CQC_DW3_V1(hop_num, pg_sz, buf_sz, cqe_sz) \
	(((hop_num) << QM_CQ_HOP_NUM_SHIFT)	| \
	((pg_sz) << QM_CQ_PAGE_SIZE_SHIFT)	| \
	((buf_sz) << QM_CQ_BUF_SIZE_SHIFT)	| \
	((cqe_sz) << QM_CQ_CQE_SIZE_SHIFT))
#define QM_MK_CQC_DW3_V2(cqe_sz) \
	((QM_Q_DEPTH - 1) | ((cqe_sz) << QM_CQ_CQE_SIZE_SHIFT))
#define QM_MK_SQC_W13(priority, orders, alg_type) \
	(((priority) << QM_SQ_PRIORITY_SHIFT)	| \
	((orders) << QM_SQ_ORDERS_SHIFT)	| \
	(((alg_type) & QM_SQ_TYPE_MASK) << QM_SQ_TYPE_SHIFT))
#define QM_MK_SQC_DW3_V1(hop_num, pg_sz, buf_sz, sqe_sz) \
	(((hop_num) << QM_SQ_HOP_NUM_SHIFT)	| \
	((pg_sz) << QM_SQ_PAGE_SIZE_SHIFT)	| \
	((buf_sz) << QM_SQ_BUF_SIZE_SHIFT)	| \
	((u32)ilog2(sqe_sz) << QM_SQ_SQE_SIZE_SHIFT))
#define QM_MK_SQC_DW3_V2(sqe_sz) \
	((QM_Q_DEPTH - 1) | ((u32)ilog2(sqe_sz) << QM_SQ_SQE_SIZE_SHIFT))

#define INIT_QC_COMMON(qc, base, pasid) do {			\
	(qc)->head = 0;						\
	(qc)->tail = 0;						\
	(qc)->base_l = cpu_to_le32(lower_32_bits(base));	\
	(qc)->base_h = cpu_to_le32(upper_32_bits(base));	\
	(qc)->dw3 = 0;						\
	(qc)->w8 = 0;						\
	(qc)->rsvd0 = 0;					\
	(qc)->pasid = cpu_to_le16(pasid);			\
	(qc)->w11 = 0;						\
	(qc)->rsvd1 = 0;					\
} while (0)

#define QMC_ALIGN(sz) ALIGN(sz, 32)

static int __hisi_qm_start(struct hisi_qm *qm);

enum vft_type {
	SQC_VFT = 0,
	CQC_VFT,
};

struct hisi_qm_resource {
	struct hisi_qm *qm;
	int distance;
	struct list_head list;
};

struct hisi_qm_hw_ops {
	int (*get_vft)(struct hisi_qm *qm, u32 *base, u32 *number);
	void (*qm_db)(struct hisi_qm *qm, u16 qn,
		      u8 cmd, u16 index, u8 priority);
	u32 (*get_irq_num)(struct hisi_qm *qm);
	int (*debug_init)(struct hisi_qm *qm);
	void (*hw_error_init)(struct hisi_qm *qm, u32 ce, u32 nfe, u32 fe,
			      u32 msi);
	void (*hw_error_uninit)(struct hisi_qm *qm);
	pci_ers_result_t (*hw_error_handle)(struct hisi_qm *qm);
};

struct qm_dfx_item {
	const char *name;
	u32 offset;
};

static struct qm_dfx_item qm_dfx_files[] = {
	{"qm_err_irq", offsetof(struct qm_dfx, qm_err_irq_cnt)},
	{"aeq_irq", offsetof(struct qm_dfx, aeq_irq_cnt)},
	{"abnormal_irq", offsetof(struct qm_dfx, abnormal_irq_cnt)},
	{"qp_err", offsetof(struct qm_dfx, qp_err_cnt)},
	{"mb_err", offsetof(struct qm_dfx, mb_err_cnt)},
};

static const char * const qm_debug_file_name[] = {
	[CURRENT_Q]    = "current_q",
	[CLEAR_ENABLE] = "clear_enable",
	[QM_STATE] = "qm_state",
};

static const struct hisi_qm_hw_error qm_hw_error[] = {
	{ .int_msk = BIT(0), .msg = "qm_axi_rresp" },
	{ .int_msk = BIT(1), .msg = "qm_axi_bresp" },
	{ .int_msk = BIT(2), .msg = "qm_ecc_mbit" },
	{ .int_msk = BIT(3), .msg = "qm_ecc_1bit" },
	{ .int_msk = BIT(4), .msg = "qm_acc_get_task_timeout" },
	{ .int_msk = BIT(5), .msg = "qm_acc_do_task_timeout" },
	{ .int_msk = BIT(6), .msg = "qm_acc_wb_not_ready_timeout" },
	{ .int_msk = BIT(7), .msg = "qm_sq_cq_vf_invalid" },
	{ .int_msk = BIT(8), .msg = "qm_cq_vf_invalid" },
	{ .int_msk = BIT(9), .msg = "qm_sq_vf_invalid" },
	{ .int_msk = BIT(10), .msg = "qm_db_timeout" },
	{ .int_msk = BIT(11), .msg = "qm_of_fifo_of" },
	{ .int_msk = BIT(12), .msg = "qm_db_random_invalid" },
	{ /* sentinel */ }
};

static const char * const qm_db_timeout[] = {
	"sq", "cq", "eq", "aeq",
};

static const char * const qm_fifo_overflow[] = {
	"cq", "eq", "aeq",
};

static const char * const qm_s[] = {
	"init", "start", "close", "stop",
};

static const char * const qp_s[] = {
	"none", "init", "start", "stop", "close",
};

static bool qm_avail_state(struct hisi_qm *qm, enum qm_state new)
{
	enum qm_state curr = atomic_read(&qm->status.flags);
	bool avail = false;

	switch (curr) {
	case QM_INIT:
		if (new == QM_START || new == QM_CLOSE)
			avail = true;
		break;
	case QM_START:
		if (new == QM_STOP)
			avail = true;
		break;
	case QM_STOP:
		if (new == QM_CLOSE || new == QM_START)
			avail = true;
		break;
	default:
		break;
	}
	dev_dbg(&qm->pdev->dev, "change qm state from %s to %s\n",
		qm_s[curr], qm_s[new]);
	if (!avail)
		dev_warn(&qm->pdev->dev, "Can not change qm state from %s to %s\n",
			 qm_s[curr], qm_s[new]);
	return avail;
}

static bool qm_qp_avail_state(struct hisi_qm *qm, struct hisi_qp *qp,
			      enum qp_state new)
{
	enum qm_state qm_curr = atomic_read(&qm->status.flags);
	enum qp_state qp_curr = 0;
	bool avail = false;

	if (qp)
		qp_curr = atomic_read(&qp->qp_status.flags);

	switch (new) {
	case QP_INIT:
		if (qm_curr == QM_START || qm_curr == QM_INIT)
			avail = true;
		break;
	case QP_START:
		if ((qm_curr == QM_START && qp_curr == QP_INIT) ||
		    (qm_curr == QM_START && qp_curr == QP_STOP))
			avail = true;
		break;
	case QP_STOP:
		if ((qm_curr == QM_START && qp_curr == QP_START) ||
		    (qp_curr == QP_INIT))
			avail = true;
		break;
	case QP_CLOSE:
		if ((qm_curr == QM_START && qp_curr == QP_INIT) ||
		    (qm_curr == QM_START && qp_curr == QP_STOP) ||
		    (qm_curr == QM_STOP && qp_curr == QP_STOP)  ||
		    (qm_curr == QM_STOP && qp_curr == QP_INIT))
			avail = true;
		break;
	default:
		break;
	}

	dev_dbg(&qm->pdev->dev, "change qp state from %s to %s in QM %s\n",
		qp_s[qp_curr], qp_s[new], qm_s[qm_curr]);

	if (!avail)
		dev_warn(&qm->pdev->dev,
			 "Can not change qp state from %s to %s in QM %s\n",
			 qp_s[qp_curr], qp_s[new], qm_s[qm_curr]);
	return avail;
}

/* return 0 mailbox ready, -ETIMEDOUT hardware timeout */
static int qm_wait_mb_ready(struct hisi_qm *qm)
{
	u32 val;

	return readl_relaxed_poll_timeout(qm->io_base + QM_MB_CMD_SEND_BASE,
					  val, !((val >> QM_MB_BUSY_SHIFT) &
					  0x1), POLL_PERIOD, POLL_TIMEOUT);
}

/* 128 bit should be wrote to hardware at one time to trigger a mailbox */
static void qm_mb_write(struct hisi_qm *qm, const void *src)
{
	void __iomem *fun_base = qm->io_base + QM_MB_CMD_SEND_BASE;
	unsigned long tmp0 = 0, tmp1 = 0;

	asm volatile("ldp %0, %1, %3\n"
		     "stp %0, %1, %2\n"
		     "dsb sy\n"
		     : "=&r" (tmp0),
		       "=&r" (tmp1),
		       "+Q" (*((char __iomem *)fun_base))
		     : "Q" (*((char *)src))
		     : "memory");
}

static int qm_mb(struct hisi_qm *qm, u8 cmd, dma_addr_t dma_addr, u16 queue,
		 bool op)
{
	struct qm_mailbox mailbox;
	int ret = 0;

	dev_dbg(&qm->pdev->dev, "QM mailbox request to q%u: %u\n", queue, cmd);

	mailbox.w0 = cpu_to_le16(cmd |
		     (op ? 0x1 << QM_MB_OP_SHIFT : 0) |
		     (0x1 << QM_MB_BUSY_SHIFT));
	mailbox.queue_num = cpu_to_le16(queue);
	mailbox.base_l = cpu_to_le32(lower_32_bits(dma_addr));
	mailbox.base_h = cpu_to_le32(upper_32_bits(dma_addr));
	mailbox.rsvd = 0;

	mutex_lock(&qm->mailbox_lock);

	if (unlikely(qm_wait_mb_ready(qm))) {
		ret = -EBUSY;
		dev_err(&qm->pdev->dev, "QM mailbox is busy to start!\n");
		goto busy_unlock;
	}

	qm_mb_write(qm, &mailbox);

	if (unlikely(qm_wait_mb_ready(qm))) {
		ret = -EBUSY;
		dev_err(&qm->pdev->dev, "QM mailbox operation timeout!\n");
		goto busy_unlock;
	}

busy_unlock:
	mutex_unlock(&qm->mailbox_lock);
	if (ret)
		atomic64_inc(&qm->debug.dfx.mb_err_cnt);
	return ret;
}

static void qm_db_v1(struct hisi_qm *qm, u16 qn, u8 cmd, u16 index, u8 priority)
{
	u64 doorbell;

	doorbell = qn | ((u64)cmd << QM_DB_CMD_SHIFT_V1) |
		   ((u64)index << QM_DB_INDEX_SHIFT_V1)  |
		   ((u64)priority << QM_DB_PRIORITY_SHIFT_V1);

	writeq(doorbell, qm->io_base + QM_DOORBELL_BASE_V1);
}

static void qm_db_v2(struct hisi_qm *qm, u16 qn, u8 cmd, u16 index, u8 priority)
{
	u64 doorbell;
	u64 dbase;
	u16 randata = 0;

	if (cmd == QM_DOORBELL_CMD_SQ || cmd == QM_DOORBELL_CMD_CQ)
		dbase = QM_DOORBELL_SQ_CQ_BASE_V2;
	else
		dbase = QM_DOORBELL_EQ_AEQ_BASE_V2;

	doorbell = qn | ((u64)cmd << QM_DB_CMD_SHIFT_V2) |
		   ((u64)randata << QM_DB_RAND_SHIFT_V2) |
		   ((u64)index << QM_DB_INDEX_SHIFT_V2)	 |
		   ((u64)priority << QM_DB_PRIORITY_SHIFT_V2);

	writeq(doorbell, qm->io_base + dbase);
}

static void qm_db(struct hisi_qm *qm, u16 qn, u8 cmd, u16 index, u8 priority)
{
	dev_dbg(&qm->pdev->dev, "QM doorbell request: qn=%u, cmd=%u, index=%u\n",
		qn, cmd, index);

	qm->ops->qm_db(qm, qn, cmd, index, priority);
}

/* Put qm memory into active, so that other configs become available */
static int qm_dev_mem_reset(struct hisi_qm *qm)
{
	u32 val;

	writel(0x1, qm->io_base + QM_MEM_START_INIT);
	return readl_relaxed_poll_timeout(qm->io_base + QM_MEM_INIT_DONE, val,
					  val & BIT(0), POLL_PERIOD,
					  POLL_TIMEOUT);
}

static u32 qm_get_irq_num_v1(struct hisi_qm *qm)
{
	return QM_IRQ_NUM_V1;
}

static u32 qm_get_irq_num_v2(struct hisi_qm *qm)
{
	if (qm->fun_type == QM_HW_PF)
		return QM_IRQ_NUM_PF_V2;
	else
		return QM_IRQ_NUM_VF_V2;
}

static void qm_cq_head_update(struct hisi_qp *qp)
{
	if (qp->qp_status.cq_head == QM_Q_DEPTH - 1) {
		qp->qp_status.cqc_phase = !qp->qp_status.cqc_phase;
		qp->qp_status.cq_head = 0;
	} else {
		qp->qp_status.cq_head++;
	}
}

static void qm_poll_qp(struct hisi_qp *qp, struct hisi_qm *qm)
{
	struct qm_cqe *cqe;

	if (unlikely(atomic_read(&qp->qp_status.flags) == QP_STOP))
		return;

	if (qp->event_cb)
		qp->event_cb(qp);
	else {
		cqe = qp->cqe + qp->qp_status.cq_head;

		if (qp->req_cb) {
			while (QM_CQE_PHASE(cqe) == qp->qp_status.cqc_phase) {
				dma_rmb();
				qp->req_cb(qp, qp->sqe + qm->sqe_size *
					   le16_to_cpu(cqe->sq_head));
				qm_cq_head_update(qp);
				cqe = qp->cqe + qp->qp_status.cq_head;
				qm_db(qm, qp->qp_id, QM_DOORBELL_CMD_CQ,
				      qp->qp_status.cq_head, 0);
				atomic_dec(&qp->qp_status.used);
			}
			/* set c_flag */
			qm_db(qm, qp->qp_id, QM_DOORBELL_CMD_CQ,
			      qp->qp_status.cq_head, 1);
		}
	}
}

static void qm_work_process(struct work_struct *work)
{
	struct hisi_qm *qm = container_of(work, struct hisi_qm, work);
	struct qm_eqe *eqe = qm->eqe + qm->status.eq_head;
	struct hisi_qp *qp;
	int eqe_num = 0;

	while (QM_EQE_PHASE(eqe) == qm->status.eqc_phase) {
		eqe_num++;
		qp = &qm->qp_array[le32_to_cpu(eqe->dw0) & QM_EQE_CQN_MASK];
		qm_poll_qp(qp, qm);

		if (qm->status.eq_head == QM_EQ_DEPTH - 1) {
			qm->status.eqc_phase = !qm->status.eqc_phase;
			eqe = qm->eqe;
			qm->status.eq_head = 0;
		} else {
			eqe++;
			qm->status.eq_head++;
		}

		if (eqe_num == QM_Q_DEPTH / 2 - 1) {
			eqe_num = 0;
			qm_db(qm, 0, QM_DOORBELL_CMD_EQ, qm->status.eq_head, 0);
		}
	}

	qm_db(qm, 0, QM_DOORBELL_CMD_EQ, qm->status.eq_head, 0);
}

static irqreturn_t do_qm_irq(int irq, void *data)
{
	struct hisi_qm *qm = (struct hisi_qm *)data;

	if (qm->wq)
		queue_work(qm->wq, &qm->work);
	else
		schedule_work(&qm->work);

	return IRQ_HANDLED;
}

static irqreturn_t qm_irq(int irq, void *data)
{
	struct hisi_qm *qm = data;

	if (readl(qm->io_base + QM_VF_EQ_INT_SOURCE))
		return do_qm_irq(irq, data);

	atomic64_inc(&qm->debug.dfx.qm_err_irq_cnt);
	dev_err(&qm->pdev->dev, "invalid int source\n");
	qm_db(qm, 0, QM_DOORBELL_CMD_EQ, qm->status.eq_head, 0);
	return IRQ_NONE;
}

static irqreturn_t qm_aeq_irq(int irq, void *data)
{
	struct hisi_qm *qm = data;
	struct qm_aeqe *aeqe = qm->aeqe + qm->status.aeq_head;
	u32 type;

	atomic64_inc(&qm->debug.dfx.aeq_irq_cnt);
	if (!readl(qm->io_base + QM_VF_AEQ_INT_SOURCE))
		return IRQ_NONE;

	while (QM_AEQE_PHASE(aeqe) == qm->status.aeqc_phase) {
		type = le32_to_cpu(aeqe->dw0) >> QM_AEQE_TYPE_SHIFT;
		if (type < ARRAY_SIZE(qm_fifo_overflow))
			dev_err(&qm->pdev->dev, "%s overflow\n",
				qm_fifo_overflow[type]);
		else
			dev_err(&qm->pdev->dev, "unknown error type %d\n",
				type);

		if (qm->status.aeq_head == QM_Q_DEPTH - 1) {
			qm->status.aeqc_phase = !qm->status.aeqc_phase;
			aeqe = qm->aeqe;
			qm->status.aeq_head = 0;
		} else {
			aeqe++;
			qm->status.aeq_head++;
		}

		qm_db(qm, 0, QM_DOORBELL_CMD_AEQ, qm->status.aeq_head, 0);
	}

	return IRQ_HANDLED;
}

static irqreturn_t qm_abnormal_irq(int irq, void *data)
{
	const struct hisi_qm_hw_error *err = qm_hw_error;
	struct hisi_qm *qm = data;
	struct device *dev = &qm->pdev->dev;
	u32 error_status, tmp;

	atomic64_inc(&qm->debug.dfx.abnormal_irq_cnt);
	if (qm->abnormal_fix) {
		qm->abnormal_fix(qm);
		return IRQ_HANDLED;
	}

	/* read err sts */
	tmp = readl(qm->io_base + QM_ABNORMAL_INT_STATUS);
	error_status = qm->msi_mask & tmp;

	while (err->msg) {
		if (err->int_msk & error_status)
			dev_err(dev, "%s [error status=0x%x] found\n",
				 err->msg, err->int_msk);

		err++;
	}

	/* clear err sts */
	writel(error_status, qm->io_base + QM_ABNORMAL_INT_SOURCE);

	return IRQ_HANDLED;
}

static int qm_irq_register(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;
	int ret;

	ret = request_irq(pci_irq_vector(pdev, QM_EQ_EVENT_IRQ_VECTOR),
				   qm_irq, IRQF_SHARED,
				   qm->dev_name, qm);
	if (ret)
		return ret;

	if (qm->ver == QM_HW_V2) {
		ret = request_irq(pci_irq_vector(pdev, QM_AEQ_EVENT_IRQ_VECTOR),
				  qm_aeq_irq, IRQF_SHARED, qm->dev_name, qm);
		if (ret)
			goto err_aeq_irq;

		if (qm->fun_type == QM_HW_PF) {
			ret = request_irq(pci_irq_vector(pdev,
					  QM_ABNORMAL_EVENT_IRQ_VECTOR),
					  qm_abnormal_irq, IRQF_SHARED,
					  qm->dev_name, qm);
			if (ret)
				goto err_abonormal_irq;
		}
	}

	return 0;

err_abonormal_irq:
	free_irq(pci_irq_vector(pdev, QM_AEQ_EVENT_IRQ_VECTOR), qm);
err_aeq_irq:
	free_irq(pci_irq_vector(pdev, QM_EQ_EVENT_IRQ_VECTOR), qm);
	return ret;
}

static void qm_irq_unregister(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;

	free_irq(pci_irq_vector(pdev, QM_EQ_EVENT_IRQ_VECTOR), qm);

	if (qm->ver == QM_HW_V2) {
		free_irq(pci_irq_vector(pdev, QM_AEQ_EVENT_IRQ_VECTOR), qm);

		if (qm->fun_type == QM_HW_PF)
			free_irq(pci_irq_vector(pdev,
				 QM_ABNORMAL_EVENT_IRQ_VECTOR), qm);
	}
}

static void qm_init_qp_status(struct hisi_qp *qp)
{
	struct hisi_qp_status *qp_status = &qp->qp_status;

	qp_status->sq_tail = 0;
	qp_status->cq_head = 0;
	qp_status->cqc_phase = true;
	atomic_set(&qp_status->used, 0);
	atomic_set(&qp_status->send_ref, 0);
}

static void qm_vft_data_cfg(struct hisi_qm *qm, enum vft_type type, u32 base,
			    u32 number)
{
	u64 tmp = 0;

	if (number > 0) {
		switch (type) {
		case SQC_VFT:
			switch (qm->ver) {
			case QM_HW_V1:
				tmp = QM_SQC_VFT_BUF_SIZE |
				      QM_SQC_VFT_SQC_SIZE |
				      QM_SQC_VFT_INDEX_NUMBER |
				      QM_SQC_VFT_VALID |
				      (u64)base << QM_SQC_VFT_START_SQN_SHIFT;
				break;
			case QM_HW_V2:
				tmp = (u64)base << QM_SQC_VFT_START_SQN_SHIFT |
				      QM_SQC_VFT_VALID |
				      (u64)(number - 1) << QM_SQC_VFT_SQN_SHIFT;
				break;
			case QM_HW_UNKNOWN:
				break;
			}
			break;
		case CQC_VFT:
			switch (qm->ver) {
			case QM_HW_V1:
				tmp = QM_CQC_VFT_BUF_SIZE |
				      QM_CQC_VFT_SQC_SIZE |
				      QM_CQC_VFT_INDEX_NUMBER |
				      QM_CQC_VFT_VALID;
				break;
			case QM_HW_V2:
				tmp = QM_CQC_VFT_VALID;
				break;
			case QM_HW_UNKNOWN:
				break;
			}
			break;
		}
	}

	writel(lower_32_bits(tmp), qm->io_base + QM_VFT_CFG_DATA_L);
	writel(upper_32_bits(tmp), qm->io_base + QM_VFT_CFG_DATA_H);
}

static int qm_set_vft_common(struct hisi_qm *qm, enum vft_type type,
			     u32 fun_num, u32 base, u32 number)
{
	int ret;
	unsigned int val;

	ret = readl_relaxed_poll_timeout(qm->io_base + QM_VFT_CFG_RDY, val,
					 val & BIT(0), POLL_PERIOD,
					 POLL_TIMEOUT);
	if (ret)
		return ret;

	writel(0x0, qm->io_base + QM_VFT_CFG_OP_WR);
	writel(type, qm->io_base + QM_VFT_CFG_TYPE);
	writel(fun_num, qm->io_base + QM_VFT_CFG_ADDRESS);

	qm_vft_data_cfg(qm, type, base, number);

	writel(0x0, qm->io_base + QM_VFT_CFG_RDY);
	writel(0x1, qm->io_base + QM_VFT_CFG_OP_ENABLE);

	return readl_relaxed_poll_timeout(qm->io_base + QM_VFT_CFG_RDY, val,
					  val & BIT(0), POLL_PERIOD,
					  POLL_TIMEOUT);
}

/* The config should be conducted after qm_dev_mem_reset() */
static int qm_set_sqc_cqc_vft(struct hisi_qm *qm, u32 fun_num, u32 base,
			      u32 number)
{
	int ret, i;

	for (i = SQC_VFT; i <= CQC_VFT; i++) {
		ret = qm_set_vft_common(qm, i, fun_num, base, number);
		if (ret)
			return ret;
	}

	return 0;
}

static int qm_get_vft_v2(struct hisi_qm *qm, u32 *base, u32 *number)
{
	u64 sqc_vft;
	int ret;

	ret = qm_mb(qm, QM_MB_CMD_SQC_VFT_V2, 0, 0, 1);
	if (ret)
		return ret;

	sqc_vft = readl(qm->io_base + QM_MB_CMD_DATA_ADDR_L) |
		  ((u64)readl(qm->io_base + QM_MB_CMD_DATA_ADDR_H) << 32);
	*base = QM_SQC_VFT_BASE_MASK_V2 & (sqc_vft >> QM_SQC_VFT_BASE_SHIFT_V2);
	*number = (QM_SQC_VFT_NUM_MASK_v2 &
		  (sqc_vft >> QM_SQC_VFT_NUM_SHIFT_V2)) + 1;

	return 0;
}

static struct hisi_qm *file_to_qm(struct debugfs_file *file)
{
	struct qm_debug *debug = file->debug;

	return container_of(debug, struct hisi_qm, debug);
}

static u32 current_q_read(struct debugfs_file *file)
{
	struct hisi_qm *qm = file_to_qm(file);

	return (readl(qm->io_base + QM_DFX_SQE_CNT_VF_SQN) >> QM_DFX_QN_SHIFT);
}

static int current_q_write(struct debugfs_file *file, u32 val)
{
	struct hisi_qm *qm = file_to_qm(file);
	u32 tmp;

	if (val >= qm->debug.curr_qm_qp_num)
		return -EINVAL;

	tmp = val << QM_DFX_QN_SHIFT |
	      (readl(qm->io_base + QM_DFX_SQE_CNT_VF_SQN) & CURRENT_FUN_MASK);
	writel(tmp, qm->io_base + QM_DFX_SQE_CNT_VF_SQN);

	tmp = val << QM_DFX_QN_SHIFT |
	      (readl(qm->io_base + QM_DFX_CQE_CNT_VF_CQN) & CURRENT_FUN_MASK);
	writel(tmp, qm->io_base + QM_DFX_CQE_CNT_VF_CQN);

	return 0;
}

static u32 clear_enable_read(struct debugfs_file *file)
{
	struct hisi_qm *qm = file_to_qm(file);

	return readl(qm->io_base + QM_DFX_CNT_CLR_CE);
}

/* rd_clr_ctrl 1 enable read clear, otherwise 0 disable it */
static int clear_enable_write(struct debugfs_file *file, u32 rd_clr_ctrl)
{
	struct hisi_qm *qm = file_to_qm(file);

	if (rd_clr_ctrl > 1)
		return -EINVAL;

	writel(rd_clr_ctrl, qm->io_base + QM_DFX_CNT_CLR_CE);

	return 0;
}

static u32 qm_state_read(struct debugfs_file *file)
{
	struct hisi_qm *qm = file_to_qm(file);

	return readl(qm->io_base + QM_IN_IDLE_ST_REG);
}

static ssize_t qm_debug_read(struct file *filp, char __user *buf,
			     size_t count, loff_t *pos)
{
	struct debugfs_file *file = filp->private_data;
	enum qm_debug_file index = file->index;
	char tbuf[TEMPBUFFER_LEN];
	u32 val;
	int ret;

	mutex_lock(&file->lock);
	switch (index) {
	case CURRENT_Q:
		val = current_q_read(file);
		break;
	case CLEAR_ENABLE:
		val = clear_enable_read(file);
		break;
	case QM_STATE:
		val = qm_state_read(file);
		break;
	default:
		mutex_unlock(&file->lock);
		return -EINVAL;
	}
	mutex_unlock(&file->lock);
	ret = snprintf(tbuf, TEMPBUFFER_LEN, "%u\n", val);

	return simple_read_from_buffer(buf, count, pos, tbuf, ret);
}

static ssize_t qm_debug_write(struct file *filp, const char __user *buf,
			      size_t count, loff_t *pos)
{
	struct debugfs_file *file = filp->private_data;
	enum qm_debug_file index = file->index;
	unsigned long val;
	char tbuf[TEMPBUFFER_LEN];
	int len, ret;

	if (*pos != 0)
		return 0;

	if (count >= TEMPBUFFER_LEN)
		return -ENOSPC;

	len = simple_write_to_buffer(tbuf, TEMPBUFFER_LEN - 1, pos, buf, count);
	if (len < 0)
		return len;

	tbuf[len] = '\0';
	if (kstrtoul(tbuf, 0, &val))
		return -EFAULT;

	mutex_lock(&file->lock);
	switch (index) {
	case CURRENT_Q:
		ret = current_q_write(file, val);
		if (ret)
			goto err_input;
		break;
	case CLEAR_ENABLE:
		ret = clear_enable_write(file, val);
		if (ret)
			goto err_input;
		break;
	default:
		ret = -EINVAL;
		goto err_input;
	}
	mutex_unlock(&file->lock);

	return count;

err_input:
	mutex_unlock(&file->lock);
	return ret;
}

static const struct file_operations qm_debug_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = qm_debug_read,
	.write = qm_debug_write,
};

struct qm_dfx_registers {
	char  *reg_name;
	u64   reg_offset;
};

static struct qm_dfx_registers qm_dfx_regs[] = {
	/* these regs are read clear */
	{"QM_ECC_1BIT_CNT               ",  0x104000ull},
	{"QM_ECC_MBIT_CNT               ",  0x104008ull},
	{"QM_DFX_MB_CNT                 ",  0x104018ull},
	{"QM_DFX_DB_CNT                 ",  0x104028ull},
	{"QM_DFX_SQE_CNT                ",  0x104038ull},
	{"QM_DFX_CQE_CNT                ",  0x104048ull},
	{"QM_DFX_SEND_SQE_TO_ACC_CNT    ",  0x104050ull},
	{"QM_DFX_WB_SQE_FROM_ACC_CNT    ",  0x104058ull},
	{"QM_DFX_ACC_FINISH_CNT         ",  0x104060ull},
	{"QM_DFX_CQE_ERR_CNT            ",  0x1040b4ull},

	{"QM_DFX_FUNS_ACTIVE_ST         ",  0x200ull},
	{"QM_ECC_1BIT_INF               ",  0x104004ull},
	{"QM_ECC_MBIT_INF               ",  0x10400cull},
	{"QM_DFX_ACC_RDY_VLD0           ",  0x1040a0ull},
	{"QM_DFX_ACC_RDY_VLD1           ",  0x1040a4ull},
	{"QM_DFX_AXI_RDY_VLD            ",  0x1040a8ull},
	{"QM_DFX_FF_ST0                 ",  0x1040c8ull},
	{"QM_DFX_FF_ST1                 ",  0x1040ccull},
	{"QM_DFX_FF_ST2                 ",  0x1040d0ull},
	{"QM_DFX_FF_ST3                 ",  0x1040d4ull},
	{"QM_DFX_FF_ST4                 ",  0x1040d8ull},
	{"QM_DFX_FF_ST5                 ",  0x1040dcull},
	{"QM_DFX_FF_ST6                 ",  0x1040e0ull},
	{"QM_IN_IDLE_ST                 ",  0x1040e4ull},
	{ NULL, 0}
};

static struct qm_dfx_registers qm_vf_dfx_regs[] = {
	{"QM_DFX_FUNS_ACTIVE_ST         ",  0x200ull},
	{ NULL, 0}
};

static int qm_regs_show(struct seq_file *s, void *unused)
{
	struct hisi_qm *qm = s->private;
	struct qm_dfx_registers *regs;
	u32 val;

	if (qm->fun_type == QM_HW_PF)
		regs = qm_dfx_regs;
	else
		regs = qm_vf_dfx_regs;

	while (regs->reg_name) {
		val = readl(qm->io_base + regs->reg_offset);
		seq_printf(s, "%s= 0x%08x\n", regs->reg_name, val);
		regs++;
	}

	return 0;
}

static int qm_regs_open(struct inode *inode, struct file *file)
{
	return single_open(file, qm_regs_show, inode->i_private);
}

static const struct file_operations qm_regs_fops = {
	.owner = THIS_MODULE,
	.open = qm_regs_open,
	.read = seq_read,
	.release = single_release,
};

static ssize_t qm_cmd_read(struct file *filp, char __user *buffer,
			   size_t count, loff_t *pos)
{
	char buf[QM_DBG_READ_LEN];
	int uncopy_bytes, len;

	if (*pos)
		return 0;

	if (count < QM_DBG_READ_LEN)
		return -ENOSPC;

	len = snprintf(buf, QM_DBG_READ_LEN, "%s\n",
		       "Please echo help to cmd to get help information");

	uncopy_bytes = copy_to_user(buffer, buf, len);
	if (uncopy_bytes)
		return -EFAULT;

	return (*pos = len);
}

static void *qm_ctx_alloc(struct hisi_qm *qm, size_t ctx_size,
			  dma_addr_t *dma_addr)
{
	struct device *dev = &qm->pdev->dev;
	void *ctx_addr;

	ctx_addr = kzalloc(ctx_size, GFP_KERNEL);
	if (!ctx_addr)
		return ERR_PTR(-ENOMEM);

	*dma_addr = dma_map_single(dev, ctx_addr, ctx_size, DMA_FROM_DEVICE);
	if (dma_mapping_error(dev, *dma_addr)) {
		dev_err(dev, "DMA mapping error!\n");
		kfree(ctx_addr);
		return ERR_PTR(-ENOMEM);
	}

	return ctx_addr;
}

static void qm_ctx_free(struct hisi_qm *qm, size_t ctx_size,
			const void *ctx_addr, dma_addr_t *dma_addr)
{
	struct device *dev = &qm->pdev->dev;

	dma_unmap_single(dev, *dma_addr, ctx_size, DMA_FROM_DEVICE);
	kfree(ctx_addr);
}

static int dump_show(struct hisi_qm *qm, void *info,
		     unsigned int info_size, char *info_name)
{
	struct device *dev = &qm->pdev->dev;
	u8 *info_curr = info;
	u8 *info_buf;
	u32 i;
#define BYTE_PER_DW	4

	info_buf = kzalloc(info_size, GFP_KERNEL);
	if (!info_buf)
		return -ENOMEM;

	for (i = 0; i < info_size; i++, info_curr++) {
		if (i % BYTE_PER_DW == 0)
			info_buf[i + 3UL] = *info_curr;
		else if (i % BYTE_PER_DW == 1)
			info_buf[i + 1UL] = *info_curr;
		else if (i % BYTE_PER_DW == 2)
			info_buf[i - 1] = *info_curr;
		else if (i % BYTE_PER_DW == 3)
			info_buf[i - 3] = *info_curr;
	}

	dev_info(dev, "%s DUMP\n", info_name);
	for (i = 0; i < info_size; i += BYTE_PER_DW) {
		pr_info("DW%d: %02X%02X %02X%02X\n", i / BYTE_PER_DW,
			info_buf[i], info_buf[i + 1UL],
			info_buf[i + 2UL], info_buf[i + 3UL]);
	}

	kfree(info_buf);
	return 0;
}

static int qm_dump_sqc_raw(struct hisi_qm *qm, dma_addr_t dma_addr, u16 qp_id)
{
	return qm_mb(qm, QM_MB_CMD_SQC, dma_addr, qp_id, 1);
}

static int qm_dump_cqc_raw(struct hisi_qm *qm, dma_addr_t dma_addr, u16 qp_id)
{
	return qm_mb(qm, QM_MB_CMD_CQC, dma_addr, qp_id, 1);
}

static int qm_sqc_dump(struct hisi_qm *qm, const char *s)
{
	struct device *dev = &qm->pdev->dev;
	struct qm_sqc *sqc, *sqc_curr;
	dma_addr_t sqc_dma;
	u32 qp_id;
	int ret;

	if (!s)
		return -EINVAL;

	ret = kstrtou32(s, 0, &qp_id);
	if (ret || qp_id >= qm->qp_num) {
		dev_err(dev, "Please input qp num (0-%d)", qm->qp_num - 1);
		return -EINVAL;
	}

	sqc = qm_ctx_alloc(qm, sizeof(struct qm_sqc), &sqc_dma);
	if (IS_ERR(sqc))
		return PTR_ERR(sqc);

	ret = qm_dump_sqc_raw(qm, sqc_dma, qp_id);
	if (ret) {
		down_read(&qm->qps_lock);
		if (qm->sqc) {
			sqc_curr = qm->sqc + qp_id;

			ret = dump_show(qm, sqc_curr, sizeof(struct qm_sqc),
					"SOFT SQC");
			if (ret)
				dev_info(dev, "Show soft sqc failed!\n");
		}
		up_read(&qm->qps_lock);

		goto mailbox_fail;
	}

	ret = dump_show(qm, sqc, sizeof(struct qm_sqc), "SQC");
	if (ret)
		dev_info(dev, "Show hw sqc failed!\n");

mailbox_fail:
	qm_ctx_free(qm, sizeof(struct qm_sqc), sqc, &sqc_dma);
	return ret;
}

static int qm_cqc_dump(struct hisi_qm *qm, const char *s)
{
	struct device *dev = &qm->pdev->dev;
	struct qm_cqc *cqc, *cqc_curr;
	dma_addr_t cqc_dma;
	u32 qp_id;
	int ret;

	if (!s)
		return -EINVAL;

	ret = kstrtou32(s, 0, &qp_id);
	if (ret || qp_id >= qm->qp_num) {
		dev_err(dev, "Please input qp num (0-%d)", qm->qp_num - 1);
		return -EINVAL;
	}

	cqc = qm_ctx_alloc(qm, sizeof(struct qm_cqc), &cqc_dma);
	if (IS_ERR(cqc))
		return PTR_ERR(cqc);

	ret = qm_dump_cqc_raw(qm, cqc_dma, qp_id);
	if (ret) {
		down_read(&qm->qps_lock);
		if (qm->cqc) {
			cqc_curr = qm->cqc + qp_id;

			ret = dump_show(qm, cqc_curr, sizeof(struct qm_cqc),
					"SOFT CQC");
			if (ret)
				dev_info(dev, "Show soft cqc failed!\n");
		}
		up_read(&qm->qps_lock);

		goto mailbox_fail;
	}

	ret = dump_show(qm, cqc, sizeof(struct qm_cqc), "CQC");
	if (ret)
		dev_info(dev, "Show hw cqc failed!\n");

mailbox_fail:
	qm_ctx_free(qm, sizeof(struct qm_cqc), cqc, &cqc_dma);
	return ret;
}

static int qm_eqc_dump(struct hisi_qm *qm, char *s)
{
	struct device *dev = &qm->pdev->dev;
	struct qm_eqc *eqc;
	dma_addr_t eqc_dma;
	int ret;

	if (strsep(&s, " ")) {
		dev_err(dev, "Please do not input extra characters!\n");
		return -EINVAL;
	}

	eqc = qm_ctx_alloc(qm, sizeof(struct qm_eqc), &eqc_dma);
	if (IS_ERR(eqc))
		return PTR_ERR(eqc);

	ret = qm_mb(qm, QM_MB_CMD_EQC, eqc_dma, 0, 1);
	if (ret)
		goto mailbox_fail;

	ret = dump_show(qm, eqc, sizeof(struct qm_eqc), "EQC");
	if (ret)
		dev_info(dev, "Show eqc failed!\n");

mailbox_fail:
	qm_ctx_free(qm, sizeof(struct qm_eqc), eqc, &eqc_dma);
	return ret;
}

static int qm_aeqc_dump(struct hisi_qm *qm, char *s)
{
	struct device *dev = &qm->pdev->dev;
	struct qm_aeqc *aeqc;
	dma_addr_t aeqc_dma;
	int ret;

	if (strsep(&s, " ")) {
		dev_err(dev, "Please do not input extra characters!\n");
		return -EINVAL;
	}

	aeqc = qm_ctx_alloc(qm, sizeof(struct qm_aeqc), &aeqc_dma);
	if (IS_ERR(aeqc))
		return PTR_ERR(aeqc);

	ret = qm_mb(qm, QM_MB_CMD_AEQC, aeqc_dma, 0, 1);
	if (ret)
		goto mailbox_fail;

	ret = dump_show(qm, aeqc, sizeof(struct qm_aeqc), "AEQC");
	if (ret)
		dev_info(dev, "Show hw aeqc failed!\n");

mailbox_fail:
	qm_ctx_free(qm, sizeof(struct qm_aeqc), aeqc, &aeqc_dma);
	return ret;
}

static int q_dump_param_parse(struct hisi_qm *qm, char *s,
			      u32 *e_id, u32 *q_id)
{
	struct device *dev = &qm->pdev->dev;
	unsigned int qp_num = qm->qp_num;
	char *presult;
	int ret;

	presult = strsep(&s, " ");
	if (!presult) {
		dev_err(dev, "Please input qp number!\n");
		return -EINVAL;
	}

	ret = kstrtou32(presult, 0, q_id);
	if (ret || *q_id >= qp_num) {
		dev_err(dev, "Please input qp num (0-%d)", qp_num - 1);
		return -EINVAL;
	}

	presult = strsep(&s, " ");
	if (!presult) {
		dev_err(dev, "Please input sqe number!\n");
		return -EINVAL;
	}

	ret = kstrtou32(presult, 0, e_id);
	if (ret || *e_id >= QM_Q_DEPTH) {
		dev_err(dev, "Please input sqe num (0-%d)", QM_Q_DEPTH - 1);
		return -EINVAL;
	}

	if (strsep(&s, " ")) {
		dev_err(dev, "Please do not input extra characters!\n");
		return -EINVAL;
	}

	return 0;
}

static int qm_sq_dump(struct hisi_qm *qm, char *s)
{
	struct device *dev = &qm->pdev->dev;
	struct hisi_qp *qp;
	u32 qp_id, sqe_id;
	void *sqe_curr;
	int ret;

	ret = q_dump_param_parse(qm, s, &sqe_id, &qp_id);
	if (ret)
		return ret;

	qp = &qm->qp_array[qp_id];
	sqe_curr = qp->sqe + (u32)(sqe_id * qm->sqe_size);
	memset(sqe_curr + qm->debug.sqe_mask_offset, SQE_ADDR_MASK,
	       qm->debug.sqe_mask_len);

	ret = dump_show(qm, sqe_curr, qm->sqe_size, "SQE");
	if (ret)
		dev_info(dev, "Show sqe failed!\n");

	return ret;
}

static int qm_cq_dump(struct hisi_qm *qm, char *s)
{
	struct device *dev = &qm->pdev->dev;
	struct qm_cqe *cqe_curr;
	struct hisi_qp *qp;
	u32 qp_id, cqe_id;
	int ret;

	ret = q_dump_param_parse(qm, s, &cqe_id, &qp_id);
	if (ret)
		return ret;

	qp = &qm->qp_array[qp_id];
	cqe_curr = qp->cqe + cqe_id;
	ret = dump_show(qm, cqe_curr, sizeof(struct qm_cqe), "CQE");
	if (ret)
		dev_info(dev, "Show cqe failed!\n");

	return ret;
}

static int qm_eq_dump(struct hisi_qm *qm, const char *s)
{
	struct device *dev = &qm->pdev->dev;
	struct qm_eqe *eqe;
	u32 eqe_id;
	int ret;

	if (!s)
		return -EINVAL;

	ret = kstrtou32(s, 0, &eqe_id);
	if (ret || eqe_id >= QM_EQ_DEPTH) {
		dev_err(dev, "Please input eqe num (0-%d)", QM_EQ_DEPTH - 1);
		return -EINVAL;
	}

	down_read(&qm->qps_lock);
	if (qm->eqe) {
		eqe = qm->eqe + eqe_id;
		ret = dump_show(qm, eqe, sizeof(struct qm_eqe), "EQE");
		if (ret)
			dev_info(dev, "Show eqe failed!\n");
	}
	up_read(&qm->qps_lock);

	return ret;
}

static int qm_aeq_dump(struct hisi_qm *qm, const char *s)
{
	struct device *dev = &qm->pdev->dev;
	struct qm_aeqe *aeqe;
	u32 aeqe_id;
	int ret;

	if (!s)
		return -EINVAL;

	ret = kstrtou32(s, 0, &aeqe_id);
	if (ret || aeqe_id >= QM_Q_DEPTH) {
		dev_err(dev, "Please input aeqe num (0-%d)", QM_Q_DEPTH - 1);
		return -EINVAL;
	}

	down_read(&qm->qps_lock);
	if (qm->aeqe) {
		aeqe = qm->aeqe + aeqe_id;
		ret = dump_show(qm, aeqe, sizeof(struct qm_aeqe), "AEQE");
		if (ret)
			dev_info(dev, "Show aeqe failed!\n");
	}
	up_read(&qm->qps_lock);

	return ret;
}

static int qm_dbg_help(struct hisi_qm *qm, char *s)
{
	struct device *dev = &qm->pdev->dev;

	if (strsep(&s, " ")) {
		dev_err(dev, "Please do not input extra characters!\n");
		return -EINVAL;
	}

	dev_info(dev, "available commands\n");
	dev_info(dev, "sqc <num>\n");
	dev_info(dev, "cqc <num>\n");
	dev_info(dev, "eqc\n");
	dev_info(dev, "aeqc\n");
	dev_info(dev, "sq <num> <e>\n");
	dev_info(dev, "cq <num> <e>\n");
	dev_info(dev, "eq <e>\n");
	dev_info(dev, "aeq <e>\n");

	return 0;
}

static int qm_cmd_write_dump(struct hisi_qm *qm, const char *cmd_buf)
{
	struct device *dev = &qm->pdev->dev;
	char *presult, *s, *s_tmp;
	int ret;

	s = kstrdup(cmd_buf, GFP_KERNEL);
	if (!s)
		return -ENOMEM;

	s_tmp = s;
	presult = strsep(&s, " ");
	if (!presult) {
		kfree(s_tmp);
		return -EINVAL;
	}

	if (!strcmp(presult, "sqc"))
		ret = qm_sqc_dump(qm, s);
	else if (!strcmp(presult, "cqc"))
		ret = qm_cqc_dump(qm, s);
	else if (!strcmp(presult, "eqc"))
		ret = qm_eqc_dump(qm, s);
	else if (!strcmp(presult, "aeqc"))
		ret = qm_aeqc_dump(qm, s);
	else if (!strcmp(presult, "sq"))
		ret = qm_sq_dump(qm, s);
	else if (!strcmp(presult, "cq"))
		ret = qm_cq_dump(qm, s);
	else if (!strcmp(presult, "eq"))
		ret = qm_eq_dump(qm, s);
	else if (!strcmp(presult, "aeq"))
		ret = qm_aeq_dump(qm, s);
	else if (!strcmp(presult, "help"))
		ret = qm_dbg_help(qm, s);
	else
		ret = -EINVAL;

	if (ret)
		dev_info(dev, "Please echo help\n");

	kfree(s_tmp);

	return ret;
}

static ssize_t qm_cmd_write(struct file *filp, const char __user *buffer,
			    size_t count, loff_t *pos)
{
	struct hisi_qm *qm = filp->private_data;
	char *cmd_buf, *cmd_buf_tmp;
	int uncopied_bytes;
	int ret;

	if (*pos)
		return 0;

	/* Judge if the instance is being reset. */
	if (unlikely(atomic_read(&qm->status.flags) == QM_STOP))
		return 0;

	if (count > QM_DBG_WRITE_LEN)
		return -ENOSPC;

	cmd_buf = kzalloc(count + 1, GFP_KERNEL);
	if (!cmd_buf)
		return -ENOMEM;

	uncopied_bytes = copy_from_user(cmd_buf, buffer, count);
	if (uncopied_bytes) {
		kfree(cmd_buf);
		return -EFAULT;
	}

	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = cmd_buf_tmp - cmd_buf + 1;
	}

	ret = qm_cmd_write_dump(qm, cmd_buf);
	if (ret) {
		kfree(cmd_buf);
		return ret;
	}

	kfree(cmd_buf);
	return count;
}

static const struct file_operations qm_cmd_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = qm_cmd_read,
	.write = qm_cmd_write,
};

static int qm_create_debugfs_file(struct hisi_qm *qm, enum qm_debug_file index)
{
	struct dentry *qm_d = qm->debug.qm_d, *tmp;
	struct debugfs_file *file = qm->debug.files + index;

	tmp = debugfs_create_file(qm_debug_file_name[index], 0600, qm_d, file,
				  &qm_debug_fops);
	if (IS_ERR(tmp))
		return -ENOENT;

	file->index = index;
	mutex_init(&file->lock);
	file->debug = &qm->debug;

	return 0;
}

static void qm_hw_error_init_v1(struct hisi_qm *qm, u32 ce, u32 nfe, u32 fe,
				u32 msi)
{
	dev_info(&qm->pdev->dev,
		 "QM v%d does not support hw error handle\n", qm->ver);

	writel(QM_ABNORMAL_INT_MASK_VALUE, qm->io_base + QM_ABNORMAL_INT_MASK);
}

static void qm_hw_error_init_v2(struct hisi_qm *qm, u32 ce, u32 nfe, u32 fe,
				u32 msi)
{
	u32 irq_enable = ce | nfe | fe | msi;
	u32 irq_unmask = ~irq_enable;
	u32 error_status;

	qm->error_mask = ce | nfe | fe;
	qm->msi_mask = msi;

	/* clear QM hw residual error source */
	error_status = readl(qm->io_base + QM_ABNORMAL_INT_STATUS);
	if (!(qm->hw_status & BIT(QM_DEV_RESET_STATUS))
		|| !error_status)
		error_status = QM_ABNORMAL_INT_SOURCE_CLR;
	else
		error_status &= qm->error_mask;

	writel(error_status, qm->io_base + QM_ABNORMAL_INT_SOURCE);

	/* configure error type */
	writel(ce, qm->io_base + QM_RAS_CE_ENABLE);
	writel(0x1, qm->io_base + QM_RAS_CE_THRESHOLD);
	writel(nfe, qm->io_base + QM_RAS_NFE_ENABLE);
	writel(fe, qm->io_base + QM_RAS_FE_ENABLE);

	/* use RAS irq default, so only set QM_RAS_MSI_INT_SEL for MSI */
	writel(msi, qm->io_base + QM_RAS_MSI_INT_SEL);

	irq_unmask &= readl(qm->io_base + QM_ABNORMAL_INT_MASK);
	writel(irq_unmask, qm->io_base + QM_ABNORMAL_INT_MASK);
}

static void qm_hw_error_uninit_v2(struct hisi_qm *qm)
{
	writel(QM_HW_ERROR_IRQ_DISABLE, qm->io_base + QM_ABNORMAL_INT_MASK);
}

static void qm_log_hw_error(struct hisi_qm *qm, u32 error_status)
{
	const struct hisi_qm_hw_error *err;
	struct device *dev = &qm->pdev->dev;
	u32 reg_val, type, vf_num;
	int i;

	for (i = 0; i < ARRAY_SIZE(qm_hw_error); i++) {
		err = &qm_hw_error[i];
		if (!(err->int_msk & error_status))
			continue;

		dev_err(dev, "%s [error status=0x%x] found\n",
			 err->msg, err->int_msk);

		if (err->int_msk & QM_DB_TIMEOUT) {
			reg_val = readl(qm->io_base +
					QM_ABNORMAL_INF01);
			type = (reg_val & QM_DB_TIMEOUT_TYPE) >>
			       QM_DB_TIMEOUT_TYPE_SHIFT;
			vf_num = reg_val & QM_DB_TIMEOUT_VF;
			dev_err(dev, "qm %s doorbell timeout in function %u\n",
				 qm_db_timeout[type], vf_num);
		} else if (err->int_msk & QM_OF_FIFO_OF) {
			reg_val = readl(qm->io_base +
					QM_ABNORMAL_INF00);
			type = (reg_val & QM_FIFO_OVERFLOW_TYPE) >>
			       QM_FIFO_OVERFLOW_TYPE_SHIFT;
			vf_num = reg_val & QM_FIFO_OVERFLOW_VF;

			if (type < ARRAY_SIZE(qm_fifo_overflow))
				dev_err(dev, "qm %s fifo overflow in function %u\n",
					 qm_fifo_overflow[type],
					 vf_num);
			else
				dev_err(dev, "unknown error type\n");
		}
	}
}

static pci_ers_result_t qm_hw_error_handle_v2(struct hisi_qm *qm)
{
	u32 error_status, tmp;

	/* read err sts */
	tmp = readl(qm->io_base + QM_ABNORMAL_INT_STATUS);
	error_status = qm->error_mask & tmp;
	if (error_status) {
		if (error_status & QM_ECC_MBIT)
			qm->err_ini.err_info.is_qm_ecc_mbit = true;

		qm_log_hw_error(qm, error_status);
		return PCI_ERS_RESULT_NEED_RESET;
	}

	return PCI_ERS_RESULT_RECOVERED;
}

static const struct hisi_qm_hw_ops qm_hw_ops_v1 = {
	.qm_db = qm_db_v1,
	.get_irq_num = qm_get_irq_num_v1,
	.hw_error_init = qm_hw_error_init_v1,
};

static const struct hisi_qm_hw_ops qm_hw_ops_v2 = {
	.get_vft = qm_get_vft_v2,
	.qm_db = qm_db_v2,
	.get_irq_num = qm_get_irq_num_v2,
	.hw_error_init = qm_hw_error_init_v2,
	.hw_error_uninit = qm_hw_error_uninit_v2,
	.hw_error_handle = qm_hw_error_handle_v2,
};

static void *qm_get_avail_sqe(struct hisi_qp *qp)
{
	struct hisi_qp_status *qp_status = &qp->qp_status;
	u16 sq_tail = qp_status->sq_tail;

	if (unlikely(atomic_read(&qp->qp_status.used) == QM_Q_DEPTH - 1))
		return NULL;

	return qp->sqe + sq_tail * qp->qm->sqe_size;
}

static void hisi_qm_unset_hw_reset(struct hisi_qp *qp)
{
	u64 *addr;

	/* Use last 32 bits of DUS to reset status. */
	addr = (u64 *)(qp->qdma.va + qp->qdma.size) - QM_RESET_STOP_TX_OFFSET;
	*addr = 0;
}

static struct hisi_qp *hisi_qm_create_qp_nolock(struct hisi_qm *qm,
						u8 alg_type)
{
	struct device *dev = &qm->pdev->dev;
	struct hisi_qp *qp;
	int qp_id;

	if (!qm_qp_avail_state(qm, NULL, QP_INIT))
		return ERR_PTR(-EPERM);

	if (!qm->free_qp_num) {
		dev_info_ratelimited(dev, "All %u queues of QM are busy!\n",
				    qm->qp_num);
		atomic64_inc(&qm->debug.dfx.qp_err_cnt);
		return ERR_PTR(-EBUSY);
	}

	qp_id = idr_alloc_cyclic(&qm->qp_idr, NULL,
				0, qm->qp_num, GFP_ATOMIC);
	if (qp_id < 0) {
		dev_info_ratelimited(dev, "All %u queues of QM are busy!\n",
				    qm->qp_num);
		atomic64_inc(&qm->debug.dfx.qp_err_cnt);
		return ERR_PTR(-EBUSY);
	}

	qp = &qm->qp_array[qp_id];
	if (!qp->is_in_kernel)
		hisi_qm_unset_hw_reset(qp);

	memset(qp->cqe, 0, sizeof(struct qm_cqe) * QM_Q_DEPTH);
	qp->event_cb = NULL;
	qp->req_cb = NULL;
	qp->alg_type = alg_type;
	qp->c_flag = 1;
	qp->is_in_kernel = true;
	qm->free_qp_num--;
	atomic_set(&qp->qp_status.flags, QP_INIT);

	return qp;
}

/**
 * hisi_qm_create_qp() - Create a queue pair from qm.
 * @qm: The qm we create a qp from.
 * @alg_type: Accelerator specific algorithm type in sqc.
 *
 * return created qp, -EBUSY if all qps in qm allocated, -ENOMEM if allocating
 * qp memory fails.
 */
struct hisi_qp *hisi_qm_create_qp(struct hisi_qm *qm, u8 alg_type)
{
	struct hisi_qp *qp;

	down_write(&qm->qps_lock);
	qp = hisi_qm_create_qp_nolock(qm, alg_type);
	up_write(&qm->qps_lock);

	return qp;
}
EXPORT_SYMBOL_GPL(hisi_qm_create_qp);

/**
 * hisi_qm_release_qp() - Release a qp back to its qm.
 * @qp: The qp we want to release.
 *
 * This function releases the resource of a qp.
 */
void hisi_qm_release_qp(struct hisi_qp *qp)
{
	struct hisi_qm *qm = qp->qm;

	down_write(&qm->qps_lock);
	if (!qm_qp_avail_state(qm, qp, QP_CLOSE)) {
		up_write(&qm->qps_lock);
		return;
	}
	qm->free_qp_num++;
	idr_remove(&qm->qp_idr, qp->qp_id);
	up_write(&qm->qps_lock);
}
EXPORT_SYMBOL_GPL(hisi_qm_release_qp);

static int qm_sq_ctx_cfg(struct hisi_qp *qp, int qp_id, int pasid)
{
	struct hisi_qm *qm = qp->qm;
	struct device *dev = &qm->pdev->dev;
	enum qm_hw_ver ver = qm->ver;
	struct qm_sqc *sqc;
	dma_addr_t sqc_dma;
	int ret;

	sqc = kzalloc(sizeof(struct qm_sqc), GFP_KERNEL);
	if (!sqc)
		return -ENOMEM;
	sqc_dma = dma_map_single(dev, sqc, sizeof(struct qm_sqc),
				 DMA_TO_DEVICE);
	if (dma_mapping_error(dev, sqc_dma)) {
		kfree(sqc);
		return -ENOMEM;
	}

	INIT_QC_COMMON(sqc, qp->sqe_dma, pasid);
	if (ver == QM_HW_V1) {
		sqc->dw3 = cpu_to_le32(QM_MK_SQC_DW3_V1(0, 0, 0, qm->sqe_size));
		sqc->w8 = cpu_to_le16(QM_Q_DEPTH - 1);
	} else if (ver == QM_HW_V2) {
		sqc->dw3 = cpu_to_le32(QM_MK_SQC_DW3_V2(qm->sqe_size));
		sqc->w8 = 0; /* rand_qc */
	}
	sqc->cq_num = cpu_to_le16(qp_id);
	sqc->w13 = cpu_to_le16(QM_MK_SQC_W13(0, 1, qp->alg_type));

	ret = qm_mb(qm, QM_MB_CMD_SQC, sqc_dma, qp_id, 0);

	dma_unmap_single(dev, sqc_dma, sizeof(struct qm_sqc), DMA_TO_DEVICE);
	kfree(sqc);

	return ret;
}

static int qm_cq_ctx_cfg(struct hisi_qp *qp, int qp_id, int pasid)
{
	struct hisi_qm *qm = qp->qm;
	struct device *dev = &qm->pdev->dev;
	enum qm_hw_ver ver = qm->ver;
	struct qm_cqc *cqc;
	dma_addr_t cqc_dma;
	int ret;

	cqc = kzalloc(sizeof(struct qm_cqc), GFP_KERNEL);
	if (!cqc)
		return -ENOMEM;

	cqc_dma = dma_map_single(dev, cqc, sizeof(struct qm_cqc),
				 DMA_TO_DEVICE);
	if (dma_mapping_error(dev, cqc_dma)) {
		kfree(cqc);
		return -ENOMEM;
	}

	INIT_QC_COMMON(cqc, qp->cqe_dma, pasid);
	if (ver == QM_HW_V1) {
		cqc->dw3 = cpu_to_le32(QM_MK_CQC_DW3_V1(0, 0, 0,
							QM_QC_CQE_SIZE));
		cqc->w8 = cpu_to_le16(QM_Q_DEPTH - 1);
	} else if (ver == QM_HW_V2) {
		cqc->dw3 = cpu_to_le32(QM_MK_CQC_DW3_V2(QM_QC_CQE_SIZE));
		cqc->w8 = 0; /* rand_qc */
	}
	cqc->dw6 = cpu_to_le32(1 << QM_CQ_PHASE_SHIFT |
			       qp->c_flag << QM_CQ_FLAG_SHIFT);

	ret = qm_mb(qm, QM_MB_CMD_CQC, cqc_dma, qp_id, 0);

	dma_unmap_single(dev, cqc_dma, sizeof(struct qm_cqc), DMA_TO_DEVICE);
	kfree(cqc);

	return ret;
}

static int qm_qp_ctx_cfg(struct hisi_qp *qp, int qp_id, int pasid)
{
	int ret;

	qm_init_qp_status(qp);

	ret = qm_sq_ctx_cfg(qp, qp_id, pasid);
	if (ret)
		return ret;

	return qm_cq_ctx_cfg(qp, qp_id, pasid);
}

static int hisi_qm_start_qp_nolock(struct hisi_qp *qp, unsigned long arg)
{
	struct hisi_qm *qm = qp->qm;
	struct device *dev = &qm->pdev->dev;
	int qp_id = qp->qp_id;
	int pasid = arg;
	int ret;

	if (!qm_qp_avail_state(qm, qp, QP_START))
		return -EPERM;

	ret = qm_qp_ctx_cfg(qp, qp_id, pasid);
	if (ret)
		return ret;
	atomic_set(&qp->qp_status.flags, QP_START);
	dev_dbg(dev, "queue %d started\n", qp_id);

	return qp_id;
}

/**
 * hisi_qm_start_qp() - Start a qp into running.
 * @qp: The qp we want to start to run.
 * @arg: Accelerator specific argument.
 *
 * After this function, qp can receive request from user. Return qp_id if
 * successful, Return -EBUSY if failed.
 */
int hisi_qm_start_qp(struct hisi_qp *qp, unsigned long arg)
{
	struct hisi_qm *qm = qp->qm;
	int ret;

	down_write(&qm->qps_lock);
	ret = hisi_qm_start_qp_nolock(qp, arg);
	up_write(&qm->qps_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(hisi_qm_start_qp);

/* Callback function should be called whether task completed or not. */
static void qp_stop_fail_cb(struct hisi_qp *qp)
{
	int qp_used = atomic_read(&qp->qp_status.used);
	u16 cur_tail = qp->qp_status.sq_tail;
	u16 cur_head = (cur_tail + QM_Q_DEPTH - qp_used) % QM_Q_DEPTH;
	struct hisi_qm *qm = qp->qm;
	u16 pos;
	int i;

	for (i = 0; i < qp_used; i++) {
		pos = (i + cur_head) % QM_Q_DEPTH;
		qp->req_cb(qp, qp->sqe + (u32)(qm->sqe_size * pos));
		atomic_dec(&qp->qp_status.used);
	}
}

static void qm_qp_has_no_task(struct hisi_qp *qp)
{
	size_t size = sizeof(struct qm_sqc) + sizeof(struct qm_cqc);
	struct device *dev = &qp->qm->pdev->dev;
	struct qm_sqc *sqc;
	struct qm_cqc *cqc;
	dma_addr_t dma_addr;
	void *addr;
	int i = 0;
	int ret;

	if (qp->qm->err_ini.err_info.is_qm_ecc_mbit ||
		qp->qm->err_ini.err_info.is_dev_ecc_mbit)
		return;

	addr = qm_ctx_alloc(qp->qm, size, &dma_addr);
	if (IS_ERR(addr)) {
		dev_err(dev, "alloc ctx for sqc and cqc failed!\n");
		return;
	}

	while (++i) {
		ret = qm_dump_sqc_raw(qp->qm, dma_addr, qp->qp_id);
		if (ret) {
			dev_err(dev, "Failed to dump sqc!\n");
			break;
		}
		sqc = addr;

		ret = qm_dump_cqc_raw(qp->qm,
				(dma_addr + sizeof(struct qm_sqc)), qp->qp_id);
		if (ret) {
			dev_err(dev, "Failed to dump cqc!\n");
			break;
		}
		cqc = addr + sizeof(struct qm_sqc);

		if ((sqc->tail == cqc->tail) &&
			(QM_SQ_TAIL_IDX(sqc) == QM_CQ_TAIL_IDX(cqc)))
			break;

		if (i == MAX_WAIT_COUNTS) {
			dev_err(dev, "Fail to wait for device stop!\n");
			break;
		}

		usleep_range(WAIT_PERIOD_US_MIN, WAIT_PERIOD_US_MAX);
	}

	qm_ctx_free(qp->qm, size, addr, &dma_addr);
}

static int hisi_qm_stop_qp_nolock(struct hisi_qp *qp)
{
	struct device *dev = &qp->qm->pdev->dev;

	/* it is stopped */
	if (atomic_read(&qp->qp_status.flags) == QP_STOP) {
		qp->is_resetting = false;
		return 0;
	}
	if (!qm_qp_avail_state(qp->qm, qp, QP_STOP))
		return -EPERM;

	atomic_set(&qp->qp_status.flags, QP_STOP);

	qm_qp_has_no_task(qp);

	if (qp->qm->wq)
		flush_workqueue(qp->qm->wq);
	else
		flush_work(&qp->qm->work);

	/* waiting for increase used count in qp send and last poll qp finish */
	while (atomic_read(&qp->qp_status.send_ref))
		udelay(WAIT_PERIOD);

	if (unlikely(qp->is_resetting && atomic_read(&qp->qp_status.used)))
		qp_stop_fail_cb(qp);

	dev_dbg(dev, "stop queue %u!", qp->qp_id);

	return 0;
}

/**
 * hisi_qm_stop_qp() - Stop a qp in qm.
 * @qp: The qp we want to stop.
 *
 * This function is reverse of hisi_qm_start_qp. Return 0 if successful.
 */
int hisi_qm_stop_qp(struct hisi_qp *qp)
{
	int ret;

	down_write(&qp->qm->qps_lock);
	ret = hisi_qm_stop_qp_nolock(qp);
	up_write(&qp->qm->qps_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(hisi_qm_stop_qp);

/**
 * hisi_qp_send() - Queue up a task in the hardware queue.
 * @qp: The qp in which to put the message.
 * @msg: The message.
 *
 * This function will return -EBUSY if qp is currently full, and -EAGAIN
 * if qp related qm is resetting.
 *
 * Note: This function may run with qm_irq_thread and ACC reset at same time.
 *       It has no race with qm_irq_thread. However, during hisi_qp_send, ACC
 *       reset may happen, we have no lock here considering performance. This
 *       causes current qm_db sending fail or can not receive sended sqe. QM
 *       sync/async receive function should handle the error sqe. ACC reset
 *       done function should clear used sqe to 0.
 */
int hisi_qp_send(struct hisi_qp *qp, const void *msg)
{
	struct hisi_qp_status *qp_status = &qp->qp_status;
	void *sqe;

	if (unlikely(atomic_read(&qp->qp_status.flags) == QP_STOP ||
		     atomic_read(&qp->qm->status.flags) == QM_STOP) ||
		     qp->is_resetting) {
		dev_info_ratelimited(&qp->qm->pdev->dev, "QP is stopped or resetting\n");
		return -EAGAIN;
	}

	atomic_inc(&qp->qp_status.send_ref);
	sqe = qm_get_avail_sqe(qp);
	if (!sqe) {
		atomic_dec(&qp->qp_status.send_ref);
		return -EBUSY;
	}

	memcpy(sqe, msg, qp->qm->sqe_size);
	qp_status->sq_tail = (qp_status->sq_tail + 1) % QM_Q_DEPTH;
	qm_db(qp->qm, qp->qp_id, QM_DOORBELL_CMD_SQ, qp_status->sq_tail, 0);
	atomic_inc(&qp->qp_status.used);
	atomic_dec(&qp->qp_status.send_ref);

	return 0;
}
EXPORT_SYMBOL_GPL(hisi_qp_send);

static void hisi_qm_cache_wb(struct hisi_qm *qm)
{
	unsigned int val;

	if (qm->ver == QM_HW_V2) {
		writel(0x1, qm->io_base + QM_CACHE_WB_START);
		if (readl_relaxed_poll_timeout(qm->io_base + QM_CACHE_WB_DONE,
					       val, val & BIT(0), POLL_PERIOD,
					       POLL_TIMEOUT))
			dev_err(&qm->pdev->dev,
				"QM writeback sqc cache fail!\n");
	}
}

int hisi_qm_get_free_qp_num(struct hisi_qm *qm)
{
	int ret;

	down_read(&qm->qps_lock);
	ret = qm->free_qp_num;
	up_read(&qm->qps_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(hisi_qm_get_free_qp_num);

static void qm_qp_event_notifier(struct hisi_qp *qp)
{
	uacce_wake_up(qp->uacce_q);
}

static int hisi_qm_get_available_instances(struct uacce *uacce)
{
	return hisi_qm_get_free_qp_num(uacce->priv);
}

static void hisi_qm_set_hw_reset(struct hisi_qm *qm, int offset)
{
	struct hisi_qp *qp;
	u32 *addr;
	int i;

	for (i = 0; i < qm->qp_num; i++) {
		qp = &qm->qp_array[i];
		if (!qp->is_in_kernel) {
			/* Use last 32 bits of DUS to save reset status. */
			addr = (u32 *)(qp->qdma.va + qp->qdma.size) - offset;
			*addr = 1;

			/* make sure setup is completed */
			mb();
		}
	}
}

static int hisi_qm_uacce_get_queue(struct uacce *uacce, unsigned long arg,
				   struct uacce_queue **q)
{
	struct hisi_qm *qm = uacce->priv;
	struct hisi_qp *qp;
	struct uacce_queue *wd_q;
	u8 alg_type = 0;

	down_write(&qm->qps_lock);
	qp = hisi_qm_create_qp_nolock(qm, alg_type);
	if (IS_ERR(qp)) {
		up_write(&qm->qps_lock);
		return PTR_ERR(qp);
	}

	wd_q = kzalloc(sizeof(struct uacce_queue), GFP_KERNEL);
	if (!wd_q) {
		up_write(&qm->qps_lock);
		hisi_qm_release_qp(qp);
		return -ENOMEM;
	}

	wd_q->priv = qp;
	wd_q->uacce = uacce;
	*q = wd_q;
	qp->uacce_q = wd_q;
	qp->event_cb = qm_qp_event_notifier;
	qp->pasid = arg;
	qp->is_in_kernel = false;

	up_write(&qm->qps_lock);
	return 0;
}

static void hisi_qm_uacce_put_queue(struct uacce_queue *q)
{
	struct hisi_qp *qp = q->priv;

	/* need to stop hardware, but can not support in v1 */
	hisi_qm_release_qp(qp);
}

/* map sq/cq/doorbell to user space */
static int hisi_qm_uacce_mmap(struct uacce_queue *q,
			      struct vm_area_struct *vma,
			      struct uacce_qfile_region *qfr)
{
	struct hisi_qp *qp = (struct hisi_qp *)q->priv;
	struct hisi_qm *qm = qp->qm;
	size_t sz = vma->vm_end - vma->vm_start;
	struct pci_dev *pdev = qm->pdev;
	struct device *dev = &pdev->dev;
	unsigned long vm_pgoff;
	int ret;

	switch (qfr->type) {
	case UACCE_QFRT_MMIO:
		if (qm->ver == QM_HW_V2) {
			if (WARN_ON(sz > PAGE_SIZE * (QM_DOORBELL_PAGE_NR +
				QM_V2_DOORBELL_OFFSET / PAGE_SIZE)))
				return -EINVAL;
		} else {
			if (WARN_ON(sz > PAGE_SIZE * QM_DOORBELL_PAGE_NR))
				return -EINVAL;
		}

		vma->vm_flags |= VM_IO;

		/*
		 * Warning: This is not safe as multiple processes use the same
		 * doorbell, v1/v2 hardware interface problem. It will be fixed
		 * it in next version.
		 */
		return remap_pfn_range(vma, vma->vm_start,
				       qm->phys_base >> PAGE_SHIFT,
				       sz, pgprot_noncached(vma->vm_page_prot));
	case UACCE_QFRT_DUS:
		if (sz != qp->qdma.size) {
			dev_err(dev, "wrong queue size %ld vs %ld\n",
				sz, qp->qdma.size);
			return -EINVAL;
		}

		/* dma_mmap_coherent() requires vm_pgoff as 0
		 * restore vm_pfoff to initial value for mmap()
		 */
		vm_pgoff = vma->vm_pgoff;
		vma->vm_pgoff = 0;
		ret = dma_mmap_coherent(dev, vma, qp->qdma.va,
					qp->qdma.dma, sz);
		vma->vm_pgoff = vm_pgoff;

		return ret;
	default:
		return -EINVAL;
	}
}

static int hisi_qm_uacce_start_queue(struct uacce_queue *q)
{
	struct hisi_qp *qp = q->priv;

	return hisi_qm_start_qp(qp, qp->pasid);
}

static void hisi_qm_uacce_stop_queue(struct uacce_queue *q)
{
	struct hisi_qp *qp = q->priv;

	hisi_qm_stop_qp(qp);
}

static int qm_set_sqctype(struct uacce_queue *q, u16 type)
{
	struct hisi_qm *qm = q->uacce->priv;
	struct hisi_qp *qp = q->priv;

	down_write(&qm->qps_lock);
	qp->alg_type = type;
	up_write(&qm->qps_lock);

	return 0;
}

static long hisi_qm_uacce_ioctl(struct uacce_queue *q, unsigned int cmd,
				unsigned long arg)
{
	struct hisi_qp *qp = q->priv;
	struct hisi_qp_ctx qp_ctx;

	if (cmd == UACCE_CMD_QM_SET_QP_CTX) {
		if (copy_from_user(&qp_ctx, (void __user *)arg,
				   sizeof(struct hisi_qp_ctx)))
			return -EFAULT;

		if (qp_ctx.qc_type != 0 && qp_ctx.qc_type != 1)
			return -EINVAL;

		qm_set_sqctype(q, qp_ctx.qc_type);
		qp_ctx.id = qp->qp_id;
		qp->c_flag = 0;
		if (copy_to_user((void __user *)arg, &qp_ctx,
				 sizeof(struct hisi_qp_ctx)))
			return -EFAULT;
	} else {
		return -EINVAL;
	}

	return 0;
}

static enum uacce_dev_state hisi_qm_get_state(struct uacce *uacce)
{
	struct hisi_qm *qm = uacce->priv;
	enum qm_state curr;

	curr = atomic_read(&qm->status.flags);
	if (curr == QM_STOP)
		return UACCE_DEV_ERR;
	else
		return UACCE_DEV_NORMAL;
}

static void hisi_qm_uacce_memory_init(struct hisi_qm *qm)
{
	unsigned long dus_page_nr, mmio_page_nr;
	struct uacce *uacce = &qm->uacce;

	/* Add one more page for device or qp status */
	dus_page_nr = (PAGE_SIZE - 1 + qm->sqe_size * QM_Q_DEPTH +
			sizeof(struct cqe) * QM_Q_DEPTH + PAGE_SIZE) >>
					PAGE_SHIFT;

	if (qm->ver == QM_HW_V2)
		mmio_page_nr = QM_DOORBELL_PAGE_NR +
			QM_V2_DOORBELL_OFFSET / PAGE_SIZE;
	else
		mmio_page_nr = QM_DOORBELL_PAGE_NR;

	uacce->qf_pg_start[UACCE_QFRT_MMIO] = 0;
	uacce->qf_pg_start[UACCE_QFRT_DUS] = mmio_page_nr;
	uacce->qf_pg_start[UACCE_QFRT_SS] = mmio_page_nr + dus_page_nr;
}

/*
 * the device is set the UACCE_DEV_SVA, but it will be cut if SVA patch is not
 * available
 */
static struct uacce_ops uacce_qm_ops = {
	.get_available_instances = hisi_qm_get_available_instances,
	.get_queue = hisi_qm_uacce_get_queue,
	.put_queue = hisi_qm_uacce_put_queue,
	.start_queue = hisi_qm_uacce_start_queue,
	.stop_queue = hisi_qm_uacce_stop_queue,
	.mmap = hisi_qm_uacce_mmap,
	.ioctl = hisi_qm_uacce_ioctl,
	.get_dev_state = hisi_qm_get_state,
};

static int qm_register_uacce(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;
	struct uacce *uacce = &qm->uacce;
	int i;

	uacce->name = dev_name(&pdev->dev);
	uacce->drv_name = pdev->driver->name;
	uacce->pdev = &pdev->dev;
	uacce->is_vf = pdev->is_virtfn;
	uacce->priv = qm;
	uacce->ops = &uacce_qm_ops;
	uacce->algs = qm->algs;

	if (uacce->is_vf) {
		struct uacce *pf_uacce;
		struct device *pf_dev = &(pci_physfn(pdev)->dev);

		/* VF uses PF's isoalte data */
		pf_uacce = dev_to_uacce(pf_dev);
		if (!pf_uacce) {
			dev_err(&pdev->dev, "fail to PF device\n");
			return -ENODEV;
		}

		uacce->isolate = &pf_uacce->isolate_data;
	} else {
		uacce->isolate = &uacce->isolate_data;
	}

	if (qm->ver == QM_HW_V1)
		uacce->api_ver = HISI_QM_API_VER_BASE;
	else
		uacce->api_ver = HISI_QM_API_VER2_BASE;

	if (qm->use_sva) {
		uacce->flags = UACCE_DEV_SVA;
	} else {
		uacce->flags = UACCE_DEV_NOIOMMU;
		if (qm->ver == QM_HW_V1)
			uacce->api_ver = HISI_QM_API_VER_BASE
					 UACCE_API_VER_NOIOMMU_SUBFIX;
		else
			uacce->api_ver = HISI_QM_API_VER2_BASE
					 UACCE_API_VER_NOIOMMU_SUBFIX;
	}

	for (i = 0; i < UACCE_QFRT_MAX; i++)
		uacce->qf_pg_start[i] = UACCE_QFR_NA;

	return uacce_register(uacce);
}

static int qm_unregister_uacce(struct hisi_qm *qm)
{
	int ret;

	ret = uacce_unregister(&qm->uacce);
	if (ret)
		return ret;

	memset(&qm->uacce, 0, sizeof(qm->uacce));

	return 0;
}

/**
 * hisi_qm_frozen() - Try to froze QM to cut continuous queue request. If
 * there is user on the QM, return failure without doing anything.
 * @qm: The qm needed to be fronzen.
 *
 * This function frozes QM, then we can do SRIOV disabling.
 */
static int hisi_qm_frozen(struct hisi_qm *qm)
{
	down_write(&qm->qps_lock);
	if (qm->is_frozen) {
		up_write(&qm->qps_lock);
		return 0;
	}

	if (qm->free_qp_num == qm->qp_num) {
		qm->free_qp_num = 0;
		qm->is_frozen = true;
		up_write(&qm->qps_lock);
		return 0;
	}

	up_write(&qm->qps_lock);

	return -EBUSY;
}

static int qm_try_frozen_vfs(struct pci_dev *pdev,
			     struct hisi_qm_list *qm_list)
{
	struct hisi_qm *qm, *vf_qm;
	struct pci_dev *dev;
	int ret = 0;

	if (!qm_list || !pdev)
		return -EINVAL;

	/* Try to frozen all the VFs as disable SRIOV */
	mutex_lock(&qm_list->lock);
	list_for_each_entry(qm, &qm_list->list, list) {
		dev = qm->pdev;
		if (dev == pdev)
			continue;
		if (pci_physfn(dev) == pdev) {
			vf_qm = pci_get_drvdata(dev);
			ret = hisi_qm_frozen(vf_qm);
			if (ret)
				goto frozen_fail;
		}
	}

frozen_fail:
	mutex_unlock(&qm_list->lock);
	return ret;
}

void hisi_qm_remove_wait_delay(struct hisi_qm *qm,
			       struct hisi_qm_list *qm_list)
{
	while (hisi_qm_frozen(qm) ||
	       ((qm->fun_type == QM_HW_PF) &&
	       qm_try_frozen_vfs(qm->pdev, qm_list))) {
		msleep(WAIT_PERIOD);
	}
	udelay(REMOVE_WAIT_DELAY);
}
EXPORT_SYMBOL_GPL(hisi_qm_remove_wait_delay);

static void hisi_qp_memory_uninit(struct hisi_qm *qm, int num)
{
	struct device *dev = &qm->pdev->dev;
	struct qm_dma *qdma;
	int i;

	for (i = num - 1; i >= 0; i--) {
		qdma = &qm->qp_array[i].qdma;
		dma_free_coherent(dev, qdma->size, qdma->va, qdma->dma);
	}

	kfree(qm->qp_array);
}

static int hisi_qp_memory_init(struct hisi_qm *qm, size_t dma_size, int id)
{
	struct device *dev = &qm->pdev->dev;
	size_t off = qm->sqe_size * QM_Q_DEPTH;
	struct hisi_qp *qp;

	qp = &qm->qp_array[id];
	qp->qdma.va = dma_alloc_coherent(dev, dma_size,
				 &qp->qdma.dma, GFP_KERNEL);
	if (!qp->qdma.va)
		return -ENOMEM;

	qp->sqe = qp->qdma.va;
	qp->sqe_dma = qp->qdma.dma;
	qp->cqe = qp->qdma.va + off;
	qp->cqe_dma = qp->qdma.dma + off;
	qp->qdma.size = dma_size;
	qp->qm = qm;
	qp->qp_id = id;

	return 0;
}

static int hisi_qm_memory_init(struct hisi_qm *qm)
{
	struct device *dev = &qm->pdev->dev;
	size_t qp_dma_size;
	size_t off = 0;
	int ret = 0;
	int i;

#define QM_INIT_BUF(qm, type, num) do { \
	(qm)->type = ((qm)->qdma.va + (off)); \
	(qm)->type##_dma = (qm)->qdma.dma + (off); \
	off += QMC_ALIGN(sizeof(struct qm_##type) * (num)); \
} while (0)

	if (qm->use_uacce)
		hisi_qm_uacce_memory_init(qm);

	idr_init(&qm->qp_idr);
	qm->qdma.size = QMC_ALIGN(sizeof(struct qm_eqe) * QM_EQ_DEPTH) +
			QMC_ALIGN(sizeof(struct qm_aeqe) * QM_Q_DEPTH) +
			QMC_ALIGN(sizeof(struct qm_sqc) * qm->qp_num) +
			QMC_ALIGN(sizeof(struct qm_cqc) * qm->qp_num);
	qm->qdma.va = dma_alloc_coherent(dev, qm->qdma.size,
			&qm->qdma.dma, GFP_ATOMIC | __GFP_ZERO);
	dev_dbg(dev, "allocate qm dma buf size=%zx)\n", qm->qdma.size);
	if (!qm->qdma.va)
		return -ENOMEM;

	QM_INIT_BUF(qm, eqe, QM_EQ_DEPTH);
	QM_INIT_BUF(qm, aeqe, QM_Q_DEPTH);
	QM_INIT_BUF(qm, sqc, qm->qp_num);
	QM_INIT_BUF(qm, cqc, qm->qp_num);

	qm->qp_array = kcalloc(qm->qp_num, sizeof(struct hisi_qp), GFP_KERNEL);
	if (!qm->qp_array) {
		ret = -ENOMEM;
		goto err_alloc_qp_array;
	}

	/* one more page for device or qp statuses */
	qp_dma_size = qm->sqe_size * QM_Q_DEPTH +
			sizeof(struct cqe) * QM_Q_DEPTH;
	qp_dma_size = PAGE_ALIGN(qp_dma_size) + PAGE_SIZE;
	for (i = 0; i < qm->qp_num; i++) {
		ret = hisi_qp_memory_init(qm, qp_dma_size, i);
		if (ret)
			goto err_init_qp_mem;

		dev_dbg(dev, "allocate qp dma buf size=%zx)\n", qp_dma_size);
	}

	return ret;
err_init_qp_mem:
	hisi_qp_memory_uninit(qm, i);
err_alloc_qp_array:
	dma_free_coherent(dev, qm->qdma.size,
			qm->qdma.va, qm->qdma.dma);
	return ret;
}

static int hisi_qm_pci_init(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;
	struct device *dev = &pdev->dev;
	unsigned int num_vec;
	int ret;

	ret = pci_enable_device_mem(pdev);
	if (ret < 0) {
		dev_err(&pdev->dev, "Failed to enable device mem!\n");
		return ret;
	}

	ret = pci_request_mem_regions(pdev, qm->dev_name);
	if (ret < 0) {
		dev_err(&pdev->dev, "Failed to request mem regions!\n");
		goto err_request_mem_regions;
	}

	qm->phys_base = pci_resource_start(pdev, PCI_BAR_2);
	qm->size = pci_resource_len(qm->pdev, PCI_BAR_2);
	qm->io_base = devm_ioremap(dev, pci_resource_start(pdev, PCI_BAR_2),
				   pci_resource_len(qm->pdev, PCI_BAR_2));
	if (!qm->io_base) {
		ret = -EIO;
		goto err_ioremap;
	}

	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (ret < 0) {
		dev_err(dev, "Failed to set 64 bit dma mask %d", ret);
		goto err_set_mask_and_coherent;
	}
	pci_set_master(pdev);

	num_vec = qm->ops->get_irq_num(qm);
	ret = pci_alloc_irq_vectors(pdev, num_vec, num_vec, PCI_IRQ_MSI);
	if (ret < 0) {
		dev_err(dev, "Failed to enable MSI vectors!\n");
		goto err_set_mask_and_coherent;
	}

	return 0;

err_set_mask_and_coherent:
	devm_iounmap(dev, qm->io_base);
err_ioremap:
	pci_release_mem_regions(pdev);
err_request_mem_regions:
	pci_disable_device(pdev);
	return ret;
}

static void hisi_qm_pci_uninit(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;
	struct device *dev = &pdev->dev;

	pci_free_irq_vectors(pdev);
	devm_iounmap(dev, qm->io_base);
	pci_release_mem_regions(pdev);
	pci_disable_device(pdev);
}

/**
 * hisi_qm_init() - Initialize configures about qm.
 * @qm: The qm needed init.
 *
 * This function init qm, then we can call hisi_qm_start to put qm into work.
 */
int hisi_qm_init(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;
	struct device *dev = &pdev->dev;
	int ret;

	switch (qm->ver) {
	case QM_HW_V1:
		qm->ops = &qm_hw_ops_v1;
		break;
	case QM_HW_V2:
		qm->ops = &qm_hw_ops_v2;
		break;
	default:
		return -EINVAL;
	}

	if (qm->use_uacce) {
		dev_info(dev, "qm register to uacce\n");
		ret = qm_register_uacce(qm);
		if (ret < 0) {
			dev_err(dev, "fail to register uacce (%d)\n", ret);
			return ret;
		}
	}

	ret = hisi_qm_pci_init(qm);
	if (ret)
		goto err_pci_init;

	ret = qm_irq_register(qm);
	if (ret)
		goto err_irq_register;

	mutex_init(&qm->mailbox_lock);
	if (qm->fun_type == QM_HW_VF && qm->ver == QM_HW_V2) {
		/* v2 or v3 starts to support get vft by mailbox */
		ret = hisi_qm_get_vft(qm, &qm->qp_base, &qm->qp_num);
		if (ret)
			goto err_get_vft;
	}

	ret = hisi_qm_memory_init(qm);
	if (ret)
		goto err_get_vft;

	qm->free_qp_num = qm->qp_num;
	qm->is_frozen = false;

	init_rwsem(&qm->qps_lock);
	atomic_set(&qm->status.flags, QM_INIT);
	INIT_WORK(&qm->work, qm_work_process);

	dev_dbg(dev, "init qm %s\n", pdev->is_physfn ? "pf" : "vf");

	return 0;

err_get_vft:
	qm_irq_unregister(qm);
err_irq_register:
	hisi_qm_pci_uninit(qm);
err_pci_init:
	if (qm->use_uacce)
		qm_unregister_uacce(qm);

	return ret;
}
EXPORT_SYMBOL_GPL(hisi_qm_init);

/**
 * hisi_qm_uninit() - Uninitialize qm.
 * @qm: The qm needed uninit.
 *
 * This function uninits qm related device resources.
 */
void hisi_qm_uninit(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;
	struct device *dev = &pdev->dev;

	down_write(&qm->qps_lock);
	if (!qm_avail_state(qm, QM_CLOSE)) {
		up_write(&qm->qps_lock);
		return;
	}

	hisi_qp_memory_uninit(qm, qm->qp_num);
	idr_destroy(&qm->qp_idr);

	/* qm hardware buffer free on put_queue if no dma api */
	if (qm->qdma.va) {
		hisi_qm_cache_wb(qm);
		dma_free_coherent(dev, qm->qdma.size,
				  qm->qdma.va, qm->qdma.dma);
		memset(&qm->qdma, 0, sizeof(qm->qdma));
	}

	qm_irq_unregister(qm);
	hisi_qm_pci_uninit(qm);
	up_write(&qm->qps_lock);

	if (qm->use_uacce)
		uacce_unregister(&qm->uacce);
}
EXPORT_SYMBOL_GPL(hisi_qm_uninit);

/**
 * hisi_qm_dev_shutdown() - shutdown device.
 * @pdev: The device will be shutdown.
 *
 * This function will stop qm when OS shutdown or rebooting.
 */
void hisi_qm_dev_shutdown(struct pci_dev *pdev)
{
	struct hisi_qm *qm = pci_get_drvdata(pdev);
	int ret;

	ret = hisi_qm_stop(qm, QM_NORMAL);
	if (ret)
		dev_err(&pdev->dev, "Fail to stop qm in shutdown!\n");

	hisi_qm_cache_wb(qm);
}
EXPORT_SYMBOL_GPL(hisi_qm_dev_shutdown);

/**
 * hisi_qm_get_vft() - Get vft from a qm.
 * @qm: The qm we want to get its vft.
 * @base: The base number of queue in vft.
 * @number: The number of queues in vft.
 *
 * We can allocate multiple queues to a qm by configuring virtual function
 * table. We get related configures by this function. Normally, we call this
 * function in VF driver to get the queue information.
 *
 * qm hw v1 does not support this interface.
 */
int hisi_qm_get_vft(struct hisi_qm *qm, u32 *base, u32 *number)
{
	if (!base || !number)
		return -EINVAL;

	if (!qm->ops->get_vft) {
		dev_err(&qm->pdev->dev, "Don't support vft read!\n");
		return -EINVAL;
	}

	return qm->ops->get_vft(qm, base, number);
}
EXPORT_SYMBOL_GPL(hisi_qm_get_vft);

/**
 * hisi_qm_set_vft() - Set "virtual function table" for a qm.
 * @fun_num: Number of operated function.
 * @qm: The qm in which to set vft, alway in a PF.
 * @base: The base number of queue in vft.
 * @number: The number of queues in vft.
 *
 * This function is alway called in PF driver, it is used to assign queues
 * among PF and VFs. Number is zero means invalid corresponding entry.
 *
 * Assign queues A~B to PF: hisi_qm_set_vft(qm, 0, A, B - A + 1)
 * Assign queues A~B to VF: hisi_qm_set_vft(qm, 2, A, B - A + 1)
 * (VF function number 0x2)
 */
static int hisi_qm_set_vft(struct hisi_qm *qm, u32 fun_num, u32 base,
		    u32 number)
{
	u32 max_q_num = qm->ctrl_q_num;

	if (base >= max_q_num || number > max_q_num ||
	    (base + number) > max_q_num)
		return -EINVAL;

	return qm_set_sqc_cqc_vft(qm, fun_num, base, number);
}

static void qm_init_eq_aeq_status(struct hisi_qm *qm)
{
	struct hisi_qm_status *status = &qm->status;

	status->eq_head = 0;
	status->aeq_head = 0;
	status->eqc_phase = true;
	status->aeqc_phase = true;
}

static int qm_eq_ctx_cfg(struct hisi_qm *qm)
{
	struct device *dev = &qm->pdev->dev;
	struct qm_eqc *eqc;
	dma_addr_t eqc_dma;
	int ret;

	eqc = kzalloc(sizeof(struct qm_eqc), GFP_KERNEL);
	if (!eqc)
		return -ENOMEM;
	eqc_dma = dma_map_single(dev, eqc, sizeof(struct qm_eqc),
				 DMA_TO_DEVICE);
	if (dma_mapping_error(dev, eqc_dma)) {
		kfree(eqc);
		return -ENOMEM;
	}

	eqc->base_l = cpu_to_le32(lower_32_bits(qm->eqe_dma));
	eqc->base_h = cpu_to_le32(upper_32_bits(qm->eqe_dma));
	if (qm->ver == QM_HW_V1)
		eqc->dw3 = cpu_to_le32(QM_EQE_AEQE_SIZE);
	eqc->dw6 = cpu_to_le32((QM_EQ_DEPTH - 1) | (1 << QM_EQC_PHASE_SHIFT));
	ret = qm_mb(qm, QM_MB_CMD_EQC, eqc_dma, 0, 0);
	dma_unmap_single(dev, eqc_dma, sizeof(struct qm_eqc), DMA_TO_DEVICE);
	kfree(eqc);

	return ret;
}

static int qm_aeq_ctx_cfg(struct hisi_qm *qm)
{
	struct device *dev = &qm->pdev->dev;
	struct qm_aeqc *aeqc;
	dma_addr_t aeqc_dma;
	int ret;

	aeqc = kzalloc(sizeof(struct qm_aeqc), GFP_KERNEL);
	if (!aeqc)
		return -ENOMEM;
	aeqc_dma = dma_map_single(dev, aeqc, sizeof(struct qm_aeqc),
				  DMA_TO_DEVICE);
	if (dma_mapping_error(dev, aeqc_dma)) {
		kfree(aeqc);
		return -ENOMEM;
	}

	aeqc->base_l = cpu_to_le32(lower_32_bits(qm->aeqe_dma));
	aeqc->base_h = cpu_to_le32(upper_32_bits(qm->aeqe_dma));
	aeqc->dw6 = cpu_to_le32((QM_Q_DEPTH - 1) | (1 << QM_EQC_PHASE_SHIFT));
	ret = qm_mb(qm, QM_MB_CMD_AEQC, aeqc_dma, 0, 0);

	dma_unmap_single(dev, aeqc_dma, sizeof(struct qm_aeqc), DMA_TO_DEVICE);
	kfree(aeqc);

	return ret;
}

static int qm_eq_aeq_ctx_cfg(struct hisi_qm *qm)
{
	struct device *dev = &qm->pdev->dev;
	int ret;

	qm_init_eq_aeq_status(qm);

	ret = qm_eq_ctx_cfg(qm);
	if (ret) {
		dev_err(dev, "Set eqc failed!\n");
		return ret;
	}

	return qm_aeq_ctx_cfg(qm);
}

static int __hisi_qm_start(struct hisi_qm *qm)
{
	int ret;

	/* dma must be ready before start, nomatter by init or by uacce mmap */
	WARN_ON(!qm->qdma.dma);

	if (qm->qp_num == 0)
		return -EINVAL;

	if (qm->fun_type == QM_HW_PF) {
		ret = qm_dev_mem_reset(qm);
		if (ret)
			return ret;

		ret = hisi_qm_set_vft(qm, 0, qm->qp_base, qm->qp_num);
		if (ret)
			return ret;
	}

	ret = qm_eq_aeq_ctx_cfg(qm);
	if (ret)
		return ret;

	ret = qm_mb(qm, QM_MB_CMD_SQC_BT, qm->sqc_dma, 0, 0);
	if (ret)
		return ret;

	ret = qm_mb(qm, QM_MB_CMD_CQC_BT, qm->cqc_dma, 0, 0);
	if (ret)
		return ret;

	writel(0x0, qm->io_base + QM_VF_EQ_INT_MASK);
	writel(0x0, qm->io_base + QM_VF_AEQ_INT_MASK);

	return 0;
}

/* restart stopped qm and qps in reset flow */
int hisi_qm_restart(struct hisi_qm *qm)
{
	struct device *dev = &qm->pdev->dev;
	struct hisi_qp *qp;
	int ret, i;

	ret = hisi_qm_start(qm);
	if (ret < 0)
		return ret;

	down_write(&qm->qps_lock);
	for (i = 0; i < qm->qp_num; i++) {
		qp = &qm->qp_array[i];

		if (atomic_read(&qp->qp_status.flags) == QP_STOP &&
		    qp->is_resetting && qp->is_in_kernel) {
			ret = hisi_qm_start_qp_nolock(qp, 0);
			if (ret < 0) {
				dev_err(dev, "Failed to start qp%d!\n", i);

				up_write(&qm->qps_lock);
				return ret;
			}
			qp->is_resetting = false;
		}
	}
	up_write(&qm->qps_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(hisi_qm_restart);

/**
 * hisi_qm_start() - start qm
 * @qm: The qm to be started.
 *
 * This function starts a qm, then we can allocate qp from this qm.
 */
int hisi_qm_start(struct hisi_qm *qm)
{
	int ret;

	down_write(&qm->qps_lock);

	if (!qm_avail_state(qm, QM_START)) {
		up_write(&qm->qps_lock);
		return -EPERM;
	}

	ret = __hisi_qm_start(qm);
	if (!ret)
		atomic_set(&qm->status.flags, QM_START);

	up_write(&qm->qps_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(hisi_qm_start);

/* Stop started qps in reset flow */
static int qm_stop_started_qp(struct hisi_qm *qm)
{
	struct device *dev = &qm->pdev->dev;
	struct hisi_qp *qp;
	int i, ret;

	for (i = 0; i < qm->qp_num; i++) {
		qp = &qm->qp_array[i];
		if (atomic_read(&qp->qp_status.flags) == QP_START) {
			qp->is_resetting = true;
			ret = hisi_qm_stop_qp_nolock(qp);
			if (ret < 0) {
				dev_err(dev, "Failed to stop qp%d!\n", i);
				return ret;
			}
		}
	}

	return 0;
}

/**
 * qm_clear_queues() - Clear memory of queues in a qm.
 * @qm: The qm which memory needs clear.
 *
 * This function clears all queues memory in a qm. Reset of accelerator can
 * use this to clear queues.
 */
static void qm_clear_queues(struct hisi_qm *qm)
{
	struct hisi_qp *qp;
	int i;

	for (i = 0; i < qm->qp_num; i++) {
		qp = &qm->qp_array[i];
		if (qp->is_in_kernel && qp->is_resetting)
			/* device state use the last page */
			memset(qp->qdma.va, 0, qp->qdma.size - PAGE_SIZE);
	}

	memset(qm->qdma.va, 0, qm->qdma.size);
}

/**
 * hisi_qm_stop() - Stop a qm.
 * @qm: The qm which will be stopped.
 * @r: The reason to stop qm.
 *
 * This function stops qm and its qps, then qm can not accept request.
 * Related resources are not released at this state, we can use hisi_qm_start
 * to let qm start again.
 */
int hisi_qm_stop(struct hisi_qm *qm, enum qm_stop_reason r)
{
	struct device *dev = &qm->pdev->dev;
	int ret = 0;

	down_write(&qm->qps_lock);

	qm->status.stop_reason = r;

	if (!qm_avail_state(qm, QM_STOP)) {
		ret = -EPERM;
		goto err_unlock;
	}

	if (qm->status.stop_reason == QM_SOFT_RESET ||
	    qm->status.stop_reason == QM_FLR) {
		hisi_qm_set_hw_reset(qm, QM_RESET_STOP_TX_OFFSET);
		ret = qm_stop_started_qp(qm);
		if (ret < 0)
			goto err_unlock;

		hisi_qm_set_hw_reset(qm, QM_RESET_STOP_RX_OFFSET);
	}

	/* Mask eq and aeq irq */
	writel(0x1, qm->io_base + QM_VF_EQ_INT_MASK);
	writel(0x1, qm->io_base + QM_VF_AEQ_INT_MASK);

	if (qm->fun_type == QM_HW_PF) {
		ret = hisi_qm_set_vft(qm, 0, 0, 0);
		if (ret) {
			dev_err(dev, "Failed to set vft!\n");
			ret = -EBUSY;
			goto err_unlock;
		}
	}

	qm_clear_queues(qm);
	atomic_set(&qm->status.flags, QM_STOP);

err_unlock:
	up_write(&qm->qps_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(hisi_qm_stop);

/**
 * hisi_qm_debug_regs_clear() - clear qm debug related registers.
 * @qm: The qm for which we want to clear.
 */
void hisi_qm_debug_regs_clear(struct hisi_qm *qm)
{
	struct qm_dfx_registers *regs;
	int i;

	/* clear current_q */
	writel(0x0, qm->io_base + QM_DFX_SQE_CNT_VF_SQN);
	writel(0x0, qm->io_base + QM_DFX_CQE_CNT_VF_CQN);

	/* clear regs, these cnt regs are read_clear */
	writel(0x1, qm->io_base + QM_DFX_CNT_CLR_CE);

	regs = qm_dfx_regs;
#define CNT_CYC_REGS_NUM		10
	for (i = 0; i < CNT_CYC_REGS_NUM; i++) {
		readl(qm->io_base + regs->reg_offset);
		regs++;
	}

	/* clear clear_enable */
	writel(0x0, qm->io_base + QM_DFX_CNT_CLR_CE);
}
EXPORT_SYMBOL_GPL(hisi_qm_debug_regs_clear);

static ssize_t qm_status_read(struct file *filp, char __user *buffer,
			   size_t count, loff_t *pos)
{
	struct hisi_qm *qm = filp->private_data;
	char buf[QM_DBG_READ_LEN];
	int val, cp_len, len;

	if (*pos)
		return 0;

	if (count < QM_DBG_READ_LEN)
		return -ENOSPC;

	val = atomic_read(&qm->status.flags);
	len = snprintf(buf, QM_DBG_READ_LEN, "%s\n", qm_s[val]);
	if (!len)
		return -EFAULT;

	cp_len = copy_to_user(buffer, buf, len);
	if (cp_len)
		return -EFAULT;

	return (*pos = len);
}


static const struct file_operations qm_status_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = qm_status_read,
};

static int qm_debugfs_atomic64_set(void *data, u64 val)
{
	if (!val)
		atomic64_set((atomic64_t *)data, 0);
	else
		return -EINVAL;

	return 0;
}

static int qm_debugfs_atomic64_get(void *data, u64 *val)
{
	*val = atomic64_read((atomic64_t *)data);

	return 0;
}

DEFINE_DEBUGFS_ATTRIBUTE(qm_atomic64_ops, qm_debugfs_atomic64_get,
			qm_debugfs_atomic64_set, "%llu\n");

/**
 * hisi_qm_debug_init() - Initialize qm related debugfs files.
 * @qm: The qm for which we want to add debugfs files.
 *
 * Create qm related debugfs files.
 */
int hisi_qm_debug_init(struct hisi_qm *qm)
{
	struct qm_dfx *dfx = &qm->debug.dfx;
	struct dentry *qm_d;
	void *data;
	int i, ret;

	qm_d = debugfs_create_dir("qm", qm->debug.debug_root);
	if (IS_ERR(qm_d))
		return -ENOENT;
	qm->debug.qm_d = qm_d;

	/* only show this in PF */
	if (qm->fun_type == QM_HW_PF)
		for (i = CURRENT_Q; i < DEBUG_FILE_NUM; i++)
			if (qm_create_debugfs_file(qm, i)) {
				ret = -ENOENT;
				goto failed_to_create;
			}

	debugfs_create_file("regs", 0444, qm->debug.qm_d, qm, &qm_regs_fops);

	debugfs_create_file("cmd", 0444, qm->debug.qm_d, qm, &qm_cmd_fops);

	debugfs_create_file("status", 0444, qm->debug.qm_d, qm,
			&qm_status_fops);

	for (i = 0; i < ARRAY_SIZE(qm_dfx_files); i++) {
		data = (atomic64_t *)((uintptr_t)dfx + qm_dfx_files[i].offset);
		debugfs_create_file(qm_dfx_files[i].name,
			0644,
			qm_d,
			data,
			&qm_atomic64_ops);
	}

	return 0;

failed_to_create:
	debugfs_remove_recursive(qm_d);
	return ret;
}
EXPORT_SYMBOL_GPL(hisi_qm_debug_init);

/**
 * qm_hw_error_init() - Configure qm hardware error report method.
 * @qm: The qm which we want to configure.
 * @ce: Correctable error configure.
 * @nfe: Non-fatal error configure.
 * @fe: Fatal error configure.
 * @msi: Error reported by message signal interrupt.
 *
 * Hardware errors of qm can be reported either by RAS interrupts which will
 * be handled by UEFI and then PCIe AER or by device MSI. User can configure
 * each error to use either of above two methods. For RAS interrupts, we can
 * configure an error as one of correctable error, non-fatal error or
 * fatal error.
 *
 * Bits indicating errors can be configured to ce, nfe, fe and msi to enable
 * related report methods. Error report will be masked if related error bit
 * does not configure.
 */
static void qm_hw_error_init(struct hisi_qm *qm)
{
	u32 nfe = qm->err_ini.err_info.nfe;
	u32 msi = qm->err_ini.err_info.msi;
	u32 ce = qm->err_ini.err_info.ce;
	u32 fe = qm->err_ini.err_info.fe;

	if (!qm->ops->hw_error_init) {
		dev_err(&qm->pdev->dev,
			"QM version %d doesn't support hw error handling!\n",
			qm->ver);
		return;
	}

	qm->ops->hw_error_init(qm, ce, nfe, fe, msi);
}

static void qm_hw_error_uninit(struct hisi_qm *qm)
{
	if (!qm->ops->hw_error_uninit) {
		dev_err(&qm->pdev->dev,
			"QM version %d doesn't support hw error handling!\n",
			qm->ver);
		return;
	}

	qm->ops->hw_error_uninit(qm);
}

/**
 * qm_hw_error_handle() - Handle qm non-fatal hardware errors.
 * @qm: The qm which has non-fatal hardware errors.
 *
 * Accelerators use this function to handle qm non-fatal hardware errors.
 */
static pci_ers_result_t qm_hw_error_handle(struct hisi_qm *qm)
{
	if (!qm->ops->hw_error_handle) {
		dev_err(&qm->pdev->dev,
			"QM version %d doesn't support hw error report!\n",
			qm->ver);
		return PCI_ERS_RESULT_NONE;
	}

	return qm->ops->hw_error_handle(qm);
}

static int qm_get_hw_error_status(struct hisi_qm *qm)
{
	u32 err_sts;

	err_sts = readl(qm->io_base + QM_ABNORMAL_INT_STATUS) & QM_ECC_MBIT;
	if (err_sts)
		return err_sts;

	return 0;
}

static int qm_reg_test(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;
	int ret;
	u32 val;

	writel(VENDOR_ID_TEST_VALUE, qm->io_base + QM_PEH_VENDOR_ID);
	ret = readl_relaxed_poll_timeout(qm->io_base + QM_PEH_VENDOR_ID, val,
					 (val == VENDOR_ID_TEST_VALUE),
					 POLL_PERIOD, POLL_TIMEOUT);
	if (ret) {
		dev_err(&pdev->dev, "Fails to read QM reg!\n");
		return ret;
	}

	writel(PCI_VENDOR_ID_HUAWEI, qm->io_base + QM_PEH_VENDOR_ID);
	ret = readl_relaxed_poll_timeout(qm->io_base + QM_PEH_VENDOR_ID, val,
					 (val == PCI_VENDOR_ID_HUAWEI),
					 POLL_PERIOD, POLL_TIMEOUT);
	if (ret)
		dev_err(&pdev->dev, "Fails to read QM reg in the second time!\n");

	return ret;
}

static int qm_set_pf_mse(struct hisi_qm *qm, bool set)
{
	struct pci_dev *pdev = qm->pdev;
	u16 cmd;
	int i;

	pci_read_config_word(pdev, PCI_COMMAND, &cmd);
	if (set)
		cmd |= PCI_COMMAND_MEMORY;
	else
		cmd &= ~PCI_COMMAND_MEMORY;

	pci_write_config_word(pdev, PCI_COMMAND, cmd);
	for (i = 0; i < MAX_WAIT_COUNTS; i++) {
		pci_read_config_word(pdev, PCI_COMMAND, &cmd);
		if (set == ((cmd & PCI_COMMAND_MEMORY) >> 1))
			return 0;

		udelay(1);
	}

	return -ETIMEDOUT;
}

static int qm_set_vf_mse(struct hisi_qm *qm, bool set)
{
	struct pci_dev *pdev = qm->pdev;
	u16 sriov_ctrl;
	int pos;
	int i;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	pci_read_config_word(pdev, pos + PCI_SRIOV_CTRL, &sriov_ctrl);
	if (set)
		sriov_ctrl |= PCI_SRIOV_CTRL_MSE;
	else
		sriov_ctrl &= ~PCI_SRIOV_CTRL_MSE;
	pci_write_config_word(pdev, pos + PCI_SRIOV_CTRL, sriov_ctrl);

	for (i = 0; i < MAX_WAIT_COUNTS; i++) {
		pci_read_config_word(pdev, pos + PCI_SRIOV_CTRL, &sriov_ctrl);
		if (set == (sriov_ctrl & PCI_SRIOV_CTRL_MSE) >>
		    PEH_SRIOV_CTRL_VF_MSE_SHIFT)
			return 0;

		udelay(1);
	}

	return -ETIMEDOUT;
}

static int qm_set_msi(struct hisi_qm *qm, bool set)
{
	struct pci_dev *pdev = qm->pdev;

	if (set) {
		pci_write_config_dword(pdev, pdev->msi_cap +
				       PCI_MSI_MASK_64, 0);
	} else {
		pci_write_config_dword(pdev, pdev->msi_cap +
				       PCI_MSI_MASK_64, PEH_MSI_DISABLE);
		if (qm->err_ini.err_info.is_qm_ecc_mbit ||
			qm->err_ini.err_info.is_dev_ecc_mbit)
			return 0;

		mdelay(1);
		if (readl(qm->io_base + QM_PEH_DFX_INFO0))
			return -EFAULT;
	}

	return 0;
}

void hisi_qm_free_qps(struct hisi_qp **qps, int qp_num)
{
	int i;

	if (!qps || qp_num < 0)
		return;

	for (i = qp_num - 1; i >= 0; i--)
		hisi_qm_release_qp(qps[i]);
}
EXPORT_SYMBOL_GPL(hisi_qm_free_qps);

static void free_list(struct list_head *head)
{
	struct hisi_qm_resource *res, *tmp;

	list_for_each_entry_safe(res, tmp, head, list) {
		list_del(&res->list);
		kfree(res);
	}
}

static int hisi_qm_sort_devices(int node, struct list_head *head,
					struct hisi_qm_list *qm_list)
{
	struct hisi_qm_resource *res, *tmp;
	struct hisi_qm *qm;
	struct list_head *n;
	struct device *dev;
	int dev_node = 0;

	list_for_each_entry(qm, &qm_list->list, list) {
		dev = &qm->pdev->dev;

		if (IS_ENABLED(CONFIG_NUMA)) {
			dev_node = dev->numa_node;
			if (dev_node < 0)
				dev_node = 0;
		}

		if (qm_list->check && !qm_list->check(qm))
			continue;

		res = kzalloc(sizeof(*res), GFP_KERNEL);
		if (!res)
			return -ENOMEM;

		res->qm = qm;
		res->distance = node_distance(dev_node, node);
		n = head;
		list_for_each_entry(tmp, head, list) {
			if (res->distance < tmp->distance) {
				n = &tmp->list;
				break;
			}
		}
		list_add_tail(&res->list, n);
	}

	return 0;
}

int hisi_qm_alloc_qps_node(int node, struct hisi_qm_list *qm_list,
				struct hisi_qp **qps, int qp_num, u8 alg_type)
{
	struct hisi_qm_resource *tmp;
	int ret = -ENODEV;
	LIST_HEAD(head);
	int i;

	if (!qps || !qm_list || qp_num <= 0)
		return -EINVAL;

	mutex_lock(&qm_list->lock);
	if (hisi_qm_sort_devices(node, &head, qm_list)) {
		mutex_unlock(&qm_list->lock);
		goto err;
	}

	list_for_each_entry(tmp, &head, list) {
		for (i = 0; i < qp_num; i++) {
			qps[i] = hisi_qm_create_qp(tmp->qm, alg_type);
			if (IS_ERR(qps[i])) {
				hisi_qm_free_qps(qps, i);
				break;
			}
		}

		if (i == qp_num) {
			ret = 0;
			break;
		}
	}

	mutex_unlock(&qm_list->lock);
	if (ret)
		pr_info("Failed to create qps, node[%d], alg[%d], qp[%d]!\n",
			node, alg_type, qp_num);

err:
	free_list(&head);
	return ret;
}
EXPORT_SYMBOL_GPL(hisi_qm_alloc_qps_node);

static int qm_vf_q_assign(struct hisi_qm *qm, u32 num_vfs)
{
	u32 q_num, i, remain_q_num;
	u32 q_base = qm->qp_num;
	int ret;

	if (!num_vfs)
		return -EINVAL;

	remain_q_num = qm->ctrl_q_num - qm->qp_num;

	/* If remain queues not enough, return error. */
	if (qm->ctrl_q_num < qm->qp_num || remain_q_num < num_vfs)
		return -EINVAL;

	q_num = remain_q_num / num_vfs;
	for (i = 1; i <= num_vfs; i++) {
		if (i == num_vfs)
			q_num += remain_q_num % num_vfs;
		ret = hisi_qm_set_vft(qm, i, q_base, q_num);
		if (ret)
			return ret;
		q_base += q_num;
	}

	return 0;
}

static int qm_clear_vft_config(struct hisi_qm *qm)
{
	int ret;
	u32 i;

	for (i = 1; i <= qm->vfs_num; i++) {
		ret = hisi_qm_set_vft(qm, i, 0, 0);
		if (ret)
			return ret;
	}
	qm->vfs_num = 0;

	return 0;
}

int hisi_qm_sriov_enable(struct pci_dev *pdev, int max_vfs)
{
	struct hisi_qm *qm = pci_get_drvdata(pdev);
	int pre_existing_vfs, num_vfs, ret;
	int total_vfs;

	total_vfs = pci_sriov_get_totalvfs(pdev);
	pre_existing_vfs = pci_num_vf(pdev);
	if (pre_existing_vfs) {
		pci_err(pdev,
			"Can't enable VF. Please disable pre-enabled VFs!\n");
		return 0;
	}

	num_vfs = min_t(int, max_vfs, total_vfs);
	ret = qm_vf_q_assign(qm, num_vfs);
	if (ret) {
		pci_err(pdev, "Can't assign queues for VF!\n");
		return ret;
	}

	qm->vfs_num = num_vfs;

	ret = pci_enable_sriov(pdev, num_vfs);
	if (ret) {
		pci_err(pdev, "Can't enable VF!\n");
		qm_clear_vft_config(qm);
		return ret;
	}

	pci_info(pdev, "VF enabled, vfs_num(=%d)!\n", num_vfs);

	return num_vfs;
}
EXPORT_SYMBOL_GPL(hisi_qm_sriov_enable);

int hisi_qm_sriov_disable(struct pci_dev *pdev, struct hisi_qm_list *qm_list)
{
	struct hisi_qm *qm = pci_get_drvdata(pdev);

	if (pci_vfs_assigned(pdev)) {
		pci_err(pdev, "Failed to disable VFs as VFs are assigned!\n");
		return -EPERM;
	}

	/* While VF is in used, SRIOV cannot be disabled.
	 * However, there is a risk that the behavior is uncertain if the
	 * device is in hardware resetting.
	 */
	if (qm_list && qm_try_frozen_vfs(pdev, qm_list)) {
		pci_err(pdev, "Uacce user space task is using its VF!\n");
		return -EBUSY;
	}

	/* remove in hpre_pci_driver will be called to free VF resources */
	pci_disable_sriov(pdev);
	return qm_clear_vft_config(qm);
}
EXPORT_SYMBOL_GPL(hisi_qm_sriov_disable);

void hisi_qm_dev_err_init(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;
	struct hisi_qm *pf_qm = pci_get_drvdata(pci_physfn(pdev));

	if (pf_qm->fun_type == QM_HW_VF)
		return;

	qm_hw_error_init(pf_qm);
	pf_qm->err_ini.hw_err_enable(pf_qm);
}
EXPORT_SYMBOL_GPL(hisi_qm_dev_err_init);

/**
 * hisi_qm_dev_err_uninit() - Uninitialize device error configuration.
 * @qm: The qm for which we want to do error uninitialization.
 *
 * Uninitialize QM and device error related configuration, It may called
 * by PF/VF, the caller should ensure the scene explicilty.
 */
void hisi_qm_dev_err_uninit(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;
	struct hisi_qm *pf_qm = pci_get_drvdata(pci_physfn(pdev));

	if (pf_qm->fun_type == QM_HW_VF)
		return;

	qm_hw_error_uninit(pf_qm);
	pf_qm->err_ini.hw_err_disable(pf_qm);
}
EXPORT_SYMBOL_GPL(hisi_qm_dev_err_uninit);

static pci_ers_result_t qm_dev_err_handle(struct hisi_qm *qm)
{
	u32 err_sts;

	/* read err sts */
	err_sts = qm->err_ini.get_dev_hw_err_status(qm);
	if (err_sts) {
		if (err_sts & qm->err_ini.err_info.ecc_2bits_mask)
			qm->err_ini.err_info.is_dev_ecc_mbit = true;

		qm->err_ini.log_dev_hw_err(qm, err_sts);
		return PCI_ERS_RESULT_NEED_RESET;
	}

	return PCI_ERS_RESULT_RECOVERED;
}

pci_ers_result_t hisi_qm_process_dev_error(struct pci_dev *pdev)
{
	struct hisi_qm *qm = pci_get_drvdata(pdev);
	pci_ers_result_t qm_ret, dev_ret;

	/* log qm error */
	qm_ret = qm_hw_error_handle(qm);

	/* log device error */
	dev_ret = qm_dev_err_handle(qm);

	return (qm_ret == PCI_ERS_RESULT_NEED_RESET ||
		dev_ret == PCI_ERS_RESULT_NEED_RESET) ?
		PCI_ERS_RESULT_NEED_RESET : PCI_ERS_RESULT_RECOVERED;
}
EXPORT_SYMBOL_GPL(hisi_qm_process_dev_error);

pci_ers_result_t hisi_qm_dev_err_detected(struct pci_dev *pdev,
					  pci_channel_state_t state)
{
	if (pdev->is_virtfn)
		return PCI_ERS_RESULT_NONE;

	pci_info(pdev, "PCI error detected, state(=%d)!!\n", state);
	if (state == pci_channel_io_perm_failure)
		return PCI_ERS_RESULT_DISCONNECT;

	return hisi_qm_process_dev_error(pdev);
}
EXPORT_SYMBOL_GPL(hisi_qm_dev_err_detected);

static int qm_vf_reset_prepare(struct pci_dev *pdev,
			       struct hisi_qm_list *qm_list,
			       enum qm_stop_reason stop_reason)
{
	struct pci_dev *dev;
	struct hisi_qm *qm;
	int ret = 0;

	mutex_lock(&qm_list->lock);
	list_for_each_entry(qm, &qm_list->list, list) {
		dev = qm->pdev;
		if (dev == pdev)
			continue;

		if (pci_physfn(dev) == pdev) {
			/* save VFs PCIE BAR configuration */
			pci_save_state(dev);

			ret = hisi_qm_stop(qm, stop_reason);
			if (ret) {
				hisi_qm_set_hw_reset(qm,
						QM_RESET_STOP_TX_OFFSET);
				hisi_qm_set_hw_reset(qm,
						QM_RESET_STOP_RX_OFFSET);
				atomic_set(&qm->status.flags, QM_STOP);
			}
		}
	}

	mutex_unlock(&qm_list->lock);
	return ret;
}

static int qm_reset_prepare_ready(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;
	struct hisi_qm *pf_qm = pci_get_drvdata(pci_physfn(pdev));
	int delay = 0;

	while (test_and_set_bit(QM_DEV_RESET_STATUS, &pf_qm->hw_status)) {
		msleep(++delay);
		if (delay > QM_RESET_WAIT_TIMEOUT)
			return -EBUSY;
	}

	return 0;
}

static int qm_controller_reset_prepare(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;
	int ret;

	ret = qm_reset_prepare_ready(qm);
	if (ret) {
		pci_err(pdev, "Controller reset not ready!\n");
		return ret;
	}

	if (qm->vfs_num) {
		ret = qm_vf_reset_prepare(pdev, qm->qm_list, QM_SOFT_RESET);
		if (ret) {
			pci_err(pdev, "Fails to stop VFs!\n");
			return ret;
		}
	}

	ret = hisi_qm_stop(qm, QM_SOFT_RESET);
	if (ret) {
		pci_err(pdev, "Fails to stop QM!\n");
		return ret;
	}

	if (qm->use_uacce) {
		ret = uacce_hw_err_isolate(&qm->uacce);
		if (ret) {
			pci_err(pdev, "Fails to isolate hw err!\n");
			return ret;
		}
	}

	return 0;
}

static void qm_dev_ecc_mbit_handle(struct hisi_qm *qm)
{
	u32 nfe_enb = 0;

	if (!qm->err_ini.err_info.is_dev_ecc_mbit &&
		qm->err_ini.err_info.is_qm_ecc_mbit &&
		qm->err_ini.close_axi_master_ooo) {

		qm->err_ini.close_axi_master_ooo(qm);

	} else if (qm->err_ini.err_info.is_dev_ecc_mbit &&
		!qm->err_ini.err_info.is_qm_ecc_mbit &&
		!qm->err_ini.close_axi_master_ooo) {

		nfe_enb = readl(qm->io_base + QM_RAS_NFE_ENABLE);
		writel(nfe_enb & QM_RAS_NFE_MBIT_DISABLE,
		       qm->io_base + QM_RAS_NFE_ENABLE);
		writel(QM_ECC_MBIT, qm->io_base + QM_PF_ABNORMAL_INT_SET);
	}
}

static int qm_soft_reset(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;
	int ret;
	u32 val;

	ret = qm_reg_test(qm);
	if (ret)
		return ret;

	if (qm->vfs_num) {
		ret = qm_set_vf_mse(qm, false);
		if (ret) {
			pci_err(pdev, "Fails to disable vf mse bit.\n");
			return ret;
		}
	}

	ret = qm_set_msi(qm, false);
	if (ret) {
		pci_err(pdev, "Fails to disable peh msi bit.\n");
		return ret;
	}

	qm_dev_ecc_mbit_handle(qm);

	/* OOO register set and check */
	writel(MASTER_GLOBAL_CTRL_SHUTDOWN, qm->io_base + MASTER_GLOBAL_CTRL);

	/* If bus lock, reset chip */
	ret = readl_relaxed_poll_timeout(qm->io_base + MASTER_TRANS_RETURN,
					val, (val == MASTER_TRANS_RETURN_RW),
					QM_REG_RD_INTVRL_US,
					QM_REG_RD_TMOUT_US);
	if (ret) {
		pci_emerg(pdev, "Bus lock! Please reset system.\n");
		return ret;
	}

	ret = qm_set_pf_mse(qm, false);
	if (ret) {
		pci_err(pdev, "Fails to disable pf mse bit.\n");
		return ret;
	}

	/* The reset related sub-control registers are not in PCI BAR */
	if (ACPI_HANDLE(&pdev->dev)) {
		unsigned long long value = 0;
		acpi_status s;

		s = acpi_evaluate_integer(ACPI_HANDLE(&pdev->dev),
					  qm->err_ini.err_info.acpi_rst,
					  NULL, &value);
		if (ACPI_FAILURE(s)) {
			pci_err(pdev, "NO controller reset method!\n");
			return -EIO;
		}

		if (value) {
			pci_err(pdev, "Reset step %llu failed!\n", value);
			return -EIO;
		}
	} else {
		pci_err(pdev, "No reset method!\n");
		return -EINVAL;
	}

	return 0;
}

static int qm_vf_reset_done(struct pci_dev *pdev,
		struct hisi_qm_list *qm_list)
{
	struct pci_dev *dev;
	struct hisi_qm *qm;
	int ret = 0;

	mutex_lock(&qm_list->lock);
	list_for_each_entry(qm, &qm_list->list, list) {
		dev = qm->pdev;
		if (dev == pdev)
			continue;

		if (pci_physfn(dev) == pdev) {
			/* enable VFs PCIE BAR configuration */
			pci_restore_state(dev);

			ret = hisi_qm_restart(qm);
			if (ret)
				goto reset_fail;
		}
	}

reset_fail:
	mutex_unlock(&qm_list->lock);
	return ret;
}

static int qm_get_dev_err_status(struct hisi_qm *qm)
{
	u32 err_sts;

	err_sts = qm->err_ini.get_dev_hw_err_status(qm) &
		  qm->err_ini.err_info.ecc_2bits_mask;
	if (err_sts)
		return err_sts;

	return 0;
}

static void hisi_qm_restart_prepare(struct hisi_qm *qm)
{
	u32 value;

	if (!qm->err_ini.err_info.is_qm_ecc_mbit &&
		!qm->err_ini.err_info.is_dev_ecc_mbit)
		return;

	value = readl(qm->io_base + AM_CFG_PORT_WR_EN);
	writel(value & ~qm->err_ini.err_info.msi_wr_port,
	       qm->io_base + AM_CFG_PORT_WR_EN);

	/* clear dev ecc 2bit error source if having */
	value = qm_get_dev_err_status(qm);
	if (value && qm->err_ini.clear_dev_hw_err_status)
		qm->err_ini.clear_dev_hw_err_status(qm, value);

	/* clear QM ecc mbit error source */
	writel(QM_ECC_MBIT, qm->io_base +
	       QM_ABNORMAL_INT_SOURCE);

	/* clear AM Reorder Buffer ecc mbit source */
	writel(ROB_ECC_ERR_MULTPL, qm->io_base +
	       AM_ROB_ECC_INT_STS);

	if (qm->err_ini.open_axi_master_ooo)
		qm->err_ini.open_axi_master_ooo(qm);
}

static void hisi_qm_restart_done(struct hisi_qm *qm)
{
	u32 value;

	if (!qm->err_ini.err_info.is_qm_ecc_mbit &&
		!qm->err_ini.err_info.is_dev_ecc_mbit)
		return;

	value = readl(qm->io_base + AM_CFG_PORT_WR_EN);
	value |= qm->err_ini.err_info.msi_wr_port;

	writel(value, qm->io_base + AM_CFG_PORT_WR_EN);
	qm->err_ini.err_info.is_qm_ecc_mbit = false;
	qm->err_ini.err_info.is_dev_ecc_mbit = false;
}

static int qm_controller_reset_done(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;
	int ret;

	ret = qm_set_msi(qm, true);
	if (ret) {
		pci_err(pdev, "Fails to enable peh msi bit!\n");
		return ret;
	}

	ret = qm_set_pf_mse(qm, true);
	if (ret) {
		pci_err(pdev, "Fails to enable pf mse bit!\n");
		return ret;
	}

	if (qm->vfs_num) {
		ret = qm_set_vf_mse(qm, true);
		if (ret) {
			pci_err(pdev, "Fails to enable vf mse bit!\n");
			return ret;
		}
	}

	ret = qm->err_ini.set_usr_domain_cache(qm);
	if (ret)
		return ret;

	hisi_qm_restart_prepare(qm);

	ret = hisi_qm_restart(qm);
	if (ret) {
		pci_err(pdev, "Failed to start QM!\n");
		return ret;
	}

	if (qm->vfs_num) {
		ret = qm_vf_q_assign(qm, qm->vfs_num);
		if (ret) {
			pci_err(pdev, "Failed to assign queue!\n");
			return ret;
		}
	}

	ret = qm_vf_reset_done(pdev, qm->qm_list);
	if (ret) {
		pci_err(pdev, "Failed to start VFs!\n");
		return -EPERM;
	}

	hisi_qm_dev_err_init(qm);

	hisi_qm_restart_done(qm);

	return 0;
}

int hisi_qm_controller_reset(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;
	int ret;

	pci_info(pdev, "Controller resetting...\n");

	ret = qm_controller_reset_prepare(qm);
	if (ret)
		goto err_prepare;

	ret = qm_soft_reset(qm);
	if (ret) {
		pci_err(pdev, "Controller reset failed (%d)\n", ret);
		goto err_reset;
	}

	ret = qm_controller_reset_done(qm);
	if (ret)
		goto err_reset;

	clear_bit(QM_DEV_RESET_STATUS, &qm->hw_status);
	pci_info(pdev, "Controller reset complete\n");

	return 0;

err_prepare:
	pci_info(pdev, "Controller reset_prepare failed\n");
	writel(MASTER_GLOBAL_CTRL_SHUTDOWN, qm->io_base + MASTER_GLOBAL_CTRL);
	hisi_qm_set_hw_reset(qm, QM_RESET_STOP_TX_OFFSET);
	hisi_qm_set_hw_reset(qm, QM_RESET_STOP_RX_OFFSET);

err_reset:
	pci_info(pdev, "Controller reset failed\n");
	clear_bit(QM_DEV_RESET_STATUS, &qm->hw_status);
	/* if resetting fails, isolate the device */
	if (qm->use_uacce && !qm->uacce.is_vf)
		atomic_set(&qm->uacce.isolate->is_isolate, 1);

	return ret;
}
EXPORT_SYMBOL_GPL(hisi_qm_controller_reset);

pci_ers_result_t hisi_qm_dev_slot_reset(struct pci_dev *pdev)
{
	struct hisi_qm *qm = pci_get_drvdata(pdev);
	int ret;

	if (pdev->is_virtfn)
		return PCI_ERS_RESULT_RECOVERED;

	pci_info(pdev, "Requesting reset due to PCI error\n");
	pci_cleanup_aer_uncorrect_error_status(pdev);

	/* reset pcie device controller */
	ret = hisi_qm_controller_reset(qm);
	if (ret) {
		pci_err(pdev, "controller reset failed (%d)\n", ret);
		return PCI_ERS_RESULT_DISCONNECT;
	}

	return PCI_ERS_RESULT_RECOVERED;
}
EXPORT_SYMBOL_GPL(hisi_qm_dev_slot_reset);

/* check the interrupt is ecc-mbit error or not */
static int qm_check_dev_error(struct hisi_qm *qm)
{
	struct pci_dev *pdev = qm->pdev;
	struct hisi_qm *pf_qm = pci_get_drvdata(pci_physfn(pdev));
	int ret;

	if (pf_qm->fun_type == QM_HW_VF)
		return 0;

	ret = qm_get_hw_error_status(pf_qm);
	if (ret)
		return ret;

	return qm_get_dev_err_status(pf_qm);
}

void hisi_qm_reset_prepare(struct pci_dev *pdev)
{
	struct hisi_qm *qm = pci_get_drvdata(pdev);
	u32 delay = 0;
	int ret;

	hisi_qm_dev_err_uninit(qm);

	while (qm_check_dev_error(qm)) {
		msleep(++delay);
		if (delay > QM_RESET_WAIT_TIMEOUT)
			return;
	}

	ret = qm_reset_prepare_ready(qm);
	if (ret) {
		pci_err(pdev, "FLR not ready!\n");
		return;
	}

	if (qm->vfs_num) {
		ret = qm_vf_reset_prepare(pdev, qm->qm_list, QM_FLR);
		if (ret)
			pci_err(pdev, "Failed to stop vfs!\n");
	}

	ret = hisi_qm_stop(qm, QM_FLR);
	if (ret) {
		pci_err(pdev, "Failed to stop QM!\n");
		goto err_prepare;
	}

	hisi_qm_cache_wb(qm);
	pci_info(pdev, "FLR resetting...\n");
	return;

err_prepare:
	pci_info(pdev, "FLR resetting prepare failed!\n");
	hisi_qm_set_hw_reset(qm, QM_RESET_STOP_TX_OFFSET);
	hisi_qm_set_hw_reset(qm, QM_RESET_STOP_RX_OFFSET);
	atomic_set(&qm->status.flags, QM_STOP);
	hisi_qm_cache_wb(qm);
}
EXPORT_SYMBOL_GPL(hisi_qm_reset_prepare);

static bool qm_flr_reset_complete(struct pci_dev *pdev)
{
	struct pci_dev *pf_pdev = pci_physfn(pdev);
	struct hisi_qm *qm = pci_get_drvdata(pf_pdev);
	u32 id;

	pci_read_config_dword(qm->pdev, PCI_COMMAND, &id);
	if (id == QM_PCI_COMMAND_INVALID) {
		pci_err(pdev, "Device can not be used!\n");
		return false;
	}

	clear_bit(QM_DEV_RESET_STATUS, &qm->hw_status);
	return true;
}

void hisi_qm_reset_done(struct pci_dev *pdev)
{
	struct hisi_qm *qm = pci_get_drvdata(pdev);
	int ret;

	hisi_qm_dev_err_init(qm);

	ret = hisi_qm_restart(qm);
	if (ret) {
		pci_err(pdev, "Failed to start QM!\n");
		goto flr_done;
	}

	if (qm->fun_type == QM_HW_PF) {
		ret = qm->err_ini.set_usr_domain_cache(qm);
		if (ret) {
			pci_err(pdev, "Failed to start QM!\n");
			goto flr_done;
		}

		if (qm->vfs_num)
			qm_vf_q_assign(qm, qm->vfs_num);

		ret = qm_vf_reset_done(pdev, qm->qm_list);
		if (ret) {
			pci_err(pdev, "Failed to start VFs!\n");
			goto flr_done;
		}
	}

flr_done:
	if (qm_flr_reset_complete(pdev))
		pci_info(pdev, "FLR reset complete\n");
}
EXPORT_SYMBOL_GPL(hisi_qm_reset_done);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Zhou Wang <wangzhou1@hisilicon.com>");
MODULE_DESCRIPTION("HiSilicon Accelerator queue manager driver");
