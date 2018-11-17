// SPDX-License-Identifier: GPL-2.0+
#include <asm/page.h>
#include <linux/bitmap.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/irqreturn.h>
#include <linux/log2.h>
#include "qm.h"

#define QM_DEF_Q_NUM			128

/* eq/aeq irq enable */
#define QM_VF_AEQ_INT_SOURCE		0x0
#define QM_VF_AEQ_INT_MASK		0x4
#define QM_VF_EQ_INT_SOURCE		0x8
#define QM_VF_EQ_INT_MASK		0xc

/* mailbox */
#define MAILBOX_CMD_SQC			0x0
#define MAILBOX_CMD_CQC			0x1
#define MAILBOX_CMD_EQC			0x2
#define MAILBOX_CMD_SQC_BT		0x4
#define MAILBOX_CMD_CQC_BT		0x5

#define MAILBOX_CMD_SEND_BASE		0x300
#define MAILBOX_EVENT_SHIFT		8
#define MAILBOX_STATUS_SHIFT		9
#define MAILBOX_BUSY_SHIFT		13
#define MAILBOX_OP_SHIFT		14
#define MAILBOX_QUEUE_SHIFT		16

/* sqc shift */
#define SQ_HEAD_SHIFT			0
#define SQ_TAIL_SHIFI			16
#define SQ_HOP_NUM_SHIFT		0
#define SQ_PAGE_SIZE_SHIFT		4
#define SQ_BUF_SIZE_SHIFT		8
#define SQ_SQE_SIZE_SHIFT		12
#define SQ_HEAD_IDX_SIG_SHIFT		0
#define SQ_TAIL_IDX_SIG_SHIFT		0
#define SQ_CQN_SHIFT			0
#define SQ_PRIORITY_SHIFT		0
#define SQ_ORDERS_SHIFT			4
#define SQ_TYPE_SHIFT			8

#define SQ_TYPE_MASK			0xf

/* cqc shift */
#define CQ_HEAD_SHIFT			0
#define CQ_TAIL_SHIFI			16
#define CQ_HOP_NUM_SHIFT		0
#define CQ_PAGE_SIZE_SHIFT		4
#define CQ_BUF_SIZE_SHIFT		8
#define CQ_SQE_SIZE_SHIFT		12
#define CQ_PASID			0
#define CQ_HEAD_IDX_SIG_SHIFT		0
#define CQ_TAIL_IDX_SIG_SHIFT		0
#define CQ_CQN_SHIFT			0
#define CQ_PRIORITY_SHIFT		16
#define CQ_ORDERS_SHIFT			0
#define CQ_TYPE_SHIFT			0
#define CQ_PHASE_SHIFT			0
#define CQ_FLAG_SHIFT			1

#define CQC_HEAD_INDEX(cqc)		((cqc)->cq_head)
#define CQC_PHASE(cqc)			(((cqc)->dw6) & 0x1)
#define CQC_CQ_ADDRESS(cqc)		(((u64)((cqc)->cq_base_h) << 32) | \
					 ((cqc)->cq_base_l))
#define CQC_PHASE_BIT			0x1

/* eqc shift */
#define MB_EQC_EQE_SHIFT		12
#define MB_EQC_PHASE_SHIFT		16

#define EQC_HEAD_INDEX(eqc)		((eqc)->eq_head)
#define EQC_TAIL_INDEX(eqc)		((eqc)->eq_tail)
#define EQC_PHASE(eqc)			((((eqc)->dw6) >> 16) & 0x1)

#define EQC_PHASE_BIT			0x00010000

/* cqe shift */
#define CQE_PHASE(cqe)			((cqe)->w7 & 0x1)
#define CQE_SQ_NUM(cqe)			((cqe)->sq_num)
#define CQE_SQ_HEAD_INDEX(cqe)		((cqe)->sq_head)

/* eqe shift */
#define EQE_PHASE(eqe)			(((eqe)->dw0 >> 16) & 0x1)
#define EQE_CQN(eqe)			(((eqe)->dw0) & 0xffff)

#define QM_EQE_CQN_MASK			0xffff

/* doorbell */
#define DOORBELL_CMD_SQ			0
#define DOORBELL_CMD_CQ			1
#define DOORBELL_CMD_EQ			2
#define DOORBELL_CMD_AEQ		3

#define DOORBELL_CMD_SEND_BASE_V1	0x340
#define DOORBELL_CMD_SEND_BASE_V2	0x1000
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
#define QM_SQC_VFT_BT_INDEX_SHIFT	22
#define QM_SQC_VFT_START_SQN_SHIFT	28
#define QM_SQC_VFT_VALID		(1ULL << 44)
#define QM_SQC_VFT_SQN_SHIFT		45
#define QM_CQC_VFT_BUF_SIZE		(7ULL << 8)
#define QM_CQC_VFT_SQC_SIZE		(5ULL << 12)
#define QM_CQC_VFT_INDEX_NUMBER		(1ULL << 16)
#define QM_CQC_VFT_BT_INDEX_SHIFT	22
#define QM_CQC_VFT_VALID		(1ULL << 28)

struct cqe {
	__le32 rsvd0;
	__le16 cmd_id;
	__le16 rsvd1;
	__le16 sq_head;
	__le16 sq_num;
	__le16 rsvd2;
	__le16 w7;
};

struct eqe {
	__le32 dw0;
};

struct sqc {
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

struct cqc {
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

#define INIT_QC(qc, base) do { \
	(qc)->head = 0; \
	(qc)->tail = 0; \
	(qc)->base_l = lower_32_bits(base); \
	(qc)->base_h = upper_32_bits(base); \
	(qc)->pasid = 0; \
	(qc)->w11 = 0; \
	(qc)->rsvd1 = 0; \
} while (0)

struct eqc {
	__le16 head;
	__le16 tail;
	__le32 base_l;
	__le32 base_h;
	__le32 dw3;
	__le32 rsvd[2];
	__le32 dw6;
};

struct mailbox {
	__le16 w0;
	__le16 queue_num;
	__le32 base_l;
	__le32 base_h;
	__le32 rsvd;
};

struct doorbell {
	__le16 queue_num;
	__le16 cmd;
	__le16 index;
	__le16 priority;
};

#define QM_DMA_BUF(p, buf) ((struct buf *)(p)->buf.addr)
#define QM_SQC(p) QM_DMA_BUF(p, sqc)
#define QM_CQC(p) QM_DMA_BUF(p, cqc)
#define QM_EQC(p) QM_DMA_BUF(p, eqc)
#define QM_EQE(p) QM_DMA_BUF(p, eqe)

#define QP_SQE_DMA(qp) ((qp)->scqe.dma)
#define QP_CQE(qp) ((struct cqe *)((qp)->scqe.addr + \
				   qp->qm->sqe_size * QM_Q_DEPTH))
#define QP_CQE_DMA(qp) ((qp)->scqe.dma + qp->qm->sqe_size * QM_Q_DEPTH)

static inline void qm_writel(struct qm_info *qm, u32 val, u32 offset)
{
	writel(val, qm->io_base + offset);
}

struct qm_info;

struct hisi_acc_qm_hw_ops {
	int (*vft_config)(struct qm_info *qm, u16 base, u32 number);
	int (*qm_start_qp)(struct hisi_qp *qp, unsigned long arg);
	void (*qm_db)(struct qm_info *qm, u16 qn,
			u8 cmd, u16 index, u8 priority);
};

static inline int hacc_qm_mb_is_busy(struct qm_info *qm)
{
	u32 val;

	return readl_relaxed_poll_timeout(QM_ADDR(qm, MAILBOX_CMD_SEND_BASE),
		val, !((val >> MAILBOX_BUSY_SHIFT) & 0x1), 10, 1000);
}

static inline void qm_mb_write(struct qm_info *qm, void *src)
{
	void __iomem *fun_base = QM_ADDR(qm, MAILBOX_CMD_SEND_BASE);
	unsigned long tmp0 = 0, tmp1 = 0;

	asm volatile("ldp %0, %1, %3\n"
		     "stp %0, %1, %2\n"
		     "dsb sy\n"
		     : "=&r" (tmp0),
		       "=&r" (tmp1),
		       "+Q" (*((char *)fun_base))
		     : "Q" (*((char *)src))
		     : "memory");
}

static int qm_mb(struct qm_info *qm, u8 cmd, dma_addr_t dma_addr, u16 queue,
		 bool op, bool event)
{
	struct mailbox mailbox;
	int i = 0;
	int ret = 0;

	memset(&mailbox, 0, sizeof(struct mailbox));

	mailbox.w0 = cmd |
		     (event ? 0x1 << MAILBOX_EVENT_SHIFT : 0) |
		     (op ? 0x1 << MAILBOX_OP_SHIFT : 0) |
		     (0x1 << MAILBOX_BUSY_SHIFT);
	mailbox.queue_num = queue;
	mailbox.base_l = lower_32_bits(dma_addr);
	mailbox.base_h = upper_32_bits(dma_addr);
	mailbox.rsvd = 0;

	mutex_lock(&qm->mailbox_lock);

	while (hacc_qm_mb_is_busy(qm) && i < 10)
		i++;
	if (i >= 10) {
		ret = -EBUSY;
		dev_err(&qm->pdev->dev, "QM mail box is busy!");
		goto busy_unlock;
	}
	qm_mb_write(qm, &mailbox);
	i = 0;
	while (hacc_qm_mb_is_busy(qm) && i < 10)
		i++;
	if (i >= 10) {
		ret = -EBUSY;
		dev_err(&qm->pdev->dev, "QM mail box is still busy!");
		goto busy_unlock;
	}

busy_unlock:
	mutex_unlock(&qm->mailbox_lock);

	return ret;
}

static void qm_db_v1(struct qm_info *qm, u16 qn, u8 cmd, u16 index, u8 priority)
{
	u64 doorbell = 0;

	doorbell = (u64)qn | ((u64)cmd << 16);
	doorbell |= ((u64)index | ((u64)priority << 16)) << 32;

	writeq(doorbell, QM_ADDR(qm, DOORBELL_CMD_SEND_BASE_V1));
}

static void qm_db_v2(struct qm_info *qm, u16 qn, u8 cmd, u16 index, u8 priority)
{
	u64 doorbell = 0;
	u16 randate = 0;

	doorbell = (u64)qn | ((u64)cmd << 12) | ((u64)randate << 16);
	doorbell |= ((u64)index | ((u64)priority << 16)) << 32;

	writeq(doorbell, QM_ADDR(qm, DOORBELL_CMD_SEND_BASE_V2));
}

static void qm_db(struct qm_info *qm, u16 qn, u8 cmd, u16 index, u8 priority)
{
	qm->ops->qm_db(qm, qn, cmd, index, priority);
}

/* @return 0 - cq/eq event, 1 - async event, 2 - abnormal error */
static u32 qm_get_irq_source(struct qm_info *qm)
{
	return readl(QM_ADDR(qm, QM_VF_EQ_INT_SOURCE));
}

static inline struct hisi_qp *to_hisi_qp(struct qm_info *qm, struct eqe *eqe)
{
	u16 cqn = eqe->dw0 & QM_EQE_CQN_MASK;
	struct hisi_qp *qp;

	read_lock(&qm->qps_lock);
	qp = qm->qp_array[cqn];
	read_unlock(&qm->qps_lock);

	return qp;
}

static inline void qm_cq_head_update(struct hisi_qp *qp)
{
	if (qp->qp_status.cq_head == QM_Q_DEPTH - 1) {
		QM_CQC(qp)->dw6 = QM_CQC(qp)->dw6 ^ CQC_PHASE_BIT;
		qp->qp_status.cq_head = 0;
	} else {
		qp->qp_status.cq_head++;
	}
}

static inline void qm_poll_qp(struct hisi_qp *qp, struct qm_info *qm)
{
	struct cqe *cqe;

	cqe = QP_CQE(qp) + qp->qp_status.cq_head;

	if (qp->req_cb) {
		while (CQE_PHASE(cqe) == CQC_PHASE(QM_CQC(qp))) {
			dma_rmb();
			qp->req_cb(qp, QP_SQE_ADDR(qp) +
				   qm->sqe_size *
				   CQE_SQ_HEAD_INDEX(cqe));
			qm_cq_head_update(qp);
			cqe = QP_CQE(qp) + qp->qp_status.cq_head;
		}
	} else if (qp->event_cb) {
		dma_rmb();
		qp->event_cb(qp);
		qm_cq_head_update(qp);
		cqe = QP_CQE(qp) + qp->qp_status.cq_head;
	} else {
		dma_rmb();
		qm_cq_head_update(qp);
		cqe = QP_CQE(qp) + qp->qp_status.cq_head;
	}

	qm_db(qm, qp->queue_id, DOORBELL_CMD_CQ, qp->qp_status.cq_head, 0);

	/* set c_flag */
	qm_db(qm, qp->queue_id, DOORBELL_CMD_CQ, qp->qp_status.cq_head, 1);
}

static irqreturn_t qm_irq_thread(int irq, void *data)
{
	struct qm_info *qm = data;
	struct eqe *eqe = QM_EQE(qm) + qm->eq_head;
	struct eqc *eqc = QM_EQC(qm);
	struct hisi_qp *qp;

	while (EQE_PHASE(eqe) == EQC_PHASE(eqc)) {
		qp = to_hisi_qp(qm, eqe);
		if (qp)
			qm_poll_qp(qp, qm);

		if (qm->eq_head == QM_Q_DEPTH - 1) {
			eqc->dw6 = eqc->dw6 ^ EQC_PHASE_BIT;
			eqe = QM_EQE(qm);
			qm->eq_head = 0;
		} else {
			eqe++;
			qm->eq_head++;
		}
	}

	qm_db(qm, 0, DOORBELL_CMD_EQ, qm->eq_head, 0);

	return IRQ_HANDLED;
}

static void qm_init_qp_status(struct hisi_qp *qp)
{
	struct hisi_acc_qp_status *qp_status = &qp->qp_status;

	qp_status->sq_tail = 0;
	qp_status->sq_head = 0;
	qp_status->cq_head = 0;
	qp_status->cqc_phase = 1;
	qp_status->is_sq_full = 0;
}

/* check if bit in regs is 1 */
static inline int qm_acc_check(struct qm_info *qm, u32 offset, u32 bit)
{
	int val;

	return readl_relaxed_poll_timeout(QM_ADDR(qm, offset), val,
					  val & BIT(bit), 10, 1000);
}

static inline int qm_init_q_buffer(struct device *dev, size_t size,
				   struct qm_dma_buffer *db)
{
	if (db->addr && db->size) {
		memset(db->addr, 0, db->size);
		return 0;
	}
	db->size = size;
	db->addr = dma_zalloc_coherent(dev, size, &db->dma, GFP_KERNEL);
	if (!db->addr)
		return -ENOMEM;

	return 0;
}

static inline void qm_uninit_q_buffer(struct device *dev,
				      struct qm_dma_buffer *db)
{
	dma_free_coherent(dev, db->size, db->addr, db->dma);
}

static inline int qm_init_bt(struct qm_info *qm, struct device *dev,
			     size_t size, struct qm_dma_buffer *db, int mb_cmd)
{
	int ret;

	ret = qm_init_q_buffer(dev, size, db);
	if (ret)
		return -ENOMEM;

	ret = qm_mb(qm, mb_cmd, db->dma, 0, 0, 0);
	if (ret) {
		qm_uninit_q_buffer(dev, db);
		return ret;
	}

	return 0;
}

/* the config should be conducted after hisi_acc_init_qm_mem() */
static int qm_vft_common_config_v1(struct qm_info *qm, u16 base, u32 number)
{
	u64 tmp;
	int ret;

	ret = qm_acc_check(qm, QM_VFT_CFG_RDY, 0);
	if (ret)
		return ret;
	qm_writel(qm, 0x0, QM_VFT_CFG_OP_WR);
	qm_writel(qm, QM_SQC_VFT, QM_VFT_CFG_TYPE);
	qm_writel(qm, qm->pdev->devfn, QM_VFT_CFG_ADDRESS);

	tmp = QM_SQC_VFT_BUF_SIZE			|
	      QM_SQC_VFT_SQC_SIZE			|
	      QM_SQC_VFT_INDEX_NUMBER			|
	      QM_SQC_VFT_VALID				|
	      (u64)base << QM_SQC_VFT_START_SQN_SHIFT;

	qm_writel(qm, tmp & 0xffffffff, QM_VFT_CFG_DATA_L);
	qm_writel(qm, tmp >> 32, QM_VFT_CFG_DATA_H);

	qm_writel(qm, 0x0, QM_VFT_CFG_RDY);
	qm_writel(qm, 0x1, QM_VFT_CFG_OP_ENABLE);
	ret = qm_acc_check(qm, QM_VFT_CFG_RDY, 0);
	if (ret)
		return ret;
	tmp = 0;

	qm_writel(qm, 0x0, QM_VFT_CFG_OP_WR);
	qm_writel(qm, QM_CQC_VFT, QM_VFT_CFG_TYPE);
	qm_writel(qm, qm->pdev->devfn, QM_VFT_CFG_ADDRESS);

	tmp = QM_CQC_VFT_BUF_SIZE			|
	      QM_CQC_VFT_SQC_SIZE			|
	      QM_CQC_VFT_INDEX_NUMBER			|
	      QM_CQC_VFT_VALID;

	qm_writel(qm, tmp & 0xffffffff, QM_VFT_CFG_DATA_L);
	qm_writel(qm, tmp >> 32, QM_VFT_CFG_DATA_H);

	qm_writel(qm, 0x0, QM_VFT_CFG_RDY);
	qm_writel(qm, 0x1, QM_VFT_CFG_OP_ENABLE);
	ret = qm_acc_check(qm, QM_VFT_CFG_RDY, 0);
	if (ret)
		return ret;
	return 0;
}

static int qm_vft_common_config_v2(struct qm_info *qm, u16 base, u32 number)
{
	u64 tmp;
	int ret;

	ret = qm_acc_check(qm, QM_VFT_CFG_RDY, 0);
	if (ret)
		return ret;
	qm_writel(qm, 0x0, QM_VFT_CFG_OP_WR);
	qm_writel(qm, QM_SQC_VFT, QM_VFT_CFG_TYPE);
	qm_writel(qm, qm->pdev->devfn, QM_VFT_CFG_ADDRESS);

	tmp = (u64)number << QM_SQC_VFT_SQN_SHIFT	|
	      QM_SQC_VFT_VALID			|
	      (u64)base << QM_SQC_VFT_START_SQN_SHIFT;

	qm_writel(qm, tmp & 0xffffffff, QM_VFT_CFG_DATA_L);
	qm_writel(qm, tmp >> 32, QM_VFT_CFG_DATA_H);

	qm_writel(qm, 0x0, QM_VFT_CFG_RDY);
	qm_writel(qm, 0x1, QM_VFT_CFG_OP_ENABLE);
	ret = qm_acc_check(qm, QM_VFT_CFG_RDY, 0);
	if (ret)
		return ret;
	tmp = 0;

	qm_writel(qm, 0x0, QM_VFT_CFG_OP_WR);
	qm_writel(qm, QM_CQC_VFT, QM_VFT_CFG_TYPE);
	qm_writel(qm, qm->pdev->devfn, QM_VFT_CFG_ADDRESS);

	tmp = QM_CQC_VFT_VALID;

	qm_writel(qm, tmp & 0xffffffff, QM_VFT_CFG_DATA_L);
	qm_writel(qm, tmp >> 32, QM_VFT_CFG_DATA_H);

	qm_writel(qm, 0x0, QM_VFT_CFG_RDY);
	qm_writel(qm, 0x1, QM_VFT_CFG_OP_ENABLE);
	ret = qm_acc_check(qm, QM_VFT_CFG_RDY, 0);
	if (ret)
		return ret;
	return 0;
}

struct hisi_qp *hisi_qm_create_qp(struct qm_info *qm, u8 alg_type)
{
	struct hisi_qp *qp;
	int qp_index;
	int ret;

	write_lock(&qm->qps_lock);
	qp_index = find_first_zero_bit(qm->qp_bitmap, qm->qp_num);
	if (qp_index >= qm->qp_num) {
		write_unlock(&qm->qps_lock);
		return ERR_PTR(-EBUSY);
	}
	set_bit(qp_index, qm->qp_bitmap);

	qp = kzalloc(sizeof(*qp), GFP_KERNEL);
	if (!qp) {
		ret = -ENOMEM;
		write_unlock(&qm->qps_lock);
		goto err_with_bitset;
	}

	qp->queue_id = qp_index;
	qp->qm = qm;
	qp->alg_type = alg_type;
	qm_init_qp_status(qp);
	write_unlock(&qm->qps_lock);
	qm->free_qp--;
	return qp;

err_with_bitset:
	clear_bit(qp_index, qm->qp_bitmap);

	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(hisi_qm_create_qp);

#ifdef CONFIG_CRYPTO_DEV_HISI_SPIMDEV
static void hisi_qm_reg_user_info(struct hisi_qp *qp, u32 version)
{
	/* Fill qp_index and qm version information here, for user space */
	*(u32 *)qp->scqe.addr = qp->queue_id;
	*((u32 *)qp->scqe.addr + 1) = version;

	/* To be fixed */

}
#endif

int hisi_qm_start_qp_v1(struct hisi_qp *qp, unsigned long arg)
{
	struct qm_info *qm = qp->qm;
	struct device *dev = &qm->pdev->dev;
	struct sqc *sqc;
	struct cqc *cqc;
	int qp_index = qp->queue_id;
	int pasid = arg;
	int ret;

	/* set sq and cq context */
	if (!qp->sqc.addr) {
		qp->sqc.addr = QM_SQC(qm) + qp_index;
		qp->sqc.dma = qm->sqc.dma + qp_index * sizeof(struct sqc);
	}
	sqc = QM_SQC(qp);

	if (!qp->cqc.addr) {
		qp->cqc.addr = QM_CQC(qm) + qp_index;
		qp->cqc.dma = qm->cqc.dma + qp_index * sizeof(struct cqc);
	}
	cqc = QM_CQC(qp);

	/* allocate sq and cq */
	ret = qm_init_q_buffer(dev,
		qm->sqe_size * QM_Q_DEPTH + sizeof(struct cqe) * QM_Q_DEPTH,
		&qp->scqe);
	if (ret)
		return ret;

	INIT_QC(sqc, qp->scqe.dma);
	sqc->pasid = pasid;
	sqc->dw3 = (0 << SQ_HOP_NUM_SHIFT)      |
		   (0 << SQ_PAGE_SIZE_SHIFT)    |
		   (0 << SQ_BUF_SIZE_SHIFT)     |
		   (ilog2(qm->sqe_size) << SQ_SQE_SIZE_SHIFT);
	sqc->w8 = QM_Q_DEPTH - 1;
	sqc->cq_num = qp_index;
	sqc->w13 = 0 << SQ_PRIORITY_SHIFT	|
		   1 << SQ_ORDERS_SHIFT		|
		   (qp->alg_type & SQ_TYPE_MASK) << SQ_TYPE_SHIFT;

	ret = qm_mb(qm, MAILBOX_CMD_SQC, qp->sqc.dma, qp_index, 0, 0);
	if (ret)
		return ret;

	INIT_QC(cqc, qp->scqe.dma + qm->sqe_size * QM_Q_DEPTH);
	cqc->dw3 = (0 << CQ_HOP_NUM_SHIFT)	|
		   (0 << CQ_PAGE_SIZE_SHIFT)	|
		   (0 << CQ_BUF_SIZE_SHIFT)	|
		   (4 << CQ_SQE_SIZE_SHIFT);
	cqc->dw6 = 1 << CQ_PHASE_SHIFT | 1 << CQ_FLAG_SHIFT;
	cqc->w8 = QM_Q_DEPTH - 1;
	ret = qm_mb(qm, MAILBOX_CMD_CQC, qp->cqc.dma, qp_index, 0, 0);
	if (ret)
		return ret;

	write_lock(&qm->qps_lock);
	qm->qp_array[qp_index] = qp;
	init_completion(&qp->completion);
	write_unlock(&qm->qps_lock);

#ifdef CONFIG_CRYPTO_DEV_HISI_SPIMDEV
	hisi_qm_reg_user_info(qp, qm->ver);
#endif

	return qp_index;
}


int hisi_qm_start_qp_v2(struct hisi_qp *qp, unsigned long arg)
{
	struct qm_info *qm = qp->qm;
	struct device *dev = &qm->pdev->dev;
	int ret;
	struct sqc *sqc;
	struct cqc *cqc;
	int qp_index = qp->queue_id;
	int pasid = arg;

	/* set sq and cq context */
	if (!qp->sqc.addr) {
		qp->sqc.addr = QM_SQC(qm) + qp_index;
		qp->sqc.dma = qm->sqc.dma + qp_index * sizeof(struct sqc);
	}
	sqc = QM_SQC(qp);

	if (!qp->cqc.addr) {
		qp->cqc.addr = QM_CQC(qm) + qp_index;
		qp->cqc.dma = qm->cqc.dma + qp_index * sizeof(struct cqc);
	}
	cqc = QM_CQC(qp);

	/* allocate sq and cq */
	ret = qm_init_q_buffer(dev,
		qm->sqe_size * QM_Q_DEPTH + sizeof(struct cqe) * QM_Q_DEPTH,
		&qp->scqe);
	if (ret)
		return ret;

	INIT_QC(sqc, qp->scqe.dma);
	sqc->pasid = pasid;
	sqc->dw3 = (QM_Q_DEPTH - 1) |
		   (ilog2(qm->sqe_size) << SQ_SQE_SIZE_SHIFT);
	sqc->w8 = 0;/*rand_qc*/
	sqc->cq_num = qp_index;
	sqc->w13 = 0 << SQ_PRIORITY_SHIFT	|
		   1 << SQ_ORDERS_SHIFT		|
		   (qp->alg_type & SQ_TYPE_MASK) << SQ_TYPE_SHIFT;

	ret = qm_mb(qm, MAILBOX_CMD_SQC, qp->sqc.dma, qp_index, 0, 0);
	if (ret)
		return ret;

	INIT_QC(cqc, qp->scqe.dma + qm->sqe_size * QM_Q_DEPTH);
	cqc->pasid = pasid;
	cqc->dw3 = (QM_Q_DEPTH - 1) |
		   (4 << CQ_SQE_SIZE_SHIFT);
	cqc->w8 = 0;/*rand_qc*/
	cqc->dw6 = 1 << CQ_PHASE_SHIFT | 1 << CQ_FLAG_SHIFT;

	ret = qm_mb(qm, MAILBOX_CMD_CQC, qp->cqc.dma, qp_index, 0, 0);
	if (ret)
		return ret;

	write_lock(&qm->qps_lock);
	qm->qp_array[qp_index] = qp;
	init_completion(&qp->completion);
	write_unlock(&qm->qps_lock);

#ifdef CONFIG_CRYPTO_DEV_HISI_SPIMDEV
	hisi_qm_reg_user_info(qp, qm->ver);
#endif
	return qp_index;
}


int hisi_qm_start_qp(struct hisi_qp *qp, unsigned long arg)
{
	struct qm_info *qm = qp->qm;

	return qm->ops->qm_start_qp(qp, arg);
}
EXPORT_SYMBOL_GPL(hisi_qm_start_qp);

static struct hisi_acc_qm_hw_ops qm_hw_ops_v1 = {
	.vft_config = qm_vft_common_config_v1,
	.qm_start_qp = hisi_qm_start_qp_v1,
	.qm_db = qm_db_v1,
};

static struct hisi_acc_qm_hw_ops qm_hw_ops_v2 = {
	.vft_config = qm_vft_common_config_v2,
	.qm_start_qp = hisi_qm_start_qp_v2,
	.qm_db = qm_db_v2,
};

void hisi_qm_release_qp(struct hisi_qp *qp)
{
	struct qm_info *qm = qp->qm;
	struct device *dev = &qm->pdev->dev;
	u64 phy = qp->udma_buf.phy_addr;
	int order = qp->udma_buf.order;

	if (order > MAX_ORDER || phy & 0xfff)
		return;
	if (phy)
		__free_pages(phys_to_page(phy), order);

	write_lock(&qm->qps_lock);
	qm->free_qp++;
	qm->qp_array[qp->queue_id] = NULL;
	bitmap_clear(qm->qp_bitmap, qp->queue_id, 1);
	write_unlock(&qm->qps_lock);

	qm_uninit_q_buffer(dev, &qp->scqe);
	kfree(qp);
}
EXPORT_SYMBOL_GPL(hisi_qm_release_qp);

static void *qm_get_avail_sqe(struct hisi_qp *qp)
{
	struct hisi_acc_qp_status *qp_status = &qp->qp_status;
	void *sq_base = QP_SQE_ADDR(qp);
	u16 sq_tail = qp_status->sq_tail;

	if (qp_status->is_sq_full == 1)
		return NULL;

	return sq_base + sq_tail * qp->qm->sqe_size;
}

int hisi_qp_send(struct hisi_qp *qp, void *msg)
{
	struct hisi_acc_qp_status *qp_status = &qp->qp_status;
	u16 sq_tail = qp_status->sq_tail;
	u16 sq_tail_next = (sq_tail + 1) % QM_Q_DEPTH;
	unsigned long timeout = 100;
	void *sqe = qm_get_avail_sqe(qp);

	if (!sqe)
		return -ENOSPC;

	memcpy(sqe, msg, qp->qm->sqe_size);

	qm_db(qp->qm, qp->queue_id, DOORBELL_CMD_SQ, sq_tail_next, 0);

	qp_status->sq_tail = sq_tail_next;

	if (qp_status->sq_tail == qp_status->sq_head)
		qp_status->is_sq_full = 1;

	/* wait until job finished */
	wait_for_completion_timeout(&qp->completion, timeout);

	return 0;
}
EXPORT_SYMBOL_GPL(hisi_qp_send);

#ifdef CONFIG_CRYPTO_DEV_HISI_SPIMDEV
/* mdev->supported_type_groups */
static struct attribute *hisi_qm_type_attrs[] = {
	&mdev_type_attr_device_api.attr,
	&mdev_type_attr_available_instances.attr,
	&mdev_type_attr_type.attr,
	NULL,
};

/* Other supported types algorithms can be added here */
static struct attribute_group hisi_zlib_type_group = {
	.name = "zlib",
	.attrs = hisi_qm_type_attrs,
};

static struct attribute_group hisi_gzip_type_group = {
	.name = "gzip",
	.attrs = hisi_qm_type_attrs,
};

static struct attribute_group hisi_rsa_type_group = {
	.name = "rsa",
	.attrs = hisi_qm_type_attrs,
};

static struct attribute_group hisi_dh_type_group = {
	.name = "dh",
	.attrs = hisi_qm_type_attrs,
};

static struct attribute_group *mdev_zip_type_groups[] = {
	&hisi_zlib_type_group,
	&hisi_gzip_type_group,
	NULL,
};

static struct attribute_group *mdev_hpre_type_groups[] = {
	&hisi_rsa_type_group,
	&hisi_dh_type_group,
	NULL,
};

static struct attribute *mdev_dev_attrs[] = {
	&dev_attr_pid.attr,
	NULL,
};

static const struct attribute_group mdev_dev_group = {
	.name  = VFIO_SPIMDEV_MDEV_ATTRS_GRP,
	.attrs = mdev_dev_attrs,
};

/* this will be showed under virtual device's directory */
static const  struct attribute_group *mdev_dev_groups[] = {
	&mdev_dev_group,
	NULL,
};

static int hisi_qm_get_queue(struct vfio_spimdev *spimdev, const char *alg,
			     struct vfio_spimdev_queue **q)
{
	struct qm_info *qm = spimdev->priv;
	struct hisi_qp *qp = NULL;
	struct vfio_spimdev_queue *wd_q;
	u8 alg_type = 0;
	int ret = 0;

	/* alg_type can be gotten from alg name */
	qp = hisi_qm_create_qp(qm, alg_type);
	if (IS_ERR(qp))
		return PTR_ERR(qp);

	wd_q = kzalloc(sizeof(struct vfio_spimdev_queue), GFP_KERNEL);
	if (!wd_q) {
		ret = -ENOMEM;
		goto err_with_qp;
	}

	wd_q->priv = qp;
	wd_q->spimdev = spimdev;
	wd_q->alg = alg;
	*q = wd_q;
	qp->spimdev_q = wd_q;

	/* PASID is 0 now, to be fixed */
	ret = qm->ops->qm_start_qp(qp, 0);
	if (ret < 0)
		goto err_with_wd_q;
	wd_q->qid = ret;
	return ret;

err_with_wd_q:
	kfree(wd_q);
err_with_qp:
	hisi_qm_release_qp(qp);
	return ret;
}

static int hisi_qm_put_queue(struct vfio_spimdev_queue *q)
{
	struct hisi_qp *qp = q->priv;

	/* need to stop hardware, but can not support in v1 */
	hisi_qm_release_qp(qp);
	kfree(q);
	return 0;
}

static int hisi_qm_reset_queue(struct vfio_spimdev_queue *q)
{
	struct hisi_qp *qp = q->priv;

	qm_init_qp_status(qp);
	return hisi_qm_start_qp(qp, 0);
}

/* map sq/cq/doorbell to user space */
static int hisi_qm_mmap(struct vfio_spimdev_queue *q,
			struct vm_area_struct *vma)
{
	struct hisi_qp *qp = (struct hisi_qp *)q->priv;
	struct qm_info *qm = qp->qm;
	struct device *dev = &qm->pdev->dev;
	size_t sz = vma->vm_end - vma->vm_start;
	u8 region;

	vma->vm_flags |= (VM_IO | VM_LOCKED | VM_DONTEXPAND | VM_DONTDUMP);
	region = _VFIO_SPIMDEV_REGION(vma->vm_pgoff);

	switch (region) {
	case 0:
		if (sz > PAGE_SIZE)
			return -EINVAL;
		/*
		 * Warning: This is not safe as multiple queues use the same
		 * doorbell, v1 hardware interface problem. v2 will fix it
		 */
		if (qm->ver == QM_HW_V2)
			return remap_pfn_range(vma, vma->vm_start,
					       (qm->phys_base + PAGE_SIZE) >>
					       PAGE_SHIFT, sz,
					       pgprot_noncached(
					       vma->vm_page_prot));
		else if (qm->ver == QM_HW_V1)
			return remap_pfn_range(vma, vma->vm_start,
				       qm->phys_base >> PAGE_SHIFT,
				       sz, pgprot_noncached(vma->vm_page_prot));
		else
			return -ENODEV;
	case 1:
		vma->vm_pgoff = 0;
		if (sz > qp->scqe.size)
			return -EINVAL;

		return dma_mmap_coherent(dev, vma, qp->scqe.addr, qp->scqe.dma,
					 sz);

	default:
		return -EINVAL;
	}
}

static int hisi_qm_get_available_qnum(struct vfio_spimdev *spimdev)
{
	int num;
	struct qm_info *qm = spimdev->priv;

	read_lock(&qm->qps_lock);
	num = qm->free_qp;
	read_unlock(&qm->qps_lock);

	return num;
}
static int qm_set_sqctype(struct hisi_qp *qp, u16 type)
{
	struct sqc *sqc;

	sqc = QM_SQC(qp);
	sqc->w13 = 0 << SQ_PRIORITY_SHIFT  |
		   1 << SQ_ORDERS_SHIFT    |
		   (type & SQ_TYPE_MASK) << SQ_TYPE_SHIFT;
	return qm_mb(qp->qm, MAILBOX_CMD_SQC, qp->sqc.dma, qp->queue_id, 0, 0);
}

static long qm_ioctl(struct vfio_spimdev_queue *q, unsigned int cmd,
		     unsigned long arg)
{
	struct vfio_spimdev *spimdev = q->spimdev;
	struct hisi_qp *qp = q->priv;
	unsigned long long phy;
	void *page;
	int order;
	struct page *page_list;
	u64 size;

	switch (cmd) {
	/* While supporting NO-IOMMU, we need this */
	case _GET_DMA_PAGES:
#ifdef CONFIG_STRICT_DEVMEM
		dev_err(spimdev->dev, "\nSTRICT_DEVMEM is on!");
		return -EPERM;
#endif
		if (copy_from_user(&size, (unsigned long long *)arg,
				   sizeof(u64)))
			return -EFAULT;
		if (size == 0)
			return -EINVAL;
		order = get_order(size);
		if (order > MAX_ORDER)
			return -ENOMEM;
		page_list = alloc_pages_node(spimdev->node_id, GFP_DMA, order);
		if (!page_list) {
			dev_err(spimdev->dev,
				"alloc 2^%d pages fail!\n", order);
			return -ENOMEM;
		}
		page = page_address(page_list);
		phy = (unsigned long long)virt_to_phys(page);
		qp->udma_buf.phy_addr = phy;
		qp->udma_buf.order = order;

		if (copy_to_user((unsigned long long *)arg, &phy,
		    sizeof(unsigned long long)))
			return -EFAULT;
		break;
	case _PUT_DMA_PAGES:
		if (copy_from_user(&phy,
				(unsigned long long *)arg,
				sizeof(unsigned long long)))
			return -EFAULT;
		phy = phy & PAGE_MASK;
		order = qp->udma_buf.order;
		if (order > MAX_ORDER || phy != qp->udma_buf.phy_addr)
			return -EINVAL;
		__free_pages(phys_to_page(phy), order);
		qp->udma_buf.phy_addr = 0;

		break;
	case HACC_QM_SET_OPTYPE:
		qm_set_sqctype(qp, (u16)(arg & 0xffff));
		break;
	default:
		dev_err(spimdev->dev,
	 "%s, ioctl cmd (0x%x) is not supported!\n", __func__, cmd);
		return -EINVAL;
	}

	return 0;
}

static const struct vfio_spimdev_ops qm_ops = {
	.get_queue = hisi_qm_get_queue,
	.put_queue = hisi_qm_put_queue,
	.mmap = hisi_qm_mmap,
	.get_available_instances = hisi_qm_get_available_qnum,
	.ioctl = qm_ioctl,
	.reset_queue = hisi_qm_reset_queue,
};

static int qm_register_spimdev(struct qm_info *qm)
{
	struct pci_dev *pdev = qm->pdev;
	struct vfio_spimdev *spimdev = &qm->spimdev;

#ifdef CONFIG_IOMMU_SVA
	spimdev->dma_flag = VFIO_SPIMDEV_DMA_MULTI_PROC_MAP;
#endif

#ifdef CONFIG_ARM_SMMU_V3
	spimdev->iommu_type = VFIO_TYPE1_IOMMU;
	spimdev->dma_flag = VFIO_SPIMDEV_DMA_SINGLE_PROC_MAP;
#else
	spimdev->iommu_type = VFIO_SPIMDEV_IOMMU;
	spimdev->dma_flag = VFIO_SPIMDEV_DMA_PHY;
#endif
	spimdev->owner = THIS_MODULE;
	spimdev->name = qm->dev_name;
	spimdev->dev = &pdev->dev;
	spimdev->is_vf = pdev->is_virtfn;
	spimdev->priv = qm;
	if (qm->ver == QM_HW_V1)
		spimdev->api_ver = "hisi_qm_v1";
	else
		spimdev->api_ver = "hisi_qm_v2";
	spimdev->flags = VFIO_SPIMDEV_SAME_ALG_QFLG;
	qm->mdev_dev_groups = mdev_dev_groups;
	spimdev->mdev_fops.mdev_attr_groups = qm->mdev_dev_groups;
	if (qm->type == ZIP)
		spimdev->mdev_fops.supported_type_groups =
						mdev_zip_type_groups;
	else if (qm->type == HPRE)
		spimdev->mdev_fops.supported_type_groups =
						mdev_hpre_type_groups;
	spimdev->ops = &qm_ops;

	return vfio_spimdev_register(spimdev);
}
#endif

int hisi_qm_init(struct qm_info *qm, enum qm_type type)
{
	struct pci_dev *pdev = qm->pdev;
	int ret;

	ret = pci_enable_device_mem(pdev);
	if (ret < 0) {
		dev_err(&pdev->dev, "Can't enable device mem!\n");
		return ret;
	}
	qm->type = type;
	qm->dev_name = pdev->driver->name;
	ret = pci_request_mem_regions(pdev, qm->dev_name);
	if (ret < 0) {
		dev_err(&pdev->dev, "Can't request mem regions!\n");
		goto err_with_pcidev;
	}

	qm->phys_base = pci_resource_start(pdev, 2);
	qm->size = pci_resource_len(qm->pdev, 2);
	qm->io_base = devm_ioremap(&pdev->dev, qm->phys_base, qm->size);
	if (!qm->io_base) {
		ret = -EIO;
		dev_err(&pdev->dev, "ioremap qm physical base fail!\n");
		goto err_with_mem_regions;
	}

	dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	pci_set_master(pdev);

	ret = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_MSI);
	if (ret < 0) {
		dev_err(&pdev->dev, "Enable MSI vectors fail!\n");
		goto err_with_mem_regions;
	}

	qm->eq_head = 0;
	mutex_init(&qm->mailbox_lock);
	rwlock_init(&qm->qps_lock);

	if (qm->ver == QM_HW_V1)
		qm->ops = &qm_hw_ops_v1;
	else if (qm->ver == QM_HW_V2)
		qm->ops = &qm_hw_ops_v2;

	return 0;

err_with_mem_regions:
	pci_release_mem_regions(pdev);
err_with_pcidev:
	pci_disable_device(pdev);

	return ret;
}
EXPORT_SYMBOL_GPL(hisi_qm_init);

void hisi_qm_uninit(struct qm_info *qm)
{
	struct pci_dev *pdev = qm->pdev;

	pci_free_irq_vectors(pdev);
	pci_release_mem_regions(pdev);
	pci_disable_device(pdev);
}
EXPORT_SYMBOL_GPL(hisi_qm_uninit);

static irqreturn_t qm_irq(int irq, void *data)
{
	struct qm_info *qm = data;
	u32 int_source;

	int_source = qm_get_irq_source(qm);
	if (int_source)
		return IRQ_WAKE_THREAD;

	dev_err(&qm->pdev->dev, "invalid int source %d\n", int_source);

	return IRQ_HANDLED;
}

int hisi_qm_start(struct qm_info *qm)
{
	struct pci_dev *pdev = qm->pdev;
	struct device *dev = &pdev->dev;
	int ret;

	if (qm->pdev->is_physfn)
		qm->ops->vft_config(qm, qm->qp_base, qm->qp_num);

	ret = qm_init_q_buffer(dev, sizeof(struct eqc), &qm->eqc);
	if (ret)
		goto err_out;

	ret = qm_init_q_buffer(dev, sizeof(struct eqe) * QM_Q_DEPTH, &qm->eqe);
	if (ret)
		goto err_with_eqc;

	QM_EQC(qm)->base_l = lower_32_bits(qm->eqe.dma);
	QM_EQC(qm)->base_h = upper_32_bits(qm->eqe.dma);
	QM_EQC(qm)->dw3 = 2 << MB_EQC_EQE_SHIFT;
	QM_EQC(qm)->dw6 = (QM_Q_DEPTH - 1) | (1 << MB_EQC_PHASE_SHIFT);
	ret = qm_mb(qm, MAILBOX_CMD_EQC, qm->eqc.dma, 0, 0, 0);
	if (ret)
		goto err_with_eqe;

	qm->qp_bitmap = kcalloc(BITS_TO_LONGS(qm->qp_num), sizeof(long),
				GFP_KERNEL);
	if (!qm->qp_bitmap)
		goto err_with_eqe;

	qm->qp_array = kcalloc(qm->qp_num, sizeof(struct hisi_qp *),
			       GFP_KERNEL);
	if (!qm->qp_array)
		goto err_with_bitmap;

	/* Init sqc_bt */
	ret = qm_init_bt(qm, dev, sizeof(struct sqc) * qm->qp_num, &qm->sqc,
			 MAILBOX_CMD_SQC_BT);
	if (ret)
		goto err_with_qp_array;

	/* Init cqc_bt */
	ret = qm_init_bt(qm, dev, sizeof(struct cqc) * qm->qp_num, &qm->cqc,
			 MAILBOX_CMD_CQC_BT);
	if (ret)
		goto err_with_sqc;

	ret = request_threaded_irq(pci_irq_vector(pdev, 0), qm_irq,
				   qm_irq_thread, IRQF_SHARED, qm->dev_name,
				   qm);
	if (ret)
		goto err_with_cqc;

#ifdef CONFIG_CRYPTO_DEV_HISI_SPIMDEV
	ret = qm_register_spimdev(qm);
	if (ret) {
		dev_err(dev, "Hisilicon QM register to SPIMDEV fail!\n");
		goto err_with_cqc;
	}
#endif

	writel(0x0, QM_ADDR(qm, QM_VF_EQ_INT_MASK));

	return 0;

err_with_cqc:
	qm_uninit_q_buffer(dev, &qm->cqc);
err_with_sqc:
	qm_uninit_q_buffer(dev, &qm->sqc);
err_with_qp_array:
	kfree(qm->qp_array);
err_with_bitmap:
	kfree(qm->qp_bitmap);
err_with_eqe:
	qm_uninit_q_buffer(dev, &qm->eqe);
err_with_eqc:
	qm_uninit_q_buffer(dev, &qm->eqc);
err_out:
	return ret;
}
EXPORT_SYMBOL_GPL(hisi_qm_start);

void hisi_qm_stop(struct qm_info *qm)
{
	struct pci_dev *pdev = qm->pdev;
	struct device *dev = &pdev->dev;

#ifdef CONFIG_CRYPTO_DEV_HISI_SPIMDEV
	vfio_spimdev_unregister(&qm->spimdev);
#endif

	free_irq(pci_irq_vector(pdev, 0), qm);
	qm_uninit_q_buffer(dev, &qm->cqc);
	kfree(qm->qp_array);
	kfree(qm->qp_bitmap);
	qm_uninit_q_buffer(dev, &qm->eqe);
	qm_uninit_q_buffer(dev, &qm->eqc);
}
EXPORT_SYMBOL_GPL(hisi_qm_stop);

/* put qm into init state, so the acce config become available */
int hisi_qm_mem_start(struct qm_info *qm)
{
	u32 val;

	qm_writel(qm, 0x1, QM_MEM_START_INIT);
	return readl_relaxed_poll_timeout(QM_ADDR(qm, QM_MEM_INIT_DONE), val,
					  val & BIT(0), 10, 1000);
}
EXPORT_SYMBOL_GPL(hisi_qm_mem_start);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Zhou Wang <wangzhou1@hisilicon.com>");
MODULE_DESCRIPTION("HiSilicon Accelerator queue manager driver");
