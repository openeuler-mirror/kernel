// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 HiSilicon Limited. */

#include <linux/device.h>
#include <linux/debugfs.h>
#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/sysfs.h>
#include <linux/vfio.h>

#include "acc_vf_migration.h"

#define VDM_OFFSET(x) offsetof(struct vfio_device_migration_info, x)
static struct dentry *mig_debugfs_root;
static int mig_root_ref;

/* return 0 VM acc device ready, -ETIMEDOUT hardware timeout */
static int qm_wait_dev_ready(struct hisi_qm *qm)
{
	u32 val;

	return readl_relaxed_poll_timeout(qm->io_base + QM_VF_STATE,
				val, !(val & 0x1), POLL_PERIOD, POLL_TIMEOUT);
}

/* 128 bit should be written to hardware at one time to trigger a mailbox */
static void qm_mb_write(struct hisi_qm *qm, const void *src)
{
	void __iomem *fun_base = qm->io_base + QM_MB_CMD_SEND_BASE;
	unsigned long tmp0 = 0;
	unsigned long tmp1 = 0;

	if (!IS_ENABLED(CONFIG_ARM64)) {
		memcpy_toio(fun_base, src, 16);
		wmb();
		return;
	}

	asm volatile("ldp %0, %1, %3\n"
		     "stp %0, %1, %2\n"
		     "dsb sy\n"
		     : "=&r" (tmp0),
		       "=&r" (tmp1),
		       "+Q" (*((char __iomem *)fun_base))
		     : "Q" (*((char *)src))
		     : "memory");
}

/* 128 bit should be read from hardware at one time */
static void qm_mb_read(struct hisi_qm *qm, void *dst)
{
	const void __iomem *fun_base = qm->io_base + QM_MB_CMD_SEND_BASE;
	unsigned long tmp0 = 0, tmp1 = 0;

	if (!IS_ENABLED(CONFIG_ARM64)) {
		memcpy_fromio(dst, fun_base, 16);
		dma_wmb();
		return;
	}

	asm volatile("ldp %0, %1, %3\n"
		     "stp %0, %1, %2\n"
		     "dmb oshst\n"
		     : "=&r" (tmp0),
		       "=&r" (tmp1),
		       "+Q" (*((char *)dst))
		     : "Q" (*((char __iomem *)fun_base))
		     : "memory");
}

static void qm_mb_pre_init(struct qm_mailbox *mailbox, u8 cmd,
			   u64 base, u16 queue, bool op)
{
	mailbox->w0 = cpu_to_le16((cmd) |
		((op) ? 0x1 << QM_MB_OP_SHIFT : 0) |
		(0x1 << QM_MB_BUSY_SHIFT));
	mailbox->queue_num = cpu_to_le16(queue);
	mailbox->base_l = cpu_to_le32(lower_32_bits(base));
	mailbox->base_h = cpu_to_le32(upper_32_bits(base));
	mailbox->rsvd = 0;
}

static int qm_wait_mb_ready(struct hisi_qm *qm)
{
	struct qm_mailbox mailbox;
	int i = 0;

	while (i++ < QM_MB_WAIT_READY_CNT) {
		qm_mb_read(qm, &mailbox);
		if (!((le16_to_cpu(mailbox.w0) >> QM_MB_BUSY_SHIFT) & 0x1))
			return 0;

		usleep_range(WAIT_PERIOD_US_MIN, WAIT_PERIOD_US_MAX);
	}

	return -EBUSY;
}

static int qm_wait_mb_finish(struct hisi_qm *qm, struct qm_mailbox *mailbox)
{
	int i = 0;

	while (i++) {
		qm_mb_read(qm, mailbox);
		if (!((le16_to_cpu(mailbox->w0) >> QM_MB_BUSY_SHIFT) & 0x1))
			break;

		if (i == QM_MB_MAX_WAIT_CNT) {
			dev_err(&qm->pdev->dev, "QM mailbox operation timeout!\n");
			return -ETIMEDOUT;
		}

		usleep_range(WAIT_PERIOD_US_MIN, WAIT_PERIOD_US_MAX);
	}

	if (le16_to_cpu(mailbox->w0) & QM_MB_STATUS_MASK) {
		dev_err(&qm->pdev->dev, "QM mailbox operation failed!\n");
		return -EIO;
	}

	return 0;
}

static int qm_mb(struct hisi_qm *qm, struct qm_mailbox *mailbox)
{
	int ret;

	mutex_lock(&qm->mailbox_lock);
	ret = qm_wait_mb_ready(qm);
	if (ret)
		goto unlock;

	qm_mb_write(qm, mailbox);
	ret = qm_wait_mb_finish(qm, mailbox);

unlock:
	mutex_unlock(&qm->mailbox_lock);

	return ret;
}

static int qm_config_set(struct hisi_qm *qm, u8 cmd, dma_addr_t dma_addr,
			       u16 queue, bool op)
{
	struct qm_mailbox mailbox;

	dev_dbg(&qm->pdev->dev, "QM mailbox request to q%u: %u-0x%llx\n",
		queue, cmd, (unsigned long long)dma_addr);

	qm_mb_pre_init(&mailbox, cmd, dma_addr, queue, op);

	return qm_mb(qm, &mailbox);
}

static int qm_config_get(struct hisi_qm *qm, u64 *base, u8 cmd, u16 queue)
{
	struct qm_mailbox mailbox;
	int ret;

	qm_mb_pre_init(&mailbox, cmd, 0, queue, 1);

	ret = qm_mb(qm, &mailbox);
	if (ret)
		return ret;

	*base = le32_to_cpu(mailbox.base_l) |
		((u64)le32_to_cpu(mailbox.base_h) << 32);

	return 0;
}

static void qm_db(struct hisi_qm *qm, u16 qn, u8 cmd,
	u16 index, u8 priority)
{
	void __iomem *io_base = qm->io_base;
	u16 randata = 0;
	u64 doorbell;

	if (cmd == QM_DOORBELL_CMD_SQ || cmd == QM_DOORBELL_CMD_CQ)
		io_base = qm->db_io_base + (u64)qn * qm->db_interval +
			  QM_DOORBELL_SQ_CQ_BASE_V2;
	else
		io_base += QM_DOORBELL_EQ_AEQ_BASE_V2;

	doorbell = qn | ((u64)cmd << QM_DB_CMD_SHIFT_V2) |
		   ((u64)randata << QM_DB_RAND_SHIFT_V2) |
		   ((u64)index << QM_DB_INDEX_SHIFT_V2) |
		   ((u64)priority << QM_DB_PRIORITY_SHIFT_V2);

	writeq(doorbell, io_base);
}

/*
 * Each state Reg is checked 100 times,
 * with a delay of 100 microseconds after each check
 */
static u32 acc_check_reg_state(struct hisi_qm *qm, u32 regs)
{
	int check_times = 0;
	u32 state;

	state = readl(qm->io_base + regs);
	while (state && check_times < ERROR_CHECK_TIMEOUT) {
		udelay(CHECK_DELAY_TIME);
		state = readl(qm->io_base + regs);
		check_times++;
	}

	return state;
}

/* Check the  PF's RAS state and Function INT state */
static int qm_check_int_state(struct acc_vf_migration *acc_vf_dev)
{
	struct hisi_qm *vfqm = acc_vf_dev->vf_qm;
	struct hisi_qm *qm = acc_vf_dev->pf_qm;
	struct device *dev = &qm->pdev->dev;
	u32 state;

	/* Check RAS state */
	state = acc_check_reg_state(qm, QM_ABNORMAL_INT_STATUS);
	if (state) {
		dev_err(dev, "failed to check QM RAS state!\n");
		return -EBUSY;
	}

	/* Check Function Communication  state between PF and VF */
	state = acc_check_reg_state(vfqm, QM_IFC_INT_STATUS);
	if (state) {
		dev_err(dev, "failed to check QM IFC INT state!\n");
		return -EBUSY;
	}
	state = acc_check_reg_state(vfqm, QM_IFC_INT_SET_V);
	if (state) {
		dev_err(dev, "failed to check QM IFC INT SET state!\n");
		return -EBUSY;
	}

	/* Check submodule task state */
	switch (acc_vf_dev->acc_type) {
	case HISI_SEC:
		state = acc_check_reg_state(qm, SEC_CORE_INT_STATUS);
		if (state) {
			dev_err(dev, "failed to check QM SEC Core INT state!\n");
			return -EBUSY;
		}
		break;
	case HISI_HPRE:
		state = acc_check_reg_state(qm, HPRE_HAC_INT_STATUS);
		if (state) {
			dev_err(dev, "failed to check QM HPRE HAC INT state!\n");
			return -EBUSY;
		}
		break;
	case HISI_ZIP:
		state = acc_check_reg_state(qm, HZIP_CORE_INT_STATUS);
		if (state) {
			dev_err(dev, "failed to check QM ZIP Core INT state!\n");
			return -EBUSY;
		}
		break;
	default:
		dev_err(dev, "failed to detect acc module type!\n");
		return -EINVAL;
	}

	return 0;
}

static int qm_read_reg(struct hisi_qm *qm, u32 reg_addr,
			 u32 *data, u8 nums)
{
	int i;

	if (nums < 1 || nums > QM_REGS_MAX_LEN) {
		dev_err(&qm->pdev->dev, "QM read input parameter is error!\n");
		return -EINVAL;
	}

	for (i = 0; i < nums; i++) {
		data[i] = readl(qm->io_base + reg_addr);
		reg_addr += QM_REG_ADDR_OFFSET;
	}

	return 0;
}

static int qm_write_reg(struct hisi_qm *qm, u32 reg_addr,
			 u32 *data, u8 nums)
{
	int i;

	if (nums < 1 || nums > QM_REGS_MAX_LEN) {
		dev_err(&qm->pdev->dev, "QM write input parameter is error!\n");
		return -EINVAL;
	}

	for (i = 0; i < nums; i++) {
		writel(data[i], qm->io_base + reg_addr);
		reg_addr += QM_REG_ADDR_OFFSET;
	}

	return 0;
}

static int qm_get_vft(struct hisi_qm *qm, u32 *base, u32 *number)
{
	u64 sqc_vft;
	int ret;

	ret = qm_config_get(qm, &sqc_vft, QM_MB_CMD_SQC_VFT_V2, 0);
	if (ret)
		return ret;

	*base = QM_SQC_VFT_BASE_MASK_V2 & (sqc_vft >> QM_SQC_VFT_BASE_SHIFT_V2);
	*number = (QM_SQC_VFT_NUM_MASK_V2 &
		  (sqc_vft >> QM_SQC_VFT_NUM_SHIFT_V2)) + 1;

	return 0;
}

static int qm_rw_regs_read(struct hisi_qm *qm, struct acc_vf_data *vf_data)
{
	struct device *dev = &qm->pdev->dev;
	int ret;

	ret = qm_read_reg(qm, QM_VF_AEQ_INT_MASK, &vf_data->aeq_int_mask, 1);
	if (ret) {
		dev_err(dev, "failed to read QM_VF_AEQ_INT_MASK!\n");
		return ret;
	}

	ret = qm_read_reg(qm, QM_VF_EQ_INT_MASK, &vf_data->eq_int_mask, 1);
	if (ret) {
		dev_err(dev, "failed to read QM_VF_EQ_INT_MASK!\n");
		return ret;
	}

	ret = qm_read_reg(qm, QM_IFC_INT_SOURCE_V,
			   &vf_data->ifc_int_source, 1);
	if (ret) {
		dev_err(dev, "failed to read QM_IFC_INT_SOURCE_V!\n");
		return ret;
	}

	ret = qm_read_reg(qm, QM_IFC_INT_MASK, &vf_data->ifc_int_mask, 1);
	if (ret) {
		dev_err(dev, "failed to read QM_IFC_INT_MASK!\n");
		return ret;
	}

	ret = qm_read_reg(qm, QM_IFC_INT_SET_V, &vf_data->ifc_int_set, 1);
	if (ret) {
		dev_err(dev, "failed to read QM_IFC_INT_SET_V!\n");
		return ret;
	}

	ret = qm_read_reg(qm, QM_PAGE_SIZE, &vf_data->page_size, 1);
	if (ret) {
		dev_err(dev, "failed to read QM_PAGE_SIZE!\n");
		return ret;
	}

	ret = qm_read_reg(qm, QM_VF_STATE, &vf_data->vf_state, 1);
	if (ret) {
		dev_err(dev, "failed to read QM_VF_STATE!\n");
		return ret;
	}

	/* QM_EQC_DW has 7 regs */
	ret = qm_read_reg(qm, QM_EQC_DW0, vf_data->qm_eqc_dw, 7);
	if (ret) {
		dev_err(dev, "failed to read QM_EQC_DW!\n");
		return ret;
	}

	/* QM_AEQC_DW has 7 regs */
	ret = qm_read_reg(qm, QM_AEQC_DW0, vf_data->qm_aeqc_dw, 7);
	if (ret) {
		dev_err(dev, "failed to read QM_AEQC_DW!\n");
		return ret;
	}

	return 0;
}

static int qm_rw_regs_write(struct hisi_qm *qm, struct acc_vf_data *vf_data)
{
	struct device *dev = &qm->pdev->dev;
	int ret;

	/* check VF state */
	if (unlikely(qm_wait_mb_ready(qm))) {
		dev_err(&qm->pdev->dev, "QM device is not ready to write!\n");
		return -EBUSY;
	}

	ret = qm_write_reg(qm, QM_VF_AEQ_INT_MASK, &vf_data->aeq_int_mask, 1);
	if (ret) {
		dev_err(dev, "failed to write QM_VF_AEQ_INT_MASK!\n");
		return ret;
	}

	ret = qm_write_reg(qm, QM_VF_EQ_INT_MASK, &vf_data->eq_int_mask, 1);
	if (ret) {
		dev_err(dev, "failed to write QM_VF_EQ_INT_MASK!\n");
		return ret;
	}

	ret = qm_write_reg(qm, QM_IFC_INT_SOURCE_V,
			   &vf_data->ifc_int_source, 1);
	if (ret) {
		dev_err(dev, "failed to write QM_IFC_INT_SOURCE_V!\n");
		return ret;
	}

	ret = qm_write_reg(qm, QM_IFC_INT_MASK, &vf_data->ifc_int_mask, 1);
	if (ret) {
		dev_err(dev, "failed to write QM_IFC_INT_MASK!\n");
		return ret;
	}

	ret = qm_write_reg(qm, QM_IFC_INT_SET_V, &vf_data->ifc_int_set, 1);
	if (ret) {
		dev_err(dev, "failed to write QM_IFC_INT_SET_V!\n");
		return ret;
	}

	ret = qm_write_reg(qm, QM_PAGE_SIZE, &vf_data->page_size, 1);
	if (ret) {
		dev_err(dev, "failed to write QM_PAGE_SIZE!\n");
		return ret;
	}

	ret = qm_write_reg(qm, QM_VF_STATE, &vf_data->vf_state, 1);
	if (ret) {
		dev_err(dev, "failed to write QM_VF_STATE!\n");
		return ret;
	}

	/* QM_EQC_DW has 7 regs */
	ret = qm_write_reg(qm, QM_EQC_DW0, vf_data->qm_eqc_dw, 7);
	if (ret) {
		dev_err(dev, "failed to write QM_EQC_DW!\n");
		return ret;
	}

	/* QM_AEQC_DW has 7 regs */
	ret = qm_write_reg(qm, QM_AEQC_DW0, vf_data->qm_aeqc_dw, 7);
	if (ret) {
		dev_err(dev, "failed to write QM_AEQC_DW!\n");
		return ret;
	}

	return 0;
}

static void vf_qm_xeqc_save(struct hisi_qm *qm,
	struct acc_vf_migration *acc_vf_dev)
{
	struct acc_vf_data *vf_data = acc_vf_dev->vf_data;
	u16 eq_head, aeq_head;

	eq_head = vf_data->qm_eqc_dw[0] & 0xFFFF;
	qm_db(qm, 0, QM_DOORBELL_CMD_EQ, eq_head, 0);

	aeq_head = vf_data->qm_aeqc_dw[0] & 0xFFFF;
	qm_db(qm, 0, QM_DOORBELL_CMD_AEQ, aeq_head, 0);
}

/*
 * the vf QM have unbind from host, insmod in the VM
 * so, qm just have the addr from pci dev
 * others is null.
 * so we need read from the SEC hardware REGs.
 */
static int vf_migration_data_store(struct hisi_qm *qm,
			struct acc_vf_migration *acc_vf_dev)
{
	struct acc_vf_data *vf_data = acc_vf_dev->vf_data;
	struct device *dev = &qm->pdev->dev;
	int ret;

	ret = qm_rw_regs_read(qm, vf_data);
	if (ret) {
		dev_err(dev, "failed to read QM regs!\n");
		return -EINVAL;
	}

	/*
	 * every Reg is 32 bit, the dma address is 64 bit
	 * so, the dma address is store in the Reg2 and Reg1
	 */
	vf_data->eqe_dma = vf_data->qm_eqc_dw[QM_XQC_ADDR_HIGH];
	vf_data->eqe_dma <<= QM_XQC_ADDR_OFFSET;
	vf_data->eqe_dma |= vf_data->qm_eqc_dw[QM_XQC_ADDR_LOW];
	vf_data->aeqe_dma = vf_data->qm_aeqc_dw[QM_XQC_ADDR_HIGH];
	vf_data->aeqe_dma <<= QM_XQC_ADDR_OFFSET;
	vf_data->aeqe_dma |= vf_data->qm_aeqc_dw[QM_XQC_ADDR_LOW];

	/* Through SQC_BT/CQC_BT to get sqc and cqc address */
	ret = qm_config_get(qm, &vf_data->sqc_dma, QM_MB_CMD_SQC_BT, 0);
	if (ret) {
		dev_err(dev, "failed to read SQC addr!\n");
		return -EINVAL;
	}

	ret = qm_config_get(qm, &vf_data->cqc_dma, QM_MB_CMD_CQC_BT, 0);
	if (ret) {
		dev_err(dev, "failed to read CQC addr!\n");
		return -EINVAL;
	}

	/* Save eqc and aeqc interrupt information */
	vf_qm_xeqc_save(qm, acc_vf_dev);

	return 0;
}

static void qm_dev_cmd_init(struct hisi_qm *qm)
{
	/* clear VF communication status registers. */
	writel(0x1, qm->io_base + QM_IFC_INT_SOURCE_V);

	/* enable pf and vf communication. */
	writel(0x0, qm->io_base + QM_IFC_INT_MASK);
}

static void vf_qm_fun_restart(struct hisi_qm *qm,
	struct acc_vf_migration *acc_vf_dev)
{
	struct acc_vf_data *vf_data = acc_vf_dev->vf_data;
	struct device *dev = &qm->pdev->dev;
	int i;

	/*
	 * When the Guest is rebooted or reseted, the SMMU page table
	 * will be destroyed, and the QP queue cannot be returned
	 * normally at this time. so if Guest acc driver have removed,
	 * don't need to restart QP.
	 */
	if (vf_data->vf_state != VF_READY) {
		dev_err(dev, "failed to restart VF!\n");
		return;
	}

	for (i = 0; i < qm->qp_num; i++)
		qm_db(qm, i, QM_DOORBELL_CMD_SQ, 0, 1);
}

static int vf_match_info_check(struct hisi_qm *qm,
	struct acc_vf_migration *acc_vf_dev)
{
	struct acc_vf_data *vf_data = acc_vf_dev->vf_data;
	struct hisi_qm *pf_qm = acc_vf_dev->pf_qm;
	struct device *dev = &qm->pdev->dev;
	u32 que_iso_state;
	int ret;

	/* vf acc type check */
	if (vf_data->acc_type != acc_vf_dev->acc_type) {
		dev_err(dev, "failed to match VF acc type!\n");
		return -EINVAL;
	}

	/* vf qp num check */
	ret = qm_get_vft(qm, &qm->qp_base, &qm->qp_num);
	if (ret || qm->qp_num <= 1) {
		dev_err(dev, "failed to get vft qp nums!\n");
		return ret;
	}

	if (vf_data->qp_num != qm->qp_num) {
		dev_err(dev, "failed to match VF qp num!\n");
		return -EINVAL;
	}

	/* vf isolation state check */
	ret = qm_read_reg(pf_qm, QM_QUE_ISO_CFG_V, &que_iso_state, 1);
	if (ret) {
		dev_err(dev, "failed to read QM_QUE_ISO_CFG_V!\n");
		return ret;
	}
	if (vf_data->que_iso_cfg != que_iso_state) {
		dev_err(dev, "failed to match isolation state!\n");
		return -EINVAL;
	}

	return 0;
}

static int vf_migration_data_recover(struct hisi_qm *qm,
	struct acc_vf_data *vf_data)
{
	struct device *dev = &qm->pdev->dev;
	int ret;

	qm->eqe_dma = vf_data->eqe_dma;
	qm->aeqe_dma = vf_data->aeqe_dma;
	qm->sqc_dma = vf_data->sqc_dma;
	qm->cqc_dma = vf_data->cqc_dma;

	qm->qp_base = vf_data->qp_base;
	qm->qp_num = vf_data->qp_num;

	ret = qm_rw_regs_write(qm, vf_data);
	if (ret) {
		dev_err(dev, "Set VF regs failed!\n");
		return ret;
	}

	ret = qm_config_set(qm, QM_MB_CMD_SQC_BT, qm->sqc_dma, 0, 0);
	if (ret) {
		dev_err(dev, "Set sqc failed!\n");
		return ret;
	}

	ret = qm_config_set(qm, QM_MB_CMD_CQC_BT, qm->cqc_dma, 0, 0);
	if (ret) {
		dev_err(dev, "Set cqc failed!\n");
		return ret;
	}

	/* which ACC module need to reinit? */
	qm_dev_cmd_init(qm);

	return 0;
}

static int vf_qm_cache_wb(struct hisi_qm *qm)
{
	unsigned int val;

	writel(0x1, qm->io_base + QM_CACHE_WB_START);
	if (readl_relaxed_poll_timeout(qm->io_base + QM_CACHE_WB_DONE,
				       val, val & BIT(0), POLL_PERIOD,
				       POLL_TIMEOUT)) {
		dev_err(&qm->pdev->dev, "vf QM writeback sqc cache fail!\n");
		return -EINVAL;
	}

	return 0;
}

static int vf_qm_func_stop(struct hisi_qm *qm)
{
	return qm_config_set(qm, QM_MB_CMD_PAUSE_QM, 0, 0, 0);
}

static int pf_qm_get_qp_num(struct hisi_qm *qm, int vf_id,
	u32 *rbase, u32 *rnumber)
{
	unsigned int val;
	u64 sqc_vft;
	int ret;

	ret = readl_relaxed_poll_timeout(qm->io_base + QM_VFT_CFG_RDY, val,
					 val & BIT(0), POLL_PERIOD,
					 POLL_TIMEOUT);
	if (ret)
		return ret;

	writel(0x1, qm->io_base + QM_VFT_CFG_OP_WR);
	/* 0 mean SQC VFT */
	writel(0x0, qm->io_base + QM_VFT_CFG_TYPE);
	writel(vf_id, qm->io_base + QM_VFT_CFG);

	writel(0x0, qm->io_base + QM_VFT_CFG_RDY);
	writel(0x1, qm->io_base + QM_VFT_CFG_OP_ENABLE);

	ret = readl_relaxed_poll_timeout(qm->io_base + QM_VFT_CFG_RDY, val,
					 val & BIT(0), POLL_PERIOD,
					 POLL_TIMEOUT);
	if (ret)
		return ret;

	sqc_vft = readl(qm->io_base + QM_VFT_CFG_DATA_L) |
		  ((u64)readl(qm->io_base + QM_VFT_CFG_DATA_H) <<
		  QM_XQC_ADDR_OFFSET);
	*rbase = QM_SQC_VFT_BASE_MASK_V2 &
		 (sqc_vft >> QM_SQC_VFT_BASE_SHIFT_V2);
	*rnumber = (QM_SQC_VFT_NUM_MASK_V2 &
		   (sqc_vft >> QM_SQC_VFT_NUM_SHIFT_V2)) + 1;

	return 0;
}

static int pf_qm_state_pre_save(struct hisi_qm *qm,
		struct acc_vf_migration *acc_vf_dev)
{
	struct acc_vf_data *vf_data = acc_vf_dev->vf_data;
	struct device *dev = &qm->pdev->dev;
	int vf_id = acc_vf_dev->vf_id;
	int ret;

	/* Vf acc type save */
	vf_data->acc_type = acc_vf_dev->acc_type;

	/* Vf qp num save from PF */
	ret = pf_qm_get_qp_num(qm, vf_id, &vf_data->qp_base, &vf_data->qp_num);
	if (ret) {
		dev_err(dev, "failed to get vft qp nums!\n");
		return -EINVAL;
	}

	/* Vf isolation state save from PF */
	ret = qm_read_reg(qm, QM_QUE_ISO_CFG_V, &vf_data->que_iso_cfg, 1);
	if (ret) {
		dev_err(dev, "failed to read QM_QUE_ISO_CFG_V!\n");
		return ret;
	}

	return 0;
}

static int vf_qm_state_save(struct hisi_qm *qm,
		struct acc_vf_migration *acc_vf_dev)
{
	struct device *dev = &acc_vf_dev->vf_dev->dev;
	int ret;

	/*
	 * check VM task driver state
	 * if vf_ready == 0x1, skip migrate.
	 */
	if (unlikely(qm_wait_dev_ready(qm))) {
		acc_vf_dev->mig_ignore = true;
		dev_err(&qm->pdev->dev, "QM device is not ready to read!\n");
		return 0;
	}

	/* First stop the ACC vf function */
	ret = vf_qm_func_stop(qm);
	if (ret) {
		dev_err(dev, "failed to stop QM VF function!\n");
		return ret;
	}

	/* Check the VF's RAS and Interrution state */
	ret = qm_check_int_state(acc_vf_dev);
	if (ret) {
		dev_err(dev, "failed to check QM INT state!\n");
		goto state_error;
	}

	/* hisi_qm_cache_wb store cache data to DDR */
	ret = vf_qm_cache_wb(qm);
	if (ret) {
		dev_err(dev, "failed to writeback QM Cache!\n");
		goto state_error;
	}

	ret = vf_migration_data_store(qm, acc_vf_dev);
	if (ret) {
		dev_err(dev, "failed to get and store migration data!\n");
		goto state_error;
	}

	return 0;

state_error:
	vf_qm_fun_restart(qm, acc_vf_dev);
	return ret;
}

static int vf_qm_state_resume(struct hisi_qm *qm,
		struct acc_vf_migration *acc_vf_dev)
{
	struct device *dev = &acc_vf_dev->vf_dev->dev;
	int ret;

	/* recover data to VF */
	ret = vf_migration_data_recover(qm, acc_vf_dev->vf_data);
	if (ret) {
		dev_err(dev, "failed to recover the VF!\n");
		return ret;
	}

	/* restart all destination VF's QP */
	vf_qm_fun_restart(qm, acc_vf_dev);

	return 0;
}

static int acc_vf_set_device_state(struct acc_vf_migration *acc_vf_dev,
				       u32 state)
{
	struct vfio_device_migration_info *mig_ctl = acc_vf_dev->mig_ctl;
	struct device *dev = &acc_vf_dev->vf_dev->dev;
	struct hisi_qm *pfqm = acc_vf_dev->pf_qm;
	struct hisi_qm *qm = acc_vf_dev->vf_qm;
	int ret = 0;

	if (state == mig_ctl->device_state)
		return 0;

	switch (state) {
	case VFIO_DEVICE_STATE_RUNNING:
		if (!mig_ctl->data_size)
			break;

		if (mig_ctl->device_state == VFIO_DEVICE_STATE_RESUMING) {
			ret = vf_qm_state_resume(qm, acc_vf_dev);
			if (ret) {
				dev_err(dev, "failed to resume device!\n");
				return -EFAULT;
			}
		}

		break;
	case VFIO_DEVICE_STATE_SAVING | VFIO_DEVICE_STATE_RUNNING:
		/* ACC should in the pre cycle to read match information data */
		ret = pf_qm_state_pre_save(pfqm, acc_vf_dev);
		if (ret) {
			dev_err(dev, "failed to pre save device state!\n");
			return -EFAULT;
		}

		/* set the pending_byte and match data size */
		mig_ctl->data_size = QM_MATCH_SIZE;
		mig_ctl->pending_bytes = mig_ctl->data_size;

		break;
	case VFIO_DEVICE_STATE_SAVING:
		/* stop the vf function */
		ret = vf_qm_state_save(qm, acc_vf_dev);
		if (ret) {
			dev_err(dev, "failed to save device state!\n");
			return -EFAULT;
		}

		if (acc_vf_dev->mig_ignore) {
			mig_ctl->data_size = 0;
			mig_ctl->pending_bytes = 0;
			break;
		}

		/* set the pending_byte and data_size */
		mig_ctl->data_size = sizeof(struct acc_vf_data);
		mig_ctl->pending_bytes = mig_ctl->data_size;

		break;
	case VFIO_DEVICE_STATE_STOP:
	case VFIO_DEVICE_STATE_RESUMING:
		break;
	default:
		ret = -EFAULT;
	}

	if (!ret) {
		dev_info(dev, "migration state: %s ----------> %s!\n",
			 vf_dev_state[mig_ctl->device_state],
			 vf_dev_state[state]);
		mig_ctl->device_state = state;
	}

	return ret;
}

static int acc_vf_data_transfer(struct acc_vf_migration *acc_vf_dev,
	char __user *buf, size_t count, u64 pos, bool iswrite)
{
	struct vfio_device_migration_info *mig_ctl = acc_vf_dev->mig_ctl;
	void *data_addr = acc_vf_dev->vf_data;
	int ret = 0;

	if (!count) {
		dev_err(&acc_vf_dev->vf_dev->dev,
			"Qemu operation data size error!\n");
		return -EINVAL;
	}

	data_addr += pos - mig_ctl->data_offset;
	if (iswrite)  {
		ret = copy_from_user(data_addr, buf, count) ?
				     -EFAULT : count;
		if (ret == count)
			mig_ctl->pending_bytes += count;
	} else {
		ret = copy_to_user(buf, data_addr, count) ?
				   -EFAULT : count;
		if (ret == count)
			mig_ctl->pending_bytes -= count;
	}

	return ret;
}

static int acc_vf_region_migration_rw(struct acc_vf_migration *acc_vf_dev,
	char __user *buf, size_t count, loff_t *ppos, bool iswrite)
{
	struct vfio_device_migration_info *mig_ctl = acc_vf_dev->mig_ctl;
	struct device *dev = &acc_vf_dev->vf_dev->dev;
	struct hisi_qm *qm = acc_vf_dev->vf_qm;
	u64 pos = *ppos & VFIO_PCI_OFFSET_MASK;
	u32 device_state;
	int ret = 0;

	switch (pos) {
	case VDM_OFFSET(device_state):
		if (count != sizeof(mig_ctl->device_state)) {
			ret = -EINVAL;
			break;
		}

		if (iswrite) {
			if (copy_from_user(&device_state, buf, count)) {
				ret = -EFAULT;
				break;
			}

			ret = acc_vf_set_device_state(acc_vf_dev,
					   device_state) ? ret : count;
		} else {
			ret = copy_to_user(buf, &mig_ctl->device_state,
					   count) ? -EFAULT : count;
		}
		break;
	case VDM_OFFSET(reserved):
		ret = -EFAULT;
		break;
	case VDM_OFFSET(pending_bytes):
		if (count != sizeof(mig_ctl->pending_bytes)) {
			ret = -EINVAL;
			break;
		}

		if (iswrite)
			ret = -EFAULT;
		else
			ret = copy_to_user(buf, &mig_ctl->pending_bytes,
					   count) ? -EFAULT : count;
		break;
	case VDM_OFFSET(data_offset):
		if (count != sizeof(mig_ctl->data_offset)) {
			ret = -EINVAL;
			break;
		}
		if (iswrite)
			ret = copy_from_user(&mig_ctl->data_offset, buf, count) ?
					     -EFAULT : count;
		else
			ret = copy_to_user(buf, &mig_ctl->data_offset, count) ?
					   -EFAULT : count;
		break;
	case VDM_OFFSET(data_size):
		if (count != sizeof(mig_ctl->data_size)) {
			ret = -EINVAL;
			break;
		}

		if (iswrite)
			ret = copy_from_user(&mig_ctl->data_size, buf, count) ?
					     -EFAULT : count;
		else
			ret = copy_to_user(buf, &mig_ctl->data_size, count) ?
					   -EFAULT : count;
		break;
	default:
		ret = -EFAULT;
		break;
	}

	/* Transfer data section */
	if (pos >= mig_ctl->data_offset &&
	    pos < MIGRATION_REGION_SZ) {
		ret = acc_vf_data_transfer(acc_vf_dev, buf,
					   count, pos, iswrite);
		if (ret != count)
			return ret;
	}

	if (mig_ctl->device_state == VFIO_DEVICE_STATE_RESUMING &&
	    mig_ctl->pending_bytes == QM_MATCH_SIZE &&
	    mig_ctl->data_size == QM_MATCH_SIZE) {
		/* check the VF match information */
		ret = vf_match_info_check(qm, acc_vf_dev);
		if (ret) {
			dev_err(dev, "failed to check match information!\n");
			return -EFAULT;
		}
		ret = count;

		/* clear the VF match data size */
		mig_ctl->pending_bytes = 0;
		mig_ctl->data_size = 0;
	}
	return ret;
}

static int acc_vf_region_migration_mmap(struct acc_vf_migration *acc_vf_dev,
					struct acc_vf_region *region,
					struct vm_area_struct *vma)
{
	return -EFAULT;
}

static void acc_vf_region_migration_release(struct acc_vf_migration *acc_vf_dev,
					    struct acc_vf_region *region)
{
	kfree(acc_vf_dev->mig_ctl);
	acc_vf_dev->mig_ctl = NULL;
}

static const struct acc_vf_region_ops acc_vf_region_ops_migration = {
	.rw		= acc_vf_region_migration_rw,
	.release	= acc_vf_region_migration_release,
	.mmap		= acc_vf_region_migration_mmap,
};

static int acc_vf_register_region(struct acc_vf_migration *acc_vf_dev,
				   const struct acc_vf_region_ops *ops,
				   void *data)
{
	struct acc_vf_region *regions;

	regions = krealloc(acc_vf_dev->regions,
			   (acc_vf_dev->num_regions + 1) * sizeof(*regions),
			   GFP_KERNEL);
	if (!regions)
		return -ENOMEM;

	acc_vf_dev->regions = regions;
	regions[acc_vf_dev->num_regions].type =
		VFIO_REGION_TYPE_MIGRATION;
	regions[acc_vf_dev->num_regions].subtype =
		VFIO_REGION_SUBTYPE_MIGRATION;
	regions[acc_vf_dev->num_regions].ops = ops;
	regions[acc_vf_dev->num_regions].size =
		MIGRATION_REGION_SZ;
	regions[acc_vf_dev->num_regions].flags =
		VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE;
	regions[acc_vf_dev->num_regions].data = data;
	acc_vf_dev->num_regions++;

	return 0;
}

static long acc_vf_get_region_info(void *device_data,
				    unsigned int cmd, unsigned long arg)
{
	int num_vdev_regions = vfio_pci_num_regions(device_data);
	struct acc_vf_migration *acc_vf_dev =
		vfio_pci_vendor_data(device_data);
	struct vfio_region_info_cap_type cap_type;
	struct acc_vf_region *regions;
	struct vfio_region_info info;
	struct vfio_info_cap caps;
	unsigned long minsz;
	int index, ret;

	minsz = offsetofend(struct vfio_region_info, offset);

	if (cmd != VFIO_DEVICE_GET_REGION_INFO)
		return -EINVAL;

	if (copy_from_user(&info, (void __user *)arg, minsz))
		return -EFAULT;

	if (info.argsz < minsz)
		return -EINVAL;

	if (info.index < VFIO_PCI_NUM_REGIONS + num_vdev_regions)
		goto default_handle;

	index = info.index - VFIO_PCI_NUM_REGIONS - num_vdev_regions;
	if (index > acc_vf_dev->num_regions) {
		dev_err(&acc_vf_dev->vf_dev->dev,
			"failed to check region numbers!\n");
		return -EINVAL;
	}

	info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
	regions = acc_vf_dev->regions;
	info.size = regions[index].size;
	info.flags = regions[index].flags;
	caps.buf = NULL;
	caps.size = 0;
	cap_type.header.id = VFIO_REGION_INFO_CAP_TYPE;
	cap_type.header.version = 1;
	cap_type.type = regions[index].type;
	cap_type.subtype = regions[index].subtype;

	ret = vfio_info_add_capability(&caps, &cap_type.header,
				       sizeof(cap_type));
	if (ret)
		return ret;

	if (regions[index].ops->add_cap) {
		ret = regions[index].ops->add_cap(acc_vf_dev,
						  &regions[index], &caps);
		if (ret) {
			kfree(caps.buf);
			return ret;
		}
	}

	if (caps.size) {
		info.flags |= VFIO_REGION_INFO_FLAG_CAPS;
		if (info.argsz < sizeof(info) + caps.size) {
			info.argsz = sizeof(info) + caps.size;
			info.cap_offset = 0;
		} else {
			vfio_info_cap_shift(&caps, sizeof(info));
			if (copy_to_user((void __user *)arg + sizeof(info),
					 caps.buf, caps.size)) {
				kfree(caps.buf);
				return -EFAULT;
			}
			info.cap_offset = sizeof(info);
		}
		kfree(caps.buf);
	}

	return copy_to_user((void __user *)arg, &info, minsz) ?
		-EFAULT : 0;

default_handle:
	ret = vfio_pci_ioctl(device_data, cmd, arg);
	if (ret)
		return ret;

	if (info.index == VFIO_PCI_BAR0_REGION_INDEX) {
		if (!acc_vf_dev->in_dirty_track)
			return ret;

		/* read default handler's data back */
		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		info.flags = VFIO_REGION_INFO_FLAG_READ |
			     VFIO_REGION_INFO_FLAG_WRITE;
		/* update customized region info */
		if (copy_to_user((void __user *)arg, &info, minsz))
			return -EFAULT;
	}

	if (info.index == VFIO_PCI_BAR2_REGION_INDEX) {
		info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
		/*
		 * ACC VF dev BAR2 region(64K) consists of both functional
		 * register space and migration control register space.
		 * Report only the first 32K(functional region) to Guest.
		 */
		info.size = pci_resource_len(acc_vf_dev->vf_dev, info.index) >> 1;
		info.flags = VFIO_REGION_INFO_FLAG_READ |
			     VFIO_REGION_INFO_FLAG_WRITE |
			     VFIO_REGION_INFO_FLAG_MMAP;
		if (copy_to_user((void __user *)arg, &info, minsz))
			return -EFAULT;
	}

	return ret;
}

static int acc_vf_open(void *device_data)
{
	struct acc_vf_migration *acc_vf_dev =
		vfio_pci_vendor_data(device_data);
	struct vfio_device_migration_info *mig_ctl;
	__u64 mig_offset;
	void *vf_data;
	int ret;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	mutex_lock(&acc_vf_dev->reflock);
	if (!acc_vf_dev->refcnt) {
		ret = acc_vf_register_region(acc_vf_dev,
					     &acc_vf_region_ops_migration,
					     NULL);
		if (ret)
			goto region_error;
		vfio_pci_set_vendor_regions(device_data,
					       acc_vf_dev->num_regions);

		/* the data region must follow migration info */
		mig_offset = sizeof(struct vfio_device_migration_info);
		mig_ctl = kzalloc(MIGRATION_REGION_SZ, GFP_KERNEL);
		if (!mig_ctl) {
			ret = -ENOMEM;
			goto mig_error;
		}
		acc_vf_dev->mig_ctl = mig_ctl;

		vf_data = (void *)mig_ctl + mig_offset;
		acc_vf_dev->vf_data = vf_data;

		mig_ctl->device_state = VFIO_DEVICE_STATE_RUNNING;
		mig_ctl->data_offset = mig_offset;
		mig_ctl->data_size = 0;
	}

	ret = vfio_pci_open(device_data);
	if (ret)
		goto open_error;

	acc_vf_dev->refcnt++;
	mutex_unlock(&acc_vf_dev->reflock);

	return 0;

open_error:
	if (!acc_vf_dev->refcnt) {
		kfree(acc_vf_dev->mig_ctl);
		acc_vf_dev->mig_ctl = NULL;
	}
mig_error:
	vfio_pci_set_vendor_regions(device_data, 0);
region_error:
	mutex_unlock(&acc_vf_dev->reflock);
	module_put(THIS_MODULE);
	return ret;
}

static void acc_vf_release(void *device_data)
{
	struct acc_vf_migration *acc_vf_dev =
		vfio_pci_vendor_data(device_data);
	int i;

	mutex_lock(&acc_vf_dev->reflock);
	if (!--acc_vf_dev->refcnt) {
		for (i = 0; i < acc_vf_dev->num_regions; i++) {
			if (!acc_vf_dev->regions[i].ops)
				continue;
			acc_vf_dev->regions[i].ops->release(acc_vf_dev,
						&acc_vf_dev->regions[i]);
		}
		kfree(acc_vf_dev->regions);
		acc_vf_dev->regions = NULL;
		acc_vf_dev->num_regions = 0;
		vfio_pci_set_vendor_regions(device_data, 0);

		kfree(acc_vf_dev->mig_ctl);
		acc_vf_dev->mig_ctl = NULL;
	}
	vfio_pci_release(device_data);
	mutex_unlock(&acc_vf_dev->reflock);
	module_put(THIS_MODULE);
}

static void acc_vf_reset(void *device_data)
{
	struct acc_vf_migration *acc_vf_dev =
		vfio_pci_vendor_data(device_data);
	struct hisi_qm *qm = acc_vf_dev->vf_qm;
	struct device *dev = &qm->pdev->dev;
	u32 vf_state = VF_NOT_READY;
	int ret;

	dev_info(dev, "QEMU prepare to Reset Guest!\n");
	ret = qm_write_reg(qm, QM_VF_STATE, &vf_state, 1);
	if (ret)
		dev_err(dev, "failed to write QM_VF_STATE\n");
}

static long acc_vf_ioctl(void *device_data,
			  unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case VFIO_DEVICE_GET_REGION_INFO:
		return acc_vf_get_region_info(device_data, cmd, arg);
	case VFIO_DEVICE_RESET:
		acc_vf_reset(device_data);
		return vfio_pci_ioctl(device_data, cmd, arg);
	default:
		return vfio_pci_ioctl(device_data, cmd, arg);
	}
}

static ssize_t acc_vf_read(void *device_data, char __user *buf,
			    size_t count, loff_t *ppos)
{
	struct acc_vf_migration *acc_vf_dev =
		vfio_pci_vendor_data(device_data);
	int num_vdev_regions = vfio_pci_num_regions(device_data);
	unsigned int index = VFIO_PCI_OFFSET_TO_INDEX(*ppos);
	int num_vendor_region = acc_vf_dev->num_regions;
	struct acc_vf_region *region;

	if (index >= VFIO_PCI_NUM_REGIONS + num_vdev_regions +
	    num_vendor_region) {
		dev_err(&acc_vf_dev->vf_dev->dev,
			"failed to check read regions index!\n");
		return -EINVAL;
	}

	if (index < VFIO_PCI_NUM_REGIONS + num_vdev_regions)
		return vfio_pci_read(device_data, buf, count, ppos);

	index -= VFIO_PCI_NUM_REGIONS + num_vdev_regions;

	region = &acc_vf_dev->regions[index];
	if (!region->ops->rw) {
		dev_err(&acc_vf_dev->vf_dev->dev,
			"failed to check regions read ops!\n");
		return -EINVAL;
	}

	return region->ops->rw(acc_vf_dev, buf, count, ppos, false);
}

static ssize_t acc_vf_write(void *device_data, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	struct acc_vf_migration *acc_vf_dev =
		vfio_pci_vendor_data(device_data);
	int num_vdev_regions = vfio_pci_num_regions(device_data);
	unsigned int index = VFIO_PCI_OFFSET_TO_INDEX(*ppos);
	int num_vendor_region = acc_vf_dev->num_regions;
	struct acc_vf_region *region;

	if (index == VFIO_PCI_BAR0_REGION_INDEX)
		pr_debug("vfio bar 0 write\n");

	if (index >= VFIO_PCI_NUM_REGIONS + num_vdev_regions +
	    num_vendor_region) {
		dev_err(&acc_vf_dev->vf_dev->dev,
			"failed to check write regions index!\n");
		return -EINVAL;
	}

	if (index < VFIO_PCI_NUM_REGIONS + num_vdev_regions)
		return vfio_pci_write(device_data, buf, count, ppos);

	index -= VFIO_PCI_NUM_REGIONS + num_vdev_regions;

	region = &acc_vf_dev->regions[index];

	if (!region->ops->rw) {
		dev_err(&acc_vf_dev->vf_dev->dev,
			"failed to check regions write ops!\n");
		return -EINVAL;
	}

	return region->ops->rw(acc_vf_dev, (char __user *)buf,
			       count, ppos, true);
}

static int acc_vf_mmap(void *device_data, struct vm_area_struct *vma)
{
	return vfio_pci_mmap(device_data, vma);
}

static void acc_vf_request(void *device_data, unsigned int count)
{
	vfio_pci_request(device_data, count);
}

static struct vfio_device_ops acc_vf_device_ops_node = {
	.name		= "acc_vf",
	.open		= acc_vf_open,
	.release	= acc_vf_release,
	.ioctl		= acc_vf_ioctl,
	.read		= acc_vf_read,
	.write		= acc_vf_write,
	.mmap		= acc_vf_mmap,
	.request	= acc_vf_request,
};

static ssize_t acc_vf_debug_read(struct file *filp, char __user *buffer,
			   size_t count, loff_t *pos)
{
	char buf[VFIO_DEV_DBG_LEN];
	int len;

	len = scnprintf(buf, VFIO_DEV_DBG_LEN, "%s\n",
			"echo 0: test vf data store\n"
			"echo 1: test vf data writeback\n"
			"echo 2: test vf send mailbox\n"
			"echo 3: dump vf dev data\n"
			"echo 4: dump migration state\n");

	return simple_read_from_buffer(buffer, count, pos, buf, len);
}

static ssize_t acc_vf_debug_write(struct file *filp, const char __user *buffer,
			    size_t count, loff_t *pos)
{
	struct acc_vf_migration *acc_vf_dev = filp->private_data;
	struct device *dev = &acc_vf_dev->vf_dev->dev;
	struct hisi_qm *qm = acc_vf_dev->vf_qm;
	char tbuf[VFIO_DEV_DBG_LEN];
	unsigned long val;
	u64 data;
	int len, ret;

	if (*pos)
		return 0;

	if (count >= VFIO_DEV_DBG_LEN)
		return -ENOSPC;

	len = simple_write_to_buffer(tbuf, VFIO_DEV_DBG_LEN - 1,
					pos, buffer, count);
	if (len < 0)
		return len;
	tbuf[len] = '\0';
	if (kstrtoul(tbuf, 0, &val))
		return -EFAULT;

	switch (val) {
	case STATE_SAVE:
		ret = vf_qm_state_save(qm, acc_vf_dev);
		if (ret)
			return -EINVAL;
		break;
	case STATE_RESUME:
		ret = vf_qm_state_resume(qm, acc_vf_dev);
		if (ret)
			return -EINVAL;
		break;
	case MB_TEST:
		data = readl(qm->io_base + QM_MB_CMD_SEND_BASE);
		dev_info(dev, "debug mailbox addr: 0x%lx, mailbox val: 0x%llx\n",
			 (uintptr_t)qm->phys_base, data);
		break;
	case MIG_DATA_DUMP:
		dev_info(dev, "dumped vf migration data:\n");
		print_hex_dump(KERN_INFO, "Mig Data:", DUMP_PREFIX_OFFSET,
				VFIO_DBG_LOG_LEN, 1,
				(unsigned char *)acc_vf_dev->vf_data,
				sizeof(struct acc_vf_data), false);
		break;
	case MIG_DEV_SHOW:
		if (!acc_vf_dev->mig_ctl)
			dev_info(dev, "migration region have release!\n");
		else
			dev_info(dev,
				 "device  state: %u\n"
				 "data   offset: %llu\n"
				 "data     size: %llu\n"
				 "pending bytes: %llu\n"
				 "data     addr: 0x%lx\n",
				 acc_vf_dev->mig_ctl->device_state,
				 acc_vf_dev->mig_ctl->data_offset,
				 acc_vf_dev->mig_ctl->data_size,
				 acc_vf_dev->mig_ctl->pending_bytes,
				 (uintptr_t)acc_vf_dev->vf_data);
		break;
	default:
		return -EINVAL;
	}

	return count;
}

static const struct file_operations acc_vf_debug_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = acc_vf_debug_read,
	.write = acc_vf_debug_write,
};

static ssize_t acc_vf_state_read(struct file *filp, char __user *buffer,
			   size_t count, loff_t *pos)
{
	struct acc_vf_migration *acc_vf_dev = filp->private_data;
	char buf[VFIO_DEV_DBG_LEN];
	u32 state;
	int len;

	if (!acc_vf_dev->mig_ctl) {
		len = scnprintf(buf, VFIO_DEV_DBG_LEN, "%s\n", "Invalid\n");
	} else {
		state = acc_vf_dev->mig_ctl->device_state;
		switch (state) {
		case VFIO_DEVICE_STATE_RUNNING:
			len = scnprintf(buf, VFIO_DEV_DBG_LEN, "%s\n",
				"RUNNING\n");
			break;
		case VFIO_DEVICE_STATE_SAVING | VFIO_DEVICE_STATE_RUNNING:
			len = scnprintf(buf, VFIO_DEV_DBG_LEN, "%s\n",
				"SAVING and RUNNING\n");
			break;
		case VFIO_DEVICE_STATE_SAVING:
			len = scnprintf(buf, VFIO_DEV_DBG_LEN, "%s\n",
				"SAVING\n");
			break;
		case VFIO_DEVICE_STATE_STOP:
			len = scnprintf(buf, VFIO_DEV_DBG_LEN, "%s\n",
				"STOP\n");
			break;
		case VFIO_DEVICE_STATE_RESUMING:
			len = scnprintf(buf, VFIO_DEV_DBG_LEN, "%s\n",
				"RESUMING\n");
			break;
		default:
			len = scnprintf(buf, VFIO_DEV_DBG_LEN, "%s\n",
				"Error\n");
		}
	}

	return simple_read_from_buffer(buffer, count, pos, buf, len);
}

static const struct file_operations acc_vf_state_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = acc_vf_state_read,
};

static void vf_debugfs_init(struct acc_vf_migration *acc_vf_dev)
{
	char name[VFIO_DEV_DBG_LEN];
	int node_id;

	if (!mig_root_ref)
		mig_debugfs_root = debugfs_create_dir("vfio_acc", NULL);
	mutex_lock(&acc_vf_dev->reflock);
	mig_root_ref++;
	mutex_unlock(&acc_vf_dev->reflock);

	node_id = dev_to_node(&acc_vf_dev->vf_dev->dev);
	if (node_id < 0)
		node_id = 0;

	if (acc_vf_dev->acc_type == HISI_SEC)
		scnprintf(name, VFIO_DEV_DBG_LEN, "sec_vf%d-%d",
			  node_id, acc_vf_dev->vf_id);
	else if (acc_vf_dev->acc_type == HISI_HPRE)
		scnprintf(name, VFIO_DEV_DBG_LEN, "hpre_vf%d-%d",
			  node_id, acc_vf_dev->vf_id);
	else
		scnprintf(name, VFIO_DEV_DBG_LEN, "zip_vf%d-%d",
			  node_id, acc_vf_dev->vf_id);

	acc_vf_dev->debug_root = debugfs_create_dir(name, mig_debugfs_root);

	debugfs_create_file("debug", 0644, acc_vf_dev->debug_root,
			    acc_vf_dev, &acc_vf_debug_fops);
	debugfs_create_file("state", 0444, acc_vf_dev->debug_root,
			    acc_vf_dev, &acc_vf_state_fops);
}

static void vf_debugfs_exit(struct acc_vf_migration *acc_vf_dev)
{
	debugfs_remove_recursive(acc_vf_dev->debug_root);

	mutex_lock(&acc_vf_dev->reflock);
	mig_root_ref--;
	mutex_unlock(&acc_vf_dev->reflock);

	if (!mig_root_ref)
		debugfs_remove_recursive(mig_debugfs_root);
}

static int qm_acc_type_init(struct acc_vf_migration *acc_vf_dev)
{
	struct hisi_qm *qm = acc_vf_dev->vf_qm;
	int i;

	acc_vf_dev->acc_type = 0;
	for (i = 0; i < ARRAY_SIZE(vf_acc_types); i++) {
		if (!strncmp(qm->dev_name, vf_acc_types[i].name,
		    strlen(vf_acc_types[i].name)))
			acc_vf_dev->acc_type = vf_acc_types[i].type;
	}
	if (!acc_vf_dev->acc_type) {
		dev_err(&acc_vf_dev->vf_dev->dev, "failed to check acc type!\n");
		return -EINVAL;
	}

	return 0;
}

static int vf_qm_pci_init(struct pci_dev *pdev, struct hisi_qm *vfqm)
{
	struct device *dev = &pdev->dev;
	u32 val;
	int ret;

	ret = pci_request_mem_regions(pdev, vfqm->dev_name);
	if (ret < 0) {
		dev_err(dev, "failed to request mem regions!\n");
		return ret;
	}

	vfqm->phys_base = pci_resource_start(pdev, PCI_BAR_2);
	vfqm->io_base = devm_ioremap(dev, pci_resource_start(pdev, PCI_BAR_2),
				     pci_resource_len(pdev, PCI_BAR_2));
	if (!vfqm->io_base) {
		ret = -EIO;
		goto err_ioremap;
	}

	val = readl(vfqm->io_base + QM_QUE_ISO_CFG_V);
	val = val & BIT(0);
	if (val) {
		vfqm->db_phys_base = pci_resource_start(pdev, PCI_BAR_4);
		vfqm->db_io_base = devm_ioremap(dev, pci_resource_start(pdev,
				PCI_BAR_4), pci_resource_len(pdev, PCI_BAR_4));
		if (!vfqm->db_io_base) {
			ret = -EIO;
			goto err_db_ioremap;
		}
	} else {
		vfqm->db_phys_base = vfqm->phys_base;
		vfqm->db_io_base = vfqm->io_base;
	}

	vfqm->pdev = pdev;
	mutex_init(&vfqm->mailbox_lock);

	/*
	 * Allow VF devices to be loaded in VM when
	 * it loaded in migration driver
	 */
	pci_release_mem_regions(pdev);

	return 0;

err_db_ioremap:
	devm_iounmap(dev, vfqm->io_base);
err_ioremap:
	pci_release_mem_regions(pdev);
	return ret;
}

static int acc_vf_dev_init(struct pci_dev *pdev, struct hisi_qm *pf_qm,
			   struct acc_vf_migration *acc_vf_dev)
{
	struct hisi_qm *vf_qm;
	int ret;

	vf_qm = kzalloc(sizeof(struct hisi_qm), GFP_KERNEL);
	if (!vf_qm)
		return -ENOMEM;

	/* get vf qm dev name from pf */
	vf_qm->dev_name = pf_qm->dev_name;
	vf_qm->fun_type = QM_HW_VF;
	acc_vf_dev->vf_qm = vf_qm;
	acc_vf_dev->pf_qm = pf_qm;

	ret = vf_qm_pci_init(pdev, vf_qm);
	if (ret)
		goto init_qm_error;

	ret = qm_acc_type_init(acc_vf_dev);
	if (ret)
		goto init_qm_error;

	return 0;

init_qm_error:
	kfree(vf_qm);
	return -ENOMEM;
}

static int hisi_acc_get_vf_id(struct pci_dev *dev)
{
	struct pci_dev *pf;

	if (!dev->is_virtfn)
		return -EINVAL;

	pf = pci_physfn(dev);
	return (((dev->bus->number << 8) + dev->devfn) -
		((pf->bus->number << 8) + pf->devfn + pf->sriov->offset)) /
	       pf->sriov->stride;
}

static void *acc_vf_probe(struct pci_dev *pdev)
{
	struct acc_vf_migration *acc_vf_dev;
	struct pci_dev *pf_dev, *vf_dev;
	struct hisi_qm *pf_qm;
	int vf_id, ret;

	pf_dev = pdev->physfn;
	vf_dev = pdev;
	/*
	 * the VF driver have been remove after unbind
	 * the PF driver have probe
	 */
	pf_qm = pci_get_drvdata(pf_dev);
	if (!pf_qm) {
		dev_err(&pdev->dev, "host qm driver not insmod!\n");
		return ERR_PTR(-EINVAL);
	}
	if (pf_qm->ver < QM_HW_V3) {
		dev_err(&pdev->dev,
			"device can't support migration! version: 0x%x\n",
			pf_qm->ver);
		return ERR_PTR(-EINVAL);
	}

	vf_id = hisi_acc_get_vf_id(vf_dev);
	if (vf_id < 0) {
		dev_info(&pdev->dev, "vf device: %s, vf id: %d\n",
			 pf_qm->dev_name, vf_id);
		return ERR_PTR(-EINVAL);
	}

	acc_vf_dev = kzalloc(sizeof(*acc_vf_dev), GFP_KERNEL);
	if (!acc_vf_dev)
		return ERR_PTR(-ENOMEM);

	ret = acc_vf_dev_init(pdev, pf_qm, acc_vf_dev);
	if (ret) {
		kfree(acc_vf_dev);
		return ERR_PTR(-ENOMEM);
	}

	acc_vf_dev->vf_id = vf_id + 1;
	acc_vf_dev->vf_vendor = pdev->vendor;
	acc_vf_dev->vf_device = pdev->device;
	acc_vf_dev->pf_dev = pf_dev;
	acc_vf_dev->vf_dev = vf_dev;
	acc_vf_dev->mig_ignore = false;
	mutex_init(&acc_vf_dev->reflock);

	vf_debugfs_init(acc_vf_dev);

	return acc_vf_dev;
}

static void acc_vf_remove(void *vendor_data)
{
	struct acc_vf_migration *acc_vf_dev = vendor_data;
	struct device *dev = &acc_vf_dev->vf_dev->dev;
	struct hisi_qm *qm = acc_vf_dev->vf_qm;

	vf_debugfs_exit(acc_vf_dev);

	devm_iounmap(dev, qm->io_base);

	kfree(qm);
	kfree(acc_vf_dev);
}

static struct vfio_pci_vendor_driver_ops  sec_vf_mig_ops = {
	.owner		= THIS_MODULE,
	.name		= "hisi_sec2",
	.vendor		= PCI_VENDOR_ID_HUAWEI,
	.device		= PCI_DEVICE_ID_HUAWEI_SEC_VF,
	.probe		= acc_vf_probe,
	.remove		= acc_vf_remove,
	.device_ops	= &acc_vf_device_ops_node,
};

static struct vfio_pci_vendor_driver_ops  hpre_vf_mig_ops = {
	.owner		= THIS_MODULE,
	.name		= "hisi_hpre",
	.vendor		= PCI_VENDOR_ID_HUAWEI,
	.device		= PCI_DEVICE_ID_HUAWEI_HPRE_VF,
	.probe		= acc_vf_probe,
	.remove		= acc_vf_remove,
	.device_ops	= &acc_vf_device_ops_node,
};

static struct vfio_pci_vendor_driver_ops  zip_vf_mig_ops = {
	.owner		= THIS_MODULE,
	.name		= "hisi_zip",
	.vendor		= PCI_VENDOR_ID_HUAWEI,
	.device		= PCI_DEVICE_ID_HUAWEI_ZIP_VF,
	.probe		= acc_vf_probe,
	.remove		= acc_vf_remove,
	.device_ops	= &acc_vf_device_ops_node,
};

static int __init acc_vf_module_init(void)
{
	__vfio_pci_register_vendor_driver(&sec_vf_mig_ops);

	__vfio_pci_register_vendor_driver(&hpre_vf_mig_ops);

	__vfio_pci_register_vendor_driver(&zip_vf_mig_ops);

	return 0;
};

static void __exit acc_vf_module_exit(void)
{
	vfio_pci_unregister_vendor_driver(&sec_vf_mig_ops);
	vfio_pci_unregister_vendor_driver(&hpre_vf_mig_ops);
	vfio_pci_unregister_vendor_driver(&zip_vf_mig_ops);
};
module_init(acc_vf_module_init);
module_exit(acc_vf_module_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Longfang Liu <liulongfang@huawei.com>");
MODULE_DESCRIPTION("HiSilicon Accelerator VF live migration driver");
