// SPDX-License-Identifier: GPL-2.0
/*
 * Linux spraid device driver
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */
#define pr_fmt(fmt) "spraid: " fmt

#include <linux/sched/signal.h>
#include <linux/version.h>
#include <linux/pci.h>
#include <linux/aer.h>
#include <linux/module.h>
#include <linux/ioport.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/cdev.h>
#include <linux/sysfs.h>
#include <linux/gfp.h>
#include <linux/types.h>
#include <linux/ratelimit.h>
#include <linux/once.h>
#include <linux/debugfs.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/blkdev.h>

#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_transport.h>
#include <scsi/scsi_dbg.h>

#include "spraid.h"

static u32 admin_tmout = 60;
module_param(admin_tmout, uint, 0644);
MODULE_PARM_DESC(admin_tmout, "admin commands timeout (seconds)");

static u32 scmd_tmout_pt = 30;
module_param(scmd_tmout_pt, uint, 0644);
MODULE_PARM_DESC(scmd_tmout_pt, "scsi commands timeout for passthrough(seconds)");

static u32 scmd_tmout_nonpt = 180;
module_param(scmd_tmout_nonpt, uint, 0644);
MODULE_PARM_DESC(scmd_tmout_nonpt, "scsi commands timeout for rawdisk&raid(seconds)");

static u32 wait_abl_tmout = 3;
module_param(wait_abl_tmout, uint, 0644);
MODULE_PARM_DESC(wait_abl_tmout, "wait abnormal io timeout(seconds)");

static bool use_sgl_force;
module_param(use_sgl_force, bool, 0644);
MODULE_PARM_DESC(use_sgl_force, "force IO use sgl format, default false");

static int ioq_depth_set(const char *val, const struct kernel_param *kp);
static const struct kernel_param_ops ioq_depth_ops = {
	.set = ioq_depth_set,
	.get = param_get_uint,
};

static u32 io_queue_depth = 1024;
module_param_cb(io_queue_depth, &ioq_depth_ops, &io_queue_depth, 0644);
MODULE_PARM_DESC(io_queue_depth, "set io queue depth, should >= 2");

static int log_debug_switch_set(const char *val, const struct kernel_param *kp)
{
	u8 n = 0;
	int ret;

	ret = kstrtou8(val, 10, &n);
	if (ret != 0)
		return -EINVAL;

	return param_set_byte(val, kp);
}

static const struct kernel_param_ops log_debug_switch_ops = {
	.set = log_debug_switch_set,
	.get = param_get_byte,
};

static unsigned char log_debug_switch;
module_param_cb(log_debug_switch, &log_debug_switch_ops, &log_debug_switch, 0644);
MODULE_PARM_DESC(log_debug_switch, "set log state, default non-zero for switch on");

static int small_pool_num_set(const char *val, const struct kernel_param *kp)
{
	u8 n = 0;
	int ret;

	ret = kstrtou8(val, 10, &n);
	if (ret != 0)
		return -EINVAL;
	if (n > MAX_SMALL_POOL_NUM)
		n = MAX_SMALL_POOL_NUM;
	if (n < 1)
		n = 1;
	*((u8 *)kp->arg) = n;

	return 0;
}

static const struct kernel_param_ops small_pool_num_ops = {
	.set = small_pool_num_set,
	.get = param_get_byte,
};

static unsigned char small_pool_num = 4;
module_param_cb(small_pool_num, &small_pool_num_ops, &small_pool_num, 0644);
MODULE_PARM_DESC(small_pool_num, "set prp small pool num, default 4, MAX 16");

static void spraid_free_queue(struct spraid_queue *spraidq);
static void spraid_handle_aen_notice(struct spraid_dev *hdev, u32 result);
static void spraid_handle_aen_vs(struct spraid_dev *hdev, u32 result);

static DEFINE_IDA(spraid_instance_ida);
static dev_t spraid_chr_devt;
static struct class *spraid_class;

#define SPRAID_CAP_TIMEOUT_UNIT_MS	(HZ / 2)

static struct workqueue_struct *spraid_wq;

#define dev_log_dbg(dev, fmt, ...)	do { \
	if (unlikely(log_debug_switch))	\
		dev_info(dev, "[%s] [%d] " fmt,	\
			__func__, __LINE__, ##__VA_ARGS__);	\
} while (0)

#define SPRAID_DRV_VERSION	"1.0.0.0"

#define ADMIN_TIMEOUT		(admin_tmout * HZ)
#define ADMIN_ERR_TIMEOUT	32757

#define SPRAID_WAIT_ABNL_CMD_TIMEOUT	(wait_abl_tmout * 2)

#define SPRAID_DMA_MSK_BIT_MAX	64

enum FW_STAT_CODE {
	FW_STAT_OK = 0,
	FW_STAT_NEED_CHECK,
	FW_STAT_ERROR,
	FW_STAT_EP_PCIE_ERROR,
	FW_STAT_NAC_DMA_ERROR,
	FW_STAT_ABORTED,
	FW_STAT_NEED_RETRY
};

static int ioq_depth_set(const char *val, const struct kernel_param *kp)
{
	int n = 0;
	int ret;

	ret = kstrtoint(val, 10, &n);
	if (ret != 0 || n < 2)
		return -EINVAL;

	return param_set_int(val, kp);
}

static int spraid_remap_bar(struct spraid_dev *hdev, u32 size)
{
	struct pci_dev *pdev = hdev->pdev;

	if (size > pci_resource_len(pdev, 0)) {
		dev_err(hdev->dev, "Input size[%u] exceed bar0 length[%llu]\n",
			size, pci_resource_len(pdev, 0));
		return -ENOMEM;
	}

	if (hdev->bar)
		iounmap(hdev->bar);

	hdev->bar = ioremap(pci_resource_start(pdev, 0), size);
	if (!hdev->bar) {
		dev_err(hdev->dev, "ioremap for bar0 failed\n");
		return -ENOMEM;
	}
	hdev->dbs = hdev->bar + SPRAID_REG_DBS;

	return 0;
}

static int spraid_dev_map(struct spraid_dev *hdev)
{
	struct pci_dev *pdev = hdev->pdev;
	int ret;

	ret = pci_request_mem_regions(pdev, "spraid");
	if (ret) {
		dev_err(hdev->dev, "fail to request memory regions\n");
		return ret;
	}

	ret = spraid_remap_bar(hdev, SPRAID_REG_DBS + 4096);
	if (ret) {
		pci_release_mem_regions(pdev);
		return ret;
	}

	return 0;
}

static void spraid_dev_unmap(struct spraid_dev *hdev)
{
	struct pci_dev *pdev = hdev->pdev;

	if (hdev->bar) {
		iounmap(hdev->bar);
		hdev->bar = NULL;
	}
	pci_release_mem_regions(pdev);
}

static int spraid_pci_enable(struct spraid_dev *hdev)
{
	struct pci_dev *pdev = hdev->pdev;
	int ret = -ENOMEM;
	u64 maskbit = SPRAID_DMA_MSK_BIT_MAX;

	if (pci_enable_device_mem(pdev)) {
		dev_err(hdev->dev, "Enable pci device memory resources failed\n");
		return ret;
	}
	pci_set_master(pdev);

	if (readl(hdev->bar + SPRAID_REG_CSTS) == U32_MAX) {
		ret = -ENODEV;
		dev_err(hdev->dev, "Read csts register failed\n");
		goto disable;
	}

	ret = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_ALL_TYPES);
	if (ret < 0) {
		dev_err(hdev->dev, "Allocate one IRQ for setup admin channel failed\n");
		goto disable;
	}

	hdev->cap = lo_hi_readq(hdev->bar + SPRAID_REG_CAP);
	hdev->ioq_depth = min_t(u32, SPRAID_CAP_MQES(hdev->cap) + 1, io_queue_depth);
	hdev->db_stride = 1 << SPRAID_CAP_STRIDE(hdev->cap);

	maskbit = SPRAID_CAP_DMAMASK(hdev->cap);
	if (maskbit < 32 || maskbit > SPRAID_DMA_MSK_BIT_MAX) {
		dev_err(hdev->dev, "err, dma mask invalid[%llu], set to default\n", maskbit);
		maskbit = SPRAID_DMA_MSK_BIT_MAX;
	}
	if (dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(maskbit))) {
		dev_err(hdev->dev, "set dma mask and coherent failed\n");
		goto disable;
	}

	dev_info(hdev->dev, "set dma mask[%llu] success\n", maskbit);

	pci_enable_pcie_error_reporting(pdev);
	pci_save_state(pdev);

	return 0;

disable:
	pci_disable_device(pdev);
	return ret;
}

static inline
struct spraid_admin_request *spraid_admin_req(struct request *req)
{
	return blk_mq_rq_to_pdu(req);
}

static int spraid_npages_prp(u32 size, struct spraid_dev *hdev)
{
	u32 nprps = DIV_ROUND_UP(size + hdev->page_size, hdev->page_size);

	return DIV_ROUND_UP(PRP_ENTRY_SIZE * nprps, PAGE_SIZE - PRP_ENTRY_SIZE);
}

static int spraid_npages_sgl(u32 nseg)
{
	return DIV_ROUND_UP(nseg * sizeof(struct spraid_sgl_desc), PAGE_SIZE);
}

static void **spraid_iod_list(struct spraid_iod *iod)
{
	return (void **)(iod->inline_sg + (iod->sg_drv_mgmt ? iod->nsge : 0));
}

static u32 spraid_iod_ext_size(struct spraid_dev *hdev, u32 size, u32 nsge,
			       bool sg_drv_mgmt, bool use_sgl)
{
	size_t alloc_size, sg_size;

	if (use_sgl)
		alloc_size = sizeof(__le64 *) * spraid_npages_sgl(nsge);
	else
		alloc_size = sizeof(__le64 *) * spraid_npages_prp(size, hdev);

	sg_size = sg_drv_mgmt ? (sizeof(struct scatterlist) * nsge) : 0;
	return sg_size + alloc_size;
}

static u32 spraid_cmd_size(struct spraid_dev *hdev, bool sg_drv_mgmt, bool use_sgl)
{
	u32 alloc_size = spraid_iod_ext_size(hdev, SPRAID_INT_BYTES(hdev),
				SPRAID_INT_PAGES, sg_drv_mgmt, use_sgl);

	dev_info(hdev->dev, "sg_drv_mgmt: %s, use_sgl: %s, iod size: %lu, alloc_size: %u\n",
		    sg_drv_mgmt ? "true" : "false", use_sgl ? "true" : "false",
		    sizeof(struct spraid_iod), alloc_size);

	return sizeof(struct spraid_iod) + alloc_size;
}

static int spraid_setup_prps(struct spraid_dev *hdev, struct spraid_iod *iod)
{
	struct scatterlist *sg = iod->sg;
	u64 dma_addr = sg_dma_address(sg);
	int dma_len = sg_dma_len(sg);
	__le64 *prp_list, *old_prp_list;
	u32 page_size = hdev->page_size;
	int offset = dma_addr & (page_size - 1);
	void **list = spraid_iod_list(iod);
	int length = iod->length;
	struct dma_pool *pool;
	dma_addr_t prp_dma;
	int nprps, i;

	length -= (page_size - offset);
	if (length <= 0) {
		iod->first_dma = 0;
		return 0;
	}

	dma_len -= (page_size - offset);
	if (dma_len) {
		dma_addr += (page_size - offset);
	} else {
		sg = sg_next(sg);
		dma_addr = sg_dma_address(sg);
		dma_len = sg_dma_len(sg);
	}

	if (length <= page_size) {
		iod->first_dma = dma_addr;
		return 0;
	}

	nprps = DIV_ROUND_UP(length, page_size);
	if (nprps <= (SMALL_POOL_SIZE / PRP_ENTRY_SIZE)) {
		pool = iod->spraidq->prp_small_pool;
		iod->npages = 0;
	} else {
		pool = hdev->prp_page_pool;
		iod->npages = 1;
	}

	prp_list = dma_pool_alloc(pool, GFP_ATOMIC, &prp_dma);
	if (!prp_list) {
		dev_err_ratelimited(hdev->dev, "Allocate first prp_list memory failed\n");
		iod->first_dma = dma_addr;
		iod->npages = -1;
		return -ENOMEM;
	}
	list[0] = prp_list;
	iod->first_dma = prp_dma;
	i = 0;
	for (;;) {
		if (i == page_size / PRP_ENTRY_SIZE) {
			old_prp_list = prp_list;

			prp_list = dma_pool_alloc(pool, GFP_ATOMIC, &prp_dma);
			if (!prp_list) {
				dev_err_ratelimited(hdev->dev, "Allocate %dth prp_list memory failed\n",
						    iod->npages + 1);
				return -ENOMEM;
			}
			list[iod->npages++] = prp_list;
			prp_list[0] = old_prp_list[i - 1];
			old_prp_list[i - 1] = cpu_to_le64(prp_dma);
			i = 1;
		}
		prp_list[i++] = cpu_to_le64(dma_addr);
		dma_len -= page_size;
		dma_addr += page_size;
		length -= page_size;
		if (length <= 0)
			break;
		if (dma_len > 0)
			continue;
		if (unlikely(dma_len < 0))
			goto bad_sgl;
		sg = sg_next(sg);
		dma_addr = sg_dma_address(sg);
		dma_len = sg_dma_len(sg);
	}

	return 0;

bad_sgl:
	dev_err(hdev->dev, "Setup prps, invalid SGL for payload: %d nents: %d\n",
		iod->length, iod->nsge);
	return -EIO;
}

#define SGES_PER_PAGE    (PAGE_SIZE / sizeof(struct spraid_sgl_desc))

static void spraid_submit_cmd(struct spraid_queue *spraidq, const void *cmd)
{
	u32 sqes = SQE_SIZE(spraidq->qid);
	unsigned long flags;
	struct spraid_admin_common_command *acd = (struct spraid_admin_common_command *)cmd;

	spin_lock_irqsave(&spraidq->sq_lock, flags);
	memcpy((spraidq->sq_cmds + sqes * spraidq->sq_tail), cmd, sqes);
	if (++spraidq->sq_tail == spraidq->q_depth)
		spraidq->sq_tail = 0;

	writel(spraidq->sq_tail, spraidq->q_db);
	spin_unlock_irqrestore(&spraidq->sq_lock, flags);

	dev_log_dbg(spraidq->hdev->dev, "cid[%d], qid[%d], opcode[0x%x], flags[0x%x], hdid[%u]\n",
		    acd->command_id, spraidq->qid, acd->opcode, acd->flags, le32_to_cpu(acd->hdid));
}

static u32 spraid_mod64(u64 dividend, u32 divisor)
{
	u64 d;
	u32 remainder;

	if (!divisor)
		pr_err("DIVISOR is zero, in div fn\n");

	d = dividend;
	remainder = do_div(d, divisor);
	return remainder;
}

static inline bool spraid_is_rw_scmd(struct scsi_cmnd *scmd)
{
	switch (scmd->cmnd[0]) {
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
	case READ_32:
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
	case WRITE_32:
		return true;
	default:
		return false;
	}
}

static bool spraid_is_prp(struct spraid_dev *hdev, struct scsi_cmnd *scmd, u32 nsge)
{
	struct scatterlist *sg = scsi_sglist(scmd);
	u32 page_size = hdev->page_size;
	bool is_prp = true;
	int i = 0;

	scsi_for_each_sg(scmd, sg, nsge, i) {
		if (i != 0 && i != nsge - 1) {
			if (spraid_mod64(sg_dma_len(sg), page_size) ||
			    spraid_mod64(sg_dma_address(sg), page_size)) {
				is_prp = false;
				break;
			}
		}

		if (nsge > 1 && i == 0) {
			if ((spraid_mod64((sg_dma_address(sg) + sg_dma_len(sg)), page_size))) {
				is_prp = false;
				break;
			}
		}

		if (nsge > 1 && i == (nsge - 1)) {
			if (spraid_mod64(sg_dma_address(sg), page_size)) {
				is_prp = false;
				break;
			}
		}
	}

	return is_prp;
}

enum {
	SPRAID_SGL_FMT_DATA_DESC     = 0x00,
	SPRAID_SGL_FMT_SEG_DESC      = 0x02,
	SPRAID_SGL_FMT_LAST_SEG_DESC    = 0x03,
	SPRAID_KEY_SGL_FMT_DATA_DESC    = 0x04,
	SPRAID_TRANSPORT_SGL_DATA_DESC  = 0x05
};

static void spraid_sgl_set_data(struct spraid_sgl_desc *sge, struct scatterlist *sg)
{
	sge->addr = cpu_to_le64(sg_dma_address(sg));
	sge->length = cpu_to_le32(sg_dma_len(sg));
	sge->type = SPRAID_SGL_FMT_DATA_DESC << 4;
}

static void spraid_sgl_set_seg(struct spraid_sgl_desc *sge, dma_addr_t dma_addr, int entries)
{
	sge->addr = cpu_to_le64(dma_addr);
	if (entries <= SGES_PER_PAGE) {
		sge->length = cpu_to_le32(entries * sizeof(*sge));
		sge->type = SPRAID_SGL_FMT_LAST_SEG_DESC << 4;
	} else {
		sge->length = cpu_to_le32(PAGE_SIZE);
		sge->type = SPRAID_SGL_FMT_SEG_DESC << 4;
	}
}

static int spraid_setup_ioq_cmd_sgl(struct spraid_dev *hdev,
				    struct scsi_cmnd *scmd, struct spraid_ioq_command *ioq_cmd,
				    struct spraid_iod *iod)
{
	struct spraid_sgl_desc *sg_list, *link, *old_sg_list;
	struct scatterlist *sg = scsi_sglist(scmd);
	void **list = spraid_iod_list(iod);
	struct dma_pool *pool;
	int nsge = iod->nsge;
	dma_addr_t sgl_dma;
	int i = 0;

	ioq_cmd->common.flags |= SPRAID_CMD_FLAG_SGL_METABUF;

	if (nsge == 1) {
		spraid_sgl_set_data(&ioq_cmd->common.dptr.sgl, sg);
		return 0;
	}

	if (nsge <= (SMALL_POOL_SIZE / sizeof(struct spraid_sgl_desc))) {
		pool = iod->spraidq->prp_small_pool;
		iod->npages = 0;
	} else {
		pool = hdev->prp_page_pool;
		iod->npages = 1;
	}

	sg_list = dma_pool_alloc(pool, GFP_ATOMIC, &sgl_dma);
	if (!sg_list) {
		dev_err_ratelimited(hdev->dev, "Allocate first sgl_list failed\n");
		iod->npages = -1;
		return -ENOMEM;
	}

	list[0] = sg_list;
	iod->first_dma = sgl_dma;
	spraid_sgl_set_seg(&ioq_cmd->common.dptr.sgl, sgl_dma, nsge);
	do {
		if (i == SGES_PER_PAGE) {
			old_sg_list = sg_list;
			link = &old_sg_list[SGES_PER_PAGE - 1];

			sg_list = dma_pool_alloc(pool, GFP_ATOMIC, &sgl_dma);
			if (!sg_list) {
				dev_err_ratelimited(hdev->dev, "Allocate %dth sgl_list failed\n",
						    iod->npages + 1);
				return -ENOMEM;
			}
			list[iod->npages++] = sg_list;

			i = 0;
			memcpy(&sg_list[i++], link, sizeof(*link));
			spraid_sgl_set_seg(link, sgl_dma, nsge);
		}

		spraid_sgl_set_data(&sg_list[i++], sg);
		sg = sg_next(sg);
	} while (--nsge > 0);

	return 0;
}

#define SPRAID_RW_FUA	BIT(14)

static void spraid_setup_rw_cmd(struct spraid_dev *hdev,
				struct spraid_rw_command *rw,
				struct scsi_cmnd *scmd)
{
	u32 start_lba_lo, start_lba_hi;
	u32 datalength = 0;
	u16 control = 0;

	start_lba_lo = 0;
	start_lba_hi = 0;

	if (scmd->sc_data_direction == DMA_TO_DEVICE) {
		rw->opcode = SPRAID_CMD_WRITE;
	} else if (scmd->sc_data_direction == DMA_FROM_DEVICE) {
		rw->opcode = SPRAID_CMD_READ;
	} else {
		dev_err(hdev->dev, "Invalid IO for unsupported data direction: %d\n",
			scmd->sc_data_direction);
		WARN_ON(1);
	}

	/* 6-byte READ(0x08) or WRITE(0x0A) cdb */
	if (scmd->cmd_len == 6) {
		datalength = (u32)(scmd->cmnd[4] == 0 ?
				IO_6_DEFAULT_TX_LEN : scmd->cmnd[4]);
		start_lba_lo = ((u32)scmd->cmnd[1] << 16) |
				((u32)scmd->cmnd[2] << 8) | (u32)scmd->cmnd[3];

		start_lba_lo &= 0x1FFFFF;
	}

	/* 10-byte READ(0x28) or WRITE(0x2A) cdb */
	else if (scmd->cmd_len == 10) {
		datalength = (u32)scmd->cmnd[8] | ((u32)scmd->cmnd[7] << 8);
		start_lba_lo = ((u32)scmd->cmnd[2] << 24) |
				((u32)scmd->cmnd[3] << 16) |
				((u32)scmd->cmnd[4] << 8) | (u32)scmd->cmnd[5];

		if (scmd->cmnd[1] & FUA_MASK)
			control |= SPRAID_RW_FUA;
	}

	/* 12-byte READ(0xA8) or WRITE(0xAA) cdb */
	else if (scmd->cmd_len == 12) {
		datalength = ((u32)scmd->cmnd[6] << 24) |
				((u32)scmd->cmnd[7] << 16) |
				((u32)scmd->cmnd[8] << 8) | (u32)scmd->cmnd[9];
		start_lba_lo = ((u32)scmd->cmnd[2] << 24) |
				((u32)scmd->cmnd[3] << 16) |
				((u32)scmd->cmnd[4] << 8) | (u32)scmd->cmnd[5];

		if (scmd->cmnd[1] & FUA_MASK)
			control |= SPRAID_RW_FUA;
	}
	/* 16-byte READ(0x88) or WRITE(0x8A) cdb */
	else if (scmd->cmd_len == 16) {
		datalength = ((u32)scmd->cmnd[10] << 24) |
			((u32)scmd->cmnd[11] << 16) |
			((u32)scmd->cmnd[12] << 8) | (u32)scmd->cmnd[13];
		start_lba_lo = ((u32)scmd->cmnd[6] << 24) |
			((u32)scmd->cmnd[7] << 16) |
			((u32)scmd->cmnd[8] << 8) | (u32)scmd->cmnd[9];
		start_lba_hi = ((u32)scmd->cmnd[2] << 24) |
			((u32)scmd->cmnd[3] << 16) |
			((u32)scmd->cmnd[4] << 8) | (u32)scmd->cmnd[5];

		if (scmd->cmnd[1] & FUA_MASK)
			control |= SPRAID_RW_FUA;
	}
	/* 32-byte READ(0x88) or WRITE(0x8A) cdb */
	else if (scmd->cmd_len == 32) {
		datalength = ((u32)scmd->cmnd[28] << 24) |
			((u32)scmd->cmnd[29] << 16) |
			((u32)scmd->cmnd[30] << 8) | (u32)scmd->cmnd[31];
		start_lba_lo = ((u32)scmd->cmnd[16] << 24) |
			((u32)scmd->cmnd[17] << 16) |
			((u32)scmd->cmnd[18] << 8) | (u32)scmd->cmnd[19];
		start_lba_hi = ((u32)scmd->cmnd[12] << 24) |
			((u32)scmd->cmnd[13] << 16) |
			((u32)scmd->cmnd[14] << 8) | (u32)scmd->cmnd[15];

		if (scmd->cmnd[10] & FUA_MASK)
			control |= SPRAID_RW_FUA;
	}

	if (unlikely(datalength > U16_MAX || datalength == 0)) {
		dev_err(hdev->dev, "Invalid IO for illegal transfer data length: %u\n",
			datalength);
		WARN_ON(1);
	}

	rw->slba = cpu_to_le64(((u64)start_lba_hi << 32) | start_lba_lo);
	/* 0base for nlb */
	rw->nlb = cpu_to_le16((u16)(datalength - 1));
	rw->control = cpu_to_le16(control);
}

static void spraid_setup_nonio_cmd(struct spraid_dev *hdev,
				   struct spraid_scsi_nonio *scsi_nonio, struct scsi_cmnd *scmd)
{
	scsi_nonio->buffer_len = cpu_to_le32(scsi_bufflen(scmd));

	switch (scmd->sc_data_direction) {
	case DMA_NONE:
		scsi_nonio->opcode = SPRAID_CMD_NONIO_NONE;
		break;
	case DMA_TO_DEVICE:
		scsi_nonio->opcode = SPRAID_CMD_NONIO_TODEV;
		break;
	case DMA_FROM_DEVICE:
		scsi_nonio->opcode = SPRAID_CMD_NONIO_FROMDEV;
		break;
	default:
		dev_err(hdev->dev, "Invalid IO for unsupported data direction: %d\n",
			scmd->sc_data_direction);
		WARN_ON(1);
	}
}

static void spraid_setup_ioq_cmd(struct spraid_dev *hdev,
				 struct spraid_ioq_command *ioq_cmd, struct scsi_cmnd *scmd)
{
	memcpy(ioq_cmd->common.cdb, scmd->cmnd, scmd->cmd_len);
	ioq_cmd->common.cdb_len = scmd->cmd_len;

	if (spraid_is_rw_scmd(scmd))
		spraid_setup_rw_cmd(hdev, &ioq_cmd->rw, scmd);
	else
		spraid_setup_nonio_cmd(hdev, &ioq_cmd->scsi_nonio, scmd);
}

static int spraid_init_iod(struct spraid_dev *hdev,
			   struct spraid_iod *iod, struct spraid_ioq_command *ioq_cmd,
			   struct scsi_cmnd *scmd)
{
	if (unlikely(!iod->sense)) {
		dev_err(hdev->dev, "Allocate sense data buffer failed\n");
		return -ENOMEM;
	}
	ioq_cmd->common.sense_addr = cpu_to_le64(iod->sense_dma);
	ioq_cmd->common.sense_len = cpu_to_le16(SCSI_SENSE_BUFFERSIZE);

	iod->nsge = 0;
	iod->npages = -1;
	iod->use_sgl = 0;
	iod->sg_drv_mgmt = false;
	WRITE_ONCE(iod->state, SPRAID_CMD_IDLE);

	return 0;
}

static void spraid_free_iod_res(struct spraid_dev *hdev, struct spraid_iod *iod)
{
	const int last_prp = hdev->page_size / sizeof(__le64) - 1;
	dma_addr_t dma_addr, next_dma_addr;
	struct spraid_sgl_desc *sg_list;
	__le64 *prp_list;
	void *addr;
	int i;

	dma_addr = iod->first_dma;
	if (iod->npages == 0)
		dma_pool_free(iod->spraidq->prp_small_pool, spraid_iod_list(iod)[0], dma_addr);

	for (i = 0; i < iod->npages; i++) {
		addr = spraid_iod_list(iod)[i];

		if (iod->use_sgl) {
			sg_list = addr;
			next_dma_addr =
				le64_to_cpu((sg_list[SGES_PER_PAGE - 1]).addr);
		} else {
			prp_list = addr;
			next_dma_addr = le64_to_cpu(prp_list[last_prp]);
		}

		dma_pool_free(hdev->prp_page_pool, addr, dma_addr);
		dma_addr = next_dma_addr;
	}

	if (iod->sg_drv_mgmt && iod->sg != iod->inline_sg) {
		iod->sg_drv_mgmt = false;
		mempool_free(iod->sg, hdev->iod_mempool);
	}

	iod->sense = NULL;
	iod->npages = -1;
}

static int spraid_io_map_data(struct spraid_dev *hdev, struct spraid_iod *iod,
			      struct scsi_cmnd *scmd, struct spraid_ioq_command *ioq_cmd)
{
	int ret;

	iod->nsge = scsi_dma_map(scmd);

	/* No data to DMA, it may be scsi no-rw command */
	if (unlikely(iod->nsge == 0))
		return 0;

	iod->length = scsi_bufflen(scmd);
	iod->sg = scsi_sglist(scmd);
	iod->use_sgl = !spraid_is_prp(hdev, scmd, iod->nsge);

	if (iod->use_sgl) {
		ret = spraid_setup_ioq_cmd_sgl(hdev, scmd, ioq_cmd, iod);
	} else {
		ret = spraid_setup_prps(hdev, iod);
		ioq_cmd->common.dptr.prp1 =
				cpu_to_le64(sg_dma_address(iod->sg));
		ioq_cmd->common.dptr.prp2 = cpu_to_le64(iod->first_dma);
	}

	if (ret)
		scsi_dma_unmap(scmd);

	return ret;
}

static void spraid_map_status(struct spraid_iod *iod, struct scsi_cmnd *scmd,
			      struct spraid_completion *cqe)
{
	scsi_set_resid(scmd, 0);

	switch ((le16_to_cpu(cqe->status) >> 1) & 0x7f) {
	case FW_STAT_OK:
		set_host_byte(scmd, DID_OK);
		break;
	case FW_STAT_NEED_CHECK:
		set_host_byte(scmd, DID_OK);
		scmd->result |= le16_to_cpu(cqe->status) >> 8;
		if (scmd->result & SAM_STAT_CHECK_CONDITION) {
			memset(scmd->sense_buffer, 0, SCSI_SENSE_BUFFERSIZE);
			memcpy(scmd->sense_buffer, iod->sense, SCSI_SENSE_BUFFERSIZE);
			set_driver_byte(scmd, DRIVER_SENSE);
		}
		break;
	case FW_STAT_ABORTED:
		set_host_byte(scmd, DID_ABORT);
		break;
	case FW_STAT_NEED_RETRY:
		set_host_byte(scmd, DID_REQUEUE);
		break;
	default:
		set_host_byte(scmd, DID_BAD_TARGET);
		break;
	}
}

static inline void spraid_get_tag_from_scmd(struct scsi_cmnd *scmd, u16 *qid, u16 *cid)
{
	u32 tag = blk_mq_unique_tag(scmd->request);

	*qid = blk_mq_unique_tag_to_hwq(tag) + 1;
	*cid = blk_mq_unique_tag_to_tag(tag);
}

static int spraid_queue_command(struct Scsi_Host *shost, struct scsi_cmnd *scmd)
{
	struct spraid_iod *iod = scsi_cmd_priv(scmd);
	struct spraid_dev *hdev = shost_priv(shost);
	struct scsi_device *sdev = scmd->device;
	struct spraid_sdev_hostdata *hostdata;
	struct spraid_ioq_command ioq_cmd;
	struct spraid_queue *ioq;
	unsigned long elapsed;
	u16 hwq, cid;
	int ret;

	if (unlikely(!scmd)) {
		dev_err(hdev->dev, "err, scmd is null, return 0\n");
		return 0;
	}

	if (unlikely(hdev->state != SPRAID_LIVE)) {
		set_host_byte(scmd, DID_NO_CONNECT);
		scmd->scsi_done(scmd);
		dev_err(hdev->dev, "[%s] err, hdev state is not live\n", __func__);
		return 0;
	}

	if (log_debug_switch)
		scsi_print_command(scmd);

	spraid_get_tag_from_scmd(scmd, &hwq, &cid);
	hostdata = sdev->hostdata;
	ioq = &hdev->queues[hwq];
	memset(&ioq_cmd, 0, sizeof(ioq_cmd));
	ioq_cmd.rw.hdid = cpu_to_le32(hostdata->hdid);
	ioq_cmd.rw.command_id = cid;

	spraid_setup_ioq_cmd(hdev, &ioq_cmd, scmd);

	ret = cid * SCSI_SENSE_BUFFERSIZE;
	iod->sense = ioq->sense + ret;
	iod->sense_dma = ioq->sense_dma_addr + ret;

	ret = spraid_init_iod(hdev, iod, &ioq_cmd, scmd);
	if (unlikely(ret))
		return SCSI_MLQUEUE_HOST_BUSY;

	iod->spraidq = ioq;
	ret = spraid_io_map_data(hdev, iod, scmd, &ioq_cmd);
	if (unlikely(ret)) {
		dev_err(hdev->dev, "spraid_io_map_data Err.\n");
		set_host_byte(scmd, DID_ERROR);
		scmd->scsi_done(scmd);
		ret = 0;
		goto deinit_iod;
	}

	WRITE_ONCE(iod->state, SPRAID_CMD_IN_FLIGHT);
	spraid_submit_cmd(ioq, &ioq_cmd);
	elapsed = jiffies - scmd->jiffies_at_alloc;
	dev_log_dbg(hdev->dev, "cid[%d], qid[%d] submit IO cost %3ld.%3ld seconds\n",
		    cid, hwq, elapsed / HZ, elapsed % HZ);
	return 0;

deinit_iod:
	spraid_free_iod_res(hdev, iod);
	return ret;
}

static int spraid_match_dev(struct spraid_dev *hdev, u16 idx, struct scsi_device *sdev)
{
	if (SPRAID_DEV_INFO_FLAG_VALID(hdev->devices[idx].flag)) {
		if (sdev->channel == hdev->devices[idx].channel &&
		    sdev->id == le16_to_cpu(hdev->devices[idx].target) &&
		    sdev->lun < hdev->devices[idx].lun) {
			dev_info(hdev->dev, "Match device success, channel:target:lun[%d:%d:%d]\n",
				 hdev->devices[idx].channel,
				 hdev->devices[idx].target,
				 hdev->devices[idx].lun);
			return 1;
		}
	}

	return 0;
}

static int spraid_slave_alloc(struct scsi_device *sdev)
{
	struct spraid_sdev_hostdata *hostdata;
	struct spraid_dev *hdev;
	u16 idx;

	hdev = shost_priv(sdev->host);
	hostdata = kzalloc(sizeof(*hostdata), GFP_KERNEL);
	if (!hostdata) {
		dev_err(hdev->dev, "Alloc scsi host data memory failed\n");
		return -ENOMEM;
	}

	down_read(&hdev->devices_rwsem);
	for (idx = 0; idx < le32_to_cpu(hdev->ctrl_info->nd); idx++) {
		if (spraid_match_dev(hdev, idx, sdev))
			goto scan_host;
	}
	up_read(&hdev->devices_rwsem);

	kfree(hostdata);
	return -ENXIO;

scan_host:
	hostdata->hdid = le32_to_cpu(hdev->devices[idx].hdid);
	sdev->hostdata = hostdata;
	up_read(&hdev->devices_rwsem);
	return 0;
}

static void spraid_slave_destroy(struct scsi_device *sdev)
{
	kfree(sdev->hostdata);
	sdev->hostdata = NULL;
}

static int spraid_slave_configure(struct scsi_device *sdev)
{
	u16 idx;
	unsigned int timeout = scmd_tmout_nonpt * HZ;
	struct spraid_dev *hdev = shost_priv(sdev->host);
	struct spraid_sdev_hostdata *hostdata = sdev->hostdata;
	u32 max_sec = sdev->host->max_sectors;

	if (!hostdata) {
		idx = hostdata->hdid - 1;
		if (sdev->channel == hdev->devices[idx].channel &&
		    sdev->id == le16_to_cpu(hdev->devices[idx].target) &&
		    sdev->lun < hdev->devices[idx].lun) {
			if (SPRAID_DEV_INFO_ATTR_PT(hdev->devices[idx].attr))
				timeout = scmd_tmout_pt * HZ;
			else
				timeout = scmd_tmout_nonpt * HZ;
			max_sec = le16_to_cpu(hdev->devices[idx].max_io_kb) << 1;
		} else {
			dev_err(hdev->dev, "[%s] err, sdev->channel:id:lun[%d:%d:%lld];"
				"devices[%d], channel:target:lun[%d:%d:%d]\n",
				__func__, sdev->channel, sdev->id, sdev->lun,
				idx, hdev->devices[idx].channel,
				hdev->devices[idx].target,
				hdev->devices[idx].lun);
		}
	} else {
		dev_err(hdev->dev, "[%s] err, sdev->hostdata is null\n", __func__);
	}

	blk_queue_rq_timeout(sdev->request_queue, timeout);
	sdev->eh_timeout = timeout;

	if ((max_sec == 0) || (max_sec > sdev->host->max_sectors))
		max_sec = sdev->host->max_sectors;
	blk_queue_max_hw_sectors(sdev->request_queue, max_sec);

	dev_info(hdev->dev, "[%s] sdev->channel:id:lun[%d:%d:%lld], scmd_timeout[%d]s, maxsec[%d]\n",
		 __func__, sdev->channel, sdev->id, sdev->lun, timeout / HZ, max_sec);

	return 0;
}

static void spraid_shost_init(struct spraid_dev *hdev)
{
	struct pci_dev *pdev = hdev->pdev;
	u8 domain, bus;
	u32 dev_func;

	domain = pci_domain_nr(pdev->bus);
	bus = pdev->bus->number;
	dev_func = pdev->devfn;

	hdev->shost->nr_hw_queues = hdev->online_queues - 1;
	hdev->shost->can_queue = (hdev->ioq_depth - SPRAID_PTCMDS_PERQ);

	hdev->shost->sg_tablesize = le16_to_cpu(hdev->ctrl_info->max_num_sge);
	/* 512B per sector */
	hdev->shost->max_sectors = (1U << ((hdev->ctrl_info->mdts) * 1U) << 12) / 512;
	hdev->shost->cmd_per_lun = MAX_CMD_PER_DEV;
	hdev->shost->max_channel = le16_to_cpu(hdev->ctrl_info->max_channel) - 1;
	hdev->shost->max_id = le32_to_cpu(hdev->ctrl_info->max_tgt_id);
	hdev->shost->max_lun = le16_to_cpu(hdev->ctrl_info->max_lun);

	hdev->shost->this_id = -1;
	hdev->shost->unique_id = (domain << 16) | (bus << 8) | dev_func;
	hdev->shost->max_cmd_len = MAX_CDB_LEN;
	hdev->shost->hostt->cmd_size = max(spraid_cmd_size(hdev, false, true),
					   spraid_cmd_size(hdev, false, false));
}

static inline void spraid_host_deinit(struct spraid_dev *hdev)
{
	ida_free(&spraid_instance_ida, hdev->instance);
}

static int spraid_alloc_queue(struct spraid_dev *hdev, u16 qid, u16 depth)
{
	struct spraid_queue *spraidq = &hdev->queues[qid];
	int ret = 0;

	if (hdev->queue_count > qid) {
		dev_info(hdev->dev, "[%s] warn: queue[%d] is exist\n", __func__, qid);
		return 0;
	}

	spraidq->cqes = dma_alloc_coherent(hdev->dev, CQ_SIZE(depth),
					   &spraidq->cq_dma_addr, GFP_KERNEL | __GFP_ZERO);
	if (!spraidq->cqes)
		return -ENOMEM;

	spraidq->sq_cmds = dma_alloc_coherent(hdev->dev, SQ_SIZE(qid, depth),
					      &spraidq->sq_dma_addr, GFP_KERNEL);
	if (!spraidq->sq_cmds) {
		ret = -ENOMEM;
		goto  free_cqes;
	}

	spin_lock_init(&spraidq->sq_lock);
	spin_lock_init(&spraidq->cq_lock);
	spraidq->hdev = hdev;
	spraidq->q_depth = depth;
	spraidq->qid = qid;
	spraidq->cq_vector = -1;
	hdev->queue_count++;

	/* alloc sense buffer */
	spraidq->sense = dma_alloc_coherent(hdev->dev, SENSE_SIZE(depth),
					    &spraidq->sense_dma_addr, GFP_KERNEL | __GFP_ZERO);
	if (!spraidq->sense) {
		ret = -ENOMEM;
		goto free_sq_cmds;
	}

	return 0;

free_sq_cmds:
	dma_free_coherent(hdev->dev, SQ_SIZE(qid, depth), (void *)spraidq->sq_cmds,
			  spraidq->sq_dma_addr);
free_cqes:
	dma_free_coherent(hdev->dev, CQ_SIZE(depth), (void *)spraidq->cqes,
			  spraidq->cq_dma_addr);
	return ret;
}

static int spraid_wait_ready(struct spraid_dev *hdev, u64 cap, bool enabled)
{
	unsigned long timeout =
	((SPRAID_CAP_TIMEOUT(cap) + 1) * SPRAID_CAP_TIMEOUT_UNIT_MS) + jiffies;
	u32 bit = enabled ? SPRAID_CSTS_RDY : 0;

	while ((readl(hdev->bar + SPRAID_REG_CSTS) & SPRAID_CSTS_RDY) != bit) {
		usleep_range(1000, 2000);
		if (fatal_signal_pending(current))
			return -EINTR;

		if (time_after(jiffies, timeout)) {
			dev_err(hdev->dev, "Device not ready; aborting %s\n",
				enabled ? "initialisation" : "reset");
			return -ENODEV;
		}
	}
	return 0;
}

static int spraid_shutdown_ctrl(struct spraid_dev *hdev)
{
	unsigned long timeout = hdev->ctrl_info->rtd3e + jiffies;

	hdev->ctrl_config &= ~SPRAID_CC_SHN_MASK;
	hdev->ctrl_config |= SPRAID_CC_SHN_NORMAL;
	writel(hdev->ctrl_config, hdev->bar + SPRAID_REG_CC);

	while ((readl(hdev->bar + SPRAID_REG_CSTS) & SPRAID_CSTS_SHST_MASK) !=
		SPRAID_CSTS_SHST_CMPLT) {
		msleep(100);
		if (fatal_signal_pending(current))
			return -EINTR;
		if (time_after(jiffies, timeout)) {
			dev_err(hdev->dev, "Device shutdown incomplete; abort shutdown\n");
			return -ENODEV;
		}
	}
	return 0;
}

static int spraid_disable_ctrl(struct spraid_dev *hdev)
{
	hdev->ctrl_config &= ~SPRAID_CC_SHN_MASK;
	hdev->ctrl_config &= ~SPRAID_CC_ENABLE;
	writel(hdev->ctrl_config, hdev->bar + SPRAID_REG_CC);

	return spraid_wait_ready(hdev, hdev->cap, false);
}

static int spraid_enable_ctrl(struct spraid_dev *hdev)
{
	u64 cap = hdev->cap;
	u32 dev_page_min = SPRAID_CAP_MPSMIN(cap) + 12;
	u32 page_shift = PAGE_SHIFT;

	if (page_shift < dev_page_min) {
		dev_err(hdev->dev, "Minimum device page size[%u], too large for host[%u]\n",
			1U << dev_page_min, 1U << page_shift);
		return -ENODEV;
	}

	page_shift = min_t(unsigned int, SPRAID_CAP_MPSMAX(cap) + 12, PAGE_SHIFT);
	hdev->page_size = 1U << page_shift;

	hdev->ctrl_config = SPRAID_CC_CSS_NVM;
	hdev->ctrl_config |= (page_shift - 12) << SPRAID_CC_MPS_SHIFT;
	hdev->ctrl_config |= SPRAID_CC_AMS_RR | SPRAID_CC_SHN_NONE;
	hdev->ctrl_config |= SPRAID_CC_IOSQES | SPRAID_CC_IOCQES;
	hdev->ctrl_config |= SPRAID_CC_ENABLE;
	writel(hdev->ctrl_config, hdev->bar + SPRAID_REG_CC);

	return spraid_wait_ready(hdev, cap, true);
}

static void spraid_init_queue(struct spraid_queue *spraidq, u16 qid)
{
	struct spraid_dev *hdev = spraidq->hdev;

	memset((void *)spraidq->cqes, 0, CQ_SIZE(spraidq->q_depth));

	spraidq->sq_tail = 0;
	spraidq->cq_head = 0;
	spraidq->cq_phase = 1;
	spraidq->q_db = &hdev->dbs[qid * 2 * hdev->db_stride];
	spraidq->prp_small_pool = hdev->prp_small_pool[qid % small_pool_num];
	hdev->online_queues++;
}

static inline bool spraid_cqe_pending(struct spraid_queue *spraidq)
{
	return (le16_to_cpu(spraidq->cqes[spraidq->cq_head].status) & 1) ==
		spraidq->cq_phase;
}

static void spraid_complete_ioq_cmnd(struct spraid_queue *ioq, struct spraid_completion *cqe)
{
	struct spraid_dev *hdev = ioq->hdev;
	struct blk_mq_tags *tags;
	struct scsi_cmnd *scmd;
	struct spraid_iod *iod;
	struct request *req;
	unsigned long elapsed;

	tags = hdev->shost->tag_set.tags[ioq->qid - 1];
	req = blk_mq_tag_to_rq(tags, cqe->cmd_id);
	if (unlikely(!req || !blk_mq_request_started(req))) {
		dev_warn(hdev->dev, "Invalid id %d completed on queue %d\n",
			 cqe->cmd_id, ioq->qid);
		return;
	}

	scmd = blk_mq_rq_to_pdu(req);
	iod = scsi_cmd_priv(scmd);

	elapsed = jiffies - scmd->jiffies_at_alloc;
	dev_log_dbg(hdev->dev, "cid[%d], qid[%d] finish IO cost %3ld.%3ld seconds\n",
		    cqe->cmd_id, ioq->qid, elapsed / HZ, elapsed % HZ);

	if (cmpxchg(&iod->state, SPRAID_CMD_IN_FLIGHT, SPRAID_CMD_COMPLETE) !=
		SPRAID_CMD_IN_FLIGHT) {
		dev_warn(hdev->dev, "cid[%d], qid[%d] enters abnormal handler, cost %3ld.%3ld seconds\n",
			 cqe->cmd_id, ioq->qid, elapsed / HZ, elapsed % HZ);
		WRITE_ONCE(iod->state, SPRAID_CMD_TMO_COMPLETE);

		if (iod->nsge) {
			iod->nsge = 0;
			scsi_dma_unmap(scmd);
		}
		spraid_free_iod_res(hdev, iod);

		return;
	}

	spraid_map_status(iod, scmd, cqe);
	if (iod->nsge) {
		iod->nsge = 0;
		scsi_dma_unmap(scmd);
	}
	spraid_free_iod_res(hdev, iod);
	scmd->scsi_done(scmd);
}

static inline void spraid_end_admin_request(struct request *req, __le16 status,
					    __le32 result0, __le32 result1)
{
	struct spraid_admin_request *rq = spraid_admin_req(req);

	rq->status = le16_to_cpu(status) >> 1;
	rq->result0 = le32_to_cpu(result0);
	rq->result1 = le32_to_cpu(result1);
	blk_mq_complete_request(req);
}

static void spraid_complete_adminq_cmnd(struct spraid_queue *adminq, struct spraid_completion *cqe)
{
	struct blk_mq_tags *tags = adminq->hdev->admin_tagset.tags[0];
	struct request *req;

	req = blk_mq_tag_to_rq(tags, cqe->cmd_id);
	if (unlikely(!req)) {
		dev_warn(adminq->hdev->dev, "Invalid id %d completed on queue %d\n",
			 cqe->cmd_id, le16_to_cpu(cqe->sq_id));
		return;
	}
	spraid_end_admin_request(req, cqe->status, cqe->result, cqe->result1);
}

static void spraid_complete_aen(struct spraid_queue *spraidq, struct spraid_completion *cqe)
{
	struct spraid_dev *hdev = spraidq->hdev;
	u32 result = le32_to_cpu(cqe->result);

	dev_info(hdev->dev, "rcv aen, status[%x], result[%x]\n",
		 le16_to_cpu(cqe->status) >> 1, result);

	if ((le16_to_cpu(cqe->status) >> 1) != SPRAID_SC_SUCCESS)
		return;
	switch (result & 0x7) {
	case SPRAID_AEN_NOTICE:
		spraid_handle_aen_notice(hdev, result);
		break;
	case SPRAID_AEN_VS:
		spraid_handle_aen_vs(hdev, result);
		break;
	default:
		dev_warn(hdev->dev, "Unsupported async event type: %u\n",
			 result & 0x7);
		break;
	}
	queue_work(spraid_wq, &hdev->aen_work);
}

static void spraid_put_ioq_ptcmd(struct spraid_dev *hdev, struct spraid_ioq_ptcmd *cmd);

static void spraid_complete_ioq_sync_cmnd(struct spraid_queue *ioq, struct spraid_completion *cqe)
{
	struct spraid_dev *hdev = ioq->hdev;
	struct spraid_ioq_ptcmd *ptcmd;

	ptcmd = hdev->ioq_ptcmds + (ioq->qid - 1) * SPRAID_PTCMDS_PERQ +
		cqe->cmd_id - SPRAID_IO_BLK_MQ_DEPTH;

	ptcmd->status = le16_to_cpu(cqe->status) >> 1;
	ptcmd->result0 = le32_to_cpu(cqe->result);
	ptcmd->result1 = le32_to_cpu(cqe->result1);

	complete(&ptcmd->cmd_done);

	spraid_put_ioq_ptcmd(hdev, ptcmd);
}

static inline void spraid_handle_cqe(struct spraid_queue *spraidq, u16 idx)
{
	struct spraid_completion *cqe = &spraidq->cqes[idx];
	struct spraid_dev *hdev = spraidq->hdev;

	if (unlikely(cqe->cmd_id >= spraidq->q_depth)) {
		dev_err(hdev->dev, "Invalid command id[%d] completed on queue %d\n",
			cqe->cmd_id, cqe->sq_id);
		return;
	}

	dev_log_dbg(hdev->dev, "cid[%d], qid[%d], result[0x%x], sq_id[%d], status[0x%x]\n",
		    cqe->cmd_id, spraidq->qid, le32_to_cpu(cqe->result),
		    le16_to_cpu(cqe->sq_id), le16_to_cpu(cqe->status));

	if (unlikely(spraidq->qid == 0 && cqe->cmd_id >= SPRAID_AQ_BLK_MQ_DEPTH)) {
		spraid_complete_aen(spraidq, cqe);
		return;
	}

	if (unlikely(spraidq->qid && cqe->cmd_id >= SPRAID_IO_BLK_MQ_DEPTH)) {
		spraid_complete_ioq_sync_cmnd(spraidq, cqe);
		return;
	}

	if (spraidq->qid)
		spraid_complete_ioq_cmnd(spraidq, cqe);
	else
		spraid_complete_adminq_cmnd(spraidq, cqe);
}

static void spraid_complete_cqes(struct spraid_queue *spraidq, u16 start, u16 end)
{
	while (start != end) {
		spraid_handle_cqe(spraidq, start);
		if (++start == spraidq->q_depth)
			start = 0;
	}
}

static inline void spraid_update_cq_head(struct spraid_queue *spraidq)
{
	if (++spraidq->cq_head == spraidq->q_depth) {
		spraidq->cq_head = 0;
		spraidq->cq_phase = !spraidq->cq_phase;
	}
}

static inline bool spraid_process_cq(struct spraid_queue *spraidq, u16 *start, u16 *end, int tag)
{
	bool found = false;

	*start = spraidq->cq_head;
	while (!found && spraid_cqe_pending(spraidq)) {
		if (spraidq->cqes[spraidq->cq_head].cmd_id == tag)
			found = true;
		spraid_update_cq_head(spraidq);
	}
	*end = spraidq->cq_head;

	if (*start != *end)
		writel(spraidq->cq_head, spraidq->q_db + spraidq->hdev->db_stride);

	return found;
}

static bool spraid_poll_cq(struct spraid_queue *spraidq, int cid)
{
	u16 start, end;
	bool found;

	if (!spraid_cqe_pending(spraidq))
		return 0;

	spin_lock_irq(&spraidq->cq_lock);
	found = spraid_process_cq(spraidq, &start, &end, cid);
	spin_unlock_irq(&spraidq->cq_lock);

	spraid_complete_cqes(spraidq, start, end);
	return found;
}

static irqreturn_t spraid_irq(int irq, void *data)
{
	struct spraid_queue *spraidq = data;
	irqreturn_t ret = IRQ_NONE;
	u16 start, end;

	spin_lock(&spraidq->cq_lock);
	if (spraidq->cq_head != spraidq->last_cq_head)
		ret = IRQ_HANDLED;

	spraid_process_cq(spraidq, &start, &end, -1);
	spraidq->last_cq_head = spraidq->cq_head;
	spin_unlock(&spraidq->cq_lock);

	if (start != end) {
		spraid_complete_cqes(spraidq, start, end);
		ret = IRQ_HANDLED;
	}
	return ret;
}

static int spraid_setup_admin_queue(struct spraid_dev *hdev)
{
	struct spraid_queue *adminq = &hdev->queues[0];
	u32 aqa;
	int ret;

	dev_info(hdev->dev, "[%s] start disable ctrl\n", __func__);

	ret = spraid_disable_ctrl(hdev);
	if (ret)
		return ret;

	ret = spraid_alloc_queue(hdev, 0, SPRAID_AQ_DEPTH);
	if (ret)
		return ret;

	aqa = adminq->q_depth - 1;
	aqa |= aqa << 16;
	writel(aqa, hdev->bar + SPRAID_REG_AQA);
	lo_hi_writeq(adminq->sq_dma_addr, hdev->bar + SPRAID_REG_ASQ);
	lo_hi_writeq(adminq->cq_dma_addr, hdev->bar + SPRAID_REG_ACQ);

	dev_info(hdev->dev, "[%s] start enable ctrl\n", __func__);

	ret = spraid_enable_ctrl(hdev);
	if (ret) {
		ret = -ENODEV;
		goto free_queue;
	}

	adminq->cq_vector = 0;
	spraid_init_queue(adminq, 0);
	ret = pci_request_irq(hdev->pdev, adminq->cq_vector, spraid_irq, NULL,
			      adminq, "spraid%d_q%d", hdev->instance, adminq->qid);

	if (ret) {
		adminq->cq_vector = -1;
		hdev->online_queues--;
		goto free_queue;
	}

	dev_info(hdev->dev, "[%s] success, queuecount:[%d], onlinequeue:[%d]\n",
		 __func__, hdev->queue_count, hdev->online_queues);

	return 0;

free_queue:
	spraid_free_queue(adminq);
	return ret;
}

static u32 spraid_bar_size(struct spraid_dev *hdev, u32 nr_ioqs)
{
	return (SPRAID_REG_DBS + ((nr_ioqs + 1) * 8 * hdev->db_stride));
}

static inline void spraid_clear_spraid_request(struct request *req)
{
	if (!(req->rq_flags & RQF_DONTPREP)) {
		spraid_admin_req(req)->flags = 0;
		req->rq_flags |= RQF_DONTPREP;
	}
}

static struct request *spraid_alloc_admin_request(struct request_queue *q,
						  struct spraid_admin_command *cmd,
						  blk_mq_req_flags_t flags)
{
	u32 op = COMMAND_IS_WRITE(cmd) ? REQ_OP_DRV_OUT : REQ_OP_DRV_IN;
	struct request *req;

	req = blk_mq_alloc_request(q, op, flags);
	if (IS_ERR(req))
		return req;
	req->cmd_flags |= REQ_FAILFAST_DRIVER;
	spraid_clear_spraid_request(req);
	spraid_admin_req(req)->cmd = cmd;

	return req;
}

static int spraid_submit_admin_sync_cmd(struct request_queue *q,
					struct spraid_admin_command *cmd,
					u32 *result, void *buffer,
	u32 bufflen, u32 timeout, int at_head, blk_mq_req_flags_t flags)
{
	struct request *req;
	int ret;

	req = spraid_alloc_admin_request(q, cmd, flags);
	if (IS_ERR(req))
		return PTR_ERR(req);

	req->timeout = timeout ? timeout : ADMIN_TIMEOUT;
	if (buffer && bufflen) {
		ret = blk_rq_map_kern(q, req, buffer, bufflen, GFP_KERNEL);
		if (ret)
			goto out;
	}
	blk_execute_rq(req->q, NULL, req, at_head);

	if (result)
		*result = spraid_admin_req(req)->result0;

	if (spraid_admin_req(req)->flags & SPRAID_REQ_CANCELLED)
		ret = -EINTR;
	else
		ret = spraid_admin_req(req)->status;

out:
	blk_mq_free_request(req);
	return ret;
}

static int spraid_create_cq(struct spraid_dev *hdev, u16 qid,
			    struct spraid_queue *spraidq, u16 cq_vector)
{
	struct spraid_admin_command admin_cmd;
	int flags = SPRAID_QUEUE_PHYS_CONTIG | SPRAID_CQ_IRQ_ENABLED;

	memset(&admin_cmd, 0, sizeof(admin_cmd));
	admin_cmd.create_cq.opcode = SPRAID_ADMIN_CREATE_CQ;
	admin_cmd.create_cq.prp1 = cpu_to_le64(spraidq->cq_dma_addr);
	admin_cmd.create_cq.cqid = cpu_to_le16(qid);
	admin_cmd.create_cq.qsize = cpu_to_le16(spraidq->q_depth - 1);
	admin_cmd.create_cq.cq_flags = cpu_to_le16(flags);
	admin_cmd.create_cq.irq_vector = cpu_to_le16(cq_vector);

	return spraid_submit_admin_sync_cmd(hdev->admin_q, &admin_cmd, NULL,
		NULL, 0, 0, 0, 0);
}

static int spraid_create_sq(struct spraid_dev *hdev, u16 qid,
			    struct spraid_queue *spraidq)
{
	struct spraid_admin_command admin_cmd;
	int flags = SPRAID_QUEUE_PHYS_CONTIG;

	memset(&admin_cmd, 0, sizeof(admin_cmd));
	admin_cmd.create_sq.opcode = SPRAID_ADMIN_CREATE_SQ;
	admin_cmd.create_sq.prp1 = cpu_to_le64(spraidq->sq_dma_addr);
	admin_cmd.create_sq.sqid = cpu_to_le16(qid);
	admin_cmd.create_sq.qsize = cpu_to_le16(spraidq->q_depth - 1);
	admin_cmd.create_sq.sq_flags = cpu_to_le16(flags);
	admin_cmd.create_sq.cqid = cpu_to_le16(qid);

	return spraid_submit_admin_sync_cmd(hdev->admin_q, &admin_cmd, NULL,
		NULL, 0, 0, 0, 0);
}

static void spraid_free_queue(struct spraid_queue *spraidq)
{
	struct spraid_dev *hdev = spraidq->hdev;

	hdev->queue_count--;
	dma_free_coherent(hdev->dev, CQ_SIZE(spraidq->q_depth),
			  (void *)spraidq->cqes, spraidq->cq_dma_addr);
	dma_free_coherent(hdev->dev, SQ_SIZE(spraidq->qid, spraidq->q_depth),
			  spraidq->sq_cmds, spraidq->sq_dma_addr);
	dma_free_coherent(hdev->dev, SENSE_SIZE(spraidq->q_depth),
			  spraidq->sense, spraidq->sense_dma_addr);
}

static void spraid_free_admin_queue(struct spraid_dev *hdev)
{
	spraid_free_queue(&hdev->queues[0]);
}

static void spraid_free_io_queues(struct spraid_dev *hdev)
{
	int i;

	for (i = hdev->queue_count - 1; i >= 1; i--)
		spraid_free_queue(&hdev->queues[i]);
}

static int spraid_delete_queue(struct spraid_dev *hdev, u8 op, u16 id)
{
	struct spraid_admin_command admin_cmd;
	int ret;

	memset(&admin_cmd, 0, sizeof(admin_cmd));
	admin_cmd.delete_queue.opcode = op;
	admin_cmd.delete_queue.qid = cpu_to_le16(id);

	ret = spraid_submit_admin_sync_cmd(hdev->admin_q, &admin_cmd, NULL,
					   NULL, 0, 0, 0, 0);

	if (ret)
		dev_err(hdev->dev, "Delete %s:[%d] failed\n",
			(op == SPRAID_ADMIN_DELETE_CQ) ? "cq" : "sq", id);

	return ret;
}

static int spraid_delete_cq(struct spraid_dev *hdev, u16 cqid)
{
	return spraid_delete_queue(hdev, SPRAID_ADMIN_DELETE_CQ, cqid);
}

static int spraid_delete_sq(struct spraid_dev *hdev, u16 sqid)
{
	return spraid_delete_queue(hdev, SPRAID_ADMIN_DELETE_SQ, sqid);
}

static int spraid_create_queue(struct spraid_queue *spraidq, u16 qid)
{
	struct spraid_dev *hdev = spraidq->hdev;
	u16 cq_vector;
	int ret;

	cq_vector = (hdev->num_vecs == 1) ? 0 : qid;
	ret = spraid_create_cq(hdev, qid, spraidq, cq_vector);
	if (ret)
		return ret;

	ret = spraid_create_sq(hdev, qid, spraidq);
	if (ret)
		goto delete_cq;

	spraid_init_queue(spraidq, qid);
	spraidq->cq_vector = cq_vector;

	ret = pci_request_irq(hdev->pdev, cq_vector, spraid_irq, NULL,
			      spraidq, "spraid%d_q%d", hdev->instance, qid);

	if (ret) {
		dev_err(hdev->dev, "Request queue[%d] irq failed\n", qid);
		goto delete_sq;
	}

	return 0;

delete_sq:
	spraidq->cq_vector = -1;
	hdev->online_queues--;
	spraid_delete_sq(hdev, qid);
delete_cq:
	spraid_delete_cq(hdev, qid);

	return ret;
}

static int spraid_create_io_queues(struct spraid_dev *hdev)
{
	u32 i, max;
	int ret = 0;

	max = min(hdev->max_qid, hdev->queue_count - 1);
	for (i = hdev->online_queues; i <= max; i++) {
		ret = spraid_create_queue(&hdev->queues[i], i);
		if (ret) {
			dev_err(hdev->dev, "Create queue[%d] failed\n", i);
			break;
		}
	}

	dev_info(hdev->dev, "[%s] queue_count[%d], online_queue[%d]",
		 __func__, hdev->queue_count, hdev->online_queues);

	return ret >= 0 ? 0 : ret;
}

static int spraid_set_features(struct spraid_dev *hdev, u32 fid, u32 dword11, void *buffer,
			       size_t buflen, u32 *result)
{
	struct spraid_admin_command admin_cmd;
	u32 res;
	int ret;

	memset(&admin_cmd, 0, sizeof(admin_cmd));
	admin_cmd.features.opcode = SPRAID_ADMIN_SET_FEATURES;
	admin_cmd.features.fid = cpu_to_le32(fid);
	admin_cmd.features.dword11 = cpu_to_le32(dword11);

	ret = spraid_submit_admin_sync_cmd(hdev->admin_q, &admin_cmd, &res,
					   buffer, buflen, 0, 0, 0);

	if (!ret && result)
		*result = res;

	return ret;
}

static int spraid_configure_timestamp(struct spraid_dev *hdev)
{
	__le64 ts;
	int ret;

	ts = cpu_to_le64(ktime_to_ms(ktime_get_real()));
	ret = spraid_set_features(hdev, SPRAID_FEAT_TIMESTAMP, 0, &ts, sizeof(ts), NULL);

	if (ret)
		dev_err(hdev->dev, "set timestamp failed: %d\n", ret);
	return ret;
}

static int spraid_set_queue_cnt(struct spraid_dev *hdev, u32 *cnt)
{
	u32 q_cnt = (*cnt - 1) | ((*cnt - 1) << 16);
	u32 nr_ioqs, result;
	int status;

	status = spraid_set_features(hdev, SPRAID_FEAT_NUM_QUEUES, q_cnt, NULL, 0, &result);
	if (status) {
		dev_err(hdev->dev, "Set queue count failed, status: %d\n",
			status);
		return -EIO;
	}

	nr_ioqs = min(result & 0xffff, result >> 16) + 1;
	*cnt = min(*cnt, nr_ioqs);
	if (*cnt == 0) {
		dev_err(hdev->dev, "Illegal queue count: zero\n");
		return -EIO;
	}
	return 0;
}

static int spraid_setup_io_queues(struct spraid_dev *hdev)
{
	struct spraid_queue *adminq = &hdev->queues[0];
	struct pci_dev *pdev = hdev->pdev;
	u32 nr_ioqs = num_online_cpus();
	u32 i, size;
	int ret;

	struct irq_affinity affd = {
		.pre_vectors = 1
	};

	ret = spraid_set_queue_cnt(hdev, &nr_ioqs);
	if (ret < 0)
		return ret;

	size = spraid_bar_size(hdev, nr_ioqs);
	ret = spraid_remap_bar(hdev, size);
	if (ret)
		return -ENOMEM;

	adminq->q_db = hdev->dbs;

	pci_free_irq(pdev, 0, adminq);
	pci_free_irq_vectors(pdev);

	ret = pci_alloc_irq_vectors_affinity(pdev, 1, (nr_ioqs + 1),
					     PCI_IRQ_ALL_TYPES | PCI_IRQ_AFFINITY, &affd);
	if (ret <= 0)
		return -EIO;

	hdev->num_vecs = ret;

	hdev->max_qid = max(ret - 1, 1);

	ret = pci_request_irq(pdev, adminq->cq_vector, spraid_irq, NULL,
			      adminq, "spraid%d_q%d", hdev->instance, adminq->qid);
	if (ret) {
		dev_err(hdev->dev, "Request admin irq failed\n");
		adminq->cq_vector = -1;
		return ret;
	}

	for (i = hdev->queue_count; i <= hdev->max_qid; i++) {
		ret = spraid_alloc_queue(hdev, i, hdev->ioq_depth);
		if (ret)
			break;
	}
	dev_info(hdev->dev, "[%s] max_qid: %d, queue_count: %d, online_queue: %d, ioq_depth: %d\n",
		 __func__, hdev->max_qid, hdev->queue_count,
	hdev->online_queues, hdev->ioq_depth);

	return spraid_create_io_queues(hdev);
}

static void spraid_delete_io_queues(struct spraid_dev *hdev)
{
	u16 queues = hdev->online_queues - 1;
	u8 opcode = SPRAID_ADMIN_DELETE_SQ;
	u16 i, pass;

	if (!pci_device_is_present(hdev->pdev)) {
		dev_err(hdev->dev, "pci_device is not present, skip disable io queues\n");
		return;
	}

	if (hdev->online_queues < 2) {
		dev_err(hdev->dev, "[%s] err, io queue has been delete\n", __func__);
		return;
	}

	for (pass = 0; pass < 2; pass++) {
		for (i = queues; i > 0; i--)
			if (spraid_delete_queue(hdev, opcode, i))
				break;

		opcode = SPRAID_ADMIN_DELETE_CQ;
	}
}

static void spraid_remove_io_queues(struct spraid_dev *hdev)
{
	spraid_delete_io_queues(hdev);
	spraid_free_io_queues(hdev);
}

static void spraid_pci_disable(struct spraid_dev *hdev)
{
	struct pci_dev *pdev = hdev->pdev;
	u32 i;

	for (i = 0; i < hdev->online_queues; i++)
		pci_free_irq(pdev, hdev->queues[i].cq_vector, &hdev->queues[i]);
	pci_free_irq_vectors(pdev);
	if (pci_is_enabled(pdev)) {
		pci_disable_pcie_error_reporting(pdev);
		pci_disable_device(pdev);
	}
	hdev->online_queues = 0;
}

static void spraid_disable_admin_queue(struct spraid_dev *hdev, bool shutdown)
{
	struct spraid_queue *adminq = &hdev->queues[0];
	u16 start, end;

	if (pci_device_is_present(hdev->pdev)) {
		if (shutdown)
			spraid_shutdown_ctrl(hdev);
		else
			spraid_disable_ctrl(hdev);
	}

	if (hdev->queue_count == 0) {
		dev_err(hdev->dev, "[%s] err, admin queue has been delete\n", __func__);
		return;
	}

	spin_lock_irq(&adminq->cq_lock);
	spraid_process_cq(adminq, &start, &end, -1);
	spin_unlock_irq(&adminq->cq_lock);

	spraid_complete_cqes(adminq, start, end);
	spraid_free_admin_queue(hdev);
}

static int spraid_create_dma_pools(struct spraid_dev *hdev)
{
	int i;
	char poolname[20] = { 0 };

	hdev->prp_page_pool = dma_pool_create("prp list page", hdev->dev,
					      PAGE_SIZE, PAGE_SIZE, 0);

	if (!hdev->prp_page_pool) {
		dev_err(hdev->dev, "create prp_page_pool failed\n");
		return -ENOMEM;
	}

	for (i = 0; i < small_pool_num; i++) {
		sprintf(poolname, "prp_list_256_%d", i);
		hdev->prp_small_pool[i] = dma_pool_create(poolname, hdev->dev, SMALL_POOL_SIZE,
							  SMALL_POOL_SIZE, 0);

		if (!hdev->prp_small_pool[i]) {
			dev_err(hdev->dev, "create prp_small_pool %d failed\n", i);
			goto destroy_prp_small_pool;
		}
	}

	return 0;

destroy_prp_small_pool:
	while (i > 0)
		dma_pool_destroy(hdev->prp_small_pool[--i]);
	dma_pool_destroy(hdev->prp_page_pool);

	return -ENOMEM;
}

static void spraid_destroy_dma_pools(struct spraid_dev *hdev)
{
	int i;

	for (i = 0; i < small_pool_num; i++)
		dma_pool_destroy(hdev->prp_small_pool[i]);
	dma_pool_destroy(hdev->prp_page_pool);
}

static int spraid_get_dev_list(struct spraid_dev *hdev, struct spraid_dev_info *devices)
{
	u32 nd = le32_to_cpu(hdev->ctrl_info->nd);
	struct spraid_admin_command admin_cmd;
	struct spraid_dev_list *list_buf;
	u32 i, idx, hdid, ndev;
	int ret = 0;

	list_buf = kmalloc(sizeof(*list_buf), GFP_KERNEL);
	if (!list_buf)
		return -ENOMEM;

	for (idx = 0; idx < nd;) {
		memset(&admin_cmd, 0, sizeof(admin_cmd));
		admin_cmd.get_info.opcode = SPRAID_ADMIN_GET_INFO;
		admin_cmd.get_info.type = SPRAID_GET_INFO_DEV_LIST;
		admin_cmd.get_info.cdw11 = cpu_to_le32(idx);

		ret = spraid_submit_admin_sync_cmd(hdev->admin_q, &admin_cmd, NULL, list_buf,
						   sizeof(*list_buf), 0, 0, 0);

		if (ret) {
			dev_err(hdev->dev, "Get device list failed, nd: %u, idx: %u, ret: %d\n",
				nd, idx, ret);
			goto out;
		}
		ndev = le32_to_cpu(list_buf->dev_num);

		dev_info(hdev->dev, "ndev numbers: %u\n", ndev);

		for (i = 0; i < ndev; i++) {
			hdid = le32_to_cpu(list_buf->devices[i].hdid);
			dev_info(hdev->dev, "list_buf->devices[%d], hdid: %u target: %d, channel: %d, lun: %d, attr[%x]\n",
				    i, hdid,
				    le16_to_cpu(list_buf->devices[i].target),
				    list_buf->devices[i].channel,
				    list_buf->devices[i].lun,
				    list_buf->devices[i].attr);
			if (hdid > nd || hdid == 0) {
				dev_err(hdev->dev, "err, hdid[%d] invalid\n", hdid);
				continue;
			}
			memcpy(&devices[hdid - 1], &list_buf->devices[i],
			       sizeof(struct spraid_dev_info));
		}
		idx += ndev;

		if (idx < MAX_DEV_ENTRY_PER_PAGE_4K)
			break;
	}

out:
	kfree(list_buf);
	return ret;
}

static void spraid_send_aen(struct spraid_dev *hdev)
{
	struct spraid_queue *adminq = &hdev->queues[0];
	struct spraid_admin_command admin_cmd;

	memset(&admin_cmd, 0, sizeof(admin_cmd));
	admin_cmd.common.opcode = SPRAID_ADMIN_ASYNC_EVENT;
	admin_cmd.common.command_id = SPRAID_AQ_BLK_MQ_DEPTH;

	spraid_submit_cmd(adminq, &admin_cmd);
	dev_info(hdev->dev, "send aen, cid[%d]\n", SPRAID_AQ_BLK_MQ_DEPTH);
}

static int spraid_add_device(struct spraid_dev *hdev, struct spraid_dev_info *device)
{
	struct Scsi_Host *shost = hdev->shost;
	struct scsi_device *sdev;

	sdev = scsi_device_lookup(shost, device->channel, le16_to_cpu(device->target), 0);
	if (sdev) {
		dev_warn(hdev->dev, "Device is already exist, channel: %d, target_id: %d, lun: %d\n",
			 device->channel, le16_to_cpu(device->target), 0);
		scsi_device_put(sdev);
		return -EEXIST;
	}
	scsi_add_device(shost, device->channel, le16_to_cpu(device->target), 0);
	return 0;
}

static int spraid_rescan_device(struct spraid_dev *hdev, struct spraid_dev_info *device)
{
	struct Scsi_Host *shost = hdev->shost;
	struct scsi_device *sdev;

	sdev = scsi_device_lookup(shost, device->channel, le16_to_cpu(device->target), 0);
	if (!sdev) {
		dev_warn(hdev->dev, "Device is not exit, channel: %d, target_id: %d, lun: %d\n",
			 device->channel, le16_to_cpu(device->target), 0);
		return -ENODEV;
	}

	scsi_rescan_device(&sdev->sdev_gendev);
	scsi_device_put(sdev);
	return 0;
}

static int spraid_remove_device(struct spraid_dev *hdev, struct spraid_dev_info *org_device)
{
	struct Scsi_Host *shost = hdev->shost;
	struct scsi_device *sdev;

	sdev = scsi_device_lookup(shost, org_device->channel, le16_to_cpu(org_device->target), 0);
	if (!sdev) {
		dev_warn(hdev->dev, "Device is not exit, channel: %d, target_id: %d, lun: %d\n",
			 org_device->channel, le16_to_cpu(org_device->target), 0);
		return -ENODEV;
	}

	scsi_remove_device(sdev);
	scsi_device_put(sdev);
	return 0;
}

static int spraid_dev_list_init(struct spraid_dev *hdev)
{
	u32 nd = le32_to_cpu(hdev->ctrl_info->nd);
	int i, ret;

	hdev->devices = kzalloc_node(nd * sizeof(struct spraid_dev_info),
				     GFP_KERNEL, hdev->numa_node);
	if (!hdev->devices)
		return -ENOMEM;

	ret = spraid_get_dev_list(hdev, hdev->devices);
	if (ret) {
		dev_err(hdev->dev, "Ignore failure of getting device list within initialization\n");
		return 0;
	}

	for (i = 0; i < nd; i++) {
		if (SPRAID_DEV_INFO_FLAG_VALID(hdev->devices[i].flag) &&
		    SPRAID_DEV_INFO_ATTR_BOOT(hdev->devices[i].attr)) {
			spraid_add_device(hdev, &hdev->devices[i]);
			break;
		}
	}
	return 0;
}

static void spraid_scan_work(struct work_struct *work)
{
	struct spraid_dev *hdev =
		container_of(work, struct spraid_dev, scan_work);
	struct spraid_dev_info *devices, *org_devices;
	u32 nd = le32_to_cpu(hdev->ctrl_info->nd);
	u8 flag, org_flag;
	int i, ret;

	devices = kcalloc(nd, sizeof(struct spraid_dev_info), GFP_KERNEL);
	if (!devices)
		return;
	ret = spraid_get_dev_list(hdev, devices);
	if (ret)
		goto free_list;
	org_devices = hdev->devices;
	for (i = 0; i < nd; i++) {
		org_flag = org_devices[i].flag;
		flag = devices[i].flag;

		dev_log_dbg(hdev->dev, "i: %d, org_flag: 0x%x, flag: 0x%x\n",
			    i, org_flag, flag);

		if (SPRAID_DEV_INFO_FLAG_VALID(flag)) {
			if (!SPRAID_DEV_INFO_FLAG_VALID(org_flag)) {
				down_write(&hdev->devices_rwsem);
				memcpy(&org_devices[i], &devices[i],
				       sizeof(struct spraid_dev_info));
				up_write(&hdev->devices_rwsem);
				spraid_add_device(hdev, &devices[i]);
			} else if (SPRAID_DEV_INFO_FLAG_CHANGE(flag)) {
				spraid_rescan_device(hdev, &devices[i]);
			}
		} else {
			if (SPRAID_DEV_INFO_FLAG_VALID(org_flag)) {
				down_write(&hdev->devices_rwsem);
				org_devices[i].flag &= 0xfe;
				up_write(&hdev->devices_rwsem);
				spraid_remove_device(hdev, &org_devices[i]);
			}
		}
	}
free_list:
	kfree(devices);
}

static void spraid_timesyn_work(struct work_struct *work)
{
	struct spraid_dev *hdev =
		container_of(work, struct spraid_dev, timesyn_work);

	spraid_configure_timestamp(hdev);
}

static void spraid_queue_scan(struct spraid_dev *hdev)
{
	queue_work(spraid_wq, &hdev->scan_work);
}

static void spraid_handle_aen_notice(struct spraid_dev *hdev, u32 result)
{
	switch ((result & 0xff00) >> 8) {
	case SPRAID_AEN_DEV_CHANGED:
		spraid_queue_scan(hdev);
		break;
	case SPRAID_AEN_HOST_PROBING:
		break;
	default:
		dev_warn(hdev->dev, "async event result %08x\n", result);
	}
}

static void spraid_handle_aen_vs(struct spraid_dev *hdev, u32 result)
{
	switch (result) {
	case SPRAID_AEN_TIMESYN:
		queue_work(spraid_wq, &hdev->timesyn_work);
		break;
	default:
		dev_warn(hdev->dev, "async event result: %x\n", result);
	}
}

static void spraid_async_event_work(struct work_struct *work)
{
	struct spraid_dev *hdev =
		container_of(work, struct spraid_dev, aen_work);

	spraid_send_aen(hdev);
}

static int spraid_alloc_resources(struct spraid_dev *hdev)
{
	int ret, nqueue;

	ret = ida_alloc(&spraid_instance_ida, GFP_KERNEL);
	if (ret < 0) {
		dev_err(hdev->dev, "Get instance id failed\n");
		return ret;
	}
	hdev->instance = ret;

	hdev->ctrl_info = kzalloc_node(sizeof(*hdev->ctrl_info),
				       GFP_KERNEL, hdev->numa_node);
	if (!hdev->ctrl_info) {
		ret = -ENOMEM;
		goto release_instance;
	}

	ret = spraid_create_dma_pools(hdev);
	if (ret)
		goto free_ctrl_info;
	nqueue = num_possible_cpus() + 1;
	hdev->queues = kcalloc_node(nqueue, sizeof(struct spraid_queue),
				    GFP_KERNEL, hdev->numa_node);
	if (!hdev->queues) {
		ret = -ENOMEM;
		goto destroy_dma_pools;
	}

	dev_info(hdev->dev, "[%s] queues num: %d\n", __func__, nqueue);

	return 0;

destroy_dma_pools:
	spraid_destroy_dma_pools(hdev);
free_ctrl_info:
	kfree(hdev->ctrl_info);
release_instance:
	ida_free(&spraid_instance_ida, hdev->instance);
	return ret;
}

static void spraid_free_resources(struct spraid_dev *hdev)
{
	kfree(hdev->queues);
	spraid_destroy_dma_pools(hdev);
	kfree(hdev->ctrl_info);
	ida_free(&spraid_instance_ida, hdev->instance);
}

static void spraid_setup_passthrough(struct request *req, struct spraid_admin_command *cmd)
{
	memcpy(cmd, spraid_admin_req(req)->cmd, sizeof(*cmd));
	cmd->common.flags &= ~SPRAID_CMD_FLAG_SGL_ALL;
}

static inline void spraid_clear_hreq(struct request *req)
{
	if (!(req->rq_flags & RQF_DONTPREP)) {
		spraid_admin_req(req)->flags = 0;
		req->rq_flags |= RQF_DONTPREP;
	}
}

static blk_status_t spraid_setup_admin_cmd(struct request *req, struct spraid_admin_command *cmd)
{
	spraid_clear_hreq(req);

	memset(cmd, 0, sizeof(*cmd));
	switch (req_op(req)) {
	case REQ_OP_DRV_IN:
	case REQ_OP_DRV_OUT:
		spraid_setup_passthrough(req, cmd);
		break;
	default:
		WARN_ON_ONCE(1);
		return BLK_STS_IOERR;
	}

	cmd->common.command_id = req->tag;
	return BLK_STS_OK;
}

static void spraid_unmap_data(struct spraid_dev *hdev, struct request *req)
{
	struct spraid_iod *iod = blk_mq_rq_to_pdu(req);
	enum dma_data_direction dma_dir = rq_data_dir(req) ?
		DMA_TO_DEVICE : DMA_FROM_DEVICE;

	if (iod->nsge)
		dma_unmap_sg(hdev->dev, iod->sg, iod->nsge, dma_dir);

	spraid_free_iod_res(hdev, iod);
}

static blk_status_t spraid_admin_map_data(struct spraid_dev *hdev, struct request *req,
					  struct spraid_admin_command *cmd)
{
	struct spraid_iod *iod = blk_mq_rq_to_pdu(req);
	struct request_queue *admin_q = req->q;
	enum dma_data_direction dma_dir = rq_data_dir(req) ?
		DMA_TO_DEVICE : DMA_FROM_DEVICE;
	blk_status_t ret = BLK_STS_IOERR;
	int nr_mapped;
	int res;

	sg_init_table(iod->sg, blk_rq_nr_phys_segments(req));
	iod->nsge = blk_rq_map_sg(admin_q, req, iod->sg);
	if (!iod->nsge)
		goto out;

	dev_info(hdev->dev, "nseg: %u, nsge: %u\n",
		    blk_rq_nr_phys_segments(req), iod->nsge);

	ret = BLK_STS_RESOURCE;
	nr_mapped = dma_map_sg_attrs(hdev->dev, iod->sg, iod->nsge, dma_dir, DMA_ATTR_NO_WARN);
	if (!nr_mapped)
		goto out;

	res = spraid_setup_prps(hdev, iod);
	if (res)
		goto unmap;
	cmd->common.dptr.prp1 = cpu_to_le64(sg_dma_address(iod->sg));
	cmd->common.dptr.prp2 = cpu_to_le64(iod->first_dma);
	return BLK_STS_OK;

unmap:
	dma_unmap_sg(hdev->dev, iod->sg, iod->nsge, dma_dir);
out:
	return ret;
}

static blk_status_t spraid_init_admin_iod(struct request *rq, struct spraid_dev *hdev)
{
	struct spraid_iod *iod = blk_mq_rq_to_pdu(rq);
	int nents = blk_rq_nr_phys_segments(rq);
	unsigned int size = blk_rq_payload_bytes(rq);

	if (nents > SPRAID_INT_PAGES || size > SPRAID_INT_BYTES(hdev)) {
		iod->sg = mempool_alloc(hdev->iod_mempool, GFP_ATOMIC);
		if (!iod->sg)
			return BLK_STS_RESOURCE;
	} else {
		iod->sg = iod->inline_sg;
	}

	iod->nsge = 0;
	iod->use_sgl = false;
	iod->npages = -1;
	iod->length = size;
	iod->sg_drv_mgmt = true;

	return BLK_STS_OK;
}

static blk_status_t spraid_queue_admin_rq(struct blk_mq_hw_ctx *hctx,
					  const struct blk_mq_queue_data *bd)
{
	struct spraid_queue *adminq = hctx->driver_data;
	struct spraid_dev *hdev = adminq->hdev;
	struct request *req = bd->rq;
	struct spraid_iod *iod = blk_mq_rq_to_pdu(req);
	struct spraid_admin_command cmd;
	blk_status_t ret;

	ret = spraid_setup_admin_cmd(req, &cmd);
	if (ret)
		goto out;

	ret = spraid_init_admin_iod(req, hdev);
	if (ret)
		goto out;

	if (blk_rq_nr_phys_segments(req)) {
		ret = spraid_admin_map_data(hdev, req, &cmd);
		if (ret)
			goto cleanup_iod;
	}

	blk_mq_start_request(req);
	spraid_submit_cmd(adminq, &cmd);
	return BLK_STS_OK;

cleanup_iod:
	spraid_free_iod_res(hdev, iod);
out:
	return ret;
}

static blk_status_t spraid_error_status(struct request *req)
{
	switch (spraid_admin_req(req)->status & 0x7ff) {
	case SPRAID_SC_SUCCESS:
		return BLK_STS_OK;
	default:
		return BLK_STS_IOERR;
	}
}

static void spraid_complete_admin_rq(struct request *req)
{
	struct spraid_iod *iod = blk_mq_rq_to_pdu(req);
	struct spraid_dev *hdev = iod->spraidq->hdev;

	if (blk_rq_nr_phys_segments(req))
		spraid_unmap_data(hdev, req);
	blk_mq_end_request(req, spraid_error_status(req));
}

static int spraid_admin_init_hctx(struct blk_mq_hw_ctx *hctx, void *data, unsigned int hctx_idx)
{
	struct spraid_dev *hdev = data;
	struct spraid_queue *adminq = &hdev->queues[0];

	WARN_ON(hctx_idx != 0);
	WARN_ON(hdev->admin_tagset.tags[0] != hctx->tags);

	hctx->driver_data = adminq;
	return 0;
}

static int spraid_admin_init_request(struct blk_mq_tag_set *set, struct request *req,
				     unsigned int hctx_idx, unsigned int numa_node)
{
	struct spraid_dev *hdev = set->driver_data;
	struct spraid_iod *iod = blk_mq_rq_to_pdu(req);
	struct spraid_queue *adminq = &hdev->queues[0];

	WARN_ON(!adminq);
	iod->spraidq = adminq;
	return 0;
}

static enum blk_eh_timer_return
spraid_admin_timeout(struct request *req, bool reserved)
{
	struct spraid_iod *iod = blk_mq_rq_to_pdu(req);
	struct spraid_queue *spraidq = iod->spraidq;
	struct spraid_dev *hdev = spraidq->hdev;

	dev_err(hdev->dev, "Admin cid[%d] qid[%d] timeout\n",
		req->tag, spraidq->qid);

	if (spraid_poll_cq(spraidq, req->tag)) {
		dev_warn(hdev->dev, "cid[%d] qid[%d] timeout, completion polled\n",
			 req->tag, spraidq->qid);
		return BLK_EH_DONE;
	}

	spraid_end_admin_request(req, cpu_to_le16(-EINVAL), 0, 0);
	return BLK_EH_DONE;
}

static int spraid_get_ctrl_info(struct spraid_dev *hdev, struct spraid_ctrl_info *ctrl_info)
{
	struct spraid_admin_command admin_cmd;

	memset(&admin_cmd, 0, sizeof(admin_cmd));
	admin_cmd.get_info.opcode = SPRAID_ADMIN_GET_INFO;
	admin_cmd.get_info.type = SPRAID_GET_INFO_CTRL;

	return spraid_submit_admin_sync_cmd(hdev->admin_q, &admin_cmd, NULL,
		ctrl_info, sizeof(struct spraid_ctrl_info), 0, 0, 0);
}

static int spraid_init_ctrl_info(struct spraid_dev *hdev)
{
	int ret;

	hdev->ctrl_info->nd = cpu_to_le32(240);
	hdev->ctrl_info->mdts = 8;
	hdev->ctrl_info->max_cmds = cpu_to_le16(4096);
	hdev->ctrl_info->max_num_sge = cpu_to_le16(128);
	hdev->ctrl_info->max_channel = cpu_to_le16(4);
	hdev->ctrl_info->max_tgt_id = cpu_to_le32(3239);
	hdev->ctrl_info->max_lun = cpu_to_le16(2);

	ret = spraid_get_ctrl_info(hdev, hdev->ctrl_info);
	if (ret)
		dev_err(hdev->dev, "get controller info failed: %d\n", ret);

	dev_info(hdev->dev, "[%s]nd = %d\n", __func__, hdev->ctrl_info->nd);
	dev_info(hdev->dev, "[%s]max_cmd = %d\n", __func__, hdev->ctrl_info->max_cmds);
	dev_info(hdev->dev, "[%s]max_channel = %d\n", __func__, hdev->ctrl_info->max_channel);
	dev_info(hdev->dev, "[%s]max_tgt_id = %d\n", __func__, hdev->ctrl_info->max_tgt_id);
	dev_info(hdev->dev, "[%s]max_lun = %d\n", __func__, hdev->ctrl_info->max_lun);
	dev_info(hdev->dev, "[%s]max_num_sge = %d\n", __func__, hdev->ctrl_info->max_num_sge);
	dev_info(hdev->dev, "[%s]lun_num_boot = %d\n", __func__, hdev->ctrl_info->lun_num_in_boot);
	dev_info(hdev->dev, "[%s]mdts = %d\n", __func__, hdev->ctrl_info->mdts);
	dev_info(hdev->dev, "[%s]acl = %d\n", __func__, hdev->ctrl_info->acl);
	dev_info(hdev->dev, "[%s]aer1 = %d\n", __func__, hdev->ctrl_info->aerl);
	dev_info(hdev->dev, "[%s]card_type = %d\n", __func__, hdev->ctrl_info->card_type);
	dev_info(hdev->dev, "[%s]rtd3e = %d\n", __func__, hdev->ctrl_info->rtd3e);
	dev_info(hdev->dev, "[%s]sn = %s\n", __func__, hdev->ctrl_info->sn);
	dev_info(hdev->dev, "[%s]fr = %s\n", __func__, hdev->ctrl_info->fr);

	return 0;
}

#define SPRAID_MAX_ADMIN_PAYLOAD_SIZE	BIT(16)
static int spraid_alloc_iod_ext_mem_pool(struct spraid_dev *hdev)
{
	u16 max_sge = le16_to_cpu(hdev->ctrl_info->max_num_sge);
	size_t alloc_size;

	alloc_size = spraid_iod_ext_size(hdev, SPRAID_MAX_ADMIN_PAYLOAD_SIZE,
					 max_sge, true, false);
	if (alloc_size > PAGE_SIZE)
		dev_warn(hdev->dev, "It is unreasonable for sg allocation more than one page\n");
	hdev->iod_mempool = mempool_create_node(1, mempool_kmalloc, mempool_kfree,
						(void *)alloc_size, GFP_KERNEL, hdev->numa_node);
	if (!hdev->iod_mempool) {
		dev_err(hdev->dev, "Create iod extension memory pool failed\n");
		return -ENOMEM;
	}

	return 0;
}

static void spraid_free_iod_ext_mem_pool(struct spraid_dev *hdev)
{
	mempool_destroy(hdev->iod_mempool);
}

static int spraid_submit_user_cmd(struct request_queue *q, struct spraid_admin_command *cmd,
				  void __user *ubuffer, unsigned int bufflen, u32 *result,
				  unsigned int timeout)
{
	struct request *req;
	struct bio *bio = NULL;
	int ret;

	req = spraid_alloc_admin_request(q, cmd, 0);
	if (IS_ERR(req))
		return PTR_ERR(req);

	req->timeout = timeout ? timeout : ADMIN_TIMEOUT;
	spraid_admin_req(req)->flags |= SPRAID_REQ_USERCMD;

	if (ubuffer && bufflen) {
		ret = blk_rq_map_user(q, req, NULL, ubuffer, bufflen, GFP_KERNEL);
		if (ret)
			goto out;
		bio = req->bio;
	}
	blk_execute_rq(req->q, NULL, req, 0);
	if (spraid_admin_req(req)->flags & SPRAID_REQ_CANCELLED)
		ret = -EINTR;
	else
		ret = spraid_admin_req(req)->status;
	if (result) {
		result[0] = spraid_admin_req(req)->result0;
		result[1] = spraid_admin_req(req)->result1;
	}
	if (bio)
		blk_rq_unmap_user(bio);
out:
	blk_mq_free_request(req);
	return ret;
}

static int spraid_user_admin_cmd(struct spraid_dev *hdev,
				 struct spraid_passthru_common_cmd __user *ucmd)
{
	struct spraid_passthru_common_cmd cmd;
	struct spraid_admin_command admin_cmd;
	u32 timeout = 0;
	int status;

	if (!capable(CAP_SYS_ADMIN)) {
		dev_err(hdev->dev, "Current user hasn't administrator right, reject service\n");
		return -EACCES;
	}

	if (copy_from_user(&cmd, ucmd, sizeof(cmd))) {
		dev_err(hdev->dev, "Copy command from user space to kernel space failed\n");
		return -EFAULT;
	}

	if (cmd.flags) {
		dev_err(hdev->dev, "Invalid flags in user command\n");
		return -EINVAL;
	}

	dev_info(hdev->dev, "user_admin_cmd opcode: 0x%x, subopcode: 0x%x\n",
		    cmd.opcode, cmd.cdw2 & 0x7ff);

	memset(&admin_cmd, 0, sizeof(admin_cmd));
	admin_cmd.common.opcode = cmd.opcode;
	admin_cmd.common.flags = cmd.flags;
	admin_cmd.common.hdid = cpu_to_le32(cmd.nsid);
	admin_cmd.common.cdw2[0] = cpu_to_le32(cmd.cdw2);
	admin_cmd.common.cdw2[1] = cpu_to_le32(cmd.cdw3);
	admin_cmd.common.cdw10 = cpu_to_le32(cmd.cdw10);
	admin_cmd.common.cdw11 = cpu_to_le32(cmd.cdw11);
	admin_cmd.common.cdw12 = cpu_to_le32(cmd.cdw12);
	admin_cmd.common.cdw13 = cpu_to_le32(cmd.cdw13);
	admin_cmd.common.cdw14 = cpu_to_le32(cmd.cdw14);
	admin_cmd.common.cdw15 = cpu_to_le32(cmd.cdw15);

	if (cmd.timeout_ms)
		timeout = msecs_to_jiffies(cmd.timeout_ms);

	status = spraid_submit_user_cmd(hdev->admin_q, &admin_cmd,
					(void __user *)(uintptr_t)cmd.addr, cmd.info_1.data_len,
					&cmd.result0, timeout);

	dev_info(hdev->dev, "user_admin_cmd status: 0x%x, result0: 0x%x, result1: 0x%x\n",
		 status, cmd.result0, cmd.result1);

	if (status >= 0) {
		if (put_user(cmd.result0, &ucmd->result0))
			return -EFAULT;
		if (put_user(cmd.result1, &ucmd->result1))
			return -EFAULT;
	}

	return status;
}

static int spraid_alloc_ioq_ptcmds(struct spraid_dev *hdev)
{
	int i;
	int ptnum = SPRAID_NR_IOQ_PTCMDS;

	INIT_LIST_HEAD(&hdev->ioq_pt_list);
	spin_lock_init(&hdev->ioq_pt_lock);

	hdev->ioq_ptcmds = kcalloc_node(ptnum, sizeof(struct spraid_ioq_ptcmd),
		GFP_KERNEL, hdev->numa_node);

	if (!hdev->ioq_ptcmds) {
		dev_err(hdev->dev, "Alloc ioq_ptcmds failed\n");
		return -ENOMEM;
	}

	for (i = 0; i < ptnum; i++) {
		hdev->ioq_ptcmds[i].qid = i / SPRAID_PTCMDS_PERQ + 1;
		hdev->ioq_ptcmds[i].cid = i % SPRAID_PTCMDS_PERQ + SPRAID_IO_BLK_MQ_DEPTH;
		list_add_tail(&(hdev->ioq_ptcmds[i].list), &hdev->ioq_pt_list);
	}

	dev_info(hdev->dev, "Alloc ioq_ptcmds success, ptnum[%d]\n", ptnum);

	return 0;
}

static struct spraid_ioq_ptcmd *spraid_get_ioq_ptcmd(struct spraid_dev *hdev)
{
	struct spraid_ioq_ptcmd *cmd = NULL;
	unsigned long flags;

	spin_lock_irqsave(&hdev->ioq_pt_lock, flags);
	if (list_empty(&hdev->ioq_pt_list)) {
		spin_unlock_irqrestore(&hdev->ioq_pt_lock, flags);
		dev_err(hdev->dev, "err, ioq ptcmd list empty\n");
		return NULL;
	}
	cmd = list_entry((&hdev->ioq_pt_list)->next, struct spraid_ioq_ptcmd, list);
	list_del_init(&cmd->list);
	spin_unlock_irqrestore(&hdev->ioq_pt_lock, flags);

	WRITE_ONCE(cmd->state, SPRAID_CMD_IDLE);

	return cmd;
}

static void spraid_put_ioq_ptcmd(struct spraid_dev *hdev, struct spraid_ioq_ptcmd *cmd)
{
	unsigned long flags;

	spin_lock_irqsave(&hdev->ioq_pt_lock, flags);
	list_add(&cmd->list, (&hdev->ioq_pt_list)->next);
	spin_unlock_irqrestore(&hdev->ioq_pt_lock, flags);
}

static int spraid_submit_ioq_sync_cmd(struct spraid_dev *hdev, struct spraid_ioq_command *cmd,
				      u32 *result, void **sense, u32 timeout)
{
	struct spraid_queue *ioq;
	int ret;
	dma_addr_t sense_dma;
	struct spraid_ioq_ptcmd *pt_cmd = spraid_get_ioq_ptcmd(hdev);

	*sense = NULL;

	if (!pt_cmd)
		return -EFAULT;

	dev_info(hdev->dev, "[%s] ptcmd, cid[%d], qid[%d]\n", __func__, pt_cmd->cid, pt_cmd->qid);

	init_completion(&pt_cmd->cmd_done);

	ioq = &hdev->queues[pt_cmd->qid];
	ret = pt_cmd->cid * SCSI_SENSE_BUFFERSIZE;
	pt_cmd->priv = ioq->sense + ret;
	sense_dma = ioq->sense_dma_addr + ret;

	cmd->common.sense_addr = cpu_to_le64(sense_dma);
	cmd->common.sense_len = cpu_to_le16(SCSI_SENSE_BUFFERSIZE);
	cmd->common.command_id = pt_cmd->cid;

	spraid_submit_cmd(ioq, cmd);

	if (!wait_for_completion_timeout(&pt_cmd->cmd_done, timeout)) {
		dev_err(hdev->dev, "[%s] cid[%d], qid[%d] timeout\n",
			__func__, pt_cmd->cid, pt_cmd->qid);
		WRITE_ONCE(pt_cmd->state, SPRAID_CMD_TIMEOUT);
		return -EINVAL;
	}

	if (result) {
		result[0] = pt_cmd->result0;
		result[1] = pt_cmd->result1;
	}

	if ((pt_cmd->status & 0x17f) == 0x101)
		*sense = pt_cmd->priv;

	return pt_cmd->status;
}

static int spraid_user_ioq_cmd(struct spraid_dev *hdev,
			       struct spraid_ioq_passthru_cmd __user *ucmd)
{
	struct spraid_ioq_passthru_cmd cmd;
	struct spraid_ioq_command ioq_cmd;
	u32 timeout = 0;
	int status = 0;
	u8 *data_ptr = NULL;
	dma_addr_t data_dma;
	enum dma_data_direction dma_dir = DMA_NONE;
	void *sense = NULL;

	if (!capable(CAP_SYS_ADMIN)) {
		dev_err(hdev->dev, "Current user hasn't administrator right, reject service\n");
		return -EACCES;
	}

	if (copy_from_user(&cmd, ucmd, sizeof(cmd))) {
		dev_err(hdev->dev, "Copy command from user space to kernel space failed\n");
		return -EFAULT;
	}

	if (cmd.data_len > PAGE_SIZE) {
		dev_err(hdev->dev, "[%s] data len bigger than 4k\n", __func__);
		return -EFAULT;
	}

	dev_info(hdev->dev, "[%s] opcode: 0x%x, subopcode: 0x%x, datalen: %d\n",
		 __func__, cmd.opcode, cmd.info_1.subopcode, cmd.data_len);

	if (cmd.addr && cmd.data_len) {
		data_ptr = dma_alloc_coherent(hdev->dev, PAGE_SIZE, &data_dma, GFP_KERNEL);
		if (!data_ptr)
			return -ENOMEM;

		dma_dir = (cmd.opcode & 1) ? DMA_TO_DEVICE : DMA_FROM_DEVICE;
	}

	if (dma_dir == DMA_TO_DEVICE) {
		if (copy_from_user(data_ptr, (void __user *)(uintptr_t)cmd.addr, cmd.data_len)) {
			dev_err(hdev->dev, "[%s] copy user data failed\n", __func__);
			status = -EFAULT;
			goto free_dma_mem;
		}
	}

	memset(&ioq_cmd, 0, sizeof(ioq_cmd));
	ioq_cmd.common.opcode = cmd.opcode;
	ioq_cmd.common.flags = cmd.flags;
	ioq_cmd.common.hdid = cpu_to_le32(cmd.nsid);
	ioq_cmd.common.sense_len = cpu_to_le16(cmd.info_0.res_sense_len);
	ioq_cmd.common.cdb_len = cmd.info_0.cdb_len;
	ioq_cmd.common.rsvd2 = cmd.info_0.rsvd0;
	ioq_cmd.common.cdw3[0] = cpu_to_le32(cmd.cdw3);
	ioq_cmd.common.cdw3[1] = cpu_to_le32(cmd.cdw4);
	ioq_cmd.common.cdw3[2] = cpu_to_le32(cmd.cdw5);
	ioq_cmd.common.dptr.prp1 = cpu_to_le64(data_dma);

	ioq_cmd.common.cdw10[0] = cpu_to_le32(cmd.cdw10);
	ioq_cmd.common.cdw10[1] = cpu_to_le32(cmd.cdw11);
	ioq_cmd.common.cdw10[2] = cpu_to_le32(cmd.cdw12);
	ioq_cmd.common.cdw10[3] = cpu_to_le32(cmd.cdw13);
	ioq_cmd.common.cdw10[4] = cpu_to_le32(cmd.cdw14);
	ioq_cmd.common.cdw10[5] = cpu_to_le32(cmd.data_len);

	memcpy(ioq_cmd.common.cdb, &cmd.cdw16, cmd.info_0.cdb_len);

	ioq_cmd.common.cdw26[0] = cpu_to_le32(cmd.cdw26[0]);
	ioq_cmd.common.cdw26[1] = cpu_to_le32(cmd.cdw26[1]);
	ioq_cmd.common.cdw26[2] = cpu_to_le32(cmd.cdw26[2]);
	ioq_cmd.common.cdw26[3] = cpu_to_le32(cmd.cdw26[3]);

	if (cmd.timeout_ms)
		timeout = msecs_to_jiffies(cmd.timeout_ms);
	timeout = timeout ? timeout : ADMIN_TIMEOUT;

	status = spraid_submit_ioq_sync_cmd(hdev, &ioq_cmd, &cmd.result0, &sense, timeout);

	if (status >= 0) {
		if (put_user(cmd.result0, &ucmd->result0)) {
			status = -EFAULT;
			goto free_dma_mem;
		}
		if (put_user(cmd.result1, &ucmd->result1)) {
			status = -EFAULT;
			goto free_dma_mem;
		}
		if (dma_dir == DMA_FROM_DEVICE &&
		    copy_to_user((void __user *)(uintptr_t)cmd.addr, data_ptr, cmd.data_len)) {
			status = -EFAULT;
			goto free_dma_mem;
		}
	}

	if (sense) {
		if (copy_to_user((void *__user *)(uintptr_t)cmd.sense_addr,
				  sense, cmd.info_0.res_sense_len)) {
			status = -EFAULT;
			goto free_dma_mem;
		}
	}

free_dma_mem:
	if (data_ptr)
		dma_free_coherent(hdev->dev, PAGE_SIZE, data_ptr, data_dma);

	return status;

}

static int spraid_reset_work_sync(struct spraid_dev *hdev);

static int spraid_user_reset_cmd(struct spraid_dev *hdev)
{
	int ret;

	dev_info(hdev->dev, "[%s] start user reset cmd\n", __func__);
	ret = spraid_reset_work_sync(hdev);
	dev_info(hdev->dev, "[%s] stop user reset cmd[%d]\n", __func__, ret);

	return ret;
}

static int hdev_open(struct inode *inode, struct file *file)
{
	struct spraid_dev *hdev =
		container_of(inode->i_cdev, struct spraid_dev, cdev);
	file->private_data = hdev;
	return 0;
}

static long hdev_ioctl(struct file *file, u32 cmd, unsigned long arg)
{
	struct spraid_dev *hdev = file->private_data;
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	case SPRAID_IOCTL_ADMIN_CMD:
		return spraid_user_admin_cmd(hdev, argp);
	case SPRAID_IOCTL_IOQ_CMD:
		return spraid_user_ioq_cmd(hdev, argp);
	case SPRAID_IOCTL_RESET_CMD:
		return spraid_user_reset_cmd(hdev);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations spraid_dev_fops = {
	.owner		= THIS_MODULE,
	.open		= hdev_open,
	.unlocked_ioctl = hdev_ioctl,
	.compat_ioctl	= hdev_ioctl,
};

static int spraid_create_cdev(struct spraid_dev *hdev)
{
	int ret;

	device_initialize(&hdev->ctrl_device);
	hdev->ctrl_device.devt = MKDEV(MAJOR(spraid_chr_devt), hdev->instance);
	hdev->ctrl_device.class = spraid_class;
	hdev->ctrl_device.parent = hdev->dev;
	dev_set_drvdata(&hdev->ctrl_device, hdev);
	ret = dev_set_name(&hdev->ctrl_device, "spraid%d", hdev->instance);
	if (ret)
		return ret;
	cdev_init(&hdev->cdev, &spraid_dev_fops);
	hdev->cdev.owner = THIS_MODULE;
	ret = cdev_device_add(&hdev->cdev, &hdev->ctrl_device);
	if (ret) {
		dev_err(hdev->dev, "Add cdev failed, ret: %d", ret);
		put_device(&hdev->ctrl_device);
		kfree_const(hdev->ctrl_device.kobj.name);
		return ret;
	}

	return 0;
}

static inline void spraid_remove_cdev(struct spraid_dev *hdev)
{
	cdev_device_del(&hdev->cdev, &hdev->ctrl_device);
}

static const struct blk_mq_ops spraid_admin_mq_ops = {
	.queue_rq = spraid_queue_admin_rq,
	.complete = spraid_complete_admin_rq,
	.init_hctx = spraid_admin_init_hctx,
	.init_request = spraid_admin_init_request,
	.timeout = spraid_admin_timeout,
};

static void spraid_remove_admin_tagset(struct spraid_dev *hdev)
{
	if (hdev->admin_q && !blk_queue_dying(hdev->admin_q)) {
		blk_mq_unquiesce_queue(hdev->admin_q);
		blk_cleanup_queue(hdev->admin_q);
		blk_mq_free_tag_set(&hdev->admin_tagset);
	}
}

static int spraid_alloc_admin_tags(struct spraid_dev *hdev)
{
	if (!hdev->admin_q) {
		hdev->admin_tagset.ops = &spraid_admin_mq_ops;
		hdev->admin_tagset.nr_hw_queues = 1;

		hdev->admin_tagset.queue_depth = SPRAID_AQ_MQ_TAG_DEPTH;
		hdev->admin_tagset.timeout = ADMIN_TIMEOUT;
		hdev->admin_tagset.numa_node = hdev->numa_node;
		hdev->admin_tagset.cmd_size =
			spraid_cmd_size(hdev, true, false);
		hdev->admin_tagset.flags = BLK_MQ_F_NO_SCHED;
		hdev->admin_tagset.driver_data = hdev;

		if (blk_mq_alloc_tag_set(&hdev->admin_tagset)) {
			dev_err(hdev->dev, "Allocate admin tagset failed\n");
			return -ENOMEM;
		}

		hdev->admin_q = blk_mq_init_queue(&hdev->admin_tagset);
		if (IS_ERR(hdev->admin_q)) {
			dev_err(hdev->dev, "Initialize admin request queue failed\n");
			blk_mq_free_tag_set(&hdev->admin_tagset);
			return -ENOMEM;
		}
		if (!blk_get_queue(hdev->admin_q)) {
			dev_err(hdev->dev, "Get admin request queue failed\n");
			spraid_remove_admin_tagset(hdev);
			hdev->admin_q = NULL;
			return -ENODEV;
		}
	} else {
		blk_mq_unquiesce_queue(hdev->admin_q);
	}
	return 0;
}

static bool spraid_check_scmd_completed(struct scsi_cmnd *scmd)
{
	struct spraid_dev *hdev = shost_priv(scmd->device->host);
	struct spraid_iod *iod = scsi_cmd_priv(scmd);
	struct spraid_queue *spraidq;
	u16 hwq, cid;

	spraid_get_tag_from_scmd(scmd, &hwq, &cid);
	spraidq = &hdev->queues[hwq];
	if (READ_ONCE(iod->state) == SPRAID_CMD_COMPLETE || spraid_poll_cq(spraidq, cid)) {
		dev_warn(hdev->dev, "cid[%d], qid[%d] has been completed\n",
			 cid, spraidq->qid);
		return true;
	}
	return false;
}

static enum blk_eh_timer_return spraid_scmd_timeout(struct scsi_cmnd *scmd)
{
	struct spraid_iod *iod = scsi_cmd_priv(scmd);
	unsigned int timeout = scmd->device->request_queue->rq_timeout;

	if (spraid_check_scmd_completed(scmd))
		goto out;

	if (time_after(jiffies, scmd->jiffies_at_alloc + timeout)) {
		if (cmpxchg(&iod->state, SPRAID_CMD_IN_FLIGHT, SPRAID_CMD_TIMEOUT) ==
		    SPRAID_CMD_IN_FLIGHT) {
			return BLK_EH_DONE;
		}
	}
out:
	return BLK_EH_RESET_TIMER;
}

/* send abort command by admin queue temporary */
static int spraid_send_abort_cmd(struct spraid_dev *hdev, u32 hdid, u16 qid, u16 cid)
{
	struct spraid_admin_command admin_cmd;

	memset(&admin_cmd, 0, sizeof(admin_cmd));
	admin_cmd.abort.opcode = SPRAID_ADMIN_ABORT_CMD;
	admin_cmd.abort.hdid = cpu_to_le32(hdid);
	admin_cmd.abort.sqid = cpu_to_le16(qid);
	admin_cmd.abort.cid = cpu_to_le16(cid);

	return spraid_submit_admin_sync_cmd(hdev->admin_q, &admin_cmd, NULL,
		NULL, 0, 0, 0, 0);
}

/* send reset command by admin quueue temporary */
static int spraid_send_reset_cmd(struct spraid_dev *hdev, int type, u32 hdid)
{
	struct spraid_admin_command admin_cmd;

	memset(&admin_cmd, 0, sizeof(admin_cmd));
	admin_cmd.reset.opcode = SPRAID_ADMIN_RESET;
	admin_cmd.reset.hdid = cpu_to_le32(hdid);
	admin_cmd.reset.type = type;

	return spraid_submit_admin_sync_cmd(hdev->admin_q, &admin_cmd, NULL,
		NULL, 0, 0, 0, 0);
}

static bool spraid_change_host_state(struct spraid_dev *hdev, enum spraid_state newstate)
{
	unsigned long flags;
	enum spraid_state oldstate;
	bool change = false;

	spin_lock_irqsave(&hdev->state_lock, flags);

	oldstate = hdev->state;
	switch (newstate) {
	case SPRAID_LIVE:
		switch (oldstate) {
		case SPRAID_NEW:
		case SPRAID_RESETTING:
			change = true;
			break;
		default:
			break;
		}
		break;
	case SPRAID_RESETTING:
		switch (oldstate) {
		case SPRAID_LIVE:
			change = true;
			break;
		default:
			break;
		}
		break;
	case SPRAID_DELETING:
		if (oldstate != SPRAID_DELETING)
			change = true;
		break;
	case SPRAID_DEAD:
		switch (oldstate) {
		case SPRAID_NEW:
		case SPRAID_LIVE:
		case SPRAID_RESETTING:
			change = true;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}
	if (change)
		hdev->state = newstate;
	spin_unlock_irqrestore(&hdev->state_lock, flags);

	dev_info(hdev->dev, "[%s][%d]->[%d], change[%d]\n", __func__, oldstate, newstate, change);

	return change;
}

static void spraid_back_fault_cqe(struct spraid_queue *ioq, struct spraid_completion *cqe)
{
	struct spraid_dev *hdev = ioq->hdev;
	struct blk_mq_tags *tags;
	struct scsi_cmnd *scmd;
	struct spraid_iod *iod;
	struct request *req;

	tags = hdev->shost->tag_set.tags[ioq->qid - 1];
	req = blk_mq_tag_to_rq(tags, cqe->cmd_id);
	if (unlikely(!req || !blk_mq_request_started(req)))
		return;

	scmd = blk_mq_rq_to_pdu(req);
	iod = scsi_cmd_priv(scmd);

	set_host_byte(scmd, DID_NO_CONNECT);
	if (iod->nsge)
		scsi_dma_unmap(scmd);
	spraid_free_iod_res(hdev, iod);
	scmd->scsi_done(scmd);
	dev_warn(hdev->dev, "Back fault CQE, cid[%d], qid[%d]\n",
		 cqe->cmd_id, ioq->qid);
}

static void spraid_back_all_io(struct spraid_dev *hdev)
{
	int i, j;
	struct spraid_queue *ioq;
	struct spraid_completion cqe = { 0 };

	for (i = 1; i <= hdev->shost->nr_hw_queues; i++) {
		ioq = &hdev->queues[i];
		for (j = 0; j < hdev->shost->can_queue; j++) {
			cqe.cmd_id = j;
			spraid_back_fault_cqe(ioq, &cqe);
		}
	}
}

static void spraid_dev_disable(struct spraid_dev *hdev, bool shutdown)
{
	struct spraid_queue *adminq = &hdev->queues[0];
	u16 start, end;
	unsigned long timeout = jiffies + 600 * HZ;

	if (pci_device_is_present(hdev->pdev)) {
		if (shutdown)
			spraid_shutdown_ctrl(hdev);
		else
			spraid_disable_ctrl(hdev);
	}

	while (!time_after(jiffies, timeout)) {
		if (!pci_device_is_present(hdev->pdev)) {
			dev_info(hdev->dev, "[%s] pci_device not present, skip wait\n", __func__);
			break;
		}
		if (!spraid_wait_ready(hdev, hdev->cap, false)) {
			dev_info(hdev->dev, "[%s] wait ready success after reset\n", __func__);
			break;
		}
		dev_info(hdev->dev, "[%s] waiting csts_rdy ready\n", __func__);
	}

	if (hdev->queue_count == 0) {
		dev_err(hdev->dev, "[%s] warn, queue has been delete\n", __func__);
		return;
	}

	spin_lock_irq(&adminq->cq_lock);
	spraid_process_cq(adminq, &start, &end, -1);
	spin_unlock_irq(&adminq->cq_lock);
	spraid_complete_cqes(adminq, start, end);

	spraid_pci_disable(hdev);

	spraid_back_all_io(hdev);
}

static void spraid_reset_work(struct work_struct *work)
{
	int ret;
	struct spraid_dev *hdev = container_of(work, struct spraid_dev, reset_work);

	if (hdev->state != SPRAID_RESETTING) {
		dev_err(hdev->dev, "[%s] err, host is not reset state\n", __func__);
		return;
	}

	dev_info(hdev->dev, "[%s] enter host reset\n", __func__);

	if (hdev->ctrl_config & SPRAID_CC_ENABLE) {
		dev_info(hdev->dev, "[%s] start dev_disable\n", __func__);
		spraid_dev_disable(hdev, false);
	}

	ret = spraid_pci_enable(hdev);
	if (ret)
		goto out;

	ret = spraid_setup_admin_queue(hdev);
	if (ret)
		goto pci_disable;

	ret = spraid_alloc_admin_tags(hdev);
	if (ret)
		goto pci_disable;

	ret = spraid_setup_io_queues(hdev);
	if (ret || hdev->online_queues <= hdev->shost->nr_hw_queues)
		goto pci_disable;

	spraid_change_host_state(hdev, SPRAID_LIVE);

	spraid_send_aen(hdev);

	return;

pci_disable:
	spraid_pci_disable(hdev);
out:
	spraid_change_host_state(hdev, SPRAID_DEAD);
	dev_err(hdev->dev, "[%s] err, host reset failed\n", __func__);
}

static int spraid_reset_work_sync(struct spraid_dev *hdev)
{
	if (!spraid_change_host_state(hdev, SPRAID_RESETTING)) {
		dev_info(hdev->dev, "[%s] can't change to reset state\n", __func__);
		return -EBUSY;
	}

	if (!queue_work(spraid_wq, &hdev->reset_work)) {
		dev_err(hdev->dev, "[%s] err, host is already in reset state\n", __func__);
		return -EBUSY;
	}

	flush_work(&hdev->reset_work);
	if (hdev->state != SPRAID_LIVE)
		return -ENODEV;

	return 0;
}

static int spraid_wait_abnl_cmd_done(struct spraid_iod *iod)
{
	u16 times = 0;

	do {
		if (READ_ONCE(iod->state) == SPRAID_CMD_TMO_COMPLETE)
			break;
		msleep(500);
		times++;
	} while (times <= SPRAID_WAIT_ABNL_CMD_TIMEOUT);

	/* wait command completion timeout after abort/reset success */
	if (times >= SPRAID_WAIT_ABNL_CMD_TIMEOUT)
		return -ETIMEDOUT;

	return 0;
}

static int spraid_abort_handler(struct scsi_cmnd *scmd)
{
	struct spraid_dev *hdev = shost_priv(scmd->device->host);
	struct spraid_iod *iod = scsi_cmd_priv(scmd);
	struct spraid_sdev_hostdata *hostdata;
	u16 hwq, cid;
	int ret;

	scsi_print_command(scmd);

	if (!spraid_wait_abnl_cmd_done(iod) || spraid_check_scmd_completed(scmd) ||
	    hdev->state != SPRAID_LIVE)
		return SUCCESS;

	hostdata = scmd->device->hostdata;
	spraid_get_tag_from_scmd(scmd, &hwq, &cid);

	dev_warn(hdev->dev, "cid[%d] qid[%d] timeout, aborting\n", cid, hwq);
	ret = spraid_send_abort_cmd(hdev, hostdata->hdid, hwq, cid);
	if (ret != ADMIN_ERR_TIMEOUT) {
		ret = spraid_wait_abnl_cmd_done(iod);
		if (ret) {
			dev_warn(hdev->dev, "cid[%d] qid[%d] abort failed, not found\n", cid, hwq);
			return FAILED;
		}
		dev_warn(hdev->dev, "cid[%d] qid[%d] abort succ\n", cid, hwq);
		return SUCCESS;
	}
	dev_warn(hdev->dev, "cid[%d] qid[%d] abort failed, timeout\n", cid, hwq);
	return FAILED;
}

static int spraid_tgt_reset_handler(struct scsi_cmnd *scmd)
{
	struct spraid_dev *hdev = shost_priv(scmd->device->host);
	struct spraid_iod *iod = scsi_cmd_priv(scmd);
	struct spraid_sdev_hostdata *hostdata;
	u16 hwq, cid;
	int ret;

	scsi_print_command(scmd);

	if (!spraid_wait_abnl_cmd_done(iod) || spraid_check_scmd_completed(scmd) ||
	    hdev->state != SPRAID_LIVE)
		return SUCCESS;

	hostdata = scmd->device->hostdata;
	spraid_get_tag_from_scmd(scmd, &hwq, &cid);

	dev_warn(hdev->dev, "cid[%d] qid[%d] timeout, target reset\n", cid, hwq);
	ret = spraid_send_reset_cmd(hdev, SPRAID_RESET_TARGET, hostdata->hdid);
	if (ret == 0) {
		ret = spraid_wait_abnl_cmd_done(iod);
		if (ret) {
			dev_warn(hdev->dev, "cid[%d] qid[%d]target reset failed, not found\n",
				 cid, hwq);
			return FAILED;
		}

		dev_warn(hdev->dev, "cid[%d] qid[%d] target reset success\n", cid, hwq);
		return SUCCESS;
	}

	dev_warn(hdev->dev, "cid[%d] qid[%d] ret[%d] target reset failed\n", cid, hwq, ret);
	return FAILED;
}

static int spraid_bus_reset_handler(struct scsi_cmnd *scmd)
{
	struct spraid_dev *hdev = shost_priv(scmd->device->host);
	struct spraid_iod *iod = scsi_cmd_priv(scmd);
	struct spraid_sdev_hostdata *hostdata;
	u16 hwq, cid;
	int ret;

	scsi_print_command(scmd);

	if (!spraid_wait_abnl_cmd_done(iod) || spraid_check_scmd_completed(scmd) ||
	    hdev->state != SPRAID_LIVE)
		return SUCCESS;

	hostdata = scmd->device->hostdata;
	spraid_get_tag_from_scmd(scmd, &hwq, &cid);

	dev_warn(hdev->dev, "cid[%d] qid[%d] timeout, bus reset\n", cid, hwq);
	ret = spraid_send_reset_cmd(hdev, SPRAID_RESET_BUS, hostdata->hdid);
	if (ret == 0) {
		ret = spraid_wait_abnl_cmd_done(iod);
		if (ret) {
			dev_warn(hdev->dev, "cid[%d] qid[%d] bus reset failed, not found\n",
				 cid, hwq);
			return FAILED;
		}

		dev_warn(hdev->dev, "cid[%d] qid[%d] bus reset succ\n", cid, hwq);
		return SUCCESS;
	}

	dev_warn(hdev->dev, "cid[%d] qid[%d] ret[%d] bus reset failed\n", cid, hwq, ret);
	return FAILED;
}

static int spraid_shost_reset_handler(struct scsi_cmnd *scmd)
{
	u16 hwq, cid;
	struct spraid_dev *hdev = shost_priv(scmd->device->host);

	scsi_print_command(scmd);
	if (spraid_check_scmd_completed(scmd) || hdev->state != SPRAID_LIVE)
		return SUCCESS;

	spraid_get_tag_from_scmd(scmd, &hwq, &cid);
	dev_warn(hdev->dev, "cid[%d] qid[%d] host reset\n", cid, hwq);

	if (spraid_reset_work_sync(hdev)) {
		dev_warn(hdev->dev, "cid[%d] qid[%d] host reset failed\n", cid, hwq);
		return FAILED;
	}

	dev_warn(hdev->dev, "cid[%d] qid[%d] host reset success\n", cid, hwq);

	return SUCCESS;
}

static ssize_t csts_pp_show(struct device *cdev, struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct spraid_dev *hdev = shost_priv(shost);
	int ret = -1;

	if (pci_device_is_present(hdev->pdev)) {
		ret = (readl(hdev->bar + SPRAID_REG_CSTS) & SPRAID_CSTS_PP_MASK);
		ret >>= SPRAID_CSTS_PP_SHIFT;
	}

	return snprintf(buf, PAGE_SIZE, "%d\n", ret);
}

static ssize_t csts_shst_show(struct device *cdev, struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct spraid_dev *hdev = shost_priv(shost);
	int ret = -1;

	if (pci_device_is_present(hdev->pdev)) {
		ret = (readl(hdev->bar + SPRAID_REG_CSTS) & SPRAID_CSTS_SHST_MASK);
		ret >>= SPRAID_CSTS_SHST_SHIFT;
	}

	return snprintf(buf, PAGE_SIZE, "%d\n", ret);
}

static ssize_t csts_cfs_show(struct device *cdev, struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct spraid_dev *hdev = shost_priv(shost);
	int ret = -1;

	if (pci_device_is_present(hdev->pdev)) {
		ret = (readl(hdev->bar + SPRAID_REG_CSTS) & SPRAID_CSTS_CFS_MASK);
		ret >>= SPRAID_CSTS_CFS_SHIFT;
	}

	return snprintf(buf, PAGE_SIZE, "%d\n", ret);
}

static ssize_t csts_rdy_show(struct device *cdev, struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct spraid_dev *hdev = shost_priv(shost);
	int ret = -1;

	if (pci_device_is_present(hdev->pdev))
		ret = (readl(hdev->bar + SPRAID_REG_CSTS) & SPRAID_CSTS_RDY);

	return snprintf(buf, PAGE_SIZE, "%d\n", ret);
}

static ssize_t fw_version_show(struct device *cdev, struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct spraid_dev *hdev = shost_priv(shost);

	return snprintf(buf, sizeof(hdev->ctrl_info->fr), "%s\n", hdev->ctrl_info->fr);
}

static DEVICE_ATTR_RO(csts_pp);
static DEVICE_ATTR_RO(csts_shst);
static DEVICE_ATTR_RO(csts_cfs);
static DEVICE_ATTR_RO(csts_rdy);
static DEVICE_ATTR_RO(fw_version);

static struct device_attribute *spraid_host_attrs[] = {
	&dev_attr_csts_pp,
	&dev_attr_csts_shst,
	&dev_attr_csts_cfs,
	&dev_attr_csts_rdy,
	&dev_attr_fw_version,
	NULL,
};

static struct scsi_host_template spraid_driver_template = {
	.module			= THIS_MODULE,
	.name			= "Ramaxel Logic spraid driver",
	.proc_name		= "spraid",
	.queuecommand		= spraid_queue_command,
	.slave_alloc		= spraid_slave_alloc,
	.slave_destroy		= spraid_slave_destroy,
	.slave_configure	= spraid_slave_configure,
	.eh_timed_out		= spraid_scmd_timeout,
	.eh_abort_handler	= spraid_abort_handler,
	.eh_target_reset_handler	= spraid_tgt_reset_handler,
	.eh_bus_reset_handler		= spraid_bus_reset_handler,
	.eh_host_reset_handler		= spraid_shost_reset_handler,
	.change_queue_depth		= scsi_change_queue_depth,
	.host_tagset			= 1,
	.this_id			= -1,
	.shost_attrs			= spraid_host_attrs,
};

static void spraid_shutdown(struct pci_dev *pdev)
{
	struct spraid_dev *hdev = pci_get_drvdata(pdev);

	spraid_remove_io_queues(hdev);
	spraid_disable_admin_queue(hdev, true);
}

static int spraid_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct spraid_dev *hdev;
	struct Scsi_Host *shost;
	int node, ret;

	shost = scsi_host_alloc(&spraid_driver_template, sizeof(*hdev));
	if (!shost) {
		dev_err(&pdev->dev, "Failed to allocate scsi host\n");
		return -ENOMEM;
	}
	hdev = shost_priv(shost);
	hdev->pdev = pdev;
	hdev->dev = get_device(&pdev->dev);

	node = dev_to_node(hdev->dev);
	if (node == NUMA_NO_NODE) {
		node = first_memory_node;
		set_dev_node(hdev->dev, node);
	}
	hdev->numa_node = node;
	hdev->shost = shost;
	pci_set_drvdata(pdev, hdev);

	ret = spraid_dev_map(hdev);
	if (ret)
		goto put_dev;

	init_rwsem(&hdev->devices_rwsem);
	INIT_WORK(&hdev->aen_work, spraid_async_event_work);
	INIT_WORK(&hdev->scan_work, spraid_scan_work);
	INIT_WORK(&hdev->timesyn_work, spraid_timesyn_work);
	INIT_WORK(&hdev->reset_work, spraid_reset_work);
	spin_lock_init(&hdev->state_lock);

	ret = spraid_alloc_resources(hdev);
	if (ret)
		goto dev_unmap;

	ret = spraid_pci_enable(hdev);
	if (ret)
		goto resources_free;

	ret = spraid_setup_admin_queue(hdev);
	if (ret)
		goto pci_disable;

	ret = spraid_alloc_admin_tags(hdev);
	if (ret)
		goto disable_admin_q;

	ret = spraid_init_ctrl_info(hdev);
	if (ret)
		goto free_admin_tagset;

	ret = spraid_alloc_iod_ext_mem_pool(hdev);
	if (ret)
		goto free_admin_tagset;

	ret = spraid_setup_io_queues(hdev);
	if (ret)
		goto free_iod_mempool;

	spraid_shost_init(hdev);

	ret = scsi_add_host(hdev->shost, hdev->dev);
	if (ret) {
		dev_err(hdev->dev, "Add shost to system failed, ret: %d\n",
			ret);
		goto remove_io_queues;
	}

	ret = spraid_create_cdev(hdev);
	if (ret)
		goto remove_io_queues;

	if (hdev->online_queues == SPRAID_ADMIN_QUEUE_NUM) {
		dev_warn(hdev->dev, "warn only admin queue can be used\n");
		return 0;
	}

	hdev->state = SPRAID_LIVE;

	spraid_send_aen(hdev);

	ret = spraid_dev_list_init(hdev);
	if (ret)
		goto remove_cdev;

	ret = spraid_configure_timestamp(hdev);
	if (ret)
		dev_warn(hdev->dev, "init set timestamp failed\n");

	ret = spraid_alloc_ioq_ptcmds(hdev);
	if (ret)
		goto remove_cdev;

	scsi_scan_host(hdev->shost);

	return 0;

remove_cdev:
	spraid_remove_cdev(hdev);
remove_io_queues:
	spraid_remove_io_queues(hdev);
free_iod_mempool:
	spraid_free_iod_ext_mem_pool(hdev);
free_admin_tagset:
	spraid_remove_admin_tagset(hdev);
disable_admin_q:
	spraid_disable_admin_queue(hdev, false);
pci_disable:
	spraid_pci_disable(hdev);
resources_free:
	spraid_free_resources(hdev);
dev_unmap:
	spraid_dev_unmap(hdev);
put_dev:
	put_device(hdev->dev);
	scsi_host_put(shost);

	return -ENODEV;
}

static void spraid_remove(struct pci_dev *pdev)
{
	struct spraid_dev *hdev = pci_get_drvdata(pdev);
	struct Scsi_Host *shost = hdev->shost;

	dev_info(hdev->dev, "enter spraid remove\n");

	spraid_change_host_state(hdev, SPRAID_DELETING);

	if (!pci_device_is_present(pdev)) {
		scsi_block_requests(shost);
		spraid_back_all_io(hdev);
		scsi_unblock_requests(shost);
	}

	flush_work(&hdev->reset_work);
	scsi_remove_host(shost);

	kfree(hdev->ioq_ptcmds);
	kfree(hdev->devices);
	spraid_remove_cdev(hdev);
	spraid_remove_io_queues(hdev);
	spraid_free_iod_ext_mem_pool(hdev);
	spraid_remove_admin_tagset(hdev);
	spraid_disable_admin_queue(hdev, false);
	spraid_pci_disable(hdev);
	spraid_free_resources(hdev);
	spraid_dev_unmap(hdev);
	put_device(hdev->dev);
	scsi_host_put(shost);

	dev_info(hdev->dev, "exit spraid remove\n");
}

static const struct pci_device_id spraid_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_RAMAXEL_LOGIC, SPRAID_SERVER_DEVICE_HAB_DID) },
	{ PCI_DEVICE(PCI_VENDOR_ID_RAMAXEL_LOGIC, SPRAID_SERVER_DEVICE_RAID_DID) },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, spraid_id_table);

static struct pci_driver spraid_driver = {
	.name		= "spraid",
	.id_table	= spraid_id_table,
	.probe		= spraid_probe,
	.remove		= spraid_remove,
	.shutdown	= spraid_shutdown,
};

static int __init spraid_init(void)
{
	int ret;

	spraid_wq = alloc_workqueue("spraid-wq", WQ_UNBOUND | WQ_MEM_RECLAIM | WQ_SYSFS, 0);
	if (!spraid_wq)
		return -ENOMEM;

	ret = alloc_chrdev_region(&spraid_chr_devt, 0, SPRAID_MINORS, "spraid");
	if (ret < 0)
		goto destroy_wq;

	spraid_class = class_create(THIS_MODULE, "spraid");
	if (IS_ERR(spraid_class)) {
		ret = PTR_ERR(spraid_class);
		goto unregister_chrdev;
	}

	ret = pci_register_driver(&spraid_driver);
	if (ret < 0)
		goto destroy_class;

	return 0;

destroy_class:
	class_destroy(spraid_class);
unregister_chrdev:
	unregister_chrdev_region(spraid_chr_devt, SPRAID_MINORS);
destroy_wq:
	destroy_workqueue(spraid_wq);

	return ret;
}

static void __exit spraid_exit(void)
{
	pci_unregister_driver(&spraid_driver);
	class_destroy(spraid_class);
	unregister_chrdev_region(spraid_chr_devt, SPRAID_MINORS);
	destroy_workqueue(spraid_wq);
	ida_destroy(&spraid_instance_ida);
}

MODULE_AUTHOR("Ramaxel Memory Technology");
MODULE_DESCRIPTION("Ramaxel Memory Technology SPraid Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(SPRAID_DRV_VERSION);
module_init(spraid_init);
module_exit(spraid_exit);
