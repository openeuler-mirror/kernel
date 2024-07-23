// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include "sdma_irq.h"

#define HISI_SDMA_IRQ_FUNC_NAME		"SDMA_CHANNEL_IOE_IRQ"
#define SDMA_IOE_NUM_MAX		(SDMA_IRQ_NUM_MAX / 2)
#define SDMA_IOC_NUM_MAX		SDMA_IOE_NUM_MAX
#define SDMA_IOC_MASKED_STATUS		0x1
#define SDMA_IOC_IOE_MASKED_STATUS	0x3

static spinlock_t err_set_lock[SDMA_IOE_NUM_MAX];

irqreturn_t sdma_chn_ioe_irq_handle(int irq, void *psdma_dev)
{
	struct hisi_sdma_device *sdma;
	u32 err_status;
	u32 cqe_status;
	u32 cqe_sqeid;
	int chn = -1;
	int i;

	sdma = (struct hisi_sdma_device *)psdma_dev;
	for (i = INT_CH_IOE_SDMAM_0 + HISI_STARS_CHN_NUM; i <= INT_CH_IOE_SDMAM_191; i++) {
		if (sdma->irq[i] == irq) {
			chn = i - (INT_CH_IOE_SDMAM_0 + HISI_STARS_CHN_NUM);
			break;
		}
	}
	if (chn < 0 || chn >= HISI_SDMA_DEFAULT_CHANNEL_NUM) {
		dev_err(&sdma->pdev->dev, "SDMA IOE int%d wrong!\n", irq);
		return IRQ_NONE;
	}

	spin_lock(&err_set_lock[chn]);
	err_status = sdma_channel_get_err_status(&sdma->channels[chn]);
	cqe_status = sdma_channel_get_cqe_status(&sdma->channels[chn]);
	cqe_sqeid = sdma_channel_get_cqe_sqeid(&sdma->channels[chn]);

	sdma->channels[chn].sync_info_base->ioe.ch_err_status = err_status;
	sdma->channels[chn].sync_info_base->ioe.ch_cqe_status = cqe_status;
	sdma->channels[chn].sync_info_base->ioe.ch_cqe_sqeid = cqe_sqeid;

	sdma_channel_clear_ioe_status(sdma->io_base + chn * HISI_SDMA_CHANNEL_IOMEM_SIZE);
	sdma_channel_clear_cqe_status(sdma->io_base + chn * HISI_SDMA_CHANNEL_IOMEM_SIZE);
	spin_unlock(&err_set_lock[chn]);

	dev_info(&sdma->pdev->dev, "sdma chn[%d], sqe[%u] error status = %u, ioe clear\n",
		 chn, cqe_sqeid, err_status);

	return IRQ_HANDLED;
}

void sdma_irq_init(struct hisi_sdma_device *sdma)
{
	struct platform_device *pdev;
	void __iomem *io_addr;
	int ret, vir_irq;
	u32 irq_cnt;
	u32 i;

	pdev = sdma->pdev;
	for (i = 0; i < sdma->nr_channel + HISI_STARS_CHN_NUM; i++) {
		io_addr = sdma->io_orig_base + i * HISI_SDMA_CHANNEL_IOMEM_SIZE;
		sdma_channel_set_irq_mask(io_addr, SDMA_IOC_MASKED_STATUS);
	}

	sdma_int_converge_dis(sdma->common_base);

	irq_cnt = (u32)sdma->irq_cnt;
	for (i = 0; i < irq_cnt; i++) {
		vir_irq = platform_get_irq(pdev, i);
		if (vir_irq < 0) {
			dev_err(&pdev->dev, "get vir_irq[idx:%d] failed:%d!\n", i, vir_irq);
			sdma->irq[i] = -1;
			continue;
		}
		sdma->irq[i] = vir_irq;
	}

	for (i = INT_CH_IOE_SDMAM_0 + HISI_STARS_CHN_NUM; i <= INT_CH_IOE_SDMAM_255; i++) {
		if (sdma->irq[i] == -1)
			continue;

		ret = devm_request_irq(&sdma->pdev->dev, sdma->irq[i], sdma_chn_ioe_irq_handle,
				       IRQF_ONESHOT, HISI_SDMA_IRQ_FUNC_NAME, sdma);
		if (ret != 0) {
			dev_err(&pdev->dev, "request_irq failed, ret=%d", ret);
			continue;
		}
	}

	for (i = 0; i < SDMA_IOE_NUM_MAX; i++)
		spin_lock_init(&err_set_lock[i]);
}

void sdma_irq_deinit(struct hisi_sdma_device *sdma)
{
	struct platform_device *pdev;
	void __iomem *io_addr;
	u32 i;

	pdev = sdma->pdev;
	for (i = 0; i < sdma->nr_channel + HISI_STARS_CHN_NUM; i++) {
		io_addr = sdma->io_orig_base + i * HISI_SDMA_CHANNEL_IOMEM_SIZE;
		sdma_channel_set_irq_mask(io_addr, SDMA_IOC_IOE_MASKED_STATUS);
	}
}
