// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include "sdma_irq.h"

#define HISI_SDMA_IRQ_FUNC_NAME(n)	"SDMA_CHANNEL##n_IOE_IRQ"
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
	int chn;

	sdma = (struct hisi_sdma_device *)psdma_dev;
	chn = irq - sdma->base_vir_irq - SDMA_IOC_NUM_MAX - HISI_STARS_CHN_NUM;
	if (chn < 0 || chn >= SDMA_IOC_NUM_MAX) {
		dev_err(&sdma->pdev->dev, "SDMA IOE int%d wrong!\n", irq);
		return 0;
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

	dev_info(&sdma->pdev->dev, "sdma chn%d error status = %u, ioe clear\n", chn, err_status);

	return 0;
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
		if (i == 0) {
			sdma->base_vir_irq = vir_irq;
			dev_info(&pdev->dev, "base_vir_irq = %d\n", vir_irq);
		}
	}

	for (i = INT_CH_IOE_SDMAM_0 + HISI_STARS_CHN_NUM; i <= INT_CH_IOE_SDMAM_255; i++) {
		if (sdma->irq[i] == -1)
			continue;

		ret = devm_request_irq(&sdma->pdev->dev, sdma->irq[i], sdma_chn_ioe_irq_handle,
				       IRQF_ONESHOT, HISI_SDMA_IRQ_FUNC_NAME(i), sdma);
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
