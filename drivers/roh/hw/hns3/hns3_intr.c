// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2020-2022 Hisilicon Limited.

#include <linux/interrupt.h>
#include <linux/pci.h>

#include "hns3_device.h"
#include "hns3_reg.h"
#include "hns3_intr.h"

static u32 hns3_roh_parse_event_type(struct hns3_roh_device *hroh_dev, u32 *clear_val)
{
	u32 cmdq_src_reg;
	u32 event_type;

	cmdq_src_reg = hns3_roh_read(hroh_dev, HNS3_ROH_VECTOR0_CMDQ_SRC_REG);
	if (BIT(HNS3_ROH_VECTOR0_RX_CMDQ_INT_B) & cmdq_src_reg)
		event_type = HNS3_ROH_VECTOR0_EVENT_MBX;
	else
		event_type = HNS3_ROH_VECTOR0_EVENT_OTHER;

	*clear_val = cmdq_src_reg;

	return event_type;
}

static void hns3_roh_clear_event_type(struct hns3_roh_device *hroh_dev,
				      u32 event_type, u32 val)
{
	switch (event_type) {
	case HNS3_ROH_VECTOR0_EVENT_MBX:
		hns3_roh_write(hroh_dev, HNS3_ROH_VECTOR0_CMDQ_SRC_REG, val);
		break;
	default:
		break;
	}
}

void hns3_roh_enable_vector(struct hns3_roh_abn_vector *vector, bool enable)
{
	writel(enable ? 1 : 0, vector->addr);
}

static irqreturn_t hns3_roh_abn_irq_handle(int irq, void *data)
{
	struct hns3_roh_device *hroh_dev = data;
	irqreturn_t result;
	u32 clear_val = 0;
	u32 event_type;

	hns3_roh_enable_vector(&hroh_dev->abn_vector, false);

	event_type = hns3_roh_parse_event_type(hroh_dev, &clear_val);
	switch (event_type) {
	case HNS3_ROH_VECTOR0_EVENT_MBX:
		/* If we are here then,
		 * 1. Either we are not handling any mbx task and we are not
		 *    scheduled as well
		 *                        OR
		 * 2. We could be handling a mbx task but nothing more is
		 *    scheduled.
		 * In both cases, we should schedule mbx task as there are more
		 * mbx messages reported by this interrupt.
		 */
		hns3_roh_mbx_task_schedule(hroh_dev);

		result = IRQ_HANDLED;
		break;
	default:
		dev_warn(hroh_dev->dev, "unknown event type, type = %u\n",
			 event_type);
		result = IRQ_NONE;
		break;
	}

	hns3_roh_clear_event_type(hroh_dev, event_type, clear_val);

	if (!clear_val || event_type == HNS3_ROH_VECTOR0_EVENT_MBX)
		hns3_roh_enable_vector(&hroh_dev->abn_vector, true);

	return result;
}

static void hns3_roh_abn_irq_uninit(struct hns3_roh_device *hroh_dev)
{
	struct hns3_roh_abn_vector *abn_vector;

	abn_vector = &hroh_dev->abn_vector;
	free_irq(abn_vector->vector_irq, hroh_dev);
}

void hns3_roh_uninit_irq(struct hns3_roh_device *hroh_dev)
{
	hns3_roh_abn_irq_uninit(hroh_dev);
}

static int hns3_roh_abn_irq_init(struct hns3_roh_device *hroh_dev)
{
	struct hns3_roh_abn_vector *abn_vector = &hroh_dev->abn_vector;
	int vector_index = hroh_dev->intr_info.vector_offset;
	int ret;

	abn_vector->vector_irq = pci_irq_vector(hroh_dev->pdev, vector_index);
	abn_vector->addr = hroh_dev->reg_base + HNS3_ROH_VECTOR0_INT_CTRL_REG;

	ret = snprintf(abn_vector->name, HNS3_ROH_INT_NAME_LEN, "%s-%s-abn",
		       HNS3_ROH_NAME, pci_name(hroh_dev->pdev));
	if (ret >= HNS3_ROH_INT_NAME_LEN || ret < 0) {
		dev_err(hroh_dev->dev, "abn vector name is too long.\n");
		return -EINVAL;
	}

	ret = request_irq(abn_vector->vector_irq, hns3_roh_abn_irq_handle, 0,
			  abn_vector->name, hroh_dev);
	if (ret) {
		dev_err(hroh_dev->dev,
			"failed to request abn irq: %d, ret = %d\n",
			abn_vector->vector_irq, ret);
		return ret;
	}

	return 0;
}

int hns3_roh_init_irq(struct hns3_roh_device *hroh_dev)
{
	int ret;

	ret = hns3_roh_abn_irq_init(hroh_dev);
	if (ret) {
		dev_err(hroh_dev->dev, "failed to init abn irq, ret = %d\n", ret);
		return ret;
	}

	return 0;
}
