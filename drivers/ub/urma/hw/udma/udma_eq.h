/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#ifndef __UDMA_EQ_H__
#define __UDMA_EQ_H__

#include <linux/auxiliary_bus.h>
#include "udma_dev.h"
#include "udma_ctrlq_tp.h"

#define EDRVNO 255

int udma_register_ae_event(struct auxiliary_device *adev);
void udma_unregister_ae_event(struct auxiliary_device *adev);
int udma_register_ce_event(struct auxiliary_device *adev);
void udma_unregister_crq_event(struct auxiliary_device *adev);
int udma_register_crq_event(struct auxiliary_device *adev);
int udma_register_ctrlq_event(struct auxiliary_device *adev);
void udma_unregister_ctrlq_event(struct auxiliary_device *adev);
int udma_register_workqueue(struct udma_dev *udma_dev);
void udma_unregister_workqueue(struct udma_dev *udma_dev);
int udma_save_tp_info(struct udma_dev *udma_dev, struct udma_ue_tp_info *info, uint8_t ue_idx);

static inline void udma_unregister_ce_event(struct auxiliary_device *adev)
{
	ubase_comp_unregister(adev);
}

struct udma_flush_work {
	struct udma_dev	*udev;
	uint32_t tp_num;
	bool check_ta_flush;
	struct work_struct	work;
};

#endif /* __UDMA_EQ_H__ */
