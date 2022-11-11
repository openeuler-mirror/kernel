/* SPDX-License-Identifier: GPL-2.0+ */
// Copyright (c) 2020-2022 Hisilicon Limited.

#ifndef __HNS3_ROH_INTR_H__
#define __HNS3_ROH_INTR_H__

#include "hns3_common.h"

void hns3_roh_enable_vector(struct hns3_roh_abn_vector *vector, bool enable);
int hns3_roh_init_irq(struct hns3_roh_device *hroh_dev);
void hns3_roh_uninit_irq(struct hns3_roh_device *hroh_dev);

#endif /* __HNS3_ROH_INTR_H__ */
