/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef DPP_DRV_INIT_H
#define DPP_DRV_INIT_H

#include "zxic_common.h"
#include "dpp_type_api.h"
#include "dpp_dev.h"

DPP_STATUS dpp_flow_init(struct dpp_dev_t *dev);
DPP_STATUS dpp_flow_uninit(struct dpp_dev_t *dev);
void dpp_flow_init_status_init(void);
DPP_STATUS dpp_flow_data_all_flush(struct dpp_dev_t *dev, u32 queue_id);
DPP_STATUS dpp_bar_msg_num_init(struct dpp_dev_t *dev);
#endif
