/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __EN_PF_EVENTS_H__
#define __EN_PF_EVENTS_H__
#include "../en_pf.h"

s32 dh_pf_events_init(struct dh_core_dev *dev);
void dh_pf_events_uninit(struct dh_core_dev *dev);
void dh_pf_sriov_cap_cfg_uninit(struct dh_core_dev *dev);
void zxdh_pf_nh_attach(struct dh_core_dev *dev, struct dh_nb *nb, bool attach);
extern irqreturn_t msix_extern_pps_irq_from_risc_handler(struct zxdh_pf_device *dev);
extern irqreturn_t msix_local_pps_irq_from_risc_handler(struct zxdh_pf_device *dev);

#endif
