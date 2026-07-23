/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_NP_INIT_H_
#define _DPP_NP_INIT_H_

#include <linux/pci.h>
#include "zxic_common.h"
#include "dpp_dev.h"

u32 dpp_vport_register(struct dpp_pf_info_t *pf_info, struct pci_dev *p_dev);
u32 dpp_vport_unregister(struct dpp_pf_info_t *pf_info);
u32 dpp_vport_reset(struct dpp_pf_info_t *pf_info);
u32 dpp_dev_status_set(struct dpp_pf_info_t *pf_info, u32 dev_status);
struct dpp_dev_mngr_t *dpp_dev_mgr_get(void);

#endif
