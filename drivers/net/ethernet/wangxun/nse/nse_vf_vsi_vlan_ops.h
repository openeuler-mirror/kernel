/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_VF_VSI_VLAN_OPS_H_
#define _NSE_VF_VSI_VLAN_OPS_H_

#include "nse_vsi_vlan_ops.h"

struct nse_vsi;

#ifdef CONFIG_PCI_IOV
void nse_vf_vsi_init_vlan_ops(struct nse_vsi *vsi);
#else
static inline void nse_vf_vsi_init_vlan_ops(struct nse_vsi *vsi) { }
#endif /* CONFIG_PCI_IOV */

#endif /* _NSE_PF_VSI_VLAN_OPS_H_ */
