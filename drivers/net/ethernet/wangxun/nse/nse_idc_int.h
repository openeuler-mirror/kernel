/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_IDC_INT_H_
#define _NSE_IDC_INT_H_

#include "iidc.h"

#define NSE_MAX_NUM_AUX		4

struct nse_pf;
void nse_send_event_to_auxs(struct nse_pf *pf, struct iidc_event *event);
struct iidc_auxiliary_drv
*nse_get_auxiliary_drv(struct iidc_core_dev_info *cdev_info);
void nse_cdev_info_update_vsi(struct iidc_core_dev_info *cdev_info,
			      struct nse_vsi *vsi);
int nse_unroll_cdev_info(struct iidc_core_dev_info *cdev_info, void *data);
struct iidc_core_dev_info
*nse_find_cdev_info_by_id(struct nse_pf *pf, int cdev_info_id);
void nse_send_vf_reset_to_aux(struct nse_pf *pf, struct iidc_core_dev_info *cdev_info, u16 vf_id);
bool nse_is_rdma_aux_loaded(struct nse_pf *pf);

#endif /* !_NSE_IDC_INT_H_ */
