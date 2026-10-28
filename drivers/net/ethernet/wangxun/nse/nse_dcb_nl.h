/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_DCB_NL_H_
#define _NSE_DCB_NL_H_

#ifdef CONFIG_DCB
void nse_dcbnl_setup(struct nse_vsi *vsi);
void nse_dcbnl_set_all(struct nse_vsi *vsi);
#else
static inline void nse_dcbnl_setup(struct nse_vsi *vsi) { }
static inline void nse_dcbnl_set_all(struct nse_vsi *vsi) { }
#endif /* CONFIG_DCB */
#endif /* _NSE_DCB_NL_H_ */
