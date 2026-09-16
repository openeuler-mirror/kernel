/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

/* WangXun(R) Ethernet Connection AM Series Linux Driver */

#ifndef _NSE_SIOV_H_
#define _NSE_SIOV_H_

#define NSE_DFLT_QS_PER_SIOV_VF		4

#if IS_ENABLED(CONFIG_VFIO_MDEV) && defined(HAVE_PASID_SUPPORT)
bool nse_is_siov_capable(struct nse_pf *pf);
void nse_initialize_siov_res(struct nse_pf *pf);
void nse_deinit_siov_res(struct nse_pf *pf);
void nse_restore_pasid_config(struct nse_pf *pf, enum nse_reset_req reset_type);
#else
static inline bool nse_is_siov_capable(struct nse_pf *pf)
{
	return false;
}
static inline void nse_initialize_siov_res(struct nse_pf *pf) { }
static inline void nse_deinit_siov_res(struct nse_pf *pf) { }
static inline void nse_restore_pasid_config(struct nse_pf *pf,
					    enum nse_reset_req reset_type) { }
#endif /* CONFIG_VFIO_MDEV && HAVE_PASID_SUPPORT */

#endif /* _NSE_SIOV_H_ */

