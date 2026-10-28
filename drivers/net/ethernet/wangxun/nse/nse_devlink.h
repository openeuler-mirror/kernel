/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_DEVLINK_H_
#define _NSE_DEVLINK_H_

#if IS_ENABLED(CONFIG_NET_DEVLINK)
struct nse_pf *nse_allocate_pf(struct device *dev);

void nse_devlink_register(struct nse_pf *pf);
void nse_devlink_unregister(struct nse_pf *pf);
int nse_devlink_create_pf_port(struct nse_pf *pf);
void nse_devlink_destroy_pf_port(struct nse_pf *pf);
int nse_devlink_create_vf_port(struct nse_vf *vf);
void nse_devlink_destroy_vf_port(struct nse_vf *vf);
#else /* CONFIG_NET_DEVLINK */
static inline struct nse_pf *nse_allocate_pf(struct device *dev)
{
	return devm_kzalloc(dev, sizeof(struct nse_pf), GFP_KERNEL);
}

static inline void nse_devlink_register(struct nse_pf *pf) { }
static inline void nse_devlink_unregister(struct nse_pf *pf) { }
static inline int nse_devlink_create_pf_port(struct nse_pf *pf) { return 0; }
static inline void nse_devlink_destroy_pf_port(struct nse_pf *pf) { }
static inline int nse_devlink_create_vf_port(struct nse_vf *vf) { return 0; }
static inline void nse_devlink_destroy_vf_port(struct nse_vf *vf) { }
#endif /* !CONFIG_NET_DEVLINK */

#if IS_ENABLED(CONFIG_NET_DEVLINK)
void nse_devlink_init_regions(struct nse_pf *pf);
void nse_devlink_destroy_regions(struct nse_pf *pf);
#else
static inline void nse_devlink_init_regions(struct nse_pf *pf) { }
static inline void nse_devlink_destroy_regions(struct nse_pf *pf) { }
#endif

int nse_devlink_tc_params_register(struct nse_vsi *vsi);
void nse_devlink_tc_params_unregister(struct nse_vsi *vsi);

#endif /* _NSE_DEVLINK_H_ */

