/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_SRIOV_SYSFS_H_
#define _NSE_SRIOV_SYSFS_H_

#define VFNAMSIZ 8

struct nse_vf_sysfs_meter_type {
	int	rx_tx; /*flag used to indicate rx or tx*/
	int	xps; /*flag used to indicate pps or bps*/
};

/*both used in sriov/vf_id directory and sriov/vf_id/meters/rx/bps directory*/
struct nse_vf_sysfs {
	struct nse_pf		*pf;
	u16		vf_id;
	struct kobject		kobj;
	union {
		struct nse_vf_sysfs_meters *meters;
		struct nse_vf_sysfs_meter_type meter_type;
	};
};

struct nse_vf_sysfs_meters {
	struct kobject		*kobj;
	struct kobject		*rx_kobj;
	struct kobject		*tx_kobj;
	struct nse_vf_sysfs		meters[4];
};

#ifdef CONFIG_PCI_IOV
int nse_sriov_sysfs_init(struct nse_pf *pf);
void nse_sriov_sysfs_cleanup(struct nse_pf *pf);
int nse_create_vfs_sysfs(struct nse_pf *pf, u16 num_vfs);
void nse_destroy_vfs_sysfs(struct nse_pf *pf);

#else
static inline int nse_sriov_sysfs_init(struct nse_pf *pf) { return 0; }
static inline void nse_sriov_sysfs_cleanup(struct nse_pf *pf) { }
static inline int nse_create_vfs_sysfs(struct nse_pf *pf, u16 num_vfs) { return 0; }
static inline void nse_destroy_vfs_sysfs(struct nse_pf *pf) { }
#endif

#endif
