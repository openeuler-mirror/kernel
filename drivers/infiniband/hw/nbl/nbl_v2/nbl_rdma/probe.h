/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2026, NEBULARMATRIX */

#ifndef NBL_RDMA_PROBE_H
#define NBL_RDMA_PROBE_H

#include <linux/auxiliary_bus.h>

struct nbl_adev;
struct nbl_core_export;
struct nbl_device;
struct nbl_pci_f;
struct pci_dev;

int nbl_init_device_type(struct nbl_pci_f *rf);
void nbl_init_rd_atomic_num(struct nbl_pci_f *rf);
void nbl_get_fw_ver(struct nbl_pci_f *rf);
void nbl_set_hw_attr(struct nbl_pci_f *rf);
void nbl_port_ibevent(struct nbl_device *nbl_dev);
int nbl_ib_register_device(struct nbl_adev *adev,
			   struct nbl_device *nbl_dev);
void nbl_ib_unregister_device(struct nbl_device *nbl_dev);
void nbl_fill_default_cfg(struct nbl_device *nbl_dev);
int nbl_fill_device_info(struct nbl_device *nbl_dev, struct nbl_adev *adev);
int nbl_add_mtu_notifier(struct nbl_device *nbl_dev);
void nbl_remove_mtu_notifier(struct nbl_device *nbl_dev);
void nbl_init_global_cfg(struct nbl_pci_f *rf);
int nbl_register_client(struct nbl_pci_f *rf, bool is_register);
int nbl_channel_init(struct nbl_pci_f *rf);
void nbl_channel_exit(struct nbl_pci_f *rf);
void nbl_confqp_flush(struct nbl_pci_f *rf);
void nbl_rdma_dsch_init(struct nbl_pci_f *rf, bool is_valid);
void nbl_pci_set_atomic(struct nbl_device *nbl_dev, struct pci_dev *pdev);
int nbl_alloc_abnormal_evt_wq(struct nbl_device *nbl_dev);
void nbl_free_abnormal_evt_wq(struct nbl_device *nbl_dev);
int nbl_register_rdma_event_notifiers(struct nbl_device *nbl_dev,
				      struct nbl_core_export *core_info);
void nbl_unregister_rdma_event_notifiers(struct nbl_device *nbl_dev,
					 struct nbl_core_export *core_info);
int nbl_add_netdev_notifier(struct nbl_device *nbl_dev);
void nbl_remove_netdev_notifier(struct nbl_device *nbl_dev);

int nbl_probe_v2(struct auxiliary_device *aux_dev,
		 const struct auxiliary_device_id *id);
void nbl_remove_v2(struct auxiliary_device *adev);

#endif /* NBL_RDMA_PROBE_H */
