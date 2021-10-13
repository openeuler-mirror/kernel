/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPNIC_LLD_H
#define SPNIC_LLD_H

#include "sphw_crm.h"

struct spnic_lld_dev {
	struct pci_dev *pdev;
	void *hwdev;
};

struct spnic_uld_info {
	/* uld_dev: should not return null even the function capability
	 * is not support the up layer driver
	 * uld_dev_name: NIC driver should copy net device name.
	 * FC driver could copy fc device name.
	 * other up layer driver don`t need copy anything
	 */
	int (*probe)(struct spnic_lld_dev *lld_dev, void **uld_dev,
		     char *uld_dev_name);
	void (*remove)(struct spnic_lld_dev *lld_dev, void *uld_dev);
	int (*suspend)(struct spnic_lld_dev *lld_dev, void *uld_dev,
		       pm_message_t state);
	int (*resume)(struct spnic_lld_dev *lld_dev, void *uld_dev);
	void (*event)(struct spnic_lld_dev *lld_dev, void *uld_dev,
		      struct sphw_event_info *event);
	int (*ioctl)(void *uld_dev, u32 cmd, const void *buf_in, u32 in_size,
		     void *buf_out, u32 *out_size);
};

int spnic_register_uld(enum sphw_service_type type, struct spnic_uld_info *uld_info);

void spnic_unregister_uld(enum sphw_service_type type);

void *spnic_get_uld_dev_by_pdev(struct pci_dev *pdev, enum sphw_service_type type);

void *spnic_get_ppf_uld_by_pdev(struct pci_dev *pdev, enum sphw_service_type type);

int spnic_get_chip_name_by_hwdev(const void *hwdev, char *ifname);

void *spnic_get_uld_dev_by_ifname(const char *ifname, enum sphw_service_type type);

int spnic_get_pf_nic_uld_array(struct pci_dev *pdev, u32 *dev_cnt, void *array[]);

int spnic_get_chip_up_bitmap(struct pci_dev *pdev, bool *is_setted, u8 *valid_up_bitmap);

int spnic_set_chip_up_bitmap(struct pci_dev *pdev, u8 valid_up_bitmap);

bool spnic_get_vf_service_load(struct pci_dev *pdev, u16 service);

int spnic_set_vf_service_load(struct pci_dev *pdev, u16 service, bool vf_srv_load);

int spnic_set_vf_service_state(struct pci_dev *pdev, u16 vf_func_id, u16 service, bool en);

bool spnic_get_vf_load_state(struct pci_dev *pdev);

int spnic_set_vf_load_state(struct pci_dev *pdev, bool vf_load_state);

int spnic_attach_nic(struct spnic_lld_dev *lld_dev);

void spnic_detach_nic(struct spnic_lld_dev *lld_dev);

void lld_hold(void);
void lld_put(void);
void lld_dev_hold(struct spnic_lld_dev *dev);
void lld_dev_put(struct spnic_lld_dev *dev);
struct spnic_lld_dev *spnic_get_lld_dev_by_ifname(const char *ifname);

void *spnic_get_ppf_hwdev_by_pdev(struct pci_dev *pdev);

void spnic_send_event_to_uld(struct pci_dev *pdev, enum sphw_service_type type,
			     struct sphw_event_info *event);
#endif
