/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPFC_LLD_H
#define SPFC_LLD_H

#include "sphw_crm.h"

struct spfc_lld_dev {
	struct pci_dev *pdev;
	void *hwdev;
};

struct spfc_uld_info {
	/* uld_dev: should not return null even the function capability
	 * is not support the up layer driver
	 * uld_dev_name: NIC driver should copy net device name.
	 * FC driver could copy fc device name.
	 * other up layer driver don`t need copy anything
	 */
	int (*probe)(struct spfc_lld_dev *lld_dev, void **uld_dev,
		     char *uld_dev_name);
	void (*remove)(struct spfc_lld_dev *lld_dev, void *uld_dev);
	int (*suspend)(struct spfc_lld_dev *lld_dev, void *uld_dev,
		       pm_message_t state);
	int (*resume)(struct spfc_lld_dev *lld_dev, void *uld_dev);
	void (*event)(struct spfc_lld_dev *lld_dev, void *uld_dev,
		      struct sphw_event_info *event);
	int (*ioctl)(void *uld_dev, u32 cmd, const void *buf_in, u32 in_size,
		     void *buf_out, u32 *out_size);
};

/* Structure pcidev private */
struct spfc_pcidev {
	struct pci_dev *pcidev;
	void *hwdev;
	struct card_node *chip_node;
	struct spfc_lld_dev lld_dev;
	/* such as fc_dev */
	void *uld_dev[SERVICE_T_MAX];
	/* Record the service object name */
	char uld_dev_name[SERVICE_T_MAX][IFNAMSIZ];
	/* It is a the global variable for driver to manage
	 * all function device linked list
	 */
	struct list_head node;
	void __iomem *cfg_reg_base;
	void __iomem *intr_reg_base;
	void __iomem *mgmt_reg_base;
	u64 db_dwqe_len;
	u64 db_base_phy;
	void __iomem *db_base;
	/* lock for attach/detach uld */
	struct mutex pdev_mutex;
	/* setted when uld driver processing event */
	unsigned long state;
	struct pci_device_id id;
	atomic_t ref_cnt;
};

enum spfc_lld_status {
	SPFC_NODE_CHANGE = BIT(0),
};

struct spfc_lld_lock {
	/* lock for chip list */
	struct mutex lld_mutex;
	unsigned long status;
	atomic_t dev_ref_cnt;
};

#ifndef MAX_SIZE
#define MAX_SIZE (16)
#endif

#endif
