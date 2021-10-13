/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPNIC_DEV_MGMT_H
#define SPNIC_DEV_MGMT_H
#include <linux/types.h>
#include <linux/bitops.h>

#define SPHW_CHIP_NAME	"spnic"

#define SPNIC_VF_PCI_CFG_REG_BAR	0
#define SPNIC_PF_PCI_CFG_REG_BAR	1

#define SPNIC_PCI_INTR_REG_BAR		2
#define SPNIC_PCI_MGMT_REG_BAR		3 /* Only PF have mgmt bar */
#define SPNIC_PCI_DB_BAR		4

/* Structure pcidev private*/
struct spnic_pcidev {
	struct pci_dev *pcidev;
	void *hwdev;
	struct card_node *chip_node;
	struct spnic_lld_dev lld_dev;
	/* Record the service object address,
	 * such as spnic_dev and toe_dev, fc_dev
	 */
	void *uld_dev[SERVICE_T_MAX];
	/* Record the service object name */
	char uld_dev_name[SERVICE_T_MAX][IFNAMSIZ];
	/* It is a the global variable for driver to manage
	 * all function device linked list
	 */
	struct list_head node;

	bool disable_vf_load;
	bool disable_srv_load[SERVICE_T_MAX];

	void __iomem *cfg_reg_base;
	void __iomem *intr_reg_base;
	void __iomem *mgmt_reg_base;
	u64 db_dwqe_len;
	u64 db_base_phy;
	void __iomem *db_base;

	/* lock for attach/detach uld */
	struct mutex pdev_mutex;

	struct spnic_sriov_info sriov_info;

	/* setted when uld driver processing event */
	unsigned long state;
	struct pci_device_id id;

	atomic_t ref_cnt;
};

extern struct list_head g_spnic_chip_list;

extern struct spnic_uld_info g_uld_info[SERVICE_T_MAX];

int alloc_chip_node(struct spnic_pcidev *pci_adapter);

void free_chip_node(struct spnic_pcidev *pci_adapter);

void lld_lock_chip_node(void);

void lld_unlock_chip_node(void);

void spnic_lld_lock_init(void);

void lld_dev_cnt_init(struct spnic_pcidev *pci_adapter);
void wait_lld_dev_unused(struct spnic_pcidev *pci_adapter);

int spnic_get_uld_dev_name(struct spnic_pcidev *dev, enum sphw_service_type type, char *ifname);

void *spnic_get_hwdev_by_pcidev(struct pci_dev *pdev);

#endif
