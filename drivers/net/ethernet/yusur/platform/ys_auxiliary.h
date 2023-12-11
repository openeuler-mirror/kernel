/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_AUXILIARY_H_
#define __YS_AUXILIARY_H_

#include "ys_utils.h"
#include <linux/auxiliary_bus.h>

#define YS_AUX_DRV(_typename, _probe, _remove, _id_table) { \
	.name = _typename, \
	.probe = _probe, \
	.remove = _remove, \
	.id_table = _id_table \
}

#define AUX_NAME_SF "sf"
#define AUX_NAME_ETH "eth"

enum {
	AUX_TYPE_SF,
	AUX_TYPE_ETH,
};

struct ys_adev {
	struct auxiliary_device adev;
	struct completion comp;
	struct pci_dev *pdev;
	int idx;
	struct list_head list;
	struct net_device *ndev;
	int ndev_type;
	u16 qbase;
	u8 netdev_qnum;
};

struct net_device *ys_aux_match_ndev(struct pci_dev *pdev, int ndev_type,
				     int id);

void ys_aux_del_match_adev(struct pci_dev *pdev, int idx, const char *name);
struct ys_adev *ys_aux_add_adev(struct pci_dev *pdev, int idx,
				const char *name);

int ys_aux_dev_init(struct pci_dev *pdev);
void ys_aux_dev_uninit(struct pci_dev *pdev);
int ys_aux_init(struct auxiliary_driver *adrvs);
void ys_aux_uninit(struct auxiliary_driver *adrvs);

int ys_aux_sf_probe(struct auxiliary_device *adev,
		    const struct auxiliary_device_id *id);
void ys_aux_sf_remove(struct auxiliary_device *adev);
int ys_aux_eth_probe(struct auxiliary_device *adev,
		     const struct auxiliary_device_id *id);
void ys_aux_eth_remove(struct auxiliary_device *adev);

#endif /* __YS_AUXILIARY_H_ */
