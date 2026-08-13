// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include "mce.h"
#include "mce_lib.h"
#include "mce_devlink.h"
#include "mce_eswitch.h"
#include "./mucse_auxiliary/mce_idc.h"
#include "mce_fwchnl.h"

#define MCE_PORT_OPT_DESC_LEN	50

static const struct devlink_ops mce_devlink_ops = {
};

static void mce_devlink_free(void *devlink_ptr)
{
	devlink_free((struct devlink *)devlink_ptr);
}

/**
 * mce_allocate_pf - Allocate devlink and return PF structure pointer
 * @dev: the device to allocate for
 *
 * Allocate a devlink instance for this device and return the private area as
 * the PF structure. The devlink memory is kept track of through devres by
 * adding an action to remove it when unwinding.
 * Returns: The result of the operation.
 */
struct mce_pf *mce_allocate_pf(struct device *dev)
{
	struct devlink *devlink;

	devlink = devlink_alloc(&mce_devlink_ops, sizeof(struct mce_pf));
	if (!devlink)
		return NULL;

	/* Add an action to teardown the devlink when unwinding the driver */
	if (devm_add_action(dev, mce_devlink_free, devlink)) {
		devlink_free(devlink);
		return NULL;
	}

	return (struct mce_pf *)devlink_priv(devlink);
}

/**
 * mce_devlink_register - Register devlink interface for this PF
 * @pf: the PF to register the devlink for.
 *
 * Register the devlink instance associated with this physical function.
 *
 * Return: zero on success or an error code on failure.
 */
void mce_devlink_register(struct mce_pf *pf)
{
	struct devlink *devlink = priv_to_devlink(pf);

	devlink_register(devlink, mce_pf_to_dev(pf));
}

/**
 * mce_devlink_unregister - Unregister devlink resources for this PF.
 * @pf: the PF structure to cleanup
 *
 * Releases resources used by devlink and cleans up associated memory.
 */
void mce_devlink_unregister(struct mce_pf *pf)
{
	struct devlink *devlink = priv_to_devlink(pf);

	devlink_unregister(devlink);
}

static void __maybe_unused
mce_devlink_set_switch_id(struct mce_pf *pf, struct netdev_phys_item_id *ppid)
{
	struct pci_dev *pdev = pf->pdev;
	u64 id;

	id = pci_get_dsn(pdev);

	ppid->id_len = sizeof(id);
	put_unaligned_be64(id, &ppid->id);
}

int mce_devlink_register_params(struct mce_pf *pf)
{
	return 0;
}

void mce_devlink_unregister_params(struct mce_pf *pf)
{
}
