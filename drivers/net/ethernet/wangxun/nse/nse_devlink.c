// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse.h"
#include "nse_lib.h"
#include "nse_devlink.h"
#include "nse_eswitch.h"

/**
 * nse_devlink_info_get - .info_get devlink handler
 * @devlink: devlink instance structure
 * @req: the devlink info request
 * @extack: extended netdev ack structure
 *
 * Callback for the devlink .info_get operation. Reports information about the
 * device.
 *
 * Return: zero on success or an error code on failure.
 */
static int nse_devlink_info_get(struct devlink *devlink,
				struct devlink_info_req *req,
				struct netlink_ext_ack *extack)
{
	pr_alert("@xzhao - todo-1: devlink_ops->info_get() = %s()\n", __func__);

	return 0;
}

static const struct devlink_ops nse_devlink_ops = {
	.supported_flash_update_params = DEVLINK_SUPPORT_FLASH_UPDATE_OVERWRITE_MASK,
	.eswitch_mode_get = nse_eswitch_mode_get,
	.eswitch_mode_set = nse_eswitch_mode_set,
	.info_get = nse_devlink_info_get,
};

static void nse_devlink_free(void *devlink_ptr)
{
	devlink_free((struct devlink *)devlink_ptr);
}

/**
 * nse_allocate_pf - Allocate devlink and return PF structure pointer
 * @dev: the device to allocate for
 *
 * Allocate a devlink instance for this device and return the private area as
 * the PF structure. The devlink memory is kept track of through devres by
 * adding an action to remove it when unwinding.
 */
struct nse_pf *nse_allocate_pf(struct device *dev)
{
	struct devlink *devlink;

	devlink = devlink_alloc(&nse_devlink_ops, sizeof(struct nse_pf), dev);
	if (!devlink)
		return NULL;

	/* Add an action to teardown the devlink when unwinding the driver */
	if (devm_add_action(dev, nse_devlink_free, devlink)) {
		devlink_free(devlink);
		return NULL;
	}

	return devlink_priv(devlink);
}

/**
 * nse_devlink_register - Register devlink interface for this PF
 * @pf: the PF to register the devlink for.
 *
 * Register the devlink instance associated with this physical function.
 *
 * Return: zero on success or an error code on failure.
 */
void nse_devlink_register(struct nse_pf *pf)
{
	struct devlink *devlink = priv_to_devlink(pf);

	devlink_register(devlink);
}

/**
 * nse_devlink_unregister - Unregister devlink resources for this PF.
 * @pf: the PF structure to cleanup
 *
 * Releases resources used by devlink and cleans up associated memory.
 */
void nse_devlink_unregister(struct nse_pf *pf)
{
	struct devlink *devlink = priv_to_devlink(pf);

	devlink_unregister(devlink);
}

/**
 * nse_devlink_set_switch_id - Set unical switch id based on pci dsn
 * @pf: the PF to create a devlink port for
 * @ppid: struct with switch id information
 */
static void
nse_devlink_set_switch_id(struct nse_pf *pf, struct netdev_phys_item_id *ppid)
{
	struct pci_dev *pdev = pf->pdev;
	u64 id;

	id = pci_get_dsn(pdev);

	ppid->id_len = sizeof(id);
	put_unaligned_be64(id, &ppid->id);
}

/**
 * nse_devlink_create_pf_port - Create a devlink port for this PF
 * @pf: the PF to create a devlink port for
 *
 * Create and register a devlink_port for this PF.
 *
 * Return: zero on success or an error code on failure.
 */
int nse_devlink_create_pf_port(struct nse_pf *pf)
{
	struct devlink_port_attrs attrs = {};
	struct devlink_port *devlink_port;
	struct devlink *devlink;
	struct nse_vsi *vsi;
	struct device *dev;
	int err;

	dev = nse_pf_to_dev(pf);

	devlink_port = &pf->devlink_port;

	vsi = nse_get_main_vsi(pf);
	if (!vsi)
		return -EIO;

	attrs.flavour = DEVLINK_PORT_FLAVOUR_PHYSICAL;
	attrs.phys.port_number = pf->hw.bus.func;

	nse_devlink_set_switch_id(pf, &attrs.switch_id);

	devlink_port_attrs_set(devlink_port, &attrs);
	devlink = priv_to_devlink(pf);

	err = devlink_port_register(devlink, devlink_port, vsi->idx);
	if (err) {
		nse_dev_err_errno(dev, err,
				  "Failed to create devlink port for PF %d",
				  pf->hw.pcore_pf_id);
		return err;
	}

	return 0;
}

/**
 * nse_devlink_destroy_pf_port - Destroy the devlink_port for this PF
 * @pf: the PF to cleanup
 *
 * Unregisters the devlink_port structure associated with this PF.
 */
void nse_devlink_destroy_pf_port(struct nse_pf *pf)
{
	struct devlink_port *devlink_port;

	devlink_port = &pf->devlink_port;

	devlink_port_type_clear(devlink_port);
	devlink_port_unregister(devlink_port);
}

/**
 * nse_devlink_create_vf_port - Create a devlink port for this VF
 * @vf: the VF to create a port for
 *
 * Create and register a devlink_port for this VF.
 *
 * Return: zero on success or an error code on failure.
 */
int nse_devlink_create_vf_port(struct nse_vf *vf)
{
	struct devlink_port_attrs attrs = {};
	struct devlink_port *devlink_port;
	struct devlink *devlink;
	struct nse_vsi *vsi;
	struct device *dev;
	struct nse_pf *pf;
	int err;

	pf = vf->pf;
	dev = nse_pf_to_dev(pf);
	devlink_port = &vf->devlink_port;

	vsi = nse_get_vf_vsi(vf);
	if (!vsi)
		return -EINVAL;

	attrs.flavour = DEVLINK_PORT_FLAVOUR_PCI_VF;
	attrs.pci_vf.pf = pf->hw.bus.func;
	attrs.pci_vf.vf = vf->vf_id;

	nse_devlink_set_switch_id(pf, &attrs.switch_id);

	devlink_port_attrs_set(devlink_port, &attrs);
	devlink = priv_to_devlink(pf);

	err = devlink_port_register(devlink, devlink_port, vsi->idx);
	if (err) {
		nse_dev_err_errno(dev, err,
				  "Failed to create devlink port for VF %d",
				  vf->vf_id);
		return err;
	}

	return 0;
}

/**
 * nse_devlink_destroy_vf_port - Destroy the devlink_port for this VF
 * @vf: the VF to cleanup
 *
 * Unregisters the devlink_port structure associated with this VF.
 */
void nse_devlink_destroy_vf_port(struct nse_vf *vf)
{
	struct devlink_port *devlink_port;

	devlink_port = &vf->devlink_port;

	devlink_port_type_clear(devlink_port);
	devlink_port_unregister(devlink_port);
}

/**
 * nse_devlink_func_caps_snapshot - Capture snapshot of device capabilities
 * @devlink: the devlink instance
 * @ops: the devlink region being snapshotted
 * @extack: extended ACK response structure
 * @data: on exit points to snapshot data buffer
 *
 * This function is called in response to the DEVLINK_CMD_REGION_TRIGGER for
 * the device-caps devlink region. It captures a snapshot of the device
 * capabilities reported by firmware.
 *
 * @returns zero on success, and updates the data pointer. Returns a non-zero
 * error code on failure.
 */
static int
nse_devlink_func_caps_snapshot(struct devlink *devlink,
			     const struct devlink_region_ops __always_unused *ops,
			     struct netlink_ext_ack *extack, u8 **data)
{
	struct nse_pf *pf = devlink_priv(devlink);
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	enum nse_status status;
	u32 cap_elem_count = 0;
	struct nse_aqc_discover_func_caps *aqc_func_caps = NULL;

	aqc_func_caps = vzalloc(NSE_AQ_MAX_BUF_LEN);
	if (!aqc_func_caps)
		return -ENOMEM;

	cap_elem_count = (NSE_AQ_MAX_BUF_LEN - sizeof(__le32)) /
							sizeof(struct nse_aqc_discover_cap_elem);

	aqc_func_caps->count = cpu_to_le32(cap_elem_count);

	status = nse_aq_discover_func_caps(hw, aqc_func_caps, NSE_AQ_MAX_BUF_LEN);
	if (status) {
		dev_dbg(dev, "nse_aq_discover_func_caps: failed to read func capabilities, err %d aq_err %d\n",
			status, hw->adminq.sq_last_status);
		NL_SET_ERR_MSG_MOD(extack, "Failed to read func capabilities");
		vfree(aqc_func_caps);
		return -EIO;
	}

	*data = (u8 *)aqc_func_caps;

	return 0;
}

static const struct devlink_region_ops nse_func_caps_region_ops = {
	.name = "func-caps",
	.destructor = vfree,
	.snapshot = nse_devlink_func_caps_snapshot,
};

/**
 * nse_devlink_init_regions - Initialize devlink regions
 * @pf: the PF device structure
 *
 * Create devlink regions used to enable access to dump the contents of the
 * flash memory on the device.
 */
void nse_devlink_init_regions(struct nse_pf *pf)
{
	struct devlink *devlink = priv_to_devlink(pf);
	struct device *dev = nse_pf_to_dev(pf);

	pf->func_caps_region = devlink_region_create(devlink,
						   &nse_func_caps_region_ops, 10,
						   NSE_AQ_MAX_BUF_LEN);
	if (IS_ERR(pf->func_caps_region)) {
		nse_dev_err_errno(dev, PTR_ERR(pf->func_caps_region),
				  "failed to create device-caps devlink region");
		pf->func_caps_region = NULL;
	}
}

/**
 * nse_devlink_destroy_regions - Destroy devlink regions
 * @pf: the PF device structure
 *
 * Remove previously created regions for this PF.
 */
void nse_devlink_destroy_regions(struct nse_pf *pf)
{
	if (pf->func_caps_region)
		devlink_region_destroy(pf->func_caps_region);
}
