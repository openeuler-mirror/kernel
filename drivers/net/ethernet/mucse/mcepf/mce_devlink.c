// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include "mce.h"
#include "mce_lib.h"
#include "mce_devlink.h"
#include "mce_eswitch.h"
#include "./mucse_auxiliary/mce_idc.h"
#include "mce_fwchnl.h"

#define MCE_PORT_OPT_DESC_LEN	50

static void mce_devlink_format_version(char *buf, size_t size, u32 version)
{
	snprintf(buf, size, "%u.%u.%u.%u", version >> 24,
		 (version >> 16) & 0xff, (version >> 8) & 0xff,
		 version & 0xff);
}

static int mce_devlink_info_get(struct devlink *devlink,
				struct devlink_info_req *req,
				struct netlink_ext_ack __always_unused *extack)
{
	struct mce_pf *pf = devlink_priv(devlink);
	char serial[3 * sizeof(u64) + 1];
	char version[32];
	u8 dsn[sizeof(u64)];
	u64 dsn_value;
	int err;

	dsn_value = pci_get_dsn(pf->pdev);
	put_unaligned_be64(dsn_value, dsn);
	snprintf(serial, sizeof(serial), "%8phD", dsn);
	err = devlink_info_serial_number_put(req, serial);
	if (err)
		return err;

	mce_devlink_format_version(version, sizeof(version), pf->hw.fw_version);
	err = devlink_info_version_running_put(req,
					       DEVLINK_INFO_VERSION_GENERIC_FW,
					       version);
	if (err)
		return err;

	mce_devlink_format_version(version, sizeof(version),
				   pf->hw.fw_stat.pxe_version);
	return devlink_info_version_running_put(req, "pxe", version);
}

static int mce_devlink_flash_update(struct devlink *devlink,
				    struct devlink_flash_update_params *params,
				    struct netlink_ext_ack __always_unused *extack)
{
	struct mce_pf *pf = devlink_priv(devlink);
	const struct firmware *fw;
	enum REGION_IN region = PART_FW;
	int err;

	if (!params->file_name)
		return -EINVAL;

	if (params->component) {
		if (!strcmp(params->component, "pxe"))
			region = PART_PXE;
		else if (strcmp(params->component, "fw"))
			return -EOPNOTSUPP;
	}

	err = request_firmware_direct(&fw, params->file_name,
				      mce_pf_to_dev(pf));
	if (err)
		return err;

	devlink_flash_update_status_notify(devlink, "Preparing to flash",
					   params->component, 0, 0);
	if ((region == PART_FW && fw->size < 0x20) ||
	    (region == PART_PXE && fw->size < sizeof(u16)))
		err = -EINVAL;
	else
		err = mce_flash_firmware(pf, region, fw->data, fw->size);

	devlink_flash_update_status_notify(devlink,
					   err ? "Flashing failed" : "Flashing done",
					   params->component, 0, 0);
	release_firmware(fw);
	return err;
}

static int mce_devlink_vf_max_ring_get(struct devlink *devlink,
				       u32 __always_unused id,
				       struct devlink_param_gset_ctx *ctx)
{
	struct mce_pf *pf = devlink_priv(devlink);

	ctx->val.vu32 = pf->hw.vf_max_ring;
	return 0;
}

static int mce_devlink_vf_max_ring_set(struct devlink *devlink,
				       u32 __always_unused id,
				       struct devlink_param_gset_ctx *ctx)
{
	struct mce_pf *pf = devlink_priv(devlink);
	int err;

	err = mce_mbx_set_vf_max_queue_cnt(&pf->hw, ctx->val.vu32);
	if (!err)
		pf->hw.vf.ops->init_vf_pcie_totalvfs(&pf->hw,
						 pf->hw.vf_max_ring);
	return err;
}

static int mce_devlink_vf_max_ring_validate(struct devlink *devlink,
					    u32 __always_unused id,
					    union devlink_param_value val,
					    struct netlink_ext_ack *extack)
{
	struct mce_pf *pf = devlink_priv(devlink);
	struct mce_hw *hw = &pf->hw;
	u32 vf_max_ring = val.vu32;

	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "disable SR-IOV before changing vf_max_ring");
		return -EPERM;
	}
	if (vf_max_ring == hw->vf_max_ring) {
		NL_SET_ERR_MSG_MOD(extack, "vf_max_ring is unchanged");
		return -EINVAL;
	}
	if (vf_max_ring < hw->vf_min_ring_cnt ||
	    vf_max_ring > hw->vf_max_ring_cnt ||
	    !is_power_of_2(vf_max_ring)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "vf_max_ring must be a supported power of two");
		return -EINVAL;
	}

	return 0;
}

static const struct devlink_param mce_devlink_params[] = {
	DEVLINK_PARAM_DRIVER(MCE_DEVLINK_PARAM_ID_VF_MAX_RING, "vf_max_ring",
			     DEVLINK_PARAM_TYPE_U32,
			     BIT(DEVLINK_PARAM_CMODE_PERMANENT),
			     mce_devlink_vf_max_ring_get,
			     mce_devlink_vf_max_ring_set,
			     mce_devlink_vf_max_ring_validate),
};

static const struct devlink_ops mce_devlink_ops = {
	.supported_flash_update_params = DEVLINK_SUPPORT_FLASH_UPDATE_COMPONENT,
	.eswitch_mode_get = mce_eswitch_mode_get,
	.eswitch_mode_set = mce_eswitch_mode_set,
	.info_get = mce_devlink_info_get,
	.flash_update = mce_devlink_flash_update,
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
	struct mce_pf *pf;

	devlink = devlink_alloc(&mce_devlink_ops, sizeof(struct mce_pf));
	if (!devlink)
		return NULL;

	/* Add an action to teardown the devlink when unwinding the driver */
	if (devm_add_action(dev, mce_devlink_free, devlink)) {
		devlink_free(devlink);
		return NULL;
	}

	pf = devlink_priv(devlink);
	pf->eswitch_mode = DEVLINK_ESWITCH_MODE_LEGACY;
	return pf;
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

int mce_devlink_create_vf_port(struct mce_pf *pf, int vfid)
{
	struct devlink_port_attrs attrs = {};
	struct devlink_port *devlink_port;
	struct devlink *devlink;
	struct vf_info *vfinfo;
	struct mce_vsi *vsi;
	struct mce_vf *vf;
	int err;

	vf = mce_pf_to_vf(pf);
	vfinfo = &vf->vfinfo[vfid];
	devlink_port = &vfinfo->devlink_port;
	devlink = priv_to_devlink(pf);
	vsi = mce_get_vf_vsi(pf, vfid);
	if (!vsi)
		return -EINVAL;

	attrs.flavour = DEVLINK_PORT_FLAVOUR_PCI_VF;
	attrs.pci_vf.pf = pf->hw.bus.func;
	attrs.pci_vf.vf = vfid;
	devlink_port_attrs_set(devlink_port, &attrs);

	err = devlink_port_register(devlink, devlink_port, vsi->idx);
	if (err) {
		dev_err(mce_pf_to_dev(pf),
			"Failed to create devlink port for VF %d\n", vfid);
		return err;
	}

	return 0;
}

void mce_devlink_destroy_vf_port(struct mce_pf *pf, int vfid)
{
	struct devlink_port *devlink_port;
	struct mce_vf *vf;

	vf = mce_pf_to_vf(pf);
	devlink_port = &vf->vfinfo[vfid].devlink_port;

	devlink_port_type_clear(devlink_port);
	devlink_port_unregister(devlink_port);
}

int mce_devlink_register_params(struct mce_pf *pf)
{
	struct devlink *devlink = priv_to_devlink(pf);
	int err;

	err = devlink_params_register(devlink, mce_devlink_params,
				      ARRAY_SIZE(mce_devlink_params));
	if (err)
		return err;
	devlink_params_publish(devlink);
	return 0;
}

void mce_devlink_unregister_params(struct mce_pf *pf)
{
	struct devlink *devlink = priv_to_devlink(pf);

	devlink_params_unpublish(devlink);
	devlink_params_unregister(devlink, mce_devlink_params,
				  ARRAY_SIZE(mce_devlink_params));
}
