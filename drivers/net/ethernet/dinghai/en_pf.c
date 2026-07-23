// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/pci.h>
#include <linux/aer.h>
#include <linux/dinghai/driver.h>
#include <linux/dinghai/lag.h>
#include <net/devlink.h>
#include <linux/dinghai/devlink.h>
#include <linux/dinghai/helper.h>
#include <linux/dinghai/dh_cmd.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fsnotify.h>
#include <linux/file.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include "en_pf.h"
#include "./en_pf/en_pf_irq.h"
#include "./en_pf/en_pf_eq.h"
#include "./en_pf/en_pf_events.h"
#include "en_aux.h"
#include "en_sf.h"
#include "en_np/init/include/dpp_np_init.h"
#include "en_pf/msg_func.h"
#include "msg_common.h"
#include "slib.h"
#include "en_aux/en_aux_events.h"

#ifdef CONFIG_ZXDH_SF
#include <linux/dinghai/en_sf.h>
#endif

#ifdef DRIVER_VERSION_VAL
#define DRV_VERSION DRIVER_VERSION_VAL
#else
#define DRV_VERSION "1.0-1"
#endif

#define DRV_SUMMARY "ZTE(R) zxdh-net driver"

const char zxdh_pf_driver_version[] = DRV_VERSION;
static const char zxdh_pf_driver_string[] = DRV_SUMMARY;
static const char zxdh_pf_copyright[] = "Copyright (c) 2022-23, ZTE Corporation.";

MODULE_AUTHOR("ZTE Corporation");
MODULE_DESCRIPTION(DRV_SUMMARY);
MODULE_VERSION(DRV_VERSION);
MODULE_LICENSE("Dual BSD/GPL");

__weak int debug_print;
module_param(debug_print, int, 0644);

u32 dh_debug_mask;
struct slot_id_array dh_slot[DPP_PCIE_SLOT_MAX];
module_param_named(debug_mask, dh_debug_mask, uint, 0644);
MODULE_PARM_DESC(debug_mask,
		 "debug mask: 1 = dump cmd data, 2 = dump cmd exec time, 3 = both. Default=0");
static bool probe_vf = 1;
module_param(probe_vf, bool, 0644);
MODULE_PARM_DESC(probe_vf, "probe_vf: 0 = N, 1 = Y");

static const struct pci_device_id dh_pf_pci_table[] = {
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_PF_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_VF_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_BSI_VENDOR_ID, ZXDH_PF_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_BSI_VENDOR_ID, ZXDH_VF_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_INICA_BOND_DEVICE_ID), 0 }, /* bond */
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_INICB_BOND_DEVICE_ID), 0 }, /* bond */
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_INICC_BOND_DEVICE_ID), 0 }, /* bond */
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_DPUA_BOND_DEVICE_ID), 0 }, /* bond */
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_INICA_UPF_BOND_DEVICE_ID), 0 }, /* bond */
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_PF_E310_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_VF_E310_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_PF_E310_CMCC_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_VF_E310_CMCC_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_PF_E312_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_VF_E312_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_PF_DPUB_NOF_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_PF_DPUB_PF_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_PF_DPUB_INITIATOR1_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_PF_DPUB_INITIATOR2_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_PF_DPUB_RDMA_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_VF_DPUB_RDMA_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_UPF_PF_I512_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_UPF_VF_I512_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_INICA_RDMA_PF_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_INICA_RDMA_VF_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_PF_E316_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_VF_E316_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_E316_XPU_VENDER_ID, ZXDH_PF_E316_XPU_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_E316_XPU_VENDER_ID, ZXDH_VF_E316_XPU_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_PF_E311_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_VF_E311_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_PF_I511_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_VF_I511_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_INICD_BOND0_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_INICD_BOND1_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_INICD_NE0_PF_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_INICD_NE0_VF_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_INICD_NE1_PF_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_INICD_NE1_VF_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_INICD_NE2_PF_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_INICD_NE2_VF_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_PF_E310_RDMA_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_VF_E310_RDMA_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_PF_E310S_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_VF_E310S_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_PF_E312S_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_VF_E312S_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_PF_DPUB_SRIOV0_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_PF_DPUB_SRIOV1_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_PF_I510_SRIOV_SEC_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_VF_I510_SRIOV_SEC_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_PF_E312_RDMA_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_VF_E312_RDMA_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_PF_INICA_OFFLOAD_DEVICE_ID), 0 },
	{ PCI_DEVICE(CTC_PF_VENDOR_ID, CTC_PF_B512Y_DEVICE_ID), 0 },
	{ PCI_DEVICE(CTC_PF_VENDOR_ID, CTC_VF_B512Y_DEVICE_ID), 0 },
	{ PCI_DEVICE(CTC_PF_VENDOR_ID, CTC_PF_B522Y_DEVICE_ID), 0 },
	{ PCI_DEVICE(CTC_PF_VENDOR_ID, CTC_VF_B522Y_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_PF_E312S_D_DEVICE_ID), 0 },
	{ PCI_DEVICE(ZXDH_PF_VENDOR_ID, ZXDH_VF_E312S_D_DEVICE_ID), 0 },
	{
		0,
	}
};

MODULE_DEVICE_TABLE(pci, dh_pf_pci_table);

static s32 set_rp_cpl_timeout_mask_status(struct pci_dev *pdev, u32 status)
{
	struct pci_dev *rp_dev = NULL;
	int aer = 0;
	u32 data = 0;

	rp_dev = pcie_find_root_port(pdev);
	if (!rp_dev) {
		LOG_ERR("Can not find RP\n");
		return -ENODEV;
	}

	aer = pci_find_ext_capability(rp_dev, PCI_EXT_CAP_ID_ERR);
	if (!aer) {
		LOG_ERR("Can not find RP AER CAP\n");
		return -ENXIO;
	}

	pci_read_config_dword(rp_dev, aer + PCI_ERR_UNCOR_MASK, &data);

	if (status)
		data |= PCI_ERR_UNC_COMP_TIME;
	else
		data &= ~PCI_ERR_UNC_COMP_TIME;

	pci_write_config_dword(rp_dev, aer + PCI_ERR_UNCOR_MASK, data);

	return 0;
}

static s32 zxdh_pf_set_cpl_timeout_mask(struct dh_core_dev *dev, u32 mask)
{
	return set_rp_cpl_timeout_mask_status(dev->pdev, mask);
}

static s32 get_rp_cpl_timeout_mask_status(struct pci_dev *pdev)
{
	struct pci_dev *rp_dev = NULL;
	int aer = 0;
	u32 data = 0;

	rp_dev = pcie_find_root_port(pdev);
	if (!rp_dev) {
		LOG_ERR("Can not find RP\n");
		return -ENODEV;
	}

	aer = pci_find_ext_capability(rp_dev, PCI_EXT_CAP_ID_ERR);
	if (!aer) {
		LOG_ERR("Can not find RP AER CAP\n");
		return -ENXIO;
	}

	pci_read_config_dword(rp_dev, aer + PCI_ERR_UNCOR_MASK, &data);

	return (data & PCI_ERR_UNC_COMP_TIME) ? 1 : 0;
}

static s32 zxdh_pf_get_cpl_timeout_if_mask(struct dh_core_dev *dev)
{
	return get_rp_cpl_timeout_mask_status(dev->pdev);
}

s32 set_rp_hp_irq_ctrl(struct pci_dev *pdev, u32 status)
{
	struct pci_dev *rp_dev = NULL;
	int express = 0;
	u32 data = 0;

	rp_dev = pcie_find_root_port(pdev);
	if (!rp_dev) {
		LOG_ERR("Can not find RP\n");
		return -ENODEV;
	}

	express = pci_find_capability(rp_dev, PCI_CAP_ID_EXP);
	if (!express) {
		LOG_ERR("Can not find RP EXPRESS CAP\n");
		return -ENXIO;
	}

	pci_read_config_dword(rp_dev, express + PCI_EXP_SLTCTL, &data);

	if (status)
		data |= PCI_EXP_SLTCTL_HPIE;
	else
		data &= ~PCI_EXP_SLTCTL_HPIE;

	pci_write_config_dword(rp_dev, express + PCI_EXP_SLTCTL, data);

	return 0;
}

s32 zxdh_pf_set_hp_irq_ctrl_status(struct dh_core_dev *dev, u32 status)
{
	return set_rp_hp_irq_ctrl(dev->pdev, status);
}

s32 get_rp_hp_irq_ctrl_status(struct pci_dev *pdev)
{
	struct pci_dev *rp_dev = NULL;
	u32 data = 0;
	int express = 0;

	rp_dev = pcie_find_root_port(pdev);
	if (!rp_dev) {
		LOG_ERR("Can not find RP\n");
		return -ENODEV;
	}

	express = pci_find_capability(rp_dev, PCI_CAP_ID_EXP);
	if (!express) {
		LOG_ERR("Can not find RP EXPRESS CAP\n");
		return -ENXIO;
	}

	pci_read_config_dword(rp_dev, express + PCI_EXP_SLTCTL, &data);

	return (data & PCI_EXP_SLTCTL_HPIE) ? 1 : 0;
}

s32 zxdh_pf_get_hp_irq_ctrl_status(struct dh_core_dev *dev)
{
	return get_rp_hp_irq_ctrl_status(dev->pdev);
}

s32 zxdh_pf_rp_config_init(struct dh_core_dev *dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dev);
	s32 err = 0;

	err = zxdh_pf_pcie_config_store(dev);
	if (err)
		return err;

	zxdh_pf_set_cpl_timeout_mask(dev, 1);

	if (pf_dev->board_type == DH_STD_E312S || pf_dev->board_type == DH_STD_E312S_D) {
		LOG_INFO("hp_irq no change\n");
		return 0;
	}

	zxdh_pf_set_hp_irq_ctrl_status(dev, 0);
	return 0;
}

static bool zxdh_pf_get_rp_link_status(struct dh_core_dev *dev)
{
	struct pci_dev *rp_dev = NULL;
	int pcie_cap = 0;
	u16 data = 0;

	rp_dev = pcie_find_root_port(dev->pdev);
	if (!rp_dev) {
		LOG_ERR("Can not find RP\n");
		return false;
	}

	pcie_cap = pci_find_capability(rp_dev, PCI_CAP_ID_EXP);
	if (!pcie_cap) {
		LOG_ERR("Can not find PCI Express CAP\n");
		return false;
	}

	pci_read_config_word(rp_dev, pcie_cap + PCI_EXP_LNKSTA, &data);
	return (data & PCI_EXP_LNKSTA_DLLLA) ? true : false;
}

static bool zxdh_pf_get_upstream_port_link_status(struct dh_core_dev *dev)
{
	struct pci_dev *up_stream_dev = NULL;
	int pcie_cap = 0;
	u16 data = 0;

	up_stream_dev = pci_upstream_bridge(dev->pdev);
	if (!up_stream_dev) {
		LOG_ERR("Can not find RP\n");
		return false;
	}
	pcie_cap = pci_find_capability(up_stream_dev, PCI_CAP_ID_EXP);
	if (!pcie_cap) {
		LOG_ERR("Can not find PCI Express CAP\n");
		return false;
	}
	pci_read_config_word(up_stream_dev, pcie_cap + PCI_EXP_LNKSTA, &data);
	return (data & PCI_EXP_LNKSTA_DLLLA) ? true : false;
}

static bool zxdh_pf_check_remove_state(struct dh_core_dev *dev)
{
	if (!zxdh_pf_get_rp_link_status(dev))
		return false;

	return zxdh_pf_get_upstream_port_link_status(dev);
}

s32 dh_pf_pci_init(struct dh_core_dev *dev)
{
	s32 ret = 0;
	struct zxdh_pf_device *pf_dev = NULL;

	pci_set_drvdata(dev->pdev, dev);

	ret = pci_enable_device(dev->pdev);
	if (ret != 0) {
		LOG_ERR("pci_enable_device failed: %d\n", ret);
		return ret;
	}

	ret = dma_set_mask_and_coherent(dev->device, DMA_BIT_MASK(64));
	if (ret != 0) {
		ret = dma_set_mask_and_coherent(dev->device, DMA_BIT_MASK(32));
		if (ret != 0) {
			LOG_ERR("dma_set_mask_and_coherent failed: %d\n", ret);
			goto err_pci;
		}
	}

	ret = pci_request_selected_regions(dev->pdev, pci_select_bars(dev->pdev, IORESOURCE_MEM),
					   "dh-pf");
	if (ret != 0) {
		LOG_ERR("pci_request_selected_regions failed: %d\n", ret);
		goto err_pci;
	}

	pci_enable_pcie_error_reporting(dev->pdev);
	pci_set_master(dev->pdev);
	ret = pci_save_state(dev->pdev);
	if (ret != 0) {
		LOG_ERR("pci_save_state failed: %d\n", ret);
		goto err_pci_save_state;
	}

	pf_dev = dh_core_priv(dev);
	pf_dev->pci_ioremap_addr[0] = (u64)(uintptr_t)pci_iomap(dev->pdev, 0, 0);
	if (pf_dev->pci_ioremap_addr[0] == 0) {
		ret = -ENOMEM;
		LOG_ERR("pci_iomap(bar 0) failed\n");
		goto err_pci_save_state;
	}

	return 0;

err_pci_save_state:
	pci_disable_pcie_error_reporting(dev->pdev);
	pci_release_selected_regions(dev->pdev, pci_select_bars(dev->pdev, IORESOURCE_MEM));
err_pci:
	pci_disable_device(dev->pdev);
	return ret;
}

void dh_pf_pci_close(struct dh_core_dev *dev)
{
	struct zxdh_pf_device *pf_dev = NULL;

	pf_dev = dh_core_priv(dev);
	pci_iounmap(dev->pdev, (void __iomem *)(uintptr_t)pf_dev->pci_ioremap_addr[0]);
	pci_disable_pcie_error_reporting(dev->pdev);
	pci_release_selected_regions(dev->pdev, pci_select_bars(dev->pdev, IORESOURCE_MEM));
	pci_disable_device(dev->pdev);
}

s32 zxdh_pf_pci_find_capability(struct pci_dev *pdev, u8 cfg_type, u32 ioresource_types, s32 *bars)
{
	s32 pos = 0;
	u8 type = 0;
	u8 bar = 0;

	for (pos = pci_find_capability(pdev, PCI_CAP_ID_VNDR); pos > 0;
	     pos = pci_find_next_capability(pdev, pos, PCI_CAP_ID_VNDR)) {
		pci_read_config_byte(pdev, pos + offsetof(struct zxdh_pf_pci_cap, cfg_type), &type);
		pci_read_config_byte(pdev, pos + offsetof(struct zxdh_pf_pci_cap, bar), &bar);

		/* ignore structures with reserved BAR values */
		if (bar > ZXDH_PF_MAX_BAR_VAL)
			continue;

		if (type == cfg_type) {
			if (pci_resource_len(pdev, bar) &&
			    pci_resource_flags(pdev, bar) & ioresource_types) {
				*bars |= (1 << bar);
				return pos;
			}
		}
	}

	return 0;
}

void __iomem *zxdh_pf_map_capability(struct dh_core_dev *dh_dev, s32 off, size_t minlen, u32 align,
				     u32 start, u32 size, size_t *len, resource_size_t *pa,
				     u32 *bar_off)
{
	struct pci_dev *pdev = dh_dev->pdev;
	u8 bar = 0;
	u32 offset = 0;
	u32 length = 0;
	void __iomem *p = NULL;

	pci_read_config_byte(pdev, off + offsetof(struct zxdh_pf_pci_cap, bar), &bar);
	pci_read_config_dword(pdev, off + offsetof(struct zxdh_pf_pci_cap, offset), &offset);
	pci_read_config_dword(pdev, off + offsetof(struct zxdh_pf_pci_cap, length), &length);

	if (bar_off)
		*bar_off = offset;

	if (length <= start) {
		LOG_ERR("bad capability len %u (>%u expected)\n", length, start);
		return NULL;
	}

	if (length - start < minlen) {
		LOG_ERR("bad capability len %u (>=%zu expected)\n", length, minlen);
		return NULL;
	}

	length -= start;
	if (start + offset < offset) {
		LOG_ERR("map wrap-around %u+%u\n", start, offset);
		return NULL;
	}

	offset += start;
	if (offset & (align - 1)) {
		LOG_ERR("offset %u not aligned to %u\n", offset, align);
		return NULL;
	}

	if (length > size)
		length = size;

	if (len)
		*len = length;

	if (minlen + offset < minlen || minlen + offset > pci_resource_len(pdev, bar)) {
		LOG_ERR("map custom queue %zu@%u out of range on bar %i length %lu\n", minlen,
			offset, bar, (unsigned long)pci_resource_len(pdev, bar));
		return NULL;
	}

	p = pci_iomap_range(pdev, bar, offset, length);
	if (unlikely(!p))
		LOG_ERR("unable to map custom queue %u@%u on bar %i\n", length, offset, bar);
	if (pa)
		*pa = pci_resource_start(pdev, bar) + offset;

	return p;
}

s32 zxdh_pf_common_cfg_init(struct dh_core_dev *dh_dev)
{
	s32 common = 0;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct pci_dev *pdev = dh_dev->pdev;

	/* check for a common config: if not, use legacy mode (bar 0). */
	common = zxdh_pf_pci_find_capability(pdev, ZXDH_PCI_CAP_COMMON_CFG,
					     IORESOURCE_IO | IORESOURCE_MEM, &pf_dev->modern_bars);
	if (common == 0) {
		LOG_ERR("missing capabilities %i, leaving for legacy driver\n", common);
		return -ENODEV;
	}

	pf_dev->common = zxdh_pf_map_capability(
		dh_dev, common, sizeof(struct zxdh_pf_pci_common_cfg), ZXDH_PF_ALIGN4, 0,
		sizeof(struct zxdh_pf_pci_common_cfg), NULL, NULL, NULL);
	if (unlikely(!pf_dev->common)) {
		LOG_ERR("pf_dev->common is null\n");
		return -EINVAL;
	}

	return 0;
}

s32 zxdh_pf_notify_cfg_init(struct dh_core_dev *dh_dev)
{
	s32 notify = 0;
	u32 notify_length = 0;
	u32 notify_offset = 0;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct pci_dev *pdev = dh_dev->pdev;

	/* If common is there, these should be too... */
	notify = zxdh_pf_pci_find_capability(pdev, ZXDH_PCI_CAP_NOTIFY_CFG,
					     IORESOURCE_IO | IORESOURCE_MEM, &pf_dev->modern_bars);
	if (notify == 0) {
		LOG_ERR("missing capabilities %i\n", notify);
		return -EINVAL;
	}

	pci_read_config_dword(
		pdev, notify + offsetof(struct zxdh_pf_pci_notify_cap, notify_off_multiplier),
		&pf_dev->notify_offset_multiplier);
	pci_read_config_dword(pdev, notify + offsetof(struct zxdh_pf_pci_notify_cap, cap.length),
			      &notify_length);
	pci_read_config_dword(pdev, notify + offsetof(struct zxdh_pf_pci_notify_cap, cap.offset),
			      &notify_offset);

	if ((u64)notify_length + (notify_offset % PAGE_SIZE) <= PAGE_SIZE) {
		pf_dev->notify_base = zxdh_pf_map_capability(dh_dev, notify, ZXDH_PF_MAP_MINLEN2,
							     ZXDH_PF_ALIGN2, 0, notify_length,
							     &pf_dev->notify_len,
							     &pf_dev->notify_pa, NULL);
		if (unlikely(!pf_dev->notify_base)) {
			LOG_ERR("pf_dev->notify_base is null\n");
			return -EINVAL;
		}
	} else {
		pf_dev->notify_map_cap = notify;
	}

	return 0;
}

s32 zxdh_pf_device_cfg_init(struct dh_core_dev *dh_dev)
{
	s32 device = 0;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct pci_dev *pdev = dh_dev->pdev;

	device = zxdh_pf_pci_find_capability(pdev, ZXDH_PCI_CAP_DEVICE_CFG,
					     IORESOURCE_IO | IORESOURCE_MEM, &pf_dev->modern_bars);

	if (device) {
		pf_dev->device = zxdh_pf_map_capability(dh_dev, device, 0, ZXDH_PF_ALIGN4, 0,
							PAGE_SIZE, &pf_dev->device_len, NULL,
							&pf_dev->dev_cfg_bar_off);
		if (unlikely(!pf_dev->device)) {
			LOG_ERR("pf_dev->device is null\n");
			return -EINVAL;
		}
	}
	return 0;
}

void zxdh_pf_modern_cfg_uninit(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct pci_dev *pdev = dh_dev->pdev;

	if (pf_dev->device)
		pci_iounmap(pdev, pf_dev->device);
	if (pf_dev->notify_base)
		pci_iounmap(pdev, pf_dev->notify_base);
	pci_iounmap(pdev, pf_dev->common);
}

s32 zxdh_pf_modern_cfg_init(struct dh_core_dev *dh_dev)
{
	s32 ret = 0;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct pci_dev *pdev = dh_dev->pdev;

	ret = zxdh_pf_common_cfg_init(dh_dev);
	if (ret != 0) {
		LOG_ERR("zxdh_pf_common_cfg_init failed: %d\n", ret);
		return -EINVAL;
	}

	ret = zxdh_pf_notify_cfg_init(dh_dev);
	if (ret != 0) {
		LOG_ERR("zxdh_pf_notify_cfg_init failed: %d\n", ret);
		goto err_map_notify;
	}

	ret = zxdh_pf_device_cfg_init(dh_dev);
	if (ret != 0) {
		LOG_ERR("zxdh_pf_device_cfg_init failed: %d\n", ret);
		goto err_map_device;
	}

	return 0;

err_map_device:
	if (pf_dev->notify_base)
		pci_iounmap(pdev, pf_dev->notify_base);
err_map_notify:
	pci_iounmap(pdev, pf_dev->common);
	return -EINVAL;
}

u16 zxdh_pf_get_queue_notify_off(struct dh_core_dev *dh_dev, u16 index)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	iowrite16(index, &pf_dev->common->queue_select);

	return ioread16(&pf_dev->common->queue_notify_off);
}

void __iomem *zxdh_pf_map_vq_notify(struct dh_core_dev *dh_dev, u32 index, resource_size_t *pa)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	u16 off = 0;

	off = zxdh_pf_get_queue_notify_off(dh_dev, index);

	if (pf_dev->notify_base) {
		/* offset should not wrap */
		if ((u64)off * pf_dev->notify_offset_multiplier + 2 > pf_dev->notify_len) {
			LOG_ERR("bad notification offset %u (x %u) for queue %u > %zd", off,
				pf_dev->notify_offset_multiplier, index, pf_dev->notify_len);
			return NULL;
		}

		if (pa)
			*pa = pf_dev->notify_pa + off * pf_dev->notify_offset_multiplier;

		return pf_dev->notify_base + off * pf_dev->notify_offset_multiplier;
	} else {
		return zxdh_pf_map_capability(dh_dev, pf_dev->notify_map_cap, 2, 2,
					      off * pf_dev->notify_offset_multiplier, 2, NULL, pa,
					      NULL);
	}
}

void zxdh_pf_unmap_vq_notify(struct dh_core_dev *dh_dev, void *priv)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	if (!pf_dev->notify_base)
		pci_iounmap(dh_dev->pdev, priv);
}

void zxdh_pf_set_status(struct dh_core_dev *dh_dev, u8 status)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	iowrite8(status, &pf_dev->common->device_status);
}

u8 zxdh_pf_get_status(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	return ioread8(&pf_dev->common->device_status);
}

static u8 zxdh_pf_get_cfg_gen(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	u8 config_generation = 0;

	config_generation = ioread8(&pf_dev->common->config_generation);
	LOG_INFO("config_generation is %d\n", config_generation);

	return config_generation;
}

static u8 zxdh_pf_wait_bar_ok(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	u8 config_generation = 0;
	u8 i = 0;

	for (i = 0; i < 20; i++) {
		config_generation = ioread8(&pf_dev->common->config_generation);

		if (!config_generation) {
			LOG_INFO("wait %ds, config_generation is %d\n", i, config_generation);
			return 0;
		}

		msleep(1000);
	}

	return -ETIMEDOUT;
}

void zxdh_pf_get_vf_mac(struct dh_core_dev *dh_dev, u8 *mac, s32 vf_id)
{
	u32 DEV_MAC_L = 0;
	u16 DEV_MAC_H = 0;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	if (pf_dev->pf_sriov_cap_base) {
		DEV_MAC_L = ioread32((void __iomem *)(pf_dev->pf_sriov_cap_base +
						      (pf_dev->sriov_bar_size) * vf_id +
						      pf_dev->dev_cfg_bar_off));
		mac[0] = DEV_MAC_L & 0xff;
		mac[1] = (DEV_MAC_L >> 8) & 0xff;
		mac[2] = (DEV_MAC_L >> 16) & 0xff;
		mac[3] = (DEV_MAC_L >> 24) & 0xff;
		DEV_MAC_H = ioread16((void __iomem *)(pf_dev->pf_sriov_cap_base +
						      (pf_dev->sriov_bar_size) * vf_id +
						      pf_dev->dev_cfg_bar_off +
						      ZXDH_DEV_MAC_HIGH_OFFSET));
		mac[4] = DEV_MAC_H & 0xff;
		mac[5] = (DEV_MAC_H >> 8) & 0xff;
	}
}

void zxdh_pf_set_vf_mac_reg(struct zxdh_pf_device *pf_dev, u8 *mac, s32 vf_id)
{
	u32 DEV_MAC_L = 0;
	u16 DEV_MAC_H = 0;

	if (pf_dev->pf_sriov_cap_base) {
		DEV_MAC_L = mac[0] | (mac[1] << 8) | (mac[2] << 16) | (mac[3] << 24);
		DEV_MAC_H = mac[4] | (mac[5] << 8);
		iowrite32(DEV_MAC_L, (void __iomem *)(pf_dev->pf_sriov_cap_base +
						      (pf_dev->sriov_bar_size) * vf_id +
						      pf_dev->dev_cfg_bar_off));
		iowrite16(DEV_MAC_H,
			  (void __iomem *)(pf_dev->pf_sriov_cap_base +
					   (pf_dev->sriov_bar_size) * vf_id +
					   pf_dev->dev_cfg_bar_off + ZXDH_DEV_MAC_HIGH_OFFSET));
	}
}

void zxdh_pf_set_vf_mac(struct dh_core_dev *dh_dev, u8 *mac, s32 vf_id)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	zxdh_pf_set_vf_mac_reg(pf_dev, mac, vf_id);
}

void zxdh_set_mac(struct dh_core_dev *dh_dev, u8 *mac)
{
	u32 DEV_MAC_L = 0;
	u16 DEV_MAC_H = 0;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	DEV_MAC_L = mac[0] | (mac[1] << 8) | (mac[2] << 16) | (mac[3] << 24);
	DEV_MAC_H = mac[4] | (mac[5] << 8);
	iowrite32(DEV_MAC_L, pf_dev->device);
	iowrite16(DEV_MAC_H, (void __iomem *)((u8 *)pf_dev->device + ZXDH_DEV_MAC_HIGH_OFFSET));
}

void zxdh_get_mac(struct dh_core_dev *dh_dev, u8 *mac)
{
	u32 DEV_MAC_L = 0;
	u16 DEV_MAC_H = 0;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	DEV_MAC_L = ioread32(pf_dev->device);
	mac[0] = DEV_MAC_L & 0xff;
	mac[1] = (DEV_MAC_L >> 8) & 0xff;
	mac[2] = (DEV_MAC_L >> 16) & 0xff;
	mac[3] = (DEV_MAC_L >> 24) & 0xff;
	DEV_MAC_H = ioread16((void __iomem *)((u8 *)pf_dev->device + ZXDH_DEV_MAC_HIGH_OFFSET));
	mac[4] = DEV_MAC_H & 0xff;
	mac[5] = (DEV_MAC_H >> 8) & 0xff;
}

u64 zxdh_pf_get_features(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	u64 device_feature = 0;

	iowrite32(0, &pf_dev->common->device_feature_select);
	device_feature = ioread32(&pf_dev->common->device_feature);
	iowrite32(1, &pf_dev->common->device_feature_select);
	device_feature |= ((u64)ioread32(&pf_dev->common->device_feature) << 32);

	return device_feature;
}

void zxdh_pf_set_features(struct dh_core_dev *dh_dev, u64 features)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	iowrite32(0, &pf_dev->common->guest_feature_select);
	iowrite32((u32)features, &pf_dev->common->guest_feature);
	iowrite32(1, &pf_dev->common->guest_feature_select);
	iowrite32(features >> 32, &pf_dev->common->guest_feature);
}

void zxdh_pf_set_queue_enable(struct dh_core_dev *dh_dev, u16 index, bool enable)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	iowrite16(index, &pf_dev->common->queue_select);
	iowrite16(enable, &pf_dev->common->queue_enable);
}

u16 zxdh_pf_get_epbdf(struct dh_core_dev *dh_dev)
{
	struct pci_dev *pdev = dh_dev->pdev;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	u32 domain = 0;
	u32 bus = 0;
	u32 devid = 0;
	u32 function = 0;

	if (!pdev) {
		LOG_ERR("err: pdev null, return epbdf data 0.\n");
		return 0;
	}

	if (sscanf(pci_name(pdev), "%x:%x:%x.%u", &domain, &bus, &devid, &function) != 4) {
		LOG_ERR("failed to get pcie bus-info\n");
		return 0;
	}
	pf_dev->epbdf = BDF_ECAM(bus, devid, function);
	return pf_dev->epbdf;
}

u64 zxdh_pf_get_spec_sbdf(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	return pf_dev->spec_sbdf;
}

bool zxdh_pf_is_multi_ep(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	return pf_dev->is_multi_ep;
}

u32 zxdh_pf_get_rp_sbdf(struct dh_core_dev *dh_dev)
{
	struct pci_dev *pdev = dh_dev->pdev;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct pci_dev *rp_pdev = NULL;
	struct pci_dev *uppder_pdev = NULL;
	u32 domain = 0;
	u32 bus = 0;
	u32 devid = 0;
	u32 function = 0;

	if (!pdev) {
		LOG_ERR("err: pdev null, return epbdf data 0\n");
		return 0;
	}

	uppder_pdev = pci_upstream_bridge(pdev);
	if (!uppder_pdev) {
		LOG_ERR("err: uppder_pdev null, return rp_sbdf data 0\n");
		return 0;
	}

	if (uppder_pdev->vendor == ZXDH_PF_VENDOR_ID &&
	    uppder_pdev->device == ZXDH_SWITCH_DEVICE_ID) {
		uppder_pdev = pci_upstream_bridge(uppder_pdev);
		if (!uppder_pdev) {
			LOG_ERR("err: uppder_pdev null, return rp_sbdf data 0\n");
			return 0;
		}

		uppder_pdev = pci_upstream_bridge(uppder_pdev);
		if (!uppder_pdev) {
			LOG_ERR("err: uppder_pdev null, return rp_sbdf data 0\n");
			return 0;
		}
		rp_pdev = uppder_pdev;
		pf_dev->is_multi_ep = true;
	} else {
		rp_pdev = uppder_pdev;
		pf_dev->is_multi_ep = false;
	}

	if (sscanf(pci_name(rp_pdev), "%x:%x:%x.%u", &domain, &bus, &devid, &function) != 4) {
		LOG_ERR("failed to get pcie rp bus-info\n");
		return 0;
	}

	pf_dev->rp_sbdf = SBDF_ECAM(domain, bus, devid, function);
	LOG_INFO("rp: domain %#x, bus %#x, devid %#x, function %#x, rp_sbdf %#x. is_multi_ep: %d\n",
		 domain, bus, devid, function, pf_dev->rp_sbdf, pf_dev->is_multi_ep);

	return pf_dev->rp_sbdf;
}

int zxdh_pf_get_pannel_port_num(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	return pf_dev->pannel_port_num;
}

u16 zxdh_pf_get_vport(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	return pf_dev->vport;
}

enum dh_coredev_type zxdh_pf_get_coredev_type(struct dh_core_dev *dh_dev)
{
	return dh_dev->coredev_type;
}

u16 zxdh_pf_get_pcie_id(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	return pf_dev->pcie_id;
}

static u16 zxdh_pf_get_slot_id(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	u16 slot_id = 0;
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	if (dh_dev->coredev_type == DH_COREDEV_PF)
		return pf_dev->slot_id;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (unlikely(!msg)) {
		LOG_ERR("failed to kzalloc\n");
		return 0;
	}

	msg->payload.hdr.op_code = ZXDH_VF_SLOT_ID_GET;

	err = zxdh_pf_msg_send_cmd(dh_dev, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (err != 0) {
		LOG_ERR("send_msg_to_pf failed, err: %d\n", err);
		kfree(msg);
		return 0;
	}
	slot_id = msg->reps.slot_info.slot_id;
	kfree(msg);

	return slot_id;
}

bool zxdh_pf_is_special_bond(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct firmware_capability *fwcap = &pf_dev->fwcap;

	if (FW_FEATURE_GET(fwcap->fw_feature, FW_FEATURE_STD) == 1)
		return true;

	return false;
}

bool zxdh_pf_suport_np_ext_stats(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct firmware_capability *fwcap = &pf_dev->fwcap;

	if (FW_FEATURE_GET(fwcap->fw_feature, FW_FEATURE_NPSTAT) == 1)
		return true;

	return false;
}

static bool zxdh_pf_is_fw_feature_support(struct dh_core_dev *dh_dev, u32 feature)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct firmware_capability *fwcap = &pf_dev->fwcap;

	if (FW_FEATURE_GET(fwcap->fw_feature, feature) == 1)
		return true;

	return false;
}

struct zxdh_np_ext_stats *zxdh_get_np_ext_stats(struct dh_core_dev *dh_dev, u8 panel_id)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	u32 err_offset = 0;
	u32 disc_offset = 0;
	struct zxdh_np_ext_stats *ext_stats = &pf_dev->np_ext_stats;
	void __iomem *err_addr = NULL;
	void __iomem *disc_addr = NULL;
	u32 err_cnt = 0;
	u32 disc_cnt = 0;

	err_offset = 2 * pf_dev->phy_port * sizeof(u32);
	disc_offset = (2 * pf_dev->phy_port + 1) * sizeof(u32);

	err_addr = (void __iomem *)(uintptr_t)(pf_dev->pci_ioremap_addr[0] +
					       ZXDH_NP_EXT_STATS_OFFSET + err_offset);
	disc_addr = (void __iomem *)(uintptr_t)(pf_dev->pci_ioremap_addr[0] +
						ZXDH_NP_EXT_STATS_OFFSET + disc_offset);
	if ((err_addr >=
	     (void __iomem *)(uintptr_t)(pf_dev->pci_ioremap_addr[0] + ZXDH_NP_EXT_STATS_OFFSET +
					 ZXDH_NP_EXT_STATS_SIZE)) ||
	    (disc_addr >=
	     (void __iomem *)(uintptr_t)(pf_dev->pci_ioremap_addr[0] + ZXDH_NP_EXT_STATS_OFFSET +
					 ZXDH_NP_EXT_STATS_SIZE))) {
		LOG_ERR("addr out-off rang, err_addr: %llx\n",
			(unsigned long long)(uintptr_t)err_addr);
		LOG_ERR("addr out-off rang, disc_addr: %llx\n",
			(unsigned long long)(uintptr_t)disc_addr);
		return NULL;
	}

	err_cnt = ioread32((void __iomem *)err_addr);
	disc_cnt = ioread32((void __iomem *)disc_addr);

	ext_stats->rx_vport2np_packets = err_cnt + disc_cnt;

	return ext_stats;
}

bool zxdh_pf_is_bond(struct dh_core_dev *dh_dev)
{
	bool flags = false;

	if (!dh_core_is_pf(dh_dev))
		return false;

	if (zxdh_pf_is_special_bond(dh_dev))
		return false;

	if (dh_dev->pdev->device == ZXDH_INICA_BOND_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_INICB_BOND_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_INICC_BOND_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_INICA_UPF_BOND_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_DPUA_BOND_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_INICD_BOND0_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_INICD_BOND1_DEVICE_ID) {
		flags = true;
	}

	return flags;
}

bool zxdh_pf_is_upf(struct dh_core_dev *dh_dev)
{
	bool flags = false;

	if (dh_dev->pdev->device == ZXDH_UPF_PF_I512_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_UPF_VF_I512_DEVICE_ID) {
		flags = true;
	}

	return flags;
}

bool zxdh_pf_is_nic(struct dh_core_dev *dh_dev)
{
	if (dh_dev->pdev->device == ZXDH_PF_E312_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_VF_E312_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_PF_E316_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_VF_E316_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_PF_E316_XPU_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_VF_E316_XPU_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_PF_E310_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_VF_E310_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_PF_E310_CMCC_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_VF_E310_CMCC_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_PF_E311_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_VF_E311_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_PF_E310_RDMA_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_VF_E310_RDMA_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_PF_E310S_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_VF_E310S_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_PF_E312S_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_VF_E312S_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_PF_E312_RDMA_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_VF_E312_RDMA_DEVICE_ID ||
	    dh_dev->pdev->device == CTC_PF_B512Y_DEVICE_ID ||
	    dh_dev->pdev->device == CTC_VF_B512Y_DEVICE_ID ||
	    dh_dev->pdev->device == CTC_PF_B522Y_DEVICE_ID ||
	    dh_dev->pdev->device == CTC_VF_B522Y_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_PF_E312S_D_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_VF_E312S_D_DEVICE_ID) {
		return true;
	}

	return false;
}

bool zxdh_pf_is_rdma_enable(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct firmware_capability *fwcap = &pf_dev->fwcap;

	if (FW_FEATURE_GET(fwcap->fw_feature, FW_FEATURE_RDMA) == 1)
		return true;

	return false;
}

bool zxdh_pf_is_drs_sec_enable(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct firmware_capability *fwcap = &pf_dev->fwcap;

	if (FW_FEATURE_GET(fwcap->fw_feature, FW_FEATURE_SEC) == 1)
		return true;

	return false;
}

u32 zxdh_pf_get_dev_type(struct dh_core_dev *dh_dev)
{
	if (dh_dev->pdev->device == ZXDH_UPF_PF_I512_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_UPF_VF_I512_DEVICE_ID) {
		return ZXDH_DEV_UPF;
	}

	if (dh_dev->pdev->device == ZXDH_INICD_NE0_PF_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_INICD_NE0_VF_DEVICE_ID) {
		return ZXDH_DEV_NE0;
	}

	if (dh_dev->pdev->device == ZXDH_INICD_NE1_PF_DEVICE_ID ||
	    dh_dev->pdev->device == ZXDH_INICD_NE1_VF_DEVICE_ID) {
		return ZXDH_DEV_NE1;
	}

	return ZXDH_DEV_UNKNOW;
}

u8 zxdh_pf_get_queue_pairs(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	return pf_dev->vq_pairs;
}

struct zxdh_vf_item *zxdh_pf_get_vf_item(struct dh_core_dev *dh_dev, u16 vf_idx)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	if (dh_dev->coredev_type != DH_COREDEV_PF) {
		LOG_ERR("Invalid device\n");
		return ERR_PTR(-EINVAL);
	}

	if (vf_idx >= ZXDH_VF_NUM_MAX) {
		LOG_ERR("vf idx(%u) out of range(0~255)\n", vf_idx);
		return ERR_PTR(-EINVAL);
	}

	if (!pf_dev->vf_item) {
		LOG_ERR("vf_item is NULL\n");
		return ERR_PTR(-EINVAL);
	}

	if (!pf_dev->vf_item[vf_idx].enable) {
		LOG_ERR("vf(%u) is disable\n", vf_idx);
		return ERR_PTR(-EINVAL);
	}

	return &(pf_dev->vf_item[vf_idx]);
}

s32 zxdh_vf_compat_check(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	u64 msg_idmax = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	if (dh_dev->coredev_type == DH_COREDEV_PF)
		return 0;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (unlikely(!msg)) {
		LOG_ERR("failed to kzalloc\n");
		return -1;
	}

	msg->payload.hdr.op_code = ZXDH_GET_K_CMPAT_VERINFO;
	msg->payload.kernel_cmpat_msg.vfid = VQM_VFID(pf_dev->vport);
	err = zxdh_pf_msg_send_cmd(dh_dev, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (err != 0) {
		LOG_ERR("send_msg_to_pf failed, err: %d\n", err);
		kfree(msg);
		return err;
	}

	msg_idmax = msg->reps.kernel_cmpat_rsp.k_msg_idmax;
	if (msg_idmax < ZXDH_MSG_TYPE_CNT_MAX) {
		LOG_INFO("msg_idmax error!, msg_idmax=%lld, ZXDH_MSG_TYPE_CNT_MAX=%d\n", msg_idmax,
			 ZXDH_MSG_TYPE_CNT_MAX);
		LOG_INFO("Perhaps the version of the pf device driver is too old.\n");
	}

	kfree(msg);

	return 0;
}

static s32 zxdh_get_mcfeature_from_pf(struct dh_core_dev *dh_dev, u64 *mcfeature)
{
	union zxdh_msg *msg = NULL;
	s32 err = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	if (dh_dev->coredev_type == DH_COREDEV_PF)
		return -1;

	msg = kzalloc(sizeof(union zxdh_msg), GFP_KERNEL);
	if (unlikely(!msg)) {
		LOG_ERR("failed to kzalloc\n");
		return -1;
	}

	msg->payload.hdr.op_code = ZXDH_MC_CMPAT_VERINFO;
	msg->payload.mcode_feature_msg.dev_id = 0;
	msg->payload.mcode_feature_msg.index = 1;
	err = zxdh_pf_msg_send_cmd(dh_dev, MODULE_VF_BAR_MSG_TO_PF, msg, msg, &para);
	if (err != 0) {
		LOG_ERR("send_msg_to_pf failed, err: %d\n", err);
		kfree(msg);
		return err;
	}

	if (msg->reps.mcode_feature_rsp.len != sizeof(msg->reps.mcode_feature_rsp.feature)) {
		LOG_ERR("rsp len error!, len=%lld\n", msg->reps.mcode_feature_rsp.len);
		kfree(msg);
		return -1;
	}

	*mcfeature = msg->reps.mcode_feature_rsp.feature;

	kfree(msg);

	return 0;
}

#define ZXDH_MCODE_FEATURE_INDEX (1)
s32 dh_pf_mcode_compat_check(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	s32 ret = 0;
	u64 mcode_feature = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = pf_dev->slot_id;
	pf_info.vport = pf_dev->vport;

	if (dh_core_is_pf(dh_dev)) {
		ret = dpp_mcode_feature_get(&pf_info, ZXDH_MCODE_FEATURE_INDEX, &mcode_feature);
		if (ret > 0) {
			LOG_ERR("mcode_feature_get failed! ret=%d\n", ret);
			return -ret;
		}
	} else {
		ret = zxdh_get_mcfeature_from_pf(dh_dev, &mcode_feature);
		if (ret != 0) {
			LOG_ERR("get_mcfeature_from_pf failed! ret=%d\n", ret);
			return -1;
		}
	}

	LOG_INFO("mcode_feature:0x%llx\n", mcode_feature);
	pf_dev->mcode_feature = mcode_feature;

	return ret;
}

void clear_zxdh_plcr_table(struct zxdh_plcr_table *table)
{
	s32 i = 0;

	for (i = 0; i <= 2; i++) {
		xa_destroy(&table->plcr_profiles[i]);
		xa_destroy(&table->plcr_flows[i]);
		xa_destroy(&table->plcr_maps[i]);
	}

	table->burst_size = 0;
	table->is_init = false;
}

s32 zxdh_pf_dpp_init(struct dh_core_dev *dh_dev, bool boot)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	s32 ret = 0;
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = pf_dev->slot_id;
	pf_info.vport = pf_dev->vport;

	ret = dpp_vport_register(&pf_info, dh_dev->pdev);
	if (ret > 0)
		return -ret;

	if (dh_dev->coredev_type == DH_COREDEV_PF) {
		clear_zxdh_plcr_table(&(pf_dev->plcr_table));
		dpp_dev_status_set(&pf_info, 1);
	}

	if (boot) {
		ret = dh_pf_mcode_compat_check(dh_dev);
		if (ret != 0)
			return ret;
	}

	return ret;
}

static s32 zxdh_pf_dpp_uninit(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct dpp_pf_info_t pf_info = { 0 };

	pf_info.slot = pf_dev->slot_id;
	pf_info.vport = pf_dev->vport;
	return dpp_vport_unregister(&pf_info);
}

static s32 zxdh_pf_dpp_reset(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct dpp_pf_info_t pf_info = { 0 };

	if (dh_dev->coredev_type == DH_COREDEV_VF)
		return 0;

	pf_info.slot = pf_dev->slot_id;
	pf_info.vport = pf_dev->vport;

	return dpp_vport_reset(&pf_info);
}

s32 zxdh_init_ip6mac_tbl(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_ipv6_mac_entry *ip6mac_entry_list = NULL;
	unsigned int ip6mact_size = DEV_MULTICAST_MAX_NUM;
	int i;

	pf_dev->ip6mac_tbl =
		kvzalloc(struct_size(pf_dev->ip6mac_tbl, hash_list, ip6mact_size), GFP_KERNEL);
	if (!pf_dev->ip6mac_tbl) {
		LOG_ERR("kvzalloc ip6mac_tbl failed\n");
		return -ENOMEM;
	}

	pf_dev->ip6mac_tbl->ip6mact_size = ip6mact_size;

	INIT_LIST_HEAD(&pf_dev->ip6mac_tbl->ip6mac_free_head);

	mutex_init(&pf_dev->ip6mac_tbl->mlock);

	for (i = 0; i < pf_dev->ip6mac_tbl->ip6mact_size; ++i)
		INIT_LIST_HEAD(&pf_dev->ip6mac_tbl->hash_list[i]);

	ip6mac_entry_list = kvcalloc(pf_dev->ip6mac_tbl->ip6mact_size,
				     sizeof(struct zxdh_ipv6_mac_entry), GFP_KERNEL);
	if (!ip6mac_entry_list) {
		kvfree(pf_dev->ip6mac_tbl);
		LOG_ERR("kvcalloc ip6mac_entry_list failed\n");
		return -ENOMEM;
	}
	pf_dev->ip6mac_tbl->ip6mac_entry_list = (void *)ip6mac_entry_list;

	for (i = 0; i < pf_dev->ip6mac_tbl->ip6mact_size; i++) {
		INIT_LIST_HEAD(&ip6mac_entry_list[i].list);
		list_add_tail(&ip6mac_entry_list[i].list, &pf_dev->ip6mac_tbl->ip6mac_free_head);
	}

	return 0;
}

void zxdh_cleanup_ip6mac_tbl(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_ipv6_mac_tbl *ip6mac_tbl = pf_dev->ip6mac_tbl;

	if (ip6mac_tbl) {
		if (ip6mac_tbl->ip6mac_entry_list) {
			kvfree(ip6mac_tbl->ip6mac_entry_list);
			ip6mac_tbl->ip6mac_entry_list = NULL;
		}
		kvfree(ip6mac_tbl);
		pf_dev->ip6mac_tbl = NULL;
	}
}

struct pci_dev *zxdh_pf_get_pdev(struct dh_core_dev *dh_dev)
{
	return dh_dev->pdev;
}

u64 zxdh_pf_get_bar_virt_addr(struct dh_core_dev *dh_dev, u8 bar_num)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	return pf_dev->pci_ioremap_addr[bar_num];
}

//#define BAR_MSG_RETRY_CNT_MAX       (10)

u64 zxdh_pf_get_bar_phy_addr(struct dh_core_dev *dh_dev, u8 bar_num)
{
	return pci_resource_start(dh_dev->pdev, bar_num);
}

u64 zxdh_pf_get_bar_size(struct dh_core_dev *dh_dev, u8 bar_num)
{
	return pci_resource_len(dh_dev->pdev, bar_num);
}

s32 zxdh_pf_msg_send_cmd(struct dh_core_dev *dh_dev, u16 module_id, void *msg, void *ack,
			 struct zxdh_bar_extra_para *para)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_reps_info *reps = (struct zxdh_reps_info *)(ack);
	struct vqm_rsp_host_data *vqm_reps = (struct vqm_rsp_host_data *)(ack);
	u64 vaddr = 0;
	s32 err = 0;
	u32 i = 0;

	vaddr = (u64)ZXDH_BAR_MSG_BASE(pf_dev->pci_ioremap_addr[0]);

	for (i = 0; i < (para->retrycnt + 1); i++) {
		if (pf_dev->quick_remove)
			return 0;

		if (!pf_dev->bar_chan_valid)
			return -7;

		err = zxdh_send_command(vaddr, pf_dev->pcie_id, module_id, msg, ack, TRUE);
		if (((-err) != BAR_MSG_ERR_LOCK_FAILED) && ((-err) != BAR_MSG_ERR_TIME_OUT))
			break;

		if ((-err) == BAR_MSG_ERR_LOCK_FAILED) {
			LOG_WARN("Get lock failed while send msg, try again ...(cnt:%u)", i);
			msleep(200);
		}
		if ((-err) == BAR_MSG_ERR_TIME_OUT) {
			LOG_WARN("Timeout while send msg, try again ...(cnt:%u)", i);
			msleep(500);
		}
	}

	if (err != 0) {
		LOG_ERR("zxdh_send_command failed, err=%d\n", err);
		return -1;
	}

	if (module_id == MODULE_CFG_VQM) {
		if (vqm_reps->check_result != 0xaa) {
			LOG_ERR("failed vqm_reps->check_result: 0x%x\n", vqm_reps->check_result);
			return -1;
		}
		return 0;
	}

	if (reps->flag != ZXDH_REPS_SUCC) {
		if (reps->flag == ZXDH_INVALID_OP_CODE) {
			LOG_ERR("msg to vf is invlaid op_code, reps->flag:0x%x\n", reps->flag);
			return ZXDH_INVALID_OP_CODE;
		}
		LOG_ERR("failed reps->flag: 0x%x\n", reps->flag);
		return -1;
	}

	return err;
}

s32 zxdh_pf_query_port(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct port_message_recv *recv_data = NULL;
	struct zxdh_port_msg *payload = NULL;
	struct zxdh_pannle_port *pnlport, *recvport;
	s32 ret = 0, idx = 0;
	struct zxdh_bar_extra_para para = { 0 };

	para.is_sync = true;
	para.retrycnt = BAR_MSG_RETRY_CNT_MAX;

	payload = kzalloc(sizeof(struct zxdh_port_msg), GFP_KERNEL);
	if (unlikely(!payload)) {
		LOG_ERR("failed to kzalloc\n");
		return -ENOMEM;
	}

	recv_data = kzalloc(sizeof(struct port_message_recv), GFP_KERNEL);
	if (unlikely(!recv_data)) {
		LOG_ERR("failed to kzalloc\n");
		goto out;
	}

	payload->pcie_id = zxdh_pf_get_pcie_id(dh_dev);

	ret = zxdh_pf_msg_send_cmd(dh_dev, MODULE_PHYPORT_QUERY, payload, recv_data, &para);
	if (ret != 0) {
		LOG_ERR("%s send message failed\n", __func__);
		goto free_recv;
	}
	LOG_INFO("pcie_id: 0x%x, bond_num: %u lag_id: %u port_num: %u\n", payload->pcie_id,
		 recv_data->bond_num, recv_data->bond_idx, recv_data->port_num);

	if (recv_data->port_num > ZXDH_PANNEL_PORT_MAX) {
		LOG_ERR("bond pf query port num from fw out of range.\n");
		ret = -1;
		goto free_recv;
	}

	if ((recv_data->bond_num != 0) && (recv_data->bond_idx >= recv_data->bond_num)) {
		LOG_ERR("bond pf query bond idx from fw out of range.\n");
		ret = -1;
		goto free_recv;
	}
	pf_dev->port_resource.pannel_num = recv_data->port_num;
	pf_dev->port_resource.bond_num = recv_data->bond_num;
	pf_dev->port_resource.bond_idx = recv_data->bond_idx;

	for (idx = 0; idx < recv_data->port_num; idx++) {
		pnlport = &pf_dev->port_resource.port[idx];
		recvport = (struct zxdh_pannle_port *)((u8 *)&recv_data->data[idx]);

		pnlport->phyport = recvport->phyport;
		pnlport->pannel_id = recvport->pannel_id;
		pnlport->link_check_bit = recvport->link_check_bit;
		pnlport->flags = 0;

		LOG_DEBUG("[%d] pannel %u, phyport %u link check bit %u\n", idx,
			  (u32)pnlport->pannel_id, (u32)pnlport->phyport,
			  (u32)pnlport->link_check_bit);
	}

free_recv:
	kfree(recv_data);
out:
	kfree(payload);
	return ret;
}

s32 zxdh_pf_query_fwinfo(struct dh_core_dev *dh_dev)
{
	s32 ret = 0;

	ret = zxdh_pf_query_port(dh_dev);
	if (ret != 0)
		return ret;

	return 0;
}

u16 zxdh_pf_get_queue_num(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	u16 qnum = 0;

	qnum = ioread16(&pf_dev->common->num_queues);

	return qnum;
}

u16 zxdh_pf_get_queue_size(struct dh_core_dev *dh_dev, u16 index)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	u16 queue_size = 0;

	iowrite16(index, &pf_dev->common->queue_select);
	queue_size = ioread16(&pf_dev->common->queue_size);

	return queue_size;
}

u16 zxdh_pf_get_queue_vector(struct dh_core_dev *dh_dev, u16 channel, struct list_head *eqs_list,
			     u16 queue_index, u16 vq_idx)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_pf_pci_common_cfg __iomem *cfg = pf_dev->common;
	struct dh_eq_vqs *eq_vqs = NULL;
	struct dh_eq_vqs *n;
	struct dh_eq_vqs *found = NULL;
	s32 i = 0;
	s32 msix_vec = ZXDH_MSI_NO_VECTOR;

	iowrite16(queue_index, &cfg->queue_select);

	list_for_each_entry_safe(eq_vqs, n, eqs_list, list) {
		if (i++ == channel) {
			found = eq_vqs;
			break;
		}
	}

	if (!found) {
		LOG_ERR("%s vq %d channel %u not found in eqs_list\n",
			pci_name(dh_dev->pdev), vq_idx, channel);
		return msix_vec;
	}

	iowrite16(found->vq_s.core.irq->index, &cfg->queue_msix_vector);
	msix_vec = ioread16(&cfg->queue_msix_vector);
	LOG_DEBUG("%s vq %d mapped to irqn %d\n", pci_name(dh_dev->pdev), vq_idx,
		  found->vq_s.core.irq->irqn);
	/* Flush the write out to device */
	return msix_vec;
}

void zxdh_pf_release_queue_vector(struct dh_core_dev *dh_dev, s32 queue_index)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_pf_pci_common_cfg __iomem *cfg = pf_dev->common;

	iowrite16(queue_index, &cfg->queue_select);
	iowrite16(ZXDH_MSI_NO_VECTOR, &cfg->queue_msix_vector);
}

void zxdh_pf_set_queue_size(struct dh_core_dev *dh_dev, u32 index, u16 size)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	iowrite16(index, &pf_dev->common->queue_select);
	iowrite16(size, &pf_dev->common->queue_size);
}

void zxdh_pf_set_queue_address(struct dh_core_dev *dh_dev, u32 index, u64 desc_addr,
			       u64 driver_addr, u64 device_addr)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	iowrite16(index, &pf_dev->common->queue_select);
	iowrite32((u32)desc_addr, &pf_dev->common->queue_desc_lo);
	iowrite32(desc_addr >> 32, &pf_dev->common->queue_desc_hi);
	iowrite32((u32)driver_addr, &pf_dev->common->queue_avail_lo);
	iowrite32(driver_addr >> 32, &pf_dev->common->queue_avail_hi);
	iowrite32((u32)device_addr, &pf_dev->common->queue_used_lo);
	iowrite32(device_addr >> 32, &pf_dev->common->queue_used_hi);
}

s32 zxdh_pf_get_phy_vq_info(u32 phy_index, u32 *phy_vq_reg, u32 *vq_bit)
{
	if (phy_index >= ZXDH_MAX_QUEUES_NUM) {
		LOG_ERR("Invalid phy_index:%u\n", phy_index);
		return -1;
	}

	*phy_vq_reg = phy_index / ZXDH_PHY_REG_BITS;
	*vq_bit = phy_index % ZXDH_PHY_REG_BITS;

	return 0;
}

s32 zxdh_pf_get_vq_lock(struct dh_core_dev *dh_dev)
{
	s32 i = 0;
	s32 val = 0;
	s32 wait_time = ZXDH_PF_WAIT_COUNT;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	for (i = 0; i < wait_time; i++) {
		val = ioread32((void __iomem *)((uintptr_t)pf_dev->common + LOCK_VQ_REG_OFFSET));
		if (val & ZXDH_PF_LOCK_ENABLE_MASK)
			break;
		udelay(ZXDH_PF_DELAY_US);
	}

	if ((val & ZXDH_PF_LOCK_ENABLE_MASK) == 0) {
		LOG_INFO("get phy vq_id is busy\n");
		return -1;
	}

	return 0;
}

s32 zxdh_pf_release_vq_lock(struct dh_core_dev *dh_dev)
{
	s32 val = 0;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	val = ioread32((void __iomem *)((uintptr_t)pf_dev->common + LOCK_VQ_REG_OFFSET));
	if (val & ZXDH_PF_LOCK_ENABLE_MASK) {
		iowrite32(ZXDH_PF_RELEASE_LOCK_VAL,
			  (void __iomem *)((uintptr_t)pf_dev->common + LOCK_VQ_REG_OFFSET));
		return 0;
	}
	LOG_INFO("no lock need to be released\n");
	return -1;
}

s32 find_valid_vqs_by_bit(struct dh_core_dev *dh_dev, u8 queue_type, u16 vq_cnt, s32 *phy_index,
			  u16 total_qp, u16 start_id)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	u32 phy_vq_reg = 0;
	u32 val = 0;
	u32 done = 0;
	u32 j = 0;
	u16 index = 0;
	u16 total_queue_num = total_qp * 2;
	u16 start_qp_id = start_id * 2;

	u32 phy_vq_reg_oft = start_qp_id / ZXDH_PHY_REG_BITS;
	u32 inval_bit = start_qp_id % ZXDH_PHY_REG_BITS;
	u32 res_bit = (total_queue_num + inval_bit) % ZXDH_PHY_REG_BITS;
	u32 vq_reg_num = (total_queue_num + inval_bit) / ZXDH_PHY_REG_BITS + (res_bit ? 1 : 0);

	LOG_DEBUG("phy_vq_reg_oft:%u, inval_bit is %u, res_bit:%u, vq_reg_num:%u\n", phy_vq_reg_oft,
		  inval_bit, res_bit, vq_reg_num);

	for (phy_vq_reg = 0; phy_vq_reg < vq_reg_num; phy_vq_reg++) {
		val = ioread32((void __iomem *)(uintptr_t)(pf_dev->pci_ioremap_addr[0] +
							   PHY_VQ_REG_OFFSET +
							   (phy_vq_reg + phy_vq_reg_oft) * 4));

		if (phy_vq_reg == 0)
			val = val | (((u32)1 << inval_bit) - 1);

		if ((phy_vq_reg == (vq_reg_num - 1)) && (res_bit != 0))
			val = val | (~((u32)1 << res_bit) + 1);

		for (j = queue_type; (j < ZXDH_PHY_REG_BITS) && (index < vq_cnt);
		     j += ZXDH_PF_POWER_INDEX2) {
			if ((val & (ZXDH_PF_GET_PHY_INDEX_BIT << j)) == 0) {
				phy_index[queue_type + 2 * index] =
					(phy_vq_reg + phy_vq_reg_oft) * ZXDH_PHY_REG_BITS + j;
				index++;
			}
		}

		if (index == vq_cnt) {
			done = ZXDH_PF_GET_PHY_INDEX_DONE;
			break;
		}
	}

	if (done != ZXDH_PF_GET_PHY_INDEX_DONE) {
		LOG_ERR("no availd phy queue, Currently can only apply %u %s queues.\n", index,
			queue_type ? "tx" : "rx");
		return -1;
	}

	return 0;
}

s32 find_valid_vqs_by_type(struct dh_core_dev *dh_dev, u8 queue_type, u16 vq_cnt, s32 *phy_index)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	u32 phy_vq_reg = 0;
	u32 vq_reg_num = ZXDH_MAX_QUEUES_NUM / ZXDH_PHY_REG_BITS;
	u32 val = 0;
	u32 done = 0;
	u32 j = 0;
	u16 index = 0;

	for (phy_vq_reg = 0; phy_vq_reg < vq_reg_num; phy_vq_reg++) {
		val = ioread32((void __iomem *)(uintptr_t)(pf_dev->pci_ioremap_addr[0] +
							   PHY_VQ_REG_OFFSET + phy_vq_reg * 4));

		for (j = queue_type; (j < ZXDH_PHY_REG_BITS) && (index < vq_cnt);
		     j += ZXDH_PF_POWER_INDEX2) {
			if ((val & (ZXDH_PF_GET_PHY_INDEX_BIT << j)) == 0) {
				phy_index[queue_type + 2 * index] =
					phy_vq_reg * ZXDH_PHY_REG_BITS + j;
				index++;
			}
		}

		if (index == vq_cnt) {
			done = ZXDH_PF_GET_PHY_INDEX_DONE;
			break;
		}
	}

	if (done != ZXDH_PF_GET_PHY_INDEX_DONE) {
		LOG_ERR("no availd phy queue, Currently can only apply %u %s queues.\n", index,
			queue_type ? "tx" : "rx");
		return -1;
	}

	return 0;
}

s32 zxdh_pf_find_valid_vqs(struct dh_core_dev *dh_dev, u16 vq_cnt, s32 *phy_index)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_dev_queue_info *dev_qinfo = NULL;
	struct zxdh_fw_compat fw_compat = pf_dev->fw_compat;
	s32 ret = 0;
	u32 pair_cnt = 0;
	u16 ep_id = 0;
	u16 pf_idx = 0;

	pair_cnt = vq_cnt / 2;

	if ((fw_compat.patch >= 1) && zxdh_pf_is_nic(dh_dev)) {
		ep_id = EPID_GEN_FROM_VPORT(pf_dev->vport);
		pf_idx = GLOBAL_PF_IDX(ep_id, pf_dev->vport);

		dev_qinfo = (struct zxdh_dev_queue_info *)(uintptr_t)(
			pf_dev->pci_ioremap_addr[0] + ZXDH_DEV_QUEUE_INFO_OFFSET + pf_idx * 4);
		LOG_DEBUG(
			"pf(vport:0x%x) get queue config: ep_id:%u, pf_idx:%u, total_qp:%u, start_id:%u\n",
			pf_dev->vport, ep_id, pf_idx, dev_qinfo->total_qp, dev_qinfo->start_id);

		ret = find_valid_vqs_by_bit(dh_dev, ZXDH_PF_RQ_TYPE, pair_cnt, phy_index,
					    dev_qinfo->total_qp, dev_qinfo->start_id);
		if (ret != 0)
			return ret;

		ret = find_valid_vqs_by_bit(dh_dev, ZXDH_PF_TQ_TYPE, pair_cnt, phy_index,
					    dev_qinfo->total_qp, dev_qinfo->start_id);
		if (ret != 0)
			return ret;

		return 0;
	}

	ret = find_valid_vqs_by_type(dh_dev, ZXDH_PF_RQ_TYPE, pair_cnt, phy_index);
	if (ret != 0)
		return ret;

	ret = find_valid_vqs_by_type(dh_dev, ZXDH_PF_TQ_TYPE, pair_cnt, phy_index);
	if (ret != 0)
		return ret;

	return 0;
}

s32 zxdh_pf_write_vqs_bit(struct dh_core_dev *dh_dev, u16 vq_cnt, u32 *phy_index)
{
	u32 phy_vq_reg = 0;
	u32 vq_bit = 0;
	u32 val = 0;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	u16 i = 0;

	for (i = 0; i < vq_cnt; ++i) {
		phy_vq_reg = phy_index[i] / ZXDH_PHY_REG_BITS;
		vq_bit = phy_index[i] % ZXDH_PHY_REG_BITS;

		val = ioread32((void __iomem *)(uintptr_t)(pf_dev->pci_ioremap_addr[0] +
							   PHY_VQ_REG_OFFSET + phy_vq_reg * 4));
		val |= (ZXDH_PF_GET_PHY_INDEX_BIT << vq_bit);
		iowrite32(val, (void __iomem *)(uintptr_t)(pf_dev->pci_ioremap_addr[0] +
							   PHY_VQ_REG_OFFSET + phy_vq_reg * 4));
	}

	return 0;
}

s32 zxdh_pf_write_queue_tlb(struct dh_core_dev *dh_dev, u16 vq_cnt, u32 *phy_index, bool need_msgq)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	u16 i = 0;
	u16 pcieid = pf_dev->pcie_id;

	for (i = 0; i < vq_cnt; ++i) {
		pcieid = pf_dev->pcie_id;
		if (need_msgq && (i >= (vq_cnt - 2)))
			pcieid |= BIT(15);
		iowrite16(pcieid,
			  (void __iomem *)(uintptr_t)(pf_dev->pci_ioremap_addr[0] +
						      pf_dev->qtlb_offset + phy_index[i] * 2));
	}

	return 0;
}

u16 zxdh_pf_get_fw_patch(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	return pf_dev->fw_compat.patch;
}

void zxdh_pf_update_link_info(struct dh_core_dev *dh_dev, struct link_info_struct *link_info_val)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	if (pf_dev->link_up && link_info_val->speed == SPEED_UNKNOWN) {
		LOG_INFO(
			"pf_dev->link_up is %d and link_info_val->speed is %d, can't update pf info\n",
			pf_dev->link_up, link_info_val->speed);
		return;
	}
	pf_dev->speed = link_info_val->speed;
	pf_dev->autoneg_enable = link_info_val->autoneg_enable;
	pf_dev->supported_speed_modes = link_info_val->supported_speed_modes;
	pf_dev->advertising_speed_modes = link_info_val->advertising_speed_modes;
	pf_dev->duplex = link_info_val->duplex;
}

s32 zxdh_pf_get_drv_msg(struct dh_core_dev *dh_dev, u8 *drv_version, u8 *drv_version_len)
{
	*drv_version_len = sizeof(zxdh_pf_driver_version);
	memcpy(drv_version, zxdh_pf_driver_version, *drv_version_len);
	return 0;
}

void zxdh_pf_set_vepa(struct dh_core_dev *dh_dev, bool setting)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	pf_dev->vepa = setting;
}

bool zxdh_pf_get_vepa(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	return pf_dev->vepa;
}

s32 zxdh_pf_request_port(struct dh_core_dev *dh_dev, void *data)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	u8 port_num = pf_dev->port_resource.pannel_num;
	struct zxdh_pannle_port *port;
	struct zxdh_pannle_port *req_data = (struct zxdh_pannle_port *)data;
	s32 idx = 0;

	for (idx = 0; idx < port_num; idx++) {
		port = &pf_dev->port_resource.port[idx];
		if (!(port->flags & PORT_FLAGS_ALLOC_STAT)) {
			req_data->phyport = port->phyport;
			req_data->pannel_id = port->pannel_id;
			req_data->link_check_bit = port->link_check_bit;
			port->flags |= PORT_FLAGS_ALLOC_STAT;
			break;
		}
	}

	if (idx == port_num) {
		LOG_ERR("failed to obtain the panel info or not released\n");
		return -1;
	}

	return 0;
}

s32 zxdh_pf_release_port(struct dh_core_dev *dh_dev, u32 pnl_id)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	u8 port_num = pf_dev->port_resource.pannel_num;
	struct zxdh_pannle_port *port;
	s32 idx = 0;

	for (idx = 0; idx < port_num; idx++) {
		port = &pf_dev->port_resource.port[idx];
		if (pnl_id == port->pannel_id) {
			port->flags &= ~PORT_FLAGS_ALLOC_STAT;
			break;
		}
	}

	return 0;
}

void zxdh_pf_set_bond_num(struct dh_core_dev *dh_dev, bool add)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	if (add)
		pf_dev->bond_num++;
	else
		pf_dev->bond_num--;
}

bool zxdh_pf_if_init(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	if (pf_dev->bond_num == 0)
		return true;

	return false;
}

void zxdh_pf_set_init_comp_flag(struct dh_core_dev *dh_dev, u8 flag)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	pf_dev->aux_comp_flag = flag;
}

struct zxdh_ipv6_mac_tbl *zxdh_pf_get_ip6mac_tbl(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	return pf_dev->ip6mac_tbl;
}

static s32 zxdh_pf_events_call_chain(struct dh_core_dev *dh_dev, unsigned long type, void *data)
{
	struct dh_eq_table *eq_table = &dh_dev->eq_table;

	return atomic_notifier_call_chain(&eq_table->nh[type], type, data);
}

u16 zxdh_pf_get_ovs_pf_vfid(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	u32 ovs_pf_vfid;

	ovs_pf_vfid = ioread32(
		(void __iomem *)(uintptr_t)(pf_dev->pci_ioremap_addr[0] + ZXDH_OVS_PF_VFID_OFFSET));
	LOG_INFO("pf(vport:0x%x) get ovs pf vfid 0x%x\n", pf_dev->vport, ovs_pf_vfid);

	return (u16)ovs_pf_vfid;
}

u8 zxdh_pf_get_board_type(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	return pf_dev->board_type;
}

bool zxdh_pf_is_hwbond(struct dh_core_dev *dh_dev, bool is_hwbond, bool update_pf)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	if (update_pf)
		pf_dev->is_hwbond = is_hwbond;

	return pf_dev->is_hwbond;
}

bool zxdh_pf_is_rdma_aux_plug(struct dh_core_dev *dh_dev, bool is_rdma_aux_plug, bool update_pf)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	if (update_pf)
		pf_dev->is_rdma_aux_plug = is_rdma_aux_plug;

	return pf_dev->is_rdma_aux_plug;
}

bool zxdh_pf_is_primary_port(struct dh_core_dev *dh_dev, bool is_primary_port, bool update_pf)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	if (update_pf)
		pf_dev->is_primary_port = is_primary_port;

	return pf_dev->is_primary_port;
}

s32 zxdh_pf_update_hb_file_val(struct dh_core_dev *dh_dev, u64 spec_sbdf, const char *file_name,
			       bool flag);

void zxdh_pf_optim_hardware_bond_time(struct dh_core_dev *dh_dev, bool enable)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct dpp_pf_info_t dpp_pf_info = {
		.slot = pf_dev->slot_id,
		.vport = pf_dev->vport,
	};
	if (enable)
		dpp_pktrx_mcode_glb_cfg_write(&dpp_pf_info, 29, 29, 1);
	else
		dpp_pktrx_mcode_glb_cfg_write(&dpp_pf_info, 29, 29, 0);
}

struct zxdh_en_sf_if en_sf_ops = {
	.en_sf_map_vq_notify = zxdh_pf_map_vq_notify,
	.en_sf_unmap_vq_notify = zxdh_pf_unmap_vq_notify,
	.en_sf_set_status = zxdh_pf_set_status,
	.en_sf_get_status = zxdh_pf_get_status,
	.en_sf_get_cfg_gen = zxdh_pf_get_cfg_gen,
	.en_sf_get_rp_link_status = zxdh_pf_check_remove_state,
	.en_sf_get_features = zxdh_pf_get_features,
	.en_sf_set_features = zxdh_pf_set_features,
	.en_sf_set_vf_mac = zxdh_pf_set_vf_mac,
	.en_sf_get_vf_mac = zxdh_pf_get_vf_mac,
	.en_sf_set_mac = zxdh_set_mac,
	.en_sf_get_mac = zxdh_get_mac,
	.en_sf_set_queue_enable = zxdh_pf_set_queue_enable,
	.en_sf_get_channels_num = zxdh_pf_get_vqs_channels_num,
	.en_sf_get_queue_num = zxdh_pf_get_queue_num,
	.en_sf_get_queue_size = zxdh_pf_get_queue_size,
	.en_sf_get_queue_vector = zxdh_pf_get_queue_vector,
	.en_sf_release_queue_vector = zxdh_pf_release_queue_vector,
	.en_sf_set_queue_size = zxdh_pf_set_queue_size,
	.en_sf_set_queue_address = zxdh_pf_set_queue_address,
	.en_sf_vq_irqs_request = zxdh_pf_vq_irqs_request,
	.en_sf_affinity_irqs_release = zxdh_pf_affinity_irqs_release,
	.en_sf_switch_irq = zxdh_pf_switch_irq,
	.en_sf_get_vq_lock = zxdh_pf_get_vq_lock,
	.en_sf_release_vq_lock = zxdh_pf_release_vq_lock,
	.en_sf_find_valid_vqs = zxdh_pf_find_valid_vqs,
	.en_sf_write_vqs_bit = zxdh_pf_write_vqs_bit,
	.en_sf_write_queue_tlb = zxdh_pf_write_queue_tlb,
	.en_sf_get_fw_patch = zxdh_pf_get_fw_patch,
	.en_sf_get_epbdf = zxdh_pf_get_epbdf,
	.en_sf_get_spec_sbdf = zxdh_pf_get_spec_sbdf,
	.en_sf_is_multi_ep = zxdh_pf_is_multi_ep,
	.en_sf_get_vport = zxdh_pf_get_vport,
	.en_sf_get_coredev_type = zxdh_pf_get_coredev_type,
	.en_sf_get_pcie_id = zxdh_pf_get_pcie_id,
	.en_sf_get_slot_id = zxdh_pf_get_slot_id,
	.en_sf_is_bond = zxdh_pf_is_bond,
	.en_sf_is_upf = zxdh_pf_is_upf,
	.en_sf_get_pdev = zxdh_pf_get_pdev,
	.en_sf_get_bar_virt_addr = zxdh_pf_get_bar_virt_addr,
	.en_sf_get_bar_phy_addr = zxdh_pf_get_bar_phy_addr,
	.en_sf_get_bar_size = zxdh_pf_get_bar_size,
	.en_sf_msg_send_cmd = zxdh_pf_msg_send_cmd,
	.en_sf_async_eq_enable = zxdh_pf_async_eq_enable,
	.en_sf_nh_attach = zxdh_pf_nh_attach,
	.en_sf_get_vf_item = zxdh_pf_get_vf_item,
	.en_sf_set_pf_link_up = zxdh_pf_set_pf_link_up,
	.en_sf_get_pf_link_up = zxdh_pf_get_pf_link_up,
	.en_sf_update_pf_link_info = zxdh_pf_update_link_info,
	.en_sf_get_drv_msg = zxdh_pf_get_drv_msg,
	.en_sf_get_vepa = zxdh_pf_get_vepa,
	.en_sf_set_vepa = zxdh_pf_set_vepa,
	.en_sf_set_bond_num = zxdh_pf_set_bond_num,
	.en_sf_if_init = zxdh_pf_if_init,
	.en_sf_request_port_info = zxdh_pf_request_port,
	.en_sf_release_port_info = zxdh_pf_release_port,
	.en_sf_get_link_info_from_vqm = zxdh_pf_get_link_info_from_vqm,
	.en_sf_set_vf_link_info = zxdh_pf_set_vf_link_info,
	.en_sf_get_vf_is_probe = zxdh_pf_get_vf_is_probe,
	.en_sf_set_pf_phy_port = zxdh_pf_set_pf_phy_port,
	.en_sf_get_pf_phy_port = zxdh_pf_get_pf_phy_port,
	.en_sf_set_init_comp_flag = zxdh_pf_set_init_comp_flag,
	.en_sf_events_call_chain = zxdh_pf_events_call_chain,
	.en_sf_get_ip6mac_tbl = zxdh_pf_get_ip6mac_tbl,
	.en_sf_is_nic = zxdh_pf_is_nic,
	.en_sf_is_special_bond = zxdh_pf_is_special_bond,
	.en_sf_get_queue_pairs = zxdh_pf_get_queue_pairs,
	.en_sf_get_cpl_timeout_if_mask = zxdh_pf_get_cpl_timeout_if_mask,
	.en_sf_set_cpl_timeout_mask = zxdh_pf_set_cpl_timeout_mask,
	.en_sf_get_hp_irq_ctrl_status = zxdh_pf_get_hp_irq_ctrl_status,
	.en_sf_set_hp_irq_ctrl_status = zxdh_pf_set_hp_irq_ctrl_status,
	.en_sf_is_rdma_enable = zxdh_pf_is_rdma_enable,
	.en_sf_get_dev_type = zxdh_pf_get_dev_type,
	.en_sf_pf_suport_np_ext_stats = zxdh_pf_suport_np_ext_stats,
	.en_sf_get_np_ext_stats = zxdh_get_np_ext_stats,
	.en_sf_is_drs_sec_enable = zxdh_pf_is_drs_sec_enable,
	.en_sf_is_fw_feature_support = zxdh_pf_is_fw_feature_support,
	.en_sf_get_ovs_pf_vfid = zxdh_pf_get_ovs_pf_vfid,
	.en_sf_get_board_type = zxdh_pf_get_board_type,
	.en_sf_is_hwbond = zxdh_pf_is_hwbond,
	.en_sf_is_rdma_aux_plug = zxdh_pf_is_rdma_aux_plug,
	.en_sf_is_primary_port = zxdh_pf_is_primary_port,
	.en_sf_optim_hardware_bond_time = zxdh_pf_optim_hardware_bond_time,
	.en_sf_update_hb_file_val = zxdh_pf_update_hb_file_val,
};

void zxdh_adev_release(struct device *dev)
{
	/* adev is embedded in its parent container which owns the memory,
	 * so nothing to free here. Release must remain non-NULL to satisfy
	 * the device core.
	 */
}

static DEFINE_IDA(zxdh_adev_ida);

s32 zxdh_plug_aux_dev(struct dh_core_dev *dh_dev, s32 idx)
{
	struct zxdh_auxiliary_device *adev = NULL;
	struct zxdh_pf_device *pf_dev = NULL;
	struct zxdh_en_sf_container *sf_con = NULL;
	struct zxdh_pf_adev *pf_adevs_table = NULL;
	s32 ret = 0;

	pf_dev = dh_core_priv(dh_dev);

	if (idx >= pf_dev->adevs_num)
		return 0;

	pf_adevs_table = &pf_dev->adevs_table[idx];
	if (pf_adevs_table->adev)
		return 0;

	sf_con = kzalloc(sizeof(struct zxdh_en_sf_container), GFP_KERNEL);

	if (unlikely(!sf_con)) {
		LOG_ERR("zxadev kzalloc is null\n");
		return -ENOMEM;
	}

	pf_adevs_table->aux_idx = ida_alloc(&zxdh_adev_ida, GFP_KERNEL);
	if (pf_adevs_table->aux_idx < 0) {
		LOG_ERR("failed to allocate device id for aux drvs\n");
		goto free_kzalloc;
	}

	adev = &sf_con->adev;

	adev->id = pf_adevs_table->aux_idx;
	adev->dev.parent = &dh_dev->pdev->dev;
	adev->dev.release = zxdh_adev_release;
	adev->name = ZXDH_PF_EN_SF_DEV_ID_NAME;

	pf_adevs_table->adev = adev;
	sf_con->dh_dev = dh_dev;
	sf_con->ops = &en_sf_ops;

	ret = zxdh_auxiliary_device_init(adev);
	if (ret != 0) {
		LOG_ERR("zxdh_auxiliary_device_init failed: %d\n", ret);
		goto free_ida_alloc;
	}

	ret = zxdh_auxiliary_device_add(adev);
	if (ret != 0) {
		LOG_ERR("zxdh_auxiliary_device_add failed: %d\n", ret);
		goto release_aux_init;
	}

	return 0;

release_aux_init:
	zxdh_auxiliary_device_uninit(adev);
free_ida_alloc:
	ida_free(&zxdh_adev_ida, pf_adevs_table->aux_idx);
	pf_adevs_table->aux_idx = -1;
free_kzalloc:
	kfree(sf_con);
	sf_con = NULL;
	return ret;
}

void zxdh_unplug_aux_dev(struct dh_core_dev *dh_dev, s32 idx)
{
	struct zxdh_pf_device *pf_dev = NULL;
	struct zxdh_en_sf_container *sf_con = NULL;
	struct zxdh_pf_adev *pf_adevs_table = NULL;

	pf_dev = dh_core_priv(dh_dev);
	if (idx >= pf_dev->adevs_num)
		return;

	pf_adevs_table = &pf_dev->adevs_table[idx];
	if (!pf_adevs_table->adev)
		return;

	sf_con = container_of(pf_adevs_table->adev, struct zxdh_en_sf_container, adev);

	zxdh_auxiliary_device_delete(pf_adevs_table->adev);
	zxdh_auxiliary_device_uninit(pf_adevs_table->adev);
	ida_free(&zxdh_adev_ida, pf_adevs_table->aux_idx);
	pf_adevs_table->aux_idx = -1;
	kfree(sf_con);
	sf_con = NULL;
}

s32 dh_pf_vf_vport_get(struct dh_core_dev *dev, u16 vf_idx, u16 *vport)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dev);
	u16 pcie_id = 0;
	struct zxdh_pci_bar_msg in = { 0 };
	struct zxdh_msg_recviver_mem result = { 0 };
	u8 recv_buf[8] = { 0 };
	s32 ret = 0;

	if (!vport)
		return BAR_MSG_ERR_NULL;

	pcie_id = FIND_VF_PCIE_ID(pf_dev->pcie_id, vf_idx);

	in.virt_addr = (u64)ZXDH_BAR_MSG_BASE(pf_dev->pci_ioremap_addr[0]);
	in.payload_addr = &pcie_id;
	in.payload_len = sizeof(pcie_id);
	in.src = MSG_CHAN_END_PF;
	in.dst = MSG_CHAN_END_RISC;
	in.event_id = MODULE_VPORT_GET;
	in.src_pcieid = pf_dev->pcie_id;

	result.recv_buffer = recv_buf;
	result.buffer_len = sizeof(recv_buf);

	ret = zxdh_bar_chan_sync_msg_send(&in, &result);
	switch (ret) {
	case BAR_MSG_OK: {
		*vport = *(u16 *)(recv_buf + 4);
		LOG_DEBUG("pf(0x%x) get vf(%u) vport(0x%x) success\n", pf_dev->pcie_id, vf_idx,
			  *vport);
		break;
	}
	default: {
		LOG_ERR("Failed to pf(0x%x) get vf(%u) vport, ret:%d.\n", pcie_id, vf_idx, ret);
		break;
	}
	}

	return ret;
}

s32 dh_pf_vf_item_init(struct dh_core_dev *dev, u16 vf_idx)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dev);
	struct zxdh_vf_item *vf_item = NULL;

	if (!pf_dev->vf_item) {
		LOG_ERR("vf_item is NULL\n");
		return -EINVAL;
	}
	if (vf_idx >= ZXDH_VF_NUM_MAX) {
		LOG_ERR("vf idx(%u) out of range(0~%d)\n", vf_idx, ZXDH_VF_NUM_MAX - 1);
		return -EINVAL;
	}
	vf_item = &pf_dev->vf_item[vf_idx];
	vf_item->link_forced = false;
	vf_item->vport = pf_dev->vf_item[0].vport + vf_idx;
	vf_item->enable = true;
	vf_item->spoofchk = false;
	mutex_init(&vf_item->lock);
	vf_item->init_np_stats = kzalloc(sizeof(struct zxdh_en_vport_np_stats), GFP_KERNEL);
	if (!vf_item->init_np_stats) {
		LOG_ERR("pf_dev->vf_item->init_np_stats failed\n");
		return -ENOMEM;
	}
	return 0;
}

s32 dh_pf_vf_item_uninit(struct dh_core_dev *dev, u16 vf_idx)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dev);
	struct zxdh_vf_item *vf_item = NULL;

	if (!pf_dev->vf_item) {
		LOG_ERR("vf_item is NULL\n");
		return -EINVAL;
	}
	if (vf_idx >= ZXDH_VF_NUM_MAX) {
		LOG_ERR("vf idx(%u) out of range(0~%d)\n", vf_idx, ZXDH_VF_NUM_MAX - 1);
		return -EINVAL;
	}
	vf_item = &pf_dev->vf_item[vf_idx];
	eth_zero_addr(vf_item->mac);
	zxdh_pf_set_vf_mac_reg(pf_dev, vf_item->mac, vf_idx);
	vf_item->pf_set_mac = false;
	vf_item->enable = false;
	vf_item->vlan = 0;
	vf_item->qos = 0;
	vf_item->vlan_proto = 0;
	vf_item->spoofchk = false;
	mutex_destroy(&vf_item->lock);
	kfree(vf_item->init_np_stats);
	return 0;
}

s32 dh_pf_vf_enable(struct dh_core_dev *dev, s32 num_vfs)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dev);
	s32 vf_idx = 0;
	s32 ret = 0;

	ret = dh_pf_vf_vport_get(dev, 0, &pf_dev->vf_item[0].vport);
	if (ret != 0)
		return ret;

	for (vf_idx = 0; vf_idx < num_vfs; vf_idx++) {
		ret = dh_pf_vf_item_init(dev, vf_idx);
		if (ret != 0) {
			LOG_ERR("Failed to init vf(%d) item\n", vf_idx);
			while (vf_idx--)
				dh_pf_vf_item_uninit(dev, vf_idx);
			return ret;
		}
	}

	return ret;
}

void dh_pf_vf_disable(struct dh_core_dev *dev, s32 num_vfs)
{
	s32 vf_idx = 0;

	for (vf_idx = 0; vf_idx < num_vfs; vf_idx++)
		dh_pf_vf_item_uninit(dev, vf_idx);
}

s32 dh_pf_sriov_enable(struct pci_dev *pdev, s32 num_vfs)
{
	struct dh_core_dev *dev = pci_get_drvdata(pdev);
	s32 pre_existing_vfs = pci_num_vf(pdev);
	s32 ret = 0;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dev);

	if ((pre_existing_vfs != 0) && (pre_existing_vfs == num_vfs))
		return 0;

	ret = dh_pf_vf_enable(dev, num_vfs);
	if (ret != 0) {
		LOG_ERR("Failed to enable vf\n");
		return ret;
	}

#ifdef ZXDH_SRIOV_SYSFS_EN
	ret = zxdh_create_vfs_sysfs(dev, num_vfs);
	if (ret != 0) {
		LOG_ERR("zxdh_create_vfs_sysfs failed : %d\n", ret);
		goto err_create_vfs_sysfs;
	}
#endif

	ret = pci_enable_sriov(pdev, num_vfs);
	if (ret != 0) {
		LOG_ERR("pci_enable_sriov failed : %d\n", ret);
		goto err_pci_enable_sriov;
	}

	LOG_DEBUG("start init_vf_link_info_work");
	zxdh_events_work_enqueue(dev, &pf_dev->init_vf_link_info_work);
	return ret;

err_pci_enable_sriov:
#ifdef ZXDH_SRIOV_SYSFS_EN
	zxdh_destroy_vfs_sysfs(dev, num_vfs);
err_create_vfs_sysfs:
#endif
	dh_pf_vf_disable(dev, num_vfs);

	return ret;
}

void dh_pf_sriov_disable(struct pci_dev *pdev)
{
	struct dh_core_dev *dev = pci_get_drvdata(pdev);
	s32 num_vfs = pci_num_vf(pdev);

	pci_disable_sriov(pdev);
#ifdef ZXDH_SRIOV_SYSFS_EN
	zxdh_destroy_vfs_sysfs(dev, num_vfs);
#endif
	dh_pf_vf_disable(dev, num_vfs);
}

s32 dh_pf_vf_item_create(struct dh_core_dev *dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dev);

	if (dev->coredev_type == DH_COREDEV_PF) {
		pf_dev->vf_item =
			kzalloc(sizeof(struct zxdh_vf_item) * ZXDH_VF_NUM_MAX, GFP_KERNEL);
		if (!pf_dev->vf_item) {
			LOG_ERR("pf_dev->vf_item kzalloc failed\n");
			return -ENOMEM;
		}
	}

	return 0;
}

void dh_pf_vf_item_destroy(struct dh_core_dev *dev, bool disable_vf)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dev);

	if (dev->coredev_type == DH_COREDEV_PF) {
		if (disable_vf)
			pci_disable_sriov(dev->pdev);
		kfree(pf_dev->vf_item);
		pf_dev->vf_item = NULL;
	}
}

static bool is_sn_invalid(u8 sn_code[])
{
	bool all_zero = true;
	bool all_ff = true;
	u8 i = 0;

	for (i = 0; i < SN_CODE_LENGTH; ++i) {
		if (sn_code[i] != 0)
			all_zero = false;
		if (sn_code[i] != 0xff)
			all_ff = false;
		if (!all_zero && !all_ff)
			break;
	}

	return all_zero || all_ff;
}

#define DH_SN_OFFSET (0x5690)
static s32 zxdh_nic_sn_get(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct nic_sn_info sn_info = { 0 };
	u8 i = 0;
	char buf[128];
	int pos = 0;

	memcpy_fromio(&sn_info,
		      (void __iomem *)(uintptr_t)(pf_dev->pci_ioremap_addr[0] + DH_SN_OFFSET),
		      sizeof(struct nic_sn_info));

	if ((sn_info.fixed_sn_valid != 0xaa) && (sn_info.pseudo_sn_valid != 0xaa)) {
		memcpy(sn_info.sn_code, pci_name(dh_dev->pdev),
		       strlen(pci_name(dh_dev->pdev)) < SN_CODE_LENGTH ?
				     strlen(pci_name(dh_dev->pdev)) :
				     SN_CODE_LENGTH);
		sn_info.pseudo_sn_valid = 0xaa;
		memcpy_toio((void __iomem *)(uintptr_t)(pf_dev->pci_ioremap_addr[0] + DH_SN_OFFSET),
			    &sn_info, sizeof(struct nic_sn_info));
	}

	if (is_sn_invalid(sn_info.sn_code))
		return -2;

	memcpy(pf_dev->sn_code, sn_info.sn_code, SN_CODE_LENGTH);

	pos = scnprintf(buf, sizeof(buf), "[zxdh_pf][%s][%d] sn_code: ", __func__, __LINE__);
	for (i = 0; i < SN_CODE_LENGTH && pos < sizeof(buf) - 4; i++)
		pos += scnprintf(buf + pos, sizeof(buf) - pos, "%02x ", pf_dev->sn_code[i]);

	scnprintf(buf + pos, sizeof(buf) - pos, "\n");
	pr_info("%s", buf);
	return 0;
}

static s32 dh_pf_slot_id_get(struct zxdh_pf_device *pf_dev)
{
	u16 i = 0;

	for (i = 1; i < DPP_PCIE_SLOT_MAX; i++) {
		if (is_sn_invalid(dh_slot[i].sn_code)) {
			memcpy(dh_slot[i].sn_code, pf_dev->sn_code, SN_CODE_LENGTH);
			pf_dev->slot_id = i;
			break;
		}

		if (memcmp(pf_dev->sn_code, dh_slot[i].sn_code, SN_CODE_LENGTH) == 0) {
			pf_dev->slot_id = i;
			break;
		}
	}

	if (i == DPP_PCIE_SLOT_MAX)
		return -1;

	return 0;
}

s32 dh_pf_pcie_id_get(struct dh_core_dev *dh_dev)
{
	s32 pos = 0;
	u8 type = 0;
	u16 padding = 0;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct pci_dev *pdev = dh_dev->pdev;

	if (dh_dev->coredev_type == DH_COREDEV_PF) {
		if (zxdh_nic_sn_get(dh_dev)) {
			LOG_ERR("zxdh_nic_sn_get failed\n");
			return -1;
		}

		if (dh_pf_slot_id_get(pf_dev)) {
			LOG_ERR("dh_pf_slot_id_get failed\n");
			return -1;
		}
		LOG_INFO("slot_id: 0x%x\n", pf_dev->slot_id);
	}
	for (pos = pci_find_capability(pdev, PCI_CAP_ID_VNDR); pos > 0;
	     pos = pci_find_next_capability(pdev, pos, PCI_CAP_ID_VNDR)) {
		pci_read_config_byte(pdev, pos + offsetof(struct zxdh_pf_pci_cap, cfg_type), &type);

		if (type == ZXDH_PCI_CAP_PCI_CFG) {
			pci_read_config_word(
				pdev, pos + offsetof(struct zxdh_pf_pci_cap, padding[0]), &padding);
			pf_dev->pcie_id = padding;
			LOG_INFO("pcie_id: 0x%x\n", pf_dev->pcie_id);
			return 0;
		}
	}

	LOG_INFO("the pci_cap that meets the requirements is not matched\n");
	return -1;
}

static u64 pci_size(u64 base, u64 maxbase, u64 mask)
{
	u64 size = mask & maxbase;

	if (!size)
		return 0;
	size = size & ~(size - 1);
	if (base == maxbase && ((base | (size - 1)) & mask) != mask)
		return 0;
	return size;
}

s32 zxdh_send_pxe_status_to_riscv(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_cfg_np_msg msg = { 0 };
	u64 vaddr = 0;
	s32 err = 0;

	if (dh_dev->coredev_type != DH_COREDEV_PF)
		return 0;

	msg.dev_id = 0;
	msg.type = ZXDH_CFG_NPSDK_TYPE;
	msg.operate_mode = ZXDH_STOP_PXE_MODE;

	vaddr = (u64)ZXDH_BAR_MSG_BASE(pf_dev->pci_ioremap_addr[0]);

	err = zxdh_send_command(vaddr, pf_dev->pcie_id, MODULE_NPSDK, &msg, &msg, true);
	if (err != 0)
		LOG_ERR("send pxe status to config np failed: %d\n", err);

	return err;
}

s32 dh_pf_sriov_cap_cfg_init(struct dh_core_dev *dh_dev)
{
	s32 pos = 0;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct pci_dev *pdev = dh_dev->pdev;
	u32 bar_address32 = 0;
	u64 bar_address64 = 0;
	u64 bar_size64 = 0;
	u32 bar_size32 = 0;
	u64 mask64 = 0;
	u32 mem_type = 0;
	u16 nr_virtfn = 0;

	if (dh_dev->coredev_type == DH_COREDEV_VF)
		return 0;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	if (pos == 0)
		return 0;

	pci_read_config_word(pdev, pos + PCI_SRIOV_TOTAL_VF, &nr_virtfn);
	if (nr_virtfn == 0)
		return 0;

	pci_read_config_dword(pdev, pos + PCI_SRIOV_BAR, &bar_address32);
	pci_write_config_dword(pdev, pos + PCI_SRIOV_BAR, ~0);
	pci_read_config_dword(pdev, pos + PCI_SRIOV_BAR, &bar_size32);
	pci_write_config_dword(pdev, pos + PCI_SRIOV_BAR, bar_address32);

	bar_size64 = bar_size32 & PCI_BASE_ADDRESS_MEM_MASK;
	bar_address64 = bar_address32 & PCI_BASE_ADDRESS_MEM_MASK;
	mask64 = (u32)PCI_BASE_ADDRESS_MEM_MASK;
	mem_type = bar_address32 & PCI_BASE_ADDRESS_MEM_TYPE_MASK;

	if (mem_type == PCI_BASE_ADDRESS_MEM_TYPE_64) {
		pci_read_config_dword(pdev, pos + PCI_SRIOV_BAR + 4, &bar_address32);
		pci_write_config_dword(pdev, pos + PCI_SRIOV_BAR + 4, ~0);
		pci_read_config_dword(pdev, pos + PCI_SRIOV_BAR + 4, &bar_size32);
		pci_write_config_dword(pdev, pos + PCI_SRIOV_BAR + 4, bar_address32);

		bar_size64 |= ((u64)bar_size32 << 32);
		bar_address64 |= ((u64)bar_address32 << 32);
		mask64 |= ((u64)~0 << 32);
	}

	bar_size64 = pci_size(bar_address64, bar_size64, mask64);
	if (!bar_size64)
		LOG_ERR("reg 0x%x: invalid BAR (can't size)\n", pos);

	if (bar_address64 == 0) {
		pf_dev->pf_sriov_cap_base = NULL;
		return 0;
	}

	pf_dev->pf_sriov_cap_base = (void __iomem *)ioremap(bar_address64, bar_size64 * nr_virtfn);
	if (!pf_dev->pf_sriov_cap_base)
		LOG_ERR("ioremap(0x%llx, 0x%llx) failed\n", bar_address64, bar_size64 * nr_virtfn);

	pf_dev->sriov_bar_size = bar_size64;
	return 0;
}

static u8 zxdh_pf_fwcap_readb(struct dh_core_dev *dh_dev, u32 offset)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	u64 vaddr = (u64)ZXDH_BAR_FWCAP(pf_dev->pci_ioremap_addr[0]);

	return readb((void __iomem *)(uintptr_t)(vaddr + offset));
}

static bool zxdh_pf_is_ovs(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	u8 product = pf_dev->product_type;

	if (product == ZXDH_PRODUCT_OVS || product == ZXDH_PRODUCT_NEO ||
	    product == ZXDH_PRODUCT_EVB_EP0 || product == ZXDH_PRODUCT_EVB_EP0_EP4) {
		return true;
	}

	return false;
}

static bool zxdh_pf_is_bond_pf_in_ovs(struct dh_core_dev *dh_dev)
{
	if (dh_core_is_pf(dh_dev) && zxdh_pf_is_bond(dh_dev) && zxdh_pf_is_ovs(dh_dev))
		return true;

	return false;
}

static s32 zxdh_pf_lag_init(struct dh_core_dev *dh_dev, s32 *port_num)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	pf_dev->pannel_port_num = 1;

	if (zxdh_pf_is_bond(dh_dev) && !zxdh_pf_is_ovs(dh_dev)) {
		LOG_ERR("pf is not ovs\n");
		return -1;
	}

	if (!zxdh_pf_is_bond_pf_in_ovs(dh_dev))
		goto out;

	pf_dev->pannel_port_num = pf_dev->port_resource.pannel_num;
	zxdh_regitster_ldev(dh_dev);
	LOG_INFO("zxdh pf lag init finish(port num %d)\n", pf_dev->pannel_port_num);

out:
	*port_num = pf_dev->pannel_port_num;
	return 0;
}

static void zxdh_pf_lag_exit(struct dh_core_dev *dh_dev)
{
	if (!zxdh_pf_is_bond_pf_in_ovs(dh_dev))
		return;

	zxdh_unregitster_ldev(dh_dev);
}

s32 dh_pf_adevs_table_init(struct dh_core_dev *dh_dev, s32 nr)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	pf_dev->adevs_table = kcalloc(nr, sizeof(*pf_dev->adevs_table), GFP_KERNEL);
	if (!pf_dev->adevs_table) {
		pf_dev->adevs_num = 0;
		LOG_ERR("pf_dev->adevs_table kzalloc failed\n");
		return -ENOMEM;
	}

	pf_dev->adevs_num = nr;

	return 0;
}

s32 zxdh_pf_vf_qpairs_uninit(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_fw_compat fw_compat = pf_dev->fw_compat;
	u8 vf_qp_user_max = 0;
	u16 ep_id = 0;
	u16 pf_idx = 0;

	if (fw_compat.patch < 1)
		return 0;

	if (dh_dev->coredev_type != DH_COREDEV_PF)
		return 0;

	ep_id = EPID_GEN_FROM_VPORT(pf_dev->vport);
	pf_idx = GLOBAL_PF_IDX(ep_id, pf_dev->vport);

	vf_qp_user_max = ioread8((void __iomem *)(uintptr_t)(pf_dev->pci_ioremap_addr[0] +
							     ZXDH_VF_MAX_QUEUE_USER_OFFSET));
	iowrite8(vf_qp_user_max, (void __iomem *)(uintptr_t)(pf_dev->pci_ioremap_addr[0] +
							     ZXDH_VF_QUEUE_USER_OFFSET + pf_idx));

	return 0;
}

void dh_pf_adevs_table_destroy(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	kfree(pf_dev->adevs_table);
	pf_dev->adevs_table = NULL;
	pf_dev->adevs_num = 0;
}

void zxdh_unplug_aux_dev_all(struct dh_core_dev *dh_dev)
{
	s32 idx;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	for (idx = 0; idx < pf_dev->adevs_num; idx++)
		zxdh_unplug_aux_dev(dh_dev, idx);
}

s32 dh_pf_fw_compat_check(struct dh_core_dev *dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dev);
	struct zxdh_fw_compat *fw_compat = NULL;

	fw_compat =
		(struct zxdh_fw_compat *)((void __iomem *)(uintptr_t)pf_dev->pci_ioremap_addr[0] +
					  ZXDH_FW_VER_OFFSET);
	memcpy(&pf_dev->fw_compat, (u8 *)(uintptr_t)fw_compat, sizeof(struct zxdh_fw_compat));

	if (fw_compat->module_id != ZXDH_MODULE_ID) {
		LOG_INFO("The module id %u from fw version is wrong, ignore fw compat check\n",
			 fw_compat->module_id);
		return 0;
	}

	if (fw_compat->major != ZXDH_MAJOR) {
		LOG_ERR("drv major:%u is not match fw:%u!\n", ZXDH_MAJOR, fw_compat->major);
		return -1;
	}

	if (fw_compat->fw_minor < ZXDH_FW_MINOR) {
		LOG_ERR("drv fw_minor:%u is higher than fw:%u!\n", ZXDH_FW_MINOR,
			fw_compat->fw_minor);
		return -1;
	}

	if (fw_compat->drv_minor > ZXDH_DRV_MINOR) {
		LOG_ERR("drv drv_minor:%u is lower than fw:%u!\n", ZXDH_DRV_MINOR,
			fw_compat->drv_minor);
		return -1;
	}

	LOG_INFO("%s fw_compat.patch = %d", pci_name(dev->pdev), pf_dev->fw_compat.patch);
	if (pf_dev->fw_compat.patch >= DH_NEW_QUEEU_ALLOC_PATCH) {
		pf_dev->qtlb_offset = ioread32((void __iomem *)(uintptr_t)(
			pf_dev->pci_ioremap_addr[0] + ZXDH_VQ_TLB_OFFSET + 4));
		pf_dev->qtlb_offset = (pf_dev->qtlb_offset << 32) +
				      ioread32((void __iomem *)(uintptr_t)(
					      pf_dev->pci_ioremap_addr[0] + ZXDH_VQ_TLB_OFFSET));
		LOG_INFO("qtlb_offset: 0x%llx", pf_dev->qtlb_offset);

		if ((pf_dev->qtlb_offset + 2 * ZXDH_MAX_QUEUES_NUM) >
		    pci_resource_len(dev->pdev, 0)) {
			LOG_ERR("pf_dev->qtlb_offset out-off rang, over BAR0 size:%llx!",
				pci_resource_len(dev->pdev, 0));

			return -1;
		}
	}

	return 0;
}

void dh_pf_fwcap_init(struct dh_core_dev *dev)
{
#define FWCAP_BAR_READ_UNIT (4)
	struct zxdh_pf_device *pf_dev = dh_core_priv(dev);
	u32 idx = 0;
	u32 group = 0;

	group = sizeof(struct firmware_capability) / FWCAP_BAR_READ_UNIT;

	for (idx = 0; idx < group; idx++) {
		*((u32 *)&pf_dev->fwcap + idx) = ioread32(
			(void __iomem *)(uintptr_t)(pf_dev->pci_ioremap_addr[0] + ZXDH_FW_CAP_OFFSET) +
			idx * FWCAP_BAR_READ_UNIT);
	}

	pf_dev->board_type = ioread8((void __iomem *)(uintptr_t)pf_dev->pci_ioremap_addr[0] +
				     ZXDH_FW_CAP_OFFSET + 1);
	pf_dev->product_type = zxdh_pf_fwcap_readb(dev, ZXDH_PRODUCT_TYPE);
	LOG_INFO("%s, board_type: %d, product type: %d\n", pci_name(dev->pdev), pf_dev->board_type,
		 pf_dev->product_type);
}

void zxdh_pf_vq_pairs_config(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_pf_queue_info *pf_qinfo = NULL;

	pf_qinfo = (struct zxdh_pf_queue_info *)(uintptr_t)(pf_dev->pci_ioremap_addr[0] +
							    ZXDH_PF_QUEUE_INFO_OFFSET);
	pf_dev->vq_pairs = (pf_qinfo->pf_qp < ZXDH_QUEUE_PAIRS_MAX) ? pf_qinfo->pf_qp :
									    ZXDH_QUEUE_PAIRS_MAX;
	LOG_DEBUG("setup pf(vport:0x%x) queue pairs to %u\n", pf_dev->vport, pf_dev->vq_pairs);
}

void zxdh_pf_vf_vq_pairs_config(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	u16 ep_id = 0;
	u16 vf_idx = 0;
	u8 *addr = NULL;
	u8 val = 0;
	u8 power = 0;
	u8 vq_pairs = 0;

	/* vport bit[12:14] ep_id */
	ep_id = EPID_GEN_FROM_VPORT(pf_dev->vport);
	vf_idx = GLOBAL_VF_IDX(ep_id, pf_dev->vport);
	addr = (u8 *)(uintptr_t)pf_dev->pci_ioremap_addr[0] + ZXDH_VF_QUEUE_PAIRS_OFFSET +
	       (vf_idx / 2);
	val = ioread8((void __iomem *)addr);
	if (vf_idx % 2)
		power = (val & 0xf0) >> 4;
	else
		power = val & 0xf;

	vq_pairs = 1 << power;
	if (vq_pairs > ZXDH_QUEUE_PAIRS_MAX) {
		LOG_ERR("vf(vport:0x%x) get queue pairs:%u exceeds max value, using default:%u\n",
			pf_dev->vport, vq_pairs, ZXDH_QUEUE_PAIRS_MAX);
		vq_pairs = ZXDH_QUEUE_PAIRS_MAX;
	}
	pf_dev->vq_pairs = vq_pairs;
	LOG_DEBUG("setup vf(vport:0x%x) queue pairs to %u\n", pf_dev->vport, pf_dev->vq_pairs);
}

s32 zxdh_pf_vq_pairs_init(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_fw_compat fw_compat = pf_dev->fw_compat;

	if (zxdh_pf_is_special_bond(dh_dev) && (dh_dev->coredev_type == DH_COREDEV_PF)) {
		zxdh_pf_vq_pairs_config(dh_dev);
		return 0;
	}

	if (zxdh_pf_is_nic(dh_dev) == false)
		return 0;

	if (fw_compat.patch < 1) {
		pf_dev->vq_pairs = ZXDH_MAX_QPS_NUM;
		return 0;
	}

	if (dh_dev->coredev_type == DH_COREDEV_PF)
		zxdh_pf_vq_pairs_config(dh_dev);
	else
		zxdh_pf_vf_vq_pairs_config(dh_dev);

	return 0;
}

bool zxdh_pf_is_panel_port(struct dh_core_dev *dh_dev)
{
	if ((zxdh_pf_get_dev_type(dh_dev) == ZXDH_DEV_UPF) ||
	    (zxdh_pf_get_dev_type(dh_dev) == ZXDH_DEV_NE0) ||
	    (zxdh_pf_get_dev_type(dh_dev) == ZXDH_DEV_NE1)) {
		return false;
	}

	return true;
}

static int create_directory(const char *path)
{
	struct path parent_path;
	struct dentry *dentry;
	int ret;
	char *last_slash;
	char parent[128];
	char name[128];

	strscpy(parent, path, sizeof(parent));
	last_slash = strrchr(parent, '/');
	if (!last_slash)
		return -EINVAL;

	*last_slash = '\0';
	strscpy(name, last_slash + 1, sizeof(name));

	ret = kern_path(parent, LOOKUP_FOLLOW, &parent_path);
	DH_LOG_DEBUG(MODULE_PF, "check parent path %s, ret is %d\n", parent, ret);
	if (ret)
		return ret;

	inode_lock_nested(parent_path.dentry->d_inode, I_MUTEX_PARENT);

	dentry = lookup_one_len(name, parent_path.dentry, zte_strlen_s(name));
	if (IS_ERR(dentry)) {
		ret = PTR_ERR(dentry);
		path_put(&parent_path);
		DH_LOG_DEBUG(MODULE_PF, "lookup_one_len error, ret is %d\n", ret);
		inode_unlock(parent_path.dentry->d_inode);
		return ret;
	}

	ret = vfs_mkdir(&nop_mnt_idmap, d_inode(parent_path.dentry), dentry, 0755);
	dput(dentry);

	inode_unlock(parent_path.dentry->d_inode);
	path_put(&parent_path);

	DH_LOG_DEBUG(MODULE_PF, "mkdir %s, ret is %d\n", path, ret);
	return ret;
}

static int create_directory_recursion(const char *path)
{
	int ret = 0;
	char *temp_path = NULL;
	char *slash = NULL;

	temp_path = kmalloc(zte_strlen_s(path) + 1, GFP_KERNEL);
	if (!temp_path)
		return -ENOMEM;

	ret = zte_snprintf_s(temp_path, zte_strlen_s(path) + 1, "%s", path);
	if (ret < 0) {
		LOG_ERR("zte_snprintf_s %s failed, ret=%d\n", path, ret);
		kfree(temp_path);
		return ret;
	}
	slash = temp_path;

	while ((slash = strchr(slash + 1, '/')) != NULL) {
		*slash = '\0';

		DH_LOG_DEBUG(MODULE_PF, "start create %s\n", temp_path);
		ret = create_directory(temp_path);
		if (ret && ret != -EEXIST) {
			kfree(temp_path);
			return ret;
		}

		*slash = '/';
	}

	ret = create_directory(temp_path);
	kfree(temp_path);
	return ret;
}

s32 zxdh_pf_update_hb_file_val(struct dh_core_dev *dh_dev, u64 spec_sbdf, const char *file_name,
			       bool flag)
{
	struct file *file = NULL;
	s32 ret = 0;
	char dir_path[128];
	char xxx_file_path[128];
	const char *target_content = flag ? "1" : "0";
	loff_t pos = 0;

	zte_snprintf_s(dir_path, sizeof(dir_path), "/etc/dinghai/net/%llx", spec_sbdf);
	zte_snprintf_s(xxx_file_path, sizeof(xxx_file_path), "%s/%s", dir_path, file_name);

	file = filp_open(xxx_file_path, O_WRONLY | O_TRUNC, 0);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		if (ret == -ENOENT) {
			LOG_INFO("File %s does not exist, attempting to create it.\n",
				 xxx_file_path);
		} else {
			LOG_ERR("Error opening file %s: %d\n", xxx_file_path, ret);
			return ret;
		}

		// Create directory if it doesn't exist
		ret = create_directory_recursion(dir_path);
		if (ret && ret != -EEXIST) {
			LOG_ERR("Failed to create directory %s: %d\n", dir_path, ret);
			return ret;
		}

		// Reopen file after directory creation
		file = filp_open(xxx_file_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
		if (IS_ERR(file)) {
			LOG_ERR("Error creating file %s: %ld\n", xxx_file_path, PTR_ERR(file));
			return -1;
		}
	}

	// Write target content to the file
	ret = kernel_write(file, target_content, zte_strlen_s(target_content), &pos);
	if (ret < 0) {
		LOG_ERR("Failed to write to file %s: %d\n", xxx_file_path, ret);
		filp_close(file, NULL);
		return ret;
	}

	filp_close(file, NULL);
	LOG_INFO("Updated content %s to file %s\n", target_content, xxx_file_path);
	return 0;
}

s32 zxdh_read_file_val(const char *xxx_file_path)
{
	struct file *file;
	ssize_t bytes_read;
	loff_t pos = 0;
	char buffer[16] = { 0 };
	size_t buffer_size = sizeof(buffer);
	int result = -1;

	file = filp_open(xxx_file_path, O_RDONLY, 0);
	if (IS_ERR(file)) {
		LOG_ERR("open %s failed\n", xxx_file_path);
		return -1;
	}

	bytes_read = kernel_read(file, buffer, buffer_size - 1, &pos);

	if (bytes_read != 1) {
		LOG_ERR("read %s failed, bytes_read %zd\n", xxx_file_path, bytes_read);
		goto cleanup;
	}

	result = (buffer[0] == '0') ? 0 : 1;
	LOG_INFO("%s buffer val: %s\n", xxx_file_path, buffer);

cleanup:
	filp_close(file, NULL);
	return result;
}

void zxdh_hardware_bond_files_process(struct dh_core_dev *dh_dev)
{
	char solid_file_path[128];
	char primary_file_path[128];
	struct path solid_path, primary_path;
	bool is_primary_port;
	s32 ret = 0;
	u16 pf_id = 0;
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	zxdh_pf_get_rp_sbdf(dh_dev);
	pf_id = (pf_dev->pcie_id >> 8) & 0x7;
	pf_dev->spec_sbdf = ((pf_dev->rp_sbdf) << 8) | (pf_id);
	LOG_INFO("spec_sbdf: %#llx, pf_id: %d\n", pf_dev->spec_sbdf, pf_id);

	/* do nothing if vf */
	if (zxdh_pf_get_coredev_type(dh_dev) == DH_COREDEV_VF || zxdh_pf_is_special_bond(dh_dev)) {
		pf_dev->is_hwbond = false;
		pf_dev->is_rdma_aux_plug = true;
		pf_dev->is_primary_port = true;
		return;
	}

	zte_snprintf_s(solid_file_path, sizeof(solid_file_path), "/etc/dinghai/net/%llx/solid",
		       pf_dev->spec_sbdf);
	zte_snprintf_s(primary_file_path, sizeof(primary_file_path),
		       "/etc/dinghai/net/%llx/primary", pf_dev->spec_sbdf);

	if (kern_path(solid_file_path, LOOKUP_FOLLOW, &solid_path) ||
	    kern_path(primary_file_path, LOOKUP_FOLLOW, &primary_path)) {
		goto no_solid;
	}
	LOG_INFO("solid and primary file exist\n");

	ret = zxdh_read_file_val(solid_file_path);
	if (ret != 1) {
		LOG_INFO("solid config is off\n");
		goto no_solid;
	}
	pf_dev->is_hwbond = true;

	ret = zxdh_read_file_val(primary_file_path);
	if (ret == -1) {
		LOG_INFO("primary config is off\n");
		goto no_solid;
	}

	is_primary_port = (!ret) ? false : true;

	if (is_primary_port) {
		pf_dev->is_primary_port = true;
		pf_dev->is_rdma_aux_plug = true;
	} else {
		pf_dev->is_primary_port = false;
		pf_dev->is_rdma_aux_plug = false;
	}
	LOG_INFO("is_hwbond %d, is_primary_port %d, is_rdma_aux_plug %d\n", pf_dev->is_hwbond,
		 pf_dev->is_primary_port, pf_dev->is_rdma_aux_plug);
	zxdh_pf_optim_hardware_bond_time(dh_dev, true);
	goto out;

no_solid:

	pf_dev->is_hwbond = false;
	pf_dev->is_rdma_aux_plug = true;
	pf_dev->is_primary_port = true;
	zxdh_pf_optim_hardware_bond_time(dh_dev, false);
	zxdh_pf_update_hb_file_val(dh_dev, pf_dev->spec_sbdf, "solid", pf_dev->is_hwbond);
	zxdh_pf_update_hb_file_val(dh_dev, pf_dev->spec_sbdf, "primary", pf_dev->is_primary_port);
	LOG_INFO("Reached no_solid. Create/Update config file. Exiting function\n");
out:
	return;
}

static s32 dh_pf_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct dh_core_dev *dh_dev = NULL;
	struct zxdh_pf_device *pf_dev = NULL;
	struct devlink *devlink = NULL;
	s32 ret = 0;
	s32 idx = 0;
	s32 port_num = 0;

	LOG_INFO("pf level start\n");
#ifdef ZTE_SAFE_FUNC_TEST
	recording_not_safe_func();
#endif

	if ((GET_COREDEV_TYPE(pdev) != DH_COREDEV_PF) && (probe_vf == 0)) {
		LOG_INFO("probe_vf is N, VF is not allowed to probe\n");
		return -1;
	}

	devlink = zxdh_devlink_alloc(&pdev->dev, &dh_pf_devlink_ops, sizeof(struct zxdh_pf_device));
	if (!devlink) {
		LOG_ERR("devlink alloc failed\n");
		return -ENOMEM;
	}

	dh_dev = devlink_priv(devlink);
	dh_dev->device = &pdev->dev;
	dh_dev->pdev = pdev;
	dh_dev->devlink_ops = &dh_pf_core_devlink_ops;

	pf_dev = dh_core_priv(dh_dev);
	pf_dev->bar_chan_valid = false;
	pf_dev->vepa = false;
	pf_dev->plcr_table.is_init = false;
	mutex_init(&dh_dev->lock);

	dh_dev->coredev_type = GET_COREDEV_TYPE(pdev);
	LOG_DEBUG("%s device: %s\n", (dh_dev->coredev_type == DH_COREDEV_PF) ? "PF" : "VF",
		  pci_name(pdev));

	ret = dh_pf_pci_init(dh_dev);
	if (ret != 0) {
		LOG_ERR("dh_pf_pci_init failed: %d\n", ret);
		goto err_irq_table_init;
	}

	ret = zxdh_pf_modern_cfg_init(dh_dev);
	if (ret != 0) {
		LOG_ERR("zxdh_pf_modern_cfg_init failed: %d\n", ret);
		goto err_cfg_init;
	}

	ret = zxdh_pf_wait_bar_ok(dh_dev);
	if (ret != 0) {
		LOG_ERR("%s wait_bar_ok time out\n", pci_name(dh_dev->pdev));
		goto err_pci;
	}

	ret = dh_pf_fw_compat_check(dh_dev);
	if (ret != 0) {
		LOG_ERR("The driver version and firmware version are incompatible\n");
		goto err_pci;
	}

	dh_pf_fwcap_init(dh_dev);

	ret = dh_pf_wait_riscv_ready(dh_dev);
	if (ret != 0) {
		LOG_ERR("%s wait_riscv_ready time out\n", pci_name(dh_dev->pdev));
		goto err_pci;
	}

	ret = dh_pf_pcie_id_get(dh_dev);
	if (ret != 0) {
		LOG_ERR("dh_pf_pcie_id_get failed: %d\n", ret);
		goto err_pci;
	}

	ret = dh_pf_vf_item_create(dh_dev);
	if (ret != 0) {
		LOG_ERR("Failed to alloc vf item\n");
		goto err_cfg_init;
	}

	ret = dh_pf_irq_table_init(dh_dev);
	if (ret != 0) {
		LOG_ERR("Failed to alloc IRQs\n");
		goto err_vf_item;
	}

	ret = dh_pf_eq_table_init(dh_dev);
	if (ret != 0) {
		LOG_ERR("Failed to alloc IRQs\n");
		goto err_eq_table_init;
	}

	ret = dh_pf_events_init(dh_dev);
	if (ret != 0) {
		LOG_ERR("failed to initialize events\n");
		goto err_events_init;
	}

	ret = dh_pf_irq_table_create(dh_dev);
	if (ret != 0) {
		LOG_ERR("Failed to alloc IRQs\n");
		goto err_irq_table_create;
	}

	ret = dh_pf_eq_table_create(dh_dev);
	if (ret != 0) {
		LOG_ERR("Failed to alloc EQs\n");
		goto err_eq_table_create;
	}

	ret = dh_pf_sriov_cap_cfg_init(dh_dev);
	if (ret != 0) {
		LOG_ERR("dh_pf_sriov_cap_cfg_init failed: %d\n", ret);
		goto err_sriov_cap_init;
	}

	ret = zxdh_send_pxe_status_to_riscv(dh_dev);
	if (ret != 0) {
		LOG_ERR("zxdh_send_pxe_status_to_riscv failed: %d\n", ret);
		goto err_send_pxe_status;
	}

	zxdh_devlink_register(devlink);

	ret = zxdh_vf_compat_check(dh_dev);
	if (ret != 0) {
		LOG_ERR("zxdh_vf_check_compat failed: %d\n", ret);
		goto err_vf_compat;
	}

	ret = zxdh_pf_dpp_init(dh_dev, true);
	if (ret != 0) {
		LOG_ERR("zxdh_pf_dpp_init failed: %d\n", ret);
		goto err_dpp_init;
	}

	ret = zxdh_pf_query_fwinfo(dh_dev);
	if (ret != 0) {
		LOG_ERR("zxdh_pf_query_fwinfo failed: %d\n", ret);
		goto err_query_fwinfo;
	}

	ret = zxdh_pf_vq_pairs_init(dh_dev);
	if (ret != 0) {
		LOG_ERR("zxdh_pf_vq_pairs_init failed: %d\n", ret);
		goto err_query_fwinfo;
	}

	ret = zxdh_pf_lag_init(dh_dev, &port_num);
	if (ret != 0) {
		LOG_ERR("zxdh_pf_lag_init failed: %d\n", ret);
		goto err_query_fwinfo;
	}

#ifdef PTP_DRIVER_INTERFACE_EN
	if (dh_dev->coredev_type == DH_COREDEV_PF) {
		ret = zxdh_ptp_init(dh_dev);
		if (ret != 0) {
			LOG_ERR("zxdh_ptp_init failed: %d\n", ret);
			goto err_ptp_init;
		}
	}
#endif

#ifdef CONFIG_DINGHAI_TSN
	if (zxdh_pf_is_panel_port(dh_dev)) {
		ret = zxdh_tsn_init(dh_dev);
		if (ret != 0) {
			LOG_ERR("zxdh_tsn_init failed: %d\n", ret);
			goto err_tsn_init;
		}
	}
#endif

#ifdef ZXDH_SRIOV_SYSFS_EN
	ret = zxdh_sriov_sysfs_init(dh_dev);
	if (ret != 0) {
		LOG_ERR("zxdh_sriov_sysfs_init failed: %d, vport = %x\n", ret, pf_dev->vport);
		goto err_sriov_sysfs;
	}
#endif

	ret = zxdh_init_ip6mac_tbl(dh_dev);
	if (ret != 0) {
		LOG_ERR("zxdh_init_ip6mac_tbl failed: %d, vport = %x\n", ret, pf_dev->vport);
		goto err_init_ip6mac_tbl;
	}

	ret = zxdh_health_init(dh_dev);
	if (ret != 0) {
		LOG_ERR("zxdh_health_init failed: %d\n", ret);
		goto err_health_init;
	}

	ret = dh_pf_adevs_table_init(dh_dev, port_num);
	if (ret != 0) {
		LOG_ERR("dh_pf_adevs_table_init failed: %d\n", ret);
		goto err_adevs_tbl_init;
	}

	if (!zxdh_pf_is_bond(dh_dev) && zxdh_pf_is_panel_port(dh_dev))
		zxdh_hardware_bond_files_process(dh_dev);

	for (idx = 0; idx < port_num; idx++)
		zxdh_plug_aux_dev(dh_dev, idx);

	LOG_INFO("pf level completed\n");

	return 0;

err_adevs_tbl_init:
	zxdh_drain_health_wq(dh_dev);
	zxdh_health_cleanup(dh_dev);
err_health_init:
	zxdh_cleanup_ip6mac_tbl(dh_dev);
err_init_ip6mac_tbl:
#ifdef ZXDH_SRIOV_SYSFS_EN
	zxdh_sriov_sysfs_exit(dh_dev);
err_sriov_sysfs:
#endif
#ifdef CONFIG_DINGHAI_TSN
	if (zxdh_pf_is_panel_port(dh_dev))
		zxdh_tsn_exit(dh_dev);
err_tsn_init:
#endif
#ifdef PTP_DRIVER_INTERFACE_EN
	if (dh_dev->coredev_type == DH_COREDEV_PF)
		zxdh_ptp_stop(dh_dev);
err_ptp_init:
#endif
	zxdh_pf_lag_exit(dh_dev);
err_query_fwinfo:
	zxdh_pf_dpp_uninit(dh_dev);
err_dpp_init:
err_vf_compat:
	zxdh_devlink_unregister(devlink);
err_send_pxe_status:
	dh_pf_sriov_cap_cfg_uninit(dh_dev);
err_sriov_cap_init:
	dh_pf_eq_table_destroy(dh_dev);
err_eq_table_create:
	dh_pf_irq_table_destroy(dh_dev);
err_irq_table_create:
	dh_pf_events_uninit(dh_dev);
err_events_init:
	dh_eq_table_cleanup(dh_dev);
err_eq_table_init:
	dh_irq_table_cleanup(dh_dev);
err_vf_item:
	dh_pf_vf_item_destroy(dh_dev, true);
err_pci:
	zxdh_pf_modern_cfg_uninit(dh_dev);
err_cfg_init:
	dh_pf_pci_close(dh_dev);
err_irq_table_init:
	mutex_destroy(&dh_dev->lock);
	zxdh_devlink_free(devlink);
	pf_dev = NULL;
	return -EPERM;
}

s32 zxdh_pf_vf_qpairs_init(struct dh_core_dev *dev, s32 num_vfs);
int zxdh_load_one(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);
	struct zxdh_core_health *health = &pf_dev->health;
	int ret = 0;

	mutex_lock(&dh_dev->lock);
	if (dh_dev->device_state == ZXDH_DEVICE_STATE_UP)
		goto unlock;

	if (dh_dev->driver_process == ZXDH_REMOVE) {
		ret = -1;
		goto unlock;
	}

	if (dh_dev->coredev_type == DH_COREDEV_VF) {
		ret = zxdh_vf_wait_pf_ok(dh_dev);
		if (ret != 0) {
			HEAL_ERR("%s zxdh_vf_wait_pf_ok failed: %d\n", pci_name(dh_dev->pdev), ret);
			goto unlock;
		}
	} else if (dh_dev->coredev_type == DH_COREDEV_PF) {
		if (pf_dev->num_vfs > 0) {
			ret = zxdh_pf_vf_qpairs_init(dh_dev, (s32)(pf_dev->num_vfs));
			if (ret != 0) {
				HEAL_ERR("Failed to recover vf queue pairs\n");
				goto unlock;
			}
		}
	}

	ret = dh_pf_irq_table_create(dh_dev);
	if (ret != 0) {
		HEAL_ERR("%s Failed to alloc IRQs\n", pci_name(dh_dev->pdev));
		goto unlock;
	}

	ret = dh_pf_eq_table_create(dh_dev);
	if (ret != 0) {
		HEAL_ERR("%s Failed to alloc EQs\n", pci_name(dh_dev->pdev));
		goto irq_table_destroy;
	}

	ret = zxdh_pf_dpp_reset(dh_dev);
	if (ret != 0) {
		HEAL_ERR("%s zxdh_pf_dpp_reset failed: %d\n", pci_name(dh_dev->pdev), ret);
		goto eq_table_destroy;
	}

	ret = zxdh_pf_dpp_init(dh_dev, false);
	if (ret != 0) {
		HEAL_ERR("%s zxdh_pf_dpp_init failed: %d\n", pci_name(dh_dev->pdev), ret);
		goto eq_table_destroy;
	}

	ret = zxdh_pf_call_aux_events(dh_dev, DH_EVENT_TYPE_AUX_LOAD);
	if (ret != 0) {
		HEAL_ERR("%s DH_EVENT_TYPE_AUX_LOAD failed: %d\n", pci_name(dh_dev->pdev), ret);
		goto dpp_uninit;
	}

	pf_dev->fast_unload = false;
	dh_dev->device_state = ZXDH_DEVICE_STATE_UP;
	health->recovery_cnt++;
	HEAL_INFO("%s %s success\n", __func__, pci_name(dh_dev->pdev));
	mutex_unlock(&dh_dev->lock);
	return 0;

dpp_uninit:
	zxdh_pf_dpp_uninit(dh_dev);
eq_table_destroy:
	dh_pf_eq_table_destroy(dh_dev);
irq_table_destroy:
	dh_pf_irq_table_destroy(dh_dev);
unlock:
	mutex_unlock(&dh_dev->lock);
	return ret;
}

static void zxdh_reset_all_vf_item(struct dh_core_dev *dh_dev)
{
	struct zxdh_vf_item *vf_item = NULL;
	u16 num_vfs = 0;
	u16 vf_idx = 0;

	if (dh_dev->coredev_type == DH_COREDEV_VF)
		return;

	num_vfs = pci_num_vf(dh_dev->pdev);
	for (vf_idx = 0; vf_idx < num_vfs; vf_idx++) {
		vf_item = zxdh_pf_get_vf_item(dh_dev, vf_idx);
		vf_item->is_probed = false;
	}
}

void zxdh_unload_one(struct dh_core_dev *dh_dev)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	HEAL_INFO("%s %s start\n", __func__, pci_name(dh_dev->pdev));
	mutex_lock(&dh_dev->lock);
	if (dh_dev->driver_process == ZXDH_REMOVE) {
		mutex_unlock(&dh_dev->lock);
		return;
	}
	pf_dev->fast_unload = true;
	pf_dev->aux_comp_flag = 0;
	zxdh_pf_call_aux_events(dh_dev, DH_EVENT_TYPE_AUX_UNLOAD);
	dh_pf_eq_table_destroy(dh_dev);
	dh_pf_irq_table_destroy(dh_dev);
	zxdh_reset_all_vf_item(dh_dev);
	mutex_unlock(&dh_dev->lock);
}

static void dh_pf_remove(struct pci_dev *pdev)
{
	struct dh_core_dev *dh_dev = pci_get_drvdata(pdev);
	struct devlink *devlink = priv_to_devlink(dh_dev);
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	if (!pf_dev)
		return;
	LOG_INFO("pf level start\n");
	if (!zxdh_pf_check_remove_state(dh_dev)) {
		pf_dev->quick_remove = true;
		LOG_INFO("%s: quick_remove start\n", pci_name(pdev));
	}

	mutex_lock(&dh_dev->lock);
	dh_dev->driver_process = ZXDH_REMOVE;
	mutex_unlock(&dh_dev->lock);
	zxdh_unplug_aux_dev_all(dh_dev);
	dh_pf_adevs_table_destroy(dh_dev);

	zxdh_drain_health_wq(dh_dev);
	zxdh_health_cleanup(dh_dev);

	zxdh_cleanup_ip6mac_tbl(dh_dev);
#ifdef ZXDH_SRIOV_SYSFS_EN
	zxdh_sriov_sysfs_exit(dh_dev);
#endif
#ifdef CONFIG_DINGHAI_TSN
	if (zxdh_pf_is_panel_port(dh_dev))
		zxdh_tsn_exit(dh_dev);
#endif
#ifdef PTP_DRIVER_INTERFACE_EN
	if (dh_dev->coredev_type == DH_COREDEV_PF)
		zxdh_ptp_stop(dh_dev);
#endif
	zxdh_pf_vf_qpairs_uninit(dh_dev);

	zxdh_pf_lag_exit(dh_dev);
	zxdh_pf_dpp_uninit(dh_dev);

	zxdh_devlink_unregister(devlink);
	dh_pf_sriov_cap_cfg_uninit(dh_dev);
	if (!pf_dev->fast_unload) {
		dh_pf_eq_table_destroy(dh_dev);
		dh_pf_irq_table_destroy(dh_dev);
	}
	dh_pf_events_uninit(dh_dev);
	dh_eq_table_cleanup(dh_dev);
	dh_irq_table_cleanup(dh_dev);
	dh_pf_vf_item_destroy(dh_dev, true);
	zxdh_pf_modern_cfg_uninit(dh_dev);
	dh_pf_pci_close(dh_dev);
	mutex_destroy(&dh_dev->lock);
	zxdh_devlink_free(devlink);

	pci_set_drvdata(pdev, NULL);
	LOG_INFO("pf level completed\n");
}

static s32 dh_pf_suspend(struct pci_dev *pdev, pm_message_t state)
{
	return 0;
}

static s32 dh_pf_resume(struct pci_dev *pdev)
{
	return 0;
}

static void dh_pf_shutdown(struct pci_dev *pdev)
{
	struct dh_core_dev *dh_dev = pci_get_drvdata(pdev);
	struct devlink *devlink = priv_to_devlink(dh_dev);
	struct zxdh_pf_device *pf_dev = dh_core_priv(dh_dev);

	LOG_INFO("pf level start\n");
	mutex_lock(&dh_dev->lock);
	dh_dev->driver_process = ZXDH_REMOVE;
	mutex_unlock(&dh_dev->lock);

	dh_pf_adevs_table_destroy(dh_dev);

	zxdh_drain_health_wq(dh_dev);
	zxdh_health_cleanup(dh_dev);

	zxdh_cleanup_ip6mac_tbl(dh_dev);
#ifdef ZXDH_SRIOV_SYSFS_EN
	zxdh_sriov_sysfs_exit(dh_dev);
#endif
#ifdef CONFIG_DINGHAI_TSN
	if (!zxdh_pf_is_upf(dh_dev))
		zxdh_tsn_exit(dh_dev);
#endif
#ifdef PTP_DRIVER_INTERFACE_EN
	if (dh_dev->coredev_type == DH_COREDEV_PF)
		zxdh_ptp_stop(dh_dev);
#endif

	zxdh_pf_lag_exit(dh_dev);
	if (!pf_dev->fast_unload)
		zxdh_pf_dpp_uninit(dh_dev);

	zxdh_devlink_unregister(devlink);
	dh_pf_sriov_cap_cfg_uninit(dh_dev);
	if (!pf_dev->fast_unload) {
		dh_pf_eq_table_destroy(dh_dev);
		dh_pf_irq_table_destroy(dh_dev);
	}
	dh_pf_events_uninit(dh_dev);
	dh_eq_table_cleanup(dh_dev);
	dh_irq_table_cleanup(dh_dev);
	dh_pf_vf_item_destroy(dh_dev, false);
	zxdh_pf_modern_cfg_uninit(dh_dev);

	dh_pf_pci_close(dh_dev);
	mutex_destroy(&dh_dev->lock);
	zxdh_devlink_free(devlink);

	pci_set_drvdata(pdev, NULL);
	LOG_INFO("pf level completed\n");
}

static pci_ers_result_t dh_pci_err_detected(struct pci_dev *pdev, pci_channel_state_t state)
{
	// LOG_INFO("PCI error detected\n");

	return state == pci_channel_io_perm_failure ? PCI_ERS_RESULT_DISCONNECT :
							    PCI_ERS_RESULT_NEED_RESET;
}

static pci_ers_result_t dh_pf_pci_slot_reset(struct pci_dev *pdev)
{
	// LOG_INFO("start PCI slot reset\n");
	return PCI_ERS_RESULT_RECOVERED;
}

static void dh_pf_pci_resume(struct pci_dev *pdev)
{
	// LOG_INFO("start PCI resume\n");
}

s32 zxdh_user_vf_qpairs_update(struct dh_core_dev *dev, u8 vf_qp, u16 pf_idx)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dev);

	iowrite8(vf_qp, (void __iomem *)(uintptr_t)(pf_dev->pci_ioremap_addr[0] +
						    ZXDH_VF_QUEUE_USER_OFFSET + pf_idx));
	return 0;
}

s32 zxdh_pf_vf_qpairs_update(struct dh_core_dev *dev, u8 vf_qp, s32 num_vfs)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dev);
	u8 power = 0;
	s32 ret = 0;
	u16 vport = 0;
	u16 vf_idx = 0;
	u16 ep_id = 0;
	s32 i = 0;
	u8 *addr = NULL;
	u8 val = 0;

	if (vf_qp == 0)
		return -1;

	while ((1U << power) <= vf_qp)
		power++;
	power--;
	vf_qp = 1 << power;
	LOG_DEBUG("pf(vport:0x%x) setup vf queue pairs:%u, power:%u\n", pf_dev->vport, vf_qp,
		  power);

	ret = dh_pf_vf_vport_get(dev, 0, &vport);
	if (ret != 0) {
		LOG_ERR("Failed to pf(vport:0x%x) get vf0 vport\n", pf_dev->vport);
		return ret;
	}

	/* vport bit[12:14] ep_id */
	ep_id = EPID_GEN_FROM_VPORT(pf_dev->vport);
	if (ep_id >= ZXDH_EP_NUM) {
		LOG_ERR("vf vport is err, ep_id:%u\n", ep_id);
		return -1;
	}

	for (i = 0; i < num_vfs; i++) {
		vf_idx = GLOBAL_VF_IDX(ep_id, vport) + i;
		addr = (u8 *)(uintptr_t)pf_dev->pci_ioremap_addr[0] + ZXDH_VF_QUEUE_PAIRS_OFFSET +
		       (vf_idx / 2);
		val = ioread8((void __iomem *)addr);
		if (vf_idx % 2)
			val = (val & 0xf) | (power << 4);
		else
			val = (val & 0xf0) | power;

		iowrite8(val, (void __iomem *)addr);
	}

	return 0;
}

s32 zxdh_pf_vf_qpairs_init(struct dh_core_dev *dev, s32 num_vfs)
{
	struct zxdh_pf_device *pf_dev = dh_core_priv(dev);
	struct zxdh_dev_queue_info *dev_qinfo = NULL;
	struct zxdh_pf_queue_info *pf_qinfo = NULL;
	struct zxdh_fw_compat fw_compat = pf_dev->fw_compat;
	u16 ep_id = 0;
	u16 pf_idx = 0;
	u16 vf_qp_flx = 0;
	u8 vf_qp_user_max = 0;
	u8 vf_qp = 0;
	s32 ret = 0;

	if (!zxdh_pf_is_nic(dev) || fw_compat.patch < 1)
		return 0;

	ep_id = EPID_GEN_FROM_VPORT(pf_dev->vport);
	pf_idx = GLOBAL_PF_IDX(ep_id, pf_dev->vport);

	dev_qinfo = (struct zxdh_dev_queue_info *)(uintptr_t)(
		pf_dev->pci_ioremap_addr[0] + ZXDH_DEV_QUEUE_INFO_OFFSET + pf_idx * 4);
	pf_qinfo = (struct zxdh_pf_queue_info *)(uintptr_t)(pf_dev->pci_ioremap_addr[0] +
							    ZXDH_PF_QUEUE_INFO_OFFSET);
	LOG_DEBUG(
		"pf(vport:0x%x) get queue config: total_qp:%u, start_qp_id:%u, pf_qp:%u, vf_qp:%u\n",
		pf_dev->vport, dev_qinfo->total_qp, dev_qinfo->start_id, pf_qinfo->pf_qp,
		pf_qinfo->vf_qp);

#ifdef ZXDH_MSGQ
	vf_qp_flx = (dev_qinfo->total_qp - pf_dev->vq_pairs - 1) / num_vfs;
#else
	vf_qp_flx = (dev_qinfo->total_qp - pf_dev->vq_pairs) / num_vfs;
#endif

	vf_qp = (pf_qinfo->vf_qp < vf_qp_flx) ? pf_qinfo->vf_qp : vf_qp_flx;
	ret = zxdh_pf_vf_qpairs_update(dev, vf_qp, num_vfs);
	if (ret != 0) {
		LOG_DEBUG("Failed to pf(vport:0x%x) setup vf queue pairs to %u\n", pf_dev->vport,
			  vf_qp);
		return ret;
	}

	vf_qp_user_max = ioread8((void __iomem *)(uintptr_t)(pf_dev->pci_ioremap_addr[0] +
							     ZXDH_VF_MAX_QUEUE_USER_OFFSET));
	vf_qp = (vf_qp_user_max < vf_qp_flx) ? vf_qp_user_max : vf_qp_flx;

	zxdh_user_vf_qpairs_update(dev, vf_qp, pf_idx);

	return 0;
}

s32 dh_pf_sriov_configure(struct pci_dev *pdev, s32 num_vfs)
{
	struct dh_core_dev *dev = pci_get_drvdata(pdev);
	struct zxdh_pf_device *pf_dev = dh_core_priv(dev);
	struct zxdh_rdma_sriov_event_info rdma_sriov_info = { 0 };

	if (dev->coredev_type != DH_COREDEV_PF) {
		LOG_ERR("This device is not capable of SR-IOV\n");
		return -EOPNOTSUPP;
	}

	if (!pf_dev->pf_sriov_cap_base) {
		LOG_ERR("sriov not enable\n");
		return -EOPNOTSUPP;
	}

	if (num_vfs > 0) {
		if (zxdh_pf_vf_qpairs_init(dev, num_vfs) != 0) {
			LOG_ERR("Failed to init vf queue pairs\n");
			return -1;
		}

		if (zxdh_pf_is_rdma_enable(dev)) {
			rdma_sriov_info.pdev = pdev;
			rdma_sriov_info.bar0_virt_addr = pf_dev->pci_ioremap_addr[0];
			rdma_sriov_info.vport_id = pf_dev->vport;
			rdma_sriov_info.num_vfs = num_vfs;
			zxdh_rdma_events_call(NULL, ZXDH_RDMA_SRIOV_EVENT, &rdma_sriov_info);
		}

		if (dh_pf_sriov_enable(pdev, num_vfs) != 0) {
			LOG_ERR("Failed to enable sriov, num_vfs:%d\n", num_vfs);
			return -1;
		}
	} else {
		dh_pf_sriov_disable(pdev);
	}

	if (zxdh_pf_pcie_config_store(dev))
		LOG_ERR("zxdh_pf_pcie_config_store failed\n");

	pf_dev->num_vfs = (u16)num_vfs;

	return num_vfs;
}

static const struct pci_error_handlers dh_pf_err_handler = { .error_detected = dh_pci_err_detected,
							     .slot_reset = dh_pf_pci_slot_reset,
							     .resume = dh_pf_pci_resume };

static struct pci_driver dh_pf_driver = {
	.name = KBUILD_MODNAME,
	.id_table = dh_pf_pci_table,
	.probe = dh_pf_probe,
	.remove = dh_pf_remove,
	.suspend = dh_pf_suspend,
	.resume = dh_pf_resume,
	.shutdown = dh_pf_shutdown,
	.err_handler = &dh_pf_err_handler,
	.sriov_configure = dh_pf_sriov_configure,
};

static s32 __init dh_pf_pci_init_module(void)
{
	s32 ret = 0;

	LOG_INFO("%s - version %s %s\n", zxdh_pf_driver_string, zxdh_pf_driver_version,
		 zxdh_pf_copyright);

	ret = pci_register_driver(&dh_pf_driver);
	if (ret != 0) {
		LOG_ERR("pci_register_driver failed: %d\n", ret);
		goto err_register_driver;
	}

	ret = dh_pf_msg_recv_func_register();
	if (ret != 0) {
		LOG_ERR("dh_pf_msg_recv_func_register failed: %d\n", ret);
		goto err_msg_recv_func_registe;
	}

#ifdef CONFIG_ZXDH_SF
	ret = zxdh_en_sf_driver_register();
	if (ret != 0) {
		LOG_ERR("zxdh_en_sf_driver_register failed: %d\n", ret);
		goto err_sf_driver_register;
	}
#endif

	return 0;

#ifdef CONFIG_ZXDH_SF
err_sf_driver_register:
	dh_pf_msg_recv_func_unregister();
#endif
err_msg_recv_func_registe:
	pci_unregister_driver(&dh_pf_driver);
err_register_driver:
	return ret;
}

static void dh_pf_pci_exit_module(void)
{
	LOG_INFO("%s - version %s %s\n", zxdh_pf_driver_string, zxdh_pf_driver_version,
		 zxdh_pf_copyright);

#ifdef CONFIG_ZXDH_SF
	zxdh_en_sf_driver_unregister();
#endif

	dh_pf_msg_recv_func_unregister();

	pci_unregister_driver(&dh_pf_driver);
}

module_init(dh_pf_pci_init_module);
module_exit(dh_pf_pci_exit_module);
