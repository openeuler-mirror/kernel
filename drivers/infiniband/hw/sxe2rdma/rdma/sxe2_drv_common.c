// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_common.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/err.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/pci_regs.h>

#include "sxe2_drv_aux.h"
#include "sxe2_drv_rdma_common.h"

int sxe2_kget_aligned_mem(struct sxe2_rdma_pci_f *rdma_func,
			  struct sxe2_rdma_dma_mem *memptr, u32 size, u32 mask)
{
	unsigned long va, newva;
	unsigned long extra;
	int ret_code = 0;

	va    = (unsigned long)rdma_func->obj_next.va;
	newva = va;
	if (mask)
		newva = ALIGN(va, (unsigned long)mask + 1ULL);

	extra	     = newva - va;
	memptr->va   = (u8 *)va + extra;
	memptr->pa   = rdma_func->obj_next.pa + extra;
	memptr->size = size;
	if (((u8 *)memptr->va + size) >
	    ((u8 *)rdma_func->obj_mem.va + rdma_func->obj_mem.size)) {
		ret_code = -ENOMEM;
		goto end;
	}

	rdma_func->obj_next.va = (u8 *)memptr->va + size;
	rdma_func->obj_next.pa = memptr->pa + size;

end:
	return ret_code;
}

u8 sxe2_kget_encoded_wqe_size(u32 wqsize, enum sxe2_queue_type queue_type)
{
	u8 encoded_size = 0;

	if (queue_type == SXE2_QUEUE_TYPE_MQ)
		encoded_size = 1;

	wqsize >>= 2;
	while (wqsize >>= 1)
		encoded_size++;

	return encoded_size;
}

int sxe2_kalloc_rsrc(struct sxe2_rdma_pci_f *rf, unsigned long *rsrc_array,
		     u32 max_rsrc, u32 *req_rsrc_num, u32 *next)
{
	u32 rsrc_num;
	unsigned long flags = 0;

	spin_lock_irqsave(&rf->rsrc_lock, flags);
	rsrc_num = (u32)find_next_zero_bit(rsrc_array, max_rsrc, *next);
	if (rsrc_num >= max_rsrc) {
		rsrc_num = (u32)find_first_zero_bit(rsrc_array, max_rsrc);
		if (rsrc_num >= max_rsrc) {
			spin_unlock_irqrestore(&rf->rsrc_lock, flags);
			return -EOVERFLOW;
		}
	}
	__set_bit((int)rsrc_num, rsrc_array);
	*next = rsrc_num + 1;
	if (*next == max_rsrc)
		*next = 0;

	*req_rsrc_num = rsrc_num;
	spin_unlock_irqrestore(&rf->rsrc_lock, flags);

	return 0;
}

void sxe2_kfree_rsrc(struct sxe2_rdma_pci_f *rf, unsigned long *rsrc_array,
		     u32 rsrc_num)
{
	unsigned long flags = 0;

	spin_lock_irqsave(&rf->rsrc_lock, flags);
	__clear_bit((int)rsrc_num, rsrc_array);
	spin_unlock_irqrestore(&rf->rsrc_lock, flags);
}

int sxe2_ucount_bitmap_zero_bits(unsigned long *bitmap, u32 max)
{
	int zero_count = 0;
	u32 i;

	for (i = 0; i < max; i++) {
		if (!test_bit((int)i, bitmap))
			zero_count++;
	}
	return zero_count;
}

u32 sxe2_round_up_pow_2(u32 value)
{
	int count = 1;

	for (value--; count <= 16; count *= 2)
		value |= value >> count;

	return ++value;
}

void sxe2_copy_ip_ntohl(u32 *dst, __be32 *src)
{
	*dst++ = ntohl(*src++);
	*dst++ = ntohl(*src++);
	*dst++ = ntohl(*src++);
	*dst   = ntohl(*src);
}

void sxe2_copy_ip_htonl(__be32 *dst, u32 *src)
{
	*dst++ = htonl(*src++);
	*dst++ = htonl(*src++);
	*dst++ = htonl(*src++);
	*dst   = htonl(*src);
}

bool sxe2_drv_core_is_tph_enable(struct sxe2_rdma_device *rdma_dev,
				 bool is_user_enable, u32 *st_mode)
{
	struct aux_core_dev_info *cdev_info = rdma_dev->rdma_func->cdev;
	struct pci_dev *pdev		    = cdev_info->pdev;
	u16 pos				    = 0;
	u32 tph_control			    = 0;
	u32 tph_capability		    = 0;
	bool ret			    = false;

	ret = check_bridge_tph_is_support(rdma_dev);
	if (!ret) {
		DRV_RDMA_LOG_DEV_INFO("device upstream bridge do NOT support TPH\n");
		goto out;
	}

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_TPH);
	if (!pos) {
		ret = false;
		DRV_RDMA_LOG_DEV_INFO("device do NOT support TPH\n");
		goto out;
	}
	pci_read_config_dword(pdev, pos + OFFSET_TPH_CAPABILITY,
			      &tph_capability);
	if (!(tph_capability & (1 << MODE_DEVICE_SPECIFIC))) {
		ret = false;
		DRV_RDMA_LOG_DEV_INFO("TPH capability is NOT enabled\n");
		goto out;
	}

	pci_read_config_dword(pdev, pos + OFFSET_TPH_CONTROL, &tph_control);

	if (tph_control & (1 << OFFSET_TPHENABLE_IN_TPH_CONTROL)) {
		if (is_user_enable) {
			ret	 = true;
			*st_mode = tph_control & 0x3;
			DRV_RDMA_LOG_DEV_INFO(
				"TPH capability is support, st mode is %u\n",
				*st_mode);
		}
	}

out:
	return ret;
}

static bool pcie_dev_is_support_tph_comp(struct sxe2_rdma_device *rdma_dev, struct pci_dev *pdev)
{
	bool ret;
	int pos = 0;
	u16 pcie_cap = 0;
	u32 devcap2 = 0;
	u8 pcie_cap_version = 0;
	u8 tph_comp = 0;

	pos = pci_find_capability(pdev, PCI_CAP_ID_EXP);
	if (!pos) {
		DRV_RDMA_LOG_DEV_ERR("PCIe Capability not found\n");
		ret = false;
		goto out;
	}

	pci_read_config_word(pdev, pos + PCI_EXP_FLAGS, &pcie_cap);
	pcie_cap_version = pcie_cap & PCI_EXP_FLAGS_VERS;
	DRV_RDMA_LOG_DEV_DEBUG("PCIe Capability Version: %d\n", pcie_cap_version);

	if (pcie_cap_version < 2) {
		DRV_RDMA_LOG_WARN_BDF("PCIe Capability version %d,\n"
							"\tDevice Capabilities 2 not supported\n",
								pcie_cap_version);
		ret = false;
		goto out;
	}

	pci_read_config_dword(pdev, pos + PCI_EXP_DEVCAP2, &devcap2);
	DRV_RDMA_LOG_DEV_DEBUG("Device Capabilities 2: 0x%x\n", devcap2);

	tph_comp = (devcap2 & SXE2_PCI_EXP_DEVCAP2_TPH_COMP_MASK) >>
		SXE2_PCI_EXP_DEVCAP2_TPH_COMP_SHIFT;
	if (tph_comp) {
		ret = true;
	} else {
		DRV_RDMA_LOG_DEV_DEBUG("upstream rp not support tph comp.\n");
		ret = false;
	}

out:
	return ret;
}

static struct pci_dev *get_upstream_bridge(struct sxe2_rdma_device *rdma_dev)
{
	struct aux_core_dev_info *cdev_info = rdma_dev->rdma_func->cdev;
	struct pci_dev *pdev		    = cdev_info->pdev;
	struct pci_bus *bus;
	struct pci_dev *bridge;

	if (!pdev || !pdev->bus) {
		DRV_RDMA_LOG_ERROR_BDF("pdev or pdev->bus is NULL.\n");
		bridge = NULL;
		goto out;
	}

	bus = pdev->bus;

	if (pci_is_root_bus(bus)) {
		DRV_RDMA_LOG_DEV_WARN("is root bus，no bridge\n");
		bridge = NULL;
		goto out;
	}

	bridge = bus->self;
	if (!bridge)
		DRV_RDMA_LOG_ERROR_BDF("get %02x upstream bridge failed.\n", bus->number);

out:
	return bridge;
}

bool check_bridge_tph_is_support(struct sxe2_rdma_device *rdma_dev)
{
	struct pci_dev *bridge;
	bool supports_tph = false;
	struct aux_core_dev_info *cdev_info = rdma_dev->rdma_func->cdev;
	struct pci_dev *pdev = cdev_info->pdev;

	if (!pdev) {
		DRV_RDMA_LOG_DEV_ERR("pdev is NULL.\n");
		supports_tph = false;
		goto out;
	}

	bridge = get_upstream_bridge(rdma_dev);
	if (!bridge) {
		DRV_RDMA_LOG_DEV_WARN("bridge is NULL\n");
		supports_tph = false;
		goto out;
	}

	supports_tph = pcie_dev_is_support_tph_comp(rdma_dev, bridge);

out:
	return supports_tph;
}

int pci_dev_set_tph_request_cap(struct sxe2_rdma_device *rdma_dev, bool state)
{
	struct aux_core_dev_info *cdev_info = rdma_dev->rdma_func->cdev;
	struct pci_dev *pdev		    = cdev_info->pdev;
	int pos = 0;
	u32 cap = 0;
	int ret = 0;

	if (!pdev) {
		DRV_RDMA_LOG_DEV_ERR("pdev is NULL.\n");
		ret = -EINVAL;
		goto out;
	}

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_TPH);
	if (!pos) {
		DRV_RDMA_LOG_DEV_ERR("device %04x:%02x:%02x.%x not support TPH request\n",
				pci_domain_nr(pdev->bus), pdev->bus->number,
				PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
		ret = -ENOENT;
		goto out;
	}

	pci_read_config_dword(pdev, pos + OFFSET_TPH_CONTROL, &cap);
	if (state)
		cap = cap | SXE2_PCI_EXP_EXT_TPH_REQ_ST_DEVICE_MODE_MASK |
			SXE2_PCI_EXP_EXT_TPH_REQ_ENABLE_MASK;
	else
		cap = 0;

	pci_write_config_dword(pdev, pos + OFFSET_TPH_CONTROL, cap);
	DRV_RDMA_LOG_DEV_DEBUG("device %04x:%02x:%02x.%x TPH cap: 0x%08x\n",
			pci_domain_nr(pdev->bus), pdev->bus->number,
			PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn), cap);

out:
	return ret;
}

int sxe2_rdma_adminq_send(struct aux_core_dev_info *cdev_info,
				 int opcode,
			     u8 *msg, u16 len, u8 *recv_msg, u16 recv_len)
{
	int ret = 0;

	switch (opcode) {
	case SXE2_CMD_RDMA_QP_ATTACH_MC:
	case SXE2_CMD_RDMA_QP_DETACH_MC:
	case SXE2_CMD_RDMA_GET_CC_QP_DFX:
		if (!recv_msg || !recv_len) {
			ret =  -EINVAL;
			goto out;
		}
		break;
	default:
		break;
	}

	ret = cdev_info->ops->rdma_send_cmd(cdev_info, opcode, msg, len, recv_msg, recv_len);

out:
	return ret;
}

