// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/io.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include "zxic_common.h"
#include "dpp_dtb_cfg.h"
#include "dpp_kernel_init.h"
#include "dpp_dtb_table_api.h"

struct hash_dma_addr_info {
	u32 slot_id;
	u32 dma_size;
	dma_addr_t dma_phy_addr;
	void *dma_vir_addr;
};

struct dpp_dma_info {
	struct dtb_queue_dma_addr_info dtb_queue_info[DPP_DTB_QUEUE_NUM_MAX];
	struct hash_dma_addr_info hash_dma_info;
};

static struct dpp_dma_info g_dpp_dma_info[DPP_PCIE_SLOT_MAX] = { 0 };
static u32 queue_used_flag[DPP_PCIE_SLOT_MAX][4] = { 0 };

static void dpp_dtb_queue_dma_flag_set(u32 slot_id, u32 queue_id)
{
	u32 bit_shift = 0;
	u32 reg_shift = 0;

	reg_shift = queue_id / 32;
	bit_shift = queue_id % 32;

	queue_used_flag[slot_id][reg_shift] = queue_used_flag[slot_id][reg_shift] |
					      (0x1 << bit_shift);
}

static void dpp_dtb_queue_dma_flag_clear(u32 slot_id, u32 queue_id)
{
	u32 bit_shift = 0;
	u32 reg_shift = 0;

	reg_shift = queue_id / 32;
	bit_shift = queue_id % 32;

	queue_used_flag[slot_id][reg_shift] = queue_used_flag[slot_id][reg_shift] &
					      ~(0x1 << bit_shift);
}

static u32 dpp_dtb_queue_dma_flag_get(u32 slot_id, u32 queue_id)
{
	u32 bit_shift = 0;
	u32 reg_shift = 0;

	u32 flag = 0;

	reg_shift = queue_id / 32;
	bit_shift = queue_id % 32;

	flag = (queue_used_flag[slot_id][reg_shift] >> bit_shift) & 0x1;

	ZXIC_COMM_TRACE_NOTICE("[%s]:slot %d queue %d flag %d!\n", __func__, slot_id, queue_id,
			       flag);

	return flag;
}

s32 dpp_dtb_queue_dma_mem_alloc(struct dpp_dev_t *dev, u32 queue_id, u32 size)
{
	dma_addr_t dma_handle;
	void *cpu_addr = NULL;
	u32 slot_id = 0;

	ZXIC_COMM_CHECK_POINT(dev);

	slot_id = (u32)DEV_PCIE_SLOT(dev);
	ZXIC_COMM_CHECK_INDEX(slot_id, 0, DPP_DEV_SLOT_MAX - 1);

	if (queue_id > (DPP_DTB_QUEUE_NUM_MAX - 1))
		return -ENOMEM;

	cpu_addr = dma_alloc_coherent(&(DEV_PCIE_DEV(dev)->dev), size, &dma_handle, GFP_KERNEL);

	if (!cpu_addr)
		return -ENOMEM;

	g_dpp_dma_info[slot_id].dtb_queue_info[queue_id].slot_id = slot_id;
	g_dpp_dma_info[slot_id].dtb_queue_info[queue_id].queue_id = queue_id;
	g_dpp_dma_info[slot_id].dtb_queue_info[queue_id].dma_vir_addr =
		ZXIC_COMM_PTR_TO_VAL(cpu_addr);
	g_dpp_dma_info[slot_id].dtb_queue_info[queue_id].dma_phy_addr = dma_handle;
	g_dpp_dma_info[slot_id].dtb_queue_info[queue_id].dma_size = size;

	ZXIC_COMM_TRACE_NOTICE("[%s]:slot %d queue %d kernel phy addr :0x%016llx !\n", __func__,
			       slot_id, queue_id, dma_handle);
	ZXIC_COMM_TRACE_NOTICE("[%s]:slot %d queue %d kernel vir addr :0x%016llx !\n", __func__,
			       slot_id, queue_id, ZXIC_COMM_PTR_TO_VAL(cpu_addr));

	dpp_dtb_queue_dma_flag_set(slot_id, queue_id);
	dpp_dtb_queue_dma_flag_get(slot_id, queue_id);

	return DPP_OK;
}

s32 dpp_dtb_queue_dma_mem_get(struct dpp_dev_t *dev, u32 queue_id,
			      struct dtb_queue_dma_addr_info *dmaAddrInfo)
{
	u32 slot_id = 0;

	ZXIC_COMM_CHECK_POINT(dev);

	slot_id = (u32)DEV_PCIE_SLOT(dev);
	ZXIC_COMM_CHECK_INDEX(slot_id, 0, DPP_DEV_SLOT_MAX - 1);

	if (queue_id > (DPP_DTB_QUEUE_NUM_MAX - 1)) {
		ZXIC_COMM_PRINT("[dpp dtb_queue_dma_mem_get]:queue id max.\n");
		return -1;
	}

	if (g_dpp_dma_info[slot_id].dtb_queue_info[queue_id].queue_id != queue_id) {
		ZXIC_COMM_PRINT("[dpp dtb_queue_dma_mem_get]:slot %d queue %d error !\n", slot_id,
				queue_id);
		return -1;
	}
	dmaAddrInfo->dma_phy_addr = g_dpp_dma_info[slot_id].dtb_queue_info[queue_id].dma_phy_addr;
	dmaAddrInfo->dma_vir_addr = g_dpp_dma_info[slot_id].dtb_queue_info[queue_id].dma_vir_addr;
	dmaAddrInfo->dma_size = g_dpp_dma_info[slot_id].dtb_queue_info[queue_id].dma_size;
	dmaAddrInfo->queue_id = queue_id;
	dmaAddrInfo->slot_id = slot_id;

	return DPP_OK;
}

s32 dpp_dtb_queue_dma_mem_release(struct dpp_dev_t *dev, u32 queue_id)
{
	dma_addr_t dma_handle = 0;
	void *cpu_addr = NULL;
	u32 dma_size = 0;
	u32 slot_id = 0;

	ZXIC_COMM_CHECK_POINT(dev);

	slot_id = (u32)DEV_PCIE_SLOT(dev);
	ZXIC_COMM_CHECK_INDEX(slot_id, 0, DPP_DEV_SLOT_MAX - 1);

	if (queue_id > (DPP_DTB_QUEUE_NUM_MAX - 1)) {
		ZXIC_COMM_PRINT("[dpp_dtb_dma_mem_release]:queue id max.\n");
		return -1;
	}

	if (g_dpp_dma_info[slot_id].dtb_queue_info[queue_id].queue_id != queue_id) {
		ZXIC_COMM_PRINT("[dpp_dtb_dma_mem_release]:slot %d queue %d error !\n", slot_id,
				queue_id);
		return -1;
	}

	dma_handle = g_dpp_dma_info[slot_id].dtb_queue_info[queue_id].dma_phy_addr;
	cpu_addr =
		ZXIC_COMM_VAL_TO_PTR(g_dpp_dma_info[slot_id].dtb_queue_info[queue_id].dma_vir_addr);
	dma_size = g_dpp_dma_info[slot_id].dtb_queue_info[queue_id].dma_size;

	if (!dma_handle)
		return -EFAULT;

	dma_free_coherent(&(DEV_PCIE_DEV(dev)->dev), dma_size, cpu_addr, dma_handle);

	ZXIC_COMM_PRINT("[dpp_dtb_dma_mem_release]:slot %d queue %d release success!\n", slot_id,
			queue_id);

	g_dpp_dma_info[slot_id].dtb_queue_info[queue_id].slot_id = 0;
	g_dpp_dma_info[slot_id].dtb_queue_info[queue_id].queue_id = 0;
	g_dpp_dma_info[slot_id].dtb_queue_info[queue_id].dma_phy_addr = 0;
	g_dpp_dma_info[slot_id].dtb_queue_info[queue_id].dma_vir_addr = 0;
	g_dpp_dma_info[slot_id].dtb_queue_info[queue_id].dma_size = 0;

	dpp_dtb_queue_dma_flag_clear(slot_id, queue_id);
	dpp_dtb_queue_dma_flag_get(slot_id, queue_id);

	return 0;
}

s32 dtb_sdt_dump_dma_alloc(struct dpp_dev_t *dev, u32 dma_size, u64 *p_dma_phy_addr,
			   u64 *p_dma_vir_addr)
{
	int rc = 0;

	dma_addr_t dma_handle;
	void *cpu_addr = NULL;

	cpu_addr = dma_alloc_coherent(&(DEV_PCIE_DEV(dev)->dev), dma_size, &dma_handle, GFP_KERNEL);

	if (!cpu_addr)
		return -ENOMEM;

	*p_dma_phy_addr = (u64)dma_handle;
	*p_dma_vir_addr = (u64)(ZXIC_COMM_PTR_TO_VAL(cpu_addr));

	return rc;
}

s32 dtb_sdt_dump_dma_release(struct dpp_dev_t *dev, u32 dma_size, u64 dma_phy_addr,
			     u64 dma_vir_addr)
{
	dma_addr_t dma_handle = 0;
	void *cpu_addr = NULL;

	dma_handle = (dma_addr_t)dma_phy_addr;
	cpu_addr = ZXIC_COMM_VAL_TO_PTR(dma_vir_addr);

	if (!dma_handle)
		return -EFAULT;

	dma_free_coherent(&(DEV_PCIE_DEV(dev)->dev), dma_size, cpu_addr, dma_handle);

	return 0;
}
