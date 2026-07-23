// SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/io.h>

#include "common_define.h"
#include "cmdk_mmu600.h"
#include "adk_mmu600.h"
#include "../../main.h"

/* CMA page allocation size - 64MB total */
#define ZXDH_CMA_PAGE_COUNT (16 * 1024) /* 16K pages * 4KB = 64MB */

/* SMMU page table size definitions */
#define ZXDH_SMMU_L1_ENTRY_SIZE 0x100 /* 256 bytes per L1 entry */
#define ZXDH_SMMU_L1_ALIGN_SIZE 0x100 /* 256 byte alignment */
#define ZXDH_SMMU_L1_PT_NUM 32 /* 32 L1 page tables */
#define ZXDH_SMMU_L1_PT_SIZE (ZXDH_SMMU_L1_PT_NUM * ZXDH_SMMU_L1_ENTRY_SIZE)

#define ZXDH_SMMU_L2_ENTRY_SIZE 0x1000 /* 4KB per L2 entry */
#define ZXDH_SMMU_L2_ALIGN_SIZE 0x1000 /* 4KB alignment */
#define ZXDH_SMMU_L2_PT_NUM 32 /* 32 L2 page tables */
#define ZXDH_SMMU_L2_PT_SIZE (ZXDH_SMMU_L2_PT_NUM * ZXDH_SMMU_L2_ENTRY_SIZE)

#define ZXDH_SMMU_L3_ENTRY_SIZE 0x1000 /* 4KB per L3 entry */
#define ZXDH_SMMU_L3_ALIGN_SIZE 0x1000 /* 4KB alignment */
#define ZXDH_SMMU_L3_PT_NUM 0x3DE /* 990 L3 page tables */
#define ZXDH_SMMU_L3_PT_SIZE (ZXDH_SMMU_L3_PT_NUM * ZXDH_SMMU_L3_ENTRY_SIZE)

#define ZXDH_SMMU_PT_TOTAL_SIZE (ZXDH_SMMU_L1_PT_SIZE + ZXDH_SMMU_L2_PT_SIZE + ZXDH_SMMU_L3_PT_SIZE)

/* L2D SMMU base physical address */
#define ZXDH_PTE_L2D_START_PA 0x6200630000ULL

/**
 * zxdh_smmu_set_pte - Set page table entry
 * @pte_req: PTE request configuration
 * @dev: Device context
 *
 * Configure page table entry for the specified virtual-to-physical mapping.
 *
 * Return: 0 on success, negative error code on failure
 */
int zxdh_smmu_set_pte(struct smmu_pte_request *pte_req, struct zxdh_sc_dev *dev)
{
	if (!pte_req || !dev)
		return -EINVAL;

	return zxdh_smmu_mmap(pte_req, dev);
}
EXPORT_SYMBOL(zxdh_smmu_set_pte);

/**
 * zxdh_smmu_enable_stream_bypass - Enable stream bypass mode
 * @stream_id: Stream ID to configure
 *
 * Configure the specified stream to bypass SMMU translation.
 *
 * Return: 0 on success, negative error code on failure
 */
int zxdh_smmu_enable_stream_bypass(u32 stream_id)
{
	return 0;
}
EXPORT_SYMBOL(zxdh_smmu_enable_stream_bypass);

/**
 * zxdh_smmu_delete_pte - Delete a page table entry
 * @stream_id: Stream ID
 * @virt_addr: Virtual address
 * @dev: Device context
 *
 * Delete the specified page table entry for the given stream and address.
 *
 * Return: 0 on success, negative error code on failure
 */
int zxdh_smmu_delete_pte(u32 stream_id, u64 virt_addr, struct zxdh_sc_dev *dev)
{
	return zxdh_smmu_cmd_tlb_sync();
}

/**
 * zxdh_smmu_alloc_cma_memory - Allocate CMA memory for SMMU
 * @dev: Device context
 *
 * Allocate coherent DMA memory for SMMU page tables using CMA.
 *
 * Return: 0 on success, negative error code on failure
 */
static int zxdh_smmu_alloc_cma_memory(struct zxdh_sc_dev *dev)
{
	struct smmu_pte_address *pte_addr = dev->pte_address;
	struct device *device = dev->hw->device;

	pte_addr->cma_page_addr = dma_alloc_coherent(device, ZXDH_SMMU_PT_TOTAL_SIZE,
						     &pte_addr->cma_page_mem_base_pa, GFP_KERNEL);
	if (!pte_addr->cma_page_addr)
		return -ENOMEM;

	pte_addr->cma_page_mem_base_va = (u64)pte_addr->cma_page_addr;

	return 0;
}

/**
 * zxdh_smmu_pagetable_init - Initialize SMMU page tables
 * @dev: Device context
 *
 * Initialize SMMU page table structures and allocate necessary memory.
 *
 * Return: 0 on success, negative error code on failure
 */
int zxdh_smmu_pagetable_init(struct zxdh_sc_dev *dev)
{
	/* Initialize page table parameters using new structure */
	struct smmu_pagetable_param pgt_param = {};
	int ret;

	if (!dev)
		return -EINVAL;

	/* Send TLB invalidation command first */
	zxdh_smmu_invalidate_tlb(dev);

	/* Set L2D start physical address */
	dev->pte_l2d_startpa = dev->l2d_smmu_addr;

	/* Allocate PTE address structure */
	dev->pte_address = kzalloc(sizeof(*dev->pte_address), GFP_KERNEL);
	if (!dev->pte_address)
		return -ENOMEM;

	/* Allocate CMA memory for page tables */
	ret = zxdh_smmu_alloc_cma_memory(dev);
	if (ret)
		goto err_free_pte_addr;

	/* Initialize page table parameters using new structure */
	pgt_param.pagetable_phy_addr = dev->pte_address->cma_page_mem_base_pa;
	pgt_param.pagetable_vir_addr = dev->pte_address->cma_page_mem_base_va;
	pgt_param.pagetable_size = ZXDH_SMMU_PT_TOTAL_SIZE;
	pgt_param.l1_pagetable_num = 32;
	pgt_param.l2_pagetable_num = 32;
	pgt_param.l3_pagetable_num = 990;

	/* Set L2D SMMU L2 offset */
	dev->pte_address->l2d_smmu_l2_offset = dev->l2d_smmu_l2_offset;

	/* Initialize SMMU structures */
	ret = zxdh_smmu_struct_init(&pgt_param, dev->pte_address, dev->hw->device);
	if (ret)
		goto err_free_cma_mem;

	return 0;

err_free_cma_mem:
	dma_free_coherent(dev->hw->device, ZXDH_SMMU_PT_TOTAL_SIZE,
			  (void *)dev->pte_address->cma_page_mem_base_va,
			  dev->pte_address->cma_page_mem_base_pa);
err_free_pte_addr:
	kfree(dev->pte_address);
	dev->pte_address = NULL;
	return ret;
}

/**
 * zxdh_smmu_pagetable_exit - Cleanup SMMU page tables
 * @dev: Device context
 *
 * Release all SMMU related memory and resources.
 *
 * Return: 0 on success, negative error code on failure
 */
int zxdh_smmu_pagetable_exit(struct zxdh_sc_dev *dev)
{
	struct smmu_pte_address *pte_addr = dev->pte_address;
	struct device *device = dev->hw->device;

	if (!pte_addr)
		return -EINVAL;

	/* Free CMA memory */
	if (pte_addr->cma_page_addr) {
		dma_free_coherent(device, ZXDH_SMMU_PT_TOTAL_SIZE, pte_addr->cma_page_addr,
				  pte_addr->cma_page_mem_base_pa);
	}

	/* Free map management memory */
	if (pte_addr->map_manage_addr)
		kfree((void *)pte_addr->map_manage_addr);

	/* Free PTE records */
	kfree(pte_addr->pte_records);

	/* Free temporary PTE buffer */
	if (pte_addr->pte_temp_vir_addr) {
		dma_free_coherent(device, ZXDH_SMMU_L1_ENTRY_SIZE * 4,
				  (void *)pte_addr->pte_temp_vir_addr, pte_addr->pte_temp_phy_addr);
	}

	/* Free PTE address structure */
	kfree(dev->pte_address);
	dev->pte_address = NULL;

	return 0;
}

int zxdh_smmu_invalidate_tlb(struct zxdh_sc_dev *dev)
{
	int ret = 0;
	u64 recv_buffer = 0;
	u8 *reply_ptr = NULL;
	u8 *risc_smmu_back_result = NULL;
	u16 *risc_smmu_back_len = NULL;
	struct zxdh_pci_bar_msg in = { 0 };
	struct zxdh_msg_recviver_mem result = { 0 };
	struct smmu_msg_info smmu_info = { 0 };
	struct zxdh_pci_f *rf = dev_to_rf(dev);
	struct zxdh_mgr mgr = { 0 };
	struct iidc_core_dev_info *cdev_info;

	ktime_t current_time;
	ktime_t last_time;
	ktime_t delta_ms;
	u32 cnt = 0;
	u32 cnt_num = ZXDH_BAR_MSG_RETRY_NUM;

	if (rf->sc_dev.driver_load == false)
		cnt_num = ZXDH_BAR_MSG_DEFAULT_NUM;

	last_time = dev->last_time;
	current_time = ktime_get_real();
	if (last_time != 0) {
		delta_ms = ktime_ms_delta(current_time, last_time);
		if (delta_ms < 100) { /* 100ms timeout */
			return 0;
		}
	}
	dev->last_time = ktime_get_real();

	cdev_info = (struct iidc_core_dev_info *)rf->cdev;
	/* query pcie id */
	mgr.pdev = cdev_info->pdev;
	ret = dh_rdma_pf_pcie_id_get(&mgr);
	if (ret) {
		pr_err("[%s] get pf pcie_id failed, ret=%d\n", __func__, ret);
		return -EINVAL;
	}

	result.recv_buffer = &recv_buffer;
	result.buffer_len = sizeof(u64);

	smmu_info.is_tlb_invalid = 1;
	smmu_info.tlb_cfg.cmd = 0x2; /* TLBI_NSNH_ALL command */

	in.payload_addr = (u8 *)&smmu_info;
	in.payload_len = sizeof(struct smmu_msg_info);

	in.src = MSG_CHAN_END_PF;
	in.dst = MSG_CHAN_END_RISC;
	in.virt_addr = (u64)dev->hw->pci_hw_addr + 0x2000;

	in.event_id = 0x5; /* SMMU event ID */
	in.src_pcieid = mgr.pcie_id;

	do {
		ret = zxdh_bar_chan_sync_msg_send(&in, &result);
		if ((ret != ZXDH_BAR_ERR_TIME_OUT) && (ret != ZXDH_BAR_ERR_LOCK_FAILED))
			break;
		cnt++;
	} while (cnt < cnt_num);

	if (ret != 0)
		pr_err("zxdh_bar_chan_sync_msg_send error, ret = %d cnt=%d\n", ret, cnt);

	reply_ptr = (u8 *)result.recv_buffer;
	if (*reply_ptr == 0xFF) {
		risc_smmu_back_result = (u8 *)(reply_ptr + 4);
		risc_smmu_back_len = (u16 *)(reply_ptr + 1);

		pr_err("risc_back_result = 0x%x, risc_smmu_back_len = 0x%x\n",
		       *(u8 *)risc_smmu_back_result, *(u8 *)risc_smmu_back_len);
	}

	return 0;
}

MODULE_AUTHOR("ZTE Corporation");
MODULE_LICENSE("GPL");
