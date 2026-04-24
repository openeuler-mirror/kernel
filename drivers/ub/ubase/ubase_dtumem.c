// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <linux/bitmap.h>
#include <linux/ummu_core.h>
#include <linux/kernel.h>
#include <ub/ubase/ubase_comm_dev.h>

#include "ubase_cmd.h"
#include "ubase_dtumem.h"

static void ubase_parse_dtu_info(struct ubase_dev *udev,
				 struct ubase_query_dtu_info_cmd *resp)
{
#define UBASE_BIT_32 32

	u32 pa_base_addr_l = le32_to_cpu(resp->pa_base_addr_l);
	u32 pa_base_addr_h = le32_to_cpu(resp->pa_base_addr_h);
	u32 va_base_addr_l = le32_to_cpu(resp->va_base_addr_l);
	u32 va_base_addr_h = le32_to_cpu(resp->va_base_addr_h);
	u32 mem_node_id_l = le32_to_cpu(resp->mem_node_id_l);
	u32 mem_node_id_h = le32_to_cpu(resp->mem_node_id_h);
	u32 pa_size_l = le32_to_cpu(resp->pa_size_l);
	u32 pa_size_h = le32_to_cpu(resp->pa_size_h);
	int mem_node_id_l_first_bit;
	int mem_node_id_h_first_bit;

	udev->caps.dev_caps.dtu_pa_base = ubase_addr_gen(pa_base_addr_h,
							 pa_base_addr_l);
	udev->caps.dev_caps.dtu_va_base = ubase_addr_gen(va_base_addr_h,
							 va_base_addr_l);
	udev->caps.dev_caps.dtu_pa_size = ubase_size_gen(pa_size_h, pa_size_l);

	mem_node_id_l_first_bit =
		find_first_bit((const unsigned long *)&mem_node_id_l, UBASE_BIT_32);
	mem_node_id_h_first_bit =
		find_first_bit((const unsigned long *)&mem_node_id_h, UBASE_BIT_32);

	if (mem_node_id_l_first_bit == UBASE_BIT_32)
		udev->dtu_info.dtu_mem_node_id = UBASE_BIT_32 + mem_node_id_h_first_bit;
	else
		udev->dtu_info.dtu_mem_node_id = mem_node_id_l_first_bit;
}

static int ubase_query_dtu_info(struct ubase_dev *udev)
{
#define UBASE_BIT_64 64

	struct ubase_query_dtu_info_cmd resp = {0};
	struct ubase_cmd_buf in, out;
	int ret;

	__ubase_fill_inout_buf(&in, UBASE_OPC_QUERY_DTU_INFO, true, 0, NULL);
	__ubase_fill_inout_buf(&out, UBASE_OPC_QUERY_DTU_INFO, false,
			       sizeof(resp), &resp);

	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret) {
		ubase_err(udev, "failed to query dtu info, ret = %d.\n", ret);
		return ret;
	}

	ubase_parse_dtu_info(udev, &resp);
	if (udev->dtu_info.dtu_mem_node_id == UBASE_BIT_64) {
		ubase_err(udev, "failed to query mem_node_id, value is %d.\n",
			  udev->dtu_info.dtu_mem_node_id);
		return -EINVAL;
	}

	return 0;
}

static void ubase_fill_dtu_config_cmd(struct ubase_dev *udev,
				      struct ubase_cfg_dtu_tbl *req, u32 tid)
{
	u64 iova_base = udev->caps.dev_caps.dtu_iova_base;
	u64 pa_base = udev->caps.dev_caps.dtu_pa_base;
	u64 pa_size = udev->caps.dev_caps.dtu_pa_size;
	u64 limit_addr = iova_base + pa_size;

	req->en = 1;
	req->execlusive = 1;
	req->perm_read = 1;
	req->perm_write = 1;
	req->perm_atomic = 1;
	req->bufferable = 1;
	req->modified = 1;
	req->read_allocate = 1;
	req->write_allocate = 1;
	req->snoop = 1;
	req->tid = cpu_to_le32(tid);
	req->base_addr_l = cpu_to_le32(lower_32_bits(iova_base));
	req->base_addr_h = cpu_to_le32(upper_32_bits(iova_base));
	req->limit_addr_l = cpu_to_le32(lower_32_bits(limit_addr));
	req->limit_addr_h = cpu_to_le32(upper_32_bits(limit_addr));
	req->target_addr_l = cpu_to_le32(lower_32_bits(pa_base));
	req->target_addr_h = cpu_to_le32(upper_32_bits(pa_base));
}

static int __ubase_dtu_tbl_init(struct ubase_dev *udev, u32 tid, u16 *dtu_win_num)
{
	struct ubase_cfg_dtu_tbl resp = {0};
	struct ubase_cfg_dtu_tbl req = {0};
	struct ubase_cmd_buf in, out;
	int ret;

	ubase_fill_dtu_config_cmd(udev, &req, tid);
	__ubase_fill_inout_buf(&in, UBASE_OPC_CONFIG_DTU_TBL, false,
			       sizeof(req), &req);
	__ubase_fill_inout_buf(&out, UBASE_OPC_CONFIG_DTU_TBL, false,
			       sizeof(resp), &resp);

	ret = __ubase_cmd_send_inout(udev, &in, &out);
	if (ret) {
		ubase_err(udev, "failed to init dtu table, ret = %d.\n", ret);
		return ret;
	}

	*dtu_win_num = le16_to_cpu(resp.win_num);
	ubase_info(udev, "dtu_win_num = %u.\n", *dtu_win_num);

	return 0;
}

static int __ubase_dtu_tbl_uninit(struct ubase_dev *udev, u16 dtu_win_num)
{
	struct ubase_cfg_dtu_tbl req = {0};
	struct ubase_cmd_buf in;
	int ret;

	req.win_num = cpu_to_le16(dtu_win_num);
	__ubase_fill_inout_buf(&in, UBASE_OPC_CONFIG_DTU_TBL, false,
			       sizeof(req), &req);

	ret = __ubase_cmd_send_in(udev, &in);
	if (ret)
		ubase_err(udev, "failed to uninit dtu table, ret = %d.\n", ret);

	return ret;
}

/**
 * ubase_dtu_tbl_init() - initialize dtu table
 * @adev: auxiliary device
 * @tid: ub entity tid
 * @dtu_win_num: window number of dtu table
 *
 * This function is used to initialize dtu table.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_dtu_tbl_init(struct auxiliary_device *aux_dev, u32 tid, u16 *dtu_win_num)
{
	struct ubase_dev *udev;

	if (!aux_dev || !dtu_win_num)
		return -EINVAL;

	udev = ubase_get_udev_by_adev(aux_dev);

	return __ubase_dtu_tbl_init(udev, tid, dtu_win_num);
}
EXPORT_SYMBOL(ubase_dtu_tbl_init);

/**
 * ubase_dtu_tbl_uninit() - uninitialize dtu table
 * @adev: auxiliary device
 * @dtu_win_num: window number of dtu table
 *
 * This function is used to uninitialize dtu table.
 *
 * Context: Process context. Takes and releases <lock>, BH-safe.
 * Return: 0 on success, negative error code otherwise
 */
int ubase_dtu_tbl_uninit(struct auxiliary_device *aux_dev, u16 dtu_win_num)
{
	struct ubase_dev *udev;

	if (!aux_dev)
		return -EINVAL;

	udev = ubase_get_udev_by_adev(aux_dev);

	return __ubase_dtu_tbl_uninit(udev, dtu_win_num);
}
EXPORT_SYMBOL(ubase_dtu_tbl_uninit);

int ubase_dtu_mem_init(struct ubase_dev *udev)
{
	u64 iova_base = 0;
	size_t size;
	int ret;

	if (!ubase_dev_dtu_supported(udev))
		return 0;

	ret = ubase_query_dtu_info(udev);
	if (ret)
		return ret;

	udev->dtu_info.domain = iommu_get_domain_for_dev(udev->dev);
	if (!udev->dtu_info.domain) {
		ubase_err(udev, "failed to get iommu domain.\n");
		return -EINVAL;
	}

	udev->dtu_info.dtu_slot = dma_alloc_iova(udev->dev,
						 udev->caps.dev_caps.dtu_pa_size,
						 0, &iova_base, &size);
	if (!udev->dtu_info.dtu_slot || !iova_base ||
	    size != udev->caps.dev_caps.dtu_pa_size) {
		ubase_err(udev, "failed to alloc dtu iova, dtu_pa_size = %llu, size = %lu.\n",
			  udev->caps.dev_caps.dtu_pa_size, size);
		return -ENOMEM;
	}

	udev->caps.dev_caps.dtu_iova_base = iova_base;
	ret = __ubase_dtu_tbl_init(udev, udev->caps.dev_caps.tid,
				   &udev->dtu_info.dtu_win_num);
	if (ret) {
		dma_free_iova(udev->dtu_info.dtu_slot);
		return ret;
	}

	ubase_info(udev, "dtu_mem_node_id: %d.\n",
		   udev->dtu_info.dtu_mem_node_id);

	return 0;
}

void ubase_dtu_mem_uninit(struct ubase_dev *udev)
{
	if (!ubase_dev_dtu_supported(udev))
		return;

	__ubase_dtu_tbl_uninit(udev, udev->dtu_info.dtu_win_num);

	udev->dtu_info.dtu_win_num = 0;

	dma_free_iova(udev->dtu_info.dtu_slot);
}

void *ubase_dtu_alloc(struct ubase_dev *udev, struct page **page,
		      size_t size, dma_addr_t *iova)
{
	u64 dtu_iova_base = udev->caps.dev_caps.dtu_iova_base;
	u64 dtu_pa_base = udev->caps.dev_caps.dtu_pa_base;
	int order = get_order(size);
	phys_addr_t pa;
	void *va;
	int ret;

	*page = alloc_pages_node(udev->dtu_info.dtu_mem_node_id,
				 GFP_KERNEL | __GFP_ZERO, order);
	if (!(*page)) {
		ubase_err(udev, "failed to alloc pages, size = %lu, order = %d.\n",
			  size, order);
		return NULL;
	}

	pa = page_to_phys(*page);
	va = page_address(*page);
	*iova = pa + dtu_iova_base - dtu_pa_base;

	ret = iommu_map(udev->dtu_info.domain, *iova, pa, PAGE_SIZE << order,
			IOMMU_READ | IOMMU_WRITE, GFP_KERNEL);
	if (ret) {
		ubase_err(udev, "failed to map iova, ret = %d.\n", ret);
		goto err_iommu_map;
	}

	return va;

err_iommu_map:
	__free_pages(*page, order);

	return NULL;
}

void ubase_dtu_free(struct ubase_dev *udev, struct page *page,
		    size_t size, dma_addr_t iova)
{
	int order = get_order(size);
	size_t alloc_size;
	size_t unmapped;

	alloc_size = PAGE_SIZE << order;
	unmapped = iommu_unmap(udev->dtu_info.domain, iova, alloc_size);
	if (unmapped != alloc_size)
		ubase_err(udev, "Failed to unmap full region: requested %lu, unmapped %lu.\n",
			  alloc_size, unmapped);

	__free_pages(page, order);
}

/**
 * ubase_adev_dtu_supported() - determine whether to support dtu feature
 * @adev: auxiliary device
 *
 * This function is used to determine whether to support dtu feature.
 *
 * Context: Any context.
 * Return: true or false
 */
bool ubase_adev_dtu_supported(struct auxiliary_device *adev)
{
	if (!adev)
		return false;

	return ubase_dev_dtu_supported(__ubase_get_udev_by_adev(adev));
}
EXPORT_SYMBOL(ubase_adev_dtu_supported);

/**
 * ubase_adev_get_mem_node_id() - get dtu memory node id
 * @adev: auxiliary device
 *
 * This function is used to get dtu memory node id.
 *
 * Context: Any context.
 * Return: -EINVAL if the aux_dev is empty, otherwise dtu memory node id
 */
int ubase_adev_get_mem_node_id(struct auxiliary_device *aux_dev)
{
	struct ubase_dev *udev;

	if (!aux_dev)
		return -EINVAL;

	udev = __ubase_get_udev_by_adev(aux_dev);

	return udev->dtu_info.dtu_mem_node_id;
}
EXPORT_SYMBOL(ubase_adev_get_mem_node_id);
