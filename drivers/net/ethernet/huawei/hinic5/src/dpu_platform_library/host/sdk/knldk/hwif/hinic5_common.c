/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_common.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#include <linux/kernel.h>
#include <linux/io-mapping.h>
#include <linux/delay.h>

#include "ossl_knl.h"
#include "hinic5_common.h"

int hinic5_dma_zalloc_coherent_align(void *dev_hdl, u64 size, u64 align,
				     unsigned int flag,
				     struct hinic5_dma_addr_align *mem_align)
{
	void *vaddr = NULL, *align_vaddr = NULL;
	dma_addr_t paddr, align_paddr;
	u64 real_size = size;

	if (!mem_align)
		return -ENOMEM;

	vaddr = dma_zalloc_coherent(dev_hdl, real_size, &paddr, flag);
	if (!vaddr)
		return -ENOMEM;

	align_paddr = ALIGN(paddr, align);
	/* align */
	if (align_paddr == paddr) {
		align_vaddr = vaddr;
		goto out;
	}

	dma_free_coherent(dev_hdl, real_size, vaddr, paddr);

	/* realloc memory for align */
	real_size = size + align;
	vaddr = dma_zalloc_coherent(dev_hdl, real_size, &paddr, flag);
	if (!vaddr)
		return -ENOMEM;

	align_paddr = ALIGN(paddr, align);
	align_vaddr = (void *)(uintptr_t)((u64)(uintptr_t)vaddr + (align_paddr - paddr));

out:
	mem_align->real_size = (u32)real_size;
	mem_align->ori_vaddr = vaddr;
	mem_align->ori_paddr = paddr;
	mem_align->align_vaddr = align_vaddr;
	mem_align->align_paddr = align_paddr;

	return 0;
}
EXPORT_SYMBOL(hinic5_dma_zalloc_coherent_align);

void hinic5_dma_free_coherent_align(void *dev_hdl,
				    struct hinic5_dma_addr_align *mem_align)
{
	if (!mem_align) {
		pr_err("mem_align is null\n");
		return;
	}
	dma_free_coherent(dev_hdl, mem_align->real_size,
			  mem_align->ori_vaddr, mem_align->ori_paddr);
}
EXPORT_SYMBOL(hinic5_dma_free_coherent_align);

int hinic5_wait_for_timeout(void *priv_data, wait_cpl_handler handler,
			    u32 wait_total_ms, u32 wait_once_us)
{
	enum hinic5_wait_return ret;
	ulong end;
	/* Take 9/10 * wait_once_us as the minimum sleep time of usleep_range */
	u32 usleep_min = wait_once_us - wait_once_us / 10;

	if (!handler)
		return -EINVAL;

	end = jiffies + msecs_to_jiffies(wait_total_ms);
	do {
		ret = handler(priv_data);
		if (ret == WAIT_PROCESS_CPL)
			return 0;
		else if (ret == WAIT_PROCESS_ERR)
			return -EIO;

		/* Sleep more than 20ms using msleep is accurate */
		if (wait_once_us >= 20 * USEC_PER_MSEC)
			msleep(wait_once_us / USEC_PER_MSEC);
		else
			usleep_range(usleep_min, wait_once_us);
	} while (time_before(jiffies, end));

	ret = handler(priv_data);
	if (ret == WAIT_PROCESS_CPL)
		return 0;
	else if (ret == WAIT_PROCESS_ERR)
		return -EIO;

	return -ETIMEDOUT;
}
