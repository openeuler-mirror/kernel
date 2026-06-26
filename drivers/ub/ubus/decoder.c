// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubus decoder: " fmt

#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/resource_ext.h>

#include "ubus.h"
#include "ubus_controller.h"
#include "decoder.h"

#define MMIO_SIZE_MASK		GENMASK_ULL(18, 16)
#define CMDQ_SIZE_MASK		GENMASK_ULL(15, 12)
#define EVTQ_SIZE_MASK		GENMASK_ULL(7, 4)
#define MMIO_SIZE_OFFSET	16
#define CMDQ_SIZE_OFFSET	12
#define EVTQ_SIZE_OFFSET	4

#define CMDQ_SIZE_USE_MASK	GENMASK(11, 8)
#define CMDQ_SIZE_USE_OFFSET	8
#define CMDQ_ENABLE		0x1

#define EVTQ_SIZE_USE_MASK	GENMASK(11, 8)
#define EVTQ_SIZE_USE_OFFSET	8
#define EVTQ_ENABLE		0x1

static void ub_decoder_uninit_queue(struct ub_bus_controller *ubc,
				    struct ub_decoder *decoder)
{
	if (ubc->ops->uninit_decoder_queue)
		ubc->ops->uninit_decoder_queue(decoder);
	else
		ub_err(ubc->uent, "ub bus controller can't uninit decoder queue\n");
}

static int ub_decoder_init_queue(struct ub_bus_controller *ubc,
				 struct ub_decoder *decoder)
{
	if (ubc->ops->init_decoder_queue && ubc->ops->uninit_decoder_queue)
		return ubc->ops->init_decoder_queue(decoder);

	ub_err(ubc->uent, "ub bus controller can't init decoder queue\n");
	return -EINVAL;
}

static u32 set_mmio_base_reg(struct ub_decoder *decoder)
{
	u32 mmio_high = upper_32_bits(decoder->mmio_base_addr);
	u32 mmio_low = lower_32_bits(decoder->mmio_base_addr);
	struct ub_entity *ent = decoder->uent;
	u32 low_bit, high_bit, ret;

	ret = (u32)ub_cfg_write_dword(ent, DECODER_MMIO_BA0,
				      0xffffffff);
	ret |= (u32)ub_cfg_write_dword(ent, DECODER_MMIO_BA1,
				       0xffffffff);
	ret |= (u32)ub_cfg_read_dword(ent, DECODER_MMIO_BA0, &low_bit);
	ret |= (u32)ub_cfg_read_dword(ent, DECODER_MMIO_BA1, &high_bit);
	if (ret) {
		ub_err(ent, "Failed to access decoder MMIO BA\n");
		return ret;
	}

	if ((low_bit | mmio_low) != low_bit ||
		(high_bit | mmio_high) != high_bit) {
		ub_err(ent, "decoder MMIO address does not match HW reg\n");
		return -EINVAL;
	}

	ret = (u32)ub_cfg_write_dword(decoder->uent, DECODER_MMIO_BA0,
				      lower_32_bits(decoder->mmio_base_addr));
	ret |= (u32)ub_cfg_write_dword(decoder->uent, DECODER_MMIO_BA1,
				       upper_32_bits(decoder->mmio_base_addr));

	return ret;
}

static u32 set_page_table_reg(struct ub_decoder *decoder)
{
	u32 matt_high = upper_32_bits(decoder->pgtlb.pgtlb_dma);
	u32 matt_low = lower_32_bits(decoder->pgtlb.pgtlb_dma);
	struct ub_entity *ent = decoder->uent;
	u32 low_bit, high_bit, ret;

	ret = (u32)ub_cfg_write_dword(ent, DECODER_MATT_BA0,
				      0xffffffff);
	ret |= (u32)ub_cfg_write_dword(ent, DECODER_MATT_BA1,
				       0xffffffff);
	ret |= (u32)ub_cfg_read_dword(ent, DECODER_MATT_BA0, &low_bit);
	ret |= (u32)ub_cfg_read_dword(ent, DECODER_MATT_BA1, &high_bit);
	if (ret) {
		ub_err(ent, "Failed to access decoder MATT BA\n");
		return ret;
	}

	if ((low_bit | matt_low) != low_bit ||
		(high_bit | matt_high) != high_bit) {
		ub_err(ent, "decoder MATT address does not match HW reg\n");
		return -EINVAL;
	}

	ret = (u32)ub_cfg_write_dword(decoder->uent, DECODER_MATT_BA0,
				      lower_32_bits(decoder->pgtlb.pgtlb_dma));
	ret |= (u32)ub_cfg_write_dword(decoder->uent, DECODER_MATT_BA1,
				       upper_32_bits(decoder->pgtlb.pgtlb_dma));

	return ret;
}

static u32 set_queue_reg(struct ub_decoder *decoder)
{
	u32 val, ret;

	/* init decoder cmdq base addr and pi ci */
	ret = (u32)ub_cfg_write_dword(decoder->uent, DECODER_CMDQ_BASE_ADDR0,
				      lower_32_bits(decoder->cmdq.base));
	ret |= (u32)ub_cfg_write_dword(decoder->uent, DECODER_CMDQ_BASE_ADDR1,
				       upper_32_bits(decoder->cmdq.base));
	ret |= (u32)ub_cfg_write_dword(decoder->uent, DECODER_CMDQ_PROD, 0);
	ret |= (u32)ub_cfg_write_dword(decoder->uent, DECODER_CMDQ_CONS, 0);

	/* set decoder cmdq conf */
	ret |= (u32)ub_cfg_read_dword(decoder->uent, DECODER_CMDQ_CFG, &val);
	decoder->vals.cmdq_cfg_val = val;
	val &= ~CMDQ_SIZE_USE_MASK;
	val |= decoder->cmdq.qs << CMDQ_SIZE_USE_OFFSET;
	val |= CMDQ_ENABLE;
	ret |= (u32)ub_cfg_write_dword(decoder->uent, DECODER_CMDQ_CFG, val);

	/* init decoder eventq base addr and pi ci */
	ret |= (u32)ub_cfg_write_dword(decoder->uent, DECODER_EVENTQ_BASE_ADDR0,
				       lower_32_bits(decoder->evtq.base));
	ret |= (u32)ub_cfg_write_dword(decoder->uent, DECODER_EVENTQ_BASE_ADDR1,
				       upper_32_bits(decoder->evtq.base));
	ret |= (u32)ub_cfg_write_dword(decoder->uent, DECODER_EVENTQ_PROD, 0);
	ret |= (u32)ub_cfg_write_dword(decoder->uent, DECODER_EVENTQ_CONS, 0);

	/* set decoder eventq conf */
	ret |= (u32)ub_cfg_read_dword(decoder->uent, DECODER_EVENTQ_CFG, &val);
	decoder->vals.evtq_cfg_val = val;
	val &= ~EVTQ_SIZE_USE_MASK;
	val |= decoder->evtq.qs << EVTQ_SIZE_USE_OFFSET;
	val |= EVTQ_ENABLE;
	ret |= (u32)ub_cfg_write_dword(decoder->uent, DECODER_EVENTQ_CFG, val);

	decoder->cmdq.prod.val = 0;
	decoder->evtq.cons.val = 0;
	if (ret)
		ub_err(decoder->uent, "set decoder queue failed\n");

	return ret;
}

static void unset_queue_reg(struct ub_decoder *decoder)
{
	struct ub_entity *uent = decoder->uent;
	u32 ret;

	ret = (u32)ub_cfg_write_dword(uent, DECODER_CMDQ_CFG,
				      decoder->vals.cmdq_cfg_val);
	ret |= (u32)ub_cfg_write_dword(uent, DECODER_EVENTQ_CFG,
				       decoder->vals.evtq_cfg_val);

	ret |= (u32)ub_cfg_write_dword(uent, DECODER_CMDQ_BASE_ADDR0, 0);
	ret |= (u32)ub_cfg_write_dword(uent, DECODER_CMDQ_BASE_ADDR1, 0);

	ret |= (u32)ub_cfg_write_dword(uent, DECODER_EVENTQ_BASE_ADDR0, 0);
	ret |= (u32)ub_cfg_write_dword(uent, DECODER_EVENTQ_BASE_ADDR1, 0);
	if (ret)
		ub_err(uent, "unset queue reg fail\n");
}

static u32 set_decoder_enable(struct ub_decoder *decoder)
{
	u32 ret;

	if (!decoder->create_matt)
		return 0;

	ret = (u32)ub_cfg_write_dword(decoder->uent, DECODER_CTRL, 1);
	if (ret)
		ub_err(decoder->uent, "set decoder enable failed\n");

	return ret;
}

static void unset_decoder_enable(struct ub_decoder *decoder)
{
	struct ub_entity *uent = decoder->uent;

	if (!decoder->create_matt)
		return;

	if (ub_cfg_write_dword(uent, DECODER_CTRL, 0))
		ub_err(uent, "unset decoder enable fail\n");
}

static u32 ub_decoder_device_set(struct ub_decoder *decoder)
{
	u32 ret = 0;

	if (decoder->create_matt) {
		ub_info(decoder->uent, "Set mmio base reg and page table reg\n");
		ret = set_mmio_base_reg(decoder);
		ret |= set_page_table_reg(decoder);
	}
	ret |= set_queue_reg(decoder);
	ret |= set_decoder_enable(decoder);
	if (ret) {
		unset_decoder_enable(decoder);
		unset_queue_reg(decoder);
	}

	return ret;
}

static int ub_decoder_create_page_table(struct ub_bus_controller *ubc,
					struct ub_decoder *decoder)
{
	if (!decoder->create_matt)
		return 0;

	if (ubc->ops->create_decoder_table && ubc->ops->free_decoder_table)
		return ubc->ops->create_decoder_table(decoder);

	ub_err(decoder->uent, "ub bus controller can't create decoder table\n");
	return -EINVAL;
}

static void ub_decoder_free_page_table(struct ub_bus_controller *ubc,
				       struct ub_decoder *decoder)
{
	if (!decoder->create_matt)
		return;

	if (ubc->ops->free_decoder_table)
		ubc->ops->free_decoder_table(decoder);
	else
		ub_err(decoder->uent,
			"ub bus controller can't free decoder table\n");
}

static int ub_get_decoder_mmio_base(struct ub_bus_controller *ubc,
				     struct ub_decoder *decoder)
{
	struct resource_entry *entry;

	resource_list_for_each_entry(entry, &ubc->resources) {
		if (entry->res->flags == IORESOURCE_MEM &&
		    strstr(entry->res->name, "UB_BUS_CTL")) {
			decoder->mmio_base_addr = entry->res->start;
			decoder->mmio_end_addr = entry->res->end;
			break;
		}
	}

	if (decoder->mmio_base_addr == 0) {
		ub_err(decoder->uent, "get decoder mmio base failed\n");
		return -EINVAL;
	}

	return 0;
}

static const char * const mmio_size_desc[] = {
	"128Gbyte", "256Gbyte", "512Gbyte", "1Tbyte",
	"2Tbyte", "4Tbyte", "8Tbyte", "16Tbyte"
};

static const u64 mmio_size[] = {
	128ULL * SZ_1G, 256ULL * SZ_1G, 512ULL * SZ_1G, SZ_1T,
	2 * SZ_1T, 4 * SZ_1T, 8 * SZ_1T, 16 * SZ_1T
};

static int ub_get_decoder_cap(struct ub_decoder *decoder)
{
	struct ub_entity *uent = decoder->uent;
	u32 val, feature;
	u64 size;
	int ret;

	ret = ub_cfg_read_dword(uent, DECODER_CAP, &val);
	if (ret) {
		ub_err(uent, "read decoder cap fail\n");
		return ret;
	}

	decoder->mmio_size_sup = (val & MMIO_SIZE_MASK) >> MMIO_SIZE_OFFSET;
	decoder->cmdq.qs = (val & CMDQ_SIZE_MASK) >> CMDQ_SIZE_OFFSET;
	decoder->evtq.qs = (val & EVTQ_SIZE_MASK) >> EVTQ_SIZE_OFFSET;
	if (decoder->cmdq.qs == 0 || decoder->evtq.qs == 0) {
		ub_err(uent, "decoder cmdq or evtq qs is 0\n");
		return -EINVAL;
	}

	size = decoder->mmio_end_addr - decoder->mmio_base_addr + 1;
	if (size > mmio_size[decoder->mmio_size_sup])
		decoder->mmio_end_addr = decoder->mmio_base_addr +
					 mmio_size[decoder->mmio_size_sup] - 1;

	ret = ub_cfg_read_dword(uent, UB_CFG1_SUPPORT_FEATURE_L, &feature);
	if (ret) {
		ub_err(uent, "read ub cfg1 support feature failed, ret=%d\n", ret);
		return ret;
	}
	decoder->create_matt = !(feature & UB_DECODER_JURIS);

	ub_info(uent, "decoder mmio_addr[%#llx-%#llx], cmdq_queue_size=%u, evtq_queue_size=%u, mmio_size_sup=%s, matt_jurisdiction=%s\n",
		decoder->mmio_base_addr, decoder->mmio_end_addr, decoder->cmdq.qs, decoder->evtq.qs,
		mmio_size_desc[decoder->mmio_size_sup],
		decoder->create_matt ? "UB driver" : "UBFM");
	return 0;
}

static int ub_create_decoder(struct ub_bus_controller *ubc)
{
	struct ub_entity *uent = ubc->uent;
	struct ub_decoder *decoder;
	int ret;

	decoder = kzalloc(sizeof(*decoder), GFP_KERNEL);
	if (!decoder)
		return -ENOMEM;

	decoder->dev = &ubc->dev;
	decoder->uent = uent;
	mutex_init(&decoder->table_lock);

	ret = ub_get_decoder_mmio_base(ubc, decoder);
	if (ret)
		goto release_decoder;

	ret = ub_get_decoder_cap(decoder);
	if (ret)
		goto release_decoder;

	ret = ub_decoder_init_queue(ubc, decoder);
	if (ret)
		goto release_decoder;

	ret = ub_decoder_create_page_table(ubc, decoder);
	if (ret) {
		ub_err(uent, "decoder create page table failed\n");
		goto release_queue;
	}

	ret = ub_decoder_device_set(decoder);
	if (ret)
		goto release_page_table;

	ubc->decoder = decoder;

	decoder->irq_num = -1;
	decoder->rg_size = SZ_4G;

	ub_info(uent, "decoder create success\n");
	return ret;

release_page_table:
	ub_decoder_free_page_table(ubc, decoder);
release_queue:
	ub_decoder_uninit_queue(ubc, decoder);
release_decoder:
	kfree(decoder);
	return ret;
}

static void unset_mmio_base_reg(struct ub_decoder *decoder)
{
	struct ub_entity *uent = decoder->uent;
	u32 ret;

	ret = (u32)ub_cfg_write_dword(uent, DECODER_MMIO_BA0, 0);
	ret |= (u32)ub_cfg_write_dword(uent, DECODER_MMIO_BA1, 0);
	if (ret)
		ub_err(uent, "unset mmio base reg failed\n");
}

static void unset_page_table_reg(struct ub_decoder *decoder)
{
	struct ub_entity *uent = decoder->uent;
	u32 ret;

	ret = (u32)ub_cfg_write_dword(uent, DECODER_MATT_BA0, 0);
	ret |= (u32)ub_cfg_write_dword(uent, DECODER_MATT_BA1, 0);
	if (ret)
		ub_err(uent, "unset page table reg failed\n");
}

static void ub_decoder_device_unset(struct ub_decoder *decoder)
{
	unset_decoder_enable(decoder);
	unset_queue_reg(decoder);
	unset_page_table_reg(decoder);
	unset_mmio_base_reg(decoder);
}

static void ub_remove_decoder(struct ub_bus_controller *ubc)
{
	struct ub_decoder *decoder = ubc->decoder;

	if (!decoder) {
		ub_err(ubc->uent, "remove decoder, decoder is null\n");
		return;
	}

	ub_decoder_device_unset(decoder);

	ub_decoder_free_page_table(ubc, decoder);

	ub_decoder_uninit_queue(ubc, decoder);

	kfree(decoder);

	ubc->decoder = NULL;
}

static irqreturn_t decoder_event_deal_handle(int irq, void *data)
{
	struct ub_entity *uent = (struct ub_entity *)data;
	struct ub_decoder *decoder = uent->ubc->decoder;
	if (!decoder) {
		ub_err(uent, "decoder does not exist\n");
		return IRQ_NONE;
	}

	if (!uent->ubc->ops->decoder_event_deal) {
		ub_err(uent, "decoder event deal does not exist\n");
		return IRQ_NONE;
	}

	uent->ubc->ops->decoder_event_deal(decoder);
	return IRQ_HANDLED;
}

void ub_init_decoder_usi(struct ub_entity *uent)
{
	int irq_num, ret;
	u32 usi_idx;

	if (!uent->ubc->decoder) {
		ub_err(uent, "decoder not exist, can't init usi\n");
		return;
	}

	ret = ub_cfg_read_dword(uent, DECODER_USI_IDX, &usi_idx);
	if (ret) {
		ub_err(uent, "get decoder usi idx failed\n");
		return;
	}

	irq_num = ub_irq_vector(uent, usi_idx);
	if (irq_num < 0) {
		ub_err(uent, "ub get irq vector failed, ret=%d\n", irq_num);
		return;
	}

	ret = request_irq((unsigned int)irq_num, decoder_event_deal_handle,
			  IRQF_SHARED, "decoder_event_handle", (void *)uent);
	if (ret)
		ub_err(uent, "decoder request_irq failed, ret=%d\n", ret);
	else
		uent->ubc->decoder->irq_num = irq_num;
}

void ub_uninit_decoder_usi(struct ub_entity *uent)
{
	int irq_num;

	if (!uent->ubc->decoder) {
		ub_err(uent, "decoder not exist, can't uninit usi\n");
		return;
	}

	irq_num = uent->ubc->decoder->irq_num;
	if (irq_num < 0)
		return;

	free_irq((unsigned int)irq_num, (void *)uent);
}

void ub_decoder_init(struct ub_entity *uent)
{
	int ret;

	if (!uent || !uent->ubc)
		return;

	if (!is_ibus_controller(uent))
		return;

	ret = ub_create_decoder(uent->ubc);
	WARN_ON(ret);
}

void ub_decoder_uninit(struct ub_entity *uent)
{
	if (!uent || !uent->ubc)
		return;

	if (!is_ibus_controller(uent))
		return;

	ub_remove_decoder(uent->ubc);
}

int ub_decoder_unmap(struct ub_decoder *decoder, phys_addr_t addr, u64 size)
{
	struct ub_bus_controller *ubc;

	if (!decoder) {
		pr_err("unmap mmio decoder ptr is null\n");
		return -EINVAL;
	}

	ubc = decoder->uent->ubc;
	if (!ubc->ops->decoder_unmap) {
		pr_err("decoder_unmap ops not exist\n");
		return -EINVAL;
	}
	return ubc->ops->decoder_unmap(ubc->decoder, addr, size);
}

int ub_decoder_map(struct ub_decoder *decoder, struct decoder_map_info *info)
{
	struct ub_bus_controller *ubc;

	if (!decoder || !info) {
		pr_err("decoder or map info is null\n");
		return -EINVAL;
	}

	ubc = decoder->uent->ubc;
	if (!ubc->ops->decoder_map || !ubc->ops->decoder_unmap) {
		pr_err("decoder_map or decoder_unmap ops not exist\n");
		return -EINVAL;
	}

	return ubc->ops->decoder_map(ubc->decoder, info);
}
