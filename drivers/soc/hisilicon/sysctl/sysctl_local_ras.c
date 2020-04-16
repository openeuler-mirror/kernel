// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Hisilicon Limited, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/delay.h>
#include <linux/io.h>
#include <acpi/ghes.h>
#include <acpi/apei.h>
#include <ras/ras_event.h>
#include <../drivers/acpi/apei/apei-internal.h>
#include "sysctl_local_ras.h"
#include "sysctl_drv.h"
#include "sysctl_dfx.h"

static LIST_HEAD(hisi_ghes_list);
static DEFINE_MUTEX(hisi_ghes_mutex);

#define HISI_GHES_ESTATUS_MAX_SIZE 65536

#define SUBCTRL_REG_BASE 0x000201070000
#define SUBCTRL_TDH_RESET_OFFSET 0xa58
#define SUBCTRL_TDH_UNRESET_OFFSET 0xa5c

#define TDH_REG_BASE 0x000201190000
#define TDH_MEM_ACCESS_OFFSET 0x140

#define TDH_IRQ_CNT_MAX 0x1000

static u32 g_sysctl_tdh_irq_cnt;
static void __iomem *sysctl_subctrl_tdh_priv[CHIP_ID_NUM_MAX];
static void __iomem *sysctl_tdh_priv[CHIP_ID_NUM_MAX];

static int sysctl_tdh_init(void)
{
	u32 chip_id;
	u64 addr;
	u64 tdh_addr;
	u64 chip_module_base;

	pr_info("[INFO] %s start.\n", __func__);

	chip_module_base = get_chip_base();

	for (chip_id = 0; chip_id < CHIP_ID_NUM_MAX; chip_id++) {
		addr = (u64)chip_id * chip_module_base + SUBCTRL_REG_BASE;
		sysctl_subctrl_tdh_priv[chip_id] = ioremap(addr, (u64)0x10000);
		if (!sysctl_subctrl_tdh_priv[chip_id])
			pr_err("chip=%u, subctrl ioremap failed\n", chip_id);

		tdh_addr = (u64)chip_id * chip_module_base + TDH_REG_BASE;
		sysctl_tdh_priv[chip_id] = ioremap(tdh_addr, (u64)0x10000);
		if (!sysctl_tdh_priv[chip_id])
			pr_err("chip=%u, tdh ioremap failed\n", chip_id);
	}

	return SYSCTL_ERR_OK;
}

static void sysctl_tdh_deinit(void)
{
	u8 chip_id;

	for (chip_id = 0; chip_id < CHIP_ID_NUM_MAX; chip_id++) {
		if (sysctl_subctrl_tdh_priv[chip_id])
			iounmap((void *)sysctl_subctrl_tdh_priv[chip_id]);

		if (sysctl_tdh_priv[chip_id])
			iounmap((void *)sysctl_tdh_priv[chip_id]);
	}
}

static int sysctl_tdh_reset(u8 chip_id)
{
	void __iomem *addr;

	if (chip_id >= CHIP_ID_NUM_MAX) {
		pr_err("err chip id %u %s\n", chip_id, __func__);
		return SYSCTL_ERR_PARAM;
	}

	if (!sysctl_subctrl_tdh_priv[chip_id])
		return SYSCTL_ERR_PARAM;

	addr = sysctl_subctrl_tdh_priv[chip_id] + SUBCTRL_TDH_RESET_OFFSET;
	writel(0x3, addr);

	return SYSCTL_ERR_OK;
}

static int sysctl_tdh_unreset(u8 chip_id)
{
	void __iomem *addr;

	if (chip_id >= CHIP_ID_NUM_MAX) {
		pr_err("err chip id %u %s\n", chip_id, __func__);
		return SYSCTL_ERR_PARAM;
	}

	if (!sysctl_subctrl_tdh_priv[chip_id])
		return SYSCTL_ERR_PARAM;

	addr = sysctl_subctrl_tdh_priv[chip_id] + SUBCTRL_TDH_UNRESET_OFFSET;
	writel(0x3, addr);

	return SYSCTL_ERR_OK;
}

static int sysctl_tdh_mem_access_open(u8 chip_id)
{
	void __iomem *addr;

	if (chip_id >= CHIP_ID_NUM_MAX) {
		pr_err("err chip id %u %s\n", chip_id, __func__);
		return SYSCTL_ERR_PARAM;
	}

	if (!sysctl_tdh_priv[chip_id])
		return SYSCTL_ERR_PARAM;

	addr = sysctl_tdh_priv[chip_id] + TDH_MEM_ACCESS_OFFSET;
	writel(0x0, addr);

	return SYSCTL_ERR_OK;
}

static inline bool sysctl_is_hest_type_generic_v2(struct ghes *ghes)
{
	return ghes->generic->header.type == ACPI_HEST_TYPE_GENERIC_ERROR_V2;
}

static int sysctl_map_gen_v2(const struct ghes *ghes)
{
	return apei_map_generic_address(&ghes->generic_v2->read_ack_register);
}

static void sysctl_unmap_gen_v2(const struct ghes *ghes)
{
	apei_unmap_generic_address(&ghes->generic_v2->read_ack_register);
}
static int sysctl_correlation_reg_report(const struct hisi_oem_type1_err_sec *ras_cper)
{
	switch (ras_cper->module_id) {
	case OEM1_MODULE_TDH:
		pr_info("[INFO] SYSCTL RAS tdh correlation_reg info:\n");
		break;
	case OEM1_MODULE_USB:
		if (ras_cper->sub_mod_id == OEM1_SUB_MODULE_USB0) {
			pr_info("[INFO] SYSCTL RAS usb0 correlation_reg info:\n");
		} else if (ras_cper->sub_mod_id == OEM1_SUB_MODULE_USB1) {
			pr_info("[INFO] SYSCTL RAS usb1 correlation_reg info:\n");
		} else if (ras_cper->sub_mod_id == OEM1_SUB_MODULE_USB2) {
			pr_info("[INFO] SYSCTL RAS usb2 correlation_reg info:\n");
		} else {
			pr_err("[ERROR] SYSCTL RAS usb sub_module_id[0x%x] is error.\n", ras_cper->sub_mod_id);
			return -1;
		}
		break;
	case OEM1_MODULE_SATA:
		pr_info("[INFO] SYSCTL RAS sata correlation_reg info:\n");
		break;
	default:
		pr_err("[ERROR] SYSCTL RAS module_id[0x%x] is error.\n", ras_cper->module_id);
		return -1;
	}

	pr_info("[INFO] SYSCTL RAS socket_id: %x.\n", ras_cper->socket_id);
	pr_info("[INFO] SYSCTL RAS nimbus_id: %x.\n", ras_cper->nimbus_id);
	pr_info("[INFO] SYSCTL RAS err_misc0: %x.\n", ras_cper->err_misc0);
	pr_info("[INFO] SYSCTL RAS err_misc1: %x.\n", ras_cper->err_misc1);
	pr_info("[INFO] SYSCTL RAS err_misc2: %x.\n", ras_cper->err_misc2);
	pr_info("[INFO] SYSCTL RAS err_misc3: %x.\n", ras_cper->err_misc3);
	pr_info("[INFO] SYSCTL RAS err_misc4: %x.\n", ras_cper->err_misc4);
	pr_info("[INFO] SYSCTL RAS err_addrl: %x.\n", ras_cper->err_addrl);
	pr_info("[INFO] SYSCTL RAS err_addrh: %x.\n", ras_cper->err_addrh);

	return 0;
}

static int sysctl_do_recovery(const struct hisi_oem_type1_err_sec *ras_cper)
{
	int ret = 0;

	switch (ras_cper->module_id) {
	case OEM1_MODULE_TDH:
		g_sysctl_tdh_irq_cnt++;

		sysctl_tdh_reset(ras_cper->socket_id);
		pr_info("[INFO] SYSCTL RAS tdh of chip[%d] reset.\n", ras_cper->socket_id);
		pr_info("[INFO] SYSCTL RAS sysctl_tdh_irq_cnt[%d].\n", g_sysctl_tdh_irq_cnt);
		udelay(20); /* Delay 20 subtleties */

		if (g_sysctl_tdh_irq_cnt <= TDH_IRQ_CNT_MAX) {
			sysctl_tdh_unreset(ras_cper->socket_id);
			pr_info("[INFO] SYSCTL RAS tdh of chip[%d] unreset.\n", ras_cper->socket_id);

			sysctl_tdh_mem_access_open(ras_cper->socket_id);
			pr_info("[INFO] SYSCTL RAS tdh of chip[%d] mem access open.\n",
				ras_cper->socket_id);
		} else {
			pr_err("[ERROR] SYSCTL RAS tdh of chip[%d] unreset %d times, won't unreset.\n",
				ras_cper->socket_id, TDH_IRQ_CNT_MAX);
		}
		break;
	case OEM1_MODULE_USB:
		if (ras_cper->sub_mod_id == OEM1_SUB_MODULE_USB0) {
			pr_info("[INFO] SYSCTL RAS usb0 error.\n");
		} else if (ras_cper->sub_mod_id == OEM1_SUB_MODULE_USB1) {
			pr_info("[INFO] SYSCTL RAS usb1 error.\n");
		} else if (ras_cper->sub_mod_id == OEM1_SUB_MODULE_USB2) {
			pr_info("[INFO] SYSCTL RAS usb2 error.\n");
		} else {
			pr_err("[ERROR] SYSCTL RAS usb sub_module_id[0x%x] is error.\n", ras_cper->sub_mod_id);
			return ret;
		}
		break;
	case OEM1_MODULE_SATA:
		pr_info("[INFO] SYSCTL RAS sata error.\n");
		break;
	default:
		pr_err("[ERROR] SYSCTL RAS module_id[0x%x] is error, has not match process in sysctl.\n",
			ras_cper->module_id);
		return ret;
	}

	(void)sysctl_correlation_reg_report(ras_cper);

	return ret;
}

static int sysctl_hest_hisi_parse_ghes_count(struct acpi_hest_header *hest_hdr, void *data)
{
	int *count = data;

	if (hest_hdr->type == ACPI_HEST_TYPE_GENERIC_ERROR ||
		hest_hdr->type == ACPI_HEST_TYPE_GENERIC_ERROR_V2)
			(*count)++;
	return 0;
}

static struct ghes *sysctl_ghes_new(struct acpi_hest_generic *sysctl_generic)
{
	struct ghes *sysctl_ghes;
	size_t err_block_length;
	int ret = 0;

	sysctl_ghes = kzalloc(sizeof(*sysctl_ghes), GFP_KERNEL);
	if (!sysctl_ghes)
		return ERR_PTR((long)-ENOMEM);

	sysctl_ghes->generic = sysctl_generic;
	if (sysctl_is_hest_type_generic_v2(sysctl_ghes)) {
		ret = sysctl_map_gen_v2(sysctl_ghes);
		if (ret)
			goto err_free;
	}

	ret = apei_map_generic_address(&sysctl_generic->error_status_address);
	if (ret)
		goto err_unmap_read_ack_addr;

	err_block_length = sysctl_generic->error_block_length;
	if (err_block_length > HISI_GHES_ESTATUS_MAX_SIZE) {
		pr_err("SYSCTL RAS Error status block length is too long: %u for "
			   "generic hardware error source: %d.\n",
			   (u32)err_block_length, sysctl_generic->header.source_id);
		err_block_length = HISI_GHES_ESTATUS_MAX_SIZE;
	}

	sysctl_ghes->estatus = NULL;

	return sysctl_ghes;

err_unmap_read_ack_addr:
	if (sysctl_is_hest_type_generic_v2(sysctl_ghes))
		sysctl_unmap_gen_v2(sysctl_ghes);
err_free:
	kfree(sysctl_ghes);
	return ERR_PTR((long)ret);
}

static int sysctl_hest_hisi_parse_ghes(struct acpi_hest_header *hest_hdr, void *data)
{
	struct acpi_hest_generic *sysctl_generic;
	struct ghes *sysctl_ghes = NULL;
	(void)data;

	sysctl_generic = container_of(hest_hdr, struct acpi_hest_generic, header);
	if (!sysctl_generic->enabled)
		return 0;

	debug_sysctrl_print("[DBG] SYSCTL RAS ghes source id: %x.\n",
		hest_hdr->source_id);
	debug_sysctrl_print("[DBG] SYSCTL RAS ghes error_block_length: %x.\n",
		sysctl_generic->error_block_length);
	debug_sysctrl_print("[DBG] SYSCTL RAS ghes notify type: %x.\n",
		sysctl_generic->notify.type);

	sysctl_ghes = sysctl_ghes_new(sysctl_generic);
	if (!sysctl_ghes) {
		pr_err("[ERROR] SYSCTL RAS sysctl_ghes is null.\n");
		return -ENOMEM;
	}

	list_add(&sysctl_ghes->list, &hisi_ghes_list);

	return 0;
}

static int sysctl_ghes_read_estatus_pre(struct ghes **sysctl_ghes, int silent)
{
	struct acpi_hest_generic *g = (*sysctl_ghes)->generic;
	u32 err_block_length;
	phys_addr_t buf_paddr;
	int ret;

	ret = apei_read(&buf_paddr, &g->error_status_address);
	if (ret) {
		if (!silent && printk_ratelimit())
			pr_err("[ERROR] SYSCTL RAS apei_read fail, source_id: %d.\n", g->header.source_id);

		pr_err("[ERROR] SYSCTL RAS apei_read fail, ret: %d.\n", ret);
		return -EIO;
	}

	if (!buf_paddr) {
		pr_err("[ERROR] SYSCTL RAS buf_paddr is null.\n");
		return -ENOENT;
	}

	err_block_length = g->error_block_length;
	if (err_block_length > HISI_GHES_ESTATUS_MAX_SIZE) {
		pr_info("[INFO] SYSCTL RAS error_block_length: %u, source_id: %d.\n", err_block_length, g->header.source_id);
		err_block_length = HISI_GHES_ESTATUS_MAX_SIZE;
	}

	(*sysctl_ghes)->estatus = ioremap_wc(buf_paddr, err_block_length);
	if (!((*sysctl_ghes)->estatus)) {
		pr_err("estatus ioremap failed\n");
		return -ENOENT;
	}

	if (!((*sysctl_ghes)->estatus->block_status)) {
		iounmap((*sysctl_ghes)->estatus);
		return -ENOENT;
	}

	(*sysctl_ghes)->buffer_paddr = buf_paddr;
	(*sysctl_ghes)->flags |= GHES_TO_CLEAR;

	return 0;
}

static int sysctl_ghes_read_estatus(struct ghes *sysctl_ghes, int silent)
{
	u32 len;
	int ret;

	ret = sysctl_ghes_read_estatus_pre(&sysctl_ghes, silent);
	if (ret)
		return ret;

	ret = -EIO;
	len = cper_estatus_len(sysctl_ghes->estatus);
	if (len < sizeof(*sysctl_ghes->estatus)) {
		pr_err("[ERROR] SYSCTL RAS len[%d] less than sizeof(*ghes->estatus)[%ld].\n",
			len, sizeof(*sysctl_ghes->estatus));
		goto error_read_block;
	}

	if (len > sysctl_ghes->generic->error_block_length) {
		pr_err("[ERROR] SYSCTL RAS len[%d] more than error_block_length[%d].\n",
			len, sysctl_ghes->generic->error_block_length);
		goto error_read_block;
	}

	if (cper_estatus_check_header(sysctl_ghes->estatus)) {
		pr_err("[ERROR] SYSCTL RAS cper_estatus_check_header fail.\n");
		goto error_read_block;
	}

	if (cper_estatus_check(sysctl_ghes->estatus)) {
		pr_err("[ERROR] SYSCTL RAS cper_estatus_check fail.\n");
		goto error_read_block;
	}

	ret = 0;
	return ret;

error_read_block:
	pr_err("[ERROR] SYSCTL RAS info of ghes error status block is error.\n");
	iounmap(sysctl_ghes->estatus);

	pr_err("[ERROR] SYSCTL RAS read error status block fail.\n");
	return ret;
}

void sysctl_ghes_clear_estatus(struct ghes *sysctl_ghes)
{
		sysctl_ghes->estatus->block_status = 0;
		if (!(sysctl_ghes->flags & GHES_TO_CLEAR))
			return;

		sysctl_ghes->flags &= ~GHES_TO_CLEAR;
}

static void sysctl_ghes_do_proc(struct ghes *sysctl_ghes,
	struct acpi_hest_generic_status *sysct_estatus)
{
	struct acpi_hest_generic_data *gdata = NULL;
	guid_t *sec_type = NULL;
	struct hisi_oem_type1_err_sec *ras_cper = NULL;
	struct cper_sec_proc_arm *arm_ras_cper = NULL;
	(void)sysctl_ghes;

	apei_estatus_for_each_section(sysct_estatus, gdata) {
		sec_type = (guid_t *)gdata->section_type;

		sysctl_dfx_do_ras(gdata);
		if (guid_equal(sec_type, &CPER_SEC_HISI_OEM_1)) {
			ras_cper = acpi_hest_get_payload(gdata);
			(void)sysctl_do_recovery(ras_cper);
		} else if (guid_equal(sec_type, &CPER_SEC_PROC_ARM)) {
			arm_ras_cper = acpi_hest_get_payload(gdata);
			if (arm_ras_cper->err_info_num != 1) {
				pr_err("[ERROR] SYSCTL RAS err_info_num[0x%x] is error.\n",
					   arm_ras_cper->err_info_num);
				return;
			}
		}

		cper_estatus_print("[INFO] SYSCTL RAS HISILICON Error : ",
						   sysctl_ghes->estatus);
	}
}

static int sysctl_ghes_proc(struct ghes *sysctl_ghes)
{
	int ret;

	ret = sysctl_ghes_read_estatus(sysctl_ghes, 0);
	if (ret)
		return ret;

	sysctl_ghes_do_proc(sysctl_ghes, sysctl_ghes->estatus);

	iounmap(sysctl_ghes->estatus);

	return ret;
}

static int sysctl_hisi_error_handler(struct work_struct *work)
{
	int ret = 0;
	struct ghes *sysctl_ghes = NULL;
	(void)work;

	list_for_each_entry(sysctl_ghes, &hisi_ghes_list, list) {
		if (!sysctl_ghes_proc(sysctl_ghes))
			ret = NOTIFY_OK;
	}

	return ret;
}

/* acpi hisi hest init */
static void sysctl_acpi_hisi_hest_init(void)
{
	int ret;
	unsigned int ghes_count = 0;

	debug_sysctrl_print("[DBG] SYSCTL RAS %s start.\n", __func__);

	if (hest_disable) {
		pr_err("[ERROR] SYSCTL RAS Table parsing disabled.\n");
		return;
	}

	ret = apei_hest_parse(sysctl_hest_hisi_parse_ghes_count, &ghes_count);
	if (ret) {
		pr_err("[ERROR] SYSCTL RAS hest_hisi_parse_ghes_count fail.\n");
		return;
	}
	debug_sysctrl_print("[DBG] SYSCTL RAS Get ghes count: %d.\n", ghes_count);

	ret = apei_hest_parse(sysctl_hest_hisi_parse_ghes, &ghes_count);
	if (ret) {
		pr_err("[ERROR] SYSCTL RAS hest_hisi_parse_ghes fail.\n");
		return;
	}
}

int sysctl_notify_hed(struct notifier_block *that, unsigned long event, void *data)
{
	int ret;
	(void)event;
	(void)data;
	(void)that;

	ret = sysctl_hisi_error_handler(NULL);

	return ret;
}

static struct notifier_block g_sysctl_ghes_hisi_notifier_hed = {
	.notifier_call = sysctl_notify_hed,
	.priority = INT_MAX,
};

int hip_sysctl_local_ras_init(void)
{
	int ret;

	sysctl_proc_init();

	ret = sysctl_tdh_init();
	if (ret != SYSCTL_ERR_OK) {
		pr_err("[ERROR] SYSCTL RAS sysctl_tdh_init fail.\n");
		return ret;
	}

	sysctl_acpi_hisi_hest_init();

	ret = register_acpi_hed_notifier(&g_sysctl_ghes_hisi_notifier_hed);
	if (ret != SYSCTL_ERR_OK) {
		pr_err("[ERROR] SYSCTL RAS register_acpi_hed_notifier fail.\n");
		return ret;
	}

	ret = sysctl_tdh_mem_access_open(0);
	if (ret != SYSCTL_ERR_OK) {
		pr_err("[ERROR] SYSCTL RAS sysctl_tdh_mem_access_open fail.\n");
		return ret;
	}

	return ret;
}

static void his_ghes_list_free(void)
{
	struct ghes *node = NULL;
	struct ghes *tmp_node = NULL;

	list_for_each_entry(node, &hisi_ghes_list, list) {
		if (!node)
			continue;

		apei_unmap_generic_address(&node->generic->error_status_address);

		if (sysctl_is_hest_type_generic_v2(node))
			sysctl_unmap_gen_v2(node);

		/* Release the node of the previous loop. */
		if (tmp_node != NULL) {
			kfree(tmp_node);
			tmp_node = NULL;
		}

		/* Record the node of the current loop. */
		tmp_node = node;

		/* hisi_ghes_list isn't a member of node. */
		if (node->list.next == &hisi_ghes_list) {
			node = NULL;
			break;
		}
	}

	if (tmp_node != NULL) {
		kfree(tmp_node);
		tmp_node = NULL;
	}
}

void hip_sysctl_local_ras_exit(void)
{
	unregister_acpi_hed_notifier(&g_sysctl_ghes_hisi_notifier_hed);
	sysctl_proc_exit();
	sysctl_tdh_deinit();
	his_ghes_list_free();

	pr_info("[INFO] hip sysctl local ras exit.\n");
}
