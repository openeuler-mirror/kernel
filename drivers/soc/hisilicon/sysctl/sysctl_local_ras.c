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
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http:
 */

#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/percpu.h>
#include <linux/acpi.h>
#include <linux/property.h>
#include <linux/platform_device.h>
#include <acpi/actbl.h>
#include <acpi/actbl1.h>
#include <acpi/ghes.h>
#include <acpi/apei.h>
#include <asm/fixmap.h>
#include <ras/ras_event.h>
#include <uapi/linux/uuid.h>
#include <../drivers/acpi/apei/apei-internal.h>

#include "sysctl_local_ras.h"
#include "sysctl_drv.h"

static LIST_HEAD(hisi_ghes_list);
static DEFINE_MUTEX(hisi_ghes_mutex);

#define HISI_GHES_ESTATUS_MAX_SIZE 65536

/* Platform Memory */
#define CPER_SEC_PLATFORM_sysctl_LOCAL_RAS \
	GUID_INIT(0x1F8161E1, 0x55D6, 0x41E6, 0xBD, 0x10, 0x7A,\
		   0xFD, 0x1D, 0xC5, 0xF7, 0xC5)

#define SUBCTRL_REG_BASE (0x000201070000)
#define SUBCTRL_LPC_RESET_OFFSET (0xa58)
#define SUBCTRL_LPC_UNRESET_OFFSET (0xa5c)

#define LPC_REG_BASE (0x000201190000)
#define LPC_MEM_ACCESS_OFFSET (0x140)

#define LPC_IRQ_CNT_MAX (0x1000)

static u32 sysctl_lpc_irq_cnt;
static void __iomem *sysctl_subctrl_lpc_priv[CHIP_ID_NUM_MAX];
static void __iomem *sysctl_lpc_priv[CHIP_ID_NUM_MAX];

static int sysctl_lpc_init(void)
{
	u32 chip_id;
	u64 addr;
	u64 lpc_addr;
	u32 chip_ver;
	u64 chip_module_base;
	void __iomem *chip_ver_addr;

	pr_info("[INFO] %s start.\n", __func__);

	chip_ver_addr = ioremap(0x20107E238, (u64)4);
	if (!chip_ver_addr) {
		pr_err("[ERROR] %s chip_ver_base is error.\n", __func__);
		return ERR_FAILED;
	}

	chip_ver = readl(chip_ver_addr);
	chip_ver = chip_ver>>28;
	if (chip_ver == CHIP_VERSION_ES) {
		pr_info("[sysctl lpc] chip is es\n");
		chip_module_base = HLLC_CHIP_MODULE_ES;
	} else {
		chip_module_base = HLLC_CHIP_MODULE_CS;
		pr_info("[sysctl lpc] chip is cs\n");
	}

	pr_info("[sysctl lpc] chip ver=%x\n", chip_ver);
	for (chip_id = 0; chip_id < CHIP_ID_NUM_MAX; chip_id++) {
			addr = (u64)chip_id * chip_module_base + SUBCTRL_REG_BASE;
			sysctl_subctrl_lpc_priv[chip_id] = ioremap(addr, (u64)0x10000);
			debug_sysctrl_print("[DBG] subctl lpc reset addr of chip[%d]: %p.\n",
				chip_id, sysctl_subctrl_lpc_priv[chip_id]);

			lpc_addr = (u64)chip_id * chip_module_base + LPC_REG_BASE;
			sysctl_lpc_priv[chip_id] = ioremap(lpc_addr, (u64)0x10000);
			debug_sysctrl_print("[DBG] lpc mem access ctrl addr of chip[%d]: %p.\n",
				chip_id, sysctl_lpc_priv[chip_id]);
	}

	iounmap((void *)chip_ver_addr);

	return ERR_OK;
}

static int sysctl_lpc_deinit(void)
{
	u8 chip_id;

	for (chip_id = 0; chip_id < CHIP_ID_NUM_MAX; chip_id++) {
		if (sysctl_subctrl_lpc_priv[chip_id])
			iounmap((void *)sysctl_subctrl_lpc_priv[chip_id]);

		if (sysctl_lpc_priv[chip_id])
			iounmap((void *)sysctl_lpc_priv[chip_id]);
	}

	return ERR_OK;
}

static int sysctl_lpc_reset(u8 chip_id)
{
	void __iomem *addr;

	addr = sysctl_subctrl_lpc_priv[chip_id] + SUBCTRL_LPC_RESET_OFFSET;
	writel(0x3, addr);

	return ERR_OK;
}

static int sysctl_lpc_unreset(u8 chip_id)
{
	void __iomem *addr;

	addr = sysctl_subctrl_lpc_priv[chip_id] + SUBCTRL_LPC_UNRESET_OFFSET;
	writel(0x3, addr);

	return ERR_OK;
}

static int sysctl_lpc_mem_access_open(u8 chip_id)
{
   void __iomem *addr;

   if (!sysctl_lpc_priv[chip_id])
	return ERR_PARAM;

   addr = sysctl_lpc_priv[chip_id] + LPC_MEM_ACCESS_OFFSET;
   writel(0x0, addr);

   return ERR_OK;
}

static inline bool is_hest_type_generic_v2(struct ghes *ghes)
{
		return ghes->generic->header.type == ACPI_HEST_TYPE_GENERIC_ERROR_V2;
}

static int map_gen_v2(const struct ghes *ghes)
{
		return apei_map_generic_address(&ghes->generic_v2->read_ack_register);
}

static void unmap_gen_v2(const struct ghes *ghes)
{
		apei_unmap_generic_address(&ghes->generic_v2->read_ack_register);
}
static int sysctl_correlation_reg_report(const struct sysctl_local_ras_cper *ras_cper)
{
	switch (ras_cper->module_id) {
	case MODULE_LPC_ERR:
		pr_info("[INFO] SYSCTL RAS lpc correlation_reg info:\n");
		break;
	case MODULE_USB_ERR:
		if (ras_cper->sub_mod_id == MODULE_USB0_ERR) {
			pr_info("[INFO] SYSCTL RAS usb0 correlation_reg info:\n");
		} else if (ras_cper->sub_mod_id == MODULE_USB1_ERR) {
			pr_info("[INFO] SYSCTL RAS usb1 correlation_reg info:\n");
		} else if (ras_cper->sub_mod_id == MODULE_USB2_ERR) {
			pr_info("[INFO] SYSCTL RAS usb2 correlation_reg info:\n");
		} else {
			pr_err("[ERROR] SYSCTL RAS usb sub_module_id[0x%x] is error.\n",
				ras_cper->sub_mod_id);
			return -1;
		}
		break;
	case MODULE_SAS_ERR:
		if (ras_cper->sub_mod_id == MODULE_SAS0_ERR) {
			pr_info("[INFO] SYSCTL RAS sas0 correlation_reg info:\n");
		} else if (ras_cper->sub_mod_id == MODULE_SAS1_ERR) {
			pr_info("[INFO] SYSCTL RAS sas1 correlation_reg info:\n");
		} else {
			pr_err("[ERROR] SYSCTL RAS sas sub_module_id[0x%x] is error.\n",
				ras_cper->sub_mod_id);
			return -1;
		}
		break;
	default:
		pr_err("[ERROR] SYSCTL RAS module_id[0x%x] is error.\n",
			ras_cper->module_id);
		return -1;
	}

	pr_info("[INFO] SYSCTL RAS socket_id: %x.\n",
		ras_cper->socket_id);
	pr_info("[INFO] SYSCTL RAS nimbus_id: %x.\n",
		ras_cper->nimbus_id);
	pr_info("[INFO] SYSCTL RAS err_misc0: %x.\n",
		ras_cper->err_misc0);
	pr_info("[INFO] SYSCTL RAS err_misc1: %x.\n",
		ras_cper->err_misc1);
	pr_info("[INFO] SYSCTL RAS err_misc2: %x.\n",
		ras_cper->err_misc2);
	pr_info("[INFO] SYSCTL RAS err_misc3: %x.\n",
		ras_cper->err_misc3);
	pr_info("[INFO] SYSCTL RAS err_misc4: %x.\n",
		ras_cper->err_misc4);
	pr_info("[INFO] SYSCTL RAS err_addrl: %x.\n",
		ras_cper->err_addrl);
	pr_info("[INFO] SYSCTL RAS err_addrh: %x.\n",
		ras_cper->err_addrh);

	return 0;
}

static int sysctl_do_recovery(const struct sysctl_local_ras_cper *ras_cper)
{
	int ret = 0;

	switch (ras_cper->module_id) {
	case MODULE_LPC_ERR:
		sysctl_lpc_irq_cnt++;

		sysctl_lpc_reset(ras_cper->socket_id);
		pr_info("[INFO] SYSCTL RAS lpc of chip[%d] reset.\n", ras_cper->socket_id);
		pr_info("[INFO] SYSCTL RAS sysctl_lpc_irq_cnt[%d].\n", sysctl_lpc_irq_cnt);
		udelay((unsigned long)20);

		if (sysctl_lpc_irq_cnt <= LPC_IRQ_CNT_MAX) {
			sysctl_lpc_unreset(ras_cper->socket_id);
			pr_info("[INFO] SYSCTL RAS lpc of chip[%d] unreset.\n",
				ras_cper->socket_id);

			sysctl_lpc_mem_access_open(ras_cper->socket_id);
			pr_info("[INFO] SYSCTL RAS lpc of chip[%d] mem access open.\n",
				ras_cper->socket_id);
		} else {
			pr_err("[ERROR] SYSCTL RAS lpc of chip[%d] unreset %d times, won't unreset.\n",
				ras_cper->socket_id, LPC_IRQ_CNT_MAX);
		}
		break;
	case MODULE_USB_ERR:
		if (ras_cper->sub_mod_id == MODULE_USB0_ERR) {
			pr_info("[INFO] SYSCTL RAS usb0 error.\n");
		} else if (ras_cper->sub_mod_id == MODULE_USB1_ERR) {
			pr_info("[INFO] SYSCTL RAS usb1 error.\n");
		} else if (ras_cper->sub_mod_id == MODULE_USB2_ERR) {
			pr_info("[INFO] SYSCTL RAS usb2 error.\n");
		} else {
			pr_err("[ERROR] SYSCTL RAS usb sub_module_id[0x%x] is error.\n",
				ras_cper->sub_mod_id);
			return ret;
		}
		break;
	case MODULE_SAS_ERR:
		if (ras_cper->sub_mod_id == MODULE_SAS0_ERR) {
			pr_info("[INFO] SYSCTL RAS sas0 error.\n");
		} else if (ras_cper->sub_mod_id == MODULE_SAS1_ERR) {
			pr_info("[INFO] SYSCTL RAS sas1 error.\n");
		} else {
			pr_err("[ERROR] SYSCTL RAS sas sub_module_id[0x%x] is error.\n",
				ras_cper->sub_mod_id);
			return ret;
		}
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
	size_t err_block_length = 0;
	int ret = 0;

	sysctl_ghes = kzalloc(sizeof(*sysctl_ghes), GFP_KERNEL);
	if (!sysctl_ghes)
		return ERR_PTR((long)-ENOMEM);

	sysctl_ghes->generic = sysctl_generic;
	if (is_hest_type_generic_v2(sysctl_ghes)) {
		ret = map_gen_v2(sysctl_ghes);
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

	sysctl_ghes->estatus = (struct acpi_hest_generic_status *)kmalloc(err_block_length, GFP_KERNEL);
	if (!sysctl_ghes->estatus) {
		ret = -ENOMEM;
		goto err_unmap_status_addr;
	}

	return sysctl_ghes;

err_unmap_status_addr:
	apei_unmap_generic_address(&sysctl_generic->error_status_address);

err_unmap_read_ack_addr:
	if (is_hest_type_generic_v2(sysctl_ghes))
		unmap_gen_v2(sysctl_ghes);
err_free:
	kfree(sysctl_ghes);
	return ERR_PTR((long)ret);
}

static int sysctl_hest_hisi_parse_ghes(struct acpi_hest_header *hest_hdr, void *data)
{
	struct acpi_hest_generic *sysctl_generic;
	struct ghes *sysctl_ghes;
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

	mutex_lock(&hisi_ghes_mutex);
	list_add_rcu(&sysctl_ghes->list, &hisi_ghes_list);
	mutex_unlock(&hisi_ghes_mutex);

	return 0;
}

static int sysctl_ghes_read_estatus(struct ghes *sysctl_ghes, int silent)
{
	struct acpi_hest_generic *g = sysctl_ghes->generic;
	phys_addr_t buf_paddr;
	u32 err_block_length = 0;
	u32 len;
	int ret = 0;

	ret = apei_read(&buf_paddr, &g->error_status_address);
	if (ret) {
		if (!silent && printk_ratelimit()) {
			pr_err("[ERROR] SYSCTL RAS apei_read fail, source_id: %d.\n",
				g->header.source_id);
		}

		pr_err("[ERROR] SYSCTL RAS apei_read fail, ret: %d.\n", ret);
		return -EIO;
	}

	if (!buf_paddr) {
		pr_err("[ERROR] SYSCTL RAS buf_paddr is null.\n");
		return -ENOENT;
	}

	err_block_length = g->error_block_length;
	if (err_block_length > HISI_GHES_ESTATUS_MAX_SIZE) {
		pr_info("[INFO] SYSCTL RAS error_block_length: %u, source_id: %d.\n",
			err_block_length, g->header.source_id);
		err_block_length = HISI_GHES_ESTATUS_MAX_SIZE;
	}
	sysctl_ghes->estatus = ioremap_wc(buf_paddr, err_block_length);

	if (!sysctl_ghes->estatus) {
		pr_err("[ERROR] SYSCTL RAS sysctl_ghes->estatus is null.\n");
		goto error_release_estatus;
	}

	if (!sysctl_ghes->estatus->block_status) {
		pr_err("[ERROR] SYSCTL RAS sysctl_ghes->estatus->block_status is 0.\n");
		iounmap(sysctl_ghes->estatus);
		return -ENOENT;
	}

	sysctl_ghes->buffer_paddr = buf_paddr;
	sysctl_ghes->flags |= GHES_TO_CLEAR;

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

	pr_info("[INFO] SYSCTL RAS HISILICON Error : ghes source id is %d.\n",
		g->header.source_id);
	pr_info("[INFO] SYSCTL RAS HISILICON Error : error status addr is 0x%llx.\n",
		buf_paddr);
	pr_info("[INFO] SYSCTL RAS HISILICON Error : data_length is %d.\n",
		sysctl_ghes->estatus->data_length);
	pr_info("[INFO] SYSCTL RAS HISILICON Error : severity is %d.\n",
		sysctl_ghes->estatus->error_severity);

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
error_release_estatus:
	pr_err("[ERROR] ioremap_wc fail, release_estatus.\n");
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
	guid_t *sec_type;
	struct sysctl_local_ras_cper *ras_cper;
	struct cper_sec_proc_arm *arm_ras_cper;
	(void)sysctl_ghes;

	apei_estatus_for_each_section(sysct_estatus, gdata) {
		sec_type = (guid_t *)gdata->section_type;

		if (guid_equal(sec_type, &CPER_SEC_PLATFORM_sysctl_LOCAL_RAS)) {
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
	return;
}

static int sysctl_ghes_proc(struct ghes *sysctl_ghes)
{
	int ret = 0;

	ret = sysctl_ghes_read_estatus(sysctl_ghes, 0);
	if (ret)
		return ret;

	sysctl_ghes_do_proc(sysctl_ghes, sysctl_ghes->estatus);

	if (sysctl_ghes->estatus)
		iounmap(sysctl_ghes->estatus);

	return ret;
}

static int sysctl_hisi_error_handler(struct work_struct *work)
{

	int ret = 0;
	struct ghes *sysctl_ghes;
	(void)work;

	pr_info("[INFO] SYSCTL RAS %s start.\n", __func__);

	rcu_read_lock();
	list_for_each_entry_rcu(sysctl_ghes, &hisi_ghes_list, list) {
		if (!sysctl_ghes_proc(sysctl_ghes))
			ret = NOTIFY_OK;
	}
	rcu_read_unlock();

	pr_info("[INFO] SYSCTL RAS sysctl_ghes_proc ret: %d.\n", ret);
	pr_info("[INFO] SYSCTL RAS %s end.\n", __func__);

	return ret;

}

/*acpi hisi hest init*/
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
	debug_sysctrl_print("[DBG] SYSCTL RAS sysctl_acpi_hisi_hest_init end.\n");

	return;
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

static struct notifier_block sysctl_ghes_hisi_notifier_hed = {
	.notifier_call = sysctl_notify_hed,
	.priority = INT_MAX,
};

int hip_sysctl_local_ras_init(void)
{
	int ret;

	sysctl_lpc_init();

	sysctl_acpi_hisi_hest_init();

	ret = register_acpi_hed_notifier(&sysctl_ghes_hisi_notifier_hed);

	sysctl_lpc_mem_access_open(0);

	return ret;
}

void hip_sysctl_local_ras_exit(void)
{
	sysctl_lpc_deinit();

	unregister_acpi_hed_notifier(&sysctl_ghes_hisi_notifier_hed);

	pr_info("[INFO] hip sysctl local ras exit.\n");
}
