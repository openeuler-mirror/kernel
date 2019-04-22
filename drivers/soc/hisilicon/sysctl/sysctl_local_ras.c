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

#define GHES_ESTATUS_MAX_SIZE 65536

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
	void __iomem *chip_ver_base;

	chip_ver_base = ioremap(0xd7d00000, (u64)0x10000);
	if (!chip_ver_base) {
		pr_err("%s: chip_ver_base is error.\n", __func__);
		return ERR_FAILED;
	}
	chip_ver_addr = chip_ver_base + 0x8;

	chip_ver = readl(chip_ver_addr);
	if ((chip_ver & CHIP_VERSION_MASK) == CHIP_VERSION_ES) {
		chip_module_base = HLLC_CHIP_MODULE_ES;
	} else if ((chip_ver & CHIP_VERSION_MASK) == CHIP_VERSION_CS) {
		chip_module_base = HLLC_CHIP_MODULE_CS;
	} else {
		pr_err("%s: chip_ver[%u] is ERR.\n", __func__, chip_ver);
		iounmap((void *)chip_ver_base);
		return ERR_FAILED;
	}

	for (chip_id = 0; chip_id < CHIP_ID_NUM_MAX; chip_id++) {
			addr = (u64)chip_id * chip_module_base + SUBCTRL_REG_BASE;
			sysctl_subctrl_lpc_priv[chip_id] = ioremap(addr, (u64)0x10000);
			debug_sysctrl_print("subctl lpc_reset addr:%p\n", sysctl_subctrl_lpc_priv[chip_id]);

			lpc_addr = (u64)chip_id * chip_module_base + LPC_REG_BASE;
			sysctl_lpc_priv[chip_id] = ioremap(lpc_addr, (u64)0x10000);
			debug_sysctrl_print("lpc mem access ctrl addr:%p\n", sysctl_lpc_priv[chip_id]);
	}

	iounmap((void *)chip_ver_base);

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
		pr_err("SYSCTL RAS lpc correlation_reg info");
		break;

	case MODULE_USB2_ERR:
		pr_err("SYSCTL RAS usb2 correlation_reg info");
		break;

	case MODULE_USB3_ERR:
		pr_err("SYSCTL RAS usb3 correlation_reg info");
		break;

	default:
		pr_err("SYSCTL RAS module_id[0x%x] correlation_reg info",
			ras_cper->module_id);
		return -1;
	}

	pr_err("SYSCTL RAS socket_id %x",
		ras_cper->socket_id);
	pr_err("SYSCTL RAS nimbus_id %x",
		ras_cper->nimbus_id);
	pr_err("SYSCTL RAS err_misc0 %x",
		ras_cper->err_misc0);
	pr_err("SYSCTL RAS err_misc1 %x",
		ras_cper->err_misc1);
	pr_err("SYSCTL RAS err_misc2 %x",
		ras_cper->err_misc2);
	pr_err("SYSCTL RAS err_misc3 %x",
		ras_cper->err_misc3);
	pr_err("SYSCTL RAS err_misc4 %x",
		ras_cper->err_misc4);
	pr_err("SYSCTL RAS err_addrl %x",
		ras_cper->err_addrl);
	pr_err("SYSCTL RAS err_addrh %x",
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
		pr_err("SYSCTL RAS lpc of chip[%d] reset", ras_cper->socket_id);
		pr_err("SYSCTL RAS sysctl_lpc_irq_cnt[%d]", sysctl_lpc_irq_cnt);
		udelay((unsigned long)20);

		if (sysctl_lpc_irq_cnt <= LPC_IRQ_CNT_MAX) {
			sysctl_lpc_unreset(ras_cper->socket_id);
			pr_err("SYSCTL RAS lpc of chip[%d] unreset",
				ras_cper->socket_id);

			sysctl_lpc_mem_access_open(ras_cper->socket_id);
			pr_err("SYSCTL RAS lpc of chip[%d] mem access open",
				ras_cper->socket_id);
		} else {
			pr_err("SYSCTL RAS lpc of chip[%d] unreset 3 times, which won't unreset",
				ras_cper->socket_id);
		}
		break;
	case MODULE_USB2_ERR:
		pr_err("SYSCTL RAS usb2 err %d", ret);
		break;
	case MODULE_USB3_ERR:
		pr_err("SYSCTL RAS usb3 err %d", ret);
		break;
	default:
		pr_err("SYSCTL RAS err module_id[0x%x]  not process in sysctl\n",
			ras_cper->module_id);
		return 0;
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

static struct ghes *sysctl_ghes_new(struct acpi_hest_generic *generic)
{
	struct ghes *ghes;
	size_t error_block_length;
	int rc = 0;

	ghes = kzalloc(sizeof(*ghes), GFP_KERNEL);
	if (!ghes)
		return ERR_PTR((long)-ENOMEM);

	ghes->generic = generic;
	if (is_hest_type_generic_v2(ghes)) {
		rc = map_gen_v2(ghes);
		if (rc)
			goto err_free;
	}

	rc = apei_map_generic_address(&generic->error_status_address);
	if (rc)
		goto err_unmap_read_ack_addr;

	error_block_length = generic->error_block_length;
	if (error_block_length > GHES_ESTATUS_MAX_SIZE) {
		pr_err("SYSCTL RAS Error status block length is too long: %u for "
				"generic hardware error source: %d.\n",
				(u32)error_block_length, generic->header.source_id);
		error_block_length = GHES_ESTATUS_MAX_SIZE;
	}

	ghes->estatus = (struct acpi_hest_generic_status *)kmalloc(error_block_length, GFP_KERNEL);
	if (!ghes->estatus) {
		rc = -ENOMEM;
		goto err_unmap_status_addr;
	}

	return ghes;

err_unmap_status_addr:
	apei_unmap_generic_address(&generic->error_status_address);

err_unmap_read_ack_addr:
	if (is_hest_type_generic_v2(ghes))
		unmap_gen_v2(ghes);
err_free:
	kfree(ghes);
	return ERR_PTR((long)rc);
}

static int sysctl_hest_hisi_parse_ghes(struct acpi_hest_header *hest_hdr, void *data)
{
	struct acpi_hest_generic *generic;
	struct ghes *ghes;
	(void)data;

	generic = container_of(hest_hdr, struct acpi_hest_generic, header);
	if (!generic->enabled)
		return 0;

	debug_sysctrl_print("SYSCTL RAS HISILICON Error : ghes source id = %x\n",
		hest_hdr->source_id);
	debug_sysctrl_print("SYSCTL RAS HISILICON Error : ghes error_block_length = %x\n",
		generic->error_block_length);
	debug_sysctrl_print("SYSCTL RAS HISILICON Error : ghes notify type = %x\n",
		generic->notify.type);

	ghes = sysctl_ghes_new(generic);
	if (!ghes)
		return -ENOMEM;

	mutex_lock(&hisi_ghes_mutex);
	list_add_rcu(&ghes->list, &hisi_ghes_list);
	mutex_unlock(&hisi_ghes_mutex);

	return 0;
}

static int sysctl_ghes_read_estatus(struct ghes *ghes, int silent)
{
	struct acpi_hest_generic *g = ghes->generic;
	phys_addr_t buf_paddr;
	u32 error_block_length;
	u32 len;
	int rc = 0;

	rc = apei_read(&buf_paddr, &g->error_status_address);
	if (rc) {
		if (!silent && printk_ratelimit()) {
			pr_err("SYSCTL RAS Failed to read error status block address for hardware error source: %d.\n",
			g->header.source_id);
		}

		pr_err("SYSCTL RAS apei_read rc: %d.\n", rc);
		return -EIO;
	}

	if (!buf_paddr) {
		pr_err("SYSCTL RAS buf_paddr is null.\n");
		return -ENOENT;
	}

	error_block_length = g->error_block_length;
	if (error_block_length > GHES_ESTATUS_MAX_SIZE) {
		pr_err("SYSCTL RAS error_block_length: %u, source_id: %d.\n",
			error_block_length, g->header.source_id);
		error_block_length = GHES_ESTATUS_MAX_SIZE;
	}
	ghes->estatus = ioremap_wc(buf_paddr, error_block_length);

	if (!ghes->estatus) {
		pr_err("SYSCTL RAS ghes->estatus is null.\n");
		goto err_release_estatus;
	}

	if (!ghes->estatus->block_status) {
		pr_err("SYSCTL RAS ghes->estatus->block_status is 0.\n");
		iounmap(ghes->estatus);
		return -ENOENT;
	}

	ghes->buffer_paddr = buf_paddr;
	ghes->flags |= GHES_TO_CLEAR;

	rc = -EIO;
	len = cper_estatus_len(ghes->estatus);
	if (len < sizeof(*ghes->estatus)) {
		pr_err("SYSCTL RAS len[%d] less than sizeof(*ghes->estatus)[%ld].\n",
			len, sizeof(*ghes->estatus));
		goto err_read_block;
	}

	if (len > ghes->generic->error_block_length) {
		pr_err("SYSCTL RAS len[%d] more than error_block_length[%d].\n",
			len, ghes->generic->error_block_length);
		goto err_read_block;
	}

	if (cper_estatus_check_header(ghes->estatus)) {
		pr_err("SYSCTL RAS cper_estatus_check_header fail.\n");
		goto err_read_block;
	}

	pr_err("SYSCTL RAS HISILICON Error : ghes source id is %d\n",
		g->header.source_id);
	pr_err("SYSCTL RAS HISILICON Error : error status addr is 0x%llx\n",
		buf_paddr);
	pr_err("SYSCTL RAS HISILICON Error : data_length = %d.\n",
		ghes->estatus->data_length);
	pr_err("SYSCTL RAS HISILICON Error : severity = %d.\n",
		ghes->estatus->error_severity);

	if (cper_estatus_check(ghes->estatus)) {
		pr_err("SYSCTL RAS cper_estatus_check fail.\n");
		goto err_read_block;
	}

	rc = 0;
	return rc;

err_read_block:
	pr_err("SYSCTL RAS ghes error status block read error\n");
	iounmap(ghes->estatus);

	pr_err("SYSCTL RAS Failed to read error status block!\n");
err_release_estatus:
	pr_err("error ioremap, release memory\n");
	return rc;
}

void sysctl_ghes_clear_estatus(struct ghes *ghes)
{
		ghes->estatus->block_status = 0;
		if (!(ghes->flags & GHES_TO_CLEAR))
				return;

		ghes->flags &= ~GHES_TO_CLEAR;
}

static void sysctl_ghes_do_proc(struct ghes *ghes,
			 struct acpi_hest_generic_status *estatus)
{

	struct acpi_hest_generic_data *gdata = NULL;
	guid_t *sec_type;
	struct sysctl_local_ras_cper *ras_cper;
	struct cper_sec_proc_arm *arm_ras_cper;
	(void)ghes;

	apei_estatus_for_each_section(estatus, gdata) {
		sec_type = (guid_t *)gdata->section_type;

		if (guid_equal(sec_type, &CPER_SEC_PLATFORM_sysctl_LOCAL_RAS)) {
			ras_cper = acpi_hest_get_payload(gdata);
			(void)sysctl_do_recovery(ras_cper);

		} else if (guid_equal(sec_type, &CPER_SEC_PROC_ARM)) {
			arm_ras_cper = acpi_hest_get_payload(gdata);
			if (arm_ras_cper->err_info_num != 1) {
				pr_err("SYSCTL RAS ERR: err_info_num[0x%x] is err.\n",
					arm_ras_cper->err_info_num);
				return;
			}
		}

		cper_estatus_print("SYSCTL RAS HISILICON Error : ",
			ghes->estatus);
	}
	return;
}

static int sysctl_ghes_proc(struct ghes *ghes)
{
	int rc = 0;

	rc = sysctl_ghes_read_estatus(ghes, 0);
	if (rc)
		return rc;

	sysctl_ghes_do_proc(ghes, ghes->estatus);

	if (ghes->estatus)
		iounmap(ghes->estatus);

	return rc;
}

static int sysctl_hisi_error_handler(struct work_struct *work)
{

	int ret = 0;
	struct ghes *ghes;
	(void)work;

	pr_err("SYSCTL RAS HISILICON Error : handler start.\n");
	rcu_read_lock();
	list_for_each_entry_rcu(ghes, &hisi_ghes_list, list) {
		if (!sysctl_ghes_proc(ghes))
			ret = NOTIFY_OK;
	}
	rcu_read_unlock();

	pr_err("SYSCTL RAS ghes_proc %d", ret);
	pr_err("SYSCTL RAS HISILICON Error : handler end.\n");

	return ret;

}

/*acpi hisi hest init*/
static void sysctl_acpi_hisi_hest_init(void)
{
	int rc;
	unsigned int ghes_count = 0;

	debug_sysctrl_print("SYSCTL RAS sysctl_acpi_hisi_hest_init start\n");

	if (hest_disable) {
		pr_err("SYSCTL RAS Table parsing disabled.\n");
		return;
	}

	rc = apei_hest_parse(sysctl_hest_hisi_parse_ghes_count, &ghes_count);
	if (rc) {
		pr_err("SYSCTL RAS hest_hisi_parse_ghes_count faile.\n");
		return;
	}

	debug_sysctrl_print("SYSCTL RAS Get ghes count = %d\n", ghes_count);

	rc = apei_hest_parse(sysctl_hest_hisi_parse_ghes, &ghes_count);
	if (rc) {
		pr_err("SYSCTL RAS hest_hisi_parse_ghes faile.\n");
		return;
	}
	debug_sysctrl_print("SYSCTL RAS sysctl_acpi_hisi_hest_init end\n");

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

	pr_err(KERN_INFO "Goodbye test.\n");
}
