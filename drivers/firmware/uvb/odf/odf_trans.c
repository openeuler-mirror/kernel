// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: odf trans file
 * Author: zhangrui
 * Create: 2025-04-18
 */
#define pr_fmt(fmt) "[UVB]: " fmt

#include <linux/string.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/sizes.h>
#include "cis_uvb_interface.h"
#include "odf_interface.h"
#include "odf_handle.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ODF Api");

struct cis_info *g_cis_info;
EXPORT_SYMBOL(g_cis_info);

DEFINE_RWLOCK(g_cis_group_lock);
EXPORT_SYMBOL(g_cis_group_lock);

struct uvb_info *g_uvb_info;
EXPORT_SYMBOL(g_uvb_info);

struct ubios_od_root *od_root;

void free_cis_info(void)
{
	struct cis_group_node *node, *tmp;
	unsigned long flags;

	write_lock_irqsave(&g_cis_group_lock, flags);

	if (!g_cis_info) {
		write_unlock_irqrestore(&g_cis_group_lock, flags);
		return;
	}

	list_for_each_entry_safe(node, tmp, &g_cis_info->group_list, list) {
		list_del(&node->list);
		kfree(node->group);
		kfree(node);
	}

	kfree(g_cis_info);
	g_cis_info = NULL;

	write_unlock_irqrestore(&g_cis_group_lock, flags);
}

struct cis_group *create_group_from_vs(struct ubios_od_value_struct *vs)
{
	struct ubios_od_list_info list;
	struct cis_group *group;
	int status;
	int i;

	status = odf_get_list_from_struct(vs, ODF_NAME_CIS_CALL_ID, &list);
	if (status) {
		pr_err("create group: get [call id list] failed, err = %d\n", status);
		return NULL;
	}

	/* count entries must fit inside [start, end): count comes from the
	 * (possibly remote) payload and must not drive the kzalloc size or
	 * the odf_get_u32_from_list() loop beyond the real buffer.
	 */
	if (list.count == 0 ||
	    (u32)list.count > (u32)((u8 *)list.end - (u8 *)list.start) / sizeof(u32)) {
		pr_err("create group: call id count %u exceeds data length %u\n",
		       list.count, (u32)((u8 *)list.end - (u8 *)list.start));
		return NULL;
	}

	group = kzalloc(sizeof(struct cis_group) + (sizeof(u32) * list.count), GFP_KERNEL);
	if (!group)
		return NULL;

	status = odf_get_u32_from_struct(vs, ODF_NAME_CIS_OWNER, &(group->owner_user_id));
	if (status) {
		pr_err("create group: get [owner id] failed, err = %d\n", status);
		goto fail;
	}

	status = odf_get_u8_from_struct(vs, ODF_NAME_CIS_USAGE, &(group->usage));
	if (status) {
		pr_err("create group: get [usage] failed, err = %d\n", status);
		goto fail;
	}

	status = odf_get_u8_from_struct(vs, ODF_NAME_CIS_INDEX, &(group->index));
	if (status)
		pr_info("cis group not get [index], use default value\n");

	status = odf_get_u32_from_struct(vs, ODF_NAME_CIS_FORWARDER_ID, &(group->forwarder_id));
	if (status)
		pr_info("cis group not get forwarder, use default value\n");

	group->cis_count = list.count;
	for (i = 0; i < list.count; i++) {
		status = odf_get_u32_from_list(&list, i, &(group->call_id[i]));
		if (status) {
			pr_err("create group: get each call id failed, err = %d\n", status);
			goto fail;
		}
	}

	return group;

fail:
	kfree(group);

	return NULL;
}
EXPORT_SYMBOL(create_group_from_vs);

static int create_cis_info_from_odf(void)
{
	struct ubios_od_list_info list;
	struct ubios_od_value_struct vs;
	struct ubios_od_value_struct ub_vs;
	struct ubios_ubrt_table *ubrt_table = NULL;
	struct acpi_table_header *table = NULL;
	u8 *sub_table = NULL;
	struct ubios_od_header *header = NULL;
	acpi_status status;
	int i = 0;
	int err = 0;
	u32 sub_table_size = 0;
	int ub_vs_err = 0;

	status = acpi_get_table(ACPI_SIG_UBRT, 0, &table);
	if (ACPI_SUCCESS(status)) {
		ubrt_table = (struct ubios_ubrt_table *)table;

		for (i = 0; i < ubrt_table->count; i++) {
			if (ubrt_table->sub_tables[i].type == UBRT_CALL_ID_SERVICE) {
				header = memremap(ubrt_table->sub_tables[i].pointer,
					sizeof(struct ubios_od_header), MEMREMAP_WB);
				if (!header) {
					pr_err("failed to map cis table to od header in ACPI\n");
					return -ENOMEM;
				}
				sub_table_size = header->total_size;
				memunmap(header);
				sub_table = (u8 *)memremap(ubrt_table->sub_tables[i].pointer,
					sub_table_size, MEMREMAP_WB);
				break;
			}
		}

		if (!sub_table) {
			pr_err("failed to get cis table address in ACPI\n");
			return -ENOMEM;
		}
		pr_info("get cis sub table success\n");

		err = odf_get_list_from_table(sub_table, ODF_NAME_CIS_GROUP, &list);
		if (err) {
			pr_err("create cis info from odf failed, group not found, err = %d\n",
				err);
			goto free_sub_table;
		}

		ub_vs_err = odf_get_vs_from_table(sub_table, ODF_NAME_CIS_UB, &ub_vs);
	} else {
		err = odf_get_list(od_root,
				ODF_FILE_NAME_CALL_ID_SERVICE "/" ODF_NAME_CIS_GROUP, &list);
		if (err) {
			pr_err("create cis info from odf failed, group not found, err = %d\n",
				err);
			return err;
		}

		ub_vs_err = odf_get_struct(od_root,
				ODF_FILE_NAME_CALL_ID_SERVICE "/" ODF_NAME_CIS_UB, &ub_vs);
	}

	g_cis_info = kzalloc(sizeof(struct cis_info), GFP_KERNEL);
	if (!g_cis_info) {
		err = -ENOMEM;
		goto free_sub_table;
	}
	INIT_LIST_HEAD(&g_cis_info->group_list);
	g_cis_info->group_count = 0;

	err = odf_get_data_from_list(&list, 0, &vs);
	if (err) {
		pr_err("create cis info from odf failed: get data from CIS group failed, err = %d\n",
			err);
		goto fail;
	}
	for (i = 0; i < list.count; i++) {
		struct cis_group_node *node;

		node = kzalloc(sizeof(struct cis_group_node), GFP_KERNEL);
		if (!node) {
			err = -ENOMEM;
			goto fail;
		}
		node->owner = 0; /* ODF source */
		node->group = create_group_from_vs(&vs);
		if (!node->group) {
			pr_err("create cis group from odf failed\n");
			kfree(node);
			err = -ENODATA;
			goto fail;
		}
		INIT_LIST_HEAD(&node->list);
		list_add_tail(&node->list, &g_cis_info->group_list);
		g_cis_info->group_count++;
		(void)odf_next_in_list(&list, &vs);
	}

	if (!ub_vs_err) {
		pr_info("found ub struct in cis info\n");
		err = odf_get_u8_from_struct(&ub_vs, ODF_NAME_CIS_USAGE, &(g_cis_info->ub.usage));
		if (err) {
			pr_err("create group: get [usage] failed, err = %d\n", status);
			goto fail;
		}

		err = odf_get_u8_from_struct(&ub_vs, ODF_NAME_CIS_INDEX, &(g_cis_info->ub.index));
		if (err)
			pr_warn("ub struct not get [index], use default value\n");

		err = odf_get_u32_from_struct(&ub_vs, ODF_NAME_CIS_FORWARDER_ID,
				&(g_cis_info->ub.forwarder_id));
		if (err)
			pr_warn("ub struct not get forwarder, use default value\n");
	} else
		pr_warn("not found ub struct in cis info\n");

	if (sub_table)
		memunmap(sub_table);

	pr_info("get cis table from odf success\n");

	return 0;

fail:
	free_cis_info();
free_sub_table:
	if (sub_table)
		memunmap(sub_table);

	return err;
}

static void free_uvb_info(void)
{
	u16 i;

	if (!g_uvb_info)
		return;

	for (i = 0; i < (g_uvb_info)->uvb_count; i++) {
		if ((g_uvb_info)->uvbs[i]) {
			kfree((g_uvb_info)->uvbs[i]);
			(g_uvb_info)->uvbs[i] = NULL;
		}
	}

	kfree(g_uvb_info);
	g_uvb_info = NULL;
}

static struct uvb *create_uvb_from_vs(const struct ubios_od_value_struct *vs)
{
	struct uvb *temp_uvb;
	struct ubios_od_table_info wd;
	int status;
	u16 row;

	status = odf_get_table_from_struct(vs, ODF_NAME_WD, &wd);
	if (status) {
		pr_err("create uvb info: get [wd] failed, [%d]\n", status);
		return NULL;
	}
	temp_uvb = kzalloc(sizeof(struct uvb) +
		sizeof(struct uvb_window_description) * wd.row, GFP_KERNEL);
	if (!temp_uvb)
		return NULL;

	if (wd.row > UVB_WINDOW_COUNT_MAX) {
		pr_err("create uvb info: uvb window count[%d] error.\n", wd.row);
		goto fail;
	}
	temp_uvb->window_count = (u8)wd.row;
	(void)odf_get_bool_from_struct(vs, ODF_NAME_SECURE, &temp_uvb->secure);
	(void)odf_get_u16_from_struct(vs, ODF_NAME_DELAY, &temp_uvb->delay);
	for (row = 0; row < wd.row; row++) {
		status = odf_get_u64_from_table(&wd,
			row, ODF_NAME_OBTAIN, &(temp_uvb->wd[row].obtain));
		if (status) {
			pr_err("create uvb info: get [obtain] failed, %d.\n", status);
			goto fail;
		}
		status = odf_get_u64_from_table(&wd,
			row, ODF_NAME_ADDRESS, &(temp_uvb->wd[row].address));
		if (status) {
			pr_err("create uvb info: get [address] failed, %d.\n", status);
			goto fail;
		}
		(void)odf_get_u64_from_table(&wd,
			row, ODF_NAME_BUFFER, &(temp_uvb->wd[row].buffer));
		(void)odf_get_u32_from_table(&wd, row, ODF_NAME_SIZE, &(temp_uvb->wd[row].size));
	}

	return temp_uvb;
fail:
	kfree(temp_uvb);

	return NULL;
}

static int create_uvb_info_from_odf(void)
{
	struct ubios_od_list_info uvb_list;
	struct ubios_od_value_struct vs;
	struct ubios_ubrt_table *ubrt_table = NULL;
	struct acpi_table_header *table = NULL;
	u8 *sub_table = NULL;
	struct ubios_od_header *header = NULL;
	acpi_status status;
	int i = 0;
	int err = 0;
	u32 sub_table_size = 0;

	status = acpi_get_table(ACPI_SIG_UBRT, 0, &table);
	if (ACPI_SUCCESS(status)) {
		ubrt_table = (struct ubios_ubrt_table *)table;
		for (i = 0; i < ubrt_table->count; i++) {
			if (ubrt_table->sub_tables[i].type == UBRT_VIRTUAL_BUS) {
				header = memremap(ubrt_table->sub_tables[i].pointer,
					sizeof(struct ubios_od_header), MEMREMAP_WB);
				if (!header) {
					pr_err("failed to map uvb table to od header in ACPI\n");
					return -ENOMEM;
				}
				sub_table_size = header->total_size;
				memunmap(header);
				sub_table = (u8 *)memremap(ubrt_table->sub_tables[i].pointer,
					sub_table_size, MEMREMAP_WB);
				break;
			}
		}

		if (!sub_table) {
			pr_err("failed to get uvb table address in ACPI\n");
			return -ENOMEM;
		}
		pr_info("get uvb sub table suceess\n");

		err = odf_get_list_from_table(sub_table, ODF_NAME_UVB, &uvb_list);
		if (err) {
			pr_err("create uvb info: find uvb from od failed, err = %d\n", err);
			goto free_sub_table;
		}
	} else {
		err = odf_get_list(od_root, ODF_FILE_NAME_VIRTUAL_BUS "/" ODF_NAME_UVB, &uvb_list);
		if (err) {
			pr_err("create uvb info: find uvb from od failed, err = %d\n", err);
			return err;
		}
	}

	g_uvb_info = kzalloc(sizeof(struct uvb_info) + sizeof(void *) * uvb_list.count, GFP_KERNEL);
	if (!g_uvb_info) {
		err = -ENOMEM;
		goto free_sub_table;
	}
	if (uvb_list.count > UVB_WINDOW_COUNT_MAX) {
		pr_err("create uvb info: uvb count[%d] error.\n", uvb_list.count);
		err = -EOVERFLOW;
		goto fail;
	}
	g_uvb_info->uvb_count = (u8)uvb_list.count;
	err = odf_get_data_from_list(&uvb_list, 0, &vs);
	if (err) {
		pr_err("create uvb info: get uvb failed [%d]\n", err);
		goto fail;
	}
	for (i = 0; i < uvb_list.count; i++) {
		g_uvb_info->uvbs[i] = create_uvb_from_vs(&vs);
		if (!g_uvb_info->uvbs[i]) {
			pr_err("create uvb from odf failed\n");
			err = -EINVAL;
			goto fail;
		}
		(void)odf_next_in_list(&uvb_list, &vs);
	}
	if (sub_table)
		memunmap(sub_table);

	pr_info("get uvb table from odf success\n");

	return 0;

fail:
	free_uvb_info();
free_sub_table:
	if (sub_table)
		memunmap(sub_table);

	return err;
}

static void free_odf_info(void)
{
	int i;

	if (od_root) {
		for (i = 0; i < od_root->count; i++) {
			if (od_root->odfs[i])
				memunmap((void *)(u64)od_root->odfs[i]);
		}
	}
	kfree(od_root);
	od_root = NULL;
}

static int create_odf_info(void)
{
	u64 od_root_phys = 0;  /* physical address */
	struct ubios_od_root *od_root_origin = NULL;  /* virtual address */
	struct acpi_table_header *ubrt_header = NULL;
	struct ubios_od_header *dump_hdr = NULL;
	struct ubios_od_header *od_hdr = NULL;
	u64 dump_phys = 0;
	u64 od_file_phys = 0;
	u32 od_root_size = 0;
	u32 od_file_size = 0;
	void *od_file_va = NULL;
	int i = 0;
	acpi_status status;
	int ret = 0;
	u16 count = 0;

	status = acpi_get_table(ACPI_SIG_UBRT, 0, &ubrt_header);
	if (ACPI_SUCCESS(status)) {
		pr_info("Success fully get UBRT table\n");
		return 0;
	}
	ret = odf_get_fdt_ubiostbl(&od_root_phys, "linux,ubios-information-table");
	if (ret) {
		pr_err("from fdt get ubiostbl failed\n");
		return -1;
	}

	od_root_origin = (struct ubios_od_root *)
		memremap(od_root_phys, sizeof(struct ubios_od_header), MEMREMAP_WB);
	if (!od_root_origin) {
		pr_err("od_root header memremap failed, od_root addr=%016llx\n", od_root_phys);
		return -1;
	}
	od_root_size = od_root_origin->header.total_size;
	memunmap((void *)od_root_origin);

	od_root_origin = (struct ubios_od_root *)memremap(od_root_phys, od_root_size, MEMREMAP_WB);
	if (!od_root_origin) {
		pr_err("od_root memremap failed, od_root addr=%016llx\n", od_root_phys);
		return -1;
	}

	count = od_root_origin->count;
	od_root = kzalloc(sizeof(struct ubios_od_root) + count * sizeof(u64), GFP_KERNEL);
	if (!od_root) {
		pr_err("kmalloc od_root failed\n");
		goto free_od_root;
	}
	memcpy(&od_root->header, &od_root_origin->header, sizeof(struct ubios_od_header));
	od_root->count = od_root_origin->count;

	/* Dump UB root table contents for debugging */
	pr_info("odf: root table dump: name=%s, total_size=%u, version=%u, count=%u\n",
		od_root_origin->header.name, od_root_origin->header.total_size,
		od_root_origin->header.version, od_root_origin->count);
	for (i = 0; i < od_root_origin->count; i++) {
		dump_phys = od_root_origin->odfs[i];

		if (!dump_phys) {
			pr_info("odf: sub_table[%d]: NULL\n", i);
			continue;
		}

		dump_hdr = (struct ubios_od_header *)memremap(dump_phys,
				sizeof(struct ubios_od_header), MEMREMAP_WB);
		if (!dump_hdr) {
			pr_info("odf: sub_table[%d]: phys=%016llx, memremap FAILED\n",
				i, dump_phys);
			continue;
		}

		pr_info("odf: sub_table[%d]: phys=%016llx, name=%s, total_size=%u, version=%u\n",
			i, dump_phys, dump_hdr->name, dump_hdr->total_size, dump_hdr->version);

		memunmap(dump_hdr);
	}

	for (i = 0; i < od_root->count; i++) {
		if (!od_root_origin->odfs[i])
			continue;

		od_file_phys = od_root_origin->odfs[i];

		/* Map header first to get total_size, then map full OD file.
		 * Same pattern as ubfi's ub_table_get(). */
		od_hdr = (struct ubios_od_header *)memremap(od_file_phys,
				sizeof(struct ubios_od_header), MEMREMAP_WB);
		if (!od_hdr) {
			pr_err("odf: failed to map od file header at %016llx\n", od_file_phys);
			continue;
		}
		od_file_size = od_hdr->total_size;
		memunmap(od_hdr);

		if (od_file_size == 0 || od_file_size > SZ_1M) {
			pr_err("odf: invalid od file size %u at %016llx\n",
				od_file_size, od_file_phys);
			continue;
		}

		od_file_va = memremap(od_file_phys, od_file_size, MEMREMAP_WB);
		if (!od_file_va) {
			pr_err("odf: failed to map od file at %016llx, size=%u\n",
				od_file_phys, od_file_size);
			continue;
		}

		od_root->odfs[i] = (u64)od_file_va;
	}
	if (od_root_origin)
		memunmap(od_root_origin);

	odf_update_checksum(&od_root->header);
	pr_info("get ubios table success\n");

	return 0;

free_od_root:
	if (od_root_origin)
		memunmap(od_root_origin);

	return -1;
}

static int __init odf_init(void)
{
	int status;

	status = create_odf_info();
	if (status) {
		pr_err("odf table init failed\n");
		return 0;
	}

	status = create_cis_info_from_odf();
	if (status) {
		pr_err("create cis info failed, cis is invalid\n");
		goto free_odf;
	}

	status = create_uvb_info_from_odf();
	if (status) {
		pr_warn("create uvb info failed, uvb channel unavailable, cis still works\n");
	} else {
		pr_info("odf init success\n");
	}

	return 0;

free_odf:
	free_odf_info();

	return 0;
}

static void __exit odf_exit(void)
{
	free_uvb_info();
	free_cis_info();
	free_odf_info();

	pr_info("odf exit success\n");
}

module_init(odf_init);
module_exit(odf_exit);
