// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: UMMU Configuration Table Management.
 */
#define pr_fmt(fmt) "UMMU: " fmt

#include <linux/xarray.h>
#include <linux/ummu_core.h>
#include <linux/cleanup.h>
#include <linux/uuid.h>
#include <ub/ubus/ubus.h>

#include "ummu.h"
#include "queue.h"
#include "flush.h"
#include "regs.h"
#include "cfg_table.h"

static DEFINE_MUTEX(ummu_dev_tct_lock);

struct os_meta {
	u32 tecte_tag;
	guid_t guid;
	struct ummu_tct_desc_cfg tct_tbl;
	struct list_head eids;
	struct kref ref;
	bool valid;
};

struct eid_info {
	eid_t eid;
	int eid_type;
	u32 kv_index;
	struct list_head node;
	int ref_cnt;
};

static struct {
	struct xarray per_os_meta;
	struct ummu_tect_cfg ummu_tect;
	bool tect_valid;
	struct ummu_capability cap;
	bool cap_valid;
} ummu_global_info;

/* protect ummu_global_info */
static DEFINE_SPINLOCK(ummu_global);

static struct ummu_tecte_data ummu_clear_tecte = {0};

static int ummu_init_tect(const struct ummu_capability *cap,
			  struct ummu_tect_cfg *tect);

static int ummu_alloc_tct(const struct ummu_capability *cap,
			  struct ummu_tct_desc_cfg *tct_cfg);
static void ummu_free_tct(struct ummu_tct_desc_cfg *tct_cfg);

char *ummu_get_eid_list(void)
{
	char *new_buffer, *buffer = NULL;
	struct eid_info *info;
	struct os_meta *meta;
	unsigned long idx;
	bool first = true;
	int str_len = 0;
	/* 100 bytes cached as string */
	char temp[100];
	int temp_len;

	guard(spinlock)(&ummu_global);
	xa_for_each(&ummu_global_info.per_os_meta, idx, meta) {
		list_for_each_entry(info, &meta->eids, node) {
			temp_len = snprintf(temp, sizeof(temp),
					    "\teid_high[0x%llx] eid_low[0x%llx]\n",
					    (u64)(info->eid >> EID_HIGH_SZ_SHIFT),
					    (u64)(info->eid));
			str_len += temp_len;
			new_buffer = krealloc(buffer, str_len + 1, GFP_ATOMIC);
			if (!new_buffer) {
				kfree(buffer);
				return NULL;
			}
			buffer = new_buffer;

			if (first) {
				memset(buffer, 0, str_len + 1);
				first = false;
			}

			strncat(buffer, temp, temp_len);
		}
	}
	return buffer;
}

static u32 ummu_kvtable_convert_hash_val(u32 val, int width)
{
	u32 hash_val = val;

	if (width == KV_TABLE_HASH_WIDTH_16BIT)
		hash_val = (u16)val;
	else if (width == KV_TABLE_HASH_WIDTH_8BIT)
		hash_val = (u8)val;
	else if (width == KV_TABLE_HASH_WIDTH_4BIT)
		hash_val = val & 0xf;

	return hash_val;
}

static u32 ummu_kvtable_crc32_calc(const u8 *data, u16 length,
					int width)
{
	u32 crc = CRC32_INIT_VALUE;
	u32 i, j;

	for (i = 0; i < length; i++) {
		crc ^= (u32)(data[length - i - 1]) << CRC32_CALC_OFFSET;
		for (j = 0; j < CRC32_CALC_LENGTH; j++) {
			if (crc & CRC32_CALC_MASK)
				crc = (crc << 1) ^ CRC32_POLY_VALUE;
			else
				crc <<= 1;
		}
	}

	return ummu_kvtable_convert_hash_val(crc, width);
}

static u32 ummu_kvtable_xor_calc(const u8 *data, u16 length,
				      int width)
{
	u16 checksum = 0;
	u16 *val;
	u32 i;

	if (width == KV_TABLE_HASH_WIDTH_16BIT) {
		val = (u16 *)data;
		for (i = 0; i < length / KV_TABLE_XOR_BYTE_TO_SHORT; i++)
			checksum ^= val[i];
	} else if (width == KV_TABLE_HASH_WIDTH_8BIT) {
		for (i = 0; i < length; i++)
			checksum ^= data[i];
	} else if (width == KV_TABLE_HASH_WIDTH_4BIT) {
		for (i = 0; i < length; i++) {
			checksum ^=
				((data[i] >> KV_TABLE_XOR_HALF_BYTE_BIT) & 0xf);
			checksum ^= (data[i] & 0xf);
		}
	}

	return checksum;
}

static u32 ummu_device_calc_hash_value_for_eid(struct ummu_device *ummu,
						    eid_t eid)
{
	if (ummu->hash_tbl_cfg.hash_sel == KV_TABLE_HASH_CRC32)
		return ummu_kvtable_crc32_calc((u8 *)&eid, sizeof(eid),
					       ummu->hash_tbl_cfg.hash_width);
	else
		return ummu_kvtable_xor_calc((u8 *)&eid, sizeof(eid),
					     ummu->hash_tbl_cfg.hash_width);
}

static int ummu_device_calc_kv_index(struct ummu_device *ummu, eid_t eid,
				     u32 *kv_index)
{
	void *cam_base = ummu->hash_tbl_cfg.cam_tbl_vaddr;
	u16 cam_depth = ummu->hash_tbl_cfg.cam_tbl_depth;
	void *kv_base = ummu->hash_tbl_cfg.kv_tbl_vaddr;
	u16 bank_depth = ummu->hash_tbl_cfg.bank_depth;
	u8 bank_num = ummu->hash_tbl_cfg.bank_num;
	__le32 *hash_ent;
	u32 hash_value;
	u16 id;

	hash_value = ummu_device_calc_hash_value_for_eid(ummu, eid);

	pr_debug("eid_high 0x%llx, eid_low 0x%llx, hash %u\n",
		(u64)(eid >> EID_HIGH_SZ_SHIFT), (u64)eid, hash_value);

	for (id = 0; id < bank_num; id++) {
		hash_ent = (__le32 *)(kv_base + (hash_value * bank_num + id) *
							HASH_ENTRY_SIZE_BYTES);
		if (!(le32_to_cpu(hash_ent[0]) & HASH_ENTRY_V)) {
			*kv_index = hash_value * bank_num + id;
			return 0;
		}
	}

	for (id = 0; id < cam_depth; id++) {
		hash_ent = (__le32 *)(cam_base + id * HASH_ENTRY_SIZE_BYTES);
		if (!(le32_to_cpu(hash_ent[0]) & HASH_ENTRY_V)) {
			*kv_index = id + bank_num * bank_depth;
			return 0;
		}
	}

	dev_err(ummu->dev, "kv index calc failed, eid_high=0x%llx, eid_low=0x%llx, hash=%u.\n",
		(u64)(eid >> EID_HIGH_SZ_SHIFT), (u64)eid, hash_value);

	return -ERANGE;
}

static void ummu_device_create_kvtable(struct ummu_device *ummu, u32 tag,
				      eid_t eid, u32 kv_index)
{
	struct ummu_mcmdq_ent cmd_create_kvtbl;
	int ret;

	pr_debug("add tag %u, eid_high 0x%llx, eid_low 0x%llx, index %u\n",
		 tag, (u64)(eid >> EID_HIGH_SZ_SHIFT), (u64)eid, kv_index);

	cmd_create_kvtbl.opcode = CMD_CREATE_KVTBL;
	cmd_create_kvtbl.create_kvtbl.evt_en = false;
	cmd_create_kvtbl.create_kvtbl.tecte_tag = tag;
	cmd_create_kvtbl.create_kvtbl.kv_index = kv_index;
	cmd_create_kvtbl.create_kvtbl.tect_base_addr =
		ummu->tect_cfg->tect_reg_addr;
	cmd_create_kvtbl.create_kvtbl.eid_low = (u64)eid;
	cmd_create_kvtbl.create_kvtbl.eid_high =
		(u64)(eid >> EID_HIGH_SZ_SHIFT);

	ret = ummu_mcmdq_issue_cmd_with_sync(ummu, &cmd_create_kvtbl);
	if (ret)
		dev_warn(ummu->dev, "issue create kvtbl cmd timeout, ret = %d\n", ret);
}

static void ummu_device_delete_kvtbl(struct ummu_device *ummu, u32 tag,
				     eid_t eid, u32 kv_index)
{
	struct ummu_mcmdq_ent cmd_delete_kvtbl = {
		.opcode = CMD_DELETE_KVTBL,
		.delete_kvtbl = {
			.evt_en = false,
			.tecte_tag = tag,
			.kv_index = kv_index,
			.eid_low = (u64)eid,
			.eid_high = (u64)(eid >> EID_HIGH_SZ_SHIFT),
		},
	};
	int ret;

	pr_debug("del tag %u, eid_high 0x%llx, eid_low 0x%llx, index %u\n",
		 tag, (u64)(eid >> EID_HIGH_SZ_SHIFT), (u64)eid, kv_index);

	ret = ummu_mcmdq_issue_cmd_with_sync(ummu, &cmd_delete_kvtbl);
	if (ret)
		dev_err(ummu->dev, "failed to issue delete kvtbl cmd(%d)\n",
			ret);
}

static void ummu_free_tct_table(struct kref *kref)
{
	struct ummu_tct_desc_cfg *cfg =
		container_of(kref, struct ummu_tct_desc_cfg, ref);

	if (cfg->tct_ptr)
		ummu_free_tct(cfg);
}

void ummu_put_tct_table(struct ummu_tct_desc_cfg *cfg)
{
	kref_put(&cfg->ref, ummu_free_tct_table);
}

static void free_os_meta(struct kref *ref)
{
	struct os_meta *meta = container_of(ref, struct os_meta, ref);

	ummu_put_tct_table(&meta->tct_tbl);
	xa_erase(&ummu_global_info.per_os_meta, meta->tecte_tag);
	kfree(meta);
}

static int os_meta_get_kv_index(struct os_meta *meta, eid_t eid, u32 *kv_index)
{
	struct eid_info *info;
	int ret = -ENOENT;

	guard(spinlock)(&ummu_global);
	list_for_each_entry(info, &meta->eids, node)
		if (info->eid == eid) {
			*kv_index = info->kv_index;
			ret = 0;
			break;
		}

	return ret;
}

static void os_meta_del_eid(struct os_meta *meta, eid_t eid)
{
	struct eid_info *info, *tmp;

	guard(spinlock)(&ummu_global);
	list_for_each_entry_safe(info, tmp, &meta->eids, node)
		if (info->eid == eid) {
			info->ref_cnt--;
			if (info->ref_cnt <= 0) {
				list_del(&info->node);
				kfree(info);
				kref_put(&meta->ref, free_os_meta);
			}
			break;
		}
}

static int os_meta_add_eid(struct os_meta *meta, eid_t eid, u32 kv_index, int type)
{
	struct eid_info *info;

	guard(spinlock)(&ummu_global);
	list_for_each_entry(info, &meta->eids, node)
		if (info->eid == eid) {
			info->ref_cnt++;
			return 0;
		}

	info = kzalloc(sizeof(*info), GFP_ATOMIC);
	if (!info)
		return -ENOMEM;

	info->ref_cnt = 1;
	info->eid = eid;
	info->kv_index = kv_index;
	info->eid_type = type;
	list_add_tail(&info->node, &meta->eids);
	kref_get(&meta->ref);
	return 0;
}

const struct ummu_capability *ummu_get_cap(void)
{
	guard(spinlock)(&ummu_global);
	if (!ummu_global_info.cap_valid)
		return NULL;

	return &ummu_global_info.cap;
}

static struct ummu_tct_desc_cfg *ummu_get_local_tct_table(void)
{
	struct ummu_tct_desc_cfg *cfg = NULL;
	struct os_meta *meta;
	int ret;

	guard(spinlock)(&ummu_global);
	if (!ummu_global_info.tect_valid)
		return NULL;

	meta = xa_load(&ummu_global_info.per_os_meta, 0);
	if (!meta)
		return NULL;

	cfg = &meta->tct_tbl;
	if (!cfg->tct_ptr) {
		if (!ummu_global_info.cap_valid)
			return NULL;

		ret = ummu_alloc_tct(&ummu_global_info.cap, cfg);
		if (ret)
			return NULL;
	}
	kref_get(&meta->tct_tbl.ref);

	return cfg;
}

static struct ummu_tect_cfg *ummu_get_tect_table(void)
{
	struct ummu_tect_cfg *tect;
	int ret;

	guard(spinlock)(&ummu_global);
	tect = &ummu_global_info.ummu_tect;
	if (!tect->tbl_vaddr) {
		if (!ummu_global_info.cap_valid)
			return NULL;
		ret = ummu_init_tect(&ummu_global_info.cap, tect);
		if (ret)
			return NULL;
	}

	kref_get(&tect->ref);

	return tect;
}

static void ummu_free_tect(struct ummu_tect_cfg *tect)
{
	u32 l1_size, l2_size;
	unsigned int i;

	if (tect->l1_tect_desc) {
		l2_size = (1UL << TECT_SPLIT) * TECT_ENTRY_SIZE_BYTES;
		for (i = 0; i < tect->num_ents; i++) {
			if (!tect->l1_tect_desc[i].l2ptr)
				continue;

			free_pages((unsigned long)tect->l1_tect_desc[i].l2ptr,
					   get_order(l2_size));
			tect->l1_tect_desc[i].l2ptr = NULL;
		}
		kfree(tect->l1_tect_desc);
		tect->l1_tect_desc = NULL;
		l1_size = tect->num_ents * TECT_L1_ENTRY_BYTES;
	} else {
		l1_size = tect->num_ents * TECT_ENTRY_SIZE_BYTES;
	}

	free_pages((unsigned long)tect->tbl_vaddr, get_order(l1_size));
	tect->tbl_vaddr = NULL;
	tect->phys = 0;
}

static void ummu_free_tect_table(struct kref *kref)
{
	struct ummu_tect_cfg *tect = container_of(kref, struct ummu_tect_cfg, ref);

	if (tect->tbl_vaddr)
		ummu_free_tect(tect);
}

void ummu_put_tect_table(struct ummu_tect_cfg *tect)
{
	kref_put(&tect->ref, ummu_free_tect_table);
}

static inline void ummu_build_tecte_bypass(struct ummu_tecte_data *tecte)
{
	memset(tecte, 0, sizeof(*tecte));
	tecte->data[0] = cpu_to_le64(
		FIELD_PREP(TECT_ENT0_ST_MODE, TECT_ENT0_ST_MODE_BYPASS) |
		FIELD_PREP(TECT_ENT0_MSD_SEL, TECT_ENT0_MSD_SEL_INCOMING));
}

static inline void ummu_build_tecte_abort(struct ummu_tecte_data *tecte)
{
	memset(tecte, 0, sizeof(*tecte));
	tecte->data[0] = cpu_to_le64(
		FIELD_PREP(TECT_ENT0_ST_MODE, TECT_ENT0_ST_MODE_ABORT));
}

static void ummu_tecte_pre_init(struct ummu_tecte_data *tect, u32 num_ents)
{
	u64 val;
	u32 i;

	for (i = 0; i < num_ents; ++i) {
		val = le64_to_cpu(tect->data[0]);
		if (val & TECT_ENT0_V)
			continue;

		ummu_build_tecte_abort(tect);

		tect->data[0] |= cpu_to_le64(TECT_ENT0_MAPT_EN);
		tect->data[1] |= cpu_to_le64(TECT_ENT1_TCT_MTM_EN);
		tect->data[6] |= cpu_to_le64(TECT_ENT6_MTM_NS);
		tect++;
	}
}

/* The TECT memory layout implementation is based on the ARM SMMU STE reference.*/
static int ummu_init_tect_linear(struct ummu_tect_cfg *tect)
{
	u32 size = PAGE_ALIGN(tect->num_ents * TECT_ENTRY_SIZE_BYTES);
	u32 reg;

	tect->tbl_vaddr = (__le64 *)__get_free_pages(GFP_ATOMIC | __GFP_ZERO,
						     get_order(size));
	if (!tect->tbl_vaddr)
		return -ENOMEM;

	tect->phys = virt_to_phys(tect->tbl_vaddr);
	tect->tbl_size = size;

	/* Configure tect_reg_cfg for linear table */
	reg = FIELD_PREP(TECT_BASE_CFG_FMT, tect->tect_fmt);
	reg |= FIELD_PREP(TECT_BASE_CFG_LOG2SIZE, ilog2(tect->num_ents));
	tect->tect_reg_cfg = reg;

	ummu_tecte_pre_init((struct ummu_tecte_data *)(tect->tbl_vaddr),
			    tect->num_ents);
	return 0;
}

static void ummu_write_tect_l1_desc(__le64 *tecte, struct ummu_tect_l1_desc *desc)
{
	u64 val = TECTD_V;

	val |= FIELD_PREP(TECT_L1_DESC_L2TECTE_NUM, ilog2(desc->l2_tecte_num));
	val |= desc->l2ptr_pa & TECT_L1_DESC_L2PTR_MASK;

	WRITE_ONCE(*tecte, cpu_to_le64(val));
}

static int ummu_init_tect_second_lvl(struct ummu_tect_cfg *tect, u32 tect_tag)
{
	struct ummu_tect_l1_desc *desc = &tect->l1_tect_desc[tect_tag >> TECT_SPLIT];
	__le64 *tecte;
	u32 size;

	if (desc && desc->l2ptr)
		return 0;

	size = (1UL << TECT_SPLIT) * TECT_ENTRY_SIZE_BYTES;
	size = PAGE_ALIGN(size);

	desc->l2_tecte_num = 1UL << TECT_SPLIT;
	desc->l2ptr = (__le64 *)__get_free_pages(GFP_ATOMIC | __GFP_ZERO,
						 get_order(size));
	if (!desc->l2ptr)
		return -ENOMEM;

	desc->l2ptr_pa = virt_to_phys(desc->l2ptr);

	ummu_tecte_pre_init((struct ummu_tecte_data *)(desc->l2ptr),
			    desc->l2_tecte_num);
	tecte = tect->tbl_vaddr + (tect_tag >> TECT_SPLIT) * TECT_L1_ENTRY_DWORDS;
	ummu_write_tect_l1_desc(tecte, desc);
	return 0;
}

static int ummu_init_tect_first_lvl(struct ummu_tect_cfg *tect)
{
	u32 l1_size = PAGE_ALIGN(tect->num_ents * TECT_L1_ENTRY_BYTES);
	u32 reg;

	tect->tbl_vaddr = (__le64 *)__get_free_pages(GFP_ATOMIC | __GFP_ZERO,
						     get_order(l1_size));
	if (!tect->tbl_vaddr)
		return -ENOMEM;

	tect->phys = virt_to_phys(tect->tbl_vaddr);
	tect->tbl_size = l1_size;

	/* Configure tect_reg_cfg for 2 levels tect */
	reg = FIELD_PREP(TECT_BASE_CFG_FMT, tect->tect_fmt);
	reg |= FIELD_PREP(TECT_BASE_CFG_SPLIT, TECT_SPLIT);
	reg |= FIELD_PREP(TECT_BASE_CFG_LOG2SIZE,
			  ilog2(tect->num_ents) + TECT_SPLIT);
	tect->tect_reg_cfg = reg;

	tect->l1_tect_desc = kcalloc(tect->num_ents,
		sizeof(struct ummu_tect_l1_desc), GFP_ATOMIC);
	if (!tect->l1_tect_desc) {
		free_pages((unsigned long)tect->tbl_vaddr, get_order(l1_size));
		tect->tbl_vaddr = NULL;
		return -ENOMEM;
	}

	return 0;
}

static int ummu_init_tect(const struct ummu_capability *cap,
			  struct ummu_tect_cfg *tect)
{
	u64 reg_val;
	u32 ent_bit;
	int ret;

	if (cap->features & UMMU_FEAT_2_LVL_TECT) {
		ent_bit = cap->deid_bits - TECT_SPLIT;
		tect->num_ents = 1UL << ent_bit;
		tect->tect_fmt = TECT_BASE_CFG_FMT_2LVL;
		ret = ummu_init_tect_first_lvl(tect);
	} else {
		tect->num_ents = 1UL << cap->deid_bits;
		tect->tect_fmt = TECT_BASE_CFG_FMT_LINEAR;
		ret = ummu_init_tect_linear(tect);
	}

	if (ret)
		return ret;

	/* configure tect base address */
	reg_val = tect->phys & TECT_BASE_ADDR_MASK;
	reg_val |= TECT_BASE_RA;
	tect->tect_reg_addr = reg_val;

	return 0;
}

void ummu_free_global_meta(void)
{
	struct os_meta *meta;
	unsigned long idx;

	guard(spinlock)(&ummu_global);
	xa_for_each(&ummu_global_info.per_os_meta, idx, meta)
		kref_put(&meta->ref, free_os_meta);

	xa_destroy(&ummu_global_info.per_os_meta);

	ummu_put_tect_table(&ummu_global_info.ummu_tect);
	ummu_global_info.tect_valid = false;
	ummu_global_info.cap_valid = false;
}

int ummu_init_global_meta(void)
{
	struct os_meta *meta;
	int ret;

	spin_lock_init(&ummu_global);
	if (ummu_global_info.tect_valid)
		return -EEXIST;

	meta = kzalloc(sizeof(*meta), GFP_KERNEL);
	if (!meta)
		return -ENOMEM;

	meta->tecte_tag = 0;
	memset(&meta->guid, 0, sizeof(meta->guid));
	INIT_LIST_HEAD(&meta->eids);
	/* 0 for local host tecte */
	xa_init_flags(&ummu_global_info.per_os_meta, XA_FLAGS_ALLOC1);
	ret = xa_err(xa_store(&ummu_global_info.per_os_meta,
			      0, meta, GFP_KERNEL));
	if (ret)
		goto free_meta;

	kref_init(&meta->tct_tbl.ref);
	kref_init(&ummu_global_info.ummu_tect.ref);
	kref_init(&meta->ref);
	ummu_global_info.tect_valid = true;
	return 0;

free_meta:
	xa_destroy(&ummu_global_info.per_os_meta);
	kfree(meta);
	return ret;
}

int ummu_prepare_tect_tct(struct ummu_device *ummu)
{
	struct ummu_tct_desc_cfg *local;
	struct ummu_tect_cfg *tect;
	int ret;

	tect = ummu_get_tect_table();
	if (!tect)
		return -EINVAL;

	local = ummu_get_local_tct_table();
	if (!local) {
		ret = -EINVAL;
		goto put_tect;
	}

	/* prepare tect */
	ummu->tect_cfg = tect;

	/* prepare tct */
	ummu->local_tct_cfg = local;
	return 0;

put_tect:
	ummu_put_tect_table(tect);
	return ret;
}

int ummu_check_cap(struct ummu_device *ummu)
{
	int ret;

	guard(spinlock)(&ummu_global);
	if (ummu_global_info.cap_valid) {
		ret = memcmp(&ummu->cap, &ummu_global_info.cap, sizeof(ummu->cap));
		WARN(ret, "expect all ummu instances has same capability!\n");
		return ret;
	}
	ummu_global_info.cap = ummu->cap;
	ummu_global_info.cap_valid = true;
	return 0;
}

static int ummu_alloc_tct_linear(struct ummu_tct_desc_cfg *tct_cfg)
{
	u32 tbl_size;

	tbl_size = tct_cfg->l1_tcte_num * TCT_ENTRY_SIZE_BYTES;
	tbl_size = PAGE_ALIGN(tbl_size);

	tct_cfg->tct_ptr = (__le64 *)__get_free_pages(GFP_ATOMIC | __GFP_ZERO,
						      get_order(tbl_size));
	if (!tct_cfg->tct_ptr)
		return -ENOMEM;
	tct_cfg->tct_phys_addr = virt_to_phys(tct_cfg->tct_ptr);

	return 0;
}

static int ummu_alloc_tct_first_lvl(struct ummu_tct_desc_cfg *tct_cfg)
{
	unsigned long l1_tcte_num = tct_cfg->l1_tcte_num;
	unsigned long l1_tbl_size;
	int ret;

	tct_cfg->l1_tct_desc = kcalloc(l1_tcte_num,
		sizeof(*tct_cfg->l1_tct_desc), GFP_ATOMIC);
	if (!tct_cfg->l1_tct_desc)
		return -ENOMEM;

	l1_tbl_size = l1_tcte_num * TCT_L1_ENTRY_SIZE_BYTES;
	l1_tbl_size = PAGE_ALIGN(l1_tbl_size);

	tct_cfg->tct_ptr = (__le64 *)__get_free_pages(GFP_ATOMIC | __GFP_ZERO,
						      get_order(l1_tbl_size));
	if (!tct_cfg->tct_ptr) {
		ret = -ENOMEM;
		goto err_free_l1_desc;
	}

	tct_cfg->tct_phys_addr = virt_to_phys(tct_cfg->tct_ptr);

	return 0;

err_free_l1_desc:
	kfree(tct_cfg->l1_tct_desc);
	tct_cfg->l1_tct_desc = NULL;
	return ret;
}

static int ummu_alloc_tct_second_lvl(struct ummu_l1_tct_desc *l1_desc)
{
	size_t l2size = TCT_L2_ENTRIES * TCT_ENTRY_SIZE_BYTES;

	l2size = PAGE_ALIGN(l2size);
	l1_desc->l2ptr = (__le64 *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
						    get_order(l2size));
	if (!l1_desc->l2ptr)
		return -ENOMEM;

	l1_desc->l2ptr_phys = virt_to_phys(l1_desc->l2ptr);

	return 0;
}

static int ummu_alloc_tct(const struct ummu_capability *cap,
			  struct ummu_tct_desc_cfg *tct_cfg)
{
	if (cap->features & UMMU_FEAT_2_LVL_TCT) {
		tct_cfg->tcte_max_bits = cap->tid_bits;
		tct_cfg->tct_fmt = TCT_FMT_LVL2_64K;
		tct_cfg->l1_tcte_num =
			DIV_ROUND_UP(1 << tct_cfg->tcte_max_bits, TCT_L2_ENTRIES);
		return ummu_alloc_tct_first_lvl(tct_cfg);
	}
	tct_cfg->tcte_max_bits = min(cap->tid_bits, TCT_LINEAR_ENTS_MAX);
	tct_cfg->tct_fmt = TCT_FMT_LINEAR;
	tct_cfg->l1_tcte_num = 1 << tct_cfg->tcte_max_bits;
	return ummu_alloc_tct_linear(tct_cfg);
}

static void ummu_free_tct(struct ummu_tct_desc_cfg *tct_cfg)
{
	size_t l1_size, l2_size;
	unsigned int i;

	if (tct_cfg->l1_tct_desc) {
		l2_size = TCT_L2_ENTRIES * TCT_ENTRY_SIZE_BYTES;
		for (i = 0; i < tct_cfg->l1_tcte_num; i++) {
			if (!tct_cfg->l1_tct_desc[i].l2ptr)
				continue;

			free_pages((unsigned long)tct_cfg->l1_tct_desc[i].l2ptr,
					   get_order(l2_size));
			tct_cfg->l1_tct_desc[i].l2ptr = NULL;
		}

		kfree(tct_cfg->l1_tct_desc);
		tct_cfg->l1_tct_desc = NULL;
		l1_size = tct_cfg->l1_tcte_num * TCT_L1_ENTRY_SIZE_BYTES;
	} else {
		l1_size = tct_cfg->l1_tcte_num * TCT_ENTRY_SIZE_BYTES;
	}

	free_pages((unsigned long)tct_cfg->tct_ptr, get_order(l1_size));
	tct_cfg->tct_ptr = NULL;
	tct_cfg->tct_phys_addr = 0;
}

/* The TCT memory layout implementation is based on the ARM SMMU CD reference.*/
static void ummu_write_tct_l1_desc(__le64 *tcte_ptr,
				   struct ummu_l1_tct_desc *l1_desc)
{
	u64 val = TCT_L1_ENTRY_V;

	val |= l1_desc->l2ptr_phys & TCT_L1_ADDR_MASK;

	WRITE_ONCE(*tcte_ptr, cpu_to_le64(val));
}

__le64 *ummu_get_tcte_ptr(struct ummu_tct_desc_cfg *tct_cfg, u32 tid)
{
	struct ummu_l1_tct_desc *l1_desc;
	int l1_idx, l2_idx;

	if (tid >= (1UL << tct_cfg->tcte_max_bits)) {
		pr_err("tid is not within the valid range.\n");
		return NULL;
	}

	/* linear tct */
	if (tct_cfg->tct_fmt == TCT_FMT_LINEAR)
		return tct_cfg->tct_ptr + tid * TCT_ENTRY_SIZE_DWORDS;

	l1_idx = tid >> TCT_SPLIT_64K;
	l1_desc = &tct_cfg->l1_tct_desc[l1_idx];
	if (!l1_desc->l2ptr) {
		pr_err("l2 tcte not initialized.\n");
		return NULL;
	}

	l2_idx = tid & (TCT_L2_ENTRIES - 1);

	return l1_desc->l2ptr + l2_idx * TCT_ENTRY_SIZE_DWORDS;
}

static __le64 *ummu_alloc_tcte(struct ummu_tct_desc_cfg *tct_cfg, u32 tid)
{
	struct ummu_l1_tct_desc *l1_desc;
	__le64 *tcte_ptr;
	int l1_idx, l2_idx;

	/* linear tct */
	if (tct_cfg->tct_fmt == TCT_FMT_LINEAR)
		return tct_cfg->tct_ptr + tid * TCT_ENTRY_SIZE_DWORDS;

	l1_idx = tid >> TCT_SPLIT_64K;
	l1_desc = &tct_cfg->l1_tct_desc[l1_idx];
	if (!l1_desc->l2ptr) {
		if (ummu_alloc_tct_second_lvl(l1_desc)) {
			pr_err("alloc second lvl tct table failed.\n");
			return NULL;
		}

		tcte_ptr = tct_cfg->tct_ptr + l1_idx * TCT_L1_ENTRY_SIZE_DWORDS;
		ummu_write_tct_l1_desc(tcte_ptr, l1_desc);
	}

	l2_idx = tid & (TCT_L2_ENTRIES - 1);

	return l1_desc->l2ptr + l2_idx * TCT_ENTRY_SIZE_DWORDS;
}

int ummu_write_tct_desc(struct ummu_device *ummu, struct ummu_domain_cfgs *cfgs,
			bool is_clear)
{
	struct ummu_domain *u_domain = container_of(cfgs, struct ummu_domain, cfgs);
	struct ummu_tct_desc_cfg *tct_cfg = cfgs->s1_cfg.tct_cfg;
	struct ummu_tct_desc *tct_desc = &cfgs->s1_cfg.tct;
	u32 type = u_domain->base_domain.domain.type;
	u32 tid = u_domain->base_domain.tid;
	u32 tag = cfgs->tecte_tag;
	bool is_valid;
	__le64 *tcte;
	u64 val;
	u8 i;

	if (tid >= (1UL << tct_cfg->tcte_max_bits))
		return -ERANGE;

	mutex_lock(&ummu_dev_tct_lock);
	tcte = ummu_alloc_tcte(tct_cfg, tid);
	mutex_unlock(&ummu_dev_tct_lock);
	if (!tcte) {
		dev_err(ummu->dev, "can not find tct entry to write!");
		return -ENOMEM;
	}

	is_valid = !!(le64_to_cpu(tcte[0]) & TCT_ENT0_V);

	if (is_clear) {
		for (i = 0; i < TCT_ENTRY_SIZE_DWORDS; i++)
			WRITE_ONCE(tcte[i], 0);
	} else {
		if (is_valid) {
			WRITE_ONCE(tcte[0], 0);
			ummu_sync_tct(ummu, tag, tid, true);
		}
		tcte[1] = cpu_to_le64(tct_desc->tcr1);
		tcte[2] = cpu_to_le64(tct_desc->ttbr & TCT_ENT2_TTBA);
		if (tct_desc->mapt_en) {
			val = cpu_to_le64(TCT_ENT3_MAPT_BBA & tct_desc->mapt_blk_phys) |
			      FIELD_PREP(TCT_ENT3_MAPT_BBA_SZ, tct_desc->blk_size_order) |
			      FIELD_PREP(TCT_ENT3_MAPT_BBA_MA, TCT_TCR_RGN_WBWA) |
			      FIELD_PREP(TCT_ENT3_MAPT_BBA_SH, TCT_MSD_IS);
			tcte[3] = cpu_to_le64(val);

			val = cpu_to_le64(TCT_ENT4_MAPT_BTA & tct_desc->mapt_blk_tbl_phys) |
			      FIELD_PREP(TCT_ENT4_MAPT_BTA_SZ, tct_desc->blk_tbl_size_order) |
			      FIELD_PREP(TCT_ENT4_MAPT_BTA_MA, TCT_TCR_RGN_WBWA) |
			      FIELD_PREP(TCT_ENT4_MAPT_BTA_SH, TCT_MSD_IS);
			tcte[4] = cpu_to_le64(val);
		}
		tcte[5] = cpu_to_le64(tct_desc->mair);
		val = tct_desc->tcr0 |
#ifdef __BIG_ENDIAN
		      TCT_ENT0_ENDI |
#endif
		      (tct_desc->mapt_en ? TCT_ENT0_MAPT_EN : 0) |
		      (tct_desc->mapt_mode == MAPT_MODE_TABLE ? TCT_ENT0_MAPT_MOD : 0) |
		      FIELD_PREP(TCT_ENT0_RTES, (tct_desc->mapt_mode == MAPT_MODE_TABLE ?
				 RTE_GRANULE_4K : 0)) |
		      (cfgs->btm_enabled ? 0 : TCT_ENT0_ASH) |
		      FIELD_PREP(TCT_ENT0_ASID, tct_desc->asid) | TCT_ENT0_V;

		if (cfgs->sva_mode == UMMU_MODE_DMA ||
		    cfgs->sva_mode == UMMU_MODE_SVA_DISABLE_PTB)
			val |= TCT_ENT0_EBIT_EN;
		else
			val &= ~TCT_ENT0_EBIT_EN;

		if (ummu->cap.features & UMMU_FEAT_HA)
			val |= TCT_ENT0_HAF;
		if (ummu->cap.features & UMMU_FEAT_HD)
			val |= TCT_ENT0_HDF;
		if (hw_bypass && type == IOMMU_DOMAIN_IDENTITY)
			val |= TCT_ENT0_MATT_BYPASS;
		WRITE_ONCE(tcte[0], cpu_to_le64(val));
	}

	ummu_sync_tct(ummu, tag, tid, true);
	return 0;
}

static bool ummu_tect_tag_in_range(struct ummu_device *ummu, u32 tect_tag)
{
	u32 range = ummu->tect_cfg->num_ents;

	if (ummu->cap.features & UMMU_FEAT_2_LVL_TECT)
		range *= 1UL << TECT_SPLIT;

	return tect_tag < range;
}

__le64 *ummu_get_tecte_ptr(struct ummu_device *ummu, u32 tect_tag)
{
	struct ummu_tect_cfg *tect = ummu->tect_cfg;
	struct ummu_tect_l1_desc *l1_desc;
	u32 l1_index, tect_index;

	if (!ummu_tect_tag_in_range(ummu, tect_tag)) {
		dev_err(ummu->dev, "tect_tag[%u] out of range.\n", tect_tag);
		return NULL;
	}

	if (tect->tect_fmt == TECT_BASE_CFG_FMT_LINEAR)
		return tect->tbl_vaddr + tect_tag * TECT_ENTRY_SIZE_DWORDS;

	l1_index = tect_tag >> TECT_SPLIT;
	l1_desc = &tect->l1_tect_desc[l1_index];
	if (!l1_desc->l2ptr) {
		dev_err(ummu->dev, "l2 tecte not initialized.\n");
		return NULL;
	}

	tect_index = tect_tag & GENMASK(TECT_SPLIT - 1, 0);
	return l1_desc->l2ptr + tect_index * TECT_ENTRY_SIZE_DWORDS;
}

static struct ummu_tecte_data *ummu_alloc_tecte(struct ummu_device *ummu, u32 tect_tag)
{
	struct ummu_tect_cfg *tect = ummu->tect_cfg;
	struct ummu_tect_l1_desc *l1_desc;
	u32 l1_index, tect_index;
	int ret;

	if (!ummu_tect_tag_in_range(ummu, tect_tag)) {
		dev_err(ummu->dev, "tect_tag[%u] out of range.\n", tect_tag);
		return NULL;
	}

	if (tect->tect_fmt == TECT_BASE_CFG_FMT_LINEAR)
		return (struct ummu_tecte_data *)(tect->tbl_vaddr +
			tect_tag * TECT_ENTRY_SIZE_DWORDS);

	l1_index = tect_tag >> TECT_SPLIT;
	l1_desc = &tect->l1_tect_desc[l1_index];
	if (!l1_desc->l2ptr) {
		ret = ummu_init_tect_second_lvl(tect, tect_tag);
		if (ret)
			return NULL;
	}

	tect_index = tect_tag & GENMASK(TECT_SPLIT - 1, 0);
	return (struct ummu_tecte_data *)(l1_desc->l2ptr +
		tect_index * TECT_ENTRY_SIZE_DWORDS);
}

static int ummu_alloc_os_meta(const struct ummu_capability *cap,
			      guid_t *guid, struct os_meta **os_data)
{
	struct os_meta *meta;
	u32 deid;
	int ret;

	meta = kzalloc(sizeof(*meta), GFP_ATOMIC);
	if (!meta)
		return -ENOMEM;
	ret = ummu_alloc_tct(cap, &meta->tct_tbl);
	if (ret)
		goto out_free_meta;

	scoped_guard(spinlock, &ummu_global) {
		ret = xa_alloc(&ummu_global_info.per_os_meta, &deid, meta,
		       XA_LIMIT(1, (1UL << cap->deid_bits) - 1), GFP_ATOMIC);
		if (ret) {
			pr_err("alloc tecte tag failed, ret = %d\n", ret);
			goto out_free_tct;
		}
	}

	guid_copy(&meta->guid, guid);
	INIT_LIST_HEAD(&meta->eids);
	kref_init(&meta->tct_tbl.ref);
	kref_init(&meta->ref);
	meta->tecte_tag = deid;
	*os_data = meta;
	kref_get(&meta->tct_tbl.ref);
	return 0;

out_free_tct:
	ummu_free_tct(&meta->tct_tbl);
out_free_meta:
	kfree(meta);
	return ret;
}

int ummu_get_tecte_tag_by_eid(eid_t eid, u32 *tecte_tag)
{
	struct eid_info *info;
	struct os_meta *meta;
	unsigned long idx;

	guard(spinlock)(&ummu_global);
	xa_for_each(&ummu_global_info.per_os_meta, idx, meta) {
		list_for_each_entry(info, &meta->eids, node) {
			if (info->eid == eid) {
				*tecte_tag = meta->tecte_tag;
				return 0;
			}
		}
	}
	return -ENODEV;
}

static struct os_meta *ummu_get_os_meta_by_guid(const guid_t *guid)
{
	struct os_meta *meta_iter;
	unsigned long idx;

	guard(spinlock)(&ummu_global);
	xa_for_each(&ummu_global_info.per_os_meta, idx, meta_iter) {
		if (guid_equal(&meta_iter->guid, guid))
			return meta_iter;
	}
	return NULL;
}

int ummu_set_domain_cfgs_tag(struct ummu_domain_cfgs *cfgs,
			     struct ummu_master *master)
{
	const guid_t *target = &guid_null;
	struct os_meta *meta = NULL;
	struct ub_entity *uent;

	if (cfgs->s1_cfg.tct_cfg)
		return 0;

	if (dev_is_ub(master->dev)) {
		uent = to_ub_entity(master->dev);
		if (ub_bi_is_dynamic(uent->bi))
			target = &uent->bi->info.guid.id;
		meta = ummu_get_os_meta_by_guid(target);
		if (!meta) {
			pr_err("get os meta by guid failed.\n");
			return -ENODEV;
		}
		cfgs->tecte_tag = meta->tecte_tag;
		cfgs->s1_cfg.tct_cfg = &meta->tct_tbl;
	} else {
		cfgs->tecte_tag = 0;
		cfgs->s1_cfg.tct_cfg = master->ummu->local_tct_cfg;
	}

	return 0;
}

static inline bool ummu_tecte_cfged(const struct ummu_tecte_data *target)
{
	return target->data[0] & cpu_to_le64(TECT_ENT0_V);
}

static void ummu_device_write_tecte_bypass(struct ummu_device *ummu,
					   u32 tag)
{
	struct ummu_tecte_data src, *dst;
	size_t i;

	dst = ummu_alloc_tecte(ummu, tag);
	if (!dst)
		return;

	if (ummu_tecte_cfged(dst))
		return;

	ummu_build_tecte_bypass(&src);

	src.data[0] |= cpu_to_le64(TECT_ENT0_V);

	for (i = 0; i < ARRAY_SIZE(src.data); i++)
		WRITE_ONCE(dst->data[i], src.data[i]);
}

static void ummu_device_make_default_tecte(struct ummu_device *ummu,
					   struct ummu_tct_desc_cfg *tct_cfg,
					   struct ummu_tecte_data *target,
					   enum eid_type type)
{
	u32 tcr_sel, st_mode;

	memset(target, 0, sizeof(*target));
	tcr_sel = ummu->cap.features & UMMU_FEAT_E2H ?
		  TECT_ENT0_TCR_EL2 : TECT_ENT0_TCR_NSEL1;

	st_mode = (type == EID_BYPASS) ? TECT_ENT0_ST_MODE_BYPASS : TECT_ENT0_ST_MODE_S1;
	target->data[0] = cpu_to_le64(
		TECT_ENT0_V | FIELD_PREP(TECT_ENT0_TCRC_SEL, tcr_sel) |
		((ummu->cap.features & UMMU_FEAT_MAPT) ? TECT_ENT0_MAPT_EN : 0) |
		FIELD_PREP(TECT_ENT0_ST_MODE, st_mode) |
		FIELD_PREP(TECT_ENT0_PRIV_SEL, TECT_ENT0_PRIV_SEL_PRIV));

	target->data[1] = cpu_to_le64(
		(tct_cfg->tct_phys_addr & TECT_ENT1_TCT_PTR) |
		FIELD_PREP(TECT_ENT1_TCT_MAX_NUM, tct_cfg->tcte_max_bits) |
		FIELD_PREP(TECT_ENT1_TCT_FMT, tct_cfg->tct_fmt) |
		FIELD_PREP(TECT_ENT1_TCT_PTR_MD0, TECT_ENT1_MD_CACHE_WBRA) |
		FIELD_PREP(TECT_ENT1_TCT_PTR_MD1, TECT_ENT1_MD_CACHE_WBRA) |
		FIELD_PREP(TECT_ENT1_TCT_PTR_MSD, TECT_ENT1_MD_CACHE_WB));

	if (!(ummu->cap.features & UMMU_FEAT_STALLS))
		target->data[1] |= cpu_to_le64(TECT_ENT1_TCT_STALL_DISABLE);
}

void ummu_build_s2_domain_tecte(struct ummu_domain *u_domain,
				struct ummu_tecte_data *target)
{
	struct ummu_device *ummu =
		core_to_ummu_device(u_domain->base_domain.core_dev);
	u64 ent0, ent2, ent3;

	memset(target, 0, sizeof(*target));
	ent0 = TECT_ENT0_V |
		FIELD_PREP(TECT_ENT0_ST_MODE, TECT_ENT0_ST_MODE_S2) |
		FIELD_PREP(TECT_ENT0_PRIV_SEL, TECT_ENT0_PRIV_SEL_PRIV) |
		FIELD_PREP(TECT_ENT0_S2_VMID, u_domain->cfgs.s2_cfg.vmid);

	ent2 = FIELD_PREP(TECT_ENT2_NS_VTCR, u_domain->cfgs.s2_cfg.vtcr) |
#ifdef __BIG_ENDIAN
		TECT_ENT2_S2_ENDI |
#endif
		TECT_ENT2_S2_PTW | TECT_ENT2_S2_FBR | TECT_ENT2_S2_AA64;
	if (ummu->cap.features & UMMU_FEAT_HA)
		ent2 |= TECT_ENT2_S2_HAF;
	if (ummu->cap.features & UMMU_FEAT_HD)
		ent2 |= TECT_ENT2_S2_HDF;

	ent3 = u_domain->cfgs.s2_cfg.vttbr & TECT_ENT3_S2_TTBR;
	target->data[0] = cpu_to_le64(ent0);
	target->data[2] = cpu_to_le64(ent2);
	target->data[3] = cpu_to_le64(ent3);
}

static bool check_tecte_can_set(const struct ummu_tecte_data *tecte,
				const struct ummu_tecte_data *src)
{
	u32 st_mode;

	if (!src->data[0])
		return true;

	st_mode = FIELD_GET(TECT_ENT0_ST_MODE, le64_to_cpu(tecte->data[0]));

	switch (st_mode) {
	case TECT_ENT0_ST_MODE_ABORT:
	case TECT_ENT0_ST_MODE_BYPASS:
		return true;
	case TECT_ENT0_ST_MODE_S1:
		if (FIELD_GET(TECT_ENT0_ST_MODE, src->data[0]) ==
		    TECT_ENT0_ST_MODE_S2)
			return true;

		return !ummu_tecte_cfged(tecte);
	case TECT_ENT0_ST_MODE_S2:
		return FIELD_GET(TECT_ENT0_ST_MODE, src->data[0]) ==
			TECT_ENT0_ST_MODE_NESTED;
	case TECT_ENT0_ST_MODE_NESTED:
		return tecte->data[1] != src->data[1];
	default:
		return false;
	}
}

static bool ummu_device_fill_tecte(struct ummu_device *ummu, u32 deid,
				  const struct ummu_tecte_data *src)
{
	struct ummu_tecte_data *tecte;

	tecte = ummu_alloc_tecte(ummu, deid);
	if (!tecte)
		return false;

	if (check_tecte_can_set(tecte, src)) {
		memcpy(tecte, src->data, sizeof(*src));
		return true;
	}
	return false;
}

void ummu_device_write_tecte(struct ummu_device *ummu, u32 deid,
			     struct ummu_tecte_data *src)
{
	if (iommu_default_passthrough())
		ummu_device_write_tecte_bypass(ummu, deid);
	else if (!src || !ummu_device_fill_tecte(ummu, deid, src))
		return;

	ummu_device_sync_tect(ummu, deid);
	ummu_device_prefetch_cfg(ummu, deid, UMMU_INVALID_TID);
}

bool dev_work_on_local(struct ummu_master *master)
{
	struct ub_entity *uent;

	if (dev_is_ub(master->dev)) {
		uent = to_ub_entity(master->dev);
		if (ub_bi_is_dynamic(uent->bi))
			return false;
	}
	return true;
}

int ummu_add_eid(struct ummu_core_device *core_dev, guid_t *guid, eid_t eid, enum eid_type type)
{
	struct ummu_device *ummu = core_to_ummu_device(core_dev);
	const struct ummu_capability *cap;
	struct ummu_tecte_data target;
	struct os_meta *meta = NULL;
	u32 kv_index;
	int ret;

	if ((type == EID_BYPASS) &&
	    (guid_is_null(guid) || !IS_ENABLED(CONFIG_UB_UMMU_BYPASSEID) || !hw_bypass))
		return -EOPNOTSUPP;

	meta = ummu_get_os_meta_by_guid((const guid_t *)guid);
	if (!meta) {
		cap = ummu_get_cap();
		if (!cap)
			return -EINVAL;
		/*
		 * os_meta is a singleton, and its release time is
		 * when no EID is attached to it.
		 */
		ret = ummu_alloc_os_meta(cap, guid, &meta);
		if (ret)
			return ret;
	}

	ret = ummu_device_calc_kv_index(ummu, eid, &kv_index);
	if (ret)
		return ret;

	ret = os_meta_add_eid(meta, eid, kv_index, type);
	if (ret) {
		dev_err(ummu->dev, "add eid failed: eid_high = 0x%llx, eid_low = 0x%llx\n",
			(u64)(eid >> EID_HIGH_SZ_SHIFT), (u64)eid);
		return ret;
	}

	if (!meta->valid) {
		meta->valid = true;
		ummu_device_make_default_tecte(ummu, &meta->tct_tbl, &target, type);
		ummu_device_write_tecte(ummu, meta->tecte_tag, &target);
	}
	ummu_device_create_kvtable(ummu, meta->tecte_tag, eid, kv_index);
	return 0;
}

void ummu_del_eid(struct ummu_core_device *core_dev, guid_t *guid, eid_t eid, enum eid_type type)
{
	struct ummu_device *ummu = core_to_ummu_device(core_dev);
	struct os_meta *meta = NULL;
	u32 kv_index;
	int ret;

	meta = ummu_get_os_meta_by_guid(guid);
	if (!meta) {
		dev_warn(ummu->dev, "the os meta corresponding to the guid not found.\n");
		return;
	}

	ret = os_meta_get_kv_index(meta, eid, &kv_index);
	if (ret) {
		dev_err(ummu->dev, "invalid eid:eid_high(0x%llx), eid_low(0x%llx)",
			(u64)(eid >> EID_HIGH_SZ_SHIFT), (u64)eid);
		return;
	}

	ummu_device_delete_kvtbl(ummu, meta->tecte_tag, eid, kv_index);
	/* 2 indicates that only the last EID remains. */
	if (kref_read(&meta->ref) == 2) {
		ummu_device_write_tecte(ummu, meta->tecte_tag, &ummu_clear_tecte);
		meta->valid = false;
	}

	os_meta_del_eid(meta, eid);
}

void ummu_device_set_tect(struct ummu_device *ummu)
{
	writeq_relaxed(ummu->tect_cfg->tect_reg_addr,
		ummu->base + UMMU_TECT_BASE);
	writel_relaxed(ummu->tect_cfg->tect_reg_cfg,
		ummu->base + UMMU_TECT_BASE_CFG);
}

int ummu_device_init_hash_table(struct ummu_device *ummu)
{
	void *kv_addr, *cam_addr;
	size_t ents, kv_size, cam_size;
	phys_addr_t kv_phys, cam_phys;
	u32 val;

	ents = KV_TABLE_DEPTH * KV_TABLE_BANK_NUM;
	kv_size = PAGE_ALIGN(ents * HASH_ENTRY_SIZE_BYTES);
	cam_size = PAGE_ALIGN(CAM_TABLE_DEPTH * HASH_ENTRY_SIZE_BYTES);

	if (!(ummu->cap.options & UMMU_OPT_KV_CAM_CONTINUITY)) {
		kv_addr = (void *)devm_get_free_pages(
			ummu->dev, GFP_KERNEL | __GFP_ZERO, get_order(kv_size));
		if (!kv_addr) {
			dev_err(ummu->dev, "allocate kv table failed(%zu bytes).\n",
				kv_size);
			return -ENOMEM;
		}
		kv_phys = virt_to_phys(kv_addr);
		cam_addr = (void *)devm_get_free_pages(
			ummu->dev, GFP_KERNEL | __GFP_ZERO, get_order(cam_size));
		if (!cam_addr) {
			dev_err(ummu->dev, "allocate cam table failed(%zu bytes).\n",
				cam_size);
			return -ENOMEM;
		}
		cam_phys = virt_to_phys(cam_addr);
	} else {
		kv_addr = (void *)devm_get_free_pages(
			ummu->dev, GFP_KERNEL | __GFP_ZERO, get_order(kv_size + cam_size));
		if (!kv_addr) {
			dev_err(ummu->dev, "allocate kv table failed(%zu bytes).\n",
				kv_size + cam_size);
			return -ENOMEM;
		}
		kv_phys = virt_to_phys(kv_addr);
		cam_addr = kv_addr + kv_size;
		cam_phys = kv_phys + kv_size;
	}

	ummu->hash_tbl_cfg.bank_depth = KV_TABLE_DEPTH;
	ummu->hash_tbl_cfg.bank_num = KV_TABLE_BANK_NUM;
	ummu->hash_tbl_cfg.hash_sel = KV_TABLE_HASH_CRC32;
	ummu->hash_tbl_cfg.hash_width = KV_TABLE_HASH_WIDTH_8BIT;
	ummu->hash_tbl_cfg.kv_tbl_vaddr = kv_addr;
	ummu->hash_tbl_cfg.kv_tbl_reg_addr = kv_phys & KV_TABLE_BASE_ADDR_MASK;
	val = FIELD_PREP(KV_TABLE_DEPTH_MASK, KV_TABLE_DEPTH) |
	      FIELD_PREP(KV_TABLE_BANK_NUM_MASK, KV_TABLE_BANK_NUM);
	ummu->hash_tbl_cfg.kv_tbl_reg_cfg = val;

	ummu->hash_tbl_cfg.cam_tbl_depth = CAM_TABLE_DEPTH;
	ummu->hash_tbl_cfg.cam_tbl_vaddr = cam_addr;
	ummu->hash_tbl_cfg.cam_tbl_reg_addr = cam_phys & CAM_TABLE_BASE_ADDR_MASK;

	val = FIELD_PREP(CAM_TABLE_DEPTH_MASK, CAM_TABLE_DEPTH);
	ummu->hash_tbl_cfg.cam_tbl_reg_cfg = val;
	return 0;
}

void ummu_device_config_hash_table(struct ummu_device *ummu)
{
	u32 reg;

	writeq_relaxed(ummu->hash_tbl_cfg.kv_tbl_reg_addr,
		       ummu->base + UMMU_KV_TABLE_BASE_OFFSET);

	writel_relaxed(ummu->hash_tbl_cfg.kv_tbl_reg_cfg,
		       ummu->base + UMMU_KV_TABLE_BASE_CFG_OFFSET);

	reg = FIELD_PREP(KV_TABLE_HASH_WIDTH_MASK, KV_TABLE_HASH_WIDTH_8BIT) |
	      FIELD_PREP(KV_TABLE_HASH_SEL_MASK, KV_TABLE_HASH_CRC32);
	writel_relaxed(reg,
		       ummu->base + UMMU_KV_TABLE_HASH_CFG0_OFFSET);

	writel_relaxed(CRC32_INIT_VALUE,
		       ummu->base + UMMU_KV_TABLE_HASH_CFG1_OFFSET);

	writeq_relaxed(ummu->hash_tbl_cfg.cam_tbl_reg_addr,
		       ummu->base + UMMU_CAM_TABLE_BASE_OFFSET);

	writel_relaxed(ummu->hash_tbl_cfg.cam_tbl_reg_cfg,
		       ummu->base + UMMU_CAM_TABLE_BASE_CFG_OFFSET);
}
