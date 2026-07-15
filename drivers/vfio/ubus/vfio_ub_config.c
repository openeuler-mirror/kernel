// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2012 Red Hat, Inc.  All rights reserved.
 * Author: Alex Williamson <alex.williamson@redhat.com>
 *
 * Derived from original vfio:
 * Copyright 2010 Cisco Systems, Inc.  All rights reserved.
 * Author: Tom Lyon, pugs@cisco.com
 *
 * Thanks to Alex Williamson and Tom Lyon for their original
 * vfio implementation.
 *
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt) "vfio ub: " fmt

#include <linux/vfio.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "vfio_ub_private.h"

#define NO_VIRT 0
#define ALL_VIRT 0xFFFFFFFFU
#define NO_WRITE 0
#define ALL_WRITE 0xFFFFFFFFU
#define NO_ENTITY0_EO 0
#define ENTITY0_EO 0xFFFFFFFFU
#define NO_ENTITYN_RO 0
#define ENTITYN_RO 0xFFFFFFFFU

/* Now, this attr control just supports at byte granularity */
enum {
	FUNC_EXIST = 0x00000000, /* idev and ub device have this register */
	IDEV_NO_EXIST = 0x01010101, /* idev does not have this register */
	UDEV_NO_EXIST = 0x02020202, /* ub device does not have this register */
	FUNC_NO_EXIST = 0x03030303, /* idev and ub device do not have this register */
};

struct attrs {
	__le32 ent0eo;
	__le32 entnro;
	__le32 exist;
};

#define CFG_MAP_INVALID (-1)

#define UB_PORT_CAP_GAP 0x100
#define UB_PORT0_BASIC_CAP 0x200

#define UB_CFG_POS_TO_CAP(pos) ((u64)(pos) >> 10)
#define UB_CFG_CAP_TO_POS(cap) ((u32)(cap) << 10)

static const u8 zero_array[UB_SLICE_SZ] = {};

/* Handle endian-ness - ub and tables are little-endian */
static inline void p_setb(struct perm_bits *p, int off, u8 virt, u8 write)
{
	p->virt[off] = virt;
	p->write[off] = write;
}

/* Handle endian-ness - ub and tables are little-endian */
static inline void p_setw(struct perm_bits *p, int off, u16 virt, u16 write)
{
	*(__le16 *)(&p->virt[off]) = cpu_to_le16(virt);
	*(__le16 *)(&p->write[off]) = cpu_to_le16(write);
}

/* Handle endian-ness - ub and tables are little-endian */
static inline void p_setd(struct perm_bits *p, int off, u32 virt, u32 write)
{
	*(__le32 *)(&p->virt[off]) = cpu_to_le32(virt);
	*(__le32 *)(&p->write[off]) = cpu_to_le32(write);
}

static inline void p_attr_setb(struct perm_bits *p, int off, u8 ent0eo, u8 entnro, u8 exist)
{
	p->ent0eo[off] = ent0eo;
	p->entnro[off] = entnro;
	p->exist[off] = exist;
}

static inline void p_attr_setw(struct perm_bits *p, int off, u16 ent0eo, u16 entnro, u16 exist)
{
	*(__le16 *)(&p->ent0eo[off]) = cpu_to_le16(ent0eo);
	*(__le16 *)(&p->entnro[off]) = cpu_to_le16(entnro);
	*(__le16 *)(&p->exist[off]) = cpu_to_le16(exist);
}

static inline void p_attr_setd(struct perm_bits *p, int off, u32 ent0eo, u32 entnro, u32 exist)
{
	*(__le32 *)(&p->ent0eo[off]) = cpu_to_le32(ent0eo);
	*(__le32 *)(&p->entnro[off]) = cpu_to_le32(entnro);
	*(__le32 *)(&p->exist[off]) = cpu_to_le32(exist);
}

static int vfio_ub_do_user_config_read(struct ub_entity *uent, u64 pos,
				       __le32 *val, int count)
{
	int ret = -EINVAL;
	u32 tmp_val = 0;
	u8 tmp_byte;
	u16 tmp_word;

	switch (count) {
	case BYTE_SIZE:
		ret = ub_cfg_read_byte(uent, pos, &tmp_byte);
		tmp_val = tmp_byte;
		break;
	case WORD_SIZE:
		ret = ub_cfg_read_word(uent, pos, &tmp_word);
		tmp_val = tmp_word;
		break;
	case DWORD_SIZE:
		ret = ub_cfg_read_dword(uent, pos, &tmp_val);
		break;
	default:
		break;
	}

	*val = cpu_to_le32(tmp_val);

	return ret;
}

static bool vfio_ub_judge_type(struct ub_entity *uent, u8 exist)
{
	return ((((exist & IDEV_NO_EXIST) == 0) && (uent_type(uent) == UB_TYPE_ICONTROLLER &&
		uent_base_code(uent) != UB_BASE_CODE_BUS_CONTROLLER)) ||
		(((exist & UDEV_NO_EXIST) == 0) && (uent_type(uent) == UB_TYPE_CONTROLLER &&
		uent_base_code(uent) != UB_BASE_CODE_BUS_CONTROLLER)));
}

static bool vfio_ub_judge_reg_read(struct ub_entity *uent, u8 ent0eo, u8 exist)
{
	if (vfio_ub_judge_type(uent, exist)) {
		if (((ent0eo == (u8)ENTITY0_EO) && (uent->entity_idx == 0)) ||
		    (ent0eo == NO_ENTITY0_EO)) {
			return true;
		}
	}

	return false;
}

static bool vfio_ub_judge_reg_write(struct ub_entity *uent, u8 ent0eo, u8 exist, u8 entnro)
{
	if (vfio_ub_judge_type(uent, exist)) {
		if (((uent->entity_idx != 0) && (ent0eo == NO_ENTITY0_EO) &&
		    (entnro == NO_ENTITYN_RO)) || uent->entity_idx == 0) {
			return true;
		}
	}

	return false;
}

static int vfio_ub_get_split_cfg_val(struct ub_entity *uent, u64 pos,
				     struct attrs *attr, __le32 *val, u32 count)
{
	u32 tmp_val = 0;
	u8 byte;
	u8 ent0eo_byte;
	u8 exist_byte;
	int ret;

	for (u32 i = 0; i < count; i++) {
		ent0eo_byte = (attr->ent0eo >> i * BITS_PER_BYTE) & 0xff;
		exist_byte = (attr->exist >> i * BITS_PER_BYTE) & 0xff;
		if (vfio_ub_judge_reg_read(uent, ent0eo_byte, exist_byte)) {
			ret = ub_cfg_read_byte(uent, pos + i, &byte);
			if (!ret)
				tmp_val = tmp_val | (((u32)byte) << i * BITS_PER_BYTE);
			else
				return ret;
		}
	}

	*val = tmp_val;

	return 0;
}

static int vfio_ub_set_split_cfg_val(struct ub_entity *uent, u64 pos,
				     struct attrs *attr, __le32 val, u32 count)
{
	u8 byte;
	u8 ent0eo_byte;
	u8 exist_byte;
	u8 entnro_byte;
	int ret;

	for (int i = 0; i < count; i++) {
		ent0eo_byte = (attr->ent0eo >> i * BITS_PER_BYTE) & 0xff;
		exist_byte = (attr->exist >> i * BITS_PER_BYTE) & 0xff;
		entnro_byte = (attr->entnro >> i * BITS_PER_BYTE) & 0xff;
		if (vfio_ub_judge_reg_write(uent, ent0eo_byte, exist_byte,
					    entnro_byte)) {
			byte = val >> i * BITS_PER_BYTE;
			ret = ub_cfg_write_byte(uent, pos + i, byte);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static int vfio_ub_default_config_read(struct vfio_ub_core_device *vdev,
				       u64 pos, int count, __le32 *val);

static struct perm_bits cap_perms[UB_CFG1_MAX_CAP + 1] = {};

static struct perm_bits port_basic_perms = {.readfn = vfio_ub_default_config_read };

/* when called this function, cap_id is always exist */
static struct perm_bits *vfio_ub_find_cap_perm(u32 cap_id)
{
	if (cap_id <= UB_CFG1_MAX_CAP)
		return &cap_perms[cap_id];

	return &port_basic_perms;
}

static int vfio_ub_user_config_read(struct ub_entity *uent, u64 pos,
				    __le32 *val, int count)
{
	struct perm_bits *perm;
	struct attrs attr = {};
	u32 offset;
	u32 cap_id;

	cap_id = UB_CFG_POS_TO_CAP(pos);
	perm = vfio_ub_find_cap_perm(cap_id);
	offset = pos - UB_CFG_CAP_TO_POS(cap_id);

	memcpy(&attr.ent0eo, perm->ent0eo + offset, count);
	memcpy(&attr.exist, perm->exist + offset, count);

	/* quick processing for most situations */
	if (likely(attr.exist == FUNC_EXIST && attr.ent0eo == NO_ENTITY0_EO))
		return vfio_ub_do_user_config_read(uent, pos, val, count);

	/* read cfg at byte unit */
	return vfio_ub_get_split_cfg_val(uent, pos, &attr, val, count);
}

static int vfio_ub_do_user_config_write(struct ub_entity *uent, u64 pos,
					__le32 val, int count)
{
	int ret = -EINVAL;
	u32 tmp_val = le32_to_cpu(val);

	switch (count) {
	case BYTE_SIZE:
		ret = ub_cfg_write_byte(uent, pos, tmp_val);
		break;
	case WORD_SIZE:
		ret = ub_cfg_write_word(uent, pos, tmp_val);
		break;
	case DWORD_SIZE:
		ret = ub_cfg_write_dword(uent, pos, tmp_val);
		break;
	default:
		break;
	}

	return ret;
}

static int vfio_ub_user_config_write(struct ub_entity *uent, u64 pos,
				     __le32 val, int count)
{
	struct perm_bits *perm;
	struct attrs attr = {};
	u32 offset;
	u32 cap_id;

	cap_id = UB_CFG_POS_TO_CAP(pos);
	perm = vfio_ub_find_cap_perm(cap_id);
	offset = pos - UB_CFG_CAP_TO_POS(cap_id);

	memcpy(&attr.ent0eo, perm->ent0eo + offset, count);
	memcpy(&attr.exist, perm->exist + offset, count);
	memcpy(&attr.entnro, perm->entnro + offset, count);

	/* quick processing for most situations */
	if (likely(attr.exist == FUNC_EXIST && attr.ent0eo == NO_ENTITY0_EO
	    && attr.entnro == NO_ENTITYN_RO))
		return vfio_ub_do_user_config_write(uent, pos, val, count);

	return vfio_ub_set_split_cfg_val(uent, pos, &attr, val, count);
}

static u8 *vfio_ub_find_cfg_buf(struct vfio_ub_core_device *vdev, u32 cap_id)
{
	int i;
	int num;

	if (cap_id <= UB_CFG1_MAX_CAP) {
		num = vdev->vconfig.map[cap_id];
		if (num != CFG_MAP_INVALID)
			return vdev->vconfig.slice[num].cfg;
	} else {
		for (i = 0; i < vdev->vconfig.nums; i++) {
			if (vdev->vconfig.slice[i].cap_id == cap_id)
				return vdev->vconfig.slice[i].cfg;
		}
	}

	return NULL;
}

static int vfio_ub_default_config_read(struct vfio_ub_core_device *vdev,
				       u64 pos, int count, __le32 *val)
{
	struct perm_bits *perm;
	__le32 virt = 0;
	u8 *buf;
	u32 cap_id;
	u32 offset;

	cap_id = UB_CFG_POS_TO_CAP(pos);
	offset = pos - UB_CFG_CAP_TO_POS(cap_id);
	perm = vfio_ub_find_cap_perm(cap_id);
	buf = vfio_ub_find_cfg_buf(vdev, cap_id);
	if (buf == NULL)
		return -EINVAL;

	memcpy(val, buf + offset, count);
	memcpy(&virt, perm->virt + offset, count);

	if (cpu_to_le32(~0U >> (DWORD_BITS - (count * BYTE_BITS))) != virt) {
		struct ub_entity *uent = vdev->uent;
		__le32 phys_val = 0;
		int ret;

		ret = vfio_ub_user_config_read(uent, pos, &phys_val, count);
		if (ret)
			return ret;

		*val = (phys_val & ~virt) | (*val & virt);
	}

	return count;
}

static __le32 vfio_ub_get_virt_write_mask(struct ub_entity *uent, u64 pos, int count)
{
	u8 ent0eo_byte, exist_byte, entnro_byte;
	struct perm_bits *perm;
	__le32 tmp_val = 0;
	u32 cap_id;
	u32 offset;

	cap_id = UB_CFG_POS_TO_CAP(pos);
	offset = pos - UB_CFG_CAP_TO_POS(cap_id);
	perm = vfio_ub_find_cap_perm(cap_id);

	for (int i = 0; i < count; i++) {
		/* register attrs control at byte unit */
		ent0eo_byte = perm->ent0eo[offset + i];
		exist_byte = perm->exist[offset + i];
		entnro_byte = perm->entnro[offset + i];

		if (vfio_ub_judge_reg_write(uent, ent0eo_byte, exist_byte,
					    entnro_byte))
			tmp_val |= 0xff << (i * BITS_PER_BYTE);
	}

	return tmp_val;
}

static int vfio_ub_default_config_write(struct vfio_ub_core_device *vdev,
					u64 pos, int count, __le32 val)
{
	__le32 virt = 0, write = 0, mask = 0;
	struct perm_bits *perm;
	u8 *buf;
	u32 cap_id;
	u32 offset;

	cap_id = UB_CFG_POS_TO_CAP(pos);
	offset = pos - UB_CFG_CAP_TO_POS(cap_id);
	perm = vfio_ub_find_cap_perm(cap_id);
	buf = vfio_ub_find_cfg_buf(vdev, cap_id);
	if (buf == NULL)
		return -EINVAL;

	memcpy(&write, perm->write + offset, count);

	if (!write)
		return count; /* just drop it, no writable bits */

	memcpy(&virt, perm->virt + offset, count);

	if (write & virt) {
		__le32 virt_val = 0;

		mask = vfio_ub_get_virt_write_mask(vdev->uent, pos, count);
		memcpy(&virt_val, buf + offset, count);
		virt_val &= ~(write & virt & mask);
		virt_val |= (val & (write & virt & mask));

		memcpy(buf + offset, &virt_val, count);
	}

	/* Non-virtualized and writable bits go to hardware */
	if (write & ~virt) {
		struct ub_entity *uent = vdev->uent;
		__le32 phys_val = 0;
		int ret;

		ret = vfio_ub_user_config_read(uent, pos, &phys_val, count);
		if (ret)
			return ret;

		phys_val &= ~(write & ~virt);
		phys_val |= (val & (write & ~virt));

		ret = vfio_ub_user_config_write(uent, pos, phys_val, count);
		if (ret)
			return ret;
	}

	return count;
}

static void free_perm_bits(struct perm_bits *perm)
{
	vfree(perm->exist);
	vfree(perm->entnro);
	vfree(perm->ent0eo);
	vfree(perm->write);
	vfree(perm->virt);
	perm->exist = NULL;
	perm->entnro = NULL;
	perm->ent0eo = NULL;
	perm->virt = NULL;
	perm->write = NULL;
}

static int alloc_perm_bits(struct perm_bits *perm, int size)
{
	int tmp;

	tmp = round_up(size, DWORD_SIZE);

	/*
	 * Zero state is
	 * - All Readable, None Writable, None Virtualized
	 */
	perm->virt = vzalloc(tmp);
	perm->write = vzalloc(tmp);
	perm->ent0eo = vzalloc(tmp);
	perm->entnro = vzalloc(tmp);
	perm->exist = vzalloc(tmp);
	if (!perm->virt || !perm->write || !perm->ent0eo ||
	    !perm->entnro || !perm->exist) {
		free_perm_bits(perm);
		return -ENOMEM;
	}

	perm->readfn = vfio_ub_default_config_read;
	perm->writefn = vfio_ub_default_config_write;

	return 0;
}

static void init_ub_cfg_chunk_perms(struct perm_bits *perm, u32 pos,
				    u32 size, u32 virt, u32 write)
{
	for (u32 idx = 0; idx < size; idx++)
		p_setd(perm, pos + idx * DWORD_SIZE, virt, write);
}

static void init_ub_cfg_chunk_attrs(struct perm_bits *perm, u32 pos, u32 size,
				    u32 ent0eo, u32 entnro, u32 exist)
{
	for (u32 idx = 0; idx < size; idx++)
		p_attr_setd(perm, pos + idx * DWORD_SIZE, ent0eo, entnro, exist);
}

static int vfio_ub_cfg0_basic_read(struct vfio_ub_core_device *vdev, u64 pos,
				   int count, __le32 *val)
{
	count = vfio_ub_default_config_read(vdev, pos, count, val);

	return count;
}

static int vfio_ub_cfg0_basic_write(struct vfio_ub_core_device *vdev, u64 pos,
				    int count, __le32 val)
{
	count = vfio_ub_default_config_write(vdev, pos, count, val);

	return count;
}

static void init_ub_cfg0_basic_operation_perm(struct perm_bits *perm)
{
	p_setd(perm, UB_CFG0_BASIC_SLICE, ALL_VIRT, NO_WRITE);
	p_setd(perm, UB_TOTAL_NUMBER_PORT, ALL_VIRT, NO_WRITE);

	init_ub_cfg_chunk_perms(perm, UB_CFG0_CAP_BITMAP,
				UB_CFG_BITMAP_SIZE / DWORD_SIZE,
				ALL_VIRT, NO_WRITE);
	init_ub_cfg_chunk_perms(perm, UB_FEATURE_SUPPORT_0,
				UB_CFG0_SUPPORT_FEATURE_SIZE / DWORD_SIZE,
				ALL_VIRT, NO_WRITE);
	init_ub_cfg_chunk_perms(perm, UB_GUID, UB_GUID_SIZE / DWORD_SIZE,
				ALL_VIRT, NO_WRITE);
	init_ub_cfg_chunk_perms(perm, UB_EID_0, UB_EID_SIZE / DWORD_SIZE,
				ALL_VIRT, ALL_WRITE);
	init_ub_cfg_chunk_perms(perm, UB_FM_EID_0, UB_FM_EID_SIZE / DWORD_SIZE,
				ALL_VIRT, ALL_WRITE);

	p_setd(perm, UB_PRIMARY_CNA, UB_PRIMARY_CNA_MASK, UB_PRIMARY_CNA_MASK);
	p_setd(perm, UB_UEID_0, ALL_VIRT, ALL_WRITE);
	p_setd(perm, UB_UEID_1, ALL_VIRT, ALL_WRITE);
	p_setd(perm, UB_UEID_2, ALL_VIRT, ALL_WRITE);
	p_setd(perm, UB_UEID_3, ALL_VIRT, ALL_WRITE);
	p_setd(perm, UB_UCNA, UB_UCNA_MASK, UB_UCNA_MASK);

	p_setw(perm, UB_UPI, (u16)ALL_VIRT, (u16)ALL_WRITE);
	p_setd(perm, UB_MODULE, ALL_VIRT, NO_WRITE);
	p_setb(perm, UB_ENTITY_RST, (u8)ALL_VIRT, UB_ENTITY_RST_BIT);
	p_setb(perm, UB_MTU_CFG, (u8)ALL_VIRT, UB_MTU_CFG_BITS);
	p_setb(perm, UB_CC_EN, (u8)ALL_VIRT, UB_CC_EN_BIT);
	p_setb(perm, UB_TH_EN, (u8)ALL_VIRT, UB_TH_EN_BIT);
	p_setd(perm, UB_FM_CNA, UB_FM_CNA_MASK, UB_FM_CNA_MASK);
}

static void init_ub_cfg0_basic_attr_perm(struct perm_bits *perm)
{
	p_attr_setw(perm, UB_TOTAL_NUMBER_ENTITIES, (u16)ENTITY0_EO, NO_ENTITYN_RO, FUNC_EXIST);
	init_ub_cfg_chunk_attrs(perm, UB_FM_EID_0, UB_FM_EID_SIZE / DWORD_SIZE,
				ENTITY0_EO, NO_ENTITYN_RO, FUNC_EXIST);

	p_attr_setd(perm, UB_PRIMARY_CNA, NO_ENTITY0_EO, ENTITYN_RO, FUNC_EXIST);
	p_attr_setd(perm, UB_PRIMARY_CNA + 0x4, NO_ENTITY0_EO, ENTITYN_RO, FUNC_NO_EXIST);
	p_attr_setd(perm, UB_PRIMARY_CNA + 0x8, NO_ENTITY0_EO, ENTITYN_RO, FUNC_NO_EXIST);
	p_attr_setd(perm, UB_PRIMARY_CNA + 0xc, NO_ENTITY0_EO, ENTITYN_RO, FUNC_NO_EXIST);
	p_attr_setd(perm, UB_PRIMARY_CNA + 0x10, NO_ENTITY0_EO, ENTITYN_RO, FUNC_NO_EXIST);

	p_attr_setd(perm, UB_ENTITY_RST, ENTITY0_EO, NO_ENTITYN_RO, FUNC_EXIST);
	p_attr_setb(perm, UB_MTU_CFG, (u8)NO_ENTITY0_EO, (u8)ENTITYN_RO, (u8)FUNC_EXIST);
	p_attr_setb(perm, UB_CC_EN, (u8)NO_ENTITY0_EO, (u8)ENTITYN_RO, (u8)FUNC_EXIST);
	p_attr_setd(perm, UB_TH_EN, ENTITY0_EO, NO_ENTITYN_RO, FUNC_EXIST);
	p_attr_setd(perm, UB_FM_CNA, ENTITY0_EO, NO_ENTITYN_RO, FUNC_EXIST);

	p_attr_setd(perm, UB_FEATURE_SUPPORT_0 + 0x4, NO_ENTITY0_EO, NO_ENTITYN_RO, FUNC_NO_EXIST);
	p_attr_setd(perm, UB_FEATURE_SUPPORT_0 + 0x8, NO_ENTITY0_EO, NO_ENTITYN_RO, FUNC_NO_EXIST);
	p_attr_setd(perm, UB_FEATURE_SUPPORT_0 + 0xc, NO_ENTITY0_EO, NO_ENTITYN_RO, FUNC_NO_EXIST);
	p_attr_setd(perm, UB_ENTITY_RST + 0x4, NO_ENTITY0_EO, NO_ENTITYN_RO, FUNC_NO_EXIST);
}

static int init_ub_cfg0_basic_perm(struct perm_bits *perm)
{
	if (alloc_perm_bits(perm, UB_SLICE_SZ))
		return -ENOMEM;

	perm->readfn = vfio_ub_cfg0_basic_read;
	perm->writefn = vfio_ub_cfg0_basic_write;

	init_ub_cfg0_basic_operation_perm(perm);
	init_ub_cfg0_basic_attr_perm(perm);
	return 0;
}

static int init_ub_cfg0_cap_perm(struct perm_bits *perm)
{
	return 0;
}

static int vfio_ub_cfg1_basic_read(struct vfio_ub_core_device *vdev, u64 pos,
				   int count, __le32 *val)
{
	count = vfio_ub_default_config_read(vdev, pos, count, val);

	return count;
}

static int vfio_ub_cfg1_basic_write(struct vfio_ub_core_device *vdev, u64 pos,
				    int count, __le32 val)
{
	int ret;
	u8 *elr;
	u8 *buf;

	count = vfio_ub_default_config_write(vdev, pos, count, val);
	if (count < 0)
		return count;

	if (pos == UB_ENTITY_RS_ACCESS_EN) {
		ret = ub_entity_enable_return(vdev->uent, val & 0x1);
		if (ret)
			return ret;
	}

	buf = vfio_ub_find_cfg_buf(vdev, UB_CFG1_BASIC_CAP);
	if (!buf)
		return -EFAULT;

	elr = buf + UB_ELR - UB_CFG1_BASIC;
	if (*elr & UB_ELR_BIT) {
		*elr = *elr & (u8)~UB_ELR_BIT;
		ret = ub_reset_entity(vdev->uent);
		if (ret) {
			ub_warn(vdev->uent, "ELR reset failed, ret=%d\n", ret);
			return ret;
		}
	}

	return count;
}

static void init_ub_cfg1_basic_operation_perm(struct perm_bits *perm)
{
	p_setd(perm, UB_CFG1_BASIC_SLICE - UB_CFG1_BASIC, ALL_VIRT, NO_WRITE);
	init_ub_cfg_chunk_perms(perm, UB_CFG1_CAP_BITMAP - UB_CFG1_BASIC,
				UB_CFG_BITMAP_SIZE / DWORD_SIZE,
				ALL_VIRT, NO_WRITE);
	init_ub_cfg_chunk_perms(perm, UB_CFG1_SUPPORT_FEATURE_L - UB_CFG1_BASIC,
				UB_CFG1_SUPPORT_FEATURE_SIZE / DWORD_SIZE,
				ALL_VIRT, NO_WRITE);

	p_setd(perm, UB_ERS0_SS - UB_CFG1_BASIC, ALL_VIRT, NO_WRITE);
	p_setd(perm, UB_ERS1_SS - UB_CFG1_BASIC, ALL_VIRT, NO_WRITE);
	p_setd(perm, UB_ERS2_SS - UB_CFG1_BASIC, ALL_VIRT, NO_WRITE);
	p_setd(perm, UB_ERS0_SA_L - UB_CFG1_BASIC, ALL_VIRT, NO_WRITE);
	p_setd(perm, UB_ERS0_SA_H - UB_CFG1_BASIC, ALL_VIRT, NO_WRITE);
	p_setd(perm, UB_ERS1_SA_L - UB_CFG1_BASIC, ALL_VIRT, NO_WRITE);
	p_setd(perm, UB_ERS1_SA_H - UB_CFG1_BASIC, ALL_VIRT, NO_WRITE);
	p_setd(perm, UB_ERS2_SA_L - UB_CFG1_BASIC, ALL_VIRT, NO_WRITE);
	p_setd(perm, UB_ERS2_SA_H - UB_CFG1_BASIC, ALL_VIRT, NO_WRITE);
	p_setd(perm, UB_ERS0_UBBA_L - UB_CFG1_BASIC, ALL_VIRT, ALL_WRITE);
	p_setd(perm, UB_ERS0_UBBA_H - UB_CFG1_BASIC, ALL_VIRT, ALL_WRITE);
	p_setd(perm, UB_ERS1_UBBA_L - UB_CFG1_BASIC, ALL_VIRT, ALL_WRITE);
	p_setd(perm, UB_ERS1_UBBA_H - UB_CFG1_BASIC, ALL_VIRT, ALL_WRITE);
	p_setd(perm, UB_ERS2_UBBA_L - UB_CFG1_BASIC, ALL_VIRT, ALL_WRITE);
	p_setd(perm, UB_ERS2_UBBA_H - UB_CFG1_BASIC, ALL_VIRT, ALL_WRITE);

	p_setd(perm, UB_ELR - UB_CFG1_BASIC, ALL_VIRT, UB_ELR_BIT);
	p_setd(perm, UB_ELR_DONE - UB_CFG1_BASIC, ~UB_ELR_DONE_BIT, NO_WRITE);
	p_setd(perm, UB_SYS_PGS - UB_CFG1_BASIC, ALL_VIRT, UB_SYS_PGS_SIZE);

	p_setd(perm, UB_ENTITY_TOKEN_ID - UB_CFG1_BASIC, NO_VIRT, UB_TOKEN_ID_MASK);
	p_setd(perm, UB_BUS_ACCESS_EN - UB_CFG1_BASIC, NO_VIRT,
	       UB_BUS_ACCESS_EN_BIT);
	p_setd(perm, UB_ENTITY_RS_ACCESS_EN - UB_CFG1_BASIC, NO_VIRT,
	       UB_BUS_ACCESS_EN_BIT);
}

static void init_ub_cfg1_basic_attr_perm(struct perm_bits *perm)
{
	p_attr_setd(perm, UB_ERS0_SA_L - UB_CFG1_BASIC, NO_ENTITY0_EO, NO_ENTITYN_RO,
		    IDEV_NO_EXIST);
	p_attr_setd(perm, UB_ERS0_SA_H - UB_CFG1_BASIC, NO_ENTITY0_EO, NO_ENTITYN_RO,
		    IDEV_NO_EXIST);

	p_attr_setd(perm, UB_ERS1_SA_L - UB_CFG1_BASIC, NO_ENTITY0_EO, NO_ENTITYN_RO,
		    IDEV_NO_EXIST);
	p_attr_setd(perm, UB_ERS1_SA_H - UB_CFG1_BASIC, NO_ENTITY0_EO, NO_ENTITYN_RO,
		    IDEV_NO_EXIST);

	p_attr_setd(perm, UB_ERS2_SA_L - UB_CFG1_BASIC, NO_ENTITY0_EO, NO_ENTITYN_RO,
		    IDEV_NO_EXIST);
	p_attr_setd(perm, UB_ERS2_SA_H - UB_CFG1_BASIC, NO_ENTITY0_EO, NO_ENTITYN_RO,
		    IDEV_NO_EXIST);

	p_attr_setd(perm, UB_ERS0_UBBA_L - UB_CFG1_BASIC, NO_ENTITY0_EO, ENTITYN_RO,
		    UDEV_NO_EXIST);
	p_attr_setd(perm, UB_ERS0_UBBA_H - UB_CFG1_BASIC, NO_ENTITY0_EO, ENTITYN_RO,
		    UDEV_NO_EXIST);

	p_attr_setd(perm, UB_ERS1_UBBA_L - UB_CFG1_BASIC, NO_ENTITY0_EO, ENTITYN_RO,
		    UDEV_NO_EXIST);
	p_attr_setd(perm, UB_ERS1_UBBA_H - UB_CFG1_BASIC, NO_ENTITY0_EO, ENTITYN_RO,
		    UDEV_NO_EXIST);

	p_attr_setd(perm, UB_ERS2_UBBA_L - UB_CFG1_BASIC, NO_ENTITY0_EO, ENTITYN_RO,
		    UDEV_NO_EXIST);
	p_attr_setd(perm, UB_ERS2_UBBA_H - UB_CFG1_BASIC, NO_ENTITY0_EO, ENTITYN_RO,
		    UDEV_NO_EXIST);

	p_attr_setd(perm, UB_SYS_PGS - UB_CFG1_BASIC, NO_ENTITY0_EO, NO_ENTITYN_RO,
		    FUNC_NO_EXIST);
	p_attr_setd(perm, UB_EU_TBA_L - UB_CFG1_BASIC, NO_ENTITY0_EO, NO_ENTITYN_RO,
		    FUNC_NO_EXIST);
	p_attr_setd(perm, UB_EU_TBA_H - UB_CFG1_BASIC, NO_ENTITY0_EO, NO_ENTITYN_RO,
		    FUNC_NO_EXIST);
	p_attr_setd(perm, UB_EU_TEN - UB_CFG1_BASIC, NO_ENTITY0_EO, NO_ENTITYN_RO,
		    FUNC_NO_EXIST);
	p_attr_setd(perm, UB_CLASS_CODE - UB_CFG1_BASIC, NO_ENTITY0_EO, NO_ENTITYN_RO,
		    FUNC_EXIST);

	p_attr_setd(perm, UB_ELR_DONE - UB_CFG1_BASIC + 0x4, NO_ENTITY0_EO, NO_ENTITYN_RO,
		    FUNC_NO_EXIST);
	p_attr_setd(perm, UB_ELR_DONE - UB_CFG1_BASIC + 0x8, NO_ENTITY0_EO, NO_ENTITYN_RO,
		    FUNC_NO_EXIST);
	p_attr_setd(perm, UB_ELR_DONE - UB_CFG1_BASIC + 0xc, NO_ENTITY0_EO, NO_ENTITYN_RO,
		    FUNC_NO_EXIST);
	p_attr_setd(perm, UB_EU_TEN - UB_CFG1_BASIC + 0x4, NO_ENTITY0_EO, NO_ENTITYN_RO,
		    FUNC_NO_EXIST);
	p_attr_setd(perm, UB_EU_TEN - UB_CFG1_BASIC + 0x8, NO_ENTITY0_EO, NO_ENTITYN_RO,
		    FUNC_NO_EXIST);
	p_attr_setd(perm, UB_EU_TEN - UB_CFG1_BASIC + 0xc, NO_ENTITY0_EO, NO_ENTITYN_RO,
		    FUNC_NO_EXIST);
	p_attr_setd(perm, UB_EU_TEN - UB_CFG1_BASIC + 0x10, NO_ENTITY0_EO, NO_ENTITYN_RO,
		    FUNC_NO_EXIST);
	p_attr_setd(perm, UB_CLASS_CODE - UB_CFG1_BASIC + 0x4, NO_ENTITY0_EO, NO_ENTITYN_RO,
		    FUNC_NO_EXIST);
	p_attr_setd(perm, UB_CLASS_CODE - UB_CFG1_BASIC + 0x8, NO_ENTITY0_EO, NO_ENTITYN_RO,
		    FUNC_NO_EXIST);
	p_attr_setd(perm, UB_CLASS_CODE - UB_CFG1_BASIC + 0xc, NO_ENTITY0_EO, NO_ENTITYN_RO,
		    FUNC_NO_EXIST);
}

static int init_ub_cfg1_basic_perm(struct perm_bits *perm)
{
	if (alloc_perm_bits(perm, UB_SLICE_SZ))
		return -ENOMEM;

	perm->readfn = vfio_ub_cfg1_basic_read;
	perm->writefn = vfio_ub_cfg1_basic_write;

	init_ub_cfg1_basic_operation_perm(perm);
	init_ub_cfg1_basic_attr_perm(perm);

	return 0;
}

static int vfio_ub_int_type2_cap_read(struct vfio_ub_core_device *vdev, u64 pos,
				int count, __le32 *val)
{
	count = vfio_ub_default_config_read(vdev, pos, count, val);

	return count;
}

static int vfio_ub_int_type2_cap_write(struct vfio_ub_core_device *vdev, u64 pos,
				 int count, __le32 val)
{
	count = vfio_ub_default_config_write(vdev, pos, count, val);

	return count;
}

static int init_ub_cfg1_int_cap_perm(struct perm_bits *perm)
{
	if (alloc_perm_bits(perm, UB_SLICE_SZ))
		return -ENOMEM;

	perm->readfn = vfio_ub_int_type2_cap_read;
	perm->writefn = vfio_ub_int_type2_cap_write;

	p_setd(perm, UB_INT_CAP_SLICE - UB_CFG1_CAP_INT_CAP, ALL_VIRT, NO_WRITE);
	p_setd(perm, UB_INT_INFO - UB_CFG1_CAP_INT_CAP, ALL_VIRT, NO_WRITE);
	p_setd(perm, UB_INT_VECTOR_TBL_SA_L - UB_CFG1_CAP_INT_CAP,
	       ALL_VIRT, NO_WRITE);
	p_setd(perm, UB_INT_VECTOR_TBL_SA_H - UB_CFG1_CAP_INT_CAP,
	       ALL_VIRT, NO_WRITE);
	p_setd(perm, UB_INT_ADDR_TBL_SA_L - UB_CFG1_CAP_INT_CAP,
	       ALL_VIRT, NO_WRITE);
	p_setd(perm, UB_INT_ADDR_TBL_SA_H - UB_CFG1_CAP_INT_CAP,
	       ALL_VIRT, NO_WRITE);
	p_setd(perm, UB_INT_PENDING_TBL_SA_L - UB_CFG1_CAP_INT_CAP,
	       ALL_VIRT, NO_WRITE);
	p_setd(perm, UB_INT_PENDING_TBL_SA_H - UB_CFG1_CAP_INT_CAP,
	       ALL_VIRT, NO_WRITE);
	p_setd(perm, UB_INT_ID - UB_CFG1_CAP_INT_CAP, ALL_VIRT, ALL_WRITE);
	p_setd(perm, UB_INT_MASK - UB_CFG1_CAP_INT_CAP, UB_INT_MASK_BIT,
	       UB_INT_MASK_BIT);

	p_setd(perm, UB_INT_EN - UB_CFG1_CAP_INT_CAP, UB_INT_EN_BIT,
	       UB_INT_EN_BIT);

	return 0;
}

static int init_ub_cfg1_cap_perm(struct perm_bits *perm)
{
	return init_ub_cfg1_int_cap_perm(&perm[UB_INT_TYPE2_CAP]);
}

static int vfio_ub_port_basic_read(struct vfio_ub_core_device *vdev, u64 pos,
				   int count, __le32 *val)
{
	count = vfio_ub_default_config_read(vdev, pos, count, val);

	return count;
}

static int vfio_ub_port_basic_write(struct vfio_ub_core_device *vdev, u64 pos,
				    int count, __le32 val)
{
	count = vfio_ub_default_config_write(vdev, pos, count, val);

	return count;
}

static int init_ub_port_basic_perm(struct perm_bits *perm)
{
	if (alloc_perm_bits(perm, UB_SLICE_SZ))
		return -ENOMEM;

	perm->readfn = vfio_ub_port_basic_read;
	perm->writefn = vfio_ub_port_basic_write;

	p_setd(perm, UB_CFG0_PORT_SLICE, ALL_VIRT, NO_WRITE);
	p_attr_setd(perm, UB_CFG0_PORT_SLICE, ENTITY0_EO, NO_ENTITYN_RO, FUNC_EXIST);

	init_ub_cfg_chunk_perms(perm, UB_CFG0_PORT_BITMAP,
				UB_CFG_BITMAP_SIZE / DWORD_SIZE,
				ALL_VIRT, NO_WRITE);
	init_ub_cfg_chunk_attrs(perm, UB_CFG0_PORT_BITMAP,
				UB_CFG_BITMAP_SIZE / DWORD_SIZE,
				ENTITY0_EO, NO_ENTITYN_RO, FUNC_EXIST);

	p_setd(perm, UB_PORT_INFO, ALL_VIRT, NO_WRITE);
	p_attr_setd(perm, UB_PORT_INFO, ENTITY0_EO, NO_ENTITYN_RO, FUNC_EXIST);

	init_ub_cfg_chunk_perms(perm, UB_NEIGHBOR_PORT_INFO,
				UB_UB_NEIGHBOR_PORT_INFO_SIZE / DWORD_SIZE,
				ALL_VIRT, NO_WRITE);
	init_ub_cfg_chunk_attrs(perm, UB_NEIGHBOR_PORT_INFO,
				UB_UB_NEIGHBOR_PORT_INFO_SIZE / DWORD_SIZE,
				ENTITY0_EO, NO_ENTITYN_RO, FUNC_EXIST);

	p_setd(perm, UB_PORT_NET_ADDR, UB_PORT_NET_ADDR_MASK, UB_PORT_NET_ADDR_MASK);
	p_attr_setd(perm, UB_PORT_NET_ADDR, ENTITY0_EO, NO_ENTITYN_RO, FUNC_EXIST);
	p_setd(perm, UB_PORT_RST, ALL_VIRT, UB_PORT_RST_BIT);
	p_attr_setd(perm, UB_PORT_RST, ENTITY0_EO, NO_ENTITYN_RO, FUNC_EXIST);

	return 0;
}

static u8 vfio_slice_supported[UB_CFG1_MAX_CAP + 1];
static void vfio_ub_init_slice_supported(void)
{
	vfio_slice_supported[UB_CFG0_BASIC_CAP] = 1;
	vfio_slice_supported[UB_CFG1_BASIC_CAP] = 1;
	vfio_slice_supported[UB_INT_TYPE2_CAP] = 1;
}

int __init vfio_ub_init_perm_bits(void)
{
	int ret;

	vfio_ub_init_slice_supported();

	ret = init_ub_cfg0_basic_perm(&cap_perms[UB_CFG0_BASIC_CAP]);
	ret |= init_ub_cfg0_cap_perm(cap_perms);

	ret |= init_ub_cfg1_basic_perm(&cap_perms[UB_CFG1_BASIC_CAP]);
	ret |= init_ub_cfg1_cap_perm(cap_perms);

	ret |= init_ub_port_basic_perm(&port_basic_perms);

	if (ret)
		vfio_ub_uninit_perm_bits();

	return ret;
}

void vfio_ub_uninit_perm_bits(void)
{
	free_perm_bits(&port_basic_perms);
	free_perm_bits(&cap_perms[UB_INT_TYPE2_CAP]);
	free_perm_bits(&cap_perms[UB_CFG1_BASIC_CAP]);
	free_perm_bits(&cap_perms[UB_CFG0_BASIC_CAP]);
}

static int vfio_ub_fill_slice_vconfig(struct vfio_ub_core_device *vdev,
				      int num, u32 pos, u32 size)
{
	__le32 *dwordp;
	u32 val = 0;
	int ret;
	u32 cap_id;
	u32 start = 0;

	cap_id = UB_CFG_POS_TO_CAP(pos);

	for (u32 i = 0; i < size; i += DWORD_SIZE) {
		ret = vfio_ub_user_config_read(vdev->uent, pos + i, &val, DWORD_SIZE);
		if (ret) {
			ub_warn(vdev->uent, "read cfgspace pos[%#x] failed, using default val 0\n",
				pos + i);
			val = 0;
		}
		dwordp = (__le32 *)(&vdev->vconfig.slice[num].cfg[i + start]);
		*dwordp = cpu_to_le32(val);
	}

	/* vfio-ub supports no port caps for userspace */
	if (cap_id >= UB_PORT0_BASIC_CAP)
		memset(&vdev->vconfig.slice[num].cfg[UB_CFG0_PORT_BITMAP], 0, UB_CFG_BITMAP_SIZE);

	return 0;
}

static struct ub_entity *ub_get_primary_ent(struct ub_entity *uent)
{
	if (uent->entity_idx == 0)
		return uent;

	return uent->is_mue ? uent->pue : uent->pue->pue;
}

static int vfio_ub_init_slice_config_info(struct vfio_ub_core_device *vdev,
					  u32 cap_id)
{
	struct vfio_ub_slice *pslice, *realloc_slice, *cur_slice;
	struct ub_entity *primary_dev;
	int used_size;
	u32 pos;
	int ret;
	u32 val;

	pos = UB_CFG_CAP_TO_POS(cap_id);
	if (cap_id != UB_PORT0_BASIC_CAP) {
		ret = ub_cfg_read_dword(vdev->uent, pos, &val);
	} else {
		primary_dev = ub_get_primary_ent(vdev->uent);
		ret = ub_cfg_read_dword(primary_dev, pos, &val);
	}

	if (ret) {
		ub_err(vdev->uent, "get cap[%#x] slice header failed, ret=%d\n", cap_id, ret);
		return ret;
	}
	used_size = (val >> SZ_4) << SZ_2;

	if (used_size == 0 || used_size > UB_SLICE_SZ) {
		ub_err(vdev->uent, "invalid cap_id[%#x] used_size[%d]\n", cap_id, used_size);
		return -EINVAL;
	}

	pslice = vdev->vconfig.slice;
	realloc_slice = (struct vfio_ub_slice *)krealloc(vdev->vconfig.slice,
				(vdev->vconfig.nums + 1) *
				sizeof(struct vfio_ub_slice), GFP_KERNEL);
	if (realloc_slice == NULL)
		return -ENOMEM;

	vdev->vconfig.slice = realloc_slice;

	cur_slice = vdev->vconfig.slice + vdev->vconfig.nums;
	cur_slice->cfg = kzalloc(used_size, GFP_KERNEL);
	if (cur_slice->cfg == NULL) {
		if (pslice == NULL) {
			kfree(vdev->vconfig.slice);
			vdev->vconfig.slice = NULL;
		}
		return -ENOMEM;
	}

	cur_slice->used_size = used_size;
	cur_slice->cap_id = cap_id;
	ret = vfio_ub_fill_slice_vconfig(vdev, vdev->vconfig.nums, pos, used_size);
	if (ret) {
		kfree(cur_slice->cfg);
		if (pslice == NULL) {
			kfree(vdev->vconfig.slice);
			vdev->vconfig.slice = NULL;
		}
		return ret;
	}

	if (cap_id <= UB_CFG1_MAX_CAP)
		vdev->vconfig.map[cap_id] = vdev->vconfig.nums;
	vdev->vconfig.nums++;

	return 0;
}

static int vfio_ub_find_cfg_cap(struct vfio_ub_core_device *vdev, u32 cap_id)
{
	int idx;

	for (idx = 0; idx < vdev->vconfig.nums; idx++) {
		if (vdev->vconfig.slice[idx].cap_id == cap_id)
			return idx;
	}

	return CFG_MAP_INVALID;
}

static void vfio_ub_uninit_slice_config_info(struct vfio_ub_core_device *vdev,
					     u32 cap_id)
{
	u32 tmp_cap;
	int num;

	if (cap_id <= UB_CFG1_MAX_CAP) {
		num = vdev->vconfig.map[cap_id];
		vdev->vconfig.map[cap_id] = CFG_MAP_INVALID;
	} else {
		num = vfio_ub_find_cfg_cap(vdev, cap_id);
	}

	if (num == CFG_MAP_INVALID)
		return;

	kfree(vdev->vconfig.slice[num].cfg);
	for (int i = num; i < vdev->vconfig.nums - 1; i++) {
		memcpy(vdev->vconfig.slice + i, vdev->vconfig.slice + i + 1,
		       sizeof(struct vfio_ub_slice));
		tmp_cap = vdev->vconfig.slice[i].cap_id;
		if (tmp_cap <= UB_CFG1_MAX_CAP)
			vdev->vconfig.map[tmp_cap] = i;
	}

	vdev->vconfig.nums--;
}

static int vfio_ub_init_cfg0_basic_info(struct vfio_ub_core_device *vdev)
{
	u8 *cfg0_bitmap_buf;
	int cfg0_basic_idx;
	int i, j, cap_idx = 0;
	int ret;

	ret = vfio_ub_init_slice_config_info(vdev, UB_CFG0_BASIC_CAP);
	if (ret)
		return ret;

	cfg0_basic_idx = vdev->vconfig.map[UB_CFG0_BASIC_CAP];
	cfg0_bitmap_buf = vdev->vconfig.slice[cfg0_basic_idx].cfg
				+ UB_CFG0_CAP_BITMAP;

	for (i = 0; i < UB_CFG_BITMAP_SIZE; i++) {
		for (j = 0; j < BITS_PER_BYTE; j++) {
			if (((cfg0_bitmap_buf[i] >> j) & 1) &&
			    vfio_slice_supported[cap_idx]) {
				vdev->vconfig.final_slice_supported[cap_idx] = 1;
			} else if (((cfg0_bitmap_buf[i] >> j) & 1) &&
				   vfio_slice_supported[cap_idx] == 0) {
				cfg0_bitmap_buf[i] = cfg0_bitmap_buf[i] &
						     ~(1 << j);
			}
			cap_idx++;
		}
	}

	return 0;
}

static void vfio_ub_uninit_cfg0_basic_info(struct vfio_ub_core_device *vdev)
{
	u32 cap_id;

	for (cap_id = 0; cap_id <= UB_CFG0_MAX_CAP; cap_id++) {
		if (vdev->vconfig.final_slice_supported[cap_id] == 1)
			vdev->vconfig.final_slice_supported[cap_id] = 0;
	}

	vfio_ub_uninit_slice_config_info(vdev, UB_CFG0_BASIC_CAP);
}

static int vfio_ub_init_cfg0_cap_info(struct vfio_ub_core_device *vdev)
{
	int cap_id;
	int ret;

	for (cap_id = 1; cap_id <= UB_CFG0_MAX_CAP; cap_id++) {
		if (vdev->vconfig.final_slice_supported[cap_id]) {
			ret = vfio_ub_init_slice_config_info(vdev, (u32)cap_id);
			if (ret)
				goto cfg0_cap_init_err;
		}
	}

	return 0;

cfg0_cap_init_err:
	for (cap_id = cap_id - 1; cap_id >= 1; cap_id--)
		vfio_ub_uninit_slice_config_info(vdev, cap_id);
	return ret;
}

static void vfio_ub_uninit_cfg0_cap_info(struct vfio_ub_core_device *vdev)
{
	u32 cap_id;

	for (cap_id = 1; cap_id <= UB_CFG0_MAX_CAP; cap_id++) {
		if (vdev->vconfig.final_slice_supported[cap_id])
			vfio_ub_uninit_slice_config_info(vdev, cap_id);
	}
}

static int vfio_ub_init_cfg1_basic_info(struct vfio_ub_core_device *vdev)
{
	u32 cap_idx = UB_CFG1_BASIC_CAP;
	u8 *cfg1_bitmap_buf;
	int cfg1_basic_idx;
	int i, j;
	int ret;

	ret = vfio_ub_init_slice_config_info(vdev, UB_CFG1_BASIC_CAP);
	if (ret)
		return ret;

	cfg1_basic_idx = vdev->vconfig.map[UB_CFG1_BASIC_CAP];
	cfg1_bitmap_buf = vdev->vconfig.slice[cfg1_basic_idx].cfg +
			  UB_CFG1_CAP_BITMAP - UB_CFG1_BASIC;

	for (i = 0; i < UB_CFG_BITMAP_SIZE; i++) {
		for (j = 0; j < BITS_PER_BYTE; j++) {
			if (((cfg1_bitmap_buf[i] >> j) & 1) &&
			    vfio_slice_supported[cap_idx]) {
				vdev->vconfig.final_slice_supported[cap_idx] = 1;
			} else if (((cfg1_bitmap_buf[i] >> j) & 1) &&
				   vfio_slice_supported[cap_idx] == 0) {
				cfg1_bitmap_buf[i] = cfg1_bitmap_buf[i] &
						     ~(1 << j);
			}
			cap_idx++;
		}
	}

	return 0;
}

static void vfio_ub_uninit_cfg1_basic_info(struct vfio_ub_core_device *vdev)
{
	u32 cap_id;

	for (cap_id = UB_DECODER_CAP; cap_id <= UB_CFG1_MAX_CAP; cap_id++) {
		if (vdev->vconfig.final_slice_supported[cap_id] == 1)
			vdev->vconfig.final_slice_supported[cap_id] = 0;
	}

	vfio_ub_uninit_slice_config_info(vdev, UB_CFG1_BASIC_CAP);
}

static int vfio_ub_init_cfg1_cap_info(struct vfio_ub_core_device *vdev)
{
	u32 cap_id;
	int ret;

	for (cap_id = UB_DECODER_CAP; cap_id <= UB_CFG1_MAX_CAP; cap_id++) {
		if (vdev->vconfig.final_slice_supported[cap_id]) {
			ret = vfio_ub_init_slice_config_info(vdev, cap_id);
			if (ret)
				goto cfg1_cap_init_err;
		}
	}

	return 0;

cfg1_cap_init_err:
	for (cap_id = cap_id - 1; cap_id >= UB_DECODER_CAP; cap_id--)
		vfio_ub_uninit_slice_config_info(vdev, cap_id);
	return ret;
}

static void vfio_ub_uninit_cfg1_cap_info(struct vfio_ub_core_device *vdev)
{
	u32 cap_id;

	for (cap_id = UB_DECODER_CAP; cap_id <= UB_CFG1_MAX_CAP; cap_id++) {
		if (vdev->vconfig.final_slice_supported[cap_id])
			vfio_ub_uninit_slice_config_info(vdev, cap_id);
	}
}

static void vfio_ub_init_port_cap_bitmap(struct vfio_ub_core_device *vdev, int idx)
{
	/* now we do not support any port cap */
	memset(vdev->vconfig.slice[idx].cfg + UB_CFG0_PORT_BITMAP,
	       0, UB_CFG_BITMAP_SIZE);
}

static int vfio_ub_init_port_basic_info(struct vfio_ub_core_device *vdev)
{
	int cfg0_basic_idx = vdev->vconfig.map[UB_CFG0_BASIC_CAP];
	u16 total_port_nums;
	__le16 *wordp;
	int ret;
	int idx;

	wordp = (__le16 *)(vdev->vconfig.slice[cfg0_basic_idx].cfg +
			   UB_TOTAL_NUMBER_PORT);
	total_port_nums = le16_to_cpu(*wordp);

	for (idx = 0; idx < total_port_nums; idx++) {
		ret = vfio_ub_init_slice_config_info(vdev, UB_PORT0_BASIC_CAP +
						     idx * UB_PORT_CAP_GAP);
		if (ret)
			goto port_basic_init_err;
		vfio_ub_init_port_cap_bitmap(vdev, vdev->vconfig.nums - 1);
	}

	return 0;

port_basic_init_err:
	for (idx = idx - 1; idx >= 0; idx--)
		vfio_ub_uninit_slice_config_info(vdev, UB_PORT0_BASIC_CAP +
						 idx * UB_PORT_CAP_GAP);
	return ret;
}

static void vfio_ub_uninit_port_basic_info(struct vfio_ub_core_device *vdev)
{
	int cfg0_basic_idx = vdev->vconfig.map[UB_CFG0_BASIC_CAP];
	u16 total_port_nums;
	u16 idx;
	__le16 *wordp;

	wordp = (__le16 *)(vdev->vconfig.slice[cfg0_basic_idx].cfg +
			  UB_TOTAL_NUMBER_PORT);
	total_port_nums = le16_to_cpu(*wordp);
	for (idx = 0; idx < total_port_nums; idx++)
		vfio_ub_uninit_slice_config_info(vdev, UB_PORT0_BASIC_CAP +
						 idx * UB_PORT_CAP_GAP);
}

int vfio_ub_config_init(struct vfio_ub_core_device *vdev)
{
	int ret;

	memset(vdev->vconfig.map, CFG_MAP_INVALID,
	       (UB_CFG1_MAX_CAP + 1) * sizeof(int));

	ret = vfio_ub_init_cfg0_basic_info(vdev);
	if (ret)
		return ret;

	ret = vfio_ub_init_cfg0_cap_info(vdev);
	if (ret)
		goto out_uninit_cfg0_basic;

	ret = vfio_ub_init_cfg1_basic_info(vdev);
	if (ret)
		goto out_uninit_cfg0_cap;

	ret = vfio_ub_init_cfg1_cap_info(vdev);
	if (ret)
		goto out_uninit_cfg1_basic;

	ret = vfio_ub_init_port_basic_info(vdev);
	if (ret)
		goto out_uninit_cfg1_cap;

	return 0;

out_uninit_cfg1_cap:
	vfio_ub_uninit_cfg1_cap_info(vdev);
out_uninit_cfg1_basic:
	vfio_ub_uninit_cfg1_basic_info(vdev);
out_uninit_cfg0_cap:
	vfio_ub_uninit_cfg0_cap_info(vdev);
out_uninit_cfg0_basic:
	vfio_ub_uninit_cfg0_basic_info(vdev);

	memset(vdev->vconfig.map, CFG_MAP_INVALID, (UB_CFG1_MAX_CAP + 1) * sizeof(int));
	kfree(vdev->vconfig.slice);
	vdev->vconfig.slice = NULL;
	vdev->vconfig.nums = 0;
	return ret;
}

void vfio_ub_config_uninit(struct vfio_ub_core_device *vdev)
{
	if (vdev->vconfig.slice == NULL)
		return;

	vfio_ub_uninit_port_basic_info(vdev);
	vfio_ub_uninit_cfg1_cap_info(vdev);
	vfio_ub_uninit_cfg1_basic_info(vdev);
	vfio_ub_uninit_cfg0_cap_info(vdev);
	vfio_ub_uninit_cfg0_basic_info(vdev);

	memset(vdev->vconfig.map, CFG_MAP_INVALID, (UB_CFG1_MAX_CAP + 1) * sizeof(int));
	kfree(vdev->vconfig.slice);
	vdev->vconfig.slice = NULL;
	vdev->vconfig.nums = 0;
}

static int vfio_ub_find_valid_cap(struct vfio_ub_core_device *vdev, u32 cap_id)
{
	int i;

	if (cap_id <= UB_CFG1_MAX_CAP) {
		if (vdev->vconfig.map[cap_id] != CFG_MAP_INVALID)
			return 0;
	} else {
		for (i = 0; i < vdev->vconfig.nums; i++) {
			if (vdev->vconfig.slice[i].cap_id == cap_id)
				return 0;
		}
	}

	return -ENOENT;
}

static int vfio_ub_find_cap_used_size(struct vfio_ub_core_device *vdev, u32 cap_id)
{
	int i;
	int num;

	if (cap_id <= UB_CFG1_MAX_CAP) {
		num = vdev->vconfig.map[cap_id];
		return vdev->vconfig.slice[num].used_size;
	}

	for (i = 0; i < vdev->vconfig.nums; i++) {
		if (vdev->vconfig.slice[i].cap_id == cap_id)
			return vdev->vconfig.slice[i].used_size;
	}

	return -ENOENT;
}

static ssize_t vfio_ub_config_rw_used_zone(struct vfio_ub_core_device *vdev,
					   char __user *buf, size_t count,
					   loff_t *ppos, bool iswrite)
{
	size_t cap_start_pos;
	struct perm_bits *perm;
	size_t left;
	u32 cap_id;
	__le32 val = 0;
	int used_size;
	int ret;

	cap_id = UB_CFG_POS_TO_CAP(*ppos);
	cap_start_pos = UB_CFG_CAP_TO_POS(cap_id);
	used_size = vfio_ub_find_cap_used_size(vdev, cap_id);

	left = cap_start_pos + used_size - *ppos;

	perm = vfio_ub_find_cap_perm(cap_id);

	count = min(count, left);
	if (count >= DWORD_SIZE && !(*ppos % DWORD_SIZE))
		count = DWORD_SIZE;
	else if (count >= WORD_SIZE && !(*ppos % WORD_SIZE))
		count = WORD_SIZE;
	else
		count = BYTE_SIZE;

	ret = count;

	if (iswrite) {
		if (!perm->writefn)
			return ret;

		if (copy_from_user(&val, buf, count))
			return -EFAULT;

		ret = perm->writefn(vdev, *ppos, count, val);
	} else {
		if (perm->readfn) {
			ret = perm->readfn(vdev, *ppos, count, &val);
			if (ret < 0)
				return ret;
		}

		if (copy_to_user(buf, &val, count))
			return -EFAULT;
	}

	return ret;
}

static ssize_t vfio_ub_config_rw_unused_zone(struct vfio_ub_core_device *vdev,
					     char __user *buf, size_t count,
					     loff_t *ppos, bool iswrite)
{
	size_t cap_start_pos;
	size_t left;
	u32 cap_id;

	cap_id = UB_CFG_POS_TO_CAP(*ppos);
	cap_start_pos = UB_CFG_CAP_TO_POS(cap_id);
	left = cap_start_pos + UB_SLICE_SZ - *ppos;

	count = min(count, left);
	if (iswrite)
		return count;

	/* read unused zone just return zero */
	if (copy_to_user(buf, zero_array, count))
		return -EFAULT;

	return count;
}

static ssize_t vfio_ub_config_do_rw(struct vfio_ub_core_device *vdev,
				    char __user *buf, size_t count,
				    loff_t *ppos, bool iswrite)
{
	u32 cap_id;
	ssize_t ret;
	size_t cap_start_pos;
	int used_size;

	if (*ppos < 0 || *ppos >= UB_ROUTE_TABLE_SLICE_START ||
	    *ppos + count > UB_ROUTE_TABLE_SLICE_START ||
	    count > UB_SLICE_SZ)
		return -EFAULT;

	cap_id = UB_CFG_POS_TO_CAP(*ppos);

	ret = vfio_ub_find_valid_cap(vdev, cap_id);
	if (ret < 0) {
		ret = vfio_ub_config_rw_unused_zone(vdev, buf,
						      count, ppos, iswrite);
	} else {
		cap_start_pos = UB_CFG_CAP_TO_POS(cap_id);
		used_size = vfio_ub_find_cap_used_size(vdev, cap_id);
		if (used_size < 0)
			return -EINVAL;

		if (*ppos < cap_start_pos + used_size) {
			ret = vfio_ub_config_rw_used_zone(vdev, buf,
							  count, ppos, iswrite);
		} else {
			ret = vfio_ub_config_rw_unused_zone(vdev, buf,
							    count, ppos, iswrite);
		}
	}

	return ret;
}

ssize_t vfio_ub_config_rw(struct vfio_ub_core_device *vdev, char __user *buf,
			  size_t count, loff_t *ppos, bool iswrite)
{
	size_t done = 0;
	int ret = 0;
	loff_t pos = *ppos;

	pos &= VFIO_UB_OFFSET_MASK;

	while (count) {
		ret = vfio_ub_config_do_rw(vdev, buf, count, &pos, iswrite);
		if (ret < 0)
			return ret;

		buf += ret;
		pos += ret;
		count -= ret;
		done += ret;
	}

	*ppos += done;

	return done;
}
