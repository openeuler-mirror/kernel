// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_resource.h"

static u16 pfvfid_to_vsi_id(void *p, int pfid, int vfid, u16 type)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)p;
	struct nbl_vsi_info *vsi_info = NBL_RES_MGT_TO_VSI_INFO(res_mgt);
	enum nbl_vsi_serv_type dst_type = NBL_VSI_SERV_PF_DATA_TYPE;
	u16 vsi_id;
	int diff;

	diff = nbl_common_pf_id_subtraction_mgtpf_id(NBL_RES_MGT_TO_COMMON(res_mgt), pfid);
	if (vfid == U32_MAX) {
		if (diff < vsi_info->num) {
			nbl_res_pf_dev_vsi_type_to_hw_vsi_type(type, &dst_type);
			vsi_id = vsi_info->serv_info[diff][dst_type].base_id;
		} else {
			vsi_id = vsi_info->serv_info[0][NBL_VSI_SERV_PF_EXTRA_TYPE].base_id
				+ (diff - vsi_info->num);
		}
	} else {
		vsi_id = vsi_info->serv_info[diff][NBL_VSI_SERV_VF_DATA_TYPE].base_id + vfid;
	}

	return vsi_id;
}

static u16 func_id_to_vsi_id(void *p, u16 func_id, u16 type)
{
	int pfid = U32_MAX;
	int vfid = U32_MAX;

	nbl_res_func_id_to_pfvfid(p, func_id, &pfid, &vfid);

	return nbl_res_pfvfid_to_vsi_id(p, pfid, vfid, type);
}

static u16 vsi_id_to_func_id(void *p, u16 vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)p;
	struct nbl_vsi_info *vsi_info = NBL_RES_MGT_TO_VSI_INFO(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_sriov_info *sriov_info;
	int i, j;
	u16 func_id = U16_MAX;
	bool vsi_find = false;

	for (i = 0; i < vsi_info->num; i++) {
		for (j = 0; j < NBL_VSI_SERV_MAX_TYPE; j++) {
			if (vsi_id >= vsi_info->serv_info[i][j].base_id &&
			    (vsi_id < vsi_info->serv_info[i][j].base_id
			     + vsi_info->serv_info[i][j].num)) {
				vsi_find = true;
				break;
			}
		}

		if (vsi_find)
			break;
	}

	if (vsi_find) {
		/* if pf_id < eth_num */
		if (j >= NBL_VSI_SERV_PF_DATA_TYPE && j <= NBL_VSI_SERV_PF_USER_TYPE)
			func_id = i + NBL_COMMON_TO_MGT_PF(common);
		/* if vf */
		else if (j == NBL_VSI_SERV_VF_DATA_TYPE) {
			sriov_info = NBL_RES_MGT_TO_SRIOV_INFO(res_mgt) + i;
			func_id = sriov_info->start_vf_func_id
			+ (vsi_id - vsi_info->serv_info[i][NBL_VSI_SERV_VF_DATA_TYPE].base_id);
		/* if extra pf */
		} else {
			func_id = vsi_info->num
			+ (vsi_id - vsi_info->serv_info[i][NBL_VSI_SERV_PF_EXTRA_TYPE].base_id);
		}
	}

	return func_id;
}

static int vsi_id_to_pf_id(void *p, u16 vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)p;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_vsi_info *vsi_info = NBL_RES_MGT_TO_VSI_INFO(res_mgt);
	int i, j;
	u32 pf_id = U32_MAX;
	bool vsi_find = false;

	for (i = 0; i < vsi_info->num; i++) {
		for (j = 0; j < NBL_VSI_SERV_MAX_TYPE; j++)
			if (vsi_id >= vsi_info->serv_info[i][j].base_id &&
			    (vsi_id < vsi_info->serv_info[i][j].base_id
			     + vsi_info->serv_info[i][j].num)){
				vsi_find = true;
				break;
			}

		if (vsi_find)
			break;
	}

	if (vsi_find) {
		/* if pf_id < eth_num */
		if (j >= NBL_VSI_SERV_PF_DATA_TYPE && j <= NBL_VSI_SERV_VF_DATA_TYPE)
			pf_id = i + NBL_COMMON_TO_MGT_PF(common);
		/* if extra pf */
		else if (j == NBL_VSI_SERV_PF_EXTRA_TYPE)
			pf_id = vsi_info->num
			+ (vsi_id - vsi_info->serv_info[i][NBL_VSI_SERV_PF_EXTRA_TYPE].base_id);
	}

	return pf_id;
}

static int func_id_to_pfvfid(void *p, u16 func_id, int *pfid, int *vfid)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)p;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_sriov_info *sriov_info;
	int diff;
	int pf_id_tmp;

	if (func_id < NBL_RES_MGT_TO_PF_NUM(res_mgt)) {
		*pfid = func_id;
		*vfid = U32_MAX;
		return 0;
	}

	for (pf_id_tmp = 0; pf_id_tmp <  NBL_RES_MGT_TO_PF_NUM(res_mgt); pf_id_tmp++) {
		diff = nbl_common_pf_id_subtraction_mgtpf_id(common, pf_id_tmp);
		sriov_info = NBL_RES_MGT_TO_SRIOV_INFO(res_mgt) + diff;
		if (func_id >= sriov_info->start_vf_func_id &&
		    func_id < sriov_info->start_vf_func_id + sriov_info->num_vfs) {
			*pfid = pf_id_tmp;
			*vfid = func_id - sriov_info->start_vf_func_id;
			return 0;
		}
	}

	return U32_MAX;
}

static int func_id_to_bdf(void *p, u16 func_id, u8 *bus, u8 *dev, u8 *function)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)p;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_sriov_info *sriov_info;
	int pfid = U32_MAX;
	int vfid = U32_MAX;
	int diff;
	u8 pf_bus, pf_devfn, devfn;

	if (nbl_res_func_id_to_pfvfid(p, func_id, &pfid, &vfid))
		return U32_MAX;

	diff = nbl_common_pf_id_subtraction_mgtpf_id(common, pfid);
	sriov_info = NBL_RES_MGT_TO_SRIOV_INFO(res_mgt) + diff;
	pf_bus = PCI_BUS_NUM(sriov_info->bdf);
	pf_devfn = sriov_info->bdf & 0xff;

	if (vfid != U32_MAX) {
		*bus = pf_bus + ((pf_devfn + sriov_info->offset + sriov_info->stride * vfid) >> 8);
		devfn = (pf_devfn + sriov_info->offset + sriov_info->stride * vfid) & 0xff;
	} else {
		*bus = pf_bus;
		devfn = pf_devfn;
	}

	*dev = PCI_SLOT(devfn);
	*function = PCI_FUNC(devfn);
	return 0;
}

static u16 pfvfid_to_func_id(void *p, int pfid, int vfid)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)p;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_sriov_info *sriov_info;
	int diff;

	if (vfid == U32_MAX)
		return pfid;

	diff = nbl_common_pf_id_subtraction_mgtpf_id(common, pfid);
	sriov_info = NBL_RES_MGT_TO_SRIOV_INFO(res_mgt) + diff;

	return sriov_info->start_vf_func_id + vfid;
}

static u64 get_func_bar_base_addr(void *p, u16 func_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)p;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_sriov_info *sriov_info;
	u64 base_addr = 0;
	int pfid = U32_MAX;
	int vfid = U32_MAX;
	int diff;

	if (nbl_res_func_id_to_pfvfid(p, func_id, &pfid, &vfid))
		return 0;

	diff = nbl_common_pf_id_subtraction_mgtpf_id(common, pfid);
	sriov_info = NBL_RES_MGT_TO_SRIOV_INFO(res_mgt) + diff;
	if (!sriov_info->pf_bar_start) {
		nbl_err(common, NBL_DEBUG_QUEUE,
			"Try to get bar addr for func %d, but PF_%d sriov not init",
			func_id, pfid);
		return 0;
	}

	if (vfid == U32_MAX)
		base_addr = sriov_info->pf_bar_start;
	else
		base_addr = sriov_info->vf_bar_start + sriov_info->vf_bar_len * vfid;

	nbl_info(common, NBL_DEBUG_QUEUE, "pfid %d vfid %d base_addr %llx\n",
		 pfid, vfid, base_addr);
	return base_addr;
}

static u8 vsi_id_to_eth_id(void *p, u16 vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)p;
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);

	if (eth_info)
		return eth_info->eth_id[nbl_res_vsi_id_to_pf_id(res_mgt, vsi_id)];
	else
		return 0;
}

static u8 eth_id_to_pf_id(void *p, u8 eth_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)p;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	int i;
	u8 pf_id_offset = 0;

	for_each_set_bit(i, eth_info->eth_bitmap, NBL_MAX_ETHERNET) {
		if (i == eth_id)
			break;
		pf_id_offset++;
	}

	return pf_id_offset + NBL_COMMON_TO_MGT_PF(common);
}

int nbl_res_func_id_to_pfvfid(struct nbl_resource_mgt *res_mgt, u16 func_id, int *pfid, int *vfid)
{
	if (!res_mgt->common_ops.func_id_to_pfvfid)
		return func_id_to_pfvfid(res_mgt, func_id, pfid, vfid);

	return res_mgt->common_ops.func_id_to_pfvfid(res_mgt, func_id, pfid, vfid);
}

u16 nbl_res_pfvfid_to_func_id(struct nbl_resource_mgt *res_mgt, int pfid, int vfid)
{
	if (!res_mgt->common_ops.pfvfid_to_func_id)
		return pfvfid_to_func_id(res_mgt, pfid, vfid);

	return res_mgt->common_ops.pfvfid_to_func_id(res_mgt, pfid, vfid);
}

u16 nbl_res_pfvfid_to_vsi_id(struct nbl_resource_mgt *res_mgt, int pfid, int vfid, u16 type)
{
	if (!res_mgt->common_ops.pfvfid_to_vsi_id)
		return pfvfid_to_vsi_id(res_mgt, pfid, vfid, type);

	return res_mgt->common_ops.pfvfid_to_vsi_id(res_mgt, pfid, vfid, type);
}

int nbl_res_func_id_to_bdf(struct nbl_resource_mgt *res_mgt, u16 func_id, u8 *bus,
			   u8 *dev, u8 *function)
{
	if (!res_mgt->common_ops.func_id_to_bdf)
		return func_id_to_bdf(res_mgt, func_id, bus, dev, function);

	return res_mgt->common_ops.func_id_to_bdf(res_mgt, func_id, bus, dev, function);
}

u16 nbl_res_vsi_id_to_func_id(struct nbl_resource_mgt *res_mgt, u16 vsi_id)
{
	if (!res_mgt->common_ops.vsi_id_to_func_id)
		return  vsi_id_to_func_id(res_mgt, vsi_id);

	return res_mgt->common_ops.vsi_id_to_func_id(res_mgt, vsi_id);
}

int nbl_res_vsi_id_to_pf_id(struct nbl_resource_mgt *res_mgt, u16 vsi_id)
{
	if (!res_mgt->common_ops.vsi_id_to_pf_id)
		return vsi_id_to_pf_id(res_mgt, vsi_id);

	return res_mgt->common_ops.vsi_id_to_pf_id(res_mgt, vsi_id);
}

u16 nbl_res_func_id_to_vsi_id(struct nbl_resource_mgt *res_mgt, u16 func_id, u16 type)
{
	if (!res_mgt->common_ops.func_id_to_vsi_id)
		return func_id_to_vsi_id(res_mgt, func_id, type);

	return res_mgt->common_ops.func_id_to_vsi_id(res_mgt, func_id, type);
}

u64 nbl_res_get_func_bar_base_addr(struct nbl_resource_mgt *res_mgt, u16 func_id)
{
	if (!res_mgt->common_ops.get_func_bar_base_addr)
		return get_func_bar_base_addr(res_mgt, func_id);

	return res_mgt->common_ops.get_func_bar_base_addr(res_mgt, func_id);
}

u16 nbl_res_get_particular_queue_id(struct nbl_resource_mgt *res_mgt, u16 vsi_id)
{
	return res_mgt->common_ops.get_particular_queue_id(res_mgt, vsi_id);
}

u8 nbl_res_vsi_id_to_eth_id(struct nbl_resource_mgt *res_mgt, u16 vsi_id)
{
	if (!res_mgt->common_ops.vsi_id_to_eth_id)
		return vsi_id_to_eth_id(res_mgt, vsi_id);

	return res_mgt->common_ops.vsi_id_to_eth_id(res_mgt, vsi_id);
}

u8 nbl_res_eth_id_to_pf_id(struct nbl_resource_mgt *res_mgt, u8 eth_id)
{
	if (!res_mgt->common_ops.eth_id_to_pf_id)
		return eth_id_to_pf_id(res_mgt, eth_id);

	return res_mgt->common_ops.eth_id_to_pf_id(res_mgt, eth_id);
}

bool nbl_res_get_flex_capability(void *priv, enum nbl_flex_cap_type cap_type)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	return test_bit(cap_type, res_mgt->flex_capability);
}

bool nbl_res_get_fix_capability(void *priv, enum nbl_fix_cap_type cap_type)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	return test_bit(cap_type, res_mgt->fix_capability);
}

void nbl_res_set_flex_capability(struct nbl_resource_mgt *res_mgt, enum nbl_flex_cap_type cap_type)
{
	set_bit(cap_type, res_mgt->flex_capability);
}

void nbl_res_set_fix_capability(struct nbl_resource_mgt *res_mgt, enum nbl_fix_cap_type cap_type)
{
	set_bit(cap_type, res_mgt->fix_capability);
}

void nbl_res_pf_dev_vsi_type_to_hw_vsi_type(u16 src_type, enum nbl_vsi_serv_type *dst_type)
{
	if (src_type == NBL_VSI_DATA)
		*dst_type = NBL_VSI_SERV_PF_DATA_TYPE;
	else if (src_type == NBL_VSI_USER)
		*dst_type = NBL_VSI_SERV_PF_USER_TYPE;
	else if (src_type == NBL_VSI_CTRL)
		*dst_type = NBL_VSI_SERV_PF_CTLR_TYPE;
}

bool nbl_res_vf_is_active(void *priv, u16 func_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *resource_info = res_mgt->resource_info;

	return test_bit(func_id, resource_info->func_bitmap);
}
