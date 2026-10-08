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
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	enum nbl_vsi_serv_type dst_type = NBL_VSI_SERV_PF_DATA_TYPE;
	u16 vsi_id = U16_MAX;
	int diff;

	diff = nbl_common_pf_id_subtraction_mgtpf_id(NBL_RES_MGT_TO_COMMON(res_mgt), pfid);
	/* some mailbox msg vfid is u16*/
	if (vfid == U32_MAX || vfid == U16_MAX) {
		if (diff < vsi_info->num) {
			nbl_res_pf_dev_vsi_type_to_hw_vsi_type(type, &dst_type);
			if (vsi_info->serv_info[diff][dst_type].num == 0)
				return U16_MAX;

			vsi_id = vsi_info->serv_info[diff][dst_type].base_id;
		} else {
			vsi_id = vsi_info->serv_info[0][NBL_VSI_SERV_PF_EXTRA_TYPE].base_id
				+ (diff - eth_info->eth_num);
		}
	} else {
		vsi_id = vsi_info->serv_info[diff][NBL_VSI_SERV_VF_DATA_TYPE].base_id + vfid;
	}

	if (vsi_id == U16_MAX)
		pr_err("convert pfid-vfid %d-%d to vsi_id(%d) failed!\n", pfid, vfid, type);

	return vsi_id;
}

static u16 func_id_to_vsi_id(void *p, u16 func_id, u16 type)
{
	int pfid = U32_MAX;
	int vfid = U32_MAX;
	int ret;

	ret = nbl_res_func_id_to_pfvfid(p, func_id, &pfid, &vfid);
	if (ret != U32_MAX)
		return nbl_res_pfvfid_to_vsi_id(p, pfid, vfid, type);
	return U16_MAX;
}

static u16 vsi_id_to_func_id(void *p, u16 vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)p;
	struct nbl_vsi_info *vsi_info = NBL_RES_MGT_TO_VSI_INFO(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
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
		if (j >= NBL_VSI_SERV_PF_DATA_TYPE && j <= NBL_VSI_SERV_PF_XDP_TYPE)
			func_id = i + NBL_COMMON_TO_MGT_PF(common);
		/* if vf */
		else if (j == NBL_VSI_SERV_VF_DATA_TYPE) {
			sriov_info = NBL_RES_MGT_TO_SRIOV_INFO(res_mgt) + i;
			func_id = sriov_info->start_vf_func_id
			+ (vsi_id - vsi_info->serv_info[i][NBL_VSI_SERV_VF_DATA_TYPE].base_id);
		/* if extra pf */
		} else {
			func_id = eth_info->eth_num
			+ (vsi_id - vsi_info->serv_info[i][NBL_VSI_SERV_PF_EXTRA_TYPE].base_id);
		}
	}

	if (func_id == U16_MAX)
		pr_err("convert vsi_id %d to func_id failed!\n", vsi_id);

	return func_id;
}

static int vsi_id_to_pf_id(void *p, u16 vsi_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)p;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_vsi_info *vsi_info = NBL_RES_MGT_TO_VSI_INFO(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
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
			pf_id = eth_info->eth_num
			+ (vsi_id - vsi_info->serv_info[i][NBL_VSI_SERV_PF_EXTRA_TYPE].base_id);
	}

	if (pf_id == U32_MAX)
		pr_err("convert vsi_id %d to pf_id failed!\n", vsi_id);

	return pf_id;
}

static int func_id_to_pfvfid(void *p, u16 func_id, int *pfid, int *vfid)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)p;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_sriov_info *sriov_info;
	unsigned long *owned_pf_bitmap = NBL_RES_MGT_TO_OWNED_PF_BITMAP(res_mgt);
	int diff;
	int pf_id_tmp;

	if (func_id < NBL_RES_MGT_TO_PF_NUM(res_mgt)) {
		*pfid = func_id;
		*vfid = U32_MAX;
		return 0;
	}

	for_each_set_bit(pf_id_tmp, owned_pf_bitmap, NBL_RES_MGT_TO_PF_NUM(res_mgt)) {
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

static u8 pf_id_to_eth_id(void *p, u16 pf_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)p;
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);

	if (pf_id >= NBL_MAX_PF)
		return 0;

	return eth_info->eth_id[pf_id];
}

static u8 eth_id_to_lag_id(void *p, u8 eth_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)p;
	struct nbl_eth_bond_info *eth_bond_info = NBL_RES_MGT_TO_ETH_BOND_INFO(res_mgt);
	int i, j;

	if (!eth_bond_info)
		return U8_MAX;

	for (i = 0; i < NBL_LAG_MAX_NUM; i++)
		for (j = 0; j < eth_bond_info->entry[i].lag_num &&
		     NBL_ETH_BOND_VALID_PORT(j); j++)
			if (eth_bond_info->entry[i].eth_id[j] == eth_id)
				return i;

	return U8_MAX;
}

static u16 vfid_to_vsi_id(void *p, u16 vf_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)p;
	u16 func_id = vf_id + NBL_MAX_PF;

	return nbl_res_func_id_to_vsi_id(res_mgt, func_id, NBL_VSI_DATA);
}

static bool check_func_active_by_queue(void *p, u16 func_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)p;
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);

	return queue_mgt->queue_info[func_id].txrx_queues ? true : false;
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

u8 nbl_res_pf_id_to_eth_id(struct nbl_resource_mgt *res_mgt, u16 pf_id)
{
	if (!res_mgt->common_ops.pf_id_to_eth_id)
		return pf_id_to_eth_id(res_mgt, pf_id);

	return res_mgt->common_ops.pf_id_to_eth_id(res_mgt, pf_id);
}

u8 nbl_res_eth_id_to_lag_id(struct nbl_resource_mgt *res_mgt, u8 eth_id)
{
	if (!res_mgt->common_ops.eth_id_to_lag_id)
		return eth_id_to_lag_id(res_mgt, eth_id);

	return res_mgt->common_ops.eth_id_to_lag_id(res_mgt, eth_id);
}

u16 nbl_res_vfid_to_vsi_id(struct nbl_resource_mgt *res_mgt, u16 vf_id)
{
	if (!res_mgt->common_ops.vfid_to_vsi_id)
		return vfid_to_vsi_id(res_mgt, vf_id);

	return res_mgt->common_ops.vfid_to_vsi_id(res_mgt, vf_id);
}

bool nbl_res_check_func_active_by_queue(struct nbl_resource_mgt *res_mgt, u16 func_id)
{
	if (!res_mgt->common_ops.check_func_active_by_queue)
		return check_func_active_by_queue(res_mgt, func_id);

	return res_mgt->common_ops.check_func_active_by_queue(res_mgt, func_id);
}

static int nbl_res_get_peer_lag_member(struct nbl_resource_mgt *res_mgt, u8 eth_id, u8 *peer_eth_id)
{
	struct nbl_eth_bond_info *eth_bond_info = NBL_RES_MGT_TO_ETH_BOND_INFO(res_mgt);
	int i, j;
	int lag_id = -1;

	if (!eth_bond_info)
		return -1;

	for (i = 0; i < NBL_LAG_MAX_NUM; i++)
		for (j = 0; j < eth_bond_info->entry[i].lag_num && NBL_ETH_BOND_VALID_PORT(j); j++)
			if (eth_bond_info->entry[i].eth_id[j] == eth_id) {
				lag_id = i;
				goto get_lagid_success;
			}

	return -1;

get_lagid_success:
	if (eth_bond_info->entry[lag_id].lag_num != 2)
		return -1;

	for (i = 0; i < eth_bond_info->entry[lag_id].lag_num; i++)
		if (eth_bond_info->entry[lag_id].eth_id[i] != eth_id) {
			*peer_eth_id = eth_bond_info->entry[lag_id].eth_id[i];
			return 0;
		}

	return -1;
}

bool nbl_res_get_flex_capability(void *priv, enum nbl_flex_cap_type *cap_type)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	return test_bit(*cap_type, res_mgt->flex_capability);
}

bool nbl_res_get_fix_capability(void *priv, enum nbl_fix_cap_type *cap_type)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	return test_bit(*cap_type, res_mgt->fix_capability);
}

void nbl_res_set_flex_capability(struct nbl_resource_mgt *res_mgt, enum nbl_flex_cap_type cap_type)
{
	set_bit(cap_type, res_mgt->flex_capability);
}

void nbl_res_set_fix_capability(struct nbl_resource_mgt *res_mgt, enum nbl_fix_cap_type cap_type)
{
	set_bit(cap_type, res_mgt->fix_capability);
}

void nbl_res_dump_func_info(void *priv, struct seq_file *m)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_interrupt_mgt *intr_mgt = NBL_RES_MGT_TO_INTR_MGT(res_mgt);
	struct nbl_queue_info *queue_info;
	struct nbl_func_interrupt_resource_mng *func_intr_res;
	u16 func_id, vsi_id;
	u8 bus = 0;
	u8 devid = 0;
	u8 function = 0;
	int j;

	for (func_id = 0; func_id < NBL_MAX_FUNC; func_id++) {
		queue_info = &queue_mgt->queue_info[func_id];
		func_intr_res = &intr_mgt->func_intr_res[func_id];

		if (queue_info->num_txrx_queues) {
			nbl_res_func_id_to_bdf(res_mgt, func_id, &bus, &devid, &function);
			vsi_id = nbl_res_func_id_to_vsi_id(res_mgt, func_id, NBL_VSI_DATA);
			seq_printf(m, "BDF %02x:%02x.%x, func_id %d, vsi_id %d, ",
				   bus, devid, function, func_id, vsi_id);
			if (func_intr_res->num_interrupts) {
				seq_printf(m, "num_interrupts %d, (",
					   func_intr_res->num_interrupts);
				for (j = 0; j < (func_intr_res->num_interrupts - 1); j++)
					seq_printf(m, "%d,", func_intr_res->interrupts[j]);
				seq_printf(m, "%d), ", func_intr_res->interrupts[j]);
			}

			if (test_bit(func_id, resource_info->rdma_info.func_cap))
				seq_puts(m, "rdma cap set, ");
			else
				seq_puts(m, "rdma cap not set, ");

			seq_printf(m, "total queue nums %d, data VSI queue_num %d queue_offset %d curr_qps %d, (",
				   queue_info->num_txrx_queues,
				   queue_info->vsi_info[NBL_VSI_DATA].queue_num,
				   queue_info->vsi_info[NBL_VSI_DATA].queue_offset,
				   queue_info->vsi_info[NBL_VSI_DATA].curr_qps);
			for (j = 0; j < (queue_info->num_txrx_queues - 1); j++)
				seq_printf(m, "%d,", queue_info->txrx_queues[j]);
			seq_printf(m, "%d)\n", queue_info->txrx_queues[j]);
		}
	}
}

void nbl_res_pf_dev_vsi_type_to_hw_vsi_type(u16 src_type, enum nbl_vsi_serv_type *dst_type)
{
	if (src_type == NBL_VSI_DATA)
		*dst_type = NBL_VSI_SERV_PF_DATA_TYPE;
	else if (src_type == NBL_VSI_USER)
		*dst_type = NBL_VSI_SERV_PF_USER_TYPE;
	else if (src_type == NBL_VSI_CTRL)
		*dst_type = NBL_VSI_SERV_PF_CTLR_TYPE;
	else if (src_type == NBL_VSI_XDP)
		*dst_type = NBL_VSI_SERV_PF_XDP_TYPE;
}

int nbl_res_get_rep_idx(struct nbl_eswitch_info *eswitch_info, u16 rep_vsi_id)
{
	u32 rep_idx = U32_MAX;

	if (rep_vsi_id >= eswitch_info->vf_base_vsi_id)
		rep_idx = rep_vsi_id - eswitch_info->vf_base_vsi_id;

	return rep_idx;
}

bool nbl_res_vf_is_active(void *priv, u16 func_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *resource_info = res_mgt->resource_info;

	return test_bit(func_id, resource_info->func_bitmap);
}

void nbl_res_set_hw_status(void *priv, enum nbl_hw_status hw_status)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->set_hw_status(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), hw_status);
}

void nbl_res_check_hw_status(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->check_hw_status(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
}

enum nbl_hw_status nbl_res_get_hw_status(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->get_hw_status(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
}

int nbl_res_get_pf_vf_num(void *priv, u16 pf_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_sriov_info *sriov_info;

	if (pf_id >= NBL_RES_MGT_TO_PF_NUM(res_mgt))
		return -1;

	sriov_info = NBL_RES_MGT_TO_SRIOV_INFO(res_mgt) + pf_id;
	if (!sriov_info->num_vfs)
		return -1;

	return sriov_info->num_vfs;
}

void nbl_res_setup_rdma_id(void *priv, struct ida *adev_ida, struct ida *grc_adev_ida,
			   struct mutex *lock)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_rdma_info *rdma_info = &resource_info->rdma_info;

	rdma_info->adev_ida = adev_ida;
	rdma_info->grc_adev_ida = grc_adev_ida;
	rdma_info->lock = lock;
}

void nbl_res_remove_rdma_id(void *priv, struct ida *adev_ida, struct ida *grc_adev_ida,
			    struct mutex *lock)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_rdma_info *rdma_info = &resource_info->rdma_info;
	u16 func_id;

	/**
	 * Only free idx when ctlr_dev driver remove, to avoid adev idx change when pf
	 * enable bond. The adev chane: delele adev, and add bond adev. So we will no
	 * delete adev.
	 */
	mutex_lock(rdma_info->lock);
	for_each_set_bit(func_id, rdma_info->func_cap, NBL_MAX_FUNC) {
		if (rdma_info->rdma_id_info[func_id].id_vaild)
			ida_free(rdma_info->adev_ida, rdma_info->rdma_id_info[func_id].id);
		if (rdma_info->rdma_id_info[func_id].grc_id_vaild)
			ida_free(rdma_info->grc_adev_ida, rdma_info->rdma_id_info[func_id].grc_id);
	}
	mutex_unlock(rdma_info->lock);
}

int nbl_res_register_rdma(void *priv, u16 *vsi_id, struct nbl_rdma_register_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_rdma_info *rdma_info = &resource_info->rdma_info;
	int pfid, vfid;
	int id;
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, *vsi_id);

	param->has_rdma = false;
	param->mem_type = NBL_RDMA_MEM_TYPE_MAX;

	if (!test_bit(func_id, rdma_info->func_cap))
		return 0;

	nbl_res_func_id_to_pfvfid(res_mgt, func_id, &pfid, &vfid);
	param->intr_num = (vfid == U32_MAX) ? rdma_info->pf_msix_num : rdma_info->vf_msix_num;
	mutex_lock(rdma_info->lock);
	if (!rdma_info->rdma_id_info[func_id].id_vaild) {
		id = ida_alloc(rdma_info->adev_ida, GFP_KERNEL);
		if (id < 0) {
			mutex_unlock(rdma_info->lock);
			return id;
		}
		rdma_info->rdma_id_info[func_id].id = id;
		rdma_info->rdma_id_info[func_id].id_vaild = true;
	}
	mutex_unlock(rdma_info->lock);
	param->has_rdma = true;
	param->mem_type = rdma_info->mem_type;
	param->id = rdma_info->rdma_id_info[func_id].id;
	/* rdma only use lower 16 bits */
	param->internal_cfg = resource_info->internal_cfg & U16_MAX;

	return 0;
}

int nbl_res_register_rdma_grc_id(void *priv, u16 *vsi_id, int *grc_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_rdma_info *rdma_info = &resource_info->rdma_info;
	int id;
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, *vsi_id);

	mutex_lock(rdma_info->lock);
	if (!rdma_info->rdma_id_info[func_id].grc_id_vaild) {
		id = ida_alloc(rdma_info->grc_adev_ida, GFP_KERNEL);
		if (id < 0) {
			mutex_unlock(rdma_info->lock);
			return id;
		}
		rdma_info->rdma_id_info[func_id].grc_id = id;
		rdma_info->rdma_id_info[func_id].grc_id_vaild = true;
	}
	mutex_unlock(rdma_info->lock);

	*grc_id = rdma_info->rdma_id_info[func_id].grc_id;

	return 0;
}

int nbl_res_unregister_rdma(void *priv, u16 *vsi_id)
{
	/* nothing to do */

	return 0;
}

int nbl_res_unregister_rdma_grc_id(void *priv, u16 *vsi_id)
{
	/* nothing to do */

	return 0;
}

u32 nbl_res_get_pfvf_queue_num(struct nbl_resource_mgt *res_mgt, int pfid, int vfid)
{
	struct nbl_resource_info *res_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_net_ring_num_info *num_info = &res_info->net_ring_num_info;
	u32 queue_num = 0;
	u16 max_qp;
	u16 func_id = nbl_res_pfvfid_to_func_id(res_mgt, pfid, vfid);

	if (vfid >= 0) {
		if (num_info->net_max_qp_num[func_id] != 0)
			queue_num = num_info->net_max_qp_num[func_id];
		else
			queue_num = num_info->vf_def_max_net_qp_num;

		max_qp = queue_mgt->vf_vsi_max_qp;
	} else {
		if (num_info->net_max_qp_num[func_id] != 0)
			queue_num = num_info->net_max_qp_num[func_id];
		else
			queue_num = num_info->pf_def_max_net_qp_num;

		max_qp = queue_mgt->pf_vsi_max_qp;
	}

	if (queue_num > max_qp) {
		nbl_warn(NBL_RES_MGT_TO_COMMON(res_mgt), NBL_DEBUG_QUEUE,
			 "Invalid queue num %u for func %d, use default", queue_num, func_id);
		queue_num = vfid >= 0 ? NBL_DEFAULT_VF_HW_QUEUE_NUM : NBL_DEFAULT_PF_HW_QUEUE_NUM;
	}

	return queue_num;
}

int nbl_res_get_user_queue_info(void *priv, u16 *vsi_id, struct nbl_ch_prm_get_queue_info *output)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_resource_info *res_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_net_ring_num_info *num_info = &res_info->net_ring_num_info;
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, *vsi_id);
	u16 default_queue;

	if (num_info->net_max_qp_num[func_id] != 0)
		default_queue = num_info->net_max_qp_num[func_id];
	else
		default_queue = num_info->pf_def_max_net_qp_num;

	output->queue_num = min_t(u16, default_queue,
				  queue_mgt->pf_coexist_vsi_max_qp - default_queue);
	output->queue_size = NBL_DEFAULT_DESC_NUM;

	if (output->queue_num > queue_mgt->pf_vsi_max_qp) {
		nbl_warn(NBL_RES_MGT_TO_COMMON(res_mgt), NBL_DEBUG_QUEUE,
			 "Invalid user queue num %d for func %d, use default",
			 output->queue_num, func_id);
		output->queue_num = NBL_DEFAULT_PF_HW_QUEUE_NUM;
	}

	nbl_info(NBL_RES_MGT_TO_COMMON(res_mgt), NBL_DEBUG_QUEUE,
		 "user dev queue num is:%d-%d", func_id, output->queue_num);
	return 0;
}

int nbl_res_get_xdp_queue_info(void *priv, u16 *vsi_id,
			       struct nbl_ch_prm_get_queue_info *output)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_resource_info *res_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_net_ring_num_info *num_info = &res_info->net_ring_num_info;
	u16 func_id = nbl_res_vsi_id_to_func_id(res_mgt, *vsi_id);
	u16 default_queue = 0;
	u16 max_qp_num;

	if (num_info->net_max_qp_num[func_id] != 0)
		default_queue = num_info->net_max_qp_num[func_id];
	else
		default_queue = num_info->pf_def_max_net_qp_num;

	output->queue_num = min_t(u16, default_queue,
				  queue_mgt->pf_coexist_vsi_max_qp - default_queue);

	if (func_id < NBL_MAX_PF)
		max_qp_num = queue_mgt->pf_vsi_max_qp;
	else
		max_qp_num = queue_mgt->vf_vsi_max_qp;

	if (output->queue_num > max_qp_num) {
		nbl_warn(NBL_RES_MGT_TO_COMMON(res_mgt), NBL_DEBUG_QUEUE,
			 "Invalid xdp queue num %d for func %d, use default",
			 output->queue_num, func_id);
		output->queue_num = max_qp_num;
	}

	nbl_info(NBL_RES_MGT_TO_COMMON(res_mgt), NBL_DEBUG_QUEUE,
		 "xdp dev queue num is:%d-%d", func_id, output->queue_num);
	return 0;
}

int nbl_res_set_phy_flow(struct nbl_resource_mgt *res_mgt, u8 eth_id, bool status)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_vsi_info *vsi_info = NBL_RES_MGT_TO_VSI_INFO(res_mgt);
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_ch_prm_set_func_vld prm = {0};
	int diff;
	int i, ret = 0;
	u8 pf_id = nbl_res_eth_id_to_pf_id(res_mgt, eth_id);

	diff = nbl_common_pf_id_subtraction_mgtpf_id(common, pf_id);
	for (i = 0; i < NBL_VSI_SERV_MAX_TYPE; i++) {
		ret = phy_ops->cfg_phy_flow(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					    vsi_info->serv_info[diff][i].base_id,
					    vsi_info->serv_info[diff][i].num, eth_id,
					    status, queue_mgt->rss_key_range_oft);
		if (ret)
			return ret;
	}

	prm.eth_id = eth_id;
	prm.vld = !status;
	nbl_res_set_dport_fc_th_vld(res_mgt, &prm);
	nbl_res_set_shaping_dport_vld(res_mgt, &prm);
	if (phy_ops->cfg_eth_port_priority_replace)
		phy_ops->cfg_eth_port_priority_replace(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
						       eth_id, status);

	return 0;
}

int nbl_res_update_offload_status(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_rep_offload_status *rep_status = &res_mgt->pmd_status.rep_status;
	bool *other_pmd_cfg = res_mgt->pmd_status.other_pmd_cfg;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_event_acl_state_update_data event_data = {0};
	struct nbl_sriov_info *sriov_info;
	int start, end, vsi_match, eth_id, ret;
	int diff;
	bool merge_status[NBL_MAX_ETHERNET] = {0};
	u8 pf_id;
	u8 peer_eth_id;
	bool status;

	/* first: init status depend on my rep cfg */
	for_each_set_bit(eth_id, eth_info->eth_bitmap, NBL_MAX_ETHERNET) {
		status = false;
		pf_id = nbl_res_eth_id_to_pf_id(res_mgt, eth_id);
		start = nbl_res_pfvfid_to_vsi_id(res_mgt, pf_id, 0, NBL_VSI_DATA);
		diff = nbl_common_pf_id_subtraction_mgtpf_id(common, pf_id);
		sriov_info = &NBL_RES_MGT_TO_SRIOV_INFO(res_mgt)[diff];
		end = nbl_res_pfvfid_to_vsi_id(res_mgt, pf_id, sriov_info->num_vfs, NBL_VSI_DATA);
		vsi_match = find_next_bit(rep_status->rep_vsi_bitmap,
					  NBL_OFFLOAD_STATUS_MAX_VSI, start);
		if (vsi_match < end || test_bit(eth_id, rep_status->rep_eth_bitmap))
			status = true;

		merge_status[eth_id] = status;
	}

	/* seond: merge bond peer member's status.
	 * For bond, there will be only one pf is bind to ovs-dpdk, but all pfs should
	 * change to offload. So merge it.
	 */
	for_each_set_bit(eth_id, eth_info->eth_bitmap, NBL_MAX_ETHERNET) {
		ret = nbl_res_get_peer_lag_member(res_mgt, eth_id, &peer_eth_id);
		if (ret)
			continue;

		status = false;
		if (merge_status[eth_id])
			status = true;

		if (other_pmd_cfg[peer_eth_id])
			status = true;

		merge_status[eth_id] = status;
	}

	nbl_info(NBL_RES_MGT_TO_COMMON(res_mgt), NBL_DEBUG_RESOURCE,
		 "update phy flow cfg new:%d-%d-%d-%d, old:%d-%d-%d-%d\n",
		 merge_status[0], merge_status[1], merge_status[2], merge_status[3],
		 rep_status->status[0], rep_status->status[1], rep_status->status[2],
		 rep_status->status[3]);

	for_each_set_bit(eth_id, eth_info->eth_bitmap, NBL_MAX_ETHERNET) {
		if (rep_status->status[eth_id] != merge_status[eth_id]) {
			nbl_res_set_phy_flow(res_mgt, eth_id, merge_status[eth_id]);
			rep_status->status[eth_id] = merge_status[eth_id];
		}
	}

	event_data.is_offload = false;
	for_each_set_bit(eth_id, eth_info->eth_bitmap, NBL_MAX_ETHERNET) {
		if (rep_status->status[eth_id])
			event_data.is_offload = true;
	}

	nbl_event_notify(NBL_EVENT_ACL_STATE_UPDATE, &event_data, NBL_COMMON_TO_VSI_ID(common),
			 NBL_COMMON_TO_BOARD_ID(common));

	return 0;
}

int nbl_res_set_dport_fc_th_vld(void *priv,
				struct nbl_ch_prm_set_func_vld *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	if (phy_ops->set_dport_fc_th_vld)
		phy_ops->set_dport_fc_th_vld(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					       param->eth_id, param->vld);

	return 0;
}

int nbl_res_set_shaping_dport_vld(void *priv,
				  struct nbl_ch_prm_set_func_vld *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	if (phy_ops->set_shaping_dport_vld)
		phy_ops->set_shaping_dport_vld(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					       param->eth_id, param->vld);

	return 0;
}

int nbl_res_cfg_eth_bond_info(void *priv, struct nbl_lag_member_list_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_eth_bond_info *eth_bond_info = NBL_RES_MGT_TO_ETH_BOND_INFO(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_eth_bond_entry origin_entry;
	struct nbl_eth_bond_entry *entry = NULL;
	struct nbl_event_link_status_update_data *event_data = NULL;
	u8 eth_btm[NBL_MAX_ETHERNET] = {0};
	int num = 0, i = 0, j = 0;

	if (param->lag_id >= NBL_LAG_MAX_NUM)
		return -EINVAL;

	entry = &eth_bond_info->entry[param->lag_id];
	memcpy(&origin_entry, entry, sizeof(origin_entry));

	/* We always clear it first, in case lag member changed. */
	memset(entry, 0, sizeof(*entry));
	if (param->lag_num > 1) {
		for (i = 0; i < param->lag_num && NBL_ETH_BOND_VALID_PORT(i); i++) {
			entry->eth_id[i] = param->member_list[i].eth_id;
			entry->vsi_id[i] = param->member_list[i].vsi_id;
			eth_btm[param->member_list[i].eth_id] = 1;
		}

		entry->lag_id = param->lag_id;
		entry->lag_num = param->lag_num;
	}

	/* If lag member changed, notify both original and new related vfs to update link_state */
	for (i = 0; i < origin_entry.lag_num && NBL_ETH_BOND_VALID_PORT(i); i++)
		eth_btm[origin_entry.eth_id[i]] = 1;

	for (i = 0; i < NBL_MAX_ETHERNET; i++)
		if (eth_btm[i])
			num++;

	nbl_res_update_offload_status(res_mgt);

	event_data = kzalloc(sizeof(*event_data), GFP_KERNEL);
	if (!event_data)
		return -ENOMEM;

	for (i = 0; i < NBL_MAX_ETHERNET; i++)
		if (eth_btm[i])
			event_data->eth_id[j++] = i;

	event_data->num = num;

	nbl_event_notify(NBL_EVENT_LINK_STATE_UPDATE, event_data,
			 NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));

	kfree(event_data);
	return 0;
}

int nbl_res_prepare_vf_chan(struct nbl_resource_mgt *res_mgt, u16 func_id)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_sriov_info *sriov_info;
	int ret;
	int diff;
	int pfid;
	int vfid;
	u16 offset;
	u16 stride;
	u16 vf_func_id;
	u8 bus;
	u8 devfn;
	u8 devid;
	u8 function;
	u8 pf_bus;
	u8 pf_devfn;

	ret = nbl_res_func_id_to_pfvfid(res_mgt, func_id, &pfid, &vfid);
	if (ret)
		return ret;

	if (vfid != U32_MAX)
		return 0;

	diff = nbl_common_pf_id_subtraction_mgtpf_id(common, func_id);
	sriov_info = NBL_RES_MGT_TO_SRIOV_INFO(res_mgt) + diff;

	if (!sriov_info->vf_bar_len)
		return 0;

	offset = sriov_info->offset;
	stride = sriov_info->stride;

	/* Configure mailbox qinfo_map_table for the pf's vfs, so af ready to process vf request */
	pf_bus = PCI_BUS_NUM(sriov_info->bdf);
	pf_devfn = sriov_info->bdf & 0xff;
	for (vfid = 0; vfid < sriov_info->num_vfs; vfid++) {
		vf_func_id = sriov_info->start_vf_func_id + vfid;
		bus = pf_bus + ((pf_devfn + offset + stride * vfid) >> 8);
		devfn = (pf_devfn + offset + stride * vfid) & 0xff;
		devid = PCI_SLOT(devfn);
		function = PCI_FUNC(devfn);

		phy_ops->cfg_mailbox_qinfo(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					vf_func_id, bus, devid, function);
	}

	return 0;
}

int nbl_res_get_pfc_buffer_size(void *priv, struct nbl_ch_prm_get_pfc_buffer_size *param,
				struct nbl_ch_prm_get_pfc_buffer_size_resp *output)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->get_pfc_buffer_size(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), param->eth_id, param->prio,
				     &output->xoff, &output->xon);

	return 0;
}

int nbl_res_set_pfc_buffer_size(void *priv, struct nbl_ch_prm_set_pfc_buffer_size *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->set_pfc_buffer_size(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), param->eth_id,
					    param->prio, param->xoff, param->xon);
}

int nbl_res_configure_qos(void *priv, struct nbl_ch_prm_configure_qos *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	int ret;

	phy_ops->configure_qos(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), param->eth_id, param->pfc,
			       param->trust, param->dscp2prio_map);
	ret = nbl_res_adminq_set_eth_pfc(priv, param->eth_id, param->pfc);

	return ret;
}

int nbl_res_update_active_vf_num(struct nbl_resource_mgt *res_mgt, u16 func_id, bool add_flag)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_sriov_info *sriov_info;
	int pfid = 0;
	int vfid = 0;
	int ret;
	int diff;

	ret = nbl_res_func_id_to_pfvfid(res_mgt, func_id, &pfid, &vfid);
	if (ret) {
		nbl_err(common, NBL_DEBUG_RESOURCE, "convert func id to pfvfid failed\n");
		return ret;
	}

	if (vfid == U32_MAX)
		return 0;

	diff = nbl_common_pf_id_subtraction_mgtpf_id(common, pfid);
	sriov_info = NBL_RES_MGT_TO_SRIOV_INFO(res_mgt) + diff;

	if (add_flag) {
		if (!test_bit(func_id, resource_info->func_bitmap)) {
			sriov_info->active_vf_num++;
			set_bit(func_id, resource_info->func_bitmap);
		}
	} else if (sriov_info->active_vf_num) {
		if (test_bit(func_id, resource_info->func_bitmap)) {
			sriov_info->active_vf_num--;
			clear_bit(func_id, resource_info->func_bitmap);
		}
	}

	return 0;
}

int nbl_res_configure_rdma_bw(void *priv, struct nbl_ch_prm_configure_rdma_bw *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->configure_rdma_bw(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), param->eth_id, param->rdma_bw);

	return 0;
}

u32 nbl_res_check_active_vf(void *priv, u16 *func_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_sriov_info *sriov_info;
	int diff;

	diff = nbl_common_pf_id_subtraction_mgtpf_id(common, *func_id);
	sriov_info = NBL_RES_MGT_TO_SRIOV_INFO(res_mgt) + diff;

	return sriov_info->active_vf_num;
}

int nbl_res_set_rate_limit(void *priv, struct nbl_ch_prm_set_rate_limit *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	phy_ops->set_rate_limit(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), param->sfid, param->type,
				param->rate);

	return 0;
}

int nbl_res_get_my_pf(void *priv, u16 *sfid, u8 *my_pf)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	int pf_id;
	int vf_id;
	int ret;

	ret = nbl_res_func_id_to_pfvfid(res_mgt, *sfid, &pf_id, &vf_id);
	*my_pf = (u8)pf_id;

	return ret;
}

int nbl_res_check_fw_working(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	unsigned long fw_pong_current;
	unsigned long seconds_current = 0;

	seconds_current = (unsigned long)ktime_get_real_seconds() + NBL_FW_HEARTBEAT_SEQ_BASE;
	phy_ops->set_fw_pong(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), seconds_current - 1);
	phy_ops->set_fw_ping(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), seconds_current);

	/* Wait for FW to ack the first heartbeat seq */
	return nbl_read_poll_timeout(phy_ops->get_fw_pong, fw_pong_current,
				     fw_pong_current == seconds_current,
				     USEC_PER_MSEC, 500 * USEC_PER_MSEC,
				     false, NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
}

int nbl_res_get_chip_temperature(void *priv, struct nbl_ch_prm_get_hwmon *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->get_chip_temperature(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
		param->type, param->senser_id);
}

int nbl_res_intr_get_abnormal_irq_num(void *priv)
{
	return 1;
}

int nbl_res_unregister_net(void *priv, u16 *func_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;

	return nbl_res_update_active_vf_num(res_mgt, *func_id, 0);
}

int nbl_res_configure_mirror(void *priv, struct nbl_ch_prm_mirror *param)
{
	u16 data_vsi, user_vsi;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	data_vsi = nbl_res_func_id_to_vsi_id(res_mgt, param->sfid, NBL_VSI_DATA);
	user_vsi = nbl_res_func_id_to_vsi_id(res_mgt, param->sfid, NBL_VSI_USER);

	phy_ops->configure_mirror(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), data_vsi, param->mirror_en,
				  param->dir, param->mt_id);
	phy_ops->configure_mirror(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), user_vsi, param->mirror_en,
				  param->dir, param->mt_id);

	return 0;
}

int nbl_res_get_mirror_table_id(void *priv, struct nbl_ch_prm_get_mirror_table_id *param,
				struct nbl_ch_prm_get_mirror_table_id *output)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);

	return phy_ops->get_mirror_table_id(NBL_RES_MGT_TO_PHY_PRIV(res_mgt),
					    param->vsi_id, param->dir, param->mirror_en,
					    &output->mt_id);
}

int nbl_res_get_dev_name(void *priv, struct nbl_ch_prm_pf_name *param,
			 struct nbl_ch_prm_pf_name *output)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	int pf_id, vf_id;
	u16 func_id;
	int name_len;

	func_id = nbl_res_vsi_id_to_func_id(res_mgt, param->vsi_id);
	nbl_res_func_id_to_pfvfid(res_mgt, func_id, &pf_id, &vf_id);
	WARN_ON(pf_id >= NBL_MAX_PF);
	name_len = snprintf(output->dev_name, IFNAMSIZ, "%sv%d",
			    resource_info->pf_name_list[pf_id], vf_id);
	if (name_len >= IFNAMSIZ)
		nbl_err(NBL_RES_MGT_TO_COMMON(res_mgt), NBL_DEBUG_RESOURCE,
			"vsi:%u-pf%uvf%u get name over length", param->vsi_id, pf_id, vf_id);

	nbl_debug(NBL_RES_MGT_TO_COMMON(res_mgt), NBL_DEBUG_RESOURCE,
		  "vsi:%u-pf%uvf%u get a pf_name->%s", param->vsi_id, pf_id, vf_id,
		  output->dev_name);
	return 0;
}

int nbl_res_register_dev_name(void *priv, struct nbl_ch_prm_pf_name *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *resource_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	u32 pf_id;

	pf_id = nbl_res_vsi_id_to_pf_id(res_mgt, param->vsi_id);
	WARN_ON(pf_id >= NBL_MAX_PF);
	strscpy(resource_info->pf_name_list[pf_id], param->dev_name, IFNAMSIZ);
	nbl_info(NBL_RES_MGT_TO_COMMON(res_mgt), NBL_DEBUG_RESOURCE,
		 "vsi:%u-pf:%u register a pf_name->%s", param->vsi_id, pf_id, param->dev_name);
	return 0;
}

bool nbl_res_check_lag_nosupport(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	return NBL_COMMON_TO_MY_PF(common) >= 2;
}
