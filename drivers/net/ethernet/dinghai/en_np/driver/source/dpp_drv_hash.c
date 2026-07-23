// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "dpp_apt_se_api.h"
#include "dpp_se_api.h"
#include "dpp_apt_se.h"
#include "dpp_sdt.h"
#include "dpp_hash.h"
#include "dpp_dtb_table.h"
#include "dpp_drv_sdt.h"
#include "dpp_drv_hash.h"
#include "dpp_kernel_init.h"

static struct se_apt_hash_convert_t g_se_hash_callback[] = {
	{ ZXDH_SDT_L2_ENTRY_TABLE_PHYPORT0, dpp_apt_set_l2entry_data, dpp_apt_get_l2entry_data },
	{ ZXDH_SDT_L2_ENTRY_TABLE_PHYPORT1, dpp_apt_set_l2entry_data, dpp_apt_get_l2entry_data },
	{ ZXDH_SDT_L2_ENTRY_TABLE_PHYPORT2, dpp_apt_set_l2entry_data, dpp_apt_get_l2entry_data },
	{ ZXDH_SDT_L2_ENTRY_TABLE_PHYPORT3, dpp_apt_set_l2entry_data, dpp_apt_get_l2entry_data },
	{ ZXDH_SDT_MC_TABLE_PHYPORT0, dpp_apt_set_mc_data, dpp_apt_get_mc_data },
	{ ZXDH_SDT_MC_TABLE_PHYPORT1, dpp_apt_set_mc_data, dpp_apt_get_mc_data },
	{ ZXDH_SDT_MC_TABLE_PHYPORT2, dpp_apt_set_mc_data, dpp_apt_get_mc_data },
	{ ZXDH_SDT_MC_TABLE_PHYPORT3, dpp_apt_set_mc_data, dpp_apt_get_mc_data },
	{ ZXDH_SDT_RDMA_ENTRY_TABLE, dpp_apt_set_rdma_trans_data, dpp_apt_get_rdma_trans_data }
};

struct se_apt_hash_convert_t *se_hash_callback_get(u32 sdt_no)
{
	u32 index = 0;
	u32 num = 0;

	num = sizeof(g_se_hash_callback) / sizeof(struct se_apt_hash_convert_t);
	for (index = 0; index < num; index++) {
		if (g_se_hash_callback[index].sdt_no == sdt_no)
			return &g_se_hash_callback[index];
	}

	return NULL;
}

u32 dpp_apt_set_l2entry_data(void *pData, struct dpp_hash_entry *pEntry)
{
	u32 key = 0;
	u32 rst = 0;
	struct zxdh_l2_fwd_t *pL2Entry = NULL;

	ZXIC_COMM_CHECK_POINT(pData);
	ZXIC_COMM_CHECK_POINT(pEntry);
	ZXIC_COMM_CHECK_POINT(pEntry->p_key);
	ZXIC_COMM_CHECK_POINT(pEntry->p_rst);

	pL2Entry = (struct zxdh_l2_fwd_t *)pData;

	ZXIC_COMM_MEMCPY(pEntry->p_key + 1, pL2Entry->key.dmac_addr, 6);

	ZXIC_COMM_UINT32_WRITE_BITS(key, pL2Entry->key.sriov_vlan_tpid, 16, 16);
	ZXIC_COMM_UINT32_WRITE_BITS(key, pL2Entry->key.sriov_vlan_id, 0, 16);
	zxic_comm_swap((u8 *)&key, sizeof(u32));
	ZXIC_COMM_MEMCPY(pEntry->p_key + 7, &key, sizeof(u32));

	ZXIC_COMM_UINT32_WRITE_BITS(rst, pL2Entry->entry.hit_flag, 31, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(rst, pL2Entry->entry.rsv, 11, 20);
	ZXIC_COMM_UINT32_WRITE_BITS(rst, pL2Entry->entry.vqm_vfid, 0, 11);

	zxic_comm_swap((u8 *)&rst, sizeof(u32));
	ZXIC_COMM_MEMCPY(pEntry->p_rst, &rst, sizeof(u32));

	return DPP_OK;
}

u32 dpp_apt_get_l2entry_data(void *pData, struct dpp_hash_entry *pEntry)
{
	struct zxdh_l2_fwd_t *pL2Entry = NULL;

	u32 key = 0;

	ZXIC_COMM_CHECK_POINT(pData);
	ZXIC_COMM_CHECK_POINT(pEntry);
	ZXIC_COMM_CHECK_POINT(pEntry->p_rst);

	pL2Entry = (struct zxdh_l2_fwd_t *)pData;

	key = *(u32 *)(pEntry->p_key + 7);
	zxic_comm_swap((u8 *)&key, sizeof(u32));
	ZXIC_COMM_UINT32_GET_BITS(pL2Entry->key.sriov_vlan_tpid, key, 16, 16);
	ZXIC_COMM_UINT32_GET_BITS(pL2Entry->key.sriov_vlan_id, key, 0, 16);

	ZXIC_COMM_MEMCPY(pL2Entry->key.dmac_addr, pEntry->p_key + 1, 6);

	zxic_comm_swap(pEntry->p_rst, sizeof(u32));
	ZXIC_COMM_UINT32_GET_BITS(pL2Entry->entry.hit_flag, *(u32 *)pEntry->p_rst, 31, 1);
	ZXIC_COMM_UINT32_GET_BITS(pL2Entry->entry.rsv, *(u32 *)pEntry->p_rst, 11, 20);
	ZXIC_COMM_UINT32_GET_BITS(pL2Entry->entry.vqm_vfid, *(u32 *)pEntry->p_rst, 0, 11);

	return DPP_OK;
}

u32 dpp_apt_set_mc_data(void *pData, struct dpp_hash_entry *pEntry)
{
	u32 key = 0;
	u32 rst = 0;

	struct zxdh_mc_t *mc_table = NULL;

	ZXIC_COMM_CHECK_POINT(pData);
	ZXIC_COMM_CHECK_POINT(pEntry);
	ZXIC_COMM_CHECK_POINT(pEntry->p_key);
	ZXIC_COMM_CHECK_POINT(pEntry->p_rst);

	mc_table = (struct zxdh_mc_t *)pData;

	ZXIC_COMM_UINT32_WRITE_BITS(key, mc_table->key.rsv, 18, 14);
	ZXIC_COMM_UINT32_WRITE_BITS(key, mc_table->key.group_id, 16, 2);

	zxic_comm_swap((u8 *)&key, sizeof(u32));
	ZXIC_COMM_MEMCPY(pEntry->p_key + 1, &key, sizeof(u32));

	ZXIC_COMM_MEMCPY(pEntry->p_key + 3, mc_table->key.mc_mac, 6);

	ZXIC_COMM_UINT32_WRITE_BITS(rst, mc_table->entry.hit_flag, 31, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(rst, mc_table->entry.mc_pf_enable, 30, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(rst, mc_table->entry.rsv1, 0, 30);
	zxic_comm_swap((u8 *)&rst, sizeof(u32));
	ZXIC_COMM_MEMCPY(pEntry->p_rst, &rst, sizeof(u32));

	ZXIC_COMM_UINT32_WRITE_BITS(rst, mc_table->entry.rsv2, 0, 32);
	zxic_comm_swap((u8 *)&rst, sizeof(u32));
	ZXIC_COMM_MEMCPY(pEntry->p_rst + 4, &rst, sizeof(u32));

	rst = mc_table->entry.mc_bitmap >> 32;
	zxic_comm_swap((u8 *)&rst, sizeof(u32));
	ZXIC_COMM_MEMCPY(pEntry->p_rst + 8, &rst, sizeof(u32));

	rst = mc_table->entry.mc_bitmap;
	zxic_comm_swap((u8 *)&rst, sizeof(u32));
	ZXIC_COMM_MEMCPY(pEntry->p_rst + 12, &rst, sizeof(u32));

	return DPP_OK;
}

u32 dpp_apt_get_mc_data(void *pData, struct dpp_hash_entry *pEntry)
{
	u32 key = 0;
	u32 rst = 0;

	struct zxdh_mc_t *mc_table = NULL;

	ZXIC_COMM_CHECK_POINT(pData);
	ZXIC_COMM_CHECK_POINT(pEntry);
	ZXIC_COMM_CHECK_POINT(pEntry->p_key);
	ZXIC_COMM_CHECK_POINT(pEntry->p_rst);

	mc_table = (struct zxdh_mc_t *)pData;

	key = *(u32 *)(pEntry->p_key + 1);
	zxic_comm_swap((u8 *)&key, sizeof(u32));
	ZXIC_COMM_UINT32_GET_BITS(mc_table->key.rsv, key, 18, 14);
	ZXIC_COMM_UINT32_GET_BITS(mc_table->key.group_id, key, 16, 2);

	ZXIC_COMM_MEMCPY(mc_table->key.mc_mac, pEntry->p_key + 3, 6);

	zxic_comm_swap(pEntry->p_rst, sizeof(u32));
	ZXIC_COMM_UINT32_GET_BITS(mc_table->entry.hit_flag, *(u32 *)pEntry->p_rst, 31, 1);
	ZXIC_COMM_UINT32_GET_BITS(mc_table->entry.mc_pf_enable, *(u32 *)pEntry->p_rst, 30, 1);
	ZXIC_COMM_UINT32_GET_BITS(mc_table->entry.rsv1, *(u32 *)pEntry->p_rst, 0, 30);

	zxic_comm_swap(pEntry->p_rst + 4, sizeof(u32));
	ZXIC_COMM_UINT32_GET_BITS(mc_table->entry.rsv2, *(u32 *)(pEntry->p_rst + 4), 0, 32);

	zxic_comm_swap(pEntry->p_rst + 8, sizeof(u32));
	ZXIC_COMM_UINT32_GET_BITS(rst, *(u32 *)(pEntry->p_rst + 8), 0, 32);
	mc_table->entry.mc_bitmap = (((u64)rst) << 32);

	zxic_comm_swap(pEntry->p_rst + 12, sizeof(u32));
	ZXIC_COMM_UINT32_GET_BITS(rst, *(u32 *)(pEntry->p_rst + 12), 0, 32);
	mc_table->entry.mc_bitmap |= rst;

	return DPP_OK;
}

u32 dpp_apt_set_rdma_trans_data(void *pData, struct dpp_hash_entry *pEntry)
{
	u32 key = 0;
	u32 rst = 0;

	struct zxdh_rdma_trans_t *rdma_trans_table = NULL;

	ZXIC_COMM_CHECK_POINT(pData);
	ZXIC_COMM_CHECK_POINT(pEntry);
	ZXIC_COMM_CHECK_POINT(pEntry->p_key);
	ZXIC_COMM_CHECK_POINT(pEntry->p_rst);

	rdma_trans_table = (struct zxdh_rdma_trans_t *)pData;

	ZXIC_COMM_MEMCPY(pEntry->p_key + 1, &key, 2);

	ZXIC_COMM_MEMCPY(pEntry->p_key + 3, rdma_trans_table->key.mac_addr, 6);

	ZXIC_COMM_UINT32_WRITE_BITS(rst, rdma_trans_table->entry.hit_flag, 31, 1);
	ZXIC_COMM_UINT32_WRITE_BITS(rst, rdma_trans_table->entry.rsv, 10, 21);
	ZXIC_COMM_UINT32_WRITE_BITS(rst, rdma_trans_table->entry.rdma_vhca_id, 0, 10);

	zxic_comm_swap((u8 *)&rst, sizeof(u32));
	ZXIC_COMM_MEMCPY(pEntry->p_rst, &rst, sizeof(u32));

	return DPP_OK;
}

u32 dpp_apt_get_rdma_trans_data(void *pData, struct dpp_hash_entry *pEntry)
{
	struct zxdh_rdma_trans_t *rdma_trans_table = NULL;

	ZXIC_COMM_CHECK_POINT(pData);
	ZXIC_COMM_CHECK_POINT(pEntry);
	ZXIC_COMM_CHECK_POINT(pEntry->p_rst);

	rdma_trans_table = (struct zxdh_rdma_trans_t *)pData;

	ZXIC_COMM_MEMCPY(rdma_trans_table->key.mac_addr, pEntry->p_key + 3, 6);

	zxic_comm_swap(pEntry->p_rst, sizeof(u32));
	ZXIC_COMM_UINT32_GET_BITS(rdma_trans_table->entry.hit_flag, *(u32 *)pEntry->p_rst, 31, 1);
	ZXIC_COMM_UINT32_GET_BITS(rdma_trans_table->entry.rsv, *(u32 *)pEntry->p_rst, 10, 21);
	ZXIC_COMM_UINT32_GET_BITS(rdma_trans_table->entry.rdma_vhca_id, *(u32 *)pEntry->p_rst, 0,
				  10);

	return DPP_OK;
}

DPP_STATUS dpp_apt_dtb_hash_table_unicast_mac_dump(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no,
						   struct zxdh_l2_fwd_t *pHashDataArr,
						   u32 *p_entry_num)
{
	DPP_STATUS rc = DPP_OK;
	u32 max_item_num = DTB_DUMP_UNICAST_MAC_DUMP_NUM;
	u32 index = 0;
	u32 entryNum = 0;
	u8 *pDumpData = NULL;
	u8 *pKey = NULL;
	u8 *pRst = NULL;

	struct dpp_hash_entry *p_dump_hash_entry = NULL;
	struct dpp_hash_entry *p_temp_entry = NULL;
	struct dpp_sdt_tbl_hash_t sdt_hash_info = { 0 };
	struct se_apt_callback_t *pAptCallback = NULL;
	struct zxdh_l2_fwd_t *p_l2_mac_entry = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(pHashDataArr);
	ZXIC_COMM_CHECK_POINT(p_entry_num);

	rc = dpp_soft_sdt_tbl_get(dev, sdt_no, &sdt_hash_info);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_soft_sdt_tbl_get");

	rc = dpp_hash_max_item_num_get(dev, sdt_no, &max_item_num);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_hash_max_item_num_get");

	pAptCallback = dpp_apt_get_func(dev, sdt_no);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), pAptCallback);

	pDumpData = (u8 *)ZXIC_COMM_VMALLOC(max_item_num * sizeof(struct dpp_hash_entry));
	ZXIC_COMM_CHECK_POINT_NO_ASSERT(pDumpData);
	pKey = (u8 *)ZXIC_COMM_VMALLOC(max_item_num * HASH_KEY_MAX);
	ZXIC_COMM_CHECK_POINT_MEMORY_VFREE_NO_ASSERT(pKey, pDumpData);
	pRst = (u8 *)ZXIC_COMM_VMALLOC(max_item_num * HASH_RST_MAX);
	ZXIC_COMM_CHECK_POINT_MEMORY_VFREE2PTR_NO_ASSERT(pRst, pKey, pDumpData);

	ZXIC_COMM_MEMSET_S(pDumpData, max_item_num * sizeof(struct dpp_hash_entry), 0x0,
			   max_item_num * sizeof(struct dpp_hash_entry));
	ZXIC_COMM_MEMSET_S(pKey, max_item_num * HASH_KEY_MAX, 0x0, max_item_num * HASH_KEY_MAX);
	ZXIC_COMM_MEMSET_S(pRst, max_item_num * HASH_RST_MAX, 0x0, max_item_num * HASH_RST_MAX);

	p_dump_hash_entry = (struct dpp_hash_entry *)pDumpData;
	for (index = 0; index < max_item_num; index++) {
		p_temp_entry = p_dump_hash_entry + index;
		p_temp_entry->p_key = pKey + index * HASH_KEY_MAX;
		p_temp_entry->p_rst = pRst + index * HASH_RST_MAX;
	}

	rc = dpp_dtb_hash_dump(dev, queue_id, sdt_no, pDumpData, &entryNum);
	ZXIC_COMM_CHECK_DEV_RC_MEMORY_VFREE3PTR_NO_ASSERT(DEV_ID(dev), rc, "dpp_apt_dtb_hash_dump",
							  pRst, pKey, pDumpData);
	ZXIC_COMM_TRACE_INFO("dpp_dtb_hash_table_only_zcam_dump unicast entry_num: %d\n", entryNum);

	for (index = 0; index < entryNum; index++) {
		p_temp_entry = p_dump_hash_entry + index;
		p_l2_mac_entry = pHashDataArr + index;

		dpp_dtb_data_print(p_temp_entry->p_key,
				   DPP_GET_ACTU_KEY_BY_SIZE(sdt_hash_info.key_size) + 1);
		dpp_dtb_data_print(p_temp_entry->p_rst, 4 * (0x1 << sdt_hash_info.rsp_mode));

		rc = pAptCallback->se_func_info.hashFunc.hash_get_func(p_l2_mac_entry,
								       p_temp_entry);
		ZXIC_COMM_CHECK_DEV_RC_MEMORY_VFREE3PTR_NO_ASSERT(DEV_ID(dev), rc, "hash_set_func",
								  pRst, pKey, pDumpData);
	}

	*p_entry_num = entryNum;

	ZXIC_COMM_VFREE(pKey);
	ZXIC_COMM_VFREE(pRst);
	ZXIC_COMM_VFREE(pDumpData);

	return DPP_OK;
}

DPP_STATUS dpp_apt_dtb_hash_table_multicast_mac_dump(struct dpp_dev_t *dev, u32 queue_id,
						     u32 sdt_no, struct zxdh_mc_t *pHashDataArr,
						     u32 *p_entry_num)
{
	DPP_STATUS rc = DPP_OK;
	u32 max_item_num = DTB_DUMP_MULTICAST_MAC_DUMP_NUM;
	u32 index = 0;
	u32 entryNum = 0;
	u8 *pDumpData = NULL;
	u8 *pKey = NULL;
	u8 *pRst = NULL;

	struct dpp_hash_entry *p_dump_hash_entry = NULL;
	struct dpp_hash_entry *p_temp_entry = NULL;
	struct dpp_sdt_tbl_hash_t sdt_hash_info = { 0 };
	struct se_apt_callback_t *pAptCallback = NULL;
	struct zxdh_mc_t *p_multicast_mac_data = NULL;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(pHashDataArr);
	ZXIC_COMM_CHECK_POINT(p_entry_num);

	rc = dpp_soft_sdt_tbl_get(dev, sdt_no, &sdt_hash_info);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_soft_sdt_tbl_get");

	rc = dpp_hash_max_item_num_get(dev, sdt_no, &max_item_num);
	ZXIC_COMM_CHECK_DEV_RC(DEV_ID(dev), rc, "dpp_hash_max_item_num_get");

	pAptCallback = dpp_apt_get_func(dev, sdt_no);
	ZXIC_COMM_CHECK_DEV_POINT(DEV_ID(dev), pAptCallback);

	pDumpData = (u8 *)ZXIC_COMM_VMALLOC(max_item_num * sizeof(struct dpp_hash_entry));
	ZXIC_COMM_CHECK_POINT_NO_ASSERT(pDumpData);
	pKey = (u8 *)ZXIC_COMM_VMALLOC(max_item_num * HASH_KEY_MAX);
	ZXIC_COMM_CHECK_POINT_MEMORY_VFREE_NO_ASSERT(pKey, pDumpData);
	pRst = (u8 *)ZXIC_COMM_VMALLOC(max_item_num * HASH_RST_MAX);
	ZXIC_COMM_CHECK_POINT_MEMORY_VFREE2PTR_NO_ASSERT(pRst, pKey, pDumpData);

	ZXIC_COMM_MEMSET_S(pDumpData, max_item_num * sizeof(struct dpp_hash_entry), 0x0,
			   max_item_num * sizeof(struct dpp_hash_entry));
	ZXIC_COMM_MEMSET_S(pKey, max_item_num * HASH_KEY_MAX, 0x0, max_item_num * HASH_KEY_MAX);
	ZXIC_COMM_MEMSET_S(pRst, max_item_num * HASH_RST_MAX, 0x0, max_item_num * HASH_RST_MAX);

	p_dump_hash_entry = (struct dpp_hash_entry *)pDumpData;
	for (index = 0; index < max_item_num; index++) {
		p_temp_entry = p_dump_hash_entry + index;
		p_temp_entry->p_key = pKey + index * HASH_KEY_MAX;
		p_temp_entry->p_rst = pRst + index * HASH_RST_MAX;
	}

	rc = dpp_dtb_hash_dump(dev, queue_id, sdt_no, pDumpData, &entryNum);
	ZXIC_COMM_CHECK_DEV_RC_MEMORY_VFREE3PTR_NO_ASSERT(DEV_ID(dev), rc, "dpp_apt_dtb_hash_dump",
							  pRst, pKey, pDumpData);

	ZXIC_COMM_TRACE_INFO("dpp_dtb_hash_table_only_zcam_dump multicast entry_num: %d\n",
			     entryNum);

	for (index = 0; index < entryNum; index++) {
		p_temp_entry = p_dump_hash_entry + index;
		p_multicast_mac_data = pHashDataArr + index;

		dpp_dtb_data_print(p_temp_entry->p_key,
				   DPP_GET_ACTU_KEY_BY_SIZE(sdt_hash_info.key_size) + 1);
		dpp_dtb_data_print(p_temp_entry->p_rst, 4 * (0x1 << sdt_hash_info.rsp_mode));

		rc = pAptCallback->se_func_info.hashFunc.hash_get_func(p_multicast_mac_data,
								       p_temp_entry);
		ZXIC_COMM_CHECK_DEV_RC_MEMORY_VFREE3PTR_NO_ASSERT(DEV_ID(dev), rc, "hash_get_func",
								  pRst, pKey, pDumpData);
	}

	*p_entry_num = entryNum;

	ZXIC_COMM_VFREE(pKey);
	ZXIC_COMM_VFREE(pRst);
	ZXIC_COMM_VFREE(pDumpData);

	return DPP_OK;
}
