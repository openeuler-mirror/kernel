/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef DPP_DRV_HASH_H
#define DPP_DRV_HASH_H

#include "zxic_common.h"
#include "dpp_apt_se_api.h"

/* hash-function for hash tbl */

/* L2 forward */
struct zxdh_l2_fwd_key {
	u16 sriov_vlan_id /* : 16; */;
	u16 sriov_vlan_tpid /* : 16; */;
	u8 dmac_addr[6] /* : 48; */;
};

struct zxdh_l2_fwd_entry {
	u32 vqm_vfid /* : 11;*/;
	u32 rsv /* : 20; */;
	u32 hit_flag /* : 1; */;
};

struct zxdh_l2_fwd_t {
	struct zxdh_l2_fwd_key key;
	struct zxdh_l2_fwd_entry entry;
};

/* multicast */
struct zxdh_mc_key {
	u8 mc_mac[6];
	u32 group_id;
	u32 rsv;
};

struct zxdh_mc_entry {
	u64 mc_bitmap;
	u32 rsv2;
	u32 rsv1;
	u32 mc_pf_enable;
	u32 hit_flag;
};

struct zxdh_mc_t {
	struct zxdh_mc_key key;
	struct zxdh_mc_entry entry;
};

struct zxdh_rdma_trans_key {
	u8 mac_addr[6]; /**<  @brief key */
	u16 rsv /* : 16; */;
};

struct zxdh_rdma_trans_entry {
	u32 rdma_vhca_id /* : 10;*/;
	u32 rsv /* : 21; */;
	u32 hit_flag /* : 1; */;
};

struct zxdh_rdma_trans_t {
	struct zxdh_rdma_trans_key key;
	struct zxdh_rdma_trans_entry entry;
};

u32 dpp_apt_set_l2entry_data(void *pData, struct dpp_hash_entry *pEntry);
u32 dpp_apt_get_l2entry_data(void *pData, struct dpp_hash_entry *pEntry);

u32 dpp_apt_set_mc_data(void *pData, struct dpp_hash_entry *pEntry);
u32 dpp_apt_get_mc_data(void *pData, struct dpp_hash_entry *pEntry);

u32 dpp_apt_set_rdma_trans_data(void *pData, struct dpp_hash_entry *pEntry);
u32 dpp_apt_get_rdma_trans_data(void *pData, struct dpp_hash_entry *pEntry);

struct dpp_hash_init_t {
	u32 func_num;
	struct dpp_apt_hash_func_res_t *func;
	u32 bulk_num;
	struct dpp_apt_hash_bulk_res_t *bulk;
	u32 ser_num;
	struct dpp_apt_hash_table_t *ser;
};

DPP_STATUS dpp_apt_dtb_hash_table_unicast_mac_dump(struct dpp_dev_t *dev, u32 queue_id, u32 sdt_no,
						   struct zxdh_l2_fwd_t *pHashDataArr,
						   u32 *p_entry_num);
DPP_STATUS dpp_apt_dtb_hash_table_multicast_mac_dump(struct dpp_dev_t *dev, u32 queue_id,
						     u32 sdt_no, struct zxdh_mc_t *pHashDataArr,
						     u32 *p_entry_num);
struct se_apt_hash_convert_t *se_hash_callback_get(u32 sdt_no);
#endif
