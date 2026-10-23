// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_include.h"
#include "nbl_flow_draco.h"
#include "nbl_tc_flow.h"
#include "nbl_tc_pedit.h"
#include "nbl_fc_draco.h"
#include "nbl_tc_flow_draco.h"
#include "nbl_resource_draco.h"
#include "nbl_phy_draco.h"
#include "nbl_tc_tun_draco.h"

atomic_t g_mirror_cnt = ATOMIC_INIT(0);

static struct nbl_profile_msg g_prf_msg_draco[NBL_ALL_PROFILE_NUM] = {
	/* profile for tunneled l2, need to consider tunnel decap, full flow length */
	[11] = {
		.valid = 1,
		.pp_mode = 0,
		.key_full = 1,
		.pt_cmd = 0,
		.from_start = 1,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 11,
		.g_profile_id = 11,
		.lkp_id = 6,
		.key_count = 8,
		.key_len = 184,
		.key_flag = 0x4000E804031,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {13, 14, 15, 16, 17, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)0,
				.offset = 0,
				.length = 4,
				.key_id = 0,
				.name = "profileID",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 8,
				.length = 16,
				.key_id = 27,
				.name = "etherType",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 24,
				.length = 48,
				.key_id = 23,
				.name = "dstMAC",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 72,
				.length = 16,
				.key_id = 25,
				.name = "vlan1_pcv",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 88,
				.length = 16,
				.key_id = 26,
				.name = "vlan2_pcv",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 104,
				.length = 32,
				.key_id = 5,
				.name = "t_vni",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 136,
				.length = 32,
				.key_id = 4,
				.name = "t_ovn_data",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 168,
				.length = 16,
				.key_id = 42,
				.name = "sport",
			},
		},
	},
	/* profile for non-tunnel l2, no tunnel related fields, half flow length */
	[12] = {
		.valid = 1,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 1,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 12,
		.g_profile_id = 12,
		.lkp_id = 7,
		.key_count = 6,
		.key_len = 120,
		.key_flag = 0x4000E800001,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {13, 14, 15, 16, 17, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)0,
				.offset = 0,
				.length = 4,
				.key_id = 0,
				.name = "profileID",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 8,
				.length = 16,
				.key_id = 27,
				.name = "etherType",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 24,
				.length = 48,
				.key_id = 23,
				.name = "dstMAC",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 72,
				.length = 16,
				.key_id = 25,
				.name = "vlan1_pcv",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 88,
				.length = 16,
				.key_id = 26,
				.name = "vlan2_pcv",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 104,
				.length = 16,
				.key_id = 42,
				.name = "sport",
			},
		},
	},
	[13] = {
		.valid = 1,
		.pp_mode = 1,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 13,
		.g_profile_id = 13,
		.lkp_id = 8,
		.key_count = 9,
		.key_len = 144,
		.key_flag = 0xD30280001,
		.act_count = 0,
		.pre_assoc_profile_id = {11, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)0,
				.offset = 0,
				.length = 4,
				.key_id = 0,
				.name = "profileID",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 8,
				.length = 8,
				.key_id = 32,
				.name = "protocol",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 16,
				.length = 16,
				.key_id = 28,
				.name = "srcPort",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 32,
				.length = 16,
				.key_id = 29,
				.name = "dstPort",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 48,
				.length = 8,
				.key_id = 35,
				.name = "ttl",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 56,
				.length = 8,
				.key_id = 34,
				.name = "tos",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 64,
				.length = 32,
				.key_id = 19,
				.name = "sip",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 96,
				.length = 32,
				.key_id = 21,
				.name = "dip",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 128,
				.length = 16,
				.key_id = 0,
				.name = "tab_index",
			},
		},
	},
	[14] = {
		.valid = 1,
		.pp_mode = 1,
		.key_full = 1,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 14,
		.g_profile_id = 14,
		.lkp_id = 9,
		.key_count = 7,
		.key_len = 320,
		.key_flag = 0x130500001,
		.act_count = 0,
		.pre_assoc_profile_id = {11, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)0,
				.offset = 0,
				.length = 4,
				.key_id = 0,
				.name = "profileID",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 8,
				.length = 8,
				.key_id = 32,
				.name = "protocol",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 16,
				.length = 16,
				.key_id = 28,
				.name = "srcPort",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 32,
				.length = 16,
				.key_id = 29,
				.name = "dstPort",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 48,
				.length = 128,
				.key_id = 20,
				.name = "sip",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 176,
				.length = 128,
				.key_id = 22,
				.name = "dip",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 304,
				.length = 16,
				.key_id = 0,
				.name = "tab_index",
			},
		},
	},
	[15] = {
		.valid = 1,
		.pp_mode = 1,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 15,
		.g_profile_id = 15,
		.lkp_id = 8,
		.key_count = 9,
		.key_len = 144,
		.key_flag = 0xD30280001,
		.act_count = 0,
		.pre_assoc_profile_id = {11, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)0,
				.offset = 0,
				.length = 4,
				.key_id = 0,
				.name = "profileID",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 8,
				.length = 8,
				.key_id = 32,
				.name = "protocol",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 16,
				.length = 16,
				.key_id = 28,
				.name = "srcPort",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 32,
				.length = 16,
				.key_id = 29,
				.name = "dstPort",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 48,
				.length = 8,
				.key_id = 35,
				.name = "ttl",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 56,
				.length = 8,
				.key_id = 34,
				.name = "tos",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 64,
				.length = 32,
				.key_id = 19,
				.name = "sip",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 96,
				.length = 32,
				.key_id = 21,
				.name = "dip",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 128,
				.length = 16,
				.key_id = 0,
				.name = "tab_index",
			},
		},
	},
	[16] = {
		.valid = 1,
		.pp_mode = 1,
		.key_full = 1,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 16,
		.g_profile_id = 16,
		.lkp_id = 9,
		.key_count = 7,
		.key_len = 320,
		.key_flag = 0x130500001,
		.act_count = 0,
		.pre_assoc_profile_id = {11, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)0,
				.offset = 0,
				.length = 4,
				.key_id = 0,
				.name = "profileID",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 8,
				.length = 8,
				.key_id = 32,
				.name = "protocol",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 16,
				.length = 16,
				.key_id = 28,
				.name = "srcPort",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 32,
				.length = 16,
				.key_id = 29,
				.name = "dstPort",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 48,
				.length = 128,
				.key_id = 20,
				.name = "sip",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 176,
				.length = 128,
				.key_id = 22,
				.name = "dip",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 304,
				.length = 16,
				.key_id = 0,
				.name = "tab_index",
			},
		},
	},
	[17] = {
		.valid = 1,
		.pp_mode = 1,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 17,
		.g_profile_id = 17,
		.lkp_id = 8,
		.key_count = 6,
		.key_len = 144,
		.key_flag = 0xD00200001,
		.act_count = 0,
		.pre_assoc_profile_id = {11, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)0,
				.offset = 0,
				.length = 4,
				.key_id = 0,
				.name = "profileID",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 8,
				.length = 8,
				.key_id = 32,
				.name = "protocol",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 48,
				.length = 8,
				.key_id = 35,
				.name = "ttl",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 56,
				.length = 8,
				.key_id = 34,
				.name = "tos",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 96,
				.length = 32,
				.key_id = 21,
				.name = "dip",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 128,
				.length = 16,
				.key_id = 0,
				.name = "tab_index",
			},
		},
	},
	[18] = {
		.valid = 1,
		.pp_mode = 1,
		.key_full = 1,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 18,
		.g_profile_id = 18,
		.lkp_id = 9,
		.key_count = 4,
		.key_len = 320,
		.key_flag = 0x100400001,
		.act_count = 0,
		.pre_assoc_profile_id = {11, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)0,
				.offset = 0,
				.length = 4,
				.key_id = 0,
				.name = "profileID",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 8,
				.length = 8,
				.key_id = 32,
				.name = "protocol",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 176,
				.length = 128,
				.key_id = 22,
				.name = "dip",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 304,
				.length = 16,
				.key_id = 0,
				.name = "tab_index",
			},
		},
	},
};

static struct nbl_profile_assoc_graph g_prf_graph_draco[NBL_FLOW_ASSOC_PROFILE_GRAPH_NUM] = {
	{
		.key_flag = 0x240D3EA84031,
		.profile_count = 2,
		.profile_id = {11, 13},
	},
	{
		.key_flag = 0x24013ED04031,
		.profile_count = 2,
		.profile_id = {11, 14},
	},
	{
		.key_flag = 0x440D3EA84031,
		.profile_count = 2,
		.profile_id = {11, 15},
	},
	{
		.key_flag = 0x44013ED04031,
		.profile_count = 2,
		.profile_id = {11, 16},
	},
	{
		.key_flag = 0x40D0EA04031,
		.profile_count = 2,
		.profile_id = {11, 17},
	},
	{
		.key_flag = 0x40D0EC04031,
		.profile_count = 2,
		.profile_id = {11, 18},
	},
	{
		.key_flag = 0x4000E804031,
		.profile_count = 1,
		.profile_id = {11},
	},
	{
		.key_flag = 0x240D3EA80001,
		.profile_count = 2,
		.profile_id = {12, 13},
	},
	{
		.key_flag = 0x24013ED00001,
		.profile_count = 2,
		.profile_id = {12, 14},
	},
	{
		.key_flag = 0x440D3EA80001,
		.profile_count = 2,
		.profile_id = {12, 15},
	},
	{
		.key_flag = 0x44013ED00001,
		.profile_count = 2,
		.profile_id = {12, 16},
	},
	{
		.key_flag = 0x40D0EA00001,
		.profile_count = 2,
		.profile_id = {12, 17},
	},
	{
		.key_flag = 0x4010EC00001,
		.profile_count = 2,
		.profile_id = {12, 18},
	},
	{
		.key_flag = 0x4000E800001,
		.profile_count = 1,
		.profile_id = {12},
	},
};

static inline void nbl_cond_lock_resource(struct mutex *lock, bool is_lock)
{
	if (is_lock)
		mutex_lock(lock);
	else
		return;
}

static inline void nbl_cond_unlock_resource(struct mutex *lock, bool is_lock)
{
	if (is_lock)
		mutex_unlock(lock);
	else
		return;
}

int nbl_bitmap_mng_init(struct nbl_bitmap_mng *bmp_mng,
			u16 size, bool use_lock, bool skip_zero)
{
	bmp_mng->safe_lock = use_lock;
	bmp_mng->bmp_size = size;
	bmp_mng->skip_zero = skip_zero;

	if (bmp_mng->safe_lock)
		mutex_init(&bmp_mng->bmp_lock);

	bmp_mng->id_bmp = kcalloc(BITS_TO_LONGS(size), sizeof(long), GFP_KERNEL);
	if (!bmp_mng->id_bmp)
		return -ENOMEM;

	return 0;
}

void nbl_bitmap_mng_release(struct nbl_bitmap_mng *bmp_mng)
{
	nbl_cond_lock_resource(&bmp_mng->bmp_lock, bmp_mng->safe_lock);
	kfree(bmp_mng->id_bmp);
	nbl_cond_unlock_resource(&bmp_mng->bmp_lock, bmp_mng->safe_lock);
}

int nbl_bitmap_mng_alloc_id(struct nbl_bitmap_mng *bmp_mng, u32 *id)
{
	u32 idx;
	int ret = 0;

	if (!bmp_mng->id_bmp || !bmp_mng->bmp_size)
		return -EINVAL;

	nbl_cond_lock_resource(&bmp_mng->bmp_lock, bmp_mng->safe_lock);

	for (;;) {
		idx = find_first_zero_bit(bmp_mng->id_bmp, bmp_mng->bmp_size);
		if (idx == bmp_mng->bmp_size) {
			ret = -ERANGE;
			goto end;
		}
		set_bit(idx, bmp_mng->id_bmp);
		if (idx == 0 && bmp_mng->skip_zero)
			continue;
		*id = idx;
		break;
	}
end:
	nbl_cond_unlock_resource(&bmp_mng->bmp_lock, bmp_mng->safe_lock);

	return ret;
}

void nbl_bitmap_mng_release_id(struct nbl_bitmap_mng *bmp_mng, u32 id)
{
	if (!bmp_mng->id_bmp || !bmp_mng->bmp_size)
		return;

	nbl_cond_lock_resource(&bmp_mng->bmp_lock, bmp_mng->safe_lock);
	clear_bit(id, bmp_mng->id_bmp);
	nbl_cond_unlock_resource(&bmp_mng->bmp_lock, bmp_mng->safe_lock);
}

static void nbl_bitmap_mng_set_id(struct nbl_bitmap_mng *bmp_mng, u32 id)
{
	if (!bmp_mng || !bmp_mng->id_bmp)
		return;

	nbl_cond_lock_resource(&bmp_mng->bmp_lock, bmp_mng->safe_lock);
	set_bit(id, bmp_mng->id_bmp);
	nbl_cond_unlock_resource(&bmp_mng->bmp_lock, bmp_mng->safe_lock);
}

void nbl_bitmap_mng_reset(struct nbl_bitmap_mng *bmp_mng)
{
	nbl_cond_lock_resource(&bmp_mng->bmp_lock, bmp_mng->safe_lock);
	memset(bmp_mng->id_bmp, 0, BITS_TO_LONGS(bmp_mng->bmp_size) * sizeof(long));
	nbl_cond_unlock_resource(&bmp_mng->bmp_lock, bmp_mng->safe_lock);
}

static int nbl_flow_cfg_req_head_ktalloc(union nbl_fem_cmd_head_u *req_head,
					 struct nbl_flow_param *param)
{
	memset(req_head->head_data, 0x0, sizeof(req_head->head_data));

	req_head->info.module = NBL_FEM_CMD_HEAD_MODULE_FEM;
	req_head->info.opcode = NBL_FEM_CMD_HEAD_OPCODE_KTALLOC;
	req_head->info.cmd_len = NBL_DRACO_CMD_KTBLOCK_LEN;

	return 0;
}

static int nbl_flow_cfg_req_param_ktalloc(union nbl_fem_cmd_data_u *data,
					  struct nbl_flow_param *param)
{
	union nbl_fem_req_param_ktalloc_u *req_param = (union nbl_fem_req_param_ktalloc_u *)data;

	memset(req_param->param_data, 0x0, sizeof(req_param->param_data));
	req_param->info.pf_id = param->pf_id;

	return 0;
}

static int nbl_flow_cfg_req_head_ktfree(union nbl_fem_cmd_head_u *req_head,
					struct nbl_flow_param *param)
{
	memset(req_head->head_data, 0x0, sizeof(req_head->head_data));

	req_head->info.module = NBL_FEM_CMD_HEAD_MODULE_FEM;
	req_head->info.opcode = NBL_FEM_CMD_HEAD_OPCODE_KTFREE;
	req_head->info.cmd_len = NBL_DRACO_CMD_KTBLOCK_LEN;

	return 0;
}

static int nbl_flow_cfg_req_param_ktfree(union nbl_fem_cmd_data_u *data,
					 struct nbl_flow_param *param)
{
	union nbl_fem_req_param_ktfree_u *req_param = (union nbl_fem_req_param_ktfree_u *)data;

	memset(req_param->param_data, 0x0, sizeof(req_param->param_data));

	if (param->free_all) {
		req_param->info.mode = NBL_FEM_CMD_PARAM_KTFREE_MODE_PF;
	} else {
		req_param->info.mode = NBL_FEM_CMD_PARAM_KTFREE_MODE_KT_IDX;
		req_param->info.kt_idx = param->start_kt_index;
	}
	req_param->info.pf_id = param->pf_id;
	req_param->info.hmc = param->hmc;

	return 0;
}

static int nbl_flow_cfg_req_head_tbladd(union nbl_fem_cmd_head_u *req_head,
					struct nbl_flow_param *param)
{
	memset(req_head->head_data, 0x0, sizeof(req_head->head_data));

	req_head->info.module = NBL_FEM_CMD_HEAD_MODULE_FEM;
	req_head->info.opcode = NBL_FEM_CMD_HEAD_OPCODE_TBLADD;
	req_head->info.cmd_len = NBL_DRACO_CMD_TBLADD_LEN;

	return 0;
}

static int nbl_flow_cfg_req_param_tbladd(union nbl_fem_cmd_data_u *data,
					 struct nbl_flow_param *param)
{
	union nbl_fem_req_param_tbladd_u *req_param = (union nbl_fem_req_param_tbladd_u *)data;

	memset(req_param->param_data, 0x0, sizeof(req_param->param_data));

	req_param->info.pf_id = param->pf_id;
	req_param->info.hmc = param->hmc;
	req_param->info.oft = param->alloc_oft;
	req_param->info.kt_mode = param->kt_mode;
	req_param->info.kt_idx = param->kt_idx;
	memcpy(req_param->info.key, param->key, param->key_len);

	return 0;
}

static int nbl_flow_cfg_req_head_tbllookup(union nbl_fem_cmd_head_u *req_head,
					   struct nbl_flow_param *param)
{
	memset(req_head->head_data, 0x0, sizeof(req_head->head_data));

	req_head->info.module = NBL_FEM_CMD_HEAD_MODULE_FEM;
	req_head->info.opcode = NBL_FEM_CMD_HEAD_OPCODE_TBLLOOKUP;
	req_head->info.cmd_len = NBL_DRACO_CMD_TBLLKP_LEN;

	return 0;
}

static int nbl_flow_cfg_req_param_tbllookup(union nbl_fem_cmd_data_u *data,
					    struct nbl_flow_param *param)
{
	union nbl_fem_req_param_tbllookup_u *req_param;

	req_param = (union nbl_fem_req_param_tbllookup_u *)data;
	memset(req_param->param_data, 0x0, sizeof(req_param->param_data));

	req_param->info.sport_flag = param->template;
	req_param->info.del_on_hit = param->del_on_hit;
	req_param->info.mode = param->lkp_mode;
	req_param->info.pf_id = param->pf_id;
	req_param->info.hmc = param->hmc;
	memcpy(req_param->info.lkp_key, param->key, NBL_DRACO_FULL_KEY_BYTES);
	req_param->info.ht_id = param->ht_id;
	req_param->info.ht_slot_id = param->ht_slot_id;
	req_param->info.kt_idx = param->kt_idx;

	return 0;
}

static int nbl_flow_cfg_req_head_tblwrite(union nbl_fem_cmd_head_u *req_head,
					  struct nbl_flow_param *param)
{
	memset(req_head->head_data, 0x0, sizeof(req_head->head_data));

	req_head->info.module = NBL_FEM_CMD_HEAD_MODULE_FEM;
	req_head->info.opcode = NBL_FEM_CMD_HEAD_OPCODE_TBLWRITE;
	req_head->info.cmd_len = NBL_DRACO_CMD_TBLWRITE_LEN;
	req_head->info.table = param->tbl_to_write;

	return 0;
}

static int nbl_flow_cfg_req_param_tblwrite(union nbl_fem_cmd_data_u *data,
					   struct nbl_flow_param *param)
{
	union nbl_fem_req_param_tblwrite_u *req_param;

	req_param = (union nbl_fem_req_param_tblwrite_u *)data;
	memset(req_param->param_data, 0x0, sizeof(req_param->param_data));

	switch (param->tbl_to_write) {
	case NBL_DRACO_DFT_TBL:
		req_param->dft_tbl.pf_id = param->pf_id;
		req_param->dft_tbl.tbl_addr = param->dft_addr;
		break;
	case NBL_DRACO_PROFILE_TBL:
	default:
		break;
	}

	memcpy(req_param->dft_tbl.data, param->tbl, NBL_DRACO_CMD_TBLWRITE_DATALEN);
	return 0;
}

static int nbl_flow_cfg_req_head_tblread(union nbl_fem_cmd_head_u *req_head,
					 struct nbl_flow_param *param)
{
	memset(req_head->head_data, 0x0, sizeof(req_head->head_data));

	req_head->info.module = NBL_FEM_CMD_HEAD_MODULE_FEM;
	req_head->info.opcode = NBL_FEM_CMD_HEAD_OPCODE_TBLREAD;
	req_head->info.cmd_len = NBL_DRACO_CMD_TBLREAD_LEN;

	return 0;
}

static int nbl_flow_cfg_req_param_tblread(union nbl_fem_cmd_data_u *data,
					  struct nbl_flow_param *param)
{
	union nbl_fem_req_param_tblread_u *req_param;

	req_param = (union nbl_fem_req_param_tblread_u *)data;
	memset(req_param->param_data, 0x0, sizeof(req_param->param_data));

	switch (param->tbl_to_read) {
	case NBL_DRACO_OFTAD_TBL_TO_READ:
		req_param->oftad.pf_id = param->pf_id;
		req_param->oftad.tbl_addr = param->read_addr & 0x3f;
		break;
	case NBL_DRACO_KT_BIND_PF_TBL_TO_READ:
		req_param->kt_bind_pf.pf_id = param->pf_id;
		break;
	default:
		break;
	}
	return 0;
}

#define NBL_FLOW_CMD_OPS_ARR_ENTRY(type, cfg_req_head_func, cfg_req_param_func)	\
	[type] = {.cfg_req_head = cfg_req_head_func,				\
		  .cfg_req_param = cfg_req_param_func,				\
		}

static const struct nbl_fem_cmd_cfg_ops cmd_cfg_ops[] = {
	NBL_FLOW_CMD_OPS_ARR_ENTRY(NBL_FEM_CMD_HEAD_OPCODE_KTALLOC,
				   nbl_flow_cfg_req_head_ktalloc,
				   nbl_flow_cfg_req_param_ktalloc),
	NBL_FLOW_CMD_OPS_ARR_ENTRY(NBL_FEM_CMD_HEAD_OPCODE_KTFREE,
				   nbl_flow_cfg_req_head_ktfree,
				   nbl_flow_cfg_req_param_ktfree),
	NBL_FLOW_CMD_OPS_ARR_ENTRY(NBL_FEM_CMD_HEAD_OPCODE_TBLADD,
				   nbl_flow_cfg_req_head_tbladd,
				   nbl_flow_cfg_req_param_tbladd),
	NBL_FLOW_CMD_OPS_ARR_ENTRY(NBL_FEM_CMD_HEAD_OPCODE_TBLLOOKUP,
				   nbl_flow_cfg_req_head_tbllookup,
				   nbl_flow_cfg_req_param_tbllookup),
	NBL_FLOW_CMD_OPS_ARR_ENTRY(NBL_FEM_CMD_HEAD_OPCODE_TBLWRITE,
				   nbl_flow_cfg_req_head_tblwrite,
				   nbl_flow_cfg_req_param_tblwrite),
	NBL_FLOW_CMD_OPS_ARR_ENTRY(NBL_FEM_CMD_HEAD_OPCODE_TBLREAD,
				   nbl_flow_cfg_req_head_tblread,
				   nbl_flow_cfg_req_param_tblread),
};

static int nbl_tc_flow_parse_eth_after(const void *rule,
				       struct nbl_flow_pattern_conf *filter,
				       u16 flag)
{
	filter->key_flag |= NBL_FLOW_KEY_INPORT16_FLAG;

	return 0;
}

static int nbl_tc_flow_parse_vlan_after(const void *rule,
					struct nbl_flow_pattern_conf *filter,
					u16 flag)
{
	filter->key_flag |= NBL_FLOW_KEY_SVLAN_FLAG;

	return 0;
}

static int nbl_tc_flow_parse_cvlan_after(const void *rule,
					 struct nbl_flow_pattern_conf *filter,
					 u16 flag)
{
	struct flow_match_vlan match;
	const struct flow_rule *tc_rule = (const struct flow_rule *)rule;

	flow_rule_match_cvlan(tc_rule, &match);
	if (match.key && match.mask) {
		if (flag & BIT(NBL_FLOW_ITEM_KEY_MASK)) {
			if (match.mask->vlan_id != NBL_FLOW_TABLE_VLAN_MASK_AS_U12 &&
			    match.mask->vlan_id != 0)
				filter->wildcard_flow = 1;
		} else {
			if (match.mask->vlan_id != VLAN_VID_MASK) {
				nbl_info(filter->common, NBL_DEBUG_FLOW,
					 "tc flow fuzzy cvlan mask 0x%04x is not supported.\n",
					 match.mask->vlan_id);
				return -EOPNOTSUPP;
			}
		}

		filter->input.cvlan_tag = match.key->vlan_id & 0xFFF;
		filter->input.cvlan_mask = match.mask->vlan_id;
		filter->input.cvlan_type = filter->input.svlan_type;
		filter->input.vlan_cnt++;
		filter->input.is_cvlan = true;
		nbl_debug(filter->common, NBL_DEBUG_FLOW,
			  "parse cvlan, wildcard_flow:%u, cvlan_id=%d/0x%x, cvlan_type=0x%04x",
			  filter->wildcard_flow, filter->input.cvlan_tag, filter->input.cvlan_mask,
			  filter->input.cvlan_type);
	}

	filter->key_flag |= NBL_FLOW_KEY_CVLAN_FLAG;

	return 0;
}

static int nbl_tc_flow_parse_icmp_after(const void *rule,
					struct nbl_flow_pattern_conf *filter,
					u16 flag)
{
	const struct flow_rule *tc_rule = (const struct flow_rule *)rule;
	struct flow_match_icmp match;

	if (filter->input.ip.proto != IPPROTO_ICMP && filter->input.ip.proto != IPPROTO_ICMPV6)
		return 0;

	flow_rule_match_icmp(tc_rule, &match);

	if (flag & BIT(NBL_FLOW_ITEM_DKEY_MASK) || flag & BIT(NBL_FLOW_ITEM_SKEY_MASK)) {
		if (flag & BIT(NBL_FLOW_ITEM_DKEY_MASK) &&
		    match.mask->code != 0 && match.mask->code != NBL_FLOW_TABLE_FULL_MASK_AS_U8)
			filter->wildcard_flow = 1;
		if (flag & BIT(NBL_FLOW_ITEM_SKEY_MASK) &&
		    match.mask->type != 0 && match.mask->type != NBL_FLOW_TABLE_FULL_MASK_AS_U8)
			filter->wildcard_flow = 1;
	} else {
		if (match.mask->code != 0 && match.mask->code != NBL_FLOW_TABLE_FULL_MASK_AS_U8) {
			nbl_debug(filter->common, NBL_DEBUG_FLOW, "icmp code must exact, now is:0x%x/0x%x",
				  match.key->code, match.mask->code);
			return -EOPNOTSUPP;
		}
	}

	if (match.key && match.mask) {
		filter->input.l4.src_port = (match.key->type << NBL_BITS_IN_U8 | match.key->code);
		filter->input.l4_mask.src_port =
					(match.mask->type << NBL_BITS_IN_U8 | match.mask->code);

		filter->input.l4.dst_port = 1;
		filter->input.l4_mask.dst_port = NBL_U16_MASK;

		filter->key_flag |= NBL_FLOW_KEY_DSTPORT_FLAG;
		filter->key_flag |= NBL_FLOW_KEY_SRCPORT_FLAG;
		filter->key_flag |= NBL_FLOW_KEY_MARK_IS_ICMP_SCTP;
	}

	nbl_debug(filter->common, NBL_DEBUG_FLOW,
		  "icmp after: code:%u/0x%x, type:%u/0x%x, wildcard_flow:%u ",
		  match.key->code, match.mask->code, match.key->type, match.mask->type,
		  filter->wildcard_flow);

	return 0;
}

static int nbl_tc_flow_parse_tcp_udp_after(const void *rule,
					   struct nbl_flow_pattern_conf *filter,
					   u16 flag)
{
	const struct flow_rule *tc_rule = (const struct flow_rule *)rule;
	struct flow_match_ports port;

	flow_rule_match_ports(tc_rule, &port);

	if (filter->input.ip.proto == IPPROTO_TCP || filter->input.ip.proto == IPPROTO_UDP) {
		if (port.key && port.mask)
			filter->key_flag |= NBL_FLOW_KEY_MARK_IS_TCP_UDP;
	}

	return 0;
}

static enum nbl_flow_vlan_type nbl_flow_get_vlan_idx(u16 vlan)
{
	switch (vlan) {
	case NBL_VLAN_TPID_VALUE:
		return NBL_FLOW_VLAN_TYPE_VLAN;
	case NBL_QINQ_TPID_VALUE:
		return NBL_FLOW_VLAN_TYPE_QINQ;
	default:
		return NBL_FLOW_VLAN_TYPE_QINQ2;
	}
	return NBL_FLOW_VLAN_TYPE_VLAN;
}

static int nbl_tc_flow_push_vlan_after(struct nbl_rule_action *rule_act,
				       const void *act_entry,
				       struct nbl_flow_pattern_conf *filter)
{
	int ret = 0;
	u64 flag = 0;
	struct nbl_common_info *common = filter->common;
	struct nbl_flow_item_vlan vlan;
	const struct flow_action_entry *tc_act = (const struct flow_action_entry *)act_entry;
	u16 vlan_type = htons(tc_act->vlan.proto);

	if (vlan_type != NBL_VLAN_TPID_VALUE && vlan_type != NBL_QINQ_TPID_VALUE) {
		nbl_err(common, NBL_DEBUG_FLOW, "push vlan only support vlan and qinq.");
		return -EOPNOTSUPP;
	}

	flag = rule_act->flag;
	memcpy(&vlan, &rule_act->vlan_info, sizeof(vlan));

	if (vlan.push_vlan_cnt > NBL_FLOW_TAB_TWO_TIME) {
		nbl_err(common, NBL_DEBUG_FLOW, "Push vlan max time is two.");
		return -EOPNOTSUPP;
	}

	if (vlan.push_vlan_cnt)
		vlan.ovlan_idx = nbl_flow_get_vlan_idx(vlan_type);
	else
		vlan.ivlan_idx = nbl_flow_get_vlan_idx(vlan_type);

	vlan.push_vlan_cnt++;
	vlan.cur_push_num++;

	switch (vlan.last_vlan) {
	case VLAN_NULL:
		if (filter->input.vlan_cnt == 0) {
			flag |= NBL_FLOW_ACTION_PUSH_INNER_VLAN;
			vlan.last_vlan = VLAN_PUSH_INNER;
		} else if (filter->input.vlan_cnt == 1) {
			flag |= NBL_FLOW_ACTION_PUSH_OUTER_VLAN;
			vlan.last_vlan = VLAN_PUSH_OUTER;
		} else {
			ret = -EOPNOTSUPP;
			nbl_err(common, NBL_DEBUG_FLOW, "2 vlans not support push\n");
		}
		/* PUSH */
		vlan.vlan_op = NBL_FLOW_VLAN_PUSH;
		break;
	case VLAN_POP_INNER:
		if (flag | NBL_FLOW_ACTION_POP_INNER_VLAN) {
			flag &= (~NBL_FLOW_ACTION_POP_INNER_VLAN);
			if (filter->input.vlan_cnt == 1)
				flag |= NBL_FLOW_ACTION_REPLACE_SINGLE_INNER_VLAN;
			else if (filter->input.vlan_cnt == 2)
				flag |= NBL_FLOW_ACTION_REPLACE_INNER_VLAN;
			else
				ret = -EOPNOTSUPP;

			/* POP->POP->PUSH */
			if (vlan.vlan_op == NBL_FLOW_VLAN_POP2)
				vlan.vlan_op = NBL_FLOW_VLAN_REP_IVLAN_POP;
			/* POP->PUSH */
			else if (vlan.vlan_op == NBL_FLOW_VLAN_POP)
				vlan.vlan_op = NBL_FLOW_VLAN_REP_OVLAN;

			if (vlan.cur_pop_num) {
				vlan.cur_pop_num--;
				vlan.last_vlan = VLAN_REPLACE_INNER;
			} else {
				ret = -EOPNOTSUPP;
			}

		} else {
			/* POP->PUSH->PUSH */
			vlan.vlan_op = NBL_FLOW_VLAN_PUSH_REP;
			flag |= NBL_FLOW_ACTION_PUSH_INNER_VLAN;
			vlan.last_vlan = VLAN_PUSH_INNER;
		}
		break;
	case VLAN_POP_OUTER:
		if (flag | NBL_FLOW_ACTION_POP_OUTER_VLAN) {
			flag &= (~NBL_FLOW_ACTION_POP_OUTER_VLAN);
			flag |= NBL_FLOW_ACTION_REPLACE_OUTER_VLAN;
			if (vlan.cur_pop_num) {
				vlan.cur_pop_num--;
				vlan.last_vlan = VLAN_REPLACE_OUTER;
			} else {
				ret = -EOPNOTSUPP;
			}
			/* POP->POP->PUSH */
			if (filter->input.vlan_cnt == 1)
				vlan.vlan_op = NBL_FLOW_VLAN_REP_IVLAN_POP;
			/* POP->PUSH */
			else
				vlan.vlan_op = NBL_FLOW_VLAN_REP_OVLAN;

		} else {
			/* POP->PUSH */
			vlan.vlan_op = NBL_FLOW_VLAN_REP_OVLAN;
			flag |= NBL_FLOW_ACTION_PUSH_OUTER_VLAN;
			vlan.last_vlan = VLAN_PUSH_OUTER;
		}
		break;
	case VLAN_PUSH_INNER:
		flag |= NBL_FLOW_ACTION_PUSH_OUTER_VLAN;
		vlan.last_vlan = VLAN_PUSH_OUTER;
		/* PUSH->PUSH */
		vlan.vlan_op = NBL_FLOW_VLAN_PUSH2;
		break;
	case VLAN_REPLACE_INNER:
		if (flag | NBL_FLOW_ACTION_POP_OUTER_VLAN) {
			/* POP->POP->PUSH->PUSH */
			vlan.vlan_op = NBL_FLOW_VLAN_REP_BOTH;
			flag &= (~NBL_FLOW_ACTION_POP_OUTER_VLAN);
			flag |= NBL_FLOW_ACTION_REPLACE_OUTER_VLAN;
			if (vlan.cur_pop_num) {
				vlan.cur_pop_num--;
				vlan.last_vlan = VLAN_REPLACE_OUTER;
			} else {
				ret = -EOPNOTSUPP;
			}
		} else {
			/* POP->PUSH->PUSH */
			if (vlan.vlan_op == NBL_FLOW_VLAN_REP_OVLAN)
				vlan.vlan_op = NBL_FLOW_VLAN_PUSH_REP;
			/* POP->POP->PUSH->PUSH */
			else if (vlan.vlan_op == NBL_FLOW_VLAN_PUSH_REP)
				vlan.vlan_op = NBL_FLOW_VLAN_REP_BOTH;
			else
				ret = -EOPNOTSUPP;
			flag |= NBL_FLOW_ACTION_PUSH_OUTER_VLAN;
			vlan.last_vlan = VLAN_PUSH_OUTER;
		}
		break;
	default:
		nbl_err(common, NBL_DEBUG_FLOW, "Unsupport last type:%u in push.", vlan.last_vlan);
		return -EOPNOTSUPP;
	}

	/* got a vlan already, and push a new vlan, ivlan_idx need transfer to ovlan_idx */
	if (filter->input.vlan_cnt == 1 &&
	    (vlan.vlan_op == NBL_FLOW_VLAN_PUSH || vlan.vlan_op == NBL_FLOW_VLAN_REP_OVLAN))
		vlan.has_vlan = 1;

	/* parse the vlan tag value */
	if (vlan.last_vlan == VLAN_PUSH_INNER || vlan.last_vlan == VLAN_REPLACE_INNER) {
		vlan.ivlan_tag = tc_act->vlan.vid;
		vlan.ivlan_tag |= tc_act->vlan.prio << NBL_VLAN_PCP_SHIFT;
	} else if (vlan.last_vlan == VLAN_PUSH_OUTER || vlan.last_vlan == VLAN_REPLACE_OUTER) {
		vlan.ovlan_tag = tc_act->vlan.vid;
		vlan.ovlan_tag |= tc_act->vlan.prio << NBL_VLAN_PCP_SHIFT;
	}
	memcpy(&rule_act->vlan_info, &vlan, sizeof(vlan));
	rule_act->flag = flag;

	return ret;
}

static int nbl_tc_flow_pop_vlan_after(struct nbl_rule_action *rule_act,
				      const void *act_entry,
				      struct nbl_flow_pattern_conf *filter)
{
	int ret = 0;
	u64 flag = 0;
	struct nbl_flow_item_vlan vlan;

	memcpy(&vlan, &rule_act->vlan_info, sizeof(vlan));
	flag = rule_act->flag;

	if (vlan.pop_vlan_cnt > NBL_FLOW_TAB_TWO_TIME) {
		nbl_err(filter->common, NBL_DEBUG_FLOW, "Pop vlan max time is two.");
		return -EOPNOTSUPP;
	}

	vlan.pop_vlan_cnt++;
	vlan.cur_pop_num++;

	switch (vlan.last_vlan) {
	case VLAN_NULL:
		if (filter->input.vlan_cnt == 1) {
			flag |= NBL_FLOW_ACTION_POP_INNER_VLAN;
			vlan.last_vlan = VLAN_POP_INNER;
		} else if (filter->input.vlan_cnt == 2) {
			flag |= NBL_FLOW_ACTION_POP_OUTER_VLAN;
			vlan.last_vlan = VLAN_POP_OUTER;
		}
		/* POP only when key got vlan */
		if (filter->input.vlan_cnt)
			vlan.vlan_op = NBL_FLOW_VLAN_POP;
		else
			ret = -EOPNOTSUPP;
		break;
	case VLAN_POP_OUTER:
		if (vlan.cur_push_num == 1) {
			/* POP->PUSH->POP = POP, so no need update vlan_op in this case */
			flag &= (~NBL_FLOW_ACTION_PUSH_INNER_VLAN);
			vlan.cur_push_num--;
			vlan.cur_pop_num--;
		} else if (vlan.cur_push_num == 0) {
			flag |= NBL_FLOW_ACTION_POP_INNER_VLAN;
			/* POP->POP */
			if (vlan.vlan_op == NBL_FLOW_VLAN_POP)
				vlan.vlan_op = NBL_FLOW_VLAN_POP2;
			/* PUSH->POP->POP */
			else if (vlan.vlan_op == NBL_FLOW_VLAN_RSV)
				vlan.vlan_op = NBL_FLOW_VLAN_POP;
			else
				ret = -EOPNOTSUPP;
		} else {
			/* POP->PUSH->PUSH->POP = POP->PUSH */
			vlan.vlan_op = NBL_FLOW_VLAN_REP_OVLAN;
		}
		vlan.last_vlan = VLAN_POP_INNER;
		break;
	case VLAN_PUSH_INNER:
		flag &= (~NBL_FLOW_ACTION_PUSH_INNER_VLAN);
		if (vlan.cur_push_num) {
			vlan.cur_push_num--;
			vlan.cur_pop_num--;
			vlan.last_vlan = VLAN_POP_INNER;
		} else {
			ret = -EOPNOTSUPP;
		}
		/* PUSH->POP */
		vlan.vlan_op = NBL_FLOW_VLAN_NULL;
		break;
	case VLAN_PUSH_OUTER:
		flag &= (~NBL_FLOW_ACTION_PUSH_OUTER_VLAN);
		if (vlan.cur_push_num) {
			vlan.cur_push_num--;
			vlan.cur_pop_num--;
			vlan.last_vlan = VLAN_POP_OUTER;
		} else {
			ret = -EOPNOTSUPP;
		}
		if (filter->input.vlan_cnt == 1)
			vlan.vlan_op = NBL_FLOW_VLAN_RSV;
		else if (filter->input.vlan_cnt == 0)
			vlan.vlan_op = NBL_FLOW_VLAN_PUSH;
		else
			ret = -EOPNOTSUPP;
		break;
	case VLAN_REPLACE_INNER:
		if (flag & NBL_FLOW_ACTION_REPLACE_INNER_VLAN)
			flag &= (~NBL_FLOW_ACTION_REPLACE_INNER_VLAN);
		else
			flag &= (~NBL_FLOW_ACTION_REPLACE_SINGLE_INNER_VLAN);

		flag |= NBL_FLOW_ACTION_POP_INNER_VLAN;
		if (vlan.cur_push_num) {
			vlan.cur_push_num--;
			vlan.last_vlan = VLAN_POP_INNER;
		} else {
			ret = -EOPNOTSUPP;
		}
		/* POP->PUSH->POP */
		vlan.vlan_op = NBL_FLOW_VLAN_POP;
		break;
	case VLAN_REPLACE_OUTER:
		flag &= (~NBL_FLOW_ACTION_REPLACE_OUTER_VLAN);
		flag |= NBL_FLOW_ACTION_POP_OUTER_VLAN;
		if (vlan.cur_push_num) {
			vlan.cur_push_num--;
			vlan.last_vlan = VLAN_POP_OUTER;
		} else {
			ret = -EOPNOTSUPP;
		}
		vlan.vlan_op = NBL_FLOW_VLAN_POP;
		break;
	default:
		ret = -EOPNOTSUPP;
	}

	if (ret) {
		nbl_err(filter->common, NBL_DEBUG_FLOW, "Unsupport last type:%u in pop, ret %d",
			vlan.last_vlan, ret);
		return ret;
	}

	memcpy(&rule_act->vlan_info, &vlan, sizeof(vlan));
	rule_act->flag = flag;

	return 0;
}

static int nbl_tc_flow_set_parse_info(struct nbl_tc_flow_mgt *tc_flow_mgt)
{
	u16 type;

	tc_flow_mgt->parse_info = kzalloc(sizeof(*tc_flow_mgt->parse_info), GFP_KERNEL);
	if (!tc_flow_mgt->parse_info)
		return -ENOMEM;

	tc_flow_mgt->parse_info->set_in_port_info = NULL;
	tc_flow_mgt->parse_info->set_out_port_info = NULL;

	/* set act parse info */
	type = BIT(NBL_FLOW_ITEM_DKEY_MASK) | BIT(NBL_FLOW_ITEM_SKEY_MASK);

	memset(tc_flow_mgt->parse_info->key_parse_info, 0,
	       sizeof(tc_flow_mgt->parse_info->key_parse_info));
	memset(tc_flow_mgt->parse_info->act_parse_info, 0,
	       sizeof(tc_flow_mgt->parse_info->act_parse_info));

	tc_flow_mgt->parse_info->key_parse_info[FLOW_DISSECTOR_KEY_ETH_ADDRS].mask_type = type;
	tc_flow_mgt->parse_info->key_parse_info[FLOW_DISSECTOR_KEY_IPV4_ADDRS].mask_type = type;
	tc_flow_mgt->parse_info->key_parse_info[FLOW_DISSECTOR_KEY_IPV6_ADDRS].mask_type = type;
	tc_flow_mgt->parse_info->key_parse_info[FLOW_DISSECTOR_KEY_PORTS].mask_type = type;
	tc_flow_mgt->parse_info->key_parse_info[FLOW_DISSECTOR_KEY_ICMP].mask_type = type;

	type = BIT(NBL_FLOW_ITEM_KEY_MASK);
	tc_flow_mgt->parse_info->key_parse_info[FLOW_DISSECTOR_KEY_VLAN].mask_type = type;
	tc_flow_mgt->parse_info->key_parse_info[FLOW_DISSECTOR_KEY_ENC_IP].mask_type = type;
	tc_flow_mgt->parse_info->key_parse_info[FLOW_DISSECTOR_KEY_ENC_PORTS].mask_type = type;
	tc_flow_mgt->parse_info->key_parse_info[FLOW_DISSECTOR_KEY_ENC_KEYID].mask_type = type;
	tc_flow_mgt->parse_info->key_parse_info[FLOW_DISSECTOR_KEY_ENC_CONTROL].mask_type = type;

	tc_flow_mgt->parse_info->key_parse_info[FLOW_DISSECTOR_KEY_ETH_ADDRS].parse_func_after =
								nbl_tc_flow_parse_eth_after;
	tc_flow_mgt->parse_info->key_parse_info[FLOW_DISSECTOR_KEY_VLAN].parse_func_after =
								nbl_tc_flow_parse_vlan_after;
	tc_flow_mgt->parse_info->key_parse_info[FLOW_DISSECTOR_KEY_CVLAN].parse_func_after =
								nbl_tc_flow_parse_cvlan_after;
	tc_flow_mgt->parse_info->key_parse_info[FLOW_DISSECTOR_KEY_ICMP].parse_func_after =
								nbl_tc_flow_parse_icmp_after;
	tc_flow_mgt->parse_info->key_parse_info[FLOW_DISSECTOR_KEY_PORTS].parse_func_after =
								nbl_tc_flow_parse_tcp_udp_after;

	/* set act parse info */
	tc_flow_mgt->parse_info->act_parse_info[FLOW_ACTION_VLAN_PUSH].ignore_parse_action = 1;
	tc_flow_mgt->parse_info->act_parse_info[FLOW_ACTION_VLAN_PUSH].parse_func_after =
									nbl_tc_flow_push_vlan_after;
	tc_flow_mgt->parse_info->act_parse_info[FLOW_ACTION_VLAN_POP].ignore_parse_action = 1;
	tc_flow_mgt->parse_info->act_parse_info[FLOW_ACTION_VLAN_POP].parse_func_after =
									nbl_tc_flow_pop_vlan_after;

	nbl_info(tc_flow_mgt->res_mgt->common, NBL_DEBUG_FLOW, "tc flow set parse info finish");

	return 0;
}

/* Structure starts here, adding an op should not modify anything below */
static int nbl_tc_flow_setup_mgt_draco(struct device *dev, struct nbl_tc_flow_mgt **tc_flow_mgt)
{
	int ret = 0;
	struct nbl_index_tbl_key flow_idx_tbl_key;

	*tc_flow_mgt = devm_kzalloc(dev, sizeof(struct nbl_tc_flow_mgt), GFP_KERNEL);
	if (!(*tc_flow_mgt))
		return -ENOMEM;

	NBL_INDEX_TBL_KEY_INIT(&flow_idx_tbl_key, dev, 0, NBL_FLOW_INDEX_LEN,
			       sizeof(struct nbl_flow_index_key));

	(*tc_flow_mgt)->flow_idx_tbl = nbl_common_init_index_table(&flow_idx_tbl_key);
	if (!(*tc_flow_mgt)->flow_idx_tbl) {
		ret = -ENOMEM;
		goto flow_idx_tbl_failed;
	}

	(*tc_flow_mgt)->priv_flow_mgt =
		devm_kzalloc(dev, sizeof(struct nbl_draco_flow_mgt), GFP_KERNEL);
	if (!(*tc_flow_mgt)->priv_flow_mgt) {
		ret = -ENOMEM;
		goto draco_mgt_failed;
	}

	return ret;

draco_mgt_failed:
	nbl_common_remove_index_table((*tc_flow_mgt)->flow_idx_tbl, NULL);
flow_idx_tbl_failed:
	devm_kfree(dev, *tc_flow_mgt);
	*tc_flow_mgt = NULL;

	return ret;
}

static void nbl_tc_flow_free_tc_mgt(struct device *dev, struct nbl_tc_flow_mgt *tc_flow_mgt)
{
	if (tc_flow_mgt && tc_flow_mgt->priv_flow_mgt)
		devm_kfree(dev, tc_flow_mgt->priv_flow_mgt);
	if (tc_flow_mgt && tc_flow_mgt->flow_idx_tbl)
		nbl_common_remove_index_table(tc_flow_mgt->flow_idx_tbl, NULL);
	if (tc_flow_mgt)
		devm_kfree(dev, tc_flow_mgt);
}

static int nbl_tc_flow_init_profile_and_hash_tbl(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_draco_flow_mgt *draco_flow_mgt = tc_flow_mgt->priv_flow_mgt;
	struct nbl_flow_node_param flow_param;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_hash_tbl_key tbl_key;
	int idx = 0;
	int ret = 0;

	memset(&tbl_key, 0, sizeof(tbl_key));

	tc_flow_mgt->profile_graph_count = ARRAY_SIZE(g_prf_graph_draco);
	memcpy(tc_flow_mgt->profile_msg, g_prf_msg_draco,
	       sizeof(struct nbl_profile_msg) * NBL_ALL_PROFILE_NUM);
	memcpy(tc_flow_mgt->profile_graph, g_prf_graph_draco,
	       sizeof(struct nbl_profile_assoc_graph) * NBL_ASSOC_PROFILE_GRAPH_NUM);

	for (; idx < NBL_DRACO_MAX_PROFILE_NUM; ++idx) {
		if (tc_flow_mgt->profile_msg[idx].key_full)
			flow_param.entries = NBL_DRACO_MAX_FULL_FLOW_KT_NUM_HASH;
		else
			flow_param.entries = NBL_DRACO_MAX_HALF_FLOW_KT_NUM_HASH;
		flow_param.key_len = NBL_DRACO_FLOW_GET_LEN(idx);

		NBL_HASH_TBL_KEY_INIT(&tbl_key, NBL_COMMON_TO_DEV(common),
				      sizeof(struct nbl_draco_flow_tab_conf),
				      sizeof(struct nbl_draco_flow_node), flow_param.entries, true);
		tc_flow_mgt->flow_tab_hash[idx].flow_tab_hash =
						nbl_common_init_hash_table(&tbl_key);
		if (!tc_flow_mgt->flow_tab_hash[idx].flow_tab_hash) {
			nbl_err(common, NBL_DEBUG_FLOW, "tc flow init profile %u failed.", idx);
			ret = -ENOMEM;
			goto flow_tab_hash_err;
		}

		nbl_info(common, NBL_DEBUG_FLOW, "tc flow init profile:%u with %u entries",
			 idx, flow_param.entries);
	}

	draco_flow_mgt->res_mgt = res_mgt;

	return ret;

flow_tab_hash_err:
	for (; idx >= 0; idx--) {
		if (tc_flow_mgt->flow_tab_hash[idx].flow_tab_hash)
			nbl_common_remove_hash_table(tc_flow_mgt->flow_tab_hash[idx].flow_tab_hash,
						     NULL);
	}

	return ret;
}

static void nbl_tc_flow_free_profile_and_hash_tbl(struct nbl_resource_mgt *res_mgt)
{
	int idx = 0;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);

	for (; idx < NBL_DRACO_MAX_PROFILE_NUM; ++idx) {
		if (tc_flow_mgt->flow_tab_hash[idx].flow_tab_hash) {
			nbl_common_remove_hash_table(tc_flow_mgt->flow_tab_hash[idx].flow_tab_hash,
						     NULL);
			tc_flow_mgt->flow_tab_hash[idx].flow_tab_hash = NULL;
		}
	}
}

static int nbl_tc_flow_init_kt_and_assoc_tbl_draco(struct nbl_resource_mgt *res_mgt)
{
	int ret = 0;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_draco_flow_mgt *draco_flow_mgt = tc_flow_mgt->priv_flow_mgt;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_hash_tbl_key kt_tbl_key;

	memset(&kt_tbl_key, 0, sizeof(kt_tbl_key));

	/* init assoc tbl*/
	ret = nbl_bitmap_mng_init(&draco_flow_mgt->assoc_table_mng,
				  NBL_DRACO_MAX_TBL_ID, true, true);
	if (ret) {
		nbl_err(common, NBL_DEBUG_FLOW, "nbl alloc assoc tbl failed, ret %d", ret);
		return ret;
	}

	/* kt resource */
	mutex_init(&draco_flow_mgt->kt_mgt.kt_lock);
	mutex_init(&draco_flow_mgt->kt_mgt.full_kt_lock);
	mutex_init(&draco_flow_mgt->kt_mgt.half_kt_lock);

	INIT_LIST_HEAD(&draco_flow_mgt->kt_mgt.kt_half_list);
	INIT_LIST_HEAD(&draco_flow_mgt->kt_mgt.kt_full_list);

	NBL_HASH_TBL_KEY_INIT(&kt_tbl_key, NBL_COMMON_TO_DEV(common),
			      sizeof(u8),
			      sizeof(struct nbl_draco_kt_node),
			      NBL_DRACO_KT_MAX_BLOCK, false);
	draco_flow_mgt->kt_mgt.kt_hash.flow_tab_hash = nbl_common_init_hash_table(&kt_tbl_key);
	if (!draco_flow_mgt->kt_mgt.kt_hash.flow_tab_hash) {
		nbl_bitmap_mng_release(&draco_flow_mgt->assoc_table_mng);
		return -ENOMEM;
	}

	/* init tcam */
	spin_lock_init(&draco_flow_mgt->tcam_lock);
	draco_flow_mgt->tcam_eviction_enabled = 1;

	return 0;
}

static void nbl_tc_flow_free_kt_and_assoc_tbl_draco(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_draco_flow_mgt *draco_flow_mgt = tc_flow_mgt->priv_flow_mgt;

	if (draco_flow_mgt->assoc_table_mng.id_bmp)
		nbl_bitmap_mng_release(&draco_flow_mgt->assoc_table_mng);

	if (draco_flow_mgt->kt_mgt.kt_hash.flow_tab_hash) {
		nbl_common_remove_hash_table(draco_flow_mgt->kt_mgt.kt_hash.flow_tab_hash, NULL);
		draco_flow_mgt->kt_mgt.kt_hash.flow_tab_hash = NULL;
	}
}

static void nbl_tc_flow_set_ped_init_para(struct nbl_draco_flow_mgt *draco_mgt)
{
	memset(draco_mgt->pedit_res, 0, sizeof(draco_mgt->pedit_res));

	mutex_init(&draco_mgt->ped_lock[NBL_DRACO_PED_UMAC_TYPE]);
	draco_mgt->pedit_res[NBL_DRACO_PED_UMAC_TYPE].pedit_num = NBL_DRACO_MAC_PED_NUM_HASH;
	draco_mgt->pedit_res[NBL_DRACO_PED_UMAC_TYPE].pedit_key_len = NBL_MAC_ADDR_LEN_AS_U8;
	draco_mgt->pedit_res[NBL_DRACO_PED_UMAC_TYPE].pedit_data_len =
						sizeof(struct nbl_tc_pedit_entry);

	mutex_init(&draco_mgt->ped_lock[NBL_DRACO_PED_UIP_TYPE]);
	draco_mgt->pedit_res[NBL_DRACO_PED_UIP_TYPE].pedit_num = NBL_DRACO_IP_PED_NUM_HASH;
	draco_mgt->pedit_res[NBL_DRACO_PED_UIP_TYPE].pedit_key_len = NBL_IPV6_ADDR_LEN_AS_U8;
	draco_mgt->pedit_res[NBL_DRACO_PED_UIP_TYPE].pedit_data_len =
						sizeof(struct nbl_tc_pedit_entry);

	mutex_init(&draco_mgt->ped_lock[NBL_DRACO_PED_TNL_TYPE]);
	draco_mgt->pedit_res[NBL_DRACO_PED_TNL_TYPE].pedit_num = NBL_DRACO_TNL_ENCAP_NUM_HASH;
	draco_mgt->pedit_res[NBL_DRACO_PED_TNL_TYPE].pedit_key_len =
						sizeof(struct nbl_flow_tnl_prof_node);
	draco_mgt->pedit_res[NBL_DRACO_PED_TNL_TYPE].pedit_data_len =
						sizeof(struct nbl_flow_tnl_prof_hnode);

	mutex_init(&draco_mgt->ped_lock[NBL_DRACO_PED_TNL_VTEP_TYPE]);
	draco_mgt->pedit_res[NBL_DRACO_PED_TNL_VTEP_TYPE].pedit_num = NBL_DRACO_TNL_VTEP_NUM;
	draco_mgt->pedit_res[NBL_DRACO_PED_TNL_VTEP_TYPE].pedit_key_len =
						sizeof(struct nbl_flow_tnl_vtep_node);
	draco_mgt->pedit_res[NBL_DRACO_PED_TNL_VTEP_TYPE].pedit_data_len =
						sizeof(struct nbl_flow_tnl_vtep_hnode);

	mutex_init(&draco_mgt->ped_lock[NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE]);
	draco_mgt->pedit_res[NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE].pedit_num =
								NBL_DRACO_TNL_VTEP_NUM - 1;
	draco_mgt->pedit_res[NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE].pedit_key_len =
						sizeof(struct nbl_flow_tnl_decap_tcam_node);
	draco_mgt->pedit_res[NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE].pedit_data_len =
						sizeof(struct nbl_flow_tnl_decap_tcam_hnode);
}

static int nbl_tc_flow_init_ped_res_draco(struct nbl_resource_mgt *res_mgt)
{
	int ret = 0;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_draco_flow_mgt *draco_mgt = tc_flow_mgt->priv_flow_mgt;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	nbl_tc_flow_set_ped_init_para(draco_mgt);

	ret = nbl_tc_pedit_init(common, draco_mgt->pedit_res, NBL_DRACO_PED_MAX);
	if (ret)
		nbl_info(common, NBL_DEBUG_FLOW, "tc flow init pedit failed, ret %d", ret);
	else
		nbl_info(common, NBL_DEBUG_FLOW, "tc flow init pedit success");

	return ret;
}

static void nbl_tc_flow_uninit_ped_res_draco(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_draco_flow_mgt *draco_mgt = tc_flow_mgt->priv_flow_mgt;
	int ret = 0;

	ret = nbl_tc_pedit_uninit(draco_mgt->pedit_res, NBL_DRACO_PED_MAX);
	if (ret)
		nbl_info(common, NBL_DEBUG_FLOW, "tc_pedit uninit failed");
	else
		nbl_info(common, NBL_DEBUG_FLOW, "tc_pedit uninit success");
}

static void nbl_tc_flow_mcc_init(struct nbl_tc_flow_mgt *tc_flow_mgt)
{
	tc_flow_mgt->tc_mcc_mgt.common = tc_flow_mgt->res_mgt->common;
	INIT_LIST_HEAD(&tc_flow_mgt->tc_mcc_mgt.mcc_list);
}

/**
 * @brief: init flow tab all resource
 *
 * @param[in] dev: the dev resource
 * @return  void
 *
 * the list of function is as follows:
 * 1. init nbl_tc_flow profile and hash tbl
 * 2. init kt and assoc tbl
 * 3. init action
 * 4. init counter
 */
static int nbl_tc_flow_init_tc_flow_draco(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	int ret = 0;

	tc_flow_mgt->res_mgt = res_mgt;

	nbl_flow_clean_create_destroy_cnt(tc_flow_mgt);

	mutex_init(&tc_flow_mgt->flow_lock);

	ret = nbl_tc_flow_init_profile_and_hash_tbl(res_mgt);
	if (ret)
		return ret;

	ret = nbl_tc_flow_init_kt_and_assoc_tbl_draco(res_mgt);
	if (ret)
		goto init_kt_res_err;

	ret = nbl_tc_flow_init_ped_res_draco(res_mgt);
	if (ret)
		goto init_ped_res_err;

	nbl_tc_flow_mcc_init(tc_flow_mgt);

	nbl_tc_flow_set_parse_info(tc_flow_mgt);

	/* todo: mcc acl.... */

	if (ret == 0) {
		nbl_flow_set_resource_init_status(tc_flow_mgt, true);
		nbl_flow_resource_available(tc_flow_mgt);
	} else {
		return ret;
	}

	/* not available still now, depends on mbx */
	return ret;
init_ped_res_err:
	nbl_tc_flow_free_kt_and_assoc_tbl_draco(res_mgt);
init_kt_res_err:
	nbl_tc_flow_free_profile_and_hash_tbl(res_mgt);

	return ret;
}

static int nbl_tc_flow_free_resource(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);

	if (!nbl_flow_is_available(tc_flow_mgt))
		return -EINVAL;

	mutex_lock(&tc_flow_mgt->flow_lock);

	nbl_tc_flow_free_profile_and_hash_tbl(res_mgt);
	nbl_tc_flow_free_kt_and_assoc_tbl_draco(res_mgt);
	nbl_tc_flow_uninit_ped_res_draco(res_mgt);
	kfree(tc_flow_mgt->parse_info);
	tc_flow_mgt->parse_info = NULL;

	mutex_unlock(&tc_flow_mgt->flow_lock);

	return 0;
}

static int nbl_tc_flow_free_tc_flow_draco(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt **tc_flow_mgt = &NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	bool available;

	if (!(*tc_flow_mgt))
		return -EINVAL;

	if (!nbl_flow_is_resource_ready(*tc_flow_mgt))
		return -EINVAL;

	available = nbl_flow_is_available(*tc_flow_mgt);

	/* Mark resource unavailable first to prevent new operations */
	nbl_flow_resource_unavailable(*tc_flow_mgt);

	/* Wait for in-flight operations to complete */
	mdelay(NBL_SAFE_THREADS_WAIT_TIME);
	nbl_flow_wait_flows_free_done(*tc_flow_mgt);
	synchronize_rcu();

	if (available)
		nbl_tc_flow_free_resource(res_mgt);

	nbl_flow_set_resource_init_status(*tc_flow_mgt, false);

	return 0;
}

int nbl_tc_flow_mgt_start_draco(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt **tc_flow_mgt;
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	int ret = 0;

	tc_flow_mgt = &NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);

	if (res_mgt->tc_flow_mgt) {
		if (nbl_flow_is_resource_ready(res_mgt->tc_flow_mgt))
			return ret;
	}

	ret = nbl_tc_flow_setup_mgt_draco(dev, tc_flow_mgt);
	if (ret)
		return ret;

	ret = nbl_fc_mgt_start_draco(res_mgt);
	if (ret)
		goto fc_mgt_start_err;

	ret = nbl_tc_flow_init_tc_flow_draco(res_mgt);
	if (ret)
		goto tc_flow_init_err;

	return ret;

tc_flow_init_err:
	nbl_fc_mgt_stop_draco(res_mgt);
fc_mgt_start_err:
	nbl_tc_flow_free_tc_mgt(dev, *tc_flow_mgt);
	*tc_flow_mgt = NULL;
	return ret;
}

int nbl_tc_flow_mgt_stop_draco(struct nbl_resource_mgt *res_mgt)
{
	int ret;
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_tc_flow_mgt **tc_flow_mgt = &NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);

	ret = nbl_tc_flow_free_tc_flow_draco(res_mgt);
	if (ret)
		return ret;

	nbl_fc_mgt_stop_draco(res_mgt);
	nbl_tc_flow_free_tc_mgt(dev, *tc_flow_mgt);
	*tc_flow_mgt = NULL;

	return 0;
}

static void nbl_get_tc_flow_parse_info(void *priv, struct nbl_tc_parse_info **parse_info)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);

	if (!tc_flow_mgt || !nbl_flow_is_available(tc_flow_mgt)) {
		*parse_info = NULL;
		return;
	}

	*parse_info = tc_flow_mgt->parse_info;
}

static bool nbl_flow_graph_lookup(struct nbl_tc_flow_mgt *tc_flow_mgt,
				  struct nbl_flow_pattern_conf *filter, bool is_acl)
{
	bool find_graph = false;
	u8 i = 0;
	u8 graph_count = tc_flow_mgt->profile_graph_count;
	struct nbl_profile_assoc_graph *graph = tc_flow_mgt->profile_graph;
	struct nbl_draco_flow_mgt *draco_flow_mgt = tc_flow_mgt->priv_flow_mgt;

	/* draco todo: acl res not ready */
	if (is_acl) {
		graph = draco_flow_mgt->acl_mgt->profile_graph;
		graph_count = (u8)draco_flow_mgt->acl_mgt->profile_graph_count;
	}

	if (filter->key_flag == 0)
		goto end;

	for (i = 0; i < graph_count; i++) {
		if (graph[i].key_flag == 0)
			continue;

		if ((graph[i].key_flag & ~NBL_FLOW_KEY_TABLE_IDX_FLAG) ==
		    (graph[i].key_flag & filter->key_flag)) {
			filter->graph_idx = i;
			if (is_acl)
				filter->acl_graph_idx = i;
			find_graph = true;
			goto end;
		}
	}

end:
	nbl_debug(tc_flow_mgt->res_mgt->common, NBL_DEBUG_FLOW, "graph find ret: %u, is_acl: %u, graph_idx: %u, acl_graph_idx:%u, key_flag:0x%llx",
		  find_graph, is_acl, filter->graph_idx, filter->acl_graph_idx, filter->key_flag);
	return find_graph;
}

static void nbl_draco_assign_assoc_tbl_id(struct nbl_tc_flow *tc_flow_ptr,
					  struct nbl_profile_offload_msg *offload_msg, int i)
{
	struct nbl_draco_flow_node *pre_node;
	u8 pre_stage = 0;

	pre_stage = offload_msg[i - 1].profile_stage;
	pre_node = (struct nbl_draco_flow_node *)(tc_flow_ptr->profile_rule[pre_stage]);
	offload_msg[i - 1].act_assoc_tbl_id = pre_node->assoc_tbl_id;
	offload_msg[i].assoc_tbl_id = pre_node->assoc_tbl_id;
}

static void nbl_draco_encode_port(struct nbl_tc_flow_param *param)
{
	union nbl_draco_sport_u sport;

	memset(&sport, 0, sizeof(sport));

	switch (param->in.type)	{
	case NBL_TC_PORT_TYPE_VSI:
		sport.tx.dir = NBL_DRACO_SPORT_DIR_TX;
		sport.tx.vsi_id = param->in.id;
		break;
	case NBL_TC_PORT_TYPE_ETH:
		sport.rx.dir = NBL_DRACO_SPORT_DIR_RX;
		sport.rx.eth_id = param->in.id;
		break;
	case NBL_TC_PORT_TYPE_BOND:
		sport.rx.dir = NBL_DRACO_SPORT_DIR_RX;
		sport.rx.lag = 1;
		sport.rx.lag_id = param->in.id;
		break;
	default:
		nbl_debug(param->common, NBL_DEBUG_FLOW, "tc flow unknown in port type:%u",
			  (u32)param->in.type);
		break;
	}

	param->filter.input.encoded_port = sport.data;
	param->filter.input.encoded_port_mask = NBL_FLOW_TABLE_FULL_MASK_AS_U16;

	switch (param->out.type) {
	case NBL_TC_PORT_TYPE_VSI:
		param->act.port_id = param->out.id;
		break;
	case NBL_TC_PORT_TYPE_ETH:
		param->act.port_id = param->out.id + NBL_FLOW_ETH_REP_0;
		break;
	case NBL_TC_PORT_TYPE_BOND:
		param->act.port_id = NBL_FLOW_BOND_REP_PORT_ID;
		param->act.lag_id = param->out.id;
		break;
	default:
		nbl_debug(param->common, NBL_DEBUG_FLOW, "tc flow unknown out port type:%u",
			  (u32)param->out.type);
		break;
	}

	nbl_debug(param->common, NBL_DEBUG_FLOW, "nbl draco encode port: param:out.type:%u, out.id:%u, act.port_id:%u",
		  param->out.type, param->out.id, param->act.port_id);
}

/* Get the res_mgt that owns the shared DECAP_VTEP hash table and index pool.
 * In bond mode, returns master PF's res_mgt (the bond member with smaller eth_id,
 * since eth_info->eth_id[] is ascending, smaller eth_id maps to lower pf_id).
 * Otherwise returns the current res_mgt.
 * This ensures bond member PFs share the same decap_vtep hash table and index pool,
 * while non-bond PFs keep independent resources.
 */
static struct nbl_resource_mgt *
nbl_draco_decap_get_target_res_mgt(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_eth_bond_info *eth_bond_info = NBL_RES_MGT_TO_ETH_BOND_INFO(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct pci_dev *master_pdev = NULL;
	struct nbl_adapter *master_adapter = NULL;
	struct nbl_resource_mgt *master_res_mgt = res_mgt;
	u8 eth_id;
	u8 master_eth_id;
	u8 master_pf_id;
	int lag_id, mem_id;

	eth_id = NBL_COMMON_TO_ETH_ID(common);
	if (!eth_bond_info || !eth_info)
		return res_mgt;

	for (lag_id = 0; lag_id < NBL_LAG_MAX_NUM; lag_id++) {
		if (!eth_bond_info->entry[lag_id].lag_num)
			continue;
		for (mem_id = 0; mem_id < NBL_LAG_MAX_PORTS; mem_id++) {
			if (eth_bond_info->entry[lag_id].eth_id[mem_id] == eth_id)
				goto get_master;
		}
	}

	return res_mgt;

get_master:
	/* use smaller eth_id */
	if (eth_bond_info->entry[lag_id].eth_id[0] > eth_bond_info->entry[lag_id].eth_id[1])
		master_eth_id = eth_bond_info->entry[lag_id].eth_id[1];
	else
		master_eth_id = eth_bond_info->entry[lag_id].eth_id[0];

	/* reverse lookup pf_id (logic_eth_id) from eth_id, then pci_get_slot */
	master_pf_id = eth_info->logic_eth_id[master_eth_id];
	master_pdev = pci_get_slot(common->pdev->bus,
				   PCI_DEVFN(PCI_SLOT(common->pdev->devfn), master_pf_id));
	if (!master_pdev)
		return res_mgt;

	master_adapter = pci_get_drvdata(master_pdev);
	pci_dev_put(master_pdev);
	if (!master_adapter)
		return res_mgt;

	master_res_mgt = NBL_ADAPTER_TO_RES_MGT(master_adapter);
	if (!master_res_mgt)
		return res_mgt;

	return master_res_mgt;
}

static int nbl_draco_decap_vtep_alloc_free_idx(struct nbl_resource_mgt *res_mgt,
					       u32 *alloc_idx, u32 free_idx, bool alloc)
{
	/* In bond mode, DECAP_VTEP index is allocated/freed use common PF's pool;
	 * in non-bond mode, from the current PF's pool.
	 */
	struct nbl_resource_mgt *target_res_mgt = nbl_draco_decap_get_target_res_mgt(res_mgt);
	struct nbl_common_info *target_common = NBL_RES_MGT_TO_COMMON(target_res_mgt);
	struct pci_dev *pdev = target_common->pdev;

	if (alloc)
		return nbl_devshr_alloc_idx(NBL_DEVSHR_INDEX_DECAP_VTEP, pdev, alloc_idx);
	return nbl_devshr_free_idx(NBL_DEVSHR_INDEX_DECAP_VTEP, pdev, free_idx);
}

static int nbl_draco_flow_get_vtep_key(struct nbl_resource_mgt *res_mgt,
				       struct nbl_flow_pattern_conf *filter,
				       struct nbl_rule_action *action)
{
#define BUF_LEN 128
	int ret = 0, i = 0, offset = 0;
	u32 decap_idx = 0;
	const struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	/* In bond mode, decap_vtep hash table and index pool are shared between
	 * bond members via the master PF; in non-bond mode, each PF uses its own.
	 */
	struct nbl_resource_mgt *target_res_mgt = nbl_draco_decap_get_target_res_mgt(res_mgt);
	struct nbl_tc_flow_mgt *tc_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(target_res_mgt);
	struct nbl_draco_flow_mgt *mgt = tc_mgt->priv_flow_mgt;
	void *pedit_tbl = mgt->pedit_res[NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE].pedit_tbl;
	struct nbl_flow_tnl_decap_tcam_hnode decap_node;
	struct nbl_flow_tnl_decap_tcam_hnode *search_decap_node = NULL;
	struct nbl_flow_tnl_decap_tcam_node decap_key;
	char dip_buf[BUF_LEN];

	memset(&decap_key, 0, sizeof(decap_key));
	memset(&decap_node, 0, sizeof(decap_node));
	memset(dip_buf, 0, sizeof(dip_buf));

	memcpy(decap_key.dip, &filter->input.ip_outer.dst_ip, NBL_IPV6_ADDR_LEN_AS_U8);
	decap_key.tnl_type = NBL_TNL_VXLAN_TYPE;
	decap_key.tnl_base = 1;
	decap_key.dmac_mask = 1;
	decap_key.cvlan_mask = 1;
	decap_key.svlan_mask = 1;
	decap_key.cvlan_tpid_mask = 1;
	decap_key.svlan_tpid_mask = 1;
	decap_key.valid_bit = 1;

	offset += snprintf(dip_buf + offset, BUF_LEN - offset, "dip:");
	for (i = 0; i < 16 && offset < BUF_LEN - 4; i++) {
		if (i == 15)
			offset += snprintf(dip_buf + offset, BUF_LEN - offset, "%02hhx",
					   decap_key.dip[i]);
		else
			offset += snprintf(dip_buf + offset, BUF_LEN - offset, "%02hhx:",
					   decap_key.dip[i]);
	}

	mutex_lock(&mgt->ped_lock[NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE]);

	search_decap_node = nbl_common_get_hash_node(pedit_tbl, &decap_key);
	if (search_decap_node) {
		search_decap_node->ref_cnt++;
		action->vtep_info.vtep_is_ref = 1;
		decap_idx = search_decap_node->decap_assd_node.loc_vtep_id;
		nbl_debug(common, NBL_DEBUG_FLOW, "TNL Decap exist, %s", dip_buf);
	} else {
		ret = nbl_draco_decap_vtep_alloc_free_idx(res_mgt, &decap_idx, 0, true);
		if (ret) {
			mutex_unlock(&mgt->ped_lock[NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE]);
			nbl_err(common, NBL_DEBUG_FLOW, "alloc decap idx failed, ret:%d,\n %s",
				ret, dip_buf);
			return ret;
		}

		if (decap_idx == 0) {
			ret = nbl_draco_decap_vtep_alloc_free_idx(res_mgt, &decap_idx, 0, true);
			if (ret) {
				mutex_unlock(&mgt->ped_lock[NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE]);
				nbl_err(common, NBL_DEBUG_FLOW, "alloc decap idx failed, ret:%d,\n%s",
					ret, dip_buf);
				return ret;
			}
		}

		decap_node.decap_tcam_key = decap_key;
		decap_node.ref_cnt = 1;
		decap_node.decap_assd_node.loc_vtep_id = decap_idx;
		decap_node.decap_assd_node.vlan_lmt = 3;

		ret = nbl_common_alloc_hash_node(pedit_tbl, &decap_key, &decap_node,
						 (void **)&search_decap_node);
		if (ret) {
			nbl_draco_decap_vtep_alloc_free_idx(res_mgt, NULL, decap_idx, false);
			mutex_unlock(&mgt->ped_lock[NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE]);
			nbl_err(common, NBL_DEBUG_FLOW, "alloc decap hash node failed, ret:%d,\n%s",
				ret, dip_buf);
			return ret;
		}
	}

	action->ped_info.ped_info[NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE].data = search_decap_node;
	action->ped_info.ped_info[NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE].ped_idx = decap_idx;
	action->ped_info.ped_info[NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE].ped_valid = 1;

	mutex_unlock(&mgt->ped_lock[NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE]);

	action->vtep_info.vtep_vld = 1;
	action->vtep_info.vtep_id = (u8)decap_idx;

	nbl_debug(common, NBL_DEBUG_FLOW, "alloc decap finish, decap_idx:%u, ref_cnt:%u, ret:%d,\ndip:%s",
		  decap_idx, search_decap_node->ref_cnt, ret, dip_buf);

	return ret;
}

static void nbl_draco_free_ped_decap_vtep(struct nbl_draco_flow_mgt *mgt, void *pedit_tbl,
					  struct nbl_flow_tnl_decap_tcam_hnode *decap_node)
{
	struct nbl_flow_tnl_decap_tcam_hnode *search_decap_node = NULL;
	struct nbl_flow_tnl_decap_tcam_hnode decap_node_zero;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(mgt->res_mgt);
	u8 decap_idx = 0;
	bool need_del_hw = false;

	if (!decap_node)
		return;

	memset(&decap_node_zero, 0, sizeof(decap_node_zero));

	mutex_lock(&mgt->ped_lock[NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE]);
	search_decap_node = nbl_common_get_hash_node(pedit_tbl, &decap_node->decap_tcam_key);
	if (search_decap_node) {
		search_decap_node->ref_cnt--;
		if (search_decap_node->ref_cnt) {
			mutex_unlock(&mgt->ped_lock[NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE]);
			goto end;
		} else {
			need_del_hw = true;
			decap_idx = search_decap_node->decap_assd_node.loc_vtep_id;
			nbl_draco_decap_vtep_alloc_free_idx(mgt->res_mgt, NULL, decap_idx, false);
			nbl_common_free_hash_node(pedit_tbl, &decap_node->decap_tcam_key);
		}
	}
	mutex_unlock(&mgt->ped_lock[NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE]);

	if (need_del_hw) {
		phy_ops->write_ped_tbl(NBL_RES_MGT_TO_PHY_PRIV(mgt->res_mgt),
				       (u8 *)&decap_node_zero.decap_tcam_key,
				       decap_idx, NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE);
		phy_ops->write_ped_tbl(NBL_RES_MGT_TO_PHY_PRIV(mgt->res_mgt),
				       (u8 *)&decap_node_zero.decap_assd_node,
				       decap_idx, NBL_DRACO_PED_TNL_DECAP_ASSD_TYPE);
	}
end:
	nbl_debug(mgt->res_mgt->common, NBL_DEBUG_FLOW, "del decap vtep: decap idx:%u, del_hw:%u",
		  decap_idx, need_del_hw);
}

static void nbl_draco_free_decap_vtep_node(struct nbl_resource_mgt *res_mgt,
					   struct nbl_rule_action *action)
{
	/* In bond mode, the decap_vtep hash node was inserted into master PF's
	 * pedit_tbl, so free must target the same table; in non-bond, use current PF.
	 */
	struct nbl_resource_mgt *target_res_mgt = nbl_draco_decap_get_target_res_mgt(res_mgt);
	struct nbl_tc_flow_mgt *tc_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(target_res_mgt);
	struct nbl_draco_flow_mgt *mgt = tc_mgt->priv_flow_mgt;
	void *pedit_tbl = mgt->pedit_res[NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE].pedit_tbl;
	struct nbl_flow_tnl_decap_tcam_hnode *decap_node =
				action->ped_info.ped_info[NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE].data;

	nbl_draco_free_ped_decap_vtep(mgt, pedit_tbl, decap_node);

	action->ped_info.ped_info[NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE].data = NULL;
	action->ped_info.ped_info[NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE].ped_valid = 0;
}

static void nbl_draco_flow_assign_decap_key(struct nbl_draco_flow_tab_conf *node_key,
					    struct nbl_draco_vtep_info *vtep_info)
{
	u32 vtep_id = vtep_info->vtep_id;

	if (!vtep_info->vtep_vld)
		return;

	/* assign vtep key */
	if (!vtep_id)
		vtep_id = NBL_DRACO_TNL_VTEP_NUM - 1;

	nbl_assign_key(node_key->key_value, 0, NBL_DRACO_UDF_LOC_VTEP_OFT,
		       NBL_DRACO_UDF_LOC_VTEP_LEN, vtep_id);
}

static int nbl_draco_flow_decap_process(struct nbl_resource_mgt *res_mgt,
					struct nbl_flow_pattern_conf *filter,
					struct nbl_rule_action *action,
					struct nbl_draco_flow_tab_conf *key)
{
	int ret = 0;

	if (!(action->flag & NBL_FLOW_ACTION_TUNNEL_DECAP))
		return ret;

	ret = nbl_draco_flow_get_vtep_key(res_mgt, filter, action);
	if (ret)
		return ret;

	nbl_draco_flow_assign_decap_key(key, &action->vtep_info);

	return 0;
}

/**
 * @brief: tnl: ipv4 tnl filter hash tab search func
 *
 * @param[in] tc_flow_mgt: tc flow hw mgt
 * @param[in] key: node key info
 * @return nbl_draco_flow_node *: return node ptr
 */
static struct nbl_draco_flow_node *
nbl_flow_tab_filter_lookup(struct nbl_resource_mgt *res_mgt,
			   struct nbl_draco_flow_tab_conf *key, u8 profile_id)
{
	struct nbl_draco_flow_node *tab_filter = NULL;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);

	if (!tc_flow_mgt->flow_tab_hash[profile_id].flow_tab_hash)
		return NULL;

	tab_filter = nbl_common_get_hash_node(tc_flow_mgt->flow_tab_hash[profile_id].flow_tab_hash,
					      key);
	return tab_filter;
}

static int nbl_draco_flow_cmd_alloc_kt_block(struct nbl_resource_mgt *res_mgt, u16 *block_id)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_flow_param param;
	union nbl_fem_cmd_data_u req_param;
	union nbl_fem_resp_data_ktalloc_u *resp_data;
	struct nbl_cmd_hdr hdr;
	struct nbl_cmd_content cmd;
	u16 pf_id = NBL_COMMON_TO_MGT_PF(common);
	int ret = 0;

	memset(&req_param, 0, sizeof(req_param));
	memset(&hdr, 0, sizeof(hdr));
	memset(&cmd, 0, sizeof(cmd));
	memset(&param, 0, sizeof(param));

	param.pf_id = pf_id;
	param.hmc = NBL_FEM_CMD_PARAM_HMC_ONC;
	ret = cmd_cfg_ops[NBL_FEM_CMD_HEAD_OPCODE_KTALLOC].cfg_req_param(&req_param, &param);
	if (ret)
		return ret;

	hdr.module = NBL_CMDQ_MODULE_FEM;
	hdr.table = NBL_CMDQ_FEM_TBL;
	hdr.opcode = NBL_CMDQ_FEM_OPCODE_KTALLOC;
	cmd.in_length = NBL_DRACO_CMD_KTBLOCK_LEN;
	cmd.in_params = *(u64 *)&req_param;

	ret = nbl_tc_call_inst_cmdq(common->tc_inst_id, (void *)&hdr, (void *)&cmd);
	resp_data = (union nbl_fem_resp_data_ktalloc_u *)&cmd.out_params;
	if (!ret) {
		*block_id = cmd.out_params / NBL_KT_BLOCK_SIZE;
		nbl_info(common, NBL_DEBUG_FLOW, "alloc kt block success, start kt_idx:%d\n",
			 resp_data->info.kt_idx);
	} else {
		nbl_err(common, NBL_DEBUG_FLOW, "alloc kt block failed, send cmdq ret:%d\n", ret);
		if (ret == NBL_CMDQ_EXCEED_RANGE)
			ret = -ERANGE;
	}

	return ret;
}

static int nbl_draco_read_fem_tbl(struct nbl_resource_mgt *res_mgt,
				  enum nbl_draco_tbl_to_read tbl_type, u8 pf_id, u32 addr,
				  union nbl_fem_resp_data_tblread_u *resp_data)
{
	int ret = 0;
	struct nbl_cmd_content cmd;

	struct nbl_flow_param param;
	union nbl_fem_cmd_data_u req_param;
	struct nbl_cmd_hdr hdr;

	memset(&req_param, 0, sizeof(req_param));
	memset(&hdr, 0, sizeof(hdr));
	memset(&cmd, 0, sizeof(cmd));
	memset(&param, 0, sizeof(param));

	hdr.module = NBL_CMDQ_MODULE_FEM;
	hdr.table = tbl_type;
	hdr.opcode = NBL_CMDQ_FEM_OPCODE_TBLREAD;

	param.tbl_to_read = tbl_type;
	param.pf_id = pf_id;
	param.read_addr = addr;
	ret = cmd_cfg_ops[NBL_FEM_CMD_HEAD_OPCODE_TBLREAD].cfg_req_param(&req_param, &param);
	if (ret) {
		nbl_err(res_mgt->common, NBL_DEBUG_FLOW,
			"config read fem tbl %d cmd param failed, ret: %d", tbl_type, ret);
		return ret;
	}
	cmd.in_length = NBL_DRACO_CMD_TBLREAD_LEN;
	cmd.in_params = *(u64 *)&req_param;
	cmd.in_va = req_param.cmd_data + NBL_DRACO_CMDQ_PARAM_LEN;
	cmd.out_va = resp_data;
	ret = nbl_tc_call_inst_cmdq(res_mgt->common->tc_inst_id, (void *)&hdr, (void *)&cmd);

	if (ret)
		nbl_err(res_mgt->common, NBL_DEBUG_FLOW, "read fem tbl %d failed, ret:%d\n",
			tbl_type, ret);

	return ret;
}

static int nbl_draco_read_fem_kt_bind_pf(struct nbl_resource_mgt *res_mgt, u8 pf_id,
					 union nbl_fem_resp_data_tblread_u *resp_data)
{
	int ret = nbl_draco_read_fem_tbl(res_mgt, NBL_DRACO_KT_BIND_PF_TBL_TO_READ,
					pf_id, 0, resp_data);
	if (!ret) {
		nbl_info(res_mgt->common, NBL_DEBUG_FLOW,
			 "kt bind pf%d: %08x %08x %08x %08x\n", pf_id,
			 resp_data->kt_bind_pf_info.kt_bind[3],
			 resp_data->kt_bind_pf_info.kt_bind[2],
			 resp_data->kt_bind_pf_info.kt_bind[1],
			 resp_data->kt_bind_pf_info.kt_bind[0]);
	}
	return ret;
}

static int nbl_draco_read_fem_tcam(struct nbl_resource_mgt *res_mgt, u8 pf_id, u32 oft_addr,
				   union nbl_fem_resp_data_tblread_u *resp_data)
{
	int ret = nbl_draco_read_fem_tbl(res_mgt, NBL_DRACO_OFTAD_TBL_TO_READ,
					pf_id, oft_addr, resp_data);
	if (!ret) {
		if (!resp_data->oft_info.oft0_valid || !resp_data->oft_info.oft1_valid)
			return ret;

		nbl_info(res_mgt->common, NBL_DEBUG_FLOW,
			 "tcam full addr %d: oft0(vld=%d,size=%d,ktidx=%d), oft1(vld=%d,size=%d,ktidx=%d)\n",
			 oft_addr << 1,
			 resp_data->oft_info.oft0_valid,
			 resp_data->oft_info.oft0_size,
			 resp_data->oft_info.oft0_ktidx,
			 resp_data->oft_info.oft1_valid,
			 resp_data->oft_info.oft1_size,
			 resp_data->oft_info.oft1_ktidx);
		nbl_info(res_mgt->common, NBL_DEBUG_FLOW,
			 "addr %d: oft0_key=0x%08x %08x %08x %08x %08x, oft1_key=0x%08x %08x %08x %08x %08x\n",
			 oft_addr << 1,
			 resp_data->oft_info.oft0_key[4], resp_data->oft_info.oft0_key[3],
			 resp_data->oft_info.oft0_key[2], resp_data->oft_info.oft0_key[1],
			 resp_data->oft_info.oft0_key[0], resp_data->oft_info.oft1_key[4],
			 resp_data->oft_info.oft1_key[3], resp_data->oft_info.oft1_key[2],
			 resp_data->oft_info.oft1_key[1], resp_data->oft_info.oft1_key[0]);
	} else {
		nbl_err(res_mgt->common, NBL_DEBUG_FLOW, "read fem tcam failed, pf:%d, oft addr:%d",
			pf_id, oft_addr << 1);
	}

	return ret;
}

static bool nbl_is_kt_belong_pf(struct nbl_resource_mgt *res_mgt,
				u32 ktidx, union nbl_fem_resp_data_tblread_u *kt_bind_pf)
{
	u32 bolok_id = NBL_DRACO_GET_KT_BLOCK_IDX(ktidx);

	if (bolok_id >= NBL_DRACO_KT_MAX_BLOCK) {
		nbl_err(res_mgt->common, NBL_DEBUG_FLOW, "kt block id %d invalid, kt_idx:%d",
			bolok_id, ktidx);
		return false;
	}

	return kt_bind_pf->kt_bind_pf_info.kt_bind[bolok_id / 32] & (1 << (bolok_id % 32));
}

static int nbl_draco_flow_remove_node_hw(struct nbl_draco_flow_mgt *draco_mgt,
					 struct nbl_draco_flow_node *node)
{
	struct nbl_resource_mgt *res_mgt = draco_mgt->res_mgt;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	union nbl_fem_cmd_data_u req_param;
	union nbl_fem_resp_data_tbllookup_u resp_data;
	struct nbl_cmd_hdr hdr;
	struct nbl_cmd_content cmd;
	struct nbl_flow_param param;
	struct nbl_profile_offload_msg *tcam_data = NULL;
	bool tcam_data_found = false;
	u8 index = 0;
	u16 ht_index;
	u16 hash_bucket;
	u16 ht0_hash;
	u16 ht1_hash;
	u16 hash_table;
	u32 kt_idx;
	u16 tcam_table;
	u16 tcam_index;
	int ret;

	memset(&req_param, 0, sizeof(req_param));
	memset(&resp_data, 0, sizeof(resp_data));
	memset(&hdr, 0, sizeof(hdr));
	memset(&cmd, 0, sizeof(cmd));
	memset(&param, 0, sizeof(param));

	param.del_on_hit = 1;
	param.lkp_mode = NBL_FEM_CMD_PARAM_MODE_FAST;
	param.pf_id = NBL_COMMON_TO_MGT_PF(common);
	param.hmc = NBL_FEM_CMD_PARAM_HMC_ONC;
	param.ht_id = node->hash_table_id;
	param.ht_slot_id = node->slot_id;
	param.kt_idx = node->kt_index;
	param.key = (u8 *)&node->key.key_value;
	if (node->kt_info.kt_type == NBL_DRACO_KT_HALF_MODE)
		param.key_len = NBL_DRACO_HALF_KEY_BYTES;
	else if (node->kt_info.kt_type == NBL_DRACO_KT_FULL_MODE)
		param.key_len = NBL_DRACO_FULL_KEY_BYTES;

	ret = cmd_cfg_ops[NBL_FEM_CMD_HEAD_OPCODE_TBLLOOKUP].cfg_req_param(&req_param, &param);
	if (ret)
		return ret;

	hdr.module = NBL_CMDQ_MODULE_FEM;
	hdr.table = NBL_CMDQ_FEM_TBL;
	hdr.opcode = NBL_CMDQ_FEM_OPCODE_TBLLKP;
	cmd.in_length = NBL_DRACO_CMD_TBLLKP_LEN;
	cmd.in_params = *(u64 *)&req_param;
	cmd.in_va = req_param.cmd_data + NBL_DRACO_CMDQ_PARAM_LEN;
	cmd.out_va = &resp_data;
	ret = nbl_tc_call_inst_cmdq(res_mgt->common->tc_inst_id, (void *)&hdr, (void *)&cmd);

	if (!ret) {
		/* remove tcam data from the to eviction tcam data list */
		if (node->tcam_flag) {
			spin_lock(&draco_mgt->tcam_lock);
			for (index = 0; index < NBL_DRACO_TCAM_SPEC; index++) {
				tcam_data = &draco_mgt->tcam_data_info[index];
				if (tcam_data->kt_index == node->kt_index) {
					memset(tcam_data, 0, sizeof(*tcam_data));
					tcam_data_found = true;
				}
			}
			spin_unlock(&draco_mgt->tcam_lock);

			if (!tcam_data_found) {
				nbl_err(common, NBL_DEBUG_FLOW, "tcam data not found!");
				return -EIO;
			}
		}

		if (resp_data.info.hit_pos == NBL_FEM_CMD_PARAM_HIT_POS_HT_KT) {
			hash_table = (u16)(resp_data.info.ht_addr & 0x4000);
			ht_index = resp_data.info.ht_addr & 0x3FFF;
			hash_bucket = resp_data.info.slot_id;
			ht0_hash = resp_data.info.hash0_idx;
			ht1_hash = resp_data.info.hash1_idx;
			kt_idx = resp_data.info.kt_idx;

			nbl_debug(common, NBL_DEBUG_FLOW, "Del ht success, kt_idx:%d tcam_flag:%d, response data - kt_idx:%d, hash_table:%d, ht_index:%d, hash_bucket:%d, ht0_hash:0x%x, ht1_hash:0x%x\n",
				  param.kt_idx, node->tcam_flag,
				 kt_idx, hash_table, ht_index, hash_bucket, ht0_hash, ht1_hash);
		} else if (resp_data.info.hit_pos == NBL_FEM_CMD_PARAM_HIT_POS_OFT) {
			tcam_table = resp_data.info.ht_addr & 0x1;
			tcam_index = resp_data.info.ht_addr & 0xFE;
			kt_idx = resp_data.info.kt_idx;

			nbl_debug(common, NBL_DEBUG_FLOW, "Del tcam success, kt_idx:%d tcam_flag:%d, response data - kt_idx:%d, tcam_table:%d, tcam_index:%d\n",
				  param.kt_idx, node->tcam_flag, kt_idx, tcam_table, tcam_index);
		}

		/* update stats */
		if (node->tcam_flag)
			draco_mgt->stats.pp_tcam_entry--;
		else if (node->profile_stage)
			draco_mgt->stats.used_pp1_entry--;
		else
			draco_mgt->stats.used_pp0_entry--;
	} else {
		nbl_err(common, NBL_DEBUG_FLOW, "Del %s failed, kt_idx:%d tcam_flag:%d, cmdq ret:%d",
			node->tcam_flag ? "tcam" : "ht", param.kt_idx, node->tcam_flag, ret);
	}

	return ret;
}

static int
nbl_draco_flow_remove_node_from_tcam(struct nbl_resource_mgt *res_mgt,
				     u32 kt_idx, bool kt_full_mode, u32 *key)
{
	int ret;
	struct nbl_draco_flow_node flow_node;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_draco_flow_mgt *draco_mgt = tc_flow_mgt->priv_flow_mgt;

	memset(&flow_node, 0, sizeof(flow_node));

	flow_node.tcam_flag = 1;
	if (kt_full_mode)
		flow_node.kt_info.kt_type = NBL_DRACO_KT_FULL_MODE;
	else
		flow_node.kt_info.kt_type = NBL_DRACO_KT_HALF_MODE;

	flow_node.kt_index = kt_idx;
	memcpy(flow_node.key.key_value, key, sizeof(flow_node.key.key_value));
	ret = nbl_draco_flow_remove_node_hw(draco_mgt, &flow_node);
	if (ret) {
		nbl_err(res_mgt->common, NBL_DEBUG_FLOW,
			"delete node by kt idx: 0x%x, full mode: %d failed",
			kt_idx, kt_full_mode);
	} else {
		nbl_err(res_mgt->common, NBL_DEBUG_FLOW,
			"delete node by kt idx: 0x%x, full mode: %d success",
			kt_idx, kt_full_mode);
	}
	return ret;
}

static void nbl_draco_free_fem_tcam(struct nbl_resource_mgt *res_mgt, u8 pf_id)
{
	union nbl_fem_resp_data_tblread_u kt_bind_pf;
	union nbl_fem_resp_data_tblread_u tcam_resp;
	u32 key[NBL_TABLE_KEY_LEN];
	u32 tcam_addr;
	int ret;

	memset(&kt_bind_pf, 0, sizeof(kt_bind_pf));
	memset(&tcam_resp, 0, sizeof(tcam_resp));
	memset(key, 0, sizeof(key));

	ret = nbl_draco_read_fem_kt_bind_pf(res_mgt, pf_id, &kt_bind_pf);
	if (ret) {
		nbl_err(res_mgt->common, NBL_DEBUG_FLOW, "read kt bind pf tbl failed, ret:%d", ret);
		return;
	}

	nbl_info(res_mgt->common, NBL_DEBUG_FLOW, "nbl draco free fem tcam for pf:%d", pf_id);

	for (tcam_addr = 0; tcam_addr < NBL_DRACO_FULL_TCAM_NUM; tcam_addr++) {
		ret = nbl_draco_read_fem_tcam(res_mgt, pf_id, tcam_addr, &tcam_resp);
		if (ret)
			continue;

		if (!tcam_resp.oft_info.oft0_valid || !tcam_resp.oft_info.oft1_valid)
			continue;

		if (tcam_resp.oft_info.oft0_size && tcam_resp.oft_info.oft1_size) {
			if (nbl_is_kt_belong_pf(res_mgt, tcam_resp.oft_info.oft0_ktidx,
						&kt_bind_pf)) {
				memset(key, 0, sizeof(key));
				memcpy(key, tcam_resp.oft_info.oft0_key,
				       sizeof(tcam_resp.oft_info.oft0_key));
				memcpy((u8 *)key + sizeof(tcam_resp.oft_info.oft0_key),
				       tcam_resp.oft_info.oft1_key,
				       sizeof(tcam_resp.oft_info.oft1_key));
				nbl_draco_flow_remove_node_from_tcam(res_mgt,
								     tcam_resp.oft_info.oft0_ktidx,
								     true, key);
			}
		} else {
			if (tcam_resp.oft_info.oft0_valid &&
			    nbl_is_kt_belong_pf(res_mgt, tcam_resp.oft_info.oft0_ktidx,
						&kt_bind_pf)) {
				memset(key, 0, sizeof(key));
				memcpy((u8 *)key + sizeof(tcam_resp.oft_info.oft0_key),
				       tcam_resp.oft_info.oft0_key,
				       sizeof(tcam_resp.oft_info.oft0_key));
				nbl_draco_flow_remove_node_from_tcam(res_mgt,
								     tcam_resp.oft_info.oft0_ktidx,
								     false, key);
			}
			if (tcam_resp.oft_info.oft1_valid &&
			    nbl_is_kt_belong_pf(res_mgt, tcam_resp.oft_info.oft1_ktidx,
						&kt_bind_pf)) {
				memset(key, 0, sizeof(key));
				memcpy((u8 *)key + sizeof(tcam_resp.oft_info.oft0_key),
				       tcam_resp.oft_info.oft1_key,
				       sizeof(tcam_resp.oft_info.oft1_key));
				nbl_draco_flow_remove_node_from_tcam(res_mgt,
								     tcam_resp.oft_info.oft1_ktidx,
								     false, key);
			}
		}
	}
}

static void nbl_flow_clear_flows(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u8 pf_id = NBL_COMMON_TO_MGT_PF(common);

	/* free fem tcam */
	nbl_draco_free_fem_tcam(res_mgt, pf_id);

	phy_ops->clear_em(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), pf_id);
}

static int
nbl_draco_flow_cmd_free_kt_block(struct nbl_resource_mgt *res_mgt, u16 block_id, bool all)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_flow_param param;
	union nbl_fem_cmd_data_u req_param;
	struct nbl_cmd_hdr hdr;
	struct nbl_cmd_content cmd;
	u16 pf_id = NBL_COMMON_TO_MGT_PF(common);
	int ret = 0;

	memset(&req_param, 0, sizeof(req_param));
	memset(&hdr, 0, sizeof(hdr));
	memset(&cmd, 0, sizeof(cmd));
	memset(&param, 0, sizeof(param));

	if (all)
		nbl_flow_clear_flows(res_mgt);

	param.pf_id = pf_id;
	param.hmc = NBL_FEM_CMD_PARAM_HMC_ONC;
	param.start_kt_index = block_id * NBL_KT_BLOCK_SIZE;
	param.free_all = all;
	ret = cmd_cfg_ops[NBL_FEM_CMD_HEAD_OPCODE_KTFREE].cfg_req_param(&req_param, &param);
	if (ret)
		return ret;

	hdr.module = NBL_CMDQ_MODULE_FEM;
	hdr.table = NBL_CMDQ_FEM_TBL;
	hdr.opcode = NBL_CMDQ_FEM_OPCODE_KTFREE;
	cmd.in_length = NBL_DRACO_CMD_KTBLOCK_LEN;
	cmd.in_params = *(u64 *)&req_param;
	ret = nbl_tc_call_inst_cmdq(common->tc_inst_id, (void *)&hdr, (void *)&cmd);

	if (!ret) {
		nbl_debug(common, NBL_DEBUG_FLOW, "pf %d kt block %d free success\n",
			  pf_id, block_id);
	} else {
		nbl_err(common, NBL_DEBUG_FLOW, "pf %d kt block %d free failed, check hardware! ret:%d\n",
			pf_id, block_id, ret);
		ret = -EIO;
	}

	return ret;
}

static void nbl_draco_uninit_kt_node(void *data)
{
	struct nbl_draco_kt_node *kt_node = (struct nbl_draco_kt_node *)data;

	nbl_bitmap_mng_release(&kt_node->kt_bmp_mng);
	nbl_bitmap_mng_release(&kt_node->kt_bmp_mng_at1);
	nbl_bitmap_mng_release(&kt_node->kt_bmp_mng_at2);
}

static void nbl_draco_flow_free_kt_block(struct nbl_draco_flow_mgt *draco_mgt,
					 struct nbl_draco_kt_node *kt_node,
					 struct nbl_draco_kt_idx_info *kt_info)
{
	struct nbl_resource_mgt *res_mgt = draco_mgt->res_mgt;

	nbl_draco_flow_cmd_free_kt_block(res_mgt, (u16)kt_node->kt_block_id, 0);
	/* if current node points to free_node, reset it to null */
	if (draco_mgt->kt_mgt.cur_node[kt_info->kt_profile_id] == kt_node)
		draco_mgt->kt_mgt.cur_node[kt_info->kt_profile_id] = NULL;

	draco_mgt->kt_mgt.kt_block_alloc_stat[kt_info->kt_profile_id]--;

	/* update the block cnt */
	mutex_lock(&draco_mgt->kt_mgt.kt_lock);
	draco_mgt->kt_mgt.kt_block_alloc_stat[NBL_DRACO_MAX_PROFILE_NUM]--;
	mutex_unlock(&draco_mgt->kt_mgt.kt_lock);

	/* remove kt_node */
	list_del(&kt_node->kt_node);
	nbl_draco_uninit_kt_node(kt_node);
	nbl_common_free_hash_node(draco_mgt->kt_mgt.kt_hash.flow_tab_hash,
				  (void *)&kt_node->kt_block_id);
}

static int nbl_draco_flow_put_kt_idx(struct nbl_draco_flow_mgt *draco_mgt,
				     struct nbl_draco_kt_idx_info *kt_info, u32 kt_idx)
{
	int ret = 0;
	struct nbl_draco_kt_node *kt_node = NULL;
	struct nbl_draco_kt_mgt *kt_mgt = &draco_mgt->kt_mgt;
	u16 kt_block_idx = NBL_DRACO_GET_KT_BLOCK_IDX(kt_idx);
	struct nbl_common_info *common = draco_mgt->res_mgt->common;
	struct mutex *kt_lock = NULL;
	void *hash_tbl = draco_mgt->kt_mgt.kt_hash.flow_tab_hash;
	u8 aside_kt_use = 1;
	u8 aside_at_type = 0;
	u32 aside_kt_idx = 0;

	if (!kt_info)
		return -ENOKEY;

	/* get the corresponding lock */
	if (kt_info->kt_type == NBL_DRACO_KT_FULL_MODE)
		kt_lock = &kt_mgt->full_kt_lock;
	else
		kt_lock = &kt_mgt->half_kt_lock;

	mutex_lock(kt_lock);
	kt_node = (struct nbl_draco_kt_node *)nbl_common_get_hash_node(hash_tbl, &kt_block_idx);
	if (!kt_node) {
		nbl_err(common, NBL_DEBUG_FLOW,
			"kt node is null when put kt node to res pool, kt_block_idx:%u, kt_idx: %u",
			kt_block_idx, kt_idx);
		goto put_kt_finished;
	}

	if (kt_node->kt_block_id != kt_block_idx) {
		nbl_err(common, NBL_DEBUG_FLOW, "put kt id s not equal to kt_block_idx, kt block: %d, kt node kt block %d, kt_idx: %u",
			kt_node->kt_block_id, kt_block_idx, kt_idx);
		ret = -EINVAL;
		goto put_kt_finished;
	}

	if (kt_info->kt_type == NBL_DRACO_KT_FULL_MODE) {
		++kt_node->avail_kt_num;
		/* kt block is empty, free it to kt-pool */
		if (NBL_DRACO_FULL_KT_BLOCK_IS_FREE(kt_node->avail_kt_num)) {
			nbl_draco_flow_free_kt_block(draco_mgt, kt_node, kt_info);
			goto put_kt_finished;
		}
		kt_idx = NBL_DRACO_GET_FULL_KT_NODE_IDX(kt_idx);
		if (kt_idx >= NBL_DRACO_FULL_KT_PER_BLOCK_CNT) {
			ret = -EINVAL;
			nbl_err(common, NBL_DEBUG_FLOW, "kt idx %d is invalid in full", kt_idx);
			goto put_kt_finished;
		}
		kt_node->kt_idx_info[kt_idx].kt_in_use = 0;
		nbl_bitmap_mng_release_id(&kt_node->kt_bmp_mng, kt_idx);
		/* make sure the first node in list are always available */
		list_del(&kt_node->kt_node);
		list_add(&kt_node->kt_node, &draco_mgt->kt_mgt.kt_full_list);
	} else {
		++kt_node->avail_kt_num;
		/* kt block is empty, free it to kt-pool */
		if (NBL_DRACO_HALF_KT_BLOCK_IS_FREE(kt_node->avail_kt_num)) {
			nbl_draco_flow_free_kt_block(draco_mgt, kt_node, kt_info);
			goto put_kt_finished;
		}

		kt_idx = NBL_DRACO_GET_HALF_KT_NODE_IDX(kt_idx);
		if (kt_idx >= NBL_DRACO_HALF_KT_PER_BLOCK_CNT) {
			ret = -EINVAL;
			nbl_err(common, NBL_DEBUG_FLOW, "kt idx %d is invalid in half", kt_idx);
			goto put_kt_finished;
		}

		nbl_bitmap_mng_release_id(&kt_node->kt_bmp_mng, kt_idx);

		/* get aside kt_idx for release */
		if (NBL_DRACO_KT_IS_ENTRY_HEAD(kt_idx))
			aside_kt_idx = kt_idx + 1;
		else
			aside_kt_idx = kt_idx - 1;

		if (aside_kt_idx >= NBL_DRACO_HALF_KT_PER_BLOCK_CNT) {
			ret = -EINVAL;
			nbl_err(common, NBL_DEBUG_FLOW, "aside kt idx %d is invalid in half",
				kt_idx);
			goto put_kt_finished;
		}

		aside_kt_use = kt_node->kt_idx_info[aside_kt_idx].kt_in_use;
		aside_at_type = kt_node->kt_idx_info[aside_kt_idx].at_type;
		if (kt_info->at_type == NBL_DRACO_AT_TYPE_1) {
			++kt_node->avail_half_at1_num;
			nbl_bitmap_mng_release_id(&kt_node->kt_bmp_mng_at1, kt_idx);
			/* the aside kt had freed already means the entry is available for at_2 */
			if (!aside_kt_use) {
				++kt_node->avail_half_at2_num;
				nbl_bitmap_mng_release_id(&kt_node->kt_bmp_mng_at2, kt_idx);
				nbl_bitmap_mng_release_id(&kt_node->kt_bmp_mng_at2, aside_kt_idx);
			} else {
				/* aside kt_idx is used but got no at is also available for at 2 */
				if (aside_at_type == NBL_DRACO_AT_TYPE_0) {
					++kt_node->avail_half_at2_num;
					nbl_bitmap_mng_release_id(&kt_node->kt_bmp_mng_at2, kt_idx);
				} else {
					if (aside_at_type > NBL_DRACO_AT_TYPE_1) {
						nbl_err(common, NBL_DEBUG_FLOW, "illegal kt_idx %u in blk %u at:%u\n",
							kt_idx, kt_node->kt_block_id,
							kt_info->at_type + aside_at_type);
						ret = -EINVAL;
						goto put_kt_finished;
					}
				}
			}
		} else if (kt_info->at_type == NBL_DRACO_AT_TYPE_2) {
			++kt_node->avail_half_at2_num;
			++kt_node->avail_half_at1_num;
			nbl_bitmap_mng_release_id(&kt_node->kt_bmp_mng_at1, kt_idx);
			nbl_bitmap_mng_release_id(&kt_node->kt_bmp_mng_at2, kt_idx);
			if (!aside_kt_use && NBL_DRACO_VAILD_BLOCK_IDX(kt_node, aside_kt_idx)) {
				++kt_node->avail_half_at1_num;
				nbl_bitmap_mng_release_id(&kt_node->kt_bmp_mng_at1, aside_kt_idx);
				nbl_bitmap_mng_release_id(&kt_node->kt_bmp_mng_at2, aside_kt_idx);
			}

			if (aside_at_type != NBL_DRACO_AT_TYPE_0) {
				nbl_err(common, NBL_DEBUG_FLOW, "illegal kt_idx %u in blk %u at:%u",
					kt_idx, kt_node->kt_block_id,
					kt_info->at_type + aside_at_type);
				ret = -EINVAL;
				goto put_kt_finished;
			}
		} else {
			/* curent at with 0 at, and the aside kt had freed before at1_num+1 */
			if (!aside_kt_use) {
				kt_node->avail_half_at1_num += 1;
				kt_node->avail_half_at2_num += 1;
				nbl_bitmap_mng_release_id(&kt_node->kt_bmp_mng_at1, kt_idx);
				nbl_bitmap_mng_release_id(&kt_node->kt_bmp_mng_at2, kt_idx);
				nbl_bitmap_mng_release_id(&kt_node->kt_bmp_mng_at1, aside_kt_idx);
				nbl_bitmap_mng_release_id(&kt_node->kt_bmp_mng_at2, aside_kt_idx);
			} else {
				if (aside_at_type < NBL_DRACO_AT_TYPE_2) {
					kt_node->avail_half_at1_num += 1;
					nbl_bitmap_mng_release_id(&kt_node->kt_bmp_mng_at1, kt_idx);
				}
			}
		}

		kt_node->kt_idx_info[kt_idx].kt_in_use = 0;
		kt_node->kt_idx_info[kt_idx].at_type = NBL_DRACO_AT_TYPE_0;
		/* make sure the first node in list are always available */
		list_del(&kt_node->kt_node);
		list_add(&kt_node->kt_node, &draco_mgt->kt_mgt.kt_half_list);
	}

put_kt_finished:
	mutex_unlock(kt_lock);
	return ret;
}

static void nbl_draco_assign_hash_key(u32 *key,
				      struct nbl_flow_pattern_conf *filter,
				      struct nbl_resource_mgt *res_mgt,
				      struct nbl_profile_offload_msg *off_msg)
{
	/* 320 bit key data, namely 5 * 64 bits */
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_profile_msg *prf_msg =
		&tc_flow_mgt->profile_msg[off_msg->profile_id];
	struct nbl_flow_key_info *key_info = prf_msg->flow_keys;
	u8 i = 0;

	/* loop through all keys of this profile */
	for (i = 0; i < prf_msg->key_count; i++, key_info++) {
		if (!key_info->valid) {
			nbl_err(common, NBL_DEBUG_FLOW,
				"tc flow hw key %s invalid, something went wrong\n",
				key_info->name);

			return;
		}

		nbl_assign_hash_key_key(key, key_info, prf_msg,
					&filter->input, prf_msg->lkp_id, off_msg->assoc_tbl_id);
	}
}

/**
 * @brief: flow_tab.add hash node, and transfer the key value
 *
 * @param[in] key: node key info
 * @param[out] ptr: hash node
 * @return int: 0-success other-fail
 */
static int nbl_flow_tab_hash_add(struct nbl_resource_mgt *res_mgt,
				 struct nbl_tc_flow_param *param,
				 struct nbl_tc_flow *tc_flow_ptr, void **ptr,
				 struct nbl_profile_offload_msg *prof_off_msg,
				 struct nbl_draco_flow_tab_conf *node_key)
{
	int ret = 0;
	u8 profile_id = prof_off_msg->profile_id;
	u8 profile_stage = prof_off_msg->profile_stage;
	struct nbl_draco_flow_node *node = NULL;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_flow_pattern_conf *filter = &param->filter;
	struct nbl_draco_flow_node *new_node;

	/* encode sport value */
	nbl_draco_encode_port(param);

	/* only pp0 need a vtep process */
	if (!prof_off_msg->profile_stage) {
		ret = nbl_draco_flow_decap_process(res_mgt, &param->filter,
						   &param->act, node_key);
		if (ret)
			goto failed_add_vtep_node;
	}

	nbl_draco_assign_hash_key(node_key->key_value, filter, res_mgt, prof_off_msg);

	mutex_lock(&tc_flow_mgt->flow_lock);
	node = nbl_flow_tab_filter_lookup(res_mgt, node_key, profile_id);
	if (node) {
		memcpy(&node->vtep_info, &param->act.vtep_info, sizeof(param->act.vtep_info));

		if (prof_off_msg->last_stage) {
			mutex_unlock(&tc_flow_mgt->flow_lock);
			nbl_err(common, NBL_DEBUG_FLOW, "tc flow offload already, drop this one, cookies 0x%llx",
				tc_flow_ptr->key.cookie);
			*ptr = node;
			ret = -EEXIST;
			goto offload_already;
		}

		node->ref_cnt++;
		*ptr = node;
		tc_flow_ptr->profile_id[profile_stage] = profile_id;
		tc_flow_ptr->profile_rule[profile_stage] = node;
		mutex_unlock(&tc_flow_mgt->flow_lock);
		nbl_info(common, NBL_DEBUG_FLOW, "tc flow hw flow_tab refcnt ++.\n");
		return -EEXIST;
	}
	mutex_unlock(&tc_flow_mgt->flow_lock);

	/* add new node */
	new_node = kzalloc(sizeof(*new_node), GFP_KERNEL);
	if (!new_node)
		goto alloc_node_failed;

	new_node->ref_cnt = 1;
	memcpy(&new_node->key, node_key, sizeof(*node_key));

	new_node->assoc_tbl_id = prof_off_msg->act_assoc_tbl_id;
	memcpy(&new_node->vtep_info, &param->act.vtep_info, sizeof(param->act.vtep_info));

	mutex_lock(&tc_flow_mgt->flow_lock);
	ret = nbl_insert_flow_tab_filter(res_mgt, node_key, new_node, (void **)&node, profile_id);
	kfree(new_node);
	if (ret) {
		mutex_unlock(&tc_flow_mgt->flow_lock);
		nbl_err(common, NBL_DEBUG_FLOW,
			"tc flow hw failed to insert flow tab filter to hash table %d.\n", ret);
		goto failed_add_flow_tab;
	}

	*ptr = node;
	tc_flow_ptr->profile_id[profile_stage] = profile_id;
	tc_flow_ptr->profile_rule[profile_stage] = node;
	mutex_unlock(&tc_flow_mgt->flow_lock);

	return ret;

failed_add_vtep_node:
	return ret;
offload_already:
alloc_node_failed:
failed_add_flow_tab:
	if (param->act.ped_info.ped_info[NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE].ped_valid)
		nbl_draco_free_decap_vtep_node(res_mgt, &param->act);
	return ret;
}

static int nbl_draco_cmdq_write_ped_table(struct nbl_draco_flow_mgt *draco_mgt,
					  u8 *data, u16 index, enum nbl_draco_ped_type ped_type)
{
	struct nbl_resource_mgt *res_mgt = draco_mgt->res_mgt;
	struct nbl_cmd_hdr hdr;
	struct nbl_cmd_content cmd;
	int ret = 0;

	memset(&hdr, 0, sizeof(hdr));
	memset(&cmd, 0, sizeof(cmd));

	hdr.module = NBL_CMDQ_MODULE_PED;
	hdr.opcode = NBL_CMDQ_PED_OPCODE_WRITE;

	switch (ped_type) {
	case NBL_DRACO_PED_TNL_VTEP_TYPE:
		hdr.table = NBL_CMDQ_PED_TBL_ENCAP_VTEP;
		cmd.in_length = NBL_DRACO_CMD_PED_TNL_LEN;
		break;
	case NBL_DRACO_PED_TNL_TYPE:
		hdr.table = NBL_CMDQ_PED_TBL_ENCAP;
		cmd.in_length = NBL_DRACO_CMD_PED_TNL_LEN;
		break;
	case NBL_DRACO_PED_UMAC_TYPE:
		hdr.table = NBL_CMDQ_PED_TBL_MAC_REP;
		cmd.in_length = NBL_DRACO_CMD_PED_REP_LEN;
		break;
	case NBL_DRACO_PED_UIP_TYPE:
		hdr.table = NBL_CMDQ_PED_TBL_IP_REP;
		cmd.in_length = NBL_DRACO_CMD_PED_REP_LEN;
		break;
	default:
		nbl_err(res_mgt->common, NBL_DEBUG_FLOW, "unsupported ped type for cmdq tbl write,ped_type: %u",
			ped_type);
	}

	cmd.in_params = index;
	cmd.in_va = data;
	ret = nbl_tc_call_inst_cmdq(res_mgt->common->tc_inst_id, (void *)&hdr, (void *)&cmd);
	if (ret) {
		nbl_err(res_mgt->common, NBL_DEBUG_FLOW, "write ped table %d failed, cmdq ret %d",
			ped_type, ret);
		return ret;
	}

	return ret;
}

static int nbl_draco_cmdq_read_ped_table(struct nbl_draco_flow_mgt *draco_mgt,
					 u8 *data, u16 index, enum nbl_draco_ped_type ped_type)
{
	struct nbl_resource_mgt *res_mgt = draco_mgt->res_mgt;
	struct nbl_cmd_hdr hdr;
	struct nbl_cmd_content cmd;
	u8 resp_data[NBL_DRACO_CMD_PED_READ_RESP_LEN + NBL_DRACO_CMDQ_PARAM_LEN];
	u16 datalen = 0;
	int ret = 0;

	memset(&hdr, 0, sizeof(hdr));
	memset(&cmd, 0, sizeof(cmd));
	memset(resp_data, 0, sizeof(resp_data));

	hdr.module = NBL_CMDQ_MODULE_PED;
	hdr.opcode = NBL_CMDQ_PED_OPCODE_READ;

	switch (ped_type) {
	case NBL_DRACO_PED_TNL_VTEP_TYPE:
		hdr.table = NBL_CMDQ_PED_TBL_ENCAP_VTEP;
		cmd.in_length = NBL_DRACO_CMD_PED_READ_LEN;
		datalen = ETH_ALEN + NBL_IPV6_ADDR_LEN_AS_U8;
		break;
	case NBL_DRACO_PED_TNL_TYPE:
		hdr.table = NBL_CMDQ_PED_TBL_ENCAP;
		cmd.in_length = NBL_DRACO_CMD_PED_READ_LEN;
		datalen = sizeof(struct nbl_flow_tnl_prof_node);
		break;
	case NBL_DRACO_PED_UMAC_TYPE:
		hdr.table = NBL_CMDQ_PED_TBL_MAC_REP;
		cmd.in_length = NBL_DRACO_CMD_PED_READ_LEN;
		datalen = ETH_ALEN;
		break;
	case NBL_DRACO_PED_UIP_TYPE:
		hdr.table = NBL_CMDQ_PED_TBL_IP_REP;
		cmd.in_length = NBL_DRACO_CMD_PED_READ_LEN;
		datalen = NBL_IPV6_ADDR_LEN_AS_U8;
		break;
	default:
		nbl_err(res_mgt->common, NBL_DEBUG_FLOW, "unsupported ped type for cmdq tbl write,ped_type: %u",
			ped_type);
	}

	cmd.in_params = index;
	cmd.out_va = resp_data;
	ret = nbl_tc_call_inst_cmdq(res_mgt->common->tc_inst_id, (void *)&hdr, (void *)&cmd);
	if (ret) {
		nbl_err(res_mgt->common, NBL_DEBUG_FLOW, "read ped table %d failed, cmdq ret %d",
			hdr.table, ret);
		return ret;
	}

	if (memcmp(data, resp_data + NBL_DRACO_CMDQ_PARAM_LEN, datalen)) {
		nbl_err(res_mgt->common, NBL_DEBUG_FLOW, "ped data read not matching data written");
		return -EIO;
	}

	return ret;
}

static void nbl_draco_free_ped_mcc(struct nbl_common_info *common,
				   struct nbl_draco_flow_mgt *draco_mgt,
				   struct nbl_draco_flow_node *node)
{
	int ret = 0;
	struct nbl_draco_flow_mcc_tbl mcc_node;
	u16 mcc_idx = node->ped_info.ped_info[NBL_DRACO_PED_MCC_TYPE].ped_idx;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(draco_mgt->res_mgt);

	memset(&mcc_node, 0, sizeof(mcc_node));

	ret = nbl_devshr_free_idx(NBL_DEVSHR_INDEX_MCC, common->pdev, mcc_idx);
	if (ret)
		nbl_err(common, NBL_DEBUG_FLOW, "nbl tc flow free mcc failed, mcc_idx:%u, ret:%d",
			mcc_idx, ret);
	else
		atomic_dec(&g_mirror_cnt);

	phy_ops->write_ped_tbl(NBL_RES_MGT_TO_PHY_PRIV(draco_mgt->res_mgt),
				(u8 *)&mcc_node, mcc_idx, NBL_DRACO_PED_MCC_TYPE);

	nbl_debug(common, NBL_DEBUG_FLOW, "nbl tc free mcc, mcc_idx:%u, mirr_cnt:%u",
		  mcc_idx, atomic_read(&g_mirror_cnt));
}

static void nbl_draco_free_ped_mac_ip(struct nbl_draco_flow_node *node,
				      struct nbl_draco_flow_mgt *draco_mgt, u16 ped_type)
{
	u16 ped_idx = 0;
	int ret = 0;
	void *pedit_tbl, *key;
	u8 *zero_key;
	struct nbl_tc_pedit_entry *h_e = NULL, *out_e = NULL;
	struct nbl_tc_pedit_entry zero_entry;
	enum nbl_devshr_index_type devshr_type = NBL_DEVSHR_INDEX_MAC;
	struct nbl_common_info *common = draco_mgt->res_mgt->common;

	memset(&zero_entry, 0, sizeof(zero_entry));

	h_e = node->ped_info.ped_info[ped_type].data;
	if (!h_e)
		return;

	if (ped_type == NBL_DRACO_PED_UMAC_TYPE || ped_type == NBL_DRACO_PED_DMAC_TYPE) {
		ped_type = NBL_DRACO_PED_UMAC_TYPE;
		devshr_type = NBL_DEVSHR_INDEX_MAC;
		key = h_e->mac;
		zero_key = zero_entry.mac;
	} else {
		ped_type = NBL_DRACO_PED_UIP_TYPE;
		devshr_type = NBL_DEVSHR_INDEX_IP;
		key = h_e->ip6;
		zero_key = zero_entry.ip6;
	}

	mutex_lock(&draco_mgt->ped_lock[ped_type]);
	pedit_tbl = draco_mgt->pedit_res[ped_type].pedit_tbl;
	out_e = nbl_common_get_hash_node(pedit_tbl, key);
	if (out_e) {
		out_e->hnode.ref_cnt--;
		if (out_e->hnode.ref_cnt > 0) {
			mutex_unlock(&draco_mgt->ped_lock[ped_type]);
			return;
		}

		ped_idx = (u16)out_e->hnode.node_idx;
		nbl_devshr_free_idx(devshr_type, common->pdev, ped_idx);
		nbl_common_free_hash_node(pedit_tbl, key);
		ret = nbl_draco_cmdq_write_ped_table(draco_mgt, zero_key, ped_idx, ped_type);
		mutex_unlock(&draco_mgt->ped_lock[ped_type]);
		if (ret)
			nbl_err(common, NBL_DEBUG_FLOW, "free hw ped failed, type:%u, ped_idx:%u, ret:%d",
				ped_type, ped_idx, ret);
	} else {
		mutex_unlock(&draco_mgt->ped_lock[ped_type]);
	}
}

static void nbl_draco_free_ped_encap_vtep(struct nbl_common_info *common,
					  struct nbl_draco_flow_mgt *draco_mgt,
					  struct nbl_flow_tnl_vtep_hnode *vtep_node)
{
	void *ped_tbl;
	u8 encap_vtep_idx = 0;
	u32 ref_cnt = 0;
	bool need_del_hw = false;
	struct nbl_flow_tnl_vtep_hnode *search_vtep_node;
	struct nbl_flow_tnl_vtep_node vtep_zero;

	memset(&vtep_zero, 0, sizeof(vtep_zero));

	mutex_lock(&draco_mgt->ped_lock[NBL_DRACO_PED_TNL_VTEP_TYPE]);
	ped_tbl = draco_mgt->pedit_res[NBL_DRACO_PED_TNL_VTEP_TYPE].pedit_tbl;
	search_vtep_node = nbl_common_get_hash_node(ped_tbl, &vtep_node->vtep_key);
	if (search_vtep_node) {
		search_vtep_node->ref_cnt--;
		ref_cnt = search_vtep_node->ref_cnt;
		if (!search_vtep_node->ref_cnt) {
			need_del_hw = true;
			encap_vtep_idx = search_vtep_node->vtep_id;
			nbl_common_free_hash_node(ped_tbl, &search_vtep_node->vtep_key);
		}
	}
	mutex_unlock(&draco_mgt->ped_lock[NBL_DRACO_PED_TNL_VTEP_TYPE]);

	nbl_debug(common, NBL_DEBUG_FLOW, "free encap vtep: idx:%u, ref_cnt:%u, del_hw:%u",
		  encap_vtep_idx, ref_cnt, need_del_hw);

	if (need_del_hw) {
		nbl_devshr_free_idx(NBL_DEVSHR_INDEX_ENCAP_VTEP, common->pdev, encap_vtep_idx);
		nbl_draco_cmdq_write_ped_table(draco_mgt, (u8 *)&vtep_zero, encap_vtep_idx,
					       NBL_DRACO_PED_TNL_VTEP_TYPE);
	}
}

static void nbl_draco_free_ped_encap_tnl(struct nbl_common_info *common,
					 struct nbl_draco_flow_mgt *draco_mgt,
					 struct nbl_flow_tnl_prof_hnode *prof_node)
{
	void *ped_tbl;
	u32 encap_tnl_idx = 0;
	u32 ref_cnt = 0;
	bool need_del_hw = false;
	struct nbl_flow_tnl_prof_hnode *search_prof_node;
	struct nbl_flow_tnl_prof_node prof_node_zero;

	memset(&prof_node_zero, 0, sizeof(prof_node_zero));

	mutex_lock(&draco_mgt->ped_lock[NBL_DRACO_PED_TNL_TYPE]);
	ped_tbl = draco_mgt->pedit_res[NBL_DRACO_PED_TNL_TYPE].pedit_tbl;
	search_prof_node = nbl_common_get_hash_node(ped_tbl, &prof_node->prof_key);
	if (search_prof_node) {
		search_prof_node->ref_cnt--;
		ref_cnt = search_prof_node->ref_cnt;
		if (!search_prof_node->ref_cnt) {
			need_del_hw = true;
			encap_tnl_idx = search_prof_node->tnl_idx;
			nbl_common_free_hash_node(ped_tbl, &search_prof_node->prof_key);
		}
	}
	mutex_unlock(&draco_mgt->ped_lock[NBL_DRACO_PED_TNL_TYPE]);

	nbl_debug(common, NBL_DEBUG_FLOW, "free encap tbl: idx:%u, ref_cnt:%u, del_hw:%u",
		  encap_tnl_idx, ref_cnt, need_del_hw);

	if (need_del_hw) {
		nbl_devshr_free_idx(NBL_DEVSHR_INDEX_ENCAP_TNL,
				    draco_mgt->res_mgt->common->pdev, encap_tnl_idx);
		nbl_draco_cmdq_write_ped_table(draco_mgt, (u8 *)&prof_node_zero, encap_tnl_idx,
					       NBL_DRACO_PED_TNL_TYPE);
	}
}

static void
nbl_draco_free_ped(struct nbl_draco_flow_node *node, struct nbl_draco_flow_mgt *draco_mgt)
{
	int idx = 0;
	struct nbl_common_info *common = draco_mgt->res_mgt->common;
	struct nbl_flow_tnl_decap_tcam_hnode *decap_node;
	struct nbl_flow_tnl_vtep_hnode *vtep_node;
	struct nbl_flow_tnl_prof_hnode *prof_node;

	for (idx = 0; idx < NBL_DRACO_NEED_PED_RECORD_TYPE_END; idx++) {
		if (!node->ped_info.ped_info[idx].ped_valid)
			continue;
		switch (idx) {
		case NBL_DRACO_PED_MCC_TYPE:
			nbl_draco_free_ped_mcc(common, draco_mgt, node);
			break;
		case NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE: {
			/* In bond mode, decap_vtep hash node was inserted into common pedit_tbl,
			 * so free must target the same table; in non-bond, use current PF.
			 */
			struct nbl_resource_mgt *decap_tgt_res_mgt =
					nbl_draco_decap_get_target_res_mgt(draco_mgt->res_mgt);
			struct nbl_tc_flow_mgt *decap_tgt_tc_mgt =
					NBL_RES_MGT_TO_TC_FLOW_MGT(decap_tgt_res_mgt);
			struct nbl_draco_flow_mgt *decap_tgt_mgt =
					decap_tgt_tc_mgt->priv_flow_mgt;
			void *decap_tgt_tbl = decap_tgt_mgt->pedit_res[idx].pedit_tbl;

			decap_node = node->ped_info.ped_info[idx].data;
			nbl_draco_free_ped_decap_vtep(decap_tgt_mgt, decap_tgt_tbl, decap_node);
			break;
		}
		case NBL_DRACO_PED_TNL_VTEP_TYPE:
			vtep_node = node->ped_info.ped_info[idx].data;
			nbl_draco_free_ped_encap_vtep(common, draco_mgt, vtep_node);
			break;
		case NBL_DRACO_PED_TNL_TYPE:
			prof_node = node->ped_info.ped_info[idx].data;
			nbl_draco_free_ped_encap_tnl(common, draco_mgt, prof_node);
			break;
		case NBL_DRACO_PED_UMAC_TYPE:
		case NBL_DRACO_PED_DMAC_TYPE:
		case NBL_DRACO_PED_UIP_TYPE:
		case NBL_DRACO_PED_DIP_TYPE:
			nbl_draco_free_ped_mac_ip(node, draco_mgt, idx);
			break;
		default:
			nbl_err(common, NBL_DEBUG_FLOW, "not support ped type:%u", idx);
			return;
		}
	}
}

static int nbl_draco_flow_free_node(struct nbl_resource_mgt *res_mgt,
				    struct nbl_draco_flow_node *node)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_draco_flow_mgt *draco_mgt = tc_flow_mgt->priv_flow_mgt;
	u8 profile_id = node->profile_index;

	if (node->offloaded)
		nbl_draco_flow_remove_node_hw(draco_mgt, node);

	if (node->kt_index)
		nbl_draco_flow_put_kt_idx(draco_mgt, &node->kt_info, node->kt_index);

	nbl_draco_free_ped(node, draco_mgt);

	if (node->assoc_tbl_id & NBL_DRACO_ASSOC_TBL_ID_MASK)
		nbl_bitmap_mng_release_id(&draco_mgt->assoc_table_mng,
					  node->assoc_tbl_id & NBL_DRACO_ASSOC_TBL_ID_MASK);

	nbl_common_free_hash_node(tc_flow_mgt->flow_tab_hash[profile_id].flow_tab_hash,
				  &node->key);
	node = NULL;

	if (tc_flow_mgt->flow_tab_hash[profile_id].tab_cnt > 0) {
		tc_flow_mgt->flow_tab_hash[profile_id].tab_cnt--;
		nbl_debug(common, NBL_DEBUG_FLOW, "tc flow rm pid=%d tab_cnt--=%d\n",
			  profile_id, tc_flow_mgt->flow_tab_hash[profile_id].tab_cnt);
	} else {
		nbl_info(common, NBL_DEBUG_FLOW, "tc flow rm pid=%d tab_cnt=%d, do not reduce\n",
			 profile_id, tc_flow_mgt->flow_tab_hash[profile_id].tab_cnt);
		return -EINVAL;
	}

	return 0;
}

static void nbl_draco_flow_set_action_data(u32 *key, u32 value, u16 length, u16 offset)
{
	u32 index = offset / NBL_BITS_IN_U32;
	u32 remain = offset % NBL_BITS_IN_U32;
	u32 shifted = 0;

	if (NBL_BITS_IN_U32 - remain < length) {
		/* if the value span across u32 boundary */
		shifted = NBL_BITS_IN_U32 - remain;
		key[index] |= (value << remain);
		key[index + 1] |= (value >> shifted);
	} else {
		key[index] |= (value << remain);
	}
}

static int nbl_draco_flow_drop_2hw(struct nbl_tc_flow_mgt *mgt, u32 *key,
				   struct nbl_rule_action *action,
				   union nbl_action_bits_ext *act_bits,
				   s16 *offsets)
{
	u16 data_len = NBL_BITS_IN_U16;
	union dport_action set_dest;

	memset(&set_dest, 0, sizeof(set_dest));

	act_bits->extab.SET_DEST = 1;
	set_dest.down.dir = DPORT_DIR_OTHER;
	set_dest.down.other_type = DPORT_OTHER_TYPE_DROP;
	set_dest.down.next_stg = NBL_NEXT_STAGE_EPRO;

	*offsets -= data_len;
	if (*offsets < 0) {
		nbl_err(mgt->res_mgt->common, NBL_DEBUG_FLOW, "ad is overlimit in drop.\n");
		return -EINVAL;
	}

	nbl_draco_flow_set_action_data(key, set_dest.data, data_len, *offsets);

	return 0;
}

static int nbl_draco_flow_mcc_action_2hw(struct nbl_tc_flow_mgt *mgt, u32 *key,
					 struct nbl_rule_action *action,
					 union nbl_action_bits_ext *act_bits,
					 s16 *offsets)
{
	u16 data_len = NBL_BITS_IN_U16;
	u32 mcc_idx = 0;
	u32 port_id = 0;
	int ret = 0;
	int idx = 0;
	struct nbl_common_info *common = mgt->res_mgt->common;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(mgt->res_mgt);
	struct nbl_draco_flow_mcc_tbl mcc_tbl_node = {  .vld = 1,
							.clr_udf_btm0 = 1,
							.clr_udf_btm1 = 1,};
	union dport_action mcc_info = { .mcc.other_type = DPORT_OTHER_TYPE_MC,
					.mcc.dir = DPORT_DIR_OTHER,
					.mcc.strip_act = 0,
					.mcc.next_stg = NBL_NEXT_STAGE_ACL0, };
	*offsets -= data_len;
	if (*offsets < 0) {
		nbl_err(common, NBL_DEBUG_FLOW, "ad is overlimit in mirror\n");
		return -EINVAL;
	}

	act_bits->extab.SET_DEST = 1;

	ret = nbl_devshr_alloc_idx(NBL_DEVSHR_INDEX_MCC, common->pdev, &mcc_idx);
	if (ret) {
		nbl_err(common, NBL_DEBUG_FLOW, "nbl tc alloc mcc idx failed, ret %d", ret);
		return ret;
	}

	mcc_info.mcc.mgid = mcc_idx;

	for (idx = 0; idx < action->mcc_cnt; idx++) {
		switch (action->port_mcc[idx].port_type) {
		case NBL_TC_PORT_TYPE_BOND:
			port_id = action->port_mcc[idx].dport_id;
			mcc_tbl_node.leaf_dport_lag |= BIT(port_id);
			break;
		case NBL_TC_PORT_TYPE_ETH:
			port_id = action->port_mcc[idx].dport_id;
			mcc_tbl_node.leaf_dport_eth |= BIT(port_id);
			break;
		case NBL_TC_PORT_TYPE_VSI:
			port_id = action->port_mcc[idx].dport_id;
			if (port_id >= 0 && port_id <= 56)
				mcc_tbl_node.leaf_dport_vsi_0_56 |= BIT(port_id);
			else if (port_id >= 57 && port_id <= 120)
				mcc_tbl_node.leaf_dport_vsi_57_120 |= BIT(port_id - 57);
			else if (port_id >= 121 && port_id <= 184)
				mcc_tbl_node.leaf_dport_vsi_121_184 |= BIT(port_id - 121);
			else if (port_id >= 185 && port_id <= 248)
				mcc_tbl_node.leaf_dport_vsi_185_248 |= BIT(port_id - 185);
			else if (port_id >= 249 && port_id <= 277)
				mcc_tbl_node.leaf_dport_vsi_249_277 |= BIT(port_id - 249);
			nbl_debug(common, NBL_DEBUG_FLOW, "port_type vsi, port id:%u", port_id);
			break;
		default:
			nbl_err(common, NBL_DEBUG_FLOW, "nbl tc mirror out port type invalid, idx: %d, type %u",
				idx, action->port_mcc[idx].port_type);
			return -EINVAL;
		}
	}

	atomic_inc(&g_mirror_cnt);

	phy_ops->write_ped_tbl(NBL_RES_MGT_TO_PHY_PRIV(mgt->res_mgt), (u8 *)&mcc_tbl_node, mcc_idx,
			       NBL_DRACO_PED_MCC_TYPE);

	action->ped_info.ped_info[NBL_DRACO_PED_MCC_TYPE].ped_idx = mcc_idx;
	action->ped_info.ped_info[NBL_DRACO_PED_MCC_TYPE].ped_valid = 1;
	nbl_draco_flow_set_action_data(key, mcc_info.data, data_len, *offsets);

	return 0;
}

static int nbl_draco_flow_set_dest_action_2hw(struct nbl_tc_flow_mgt *mgt, u32 *key,
					      struct nbl_rule_action *action,
					      union nbl_action_bits_ext *act_bits,
					      s16 *offsets, bool is_acl)
{
	u16 data_len = NBL_BITS_IN_U16;
	union dport_action set_dest;

	memset(&set_dest, 0, sizeof(set_dest));

	act_bits->extab.SET_DEST = 1;
	if (action->port_id >= NBL_FLOW_ETH_REP_0 &&
	    action->port_id <= NBL_FLOW_ETH_REP_3) {
		set_dest.down.dir = DPORT_DIR_OTHER;
		set_dest.down.other_type = DPORT_OTHER_TYPE_ETH;
		set_dest.down.eth_id =
			(action->port_id % NBL_FLOW_ETH_REP_0);
		set_dest.down.next_stg = NBL_NEXT_STAGE_ACL0;
		set_dest.down.lag_vld = 0;
		set_dest.down.lag_id = 0;
	} else if (action->port_id >= NBL_FLOW_BOND_REP_PORT_ID) {
		set_dest.down.dir = DPORT_DIR_OTHER;
		set_dest.down.other_type = DPORT_OTHER_TYPE_ETH;
		set_dest.down.next_stg = NBL_NEXT_STAGE_ACL0;
		set_dest.down.lag_vld = 1;
		set_dest.down.eth_id =
			(action->port_id % NBL_FLOW_ETH_REP_0);
		set_dest.down.lag_id = action->lag_id;
	} else {
		set_dest.up.vsi_id = action->port_id;
		set_dest.up.dir = DPORT_DIR_RX;
		set_dest.up.next_stg = NBL_NEXT_STAGE_ACL0;
		set_dest.up.DQ_V = 0;
		set_dest.up.strip_act = 0;
	}

	*offsets -= data_len;
	if (*offsets < 0)  {
		nbl_err(mgt->res_mgt->common, NBL_DEBUG_FLOW, "ad is overlimit in dport\n");
		return -EINVAL;
	}

	/* if is ACL, set next stage to EPRO */
	if (is_acl)
		set_dest.up.next_stg = NBL_NEXT_STAGE_EPRO;

	nbl_draco_flow_set_action_data(key, set_dest.data, data_len, *offsets);

	return 0;
}

static int
nbl_draco_flow_port_id_action_2hw(struct nbl_tc_flow_mgt *mgt, u32 *key,
				  struct nbl_rule_action *action,
				  union nbl_action_bits_ext *act_bits,
				  s16 *offsets)
{
	/* if is a mcc, return mcc_process */
	if (action->mcc_cnt > 1)
		return nbl_draco_flow_mcc_action_2hw(mgt, key, action, act_bits, offsets);

	return nbl_draco_flow_set_dest_action_2hw(mgt, key, action, act_bits, offsets, false);
}

static int nbl_draco_udf_data_2hw(struct nbl_tc_flow_mgt *mgt, u32 *key,
				  struct nbl_rule_action *action,
				  union nbl_action_bits_ext *act_bits,
				  s16 *offsets)
{
	u16 data_len = NBL_DRACO_UDF_ID_SET_STAT_CAR_LEN;
	union nbl_flow_udfs udf;

	memset(&udf, 0, sizeof(udf));

	/* set UDF data for flow stat action */
	act_bits->extab.SET_UDF = NBL_DRACO_UDF_ID_SET_STAT_CAR;
	udf.info.flow_stat_id = action->counter_id & NBL_DRACO_UDF_STAT_ID_VLD_BITS;
	udf.info.flow_stat_vld = 1;

	*offsets -= data_len;
	if (*offsets < 0) {
		nbl_err(mgt->res_mgt->common, NBL_DEBUG_FLOW, "ad is overlimit in flow car.");
		return -EINVAL;
	}

	/* record counter_id offset for later update */
	action->counter_oft = *offsets;
	nbl_draco_flow_set_action_data(key, udf.data[1], data_len, *offsets);

	return 0;
}

static int nbl_draco_flow_vlan_action_2hw(struct nbl_tc_flow_mgt *mgt, u32 *key,
					  struct nbl_rule_action *action,
					  union nbl_action_bits_ext *act_bits,
					  s16 *offsets)
{
	int ret = 0;
	u16 data_len = 0;
	u32 data = 0;
	struct nbl_draco_vlan_info *vlan_info = (struct nbl_draco_vlan_info *)&data;

	/* action had set before */
	if (act_bits->extab.VLAN_OP)
		return 0;

	act_bits->extab.VLAN_OP = action->vlan_info.vlan_op;

	switch (action->vlan_info.vlan_op) {
	case NBL_FLOW_VLAN_POP:
	case NBL_FLOW_VLAN_POP2:
		break;
	case NBL_FLOW_VLAN_PUSH:
		data = action->vlan_info.ovlan_tag;
		data_len = NBL_BITS_IN_U16;
		/* no vlan, push need change to outer */
		if (!action->vlan_info.has_vlan)
			data = action->vlan_info.ivlan_tag;
		vlan_info->tpid_sel = action->vlan_info.ivlan_idx;

		break;
	case NBL_FLOW_VLAN_REP_BOTH:
	case NBL_FLOW_VLAN_PUSH2:
	case NBL_FLOW_VLAN_PUSH_REP:
		data = action->vlan_info.ovlan_tag;
		data = (data << NBL_BITS_IN_U16) | action->vlan_info.ivlan_tag;
		data_len = NBL_BITS_IN_U32;
		vlan_info->tpid_sel = action->vlan_info.ivlan_idx;
		++vlan_info;
		vlan_info->tpid_sel = action->vlan_info.ovlan_idx;
		break;
	case NBL_FLOW_VLAN_REP_IVLAN_POP:
		data = action->vlan_info.ivlan_tag;
		data_len = NBL_BITS_IN_U16;
		vlan_info->tpid_sel  = action->vlan_info.ivlan_idx;
		break;
	case NBL_FLOW_VLAN_REP_OVLAN:
		data = action->vlan_info.ovlan_tag;
		data_len = NBL_BITS_IN_U16;
		/* got a vlan, push need change to inner */
		if (action->vlan_info.has_vlan)
			data = action->vlan_info.ivlan_tag;
		vlan_info->tpid_sel = action->vlan_info.ivlan_idx;

		break;
	default:
		nbl_debug(mgt->res_mgt->common, NBL_DEBUG_FLOW, "no need do vlan edit\n");
		break;
	}

	nbl_debug(mgt->res_mgt->common, NBL_DEBUG_FLOW, "vlan ped(%u) data is:%u-(%u)\n",
		  action->vlan_info.vlan_op, data, action->port_id);
	*offsets -= data_len;
	if (*offsets < 0)  {
		nbl_debug(mgt->res_mgt->common, NBL_DEBUG_FLOW, "ad is overlimit in vlan_op\n");
		return -EINVAL;
	}

	if (data_len)
		nbl_draco_flow_set_action_data(key, data, data_len, *offsets);

	return ret;
}

static int nbl_draco_flow_set_sp_action_2hw(struct nbl_tc_flow_mgt *mgt, u32 *key,
					    struct nbl_rule_action *action,
					    union nbl_action_bits_ext *act_bits,
					    s16 *offsets)
{
	u16 data_len = NBL_BITS_IN_U16;
	u16 data;

	act_bits->extab.SET_SP = 1;
	*offsets -= data_len;
	if (*offsets < 0)  {
		nbl_err(mgt->res_mgt->common, NBL_DEBUG_FLOW, "ad is overlimit in set sport\n");
		return -EINVAL;
	}

	if (action->tc_pedit_info.pedit_node.pedit_proto)
		data = be16_to_cpu(action->tc_pedit_info.val.udp.source);
	else
		data = be16_to_cpu(action->tc_pedit_info.val.tcp.source);

	nbl_debug(mgt->res_mgt->common, NBL_DEBUG_FLOW, "set sport:proto:%d, orig-udp:0x%x, orig-tcp:0x%x, new:0x%x\n",
		  action->tc_pedit_info.pedit_node.pedit_proto,
		  action->tc_pedit_info.val.udp.source,
		  action->tc_pedit_info.val.tcp.source, data);
	nbl_draco_flow_set_action_data(key, data, data_len, *offsets);

	return 0;
}

static int nbl_draco_flow_set_dp_action_2hw(struct nbl_tc_flow_mgt *mgt, u32 *key,
					    struct nbl_rule_action *action,
					    union nbl_action_bits_ext *act_bits,
					    s16 *offsets)
{
	u16 data_len = NBL_BITS_IN_U16;
	u16 data;

	act_bits->extab.SET_DP = 1;
	*offsets -= data_len;
	if (*offsets < 0)  {
		nbl_err(mgt->res_mgt->common, NBL_DEBUG_FLOW, "ad is overlimit in set dport\n");
		return -EINVAL;
	}

	if (action->tc_pedit_info.pedit_node.pedit_proto)
		data = be16_to_cpu(action->tc_pedit_info.val.udp.dest);
	else
		data = be16_to_cpu(action->tc_pedit_info.val.tcp.dest);

	nbl_debug(mgt->res_mgt->common, NBL_DEBUG_FLOW, "set dport:proto:%d, orig-udp:0x%x, orig-tcp:0x%x, new:0x%x\n",
		  action->tc_pedit_info.pedit_node.pedit_proto, action->tc_pedit_info.val.udp.dest,
		  action->tc_pedit_info.val.tcp.dest, data);
	nbl_draco_flow_set_action_data(key, data, data_len, *offsets);

	return 0;
}

static int nbl_draco_flow_set_sip4_action_2hw(struct nbl_tc_flow_mgt *mgt, u32 *key,
					      struct nbl_rule_action *action,
					      union nbl_action_bits_ext *act_bits,
					      s16 *offsets)
{
	u16 data_len = NBL_DRACO_ACTION_LEN_IP4NAT;

	act_bits->extab.SET_SIP = 1;
	*offsets -= data_len;
	if (*offsets < 0) {
		nbl_err(mgt->res_mgt->common, NBL_DEBUG_FLOW, "ad is overlimit in sip4\n");
		return -EINVAL;
	}

	nbl_draco_flow_set_action_data(key, be32_to_cpu(action->tc_pedit_info.val.ip4.saddr),
				       data_len, *offsets);

	return 0;
}

static int nbl_draco_flow_set_dip4_action_2hw(struct nbl_tc_flow_mgt *mgt, u32 *key,
					      struct nbl_rule_action *action,
					      union nbl_action_bits_ext *act_bits,
					      s16 *offsets)
{
	u16 data_len = NBL_DRACO_ACTION_LEN_IP4NAT;

	act_bits->extab.SET_DIP = 1;
	*offsets -= data_len;
	if (*offsets < 0) {
		nbl_err(mgt->res_mgt->common, NBL_DEBUG_FLOW, "ad is overlimit in dip4\n");
		return -EINVAL;
	}

	nbl_draco_flow_set_action_data(key, be32_to_cpu(action->tc_pedit_info.val.ip4.daddr),
				       data_len, *offsets);

	return 0;
}

static int nbl_draco_flow_set_ip6_process(struct nbl_tc_flow_mgt *mgt, u32 *key,
					  struct nbl_rule_action *action,
					  s16 *offsets, bool is_sip)
{
	const struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(mgt->res_mgt);
	u16 data_len = NBL_DRACO_ACTION_LEN_IP6NAT;
	struct nbl_draco_flow_mgt *draco_mgt = mgt->priv_flow_mgt;
	void *pedit_tbl = draco_mgt->pedit_res[NBL_DRACO_PED_UIP_TYPE].pedit_tbl;
	struct nbl_tc_pedit_entry in_e, *h_e, *new_e;
	u32 ip_idx = 0;
	int idx = 0, oft = 0, ret = 0;
	char ip6[128];
	bool is_new = false;
	u32 *cur_ip_s = (u32 *)&in_e.ip6;
	u32 *ip = &action->tc_pedit_info.val.ip6.daddr.in6_u.u6_addr32[3];
	enum nbl_draco_ped_type ped_type = NBL_DRACO_PED_DIP_TYPE;

	*offsets -= data_len;
	if (*offsets < 0) {
		nbl_err(common, NBL_DEBUG_FLOW, "ad is overlimit in ip6, offsets:%d\n", *offsets);
		return -1;
	}

	memset(&in_e, 0, sizeof(in_e));
	memset(ip6, 0, sizeof(ip6));

	if (is_sip) {
		ip = &action->tc_pedit_info.val.ip6.saddr.in6_u.u6_addr32[3];
		ped_type = NBL_DRACO_PED_UIP_TYPE;
	}

	for (idx = 0; idx < 4; ++idx) {
		*cur_ip_s = be32_to_cpu(*ip);
		oft += snprintf(&ip6[oft], 128 - oft, "-%x", *cur_ip_s);
		--ip;
		++cur_ip_s;
	}

	mutex_lock(&draco_mgt->ped_lock[NBL_DRACO_PED_UIP_TYPE]);

	h_e = nbl_common_get_hash_node(pedit_tbl, in_e.ip6);
	if (h_e) {
		ip_idx = h_e->hnode.node_idx;
		h_e->hnode.ref_cnt++;
		nbl_debug(common, NBL_DEBUG_FLOW, "ip already exist, is_sip:%u, ip_idx:%u, ref_cnt:%u, ip:%s",
			  is_sip, ip_idx, h_e->hnode.ref_cnt, ip6);
		action->ped_info.ped_info[ped_type].data = h_e;
	} else {
		ret = nbl_devshr_alloc_idx(NBL_DEVSHR_INDEX_IP, common->pdev, &ip_idx);
		if (ret) {
			mutex_unlock(&draco_mgt->ped_lock[NBL_DRACO_PED_UIP_TYPE]);
			nbl_err(common, NBL_DEBUG_FLOW, "alloc ip idx failed, ip:%s, ret %d",
				ip6, ret);
			return ret;
		}

		in_e.hnode.node_idx = ip_idx;
		in_e.hnode.ref_cnt = 1;

		ret = nbl_common_alloc_hash_node(pedit_tbl, in_e.ip6, &in_e, (void **)&new_e);
		if (ret) {
			nbl_devshr_free_idx(NBL_DEVSHR_INDEX_IP, common->pdev, ip_idx);
			mutex_unlock(&draco_mgt->ped_lock[NBL_DRACO_PED_UIP_TYPE]);
			nbl_err(common, NBL_DEBUG_FLOW, "alloc ip hash node failed, ip:%s, ret %d",
				ip6, ret);
			return ret;
		}
		is_new = true;
		action->ped_info.ped_info[ped_type].data = new_e;
	}

	mutex_unlock(&draco_mgt->ped_lock[NBL_DRACO_PED_UIP_TYPE]);

	if (is_new) {
		ret = nbl_draco_cmdq_write_ped_table(draco_mgt, in_e.ip6, (u16)ip_idx,
						     NBL_DRACO_PED_UIP_TYPE);
		if (ret) {
			nbl_common_free_hash_node(pedit_tbl, in_e.ip6);
			nbl_devshr_free_idx(NBL_DEVSHR_INDEX_IP, common->pdev, ip_idx);
			action->ped_info.ped_info[ped_type].data = NULL;
			nbl_err(common, NBL_DEBUG_FLOW, "write ipto hw failed, ip:%s, ret %d",
				ip6, ret);
			return ret;
		}
	}

	nbl_draco_cmdq_read_ped_table(draco_mgt, in_e.ip6, (u16)ip_idx, NBL_DRACO_PED_UIP_TYPE);

	nbl_draco_flow_set_action_data(key, ip_idx, data_len, *offsets);

	nbl_debug(common, NBL_DEBUG_FLOW, "edit ip, is_new:%u, is_sip:%u, ip:%s, ip_idx:%u",
		  is_new, is_sip, ip6, ip_idx);

	action->ped_info.ped_info[ped_type].ped_valid = 1;
	action->ped_info.ped_info[ped_type].ped_idx = ip_idx;

	return 0;
}

static int nbl_draco_flow_set_sip6_action_2hw(struct nbl_tc_flow_mgt *mgt, u32 *key,
					      struct nbl_rule_action *action,
					      union nbl_action_bits_ext *act_bits,
					      s16 *offsets)
{
	act_bits->extab.SET_SIP = 1;
	return nbl_draco_flow_set_ip6_process(mgt, key, action, offsets, true);
}

static int nbl_draco_flow_set_dip6_action_2hw(struct nbl_tc_flow_mgt *mgt, u32 *key,
					      struct nbl_rule_action *action,
					      union nbl_action_bits_ext *act_bits,
					      s16 *offsets)
{
	act_bits->extab.SET_DIP = 1;
	return nbl_draco_flow_set_ip6_process(mgt, key, action, offsets, false);
}

static int nbl_draco_flow_set_mac_process(struct nbl_tc_flow_mgt *mgt, u32 *key,
					  struct nbl_rule_action *action,
					  s16 *offsets, bool is_smac)
{
	struct nbl_tc_pedit_entry in_e, *h_e, *new_e;
	struct nbl_draco_flow_mgt *draco_mgt = mgt->priv_flow_mgt;
	struct nbl_common_info *common = mgt->res_mgt->common;
	void *pedit_tbl = draco_mgt->pedit_res[NBL_DRACO_PED_UMAC_TYPE].pedit_tbl;
	u8 *data = action->tc_pedit_info.val.eth.h_dest;
	u16 data_len = NBL_DRACO_ACTION_LEN_MACNAT;
	u32 mac_idx = 0;
	u8 *cur_mac;
	char mac[128];
	int oft = 0, idx = 0, ret = 0;
	bool is_new = false;
	enum nbl_draco_ped_type ped_type = NBL_DRACO_PED_DMAC_TYPE;

	memset(&in_e, 0, sizeof(in_e));
	memset(mac, 0, sizeof(mac));
	cur_mac = in_e.mac;

	if (is_smac) {
		data = action->tc_pedit_info.val.eth.h_source;
		ped_type = NBL_DRACO_PED_UMAC_TYPE;
	}

	for (idx = 0; idx < ETH_ALEN; ++idx) {
		*cur_mac = data[ETH_ALEN - 1 - idx];
		oft += snprintf(&mac[oft], 128 - oft, "-%x", *cur_mac);
		++cur_mac;
	}

	*offsets -= data_len;
	if (*offsets < 0) {
		nbl_err(mgt->res_mgt->common, NBL_DEBUG_FLOW, "ad is overlimit in mac\n");
		return -EINVAL;
	}

	mutex_lock(&draco_mgt->ped_lock[NBL_DRACO_PED_UMAC_TYPE]);

	h_e = nbl_common_get_hash_node(pedit_tbl, in_e.mac);
	if (h_e) {
		mac_idx = h_e->hnode.node_idx;
		h_e->hnode.ref_cnt++;
		action->ped_info.ped_info[ped_type].data = h_e;
		nbl_debug(common, NBL_DEBUG_FLOW, "already exist, is_smac:%u, mac_idx:%u, ref_cnt:%u, h_e:%p, mac:%s",
			  is_smac, mac_idx, h_e->hnode.ref_cnt, h_e, mac);
	} else {
		ret = nbl_devshr_alloc_idx(NBL_DEVSHR_INDEX_MAC, common->pdev, &mac_idx);
		if (ret) {
			mutex_unlock(&draco_mgt->ped_lock[NBL_DRACO_PED_UMAC_TYPE]);
			nbl_err(common, NBL_DEBUG_FLOW, "alloc mac idx failed, mac:%s, ret %d",
				mac, ret);
			return ret;
		}

		in_e.hnode.node_idx = mac_idx;
		in_e.hnode.ref_cnt = 1;

		ret = nbl_common_alloc_hash_node(pedit_tbl, in_e.mac, &in_e, (void **)&new_e);
		if (ret) {
			nbl_devshr_free_idx(NBL_DEVSHR_INDEX_MAC, common->pdev, mac_idx);
			mutex_unlock(&draco_mgt->ped_lock[NBL_DRACO_PED_UMAC_TYPE]);
			nbl_err(common, NBL_DEBUG_FLOW, "alloc mac hash node failed, mac:%s, ret %d",
				mac, ret);
			return ret;
		}
		is_new = true;
		action->ped_info.ped_info[ped_type].data = new_e;
	}
	mutex_unlock(&draco_mgt->ped_lock[NBL_DRACO_PED_UMAC_TYPE]);

	if (is_new) {
		ret = nbl_draco_cmdq_write_ped_table(draco_mgt, in_e.mac, (u16)mac_idx,
						     NBL_DRACO_PED_UMAC_TYPE);
		if (ret) {
			nbl_common_free_hash_node(pedit_tbl, in_e.mac);
			nbl_devshr_free_idx(NBL_DEVSHR_INDEX_MAC, common->pdev, mac_idx);
			action->ped_info.ped_info[ped_type].data = NULL;
			nbl_err(common, NBL_DEBUG_FLOW, "write mac to hw failed, mac:%s, ret %d",
				mac, ret);
			return ret;
		}
	}

	nbl_draco_cmdq_read_ped_table(draco_mgt, in_e.mac, (u16)mac_idx, NBL_DRACO_PED_UMAC_TYPE);

	nbl_draco_flow_set_action_data(key, mac_idx, data_len, *offsets);

	nbl_debug(common, NBL_DEBUG_FLOW, "is_smac:%u, mac_idx:%u, offsets:%u, is_new:%u, mac:%s",
		  is_smac, mac_idx, *offsets, is_new, mac);

	action->ped_info.ped_info[ped_type].ped_valid = 1;
	action->ped_info.ped_info[ped_type].ped_idx = mac_idx;

	return 0;
}

static int nbl_draco_flow_set_smac_action_2hw(struct nbl_tc_flow_mgt *mgt, u32 *key,
					      struct nbl_rule_action *action,
					      union nbl_action_bits_ext *act_bits,
					      s16 *offsets)
{
	act_bits->extab.SET_SMAC = 1;
	return nbl_draco_flow_set_mac_process(mgt, key, action, offsets, true);
}

static int nbl_draco_flow_set_dmac_action_2hw(struct nbl_tc_flow_mgt *mgt, u32 *key,
					      struct nbl_rule_action *action,
					      union nbl_action_bits_ext *act_bits,
					      s16 *offsets)
{
	act_bits->extab.SET_DMAC = 1;
	return nbl_draco_flow_set_mac_process(mgt, key, action, offsets, false);
}

static int nbl_draco_flow_decap_tnl_action_2hw(struct nbl_tc_flow_mgt *mgt, u32 *key,
					       struct nbl_rule_action *action,
					       union nbl_action_bits_ext *act_bits,
					       s16 *offsets)
{
	u16 decap_assd_idx = action->vtep_info.vtep_id;
	struct nbl_common_info *common = mgt->res_mgt->common;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(mgt->res_mgt);
	struct nbl_flow_tnl_decap_tcam_hnode *decap_node =
				action->ped_info.ped_info[NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE].data;

	act_bits->extab.TNL_OP = 1;
	if (!action->vtep_info.vtep_vld || !decap_node) {
		nbl_info(common, NBL_DEBUG_FLOW, "vtep_info invalid or decap_node is NULL");
		return -EINVAL;
	}

	if (action->vtep_info.vtep_id == 0) {
		nbl_info(common, NBL_DEBUG_FLOW, "vtep_idx 0 is not a valid idx");
		return -EINVAL;
	}

	if (!action->vtep_info.vtep_is_ref) {
		phy_ops->write_ped_tbl(NBL_RES_MGT_TO_PHY_PRIV(mgt->res_mgt),
				       (u8 *)&decap_node->decap_tcam_key, decap_assd_idx,
				       NBL_DRACO_PED_TNL_DECAP_TCAM_TYPE);
		phy_ops->write_ped_tbl(NBL_RES_MGT_TO_PHY_PRIV(mgt->res_mgt),
				       (u8 *)&decap_node->decap_assd_node, decap_assd_idx,
				       NBL_DRACO_PED_TNL_DECAP_ASSD_TYPE);
	}

	return 0;
}

static void nbl_draco_free_encap_vtep(struct nbl_draco_flow_mgt *mgt,
				      struct nbl_flow_tnl_vtep_node *vtep_node)
{
	struct nbl_flow_tnl_vtep_hnode *encap_vtep;
	void *ped_tbl = mgt->pedit_res[NBL_DRACO_PED_TNL_VTEP_TYPE].pedit_tbl;

	mutex_lock(&mgt->ped_lock[NBL_DRACO_PED_TNL_VTEP_TYPE]);
	encap_vtep = nbl_common_get_hash_node(ped_tbl, vtep_node);
	if (encap_vtep) {
		encap_vtep->ref_cnt--;
		if (!encap_vtep->ref_cnt) {
			nbl_devshr_free_idx(NBL_DEVSHR_INDEX_ENCAP_VTEP,
					    mgt->res_mgt->common->pdev, encap_vtep->vtep_id);
			nbl_common_free_hash_node(ped_tbl, vtep_node);
		}
	}
	mutex_unlock(&mgt->ped_lock[NBL_DRACO_PED_TNL_VTEP_TYPE]);
}

static void nbl_draco_free_encap_tnl(struct nbl_draco_flow_mgt *mgt,
				     struct nbl_flow_tnl_prof_node *prof_node)
{
	struct nbl_flow_tnl_prof_hnode *encap_prof;
	void *ped_tbl = mgt->pedit_res[NBL_DRACO_PED_TNL_TYPE].pedit_tbl;

	mutex_lock(&mgt->ped_lock[NBL_DRACO_PED_TNL_TYPE]);
	encap_prof = nbl_common_get_hash_node(ped_tbl, prof_node);
	if (encap_prof) {
		encap_prof->ref_cnt--;
		if (!encap_prof->ref_cnt) {
			nbl_devshr_free_idx(NBL_DEVSHR_INDEX_ENCAP_TNL,
					    mgt->res_mgt->common->pdev, encap_prof->tnl_idx);
			nbl_common_free_hash_node(ped_tbl, prof_node);
		}
	}
	mutex_unlock(&mgt->ped_lock[NBL_DRACO_PED_TNL_TYPE]);
}

static int nbl_draco_add_vtep_add_encap(struct nbl_draco_flow_mgt *mgt,
					struct nbl_flow_tnl_vtep_node *vtep_node,
					struct nbl_flow_tnl_prof_node *prof_node,
					struct nbl_rule_action *action,
					u16 *tnl_idx, bool is_mirr)
{
	struct nbl_flow_tnl_prof_hnode *search_prof_node = NULL;
	struct nbl_flow_tnl_prof_hnode new_prof_node;
	struct nbl_flow_tnl_vtep_hnode *search_vtep_node = NULL;
	struct nbl_flow_tnl_vtep_hnode new_vtep_node;
	struct nbl_flow_tnl_vtep_node zero_vtep_node;
	int ret = 0;
	struct nbl_common_info *common = mgt->res_mgt->common;
	enum nbl_draco_ped_type ped_type = NBL_DRACO_PED_TNL_VTEP_TYPE;
	void *ped_tbl;
	bool write_vtep = false;
	bool write_tnl = false;
	u32 idx = 0, ref_cnt = 0;

	memset(&new_prof_node, 0, sizeof(new_prof_node));
	memset(&new_vtep_node, 0, sizeof(new_vtep_node));
	memset(&zero_vtep_node, 0, sizeof(zero_vtep_node));

	mutex_lock(&mgt->ped_lock[ped_type]);
	ped_tbl = mgt->pedit_res[ped_type].pedit_tbl;
	search_vtep_node = nbl_common_get_hash_node(ped_tbl, vtep_node);
	if (search_vtep_node) {
		search_vtep_node->ref_cnt++;
		idx = search_vtep_node->vtep_id;
		ref_cnt = search_vtep_node->ref_cnt;
	} else {
		write_vtep = true;
		ret = nbl_devshr_alloc_idx(NBL_DEVSHR_INDEX_ENCAP_VTEP, common->pdev, &idx);
		if (ret) {
			mutex_unlock(&mgt->ped_lock[ped_type]);
			nbl_err(common, NBL_DEBUG_FLOW, "alloc encap vtep idx failed, ret:%d", ret);
			return ret;
		}
		if (idx == 0) {
			ret = nbl_devshr_alloc_idx(NBL_DEVSHR_INDEX_ENCAP_VTEP, common->pdev, &idx);
			if (ret) {
				mutex_unlock(&mgt->ped_lock[ped_type]);
				nbl_err(common, NBL_DEBUG_FLOW, "alloc encap vtep idx failed, ret:%d",
					ret);
				return ret;
			}
		}
		new_vtep_node.ref_cnt = 1;
		new_vtep_node.vtep_id = (u8)idx;
		memcpy(&new_vtep_node.vtep_key, vtep_node, sizeof(*vtep_node));

		ret = nbl_common_alloc_hash_node(ped_tbl, vtep_node, &new_vtep_node,
						 (void **)&search_vtep_node);
		if (ret) {
			nbl_devshr_free_idx(NBL_DEVSHR_INDEX_ENCAP_VTEP, common->pdev, idx);
			mutex_unlock(&mgt->ped_lock[ped_type]);
			nbl_err(common, NBL_DEBUG_FLOW, "alloc encap vtep hash node failed, ret:%d",
				ret);

			return ret;
		}
		ref_cnt = 1;
	}
	action->ped_info.ped_info[ped_type].data = search_vtep_node;
	mutex_unlock(&mgt->ped_lock[ped_type]);

	nbl_debug(common, NBL_DEBUG_FLOW, "tnl encap vtep set to hw:%u, vtep idx:%u, ref_cnt:%u",
		  write_vtep, idx, ref_cnt);

	ped_type = NBL_DRACO_PED_TNL_TYPE;

	mutex_lock(&mgt->ped_lock[ped_type]);
	prof_node->loc_vtep_id = idx;
	ped_tbl = mgt->pedit_res[ped_type].pedit_tbl;
	search_prof_node = nbl_common_get_hash_node(ped_tbl, prof_node);
	if (search_prof_node) {
		search_prof_node->ref_cnt++;
		idx = search_prof_node->tnl_idx;
		ref_cnt = search_prof_node->ref_cnt;
	} else {
		write_tnl = true;
		new_prof_node.ref_cnt = 1;
		idx = 0;
		memcpy(&new_prof_node.prof_key, prof_node, sizeof(*prof_node));

		ret = nbl_devshr_alloc_idx(NBL_DEVSHR_INDEX_ENCAP_TNL, common->pdev, &idx);
		if (ret) {
			mutex_unlock(&mgt->ped_lock[ped_type]);
			nbl_err(common, NBL_DEBUG_FLOW, "alloc encap idx failed, ret:%d", ret);
			goto alloc_encap_tnl_idx_failed;
		}

		new_prof_node.tnl_idx = idx;
		ret = nbl_common_alloc_hash_node(ped_tbl, prof_node, &new_prof_node,
						 (void **)&search_prof_node);
		if (ret) {
			mutex_unlock(&mgt->ped_lock[ped_type]);
			nbl_err(common, NBL_DEBUG_FLOW, "alloc encap tnl hash node failed, ret:%d",
				ret);

			goto alloc_encap_tnl_hash_node_failed;
		}
		ref_cnt = 1;
	}
	action->ped_info.ped_info[ped_type].data = search_prof_node;
	mutex_unlock(&mgt->ped_lock[ped_type]);

	*tnl_idx = (u16)idx;
	nbl_debug(common, NBL_DEBUG_FLOW,
		  "tnl encap prof set to hw:%u, encap tnl idx:%u, ref_cnt:%u, ret:%d",
		  write_tnl, idx, ref_cnt, ret);

	if (write_vtep)
		ret = nbl_draco_cmdq_write_ped_table(mgt, (u8 *)vtep_node, prof_node->loc_vtep_id,
						     NBL_DRACO_PED_TNL_VTEP_TYPE);
	if (ret) {
		nbl_err(common, NBL_DEBUG_FLOW, "cmdq write ped tnl vtep failed, ret:%d", ret);
		nbl_draco_free_encap_vtep(mgt, vtep_node);
		nbl_draco_free_encap_tnl(mgt, prof_node);
		return ret;
	}

	if (write_tnl)
		ret = nbl_draco_cmdq_write_ped_table(mgt, (u8 *)prof_node, idx,
						     NBL_DRACO_PED_TNL_TYPE);
	if (ret) {
		nbl_err(common, NBL_DEBUG_FLOW, "cmdq write ped tnl prof failed, ret:%d", ret);
		nbl_draco_cmdq_write_ped_table(mgt, (u8 *)(&zero_vtep_node), prof_node->loc_vtep_id,
					       NBL_DRACO_PED_TNL_VTEP_TYPE);
		nbl_draco_free_encap_vtep(mgt, vtep_node);
		nbl_draco_free_encap_tnl(mgt, prof_node);
		return ret;
	}

	return 0;

alloc_encap_tnl_hash_node_failed:
	nbl_devshr_free_idx(NBL_DEVSHR_INDEX_ENCAP_TNL, common->pdev, idx);
alloc_encap_tnl_idx_failed:
	nbl_draco_free_encap_vtep(mgt, vtep_node);

	return ret;
}

static int nbl_draco_flow_encap_tnl_action_2hw(struct nbl_tc_flow_mgt *mgt, u32 *key,
					       struct nbl_rule_action *action,
					       union nbl_action_bits_ext *act_bits,
					       s16 *offsets)
{
	int ret = 0;
	u16 tnl_idx;
	u16 data_len = NBL_DRACO_ACTION_LEN_TNL;
	struct nbl_tnl_encap_data tnl_data;
	struct nbl_draco_flow_mgt *draco_mgt = mgt->priv_flow_mgt;
	struct nbl_flow_tnl_prof_node *prof_node =
			NBL_DRACO_GET_PROF_NODE_DATA(action->draco_encap_buf);
	struct nbl_flow_tnl_vtep_node *vtep_node =
			NBL_DRACO_GET_VTEP_NODE_DATA(action->draco_encap_buf);

	memset(&tnl_data, 0, sizeof(tnl_data));

	act_bits->extab.TNL_OP = 1;
	if (*offsets < data_len) {
		nbl_err(mgt->res_mgt->common, NBL_DEBUG_FLOW, "ad is overlimit in tnl_encap\n");
		return -1;
	}

	ret = nbl_draco_add_vtep_add_encap(draco_mgt, vtep_node, prof_node, action,
					   &tnl_idx, false);
	if (ret)
		return ret;

	action->ped_info.ped_info[NBL_DRACO_PED_TNL_VTEP_TYPE].ped_valid = 1;
	action->ped_info.ped_info[NBL_DRACO_PED_TNL_VTEP_TYPE].ped_idx = prof_node->loc_vtep_id;

	action->ped_info.ped_info[NBL_DRACO_PED_TNL_TYPE].ped_valid = 1;
	action->ped_info.ped_info[NBL_DRACO_PED_TNL_TYPE].ped_idx = tnl_idx;

	/* fill the tnl data */
	if (NBL_TNL_NOT_UDP_HDR(prof_node->tnl_type))
		tnl_data.udp_enc = 0;
	else
		tnl_data.udp_enc = 1;

	/* hw-tnl only need 3 bytes for vni */
	memcpy(tnl_data.vni, &action->vni, sizeof(tnl_data.vni));
	tnl_data.encap_id = tnl_idx;
	if (prof_node->ov_info || prof_node->iv_info)
		tnl_data.untag_enc = 1;

	/* action data set 32 bits at most, start set the tnl ad */
	*offsets -= NBL_BITS_IN_U16;
	nbl_draco_flow_set_action_data(key, tnl_data.u16_encap_data, NBL_BITS_IN_U16, *offsets);
	*offsets -= NBL_BITS_IN_U24;
	nbl_draco_flow_set_action_data(key, *(u32 *)tnl_data.vni, NBL_BITS_IN_U24, *offsets);

	nbl_debug(mgt->res_mgt->common, NBL_DEBUG_FLOW, "tnl encap 2hw finish, tnl_data: encap_data:0x%x, vni:0x%x-0x%x-0x%x, act_bits:0x%x, offsets:%d",
		  tnl_data.u16_encap_data, tnl_data.vni[0], tnl_data.vni[1], tnl_data.vni[2],
		  act_bits->data, *offsets);

	return 0;
}

/**
 * the action flag should follow the order like this(from up to down)
 * vlan_op
 * set_tos set_ttl
 * set_sp set_dp set_sip set_dip set_smac set_dmac
 * decap/encap
 */
static struct nbl_draco_flow_action_2hw draco_acts_2hw[] = {
	{ NBL_FLOW_ACTION_DROP, nbl_draco_flow_drop_2hw },
	{ NBL_FLOW_ACTION_PORT_ID, nbl_draco_flow_port_id_action_2hw },
	{ NBL_FLOW_ACTION_MCC, nbl_draco_flow_mcc_action_2hw },
	{ NBL_FLOW_ACTION_COUNTER, nbl_draco_udf_data_2hw },
	{ NBL_FLOW_ACTION_POP_INNER_VLAN, nbl_draco_flow_vlan_action_2hw },
	{ NBL_FLOW_ACTION_POP_OUTER_VLAN, nbl_draco_flow_vlan_action_2hw },
	{ NBL_FLOW_ACTION_PUSH_INNER_VLAN, nbl_draco_flow_vlan_action_2hw },
	{ NBL_FLOW_ACTION_PUSH_OUTER_VLAN, nbl_draco_flow_vlan_action_2hw },
	{ NBL_FLOW_ACTION_REPLACE_OUTER_VLAN, nbl_draco_flow_vlan_action_2hw },
	{ NBL_FLOW_ACTION_REPLACE_INNER_VLAN, nbl_draco_flow_vlan_action_2hw },
	{ NBL_FLOW_ACTION_REPLACE_SINGLE_INNER_VLAN, nbl_draco_flow_vlan_action_2hw },
	{ NBL_FLOW_ACTION_SET_SRC_PORT, nbl_draco_flow_set_sp_action_2hw },
	{ NBL_FLOW_ACTION_SET_DST_PORT, nbl_draco_flow_set_dp_action_2hw },
	{ NBL_FLOW_ACTION_SET_IPV4_SRC_IP, nbl_draco_flow_set_sip4_action_2hw },
	{ NBL_FLOW_ACTION_SET_IPV4_DST_IP, nbl_draco_flow_set_dip4_action_2hw },
	{ NBL_FLOW_ACTION_SET_IPV6_SRC_IP, nbl_draco_flow_set_sip6_action_2hw },
	{ NBL_FLOW_ACTION_SET_IPV6_DST_IP, nbl_draco_flow_set_dip6_action_2hw },
	{ NBL_FLOW_ACTION_SET_SRC_MAC, nbl_draco_flow_set_smac_action_2hw },
	{ NBL_FLOW_ACTION_SET_DST_MAC, nbl_draco_flow_set_dmac_action_2hw },
	{ NBL_FLOW_ACTION_TUNNEL_DECAP, nbl_draco_flow_decap_tnl_action_2hw },
	{ NBL_FLOW_ACTION_TUNNEL_ENCAP, nbl_draco_flow_encap_tnl_action_2hw },
};

static void nbl_draco_flow_set_pp0_index(struct nbl_profile_offload_msg *offload_msg, u32 *key,
					 union nbl_action_bits_ext *act_bits, u16 *offsets)
{
	u16 data_len = NBL_DRACO_UDF_ID_SET_PP0_IDX_LEN;

	*offsets -= data_len;
	act_bits->extab.SET_UDF = NBL_DRACO_UDF_ID_SET_PP0_IDX;
	nbl_draco_flow_set_action_data(key, offload_msg->act_assoc_tbl_id,
				       data_len, *offsets);
}

static int nbl_draco_flow_assign_action(struct nbl_tc_flow_mgt *tc_flow_mgt,
					struct nbl_profile_offload_msg *offload_msg,
					struct nbl_rule_action *action,
					u32 *key)
{
	int ret = 0;
	struct nbl_profile_msg *profile = &tc_flow_mgt->profile_msg[offload_msg->profile_id];
	union nbl_action_bits_ext act_bits;
	u32 act_num = ARRAY_SIZE(draco_acts_2hw);
	s16 total_offset = 0;
	s16 act_length = 0;
	u32 idx;

	memset(&act_bits, 0, sizeof(act_bits));

	/* assign action data for key, and update action bits */
	total_offset = NBL_DRACO_FLOW_MAX_LEN - profile->key_len - NBL_DRACO_KT_AB_EXT;

	if (offload_msg->last_stage) {
		for (idx = 0; idx < act_num; idx++) {
			if (!(action->flag & draco_acts_2hw[idx].draco_action_type))
				continue;

			if (!draco_acts_2hw[idx].act_2hw)
				continue;

			ret = draco_acts_2hw[idx].act_2hw(tc_flow_mgt, key, action,
							  &act_bits, &total_offset);
			if (ret)
				return ret;
		}
	} else {
		/* the associative action: SET_UDF */
		nbl_draco_flow_set_pp0_index(offload_msg, key, &act_bits, &total_offset);
	}

	/* check action length */
	act_length = NBL_DRACO_FLOW_MAX_LEN - total_offset -
		(profile->key_full ? NBL_DRACO_FULL_KEY : NBL_DRACO_HALF_KEY);
	if (act_length > NBL_DRACO_FULL_AT) {
		nbl_err(tc_flow_mgt->res_mgt->common, NBL_DEBUG_FLOW,
			"flow act length %u max then %u. total_offset:%u, key_full:%u\n",
			act_length, NBL_DRACO_FULL_AT, total_offset, profile->key_full);
		return -EINVAL;
	}

	if (act_length > NBL_DRACO_HALF_AT)
		offload_msg->at_type = NBL_DRACO_AT_TYPE_2;
	else if (act_length > 0)
		offload_msg->at_type = NBL_DRACO_AT_TYPE_1;
	else
		offload_msg->at_type = NBL_DRACO_AT_TYPE_0;

	/* assign action bits for key */
	total_offset = NBL_DRACO_FLOW_MAX_LEN - profile->key_len - NBL_DRACO_KT_AB_EXT;
	nbl_draco_flow_set_action_data(key, act_bits.data, NBL_DRACO_KT_AB_EXT, total_offset);

	return 0;
}

static void nbl_draco_get_action_info(struct nbl_rule_action *action,
				      struct nbl_draco_flow_node *node)
{
	node->ped_info = action->ped_info;
}

static inline u16 nbl_draco_get_kt_avail(struct nbl_draco_kt_node *kt_node,
					 struct nbl_draco_kt_idx_info *kt_info)
{
	u16 kt_num = 0;

	if (!kt_node || !kt_info)
		return 0;

	if (kt_info->kt_type == NBL_DRACO_KT_FULL_MODE) {
		kt_num = kt_node->avail_kt_num;
	} else {
		if (kt_info->at_type == NBL_DRACO_AT_TYPE_0)
			kt_num = kt_node->avail_kt_num;
		else if (kt_info->at_type == NBL_DRACO_AT_TYPE_1)
			kt_num = kt_node->avail_half_at1_num;
		else
			kt_num = kt_node->avail_half_at2_num;
	}

	return kt_num;
}

/* only for half KT cases */
static inline u32 nbl_draco_flow_kt_get_suitable(struct nbl_common_info *common,
						 struct nbl_draco_kt_node *kt_node,
						 struct nbl_draco_kt_idx_info *kt_info,
						 u32 *kt_index)
{
	int ret = 0;
	u32 kt_idx = NBL_INVALID_U32;

	switch (kt_info->at_type) {
	case NBL_DRACO_AT_TYPE_0:
		ret = nbl_bitmap_mng_alloc_id(&kt_node->kt_bmp_mng, &kt_idx);
		if (ret)
			goto alloc_error;
		nbl_bitmap_mng_set_id(&kt_node->kt_bmp_mng_at1, kt_idx);
		nbl_bitmap_mng_set_id(&kt_node->kt_bmp_mng_at2, kt_idx);
		break;
	case NBL_DRACO_AT_TYPE_1:
		ret = nbl_bitmap_mng_alloc_id(&kt_node->kt_bmp_mng_at1, &kt_idx);
		if (ret)
			goto alloc_error;
		nbl_bitmap_mng_set_id(&kt_node->kt_bmp_mng, kt_idx);
		nbl_bitmap_mng_set_id(&kt_node->kt_bmp_mng_at2, kt_idx);
		if (NBL_DRACO_KT_IS_ENTRY_HEAD(kt_idx))
			nbl_bitmap_mng_set_id(&kt_node->kt_bmp_mng_at2, kt_idx + 1);
		else
			nbl_bitmap_mng_set_id(&kt_node->kt_bmp_mng_at2, kt_idx - 1);
		break;
	case NBL_DRACO_AT_TYPE_2:
		ret = nbl_bitmap_mng_alloc_id(&kt_node->kt_bmp_mng_at2, &kt_idx);
		if (ret)
			goto alloc_error;
		nbl_bitmap_mng_set_id(&kt_node->kt_bmp_mng, kt_idx);
		nbl_bitmap_mng_set_id(&kt_node->kt_bmp_mng_at1, kt_idx);
		if (NBL_DRACO_KT_IS_ENTRY_HEAD(kt_idx)) {
			nbl_bitmap_mng_set_id(&kt_node->kt_bmp_mng_at1, kt_idx + 1);
			nbl_bitmap_mng_set_id(&kt_node->kt_bmp_mng_at2, kt_idx + 1);
		} else {
			nbl_bitmap_mng_set_id(&kt_node->kt_bmp_mng_at1, kt_idx - 1);
			nbl_bitmap_mng_set_id(&kt_node->kt_bmp_mng_at2, kt_idx - 1);
		}
		break;
	default:
		nbl_err(common, NBL_DEBUG_FLOW, "invalid at type, TYPE %d", kt_info->at_type);
	}

	*kt_index = kt_idx;

alloc_error:
	if (ret)
		nbl_err(common, NBL_DEBUG_FLOW, "kt allocation should not fail in at_%u, ret %d",
			kt_info->at_type, ret);

	return ret;
}

static int nbl_draco_flow_alloc_kt(struct nbl_draco_kt_node *kt_node,
				   struct nbl_draco_kt_idx_info *kt_info,
				   struct nbl_common_info *common,
				   u32 *kt_index)
{
	int ret = 0;
	u32 kt_idx = 0;
	u32 aside_kt_idx = 0;
	u8 aside_at_type = 0;
	u8 aside_kt_use = 0;

	if (!kt_node || !kt_info) {
		nbl_err(common, NBL_DEBUG_FLOW, "kt_node mgt is null");
		return -EINVAL;
	}

	if (kt_info->kt_type == NBL_DRACO_KT_FULL_MODE) {
		ret = nbl_bitmap_mng_alloc_id(&kt_node->kt_bmp_mng, &kt_idx);
		if (ret)
			goto alloc_error;
		kt_node->kt_idx_info[kt_idx] = *kt_info;
		kt_node->kt_idx_info[kt_idx].kt_in_use = 1;
		kt_node->avail_kt_num--;
		kt_idx = NBL_DRACO_GET_FULL_KT_IDX(kt_node->kt_block_id, kt_idx);
		kt_info->kt_block_id = kt_node->kt_block_id;
	} else {
		ret = nbl_draco_flow_kt_get_suitable(common, kt_node, kt_info, &kt_idx);
		if (ret)
			goto alloc_error;

		if (NBL_DRACO_KT_IS_ENTRY_HEAD(kt_idx))
			aside_kt_idx = kt_idx + 1;
		else
			aside_kt_idx = kt_idx - 1;
		kt_node->kt_idx_info[kt_idx] = *kt_info;
		kt_node->kt_idx_info[kt_idx].kt_in_use = 1;
		kt_node->kt_idx_info[kt_idx].at_type = kt_info->at_type;

		/* avail_kt_num - 1 at least */
		--kt_node->avail_kt_num;
		/* there are 2 case need minus avail_half_at2_num
		 * 1. every 2 kt without at
		 * 2. kt with 1 at, and the aside kt is not in use
		 */
		aside_kt_use = kt_node->kt_idx_info[aside_kt_idx].kt_in_use;
		aside_at_type = kt_node->kt_idx_info[aside_kt_idx].at_type;
		if (kt_info->at_type == NBL_DRACO_AT_TYPE_0) {
			/* check aside at-info to decide how to deal with at_num */
			if (aside_kt_use) {
				/* aside */
				if (aside_at_type == NBL_DRACO_AT_TYPE_0)
					--kt_node->avail_half_at2_num;
				if (aside_at_type < NBL_DRACO_AT_TYPE_2)
					--kt_node->avail_half_at1_num;
			} else {
				--kt_node->avail_half_at1_num;
			}
		} else if (kt_info->at_type == NBL_DRACO_AT_TYPE_1) {
			if (!aside_kt_use)
				--kt_node->avail_half_at2_num;
			else
				WARN_ON(aside_at_type >= NBL_DRACO_AT_TYPE_2);
			--kt_node->avail_half_at1_num;
		} else {
			--kt_node->avail_half_at2_num;
			--kt_node->avail_half_at1_num;
			if (!aside_kt_use && NBL_DRACO_VAILD_BLOCK_IDX(kt_node, aside_kt_idx))
				--kt_node->avail_half_at1_num;
			else
				WARN_ON(aside_at_type != NBL_DRACO_AT_TYPE_0);
		}

		kt_idx = NBL_DRACO_GET_HALF_KT_IDX(kt_node->kt_block_id, kt_idx);
		kt_info->kt_block_id = kt_node->kt_block_id;
	}

	*kt_index = kt_idx;

alloc_error:
	/* kt alloc should never fail in this case */
	if (ret)
		nbl_err(common, NBL_DEBUG_FLOW, "kt_node mgt is in a mess, ret %d, kt_idx 0x%x",
			ret, kt_idx);

	return ret;
}

static struct nbl_draco_kt_node *
nbl_draro_flow_get_cur_kt_node(struct nbl_draco_kt_mgt *kt_mgt,
			       struct nbl_draco_kt_idx_info *kt_info)
{
	struct nbl_draco_kt_node *kt_node = NULL;
	struct nbl_draco_kt_node *safe_node = NULL;
	struct list_head *kt_list = NULL;

	if (kt_info->kt_type == NBL_DRACO_KT_FULL_MODE)
		kt_list = &kt_mgt->kt_full_list;
	else
		kt_list = &kt_mgt->kt_half_list;

	/* list is empty now, return and alloc one from kt_pool(hw) */
	if (!kt_list)
		return NULL;

	list_for_each_entry_safe(kt_node, safe_node, kt_list, kt_node) {
		/* one block only store one profile */
		if (!kt_node)
			continue;
		if (kt_node->kt_idx_info[0].kt_profile_id != kt_info->kt_profile_id)
			continue;
		if (nbl_draco_get_kt_avail(kt_node, kt_info))
			return kt_node;
	}

	return NULL;
}

static int nbl_draco_flow_scan_kt_idx(struct nbl_common_info *common,
				      struct nbl_draco_kt_mgt *kt_mgt,
				      struct nbl_draco_kt_idx_info *kt_info,
				      u32 *kt_index)
{
	int ret = -ENOKEY;
	struct nbl_draco_kt_node *kt_node = NULL;

	kt_node = nbl_draro_flow_get_cur_kt_node(kt_mgt, kt_info);
	if (kt_node) {
		/* update the cur_node */
		kt_mgt->cur_node[kt_info->kt_profile_id] = kt_node;
		/* now we can alloc kt idx */
		ret = nbl_draco_flow_alloc_kt(kt_node, kt_info, common, kt_index);
	}

	return ret;
}

static inline int nbl_draco_kt_block_allock_check(struct nbl_resource_mgt *res_mgt,
						  struct nbl_draco_kt_mgt *kt_mgt,
						  struct nbl_draco_kt_idx_info *kt_info)
{
	u8 kt_alloced_cnt = kt_mgt->kt_block_alloc_stat[NBL_DRACO_MAX_PROFILE_NUM];

	/* for future use: check every profile limit */
	if (kt_alloced_cnt >= NBL_DRACO_KT_MAX_BLOCK) {
		nbl_err(res_mgt->common, NBL_DEBUG_FLOW, "kt block exceed max:%u", kt_alloced_cnt);
		return -ERANGE;
	}

	return 0;
}

static inline int nbl_draco_flow_init_kt_block(struct nbl_resource_mgt *res_mgt,
					       struct nbl_draco_flow_mgt *draco_mgt,
					       struct nbl_draco_kt_node *kt_node,
					       struct nbl_draco_kt_idx_info *kt_info)
{
	int ret = 0;
	bool skip_zero = 0;

	/* block-0 need skip 0 */
	if (!kt_node->kt_block_id)
		skip_zero = 1;

	if (kt_info->kt_type == NBL_DRACO_KT_FULL_MODE) {
		ret = nbl_bitmap_mng_init(&kt_node->kt_bmp_mng,
					  NBL_DRACO_FULL_KT_PER_BLOCK_CNT, false, skip_zero);
		if (ret) {
			nbl_err(res_mgt->common, NBL_DEBUG_FLOW,
				"alloc kt bmp failed, ret %d", ret);
			return ret;
		}

		kt_node->avail_kt_num = NBL_DRACO_FULL_KT_PER_BLOCK_CNT;
		if (skip_zero)
			kt_node->avail_kt_num--;
	} else {
		ret = nbl_bitmap_mng_init(&kt_node->kt_bmp_mng,
					  NBL_DRACO_HALF_KT_PER_BLOCK_CNT, false, skip_zero);
		ret |= nbl_bitmap_mng_init(&kt_node->kt_bmp_mng_at1,
					  NBL_DRACO_HALF_KT_PER_BLOCK_CNT, false, skip_zero);
		ret |= nbl_bitmap_mng_init(&kt_node->kt_bmp_mng_at2,
					  NBL_DRACO_HALF_KT_PER_BLOCK_CNT, false, skip_zero);
		if (ret) {
			nbl_err(res_mgt->common, NBL_DEBUG_FLOW,
				"alloc kt bmp failed, ret %d", ret);
			return ret;
		}

		kt_node->avail_kt_num = NBL_DRACO_HALF_KT_PER_BLOCK_CNT;
		kt_node->avail_half_at1_num = NBL_DRACO_HALF_KT_PER_BLOCK_CNT;
		kt_node->avail_half_at2_num = NBL_DRACO_FULL_KT_PER_BLOCK_CNT;
		if (skip_zero) {
			kt_node->avail_kt_num--;
			kt_node->avail_half_at1_num--;
		}
	}

	draco_mgt->kt_mgt.cur_node[kt_info->kt_profile_id] = kt_node;
	draco_mgt->kt_mgt.kt_block_alloc_stat[kt_info->kt_profile_id]++;
	kt_node->kt_idx_info[0].kt_profile_id = kt_info->kt_profile_id;

	/* update the block cnt */
	mutex_lock(&draco_mgt->kt_mgt.kt_lock);
	draco_mgt->kt_mgt.kt_block_alloc_stat[NBL_DRACO_MAX_PROFILE_NUM]++;
	mutex_unlock(&draco_mgt->kt_mgt.kt_lock);

	return ret;
}

static inline void nbl_draco_flow_uninit_kt_block(struct nbl_draco_flow_mgt *draco_mgt,
						  struct nbl_draco_kt_node *kt_node,
						  struct nbl_draco_kt_idx_info *kt_info)
{
	if (kt_info->kt_type == NBL_DRACO_KT_FULL_MODE) {
		nbl_bitmap_mng_release(&kt_node->kt_bmp_mng);
	} else {
		nbl_bitmap_mng_release(&kt_node->kt_bmp_mng);
		nbl_bitmap_mng_release(&kt_node->kt_bmp_mng_at1);
		nbl_bitmap_mng_release(&kt_node->kt_bmp_mng_at2);
	}

	draco_mgt->kt_mgt.kt_block_alloc_stat[kt_info->kt_profile_id]--;

	/* update the block cnt */
	mutex_lock(&draco_mgt->kt_mgt.kt_lock);
	draco_mgt->kt_mgt.kt_block_alloc_stat[NBL_DRACO_MAX_PROFILE_NUM]--;
	mutex_unlock(&draco_mgt->kt_mgt.kt_lock);
}

static int nbl_draco_flow_alloc_kt_block(struct nbl_common_info *common,
					 struct nbl_draco_flow_mgt *draco_mgt,
					 struct nbl_draco_kt_idx_info *kt_info)
{
	struct nbl_draco_kt_node *kt_new_node;
	struct nbl_draco_kt_node *kt_node;
	struct nbl_resource_mgt *res_mgt = draco_mgt->res_mgt;
	u16 block_id = 0;
	int ret = 0;

	if (nbl_draco_kt_block_allock_check(res_mgt, &draco_mgt->kt_mgt, kt_info))
		return -ERANGE;

	kt_new_node = devm_kzalloc(common->dev, sizeof(*kt_new_node), GFP_KERNEL);
	if (!kt_new_node)
		return -ENOMEM;

	ret = nbl_draco_flow_cmd_alloc_kt_block(res_mgt, &block_id);
	if (ret)
		return ret;

	kt_new_node->kt_block_id = (u8)block_id;

	ret = nbl_common_alloc_hash_node(draco_mgt->kt_mgt.kt_hash.flow_tab_hash,
					 (void *)(&kt_new_node->kt_block_id),
					 (void *)(kt_new_node),
					 (void **)&kt_node);
	if (ret) {
		devm_kfree(common->dev, kt_new_node);
		nbl_draco_flow_cmd_free_kt_block(res_mgt, block_id, 0);
		nbl_err(common, NBL_DEBUG_FLOW, "nbl kt node add hash failed, ret %d", ret);
		return ret;
	}

	/* init kt_node */
	kt_node->kt_block_id = (u8)block_id;
	ret = nbl_draco_flow_init_kt_block(res_mgt, draco_mgt, kt_node, kt_info);
	if (ret) {
		devm_kfree(common->dev, kt_new_node);
		nbl_draco_flow_cmd_free_kt_block(res_mgt, block_id, 0);
		nbl_common_free_hash_node(draco_mgt->kt_mgt.kt_hash.flow_tab_hash, &block_id);
		nbl_err(common, NBL_DEBUG_FLOW, "nbl init kt block failed, ret %d", ret);
		return ret;
	}

	/* add kt node to list */
	if (kt_info->kt_type == NBL_DRACO_KT_FULL_MODE)
		list_add(&kt_node->kt_node, &draco_mgt->kt_mgt.kt_full_list);
	else
		list_add(&kt_node->kt_node, &draco_mgt->kt_mgt.kt_half_list);

	devm_kfree(common->dev, kt_new_node);

	return ret;
}

static int nbl_draco_flow_get_kt_idx(struct nbl_tc_flow_mgt *tc_flow_mgt,
				     struct nbl_draco_kt_idx_info *kt_info,
				     uint32_t *kt_index)
{
	int ret = -ENOKEY;
	struct nbl_draco_flow_mgt *draco_mgt = tc_flow_mgt->priv_flow_mgt;
	struct nbl_draco_kt_mgt *kt_mgt = &draco_mgt->kt_mgt;
	/* get current profile kt_block */
	struct nbl_draco_kt_node *block_node = NULL;
	struct nbl_common_info *common = tc_flow_mgt->res_mgt->common;
	u16 avail_kt_num = 0;
	struct mutex *kt_lock = NULL;

	if (kt_info->kt_type == NBL_DRACO_KT_FULL_MODE)
		kt_lock = &kt_mgt->full_kt_lock;
	else
		kt_lock = &kt_mgt->half_kt_lock;

	mutex_lock(kt_lock);
	block_node = kt_mgt->cur_node[kt_info->kt_profile_id];
	avail_kt_num = nbl_draco_get_kt_avail(block_node, kt_info);

	/* we can get kt-idx from cur_node */
	if (avail_kt_num) {
		ret = nbl_draco_flow_alloc_kt(block_node, kt_info, common, kt_index);
		goto get_kt_finish;
	} else {
		/* no available kt in current block, try get from kt_list */
		ret = nbl_draco_flow_scan_kt_idx(common, kt_mgt, kt_info, kt_index);

		/* no available kt in kt_list, try alloc a new block */
		if (ret)
			ret = nbl_draco_flow_alloc_kt_block(common, draco_mgt, kt_info);
		else
			goto get_kt_finish;

		/* alloc kt-block failed and scan kt-block failed, goto kt_finish */
		if (ret)
			goto get_kt_finish;

		block_node = kt_mgt->cur_node[kt_info->kt_profile_id];
		ret = nbl_draco_flow_alloc_kt(block_node, kt_info, common, kt_index);
	}

get_kt_finish:
	mutex_unlock(kt_lock);
	return ret;
}

static void nbl_draco_move_at_data(struct nbl_common_info *common, u8 *key,
				   u16 at_bytes, u32 kt_index)
{
	u16 cpy_src = NBL_DRACO_FULL_KT_AT - NBL_DRACO_HALF_KEY_BYTES;
	u16 cpy_dst = NBL_DRACO_AT2_LENGTH;

	if (kt_index % 2) {
		switch (at_bytes) {
		case NBL_DRACO_AT0_LENGTH:
			return;
		case NBL_DRACO_AT1_LENGTH:
		case NBL_DRACO_AT2_LENGTH:
			cpy_src -= at_bytes;
			cpy_dst -= at_bytes;
			break;
		default:
			nbl_err(common, NBL_DEBUG_FLOW, "unexpected at len at_bytes %d", at_bytes);
			return;
		}

		memcpy(key + cpy_dst, key + cpy_src, at_bytes);
		memset(key + cpy_src, 0, at_bytes);
	} else {
		switch (at_bytes) {
		case NBL_DRACO_AT0_LENGTH:
			return;
		case NBL_DRACO_AT1_LENGTH:
			cpy_src -= NBL_DRACO_AT_BYTES;
			memcpy(key, key + cpy_src, at_bytes);
			memset(key + cpy_src, 0, at_bytes);
			break;
		case NBL_DRACO_AT2_LENGTH:
			cpy_src -= NBL_DRACO_AT_BYTES;
			memcpy(key, key + cpy_src, NBL_DRACO_AT_BYTES);
			cpy_src -= NBL_DRACO_AT_BYTES;
			memmove(key + NBL_DRACO_AT_BYTES, key + cpy_src, NBL_DRACO_AT_BYTES);
			memset(key + NBL_DRACO_AT2_LENGTH, 0, NBL_DRACO_HALF_KEY_BYTES);
			break;
		default:
			nbl_err(common, NBL_DEBUG_FLOW, "unexpected at len at_bytes %d", at_bytes);
			return;
		}
	}
}

static inline int nbl_draco_flow_set_node_info(struct nbl_tc_flow_mgt *tc_flow_mgt,
					       struct nbl_profile_offload_msg *offload_msg,
					       struct nbl_draco_flow_node *node,
					       struct nbl_tc_flow_param *param)
{
	int ret = -EINVAL;
	u16 bind_car_id = INVALID_CAR_ID;
	u32 kt_index;
	struct nbl_draco_kt_idx_info *kt_info = &node->kt_info;
	struct nbl_draco_flow_mgt *draco_mgt = tc_flow_mgt->priv_flow_mgt;
	struct nbl_profile_msg *profile = &tc_flow_mgt->profile_msg[offload_msg->profile_id];
	u32 *key = (u32 *)&node->key;
	union nbl_flow_udfs udfs;

	memset(&udfs, 0, sizeof(udfs));

	node->graph_index = offload_msg->graph_index;
	node->profile_index = offload_msg->profile_id;
	node->profile_stage = offload_msg->profile_stage;
	node->assoc_tbl_id = offload_msg->act_assoc_tbl_id;

	/* key in node contains full KT with AT and ActionBits,
	 * key in node will use the full 496 bits for hash calculation
	 */
	ret = nbl_draco_flow_assign_action(tc_flow_mgt, offload_msg, &param->act, key);
	if (ret) {
		nbl_draco_get_action_info(&param->act, node);
		nbl_err(param->common, NBL_DEBUG_FLOW, "convert act to hw buf failed, ret %d", ret);
		return ret;
	}

	nbl_draco_get_action_info(&param->act, node);
	kt_info->kt_type = offload_msg->full_key;
	kt_info->at_type = offload_msg->at_type;
	kt_info->kt_profile_id = offload_msg->profile_id;
	ret = nbl_draco_flow_get_kt_idx(tc_flow_mgt, kt_info, &kt_index);
	nbl_debug(param->common, NBL_DEBUG_FLOW, "kt type: %d; at type: %d; profile_id: %d; block id: %d; kt index: 0x%x; ret %d",
		  kt_info->kt_type, kt_info->at_type, kt_info->kt_profile_id,
		  kt_info->kt_block_id, kt_index, ret);
	if (ret) {
		nbl_err(param->common, NBL_DEBUG_FLOW, "get kt idx failed, ret %d", ret);
		return ret;
	}

	udfs.info.flow_stat_id = kt_index;
	udfs.info.flow_stat_vld = 1;
	/* now we could update counter_id for kt_index can only get here */
	nbl_draco_flow_set_action_data((u32 *)&node->key, udfs.data[1],
				       NBL_BYTES_TO_BITS(sizeof(u32)),
				       (u16)param->act.counter_oft);
	offload_msg->kt_index = kt_index;
	node->kt_index = (u32)kt_index;

	if (offload_msg->last_stage) {
		param->act.counter_id = node->kt_index;

		if (param->act.flag & NBL_FLOW_ACTION_CAR)
			bind_car_id = param->act.car_id;

		ret = nbl_fc_add_stats_draco(tc_flow_mgt->res_mgt, false, param->key.cookie,
					     node->kt_index, bind_car_id);
		if (ret < 0) {
			nbl_draco_flow_put_kt_idx(draco_mgt, kt_info, kt_index);
			return ret;
		}
	}

	/* move action data, if necessary */
	if (!profile->key_full)
		nbl_draco_move_at_data(param->common, (u8 *)&node->key + NBL_DRACO_VLD_KAT_OFFSET,
				       NBL_DRACO_GET_AT_BYTES(offload_msg->at_type),
				       offload_msg->kt_index);

	return 0;
}

static int nbl_flow_search_key(struct nbl_resource_mgt *res_mgt, u8 *search_key, u8 kt_type)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_flow_param param;
	union nbl_fem_cmd_data_u req_param;
	union nbl_fem_resp_data_tbllookup_u resp_data;
	struct nbl_cmd_hdr hdr;
	struct nbl_cmd_content cmd;
	u16 pf_id = NBL_COMMON_TO_MGT_PF(common);
	u16 ht_index;
	u16 hash_bucket;
	u16 ht0_hash;
	u16 ht1_hash;
	u16 hash_table;
	u32 kt_idx;
	u16 tcam_table;
	u16 tcam_index;
	int ret = 0;

	memset(&req_param, 0, sizeof(req_param));
	memset(&resp_data, 0, sizeof(resp_data));
	memset(&hdr, 0, sizeof(hdr));
	memset(&cmd, 0, sizeof(cmd));
	memset(&param, 0, sizeof(param));

	param.template = 0;
	param.del_on_hit = 0;
	param.lkp_mode = NBL_FEM_CMD_PARAM_MODE_NORMAL;
	param.pf_id = pf_id;
	param.hmc = NBL_FEM_CMD_PARAM_HMC_ONC;
	param.key = search_key;
	if (kt_type == NBL_DRACO_KT_HALF_MODE)
		param.key_len = NBL_DRACO_HALF_KEY_BYTES;
	else if (kt_type == NBL_DRACO_KT_FULL_MODE)
		param.key_len = NBL_DRACO_FULL_KEY_BYTES;

	ret = cmd_cfg_ops[NBL_FEM_CMD_HEAD_OPCODE_TBLLOOKUP].cfg_req_param(&req_param, &param);
	if (ret)
		return ret;

	hdr.module = NBL_CMDQ_MODULE_FEM;
	hdr.table = NBL_CMDQ_FEM_TBL;
	hdr.opcode = NBL_CMDQ_FEM_OPCODE_TBLLKP;
	cmd.in_length = NBL_DRACO_CMD_TBLLKP_LEN;
	cmd.in_params = *(u64 *)&req_param;
	cmd.in_va = req_param.cmd_data + NBL_DRACO_CMDQ_PARAM_LEN;
	cmd.out_va = &resp_data;
	ret = nbl_tc_call_inst_cmdq(common->tc_inst_id, (void *)&hdr, (void *)&cmd);
	if (!ret) {
		if (resp_data.info.hit_pos == NBL_FEM_CMD_PARAM_HIT_POS_HT_KT) {
			hash_table = (resp_data.info.ht_addr >> 14);
			ht_index = resp_data.info.ht_addr & 0x3FFF;
			hash_bucket = resp_data.info.slot_id;
			ht0_hash = resp_data.info.hash0_idx;
			ht1_hash = resp_data.info.hash1_idx;
			kt_idx = resp_data.info.kt_idx;
			nbl_debug(common, NBL_DEBUG_FLOW,
				  "Lookup hit ht - kt_idx:%d, hash_table:%d, ht_index:%d, hash_bucket:%d, ht0_hash:0x%x, ht1_hash:0x%x",
				  kt_idx, hash_table, ht_index, hash_bucket, ht0_hash, ht1_hash);
		} else if (resp_data.info.hit_pos == NBL_FEM_CMD_PARAM_HIT_POS_OFT) {
			tcam_table = resp_data.info.ht_addr & 0x1;
			tcam_index = resp_data.info.ht_addr & 0xFE;
			kt_idx = resp_data.info.kt_idx;
			nbl_debug(common, NBL_DEBUG_FLOW,
				  "Lookup hit tcam - kt_idx:%d, tcam_table:%d, tcam_index:%d",
				  kt_idx, tcam_table, tcam_index);
		}
	} else {
		nbl_err(common, NBL_DEBUG_FLOW, "insert search kt/tcam failed, cmdq ret:%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

static int nbl_draco_flow_store_node_hw(struct nbl_draco_flow_mgt *draco_mgt,
					struct nbl_profile_offload_msg *offload_msg,
					struct nbl_draco_flow_node *node)
{
	struct nbl_resource_mgt *res_mgt = draco_mgt->res_mgt;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	union nbl_fem_cmd_data_u req_param;
	struct nbl_cmd_hdr hdr;
	struct nbl_cmd_content cmd;
	union nbl_fem_resp_data_tbladd_u *resp_data;
	struct nbl_flow_param param;
	struct nbl_profile_offload_msg *tcam_data_info;
	int ret = 0;

	memset(&req_param, 0, sizeof(req_param));
	memset(&hdr, 0, sizeof(hdr));
	memset(&cmd, 0, sizeof(cmd));
	memset(&param, 0, sizeof(param));

	param.kt_idx = node->kt_index;
	offload_msg->kt_index = node->kt_index;
	param.pf_id = NBL_COMMON_TO_MGT_PF(common);
	param.hmc = NBL_FEM_CMD_PARAM_HMC_ONC;
	param.alloc_oft = !offload_msg->avoid_tcam;
	param.kt_mode = offload_msg->at_type;
	param.key = (u8 *)&node->key.buf + NBL_DRACO_VLD_KAT_OFFSET;
	param.key_len = NBL_DRACO_FULL_KT_AT;
	ret = cmd_cfg_ops[NBL_FEM_CMD_HEAD_OPCODE_TBLADD].cfg_req_param(&req_param, &param);
	if (ret)
		return ret;

	hdr.module = NBL_CMDQ_MODULE_FEM;
	hdr.table = NBL_CMDQ_FEM_TBL;
	hdr.opcode = NBL_CMDQ_FEM_OPCODE_TBLADD;
	cmd.in_length = NBL_DRACO_CMD_TBLADD_LEN;
	cmd.in_params = *(u64 *)&req_param;
	cmd.in_va = req_param.cmd_data + NBL_DRACO_CMDQ_PARAM_LEN;

	ret = nbl_tc_call_inst_cmdq(res_mgt->common->tc_inst_id, (void *)&hdr, (void *)&cmd);
	resp_data = (union nbl_fem_resp_data_tbladd_u *)&cmd.out_params;

	/* check response */
	if (!ret) {
		if (resp_data->info.tbl_type == NBL_FEM_CMD_PARAM_TBL_TYPE_HT) {
			node->tcam_flag = false;
			node->hash_table_id = (resp_data->info.tbl_idx >> 14);
			node->ht_index = resp_data->info.tbl_idx & 0x3FFF;
			node->slot_id = resp_data->info.slot_id;
			node->ht0_hash = resp_data->info.hash_data0;
			node->ht1_hash = resp_data->info.hash_data1;
			nbl_debug(common, NBL_DEBUG_FLOW, "add kt success for kt_idx:0x%x, hash_table:%d, ht_index:0x%x, hash_bucket:%d, ht0_hash:0x%x, ht1_hash:0x%x\n",
				  param.kt_idx, node->hash_table_id, node->ht_index,
				  node->slot_id, node->ht0_hash, node->ht1_hash);
		} else if (resp_data->info.tbl_type == NBL_FEM_CMD_PARAM_TBL_TYPE_OFT) {
			if (offload_msg->avoid_tcam) {
				nbl_err(common, NBL_DEBUG_FLOW,
					"tried to avoid tcam but hw still use tcam");
				ret = -EIO;
				goto set_kt_fail;
			}

			node->tcam_flag = true;
			node->tcam_table_id = resp_data->info.tbl_idx & 0x1;
			node->tcam_index = resp_data->info.tbl_idx & 0xFE;
			node->ht0_hash = resp_data->info.hash_data0;
			node->ht1_hash = resp_data->info.hash_data1;
			nbl_debug(common, NBL_DEBUG_FLOW, "add kt success for kt_idx:0x%x, tcam_table:%d, tcam_index:%d, hash0:0x%x, hash1:0x%x\n",
				  param.kt_idx, node->tcam_table_id, node->tcam_index,
				  node->ht0_hash, node->ht1_hash);
			/* insert node in tcam data array */
			if (resp_data->info.tbl_idx >= NBL_DRACO_TCAM_SPEC) {
				nbl_err(common, NBL_DEBUG_FLOW, "tbl idx more than tcam spec");
				ret = -ERANGE;
			}
			offload_msg->avoid_tcam = true;
			tcam_data_info =
				&draco_mgt->tcam_data_info[node->tcam_index + node->tcam_table_id];
			memcpy(tcam_data_info, offload_msg, sizeof(*offload_msg));
		}
	} else {
		nbl_err(common, NBL_DEBUG_FLOW, "add kt failed kt_idx:0x%x,avoid_tcam:%u, ret:%d\n",
			param.kt_idx, offload_msg->avoid_tcam, ret);

		if (!offload_msg->avoid_tcam)
			return -EIO;

		ret = -EIO;
		goto set_kt_fail;
	}

	/* update stats */
	if (node->tcam_flag)
		draco_mgt->stats.pp_tcam_entry++;
	else if (offload_msg->profile_stage)
		draco_mgt->stats.used_pp1_entry++;
	else
		draco_mgt->stats.used_pp0_entry++;

	/* mark node as offloaded to hw */
	node->offloaded = 1;
	ret = nbl_flow_search_key(res_mgt, (u8 *)node->key.key_value, offload_msg->full_key);
	if (ret) {
		nbl_err(common, NBL_DEBUG_ACCEL, "insert key succ but search failed, ret:%d", ret);
		goto search_fail;
	}

	return 0;

search_fail:
set_kt_fail:
	return ret;
}

static int nbl_draco_flow_store_node(struct nbl_resource_mgt *res_mgt,
				     struct nbl_profile_offload_msg *offload_msg,
				     struct nbl_tc_flow_param *param,
				     struct nbl_tc_flow *tc_flow_ptr)
{
	int ret = 0;
	struct nbl_draco_flow_node *node = NULL;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_tc_flow_mgt *flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_draco_flow_mgt *draco_mgt = flow_mgt->priv_flow_mgt;
	struct nbl_draco_flow_tab_conf node_key;

	memset(&node_key, 0, sizeof(node_key));

	nbl_debug(common, NBL_DEBUG_FLOW, "flow store cookies 0x%llx", tc_flow_ptr->key.cookie);
	/* alloc the node & find profile message */
	ret = nbl_flow_tab_hash_add(res_mgt, param, tc_flow_ptr,
				    (void **)&node, offload_msg, &node_key);
	if (ret || !node) {
		nbl_info(common, NBL_DEBUG_FLOW,
			 "tc flow hw flow_tab hash-list storage fail, ret %d, to store flow node %p.\n",
			 ret, node);
		return ret;
	}

	if (node->ref_cnt > 1)
		return 0;

	ret = nbl_draco_flow_set_node_info(res_mgt->tc_flow_mgt, offload_msg, node, param);
	if (ret)
		goto failed_set_node;

	tc_flow_ptr->flow_stat_id = node->kt_index;
	tc_flow_ptr->act_flags = node->act_flags;

	ret = nbl_draco_flow_store_node_hw(draco_mgt, offload_msg, node);
	if (ret)
		goto failed_store_hw;

	/* save the origin flow key in tc_flow */
	memcpy(&node->key, &node_key, sizeof(node_key));

	return 0;

failed_store_hw:
	if (offload_msg->last_stage)
		nbl_fc_del_stats_draco(draco_mgt->res_mgt, false, tc_flow_ptr->key.cookie);

failed_set_node:
	nbl_err(common, NBL_DEBUG_FLOW, "failed_store_hw , last_stage:%d, kt_idx:%u, ret %d",
		offload_msg->last_stage, node->kt_index, ret);
	memcpy(&node->key, &node_key, sizeof(node_key));
	nbl_draco_flow_free_node(res_mgt, node);

	return ret;
}

static int nbl_draco_flow_remove_node(struct nbl_resource_mgt *res_mgt,
				      struct nbl_draco_flow_node *flow_node)
{
	struct nbl_draco_flow_node *node = NULL;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);

	u8 profile_id = flow_node->profile_index;
	int ret = 0;

	mutex_lock(&tc_flow_mgt->flow_lock);

	node = nbl_flow_tab_filter_lookup(res_mgt, &flow_node->key, profile_id);
	if (node) {
		if (node->ref_cnt >= NBL_FLOW_TAB_ONE_TIME)
			node->ref_cnt--;
		if (node->ref_cnt == 0)
			ret = nbl_draco_flow_free_node(res_mgt, node);
	}

	mutex_unlock(&tc_flow_mgt->flow_lock);

	return ret;
}

/**
 * @brief: storage flow tab:
 * 1.configure which key template we need to use
 * 2.storage key info
 * 3.storage action info
 * 4.offload to hw
 * 5.if tunnel outer flow tab exist,storage tunnel outer flowtab
 *
 * @param[in] tc_flow_mgt: tc flow hw info
 * @param[in] tc_flow_ptr: nbl_tc_flow pointer which
 *                      point to the key template
 * @param[in] param: key and actions info
 * @return int: 0-success other-fail.
 */
static int nbl_draco_flow_storage(struct nbl_resource_mgt *res_mgt,
				  struct nbl_tc_flow *tc_flow_ptr,
				  struct nbl_tc_flow_param *param)
{
	int ret = 0;
	int i = 0;
	u16 profile_index;
	u32 pp0_idx = 0;
	struct nbl_profile_offload_msg offload_msg[NBL_ASSOC_PROFILE_STAGE_NUM];
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_draco_flow_mgt *draco_flow_mgt = tc_flow_mgt->priv_flow_mgt;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_profile_msg *all_profile = tc_flow_mgt->profile_msg;
	struct nbl_profile_msg *profile = tc_flow_mgt->profile_msg;
	struct nbl_profile_assoc_graph *graph =
					&tc_flow_mgt->profile_graph[param->filter.graph_idx];
	u16 pf_id = NBL_COMMON_TO_MGT_PF(common);

	memset(offload_msg, 0, sizeof(offload_msg));
	param->act.next_stg_sel = NEXT_STG_SEL_EPRO;

	for (i = 0; i < NBL_ASSOC_PROFILE_STAGE_NUM; i++) {
		profile_index = graph->profile_id[i];
		if (i && profile_index == 0)
			break;
		profile = all_profile + profile_index;
		offload_msg[i].pp_or_acl = 0; /* mark as pp */
		offload_msg[i].graph_index = param->filter.graph_idx;
		offload_msg[i].profile_id = profile_index;
		offload_msg[i].profile_stage = i;
		offload_msg[i].full_key = profile->key_full;
		offload_msg[i].avoid_tcam = false;

		/* 2 levels at most */
		if (i > 1) {
			nbl_info(common, NBL_DEBUG_FLOW,
				 "tc flow hw tab storage failed, stage more than 2.\n");
			goto failed_flow_stage;
		}

		if ((i == NBL_ASSOC_PROFILE_STAGE_NUM - 1) || graph->profile_id[i + 1] == 0)
			offload_msg[i].last_stage = true;

		if (!offload_msg[i].last_stage) {
			ret = nbl_bitmap_mng_alloc_id(&draco_flow_mgt->assoc_table_mng, &pp0_idx);
			if (ret) {
				nbl_info(common, NBL_DEBUG_FLOW, "alloc assoc id failed, ret %d.\n",
					 ret);
				goto failed_alloc_assoc_tbl_id;
			}
			nbl_info(common, NBL_DEBUG_FLOW, "alloc assoc id, idx %d.\n", pp0_idx);
			offload_msg[i].act_assoc_tbl_id =
						(pp0_idx & NBL_DRACO_ASSOC_TBL_ID_MASK) |
						(pf_id << NBL_DRACO_ASSOC_PF_ID_SHIFT);
		} else {
			/* not last stage, i should be larger than 0 */
			if (i > 0)
				nbl_draco_assign_assoc_tbl_id(tc_flow_ptr, offload_msg, i);
		}

		ret = nbl_draco_flow_store_node(res_mgt, offload_msg + i, param, tc_flow_ptr);
		if (ret) {
			if (ret == -EEXIST && graph->profile_count == 2 && i == 0) {
				ret = 0;
			} else {
				nbl_info(common, NBL_DEBUG_FLOW, "tc flow hw tab storage failed, stage %d, ret %d.\n",
					 i, ret);
				goto failed_store_flow_tab;
			}
		}
	}

	nbl_debug(common, NBL_DEBUG_FLOW, "draco flow storage ret %d, cookie:0x%llx.\n",
		  ret, tc_flow_ptr->key.cookie);

	return ret;

failed_flow_stage:
failed_alloc_assoc_tbl_id:
failed_store_flow_tab:
	i--;
	for (; i >= 0; i--) {
		nbl_bitmap_mng_release_id(&draco_flow_mgt->assoc_table_mng,
					  offload_msg[i].act_assoc_tbl_id &
					  NBL_DRACO_ASSOC_TBL_ID_MASK);
		nbl_draco_flow_remove_node(res_mgt, tc_flow_ptr->profile_rule[i]);
		tc_flow_ptr->profile_rule[i] = NULL;
	}

	return ret;
}

static int nbl_tc_flow_add_tc_flow(void *priv, struct nbl_tc_flow_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	int ret = 0, i;
	struct nbl_tc_flow *tc_flow_ptr = NULL;

	if (!tc_flow_mgt) {
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow hw add tc_flow_mgt is null.\n");
		return -EINVAL;
	}

	if (!nbl_flow_is_available(tc_flow_mgt)) {
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow hw resource unavailable.\n");
		return -EINVAL;
	}

	if (param->in.type == NBL_TC_PORT_TYPE_VSI)
		param->act.flag |= NBL_FLOW_ACTION_EGRESS;
	else
		param->act.flag |= NBL_FLOW_ACTION_INGRESS;

	param->filter.input.port = param->in.id;
	param->filter.input.dir = (param->act.flag & NBL_FLOW_ACTION_EGRESS);

	tc_flow_ptr = nbl_tc_flow_insert_index(res_mgt, &param->key);
	if (!tc_flow_ptr) {
		nbl_err(common, NBL_DEBUG_FLOW,
			"tc flow hw index=%llx add failed!\n", param->key.cookie);
		ret = -EINVAL;
		goto flow_idx_err;
	}

	if (!nbl_flow_graph_lookup(tc_flow_mgt, &param->filter, false)) {
		nbl_info(common, NBL_DEBUG_FLOW, "tc flow can not find graph, key_flag:0x%llx.\n",
			 param->filter.key_flag);
		ret = -EINVAL;
		goto failed_lookup_graph;
	}

	param->act.flag |= NBL_FLOW_ACTION_COUNTER;
	tc_flow_ptr->key.cookie = param->key.cookie;

	if (param->filter.wildcard_flow)
		param->filter.key_flag |= NBL_FLOW_KEY_NEED_ACL_FLAG;

	if (param->filter.key_flag & NBL_FLOW_KEY_NEED_ACL_FLAG) {
		tc_flow_ptr->acl_flag = 1;
		goto flow_acl_storage;
	}

	ret = nbl_draco_flow_storage(res_mgt, tc_flow_ptr, param);
	if (ret)
		goto failed_storage_flow;

	tc_flow_ptr->act_flags = param->act.flag;
	if (param->act.flag & NBL_FLOW_ACTION_TUNNEL_ENCAP) {
		tc_flow_ptr->encap_key = kzalloc(sizeof(*tc_flow_ptr->encap_key), GFP_KERNEL);
		if (!tc_flow_ptr->encap_key) {
			ret = -ENOMEM;
			goto failed_alloc_encap_key;
		}
		memcpy(tc_flow_ptr->encap_key, &param->act.encap_key, sizeof(param->act.encap_key));
	}

	if (NBL_TC_PEDIT_GET_NODE_RES_VAL(param->act.tc_pedit_info.pedit_node))
		tc_flow_ptr->pedit_node = param->act.tc_pedit_info.pedit_node;

	atomic64_inc(&tc_flow_mgt->create_num);

	return 0;

failed_alloc_encap_key:
	for (i = 0; i < NBL_ASSOC_PROFILE_STAGE_NUM; i++) {
		if (tc_flow_ptr->profile_rule[i])
			nbl_draco_flow_remove_node(res_mgt,
						   (struct nbl_draco_flow_node *)
						   tc_flow_ptr->profile_rule[i]);
	}

failed_storage_flow:
failed_lookup_graph:
	nbl_tc_flow_delete_index(res_mgt, &param->key);
flow_idx_err:
	nbl_err(common, NBL_DEBUG_FLOW, "tc flow add failed, ret: %d", ret);
	return ret;

flow_acl_storage:
	/* draco todo: acl storage */
	nbl_info(common, NBL_DEBUG_FLOW, "TODO: acl support later.");

	return -EOPNOTSUPP;
}

static int nbl_tc_flow_del_tc_flow(void *priv, struct nbl_tc_flow_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	int ret = 0;
	int i;
	struct nbl_tc_flow *tc_flow_node = NULL;
	struct nbl_draco_flow_node *node = NULL;

	if (!tc_flow_mgt) {
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow hw del tc_flow_mgt is null.\n");
		return -EINVAL;
	}

	if (!nbl_flow_is_available(tc_flow_mgt)) {
		nbl_err(common, NBL_DEBUG_FLOW,
			"tc flow hw resource unavailable.\n");
		return -EINVAL;
	}

	tc_flow_node = nbl_tc_flow_index_lookup(res_mgt, &param->key);
	if (!tc_flow_node) {
		nbl_fc_del_stats_draco(priv, true, param->key.cookie);
		nbl_fc_del_stats_draco(priv, false, param->key.cookie);
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow hw cookie=%llx not exist to del tc flow!\n",
			  param->key.cookie);
		return -ENOENT;
	}

	if (tc_flow_node->acl_flag)
		goto flow_del_acl;

	for (i = 0; i < NBL_ASSOC_PROFILE_STAGE_NUM; i++) {
		node = (struct nbl_draco_flow_node *)tc_flow_node->profile_rule[i];
		if (node) {
			ret = nbl_draco_flow_remove_node(res_mgt, node);
			if (ret)
				nbl_err(common, NBL_DEBUG_FLOW, "draco flow rm node failed, cookie:0x%llx, stage:%d, ret %d",
					tc_flow_node->key.cookie, i, ret);
		}
	}

	nbl_tc_flow_delete_index(res_mgt, &param->key);
	nbl_fc_del_stats_draco(priv, false, param->key.cookie);

	atomic64_inc(&tc_flow_mgt->destroy_num);

	return ret;

flow_del_acl:
	nbl_info(common, NBL_DEBUG_FLOW, "TODO: draco del acl flow");

	return -EOPNOTSUPP;
}

static void nbl_tc_flow_del_filter_tbl_draco(struct nbl_resource_mgt *res_mgt,
					     struct nbl_tc_flow *tc_flow_node)
{
	int i;
	int ret;
	struct nbl_draco_flow_node *node;

	for (i = 0; i < NBL_ASSOC_PROFILE_STAGE_NUM; i++) {
		node = (struct nbl_draco_flow_node *)tc_flow_node->profile_rule[i];
		if (node) {
			ret = nbl_draco_flow_remove_node(res_mgt, node);
			if (ret)
				nbl_err(res_mgt->common, NBL_DEBUG_FLOW, "tc flow rm node failed, cookie:0x%llx, stage:%d, ret %d",
					tc_flow_node->key.cookie, i, ret);
		}
	}
}

static void nbl_tc_flow_del_action_func_draco(void *priv, int index, void *data)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_tc_flow *flow_node;
	struct nbl_flow_index_key *flow_key = (struct nbl_flow_index_key *)data;

	flow_node = (struct nbl_tc_flow *)((u8 *)flow_key + sizeof(struct nbl_flow_index_key));
	nbl_fc_del_stats_draco(priv, flow_node->is_spec, flow_key->cookie);
	nbl_tc_flow_del_filter_tbl_draco(res_mgt, flow_node);
	atomic64_inc(&tc_flow_mgt->destroy_num);
}

int nbl_tc_flow_flush_flow_draco(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_index_tbl_scan_key scan_key;

	NBL_INDEX_TBL_SCAN_KEY_INIT(&scan_key, true, res_mgt, &nbl_tc_flow_del_action_func_draco);
	nbl_common_scan_index_table(tc_flow_mgt->flow_idx_tbl, &scan_key);

	return 0;
}

/* NBL_FLOW_SET_OPS(ops_name, func)
 *
 * Use X Macros to reduce setup and remove codes.
 */
#define NBL_TC_FLOW_OPS_TBL								\
do {											\
	NBL_TC_FLOW_SET_OPS(get_tc_flow_parse_info, nbl_get_tc_flow_parse_info);	\
	NBL_TC_FLOW_SET_OPS(add_tc_flow, nbl_tc_flow_add_tc_flow);			\
	NBL_TC_FLOW_SET_OPS(del_tc_flow, nbl_tc_flow_del_tc_flow);			\
	NBL_TC_FLOW_SET_OPS(flow_index_lookup, nbl_tc_flow_idx_lookup);			\
} while (0)

int nbl_tc_flow_setup_ops_draco(struct nbl_resource_ops *res_ops)
{
	int ret = 0;
#define NBL_TC_FLOW_SET_OPS(name, func) do {res_ops->NBL_NAME(name) = func; ; } while (0)
	NBL_TC_FLOW_OPS_TBL;
#undef  NBL_TC_FLOW_SET_OPS

	ret = nbl_fc_setup_ops_draco(res_ops);
	if (ret)
		return ret;

	ret = nbl_tc_tun_setup_ops_draco(res_ops);
	return ret;
}

void nbl_tc_flow_remove_ops_draco(struct nbl_resource_ops *res_ops)
{
#define NBL_TC_FLOW_SET_OPS(name, func) do {res_ops->NBL_NAME(name) = NULL; ; } while (0)
	NBL_TC_FLOW_OPS_TBL;
#undef  NBL_TC_FLOW_SET_OPS

	nbl_fc_remove_ops_draco(res_ops);
	nbl_tc_tun_remove_ops_draco(res_ops);
}

