// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */
#include "nbl_tc_flow_leonis.h"
#include "nbl_tc_flow_filter_leonis.h"
#include "nbl_p4_actions.h"
#include "nbl_fc_leonis.h"
#include "nbl_tc_tun_leonis.h"
#include "nbl_tc_pedit.h"
#include "nbl_resource_leonis.h"
#include "nbl_tc_flow.h"

static struct nbl_profile_msg g_prf_msg[NBL_ALL_PROFILE_NUM] = {
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 1,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 1,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 1,
		.profile_id = 0,
		.g_profile_id = 16,
		.key_count = 7,
		.key_len = 100,
		.key_flag = 20500,
		.act_count = 2,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
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
				.offset = 4,
				.length = 32,
				.key_id = 2,
				.name = "t_dip",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 36,
				.length = 32,
				.key_id = 4,
				.name = "t_ovnData",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 68,
				.length = 16,
				.key_id = 14,
				.name = "t_ovnClass",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 84,
				.length = 16,
				.key_id = 12,
				.name = "t_dstPort",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 138,
				.length = 22,
				.key_id = 0,
				.name = "action0",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 116,
				.length = 22,
				.key_id = 0,
				.name = "action1",
			},
		},
	},
	{
		.valid = 1,
		.pp_mode = 0,
		.key_full = 1,
		.pt_cmd = 0,
		.from_start = 1,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 1,
		.profile_id = 1,
		.g_profile_id = 17,
		.key_count = 10,
		.key_len = 196,
		.key_flag = 20504,
		.act_count = 5,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
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
				.offset = 4,
				.length = 128,
				.key_id = 3,
				.name = "t_dip",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 132,
				.length = 32,
				.key_id = 4,
				.name = "t_ovnData",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 164,
				.length = 16,
				.key_id = 14,
				.name = "t_ovnClass",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 180,
				.length = 16,
				.key_id = 12,
				.name = "t_dstPort",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 298,
				.length = 22,
				.key_id = 0,
				.name = "action0",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 276,
				.length = 22,
				.key_id = 0,
				.name = "action1",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 254,
				.length = 22,
				.key_id = 0,
				.name = "action2",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 232,
				.length = 22,
				.key_id = 0,
				.name = "action3",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 210,
				.length = 22,
				.key_id = 0,
				.name = "action4",
			},
		},
	},
	{
		.valid = 1,
		.pp_mode = 1,
		.key_full = 1,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 1,
		.profile_id = 2,
		.g_profile_id = 18,
		.key_count = 18,
		.key_len = 160,
		.key_flag = 549999083555,
		.act_count = 7,
		.pre_assoc_profile_id = {16, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {32, 33, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
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
				.offset = 4,
				.length = 32,
				.key_id = 5,
				.name = "t_vni",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 36,
				.length = 48,
				.key_id = 23,
				.name = "dstMAC",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 84,
				.length = 16,
				.key_id = 27,
				.name = "etherType",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 100,
				.length = 16,
				.key_id = 26,
				.name = "vlan2_pcv",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 116,
				.length = 16,
				.key_id = 25,
				.name = "vlan1_pcv",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 148,
				.length = 8,
				.key_id = 1,
				.name = "sport_b8",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 156,
				.length = 4,
				.key_id = 39,
				.name = "sport_b4",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)3,
				.offset = 100,
				.length = 4,
				.key_id = 0,
				.name = "vlan2_pcv_mask",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)3,
				.offset = 116,
				.length = 4,
				.key_id = 0,
				.name = "vlan1_pcv_mask",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 132,
				.length = 16,
				.key_id = 0,
				.name = "tab_index",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 298,
				.length = 22,
				.key_id = 0,
				.name = "action0",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 276,
				.length = 22,
				.key_id = 0,
				.name = "action1",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 254,
				.length = 22,
				.key_id = 0,
				.name = "action2",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 232,
				.length = 22,
				.key_id = 0,
				.name = "action3",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 210,
				.length = 22,
				.key_id = 0,
				.name = "action4",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 188,
				.length = 22,
				.key_id = 0,
				.name = "action5",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 166,
				.length = 22,
				.key_id = 0,
				.name = "action6",
			},
		},
	},
	{
		.valid = 1,
		.pp_mode = 1,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 1,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 1,
		.profile_id = 3,
		.g_profile_id = 19,
		.key_count = 11,
		.key_len = 112,
		.key_flag = 549999083522,
		.act_count = 2,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {32, 33, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
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
				.offset = 4,
				.length = 48,
				.key_id = 23,
				.name = "dstMAC",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 52,
				.length = 16,
				.key_id = 27,
				.name = "etherType",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 68,
				.length = 16,
				.key_id = 26,
				.name = "vlan2_pcv",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 84,
				.length = 16,
				.key_id = 25,
				.name = "vlan1_pcv",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 100,
				.length = 8,
				.key_id = 1,
				.name = "sport_b8",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 108,
				.length = 4,
				.key_id = 39,
				.name = "sport_b4",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)3,
				.offset = 68,
				.length = 4,
				.key_id = 0,
				.name = "vlan2_pcv_mask",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)3,
				.offset = 84,
				.length = 4,
				.key_id = 0,
				.name = "vlan1_pcv_mask",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 138,
				.length = 22,
				.key_id = 0,
				.name = "action0",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 116,
				.length = 22,
				.key_id = 0,
				.name = "action1",
			},
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 1,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 1,
		.pp_id = 2,
		.profile_id = 0,
		.g_profile_id = 32,
		.key_count = 9,
		.key_len = 68,
		.key_flag = 51541704705,
		.act_count = 4,
		.pre_assoc_profile_id = {18, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {34, 36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
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
				.offset = 4,
				.length = 32,
				.key_id = 21,
				.name = "dip",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 36,
				.length = 8,
				.key_id = 35,
				.name = "ttl",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 44,
				.length = 8,
				.key_id = 34,
				.name = "tos",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 52,
				.length = 16,
				.key_id = 0,
				.name = "tab_index",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 138,
				.length = 22,
				.key_id = 0,
				.name = "action0",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 116,
				.length = 22,
				.key_id = 0,
				.name = "action1",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 94,
				.length = 22,
				.key_id = 0,
				.name = "action2",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 72,
				.length = 22,
				.key_id = 0,
				.name = "action3",
			},
		},
	},
	{
		.valid = 1,
		.pp_mode = 0,
		.key_full = 1,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 1,
		.pp_id = 2,
		.profile_id = 1,
		.g_profile_id = 33,
		.key_count = 12,
		.key_len = 164,
		.key_flag = 51543801857,
		.act_count = 7,
		.pre_assoc_profile_id = {18, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {35, 37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
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
				.offset = 4,
				.length = 128,
				.key_id = 22,
				.name = "dip",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 132,
				.length = 8,
				.key_id = 35,
				.name = "ttl",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 140,
				.length = 8,
				.key_id = 34,
				.name = "tos",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 148,
				.length = 16,
				.key_id = 0,
				.name = "tab_index",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 298,
				.length = 22,
				.key_id = 0,
				.name = "action0",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 276,
				.length = 22,
				.key_id = 0,
				.name = "action1",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 254,
				.length = 22,
				.key_id = 0,
				.name = "action2",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 232,
				.length = 22,
				.key_id = 0,
				.name = "action3",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 210,
				.length = 22,
				.key_id = 0,
				.name = "action4",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 188,
				.length = 22,
				.key_id = 0,
				.name = "action5",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 166,
				.length = 22,
				.key_id = 0,
				.name = "action6",
			},
		},
	},
	{
		.valid = 1,
		.pp_mode = 1,
		.key_full = 1,
		.pt_cmd = 1,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 2,
		.profile_id = 2,
		.g_profile_id = 34,
		.key_count = 13,
		.key_len = 164,
		.key_flag = 8801195917312,
		.act_count = 7,
		.pre_assoc_profile_id = {32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
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
				.offset = 36,
				.length = 32,
				.key_id = 19,
				.name = "sip",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 68,
				.length = 32,
				.key_id = 21,
				.name = "dip",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 124,
				.length = 8,
				.key_id = 32,
				.name = "protocol",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 132,
				.length = 16,
				.key_id = 28,
				.name = "srcPort",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 148,
				.length = 16,
				.key_id = 29,
				.name = "dstPort",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 298,
				.length = 22,
				.key_id = 0,
				.name = "action0",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 276,
				.length = 22,
				.key_id = 0,
				.name = "action1",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 254,
				.length = 22,
				.key_id = 0,
				.name = "action2",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 232,
				.length = 22,
				.key_id = 0,
				.name = "action3",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 210,
				.length = 22,
				.key_id = 0,
				.name = "action4",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 188,
				.length = 22,
				.key_id = 0,
				.name = "action5",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 166,
				.length = 22,
				.key_id = 0,
				.name = "action6",
			},
		},
	},
	{
		.valid = 1,
		.pp_mode = 1,
		.key_full = 1,
		.pt_cmd = 1,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 2,
		.profile_id = 3,
		.g_profile_id = 35,
		.key_count = 13,
		.key_len = 164,
		.key_flag = 8801198538752,
		.act_count = 7,
		.pre_assoc_profile_id = {33, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
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
				.offset = 36,
				.length = 32,
				.key_id = 20,
				.name = "sip",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 68,
				.length = 32,
				.key_id = 22,
				.name = "dip",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 124,
				.length = 8,
				.key_id = 32,
				.name = "protocol",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 132,
				.length = 16,
				.key_id = 28,
				.name = "srcPort",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 148,
				.length = 16,
				.key_id = 29,
				.name = "dstPort",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 298,
				.length = 22,
				.key_id = 0,
				.name = "action0",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 276,
				.length = 22,
				.key_id = 0,
				.name = "action1",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 254,
				.length = 22,
				.key_id = 0,
				.name = "action2",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 232,
				.length = 22,
				.key_id = 0,
				.name = "action3",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 210,
				.length = 22,
				.key_id = 0,
				.name = "action4",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 188,
				.length = 22,
				.key_id = 0,
				.name = "action5",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 166,
				.length = 22,
				.key_id = 0,
				.name = "action6",
			},
		},
	},
	{
		.valid = 1,
		.pp_mode = 1,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 1,
		.pp_id = 2,
		.profile_id = 4,
		.g_profile_id = 36,
		.key_count = 8,
		.key_len = 100,
		.key_flag = 5100797953,
		.act_count = 2,
		.pre_assoc_profile_id = {32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
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
				.offset = 4,
				.length = 32,
				.key_id = 19,
				.name = "sip",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 36,
				.length = 16,
				.key_id = 28,
				.name = "srcPort",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 52,
				.length = 16,
				.key_id = 29,
				.name = "dstPort",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 68,
				.length = 8,
				.key_id = 32,
				.name = "protocol",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 84,
				.length = 16,
				.key_id = 0,
				.name = "tab_index",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 138,
				.length = 22,
				.key_id = 0,
				.name = "action0",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 116,
				.length = 22,
				.key_id = 0,
				.name = "action1",
			},
		},
	},
	{
		.valid = 1,
		.pp_mode = 1,
		.key_full = 1,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 1,
		.pp_id = 2,
		.profile_id = 5,
		.g_profile_id = 37,
		.key_count = 11,
		.key_len = 196,
		.key_flag = 5101322241,
		.act_count = 5,
		.pre_assoc_profile_id = {33, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
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
				.offset = 4,
				.length = 128,
				.key_id = 20,
				.name = "sip",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 132,
				.length = 16,
				.key_id = 28,
				.name = "srcPort",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 148,
				.length = 16,
				.key_id = 29,
				.name = "dstPort",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 164,
				.length = 8,
				.key_id = 32,
				.name = "protocol",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 180,
				.length = 16,
				.key_id = 0,
				.name = "tab_index",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 298,
				.length = 22,
				.key_id = 0,
				.name = "action0",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 276,
				.length = 22,
				.key_id = 0,
				.name = "action1",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 254,
				.length = 22,
				.key_id = 0,
				.name = "action2",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 232,
				.length = 22,
				.key_id = 0,
				.name = "action3",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)1,
				.offset = 210,
				.length = 22,
				.key_id = 0,
				.name = "action4",
			},
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 1,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 3,
		.profile_id = 0,
		.g_profile_id = 48,
		.key_count = 7,
		.key_len = 116,
		.key_flag = 17597286842369,
		.act_count = 0,
		.pre_assoc_profile_id = {34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
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
				.offset = 4,
				.length = 32,
				.key_id = 19,
				.name = "sip",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 36,
				.length = 16,
				.key_id = 28,
				.name = "srcPort",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 52,
				.length = 16,
				.key_id = 29,
				.name = "dstPort",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 68,
				.length = 8,
				.key_id = 32,
				.name = "protocol",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 84,
				.length = 16,
				.key_id = 0,
				.name = "tab_index",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 100,
				.length = 16,
				.key_id = 44,
				.name = "dp_hash0",
			},
		},
	},
	{
		.valid = 1,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 3,
		.profile_id = 1,
		.g_profile_id = 49,
		.key_count = 7,
		.key_len = 212,
		.key_flag = 17597287366657,
		.act_count = 0,
		.pre_assoc_profile_id = {35, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
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
				.offset = 4,
				.length = 128,
				.key_id = 20,
				.name = "sip",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 132,
				.length = 16,
				.key_id = 28,
				.name = "srcPort",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 148,
				.length = 16,
				.key_id = 29,
				.name = "dstPort",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 164,
				.length = 8,
				.key_id = 32,
				.name = "protocol",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 180,
				.length = 16,
				.key_id = 0,
				.name = "tab_index",
			},
			{
				.valid = 1,
				.key_type = (enum nbl_flow_key_type)2,
				.offset = 196,
				.length = 16,
				.key_id = 44,
				.name = "dp_hash0",
			},
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
	{
		.valid = 0,
		.pp_mode = 0,
		.key_full = 0,
		.pt_cmd = 0,
		.from_start = 0,
		.to_end = 0,
		.need_upcall = 0,
		.pp_id = 0,
		.profile_id = 0,
		.g_profile_id = 0,
		.key_count = 0,
		.key_len = 0,
		.key_flag = 0,
		.act_count = 0,
		.pre_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.next_assoc_profile_id = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.flow_keys = {
		},
	},
};

static struct nbl_profile_assoc_graph g_prf_graph[NBL_ASSOC_PROFILE_GRAPH_NUM] = {
	{
		.key_flag = 26994920673335,
		.profile_count = 5,
		.profile_id = {16, 18, 32, 34, 48},
	},
	{
		.key_flag = 606641606711,
		.profile_count = 4,
		.profile_id = {16, 18, 32, 36},
	},
	{
		.key_flag = 601540808759,
		.profile_count = 3,
		.profile_id = {16, 18, 32},
	},
	{
		.key_flag = 26994923294775,
		.profile_count = 5,
		.profile_id = {16, 18, 33, 35, 49},
	},
	{
		.key_flag = 606644228151,
		.profile_count = 4,
		.profile_id = {16, 18, 33, 37},
	},
	{
		.key_flag = 601542905911,
		.profile_count = 3,
		.profile_id = {16, 18, 33},
	},
	{
		.key_flag = 549999104055,
		.profile_count = 2,
		.profile_id = {16, 18},
	},
	{
		.key_flag = 20500,
		.profile_count = 1,
		.profile_id = {16},
	},
	{
		.key_flag = 26994920673339,
		.profile_count = 5,
		.profile_id = {17, 18, 32, 34, 48},
	},
	{
		.key_flag = 606641606715,
		.profile_count = 4,
		.profile_id = {17, 18, 32, 36},
	},
	{
		.key_flag = 601540808763,
		.profile_count = 3,
		.profile_id = {17, 18, 32},
	},
	{
		.key_flag = 26994923294779,
		.profile_count = 5,
		.profile_id = {17, 18, 33, 35, 49},
	},
	{
		.key_flag = 606644228155,
		.profile_count = 4,
		.profile_id = {17, 18, 33, 37},
	},
	{
		.key_flag = 601542905915,
		.profile_count = 3,
		.profile_id = {17, 18, 33},
	},
	{
		.key_flag = 549999104059,
		.profile_count = 2,
		.profile_id = {17, 18},
	},
	{
		.key_flag = 20504,
		.profile_count = 1,
		.profile_id = {17},
	},
	{
		.key_flag = 26994920652803,
		.profile_count = 4,
		.profile_id = {19, 32, 34, 48},
	},
	{
		.key_flag = 606641586179,
		.profile_count = 3,
		.profile_id = {19, 32, 36},
	},
	{
		.key_flag = 601540788227,
		.profile_count = 2,
		.profile_id = {19, 32},
	},
	{
		.key_flag = 26994923274243,
		.profile_count = 4,
		.profile_id = {19, 33, 35, 49},
	},
	{
		.key_flag = 606644207619,
		.profile_count = 3,
		.profile_id = {19, 33, 37},
	},
	{
		.key_flag = 601542885379,
		.profile_count = 2,
		.profile_id = {19, 33},
	},
	{
		.key_flag = 549999083522,
		.profile_count = 1,
		.profile_id = {19},
	},
};

static u8 g_profile_graph_count = 23;

static void nbl_debug_print_hash_key(struct nbl_common_info *common,
				     struct nbl_flow_tab_conf *hash_key,
				     struct nbl_profile_msg *prf_msg,
				     struct nbl_fdir_fltr *input)
{
	size_t index = 0;
	u32 *ptr = (u32 *)(&hash_key->key_value);
	/* debug example: tnl v4/v6/l2 */
	const union nbl_ipv4_tnl_data_u *p0 = (union nbl_ipv4_tnl_data_u *)(ptr);
	const union nbl_ipv6_tnl_data_u *p1 = (union nbl_ipv6_tnl_data_u *)(ptr);
	const union nbl_l2_tnl_data_u *p2 = (union nbl_l2_tnl_data_u *)(ptr);

	/* debug example: nontnl l2 */
	const union nbl_l2_notnl_data_u *p3 = (union nbl_l2_notnl_data_u *)(ptr);

	/* debug example: l3 */
	const union nbl_l3_ipv4_data_u *p4 = (union nbl_l3_ipv4_data_u *)(ptr);
	const union nbl_l3_ipv6_data_u *p5 = (union nbl_l3_ipv6_data_u *)(ptr);

	/* debug example: t5 ipv4 (160 bits) and t5 ipv6 (320 bits) */
	const union nbl_t5_ipv4_data_u *p8 = (union nbl_t5_ipv4_data_u *)(ptr);
	const union nbl_t5_ipv6_data_u *p9 = (union nbl_t5_ipv6_data_u *)(ptr);

	unsigned long long test_l2_notnl =
		NBL_FLOW_KEY_DSTMAC_FLAG | NBL_FLOW_KEY_ETHERTYPE_FLAG |
		NBL_FLOW_KEY_SVLAN_FLAG | NBL_FLOW_KEY_CVLAN_FLAG;

	unsigned long long test_tnl_v4 =
		NBL_FLOW_KEY_T_DIPV4_FLAG | NBL_FLOW_KEY_T_OPT_DATA_FLAG |
		NBL_FLOW_KEY_T_OPT_CLASS_FLAG | NBL_FLOW_KEY_T_DSTPORT_FLAG;

	unsigned long long test_tnl_v6 =
		NBL_FLOW_KEY_T_DIPV6_FLAG | NBL_FLOW_KEY_T_OPT_DATA_FLAG |
		NBL_FLOW_KEY_T_OPT_CLASS_FLAG | NBL_FLOW_KEY_T_DSTPORT_FLAG;

	unsigned long long test_tnl_l2 =
		NBL_FLOW_KEY_T_VNI_FLAG | NBL_FLOW_KEY_DSTMAC_FLAG |
		NBL_FLOW_KEY_ETHERTYPE_FLAG | NBL_FLOW_KEY_CVLAN_FLAG |
		NBL_FLOW_KEY_SVLAN_FLAG;

	unsigned long long test_l3_v4 = NBL_FLOW_KEY_DIPV4_FLAG |
					NBL_FLOW_KEY_TTL_FLAG |
					NBL_FLOW_KEY_DSCP_FLAG;

	unsigned long long test_l3_v6 = NBL_FLOW_KEY_DIPV6_FLAG |
					NBL_FLOW_KEY_TTL_FLAG |
					NBL_FLOW_KEY_DSCP_FLAG;

	unsigned long long test_t5_ipv6 =
		NBL_FLOW_KEY_DSTPORT_FLAG | NBL_FLOW_KEY_SRCPORT_FLAG |
		NBL_FLOW_KEY_PROTOCOL_FLAG | NBL_FLOW_KEY_SIPV6_FLAG;

	unsigned long long test_t5_ipv4 =
		NBL_FLOW_KEY_DSTPORT_FLAG | NBL_FLOW_KEY_SRCPORT_FLAG |
		NBL_FLOW_KEY_PROTOCOL_FLAG | NBL_FLOW_KEY_SIPV4_FLAG;

	u8 offset =
		prf_msg->key_full ? 0 : (NBL_FEM_KT_HALF_LEN / NBL_BITS_IN_U32);
	ptr += offset;

	/* print out all the fields */
	for (index = 0; index < 10; index++)
		nbl_debug(common, NBL_DEBUG_FLOW, "tc flow hw kt data[%zu]: %x\n", index,
			  hash_key->key_value[index]);

	if ((prf_msg->key_flag & test_tnl_v4) == test_tnl_v4) {
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow hw calculated tv4 profile: id %d, dipv4 0x%x, optdata 0x%x, optclass 0x%x, dport 0x%x\n",
			  p0->info.template, p0->info.dst_ip,
			  p0->info.option_data, p0->info.option_class,
			  p0->info.dst_port);
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow hw original tv4 profile: id %d, dipv4 0x%x, dport 0x%x\n",
			  prf_msg->profile_id, input->ip_outer.dst_ip.addr,
			  input->l4_outer.dst_port);
	} else if ((prf_msg->key_flag & test_tnl_v6) == test_tnl_v6) {
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow hw calculated tv6 profile: id %d, dipv6 0x%lx 0x%lx, optdata 0x%x, optclass 0x%x, dport 0x%x\n",
			  p1->info.template, (unsigned long)p1->info.dst_ipv6_1,
			  (unsigned long)p1->info.dst_ipv6_2,
			  p1->info.option_data, p1->info.option_class,
			  p1->info.dst_port);
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow hw originla tv6 profile: id %d, dipv6 0x%x, dport 0x%x\n",
			  prf_msg->profile_id, input->ip_outer.dst_ip.addr,
			  input->l4_outer.dst_port);
	} else if ((prf_msg->key_flag & test_tnl_l2) == test_tnl_l2) {
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow hw calculated tnl l2 profile: id %d, vni %d, dstmac 0x%lx, etype 0x%04x, cvlan %d, svlan %d\n",
			  p2->info.template, p2->info.vni,
			  (unsigned long)p2->info.dst_mac, p2->info.ether_type,
			  p2->info.cvlan_id, p2->info.svlan_id);
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow hw original tnl l2 profile: id %d, dstmac 0x%llx, etype 0x%04x, cvlan %d, svlan %d\n",
			  prf_msg->profile_id,
			  *(u64 *)input->l2_data.dst_mac,
			  input->l2_data.ether_type, input->cvlan_tag,
			  input->svlan_tag);
	} else if ((prf_msg->key_flag & test_l2_notnl) == test_l2_notnl) {
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow hw calculated l2 profile: id %d, dstmac 0x%lx, etype 0x%04x, svlan %d, cvlan %d\n",
			  p3->info.template, (unsigned long)p3->info.dst_mac,
			  p3->info.ether_type, p3->info.svlan_id,
			  p3->info.cvlan_id);
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow hw original l2 profile: id %d, dstmac 0x%llx, etype 0x%04x, svlan %d, cvlan %d\n",
			  prf_msg->profile_id,
			  *(u64 *)input->l2_data.dst_mac,
			  input->l2_data.ether_type, input->svlan_tag,
			  input->cvlan_tag);
	} else if ((prf_msg->key_flag & test_l3_v4) == test_l3_v4) {
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow hw calculated l3 v4: id %d, dip 0x%x, ttl %d, dscp %d\n",
			  p4->info.template, p4->info.dst_ip, p4->info.ttl,
			  p4->info.dscp);
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow hw original l3 v4: id %d, dip 0x%x, ttl %d, dscp %d\n",
			  prf_msg->profile_id, input->ip.dst_ip.addr,
			  input->ip.ttl, input->ip.tos);
	} else if ((prf_msg->key_flag & test_l3_v6) == test_l3_v6) {
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow hw calculated l3 v6: id %d, dip 0x%llx-%llx, ttl %d, dscp %d\n",
			  p5->info.template, p5->info.dst_ipv6_1,
			  p5->info.dst_ipv6_2, p5->info.hoplimit, p5->info.dscp);
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow hw original l3 v6: id %d, dip 0x%llx-%llx, ttl %d, dscp %d\n",
			  prf_msg->profile_id,
			  *(u64 *)input->ip.dst_ip.v6_addr,
			  *((u64 *)input->ip.dst_ip.v6_addr + 1),
			  input->ip.ttl, input->ip.tos);
	} else if ((prf_msg->key_flag & test_t5_ipv4) == test_t5_ipv4) {
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow hw calculated t5 ipv4 profile: id %d, sip 0x%x, srcport %d, dstport %d, protocol %d\n",
			  p8->info.template, p8->info.src_ip, p8->info.src_port,
			  p8->info.dst_port, p8->info.proto);
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow hw original data: sip: 0x%x, srcport %d,  dstport %d, protocol %d\n",
			  input->ip.src_ip.addr, input->l4.src_port,
			  input->l4.dst_port, input->ip.proto);
	} else if ((prf_msg->key_flag & test_t5_ipv6) == test_t5_ipv6) {
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow hw calculated t5 ipv6 profile: sip 0x%llx-%llx, srcport %d, dstport %d, protocol %d\n",
			  p9->info.src_ipv6_1, p9->info.src_ipv6_2,
			  p9->info.src_port, p9->info.dst_port, p9->info.proto);
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow hw original data: sip: 0x%llx-%llx, srcport %d,  dstport %d, protocol %d\n",
			  *(u64 *)input->ip.src_ip.v6_addr,
			  *((u64 *)input->ip.src_ip.v6_addr + 1),
			  input->l4.src_port, input->l4.dst_port,
			  input->ip.proto);
	}
}

static void nbl_assign_hash_key(struct nbl_flow_tab_conf *hash_key,
				struct nbl_flow_pattern_conf *filter,
				struct nbl_resource_mgt *res_mgt,
				struct nbl_profile_offload_msg *off_msg)
{
	/* 320 bit key data, namely 5 * 64 bits */
	u32 *kt_data = hash_key->key_value;
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

		nbl_assign_hash_key_key(kt_data, key_info, prf_msg,
					&filter->input, prf_msg->profile_id, off_msg->assoc_tbl_id);
	}

	/* print out the 320 bit key */
	nbl_debug_print_hash_key(common, hash_key, prf_msg, &filter->input);
}

/**
 * @brief: offload sw-tab to hw
 */
static int nbl_add_nic_hw_flow_tab(void *node, struct nbl_rule_action *act,
				   struct nbl_resource_mgt *res_mgt,
				   struct nbl_flow_idx_info *idx_info)
{
	int rc = 0;

	WARN_ON(!node);
	rc = nbl_flow_offload_ops.add(node, act, res_mgt, idx_info);
	return rc;
}

/**
 * @brief: hw flow tab destroy
 */
static int nbl_del_nic_hw_flow_tab(void *node, struct nbl_resource_mgt *res_mgt,
				   struct nbl_flow_idx_info *idx_info)
{
	int rc = 0;

	WARN_ON(!node);
	rc = nbl_flow_offload_ops.del(node, res_mgt, idx_info);
	return rc;
}

/**
 * @brief: hw flow tab query
 */
__maybe_unused static int nbl_query_nic_hw_flow_tab(void *node, u32 idx,
						    void *query_rslt)
{
	int rc = 0;

	WARN_ON(!node);
	rc = nbl_flow_offload_ops.query(node, idx, query_rslt);
	return rc;
}

int nbl_tc_flow_alloc_bmp_id(unsigned long *bitmap_mng, u32 size,
			     u8 type, u32 *bitmap_id)
{
	u32 id;

	if (type == NBL_TC_KT_HALF_MODE) {
		id = find_first_zero_bit(bitmap_mng, size);
		if (id == size)
			return -ENOSPC;
		set_bit(id, bitmap_mng);
	} else {
		id = nbl_common_find_available_idx(bitmap_mng, size, 2, 2);
		if (id == size)
			return -ENOSPC;
		set_bit(id, bitmap_mng);
		set_bit(id + 1, bitmap_mng);
	}

	*bitmap_id = id;
	return 0;
}

void nbl_tc_flow_free_bmp_id(unsigned long *bitmap_mng, u32 id, u8 type)
{
	if (type == NBL_TC_KT_HALF_MODE) {
		clear_bit(id, bitmap_mng);
	} else {
		clear_bit(id, bitmap_mng);
		clear_bit(id + 1, bitmap_mng);
	}
}

/**
 * @brief: tnl: ipv4 tnl filter hash tab search func
 *
 * @param[in] tc_flow_mgt: tc flow hw mgt
 * @param[in] key: node key info
 * @return nbl_flow_tab_filter *: return node ptr
 */
static struct nbl_flow_tab_filter *
nbl_flow_tab_filter_lookup(struct nbl_resource_mgt *res_mgt,
			   struct nbl_flow_tab_conf *key, u8 profile_id)
{
	struct nbl_flow_tab_filter *tab_filter = NULL;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);

	if (!tc_flow_mgt->flow_tab_hash[profile_id].flow_tab_hash)
		return NULL;

	tab_filter = nbl_common_get_hash_node(tc_flow_mgt->flow_tab_hash[profile_id].flow_tab_hash,
					      key);
	return tab_filter;
}

/**
 * @brief:delete ipv4-tnl-hash-list
 * @param[in] tc_flow_mgt: tc flow hw mgt
 * @return int: 0-success other-fail
 *
 */
static int
nbl_flow_flush_flow_tab_hash_list(struct nbl_resource_mgt *res_mgt,
				  u8 profile_id)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);

	if (!tc_flow_mgt->flow_tab_hash[profile_id].flow_tab_hash)
		return 0;

	nbl_common_remove_hash_table(tc_flow_mgt->flow_tab_hash[profile_id].flow_tab_hash, NULL);
	tc_flow_mgt->flow_tab_hash[profile_id].flow_tab_hash = NULL;

	return 0;
}

static int nbl_flow_flush_hash_list(struct nbl_resource_mgt *res_mgt)
{
	int ret = 0;
	u8 i = 0;

	for (i = 0; i < NBL_ALL_PROFILE_NUM; i++)
		ret |= nbl_flow_flush_flow_tab_hash_list(res_mgt, i);

	return ret;
}

/**
 * @brief: tnl.remove hash tab node func
 *
 * @param[in] tc_flow_mgt: tc_flow_mgt
 * @param[in] key: node key info
 * @param[in] off: is need to offload to hw
 * @return int: 0-success other-fail
 */
static int nbl_rmv_flow_tab_filter(struct nbl_resource_mgt *res_mgt,
				   void *key, bool off, bool last_stage,
				   u8 profile_id)
{
	struct nbl_flow_idx_info idx_info = { 0 };
	struct nbl_flow_tab_filter *node = NULL;
	struct nbl_flow_tab_filter tmp_node;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	int ret = 0;

	mutex_lock(&tc_flow_mgt->flow_lock);
	node = nbl_flow_tab_filter_lookup(res_mgt, key, profile_id);
	if (!node) {
		mutex_unlock(&tc_flow_mgt->flow_lock);
	} else if (node && node->ref_cnt > NBL_FLOW_TAB_ONE_TIME) {
		node->ref_cnt--;
		mutex_unlock(&tc_flow_mgt->flow_lock);
	} else {
		memcpy(&tmp_node, node, sizeof(*node));
		if (node->edit_item.is_mir)
			list_replace_init(&node->edit_item.tc_mcc_list,
					  &tmp_node.edit_item.tc_mcc_list);

		if (node->assoc_tbl_id >= NBL_FLOW_TABLE_NUM) {
			mutex_unlock(&tc_flow_mgt->flow_lock);
			nbl_err(common, NBL_DEBUG_FLOW, "tc flow hw assoc_tbl_id invalid %u.\n",
				node->assoc_tbl_id);
			return -EINVAL;
		}

		if (node->assoc_tbl_id != 0)
			nbl_tc_flow_free_bmp_id(tc_flow_mgt->assoc_table_bmp,
						node->assoc_tbl_id, 0);

		nbl_common_free_hash_node(tc_flow_mgt->flow_tab_hash[profile_id].flow_tab_hash,
					  key);
		node = NULL;

		if (tc_flow_mgt->flow_tab_hash[profile_id].tab_cnt > 0) {
			tc_flow_mgt->flow_tab_hash[profile_id].tab_cnt--;
			nbl_debug(common, NBL_DEBUG_FLOW, "tc flow hw rmv pid=%d tab_cnt--=%d\n",
				  profile_id, tc_flow_mgt->flow_tab_hash[profile_id].tab_cnt);
		} else {
			nbl_err(common, NBL_DEBUG_FLOW, "tc flow hw rmv pid=%d tab_cnt=%d, do not reduce\n",
				profile_id, tc_flow_mgt->flow_tab_hash[profile_id].tab_cnt);
			mutex_unlock(&tc_flow_mgt->flow_lock);
			return -EINVAL;
		}

		mutex_unlock(&tc_flow_mgt->flow_lock);

		/* del hw */
		ret = 0;
		if (off) {
			idx_info.last_stage = last_stage;
			idx_info.profile_id = profile_id;
			ret = nbl_del_nic_hw_flow_tab(&tmp_node, res_mgt, &idx_info);
		}
	}
	return ret;
}

/**
 * @brief: flow_tab.add hash node, and transfer the key value
 *
 * @param[in] key: node key info
 * @param[out] ptr: hash node
 * @return int: 0-success other-fail
 */
static int nbl_flow_tab_hash_add(struct nbl_resource_mgt *res_mgt,
				 struct nbl_flow_pattern_conf *filter,
				 struct nbl_tc_flow *tc_flow_ptr, void **ptr,
				 struct nbl_profile_offload_msg *prof_off_msg)
{
	struct nbl_flow_tab_filter *node = NULL;
	const struct nbl_flow_tab_filter *pre_node = NULL;
	struct nbl_flow_tab_conf hash_key;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	int ret = 0;
	u8 profile_id = prof_off_msg->profile_id;
	u8 profile_stage = prof_off_msg->profile_stage;
	u32 entries = 0;
	struct nbl_flow_tab_filter filter_data;

	memset(&hash_key, 0, sizeof(hash_key));

	if (profile_stage != 0) {
		pre_node = tc_flow_ptr->profile_rule[profile_stage - 1];
		if (!pre_node)
			return -EINVAL;
		prof_off_msg->assoc_tbl_id = (u16)pre_node->assoc_tbl_id;
	}
	nbl_assign_hash_key(&hash_key, filter, res_mgt, prof_off_msg);

	mutex_lock(&tc_flow_mgt->flow_lock);
	node = nbl_flow_tab_filter_lookup(res_mgt, &hash_key, profile_id);
	if (node) {
		if (prof_off_msg->last_stage) {
			nbl_info(common, NBL_DEBUG_FLOW, "tc flow offload already, drop this one");
			mutex_unlock(&tc_flow_mgt->flow_lock);
			return -EEXIST;
		}

		node->ref_cnt++;
		*ptr = node;
		tc_flow_ptr->profile_id[profile_stage] = profile_id;
		tc_flow_ptr->profile_rule[profile_stage] = node;
		mutex_unlock(&tc_flow_mgt->flow_lock);
		nbl_debug(common, NBL_DEBUG_FLOW, "tc flow hw flow_tab refcnt ++.\n");
		return 0;
	}

	if (profile_id <= NBL_PP1_PROFILE_ID_MAX && profile_id > NBL_PP0_PROFILE_ID_MAX) {
		entries = NBL_FLOW_TABLE_LEN;
	} else if (profile_id <= NBL_PP2_PROFILE_ID_MAX && profile_id > NBL_PP1_PROFILE_ID_MAX) {
		entries = NBL_FLOW_TABLE_LEN * 8;
	} else {
		mutex_unlock(&tc_flow_mgt->flow_lock);
		return 0;
	}

	if (tc_flow_mgt->flow_tab_hash[profile_id].tab_cnt >= entries) {
		mutex_unlock(&tc_flow_mgt->flow_lock);
		nbl_debug(common, NBL_DEBUG_FLOW, "tc flow hw pid=%d flow_tab num is greater than %d.",
			  profile_id, entries);
		return -EINVAL;
	}

	memset(&filter_data, 0, sizeof(filter_data));
	filter_data.ref_cnt = 1;
	memcpy(&filter_data.key, &hash_key, sizeof(hash_key));

	if (prof_off_msg->last_stage)
		goto insert_filter;

	/* alloc bmp */
	ret = nbl_tc_flow_alloc_bmp_id(tc_flow_mgt->assoc_table_bmp,
				       NBL_FLOW_TABLE_NUM, 0, &filter_data.assoc_tbl_id);
	if (ret) {
		mutex_unlock(&tc_flow_mgt->flow_lock);
		nbl_debug(common, NBL_DEBUG_FLOW, "tc flow hw failed to alloc id for flow tab.\n");
		return -ENOSPC;
	}

	if (!filter_data.assoc_tbl_id) {
		ret = nbl_tc_flow_alloc_bmp_id(tc_flow_mgt->assoc_table_bmp,
					       NBL_FLOW_TABLE_NUM, 0, &filter_data.assoc_tbl_id);
		if (ret) {
			mutex_unlock(&tc_flow_mgt->flow_lock);
			nbl_debug(common, NBL_DEBUG_FLOW, "tc flow hw failed to alloc id for flow tab.\n");
			return -ENOSPC;
		}
	}

insert_filter:
	ret = nbl_insert_flow_tab_filter(res_mgt, &hash_key, &filter_data,
					 (void **)&node, profile_id);
	if (ret) {
		if (!prof_off_msg->last_stage)
			nbl_tc_flow_free_bmp_id(tc_flow_mgt->assoc_table_bmp,
						filter_data.assoc_tbl_id, 0);
		mutex_unlock(&tc_flow_mgt->flow_lock);
		nbl_info(common, NBL_DEBUG_FLOW,
			 "tc flow hw failed to insert flow tab filter to hash table %d.\n", ret);
		return ret;
	}

	*ptr = node;
	tc_flow_ptr->profile_id[profile_stage] = profile_id;
	tc_flow_ptr->profile_rule[profile_stage] = node;
	mutex_unlock(&tc_flow_mgt->flow_lock);
	return ret;
}

/**
 * @brief: outer tnl flow tab resource storage and offload to hw
 *
 * @param[in] tc_flow_mgt: tc flow hw info
 * @param[in] act: nbl_rule_action info
 * @param[in] filter: nbl_flow_pattern_conf info
 * @param[out] tc_flow_ptr: tc-flow pointer
 * @return int: zero init success, other init failed
 */
static int nbl_flow_tab_storage(struct nbl_resource_mgt *res_mgt,
				__maybe_unused struct nbl_rule_action *act,
				struct nbl_flow_pattern_conf *filter,
				struct nbl_tc_flow *tc_flow_ptr,
				struct nbl_profile_offload_msg *prof_off_msg)
{
	int ret = 0;
	struct nbl_flow_tab_filter *flow_tab_node = NULL;
	struct nbl_flow_idx_info idx_info = { 0 };
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	ret = nbl_flow_tab_hash_add(res_mgt, filter, tc_flow_ptr,
				    (void **)&flow_tab_node, prof_off_msg);
	if (ret || !flow_tab_node) {
		nbl_info(common, NBL_DEBUG_FLOW, "tc flow hw flow_tab hash-list storage fail, ret %d, to store flow node %p.\n",
			 ret, flow_tab_node);
		return ret;
	}
	if (flow_tab_node->ref_cnt > 1)
		return 0;

	flow_tab_node->act_flags = act->flag;
	idx_info.profile_id = prof_off_msg->profile_id;
	idx_info.last_stage = prof_off_msg->last_stage;
	idx_info.key_flag = filter->key_flag;
	idx_info.pt_cmd = prof_off_msg->pt_cmd;
	ret = nbl_add_nic_hw_flow_tab(flow_tab_node, act, res_mgt, &idx_info);
	if (ret) {
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow hw add flow 2hw fail, ret %d.\n", ret);
		return ret;
	}
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
 * @param[in] filter: key info
 * @param[in] act: actions info
 * @return int: 0-success other-fail.
 */
static int nbl_flow_tab_storage_entr(struct nbl_resource_mgt *res_mgt,
				     struct nbl_tc_flow *tc_flow_ptr,
				     struct nbl_flow_pattern_conf *filter,
				     struct nbl_rule_action *act)
{
	int ret = 0;
	int ret_2 = 0;
	int i = 0;
	struct nbl_profile_assoc_graph *asso_graph = NULL;
	struct nbl_profile_offload_msg prof_off_msg = { 0 };
	u8 cur_stage = 0;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	act->next_stg_sel = NEXT_STG_SEL_EPRO;
	asso_graph = &tc_flow_mgt->profile_graph[filter->graph_idx];

	for (i = 0; i < NBL_ASSOC_PROFILE_STAGE_NUM; i++) {
		/* pp used to calc ecmp-dphash no need offload flow */
		if (i && asso_graph->profile_id[i] == 0)
			break;

		prof_off_msg.profile_id = asso_graph->profile_id[i];
		prof_off_msg.profile_stage = (u8)i;
		prof_off_msg.pt_cmd =
			tc_flow_mgt->profile_msg[asso_graph->profile_id[i + 1]].pt_cmd;
		cur_stage = tc_flow_mgt->profile_msg[prof_off_msg.profile_id].pp_id;
		if ((i == NBL_ASSOC_PROFILE_STAGE_NUM - 1) || asso_graph->profile_id[i + 1] == 0)
			prof_off_msg.last_stage = true;

		ret = nbl_flow_tab_storage(res_mgt, act, filter,
					   tc_flow_ptr, &prof_off_msg);

		if (ret) {
			nbl_info(common, NBL_DEBUG_FLOW,
				 "tc flow hw tab storage failed, ret %d.\n", ret);
			goto fail_flow_tab;
		}
	}

	return ret;

fail_flow_tab:
	for (i = prof_off_msg.profile_stage; i >= 0; i--) {
		struct nbl_flow_tab_filter *flow_tab_node =
			tc_flow_ptr->profile_rule[i];
		if (!flow_tab_node)
			continue;

		tc_flow_ptr->profile_rule[i] = NULL;
		ret_2 |= nbl_rmv_flow_tab_filter(res_mgt,
						 &flow_tab_node->key, true,
						 false,
						 asso_graph->profile_id[i]);
		if (ret_2 != 0 && ret_2 != -ENONET) {
			nbl_err(common, NBL_DEBUG_FLOW,
				"tc flow hw del failed when flow table storage failed. tnl_flag %d, ret_2 %d.\n",
				filter->input.tnl_flag, ret_2);
			return ret_2;
		}
	}
	return ret;
}

/**
 * @brief: nbl_profile_assoc_graph_lookup
 * @return:
 *     true : find
 *     false : not found
 */
static bool nbl_flow_assoc_graph_lookup(struct nbl_resource_mgt *res_mgt,
					struct nbl_flow_pattern_conf *filter)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	u8 i = 0;

	if (filter->key_flag == 0)
		return false;

	for (i = 0; i < NBL_ASSOC_PROFILE_GRAPH_NUM; i++) {
		if (tc_flow_mgt->profile_graph[i].key_flag == 0)
			continue;

		if ((tc_flow_mgt->profile_graph[i].key_flag & ~NBL_FLOW_KEY_TABLE_IDX_FLAG) ==
		    (tc_flow_mgt->profile_graph[i].key_flag & filter->key_flag)) {
			filter->graph_idx = i;
			return true;
		}
	}

	return false;
}

static int nbl_flow_tc_encap_tbl_uninit(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);

	nbl_common_remove_hash_table(tc_flow_mgt->encap_tbl.flow_tab_hash, NULL);
	tc_flow_mgt->encap_tbl.flow_tab_hash = NULL;

	return 0;
}

/**
 * @brief: destroy nbl_tc_flow of all and action hash-list
 *
 * @param[in] error: error info
 * return int: 0-success other-fail
 */
int nbl_flow_flush(struct nbl_resource_mgt *res_mgt)
{
	int ret = 0;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	if (!nbl_flow_is_available(tc_flow_mgt))
		return -EINVAL;

	mutex_lock(&tc_flow_mgt->flow_lock);

	ret = nbl_flow_flush_hash_list(res_mgt);
	if (ret) {
		mutex_unlock(&tc_flow_mgt->flow_lock);
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow hw flush_hash_list failed %d.\n", ret);
		return -EINVAL;
	}

	mutex_unlock(&tc_flow_mgt->flow_lock);

	mutex_lock(&tc_flow_mgt->encap_tbl_lock);
	nbl_flow_tc_encap_tbl_uninit(res_mgt);
	mutex_unlock(&tc_flow_mgt->encap_tbl_lock);

	return ret;
}

/**
 * @brief: flow_tab_filter hash-list init:
 *
 * @return int: 0-success other-fail.
 */
static int nbl_flow_tab_filter_init(struct nbl_resource_mgt *res_mgt,
				    u8 profile_id)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u32 entries = 0;
	struct nbl_hash_tbl_key tbl_key = {0};

	if (profile_id > NBL_PP2_PROFILE_ID_MAX && profile_id < NBL_ALL_PROFILE_NUM)
		return 0;

	if (profile_id <= NBL_PP0_PROFILE_ID_MAX)
		entries = 0;
	else if (profile_id <= NBL_PP1_PROFILE_ID_MAX)
		entries = NBL_FLOW_TABLE_LEN;
	else if (profile_id <= NBL_PP2_PROFILE_ID_MAX)
		entries = NBL_FLOW_TABLE_LEN * 8;
	else
		entries = 0;

	if (!entries)
		return  -EINVAL;

	/* hash_buck is 2-bytes wide, update it if needed */
	entries = entries >= 0xffff ? 0xffff : entries;
	NBL_HASH_TBL_KEY_INIT(&tbl_key, NBL_COMMON_TO_DEV(common), sizeof(struct nbl_flow_tab_conf),
			      sizeof(struct nbl_flow_tab_filter), entries, false);
	tc_flow_mgt->flow_tab_hash[profile_id].flow_tab_hash =
					nbl_common_init_hash_table(&tbl_key);
	if (!tc_flow_mgt->flow_tab_hash[profile_id].flow_tab_hash)
		return -EINVAL;

	nbl_info(common, NBL_DEBUG_FLOW, "tc flow init profile:%u with %u entries",
		 profile_id, entries);

	return 0;
}

static int nbl_flow_tc_encap_tbl_init(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	struct nbl_hash_tbl_key tbl_key = {0};

	NBL_HASH_TBL_KEY_INIT(&tbl_key, NBL_COMMON_TO_DEV(common), sizeof(struct nbl_encap_key),
			      sizeof(struct nbl_encap_entry), NBL_TC_ENCAP_TBL_DEPTH, false);
	tc_flow_mgt->encap_tbl.flow_tab_hash = nbl_common_init_hash_table(&tbl_key);
	if (!tc_flow_mgt->encap_tbl.flow_tab_hash)
		return -EINVAL;

	mutex_init(&tc_flow_mgt->encap_tbl_lock);

	return 0;
}

static int nbl_flow_pp1_ht0_tbl_hash_init(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	tc_flow_mgt->pp1_ht0_mng.hash_map =
		devm_kzalloc(common->dev,
			     sizeof(struct nbl_flow_pp_ht_tbl *) * NBL_FEM_HT_PP1_LEN, GFP_KERNEL);
	if (!tc_flow_mgt->pp1_ht0_mng.hash_map)
		return -ENOMEM;

	return 0;
}

static void
nbl_flow_pp1_ht0_tbl_hash_uninit(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	devm_kfree(common->dev, tc_flow_mgt->pp1_ht0_mng.hash_map);
	tc_flow_mgt->pp1_ht0_mng.hash_map = NULL;
}

static int nbl_flow_pp1_ht1_tbl_hash_init(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	tc_flow_mgt->pp1_ht1_mng.hash_map =
		devm_kzalloc(common->dev,
			     sizeof(struct nbl_flow_pp_ht_tbl *) * NBL_FEM_HT_PP1_LEN, GFP_KERNEL);
	if (!tc_flow_mgt->pp1_ht1_mng.hash_map)
		return -ENOMEM;

	return 0;
}

static void
nbl_flow_pp1_ht1_tbl_hash_uninit(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	devm_kfree(common->dev, tc_flow_mgt->pp1_ht1_mng.hash_map);
	tc_flow_mgt->pp1_ht1_mng.hash_map = NULL;
}

static int nbl_flow_pp2_ht0_tbl_hash_init(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	tc_flow_mgt->pp2_ht0_mng.hash_map =
		devm_kzalloc(common->dev,
			     sizeof(struct nbl_flow_pp_ht_tbl *) * NBL_FEM_HT_PP2_LEN, GFP_KERNEL);
	if (!tc_flow_mgt->pp2_ht0_mng.hash_map)
		return -ENOMEM;

	return 0;
}

static void
nbl_flow_pp2_ht0_tbl_hash_uninit(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	devm_kfree(common->dev, tc_flow_mgt->pp2_ht0_mng.hash_map);
	tc_flow_mgt->pp2_ht0_mng.hash_map = NULL;
}

static int nbl_flow_pp2_ht1_tbl_hash_init(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	tc_flow_mgt->pp2_ht1_mng.hash_map =
		devm_kzalloc(common->dev,
			     sizeof(struct nbl_flow_pp_ht_tbl *) * NBL_FEM_HT_PP2_LEN, GFP_KERNEL);
	if (!tc_flow_mgt->pp2_ht1_mng.hash_map)
		return -ENOMEM;

	return 0;
}

static void
nbl_flow_pp2_ht1_tbl_hash_uninit(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	devm_kfree(common->dev, tc_flow_mgt->pp2_ht1_mng.hash_map);
	tc_flow_mgt->pp2_ht1_mng.hash_map = NULL;
}

struct nbl_flow_pp_ht_tbl *
nbl_pp_ht_lookup(struct nbl_flow_pp_ht_mng *pp_ht_mng, u16 hash_value,
		 struct nbl_flow_pp_ht_key *pp_ht_key)
{
	struct nbl_flow_pp_ht_tbl *node = NULL;
	u16 i;
	bool is_find = false;

	if (!pp_ht_mng || !pp_ht_key)
		return NULL;

	node = pp_ht_mng->hash_map[hash_value];

	if (node) {
		for (i = 0; i < NBL_HASH_CFT_MAX; i++) {
			if (!memcmp(pp_ht_key, &node->key[i], sizeof(node->key[i]))) {
				is_find = true;
				break;
			}
		}
	}

	if (is_find)
		return node;

	return NULL;
}

int nbl_insert_pp_ht(struct nbl_resource_mgt *res_mgt,
		     struct nbl_flow_pp_ht_mng *pp_ht_mng, u16 hash_value0,
		     u16 hash_value1, u32 key_index)
{
	struct nbl_flow_pp_ht_tbl *node;

	if (!pp_ht_mng)
		return -EINVAL;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	node->key[0].vid = 1;
	node->key[0].ht_other_index = hash_value1;
	node->key[0].kt_index = key_index;
	node->ref_cnt = 1;

	pp_ht_mng->hash_map[hash_value0] = node;

	return 0;
}

int nbl_delete_pp_ht(struct nbl_resource_mgt *res_mgt,
		     struct nbl_flow_pp_ht_mng *pp_ht_mng,
		     struct nbl_flow_pp_ht_tbl *node, u16 hash_value0,
		     u16 hash_value1, u32 key_index)
{
	u16 i;
	int ret = 0;
	bool is_delete = false;

	if (!pp_ht_mng || !node)
		return -EINVAL;

	if (node->ref_cnt > NBL_FLOW_TAB_ONE_TIME) {
		for (i = 0; i < NBL_HASH_CFT_MAX; i++) {
			if (node->key[i].ht_other_index == hash_value1 &&
			    node->key[i].kt_index == key_index) {
				node->key[i].vid = 0;
				node->key[i].ht_other_index = 0;
				node->key[i].kt_index = 0;
				node->ref_cnt = node->ref_cnt - 1;

				is_delete = true;
				break;
			}
		}
	} else {
		pp_ht_mng->hash_map[hash_value0] = NULL;
		kfree(node);
		node = NULL;

		is_delete = true;
	}

	if (is_delete)
		return ret;

	return -ENODEV;
}

bool nbl_pp_ht0_ht1_search(struct nbl_flow_pp_ht_mng *pp_ht0_mng, u16 ht0_hash,
			   struct nbl_flow_pp_ht_mng *pp_ht1_mng, u16 ht1_hash)
{
	struct nbl_flow_pp_ht_tbl *node0 = NULL;
	struct nbl_flow_pp_ht_tbl *node1 = NULL;
	u16 i = 0;
	bool is_find = false;

	if (!pp_ht0_mng || !pp_ht1_mng)
		return is_find;

	node0 = pp_ht0_mng->hash_map[ht0_hash];

	if (node0)
		for (i = 0; i < NBL_HASH_CFT_MAX; i++)
			if (node0->key[i].vid &&
			    node0->key[i].ht_other_index == ht1_hash) {
				is_find = true;
				return is_find;
			}

	node1 = pp_ht1_mng->hash_map[ht1_hash];

	if (node1)
		for (i = 0; i < NBL_HASH_CFT_MAX; i++)
			if (node1->key[i].vid &&
			    node1->key[i].ht_other_index == ht0_hash) {
				is_find = true;
				return is_find;
			}

	return is_find;
}

static int nbl_flow_pp_at_tbl_init(struct nbl_resource_mgt *res_mgt)
{
	u32 i;
	u32 j;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_index_tbl_key tbl_key;
	u32 at_idx_num[NBL_PP_TYPE_MAX][NBL_AT_TYPE_MAX] = {
		{0, 0, 0},
		{0, NBL_FEM_AT_PP1_LEN, NBL_FEM_AT2_PP1_LEN},
		{0, NBL_FEM_AT_PP2_LEN, NBL_FEM_AT2_PP2_LEN },
	};

	for (i = 0; i < NBL_PP_TYPE_MAX; i++) {
		for (j = 0; j < NBL_AT_TYPE_MAX; j++) {
			if (!at_idx_num[i][j])
				continue;

			NBL_INDEX_TBL_KEY_INIT(&tbl_key, NBL_COMMON_TO_DEV(common), 0,
					       at_idx_num[i][j],
					       sizeof(struct nbl_flow_pp_at_key));
			tc_flow_mgt->at_mng.at_tbl[i][j] = nbl_common_init_index_table(&tbl_key);
			if (!tc_flow_mgt->at_mng.at_tbl[i][j])
				return -ENOMEM;
		}
	}

	return 0;
}

static void nbl_flow_pp_at_tbl_uninit(struct nbl_resource_mgt *res_mgt)
{
	u32 i;
	u32 j;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);

	for (i = 0; i < NBL_PP_TYPE_MAX; i++) {
		for (j = 0; j < NBL_AT_TYPE_MAX; j++) {
			nbl_common_remove_index_table(tc_flow_mgt->at_mng.at_tbl[i][j], NULL);
			tc_flow_mgt->at_mng.at_tbl[i][j] = NULL;
		}
	}
}

int nbl_pp_at_lookup(struct nbl_resource_mgt *res_mgt, u8 pp_type, u8 at_type,
		     struct nbl_flow_pp_at_key *act_key, struct nbl_flow_at_tbl **act_node)
{
	int idx;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	void *at_tbl = tc_flow_mgt->at_mng.at_tbl[pp_type][at_type];
	struct nbl_index_key_extra extra_key;

	NBL_INDEX_EXTRA_KEY_INIT(&extra_key, 0, 0, true);
	idx = nbl_common_get_index_with_data(at_tbl, act_key->act, &extra_key, NULL, 0,
					     (void **)act_node);
	return idx;
}

int nbl_insert_pp_at(struct nbl_resource_mgt *res_mgt, u8 pp_type, u8 at_type,
		     struct nbl_flow_pp_at_key *act_key, struct nbl_flow_at_tbl **act_node)
{
	int idx;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	void *at_tbl = tc_flow_mgt->at_mng.at_tbl[pp_type][at_type];
	struct nbl_index_key_extra extra_key;
	struct nbl_flow_at_tbl at_node_tmp;

	NBL_INDEX_EXTRA_KEY_INIT(&extra_key, NBL_FLOW_AT_IDX_NUM, NBL_FLOW_AT_IDX_MULTIPLE, false);
	at_node_tmp.ref_cnt = 1;
	idx = nbl_common_alloc_index(at_tbl, act_key->act, &extra_key, &at_node_tmp,
				     sizeof(struct nbl_flow_at_tbl), (void **)act_node);
	return idx;
}

static int nbl_flow_tcam_init(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);

	memset(tc_flow_mgt->tcam_pp0_key_mng, 0,
	       sizeof(struct nbl_flow_tcam_key_mng) * NBL_FEM_TCAM_MAX_NUM);
	memset(tc_flow_mgt->tcam_pp1_key_mng, 0,
	       sizeof(struct nbl_flow_tcam_key_mng) * NBL_FEM_TCAM_MAX_NUM);
	memset(tc_flow_mgt->tcam_pp2_key_mng, 0,
	       sizeof(struct nbl_flow_tcam_key_mng) * NBL_FEM_TCAM_MAX_NUM);
	memset(tc_flow_mgt->tcam_pp0_ad_mng, 0,
	       sizeof(struct nbl_flow_tcam_ad_mng) * NBL_FEM_TCAM_MAX_NUM);
	memset(tc_flow_mgt->tcam_pp1_ad_mng, 0,
	       sizeof(struct nbl_flow_tcam_ad_mng) * NBL_FEM_TCAM_MAX_NUM);
	memset(tc_flow_mgt->tcam_pp2_ad_mng, 0,
	       sizeof(struct nbl_flow_tcam_ad_mng) * NBL_FEM_TCAM_MAX_NUM);

	return 0;
}

static void nbl_flow_tcam_uninit(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);

	memset(tc_flow_mgt->tcam_pp0_key_mng, 0,
	       sizeof(struct nbl_flow_tcam_key_mng) * NBL_FEM_TCAM_MAX_NUM);
	memset(tc_flow_mgt->tcam_pp1_key_mng, 0,
	       sizeof(struct nbl_flow_tcam_key_mng) * NBL_FEM_TCAM_MAX_NUM);
	memset(tc_flow_mgt->tcam_pp2_key_mng, 0,
	       sizeof(struct nbl_flow_tcam_key_mng) * NBL_FEM_TCAM_MAX_NUM);
	memset(tc_flow_mgt->tcam_pp0_ad_mng, 0,
	       sizeof(struct nbl_flow_tcam_ad_mng) * NBL_FEM_TCAM_MAX_NUM);
	memset(tc_flow_mgt->tcam_pp1_ad_mng, 0,
	       sizeof(struct nbl_flow_tcam_ad_mng) * NBL_FEM_TCAM_MAX_NUM);
	memset(tc_flow_mgt->tcam_pp2_ad_mng, 0,
	       sizeof(struct nbl_flow_tcam_ad_mng) * NBL_FEM_TCAM_MAX_NUM);
}

int nbl_tcam_key_lookup(struct nbl_flow_tcam_key_mng *tcam_pp_key_mng,
			struct nbl_tcam_item *tcam_item, u16 *index)
{
	int ret = 0;
	u16 i;
	bool is_find = false;

	if (!tcam_pp_key_mng || !tcam_item || !index)
		return -EINVAL;

	if (tcam_item->key_mode == NBL_TC_KT_FULL_MODE) {
		for (i = 0; i < NBL_FEM_TCAM_MAX_NUM - 1; i += 2) {
			if (tcam_pp_key_mng[i].item.key_mode != NBL_TC_KT_FULL_MODE)
				continue;
			if (!(memcmp(tcam_pp_key_mng[i].item.key,
				     tcam_item->kt_data.hash_key,
				     sizeof(tcam_item->kt_data.hash_key) / 2) &&
			      memcmp(tcam_pp_key_mng[i + 1].item.key,
				     &tcam_item->kt_data.hash_key[20],
				     sizeof(tcam_item->kt_data.hash_key) / 2))) {
				*index = i;
				is_find = true;
				break;
			}
		}
	} else {
		for (i = 0; i < NBL_FEM_TCAM_MAX_NUM; i++) {
			if (tcam_pp_key_mng[i].item.key_mode != NBL_TC_KT_HALF_MODE)
				continue;
			if (!(memcmp(tcam_pp_key_mng[i].item.key, tcam_item->kt_data.hash_key,
				     sizeof(tcam_item->kt_data.hash_key) / 2))) {
				*index = i;
				is_find = true;
				break;
			}
		}
	}

	if (is_find)
		return ret;

	return -ENODEV;
}

int nbl_insert_tcam_key_ad(struct nbl_common_info *common,
			   struct nbl_flow_tcam_key_mng *tcam_pp_key_mng,
			   struct nbl_flow_tcam_ad_mng *tcam_pp_ad_mng,
			   struct nbl_tcam_item *tcam_item,
			   struct nbl_flow_tcam_ad_item *ad_item,
			   u16 *index)
{
	int ret = 0;
	u16 i = 0;

	bool is_insert = false;

	if (!tcam_pp_key_mng || !tcam_pp_ad_mng || !tcam_item || !ad_item || !index)
		return -EINVAL;

	if (tcam_item->key_mode == NBL_TC_KT_FULL_MODE) {
		for (; i < NBL_FEM_TCAM_MAX_NUM - 1; i += 2) {
			if (!(tcam_pp_key_mng[i].item.key_mode &&
			      tcam_pp_key_mng[i + 1].item.key_mode)) {
				memcpy(tcam_pp_key_mng[i].item.key,
				       tcam_item->kt_data.hash_key,
				       sizeof(tcam_item->kt_data.hash_key) / 2);
				memcpy(tcam_pp_key_mng[i + 1].item.key,
				       &tcam_item->kt_data.hash_key[20],
				       sizeof(tcam_item->kt_data.hash_key) / 2);
				tcam_pp_key_mng[i].item.key_mode = NBL_TC_KT_FULL_MODE;
				tcam_pp_key_mng[i + 1].item.key_mode = NBL_TC_KT_FULL_MODE;
				tcam_pp_key_mng[i].ref_cnt = 1;
				tcam_pp_key_mng[i + 1].ref_cnt = 1;
				tcam_pp_key_mng[i].item.sw_hash_id = tcam_item->sw_hash_id;
				tcam_pp_key_mng[i].item.profile_id = tcam_item->profile_id;

				memcpy(tcam_pp_ad_mng[i].item.action, ad_item->action,
				       sizeof(ad_item->action));

				*index = i;
				is_insert = true;
				nbl_debug(common, NBL_DEBUG_FLOW,
					  "tc flow hw tcam: insert pp%d index=%d,%d\n",
					  tcam_item->pp_type, *index, *index + 1);
				break;
			}
		}
	} else {
		for (; i < NBL_FEM_TCAM_MAX_NUM; i++) {
			if (!tcam_pp_key_mng[i].item.key_mode) {
				memcpy(tcam_pp_key_mng[i].item.key, tcam_item->kt_data.hash_key,
				       sizeof(tcam_item->kt_data.hash_key) / 2);
				tcam_pp_key_mng[i].item.key_mode = NBL_TC_KT_HALF_MODE;
				tcam_pp_key_mng[i].ref_cnt = 1;
				tcam_pp_key_mng[i].item.sw_hash_id =
					tcam_item->sw_hash_id;
				tcam_pp_key_mng[i].item.profile_id =
					tcam_item->profile_id;

				memcpy(tcam_pp_ad_mng[i].item.action, ad_item->action,
				       sizeof(ad_item->action));

				*index = i;
				is_insert = true;
				nbl_debug(common, NBL_DEBUG_FLOW,
					  "tc flow hw tcam: insert pp%d index=%d\n",
					  tcam_item->pp_type, *index);
				break;
			}
		}
	}

	if (is_insert)
		return ret;

	return -ENODEV;
}

int nbl_delete_tcam_key_ad(struct nbl_common_info *common,
			   struct nbl_flow_tcam_key_mng *tcam_pp_key_mng,
			   struct nbl_flow_tcam_ad_mng *tcam_pp_ad_mng,
			   u16 index, u8 key_mode, u8 pp_type)
{
	int ret = 0;

	if (!tcam_pp_key_mng || !tcam_pp_ad_mng)
		return -EINVAL;

	if (key_mode == NBL_TC_KT_FULL_MODE) {
		if (tcam_pp_key_mng[index].ref_cnt > 1) {
			tcam_pp_key_mng[index].ref_cnt--;
			tcam_pp_key_mng[index + 1].ref_cnt--;
			nbl_debug(common, NBL_DEBUG_FLOW,
				  "tc flow hw tcam: ref_cnt-- pp%d index=%d, ref_cnt=%d\n",
				  pp_type, index, tcam_pp_key_mng[index].ref_cnt);
			nbl_debug(common, NBL_DEBUG_FLOW,
				  "tc flow hw tcam: ref_cnt-- pp%d index=%d, ref_cnt=%d\n",
				  pp_type, index + 1,
				  tcam_pp_key_mng[index + 1].ref_cnt);
		} else {
			memset(&tcam_pp_key_mng[index], 0,
			       sizeof(tcam_pp_key_mng[index]));
			memset(&tcam_pp_key_mng[index + 1], 0,
			       sizeof(tcam_pp_key_mng[index + 1]));
			memset(&tcam_pp_ad_mng[index], 0,
			       sizeof(tcam_pp_ad_mng[index]));
			nbl_debug(common, NBL_DEBUG_FLOW,
				  "tc flow hw tcam: delete pp%d index=%d,%d\n",
				  pp_type, index, index + 1);
		}
	} else {
		if (tcam_pp_key_mng[index].ref_cnt > 1) {
			tcam_pp_key_mng[index].ref_cnt--;
			nbl_debug(common, NBL_DEBUG_FLOW,
				  "tc flow hw tcam:ref_cnt-- pp%d index=%d, ref_cnt=%d\n",
				  pp_type, index, tcam_pp_key_mng[index].ref_cnt);
		} else {
			memset(&tcam_pp_key_mng[index], 0,
			       sizeof(tcam_pp_key_mng[index]));
			memset(&tcam_pp_ad_mng[index], 0,
			       sizeof(tcam_pp_ad_mng[index]));
			nbl_debug(common, NBL_DEBUG_FLOW,
				  "tc flow hw tcam: delete pp%d index=%d\n", pp_type, index);
		}
	}

	return ret;
}

static int nbl_flow_mcc_init(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	nbl_tc_mcc_init(&tc_flow_mgt->tc_mcc_mgt, common);

	return 0;
}

static void nbl_tc_flow_set_pedit_res(struct nbl_tc_pedit_res_info *pedit_res)
{
	pedit_res[NBL_FLOW_PED_UMAC_TYPE].pedit_num = NBL_FLOW_TC_PEDIT_MAC;
	pedit_res[NBL_FLOW_PED_UMAC_TYPE].pedit_base_id = NBL_FLOW_TC_PEDIT_MAC_BASE;
	pedit_res[NBL_FLOW_PED_UMAC_TYPE].pedit_key_len = NBL_TC_PEDIT_KEY_LEN;
	pedit_res[NBL_FLOW_PED_UMAC_TYPE].pedit_data_len = sizeof(struct nbl_tc_pedit_entry);

	pedit_res[NBL_FLOW_PED_DMAC_TYPE].pedit_num = NBL_FLOW_TC_PEDIT_MAC;
	pedit_res[NBL_FLOW_PED_DMAC_TYPE].pedit_base_id = NBL_FLOW_TC_PEDIT_MAC_BASE;
	pedit_res[NBL_FLOW_PED_DMAC_TYPE].pedit_key_len = NBL_TC_PEDIT_KEY_LEN;
	pedit_res[NBL_FLOW_PED_DMAC_TYPE].pedit_data_len = sizeof(struct nbl_tc_pedit_entry);

	pedit_res[NBL_FLOW_PED_UIP_TYPE].pedit_num = NBL_FLOW_TC_PEDIT_IP;
	pedit_res[NBL_FLOW_PED_UIP_TYPE].pedit_base_id = NBL_FLOW_TC_PEDIT_IP_BASE;
	pedit_res[NBL_FLOW_PED_UIP_TYPE].pedit_key_len = NBL_TC_PEDIT_KEY_LEN;
	pedit_res[NBL_FLOW_PED_UIP_TYPE].pedit_data_len = sizeof(struct nbl_tc_pedit_entry);

	pedit_res[NBL_FLOW_PED_DIP_TYPE].pedit_num = NBL_FLOW_TC_PEDIT_IP;
	pedit_res[NBL_FLOW_PED_DIP_TYPE].pedit_base_id = NBL_FLOW_TC_PEDIT_IP_BASE;
	pedit_res[NBL_FLOW_PED_DIP_TYPE].pedit_key_len = NBL_TC_PEDIT_KEY_LEN;
	pedit_res[NBL_FLOW_PED_DIP_TYPE].pedit_data_len = sizeof(struct nbl_tc_pedit_entry);

	/* special handle:leonis ipv6 need 2 ped-addr, v4 & v6 could share the same hw-resource */
	pedit_res[NBL_FLOW_PED_UIP_TYPE].pedit_num_h = NBL_FLOW_TC_PEDIT_IP6;
	pedit_res[NBL_FLOW_PED_DIP_TYPE].pedit_num_h = NBL_FLOW_TC_PEDIT_IP6;
}

static int nbl_tc_flow_init_pedit(struct nbl_resource_mgt *res_mgt)
{
	int ret = 0;
	struct nbl_tc_pedit_mgt *pedit_mgt;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);

	/* set pedit cap */
	memset(&tc_flow_mgt->pedit_mgt, 0, sizeof(tc_flow_mgt->pedit_mgt));
	pedit_mgt = &tc_flow_mgt->pedit_mgt;
	nbl_tc_flow_set_pedit_res(pedit_mgt->pedit_res);
	mutex_init(&pedit_mgt->pedit_lock);
	pedit_mgt->common = common;

	/*set pedit hw-resource */
	ret = nbl_tc_pedit_init(common, pedit_mgt->pedit_res, NBL_FLOW_PED_RES_MAX);

	if (ret)
		nbl_info(common, NBL_DEBUG_FLOW, "tc_pedit init failed");
	else
		nbl_info(common, NBL_DEBUG_FLOW, "tc_pedit init success");

	return ret;
}

static void nbl_tc_flow_uninit_pedit(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	int ret = 0;

	ret = nbl_tc_pedit_uninit(tc_flow_mgt->pedit_mgt.pedit_res, NBL_FLOW_PED_RES_MAX);
	if (ret)
		nbl_info(common, NBL_DEBUG_FLOW, "tc_pedit uninit failed");
	else
		nbl_info(common, NBL_DEBUG_FLOW, "tc_pedit uninit success");
}

static struct nbl_flow_info_init flow_info_init_list[] = {
	{ nbl_flow_pp1_ht0_tbl_hash_init },
	{ nbl_flow_pp1_ht1_tbl_hash_init },
	{ nbl_flow_pp2_ht0_tbl_hash_init },
	{ nbl_flow_pp2_ht1_tbl_hash_init },

	{ nbl_flow_tcam_init },
	{ nbl_flow_mcc_init },
	{ nbl_tc_flow_init_pedit },
};

static struct nbl_flow_info_uninit flow_info_uninit_list[] = {
	{ nbl_flow_pp1_ht0_tbl_hash_uninit },
	{ nbl_flow_pp1_ht1_tbl_hash_uninit },
	{ nbl_flow_pp2_ht0_tbl_hash_uninit },
	{ nbl_flow_pp2_ht1_tbl_hash_uninit },

	{ nbl_flow_tcam_uninit },
	{ nbl_tc_flow_uninit_pedit },
};

static int nbl_flow_info_init_list(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	u32 idx = 0;
	u8 profile_id = 0;
	struct nbl_profile_msg *profile_msg = NULL;
	struct nbl_flow_prf_data *prf_info = NULL;
	u32 item_cnt = 0;
	int ret = 0;
	u8 p_id = NBL_FLOW_PROFILE_START;

	for (profile_id = p_id; profile_id < NBL_ALL_PROFILE_NUM; profile_id++) {
		profile_msg = &tc_flow_mgt->profile_msg[profile_id];
		if (profile_msg->key_len != 0) {
			ret = nbl_flow_tab_filter_init(res_mgt, profile_id);
			if (ret)
				return ret;
		}

		if (profile_msg->need_upcall && !profile_msg->pt_cmd &&
		    profile_id < NBL_PP_STAGE_PROFILE_NUM) {
			prf_info = &tc_flow_mgt->prf_info.prf_data[item_cnt];
			prf_info->pp_id = profile_msg->pp_id;
			prf_info->prf_id = profile_msg->profile_id;
			++item_cnt;
		}
	}
	tc_flow_mgt->prf_info.item_cnt = item_cnt;

	for (; idx < ARRAY_SIZE(flow_info_init_list); idx++) {
		ret = flow_info_init_list[idx].init_func(res_mgt);
		if (ret)
			return ret;
	}

	ret = nbl_flow_pp_at_tbl_init(res_mgt);
	if (ret)
		return ret;

	ret = nbl_flow_tc_encap_tbl_init(res_mgt);

	return ret;
}

void nbl_flow_info_uninit_list(struct nbl_resource_mgt *res_mgt)
{
	u32 idx;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);

	mutex_lock(&tc_flow_mgt->flow_lock);
	for (idx = 0; idx < ARRAY_SIZE(flow_info_uninit_list); idx++)
		flow_info_uninit_list[idx].uninit_func(res_mgt);

	nbl_flow_pp_at_tbl_uninit(res_mgt);
	mutex_unlock(&tc_flow_mgt->flow_lock);
}

static int nbl_tc_flow_resource_init(struct nbl_resource_mgt *res_mgt)
{
	int ret = 0;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	mutex_init(&tc_flow_mgt->flow_lock);

	ret = nbl_flow_info_init_list(res_mgt);
	if (ret) {
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow hw info init failed.\n");
		goto flow_info_init_failed;
	}

	nbl_info(common, NBL_DEBUG_FLOW, "tc flow hw resource init success\n");

	return ret;

flow_info_init_failed:
	nbl_flow_info_uninit_list(res_mgt);
	return ret;
}

static int nbl_flow_resource_free(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);

	nbl_flow_flush(res_mgt);

	nbl_flow_info_uninit_list(res_mgt);

	kfree(tc_flow_mgt->parse_info);
	tc_flow_mgt->parse_info = NULL;

	return 0;
}

static int nbl_leonis_tc_flow_set_in_port_info(struct nbl_tc_flow_param *param,
					       struct nbl_flow_pattern_conf *filter)
{
	switch (param->in.type) {
	case NBL_TC_PORT_TYPE_VSI:
		filter->input.port = param->in.id | NBL_FLOW_IN_PORT_TYPE_VSI;
		break;
	case NBL_TC_PORT_TYPE_ETH:
		filter->input.port = param->in.id;
		break;
	case NBL_TC_PORT_TYPE_BOND:
		filter->input.port = param->in.id | NBL_FLOW_IN_PORT_TYPE_LAG;
		break;
	default:
		nbl_err(param->common, NBL_DEBUG_FLOW, "tc flow invalid in_port type:%d\n",
			param->in.type);
		return -EINVAL;
	}

	nbl_debug(param->common, NBL_DEBUG_FLOW, "tc flow set in_port info: type:%d, port:%u\n",
		  param->in.type, filter->input.port);

	return 0;
}

static int nbl_leonis_tc_flow_set_out_port_info(struct nbl_tc_flow_param *param,
						struct nbl_rule_action *rule_act)
{
	/* special process bond and eth when not encap */
	if (!param->encap) {
		switch (param->out.type) {
		case NBL_TC_PORT_TYPE_VSI:
			rule_act->port_id = param->out.id;
			break;
		case NBL_TC_PORT_TYPE_ETH:
			rule_act->port_id = param->out.id | NBL_FLOW_OUT_PORT_TYPE_ETH;
			rule_act->vlan.port_id = param->out.id + NBL_VLAN_TYPE_ETH_BASE;
			break;
		case NBL_TC_PORT_TYPE_BOND:
			rule_act->port_id = (param->out.id << 2) | NBL_FLOW_OUT_PORT_TYPE_LAG;
			rule_act->vlan.port_id = param->out.id;
			break;
		default:
			nbl_err(param->common, NBL_DEBUG_FLOW, "tc flow invalid out_port type:%d, param->in.type:%d, encap:%u.\n",
				param->out.type, param->in.type, param->encap);
			return -EINVAL;
		}
	}

	nbl_debug(param->common, NBL_DEBUG_FLOW,
		  "tc flow set out_port info: type:%d, port:%u, encap:%u.\n",
		  param->out.type, rule_act->port_id, param->encap);

	return 0;
}

static int nbl_tc_flow_set_parse_info(struct nbl_tc_flow_mgt *tc_flow_mgt)
{
	tc_flow_mgt->parse_info = kzalloc(sizeof(*tc_flow_mgt->parse_info), GFP_KERNEL);
	if (!tc_flow_mgt->parse_info)
		return -ENOMEM;

	tc_flow_mgt->parse_info->set_in_port_info = nbl_leonis_tc_flow_set_in_port_info;
	tc_flow_mgt->parse_info->set_out_port_info = nbl_leonis_tc_flow_set_out_port_info;

	memset(tc_flow_mgt->parse_info->key_parse_info, 0,
	       sizeof(tc_flow_mgt->parse_info->key_parse_info));
	memset(tc_flow_mgt->parse_info->act_parse_info, 0,
	       sizeof(tc_flow_mgt->parse_info->act_parse_info));

	return 0;
}

/**
 * @brief: init flow tab all resource
 *
 * @param[in] dev: the dev resource
 * @return  void
 *
 * the list of function is as follows:
 * 1. init nbl_tc_flow list resource
 * 2. init all kinds of key template resource
 * 3. init action resource
 * 4. init counter resource
 */
static int nbl_tc_flow_init(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	int ret = 0;

	tc_flow_mgt->res_mgt = res_mgt;
	nbl_flow_clean_create_destroy_cnt(tc_flow_mgt);

	if (nbl_flow_is_resource_ready(tc_flow_mgt))
		return ret;

	tc_flow_mgt->profile_graph_count = g_profile_graph_count;
	memcpy(tc_flow_mgt->profile_msg, g_prf_msg,
	       sizeof(struct nbl_profile_msg) * NBL_ALL_PROFILE_NUM);
	memcpy(tc_flow_mgt->profile_graph, g_prf_graph,
	       sizeof(struct nbl_profile_assoc_graph) * NBL_ASSOC_PROFILE_GRAPH_NUM);

	nbl_tc_flow_set_parse_info(tc_flow_mgt);

	ret = nbl_tc_flow_resource_init(res_mgt);
	if (ret == 0) {
		nbl_flow_set_resource_init_status(tc_flow_mgt, true);
		nbl_flow_resource_available(tc_flow_mgt);
	} else {
		return ret;
	}

	/* not available still now, depends on mbx */
	return ret;
}

/**
 * @brief: uninit flow tab all resource
 *
 * @param[in] dev: the dev resource
 * @return  void
 */
static void nbl_flow_fini(struct nbl_resource_mgt *res_mgt, bool available)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);

	if (!nbl_flow_is_resource_ready(tc_flow_mgt))
		return;

	if (available) {
		nbl_flow_resource_free(res_mgt);
		kfree(tc_flow_mgt->parse_info);
		tc_flow_mgt->parse_info = NULL;
	}

	nbl_flow_set_resource_init_status(tc_flow_mgt, false);
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

static int nbl_tc_flow_add_tc_flow(void *priv, struct nbl_tc_flow_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	int ret = 0;
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

	param->filter.input.dir = (param->act.flag & NBL_FLOW_ACTION_EGRESS);

	tc_flow_ptr = nbl_tc_flow_insert_index(res_mgt, &param->key);
	if (!tc_flow_ptr) {
		nbl_err(common, NBL_DEBUG_FLOW,
			"tc flow hw index=%llx add failed!\n", param->key.cookie);
		ret = -EINVAL;
		goto flow_idx_err;
	}

	tc_flow_ptr->flow_stat_id = nbl_fc_add_stats_leonis(priv, NBL_FC_COMMON_TYPE,
							    param->key.cookie);
	if (tc_flow_ptr->flow_stat_id < 0) {
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow hw failed to add a counter.\n");
		ret = -EINVAL;
		goto stats_out;
	} else {
		param->act.counter_id = tc_flow_ptr->flow_stat_id;
		param->act.flag |= NBL_FLOW_ACTION_COUNTER;
	}

	if (!nbl_flow_assoc_graph_lookup(res_mgt, &param->filter)) {
		nbl_info(common, NBL_DEBUG_FLOW, "tc flow hw can not find graph, key_flag:0x%llx.\n",
			 param->filter.key_flag);
		ret = -EINVAL;
		goto out;
	}

	ret = nbl_flow_tab_storage_entr(res_mgt, tc_flow_ptr,
					&param->filter, &param->act);

	if (ret)
		goto out;
	atomic64_inc(&tc_flow_mgt->create_num);
	tc_flow_ptr->act_flags = param->act.flag;
	if (param->act.flag & NBL_FLOW_ACTION_TUNNEL_ENCAP) {
		tc_flow_ptr->encap_key = kzalloc(sizeof(*tc_flow_ptr->encap_key), GFP_KERNEL);
		if (!tc_flow_ptr->encap_key) {
			ret = -ENOMEM;
			goto out;
		}
		memcpy(tc_flow_ptr->encap_key, &param->act.encap_key, sizeof(param->act.encap_key));
	}

	if (NBL_TC_PEDIT_GET_NODE_RES_VAL(param->act.tc_pedit_info.pedit_node))
		tc_flow_ptr->pedit_node = param->act.tc_pedit_info.pedit_node;

	return ret;

out:
	nbl_fc_del_stats_leonis(priv, param->key.cookie);
	if (NBL_TC_PEDIT_GET_NODE_RES_VAL(param->act.tc_pedit_info.pedit_node))
		nbl_tc_pedit_del_node(&tc_flow_mgt->pedit_mgt,
				      &param->act.tc_pedit_info.pedit_node);
stats_out:
	nbl_tc_flow_delete_index(res_mgt, &param->key);
flow_idx_err:
	return ret;
}

static int nbl_tc_flow_del_edit_act(struct nbl_resource_mgt *res_mgt,
				    struct nbl_tc_flow *tc_flow_node)
{
	int ret = 0;
	struct nbl_tc_pedit_node_res *pedit_node = &tc_flow_node->pedit_node;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	if (tc_flow_node->act_flags & NBL_FLOW_ACTION_TUNNEL_ENCAP) {
		ret = nbl_tc_tun_encap_del(res_mgt, tc_flow_node->encap_key);
		kfree(tc_flow_node->encap_key);
	}

	if (NBL_TC_PEDIT_GET_NODE_RES_VAL(*pedit_node)) {
		ret = nbl_tc_pedit_del_node(&tc_flow_mgt->pedit_mgt, pedit_node);
		if (ret)
			nbl_err(common, NBL_DEBUG_FLOW, "del tc_pedit node error");
	}

	return ret;
}

static void nbl_tc_flow_del_filter_tbl(struct nbl_resource_mgt *res_mgt,
				       struct nbl_tc_flow *tc_flow_node)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	int ret = 0;
	u8 i = 0;
	bool last_stage = false;
	struct nbl_flow_tab_filter *flow_tab_node;

	for (i = 0; i < NBL_PP_PROFILE_STAGE_NUM; i++) {
		flow_tab_node = tc_flow_node->profile_rule[i];
		if (!flow_tab_node)
			continue;

		if (i && tc_flow_node->profile_id[i] == 0)
			break;

		if (tc_flow_mgt->profile_msg[tc_flow_node->profile_id[i]].key_flag == 0)
			break;

		if (i == (NBL_ASSOC_PROFILE_STAGE_NUM - 1) ||
		    tc_flow_node->profile_id[i + 1] == 0)
			last_stage = true;

		if (tc_flow_mgt->profile_msg[tc_flow_node->profile_id[i]].g_profile_id <
		    NBL_PP_STAGE_PROFILE_NUM) {
			ret |= nbl_rmv_flow_tab_filter(res_mgt, &flow_tab_node->key,
						true, last_stage, tc_flow_node->profile_id[i]);
		}

		if (ret != 0 && ret != -ENONET) {
			nbl_err(common, NBL_DEBUG_FLOW,
				"tc flow hw del failed ret %d.\n", ret);
			return;
		}
	}

	/* del actions */
	ret = nbl_tc_flow_del_edit_act(res_mgt, tc_flow_node);
	if (ret)
		nbl_err(common, NBL_DEBUG_FLOW,
			"tc flow del edit action failed ret %d.\n", ret);
}

static int nbl_tc_flow_del_tc_flow(void *priv, struct nbl_tc_flow_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	int ret = 0;
	struct nbl_tc_flow *tc_flow_node = NULL;

	if (!tc_flow_mgt) {
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow hw del tc_flow_mgt is null.\n");
		return -EINVAL;
	}

	if (!nbl_flow_is_available(tc_flow_mgt)) {
		nbl_err(common, NBL_DEBUG_FLOW,
			"tc flow hw resource unavailable.\n");
		return -EINVAL;
	}

	nbl_fc_del_stats_leonis(priv, param->key.cookie);
	tc_flow_node = nbl_tc_flow_index_lookup(res_mgt, &param->key);
	if (!tc_flow_node) {
		nbl_debug(common, NBL_DEBUG_FLOW,
			  "tc flow hw cookie=%llx not exist to del tc flow!\n",
			  param->key.cookie);
		return -ENOENT;
	}

	nbl_tc_flow_del_filter_tbl(res_mgt, tc_flow_node);
	ret = nbl_tc_flow_delete_index(res_mgt, &param->key);
	if (ret)
		nbl_info(common, NBL_DEBUG_FLOW, "tc flow hw del tc-flow-list failed.\n");
	else
		atomic64_inc(&tc_flow_mgt->destroy_num);

	return ret;
}

static void nbl_tc_flow_node_del_action_func(void *priv, int index, void *data)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_tc_flow *flow_node;
	struct nbl_flow_index_key *flow_key = (struct nbl_flow_index_key *)data;

	flow_node = (struct nbl_tc_flow *)((u8 *)flow_key + sizeof(struct nbl_flow_index_key));
	nbl_fc_del_stats_leonis(priv, flow_key->cookie);
	nbl_tc_flow_del_filter_tbl(res_mgt, flow_node);
	atomic64_inc(&tc_flow_mgt->destroy_num);
}

int nbl_tc_flow_flush_flow(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt *tc_flow_mgt = NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);
	struct nbl_index_tbl_scan_key scan_key;

	NBL_INDEX_TBL_SCAN_KEY_INIT(&scan_key, true, res_mgt, &nbl_tc_flow_node_del_action_func);
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

/* Structure starts here, adding an op should not modify anything below */
static int nbl_tc_flow_setup_mgt(struct device *dev, struct nbl_tc_flow_mgt **tc_flow_mgt)
{
	struct nbl_index_tbl_key flow_idx_tbl_key;

	*tc_flow_mgt = devm_kzalloc(dev, sizeof(struct nbl_tc_flow_mgt), GFP_KERNEL);
	if (!*tc_flow_mgt)
		return -ENOMEM;

	NBL_INDEX_TBL_KEY_INIT(&flow_idx_tbl_key, dev, 0, NBL_FLOW_INDEX_LEN,
			       sizeof(struct nbl_flow_index_key));
	(*tc_flow_mgt)->flow_idx_tbl = nbl_common_init_index_table(&flow_idx_tbl_key);
	if (!(*tc_flow_mgt)->flow_idx_tbl)
		return -ENOMEM;

	return 0;
}

static void nbl_tc_flow_remove_mgt(struct device *dev, struct nbl_tc_flow_mgt **tc_flow_mgt)
{
	nbl_common_remove_index_table((*tc_flow_mgt)->flow_idx_tbl, NULL);
	devm_kfree(dev, *tc_flow_mgt);
	*tc_flow_mgt = NULL;
}

int nbl_tc_flow_mgt_start_leonis(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_tc_flow_mgt **tc_flow_mgt;
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	int ret = 0;

	tc_flow_mgt = &NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);

	ret = nbl_tc_flow_setup_mgt(dev, tc_flow_mgt);
	if (ret)
		return ret;
	ret = nbl_tc_flow_init(res_mgt);

	/* init sub-module hw-flow-stats */
	if (!ret)
		return nbl_fc_mgt_start_leonis(res_mgt);
	return ret;
}

void nbl_tc_flow_mgt_stop_leonis(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_tc_flow_mgt **tc_flow_mgt;
	bool available;

	tc_flow_mgt = &NBL_RES_MGT_TO_TC_FLOW_MGT(res_mgt);

	if (!(*tc_flow_mgt))
		return;

	/* Mark resource unavailable first to prevent new stats queries */
	available = nbl_flow_is_available(*tc_flow_mgt);
	nbl_flow_resource_unavailable(*tc_flow_mgt);

	/* Wait for in-flight operations to complete */
	mdelay(NBL_SAFE_THREADS_WAIT_TIME);
	nbl_flow_wait_flows_free_done(*tc_flow_mgt);
	synchronize_rcu();

	nbl_flow_fini(res_mgt, available);
	nbl_fc_mgt_stop_leonis(res_mgt);
	nbl_tc_flow_remove_mgt(dev, tc_flow_mgt);
}

int nbl_tc_flow_setup_ops_leonis(struct nbl_resource_ops *res_ops)
{
	int ret = 0;
#define NBL_TC_FLOW_SET_OPS(name, func) do {res_ops->NBL_NAME(name) = func; ; } while (0)
	NBL_TC_FLOW_OPS_TBL;
#undef  NBL_TC_FLOW_SET_OPS

	ret = nbl_fc_setup_ops_leonis(res_ops);
	if (ret)
		return ret;
	ret = nbl_tc_tun_setup_ops(res_ops);
	return ret;
}

void nbl_tc_flow_remove_ops_leonis(struct nbl_resource_ops *res_ops)
{
#define NBL_TC_FLOW_SET_OPS(name, func) do {res_ops->NBL_NAME(name) = NULL; ; } while (0)
	NBL_TC_FLOW_OPS_TBL;
#undef  NBL_TC_FLOW_SET_OPS

	nbl_fc_remove_ops_leonis(res_ops);
	nbl_tc_tun_remove_ops(res_ops);
}
