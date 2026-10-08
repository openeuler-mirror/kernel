/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */
#ifndef _NBL_TC_FLOW_FILTER_LEONIS_H_
#define _NBL_TC_FLOW_FILTER_LEONIS_H_

#include "nbl_tc_flow_leonis.h"

#define NBL_ACC_HT0				(0)
#define NBL_ACC_HT1				(1)

#define NBL_TC_UPDATE_MAC_OFT(p) ((p) += 2)
#define NBL_TC_UPDATE_IP_OFT(p) ((p) += 4)

struct nbl_flow_offload_ops {
	int (*add)
		(void *ptr,
		 struct nbl_rule_action *act,
		 struct nbl_resource_mgt *res_mgt,
		 struct nbl_flow_idx_info *idx_info);

	int (*del)
		(void *pt,
		struct nbl_resource_mgt *res_mgt,
		 struct nbl_flow_idx_info *idx_info);

	int (*query)
		(void *ptr,
		 u32 idx,
		 void *query_rslt);
};

extern const struct nbl_flow_offload_ops nbl_flow_offload_ops;

struct nbl_flow_action_2hw {
	u64 action_type;
	int (*act_2hw)(struct nbl_rule_action *action, u32 *buf, u16 *item,
		       struct nbl_edit_item *edit_item, struct nbl_resource_mgt *res_mgt);
};

struct nbl_del_action_2hw {
	u64 action_type;
	int (*del_act_2hw)(struct nbl_tc_flow_mgt *tc_flow_mgt,
			   struct nbl_edit_item *edit_item);
};

union nbl_ipv4_tnl_data_u {
	struct nbl_ipv4_tnl_data {
		u32 act0:22;
		u32 act1:22;
		u32 rsv1:16;
		u32 dst_port:16;
		u32 option_class:16;
		u32 option_data:32;
		u32 dst_ip:32;
		u32 template:4;
		u32 rsv[5];
	} __packed info;
#define NBL_IPV4_TNL_DATA_TAB_WIDTH (sizeof(struct nbl_ipv4_tnl_data) \
		/ sizeof(u32))
	u32 data[NBL_IPV4_TNL_DATA_TAB_WIDTH];
	u8 hash_key[sizeof(struct nbl_ipv4_tnl_data)];
} __packed;

union nbl_ipv6_tnl_data_u {
	struct nbl_ipv6_tnl_data {
		u32 act0:22;
		u32 act1:22;
		u32 act2:22;
		u32 act3:22;
		u32 act4:22;
		u32 rsv:14;
		u32 dst_port:16;
		u32 option_class:16;
		u32 option_data:32;
		u64 dst_ipv6_2:64;
		u64 dst_ipv6_1:64;
		u32 template:4;
	} __packed info;
#define NBL_IPV6_TNL_DATA_TAB_WIDTH (sizeof(struct nbl_ipv6_tnl_data) \
		/ sizeof(u32))
	u32 data[NBL_IPV6_TNL_DATA_TAB_WIDTH];
	u8 hash_key[sizeof(struct nbl_ipv6_tnl_data)];
} __packed;

union nbl_l2_tnl_data_u {
	struct nbl_l2_tnl_data {
		u32 act0:22;
		u32 act1:22;
		u32 act2:22;
		u32 act3:22;
		u32 act4:22;
		u32 act5:22;
		u32 act6:22;
		u32 rsv2:6;
		u32 inport:12;
		u32 metadata:16;
		u32 svlan_id:12;
		u32 rsv1:4;
		u32 cvlan_id:12;
		u32 rsv:4;
		u32 ether_type:16;
		u64 dst_mac:48;
		u32 vni:32;
		u32 template:4;
	} __packed info;
#define NBL_L2_TNL_DATA_TAB_WIDTH (sizeof(struct nbl_l2_tnl_data) \
		/ sizeof(u32))
	u32 data[NBL_L2_TNL_DATA_TAB_WIDTH];
	u8 hash_key[sizeof(struct nbl_l2_tnl_data)];
} __packed;

union nbl_l2_notnl_data_u {
	struct nbl_l2_notnl_data {
		u32 act0:22;
		u32 act1:22;
		u32 rsv3:4;
		u32 inport:12;
		u32 svlan_id:12;
		u32 rsv2:4;
		u32 cvlan_id:12;
		u32 rsv1:4;
		u32 ether_type:16;
		u64 dst_mac:48;
		u32 template:4;
		u32 rsv[5];
	} __packed info;
#define NBL_L2_NOTNL_DATA_TAB_WIDTH (sizeof(struct nbl_l2_notnl_data) \
		/ sizeof(u32))
	u32 data[NBL_L2_NOTNL_DATA_TAB_WIDTH];
	u8 hash_key[sizeof(struct nbl_l2_notnl_data)];
} __packed;

union nbl_l3_ipv4_data_u {
	struct nbl_l3_ipv4_data {
		u32 act0:22;
		u32 act1:22;
		u32 act2:22;
		u32 act3:22;
		u32 rsv1:4;
		u32 metadata:16;
		u32 dscp:8;
		u32 ttl:8;
		u32 dst_ip:32;
		u32 template:4;
		u32 rsv[5];
	} __packed info;
#define NBL_L3_IPV4_DATA_TAB_WIDTH (sizeof(struct nbl_l3_ipv4_data) \
		/ sizeof(u32))
	u32 data[NBL_L3_IPV4_DATA_TAB_WIDTH];
	u8 hash_key[sizeof(struct nbl_l3_ipv4_data)];
} __packed;

union nbl_l3_ipv6_data_u {
	struct nbl_l3_ipv6_data {
		u32 act0:22;
		u32 act1:22;
		u32 act2:22;
		u32 act3:22;
		u32 act4:22;
		u32 act5:22;
		u32 act6:22;
		u32 rsv:2;
		u32 metadata:16;
		u32 dscp:8;
		u32 hoplimit:8;
		u64 dst_ipv6_2:64;
		u64 dst_ipv6_1:64;
		u32 template:4;
	} __packed info;
#define NBL_L3_IPV6_DATA_TAB_WIDTH (sizeof(struct nbl_l3_ipv6_data) \
		/ sizeof(u32))
	u32 data[NBL_L3_IPV6_DATA_TAB_WIDTH];
	u8 hash_key[sizeof(struct nbl_l3_ipv6_data)];
} __packed;

union nbl_t5_ipv4_data_u {
	struct nbl_t5_ipv4_data {
		u32 act0:22;
		u32 act1:22;
		u32 rsv1:16;
		u32 metadata:16;
		u32 pad:8;
		u32 proto:8;
		u32 dst_port:16;
		u32 src_port:16;
		u32 src_ip:32;
		u32 template:4;
		u32 rsv[5];
	} __packed info;
#define NBL_T5_IPV4_DATA_TAB_WIDTH (sizeof(struct nbl_t5_ipv4_data) \
		/ sizeof(u32))
	u32 data[NBL_T5_IPV4_DATA_TAB_WIDTH];
	u8 hash_key[sizeof(struct nbl_t5_ipv4_data)];
} __packed;

union nbl_t5_ipv6_data_u {
	struct nbl_t5_ipv6_data {
		u32 act0:22;
		u32 act1:22;
		u32 act2:22;
		u32 act3:22;
		u32 act4:22;
		u32 rsv:14;
		u32 metadata:16;
		u32 pad:8;
		u32 proto:8;
		u32 dst_port:16;
		u32 src_port:16;
		u64 src_ipv6_2:64;
		u64 src_ipv6_1:64;
		u32 template:4;
	} __packed info;
#define NBL_T5_IPV6_DATA_TAB_WIDTH (sizeof(struct nbl_t5_ipv6_data) \
		/ sizeof(u32))
	u32 data[NBL_T5_IPV6_DATA_TAB_WIDTH];
	u8 hash_key[sizeof(struct nbl_t5_ipv6_data)];
} __packed;

#define NBL_FEM_KT_ACC_DATA			(NBL_PPE_FEM_BASE + 0x00000348)

#define NBL_FEM_EM0_TCAM_TABLE_ADDR  (0xa0b000)
#define NBL_FEM_EM_TCAM_TABLE_DEPTH (64)
#define NBL_FEM_EM_TCAM_TABLE_WIDTH (256)
union fem_em_tcam_table_u {
	struct fem_em_tcam_table {
		u32 key[5];              /* [159:0] Default:0x0 RW */
		u32 key_vld:1;           /* [160] Default:0x0 RW */
		u32 key_size:1;          /* [161] Default:0x0 RW */
		u32 rsv:30;              /* [191:162] Default:0x0 RO */
		u32 rsv1[2];              /* [255:192] Default:0x0 RO */
	} __packed info;
	u32 data[NBL_FEM_EM_TCAM_TABLE_WIDTH / 32];
	u8 hash_key[sizeof(struct fem_em_tcam_table)];
} __packed;

#define NBL_FEM_EM_TCAM_TABLE_REG(r, t) (NBL_FEM_EM0_TCAM_TABLE_ADDR + 0x1000 * (r) + \
		(NBL_FEM_EM_TCAM_TABLE_WIDTH / 8) * (t))

#define NBL_FEM_EM0_AD_TABLE_ADDR  (0xa08000)
#define NBL_FEM_EM_AD_TABLE_DEPTH (64)
#define NBL_FEM_EM_AD_TABLE_WIDTH (512)
union fem_em_ad_table_u {
	struct fem_em_ad_table {
		u32 action0:22;          /* [21:0] Default:0x0 RW */
		u32 action1:22;          /* [43:22] Default:0x0 RW */
		u32 action2:22;          /* [65:44] Default:0x0 RW */
		u32 action3:22;          /* [87:66] Default:0x0 RW */
		u32 action4:22;          /* [109:88] Default:0x0 RW */
		u32 action5:22;          /* [131:110] Default:0x0 RW */
		u32 action6:22;          /* [153:132] Default:0x0 RW */
		u32 action7:22;          /* [175:154] Default:0x0 RW */
		u32 action8:22;          /* [197:176] Default:0x0 RW */
		u32 action9:22;          /* [219:198] Default:0x0 RW */
		u32 action10:22;         /* [241:220] Default:0x0 RW */
		u32 action11:22;         /* [263:242] Default:0x0 RW */
		u32 action12:22;         /* [285:264] Default:0x0 RW */
		u32 action13:22;         /* [307:286] Default:0x0 RW */
		u32 action14:22;         /* [329:308] Default:0x0 RW */
		u32 action15:22;         /* [351:330] Default:0x0 RW */
		u32 rsv[5];          /* [511:352] Default:0x0 RO */
	} __packed info;
	u32 data[NBL_FEM_EM_AD_TABLE_WIDTH / 32];
	u8 hash_key[sizeof(struct fem_em_ad_table)];
} __packed;

#define NBL_FEM_EM_AD_TABLE_REG(r, t) (NBL_FEM_EM0_AD_TABLE_ADDR + 0x1000 * (r) + \
		(NBL_FEM_EM_AD_TABLE_WIDTH / 8) * (t))

union nbl_fem_at_acc_data_u {
	struct nbl_fem_at_acc_data {
		u32 at1:22;
		u32 at2:22;
		u32 at3:22;
		u32 at4:22;
		u32 at5:22;
		u32 at6:22;
		u32 at7:22;
		u32 at8:22;
		u32 rsv:16;
	} __packed info;
#define NBL_FEM_AT_ACC_DATA_TBL_WIDTH (sizeof(struct nbl_fem_at_acc_data) \
		/ sizeof(u32))
	u32 data[NBL_FEM_AT_ACC_DATA_TBL_WIDTH];
} __packed;

#define NBL_FEM_AT_ACC_DATA			(NBL_PPE_FEM_BASE + 0x00000398)

union nbl_fem_all_at_data_u {
	struct nbl_fem_all_at_data {
		u32 at1:22;
		u32 at2:22;
		u32 at3:22;
		u32 at4:22;
		u32 at5:22;
		u32 at6:22;
		u32 at7:22;
		u32 at8:22;
		u32 at9:22;
		u32 at10:22;
		u32 at11:22;
		u32 at12:22;
		u32 at13:22;
		u32 at14:22;
		u32 at15:22;
		u32 at16:22;
	} __packed info;
#define NBL_FEM_ALL_AT_DATA_TBL_WIDTH (sizeof(struct nbl_fem_all_at_data) \
		/ sizeof(u32))
	u32 data[NBL_FEM_ALL_AT_DATA_TBL_WIDTH];
} __packed;

union nbl_fem_four_at_data_u {
	struct nbl_fem_four_at_data {
		u32 at1:22;
		u32 at2:22;
		u32 at3:22;
		u32 at4:22;
	} __packed info;
#define NBL_FEM_FOUR_AT_DATA_TBL_WIDTH (sizeof(struct nbl_fem_four_at_data) \
		/ sizeof(u32))
	u32 data[NBL_FEM_FOUR_AT_DATA_TBL_WIDTH];
} __packed;

/* COMMON CRC16 Calc */
u16 nbl_calc_crc16(const u8 *data, u32 size, u16 crc_poly,
		   u16 init_value, u8 ref_flag, u16 xorout);
#define NBL_CRC16_CCITT(data, size) \
			nbl_calc_crc16(data, size, 0x1021, 0x0000, 1, 0x0000)
#define NBL_CRC16_CCITT_FALSE(data, size) \
			nbl_calc_crc16(data, size, 0x1021, 0xFFFF, 0, 0x0000)
#define NBL_CRC16_XMODEM(data, size) \
			nbl_calc_crc16(data, size, 0x1021, 0x0000, 0, 0x0000)
#define NBL_CRC16_IBM(data, size) \
			nbl_calc_crc16(data, size, 0x8005, 0x0000, 1, 0x0000)

/* CMDQ data content for FEM-KT AT */
union nbl_cmd_fem_ktat_u {
	struct nbl_cmd_fem_ktat {
		u32 at_index;
		u8	at_valid:1;
		u8 rsv0:7;
		u8 at_size:8;
		u16 rsv1:16;
		u32 kt_index;
		u8 kt_valid:1;
		u8 rsv2:7;
		u8 kt_size:8;
		u16 rsv3:16;
		u32 at_data[8];
		u32 kt_data[10];
		u32 kt_em:2;
		u32 rsv4:30;
		u32 rsv5[5];
	} __packed info;
#define NBL_CMD_FEM_KTAT_TAB_WIDTH (sizeof(struct nbl_cmd_fem_ktat) \
		/ sizeof(u32))
	u32 data[NBL_CMD_FEM_KTAT_TAB_WIDTH];
} __packed;

#define NBL_CMD_FEM_KT_SIZE (16 + 32)
#define HALF_CMD_DESC_LENGTH 16

union nbl_fem_ht_acc_data_u {
	struct nbl_fem_ht_acc_data {
		u32 kt_index:17;
		u32 hash:14;
		u32 vld:1;
	} __packed info;
#define NBL_FEM_HT_ACC_DATA_TBL_WIDTH (sizeof(struct nbl_fem_ht_acc_data) \
		/ sizeof(u32))
	u32 data[NBL_FEM_HT_ACC_DATA_TBL_WIDTH];
} __packed;

/* CMDQ data content for FEM-HT */
union nbl_cmd_fem_ht_u {
	struct nbl_cmd_fem_ht {
		u32 bucket_id:2;  /* four buckets in the hash entry */
		u32 entry_id:14;  /* hash table entry id  */
		u32 ht_id:1;  /* 0:HT0, 1:HT1 */
		u32 em_id:2;  /* 0:pp0 1:pp1 2 or 3:pp2 */
		u32 rsv:13;
		u8	ht_valid:1;
		u8 rsv0:7;
		u8 rsv1:8;
		u16 rsv2:16;
		u32 kt_index;
		u8 kt_valid:1;
		u8 rsv3:7;
		u8 kt_size:8;
		u16 rsv4:16;
		union nbl_fem_ht_acc_data_u ht_data[4];
		u32 rsv5[4];
		u32 kt_data[10];
		u32 kt_em:2;
		u32 rsv6:30;
		u32 rsv7[5];
	} __packed info;
#define NBL_CMD_FEM_HT_TAB_WIDTH (sizeof(struct nbl_cmd_fem_ht) \
		/ sizeof(u32))
	u32 data[NBL_CMD_FEM_HT_TAB_WIDTH];
} __packed;

/* size macros, all in unit of bytes */
#define NBL_CMDQ_FEM_R_REQ_LEN 16
#define NBL_CMDQ_FEM_W_REQ_LEN 112
#define NBL_CMDQ_FEM_S_REQ_LEN 112
#define NBL_CMDQ_ACL_TCAM_R_REQ_LEN 4
#define NBL_CMDQ_ACL_TCAM_W_REQ_LEN 168
#define NBL_CMDQ_ACL_TCAM_S_REQ_LEN 84
#define NBL_CMDQ_ACL_STAT_BASE_LEN 32
#define NBL_CMDQ_ACL_STAT_ITEM_LEN 12

#define NBL_PPE_KT_FULL_SIZE 40
#define NBL_PPE_KT_HALF_SIZE 20

#endif
