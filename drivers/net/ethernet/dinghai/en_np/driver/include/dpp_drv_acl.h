/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef DPP_DRV_ACL_H
#define DPP_DRV_ACL_H

#include "zxic_common.h"
#include "dpp_apt_se_api.h"
#include "dpp_apt_se.h"

struct zxdh_ipsec_enc_key {
	u8 dip[16];
	u8 sip[16];
	u32 rsv2;
	u32 rsv1;
};

struct zxdh_ipsec_enc_mask {
	u8 dip[16];
	u8 sip[16];
	u32 rsv2;
	u32 rsv1;
};

struct zxdh_ipsec_enc_entry {
	u32 sa_id;
	u32 rsv;
	u32 hit_flag;
};

struct zxdh_ipsec_enc_t {
	u32 index;
	struct zxdh_ipsec_enc_key key;
	struct zxdh_ipsec_enc_mask mask;
	struct zxdh_ipsec_enc_entry entry;
};

struct zxdh_pkt_cap_key {
	u32 rsv;
	u32 qp;
	u16 vhca_id;
	u16 vqm_vfid;
	u16 ethtype;
	u16 sport;
	u16 dport;
	u16 key_word_off;
	u8 protocol;
	u8 key_word_len;
	u8 capture_pkt_flag;
	u8 panel_id;
	u8 sip[16];
	u8 dip[16];
	u8 dmac[6];
	u8 smac[6];
	u8 key_word[15];
};

struct zxdh_pkt_cap_mask {
	u32 rsv_mask;
	u32 qp_mask;
	u16 vhca_id_mask;
	u16 vqm_vfid_mask;
	u16 ethtype_mask;
	u16 sport_mask;
	u16 dport_mask;
	u16 key_word_off_mask;
	u8 protocol_mask;
	u8 key_word_len_mask;
	u8 capture_pkt_flag_mask;
	u8 panel_id_mask;
	u8 sip_mask[16];
	u8 dip_mask[16];
	u8 dmac_mask[6];
	u8 smac_mask[6];
	u8 key_word_mask[15];
};

struct zxdh_pkt_cap_entry {
	u32 vqm_vfid;
	u32 index;
	u32 value_flag;
	u32 hit_flag;
};

struct zxdh_pkt_cap_t {
	u32 index;
	struct zxdh_pkt_cap_key key;
	struct zxdh_pkt_cap_mask mask;
	struct zxdh_pkt_cap_entry entry;
};

u32 dpp_apt_set_ipsec_enc_data(void *pData, struct dpp_acl_entry_ex_t *aclEntry);
u32 dpp_apt_get_ipsec_enc_data(void *pData, struct dpp_acl_entry_ex_t *aclEntry);
u32 dpp_apt_set_pkt_cap_data(void *pData, struct dpp_acl_entry_ex_t *aclEntry);
u32 dpp_apt_get_pkt_cap_data(void *pData, struct dpp_acl_entry_ex_t *aclEntry);

struct se_apt_acl_convert_t *se_acl_callback_get(u32 sdt_no);

#endif
