/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_PARSE_H_
#define _MCE_PARSE_H_

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
struct mce_fdir_handle;
struct mce_tc_flower_fltr;
enum mce_flow_item_type;
struct mce_lkup_meta;
struct mce_lkup_meta *
mce_parse_get_next_meta(struct mce_tc_flower_fltr *tc_fltr, void *handle,
			u32 *meta_num, bool is_tunnel);
int mce_fd_check_params_valid(struct mce_pf *pf,
			      struct mce_tc_flower_fltr *tc_fltr,
			      struct mce_lkup_meta *meta, int meta_num,
			      bool is_tunnel);
int mce_parse_eth(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		  struct mce_lkup_meta *meta, u64 *inset,
		    u8 *fd_compose, bool is_tunnel);
int mce_parse_enc_eth(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		      struct mce_lkup_meta *meta, u64 *inset,
			u8 *fd_compose, bool is_tunnel);
int mce_parse_vlan(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		   struct mce_lkup_meta *meta, u64 *inset, u8 *fd_compose,
		   bool is_tunnel);
int mce_parse_ip4(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		  struct mce_lkup_meta *meta, u64 *inset,
		    u8 *fd_compose, bool is_tunnel);
int mce_parse_enc_ip4(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		      struct mce_lkup_meta *meta, u64 *inset,
			u8 *fd_compose, bool is_tunnel);
int mce_parse_ip6(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		  struct mce_lkup_meta *meta, u64 *inset,
		    u8 *fd_compose, bool is_tunnel);
int mce_parse_enc_ip6(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		      struct mce_lkup_meta *meta, u64 *inset,
			u8 *fd_compose, bool is_tunnel);
int mce_parse_udp(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		  struct mce_lkup_meta *meta, u64 *inset,
		    u8 *fd_compose, bool is_tunnel);
int mce_parse_enc_udp(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		      struct mce_lkup_meta *meta, u64 *inset,
			u8 *fd_compose, bool is_tunnel);
int mce_parse_tcp(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		  struct mce_lkup_meta *meta, u64 *inset,
		    u8 *fd_compose, bool is_tunnel);
int mce_parse_sctp(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		   struct mce_lkup_meta *meta, u64 *inset,
		     u8 *fd_compose, bool is_tunnel);
int mce_parse_vxlan(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		    struct mce_lkup_meta *meta, u64 *inset,
		      u8 *compose, bool is_tunnel);
int mce_parse_geneve(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		     struct mce_lkup_meta *meta, u64 *inset,
		       u8 *compose, bool is_tunnel);
int mce_parse_nvgre(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		    struct mce_lkup_meta *meta, u64 *inset,
		      u8 *compose, bool is_tunnel);
int mce_parse_gtpc(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		   struct mce_lkup_meta *meta, u64 *inset, u8 *compose,
		     bool is_tunnel);
int mce_parse_gtpu(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		   struct mce_lkup_meta *meta, u64 *inset, u8 *compose,
		     bool is_tunnel);
int mce_parse_esp(struct mce_tc_flower_fltr *tc_fltr, u32 flags,
		  struct mce_lkup_meta *meta, u64 *inset, u8 *compose,
		  bool is_tunnel);
int mce_parse_arfs_eth(struct mce_lkup_meta *meta, const struct flow_keys *fk,
		       u64 *inset, u8 *compose);
int mce_parse_arfs_ip4(struct mce_lkup_meta *meta, const struct flow_keys *fk,
		       u64 *inset, u8 *compose);
int mce_parse_arfs_ip6(struct mce_lkup_meta *meta, const struct flow_keys *fk,
		       u64 *inset, u8 *compose);
int mce_parse_arfs_udp(struct mce_lkup_meta *meta, const struct flow_keys *fk,
		       u64 *inset, u8 *compose);
int mce_parse_arfs_tcp(struct mce_lkup_meta *meta, const struct flow_keys *fk,
		       u64 *inset, u8 *compose);
int mce_compose_init_item_type(u8 **compose);
int mce_compose_deinit_item_type(u8 *compose);
int mce_compose_set_item_type(u8 *compose, enum mce_flow_item_type type);
#endif /* CONFIG_NET_CLS_FLOWER */

#endif
