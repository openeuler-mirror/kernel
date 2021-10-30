/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef UNF_FCSTRUCT_H
#define UNF_FCSTRUCT_H

#include "unf_type.h"
#include "unf_scsi_common.h"

#define FC_RCTL_BLS 0x80000000

/*
 * * R_CTL Basic Link Data defines
 */

#define FC_RCTL_BLS_ACC (FC_RCTL_BLS | 0x04000000)
#define FC_RCTL_BLS_RJT (FC_RCTL_BLS | 0x05000000)

/*
 * * BA_RJT reason code defines
 */
#define FCXLS_BA_RJT_LOGICAL_ERROR 0x00030000

/*
 * * BA_RJT code explanation
 */

#define FCXLS_LS_RJT_INVALID_OXID_RXID 0x00001700

/*
 * * ELS ACC
 */
struct unf_els_acc {
	struct unf_fc_head frame_hdr;
	u32 cmnd;
};

/*
 * * ELS RJT
 */
struct unf_els_rjt {
	struct unf_fc_head frame_hdr;
	u32 cmnd;
	u32 reason_code;
};

/*
 * * FLOGI payload,
 * * FC-LS-2 FLOGI, PLOGI, FDISC or LS_ACC Payload
 */
struct unf_flogi_fdisc_payload {
	u32 cmnd;
	struct unf_fabric_parm fabric_parms;
};

/*
 * * Flogi and Flogi accept frames.  They are the same structure
 */
struct unf_flogi_fdisc_acc {
	struct unf_fc_head frame_hdr;
	struct unf_flogi_fdisc_payload flogi_payload;
};

/*
 * * Fdisc and Fdisc accept frames.  They are the same structure
 */

struct unf_fdisc_acc {
	struct unf_fc_head frame_hdr;
	struct unf_flogi_fdisc_payload fdisc_payload;
};

/*
 * * PLOGI payload
 */
struct unf_plogi_payload {
	u32 cmnd;
	struct unf_lgn_parm stparms;
};

/*
 *Plogi, Plogi accept, Pdisc and Pdisc accept frames.  They are all the same
 *structure.
 */
struct unf_plogi_pdisc {
	struct unf_fc_head frame_hdr;
	struct unf_plogi_payload payload;
};

/*
 * * LOGO logout link service requests invalidation of service parameters and
 * * port name.
 * *   see FC-PH 4.3 Section 21.4.8
 */
struct unf_logo_payload {
	u32 cmnd;
	u32 nport_id;
	u32 high_port_name;
	u32 low_port_name;
};

/*
 * * payload to hold LOGO command
 */
struct unf_logo {
	struct unf_fc_head frame_hdr;
	struct unf_logo_payload payload;
};

/*
 * * payload for ECHO command, refer to FC-LS-2 4.2.4
 */
struct unf_echo_payload {
	u32 cmnd;
#define UNF_FC_ECHO_PAYLOAD_LENGTH 255 /* Length in words */
	u32 data[UNF_FC_ECHO_PAYLOAD_LENGTH];
};

struct unf_echo {
	struct unf_fc_head frame_hdr;
	struct unf_echo_payload *echo_pld;
	dma_addr_t phy_echo_addr;
};

#define UNF_PRLI_SIRT_EXTRA_SIZE 12

/*
 * * payload for PRLI and PRLO
 */
struct unf_prli_payload {
	u32 cmnd;
#define UNF_FC_PRLI_PAYLOAD_LENGTH 7 /* Length in words */
	u32 parms[UNF_FC_PRLI_PAYLOAD_LENGTH];
};

/*
 * * FCHS structure with payload
 */
struct unf_prli_prlo {
	struct unf_fc_head frame_hdr;
	struct unf_prli_payload payload;
};

struct unf_adisc_payload {
	u32 cmnd;
	u32 hard_address;
	u32 high_port_name;
	u32 low_port_name;
	u32 high_node_name;
	u32 low_node_name;
	u32 nport_id;
};

/*
 * * FCHS structure with payload
 */
struct unf_adisc {
	struct unf_fc_head frame_hdr; /* FCHS structure */
	struct unf_adisc_payload
	    adisc_payl; /* Payload data containing ADISC info
			 */
};

/*
 * * RLS payload
 */
struct unf_rls_payload {
	u32 cmnd;
	u32 nport_id; /* in litle endian format */
};

/*
 * * RLS
 */
struct unf_rls {
	struct unf_fc_head frame_hdr; /* FCHS structure */
	struct unf_rls_payload rls;   /* payload data containing the RLS info */
};

/*
 * * RLS accept payload
 */
struct unf_rls_acc_payload {
	u32 cmnd;
	u32 link_failure_count;
	u32 loss_of_sync_count;
	u32 loss_of_signal_count;
	u32 primitive_seq_count;
	u32 invalid_trans_word_count;
	u32 invalid_crc_count;
};

/*
 * * RLS accept
 */
struct unf_rls_acc {
	struct unf_fc_head frame_hdr; /* FCHS structure */
	struct unf_rls_acc_payload
	    rls; /* payload data containing the RLS ACC info
		  */
};

/*
 * * FCHS structure with payload
 */
struct unf_rrq {
	struct unf_fc_head frame_hdr;
	u32 cmnd;
	u32 sid;
	u32 oxid_rxid;
};

#define UNF_SCR_PAYLOAD_CNT 2
struct unf_scr {
	struct unf_fc_head frame_hdr;
	u32 payload[UNF_SCR_PAYLOAD_CNT];
};

struct unf_ctiu_prem {
	u32 rev_inid;
	u32 gstype_gssub_options;
	u32 cmnd_rsp_size;
	u32 frag_reason_exp_vend;
};

#define UNF_FC4TYPE_CNT 8
struct unf_rftid {
	struct unf_fc_head frame_hdr;
	struct unf_ctiu_prem ctiu_pream;
	u32 nport_id;
	u32 fc4_types[UNF_FC4TYPE_CNT];
};

struct unf_rffid {
	struct unf_fc_head frame_hdr;
	struct unf_ctiu_prem ctiu_pream;
	u32 nport_id;
	u32 fc4_feature;
};

struct unf_rffid_rsp {
	struct unf_fc_head frame_hdr;
	struct unf_ctiu_prem ctiu_pream;
};

struct unf_gffid {
	struct unf_fc_head frame_hdr;
	struct unf_ctiu_prem ctiu_pream;
	u32 nport_id;
};

struct unf_gffid_rsp {
	struct unf_fc_head frame_hdr;
	struct unf_ctiu_prem ctiu_pream;
	u32 fc4_feature[32];
};

struct unf_gnnid {
	struct unf_fc_head frame_hdr;
	struct unf_ctiu_prem ctiu_pream;
	u32 nport_id;
};

struct unf_gnnid_rsp {
	struct unf_fc_head frame_hdr;
	struct unf_ctiu_prem ctiu_pream;
	u32 node_name[2];
};

struct unf_gpnid {
	struct unf_fc_head frame_hdr;
	struct unf_ctiu_prem ctiu_pream;
	u32 nport_id;
};

struct unf_gpnid_rsp {
	struct unf_fc_head frame_hdr;
	struct unf_ctiu_prem ctiu_pream;
	u32 port_name[2];
};

struct unf_rft_rsp {
	struct unf_fc_head frame_hdr;
	struct unf_ctiu_prem ctiu_pream;
};

struct unf_ls_rjt_pld {
	u32 srr_op; /* 01000000h */
	u8 vandor;
	u8 reason_exp;
	u8 reason;
	u8 reserved;
};

struct unf_ls_rjt {
	struct unf_fc_head frame_hdr;
	struct unf_ls_rjt_pld pld;
};

struct unf_rec_pld {
	u32 rec_cmnd;
	u32 xchg_org_sid; /* bit0-bit23 */
	u16 rx_id;
	u16 ox_id;
};

struct unf_rec {
	struct unf_fc_head frame_hdr;
	struct unf_rec_pld rec_pld;
};

struct unf_rec_acc_pld {
	u32 cmnd;
	u16 rx_id;
	u16 ox_id;
	u32 org_addr_id; /* bit0-bit23 */
	u32 rsp_addr_id; /* bit0-bit23 */
};

struct unf_rec_acc {
	struct unf_fc_head frame_hdr;
	struct unf_rec_acc_pld payload;
};

struct unf_gid {
	struct unf_ctiu_prem ctiu_pream;
	u32 scope_type;
};

struct unf_gid_acc {
	struct unf_fc_head frame_hdr;
	struct unf_ctiu_prem ctiu_pream;
};

#define UNF_LOOPMAP_COUNT 128
struct unf_loop_init {
	struct unf_fc_head frame_hdr;
	u32 cmnd;
#define UNF_FC_ALPA_BIT_MAP_SIZE 4
	u32 alpha_bit_map[UNF_FC_ALPA_BIT_MAP_SIZE];
};

struct unf_loop_map {
	struct unf_fc_head frame_hdr;
	u32 cmnd;
	u32 loop_map[32];
};

struct unf_ctiu_rjt {
	struct unf_fc_head frame_hdr;
	struct unf_ctiu_prem ctiu_pream;
};

struct unf_gid_acc_pld {
	struct unf_ctiu_prem ctiu_pream;

	u32 gid_port_id[UNF_GID_PORT_CNT];
};

struct unf_gid_rsp {
	struct unf_gid_acc_pld *gid_acc_pld;
};

struct unf_gid_req_rsp {
	struct unf_fc_head frame_hdr;
	struct unf_gid gid_req;
	struct unf_gid_rsp gid_rsp;
};

/* FC-LS-2 Table 31 RSCN Payload */
struct unf_rscn_port_id_page {
	u8 port_id_port;
	u8 port_id_area;
	u8 port_id_domain;

	u8 addr_format : 2;
	u8 event_qualifier : 4;
	u8 reserved : 2;
};

struct unf_rscn_pld {
	u32 cmnd;
	struct unf_rscn_port_id_page port_id_page[UNF_RSCN_PAGE_SUM];
};

struct unf_rscn {
	struct unf_fc_head frame_hdr;
	struct unf_rscn_pld *rscn_pld;
};

union unf_sfs_u {
	struct {
		struct unf_fc_head frame_head;
		u8 data[0];
	} sfs_common;
	struct unf_els_acc els_acc;
	struct unf_els_rjt els_rjt;
	struct unf_plogi_pdisc plogi;
	struct unf_logo logo;
	struct unf_echo echo;
	struct unf_echo echo_acc;
	struct unf_prli_prlo prli;
	struct unf_prli_prlo prlo;
	struct unf_rls rls;
	struct unf_rls_acc rls_acc;
	struct unf_plogi_pdisc pdisc;
	struct unf_adisc adisc;
	struct unf_rrq rrq;
	struct unf_flogi_fdisc_acc flogi;
	struct unf_fdisc_acc fdisc;
	struct unf_scr scr;
	struct unf_rec rec;
	struct unf_rec_acc rec_acc;
	struct unf_ls_rjt ls_rjt;
	struct unf_rscn rscn;
	struct unf_gid_req_rsp get_id;
	struct unf_rftid rft_id;
	struct unf_rft_rsp rft_id_rsp;
	struct unf_rffid rff_id;
	struct unf_rffid_rsp rff_id_rsp;
	struct unf_gffid gff_id;
	struct unf_gffid_rsp gff_id_rsp;
	struct unf_gnnid gnn_id;
	struct unf_gnnid_rsp gnn_id_rsp;
	struct unf_gpnid gpn_id;
	struct unf_gpnid_rsp gpn_id_rsp;
	struct unf_plogi_pdisc plogi_acc;
	struct unf_plogi_pdisc pdisc_acc;
	struct unf_adisc adisc_acc;
	struct unf_prli_prlo prli_acc;
	struct unf_prli_prlo prlo_acc;
	struct unf_flogi_fdisc_acc flogi_acc;
	struct unf_fdisc_acc fdisc_acc;
	struct unf_loop_init lpi;
	struct unf_loop_map loop_map;
	struct unf_ctiu_rjt ctiu_rjt;
};

struct unf_sfs_entry {
	union unf_sfs_u *fc_sfs_entry_ptr; /* Virtual addr of SFS buffer */
	u64 sfs_buff_phy_addr;		   /* Physical addr of SFS buffer */
	u32 sfs_buff_len;		   /* Length of bytes in SFS buffer */
	u32 cur_offset;
};

struct unf_fcp_rsp_iu_entry {
	u8 *fcp_rsp_iu;
	u32 fcp_sense_len;
};

struct unf_rjt_info {
	u32 els_cmnd_code;
	u32 reason_code;
	u32 reason_explanation;
	u8 class_mode;
	u8 ucrsvd[3];
};

#endif
