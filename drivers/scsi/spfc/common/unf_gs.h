/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef UNF_GS_H
#define UNF_GS_H

#include "unf_type.h"
#include "unf_lport.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

u32 unf_send_scr(struct unf_lport *lport,
		 struct unf_rport *rport);
u32 unf_send_ctpass_thru(struct unf_lport *lport,
			 void *buffer, u32 bufflen);

u32 unf_send_gid_ft(struct unf_lport *lport,
		    struct unf_rport *rport);
u32 unf_send_gid_pt(struct unf_lport *lport,
		    struct unf_rport *rport);
u32 unf_send_gpn_id(struct unf_lport *lport,
		    struct unf_rport *sns_port, u32 nport_id);
u32 unf_send_gnn_id(struct unf_lport *lport,
		    struct unf_rport *sns_port, u32 nport_id);
u32 unf_send_gff_id(struct unf_lport *lport,
		    struct unf_rport *sns_port, u32 nport_id);

u32 unf_send_rff_id(struct unf_lport *lport,
		    struct unf_rport *rport, u32 fc4_type);
u32 unf_send_rft_id(struct unf_lport *lport,
		    struct unf_rport *rport);
void unf_rcv_gnn_id_rsp_unknown(struct unf_lport *lport,
				struct unf_rport *sns_port, u32 nport_id);
void unf_rcv_gpn_id_rsp_unknown(struct unf_lport *lport, u32 nport_id);
void unf_rcv_gff_id_rsp_unknown(struct unf_lport *lport, u32 nport_id);
void unf_check_rport_need_delay_plogi(struct unf_lport *lport,
				      struct unf_rport *rport, u32 port_feature);

struct send_com_trans_in {
	unsigned char port_wwn[8];
	u32 req_buffer_count;
	unsigned char req_buffer[ARRAY_INDEX_1];
};

struct send_com_trans_out {
	u32 hba_status;
	u32 total_resp_buffer_cnt;
	u32 actual_resp_buffer_cnt;
	unsigned char resp_buffer[ARRAY_INDEX_1];
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
