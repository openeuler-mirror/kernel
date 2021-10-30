/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef UNF_SERVICE_H
#define UNF_SERVICE_H

#include "unf_type.h"
#include "unf_exchg.h"
#include "unf_rport.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

extern u32 max_frame_size;
#define UNF_INIT_DISC 0x1 /* first time DISC */
#define UNF_RSCN_DISC 0x2 /* RSCN Port Addr DISC */
#define UNF_SET_ELS_ACC_TYPE(els_cmd) ((u32)(els_cmd) << 16 | ELS_ACC)
#define UNF_SET_ELS_RJT_TYPE(els_cmd) ((u32)(els_cmd) << 16 | ELS_RJT)
#define UNF_XCHG_IS_ELS_REPLY(xchg)                    \
	((ELS_ACC == ((xchg)->cmnd_code & 0x0ffff)) || \
	 (ELS_RJT == ((xchg)->cmnd_code & 0x0ffff)))

struct unf_els_handle_table {
	u32 cmnd;
	u32 (*els_cmnd_handler)(struct unf_lport *lport, u32 sid, struct unf_xchg *xchg);
};

void unf_select_sq(struct unf_xchg *xchg, struct unf_frame_pkg *pkg);
void unf_fill_package(struct unf_frame_pkg *pkg, struct unf_xchg *xchg,
		      struct unf_rport *rport);
struct unf_xchg *unf_get_sfs_free_xchg_and_init(struct unf_lport *lport,
						u32 did,
						struct unf_rport *rport,
						union unf_sfs_u **fc_entry);
void *unf_get_one_big_sfs_buf(struct unf_xchg *xchg);
u32 unf_mv_resp_2_xchg(struct unf_xchg *xchg, struct unf_frame_pkg *pkg);
void unf_rport_immediate_link_down(struct unf_lport *lport,
				   struct unf_rport *rport);
struct unf_rport *unf_find_rport(struct unf_lport *lport, u32 rport_nport_id,
				 u64 port_name);
void unf_process_logo_in_fabric(struct unf_lport *lport,
				struct unf_rport *rport);
void unf_notify_chip_free_xid(struct unf_xchg *xchg);

u32 unf_ls_gs_cmnd_send(struct unf_lport *lport, struct unf_frame_pkg *pkg,
			struct unf_xchg *xchg);
u32 unf_receive_ls_gs_pkg(void *lport, struct unf_frame_pkg *pkg);
struct unf_xchg *unf_mv_data_2_xchg(struct unf_lport *lport,
				    struct unf_frame_pkg *pkg);
u32 unf_receive_bls_pkg(void *lport, struct unf_frame_pkg *pkg);
u32 unf_send_els_done(void *lport, struct unf_frame_pkg *pkg);
u32 unf_send_els_rjt_by_did(struct unf_lport *lport, struct unf_xchg *xchg,
			    u32 did, struct unf_rjt_info *rjt_info);
u32 unf_send_els_rjt_by_rport(struct unf_lport *lport, struct unf_xchg *xchg,
			      struct unf_rport *rport,
			      struct unf_rjt_info *rjt_info);
u32 unf_send_abts(struct unf_lport *lport, struct unf_xchg *xchg);
void unf_process_rport_after_logo(struct unf_lport *lport,
				  struct unf_rport *rport);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UNF_SERVICE_H__ */
