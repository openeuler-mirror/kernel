/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef UNF_LS_H
#define UNF_LS_H

#include "unf_type.h"
#include "unf_exchg.h"
#include "unf_rport.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

u32 unf_send_adisc(struct unf_lport *lport, struct unf_rport *rport);
u32 unf_send_pdisc(struct unf_lport *lport, struct unf_rport *rport);
u32 unf_send_flogi(struct unf_lport *lport, struct unf_rport *rport);
u32 unf_send_fdisc(struct unf_lport *lport, struct unf_rport *rport);
u32 unf_send_plogi(struct unf_lport *lport, struct unf_rport *rport);
u32 unf_send_prli(struct unf_lport *lport, struct unf_rport *rport,
		  u32 cmnd_code);
u32 unf_send_prlo(struct unf_lport *lport, struct unf_rport *rport);
u32 unf_send_logo(struct unf_lport *lport, struct unf_rport *rport);
u32 unf_send_logo_by_did(struct unf_lport *lport, u32 did);
u32 unf_send_echo(struct unf_lport *lport, struct unf_rport *rport, u32 *time);
u32 unf_send_plogi_rjt_by_did(struct unf_lport *lport, u32 did);
u32 unf_send_rrq(struct unf_lport *lport, struct unf_rport *rport,
		 struct unf_xchg *xchg);
void unf_flogi_ob_callback(struct unf_xchg *xchg);
void unf_flogi_callback(void *lport, void *rport, void *xchg);
void unf_fdisc_ob_callback(struct unf_xchg *xchg);
void unf_fdisc_callback(void *lport, void *rport, void *xchg);

void unf_plogi_ob_callback(struct unf_xchg *xchg);
void unf_plogi_callback(void *lport, void *rport, void *xchg);
void unf_prli_ob_callback(struct unf_xchg *xchg);
void unf_prli_callback(void *lport, void *rport, void *xchg);
u32 unf_flogi_handler(struct unf_lport *lport, u32 sid, struct unf_xchg *xchg);
u32 unf_plogi_handler(struct unf_lport *lport, u32 sid, struct unf_xchg *xchg);
u32 unf_rec_handler(struct unf_lport *lport, u32 sid, struct unf_xchg *xchg);
u32 unf_prli_handler(struct unf_lport *lport, u32 sid, struct unf_xchg *xchg);
u32 unf_prlo_handler(struct unf_lport *lport, u32 sid, struct unf_xchg *xchg);
u32 unf_rscn_handler(struct unf_lport *lport, u32 sid, struct unf_xchg *xchg);
u32 unf_logo_handler(struct unf_lport *lport, u32 sid, struct unf_xchg *xchg);
u32 unf_echo_handler(struct unf_lport *lport, u32 sid, struct unf_xchg *xchg);
u32 unf_pdisc_handler(struct unf_lport *lport, u32 sid, struct unf_xchg *xchg);
u32 unf_send_pdisc_rjt(struct unf_lport *lport, struct unf_rport *rport,
		       struct unf_xchg *xchg);
u32 unf_adisc_handler(struct unf_lport *lport, u32 sid, struct unf_xchg *xchg);
u32 unf_rrq_handler(struct unf_lport *lport, u32 sid, struct unf_xchg *xchg);
u32 unf_send_rec(struct unf_lport *lport, struct unf_rport *rport,
		 struct unf_xchg *io_xchg);

u32 unf_low_level_bb_scn(struct unf_lport *lport);
typedef int (*unf_event_task)(void *arg_in, void *arg_out);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UNF_SERVICE_H__ */
