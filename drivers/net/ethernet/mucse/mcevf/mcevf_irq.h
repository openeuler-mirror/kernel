/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2020-2026 Mucse Corporation. */

#ifndef _MCEVF_IRQ_H_
#define _MCEVF_IRQ_H_

int mcevf_napi_poll(struct napi_struct *napi, int budget);
void mcevf_napi_add(struct mcevf_vsi *vsi);
int mcevf_get_irq_num(struct mcevf_pf *pf, int idx);
int mcevf_init_interrupt_scheme(struct mcevf_pf *pf);
void mcevf_clear_interrupt_scheme(struct mcevf_pf *pf);
int mcevf_vsi_req_irq_msix(struct mcevf_vsi *vsi, char *basename);

#endif /* _MCEVF_IRQ_H_ */
