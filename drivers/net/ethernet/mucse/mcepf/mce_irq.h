/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_IRQ_H_
#define _MCE_IRQ_H_

int mce_napi_poll(struct napi_struct *napi, int budget);
void mce_napi_add(struct mce_vsi *vsi);
int mce_get_msix_vector(struct mce_hw *hw);
int mce_get_irq_num(struct mce_pf *pf, int idx);
int mce_init_interrupt_scheme(struct mce_pf *pf);
void mce_clear_interrupt_scheme(struct mce_pf *pf);
int mce_reinit_pcie_msix(struct mce_pf *pf);
int mce_vsi_req_irq_msix(struct mce_vsi *vsi, char *basename);
void mce_irq_apply_affinity(struct mce_q_vector *q_vector, int irq_num);
void mce_irq_clear_affinity(struct mce_pf *pf, int irq_num);

#endif /* _MCE_IRQ_H_ */
