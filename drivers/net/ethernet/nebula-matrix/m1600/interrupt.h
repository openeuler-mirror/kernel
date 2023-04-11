/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author: Monte Song <monte.song@nebula-matrix.com>
 */

#ifndef _NBL_INTERRUPT_H_
#define _NBL_INTERRUPT_H_

int nbl_init_interrupt_scheme(struct nbl_adapter *adapter);
void nbl_fini_interrupt_scheme(struct nbl_adapter *adapter);

int nbl_napi_poll(struct napi_struct *napi, int budget);

int nbl_request_irq(struct nbl_adapter *adapter);
void nbl_free_irq(struct nbl_adapter *adapter);

void nbl_enable_all_napis(struct nbl_adapter *adapter);
void nbl_disable_all_napis(struct nbl_adapter *adapter);

void nbl_configure_msix_irqs(struct nbl_adapter *adapter);

void nbl_af_configure_msix_irq(struct nbl_hw *hw, u16 func_id, u16 local_vector_id);

void nbl_af_clear_msix_irq_conf(struct nbl_hw *hw, u16 func_id, u16 local_vector_id);
void nbl_clear_msix_irqs_conf(struct nbl_adapter *adapter);

void nbl_enable_msix_irq(struct nbl_hw *hw, struct nbl_q_vector *q_vector);

int nbl_af_forward_ring_napi_poll(struct napi_struct *napi, int budget);

int nbl_af_forward_ring_request_irq(struct nbl_adapter *adapter);
void nbl_af_forward_ring_free_irq(struct nbl_adapter *adapter);

void nbl_af_enable_forward_ring_napi(struct nbl_adapter *adapter);
void nbl_af_disable_forward_ring_napi(struct nbl_adapter *adapter);

void nbl_af_configure_forward_ring_irq(struct nbl_adapter *adapter);
void nbl_af_clear_forward_ring_irq_conf(struct nbl_adapter *adapter);

#endif
