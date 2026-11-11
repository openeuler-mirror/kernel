/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_BASE_H_
#define _NSE_BASE_H_

#include "nse.h"

int nse_vsi_cfg_rxq(struct nse_ring *ring);

int nse_vsi_ctrl_one_rx_ring(struct nse_vsi *vsi, bool ena, u16 rxq_idx);
int nse_vsi_ctrl_all_rx_rings(struct nse_vsi *vsi, bool ena);
int nse_vsi_ctrl_all_rx_rings_bulk(struct nse_vsi *vsi, bool ena);
int nse_vsi_wait_one_rx_ring(struct nse_vsi *vsi, bool ena, u16 rxq_idx);

int nse_vsi_ctrl_one_tx_ring(struct nse_vsi *vsi, bool ena, u16 rxq_idx);
int nse_vsi_wait_one_tx_ring(struct nse_vsi *vsi, bool ena, u16 rxq_idx);

int nse_vsi_ctrl_one_txcq_ring(struct nse_vsi *vsi, bool ena, u16 q_idx);
int nse_vsi_wait_one_txcq_ring(struct nse_vsi *vsi, bool ena, u16 q_idx);
int nse_vsi_ctrl_all_txcq_rings(struct nse_vsi *vsi, bool ena);

int nse_vsi_alloc_q_vectors(struct nse_vsi *vsi);
int nse_vsi_map_txcq_rings_to_vectors(struct nse_vsi *vsi);
int nse_vsi_map_rings_to_vectors(struct nse_vsi *vsi);
void nse_vsi_free_q_vectors(struct nse_vsi *vsi);

int nse_vsi_cfg_txq(struct nse_ring *tx_ring);

int nse_vsi_cfg_lan_txcq(struct nse_txcq_ring *cq_ring);

void nse_vsi_clear_q_irqll_status(struct nse_vsi *vsi);

void nse_cfg_itr(struct nse_hw *hw, struct nse_q_vector *q_vector);
void
nse_cfg_txq_interrupt(struct nse_vsi *vsi, u16 txq, u16 msix_idx);
void
nse_cfg_rxq_interrupt(struct nse_vsi *vsi, u16 rxq, u16 msix_idx);
void nse_trigger_sw_intr(struct nse_hw *hw, struct nse_q_vector *q_vector);

int
nse_vsi_start_tx_ring(struct nse_vsi *vsi, struct nse_ring *ring);

int
nse_vsi_stop_tx_ring(struct nse_vsi *vsi,
		     struct nse_ring *ring,
		     struct nse_txq_meta *txq_meta, bool tdm_stopped);

void
nse_fill_txq_meta(struct nse_vsi *vsi, struct nse_ring *ring,
		  struct nse_txq_meta *txq_meta);
#endif /* _NSE_BASE_H_ */
