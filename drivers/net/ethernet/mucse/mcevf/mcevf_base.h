/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2020-2026 Mucse Corporation. */

#ifndef _MCEVF_BASE_H_
#define _MCEVF_BASE_H_

#include "mcevf.h"

#define MCEVF_TX_INT_DELAY_TIME (8)
#define MCEVF_RX_INT_DELAY_TIME (8)
#define MCEVF_TX_INT_DELAY_PKTS (128)
#define MCEVF_RX_INT_DELAY_PKTS (128)

int mcevf_vsi_alloc_q_vectors(struct mcevf_vsi *vsi);
void mcevf_vsi_free_q_vectors(struct mcevf_vsi *vsi);

#endif /* _MCEVF_BASE_H_ */
