/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 - 2023 Mucse Corporation. */

#ifndef RNP_MPE_H
#define RNP_MPE_H

#include "rnp.h"

extern unsigned int mpe_src_port;
extern unsigned int mpe_pkt_version;

int rnp_rpu_mpe_start(struct rnp_adapter *adapter);
void rnp_rpu_mpe_stop(struct rnp_adapter *adapter);

#endif // RNP_MPE_H
