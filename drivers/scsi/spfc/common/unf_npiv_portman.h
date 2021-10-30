/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef UNF_NPIV_PORTMAN_H
#define UNF_NPIV_PORTMAN_H

#include "unf_type.h"
#include "unf_lport.h"

/* Lport resigster stLPortMgTemp function */
void *unf_lookup_vport_by_index(void *lport, u16 vp_index);
void *unf_lookup_vport_by_portid(void *lport, u32 port_id);
void *unf_lookup_vport_by_did(void *lport, u32 did);
void *unf_lookup_vport_by_wwpn(void *lport, u64 wwpn);
void unf_linkdown_one_vport(struct unf_lport *vport);

#endif
