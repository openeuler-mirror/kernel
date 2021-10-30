/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef UNF_NPIV_H
#define UNF_NPIV_H

#include "unf_type.h"
#include "unf_common.h"
#include "unf_lport.h"

/* product VPORT configure */
struct vport_config {
	u64 node_name;
	u64 port_name;
	u32 port_mode; /* INI, TGT or both */
};

/* product Vport function */
#define PORTID_VPINDEX_MASK 0xff000000
#define PORTID_VPINDEX_SHIT 24
u32 unf_npiv_conf(u32 port_id, u64 wwpn, enum unf_rport_qos_level qos_level);
struct unf_lport *unf_creat_vport(struct unf_lport *lport,
				  struct vport_config *vport_config);
u32 unf_delete_vport(u32 port_id, u32 vp_index);

/* Vport pool creat and release function */
u32 unf_init_vport_pool(struct unf_lport *lport);
void unf_free_vport_pool(struct unf_lport *lport);

/* Lport resigster stLPortMgTemp function */
void unf_vport_remove(void *vport);
void unf_vport_ref_dec(struct unf_lport *vport);

/* linkdown all Vport after receive linkdown event */
void unf_linkdown_all_vports(void *lport);
/* Lport receive Flogi Acc linkup all Vport */
void unf_linkup_all_vports(struct unf_lport *lport);
/* Lport remove delete all Vport */
void unf_destroy_all_vports(struct unf_lport *lport);
void unf_vport_fabric_logo(struct unf_lport *vport);
u32 unf_destroy_one_vport(struct unf_lport *vport);
u32 unf_drop_vport(struct unf_lport *vport);
u32 unf_init_vport_mgr_temp(struct unf_lport *lport);
void unf_release_vport_mgr_temp(struct unf_lport *lport);
struct unf_lport *unf_get_vport_by_slab_index(struct unf_vport_pool *vport_pool,
					      u16 slab_index);
#endif
