/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_VF_LIB_PRIVATE_H_
#define _NSE_VF_LIB_PRIVATE_H_

#include "nse_vf_lib.h"

/* This header file is for exposing functions in nse_vf_lib.c to other files
 * which are also conditionally compiled depending on CONFIG_PCI_IOV.
 * Functions which may be used by other files should be exposed as part of
 * nse_vf_lib.h
 *
 * Functions in this file are exposed only when CONFIG_PCI_IOV is enabled, and
 * thus this header must not be included by .c files which may be compiled
 * with CONFIG_PCI_IOV disabled.
 *
 * To avoid this, only include this header file directly within .c files that
 * are conditionally enabled in the "ice-$(CONFIG_PCI_IOV)" block.
 */

#ifndef CONFIG_PCI_IOV
#warning "Only include nse_vf_lib_private.h in CONFIG_PCI_IOV virtualization files"
#endif

int nse_initialize_vf_entry(struct nse_vf *vf);
void nse_dis_vf_qs(struct nse_vf *vf, bool lan_stopped);
void nse_dis_vf_mappings(struct nse_vf *vf);
enum virtchnl_status_code nse_err_to_virt_err(enum nse_status nse_err);
int nse_check_vf_init(struct nse_vf *vf);
struct nse_port_info *nse_vf_get_port_info(struct nse_vf *vf);
int nse_vsi_apply_spoofchk(struct nse_vsi *vsi, bool enable);
bool nse_is_vf_trusted(struct nse_vf *vf);
bool nse_vf_has_no_qs_ena(struct nse_vf *vf);
bool nse_is_vf_link_up(struct nse_vf *vf);
int nse_vf_rebuild_host_vlan_cfg(struct nse_vf *vf, struct nse_vsi *vsi);
void nse_vf_rebuild_host_cfg(struct nse_vf *vf);
int nse_vf_init_host_cfg(struct nse_vf *vf, struct nse_vsi *vsi);
void nse_vf_invalidate_vsi(struct nse_vf *vf);
void nse_vf_vsi_release(struct nse_vf *vf);
void nse_vf_set_initialized(struct nse_vf *vf);

#endif /* _NSE_VF_LIB_PRIVATE_H_ */
