/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2026, NEBULARMATRIX */

#ifndef NBL_RDMA_RESOURCE_H
#define NBL_RDMA_RESOURCE_H

struct nbl_pci_f;

int nbl_shadow_init(struct nbl_pci_f *rf);
void nbl_shadow_exit(struct nbl_pci_f *rf);
u16 nbl_get_ddr_obj_sz(u8 obj_type);
int nbl_update_voa_tbl(struct nbl_pci_f *rf, u16 function_id, bool valid);
int nbl_set_ecpu_rdma_vfid(struct nbl_pci_f *rf);
int nbl_clear_ecpu_rdma_vfid(struct nbl_pci_f *rf);
int nbl_get_admin_pf_init_params(struct nbl_pci_f *rf);
void nbl_set_vfid_vsi_map_v3(struct nbl_pci_f *rf, bool is_valid,
			     u16 vsi_id);
int nbl_get_rdma_function_id(struct nbl_pci_f *rf);
int nbl_put_rdma_function_id(struct nbl_pci_f *rf);
int df200_get_host_init_params(struct nbl_pci_f *rf);
int df200_get_host_rdma_function_id(struct nbl_pci_f *rf);
int df200_host_free_function_id(struct nbl_pci_f *rf);
int nbl_get_function_id_via_channel(struct nbl_pci_f *rf);
int nbl_free_function_id_via_channel(struct nbl_pci_f *rf);
void nbl_direct_set_vf_enable_tbl(struct nbl_pci_f *rf, u16 function_id,
				  u8 enable);

int nbl_get_function_num(struct nbl_pci_f *rf);
int nbl_free_function_num(struct nbl_pci_f *rf);
int nbl_set_hdma_vf_enable(struct nbl_pci_f *rf, u8 enable);
int nbl_qp_res_init(struct nbl_pci_f *rf);
int nbl_get_resv_init_params(struct nbl_pci_f *rf);
int nbl_get_init_params(struct nbl_pci_f *rf);

#endif /* NBL_RDMA_RESOURCE_H */
