/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2026, NEBULARMATRIX */

#ifndef NBL_PRODUCT_INTERNAL_H
#define NBL_PRODUCT_INTERNAL_H

#include "product.h"

extern const struct nbl_lifecycle_ops nbl_df200_ecpu_lifecycle_ops;
extern const struct nbl_lifecycle_ops nbl_df200_host_lifecycle_ops;
extern const struct nbl_lifecycle_ops nbl_draco_lifecycle_ops;
extern const struct nbl_lifecycle_ops nbl_orion_lifecycle_ops;
extern const struct nbl_lifecycle_ops nbl_rnic400_lifecycle_ops;
extern const struct nbl_fun_ops nbl_common_fun_ops;
extern const struct nbl_fun_ops nbl_df200_fun_ops;
extern const struct nbl_fun_ops nbl_rnic400_fun_ops;
extern const struct nbl_resource_ops nbl_df200_resource_ops;
extern const struct nbl_resource_ops nbl_draco_resource_ops;
extern const struct nbl_resource_ops nbl_orion_resource_ops;
extern const struct nbl_resource_ops nbl_rnic400_resource_ops;
extern const struct nbl_irq_ops nbl_df200_ecpu_irq_ops;
extern const struct nbl_irq_ops nbl_host_irq_ops;
extern const struct nbl_irq_ops nbl_rnic400_irq_ops;
extern const struct nbl_gid_ops nbl_direct_gid_ops;
extern const struct nbl_gid_ops nbl_draco_gid_ops;
extern const struct nbl_gid_ops nbl_orion_gid_ops;
extern const struct nbl_feature_ops nbl_common_feature_ops;
extern const struct nbl_feature_ops nbl_rnic400_feature_ops;
extern const struct nbl_dump_ops nbl_df200_dump_ops;
extern const struct nbl_dump_ops nbl_draco_dump_ops;
extern const struct nbl_dump_ops nbl_rnic400_dump_ops;
extern const struct nbl_cq_ops nbl_common_cq_ops;
extern const struct nbl_cq_ops nbl_rnic400_cq_ops;
extern const struct nbl_qpc_ops nbl_df200_qpc_ops;
extern const struct nbl_qpc_ops nbl_draco_qpc_ops;
extern const struct nbl_qpc_ops nbl_rnic400_qpc_ops;
extern const struct nbl_qos_ops nbl_df200_qos_ops;
extern const struct nbl_qos_ops nbl_draco_qos_ops;
extern const struct nbl_qos_ops nbl_rnic400_qos_ops;
extern const struct nbl_congestion_ops nbl_df200_congestion_ops;
extern const struct nbl_congestion_ops nbl_draco_congestion_ops;
extern const struct nbl_congestion_ops nbl_rnic400_congestion_ops;

void nbl_df200_reset_rdma(struct nbl_pci_f *rf);
void nbl_draco_reset_rdma(struct nbl_pci_f *rf);
void nbl_orion_reset_rdma(struct nbl_pci_f *rf);
void nbl_rnic400_reset_rdma(struct nbl_pci_f *rf);
void nbl_tqp_flush(struct nbl_pci_f *rf);
void nbl_rq_db_flush(struct nbl_pci_f *rf);
void nbl_armcq_db_flush(struct nbl_pci_f *rf);
int nbl_df200_armcq_get_flush_status(struct nbl_pci_f *rf);
int nbl_draco_armcq_get_flush_status(struct nbl_pci_f *rf);
int nbl_rnic400_armcq_get_flush_status(struct nbl_pci_f *rf);

const struct nbl_product_desc *nbl_product_lookup(u16 device_id);
int nbl_product_validate(const struct nbl_product_desc *product,
			 const struct nbl_rdma_dev_ops *dev_ops,
			 const struct nbl_cqp_ops *cqp_ops);

#endif /* NBL_PRODUCT_INTERNAL_H */
