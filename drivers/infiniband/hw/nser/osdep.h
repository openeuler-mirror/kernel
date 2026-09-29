/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2018 - 2025 Beijing WangXun Technology Co., Ltd. */
#ifndef NSER_OSDEP_H
#define NSER_OSDEP_H

#include <linux/etherdevice.h>
#include <linux/pci.h>
#include <linux/bitfield.h>
#include <crypto/hash.h>
#include <rdma/ib_verbs.h>
#include <linux/workqueue.h>
#include <linux/refcount.h>

#define STATS_TIMER_DELAY	30000
#define idev_to_dev(ptr) (((ptr)->hw->device))

#define nser_dbg(idev, fmt, ...)		\
do {								\
	struct ib_device *ibdev = nser_get_ibdev(idev);	\
	if (ibdev)						\
		ibdev_dbg(ibdev, fmt, ##__VA_ARGS__);		\
	else							\
		dev_dbg(idev_to_dev(idev), fmt, ##__VA_ARGS__);	\
} while (0)

struct nser_dma_info {
	dma_addr_t *dmaaddrs;
};

struct nser_dma_mem {
	void *va;
	dma_addr_t pa;
	u32 size;
} __packed;

struct nser_virt_mem {
	void *va;
	u32 size;
} __packed;

struct nser_sc_vsi;
struct nser_sc_dev;
struct nser_sc_qp;
struct nser_update_sds_info;
struct nser_hmc_fcn_info;
struct nser_manage_vf_pble_info;
struct nser_hw;
struct nser_pci_f;
struct nser_virtchnl_req;

struct ib_device *nser_get_ibdev(struct nser_sc_dev *dev);
u8 __iomem *nser_get_hw_addr(void *dev);
bool nser_vf_clear_to_send(struct nser_sc_dev *dev);

void nser_free_hash_desc(struct shash_desc *hash_desc);
int nser_init_hash_desc(struct shash_desc **hash_desc);

int nser_cqp_sds_cmd(struct nser_sc_dev *dev,
		      struct nser_update_sds_info *info);
int nser_cqp_manage_hmc_fcn_cmd(struct nser_sc_dev *dev,
				 struct nser_hmc_fcn_info *hmcfcninfo,
				 u16 *pmf_idx);
int nser_cqp_query_fpm_val_cmd(struct nser_sc_dev *dev,
				struct nser_dma_mem *val_mem, u8 hmc_fn_id);
int nser_cqp_commit_fpm_val_cmd(struct nser_sc_dev *dev,
				 struct nser_dma_mem *val_mem, u8 hmc_fn_id);
int nser_alloc_query_fpm_buf(struct nser_sc_dev *dev,
			      struct nser_dma_mem *mem);
void *nser_remove_cqp_head(struct nser_sc_dev *dev);

void nser_hw_stats_start_timer(struct nser_sc_vsi *vsi);
void nser_hw_stats_stop_timer(struct nser_sc_vsi *vsi);
void wr32(struct nser_hw *hw, u32 reg, u32 val);
u32 rd32(struct nser_hw *hw, u32 reg);
u64 rd64(struct nser_hw *hw, u32 reg);
int nser_map_vm_page_list(struct nser_hw *hw, void *va, dma_addr_t *pg_dma,
			   u32 pg_cnt);
void nser_unmap_vm_page_list(struct nser_hw *hw, dma_addr_t *pg_dma, u32 pg_cnt);
int nser_vf_wait_vchnl_resp(struct nser_sc_dev *dev,
			     struct nser_virtchnl_req *vchnl_req);
int nser_vchnl_vf_get_resp(struct nser_sc_dev *dev,
			    struct nser_virtchnl_req *vchnl_req);
#endif /* NSER_OSDEP_H */
