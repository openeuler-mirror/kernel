/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_MAIN_EXTENSION_H
#define ROCE_MAIN_EXTENSION_H

#include <linux/pci.h>

#include "hinic3_hw.h"
#include "hinic3_crm.h"
#include "hinic3_lld.h"
#include "hinic3_mbox.h"
#include "hinic3_srv_nic.h"

#include "roce.h"
#include "roce_mix.h"
#include "roce_srq.h"
#include "roce_cq.h"
#include "roce_qp.h"
#include "roce_dfx.h"
#include "roce_cmd.h"
#include "rdma_comp.h"
#include "hmm_mr.h"
#include "roce_qp_post_send_extension.h"

#define ROCE_MAX_WQES_COMPUTE				   (4 * K_UNIT - 1)
#define RDMA_MAX_SQ_DESC_SZ_COMPUTE			 512
#define ROCE_MAX_SQ_INLINE_DATA_SZ_COMPUTE	  448

struct hinic3_uld_info *roce3_info_get(void);

void roce3_service_init_pre(void);

void roce3_service_init_ext(void);

void roce3_lock_rdev(void);

void roce3_unlock_rdev(void);

int roce3_get_rdev_by_uld(struct hinic3_lld_dev *lld_dev, void *uld_dev, struct roce3_device **rdev,
	struct hinic3_event_info *event);

void roce3_init_dev_ext_handlers(struct roce3_device *rdev);

int roce3_board_cfg_check(struct roce3_device *rdev);

int roce3_init_dev_ext(struct roce3_device *rdev);

void roce3_remove_clean_res_ext(struct roce3_device *rdev);

int roce3_set_comm_event(const struct roce3_device *rdev, const struct hinic3_event_info *event);

bool roce3_hca_is_present(const struct roce3_device *rdev);

int roce3_mmap_ext(struct roce3_device *rdev, struct roce3_ucontext *ucontext,
	struct vm_area_struct *vma);

int roce3_dfx_mem_alloc(struct roce3_device *rdev);

void roce3_dfx_mem_free(struct roce3_device *rdev);

int ib_copy_to_udata_ext(struct ib_udata *udata, struct roce3_alloc_ucontext_resp *resp);

void *roce3_ucontext_alloc_ext(void);

void roce3_resp_set_ext(struct roce3_device *rdev, struct roce3_alloc_ucontext_resp *resp);

void *roce3_resp_alloc_ext(void);

void roce3_ucontext_set_ext(struct roce3_device *rdev, struct roce3_ucontext *context);

void *roce3_rdev_alloc_ext(void);

void roce3_rdev_set_ext(struct roce3_device *rdev);

void roce3_rdma_cap_ext(struct rdma_service_cap *rdma_cap);

#endif /* ROCE_MAIN_EXTENSION_H */
