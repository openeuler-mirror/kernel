// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/module.h>
#include <linux/netdevice.h>

#include "hinic3_hw.h"
#include "hmm_comp.h"
#include "hmm_mr.h"

int hmm_rdma_mpt_alloc(void *hwdev, struct rdma_mpt *mpt, u32 service_type)
{
	struct hmm_comp_priv *comp_priv = NULL;
	struct rdma_mpt_entry *mpt_entry = NULL;
	u32 mpt_entry_size = 0;

	if ((hwdev == NULL) || (mpt == NULL)) {
		pr_err("%s: Hwdev or mpt is null\n", __func__);
		return -EINVAL;
	}

	comp_priv = get_hmm_comp_priv(hwdev, service_type);
	if (comp_priv == NULL) {
		pr_err("%s: Comp_priv is null\n", __func__);
		return -EINVAL;
	}
	mpt_entry_size = comp_priv->rdma_cap.mpt_entry_sz;

	mpt->mpt_object =
		(void *)cqm_object_qpc_mpt_create(hwdev, service_type, CQM_OBJECT_MPT,
			mpt_entry_size, mpt, CQM_INDEX_INVALID, false);
	if (mpt->mpt_object == NULL) {
		pr_err("%s: Alloc mpt_object failed, err(%d)\n", __func__, -ENOMEM);
		return -ENOMEM;
	}

	mpt->mpt_index = ((struct tag_cqm_qpc_mpt *)mpt->mpt_object)->xid;
	mpt->vaddr = (void *)((struct tag_cqm_qpc_mpt *)mpt->mpt_object)->vaddr;
	if (!cqm_need_secure_mem(hwdev)) {
		memset(mpt->vaddr, 0, sizeof(struct rdma_mpt_entry));

		mpt_entry = (struct rdma_mpt_entry *)mpt->vaddr;
		mpt_entry->roce_mpt_ctx.dw2.bs.status = RDMA_MPT_STATUS_MEM_INIT;
		mpt_entry->roce_mpt_ctx.dw2.value = cpu_to_be32(mpt_entry->roce_mpt_ctx.dw2.value);
	}
	return 0;
}


void hmm_rdma_mpt_free(void *hwdev, struct rdma_mpt *mpt)
{
	if ((hwdev == NULL) || (mpt == NULL)) {
		pr_err("%s: Hwdev or mpt is null\n", __func__);
		return;
	}
	hiudk_cqm_object_delete(hwdev, &((struct tag_cqm_qpc_mpt *)mpt->mpt_object)->object);
	mpt->vaddr = NULL;
	mpt->mpt_object = NULL;
}
