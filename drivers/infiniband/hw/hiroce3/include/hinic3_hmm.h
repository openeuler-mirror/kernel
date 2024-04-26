/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef HINIC_HMM_H__
#define HINIC_HMM_H__

/* has no mpt entry */
#define HMM_MPT_EN_SW 1	/* has mpt, state INVALID */
#define HMM_MPT_EN_HW 2	/* has mpt, state FREE or VALID */
#define HMM_MPT_DISABLED 0 /* has no mpt entry */
#define HMM_MPT_FIX_BUG_LKEY 0

#include "hinic3_cqm.h"
#include "hinic3_hwdev.h"
#include "hmm_comp.h"
#include "hmm_mr.h"

/*
 ****************************************************************************
 Prototype	: hmm_reg_user_mr_update
 Description  : MR注册生成和更新MPT和MTT表
 Input		: struct hinic3_hwdev *hwdev
				hmm_mr *mr MR结构，包含已
				经完成用户态内存的物理地址获取umem
				u32 pdn  PD号，如果不支持的pd的特性直接填0.
				u64 length 需要注册的用户态地址长度
				u64 virt_addr 需要注册的IOV虚拟地址首地址
				int hmm_access填入enum rdma_ib_access的值
				u32 service_type enum hinic3_service_type的值
 Output	   : None
****************************************************************************
*/
int hmm_reg_user_mr_update(struct hinic3_hwdev *hwdev, struct hmm_mr *mr, u32 pdn, u64 length,
	u64 virt_addr, int access, u32 service_type, u16 channel);


/*
 ****************************************************************************
 Prototype	: hmm_reg_user_mr_update
 Description  : MR去注册删除MPT和MTT表
 Input		: struct hinic3_hwdev *hwdev
				rdma_mr *mr MR结构
				u32 service_type enum hinic3_service_type的值
 Output	   : None
****************************************************************************
*/
int hmm_dereg_mr_update(struct hinic3_hwdev *hwdev, struct rdma_mr *mr,
	u32 service_type, u16 channel);

#ifndef ROCE_SERVICE
/*
 ****************************************************************************
 Prototype	: hmm_reg_user_mr
 Description  : register MR for user
 Input		: struct hinic3_hwdev *hwdev
				u32 pdn PD��
				u64 start ע��memory����ʼ��ַ
				u64 length ע���ڴ�ĳ���
				u64 virt_addr io�������ַ
				int hmm_access ����enum rdma_ib_access��ֵ
				u32 service_type enum hinic3_service_type��ֵ
 Output	   : None
****************************************************************************
*/
struct hmm_mr *hmm_reg_user_mr(struct hinic3_hwdev *hwdev, u64 start, u32 pdn, u64 length,
	u64 virt_addr, int hmm_access, u32 service_type, u16 channel);

/*
 ****************************************************************************
 Prototype	: hmm_dereg_mr
 Description  : dereg DMA_MR, user_MR or FRMR
 Input		: struct hmm_mr *mr
			  : u32 service_type enum hinic3_service_type的值
 Output	   : None

****************************************************************************
*/
int hmm_dereg_mr(struct hmm_mr *mr, u32 service_type, u16 channel);
#endif

int hmm_rdma_write_mtt(void *hwdev, struct rdma_mtt *mtt, u32 start_index, u32 npages,
	u64 *page_list, u32 service_type);

int hmm_rdma_mtt_alloc(void *hwdev, u32 npages, u32 page_shift,
	struct rdma_mtt *mtt, u32 service_type);

void hmm_rdma_mtt_free(void *hwdev, struct rdma_mtt *mtt, u32 service_type);

int hmm_init_mtt_table(struct hmm_comp_priv *comp_priv);

void hmm_cleanup_mtt_table(struct hmm_comp_priv *comp_priv);

#endif /* HINIC_RDMA_H__ */
