// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include "roce_main_extension.h"

#ifndef PANGEA_NOF

#ifdef ROCE_BONDING_EN
#include "roce_bond.h"

static struct mutex g_rdev_mutex;
#endif

void roce3_service_init_pre(void)
{
#ifdef ROCE_BONDING_EN
	mutex_init(&g_rdev_mutex);
#endif

}

void roce3_service_init_ext(void)
{
}

void roce3_lock_rdev(void)
{
#ifdef ROCE_BONDING_EN
	mutex_lock(&g_rdev_mutex);
#endif

}

void roce3_unlock_rdev(void)
{
#ifdef ROCE_BONDING_EN
	mutex_unlock(&g_rdev_mutex);
#endif
}

int roce3_get_rdev_by_uld(struct hinic3_lld_dev *lld_dev, void *uld_dev, struct roce3_device **rdev,
	struct hinic3_event_info *event)
{
#ifdef ROCE_BONDING_EN
	int ret;

	ret = roce3_bond_event_cfg_rdev(lld_dev, uld_dev, rdev);
	if (ret != 0) {
		pr_err("[ROCE] %s: Cfg bond rdev failed(%d)\n", __func__, ret);
		return ret;
	}
	ret = roce3_bonded_port_event_report(*rdev, event);
	if (ret != 0) {
		pr_err("[ROCE] %s: Report bond event failed(%d)\n", __func__, ret);
		return ret;
	}
#else
	if ((lld_dev == NULL) || (uld_dev == NULL)) {
		pr_err("[ROCE] %s: Input params is null\n", __func__);
		return -ENODEV;
	}
	*rdev = (struct roce3_device *)uld_dev;
#endif
	return 0;
}
#endif /* !PANGEA_NOF */

#ifdef ROCE_STANDARD
void roce3_init_dev_ext_handlers(struct roce3_device *rdev)
{
}
#endif /* ROCE_STANDARD */

#ifndef PANGEA_NOF
void roce3_remove_clean_res_ext(struct roce3_device *rdev)
{
#ifdef __ROCE_DFX__
	roce3_dfx_clean_up(rdev);
#endif
}
#endif /* PANGEA_NOF */

#ifndef PANGEA_NOF
int roce3_board_cfg_check(struct roce3_device *rdev)
{
	int ret = 0;
	int port_num = 0;
	int port_speed = 0;

	port_num = rdev->board_info.port_num;
	port_speed = rdev->board_info.port_speed;
	if ((port_num == ROCE3_2_PORT_NUM) && (port_speed == ROCE3_100G_PORT_SPEED)) {
		rdev->hw_info.hca_type = ROCE3_2_100G_HCA;
	} else if ((port_num == ROCE3_4_PORT_NUM) && (port_speed == ROCE3_25G_PORT_SPEED)) {
		rdev->hw_info.hca_type = ROCE3_4_25G_HCA;
	} else if ((port_num == ROCE3_2_PORT_NUM) && (port_speed == ROCE3_25G_PORT_SPEED)) {
		rdev->hw_info.hca_type = ROCE3_2_25G_HCA;
	} else {
		pr_err("[ROCE] %s: Invalid fw cfg\n", __func__);
		ret = (-EINVAL);
	}

	return ret;
}

int roce3_mmap_ext(struct roce3_device *rdev, struct roce3_ucontext *ucontext,
	struct vm_area_struct *vma)
{
	dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Not support, func_id(%d)\n",
		__func__, rdev->glb_func_id);
	return -EINVAL;
}

int roce3_dfx_mem_alloc(struct roce3_device *rdev)
{
	return 0;
}

void roce3_dfx_mem_free(struct roce3_device *rdev)
{
}

void *roce3_ucontext_alloc_ext(void)
{
	return kzalloc(sizeof(struct roce3_ucontext), GFP_KERNEL);
}

void *roce3_resp_alloc_ext(void)
{
	return kzalloc(sizeof(struct roce3_alloc_ucontext_resp), GFP_KERNEL);
}

void roce3_resp_set_ext(struct roce3_device *rdev, struct roce3_alloc_ucontext_resp *resp)
{
}

void roce3_ucontext_set_ext(struct roce3_device *rdev, struct roce3_ucontext *context)
{
}

void *roce3_rdev_alloc_ext(void)
{
	return (void *)ib_alloc_device(roce3_device, ib_dev);
}

void roce3_rdev_set_ext(struct roce3_device *rdev)
{
}

int ib_copy_to_udata_ext(struct ib_udata *udata, struct roce3_alloc_ucontext_resp *resp)
{
	return ib_copy_to_udata(udata, resp, sizeof(struct roce3_alloc_ucontext_resp));
}

int roce3_set_comm_event(const struct roce3_device *rdev, const struct hinic3_event_info *event)
{
	dev_err(rdev->hwdev_hdl, "[ROCE, ERR] %s: Comm event unsupported, func_id(%d), event(%d)\n",
		__func__, rdev->glb_func_id, event->type);
	return -1;
}

bool roce3_hca_is_present(const struct roce3_device *rdev)
{
	return true;
}
#endif /* PANGEA_NOF */

#if !defined(NOF_AA)
int roce3_init_dev_ext(struct roce3_device *rdev)
{
	return 0;
}

#if defined(EULER_2_10_OFED_4_19) || defined(KY10_OFED_4_19)
void roce3_rdma_cap_ext(struct rdma_service_cap *rdma_cap)
{
	rdma_cap->max_sq_desc_sz = RDMA_MAX_SQ_DESC_SZ_COMPUTE;
	rdma_cap->dev_rdma_cap.roce_own_cap.max_wqes = ROCE_MAX_WQES_COMPUTE;
	rdma_cap->dev_rdma_cap.roce_own_cap.max_sq_inline_data_sz =
		ROCE_MAX_SQ_INLINE_DATA_SZ_COMPUTE;
}
#else
void roce3_rdma_cap_ext(struct rdma_service_cap *rdma_cap)
{
}
#endif

#endif
