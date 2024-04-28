// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/module.h>
#include <linux/netdevice.h>

#include "hinic3_hw.h"
#include "rdma_comp.h"
#include "hinic3_hmm.h"

#define ROCE_MAX_RDMA_RC_EXTEND 384 /* 12K */

static int rdma_init_pd_table(struct rdma_comp_priv *comp_priv)
{
	int ret = 0;
	u32 num = 0;
	u32 reserved_bot = 0;

	num = comp_priv->rdma_cap.num_pds;
	reserved_bot = comp_priv->rdma_cap.reserved_pds;

	ret = rdma_bitmap_init(&comp_priv->pd_bitmap, num, num - 1, reserved_bot, 0);
	if (ret != 0) {
		pr_err("%s: Can't initialize pd's bitmap, ret(%d)\n", __func__, ret);
		return ret;
	}

	return 0;
}

static void rdma_cleanup_gid_table(struct rdma_comp_priv *comp_priv)
{
	struct rdma_gid_entry **gid_table = NULL;
	int i = 0;
	int port_num = 0;

	gid_table = comp_priv->rdma_comp_res.gid_table;
	if (gid_table == NULL) {
		pr_err("%s: Gid_table is null\n", __func__);
		return;
	}

	port_num = (int)comp_priv->rdma_cap.num_ports;
	for (i = 0; i < port_num; i++) {
		kfree(gid_table[i]);
		gid_table[i] = NULL;
	}

	kfree(gid_table);
	comp_priv->rdma_comp_res.gid_table = NULL;
}

static int rdma_init_gid_table(struct rdma_comp_priv *comp_priv)
{
	struct rdma_gid_entry **gid_table = NULL;
	u32 i = 0;
	u32 port_num = 0;
	u32 gids_per_port = 0;

	port_num = comp_priv->rdma_cap.num_ports;
	gids_per_port = comp_priv->rdma_cap.max_gid_per_port;
	if ((port_num == 0) || (gids_per_port == 0)) {
		pr_err("%s: Alloc memory for gid_tbl failed, port_num(%d), gids_per_ports(%d)\n",
			__func__, port_num, gids_per_port);
		return -EINVAL;
	}

	gid_table = kcalloc(port_num, sizeof(struct rdma_gid_entry *), GFP_KERNEL);
	if (gid_table == NULL)
		return -ENOMEM;

	comp_priv->rdma_comp_res.gid_table = gid_table;

	for (i = 0; i < port_num; i++) {
		gid_table[i] = kcalloc(gids_per_port, sizeof(struct rdma_gid_entry), GFP_KERNEL);
		if (gid_table[i] == NULL)
			goto err_out;
	}
	return 0;
err_out:
	for (i = 0; i < port_num; i++) {
		kfree(gid_table[i]);
		gid_table[i] = NULL;
	}
	kfree(gid_table);
	comp_priv->rdma_comp_res.gid_table = NULL;

	return -ENOMEM;
}

static int rdma_init_xrcd_table(struct rdma_comp_priv *comp_priv)
{
	int ret = 0;
	u32 num = 0;
	u32 reserved_bot = 0;

	num = comp_priv->rdma_cap.max_xrcds;
	reserved_bot = comp_priv->rdma_cap.reserved_xrcds;

	ret = rdma_bitmap_init(&comp_priv->xrcd_bitmap, num, num - 1, reserved_bot, 0);
	if (ret != 0) {
		pr_err("%s: Can't initialize xrcd's bitmap!, ret(%d)\n", __func__, ret);
		return ret;
	}

	return 0;
}

static void rdma_cleanup_xrcd_table(struct rdma_comp_priv *comp_priv)
{
	rdma_bitmap_cleanup(&comp_priv->xrcd_bitmap);
}

static int rdma_init_rdmarc_table(struct rdma_comp_priv *comp_priv)
{
	int ret = 0;
	u32 i = 0;
	u32 max_order = 0; /* rdmarc buddy max priority num */
	u32 qp_num = 0;
	u32 rdmarc_per_qp = 0; /* rdmarc num per qp */
	u32 rdmarc_size = 0;
	u32 log_rdmarc_per_seg = 0; /* min num of entry, 2^log_rdmarc_per_seg */
	u32 rdmarc_pow_of_two = 0;

	qp_num = comp_priv->rdma_cap.dev_rdma_cap.roce_own_cap.max_qps;
	rdmarc_per_qp = comp_priv->rdma_cap.dev_rdma_cap.roce_own_cap.max_qp_dest_rdma +
		ROCE_MAX_RDMA_RC_EXTEND;
	rdmarc_size = comp_priv->rdma_cap.dev_rdma_cap.roce_own_cap.rdmarc_entry_sz;
	log_rdmarc_per_seg = comp_priv->rdma_cap.log_rdmarc_seg;
	for (i = 1; i < qp_num * rdmarc_per_qp; i <<= 1)
		max_order++;

	max_order = (max_order > log_rdmarc_per_seg) ? (max_order - log_rdmarc_per_seg) : 0;

	ret = hmm_buddy_init(&comp_priv->rdmarc_buddy, max_order);
	if (ret != 0) {
		pr_err("%s: Initialize rdmarc's buddy failed, ret(%d)\n", __func__, -ENOMEM);
		return -ENOMEM;
	}
	/*lint -e587*/
	rdmarc_pow_of_two = (u32)(HMM_EM_ROUNDUP_POW_OF_TWO(
		(u32)(qp_num * rdmarc_per_qp)) & 0xffffffff);
	/*lint +e587*/
	ret = hmm_em_init_table(comp_priv->pdev, &comp_priv->rdmarc_em_table,
		rdmarc_size, rdmarc_pow_of_two, 0, RDMA_EM_MIN_ORDER);
	if (ret != 0) {
		pr_err("%s: Initialize rdmarc's em_table failed, ret(%d)\n", __func__, ret);
		goto err_out;
	}

	return 0;

err_out:
	hmm_buddy_cleanup(&comp_priv->rdmarc_buddy);

	return -ENOMEM;
}

static int roce3_rdma_init_pd_table(struct rdma_comp_priv *comp_priv)
{
	int ret = 0;

	ret = rdma_init_pd_table(comp_priv);
	if (ret != 0) {
		pr_err("%s: Initialize pd's table failed, ret(%d)\n", __func__, ret);
		return ret;
	}

	return 0;
}

static int roce3_rdma_init_mtt_table(struct rdma_comp_priv *comp_priv)
{
	int ret = 0;

	ret = hmm_init_mtt_table((struct hmm_comp_priv *)(void *)comp_priv);
	if (ret != 0) {
		pr_err("%s: Initialize mtt's table failed, ret(%d)\n", __func__, ret);
		return ret;
	}

	return 0;
}

static int roce3_rdma_init_bitmap(struct rdma_comp_priv *comp_priv)
{
	int ret;

	ret = roce3_rdma_init_pd_table(comp_priv);
	if (ret != 0)
		return ret;

	ret = roce3_rdma_init_mtt_table(comp_priv);
	if (ret != 0) {
		rdma_cleanup_pd_table(comp_priv);
		return ret;
	}

	return 0;
}

static void roce3_rdma_unit_bitmap(struct rdma_comp_priv *comp_priv)
{
	hmm_cleanup_mtt_table((struct hmm_comp_priv *)(void *)comp_priv);
	rdma_cleanup_pd_table(comp_priv);
}

static int roce3_rdma_init_table(void *hwdev, struct rdma_comp_priv *comp_priv)
{
	int ret = 0;

	ret = roce3_rdma_init_bitmap(comp_priv);
	if (ret != 0)
		return ret;

	if (hinic3_support_roce(hwdev, NULL)) {
		ret = rdma_init_gid_table(comp_priv);
		if (ret != 0) {
			pr_err("%s: Initialize gid table failed, ret(%d)\n", __func__, ret);
			goto err_init_gid_table;
		}
		ret = rdma_init_xrcd_table(comp_priv);
		if (ret != 0) {
			pr_err("%s: Initialize xrcd's table failed, ret(%d)\n", __func__, ret);
			goto err_init_xrcd;
		}
		ret = rdma_init_rdmarc_table(comp_priv);
		if (ret != 0) {
			pr_err("%s: Initialize rdmarc's table failed, ret(%d)\n",
				__func__, ret);
			goto err_init_rdmarc_table;
		}
	}

	pr_info("%s: Rdma init resource successful\n", __func__);
	return 0;
err_init_rdmarc_table:
	rdma_cleanup_xrcd_table(comp_priv);
err_init_xrcd:
	rdma_cleanup_gid_table(comp_priv);
err_init_gid_table:
	roce3_rdma_unit_bitmap(comp_priv);
	return ret;
}

static void rdma_cleanup_rdmarc_table(struct rdma_comp_priv *comp_priv)
{
	hmm_em_cleanup_table(comp_priv->pdev, &comp_priv->rdmarc_em_table);

	hmm_buddy_cleanup(&comp_priv->rdmarc_buddy);
}

static void roce3_rdma_unit_table(void *hwdev, struct rdma_comp_priv *comp_priv)
{
	if (hinic3_support_roce(hwdev, NULL)) {
		rdma_cleanup_rdmarc_table(comp_priv);
		rdma_cleanup_xrcd_table(comp_priv);
		rdma_cleanup_gid_table(comp_priv);
	}

	roce3_rdma_unit_bitmap(comp_priv);
}

void roce3_rdma_cleanup_resource(void *hwdev)
{
	struct rdma_comp_priv *comp_priv = NULL;

	if (hwdev == NULL) {
		pr_err("%s: Hwdev is null\n", __func__);
		return;
	}

	if (!hinic3_support_rdma(hwdev, NULL)) {
		pr_err("%s: Not support rdma service\n", __func__);
		return;
	}

	comp_priv = get_rdma_comp_priv(hwdev);
	if (comp_priv == NULL) {
		pr_err("%s: Comp_priv is null\n", __func__);
		return;
	}

	roce3_rdma_unit_table(hwdev, comp_priv);

	kfree(comp_priv);

	hinic3_unregister_service_adapter((void *)hwdev, SERVICE_T_ROCE);

	pr_info("%s: Rdma cleanup resource successful", __func__);
}

static int roce3_rdma_init_comp_priv(struct rdma_comp_priv *comp_priv,
	void *hwdev, struct rdma_service_cap *rdma_cap)
{
	int ret;

	mutex_init(&comp_priv->rdma_comp_res.mutex);
	comp_priv->hwdev = hwdev;
	comp_priv->pdev = (struct pci_dev *)((struct hinic3_hwdev *)hwdev)->pcidev_hdl;
	memcpy((void *)&comp_priv->rdma_cap, (void *)rdma_cap,
		sizeof(struct rdma_service_cap));
	// to adapt hmm struct
	comp_priv->rdma_cap.dmtt_cl_start = rdma_cap->dev_rdma_cap.roce_own_cap.dmtt_cl_start;
	comp_priv->rdma_cap.dmtt_cl_end = rdma_cap->dev_rdma_cap.roce_own_cap.dmtt_cl_end;
	comp_priv->rdma_cap.dmtt_cl_sz = rdma_cap->dev_rdma_cap.roce_own_cap.dmtt_cl_sz;

	switch (g_mtt_page_size) {
	case ROCE3_RDMA_MTT_PAGE_SIZE_4K:
		comp_priv->mtt_page_size = ROCE_MTT_PAGE_SIZE_4K;
		comp_priv->mtt_page_shift = ROCE_MTT_PAGE_SIZE_4K_SHIFT;
		break;
	case ROCE3_RDMA_MTT_PAGE_SIZE_64K:
		comp_priv->mtt_page_size = ROCE_MTT_PAGE_SIZE_64K;
		comp_priv->mtt_page_shift = ROCE_MTT_PAGE_SIZE_64K_SHIFT;
		break;
	case ROCE3_RDMA_MTT_PAGE_SIZE_2M:
		comp_priv->mtt_page_size = ROCE_MTT_PAGE_SIZE_2M;
		comp_priv->mtt_page_shift = ROCE_MTT_PAGE_SIZE_2M_SHIFT;
		break;
	default:
		comp_priv->mtt_page_size = ROCE_MTT_PAGE_SIZE_4K;
		comp_priv->mtt_page_shift = ROCE_MTT_PAGE_SIZE_4K_SHIFT;
		break;
	}
	ret = roce3_rdma_init_table(hwdev, comp_priv);
	if (ret != 0)
		return ret;

	ret = hinic3_register_service_adapter((void *)hwdev, (void *)comp_priv, SERVICE_T_ROCE);
	if (ret != 0) {
		roce3_rdma_unit_table(hwdev, comp_priv);
		pr_err("%s: put rdma_comp_res failed, ret(%d)\n", __func__, ret);
		return ret;
	}
	return ret;
}

int roce3_rdma_init_resource(void *hwdev)
{
	struct rdma_comp_priv *comp_priv = NULL;
	struct rdma_service_cap rdma_cap;
	int ret = 0;

	if (hwdev == NULL) {
		pr_err("%s: Hwdev is null\n", __func__);
		return -EINVAL;
	}

	if (!hinic3_support_rdma(hwdev, &rdma_cap)) {
		pr_info("%s: Neither ROCE nor IWARP\n", __func__);
		return 0;
	}

	comp_priv = kzalloc(sizeof(struct rdma_comp_priv), GFP_KERNEL);
	if (comp_priv == NULL)
		return -ENOMEM;

	ret = roce3_rdma_init_comp_priv(comp_priv, hwdev, &rdma_cap);
	if (ret != 0) {
		kfree(comp_priv);
		return ret;
	}

	return 0;
}
