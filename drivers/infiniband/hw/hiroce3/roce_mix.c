// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <rdma/ib_mad.h>
#include <rdma/ib_verbs.h>
#include <linux/pci.h>

#include <rdma/ib_addr.h>
#include <rdma/ib_cache.h>

#include "hinic3_crm.h"
#include "hinic3_srv_nic.h"

#include "roce.h"
#include "roce_compat.h"
#include "roce_user.h"
#include "roce_pd.h"
#include "roce_qp.h"
#include "roce_cmd.h"
#include "roce_netdev.h"
#include "roce_main_extension.h"
#include "roce_pub_cmd.h"

#include "roce_mix.h"

#ifdef ROCE_BONDING_EN
#include "roce_bond.h"
#endif

struct net_device *roce3_ib_get_netdev(struct ib_device *ibdev, u8 port_num)
{
	struct roce3_device *rdev = NULL;
	struct net_device *netdev = NULL;

	if (ibdev == NULL) {
		pr_err("[ROCE] %s: Ibdev is null\n", __func__);
		return NULL;
	}

	rdev = to_roce3_dev(ibdev);
	if (roce3_hca_is_present(rdev) == 0) {
		pr_err("[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return NULL;
	}

#ifdef ROCE_BONDING_EN
	netdev = roce3_bond_get_netdev(rdev);
	if (netdev != NULL)
		return netdev;
#endif

	netdev = rdev->ndev;

	dev_hold(netdev);

	return netdev;
}

static void roce3_parse_fw_version(struct roce3_device *rdev, u64 *fw_ver)
{
	int ret;
	int i = 0;
	struct hinic3_fw_version fw_version;
	char *fw_str = (char *)fw_version.microcode_ver;
	char *fw_temp = NULL;
	u64 fw_verion[ROCE_FW_VERSION_LEN] = {0};

	ret = hinic3_get_fw_version(rdev->hwdev, &fw_version, HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		pr_warn("[ROCE] %s: get fw version failed\n", __func__);
		*fw_ver = ROCE_FW_VER;
		return;
	}
	pr_info("[ROCE] %s: fw ver:%s - %s - %s\n", __func__, fw_version.boot_ver,
		fw_version.mgmt_ver, fw_version.microcode_ver);

	while (((fw_temp = strsep(&fw_str, ".")) != NULL) && (i < ROCE_FW_VERSION_LEN)) {
		ret = kstrtou64(fw_temp, 10, &fw_verion[i]);
		if (ret != 0) {
			pr_warn("[ROCE] %s: parse fw version failed\n", __func__);
			*fw_ver = ROCE_FW_VER;
			return;
		}

		i++;
	}
/*
 *	0 is fw_version array idx, 32 is offset
 *	1 is fw_version array idx, 16 is offset
 *	2 is fw_version array idx, 8 is offset
 *	3 is fw_version array idx
 */
	*fw_ver = (((fw_verion[0] & 0xffffffff) << 32) |
		((fw_verion[1] & 0xffff) << 16) |
		((fw_verion[2] & 0xff) << 8) |
		(fw_verion[3] & 0xff));
}

static void roce3_set_local_cap_flag(const struct rdma_service_cap *rdma_cap,
	struct ib_device_attr *props)
{
	if (((rdma_cap->flags & RDMA_BMME_FLAG_LOCAL_INV) != 0) &&
		((rdma_cap->flags & RDMA_BMME_FLAG_REMOTE_INV) != 0) &&
		((rdma_cap->flags & RDMA_BMME_FLAG_FAST_REG_WR) != 0)) {
		props->device_cap_flags = props->device_cap_flags | IB_DEVICE_MEM_MGT_EXTENSIONS;
	}
}

static void roce3_set_bmme_cap_flag(const struct rdma_service_cap *rdma_cap,
	struct ib_device_attr *props)
{
	if ((rdma_cap->flags & RDMA_BMME_FLAG_TYPE_2_WIN) != 0) {
		if ((rdma_cap->flags & RDMA_BMME_FLAG_WIN_TYPE_2B) != 0)
			props->device_cap_flags = props->device_cap_flags |
				IB_DEVICE_MEM_WINDOW_TYPE_2B;
		else
			props->device_cap_flags = props->device_cap_flags |
				IB_DEVICE_MEM_WINDOW_TYPE_2A;
	}
}

static void roce3_query_device_props_set(struct roce3_device *rdev,
	struct rdma_service_cap *rdma_cap, struct ib_device_attr *props)
{
	props->vendor_id = rdev->pdev->vendor;
	props->vendor_part_id = rdev->pdev->device;
	roce3_parse_fw_version(rdev, &props->fw_ver);
	props->hw_ver = ROCE_HW_VER;

	/* sys_image_guid equal GID */
	props->sys_image_guid = rdev->ib_dev.node_guid;

	props->max_mr_size = ~0ULL;
	props->page_size_cap = rdma_cap->page_size_cap;
	props->max_qp = (int)(rdma_cap->dev_rdma_cap.roce_own_cap.max_qps - rdma_cap->reserved_qps);
	props->max_qp_wr = (int)rdma_cap->dev_rdma_cap.roce_own_cap.max_wqes;
	/*
	 * 4.19 ofed will return the smaller of sq/rq sge num to user space.
	 * 4.17 We use max_sge to only represent max sq sge num, max_rq_sge is a fixed macro of 16.
	 */
	props->max_send_sge = rdma_cap->max_sq_sg;
	props->max_recv_sge = rdma_cap->dev_rdma_cap.roce_own_cap.max_rq_sg;
	props->max_cq = (int)(rdma_cap->dev_rdma_cap.roce_own_cap.max_cqs - rdma_cap->reserved_cqs);
	props->max_cqe = (int)rdma_cap->max_cqes;

	if ((rdev->board_info.port_num == ROCE_PORT_NUM_2) &&
		(rdev->board_info.port_speed == ROCE_25G_PORT_SPEED)) {
		// 2 smf for 64B cache
		props->max_mr = (int)(rdma_cap->dev_rdma_cap.roce_own_cap.max_mpts -
			rdma_cap->reserved_mrws) / MEND_CAP_DEVIDE;
		props->max_srq =
			(int)(rdma_cap->dev_rdma_cap.roce_own_cap.max_srqs -
			rdma_cap->dev_rdma_cap.roce_own_cap.reserved_srqs) /
			MEND_CAP_DEVIDE;
	} else {
		props->max_mr = (int)(rdma_cap->dev_rdma_cap.roce_own_cap.max_mpts -
			rdma_cap->reserved_mrws);
		props->max_srq =
			(int)(rdma_cap->dev_rdma_cap.roce_own_cap.max_srqs -
			rdma_cap->dev_rdma_cap.roce_own_cap.reserved_srqs);
	}

	props->max_mw = props->max_mr;
	props->max_pd = (int)(rdma_cap->num_pds - rdma_cap->reserved_pds);
	props->max_qp_rd_atom = (int)rdma_cap->dev_rdma_cap.roce_own_cap.max_qp_dest_rdma;
	props->max_qp_init_rd_atom = (int)rdma_cap->dev_rdma_cap.roce_own_cap.max_qp_init_rdma;
	props->max_res_rd_atom = props->max_qp_rd_atom * props->max_qp;

	props->max_srq_wr = (int)rdma_cap->dev_rdma_cap.roce_own_cap.max_srq_wqes;
	props->max_srq_sge = (int)rdma_cap->dev_rdma_cap.roce_own_cap.max_srq_sge;
	props->max_fast_reg_page_list_len = rdma_cap->max_frpl_len;
	props->local_ca_ack_delay = (u8)rdma_cap->local_ca_ack_delay;
	props->atomic_cap = ((rdma_cap->flags & RDMA_DEV_CAP_FLAG_ATOMIC) != 0) ?
		IB_ATOMIC_HCA : IB_ATOMIC_NONE;
	props->masked_atomic_cap = props->atomic_cap;
	props->max_pkeys = (u16)rdma_cap->max_pkeys;
	props->max_ah = INT_MAX;
}
/*
 ****************************************************************************
 Prototype	: roce3_query_device
 Description  : query device attribute
 Input		: struct ib_device *ibdev
				struct ib_device_attr *props
				struct ib_udata *uhw
 Output	   : struct ib_device_attr *props

  1.Date		 : 2015/5/8
	Modification : Created function

****************************************************************************
*/
int roce3_query_device(struct ib_device *ibdev, struct ib_device_attr *props, struct ib_udata *uhw)
{
	struct roce3_device *rdev = NULL;
	struct rdma_service_cap *rdma_cap = NULL;

	if ((ibdev == NULL) || (props == NULL)) {
		pr_err("[ROCE] %s: Ibdev or props is null\n", __func__);
		return -EINVAL;
	}

	rdev = to_roce3_dev(ibdev);
	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -EPERM;
	}

	memset(props, 0, sizeof(*props));

	rdma_cap = &rdev->rdma_cap;

	props->device_cap_flags = IB_DEVICE_PORT_ACTIVE_EVENT | IB_DEVICE_RC_RNR_NAK_GEN;

	/* APM */
	if ((rdma_cap->flags & RDMA_DEV_CAP_FLAG_APM) != 0)
		props->device_cap_flags = props->device_cap_flags | IB_DEVICE_AUTO_PATH_MIG;

	/* rsvd_lKey */
	if ((rdma_cap->flags & RDMA_BMME_FLAG_RESERVED_LKEY) != 0)
		props->device_cap_flags = props->device_cap_flags | IB_DEVICE_LOCAL_DMA_LKEY;

	roce3_set_local_cap_flag(rdma_cap, props);

#ifndef ROCE_COMPUTE
	/* support XRC */
	if ((rdma_cap->flags & RDMA_DEV_CAP_FLAG_XRC) != 0)
		props->device_cap_flags = props->device_cap_flags | IB_DEVICE_XRC;
#endif

	/* support MW */
	if ((rdma_cap->flags & RDMA_DEV_CAP_FLAG_MEM_WINDOW) != 0)
		props->device_cap_flags = props->device_cap_flags | IB_DEVICE_MEM_WINDOW;

	roce3_set_bmme_cap_flag(rdma_cap, props);

	roce3_query_device_props_set(rdev, rdma_cap, props);
	return 0;
}

static void eth_link_get_speed(struct ib_port_attr *props, enum mag_cmd_port_speed speed)
{
	switch (speed) {
	/* 10G <==> 1X x 10G */
	case PORT_SPEED_10GB:
		props->active_width = IB_WIDTH_1X;
		props->active_speed = IB_SPEED_QDR;
		break;

	/* 25G <==> 1X x 25G */
	case PORT_SPEED_25GB:
		props->active_width = IB_WIDTH_1X;
		props->active_speed = IB_SPEED_EDR;
		break;

	/* 40G <==> 4X x 10G */
	case PORT_SPEED_40GB:
		props->active_width = IB_WIDTH_4X;
		props->active_speed = IB_SPEED_QDR;
		break;

	/* 100G <==> 4X x 25G */
	case PORT_SPEED_100GB:
		props->active_width = IB_WIDTH_4X;
		props->active_speed = IB_SPEED_EDR;
		break;

	default:
		props->active_width = 0;
		props->active_speed = 0;
		break;
	}
}

static void roce3_set_ib_port_attr(struct ib_port_attr *props, struct roce3_device *rdev)
{
	props->port_cap_flags = IB_PORT_CM_SUP;
	props->gid_tbl_len = (int)rdev->rdma_cap.max_gid_per_port;
	props->max_msg_sz = rdev->rdma_cap.dev_rdma_cap.roce_own_cap.max_msg_sz;
	props->pkey_tbl_len = (u16)rdev->rdma_cap.max_pkeys;
	props->max_mtu = IB_MTU_4096;
	props->state = IB_PORT_DOWN;
	props->phys_state = ROCE_PORT_PHYS_STATE_DISABLED;
	props->active_mtu = IB_MTU_256;
}
#ifdef OFED_MLNX_5_8
static void eth_link_query_port(struct ib_device *ibdev, u8 port, struct ib_port_attr *props)
#else
static void eth_link_query_port(struct ib_device *ibdev, u32 port, struct ib_port_attr *props)
#endif
{
	struct roce3_device *rdev = NULL;
	struct net_device *netdev = NULL;
#ifdef ROCE_BONDING_EN
	struct net_device *upper = NULL;
#endif
	enum ib_mtu mtu;
	enum mag_cmd_port_speed speed = PORT_SPEED_10GB;
	int ret = 0;

	rdev = to_roce3_dev(ibdev);
	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE] %s: HCA not present(return fail), func_id(%u), dev_name(%s).\n",
			__func__, rdev->glb_func_id, ibdev->name);
		return;
	}

	roce3_set_ib_port_attr(props, rdev);

	ret = hinic3_get_speed(rdev->hwdev, &speed, HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to get speed, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		props->active_width = 0;
		props->active_speed = 0;
		return;
	}

	eth_link_get_speed(props, speed);

	netdev = roce3_ib_get_netdev(ibdev, ROCE_DEFAULT_PORT_NUM);
	if (netdev == NULL)
		return;

#ifdef ROCE_BONDING_EN
	if (roce3_bond_is_active(rdev)) {
		rcu_read_lock();
		upper = netdev_master_upper_dev_get_rcu(netdev);
		if (upper != NULL) {
			dev_put(netdev);
			netdev = upper;
			dev_hold(netdev);
		}
		rcu_read_unlock();
	}
#endif

	if (netif_running(netdev) && netif_carrier_ok(netdev)) {
		props->state = IB_PORT_ACTIVE;
		props->phys_state = ROCE_PORT_PHYS_STATE_LINKUP;
	}

	mtu = (enum ib_mtu)iboe_get_mtu((int)netdev->mtu);

	dev_put(netdev);

	props->active_mtu = ROCE_MIN(props->max_mtu, mtu);
}

/*
 ****************************************************************************
 Prototype	: roce3_query_port
 Description  : query port attribute
 Input		: struct ib_device *ibdev
				u8 port
				struct ib_port_attr *props
 Output	   : struct ib_port_attr *props

  1.Date		 : 2015/5/8
	Modification : Created function

****************************************************************************
*/
int roce3_query_port(struct ib_device *ibdev, u8 port, struct ib_port_attr *props)
{
	if ((ibdev == NULL) || (props == NULL)) {
		pr_err("[ROCE] %s: Ibdev or props is null\n", __func__);
		return -EINVAL;
	}

	memset(props, 0, sizeof(*props));

	eth_link_query_port(ibdev, port, props);

	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_query_gid
 Description  : query gid
 Input		: struct ib_device *ibdev
				u8 port
				int index
				union ib_gid *gid
 Output	   : union ib_gid *gid

  1.Date		 : 2015/5/8
	Modification : Created function

  2.Date		 : 2015/6/8
	Modification : Modify function

****************************************************************************
*/
int roce3_query_gid(struct ib_device *ibdev, u8 port, int index, union ib_gid *gid)
{
	int ret = 0;
	struct roce3_device *rdev = NULL;
	struct rdma_gid_entry gid_entry;

	if ((ibdev == NULL) || (gid == NULL)) {
		pr_err("[ROCE] %s: Ibdev or gid is null\n", __func__);
		return -EINVAL;
	}

	rdev = to_roce3_dev(ibdev);
	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -EPERM;
	}

	ret = roce3_rdma_get_gid(rdev->hwdev, (u32)port, (u32)index, &gid_entry);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to get gid, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return ret;
	}

	memcpy((void *)gid->raw, (void *)gid_entry.raw, sizeof(*gid));

	// 按照OFED的gid生成方式转换GID, 仅IPv4场景需要转换
	if (gid_entry.dw6_h.bs.gid_type == ROCE_IPv4_ROCEv2_GID) {
		// 未add的gid直接返回，不需要转换
		if ((gid->global.subnet_prefix == 0) && (gid->global.interface_id == 0))
			return 0;
		ipv6_addr_set_v4mapped(*((u32 *)(void *)gid + ROCE_GID_IP_IDX),
			(struct in6_addr *)gid);
	}

	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_query_pkey
 Description  : query pkey
 Input		: struct ib_device *ibdev
				u8 port
				u16 index
				u16 *pkey
 Output	   : u16 *pkey

  1.Date		 : 2015/5/8
	Modification : Created function

****************************************************************************
*/
int roce3_query_pkey(struct ib_device *ibdev, u8 port, u16 index, u16 *pkey)
{
	struct roce3_device *rdev = NULL;

	if ((ibdev == NULL) || (pkey == NULL)) {
		pr_err("[ROCE] %s: Ibdev or pkey is null\n", __func__);
		return -EINVAL;
	}

	rdev = to_roce3_dev(ibdev);
	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -EPERM;
	}

	if (pkey == NULL) {
		pr_err("[ROCE] %s: Pkey is null\n", __func__);
		return -EINVAL;
	}

	*pkey = 0xffff;

	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_modify_device
 Description  : modify device attribute
 Input		: struct ib_device *ibdev
				int mask
				struct ib_device_modify *props
 Output	   : None

  1.Date		 : 2015/5/8
	Modification : Created function

****************************************************************************
*/
int roce3_modify_device(struct ib_device *ibdev, int mask, struct ib_device_modify *props)
{
	unsigned long flags = 0;
	struct roce3_device *rdev = NULL;

	if ((ibdev == NULL) || (props == NULL)) {
		pr_err("[ROCE] %s: Ibdev or props is null\n", __func__);
		return -EINVAL;
	}

	if (((unsigned int)mask & ~IB_DEVICE_MODIFY_NODE_DESC) != 0) {
		pr_err("[ROCE] %s: Not supported to modify node description\n", __func__);
		return -EOPNOTSUPP;
	}

	if ((((u32)mask) & IB_DEVICE_MODIFY_NODE_DESC) == 0) {
		pr_info("[ROCE] %s: No need to modify node description\n", __func__);
		return 0;
	}

	rdev = to_roce3_dev(ibdev);
	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -EPERM;
	}

	spin_lock_irqsave(&rdev->node_desc_lock, flags);
	memcpy((void *)ibdev->node_desc, (void *)props->node_desc, IB_DEVICE_NODE_DESC_MAX);
	spin_unlock_irqrestore(&rdev->node_desc_lock, flags);

	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_modify_port
 Description  : modify port attribute
 Input		: struct ib_device *ibdev
				u8 port
				int mask
				struct ib_port_modify *props
 Output	   : None

  1.Date		 : 2015/5/8
	Modification : Created function

****************************************************************************
*/
int roce3_modify_port(struct ib_device *ibdev, u8 port, int mask, struct ib_port_modify *props)
{
	int ret = 0;
	struct ib_port_attr attr;
	struct roce3_device *rdev = NULL;

	if (ibdev == NULL) {
		pr_err("[ROCE] %s: Ibdev is null\n", __func__);
		return -EINVAL;
	}

	rdev = to_roce3_dev(ibdev);
	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -EPERM;
	}

	memset(&attr, 0, sizeof(struct ib_port_attr));

	mutex_lock(&rdev->cap_mask_mutex);

	ret = roce3_query_port(ibdev, port, &attr);
	if (ret != 0)
		dev_err(rdev->hwdev_hdl,
		"[ROCE, ERR] %s: Failed to query port, func_id(%d)\n",
		__func__, rdev->glb_func_id);

	mutex_unlock(&rdev->cap_mask_mutex);

	return ret;
}

static void roce3_alloc_ucontext_set(struct roce3_device *rdev,
	struct roce3_alloc_ucontext_resp *resp)
{
	struct rdma_service_cap *rdma_cap = NULL;

	rdma_cap = &rdev->rdma_cap;

	resp->num_qps = rdma_cap->dev_rdma_cap.roce_own_cap.max_qps;
	resp->num_xsrqs = rdma_cap->dev_rdma_cap.roce_own_cap.max_srqs;
	resp->cqe_size = rdma_cap->cqe_size;
	resp->wqebb_size = rdma_cap->wqebb_size;
	resp->dwqe_size = rdma_cap->direct_wqe_size;
	resp->max_msg_size = rdma_cap->dev_rdma_cap.roce_own_cap.max_msg_sz;
	resp->max_comp_vector = rdma_cap->num_comp_vectors;
	resp->max_inline_size = rdma_cap->dev_rdma_cap.roce_own_cap.max_sq_inline_data_sz;

	resp->storage_aa_en = roce3_is_roceaa(rdev->cfg_info.scence_id);
	resp->phy_port = rdev->hw_info.phy_port;
	resp->srq_container_en = rdev->cfg_info.srq_container_en;
	resp->srq_container_mode = rdev->cfg_info.srq_container_mode;
	resp->xrc_srq_container_mode = rdev->cfg_info.xrc_srq_container_mode;
	resp->warn_th = rdev->cfg_info.warn_th;

	roce3_resp_set_ext(rdev, resp);
}

static int roce3_alloc_ucontext_pre_check(struct ib_device *ibdev, const struct ib_udata *udata)
{
	struct roce3_device *rdev = NULL;

	if ((ibdev == NULL) || (udata == NULL)) {
		pr_err("[ROCE] %s: Ibdev or udata is null\n", __func__);
		return -EINVAL;
	}

	rdev = to_roce3_dev(ibdev);
	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -EPERM;
	}

	if (!rdev->ib_active) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Device is abnormal, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return -EAGAIN;
	}

	return 0;
}

static int roce3_alloc_ucontext_return(struct roce3_device *rdev, struct ib_udata *udata,
	struct roce3_ucontext *context, struct roce3_alloc_ucontext_resp *resp)
{
	int ret;

	resp->db_offset = context->db_dma_addr & ((1 << PAGE_SHIFT) - 1);
	resp->dwqe_offset = context->dwqe_dma_addr & ((1 << PAGE_SHIFT) - 1);

	if (context->dwqe_dma_addr == 0)
		resp->dwqe_size = 0;

	roce3_ucontext_set_ext(rdev, context);

	INIT_LIST_HEAD(&context->db_page_list);
	mutex_init(&context->db_page_mutex);

	/* Copy data to user space */
	ret = ib_copy_to_udata_ext(udata, resp);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to copy data to user space, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return ret;
	}

	return 0;
}

int roce3_alloc_ucontext(struct ib_ucontext *ibucontext, struct ib_udata *udata)
{
	int ret;
	struct roce3_ucontext *context = rdma_udata_to_drv_context(
		udata, struct roce3_ucontext, ibucontext);
	struct roce3_device *rdev = to_roce3_dev(ibucontext->device);
	struct roce3_alloc_ucontext_resp *resp = NULL;

	ret = roce3_alloc_ucontext_pre_check(ibucontext->device, udata);
	if (ret != 0)
		return ret;

	resp = roce3_resp_alloc_ext();
	if (resp == NULL) {
		ret = (-ENOMEM);
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc ucontext, func_id(%u)\n",
			__func__, rdev->glb_func_id);
		goto err;
	}

	roce3_alloc_ucontext_set(rdev, resp);
	/* Alloc user space context Doorbell and DWQE */
	ret = hinic3_alloc_db_phy_addr(rdev->hwdev, &context->db_dma_addr, &context->dwqe_dma_addr);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc DB pa, ret(%d), func_id(%u)\n",
			__func__, ret, rdev->glb_func_id);
		goto err_db;
	}

	/* Copy data to user space */
	ret = roce3_alloc_ucontext_return(rdev, udata, context, resp);
	if (ret != 0)
		goto err_return;

	kfree(resp);

	return 0;
err_return:
	hinic3_free_db_phy_addr(rdev->hwdev, context->db_dma_addr, context->dwqe_dma_addr);
err_db:
	kfree(resp);
err:
	return ret;
}

void roce3_dealloc_ucontext(struct ib_ucontext *ibcontext)
{
	struct roce3_ucontext *context = NULL;
	struct roce3_device *rdev = NULL;

	if (ibcontext == NULL) {
		pr_err("[ROCE] %s: Ibcontext is null\n", __func__);
		return;
	}

	context = to_roce3_ucontext(ibcontext);
	rdev = to_roce3_dev(ibcontext->device);

	hinic3_free_db_phy_addr(rdev->hwdev, context->db_dma_addr, context->dwqe_dma_addr);
}

/*
 ****************************************************************************
 Prototype	: roce3_mmap
 Description  : memory map
 Input		: struct ib_ucontext *ibcontext
				struct vm_area_struct *vma
 Output	   : None

  1.Date		 : 2015/5/8
	Modification : Created function

****************************************************************************
*/
int roce3_mmap(struct ib_ucontext *ibcontext, struct vm_area_struct *vma)
{
	struct roce3_device *rdev = NULL;
	struct roce3_ucontext *ucontext = NULL;
	unsigned long db_pfn = 0;
	unsigned long dwqe_pfn = 0;
	int res = 0;

	if ((ibcontext == NULL) || (vma == NULL)) {
		pr_err("[ROCE] %s: Ibcontext or vma is null\n", __func__);
		return -EINVAL;
	}

	rdev = to_roce3_dev(ibcontext->device);
	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -EPERM;
	}

	ucontext = to_roce3_ucontext(ibcontext);
	db_pfn = ucontext->db_dma_addr >> PAGE_SHIFT;
	dwqe_pfn = ucontext->dwqe_dma_addr >> PAGE_SHIFT;

	if ((vma->vm_end - vma->vm_start) != PAGE_SIZE) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: (Vm_end - vm_start) is not equal to PAGE_SIZE, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		return -EINVAL;
	}

	/* map hw DB to physical page from user */
	if (vma->vm_pgoff == USR_MMAP_DB_OFFSET) {
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		/* construct vm_start~vm_start+PAGE_SIZE page table
		 * db_pfn is page number
		 * vm_page_prot means attr
		 */
		if (io_remap_pfn_range(vma, vma->vm_start, db_pfn, PAGE_SIZE,
			vma->vm_page_prot) != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to do db io remap, func_id(%d)\n",
				__func__, rdev->glb_func_id);
			return -EAGAIN;
		}
		return 0;
	}
	// DWQE mmap
	if ((vma->vm_pgoff == USR_MMAP_DWQE_OFFSET) && (rdev->rdma_cap.direct_wqe_size != 0)) {
#ifdef __aarch64__
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
#else
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
#endif

		if (io_remap_pfn_range(vma, vma->vm_start, dwqe_pfn, PAGE_SIZE,
			vma->vm_page_prot) != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to do dwqe io remap, func_id(%d)\n",
				__func__, rdev->glb_func_id);
			return -EAGAIN;
		}
		return 0;
	}

	res = roce3_mmap_ext(rdev, ucontext, vma);
	return res;
}

enum rdma_link_layer roce3_port_link_layer(struct ib_device *ibdev, u8 port_num)
{
	struct roce3_device *rdev = NULL;

	if (ibdev == NULL)
		return IB_LINK_LAYER_UNSPECIFIED;

	rdev = to_roce3_dev(ibdev);
	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return IB_LINK_LAYER_UNSPECIFIED;
	}

	if (port_num != ROCE_DEFAULT_PORT_NUM)
		return IB_LINK_LAYER_UNSPECIFIED;

	return IB_LINK_LAYER_ETHERNET;
}

static void roce3_resolve_cb(int status, struct sockaddr *src_addr,
	struct rdma_dev_addr *addr, void *context)
{
	((struct roce3_resolve_cb_context *)context)->status = status;
	complete(&((struct roce3_resolve_cb_context *)context)->comp);
}

static int roce3_rdma_addr_find_l2_eth_by_grh(const union ib_gid *sgid, const union ib_gid *dgid,
	u8 *dmac, const struct net_device *ndev, int *hoplimit, struct roce3_device *rdev)
{
	struct rdma_dev_addr dev_addr;
	struct roce3_resolve_cb_context ctx;
	union {
		struct sockaddr _sockaddr;
		struct sockaddr_in _sockaddr_in;
		struct sockaddr_in6 _sockaddr_in6;
	} sgid_addr, dgid_addr;
	int ret;

	rdma_gid2ip((struct sockaddr *)&sgid_addr, sgid);
	rdma_gid2ip((struct sockaddr *)&dgid_addr, dgid);

	memset(&dev_addr, 0, sizeof(dev_addr));

	if (ndev) {
		dev_addr.bound_dev_if = ndev->ifindex;
		dev_addr.net = dev_net(ndev);
	} else {
		dev_addr.net = &init_net;
	}

	init_completion(&ctx.comp);
	ret = rdma_resolve_ip(&sgid_addr._sockaddr, &dgid_addr._sockaddr, &dev_addr,
		RESOLVE_IP_TIME_OUT, roce3_resolve_cb, false, &ctx);
	if (ret != 0) {
		pr_err("[ROCE] %s: rdma_resolve_ip failed. Igonore the err.\n", __func__);
		roce3_resolve_cb(0, &sgid_addr._sockaddr, &dev_addr, &ctx);
	}

	wait_for_completion(&ctx.comp);

	memcpy(dmac, dev_addr.dst_dev_addr, ETH_ALEN);
	if (hoplimit)
		*hoplimit = dev_addr.hoplimit;

	return 0;
}

static int roce3_ah_valid_check(struct ib_global_route *grh, u16 *vlan_id, u8 *dmac)
{
	u8 unicast_gid0[ROCE_GID_LEN] = { 0 };
	u8 unicast_gid1[ROCE_GID_LEN] = { 0 };

	/* check gid(unicast gid can not be 0 or 1) */
	unicast_gid0[ROCE_GID_HIGHEST_BYTE] = 0;
	unicast_gid1[ROCE_GID_HIGHEST_BYTE] = 1;

	if ((ROCE_MEMCMP(grh->dgid.raw, unicast_gid0, sizeof(union ib_gid)) == 0) ||
		(ROCE_MEMCMP(grh->dgid.raw, unicast_gid1, sizeof(union ib_gid)) == 0)) {
		pr_err("[ROCE] %s: Invalid unicast dgid\n", __func__);
		return (-EINVAL);
	}

	if (rdma_link_local_addr((struct in6_addr *)grh->dgid.raw) != 0) {
		rdma_get_ll_mac((struct in6_addr *)grh->dgid.raw, dmac);
		*vlan_id = ROCE_DEFAULT_VLAN_ID;
	}

	return 0;
}

static int roce3_fill_gid_attr(struct roce3_device *rdev, struct rdma_ah_attr *ah_attr,
	union ib_gid *sgid, const struct ib_gid_attr **sgid_attr)
{
	int ret = 0;

	ret = rdma_query_gid(&rdev->ib_dev, ah_attr->port_num, ah_attr->grh.sgid_index, sgid);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE, ERR] : Failed to query gid func_id(%u),port_num(%d),gid_index(%d),ret(%d)\n",
			rdev->glb_func_id, ah_attr->port_num, ah_attr->grh.sgid_index, ret);
		return ret;
	}

	*sgid_attr = rdma_get_gid_attr(&rdev->ib_dev, ah_attr->port_num, ah_attr->grh.sgid_index);
	if (IS_ERR_OR_NULL(*sgid_attr)) {
		ret = (int)PTR_ERR(*sgid_attr);
		dev_err(rdev->hwdev_hdl,
			"[ROCE] : Failed to get sgid_attr, func_id(%u), ret(%d).\n",
			rdev->glb_func_id, ret);
		return ret;
	}

	return ret;
}

static void roce3_release_gid_ref_cnt(const struct ib_gid_attr *sgid_attr)
{
	rdma_put_gid_attr(sgid_attr);
}

static struct net_device *roce3_fill_netdev(struct roce3_device *rdev, union ib_gid *sgid)
{
	struct net_device *netdev = NULL;
	union {
		struct sockaddr _sockaddr;
		struct sockaddr_in _sockaddr_in;
		struct sockaddr_in6 _sockaddr_in6;
	} socket_addr;

	rdma_gid2ip((struct sockaddr *)&socket_addr, sgid);

	/* find netdev,rdev->ndevis not valid in vlan scenario */
	netdev = ip_dev_find(&init_net,
		((const struct sockaddr_in *)&socket_addr._sockaddr)->sin_addr.s_addr);
	if (netdev)
		dev_put(netdev);

	return netdev;
}

int roce3_resolve_grh(struct roce3_device *rdev, struct rdma_ah_attr *ah_attr,
	u16 *vlan_id, struct ib_udata *udata)
{
	int ret = 0;
	u8 zero_mac[ETH_ALEN] = { 0 };
	u8 *dmac = NULL;
	union ib_gid sgid;
	const struct ib_gid_attr *sgid_attr = NULL;
	struct net_device *netdev = NULL;

	if ((rdev == NULL) || (ah_attr == NULL) || (vlan_id == NULL)) {
		pr_err("[ROCE, ERR] %s: Input pointer is NULL, rdev(%p), ah_attr(%p), vlan_id(%p).\n",
			__func__, rdev, ah_attr, vlan_id);
		return (-EINVAL);
	}

	dmac = ah_attr->roce.dmac;
	ret = roce3_ah_valid_check(&ah_attr->grh, vlan_id, dmac);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] : Failed to check grh input, func_id(%u), ret(%d).\n",
			rdev->glb_func_id, ret);
		return ret;
	}
	if (ROCE_MEMCMP(dmac, zero_mac, ETH_ALEN) != 0)
		return 0;

	ret = roce3_fill_gid_attr(rdev, ah_attr, &sgid, &sgid_attr);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] : Failed to fill gid attr, func_id(%u), ret(%d)\n",
			rdev->glb_func_id, ret);
		return ret;
	}

	netdev = roce3_fill_netdev(rdev, &sgid);

	/* reparse dmac avoiding invalid damc from OFED */
	ret = roce3_rdma_addr_find_l2_eth_by_grh(&sgid, &ah_attr->grh.dgid, dmac,
		netdev, NULL, rdev);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] : Failed to find dmac by grh, func_id(%u)\n",
			rdev->glb_func_id);
		goto resolve_grh_end;
	}

	if (ROCE_MEMCMP(dmac, zero_mac, ETH_ALEN) == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] : Failed to find valid dmac, func_id(%u)\n",
			rdev->glb_func_id);
		ret = (-EINVAL);
		goto resolve_grh_end;
	}

	*vlan_id = rdma_vlan_dev_vlan_id(sgid_attr->ndev);

resolve_grh_end:
	roce3_release_gid_ref_cnt(sgid_attr);

	return ret;
}

static int ah_get_vlan_id(struct roce3_device *rdev, struct ib_pd *pd,
	struct rdma_ah_attr *ah_attr, u32 *vlan_id)
{
	struct net_device *ndev;

	rcu_read_lock();
	ndev = rcu_dereference(ah_attr->grh.sgid_attr->ndev);
	if (ndev == NULL) {
		rcu_read_unlock();
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] : Net device is NULL, func_id(%u)\n", rdev->glb_func_id);
		return -EINVAL;
	}
	*vlan_id = rdma_vlan_dev_vlan_id(ndev);
	rcu_read_unlock();

	return 0;
}

static int create_ib_ah(struct roce3_device *rdev, struct ib_pd *pd, struct roce3_ah *rah,
	struct rdma_ah_attr *ah_attr)
{
	int ret;
	u8 *dmac = ah_attr->roce.dmac;
	u32 vlan_id = 0;

	ret = ah_get_vlan_id(rdev, pd, ah_attr, &vlan_id);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to get vlan_id (ret:%d)\n", __func__, ret);
		return -EFAULT;
	}

	if (((u32)rdma_ah_get_ah_flags(ah_attr) & IB_AH_GRH) != 0) {
		memcpy((void *)rah->priv_ah.dgid, (void *)ah_attr->grh.dgid.raw,
			sizeof(rah->priv_ah.dgid));
		rah->priv_ah.dw2.bs.flow_label = ah_attr->grh.flow_label & 0xfffff;
		rah->priv_ah.dw1.bs.sgid_index = ah_attr->grh.sgid_index & 0x7f;
		rah->priv_ah.dw1.bs.hoplimit = ah_attr->grh.hop_limit;
		rah->priv_ah.dw1.bs.tclass = (u8)(ah_attr->grh.traffic_class | 0x2);
	}
	rah->priv_ah.dw0.bs.pd = to_roce3_pd(pd)->pdn & 0x3ffff;
	rah->priv_ah.dw0.bs.wqe_cos = roce3_get_db_cos_from_vlan_pri(rdev, ah_attr->sl);
	rah->priv_ah.dw0.value = cpu_to_be32(rah->priv_ah.dw0.value);

	rah->priv_ah.dw1.bs.port = ah_attr->port_num & 0xf;
	rah->priv_ah.dw2.bs.smac_index = rdev->glb_func_id; /* set global Function ID */
	rah->priv_ah.dw2.value = cpu_to_be32(rah->priv_ah.dw2.value);

	rah->priv_ah.dw1.bs.resv = 0;
	rah->priv_ah.dw7.bs.vlan_id = vlan_id & 0xfff;
	rah->priv_ah.dw7.bs.vlan_pri = ah_attr->sl & 0x7;

	rah->priv_ah.dw1.value = cpu_to_be32(rah->priv_ah.dw1.value);

	rah->priv_ah.dw7.bs.dmac_h16 = (dmac[0] << ROCE_RAH_DMAC_H16_SHIFT) | dmac[1];
	rah->priv_ah.dw7.value = cpu_to_be32(rah->priv_ah.dw7.value);

	memcpy((void *)&rah->priv_ah.dmac_l32,
		(void *)&dmac[ROCE_RAH_DMAC_L32_START], sizeof(rah->priv_ah.dmac_l32));

	return 0;
}

int roce3_create_ah(struct ib_ah *ibah, struct rdma_ah_init_attr *init_attr, struct ib_udata *udata)
{
	struct roce3_ah *rah = to_roce3_ah(ibah);
	struct roce3_device *rdev = to_roce3_dev(ibah->device);
	struct rdma_ah_attr *ah_attr = init_attr->ah_attr;
	enum rdma_ah_attr_type ah_type = ah_attr->type;

	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -EPERM;
	}

	if ((ah_type == RDMA_AH_ATTR_TYPE_ROCE) && (((u32)rdma_ah_get_ah_flags(ah_attr)
		& IB_AH_GRH) == 0))
		return -EINVAL;

	return create_ib_ah(rdev, ibah->pd, rah, ah_attr);
}

int roce3_query_ah(struct ib_ah *ibah, struct rdma_ah_attr *ah_attr)
{
	struct roce3_ah *ah = NULL;
	struct roce3_priv_ah priv_ah;

	if ((ibah == NULL) || (ah_attr == NULL)) {
		pr_err("[ROCE] %s: Ibah or ah_attr is null\n", __func__);
		return -EINVAL;
	}

	ah = to_roce3_ah(ibah);
	memset(ah_attr, 0, sizeof(*ah_attr));

	priv_ah.dw1.value = be32_to_cpu(ah->priv_ah.dw1.value);
	priv_ah.dw2.value = be32_to_cpu(ah->priv_ah.dw2.value);
	priv_ah.dw7.value = be32_to_cpu(ah->priv_ah.dw7.value);

	ah_attr->ah_flags = IB_AH_GRH;
	ah_attr->sl = priv_ah.dw7.bs.vlan_pri;
	ah_attr->port_num = priv_ah.dw1.bs.port;
	ah_attr->grh.traffic_class = priv_ah.dw1.bs.tclass;
	ah_attr->grh.hop_limit = priv_ah.dw1.bs.hoplimit;
	ah_attr->grh.sgid_index = priv_ah.dw1.bs.sgid_index;
	ah_attr->grh.flow_label = priv_ah.dw2.bs.flow_label;

	memcpy((void *)ah_attr->grh.dgid.raw, (void *)ah->priv_ah.dgid,
		sizeof(ah->priv_ah.dgid));
	return 0;
}

int roce3_destroy_ah(struct ib_ah *ibah, u32 flags)
{
	return 0;
}

int roce3_port_immutable(struct ib_device *ibdev, u8 port_num, struct ib_port_immutable *immutable)
{
	struct ib_port_attr attr;
	int err;
	struct roce3_device *rdev = to_roce3_dev(ibdev);

	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -EPERM;
	}
	immutable->core_cap_flags = RDMA_CORE_PORT_IBA_ROCE_UDP_ENCAP; // only rocev2

	err = ib_query_port(ibdev, port_num, &attr);
	if (err != 0) {
		pr_err("[ROCE] %s: query ib port failed\n", __func__);
		return err;
	}

	immutable->pkey_tbl_len = attr.pkey_tbl_len;
	immutable->gid_tbl_len = attr.gid_tbl_len;
	immutable->max_mad_size = IB_MGMT_MAD_SIZE;

	return 0;
}

int roce3_get_dcb_cfg_cos(struct roce3_device *rdev, struct roce3_get_cos_inbuf *inbuf, u8 *cos)
{
	int ret;
	u8 pri;
	struct rdma_gid_entry gid;
	struct hinic3_dcb_state dcb = { 0 };

	ret = roce3_rdma_get_gid(rdev->hwdev, inbuf->port_num, inbuf->sgid_index, &gid);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to init gid info\n", __func__);
		return (-EINVAL);
	}

	ret = hinic3_get_dcb_state(rdev->hwdev, &dcb);
	if (ret != 0) {
		pr_err("[ROCE] %s: hinic3_get_dcb_state failed.ret: %d.\n", __func__, ret);
		return (-EINVAL);
	}

	*cos = dcb.default_cos;
	gid.dw6_h.value = cpu_to_le16(gid.dw6_h.value);
	if ((dcb.trust == ROCE3_DCB_PCP) && (gid.dw6_h.bs.tag == ROCE_GID_VLAN_INVALID)) {
		// pcp cfg & no vlan should use default cos
		return 0;
	}

	pri = (dcb.trust == ROCE3_DCB_PCP) ? inbuf->sl : (inbuf->traffic_class >> ROCE3_DSCP_IDX);
	ret = hinic3_get_cos_by_pri(rdev->hwdev, pri, cos);
	if (ret != 0) {
		pr_err("[ROCE] %s: get_cos_by_pri failed.ret: %d, pri:%u, dcb_on:%u, trust:%u.\n",
			__func__, ret, pri, dcb.dcb_on, dcb.trust);
		return (-EINVAL);
	}

	return 0;
}
