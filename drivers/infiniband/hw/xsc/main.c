// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/namei.h>
#include <linux/kobject.h>
#include <linux/kernfs.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/io-mapping.h>
#include <linux/sched.h>
#include <linux/netdevice.h>
#include <net/bonding.h>
#include "common/xsc_core.h"
#include "common/xsc_hsi.h"
#include "common/xsc_cmd.h"
#include "common/driver.h"
#include "common/xsc_lag.h"

#include <rdma/ib_user_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_umem.h>

#include "user.h"
#include "xsc_ib.h"
#include "xsc_rdma_ctrl.h"
#include "xsc_rdma_prgrmmbl_cc_ctrl.h"
#include "xsc_sample_ctrl.h"

#define DRIVER_NAME "xsc_ib"

MODULE_DESCRIPTION("Yunsilicon HCA IB driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRIVER_VERSION);

static int xsc_ib_query_device(struct ib_device *ibdev,
			       struct ib_device_attr *props,
			       struct ib_udata *udata)
{
	struct xsc_ib_dev *dev = to_mdev(ibdev);
	int max_rq_sg;
	int max_sq_sg;
	u64 flags;
	struct xsc_ib_query_device_resp resp;
	size_t resp_len;
	u64 max_tso;
	int err = -ENOMEM;
	union xsc_ib_fw_ver fw_ver;

	memset(&resp, 0, sizeof(resp));
	memset(props, 0, sizeof(*props));

	resp_len = sizeof(resp.comp_mask) + sizeof(resp.response_length);
	/*check param*/
	if (udata->outlen && udata->outlen < resp_len)
		return -EINVAL;

	if (udata->inlen && !ib_is_udata_cleared(udata, 0, udata->inlen))
		return -EINVAL;

	resp.response_length = resp_len;

	fw_ver.data = 0;
	fw_ver.s.ver_major = dev->xdev->fw_version_major;
	fw_ver.s.ver_minor = dev->xdev->fw_version_minor;
	fw_ver.s.ver_patch = dev->xdev->fw_version_patch;
	fw_ver.s.ver_tweak = dev->xdev->fw_version_tweak;
	props->fw_ver = fw_ver.data;

	props->device_cap_flags    = IB_DEVICE_CHANGE_PHY_PORT |
		IB_DEVICE_PORT_ACTIVE_EVENT		|
		IB_DEVICE_SYS_IMAGE_GUID		|
		IB_DEVICE_RC_RNR_NAK_GEN;
	props->kernel_cap_flags =  IBK_BLOCK_MULTICAST_LOOPBACK;
	props->kernel_cap_flags |= IBK_LOCAL_DMA_LKEY;

	flags = dev->xdev->caps.flags;
	if (flags & XSC_DEV_CAP_FLAG_BAD_PKEY_CNTR)
		props->device_cap_flags |= IB_DEVICE_BAD_PKEY_CNTR;
	if (flags & XSC_DEV_CAP_FLAG_BAD_QKEY_CNTR)
		props->device_cap_flags |= IB_DEVICE_BAD_QKEY_CNTR;
	if (flags & XSC_DEV_CAP_FLAG_APM)
		props->device_cap_flags |= IB_DEVICE_AUTO_PATH_MIG;
	if (flags & XSC_DEV_CAP_FLAG_XRC)
		props->device_cap_flags |= IB_DEVICE_XRC;
	props->device_cap_flags |= IB_DEVICE_MEM_MGT_EXTENSIONS;

	props->page_size_cap	   = dev->xdev->caps.min_page_sz;
	props->max_mr_size	   = xsc_get_max_mr_size(dev->xdev);
	props->max_qp		   = dev->xdev->caps.max_qp;
	props->max_qp_wr	   = xsc_get_max_qp_depth(dev->xdev);
	max_rq_sg = dev->xdev->caps.max_rq_desc_sz / sizeof(struct xsc_wqe_data_seg);
	max_sq_sg = (dev->xdev->caps.max_sq_desc_sz - sizeof(struct xsc_wqe_ctrl_seg_2)) /
		sizeof(struct xsc_wqe_data_seg_2);

	props->max_send_sge = dev->xdev->caps.send_ds_num - XSC_CTRL_SEG_NUM -
		XSC_RADDR_SEG_NUM;
	props->max_recv_sge = dev->xdev->caps.recv_ds_num;
	props->max_sge_rd	   = 1;/*max sge per read wqe*/
	props->max_cq		   = dev->xdev->caps.max_cq;
	props->max_cqe		   = dev->xdev->caps.max_cqes;
	props->max_mr		   = (1 << dev->xdev->caps.log_max_mkey) - 1;
	props->max_pd		   = dev->xdev->caps.max_pd;
	props->max_qp_rd_atom	   = dev->xdev->caps.max_ra_res_qp;
	props->max_qp_init_rd_atom = dev->xdev->caps.max_ra_req_qp;
	props->max_res_rd_atom	   = props->max_qp_rd_atom * props->max_qp;
	props->max_srq		   = xsc_max_srq ?
		roundup_pow_of_two(min_t(unsigned int, xsc_max_srq, XSC_MAX_SRQ_NUM)) : 0;
	props->max_srq_wr	   = dev->xdev->caps.max_srq_wqes;
	props->max_srq_sge	   = 4;
	props->max_fast_reg_page_list_len = (unsigned int)-1;
	props->local_ca_ack_delay  = dev->xdev->caps.local_ca_ack_delay;
	props->atomic_cap	   = is_support_rdma_atomic(dev->xdev) ?
		IB_ATOMIC_HCA : IB_ATOMIC_NONE;
	props->masked_atomic_cap   = IB_ATOMIC_HCA;
	props->max_mcast_grp	   =
		dev->xdev->caps.log_max_mcg ? (1 << dev->xdev->caps.log_max_mcg) : 0;
	props->max_mcast_qp_attach = dev->xdev->caps.max_qp_mcg;
	props->max_total_mcast_qp_attach = props->max_mcast_qp_attach *
					   props->max_mcast_grp;

	props->sys_image_guid = dev->xdev->board_info->guid;
	props->vendor_id = dev->xdev->pdev->vendor;
	props->vendor_part_id = dev->xdev->pdev->device;
	props->hw_ver = ((dev->xdev->chip_ver_l & 0xffff) << 16) |
		(dev->xdev->hotfix_num & 0xffff);
	props->max_pkeys = 0x80;
	props->max_wq_type_rq = dev->xdev->caps.max_qp;
#ifdef HAVE_IB_DEV_ATTR_MAX_SGL_RD
	props->max_sgl_rd = dev->xdev->caps.max_sgl_rd;
#endif

	props->hca_core_clock = dev->xdev->caps.hca_core_clock * 1000;//KHz
	props->rss_caps.max_rwq_indirection_tables =
		dev->xdev->caps.max_rwq_indirection_tables;
	props->rss_caps.max_rwq_indirection_table_size =
		dev->xdev->caps.max_rwq_indirection_table_size;
	props->rss_caps.supported_qpts = 1 << IB_QPT_RAW_PACKET;

	/*response tso_caps extend param*/
	if (field_avail(typeof(resp), tso_caps, udata->outlen)) {
		max_tso = dev->xdev->caps.log_max_tso ? (1 << dev->xdev->caps.log_max_tso) : 0;
		if (max_tso) {
			resp.tso_caps.max_tso = max_tso;
			resp.tso_caps.supported_qpts |= 1 << IB_QPT_RAW_PACKET;
			resp.response_length += sizeof(resp.tso_caps);
		}
	}

	/*response rss_caps extend param*/
	if (field_avail(typeof(resp), rss_caps, udata->outlen)) {
		resp.rss_caps.rx_hash_function = XSC_RX_HASH_FUNC_TOEPLITZ;
		resp.rss_caps.rx_hash_fields_mask =
			XSC_RX_HASH_SRC_IPV4 |
			XSC_RX_HASH_DST_IPV4 |
			XSC_RX_HASH_SRC_IPV6 |
			XSC_RX_HASH_DST_IPV6 |
			XSC_RX_HASH_SRC_PORT_TCP |
			XSC_RX_HASH_DST_PORT_TCP |
			XSC_RX_HASH_SRC_PORT_UDP |
			XSC_RX_HASH_DST_PORT_UDP |
			XSC_RX_HASH_INNER;
		resp.response_length += sizeof(resp.rss_caps);
	}

	/*response packet pacing caps*/
	if (field_avail(typeof(resp), packet_pacing_caps, udata->outlen)) {
		resp.packet_pacing_caps.qp_rate_limit_max =
			dev->xdev->caps.qp_rate_limit_max;
		resp.packet_pacing_caps.qp_rate_limit_min =
			dev->xdev->caps.qp_rate_limit_min;
		resp.packet_pacing_caps.supported_qpts |= 1 << IB_QPT_RAW_PACKET;

		resp.response_length += sizeof(resp.packet_pacing_caps);
	}

	/*copy response data to user*/
	if (udata->outlen) {
		err = ib_copy_to_udata(udata, &resp, resp.response_length);
		if (err) {
			xsc_ib_err(dev, "copy response info to udata fail,err=%d\n", err);
			return err;
		}
	}

	return 0;
}

static void xsc_calc_link_info(struct xsc_core_device *xdev,
			       struct ib_port_attr *props)
{
	switch (xsc_get_link_speed(xdev)) {
	case MODULE_SPEED_10G:
		props->active_speed = XSC_RDMA_LINK_SPEED_10GB;
		props->active_width = 1;
		break;
	case MODULE_SPEED_25G:
		props->active_speed = XSC_RDMA_LINK_SPEED_25GB;
		props->active_width = 1;
		break;
	case MODULE_SPEED_40G_R4:
		props->active_speed = XSC_RDMA_LINK_SPEED_10GB;
		props->active_width = 2;
		break;
	case MODULE_SPEED_50G_R:
		props->active_speed = XSC_RDMA_LINK_SPEED_50GB;
		props->active_width = 1;
		break;
	case MODULE_SPEED_50G_R2:
		props->active_speed = XSC_RDMA_LINK_SPEED_50GB;
		props->active_width = 1;
		break;
	case MODULE_SPEED_100G_R2:
		props->active_speed = XSC_RDMA_LINK_SPEED_25GB;
		props->active_width = 2;
		break;
	case MODULE_SPEED_100G_R4:
		props->active_speed = XSC_RDMA_LINK_SPEED_25GB;
		props->active_width = 2;
		break;
	case MODULE_SPEED_200G_R4:
		props->active_speed = XSC_RDMA_LINK_SPEED_50GB;
		props->active_width = 2;
		break;
	case MODULE_SPEED_200G_R8:
		props->active_speed = XSC_RDMA_LINK_SPEED_25GB;
		props->active_width = 4;
		break;
	case MODULE_SPEED_400G_R8:
		props->active_speed = XSC_RDMA_LINK_SPEED_50GB;
		props->active_width = 4;
		break;
	case MODULE_SPEED_400G_R4:
		props->active_speed = XSC_RDMA_LINK_SPEED_100GB;
		props->active_width = 2;
		break;
	default:
		props->active_speed = XSC_RDMA_LINK_SPEED_25GB;
		props->active_width = 1;
		break;
	}
}

static enum rdma_link_layer xsc_ib_port_link_layer(struct ib_device *ibdev, u32 port)
{
	return IB_LINK_LAYER_ETHERNET;
}

int xsc_ib_query_port(struct ib_device *ibdev, u32 port,
		      struct ib_port_attr *props)
{
	struct xsc_ib_dev *dev = to_mdev(ibdev);
	struct net_device *ndev = dev->netdev;
	struct xsc_core_device *xdev = dev->xdev;
	struct net_device *upper = NULL;

	if (port < 1 || port > xdev->caps.num_ports) {
		xsc_ib_warn(dev, "invalid port number %d\n", port);
		return -EINVAL;
	}

	memset(props, 0, sizeof(*props));

	if (netif_running(ndev) && netif_carrier_ok(ndev))
		props->state = IB_PORT_ACTIVE;
	else
		props->state = IB_PORT_DOWN;

	props->max_mtu = is_support_8k_mtu(xdev) ? IB_MTU_8192 : IB_MTU_4096;

	if (xsc_lag_is_roce(xdev) || xsc_lag_is_sriov(xdev)) {
		rcu_read_lock();
		upper = netdev_master_upper_dev_get_rcu(ndev);
		if (upper) {
			ndev = upper;
			dev_hold(ndev);
		}
		rcu_read_unlock();
	}

	props->active_mtu = min(props->max_mtu, xsc_net_to_ib_mtu(ndev->mtu));
	props->gid_tbl_len = 256;
	props->port_cap_flags = 0x4010000;
	props->max_msg_sz = 0x40000000;
	props->bad_pkey_cntr = 0;
	props->qkey_viol_cntr = 0;
	props->pkey_tbl_len = 1;
	props->lid = 0;
	props->sm_lid = 0;
	props->lmc = 0;
	props->max_vl_num = 0;
	props->sm_sl = 0;
	props->subnet_timeout = 0;
	props->init_type_reply = 0;
	if (!is_support_rdma(xdev)) {
		props->active_width = 1;
		props->active_speed = XSC_RDMA_LINK_SPEED_25GB;
	} else {
		xsc_calc_link_info(xdev, props);
	}

	props->phys_state = netif_carrier_ok(ndev) ? XSC_RDMA_PHY_STATE_LINK_UP :
				XSC_RDMA_PHY_STATE_DISABLED;

	if (upper)
		dev_put(ndev);

	return 0;
}

const struct xsc_gid xsc_gid_zero;

static int xsc_ib_query_gid(struct ib_device *ibdev, u32 port_num,
			    int index, union ib_gid *gid)
{
	struct xsc_ib_dev *dev = to_mdev(ibdev);
	struct xsc_sgid_tbl *sgid_tbl = &dev->ib_res.sgid_tbl;

	/* Ignore port_num */
	memset(gid, 0, sizeof(*gid));
	if (index >= sgid_tbl->max)
		return -EINVAL;

	memcpy(gid, &sgid_tbl->tbl[index], sizeof(*gid));

	return 0;
}

static int xsc_ib_del_gid(const struct ib_gid_attr *attr, void **context)
{
	int index = 0;
	struct xsc_ib_dev *dev = to_mdev(attr->device);
	struct xsc_gid *gid_raw = (struct xsc_gid *)&attr->gid;
	struct xsc_sgid_tbl *sgid_tbl = &dev->ib_res.sgid_tbl;

	if (attr->port_num > XSC_MAX_PORTS ||
	    (!rdma_cap_roce_gid_table(attr->device, attr->port_num)) ||
	    attr->index >= sgid_tbl->max)
		return -EINVAL;

	if (!sgid_tbl)
		return -EINVAL;

	if (!sgid_tbl->count)
		return -ENOMEM;

	for (index = 0; index < sgid_tbl->max; index++) {
		if (!memcmp(&sgid_tbl->tbl[index], gid_raw, sizeof(*gid_raw)))
			break;
	}

	if (index == sgid_tbl->max)
		return 0;

	memcpy(&sgid_tbl->tbl[index], &xsc_gid_zero, sizeof(xsc_gid_zero));
	sgid_tbl->count--;
	xsc_ib_info(dev, "Del gid from index:%u, count:%u\n", index, sgid_tbl->count);

	return 0;
}

static int xsc_ib_add_gid(const struct ib_gid_attr *attr, void **context)
{
	int i = 0;
	u32 free_idx = 0;
	struct xsc_ib_dev *dev = to_mdev(attr->device);
	struct xsc_gid *gid_raw = (struct xsc_gid *)&attr->gid;
	struct xsc_sgid_tbl *sgid_tbl = &dev->ib_res.sgid_tbl;

	if (!sgid_tbl)
		return -EINVAL;

	if (sgid_tbl->count == sgid_tbl->max)
		return -ENOMEM;

	if (attr->port_num > XSC_MAX_PORTS ||
	    !rdma_cap_roce_gid_table(attr->device, attr->port_num) ||
	    !context)
		return -EINVAL;
	free_idx = sgid_tbl->max;
	for (i = 0; i < sgid_tbl->max; i++) {
		if (!memcmp(&sgid_tbl->tbl[i], gid_raw, sizeof(*gid_raw))) {
			return 0;
		} else if (!memcmp(&sgid_tbl->tbl[i], &xsc_gid_zero, sizeof(xsc_gid_zero)) &&
				free_idx == sgid_tbl->max) {
			free_idx = i;
		}
	}

	if (free_idx == sgid_tbl->max)
		return -ENOMEM;

	memcpy(&sgid_tbl->tbl[free_idx], gid_raw, sizeof(*gid_raw));
	sgid_tbl->count++;
	xsc_ib_info(dev, "Add gid to index:%u, count:%u, max:%u\n", free_idx, sgid_tbl->count,
		    sgid_tbl->max);

	return 0;
}

static int xsc_ib_query_pkey(struct ib_device *ibdev, u32 port, u16 index,
			     u16 *pkey)
{
	*pkey = 0xffff;
	return 0;
}

struct xsc_reg_node_desc {
	u8	desc[64];
};

static int xsc_ib_modify_device(struct ib_device *ibdev, int mask,
				struct ib_device_modify *props)
{
	struct xsc_ib_dev *dev = to_mdev(ibdev);
	struct xsc_reg_node_desc in;
	struct xsc_reg_node_desc out;
	int err;

	return 0;

	if (mask & ~IB_DEVICE_MODIFY_NODE_DESC)
		return -EOPNOTSUPP;

	if (!(mask & IB_DEVICE_MODIFY_NODE_DESC))
		return 0;

	/*
	 * If possible, pass node desc to FW, so it can generate
	 * a 144 trap.  If cmd fails, just ignore.
	 */
	memcpy(&in, props->node_desc, 64);
	err = xsc_core_access_reg(dev->xdev, &in, sizeof(in), &out,
				  sizeof(out), XSC_REG_NODE_DESC, 0, 1);
	if (err)
		return err;

	memcpy(ibdev->node_desc, props->node_desc, 64);

	return err;
}

static int xsc_ib_modify_port(struct ib_device *ibdev, u32 port, int mask,
			      struct ib_port_modify *props)
{
	struct xsc_ib_dev *dev = to_mdev(ibdev);
	struct ib_port_attr attr;
	u32 tmp;
	int err;

	return 0;

	mutex_lock(&dev->cap_mask_mutex);

	err = xsc_ib_query_port(ibdev, port, &attr);
	if (err)
		goto out;

	tmp = (attr.port_cap_flags | props->set_port_cap_mask) &
		~props->clr_port_cap_mask;

	err = xsc_set_port_caps(dev->xdev, port, tmp);

out:
	mutex_unlock(&dev->cap_mask_mutex);
	return err;
}

xsc_ib_alloc_ucontext_def()
{
	struct ib_device *ibdev = uctx->device;
	struct xsc_ib_dev *dev = to_mdev(ibdev);
	struct xsc_ib_alloc_ucontext_req req;
	struct xsc_ib_alloc_ucontext_resp resp;
	struct xsc_ib_ucontext *context;
	int err;

	if (!dev->ib_active)
		return RET_VALUE(-EAGAIN);

	err = ib_copy_from_udata(&req, udata, sizeof(req));
	if (err)
		return RET_VALUE(err);

	if (req.abi_ver != CURRENT_UCONTEXT_ABI_VER && !xsc_is_rdma_comptible_device(dev->xdev)) {
		xsc_ib_err(dev, "ucontext abi version mismatch, user is %d, kernel is %d\n",
			   req.abi_ver, CURRENT_UCONTEXT_ABI_VER);
		return RET_VALUE(-EINVAL);
	}

	memset(&resp, 0, sizeof(resp));
	resp.qp_tab_size      = dev->xdev->caps.max_qp;
	resp.cache_line_size  = L1_CACHE_BYTES;
	resp.max_sq_desc_sz = dev->xdev->caps.max_sq_desc_sz;
	resp.max_rq_desc_sz = dev->xdev->caps.max_rq_desc_sz;
	resp.max_send_wqebb = dev->xdev->caps.max_wqes;
	resp.max_recv_wr = dev->xdev->caps.max_wqes;
	resp.max_srq = xsc_max_srq ?
		roundup_pow_of_two(min_t(unsigned int, xsc_max_srq, XSC_MAX_SRQ_NUM)) : 0;
	resp.max_srq_recv_wr = dev->xdev->caps.max_srq_wqes;
	resp.srq_min_wr_num = min_t(unsigned int, xsc_srq_min_wr, dev->xdev->caps.max_wqes);
	resp.srq_min_wr_num = max_t(unsigned int, resp.srq_min_wr_num, XSC_SRQ_MIN_WR_NUM);
	resp.srq_max_wr_num = min_t(unsigned int, xsc_srq_max_wr, dev->xdev->caps.max_wqes);
	resp.srq_max_wr_num = max_t(unsigned int, resp.srq_max_wr_num, XSC_SRQ_MIN_WR_NUM);
	xsc_get_db_addr(dev->xdev, &resp.qpm_tx_db, &resp.qpm_rx_db,
			&resp.cqm_armdb, &resp.cqm_next_cid_reg, NULL);
	resp.send_ds_num = dev->xdev->caps.send_ds_num;
	resp.recv_ds_num = dev->xdev->caps.recv_ds_num;
	resp.cmds_supp_uhw |= XSC_USER_CMDS_SUPP_UHW_QUERY_DEVICE;
	resp.device_id = dev->xdev->pdev->device;

	if (req.abi_ver >= ALLOC_UCONTEXT_VER_V1) {
		xsc_get_multidb_info(dev->xdev, &resp.multidb_num, &resp.tx_multidb_base);
		resp.rdma_proto_mode = dev->xdev->rdma_proto_mode;
	}

	if (is_support_cqe64(dev->xdev))
		resp.hw_feature_flag |= XSC_HW_FEATURE_FLAG_SUPPORT_CQE64;

	context = to_xucontext(uctx);

	INIT_LIST_HEAD(&context->db_page_list);
	mutex_init(&context->db_page_mutex);

	resp.num_ports = dev->xdev->caps.num_ports;
	err = ib_copy_to_udata(udata, &resp, min_t(int, udata->outlen, sizeof(resp)));
	if (err)
		goto out_ctx;

	return 0;

out_ctx:
	return RET_VALUE(err);
}

xsc_ib_dealloc_ucontext_def()
{
	return;
}

static int xsc_ib_mmap(struct ib_ucontext *ibcontext, struct vm_area_struct *vma)
{
	struct xsc_ib_dev *dev = to_mdev(ibcontext->device);
	struct xsc_core_device *xdev = dev->xdev;
	unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
	resource_size_t reg_base;
	resource_size_t reg_size = vma->vm_end - vma->vm_start;
	u64 tx_db = 0;
	u64 rx_db = 0;
	u64 cq_db = 0;
	u64 cq_reg = 0;

	xsc_get_db_addr(xdev, &tx_db, &rx_db, &cq_db, &cq_reg, NULL);
	xsc_core_dbg(xdev, "offset:0x%lx", offset);

	if (offset == (tx_db & PAGE_MASK))
		reg_base = pci_resource_start(xdev->pdev, xdev->bar_num) + (tx_db & PAGE_MASK);
	else if (offset == (rx_db & PAGE_MASK))
		reg_base = pci_resource_start(xdev->pdev, xdev->bar_num) + (rx_db & PAGE_MASK);
	else if (offset == (cq_reg & PAGE_MASK))
		reg_base = pci_resource_start(xdev->pdev, xdev->bar_num) + (cq_reg & PAGE_MASK);
	else if (offset == (cq_db & PAGE_MASK))
		reg_base = pci_resource_start(xdev->pdev, xdev->bar_num) + (cq_db & PAGE_MASK);
	else if (offset == (QPM_TX_MDB_BASE_REG_ADDR & PAGE_MASK))
		reg_base = pci_resource_start(xdev->pdev, xdev->bar_num) +
			(QPM_TX_MDB_BASE_REG_ADDR & PAGE_MASK);
	else if (offset == (xdev->caps.mdb_base & PAGE_MASK))
		reg_base = pci_resource_start(xdev->pdev, xdev->bar_num) +
			(xdev->caps.mdb_base & PAGE_MASK);
	else
		return -EINVAL;

	xsc_core_dbg(xdev, "regbase:0x%llx", reg_base);

	reg_base = (xsc_core_is_pf(xdev) && !is_pf_bar_compressed(xdev)) ?
		reg_base - 0xA0000000 : reg_base;

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	return remap_pfn_range(vma, vma->vm_start, reg_base >> PAGE_SHIFT,
			       reg_size, vma->vm_page_prot);

	return 0;
}

xsc_ib_alloc_pd_def()
{
	struct ib_device *ibdev = ibpd->device;
	struct xsc_ib_alloc_pd_resp resp;
	struct xsc_ib_pd *pd;
	int err;

	pd = to_mpd(ibpd);

	err = xsc_core_alloc_pd(to_mdev(ibdev)->xdev, &pd->pdn);
	if (err) {
		return RET_VALUE(err);
	}

	if (udata) {
		resp.pdn = pd->pdn;
		if (ib_copy_to_udata(udata, &resp, sizeof(resp))) {
			xsc_core_dealloc_pd(to_mdev(ibdev)->xdev, pd->pdn);
			return RET_VALUE(-EFAULT);
		}
	} else {
		pd->pa_lkey = 0;
	}

	return 0;
}

xsc_ib_dealloc_pd_def()
{
	struct xsc_ib_dev *mdev = to_mdev(pd->device);
	struct xsc_ib_pd *mpd = to_mpd(pd);

	xsc_core_dealloc_pd(mdev->xdev, mpd->pdn);

	return 0;
}

static int xsc_port_immutable(struct ib_device *ibdev, u32 port_num,
			      struct ib_port_immutable *immutable)
{
	struct ib_port_attr attr;
	int err;

	err = ib_query_port(ibdev, port_num, &attr);
	if (err)
		return err;

	immutable->pkey_tbl_len = attr.pkey_tbl_len;
	immutable->gid_tbl_len = attr.gid_tbl_len;
	immutable->core_cap_flags = RDMA_CORE_PORT_IBA_ROCE |
				    RDMA_CORE_PORT_IBA_ROCE_UDP_ENCAP;
	immutable->max_mad_size = IB_MGMT_MAD_SIZE;

	return 0;
}

static void _xsc_get_netdev(struct xsc_ib_dev *dev)
{
	struct net_device *netdev = (struct net_device *)(dev->xdev->netdev);

	dev->netdev = netdev;
}

static struct net_device *xsc_get_netdev(struct ib_device *ibdev, u32 port_num)
{
	struct xsc_ib_dev *xsc_ib_dev = to_mdev(ibdev);
	struct net_device *dev = xsc_ib_dev->netdev;
	struct xsc_core_device *xdev = xsc_ib_dev->xdev;
	struct xsc_board_lag *board_lag = xsc_board_lag_get(xdev);

	if (dev) {
		if (board_lag) {
			xsc_board_lag_lock(xdev);
			if (xsc_lag_is_roce(xdev)) {
				struct net_device *upper = NULL;

				rcu_read_lock();
				upper = netdev_master_upper_dev_get_rcu(dev);
				if (upper) {
					struct net_device *active;

					active = bond_option_active_slave_get_rcu(
							netdev_priv(upper));
					if (active)
						dev = active;
				}
				rcu_read_unlock();
			}
			xsc_board_lag_unlock(xdev);
		}
		dev_hold(dev);
	}

	return dev;
}

static void xsc_get_guid(const u8 *dev_addr, u8 *guid)
{
	u8 mac[ETH_ALEN];

	/* MAC-48 to EUI-64 mapping */
	memcpy(mac, dev_addr, ETH_ALEN);
	guid[0] = mac[0] ^ 2;
	guid[1] = mac[1];
	guid[2] = mac[2];
	guid[3] = 0xff;
	guid[4] = 0xfe;
	guid[5] = mac[3];
	guid[6] = mac[4];
	guid[7] = mac[5];
}

static int init_node_data(struct xsc_ib_dev *dev)
{
	int err = -ENOMEM;

	strscpy(dev->ib_dev.node_desc, "xsc_node_desc", sizeof(dev->ib_dev.node_desc));

	if (unlikely(!dev->netdev->dev_addr))
		_xsc_get_netdev(dev);
	xsc_get_guid(dev->netdev->dev_addr, (u8 *)&dev->ib_dev.node_guid);
	err = 0;
	return err;
}

static void xsc_core_event(struct xsc_core_device *xdev, enum xsc_dev_event event,
			   unsigned long param)
{
	struct xsc_priv *priv = &xdev->priv;
	struct xsc_device_context *dev_ctx;
	unsigned long flags;

	spin_lock_irqsave(&priv->ctx_lock, flags);

	/* After xsc_detach_device, the dev_ctx->intf is still set and dev_ctx is
	 * still in priv->ctx_list. In this case, only notify the dev_ctx if its
	 * ADDED or ATTACHED bit are set.
	 */
	list_for_each_entry(dev_ctx, &priv->ctx_list, list) {
		if (dev_ctx->intf->event)
			dev_ctx->intf->event(xdev, dev_ctx->context, 0, param);
	}
	spin_unlock_irqrestore(&priv->ctx_lock, flags);
}

static void xsc_ib_event(struct xsc_core_device *dev, void *context,
			 enum xsc_dev_event event, unsigned long data)
{
	struct xsc_ib_dev *ibdev = (struct xsc_ib_dev *)context;
	struct ib_event ibev;
	u8 port = 0;

	switch (event) {
	case XSC_DEV_EVENT_SYS_ERROR:
		ibdev->ib_active = false;
		ibev.event = IB_EVENT_DEVICE_FATAL;
		break;

	case XSC_DEV_EVENT_PORT_UP:
		ibev.event = IB_EVENT_PORT_ACTIVE;
		port = *(u8 *)data;
		break;

	case XSC_DEV_EVENT_PORT_DOWN:
		ibev.event = IB_EVENT_PORT_ERR;
		port = *(u8 *)data;
		break;

	case XSC_DEV_EVENT_PORT_INITIALIZED:
		/* not used by ULPs */
		return;

	case XSC_DEV_EVENT_LID_CHANGE:
		ibev.event = IB_EVENT_LID_CHANGE;
		port = *(u8 *)data;
		break;

	case XSC_DEV_EVENT_PKEY_CHANGE:
		ibev.event = IB_EVENT_PKEY_CHANGE;
		port = *(u8 *)data;
		break;

	case XSC_DEV_EVENT_GUID_CHANGE:
		ibev.event = IB_EVENT_GID_CHANGE;
		port = *(u8 *)data;
		break;

	case XSC_DEV_EVENT_CLIENT_REREG:
		ibev.event = IB_EVENT_CLIENT_REREGISTER;
		port = *(u8 *)data;
		break;
	}

	ibev.device	      = &ibdev->ib_dev;
	ibev.element.port_num = port;

	if (ibdev->ib_active)
		ib_dispatch_event(&ibev);
}

static int get_port_caps(struct xsc_ib_dev *dev)
{
	struct ib_device_attr *dprops = NULL;
	struct ib_port_attr *pprops = NULL;
	int err = -ENOMEM;
	u32 port;
	/*used to prevent coredump when insmod xsc*/
	struct ib_udata uhw = {.inlen = 0, .outlen = 0};

	pprops = kmalloc(sizeof(*pprops), GFP_KERNEL);
	if (!pprops)
		goto out;

	dprops = kmalloc(sizeof(*dprops), GFP_KERNEL);
	if (!dprops)
		goto out;

	err = xsc_ib_query_device(&dev->ib_dev, dprops, &uhw);
	if (err) {
		xsc_ib_warn(dev, "query_device failed %d\n", err);
		goto out;
	}

	for (port = 1; port <= dev->xdev->caps.num_ports; port++) {
		err = xsc_ib_query_port(&dev->ib_dev, port, pprops);
		if (err) {
			xsc_ib_warn(dev, "query_port %d failed %d\n", port, err);
			break;
		}
		dev->xdev->caps.port[port - 1].pkey_table_len = dprops->max_pkeys;
		dev->xdev->caps.port[port - 1].gid_table_len = pprops->gid_tbl_len;
		xsc_ib_dbg(dev, "pkey_table_len %d, gid_table_len %d\n",
			   dprops->max_pkeys, pprops->gid_tbl_len);
	}

out:
	kfree(pprops);
	kfree(dprops);

	return err;
}

static int xsc_create_dev_res(struct xsc_ib_res *ib_res)
{
	struct xsc_ib_dev *dev;

	dev = container_of(ib_res, struct xsc_ib_dev, ib_res);
	ib_res->sgid_tbl.max = dev->xdev->caps.port[0].gid_table_len;

	ib_res->sgid_tbl.tbl = kcalloc(ib_res->sgid_tbl.max, sizeof(struct xsc_gid),
				       GFP_KERNEL);

	if (!ib_res->sgid_tbl.tbl)
		return -ENOMEM;

	return 0;
}

static void xsc_destroy_dev_res(struct xsc_ib_res *ib_res)
{
	kfree(ib_res->sgid_tbl.tbl);
}

static int populate_specs_root(struct xsc_ib_dev *dev)
{
	const struct uverbs_object_tree_def **trees =
		(const struct uverbs_object_tree_def **)dev->driver_trees;
	size_t num_trees = 0;
	trees[num_trees++] = xsc_ib_get_devx_tree();

	WARN_ON(num_trees >= ARRAY_SIZE(dev->driver_trees));
	trees[num_trees] = NULL;

	return 0;
}

static void crc_table_init(struct xsc_ib_dev *dev)
{
	u32 c, i, j;

	for (i = 0; i < 256; i++) {
		c = i;
		for (j = 0; j < 8; j++) {
			if (c & 1)
				c = 0xedb88320L ^ (c >> 1);
			else
				c = c >> 1;
		}
		dev->crc_32_table[i] = c;
	}
}

static void xsc_ib_get_dev_fw_str(struct ib_device *ibdev, char *str)
{
	struct xsc_core_device *dev = to_mdev(ibdev)->xdev;
	u8 ver_major = dev->fw_version_major;
	u8 ver_minor = dev->fw_version_minor;
	u16 ver_patch = dev->fw_version_patch;
	u32 ver_tweak = dev->fw_version_tweak;

	if (ver_tweak == 0) {
		snprintf(str, IB_FW_VERSION_NAME_MAX, "v%u.%u.%u",
			 ver_major,  ver_minor, ver_patch);
	} else {
		snprintf(str, IB_FW_VERSION_NAME_MAX, "v%u.%u.%u+%u",
			 ver_major, ver_minor, ver_patch, ver_tweak);
	}
}

static void xsc_ib_disassociate_ucontext(struct ib_ucontext *ibcontext)
{
}

static void xsc_ib_dev_setting(struct xsc_ib_dev *dev)
{
	dev->ib_dev.ops.owner		= THIS_MODULE;
	dev->ib_dev.ops.uverbs_abi_ver	= XSC_IB_UVERBS_ABI_VERSION;
	dev->ib_dev.ops.driver_id = (enum rdma_driver_id)RDMA_DRIVER_XSC5;
	dev->ib_dev.ops.uverbs_no_driver_id_binding = 1;
	dev->ib_dev.ops.disassociate_ucontext = xsc_ib_disassociate_ucontext;
	dev->ib_dev.ops.query_device	= xsc_ib_query_device;
	dev->ib_dev.ops.query_port	= xsc_ib_query_port;
	dev->ib_dev.ops.query_gid	= xsc_ib_query_gid;
	dev->ib_dev.ops.add_gid		= xsc_ib_add_gid;
	dev->ib_dev.ops.del_gid		= xsc_ib_del_gid;
	dev->ib_dev.ops.query_pkey	= xsc_ib_query_pkey;

	dev->ib_dev.ops.modify_device	= xsc_ib_modify_device;
	dev->ib_dev.ops.modify_port	= xsc_ib_modify_port;
	dev->ib_dev.ops.alloc_ucontext	= xsc_ib_alloc_ucontext;
	dev->ib_dev.ops.dealloc_ucontext = xsc_ib_dealloc_ucontext;
	dev->ib_dev.ops.mmap		= xsc_ib_mmap;

	dev->ib_dev.ops.alloc_pd		= xsc_ib_alloc_pd;
	dev->ib_dev.ops.dealloc_pd		= xsc_ib_dealloc_pd;
	dev->ib_dev.ops.create_ah		= xsc_ib_create_ah;
	dev->ib_dev.ops.query_ah		= xsc_ib_query_ah;
	dev->ib_dev.ops.destroy_ah		= xsc_ib_destroy_ah;

	dev->ib_dev.ops.get_link_layer	= xsc_ib_port_link_layer;
	dev->ib_dev.ops.get_netdev		= xsc_get_netdev;

	dev->ib_dev.ops.create_qp		= xsc_ib_create_qp;
	dev->ib_dev.ops.modify_qp		= xsc_ib_modify_qp;
	dev->ib_dev.ops.query_qp		= xsc_ib_query_qp;
	dev->ib_dev.ops.destroy_qp		= xsc_ib_destroy_qp;
	dev->ib_dev.ops.post_send		= xsc_ib_post_send_nodrain;
	dev->ib_dev.ops.post_recv		= xsc_ib_post_recv_nodrain;
	dev->ib_dev.ops.create_cq		= xsc_ib_create_cq;
	dev->ib_dev.ops.destroy_cq		= xsc_ib_destroy_cq;
	dev->ib_dev.ops.poll_cq		= xsc_ib_poll_cq;
	dev->ib_dev.ops.req_notify_cq	= xsc_ib_arm_cq;
	dev->ib_dev.ops.get_dma_mr		= xsc_ib_get_dma_mr;
	dev->ib_dev.ops.reg_user_mr		= xsc_ib_reg_user_mr;//optional
	dev->ib_dev.ops.reg_user_mr_dmabuf	= xsc_ib_reg_user_mr_dmabuf;
	dev->ib_dev.ops.dereg_mr		= xsc_ib_dereg_mr;
	dev->ib_dev.ops.alloc_mr		= xsc_ib_alloc_mr;
	dev->ib_dev.ops.map_mr_sg		= xsc_ib_map_mr_sg;

	dev->ib_dev.ops.get_port_immutable		= xsc_port_immutable;

	dev->ib_dev.ops.drain_sq		= xsc_ib_drain_sq;
	dev->ib_dev.ops.drain_rq		= xsc_ib_drain_rq;
	dev->ib_dev.ops.get_dev_fw_str	= xsc_ib_get_dev_fw_str;
	dev->ib_dev.ops.create_srq		= xsc_ib_create_srq;
	dev->ib_dev.ops.destroy_srq		= xsc_ib_destroy_srq;
	dev->ib_dev.ops.query_srq		= xsc_ib_query_srq;
	dev->ib_dev.ops.modify_srq		= xsc_ib_modify_srq;
	dev->ib_dev.ops.post_srq_recv	= xsc_ib_post_srq_recv;

	dev->ib_dev.ops INIT_RDMA_OBJ_SIZE(ib_ah, xsc_ib_ah, ibah);
	dev->ib_dev.ops INIT_RDMA_OBJ_SIZE(ib_cq, xsc_ib_cq, ibcq);
	dev->ib_dev.ops INIT_RDMA_OBJ_SIZE(ib_pd, xsc_ib_pd, ibpd);
	dev->ib_dev.ops INIT_RDMA_OBJ_SIZE(ib_ucontext, xsc_ib_ucontext, ibucontext);
	dev->ib_dev.ops INIT_RDMA_OBJ_SIZE(ib_qp, xsc_ib_qp, ibqp);
	dev->ib_dev.ops INIT_RDMA_OBJ_SIZE(ib_srq, xsc_ib_srq, ibsrq);

}

static void xsc_get_port_state(struct net_device *ndev, enum xsc_dev_event *ev)
{
	*ev = XSC_DEV_EVENT_PORT_DOWN;
	if (netif_running(ndev) && netif_carrier_ok(ndev))
		*ev = XSC_DEV_EVENT_PORT_UP;
}

static int xsc_netdev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct xsc_ib_dev *ibdev = container_of(this, struct xsc_ib_dev, nb);
	struct net_device *ndev = netdev_notifier_info_to_dev(ptr);
	enum xsc_dev_event ev;
	u8 port = 1;

	if (ndev != ibdev->netdev)
		goto done;

	xsc_ib_info(ibdev, "netdev notfiy event:%ld\n", event);
	switch (event) {
	case NETDEV_CHANGE:
	case NETDEV_UP:
	case NETDEV_DOWN:
		xsc_get_port_state(ibdev->netdev, &ev);
		xsc_ib_event(ibdev->xdev, ibdev, ev, (unsigned long)&port);
		break;
	default:
		break;
	}
done:
	return NOTIFY_DONE;
}

static int xsc_register_netdev_notifier(struct xsc_ib_dev *ibdev)
{
	ibdev->nb.notifier_call = xsc_netdev_event;
	return register_netdevice_notifier(&ibdev->nb);
}

static int xsc_unregister_netdev_notifier(struct xsc_ib_dev *ibdev)
{
	return unregister_netdevice_notifier(&ibdev->nb);
}

static void xsc_get_mdev_ibdev_name(struct net_device *netdev, char *name, int len)
{
	struct ib_device *ibdev;
	struct device *dev;
	const char *path = "/sys/class/infiniband/";
	struct path parent_path;
	struct path child_path;
	struct kobject *kobj;
	struct dentry *parent;
	struct dentry *child;
	struct inode *inode;
	struct kernfs_node *kn;
	char child_name[128];

	if (kern_path(path, LOOKUP_FOLLOW, &parent_path))
		return;

	parent = parent_path.dentry;
	inode_lock(parent->d_inode);
	list_for_each_entry(child, &parent->d_subdirs, d_child) {
		sprintf(child_name, "/sys/class/infiniband/%s", child->d_iname);
		if (kern_path(child_name, LOOKUP_FOLLOW, &child_path))
			continue;
		inode = child_path.dentry->d_inode;
		inode_lock(inode);
		kn = inode->i_private;
		if (!kn)
			goto next;
		kobj = kn->priv;
		if (!kobj)
			goto next;
		dev = container_of(kobj, struct device, kobj);
		ibdev = container_of(dev, struct ib_device, dev);
		if (ibdev->dev.parent == netdev->dev.parent) {
			memcpy(name, ibdev->name, len);
			inode_unlock(inode);
			path_put(&child_path);
			break;
		}
next:
		inode_unlock(inode);
		path_put(&child_path);
	}
	inode_unlock(parent->d_inode);
	path_put(&parent_path);
}

static void xsc_cm_ip_id_init(struct xsc_ib_dev *dev)
{
	u16 rand_val = 0;

	get_random_bytes(&rand_val, sizeof(rand_val));
	atomic_set(&dev->xdev->cm_ip_id, rand_val);
	xsc_ib_info(dev, "RDMA dev %s cm ip.id init with random val: 0x%04x\n",
		    dev->ib_dev.name, rand_val);
}

static int init_one(struct xsc_core_device *xdev,
		    struct xsc_ib_dev **m_ibdev)
{
	struct xsc_ib_dev *dev;
	int err;

	dev = (struct xsc_ib_dev *)ib_alloc_device(xsc_ib_dev, ib_dev);
	if (!dev)
		return -ENOMEM;

	dev->xdev = xdev;
	xdev->event = xsc_core_event;
	_xsc_get_netdev(dev);
	err = get_port_caps(dev);
	if (err)
		goto err_free;
	if (!xdev->caps.msix_enable)
		dev->num_comp_vectors = 1;
	else
		dev->num_comp_vectors = xdev->dev_res->eq_table.num_comp_vectors;

	if (xsc_lag_is_roce(xdev))
		strscpy(dev->ib_dev.name, "xscale_bond_%d", IB_DEVICE_NAME_MAX);
	else
		strscpy(dev->ib_dev.name, "xscale_%d", IB_DEVICE_NAME_MAX);

	dev->ib_dev.node_type		= RDMA_NODE_IB_CA;
	dev->ib_dev.local_dma_lkey	= 0xFF;
	dev->num_ports		= xdev->caps.num_ports;
	dev->ib_dev.phys_port_cnt     = dev->num_ports;
	dev->ib_dev.num_comp_vectors	= dev->num_comp_vectors;
	dev->ib_dev.dev.parent = &xdev->pdev->dev;
	xsc_ib_dev_setting(dev);
	dev->xdev->priv.cm_dscp = DSCP_PCP_UNSET;
	dev->xdev->priv.cm_pcp = DSCP_PCP_UNSET;
	dev->xdev->priv.force_pcp = DSCP_PCP_UNSET;
	dev->xdev->priv.force_dscp = DSCP_PCP_UNSET;
	dev->xdev->rdma_proto_mode = RDMA_PROTO_ROCEV2;
	dev->xdev->cm_udp_dst_port = ROCE_V2_UDP_DPORT;
	dev->xdev->veroce_udp_dst_port = VEROCE_UDP_DPORT;

	dev->ib_dev.uverbs_cmd_mask	=
		(1ull << IB_USER_VERBS_CMD_GET_CONTEXT)		|
		(1ull << IB_USER_VERBS_CMD_QUERY_DEVICE)	|
		(1ull << IB_USER_VERBS_CMD_QUERY_PORT)		|
		(1ull << IB_USER_VERBS_CMD_ALLOC_PD)		|
		(1ull << IB_USER_VERBS_CMD_DEALLOC_PD)		|
		(1ull << IB_USER_VERBS_CMD_CREATE_AH)		|
		(1ull << IB_USER_VERBS_CMD_DESTROY_AH)		|
		(1ull << IB_USER_VERBS_CMD_REG_MR)		|
		(1ull << IB_USER_VERBS_CMD_REREG_MR)		|
		(1ull << IB_USER_VERBS_CMD_DEREG_MR)		|
		(1ull << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL)	|
		(1ull << IB_USER_VERBS_CMD_CREATE_CQ)		|
		(1ull << IB_USER_VERBS_CMD_RESIZE_CQ)		|
		(1ull << IB_USER_VERBS_CMD_DESTROY_CQ)		|
		(1ull << IB_USER_VERBS_CMD_CREATE_QP)		|
		(1ull << IB_USER_VERBS_CMD_MODIFY_QP)		|
		(1ull << IB_USER_VERBS_CMD_QUERY_QP)		|
		(1ull << IB_USER_VERBS_CMD_DESTROY_QP)		|
		(1ull << IB_USER_VERBS_CMD_ATTACH_MCAST)	|
		(1ull << IB_USER_VERBS_CMD_DETACH_MCAST)	|
		(1ull << IB_USER_VERBS_CMD_CREATE_SRQ)		|
		(1ull << IB_USER_VERBS_CMD_MODIFY_SRQ)		|
		(1ull << IB_USER_VERBS_CMD_QUERY_SRQ)		|
		(1ull << IB_USER_VERBS_CMD_DESTROY_SRQ)		|
		(1ull << IB_USER_VERBS_CMD_CREATE_XSRQ)		|
		(1ull << IB_USER_VERBS_CMD_OPEN_QP);

	init_node_data(dev);

	mutex_init(&dev->cap_mask_mutex);
	spin_lock_init(&dev->mr_lock);

	err = xsc_create_dev_res(&dev->ib_res);
	if (err)
		goto err_free;

	crc_table_init(dev);

	build_opcode_map(dev);

	populate_specs_root(dev);

	xsc_reg_local_dma_mr(xdev);

	if (ib_register_device(&dev->ib_dev, dev->ib_dev.name, dev->xdev->device))
		goto err_rsrc;

	memcpy(dev->xdev->priv.ibdev_name, dev->ib_dev.name, IB_DEVICE_NAME_MAX);

	rdma_roce_rescan_device(&dev->ib_dev);
	dev->ib_active = true;
	*m_ibdev = dev;

	xdev->get_rdma_ctrl_info = xsc_get_rdma_ctrl_info;
	xsc_register_get_mdev_ibdev_name_func(xsc_get_mdev_ibdev_name);

	xsc_register_netdev_notifier(dev);

	xsc_counters_init(&dev->ib_dev, xdev);

	xsc_rtt_sysfs_init(&dev->ib_dev, xdev);

	xsc_ib_sysfs_init(&dev->ib_dev, xdev);

	xsc_cm_ip_id_init(dev);

	return 0;

err_rsrc:
	xsc_destroy_dev_res(&dev->ib_res);

err_free:
	ib_dealloc_device((struct ib_device *)dev);

	return err;
}

static void remove_one(struct xsc_core_device *xdev, void *intf_ctx)
{
	struct xsc_ib_dev *dev = (struct xsc_ib_dev *)intf_ctx;

	xdev->get_rdma_ctrl_info = NULL;
	xsc_unregister_get_mdev_ibdev_name_func();
	xsc_rtt_sysfs_fini(xdev);
	xsc_ib_sysfs_fini(&dev->ib_dev, xdev);
	xsc_counters_fini(&dev->ib_dev, xdev);
	xsc_unregister_netdev_notifier(dev);
	ib_unregister_device(&dev->ib_dev);
	ib_dealloc_device(&dev->ib_dev);
}

static void init_iommu_state(struct xsc_ib_dev *xdev)
{
	if (xdev) {
		struct iommu_domain *domain;

		xdev->iommu_state = XSC_IB_IOMMU_MAP_DISABLE;
		domain = iommu_get_domain_for_dev(xdev->ib_dev.dma_device);
		if (domain) {
			if (domain->type & __IOMMU_DOMAIN_DMA_API)
				xdev->iommu_state = XSC_IB_IOMMU_MAP_NORMAL;
		} else {
			/* try to allocate dma memory, if dma address is not equal to phys address,
			 * the iommu map is enabled, but iommu domain is unknown.
			 */
			dma_addr_t dma_addr;

			void *tmp = dma_alloc_coherent(xdev->ib_dev.dma_device, PAGE_SIZE,
						       &dma_addr, GFP_KERNEL);
			if (tmp) {
				if (virt_to_phys(tmp) != dma_addr)
					xdev->iommu_state = XSC_IB_IOMMU_MAP_UNKNOWN_DOMAIN;
				dma_free_coherent(xdev->ib_dev.dma_device, PAGE_SIZE,
						  tmp, dma_addr);
			}
		}

		if (xdev->iommu_state)
			xsc_ib_dbg(xdev, "ibdev supports iommu dma map, state=%d\n",
				   xdev->iommu_state);
		else
			xsc_ib_dbg(xdev, "ibdev does not support iommu dma map\n");
	}
}

static bool xsc_need_create_ib_device(struct xsc_core_device *dev)
{
	if (xsc_get_roce_lag_xdev(dev) == dev)
		return true;

	return false;
}

static void *xsc_add(struct xsc_core_device *xpdev)
{
	struct xsc_ib_dev *m_ibdev = NULL;
	int ret = -1;

	if (!xsc_need_create_ib_device(xpdev))
		return NULL;

	pr_info("add rdma driver\n");

	ret = init_one(xpdev, &m_ibdev);
	if (ret) {
		pr_err("xsc ib dev add fail, ret = %d\n", ret);
		return NULL;
	}

	init_iommu_state(m_ibdev);

	return m_ibdev;
}

static void xsc_remove(struct xsc_core_device *xpdev, void *context)
{
	pr_info("remove rdma driver\n");
	remove_one(xpdev, context);
}

static struct xsc_interface xsc_interface = {
	.add       = xsc_add,
	.remove    = xsc_remove,
	.event	= xsc_ib_event,
	.protocol  = XSC_INTERFACE_PROTOCOL_IB,
};

void xsc_remove_rdma_driver(void)
{
	xsc_rdma_ctrl_fini();
	xsc_rdma_prgrmmbl_cc_ctrl_fini();
	xsc_sample_ctrl_fini();
	xsc_unregister_interface(&xsc_interface);
}

static int __init xsc_ib_init(void)
{
	int ret;

	ret = xsc_register_interface(&xsc_interface);
	if (ret)
		goto out;

	ret = xsc_rdma_ctrl_init();
	if (ret != 0) {
		pr_err("failed to register port control node\n");
		xsc_unregister_interface(&xsc_interface);
		goto out;
	}

	ret = xsc_rdma_prgrmmbl_cc_ctrl_init();
	if (ret != 0) {
		pr_err("failed to register programmable cc control node\n");
		xsc_unregister_interface(&xsc_interface);
		goto out;
	}

	ret = xsc_sample_ctrl_init();
	if (ret != 0) {
		pr_err("failed to register sample control node\n");
		xsc_unregister_interface(&xsc_interface);
		goto out;
	}

	return 0;
out:
	return ret;
}

static void __exit xsc_ib_cleanup(void)
{
	xsc_remove_rdma_driver();
}

module_init(xsc_ib_init);
module_exit(xsc_ib_cleanup);
