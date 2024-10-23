// SPDX-License-Identifier: GPL-2.0
/* Huawei HNS3_UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#include <linux/module.h>
#include <linux/acpi.h>
#include <linux/iommu.h>
#include <linux/of_platform.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>
#include "urma/ubcore_api.h"
#include "hnae3.h"
#include "hns3_udma_hem.h"
#include "hns3_udma_tp.h"
#include "hns3_udma_jfr.h"
#include "hns3_udma_jfc.h"
#include "hns3_udma_jfs.h"
#include "hns3_udma_segment.h"
#include "hns3_udma_jetty.h"
#include "hns3_udma_dca.h"
#include "hns3_udma_cmd.h"
#include "hns3_udma_dfx.h"
#include "hns3_udma_sysfs.h"
#include "hns3_udma_debugfs.h"
#include "hns3_udma_eid.h"
#include "hns3_udma_user_ctl.h"

static int is_active = 1;

static int hns3_udma_uar_alloc(struct hns3_udma_dev *udma_dev, struct hns3_udma_uar *uar)
{
	struct hns3_udma_ida *uar_ida = &udma_dev->uar_ida;
	int id;

	/* Using bitmap to manager UAR index */
	id = ida_alloc_range(&uar_ida->ida, uar_ida->min, uar_ida->max,
			     GFP_KERNEL);
	if (id < 0) {
		dev_err(udma_dev->dev, "failed to alloc uar id(%d).\n", id);
		return id;
	}
	uar->logic_idx = (uint64_t)id;

	uar->pfn = ((pci_resource_start(udma_dev->pci_dev,
					HNS3_UDMA_DEV_START_OFFSET)) >> PAGE_SHIFT);
	if (udma_dev->caps.flags & HNS3_UDMA_CAP_FLAG_DIRECT_WQE)
		udma_dev->dwqe_page =
			pci_resource_start(udma_dev->pci_dev,
					   HNS3_UDMA_DEV_EX_START_OFFSET);

	return 0;
}

static int hns3_udma_init_ctx_resp(struct hns3_udma_dev *dev, struct ubcore_udrv_priv *udrv_data,
				   struct hns3_udma_dca_ctx *dca_ctx)
{
	struct hns3_udma_create_ctx_resp resp = {};
	unsigned long byte;

	if (!udrv_data->out_addr || udrv_data->out_len < sizeof(resp)) {
		dev_err(dev->dev,
			"Invalid out: len %u or addr is null.\n",
			udrv_data->out_len);
		return -EINVAL;
	}

	resp.num_comp_vectors = dev->caps.num_comp_vectors;
	resp.num_qps_shift = dev->caps.num_qps_shift;
	resp.max_jfc_cqe = dev->caps.max_cqes;
	resp.cqe_size = dev->caps.cqe_sz;
	resp.max_jfr_wr = dev->caps.max_srq_wrs;
	resp.max_jfr_sge = dev->caps.max_srq_sges;
	resp.max_jfs_wr = dev->caps.max_wqes;
	resp.max_jfs_sge = dev->caps.max_sq_sg;
	resp.poe_ch_num = dev->caps.poe_ch_num;
	resp.db_addr = pci_resource_start(dev->pci_dev, HNS3_UDMA_DEV_START_OFFSET) +
		       HNS3_UDMA_DB_ADDR_OFFSET;
	resp.chip_id = dev->chip_id;
	resp.die_id = dev->die_id;
	resp.func_id = dev->func_id;

	if (dev->caps.flags & HNS3_UDMA_CAP_FLAG_DCA_MODE) {
		resp.dca_qps = dca_ctx->max_qps;
		resp.dca_mmap_size = dca_ctx->status_npage * PAGE_SIZE;
		resp.dca_mode = dev->caps.flags & HNS3_UDMA_CAP_FLAG_DCA_MODE;
	}

	byte = copy_to_user((void *)udrv_data->out_addr, &resp, sizeof(resp));
	if (byte) {
		dev_err(dev->dev,
			"copy ctx resp to user failed, byte = %lu.\n", byte);
		return -EFAULT;
	}

	return 0;
}

static void hns3_udma_uar_free(struct hns3_udma_dev *udma_dev,
			       struct hns3_udma_ucontext *context)
{
	ida_free(&udma_dev->uar_ida.ida, (int)context->uar.logic_idx);
}

static void init_ucontext_list(struct hns3_udma_dev *udma_dev,
			       struct hns3_udma_ucontext *uctx)
{
	if (udma_dev->caps.flags & HNS3_UDMA_CAP_FLAG_CQ_RECORD_DB ||
	    udma_dev->caps.flags & HNS3_UDMA_CAP_FLAG_QP_RECORD_DB) {
		INIT_LIST_HEAD(&uctx->pgdir_list);
		mutex_init(&uctx->pgdir_mutex);
	}
}

static struct ubcore_ucontext *hns3_udma_alloc_ucontext(struct ubcore_device *dev,
							uint32_t eid_index,
							struct ubcore_udrv_priv *udrv_data)
{
	struct hns3_udma_dev *udma_dev = to_hns3_udma_dev(dev);
	struct hns3_udma_ucontext *context;
	struct hns3_udma_eid *udma_eid;
	int ret;

	if (!udrv_data) {
		dev_err(udma_dev->dev, "ucontext udrv_data is null\n.");
		return NULL;
	}

	context = kzalloc(sizeof(struct hns3_udma_ucontext), GFP_KERNEL);
	if (!context)
		return NULL;

	udma_eid = (struct hns3_udma_eid *)xa_load(&udma_dev->eid_table, eid_index);
	if (IS_ERR_OR_NULL(udma_eid)) {
		dev_err(udma_dev->dev, "Failed to find eid, index = %d\n.",
			eid_index);
		goto err_alloc_ucontext;
	}
	if (udma_eid->type != SGID_TYPE_IPV4) {
		dev_err(udma_dev->dev, "Failed to check type, index = %d\n.",
			eid_index);
		goto err_alloc_ucontext;
	}
	context->eid_index = eid_index;

	ret = hns3_udma_uar_alloc(udma_dev, &context->uar);
	if (ret) {
		dev_err(udma_dev->dev, "Alloc hns3_udma_uar Failed.\n");
		goto err_alloc_ucontext;
	}

	ret = hns3_udma_register_udca(udma_dev, context, udrv_data);
	if (ret) {
		dev_err(udma_dev->dev, "Register udca Failed.\n");
		goto err_alloc_uar;
	}

	ret = hns3_udma_init_ctx_resp(udma_dev, udrv_data, &context->dca_ctx);
	if (ret) {
		dev_err(udma_dev->dev, "Init ctx resp failed.\n");
		hns3_udma_unregister_udca(udma_dev, context);
		goto err_alloc_uar;
	}

	if (context->dca_ctx.unit_size > 0 && udma_dev->caps.flags &
	    HNS3_UDMA_CAP_FLAG_DCA_MODE)
		hns3_udma_register_uctx_debugfs(udma_dev, context);

	context->cq_bank_id = hns3_udma_get_cq_bankid_for_uctx(udma_dev);
	init_ucontext_list(udma_dev, context);

	return &context->uctx;

err_alloc_uar:
	hns3_udma_uar_free(udma_dev, context);
err_alloc_ucontext:
	kfree(context);
	return NULL;
}

static int hns3_udma_free_ucontext(struct ubcore_ucontext *uctx)
{
	struct hns3_udma_ucontext *context = to_hns3_udma_ucontext(uctx);
	struct hns3_udma_dev *udma_dev = to_hns3_udma_dev(uctx->ub_dev);

	hns3_udma_put_cq_bankid_for_uctx(context);
	if (udma_dev->caps.flags & HNS3_UDMA_CAP_FLAG_DCA_MODE)
		hns3_udma_unregister_udca(udma_dev, context);

	ida_free(&udma_dev->uar_ida.ida, (int)context->uar.logic_idx);
	kfree(context);
	return 0;
}

static int get_mmap_cmd(struct vm_area_struct *vma)
{
	return (vma->vm_pgoff & HNS3_UDMA_MAP_COMMAND_MASK);
}

static uint64_t get_mmap_idx(struct vm_area_struct *vma)
{
	return ((vma->vm_pgoff >> HNS3_UDMA_MAP_INDEX_SHIFT) & HNS3_UDMA_MAP_INDEX_MASK);
}

static int mmap_dca(struct ubcore_ucontext *context, struct vm_area_struct *vma)
{
	struct hns3_udma_ucontext *uctx = to_hns3_udma_ucontext(context);
	struct hns3_udma_dca_ctx *ctx = &uctx->dca_ctx;
	struct page **pages;
	unsigned long num;
	int ret;

	if (vma->vm_end - vma->vm_start != (ctx->status_npage * PAGE_SIZE))
		return -EINVAL;

	if (!(vma->vm_flags & VM_WRITE) ||
	    !(vma->vm_flags & VM_SHARED) ||
	    (vma->vm_flags & VM_EXEC))
		return -EPERM;

	if (!ctx->buf_status)
		return -EOPNOTSUPP;

	pages = kcalloc(ctx->status_npage, sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	for (num = 0; num < ctx->status_npage; num++)
		pages[num] = virt_to_page(ctx->buf_status + num * PAGE_SIZE);

	ret = vm_insert_pages(vma, vma->vm_start, pages, &num);
	kfree(pages);

	return ret;
}

static bool hns3_udma_mmap_check_qpn(struct ubcore_ucontext *uctx, uint64_t qpn)
{
	struct hns3_udma_dev *udma_dev = to_hns3_udma_dev(uctx->ub_dev);
	struct hns3_udma_qp *qp;
	bool ret = true;

	xa_lock(&udma_dev->qp_table.xa);

	qp = get_qp(udma_dev, qpn);
	if (!qp) {
		xa_unlock(&udma_dev->qp_table.xa);
		return false;
	}
	refcount_inc(&qp->refcount);

	xa_unlock(&udma_dev->qp_table.xa);

	if (uctx != qp->qp_attr.uctx)
		ret = false;
	if (refcount_dec_and_test(&qp->refcount))
		complete(&qp->free);

	return ret;
}

static int hns3_udma_mmap(struct ubcore_ucontext *uctx, struct vm_area_struct *vma)
{
	struct hns3_udma_dev *udma_dev = to_hns3_udma_dev(uctx->ub_dev);
	uint64_t address;
	uint64_t qpn;
	int cmd;

	if (((vma->vm_end - vma->vm_start) % PAGE_SIZE) != 0) {
		dev_err(udma_dev->dev, "mmap failed, unexpected vm area size.\n");
		return -EINVAL;
	}

	cmd = get_mmap_cmd(vma);
	switch (cmd) {
	case HNS3_UDMA_MMAP_UAR_PAGE:
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		if (io_remap_pfn_range(vma, vma->vm_start,
				       to_hns3_udma_ucontext(uctx)->uar.pfn,
				       PAGE_SIZE, vma->vm_page_prot))
			return -EAGAIN;
		break;
	case HNS3_UDMA_MMAP_DWQE_PAGE:
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		qpn = get_mmap_idx(vma);
		if (!hns3_udma_mmap_check_qpn(uctx, qpn))
			return -EINVAL;
		address = udma_dev->dwqe_page + qpn * HNS3_UDMA_DWQE_PAGE_SIZE;
		if (io_remap_pfn_range(vma, vma->vm_start, address >> PAGE_SHIFT,
				       HNS3_UDMA_DWQE_PAGE_SIZE, vma->vm_page_prot))
			return -EAGAIN;
		break;
	case HNS3_UDMA_MMAP_RESET_PAGE:
		if (vma->vm_flags & (VM_WRITE | VM_EXEC))
			return -EINVAL;

		if (remap_pfn_range(vma, vma->vm_start,
				    page_to_pfn(udma_dev->reset_page),
				    PAGE_SIZE, vma->vm_page_prot))
			return -EAGAIN;
		break;
	case HNS3_UDMA_MMAP_TYPE_DCA:
		if (mmap_dca(uctx, vma))
			return -EAGAIN;
		break;
	default:
		dev_err(udma_dev->dev,
			"mmap failed, cmd(%d) not support\n", cmd);
		return -EINVAL;
	}

	return 0;
}

static int hns3_udma_query_stats(struct ubcore_device *dev, struct ubcore_stats_key *key,
				 struct ubcore_stats_val *val)
{
	struct ubcore_stats_com_val *com_val = (struct ubcore_stats_com_val *)val->addr;
	struct hns3_udma_cmq_desc desc[HNS3_UDMA_QUERY_COUNTER];
	struct hns3_udma_dev *udma_dev = to_hns3_udma_dev(dev);
	struct hns3_udma_tx_err_cnt_cmd_data *resp_tx_err;
	struct hns3_udma_rx_cnt_cmd_data *resp_rx;
	struct hns3_udma_tx_cnt_cmd_data *resp_tx;
	int ret;
	int i;

	if (val->len != sizeof(struct ubcore_stats_com_val)) {
		dev_err(udma_dev->dev, "The val len is err.\n");
		return -EINVAL;
	}

	for (i = 0; i < HNS3_UDMA_QUERY_COUNTER; i++) {
		hns3_udma_cmq_setup_basic_desc(&desc[i], HNS3_UDMA_OPC_QUERY_COUNTER, true);
		if (i < (HNS3_UDMA_QUERY_COUNTER - 1))
			desc[i].flag |= cpu_to_le16(HNS3_UDMA_CMD_FLAG_NEXT);
		else
			desc[i].flag &= ~cpu_to_le16(HNS3_UDMA_CMD_FLAG_NEXT);
	}

	ret = hns3_udma_cmq_send(udma_dev, desc, HNS3_UDMA_QUERY_COUNTER);
	if (ret) {
		dev_err(udma_dev->dev, "Failed to query stats, ret = %d.\n", ret);
		return ret;
	}

	resp_rx = (struct hns3_udma_rx_cnt_cmd_data *)desc[HNS3_UDMA_QX_RESP].data;
	resp_tx = (struct hns3_udma_tx_cnt_cmd_data *)desc[HNS3_UDMA_TX_RESP].data;
	resp_tx_err = (struct hns3_udma_tx_err_cnt_cmd_data *)desc[HNS3_UDMA_TX_ERR_RESP].data;

	com_val->tx_pkt = resp_tx->pkt_tx_cnt;
	com_val->tx_pkt_err = resp_tx_err->err_pkt_tx_cnt;

	com_val->rx_pkt = resp_rx->pkt_rx_cnt;
	com_val->rx_pkt_err = resp_rx->err_pkt_rx_cnt;

	/* tx_bytes and rx_bytes are not support now */
	com_val->tx_bytes = 0;
	com_val->rx_bytes = 0;

	return ret;
}

static uint16_t query_congest_alg(uint8_t hns3_udma_cc_caps)
{
	uint16_t ubcore_cc_alg = 0;

	if (hns3_udma_cc_caps & HNS3_UDMA_CONG_SEL_DCQCN)
		ubcore_cc_alg |= UBCORE_CC_DCQCN;
	if (hns3_udma_cc_caps & HNS3_UDMA_CONG_SEL_LDCP)
		ubcore_cc_alg |= UBCORE_CC_LDCP;
	if (hns3_udma_cc_caps & HNS3_UDMA_CONG_SEL_HC3)
		ubcore_cc_alg |= UBCORE_CC_HC3;
	if (hns3_udma_cc_caps & HNS3_UDMA_CONG_SEL_DIP)
		ubcore_cc_alg |= UBCORE_CC_DIP;

	return ubcore_cc_alg;
}

static int hns3_udma_query_device_attr(struct ubcore_device *dev,
				       struct ubcore_device_attr *attr)
{
#define HNS3_UDMA_MAX_TP_IN_TPG 10
	struct hns3_udma_dev *udma_dev = to_hns3_udma_dev(dev);
	struct device *dev_of_hns3_udma = udma_dev->dev;
	struct net_device *net_dev;
	int i;

	attr->dev_cap.max_eid_cnt = udma_dev->caps.max_eid_cnt;
	attr->dev_cap.max_netaddr_cnt = udma_dev->caps.max_eid_cnt;
	attr->dev_cap.max_jfc = udma_dev->caps.num_jfc;
	attr->dev_cap.max_jfs = udma_dev->caps.num_jfs;
	attr->dev_cap.max_jfr = udma_dev->caps.num_jfr;
	attr->dev_cap.max_jetty = udma_dev->caps.num_jetty;
	attr->dev_cap.max_jfc_depth = udma_dev->caps.max_cqes;
	attr->dev_cap.max_jfs_depth = udma_dev->caps.max_wqes;
	attr->dev_cap.max_jfr_depth = udma_dev->caps.max_srq_wrs;
	attr->dev_cap.max_jfs_inline_size = udma_dev->caps.max_sq_inline;
	attr->dev_cap.max_jfs_sge = udma_dev->caps.max_sq_sg;
	attr->dev_cap.max_jfr_sge = udma_dev->caps.max_srq_sges;
	attr->dev_cap.max_msg_size = HNS3_UDMA_MAX_MSG_LEN;
	attr->dev_cap.trans_mode = UBCORE_TP_RC | UBCORE_TP_UM;
	attr->dev_cap.feature.bs.oor = udma_dev->caps.oor_en;
	attr->dev_cap.ceq_cnt = udma_dev->caps.num_comp_vectors;
	attr->dev_cap.feature.bs.jfc_inline = !!(udma_dev->caps.flags &
						 HNS3_UDMA_CAP_FLAG_CQE_INLINE);
	attr->dev_cap.feature.bs.spray_en = !!(udma_dev->caps.flags & HNS3_UDMA_CAP_FLAG_AR);
	attr->dev_cap.max_jfs_rsge = udma_dev->caps.max_sq_sg;
	attr->dev_cap.sub_trans_mode_cap = UBCORE_RC_USER_TP | UBCORE_RC_TP_DST_ORDERING;
	attr->dev_cap.congestion_ctrl_alg = query_congest_alg(udma_dev->caps.cong_type);
	attr->dev_cap.max_fe_cnt = udma_dev->func_num - 1;
	attr->port_cnt = udma_dev->caps.num_ports;
	attr->tp_maintainer = true;
	attr->dev_cap.max_tp_in_tpg = HNS3_UDMA_MAX_TP_IN_TPG;
	attr->fe_idx = udma_dev->func_id;
	attr->pattern = UBCORE_PATTERN_1;

	for (i = 0; i < udma_dev->caps.num_ports; i++) {
		net_dev = udma_dev->uboe.netdevs[i];
		if (!net_dev) {
			dev_err(dev_of_hns3_udma, "Find netdev %d failed!\n", i);
			return -EINVAL;
		}
		attr->port_attr[i].max_mtu =
			hns3_udma_mtu_int_to_enum(net_dev->max_mtu);
	}

	return 0;
}

static int hns3_udma_get_active_speed(uint32_t speed, struct ubcore_port_status *port_status)
{
	if (speed == SPEED_100G) {
		port_status->active_width = UBCORE_LINK_X1;
		port_status->active_speed = UBCORE_SP_100G;
	} else if (speed == SPEED_200G) {
		port_status->active_width = UBCORE_LINK_X1;
		port_status->active_speed = UBCORE_SP_200G;
	} else {
		return -EINVAL;
	}

	return 0;
}

static int hns3_udma_query_device_status(struct ubcore_device *dev,
					 struct ubcore_device_status *dev_status)
{
	struct hns3_udma_dev *udma_dev = to_hns3_udma_dev(dev);
	enum ubcore_mtu net_dev_mtu;
	struct net_device *net_dev;
	enum ubcore_mtu mtu;
	uint8_t port_num;
	int ret;
	int i;

	port_num = udma_dev->caps.num_ports;

	for (i = 0; i < port_num; i++) {
		net_dev = udma_dev->uboe.netdevs[i];
		if (!net_dev) {
			dev_err(udma_dev->dev, "Find netdev %d failed!\n", i);
			return -EINVAL;
		}

		if (is_active) {
			dev_status->port_status[i].state =
				(netif_running(net_dev) &&
				netif_carrier_ok(net_dev)) ?
				UBCORE_PORT_ACTIVE : UBCORE_PORT_DOWN;
		} else {
			dev_status->port_status[i].state = UBCORE_PORT_ACTIVE;
		}

		net_dev_mtu = ubcore_get_mtu(net_dev->max_mtu);
		mtu = ubcore_get_mtu(net_dev->mtu);

		dev_status->port_status[i].active_mtu = (enum ubcore_mtu)
							(mtu ? min(net_dev_mtu, mtu) :
							       UBCORE_MTU_256);

		ret = hns3_udma_get_active_speed(udma_dev->caps.speed, &dev_status->port_status[i]);
		if (ret) {
			dev_err(udma_dev->dev, "Port[%d] query speed and width failed!\n", i);
			return ret;
		}
	}

	return 0;
}

static int hns3_udma_send_req(struct ubcore_device *dev, struct ubcore_req *msg)
{
	struct hns3_udma_dev *udma_dev = to_hns3_udma_dev(dev);
	struct ubcore_req_host *req_host_msg;
	int ret;

	if (msg == NULL) {
		dev_err(udma_dev->dev, "The req message to be sent is empty.\n");
		return -EINVAL;
	}

	req_host_msg = kzalloc(sizeof(struct ubcore_req_host) + msg->len, GFP_KERNEL);
	if (!req_host_msg)
		return -ENOMEM;

	req_host_msg->src_fe_idx = 0;
	memcpy(&req_host_msg->req, msg, sizeof(struct ubcore_req) + msg->len);
	ret = ubcore_recv_req(dev, req_host_msg);
	if (ret)
		dev_err(udma_dev->dev, "Fail to recv req msg, ret = %d.\n", ret);
	kfree(req_host_msg);

	return ret;
}

static int hns3_udma_send_resp(struct ubcore_device *dev, struct ubcore_resp_host *msg)
{
	struct hns3_udma_dev *udma_dev = to_hns3_udma_dev(dev);
	struct ubcore_resp *resp_msg;
	int ret;

	if (msg == NULL) {
		dev_err(udma_dev->dev, "The resp message to be sent is empty.\n");
		return -EINVAL;
	}

	resp_msg = kzalloc(sizeof(struct ubcore_resp) + msg->resp.len, GFP_KERNEL);
	if (!resp_msg)
		return -ENOMEM;

	memcpy(resp_msg, &msg->resp, sizeof(struct ubcore_resp) + msg->resp.len);
	ret = ubcore_recv_resp(dev, resp_msg);
	if (ret)
		dev_err(udma_dev->dev, "Fail to recv resp msg, ret = %d.\n", ret);
	kfree(resp_msg);

	return ret;
}

static struct ubcore_ops g_hns3_udma_dev_ops = {
	.owner = THIS_MODULE,
	.abi_version = 1,
	.add_ueid = hns3_udma_add_ueid,
	.delete_ueid = hns3_udma_delete_ueid,
	.query_device_attr = hns3_udma_query_device_attr,
	.query_device_status = hns3_udma_query_device_status,
	.query_res = hns3_udma_query_res,
	.alloc_ucontext = hns3_udma_alloc_ucontext,
	.free_ucontext = hns3_udma_free_ucontext,
	.mmap = hns3_udma_mmap,
	.register_seg = hns3_udma_register_seg,
	.unregister_seg = hns3_udma_unregister_seg,
	.import_seg = hns3_udma_import_seg,
	.unimport_seg = hns3_udma_unimport_seg,
	.create_jfc = hns3_udma_create_jfc,
	.modify_jfc = hns3_udma_modify_jfc,
	.destroy_jfc = hns3_udma_destroy_jfc,
	.create_jfs = hns3_udma_create_jfs,
	.destroy_jfs = hns3_udma_destroy_jfs,
	.create_jfr = hns3_udma_create_jfr,
	.modify_jfr = hns3_udma_modify_jfr,
	.destroy_jfr = hns3_udma_destroy_jfr,
	.import_jfr = hns3_udma_import_jfr,
	.unimport_jfr = hns3_udma_unimport_jfr,
	.create_jetty = hns3_udma_create_jetty,
	.destroy_jetty = hns3_udma_destroy_jetty,
	.import_jetty = hns3_udma_import_jetty,
	.unimport_jetty = hns3_udma_unimport_jetty,
	.create_tp = hns3_udma_create_tp,
	.modify_tp = hns3_udma_modify_tp,
	.modify_user_tp = hns3_udma_modify_user_tp,
	.destroy_tp = hns3_udma_destroy_tp,
	.send_req = hns3_udma_send_req,
	.send_resp = hns3_udma_send_resp,
	.user_ctl = hns3_udma_user_ctl,
	.query_stats = hns3_udma_query_stats,
};

static void hns3_udma_cleanup_uar_table(struct hns3_udma_dev *dev)
{
	struct hns3_udma_ida *uar_ida = &dev->uar_ida;

	if (!ida_is_empty(&uar_ida->ida))
		dev_err(dev->dev, "IDA not empty in clean up uar table.\n");
	ida_destroy(&uar_ida->ida);
}

static void hns3_udma_init_uar_table(struct hns3_udma_dev *udma_dev)
{
	struct hns3_udma_ida *uar_ida = &udma_dev->uar_ida;

	ida_init(&uar_ida->ida);
	uar_ida->max = udma_dev->caps.num_uars - 1;
	uar_ida->min = udma_dev->caps.reserved_uars;
}

static void hns3_udma_cleanup_seg_table(struct hns3_udma_dev *dev)
{
	struct hns3_udma_ida *seg_ida = &dev->seg_table.seg_ida;

	if (!ida_is_empty(&seg_ida->ida))
		dev_err(dev->dev, "IDA not empty in clean up seg table.\n");
	ida_destroy(&seg_ida->ida);
}

static void hns3_udma_init_seg_table(struct hns3_udma_dev *udma_dev)
{
	struct hns3_udma_ida *seg_ida = &udma_dev->seg_table.seg_ida;

	ida_init(&seg_ida->ida);
	seg_ida->max = udma_dev->caps.num_mtpts - 1;
	seg_ida->min = udma_dev->caps.reserved_mrws;
}

static void hns3_udma_cleanup_jfc_table(struct hns3_udma_dev *udma_dev)
{
	struct hns3_udma_jfc_table *jfc_table = &udma_dev->jfc_table;
	unsigned long index = 0;
	struct hns3_udma_jfc *jfc;
	int i;

	for (i = 0; i < HNS3_UDMA_CQ_BANK_NUM; i++) {
		if (!ida_is_empty(&jfc_table->bank[i].ida))
			dev_err(udma_dev->dev,
				"IDA not empty in clean up jfc bank[%d] table\n",
				i);
		ida_destroy(&jfc_table->bank[i].ida);
	}

	if (!xa_empty(&jfc_table->xa)) {
		dev_err(udma_dev->dev, "JFC not empty\n");
		xa_for_each(&jfc_table->xa, index, jfc)
			hns3_udma_table_put(udma_dev, &jfc_table->table, index);
	}
	xa_destroy(&jfc_table->xa);
}

static void hns3_udma_init_jfc_table(struct hns3_udma_dev *udma_dev)
{
	struct hns3_udma_jfc_table *jfc_table = &udma_dev->jfc_table;
	uint32_t max;
	uint32_t i;

	mutex_init(&jfc_table->bank_mutex);
	xa_init(&jfc_table->xa);

	/* reserve jfc id 0 */
	jfc_table->bank[0].min = 1;

	max = udma_dev->caps.num_jfc / HNS3_UDMA_CQ_BANK_NUM - 1;

	for (i = 0; i < HNS3_UDMA_CQ_BANK_NUM; i++) {
		ida_init(&jfc_table->bank[i].ida);
		jfc_table->bank[i].max = max;
	}
}

static void hns3_udma_cleanup_jfr_table(struct hns3_udma_dev *dev)
{
	struct hns3_udma_jfr_table *jfr_table = &dev->jfr_table;
	struct hns3_udma_ida *jfr_ida = &jfr_table->jfr_ida;
	struct hns3_udma_jfr *jfr;
	unsigned long index = 0;

	if (!ida_is_empty(&jfr_ida->ida))
		dev_err(dev->dev, "IDA not empty in clean up jfr table.\n");
	ida_destroy(&jfr_ida->ida);

	if (!xa_empty(&jfr_table->xa)) {
		dev_err(dev->dev, "JFR not empty\n");
		xa_for_each(&jfr_table->xa, index, jfr)
			hns3_udma_table_put(dev, &jfr_table->table, index);
	}
	xa_destroy(&jfr_table->xa);
}

static void hns3_udma_init_jfr_table(struct hns3_udma_dev *dev)
{
	struct hns3_udma_jfr_table *jfr_table = &dev->jfr_table;
	struct hns3_udma_ida *jfr_ida = &jfr_table->jfr_ida;

	xa_init(&jfr_table->xa);
	ida_init(&jfr_ida->ida);
	jfr_ida->max = dev->caps.num_jfr - 1;
	/* reserve jfr id 0 */
	jfr_ida->min = 1;
}

static void hns3_udma_cleanup_jfs_table(struct hns3_udma_dev *dev)
{
	struct hns3_udma_jfs_table *jfs_table = &dev->jfs_table;
	struct hns3_udma_ida *jfs_ida = &jfs_table->jfs_ida;

	if (!ida_is_empty(&jfs_ida->ida))
		dev_err(dev->dev, "IDA not empty in clean up jfs table.\n");
	ida_destroy(&jfs_ida->ida);

	if (!xa_empty(&jfs_table->xa))
		dev_err(dev->dev, "JFS table not empty.\n");
	xa_destroy(&jfs_table->xa);
}

static void hns3_udma_init_jfs_table(struct hns3_udma_dev *dev)
{
	struct hns3_udma_jfs_table *jfs_table = &dev->jfs_table;
	struct hns3_udma_ida *jfs_ida = &jfs_table->jfs_ida;

	xa_init(&jfs_table->xa);
	ida_init(&jfs_ida->ida);
	jfs_ida->max = dev->caps.num_jfs - 1;
	/* reserve jfs id 0 */
	jfs_ida->min = 1;
}

static void hns3_udma_cleanup_jetty_table(struct hns3_udma_dev *dev)
{
	struct hns3_udma_jetty_table	*jetty_table = &dev->jetty_table;
	struct hns3_udma_ida *jetty_ida = &jetty_table->jetty_ida;

	if (!ida_is_empty(&jetty_ida->ida))
		dev_err(dev->dev, "IDA not empty in clean up jetty table.\n");
	ida_destroy(&jetty_ida->ida);

	if (!xa_empty(&jetty_table->xa))
		dev_err(dev->dev, "Jetty table not empty.\n");
	xa_destroy(&jetty_table->xa);
}

static void hns3_udma_init_jetty_table(struct hns3_udma_dev *dev)
{
	struct hns3_udma_jetty_table	*jetty_table = &dev->jetty_table;
	struct hns3_udma_ida *jetty_ida = &jetty_table->jetty_ida;

	xa_init(&jetty_table->xa);
	ida_init(&jetty_ida->ida);
	jetty_ida->max = dev->caps.num_jetty - 1;
	/* reserve jetty id 0 */
	jetty_ida->min = 1;
}

static void hns3_udma_cleanup_eid_table(struct hns3_udma_dev *dev)
{
	if (!xa_empty(&dev->eid_table))
		dev_err(dev->dev, "EID table not empty.\n");
	xa_destroy(&dev->eid_table);
}

static void hns3_udma_init_eid_table(struct hns3_udma_dev *dev)
{
	xa_init(&dev->eid_table);
}

int hns3_udma_init_eq_idx_table(struct hns3_udma_dev *udma_dev)
{
	uint32_t eq_num;

	eq_num = udma_dev->caps.num_comp_vectors +
		 udma_dev->caps.num_aeq_vectors;
	udma_dev->eq_table.idx_table = kcalloc(eq_num, sizeof(uint32_t),
						GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(udma_dev->eq_table.idx_table))
		return -ENOMEM;

	return 0;
}

int hns3_udma_setup_hca(struct hns3_udma_dev *udma_dev)
{
	struct device *dev = udma_dev->dev;
	int ret;

	INIT_LIST_HEAD(&udma_dev->qp_list);
	spin_lock_init(&udma_dev->qp_list_lock);
	INIT_LIST_HEAD(&udma_dev->dip_list);
	spin_lock_init(&udma_dev->dip_list_lock);

	hns3_udma_init_uar_table(udma_dev);

	ret = hns3_udma_init_qp_table(udma_dev);
	if (ret) {
		dev_err(dev, "Failed to init qp_table.\n");
		goto err_uar_table_free;
	}

	hns3_udma_init_seg_table(udma_dev);
	hns3_udma_init_jfc_table(udma_dev);
	hns3_udma_init_jfr_table(udma_dev);
	hns3_udma_init_jfs_table(udma_dev);
	hns3_udma_init_jetty_table(udma_dev);
	hns3_udma_init_eid_table(udma_dev);
	ret = hns3_udma_init_eq_idx_table(udma_dev);
	if (ret) {
		dev_err(dev, "Failed to init eq_table.\n");
		goto err_eq_table;
	}

	return 0;
err_eq_table:
	hns3_udma_cleanup_eid_table(udma_dev);
	hns3_udma_cleanup_jetty_table(udma_dev);
	hns3_udma_cleanup_jfs_table(udma_dev);
	hns3_udma_cleanup_jfr_table(udma_dev);
	hns3_udma_cleanup_jfc_table(udma_dev);
	hns3_udma_cleanup_seg_table(udma_dev);
	hns3_udma_cleanup_qp_table(udma_dev);

err_uar_table_free:
	hns3_udma_cleanup_uar_table(udma_dev);
	return ret;
}

void hns3_udma_teardown_hca(struct hns3_udma_dev *udma_dev)
{
	kfree(udma_dev->eq_table.idx_table);
	hns3_udma_cleanup_eid_table(udma_dev);
	hns3_udma_cleanup_jetty_table(udma_dev);
	hns3_udma_cleanup_jfs_table(udma_dev);
	hns3_udma_cleanup_jfr_table(udma_dev);
	hns3_udma_cleanup_jfc_table(udma_dev);
	hns3_udma_cleanup_seg_table(udma_dev);
	hns3_udma_cleanup_qp_table(udma_dev);
	hns3_udma_cleanup_uar_table(udma_dev);
}

int hns3_udma_init_common_hem(struct hns3_udma_dev *udma_dev)
{
	struct device *dev = udma_dev->dev;
	int ret;

	ret = hns3_udma_init_hem_table(udma_dev, &udma_dev->seg_table.table,
				       HEM_TYPE_MTPT, udma_dev->caps.mtpt_entry_sz,
				       udma_dev->caps.num_mtpts);
	if (ret) {
		dev_err(dev, "Failed to init MTPT context memory.\n");
		return ret;
	}
	dev_info(dev, "init MPT hem table success.\n");

	ret = hns3_udma_init_hem_table(udma_dev, &udma_dev->qp_table.qp_table,
				       HEM_TYPE_QPC, udma_dev->caps.qpc_sz,
				       udma_dev->caps.num_qps);
	if (ret) {
		dev_err(dev, "Failed to init QP context memory.\n");
		goto err_unmap_dmpt;
	}
	dev_info(dev, "init QPC hem table success.\n");

	ret = hns3_udma_init_hem_table(udma_dev, &udma_dev->jfc_table.table,
				       HEM_TYPE_CQC, udma_dev->caps.cqc_entry_sz,
				       udma_dev->caps.num_cqs);
	if (ret) {
		dev_err(dev, "Failed to init CQ context memory.\n");
		goto err_unmap_qp;
	}
	dev_info(dev, "init CQC hem table success.\n");

	if (udma_dev->caps.flags & HNS3_UDMA_CAP_FLAG_SRQ) {
		ret = hns3_udma_init_hem_table(udma_dev, &udma_dev->jfr_table.table,
					       HEM_TYPE_SRQC,
					       udma_dev->caps.srqc_entry_sz,
					       udma_dev->caps.num_srqs);
		if (ret) {
			dev_err(dev, "Failed to init SRQ context memory.\n");
			goto err_unmap_cq;
		}
		dev_info(dev, "init SRQC hem table success.\n");
	}

	if (udma_dev->caps.flags & HNS3_UDMA_CAP_FLAG_QP_FLOW_CTRL) {
		ret = hns3_udma_init_hem_table(udma_dev,
					       &udma_dev->qp_table.sccc_table,
					       HEM_TYPE_SCCC,
					       udma_dev->caps.scc_ctx_sz,
					       udma_dev->caps.num_qps);
		if (ret) {
			dev_err(dev, "Failed to init SCC context memory.\n");
			goto err_unmap_srq;
		}
		dev_info(dev, "init SCCC hem table success.\n");
	}

	if (udma_dev->caps.gmv_entry_sz) {
		ret = hns3_udma_init_hem_table(udma_dev, &udma_dev->gmv_table,
					       HEM_TYPE_GMV,
					       udma_dev->caps.gmv_entry_sz,
					       udma_dev->caps.gmv_entry_num);
		if (ret) {
			dev_err(dev, "failed to init gmv table memory.\n");
			goto err_unmap_ctx;
		}
		dev_info(dev, "init GMV hem table success.\n");
	}

	return 0;
err_unmap_ctx:
	if (udma_dev->caps.flags & HNS3_UDMA_CAP_FLAG_QP_FLOW_CTRL)
		hns3_udma_cleanup_hem_table(udma_dev,
					    &udma_dev->qp_table.sccc_table);
err_unmap_srq:
	if (udma_dev->caps.flags & HNS3_UDMA_CAP_FLAG_SRQ)
		hns3_udma_cleanup_hem_table(udma_dev, &udma_dev->jfr_table.table);
err_unmap_cq:
	hns3_udma_cleanup_hem_table(udma_dev, &udma_dev->jfc_table.table);
err_unmap_qp:
	hns3_udma_cleanup_hem_table(udma_dev, &udma_dev->qp_table.qp_table);
err_unmap_dmpt:
	hns3_udma_cleanup_hem_table(udma_dev, &udma_dev->seg_table.table);

	return ret;
}

static int hns3_udma_init_hem(struct hns3_udma_dev *udma_dev)
{
	struct device *dev = udma_dev->dev;
	int ret;

	ret = hns3_udma_init_common_hem(udma_dev);
	if (ret) {
		dev_err(dev, "Failed to init common hem table of PF.\n");
		return ret;
	}

	if (udma_dev->caps.qpc_timer_entry_sz) {
		ret = hns3_udma_init_hem_table(udma_dev, &udma_dev->qpc_timer_table,
					       HEM_TYPE_QPC_TIMER,
					       udma_dev->caps.qpc_timer_entry_sz,
					       udma_dev->caps.num_qpc_timer);
		if (ret) {
			dev_err(dev, "Failed to init QPC timer memory.\n");
			goto err_unmap_vf_hem;
		}
	}
	if (udma_dev->caps.cqc_timer_entry_sz) {
		ret = hns3_udma_init_hem_table(udma_dev, &udma_dev->cqc_timer_table,
					       HEM_TYPE_CQC_TIMER,
					       udma_dev->caps.cqc_timer_entry_sz,
					       udma_dev->caps.cqc_timer_bt_num);
		if (ret) {
			dev_err(dev, "Failed to init CQC timer memory.\n");
			goto err_unmap_qpc_timer;
		}
	}

	return 0;
err_unmap_qpc_timer:
	if (udma_dev->caps.qpc_timer_entry_sz)
		hns3_udma_cleanup_hem_table(udma_dev, &udma_dev->qpc_timer_table);
err_unmap_vf_hem:
	hns3_udma_cleanup_common_hem(udma_dev);

	return ret;
}

void hns3_udma_cleanup_common_hem(struct hns3_udma_dev *udma_dev)
{
	if (udma_dev->caps.gmv_entry_sz)
		hns3_udma_cleanup_hem_table(udma_dev, &udma_dev->gmv_table);
	if (udma_dev->caps.flags & HNS3_UDMA_CAP_FLAG_QP_FLOW_CTRL)
		hns3_udma_cleanup_hem_table(udma_dev,
					    &udma_dev->qp_table.sccc_table);
	if (udma_dev->caps.flags & HNS3_UDMA_CAP_FLAG_SRQ)
		hns3_udma_cleanup_hem_table(udma_dev, &udma_dev->jfr_table.table);
	hns3_udma_cleanup_hem_table(udma_dev, &udma_dev->jfc_table.table);

	hns3_udma_cleanup_hem_table(udma_dev, &udma_dev->qp_table.qp_table);
	hns3_udma_cleanup_hem_table(udma_dev, &udma_dev->seg_table.table);
}

static void hns3_udma_cleanup_hem(struct hns3_udma_dev *udma_dev)
{
	if (udma_dev->caps.qpc_timer_entry_sz)
		hns3_udma_cleanup_hem_table(udma_dev, &udma_dev->qpc_timer_table);
	if (udma_dev->caps.cqc_timer_entry_sz)
		hns3_udma_cleanup_hem_table(udma_dev, &udma_dev->cqc_timer_table);

	hns3_udma_cleanup_common_hem(udma_dev);
}

void hns3_udma_set_poe_ch_num(struct hns3_udma_dev *dev)
{
#define HNS3_UDMA_POE_CH_NUM 4
	dev->caps.poe_ch_num = HNS3_UDMA_POE_CH_NUM;
}

static void hns3_udma_set_devname(struct hns3_udma_dev *udma_dev,
				  struct ubcore_device *ub_dev)
{
#define UB_DEV_BASE_NAME "ubl"
#define UB_DEV_NAME_SHIFT 3

	if (strncasecmp(ub_dev->netdev->name, UB_DEV_BASE_NAME, UB_DEV_NAME_SHIFT))
		scnprintf(udma_dev->dev_name, UBCORE_MAX_DEV_NAME, "hns3_udma_c%ud%uf%u",
			  udma_dev->chip_id, udma_dev->die_id, udma_dev->func_id);
	else
		scnprintf(udma_dev->dev_name, UBCORE_MAX_DEV_NAME, "hns3_udma%s",
			  ub_dev->netdev->name + UB_DEV_NAME_SHIFT);

	dev_info(udma_dev->dev, "Set dev_name %s\n", udma_dev->dev_name);
	strlcpy(ub_dev->dev_name, udma_dev->dev_name, UBCORE_MAX_DEV_NAME);
}

static int hns3_udma_register_device(struct hns3_udma_dev *udma_dev)
{
	struct ubcore_device *ub_dev = NULL;

	ub_dev = &udma_dev->ub_dev;
	ub_dev->transport_type = UBCORE_TRANSPORT_HNS_UB;
	ub_dev->ops = &g_hns3_udma_dev_ops;
	ub_dev->dev.parent = udma_dev->dev;
	ub_dev->dma_dev = ub_dev->dev.parent;
	ub_dev->netdev = udma_dev->uboe.netdevs[0];
	scnprintf(ub_dev->ops->driver_name, UBCORE_MAX_DRIVER_NAME, "hns3_udma_v1");
	hns3_udma_set_devname(udma_dev, ub_dev);

	return ubcore_register_device(ub_dev);
}

static void hns3_udma_unregister_device(struct hns3_udma_dev *udma_dev)
{
	struct ubcore_device *ub_dev = &udma_dev->ub_dev;

	ubcore_unregister_device(ub_dev);
}

int hns3_udma_client_init(struct hns3_udma_dev *udma_dev)
{
	struct device *dev = udma_dev->dev;
	int ret;

	udma_dev->is_reset = false;

	ret = udma_dev->hw->cmq_init(udma_dev);
	if (ret) {
		dev_err(dev, "Init UB Command Queue failed!\n");
		goto error_failed_cmq_init;
	}

	ret = udma_dev->hw->hw_profile(udma_dev);
	if (ret) {
		dev_err(dev, "Get UB engine profile failed!\n");
		goto error_failed_hw_profile;
	}

	ret = hns3_udma_cmd_init(udma_dev);
	if (ret) {
		dev_err(dev, "cmd init failed!\n");
		goto error_failed_cmd_init;
	}

	ret = udma_dev->hw->init_eq(udma_dev);
	if (ret) {
		dev_err(dev, "eq init failed!\n");
		goto error_failed_eq_table;
	}

	if (udma_dev->cmd_mod) {
		ret = hns3_udma_cmd_use_events(udma_dev);
		if (ret) {
			udma_dev->cmd_mod = 0;
			dev_warn(dev,
				 "Cmd event mode failed, set back to poll!\n");
		}
	}

	ret = hns3_udma_init_hem(udma_dev);
	if (ret) {
		dev_err(dev, "init HEM(Hardware Entry Memory) failed!\n");
		goto error_failed_hem_init;
	}

	ret = hns3_udma_setup_hca(udma_dev);
	if (ret) {
		dev_err(dev, "setup hca failed!\n");
		goto error_failed_setup;
	}

	ret = udma_dev->hw->hw_init(udma_dev);
	if (ret) {
		dev_err(dev, "hw_init failed!\n");
		goto error_failed_engine_init;
	}

	hns3_udma_set_poe_ch_num(udma_dev);
	ret = hns3_udma_register_device(udma_dev);
	if (ret) {
		dev_err(dev, "hns3_udma register device failed!\n");
		goto error_failed_register_device;
	}

	hns3_udma_register_debugfs(udma_dev);

	return 0;

error_failed_register_device:
	udma_dev->hw->hw_exit(udma_dev);

error_failed_engine_init:
	hns3_udma_teardown_hca(udma_dev);

error_failed_setup:
	hns3_udma_cleanup_hem(udma_dev);

error_failed_hem_init:
	if (udma_dev->cmd_mod)
		hns3_udma_cmd_use_polling(udma_dev);

	udma_dev->hw->cleanup_eq(udma_dev);

error_failed_eq_table:
	hns3_udma_cmd_cleanup(udma_dev);

error_failed_cmd_init:
error_failed_hw_profile:
	udma_dev->hw->cmq_exit(udma_dev);

error_failed_cmq_init:
	return ret;
}

void hns3_udma_hnae_client_exit(struct hns3_udma_dev *udma_dev)
{
	hns3_udma_unregister_device(udma_dev);
	hns3_udma_unregister_debugfs(udma_dev);
	hns3_udma_free_dca_safe_buf(udma_dev);

	if (udma_dev->hw->hw_exit)
		udma_dev->hw->hw_exit(udma_dev);

	hns3_udma_teardown_hca(udma_dev);

	hns3_udma_cleanup_hem(udma_dev);

	if (udma_dev->cmd_mod)
		hns3_udma_cmd_use_polling(udma_dev);

	udma_dev->hw->cleanup_eq(udma_dev);

	hns3_udma_cmd_cleanup(udma_dev);
	if (udma_dev->hw->cmq_exit)
		udma_dev->hw->cmq_exit(udma_dev);
}

module_param(is_active, int, 0644);
MODULE_PARM_DESC(is_active, "Set the link status to ON, default: 1");
