// SPDX-License-Identifier: GPL-2.0
/* Huawei UDMA Linux driver
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

#include <linux/iommu.h>
#include <linux/pci.h>
#include "urma/ubcore_api.h"
#include "hns3_udma_abi.h"
#include "hnae3.h"
#include "hns3_udma_device.h"
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
#include "hns3_udma_debugfs.h"
#include "hns3_udma_eid.h"
#include "hns3_udma_user_ctl.h"

static int is_active = 1;

static int udma_uar_alloc(struct udma_dev *udma_dev, struct udma_uar *uar)
{
	struct udma_ida *uar_ida = &udma_dev->uar_ida;
	int id;

	/* Using bitmap to manager UAR index */
	id = ida_alloc_range(&uar_ida->ida, uar_ida->min, uar_ida->max,
			     GFP_KERNEL);
	if (id < 0) {
		dev_err(udma_dev->dev, "failed to alloc uar id(%d).\n", id);
		return id;
	}
	uar->logic_idx = (uint64_t)id;

	if (uar->logic_idx > 0 && udma_dev->caps.phy_num_uars > 1)
		uar->index = (uar->logic_idx - 1) %
			     (udma_dev->caps.phy_num_uars - 1) + 1;
	else
		uar->index = 0;

	uar->pfn = ((pci_resource_start(udma_dev->pci_dev,
					UDMA_DEV_START_OFFSET)) >> PAGE_SHIFT);
	if (udma_dev->caps.flags & UDMA_CAP_FLAG_DIRECT_WQE)
		udma_dev->dwqe_page =
			pci_resource_start(udma_dev->pci_dev,
					   UDMA_DEV_EX_START_OFFSET);

	return 0;
}

static int udma_init_ctx_resp(struct udma_dev *dev, struct ubcore_udrv_priv *udrv_data,
			      struct udma_dca_ctx *dca_ctx)
{
	struct udma_create_ctx_resp resp = {};
	int ret;

	resp.num_comp_vectors = dev->caps.num_comp_vectors;
	resp.num_qps_shift = dev->caps.num_qps_shift;
	resp.num_jfs_shift = dev->caps.num_jfs_shift;
	resp.num_jfr_shift = dev->caps.num_jfr_shift;
	resp.num_jetty_shift = dev->caps.num_jetty_shift;
	resp.max_jfc_cqe = dev->caps.max_cqes;
	resp.cqe_size = dev->caps.cqe_sz;
	resp.max_jfr_wr = dev->caps.max_srq_wrs;
	resp.max_jfr_sge = dev->caps.max_srq_sges;
	resp.max_jfs_wr = dev->caps.max_wqes;
	resp.max_jfs_sge = dev->caps.max_sq_sg;
	resp.poe_ch_num = dev->caps.poe_ch_num;
	resp.db_addr = pci_resource_start(dev->pci_dev, UDMA_DEV_START_OFFSET) +
		       UDMA_DB_ADDR_OFFSET;
	resp.chip_id = dev->chip_id;
	resp.die_id = dev->die_id;
	resp.func_id = dev->func_id;

	if (dev->caps.flags & UDMA_CAP_FLAG_DCA_MODE) {
		resp.dca_qps = dca_ctx->max_qps;
		resp.dca_mmap_size = dca_ctx->status_npage * PAGE_SIZE;
		resp.dca_mode = dev->caps.flags & UDMA_CAP_FLAG_DCA_MODE;
	}

	ret = copy_to_user((void *)udrv_data->out_addr, &resp,
			   min(udrv_data->out_len, (uint32_t)sizeof(resp)));
	if (ret)
		dev_err(dev->dev,
			"copy ctx resp to user failed, ret = %d.\n", ret);

	return ret;
}

static void udma_uar_free(struct udma_dev *udma_dev,
			  struct udma_ucontext *context)
{
	ida_free(&udma_dev->uar_ida.ida, (int)context->uar.logic_idx);
}

static struct ubcore_ucontext *udma_alloc_ucontext(struct ubcore_device *dev,
						   uint32_t eid_index,
						   struct ubcore_udrv_priv *udrv_data)
{
	struct udma_dev *udma_dev = to_udma_dev(dev);
	struct udma_ucontext *context;
	struct udma_eid *udma_eid;
	int ret;

	context = kzalloc(sizeof(struct udma_ucontext), GFP_KERNEL);
	if (!context)
		return NULL;

	udma_eid = (struct udma_eid *)xa_load(&udma_dev->eid_table, eid_index);
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

	ret = udma_uar_alloc(udma_dev, &context->uar);
	if (ret) {
		dev_err(udma_dev->dev, "Alloc udma_uar Failed.\n");
		goto err_alloc_ucontext;
	}

	ret = udma_register_udca(udma_dev, context, udrv_data);
	if (ret) {
		dev_err(udma_dev->dev, "Register udca Failed.\n");
		goto err_alloc_uar;
	}

	ret = udma_init_ctx_resp(udma_dev, udrv_data, &context->dca_ctx);
	if (ret) {
		dev_err(udma_dev->dev, "Init ctx resp failed.\n");
		udma_unregister_udca(udma_dev, context);
		goto err_alloc_uar;
	}

	if (context->dca_ctx.unit_size > 0 && udma_dev->caps.flags &
	    UDMA_CAP_FLAG_DCA_MODE)
		udma_register_uctx_debugfs(udma_dev, context);

	return &context->uctx;

err_alloc_uar:
	udma_uar_free(udma_dev, context);
err_alloc_ucontext:
	kfree(context);
	return NULL;
}

static int udma_free_ucontext(struct ubcore_ucontext *uctx)
{
	struct udma_ucontext *context = to_udma_ucontext(uctx);
	struct udma_dev *udma_dev = to_udma_dev(uctx->ub_dev);

	if (udma_dev->caps.flags & UDMA_CAP_FLAG_DCA_MODE)
		udma_unregister_udca(udma_dev, context);

	ida_free(&udma_dev->uar_ida.ida, (int)context->uar.logic_idx);
	kfree(context);
	return 0;
}

static int get_mmap_cmd(struct vm_area_struct *vma)
{
	return (vma->vm_pgoff & MAP_COMMAND_MASK);
}

static uint64_t get_mmap_idx(struct vm_area_struct *vma)
{
	return ((vma->vm_pgoff >> MAP_INDEX_SHIFT) & MAP_INDEX_MASK);
}

static int mmap_dca(struct ubcore_ucontext *context, struct vm_area_struct *vma)
{
	struct udma_ucontext *uctx = to_udma_ucontext(context);
	struct udma_dca_ctx *ctx = &uctx->dca_ctx;
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

static int udma_mmap(struct ubcore_ucontext *uctx, struct vm_area_struct *vma)
{
	struct udma_dev *udma_dev = to_udma_dev(uctx->ub_dev);
	uint64_t address;
	uint64_t qpn;
	int cmd;

	if (((vma->vm_end - vma->vm_start) % PAGE_SIZE) != 0) {
		dev_err(udma_dev->dev,
			"mmap failed, unexpected vm area size.\n");
		return -EINVAL;
	}

	cmd = get_mmap_cmd(vma);
	switch (cmd) {
	case UDMA_MMAP_UAR_PAGE:
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		if (io_remap_pfn_range(vma, vma->vm_start,
				       to_udma_ucontext(uctx)->uar.pfn,
				       PAGE_SIZE, vma->vm_page_prot))
			return -EAGAIN;
		break;
	case UDMA_MMAP_DWQE_PAGE:
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		qpn = get_mmap_idx(vma);
		address = udma_dev->dwqe_page + qpn * UDMA_DWQE_PAGE_SIZE;
		if (io_remap_pfn_range(vma, vma->vm_start,
				       address >> PAGE_SHIFT,
				       UDMA_DWQE_PAGE_SIZE, vma->vm_page_prot))
			return -EAGAIN;
		break;
	case UDMA_MMAP_RESET_PAGE:
		if (vma->vm_flags & (VM_WRITE | VM_EXEC))
			return -EINVAL;

		if (remap_pfn_range(vma, vma->vm_start,
				    page_to_pfn(udma_dev->reset_page),
				    PAGE_SIZE, vma->vm_page_prot))
			return -EAGAIN;
		break;
	case UDMA_MMAP_TYPE_DCA:
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

static int udma_query_stats(struct ubcore_device *dev, struct ubcore_stats_key *key,
			    struct ubcore_stats_val *val)
{
	struct ubcore_stats_com_val *com_val = (struct ubcore_stats_com_val *)val->addr;
	struct udma_cmq_desc desc[UDMA_QUERY_COUNTER];
	struct udma_dev *udma_dev = to_udma_dev(dev);
	struct udma_tx_err_cnt_cmd_data *resp_tx_err;
	struct udma_rx_cnt_cmd_data *resp_rx;
	struct udma_tx_cnt_cmd_data *resp_tx;
	int ret;
	int i;

	if (val->len != sizeof(struct ubcore_stats_com_val)) {
		dev_err(udma_dev->dev, "The val len is err.\n");
		return -EINVAL;
	}

	for (i = 0; i < UDMA_QUERY_COUNTER; i++) {
		udma_cmq_setup_basic_desc(&desc[i], UDMA_OPC_QUERY_COUNTER, true);
		if (i < (UDMA_QUERY_COUNTER - 1))
			desc[i].flag |= cpu_to_le16(UDMA_CMD_FLAG_NEXT);
		else
			desc[i].flag &= ~cpu_to_le16(UDMA_CMD_FLAG_NEXT);
	}

	ret = udma_cmq_send(udma_dev, desc, UDMA_QUERY_COUNTER);
	if (ret) {
		dev_err(udma_dev->dev, "Failed to query stats, ret = %d.\n", ret);
		return ret;
	}

	resp_rx = (struct udma_rx_cnt_cmd_data *)desc[UDMA_QX_RESP].data;
	resp_tx = (struct udma_tx_cnt_cmd_data *)desc[UDMA_TX_RESP].data;
	resp_tx_err = (struct udma_tx_err_cnt_cmd_data *)desc[UDMA_TX_ERR_RESP].data;

	com_val->tx_pkt = resp_tx->pkt_tx_cnt;
	com_val->tx_pkt_err = resp_tx_err->err_pkt_tx_cnt;

	com_val->rx_pkt = resp_rx->pkt_rx_cnt;
	com_val->rx_pkt_err = resp_rx->err_pkt_rx_cnt;

	/* tx_bytes and rx_bytes are not support now */
	com_val->tx_bytes = 0;
	com_val->rx_bytes = 0;

	return ret;
}

static uint16_t query_congest_alg(uint8_t udma_cc_caps)
{
	uint16_t ubcore_cc_alg = 0;

	if (udma_cc_caps & UDMA_CONG_SEL_DCQCN)
		ubcore_cc_alg |= UBCORE_CC_DCQCN;
	if (udma_cc_caps & UDMA_CONG_SEL_LDCP)
		ubcore_cc_alg |= UBCORE_CC_LDCP;
	if (udma_cc_caps & UDMA_CONG_SEL_HC3)
		ubcore_cc_alg |= UBCORE_CC_HC3;
	if (udma_cc_caps & UDMA_CONG_SEL_DIP)
		ubcore_cc_alg |= UBCORE_CC_DIP;

	return ubcore_cc_alg;
}

static int udma_query_device_attr(struct ubcore_device *dev,
				  struct ubcore_device_attr *attr)
{
#define UDMA_MAX_TP_IN_TPG 10
	struct udma_dev *udma_dev = to_udma_dev(dev);
	struct device *dev_of_udma = udma_dev->dev;
	struct net_device *net_dev;
	int i;

	attr->dev_cap.max_eid_cnt = udma_dev->caps.max_eid_cnt;
	attr->dev_cap.max_jfc = (1 << udma_dev->caps.num_jfc_shift);
	attr->dev_cap.max_jfs = (1 << udma_dev->caps.num_jfs_shift);
	attr->dev_cap.max_jfr = (1 << udma_dev->caps.num_jfr_shift);
	attr->dev_cap.max_jetty = (1 << udma_dev->caps.num_jetty_shift);
	attr->dev_cap.max_jfc_depth = udma_dev->caps.max_cqes;
	attr->dev_cap.max_jfs_depth = udma_dev->caps.max_wqes;
	attr->dev_cap.max_jfr_depth = udma_dev->caps.max_srq_wrs;
	attr->dev_cap.max_jfs_inline_size = udma_dev->caps.max_sq_inline;
	attr->dev_cap.max_jfs_sge = udma_dev->caps.max_sq_sg;
	attr->dev_cap.max_jfr_sge = udma_dev->caps.max_srq_sges;
	attr->dev_cap.max_msg_size = UDMA_MAX_MSG_LEN;
	attr->dev_cap.trans_mode = UBCORE_TP_UM;
	attr->dev_cap.feature.bs.oor = udma_dev->caps.oor_en;
	attr->dev_cap.ceq_cnt = udma_dev->caps.num_comp_vectors;
	attr->dev_cap.feature.bs.jfc_inline = !!(udma_dev->caps.flags & UDMA_CAP_FLAG_CQE_INLINE);
	attr->dev_cap.feature.bs.spray_en = !!(udma_dev->caps.flags & UDMA_CAP_FLAG_AR);
	attr->dev_cap.max_jfs_rsge = udma_dev->caps.max_sq_sg;
	attr->dev_cap.congestion_ctrl_alg = query_congest_alg(udma_dev->caps.cong_type);
	attr->dev_cap.max_fe_cnt = udma_dev->func_num - 1;
	attr->port_cnt = udma_dev->caps.num_ports;
	attr->tp_maintainer = true;
	attr->dev_cap.max_tp_in_tpg = UDMA_MAX_TP_IN_TPG;

	for (i = 0; i < udma_dev->caps.num_ports; i++) {
		net_dev = udma_dev->uboe.netdevs[i];
		if (!net_dev) {
			dev_err(dev_of_udma, "Find netdev %u failed!\n", i);
			return -EINVAL;
		}
		attr->port_attr[i].max_mtu =
			udma_mtu_int_to_enum(net_dev->max_mtu);
	}

	return 0;
}

static int udma_get_active_speed(uint32_t speed, struct ubcore_port_status *port_status)
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

static int udma_query_device_status(struct ubcore_device *dev,
				    struct ubcore_device_status *dev_status)
{
	struct udma_dev *udma_dev = to_udma_dev(dev);
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
			dev_err(udma_dev->dev, "Find netdev %u failed!\n", i);
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
						(mtu ? min(net_dev_mtu, mtu) : UBCORE_MTU_256);

		ret = udma_get_active_speed(udma_dev->caps.speed, &dev_status->port_status[i]);
		if (ret) {
			dev_err(udma_dev->dev, "Port[%u] query speed and width failed!\n", i);
			return ret;
		}
	}

	return 0;
}

int udma_send_req(struct ubcore_device *dev, struct ubcore_req *msg)
{
	struct udma_dev *udma_dev = to_udma_dev(dev);
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

int udma_send_resp(struct ubcore_device *dev, struct ubcore_resp_host *msg)
{
	struct udma_dev *udma_dev = to_udma_dev(dev);
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

static struct ubcore_ops g_udma_dev_ops = {
	.owner = THIS_MODULE,
	.abi_version = 1,
	.add_ueid = udma_add_ueid,
	.delete_ueid = udma_delete_ueid,
	.query_device_attr = udma_query_device_attr,
	.query_device_status = udma_query_device_status,
	.query_res = udma_query_res,
	.alloc_ucontext = udma_alloc_ucontext,
	.free_ucontext = udma_free_ucontext,
	.mmap = udma_mmap,
	.register_seg = udma_register_seg,
	.unregister_seg = udma_unregister_seg,
	.import_seg = udma_import_seg,
	.unimport_seg = udma_unimport_seg,
	.create_jfc = udma_create_jfc,
	.modify_jfc = udma_modify_jfc,
	.destroy_jfc = udma_destroy_jfc,
	.create_jfs = udma_create_jfs,
	.destroy_jfs = udma_destroy_jfs,
	.create_jfr = udma_create_jfr,
	.modify_jfr = udma_modify_jfr,
	.destroy_jfr = udma_destroy_jfr,
	.import_jfr = udma_import_jfr,
	.unimport_jfr = udma_unimport_jfr,
	.create_jetty = udma_create_jetty,
	.destroy_jetty = udma_destroy_jetty,
	.import_jetty = udma_import_jetty,
	.unimport_jetty = udma_unimport_jetty,
	.create_tp = udma_create_tp,
	.modify_tp = udma_modify_tp,
	.destroy_tp = udma_destroy_tp,
	.send_req = udma_send_req,
	.send_resp = udma_send_resp,
	.user_ctl = udma_user_ctl,
	.query_stats = udma_query_stats,
};

static void udma_cleanup_uar_table(struct udma_dev *dev)
{
	struct udma_ida *uar_ida = &dev->uar_ida;

	if (!ida_is_empty(&uar_ida->ida))
		dev_err(dev->dev, "IDA not empty in clean up uar table.\n");
	ida_destroy(&uar_ida->ida);
}

static void udma_init_uar_table(struct udma_dev *udma_dev)
{
	struct udma_ida *uar_ida = &udma_dev->uar_ida;

	ida_init(&uar_ida->ida);
	uar_ida->max = udma_dev->caps.num_uars - 1;
	uar_ida->min = udma_dev->caps.reserved_uars;
}

static void udma_cleanup_seg_table(struct udma_dev *dev)
{
	struct udma_ida *seg_ida = &dev->seg_table.seg_ida;

	if (!ida_is_empty(&seg_ida->ida))
		dev_err(dev->dev, "IDA not empty in clean up seg table.\n");
	ida_destroy(&seg_ida->ida);
}

static void udma_init_seg_table(struct udma_dev *udma_dev)
{
	struct udma_ida *seg_ida = &udma_dev->seg_table.seg_ida;

	ida_init(&seg_ida->ida);
	seg_ida->max = udma_dev->caps.num_mtpts - 1;
	seg_ida->min = udma_dev->caps.reserved_mrws;
}

static void udma_cleanup_jfc_table(struct udma_dev *udma_dev)
{
	struct udma_jfc_table *jfc_table = &udma_dev->jfc_table;
	struct udma_jfc *jfc;
	unsigned long index;
	int i;

	for (i = 0; i < UDMA_CQ_BANK_NUM; i++) {
		if (!ida_is_empty(&jfc_table->bank[i].ida))
			dev_err(udma_dev->dev,
				"IDA not empty in clean up jfc bank[%d] table\n",
				i);
		ida_destroy(&jfc_table->bank[i].ida);
	}

	if (!xa_empty(&jfc_table->xa)) {
		dev_err(udma_dev->dev, "JFC not empty\n");
		xa_for_each(&jfc_table->xa, index, jfc)
			udma_table_put(udma_dev, &jfc_table->table, index);
	}
	xa_destroy(&jfc_table->xa);
}

static void udma_init_jfc_table(struct udma_dev *udma_dev)
{
	struct udma_jfc_table *jfc_table = &udma_dev->jfc_table;
	uint32_t reserved_from_bot;
	uint32_t i;

	mutex_init(&jfc_table->bank_mutex);
	xa_init(&jfc_table->xa);

	reserved_from_bot = 1;

	for (i = 0; i < reserved_from_bot; i++) {
		jfc_table->bank[get_jfc_bankid(i)].inuse++;
		jfc_table->bank[get_jfc_bankid(i)].min++;
	}

	for (i = 0; i < UDMA_CQ_BANK_NUM; i++) {
		ida_init(&jfc_table->bank[i].ida);
		jfc_table->bank[i].max = (1 << udma_dev->caps.num_jfc_shift) /
					UDMA_CQ_BANK_NUM - 1;
	}
}

static void udma_cleanup_jfr_table(struct udma_dev *dev)
{
	struct udma_jfr_table *jfr_table = &dev->jfr_table;
	struct udma_ida *jfr_ida = &jfr_table->jfr_ida;
	unsigned long index = 0;
	struct udma_jfr *jfr;

	if (!ida_is_empty(&jfr_ida->ida))
		dev_err(dev->dev, "IDA not empty in clean up jfr table.\n");
	ida_destroy(&jfr_ida->ida);

	if (!xa_empty(&jfr_table->xa)) {
		dev_err(dev->dev, "JFR not empty\n");
		xa_for_each(&jfr_table->xa, index, jfr)
			udma_table_put(dev, &jfr_table->table, index);
	}
	xa_destroy(&jfr_table->xa);
}

static void udma_init_jfr_table(struct udma_dev *dev)
{
	struct udma_jfr_table *jfr_table = &dev->jfr_table;
	struct udma_ida *jfr_ida = &jfr_table->jfr_ida;

	xa_init(&jfr_table->xa);
	ida_init(&jfr_ida->ida);
	jfr_ida->max = (1 << dev->caps.num_jfr_shift) - 1;
	/* reserve jfr id 0 */
	jfr_ida->min = 1;
}

static void udma_cleanup_jfs_table(struct udma_dev *dev)
{
	struct udma_jfs_table *jfs_table = &dev->jfs_table;
	struct udma_ida *jfs_ida = &jfs_table->jfs_ida;

	if (!ida_is_empty(&jfs_ida->ida))
		dev_err(dev->dev, "IDA not empty in clean up jfs table.\n");
	ida_destroy(&jfs_ida->ida);

	if (!xa_empty(&jfs_table->xa))
		dev_err(dev->dev, "JFS table not empty.\n");
	xa_destroy(&jfs_table->xa);
}

static void udma_init_jfs_table(struct udma_dev *dev)
{
	struct udma_jfs_table *jfs_table = &dev->jfs_table;
	struct udma_ida *jfs_ida = &jfs_table->jfs_ida;

	xa_init(&jfs_table->xa);
	ida_init(&jfs_ida->ida);
	jfs_ida->max = (1 << dev->caps.num_jfs_shift) - 1;
	/* reserve jfs id 0 */
	jfs_ida->min = 1;
}

static void udma_cleanup_jetty_table(struct udma_dev *dev)
{
	struct udma_jetty_table	*jetty_table = &dev->jetty_table;
	struct udma_ida *jetty_ida = &jetty_table->jetty_ida;

	if (!ida_is_empty(&jetty_ida->ida))
		dev_err(dev->dev, "IDA not empty in clean up jetty table.\n");
	ida_destroy(&jetty_ida->ida);

	if (!xa_empty(&jetty_table->xa))
		dev_err(dev->dev, "Jetty table not empty.\n");
	xa_destroy(&jetty_table->xa);
}

static void udma_init_jetty_table(struct udma_dev *dev)
{
	struct udma_jetty_table	*jetty_table = &dev->jetty_table;
	struct udma_ida *jetty_ida = &jetty_table->jetty_ida;

	xa_init(&jetty_table->xa);
	ida_init(&jetty_ida->ida);
	jetty_ida->max = (1 << dev->caps.num_jetty_shift) - 1;
	/* reserve jetty id 0 */
	jetty_ida->min = 1;
}

static void udma_cleanup_eid_table(struct udma_dev *dev)
{
	if (!xa_empty(&dev->eid_table))
		dev_err(dev->dev, "EID table not empty.\n");
	xa_destroy(&dev->eid_table);
}

static void udma_init_eid_table(struct udma_dev *dev)
{
	xa_init(&dev->eid_table);
}

int udma_init_eq_idx_table(struct udma_dev *udma_dev)
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

int udma_setup_hca(struct udma_dev *udma_dev)
{
	struct device *dev = udma_dev->dev;
	int ret;

	INIT_LIST_HEAD(&udma_dev->qp_list);
	spin_lock_init(&udma_dev->qp_list_lock);
	INIT_LIST_HEAD(&udma_dev->dip_list);
	spin_lock_init(&udma_dev->dip_list_lock);

	if (udma_dev->caps.flags & UDMA_CAP_FLAG_CQ_RECORD_DB ||
	    udma_dev->caps.flags & UDMA_CAP_FLAG_QP_RECORD_DB) {
		INIT_LIST_HEAD(&udma_dev->pgdir_list);
		mutex_init(&udma_dev->pgdir_mutex);
	}

	udma_init_uar_table(udma_dev);

	ret = udma_init_qp_table(udma_dev);
	if (ret) {
		dev_err(dev, "Failed to init qp_table.\n");
		goto err_uar_table_free;
	}

	udma_init_seg_table(udma_dev);
	udma_init_jfc_table(udma_dev);
	udma_init_jfr_table(udma_dev);
	udma_init_jfs_table(udma_dev);
	udma_init_jetty_table(udma_dev);
	udma_init_eid_table(udma_dev);
	ret = udma_init_eq_idx_table(udma_dev);
	if (ret) {
		dev_err(dev, "Failed to init eq_table.\n");
		goto err_eq_table;
	}

	return 0;
err_eq_table:
	udma_cleanup_eid_table(udma_dev);
	udma_cleanup_jetty_table(udma_dev);
	udma_cleanup_jfs_table(udma_dev);
	udma_cleanup_jfr_table(udma_dev);
	udma_cleanup_jfc_table(udma_dev);
	udma_cleanup_seg_table(udma_dev);
	udma_cleanup_qp_table(udma_dev);

err_uar_table_free:
	udma_cleanup_uar_table(udma_dev);
	return ret;
}

void udma_teardown_hca(struct udma_dev *udma_dev)
{
	kfree(udma_dev->eq_table.idx_table);
	udma_cleanup_eid_table(udma_dev);
	udma_cleanup_jetty_table(udma_dev);
	udma_cleanup_jfs_table(udma_dev);
	udma_cleanup_jfr_table(udma_dev);
	udma_cleanup_jfc_table(udma_dev);
	udma_cleanup_seg_table(udma_dev);
	udma_cleanup_qp_table(udma_dev);
	udma_cleanup_uar_table(udma_dev);
}

int udma_init_common_hem(struct udma_dev *udma_dev)
{
	struct device *dev = udma_dev->dev;
	int ret;

	ret = udma_init_hem_table(udma_dev, &udma_dev->seg_table.table,
				  HEM_TYPE_MTPT, udma_dev->caps.mtpt_entry_sz,
				  udma_dev->caps.num_mtpts);
	if (ret) {
		dev_err(dev, "Failed to init MTPT context memory.\n");
		return ret;
	}
	dev_info(dev, "init MPT hem table success.\n");

	ret = udma_init_hem_table(udma_dev, &udma_dev->qp_table.qp_table,
				  HEM_TYPE_QPC, udma_dev->caps.qpc_sz,
				  udma_dev->caps.num_qps);
	if (ret) {
		dev_err(dev, "Failed to init QP context memory.\n");
		goto err_unmap_dmpt;
	}
	dev_info(dev, "init QPC hem table success.\n");

	ret = udma_init_hem_table(udma_dev, &udma_dev->qp_table.irrl_table,
				  HEM_TYPE_IRRL, udma_dev->caps.irrl_entry_sz *
				  udma_dev->caps.max_qp_init_rdma,
				  udma_dev->caps.num_qps);
	if (ret) {
		dev_err(dev, "Failed to init irrl_table memory.\n");
		goto err_unmap_qp;
	}
	dev_info(dev, "init IRRL hem table success.\n");

	if (udma_dev->caps.trrl_entry_sz) {
		ret = udma_init_hem_table(udma_dev,
					  &udma_dev->qp_table.trrl_table,
					  HEM_TYPE_TRRL,
					  udma_dev->caps.trrl_entry_sz *
					  udma_dev->caps.max_qp_dest_rdma,
					  udma_dev->caps.num_qps);
		if (ret) {
			dev_err(dev, "Failed to init trrl_table memory.\n");
			goto err_unmap_irrl;
		}
		dev_info(dev, "init TRRL hem table success.\n");
	}

	ret = udma_init_hem_table(udma_dev, &udma_dev->jfc_table.table,
				  HEM_TYPE_CQC, udma_dev->caps.cqc_entry_sz,
				  udma_dev->caps.num_cqs);
	if (ret) {
		dev_err(dev, "Failed to init CQ context memory.\n");
		goto err_unmap_trrl;
	}
	dev_info(dev, "init CQC hem table success.\n");

	if (udma_dev->caps.flags & UDMA_CAP_FLAG_SRQ) {
		ret = udma_init_hem_table(udma_dev, &udma_dev->jfr_table.table,
					  HEM_TYPE_SRQC,
					  udma_dev->caps.srqc_entry_sz,
					  udma_dev->caps.num_srqs);
		if (ret) {
			dev_err(dev, "Failed to init SRQ context memory.\n");
			goto err_unmap_cq;
		}
		dev_info(dev, "init SRQC hem table success.\n");
	}

	if (udma_dev->caps.flags & UDMA_CAP_FLAG_QP_FLOW_CTRL) {
		ret = udma_init_hem_table(udma_dev,
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
		ret = udma_init_hem_table(udma_dev, &udma_dev->gmv_table,
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
	if (udma_dev->caps.flags & UDMA_CAP_FLAG_QP_FLOW_CTRL)
		udma_cleanup_hem_table(udma_dev,
				       &udma_dev->qp_table.sccc_table);
err_unmap_srq:
	if (udma_dev->caps.flags & UDMA_CAP_FLAG_SRQ)
		udma_cleanup_hem_table(udma_dev, &udma_dev->jfr_table.table);
err_unmap_cq:
	udma_cleanup_hem_table(udma_dev, &udma_dev->jfc_table.table);
err_unmap_trrl:
	if (udma_dev->caps.trrl_entry_sz)
		udma_cleanup_hem_table(udma_dev,
				       &udma_dev->qp_table.trrl_table);
err_unmap_irrl:
	udma_cleanup_hem_table(udma_dev, &udma_dev->qp_table.irrl_table);
err_unmap_qp:
	udma_cleanup_hem_table(udma_dev, &udma_dev->qp_table.qp_table);
err_unmap_dmpt:
	udma_cleanup_hem_table(udma_dev, &udma_dev->seg_table.table);

	return ret;
}

static int udma_init_hem(struct udma_dev *udma_dev)
{
	struct device *dev = udma_dev->dev;
	int ret;

	ret = udma_init_common_hem(udma_dev);
	if (ret) {
		dev_err(dev, "Failed to init common hem table of PF.\n");
		return ret;
	}

	if (udma_dev->caps.qpc_timer_entry_sz) {
		ret = udma_init_hem_table(udma_dev, &udma_dev->qpc_timer_table,
					  HEM_TYPE_QPC_TIMER,
					  udma_dev->caps.qpc_timer_entry_sz,
					  udma_dev->caps.num_qpc_timer);
		if (ret) {
			dev_err(dev, "Failed to init QPC timer memory.\n");
			goto err_unmap_vf_hem;
		}
	}
	if (udma_dev->caps.cqc_timer_entry_sz) {
		ret = udma_init_hem_table(udma_dev, &udma_dev->cqc_timer_table,
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
		udma_cleanup_hem_table(udma_dev, &udma_dev->qpc_timer_table);
err_unmap_vf_hem:
	udma_cleanup_common_hem(udma_dev);

	return ret;
}

void udma_cleanup_common_hem(struct udma_dev *udma_dev)
{
	if (udma_dev->caps.gmv_entry_sz)
		udma_cleanup_hem_table(udma_dev, &udma_dev->gmv_table);
	if (udma_dev->caps.flags & UDMA_CAP_FLAG_QP_FLOW_CTRL)
		udma_cleanup_hem_table(udma_dev,
				       &udma_dev->qp_table.sccc_table);
	if (udma_dev->caps.flags & UDMA_CAP_FLAG_SRQ)
		udma_cleanup_hem_table(udma_dev, &udma_dev->jfr_table.table);
	udma_cleanup_hem_table(udma_dev, &udma_dev->jfc_table.table);
	if (udma_dev->caps.trrl_entry_sz)
		udma_cleanup_hem_table(udma_dev,
				       &udma_dev->qp_table.trrl_table);

	udma_cleanup_hem_table(udma_dev, &udma_dev->qp_table.irrl_table);
	udma_cleanup_hem_table(udma_dev, &udma_dev->qp_table.qp_table);
	udma_cleanup_hem_table(udma_dev, &udma_dev->seg_table.table);
}

static void udma_cleanup_hem(struct udma_dev *udma_dev)
{
	if (udma_dev->caps.qpc_timer_entry_sz)
		udma_cleanup_hem_table(udma_dev, &udma_dev->qpc_timer_table);
	if (udma_dev->caps.cqc_timer_entry_sz)
		udma_cleanup_hem_table(udma_dev, &udma_dev->cqc_timer_table);

	udma_cleanup_common_hem(udma_dev);
}

void udma_set_poe_ch_num(struct udma_dev *dev)
{
#define UDMA_POE_CH_NUM 4

	dev->caps.poe_ch_num = UDMA_POE_CH_NUM;
}

static void udma_set_devname(struct udma_dev *udma_dev,
			     struct ubcore_device *ub_dev)
{
	if (strncasecmp(ub_dev->netdev->name, UB_DEV_BASE_NAME, UB_DEV_NAME_SHIFT))
		scnprintf(udma_dev->dev_name, UBCORE_MAX_DEV_NAME, "udma_c%ud%uf%u",
			  udma_dev->chip_id, udma_dev->die_id, udma_dev->func_id);
	else
		scnprintf(udma_dev->dev_name, UBCORE_MAX_DEV_NAME, "udma%s",
			  ub_dev->netdev->name + UB_DEV_NAME_SHIFT);

	dev_info(udma_dev->dev, "Set dev_name %s\n", udma_dev->dev_name);
	strlcpy(ub_dev->dev_name, udma_dev->dev_name, UBCORE_MAX_DEV_NAME);
}

static int udma_register_device(struct udma_dev *udma_dev)
{
	struct ubcore_device *ub_dev = NULL;
	struct udma_netdev *uboe = NULL;

	ub_dev = &udma_dev->ub_dev;
	uboe = &udma_dev->uboe;
	spin_lock_init(&uboe->lock);
	ub_dev->transport_type = UBCORE_TRANSPORT_IB;
	ub_dev->ops = &g_udma_dev_ops;
	ub_dev->dev.parent = udma_dev->dev;
	ub_dev->dma_dev = ub_dev->dev.parent;
	ub_dev->netdev = udma_dev->uboe.netdevs[0];
	scnprintf(ub_dev->ops->driver_name, UBCORE_MAX_DRIVER_NAME, "udma_v1");
	udma_set_devname(udma_dev, ub_dev);

	return ubcore_register_device(ub_dev);
}

static void udma_unregister_device(struct udma_dev *udma_dev)
{
	struct ubcore_device *ub_dev = &udma_dev->ub_dev;

	ubcore_unregister_device(ub_dev);
}

int udma_hnae_client_init(struct udma_dev *udma_dev)
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

	ret = udma_cmd_init(udma_dev);
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
		ret = udma_cmd_use_events(udma_dev);
		if (ret) {
			udma_dev->cmd_mod = 0;
			dev_warn(dev,
				 "Cmd event mode failed, set back to poll!\n");
		}
	}

	ret = udma_init_hem(udma_dev);
	if (ret) {
		dev_err(dev, "init HEM(Hardware Entry Memory) failed!\n");
		goto error_failed_hem_init;
	}

	ret = udma_setup_hca(udma_dev);
	if (ret) {
		dev_err(dev, "setup hca failed!\n");
		goto error_failed_setup;
	}

	ret = udma_dev->hw->hw_init(udma_dev);
	if (ret) {
		dev_err(dev, "hw_init failed!\n");
		goto error_failed_engine_init;
	}

	udma_set_poe_ch_num(udma_dev);
	ret = udma_register_device(udma_dev);
	if (ret) {
		dev_err(dev, "udma register device failed!\n");
		goto error_failed_register_device;
	}

	udma_register_debugfs(udma_dev);

	return 0;

error_failed_register_device:
	udma_dev->hw->hw_exit(udma_dev);

error_failed_engine_init:
	udma_teardown_hca(udma_dev);

error_failed_setup:
	udma_cleanup_hem(udma_dev);

error_failed_hem_init:
	if (udma_dev->cmd_mod)
		udma_cmd_use_polling(udma_dev);

	udma_dev->hw->cleanup_eq(udma_dev);

error_failed_eq_table:
	udma_cmd_cleanup(udma_dev);

error_failed_cmd_init:
error_failed_hw_profile:
	udma_dev->hw->cmq_exit(udma_dev);

error_failed_cmq_init:
	return ret;
}

void udma_hnae_client_exit(struct udma_dev *udma_dev)
{
	udma_unregister_device(udma_dev);
	udma_unregister_debugfs(udma_dev);

	if (udma_dev->hw->hw_exit)
		udma_dev->hw->hw_exit(udma_dev);

	udma_teardown_hca(udma_dev);

	udma_cleanup_hem(udma_dev);

	if (udma_dev->cmd_mod)
		udma_cmd_use_polling(udma_dev);

	udma_dev->hw->cleanup_eq(udma_dev);

	udma_cmd_cleanup(udma_dev);
	if (udma_dev->hw->cmq_exit)
		udma_dev->hw->cmq_exit(udma_dev);
}

module_param(is_active, int, 0644);
MODULE_PARM_DESC(is_active, "Set the link status to ON, default: 1");
