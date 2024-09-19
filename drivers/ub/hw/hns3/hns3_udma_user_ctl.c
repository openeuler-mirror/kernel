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

#include "urma/ubcore_api.h"
#include "hns3_udma_dca.h"
#include "hns3_udma_cmd.h"
#include "hns3_udma_user_ctl_api.h"

int hns3_udma_user_ctl_flush_cqe(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
				 struct ubcore_user_ctl_out *out,
				 struct ubcore_udrv_priv *udrv_data)
{
	struct hns3_udma_dev *udma_device = to_hns3_udma_dev(uctx->ub_dev);
	struct flush_cqe_param fcp = {};
	struct hns3_udma_qp *udma_qp;
	unsigned long byte;
	uint32_t sq_pi;
	uint32_t qpn;
	int ret;

	if (in->len < sizeof(struct flush_cqe_param)) {
		dev_err(udma_device->dev, "invalid input in flush cqe: len %u\n", in->len);
		return -EINVAL;
	}

	byte = copy_from_user(&fcp, (void *)in->addr,
			      sizeof(struct flush_cqe_param));
	if (byte) {
		dev_err(udma_device->dev,
			"copy_from_user failed in flush_cqe, byte:%lu.\n", byte);
		return -EFAULT;
	}
	sq_pi = fcp.sq_producer_idx;
	qpn = fcp.qpn;

	xa_lock(&udma_device->qp_table.xa);
	udma_qp = (struct hns3_udma_qp *)xa_load(&udma_device->qp_table.xa, qpn);
	if (!udma_qp) {
		dev_err(udma_device->dev, "get qp(0x%x) error.\n", qpn);
		xa_unlock(&udma_device->qp_table.xa);
		return -EINVAL;
	}
	refcount_inc(&udma_qp->refcount);
	xa_unlock(&udma_device->qp_table.xa);

	ret = hns3_udma_flush_cqe(udma_device, udma_qp, sq_pi);

	if (refcount_dec_and_test(&udma_qp->refcount))
		complete(&udma_qp->free);

	return ret;
}

static int config_poe_addr(struct hns3_udma_dev *udma_device, uint8_t id,
			   uint64_t addr)
{
	struct hns3_udma_poe_cfg_addr_cmq *cmd;
	struct hns3_udma_cmq_desc desc = {};
	int ret;

	hns3_udma_cmq_setup_basic_desc(&desc, HNS3_UDMA_OPC_CFG_POE_ADDR, false);
	cmd = (struct hns3_udma_poe_cfg_addr_cmq *)desc.data;
	cmd->channel_id = cpu_to_le32(id);
	cmd->poe_addr_l = cpu_to_le32(lower_32_bits(addr));
	cmd->poe_addr_h = cpu_to_le32(upper_32_bits(addr));

	ret = hns3_udma_cmq_send(udma_device, &desc, 1);
	if (ret)
		dev_err(udma_device->dev,
			"configure poe channel %u addr failed, ret = %d.\n",
			id, ret);
	return ret;
}

static int config_poe_attr(struct hns3_udma_dev *udma_device, uint8_t id, bool en)
{
	struct hns3_udma_poe_cfg_attr_cmq *cmd;
	struct hns3_udma_cmq_desc desc = {};
	int ret;

	hns3_udma_cmq_setup_basic_desc(&desc, HNS3_UDMA_OPC_CFG_POE_ATTR, false);
	cmd = (struct hns3_udma_poe_cfg_attr_cmq *)desc.data;
	cmd->channel_id = cpu_to_le32(id);
	cmd->rsv_en_outstd = en ? 1 : 0;

	ret = hns3_udma_cmq_send(udma_device, &desc, 1);
	if (ret)
		dev_err(udma_device->dev,
			"configure poe channel %u attr failed, ret = %d.\n",
			id, ret);
	return ret;
}

static int check_poe_channel(struct hns3_udma_dev *udma_device, uint8_t poe_ch)
{
	if (poe_ch >= udma_device->caps.poe_ch_num) {
		dev_err(udma_device->dev, "invalid POE channel %u.\n", poe_ch);
		return -EINVAL;
	}

	return 0;
}

static int hns3_udma_config_and_active_poe(struct hns3_udma_dev *dev,
					   uint8_t poe_channel,
					   uint64_t poe_addr)
{
	int ret;

	ret = config_poe_addr(dev, poe_channel, poe_addr);
	if (ret) {
		dev_err(dev->dev, "config poe addr failed, ret = %d.\n", ret);
		return ret;
	}

	ret = config_poe_attr(dev, poe_channel, !!poe_addr);
	if (ret) {
		dev_err(dev->dev, "config poe attr failed, ret = %d.\n", ret);
		(void)config_poe_addr(dev, poe_channel, 0);
	}

	return ret;
}

int hns3_udma_user_ctl_config_poe(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
				  struct ubcore_user_ctl_out *out,
				  struct ubcore_udrv_priv *udrv_data)
{
	struct hns3_udma_poe_info poe_info = {};
	struct hns3_udma_dev *udma_device;
	unsigned long byte;
	int ret;

	udma_device = to_hns3_udma_dev(uctx->ub_dev);
	if (in->len < sizeof(struct hns3_udma_poe_info)) {
		dev_err(udma_device->dev, "invalid input in config poe: len %u\n", in->len);
		return -EINVAL;
	}

	byte = copy_from_user(&poe_info, (void *)in->addr,
			      sizeof(struct hns3_udma_poe_info));
	if (byte) {
		dev_err(udma_device->dev, "cp from user failed in config poe, byte:%lu.\n",
			byte);
		return -EFAULT;
	}

	ret = check_poe_channel(udma_device, poe_info.poe_channel);
	if (ret) {
		dev_err(udma_device->dev, "check channel failed in config poe, ret:%d.\n",
			ret);
		return ret;
	}

	return hns3_udma_config_and_active_poe(udma_device, poe_info.poe_channel,
					       poe_info.poe_addr);
}

static int query_poe_addr(struct hns3_udma_dev *udma_device, uint8_t id,
			  uint64_t *addr)
{
#define POE_ADDR_H_SHIFT 32
	struct hns3_udma_poe_cfg_addr_cmq *resp;
	struct hns3_udma_cmq_desc desc = {};
	int ret;

	hns3_udma_cmq_setup_basic_desc(&desc, HNS3_UDMA_OPC_CFG_POE_ADDR, true);
	resp = (struct hns3_udma_poe_cfg_addr_cmq *)desc.data;
	resp->channel_id = cpu_to_le32(id);

	ret = hns3_udma_cmq_send(udma_device, &desc, 1);
	if (ret) {
		dev_err(udma_device->dev,
			"Query poe channel %u addr failed, ret = %d.\n",
			id, ret);
		return ret;
	}

	*addr = resp->poe_addr_l | ((uint64_t)resp->poe_addr_h <<
				    POE_ADDR_H_SHIFT);

	return ret;
}

static int query_poe_attr(struct hns3_udma_dev *udma_device, uint8_t id, bool *en)
{
	struct hns3_udma_poe_cfg_attr_cmq *resp;
	struct hns3_udma_cmq_desc desc = {};
	int ret;

	hns3_udma_cmq_setup_basic_desc(&desc, HNS3_UDMA_OPC_CFG_POE_ATTR, true);
	resp = (struct hns3_udma_poe_cfg_attr_cmq *)desc.data;
	resp->channel_id = cpu_to_le32(id);

	ret = hns3_udma_cmq_send(udma_device, &desc, 1);
	if (ret) {
		dev_err(udma_device->dev,
			"Query poe channel %u attr failed, ret = %d.\n",
			id, ret);
		return ret;
	}

	*en = !!resp->rsv_en_outstd;

	return ret;
}

int hns3_udma_user_ctl_query_poe(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
				 struct ubcore_user_ctl_out *out,
				 struct ubcore_udrv_priv *udrv_data)
{
	struct hns3_udma_dev *udma_device = to_hns3_udma_dev(uctx->ub_dev);
	struct hns3_udma_poe_info poe_info_out = {};
	struct hns3_udma_poe_info poe_info_in = {};
	uint64_t poe_addr;
	bool poe_en;
	int ret;

	if (in->len < sizeof(struct hns3_udma_poe_info) || ((void *)out->addr == NULL) ||
	   (out->len < sizeof(struct hns3_udma_poe_info))) {
		dev_err(udma_device->dev,
			"invalid param in query poe: in len %u, out len %u, or out addr is NULL\n",
			in->len, out->len);
		return -EINVAL;
	}

	if (copy_from_user(&poe_info_in, (void *)in->addr,
			   sizeof(struct hns3_udma_poe_info))) {
		dev_err(udma_device->dev, "cp from user failed in query poe.\n");
		return -EFAULT;
	}

	ret = check_poe_channel(udma_device, poe_info_in.poe_channel);
	if (ret) {
		dev_err(udma_device->dev, "check channel failed in query poe, ret:%d.\n",
			ret);
		return ret;
	}

	ret = query_poe_attr(udma_device, poe_info_in.poe_channel, &poe_en);
	if (ret) {
		dev_err(udma_device->dev, "query attr failed in query poe, ret:%d.\n",
			ret);
		return ret;
	}

	ret = query_poe_addr(udma_device, poe_info_in.poe_channel, &poe_addr);
	if (ret) {
		dev_err(udma_device->dev, "query addr failed in query poe, ret:%d.\n",
			ret);
		return ret;
	}

	poe_info_out.en = poe_en ? 1 : 0;
	poe_info_out.poe_addr = poe_addr;
	if (copy_to_user((void *)out->addr, &poe_info_out, sizeof(struct hns3_udma_poe_info))) {
		dev_err(udma_device->dev, "cp to user failed in query poe.");
		return -EFAULT;
	}
	return ret;
}

int hns3_udma_user_ctl_dca_reg(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
			       struct ubcore_user_ctl_out *out, struct ubcore_udrv_priv *udrv_data)
{
	struct hns3_udma_dev *udma_device = to_hns3_udma_dev(uctx->ub_dev);
	struct hns3_udma_ucontext *context = to_hns3_udma_ucontext(uctx);
	struct hns3_udma_dca_reg_attr attr = {};
	int ret;

	if (in->len < sizeof(struct hns3_udma_dca_reg_attr)) {
		dev_err(udma_device->dev, "invalid input in dca reg: len %u\n", in->len);
		return -EINVAL;
	}

	if (copy_from_user(&attr, (void *)in->addr,
			   sizeof(struct hns3_udma_dca_reg_attr))) {
		dev_err(udma_device->dev, "cp from user failed in dca reg.\n");
		return -EFAULT;
	}

	ret = hns3_udma_register_dca_mem(udma_device, context, &attr);
	if (ret)
		dev_err(udma_device->dev,
			"register dca mem failed, ret:%d.\n", ret);

	return ret;
}

int hns3_udma_user_ctl_dca_dereg(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
				 struct ubcore_user_ctl_out *out,
				 struct ubcore_udrv_priv *udrv_data)
{
	struct hns3_udma_dev *udma_device = to_hns3_udma_dev(uctx->ub_dev);
	struct hns3_udma_ucontext *context = to_hns3_udma_ucontext(uctx);
	struct hns3_udma_dca_dereg_attr attr = {};
	int ret;

	if (in->len < sizeof(struct hns3_udma_dca_dereg_attr)) {
		dev_err(udma_device->dev, "invalid input in dca dereg: len %u\n", in->len);
		return -EINVAL;
	}

	if (copy_from_user(&attr, (void *)in->addr,
			   sizeof(struct hns3_udma_dca_dereg_attr))) {
		dev_err(udma_device->dev, "cp from user failed in dca dereg.\n");
		return -EFAULT;
	}

	attr.mem = NULL;
	ret = hns3_udma_unregister_dca_mem(udma_device, context, &attr, true);
	if (ret) {
		dev_err(udma_device->dev, "deregister dca mem failed, ret:%d.\n", ret);
		return -EFAULT;
	}

	return 0;
}

int hns3_udma_user_ctl_dca_shrink(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
				  struct ubcore_user_ctl_out *out,
				  struct ubcore_udrv_priv *udrv_data)
{
	struct hns3_udma_dev *udma_device = to_hns3_udma_dev(uctx->ub_dev);
	struct hns3_udma_ucontext *context = to_hns3_udma_ucontext(uctx);
	struct hns3_udma_dca_shrink_attr shrink_attr = {};
	struct hns3_udma_dca_shrink_resp shrink_resp = {};
	struct hns3_udma_dca_dereg_attr dereg_attr = {};

	if ((in->len < sizeof(struct hns3_udma_dca_shrink_attr)) ||
		(out->len < sizeof(struct hns3_udma_dca_shrink_resp)) ||
		!out->addr) {
		dev_err(udma_device->dev,
			"invalid input in dca shrink: len %u or output len %u, or out addr is null\n",
			in->len, out->len);
		return -EINVAL;
	}

	if (copy_from_user(&shrink_attr, (void *)in->addr,
			   sizeof(struct hns3_udma_dca_shrink_attr))) {
		dev_err(udma_device->dev, "cp from user failed in dca shrink.\n");
		return -EFAULT;
	}

	hns3_udma_shrink_dca_mem(udma_device, context, &shrink_attr, &shrink_resp);

	if (shrink_resp.free_mems >= 1) {
		dereg_attr.mem = shrink_resp.mem;
		hns3_udma_unregister_dca_mem(udma_device, context, &dereg_attr, false);
		shrink_resp.mem = NULL;
	}

	if (copy_to_user((void *)out->addr, &shrink_resp,
			sizeof(struct hns3_udma_dca_shrink_resp))) {
		dev_err(udma_device->dev, "cp to user failed in dca shrink\n");
		return -EFAULT;
	}

	return 0;
}

int hns3_udma_user_ctl_dca_attach(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
				  struct ubcore_user_ctl_out *out,
				  struct ubcore_udrv_priv  *udrv_data)
{
	struct hns3_udma_dev *udma_device = to_hns3_udma_dev(uctx->ub_dev);
	struct hns3_udma_dca_attach_attr attr = {};
	struct hns3_udma_dca_attach_resp resp = {};
	unsigned long byte;
	int ret;

	if (in->len < sizeof(struct hns3_udma_dca_attach_attr)) {
		dev_err(udma_device->dev,
			"invalid input in dca attach: len %u or out addr is null\n",
			in->len);
		return -EINVAL;
	}

	if (out->len < sizeof(struct hns3_udma_dca_attach_resp) || !out->addr) {
		dev_err(udma_device->dev,
			"invalid output in dca attach: len %u or out addr is null\n",
			out->len);
		return -EINVAL;
	}

	byte = copy_from_user(&attr, (void *)in->addr,
			      sizeof(struct hns3_udma_dca_attach_attr));
	if (byte) {
		dev_err(udma_device->dev, "cp from user failed in dca attach, byte:%lu.\n",
			byte);
		return -EFAULT;
	}

	ret = hns3_udma_dca_attach(udma_device, &attr, &resp);
	if (ret) {
		dev_err(udma_device->dev, "attach dca mem failed, ret:%d.\n",
			ret);
		return ret;
	}

	byte = copy_to_user((void *)out->addr, &resp,
			    sizeof(struct hns3_udma_dca_attach_resp));
	if (byte) {
		hns3_udma_dca_disattach(udma_device, &attr);
		dev_err(udma_device->dev, "cp to user failed in dca_attach, ret:%d.\n",
			ret);
		return -EFAULT;
	}

	return 0;
}

int hns3_udma_user_ctl_dca_detach(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
				  struct ubcore_user_ctl_out *out,
				  struct ubcore_udrv_priv *udrv_data)
{
	struct hns3_udma_dev *udma_device = to_hns3_udma_dev(uctx->ub_dev);
	struct hns3_udma_dca_detach_attr attr = {};
	unsigned long byte;

	if (in->len < sizeof(struct hns3_udma_dca_detach_attr)) {
		dev_err(udma_device->dev, "invalid input in dca detach: len %u\n", in->len);
		return -EINVAL;
	}
	byte = copy_from_user(&attr, (void *)in->addr,
			      sizeof(struct hns3_udma_dca_detach_attr));
	if (byte) {
		dev_err(udma_device->dev, "cp from user failed in dca detach, byte:%lu.\n",
			byte);
		return -EFAULT;
	}

	hns3_udma_dca_detach(udma_device, &attr);

	return 0;
}

int hns3_udma_user_ctl_dca_query(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
				 struct ubcore_user_ctl_out *out,
				 struct ubcore_udrv_priv *udrv_data)
{
	struct hns3_udma_dev *udma_device = to_hns3_udma_dev(uctx->ub_dev);
	struct hns3_udma_dca_query_attr attr = {};
	struct hns3_udma_dca_query_resp resp = {};
	unsigned long byte;
	int ret;

	if (in->len < sizeof(struct hns3_udma_dca_query_attr)) {
		dev_err(udma_device->dev, "Invalid dca query in_len %u.\n",
			in->len);
		return -EINVAL;
	}

	if (out->len < sizeof(struct hns3_udma_dca_query_resp) || !out->addr) {
		dev_err(udma_device->dev,
			"Invalid dca query out_len %u or null addr.\n",
			out->len);
		return -EINVAL;
	}

	byte = copy_from_user(&attr, (void *)in->addr,
			      sizeof(struct hns3_udma_dca_query_attr));
	if (byte) {
		dev_err(udma_device->dev, "cp from user failed in dca query, byte:%lu.\n",
			byte);
		return -EFAULT;
	}

	ret = hns3_udma_query_dca_mem(udma_device, &attr, &resp);
	if (ret) {
		dev_err(udma_device->dev, "query dca mem failed, ret:%d.\n",
			ret);
		return ret;
	}

	byte = copy_to_user((void *)out->addr, &resp,
			    sizeof(struct hns3_udma_dca_query_resp));
	if (byte) {
		dev_err(udma_device->dev, "cp to user failed in dca_query, byte:%lu.\n",
			byte);
		return -EFAULT;
	}

	return 0;
}

typedef int (*hns3_udma_user_ctl_opcode)(struct ubcore_ucontext *uctx,
					 struct ubcore_user_ctl_in *in,
					 struct ubcore_user_ctl_out *out,
					 struct ubcore_udrv_priv *udrv_data);

static hns3_udma_user_ctl_opcode g_hns3_udma_user_ctl_opcodes[] = {
	[HNS3_UDMA_USER_CTL_FLUSH_CQE] = hns3_udma_user_ctl_flush_cqe,
	[HNS3_UDMA_CONFIG_POE_CHANNEL] = hns3_udma_user_ctl_config_poe,
	[HNS3_UDMA_QUERY_POE_CHANNEL] = hns3_udma_user_ctl_query_poe,
	[HNS3_UDMA_DCA_MEM_REG] = hns3_udma_user_ctl_dca_reg,
	[HNS3_UDMA_DCA_MEM_DEREG] = hns3_udma_user_ctl_dca_dereg,
	[HNS3_UDMA_DCA_MEM_SHRINK] = hns3_udma_user_ctl_dca_shrink,
	[HNS3_UDMA_DCA_MEM_ATTACH] = hns3_udma_user_ctl_dca_attach,
	[HNS3_UDMA_DCA_MEM_DETACH] = hns3_udma_user_ctl_dca_detach,
	[HNS3_UDMA_DCA_MEM_QUERY] = hns3_udma_user_ctl_dca_query,
};

int hns3_udma_u_user_ctl(struct ubcore_device *dev, struct ubcore_user_ctl *k_user_ctl)
{
	struct ubcore_udrv_priv udrv_data = k_user_ctl->udrv_data;
	struct ubcore_user_ctl_out out = k_user_ctl->out;
	struct ubcore_ucontext *uctx = k_user_ctl->uctx;
	struct ubcore_user_ctl_in in = k_user_ctl->in;
	struct hns3_udma_dev *udma_device;

	if (((void *)in.addr == NULL) || (uctx->ub_dev == NULL))
		return -EINVAL;
	udma_device = to_hns3_udma_dev(uctx->ub_dev);
	if (in.opcode >= HNS3_UDMA_OPCODE_NUM ||
	    !g_hns3_udma_user_ctl_opcodes[in.opcode]) {
		dev_err(udma_device->dev, "bad user_ctl opcode: 0x%x.\n",
			(int)in.opcode);
		return -EINVAL;
	}
	return g_hns3_udma_user_ctl_opcodes[in.opcode](uctx, &in, &out, &udrv_data);
}

static int hns3_udma_k_user_ctl_config_poe_chl(struct hns3_udma_dev *dev,
					       struct ubcore_user_ctl_in *in,
					       struct ubcore_user_ctl_out *out)
{
	struct hns3_udma_user_ctl_cfg_poe_channel_in cfg_in = {};
	int ret;

	if (in->len < sizeof(cfg_in)) {
		dev_err(dev->dev, "invalid input in config poe chl: len %u\n", in->len);
		return -EINVAL;
	}
	memcpy(&cfg_in, (void *)in->addr, sizeof(cfg_in));
	ret = check_poe_channel(dev, cfg_in.poe_channel);
	if (ret) {
		dev_err(dev->dev, "check poe channel failed, ret = %d.\n", ret);
		return ret;
	}

	return hns3_udma_config_and_active_poe(dev, cfg_in.poe_channel, cfg_in.init_attr->poe_addr);
}

static int hns3_udma_k_user_ctl_notify_attr(struct hns3_udma_dev *dev,
					    struct ubcore_user_ctl_in *in,
					    struct ubcore_user_ctl_out *out)
{
	struct hns3_udma_user_ctl_config_notify_attr attr_in = {};

	if (in->len < sizeof(attr_in)) {
		dev_err(dev->dev, "invalid input in ctl notify attr: len %u\n", in->len);
		return -EINVAL;
	}
	memcpy(&attr_in, (void *)in->addr, sizeof(attr_in));
	dev->notify_addr = attr_in.notify_addr;

	return 0;
}

static int hns3_udma_k_user_ctl_query_hw_id(struct hns3_udma_dev *dev,
					    struct ubcore_user_ctl_in *in,
					    struct ubcore_user_ctl_out *out)
{
	struct hns3_udma_user_ctl_query_hw_id_out info_out = {};

	if (((void *)out->addr == NULL) || (out->len < sizeof(info_out))) {
		dev_err(dev->dev, "invalid output in query hw id: len %u or addr is NULL\n",
			out->len);
		return -EINVAL;
	}
	info_out.chip_id = dev->chip_id;
	info_out.die_id = dev->die_id;
	info_out.func_id = dev->func_id;
	memcpy((void *)out->addr, &info_out, min_t(uint32_t, out->len, sizeof(info_out)));

	return 0;
}

typedef int (*hns3_udma_k_user_ctl_ops)(struct hns3_udma_dev *dev,
					struct ubcore_user_ctl_in *in,
					struct ubcore_user_ctl_out *out);

static hns3_udma_k_user_ctl_ops g_hns3_udma_user_ctl_ops[] = {
	[HNS3_UDMA_K_USER_CTL_CONFIG_POE_CHANNEL] = hns3_udma_k_user_ctl_config_poe_chl,
	[HNS3_UDMA_K_USER_CTL_CONFIG_NOTIFY_ATTR] = hns3_udma_k_user_ctl_notify_attr,
	[HNS3_UDMA_K_USER_CTL_QUERY_HW_ID] = hns3_udma_k_user_ctl_query_hw_id,
};

static int hns3_udma_k_user_ctl(struct ubcore_device *dev,
			   struct ubcore_user_ctl *k_user_ctl)
{
	struct ubcore_user_ctl_out out = k_user_ctl->out;
	struct ubcore_user_ctl_in in = k_user_ctl->in;
	struct hns3_udma_dev *udma_dev = to_hns3_udma_dev(dev);

	if (in.opcode >= HNS3_UDMA_K_USER_CTL_OPCODE_NUM ||
	    !g_hns3_udma_user_ctl_ops[in.opcode]) {
		dev_err(udma_dev->dev, "bad kernel user ctl opcode: 0x%x.\n",
			in.opcode);
		return -EINVAL;
	}
	if ((in.opcode != HNS3_UDMA_K_USER_CTL_QUERY_HW_ID) && ((void *)in.addr == NULL)) {
		dev_err(udma_dev->dev, "bad input addr.\n");
		return -EINVAL;
	}
	return g_hns3_udma_user_ctl_ops[in.opcode](udma_dev, &in, &out);
}

int hns3_udma_user_ctl(struct ubcore_device *dev, struct ubcore_user_ctl *k_user_ctl)
{
	if (k_user_ctl->uctx)
		return hns3_udma_u_user_ctl(dev, k_user_ctl);
	else
		return hns3_udma_k_user_ctl(dev, k_user_ctl);
}
