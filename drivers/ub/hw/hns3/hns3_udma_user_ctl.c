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

#include "urma/ubcore_api.h"
#include "hns3_udma_dca.h"
#include "hns3_udma_cmd.h"
#include "hns3_udma_user_ctl_api.h"

int udma_user_ctl_flush_cqe(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
			    struct ubcore_user_ctl_out *out,
			    struct ubcore_udrv_priv *udrv_data)
{
	struct udma_dev *udma_device = to_udma_dev(uctx->ub_dev);
	struct flush_cqe_param fcp;
	struct udma_qp *udma_qp;
	uint32_t sq_pi;
	uint32_t qpn;
	int ret;

	ret = (int)copy_from_user(&fcp, (void *)in->addr,
				  sizeof(struct flush_cqe_param));
	if (ret) {
		dev_err(udma_device->dev,
			"copy_from_user failed in flush_cqe, ret:%d.\n", ret);
		return -EFAULT;
	}
	sq_pi = fcp.sq_producer_idx;
	qpn = fcp.qpn;

	xa_lock(&udma_device->qp_table.xa);
	udma_qp = (struct udma_qp *)xa_load(&udma_device->qp_table.xa, qpn);
	if (!udma_qp) {
		dev_err(udma_device->dev, "get qp(0x%x) error.\n", qpn);
		xa_unlock(&udma_device->qp_table.xa);
		return -EINVAL;
	}
	refcount_inc(&udma_qp->refcount);
	xa_unlock(&udma_device->qp_table.xa);

	ret = udma_flush_cqe(udma_device, udma_qp, sq_pi);

	if (refcount_dec_and_test(&udma_qp->refcount))
		complete(&udma_qp->free);

	return ret;
}

static int config_poe_addr(struct udma_dev *udma_device, uint8_t id,
			   uint64_t addr)
{
	struct udma_poe_cfg_addr_cmq *cmd;
	struct udma_cmq_desc desc;
	int ret;

	udma_cmq_setup_basic_desc(&desc, UDMA_OPC_CFG_POE_ADDR, false);
	cmd = (struct udma_poe_cfg_addr_cmq *)desc.data;
	cmd->channel_id = cpu_to_le32(id);
	cmd->poe_addr_l = cpu_to_le32(lower_32_bits(addr));
	cmd->poe_addr_h = cpu_to_le32(upper_32_bits(addr));

	ret = udma_cmq_send(udma_device, &desc, 1);
	if (ret)
		dev_err(udma_device->dev,
			"configure poe channel %u addr failed, ret = %d.\n",
			id, ret);
	return ret;
}

static int config_poe_attr(struct udma_dev *udma_device, uint8_t id, bool en)
{
	struct udma_poe_cfg_attr_cmq *cmd;
	struct udma_cmq_desc desc;
	int ret;

	udma_cmq_setup_basic_desc(&desc, UDMA_OPC_CFG_POE_ATTR, false);
	cmd = (struct udma_poe_cfg_attr_cmq *)desc.data;
	cmd->channel_id = cpu_to_le32(id);
	cmd->rsv_en_outstd = en ? 1 : 0;

	ret = udma_cmq_send(udma_device, &desc, 1);
	if (ret)
		dev_err(udma_device->dev,
			"configure poe channel %u attr failed, ret = %d.\n",
			id, ret);
	return ret;
}

static int check_poe_channel(struct udma_dev *udma_device, uint8_t poe_ch)
{
	if (poe_ch >= udma_device->caps.poe_ch_num) {
		dev_err(udma_device->dev, "invalid POE channel %u.\n", poe_ch);
		return -EINVAL;
	}

	return 0;
}

int udma_user_ctl_config_poe(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
			     struct ubcore_user_ctl_out *out,
			     struct ubcore_udrv_priv *udrv_data)
{
	struct udma_poe_info poe_info;
	struct udma_dev *udma_device;
	int ret;

	udma_device = to_udma_dev(uctx->ub_dev);
	ret = (int)copy_from_user(&poe_info,
				  (void *)in->addr,
				  sizeof(struct udma_poe_info));
	if (ret) {
		dev_err(udma_device->dev, "cp from user failed in config poe, ret:%d.\n",
			ret);
		return -EFAULT;
	}

	ret = check_poe_channel(udma_device, poe_info.poe_channel);
	if (ret) {
		dev_err(udma_device->dev, "check channel failed in config poe, ret:%d.\n",
			ret);
		return ret;
	}

	ret = config_poe_attr(udma_device, poe_info.poe_channel,
			      !!poe_info.poe_addr);
	if (ret) {
		dev_err(udma_device->dev, "config attr failed in config poe, ret:%d.\n",
			ret);
		config_poe_addr(udma_device, poe_info.poe_channel, 0);
		return ret;
	}

	ret = config_poe_addr(udma_device, poe_info.poe_channel,
			      poe_info.poe_addr);
	if (ret)
		dev_err(udma_device->dev, "config addr failed in config poe, ret:%d.\n",
		ret);

	return ret;
}

static int query_poe_addr(struct udma_dev *udma_device, uint8_t id,
			  uint64_t *addr)
{
#define POE_ADDR_H_SHIFT 32
	struct udma_poe_cfg_addr_cmq *resp;
	struct udma_cmq_desc desc;
	int ret;

	udma_cmq_setup_basic_desc(&desc, UDMA_OPC_CFG_POE_ADDR, true);
	resp = (struct udma_poe_cfg_addr_cmq *)desc.data;
	resp->channel_id = cpu_to_le32(id);

	ret = udma_cmq_send(udma_device, &desc, 1);
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

static int query_poe_attr(struct udma_dev *udma_device, uint8_t id, bool *en)
{
	struct udma_poe_cfg_attr_cmq *resp;
	struct udma_cmq_desc desc;
	int ret;

	udma_cmq_setup_basic_desc(&desc, UDMA_OPC_CFG_POE_ATTR, true);
	resp = (struct udma_poe_cfg_attr_cmq *)desc.data;
	resp->channel_id = cpu_to_le32(id);

	ret = udma_cmq_send(udma_device, &desc, 1);
	if (ret) {
		dev_err(udma_device->dev,
			"Query poe channel %u attr failed, ret = %d.\n",
			id, ret);
		return ret;
	}

	*en = !!resp->rsv_en_outstd;

	return ret;
}

int udma_user_ctl_query_poe(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
			    struct ubcore_user_ctl_out *out,
			    struct ubcore_udrv_priv *udrv_data)
{
	struct udma_poe_info poe_info_out = {};
	struct udma_poe_info poe_info_in = {};
	struct udma_dev *udma_device;
	uint64_t poe_addr;
	bool poe_en;
	int ret;

	udma_device = to_udma_dev(uctx->ub_dev);
	ret = (int)copy_from_user(&poe_info_in, (void *)in->addr,
				  sizeof(struct udma_poe_info));
	if (ret) {
		dev_err(udma_device->dev, "cp from user failed in query poe, ret:%d.\n",
			ret);
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
	ret = (int)copy_to_user((void *)out->addr, &poe_info_out,
			   min(out->len,
			       (uint32_t)sizeof(struct udma_poe_info)));
	if (ret) {
		dev_err(udma_device->dev, "cp to user failed in query poe, ret:%d.\n",
			ret);
		return -EFAULT;
	}
	return ret;
}

int udma_user_ctl_dca_reg(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
			  struct ubcore_user_ctl_out *out, struct ubcore_udrv_priv *udrv_data)
{
	struct udma_dev *udma_device = to_udma_dev(uctx->ub_dev);
	struct udma_ucontext *context = to_udma_ucontext(uctx);
	struct udma_dca_reg_attr attr = {};
	int ret;

	ret = (int)copy_from_user(&attr, (void *)in->addr,
				  sizeof(struct udma_dca_reg_attr));
	if (ret) {
		dev_err(udma_device->dev, "cp from user failed in dca reg, ret:%d.\n",
			ret);
		return -EFAULT;
	}

	ret = udma_register_dca_mem(udma_device, context, &attr);
	if (ret)
		dev_err(udma_device->dev,
			"register dca mem failed, ret:%d.\n", ret);

	return ret;
}

int udma_user_ctl_dca_dereg(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
			    struct ubcore_user_ctl_out *out,
			    struct ubcore_udrv_priv *udrv_data)
{
	struct udma_dev *udma_device = to_udma_dev(uctx->ub_dev);
	struct udma_ucontext *context = to_udma_ucontext(uctx);
	struct udma_dca_dereg_attr attr = {};
	int ret;

	ret = (int)copy_from_user(&attr, (void *)in->addr,
				  sizeof(struct udma_dca_dereg_attr));
	if (ret) {
		dev_err(udma_device->dev, "cp from user failed in dca dereg, ret:%d.\n",
			ret);
		return -EFAULT;
	}

	attr.mem = NULL;
	ret = udma_unregister_dca_mem(udma_device, context, &attr, true);
	if (ret) {
		dev_err(udma_device->dev, "deregister dca mem failed, ret:%d.\n", ret);
		return -EFAULT;
	}

	return 0;
}

int udma_user_ctl_dca_shrink(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
			     struct ubcore_user_ctl_out *out,
			     struct ubcore_udrv_priv *udrv_data)
{
	struct udma_dev *udma_device = to_udma_dev(uctx->ub_dev);
	struct udma_ucontext *context = to_udma_ucontext(uctx);
	struct udma_dca_shrink_attr shrink_attr = {};
	struct udma_dca_shrink_resp shrink_resp = {};
	struct udma_dca_dereg_attr dereg_attr = {};
	int ret;

	ret = (int)copy_from_user(&shrink_attr, (void *)in->addr,
				  sizeof(struct udma_dca_shrink_attr));
	if (ret) {
		dev_err(udma_device->dev, "cp from user failed in dca shrink, ret:%d.\n",
			ret);
		return -EFAULT;
	}

	udma_shrink_dca_mem(udma_device, context, &shrink_attr, &shrink_resp);

	if (shrink_resp.free_mems >= 1) {
		dereg_attr.mem = shrink_resp.mem;
		udma_unregister_dca_mem(udma_device, context, &dereg_attr, false);
		shrink_resp.mem = NULL;
	}

	ret = (int)copy_to_user((void *)out->addr, &shrink_resp,
				min(out->len,
				    (uint32_t)sizeof(struct udma_dca_shrink_resp)));
	if (ret) {
		dev_err(udma_device->dev, "cp to user failed in dca shrink, ret:%d.\n",
			ret);
		return -EFAULT;
	}

	return 0;
}

int udma_user_ctl_dca_attach(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
			     struct ubcore_user_ctl_out *out,
			     struct ubcore_udrv_priv  *udrv_data)
{
	struct udma_dev *udma_device = to_udma_dev(uctx->ub_dev);
	struct udma_dca_attach_attr attr = {};
	struct udma_dca_attach_resp resp = {};
	int ret;

	ret = (int)copy_from_user(&attr, (void *)in->addr,
				  sizeof(struct udma_dca_attach_attr));
	if (ret) {
		dev_err(udma_device->dev, "cp from user failed in dca attach, ret:%d.\n",
			ret);
		return -EFAULT;
	}

	ret = udma_dca_attach(udma_device, &attr, &resp);
	if (ret) {
		dev_err(udma_device->dev, "attach dca mem failed, ret:%d.\n",
			ret);
		return ret;
	}

	ret = (int)copy_to_user((void *)out->addr, &resp,
				min(out->len,
				    (uint32_t)sizeof(struct udma_dca_attach_resp)));
	if (ret) {
		udma_dca_disattach(udma_device, &attr);
		dev_err(udma_device->dev, "cp to user failed in dca_attach, ret:%d.\n",
			ret);
		return -EFAULT;
	}

	return 0;
}

int udma_user_ctl_dca_detach(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
			     struct ubcore_user_ctl_out *out,
			     struct ubcore_udrv_priv *udrv_data)
{
	struct udma_dev *udma_device = to_udma_dev(uctx->ub_dev);
	struct udma_dca_detach_attr attr = {};
	int ret;

	ret = (int)copy_from_user(&attr, (void *)in->addr,
				  sizeof(struct udma_dca_detach_attr));
	if (ret) {
		dev_err(udma_device->dev, "cp from user failed in dca detach, ret:%d.\n",
			ret);
		return -EFAULT;
	}

	udma_dca_detach(udma_device, &attr);

	return 0;
}

int udma_user_ctl_dca_query(struct ubcore_ucontext *uctx, struct ubcore_user_ctl_in *in,
			    struct ubcore_user_ctl_out *out,
			    struct ubcore_udrv_priv *udrv_data)
{
	struct udma_dev *udma_device = to_udma_dev(uctx->ub_dev);
	struct udma_dca_query_attr attr = {};
	struct udma_dca_query_resp resp = {};
	int ret;

	ret = (int)copy_from_user(&attr, (void *)in->addr,
				  sizeof(struct udma_dca_query_attr));
	if (ret) {
		dev_err(udma_device->dev, "cp from user failed in dca query, ret:%d.\n",
			ret);
		return -EFAULT;
	}

	ret = udma_query_dca_mem(udma_device, &attr, &resp);
	if (ret) {
		dev_err(udma_device->dev, "query dca mem failed, ret:%d.\n",
			ret);
		return ret;
	}

	ret = (int)copy_to_user((void *)out->addr, &resp,
				min(out->len,
				    (uint32_t)sizeof(struct udma_dca_query_resp)));
	if (ret) {
		dev_err(udma_device->dev, "cp to user failed in dca_query, ret:%d.\n",
			ret);
		return -EFAULT;
	}

	return 0;
}

typedef int (*udma_user_ctl_opcode)(struct ubcore_ucontext *uctx,
				    struct ubcore_user_ctl_in *in,
				    struct ubcore_user_ctl_out *out,
				    struct ubcore_udrv_priv *udrv_data);

static udma_user_ctl_opcode g_udma_user_ctl_opcodes[] = {
	[UDMA_USER_CTL_FLUSH_CQE] = udma_user_ctl_flush_cqe,
	[UDMA_CONFIG_POE_CHANNEL] = udma_user_ctl_config_poe,
	[UDMA_QUERY_POE_CHANNEL] = udma_user_ctl_query_poe,
	[UDMA_DCA_MEM_REG] = udma_user_ctl_dca_reg,
	[UDMA_DCA_MEM_DEREG] = udma_user_ctl_dca_dereg,
	[UDMA_DCA_MEM_SHRINK] = udma_user_ctl_dca_shrink,
	[UDMA_DCA_MEM_ATTACH] = udma_user_ctl_dca_attach,
	[UDMA_DCA_MEM_DETACH] = udma_user_ctl_dca_detach,
	[UDMA_DCA_MEM_QUERY] = udma_user_ctl_dca_query,
};

int udma_u_user_ctl(struct ubcore_device *dev, struct ubcore_user_ctl *k_user_ctl)
{
	struct ubcore_udrv_priv udrv_data = k_user_ctl->udrv_data;
	struct ubcore_user_ctl_out out = k_user_ctl->out;
	struct ubcore_ucontext *uctx = k_user_ctl->uctx;
	struct ubcore_user_ctl_in in = k_user_ctl->in;
	struct udma_dev *udma_device;

	udma_device = to_udma_dev(uctx->ub_dev);
	if (in.opcode >= UDMA_OPCODE_NUM ||
	    !g_udma_user_ctl_opcodes[in.opcode]) {
		dev_err(udma_device->dev, "bad user_ctl opcode: 0x%x.\n",
			(int)in.opcode);
		return -EINVAL;
	}
	return g_udma_user_ctl_opcodes[in.opcode](uctx, &in, &out, &udrv_data);
}

static int udma_k_user_ctl_config_poe_chl(struct udma_dev *dev,
					  struct ubcore_user_ctl_in *in,
					  struct ubcore_user_ctl_out *out)
{
	struct hns3_udma_user_ctl_cfg_poe_channel_in cfg_in;
	int ret;

	memcpy(&cfg_in, (void *)in->addr, min_t(uint32_t, in->len, sizeof(cfg_in)));
	ret = check_poe_channel(dev, cfg_in.poe_channel);
	if (ret) {
		dev_err(dev->dev, "check poe channel failed, ret = %d.\n", ret);
		return ret;
	}

	ret = config_poe_attr(dev, cfg_in.poe_channel, !!cfg_in.init_attr->poe_addr);
	if (ret) {
		dev_err(dev->dev, "config poe attr failed, ret = %d.\n", ret);
		return ret;
	}

	ret = config_poe_addr(dev, cfg_in.poe_channel, cfg_in.init_attr->poe_addr);
	if (ret)
		dev_err(dev->dev, "config poe addr failed, ret = %d.\n", ret);

	return ret;
}

static int udma_k_user_ctl_notify_attr(struct udma_dev *dev,
				       struct ubcore_user_ctl_in *in,
				       struct ubcore_user_ctl_out *out)
{
	struct hns3_udma_user_ctl_config_notify_attr attr_in;

	memcpy(&attr_in, (void *)in->addr, min_t(uint32_t, in->len, sizeof(attr_in)));
	dev->notify_addr = attr_in.notify_addr;

	return 0;
}

static int udma_k_user_ctl_query_hw_id(struct udma_dev *dev,
				       struct ubcore_user_ctl_in *in,
				       struct ubcore_user_ctl_out *out)
{
	struct hns3_udma_user_ctl_query_hw_id_out info_out;

	info_out.chip_id = dev->chip_id;
	info_out.die_id = dev->die_id;
	info_out.func_id = dev->func_id;
	memcpy((void *)out->addr, &info_out, min_t(uint32_t, out->len, sizeof(info_out)));

	return 0;
}

typedef int (*udma_k_user_ctl_ops)(struct udma_dev *dev,
				   struct ubcore_user_ctl_in *in,
				   struct ubcore_user_ctl_out *out);

static udma_k_user_ctl_ops g_udma_user_ctl_ops[] = {
	[HNS3_UDMA_K_USER_CTL_CONFIG_POE_CHANNEL] = udma_k_user_ctl_config_poe_chl,
	[HNS3_UDMA_K_USER_CTL_CONFIG_NOTIFY_ATTR] = udma_k_user_ctl_notify_attr,
	[HNS3_UDMA_K_USER_CTL_QUERY_HW_ID] = udma_k_user_ctl_query_hw_id,
};

int udma_k_user_ctl(struct ubcore_device *dev, struct ubcore_user_ctl *k_user_ctl)
{
	struct ubcore_user_ctl_out out = k_user_ctl->out;
	struct ubcore_user_ctl_in in = k_user_ctl->in;
	struct udma_dev *udma_dev = to_udma_dev(dev);

	if (in.opcode >= HNS3_UDMA_K_USER_CTL_OPCODE_NUM ||
	    !g_udma_user_ctl_ops[in.opcode]) {
		dev_err(udma_dev->dev, "bad kernel user ctl opcode: 0x%x.\n",
			in.opcode);
		return -EINVAL;
	}
	return g_udma_user_ctl_ops[in.opcode](udma_dev, &in, &out);
}

int udma_user_ctl(struct ubcore_device *dev, struct ubcore_user_ctl *k_user_ctl)
{
	if (k_user_ctl->uctx)
		return udma_u_user_ctl(dev, k_user_ctl);
	else
		return udma_k_user_ctl(dev, k_user_ctl);
}
