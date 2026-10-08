// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_adminq.h"

static int nbl_res_adminq_update_ring_num(void *priv);

/* ****   FW CMD FILTERS START  **** */

static int nbl_res_adminq_check_net_ring_num(struct nbl_resource_mgt *res_mgt,
					     struct nbl_fw_cmd_net_ring_num_param *param)
{
	struct nbl_resource_info *res_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u32 sum = 0, pf_real_num = 0, vf_real_num = 0;
	int i, j;
	int base_vf_id;
	u32 switch_sum_num[NBL_MAX_PF] = {0};

	pf_real_num = NBL_VSI_PF_LEGAL_QUEUE_NUM(param->pf_def_max_net_qp_num);
	vf_real_num = NBL_VSI_VF_REAL_QUEUE_NUM(param->vf_def_max_net_qp_num);

	if (pf_real_num > queue_mgt->pf_func_max_qp_chk || vf_real_num > queue_mgt->vf_vsi_max_qp)
		return -EINVAL;

	/* TODO: should we consider when pf_num is 8? */
	for (i = 0; i < NBL_COMMON_TO_ETH_MODE(common); i++) {
		pf_real_num = param->net_max_qp_num[i] ?
			      NBL_VSI_PF_LEGAL_QUEUE_NUM(param->net_max_qp_num[i]) :
			      NBL_VSI_PF_LEGAL_QUEUE_NUM(param->pf_def_max_net_qp_num);

		if (pf_real_num > queue_mgt->pf_func_max_qp_chk)
			return -EINVAL;

		pf_real_num = param->net_max_qp_num[i] ?
			      NBL_VSI_PF_MAX_QUEUE_NUM(param->net_max_qp_num[i]) :
			      NBL_VSI_PF_MAX_QUEUE_NUM(param->pf_def_max_net_qp_num);
		if (pf_real_num > queue_mgt->pf_func_max_qp)
			pf_real_num = queue_mgt->pf_func_max_qp;

		sum += pf_real_num;
		switch_sum_num[i] = pf_real_num;

		for (j = 0; j < res_info->max_vf_bypf_num; j++) {
			base_vf_id = i * res_info->max_vf_bypf_num + NBL_MAX_PF;
			vf_real_num = param->net_max_qp_num[base_vf_id + j] ?
				NBL_VSI_VF_REAL_QUEUE_NUM(param->net_max_qp_num[base_vf_id + j]) :
				NBL_VSI_VF_REAL_QUEUE_NUM(param->vf_def_max_net_qp_num);
			if (vf_real_num > queue_mgt->vf_func_max_qp)
				return -EINVAL;

			sum += vf_real_num;
			switch_sum_num[i] += vf_real_num;
		}

		if (switch_sum_num[i] > queue_mgt->max_queue)
			return -EINVAL;
	}

	if (queue_mgt->check_allpf_qp && sum > queue_mgt->max_queue)
		return -EINVAL;

	return 0;
}

static int nbl_res_adminq_check_rdma_cap(struct nbl_resource_mgt *res_mgt,
					 struct nbl_fw_cmd_rdma_cap_param *param)
{
	struct nbl_resource_info *res_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_rdma_info *rdma_info = &res_info->rdma_info;
	int count = 0, i, j;

	for (i = 0; i < NBL_RDMA_CAP_CMD_LEN; i++)
		for (j = 0; j < BITS_PER_BYTE; j++)
			if (param->rdma_func_bitmaps[i] & BIT(j))
				count++;

	if (count > rdma_info->rdma_max_func_num)
		return -EINVAL;

	return 0;
}

static int nbl_res_adminq_check_rdma_mem_type(struct nbl_resource_mgt *res_mgt,
					      struct nbl_fw_cmd_rdma_mem_type_param *param)
{
	return param->mem_type > NBL_RDMA_MEM_TYPE_MAX ? -EINVAL : 0;
}

static u32 nbl_res_adminq_sum_vf_num(struct nbl_fw_cmd_vf_num_param *param)
{
	u32 count = 0;
	int i;

	for (i = 0; i < NBL_VF_NUM_CMD_LEN; i++)
		count += param->vf_max_num[i];

	return count;
}

static int nbl_res_adminq_check_vf_num_type(struct nbl_resource_mgt *res_mgt,
					    struct nbl_fw_cmd_vf_num_param *param)
{
	u32 count;

	count = nbl_res_adminq_sum_vf_num(param);
	if (count > NBL_MAX_VF)
		return -EINVAL;

	return 0;
}

static int nbl_res_fw_cmd_filter_rw_in(struct nbl_resource_mgt *res_mgt, void *data, u16 len)
{
	struct nbl_chan_resource_write_param *param = (struct nbl_chan_resource_write_param *)data;
	struct nbl_fw_cmd_net_ring_num_param *net_ring_num_param;
	struct nbl_fw_cmd_rdma_cap_param *rdma_cap_param;
	struct nbl_fw_cmd_rdma_mem_type_param *rdma_mem_type_param;
	struct nbl_fw_cmd_vf_num_param *vf_num_param;

	switch (param->resid) {
	case NBL_ADMINQ_PFA_TLV_NET_RING_NUM:
		net_ring_num_param = (struct nbl_fw_cmd_net_ring_num_param *)param->data;
		return nbl_res_adminq_check_net_ring_num(res_mgt, net_ring_num_param);
	case NBL_ADMINQ_PFA_TLV_RDMA_CAP:
		rdma_cap_param = (struct nbl_fw_cmd_rdma_cap_param *)param->data;
		return nbl_res_adminq_check_rdma_cap(res_mgt, rdma_cap_param);
	case NBL_ADMINQ_PFA_TLV_RDMA_MEM_TYPE:
		rdma_mem_type_param = (struct nbl_fw_cmd_rdma_mem_type_param *)param->data;
		return nbl_res_adminq_check_rdma_mem_type(res_mgt, rdma_mem_type_param);
	case NBL_ADMINQ_PFA_TLV_VF_NUM:
		vf_num_param = (struct nbl_fw_cmd_vf_num_param *)param->data;
		return nbl_res_adminq_check_vf_num_type(res_mgt, vf_num_param);
	default:
		break;
	}

	return 0;
}

static int nbl_res_fw_cmd_filter_rw_out(struct nbl_resource_mgt *res_mgt, void *in, u16 in_len,
					void *out, u16 out_len)
{
	struct nbl_resource_info *res_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct nbl_net_ring_num_info *num_info = &res_info->net_ring_num_info;
	struct nbl_chan_resource_write_param *param = (struct nbl_chan_resource_write_param *)in;
	struct nbl_fw_cmd_net_ring_num_param *net_ring_num_param;
	struct nbl_fw_cmd_vf_num_param *vf_num_param;
	size_t copy_len;
	u32 count;

	switch (param->resid) {
	case NBL_ADMINQ_PFA_TLV_NET_RING_NUM:
		net_ring_num_param = (struct nbl_fw_cmd_net_ring_num_param *)param->data;
		copy_len = min_t(size_t, sizeof(*num_info), (size_t)in_len);
		memcpy(num_info, net_ring_num_param, copy_len);
		nbl_devcomm_send_event(adminq_mgt->comp_dev, NBL_DEVCOMM_RES_CFG_QP_NUM_EVENT,
				       NBL_DEVCOMM_RES_CFG_QP_NUM_EVENT,
				       net_ring_num_param);
		break;
	case NBL_ADMINQ_PFA_TLV_VF_NUM:
		vf_num_param = (struct nbl_fw_cmd_vf_num_param *)param->data;
		count = nbl_res_adminq_sum_vf_num(vf_num_param);
		res_info->max_vf_num = count;
		res_info->max_vf_bypf_num = vf_num_param->vf_max_num[0];
		nbl_devcomm_send_event(adminq_mgt->comp_dev, NBL_DEVCOMM_RES_CFG_VF_NUM_EVENT,
				       NBL_DEVCOMM_RES_CFG_VF_NUM_EVENT,
				       vf_num_param);
		break;
	default:
		break;
	}

	return 0;
}

static void nbl_res_adminq_add_cmd_filter_res_write(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_res_fw_cmd_filter filter = {
		.in = nbl_res_fw_cmd_filter_rw_in,
		.out = nbl_res_fw_cmd_filter_rw_out,
	};
	u16 key = 0;

	key = NBL_CHAN_MSG_ADMINQ_RESOURCE_WRITE;

	if (nbl_common_alloc_hash_node(adminq_mgt->cmd_filter, &key, &filter, NULL))
		nbl_warn(common, NBL_DEBUG_ADMINQ, "Fail to register res_write in filter");
}

/* ****   FW CMD FILTERS END   **** */

static int nbl_res_adminq_set_module_eeprom_info(struct nbl_resource_mgt *res_mgt,
						 u8 eth_id,
						 u8 i2c_address,
						 u8 page,
						 u8 bank,
						 u32 offset,
						 u32 length,
						 u8 *data)
{
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_chan_send_info chan_send;
	struct nbl_chan_param_module_eeprom_info param = {0};
	u32 xfer_size = 0;
	u32 byte_offset = 0;
	int data_length = length;
	int ret = 0;

	do {
		xfer_size = min_t(u32, data_length, NBL_MODULE_EEPRO_WRITE_MAX_LEN);
		data_length -= xfer_size;

		param.eth_id = eth_id;
		param.i2c_address = i2c_address;
		param.page = page;
		param.bank = bank;
		param.write = 1;
		param.version = 1;
		param.offset = offset + byte_offset;
		param.length = xfer_size;
		memcpy(param.data, data + byte_offset, xfer_size);

		NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
			      NBL_CHAN_MSG_ADMINQ_GET_MODULE_EEPROM,
			      &param, sizeof(param), NULL, 0, 1);
		ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
		if (ret) {
			dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x, eth_id:%d, i2c_address:%d, page:%d, bank:%d, offset:%d, length:%d\n",
				ret, NBL_CHAN_MSG_ADMINQ_GET_MODULE_EEPROM,
				eth_info->logic_eth_id[eth_id],
				i2c_address, page, bank, offset + byte_offset, xfer_size);
		}
		byte_offset += xfer_size;
	} while (!ret && data_length > 0);

	return ret;
}

static int nbl_res_adminq_turn_module_eeprom_page(struct nbl_resource_mgt *res_mgt,
						  u8 eth_id, u8 page)
{
	int ret;
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);

	ret = nbl_res_adminq_set_module_eeprom_info(res_mgt, eth_id, I2C_DEV_ADDR_A0, 0, 0,
						    SFF_8636_TURNPAGE_ADDR, 1, &page);
	if (ret) {
		dev_err(dev, "eth %d set_module_eeprom_info failed %d\n",
			eth_info->logic_eth_id[eth_id], ret);
		return -EIO;
	}

	return ret;
}

static void nbl_res_get_module_eeprom_page(u32 addr, u8 *upper_page, u8 *offset)
{
	if (addr >= SFF_8638_PAGESIZE) {
		*upper_page = (addr - SFF_8638_PAGESIZE) / SFF_8638_PAGESIZE;
		*offset = (u8)(addr - (*upper_page * SFF_8638_PAGESIZE));
	} else {
		*upper_page = 0;
		*offset = addr;
	}
}

static int nbl_res_adminq_get_module_eeprom_info(struct nbl_resource_mgt *res_mgt,
						 u8 eth_id,
						 u8 i2c_address,
						 u8 page,
						 u8 bank,
						 u32 offset,
						 u32 length,
						 u8 *data)
{
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_chan_send_info chan_send;
	struct nbl_chan_param_module_eeprom_info param = {0};
	u32 xfer_size = 0;
	u32 byte_offset = 0;
	int data_length = length;
	int ret = 0;

	/* read a maximum of 128 bytes each time */
	do {
		xfer_size = min_t(u32, data_length, NBL_MAX_PHY_I2C_RESP_SIZE);
		data_length -= xfer_size;

		param.eth_id = eth_id;
		param.i2c_address = i2c_address;
		param.page = page;
		param.bank = bank;
		param.write = 0;
		param.version = 1;
		param.offset = offset + byte_offset;
		param.length = xfer_size;

		NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
			      NBL_CHAN_MSG_ADMINQ_GET_MODULE_EEPROM,
			      &param, sizeof(param), data + byte_offset, xfer_size, 1);
		ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
		if (ret) {
			dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x, eth_id:%d, i2c_address:%d, page:%d, bank:%d, offset:%d, length:%d\n",
				ret, NBL_CHAN_MSG_ADMINQ_GET_MODULE_EEPROM,
				eth_info->logic_eth_id[eth_id],
				i2c_address, page, bank, offset + byte_offset, xfer_size);
		}
		byte_offset += xfer_size;
	} while (!ret && data_length > 0);

	return ret;
}

static int nbl_res_adminq_flash_read(struct nbl_resource_mgt *res_mgt, u32 bank_id,
				     u32 offset, u32 len, u8 *data)
{
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_chan_send_info chan_send;
	struct nbl_chan_param_flash_read read_param;
	int remain = len, sec_offset = 0, ret = 0;

	while (remain > 0) {
		read_param.bank_id = bank_id;
		read_param.offset = offset + sec_offset;
		read_param.len = remain > NBL_CHAN_FLASH_READ_LEN ? NBL_CHAN_FLASH_READ_LEN :
								    remain;

		NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
			      NBL_CHAN_MSG_ADMINQ_FLASH_READ, &read_param, sizeof(read_param),
			      data + sec_offset, read_param.len, 1);
		ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
		if (ret) {
			nbl_err(common, NBL_DEBUG_ADMINQ,
				"adminq flash read fail on bank %d, offset %d", bank_id, offset);
			return ret;
		}

		remain -= read_param.len;
		sec_offset += read_param.len;
	}

	return ret;
}

static int nbl_res_adminq_flash_erase(struct nbl_resource_mgt *res_mgt, u32 bank_id,
				      u32 offset, u32 len)
{
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_chan_send_info chan_send;
	struct nbl_chan_param_flash_erase erase_param;
	int remain = len, sec_offset = 0, ret = 0;

	while (remain > 0) {
		erase_param.bank_id = bank_id;
		erase_param.offset = offset + sec_offset;
		/* When erase, it must be 4k-aligned, so we always erase 4k each time. */
		erase_param.len = NBL_CHAN_FLASH_ERASE_LEN;

		NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
			      NBL_CHAN_MSG_ADMINQ_FLASH_ERASE,
			      &erase_param, sizeof(erase_param), NULL, 0, 1);
		ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
		if (ret) {
			nbl_err(common, NBL_DEBUG_ADMINQ,
				"adminq flash erase fail on bank %d, offset %d",
				bank_id, erase_param.offset);
			return ret;
		}

		remain -= erase_param.len;
		sec_offset += erase_param.len;
	}

	return ret;
}

static int nbl_res_adminq_flash_write(struct nbl_resource_mgt *res_mgt, u32 bank_id,
				      u32 offset, u32 len, const u8 *data)
{
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_chan_send_info chan_send;
	struct nbl_chan_param_flash_write *write_param = NULL;
	int remain = len, sec_offset = 0, ret = 0;

	write_param = kzalloc(sizeof(*write_param), GFP_KERNEL);
	if (!write_param)
		return -ENOMEM;

	while (remain > 0) {
		write_param->bank_id = bank_id;
		write_param->offset = offset + sec_offset;
		write_param->len = remain > NBL_CHAN_FLASH_WRITE_LEN ? NBL_CHAN_FLASH_WRITE_LEN :
								       remain;
		memcpy(write_param->data, data + sec_offset, write_param->len);

		NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
			      NBL_CHAN_MSG_ADMINQ_FLASH_WRITE,
			      write_param, sizeof(*write_param), NULL, 0, 1);
		ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
		if (ret) {
			nbl_err(common, NBL_DEBUG_ADMINQ,
				"adminq flash write fail on bank %d, offset %d", bank_id, offset);
			kfree(write_param);
			return ret;
		}

		remain -= write_param->len;
		sec_offset += write_param->len;
	}

	kfree(write_param);
	return ret;
}

static int nbl_res_adminq_get_nvm_bank_index(struct nbl_resource_mgt *res_mgt, int *rbank)
{
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_chan_send_info chan_send;

	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
		      NBL_CHAN_MSG_ADMINQ_GET_NVM_BANK_INDEX, NULL, 0, rbank, sizeof(*rbank), 1);
	return chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
}

static int nbl_res_adminq_flash_set_nvm_bank(struct nbl_resource_mgt *res_mgt, int rbank,
					     int bank_id, int op)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u16 nvmidx;
	u8 *idxbuf = NULL;
	int ret = 0;

	idxbuf = kzalloc(NBL_ADMINQ_IDX_LEN, GFP_KERNEL);
	if (!idxbuf)
		return -ENOMEM;

	memset(idxbuf, 0xFF, NBL_ADMINQ_IDX_LEN);

	if (op == NBL_ADMINQ_NVM_BANK_REPAIR)
		idxbuf[0] = rbank ? 0xFF : 0x00;
	else if (op == NBL_ADMINQ_NVM_BANK_SWITCH)
		idxbuf[0] = rbank ? 0x00 : 0xFF;

	idxbuf[1] = 0x5A;
	memset(&idxbuf[4080], 0, NBL_ADMINQ_IDX_LEN - 4080);
	memcpy(&idxbuf[4080], "M181XXSRIS", strlen("M181XXSRIS"));

	ret |= nbl_res_adminq_flash_erase(res_mgt, bank_id, 0, NBL_ADMINQ_IDX_LEN);
	ret |= nbl_res_adminq_flash_write(res_mgt, bank_id, 0, NBL_ADMINQ_IDX_LEN, idxbuf);

	ret |= nbl_res_adminq_flash_read(res_mgt, bank_id, 0, sizeof(nvmidx), (u8 *)&nvmidx);
	if (ret)
		goto out;

	if (op == NBL_ADMINQ_NVM_BANK_SWITCH)
		rbank = !rbank;

	if (((nvmidx >> 2) & 1) != rbank) {
		nbl_err(common, NBL_DEBUG_ADMINQ,
			"S0 update bank index is %d but read back index is %d",
			rbank, (nvmidx >> 2) & 1);
		ret = -EFAULT;
		goto out;
	}

out:
	kfree(idxbuf);
	return ret;
}

static int nbl_res_adminq_flash_verify(struct nbl_resource_mgt *res_mgt, int *rbank)
{
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_chan_send_info chan_send;
	int verify_bank, sign0, sign1, ret = 0;

	verify_bank = 0;
	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
		      NBL_CHAN_MSG_ADMINQ_VERIFY_NVM_BANK, &verify_bank, sizeof(verify_bank),
		      &sign0, sizeof(sign0), 1);
	ret |= chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);

	verify_bank = 1;
	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
		      NBL_CHAN_MSG_ADMINQ_VERIFY_NVM_BANK, &verify_bank, sizeof(verify_bank),
		      &sign1, sizeof(sign1), 1);
	ret |= chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);

	sign0 = !sign0;
	sign1 = !sign1;

	if (ret || (sign0 != 0 && sign0 != 1) || (sign1 != 0 && sign1 != 1) || (!sign0 && !sign1)) {
		nbl_err(common, NBL_DEBUG_ADMINQ,
			"Verify signature both invalid, ret %d, sign0 %d, sign1 %d",
			ret, sign0, sign1);
		return -EFAULT;
	}

	if (sign0 != sign1) {
		nbl_warn(common, NBL_DEBUG_ADMINQ, "WARN: bank0 and bank1 signature: %s/%s",
			 sign0 ? "pass" : "fail", sign1 ? "pass" : "fail");

		/* Set rbank to fail bank to because we will switch bank idx next */
		if (sign0)
			*rbank = 1;
		else if (sign1)
			*rbank = 0;
		else
			return -EFAULT;
	}

	return 0;
}

static int nbl_res_adminq_flash_lock(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_chan_send_info chan_send;
	u32 success = 0, ret = 0;

	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID, NBL_CHAN_MSG_ADMINQ_FLASH_LOCK,
		      NULL, 0, &success, sizeof(success), 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret)
		return ret;

	return !success;
}

static int nbl_res_adminq_flash_unlock(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_chan_send_info chan_send;
	u32 success = 0;

	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
		      NBL_CHAN_MSG_ADMINQ_FLASH_UNLOCK, NULL, 0, &success, sizeof(success), 1);
	return chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
}

static int nbl_res_adminq_flash_prepare(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	u16 nvmidx0, nvmidx1;
	int rbank, ret = 0;

	ret = nbl_res_adminq_get_nvm_bank_index(res_mgt, &rbank);
	if (ret || (rbank != 0 && rbank != 1))
		return -EFAULT;

	ret |= nbl_res_adminq_flash_read(res_mgt, BANKID_SR_BANK0, 0,
					sizeof(nvmidx0), (u8 *)&nvmidx0);
	ret |= nbl_res_adminq_flash_read(res_mgt, BANKID_SR_BANK1, 0,
					sizeof(nvmidx1), (u8 *)&nvmidx1);
	if (ret)
		return ret;

	if ((((nvmidx0 >> 2) & 1) != rbank))
		ret = nbl_res_adminq_flash_set_nvm_bank(res_mgt, rbank, BANKID_SR_BANK0,
							NBL_ADMINQ_NVM_BANK_REPAIR);

	if ((((nvmidx1 >> 2) & 1) != rbank))
		ret = nbl_res_adminq_flash_set_nvm_bank(res_mgt, rbank, BANKID_SR_BANK1,
							NBL_ADMINQ_NVM_BANK_REPAIR);

	return ret;
}

static int nbl_res_adminq_flash_image(void *priv, struct nbl_flash_image_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	int rbank, write_bank, ret = 0;

	switch (param->module) {
	case NBL_ADMINQ_BANK_INDEX_SPI_BOOT:
		ret |= nbl_res_adminq_flash_erase(res_mgt, BANKID_BOOT_BANK, 0, param->len);
		ret |= nbl_res_adminq_flash_write(res_mgt, BANKID_BOOT_BANK, 0, param->len,
						  param->data);

		break;
	case NBL_ADMINQ_BANK_INDEX_NVM_BANK:
		if (nbl_res_adminq_get_nvm_bank_index(res_mgt, &rbank))
			return -EFAULT;

		write_bank = rbank ? BANKID_NVM_BANK0 : BANKID_NVM_BANK1;

		ret |= nbl_res_adminq_flash_erase(res_mgt, write_bank, 0, param->len);
		ret |= nbl_res_adminq_flash_write(res_mgt, write_bank, 0, param->len,
						  param->data);

		break;
	default:
		return 0;
	}

	return ret;
}

static int nbl_res_adminq_flash_activate(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	int rbank, ret = 0;

	ret = nbl_res_adminq_get_nvm_bank_index(res_mgt, &rbank);
	if (ret || (rbank != 0 && rbank != 1))
		return -EFAULT;

	ret = nbl_res_adminq_flash_verify(res_mgt, &rbank);
	if (ret)
		return ret;

	ret = nbl_res_adminq_flash_set_nvm_bank(res_mgt, rbank, BANKID_SR_BANK0,
						NBL_ADMINQ_NVM_BANK_SWITCH);
	if (ret)
		return ret;

	ret = nbl_res_adminq_flash_set_nvm_bank(res_mgt, rbank, BANKID_SR_BANK1,
						NBL_ADMINQ_NVM_BANK_SWITCH);

	return ret;
}

/* get_emp_version is deprecated, repalced by get_firmware_version, 0x8102 */
static int nbl_res_adminq_get_firmware_version(void *priv,
					       struct nbl_ch_prm_get_firmware_version *output)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u16 func_id = NBL_COMMON_TO_MGT_PF(common);
	struct device *dev = NBL_COMMON_TO_DEV(common);
	struct nbl_chan_send_info chan_send;
	struct nbl_chan_param_nvm_version_resp resp_param;
	int ret = 0;
	u32 version_type = NBL_FW_VERSION_RUNNING_BANK;

	if (func_id != output->sfid) {
		memcpy(output->version, adminq_mgt->firmware_version, NBL_FRIMWARE_VERSION_LEN);
		return 0;
	}

	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID, NBL_CHAN_MSG_ADMINQ_GET_NVM_VERSION,
		      &version_type, sizeof(version_type), &resp_param, sizeof(resp_param), 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x\n",
			ret, NBL_CHAN_MSG_ADMINQ_GET_NVM_VERSION);
		return ret;
	}

	if (!memcmp(resp_param.magic, adminq_mgt->firmware_magic, sizeof(resp_param.magic))) {
		snprintf(output->version, NBL_FRIMWARE_VERSION_LEN,
			 "%d.%d.%d build %04d%02d%02d %08x",
			 BCD2BYTE((resp_param.version >> 16) & 0xFF),
			 BCD2BYTE((resp_param.version >> 8) & 0xFF),
			 BCD2BYTE(resp_param.version & 0xFF),
			 BCD2SHORT((resp_param.build_date >> 16) & 0xFFFF),
			 BCD2BYTE((resp_param.build_date >> 8) & 0xFF),
			 BCD2BYTE(resp_param.build_date & 0xFF),
			 resp_param.build_hash);
		memcpy(adminq_mgt->firmware_version, output->version, NBL_FRIMWARE_VERSION_LEN);
	} else {
		dev_err(dev, "adminq msg firmware version magic check failed\n");
		return -EINVAL;
	}

	return 0;
}

static int nbl_res_adminq_set_sfp_state(void *priv, struct nbl_ch_prm_set_sfp_state *prm)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_chan_send_info chan_send;
	struct nbl_port_key *param;
	int param_len = 0;
	u64 data = 0;
	u64 key = 0;
	int ret;

	param_len = sizeof(struct nbl_port_key) + 1 * sizeof(u64);
	param = kzalloc(param_len, GFP_KERNEL);

	key = NBL_PORT_KEY_MODULE_SWITCH;
	if (prm->state)
		data = NBL_PORT_SFP_ON + (key << NBL_PORT_KEY_KEY_SHIFT);
	else
		data = NBL_PORT_SFP_OFF + (key << NBL_PORT_KEY_KEY_SHIFT);

	memset(param, 0, param_len);
	param->id = prm->eth_id;
	param->subop = NBL_PORT_SUBOP_WRITE;
	param->data[0] = data;

	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
		      NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
		      param, param_len, NULL, 0, 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x, eth_id:%d, sfp %s\n",
			ret, NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
			eth_info->logic_eth_id[prm->eth_id],
			prm->state ? "on" : "off");
		kfree(param);
		return ret;
	}

	kfree(param);
	return 0;
}

int nbl_res_open_sfp(struct nbl_resource_mgt *res_mgt, u8 eth_id)
{
	struct nbl_ch_prm_set_sfp_state prm = {0};

	prm.eth_id = eth_id;
	prm.state = NBL_SFP_MODULE_ON;
	return nbl_res_adminq_set_sfp_state(res_mgt, &prm);
}

static int nbl_res_adminq_set_eth_loopback(void *priv, struct nbl_ch_prm_set_eth_loopback *prm)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_chan_send_info chan_send;
	struct nbl_port_key *param;
	int param_len = 0;
	u64 data = 0;
	u64 key = 0;
	int ret;

	param_len = sizeof(struct nbl_port_key) + 1 * sizeof(u64);
	param = kzalloc(param_len, GFP_KERNEL);

	key = NBL_PORT_KEY_LOOPBACK;
	if (prm->enable)
		data = NBL_PORT_ENABLE_LOOPBACK + (key << NBL_PORT_KEY_KEY_SHIFT);
	else
		data = NBL_PORT_DISABLE_LOOPBCK + (key << NBL_PORT_KEY_KEY_SHIFT);

	memset(param, 0, param_len);
	param->id = prm->eth_port_id;
	param->subop = NBL_PORT_SUBOP_WRITE;
	param->data[0] = data;

	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
		      NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
			param, param_len, NULL, 0, 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x, eth_id:%d, %s eth loopback\n",
			ret, NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
			eth_info->logic_eth_id[prm->eth_port_id],
			prm->enable ? "enable" : "disable");

		kfree(param);
		return ret;
	}

	kfree(param);
	return 0;
}

static bool nbl_res_adminq_check_fw_heartbeat(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	unsigned long check_time;
	u32 seq_acked;

	check_time = jiffies;
	if (time_before(check_time, adminq_mgt->fw_last_hb_time + 5 * HZ))
		return true;

	seq_acked = phy_ops->get_fw_pong(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
	if (adminq_mgt->fw_last_hb_seq == seq_acked) {
		adminq_mgt->fw_last_hb_seq++;
		adminq_mgt->fw_last_hb_time = check_time;
		phy_ops->set_fw_ping(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), adminq_mgt->fw_last_hb_seq);
		return true;
	}

	dev_info(dev, "check fw heartbeat failed, last_hb_seq 0x%x, seq acked 0x%x\n",
		 adminq_mgt->fw_last_hb_seq, seq_acked);

	return false;
}

static bool nbl_res_adminq_check_fw_reset(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u32 seq_acked;

	seq_acked = phy_ops->get_fw_pong(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
	if (adminq_mgt->fw_last_hb_seq != seq_acked) {
		phy_ops->set_fw_ping(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), adminq_mgt->fw_last_hb_seq);
		return false;
	}

	return true;
}

static int nbl_res_adminq_get_port_attributes(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_chan_send_info chan_send;
	struct nbl_port_key *param;
	int param_len = 0;
	u64 port_caps = 0;
	u64 port_advertising = 0;
	u64 key = 0;
	int eth_id = 0;
	int ret;

	param_len = sizeof(struct nbl_port_key) + 1 * sizeof(u64);
	param = kzalloc(param_len, GFP_KERNEL);

	for_each_set_bit(eth_id, eth_info->eth_bitmap, NBL_MAX_ETHERNET) {
		key = NBL_PORT_KEY_CAPABILITIES;
		port_caps = 0;

		memset(param, 0, param_len);
		param->id = eth_id;
		param->subop = NBL_PORT_SUBOP_READ;
		param->data[0] = key << NBL_PORT_KEY_KEY_SHIFT;

		NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
			      NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
			      param, param_len, (void *)&port_caps, sizeof(port_caps), 1);
		ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
		if (ret) {
			dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x, eth_id:%d, get_port_caps\n",
				ret, NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
				eth_info->logic_eth_id[eth_id]);
			kfree(param);
			return ret;
		}

		eth_info->port_caps[eth_id] = port_caps & NBL_PORT_KEY_DATA_MASK;

		dev_info(dev, "ctrl dev get eth %d port caps: %llx\n",
			 eth_info->logic_eth_id[eth_id],
			 eth_info->port_caps[eth_id]);
	}

	for_each_set_bit(eth_id, eth_info->eth_bitmap, NBL_MAX_ETHERNET) {
		key = NBL_PORT_KEY_ADVERT;
		port_advertising = 0;

		memset(param, 0, param_len);
		param->id = eth_id;
		param->subop = NBL_PORT_SUBOP_READ;
		param->data[0] = key << NBL_PORT_KEY_KEY_SHIFT;

		NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
			      NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
			      param, param_len,
			      (void *)&port_advertising, sizeof(port_advertising), 1);
		ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
		if (ret) {
			dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x, eth_id:%d, port_advertising\n",
				ret, NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
				eth_info->logic_eth_id[eth_id]);
			kfree(param);
			return ret;
		}

		port_advertising = port_advertising & NBL_PORT_KEY_DATA_MASK;
		/* set default FEC mode: auto */
		port_advertising = port_advertising & ~NBL_PORT_CAP_FEC_MASK;
		port_advertising += BIT(NBL_PORT_CAP_FEC_RS);
		port_advertising += BIT(NBL_PORT_CAP_FEC_BASER);
		/* set default pause: tx on, rx on */
		port_advertising = port_advertising & ~NBL_PORT_CAP_PAUSE_MASK;
		port_advertising += BIT(NBL_PORT_CAP_TX_PAUSE);
		port_advertising += BIT(NBL_PORT_CAP_RX_PAUSE);
		eth_info->port_advertising[eth_id] = port_advertising;

		dev_info(dev, "ctrl dev get eth %d port advertising: %llx\n",
			 eth_info->logic_eth_id[eth_id],
			 eth_info->port_advertising[eth_id]);
	}

	kfree(param);
	return 0;
}

static int nbl_res_adminq_enable_port(void *priv, bool enable)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_chan_send_info chan_send;
	struct nbl_port_key *param;
	int param_len = 0;
	u64 data = 0;
	u64 key = 0;
	int eth_id = 0;
	int ret;
	struct nbl_ch_prm_set_sfp_state prm = {0};

	param_len = sizeof(struct nbl_port_key) + 1 * sizeof(u64);
	param = kzalloc(param_len, GFP_KERNEL);

	if (enable) {
		key = NBL_PORT_KEY_ENABLE;
		data = NBL_PORT_FLAG_ENABLE_NOTIFY + (key << NBL_PORT_KEY_KEY_SHIFT);
	} else {
		key = NBL_PORT_KEY_DISABLE;
		data = key << NBL_PORT_KEY_KEY_SHIFT;
	}

	for_each_set_bit(eth_id, eth_info->eth_bitmap, NBL_MAX_ETHERNET) {
		prm.eth_id = eth_id;
		prm.state = NBL_SFP_MODULE_ON;
		nbl_res_adminq_set_sfp_state(res_mgt, &prm);

		memset(param, 0, param_len);
		param->id = eth_id;
		param->subop = NBL_PORT_SUBOP_WRITE;
		param->data[0] = data;

		NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
			      NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
			      param, param_len, NULL, 0, 1);
		ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
		if (ret) {
			dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x, eth_id:%d, %s port\n",
				ret, NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
				eth_info->logic_eth_id[eth_id], enable ? "enable" : "disable");
			kfree(param);
			return ret;
		}

		dev_info(dev, "ctrl dev %s eth %d\n", enable ? "enable" : "disable",
			 eth_info->logic_eth_id[eth_id]);
	}

	kfree(param);

	return 0;
}

static int nbl_res_adminq_get_special_port_type(struct nbl_resource_mgt *res_mgt, u8 eth_id)
{
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	u8 port_type = NBL_PORT_TYPE_UNKNOWN;
	u8 cable_tech = 0;
	int ret;

	ret = nbl_res_adminq_turn_module_eeprom_page(res_mgt, eth_id, 0);
	if (ret) {
		dev_err(dev, "eth %d get_module_eeprom_info failed %d\n",
			eth_info->logic_eth_id[eth_id], ret);
		port_type = NBL_PORT_TYPE_UNKNOWN;
		return port_type;
	}

	ret = nbl_res_adminq_get_module_eeprom_info(res_mgt, eth_id, I2C_DEV_ADDR_A0,
						    0, 0, SFF8636_DEVICE_TECH_OFFSET,
							1, &cable_tech);
	if (ret) {
		dev_err(dev, "eth %d get_module_eeprom_info failed %d\n",
			eth_info->logic_eth_id[eth_id], ret);
		port_type = NBL_PORT_TYPE_UNKNOWN;
		return port_type;
	}
	cable_tech = (cable_tech >> 4) & 0x0f;
	switch (cable_tech) {
	case SFF8636_TRANSMIT_FIBER_850nm_VCSEL:
	case SFF8636_TRANSMIT_FIBER_1310nm_VCSEL:
	case SFF8636_TRANSMIT_FIBER_1550nm_VCSEL:
	case SFF8636_TRANSMIT_FIBER_1310nm_FP:
	case SFF8636_TRANSMIT_FIBER_1310nm_DFB:
	case SFF8636_TRANSMIT_FIBER_1550nm_DFB:
	case SFF8636_TRANSMIT_FIBER_1310nm_EML:
	case SFF8636_TRANSMIT_FIBER_1550nm_EML:
	case SFF8636_TRANSMIT_FIBER_1490nm_DFB:
		port_type = NBL_PORT_TYPE_FIBRE;
		break;
	case SFF8636_TRANSMIT_COPPER_UNEQUA:
	case SFF8636_TRANSMIT_COPPER_PASSIVE_EQUALIZED:
	case SFF8636_TRANSMIT_COPPER_NEAR_FAR_END:
	case SFF8636_TRANSMIT_COPPER_FAR_END:
	case SFF8636_TRANSMIT_COPPER_NEAR_END:
	case SFF8636_TRANSMIT_COPPER_LINEAR_ACTIVE:
		port_type = NBL_PORT_TYPE_COPPER;
		break;
	default:
		dev_err(dev, "eth %d unknown port_type\n", eth_info->logic_eth_id[eth_id]);
		port_type = NBL_PORT_TYPE_UNKNOWN;
		break;
	}
	return port_type;
}

static int nbl_res_adminq_get_common_port_type(struct nbl_resource_mgt *res_mgt, u8 eth_id)
{
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	u8 data[SFF_8472_CABLE_SPEC_COMP + 1];
	u8 cable_tech = 0;
	u8 cable_comp = 0;
	u8 port_type = NBL_PORT_TYPE_UNKNOWN;
	int ret;

	ret = nbl_res_adminq_get_module_eeprom_info(res_mgt, eth_id, I2C_DEV_ADDR_A0, 0, 0, 0,
						    SFF_8472_CABLE_SPEC_COMP + 1, data);
	if (ret) {
		dev_err(dev, "eth %d get_module_eeprom_info failed %d\n",
			eth_info->logic_eth_id[eth_id], ret);
		port_type = NBL_PORT_TYPE_UNKNOWN;
		return port_type;
	}

	cable_tech = data[SFF_8472_CABLE_TECHNOLOGY];

	if (cable_tech & SFF_PASSIVE_CABLE) {
		cable_comp = data[SFF_8472_CABLE_SPEC_COMP];

		/* determine if the port is a cooper cable */
		if (cable_comp == SFF_COPPER_UNSPECIFIED ||
		    cable_comp & SFF_COPPER_8431_APPENDIX_E)
			port_type = NBL_PORT_TYPE_COPPER;
		else
			port_type = NBL_PORT_TYPE_FIBRE;
	} else if (cable_tech & SFF_ACTIVE_CABLE) {
		cable_comp = data[SFF_8472_CABLE_SPEC_COMP];

		/* determine if the port is a cooper cable */
		if (cable_comp == SFF_COPPER_UNSPECIFIED ||
		    cable_comp == SFF_COPPER_8431_APPENDIX_E ||
		    cable_comp == SFF_COPPER_8431_LIMITING)
			port_type = NBL_PORT_TYPE_COPPER;
		else
			port_type = NBL_PORT_TYPE_FIBRE;
	} else {
		port_type = NBL_PORT_TYPE_FIBRE;
	}

	return port_type;
}

static int nbl_res_adminq_get_port_type(struct nbl_resource_mgt *res_mgt, u8 eth_id)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);

	if (common->port_type == NBL_FW_PORT_RJ45)
		return NBL_PORT_TYPE_TP;
	if (res_mgt->resource_info->board_info.eth_speed == NBL_FW_PORT_SPEED_100G)
		return nbl_res_adminq_get_special_port_type(res_mgt, eth_id);

	return nbl_res_adminq_get_common_port_type(res_mgt, eth_id);
}

static s32 nbl_res_adminq_get_module_bitrate(struct nbl_resource_mgt *res_mgt, u8 eth_id)
{
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	u8 data[SFF_8472_SIGNALING_RATE_MAX + 1];
	u32 result;
	u8 br_nom;
	u8 br_max;
	u8 identifier;
	u8 encoding = 0;
	int port_max_rate;
	int ret;

	if (res_mgt->resource_info->board_info.eth_speed == NBL_FW_PORT_SPEED_100G) {
		ret = nbl_res_adminq_turn_module_eeprom_page(res_mgt, eth_id, 0);
		if (ret) {
			dev_err(dev, "eth %d get_module_eeprom_info failed %d\n",
				eth_info->logic_eth_id[eth_id], ret);
			return NBL_PORT_MAX_RATE_UNKNOWN;
		}
	}

	ret = nbl_res_adminq_get_module_eeprom_info(res_mgt, eth_id, I2C_DEV_ADDR_A0, 0, 0, 0,
						    SFF_8472_SIGNALING_RATE_MAX + 1, data);
	if (ret) {
		dev_err(dev, "eth %d get_module_eeprom_info failed %d\n",
			eth_info->logic_eth_id[eth_id], ret);
		return NBL_PORT_MAX_RATE_UNKNOWN;
	}

	if (res_mgt->resource_info->board_info.eth_speed == NBL_FW_PORT_SPEED_100G) {
		ret = nbl_res_adminq_get_module_eeprom_info(res_mgt, eth_id,
							    I2C_DEV_ADDR_A0, 0, 0,
							    SFF_8636_VENDOR_ENCODING,
							    1, &encoding);
		if (ret) {
			dev_err(dev, "eth %d get_module_eeprom_info failed %d\n",
				eth_info->logic_eth_id[eth_id], ret);
			return NBL_PORT_MAX_RATE_UNKNOWN;
		}
	}

	br_nom = data[SFF_8472_SIGNALING_RATE];
	br_max = data[SFF_8472_SIGNALING_RATE_MAX];
	identifier = data[SFF_8472_IDENTIFIER];

	/* sff-8472 section 5.6 */
	if (br_nom == 255)
		result = (u32)br_max * 250;
	else if (br_nom == 0)
		result = 0;
	else
		result = (u32)br_nom * 100;

	switch (result / 1000) {
	case 25:
		port_max_rate = NBL_PORT_MAX_RATE_25G;
		break;
	case 10:
		port_max_rate = NBL_PORT_MAX_RATE_10G;
		break;
	case 1:
		port_max_rate = NBL_PORT_MAX_RATE_1G;
		break;
	default:
		port_max_rate = NBL_PORT_MAX_RATE_UNKNOWN;
		break;
	}

	if (identifier == SFF_IDENTIFIER_QSFP28)
		port_max_rate = NBL_PORT_MAX_RATE_100G;

	if (identifier == SFF_IDENTIFIER_PAM4 || encoding == SFF_8636_ENCODING_PAM4)
		port_max_rate = NBL_PORT_MAX_RATE_100G_PAM4;

	return port_max_rate;
}

static void nbl_res_eth_task_schedule(struct nbl_adminq_mgt *adminq_mgt)
{
	nbl_common_queue_work(&adminq_mgt->eth_task, true);
}

static int nbl_res_adminq_get_bond_link_state(struct nbl_resource_mgt *res_mgt, u8 eth_id)
{
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_eth_bond_info *eth_bond_info = NBL_RES_MGT_TO_ETH_BOND_INFO(res_mgt);
	struct nbl_eth_bond_entry *entry = NULL;
	u8 lag_id = nbl_res_eth_id_to_lag_id(res_mgt, eth_id);
	int i, link_state = 0;

	if (lag_id >= NBL_LAG_MAX_NUM)
		return eth_info->link_state[eth_id];

	/* bond_link_state will be 1 if any eth port is up */
	entry = &eth_bond_info->entry[lag_id];
	for (i = 0; i < entry->lag_num && NBL_ETH_BOND_VALID_PORT(i); i++)
		link_state |= !!(eth_info->link_state[entry->eth_id[i]]);

	return link_state;
}

static int nbl_res_adminq_handle_link_state_update(u16 type, void *event_data, void *callback_data)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)callback_data;
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct nbl_event_link_status_update_data *data =
		(struct nbl_event_link_status_update_data *)event_data;
	int i;

	mutex_lock(&adminq_mgt->eth_lock);
	for (i = 0; i < data->num; i++)
		adminq_mgt->link_state_changed[data->eth_id[i]] = 1;

	mutex_unlock(&adminq_mgt->eth_lock);

	nbl_res_eth_task_schedule(adminq_mgt);

	return 0;
}

static void nbl_res_adminq_recv_port_notify(void *priv, void *data)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_eth_bond_info *eth_bond_info = NBL_RES_MGT_TO_ETH_BOND_INFO(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_port_notify *notify;
	int i, eth_id = 0, eth_tmp = 0;
	u8 lag_id;
	u8 last_module_inplace = 0;
	u8 last_link_state = 0;
	u32 last_speed;
	bool my_flag = false;
	bool lag_flag = false;
	bool changed = false;

	notify = (struct nbl_port_notify *)data;
	eth_id = notify->id;

	if (test_bit(eth_id, eth_info->eth_bitmap))
		my_flag = true;

	lag_id = nbl_res_eth_id_to_lag_id(res_mgt, eth_id);
	if (lag_id < NBL_LAG_MAX_NUM)
		lag_flag = true;

	dev_info(dev, "eth_id:%d, my_flag:%d, lag_flag:%d, link_state:%d, module_inplace:%d, speed:%d, flow_ctrl:%d, fec:%d, advertising:%llx, lp_advertising:%llx\n",
		 eth_info->logic_eth_id[eth_id], my_flag, lag_flag, notify->link_state,
		 notify->module_inplace, notify->speed * 10, notify->flow_ctrl,
		 notify->fec, notify->advertising, notify->lp_advertising);

	mutex_lock(&adminq_mgt->eth_lock);

	last_module_inplace = eth_info->module_inplace[eth_id];
	last_link_state = eth_info->link_state[eth_id];
	last_speed = eth_info->link_speed[eth_id];
	if (!notify->link_state)
		eth_info->link_down_count[eth_id]++;

	eth_info->link_state[eth_id] = notify->link_state;
	eth_info->module_inplace[eth_id] = notify->module_inplace;
	/* when eth link down, don not update speed
	 * when config autoneg to off, ethtool read speed and set it with disable autoneg command,
	 * if eth is link down, the speed from emp is not credible,
	 * need to reserver last link up speed.
	 */
	if (notify->link_state || !eth_info->link_speed[eth_id])
		eth_info->link_speed[eth_id] = notify->speed * 10;

	if (my_flag && !lag_flag && last_speed != eth_info->link_speed[eth_id]) {
		adminq_mgt->speed_changed[eth_id] = 1;
		changed = true;
	}
	eth_info->active_fc[eth_id] = notify->flow_ctrl;
	eth_info->active_fec[eth_id] = notify->fec;
	eth_info->port_lp_advertising[eth_id] = notify->lp_advertising;
	eth_info->port_advertising[eth_id] = notify->advertising;

	if (my_flag && !last_module_inplace && notify->module_inplace) {
		adminq_mgt->module_inplace_changed[eth_id] = 1;
		changed = true;
	}

	if (my_flag && last_link_state != notify->link_state) {
		adminq_mgt->link_state_changed[eth_id] = 1;
		changed = true;
	}

	/* If this eth belongs to a bond, vf state depend bond group. Only the two eth all down,
	 * vf will down. Just one eth up, the vf will up.
	 */
	if (lag_flag) {
		for (i = 0; i < eth_bond_info->entry[lag_id].lag_num &&
		     NBL_ETH_BOND_VALID_PORT(i); i++) {
			eth_tmp = eth_bond_info->entry[lag_id].eth_id[i];
			adminq_mgt->link_state_changed[eth_tmp] = 1;
		}
		changed = true;
	}
	if (changed)
		nbl_res_eth_task_schedule(adminq_mgt);

	mutex_unlock(&adminq_mgt->eth_lock);
}

static int nbl_res_adminq_set_port_advertising(void *priv,
					       struct nbl_port_advertising *advertising)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_chan_send_info chan_send;
	struct nbl_port_key *param;
	int param_len = 0;
	int eth_id = 0;
	u64 key = 0;
	u64 data = 0;
	u64 new_advert = 0;
	int ret;

	eth_id = advertising->eth_id;
	mutex_lock(&eth_info->eth_lock);
	param_len = sizeof(struct nbl_port_key) + 1 * sizeof(u64);
	param = kzalloc(param_len, GFP_KERNEL);

	new_advert = eth_info->port_advertising[eth_id];

	/* set autoneg */
	if (advertising->autoneg != 0) {
		new_advert = new_advert | NBL_PORT_CAP_AUTONEG_MASK | NBL_PORT_CAP_PAUSE_MASK;
		new_advert |= BIT(NBL_PORT_CAP_AUTONEG);
	} else {
		new_advert = new_advert & ~NBL_PORT_CAP_AUTONEG_MASK;
	}

	if (advertising->active_fc != 0) {
		new_advert = new_advert & ~NBL_PORT_CAP_PAUSE_MASK;
		if (advertising->active_fc & NBL_PORT_TX_PAUSE)
			new_advert |= BIT(NBL_PORT_CAP_TX_PAUSE);
		if (advertising->active_fc & NBL_PORT_RX_PAUSE)
			new_advert |= BIT(NBL_PORT_CAP_RX_PAUSE);
	}

	/* set FEC */
	if (advertising->active_fec != 0) {
		new_advert = new_advert & ~NBL_PORT_CAP_FEC_MASK &
			      ~BIT_ULL(NBL_PORT_CAP_FEC_AUTONEG);

		/* when ethtool set FEC_AUTO, we set default fec mode */
		if (advertising->active_fec == NBL_PORT_FEC_AUTO &&
		    (!advertising->autoneg &&
		     !(eth_info->port_caps[eth_id] & BIT_ULL(NBL_PORT_CAP_FEC_AUTONEG)))) {
			advertising->active_fec = NBL_PORT_FEC_OFF;
			if (eth_info->link_speed[eth_id] == SPEED_1000)
				advertising->active_fec = NBL_ETH_1G_DEFAULT_FEC_MODE;
			if (eth_info->link_speed[eth_id] == SPEED_10000)
				advertising->active_fec = NBL_ETH_10G_DEFAULT_FEC_MODE;
			if (eth_info->link_speed[eth_id] == SPEED_25000)
				advertising->active_fec = NBL_ETH_25G_DEFAULT_FEC_MODE;
		}

		if (advertising->active_fec == NBL_PORT_FEC_OFF)
			new_advert |= BIT(NBL_PORT_CAP_FEC_OFF);
		if (advertising->active_fec == NBL_PORT_FEC_RS)
			new_advert |= BIT(NBL_PORT_CAP_FEC_RS);
		if (advertising->active_fec == NBL_PORT_FEC_BASER)
			new_advert |= BIT(NBL_PORT_CAP_FEC_BASER);
		if (advertising->active_fec == NBL_PORT_FEC_AUTO) {
			new_advert |= NBL_PORT_CAP_FEC_MASK;
			if (eth_info->port_caps[eth_id] & BIT_ULL(NBL_PORT_CAP_FEC_AUTONEG))
				new_advert |= BIT_ULL(NBL_PORT_CAP_FEC_AUTONEG);
		}
	}

	/* set speed */
	if (advertising->speed_advert != 0) {
		new_advert = (new_advert & (NBL_PORT_CAP_AUTONEG_MASK | NBL_PORT_CAP_FEC_MASK |
			      NBL_PORT_CAP_PAUSE_MASK | BIT_ULL(NBL_PORT_CAP_FEC_AUTONEG))) |
			      advertising->speed_advert;
	}

	if (eth_info->port_max_rate[eth_id] != NBL_PORT_MAX_RATE_100G_PAM4 ||
	    (!(new_advert & NBL_PORT_CAP_SPEED_100G_MASK) &&
	     eth_info->port_max_rate[eth_id] == NBL_PORT_MAX_RATE_100G_PAM4))
		new_advert &= ~NBL_PORT_CAP_PAM4_MASK;
	else
		new_advert |= NBL_PORT_CAP_PAM4_MASK;

	new_advert &= eth_info->port_caps[eth_id];
	dev_notice(dev, "set NBL_PORT_KEY_ADVERT eth id %d new_advert 0x%llx\n",
		   eth_info->logic_eth_id[eth_id], new_advert);

	key = NBL_PORT_KEY_ADVERT;
	data = new_advert + (key << NBL_PORT_KEY_KEY_SHIFT);

	param->id = advertising->eth_id;
	param->subop = NBL_PORT_SUBOP_WRITE;
	param->data[0] = data;

	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
		      NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
		      param, param_len, NULL, 0, 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x, eth_id:%d, set_port_advertising\n",
			ret, NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
			eth_info->logic_eth_id[eth_id]);
		kfree(param);
		mutex_unlock(&eth_info->eth_lock);
		return ret;
	}

	eth_info->port_advertising[eth_id] = new_advert;

	kfree(param);
	mutex_unlock(&eth_info->eth_lock);
	return 0;
}

static int nbl_res_adminq_get_port_state(void *priv, u8 eth_id, struct nbl_port_state *port_state)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);

	port_state->port_caps = eth_info->port_caps[eth_id];
	port_state->port_advertising = eth_info->port_advertising[eth_id];
	port_state->port_lp_advertising = eth_info->port_lp_advertising[eth_id];
	port_state->link_speed = eth_info->link_speed[eth_id];
	port_state->active_fc = eth_info->active_fc[eth_id];
	port_state->active_fec = eth_info->active_fec[eth_id];
	port_state->link_state = eth_info->link_state[eth_id];
	port_state->module_inplace = eth_info->module_inplace[eth_id];
	port_state->fw_port_max_speed = res_mgt->resource_info->board_info.eth_speed;
	port_state->module_repluged = eth_info->module_repluged[eth_id];
	eth_info->module_repluged[eth_id] = 0;
	if (port_state->module_inplace) {
		port_state->port_type = eth_info->port_type[eth_id];
		port_state->port_max_rate = eth_info->port_max_rate[eth_id];
	} else {
		port_state->port_caps = port_state->port_caps & ~NBL_PORT_CAP_FEC_MASK;
		port_state->port_caps = port_state->port_caps & ~NBL_PORT_CAP_PAUSE_MASK;
		port_state->port_caps = port_state->port_caps & ~NBL_PORT_CAP_AUTONEG_MASK;
		port_state->port_advertising =
				port_state->port_advertising & ~NBL_PORT_CAP_FEC_MASK;
		port_state->port_advertising =
				port_state->port_advertising & ~NBL_PORT_CAP_PAUSE_MASK;
		port_state->port_advertising =
				port_state->port_advertising & ~NBL_PORT_CAP_AUTONEG_MASK;
	}

	return 0;
}

static int nbl_res_adminq_get_module_info(void *priv, u8 eth_id, struct ethtool_modinfo *info)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	u8 sff8472_rev;
	u8 addr_mode;
	bool page_swap = false;
	u8 module_inplace = 0; /* 1 inplace, 0 not inplace */
	u8 data[SFF_8472_COMPLIANCE + 1];
	int ret;

	module_inplace = eth_info->module_inplace[eth_id];
	if (!module_inplace) {
		dev_err(dev, "Optical module of ETH port %u is not inplace\n",
			eth_info->logic_eth_id[eth_id]);
		return -EIO;
	}

	if (res_mgt->resource_info->board_info.eth_speed == NBL_FW_PORT_SPEED_100G) {
		info->type = ETH_MODULE_SFF_8636;
		info->eeprom_len = ETH_MODULE_SFF_8636_MAX_LEN;
		return 0;
	}
	mutex_lock(&eth_info->eth_lock);
	ret = nbl_res_adminq_get_module_eeprom_info(res_mgt, eth_id, I2C_DEV_ADDR_A0, 0, 0, 0,
						    SFF_8472_COMPLIANCE + 1, data);
	if (ret) {
		dev_err(dev, "eth %d get_module_eeprom_info failed %d\n",
			eth_info->logic_eth_id[eth_id], ret);
		mutex_unlock(&eth_info->eth_lock);
		return -EIO;
	}

	sff8472_rev = data[SFF_8472_COMPLIANCE];
	addr_mode = data[SFF_8472_DIAGNOSTIC];

	/* check if can access page 0xA2 directly, see sff-8472 */
	if (addr_mode & SFF_8472_ADDRESSING_MODE) {
		dev_err(dev, "Address change required to access page 0xA2 which is not supported\n");
		page_swap = true;
	}

	if ((sff8472_rev & 0xFF) == SFF_8472_UNSUPPORTED || page_swap ||
	    !(addr_mode & SFF_DDM_IMPLEMENTED)) {
		/* We have an SFP, but it does not support SFF-8472 */
		info->type = ETH_MODULE_SFF_8079;
		info->eeprom_len = ETH_MODULE_SFF_8079_LEN;
	} else {
		/* We have an SFP which supports a revision of SFF-8472 */
		info->type = ETH_MODULE_SFF_8472;
		info->eeprom_len = ETH_MODULE_SFF_8472_LEN;
	}
	mutex_unlock(&eth_info->eth_lock);
	return 0;
}

static int nbl_res_adminq_get_module_eeprom(void *priv, u8 eth_id,
					    struct ethtool_eeprom *eeprom, u8 *data)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	u8 module_inplace = 0; /* 1 inplace, 0 not inplace */
	u32 start = eeprom->offset;
	u32 total_len = eeprom->len;
	u32 length;
	u8 turn_page, offset;
	int ret;

	if (eeprom->len == 0)
		return -EINVAL;

	module_inplace = eth_info->module_inplace[eth_id];
	if (!module_inplace) {
		dev_err(dev, "Optical module of ETH port %u is not inplace\n",
			eth_info->logic_eth_id[eth_id]);
		return -EIO;
	}
	mutex_lock(&eth_info->eth_lock);
	if (res_mgt->resource_info->board_info.eth_speed == NBL_FW_PORT_SPEED_100G) {
		while (start < ETH_MODULE_SFF_8636_MAX_LEN && total_len) {
			nbl_res_get_module_eeprom_page(start, &turn_page, &offset);
			length = min(SFF_8638_PAGESIZE, total_len);
			if (offset % SFF_8638_PAGESIZE + length > SFF_8638_PAGESIZE)
				length = SFF_8638_PAGESIZE - offset % SFF_8638_PAGESIZE;

			/* emp always return 0 */
			ret = nbl_res_adminq_turn_module_eeprom_page(res_mgt, eth_id, turn_page);
			if (ret) {
				dev_err(dev, "eth %d turn_module_eeprom_page failed %d\n",
					eth_info->logic_eth_id[eth_id], ret);
			}

			/* emp will switch page, and then read eeprom data */
			ret = nbl_res_adminq_get_module_eeprom_info(res_mgt, eth_id,
								    I2C_DEV_ADDR_A0, turn_page, 0,
								    offset, length, data);
			if (ret) {
				dev_info(dev, "eth %d get_module_eeprom_info failed %d\n",
					 eth_info->logic_eth_id[eth_id], ret);
			}
			start += length;
			data += length;
			total_len -= length;
		}
		mutex_unlock(&eth_info->eth_lock);
		return 0;
	}

	length = total_len;
	/* Read A0 portion of eth EEPROM */
	if (start < ETH_MODULE_SFF_8079_LEN) {
		if (start + length > ETH_MODULE_SFF_8079_LEN)
			length = ETH_MODULE_SFF_8079_LEN - start;

		ret = nbl_res_adminq_get_module_eeprom_info(res_mgt, eth_id, I2C_DEV_ADDR_A0, 0, 0,
							    start, length, data);
		if (ret) {
			dev_err(dev, "eth %d get_module_eeprom_info failed %d\n",
				eth_info->logic_eth_id[eth_id], ret);
			mutex_unlock(&eth_info->eth_lock);
			return -EIO;
		}
		start += length;
		data += length;
		length = total_len - length;
	}

	/* Read A2 portion of eth EEPROM */
	if (length) {
		start -= ETH_MODULE_SFF_8079_LEN;
		ret = nbl_res_adminq_get_module_eeprom_info(res_mgt, eth_id, I2C_DEV_ADDR_A2, 0, 0,
							    start, length, data);
		if (ret) {
			dev_err(dev, "eth %d get_module_eeprom_info failed %d\n",
				eth_info->logic_eth_id[eth_id], ret);
			mutex_unlock(&eth_info->eth_lock);
			return -EIO;
		}
	}
	mutex_unlock(&eth_info->eth_lock);
	return 0;
}

static int nbl_res_adminq_get_link_state(void *priv, u8 eth_id,
					 struct nbl_eth_link_info *eth_link_info)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);

	eth_link_info->link_status = eth_info->link_state[eth_id];
	eth_link_info->link_speed = eth_info->link_speed[eth_id];

	return 0;
}

static int nbl_res_adminq_get_link_down_count(void *priv, u8 eth_id, u64 *link_down_count)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);

	*link_down_count = eth_info->link_down_count[eth_id];
	return 0;
}

static int nbl_res_adminq_get_link_status_opcode(void *priv, u8 eth_id, u32 *link_status_opcode)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_chan_send_info chan_send;
	struct nbl_port_key *param;
	u64 data = 0, key = 0, result = 0;
	int param_len = 0, ret = 0;

	param_len = sizeof(struct nbl_port_key) + 1 * sizeof(u64);
	param = kzalloc(param_len, GFP_KERNEL);

	key = NBL_PORT_KEY_GET_LINK_STATUS_OPCODE;

	data += (key << NBL_PORT_KEY_KEY_SHIFT);

	memset(param, 0, param_len);
	param->id = eth_id;
	param->subop = NBL_PORT_SUBOP_READ;
	param->data[0] = data;

	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
		      NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
		      param, param_len, &result, sizeof(result), 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x, eth_id:%d\n",
			ret, NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
			eth_info->logic_eth_id[eth_id]);
		kfree(param);
		return ret;
	}

	*link_status_opcode = result;

	kfree(param);
	return 0;
}

static int nbl_res_adminq_get_eth_mac_addr(void *priv, u8 *mac, u8 eth_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_chan_send_info chan_send;
	struct nbl_port_key *param;
	u64 data = 0, key = 0, result = 0;
	int param_len = 0, i, ret;
	u8 reverse_mac[ETH_ALEN];

	param_len = sizeof(struct nbl_port_key) + 1 * sizeof(u64);
	param = kzalloc(param_len, GFP_KERNEL);

	key = NBL_PORT_KEY_MAC_ADDRESS;

	data += (key << NBL_PORT_KEY_KEY_SHIFT);

	memset(param, 0, param_len);
	param->id = eth_id;
	param->subop = NBL_PORT_SUBOP_READ;
	param->data[0] = data;

	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
		      NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
		      param, param_len, &result, sizeof(result), 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x, eth_id:%d\n",
			ret, NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
			eth_info->logic_eth_id[eth_id]);
		kfree(param);
		return ret;
	}

	memcpy(reverse_mac, &result, ETH_ALEN);

	/*convert mac address*/
	for (i = 0; i < ETH_ALEN; i++)
		mac[i] = reverse_mac[ETH_ALEN - 1 - i];

	kfree(param);
	return 0;
}

int nbl_res_get_eth_mac(struct nbl_resource_mgt *res_mgt, u8 *mac, u8 eth_id)
{
	return nbl_res_adminq_get_eth_mac_addr(res_mgt, mac, eth_id);
}

static int nbl_res_adminq_set_eth_mac_addr(void *priv, u8 *mac, u8 eth_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_chan_send_info chan_send;
	struct nbl_port_key *param;
	int param_len = 0;
	u64 data = 0;
	u64 key = 0;
	int ret;
	int i;
	u8 reverse_mac[ETH_ALEN];

	param_len = sizeof(struct nbl_port_key) + 1 * sizeof(u64);
	param = kzalloc(param_len, GFP_KERNEL);

	key = NBL_PORT_KEY_MAC_ADDRESS;

	/*convert mac address*/
	for (i = 0; i < ETH_ALEN; i++)
		reverse_mac[i] = mac[ETH_ALEN - 1 - i];

	memcpy(&data, reverse_mac, ETH_ALEN);

	data += (key << NBL_PORT_KEY_KEY_SHIFT);

	memset(param, 0, param_len);
	param->id = eth_id;
	param->subop = NBL_PORT_SUBOP_WRITE;
	param->data[0] = data;

	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
		      NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
		      param, param_len, NULL, 0, 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x, eth_id:%d, reverse_mac=0x%x:%x:%x:%x:%x:%x\n",
			ret, NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
			eth_info->logic_eth_id[eth_id], reverse_mac[0],
			reverse_mac[1], reverse_mac[2], reverse_mac[3],
			reverse_mac[4], reverse_mac[5]);
		kfree(param);
		return ret;
	}

	kfree(param);
	return 0;
}

static int nbl_res_adminq_get_fec_stats(void *priv, u32 eth_id,
					struct nbl_fec_stats *fec_stats)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_chan_send_info chan_send;
	int data_len = sizeof(struct nbl_fec_stats);
	int ret;

	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
		      NBL_CHAN_MSG_ADMINQ_GET_FEC_STATS, &eth_id,
		      sizeof(eth_id), fec_stats, data_len, 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret)
		dev_err(dev, "ctrl eth %d fec stats failed", eth_id);

	return ret;
}

static int nbl_res_adminq_ctrl_port_led(void *priv, u8 eth_id,
					enum nbl_led_reg_ctrl led_ctrl, u32 *led_reg)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_chan_send_info chan_send;
	struct nbl_port_key *param;
	int param_len = 0;
	u64 data = 0;
	u64 key = 0;
	int ret;

	param_len = sizeof(struct nbl_port_key) + 1 * sizeof(u64);
	param = kzalloc(param_len, GFP_KERNEL);

	key = NBL_PORT_KEY_LED_BLINK;

	switch (led_ctrl) {
	case NBL_LED_REG_ACTIVE:
		data = 1;
		break;
	case NBL_LED_REG_INACTIVE:
		data = 0;
		break;
	default:
		return 0;
	}

	data += (key << NBL_PORT_KEY_KEY_SHIFT);

	memset(param, 0, param_len);
	param->id = eth_id;
	param->subop = NBL_PORT_SUBOP_WRITE;
	param->data[0] = data;

	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
		      NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
		      param, param_len, NULL, 0, 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err(dev, "ctrl eth %d blink failed", eth_info->logic_eth_id[eth_id]);
		kfree(param);
		return ret;
	}

	kfree(param);
	return 0;
}

int nbl_res_adminq_set_eth_pfc(void *priv, u8 eth_id, u8 *pfc)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_chan_send_info chan_send;
	struct nbl_port_key *param;
	int param_len = 0;
	u64 data = 0;
	u64 key = 0;
	int ret;
	int i;

	mutex_lock(&eth_info->eth_lock);
	param_len = sizeof(struct nbl_port_key) + 1 * sizeof(u64);
	param = kzalloc(param_len, GFP_KERNEL);

	for (i = 0; i < NBL_MAX_PFC_PRIORITIES; i++) {
		if (pfc[i])
			data |= 1 << i;
	}

	key = NBL_PORT_KEY_SET_PFC_CFG;
	data += (key << NBL_PORT_KEY_KEY_SHIFT);

	memset(param, 0, param_len);
	param->id = eth_id;
	param->subop = NBL_PORT_SUBOP_WRITE;
	param->data[0] = data;

	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
		      NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
		      param, param_len, NULL, 0, 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x, eth_id:%d,\n",
			ret, NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
			eth_info->logic_eth_id[eth_id]);
		kfree(param);
		mutex_unlock(&eth_info->eth_lock);
		return ret;
	}

	kfree(param);
	mutex_unlock(&eth_info->eth_lock);
	return 0;
}

static int nbl_res_adminq_pt_filter_in(struct nbl_resource_mgt *res_mgt,
				       struct nbl_passthrough_fw_cmd_param *param)
{
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct nbl_res_fw_cmd_filter *filter;

	if (!adminq_mgt->cmd_filter)
		return 0;

	filter = nbl_common_get_hash_node(adminq_mgt->cmd_filter, &param->opcode);
	if (filter && filter->in)
		return filter->in(res_mgt, param->data, param->in_size);

	return 0;
}

static int nbl_res_adminq_pt_filter_out(struct nbl_resource_mgt *res_mgt,
					struct nbl_passthrough_fw_cmd_param *param,
					struct nbl_passthrough_fw_cmd_param *result)
{
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct nbl_res_fw_cmd_filter *filter;
	int ret = 0;

	if (!adminq_mgt->cmd_filter)
		return 0;

	filter = nbl_common_get_hash_node(adminq_mgt->cmd_filter, &param->opcode);
	if (filter && filter->out)
		ret = filter->out(res_mgt, param->data, param->in_size,
				  result->data, result->out_size);

	return 0;
}

static int nbl_res_adminq_passthrough(void *priv, struct nbl_passthrough_fw_cmd_param *param,
				      struct nbl_passthrough_fw_cmd_param *result)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_chan_send_info chan_send;
	u8 *in_data = NULL, *out_data = NULL;
	int ret = 0;

	ret = nbl_res_adminq_pt_filter_in(res_mgt, param);
	if (ret)
		return ret;

	if (param->in_size) {
		in_data = kzalloc(param->in_size, GFP_KERNEL);
		if (!in_data)
			goto in_data_fail;
		memcpy(in_data, param->data, param->in_size);
	}
	if (param->out_size) {
		out_data = kzalloc(param->out_size, GFP_KERNEL);
		if (!out_data)
			goto out_data_fail;
	}

	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID, param->opcode,
		      in_data, param->in_size, out_data, param->out_size, 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_dbg(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x\n",
			ret, param->opcode);
		goto send_fail;
	}

	result->opcode = param->opcode;
	result->errcode = ret;
	result->out_size = param->out_size;
	if (result->out_size)
		memcpy(result->data, out_data, param->out_size);

	nbl_res_adminq_pt_filter_out(res_mgt, param, result);

send_fail:
	kfree(out_data);
out_data_fail:
	kfree(in_data);
in_data_fail:
	return ret;
}

static int nbl_res_adminq_update_ring_num(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *res_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(NBL_RES_MGT_TO_COMMON(res_mgt));
	struct nbl_chan_send_info chan_send;
	struct nbl_chan_resource_read_param *param;
	struct nbl_net_ring_num_info *info;
	struct nbl_fw_cmd_net_ring_num_param *qp_num;
	int ret = 0;

	param = kzalloc(sizeof(*param), GFP_KERNEL);
	if (!param) {
		ret = -ENOMEM;
		goto alloc_param_fail;
	}

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		ret = -ENOMEM;
		goto alloc_info_fail;
	}

	param->resid = NBL_ADMINQ_PFA_TLV_NET_RING_NUM;
	param->offset = 0;
	param->len = sizeof(*info);
	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID, NBL_CHAN_MSG_ADMINQ_RESOURCE_READ,
		      param, sizeof(*param), info, sizeof(*info), 1);

	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x\n",
			ret, NBL_CHAN_MSG_ADMINQ_RESOURCE_READ);
		goto send_fail;
	}

	if (info->pf_def_max_net_qp_num && info->vf_def_max_net_qp_num) {
		qp_num = (struct nbl_fw_cmd_net_ring_num_param *)info;
		ret = nbl_res_adminq_check_net_ring_num(res_mgt, qp_num);
		if (!ret)
			memcpy(&res_info->net_ring_num_info, info,
			       sizeof(res_info->net_ring_num_info));
	}

send_fail:
	kfree(info);
alloc_info_fail:
	kfree(param);
alloc_param_fail:
	return 0;
}

static int nbl_res_adminq_rdma_cap_default(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_resource_info *res_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	u16 i = 0;

	for (i = 0; i < NBL_RES_MGT_TO_PF_NUM(res_mgt); i++)
		set_bit(i, res_info->rdma_info.func_cap);

	return 0;
}

static int nbl_res_adminq_rdma_cap_tlv(struct nbl_resource_mgt *res_mgt,
				       struct nbl_rdma_cap_info *info)
{
	struct nbl_resource_info *res_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	int i, j;

	for (i = 0; i < NBL_RDMA_CAP_CMD_LEN; i++)
		for (j = 0; j < BITS_PER_BYTE; j++)
			if (info->rdma_func_bitmaps[i] & BIT(j))
				set_bit(i * BITS_PER_BYTE + j, res_info->rdma_info.func_cap);

	return 0;
}

static int nbl_res_adminq_update_rdma_cap(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(NBL_RES_MGT_TO_COMMON(res_mgt));
	struct nbl_chan_send_info chan_send;
	struct nbl_chan_resource_read_param *param;
	struct nbl_rdma_cap_info *info;
	int ret = 0;

	param = kzalloc(sizeof(*param), GFP_KERNEL);
	if (!param) {
		ret = -ENOMEM;
		goto alloc_param_fail;
	}

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		ret = -ENOMEM;
		goto alloc_info_fail;
	}

	param->resid = NBL_ADMINQ_PFA_TLV_RDMA_CAP;
	param->offset = 0;
	param->len = sizeof(*info);
	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID, NBL_CHAN_MSG_ADMINQ_RESOURCE_READ,
		      param, sizeof(*param), info, sizeof(*info), 1);

	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x\n",
			ret, NBL_CHAN_MSG_ADMINQ_RESOURCE_READ);
		info->valid = 1;
	}

	/* For some reason, valid == 0 means valid, and 1 means invalid */
	if (info->valid)
		nbl_res_adminq_rdma_cap_default(res_mgt);
	else
		nbl_res_adminq_rdma_cap_tlv(res_mgt, info);

	kfree(info);
alloc_info_fail:
	kfree(param);
alloc_param_fail:
	return ret;
}

static void nbl_res_adminq_get_rdma_cap_num(void *priv, u16 *cap_num, u16 *my_cap_num)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_resource_info *res_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	u16 rdma_cap_num = 0;
	u16 rdma_my_cap_num = 0;
	int i;
	int ret;
	int pf_id, vf_id;

	for (i = 0; i < NBL_MAX_PF; i++) {
		if (!test_bit(i, res_info->rdma_info.func_cap))
			continue;

		rdma_cap_num++;
		if (i == NBL_COMMON_TO_MGT_PF(common))
			rdma_my_cap_num++;
	}

	for (i = NBL_MAX_PF; i < NBL_MAX_FUNC; i++) {
		if (!test_bit(i, res_info->rdma_info.func_cap))
			continue;

		rdma_cap_num++;

		ret = nbl_res_func_id_to_pfvfid(res_mgt, i, &pf_id, &vf_id);
		if (!ret)
			rdma_my_cap_num++;
	}

	*cap_num = rdma_cap_num;
	*my_cap_num = rdma_my_cap_num;
}

static int nbl_res_adminq_update_rdma_mem_type(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *res_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(NBL_RES_MGT_TO_COMMON(res_mgt));
	struct nbl_chan_send_info chan_send;
	struct nbl_chan_resource_read_param *param;
	struct nbl_rdma_mem_type_info *info;
	int ret = 0;

	param = kzalloc(sizeof(*param), GFP_KERNEL);
	if (!param) {
		ret = -ENOMEM;
		goto alloc_param_fail;
	}

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		ret = -ENOMEM;
		goto alloc_info_fail;
	}

	param->resid = NBL_ADMINQ_PFA_TLV_RDMA_MEM_TYPE;
	param->offset = 0;
	param->len = sizeof(*info);
	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID, NBL_CHAN_MSG_ADMINQ_RESOURCE_READ,
		      param, sizeof(*param), info, sizeof(*info), 1);

	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x\n",
			ret, NBL_CHAN_MSG_ADMINQ_RESOURCE_READ);
		goto send_fail;
	}

	if (info->mem_type <= NBL_RDMA_MEM_TYPE_MAX)
		res_info->rdma_info.mem_type = info->mem_type;
	else
		res_info->rdma_info.mem_type = NBL_RDMA_MEM_TYPE_MAX;

send_fail:
	kfree(info);
alloc_info_fail:
	kfree(param);
alloc_param_fail:
	return ret;
}

static int nbl_res_adminq_update_internal_cfg(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_resource_info *res_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(NBL_RES_MGT_TO_COMMON(res_mgt));
	struct nbl_chan_send_info chan_send;
	struct nbl_chan_resource_read_param *param;
	struct nbl_internal_cfg_info *info;
	int ret = 0;

	param = kzalloc(sizeof(*param), GFP_KERNEL);
	if (!param) {
		ret = -ENOMEM;
		goto alloc_param_fail;
	}

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		ret = -ENOMEM;
		goto alloc_info_fail;
	}

	param->resid = NBL_ADMINQ_PFA_TLV_INTERNAL_CFG;
	param->offset = 0;
	param->len = sizeof(*info);
	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID, NBL_CHAN_MSG_ADMINQ_RESOURCE_READ,
		      param, sizeof(*param), info, sizeof(*info), 1);

	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_dbg(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x\n",
			ret, NBL_CHAN_MSG_ADMINQ_RESOURCE_READ);
		goto send_fail;
	}

	res_info->internal_cfg = info->cfg;

send_fail:
	kfree(info);
alloc_info_fail:
	kfree(param);
alloc_param_fail:
	return ret;
}

static int nbl_res_adminq_restore_default_cfg(void *priv, u8 eth_id)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_chan_send_info chan_send;
	struct nbl_port_key *param;
	int param_len = 0;
	u64 data = 0;
	u64 key = 0;
	int ret;

	key = NBL_PORT_KEY_RESTORE_DEFAULTE_CFG;
	data = (key << NBL_PORT_KEY_KEY_SHIFT);
	param_len = sizeof(struct nbl_port_key) + 1 * sizeof(u64);
	param = kzalloc(param_len, GFP_KERNEL);
	param->id = eth_id;
	param->subop = NBL_PORT_SUBOP_WRITE;
	param->data[0] = data;

	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
		      NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
		      param, param_len, NULL, 0, 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err(dev, "ctrl eth %d restore defaulte cfg failed ret %d\n",
			eth_info->logic_eth_id[eth_id], ret);
		kfree(param);
		return ret;
	}

	kfree(param);
	return 0;
}

static int nbl_res_adminq_nway_reset(void *priv, u8 eth_id)
{
	return nbl_res_adminq_restore_default_cfg(priv, eth_id);
}

static int nbl_res_adminq_init_port(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	u8 eth_id;

	for_each_set_bit(eth_id, eth_info->eth_bitmap, NBL_MAX_ETHERNET)
		nbl_res_adminq_restore_default_cfg(priv, eth_id);

	return 0;
}

static int nbl_res_adminq_set_wol(void *priv, u8 eth_id, bool enable)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(NBL_RES_MGT_TO_COMMON(res_mgt));
	struct nbl_chan_send_info chan_send;
	struct nbl_chan_adminq_reg_write_param reg_write = {0};
	struct nbl_chan_adminq_reg_read_param reg_read = {0};
	u32 value;
	int ret = 0;

	dev_info(dev, "set_wol ethid %d %sabled", eth_id, enable ? "en" : "dis");

	reg_read.reg = adminq_mgt->wol_reg_offset;
	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID, NBL_CHAN_MSG_ADMINQ_REGISTER_READ,
		      &reg_read, sizeof(reg_read), &value, sizeof(value), 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err(dev, "adminq send msg failed with ret: %d\n", ret);
		return ret;
	}

	reg_write.reg = adminq_mgt->wol_reg_offset;
	reg_write.value = (value & ~(1 << eth_id)) | (enable << eth_id);
	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID, NBL_CHAN_MSG_ADMINQ_REGISTER_WRITE,
		      &reg_write, sizeof(reg_write), NULL, 0, 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret)
		dev_err(dev, "adminq send msg failed with ret: %d\n", ret);

	return ret;
}

#define ADD_ETH_STATISTICS(name)  {#name}
static struct nbl_eth_stats_info _eth_statistics[] = {
	ADD_ETH_STATISTICS(eth_frames_tx),
	ADD_ETH_STATISTICS(eth_frames_tx_ok),
	ADD_ETH_STATISTICS(eth_frames_tx_badfcs),
	ADD_ETH_STATISTICS(eth_unicast_frames_tx_ok),
	ADD_ETH_STATISTICS(eth_multicast_frames_tx_ok),
	ADD_ETH_STATISTICS(eth_broadcast_frames_tx_ok),
	ADD_ETH_STATISTICS(eth_macctrl_frames_tx_ok),
	ADD_ETH_STATISTICS(eth_fragment_frames_tx),
	ADD_ETH_STATISTICS(eth_fragment_frames_tx_ok),
	ADD_ETH_STATISTICS(eth_pause_frames_tx),
	ADD_ETH_STATISTICS(eth_pause_macctrl_frames_tx),
	ADD_ETH_STATISTICS(eth_pfc_frames_tx),
	ADD_ETH_STATISTICS(eth_pfc_frames_tx_prio0),
	ADD_ETH_STATISTICS(eth_pfc_frames_tx_prio1),
	ADD_ETH_STATISTICS(eth_pfc_frames_tx_prio2),
	ADD_ETH_STATISTICS(eth_pfc_frames_tx_prio3),
	ADD_ETH_STATISTICS(eth_pfc_frames_tx_prio4),
	ADD_ETH_STATISTICS(eth_pfc_frames_tx_prio5),
	ADD_ETH_STATISTICS(eth_pfc_frames_tx_prio6),
	ADD_ETH_STATISTICS(eth_pfc_frames_tx_prio7),
	ADD_ETH_STATISTICS(eth_verify_frames_tx),
	ADD_ETH_STATISTICS(eth_respond_frames_tx),
	ADD_ETH_STATISTICS(eth_frames_tx_64B),
	ADD_ETH_STATISTICS(eth_frames_tx_65_to_127B),
	ADD_ETH_STATISTICS(eth_frames_tx_128_to_255B),
	ADD_ETH_STATISTICS(eth_frames_tx_256_to_511B),
	ADD_ETH_STATISTICS(eth_frames_tx_512_to_1023B),
	ADD_ETH_STATISTICS(eth_frames_tx_1024_to_1535B),
	ADD_ETH_STATISTICS(eth_frames_tx_1536_to_2047B),
	ADD_ETH_STATISTICS(eth_frames_tx_2048_to_MAXB),
	ADD_ETH_STATISTICS(eth_undersize_frames_tx_goodfcs),
	ADD_ETH_STATISTICS(eth_oversize_frames_tx_goodfcs),
	ADD_ETH_STATISTICS(eth_undersize_frames_tx_badfcs),
	ADD_ETH_STATISTICS(eth_oversize_frames_tx_badfcs),
	ADD_ETH_STATISTICS(eth_octets_tx),
	ADD_ETH_STATISTICS(eth_octets_tx_ok),
	ADD_ETH_STATISTICS(eth_octets_tx_badfcs),
	ADD_ETH_STATISTICS(eth_frames_rx),
	ADD_ETH_STATISTICS(eth_frames_rx_ok),
	ADD_ETH_STATISTICS(eth_frames_rx_badfcs),
	ADD_ETH_STATISTICS(eth_undersize_frames_rx_goodfcs),
	ADD_ETH_STATISTICS(eth_undersize_frames_rx_badfcs),
	ADD_ETH_STATISTICS(eth_oversize_frames_rx_goodfcs),
	ADD_ETH_STATISTICS(eth_oversize_frames_rx_badfcs),
	ADD_ETH_STATISTICS(eth_frames_rx_misc_error),
	ADD_ETH_STATISTICS(eth_frames_rx_misc_dropped),
	ADD_ETH_STATISTICS(eth_unicast_frames_rx_ok),
	ADD_ETH_STATISTICS(eth_multicast_frames_rx_ok),
	ADD_ETH_STATISTICS(eth_broadcast_frames_rx_ok),
	ADD_ETH_STATISTICS(eth_pause_frames_rx),
	ADD_ETH_STATISTICS(eth_pfc_frames_rx),
	ADD_ETH_STATISTICS(eth_pfc_frames_rx_prio0),
	ADD_ETH_STATISTICS(eth_pfc_frames_rx_prio1),
	ADD_ETH_STATISTICS(eth_pfc_frames_rx_prio2),
	ADD_ETH_STATISTICS(eth_pfc_frames_rx_prio3),
	ADD_ETH_STATISTICS(eth_pfc_frames_rx_prio4),
	ADD_ETH_STATISTICS(eth_pfc_frames_rx_prio5),
	ADD_ETH_STATISTICS(eth_pfc_frames_rx_prio6),
	ADD_ETH_STATISTICS(eth_pfc_frames_rx_prio7),
	ADD_ETH_STATISTICS(eth_macctrl_frames_rx),
	ADD_ETH_STATISTICS(eth_verify_frames_rx_ok),
	ADD_ETH_STATISTICS(eth_respond_frames_rx_ok),
	ADD_ETH_STATISTICS(eth_fragment_frames_rx_ok),
	ADD_ETH_STATISTICS(eth_fragment_rx_smdc_nocontext),
	ADD_ETH_STATISTICS(eth_fragment_rx_smds_seq_error),
	ADD_ETH_STATISTICS(eth_fragment_rx_smdc_seq_error),
	ADD_ETH_STATISTICS(eth_fragment_rx_frag_cnt_error),
	ADD_ETH_STATISTICS(eth_frames_assembled_ok),
	ADD_ETH_STATISTICS(eth_frames_assembled_error),
	ADD_ETH_STATISTICS(eth_frames_rx_64B),
	ADD_ETH_STATISTICS(eth_frames_rx_65_to_127B),
	ADD_ETH_STATISTICS(eth_frames_rx_128_to_255B),
	ADD_ETH_STATISTICS(eth_frames_rx_256_to_511B),
	ADD_ETH_STATISTICS(eth_frames_rx_512_to_1023B),
	ADD_ETH_STATISTICS(eth_frames_rx_1024_to_1518B),
	ADD_ETH_STATISTICS(eth_frames_rx_1519_to_2047B),
	ADD_ETH_STATISTICS(eth_frames_rx_2048_to_MAXB),
	ADD_ETH_STATISTICS(eth_octets_rx),
	ADD_ETH_STATISTICS(eth_octets_rx_ok),
	ADD_ETH_STATISTICS(eth_octets_rx_badfcs),
	ADD_ETH_STATISTICS(eth_octets_rx_dropped),
	ADD_ETH_STATISTICS(eth_unsupported_opcodes_rx),
};

static struct nbl_eth_stats_info _eth_statistics_draco[] = {
	ADD_ETH_STATISTICS(eth_rx_prio0_packets),
	ADD_ETH_STATISTICS(eth_rx_prio0_bytes),
	ADD_ETH_STATISTICS(eth_rx_prio0_drop_packets),
	ADD_ETH_STATISTICS(eth_tx_prio0_packets),
	ADD_ETH_STATISTICS(eth_tx_prio0_bytes),
	ADD_ETH_STATISTICS(eth_tx_prio0_drop_packets),
	ADD_ETH_STATISTICS(eth_rx_prio1_packets),
	ADD_ETH_STATISTICS(eth_rx_prio1_bytes),
	ADD_ETH_STATISTICS(eth_rx_prio1_drop_packets),
	ADD_ETH_STATISTICS(eth_tx_prio1_packets),
	ADD_ETH_STATISTICS(eth_tx_prio1_bytes),
	ADD_ETH_STATISTICS(eth_tx_prio1_drop_packets),
	ADD_ETH_STATISTICS(eth_rx_prio2_packets),
	ADD_ETH_STATISTICS(eth_rx_prio2_bytes),
	ADD_ETH_STATISTICS(eth_rx_prio2_drop_packets),
	ADD_ETH_STATISTICS(eth_tx_prio2_packets),
	ADD_ETH_STATISTICS(eth_tx_prio2_bytes),
	ADD_ETH_STATISTICS(eth_tx_prio2_drop_packets),
	ADD_ETH_STATISTICS(eth_rx_prio3_packets),
	ADD_ETH_STATISTICS(eth_rx_prio3_bytes),
	ADD_ETH_STATISTICS(eth_rx_prio3_drop_packets),
	ADD_ETH_STATISTICS(eth_tx_prio3_packets),
	ADD_ETH_STATISTICS(eth_tx_prio3_bytes),
	ADD_ETH_STATISTICS(eth_tx_prio3_drop_packets),
	ADD_ETH_STATISTICS(eth_rx_prio4_packets),
	ADD_ETH_STATISTICS(eth_rx_prio4_bytes),
	ADD_ETH_STATISTICS(eth_rx_prio4_drop_packets),
	ADD_ETH_STATISTICS(eth_tx_prio4_packets),
	ADD_ETH_STATISTICS(eth_tx_prio4_bytes),
	ADD_ETH_STATISTICS(eth_tx_prio4_drop_packets),
	ADD_ETH_STATISTICS(eth_rx_prio5_packets),
	ADD_ETH_STATISTICS(eth_rx_prio5_bytes),
	ADD_ETH_STATISTICS(eth_rx_prio5_drop_packets),
	ADD_ETH_STATISTICS(eth_tx_prio5_packets),
	ADD_ETH_STATISTICS(eth_tx_prio5_bytes),
	ADD_ETH_STATISTICS(eth_tx_prio5_drop_packets),
	ADD_ETH_STATISTICS(eth_rx_prio6_packets),
	ADD_ETH_STATISTICS(eth_rx_prio6_bytes),
	ADD_ETH_STATISTICS(eth_rx_prio6_drop_packets),
	ADD_ETH_STATISTICS(eth_tx_prio6_packets),
	ADD_ETH_STATISTICS(eth_tx_prio6_bytes),
	ADD_ETH_STATISTICS(eth_tx_prio6_drop_packets),
	ADD_ETH_STATISTICS(eth_rx_prio7_packets),
	ADD_ETH_STATISTICS(eth_rx_prio7_bytes),
	ADD_ETH_STATISTICS(eth_rx_prio7_drop_packets),
	ADD_ETH_STATISTICS(eth_tx_prio7_packets),
	ADD_ETH_STATISTICS(eth_tx_prio7_bytes),
	ADD_ETH_STATISTICS(eth_tx_prio7_drop_packets),
	ADD_ETH_STATISTICS(eth_frames_tx),
	ADD_ETH_STATISTICS(eth_frames_tx_ok),
	ADD_ETH_STATISTICS(eth_unicast_frames_tx),
	ADD_ETH_STATISTICS(eth_multicast_frames_tx),
	ADD_ETH_STATISTICS(eth_multicast_frames_tx_ok),
	ADD_ETH_STATISTICS(eth_broadcast_frames_tx),
	ADD_ETH_STATISTICS(eth_broadcast_frames_tx_ok),
	ADD_ETH_STATISTICS(eth_underflow_error_frames_tx),
	ADD_ETH_STATISTICS(eth_pause_frames_tx),
	ADD_ETH_STATISTICS(eth_vlan_frames_tx),
	ADD_ETH_STATISTICS(eth_frames_tx_64B),
	ADD_ETH_STATISTICS(eth_frames_tx_65_to_127B),
	ADD_ETH_STATISTICS(eth_frames_tx_128_to_255B),
	ADD_ETH_STATISTICS(eth_frames_tx_256_to_511B),
	ADD_ETH_STATISTICS(eth_frames_tx_512_to_1023B),
	ADD_ETH_STATISTICS(eth_frames_tx_1024_to_MAXB),
	ADD_ETH_STATISTICS(eth_octets_tx),
	ADD_ETH_STATISTICS(eth_frames_rx),
	ADD_ETH_STATISTICS(eth_undersize_frames_rx_good),
	ADD_ETH_STATISTICS(eth_oversize_frames_rx_good),
	ADD_ETH_STATISTICS(eth_unicast_frames_rx_ok),
	ADD_ETH_STATISTICS(eth_multicast_frames_rx_ok),
	ADD_ETH_STATISTICS(eth_broadcast_frames_rx_ok),
	ADD_ETH_STATISTICS(eth_crc_error_frames_rx),
	ADD_ETH_STATISTICS(eth_runt_error_frames_rx),
	ADD_ETH_STATISTICS(eth_jabber_error_frames_rx),
	ADD_ETH_STATISTICS(eth_length_error_frames_rx),
	ADD_ETH_STATISTICS(eth_out_of_range_type_frames_rx),
	ADD_ETH_STATISTICS(eth_pause_frames_rx),
	ADD_ETH_STATISTICS(eth_vlan_frames_rx),
	ADD_ETH_STATISTICS(eth_watchdog_error_frames_rx),
	ADD_ETH_STATISTICS(eth_frames_rx_64B),
	ADD_ETH_STATISTICS(eth_frames_rx_65_to_127B),
	ADD_ETH_STATISTICS(eth_frames_rx_128_to_255B),
	ADD_ETH_STATISTICS(eth_frames_rx_256_to_511B),
	ADD_ETH_STATISTICS(eth_frames_rx_512_to_1023B),
	ADD_ETH_STATISTICS(eth_frames_rx_1024_to_MAXB),
	ADD_ETH_STATISTICS(eth_octets_rx),
	ADD_ETH_STATISTICS(eth_octets_rx_ok),
};

static void nbl_res_adminq_get_private_stat_len(void *priv, u32 *len)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);

	*len = adminq_mgt->eth_stats_array_size;
}

static void nbl_res_adminq_get_private_stat_data(void *priv, u32 eth_id, u64 *data, u32 data_len)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_chan_send_info chan_send;
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	int ret = 0;
	int idx = 0;

	mutex_lock(&eth_info->eth_lock);
	NBL_OPS_CALL(phy_ops->get_prio_stat_data,
		     (NBL_RES_MGT_TO_PHY_PRIV(res_mgt), eth_id, data, &idx));

	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
		      NBL_CHAN_MSG_ADMINQ_GET_ETH_STATS,
		      &eth_id, sizeof(eth_id), data + idx, data_len - idx, 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret)
		dev_err(dev, "adminq get eth %d private stats failed ret: %d\n",
			eth_info->logic_eth_id[eth_id], ret);
	mutex_unlock(&eth_info->eth_lock);
}

static void nbl_res_adminq_fill_private_stat_strings(void *priv, u8 *strings)
{
	int i;
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);

	for (i = 0; i < adminq_mgt->eth_stats_array_size; i++) {
		snprintf(strings, ETH_GSTRING_LEN, "%s", adminq_mgt->eth_stats_info[i].descp);
		strings += ETH_GSTRING_LEN;
	}
}

static int nbl_res_adminq_get_eth_ctrl_stats(void *priv, u32 *eth_id,
					     struct nbl_eth_ctrl_stats *output)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_chan_send_info chan_send;
	u64 *eth_stats = NULL;
	u32 data_length = adminq_mgt->eth_stats_struct_size;
	u16 *offset = adminq_mgt->eth_stats_offset;
	int ret = 0;

	eth_stats = kzalloc(data_length, GFP_KERNEL);
	if (!eth_stats)
		return -ENOMEM;

	mutex_lock(&eth_info->eth_lock);
	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
		      NBL_CHAN_MSG_ADMINQ_GET_ETH_STATS,
		      eth_id, sizeof(*eth_id), eth_stats, data_length, 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err(dev, "adminq get eth %d ctrl stats failed ret: %d\n",
			eth_info->logic_eth_id[*eth_id], ret);
		goto exit;
	}

	output->macctrl_frames_txd_ok =
		ETH_STATIS_GET(eth_stats, ETH_STATIS_OFFSET(offset[NBL_MACCTRL_FRAME_TX_OK]),
			       ETH_STATIS_VLD(offset[NBL_MACCTRL_FRAME_TX_OK]));
	output->macctrl_frames_rxd =
		ETH_STATIS_GET(eth_stats, ETH_STATIS_OFFSET(offset[NBL_MACCTRL_FRAME_RX]),
			       ETH_STATIS_VLD(offset[NBL_MACCTRL_FRAME_RX]));
	output->unsupported_opcodes_rx =
		ETH_STATIS_GET(eth_stats, ETH_STATIS_OFFSET(offset[NBL_UNSUPPORTED_OPCODES_RX]),
			       ETH_STATIS_VLD(offset[NBL_UNSUPPORTED_OPCODES_RX]));

exit:
	mutex_unlock(&eth_info->eth_lock);
	kfree(eth_stats);
	return ret;
}

static int nbl_res_adminq_get_pause_stats(void *priv, u32 *eth_id,
					  struct nbl_pause_stats *output)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_chan_send_info chan_send;
	u64 *eth_stats = NULL;
	u32 data_length = adminq_mgt->eth_stats_struct_size;
	u16 *offset = adminq_mgt->eth_stats_offset;
	int ret = 0;

	eth_stats = kzalloc(data_length, GFP_KERNEL);
	if (!eth_stats)
		return -ENOMEM;

	mutex_lock(&eth_info->eth_lock);
	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
		      NBL_CHAN_MSG_ADMINQ_GET_ETH_STATS,
		      eth_id, sizeof(*eth_id), (void *)eth_stats, data_length, 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err(dev, "adminq get eth %d pause stats failed ret: %d\n",
			eth_info->logic_eth_id[*eth_id], ret);
		goto exit;
	}

	output->rx_pause_frames =
		ETH_STATIS_GET(eth_stats, ETH_STATIS_OFFSET(offset[NBL_PAUSE_FRAME_RX]),
			       ETH_STATIS_VLD(offset[NBL_PAUSE_FRAME_RX]));
	output->tx_pause_frames =
		ETH_STATIS_GET(eth_stats, ETH_STATIS_OFFSET(offset[NBL_PAUSE_FRAME_TX]),
			       ETH_STATIS_VLD(offset[NBL_PAUSE_FRAME_TX]));

exit:
	mutex_unlock(&eth_info->eth_lock);
	kfree(eth_stats);
	return ret;
}

static int nbl_res_adminq_get_eth_abnormal_stats(void *priv, u8 *eth_id,
						 struct nbl_eth_abnormal_stats *output)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_chan_send_info chan_send;
	u64 *eth_stats = NULL;
	u32 data_length = adminq_mgt->eth_stats_struct_size;
	u32 eth_id_val = *eth_id;
	u16 *offset = adminq_mgt->eth_stats_offset;
	int ret = 0;

	eth_stats = kzalloc(data_length, GFP_KERNEL);
	if (!eth_stats)
		return -ENOMEM;

	mutex_lock(&eth_info->eth_lock);
	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
		      NBL_CHAN_MSG_ADMINQ_GET_ETH_STATS,
		      &eth_id_val, sizeof(eth_id_val), (u64 *)eth_stats, data_length, 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err_once(dev, "adminq get eth %d abnormal stats failed ret: %d\n",
			     eth_info->logic_eth_id[*eth_id], ret);
		mutex_unlock(&eth_info->eth_lock);
		kfree(eth_stats);
		return ret;
	}

	output->rx_crc_errors =
		ETH_STATIS_GET(eth_stats, ETH_STATIS_OFFSET(offset[NBL_FRAME_RX_BADFCS]),
			       ETH_STATIS_VLD(offset[NBL_FRAME_RX_BADFCS]));
	output->rx_frame_errors =
		ETH_STATIS_GET(eth_stats, ETH_STATIS_OFFSET(offset[NBL_FRAME_RX]),
			       ETH_STATIS_VLD(offset[NBL_FRAME_RX])) -
		ETH_STATIS_GET(eth_stats, ETH_STATIS_OFFSET(offset[NBL_FRAME_RX_OK]),
			       ETH_STATIS_VLD(offset[NBL_FRAME_RX_OK]));
	output->rx_length_errors =
		ETH_STATIS_GET(eth_stats,
			       ETH_STATIS_OFFSET(offset[NBL_UNDERSIZE_FRAME_RX_GOODFAS]),
			       ETH_STATIS_VLD(offset[NBL_UNDERSIZE_FRAME_RX_GOODFAS])) +
		ETH_STATIS_GET(eth_stats,
			       ETH_STATIS_OFFSET(offset[NBL_OVERSIZE_FRAME_RX_GOODFAS]),
			       ETH_STATIS_VLD(offset[NBL_OVERSIZE_FRAME_RX_GOODFAS]));

	mutex_unlock(&eth_info->eth_lock);
	kfree(eth_stats);
	return 0;
}

static u32 nbl_convert_temp_type_eeprom_offset(enum nbl_hwmon_type type)
{
	switch (type) {
	case NBL_HWMON_TEMP_INPUT:
		return SFF_8636_TEMP;
	case NBL_HWMON_TEMP_MAX:
		return SFF_8636_TEMP_MAX;
	case NBL_HWMON_TEMP_CRIT:
		return SFF_8636_TEMP_CIRT;
	default:
		return SFF_8636_TEMP;
	}
}

static u32 nbl_convert_temp_type_qsfp28_eeprom_offset(enum nbl_hwmon_type type)
{
	switch (type) {
	case NBL_HWMON_TEMP_INPUT:
		return SFF_8636_QSFP28_TEMP;
	case NBL_HWMON_TEMP_MAX:
		return SFF_8636_QSFP28_TEMP_MAX;
	case NBL_HWMON_TEMP_CRIT:
		return SFF_8636_QSFP28_TEMP_CIRT;
	default:
		return SFF_8636_QSFP28_TEMP;
	}
}

/* return value need to convert to Mil degree Celsius(1/1000) */
static int nbl_res_adminq_get_module_temp_common(void *priv, u8 eth_id,
						 enum nbl_hwmon_type type)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct ethtool_modinfo info = {0};
	u32 offset;
	int temp = 0;
	int ret = 0;

	ret = nbl_res_adminq_get_module_info(res_mgt, eth_id, &info);
	if (ret) {
		dev_err(dev, "get_module_info eth id %d ret: %d\n",
			eth_info->logic_eth_id[eth_id], ret);
		return 0;
	}

	if (info.eeprom_len <= ETH_MODULE_SFF_8079_LEN)
		return 0;

	offset = nbl_convert_temp_type_eeprom_offset(type);

	ret = nbl_res_adminq_get_module_eeprom_info(res_mgt, eth_id, I2C_DEV_ADDR_A2,
						    0, 0, offset, 1, (u8 *)&temp);
	if (ret) {
		dev_err(dev, "eth %d get_module_eeprom_info failed %d\n",
			eth_info->logic_eth_id[eth_id], ret);
		return 0;
	}

	return temp * 1000;
}

static int nbl_res_adminq_get_eth_mac_stats(void *priv, u32 *eth_id,
					    struct nbl_eth_mac_stats *output)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_chan_send_info chan_send;
	u32 data_length = adminq_mgt->eth_stats_struct_size;
	u64 *eth_stats = NULL;
	u16 *offset = adminq_mgt->eth_stats_offset;
	int ret = 0;

	eth_stats = kzalloc(data_length, GFP_KERNEL);
	if (!eth_stats)
		return -ENOMEM;

	mutex_lock(&eth_info->eth_lock);
	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
		      NBL_CHAN_MSG_ADMINQ_GET_ETH_STATS,
		      eth_id, sizeof(*eth_id), (void *)eth_stats, data_length, 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err(dev, "adminq get eth %d mac stats failed ret: %d\n",
			eth_info->logic_eth_id[*eth_id], ret);
		goto exit;
	}

	output->frames_txd_ok =
		ETH_STATIS_GET(eth_stats, ETH_STATIS_OFFSET(offset[NBL_FRAME_TX_OK]),
			       ETH_STATIS_VLD(offset[NBL_FRAME_TX_OK]));
	if (ETH_STATIS_VLD(offset[NBL_FRAME_RX_OK])) {
		output->frames_rxd_ok =
			ETH_STATIS_GET(eth_stats, ETH_STATIS_OFFSET(offset[NBL_FRAME_RX_OK]),
				       ETH_STATIS_VLD(offset[NBL_FRAME_RX_OK]));
	} else {
		output->frames_rxd_ok =
			ETH_STATIS_GET(eth_stats, ETH_STATIS_OFFSET(offset[NBL_UNI_FRAME_RXD_OK]),
				       ETH_STATIS_VLD(offset[NBL_UNI_FRAME_RXD_OK])) +
			ETH_STATIS_GET(eth_stats, ETH_STATIS_OFFSET(offset[NBL_MUL_FRAME_RXD_OK]),
				       ETH_STATIS_VLD(offset[NBL_MUL_FRAME_RXD_OK])) +
			ETH_STATIS_GET(eth_stats, ETH_STATIS_OFFSET(offset[NBL_BROAD_FRAME_RXD_OK]),
				       ETH_STATIS_VLD(offset[NBL_BROAD_FRAME_RXD_OK]));
	}
	output->octets_txd_ok =
		ETH_STATIS_GET(eth_stats, ETH_STATIS_OFFSET(offset[NBL_OCTETS_TX_OK]),
			       ETH_STATIS_VLD(offset[NBL_OCTETS_TX_OK]));
	output->octets_rxd_ok =
		ETH_STATIS_GET(eth_stats, ETH_STATIS_OFFSET(offset[NBL_OCTETS_RX_OK]),
			       ETH_STATIS_VLD(offset[NBL_OCTETS_RX_OK]));
	output->multicast_frames_txd_ok =
		ETH_STATIS_GET(eth_stats, ETH_STATIS_OFFSET(offset[NBL_MUL_FRAME_TXD_OK]),
			       ETH_STATIS_VLD(offset[NBL_MUL_FRAME_TXD_OK]));
	output->broadcast_frames_txd_ok =
		ETH_STATIS_GET(eth_stats, ETH_STATIS_OFFSET(offset[NBL_BROAD_FRAME_TXD_OK]),
			       ETH_STATIS_VLD(offset[NBL_BROAD_FRAME_TXD_OK]));
	output->multicast_frames_rxd_ok =
		ETH_STATIS_GET(eth_stats, ETH_STATIS_OFFSET(offset[NBL_MUL_FRAME_RXD_OK]),
			       ETH_STATIS_VLD(offset[NBL_MUL_FRAME_RXD_OK]));
	output->broadcast_frames_rxd_ok =
		ETH_STATIS_GET(eth_stats, ETH_STATIS_OFFSET(offset[NBL_BROAD_FRAME_RXD_OK]),
			       ETH_STATIS_VLD(offset[NBL_BROAD_FRAME_RXD_OK]));

	if (ETH_STATIS_VLD(offset[NBL_FRAME_RX_OK]) ||
	    (ETH_STATIS_VLD(offset[NBL_UNI_FRAME_RXD_OK]) &&
	     ETH_STATIS_VLD(offset[NBL_MUL_FRAME_RXD_OK]) &&
	     ETH_STATIS_VLD(offset[NBL_BROAD_FRAME_RXD_OK])))
		output->frames_rxd_ok_is_valid = 1;
	if (ETH_STATIS_VLD(offset[NBL_OCTETS_TX_OK]))
		output->octets_txd_ok_is_valid = 1;
	if (ETH_STATIS_VLD(offset[NBL_OCTETS_RX_OK]))
		output->octets_rxd_ok_is_valid = 1;

exit:
	mutex_unlock(&eth_info->eth_lock);
	kfree(eth_stats);
	return ret;
}

static int nbl_res_adminq_get_rmon_stats(void *priv, u32 *eth_id,
					 struct nbl_rmon_stats *output)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_chan_send_info chan_send;
	u64 *eth_stats = NULL;
	u32 data_length = adminq_mgt->eth_stats_struct_size;
	u16 *offset = adminq_mgt->eth_stats_offset;
	u64 *rx = output->rmon_rx_range;
	u64 *tx = output->rmon_tx_range;
	u8 i = 0;
	u8 j = 0;
	u8 eth_stats_pkts_max = 0;
	int ret = 0;

	eth_stats = kzalloc(data_length, GFP_KERNEL);
	if (!eth_stats)
		return -ENOMEM;

	mutex_lock(&eth_info->eth_lock);
	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
		      NBL_CHAN_MSG_ADMINQ_GET_ETH_STATS,
		      eth_id, sizeof(*eth_id), (void *)eth_stats, data_length, 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err(dev, "adminq get eth %d rmon stats failed ret: %d\n",
			eth_info->logic_eth_id[*eth_id], ret);
		goto exit;
	}

	output->undersize_frames_rxd_goodfcs =
		ETH_STATIS_GET(eth_stats,
			       ETH_STATIS_OFFSET(offset[NBL_UNDERSIZE_FRAME_RX_GOODFAS]),
			       ETH_STATIS_VLD(offset[NBL_UNDERSIZE_FRAME_RX_GOODFAS]));
	output->oversize_frames_rxd_goodfcs =
		ETH_STATIS_GET(eth_stats,
			       ETH_STATIS_OFFSET(offset[NBL_OVERSIZE_FRAME_RX_GOODFAS]),
			       ETH_STATIS_VLD(offset[NBL_OVERSIZE_FRAME_RX_GOODFAS]));
	output->undersize_frames_rxd_badfcs =
		ETH_STATIS_GET(eth_stats,
			       ETH_STATIS_OFFSET(offset[NBL_UNDERSIZE_FRAME_RX_BADFAS]),
			       ETH_STATIS_VLD(offset[NBL_UNDERSIZE_FRAME_RX_BADFAS]));
	output->oversize_frames_rxd_badfcs =
		ETH_STATIS_GET(eth_stats,
			       ETH_STATIS_OFFSET(offset[NBL_OVERSIZE_FRAME_RX_BADFAS]),
			       ETH_STATIS_VLD(offset[NBL_OVERSIZE_FRAME_RX_BADFAS]));

	if (ETH_STATIS_VLD(offset[NBL_FRAME_RX_sizerange6]) &&
	    ETH_STATIS_VLD(offset[NBL_FRAME_TX_sizerange6]) &&
	    ETH_STATIS_VLD(offset[NBL_FRAME_RX_sizerange7]) &&
	    ETH_STATIS_VLD(offset[NBL_FRAME_TX_sizerange7])) {
		eth_stats_pkts_max = ETHER_STATS_PKTS_2048_TO_MAX_OCTETS;
		output->rmon_rx_range2048_is_valid = 1;
	} else {
		eth_stats_pkts_max = ETHER_STATS_PKTS_1024_TO_MAX_OCTETS;
	}

	for (i = ETHER_STATS_PKTS_64_OCTETS, j = NBL_FRAME_RX_sizerange0;
	     i <= eth_stats_pkts_max; i++, j++) {
		rx[i] = ETH_STATIS_GET(eth_stats, ETH_STATIS_OFFSET(offset[j]),
				       ETH_STATIS_VLD(offset[j]));
	}

	for (i = ETHER_STATS_PKTS_64_OCTETS, j = NBL_FRAME_TX_sizerange0;
	     i <= eth_stats_pkts_max; i++, j++) {
		tx[i] = ETH_STATIS_GET(eth_stats, ETH_STATIS_OFFSET(offset[j]),
				       ETH_STATIS_VLD(offset[j]));
	}

exit:
	mutex_unlock(&eth_info->eth_lock);
	kfree(eth_stats);
	return ret;
}

static const struct ethtool_rmon_hist_range rmon_ranges_leonis[] = {
	{    0,    64},
	{   65,   127},
	{  128,   255},
	{  256,   511},
	{  512,  1023},
	{ 1024,  1518},
	{ 1519,  2047},
	{ 2048, 65535},
	{},
};

static const struct ethtool_rmon_hist_range rmon_ranges_draco[] = {
	{    0,    64},
	{   65,   127},
	{  128,   255},
	{  256,   511},
	{  512,  1023},
	{ 1024,  65535},
	{},
};

static void nbl_res_adminq_get_rmon_hist_range(void *priv,
					       const struct ethtool_rmon_hist_range **range)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);

	*range = adminq_mgt->rmon_ranges;
}

/* return value need to convert to Mil degree Celsius(1/1000) */
static int nbl_res_adminq_get_module_temp_special(struct nbl_resource_mgt *res_mgt, u8 eth_id,
						  enum nbl_hwmon_type type)
{
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	u32 addr;
	u8 offset, turn_page;
	int temp = 0;
	int ret = 0;

	addr = nbl_convert_temp_type_qsfp28_eeprom_offset(type);

	nbl_res_get_module_eeprom_page(addr, &turn_page, &offset);

	ret = nbl_res_adminq_turn_module_eeprom_page(res_mgt, eth_id, turn_page);
	if (ret) {
		dev_err(dev, "eth %d get_module_eeprom_info failed %d\n",
			eth_info->logic_eth_id[eth_id], ret);
		return 0;
	}

	ret = nbl_res_adminq_get_module_eeprom_info(res_mgt, eth_id, I2C_DEV_ADDR_A0,
						    0, 0, offset, 1, (u8 *)&temp);
	if (ret) {
		dev_err(dev, "eth %d get_module_eeprom_info failed %d\n",
			eth_info->logic_eth_id[eth_id], ret);
		return 0;
	}

	return temp * 1000;
}

static int nbl_res_adminq_get_module_temperature(void *priv, struct nbl_ch_prm_get_hwmon *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);

	if (!eth_info->module_inplace[param->senser_id])
		return 0;

	if (res_mgt->resource_info->board_info.eth_speed == NBL_FW_PORT_SPEED_100G)
		return nbl_res_adminq_get_module_temp_special(res_mgt,
			param->senser_id, param->type);
	else
		return nbl_res_adminq_get_module_temp_common(res_mgt,
			param->senser_id, param->type);
}

static __maybe_unused int nbl_res_adminq_load_p4(void *priv, struct nbl_load_p4_param *p4_param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_chan_send_info chan_send;
	struct nbl_chan_param_load_p4 *param;
	int ret = 0;

	param = kzalloc(sizeof(*param) + p4_param->size, GFP_KERNEL);
	if (!param)
		return -ENOMEM;

	param->addr = p4_param->addr;
	param->size = p4_param->size;
	param->section_index = p4_param->section_index;
	param->section_offset = p4_param->section_offset;
	param->load_start = p4_param->start;
	param->load_end = p4_param->end;
	strscpy(param->name, p4_param->name, sizeof(param->name));
	memcpy(param->data, p4_param->data, p4_param->size);

	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID, NBL_CHAN_MSG_ADMINQ_LOAD_P4,
		      param, sizeof(*param) + p4_param->size, NULL, 0, 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret)
		dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x\n",
			ret, NBL_CHAN_MSG_ADMINQ_LOAD_P4);

	kfree(param);
	return ret;
}

static void nbl_res_adminq_cfg_eth_bond_event(void *priv, bool enable)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_event_callback event_callback = {0};

	event_callback.callback_data = res_mgt;
	event_callback.callback = nbl_res_adminq_handle_link_state_update;

	if (enable)
		nbl_event_register(NBL_EVENT_LINK_STATE_UPDATE, &event_callback,
				   NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));
	else
		nbl_event_unregister(NBL_EVENT_LINK_STATE_UPDATE, &event_callback,
				     NBL_COMMON_TO_VSI_ID(common), NBL_COMMON_TO_BOARD_ID(common));
}

static int nbl_res_get_part_number(void *priv, char *part_number)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(NBL_RES_MGT_TO_COMMON(res_mgt));
	struct nbl_chan_send_info chan_send;
	struct nbl_chan_resource_read_param *param;
	struct nbl_host_board_config *info;
	int ret = 0;

	param = kzalloc(sizeof(*param), GFP_KERNEL);
	if (!param) {
		ret = -ENOMEM;
		goto alloc_param_fail;
	}

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		ret = -ENOMEM;
		goto alloc_info_fail;
	}

	param->resid = NBL_ADMINQ_RESID_FSI_SECTION_HBC;
	param->offset = 0;
	param->len = sizeof(*info);
	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID, NBL_CHAN_MSG_ADMINQ_RESOURCE_READ,
		      param, sizeof(*param), info, sizeof(*info), 1);

	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x, resid: 0x%x\n",
			ret, NBL_CHAN_MSG_ADMINQ_RESOURCE_READ, NBL_ADMINQ_RESID_FSI_SECTION_HBC);
		goto send_fail;
	}

	memcpy(part_number, info->product_name, sizeof(info->product_name));

send_fail:
	kfree(info);
alloc_info_fail:
	kfree(param);
alloc_param_fail:
	return ret;
}

static int nbl_res_get_serial_number(void *priv, char *serial_number)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(NBL_RES_MGT_TO_COMMON(res_mgt));
	struct nbl_chan_send_info chan_send;
	struct nbl_chan_resource_read_param *param;
	struct nbl_serial_number_info *info;
	int ret = 0;

	param = kzalloc(sizeof(*param), GFP_KERNEL);
	if (!param) {
		ret = -ENOMEM;
		goto alloc_param_fail;
	}

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		ret = -ENOMEM;
		goto alloc_info_fail;
	}

	param->resid = NBL_ADMINQ_RESID_FSI_TLV_SERIAL_NUMBER;
	param->offset = 0;
	param->len = sizeof(*info);
	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID, NBL_CHAN_MSG_ADMINQ_RESOURCE_READ,
		      param, sizeof(*param), info, sizeof(*info), 1);

	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x, resid: 0x%x\n",
			ret, NBL_CHAN_MSG_ADMINQ_RESOURCE_READ,
			NBL_ADMINQ_RESID_FSI_TLV_SERIAL_NUMBER);
		goto send_fail;
	}
	memcpy(serial_number, info->sn, info->len);

send_fail:
	kfree(info);
alloc_info_fail:
	kfree(param);
alloc_param_fail:
	return ret;
}

/* NBL_ADMINQ_SET_OPS(ops_name, func)
 *
 * Use X Macros to reduce setup and remove codes.
 */
#define NBL_ADMINQ_OPS_TBL									\
do {												\
	NBL_ADMINQ_SET_OPS(get_firmware_version, nbl_res_adminq_get_firmware_version);		\
	NBL_ADMINQ_SET_OPS(flash_lock, nbl_res_adminq_flash_lock);				\
	NBL_ADMINQ_SET_OPS(flash_unlock, nbl_res_adminq_flash_unlock);				\
	NBL_ADMINQ_SET_OPS(flash_prepare, nbl_res_adminq_flash_prepare);			\
	NBL_ADMINQ_SET_OPS(flash_image, nbl_res_adminq_flash_image);				\
	NBL_ADMINQ_SET_OPS(flash_activate, nbl_res_adminq_flash_activate);			\
	NBL_ADMINQ_SET_OPS(set_sfp_state, nbl_res_adminq_set_sfp_state);			\
	NBL_ADMINQ_SET_OPS(set_eth_loopback, nbl_res_adminq_set_eth_loopback);			\
	NBL_ADMINQ_SET_OPS(check_fw_heartbeat, nbl_res_adminq_check_fw_heartbeat);		\
	NBL_ADMINQ_SET_OPS(check_fw_reset, nbl_res_adminq_check_fw_reset);			\
	NBL_ADMINQ_SET_OPS(get_port_attributes, nbl_res_adminq_get_port_attributes);		\
	NBL_ADMINQ_SET_OPS(update_ring_num, nbl_res_adminq_update_ring_num);			\
	NBL_ADMINQ_SET_OPS(update_rdma_cap, nbl_res_adminq_update_rdma_cap);			\
	NBL_ADMINQ_SET_OPS(update_rdma_mem_type, nbl_res_adminq_update_rdma_mem_type);		\
	NBL_ADMINQ_SET_OPS(update_internal_cfg, nbl_res_adminq_update_internal_cfg);		\
	NBL_ADMINQ_SET_OPS(get_rdma_cap_num, nbl_res_adminq_get_rdma_cap_num);			\
	NBL_ADMINQ_SET_OPS(init_port, nbl_res_adminq_init_port);				\
	NBL_ADMINQ_SET_OPS(enable_port, nbl_res_adminq_enable_port);				\
	NBL_ADMINQ_SET_OPS(recv_port_notify, nbl_res_adminq_recv_port_notify);			\
	NBL_ADMINQ_SET_OPS(set_port_advertising, nbl_res_adminq_set_port_advertising);		\
	NBL_ADMINQ_SET_OPS(get_port_state, nbl_res_adminq_get_port_state);			\
	NBL_ADMINQ_SET_OPS(get_module_info, nbl_res_adminq_get_module_info);			\
	NBL_ADMINQ_SET_OPS(get_module_eeprom, nbl_res_adminq_get_module_eeprom);		\
	NBL_ADMINQ_SET_OPS(get_link_state, nbl_res_adminq_get_link_state);			\
	NBL_ADMINQ_SET_OPS(get_link_down_count, nbl_res_adminq_get_link_down_count);		\
	NBL_ADMINQ_SET_OPS(get_link_status_opcode, nbl_res_adminq_get_link_status_opcode);	\
	NBL_ADMINQ_SET_OPS(set_eth_mac_addr, nbl_res_adminq_set_eth_mac_addr);			\
	NBL_ADMINQ_SET_OPS(get_eth_ctrl_stats, nbl_res_adminq_get_eth_ctrl_stats);		\
	NBL_ADMINQ_SET_OPS(ctrl_port_led, nbl_res_adminq_ctrl_port_led);			\
	NBL_ADMINQ_SET_OPS(set_wol, nbl_res_adminq_set_wol);					\
	NBL_ADMINQ_SET_OPS(nway_reset, nbl_res_adminq_nway_reset);				\
	NBL_ADMINQ_SET_OPS(passthrough_fw_cmd, nbl_res_adminq_passthrough);			\
	NBL_ADMINQ_SET_OPS(get_private_stat_len, nbl_res_adminq_get_private_stat_len);		\
	NBL_ADMINQ_SET_OPS(get_private_stat_data, nbl_res_adminq_get_private_stat_data);	\
	NBL_ADMINQ_SET_OPS(fill_private_stat_strings, nbl_res_adminq_fill_private_stat_strings);\
	NBL_ADMINQ_SET_OPS(get_pause_stats, nbl_res_adminq_get_pause_stats);			\
	NBL_ADMINQ_SET_OPS(get_eth_mac_stats, nbl_res_adminq_get_eth_mac_stats);		\
	NBL_ADMINQ_SET_OPS(get_module_temperature, nbl_res_adminq_get_module_temperature);	\
	NBL_ADMINQ_SET_OPS(cfg_eth_bond_event, nbl_res_adminq_cfg_eth_bond_event);		\
	NBL_ADMINQ_SET_OPS(get_eth_abnormal_stats, nbl_res_adminq_get_eth_abnormal_stats);	\
	NBL_ADMINQ_SET_OPS(get_fec_stats, nbl_res_adminq_get_fec_stats);			\
	NBL_ADMINQ_SET_OPS(get_rmon_stats, nbl_res_adminq_get_rmon_stats);			\
	NBL_ADMINQ_SET_OPS(get_rmon_hist_range, nbl_res_adminq_get_rmon_hist_range);		\
	NBL_ADMINQ_SET_OPS(get_part_number, nbl_res_get_part_number);				\
	NBL_ADMINQ_SET_OPS(get_serial_number, nbl_res_get_serial_number);			\
} while (0)

/* Structure starts here, adding an op should not modify anything below */
static int nbl_adminq_setup_mgt(struct device *dev, struct nbl_adminq_mgt **adminq_mgt)
{
	*adminq_mgt = devm_kzalloc(dev, sizeof(struct nbl_adminq_mgt), GFP_KERNEL);
	if (!*adminq_mgt)
		return -ENOMEM;

	return 0;
}

static void nbl_adminq_remove_mgt(struct device *dev, struct nbl_adminq_mgt **adminq_mgt)
{
	devm_kfree(dev, *adminq_mgt);
	*adminq_mgt = NULL;
}

static int nbl_res_adminq_chan_notify_link_state_req(struct nbl_resource_mgt *res_mgt,
						     u16 fid, u8 link_state, u32 link_speed)
{
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_chan_send_info chan_send;
	struct nbl_chan_param_notify_link_state link_info = {0};

	chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);

	link_info.link_state = link_state;
	link_info.link_speed = link_speed;
	NBL_CHAN_SEND(chan_send, fid, NBL_CHAN_MSG_NOTIFY_LINK_STATE, &link_info,
		      sizeof(link_info), NULL, 0, 0);
	return chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
}

static int nbl_res_adminq_notify_eth_rep_link_req(struct nbl_resource_mgt *res_mgt,
						  u16 fid, u8 eth_id, u8 link_state)
{
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_chan_param_eth_rep_notify_link_state param = {0};
	struct nbl_chan_send_info chan_send;

	chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);

	param.eth_id = eth_id;
	param.link_state = link_state;
	NBL_CHAN_SEND(chan_send, fid, NBL_CHAN_MSG_NOTIFY_ETH_REP_LINK_STATE, &param, sizeof(param),
		      NULL, 0, 0);
	return chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
}

static void nbl_res_adminq_notify_link_state(struct nbl_resource_mgt *res_mgt, u8 eth_id,
					     u8 link_state)
{
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_pmd_status *pmd_status = &res_mgt->pmd_status;
	struct nbl_sriov_info *sriov_info;
	struct nbl_queue_info *queue_info;
	u16 pf_fid = 0, vf_fid = 0, bond_link_state = 0, link_speed = 0;
	int i = 0, j = 0;
	int diff;

	for (i = 0; i < NBL_RES_MGT_TO_PF_NUM(res_mgt); i++) {
		if (eth_info->pf_bitmap[eth_id] & BIT(i))
			pf_fid = nbl_res_pfvfid_to_func_id(res_mgt, i, -1);
		else
			continue;

		diff = nbl_common_pf_id_subtraction_mgtpf_id(common, pf_fid);
		sriov_info = &NBL_RES_MGT_TO_SRIOV_INFO(res_mgt)[diff];
		queue_info = &queue_mgt->queue_info[pf_fid];

		/* send eth's link state to pf */
		if (queue_info->num_txrx_queues)
			nbl_res_adminq_chan_notify_link_state_req(res_mgt,
								  pf_fid,
								  link_state,
								  eth_info->link_speed[eth_id]);

		/* Use bond_link_state for vfs.
		 * If there is no bond, then it will equals to link_state.
		 */
		bond_link_state = nbl_res_adminq_get_bond_link_state(res_mgt, eth_id);

		/* send eth's link state to pf's all vf */
		for (j = 0; j < sriov_info->num_vfs; j++) {
			vf_fid = sriov_info->start_vf_func_id + j;
			queue_info = &queue_mgt->queue_info[vf_fid];
			if (queue_info->num_txrx_queues) {
				link_speed = eth_info->link_speed[eth_id];
				nbl_res_adminq_chan_notify_link_state_req(res_mgt, vf_fid,
									  bond_link_state,
									  link_speed);
			}
		}
	}

	if (pmd_status->upcall_port_info.upcall_port_active) {
		nbl_res_adminq_notify_eth_rep_link_req(res_mgt,
						       pmd_status->upcall_port_info.func_id,
						       eth_id, link_state);
	}
}

static void nbl_res_adminq_eth_task(struct work_struct *work)
{
	struct nbl_adminq_mgt *adminq_mgt = container_of(work, struct nbl_adminq_mgt,
							 eth_task);
	struct nbl_resource_mgt *res_mgt = adminq_mgt->res_mgt;
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	u8 eth_id = 0;
	u8 port_max_rate = 0;
	u8 max_eth_speed;

	for_each_set_bit(eth_id, eth_info->eth_bitmap, NBL_MAX_ETHERNET) {
		if (adminq_mgt->module_inplace_changed[eth_id]) {
			/* module not-inplace, transitions to inplace status */
			/* read module register */
			if (common->port_type == NBL_FW_PORT_RJ45) {
				max_eth_speed = res_mgt->resource_info->board_info.eth_speed;
				port_max_rate = nbl_fw_speed_to_port_speed(max_eth_speed);
				eth_info->port_max_rate[eth_id] = port_max_rate;
				eth_info->port_type[eth_id] = NBL_PORT_TYPE_TP;
			} else {
				port_max_rate = nbl_res_adminq_get_module_bitrate(res_mgt, eth_id);
				if (port_max_rate == NBL_PORT_MAX_RATE_UNKNOWN) {
					max_eth_speed =
						res_mgt->resource_info->board_info.eth_speed;
					port_max_rate = nbl_fw_speed_to_port_speed(max_eth_speed);
				}

				eth_info->port_max_rate[eth_id] = port_max_rate;
				eth_info->port_type[eth_id] =
					nbl_res_adminq_get_port_type(res_mgt, eth_id);
			}
			eth_info->module_repluged[eth_id] = 1;
			/* copper and TP(RJ45) port support auto-negotiation */
			if (eth_info->port_type[eth_id] == NBL_PORT_TYPE_COPPER ||
			    eth_info->port_type[eth_id] == NBL_PORT_TYPE_TP)
				eth_info->port_caps[eth_id] |= BIT(NBL_PORT_CAP_AUTONEG);
			else
				eth_info->port_caps[eth_id] &= ~BIT_MASK(NBL_PORT_CAP_AUTONEG);

			adminq_mgt->module_inplace_changed[eth_id] = 0;
		}

		mutex_lock(&adminq_mgt->eth_lock);
		if (adminq_mgt->link_state_changed[eth_id]) {
			/* eth link state changed, notify pf and vf */
			nbl_res_adminq_notify_link_state(res_mgt, eth_id,
							 eth_info->link_state[eth_id]);
			adminq_mgt->link_state_changed[eth_id] = 0;
		}
		if (adminq_mgt->speed_changed[eth_id]) {
			phy_ops->cfg_eth_shaping(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), eth_id,
					 eth_info->link_speed[eth_id]);
			adminq_mgt->speed_changed[eth_id] = 0;
		}
		mutex_unlock(&adminq_mgt->eth_lock);
	}
}

static int nbl_res_adminq_setup_cmd_filter(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_hash_tbl_key tbl_key = {0};

	NBL_HASH_TBL_KEY_INIT(&tbl_key, NBL_COMMON_TO_DEV(common), sizeof(u16),
			      sizeof(struct nbl_res_fw_cmd_filter),
			      NBL_RES_FW_CMD_FILTER_MAX, false);

	adminq_mgt->cmd_filter = nbl_common_init_hash_table(&tbl_key);
	if (!adminq_mgt->cmd_filter)
		return -EFAULT;

	return 0;
}

static void nbl_res_adminq_remove_cmd_filter(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);

	if (adminq_mgt->cmd_filter)
		nbl_common_remove_hash_table(adminq_mgt->cmd_filter, NULL);

	adminq_mgt->cmd_filter = NULL;
}

static int nbl_adminq_res_comp_event_cb(int event, void *priv_data, void *event_data)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv_data;
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_resource_info *res_info = NBL_RES_MGT_TO_RES_INFO(res_mgt);
	struct nbl_net_ring_num_info *num_info;
	struct nbl_fw_cmd_net_ring_num_param *net_ring_num_param;
	struct nbl_fw_cmd_vf_num_param *vf_num_param;
	size_t copy_len;
	u32 count;

	switch (event) {
	case NBL_DEVCOMM_RES_CFG_QP_NUM_EVENT:
		net_ring_num_param = (struct nbl_fw_cmd_net_ring_num_param *)event_data;
		num_info = &res_info->net_ring_num_info;
		copy_len = min_t(size_t, sizeof(*num_info), sizeof(*net_ring_num_param));
		memcpy(num_info, net_ring_num_param, copy_len);
		nbl_info(common, NBL_DEBUG_ADMINQ,
			 "receive comp qp_num cfg event qp_num:%d-%d, func qp_num:%d-%d\n",
			 net_ring_num_param->pf_def_max_net_qp_num,
			 net_ring_num_param->vf_def_max_net_qp_num,
			 net_ring_num_param->net_max_qp_num[0],
			 net_ring_num_param->net_max_qp_num[519]);
		break;
	case NBL_DEVCOMM_RES_CFG_VF_NUM_EVENT:
		vf_num_param = (struct nbl_fw_cmd_vf_num_param *)event_data;
		count = nbl_res_adminq_sum_vf_num(vf_num_param);
		res_info->max_vf_num = count;
		res_info->max_vf_bypf_num = vf_num_param->vf_max_num[0];
		nbl_info(common, NBL_DEBUG_ADMINQ,
			 "receive comp vf_num cfg event, vf_num:%d-%d-%d-%d\n",
			 vf_num_param->vf_max_num[0], vf_num_param->vf_max_num[1],
			 vf_num_param->vf_max_num[2], vf_num_param->vf_max_num[3]);
		break;
	default:
		break;
	}

	return 0;
}

static int nbl_adminq_register_nblconfig_comp(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_devcomm_match_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.key.val = pci_domain_nr(common->pdev->bus) << 16 | common->pdev->bus->number;
	adminq_mgt->comp_dev = nbl_devcomm_register_component(NBL_DEVCOMM_RES_TMPL,
							      &attr,
							      nbl_adminq_res_comp_event_cb,
							      res_mgt);
	if (!adminq_mgt->comp_dev)
		return -ENOMEM;

	return 0;
}

static void nbl_adminq_unregister_nblconfig_comp(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);

	nbl_devcomm_unregister_component(adminq_mgt->comp_dev);
	adminq_mgt->comp_dev = NULL;
}

int nbl_adminq_mgt_start(struct nbl_resource_mgt *res_mgt, char *firmware_magic, bool is_ctrl)
{
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_res_product_ops *product_ops = NBL_RES_MGT_TO_PROD_OPS(res_mgt);
	struct nbl_adminq_mgt **adminq_mgt = &NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	int ret;

	ret = nbl_adminq_setup_mgt(dev, adminq_mgt);
	if (ret)
		goto setup_mgt_fail;

	NBL_OPS_CALL(product_ops->adminq_mgt_init, (res_mgt));

	if (!is_ctrl)
		return 0;

	(*adminq_mgt)->res_mgt = res_mgt;
	(*adminq_mgt)->fw_last_hb_seq = (u32)phy_ops->get_fw_pong(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
	memcpy((*adminq_mgt)->firmware_magic, firmware_magic,
	       sizeof((*adminq_mgt)->firmware_magic));
	INIT_WORK(&(*adminq_mgt)->eth_task, nbl_res_adminq_eth_task);
	(*adminq_mgt)->eth_task_init = true;
	mutex_init(&(*adminq_mgt)->eth_lock);
	ret = nbl_res_adminq_setup_cmd_filter(res_mgt);
	if (ret)
		goto set_filter_fail;

	nbl_res_adminq_add_cmd_filter_res_write(res_mgt);
	ret = nbl_adminq_register_nblconfig_comp(res_mgt);
	if (ret)
		goto register_res_comp_fail;

	return 0;

register_res_comp_fail:
	nbl_res_adminq_remove_cmd_filter(res_mgt);
set_filter_fail:
	cancel_work_sync(&((*adminq_mgt)->eth_task));
	nbl_adminq_remove_mgt(dev, adminq_mgt);
setup_mgt_fail:
	return ret;
}

void nbl_adminq_mgt_stop(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_adminq_mgt **adminq_mgt = &NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);

	if (!(*adminq_mgt))
		return;

	nbl_res_adminq_remove_cmd_filter(res_mgt);
	nbl_adminq_unregister_nblconfig_comp(res_mgt);

	if ((*adminq_mgt)->eth_task_init)
		cancel_work_sync(&((*adminq_mgt)->eth_task));
	nbl_adminq_remove_mgt(dev, adminq_mgt);
}

int nbl_adminq_setup_ops(struct nbl_resource_ops *res_ops)
{
#define NBL_ADMINQ_SET_OPS(name, func) do {res_ops->NBL_NAME(name) = func; ; } while (0)
	NBL_ADMINQ_OPS_TBL;
#undef  NBL_ADMINQ_SET_OPS

	return 0;
}

static u16 nbl_leonis_eth_statisc_offset[NBL_ETH_STATISC_MAX] = {
	[NBL_MACCTRL_FRAME_TX_OK] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, tx_stats.macctrl_frames_txd_ok), 1),
	[NBL_MACCTRL_FRAME_RX] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, rx_stats.macctrl_frames_rxd), 1),
	[NBL_UNSUPPORTED_OPCODES_RX] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, rx_stats.unsupported_opcodes_rx), 1),
	[NBL_PAUSE_FRAME_TX] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, tx_stats.pause_macctrl_frames_txd), 1),
	[NBL_PAUSE_FRAME_RX] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, rx_stats.pause_macctrl_frames_rxd), 1),
	[NBL_FRAME_RX_BADFCS] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, rx_stats.frames_rxd_badfcs), 1),
	[NBL_FRAME_RX] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, rx_stats.frames_rxd), 1),
	[NBL_FRAME_RX_OK] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, rx_stats.frames_rxd_ok), 1),
	[NBL_UNDERSIZE_FRAME_RX_GOODFAS] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, rx_stats.undersize_frames_rxd_goodfcs), 1),
	[NBL_OVERSIZE_FRAME_RX_GOODFAS] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, rx_stats.oversize_frames_rxd_goodfcs), 1),
	[NBL_OCTETS_RX_OK] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, rx_stats.octets_rxd_ok), 1),
	[NBL_OCTETS_TX_OK] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, tx_stats.octets_txd_ok), 1),
	[NBL_FRAME_TX_OK] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, tx_stats.frames_txd_ok), 1),
	[NBL_MUL_FRAME_TXD_OK] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, tx_stats.multicast_frames_txd_ok), 1),
	[NBL_BROAD_FRAME_TXD_OK] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, tx_stats.broadcast_frames_txd_ok), 1),
	[NBL_MUL_FRAME_RXD_OK] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, rx_stats.multicast_frames_rxd_ok), 1),
	[NBL_BROAD_FRAME_RXD_OK] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, rx_stats.broadcast_frames_rxd_ok), 1),
	[NBL_UNI_FRAME_RXD_OK] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, rx_stats.unicast_frames_rxd_ok), 1),
	[NBL_UNDERSIZE_FRAME_RX_BADFAS] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, rx_stats.undersize_frames_rxd_badfcs), 1),
	[NBL_OVERSIZE_FRAME_RX_BADFAS] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, rx_stats.oversize_frames_rxd_badfcs), 1),
	[NBL_FRAME_RX_sizerange0] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, rx_stats.frames_rxd_sizerange0), 1),
	[NBL_FRAME_RX_sizerange1] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, rx_stats.frames_rxd_sizerange1), 1),
	[NBL_FRAME_RX_sizerange2] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, rx_stats.frames_rxd_sizerange2), 1),
	[NBL_FRAME_RX_sizerange3] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, rx_stats.frames_rxd_sizerange3), 1),
	[NBL_FRAME_RX_sizerange4] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, rx_stats.frames_rxd_sizerange4), 1),
	[NBL_FRAME_RX_sizerange5] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, rx_stats.frames_rxd_sizerange5), 1),
	[NBL_FRAME_RX_sizerange6] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, rx_stats.frames_rxd_sizerange6), 1),
	[NBL_FRAME_RX_sizerange7] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, rx_stats.frames_rxd_sizerange7), 1),
	[NBL_FRAME_TX_sizerange0] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, tx_stats.frames_txd_sizerange0), 1),
	[NBL_FRAME_TX_sizerange1] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, tx_stats.frames_txd_sizerange1), 1),
	[NBL_FRAME_TX_sizerange2] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, tx_stats.frames_txd_sizerange2), 1),
	[NBL_FRAME_TX_sizerange3] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, tx_stats.frames_txd_sizerange3), 1),
	[NBL_FRAME_TX_sizerange4] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, tx_stats.frames_txd_sizerange4), 1),
	[NBL_FRAME_TX_sizerange5] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, tx_stats.frames_txd_sizerange5), 1),
	[NBL_FRAME_TX_sizerange6] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, tx_stats.frames_txd_sizerange6), 1),
	[NBL_FRAME_TX_sizerange7] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_leonis_eth_stats, tx_stats.frames_txd_sizerange7), 1),
};

static u16 nbl_draco_eth_statisc_offset[NBL_ETH_STATISC_MAX] = {
	[NBL_MACCTRL_FRAME_TX_OK] = ETH_STATIS_LOC(0, 0),
	[NBL_MACCTRL_FRAME_RX] = ETH_STATIS_LOC(0, 0),
	[NBL_UNSUPPORTED_OPCODES_RX] = ETH_STATIS_LOC(0, 0),
	[NBL_PAUSE_FRAME_TX] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, tx_stats.pause_frames_txd), 1),
	[NBL_PAUSE_FRAME_RX] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, rx_stats.pause_frames_rxd), 1),
	[NBL_FRAME_RX_BADFCS] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, rx_stats.crc_error_frames_rxd), 1),
	[NBL_FRAME_RX] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, rx_stats.frames_rxd), 0),
	[NBL_FRAME_RX_OK] = ETH_STATIS_LOC(0, 0),
	[NBL_UNDERSIZE_FRAME_RX_GOODFAS] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, rx_stats.undersize_frames_rxd_good), 1),
	[NBL_OVERSIZE_FRAME_RX_GOODFAS] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, rx_stats.oversize_frames_rxd_good), 1),
	[NBL_OCTETS_RX_OK] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, rx_stats.octets_rxd_ok), 0),
	[NBL_OCTETS_TX_OK] = ETH_STATIS_LOC(0, 0),
	[NBL_FRAME_TX_OK] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, tx_stats.frames_txd_ok), 1),
	[NBL_MUL_FRAME_TXD_OK] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, tx_stats.multicast_frames_txd_ok), 1),
	[NBL_BROAD_FRAME_TXD_OK] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, tx_stats.broadcast_frames_txd_ok), 1),
	[NBL_MUL_FRAME_RXD_OK] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, rx_stats.multicast_frames_rxd_ok), 1),
	[NBL_BROAD_FRAME_RXD_OK] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, rx_stats.broadcast_frames_rxd_ok), 1),
	[NBL_UNI_FRAME_RXD_OK] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, rx_stats.unicast_frames_rxd_ok), 1),
	[NBL_UNDERSIZE_FRAME_RX_BADFAS] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, rx_stats.runt_error_frames_rxd), 1),
	[NBL_OVERSIZE_FRAME_RX_BADFAS] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, rx_stats.jabber_error_frames_rxd), 1),
	[NBL_FRAME_RX_sizerange0] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, rx_stats.frames_rxd_sizerange0), 1),
	[NBL_FRAME_RX_sizerange1] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, rx_stats.frames_rxd_sizerange1), 1),
	[NBL_FRAME_RX_sizerange2] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, rx_stats.frames_rxd_sizerange2), 1),
	[NBL_FRAME_RX_sizerange3] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, rx_stats.frames_rxd_sizerange3), 1),
	[NBL_FRAME_RX_sizerange4] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, rx_stats.frames_rxd_sizerange4), 1),
	[NBL_FRAME_RX_sizerange5] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, rx_stats.frames_rxd_sizerange5), 1),
	[NBL_FRAME_RX_sizerange6] = ETH_STATIS_LOC(0, 0),
	[NBL_FRAME_RX_sizerange7] = ETH_STATIS_LOC(0, 0),
	[NBL_FRAME_TX_sizerange0] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, tx_stats.frames_txd_sizerange0), 1),
	[NBL_FRAME_TX_sizerange1] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, tx_stats.frames_txd_sizerange1), 1),
	[NBL_FRAME_TX_sizerange2] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, tx_stats.frames_txd_sizerange2), 1),
	[NBL_FRAME_TX_sizerange3] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, tx_stats.frames_txd_sizerange3), 1),
	[NBL_FRAME_TX_sizerange4] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, tx_stats.frames_txd_sizerange4), 1),
	[NBL_FRAME_TX_sizerange5] = ETH_STATIS_LOC
		(OFFSET_U64(struct nbl_draco_eth_stats, tx_stats.frames_txd_sizerange5), 1),
	[NBL_FRAME_TX_sizerange6] = ETH_STATIS_LOC(0, 0),
	[NBL_FRAME_TX_sizerange7] = ETH_STATIS_LOC(0, 0),
};

void nbl_adminq_mgt_init_leonis(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);

	adminq_mgt->eth_stats_info = _eth_statistics;
	adminq_mgt->eth_stats_array_size = ARRAY_SIZE(_eth_statistics);
	adminq_mgt->eth_stats_offset = nbl_leonis_eth_statisc_offset;
	adminq_mgt->eth_stats_struct_size = sizeof(struct nbl_leonis_eth_stats);
	adminq_mgt->wol_reg_offset = NBL_ADMINQ_ETH_WOL_REG_OFFSET_LEONIS;
	adminq_mgt->rmon_ranges = rmon_ranges_leonis;
}

void nbl_adminq_mgt_init_draco(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);

	adminq_mgt->eth_stats_info = _eth_statistics_draco;
	adminq_mgt->eth_stats_array_size = ARRAY_SIZE(_eth_statistics_draco);
	adminq_mgt->eth_stats_offset = nbl_draco_eth_statisc_offset;
	adminq_mgt->eth_stats_struct_size = sizeof(struct nbl_draco_eth_stats);
	adminq_mgt->wol_reg_offset = NBL_ADMINQ_ETH_WOL_REG_OFFSET_DRACO;
	adminq_mgt->rmon_ranges = rmon_ranges_draco;
}
