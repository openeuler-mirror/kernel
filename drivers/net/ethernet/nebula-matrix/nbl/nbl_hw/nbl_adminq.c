// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_adminq.h"

static int nbl_res_adminq_update_ring_num(void *priv);

/* ****   FW CMD FILTERS START  **** */

static int nbl_res_adminq_check_ring_num(struct nbl_resource_mgt *res_mgt,
					 struct nbl_fw_cmd_ring_num_param *param)
{
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	u32 sum = 0, pf_real_num = 0, vf_real_num = 0;
	int i;

	pf_real_num = NBL_VSI_PF_REAL_QUEUE_NUM(param->pf_def_max_net_qp_num);
	vf_real_num = NBL_VSI_VF_REAL_QUEUE_NUM(param->vf_def_max_net_qp_num);

	if (pf_real_num > NBL_MAX_TXRX_QUEUE_PER_FUNC || vf_real_num > NBL_MAX_TXRX_QUEUE_PER_FUNC)
		return -EINVAL;

	/* TODO: should we consider when pf_num is 8? */
	for (i = 0; i < NBL_COMMON_TO_ETH_MODE(common); i++) {
		pf_real_num = param->net_max_qp_num[i] ?
			      NBL_VSI_PF_REAL_QUEUE_NUM(param->net_max_qp_num[i]) :
			      NBL_VSI_PF_REAL_QUEUE_NUM(param->pf_def_max_net_qp_num);

		if (pf_real_num > NBL_MAX_TXRX_QUEUE_PER_FUNC)
			return -EINVAL;

		sum += pf_real_num;
	}

	for (i = NBL_MAX_PF; i < NBL_MAX_FUNC; i++) {
		vf_real_num = param->net_max_qp_num[i] ?
			      NBL_VSI_VF_REAL_QUEUE_NUM(param->net_max_qp_num[i]) :
			      NBL_VSI_VF_REAL_QUEUE_NUM(param->vf_def_max_net_qp_num);

		if (vf_real_num > NBL_MAX_TXRX_QUEUE_PER_FUNC)
			return -EINVAL;

		sum += vf_real_num;
	}

	if (sum > NBL_MAX_TXRX_QUEUE)
		return -EINVAL;

	return 0;
}

static int nbl_res_fw_cmd_filter_rw_in(struct nbl_resource_mgt *res_mgt, void *data, int len)
{
	struct nbl_chan_resource_write_param *param = (struct nbl_chan_resource_write_param *)data;
	struct nbl_fw_cmd_ring_num_param *num_param;

	switch (param->resid) {
	case NBL_ADMINQ_PFA_TLV_PFVF_RING_ID:
		num_param = (struct nbl_fw_cmd_ring_num_param *)param->data;
		return nbl_res_adminq_check_ring_num(res_mgt, num_param);
	default:
		break;
	}

	return 0;
}

static void nbl_res_adminq_add_cmd_filter_res_write(struct nbl_resource_mgt *res_mgt)
{
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct nbl_common_info *common = NBL_RES_MGT_TO_COMMON(res_mgt);
	struct nbl_res_fw_cmd_filter filter = {0};
	u16 key = 0;

	key = NBL_CHAN_MSG_ADMINQ_RESOURCE_WRITE;
	filter.in = nbl_res_fw_cmd_filter_rw_in;

	if (nbl_common_alloc_hash_node(adminq_mgt->cmd_filter, &key, &filter))
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
		param.offset = offset + byte_offset;
		param.length = xfer_size;
		memcpy(param.data, data + byte_offset, xfer_size);

		NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
			      NBL_CHAN_MSG_ADMINQ_GET_MODULE_EEPROM,
			      &param, sizeof(param), NULL, 0, 1);
		ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
		if (ret) {
			dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x, eth_id:%d,\n"
				"i2c_address:%d, page:%d, bank:%d, offset:%d, length:%d\n",
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
		param.offset = offset + byte_offset;
		param.length = xfer_size;

		NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
			      NBL_CHAN_MSG_ADMINQ_GET_MODULE_EEPROM,
			      &param, sizeof(param), data + byte_offset, xfer_size, 1);
		ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
		if (ret) {
			dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x, eth_id:%d,\n"
				"i2c_address:%d, page:%d, bank:%d, offset:%d, length:%d\n",
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
	strscpy((char *)&idxbuf[4080], "M181XXSRIS", NBL_ADMINQ_IDX_LEN - 4080);

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

static int nbl_res_adminq_flash_image(void *priv, u32 module, const u8 *data, size_t len)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	int rbank, write_bank, ret = 0;

	switch (module) {
	case NBL_ADMINQ_BANK_INDEX_SPI_BOOT:
		ret |= nbl_res_adminq_flash_erase(res_mgt, BANKID_BOOT_BANK, 0, len);
		ret |= nbl_res_adminq_flash_write(res_mgt, BANKID_BOOT_BANK, 0, len, data);

		break;
	case NBL_ADMINQ_BANK_INDEX_NVM_BANK:
		if (nbl_res_adminq_get_nvm_bank_index(res_mgt, &rbank))
			return -EFAULT;

		write_bank = rbank ? BANKID_NVM_BANK0 : BANKID_NVM_BANK1;

		ret |= nbl_res_adminq_flash_erase(res_mgt, write_bank, 0, len);
		ret |= nbl_res_adminq_flash_write(res_mgt, write_bank, 0, len, data);

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
static int nbl_res_adminq_get_firmware_version(void *priv, char *firmware_verion)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_chan_send_info chan_send;
	struct nbl_chan_param_nvm_version_resp resp_param;
	int ret = 0;
	u32 version_type = NBL_FW_VERSION_RUNNING_BANK;

	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID, NBL_CHAN_MSG_ADMINQ_GET_NVM_VERSION,
		      &version_type, sizeof(version_type), &resp_param, sizeof(resp_param), 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x\n",
			ret, NBL_CHAN_MSG_ADMINQ_GET_NVM_VERSION);
		return ret;
	}

	if (!memcmp(resp_param.magic, FIRMWARE_MAGIC, sizeof(resp_param.magic))) {
		snprintf(firmware_verion, ETHTOOL_FWVERS_LEN,
			 "%d.%d.%d build %04d%02d%02d %08x",
			 BCD2BYTE((resp_param.version >> 16) & 0xFF),
			 BCD2BYTE((resp_param.version >> 8) & 0xFF),
			 BCD2BYTE(resp_param.version & 0xFF),
			 BCD2SHORT((resp_param.build_date >> 16) & 0xFFFF),
			 BCD2BYTE((resp_param.build_date >> 8) & 0xFF),
			 BCD2BYTE(resp_param.build_date & 0xFF),
			 resp_param.build_hash);
	} else {
		dev_err(dev, "adminq msg firmware verion magic check failed\n");
		return -EINVAL;
	}

	return 0;
}

static int nbl_res_adminq_set_sfp_state(void *priv, u8 eth_id, u8 state)
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
	if (state)
		data = NBL_PORT_SFP_ON + (key << NBL_PORT_KEY_KEY_SHIFT);
	else
		data = NBL_PORT_SFP_OFF + (key << NBL_PORT_KEY_KEY_SHIFT);

	memset(param, 0, param_len);
	param->id = eth_id;
	param->subop = NBL_PORT_SUBOP_WRITE;
	param->data[0] = data;

	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
		      NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
		      param, param_len, NULL, 0, 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x, eth_id:%d, sfp %s\n",
			ret, NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
			eth_info->logic_eth_id[eth_id],
			state ? "on" : "off");
		kfree(param);
		return ret;
	}

	kfree(param);
	return 0;
}

int nbl_res_open_sfp(struct nbl_resource_mgt *res_mgt, u8 eth_id)
{
	return nbl_res_adminq_set_sfp_state(res_mgt, eth_id, NBL_SFP_MODULE_ON);
}

static int nbl_res_adminq_setup_loopback(void *priv, u32 eth_id, u32 enable)
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
	if (enable)
		data = NBL_PORT_ENABLE_LOOPBACK + (key << NBL_PORT_KEY_KEY_SHIFT);
	else
		data = NBL_PORT_DISABLE_LOOPBCK + (key << NBL_PORT_KEY_KEY_SHIFT);

	memset(param, 0, param_len);
	param->id = eth_id;
	param->subop = NBL_PORT_SUBOP_WRITE;
	param->data[0] = data;

	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
		      NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
		      param, param_len, NULL, 0, 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x, eth_id:%d, %s eth loopback\n",
			ret, NBL_CHAN_MSG_ADMINQ_MANAGE_PORT_ATTRIBUTES,
			eth_info->logic_eth_id[eth_id],
			enable ? "enable" : "disable");

		kfree(param);
		return ret;
	}

	kfree(param);
	return 0;
}

static bool nbl_res_adminq_check_fw_heartbeat(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	unsigned long check_time;
	unsigned long seq_acked;

	if (adminq_mgt->fw_resetting) {
		adminq_mgt->fw_last_hb_seq++;
		return false;
	}

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

	return false;
}

static bool nbl_res_adminq_check_fw_reset(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	unsigned long seq_acked;

	seq_acked = phy_ops->get_fw_pong(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));
	if (adminq_mgt->fw_last_hb_seq != seq_acked) {
		phy_ops->set_fw_ping(NBL_RES_MGT_TO_PHY_PRIV(res_mgt), adminq_mgt->fw_last_hb_seq);
		return false;
	}

	adminq_mgt->fw_resetting = false;
	wake_up(&adminq_mgt->wait_queue);
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
		nbl_res_adminq_set_sfp_state(res_mgt, eth_id, NBL_SFP_MODULE_ON);

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
		    cable_comp == SFF_COPPER_8431_APPENDIX_E)
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
	nbl_common_queue_work(&adminq_mgt->eth_task, true, false);
}

static void nbl_res_adminq_recv_port_notify(void *priv, void *data)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_port_notify *notify;
	u8 last_module_inplace = 0;
	u8 last_link_state = 0;
	int eth_id = 0;

	notify = (struct nbl_port_notify *)data;
	eth_id = notify->id;

	dev_info(dev, "eth_id:%d link_state:%d, module_inplace:%d, speed:%d, flow_ctrl:%d, fec:%d, advertising:%llx, lp_advertising:%llx\n",
		 eth_info->logic_eth_id[eth_id], notify->link_state, notify->module_inplace,
		 notify->speed * 10, notify->flow_ctrl,
		 notify->fec, notify->advertising, notify->lp_advertising);

	mutex_lock(&adminq_mgt->eth_lock);

	last_module_inplace = eth_info->module_inplace[eth_id];
	last_link_state = eth_info->link_state[eth_id];

	eth_info->link_state[eth_id] = notify->link_state;
	eth_info->module_inplace[eth_id] = notify->module_inplace;
	/* when eth link down, don not update speed
	 * when config autoneg to off, ethtool read speed and set it with disable autoneg command,
	 * if eth is link down, the speed from emp is not credible,
	 * need to reserver last link up speed.
	 */
	if (notify->link_state || !eth_info->link_speed[eth_id])
		eth_info->link_speed[eth_id] = notify->speed * 10;
	eth_info->active_fc[eth_id] = notify->flow_ctrl;
	eth_info->active_fec[eth_id] = notify->fec;
	eth_info->port_lp_advertising[eth_id] = notify->lp_advertising;

	if (!last_module_inplace && notify->module_inplace) {
		adminq_mgt->module_inplace_changed[eth_id] = 1;
		nbl_res_eth_task_schedule(adminq_mgt);
	}

	if (last_link_state != notify->link_state) {
		adminq_mgt->link_state_changed[eth_id] = 1;
		nbl_res_eth_task_schedule(adminq_mgt);
	}

	mutex_unlock(&adminq_mgt->eth_lock);
}

static int nbl_get_highest_bit(u64 advertise)
{
	int highest_bit_pos = 0;

	while (advertise != 0) {
		advertise >>= 1;
		highest_bit_pos++;
	}

	return highest_bit_pos;
}

static int nbl_res_adminq_set_port_advertising(void *priv,
					       struct nbl_port_advertising *advertising)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_chan_send_info chan_send;
	int highest_bit_pos = 0;
	struct nbl_port_key *param;
	int param_len = 0;
	int eth_id = 0;
	u64 key = 0;
	u64 data = 0;
	u64 new_advert = 0;
	int ret;

	param_len = sizeof(struct nbl_port_key) + 1 * sizeof(u64);
	param = kzalloc(param_len, GFP_KERNEL);

	eth_id = advertising->eth_id;
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
		new_advert = new_advert & ~NBL_PORT_CAP_FEC_MASK;

		/* when ethtool set FEC_AUTO, we set default fec mode */
		if (advertising->active_fec == NBL_PORT_FEC_AUTO && !advertising->autoneg) {
			advertising->active_fec = NBL_PORT_FEC_OFF;
			if (eth_info->link_speed[eth_id] == SPEED_1000)
				advertising->active_fec = NBL_ETH_1G_DEFAULT_FEC_MODE;
			if (eth_info->link_speed[eth_id] == SPEED_10000)
				advertising->active_fec = NBL_ETH_10G_DEFAULT_FEC_MODE;
			if (eth_info->link_speed[eth_id] == SPEED_25000)
				advertising->active_fec = NBL_ETH_25G_DEFAULT_FEC_MODE;
		}

		if (advertising->active_fec == NBL_PORT_FEC_OFF)
			new_advert |= BIT(NBL_PORT_CAP_FEC_NONE);
		if (advertising->active_fec == NBL_PORT_FEC_RS)
			new_advert |= BIT(NBL_PORT_CAP_FEC_RS);
		if (advertising->active_fec == NBL_PORT_FEC_BASER)
			new_advert |= BIT(NBL_PORT_CAP_FEC_BASER);
		if (advertising->active_fec == NBL_PORT_FEC_AUTO)
			new_advert |= NBL_PORT_CAP_FEC_MASK;
	}

	/* set speed */
	if (advertising->speed_advert != 0) {
		new_advert = (new_advert & (NBL_PORT_CAP_AUTONEG_MASK | NBL_PORT_CAP_FEC_MASK |
			      NBL_PORT_CAP_PAUSE_MASK)) | advertising->speed_advert;
	}

	highest_bit_pos = nbl_get_highest_bit(new_advert);
	/* speed 10G only can set fec off or baseR, if set RS we change it to baseR */
	if (highest_bit_pos <= NBL_PORT_CAP_10GBASE_SR &&
	    highest_bit_pos >= NBL_PORT_CAP_10GBASE_T && !advertising->autoneg) {
		if (new_advert & BIT(NBL_PORT_CAP_FEC_RS)) {
			new_advert = new_advert & ~NBL_PORT_CAP_FEC_MASK;
			new_advert |= BIT(NBL_PORT_CAP_FEC_BASER);
			dev_notice(dev, "speed 10G default set fec baseR, set fec baseR\n");
			dev_notice(dev, "set new_advert:%llx\n", new_advert);
		}
	}

	if (eth_info->port_max_rate[eth_id] != NBL_PORT_MAX_RATE_100G_PAM4)
		new_advert &= ~NBL_PORT_CAP_PAM4_MASK;
	else
		new_advert |= NBL_PORT_CAP_PAM4_MASK;

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
		return ret;
	}

	eth_info->port_advertising[eth_id] = new_advert;

	kfree(param);
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

	ret = nbl_res_adminq_get_module_eeprom_info(res_mgt, eth_id, I2C_DEV_ADDR_A0, 0, 0, 0,
						    SFF_8472_COMPLIANCE + 1, data);
	if (ret) {
		dev_err(dev, "eth %d get_module_eeprom_info failed %d\n",
			eth_info->logic_eth_id[eth_id], ret);
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
	u32 length = eeprom->len;
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

	if (res_mgt->resource_info->board_info.eth_speed == NBL_FW_PORT_SPEED_100G) {
		while (start < ETH_MODULE_SFF_8636_MAX_LEN) {
			length = SFF_8638_PAGESIZE;
			if (start + length > ETH_MODULE_SFF_8636_MAX_LEN)
				length = ETH_MODULE_SFF_8636_MAX_LEN - start;

			nbl_res_get_module_eeprom_page(start, &turn_page, &offset);
			ret = nbl_res_adminq_turn_module_eeprom_page(res_mgt, eth_id, turn_page);
			if (ret) {
				dev_err(dev, "eth %d get_module_eeprom_info failed %d\n",
					eth_info->logic_eth_id[eth_id], ret);
				return -EIO;
			}

			ret = nbl_res_adminq_get_module_eeprom_info(res_mgt, eth_id,
								    I2C_DEV_ADDR_A0, 0, 0,
								    offset, length, data);
			if (ret) {
				dev_err(dev, "eth %d get_module_eeprom_info failed %d\n",
					eth_info->logic_eth_id[eth_id], ret);
				return -EIO;
			}
			start += length;
			data += length;
			length = eeprom->len - length;
		}
		return 0;
	}

	/* Read A0 portion of eth EEPROM */
	if (start < ETH_MODULE_SFF_8079_LEN) {
		if (start + eeprom->len > ETH_MODULE_SFF_8079_LEN)
			length = ETH_MODULE_SFF_8079_LEN - start;

		ret = nbl_res_adminq_get_module_eeprom_info(res_mgt, eth_id, I2C_DEV_ADDR_A0, 0, 0,
							    start, length, data);
		if (ret) {
			dev_err(dev, "eth %d get_module_eeprom_info failed %d\n",
				eth_info->logic_eth_id[eth_id], ret);
			return -EIO;
		}
		start += length;
		data += length;
		length = eeprom->len - length;
	}

	/* Read A2 portion of eth EEPROM */
	if (length) {
		start -= ETH_MODULE_SFF_8079_LEN;
		ret = nbl_res_adminq_get_module_eeprom_info(res_mgt, eth_id, I2C_DEV_ADDR_A2, 0, 0,
							    start, length, data);
		if (ret) {
			dev_err(dev, "eth %d get_module_eeprom_info failed %d\n",
				eth_info->logic_eth_id[eth_id], ret);
			return -EIO;
		}
	}

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

	key = NBL_PORT_KRY_LED_BLINK;

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

static int nbl_res_adminq_pt_filter_in(struct nbl_resource_mgt *res_mgt,
				       struct nbl_passthrough_fw_cmd_param *param)
{
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct nbl_res_fw_cmd_filter *filter;

	filter = nbl_common_get_hash_node(adminq_mgt->cmd_filter, &param->opcode);
	if (filter && filter->in)
		return filter->in(res_mgt, param->data, param->in_size);

	return 0;
}

static int nbl_res_adminq_pt_filter_out(struct nbl_resource_mgt *res_mgt,
					struct nbl_passthrough_fw_cmd_param *param)
{
	struct nbl_adminq_mgt *adminq_mgt = NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct nbl_res_fw_cmd_filter *filter;
	int ret = 0;

	filter = nbl_common_get_hash_node(adminq_mgt->cmd_filter, &param->opcode);
	if (filter && filter->out)
		ret = filter->out(res_mgt, param->data, param->out_size);

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
		dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x\n",
			ret, param->opcode);
		goto send_fail;
	}

	result->opcode = param->opcode;
	result->errcode = ret;
	result->out_size = param->out_size;
	if (result->out_size)
		memcpy(result->data, out_data, param->out_size);

	nbl_res_adminq_pt_filter_out(res_mgt, result);

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

	param->resid = NBL_ADMINQ_PFA_TLV_PFVF_RING_ID;
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

	if (info->pf_def_max_net_qp_num && info->vf_def_max_net_qp_num)
		memcpy(&res_info->net_ring_num_info, info, sizeof(res_info->net_ring_num_info));

send_fail:
	kfree(info);
alloc_info_fail:
	kfree(param);
alloc_param_fail:
	return ret;
}

static int nbl_res_adminq_set_ring_num(void *priv, struct nbl_fw_cmd_ring_num_param *param)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(NBL_RES_MGT_TO_COMMON(res_mgt));
	struct nbl_chan_send_info chan_send;
	struct nbl_chan_resource_write_param *data;
	int data_len = sizeof(struct nbl_fw_cmd_ring_num_param);
	int ret = 0;

	data = kzalloc(sizeof(*data) + data_len, GFP_KERNEL);
	if (!data)
		goto alloc_data_fail;

	data->resid = NBL_ADMINQ_PFA_TLV_PFVF_RING_ID;
	data->offset = 0;
	data->len = data_len;
	memcpy(data->data, param, data_len);

	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID, NBL_CHAN_MSG_ADMINQ_RESOURCE_WRITE,
		      data, sizeof(*data) + data_len, NULL, 0, 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret)
		dev_err(dev, "adminq send msg failed with ret: %d\n", ret);

	kfree(data);
alloc_data_fail:
	return ret;
}

static void nbl_res_adminq_set_eth_speed(struct nbl_resource_mgt *res_mgt,
					 u8 eth_id, u32 speed, u8 active_fec, u8 autoneg)
{
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_port_advertising port_advertising = {0};
	u64 speed_advert = 0;

	speed_advert = nbl_speed_to_link_mode(speed, autoneg);
	speed_advert &= eth_info->port_caps[eth_id];

	if (!speed_advert) {
		dev_err(dev, "eth %d speed %d is not support, exit\n",
			eth_info->logic_eth_id[eth_id], speed);
		return;
	}

	if (active_fec == NBL_PORT_FEC_OFF) {
		if (!(eth_info->port_caps[eth_id] & BIT(NBL_PORT_CAP_FEC_NONE))) {
			dev_err(dev, "eth %d optical module plug in, want to set fec mode off, but eth caps %llx donot support it\n",
				eth_info->logic_eth_id[eth_id], eth_info->port_caps[eth_id]);
		}
	}
	if (active_fec == NBL_PORT_FEC_RS) {
		if (!(eth_info->port_caps[eth_id] & BIT(NBL_PORT_CAP_FEC_RS))) {
			dev_err(dev, "eth %d optical module plug in, want to set fec mode RS, but eth caps %llx donot support it\n",
				eth_info->logic_eth_id[eth_id], eth_info->port_caps[eth_id]);
		}
	}
	if (active_fec == NBL_PORT_FEC_BASER) {
		if (!(eth_info->port_caps[eth_id] & BIT(NBL_PORT_CAP_FEC_BASER))) {
			dev_err(dev, "eth %d optical module plug in, want to set fec mode baseR, but eth caps %llx donot support it\n",
				eth_info->logic_eth_id[eth_id], eth_info->port_caps[eth_id]);
		}
	}
	if (active_fec == NBL_PORT_FEC_AUTO) {
		if (!(eth_info->port_caps[eth_id] & BIT(NBL_PORT_CAP_AUTONEG))) {
			dev_err(dev, "eth %d optical module plug in, want to set fec mode auto, but eth caps %llx donot support it\n",
				eth_info->logic_eth_id[eth_id], eth_info->port_caps[eth_id]);
		}
	}
	port_advertising.eth_id = eth_id;
	port_advertising.speed_advert = speed_advert;
	port_advertising.active_fec = active_fec;
	port_advertising.autoneg = autoneg;
	dev_info(dev, "eth %d optical module plug in, set speed_advert:%llx, active_fec:%x, autoneg %d\n",
		 eth_info->logic_eth_id[eth_id], speed_advert, active_fec, autoneg);
	nbl_res_adminq_set_port_advertising(res_mgt, &port_advertising);
}

static void nbl_res_adminq_recovery_eth(struct nbl_resource_mgt *res_mgt, u8 eth_id)
{
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	u8 port_max_rate = 0;
	u8 port_type;
	u32 port_max_speed = 0;
	u8 active_fec = 0;
	u8 autoneg = 0;

	if (!eth_info->module_inplace[eth_id])
		return;

	port_max_rate = eth_info->port_max_rate[eth_id];

	switch (port_max_rate) {
	case NBL_PORT_MAX_RATE_1G:
		port_max_speed = SPEED_1000;
		active_fec = NBL_ETH_1G_DEFAULT_FEC_MODE;
		break;
	case NBL_PORT_MAX_RATE_10G:
		port_max_speed = SPEED_10000;
		active_fec = NBL_ETH_10G_DEFAULT_FEC_MODE;
		break;
	case NBL_PORT_MAX_RATE_25G:
		port_max_speed = SPEED_25000;
		active_fec = NBL_ETH_25G_DEFAULT_FEC_MODE;
		break;
	case NBL_PORT_MAX_RATE_100G:
	case NBL_PORT_MAX_RATE_100G_PAM4:
		port_max_speed = SPEED_100000;
		active_fec = NBL_ETH_100G_DEFAULT_FEC_MODE;
		break;
	default:
		/* default set 25G */
		port_max_speed = SPEED_25000;
		active_fec = NBL_ETH_25G_DEFAULT_FEC_MODE;
		break;
	}

	port_type = eth_info->port_type[eth_id];
	/* cooper support auto-negotiation */
	if (port_type == NBL_PORT_TYPE_COPPER) {
		if (port_max_speed >= SPEED_25000)
			autoneg = 1;
		else
			autoneg = 0; /* disable autoneg when 10G module pluged */

		eth_info->port_caps[eth_id] |= BIT(NBL_PORT_CAP_AUTONEG);
	} else {
		autoneg = 0;
		eth_info->port_caps[eth_id] &= ~BIT_MASK(NBL_PORT_CAP_AUTONEG);
	}
	/* when optical module plug in, we must set default fec */
	nbl_res_adminq_set_eth_speed(res_mgt, eth_id, port_max_speed, active_fec, autoneg);
}

static int nbl_res_adminq_nway_reset(void *priv, u8 eth_id)
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

	key = NBL_PORT_KEY_DISABLE;
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
		dev_err(dev, "ctrl eth %d disable failed ret %d\n",
			eth_info->logic_eth_id[eth_id], ret);
		kfree(param);
		return ret;
	}

	key = NBL_PORT_KEY_ENABLE;
	data = NBL_PORT_FLAG_ENABLE_NOTIFY + (key << NBL_PORT_KEY_KEY_SHIFT);

	param_len = sizeof(struct nbl_port_key) + 1 * sizeof(u64);
	param->data[0] = data;
	param->id = eth_id;
	param->subop = NBL_PORT_SUBOP_WRITE;
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret) {
		dev_err(dev, "ctrl eth %d enable failed %d\n",
			eth_info->logic_eth_id[eth_id], ret);
		kfree(param);
		return ret;
	}

	nbl_res_adminq_recovery_eth(res_mgt, eth_id);

	kfree(param);
	return 0;
}

#define ADD_ETH_STATISTICS(name)  {#name}
static struct nbl_leonis_eth_stats_info _eth_statistics[] = {
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
	ADD_ETH_STATISTICS(eth_frames_rx_1024_to_1535B),
	ADD_ETH_STATISTICS(eth_frames_rx_1536_to_2047B),
	ADD_ETH_STATISTICS(eth_frames_rx_2048_to_MAXB),
	ADD_ETH_STATISTICS(eth_octets_rx),
	ADD_ETH_STATISTICS(eth_octets_rx_ok),
	ADD_ETH_STATISTICS(eth_octets_rx_badfcs),
	ADD_ETH_STATISTICS(eth_octets_rx_dropped),
};

static void nbl_res_adminq_get_private_stat_len(void *priv, u32 *len)
{
	*len = ARRAY_SIZE(_eth_statistics);
}

static void nbl_res_adminq_get_private_stat_data(void *priv, u32 eth_id, u64 *data)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_chan_send_info chan_send;
	int data_length = sizeof(struct nbl_leonis_eth_stats);
	int ret = 0;

	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID,
		      NBL_CHAN_MSG_ADMINQ_GET_ETH_STATS,
		      &eth_id, sizeof(eth_id), data, data_length, 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret)
		dev_err(dev, "adminq get eth %d stats failed ret: %d\n",
			eth_info->logic_eth_id[eth_id], ret);
}

static void nbl_res_adminq_fill_private_stat_strings(void *priv, u8 *strings)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(_eth_statistics); i++) {
		snprintf(strings, ETH_GSTRING_LEN, "%s", _eth_statistics[i].descp);
		strings += ETH_GSTRING_LEN;
	}
}

static u32 nbl_convert_temp_type_eeprom_offset(enum nbl_module_temp_type type)
{
	switch (type) {
	case NBL_MODULE_TEMP:
		return SFF_8636_TEMP;
	case NBL_MODULE_TEMP_MAX:
		return SFF_8636_TEMP_MAX;
	case NBL_MODULE_TEMP_CRIT:
		return SFF_8636_TEMP_CIRT;
	default:
		return SFF_8636_TEMP;
	}
}

static u32 nbl_convert_temp_type_qsfp28_eeprom_offset(enum nbl_module_temp_type type)
{
	switch (type) {
	case NBL_MODULE_TEMP:
		return SFF_8636_QSFP28_TEMP;
	case NBL_MODULE_TEMP_MAX:
		return SFF_8636_QSFP28_TEMP_MAX;
	case NBL_MODULE_TEMP_CRIT:
		return SFF_8636_QSFP28_TEMP_CIRT;
	default:
		return SFF_8636_QSFP28_TEMP;
	}
}

static int nbl_res_adminq_get_module_temp_common(struct nbl_resource_mgt *res_mgt, u8 eth_id,
						 enum nbl_module_temp_type type)
{
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

	return temp;
}

static int nbl_res_adminq_get_module_temp_special(struct nbl_resource_mgt *res_mgt, u8 eth_id,
						  enum nbl_module_temp_type type)
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

	return temp;
}

static int nbl_res_adminq_get_module_temperature(void *priv, u8 eth_id,
						 enum nbl_module_temp_type type)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);

	if (!eth_info->module_inplace[eth_id])
		return 0;

	if (res_mgt->resource_info->board_info.eth_speed == NBL_FW_PORT_SPEED_100G)
		return nbl_res_adminq_get_module_temp_special(res_mgt, eth_id, type);
	else
		return nbl_res_adminq_get_module_temp_common(res_mgt, eth_id, type);
}

static int nbl_res_adminq_load_p4(void *priv, struct nbl_load_p4_param *p4_param)
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

static int nbl_res_adminq_load_p4_default(void *priv)
{
	struct nbl_resource_mgt *res_mgt = (struct nbl_resource_mgt *)priv;
	struct nbl_channel_ops *chan_ops = NBL_RES_MGT_TO_CHAN_OPS(res_mgt);
	struct device *dev = NBL_COMMON_TO_DEV(res_mgt->common);
	struct nbl_chan_send_info chan_send;
	int ret = 0;

	NBL_CHAN_SEND(chan_send, NBL_CHAN_ADMINQ_FUNCTION_ID, NBL_CHAN_MSG_ADMINQ_LOAD_P4_DEFAULT,
		      NULL, 0, NULL, 0, 1);
	ret = chan_ops->send_msg(NBL_RES_MGT_TO_CHAN_PRIV(res_mgt), &chan_send);
	if (ret)
		dev_err(dev, "adminq send msg failed with ret: %d, msg_type: 0x%x\n",
			ret, NBL_CHAN_MSG_ADMINQ_LOAD_P4_DEFAULT);

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
	NBL_ADMINQ_SET_OPS(setup_loopback, nbl_res_adminq_setup_loopback);			\
	NBL_ADMINQ_SET_OPS(check_fw_heartbeat, nbl_res_adminq_check_fw_heartbeat);		\
	NBL_ADMINQ_SET_OPS(check_fw_reset, nbl_res_adminq_check_fw_reset);			\
	NBL_ADMINQ_SET_OPS(get_port_attributes, nbl_res_adminq_get_port_attributes);		\
	NBL_ADMINQ_SET_OPS(update_ring_num, nbl_res_adminq_update_ring_num);			\
	NBL_ADMINQ_SET_OPS(set_ring_num, nbl_res_adminq_set_ring_num);				\
	NBL_ADMINQ_SET_OPS(enable_port, nbl_res_adminq_enable_port);				\
	NBL_ADMINQ_SET_OPS(recv_port_notify, nbl_res_adminq_recv_port_notify);			\
	NBL_ADMINQ_SET_OPS(set_port_advertising, nbl_res_adminq_set_port_advertising);		\
	NBL_ADMINQ_SET_OPS(get_port_state, nbl_res_adminq_get_port_state);			\
	NBL_ADMINQ_SET_OPS(get_module_info, nbl_res_adminq_get_module_info);			\
	NBL_ADMINQ_SET_OPS(get_module_eeprom, nbl_res_adminq_get_module_eeprom);		\
	NBL_ADMINQ_SET_OPS(get_link_state, nbl_res_adminq_get_link_state);			\
	NBL_ADMINQ_SET_OPS(set_eth_mac_addr, nbl_res_adminq_set_eth_mac_addr);			\
	NBL_ADMINQ_SET_OPS(ctrl_port_led, nbl_res_adminq_ctrl_port_led);			\
	NBL_ADMINQ_SET_OPS(nway_reset, nbl_res_adminq_nway_reset);				\
	NBL_ADMINQ_SET_OPS(passthrough_fw_cmd, nbl_res_adminq_passthrough);			\
	NBL_ADMINQ_SET_OPS(get_private_stat_len, nbl_res_adminq_get_private_stat_len);		\
	NBL_ADMINQ_SET_OPS(get_private_stat_data, nbl_res_adminq_get_private_stat_data);	\
	NBL_ADMINQ_SET_OPS(fill_private_stat_strings, nbl_res_adminq_fill_private_stat_strings);\
	NBL_ADMINQ_SET_OPS(get_module_temperature, nbl_res_adminq_get_module_temperature);	\
	NBL_ADMINQ_SET_OPS(load_p4, nbl_res_adminq_load_p4);					\
	NBL_ADMINQ_SET_OPS(load_p4_default, nbl_res_adminq_load_p4_default);			\
} while (0)

/* Structure starts here, adding an op should not modify anything below */
static int nbl_adminq_setup_mgt(struct device *dev, struct nbl_adminq_mgt **adminq_mgt)
{
	*adminq_mgt = devm_kzalloc(dev, sizeof(struct nbl_adminq_mgt), GFP_KERNEL);
	if (!*adminq_mgt)
		return -ENOMEM;

	init_waitqueue_head(&(*adminq_mgt)->wait_queue);
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

static void nbl_res_adminq_notify_link_state(struct nbl_resource_mgt *res_mgt, u8 eth_id,
					     u8 link_state)
{
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	struct nbl_queue_mgt *queue_mgt = NBL_RES_MGT_TO_QUEUE_MGT(res_mgt);
	struct nbl_sriov_info *sriov_info;
	struct nbl_queue_info *queue_info;
	u16 pf_fid = 0, vf_fid = 0, link_speed = 0;
	int i = 0, j = 0;

	for (i = 0; i < NBL_RES_MGT_TO_PF_NUM(res_mgt); i++) {
		if (eth_info->pf_bitmap[eth_id] & BIT(i))
			pf_fid = nbl_res_pfvfid_to_func_id(res_mgt, i, -1);
		else
			continue;

		sriov_info = &NBL_RES_MGT_TO_SRIOV_INFO(res_mgt)[pf_fid];
		queue_info = &queue_mgt->queue_info[pf_fid];

		/* send eth's link state to pf */
		if (queue_info->num_txrx_queues)
			nbl_res_adminq_chan_notify_link_state_req(res_mgt,
								  pf_fid,
								  link_state,
								  eth_info->link_speed[eth_id]);

		/* send eth's link state to pf's all vf */
		for (j = 0; j < sriov_info->num_vfs; j++) {
			vf_fid = sriov_info->start_vf_func_id + j;
			queue_info = &queue_mgt->queue_info[vf_fid];
			if (queue_info->num_txrx_queues) {
				link_speed = eth_info->link_speed[eth_id];
				nbl_res_adminq_chan_notify_link_state_req(res_mgt, vf_fid,
									  link_state,
									  link_speed);
			}
		}
	}
}

static void nbl_res_adminq_eth_task(struct work_struct *work)
{
	struct nbl_adminq_mgt *adminq_mgt = container_of(work, struct nbl_adminq_mgt,
							 eth_task);
	struct nbl_resource_mgt *res_mgt = adminq_mgt->res_mgt;
	struct nbl_eth_info *eth_info = NBL_RES_MGT_TO_ETH_INFO(res_mgt);
	u8 eth_id = 0;
	u8 port_max_rate = 0;
	u32 port_max_speed = 0;
	u8 active_fec = 0;
	u8 autoneg = 0;

	for (eth_id = 0 ; eth_id < NBL_MAX_ETHERNET; eth_id++) {
		if (adminq_mgt->module_inplace_changed[eth_id]) {
			/* module not-inplace, transitions to inplace status */
			/* read module register and set speed, */
			/* set fec mode: 10G default OFF, 25G default RS */
			port_max_rate = nbl_res_adminq_get_module_bitrate(res_mgt, eth_id);
			switch (port_max_rate) {
			case NBL_PORT_MAX_RATE_1G:
				port_max_speed = SPEED_1000;
				active_fec = NBL_ETH_1G_DEFAULT_FEC_MODE;
				break;
			case NBL_PORT_MAX_RATE_10G:
				port_max_speed = SPEED_10000;
				active_fec = NBL_ETH_10G_DEFAULT_FEC_MODE;
				break;
			case NBL_PORT_MAX_RATE_25G:
				port_max_speed = SPEED_25000;
				active_fec = NBL_ETH_25G_DEFAULT_FEC_MODE;
				break;
			case NBL_PORT_MAX_RATE_100G:
			case NBL_PORT_MAX_RATE_100G_PAM4:
				port_max_speed = SPEED_100000;
				active_fec = NBL_ETH_100G_DEFAULT_FEC_MODE;
				break;
			default:
				/* default set 25G */
				port_max_speed = SPEED_25000;
				active_fec = NBL_ETH_25G_DEFAULT_FEC_MODE;
				break;
			}

			eth_info->port_max_rate[eth_id] = port_max_rate;
			eth_info->port_type[eth_id] = nbl_res_adminq_get_port_type(res_mgt, eth_id);
			/* cooper support auto-negotiation */
			if (eth_info->port_type[eth_id] == NBL_PORT_TYPE_COPPER) {
				if (port_max_speed >= SPEED_25000)
					autoneg = 1;
				else
					autoneg = 0; /* disable autoneg when 10G module pluged */

				eth_info->port_caps[eth_id] |= BIT(NBL_PORT_CAP_AUTONEG);
			} else {
				autoneg = 0;
				eth_info->port_caps[eth_id] &= ~BIT_MASK(NBL_PORT_CAP_AUTONEG);
			}

			/* when optical module plug in, we must set default fec */
			nbl_res_adminq_set_eth_speed(res_mgt, eth_id, port_max_speed,
						     active_fec, autoneg);

			adminq_mgt->module_inplace_changed[eth_id] = 0;
		}

		mutex_lock(&adminq_mgt->eth_lock);
		if (adminq_mgt->link_state_changed[eth_id]) {
			/* eth link state changed, notify pf and vf */
			nbl_res_adminq_notify_link_state(res_mgt, eth_id,
							 eth_info->link_state[eth_id]);
			adminq_mgt->link_state_changed[eth_id] = 0;
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
	struct nbl_hash_tbl_del_key del_key = {0};

	if (adminq_mgt->cmd_filter)
		nbl_common_remove_hash_table(adminq_mgt->cmd_filter, &del_key);

	adminq_mgt->cmd_filter = NULL;
}

int nbl_adminq_mgt_start(struct nbl_resource_mgt *res_mgt)
{
	struct device *dev = NBL_RES_MGT_TO_DEV(res_mgt);
	struct nbl_adminq_mgt **adminq_mgt = &NBL_RES_MGT_TO_ADMINQ_MGT(res_mgt);
	struct nbl_phy_ops *phy_ops = NBL_RES_MGT_TO_PHY_OPS(res_mgt);
	int ret;

	ret = nbl_adminq_setup_mgt(dev, adminq_mgt);
	if (ret)
		goto setup_mgt_fail;

	(*adminq_mgt)->res_mgt = res_mgt;

	(*adminq_mgt)->fw_last_hb_seq = (u32)phy_ops->get_fw_pong(NBL_RES_MGT_TO_PHY_PRIV(res_mgt));

	INIT_WORK(&(*adminq_mgt)->eth_task, nbl_res_adminq_eth_task);
	mutex_init(&(*adminq_mgt)->eth_lock);

	ret = nbl_res_adminq_setup_cmd_filter(res_mgt);
	if (ret)
		goto set_filter_fail;

	nbl_res_adminq_add_cmd_filter_res_write(res_mgt);

	return 0;

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

void nbl_adminq_remove_ops(struct nbl_resource_ops *res_ops)
{
#define NBL_ADMINQ_SET_OPS(name, func) do {res_ops->NBL_NAME(name) = NULL; ; } while (0)
	NBL_ADMINQ_OPS_TBL;
#undef  NBL_ADMINQ_SET_OPS
}
