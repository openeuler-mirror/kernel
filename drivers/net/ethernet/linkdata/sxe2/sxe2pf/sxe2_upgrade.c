// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_upgrade.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/random.h>
#include <linux/firmware.h>

#include "sxe2_ethtool.h"
#include "sxe2_upgrade.h"
#include "sxe2_netdev.h"
#include "sxe2_msg.h"
#include "sxe2_vsi.h"

STATIC void sxe2_upgd_calc_check_sum(u32 *check_sum, u8 *data, u32 data_len)
{
	u32 per_len = sizeof(u16);

	SXE2_BUG_ON(!data);

	while (data_len >= per_len) {
		*check_sum += *((u16 *)data);
		data += per_len;
		data_len -= per_len;
	}

	*check_sum = ~(*check_sum);
}

STATIC s32 sxe2_upgd_do_check_sum(u32 pack_check_sum, u8 *data, u32 data_len)
{
	s32 ret = 0;
	u32 check_sum = 0;

	sxe2_upgd_calc_check_sum(&check_sum, data, data_len);

	if (pack_check_sum != check_sum) {
		ret = -EINVAL;
		LOG_ERROR("upgrade check_sum check failed: check_sum:%u, \t"
			  "expect:%u\n",
			  check_sum, pack_check_sum);
	}

	return ret;
}

STATIC s32 sxe2_upgd_package_check(u8 *pack_data, u32 pack_len)
{
	s32 ret = 0;
	struct sxe2_pkg_header *pack_header = NULL;
	u8 *data_pos = NULL;
	u32 hdr_len = 0;

	SXE2_BUG_ON(!pack_data);

	if (pack_len <= sizeof(struct sxe2_pkg_header)) {
		ret = -EINVAL;
		LOG_INFO("pack_len %d less than package header:%zu\n", pack_len,
			 sizeof(struct sxe2_pkg_header));
		goto l_end;
	}

	data_pos = pack_data;
	pack_header = (struct sxe2_pkg_header *)data_pos;

	if (pack_header->magic != SXE2_PACK_DATA_BEGIN_NUM) {
		LOG_INFO("magic(%d) failed\n", pack_header->magic);
		ret = -EINVAL;
		goto l_end;
	}

	hdr_len = sizeof(struct sxe2_pkg_header);
	ret = sxe2_upgd_do_check_sum(pack_header->pkg_check_sum, data_pos + hdr_len,
				     pack_len - hdr_len);
	if (ret) {
		LOG_INFO("sxe2_upgd_do_check_sum failed\n");
		goto l_end;
	}

l_end:
	return ret;
}

STATIC s32 sxe2_region_image_check(u8 *pack_data, u32 region_len, u32 pack_len)
{
	s32 ret = 0;
	struct sxe2_fw_header_with_sign *fw_hdr = NULL;
	u32 hdr_len = 0;
	u8 *data_pos = NULL;
	u32 hdr_chk_len = 0;
	u32 magic_offset = 0;

	SXE2_BUG_ON(!pack_data);

	data_pos = pack_data;
	fw_hdr = (struct sxe2_fw_header_with_sign *)data_pos;

	if (region_len > pack_len ||
	    fw_hdr->fw_header.image_len >
			    (pack_len - sizeof(struct sxe2_fw_header_with_sign))) {
		ret = -EINVAL;
		LOG_INFO("region_len:%u > pack_len:%u\n", region_len, pack_len);
		goto l_end;
	}

	if (fw_hdr->fw_header.magic != SXE2_DATABEGIN_NUM) {
		LOG_INFO("image magic(%d) check failed\n", fw_hdr->fw_header.magic);
		goto l_end;
	}

	data_pos = pack_data;
	hdr_len = sizeof(struct sxe2_fw_header_with_sign);
	magic_offset = hdr_len - sizeof(struct sxe2_region_header) +
		       sizeof(fw_hdr->fw_header.magic);
	hdr_chk_len = hdr_len - magic_offset -
		      sizeof(fw_hdr->fw_header.check_sum_header);
	ret = sxe2_upgd_do_check_sum(fw_hdr->fw_header.check_sum_header,
				     data_pos + magic_offset, hdr_chk_len);
	if (ret) {
		LOG_INFO("sxe2_upgd_do_check_sum header failed\n");
		goto l_end;
	}

	data_pos = pack_data;
	ret = sxe2_upgd_do_check_sum(fw_hdr->fw_header.check_sum_file,
				     data_pos + hdr_len,
				     fw_hdr->fw_header.image_len);
	if (ret) {
		LOG_INFO("sxe2_upgd_do_check_sum file failed\n");
		goto l_end;
	}

l_end:
	return ret;
}

STATIC s32 sxe2_upgd_fw_arr_get(struct sxe2_adapter *adapter, u8 *pkg_data,
				u32 pkg_len, u32 fw_type,
				struct sxe2_upgrade_fw_array *fw_arr)
{
	s32 ret = 0;
	struct sxe2_pkg_header *pkg_header;
	struct sxe2_fw_header_with_sign *fw_header;
	struct sxe2_region_header *region_header;
	u8 *data_pos = NULL;
	u32 index = 0;
	u32 offset = 0;
	u32 fw_len = 0;

	if (fw_type == ETHTOOL_FLASH_ALL_REGIONS || fw_type > SXE2_INVAL_U16) {
		pkg_header = (struct sxe2_pkg_header *)pkg_data;

		ret = sxe2_upgd_package_check(pkg_data, pkg_len);
		if (ret) {
			LOG_INFO_BDF("sxe2_upgd_package_check failed\n");
			goto l_end;
		}

		fw_arr->fw_cnt = pkg_header->fw_count;
		offset += sizeof(struct sxe2_pkg_header);
		for (index = 0; index < fw_arr->fw_cnt; index++) {
			if (offset >= pkg_len ||
			    offset + sizeof(struct sxe2_fw_header_with_sign) >=
					    pkg_len) {
				ret = -EINVAL;
				LOG_INFO_BDF("offset:%d large than \t"
					     "pkg_len:%d,sum:%lu, \t"
					     "it may occur visit invalid memory\n",
					     offset, pkg_len,
					     offset + sizeof(struct
							     sxe2_fw_header_with_sign));
				goto l_end;
			}

			data_pos = pkg_data + offset;
			fw_header = (struct sxe2_fw_header_with_sign *)data_pos;
			region_header = &fw_header->fw_header;
			fw_len = region_header->image_len +
				 (u32)sizeof(struct sxe2_fw_header_with_sign);

			if (offset + fw_len > pkg_len) {
				ret = EINVAL;
				LOG_INFO_BDF("(offset large than pkg_len, %s\t",
					     "it may occur visit invalid memory\n");
				goto l_end;
			}

			ret = sxe2_region_image_check(data_pos, fw_len, pkg_len);
			if (ret) {
				LOG_INFO_BDF("sxe2_region_image_check failed\n");
				goto l_end;
			}

			fw_arr->fw_arr[index].offset = offset;
			fw_arr->fw_arr[index].image_len = fw_len;
			fw_arr->fw_arr[index].fw_type =
					(u32)SXE2_FWHEADER_IMAGETYPE(region_header);

			offset += fw_len;
		}
	} else {
		return -EINVAL;
	}

l_end:
	return ret;
}

STATIC s32 sxe2_upgd_64bit_set(u64 *value, u32 bit)
{
	s32 ret = 0;

	LOG_DEBUG("bit=%d\n", bit);

	if (bit >= SXE2_BIT_MAP_64) {
		ret = -EINVAL;
		LOG_DEBUG("upgrade u64 bit set failed. bit=%d > 64\n", bit);
		goto l_end;
	} else {
		SXE2_SET_BIT64(*value, bit);
	}

l_end:
	return ret;
}

STATIC s32 sxe2_upgd_prep_info_fill(struct sxe2_upgrade_prepare_cmd *prepare_info,
				    struct sxe2_upgrade_fw_array *fw_array, u64 uuid,
				    bool ispack, struct sxe2_pkg_header *pkg_hdr)
{
	s32 ret = 0;
	u32 fw_index = 0;

	prepare_info->fw_type_cnt = fw_array->fw_cnt;
	prepare_info->uuid = uuid;
	prepare_info->is_pkg = ispack;

	for (fw_index = 0; fw_index < fw_array->fw_cnt; fw_index++) {
		ret = sxe2_upgd_64bit_set(&prepare_info->fw_type_bitmap,
					  fw_array->fw_arr[fw_index].fw_type);
		if (ret) {
			LOG_INFO("sxe2_upgd_64bit_set failed, imageType=%d\n",
				 fw_array->fw_arr[fw_index].fw_type);
			goto l_end;
		}
	}

	(void)memcpy(&prepare_info->pkg_hdr_info, pkg_hdr, sizeof(*pkg_hdr));

l_end:
	return ret;
}

s32 sxe2_upgrade_prepare(struct sxe2_adapter *adapter,
			 struct sxe2_upgrade_fw_array *fw_arr, u64 uuid,
			 struct sxe2_pkg_header *pkg_hdr)
{
	s32 ret;
	struct sxe2_upgrade_prepare_cmd prep_info = {};
	struct sxe2_cmd_params cmd = {};

	LOG_DEBUG_BDF("fw_cnt:%d\n", fw_arr->fw_cnt);

	ret = sxe2_upgd_prep_info_fill(&prep_info, fw_arr, uuid, true, pkg_hdr);
	if (ret) {
		LOG_INFO_BDF("sxe2_upgd_prep_info_fill failed\n");
		goto l_end;
	}

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_FW_DOWNLOAD_PRE, (void *)&prep_info,
				  sizeof(prep_info), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("upgrade pkg failed, ret=%d\n", ret);
		ret = -EIO;
		goto l_end;
	}

l_end:
	return ret;
}

STATIC void sxe2_upgd_open_info_fill(struct sxe2_upgrade_open_cmd *open_info,
				     u32 frag_num, u32 pack_len, u32 fw_type,
				     u64 uuid)
{
	open_info->dev_type = SXE2_ETH_UPGRADE_DEV_TYPE_CTRL;
	open_info->fw_type = fw_type;

	open_info->uuid = uuid;
	open_info->frag_num = frag_num;
	open_info->frag_len = SXE2_FRAG_LEN;
	open_info->fw_len = pack_len;
	open_info->force = false;
	open_info->no_reset = false;
	open_info->forcehcb = false;
	open_info->ispacket = false;
	open_info->resetnow = false;
	open_info->forceclose = false;
	open_info->all = false;
	open_info->backup = false;
	open_info->no_sign_chk = false;
	open_info->no_ver_chk = true;
	open_info->is_fw_head = false;
}

s32 sxe2_upgrade_open(struct sxe2_adapter *adapter, u32 frag_num, u32 pack_len,
		      u32 fw_type, u64 uuid)
{
	s32 ret = 0;
	struct sxe2_upgrade_open_cmd *open_info = NULL;
	struct sxe2_cmd_params cmd = {};

	open_info = kzalloc(sizeof(*open_info), GFP_KERNEL);
	if (!open_info) {
		ret = -ENOMEM;
		LOG_ERROR_BDF("upgrade pkg no memory, ret=%d\n", ret);
		(void)open_info;
		goto l_end;
	}

	sxe2_upgd_open_info_fill(open_info, frag_num, pack_len, fw_type, uuid);

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_FW_DOWNLOAD_OPEN, (void *)open_info,
				  sizeof(*open_info), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("upgrade pkg failed, ret=%d\n", ret);
		ret = -EIO;
	}

	kfree(open_info);
l_end:
	return ret;
}

STATIC u32 sxe2_upgradefrag_num_get(u32 pack_len, u32 frag_len)
{
	u32 frag_num = 0;

	frag_num = DIV_ROUND_UP(pack_len, frag_len);

	return frag_num;
}

STATIC s32 sxe2_upgd_pkg_div_frag(u8 *pack_data, u32 pack_len, u32 frag_id,
				  u8 *frag_data)
{
	s32 ret = 0;
	u32 frag_num = 0;
	u32 frag_len = SXE2_FRAG_LEN;
	u32 offset = frag_id * SXE2_FRAG_LEN;

	SXE2_BUG_ON(NULL == pack_data || NULL == frag_data);

	frag_num = sxe2_upgradefrag_num_get(pack_len, SXE2_FRAG_LEN);

	LOG_DEBUG("frag_num = %d\n", frag_num);

	if (frag_num - 1 == frag_id) {
		frag_len = pack_len - frag_id * SXE2_FRAG_LEN;
		LOG_DEBUG("last frag_len = %d\n", frag_len);
	}

	(void)memcpy(frag_data, &pack_data[offset], frag_len);

	return ret;
}

STATIC s32 sxe2_upgd_frag_head_init(struct sxe2_frag_head *frag_head, u32 frag_id,
				    u8 *frag_data, u32 pack_len, u64 uuid)
{
	s32 ret = 0;
	u32 frag_num = 0;
	u32 check_sum = 0;

	SXE2_BUG_ON(NULL == frag_head || NULL == frag_data);

	frag_num = sxe2_upgradefrag_num_get(pack_len, SXE2_FRAG_LEN);

	frag_head->frag_sid = frag_id;
	frag_head->uuid = uuid;
	frag_head->frag_len = SXE2_FRAG_LEN;
	frag_head->version = SXE2_UPGRADE_PROTOCAL_VERSION;
	frag_head->symbol_enable = SXE2_FRAG_ENABLE;
	frag_head->symbol_more = (frag_num - 1 == frag_id) ? 0 : 1;

	if (frag_head->symbol_more == 0)
		frag_head->frag_len = pack_len - frag_id * SXE2_FRAG_LEN;

	sxe2_upgd_calc_check_sum(&check_sum, frag_data, frag_head->frag_len);

	frag_head->checksum = check_sum;

	return ret;
}

s32 sxe2_upgrade_flash(struct sxe2_adapter *adapter,
		       struct sxe2_update_flash_param *upgd_flash_obj)
{
	s32 ret = 0;
	struct sxe2_upgrade_flash_cmd *download_info;
	struct sxe2_cmd_params cmd = {};

	download_info = (struct sxe2_upgrade_flash_cmd *)upgd_flash_obj->raw_data;
	memset(download_info, 0, sizeof(struct sxe2_upgrade_flash_cmd));

	ret = sxe2_upgd_pkg_div_frag(upgd_flash_obj->pack_data,
				     upgd_flash_obj->pack_len,
				     upgd_flash_obj->frag_index,
				     download_info->raw_data);
	if (ret) {
		LOG_INFO_BDF("sxe2_upgd_pkg_div_frag failed, pack_len = %d, \t"
			     "frag_index =%d\n",
			     upgd_flash_obj->pack_len, upgd_flash_obj->frag_index);
		goto l_end;
	}

	ret = sxe2_upgd_frag_head_init(&download_info->frag_head,
				       upgd_flash_obj->frag_index,
				       download_info->raw_data,
				       upgd_flash_obj->pack_len,
				       upgd_flash_obj->uuid);
	if (ret) {
		LOG_INFO_BDF("sxe2_upgd_frag_head_init failed, pack_len = %d, \t"
			     "frag_index =%d\n",
			     upgd_flash_obj->pack_len, upgd_flash_obj->frag_index);
		goto l_end;
	}

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_FW_DOWNLOAD_FLASH,
				  (void *)download_info,
				  sizeof(struct sxe2_upgrade_flash_cmd), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("upgrade pkg failed, ret=%d\n", ret);
		ret = -EIO;
	}

l_end:
	return ret;
}

s32 sxe2_upgrade_close(struct sxe2_adapter *adapter, u64 uuid, u32 err)
{
	s32 ret = 0;
	struct sxe2_upgrade_close_cmd close_info = {};
	struct sxe2_cmd_params cmd = {};

	close_info.err_code = err;
	close_info.reset_now = false;
	close_info.uuid = uuid;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_FW_DOWNLOAD_CLOSE,
				  (void *)&close_info, sizeof(close_info), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("upgrade pkg failed, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

s32 sxe2_upgrade_end(struct sxe2_adapter *adapter, u32 err, u32 fw_type, u64 uuid)
{
	s32 ret = 0;
	struct sxe2_upgrade_end_cmd end_info = {};
	struct sxe2_cmd_params cmd = {};

	end_info.uuid = uuid;
	end_info.fw_type = SXE2_UPDATE_FWTYPE_FW_PACKAGE;
	end_info.err_code = err;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_FW_DOWNLOAD_END, (void *)&end_info,
				  sizeof(end_info), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("upgrade pkg failed, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

STATIC s32 sxe2_upgrade_data_trans(struct sxe2_adapter *adapter, u8 *pack_data,
				   u32 pack_len, u32 fw_type, u64 uuid)
{
	s32 ret = 0;
	u32 err = 0;
	u32 frag_num = 0;
	u32 frag_index = 0;
	struct sxe2_update_flash_param upgd_flash_obj = {};

	upgd_flash_obj.raw_data =
			kzalloc(sizeof(struct sxe2_upgrade_flash_cmd), GFP_KERNEL);
	if (!upgd_flash_obj.raw_data) {
		ret = -ENOMEM;
		LOG_INFO_BDF("sxe2_upgrade_flash memory not enough, 2k is needed.");
		goto l_end;
	}

	frag_num = sxe2_upgradefrag_num_get(pack_len, SXE2_FRAG_LEN);

	ret = sxe2_upgrade_open(adapter, frag_num, pack_len, fw_type, uuid);
	if (ret) {
		LOG_INFO_BDF("sxe2_upgrade_open failed,ret = [%d]\n", ret);
		goto l_close;
	}

	upgd_flash_obj.uuid = uuid;
	upgd_flash_obj.pack_len = pack_len;
	upgd_flash_obj.frag_num = frag_num;
	upgd_flash_obj.fw_type = fw_type;
	upgd_flash_obj.pack_data = pack_data;

	for (frag_index = 0; frag_index < frag_num; frag_index++) {
		upgd_flash_obj.frag_index = frag_index;
		ret = sxe2_upgrade_flash(adapter, &upgd_flash_obj);
		if (ret) {
			LOG_INFO_BDF("sxe2_upgrade_flash frag[%d] failed\n",
				     frag_index);
			goto l_close;
		}
	}

l_close:
	err = (u32)ret;
	ret = sxe2_upgrade_close(adapter, uuid, err);
	if (ret && !err) {
		LOG_INFO_BDF("sxe2_upgrade_close failed, ret = [%d],err = [%d]", ret,
			     err);
		goto l_end;
	} else {
		ret = (s32)err;
	}

l_end:
	kfree(upgd_flash_obj.raw_data);
	return ret;
}

STATIC s32 sxe2_upgd_pkg_header_info_get(struct sxe2_adapter *adapter, u32 fw_type,
					 struct sxe2_pkg_header *pkg_hdr,
					 u8 *pack_data, u32 pack_len)
{
	s32 ret = 0;

	if (pack_len <= sizeof(struct sxe2_pkg_header)) {
		ret = -EINVAL;
		LOG_INFO_BDF("pack_len[%d] <= pack_header[%zd]\n", pack_len,
			     sizeof(struct sxe2_pkg_header));
		goto l_end;
	}
	(void)memcpy(pkg_hdr, pack_data, sizeof(*pkg_hdr));

l_end:
	return ret;
}

STATIC s32 sxe2_upgrade_image(struct sxe2_adapter *adapter, u8 *pkg_data,
			      u32 pkg_len, u32 install_type, u64 uuid)
{
	s32 ret = 0;
	u32 err = 0;
	u8 *data_pos = NULL;
	u8 *fw_data = NULL;
	u32 index = 0;
	u32 fw_len = 0;
	u32 region_type = 0;
	struct sxe2_upgrade_fw_array *fw_arr = NULL;
	struct sxe2_pkg_header pkg_hdr = {};

	fw_arr = kzalloc(sizeof(*fw_arr), GFP_KERNEL);
	if (!fw_arr) {
		ret = -ENOMEM;
		goto l_out;
	}

	data_pos = pkg_data;
	ret = sxe2_upgd_fw_arr_get(adapter, data_pos, pkg_len, install_type, fw_arr);
	if (ret) {
		LOG_INFO_BDF("sxe2_upgd_fw_arr_get failed\n");
		goto final;
	}

	data_pos = pkg_data;
	ret = sxe2_upgd_pkg_header_info_get(adapter, install_type, &pkg_hdr,
					    data_pos, pkg_len);
	if (ret) {
		LOG_INFO_BDF("sxe2_upgd_pkg_header_info_get failed(%d)\n", ret);
		goto final;
	}

	ret = sxe2_upgrade_prepare(adapter, fw_arr, uuid, &pkg_hdr);
	if (ret) {
		LOG_INFO_BDF("sxe2_upgrade_prepare failed(%d)\n", ret);
		goto l_end;
	}

	data_pos = pkg_data;
	for (index = 0; index < fw_arr->fw_cnt; index++) {
		fw_data = data_pos + fw_arr->fw_arr[index].offset;
		fw_len = fw_arr->fw_arr[index].image_len;
		region_type = fw_arr->fw_arr[index].fw_type;

		ret = sxe2_upgrade_data_trans(adapter, fw_data, fw_len, region_type,
					      uuid);
		if (ret) {
			LOG_INFO_BDF("sxe2_upgrade_data_trans failed(%d)\n", ret);
			goto l_end;
		}
	}

l_end:
	err = (u32)ret;
	ret = sxe2_upgrade_end(adapter, err, install_type, uuid);

	if (ret && !err) {
		LOG_INFO_BDF("sxe2_upgrade_end failed");
		goto final;
	} else {
		ret = (s32)err;
	}

final:
	kfree(fw_arr);

l_out:
	return ret;
}

s32 sxe2_flash_package_from_file(struct net_device *dev, const char *file_name,
				 u32 install_type)
{
	s32 ret;
	struct sxe2_netdev_priv *priv = netdev_priv(dev);
	struct sxe2_vsi *vsi = priv->vsi;
	struct sxe2_adapter *adapter = vsi->adapter;
	const struct firmware *fw;
	u64 uuid;

	get_random_bytes(&uuid, sizeof(uuid));

	ret = request_firmware_direct(&fw, file_name, &adapter->pdev->dev);
	if (ret) {
		LOG_INFO_BDF("pkg error %d requesting file: %s\n", ret, file_name);
		goto l_end;
	}

	dev_hold(dev);
	rtnl_unlock();

	ret = sxe2_upgrade_image(adapter, (u8 *)fw->data, fw->size, install_type,
				 uuid);
	if (ret)
		LOG_ERROR_BDF("sxe2 update image failed, ret = %d\n", ret);
	else
		LOG_DEV_INFO("sxe2 update image done!\n");

	release_firmware(fw);

	rtnl_lock();
	dev_put(dev);

l_end:
	return ret;
}
