// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_ddp.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_common.h"
#include "sxe2_log.h"
#include "sxe2_cmd.h"
#include "sxe2_ddp.h"
#include "sxe2_sriov.h"
#include "sxe2_fnav.h"
#include "sxe2_rss.h"
#include "sxe2_netdev.h"
#include "sxe2_acl.h"

#define SXE2_WAIT_BUSY_DONE_TIMEOUT 300

struct sxe2_ddp_data_parse g_ddp_parse_table[] = {
		{SXE2_SECT_RSSPTG_TYPE, sxe2_rss_ptg_parse_from_ddp},
		{SXE2_SECT_FNAVPTG_TYPE, sxe2_fnav_ptg_parse_from_ddp},
		{SXE2_SECT_FNAVMASK_TYPE, sxe2_fnav_mask_parse_from_ddp},
		{SXE2_SECT_SWEXTRACTOR_TYPE, sxe2_sw_profile_parse_from_ddp},
		{SXE2_SECT_ACLPTG_TYPE, sxe2_acl_ptg_parse_from_ddp},
};

STATIC s32 sxe2_verify_pkg(struct sxe2_adapter *adapter, struct sxe2_pkg_hdr *hdr)
{
	s32 err = SXE2_DDP_PKG_SUCCESS;

	if (hdr->pkg_drv_ver.major > SXE2_DDP_DRV_VER_MAJ) {
		LOG_INFO_BDF("file version(%d) too high.\n", hdr->pkg_drv_ver.major);
		err = -SXE2_DDP_PKG_FILE_VERSION_TOO_HIGH;
	}

	if (hdr->seg_count == 0) {
		err = -SXE2_DDP_PKG_INVALID_FILE;
		LOG_INFO_BDF("file have no segment.\n");
	}

	return err;
}

struct sxe2_buf_table *sxe2_get_buf_table(struct sxe2_seg *sxe2_seg)
{
	return &sxe2_seg->buf_table;
}

struct sxe2_seg *sxe2_get_pkg_segment(struct sxe2_pkg_hdr *hdr,
				      enum sxe2_segment_type type)
{
	struct sxe2_seg *seg = NULL;
	u32 seg_count = hdr->seg_count;
	u32 i;
	u32 offset;
	u64 hdr_size = sizeof(struct sxe2_pkg_hdr) + seg_count * sizeof(__le32);

	for (i = 0; i < seg_count; i++) {
		offset = hdr->seg_offset[i];
		if (offset < hdr_size)
			return NULL;

		seg = (struct sxe2_seg *)((u8 *)hdr + offset);
		if (seg->hdr.seg_type == type)
			return seg;
	}

	return NULL;
}

s32 sxe2_ddp_pre_deal(struct sxe2_adapter *adapter, struct sxe2_pkg_hdr *hdr)
{
	s32 ret;
	struct sxe2_fwc_ddp_state ddp_state = {};
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_DP_DLD_PRE, (void *)hdr,
				  sizeof(*hdr), &ddp_state, sizeof(ddp_state));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("get ddp pre failed, ret=%d\n", ret);
		if (ret != -SXE2_DDP_PKG_BUSY)
			ret = -SXE2_DDP_PKG_ERR;
		goto l_end;
	}

	if (ddp_state.state == SXE2_DDP_STATE_UNINIT) {
		ret = SXE2_DDP_PKG_SUCCESS;
	} else if (ddp_state.state == SXE2_DDP_STATE_PROC) {
		LOG_INFO_BDF("code(%d) error, ddp failed.\n", ddp_state.state);
		ret = -SXE2_DDP_PKG_BUSY;
	} else {
		ret = -SXE2_DDP_PKG_ERR;
	}

l_end:
	return ret;
}

s32 sxe2_ddp_proc_deal(struct sxe2_adapter *adapter, struct sxe2_buf *buffer)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_DP_DLD_PROC, buffer,
				  sizeof(*buffer), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("ddp process failed, ret=%d\n", ret);
		if (ret != -SXE2_DDP_PKG_BUSY)
			ret = -SXE2_DDP_PKG_ERR;
	}

	return ret;
}

s32 sxe2_ddp_deal_done(struct sxe2_adapter *adapter, s32 result)
{
	s32 ret;
	struct sxe2_fwc_ddp_state ddp_state = {};
	struct sxe2_cmd_params cmd = {};
	__le32 res = cpu_to_le32((u32)result);

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_DP_DLD_DONE, &res, sizeof(res),
				  &ddp_state, sizeof(ddp_state));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("get ddp done failed, ret=%d\n", ret);
		if (ret != -SXE2_DDP_PKG_BUSY)
			ret = -SXE2_DDP_PKG_ERR;
		goto l_end;
	}

	if (ddp_state.state == SXE2_DDP_STATE_FINISH) {
		ret = SXE2_DDP_PKG_SUCCESS;
	} else {
		LOG_WARN_BDF("code(%d) error, ddp failed.\n", ddp_state.state);
		ret = -SXE2_DDP_PKG_ERR;
	}

l_end:
	return ret;
}

s32 sxe2_ddp_acquire_state(struct sxe2_adapter *adapter, struct sxe2_pkg_hdr *hdr)
{
	s32 ret;
	struct sxe2_fwc_ddp_state ddp_state = {};
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_DP_DLD_STATE, NULL, 0, &ddp_state,
				  sizeof(ddp_state));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("get ddp state failed, ret=%d\n", ret);
		ret = -SXE2_DDP_PKG_ERR;
		goto l_end;
	}

	if (ddp_state.state == SXE2_DDP_STATE_PROC) {
		ret = -SXE2_DDP_PKG_BUSY;
	} else if (ddp_state.state == SXE2_DDP_STATE_FINISH) {
		if (hdr) {
			if ((__le16)((hdr->pkg_fw_ver.major << 8) +
				     hdr->pkg_fw_ver.minor) == ddp_state.ver) {
				ret = -SXE2_DDP_PKG_SAME_VERSION_ALREADY_LOADED;
			} else {
				ret = -SXE2_DDP_PKG_COMPATIBLE_ALREADY_LOADED;
			}
		} else {
			ret = -SXE2_DDP_PKG_ALREADY_LOADED;
		}

	} else if (ddp_state.state == SXE2_DDP_STATE_ERROR) {
		ret = -SXE2_DDP_PKG_ALREADY_LOADED_NOT_SUPPORTED;
	} else if (ddp_state.state == SXE2_DDP_STATE_UNINIT) {
		ret = SXE2_DDP_PKG_SUCCESS;
	} else {
		LOG_DEV_WARN("code(%d) error, unexpected running branch.\n",
			     ddp_state.state);
		ret = -SXE2_DDP_PKG_ERR;
	}

l_end:
	return ret;
}

s32 sxe2_init_pkg(struct sxe2_adapter *adapter, u8 *buff, u32 len)
{
	s32 err;
	s32 rc = SXE2_DDP_PKG_SUCCESS;
	struct sxe2_pkg_hdr *hdr = (struct sxe2_pkg_hdr *)buff;
	struct sxe2_seg *seg = NULL;
	struct sxe2_buf_table *buf_table;
	u32 i = 0;
	u16 timeout = SXE2_WAIT_BUSY_DONE_TIMEOUT;

	if (len < SXE2_MIN_CFG_SZ) {
		rc = -SXE2_DDP_PKG_INVALID_FILE;
		goto end;
	}

	err = sxe2_verify_pkg(adapter, hdr);
	if (err) {
		rc = err;
		LOG_WARN_BDF("failed to verify pkg (err: %d)\n", err);
		goto end;
	}

	seg = sxe2_get_pkg_segment(hdr, SXE2_SGM_BLK_DP);
	if (!seg) {
		LOG_WARN_BDF("can not find segment ptr.\n");
		rc = -SXE2_DDP_PKG_MANIFEST_INVALID;
		goto end;
	}

	err = sxe2_ddp_pre_deal(adapter, hdr);
	if (err == -SXE2_DDP_PKG_BUSY) {
		do {
			(void)msleep(SXE2_DDP_DELAY_100MS);
			err = sxe2_ddp_acquire_state(adapter, hdr);
			i++;
			if (i > timeout) {
				err = -SXE2_DDP_PKG_ERR;
				break;
			}
		} while (err == -SXE2_DDP_PKG_BUSY);

		if (sxe2_is_init_pkg_successful(err)) {
			rc = err;
			goto end;
		}
	}

	if (!sxe2_is_init_pkg_successful(err)) {
		LOG_WARN_BDF("failed to download pkg (err: %d)\n", err);
		goto notify;
	}

	buf_table = sxe2_get_buf_table(seg);
	for (i = 0; i < buf_table->buf_count; i++) {
		err = sxe2_ddp_proc_deal(adapter, &buf_table->buf_array[i]);
		if (err)
			break;
	}

notify:
	if (!sxe2_is_init_pkg_successful(err))
		rc = err;

	err = sxe2_ddp_deal_done(adapter, err);
	if (err)
		rc = err;
end:
	return rc;
}

s32 sxe2_copy_and_init_pkg(struct sxe2_adapter *adapter, const u8 *buf, u32 len)
{
	s32 err;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);
	u8 *buf_copy;
	struct sxe2_hw *hw = &adapter->hw;

	if (!buf || !len)
		return -SXE2_DDP_PKG_ERR;

	buf_copy = devm_kmemdup(dev, buf, len, GFP_KERNEL);
	if (!buf_copy) {
		LOG_ERROR_BDF("failed to alloc ddp cfg memory\n");
		return -SXE2_DDP_PKG_ERR;
	}

	err = sxe2_init_pkg(adapter, buf_copy, len);
	if (!sxe2_is_init_pkg_successful(err)) {
		devm_kfree(dev, buf_copy);
	} else {
		hw->pkg_copy = buf_copy;
		hw->pkg_size = len;
	}

	return err;
}

bool sxe2_is_init_pkg_successful(s32 state)
{
	switch (state) {
	case SXE2_DDP_PKG_SUCCESS:
	case -SXE2_DDP_PKG_ALREADY_LOADED:
	case -SXE2_DDP_PKG_SAME_VERSION_ALREADY_LOADED:
	case -SXE2_DDP_PKG_COMPATIBLE_ALREADY_LOADED:
		return true;
	default:
		return false;
	}
}

void sxe2_free_seg(struct sxe2_adapter *adapter)
{
	struct sxe2_hw *hw = &adapter->hw;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);

	if (hw->pkg_copy) {
		devm_kfree(dev, hw->pkg_copy);
		hw->pkg_copy = NULL;
		hw->pkg_size = 0;
	}
}

s32 sxe2_ddp_rebuild(struct sxe2_adapter *adapter)
{
	s32 ret = SXE2_DDP_PKG_SUCCESS;

	if (!sxe2_is_safe_mode(adapter)) {
		do {
			ret = sxe2_ddp_acquire_state(adapter, NULL);
			if (ret == -SXE2_DDP_PKG_ALREADY_LOADED) {
				LOG_DEBUG_BDF("pkg has already download in \t"
					      "device.\n");
				ret = SXE2_DDP_PKG_SUCCESS;
				break;
			} else if (ret == -SXE2_DDP_PKG_ALREADY_LOADED_NOT_SUPPORTED ||
				   ret == SXE2_DDP_PKG_SUCCESS) {
				sxe2_load_pkg(NULL, adapter);
				if (sxe2_is_safe_mode(adapter)) {
					LOG_DEV_ERR("failed to reload DDP \t"
						    "Package.\n");
					set_bit(SXE2_FLAG_ADVANCE_MODE,
						adapter->flags);
					ret = -EIO;
				}
				break;
			} else if (ret == -SXE2_DDP_PKG_BUSY) {
				msleep(SXE2_DDP_DELAY_100MS);
				continue;
			} else {
				LOG_DEV_ERR("pkg process err in device.(%d)\n", ret);
				break;
			}
		} while (1);
	}

	return ret;
}

STATIC s32 sxe2_ddp_store_by_type(struct sxe2_adapter *adapter, u16 type, u8 *data,
				  u16 size, u16 base_id)
{
	s32 rc = 0;
	u32 index;
	u32 table_size = (sizeof(g_ddp_parse_table) /
			  sizeof(struct sxe2_ddp_data_parse));
	sxe2_ddp_data_parse_cb cb = NULL;

	for (index = 0; index < table_size; index++) {
		if (g_ddp_parse_table[index].sec_type == type) {
			cb = g_ddp_parse_table[index].cb;
			break;
		}
	}

	if (cb) {
		rc = cb(data, size, base_id, adapter);
		if (rc) {
			LOG_INFO_BDF("ddp data store failed! size[%d] base_id[%d] \t"
				     "type[%d]\n",
				     size, base_id, type);
		}
	} else {
		LOG_DEBUG_BDF("ddp data[%d] do not need store!\n", type);
	}

	return rc;
}

s32 sxe2_ddp_params_store(struct sxe2_adapter *adapter)
{
	s32 rc = 0;
	u32 buf_cnt;
	u16 sec_cnt;
	struct sxe2_hw *hw = &adapter->hw;
	struct sxe2_pkg_hdr *hdr = (struct sxe2_pkg_hdr *)hw->pkg_copy;
	struct sxe2_seg *seg = NULL;
	struct sxe2_buf_table *buf_table;
	struct sxe2_section_entry *sec_entry;
	u16 base_id = 0;
	u16 unit_cnt = 0;
	u16 cur_type = SXE2_INVAL_U16;

	if (sxe2_is_safe_mode(adapter)) {
		LOG_WARN_BDF("running in safe mode.\n");
		goto end;
	}

	if (!hdr) {
		LOG_WARN_BDF("buffer is nullptr!\n");
		return -EINVAL;
	}

	seg = sxe2_get_pkg_segment(hdr, SXE2_SGM_BLK_DP);
	if (!seg) {
		LOG_WARN_BDF("can not find segment ptr.\n");
		rc = -SXE2_DDP_PKG_MANIFEST_INVALID;
		goto end;
	}

	buf_table = sxe2_get_buf_table(seg);

	for (buf_cnt = 0; buf_cnt < buf_table->buf_count; buf_cnt++) {
		struct sxe2_buf_hdr *buffer_hdr =
				(struct sxe2_buf_hdr *)buf_table->buf_array[buf_cnt]
						.buf;

		for (sec_cnt = 0; sec_cnt < buffer_hdr->section_count; sec_cnt++) {
			sec_entry = &buffer_hdr->section_entry[sec_cnt];
			if (sec_entry->unit_size == 0) {
				LOG_WARN_BDF("ddp file[%d] is invalid.\n", sec_cnt);
				rc = -SXE2_DDP_PKG_BUFFER_INVALID;
				break;
			}

			if (cur_type != sec_entry->type) {
				base_id = 0;
				cur_type = sec_entry->type;
			}

			unit_cnt = (sec_entry->size / sec_entry->unit_size);
			rc = sxe2_ddp_store_by_type(adapter, sec_entry->type,
						    (u8 *)buffer_hdr + sec_entry->offset,
						    unit_cnt, base_id);
			if (rc) {
				LOG_WARN_BDF("ddp data type[%d] base[%d] count[%d] \t"
					     "store failed.\n",
					     cur_type, base_id, unit_cnt);
				break;
			}
			base_id += unit_cnt;
		}
	}
end:
	return rc;
}
