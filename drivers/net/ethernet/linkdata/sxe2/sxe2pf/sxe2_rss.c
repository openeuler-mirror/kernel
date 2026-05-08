// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_rss.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_rss.h"
#include "sxe2.h"
#include "sxe2_cmd.h"
#include "sxe2_cmd_channel.h"
#include "sxe2_log.h"
#include "sxe2_common.h"
#include "sxe2_flow.h"

static struct sxe2_rss_hash_cfg default_rss_cfg_ip4;
static struct sxe2_rss_hash_cfg default_rss_cfg_tcp4;
static struct sxe2_rss_hash_cfg default_rss_cfg_udp4;
static struct sxe2_rss_hash_cfg default_rss_cfg_sctp4;
static struct sxe2_rss_hash_cfg default_rss_cfg_ip6;
static struct sxe2_rss_hash_cfg default_rss_cfg_tcp6;
static struct sxe2_rss_hash_cfg default_rss_cfg_udp6;
static struct sxe2_rss_hash_cfg default_rss_cfg_sctp6;

static struct sxe2_rss_hash_cfg *default_rss_cfgs[] = {
		&default_rss_cfg_ip4,  &default_rss_cfg_tcp4,
		&default_rss_cfg_udp4, &default_rss_cfg_sctp4,

		&default_rss_cfg_ip6,  &default_rss_cfg_tcp6,
		&default_rss_cfg_udp6, &default_rss_cfg_sctp6,
};

void sxe2_rss_flow_ctxt_init(struct sxe2_adapter *adapter)
{
	struct sxe2_rss_ctxt *rss_flow_ctxt = &adapter->rss_flow_ctxt;

	sxe2_flow_ppp_comm_ctxt_init(&rss_flow_ctxt->ppp, adapter,
				     SXE2_HW_BLOCK_ID_RSS);

	sxe2_rss_comm_init(rss_flow_ctxt);

	LOG_DEBUG_BDF("rss flow context init done");
}

void sxe2_rss_flow_ctxt_deinit(struct sxe2_adapter *adapter)
{
	struct sxe2_rss_ctxt *rss_flow_ctxt = &adapter->rss_flow_ctxt;

	sxe2_flow_ppp_comm_ctxt_deinit(&rss_flow_ctxt->ppp);
	sxe2_rss_comm_deinit(rss_flow_ctxt);

	LOG_DEBUG_BDF("rss flow context deinit done.\n");
}

void sxe2_rss_ctxt_init(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter = vsi->adapter;

	vsi->rss_ctxt.hash_type = SXE2_RSS_HASH_FUNC_TOEPLITZ;
	switch (vsi->type) {
	case SXE2_VSI_T_PF:
		vsi->rss_ctxt.lut_type = SXE2_RSS_PF_LUT;
		vsi->rss_ctxt.lut_size = adapter->caps_ctxt.max_rss_lut_size;
		vsi->rss_ctxt.queue_size =
				min_t(u16, SXE2_PF_LUT_MAX_QUEUE, vsi->rxqs.q_cnt);
		break;
	case SXE2_VSI_T_DPDK_PF:
		vsi->rss_ctxt.lut_type = SXE2_RSS_GLOBAL_LUT;
		vsi->rss_ctxt.lut_size = SXE2_RSS_LUT_SIZE_512;
		vsi->rss_ctxt.global_lut_id = (u8)adapter->caps_ctxt.global_lut_base;
		vsi->rss_ctxt.queue_size = min_t(u16, SXE2_GLOBAL_LUT_MAX_QUEUE,
						 vsi->rxqs.q_cnt);
		break;
	case SXE2_VSI_T_VF:
	case SXE2_VSI_T_DPDK_VF:
		vsi->rss_ctxt.lut_type = SXE2_RSS_VSI_LUT;
		vsi->rss_ctxt.lut_size = SXE2_RSS_LUT_SIZE_64;
		vsi->rss_ctxt.queue_size =
				min_t(u16, SXE2_VSI_LUT_MAX_QUEUE, vsi->rxqs.q_cnt);
		break;
	default:
		LOG_INFO_BDF("unsupport Vsi Type: %u\n", vsi->type);
		break;
	}
	LOG_DEBUG_BDF("rss ctxt init ok, hash type: %u, lut_type: %u, lut_size: %u,\t"
		      "queue_size: %u\n",
		      vsi->rss_ctxt.hash_type, vsi->rss_ctxt.lut_type,
		      vsi->rss_ctxt.lut_size, vsi->rss_ctxt.queue_size);
}

void sxe2_rss_fill_lut(u8 *lut, u16 lut_size, u16 queue_size)
{
	u16 i = 0;

	for (i = 0; i < lut_size; i++)
		lut[i] = (u8)(i % queue_size);
}

static void sxe2_default_rss_cfg_create(void)
{
	default_rss_cfg_ip4.hdr_type = SXE2_RSS_ANY_HEADERS;
	default_rss_cfg_ip4.symm = false;
	set_bit(SXE2_FLOW_HDR_IPV4, default_rss_cfg_ip4.headers);
	set_bit(SXE2_FLOW_FLD_ID_IPV4_SA, default_rss_cfg_ip4.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_IPV4_DA, default_rss_cfg_ip4.hash_flds);

	default_rss_cfg_tcp4.hdr_type = SXE2_RSS_ANY_HEADERS;
	default_rss_cfg_tcp4.symm = false;
	set_bit(SXE2_FLOW_HDR_IPV4, default_rss_cfg_tcp4.headers);
	set_bit(SXE2_FLOW_HDR_TCP, default_rss_cfg_tcp4.headers);
	set_bit(SXE2_FLOW_FLD_ID_IPV4_SA, default_rss_cfg_tcp4.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_IPV4_DA, default_rss_cfg_tcp4.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_TCP_SRC_PORT, default_rss_cfg_tcp4.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_TCP_DST_PORT, default_rss_cfg_tcp4.hash_flds);

	default_rss_cfg_udp4.hdr_type = SXE2_RSS_ANY_HEADERS;
	default_rss_cfg_udp4.symm = false;
	set_bit(SXE2_FLOW_HDR_IPV4, default_rss_cfg_udp4.headers);
	set_bit(SXE2_FLOW_HDR_UDP, default_rss_cfg_udp4.headers);
	set_bit(SXE2_FLOW_FLD_ID_IPV4_SA, default_rss_cfg_udp4.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_IPV4_DA, default_rss_cfg_udp4.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_UDP_SRC_PORT, default_rss_cfg_udp4.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_UDP_DST_PORT, default_rss_cfg_udp4.hash_flds);

	default_rss_cfg_sctp4.hdr_type = SXE2_RSS_ANY_HEADERS;
	default_rss_cfg_sctp4.symm = false;
	set_bit(SXE2_FLOW_HDR_IPV4, default_rss_cfg_sctp4.headers);
	set_bit(SXE2_FLOW_HDR_SCTP, default_rss_cfg_sctp4.headers);
	set_bit(SXE2_FLOW_FLD_ID_IPV4_SA, default_rss_cfg_sctp4.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_IPV4_DA, default_rss_cfg_sctp4.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_SCTP_SRC_PORT, default_rss_cfg_sctp4.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_SCTP_DST_PORT, default_rss_cfg_sctp4.hash_flds);

	default_rss_cfg_ip6.hdr_type = SXE2_RSS_ANY_HEADERS;
	default_rss_cfg_ip6.symm = false;
	set_bit(SXE2_FLOW_HDR_IPV6, default_rss_cfg_ip6.headers);
	set_bit(SXE2_FLOW_FLD_ID_IPV6_SA, default_rss_cfg_ip6.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_IPV6_DA, default_rss_cfg_ip6.hash_flds);

	default_rss_cfg_tcp6.hdr_type = SXE2_RSS_ANY_HEADERS;
	default_rss_cfg_tcp6.symm = false;
	set_bit(SXE2_FLOW_HDR_IPV6, default_rss_cfg_tcp6.headers);
	set_bit(SXE2_FLOW_HDR_TCP, default_rss_cfg_tcp6.headers);
	set_bit(SXE2_FLOW_FLD_ID_IPV6_SA, default_rss_cfg_tcp6.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_IPV6_DA, default_rss_cfg_tcp6.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_TCP_SRC_PORT, default_rss_cfg_tcp6.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_TCP_DST_PORT, default_rss_cfg_tcp6.hash_flds);

	default_rss_cfg_udp6.hdr_type = SXE2_RSS_ANY_HEADERS;
	default_rss_cfg_udp6.symm = false;
	set_bit(SXE2_FLOW_HDR_IPV6, default_rss_cfg_udp6.headers);
	set_bit(SXE2_FLOW_HDR_UDP, default_rss_cfg_udp6.headers);
	set_bit(SXE2_FLOW_FLD_ID_IPV6_SA, default_rss_cfg_udp6.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_IPV6_DA, default_rss_cfg_udp6.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_UDP_SRC_PORT, default_rss_cfg_udp6.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_UDP_DST_PORT, default_rss_cfg_udp6.hash_flds);

	default_rss_cfg_sctp6.hdr_type = SXE2_RSS_ANY_HEADERS;
	default_rss_cfg_sctp6.symm = false;
	set_bit(SXE2_FLOW_HDR_IPV6, default_rss_cfg_sctp6.headers);
	set_bit(SXE2_FLOW_HDR_SCTP, default_rss_cfg_sctp6.headers);
	set_bit(SXE2_FLOW_FLD_ID_IPV6_SA, default_rss_cfg_sctp6.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_IPV6_DA, default_rss_cfg_sctp6.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_SCTP_SRC_PORT, default_rss_cfg_sctp6.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_SCTP_DST_PORT, default_rss_cfg_sctp6.hash_flds);
}

s32 sxe2_rss_default_flow_set(struct sxe2_vsi *vsi)
{
	u32 i, j;
	s32 ret = 0;
	s32 ret_tmp;
	struct sxe2_rss_hash_cfg *cfg;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_rss_ctxt *rss_flow_ctxt = &adapter->rss_flow_ctxt;

	if (sxe2_is_safe_mode(adapter)) {
		LOG_ERROR_BDF("sxe2 rss is in safe mode, not support.\n");
		return -EINVAL;
	}

	sxe2_default_rss_cfg_create();

	for (i = 0; i < ARRAY_SIZE(default_rss_cfgs); i++) {
		cfg = default_rss_cfgs[i];
		ret_tmp = sxe2_add_rss_flow(rss_flow_ctxt, vsi->id_in_pf, cfg);
		if (ret_tmp) {
			LOG_ERROR_BDF("rss flow[%u] add failed, ret: %d, type:%d,\t"
				      "symm:%d\n",
				      i, ret_tmp, cfg->hdr_type, cfg->symm);
			LOG_ERROR_BDF("headers[%lu]:\n",
				      BITS_TO_LONGS(SXE2_FLOW_HDR_MAX));
			for (j = 0; j < BITS_TO_LONGS(SXE2_FLOW_HDR_MAX); j++) {
				LOG_ERROR_BDF("headers[%u] = 0x%lx\n", j,
					      cfg->headers[j]);
			}
			LOG_ERROR_BDF("hash_flds[%lu]:\n",
				      BITS_TO_LONGS(SXE2_FLOW_FLD_ID_MAX));
			for (j = 0; j < BITS_TO_LONGS(SXE2_FLOW_FLD_ID_MAX); j++) {
				LOG_ERROR_BDF("hash_flds[%u] = 0x%lx\n", j,
					      cfg->hash_flds[j]);
			}
		}
		ret |= ret_tmp;
	}

	return ret;
}

void sxe2_rss_vsi_flow_clean(struct sxe2_vsi *vsi)
{
	struct sxe2_adapter *adapter = vsi->adapter;

	if (sxe2_is_safe_mode(adapter)) {
		LOG_DEV_ERR("sxe2 rss in safe mode is not supported.\n");
		return;
	}
	(void)sxe2_rss_delete_vsi_flows(&adapter->rss_flow_ctxt, vsi->id_in_pf);
}

s32 sxe2_fwc_rss_hash_ctrl_set(struct sxe2_vsi *vsi)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_cmd_params cmd = {0};
	struct sxe2_rss_vsi_hctrl hctrl = {0};

	hctrl.vsi_hw_id = cpu_to_le16(vsi->idx_in_dev);
	hctrl.hash_type = vsi->rss_ctxt.hash_type;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_RSS_VSI_HCTRL_SET, &hctrl,
				  sizeof(hctrl), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("vsi hash ctrl set cmd fail, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

s32 sxe2_fwc_rss_lut_set(struct sxe2_vsi *vsi, u8 *lut, u16 lut_size)
{
	s32 ret = 0;
	u16 buff_size = sizeof(struct sxe2_rss_lut_cfg) + lut_size;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_cmd_params cmd = {0};
	struct sxe2_rss_lut_cfg *lut_cfg = NULL;

	if (lut_size > vsi->rss_ctxt.lut_size) {
		LOG_ERROR_BDF("lut size = %u is invalid!\n", lut_size);
		return -EINVAL;
	}

	lut_cfg = kzalloc(buff_size, GFP_KERNEL);
	if (!lut_cfg) {
		LOG_ERROR_BDF("no memory!\n");
		return -ENOMEM;
	}
	lut_cfg->vsi_hw_id = cpu_to_le16(vsi->idx_in_dev);
	lut_cfg->lut_type = vsi->rss_ctxt.lut_type;
	lut_cfg->global_lut_id = 0;
	if (vsi->rss_ctxt.lut_type == SXE2_RSS_GLOBAL_LUT)
		lut_cfg->global_lut_id = vsi->rss_ctxt.global_lut_id;

	lut_cfg->lut_size = cpu_to_le16(lut_size);
	memcpy(lut_cfg->lut, lut, lut_size);

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_RSS_LUT_SET, lut_cfg, buff_size,
				  NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("rss lut set cmd fail, ret=%d\n", ret);
		ret = -EIO;
	}

	kfree(lut_cfg);
	return ret;
}

s32 sxe2_fwc_rss_lut_get(struct sxe2_vsi *vsi, u8 *lut, u16 lut_size)
{
	s32 ret = 0;
	u16 buff_size = sizeof(struct sxe2_rss_lut_cfg) + lut_size;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_cmd_params cmd = {0};
	struct sxe2_rss_lut_cfg *lut_cfg = NULL;

	if (!lut)
		return -EINVAL;

	lut_cfg = kzalloc(buff_size, GFP_KERNEL);
	if (!lut_cfg) {
		LOG_ERROR_BDF("no memory!\n");
		return -ENOMEM;
	}
	lut_cfg->vsi_hw_id = cpu_to_le16(vsi->idx_in_dev);
	lut_cfg->lut_type = vsi->rss_ctxt.lut_type;
	lut_cfg->global_lut_id = 0;
	lut_cfg->lut_size = cpu_to_le16(lut_size);

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_RSS_LUT_GET, lut_cfg, buff_size,
				  lut_cfg, buff_size);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("rss lut set cmd fail, ret=%d\n", ret);
		ret = -EIO;
	}

	memcpy(lut, lut_cfg->lut, lut_size);

	kfree(lut_cfg);
	return ret;
}

s32 sxe2_fwc_rss_hkey_set(struct sxe2_vsi *vsi, u8 *hkey)
{
	s32 ret = 0;
	u8 i;
	u16 buff_size = sizeof(struct sxe2_rss_hkey_cfg) + SXE2_RSS_HASH_KEY_SIZE;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_cmd_params cmd = {0};
	struct sxe2_rss_hkey_cfg *hkey_cfg = NULL;

	hkey_cfg = kzalloc(buff_size, GFP_KERNEL);
	if (!hkey_cfg) {
		LOG_ERROR_BDF("no memory!\n");
		return -ENOMEM;
	}
	hkey_cfg->vsi_hw_id = cpu_to_le16(vsi->idx_in_dev);

	for (i = 0; i < SXE2_RSS_HASH_KEY_SIZE; i++)
		hkey_cfg->key[i] = hkey[i];

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_RSS_HKEY_SET, hkey_cfg, buff_size,
				  NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("rss hash key set cmd fail, ret=%d\n", ret);
		ret = -EIO;
	}

	kfree(hkey_cfg);
	return ret;
}

s32 sxe2_fwc_rss_hkey_get(struct sxe2_vsi *vsi, u8 *hkey)
{
	s32 ret = 0;
	u16 buff_size = sizeof(struct sxe2_rss_hkey_cfg) + SXE2_RSS_HASH_KEY_SIZE;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_cmd_params cmd = {0};
	struct sxe2_rss_hkey_cfg *hkey_cfg = NULL;

	if (!hkey)
		return -EINVAL;

	hkey_cfg = kzalloc(buff_size, GFP_KERNEL);
	if (!hkey_cfg) {
		LOG_ERROR_BDF("no memory!\n");
		return -ENOMEM;
	}
	hkey_cfg->vsi_hw_id = cpu_to_le16(vsi->idx_in_dev);

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_RSS_HKEY_GET, hkey_cfg, buff_size,
				  hkey_cfg, buff_size);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("rss hash key get cmd fail, ret=%d\n", ret);
		ret = -EIO;
	}

	memcpy(hkey, hkey_cfg->key, SXE2_RSS_HASH_KEY_SIZE);

	kfree(hkey_cfg);
	return ret;
}

void sxe2_fwc_rss_trace_trigger(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {0};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_RSS_TRACE_TRIGGER, NULL, 0, NULL,
				  0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret)
		LOG_ERROR_BDF("rss trace trigger cmd fail, ret=%d\n", ret);
}

void sxe2_fwc_rss_trace_recorder(struct sxe2_adapter *adapter)
{
	s32 ret;
	s32 i = 0;
	struct sxe2_cmd_params cmd = {0};
	struct sxe2_rss_trace_recorder recorder = {0};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_RSS_TRACE_RECORDER, NULL, 0,
				  &recorder, sizeof(struct sxe2_rss_trace_recorder));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("rss trace recorder cmd fail, ret=%d\n", ret);
		return;
	}

	LOG_DEV_INFO("****rss trace recorder start****");
	LOG_DEV_INFO("status0: %u\n", recorder.trace_status0);
	if (recorder.trace_status0 == 0) {
		LOG_DEV_INFO("profile_id0: 0x%08X\n",
			     __le32_to_cpu(recorder.profile_id0));
		for (i = 0; i < SXE2_RSS_FV_TRACE_CNT; i++) {
			LOG_DEV_INFO("fv[%d]: 0x%08X\n", i,
				     __le32_to_cpu(recorder.fv[i]));
		}
	}
	LOG_DEV_INFO("status1: %u\n", recorder.trace_status1);
	if (recorder.trace_status1 == 0)
		LOG_DEV_INFO("hash1: 0x%08X\n", __le32_to_cpu(recorder.hash1));

	LOG_DEV_INFO("status2: %u\n", recorder.trace_status2);
	if (recorder.trace_status2 == 0) {
		LOG_DEV_INFO("hash2: 0x%08X\n", __le32_to_cpu(recorder.hash2));
		LOG_DEV_INFO("profile_id2: %u\n", recorder.profile_id2);
		LOG_DEV_INFO("bad_profile: %u\n", recorder.bad_profile);
		LOG_DEV_INFO("q_index: %u\n", __le16_to_cpu(recorder.q_index));
		LOG_DEV_INFO("thread_id: %u\n", recorder.thread_id);
		LOG_DEV_INFO("vsi: %u\n", __le16_to_cpu(recorder.vsi));
	}
	LOG_DEV_INFO("****rss trace recorder end****");
}

u16 sxe2_rss_queue_size_correct(u16 new_size)
{
	return (u16)min_t(u16, SXE2_PF_LUT_MAX_QUEUE, new_size);
}

s32 sxe2_rss_lut_reset(struct sxe2_vsi *vsi, u16 queue_size)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;
	u8 *lut = NULL;
	u16 new_queue_size = 0;

	if (queue_size == 0) {
		LOG_ERROR_BDF("invalid queue size!");
		return -EINVAL;
	}

	lut = kzalloc(vsi->rss_ctxt.lut_size, GFP_KERNEL);
	if (!lut) {
		ret = -ENOMEM;
		LOG_ERROR_BDF("no memory!\n");
		goto l_lut_alloc_failed;
	}

	new_queue_size = sxe2_rss_queue_size_correct(queue_size);

	sxe2_rss_fill_lut(lut, vsi->rss_ctxt.lut_size, new_queue_size);
	ret = sxe2_fwc_rss_lut_set(vsi, lut, vsi->rss_ctxt.lut_size);
	if (ret != 0) {
		LOG_ERROR_BDF("sxe2_rss_lut_set failed, ret: %d, lut: %p, lut_size:\t"
			      "%u\n",
			      ret, lut, vsi->rss_ctxt.lut_size);
		goto l_lut_free;
	}

	vsi->rss_ctxt.queue_size = new_queue_size;
	if (vsi->rss_ctxt.lut) {
		memcpy(vsi->rss_ctxt.lut, lut, vsi->rss_ctxt.lut_size);
		LOG_DEV_INFO("rx queue size change, clearing user lut,\n"
			     "re-run ethtool [-x|-X] to [check|set] settings if\t"
			     "needed.\n");
	}

l_lut_free:
	kfree(lut);
l_lut_alloc_failed:
	return ret;
}

s32 sxe2_rss_ptg_parse_from_ddp(u8 *data, u16 cnt, u16 base_id,
				struct sxe2_adapter *adapter)
{
	u16 i = 0;
	u16 j = 0;
	u16 table_idx = 0;
	s32 ret = 0;
	u16 per_size = 0;
	u16 ddp_max_cnt;
	u8 port_idx = adapter->port_idx;

	per_size = sizeof(struct sxe2_ddp_rxft_ptg);
	ddp_max_cnt = (SXE2_MAX_PTYPE_NUM * SXE2_MAX_CDID_NUM) / per_size;
	if (!data || base_id >= ddp_max_cnt || cnt > ddp_max_cnt) {
		LOG_ERROR_BDF("sxe2 rss ptg parse from ddp failed, port_idx=%u !\n",
			      port_idx);
		ret = -EINVAL;
		goto l_end;
	}

	table_idx = (u16)((u32)base_id * per_size);
	for (i = 0; i < cnt; i++) {
		for (j = 0; j < per_size; j++) {
			if (table_idx >= (port_idx * SXE2_MAX_PTYPE_NUM) &&
			    table_idx < ((port_idx + 1) * SXE2_MAX_PTYPE_NUM)) {
				adapter->rss_flow_ctxt.ppp
						.pt_to_grp[table_idx %
							   SXE2_MAX_PTYPE_NUM]
						.idx = *data;
			}
			table_idx++;
			data++;
		}
	}
	LOG_INFO_BDF("sxe2 rss ptg parse from ddp, port_idx=%u !\n", port_idx);

l_end:
	return ret;
}

void sxe2_rss_xlt2_dump(struct sxe2_adapter *adapter)
{
	sxe2_flow_xlt2_dump(&adapter->rss_flow_ctxt.ppp);
}

void sxe2_rss_vsig_dump(struct sxe2_adapter *adapter)
{
	sxe2_flow_vsig_dump(&adapter->rss_flow_ctxt.ppp);
}

void sxe2_rss_prof_dump(struct sxe2_adapter *adapter)
{
	sxe2_flow_prof_dump(&adapter->rss_flow_ctxt.ppp);
}

void sxe2_rss_mask_dump(struct sxe2_adapter *adapter)
{
	sxe2_flow_mask_dump(&adapter->rss_flow_ctxt.ppp);
}
