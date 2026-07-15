// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_rxft.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/bitmap.h>
#include "sxe2vf.h"
#include "sxe2vf_ethtool.h"
#include "sxe2_log.h"
#include "sxe2_version.h"
#include "sxe2_mbx_public.h"

static struct sxe2vf_rss_hash_cfg default_vf_rss_cfg_ip4;
static struct sxe2vf_rss_hash_cfg default_vf_rss_cfg_tcp4;
static struct sxe2vf_rss_hash_cfg default_vf_rss_cfg_udp4;
static struct sxe2vf_rss_hash_cfg default_vf_rss_cfg_sctp4;
static struct sxe2vf_rss_hash_cfg default_vf_rss_cfg_ip6;
static struct sxe2vf_rss_hash_cfg default_vf_rss_cfg_tcp6;
static struct sxe2vf_rss_hash_cfg default_vf_rss_cfg_udp6;
static struct sxe2vf_rss_hash_cfg default_vf_rss_cfg_sctp6;

static struct sxe2vf_rss_hash_cfg *default_vf_rss_cfgs[] = {
		&default_vf_rss_cfg_ip4,  &default_vf_rss_cfg_tcp4,
		&default_vf_rss_cfg_udp4, &default_vf_rss_cfg_sctp4,

		&default_vf_rss_cfg_ip6,  &default_vf_rss_cfg_tcp6,
		&default_vf_rss_cfg_udp6, &default_vf_rss_cfg_sctp6,
};

static void sxe2vf_default_rss_cfg_create(void)
{
	default_vf_rss_cfg_ip4.symm = false;
	set_bit(SXE2_FLOW_HDR_IPV4, default_vf_rss_cfg_ip4.headers);
	set_bit(SXE2_FLOW_FLD_ID_IPV4_SA, default_vf_rss_cfg_ip4.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_IPV4_DA, default_vf_rss_cfg_ip4.hash_flds);

	default_vf_rss_cfg_tcp4.symm = false;
	set_bit(SXE2_FLOW_HDR_IPV4, default_vf_rss_cfg_tcp4.headers);
	set_bit(SXE2_FLOW_HDR_TCP, default_vf_rss_cfg_tcp4.headers);
	set_bit(SXE2_FLOW_FLD_ID_IPV4_SA, default_vf_rss_cfg_tcp4.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_IPV4_DA, default_vf_rss_cfg_tcp4.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_TCP_SRC_PORT, default_vf_rss_cfg_tcp4.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_TCP_DST_PORT, default_vf_rss_cfg_tcp4.hash_flds);

	default_vf_rss_cfg_udp4.symm = false;
	set_bit(SXE2_FLOW_HDR_IPV4, default_vf_rss_cfg_udp4.headers);
	set_bit(SXE2_FLOW_HDR_UDP, default_vf_rss_cfg_udp4.headers);
	set_bit(SXE2_FLOW_FLD_ID_IPV4_SA, default_vf_rss_cfg_udp4.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_IPV4_DA, default_vf_rss_cfg_udp4.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_UDP_SRC_PORT, default_vf_rss_cfg_udp4.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_UDP_DST_PORT, default_vf_rss_cfg_udp4.hash_flds);

	default_vf_rss_cfg_sctp4.symm = false;
	set_bit(SXE2_FLOW_HDR_IPV4, default_vf_rss_cfg_sctp4.headers);
	set_bit(SXE2_FLOW_HDR_SCTP, default_vf_rss_cfg_sctp4.headers);
	set_bit(SXE2_FLOW_FLD_ID_IPV4_SA, default_vf_rss_cfg_sctp4.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_IPV4_DA, default_vf_rss_cfg_sctp4.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_SCTP_SRC_PORT, default_vf_rss_cfg_sctp4.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_SCTP_DST_PORT, default_vf_rss_cfg_sctp4.hash_flds);

	default_vf_rss_cfg_ip6.symm = false;
	set_bit(SXE2_FLOW_HDR_IPV6, default_vf_rss_cfg_ip6.headers);
	set_bit(SXE2_FLOW_FLD_ID_IPV6_SA, default_vf_rss_cfg_ip6.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_IPV6_DA, default_vf_rss_cfg_ip6.hash_flds);

	default_vf_rss_cfg_tcp6.symm = false;
	set_bit(SXE2_FLOW_HDR_IPV6, default_vf_rss_cfg_tcp6.headers);
	set_bit(SXE2_FLOW_HDR_TCP, default_vf_rss_cfg_tcp6.headers);
	set_bit(SXE2_FLOW_FLD_ID_IPV6_SA, default_vf_rss_cfg_tcp6.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_IPV6_DA, default_vf_rss_cfg_tcp6.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_TCP_SRC_PORT, default_vf_rss_cfg_tcp6.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_TCP_DST_PORT, default_vf_rss_cfg_tcp6.hash_flds);

	default_vf_rss_cfg_udp6.symm = false;
	set_bit(SXE2_FLOW_HDR_IPV6, default_vf_rss_cfg_udp6.headers);
	set_bit(SXE2_FLOW_HDR_UDP, default_vf_rss_cfg_udp6.headers);
	set_bit(SXE2_FLOW_FLD_ID_IPV6_SA, default_vf_rss_cfg_udp6.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_IPV6_DA, default_vf_rss_cfg_udp6.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_UDP_SRC_PORT, default_vf_rss_cfg_udp6.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_UDP_DST_PORT, default_vf_rss_cfg_udp6.hash_flds);

	default_vf_rss_cfg_sctp6.symm = false;
	set_bit(SXE2_FLOW_HDR_IPV6, default_vf_rss_cfg_sctp6.headers);
	set_bit(SXE2_FLOW_HDR_SCTP, default_vf_rss_cfg_sctp6.headers);
	set_bit(SXE2_FLOW_FLD_ID_IPV6_SA, default_vf_rss_cfg_sctp6.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_IPV6_DA, default_vf_rss_cfg_sctp6.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_SCTP_SRC_PORT, default_vf_rss_cfg_sctp6.hash_flds);
	set_bit(SXE2_FLOW_FLD_ID_SCTP_DST_PORT, default_vf_rss_cfg_sctp6.hash_flds);
}

struct sxe2vf_rss_cfg *sxe2vf_find_rss_cfg_by_hdrs(struct sxe2vf_adapter *adapter,
						   unsigned long *hdrs)
{
	struct sxe2vf_rss_cfg *rss_cfg = NULL;

	if (list_empty(&adapter->rss_ctxt.rss_cfgs))
		goto l_out;

	list_for_each_entry(rss_cfg, &adapter->rss_ctxt.rss_cfgs, l_node) {
		if (bitmap_equal(rss_cfg->hash_cfg.headers, hdrs,
				 SXE2_FLOW_HDR_MAX)) {
			goto l_out;
		}
	}
	rss_cfg = NULL;
l_out:
	return rss_cfg;
}

STATIC void
sxe2vf_rss_hash_cfg_convert_hash_msg(struct sxe2vf_rss_hash_cfg *hash_cfg,
				     struct sxe2_vf_rss_hash_msg *rss_hash_msg)
{
	u32 tmp_headers[BITS_TO_U32(SXE2_FLOW_HDR_MAX)];
	u32 tmp_flds[BITS_TO_U32(SXE2_FLOW_FLD_ID_MAX)];
	u32 i = 0;

	bitmap_to_arr32(tmp_headers, hash_cfg->headers, SXE2_FLOW_HDR_MAX);
	bitmap_to_arr32(tmp_flds, hash_cfg->hash_flds, SXE2_FLOW_FLD_ID_MAX);

	for (i = 0; i < BITS_TO_U32(SXE2_FLOW_HDR_MAX); i++)
		rss_hash_msg->headers[i] = cpu_to_le32(tmp_headers[i]);

	for (i = 0; i < BITS_TO_U32(SXE2_FLOW_FLD_ID_MAX); i++)
		rss_hash_msg->hash_flds[i] = cpu_to_le32(tmp_flds[i]);

	rss_hash_msg->symm = (hash_cfg->symm ? 1 : 0);
	rss_hash_msg->hdr_type = cpu_to_le32(SXE2_RSS_ANY_HEADERS);
}

STATIC s32 sxe2vf_add_rss_cfg_func(struct sxe2vf_adapter *adapter,
				   struct sxe2vf_rss_hash_cfg *hash_cfg)
{
	s32 ret = 0;
	struct sxe2vf_msg_params params = {0};
	struct sxe2_vf_rss_hash_msg rss_hash_msg = {0};

	sxe2vf_rss_hash_cfg_convert_hash_msg(hash_cfg, &rss_hash_msg);

	sxe2vf_mbx_msg_dflt_params_fill(&params,
					SXE2VF_MSG_RESP_WAIT_NOTIFY, SXE2_VF_ADD_RSS_CFG,
					&rss_hash_msg,
					sizeof(struct sxe2_vf_rss_hash_msg), NULL, 0);

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf rss send mbx add rss cfg fail!\n");

	return ret;
}

STATIC s32 sxe2vf_clear_rss_cfg_func(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2vf_msg_params params = {0};

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_CLEAR_RSS_CFG, NULL, 0, NULL, 0);

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf rss send mbx clear rss cfg fail!\n");

	return ret;
}

STATIC s32 sxe2vf_set_rss_hash_ctrl_func(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2vf_msg_params params = {0};
	struct sxe2_vf_rss_hash_ctrl hash_ctrl;

	hash_ctrl.hash_func = SXE2_RSS_HASH_FUNC_TOEPLITZ;
	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_SET_RSS_HASH_CTRL, &hash_ctrl,
					sizeof(struct sxe2_vf_rss_hash_ctrl), NULL,
					0);

	if (ret)
		LOG_ERROR_BDF("sxe2 vf rss send mbx clear rss cfg fail!\n");

	return ret;
}

STATIC void sxe2vf_rss_clear_cfg(struct sxe2vf_adapter *adapter)
{
	struct device *dev = SXE2VF_ADAPTER_TO_DEV(adapter);
	struct sxe2vf_rss_cfg *rss_cfg;
	struct sxe2vf_rss_cfg *tmp;
	s32 ret = 0;

	if (list_empty(&adapter->rss_ctxt.rss_cfgs))
		goto l_end;

	mutex_lock(&adapter->rss_ctxt.rss_cfgs_lock);
	ret = sxe2vf_clear_rss_cfg_func(adapter);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf rss send mbx clear rss cfg fail, ret = %d!\n",
			      ret);
	}

	list_for_each_entry_safe(rss_cfg, tmp, &adapter->rss_ctxt.rss_cfgs, l_node) {
		list_del(&rss_cfg->l_node);
		devm_kfree(dev, rss_cfg);
	}
	mutex_unlock(&adapter->rss_ctxt.rss_cfgs_lock);

l_end:
	return;
}

s32 sxe2vf_rss_add_cfg(struct sxe2vf_adapter *adapter,
		       struct sxe2vf_rss_hash_cfg *hash_cfg, bool is_default)
{
	struct device *dev = SXE2VF_ADAPTER_TO_DEV(adapter);
	struct sxe2vf_rss_cfg *old_cfg;
	struct sxe2vf_rss_cfg *new_cfg;
	s32 ret = 0;

	mutex_lock(&adapter->rss_ctxt.rss_cfgs_lock);

	old_cfg = sxe2vf_find_rss_cfg_by_hdrs(adapter, hash_cfg->headers);
	if (old_cfg) {
		if (bitmap_equal(old_cfg->hash_cfg.hash_flds, hash_cfg->hash_flds,
				 SXE2_FLOW_FLD_ID_MAX)) {
			goto l_end;
		} else {
			if (is_default)
				ret = 0;
			else
				ret = sxe2vf_add_rss_cfg_func(adapter, hash_cfg);

			if (!ret)
				bitmap_copy(old_cfg->hash_cfg.hash_flds,
					    hash_cfg->hash_flds,
					    SXE2_FLOW_FLD_ID_MAX);
			else
				LOG_ERROR_BDF("sxe2 vf rss failed to add rss cfg.\n");
		}
	} else {
		new_cfg = devm_kzalloc(dev, sizeof(*new_cfg), GFP_KERNEL);
		if (!new_cfg) {
			LOG_ERROR_BDF("sxe2 vf rss failed to alloc rss_cfg memory.\n");
			ret = -ENOMEM;
			goto l_end;
		}
		if (is_default)
			ret = 0;
		else
			ret = sxe2vf_add_rss_cfg_func(adapter, hash_cfg);

		if (!ret) {
			bitmap_copy(new_cfg->hash_cfg.hash_flds, hash_cfg->hash_flds,
				    SXE2_FLOW_FLD_ID_MAX);
			bitmap_copy(new_cfg->hash_cfg.headers, hash_cfg->headers,
				    SXE2_FLOW_HDR_MAX);
			list_add_tail(&new_cfg->l_node, &adapter->rss_ctxt.rss_cfgs);
		} else {
			LOG_ERROR_BDF("sxe2 vf rss failed to add rss cfg.\n");
			devm_kfree(dev, new_cfg);
		}
	}

l_end:
	mutex_unlock(&adapter->rss_ctxt.rss_cfgs_lock);
	return ret;
}

void sxe2vf_analysis_hdrs(struct ethtool_rxnfc *nfc, unsigned long *hdrs)
{
	bitmap_zero(hdrs, SXE2_FLOW_HDR_MAX);
	switch (nfc->flow_type) {
	case TCP_V4_FLOW:
		set_bit(SXE2_FLOW_HDR_IPV4, hdrs);
		set_bit(SXE2_FLOW_HDR_TCP, hdrs);
		break;
	case UDP_V4_FLOW:
		set_bit(SXE2_FLOW_HDR_IPV4, hdrs);
		set_bit(SXE2_FLOW_HDR_UDP, hdrs);
		break;
	case SCTP_V4_FLOW:
		set_bit(SXE2_FLOW_HDR_IPV4, hdrs);
		set_bit(SXE2_FLOW_HDR_SCTP, hdrs);
		break;
	case TCP_V6_FLOW:
		set_bit(SXE2_FLOW_HDR_IPV6, hdrs);
		set_bit(SXE2_FLOW_HDR_TCP, hdrs);
		break;
	case UDP_V6_FLOW:
		set_bit(SXE2_FLOW_HDR_IPV6, hdrs);
		set_bit(SXE2_FLOW_HDR_UDP, hdrs);
		break;
	case SCTP_V6_FLOW:
		set_bit(SXE2_FLOW_HDR_IPV6, hdrs);
		set_bit(SXE2_FLOW_HDR_SCTP, hdrs);
		break;
	default:
		break;
	}
}

void sxe2vf_analysis_hash_flds(struct ethtool_rxnfc *nfc, unsigned long *hash_flds)
{
	bitmap_zero(hash_flds, SXE2_FLOW_FLD_ID_MAX);
	if (nfc->data & RXH_IP_SRC || nfc->data & RXH_IP_DST) {
		switch (nfc->flow_type) {
		case TCP_V4_FLOW:
		case UDP_V4_FLOW:
		case SCTP_V4_FLOW:
			if (nfc->data & RXH_IP_SRC)
				set_bit(SXE2_FLOW_FLD_ID_IPV4_SA, hash_flds);

			if (nfc->data & RXH_IP_DST)
				set_bit(SXE2_FLOW_FLD_ID_IPV4_DA, hash_flds);

			break;
		case TCP_V6_FLOW:
		case UDP_V6_FLOW:
		case SCTP_V6_FLOW:
			if (nfc->data & RXH_IP_SRC)
				set_bit(SXE2_FLOW_FLD_ID_IPV6_SA, hash_flds);

			if (nfc->data & RXH_IP_DST)
				set_bit(SXE2_FLOW_FLD_ID_IPV6_DA, hash_flds);

			break;
		default:
			break;
		}
	}

	if (nfc->data & RXH_L4_B_0_1 || nfc->data & RXH_L4_B_2_3) {
		switch (nfc->flow_type) {
		case TCP_V4_FLOW:
		case TCP_V6_FLOW:
			if (nfc->data & RXH_L4_B_0_1)
				set_bit(SXE2_FLOW_FLD_ID_TCP_SRC_PORT, hash_flds);
			if (nfc->data & RXH_L4_B_2_3)
				set_bit(SXE2_FLOW_FLD_ID_TCP_DST_PORT, hash_flds);
			break;
		case UDP_V4_FLOW:
		case UDP_V6_FLOW:
			if (nfc->data & RXH_L4_B_0_1)
				set_bit(SXE2_FLOW_FLD_ID_UDP_SRC_PORT, hash_flds);
			if (nfc->data & RXH_L4_B_2_3)
				set_bit(SXE2_FLOW_FLD_ID_UDP_DST_PORT, hash_flds);
			break;
		case SCTP_V4_FLOW:
		case SCTP_V6_FLOW:
			if (nfc->data & RXH_L4_B_0_1)
				set_bit(SXE2_FLOW_FLD_ID_SCTP_SRC_PORT, hash_flds);
			if (nfc->data & RXH_L4_B_2_3)
				set_bit(SXE2_FLOW_FLD_ID_SCTP_DST_PORT, hash_flds);
			break;
		default:
			break;
		}
	}
}

void sxe2vf_get_rss_flow(struct sxe2vf_adapter *adapter, struct ethtool_rxnfc *nfc)
{
	DECLARE_BITMAP(headers, SXE2_FLOW_HDR_MAX);
	DECLARE_BITMAP(hash_flds, SXE2_FLOW_FLD_ID_MAX);
	struct sxe2vf_rss_cfg *hash_cfg;
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;

	nfc->data = 0;

#ifdef SXE2_CFG_RELEASE
	UNUSED(vsi);
#endif

	sxe2vf_analysis_hdrs(nfc, headers);
	if (bitmap_empty(headers, SXE2_FLOW_HDR_MAX)) {
		LOG_ERROR_BDF("sxe2 vf rss (id: %u) nfc input hdrs is empty.\n",
			      vsi->vsi_id);
		return;
	}

	mutex_lock(&adapter->rss_ctxt.rss_cfgs_lock);
	hash_cfg = sxe2vf_find_rss_cfg_by_hdrs(adapter, headers);
	if (!hash_cfg) {
		LOG_ERROR_BDF("sxe2 vf rss (id: %u) can not find same hdrs in hash cfg.\n",
			      vsi->vsi_id);
		mutex_unlock(&adapter->rss_ctxt.rss_cfgs_lock);
		return;
	}
	bitmap_copy(hash_flds, hash_cfg->hash_cfg.hash_flds, SXE2_FLOW_FLD_ID_MAX);
	mutex_unlock(&adapter->rss_ctxt.rss_cfgs_lock);

	if (test_bit(SXE2_FLOW_FLD_ID_IPV4_SA, hash_flds) ||
	    test_bit(SXE2_FLOW_FLD_ID_IPV6_SA, hash_flds)) {
		nfc->data |= (u64)RXH_IP_SRC;
	}

	if (test_bit(SXE2_FLOW_FLD_ID_IPV4_DA, hash_flds) ||
	    test_bit(SXE2_FLOW_FLD_ID_IPV6_DA, hash_flds)) {
		nfc->data |= (u64)RXH_IP_DST;
	}

	if (test_bit(SXE2_FLOW_FLD_ID_TCP_SRC_PORT, hash_flds) ||
	    test_bit(SXE2_FLOW_FLD_ID_UDP_SRC_PORT, hash_flds) ||
	    test_bit(SXE2_FLOW_FLD_ID_SCTP_SRC_PORT, hash_flds)) {
		nfc->data |= (u64)RXH_L4_B_0_1;
	}

	if (test_bit(SXE2_FLOW_FLD_ID_TCP_DST_PORT, hash_flds) ||
	    test_bit(SXE2_FLOW_FLD_ID_UDP_DST_PORT, hash_flds) ||
	    test_bit(SXE2_FLOW_FLD_ID_SCTP_DST_PORT, hash_flds)) {
		nfc->data |= (u64)RXH_L4_B_2_3;
	}
}

int sxe2vf_set_rss_flow(struct sxe2vf_adapter *adapter, struct ethtool_rxnfc *nfc)
{
	int ret = 0;
	struct sxe2vf_rss_hash_cfg hash_cfg = {0};
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;

#ifdef SXE2_CFG_RELEASE
	UNUSED(vsi);
#endif

	sxe2vf_analysis_hdrs(nfc, hash_cfg.headers);
	if (bitmap_empty(hash_cfg.headers, SXE2_FLOW_HDR_MAX)) {
		LOG_ERROR_BDF("sxe2 vf rss (id: %u) invalid field type!\n",
			      vsi->vsi_id);
		return -EINVAL;
	}

	sxe2vf_analysis_hash_flds(nfc, hash_cfg.hash_flds);
	if (bitmap_empty(hash_cfg.hash_flds, SXE2_FLOW_FLD_ID_MAX)) {
		LOG_ERROR_BDF("sxe2 vf rss (id: %u) invalid field type!\n",
			      vsi->vsi_id);
		return -EINVAL;
	}

	ret = sxe2vf_rss_add_cfg(adapter, &hash_cfg, false);
	return ret;
}

s32 sxe2vf_rss_default_flow_set(struct sxe2vf_adapter *adapter)
{
	u32 i;
	s32 ret = 0;
	struct sxe2vf_rss_hash_cfg *cfg;
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;
	struct sxe2vf_msg_params params = {0};

#ifdef SXE2_CFG_RELEASE
	UNUSED(vsi);
#endif

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_ADD_DEFAULT_RSS_CFG, NULL, 0, NULL,
					0);

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf rss send mbx add default rss cfg fail!\n");
		goto l_end;
	}
	sxe2vf_default_rss_cfg_create();

	for (i = 0; i < ARRAY_SIZE(default_vf_rss_cfgs); i++) {
		cfg = default_vf_rss_cfgs[i];
		ret = sxe2vf_rss_add_cfg(adapter, cfg, true);
		if (ret) {
			LOG_ERROR_BDF("sxe2 vf rss (id: %u) add default cfg failed.\n",
				      vsi->vsi_id);
			sxe2vf_rss_clear_cfg(adapter);
			break;
		}
	}

l_end:
	return ret;
}

STATIC s32 sxe2vf_rss_replay_hash_cfg(struct sxe2vf_adapter *adapter)
{
	struct device *dev = SXE2VF_ADAPTER_TO_DEV(adapter);
	s32 ret = 0;
	struct sxe2vf_msg_params params = {0};
	struct sxe2vf_rss_cfg *rss_cfg;
	struct sxe2vf_rss_cfg *tmp;

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_REPLAY_RSS_CFG, NULL, 0, NULL, 0);

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret) {
		mutex_lock(&adapter->rss_ctxt.rss_cfgs_lock);
		list_for_each_entry_safe(rss_cfg, tmp, &adapter->rss_ctxt.rss_cfgs,
					 l_node) {
			list_del(&rss_cfg->l_node);
			devm_kfree(dev, rss_cfg);
		}
		mutex_unlock(&adapter->rss_ctxt.rss_cfgs_lock);
		LOG_DEV_WARN("sxe2 vf replay rss cfg fail in rebuild, ret=%d!\t"
			     "please type \"ethtool -N [devname] rx-flow-hash\"recfg rss\n",
			     ret);
	}

	return ret;
}

STATIC s32 sxe2vf_rss_hash_key_deinit(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_msg_params params = {0};
	u8 *key_msg = NULL;
	s32 ret = 0;
	struct device *dev = SXE2VF_ADAPTER_TO_DEV(adapter);

	key_msg = kzalloc(adapter->rss_ctxt.rss_key_size, GFP_KERNEL);
	if (!key_msg) {
		ret = -ENOMEM;
		LOG_ERROR_BDF("No memory!\n");
		goto l_out;
	}

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_SET_RSS_KEY, key_msg,
					adapter->rss_ctxt.rss_key_size, NULL, 0);
	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf rss set hash key fail!\n");

	kfree(key_msg);

l_out:

	if (adapter->rss_ctxt.key) {
		devm_kfree(dev, adapter->rss_ctxt.key);
		adapter->rss_ctxt.key = NULL;
	}

	return ret;
}

STATIC s32 sxe2vf_rss_hash_lut_deinit(struct sxe2vf_adapter *adapter)
{
	struct device *dev = SXE2VF_ADAPTER_TO_DEV(adapter);
	struct sxe2vf_msg_params params = {0};
	u8 *lut_msg = NULL;
	s32 ret = 0;

	lut_msg = kzalloc(adapter->rss_ctxt.rss_lut_size, GFP_KERNEL);
	if (!lut_msg) {
		ret = -ENOMEM;
		LOG_ERROR_BDF("No memory!\n");
		goto l_out;
	}

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_SET_RSS_LUT, lut_msg,
					adapter->rss_ctxt.rss_lut_size, NULL, 0);
	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf rss set lut fail!\n");

	kfree(lut_msg);

l_out:
	if (adapter->rss_ctxt.lut) {
		devm_kfree(dev, adapter->rss_ctxt.lut);
		adapter->rss_ctxt.lut = NULL;
	}

	return ret;
}

void sxe2vf_rss_deinit(struct sxe2vf_adapter *adapter)
{
	if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		return;

	if (!adapter->rss_ctxt.init) {
		LOG_INFO_BDF("sxe2 vf rss not init or already deinit!\n");
		return;
	}

	(void)sxe2vf_rss_hash_key_deinit(adapter);

	(void)sxe2vf_rss_hash_lut_deinit(adapter);

	sxe2vf_rss_clear_cfg(adapter);

	adapter->rss_ctxt.init = false;
	LOG_INFO_BDF("sxe2 vf rss deinit success!\n");
}

STATIC s32 sxe2vf_rss_hash_key_init(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_msg_params params = {0};
	struct device *dev = SXE2VF_ADAPTER_TO_DEV(adapter);
	u8 *key_msg = NULL;
	s32 ret = 0;

	if (adapter->rss_ctxt.rss_key_size == 0) {
		LOG_ERROR_BDF("sxe2 vf rss hash key init failed. key size is 0!\n");
		ret = -EINVAL;
		goto l_out;
	}

	key_msg = devm_kzalloc(dev, adapter->rss_ctxt.rss_key_size, GFP_KERNEL);
	if (!key_msg) {
		ret = -ENOMEM;
		LOG_ERROR_BDF("No memory!\n");
		goto l_out;
	}
	if (adapter->rss_ctxt.key) {
		memcpy(key_msg, adapter->rss_ctxt.key,
		       adapter->rss_ctxt.rss_key_size);
	} else {
		netdev_rss_key_fill((void *)key_msg, adapter->rss_ctxt.rss_key_size);
	}

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_SET_RSS_KEY, key_msg,
					adapter->rss_ctxt.rss_key_size, NULL, 0);
	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf rss set hash key fail!\n");
		if (adapter->rss_ctxt.key)
			memset(adapter->rss_ctxt.key, 0,
			       adapter->rss_ctxt.rss_key_size);

		devm_kfree(dev, key_msg);
		goto l_out;
	}

	if (!adapter->rss_ctxt.key)
		adapter->rss_ctxt.key = key_msg;
	else
		devm_kfree(dev, key_msg);
l_out:
	return ret;
}

STATIC s32 sxe2vf_rss_hash_lut_init(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_msg_params params = {0};
	struct device *dev = SXE2VF_ADAPTER_TO_DEV(adapter);
	u8 *lut_msg = NULL;
	s32 ret = 0;
	u16 i = 0;

	if (adapter->rss_ctxt.rss_lut_size == 0) {
		LOG_ERROR_BDF("sxe2 vf rss hash lut init failed. lut size is 0!\n");
		ret = -EINVAL;
		goto l_out;
	}

	lut_msg = devm_kzalloc(dev, adapter->rss_ctxt.rss_lut_size, GFP_KERNEL);
	if (!lut_msg) {
		ret = -ENOMEM;
		LOG_ERROR_BDF("No memory!\n");
		goto l_out;
	}
	if (adapter->rss_ctxt.lut) {
		memcpy(lut_msg, adapter->rss_ctxt.lut,
		       adapter->rss_ctxt.rss_lut_size);
	} else {
		for (i = 0; i < adapter->rss_ctxt.rss_lut_size; i++)
			lut_msg[i] = (u8)(i % adapter->vsi_ctxt.vf_vsi->rxqs.q_cnt);
	}

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_SET_RSS_LUT, lut_msg,
					adapter->rss_ctxt.rss_lut_size, NULL, 0);
	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf rss set lut fail!\n");
		if (adapter->rss_ctxt.lut)
			memset(adapter->rss_ctxt.lut, 0,
			       adapter->rss_ctxt.rss_lut_size);

		devm_kfree(dev, lut_msg);
		goto l_out;
	}

	if (!adapter->rss_ctxt.lut)
		adapter->rss_ctxt.lut = lut_msg;
	else
		devm_kfree(dev, lut_msg);

l_out:
	return ret;
}

s32 sxe2vf_rss_init(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;

	if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		return 0;

	ret = sxe2vf_set_rss_hash_ctrl_func(adapter);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf rss init hash ctrl fail, ret=%u !\n", ret);
		goto l_end;
	}

	ret = sxe2vf_rss_hash_key_init(adapter);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf rss init hash key fail, ret=%u !\n", ret);
		goto l_end;
	}

	ret = sxe2vf_rss_hash_lut_init(adapter);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf rss init hash lut fail, ret=%u !\n", ret);
		(void)sxe2vf_rss_hash_key_deinit(adapter);
		goto l_end;
	}

	ret = sxe2vf_rss_default_flow_set(adapter);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf rss add default flow fail, ret=%u !\n", ret);
		ret = 0;
	}

	adapter->rss_ctxt.init = true;

	LOG_INFO_BDF("sxe2 vf rss init success!\n");

l_end:
	return ret;
}

s32 sxe2vf_rss_rebuild(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;

	if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		return 0;

	ret = sxe2vf_set_rss_hash_ctrl_func(adapter);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf rss init hash ctrl fail, ret=%u !\n", ret);

	ret = sxe2vf_rss_hash_key_init(adapter);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf rss reinit hash key fail, ret=%u !\n", ret);

	ret = sxe2vf_rss_hash_lut_init(adapter);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf rss reinit hash lut fail, ret=%u !\n", ret);

	ret = sxe2vf_rss_replay_hash_cfg(adapter);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf rss reinit hash cdf fail, ret=%u !\n", ret);
		ret = 0;
	}

	LOG_INFO_BDF("sxe2 vf rss rebuild done!\n");

	return ret;
}

s32 sxe2vf_set_channels_rss_reset(struct net_device *netdev,
				  struct sxe2vf_adapter *adapter, u32 new_queue)
{
	struct sxe2vf_msg_params params = {0};
	u8 *lut_msg = NULL;
	s32 ret = 0;
	u16 i = 0;

	if (!netif_is_rxfh_configured(netdev)) {
		if (adapter->rss_ctxt.lut) {
			for (i = 0; i < adapter->rss_ctxt.rss_lut_size; i++)
				adapter->rss_ctxt.lut[i] = (u8)(i % new_queue);
		}
		LOG_DEV_INFO("rx queue size change, clearing user lut,\t"
			     "re-run ethtool [-x|-X] to [check|set] settings if needed.\n");

		lut_msg = kzalloc(adapter->rss_ctxt.rss_lut_size, GFP_KERNEL);
		if (!lut_msg) {
			ret = -ENOMEM;
			LOG_ERROR_BDF("No memory!\n");
			goto l_out;
		}
		for (i = 0; i < adapter->rss_ctxt.rss_lut_size; i++)
			lut_msg[i] = (u8)(i % new_queue);

		sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
						SXE2_VF_SET_RSS_LUT, lut_msg,
						adapter->rss_ctxt.rss_lut_size, NULL,
						0);
		ret = sxe2vf_mbx_msg_send(adapter, &params);
		if (ret)
			LOG_ERROR_BDF("sxe2 vf rss set lut fail!\n");
	}
	kfree(lut_msg);
l_out:
	return ret;
}

int sxe2vf_set_channels_fnav_check(struct sxe2vf_adapter *adapter, u32 new_cnt)
{
	int ret = 0;
	struct sxe2vf_fnav_filter *filter = NULL;

	mutex_lock(&adapter->fnav_ctxt.filter_list_lock);
	list_for_each_entry(filter, &adapter->fnav_ctxt.filter_list, l_node) {
		if (filter->act_type == SXE2_FNAV_ACTION_QUEUE &&
		    filter->q_index >= new_cnt) {
			ret = -EINVAL;
			LOG_ERROR_BDF("change channel fnav check failed, loc=%u,\t"
				      "q_id=%u.\n",
				      filter->filter_loc, filter->q_index);
			break;
		}
	}
	mutex_unlock(&adapter->fnav_ctxt.filter_list_lock);
	return ret;
}

struct sxe2vf_fnav_filter *
sxe2vf_fnav_find_filter_by_loc_unlock(struct sxe2vf_adapter *adapter, u32 loc)
{
	struct sxe2vf_fnav_filter *filter_tmp = NULL;
	struct sxe2vf_fnav_filter *filter_find = NULL;

	list_for_each_entry(filter_tmp, &adapter->fnav_ctxt.filter_list, l_node) {
		if (loc == filter_tmp->filter_loc) {
			filter_find = filter_tmp;
			break;
		}
		if (loc < filter_tmp->filter_loc)
			break;
	}

	return filter_find;
}

u32 sxe2vf_flow_type_to_ethtool_flow(enum sxe2_fnav_flow_type flow_type)
{
	switch (flow_type) {
	case SXE2_FNAV_FLOW_TYPE_ETH:
		return ETHER_FLOW;
	case SXE2_FNAV_FLOW_TYPE_IPV4_TCP:
		return TCP_V4_FLOW;
	case SXE2_FNAV_FLOW_TYPE_IPV4_UDP:
		return UDP_V4_FLOW;
	case SXE2_FNAV_FLOW_TYPE_IPV4_SCTP:
		return SCTP_V4_FLOW;
	case SXE2_FNAV_FLOW_TYPE_IPV4_OTHER:
		return IPV4_USER_FLOW;
	case SXE2_FNAV_FLOW_TYPE_IPV6_TCP:
		return TCP_V6_FLOW;
	case SXE2_FNAV_FLOW_TYPE_IPV6_UDP:
		return UDP_V6_FLOW;
	case SXE2_FNAV_FLOW_TYPE_IPV6_SCTP:
		return SCTP_V6_FLOW;
	case SXE2_FNAV_FLOW_TYPE_IPV6_OTHER:
		return IPV6_USER_FLOW;
	default:
		return 0;
	}
}

enum sxe2_fnav_flow_type sxe2vf_ethtool_flow_to_type(u32 flow)
{
	enum sxe2_fnav_flow_type flow_type;

	switch (flow) {
	case ETHER_FLOW:
		flow_type = SXE2_FNAV_FLOW_TYPE_ETH;
		break;
	case TCP_V4_FLOW:
		flow_type = SXE2_FNAV_FLOW_TYPE_IPV4_TCP;
		break;
	case UDP_V4_FLOW:
		flow_type = SXE2_FNAV_FLOW_TYPE_IPV4_UDP;
		break;
	case SCTP_V4_FLOW:
		flow_type = SXE2_FNAV_FLOW_TYPE_IPV4_SCTP;
		break;
	case IPV4_USER_FLOW:
		flow_type = SXE2_FNAV_FLOW_TYPE_IPV4_OTHER;
		break;
	case TCP_V6_FLOW:
		flow_type = SXE2_FNAV_FLOW_TYPE_IPV6_TCP;
		break;
	case UDP_V6_FLOW:
		flow_type = SXE2_FNAV_FLOW_TYPE_IPV6_UDP;
		break;
	case SCTP_V6_FLOW:
		flow_type = SXE2_FNAV_FLOW_TYPE_IPV6_SCTP;
		break;
	case IPV6_USER_FLOW:
		flow_type = SXE2_FNAV_FLOW_TYPE_IPV6_OTHER;
		break;
	default:
		flow_type = SXE2_FNAV_FLOW_TYPE_NONE;
		break;
	}

	return flow_type;
}

int sxe2vf_ethtool_fnav_filter_get_by_loc(struct sxe2vf_adapter *adapter,
					  struct ethtool_rxnfc *cmd)
{
	int ret = 0;
	struct ethtool_rx_flow_spec *fsp = (struct ethtool_rx_flow_spec *)&cmd->fs;
	struct sxe2vf_fnav_filter *filter = NULL;
	struct sxe2vf_fnav_filter_full_key *full_key = NULL;

	mutex_lock(&adapter->fnav_ctxt.filter_list_lock);

	filter = sxe2vf_fnav_find_filter_by_loc_unlock(adapter, fsp->location);
	if (!filter) {
		LOG_ERROR_BDF("filter in loc[%u] is not found.\n", fsp->location);
		ret = -EINVAL;
		goto l_unlock;
	}
	full_key = &filter->full_key;

	fsp->flow_type = sxe2vf_flow_type_to_ethtool_flow(filter->flow_type);

	memset(&fsp->m_u, 0, sizeof(fsp->m_u));
	memset(&fsp->m_ext, 0, sizeof(fsp->m_ext));

	if (filter->act_type == SXE2_FNAV_ACTION_DROP)
		fsp->ring_cookie = RX_CLS_FLOW_DISC;
	else
		fsp->ring_cookie = filter->q_index;

	switch (fsp->flow_type) {
	case TCP_V4_FLOW:
	case UDP_V4_FLOW:
	case SCTP_V4_FLOW:
		fsp->h_u.tcp_ip4_spec.ip4src = full_key->ip_data.v4_addrs.src_ip;
		fsp->h_u.tcp_ip4_spec.ip4dst = full_key->ip_data.v4_addrs.dst_ip;
		fsp->h_u.tcp_ip4_spec.psrc = full_key->ip_data.src_port;
		fsp->h_u.tcp_ip4_spec.pdst = full_key->ip_data.dst_port;
		fsp->h_u.tcp_ip4_spec.tos = full_key->ip_data.tos;
		fsp->m_u.tcp_ip4_spec.ip4src = full_key->ip_mask.v4_addrs.src_ip;
		fsp->m_u.tcp_ip4_spec.ip4dst = full_key->ip_mask.v4_addrs.dst_ip;
		fsp->m_u.tcp_ip4_spec.psrc = full_key->ip_mask.src_port;
		fsp->m_u.tcp_ip4_spec.pdst = full_key->ip_mask.dst_port;
		fsp->m_u.tcp_ip4_spec.tos = full_key->ip_mask.tos;
		break;
	case IPV4_USER_FLOW:
		fsp->h_u.usr_ip4_spec.ip4src = full_key->ip_data.v4_addrs.src_ip;
		fsp->h_u.usr_ip4_spec.ip4dst = full_key->ip_data.v4_addrs.dst_ip;
		fsp->h_u.usr_ip4_spec.l4_4_bytes = full_key->ip_data.l4_header;
		fsp->h_u.usr_ip4_spec.tos = full_key->ip_data.tos;
		fsp->h_u.usr_ip4_spec.ip_ver = ETH_RX_NFC_IP4;
		fsp->h_u.usr_ip4_spec.proto = full_key->ip_data.proto;
		fsp->m_u.usr_ip4_spec.ip4src = full_key->ip_mask.v4_addrs.src_ip;
		fsp->m_u.usr_ip4_spec.ip4dst = full_key->ip_mask.v4_addrs.dst_ip;
		fsp->m_u.usr_ip4_spec.l4_4_bytes = full_key->ip_mask.l4_header;
		fsp->m_u.usr_ip4_spec.tos = full_key->ip_mask.tos;
		fsp->m_u.usr_ip4_spec.ip_ver = 0xFF;
		fsp->m_u.usr_ip4_spec.proto = full_key->ip_mask.proto;
		break;
	case TCP_V6_FLOW:
	case UDP_V6_FLOW:
	case SCTP_V6_FLOW:
		memcpy(fsp->h_u.usr_ip6_spec.ip6src,
		       &full_key->ip_data.v6_addrs.src_ip, sizeof(struct in6_addr));
		memcpy(fsp->h_u.usr_ip6_spec.ip6dst,
		       &full_key->ip_data.v6_addrs.dst_ip, sizeof(struct in6_addr));
		fsp->h_u.tcp_ip6_spec.psrc = full_key->ip_data.src_port;
		fsp->h_u.tcp_ip6_spec.pdst = full_key->ip_data.dst_port;
		fsp->h_u.tcp_ip6_spec.tclass = full_key->ip_data.tclass;
		memcpy(fsp->m_u.usr_ip6_spec.ip6src,
		       &full_key->ip_mask.v6_addrs.src_ip, sizeof(struct in6_addr));
		memcpy(fsp->m_u.usr_ip6_spec.ip6dst,
		       &full_key->ip_mask.v6_addrs.dst_ip, sizeof(struct in6_addr));
		fsp->m_u.tcp_ip6_spec.psrc = full_key->ip_mask.src_port;
		fsp->m_u.tcp_ip6_spec.pdst = full_key->ip_mask.dst_port;
		fsp->m_u.tcp_ip6_spec.tclass = full_key->ip_mask.tclass;
		break;
	case IPV6_USER_FLOW:
		memcpy(fsp->h_u.usr_ip6_spec.ip6src,
		       &full_key->ip_data.v6_addrs.src_ip, sizeof(struct in6_addr));
		memcpy(fsp->h_u.usr_ip6_spec.ip6dst,
		       &full_key->ip_data.v6_addrs.dst_ip, sizeof(struct in6_addr));
		fsp->h_u.usr_ip6_spec.l4_4_bytes = full_key->ip_data.l4_header;
		fsp->h_u.usr_ip6_spec.tclass = full_key->ip_data.tclass;
		fsp->h_u.usr_ip6_spec.l4_proto = full_key->ip_data.proto;
		memcpy(fsp->m_u.usr_ip6_spec.ip6src,
		       &full_key->ip_mask.v6_addrs.src_ip, sizeof(struct in6_addr));
		memcpy(fsp->m_u.usr_ip6_spec.ip6dst,
		       &full_key->ip_mask.v6_addrs.dst_ip, sizeof(struct in6_addr));
		fsp->m_u.usr_ip6_spec.l4_4_bytes = full_key->ip_mask.l4_header;
		fsp->m_u.usr_ip6_spec.tclass = full_key->ip_mask.tclass;
		fsp->m_u.usr_ip6_spec.l4_proto = full_key->ip_mask.proto;
		break;
	case ETHER_FLOW:
		fsp->h_u.ether_spec.h_proto = full_key->eth_data.etype;
		fsp->m_u.ether_spec.h_proto = full_key->eth_mask.etype;
		memcpy(fsp->h_u.ether_spec.h_source, full_key->eth_data.src,
		       sizeof(fsp->h_u.ether_spec.h_source));
		memcpy(fsp->m_u.ether_spec.h_source, full_key->eth_mask.src,
		       sizeof(fsp->m_u.ether_spec.h_source));
		memcpy(fsp->h_u.ether_spec.h_dest, full_key->eth_data.dst,
		       sizeof(fsp->h_u.ether_spec.h_dest));
		memcpy(fsp->m_u.ether_spec.h_dest, full_key->eth_mask.dst,
		       sizeof(fsp->m_u.ether_spec.h_dest));
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if (filter->has_flex_filed) {
		fsp->flow_type |= FLOW_EXT;
		memcpy(fsp->h_ext.data, full_key->ext_data.usr_def,
		       sizeof(fsp->h_ext.data));
		memcpy(fsp->m_ext.data, full_key->ext_mask.usr_def,
		       sizeof(fsp->m_ext.data));
		fsp->h_ext.vlan_etype = full_key->ext_data.vlan_type;
		fsp->m_ext.vlan_etype = full_key->ext_mask.vlan_type;
		fsp->h_ext.vlan_tci = full_key->ext_data.s_vlan_tag;
		fsp->m_ext.vlan_tci = full_key->ext_mask.s_vlan_tag;
	}

l_unlock:
	mutex_unlock(&adapter->fnav_ctxt.filter_list_lock);
	return ret;
}

int sxe2vf_ethtool_ntuple_filter_locs_get(struct sxe2vf_adapter *adapter,
					  struct ethtool_rxnfc *cmd,
					  u32 *filter_locs)
{
	int ret = 0;
	unsigned int cnt = 0;
	struct sxe2vf_fnav_filter *filter = NULL;

	cmd->data = SXE2VF_MAX_FNAV_FILTERS;

	mutex_lock(&adapter->fnav_ctxt.filter_list_lock);
	list_for_each_entry(filter, &adapter->fnav_ctxt.filter_list, l_node) {
		if (cnt == cmd->rule_cnt) {
			ret = -EMSGSIZE;
			LOG_ERROR_BDF("sxe2 vf fnav  filter cnt is over cmdCnt=%d,\t"
				      "vsi id=%d.\n",
				      cmd->rule_cnt,
				      adapter->vsi_ctxt.vf_vsi->vsi_id);
			break;
		}
		filter_locs[cnt] = filter->filter_loc;
		cnt++;
	}
	mutex_unlock(&adapter->fnav_ctxt.filter_list_lock);

	if (!ret)
		cmd->rule_cnt = cnt;

	return ret;
}

STATIC s32 sxe2vf_fnav_alloc_stat_idx(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2vf_fnav_context *fnav_ctxt = &adapter->fnav_ctxt;
	struct sxe2vf_msg_params params = {0};
	struct sxe2_vf_fnav_stat_msg stat_msg;
	struct sxe2_vf_fnav_stat_alloc_req_msg stat_req;

	fnav_ctxt->stat_idx = SXE2_VF_FNAV_INVALID_STAT_IDX;
	stat_req.need_update = true;

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_FNAV_ALLOC_STAT, &stat_req,
					sizeof(stat_req), &stat_msg,
					sizeof(struct sxe2_vf_fnav_stat_msg));
	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf fnav alloc stat idx fail!\n");
		goto l_end;
	}
	fnav_ctxt->stat_idx = le16_to_cpu(stat_msg.stat_index);

l_end:
	return ret;
}

STATIC s32 sxe2vf_fnav_free_stat_idx(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2vf_fnav_context *fnav_ctxt = &adapter->fnav_ctxt;
	struct sxe2vf_msg_params params = {0};
	struct sxe2_vf_fnav_stat_msg stat_msg;

	stat_msg.stat_index = cpu_to_le16(fnav_ctxt->stat_idx);

	sxe2vf_mbx_msg_dflt_params_fill(&params,
					SXE2VF_MSG_RESP_WAIT_NOTIFY, SXE2_VF_FNAV_FREE_STAT,
					&stat_msg, sizeof(struct sxe2_vf_fnav_stat_msg), NULL, 0);
	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf fnav free stat idx fail!\n");
		goto l_end;
	}
	fnav_ctxt->stat_idx = SXE2_VF_FNAV_INVALID_STAT_IDX;

l_end:
	return ret;
}

STATIC s32 sxe2vf_fnav_match_clear(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2vf_msg_params params = {0};

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_FNAV_MATCH_CLEAR, NULL, 0, NULL, 0);
	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret)
		LOG_ERROR_BDF("sxe2 vf fnav match clear fail!\n");

	return ret;
}

s32 sxe2vf_fnav_init(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2vf_fnav_context *filter_ctxt = &adapter->fnav_ctxt;

	if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		return 0;

	ret = sxe2vf_fnav_match_clear(adapter);
	if (ret)
		goto l_end;

	ret = sxe2vf_fnav_alloc_stat_idx(adapter);
	if (ret)
		goto l_end;

	adapter->fnav_ctxt.fnav_match = 0;

	clear_bit(SXE2VF_FLAG_FNAV_ENABLE, adapter->flags);
	if (adapter->fnav_ctxt.space_bsize > 0 ||
	    adapter->fnav_ctxt.space_gsize > 0) {
		set_bit(SXE2VF_FLAG_FNAV_ENABLE, adapter->flags);
	}

	filter_ctxt->filter_cnt = 0;
	mutex_init(&filter_ctxt->filter_list_lock);
	INIT_LIST_HEAD(&filter_ctxt->filter_list);

	filter_ctxt->init = true;
	LOG_INFO_BDF("sxe2 vf fnav  init success.\n");

l_end:
	return ret;
}

void sxe2vf_fnav_deinit(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_fnav_context *filter_ctxt = &adapter->fnav_ctxt;
	struct device *dev = SXE2VF_ADAPTER_TO_DEV(adapter);
	struct sxe2vf_fnav_filter *filter, *tmp;

	if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		return;

	if (!filter_ctxt->init) {
		LOG_INFO_BDF("sxe2 vf fnav already deinit!\n");
		return;
	}

	clear_bit(SXE2VF_FLAG_FNAV_ENABLE, adapter->flags);

	mutex_lock(&filter_ctxt->filter_list_lock);
	list_for_each_entry_safe(filter, tmp, &filter_ctxt->filter_list, l_node) {
		list_del(&filter->l_node);
		devm_kfree(dev, filter);
	}
	filter_ctxt->filter_cnt = 0;
	mutex_unlock(&filter_ctxt->filter_list_lock);

	mutex_destroy(&filter_ctxt->filter_list_lock);

	(void)sxe2vf_fnav_free_stat_idx(adapter);

	filter_ctxt->init = false;

	LOG_INFO_BDF("sxe2 vf fnav deinit success.\n");
}

bool sxe2vf_fnav_is_dup_filter(struct sxe2vf_adapter *adapter,
			       struct sxe2vf_fnav_filter *filter)
{
	struct sxe2vf_fnav_filter *tmp;
	bool ret = false;

	mutex_lock(&adapter->fnav_ctxt.filter_list_lock);
	list_for_each_entry(tmp, &adapter->fnav_ctxt.filter_list, l_node) {
		if (tmp->flow_type != filter->flow_type)
			continue;

		if (!memcmp(&tmp->full_key, &filter->full_key,
			    sizeof(filter->full_key))) {
			ret = true;
			break;
		}
	}
	mutex_unlock(&adapter->fnav_ctxt.filter_list_lock);

	if (ret) {
		if (filter->filter_loc == tmp->filter_loc &&
		    filter->q_index != tmp->q_index) {
			ret = false;
		}
	}

	return ret;
}

s32 sxe2vf_fnav_del_filter(struct sxe2vf_adapter *adapter,
			   struct sxe2vf_fnav_filter *filter)
{
	s32 ret = 0;
	struct device *dev = SXE2VF_ADAPTER_TO_DEV(adapter);
	struct sxe2vf_fnav_context *fnav_ctxt = &adapter->fnav_ctxt;
	struct sxe2vf_msg_params params = {0};
	struct sxe2_vf_fnav_filter_del_msg del_msg;

	del_msg.flow_id = cpu_to_le32(filter->flow_id);

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_FNAV_FILTER_DEL, &del_msg,
					sizeof(struct sxe2_vf_fnav_filter_del_msg),
					NULL, 0);

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf fnav del filter fail!\n");
	} else {
		LOG_INFO_BDF("sxe2 vf fnav del filter success, flow_id = %u !\n",
			     filter->flow_id);
		list_del(&filter->l_node);
		devm_kfree(dev, filter);
		fnav_ctxt->filter_cnt--;
	}

	return ret;
}

s32 sxe2vf_fnav_all_filter_del(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2vf_fnav_filter *filter, *tmp;
	struct sxe2vf_msg_params params = {0};
	struct device *dev = SXE2VF_ADAPTER_TO_DEV(adapter);

	sxe2vf_mbx_msg_dflt_params_fill(&params, SXE2VF_MSG_RESP_WAIT_NOTIFY,
					SXE2_VF_FNAV_FILTER_CLEAR, NULL, 0, NULL, 0);

	ret = sxe2vf_mbx_msg_send(adapter, &params);
	if (ret) {
		LOG_ERROR_BDF("sxe2 vf fnav del filter fail!\n");
		goto l_end;
	}

	mutex_lock(&adapter->fnav_ctxt.filter_list_lock);
	list_for_each_entry_safe(filter, tmp, &adapter->fnav_ctxt.filter_list,
				 l_node) {
		list_del(&filter->l_node);
		devm_kfree(dev, filter);
		adapter->fnav_ctxt.filter_cnt--;
	}
	mutex_unlock(&adapter->fnav_ctxt.filter_list_lock);

	LOG_DEBUG_BDF("sxe2 vf fnav del all filter done ret:%d.\n", ret);
l_end:
	return ret;
}

s32 sxe2vf_fnav_rebuild(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2vf_fnav_filter *filter, *tmp;
	struct device *dev = SXE2VF_ADAPTER_TO_DEV(adapter);

	if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		return 0;

	if (!test_bit(SXE2VF_FLAG_FNAV_ENABLE, adapter->flags)) {
		LOG_INFO_BDF("sxe2 vf fnav switch is disable!\n");
		goto l_end;
	}

	ret = sxe2vf_fnav_alloc_stat_idx(adapter);

	mutex_lock(&adapter->fnav_ctxt.filter_list_lock);
	list_for_each_entry_safe(filter, tmp, &adapter->fnav_ctxt.filter_list,
				 l_node) {
		if (!ret) {
			filter->full_msg.action[1].act_count.stat_ctrl =
					cpu_to_le32(SXE2_FNAV_STAT_ENA_PKTS);
			filter->full_msg.action[1].act_count.stat_index =
					cpu_to_le32(adapter->fnav_ctxt.stat_idx);
			filter->full_msg.action[1].type =
					cpu_to_le32(SXE2_FNAV_ACTION_COUNT);
			filter->full_msg.action_cnt = 2;
		} else {
			filter->full_msg.action_cnt = 1;
		}
		ret = sxe2vf_fnav_add_filter_with_packet(adapter, filter);
		if (ret) {
			LOG_ERROR_BDF("sxe2 vf fnav set filter failed,\t"
				      "filter_loc=%d ret=%d !\n",
				      filter->filter_loc, ret);
			list_del(&filter->l_node);
			devm_kfree(dev, filter);
			adapter->fnav_ctxt.filter_cnt--;
		} else {
			LOG_INFO_BDF("sxe2 vf fnav set filter success,\t"
				     "filter_loc=%d ret=%d !\n",
				     filter->filter_loc, ret);
		}
	}
	mutex_unlock(&adapter->fnav_ctxt.filter_list_lock);

l_end:
	LOG_INFO_BDF("sxe2 vf fnav rebuild filter done, vsi id=%d. ret:%d\n",
		     adapter->vsi_ctxt.vf_vsi->vsi_id, ret);
	return ret;
}
