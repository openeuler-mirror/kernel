// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_ipsec.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <net/xfrm.h>
#include <linux/if_bridge.h>
#include "sxe2_compat.h"
#include "sxe2.h"
#include "sxe2_netdev.h"
#include "sxe2_log.h"
#include "sxe2_ipsec.h"
#include "sxe2_rx.h"
#include "sxe2_tx.h"
#include "sxe2_spec.h"

#ifndef SADB_X_EALG_SM4CBC
#define SADB_X_EALG_SM4CBC 24
#endif

#ifndef SADB_X_AALG_SM3_256HMAC
#define SADB_X_AALG_SM3_256HMAC 10
#endif

#define SXE2_IPSEC_AES_KEY_BITS (256)
#define SXE2_IPSEC_SHA256_AUTH_BITS (256)
#define SXE2_IPSEC_SHA256_TRUNC_BITS (128)

#define SXE2_IPSEC_SM4_KEY_BITS (128)
#define SXE2_IPSEC_SM3_AUTH_BITS (256)
#define SXE2_IPSEC_SM3_TRUNC_BITS (96)

#define SXE2_IPSEC_TX_ENCRYPT (BIT(0))
#define SXE2_IPSEC_TX_ENGINE_SM4 (BIT(1))

#define SXE2_IPSEC_RX_VALID (BIT(0))
#define SXE2_IPSEC_RX_IPV6 (BIT(2))
#define SXE2_IPSEC_RX_DECRYPT (BIT(3))
#define SXE2_IPSEC_RX_ENGINE_SM4 (BIT(4))

#define SXE2_IPSEC_ALG_SM4 (1)
#define SXE2_IPSEC_ALG_AES (0)

enum sxe2_rx_ipsec_status {
	SXE2_IPSEC_DECRYPT_INTIGRITY_SUCCESS,
	SXE2_IPSEC_PACKET_TOOLONG_OVER_2K,
	SXE2_IPSEC_SPI_IP_NOT_MATCHED,
	SXE2_IPSEC_IP_KEY_INVALID,
	SXE2_IPSEC_PAYLOAD_ICV_NOTALIGNED,
	SXE2_IPSEC_ICV_CHECK_FAIL,
	SXE2_IPSEC_DISABLED_BYPASS,
	SXE2_IPSEC_MACSEC_BYPASS
};

static s32 sxe2_ipsec_xs_validate(struct xfrm_state *xs)
{
#ifdef IPSEC_HAVE_REAL_DEV
	struct net_device *netdev = xs->xso.real_dev;
#else
	struct net_device *netdev = xs->xso.dev;
#endif
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_adapter *adapter = priv->vsi->adapter;

	if (xs->props.aalgo != SADB_AALG_NONE) {
		if (!xs->aalg) {
			LOG_ERROR_BDF("auth instance error.\n");

			return -EINVAL;
		}

		if (xs->props.aalgo != SADB_X_AALG_SHA2_256HMAC &&
		    xs->props.aalgo != SADB_X_AALG_SM3_256HMAC) {
			LOG_ERROR_BDF("sxe2 only support hmac(sha256) or sm3(256),\t"
				      "otherwise do not use auth\n");

			return -EINVAL;
		}
	}

	if (!xs->ealg) {
		LOG_ERROR_BDF("sxe2 cannot offload without ealg\n");

		return -EINVAL;
	}

	if (xs->props.ealgo != SADB_X_EALG_AESCBC &&
	    xs->props.ealgo != SADB_X_EALG_SM4CBC) {
		LOG_ERROR_BDF("sxe2 only support cbc(aes) or cbc(sm4)\n");
		return -EINVAL;
	}

	if (xs->props.calgo != SADB_X_CALG_NONE) {
		LOG_ERROR_BDF("sxe2 do not support compressed xfrm offloads.\n");
		return -EINVAL;
	}

	if (xs->props.family != AF_INET && xs->props.family != AF_INET6) {
		LOG_ERROR_BDF("sxe2 only support IPv4/6 xfrm offloads.\n");
		return -EINVAL;
	}

	if (xs->props.mode != XFRM_MODE_TUNNEL) {
		LOG_ERROR_BDF("sxe2 only support tunnel xfrm offloads\n");
		return -EINVAL;
	}

	if (xs->id.proto != IPPROTO_ESP) {
		LOG_ERROR_BDF("sxe2 only support ESP xfrm offloads\n");
		return -EINVAL;
	}

	if (xs->ealg->alg_key_len != SXE2_IPSEC_SM4_KEY_BITS &&
	    xs->ealg->alg_key_len != SXE2_IPSEC_AES_KEY_BITS) {
		LOG_ERROR_BDF("sxe2 only support 256bit or 128bit key\n");
		return -EINVAL;
	}

	if (xs->aalg &&
	    xs->aalg->alg_key_len != SXE2_IPSEC_SM3_AUTH_BITS &&
	    xs->aalg->alg_key_len != SXE2_IPSEC_SHA256_AUTH_BITS) {
		LOG_ERROR_BDF("sxe2 check aalg auth and trunc length failed.keylen:%d\n",
			      xs->aalg->alg_key_len);
		return -EINVAL;
	}

	if (xs->aalg &&
	    xs->aalg->alg_trunc_len != SXE2_IPSEC_SHA256_TRUNC_BITS &&
	    xs->aalg->alg_trunc_len != SXE2_IPSEC_SM3_TRUNC_BITS) {
		LOG_ERROR_BDF("sxe2 check aalg auth and trunc length failed.trunc_len:%d\n",
			      xs->aalg->alg_trunc_len);
		return -EINVAL;
	}

	return 0;
}

STATIC int sxe2_ipsec_parse_proto_keys(struct xfrm_state *xs, u8 *ealg_key,
				       u8 *aalg_key)
{
#ifdef IPSEC_HAVE_REAL_DEV
	struct net_device *netdev = xs->xso.real_dev;
#else
	struct net_device *netdev = xs->xso.dev;
#endif
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_adapter *adapter = priv->vsi->adapter;

	if (!xs->ealg) {
		LOG_ERROR_BDF("null ealg.\n");
		return -EINVAL;
	}

	if (xs->props.ealgo == SADB_X_EALG_AESCBC) {
		if (xs->ealg->alg_key_len != SXE2_IPSEC_AES_KEY_BITS) {
			LOG_ERROR_BDF("failed to check ipsec keylen[%d]\n",
				      xs->ealg->alg_key_len);
			return -EINVAL;
		}

		memcpy(ealg_key, xs->ealg->alg_key, SXE2_IPSEC_AESKEY_LENGTH);

		if (xs->aalg) {
			if (xs->aalg->alg_key_len != SXE2_IPSEC_SHA256_AUTH_BITS ||
			    xs->aalg->alg_trunc_len != SXE2_IPSEC_SHA256_TRUNC_BITS) {
				LOG_ERROR_BDF("failed to check auth key len [%d = %d] or \t"
					      "auth trunc len[%d = %d]\n",
					      xs->aalg->alg_key_len,
					      SXE2_IPSEC_SHA256_AUTH_BITS,
					      xs->aalg->alg_trunc_len,
					      SXE2_IPSEC_SHA256_TRUNC_BITS);

				return -EINVAL;
			}

			memcpy(aalg_key, xs->aalg->alg_key, SXE2_IPSEC_AESAUTH_LENGTH);
		}
	} else if (xs->props.ealgo == SADB_X_EALG_SM4CBC) {
		if (xs->ealg->alg_key_len != SXE2_IPSEC_SM4_KEY_BITS) {
			LOG_ERROR_BDF("failed to check ipsec keylen[%d]\n",
				      xs->ealg->alg_key_len);
			return -EINVAL;
		}
		memcpy(ealg_key, xs->ealg->alg_key, SXE2_IPSEC_SMKEY_LENGTH);
		if (xs->aalg) {
			if (xs->aalg->alg_key_len != SXE2_IPSEC_SM3_AUTH_BITS ||
			    xs->aalg->alg_trunc_len != SXE2_IPSEC_SM3_TRUNC_BITS) {
				LOG_ERROR_BDF("failed to check ipsec keylen[%d]\n",
					      xs->aalg->alg_key_len);
				return -EINVAL;
			}
			memcpy(aalg_key, xs->aalg->alg_key, SXE2_IPSEC_SMAUTH_LENGTH);
		}
	} else {
		LOG_ERROR_BDF("wrong aelg name:%s .\n", xs->ealg->alg_name);
		return -EINVAL;
	}

	return 0;
}

bool sxe2_is_ipsec_offload_enable(struct net_device *netdev)
{
	return netdev->features & NETIF_F_HW_ESP;
}

static s32 sxe2_ipsec_empty_rxtable_find(struct sxe2_adapter *adapter)
{
	u32 i;
	struct sxe2_ipsec_context *ipsec = &adapter->ipsec_ctxt;

	if (ipsec->rx_sa_cnt == ipsec->max_rx_sa_cnt)
		goto out_full;

	for (i = 0; i < ipsec->max_rx_sa_cnt; i++) {
		if (!ipsec->rx_sa_table[i].used) {
			LOG_DEBUG_BDF("get empty rx sa cnt is %d\n", i);
			ipsec->rx_sa_table[i].index = (u16)i;
			return ipsec->rx_sa_table[i].index;
		}
	}

out_full:
	LOG_ERROR_BDF("failed to get empty rx sa, table is full\n");

	return -ENOSPC;
}

s32 sxe2_fwc_ipsec_rx_sa_set(struct sxe2_adapter *adapter,
			     struct sxe2_fwc_ipsec_rxsa_set_req *req,
			     struct sxe2_fwc_ipsec_rxsa_add_resp *resp)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {0};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_IPSEC_RXSA_SET, req,
				  sizeof(*req), resp, sizeof(*resp));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("failed to add rx sa with adminq, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

s32 sxe2_fwc_ipsec_rx_sa_add(struct sxe2_adapter *adapter,
			     struct sxe2_fwc_ipsec_rxsa_add_req *req,
			     struct sxe2_fwc_ipsec_rxsa_add_resp *resp)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {0};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_IPSEC_RXSA_ADD, req, sizeof(*req),
				  resp, sizeof(*resp));
	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_IPSEC_RXSA_ADD, req,
				  sizeof(*req), resp, sizeof(*resp));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("failed to add rx sa with adminq, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

static s32 sxe2_ipsec_rx_sa_add(struct sxe2_adapter *adapter,
				struct sxe2_rx_sa *rsa)
{
	s32 ret;
	u32 i;
	u32 mode = 0;
	struct sxe2_fwc_ipsec_rxsa_add_req req;
	struct sxe2_fwc_ipsec_rxsa_add_resp resp;

	if (rsa->engine)
		mode |= SXE2_IPSEC_RX_ENGINE_SM4;

	if (rsa->is_auth)
		mode |= SXE2_IPSEC_RX_DECRYPT;

	if (rsa->ipv6)
		mode |= SXE2_IPSEC_RX_IPV6;

	req.mode = cpu_to_le32(mode);
	req.spi = cpu_to_le32(rsa->spi);

	LOG_DEBUG_BDF("mode:%d ,spi:0x%x\n", req.mode, req.spi);
	for (i = 0; i < SXE2_IPV6_ADDR_LEN; i++)
		req.ipaddr[i] = cpu_to_le32(rsa->ipaddr[i]);

	memcpy(req.encrypt_keys, rsa->enc_key, SXE2_IPSEC_KEY_LEN);
	memcpy(req.auth_keys, rsa->auth_key, SXE2_IPSEC_KEY_LEN);

	req.func_type = rsa->is_vf ? SXE2_VF : SXE2_PF;
	req.func_id = rsa->is_vf ? (u8)(adapter->vf_ctxt.vfid_base + rsa->vf_id) : adapter->pf_idx;
	req.drv_id = 0;

	ret = sxe2_fwc_ipsec_rx_sa_add(adapter, &req, &resp);
	if (ret) {
		LOG_ERROR_BDF("failed to add rx sa, ret=%d\n", ret);
		ret = -EIO;
		goto out;
	}

	rsa->hw_index = le32_to_cpu(resp.sa_idx);
	rsa->ip_id = resp.ip_id;
	LOG_DEBUG_BDF("add rx sa ok - sa_idx:%d ip_id:%d\n", rsa->hw_index,
		      rsa->ip_id);

out:

	return ret;
}

static s32 sxe2_ipsec_rx_state_add(struct sxe2_adapter *adapter,
				   struct xfrm_state *xs, bool is_vf, u32 vf_id,
				   u32 *hw_index)
{
	s32 ret;
	u32 i;
	struct sxe2_rx_sa rsa;
	struct sxe2_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	unsigned long flags;

	ret = sxe2_ipsec_empty_rxtable_find(adapter);
	if (ret < 0) {
		LOG_ERROR_BDF("failed to get empty rx_sa idx.\n");
		return ret;
	}

	(void)memset(&rsa, 0x0, sizeof(rsa));
	rsa.xs = xs;

	if (xs->aalg)
		rsa.is_auth = true;
	else
		rsa.is_auth = false;

	if (xs->props.ealgo == SADB_X_EALG_AESCBC) {
		rsa.engine = SXE2_IPSEC_ALG_AES;
	} else if (xs->props.ealgo == SADB_X_EALG_SM4CBC) {
		rsa.engine = SXE2_IPSEC_ALG_SM4;
	} else {
		rsa.engine = SXE2_IPSEC_ALG_AES;
		LOG_ERROR_BDF("wrong ealg[%s]\n", xs->ealg->alg_name);
	}

	if (xs->props.family == AF_INET6) {
		rsa.ipv6 = true;
		for (i = 0; i < SXE2_IPV6_ADDR_LEN; i++)
			rsa.ipaddr[i] = xs->id.daddr.a6[i];

	} else {
		rsa.ipv6 = false;
		rsa.ipaddr[0] = xs->id.daddr.a4;
	}

	rsa.index = (u16)ret;
	rsa.used = true;
	rsa.spi = xs->id.spi;
	LOG_DEBUG_BDF("xs spi:0x%x rsa.spi:0x%x\n", be32_to_cpu(xs->id.spi),
		      be32_to_cpu(rsa.spi));
	ret = sxe2_ipsec_parse_proto_keys(xs, rsa.enc_key, rsa.auth_key);
	if (ret) {
		LOG_ERROR_BDF("failed to get key data for Rx SA table\n");
		return ret;
	}
	if (is_vf) {
		rsa.is_vf = true;
		rsa.vf_id = vf_id;
	}
	ret = sxe2_ipsec_rx_sa_add(adapter, &rsa);
	if (ret) {
		LOG_ERROR_BDF("failed to add rx sa ret=%d.\n", ret);
		memset(&rsa, 0x0, sizeof(rsa));
		return ret;
	}
	LOG_DEBUG_BDF("add fw rx_sa[index:%d] ok.\n", rsa.hw_index);

	xs->xso.offload_handle = rsa.index;
	*hw_index = rsa.hw_index;
	(void)memcpy(&ipsec->rx_sa_table[rsa.index], &rsa, sizeof(rsa));

	spin_lock_irqsave(&ipsec->rx_hlist_lock, flags);
	hash_add_rcu(ipsec->rx_sa_list, &ipsec->rx_sa_table[rsa.index].hlist,
		     rsa.xs->id.spi);
	ipsec->rx_sa_cnt++;
	spin_unlock_irqrestore(&ipsec->rx_hlist_lock, flags);
	LOG_DEBUG_BDF("[count++]current rx sa cnt is %d\n", ipsec->rx_sa_cnt);

	return 0;
}

static s32 sxe2_ipsec_empty_txtable_find(struct sxe2_adapter *adapter)
{
	u32 i;
	struct sxe2_ipsec_context *ipsec = &adapter->ipsec_ctxt;

	if (ipsec->tx_sa_cnt == ipsec->max_tx_sa_cnt)
		goto out_full;

	for (i = 0; i < ipsec->max_tx_sa_cnt; i++) {
		if (!ipsec->tx_sa_table[i].used) {
			LOG_DEBUG_BDF("get empty tx sa cnt is %d\n", i);
			return (s32)i;
		}
	}
out_full:
	LOG_ERROR_BDF("failed to get empty tx sa, table is full\n");
	return -ENOSPC;
}

s32 sxe2_fwc_ipsec_tx_sa_set(struct sxe2_adapter *adapter,
			     struct sxe2_fwc_ipsec_txsa_set_req *req,
			     struct sxe2_fwc_ipsec_txsa_add_resp *resp)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {0};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_IPSEC_TXSA_SET, req,
				  sizeof(*req), resp, sizeof(*resp));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("failed to set tx sa with adminq, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

s32 sxe2_fwc_ipsec_tx_sa_add(struct sxe2_adapter *adapter,
			     struct sxe2_fwc_ipsec_txsa_add_req *req,
			     struct sxe2_fwc_ipsec_txsa_add_resp *resp)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {0};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_IPSEC_TXSA_ADD, req,
				  sizeof(*req), resp, sizeof(*resp));

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("failed to add tx sa with adminq, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

static s32 sxe2_ipsec_tx_sa_add(struct sxe2_adapter *adapter,
				struct sxe2_tx_sa *sa)
{
	s32 ret;
	u32 mode = 0;
	u32 i;
	struct sxe2_fwc_ipsec_txsa_add_req req;
	struct sxe2_fwc_ipsec_txsa_add_resp resp;

	if (sa->engine)
		mode |= SXE2_IPSEC_TX_ENGINE_SM4;

	if (sa->is_auth)
		mode |= SXE2_IPSEC_TX_ENCRYPT;

	req.mode = cpu_to_le32(mode);

	for (i = 0; i < SXE2_IPSEC_KEY_LEN; i++) {
		req.encrypt_keys[i] = sa->enc_key[i];
		req.auth_keys[i] = sa->auth_key[i];
	}

	req.func_type = sa->is_vf ? SXE2_VF : SXE2_PF;
	req.func_id = sa->is_vf ? (u8)(adapter->vf_ctxt.vfid_base + sa->vf_id) : adapter->pf_idx;
	req.drv_id = 0;

	ret = sxe2_fwc_ipsec_tx_sa_add(adapter, &req, &resp);
	if (ret) {
		LOG_ERROR_BDF("failed to add tx sa, ret=%d\n", ret);
		ret = -EIO;
		goto out;
	}
	sa->hw_index = le32_to_cpu(resp.index);

out:

	return ret;
}

static s32 sxe2_ipsec_tx_state_add(struct sxe2_adapter *adapter,
				   struct xfrm_state *xs, bool is_vf, u32 vf_id,
				   u32 *hw_index)
{
	struct sxe2_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	s32 ret;
	struct sxe2_tx_sa tsa;

	ret = sxe2_ipsec_empty_txtable_find(adapter);
	if (ret < 0) {
		LOG_ERROR_BDF("no more tx sa space.\n");
		return ret;
	}

	(void)memset(&tsa, 0x0, sizeof(tsa));
	tsa.index = (u16)ret;
	tsa.xs = xs;
	tsa.used = true;

	if (xs->aalg)
		tsa.is_auth = true;
	else
		tsa.is_auth = false;

	if (xs->props.ealgo == SADB_X_EALG_AESCBC) {
		tsa.engine = SXE2_IPSEC_ALG_AES;
	} else if (xs->props.ealgo == SADB_X_EALG_SM4CBC) {
		tsa.engine = SXE2_IPSEC_ALG_SM4;
	} else {
		tsa.engine = SXE2_IPSEC_ALG_AES;
		LOG_ERROR_BDF("wrong ealg[%s]\n", xs->ealg->alg_name);
	}

	ret = sxe2_ipsec_parse_proto_keys(xs, tsa.enc_key, tsa.auth_key);
	if (ret) {
		LOG_ERROR_BDF("failed to get key data for Tx SA table\n");
		memset(&tsa, 0x0, sizeof(tsa));
		return ret;
	}

	tsa.spi = xs->id.spi;

	if (is_vf) {
		tsa.is_vf = true;
		tsa.vf_id = vf_id;
	}

	ret = sxe2_ipsec_tx_sa_add(adapter, &tsa);
	if (ret) {
		LOG_ERROR_BDF("fFailed to request Tx SA entry\n");
		memset(&tsa, 0x0, sizeof(tsa));
		return ret;
	}
	LOG_DEBUG_BDF("add fw tx_sa[index:%d] ok.\n", tsa.index);

	xs->xso.offload_handle = tsa.index;
	*hw_index = tsa.hw_index;
	(void)memcpy(&ipsec->tx_sa_table[tsa.index], &tsa, sizeof(tsa));
	ipsec->tx_sa_cnt++;
	LOG_DEBUG_BDF("[count++]current tx sa cnt is %d\n", ipsec->tx_sa_cnt);

	return 0;
}

#ifdef IPSEC_STATE_ADD_API_NEED_1_PARAMS
static int sxe2_ipsec_state_add(struct xfrm_state *xs)
#else
static int sxe2_ipsec_state_add(struct xfrm_state *xs,
				struct netlink_ext_ack *extack)
#endif
{
#ifdef IPSEC_HAVE_REAL_DEV
	struct net_device *netdev = xs->xso.real_dev;
#else
	struct net_device *netdev = xs->xso.dev;
#endif
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_adapter *adapter = priv->vsi->adapter;
	s32 ret;
	u32 hw_index;

	mutex_lock(&adapter->ipsec_ctxt.context_lock);

	if (adapter->ipsec_ctxt.status != SXE2_IPSEC_READY) {
		LOG_ERROR_BDF("failed to add sa, because ipsec status is wrong\n");
		ret = -EBUSY;
		goto out;
	}

	if (!sxe2_is_ipsec_offload_enable(netdev)) {
		LOG_ERROR_BDF("failed to add sa, because ipsec offload is disable.\n");
		ret = -EINVAL;
		goto out;
	}

	ret = sxe2_ipsec_xs_validate(xs);
	if (ret)
		goto out;

#ifdef IPSEC_HAVE_XS_XSO_DIR
	if (xs->xso.dir == XFRM_DEV_OFFLOAD_IN) {
#else
	if (xs->xso.flags & XFRM_OFFLOAD_INBOUND) {
#endif
		ret = sxe2_ipsec_rx_state_add(adapter, xs, false, 0, &hw_index);
		if (ret)
			LOG_ERROR_BDF("failed to add rx sa\n");
	} else {
		ret = sxe2_ipsec_tx_state_add(adapter, xs, false, 0, &hw_index);
		if (ret)
			LOG_ERROR_BDF("failed to add tx sa\n");
	}

out:
	mutex_unlock(&adapter->ipsec_ctxt.context_lock);

	return ret;
}

static struct sxe2_rx_sa *sxe2_ipsec_rx_sa_find_rcu(struct sxe2_adapter *adapter,
						    u32 hw_idx, u32 spi)
{
	struct sxe2_rx_sa *rsa = NULL;
	struct sxe2_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	bool hit = false;

	if (!ipsec->rx_sa_table) {
		LOG_ERROR_BDF("rx sa table is NULL.\n");
		return NULL;
	}

	rcu_read_lock();
	hash_for_each_possible_rcu(ipsec->rx_sa_list, rsa, hlist, spi) {
		if (!rsa->used)
			continue;

		if (hw_idx == rsa->index) {
			LOG_DEBUG_BDF("rsa use:%d sa:[%d %d]\n", rsa->used,
				      rsa->hw_index, hw_idx);
			hit = true;
			break;
		}
	}
	rcu_read_unlock();

	if (!hit) {
		LOG_ERROR_BDF("failed to find rsa[sa:%d,spi:%d]\n", hw_idx, spi);
		return NULL;
	}
	return rsa;
}

static struct sxe2_rx_sa *sxe2_ipsec_rx_sa_find(struct sxe2_adapter *adapter,
						u32 hw_idx, u32 spi)
{
	struct sxe2_rx_sa *rsa = NULL;
	struct sxe2_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	u32 i;

	if (!ipsec->rx_sa_table) {
		LOG_ERROR_BDF("rx sa table is NULL.\n");
		return NULL;
	}

	for (i = 0; i < ipsec->max_rx_sa_cnt; i++) {
		rsa = &ipsec->rx_sa_table[i];
		if (!rsa->used)
			continue;
		if (hw_idx == rsa->index && spi == rsa->spi) {
			LOG_DEBUG_BDF("rsa use:%d sa:[%d %d]\n", rsa->used,
				      rsa->hw_index, hw_idx);
			return rsa;
		}
	}

	LOG_ERROR_BDF("failed to find rsa[sa:%d,spi:%d]\n", hw_idx, spi);

	return NULL;
}

s32 sxe2_fwc_ipsec_rx_sa_del(struct sxe2_adapter *adapter,
			     struct sxe2_fwc_ipsec_rxsa_del_req *req)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {0};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_IPSEC_RXSA_DEL, req,
				  sizeof(*req), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("failed to delete tx sa with adminq, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

static s32 sxe2_ipsec_rx_sa_del(struct sxe2_adapter *adapter,
				struct sxe2_rx_sa *rsa)
{
	s32 ret;
	struct sxe2_fwc_ipsec_rxsa_del_req req;

	req.sa_idx = cpu_to_le16((u16)rsa->hw_index);
	req.spi	   = cpu_to_le32(rsa->spi);
	req.ip_id  = (u8)rsa->ip_id;
	req.func_type = rsa->is_vf ? SXE2_VF : SXE2_PF;
	req.func_id = rsa->is_vf ? (u8)(adapter->vf_ctxt.vfid_base + rsa->vf_id) : adapter->pf_idx;
	req.drv_id = 0;

	ret = sxe2_fwc_ipsec_rx_sa_del(adapter, &req);
	if (ret) {
		LOG_ERROR_BDF("failed to delete tx sa, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

static void sxe2_ipsec_vf_xs_free(struct xfrm_state *xs)
{
	if (!xs)
		return;

	if (xs->ealg) {
		kfree_sensitive(xs->ealg);
		xs->ealg = NULL;
	}

	if (xs->aalg) {
		kfree_sensitive(xs->aalg);
		xs->aalg = NULL;
	}

	kfree_sensitive(xs);
}

void sxe2_ipsec_rx_state_free(struct sxe2_adapter *adapter, struct sxe2_rx_sa *rsa)
{
	struct sxe2_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	s32 ret;

	if (!rsa || !rsa->used) {
		LOG_ERROR_BDF("invalid rx sa selected\n");
		return;
	}

	ret = sxe2_ipsec_rx_sa_del(adapter, rsa);

	if (ret)
		LOG_ERROR_BDF("failed to delete rx_sa[%d], ret :%d\n",
			      rsa->hw_index, ret);
	else
		LOG_DEBUG_BDF("delete fw rx_sa[%d] ok.\n", rsa->hw_index);

	rsa->used = false;

	if (rsa->is_vf)
		sxe2_ipsec_vf_xs_free(rsa->xs);

	synchronize_rcu();
	(void)memset(rsa, 0, sizeof(struct sxe2_rx_sa));

	ipsec->rx_sa_cnt--;

	LOG_DEBUG_BDF("[count--]current rx sa cnt is %d\n", ipsec->rx_sa_cnt);
}

s32 sxe2_fwc_ipsec_tx_sa_del(struct sxe2_adapter *adapter,
			     struct sxe2_fwc_ipsec_txsa_del_req *req)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {0};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_IPSEC_TXSA_DEL, req,
				  sizeof(*req), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("failed to delete tx sa with adminq, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

static s32 sxe2_ipsec_tx_sa_del(struct sxe2_adapter *adapter,
				struct sxe2_tx_sa *tsa)
{
	s32 ret;
	struct sxe2_fwc_ipsec_txsa_del_req req;

	req.sa_idx = cpu_to_le16((u16)tsa->hw_index);
	req.func_type = tsa->is_vf ? SXE2_VF : SXE2_PF;
	req.func_id = tsa->is_vf ? (u8)(adapter->vf_ctxt.vfid_base + tsa->vf_id) : adapter->pf_idx;
	req.drv_id = 0;

	ret = sxe2_fwc_ipsec_tx_sa_del(adapter, &req);
	if (ret) {
		LOG_ERROR_BDF("failed to delete tx sa, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

static struct sxe2_tx_sa *sxe2_ipsec_tx_sa_find(struct sxe2_adapter *adapter,
						u32 index)
{
	struct sxe2_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	struct sxe2_tx_sa *tsa;

	if (!ipsec->tx_sa_table) {
		LOG_ERROR_BDF("tx sa table is NULL\n");
		goto out;
	}

	tsa = &ipsec->tx_sa_table[index];
	if (!tsa->used) {
		LOG_ERROR_BDF("request sa is not used\n");
		goto out;
	}

	return tsa;

out:
	return NULL;
}

void sxe2_ipsec_tx_state_free(struct sxe2_adapter *adapter, struct sxe2_tx_sa *tsa)
{
	struct sxe2_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	s32 ret;

	if (!tsa || !tsa->used) {
		LOG_ERROR_BDF("failed to find txsa, sa_idx=%d\n", tsa->hw_index);
		return;
	}

	ret = sxe2_ipsec_tx_sa_del(adapter, tsa);
	if (ret) {
		LOG_ERROR_BDF("failed to delete tx_sa[%d] from fw, ret=%d\n",
			      tsa->hw_index, ret);
	} else {
		LOG_DEBUG_BDF("delete tx_sa[%d] from fw ok.\n", tsa->hw_index);
	}
	tsa->hw_index = SXE2_IPSEC_HW_INDEX_INVALID;
	tsa->used = false;

	if (tsa->is_vf && tsa->xs)
		sxe2_ipsec_vf_xs_free(tsa->xs);

	(void)memset(tsa, 0, sizeof(struct sxe2_tx_sa));
	ipsec->tx_sa_cnt--;
	LOG_DEBUG_BDF("[count--]current tx sa cnt is %d\n", ipsec->tx_sa_cnt);
}

static void sxe2_ipsec_state_delete(struct xfrm_state *xs)
{
#ifdef IPSEC_HAVE_REAL_DEV
	struct net_device *netdev = xs->xso.real_dev;
#else
	struct net_device *netdev = xs->xso.dev;
#endif
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_adapter *adapter = priv->vsi->adapter;
	struct sxe2_rx_sa *rx_sa = NULL;
	struct sxe2_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	unsigned long flags;

#ifdef IPSEC_HAVE_XS_XSO_DIR
	if (xs->xso.dir == XFRM_DEV_OFFLOAD_IN) {
#else
	if (xs->xso.flags & XFRM_OFFLOAD_INBOUND) {
#endif
		LOG_DEBUG_BDF("delete rx sa.\n");
		rx_sa = sxe2_ipsec_rx_sa_find_rcu(adapter,
						  (u32)xs->xso.offload_handle, xs->id.spi);
		if (!rx_sa) {
			LOG_ERROR_BDF("failed to find rxsa ,spi = 0x%x,sa idx = 0x%lx\n",
				      xs->id.spi, xs->xso.offload_handle);
			return;
		}

		spin_lock_irqsave(&ipsec->rx_hlist_lock, flags);
		hash_del_rcu(&rx_sa->hlist);
		spin_unlock_irqrestore(&ipsec->rx_hlist_lock, flags);
	} else {
		LOG_DEBUG_BDF("delete tx sa.\n");
	}
}

static void sxe2_ipsec_state_free(struct xfrm_state *xs)
{
#ifdef IPSEC_HAVE_REAL_DEV
	struct net_device *netdev = xs->xso.real_dev;
#else
	struct net_device *netdev = xs->xso.dev;
#endif
	struct sxe2_netdev_priv *priv = netdev_priv(netdev);
	struct sxe2_adapter *adapter = priv->vsi->adapter;
	struct sxe2_rx_sa *rx_sa = NULL;
	struct sxe2_tx_sa *tx_sa = NULL;

	mutex_lock(&adapter->ipsec_ctxt.context_lock);
	if (adapter->ipsec_ctxt.status == SXE2_IPSEC_RESETTING)
		LOG_WARN_BDF("try to free sa when nic is resetting.\n");

#ifdef IPSEC_HAVE_XS_XSO_DIR
	if (xs->xso.dir == XFRM_DEV_OFFLOAD_IN) {
#else
	if (xs->xso.flags & XFRM_OFFLOAD_INBOUND) {
#endif
		LOG_DEBUG_BDF("free rx sa.\n");
		rx_sa = sxe2_ipsec_rx_sa_find(adapter, (u32)xs->xso.offload_handle, xs->id.spi);
		if (!rx_sa) {
			LOG_ERROR_BDF("failed to find rxsa ,spi = 0x%x,sa idx = 0x%lx\n",
				      xs->id.spi, xs->xso.offload_handle);
			goto out;
		}

		sxe2_ipsec_rx_state_free(adapter, rx_sa);
	} else {
		LOG_DEBUG_BDF("free tx sa.\n");
		tx_sa = sxe2_ipsec_tx_sa_find(adapter, (u32)xs->xso.offload_handle);
		if (!tx_sa) {
			LOG_ERROR_BDF("failed to find txsa ,sa idx = 0x%lx\n",
				      xs->xso.offload_handle);
			goto out;
		}

		sxe2_ipsec_tx_state_free(adapter, tx_sa);
	}

out:

	mutex_unlock(&adapter->ipsec_ctxt.context_lock);
}

static bool sxe2_ipsec_offload_ok(struct sk_buff *skb, struct xfrm_state *xs)
{
	if (xs->props.family == AF_INET) {
		if (ip_hdr(skb)->ihl != 5)
			return false;

	} else {
		if (ipv6_ext_hdr(ipv6_hdr(skb)->nexthdr))
			return false;
	}

	if (skb->len > SXE2_IPSEC_PAYLOAD_LIMIT)
		return false;

	return true;
}

const struct xfrmdev_ops sxe2_ipsec_ops = {
		.xdo_dev_state_add = sxe2_ipsec_state_add,
		.xdo_dev_state_delete = sxe2_ipsec_state_delete,
		.xdo_dev_state_free = sxe2_ipsec_state_free,
		.xdo_dev_offload_ok = sxe2_ipsec_offload_ok,
};

s32 sxe2_ipsec_fwc_get_ipsec_capa(struct sxe2_adapter *adapter,
				  struct sxe2_fwc_ipsec_capa_resq *resp)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {0};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_IPSEC_GET_CAPA, NULL, 0, resp,
				  sizeof(*resp));
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("failed to get ipsec capacity with adminq, ret=%d\n",
			      ret);
		ret = -EIO;
	}

	return ret;
}

STATIC s32 sxe2_ipsec_get_ipsec_capa(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_fwc_ipsec_capa_resq resp;

	ret = sxe2_ipsec_fwc_get_ipsec_capa(adapter, &resp);
	if (ret) {
		LOG_ERROR_BDF("failed to init ipsec, ret=%d\n", ret);
		ret = -EIO;
		goto out;
	}

	adapter->ipsec_ctxt.max_tx_sa_cnt = resp.tx_sa_cnt;
	adapter->ipsec_ctxt.max_rx_sa_cnt = resp.rx_sa_cnt;
out:
	return ret;
}

s32 sxe2_ipsec_init(struct sxe2_adapter *adapter)
{
	struct net_device *netdev = adapter->vsi_ctxt.main_vsi->netdev;
	struct sxe2_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	s32 ret;
	u32 size, i;

	memset(ipsec, 0, sizeof(struct sxe2_ipsec_context));
	ipsec->status = SXE2_IPSEC_UNINITIALIZED;
	mutex_init(&adapter->ipsec_ctxt.context_lock);
	ret = sxe2_ipsec_get_ipsec_capa(adapter);
	if (ret) {
		LOG_ERROR_BDF("failed to get ipsec capability.\n");
		goto l_out;
	}

	LOG_DEBUG_BDF("[init]current ipsec depth:[tx:%d rx:%d]\n",
		      ipsec->max_tx_sa_cnt, ipsec->max_rx_sa_cnt);

	if (ipsec->max_tx_sa_cnt == 0 && ipsec->max_rx_sa_cnt == 0) {
		ret = 0;
		goto l_disable;
	}

	size = (u32)sizeof(struct sxe2_rx_sa) * ipsec->max_rx_sa_cnt;
	ipsec->rx_sa_table = kzalloc(size, GFP_KERNEL);
	if (!ipsec->rx_sa_table) {
		LOG_ERROR_BDF("ipsec rx sa table mem:%uB alloc fail.\n", size);
		ret = -ENOMEM;
		goto l_out;
	}
	for (i = 0; i < ipsec->max_rx_sa_cnt; i++)
		ipsec->rx_sa_table[i].hw_index = SXE2_IPSEC_HW_INDEX_INVALID;

	size = (u32)sizeof(struct sxe2_tx_sa) * ipsec->max_tx_sa_cnt;
	ipsec->tx_sa_table = kzalloc(size, GFP_KERNEL);
	if (!ipsec->tx_sa_table) {
		LOG_ERROR_BDF("ipsec tx sa table mem:%uB alloc fail.\n", size);
		ret = -ENOMEM;
		goto l_free_rx_sa;
	}
	for (i = 0; i < ipsec->max_tx_sa_cnt; i++)
		ipsec->tx_sa_table[i].hw_index = SXE2_IPSEC_HW_INDEX_INVALID;

	spin_lock_init(&adapter->ipsec_ctxt.rx_hlist_lock);
	ipsec->rx_sa_cnt = 0;
	ipsec->tx_sa_cnt = 0;
	hash_init(ipsec->rx_sa_list);

	(void)memset(&ipsec->hw_stats, 0x0, sizeof(struct sxe2_ipsec_hw_stats));

	netdev->xfrmdev_ops = &sxe2_ipsec_ops;
	ipsec->status = SXE2_IPSEC_READY;

l_disable:
	return ret;

l_free_rx_sa:
	kfree(ipsec->rx_sa_table);
	ipsec->rx_sa_table = NULL;

l_out:
	LOG_ERROR_BDF("failed to init ipsec\n");
	ipsec->status = SXE2_IPSEC_ERROR;
	mutex_destroy(&adapter->ipsec_ctxt.context_lock);

	return ret;
}

void sxe2_ipsec_deinit(struct sxe2_adapter *adapter)
{
	struct sxe2_ipsec_context *ipsec = &adapter->ipsec_ctxt;

	ipsec->status = SXE2_IPSEC_UNINITIALIZED;
	kfree(ipsec->rx_sa_table);
	ipsec->rx_sa_table = NULL;

	kfree(ipsec->tx_sa_table);
	ipsec->tx_sa_table = NULL;

	mutex_destroy(&ipsec->context_lock);
}

s32 sxe2_ipsec_tx(struct sxe2_queue *txq, struct sxe2_tx_buf *first,
		  struct sxe2_tx_offload_info *offload)
{
	struct sxe2_netdev_priv *priv = netdev_priv(txq->netdev);
	struct sxe2_adapter *adapter = priv->vsi->adapter;
	struct xfrm_state *xs;
	struct sec_path *sp;
	struct sxe2_tx_sa *tsa;

	u32 index;
	u64 qw1 = offload->ctxt_desc_qw1;

	if (skb_is_gso(first->skb)) {
		LOG_ERROR_BDF("failed to offload ipsec,because tso is on.\n");
		goto out_failed;
	}

	sp = skb_sec_path(first->skb);
	if (unlikely(!sp->len)) {
		LOG_ERROR_BDF("failed to get sec path length = %d\n", sp->len);
		txq->stats->ipsec_stats.tx_error_invalid_sp++;
		goto out_failed;
	}

	xs = xfrm_input_state(first->skb);
	if (unlikely(!xs)) {
		LOG_ERROR_BDF("failed to get xfrm state,xs=%p\n", xs);
		txq->stats->ipsec_stats.tx_error_invalid_state++;
		goto out_failed;
	}

	index = (u32)xs->xso.offload_handle;
	tsa = sxe2_ipsec_tx_sa_find(adapter, index);
	if (unlikely(!tsa || !tsa->used)) {
		LOG_ERROR_BDF("unavailable sa_idx=%d\n", index);
		txq->stats->ipsec_stats.tx_error_invalid_state++;
		goto out_failed;
	}

	qw1 |= (u64)SXE2_TX_DESC_DTYPE_CTXT;
	qw1 |= 0x1 << SXE2_TXCD_QW1_IPSEC_EN_S;

	if (!tsa->is_auth)
		qw1 |= 0x1 << SXE2_TXCD_QW1_IPSEC_MODE_S;

	qw1 |= tsa->engine << SXE2_TXCD_QW1_IPSEC_ENGINE_MODE_S;
	qw1 |= (tsa->hw_index << SXE2_TXCD_QW1_IPSEC_SA_IDX_S) &
	       SXE2_TXCD_QW1_IPSEC_SA_IDX_M;

	offload->ctxt_desc_qw1 = qw1;
	offload->ctxt_desc_ipsec_offset = (u16)skb_transport_offset(first->skb);
#ifdef SXE2_CFG_DEBUG
	if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
		LOG_DEBUG_BDF("tx ipsec offload succeed!qw1:0x%llx, \t"
			      "ipsecoffset:0x%x,sa_index:%d\n",
			      offload->ctxt_desc_qw1, offload->ctxt_desc_ipsec_offset,
			      tsa->hw_index);
	}
#endif

	txq->stats->ipsec_stats.tx_offload_success++;
	return 0;

out_failed:

	return -1;
}

static bool sxe2_update_ipsec_stats(struct sxe2_adapter *adapter,
				    union sxe2_rx_desc *desc, struct sxe2_queue *rxq)
{
	bool ret = false;
	u8 ipsec_status = 0;
	struct sxe2_ipsec_context *ipsec = &adapter->ipsec_ctxt;

	ipsec_status = SXE2_RX_DESC_IPSEC_STATUS_GET(le32_to_cpu(desc->wb.status_lrocnt_fdpf_id));
	switch (ipsec_status) {
	case SXE2_IPSEC_DECRYPT_INTIGRITY_SUCCESS:
		ipsec->hw_stats.rx_decrypt_success++;
		ret = false;
		break;
	case SXE2_IPSEC_PACKET_TOOLONG_OVER_2K:
		ipsec->hw_stats.over_2k++;
		ret = true;
		break;
	case SXE2_IPSEC_SPI_IP_NOT_MATCHED:
		ipsec->hw_stats.spi_ip_not_matched++;
		ret = true;
		break;
	case SXE2_IPSEC_IP_KEY_INVALID:
		ipsec->hw_stats.ip_key_invalid++;
		ret = true;
		break;
	case SXE2_IPSEC_PAYLOAD_ICV_NOTALIGNED:
		ipsec->hw_stats.not_aligned++;
		ret = true;
		break;
	case SXE2_IPSEC_ICV_CHECK_FAIL:
		ipsec->hw_stats.icv_fail++;
		ret = true;
		break;
	case SXE2_IPSEC_DISABLED_BYPASS:
		ipsec->hw_stats.bypass_disable++;
		ret = true;
		break;
	case SXE2_IPSEC_MACSEC_BYPASS:
		ipsec->hw_stats.bypass_macsec++;
		ret = true;
		break;
	}

	if (ret && ipsec_status != SXE2_IPSEC_DISABLED_BYPASS &&
	    ipsec_status != SXE2_IPSEC_MACSEC_BYPASS) {
		LOG_ERROR_BDF("ipsec offload failed,status is %d\n", ipsec_status);
		rxq->stats->ipsec_stats.rx_error_decrypt_fail++;
	}

	return ret;
}

void sxe2_ipsec_rx(struct sxe2_queue *rxq, union sxe2_rx_desc *desc,
		   struct sk_buff *skb, u16 ptype)
{
	struct sxe2_netdev_priv *priv = netdev_priv(rxq->netdev);
	struct sxe2_adapter *adapter = priv->vsi->adapter;
	struct sxe2_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	struct xfrm_state *xs = NULL;
	struct xfrm_offload *xo = NULL;
	struct sxe2_rx_sa *rsa;
#ifndef IPSEC_NEED_USE_SECPATH_DUP
	struct sec_path *sp;
#endif
	__be32 spi;
	bool is_ipv4;
	bool is_ipv6;
	struct iphdr *ip4 = NULL;
	struct ipv6hdr *ip6 = NULL;
	u8 *c_hdr;
	struct sxe2_rx_ptype_info ptype_info;

	if (sxe2_update_ipsec_stats(adapter, desc, rxq))
		return;

	ptype_info = sxe2_rx_ptype_parse(ptype);

	is_ipv4 = (ptype_info.outer_ip == SXE2_PTYPE_OUTER_IP &&
		   ptype_info.outer_ip_ver == SXE2_PTYPE_OUTER_IPV4);

	is_ipv6 = (ptype_info.outer_ip == SXE2_PTYPE_OUTER_IP &&
		   ptype_info.outer_ip_ver == SXE2_PTYPE_OUTER_IPV6);

	if (is_ipv4) {
		ip4 = (struct iphdr *)(skb->data);
		c_hdr = (u8 *)ip4 + (size_t)(ip4->ihl * 4);
	} else if (is_ipv6) {
		ip6 = (struct ipv6hdr *)(skb->data);
		c_hdr = (u8 *)ip6 + sizeof(struct ipv6hdr);
	} else {
		LOG_DEBUG_BDF("rx ipsec offload failed.ptype:%d!\n", ptype);
		rxq->stats->ipsec_stats.rx_error_invalid_ptype++;
		return;
	}

	spi = ((struct ip_esp_hdr *)c_hdr)->spi;

	rcu_read_lock();
	hash_for_each_possible_rcu(ipsec->rx_sa_list, rsa, hlist, spi) {
		if (spi == rsa->xs->id.spi) {
			if (is_ipv4) {
				if (ip4->daddr == rsa->xs->id.daddr.a4) {
					xs = rsa->xs;
					xfrm_state_hold(xs);
					break;
				}
			} else if (is_ipv6) {
				if (!ipv6_addr_cmp(&rsa->xs->id.daddr.in6,
						   &ip6->daddr)) {
					xs = rsa->xs;
					xfrm_state_hold(xs);
					break;
				}
			}
		}
	}
	rcu_read_unlock();

	if (unlikely(!xs)) {
		LOG_ERROR_BDF("ipsec offload failed, xs is NULL!\n");
		rxq->stats->ipsec_stats.rx_error_invalid_state++;
		return;
	}

#ifdef IPSEC_NEED_USE_SECPATH_DUP
	skb->sp = secpath_dup(skb->sp);
	if (unlikely(!skb->sp)) {
		LOG_ERROR_BDF("rx ipsec offload failed,sp is NULL!\n");
		return;
	}
	skb->sp->xvec[skb->sp->len++] = xs;
	skb->sp->olen++;
#else
	sp = secpath_set(skb);
	if (unlikely(!sp)) {
		LOG_ERROR_BDF("rx ipsec offload failed,sp is NULL!\n");
		rxq->stats->ipsec_stats.rx_error_invalid_sp++;

		return;
	}

	sp->xvec[sp->len++] = xs;
	sp->olen++;
#endif

	xo = xfrm_offload(skb);
	xo->flags = CRYPTO_DONE;
	xo->status = CRYPTO_SUCCESS;

	rxq->stats->ipsec_stats.rx_offload_success++;
}

void sxe2_ipsec_stop(struct sxe2_adapter *adapter)
{
	struct sxe2_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	u32 i;
	s32 ret;
	struct sxe2_rx_sa *rsa;
	struct sxe2_tx_sa *tsa;

	mutex_lock(&adapter->ipsec_ctxt.context_lock);
	if (ipsec->status != SXE2_IPSEC_READY)
		goto out_unlock;

	ipsec->status = SXE2_IPSEC_RESETTING;

	for (i = 0; i < ipsec->max_tx_sa_cnt; i++) {
		tsa = &ipsec->tx_sa_table[i];
		if (!tsa)
			continue;

		if (!tsa->used)
			continue;

		if (tsa->is_vf)
			continue;

		ret = sxe2_ipsec_tx_sa_del(adapter, tsa);
		if (ret)
			LOG_ERROR_BDF("failed to delete tx sa[%d],ret=%d\n",
				      tsa->hw_index, ret);
		else
			LOG_DEBUG_BDF("delete fw tx_sa[index:%d] ok.\n",
				      tsa->hw_index);
		tsa->hw_index = SXE2_IPSEC_HW_INDEX_INVALID;
	}

	for (i = 0; i < ipsec->max_rx_sa_cnt; i++) {
		rsa = &ipsec->rx_sa_table[i];
		if (!rsa)
			continue;

		if (!rsa->used)
			continue;

		if (rsa->is_vf)
			continue;

		ret = sxe2_ipsec_rx_sa_del(adapter, rsa);
		if (ret)
			LOG_ERROR_BDF("failed to delete rx sa[%d],ret=%d\n",
				      rsa->hw_index, ret);
		else
			LOG_DEBUG_BDF("delete fw rx_sa[index:%d] ok.\n", i);
		rsa->hw_index = SXE2_IPSEC_HW_INDEX_INVALID;
	}
out_unlock:
	mutex_unlock(&adapter->ipsec_ctxt.context_lock);
}

void sxe2_ipsec_sa_clean(struct sxe2_adapter *adapter)
{
	struct sxe2_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	u32 i;

	for (i = 0; i < ipsec->max_rx_sa_cnt; i++)
		ipsec->rx_sa_table[i].hw_index = SXE2_IPSEC_HW_INDEX_INVALID;

	for (i = 0; i < ipsec->max_tx_sa_cnt; i++)
		ipsec->tx_sa_table[i].hw_index = SXE2_IPSEC_HW_INDEX_INVALID;
}

s32 sxe2_ipsec_rebuild(struct sxe2_adapter *adapter)
{
	u32 i;
	s32 ret;
	struct sxe2_tx_sa *tsa;
	struct sxe2_rx_sa *rsa;
	struct sxe2_ipsec_context *ipsec = &adapter->ipsec_ctxt;

	mutex_lock(&adapter->ipsec_ctxt.context_lock);
	if (ipsec->status != SXE2_IPSEC_RESETTING) {
		LOG_DEBUG_BDF("ipsec rebuild after initial failed\n");
		goto out_unlock;
	}

	for (i = 0; i < ipsec->max_tx_sa_cnt; i++) {
		tsa = &ipsec->tx_sa_table[i];
		if (!tsa->used)
			continue;
		if (tsa->is_vf)
			continue;

		ret = sxe2_ipsec_tx_sa_add(adapter, tsa);
		if (ret) {
			sxe2_ipsec_state_delete(tsa->xs);
			tsa->used = false;
			ipsec->tx_sa_cnt--;
			LOG_DEV_ERR("failed to request Tx SA[spi:0x%x] in reset, \t"
				    "please del this sa ret: %d\n",
				    be32_to_cpu(tsa->spi), ret);
			ret = -EIO;
		} else {
			LOG_DEBUG_BDF("add fw tx_sa[index:%d] ok.\n", i);
		}
	}

	for (i = 0; i < ipsec->max_rx_sa_cnt; i++) {
		rsa = &ipsec->rx_sa_table[i];
		if (!rsa->used)
			continue;
		if (rsa->is_vf)
			continue;

		ret = sxe2_ipsec_rx_sa_add(adapter, rsa);
		if (ret) {
			sxe2_ipsec_state_delete(rsa->xs);
			rsa->used = false;
			ipsec->rx_sa_cnt--;
			LOG_DEV_ERR("failed to request Rx SA[spi:0x%x] in reset, \t"
				    "please del this sa, ret: %d\n",
				    be32_to_cpu(rsa->spi), ret);
			ret = -EIO;
		} else {
			LOG_DEBUG_BDF("add fw rx_sa[index:%d] ok.\n", i);
		}
	}

	ipsec->status = SXE2_IPSEC_READY;

out_unlock:
	mutex_unlock(&adapter->ipsec_ctxt.context_lock);

	return 0;
}

bool sxe2_is_ipsec_can_not_disable(struct sxe2_adapter *adapter)
{
	struct sxe2_ipsec_context *ipsec = &adapter->ipsec_ctxt;

	return (!!ipsec->rx_sa_cnt) || (!!ipsec->tx_sa_cnt);
}

bool sxe2_ipsec_conflict_features_check(struct sxe2_adapter *adapter,
					struct net_device *netdev)
{
	netdev_features_t tso_features =
			NETIF_F_TSO | NETIF_F_TSO_ECN | NETIF_F_TSO6 |
			NETIF_F_GSO_GRE | NETIF_F_GSO_UDP_TUNNEL |
			NETIF_F_GSO_GRE_CSUM | NETIF_F_GSO_UDP_TUNNEL_CSUM |
			NETIF_F_GSO_PARTIAL |
#ifdef NETIF_F_GSO_UDP_L4
			NETIF_F_GSO_UDP_L4 |
#endif
			NETIF_F_GSO_IPXIP4 | NETIF_F_GSO_IPXIP6;

	netdev_features_t features = netdev->features;

	if (features & NETIF_F_LRO)
		return true;

	if (features & (NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_STAG_TX))
		return true;

	if (features & (NETIF_F_IP_CSUM | NETIF_F_SCTP_CRC | NETIF_F_IPV6_CSUM))
		return true;

	if (features & (tso_features))
		return true;

#ifdef HAVE_MACSEC_SUPPORT
	if (features & NETIF_F_HW_MACSEC)
		return true;
#endif

	return false;
}

s32 sxe2_ipsec_vf_sa_add(struct sxe2_adapter *adapter, u32 vf_id,
			 struct sxe2_vf_ipsec_sa_add_msg *req, u32 *hw_index,
			 bool is_restore)
{
	s32 ret = 0;
	u32 enc_size, auth_size, trunc_size;
	struct xfrm_state *xs = NULL;

	xs = kzalloc(sizeof(*xs), GFP_KERNEL);
	if (!xs) {
		ret = -ENOMEM;
		return ret;
	}

	if (req->dir == SXE2_IPSEC_DIR_RX) {
#ifdef IPSEC_HAVE_XS_XSO_DIR
		xs->xso.dir = XFRM_DEV_OFFLOAD_IN;
#else
		xs->xso.flags |= XFRM_OFFLOAD_INBOUND;
#endif
	}

	xs->id.spi = req->spi;

	if (req->mode & SXE2_MBX_IPSEC_IPV6) {
		xs->props.family = AF_INET6;
		(void)memcpy(&xs->id.daddr.a6, req->addr, sizeof(xs->id.daddr.a6));
	} else {
		xs->props.family = AF_INET;
		(void)memcpy(&xs->id.daddr.a4, req->addr, sizeof(xs->id.daddr.a4));
	}

#ifdef IPSEC_HAVE_REAL_DEV
	xs->xso.dev = adapter->vsi_ctxt.main_vsi->netdev;
	xs->xso.real_dev = adapter->vsi_ctxt.main_vsi->netdev;
#else
	xs->xso.dev = adapter->vsi_ctxt.main_vsi->netdev;
#endif

	if (req->mode & SXE2_MBX_IPSEC_SM4) {
		xs->props.ealgo = SADB_X_EALG_SM4CBC;
		enc_size = SXE2_IPSEC_SM4_KEY_BITS;
		auth_size = SXE2_IPSEC_SM3_AUTH_BITS;
		trunc_size = SXE2_IPSEC_SM3_AUTH_BITS;
	} else {
		xs->props.ealgo = SADB_X_EALG_AESCBC;
		enc_size = SXE2_IPSEC_AES_KEY_BITS;
		auth_size = SXE2_IPSEC_SHA256_AUTH_BITS;
		trunc_size = SXE2_IPSEC_SHA256_TRUNC_BITS;
	}

	xs->ealg = kzalloc(sizeof(*xs->ealg) + enc_size / BITS_PER_BYTE, GFP_KERNEL);

	if (!xs->ealg) {
		ret = -ENOMEM;
		goto err;
	}

	xs->ealg->alg_key_len = enc_size;
	(void)memcpy(xs->ealg->alg_key, req->enc_key, enc_size / BITS_PER_BYTE);

	if (req->mode & SXE2_MBX_IPSEC_AUTH) {
		xs->aalg = kzalloc(sizeof(*xs->aalg) + auth_size / BITS_PER_BYTE,
				   GFP_KERNEL);
		if (!xs->aalg) {
			ret = -ENOMEM;
			goto err;
		}

		xs->aalg->alg_key_len = auth_size;
		(void)memcpy(xs->aalg->alg_key, req->auth_key,
			     auth_size / BITS_PER_BYTE);
		xs->aalg->alg_trunc_len = trunc_size;
	}

	mutex_lock(&adapter->ipsec_ctxt.context_lock);

	if (req->dir == SXE2_IPSEC_DIR_RX) {
		ret = sxe2_ipsec_rx_state_add(adapter, xs, true, vf_id, hw_index);
		if (ret)
			goto err_unlock;
	} else {
		ret = sxe2_ipsec_tx_state_add(adapter, xs, true, vf_id, hw_index);
		if (ret)
			goto err_unlock;
	}

	mutex_unlock(&adapter->ipsec_ctxt.context_lock);

	return ret;

err_unlock:
	mutex_unlock(&adapter->ipsec_ctxt.context_lock);

err:
	sxe2_ipsec_vf_xs_free(xs);

	return ret;
}

s32 sxe2_ipsec_vf_sa_free(struct sxe2_adapter *adapter, u32 vf_id,
			  struct sxe2_vf_ipsec_sa_del_msg *req)
{
	struct sxe2_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	s32 ret = 0;
	u32 i = 0;
	u32 hw_index = req->sa_idx;
	struct sxe2_tx_sa *tsa = NULL;
	struct sxe2_rx_sa *rsa = NULL;

	mutex_lock(&adapter->ipsec_ctxt.context_lock);
	if (req->dir == SXE2_IPSEC_DIR_RX) {
		if (hw_index >= ipsec->max_rx_sa_cnt) {
			ret = -EINVAL;
			goto out_unlock;
		}

		for (i = 0; i < ipsec->max_rx_sa_cnt; i++) {
			if (ipsec->rx_sa_table[i].used &&
			    ipsec->rx_sa_table[i].is_vf &&
			    ipsec->rx_sa_table[i].vf_id == vf_id &&
			    ipsec->rx_sa_table[i].hw_index == hw_index) {
				rsa = &ipsec->rx_sa_table[i];
				break;
			}
		}

		if (!rsa) {
			LOG_ERROR_BDF("failed to delete vf sa ,sa index:%d, vf id:%d\n",
				      hw_index, vf_id);
			ret = -ENOENT;
			goto out_unlock;
		}

		sxe2_ipsec_rx_state_free(adapter, rsa);
	} else {
		if (hw_index >= ipsec->max_tx_sa_cnt) {
			ret = -EINVAL;
			goto out_unlock;
		}

		for (i = 0; i < ipsec->max_tx_sa_cnt; i++) {
			if (ipsec->tx_sa_table[i].used &&
			    ipsec->tx_sa_table[i].is_vf &&
			    ipsec->tx_sa_table[i].vf_id == vf_id &&
			    ipsec->tx_sa_table[i].hw_index == hw_index) {
				tsa = &ipsec->tx_sa_table[i];
				break;
			}
		}

		if (!tsa) {
			ret = -ENOENT;
			goto out_unlock;
		}

		sxe2_ipsec_tx_state_free(adapter, tsa);
	}

out_unlock:
	mutex_unlock(&adapter->ipsec_ctxt.context_lock);

	return ret;
}

static s32 sxe2_fwc_ipsec_drv_clear(struct sxe2_adapter *adapter,
				    struct sxe2_fwc_ipsec_drv_clr_req *req)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {0};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_IPSEC_DRV_CLEAR, req,
				  sizeof(*req), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("failed to clear driver sa, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

s32 sxe2_dpdk_ipsec_resource_release(struct sxe2_adapter *adapter,
				     struct sxe2_obj *obj)
{
	struct sxe2_fwc_ipsec_drv_clr_req req;

	req.func_type = obj->func_type;
	req.func_id = obj->func_type == SXE2_PF ? obj->pf_id : obj->vf_id;
	req.drv_id = (u8)((obj->drv_type << 6) | obj->drv_id);
	return sxe2_fwc_ipsec_drv_clear(adapter, &req);
}
