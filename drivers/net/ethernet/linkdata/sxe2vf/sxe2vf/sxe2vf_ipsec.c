// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_ipsec.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include "sxe2_compat.h"
#include <net/xfrm.h>
#include <linux/if_bridge.h>
#include "sxe2vf.h"
#include "sxe2vf_netdev.h"
#include "sxe2_log.h"
#include "sxe2vf_ipsec.h"
#include "sxe2vf_rx.h"
#include "sxe2vf_tx.h"

#ifndef SADB_X_EALG_SM4CBC
#define SADB_X_EALG_SM4CBC 24
#endif

#ifndef SADB_X_AALG_SM3_256HMAC
#define SADB_X_AALG_SM3_256HMAC 10
#endif

#define SXE2VF_IPSEC_AES_KEY_BITS (256)
#define SXE2VF_IPSEC_SHA256_AUTH_BITS (256)
#define SXE2VF_IPSEC_SHA256_TRUNC_BITS (128)

#define SXE2VF_IPSEC_SM4_KEY_BITS (128)
#define SXE2VF_IPSEC_SM3_AUTH_BITS (256)
#define SXE2VF_IPSEC_SM3_TRUNC_BITS (96)

#define SXE2VF_IPSEC_ALG_SM4 (1)
#define SXE2VF_IPSEC_ALG_AES (0)

enum sxe2vf_rx_ipsec_status {
	SXE2VF_IPSEC_DECRYPT_INTIGRITY_SUCCESS,
	SXE2VF_IPSEC_PACKET_TOOLONG_OVER_2K,
	SXE2VF_IPSEC_SPI_IP_NOT_MATCHED,
	SXE2VF_IPSEC_IP_KEY_INVALID,
	SXE2VF_IPSEC_PAYLOAD_ICV_NOTALIGNED,
	SXE2VF_IPSEC_ICV_CHECK_FAIL,
	SXE2VF_IPSEC_DISABLED_BYPASS,
	SXE2VF_IPSEC_MACSEC_BYPASS
};

static s32 sxe2vf_ipsec_xs_validate(struct xfrm_state *xs)
{
#ifdef IPSEC_HAVE_REAL_DEV
	struct net_device *netdev = xs->xso.real_dev;
#else
	struct net_device *netdev = xs->xso.dev;
#endif
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);

	if (xs->props.aalgo != SADB_AALG_NONE) {
		if (!xs->aalg) {
			LOG_ERROR_BDF("auth instance error.\n");
			return -EINVAL;
		}
		if (xs->props.aalgo != SADB_X_AALG_SHA2_256HMAC &&
		    xs->props.aalgo != SADB_X_AALG_SM3_256HMAC) {
			LOG_ERROR_BDF("sxe2 only support hmac(sha256) or \t"
				      "sm3_256hmac.\n");
			return -EINVAL;
		}
	}

	if (!xs->ealg) {
		LOG_ERROR_BDF("sxe2 cannot offload without ealg\n");
		return -EINVAL;
	}

	if (xs->props.ealgo != SADB_X_EALG_AESCBC &&
	    xs->props.ealgo != SADB_X_EALG_SM4CBC) {
		LOG_ERROR_BDF("sxe2 only support cbc(aes) or sm4cbc.\n");
		return -EINVAL;
	}

	if (xs->props.calgo != SADB_X_CALG_NONE) {
		LOG_ERROR_BDF("sxe2 do not support compressed xfrm offloads\n");
		return -EINVAL;
	}

	if (xs->props.family != AF_INET && xs->props.family != AF_INET6) {
		LOG_ERROR_BDF("sxe2 only support IPv4/6 xfrm offloads\n");
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

	if (xs->ealg->alg_key_len != SXE2VF_IPSEC_SM4_KEY_BITS &&
	    xs->ealg->alg_key_len != SXE2VF_IPSEC_AES_KEY_BITS) {
		LOG_ERROR_BDF("sxe2 only support 256bit or 128bit key\n");
		return -EINVAL;
	}

	if (xs->aalg && xs->aalg->alg_key_len != SXE2VF_IPSEC_SM3_AUTH_BITS &&
	    xs->aalg->alg_key_len != SXE2VF_IPSEC_SHA256_AUTH_BITS) {
		LOG_ERROR_BDF("sxe2 check aalg auth and trunc length \t"
			      "failed.keylen:%d\n",
			      xs->aalg->alg_key_len);
		return -EINVAL;
	}

	if (xs->aalg && xs->aalg->alg_trunc_len != SXE2VF_IPSEC_SHA256_TRUNC_BITS &&
	    xs->aalg->alg_trunc_len != SXE2VF_IPSEC_SM3_TRUNC_BITS) {
		LOG_ERROR_BDF("sxe2 check aalg auth and trunc length \t"
			      "failed.trunc_len:%d\n",
			      xs->aalg->alg_trunc_len);
		return -EINVAL;
	}
	return 0;
}

static int sxe2vf_ipsec_parse_proto_keys(struct xfrm_state *xs, u8 *ealg_key,
					 u8 *aalg_key)
{
#ifdef IPSEC_HAVE_REAL_DEV
	struct net_device *netdev = xs->xso.real_dev;
#else
	struct net_device *netdev = xs->xso.dev;
#endif
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);

	if (!xs->ealg) {
		LOG_ERROR_BDF("null ealg.\n");
		return -EINVAL;
	}

	if (xs->props.ealgo == SADB_X_EALG_AESCBC) {
		if (xs->ealg->alg_key_len != SXE2VF_IPSEC_AES_KEY_BITS) {
			LOG_ERROR_BDF("failed to check ipsec keylen[%d]\n",
				      xs->ealg->alg_key_len);
			return -EINVAL;
		}

		memcpy(ealg_key, xs->ealg->alg_key, SXE2VF_IPSEC_AESKEY_LENGTH);

		if (xs->aalg) {
			if (xs->aalg->alg_key_len !=
			     SXE2VF_IPSEC_SHA256_AUTH_BITS ||
			    xs->aalg->alg_trunc_len !=
			     SXE2VF_IPSEC_SHA256_TRUNC_BITS) {
				LOG_ERROR_BDF("failed to check auth key len [%d = \t"
					      "%d]\t"
					      "or auth trunc len[%d = %d]\n",
					      xs->aalg->alg_key_len,
					      SXE2VF_IPSEC_SHA256_AUTH_BITS,
					      xs->aalg->alg_trunc_len,
					      SXE2VF_IPSEC_SHA256_TRUNC_BITS);
				return -EINVAL;
			}

			memcpy(aalg_key, xs->aalg->alg_key,
			       SXE2VF_IPSEC_AESAUTH_LENGTH);
		}
	} else if (xs->props.ealgo == SADB_X_EALG_SM4CBC) {
		if (xs->ealg->alg_key_len != SXE2VF_IPSEC_SM4_KEY_BITS) {
			LOG_ERROR_BDF("failed to check ealg key len [%d = %d]\n",
				      xs->ealg->alg_key_len,
				      SXE2VF_IPSEC_SM4_KEY_BITS);
			return -EINVAL;
		}
		memcpy(ealg_key, xs->ealg->alg_key, SXE2VF_IPSEC_SMKEY_LENGTH);
		if (xs->aalg) {
			if (xs->aalg->alg_key_len != SXE2VF_IPSEC_SM3_AUTH_BITS ||
			    xs->aalg->alg_trunc_len != SXE2VF_IPSEC_SM3_TRUNC_BITS) {
				LOG_ERROR_BDF("failed to check aalg key len [%d = \t"
					      "%d] or\t"
					      "auth trunc len[%d = %d]\n",
					      xs->aalg->alg_key_len,
					      SXE2VF_IPSEC_SM3_AUTH_BITS,
					      xs->aalg->alg_trunc_len,
					      SXE2VF_IPSEC_SM3_TRUNC_BITS);
				return -EINVAL;
			}
			memcpy(aalg_key, xs->aalg->alg_key,
			       SXE2VF_IPSEC_SMAUTH_LENGTH);
		}
	} else {
		LOG_ERROR_BDF("wrong aelg name:%s .\n", xs->ealg->alg_name);
		return -EINVAL;
	}
	return 0;
}

bool sxe2vf_is_ipsec_offload_enable(struct net_device *netdev)
{
	return netdev->features & NETIF_F_HW_ESP;
}

static s32 sxe2vf_ipsec_empty_rxtable_find(struct sxe2vf_adapter *adapter)
{
	u16 i;
	struct sxe2vf_ipsec_context *ipsec = &adapter->ipsec_ctxt;

	if (ipsec->rx_sa_cnt == ipsec->max_rx_sa_cnt)
		goto out_full;

	for (i = 0; i < ipsec->max_rx_sa_cnt; i++) {
		if (!ipsec->rx_sa_table[i].used) {
			LOG_DEBUG_BDF("get empty rx sa cnt is %d\n", i);
			ipsec->rx_sa_table[i].index = i;
			return ipsec->rx_sa_table[i].index;
		}
	}
out_full:
	LOG_ERROR_BDF("failed to get empty rx sa, table is full\n");
	return -ENOSPC;
}

static s32 sxe2vf_ipsec_rx_state_add(struct sxe2vf_adapter *adapter,
				     struct xfrm_state *xs)
{
	s32 ret;
	u32 i;
	struct sxe2vf_rx_sa rsa;
	struct sxe2vf_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	unsigned long flags;

	ret = sxe2vf_ipsec_empty_rxtable_find(adapter);
	if (ret < 0)
		return ret;

	(void)memset(&rsa, 0x0, sizeof(rsa));
	rsa.xs = xs;
	if (xs->aalg)
		rsa.is_auth = true;
	else
		rsa.is_auth = false;

	if (xs->props.ealgo == SADB_X_EALG_AESCBC) {
		rsa.engine = SXE2VF_IPSEC_ALG_AES;
	} else if (xs->props.ealgo == SADB_X_EALG_SM4CBC) {
		rsa.engine = SXE2VF_IPSEC_ALG_SM4;
	} else {
		rsa.engine = SXE2VF_IPSEC_ALG_AES;
		LOG_ERROR_BDF("wrong ealg[%s]\n", xs->ealg->alg_name);
	}

	if (xs->props.family == AF_INET6) {
		rsa.ipv6 = true;
		for (i = 0; i < SXE2VF_IPV6_ADDR_LEN; i++)
			rsa.ipaddr[i] = xs->id.daddr.a6[i];

	} else {
		rsa.ipv6 = false;
		rsa.ipaddr[0] = xs->id.daddr.a4;
	}

	rsa.index = (u16)ret;
	rsa.used = true;
	rsa.spi = xs->id.spi;
	LOG_DEBUG_BDF("xs spi:0x%x rsa.spi:0x%x\n", xs->id.spi, rsa.spi);
	ret = sxe2vf_ipsec_parse_proto_keys(xs, rsa.enc_key, rsa.auth_key);
	if (ret) {
		LOG_ERROR_BDF("failed to get key data for Rx SA table\n");
		return ret;
	}

	ret = sxe2vf_ipsec_add_rxsa_msg_send(adapter, &rsa, false);
	if (ret) {
		LOG_ERROR_BDF("failed to add rx sa,ret:%d\n", ret);
		return ret;
	}
	xs->xso.offload_handle = rsa.index;
	(void)memcpy(&ipsec->rx_sa_table[rsa.index], &rsa, sizeof(rsa));
	spin_lock_irqsave(&ipsec->rx_hlist_lock, flags);
	hash_add_rcu(ipsec->rx_sa_list, &ipsec->rx_sa_table[rsa.index].hlist,
		     rsa.xs->id.spi);
	ipsec->rx_sa_cnt++;
	spin_unlock_irqrestore(&ipsec->rx_hlist_lock, flags);
	LOG_DEBUG_BDF("[count++]current rx sa cnt is %d\n", ipsec->rx_sa_cnt);
	return 0;
}

static s32 sxe2vf_ipsec_empty_txtable_find(struct sxe2vf_adapter *adapter)
{
	u32 i;
	struct sxe2vf_ipsec_context *ipsec = &adapter->ipsec_ctxt;

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

static struct sxe2vf_tx_sa *sxe2vf_ipsec_tx_sa_find(struct sxe2vf_adapter *adapter,
						    u32 index)
{
	struct sxe2vf_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	struct sxe2vf_tx_sa *tsa;

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

static s32 sxe2vf_ipsec_tx_state_add(struct sxe2vf_adapter *adapter,
				     struct xfrm_state *xs)
{
	struct sxe2vf_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	s32 ret;
	struct sxe2vf_tx_sa tsa;

	ret = sxe2vf_ipsec_empty_txtable_find(adapter);
	if (ret < 0)
		return ret;

	(void)memset(&tsa, 0x0, sizeof(tsa));
	tsa.index = (u16)ret;
	tsa.xs = xs;
	tsa.used = true;
	if (xs->aalg)
		tsa.is_auth = true;
	else
		tsa.is_auth = false;

	if (xs->props.ealgo == SADB_X_EALG_AESCBC) {
		tsa.engine = SXE2VF_IPSEC_ALG_AES;
	} else if (xs->props.ealgo == SADB_X_EALG_SM4CBC) {
		tsa.engine = SXE2VF_IPSEC_ALG_SM4;
	} else {
		tsa.engine = SXE2VF_IPSEC_ALG_AES;
		LOG_ERROR_BDF("wrong ealg[%s]\n", xs->ealg->alg_name);
	}

	ret = sxe2vf_ipsec_parse_proto_keys(xs, tsa.enc_key, tsa.auth_key);
	if (ret) {
		LOG_ERROR_BDF("failed to get key data for Tx SA table\n");
		return ret;
	}

	tsa.spi = xs->id.spi;

	ret = sxe2vf_ipsec_add_txsa_msg_send(adapter, &tsa, false);
	if (ret) {
		LOG_ERROR_BDF("failed to add tx sa,ret:%d\n", ret);
		return ret;
	}
	xs->xso.offload_handle = tsa.index;
	(void)memcpy(&ipsec->tx_sa_table[tsa.index], &tsa, sizeof(tsa));
	ipsec->tx_sa_cnt++;
	LOG_DEBUG_BDF("[count++]current tx sa cnt is %d\n", ipsec->tx_sa_cnt);

	return 0;
}

#ifdef IPSEC_STATE_ADD_API_NEED_1_PARAMS
static int sxe2vf_ipsec_state_add(struct xfrm_state *xs)
#else
static int sxe2vf_ipsec_state_add(struct xfrm_state *xs,
				  struct netlink_ext_ack *extack)
#endif
{
#ifdef IPSEC_HAVE_REAL_DEV
	struct net_device *netdev = xs->xso.real_dev;
#else
	struct net_device *netdev = xs->xso.dev;
#endif
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	s32 ret;

	mutex_lock(&adapter->ipsec_ctxt.context_lock);
	if (adapter->ipsec_ctxt.status != SXE2VF_IPSEC_READY) {
		LOG_ERROR_BDF("failed to add sa, because ipsec status is wrong\n");
		ret = -EBUSY;
		goto out;
	}

	if (!sxe2vf_is_ipsec_offload_enable(netdev)) {
		LOG_ERROR_BDF("failed to add sa, because ipsec offload is \t"
			      "disable.\n");
		ret = -EINVAL;
		goto out;
	}

	ret = sxe2vf_ipsec_xs_validate(xs);
	if (ret)
		goto out;

#ifdef IPSEC_HAVE_XS_XSO_DIR
	if (xs->xso.dir == XFRM_DEV_OFFLOAD_IN) {
#else
	if (xs->xso.flags & XFRM_OFFLOAD_INBOUND) {
#endif
		ret = sxe2vf_ipsec_rx_state_add(adapter, xs);
		if (ret)
			LOG_ERROR_BDF("failed to add rx sa\n");
	} else {
		ret = sxe2vf_ipsec_tx_state_add(adapter, xs);
		if (ret)
			LOG_ERROR_BDF("failed to add tx sa\n");
	}
out:
	mutex_unlock(&adapter->ipsec_ctxt.context_lock);
	return ret;
}

static struct sxe2vf_rx_sa *sxe2vf_ipsec_rx_sa_find(struct sxe2vf_adapter *adapter,
						    u32 index, u32 spi)
{
	struct sxe2vf_rx_sa *rsa = NULL;
	struct sxe2vf_ipsec_context *ipsec = &adapter->ipsec_ctxt;

	if (!ipsec->rx_sa_table)
		goto out;

	rsa = &ipsec->rx_sa_table[index];
	if (!rsa->used)
		goto out;

	if (rsa->spi == spi) {
		LOG_DEBUG_BDF("rsa use:%d sa:[%d %d]\n", rsa->used, rsa->hw_index,
			      index);
		return rsa;
	}

out:
	LOG_ERROR_BDF("failed to find rsa[sa:%d,spi:%d]\n", index, spi);

	return NULL;
}

static struct sxe2vf_rx_sa *
sxe2vf_ipsec_rx_sa_find_rcu(struct sxe2vf_adapter *adapter, u32 index, u32 spi)
{
	struct sxe2vf_rx_sa *rsa = NULL;
	struct sxe2vf_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	bool hit = false;

	if (!ipsec->rx_sa_table) {
		LOG_ERROR_BDF("rx sa table is NULL.\n");
		return NULL;
	}

	rcu_read_lock();
	hash_for_each_possible_rcu(ipsec->rx_sa_list, rsa, hlist, spi) {
		if (!rsa->used)
			continue;

		if (index == rsa->index) {
			LOG_DEBUG_BDF("rsa use:%d sa:[%d %d]\n", rsa->used,
				      rsa->hw_index, index);
			hit = true;
			break;
		}
	}
	rcu_read_unlock();
	if (!hit) {
		LOG_ERROR_BDF("failed to find rsa[sa:%d,spi:%d]\n", index, spi);
		return NULL;
	}
	return rsa;
}

static void sxe2vf_ipsec_rx_state_clear(struct sxe2vf_adapter *adapter,
					struct sxe2vf_rx_sa *rsa)
{
	struct sxe2vf_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	s32 ret;

	if (!rsa || !rsa->used) {
		LOG_ERROR_BDF("invalid rx sa selected\n");
		return;
	}

	ret = sxe2vf_ipsec_clear_sa_msg_send(adapter, SXE2_IPSEC_DIR_RX,
					     rsa->hw_index);
	if (ret)
		LOG_ERROR_BDF("failed to delete rxsa,ret:%d\n", ret);

	synchronize_rcu();
	(void)memset(rsa, 0, sizeof(struct sxe2vf_rx_sa));
	ipsec->rx_sa_cnt--;
	LOG_DEBUG_BDF("[count--]current rx sa cnt is %d\n", ipsec->rx_sa_cnt);
}

static void sxe2vf_ipsec_tx_state_clear(struct sxe2vf_adapter *adapter,
					struct sxe2vf_tx_sa *tsa)
{
	struct sxe2vf_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	s32 ret;
#ifndef SXE2_CFG_RELEASE
	u32 sa_idx = tsa->hw_index;
#endif

	if (!tsa || !tsa->used) {
		LOG_ERROR_BDF("failed to find txsa, sa_idx=%d\n", sa_idx);
		return;
	}

	ret = sxe2vf_ipsec_clear_sa_msg_send(adapter, SXE2_IPSEC_DIR_TX,
					     tsa->hw_index);
	if (ret)
		LOG_ERROR_BDF("failed to delete tx sa, ret:%d\n", ret);

	(void)memset(tsa, 0, sizeof(struct sxe2vf_tx_sa));
	ipsec->tx_sa_cnt--;
	LOG_DEBUG_BDF("[count--]current tx sa cnt is %d\n", ipsec->tx_sa_cnt);
}

static void sxe2vf_ipsec_state_delete(struct xfrm_state *xs)
{
#ifdef IPSEC_HAVE_REAL_DEV
	struct net_device *netdev = xs->xso.real_dev;
#else
	struct net_device *netdev = xs->xso.dev;
#endif
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	struct sxe2vf_rx_sa *rx_sa = NULL;
	unsigned long flags;

#ifdef IPSEC_HAVE_XS_XSO_DIR
	if (xs->xso.dir == XFRM_DEV_OFFLOAD_IN) {
#else
	if (xs->xso.flags & XFRM_OFFLOAD_INBOUND) {
#endif
		LOG_DEBUG_BDF("delete rx sa.\n");
		rx_sa =
			sxe2vf_ipsec_rx_sa_find_rcu(adapter,
						    (u32)(xs->xso.offload_handle),
						    xs->id.spi);
		if (!rx_sa) {
			LOG_ERROR_BDF("failed to find rxsa ,spi = 0x%x, idx = \t"
				      "0x%lx\n",
				      xs->id.spi, xs->xso.offload_handle);
			return;
		}
		spin_lock_irqsave(&ipsec->rx_hlist_lock, flags);
		hash_del_rcu(&rx_sa->hlist);
		spin_unlock_irqrestore(&ipsec->rx_hlist_lock, flags);
	}
}

static void sxe2vf_ipsec_state_free(struct xfrm_state *xs)
{
#ifdef IPSEC_HAVE_REAL_DEV
	struct net_device *netdev = xs->xso.real_dev;
#else
	struct net_device *netdev = xs->xso.dev;
#endif
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);
	struct sxe2vf_rx_sa *rx_sa = NULL;
	struct sxe2vf_tx_sa *tx_sa = NULL;

	if (adapter->ipsec_ctxt.status != SXE2VF_IPSEC_READY)
		LOG_DEBUG_BDF("try to delete sa while resetting\n");

#ifdef IPSEC_HAVE_XS_XSO_DIR
	if (xs->xso.dir == XFRM_DEV_OFFLOAD_IN) {
#else
	if (xs->xso.flags & XFRM_OFFLOAD_INBOUND) {
#endif
		LOG_DEBUG_BDF("delete rx sa.\n");
		rx_sa =
			sxe2vf_ipsec_rx_sa_find(adapter,
						(u32)(xs->xso.offload_handle),
						xs->id.spi);
		if (!rx_sa) {
			LOG_ERROR_BDF("failed to find rxsa ,spi = 0x%x, idx = \t"
				      "0x%lx\n",
				      xs->id.spi, xs->xso.offload_handle);
			return;
		}

		sxe2vf_ipsec_rx_state_clear(adapter, rx_sa);
	} else {
		LOG_DEBUG_BDF("delete tx sa.\n");
		tx_sa = sxe2vf_ipsec_tx_sa_find(adapter,
						(u32)(xs->xso.offload_handle));
		if (!tx_sa) {
			LOG_ERROR_BDF("failed to find txsa ,sa idx = 0x%lx\n",
				      xs->xso.offload_handle);
			return;
		}

		sxe2vf_ipsec_tx_state_clear(adapter, tx_sa);
	}
}

static bool sxe2vf_ipsec_offload_ok(struct sk_buff *skb, struct xfrm_state *xs)
{
	if (xs->props.family == AF_INET) {
		if (ip_hdr(skb)->ihl != 5)
			return false;
	} else {
		if (ipv6_ext_hdr(ipv6_hdr(skb)->nexthdr))
			return false;
	}

	if (skb->len > SXE2VF_IPSEC_PAYLOAD_LIMIT)
		return false;

	return true;
}

const struct xfrmdev_ops sxe2vf_ipsec_ops = {
		.xdo_dev_state_add = sxe2vf_ipsec_state_add,
		.xdo_dev_state_delete = sxe2vf_ipsec_state_delete,
		.xdo_dev_state_free = sxe2vf_ipsec_state_free,
		.xdo_dev_offload_ok = sxe2vf_ipsec_offload_ok,
};

s32 sxe2vf_ipsec_init(struct sxe2vf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct sxe2vf_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	s32 ret = 0;
	u32 size;

	memset(ipsec, 0, sizeof(struct sxe2vf_ipsec_context));

	mutex_init(&ipsec->context_lock);
	ipsec->status = SXE2VF_IPSEC_UNINITIALIZED;
	ret = sxe2vf_ipsec_get_capa_msg_send(adapter);
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

	size = (u32)sizeof(struct sxe2vf_rx_sa) * ipsec->max_rx_sa_cnt;
	ipsec->rx_sa_table = kzalloc(size, GFP_KERNEL);
	if (!ipsec->rx_sa_table) {
		LOG_ERROR_BDF("ipsec rx sa table mem:%uB alloc fail.\n", size);
		ret = -ENOMEM;
		goto l_out;
	}

	size = (u32)sizeof(struct sxe2vf_tx_sa) * ipsec->max_tx_sa_cnt;
	ipsec->tx_sa_table = kzalloc(size, GFP_KERNEL);
	if (!ipsec->tx_sa_table) {
		LOG_ERROR_BDF("ipsec tx sa table mem:%uB alloc fail.\n", size);
		ret = -ENOMEM;
		goto l_free_rx_sa;
	}

	ipsec->rx_sa_cnt = 0;
	ipsec->tx_sa_cnt = 0;
	hash_init(ipsec->rx_sa_list);
	spin_lock_init(&ipsec->rx_hlist_lock);
	(void)memset(&ipsec->hw_stats, 0x0, sizeof(struct sxe2vf_ipsec_hw_stats));
	netdev->xfrmdev_ops = &sxe2vf_ipsec_ops;
	ipsec->status = SXE2VF_IPSEC_READY;

l_disable:
	return ret;

l_free_rx_sa:
	kfree(ipsec->rx_sa_table);
	ipsec->rx_sa_table = NULL;

l_out:
	ipsec->status = SXE2VF_IPSEC_ERROR;
	LOG_ERROR_BDF("failed to init ipsec\n");
	return ret;
}

void sxe2vf_ipsec_deinit(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_ipsec_context *ipsec = &adapter->ipsec_ctxt;

	ipsec->status = SXE2VF_IPSEC_UNINITIALIZED;
	kfree(ipsec->rx_sa_table);
	ipsec->rx_sa_table = NULL;

	kfree(ipsec->tx_sa_table);
	ipsec->tx_sa_table = NULL;

	mutex_destroy(&ipsec->context_lock);
}

s32 sxe2vf_ipsec_tx(struct sxe2vf_queue *txq, struct sxe2vf_tx_buf *first,
		    struct sxe2vf_tx_offload_info *offload)
{
	struct sxe2vf_adapter *adapter = netdev_priv(txq->netdev);
	struct xfrm_state *xs;
	struct sec_path *sp;
	struct sxe2vf_tx_sa *tsa;

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
	tsa = sxe2vf_ipsec_tx_sa_find(adapter, index);

	if (unlikely(!tsa || !tsa->used)) {
		LOG_ERROR_BDF("unavailable index=%d\n", index);
		txq->stats->ipsec_stats.tx_error_invalid_state++;
		goto out_failed;
	}

	qw1 |= (u64)SXE2VF_TX_DESC_DTYPE_CTXT;
	qw1 |= 0x1 << SXE2VF_TXCD_QW1_IPSEC_EN_S;
	if (!tsa->is_auth)
		qw1 |= 0x1 << SXE2VF_TXCD_QW1_IPSEC_MODE_S;
	qw1 |= tsa->engine << SXE2VF_TXCD_QW1_IPSEC_ENGINE_MODE_S;
	qw1 |= (tsa->hw_index << SXE2VF_TXCD_QW1_IPSEC_SA_IDX_S) &
	       SXE2VF_TXCD_QW1_IPSEC_SA_IDX_M;
	offload->ctxt_desc_qw1 = qw1;
	offload->ctxt_desc_ipsec_offset = (u16)skb_transport_offset(first->skb);

	LOG_DEBUG_BDF("tx ipsec offload succeed!qw1:0x%llx, \t"
		      "ipsec_offset:0x%x,sa_index:%d\n",
		      offload->ctxt_desc_qw1, offload->ctxt_desc_ipsec_offset,
		      tsa->hw_index);

	txq->stats->ipsec_stats.tx_offload_success++;

	return 0;

out_failed:

	return -1;
}

static bool sxe2vf_update_ipsec_stats(struct sxe2vf_adapter *adapter,
				      union sxe2vf_rx_desc *desc,
				      struct sxe2vf_queue *rxq)
{
	bool ret = false;
	u8 ipsec_status = 0;
	struct sxe2vf_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	u32 status_lrocnt_fdpf_id = le32_to_cpu(desc->wb.status_lrocnt_fdpf_id);

	ipsec_status = SXE2VF_RX_DESC_IPSEC_STATUS_GET(status_lrocnt_fdpf_id);

	switch (ipsec_status) {
	case SXE2VF_IPSEC_DECRYPT_INTIGRITY_SUCCESS:
		ipsec->hw_stats.rx_decrypt_success++;
		ret = false;
		break;
	case SXE2VF_IPSEC_PACKET_TOOLONG_OVER_2K:
		ipsec->hw_stats.over_2k++;
		ret = true;
		break;
	case SXE2VF_IPSEC_SPI_IP_NOT_MATCHED:
		ipsec->hw_stats.spi_ip_not_matched++;
		ret = true;
		break;
	case SXE2VF_IPSEC_IP_KEY_INVALID:
		ipsec->hw_stats.ip_key_invalid++;
		ret = true;
		break;
	case SXE2VF_IPSEC_PAYLOAD_ICV_NOTALIGNED:
		ipsec->hw_stats.not_aligned++;
		ret = true;
		break;
	case SXE2VF_IPSEC_ICV_CHECK_FAIL:
		ipsec->hw_stats.icv_fail++;
		ret = true;
		break;
	case SXE2VF_IPSEC_DISABLED_BYPASS:
		ipsec->hw_stats.bypass_disable++;
		ret = true;
		break;
	case SXE2VF_IPSEC_MACSEC_BYPASS:
		ipsec->hw_stats.bypass_macsec++;
		ret = true;
		break;
	}

	if (ret && ipsec_status != SXE2VF_IPSEC_DISABLED_BYPASS &&
	    ipsec_status != SXE2VF_IPSEC_MACSEC_BYPASS) {
		LOG_ERROR_BDF("ipsec offload failed,status is %d\n", ipsec_status);
		rxq->stats->ipsec_stats.rx_error_decrypt_fail++;
	}

	return ret;
}

void sxe2vf_ipsec_rx(struct sxe2vf_queue *rxq, union sxe2vf_rx_desc *desc,
		     struct sk_buff *skb, u16 ptype)
{
	struct sxe2vf_adapter *adapter = netdev_priv(rxq->netdev);
	struct sxe2vf_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	struct xfrm_state *xs = NULL;
	struct xfrm_offload *xo = NULL;
	struct sxe2vf_rx_sa *rsa;
#ifndef IPSEC_NEED_USE_SECPATH_DUP
	struct sec_path *sp;
#endif
	__be32 spi;
	bool is_ipv4;
	bool is_ipv6;
	struct iphdr *ip4 = NULL;
	struct ipv6hdr *ip6 = NULL;
	u8 *c_hdr;
	struct sxe2vf_rx_ptype_info ptype_info;

	if (sxe2vf_update_ipsec_stats(adapter, desc, rxq))
		return;

	ptype_info = sxe2vf_rx_ptype_parse(ptype);
	is_ipv4 = (ptype_info.outer_ip == SXE2VF_PTYPE_OUTER_IP) &&
		  (ptype_info.outer_ip_ver == SXE2VF_PTYPE_OUTER_IPV4);
	is_ipv6 = (ptype_info.outer_ip == SXE2VF_PTYPE_OUTER_IP) &&
		  (ptype_info.outer_ip_ver == SXE2VF_PTYPE_OUTER_IPV6);

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
		LOG_ERROR_BDF("rx ipsec offload failed! invalid xs\n");
		rxq->stats->ipsec_stats.rx_error_invalid_state++;
		return;
	}

#ifdef IPSEC_NEED_USE_SECPATH_DUP
	skb->sp = secpath_dup(skb->sp);
	if (unlikely(!skb->sp)) {
		LOG_DEV_ERR("rx ipsec offload failed! invalid sp\n");
		return;
	}
	skb->sp->xvec[skb->sp->len++] = xs;
	skb->sp->olen++;
#else
	sp = secpath_set(skb);
	if (unlikely(!sp)) {
		LOG_ERROR_BDF("rx ipsec offload failed! invalid sp\n");
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

s32 sxe2vf_ipsec_stop(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_ipsec_context *ipsec = &adapter->ipsec_ctxt;
	u32 i;
	s32 ret;
	struct sxe2vf_rx_sa *rsa;

	mutex_lock(&adapter->ipsec_ctxt.context_lock);

	if (ipsec->status != SXE2VF_IPSEC_READY)
		goto out_unlock;

	ipsec->status = SXE2VF_IPSEC_RESETTING;

	for (i = 0; i < ipsec->max_tx_sa_cnt; i++) {
		if (!ipsec->tx_sa_table[i].used)
			continue;

		ret = sxe2vf_ipsec_clear_sa_msg_send(adapter, SXE2_IPSEC_DIR_TX,
						     ipsec->tx_sa_table[i].hw_index);
		if (ret) {
			LOG_ERROR_BDF("failed to delete tx \t"
				      "sa[index:%d,sa_index:%d],ret=%d\n",
				      i, ipsec->tx_sa_table[i].hw_index, ret);
		} else {
			LOG_DEBUG_BDF("delete fw tx_sa[index:%d,sa_index:%d] ok.\n",
				      i, ipsec->tx_sa_table[i].hw_index);
		}
	}

	for (i = 0; i < ipsec->max_rx_sa_cnt; i++) {
		rsa = &ipsec->rx_sa_table[i];
		if (!rsa->used)
			continue;

		ret = sxe2vf_ipsec_clear_sa_msg_send(adapter, SXE2_IPSEC_DIR_RX,
						     ipsec->rx_sa_table[i].hw_index);
		if (ret)
			LOG_ERROR_BDF("failed to delete rx sa[index:%d]\n", i);
		else
			LOG_DEBUG_BDF("delete fw rx_sa[index:%d] ok.\n", i);
	}

out_unlock:
	mutex_unlock(&adapter->ipsec_ctxt.context_lock);
	return 0;
}

s32 sxe2vf_ipsec_rebuild(struct sxe2vf_adapter *adapter)
{
	u32 i;
	s32 ret;
	struct sxe2vf_tx_sa *tsa;
	struct sxe2vf_rx_sa *rsa;
	struct sxe2vf_ipsec_context *ipsec = &adapter->ipsec_ctxt;

	mutex_lock(&adapter->ipsec_ctxt.context_lock);

	if (ipsec->status != SXE2VF_IPSEC_RESETTING) {
		LOG_DEBUG_BDF("ipsec rebuild after initial failed\n");
		goto out_unlock;
	}

	for (i = 0; i < ipsec->max_tx_sa_cnt; i++) {
		tsa = &ipsec->tx_sa_table[i];
		if (!tsa->used)
			continue;

		ret = sxe2vf_ipsec_add_txsa_msg_send(adapter, tsa, true);
		if (ret) {
			sxe2vf_ipsec_state_delete(tsa->xs);
			tsa->used = false;
			ipsec->tx_sa_cnt--;
			LOG_DEV_ERR("failed to request Tx SA[spi:0x%x] in reset, \t"
				    "please\t"
				    "del this sa, ret %d\n",
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

		ret = sxe2vf_ipsec_add_rxsa_msg_send(adapter, rsa, true);
		if (ret) {
			sxe2vf_ipsec_state_delete(rsa->xs);
			rsa->used = false;
			ipsec->rx_sa_cnt--;
			LOG_DEV_ERR("failed to request Tx SA[spi:0x%x] in reset, \t"
				    "please\t"
				    "del this sa, ret %d\n",
				    be32_to_cpu(rsa->spi), ret);
			ret = -EIO;
		} else {
			LOG_DEBUG_BDF("add fw rx_sa[index:%d] ok.\n", i);
		}
	}

	ipsec->status = SXE2VF_IPSEC_READY;

out_unlock:
	mutex_unlock(&adapter->ipsec_ctxt.context_lock);
	return 0;
}

bool sxe2vf_is_ipsec_can_not_disable(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_ipsec_context *ipsec = &adapter->ipsec_ctxt;

	return (!!ipsec->rx_sa_cnt) || (!!ipsec->tx_sa_cnt);
}

bool sxe2vf_ipsec_conflict_features_check(struct net_device *netdev)
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

	return false;
}
