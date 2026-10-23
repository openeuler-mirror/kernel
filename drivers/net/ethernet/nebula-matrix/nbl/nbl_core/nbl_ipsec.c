// SPDX-License-Identifier: GPL-2.0
#include "nbl_ipsec.h"
#if IS_ENABLED(CONFIG_XFRM_OFFLOAD)
static int nbl_validate_xfrm_state(struct net_device *netdev, struct xfrm_state *x)
{
	if (x->id.proto != IPPROTO_ESP) {
		netdev_err(netdev, "Only ESP xfrm state may be offloaded\n");
		return -EINVAL;
	}

	if (x->props.aalgo != SADB_AALG_NONE) {
		netdev_err(netdev, "Cannot offload authenticated xfrm states\n");
		return -EINVAL;
	}

	if (x->props.ealgo != SADB_X_EALG_AES_GCM_ICV8 &&
	    x->props.ealgo != SADB_X_EALG_AES_GCM_ICV12 &&
	    x->props.ealgo != SADB_X_EALG_AES_GCM_ICV16) {
		netdev_err(netdev, "Only aes-gcm/sm4 xfrm state may be offloaded\n");
		return -EINVAL;
	}

	if (x->props.family != AF_INET && x->props.family != AF_INET6) {
		netdev_err(netdev, "Only IPv4/6 xfrm state may be offloaded\n");
		return -EINVAL;
	}

	if (x->props.mode != XFRM_MODE_TRANSPORT && x->props.mode != XFRM_MODE_TUNNEL) {
		netdev_err(netdev, "Only transport and tunnel xfrm state may be offloaded\n");
		return -EINVAL;
	}

	if (!x->aead) {
		netdev_err(netdev, "Cannot offload xfrm state without aead\n");
		return -EINVAL;
	}

	if (x->aead->alg_key_len != NBL_IPSEC_AES_128_ALG_LEN &&
	    x->aead->alg_key_len != NBL_IPSEC_AES_256_ALG_LEN) {
		netdev_err(netdev, "Cannot offload xfrm key length other than 128/256 bit\n");
		return -EINVAL;
	}

	if (x->aead->alg_icv_len != NBL_IPSEC_ICV_LEN_64 &&
	    x->aead->alg_icv_len != NBL_IPSEC_ICV_LEN_96 &&
	    x->aead->alg_icv_len != NBL_IPSEC_ICV_LEN_128) {
		netdev_err(netdev, "Cannot offload xfrm icv length other than 64/96/128 bit\n");
		return -EINVAL;
	}

	if (x->replay_esn && x->replay_esn->replay_window &&
	    x->replay_esn->replay_window != NBL_IPSEC_WINDOW_32 &&
	    x->replay_esn->replay_window != NBL_IPSEC_WINDOW_64 &&
	    x->replay_esn->replay_window != NBL_IPSEC_WINDOW_128 &&
	    x->replay_esn->replay_window != NBL_IPSEC_WINDOW_256) {
		netdev_err(netdev,
			   "Cannot offload xfrm replay_window other than 32/64/128/256 bit\n");
		return -EINVAL;
	}

	if (!(x->props.flags & XFRM_STATE_ESN) && x->props.replay_window &&
	    x->props.replay_window != NBL_IPSEC_WINDOW_32 &&
	    x->props.replay_window != NBL_IPSEC_WINDOW_64 &&
	    x->props.replay_window != NBL_IPSEC_WINDOW_128 &&
	    x->props.replay_window != NBL_IPSEC_WINDOW_256) {
		netdev_err(netdev,
			   "Cannot offload xfrm replay_window other than 32/64/128/256 bit\n");
		return -EINVAL;
	}

	if (!x->geniv) {
		netdev_err(netdev, "Cannot offload xfrm state without geniv\n");
		return -EINVAL;
	}

	if (strcmp(x->geniv, "seqiv")) {
		netdev_err(netdev, "Cannot offload xfrm state with geniv other than seqiv\n");
		return -EINVAL;
	}

	if ((x->lft.hard_byte_limit != XFRM_INF || x->lft.soft_byte_limit != XFRM_INF) &&
	    (x->lft.hard_packet_limit != XFRM_INF || x->lft.soft_packet_limit != XFRM_INF)) {
		netdev_err(netdev,
			   "Offloaded xfrm state does not support both byte & packet limits\n");
		return -EINVAL;
	}

	if (x->lft.soft_byte_limit >= x->lft.hard_byte_limit &&
	    x->lft.soft_byte_limit != XFRM_INF) {
		netdev_err(netdev, "Hard byte limit must be greater than soft limit\n");
		return -EINVAL;
	}

	if (x->lft.soft_packet_limit >= x->lft.hard_packet_limit &&
	    x->lft.soft_packet_limit != XFRM_INF) {
		netdev_err(netdev, "Hard packet limit must be greater than soft limit\n");
		return -EINVAL;
	}

	return 0;
}

static void nbl_ipsec_update_esn_state(struct xfrm_state *x, struct nbl_ipsec_esn_state *esn_state)
{
	bool esn = !!(x->props.flags & XFRM_STATE_ESN);
	bool inbound = (x->xso.dir == XFRM_DEV_OFFLOAD_IN);
	u32 bottom = 0;

	if (!esn) {
		esn_state->enable = 0;
		if (!inbound) {
			esn_state->sn = x->replay.oseq + 1;
			esn_state->wrap_en = (x->props.extra_flags & XFRM_SA_XFLAG_OSEQ_MAY_WRAP);
			return;
		}

		esn_state->sn = x->replay.seq + 1;
		if (x->props.replay_window) {
			esn_state->window_en = 1;
			esn_state->option = ilog2(x->props.replay_window / NBL_IPSEC_WINDOW_32);
		}
		return;
	}

	esn_state->enable = 1;
	if (!inbound) {
		esn_state->sn = x->replay_esn->oseq + 1;
		esn_state->esn = x->replay_esn->oseq_hi;
		return;
	}

	if (x->replay_esn->seq >= x->replay_esn->replay_window)
		bottom = x->replay_esn->seq - x->replay_esn->replay_window + 1;

	if (x->replay_esn->seq < NBL_IPSEC_REPLAY_MID_SEQ)
		esn_state->overlap = 1;

	esn_state->sn = x->replay_esn->seq + 1;
	esn_state->esn = xfrm_replay_seqhi(x, htonl(bottom));
	if (x->replay_esn->replay_window) {
		esn_state->window_en = 1;
		esn_state->option = ilog2(x->replay_esn->replay_window / NBL_IPSEC_WINDOW_32);
	}
}

static void nbl_ipsec_init_cfg_info(struct xfrm_state *x, struct nbl_ipsec_cfg_info *cfg_info)
{
	cfg_info->sa_key.family = x->props.family;
	cfg_info->sa_key.mark = x->mark.v & x->mark.m;
	cfg_info->sa_key.spi = x->id.spi;
	cfg_info->vld = true;
	memcpy(&cfg_info->sa_key.daddr, x->id.daddr.a6, sizeof(x->id.daddr.a6));

	if (x->lft.hard_byte_limit != XFRM_INF) {
		cfg_info->limit_type = NBL_IPSEC_LIFETIME_BYTE;
		cfg_info->hard_limit = x->lft.hard_byte_limit;
		if (x->lft.soft_byte_limit != XFRM_INF)
			cfg_info->soft_limit = x->lft.soft_byte_limit;
	}

	if (x->lft.hard_packet_limit != XFRM_INF) {
		cfg_info->limit_type = NBL_IPSEC_LIFETIME_PACKET;
		cfg_info->hard_limit = x->lft.hard_packet_limit;
		if (x->lft.soft_packet_limit != XFRM_INF)
			cfg_info->soft_limit = x->lft.soft_packet_limit;
	}

	if (cfg_info->hard_limit == 0)
		return;
	if (cfg_info->soft_limit == 0)
		cfg_info->soft_limit = NBL_GET_SOFT_BY_HARD(cfg_info->hard_limit);

	cfg_info->limit_enable = 1;
	cfg_info->hard_round = cfg_info->hard_limit >> NBL_IPSEC_LIFETIME_ROUND;
	cfg_info->hard_remain = cfg_info->hard_limit & NBL_IPSEC_LIFETIME_REMAIN;
	cfg_info->soft_round = cfg_info->soft_limit >> NBL_IPSEC_LIFETIME_ROUND;
	cfg_info->soft_remain = cfg_info->soft_limit & NBL_IPSEC_LIFETIME_REMAIN;

	if (cfg_info->hard_round <= 1) {
		cfg_info->lft_cnt = cfg_info->hard_limit;
		cfg_info->lft_diff = cfg_info->hard_limit - cfg_info->soft_limit;
		cfg_info->hard_round = 0;
		cfg_info->soft_round = 0;
	} else {
		cfg_info->lft_cnt = (1 << NBL_IPSEC_LIFETIME_ROUND) + cfg_info->soft_remain;
		cfg_info->lft_diff = (1 << NBL_IPSEC_LIFETIME_ROUND);
	}
}

static void nbl_ipsec_build_accel_xfrm_attrs(struct xfrm_state *x,
					     struct nbl_accel_esp_xfrm_attrs *attrs)
{
	struct aes_gcm_keymat *aes_gcm = &attrs->aes_gcm;
	struct aead_geniv_ctx *geniv_ctx;
	unsigned int key_len, icv_len;
	int i;
	u8 key[NBL_IPSEC_KEY_LEN_TOTAL] = {0};
	__be32 salt;

	/* key */
	key_len = NBL_GET_KEYLEN_BY_ALG(x->aead->alg_key_len);
	for (i = 0; i < key_len; i++)
		key[key_len - i - 1] = x->aead->alg_key[i];
	memcpy(aes_gcm->aes_key, key, key_len);
	if (strncmp(x->aead->alg_name, "rfc4106(gcm(aes))", sizeof(x->aead->alg_name)) == 0) {
		if (key_len == NBL_IPSEC_AES128_KEY_LEN)
			aes_gcm->crypto_type = NBL_IPSEC_AES_GCM_128;
		else
			aes_gcm->crypto_type = NBL_IPSEC_AES_GCM_256;
	} else {
		aes_gcm->crypto_type = NBL_IPSEC_SM4_GCM;
	}

	/* salt and seq_iv */
	geniv_ctx = crypto_aead_ctx(x->data);
	memcpy(&aes_gcm->seq_iv, &geniv_ctx->salt, sizeof(u64));
	memcpy(&salt, x->aead->alg_key + key_len, sizeof(u32));
	aes_gcm->salt = be32_to_cpu(salt);

	/* icv len */
	icv_len = x->aead->alg_icv_len;
	if (icv_len == NBL_IPSEC_ICV_LEN_64)
		aes_gcm->icv_len = NBL_IPSEC_ICV_64_TYPE;
	else if (icv_len == NBL_IPSEC_ICV_LEN_96)
		aes_gcm->icv_len = NBL_IPSEC_ICV_96_TYPE;
	else
		aes_gcm->icv_len = NBL_IPSEC_ICV_128_TYPE;

	/* tunnel mode */
	attrs->tunnel_mode = x->props.mode;
	/* spi */
	attrs->spi = be32_to_cpu(x->id.spi);

	/* nat traversal */
	if (x->encap) {
		attrs->nat_flag = 1;
		attrs->sport = be16_to_cpu(x->encap->encap_sport);
		attrs->dport = be16_to_cpu(x->encap->encap_dport);
	}

	/* source, destination ips */
	memcpy(&attrs->saddr, x->props.saddr.a6, sizeof(attrs->saddr));
	memcpy(&attrs->daddr, x->id.daddr.a6, sizeof(attrs->daddr));
	attrs->is_ipv6 = (x->props.family != AF_INET);
}

static void nbl_ipsec_free_tx_index(struct net_device *netdev, u32 index)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_ch_prm_ipsec_index prm = {0};

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	prm.index = index;
	netdev_info(netdev, "nbl ipsec egress free index %u\n", index);
	disp_ops->free_ipsec_tx_index(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &prm);
}

static void nbl_ipsec_free_rx_index(struct net_device *netdev, u32 index)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_ch_prm_ipsec_index prm = {0};

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	prm.index = index;
	netdev_info(netdev, "nbl ipsec ingress free index %u\n", index);
	disp_ops->free_ipsec_rx_index(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &prm);
}

static int nbl_ipsec_alloc_tx_index(struct net_device *netdev, struct nbl_ipsec_cfg_info *cfg_info)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_common_info *common;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_ch_prm_ipsec_index prm = {0};

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	cfg_info->vsi = NBL_COMMON_TO_VSI_ID(common);

	memcpy(&prm.cfg_info, cfg_info, sizeof(prm.cfg_info));
	return disp_ops->alloc_ipsec_tx_index(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &prm);
}

static int nbl_ipsec_alloc_rx_index(struct net_device *netdev, struct nbl_ipsec_cfg_info *cfg_info)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_common_info *common;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_ch_prm_ipsec_index prm = {0};

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	cfg_info->vsi = NBL_COMMON_TO_VSI_ID(common);

	memcpy(&prm.cfg_info, cfg_info, sizeof(prm.cfg_info));
	return disp_ops->alloc_ipsec_rx_index(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &prm);
}

static void nbl_ipsec_cfg_tx_sad(struct net_device *netdev, u32 index,
				 struct nbl_ipsec_sa_entry *sa_entry)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_ch_prm_cfg_ipsec_sad prm = {0};

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	prm.index = index;
	memcpy(&prm.sa_entry, sa_entry, sizeof(prm.sa_entry));
	netdev_info(netdev, "nbl ipsec cfg tx sad index %u\n", index);

	disp_ops->cfg_ipsec_tx_sad(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &prm);
}

static void nbl_ipsec_cfg_rx_sad(struct net_device *netdev, u32 index,
				 struct nbl_ipsec_sa_entry *sa_entry)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_ch_prm_cfg_ipsec_sad prm = {0};

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	prm.index = index;
	memcpy(&prm.sa_entry, sa_entry, sizeof(prm.sa_entry));
	netdev_info(netdev, "nbl ipsec cfg rx sad index %u\n", index);

	disp_ops->cfg_ipsec_rx_sad(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &prm);
}

static int nbl_ipsec_add_rx_flow(struct net_device *netdev, u32 index,
				 struct nbl_accel_esp_xfrm_attrs *attrs)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_common_info *common;
	u32 data[NBL_IPSEC_SPI_DIP__LEN] = {0};
	u32 dip[NBL_IPSEC_FLOW_IP_LEN] = {0};
	int i;
	struct nbl_ch_prm_cfg_ipsec_flow prm = {0};

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	common = NBL_SERV_MGT_TO_COMMON(serv_mgt);

	memcpy(data, &attrs->spi, sizeof(attrs->spi));
	if (attrs->is_ipv6) {
		for (i = 0; i < NBL_IPSEC_FLOW_IP_LEN; i++)
			dip[i] = ntohl(attrs->daddr.a6[NBL_IPSEC_FLOW_IP_LEN - 1 - i]);
	} else {
		dip[0] = ntohl(attrs->daddr.a4);
	}
	memcpy(data + 1, dip, sizeof(dip));

	prm.index = index;
	prm.vsi = NBL_COMMON_TO_VSI_ID(common);
	memcpy(prm.data, data, sizeof(data));
	return disp_ops->add_ipsec_rx_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &prm);
}

static int nbl_ipsec_add_tx_flow(struct net_device *netdev, u32 index, struct xfrm_selector *sel)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_common_info *common;
	u32 data[NBL_IPSEC_FLOW_TOTAL_LEN] = {0};
	u32 sip[NBL_IPSEC_FLOW_IP_LEN] = {0};
	u32 dip[NBL_IPSEC_FLOW_IP_LEN] = {0};
	struct nbl_ch_prm_cfg_ipsec_flow prm = {0};

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	common = NBL_SERV_MGT_TO_COMMON(serv_mgt);

	switch (sel->family) {
	case AF_INET:
		data[0] = AF_INET;
		data[NBL_IPSEC_FLOW_SIP_OFF] = ntohl(sel->saddr.a4);
		data[NBL_IPSEC_FLOW_DIP_OFF] = ntohl(sel->daddr.a4);
		break;
	case AF_INET6:
		data[0] = AF_INET6;
		be32_to_cpu_array(sip, sel->saddr.a6, NBL_IPSEC_FLOW_IP_LEN);
		be32_to_cpu_array(dip, sel->daddr.a6, NBL_IPSEC_FLOW_IP_LEN);
		memcpy(data + NBL_IPSEC_FLOW_SIP_OFF, sip, sizeof(sip));
		memcpy(data + NBL_IPSEC_FLOW_DIP_OFF, dip, sizeof(dip));
		break;
	default:
		return -EINVAL;
	}

	prm.index = index;
	prm.vsi = NBL_COMMON_TO_VSI_ID(common);
	memcpy(prm.data, data, sizeof(prm.data));
	return disp_ops->add_ipsec_tx_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &prm);
}

static int nbl_xfrm_add_state(struct xfrm_state *x, struct netlink_ext_ack *extack)
{
	struct nbl_ipsec_sa_entry *sa_entry;
	struct net_device *netdev = x->xso.dev;
	int index;
	int ret = 0;

	if (nbl_validate_xfrm_state(netdev, x))
		return -EINVAL;

	sa_entry = kzalloc(sizeof(*sa_entry), GFP_KERNEL);
	if (!sa_entry)
		return -ENOMEM;

	nbl_ipsec_init_cfg_info(x, &sa_entry->cfg_info);
	nbl_ipsec_update_esn_state(x, &sa_entry->esn_state);
	nbl_ipsec_build_accel_xfrm_attrs(x, &sa_entry->attrs);

	if (x->xso.dir == XFRM_DEV_OFFLOAD_IN) {
		index = nbl_ipsec_alloc_rx_index(netdev, &sa_entry->cfg_info);
		if (index < 0) {
			netdev_err(netdev, "No enough rx session resources\n");
			kfree(sa_entry);
			return -ENOSPC;
		}
		netdev_info(netdev, "nbl ipsec ingress index %d\n", index);

		ret = nbl_ipsec_add_rx_flow(netdev, index, &sa_entry->attrs);
		if (ret) {
			netdev_err(netdev, "No enough rx flow resources for %d\n", index);
			nbl_ipsec_free_rx_index(netdev, index);
			kfree(sa_entry);
			return -ENOSPC;
		}
		nbl_ipsec_cfg_rx_sad(netdev, index, sa_entry);
	} else {
		index = nbl_ipsec_alloc_tx_index(netdev, &sa_entry->cfg_info);
		if (index < 0) {
			netdev_err(netdev, "No enough tx session resources\n");
			kfree(sa_entry);
			return -ENOSPC;
		}
		netdev_info(netdev, "nbl ipsec egress index %d\n", index);

		ret = nbl_ipsec_add_tx_flow(netdev, index, &x->sel);
		if (ret) {
			netdev_err(netdev, "No enough tx flow resources for %d\n", index);
			nbl_ipsec_free_tx_index(netdev, index);
			kfree(sa_entry);
			return -ENOSPC;
		}
		nbl_ipsec_cfg_tx_sad(netdev, index, sa_entry);
	}

	sa_entry->index = (u32)index;
	x->xso.offload_handle = (unsigned long)sa_entry;

	return 0;
}

static void nbl_ipsec_del_tx_flow(struct net_device *netdev, u32 index)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_ch_prm_cfg_ipsec_flow prm = {0};

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	prm.index = index;
	disp_ops->del_ipsec_tx_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &prm);
}

static void nbl_ipsec_del_rx_flow(struct net_device *netdev, u32 index)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_ch_prm_cfg_ipsec_flow prm = {0};

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	prm.index = index;
	disp_ops->del_ipsec_rx_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &prm);
}

static void nbl_xfrm_del_state(struct xfrm_state *x)
{
}

static void nbl_xfrm_free_state(struct xfrm_state *x)
{
	struct nbl_ipsec_sa_entry *sa_entry = (struct nbl_ipsec_sa_entry *)x->xso.offload_handle;
	struct net_device *netdev = x->xso.dev;

	if (x->xso.dir == XFRM_DEV_OFFLOAD_IN) {
		nbl_ipsec_del_rx_flow(netdev, sa_entry->index);
		nbl_ipsec_free_rx_index(netdev, sa_entry->index);
	} else {
		nbl_ipsec_del_tx_flow(netdev, sa_entry->index);
		nbl_ipsec_free_tx_index(netdev, sa_entry->index);
	}

	kfree(sa_entry);
}

static bool nbl_offload_ok(struct sk_buff *skb, struct xfrm_state *x)
{
#define NBL_IP_HEADER_LEN		5
	if (x->props.family == AF_INET) {
		if (ip_hdr(skb)->ihl != NBL_IP_HEADER_LEN)
			return false;
	} else {
		if (ipv6_ext_hdr(ipv6_hdr(skb)->nexthdr))
			return false;
	}

	return true;
}

static void nbl_xfrm_advance_esn_state(struct xfrm_state *x)
{
	// not need to do anything
}

static bool nbl_check_ipsec_status(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;
	struct nbl_dispatch_ops *disp_ops;

	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	return disp_ops->check_ipsec_status(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
}

static void nbl_handle_dipsec_lft_event(struct nbl_service_mgt *serv_mgt)
{
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	union nbl_ipsec_lft_info lft_info = {0};
	u32 index;

	lft_info.data = disp_ops->get_dipsec_lft_info(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	index = lft_info.soft_sad_index;
	if (lft_info.soft_vld)
		disp_ops->handle_dipsec_soft_expire(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						    &index);

	index = lft_info.hard_sad_index;
	if (lft_info.hard_vld)
		disp_ops->handle_dipsec_hard_expire(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						    &index);
}

static void nbl_handle_uipsec_lft_event(struct nbl_service_mgt *serv_mgt)
{
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	union nbl_ipsec_lft_info lft_info = {0};
	u32 index;

	lft_info.data = disp_ops->get_uipsec_lft_info(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	index = lft_info.soft_sad_index;
	if (lft_info.soft_vld)
		disp_ops->handle_uipsec_soft_expire(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						    &index);

	index = lft_info.hard_sad_index;
	if (lft_info.hard_vld)
		disp_ops->handle_uipsec_hard_expire(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						    &index);
}

static void nbl_handle_ipsec_event(void *priv)
{
	struct nbl_service_mgt *serv_mgt = (struct nbl_service_mgt *)priv;

	nbl_handle_dipsec_lft_event(serv_mgt);
	nbl_handle_uipsec_lft_event(serv_mgt);
}

#define NBL_SERV_XFRM_OPS_TBL								\
do {											\
	NBL_SERV_SET_XFRM_OPS(add_xdo_dev_state, nbl_xfrm_add_state);			\
	NBL_SERV_SET_XFRM_OPS(delete_xdo_dev_state, nbl_xfrm_del_state);		\
	NBL_SERV_SET_XFRM_OPS(free_xdo_dev_state, nbl_xfrm_free_state);			\
	NBL_SERV_SET_XFRM_OPS(xdo_dev_offload_ok, nbl_offload_ok);			\
	NBL_SERV_SET_XFRM_OPS(xdo_dev_state_advance_esn, nbl_xfrm_advance_esn_state);	\
	NBL_SERV_SET_XFRM_OPS(check_ipsec_status, nbl_check_ipsec_status);		\
	NBL_SERV_SET_XFRM_OPS(handle_ipsec_event, nbl_handle_ipsec_event);		\
} while (0)

void nbl_serv_setup_xfrm_ops(struct nbl_service_ops *serv_ops)
{
#define NBL_SERV_SET_XFRM_OPS(name, func) do {serv_ops->NBL_NAME(name) = func; ; } while (0)
	NBL_SERV_XFRM_OPS_TBL;
#undef  NBL_SERV_SET_XFRM_OPS
}

#else
void nbl_serv_setup_xfrm_ops(struct nbl_service_ops *serv_ops)
{
}
#endif
