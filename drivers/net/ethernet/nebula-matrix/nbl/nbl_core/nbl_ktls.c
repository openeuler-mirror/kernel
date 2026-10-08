// SPDX-License-Identifier: GPL-2.0
#include "nbl_ktls.h"
#if IS_ENABLED(CONFIG_TLS_DEVICE)
static void nbl_ktls_free_tx_index(struct net_device *netdev, u32 index)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->free_ktls_tx_index(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &index);
}

static void nbl_ktls_free_rx_index(struct net_device *netdev, u32 index)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	disp_ops->free_ktls_rx_index(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &index);
}

static int nbl_ktls_alloc_tx_index(struct net_device *netdev)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_common_info *common;
	u16 vsi;

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	vsi = NBL_COMMON_TO_VSI_ID(common);

	return disp_ops->alloc_ktls_tx_index(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &vsi);
}

static int nbl_ktls_alloc_rx_index(struct net_device *netdev)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_common_info *common;
	u16 vsi;

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	vsi = NBL_COMMON_TO_VSI_ID(common);

	return disp_ops->alloc_ktls_rx_index(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &vsi);
}

static void nbl_ktls_cfg_tx_keymat(struct net_device *netdev, u32 index,
				   struct tls_crypto_info *crypto_info,
				   struct nbl_ktls_offload_context_tx *priv_tx)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_common_info *common;
	struct nbl_dispatch_ops *disp_ops;
	struct tls12_crypto_info_aes_gcm_128 *crypto_info_aes_128;
	struct tls12_crypto_info_aes_gcm_256 *crypto_info_aes_256;
	struct nbl_ch_prm_cfg_ktls_keymat keymat = {0};
	struct tls12_crypto_info_sm4_gcm *crypto_info_sm4;

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	switch (crypto_info->cipher_type) {
	case TLS_CIPHER_AES_GCM_128:
		crypto_info_aes_128 = (struct tls12_crypto_info_aes_gcm_128 *)crypto_info;

		/* Leonis cfg key and salt through register */
		keymat.index = index;
		keymat.mode = NBL_KTLS_AES_GCM_128;
		memcpy(keymat.salt, crypto_info_aes_128->salt, sizeof(keymat.salt));
		memcpy(keymat.key, crypto_info_aes_128->key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
		keymat.key_len = TLS_CIPHER_AES_GCM_128_KEY_SIZE;
		disp_ops->cfg_ktls_tx_keymat(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &keymat);

		/* Draco cfg key and salt through pkt, so store them in ctx */
		memcpy(priv_tx->salt, crypto_info_aes_128->salt, NBL_KTLS_SALT_LEN);
		memcpy(priv_tx->key + NBL_KTLS_KEY_HALF, crypto_info_aes_128->key,
		       TLS_CIPHER_AES_GCM_128_KEY_SIZE);
		priv_tx->crypto_type = 0;

		memcpy(priv_tx->iv, crypto_info_aes_128->iv, NBL_KTLS_IV_LEN);
		memcpy(priv_tx->rec_num, crypto_info_aes_128->rec_seq, NBL_KTLS_REC_LEN);
		break;
	case TLS_CIPHER_AES_GCM_256:
		crypto_info_aes_256 = (struct tls12_crypto_info_aes_gcm_256 *)crypto_info;

		/* Leonis cfg key and salt through register */
		keymat.index = index;
		keymat.mode = NBL_KTLS_AES_GCM_256;
		memcpy(keymat.salt, crypto_info_aes_256->salt, sizeof(keymat.salt));
		memcpy(keymat.key, crypto_info_aes_256->key, TLS_CIPHER_AES_GCM_256_KEY_SIZE);
		keymat.key_len = TLS_CIPHER_AES_GCM_256_KEY_SIZE;
		disp_ops->cfg_ktls_tx_keymat(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &keymat);

		/* Draco cfg key and salt through pkt, so store them in ctx */
		memcpy(priv_tx->salt, crypto_info_aes_256->salt, NBL_KTLS_SALT_LEN);
		memcpy(priv_tx->key, crypto_info_aes_256->key, TLS_CIPHER_AES_GCM_256_KEY_SIZE);
		priv_tx->crypto_type = 1;

		memcpy(priv_tx->iv, crypto_info_aes_256->iv, NBL_KTLS_IV_LEN);
		memcpy(priv_tx->rec_num, crypto_info_aes_256->rec_seq, NBL_KTLS_REC_LEN);
		break;
	case TLS_CIPHER_SM4_GCM:
		crypto_info_sm4 = (struct tls12_crypto_info_sm4_gcm *)crypto_info;

		/* Leonis cfg key and salt through register */
		keymat.index = index;
		keymat.mode = NBL_KTLS_SM4_GCM;
		memcpy(keymat.salt, crypto_info_sm4->salt, sizeof(keymat.salt));
		memcpy(keymat.key, crypto_info_sm4->key, TLS_CIPHER_SM4_GCM_KEY_SIZE);
		keymat.key_len = TLS_CIPHER_SM4_GCM_KEY_SIZE;
		disp_ops->cfg_ktls_tx_keymat(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &keymat);

		/* Draco cfg key and salt through pkt, so store them in ctx */
		memcpy(priv_tx->salt, crypto_info_sm4->salt, NBL_KTLS_SALT_LEN);
		memcpy(priv_tx->key, crypto_info_sm4->key, TLS_CIPHER_SM4_GCM_KEY_SIZE);
		priv_tx->crypto_type = 2;

		memcpy(priv_tx->iv, crypto_info_sm4->iv, NBL_KTLS_IV_LEN);
		memcpy(priv_tx->rec_num, crypto_info_sm4->rec_seq, NBL_KTLS_REC_LEN);
		break;
	}
}

static int nbl_ktls_add_tx(struct net_device *netdev, struct sock *sk,
			   struct tls_crypto_info *crypto_info, u32 start_offload_tcp_sn)
{
	struct tls_context *tls_ctx;
	struct nbl_ktls_offload_context_tx *priv_tx;
	struct nbl_ktls_offload_context_tx **ctx;
	int index;

	priv_tx = kzalloc(sizeof(*priv_tx), GFP_KERNEL);
	if (!priv_tx)
		return -ENOMEM;

	/* get unused index */
	index = nbl_ktls_alloc_tx_index(netdev);
	if (index < 0) {
		netdev_err(netdev, "No enough tx session resources\n");
		kfree(priv_tx);
		return -ENOSPC;
	}

	netdev_info(netdev, "nbl ktls egress index %d, start seq %u\n",
		    index, start_offload_tcp_sn);
	nbl_ktls_cfg_tx_keymat(netdev, index, crypto_info, priv_tx);

	priv_tx->index = (u32)index;
	priv_tx->expected_tcp = start_offload_tcp_sn;
	tls_ctx = tls_get_ctx(sk);
	priv_tx->tx_ctx = tls_offload_ctx_tx(tls_ctx);
	priv_tx->ctx_post_pending = true;
	ctx = __tls_driver_ctx(tls_ctx, TLS_OFFLOAD_CTX_DIR_TX);
	*ctx = priv_tx;

	return 0;
}

static void nbl_ktls_cfg_rx_keymat(struct net_device *netdev, u32 index,
				   struct tls_crypto_info *crypto_info,
				   struct nbl_ktls_offload_context_rx *priv_rx)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct tls12_crypto_info_aes_gcm_128 *crypto_info_aes_128;
	struct tls12_crypto_info_aes_gcm_256 *crypto_info_aes_256;
	struct nbl_ch_prm_cfg_ktls_keymat keymat = {0};
	struct tls12_crypto_info_sm4_gcm *crypto_info_sm4;

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	switch (crypto_info->cipher_type) {
	case TLS_CIPHER_AES_GCM_128:
		crypto_info_aes_128 = (struct tls12_crypto_info_aes_gcm_128 *)crypto_info;

		keymat.index = index;
		keymat.mode = NBL_KTLS_AES_GCM_128;
		memcpy(keymat.salt, crypto_info_aes_128->salt, sizeof(keymat.salt));
		memcpy(keymat.key, crypto_info_aes_128->key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
		keymat.key_len = TLS_CIPHER_AES_GCM_128_KEY_SIZE;
		disp_ops->cfg_ktls_rx_keymat(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &keymat);
		memcpy(priv_rx->rec_num, crypto_info_aes_128->rec_seq, NBL_KTLS_REC_LEN);
		break;
	case TLS_CIPHER_AES_GCM_256:
		crypto_info_aes_256 = (struct tls12_crypto_info_aes_gcm_256 *)crypto_info;

		keymat.index = index;
		keymat.mode = NBL_KTLS_AES_GCM_256;
		memcpy(keymat.salt, crypto_info_aes_256->salt, sizeof(keymat.salt));
		memcpy(keymat.key, crypto_info_aes_256->key, TLS_CIPHER_AES_GCM_256_KEY_SIZE);
		keymat.key_len = TLS_CIPHER_AES_GCM_256_KEY_SIZE;
		disp_ops->cfg_ktls_rx_keymat(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &keymat);
		memcpy(priv_rx->rec_num, crypto_info_aes_256->rec_seq, NBL_KTLS_REC_LEN);
		break;
	case TLS_CIPHER_SM4_GCM:
		crypto_info_sm4 = (struct tls12_crypto_info_sm4_gcm *)crypto_info;

		keymat.index = index;
		keymat.mode = NBL_KTLS_SM4_GCM;
		memcpy(keymat.salt, crypto_info_sm4->salt, sizeof(keymat.salt));
		memcpy(keymat.key, crypto_info_sm4->key, TLS_CIPHER_SM4_GCM_KEY_SIZE);
		keymat.key_len = TLS_CIPHER_SM4_GCM_KEY_SIZE;
		disp_ops->cfg_ktls_rx_keymat(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &keymat);
		memcpy(priv_rx->rec_num, crypto_info_sm4->rec_seq, NBL_KTLS_REC_LEN);
		break;
	}
}

static void nbl_ktls_cfg_rx_record(struct net_device *netdev, u32 index,
				   u32 tcp_sn, u64 rec_num, bool init)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_ch_prm_cfg_ktls_record record = {0};

	if (common->product_type == NBL_LEONIS_TYPE && init)
		rec_num--;

	netdev_info(netdev, "nbl ktls cfg index %u, tcp_seq %u, rec_num %llu, init %u.\n",
		    index, tcp_sn, rec_num, init);
	record.init = init;
	record.index = index;
	record.tcp_sn = tcp_sn;
	record.rec_num = rec_num;
	disp_ops->cfg_ktls_rx_record(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &record);
}

static int nbl_ktls_add_rx_flow(struct net_device *netdev, u32 index, struct sock *sk)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_common_info *common;
	u32 data[NBL_KTLS_FLOW_TOTAL_LEN] = {0};
	u32 sip[NBL_KTLS_FLOW_IP_LEN] = {0};
	u32 dip[NBL_KTLS_FLOW_IP_LEN] = {0};
	struct nbl_ch_prm_cfg_ktls_flow prm = {0};

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	common = NBL_SERV_MGT_TO_COMMON(serv_mgt);

	switch (sk->sk_family) {
	case AF_INET:
		data[NBL_KTLS_FLOW_TYPE_OFF] = AF_INET;
		data[NBL_KTLS_FLOW_SIP_OFF] = ntohl(inet_sk(sk)->inet_daddr);
		data[NBL_KTLS_FLOW_DIP_OFF] = ntohl(inet_sk(sk)->inet_rcv_saddr);
		break;
	case AF_INET6:
		data[NBL_KTLS_FLOW_TYPE_OFF] = AF_INET6;
		be32_to_cpu_array(sip, sk->sk_v6_daddr.s6_addr32, NBL_KTLS_FLOW_IP_LEN);
		be32_to_cpu_array(dip, inet6_sk(sk)->saddr.s6_addr32, NBL_KTLS_FLOW_IP_LEN);
		memcpy(data + NBL_KTLS_FLOW_SIP_OFF, sip, sizeof(sip));
		memcpy(data + NBL_KTLS_FLOW_DIP_OFF, dip, sizeof(dip));
		break;
	default:
		return -EINVAL;
	}

	data[NBL_KTLS_FLOW_DPORT_OFF] = ntohs(inet_sk(sk)->inet_dport);
	data[NBL_KTLS_FLOW_SPORT_OFF] = ntohs(inet_sk(sk)->inet_sport);

	prm.index = index;
	prm.vsi = NBL_COMMON_TO_VSI_ID(common);
	memcpy(prm.data, data, sizeof(prm.data));
	return disp_ops->add_ktls_rx_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &prm);
}

static int nbl_ktls_add_rx(struct net_device *netdev, struct sock *sk,
			   struct tls_crypto_info *crypto_info, u32 start_offload_tcp_sn)
{
	struct nbl_ktls_offload_context_rx *priv_rx;
	struct nbl_ktls_offload_context_rx **ctx;
	struct tls_context *tls_ctx;
	int index;
	int ret = 0;

	priv_rx = kzalloc(sizeof(*priv_rx), GFP_KERNEL);
	if (!priv_rx)
		return -ENOMEM;

	/* get unused index */
	index = nbl_ktls_alloc_rx_index(netdev);
	if (index < 0) {
		netdev_err(netdev, "No enough rx session resources\n");
		kfree(priv_rx);
		return -ENOSPC;
	}

	netdev_info(netdev, "nbl ktls ingress index %d, expected seq %u\n",
		    index, start_offload_tcp_sn);
	ret = nbl_ktls_add_rx_flow(netdev, index, sk);
	if (ret) {
		netdev_err(netdev, "No enough rx flow resources for %d\n", index);
		nbl_ktls_free_rx_index(netdev, index);
		kfree(priv_rx);
		return -ENOSPC;
	}
	nbl_ktls_cfg_rx_keymat(netdev, index, crypto_info, priv_rx);
	nbl_ktls_cfg_rx_record(netdev, index, start_offload_tcp_sn,
			       be64_to_cpu(*(__be64 *)priv_rx->rec_num), true);

	priv_rx->index = (u32)index;
	tls_ctx = tls_get_ctx(sk);
	ctx = __tls_driver_ctx(tls_ctx, TLS_OFFLOAD_CTX_DIR_RX);
	*ctx = priv_rx;
	tls_offload_rx_resync_set_type(sk, TLS_OFFLOAD_SYNC_TYPE_DRIVER_REQ);
	return 0;
}

static int nbl_ktls_add(struct net_device *netdev, struct sock *sk,
			enum tls_offload_ctx_dir direction,
			struct tls_crypto_info *crypto_info,
			u32 start_offload_tcp_sn)
{
	int err = 0;

	if (crypto_info->cipher_type != TLS_CIPHER_AES_GCM_128 &&
	    crypto_info->cipher_type != TLS_CIPHER_SM4_GCM &&
	    crypto_info->cipher_type != TLS_CIPHER_AES_GCM_256) {
		netdev_info(netdev, "Unsupported cipher type %u\n", crypto_info->cipher_type);
		return -EOPNOTSUPP;
	}

	if (direction == TLS_OFFLOAD_CTX_DIR_TX)
		err = nbl_ktls_add_tx(netdev, sk, crypto_info, start_offload_tcp_sn);
	else
		err = nbl_ktls_add_rx(netdev, sk, crypto_info, start_offload_tcp_sn);

	return err;
}

static void nbl_ktls_del_tx(struct net_device *netdev, struct tls_context *tls_ctx)
{
	struct nbl_ktls_offload_context_tx **ctx =
		__tls_driver_ctx(tls_ctx, TLS_OFFLOAD_CTX_DIR_TX);
	struct nbl_ktls_offload_context_tx *priv_tx = *ctx;

	netdev_info(netdev, "nbl ktls egress free index %u\n", priv_tx->index);
	nbl_ktls_free_tx_index(netdev, priv_tx->index);
	kfree(priv_tx);
}

static void nbl_ktls_del_rx_flow(struct net_device *netdev, u32 index)
{
	struct nbl_service_mgt *serv_mgt;
	struct nbl_dispatch_ops *disp_ops;
	struct nbl_ch_prm_cfg_ktls_flow prm = {0};

	serv_mgt = NBL_NETDEV_TO_SERV_MGT(netdev);
	disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);

	prm.index = index;
	disp_ops->del_ktls_rx_flow(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), &prm);
}

static void nbl_ktls_del_rx(struct net_device *netdev, struct tls_context *tls_ctx)
{
	struct nbl_ktls_offload_context_rx **ctx =
		__tls_driver_ctx(tls_ctx, TLS_OFFLOAD_CTX_DIR_RX);
	struct nbl_ktls_offload_context_rx *priv_rx = *ctx;

	netdev_info(netdev, "nbl ktls ingress free index %u\n", priv_rx->index);
	nbl_ktls_free_rx_index(netdev, priv_rx->index);
	nbl_ktls_del_rx_flow(netdev, priv_rx->index);
	kfree(priv_rx);
}

static void nbl_ktls_del(struct net_device *netdev, struct tls_context *tls_ctx,
			 enum tls_offload_ctx_dir direction)
{
	if (direction == TLS_OFFLOAD_CTX_DIR_TX)
		nbl_ktls_del_tx(netdev, tls_ctx);
	else
		nbl_ktls_del_rx(netdev, tls_ctx);
}

static void nbl_ktls_rx_resync(struct net_device *netdev, struct sock *sk,
			       u32 tcp_seq, u8 *rec_num)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct nbl_ktls_offload_context_rx **ctx =
		__tls_driver_ctx(tls_ctx, TLS_OFFLOAD_CTX_DIR_RX);
	struct nbl_ktls_offload_context_rx *priv = *ctx;

	nbl_ktls_cfg_rx_record(netdev, priv->index, priv->tcp_seq,
			       be64_to_cpu(*(__be64 *)rec_num), false);
}

static int nbl_ktls_resync(struct net_device *netdev, struct sock *sk,
			   u32 tcp_seq, u8 *rec_num,
			   enum tls_offload_ctx_dir direction)
{
	if (direction != TLS_OFFLOAD_CTX_DIR_RX)
		return -1;

	nbl_ktls_rx_resync(netdev, sk, tcp_seq, rec_num);
	return 0;
}

#define NBL_SERV_KTLS_OPS_TBL								\
do {											\
	NBL_SERV_SET_KTLS_OPS(add_tls_dev, nbl_ktls_add);				\
	NBL_SERV_SET_KTLS_OPS(del_tls_dev, nbl_ktls_del);				\
	NBL_SERV_SET_KTLS_OPS(resync_tls_dev, nbl_ktls_resync);				\
} while (0)

void nbl_serv_setup_ktls_ops(struct nbl_service_ops *serv_ops)
{
#define NBL_SERV_SET_KTLS_OPS(name, func) do {serv_ops->NBL_NAME(name) = func; ; } while (0)
	NBL_SERV_KTLS_OPS_TBL;
#undef  NBL_SERV_SET_KTLS_OPS
}

#else

void nbl_serv_setup_ktls_ops(struct nbl_service_ops *serv_ops) {}

#endif /* end ifdef CONFIG_TLS_DEVICE*/
