/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_macsec_protocol.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : Adapt to Linux standard kernel macsec
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [MACsec]" fmt

#include <linux/netdevice.h>
#include "ossl_knl.h"

#include "hinic5_srv_nic.h"
#include "hinic5_nic_dev.h"

#include "hinic5_macsec_common.h"
#include "hinic5_macsec_dfx.h"
#include "hinic5_macsec_dev.h"

#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)) && \
	IS_ENABLED(CONFIG_MACSEC) && \
	defined(HAVE_NETDEVICE_MACSEC_OPS))

#include <net/macsec.h>

#define htonll(x)	(htonl(1) == 1 ? (x) : \
	((((uint64_t)htonl((x) & 0xFFFFFFFF)) << 32) | \
	 htonl((x) >> 32)))
#define ntohll(x)	(ntohl(1) == 1 ? (x) : \
	((((uint64_t)ntohl((x) & 0xFFFFFFFF)) << 32) | \
	 ntohl((x) >> 32)))
#define VALIDATE_RET_OK 0x5a5aa5a5
#define HIMACSEC_DEV_LINK_KIND "macsec"

struct hinic5_nic_dev *macsec_get_nic_dev_by_netdev(struct net_device *netdev)
{
	struct hinic5_nic_dev *nic_dev = NULL;

	if (!netdev) {
		pr_err("Get nic dev fail, netdev is NULL");
		return NULL;
	}

	nic_dev = netdev_priv(netdev);
	if (!nic_dev) {
		pr_err("Get nic dev fail, nic_dev is NULL");
		return NULL;
	}
	return nic_dev;
}

int macsec_base_validate(struct hinic5_nic_dev *nic_dev, struct macsec_context *ctx)
{
	if (!nic_dev || !nic_dev->macsec_res) {
		pr_err("NIC device is NULL");
		return -ENODEV;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	if (ctx->prepare != 0)
		return 0;
#endif
	return VALIDATE_RET_OK;
}

int macsec_sa_update_validate(struct hinic5_nic_dev *nic_dev, struct macsec_context *ctx,
			      struct himacsec_sa **priv_sa, crypt_direction_e direct, u64 sci)
{
	int ret = macsec_base_validate(nic_dev, ctx);
	u8 assoc_num = ctx->sa.assoc_num;

	if (ret != VALIDATE_RET_OK)
		return ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 8)
	if (ctx->sa.update_pn) {
		macsec_err(nic_dev->lld_dev->dev, "Update sa failed, not support pn update");
		return -EINVAL;
	}
#endif

	*priv_sa = himacsec_get_valid_dev_sa(nic_dev, sci, assoc_num, direct);
	if (!*priv_sa) {
		macsec_err(nic_dev->lld_dev->dev, "Update sa failed, sa does not exist, sci=%llx, an=0x%x",
			   sci, assoc_num);
		return -EINVAL;
	}

	return VALIDATE_RET_OK;
}

int himacsec_sa_active_update(struct hinic5_nic_dev *nic_dev,
			      struct himacsec_sa *macsec_sa, u8 active)
{
	int ret;
	u8 temp_active_status;

	// 1. If sa active is the same before and after command, no processing
	if (macsec_sa->info.enable_receive == active)
		return 0;

	// 2. Changed sa enable config
	temp_active_status = macsec_sa->info.enable_receive;
	macsec_sa->info.enable_receive = active;
	ret = himacsec_cmd_exec_sa_op(nic_dev->lld_dev, &macsec_sa->info, MACSEC_CMD_DEC_SA_UPDATE);
	if (ret != 0) {
		macsec_sa->info.enable_receive = temp_active_status;
		macsec_err(nic_dev->lld_dev->dev, "Update sa failed, ret=%d", ret);
	}

	return ret;
}

void reverse_u8_array(u8 *array, u32 size)
{
	u32 left = 0;
	u32 right = size - 1;

	while (left < right) {
		u8 temp = array[left];

		array[left] = array[right];
		array[right] = temp;
		left++;
		right--;
	}
}

int macsec_secy_features_validate(struct macsec_context *ctx)
{
	const struct net_device *netdev = ctx->netdev;
	const struct macsec_secy *secy = ctx->secy;

	if (secy->icv_len != HIMACSEC_ICV_LEN) {
		pr_err("%s: MACsec offload is supported only when icv_len is %d",
		       netdev->name, HIMACSEC_ICV_LEN);
		return -EINVAL;
	}

	if (secy->key_len != HIMACSEC_KEY_LENGTH_128 &&
	    secy->key_len != HIMACSEC_KEY_LENGTH_256) {
		pr_err("%s: MACsec offload is supported only when key_len is 128bit or 256bit",
		       netdev->name);
		return -EINVAL;
	}

	if (secy->validate_frames >= __MACSEC_VALIDATE_END) {
		pr_err("%s: MACsec offload is supported only when validate value was legal",
		       netdev->name);
		return -EINVAL;
	}

	return 0;
}

/* direct:true macsec_key_length convert to reg_key_length;
 * false reg_key_length convert to macsec_key_length
 */
void macsec_adapt_convert_key_length(u8 *reg_key_length, u16 *macsec_key_length, bool direct)
{
	if (direct) {
		// macsec_key_length convert to reg_key_length
		if (*macsec_key_length == HIMACSEC_KEY_LENGTH_128) {
			*reg_key_length = HIMACSEC_REG_KEY_LENGTH_128;
		} else if (*macsec_key_length == HIMACSEC_KEY_LENGTH_256) {
			*reg_key_length = HIMACSEC_REG_KEY_LENGTH_256;
		} else {
			// macsec_secy_features_validate has checked, macsec_key_length=128 or 256
			pr_err("Parse sa key length failed, macsec key length=%d", *reg_key_length);
		}
	} else {
		// reg_key_length convert to macsec_key_length
		if (*reg_key_length == HIMACSEC_REG_KEY_LENGTH_128) {
			*macsec_key_length = HIMACSEC_KEY_LENGTH_128;
		} else if (*reg_key_length == HIMACSEC_REG_KEY_LENGTH_256) {
			*macsec_key_length = HIMACSEC_KEY_LENGTH_256;
		} else {
			// Read the exception value from the register,
			// request does not return failure, fill in the exception value
			*macsec_key_length = 0;
			pr_err("Parse sa key length failed, reg key length=%d", *reg_key_length);
		}
	}
}

void macsec_adapt_convert_validate_type(u8 *reg_validate_val,
					enum macsec_validation_type *macsec_validation_val,
					bool direct)
{
	if (direct) {
		// macsec val to reg val
		if (*macsec_validation_val < __MACSEC_VALIDATE_END) {
			*reg_validate_val = (u8)(*macsec_validation_val) + 1;
			return;
		}
		pr_err("Parse validate type failed, macsec validate=%d", *macsec_validation_val);
	} else {
		// reg val to macsec val
		if (*reg_validate_val < (u8)VALIDATE_MODE_MAX) {
			*macsec_validation_val = *reg_validate_val - 1;
			return;
		}
		pr_err("Parse validate type failed, reg validate=%d", *reg_validate_val);
	}
}

void macsec_adapt_key_handle(struct macsec_context *ctx, struct himacsec_sa *sa, u32 key_len)
{
	memcpy(sa->info.sak, ctx->sa.key, HIMACSEC_MAX_SAK_KEY_LEN);
	memset(ctx->sa.key, 0, HIMACSEC_MAX_SAK_KEY_LEN);
	reverse_u8_array((u8 *)sa->info.sak, ctx->secy->key_len);

	// set 128bit key in high 128bit
	if (key_len == HIMACSEC_KEY_LENGTH_128) {
		memcpy(((u8 *)sa->info.sak + HIMACSEC_KEY_LENGTH_128),
		       sa->info.sak, HIMACSEC_KEY_LENGTH_128);
		memset(sa->info.sak, 0, HIMACSEC_KEY_LENGTH_128);
	}
}

/* Algorithm only has AES, length/xpn enable is in secy */
int macsec_adapt_add_tx_sa(struct macsec_context *ctx)
{
	struct net_device *netdev = ctx->netdev;
	struct himacsec_sa enc_sa = {0};
	struct hinic5_nic_dev *nic_dev = macsec_get_nic_dev_by_netdev(netdev);
	int ret;

	if (macsec_secy_features_validate(ctx) != 0)
		return -EINVAL;

	// Adapt kernel 2 stage commit offload
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	if (ctx->prepare != 0)
		return 0;
#endif

	if (!nic_dev) {
		pr_err("Add protocol encryption sa failed, nic device is NULL");
		return -ENODEV;
	}

	// Sak param set
	macsec_adapt_key_handle(ctx, &enc_sa, ctx->secy->key_len);

	// Key length set
	macsec_adapt_convert_key_length(&enc_sa.info.current_key_length, &ctx->secy->key_len, true);

	enc_sa.info.sci = ntohll(ctx->secy->sci);
	enc_sa.info.an = ctx->sa.assoc_num;
	enc_sa.info.enable_transmit = ctx->sa.tx_sa->active;
	enc_sa.info.pn_th = HIMACSEC_DEFAULT_PN_THRESHOLD;
	enc_sa.info.next_pn = ctx->sa.tx_sa->next_pn;

	// The algorithm only has AES
	enc_sa.info.current_crypto_algo = HIMACSEC_CRYPTO_ALGO_AES;
	enc_sa.info.extended_pn_enable = (u8)ctx->secy->xpn;

	enc_sa.info.ssci = ntohl(ctx->sa.tx_sa->ssci);

	// Salt value parameter processing
	memcpy(enc_sa.info.salt, ctx->sa.tx_sa->key.salt.bytes, MACSEC_SALT_LEN);
	reverse_u8_array((u8 *)enc_sa.info.salt, MACSEC_SALT_LEN);

	ret = himacsec_create_sa(nic_dev, &enc_sa.info, MACSEC_OUTBOUND);
	if (ret != 0)
		macsec_err(nic_dev->lld_dev->dev, "%s: Add protocol encryption sa failed, ret=%d",
			   netdev->name, ret);
	return ret;
}

int macsec_adapt_del_tx_sa(struct macsec_context *ctx)
{
	struct net_device *netdev = ctx->netdev;
	u64 sci = 0;
	u8 assoc_num = 0;
	int ret;
	struct hinic5_nic_dev *nic_dev = macsec_get_nic_dev_by_netdev(netdev);

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	if (ctx->prepare != 0)
		return 0;
#endif

	if (!nic_dev) {
		pr_err("Del protocol encryption sa failed, nic device is NULL");
		return -ENODEV;
	}

	sci = ntohll(ctx->secy->sci);
	assoc_num = ctx->sa.assoc_num;
	ret = himacsec_destroy_sa(nic_dev, sci, assoc_num, MACSEC_OUTBOUND);
	if (ret != 0)
		macsec_err(nic_dev->lld_dev->dev, "%s: Delete protocol encryption sa failed, ret=%d",
			   netdev->name, ret);
	return ret;
}

int macsec_adapt_add_rx_sa(struct macsec_context *ctx)
{
	struct net_device *netdev = ctx->netdev;
	struct himacsec_sa dec_sa = {0};
	struct hinic5_nic_dev *nic_dev = macsec_get_nic_dev_by_netdev(netdev);
	int ret;

	if (macsec_secy_features_validate(ctx) != 0)
		return -EINVAL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	if (ctx->prepare != 0)
		return 0;
#endif

	if (!nic_dev) {
		pr_err("Add protocol decryption sa failed, macsec device is NULL");
		return -ENODEV;
	}

	// Sak param set
	macsec_adapt_key_handle(ctx, &dec_sa, ctx->secy->key_len);

	// Set key length
	macsec_adapt_convert_key_length(&dec_sa.info.current_key_length, &ctx->secy->key_len, true);

	dec_sa.info.sci = ntohll(ctx->sa.rx_sa->sc->sci);
	dec_sa.info.an = ctx->sa.assoc_num;
	dec_sa.info.next_pn = ctx->sa.rx_sa->next_pn;
	dec_sa.info.replay_protect = ctx->secy->replay_protect;
	dec_sa.info.replay_window = ctx->secy->replay_window;
	dec_sa.info.enable_receive = ctx->sa.rx_sa->active;

	// Only support AES
	dec_sa.info.current_crypto_algo = HIMACSEC_CRYPTO_ALGO_AES;
	dec_sa.info.extended_pn_enable = (u8)ctx->secy->xpn;

	// Salt value parameter processing
	dec_sa.info.ssci = ntohl(ctx->sa.rx_sa->ssci);
	memcpy(dec_sa.info.salt, ctx->sa.rx_sa->key.salt.bytes, MACSEC_SALT_LEN);
	reverse_u8_array((u8 *)dec_sa.info.salt, MACSEC_SALT_LEN);

	/* TODO set lowest_pn */

	ret = himacsec_create_sa(nic_dev, &dec_sa.info, MACSEC_INBOUND);
	if (ret != 0)
		macsec_err(nic_dev->lld_dev->dev, "%s: Add protocol decryption sa failed, ret=%d",
			   netdev->name, ret);
	return ret;
}

int macsec_adapt_del_rx_sa(struct macsec_context *ctx)
{
	struct net_device *netdev = ctx->netdev;
	struct hinic5_nic_dev *nic_dev = macsec_get_nic_dev_by_netdev(netdev);
	u64 sci;
	int ret;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	if (ctx->prepare != 0)
		return 0;
#endif

	if (!nic_dev) {
		pr_err("Del protocol decryption sa failed, nic device is NULL");
		return -ENODEV;
	}

	sci = ntohll(ctx->sa.rx_sa->sc->sci);
	ret = himacsec_destroy_sa(nic_dev, sci, ctx->sa.assoc_num, MACSEC_INBOUND);
	if (ret != 0)
		macsec_err(nic_dev->lld_dev->dev, "%s Delete protocol decryption sa failed, ret=%d",
			   netdev->name, ret);
	return ret;
}

int macsec_adapt_add_rx_sc(struct macsec_context *ctx)
{
	struct net_device *netdev = ctx->netdev;
	struct himacsec_sc dec_sc = {0};
	struct hinic5_nic_dev *nic_dev = macsec_get_nic_dev_by_netdev(netdev);
	int ret;

	if (macsec_secy_features_validate(ctx) != 0)
		return -EINVAL;

	// adapt kernel 2 stage commit offload
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	if (ctx->prepare != 0)
		return 0;
#endif

	if (!nic_dev) {
		pr_err("Add protocol decryption sc failed, nic device is NULL");
		return -ENODEV;
	}

	dec_sc.info.sci = ntohll(ctx->rx_sc->sci);
	macsec_adapt_convert_validate_type(&dec_sc.info.validate_frames,
					   &ctx->secy->validate_frames, true);

	ret = himacsec_create_sc(nic_dev, &dec_sc.info, MACSEC_INBOUND);
	if (ret != 0)
		macsec_err(nic_dev->lld_dev->dev, "%s: Add protocol decryption sc failed, ret=%d",
			   netdev->name, ret);
	return ret;
}

static int macsec_update_rxsa_by_rxsc(const struct macsec_rx_sc *ctx_rx_sc,
				      struct hinic5_nic_dev *nic_dev, u64 sci)
{
	const struct macsec_rx_sa *rx_sa = NULL;
	struct himacsec_sa *dec_sa = NULL;
	int ret, i;

	for (i = 0; i < MACSEC_NUM_AN; i++) {
		rx_sa = ctx_rx_sc->sa[i];
		if (!rx_sa)
			continue;

		dec_sa = himacsec_get_valid_dev_sa(nic_dev, sci, i, MACSEC_INBOUND);
		if (!dec_sa) {
			macsec_err(nic_dev->lld_dev->dev, "Update decryption sc failed, an=%d", i);
			return -EINVAL;
		}

		if (ctx_rx_sc->active) {
			/* rx_sc active, the state of SA is determined
			 * by the SA state in the standard kernel
			 */
			ret = himacsec_sa_active_update(nic_dev, dec_sa, rx_sa->active);
		} else {
			/* rx_sc not active, all SA off */
			ret = himacsec_sa_active_update(nic_dev, dec_sa, (u8)ctx_rx_sc->active);
		}

		if (ret != 0)
			return ret;
	}
	return 0;
}

int macsec_adapt_update_rx_sc(struct macsec_context *ctx)
{
	const struct macsec_rx_sc *ctx_rx_sc = ctx->rx_sc;
	struct net_device *netdev = ctx->netdev;
	struct hinic5_nic_dev *nic_dev = macsec_get_nic_dev_by_netdev(netdev);
	struct himacsec_sc *dec_sc = NULL;
	u64 sci;
	int ret;

	if (!ctx_rx_sc) {
		pr_info("%s, nothing changed", __func__);
		return 0;
	}

	ret = macsec_base_validate(nic_dev, ctx);
	if (ret != VALIDATE_RET_OK) {
		pr_err("%s, macsec_base_validate fail", __func__);
		return ret;
	}

	sci = ntohll(ctx->rx_sc->sci);
	dec_sc = himacsec_get_valid_dev_sc(nic_dev, sci, MACSEC_INBOUND);
	if (!dec_sc) {
		macsec_err(nic_dev->lld_dev->dev, "Update decryption sc failed, not found sc, sci=%llx",
			   sci);
		return -EINVAL;
	}

	ret = macsec_update_rxsa_by_rxsc(ctx_rx_sc, nic_dev, sci);
	if (ret != 0) {
		macsec_err(nic_dev->lld_dev->dev, "Update decryption sc failed, ret=%d", ret);
		return ret;
	}
	return 0;
}

int macsec_adapt_del_rx_sc(struct macsec_context *ctx)
{
	struct net_device *netdev = ctx->netdev;
	struct hinic5_nic_dev *nic_dev = macsec_get_nic_dev_by_netdev(netdev);
	u64 sci = 0;
	int ret;

	// adapt kernel 2 stage commit offload
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	if (ctx->prepare != 0)
		return 0;
#endif

	if (!nic_dev) {
		pr_err("Del protocol decryption sc failed, nic device is NULL");
		return -ENODEV;
	}

	sci = ntohll(ctx->rx_sc->sci);
	ret = himacsec_destroy_sc(nic_dev, sci, MACSEC_INBOUND);
	if (ret != 0)
		macsec_err(nic_dev->lld_dev->dev, "%s: Delete protocol decryption sc failed, ret=%d",
			   netdev->name, ret);
	return ret;
}

int macsec_adapt_add_secy(struct macsec_context *ctx)
{
	struct net_device *netdev = ctx->netdev;
	struct himacsec_sc tx_sc = {0};
	struct hinic5_nic_dev *nic_dev = macsec_get_nic_dev_by_netdev(netdev);
	struct macsec_resource *macsec_res = NULL;
	int ret;

	if (macsec_secy_features_validate(ctx) != 0)
		return -EINVAL;

	// adapt kernel 2 stage commit offload
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	if (ctx->prepare != 0)
		return 0;
#endif

	if (!nic_dev) {
		pr_err("Add protocol secy failed, nic device is NULL");
		return -ENODEV;
	}

	macsec_res = nic_dev->macsec_res;
	if (!macsec_res) {
		macsec_err(nic_dev->lld_dev->dev, "Add protocol secy failed, macsec resource is NULL");
		return -ENODEV;
	}
	// Save the offloaded vf index
	if (ctx->secy->netdev)
		macsec_res->offload_child_dev_idx[macsec_res->offload_dev_num++] =
									ctx->secy->netdev->ifindex;

	tx_sc.info.sci = ntohll(ctx->secy->sci);
	tx_sc.info.use_es_enable = ctx->secy->tx_sc.end_station;
	tx_sc.info.use_scb_enable = ctx->secy->tx_sc.scb;
	tx_sc.info.include_sci_enable = ctx->secy->tx_sc.send_sci;
	tx_sc.info.protect_frames = ctx->secy->protect_frames; // Indicates whether to protect
							       // (verification is also protection)
	/* 0: integrity only
	 * 1:confidentiality, cannot configure offset protection
	 */
	tx_sc.info.protection_mode = ctx->secy->tx_sc.encrypt;

	/* Call service layer */
	ret = himacsec_create_sc(nic_dev, &tx_sc.info, MACSEC_OUTBOUND);
	if (ret != 0)
		macsec_err(nic_dev->lld_dev->dev, "%s: Add protocol encryption sc failed, ret=%d",
			   netdev->name, ret);
	return ret;
}

int macsec_adapt_clean_up_rx_sc(struct net_device *netdev, struct hinic5_nic_dev *nic_dev,
				struct macsec_context *ctx)
{
	struct macsec_rx_sc *rx_sc = NULL;
	u64 rx_sci;
	int ret = 0;

	if (!ctx->secy || !ctx->secy->rx_sc) {
		pr_info("%s: Delete protocol decryption sc skip, decryption sc not exist",
			netdev->name);
		return 0;
	}

	rx_sc = ctx->secy->rx_sc;
	while (rx_sc) {
		rx_sci = ntohll(ctx->secy->rx_sc->sci);
		ret |= himacsec_destroy_sc(nic_dev, rx_sci, MACSEC_INBOUND);
		if (ret != 0) {
			macsec_err(nic_dev->lld_dev->dev, "%s: Delete decryption sc failed, sci=%llx, ret=%d",
				   netdev->name, rx_sci, ret);
		}
		rx_sc = rx_sc->next;
	}
	return ret;
}

int macsec_adapt_del_secy(struct macsec_context *ctx)
{
	struct net_device *netdev = ctx->netdev;
	struct hinic5_nic_dev *nic_dev = macsec_get_nic_dev_by_netdev(netdev);
	u64 tx_sci = ntohll(ctx->secy->sci);
	int ret;

	// adapt kernel 2 stage commit offload
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	if (ctx->prepare != 0)
		return 0;
#endif

	if (!nic_dev) {
		pr_err("Delete protocol secy failed, macsec device is NULL");
		return -ENODEV;
	}

	// delete macsec tx config
	ret = himacsec_destroy_sc(nic_dev, tx_sci, MACSEC_OUTBOUND);
	if (ret != 0) {
		macsec_err(nic_dev->lld_dev->dev, "%s: Delete protocol encryption sc failed, sci=%llx, ret=%d",
			   netdev->name, tx_sci, ret);
		return ret;
	}

	// delete macsec rx config
	ret = macsec_adapt_clean_up_rx_sc(netdev, nic_dev, ctx);
	if (ret != 0)
		macsec_err(nic_dev->lld_dev->dev, "%s: Delete protocol decryption sc failed, ret=%d",
			   netdev->name, ret);

	return ret;
}

int macsec_adapt_update_tx_sa(struct macsec_context *ctx)
{
	const struct macsec_tx_sa *ctx_tx_sa = ctx->sa.tx_sa;
	struct net_device *netdev = ctx->netdev;
	struct hinic5_nic_dev *nic_dev = macsec_get_nic_dev_by_netdev(netdev);
	struct himacsec_sa *macsec_sa = NULL;
	u64 tx_sci = ntohll(ctx->secy->sci);
	int ret;
	u8 active;

	if (!nic_dev) {
		pr_err("Update encryption sa failed, nic device is NULL");
		return -ENODEV;
	}

	ret = macsec_sa_update_validate(nic_dev, ctx, &macsec_sa, MACSEC_OUTBOUND, tx_sci);
	if (ret != VALIDATE_RET_OK)
		return ret;

	// 1. If sa active is the same before and after command, no processing
	if (macsec_sa->info.enable_transmit == (u8)ctx_tx_sa->active)
		return 0;

	// 2. Changed sa enable config
	active = macsec_sa->info.enable_transmit;
	macsec_sa->info.enable_transmit = (u8)ctx_tx_sa->active;
	ret = himacsec_cmd_exec_sa_op(nic_dev->lld_dev, &macsec_sa->info, MACSEC_CMD_ENC_SA_UPDATE);
	if (ret != 0) {
		macsec_sa->info.enable_transmit = active;
		macsec_err(nic_dev->lld_dev->dev, "Update encryption sa failed, ret=%d", ret);
	}

	return ret;
}

int macsec_adapt_update_rx_sa(struct macsec_context *ctx)
{
	const struct macsec_rx_sa *ctx_rx_sa = ctx->sa.rx_sa;
	struct net_device *netdev = ctx->netdev;
	struct hinic5_nic_dev *nic_dev = macsec_get_nic_dev_by_netdev(netdev);
	struct himacsec_sa *macsec_sa = NULL;
	u64 rx_sci = ntohll(ctx_rx_sa->sc->sci);
	int ret;

	ret = macsec_sa_update_validate(nic_dev, ctx, &macsec_sa, MACSEC_INBOUND, rx_sci);
	if (ret != VALIDATE_RET_OK)
		return ret;

	return himacsec_sa_active_update(nic_dev, macsec_sa, (u8)ctx_rx_sa->active);
}

static int macsec_update_txsa_by_txsc(const struct macsec_tx_sc *ctx_tx_sc,
				      struct hinic5_nic_dev *nic_dev, u64 sci)
{
	struct macsec_tx_sa *tx_sa = NULL;
	struct himacsec_sa *enc_sa = NULL;
	int ret, i;

	// Traverse and update ctx_tx_sa
	for (i = 0; i < MACSEC_NUM_AN; i++) {
		tx_sa = ctx_tx_sc->sa[i];
		if (!tx_sa)
			continue;

		enc_sa = himacsec_get_valid_dev_sa(nic_dev, sci, i, MACSEC_OUTBOUND);
		if (!enc_sa) {
			macsec_err(nic_dev->lld_dev->dev, "%s, get sa failed, an= %d", __func__, i);
			return -EINVAL;
		}

		if (ctx_tx_sc->active)
			ret = himacsec_sa_active_update(nic_dev, enc_sa, tx_sa->active);
		else
			ret = himacsec_sa_active_update(nic_dev, enc_sa, (u8)ctx_tx_sc->active);
		if (ret != 0)
			return ret;
	}
	return 0;
}

static int macsec_adapt_update_tx_sc(struct macsec_context *ctx)
{
	const struct macsec_tx_sc *ctx_tx_sc = &ctx->secy->tx_sc;
	struct net_device *netdev = ctx->netdev;
	struct hinic5_nic_dev *nic_dev = macsec_get_nic_dev_by_netdev(netdev);
	struct himacsec_sc *enc_sc = NULL;
	int ret;
	u64 sci;

	if (!ctx_tx_sc) {
		pr_info("%s, nothing changed", __func__);
		return 0;
	}

	ret = macsec_base_validate(nic_dev, ctx);
	if (ret != VALIDATE_RET_OK) {
		pr_err("%s, macsec_base_validate fail, ret:%d", __func__, ret);
		return ret;
	}

	sci = ntohll(ctx->secy->sci);
	enc_sc = himacsec_get_valid_dev_sc(nic_dev, sci, MACSEC_OUTBOUND);
	if (!enc_sc) {
		macsec_err(nic_dev->lld_dev->dev, "%s, update encryption sc failed, sc not found, sci=0x%llx",
			   __func__, sci);
		return -EINVAL;
	}

	if (ctx_tx_sc->encrypt) {
		macsec_info(nic_dev->lld_dev->dev, "%s, encrypt is true, set protection_mode CONFIDENTIALITY",
			    __func__);
		enc_sc->info.protection_mode = PROTECTION_MODE_CONFIDENTIALITY;
	}

	// Update encoding_sa
	if (enc_sc->info.encoding_sa != ctx_tx_sc->encoding_sa) {
		enc_sc->info.encoding_sa = ctx_tx_sc->encoding_sa;
		ret = himacsec_set_sc(nic_dev, &enc_sc->info, MACSEC_OUTBOUND);
		if (ret != 0) {
			macsec_err(nic_dev->lld_dev->dev, "%s, himacsec_set_sc(sci=0x%llx) failed, ret: %d",
				   __func__, sci, ret);
			return ret;
		}
	}

	ret = macsec_update_txsa_by_txsc(ctx_tx_sc, nic_dev, sci);
	if (ret != 0) {
		macsec_err(nic_dev->lld_dev->dev, "%s, update encryption sc failed, ret= %d",
			   __func__, ret);
		return ret;
	}

	return 0;
}

int macsec_adapt_update_secy(struct macsec_context *ctx)
{
	/* Secy involves all sc and sa config, complex flow, not allowed to modify temporarily */
	int ret;

	if (!macsec_secy_features_validate(ctx))
		return -EINVAL;

	ret = macsec_adapt_update_tx_sc(ctx);
	if (ret != 0) {
		pr_err("%s update tx_sc failed, ret=%d", __func__, ret);
		return ret;
	}

	ret = macsec_adapt_update_rx_sc(ctx);
	if (ret != 0) {
		pr_err("%s update rx_sc failed, ret=%d", __func__, ret);
		return ret;
	}

	return 0;
}

static const struct macsec_ops macsec_offload_ops = {
	/* Secy */
	.mdo_add_secy = macsec_adapt_add_secy,
	.mdo_upd_secy = macsec_adapt_update_secy,
	.mdo_del_secy = macsec_adapt_del_secy,

	/* Security channels */
	.mdo_add_rxsc = macsec_adapt_add_rx_sc,
	.mdo_upd_rxsc = macsec_adapt_update_rx_sc,
	.mdo_del_rxsc = macsec_adapt_del_rx_sc,

	/* Security associations */
	.mdo_add_rxsa = macsec_adapt_add_rx_sa,
	.mdo_upd_rxsa = macsec_adapt_update_rx_sa,
	.mdo_del_rxsa = macsec_adapt_del_rx_sa,
	.mdo_add_txsa = macsec_adapt_add_tx_sa,
	.mdo_upd_txsa = macsec_adapt_update_tx_sa,
	.mdo_del_txsa = macsec_adapt_del_tx_sa,
};

void himacsec_offload_init(struct hinic5_nic_dev *nic_dev)
{
	struct net_device *netdev = nic_dev->netdev;
	struct macsec_resource *macsec_res = nic_dev->macsec_res;

	if (macsec_res->spec.max_sa == 2) { /* 2 SA mode */
		macsec_info(nic_dev->lld_dev->dev, "%s: Sc mode is 0, do not support offload protocol macsec",
			    netdev->name);
		return;
	}

	netdev->macsec_ops = &macsec_offload_ops;
	netdev->features |= NETIF_F_HW_MACSEC;
}

bool himacsec_check_offload(u32 ifindex, u32 *offload)
{
	u32 i;

	for (i = 0; i < MACSEC_SC_NUM; i++)
		if (offload[i] == ifindex)
			return true;
	return false;
}

int himacsec_get_offload_idx(u32 ifindex, u32 *offload, u32 *index)
{
	u32 i;

	for (i = 0; i < MACSEC_SC_NUM; i++) {
		if (offload[i] == ifindex) {
			*index = i;
			return 0;
		}
	}
	return -1;
}

/* Because vf ifindex is saved as array in himacsec_dev,
 * need to move forward from the currently deleted vf index when deleting
 */
int himacsec_dev_del_offload(u32 ifindex, struct macsec_resource *macsec_res)
{
	u32 index = 0;
	int ret = 0;

	if (macsec_res->offload_dev_num == 0)
		return 0;

	ret = himacsec_get_offload_idx(ifindex, macsec_res->offload_child_dev_idx, &index);
	if (ret < 0)
		return ret;

	for (; index < macsec_res->offload_dev_num - 1; index++)
		macsec_res->offload_child_dev_idx[index] =
						macsec_res->offload_child_dev_idx[index + 1];
	// offload vf count minus 1
	macsec_res->offload_dev_num--;
	return ret;
}

void himacsec_remove_macsec_offload(struct net_device *dev, struct macsec_resource *macsec_res,
				    struct hinic5_lld_dev *lld_dev)
{
	int ret = 0;

	struct net_device *lower_dev;
	struct list_head *iter;
	// Traverse all lower devices
	rcu_read_lock();
	netdev_for_each_upper_dev_rcu(dev, lower_dev, iter) {
		// Check if it is a macsec device
		if (lower_dev->rtnl_link_ops &&
		    lower_dev->rtnl_link_ops->kind &&
		    strcmp(lower_dev->rtnl_link_ops->kind, HIMACSEC_DEV_LINK_KIND) == 0) {
			macsec_info(lld_dev->dev, "Unregistering macsec offload for dev: %s, lower_dev %s, pf_ifindex: %d, vf_ifindex: %d ",
				    dev->name, lower_dev->name, dev->ifindex, lower_dev->ifindex);

			// Unregister link, delete vf device
			if (himacsec_check_offload((u32)lower_dev->ifindex,
						   macsec_res->offload_child_dev_idx)) {
				macsec_info(lld_dev->dev, "dev %s is offload , delete link",
					    lower_dev->name);
				rtnl_lock();
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)) /* LINUX_VERSION_CODE < 6.6.0 */
				rtnl_delete_link(lower_dev);
#else /* LINUX_VERSION_CODE >= 6.6.0 */
				rtnl_delete_link(lower_dev, 0, NULL);
#endif
				rtnl_unlock();
				// Delete vf_ifindex recorded in offload_child_dev_idx
				ret = himacsec_dev_del_offload(lower_dev->ifindex, macsec_res);
				if (ret < 0) {
					macsec_err(lld_dev->dev, "delete child dev index fail: if_index is not in offload list, if_index: %d",
						   lower_dev->ifindex);
					break;
				}
			} else {
				// Not unregistering link, return directly
				// (vf link created by stack, no need to delete)
				macsec_info(lld_dev->dev, "dev %s is not offload , skip delete link",
					    lower_dev->name);
			}
		} else {
			macsec_info(lld_dev->dev, "%s is not a macsec device\n", lower_dev->name);
		}
	}

	rcu_read_unlock();
}

void himacsec_offload_deinit(struct hinic5_nic_dev *nic_dev)
{
	struct net_device *netdev = nic_dev->netdev;
	struct macsec_resource *macsec_res = nic_dev->macsec_res;

	if (!netdev->macsec_ops)
		return;

	netdev->macsec_ops = NULL;
	netdev->features &= ~NETIF_F_HW_MACSEC;

	himacsec_remove_macsec_offload(netdev, macsec_res, nic_dev->lld_dev);
}

#else

void himacsec_offload_init(struct hinic5_nic_dev *nic_dev)
{
}

void himacsec_offload_deinit(struct hinic5_nic_dev *nic_dev)
{
}

#endif
