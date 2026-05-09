// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_macsec.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#include "sxe2_compat.h"
#include "sxe2.h"
#include "sxe2_netdev.h"
#include "sxe2_log.h"
#include "sxe2_macsec.h"
#include "sxe2_rx.h"
#include "sxe2_tx.h"
#include "sxe2_spec.h"

#ifdef HAVE_MACSEC_SUPPORT

static u64 swap_uint64(u64 val)
{
	val = ((val << 8) & 0xFF00FF00FF00FF00) | ((val >> 8) & 0x00FF00FF00FF00FF);
	val = ((val << 16) & 0xFFFF0000FFFF0000) | ((val >> 16) & 0x0000FFFF0000FFFF);
	return (val << 32) | (val >> 32);
}

STATIC bool sxe2_macsec_offload_en(struct net_device *netdev)
{
	return netdev->features & NETIF_F_HW_MACSEC;
}

static bool sxe2_macsec_secy_check(struct macsec_context *ctx)
{
	const struct macsec_secy *secy = ctx->secy;

	if (secy->key_len != SXE2_MACSEC_KEY_LEN) {
		LOG_ERROR("MACsec offload is supported only when key_len is %d\n",
			  SXE2_MACSEC_KEY_LEN);
		return false;
	}

	if (secy->icv_len != SXE2_MACSEC_KEY_LEN) {
		LOG_ERROR("MACsec offload is supported only when icv_len is %d\n",
			  SXE2_MACSEC_KEY_LEN);
		return false;
	}

	if (!secy->protect_frames) {
		LOG_ERROR("MACsec offload is supported only when protect_frames is set\n");
		return false;
	}

	if (secy->replay_window) {
		LOG_ERROR("MACsec offload: replay_protect isn't supported\n");
		return false;
	}

	if (secy->tx_sc.scb) {
		LOG_ERROR("MACsec offload: scb isn't supported\n");
		return false;
	}

	return true;
}

static void sxe2_macsec_txsc_clear(struct sxe2_macsec_context *macsec)
{
	struct sxe2_macsec_txsc *tx_sc = &macsec->tx_sc;

	tx_sc->active  = 0;
	tx_sc->encrypt = 0;
	tx_sc->aisci   = 0;
	tx_sc->es      = 0;
}

static void sxe2_macsec_rxsc_clear(struct sxe2_macsec_context *macsec)
{
	struct sxe2_macsec_rxsc *rx_sc = macsec->rx_sc;

	rx_sc->active  = 0;
	rx_sc->protect = 0;
	rx_sc->sci     = 0;
}

static void sxe2_macsec_rxsc_release(struct sxe2_macsec_context *macsec)
{
	struct sxe2_macsec_rxsc *rx_sc;

	rx_sc = rcu_replace_pointer(macsec->rx_sc, NULL, 1);

	synchronize_rcu();

	if (rx_sc) {
		if (rx_sc->md_dst)
			dst_release(&rx_sc->md_dst->dst);
		kfree_rcu(rx_sc, rcu);
	};
}

static void sxe2_macsec_sa_clear(struct sxe2_macsec_sa *sa)
{
	sa->added    = false;
	sa->active   = false;
	sa->an_value = 0;
	sa->ssci     = 0;
	(void)memset(sa->pn, 0, sizeof(sa->pn));
	(void)memset(sa->salt, 0, sizeof(sa->salt));
	(void)memset(sa->key, 0, sizeof(sa->key));
}

static s32 sxe2_macsec_txsc_cfg(struct sxe2_adapter *adapter)
{
	s32 ret				   = 0;
	struct sxe2_cmd_params cmd	   = {};
	struct sxe2_macsec_context *macsec = &adapter->macsec_ctxt;
	struct sxe2_macsec_txsc *tx_sc	   = &macsec->tx_sc;
	struct sxe2_fw_macsec_txsc txsc;

	txsc.active  = (u8)tx_sc->active;
	txsc.xpn     = (u8)macsec->xpn;
	txsc.aisci   = (u8)tx_sc->aisci;
	txsc.es	     = (u8)tx_sc->es;
	txsc.encrypt = (u8)tx_sc->encrypt;
	txsc.sci     = cpu_to_le64(macsec->sci);

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_MACSEC_TXSC_CFG, &txsc,
				  sizeof(struct sxe2_fw_macsec_txsc), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("macsec txsc config failed, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

static s32 sxe2_macsec_txsa_cfg(struct sxe2_adapter *adapter,
				struct sxe2_macsec_sa *tx_sa)
{
	s32 ret = 0;
	u8 i;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_fw_macsec_sa txsa;

	txsa.active   = (u8)tx_sa->active;
	txsa.an_value = tx_sa->an_value;
	txsa.ssci     = cpu_to_le32(tx_sa->ssci);
	for (i = 0; i < MACSEC_PN_LEN_MAX; i++)
		txsa.pn[i] = cpu_to_le32(tx_sa->pn[i]);

	for (i = 0; i < MACSEC_SALT_COUNT; i++)
		txsa.salt[i] = cpu_to_le32(tx_sa->salt[i]);

	for (i = 0; i < MACSEC_KEY_LEN; i++)
		txsa.key[i] = cpu_to_le32(tx_sa->key[i]);

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_MACSEC_TXSA_CFG, &txsa,
				  sizeof(struct sxe2_fw_macsec_sa), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("macsec txsa config failed, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

static s32 sxe2_macsec_rxsc_cfg(struct sxe2_adapter *adapter)
{
	s32 ret				   = 0;
	struct sxe2_cmd_params cmd	   = {};
	struct sxe2_macsec_context *macsec = &adapter->macsec_ctxt;
	struct sxe2_macsec_rxsc *rx_sc	   = macsec->rx_sc;
	struct sxe2_fw_macsec_rxsc rxsc;

	rxsc.active	   = (u8)rx_sc->active;
	rxsc.xpn	   = (u8)macsec->xpn;
	rxsc.protect	   = (u8)macsec->protect;
	rxsc.validate_mode = macsec->validate_frames;
	rxsc.sci	   = cpu_to_le64(rx_sc->sci);

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_MACSEC_RXSC_CFG, &rxsc,
				  sizeof(struct sxe2_fw_macsec_rxsc), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("macsec rxsc config failed, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

static s32 sxe2_macsec_rxsa_cfg(struct sxe2_adapter *adapter,
				struct sxe2_macsec_sa *rx_sa)
{
	s32 ret = 0;
	u8 i;
	struct sxe2_cmd_params cmd = {};
	struct sxe2_fw_macsec_sa rxsa;

	rxsa.active   = (u8)rx_sa->active;
	rxsa.an_value = rx_sa->an_value;
	rxsa.ssci     = cpu_to_le32(rx_sa->ssci);
	for (i = 0; i < MACSEC_PN_LEN_MAX; i++)
		rxsa.pn[i] = cpu_to_le32(rx_sa->pn[i]);

	for (i = 0; i < MACSEC_SALT_COUNT; i++)
		rxsa.salt[i] = cpu_to_le32(rx_sa->salt[i]);

	for (i = 0; i < MACSEC_KEY_LEN; i++)
		rxsa.key[i] = cpu_to_le32(rx_sa->key[i]);

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_MACSEC_RXSA_CFG, &rxsa,
				  sizeof(struct sxe2_fw_macsec_sa), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("macsec rxsa config failed, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

static s32 sxe2_macsec_add_secy(struct macsec_context *ctx)
{
	s32 ret				     = 0;
	struct sxe2_netdev_priv *priv	     = netdev_priv(ctx->netdev);
	struct sxe2_adapter *adapter	     = priv->vsi->adapter;
	struct sxe2_macsec_context *macsec   = &adapter->macsec_ctxt;
	struct sxe2_macsec_txsc *tx_sc	     = &macsec->tx_sc;
	const struct macsec_secy *secy	     = ctx->secy;
	const struct macsec_tx_sc *ctx_tx_sc = &secy->tx_sc;

	LOG_DEBUG_BDF("macsec add secy start...\n");

	if (!sxe2_macsec_secy_check(ctx))
		return -EINVAL;

	mutex_lock(&macsec->lock);

	if (!sxe2_macsec_offload_en(ctx->netdev)) {
		LOG_ERROR_BDF("failed to add secy, because macsec offload is disable.\n");
		ret = -EINVAL;
		goto out;
	}

	if (macsec->state != SXE2_MACSEC_STATE_READY) {
		ret = -EBUSY;
		goto out;
	}

	if (macsec->netdev) {
		LOG_ERROR_BDF("macsec secy add error, macsec net_device already exist.\n");
		ret = -EINVAL;
		goto out;
	}

	macsec->validate_frames = secy->validate_frames;
	macsec->xpn		= secy->xpn;
	macsec->sci		= swap_uint64(secy->sci);
	macsec->protect		= secy->replay_protect;

	tx_sc->active  = ctx_tx_sc->active;
	tx_sc->aisci   = ctx_tx_sc->send_sci;
	tx_sc->es      = ctx_tx_sc->end_station;
	tx_sc->encrypt = ctx_tx_sc->encrypt;

	ret = sxe2_macsec_txsc_cfg(adapter);
	if (ret) {
		LOG_ERROR_BDF("macsec update txsc, param config failed.\n");
		goto out;
	}

	macsec->netdev = secy->netdev;

out:
	mutex_unlock(&macsec->lock);

	return ret;
}

static s32 sxe2_macsec_upd_secy(struct macsec_context *ctx)
{
	s32 ret				     = 0;
	struct sxe2_netdev_priv *priv	     = netdev_priv(ctx->netdev);
	struct sxe2_adapter *adapter	     = priv->vsi->adapter;
	struct sxe2_macsec_context *macsec   = &adapter->macsec_ctxt;
	struct sxe2_macsec_txsc *tx_sc	     = &macsec->tx_sc;
	struct sxe2_macsec_rxsc *rx_sc	     = macsec->rx_sc;
	const struct macsec_secy *secy	     = ctx->secy;
	const struct macsec_tx_sc *ctx_tx_sc = &secy->tx_sc;

	LOG_DEBUG_BDF("macsec upd secy start...\n");

	if (!sxe2_macsec_secy_check(ctx))
		return -EINVAL;

	mutex_lock(&macsec->lock);

	if (!sxe2_macsec_offload_en(ctx->netdev)) {
		LOG_ERROR_BDF("failed to upd secy, because macsec offload is disable.\n");
		ret = -EINVAL;
		goto out;
	}

	if (macsec->state != SXE2_MACSEC_STATE_READY) {
		ret = -EBUSY;
		goto out;
	}

	if (macsec->xpn != secy->xpn || macsec->sci != swap_uint64(secy->sci) ||
	    tx_sc->aisci != ctx_tx_sc->send_sci ||
	    tx_sc->es != ctx_tx_sc->end_station ||
	    tx_sc->encrypt != ctx_tx_sc->encrypt) {
		macsec->xpn    = secy->xpn;
		macsec->sci    = swap_uint64(secy->sci);
		tx_sc->aisci   = ctx_tx_sc->send_sci;
		tx_sc->es      = ctx_tx_sc->end_station;
		tx_sc->encrypt = ctx_tx_sc->encrypt;

		ret = sxe2_macsec_txsc_cfg(adapter);
		if (ret) {
			LOG_ERROR_BDF("macsec txsc config failed.\n");
			goto out;
		}
	}

	if (macsec->validate_frames != secy->validate_frames ||
	    macsec->protect != secy->replay_protect ||
	    macsec->xpn != secy->xpn) {
		macsec->validate_frames = secy->validate_frames;
		macsec->protect		= secy->replay_protect;

		if (!rx_sc) {
			LOG_INFO_BDF("rxsc not add, can not update validate_frames, \t"
				     "protect or pn/xpn.\n");
			goto out;
		}

		ret = sxe2_macsec_rxsc_cfg(adapter);
		if (ret) {
			LOG_ERROR_BDF("macsec rxsc config failed.\n");
			goto out;
		}
	}

out:
	mutex_unlock(&macsec->lock);

	return 0;
}

static s32 sxe2_macsec_del_secy(struct macsec_context *ctx)
{
	s32 ret = 0;
	u8 i;
	struct sxe2_netdev_priv *priv	   = netdev_priv(ctx->netdev);
	struct sxe2_adapter *adapter	   = priv->vsi->adapter;
	struct sxe2_macsec_context *macsec = &adapter->macsec_ctxt;
	struct sxe2_macsec_sa *tx_sa;
	struct sxe2_macsec_sa *rx_sa;

	LOG_DEBUG_BDF("macsec del secy start...\n");

	mutex_lock(&macsec->lock);

	if (!sxe2_macsec_offload_en(ctx->netdev)) {
		LOG_ERROR_BDF("failed to del secy, because macsec offload is disable.\n");
		ret = -EINVAL;
		goto out;
	}

	if (macsec->state != SXE2_MACSEC_STATE_READY) {
		ret = -EBUSY;
		goto out;
	}

	macsec->xpn		= 0;
	macsec->sci		= 0;
	macsec->protect		= 0;
	macsec->validate_frames = 0;

	sxe2_macsec_txsc_clear(macsec);
	ret = sxe2_macsec_txsc_cfg(adapter);
	if (ret) {
		LOG_ERROR_BDF("macsec delete txsc, delete failed.\n");
		goto out;
	}

	for (i = 0; i < SXE2_MACSEC_MAX_SA; i++) {
		tx_sa = &macsec->tx_sc.sa[i];
		if (!tx_sa->added)
			continue;

		sxe2_macsec_sa_clear(tx_sa);
		(void)sxe2_macsec_txsa_cfg(adapter, tx_sa);
	}

	if (!macsec->rx_sc) {
		LOG_ERROR_BDF("macsec delete rxsc, rxsc is null, not need delete.\n");
		goto netdev_null;
	}

	sxe2_macsec_rxsc_clear(macsec);
	ret = sxe2_macsec_rxsc_cfg(adapter);
	if (ret) {
		LOG_ERROR_BDF("macsec delete rxsc, delete failed.\n");
		goto out;
	}

	for (i = 0; i < SXE2_MACSEC_MAX_SA; i++) {
		rx_sa = &macsec->rx_sc->sa[i];
		if (!rx_sa->added)
			continue;

		sxe2_macsec_sa_clear(rx_sa);
		(void)sxe2_macsec_rxsa_cfg(adapter, rx_sa);
	}
	sxe2_macsec_rxsc_release(macsec);

netdev_null:
	macsec->netdev = NULL;

out:
	mutex_unlock(&macsec->lock);

	return ret;
}

static s32 sxe2_macsec_add_txsa(struct macsec_context *ctx)
{
	s32 ret	 = 0;
	u8 sa_id = ctx->sa.assoc_num;
	u8 i, j, other_sa;
	u8 key[SXE2_MACSEC_KEY_LEN];
	u8 max_id			   = SXE2_MACSEC_KEY_LEN - 1;
	struct sxe2_netdev_priv *priv	   = netdev_priv(ctx->netdev);
	struct sxe2_adapter *adapter	   = priv->vsi->adapter;
	struct sxe2_macsec_context *macsec = &adapter->macsec_ctxt;
	struct sxe2_macsec_sa *tx_sa;
	const struct macsec_secy *secy	     = ctx->secy;
	const struct macsec_tx_sc *ctx_tx_sc = &secy->tx_sc;
	const struct macsec_tx_sa *ctx_tx_sa = ctx->sa.tx_sa;

	LOG_DEBUG_BDF("macsec add txsa start...\n");

	if (ctx->sa.assoc_num >= SXE2_MACSEC_MAX_SA) {
		LOG_ERROR_BDF("macsec sa max num = 2, sa_id should be 0 or 1.\n");
		ret = -EINVAL;
		goto out;
	}

	mutex_lock(&macsec->lock);

	if (!sxe2_macsec_offload_en(ctx->netdev)) {
		LOG_ERROR_BDF("failed to add txsa, because macsec offload is disable.\n");
		ret = -EINVAL;
		goto out;
	}

	if (macsec->state != SXE2_MACSEC_STATE_READY) {
		ret = -EBUSY;
		goto out;
	}

	tx_sa = &macsec->tx_sc.sa[sa_id];

	if (tx_sa->added) {
		LOG_ERROR_BDF("macsec tx sa add error, tx sa %d already exist.\n", sa_id);
		ret = -EEXIST;
		goto out;
	}

	other_sa = sa_id ? 0 : 1;
	if (macsec->tx_sc.sa[other_sa].added &&
	    macsec->tx_sc.sa[other_sa].active && ctx_tx_sa->active) {
		LOG_ERROR_BDF("macsec add txsa, only support one sa active.\n");
		ret = -EOPNOTSUPP;
		goto out;
	}

	tx_sa->active	= ctx_tx_sa->active;
	tx_sa->an_value = ctx->sa.assoc_num;
	tx_sa->pn[0]	= ctx_tx_sa->next_pn_halves.lower;
	for (i = 0; i <= max_id; i++) {
		j = (u8)(max_id - i);
		key[i] = ctx->sa.key[j];
	}
	if (macsec->xpn) {
		tx_sa->ssci  = ctx_tx_sa->ssci;
		tx_sa->pn[1] = ctx_tx_sa->next_pn_halves.upper;
		(void)memcpy(tx_sa->salt, &ctx_tx_sa->key.salt, MACSEC_SALT_LEN);
	}
	(void)memcpy(tx_sa->key, key, SXE2_MACSEC_KEY_LEN);

	if (!secy->operational || tx_sa->an_value != ctx_tx_sc->encoding_sa) {
		LOG_ERROR_BDF("macsec txsa add failed, operational[%d], \t"
			      "an_value[%d], encoding_sa[%d].\n",
			      secy->operational, tx_sa->an_value,
			      ctx_tx_sc->encoding_sa);
		goto out;
	}

	ret = sxe2_macsec_txsa_cfg(adapter, tx_sa);
	if (ret) {
		LOG_ERROR_BDF("macsec txsa config failed.\n");
		goto out;
	}

	tx_sa->added = true;

out:
	mutex_unlock(&macsec->lock);

	return ret;
}

static s32 sxe2_macsec_upd_txsa(struct macsec_context *ctx)
{
	s32 ret	 = 0;
	u8 sa_id = ctx->sa.assoc_num;
	u8 other_sa;
	struct sxe2_netdev_priv *priv	   = netdev_priv(ctx->netdev);
	struct sxe2_adapter *adapter	   = priv->vsi->adapter;
	struct sxe2_macsec_context *macsec = &adapter->macsec_ctxt;
	struct sxe2_macsec_sa *tx_sa;
	const struct macsec_tx_sa *ctx_tx_sa = ctx->sa.tx_sa;

	LOG_DEBUG_BDF("macsec upd txsa start...\n");

	if (ctx->sa.assoc_num >= SXE2_MACSEC_MAX_SA) {
		LOG_ERROR_BDF("macsec sa max num = 2, sa_id should be 0 or 1.\n");
		ret = -EINVAL;
		goto out;
	}

	mutex_lock(&macsec->lock);

	if (!sxe2_macsec_offload_en(ctx->netdev)) {
		LOG_ERROR_BDF("failed to upd txsa, because macsec offload is disable.\n");
		ret = -EINVAL;
		goto out;
	}

	if (macsec->state != SXE2_MACSEC_STATE_READY) {
		ret = -EBUSY;
		goto out;
	}

	tx_sa = &macsec->tx_sc.sa[sa_id];

	if (!tx_sa->added) {
		LOG_ERROR_BDF("macsec tx sa update error, tx sa %d doesn't exist.\n", sa_id);
		ret = -EINVAL;
		goto out;
	}

	if (tx_sa->pn[0] != ctx_tx_sa->next_pn_halves.lower) {
		LOG_INFO_BDF("MACsec offload: update TX sa %d PN isn't supported\n", sa_id);
		ret = -EINVAL;
		goto out;
	}

	if (tx_sa->active == ctx_tx_sa->active) {
		LOG_INFO_BDF("update tx sa active=%d , no change, so no config.\n",
			     ctx_tx_sa->active);
		goto out;
	}

	other_sa = sa_id ? 0 : 1;
	if (macsec->tx_sc.sa[other_sa].added &&
	    macsec->tx_sc.sa[other_sa].active && ctx_tx_sa->active) {
		LOG_ERROR_BDF("macsec upd txsa, only support one sa active.\n");
		ret = -EOPNOTSUPP;
		goto out;
	}

	tx_sa->active = ctx_tx_sa->active;

	ret = sxe2_macsec_txsa_cfg(adapter, tx_sa);
	if (ret) {
		LOG_ERROR_BDF("macsec txsa fill and cfg failed.\n");
		goto out;
	}

out:
	mutex_unlock(&macsec->lock);

	return ret;
}

static s32 sxe2_macsec_del_txsa(struct macsec_context *ctx)
{
	s32 ret				   = 0;
	u8 sa_id			   = ctx->sa.assoc_num;
	struct sxe2_netdev_priv *priv	   = netdev_priv(ctx->netdev);
	struct sxe2_adapter *adapter	   = priv->vsi->adapter;
	struct sxe2_macsec_context *macsec = &adapter->macsec_ctxt;
	struct sxe2_macsec_sa *tx_sa;

	LOG_DEBUG_BDF("macsec del txsa start...\n");

	if (ctx->sa.assoc_num >= SXE2_MACSEC_MAX_SA) {
		LOG_ERROR_BDF("macsec sa max num = 2, sa_id should be 0 or 1.\n");
		ret = -EINVAL;
		goto out;
	}

	mutex_lock(&macsec->lock);

	if (!sxe2_macsec_offload_en(ctx->netdev)) {
		LOG_ERROR_BDF("failed to del txsa, because macsec offload is disable.\n");
		ret = -EINVAL;
		goto out;
	}

	if (macsec->state != SXE2_MACSEC_STATE_READY) {
		ret = -EBUSY;
		goto out;
	}

	tx_sa = &macsec->tx_sc.sa[sa_id];

	if (!tx_sa->added) {
		LOG_ERROR_BDF("macsec tx sa delete error, tx sa %d doesn't exist.\n", sa_id);
		ret = -EEXIST;
		goto out;
	}

	sxe2_macsec_sa_clear(tx_sa);

	ret = sxe2_macsec_txsa_cfg(adapter, tx_sa);
	if (ret) {
		LOG_ERROR_BDF("macsec txsa clear and delete failed.\n");
		goto out;
	}

out:
	mutex_unlock(&macsec->lock);

	return ret;
}

static s32 sxe2_macsec_add_rxsc(struct macsec_context *ctx)
{
	s32 ret				   = 0;
	struct sxe2_netdev_priv *priv	   = netdev_priv(ctx->netdev);
	struct sxe2_adapter *adapter	   = priv->vsi->adapter;
	struct sxe2_macsec_context *macsec = &adapter->macsec_ctxt;
	struct sxe2_macsec_rxsc *rx_sc;
	const struct macsec_rx_sc *ctx_rx_sc = ctx->rx_sc;

	LOG_DEBUG_BDF("macsec add rxsc start...\n");

	mutex_lock(&macsec->lock);

	if (!sxe2_macsec_offload_en(ctx->netdev)) {
		LOG_ERROR_BDF("failed to add rxsc, because macsec offload is disable.\n");
		ret = -EINVAL;
		goto out;
	}

	if (macsec->state != SXE2_MACSEC_STATE_READY) {
		ret = -EBUSY;
		goto out;
	}

	if (macsec->rx_sc) {
		LOG_ERROR_BDF("macsec rx sc add error, rx sc already exist.\n");
		ret = -EEXIST;
		goto out;
	}

	rx_sc = kzalloc(sizeof(*rx_sc), GFP_KERNEL);
	if (!rx_sc) {
		ret = -ENOMEM;
		goto out;
	}

	rx_sc->md_dst = metadata_dst_alloc(0, METADATA_MACSEC, GFP_KERNEL);
	if (!rx_sc->md_dst) {
		ret = -ENOMEM;
		goto out;
	}

	rx_sc->active = ctx_rx_sc->active;
	rx_sc->sci    = swap_uint64(ctx_rx_sc->sci);
#ifdef SUPPORT_MACSEC_INFO_STRUCT
	rx_sc->md_dst->u.macsec_info.sci = ctx_rx_sc->sci;
#endif
	rcu_assign_pointer(macsec->rx_sc, rx_sc);

	ret = sxe2_macsec_rxsc_cfg(adapter);
	if (ret) {
		LOG_ERROR_BDF("macsec add rxsc, param fill or config failed.\n");
		goto out;
	}

out:
	mutex_unlock(&macsec->lock);

	return ret;
}

static s32 sxe2_macsec_upd_rxsc(struct macsec_context *ctx)
{
	s32 ret				     = 0;
	struct sxe2_netdev_priv *priv	     = netdev_priv(ctx->netdev);
	struct sxe2_adapter *adapter	     = priv->vsi->adapter;
	struct sxe2_macsec_context *macsec   = &adapter->macsec_ctxt;
	struct sxe2_macsec_rxsc *rx_sc	     = macsec->rx_sc;
	const struct macsec_rx_sc *ctx_rx_sc = ctx->rx_sc;

	LOG_DEBUG_BDF("macsec upd rxsc start...\n");

	mutex_lock(&macsec->lock);

	if (!sxe2_macsec_offload_en(ctx->netdev)) {
		LOG_ERROR_BDF("failed to upd rxsc, because macsec offload is disable.\n");
		ret = -EINVAL;
		goto out;
	}

	if (macsec->state != SXE2_MACSEC_STATE_READY) {
		ret = -EBUSY;
		goto out;
	}

	if (!rx_sc) {
		LOG_INFO_BDF("not create rxsc, not support update.\n");
		ret = -EINVAL;
		goto out;
	}

	if (rx_sc->active == ctx_rx_sc->active) {
		LOG_INFO_BDF("update rx sc active=%d , no change, so no config.\n",
			     ctx_rx_sc->active);
		goto out;
	}

	rx_sc->active = ctx_rx_sc->active;

	ret = sxe2_macsec_rxsc_cfg(adapter);
	if (ret) {
		LOG_ERROR_BDF("macsec add rxsc, param fill or config failed.\n");
		goto out;
	}

out:
	mutex_unlock(&macsec->lock);

	return ret;
}

static s32 sxe2_macsec_del_rxsc(struct macsec_context *ctx)
{
	s32 ret = 0;
	u8 i;
	struct sxe2_netdev_priv *priv	   = netdev_priv(ctx->netdev);
	struct sxe2_adapter *adapter	   = priv->vsi->adapter;
	struct sxe2_macsec_context *macsec = &adapter->macsec_ctxt;
	struct sxe2_macsec_sa *rx_sa;

	LOG_DEBUG_BDF("macsec del rxsc start...\n");

	mutex_lock(&macsec->lock);

	if (!sxe2_macsec_offload_en(ctx->netdev)) {
		LOG_ERROR_BDF("failed to del rxsc, because macsec offload is disable.\n");
		ret = -EINVAL;
		goto out;
	}

	if (macsec->state != SXE2_MACSEC_STATE_READY) {
		ret = -EBUSY;
		goto out;
	}

	if (!macsec->rx_sc) {
		LOG_ERROR_BDF("macsec rx sc delete error, rx sc doesn't exist.\n");
		ret = -EINVAL;
		goto out;
	}

	sxe2_macsec_rxsc_clear(macsec);
	ret = sxe2_macsec_rxsc_cfg(adapter);
	if (ret) {
		LOG_ERROR_BDF("macsec delete rxsc, delete failed.\n");
		goto out;
	}

	for (i = 0; i < SXE2_MACSEC_MAX_SA; i++) {
		rx_sa = &macsec->rx_sc->sa[i];
		if (!rx_sa->added)
			continue;

		sxe2_macsec_sa_clear(rx_sa);
		(void)sxe2_macsec_rxsa_cfg(adapter, rx_sa);
	}

	sxe2_macsec_rxsc_release(macsec);

out:
	mutex_unlock(&macsec->lock);

	return ret;
}

static s32 sxe2_macsec_add_rxsa(struct macsec_context *ctx)
{
	s32 ret = 0;
	u8 i, j, other_sa;
	u8 sa_id = ctx->sa.assoc_num;
	u8 key[SXE2_MACSEC_KEY_LEN];
	u8 max_id			   = SXE2_MACSEC_KEY_LEN - 1;
	struct sxe2_netdev_priv *priv	   = netdev_priv(ctx->netdev);
	struct sxe2_adapter *adapter	   = priv->vsi->adapter;
	struct sxe2_macsec_context *macsec = &adapter->macsec_ctxt;
	struct sxe2_macsec_sa *rx_sa;
	const struct macsec_rx_sa *ctx_rx_sa = ctx->sa.rx_sa;

	LOG_DEBUG_BDF("macsec add rxsa start...\n");

	if (ctx->sa.assoc_num >= SXE2_MACSEC_MAX_SA) {
		LOG_ERROR_BDF("macsec sa max num = 2, sa_id should be 0 or 1.\n");
		ret = -EINVAL;
		goto out;
	}

	mutex_lock(&macsec->lock);

	if (!sxe2_macsec_offload_en(ctx->netdev)) {
		LOG_ERROR_BDF("failed to add rxsa, because macsec offload is disable.\n");
		ret = -EINVAL;
		goto out;
	}

	if (macsec->state != SXE2_MACSEC_STATE_READY) {
		ret = -EBUSY;
		goto out;
	}

	if (!macsec->rx_sc) {
		LOG_INFO_BDF("not create rxsc, not support add rxsa.\n");
		ret = -EINVAL;
		goto out;
	}

	rx_sa = &macsec->rx_sc->sa[sa_id];

	if (rx_sa->added) {
		LOG_ERROR_BDF("macsec rx sa add error, rx sa %d already exist.\n", sa_id);
		ret = -EINVAL;
		goto out;
	}

	other_sa = sa_id ? 0 : 1;
	if (macsec->rx_sc->sa[other_sa].added &&
	    macsec->rx_sc->sa[other_sa].active && ctx_rx_sa->active) {
		LOG_ERROR_BDF("macsec add rxsa, only support one sa active.\n");
		ret = -EOPNOTSUPP;
		goto out;
	}

	rx_sa->active	= ctx_rx_sa->active;
	rx_sa->an_value = ctx->sa.assoc_num;
	rx_sa->pn[0]	= ctx_rx_sa->next_pn_halves.lower;
	for (i = 0; i <= max_id; i++) {
		j      = (u8)(max_id - i);
		key[i] = ctx->sa.key[j];
	}
	if (macsec->xpn) {
		rx_sa->ssci  = ctx_rx_sa->ssci;
		rx_sa->pn[1] = ctx_rx_sa->next_pn_halves.upper;
		(void)memcpy(rx_sa->salt, &ctx_rx_sa->key.salt, MACSEC_SALT_LEN);
	}
	(void)memcpy(rx_sa->key, key, SXE2_MACSEC_KEY_LEN);

	ret = sxe2_macsec_rxsa_cfg(adapter, rx_sa);
	if (ret) {
		LOG_ERROR_BDF("macsec rx sa fill and cfg error.\n");
		goto out;
	}

	rx_sa->added = true;

out:
	mutex_unlock(&macsec->lock);

	return ret;
}

static s32 sxe2_macsec_upd_rxsa(struct macsec_context *ctx)
{
	s32 ret	 = 0;
	u8 sa_id = ctx->sa.assoc_num;
	u8 other_sa;
	struct sxe2_netdev_priv *priv	   = netdev_priv(ctx->netdev);
	struct sxe2_adapter *adapter	   = priv->vsi->adapter;
	struct sxe2_macsec_context *macsec = &adapter->macsec_ctxt;
	struct sxe2_macsec_sa *rx_sa;
	const struct macsec_rx_sa *ctx_rx_sa = ctx->sa.rx_sa;

	LOG_DEBUG_BDF("macsec upd rxsa start...\n");

	if (ctx->sa.assoc_num >= SXE2_MACSEC_MAX_SA) {
		LOG_ERROR_BDF("macsec sa max num = 2, sa_id should be 0 or 1.\n");
		ret = -EINVAL;
		goto out;
	}

	mutex_lock(&macsec->lock);

	if (!sxe2_macsec_offload_en(ctx->netdev)) {
		LOG_ERROR_BDF("failed to upd rxsa, because macsec offload is disable.\n");
		ret = -EINVAL;
		goto out;
	}

	if (macsec->state != SXE2_MACSEC_STATE_READY) {
		ret = -EBUSY;
		goto out;
	}

	if (!macsec->rx_sc) {
		LOG_INFO_BDF("not create rxsc, not support update rxsa.\n");
		ret = -EINVAL;
		goto out;
	}

	rx_sa = &macsec->rx_sc->sa[sa_id];

	if (!rx_sa->added) {
		LOG_ERROR_BDF("macsec rx sa update error, rx sa %d doesn't exist.\n", sa_id);
		ret = -EINVAL;
		goto out;
	}

	if (rx_sa->pn[0] != ctx_rx_sa->next_pn_halves.lower) {
		LOG_INFO_BDF("MACsec offload: update RX sa %d PN isn't supported\n", sa_id);
		ret = -EINVAL;
		goto out;
	}

	if (rx_sa->active == ctx_rx_sa->active) {
		LOG_INFO_BDF("update tx sa active=%d , no change, so no config.\n",
			     ctx_rx_sa->active);
		goto out;
	}

	other_sa = sa_id ? 0 : 1;
	if (macsec->rx_sc->sa[other_sa].added &&
	    macsec->rx_sc->sa[other_sa].active && ctx_rx_sa->active) {
		LOG_ERROR_BDF("macsec upd rxsa, only support one sa active.\n");
		ret = -EOPNOTSUPP;
		goto out;
	}

	rx_sa->active = ctx_rx_sa->active;

	ret = sxe2_macsec_rxsa_cfg(adapter, rx_sa);
	if (ret) {
		LOG_ERROR_BDF("macsec rx sa fill and cfg error.\n");
		goto out;
	}

out:
	mutex_unlock(&macsec->lock);

	return ret;
}

static s32 sxe2_macsec_del_rxsa(struct macsec_context *ctx)
{
	s32 ret				   = 0;
	u8 sa_id			   = ctx->sa.assoc_num;
	struct sxe2_netdev_priv *priv	   = netdev_priv(ctx->netdev);
	struct sxe2_adapter *adapter	   = priv->vsi->adapter;
	struct sxe2_macsec_context *macsec = &adapter->macsec_ctxt;
	struct sxe2_macsec_sa *rx_sa;

	LOG_DEBUG_BDF("macsec del rxsa start...\n");

	if (ctx->sa.assoc_num >= SXE2_MACSEC_MAX_SA) {
		LOG_ERROR_BDF("macsec sa max num = 2, sa_id should be 0 or 1.\n");
		ret = -EINVAL;
		goto out;
	}

	mutex_lock(&macsec->lock);

	if (!sxe2_macsec_offload_en(ctx->netdev)) {
		LOG_ERROR_BDF("failed to del rxsa, because macsec offload is disable.\n");
		ret = -EINVAL;
		goto out;
	}

	if (macsec->state != SXE2_MACSEC_STATE_READY) {
		ret = -EBUSY;
		goto out;
	}

	if (!macsec->rx_sc) {
		LOG_INFO_BDF("not create rxsc, not support delete rxsa.\n");
		ret = -EINVAL;
		goto out;
	}

	rx_sa = &macsec->rx_sc->sa[sa_id];

	if (!rx_sa->added) {
		LOG_ERROR_BDF("macsec rx sa delete error, rx sa %d doesn't exist.\n", sa_id);
		ret = -EINVAL;
		goto out;
	}

	sxe2_macsec_sa_clear(rx_sa);

	ret = sxe2_macsec_rxsa_cfg(adapter, rx_sa);
	if (ret) {
		LOG_ERROR_BDF("macsec rxsa clear and delete failed.\n");
		goto out;
	}

out:
	mutex_unlock(&macsec->lock);

	return ret;
}

static const struct macsec_ops sxe2_macsec_ops = {
	.mdo_add_secy = sxe2_macsec_add_secy,
	.mdo_upd_secy = sxe2_macsec_upd_secy,
	.mdo_del_secy = sxe2_macsec_del_secy,
	.mdo_add_txsa = sxe2_macsec_add_txsa,
	.mdo_upd_txsa = sxe2_macsec_upd_txsa,
	.mdo_del_txsa = sxe2_macsec_del_txsa,
	.mdo_add_rxsc = sxe2_macsec_add_rxsc,
	.mdo_upd_rxsc = sxe2_macsec_upd_rxsc,
	.mdo_del_rxsc = sxe2_macsec_del_rxsc,
	.mdo_add_rxsa = sxe2_macsec_add_rxsa,
	.mdo_upd_rxsa = sxe2_macsec_upd_rxsa,
	.mdo_del_rxsa = sxe2_macsec_del_rxsa,
};

static s32 sxe2_macsec_fix_cfg(struct sxe2_adapter *adapter)
{
	s32 ret			   = 0;
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_MACSEC_FIX_CFG, NULL, 0, NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("macsec fix cfg failed, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

s32 sxe2_macsec_init(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	struct net_device *netdev	   = adapter->vsi_ctxt.main_vsi->netdev;
	struct sxe2_macsec_context *macsec = &adapter->macsec_ctxt;

	LOG_DEBUG_BDF("macsec init start...\n");

	mutex_init(&adapter->macsec_ctxt.lock);
	netdev->macsec_ops = &sxe2_macsec_ops;
	macsec->netdev = NULL;
	macsec->rx_sc  = NULL;

	ret = sxe2_macsec_fix_cfg(adapter);
	if (ret) {
		LOG_ERROR_BDF("macsec init failed.\n");
		goto l_err;
	}

	macsec->state  = SXE2_MACSEC_STATE_READY;

	return ret;

l_err:
	macsec->state = SXE2_MACSEC_STATE_UNINIT;
	netdev->macsec_ops = NULL;
	mutex_destroy(&adapter->macsec_ctxt.lock);
	return ret;
}

void sxe2_macsec_deinit(struct sxe2_adapter *adapter)
{
	struct sxe2_macsec_context *macsec = &adapter->macsec_ctxt;

	LOG_DEBUG_BDF("macsec deinit start...\n");

	macsec->state = SXE2_MACSEC_STATE_UNINIT;
	mutex_destroy(&macsec->lock);
}

s32 sxe2_macsec_rebuild(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	u8 sa_id;
	struct sxe2_macsec_context *macsec = &adapter->macsec_ctxt;
	struct sxe2_macsec_rxsc *rx_sc	   = macsec->rx_sc;
	struct sxe2_macsec_sa *tx_sa;
	struct sxe2_macsec_sa *rx_sa;

	mutex_lock(&macsec->lock);

	LOG_DEBUG_BDF("macsec rebuild start...\n");

	if (!macsec->netdev) {
		LOG_ERROR_BDF("macsec rebuild txsc, netdev is null, not need config.\n");
		goto out;
	}

	ret = sxe2_macsec_txsc_cfg(adapter);
	if (ret) {
		LOG_ERROR_BDF("macsec update txsc, param config failed.\n");
		goto out;
	}

	for (sa_id = 0; sa_id < SXE2_MACSEC_MAX_SA; sa_id++) {
		tx_sa = &macsec->tx_sc.sa[sa_id];
		if (!tx_sa->added)
			continue;

		ret = sxe2_macsec_txsa_cfg(adapter, tx_sa);
		if (ret) {
			LOG_ERROR_BDF("macsec txsa config failed.\n");
			goto out;
		}
	}

	if (!rx_sc) {
		LOG_ERROR_BDF("macsec rebuild rxsc, rxsc is null, not need config.\n");
		goto out;
	}

	ret = sxe2_macsec_rxsc_cfg(adapter);
	if (ret) {
		LOG_ERROR_BDF("macsec add rxsc, param fill or config failed.\n");
		goto out;
	}

	for (sa_id = 0; sa_id < SXE2_MACSEC_MAX_SA; sa_id++) {
		rx_sa = &macsec->rx_sc->sa[sa_id];
		if (!rx_sa->added)
			continue;

		ret = sxe2_macsec_rxsa_cfg(adapter, rx_sa);
		if (ret) {
			LOG_ERROR_BDF("macsec rx sa fill and cfg error.\n");
			goto out;
		}
	}

out:
	mutex_unlock(&macsec->lock);

	return ret;
}

bool sxe2_macsec_offload(struct sxe2_adapter *adapter, struct sk_buff *skb)
{
	bool ret = false;
#ifdef SXE2_UNSUPPORT
	struct metadata_dst *md_dst = skb_metadata_dst(skb);

	return md_dst && (md_dst->type == METADATA_MACSEC);
#endif

	if (adapter->vsi_ctxt.main_vsi->netdev->features & NETIF_F_HW_MACSEC)
		ret = true;
	else
		ret = false;

	return ret;
}

void sxe2_macsec_rx(struct sxe2_queue *rxq, struct sk_buff *skb)
{
	struct sxe2_adapter *adapter	   = rxq->vsi->adapter;
	struct sxe2_macsec_context *macsec = &adapter->macsec_ctxt;
	struct sxe2_macsec_rxsc *rx_sc;

	rcu_read_lock();

	rx_sc = rcu_dereference(macsec->rx_sc);
	if (rx_sc) {
		dst_hold(&rx_sc->md_dst->dst);
		skb_dst_set(skb, &rx_sc->md_dst->dst);
	}

	rcu_read_unlock();
}

void sxe2_macsec_enter_reset(struct sxe2_adapter *adapter, bool to_reset)
{
	mutex_lock(&adapter->macsec_ctxt.lock);
	if (to_reset)
		adapter->macsec_ctxt.state = SXE2_MACSEC_STATE_RESET;
	else
		adapter->macsec_ctxt.state = SXE2_MACSEC_STATE_READY;

	mutex_unlock(&adapter->macsec_ctxt.lock);
}

bool sxe2_macsec_conflict_features_check(struct net_device *netdev)
{
	netdev_features_t features = netdev->features;

	if (features & NETIF_F_HW_ESP)
		return true;

	return false;
}

bool sxe2_is_macsec_can_not_disable(struct sxe2_adapter *adapter)
{
	struct sxe2_macsec_context *macsec = &adapter->macsec_ctxt;

	return (!!macsec->netdev);
}

#endif
