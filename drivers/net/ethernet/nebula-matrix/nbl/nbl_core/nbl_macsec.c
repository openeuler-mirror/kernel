// SPDX-License-Identifier: GPL-2.0

#include "nbl_macsec.h"
#if IS_ENABLED(CONFIG_MACSEC)
#include <linux/xarray.h>
#include <net/dst_metadata.h>

static struct nbl_macsec_dev *
nbl_macsec_get_macsec_dev(struct nbl_macsec_info *macsec, const struct net_device *netdev)
{
	struct nbl_macsec_dev *macsec_dev;
	const struct list_head *list;

	list = &macsec->macsec_dev_list;
	list_for_each_entry_rcu(macsec_dev, list, macsec_dev_node) {
		if (macsec_dev->netdev == netdev)
			return macsec_dev;
	}

	return NULL;
}

static struct nbl_macsec_rx_sc *
nbl_macsec_get_macsec_rxsc(const struct list_head *list, u64 sci)
{
	struct nbl_macsec_rx_sc *rx_sc;
	u32 sci_l, sci_m, sci_h;

	sci_l = sci & 0xfff;
	sci_m = sci >> 12;
	sci_h = sci >> 44;
	list_for_each_entry_rcu(rx_sc, list, rx_sc_node) {
		if (rx_sc->sci_l == sci_l && rx_sc->sci_m == sci_m &&
		    rx_sc->sci_h == sci_h)
			return rx_sc;
	}

	return NULL;
}

static int nbl_macsec_add_txsa(struct macsec_context *ctx)
{
	const struct macsec_tx_sc *tx_sc = &ctx->secy->tx_sc;
	const struct macsec_tx_sa *ctx_tx_sa = ctx->sa.tx_sa;
	const struct macsec_secy *secy = ctx->secy;
	const struct net_device *netdev = ctx->secy->netdev;
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(ctx->netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_macsec_info *macsec = serv_mgt->macsec;
	struct nbl_macsec_dev *macsec_dev;
	struct nbl_macsec_sa *tx_sa;
	u8 assoc_num = ctx->sa.assoc_num;
	int index, i;
	int err = 0;

	mutex_lock(&macsec->lock);
	netdev_info(ctx->netdev, "MACsec offload: add tx sa\n");
	macsec_dev = nbl_macsec_get_macsec_dev(macsec, netdev);
	if (!macsec_dev) {
		netdev_err(ctx->netdev, "MACsec offload: Failed to find device\n");
		err = -EINVAL;
		goto out;
	}

	if (macsec_dev->tx_sc.tx_sa[assoc_num]) {
		netdev_err(ctx->netdev, "MACsec offload: TX sa: %d already exist\n", assoc_num);
		err = -EEXIST;
		goto out;
	}

	tx_sa = kzalloc(sizeof(*tx_sa), GFP_KERNEL);
	if (!tx_sa) {
		err = -ENOMEM;
		goto out;
	}

	tx_sa->active = ctx_tx_sa->active;
	tx_sa->sa_pn.pn = ctx_tx_sa->next_pn_halves.lower;
	if (secy->xpn) {
		tx_sa->ssci = ctx_tx_sa->ssci;
		memcpy(tx_sa->salt, &ctx_tx_sa->key.salt, NBL_MACSEC_SALT_LEN);
		tx_sa->sa_pn.epn = ctx_tx_sa->next_pn_halves.upper;
	}

	for (i = 0; i < secy->key_len; i++)
		tx_sa->sec_key[i] = ctx->sa.key[secy->key_len - i - 1];

	macsec_dev->tx_sc.tx_sa[assoc_num] = tx_sa;
	if (!secy->operational || assoc_num != tx_sc->encoding_sa || !tx_sa->active)
		goto out;
	index = macsec_dev->tx_sc.index * MACSEC_NUM_AN + assoc_num;
	disp_ops->cfg_macsec_sa(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), index, tx_sa, true);
	netdev_info(ctx->netdev, "MACsec offload: end add tx sa %u\n", index);

out:
	mutex_unlock(&macsec->lock);
	return err;
}

static int nbl_macsec_upd_txsa(struct macsec_context *ctx)
{
	const struct macsec_tx_sa *ctx_tx_sa = ctx->sa.tx_sa;
	const struct net_device *netdev = ctx->secy->netdev;
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(ctx->netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_macsec_info *macsec = serv_mgt->macsec;
	struct nbl_macsec_dev *macsec_dev;
	struct nbl_macsec_sa *tx_sa;
	u8 assoc_num = ctx->sa.assoc_num;
	int index;
	int err = 0;

	mutex_lock(&macsec->lock);
	macsec_dev = nbl_macsec_get_macsec_dev(macsec, netdev);
	if (!macsec_dev) {
		netdev_err(ctx->netdev, "MACsec offload: Failed to find device\n");
		err = -EINVAL;
		goto out;
	}

	tx_sa = macsec_dev->tx_sc.tx_sa[assoc_num];
	if (!tx_sa) {
		netdev_err(ctx->netdev, "MACsec offload: TX sa: %d doesn't exist\n", assoc_num);
		err = -ENOENT;
		goto out;
	}

	tx_sa->active = ctx_tx_sa->active;
	tx_sa->sa_pn.pn = ctx_tx_sa->next_pn_halves.lower;
	if (ctx->secy->xpn) {
		tx_sa->ssci = ctx_tx_sa->ssci;
		memcpy(tx_sa->salt, &ctx_tx_sa->key.salt, NBL_MACSEC_SALT_LEN);
		tx_sa->sa_pn.epn = ctx_tx_sa->next_pn_halves.upper;
	}

	index = macsec_dev->tx_sc.index * MACSEC_NUM_AN + assoc_num;
	disp_ops->cfg_macsec_sa(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), index, tx_sa, true);

	netdev_info(ctx->netdev, "MACsec offload: end upd txsa\n");

out:
	mutex_unlock(&macsec->lock);
	return err;
}

static int nbl_macsec_del_txsa(struct macsec_context *ctx)
{
	const struct net_device *netdev = ctx->secy->netdev;
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(ctx->netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_macsec_info *macsec = serv_mgt->macsec;
	struct nbl_macsec_dev *macsec_dev;
	struct nbl_macsec_sa *tx_sa;
	u8 assoc_num = ctx->sa.assoc_num;
	int index;
	int err = 0;

	mutex_lock(&macsec->lock);
	macsec_dev = nbl_macsec_get_macsec_dev(macsec, netdev);
	if (!macsec_dev) {
		netdev_err(ctx->netdev, "MACsec offload: Failed to find device\n");
		err = -EINVAL;
		goto out;
	}

	tx_sa = macsec_dev->tx_sc.tx_sa[assoc_num];
	if (!tx_sa) {
		netdev_err(ctx->netdev, "MACsec offload: TX sa: %d doesn't exist\n", assoc_num);
		err = -EEXIST;
		goto out;
	}

	tx_sa->active = 0;
	index = macsec_dev->tx_sc.index * MACSEC_NUM_AN + assoc_num;
	disp_ops->cfg_macsec_sa(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), index, tx_sa, true);
	kfree(tx_sa);
	macsec_dev->tx_sc.tx_sa[assoc_num] = NULL;

out:
	mutex_unlock(&macsec->lock);
	return err;
}

static int nbl_macsec_add_rxsc(struct macsec_context *ctx)
{
	const struct net_device *netdev = ctx->secy->netdev;
	const struct macsec_rx_sc *ctx_rx_sc = ctx->rx_sc;
	const struct macsec_secy *secy = ctx->secy;
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(ctx->netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_macsec_info *macsec = serv_mgt->macsec;
	struct nbl_macsec_dev *macsec_dev;
	struct nbl_macsec_rx_sc *rx_sc;
	struct list_head *rx_sc_list;
	u64 sci;
	int index;
	int err = 0;

	mutex_lock(&macsec->lock);
	netdev_info(ctx->netdev, "MACsec offload: add rx sc\n");
	macsec_dev = nbl_macsec_get_macsec_dev(macsec, netdev);
	if (!macsec_dev) {
		netdev_err(ctx->netdev, "MACsec offload: Failed to find device\n");
		err = -EINVAL;
		goto out;
	}

	sci = be64_to_cpu(*(__be64 *)&ctx_rx_sc->sci);
	rx_sc_list = &macsec_dev->macsec_rx_sc_list;
	rx_sc = nbl_macsec_get_macsec_rxsc(rx_sc_list, sci);
	if (rx_sc) {
		netdev_err(ctx->netdev,
			   "MACsec offload: RX sc: (sci 0x%llx) already exists\n", sci);
		err = -EEXIST;
		goto out;
	}

	rx_sc = kzalloc(sizeof(*rx_sc), GFP_KERNEL);
	if (!rx_sc) {
		err = -ENOMEM;
		goto out;
	}

	rx_sc->md_dst = metadata_dst_alloc(0, METADATA_MACSEC, GFP_KERNEL);
	if (!rx_sc->md_dst) {
		err = -ENOMEM;
		kfree(rx_sc);
		goto out;
	}

	index = disp_ops->alloc_macsec_rxsc_index(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	if (index < 0) {
		netdev_err(ctx->netdev, "No enough macsec secy resources\n");
		err = -ENOSPC;
		metadata_dst_free(rx_sc->md_dst);
		kfree(rx_sc);
		goto out;
	}

	netdev_info(ctx->netdev, "MACsec offload: add rx sc: (sci 0x%llx) add\n", sci);
	rx_sc->active = ctx_rx_sc->active;
	rx_sc->win_size = ilog2(secy->replay_window / 32);
	rx_sc->offset = 0;
	rx_sc->icv_len = secy->icv_len;
	rx_sc->validate_frame = secy->validate_frames;
	rx_sc->key_type = 0;    // 0:aes 1:sm4
	rx_sc->key_len = (secy->key_len == NBL_MACSEC_KEY_LEN ? 1 : 0);
	rx_sc->xpn = secy->xpn;
	rx_sc->replay = secy->replay_protect;
	rx_sc->sci_l = sci;
	rx_sc->sci_m = sci >> 12;
	rx_sc->sci_h = sci >> 44;
	rx_sc->sport_id = NBL_COMMON_TO_ETH_ID(common);
	rx_sc->index = (u32)index;
	disp_ops->cfg_macsec_rxsc(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), (u32)index, rx_sc);
	list_add_rcu(&rx_sc->rx_sc_node, rx_sc_list);
	rx_sc->md_dst->u.macsec_info.sci = ctx_rx_sc->sci;
	netdev_info(ctx->netdev, "MACsec offload: end add rx sc\n");

out:
	mutex_unlock(&macsec->lock);
	return err;
}

static int nbl_macsec_upd_rxsc(struct macsec_context *ctx)
{
	const struct net_device *netdev = ctx->secy->netdev;
	const struct macsec_rx_sc *ctx_rx_sc = ctx->rx_sc;
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(ctx->netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_macsec_info *macsec = serv_mgt->macsec;
	struct nbl_macsec_dev *macsec_dev;
	struct nbl_macsec_rx_sc *rx_sc;
	struct list_head *rx_sc_list;
	u64 sci;
	int err = 0;

	mutex_lock(&macsec->lock);
	macsec_dev = nbl_macsec_get_macsec_dev(macsec, netdev);
	if (!macsec_dev) {
		netdev_err(ctx->netdev, "MACsec offload: Failed to find device\n");
		err = -EINVAL;
		goto out;
	}

	sci = be64_to_cpu(*(__be64 *)&ctx_rx_sc->sci);
	rx_sc_list = &macsec_dev->macsec_rx_sc_list;
	rx_sc = nbl_macsec_get_macsec_rxsc(rx_sc_list, sci);
	if (!rx_sc) {
		err = -EINVAL;
		goto out;
	}

	if (rx_sc->active == ctx_rx_sc->active)
		goto out;

	rx_sc->active = ctx_rx_sc->active;
	disp_ops->cfg_macsec_rxsc(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), rx_sc->index, rx_sc);

out:
	mutex_unlock(&macsec->lock);
	return err;
}

static int nbl_macsec_del_rxsc(struct macsec_context *ctx)
{
	const struct net_device *netdev = ctx->secy->netdev;
	const struct macsec_rx_sc *ctx_rx_sc = ctx->rx_sc;
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(ctx->netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_macsec_info *macsec = serv_mgt->macsec;
	struct nbl_macsec_dev *macsec_dev;
	struct nbl_macsec_rx_sc *rx_sc;
	struct nbl_macsec_sa *rx_sa;
	struct list_head *rx_sc_list;
	u64 sci;
	int i, index;
	int err = 0;

	mutex_lock(&macsec->lock);
	macsec_dev = nbl_macsec_get_macsec_dev(macsec, netdev);
	if (!macsec_dev) {
		netdev_err(ctx->netdev, "MACsec offload: Failed to find device\n");
		err = -EINVAL;
		goto out;
	}

	sci = be64_to_cpu(*(__be64 *)&ctx_rx_sc->sci);
	rx_sc_list = &macsec_dev->macsec_rx_sc_list;
	rx_sc = nbl_macsec_get_macsec_rxsc(rx_sc_list, sci);
	if (!rx_sc) {
		err = -EINVAL;
		goto out;
	}

	netdev_info(ctx->netdev, "MACsec offload: del rxsc index %u\n", rx_sc->index);

	for (i = 0; i < MACSEC_NUM_AN; i++) {
		rx_sa = rx_sc->rx_sa[i];
		if (!rx_sa)
			continue;
		rx_sa->active = 0;
		index = rx_sc->index * MACSEC_NUM_AN + i;
		disp_ops->cfg_macsec_sa(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), index, rx_sa, false);
		kfree(rx_sa);
		rx_sc->rx_sa[i] = NULL;
	}

	netdev_info(ctx->netdev, "MACsec offload: begin del rxsc\n");
	rx_sc->active = 0;
	disp_ops->cfg_macsec_rxsc(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), rx_sc->index, rx_sc);
	disp_ops->free_macsec_rxsc_index(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), rx_sc->index);
	list_del_rcu(&rx_sc->rx_sc_node);
	netdev_info(ctx->netdev, "MACsec offload: end del rxsc\n");
	metadata_dst_free(rx_sc->md_dst);
	kfree(rx_sc);

out:
	mutex_unlock(&macsec->lock);
	return err;
}

static int nbl_macsec_add_rxsa(struct macsec_context *ctx)
{
	const struct net_device *netdev = ctx->secy->netdev;
	const struct macsec_rx_sa *ctx_rx_sa = ctx->sa.rx_sa;
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(ctx->netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_macsec_info *macsec = serv_mgt->macsec;
	struct nbl_macsec_dev *macsec_dev;
	struct nbl_macsec_rx_sc *rx_sc;
	struct nbl_macsec_sa *rx_sa;
	struct list_head *rx_sc_list;
	u8 assoc_num = ctx->sa.assoc_num;
	u64 sci;
	int index, i;
	int err = 0;

	mutex_lock(&macsec->lock);
	netdev_info(ctx->netdev, "MACsec offload: add rx sa\n");
	macsec_dev = nbl_macsec_get_macsec_dev(macsec, netdev);
	if (!macsec_dev) {
		netdev_err(ctx->netdev, "MACsec offload: Failed to find device\n");
		err = -EINVAL;
		goto out;
	}

	sci = be64_to_cpu(*(__be64 *)&ctx_rx_sa->sc->sci);
	rx_sc_list = &macsec_dev->macsec_rx_sc_list;
	rx_sc = nbl_macsec_get_macsec_rxsc(rx_sc_list, sci);
	if (!rx_sc) {
		netdev_err(ctx->netdev,
			   "MACsec offload: RX sc: (sci 0x%llx) doesn't exists\n", sci);
		err = -EINVAL;
		goto out;
	}

	if (rx_sc->rx_sa[assoc_num]) {
		netdev_err(ctx->netdev, "MACsec offload: RX sc: (sci 0x%llx) rx sa %d already exists\n",
			   sci, assoc_num);
		err = -EEXIST;
		goto out;
	}

	rx_sa = kzalloc(sizeof(*rx_sa), GFP_KERNEL);
	if (!rx_sa) {
		err = -ENOMEM;
		goto out;
	}

	rx_sa->active = ctx_rx_sa->active;
	if (ctx->secy->xpn) {
		rx_sa->ssci = ctx_rx_sa->ssci;
		memcpy(rx_sa->salt, &ctx_rx_sa->key.salt, NBL_MACSEC_SALT_LEN);
		rx_sa->sa_pn.epn = ctx_rx_sa->next_pn_halves.upper;
	}

	for (i = 0; i < ctx->secy->key_len; i++)
		rx_sa->sec_key[i] = ctx->sa.key[ctx->secy->key_len - i - 1];

	rx_sa->sa_pn.pn = ctx_rx_sa->next_pn_halves.lower;
	rx_sc->rx_sa[assoc_num] = rx_sa;
	index = rx_sc->index * MACSEC_NUM_AN + assoc_num;
	disp_ops->cfg_macsec_sa(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), index, rx_sa, false);
	netdev_info(ctx->netdev, "MACsec offload: end add rx sa %u\n", index);

out:
	mutex_unlock(&macsec->lock);
	return err;
}

static int nbl_macsec_upd_rxsa(struct macsec_context *ctx)
{
	const struct net_device *netdev = ctx->secy->netdev;
	const struct macsec_rx_sa *ctx_rx_sa = ctx->sa.rx_sa;
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(ctx->netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_macsec_info *macsec = serv_mgt->macsec;
	struct nbl_macsec_dev *macsec_dev;
	struct nbl_macsec_rx_sc *rx_sc;
	struct nbl_macsec_sa *rx_sa;
	struct list_head *rx_sc_list;
	u8 assoc_num = ctx->sa.assoc_num;
	u64 sci;
	int index;
	int err = 0;

	mutex_lock(&macsec->lock);
	macsec_dev = nbl_macsec_get_macsec_dev(macsec, netdev);
	if (!macsec_dev) {
		netdev_err(ctx->netdev, "MACsec offload: Failed to find device\n");
		err = -EINVAL;
		goto out;
	}

	sci = be64_to_cpu(*(__be64 *)&ctx_rx_sa->sc->sci);
	rx_sc_list = &macsec_dev->macsec_rx_sc_list;
	rx_sc = nbl_macsec_get_macsec_rxsc(rx_sc_list, sci);
	if (!rx_sc) {
		netdev_err(ctx->netdev,
			   "MACsec offload: RX sc: (sci 0x%llx) doesn't exists\n", sci);
		err = -EINVAL;
		goto out;
	}

	rx_sa = rx_sc->rx_sa[assoc_num];
	if (!rx_sa) {
		netdev_err(ctx->netdev, "MACsec offload: RX sc: (sci 0x%llx) rx sa %d doesn't exists\n",
			   sci, assoc_num);
		err = -ENOENT;
		goto out;
	}

	rx_sa->active = ctx_rx_sa->active;
	if (ctx->secy->xpn) {
		rx_sa->ssci = ctx_rx_sa->ssci;
		memcpy(rx_sa->salt, &ctx_rx_sa->key.salt, NBL_MACSEC_SALT_LEN);
		rx_sa->sa_pn.epn = ctx_rx_sa->next_pn_halves.upper;
	}

	rx_sa->sa_pn.pn = ctx_rx_sa->next_pn_halves.lower;
	index = rx_sc->index * MACSEC_NUM_AN + assoc_num;
	disp_ops->cfg_macsec_sa(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), index, rx_sa, false);

	netdev_info(ctx->netdev, "MACsec offload: end upd rxsa\n");

out:
	mutex_unlock(&macsec->lock);
	return err;
}

static int nbl_macsec_del_rxsa(struct macsec_context *ctx)
{
	const struct net_device *netdev = ctx->secy->netdev;
	const struct macsec_rx_sa *ctx_rx_sa = ctx->sa.rx_sa;
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(ctx->netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_macsec_info *macsec = serv_mgt->macsec;
	struct nbl_macsec_dev *macsec_dev;
	struct nbl_macsec_rx_sc *rx_sc;
	struct nbl_macsec_sa *rx_sa;
	struct list_head *rx_sc_list;
	u8 assoc_num = ctx->sa.assoc_num;
	u64 sci;
	int index;
	int err = 0;

	mutex_lock(&macsec->lock);
	macsec_dev = nbl_macsec_get_macsec_dev(macsec, netdev);
	if (!macsec_dev) {
		netdev_err(ctx->netdev, "MACsec offload: Failed to find device\n");
		err = -EINVAL;
		goto out;
	}

	sci = be64_to_cpu(*(__be64 *)&ctx_rx_sa->sc->sci);
	rx_sc_list = &macsec_dev->macsec_rx_sc_list;
	rx_sc = nbl_macsec_get_macsec_rxsc(rx_sc_list, sci);
	if (!rx_sc) {
		netdev_err(ctx->netdev,
			   "MACsec offload: RX sc: (sci 0x%llx) doesn't exists\n", sci);
		err = -EINVAL;
		goto out;
	}

	rx_sa = rx_sc->rx_sa[assoc_num];
	if (!rx_sa) {
		netdev_err(ctx->netdev, "MACsec offload: RX sc: (sci 0x%llx) rx sa %d doesn't exists\n",
			   sci, assoc_num);
		err = -EEXIST;
		goto out;
	}

	index = rx_sc->index * MACSEC_NUM_AN + assoc_num;
	disp_ops->cfg_macsec_sa(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), index, rx_sa, false);
	kfree(rx_sa);
	rx_sc->rx_sa[assoc_num] = NULL;

out:
	mutex_unlock(&macsec->lock);
	return err;
}

static int nbl_macsec_add_secy(struct macsec_context *ctx)
{
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(ctx->netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_macsec_info *macsec = serv_mgt->macsec;
	const struct net_device *netdev = ctx->secy->netdev;
	struct nbl_macsec_dev *macsec_dev;
	u64 sci;
	int index, i;
	int err = 0;

	mutex_lock(&macsec->lock);
	if (nbl_macsec_get_macsec_dev(macsec, netdev)) {
		netdev_err(ctx->netdev, "MACsec offload: macsec device already exist\n");
		goto out;
	}

	netdev_info(ctx->netdev, "MACsec offload: req tx sc index\n");
	index = disp_ops->alloc_macsec_txsc_index(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt));
	if (index < 0) {
		netdev_err(ctx->netdev, "No enough macsec secy resources\n");
		err = -ENOSPC;
		goto out;
	}

	sci = be64_to_cpu(*(__be64 *)&ctx->secy->sci);
	netdev_info(ctx->netdev,
		    "MACsec offload: add sec secy, index %d, sci 0x%llx\n", index, sci);
	macsec_dev = kzalloc(sizeof(*macsec_dev), GFP_KERNEL);
	if (!macsec_dev) {
		err = -ENOMEM;
		goto out;
	}

	macsec_dev->netdev = netdev;
	macsec_dev->macsec_fs.mask = 0xd;
	macsec_dev->macsec_fs.sci = sci;
	macsec_dev->macsec_fs.port_id = NBL_COMMON_TO_ETH_ID(common);
	macsec_dev->macsec_fs.vld = 1;
	for (i = 0; i < 6; i++)
		macsec_dev->macsec_fs.smac[i] = netdev->dev_addr[5 - i];
	disp_ops->cfg_macsec_fs(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				(u32)index, &macsec_dev->macsec_fs);

	macsec_dev->tx_sc.index = (u32)index;
	macsec_dev->tx_sc.offset = 0;
	macsec_dev->tx_sc.icv_len = ctx->secy->icv_len;
	macsec_dev->tx_sc.an = ctx->secy->tx_sc.encoding_sa;
	macsec_dev->tx_sc.svlan_clear = 0;
	macsec_dev->tx_sc.cvlan_clear = 0;
	macsec_dev->tx_sc.key_type = 0;    // 0:aes 1:sm4
	macsec_dev->tx_sc.key_len = (ctx->secy->key_len == NBL_MACSEC_KEY_LEN ? 1 : 0);
	macsec_dev->tx_sc.xpn = ctx->secy->xpn;
	macsec_dev->tx_sc.scb = ctx->secy->tx_sc.scb;
	macsec_dev->tx_sc.end_station = ctx->secy->tx_sc.end_station;
	macsec_dev->tx_sc.send_sci = ctx->secy->tx_sc.send_sci;
	macsec_dev->tx_sc.encrypt = ctx->secy->tx_sc.encrypt;
	macsec_dev->tx_sc.protect = ctx->secy->protect_frames;
	macsec_dev->tx_sc.active = ctx->secy->tx_sc.active;
	disp_ops->cfg_macsec_txsc(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				  (u32)index, &macsec_dev->tx_sc);

	INIT_LIST_HEAD_RCU(&macsec_dev->macsec_rx_sc_list);
	list_add_rcu(&macsec_dev->macsec_dev_node, &macsec->macsec_dev_list);
	macsec->dev_num++;
	netdev_info(ctx->netdev, "MACsec offload: end add secy\n");

out:
	mutex_unlock(&macsec->lock);
	return err;
}

static int nbl_macsec_upd_secy(struct macsec_context *ctx)
{
	const struct net_device *netdev = ctx->secy->netdev;
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(ctx->netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_common_info *common = NBL_SERV_MGT_TO_COMMON(serv_mgt);
	struct nbl_macsec_info *macsec = serv_mgt->macsec;
	struct nbl_macsec_dev *macsec_dev;
	u64 sci;
	int index, i;
	int err = 0;

	mutex_lock(&macsec->lock);
	macsec_dev = nbl_macsec_get_macsec_dev(macsec, netdev);
	if (!macsec_dev) {
		netdev_err(ctx->netdev, "MACsec offload: Failed to find device\n");
		err = -EINVAL;
		goto out;
	}

	index = macsec_dev->tx_sc.index;
	sci = be64_to_cpu(*(__be64 *)&ctx->secy->sci);
	netdev_info(ctx->netdev,
		    "MACsec offload: upd sec secy, index %d, sci 0x%llx\n", index, sci);

	macsec_dev->macsec_fs.mask = 0x1d;
	macsec_dev->macsec_fs.sci = sci;
	macsec_dev->macsec_fs.port_id = NBL_COMMON_TO_ETH_ID(common);
	macsec_dev->macsec_fs.vld = 1;
	for (i = 0; i < 6; i++)
		macsec_dev->macsec_fs.smac[i] = netdev->dev_addr[5 - i];
	disp_ops->cfg_macsec_fs(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				(u32)index, &macsec_dev->macsec_fs);

	netdev_info(ctx->netdev, "MACsec offload: end upd sec secy\n");

out:
	mutex_unlock(&macsec->lock);
	return err;
}

static int nbl_macsec_del_secy(struct macsec_context *ctx)
{
	const struct net_device *netdev = ctx->secy->netdev;
	struct nbl_service_mgt *serv_mgt = NBL_NETDEV_TO_SERV_MGT(ctx->netdev);
	struct nbl_dispatch_ops *disp_ops = NBL_SERV_MGT_TO_DISP_OPS(serv_mgt);
	struct nbl_macsec_info *macsec = serv_mgt->macsec;
	struct nbl_macsec_dev *macsec_dev;
	struct nbl_macsec_rx_sc *rx_sc;
	struct nbl_macsec_sa *tx_sa;
	struct nbl_macsec_sa *rx_sa;
	struct list_head *rx_sc_list;
	int index, i;
	int err = 0;

	mutex_lock(&macsec->lock);
	netdev_info(ctx->netdev, "MACsec offload: del sec secy\n");
	macsec_dev = nbl_macsec_get_macsec_dev(macsec, netdev);
	if (!macsec_dev) {
		netdev_err(ctx->netdev, "MACsec offload: Failed to find device\n");
		err = -EINVAL;
		goto out;
	}

	for (i = 0; i < MACSEC_NUM_AN; i++) {
		tx_sa = macsec_dev->tx_sc.tx_sa[i];
		if (!tx_sa)
			continue;

		tx_sa->active = 0;
		index = macsec_dev->tx_sc.index * MACSEC_NUM_AN + i;
		disp_ops->cfg_macsec_sa(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt), index, tx_sa, true);
		kfree(tx_sa);
		macsec_dev->tx_sc.tx_sa[i] = NULL;
	}

	macsec_dev->macsec_fs.vld = 0;
	disp_ops->cfg_macsec_fs(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				macsec_dev->tx_sc.index, &macsec_dev->macsec_fs);
	macsec_dev->tx_sc.active = 0;
	disp_ops->cfg_macsec_txsc(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
				  macsec_dev->tx_sc.index, &macsec_dev->tx_sc);
	disp_ops->free_macsec_txsc_index(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					 macsec_dev->tx_sc.index);

	rx_sc_list = &macsec_dev->macsec_rx_sc_list;
	list_for_each_entry_rcu(rx_sc, rx_sc_list, rx_sc_node) {
		for (i = 0; i < MACSEC_NUM_AN; i++) {
			rx_sa = rx_sc->rx_sa[i];
			if (!rx_sa)
				continue;

			rx_sa->active = 0;
			index = rx_sc->index * MACSEC_NUM_AN + i;
			disp_ops->cfg_macsec_sa(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						index, rx_sa, false);
			kfree(rx_sa);
			rx_sc->rx_sa[i] = NULL;
		}
		rx_sc->active = 0;
		disp_ops->cfg_macsec_rxsc(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
					  rx_sc->index, rx_sc);
		disp_ops->free_macsec_rxsc_index(NBL_SERV_MGT_TO_DISP_PRIV(serv_mgt),
						 rx_sc->index);
		list_del_rcu(&rx_sc->rx_sc_node);
		metadata_dst_free(rx_sc->md_dst);
		kfree(rx_sc);
	}

	list_del_rcu(&macsec_dev->macsec_dev_node);
	macsec->dev_num--;
	kfree(macsec_dev);
	netdev_info(ctx->netdev, "MACsec offload: end del sec secy\n");

out:
	mutex_unlock(&macsec->lock);
	return err;
}

#define NBL_SERV_MACSEC_OPS_TBL								\
do {											\
	NBL_SERV_SET_MACSEC_OPS(add_macsec_txsa, nbl_macsec_add_txsa);			\
	NBL_SERV_SET_MACSEC_OPS(upd_macsec_txsa, nbl_macsec_upd_txsa);			\
	NBL_SERV_SET_MACSEC_OPS(del_macsec_txsa, nbl_macsec_del_txsa);			\
	NBL_SERV_SET_MACSEC_OPS(add_macsec_rxsc, nbl_macsec_add_rxsc);			\
	NBL_SERV_SET_MACSEC_OPS(upd_macsec_rxsc, nbl_macsec_upd_rxsc);			\
	NBL_SERV_SET_MACSEC_OPS(del_macsec_rxsc, nbl_macsec_del_rxsc);			\
	NBL_SERV_SET_MACSEC_OPS(add_macsec_rxsa, nbl_macsec_add_rxsa);			\
	NBL_SERV_SET_MACSEC_OPS(upd_macsec_rxsa, nbl_macsec_upd_rxsa);			\
	NBL_SERV_SET_MACSEC_OPS(del_macsec_rxsa, nbl_macsec_del_rxsa);			\
	NBL_SERV_SET_MACSEC_OPS(add_macsec_secy, nbl_macsec_add_secy);			\
	NBL_SERV_SET_MACSEC_OPS(upd_macsec_secy, nbl_macsec_upd_secy);			\
	NBL_SERV_SET_MACSEC_OPS(del_macsec_secy, nbl_macsec_del_secy);			\
} while (0)

void nbl_serv_setup_macsec_ops(struct nbl_service_ops *serv_ops)
{
#define NBL_SERV_SET_MACSEC_OPS(name, func) do {serv_ops->NBL_NAME(name) = func; ; } while (0)
	NBL_SERV_MACSEC_OPS_TBL;
#undef  NBL_SERV_SET_MACSEC_OPS
}

#else

void nbl_serv_setup_macsec_ops(struct nbl_service_ops *serv_ops) {}

#endif /* end ifdef CONFIG_MACSEC*/
