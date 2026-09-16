// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#if IS_ENABLED(CONFIG_NET_DEVLINK)
#include "nse.h"
#include "nse_lib.h"
#include "nse_eswitch.h"
#include "nse_fltr.h"
#include "nse_repr.h"
#include "nse_devlink.h"
#include "nse_pf_vsi_vlan_ops.h"
#include "nse_tc_lib.h"
#include "nse_neigh.h"
#include "nse_vf_meter.h"
#include <net/psample.h>
#include "nse_lpm.h"

/**
 * nse_eswitch_setup_env - configure switchdev HW filters
 * @pf: pointer to PF struct
 *
 * This function adds HW filters configuration specific for switchdev
 * mode.
 */
static int nse_eswitch_setup_env(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;
	struct nse_vsi *uplink_vsi = pf->switchdev.uplink_vsi;
	struct net_device *uplink_netdev = uplink_vsi->netdev;
	struct nse_vsi *ctrl_vsi = pf->switchdev.control_vsi;
	struct nse_vsi_vlan_ops *vlan_ops;

	vlan_ops = nse_get_compat_vsi_vlan_ops(ctrl_vsi);
	if (vlan_ops->dis_stripping(ctrl_vsi) ||
	    vlan_ops->dis_insertion(ctrl_vsi))
		return -ENODEV;

	nse_remove_vsi_fltr(&pf->hw, uplink_vsi->idx);
	nse_vsi_update_switch(uplink_vsi, nse_vsi_ctx_clear_rx_dflt_vsi);

	netif_addr_lock_bh(uplink_netdev);
	__dev_uc_unsync(uplink_netdev, NULL);
	__dev_mc_unsync(uplink_netdev, NULL);
	netif_addr_unlock_bh(uplink_netdev);

	if (nse_vsi_add_vlan_zero(uplink_vsi)) {
		dev_err(nse_hw_to_dev(hw), "[%s, %d] Failed to add 0 vlan\n",
			__func__, __LINE__);
		goto err_add_vlan_zero;
	}

	/*at Rx direction, uplink_vsi should be ovs miss vsi*/
#ifdef NSE_ESWITH_SET_MODE
	if (nse_vsi_update_switch(uplink_vsi, nse_vsi_ctx_set_rx_ovs_miss))
#else
	if (nse_vsi_update_switch(uplink_vsi, nse_vsi_ctx_set_rx_dflt_vsi))
#endif
	{
		dev_err(nse_hw_to_dev(hw), "[%s, %d] Failed to set rx ovs miss\n",
			__func__, __LINE__);
		goto err_ovs_miss_rx;
	}
	/*at Tx direction, ctrl vsi should be ovs miss vsi */
	if (nse_vsi_update_switch(ctrl_vsi, nse_vsi_ctx_set_tx_ovs_miss)) {
		dev_err(nse_hw_to_dev(hw), "[%s, %d] Failed to set tx ovs miss\n",
			__func__, __LINE__);
		goto err_ovs_miss_tx;
	}

	/*tx desc of main VSI can decide destination*/
	if (nse_vsi_update_switch(uplink_vsi, nse_vsi_ctx_set_allow_override)) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to set uplink allow override\n",
			__func__, __LINE__);
		goto err_override_uplink;
	}

	/*tx desc of switchdev ctrl VSI can decide destination*/
	if (nse_vsi_update_switch(ctrl_vsi, nse_vsi_ctx_set_allow_override)) {
		dev_err(nse_hw_to_dev(hw),
			"[%s, %d] Failed to set ctrl_vsi allow override\n",
			__func__, __LINE__);
		goto err_override_control;
	}

	if (pf->switchdev.pf_roce_en) {
		dev_info(nse_hw_to_dev(hw),
			"[%s, %d] Start to disable uplink vsi roce fltr\n",
			__func__, __LINE__);
		if (nse_cfg_roce_fltr(hw, uplink_vsi->idx, false)) {
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Failed to disable uplink vsi roce fltr\n",
				__func__, __LINE__);
			goto err_override_control;
		}

		uplink_vsi->info.pe_flags &= ~NSE_AQ_VSI_PE_FLAG_FLTR_EN;
	}

	if (nse_eswitch_set_mode(pf, DEVLINK_ESWITCH_MODE_SWITCHDEV))
		goto err_set_mode;

	return 0;

err_set_mode:
	nse_eswitch_set_mode(pf, DEVLINK_ESWITCH_MODE_LEGACY);

err_override_control:
	nse_vsi_update_switch(uplink_vsi, nse_vsi_ctx_clear_allow_override);

err_override_uplink:
	nse_vsi_update_switch(ctrl_vsi, nse_vsi_ctx_clear_tx_ovs_miss);

err_ovs_miss_tx:
#ifdef NSE_ESWITH_SET_MODE
	nse_vsi_update_switch(uplink_vsi, nse_vsi_ctx_clear_rx_ovs_miss);
#else
	nse_vsi_update_switch(uplink_vsi, nse_vsi_ctx_clear_rx_dflt_vsi);
#endif

err_ovs_miss_rx:
err_add_vlan_zero:
	nse_fltr_add_mac_and_broadcast(uplink_vsi,
				       uplink_vsi->port_info->mac.perm_addr,
				       NSE_FWD_TO_VSI);
	return -ENODEV;
}

/**
 * nse_eswitch_release_env - clear switchdev HW filters
 * @pf: pointer to PF struct
 *
 * This function removes HW filters configuration specific for switchdev
 * mode and restores default legacy mode settings.
 */
static void
nse_eswitch_release_env(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;
	struct nse_vsi *uplink_vsi = pf->switchdev.uplink_vsi;
	struct nse_vsi *ctrl_vsi = pf->switchdev.control_vsi;

	if (pf->switchdev.pf_roce_en) {
		if (nse_cfg_roce_fltr(hw, uplink_vsi->idx, true)) {
			dev_err(nse_hw_to_dev(hw),
				"[%s, %d] Failed to enable uplink vsi roce fltr\n",
				__func__, __LINE__);
		} else {
			uplink_vsi->info.pe_flags |= NSE_AQ_VSI_PE_FLAG_FLTR_EN;
		}
	}

	nse_vsi_update_switch(ctrl_vsi, nse_vsi_ctx_clear_allow_override);
	nse_vsi_update_switch(uplink_vsi, nse_vsi_ctx_clear_allow_override);
	nse_vsi_update_switch(ctrl_vsi, nse_vsi_ctx_clear_tx_ovs_miss);
	nse_vsi_update_switch(uplink_vsi, nse_vsi_ctx_clear_rx_ovs_miss);
	nse_fltr_add_mac_and_broadcast(uplink_vsi,
				       uplink_vsi->port_info->mac.perm_addr,
				       NSE_FWD_TO_VSI);
}

/**
 * nse_eswitch_remap_ring - reconfigure ring of switchdev ctrl VSI
 * @ring: pointer to ring
 * @q_vector: pointer of q_vector which is connected with this ring
 * @netdev: netdevice connected with this ring
 */
static void
nse_eswitch_remap_ring(struct nse_ring *ring, struct nse_q_vector *q_vector,
		       struct net_device *netdev)
{
	ring->q_vector = q_vector;
	ring->next = NULL;
	ring->netdev = netdev;
}

/**
 * nse_eswitch_remap_rings_to_vectors - reconfigure rings of switchdev ctrl VSI
 * @pf: pointer to PF struct
 *
 * In switchdev number of allocated Tx/Rx rings is equal.
 *
 * This function fills q_vectors structures associated with representator and
 * move each ring pairs to port representator netdevs. Each port representor
 * will have dedicated 1 Tx/Rx ring pair, so number of rings pair is equal to
 * number of VFs.
 */
void nse_eswitch_remap_rings_to_vectors(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;
	struct nse_vsi *vsi = pf->switchdev.control_vsi;
	u16 q_id;
	bool actually_remap;
	unsigned int bkt;
	struct nse_vf *vf;

	lockdep_assert_held(&pf->vfs.table_lock);

	nse_for_each_vf(pf, bkt, vf) {
		struct nse_q_vector *q_vector;
		struct nse_q_vector *real_q_vector = NULL;	/* control_vsi->q_vec[] element */
		struct nse_ring *tx_ring;
		struct nse_ring *rx_ring;
		struct nse_repr *repr;

		repr = vf->repr;
		q_vector = repr->q_vector;
		q_vector->vsi = vsi;

		/*  only map 0th (the first) vf->repr->q_vector of every 8 VFs --- corresponding to
		 * nse_vsi_set_num_qs()
		 */

		actually_remap = true;

		if (vf->vf_id % 8)
			actually_remap = false;

		/*  special case: if switchdev-ctrl-vsi is only 1 lanQ, then only VF-0 repr remap to
		 * it, all other VF repr considered not actually remap
		 */
		if (vsi->num_txq == 1 && vf->vf_id)
			actually_remap = false;

		nse_debug(hw, NSE_DBG_SRIOV, "[%s] vf (id=%d), actually_remap=%d\n",
			  __func__, vf->vf_id, actually_remap);

		if (actually_remap) {
			q_id = vf->vf_id / 8;

			nse_debug(hw, NSE_DBG_SRIOV, "\t vf (id=%d), actually remap=1, vsi->num_txq=%d, q_id=%d\n",
				  vf->vf_id, vsi->num_txq, q_id);

			tx_ring = vsi->tx_rings[q_id];
			rx_ring = vsi->rx_rings[q_id];
			/*  in nse_vsi_set_num_qs() we have Q space size = irq space size, so q_id
			 * is real_q_vector index
			 */
			real_q_vector = vsi->q_vectors[q_id];

			repr->real_q_vector = real_q_vector;

			/* copy real_q_vector's reg_idx */
			q_vector->reg_idx = real_q_vector->reg_idx;

			q_vector->num_ring_tx = 1;
			q_vector->tx.ring = tx_ring;
			nse_eswitch_remap_ring(tx_ring, q_vector, repr->netdev);
			/* In switchdev mode, from OS stack perspective, there is only
			 * one queue for given netdev, so it needs to be indexed as 0.
			 */
			tx_ring->q_index = 0;

			q_vector->num_ring_rx = 1;
			q_vector->rx.ring = rx_ring;
			nse_eswitch_remap_ring(rx_ring, q_vector, repr->netdev);

		} else {
			repr->real_q_vector = NULL;

			/* meaningless, because not actually_remap */
			q_vector->reg_idx = vsi->q_vectors[0]->reg_idx;

			q_vector->num_ring_tx = 0;
			q_vector->tx.ring = NULL;

			q_vector->num_ring_rx = 0;
			q_vector->rx.ring = NULL;
		}
	}
}

/**
 * nse_eswitch_release_reprs - clear PR VSIs configuration
 * @pf: poiner to PF struct
 * @ctrl_vsi: pointer to switchdev control VSI
 */
static void
nse_eswitch_release_reprs(struct nse_pf *pf, struct nse_vsi *ctrl_vsi)
{
	struct nse_vf *vf;
	unsigned int bkt;

	lockdep_assert_held(&pf->vfs.table_lock);

	kfree(ctrl_vsi->target_netdevs);
	ctrl_vsi->target_netdevs = NULL;

	nse_for_each_vf(pf, bkt, vf) {
		struct nse_vsi *vsi = vf->repr->src_vsi;

		/* Skip VFs that aren't configured */
		if (!vf->repr->dst)
			continue;

		nse_vsi_update_switch(vsi, nse_vsi_ctx_set_antispoof);
		metadata_dst_free(vf->repr->dst);
		vf->repr->dst = NULL;
		nse_fltr_add_mac_and_broadcast(vsi, vf->hw_lan_addr.addr,
					       NSE_FWD_TO_VSI);

		netif_napi_del(&vf->repr->q_vector->napi);
	}
}

/**
 * nse_eswitch_setup_reprs - configure port reprs to run in switchdev mode
 * @pf: pointer to PF struct
 */
static int nse_eswitch_setup_reprs(struct nse_pf *pf, bool init)
{
	struct nse_vsi *ctrl_vsi = pf->switchdev.control_vsi;
	struct nse_vf *vf;
	unsigned int bkt;
	unsigned int max_vsi_num = 0;

	lockdep_assert_held(&pf->vfs.table_lock);

	nse_for_each_vf(pf, bkt, vf) {
		struct nse_vsi *vsi = vf->repr->src_vsi;

		nse_remove_vsi_fltr(&pf->hw, vsi->idx);
		nse_vsi_update_switch(vsi, nse_vsi_ctx_clear_rx_dflt_vsi);

		if (init)
			vf->repr->dst = metadata_dst_alloc(0, METADATA_HW_PORT_MUX,
						   GFP_KERNEL);
		if (!vf->repr->dst) {
			nse_fltr_add_mac_and_broadcast(vsi,
						       vf->hw_lan_addr.addr,
						       NSE_FWD_TO_VSI);
			goto err;
		}

		if (nse_vsi_update_switch(vsi, nse_vsi_ctx_clear_antispoof)) {
			nse_fltr_add_mac_and_broadcast(vsi,
						       vf->hw_lan_addr.addr,
						       NSE_FWD_TO_VSI);
			metadata_dst_free(vf->repr->dst);
			vf->repr->dst = NULL;
			goto err;
		}

		if (nse_vsi_add_vlan_zero(vsi)) {
			nse_fltr_add_mac_and_broadcast(vsi,
						       vf->hw_lan_addr.addr,
						       NSE_FWD_TO_VSI);
			metadata_dst_free(vf->repr->dst);
			vf->repr->dst = NULL;
			nse_vsi_update_switch(vsi, nse_vsi_ctx_set_antispoof);
			goto err;
		}

		if (max_vsi_num < vsi->vsi_abs_num)
			max_vsi_num = vsi->vsi_abs_num;

		netif_napi_add(vf->repr->netdev, &vf->repr->q_vector->napi,
			       nse_napi_poll);

		netif_keep_dst(vf->repr->netdev);
	}

	kfree(ctrl_vsi->target_netdevs);

	ctrl_vsi->target_netdevs_len = max_vsi_num + 1;

	ctrl_vsi->target_netdevs = kcalloc(max_vsi_num + 1,
						sizeof(struct net_device *),
						GFP_KERNEL);
	if (!ctrl_vsi->target_netdevs)
		goto err;

	nse_for_each_vf(pf, bkt, vf) {
		struct metadata_dst *dst;
		struct nse_repr *repr;
		struct nse_vsi *vsi;

		repr = vf->repr;
		vsi = repr->src_vsi;

		ctrl_vsi->target_netdevs[vsi->vsi_abs_num] = repr->netdev;

		dst = repr->dst;
		dst->u.port_info.port_id = vsi->vsi_abs_num;
		dst->u.port_info.lower_dev = repr->netdev;

		nse_repr_set_traffic_vsi(repr, ctrl_vsi);
	}

	return 0;

err:
	nse_eswitch_release_reprs(pf, ctrl_vsi);

	return -ENODEV;
}

/**
 * nse_eswitch_update_repr - reconfigure VF port representor
 * @vsi: VF VSI for which port representor is configured
 */
void nse_eswitch_update_repr(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_repr *repr;
	struct nse_vf *vf;
	int ret;

	if (!nse_is_switchdev_running(pf))
		return;

	vf = vsi->vf;
	repr = vf->repr;
	repr->src_vsi = vsi;
	repr->dst->u.port_info.port_id = vsi->vsi_abs_num;

	ret = nse_vsi_update_switch(vsi, nse_vsi_ctx_clear_antispoof);
	if (ret) {
		nse_fltr_add_mac_and_broadcast(vsi, vf->hw_lan_addr.addr,
					       NSE_FWD_TO_VSI);
		dev_err(nse_pf_to_dev(pf), "Failed to update VF %d port representor",
			vf->vf_id);
	}
}

/**
 * nse_eswitch_port_start_xmit - callback for packets transmit
 * @skb: send buffer
 * @netdev: network interface device structure
 *
 * Returns NETDEV_TX_OK if sent, else an error code
 */
netdev_tx_t
nse_eswitch_port_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct nse_netdev_priv *np;
	struct nse_repr *repr;
	struct nse_vsi *vsi;
	u64 skb_len = skb->len;
	netdev_tx_t ret;

	np = netdev_priv(netdev);
	vsi = np->vsi;

	if (!vsi || test_bit(NSE_VSI_DOWN, vsi->state))
		return NETDEV_TX_BUSY;

	if (nse_is_reset_in_progress(vsi->back->state) ||
	    test_bit(NSE_VF_DIS, vsi->back->state))
		return NETDEV_TX_BUSY;

	repr = nse_netdev_to_repr(netdev);
	skb_dst_drop(skb);
	dst_hold((struct dst_entry *)repr->dst);
	skb_dst_set(skb, (struct dst_entry *)repr->dst);

	skb->queue_mapping = (repr->vf->vf_id % vsi->num_txq);

	/* like HARD_TX_LOCK() / HARD_TX_UNLOCK() in __dev_queue_xmit() */
	spin_lock_bh(&vsi->tx_rings_locks[skb->queue_mapping]);

	ret = nse_start_xmit(skb, netdev);

	spin_unlock_bh(&vsi->tx_rings_locks[skb->queue_mapping]);

	if (ret == NETDEV_TX_OK) {
		repr->tx_packets++;
		repr->tx_bytes += skb_len;
	}

	return ret;
}

/**
 * nse_eswitch_set_target_vsi - set switchdev context in Tx context descriptor
 * @skb: pointer to send buffer
 * @off: pointer to offload struct
 */
void
nse_eswitch_set_target_vsi(struct sk_buff *skb,
			   struct nse_tx_offload_params *off)
{
	struct metadata_dst *dst = skb_metadata_dst(skb);
	u64 dst_vsi;

	if (!dst) {
		off->cd_qw1 |= ((NSE_TX_DESC_DTYPE_CTX << NSE_TXD_CTX_DTYPE_S) |
						(NSE_TXD_CTX_SWITCH_UPLINK <<
						 NSE_TXD_CTX_SWITCH_S));
	} else {
		dst_vsi = (u64)dst->u.port_info.port_id;	/* VSI absolute ID */

		off->cd_qw1 |= ((NSE_TX_DESC_DTYPE_CTX << NSE_TXD_CTX_DTYPE_S) |
						(NSE_TXD_CTX_SWITCH_VSI << NSE_TXD_CTX_SWITCH_S) |
						((dst_vsi <<
						 NSE_TXD_CTX_DEST_VSI_S) & NSE_TXD_CTX_DEST_VSI_M));
	}
}

/**
 * nse_eswitch_vsi_setup - configure switchdev control VSI
 * @pf: pointer to PF structure
 * @pi: pointer to port_info structure
 */
static struct nse_vsi *
nse_eswitch_vsi_setup(struct nse_pf *pf, struct nse_port_info *pi)
{
	return nse_vsi_setup(pf, pi, NSE_VSI_SWITCHDEV_CTRL, NULL, 0);
}

/**
 * nse_eswitch_napi_del - remove NAPI handle for all port representors
 * @pf: pointer to PF structure
 */
static void nse_eswitch_napi_del(struct nse_pf *pf)
{
	struct nse_vf *vf;
	unsigned int bkt;

	lockdep_assert_held(&pf->vfs.table_lock);

	nse_for_each_vf(pf, bkt, vf)
		netif_napi_del(&vf->repr->q_vector->napi);
}

/**
 * nse_eswitch_napi_enable - enable NAPI for all port representors
 * @pf: pointer to PF structure
 */
static void nse_eswitch_napi_enable(struct nse_pf *pf)
{
	struct nse_vf *vf;
	unsigned int bkt;

	lockdep_assert_held(&pf->vfs.table_lock);

	nse_for_each_vf(pf, bkt, vf)
		napi_enable(&vf->repr->q_vector->napi);
}

/**
 * nse_eswitch_napi_disable - disable NAPI for all port representors
 * @pf: pointer to PF structure
 */
static void nse_eswitch_napi_disable(struct nse_pf *pf)
{
	struct nse_vf *vf;
	unsigned int bkt;

	lockdep_assert_held(&pf->vfs.table_lock);

	nse_for_each_vf(pf, bkt, vf)
		napi_disable(&vf->repr->q_vector->napi);
}

/**
 * nse_eswitch_enable_switchdev - configure eswitch in switchdev mode
 * @pf: pointer to PF structure
 */
static int
nse_eswitch_enable_switchdev(struct nse_pf *pf)
{
	struct nse_vsi *ctrl_vsi;

	lockdep_assert_held(&pf->vfs.table_lock);

	pf->switchdev.control_vsi = nse_eswitch_vsi_setup(pf, pf->hw.port_info);
	if (!pf->switchdev.control_vsi)
		return -ENODEV;

	ctrl_vsi = pf->switchdev.control_vsi;
	pf->switchdev.uplink_vsi = nse_get_main_vsi(pf);
	if (!pf->switchdev.uplink_vsi)
		goto err_vsi;

	if (nse_tc_ct_init(pf)) {
		dev_err(nse_pf_to_dev(pf),
			"[%s, %d] Failed to initial conntrack info for switchdev\n",
			__func__, __LINE__);
		goto err_ct_init;

	};

	if (nse_neigh_init(&pf->hw, &pf->switchdev)) {
		dev_err(nse_pf_to_dev(pf),
			"[%s, %d] Failed to initial neigh info for switchdev\n",
			__func__, __LINE__);
		goto err_neigh_init;
	}

	if (nse_eswitch_setup_env(pf))
		goto err_setup_env;

	if (nse_repr_add_for_all_vfs(pf))
		goto err_repr_add;

	if (nse_eswitch_setup_reprs(pf, true))
		goto err_setup_reprs;

	nse_eswitch_remap_rings_to_vectors(pf);

	if (nse_vsi_open(ctrl_vsi))
		goto err_open_vsi;

	nse_eswitch_napi_enable(pf);

	nse_create_uplink_sysfs(pf);

	return 0;

err_open_vsi:
err_setup_reprs:
	nse_repr_rem_from_all_vfs(pf);
err_repr_add:
err_setup_env:
	nse_eswitch_release_env(pf);
err_neigh_init:
	nse_neigh_cleanup(&pf->hw, &pf->switchdev);
err_ct_init:
	nse_tc_ct_cleanup(pf);
err_vsi:
	nse_vsi_release(ctrl_vsi);
	return -ENODEV;
}

/**
 * nse_eswitch_disable_switchdev - disable switchdev resources
 * @pf: pointer to PF structure
 */
static void nse_eswitch_disable_switchdev(struct nse_pf *pf)
{
	struct nse_vsi *ctrl_vsi = pf->switchdev.control_vsi;
	struct nse_hw *hw = &pf->hw;

	lockdep_assert_held(&pf->vfs.table_lock);

	nse_acl_destrory_hw_repr_meter(pf->switchdev.uplink_vsi,
					&pf->switchdev.uplink_meter);
	memset(&pf->switchdev.uplink_meter,
				0, sizeof(pf->switchdev.uplink_meter));
	nse_cleanup_uplink_sysfs(pf);
	nse_eswitch_napi_disable(pf);
#ifdef NSE_ESWITH_SET_MODE
	nse_eswitch_set_mode(pf, DEVLINK_ESWITCH_MODE_LEGACY);
#endif
	nse_neigh_cleanup(hw, &pf->switchdev);
	nse_eswitch_release_env(pf);
	nse_eswitch_release_reprs(pf, ctrl_vsi);
	nse_vsi_release(ctrl_vsi);
	nse_repr_rem_from_all_vfs(pf);
	nse_cleanup_tc_fltrs(pf);
	nse_del_all_adv_rcp_per_profile(hw);
	nse_del_all_adv_luts(hw);
	/*conntrack cleanup should be after tc flter cleanup*/
	nse_tc_ct_cleanup(pf);
}

/**
 * nse_eswitch_mode_set - set new eswitch mode
 * @devlink: pointer to devlink structure
 * @mode: eswitch mode to switch to
 * @extack: pointer to extack structure
 */
int nse_eswitch_mode_set(struct devlink *devlink, u16 mode,
		     struct netlink_ext_ack *extack)
{
	struct nse_pf *pf = devlink_priv(devlink);
	struct nse_vsi *vsi = nse_get_main_vsi(pf);
	struct net_device *ndev = vsi->netdev;
	struct device *dev = nse_pf_to_dev(pf);

	if (pf->eswitch_mode == mode)
		return 0;

	if (nse_has_vfs(pf)) {
		dev_info(dev, "Changing eswitch mode is allowed only if there is no VFs created");
		return -EOPNOTSUPP;
	}

	switch (mode) {
	case DEVLINK_ESWITCH_MODE_LEGACY:
		dev_info(dev, "PF %d changed eswitch mode to legacy",
			 pf->hw.pcore_pf_id);
		break;
	case DEVLINK_ESWITCH_MODE_SWITCHDEV:
	{
		if (nse_is_offloaded_macvlan_ena(pf)) {
			dev_err(dev, "switchdev cannot be configured -  L2 Forwarding Offload is currently enabled.\n");
			return -EOPNOTSUPP;
		}

		if (nse_is_hw_static_fea_set(&pf->hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY)) {
			dev_err(dev,
				"switchdev mode is unsupported in hardware legacy switch\n");
			return -EOPNOTSUPP;
		}

		if (nse_is_erouter_mode_en(&pf->hw)) {
			dev_err(dev,
				"switchdev cannot be configured - lpm is enabled\n");
			return -EOPNOTSUPP;
		}

		ndev->features |= NETIF_F_HW_TC;
		set_bit(NSE_FLAG_CLS_FLOWER, pf->flags);

		dev_info(dev, "PF %d changed eswitch mode to switchdev",
			 pf->hw.pcore_pf_id);
		break;
	}
	default:
		NL_SET_ERR_MSG_MOD(extack, "Unknown eswitch mode");

		return -EINVAL;
	}

	pf->eswitch_mode = mode;
	return 0;
}

/**
 * nse_eswitch_get_target_netdev - return port representor netdev
 * @rx_ring: pointer to rx ring
 * @rx_desc: pointer to rx descriptor
 *
 * When working in switchdev mode context (when control vsi is used), this
 * function returns netdev of appropriate port representor. For non-switchdev
 * context, regular netdev associated with rx ring is returned.
 */
struct net_device *
nse_eswitch_get_target_netdev(struct nse_ring *rx_ring,
			      union nse_32b_rx_desc *rx_desc, struct sk_buff *skb)
{
	struct nse_32b_rx_desc_switchdev *desc;
	struct nse_vsi *vsi = rx_ring->vsi;
	struct nse_vsi *control_vsi;
	struct nse_repr *repr;
	u16 src_md, port_type, target_vsi_id;

	control_vsi = vsi->back->switchdev.control_vsi;
	if (vsi != control_vsi)
		return rx_ring->netdev;

	if (rx_desc->wb.rxdid != NSE_RXDID_FLEX_SWITCHDEV)
		return rx_ring->netdev;

	desc = (struct nse_32b_rx_desc_switchdev *)rx_desc;
	src_md = le16_to_cpu(desc->source_vsi_lan);

	port_type = (src_md >> NSE_IN_PORT_TYPE_S) &
					NSE_IN_PORT_TYPE_MASK;
	target_vsi_id = src_md & NSE_IN_PORT_ID_MASK;

	if (port_type == NSE_IN_PORT_TYPE_HOST &&
		target_vsi_id < vsi->target_netdevs_len &&
		vsi->target_netdevs && vsi->target_netdevs[target_vsi_id]) {
		if (nse_is_port_repr_netdev(vsi->target_netdevs[target_vsi_id])) {
			repr = nse_netdev_to_repr(vsi->target_netdevs[target_vsi_id]);
			repr->rx_packets++;
			repr->rx_bytes += skb->len;
		}

		return vsi->target_netdevs[target_vsi_id];
	} else {
		return rx_ring->netdev;
	}
}

/**
 * nse_eswitch_restore_skb_chain
 * @skb: pointer to packet buffer
 * @chain_id: non-zero chain id should be restored
 */
static void
nse_eswitch_restore_skb_chain(struct sk_buff *skb,
			u16 chain_id)
{
#if IS_ENABLED(CONFIG_NET_TC_SKB_EXT)
#endif
}

/**
 * nse_eswitch_restore_skb_sflow
 * @skb: pointer to packet buffer
 * @sflow: pointer to sflow configuration information
 */
static void
nse_eswitch_restore_skb_sflow(struct sk_buff *skb,
			struct nse_sw_sflow *sflow)
{
	u32 trunc_size = sflow->sflow_info.trunc_size;
	struct psample_group psample_group = {};
	struct psample_metadata md = {};

	psample_group.group_num = sflow->sflow_info.group_num;
	psample_group.net = &init_net;

	md.trunc_size = trunc_size ? min(trunc_size, skb->len) : skb->len;
	md.in_ifindex = skb->dev->ifindex;

	skb_push(skb, ETH_HLEN);

	psample_sample_packet(&psample_group, skb, sflow->sflow_info.rate, &md);
}

/**
 * nse_eswitch_restore_skb
 * @rx_ring: pointer to rx ring
 * @rx_desc: pointer to rx descriptor
 *
 * When working in switchdev mode , some info need restore to skb
 * such as sflow flag and chain id
 */
int
nse_eswitch_restore_skb(struct nse_ring *rx_ring,
			      union nse_32b_rx_desc *rx_desc, struct sk_buff *skb)
{
	struct nse_32b_rx_desc_switchdev *swdev_desc;
	struct nse_32b_rx_desc_nic *nic_desc;
	struct nse_vsi *vsi = rx_ring->vsi;
	struct nse_pf *pf = (struct nse_pf *)vsi->back;
	struct device *dev = nse_pf_to_dev(pf);
	bool is_sflow;
	u16 metadata, chain_id;

	if (!nse_is_eswitch_mode_switchdev(pf))
		return 0;

	if (rx_desc->wb.rxdid == NSE_RXDID_FLEX_SWITCHDEV) {
		swdev_desc = (struct nse_32b_rx_desc_switchdev *)rx_desc;
		metadata = le16_to_cpu(swdev_desc->source_vsi_lan);
	} else if (rx_desc->wb.rxdid == NSE_RXDID_FLEX_NIC) {
		nic_desc = (struct nse_32b_rx_desc_nic *)rx_desc;
		metadata = le16_to_cpu(nic_desc->source_vsi_lan);
	} else {
		dev_err(dev, "rx desc rxdid err in switchdev mode\n, rxdid = %d",
			rx_desc->wb.rxdid);
		return -EINVAL;
	}

	chain_id = (metadata >> NSE_RXD_FLEXI_MD6_CHAIN_ID_S) &
				NSE_RXD_FLEXI_MD6_CHAIN_ID_M;

	is_sflow = !!(metadata & NSE_RXD_FLEXI_MD6_SFLOW_VALID_M);
	if (is_sflow) {
		struct nse_sw_sflow *sflow = pf->hw.switch_info->sflow;

		if (!sflow) {
			dev_err(dev, "rx desc sflow valid but sflow config is NULL\n");
			return -EINVAL;
		}

		dev_info(dev, "rcv a sampled packet, which need to restore skb sflow\n");

		nse_eswitch_restore_skb_sflow(skb, sflow);
		/* skb had been stolen by psample module, but skb was not freed.
		 *  skb will be freed when NSE_STOLEN is returned.
		 */
		return NSE_STOLEN;
	}

	if (chain_id) {
		dev_info(dev, "rcv a pkt need to restore chain id(%d)\n", chain_id);
		nse_eswitch_restore_skb_chain(skb, chain_id);
	}

	return 0;
}

/**
 * nse_eswitch_mode_get - get current eswitch mode
 * @devlink: pointer to devlink structure
 * @mode: output parameter for current eswitch mode
 */
int nse_eswitch_mode_get(struct devlink *devlink, u16 *mode)
{
	struct nse_pf *pf = devlink_priv(devlink);

	*mode = pf->eswitch_mode;
	return 0;
}

/**
 * nse_is_eswitch_mode_switchdev - check if eswitch mode is set to switchdev
 * @pf: pointer to PF structure
 *
 * Returns true if eswitch mode is set to DEVLINK_ESWITCH_MODE_SWITCHDEV,
 * false otherwise.
 */
bool nse_is_eswitch_mode_switchdev(struct nse_pf *pf)
{
	return pf->eswitch_mode == DEVLINK_ESWITCH_MODE_SWITCHDEV;
}

/**
 * nse_eswitch_release - cleanup eswitch
 * @pf: pointer to PF structure
 */
void nse_eswitch_release(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;

	nse_debug(hw, NSE_DBG_SYS, "[%s] eswitch_mode=%d\n", __func__, pf->eswitch_mode);

	lockdep_assert_held(&pf->vfs.table_lock);

	nse_vf_meter_destroy_all(pf);

	if (pf->eswitch_mode == DEVLINK_ESWITCH_MODE_LEGACY)
		return;

	pf->switchdev.is_running = false;

	nse_eswitch_disable_switchdev(pf);
}

/**
 * nse_eswitch_configure - configure eswitch
 * @pf: pointer to PF structure
 */
int nse_eswitch_configure(struct nse_pf *pf)
{
	int status;

	lockdep_assert_held(&pf->vfs.table_lock);

	if (nse_vf_meter_create_meters(pf))
		return -ENOMEM;

	if (pf->eswitch_mode == DEVLINK_ESWITCH_MODE_LEGACY || pf->switchdev.is_running)
		return 0;

	status = nse_eswitch_enable_switchdev(pf);
	if (status)
		return status;

	pf->switchdev.is_running = true;
	return 0;
}

/**
 * nse_eswitch_start_all_tx_queues - start Tx queues of all port representors
 * @pf: pointer to PF structure
 */
static void nse_eswitch_start_all_tx_queues(struct nse_pf *pf)
{
	struct nse_vf *vf;
	unsigned int bkt;

	lockdep_assert_held(&pf->vfs.table_lock);

	if (test_bit(NSE_DOWN, pf->state))
		return;

	nse_for_each_vf(pf, bkt, vf)
		if (vf->repr)
			nse_repr_start_tx_queues(vf->repr);
}

/**
 * nse_eswitch_stop_all_tx_queues - stop Tx queues of all port representors
 * @pf: pointer to PF structure
 */
void nse_eswitch_stop_all_tx_queues(struct nse_pf *pf)
{
	struct nse_vf *vf;
	unsigned int bkt;

	lockdep_assert_held(&pf->vfs.table_lock);

	if (test_bit(NSE_DOWN, pf->state))
		return;

	nse_for_each_vf(pf, bkt, vf)
		if (vf->repr)
			nse_repr_stop_tx_queues(vf->repr);
}

/**
 * nse_eswitch_rebuild - rebuild eswitch
 * @pf: pointer to PF structure
 * @reset_type: type of reset
 */
int nse_eswitch_rebuild(struct nse_pf *pf, enum nse_reset_req reset_type)
{
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vsi *ctrl_vsi = pf->switchdev.control_vsi;
	int status;

	nse_debug(hw, NSE_DBG_SYS, "[%s] reset_type=%d\n", __func__, reset_type);

	nse_eswitch_napi_disable(pf);
	nse_eswitch_napi_del(pf);

	status = nse_eswitch_setup_env(pf);
	if (status)
		return status;

	status = nse_eswitch_setup_reprs(pf, false);
	if (status)
		return status;

	nse_eswitch_remap_rings_to_vectors(pf);

	if (nse_is_high_reset_type(reset_type))
		nse_replay_tc_fltrs(pf);

	/*  open switchdev-ctrl-VSI now, not in previous nse_rebuild_vsi_under_pf_drv_by_type(
	 * NSE_VSI_SWITCHDEV_CTRL)
	 */
	status = nse_vsi_open(ctrl_vsi);
	if (status) {
		dev_err(dev, "[%s] FAIL vsi_open(switchdev-ctrl-VSI), status=%d\n",
			__func__, status);
		return status;
	}

	nse_eswitch_napi_enable(pf);
	nse_eswitch_start_all_tx_queues(pf);

	return 0;
}

#endif /* CONFIG_NET_DEVLINK */

