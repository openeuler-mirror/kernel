// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include "mce.h"
#include "mce_dcbnl.h"
#include "mce_dcb.h"
#include "mce_lib.h"

#define MCE_DCB_HW_CHG_RST (0) /* DCB configuration changed with reset */
#define MCE_DCB_NO_HW_CHG  (1) /* DCB configuration did not change */
#define MCE_DCB_HW_CHG (2) /* DCB configuration changed, no reset */

static int mce_dcbnl_validate_ets(struct net_device *netdev,
				  struct ieee_ets *ets)
{
	bool have_ets_tc = false;
	int bw_sum = 0;
	int i;

	/* Validate Priority */
	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		if (ets->prio_tc[i] >= MCE_MAX_TC_CNT) {
			netdev_err(netdev,
				   "Failed to validate ETS: tc(%d) of priority(%d) is not valid\n",
				   ets->prio_tc[i], i);
			return -EINVAL;
		}
	}

	/* Validate Bandwidth Sum */
	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		switch (ets->tc_tsa[i]) {
		case (IEEE_8021QAZ_TSA_ETS):
			have_ets_tc = true;
			bw_sum += ets->tc_tx_bw[i];
			break;
		case (IEEE_8021QAZ_TSA_STRICT):
			break;
		default:
			netdev_err(netdev, "Unsupported tsa type\n");
			return -EOPNOTSUPP;
		}
	}

	if (have_ets_tc && bw_sum != 100) {
		netdev_err(netdev,
			   "Failed to validate ETS: BW sum is illegal\n");
		return -EINVAL;
	}

	return 0;
}

/**
 * mce_dcbnl_getets - retrieve local ETS configuration
 * @netdev: the relevant netdev
 * @ets: struct to hold ETS configuration
 * Returns: The result of the operation.
 */
int mce_dcbnl_getets(struct net_device *netdev,
		     struct ieee_ets *ets)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_ets_cfg *etscfg = NULL;
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;
	u8 i = 0;

	if (!test_bit(MCE_DCB_EN, dcb->flags))
		return -EOPNOTSUPP;

	etscfg = &dcb->cur_etscfg;

	ets->ets_cap = etscfg->ets_cap;

	for (i = 0; i < MCE_MAX_PRIORITY; i++)
		ets->prio_tc[i] = etscfg->prio_table[i];

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		ets->tc_tx_bw[i] = etscfg->tcbwtable[i];
		ets->tc_tsa[i] = etscfg->tsatable[i];
	}

	return 0;
}

/**
 * mce_dcbnl_getets - set IEEE ETS configuration
 * @netdev: pointer to relevant netdev
 * @ets: struct to hold ETS configuration
 * Returns: The result of the operation.
 */
static int mce_dcbnl_setets(struct net_device *netdev,
			    struct ieee_ets *ets)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_ets_cfg *etscfg = NULL;
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;
	bool old_ets = test_bit(MCE_ETS_EN, dcb->flags);
	bool ets_default_flag = false;
	struct iidc_event *event;
	int err = 0;
	u8 i = 0;

	if (!test_bit(MCE_DCB_EN, dcb->flags))
		return -EOPNOTSUPP;
	/* if dcb tools control, just return */
	if (test_bit(MCE_FLAG_DCB_TOOLS, dcb->flags))
		return -EINVAL;
	/* now not support in sriov */
	/* but must return 0 to enable pfc */
	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return 0;

	err = mce_dcbnl_validate_ets(netdev, ets);
	if (err)
		return err;

	mutex_lock(&dcb->dcb_mutex);

	etscfg = &dcb->new_etscfg;

	/* get ets cfg from user */
	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		etscfg->prio_table[i] = ets->prio_tc[i];
		etscfg->tsatable[i] = ets->tc_tsa[i];
		etscfg->tcbwtable[i] = ets->tc_tx_bw[i];
	}

	ets_default_flag = is_default_etscfg(etscfg);
	if (ets_default_flag)
		clear_bit(MCE_ETS_EN, dcb->flags);
	else
		set_bit(MCE_ETS_EN, dcb->flags);

	if (memcmp(etscfg, &dcb->cur_etscfg, sizeof(*etscfg)) == 0) {
		mutex_unlock(&dcb->dcb_mutex);
		return 0;
	}

	set_bit(MCE_DCB_IN_PROGRESS, pf->state);
	/* update dcb->new_etscfg to dcb->new_tccfg */
	err = mce_dcb_update_swetscfg(dcb);
	if (err) {
		/* if error, clear_bit */
		/* keep old state */
		if (old_ets)
			set_bit(MCE_ETS_EN, dcb->flags);
		else
			clear_bit(MCE_ETS_EN, dcb->flags);
		mutex_unlock(&dcb->dcb_mutex);
		clear_bit(MCE_DCB_IN_PROGRESS, pf->state);
		return err;
	}

	if (!ets_default_flag)
		clear_bit(MCE_MQPRIO_CHANNEL, dcb->flags);

	/* update new to cur */
	if (test_bit(MCE_ETS_EN, dcb->flags) || ets_default_flag) {
		memcpy(&dcb->cur_etscfg, &dcb->new_etscfg,
		       sizeof(dcb->cur_etscfg));
		memcpy(&dcb->cur_tccfg, &dcb->new_tccfg,
		       sizeof(dcb->cur_tccfg));
		/* store ets setup */
		memcpy(&dcb->ets_os, ets, sizeof(struct ieee_ets));
	}
	/* echo mrdma change dcb */

	event = kzalloc(sizeof(*event), GFP_KERNEL);
	set_bit(IIDC_EVENT_BEFORE_TC_CHANGE, event->type);
	mce_send_event_to_auxs(pf, event);
	/* update setup to hw */
	mce_dcb_update_hwetscfg(dcb);

	/* if pfc en */
	if (test_bit(MCE_PFC_EN, dcb->flags))
		mce_dcb_update_hwpfccfg(dcb);
	clear_bit(IIDC_EVENT_BEFORE_TC_CHANGE, event->type);
	set_bit(IIDC_EVENT_AFTER_TC_CHANGE, event->type);
	mce_send_event_to_auxs(pf, event);
	kfree(event);

	mce_vsi_cfg_netdev_tc(vsi, dcb);

	mutex_unlock(&dcb->dcb_mutex);
	clear_bit(MCE_DCB_IN_PROGRESS, pf->state);

	return 0;
}

/**
 * mce_dcbnl_getpfc - retrieve local IEEE PFC config
 * @netdev: pointer to netdev struct
 * @pfc: struct to hold PFC info
 * Returns: The result of the operation.
 */
int mce_dcbnl_getpfc(struct net_device *netdev,
		     struct ieee_pfc *pfc)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_pfc_cfg *pfccfg = NULL;
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;

	if (!test_bit(MCE_DCB_EN, dcb->flags))
		return -EOPNOTSUPP;

	pfccfg = &dcb->cur_pfccfg;
	pfc->pfc_cap = MCE_MAX_PRIORITY;
	/* fpga only support 4tcs */
	pfc->pfc_en = pfccfg->pfcena;

	return 0;
}

static void wait_all_tx_done(struct mce_vsi *vsi)
{
	struct mce_ring *ring;
	int timeout;
	u16 ntu;
	u16 ntc;
	int i;

	mce_for_each_txq_new(vsi, i) {
		ring = vsi->tx_rings[i];
		if (!ring)
			continue;
		if (!ring->q_vector)
			continue;

		timeout = 0;
		do {
			ntu = ring->next_to_use;
			ntc = ring->next_to_clean;

			if (ntc == ntu)
				break;
			if ((++timeout) > 50) {
				if (ring_rd32(ring, 0x70) != ntu)
					raw_wr32(ntu, ring->tail);
			}

			if ((++timeout) > 200) {
				dev_err(ring->dev,
					"wait tx-%u done timeout, ntu-%u ntc-%u\n",
					ring->q_index, ntu, ntc);

				break;
			}
			usleep_range(3000, 5000);
		} while (ntc != ntu);
	}
	/* wait 30ms - 50ms all packet to mac */
	for (i = 0; i < 100; i++)
		usleep_range(300, 500);
}

static void update_pause_mode(struct mce_pf *pf, bool pfc_en)
{
	/* pfc off -> on, record old pfc */
	if ((!test_bit(MCE_PFC_EN, pf->dcb->flags)) && (pfc_en)) {
		pf->fc.old_mode = pf->fc.current_mode;
		pf->fc.req_mode = MCE_FC_NONE;
	} else if (!pfc_en) {
		/* pfc off, recover it */
		pf->fc.req_mode = pf->fc.old_mode;
	}
}

/**
 * mce_dcbnl_setpfc - set local IEEE PFC config
 * @netdev: pointer to relevant netdev
 * @pfc: pointer to struct holding PFC config
 * Returns: The result of the operation.
 */
static int mce_dcbnl_setpfc(struct net_device *netdev,
			    struct ieee_pfc *pfc)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_pfc_cfg *new_pfccfg = NULL;
	struct mce_pfc_cfg *cur_pfccfg = NULL;
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;
	struct mce_tc_cfg *tccfg = &dcb->cur_tccfg;
	bool pfc_default_flag = false;
	struct iidc_event *event;

	if (!test_bit(MCE_DCB_EN, dcb->flags))
		return -EOPNOTSUPP;
	/* if dcb tools control, just return */
	if (test_bit(MCE_FLAG_DCB_TOOLS, dcb->flags))
		return -EINVAL;

	if (!(dcb->dcbx_cap & DCB_CAP_DCBX_VER_IEEE))
		return -EINVAL;

	if (test_bit(MCE_ETS_EN, dcb->flags)) {
		int i, j, prio_cnt = 0, min_queue = 0;
		/* check each tc pfc_en */
		for (i = 0; i < tccfg->tc_cnt; i++) {
			min_queue = 0;
			prio_cnt = 0;
			for (j = 0; j < IEEE_8021QAZ_MAX_TCS; j++) {
				if ((tccfg->tc_prios_bit[i] & (1 << j)) != 0) {
					/* if this prio not valid for nic, no-need */
					if (!(vsi->valid_prio & (1 << i)))
						continue;
					prio_cnt++;
					if (pfc->pfc_en & (1 << j))
						min_queue++;
				}
			}
			if (prio_cnt != min_queue && min_queue != 0)
				min_queue++;

			if (min_queue > vsi->num_txq_real) {
				netdev_err(netdev,
					   "tc %d queue %d, cannot support pfc need %d\n", i,
					   vsi->num_txq_real, min_queue);
				return -EINVAL;
			}
		}
	} else {
		/* if only pfc */
		int i = 0, j = 0;

		for (i = 0; i < MCE_MAX_PRIORITY; i++) {
			/* if this prio not valid for nic, no-need */
			if (!(vsi->valid_prio & (1 << i)))
				continue;
			if ((pfc->pfc_en & (1 << i)) != 0)
				j++;
		}
		/* if not all nic prio pfc is on */
		if ((pfc->pfc_en & vsi->valid_prio) != vsi->valid_prio) {
			if (j != MCE_MAX_PRIORITY && j != 0)
				j++;
		}
		if (j > vsi->num_txq_real) {
			netdev_err(netdev, "pfc need %d queues, but max %d\n",
				   j, vsi->num_txq_real);
			netdev_err(netdev, "try pfc_en %x\n",
				   pfc->pfc_en);
			return -EINVAL;
		}
	}
	/* only close pause if pfc on */
	/* record old mode in order to recover from pfc */
	update_pause_mode(pf, !!pfc->pfc_en);

	mutex_lock(&dcb->dcb_mutex);

	new_pfccfg = &dcb->new_pfccfg;
	cur_pfccfg = &dcb->cur_pfccfg;

	if (cur_pfccfg->pfcena == pfc->pfc_en) {
		mutex_unlock(&dcb->dcb_mutex);
		return 0;
	}

	set_bit(MCE_DCB_IN_PROGRESS, pf->state);
	wait_all_tx_done(vsi);
	/* wait all tx done */
	netif_tx_disable(netdev);
	if (pfc->pfc_cap) {
		new_pfccfg->pfccap = pfc->pfc_cap;
	} else {
		/* mabye bug? */
		new_pfccfg->pfccap = MCE_MAX_PRIORITY;
	}

	new_pfccfg->pfcena = pfc->pfc_en;

	pfc_default_flag = is_default_pfccfg(new_pfccfg);
	if (pfc_default_flag)
		clear_bit(MCE_PFC_EN, dcb->flags);
	else
		set_bit(MCE_PFC_EN, dcb->flags);
	if (!test_bit(MCE_FLAG_RX_BUFFER_MANUALLY, pf->flags)) {
		if (memcmp(new_pfccfg, cur_pfccfg, sizeof(*new_pfccfg)) == 0) {
			mutex_unlock(&dcb->dcb_mutex);
			clear_bit(MCE_DCB_IN_PROGRESS, pf->state);
			netif_tx_start_all_queues(netdev);
			return 0;
		}
	} else {
		/* in rx in Manually, not compary it */
		if (memcmp(new_pfccfg, cur_pfccfg, sizeof(struct mce_pfc_cfg_v1)) == 0) {
			mutex_unlock(&dcb->dcb_mutex);
			clear_bit(MCE_DCB_IN_PROGRESS, pf->state);
			netif_tx_start_all_queues(netdev);
			return 0;
		}
	}

	mce_dcb_update_swpfccfg(dcb);

	if (test_bit(MCE_PFC_EN, dcb->flags) || pfc_default_flag) {
		memcpy(&dcb->cur_pfccfg, &dcb->new_pfccfg,
		       sizeof(dcb->cur_pfccfg));
		/* strore os setup */
		memcpy(&dcb->pfc_os, pfc, sizeof(struct ieee_pfc));
		/* store new pfc value */
		/* if ets open, we should not memcpy */
		if (!test_bit(MCE_ETS_EN, dcb->flags))
			memcpy(&dcb->cur_tccfg, &dcb->new_tccfg,
			       sizeof(dcb->cur_tccfg));
	}

	event = kzalloc(sizeof(*event), GFP_KERNEL);
	set_bit(IIDC_EVENT_BEFORE_TC_CHANGE, event->type);
	mce_send_event_to_auxs(pf, event);
	/* update to hw */
	mce_dcb_update_hwpfccfg(dcb);

	clear_bit(IIDC_EVENT_BEFORE_TC_CHANGE, event->type);
	set_bit(IIDC_EVENT_AFTER_TC_CHANGE, event->type);
	mce_send_event_to_auxs(pf, event);
	kfree(event);

	mce_vsi_cfg_netdev_tc(vsi, dcb);

	mutex_unlock(&dcb->dcb_mutex);
	clear_bit(MCE_DCB_IN_PROGRESS, pf->state);
	netif_tx_start_all_queues(netdev);
	return 0;
}

/**
 * mce_dcbnl_setapp - set local IEEE App config
 * @netdev: relevant netdev struct
 * @app: struct to hold app config info
 * Returns: The result of the operation.
 */
static int mce_dcbnl_setapp(struct net_device *netdev,
			    struct dcb_app *app)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;
	struct iidc_event *event;
	int ret = 0;

	if (!test_bit(MCE_DCB_EN, dcb->flags))
		return -EOPNOTSUPP;
	/* if dcb tools control, just return */
	if (test_bit(MCE_FLAG_DCB_TOOLS, dcb->flags))
		return -EINVAL;

	if (app->selector != IEEE_8021QAZ_APP_SEL_DSCP ||
	    app->protocol >= MCE_MAX_DSCP ||
	    app->priority >= MCE_MAX_PRIORITY)
		return -EINVAL;

	mutex_lock(&dcb->dcb_mutex);

	ret = dcb_ieee_setapp(netdev, app);
	if (ret)
		goto setapp_out;

	if (test_and_set_bit(app->protocol, dcb->dscp_mapped)) {
		netdev_err(netdev, "DSCP value %u already user mapped\n",
			   app->protocol);
		ret = dcb_ieee_delapp(netdev, app);
		if (ret)
			netdev_err(netdev,
				   "Failed to delete re-mapping TLV\n");
		ret = -EINVAL;
		goto setapp_out;
	}

	dcb->dscp_map[app->protocol] = app->priority;
	pf->hw.ops->set_dscp(&pf->hw, dcb);
	event = kzalloc(sizeof(*event), GFP_KERNEL);
	set_bit(IIDC_EVENT_AFTER_TC_CHANGE, event->type);
	mce_send_event_to_auxs(pf, event);
	kfree(event);

setapp_out:
	mutex_unlock(&dcb->dcb_mutex);
	return ret;
}

/**
 * mce_dcbnl_delapp - Delete local IEEE App config
 * @netdev: relevant netdev
 * @app: struct to hold app too delete
 *
 * Will not delete first application required by the FW
 * Returns: The result of the operation.
 */
static int mce_dcbnl_delapp(struct net_device *netdev,
			    struct dcb_app *app)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;
	struct iidc_event *event;
	int ret = 0;

	if (!test_bit(MCE_DCB_EN, dcb->flags))
		return -EOPNOTSUPP;

	if (app->selector != IEEE_8021QAZ_APP_SEL_DSCP ||
	    app->protocol >= MCE_MAX_DSCP)
		return -EINVAL;

	mutex_lock(&dcb->dcb_mutex);

	if (!test_bit(app->protocol, dcb->dscp_mapped)) {
		netdev_err(netdev, "DSCP value %u is't user mapped\n",
			   app->protocol);
		ret = -ENOENT;
		goto delapp_out;
	}

	/* Check if the entry matches setting */
	if (app->priority != dcb->dscp_map[app->protocol]) {
		netdev_err(netdev,
			   "DSCP value %u does not match priority %u\n",
			   app->protocol, app->priority);
		ret = -ENOENT;
		goto delapp_out;
	}

	/* Delete the app entry */
	ret = dcb_ieee_delapp(netdev, app);
	if (ret)
		goto delapp_out;

	dcb->dscp_map[app->protocol] = app->protocol / 8;
	clear_bit(app->protocol, dcb->dscp_mapped);

	pf->hw.ops->set_dscp(&pf->hw, dcb);
	event = kzalloc(sizeof(*event), GFP_KERNEL);
	set_bit(IIDC_EVENT_AFTER_TC_CHANGE, event->type);
	mce_send_event_to_auxs(pf, event);
	kfree(event);

delapp_out:
	mutex_unlock(&dcb->dcb_mutex);
	return ret;
}

/**
 * mce_dcbnl_getstate - get DCB enabled state
 * @netdev: pointer to netdev struct
 * Returns: The result of the operation.
 */
static u8 mce_dcbnl_getstate(struct net_device *netdev)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;
	u8 state = 0;

	state = test_bit(MCE_DCB_EN, dcb->flags);
	netdev_dbg(netdev, "Get DCB state = %d\n", state);

	return state;
}

/**
 * mce_dcbnl_setstate - get DCB enabled state
 * @netdev: pointer to netdev struct
 * @state: requested DCB state
 * Returns: The result of the operation.
 */
static u8 mce_dcbnl_setstate(struct net_device *netdev, u8 state)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;

	/* not support dcb in sriov mode on */

	if (!!state == test_bit(MCE_DCB_EN, dcb->flags))
		return MCE_DCB_NO_HW_CHG;

	set_bit(MCE_DCB_IN_PROGRESS, pf->state);
	wait_all_tx_done(vsi);
	if (state) {
		set_bit(MCE_DCB_EN, dcb->flags);
		mce_dcbnl_set_app(dcb, vsi->netdev);
	} else {
		clear_bit(MCE_DCB_EN, dcb->flags);
		mce_dcbnl_del_app(dcb, vsi->netdev);
		/* it pfc on, close it */
		if (test_bit(MCE_PFC_EN, dcb->flags)) {
			clear_bit(MCE_PFC_EN, dcb->flags);
			/* clean pfc info */
			update_pause_mode(pf, false);
			mce_dcb_pfc_default(&dcb->cur_pfccfg);
			mce_dcb_pfc_default(&dcb->new_pfccfg);
			mce_dcb_update_hwpfccfg(dcb);
		}
		if (test_bit(MCE_ETS_EN, dcb->flags)) {
			clear_bit(MCE_ETS_EN, dcb->flags);
			/* clean ets info */
			mce_dcb_update_hwetscfg(dcb);
			mce_dcb_ets_default(&dcb->cur_etscfg);
			mce_dcb_ets_default(&dcb->new_etscfg);
		}
		/* should change ntc */
		/* should clean pfc, ets hw setup */
	}

	clear_bit(MCE_DCB_IN_PROGRESS, pf->state);
	/* maybe setup protoqueu map */
	set_bit(MCE_FLAG_USR_CHANGE_QNUM_ENA, pf->flags);
	mce_vsi_recfg_qs(vsi, vsi->num_rxq, vsi->num_txq_real);

	return MCE_DCB_HW_CHG;
}

/**
 * mce_dcbnl_get_perm_hw_addr - MAC address used by DCBX
 * @netdev: pointer to netdev struct
 * @perm_addr: buffer to return permanent MAC address
 */
static void mce_dcbnl_get_perm_hw_addr(struct net_device *netdev,
				       u8 *perm_addr)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	int i, j;

	memset(perm_addr, 0xff, MAX_ADDR_LEN);

	for (i = 0; i < netdev->addr_len; i++)
		perm_addr[i] = pf->hw.port_info->perm_addr[i];

	for (j = 0; j < netdev->addr_len; j++, i++)
		perm_addr[i] = pf->hw.port_info->perm_addr[j];
}

/**
 * mce_dcbnl_get_pg_tc_cfg_tx - get CEE PG Tx config
 * @netdev: pointer to netdev struct
 * @prio: the corresponding user priority
 * @prio_type: traffic priority type
 * @pgid: the BW group ID the traffic class belongs to
 * @bw_pct: BW percentage for the corresponding BWG
 * @up_map: prio mapped to corresponding TC
 */
static void mce_dcbnl_get_pg_tc_cfg_tx(struct net_device *netdev,
				       int prio,
				       u8 __always_unused *prio_type,
				       u8 *pgid,
				       u8 __always_unused *bw_pct,
				       u8 __always_unused *up_map)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;

	if (!test_bit(MCE_DCB_EN, dcb->flags))
		return;

	if (test_bit(MCE_FLAG_DCB_TOOLS, dcb->flags))
		return;

	if (!(dcb->dcbx_cap & DCB_CAP_DCBX_VER_CEE))
		return;

	if (prio >= MCE_MAX_PRIORITY)
		return;

	*pgid = dcb->cur_etscfg.prio_table[prio];
	netdev_dbg(netdev, "Get PG config prio=%d tc=%d\n", prio, *pgid);
}

/**
 * mce_dcbnl_set_pg_tc_cfg_tx - set CEE PG Tx config
 * @netdev: pointer to relevant netdev
 * @tc: the corresponding traffic class
 * @prio_type: the traffic priority type
 * @bwg_id: the BW group ID the TC belongs to
 * @bw_pct: the BW perventage for the BWG
 * @up_map: prio mapped to corresponding TC
 */
static void mce_dcbnl_set_pg_tc_cfg_tx(struct net_device *netdev,
				       int tc,
				       u8 __always_unused prio_type,
				       u8 __always_unused bwg_id,
				       u8 __always_unused bw_pct, u8 up_map)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;
	u8 i = 0;

	if (!test_bit(MCE_DCB_EN, dcb->flags))
		return;
	/* if dcb tools control, just return */
	if (test_bit(MCE_FLAG_DCB_TOOLS, dcb->flags))
		return;

	if (!(dcb->dcbx_cap & DCB_CAP_DCBX_VER_CEE))
		return;

	if (tc >= MCE_MAX_TC_CNT) {
		netdev_err(netdev,
			   "tc(%d) is out of max tc(%d)\n",
			   tc, MCE_MAX_TC_CNT);
		return;
	}

	/* prio_type, bwg_id and bw_pct per UP are not supported */
	/* setup tcx bitmap */

	for (i = 0; i < MCE_MAX_PRIORITY; i++) {
		if (up_map & BIT(i))
			dcb->new_etscfg.prio_table[i] = tc;
	}

	dcb->new_etscfg.tsatable[tc] = IEEE_8021QAZ_TSA_ETS;
}

/**
 * mce_dcbnl_get_pg_bwg_cfg_tx - Get CEE PGBW config
 * @netdev: pointer to the netdev struct
 * @pgid: corresponding traffic class
 * @bw_pct: the BW percentage for the corresponding TC
 */
static void mce_dcbnl_get_pg_bwg_cfg_tx(struct net_device *netdev,
					int pgid, u8 *bw_pct)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;

	if (!test_bit(MCE_DCB_EN, dcb->flags))
		return;

	if (test_bit(MCE_FLAG_DCB_TOOLS, dcb->flags))
		return;

	if (!(dcb->dcbx_cap & DCB_CAP_DCBX_VER_CEE))
		return;

	if (pgid >= 8) {
		netdev_err(netdev,
			   "pgid(%d) is out of max tc(%d)\n",
			   pgid, MCE_MAX_TC_CNT);
		return;
	}

	*bw_pct = dcb->cur_etscfg.tcbwtable[pgid];
	netdev_dbg(netdev, "Get PG BW config tc=%d bw_pct=%d\n", pgid,
		   *bw_pct);
}

/**
 * mce_dcbnl_set_pg_bwg_cfg_tx - set CEE PG Tx BW config
 * @netdev: the corresponding netdev
 * @pgid: Correspongind traffic class
 * @bw_pct: the BW percentage for the specified TC
 */
static void mce_dcbnl_set_pg_bwg_cfg_tx(struct net_device *netdev,
					int pgid, u8 bw_pct)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;

	if (!test_bit(MCE_DCB_EN, dcb->flags))
		return;
	/* if dcb tools control, just return */
	if (test_bit(MCE_FLAG_DCB_TOOLS, dcb->flags))
		return;

	if (!(dcb->dcbx_cap & DCB_CAP_DCBX_VER_CEE))
		return;

	if (pgid >= MCE_MAX_TC_CNT) {
		netdev_err(netdev,
			   "pgid(%d) is out of max tc(%d)\n",
			   pgid, MCE_MAX_TC_CNT);
		return;
	}

	dcb->new_etscfg.tcbwtable[pgid] = bw_pct;
}

/**
 * mce_dcbnl_get_pg_tc_cfg_rx - Get CEE PG Rx config
 * @netdev: pointer to netdev struct
 * @prio: the corresponding user priority
 * @prio_type: the traffic priority type
 * @pgid: the PG ID
 * @bw_pct: the BW percentage for the corresponding BWG
 * @up_map: prio mapped to corresponding TC
 */
static void mce_dcbnl_get_pg_tc_cfg_rx(struct net_device *netdev,
				       int prio,
				       u8 __always_unused *prio_type,
				       u8 *pgid,
				       u8 __always_unused *bw_pct,
				       u8 __always_unused *up_map)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;

	if (!test_bit(MCE_DCB_EN, dcb->flags))
		return;

	if (test_bit(MCE_FLAG_DCB_TOOLS, dcb->flags))
		return;

	if (!(dcb->dcbx_cap & DCB_CAP_DCBX_VER_CEE))
		return;

	if (prio >= MCE_MAX_PRIORITY) {
		netdev_err(netdev,
			   "prio(%d) is out of max prio(%d)\n",
			   prio, MCE_MAX_PRIORITY);
		return;
	}

	*pgid = dcb->cur_etscfg.prio_table[prio];
}

/**
 * mce_dcbnl_set_pg_tc_cfg_rx - Configure the CEE priority group traffic class for Rx.
 * @netdev: relevant netdev struct
 * @prio: corresponding user priority
 * @prio_type: the traffic priority type
 * @pgid: the PG ID
 * @bw_pct: BW percentage for corresponding BWG
 * @up_map: prio mapped to corresponding TC
 *
 * lldpad requires this function pointer to be non-NULL to complete CEE config.
 */
static void mce_dcbnl_set_pg_tc_cfg_rx(struct net_device *netdev,
				       int __always_unused prio,
				       u8 __always_unused prio_type,
				       u8 __always_unused pgid,
				       u8 __always_unused bw_pct,
				       u8 __always_unused up_map)
{
	netdev_dbg(netdev, "Rx TC PG Config Not Supported.\n");
}

/**
 * mce_dcbnl_get_pg_bwg_cfg_rx - Get CEE PG BW Rx config
 * @netdev: pointer to netdev struct
 * @pgid: the corresponding traffic class
 * @bw_pct: the BW percentage for the corresponding TC
 */
static void mce_dcbnl_get_pg_bwg_cfg_rx(struct net_device *netdev,
					int __always_unused pgid,
					u8 *bw_pct)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;

	if (!test_bit(MCE_DCB_EN, dcb->flags))
		return;

	if (test_bit(MCE_FLAG_DCB_TOOLS, dcb->flags))
		return;

	if (!(dcb->dcbx_cap & DCB_CAP_DCBX_VER_CEE))
		return;

	*bw_pct = 0;
}

/**
 * mce_dcbnl_set_pg_bwg_cfg_rx - Configure the CEE PG bandwidth group for Rx.
 * @netdev: the corresponding netdev
 * @pgid: corresponding TC
 * @bw_pct: BW percentage for given TC
 *
 * lldpad requires this function pointer to be non-NULL to complete CEE config.
 */
static void mce_dcbnl_set_pg_bwg_cfg_rx(struct net_device *netdev,
					int __always_unused pgid,
					u8 __always_unused bw_pct)
{
	netdev_dbg(netdev, "Rx BWG PG Config Not Supported.\n");
}

/**
 * mce_dcbnl_get_pfc_cfg - Get CEE PFC config
 * @netdev: pointer to netdev struct
 * @prio: corresponding user priority
 * @setting: the PFC setting for given priority
 */
static void mce_dcbnl_get_pfc_cfg(struct net_device *netdev,
				  int prio, u8 *setting)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;

	if (!test_bit(MCE_DCB_EN, dcb->flags))
		return;

	if (test_bit(MCE_FLAG_DCB_TOOLS, dcb->flags))
		return;
	if (!(dcb->dcbx_cap & DCB_CAP_DCBX_VER_CEE))
		return;

	if (prio >= MCE_MAX_PRIORITY) {
		netdev_err(netdev,
			   "prio(%d) is out of max prio(%d)\n",
			   prio, MCE_MAX_PRIORITY);
		return;
	}

	*setting = (dcb->cur_pfccfg.pfcena >> prio) & 0x1;
	netdev_dbg(netdev,
		   "Get PFC Config up=%d, setting=%d, pfcenable=0x%x\n",
		   prio, *setting, dcb->cur_pfccfg.pfcena);
}

/**
 * mce_dcbnl_set_pfc_cfg - Set CEE PFC config
 * @netdev: the corresponding netdev
 * @prio: User Priority
 * @set: PFC setting to apply
 */
static void mce_dcbnl_set_pfc_cfg(struct net_device *netdev,
				  int prio, u8 set)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;

	if (!test_bit(MCE_DCB_EN, dcb->flags))
		return;
	/* if dcb tools control, just return */
	if (test_bit(MCE_FLAG_DCB_TOOLS, dcb->flags))
		return;

	if (!(dcb->dcbx_cap & DCB_CAP_DCBX_VER_CEE))
		return;

	if (prio >= MCE_MAX_PRIORITY) {
		netdev_err(netdev,
			   "prio(%d) is out of max prio(%d)\n",
			   prio, MCE_MAX_PRIORITY);
		return;
	}

	if (prio != 0 && pf->fc.current_mode != MCE_FC_NONE)
		pf->fc.current_mode = MCE_FC_NONE;

	dcb->new_pfccfg.pfccap = MCE_MAX_PRIORITY;
	if (set)
		dcb->new_pfccfg.pfcena |= BIT(prio);
	else
		dcb->new_pfccfg.pfcena &= ~BIT(prio);

	netdev_dbg(netdev, "Set PFC config UP:%d set:%d pfcena:0x%x\n",
		   prio, set, dcb->new_pfccfg.pfcena);
}

/**
 * mce_dcbnl_cee_set_all - Commit CEE DCB settings to HW
 * @netdev: the corresponding netdev
 * Returns: The result of the operation.
 */
static u8 mce_dcbnl_cee_set_all(struct net_device *netdev)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_ets_cfg *etscfg = NULL;
	struct mce_pfc_cfg *pfccfg = NULL;
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;
	struct mce_tc_cfg *tccfg = &dcb->new_tccfg;
	bool ets_default_flag = false;
	bool pfc_default_flag = false;
	int err = MCE_DCB_HW_CHG_RST;

	if (!test_bit(MCE_DCB_EN, dcb->flags))
		return MCE_DCB_NO_HW_CHG;
	/* if dcb tools control, just return */
	if (test_bit(MCE_FLAG_DCB_TOOLS, dcb->flags))
		return -EOPNOTSUPP;

	if (!(dcb->dcbx_cap & DCB_CAP_DCBX_VER_CEE))
		return MCE_DCB_NO_HW_CHG;

	if ((!memcmp(&dcb->cur_etscfg, &dcb->new_etscfg, sizeof(dcb->cur_etscfg))) &&
	    (!memcmp(&dcb->cur_pfccfg, &dcb->new_pfccfg, sizeof(dcb->cur_pfccfg)))) {
		return 0;
	}

	mutex_lock(&dcb->dcb_mutex);

	etscfg = &dcb->new_etscfg;

	ets_default_flag = is_default_etscfg(etscfg);
	if (ets_default_flag)
		clear_bit(MCE_ETS_EN, dcb->flags);
	else
		set_bit(MCE_ETS_EN, dcb->flags);

	err = mce_dcb_update_swetscfg(dcb);
	if (err) {
		err = MCE_DCB_NO_HW_CHG;
		goto out;
	}

	if (test_bit(MCE_ETS_EN, dcb->flags) || ets_default_flag) {
		memcpy(&dcb->cur_etscfg, etscfg,
		       sizeof(dcb->cur_etscfg));
		memcpy(&dcb->cur_tccfg, &dcb->new_tccfg,
		       sizeof(dcb->cur_tccfg));
	}

	mce_dcb_update_hwetscfg(dcb);

	pfccfg = &dcb->new_pfccfg;

	pfc_default_flag = is_default_pfccfg(pfccfg);
	if (pfc_default_flag)
		clear_bit(MCE_PFC_EN, dcb->flags);
	else
		set_bit(MCE_PFC_EN, dcb->flags);

	mce_dcb_update_swpfccfg(dcb);

	if (test_bit(MCE_PFC_EN, dcb->flags) || pfc_default_flag) {
		memcpy(&dcb->cur_pfccfg, pfccfg,
		       sizeof(dcb->cur_pfccfg));
		memcpy(&dcb->cur_tccfg, &dcb->new_tccfg,
		       sizeof(dcb->cur_tccfg));
	}

	mce_dcb_update_hwpfccfg(dcb);

	/* if ets or pfc open we should update tc info */
	/* others close it */
	if (test_bit(MCE_ETS_EN, dcb->flags) || test_bit(MCE_PFC_EN, dcb->flags)) {
		/* update me later */
		/* now fixed */
		tccfg->ntc_cnt = MCE_MAX_TC_CNT;
	} else {
		tccfg->ntc_cnt = 0;
	}

	mce_vsi_cfg_netdev_tc(vsi, dcb);
out:
	mutex_unlock(&dcb->dcb_mutex);
	return (err != MCE_DCB_HW_CHG_RST) ? MCE_DCB_NO_HW_CHG : err;
}

/**
 * mce_dcbnl_get_cap - Get DCBX capabilities of adapter
 * @netdev: pointer to netdev struct
 * @capid: the capability type
 * @cap: the capability value
 * Returns: The result of the operation.
 */
static u8 mce_dcbnl_get_cap(struct net_device *netdev,
			    int capid, u8 *cap)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;
	u8 ret = 0;

	switch (capid) {
	case DCB_CAP_ATTR_PG:
		*cap = true;
		break;
	case DCB_CAP_ATTR_PFC:
		*cap = true;
		break;
	case DCB_CAP_ATTR_UP2TC:
		*cap = false;
		break;
	case DCB_CAP_ATTR_PG_TCS:
		*cap = 1 << (MCE_MAX_TC_CNT - 1);
		break;
	case DCB_CAP_ATTR_PFC_TCS:
		*cap = 1 << (MCE_MAX_TC_CNT - 1);
		break;
	case DCB_CAP_ATTR_GSP:
		*cap = false;
		break;
	case DCB_CAP_ATTR_BCN:
		*cap = false;
		break;
	case DCB_CAP_ATTR_DCBX:
		*cap = dcb->dcbx_cap;
		break;
	default:
		*cap = false;
		ret = 1;
		break;
	}

	netdev_dbg(netdev, "DCBX Get Capability cap=%d capval=0x%x\n",
		   capid, *cap);
	return ret;
}

/**
 * mce_dcbnl_setnumtcs - Get max number of traffic classes supported
 * @netdev: pointer to netdev struct
 * @tcid: TC ID
 * @num: total number of TCs supported by the adapter
 *
 * Return: the total number of TCs supported
 */
static int mce_dcbnl_setnumtcs(struct net_device *netdev,
			       int __always_unused tcid, u8 num)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;

	if (test_bit(MCE_VSI_DOWN, vsi->state))
		return 0;

	if (!test_bit(MCE_DCB_EN, dcb->flags))
		return -EOPNOTSUPP;

	/* if dcb tools control, just return */
	if (test_bit(MCE_FLAG_DCB_TOOLS, dcb->flags))
		return -EINVAL;

	return 0;
}

/**
 * mce_dcbnl_getnumtcs - Get max number of traffic classes supported
 * @netdev: pointer to netdev struct
 * @tcid: TC ID
 * @num: total number of TCs supported by the adapter
 *
 * Return: the total number of TCs supported
 */
static int mce_dcbnl_getnumtcs(struct net_device *netdev,
			       int __always_unused tcid, u8 *num)
{
/*  */
/*  */

	*num = MCE_MAX_TC_CNT;
	return 0;
}

/**
 * mce_dcbnl_getapp - get CEE APP
 * @netdev: pointer to netdev struct
 * @idtype: the App selector
 * @id: the App ethtype or port number
 * Returns: The result of the operation.
 */
static int mce_dcbnl_getapp(struct net_device *netdev, u8 idtype, u16 id)
{
	struct dcb_app app = {
		.selector = idtype,
		.protocol = id,
	};
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;

	if (!test_bit(MCE_DCB_EN, dcb->flags))
		return -EOPNOTSUPP;

	if (test_bit(MCE_FLAG_DCB_TOOLS, dcb->flags))
		return -EINVAL;

	if (!(dcb->dcbx_cap & DCB_CAP_DCBX_VER_CEE))
		return -EINVAL;

	return dcb_getapp(netdev, &app);
}

/**
 * mce_dcbnl_getpfcstate - get CEE PFC mode
 * @netdev: pointer to netdev struct
 * Returns: The result of the operation.
 */
static u8 mce_dcbnl_getpfcstate(struct net_device *netdev)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;

	/* Return enabled if any UP enabled for PFC */
	if (dcb->cur_pfccfg.pfcena)
		return 1;

	return 0;
}

/**
 * mce_dcbnl_getdcbx - retrieve current DCBX capability
 * @netdev: pointer to the netdev struct
 * Returns: The result of the operation.
 */
static u8 mce_dcbnl_getdcbx(struct net_device *netdev)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;

	if (!test_bit(MCE_DCB_EN, dcb->flags))
		return 0;

	netdev_dbg(netdev, "Get DCBx mode = 0x%x\n", dcb->dcbx_cap);

	return dcb->dcbx_cap;
}

/**
 * mce_dcbnl_setdcbx - set required DCBX capability
 * @netdev: the corresponding netdev
 * @mode: required mode
 * Returns: The result of the operation.
 */
static u8 mce_dcbnl_setdcbx(struct net_device *netdev, u8 mode)
{
	struct mce_netdev_priv *np = netdev_priv(netdev);
	struct mce_vsi *vsi = np->vsi;
	struct mce_pf *pf = vsi->back;
	struct mce_dcb *dcb = pf->dcb;

	if (test_bit(MCE_FLAG_DCB_TOOLS, dcb->flags))
		return MCE_DCB_NO_HW_CHG;

	/* No support for LLD_MANAGED modes */
	if ((mode & DCB_CAP_DCBX_LLD_MANAGED) ||
	    ((mode & DCB_CAP_DCBX_VER_IEEE) &&
	     (mode & DCB_CAP_DCBX_VER_CEE)) ||
	    !(mode & DCB_CAP_DCBX_HOST))
		return MCE_DCB_NO_HW_CHG;

	/* Already set to the given mode no change */
	if (mode == dcb->dcbx_cap)
		return MCE_DCB_NO_HW_CHG;

	dcb->dcbx_cap = mode;

	netdev_dbg(netdev, "Set DCBx mode = 0x%x\n", dcb->dcbx_cap);

	return MCE_DCB_HW_CHG_RST;
}

static const struct dcbnl_rtnl_ops dcbnl_ops = {
	/* IEEE 802.1Qaz std */
	.ieee_getets = mce_dcbnl_getets,
	.ieee_setets = mce_dcbnl_setets,
	.ieee_getpfc = mce_dcbnl_getpfc,
	.ieee_setpfc = mce_dcbnl_setpfc,
	.ieee_setapp = mce_dcbnl_setapp,
	.ieee_delapp = mce_dcbnl_delapp,

	/* CEE std */
	.getstate = mce_dcbnl_getstate,
	.setstate = mce_dcbnl_setstate,
	.getpermhwaddr = mce_dcbnl_get_perm_hw_addr,
	.getpgtccfgtx  = mce_dcbnl_get_pg_tc_cfg_tx,
	.setpgtccfgtx  = mce_dcbnl_set_pg_tc_cfg_tx,
	.getpgbwgcfgtx = mce_dcbnl_get_pg_bwg_cfg_tx,
	.setpgbwgcfgtx = mce_dcbnl_set_pg_bwg_cfg_tx,
	.getpgtccfgrx  = mce_dcbnl_get_pg_tc_cfg_rx,
	.setpgtccfgrx  = mce_dcbnl_set_pg_tc_cfg_rx,
	.getpgbwgcfgrx = mce_dcbnl_get_pg_bwg_cfg_rx,
	.setpgbwgcfgrx = mce_dcbnl_set_pg_bwg_cfg_rx,
	.getpfccfg = mce_dcbnl_get_pfc_cfg,
	.setpfccfg = mce_dcbnl_set_pfc_cfg,
	.setall = mce_dcbnl_cee_set_all,
	.getcap = mce_dcbnl_get_cap,
	.getapp = mce_dcbnl_getapp,
	.getnumtcs = mce_dcbnl_getnumtcs,
	.setnumtcs = mce_dcbnl_setnumtcs,
	.getpfcstate = mce_dcbnl_getpfcstate,

	/* DCBX configuration */
	.getdcbx = mce_dcbnl_getdcbx,
	.setdcbx = mce_dcbnl_setdcbx,
};

void mce_set_dcbnl_ops(struct net_device *netdev)
{
	netdev->dcbnl_ops = &dcbnl_ops;
}

enum {
	INIT,
	DELETE,
};

static void mce_dcbnl_dscp_app(struct mce_dcb *dcb,
			       struct net_device *netdev,
			       int action)
{
	struct dcb_app temp;
	unsigned int i;

	if (!netdev)
		return;

	temp.selector = IEEE_8021QAZ_APP_SEL_DSCP;
	for (i = 0; i < MCE_MAX_DSCP; i++) {
		temp.protocol = i;
		temp.priority = dcb->dscp_map[i];
		if (action == INIT)
			dcb_ieee_setapp(netdev, &temp);
		else
			dcb_ieee_delapp(netdev, &temp);
	}
}

void mce_dcbnl_set_app(struct mce_dcb *dcb, struct net_device *netdev)
{
	mce_dcbnl_dscp_app(dcb, netdev, INIT);
}

void mce_dcbnl_del_app(struct mce_dcb *dcb, struct net_device *netdev)
{
	mce_dcbnl_dscp_app(dcb, netdev, DELETE);
}

void mce_recover_dcb(struct mce_pf *pf)
{
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct net_device *netdev = vsi->netdev;
	const struct dcbnl_rtnl_ops *dcbnl_ops = netdev->dcbnl_ops;
	struct mce_dcb *dcb = pf->dcb;
	struct mce_pfc_cfg *pfccfg_bk = &dcb->backup_pfccfg;
	struct mce_pfc_cfg *pfccfg = &dcb->cur_pfccfg;
	struct mce_hw *hw = &pf->hw;
	int dcb_tools = 0;
	int i;
	/* try to recover if not default pfc or ets */

	if (!dcb->dcb_state_old)
		return;

	if (!netif_running(vsi->netdev))
		return;

	if (!test_bit(MCE_DCB_EN, dcb->flags)) {
		rtnl_lock();
		dcbnl_ops->setstate(netdev, 1);
		rtnl_unlock();
	}

	if (test_bit(MCE_FLAG_DCB_TOOLS, dcb->flags)) {
		clear_bit(MCE_FLAG_DCB_TOOLS, dcb->flags);
		dcb_tools = 1;
	}

	netdev->dcbnl_ops->ieee_setpfc(netdev, &dcb->pfc_os);

	/* try to backup rx buffer setup */
	for (i = 0; i < MCE_MAX_PRIORITY; i++) {
		pfccfg->fifo_head[i] = pfccfg_bk->fifo_head[i];
		pfccfg->fifo_tail[i] = pfccfg_bk->fifo_tail[i];
		pfccfg->fifo_depth[i] = pfccfg_bk->fifo_depth[i];
		pfccfg->rx_pri2buf[i] = pfccfg_bk->rx_pri2buf[i];
	}
	hw->ops->setup_rx_buffer(hw);

	if (dcb_tools)
		set_bit(MCE_FLAG_DCB_TOOLS, dcb->flags);
	/* mabye should echo vf */
	mce_reset_vf(netdev);
}

void mce_force_close_dcb(struct mce_pf *pf)
{
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct mce_dcb *dcb = pf->dcb;

	if (!dcb)
		return;
	if (test_bit(MCE_DCB_EN, dcb->flags)) {
		clear_bit(MCE_DCB_EN, dcb->flags);
		mce_dcb_tc_default(&dcb->cur_tccfg);
		mce_dcb_tc_default(&dcb->new_tccfg);
		mce_dcbnl_del_app(dcb, vsi->netdev);
		if (test_bit(MCE_PFC_EN, dcb->flags)) {
			clear_bit(MCE_PFC_EN, dcb->flags);
			/* backup rx buffer setup */
			/* we close pfc, should recover pause */
			pf->fc.req_mode = pf->fc.old_mode;
				memcpy(&dcb->backup_pfccfg, &dcb->cur_pfccfg,
				       sizeof(struct mce_pfc_cfg));
			mce_dcb_pfc_default(&dcb->cur_pfccfg);
			mce_dcb_pfc_default(&dcb->new_pfccfg);
			mce_dcb_update_hwpfccfg(dcb);
		}
		if (test_bit(MCE_ETS_EN, dcb->flags)) {
			clear_bit(MCE_ETS_EN, dcb->flags);
			mce_dcb_update_hwetscfg(dcb);
			mce_dcb_ets_default(&dcb->cur_etscfg);
			mce_dcb_ets_default(&dcb->new_etscfg);
		}
		/* record status before */
		dcb->dcb_state_old = 1;
	} else {
		dcb->dcb_state_old = 0;
	}
}
