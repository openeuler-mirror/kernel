// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse_virtchnl.h"
#include "nse_vf_lib_private.h"
#include "nse.h"
#include "nse_base.h"
#include "nse_lib.h"
#include "nse_fltr.h"
#include "nse_virtchnl_allowlist.h"
#include "nse_vf_vsi_vlan_ops.h"
#include "nse_vlan.h"
#include "nse_dcb_lib.h"

/**
 * nse_vc_vf_broadcast - Broadcast a message to all VFs on PF
 * @pf: pointer to the PF structure
 * @v_opcode: operation code
 * @v_retval: return value
 * @msg: pointer to the msg buffer
 * @msglen: msg length
 */
void
nse_vc_vf_broadcast(struct nse_pf *pf, enum virtchnl_ops v_opcode,
		    enum virtchnl_status_code v_retval, u8 *msg, u16 msglen)
{
	struct nse_hw *hw = &pf->hw;
	struct nse_vf *vf;
	unsigned int bkt;

	mutex_lock(&pf->vfs.table_lock);
	nse_for_each_vf(pf, bkt, vf) {
		/* Not all vfs are enabled so skip the ones that are not */
		if (!test_bit(NSE_VF_STATE_INIT, vf->vf_states) &&
		    !test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states))
			continue;

		/* Ignore return value on purpose - a given VF may fail, but
		 * we need to keep going and send to all of them
		 */
		if (vf->use_pv_msgbox)
			(void)nse_msgbox_p2v_send_msg_to_vf(hw, vf->vf_vsi_abs_id,
										v_opcode, v_retval,
											msg,
											msglen);
		else
			(void)nse_aq_send_msg_to_vf(hw, vf->vf_vsi_abs_id,
										v_opcode, v_retval,
											msg, msglen,
											NULL);
	}
	mutex_unlock(&pf->vfs.table_lock);
}

/**
 * nse_set_pfe_link - Set the link speed/status of the virtchnl_pf_event
 * @vf: pointer to the VF structure
 * @pfe: pointer to the virtchnl_pf_event to set link speed/status for
 * @nse_link_speed: link speed specified by ICE_AQ_LINK_SPEED_*
 * @link_up: whether or not to set the link up/down
 */
static void
nse_set_pfe_link(struct nse_vf *vf, struct virtchnl_pf_event *pfe,
		 int link_speed, bool link_up, bool force)
{
	struct nse_hw *hw = &vf->pf->hw;

	if (vf->driver_caps & VIRTCHNL_VF_CAP_ADV_LINK_SPEED) {
		pfe->event_data.link_event_adv.link_status = link_up;
		/* Speed in Mbps */
		pfe->event_data.link_event_adv.link_speed =
			nse_conv_link_speed_to_virtchnl(hw, true, link_speed);

		if (force)
			pfe->event_data.link_event_adv.flags |= VIRTCHNL_LINK_EVENT_FLAG_FORCE_UPDATE;
	} else {
		pfe->event_data.link_event.link_status = link_up;
		/* Legacy method for virtchnl link speeds */
		pfe->event_data.link_event.link_speed =
			(enum virtchnl_link_speed)
			nse_conv_link_speed_to_virtchnl(hw, false, link_speed);

		if (force)
			pfe->event_data.link_event.flags |= VIRTCHNL_LINK_EVENT_FLAG_FORCE_UPDATE;
	}
}

/**
 * nse_vc_notify_reset - Send pending reset message to all VFs
 * @pf: pointer to the PF structure
 *
 * indicate a pending reset to all VFs on a given PF
 */
void nse_vc_notify_reset(struct nse_pf *pf, enum nse_reset_req reset_type)
{
	struct virtchnl_pf_event pfe;

	if (!nse_has_vfs(pf))
		return;

	pfe.event = VIRTCHNL_EVENT_RESET_IMPENDING;
	pfe.severity = PF_EVENT_SEVERITY_CERTAIN_DOOM;
	pfe.event_data.reset_event.reset_type = reset_type;

	nse_debug(&pf->hw, NSE_DBG_SYS, "[%s] vf_broadcast(EVENT_RESET_IMPENDING)\n", __func__);

	nse_vc_vf_broadcast(pf, VIRTCHNL_OP_EVENT, VIRTCHNL_STATUS_SUCCESS,
			    (u8 *)&pfe, sizeof(struct virtchnl_pf_event));
}

/**
 * nse_vc_notify_vf_link_state - Inform a VF of link status
 * @vf: pointer to the VF structure
 *
 * send a link status message to a single VF
 */
void nse_vc_notify_vf_link_state(struct nse_vf *vf, bool force)
{
	struct virtchnl_pf_event pfe = { 0 };
	struct nse_hw *hw = &vf->pf->hw;
	struct nse_port_info *pi;
	int link_speed;

	pi = nse_vf_get_port_info(vf);

	pfe.event = VIRTCHNL_EVENT_LINK_CHANGE;
	pfe.severity = PF_EVENT_SEVERITY_INFO;

	if (nse_is_vf_link_up(vf)) {
		link_speed = pi->lmac_phy_info.link_info.link_speed;

		nse_set_pfe_link(vf, &pfe, link_speed, true, force);

	} else
		nse_set_pfe_link(vf, &pfe, NSE_AQ_LINK_SPEED_UNKNOWN, false, force);

	if (vf->use_pv_msgbox)
		(void)nse_msgbox_p2v_send_msg_to_vf(hw, vf->vf_vsi_abs_id, VIRTCHNL_OP_EVENT,
			      VIRTCHNL_STATUS_SUCCESS, (u8 *)&pfe, sizeof(pfe));
	else
		(void)nse_aq_send_msg_to_vf(hw, vf->vf_vsi_abs_id, VIRTCHNL_OP_EVENT,
			      VIRTCHNL_STATUS_SUCCESS, (u8 *)&pfe, sizeof(pfe), NULL);
}

/**
 * nse_vc_notify_link_state - Inform all VFs on a PF of link status
 * @pf: pointer to the PF structure
 */
void nse_vc_notify_link_state(struct nse_pf *pf, bool force)
{
	struct nse_vf *vf;
	unsigned int bkt;

	mutex_lock(&pf->vfs.table_lock);
	nse_for_each_vf(pf, bkt, vf)
		nse_vc_notify_vf_link_state(vf, force);
	mutex_unlock(&pf->vfs.table_lock);
}

/**
 * nse_vc_send_msg_to_vf - Send message to VF
 * @vf: pointer to the VF info
 * @v_opcode: virtual channel opcode
 * @v_retval: virtual channel return value
 * @msg: pointer to the msg buffer
 * @msglen: msg length
 *
 * send msg to VF
 */
int
nse_vc_send_msg_to_vf(struct nse_vf *vf, u32 v_opcode,
		      enum virtchnl_status_code v_retval, u8 *msg, u16 msglen)
{
	enum nse_status aq_ret;
	struct nse_pf *pf = vf->pf;
	struct device *dev = nse_pf_to_dev(pf);

	if (vf->use_pv_msgbox)
		aq_ret = nse_msgbox_p2v_send_msg_to_vf(&pf->hw, vf->vf_vsi_abs_id,
							v_opcode, v_retval, msg, msglen);
	else
		aq_ret = nse_aq_send_msg_to_vf(&pf->hw, vf->vf_vsi_abs_id,
							v_opcode, v_retval, msg, msglen, NULL);

	if (aq_ret && pf->hw.adminq.sq_last_status != NSE_AQ_RC_ENOENT) {
		dev_info(dev, "Unable to send the message to VF(vf_id=%d, vf_vsi_abs_id=%d) --- status(%s), aq_err(%s)\n",
			 vf->vf_id, vf->vf_vsi_abs_id,
			 nse_stat_str(aq_ret),
			 nse_aq_str(pf->hw.adminq.sq_last_status));
		return -EIO;
	}

	return 0;
}

/**
 * nse_vc_get_ver_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * called from the VF to request the API version used by the PF
 */
static int nse_vc_get_ver_msg(struct nse_vf *vf, u8 *msg)
{
	struct virtchnl_version_info info = {
		VIRTCHNL_VERSION_MAJOR, VIRTCHNL_VERSION_MINOR
	};

	vf->vf_ver = *(struct virtchnl_version_info *)msg;

	return nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_VERSION,
				     VIRTCHNL_STATUS_SUCCESS, (u8 *)&info,
				     sizeof(struct virtchnl_version_info));
}

/**
 * nse_vc_get_max_frame_size - get max frame size allowed for VF
 * @vf: VF used to determine max frame size
 *
 * Max frame size is determined based on the current port's max frame size and
 * whether a port VLAN is configured on this VF. The VF is not aware whether
 * it's in a port VLAN so the PF needs to account for this in max frame size
 * checks and sending the max frame size to the VF.
 */
static u16 nse_vc_get_max_mtu(struct nse_vf *vf)
{
	return NSE_MAX_MTU;
}

static u16 nse_vc_get_max_frame_size(struct nse_vf *vf)
{
	return NSE_AQ_SET_MAC_FRAME_SIZE_MAX;
}

/**
 * nse_vc_get_vlan_caps
 * @hw: pointer to the hw
 * @vf: pointer to the VF info
 * @vsi: pointer to the VSI
 * @driver_caps: current driver caps
 *
 * Return 0 if there is no VLAN caps supported, or VLAN caps value
 */
static u32
nse_vc_get_vlan_caps(struct nse_hw *hw, struct nse_vf *vf, struct nse_vsi *vsi,
		     u32 driver_caps)
{
	if (nse_is_eswitch_mode_switchdev(vf->pf))
		/* In switchdev setting VLAN from VF isn't supported */
		return 0;

	if (driver_caps & VIRTCHNL_VF_OFFLOAD_VLAN_V2) {
		/* VLAN offloads based on current device configuration */
		return VIRTCHNL_VF_OFFLOAD_VLAN_V2;
	}

	return 0;
}

/**
 * nse_vc_get_vf_res_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * called from the VF to request its resources
 */
static int nse_vc_get_vf_res_msg(struct nse_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_vf_resource *vfres = NULL;
	struct nse_pf *pf = vf->pf;
	struct nse_hw *hw = &pf->hw;
	struct nse_vsi *vsi;
	struct nse_fdir_cb *cb = &hw->fdir_cb;
	int len = 0;
	int ret;

	if (nse_check_vf_init(vf)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	len = sizeof(struct virtchnl_vf_resource);

	vfres = kzalloc(len, GFP_KERNEL);
	if (!vfres) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		len = 0;
		goto err;
	}

	vf->driver_req_caps = *(u64 *)msg;
	vf->driver_caps = *(u64 *)msg;

	vfres->platform_info = hw->hw_conf.hw_platform;

	vfres->pf_id = hw->pcore_pf_id;
	vfres->lan_channel_pf_id = hw->chan_pf_id;

	vfres->vf_cap_flags = VIRTCHNL_VF_OFFLOAD_L2;
	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	vfres->vf_cap_flags |= nse_vc_get_vlan_caps(hw, vf, vsi,
						    vf->driver_caps);

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RSS_PF)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_RSS_PF;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_TSO) {
		if (pf->tso_hsb_usable) {
			vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_TSO;

			if ((vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ENCAP_TSO) &&
				nse_is_hw_static_fea_set(hw,
							 NSE_HW_STATIC_FEA_TDM_SUPPORT_TNL_TSO)) {
				vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_ENCAP_TSO;
			}
		}
	}

	if ((vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ENCAP_CSUM) &&
		nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_TDM_SUPPORT_TNL_CSUM))
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_ENCAP_CSUM;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RX_POLLING)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_RX_POLLING;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_WB_ON_ITR)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_WB_ON_ITR;

	if (nse_bypass_switch && (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_BYPASS_SWITCH))
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_BYPASS_SWITCH;

	if (vsi->sw_conf.lan_tx_use_cq) {
		vf->driver_caps |= VIRTCHNL_VF_CAP_LAN_TX_USE_CQ;

		vfres->vf_cap_flags |= VIRTCHNL_VF_CAP_LAN_TX_USE_CQ;

		vfres->lan_txcq_base_abs_id = vsi->vsi_txcq_space_start + pf->lan_txcq_space_start;
		vfres->lan_txcq_num = vsi->alloc_txcq;	//= pf->vfs.num_txcq_per
		vfres->lan_txcq_initial_hw_gen = nse_lan_txcq_initial_hw_gen;
	}

	vfres->max_lan_vectors = pf->vfs.max_lan_msix_per;

	if (pf->sw_conf.lan_rx_ena_rsc &&
		(vf->driver_caps & VIRTCHNL_VF_CAP_LAN_RX_USE_RSC)) {
		vfres->vf_cap_flags |= VIRTCHNL_VF_CAP_LAN_RX_USE_RSC;

		vsi->sw_conf.lan_rx_ena_rsc = true;
	} else {
		vsi->sw_conf.lan_rx_ena_rsc = false;
	}

	if (vf->driver_caps & VIRTCHNL_VF_CAP_ADV_LINK_SPEED)
		vfres->vf_cap_flags |= VIRTCHNL_VF_CAP_ADV_LINK_SPEED;

	if (vf->driver_caps & VIRTCHNL_VF_CAP_FDIR) {
		if (vsi->sw_conf.fdir_ena) {
			vfres->vf_cap_flags |= VIRTCHNL_VF_CAP_FDIR;
			vfres->fdir_mode = cb->mode;
			vfres->fdir_hkey = cb->setting.fdir_hkey;
			vfres->fdir_skey = cb->setting.fdir_skey;
			vfres->fdir_drp_rxq_abs_id = cb->drp_rxq_rel_id + pf->lan_rxq_space_start;
			vfres->fdir_max_num_pfilter = vsi->sw_conf.fdir_max_num_pfilter_vsi;
			vfres->fdir_max_num_sfilter = vsi->sw_conf.fdir_max_num_sfilter_vsi;
		}
	}

	if ((vf->driver_caps & VIRTCHNL_VF_CAP_LOGALL) &&
		nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_MISC_SUPPORT_VIRTIO)) {
		vfres->vf_cap_flags |= VIRTCHNL_VF_CAP_LOGALL;
	}

	if (vf->driver_caps & VIRTCHNL_VF_CAP_RDMA &&
	    vf->vf_ops->cfg_rdma_irq_map && vf->vf_ops->clear_rdma_irq_map &&
	    nse_chk_rdma_cap(pf) && nse_is_rdma_aux_loaded(pf))
		vfres->vf_cap_flags |= VIRTCHNL_VF_CAP_RDMA;

	vfres->num_vsis = 1;
	/* Tx and Rx queue are equal for VF */
	vfres->num_queue_pairs = pf->vfs.num_qps_per;
	vfres->max_vectors = pf->vfs.num_msix_per;

	vfres->lan_rxq_base_abs_id = vsi->vsi_rxq_space_start + pf->lan_rxq_space_start;

	vfres->rss_key_size = NSE_RSS_KEY_SIZE;
	vfres->rss_lut_size = vsi->rss_lut_size_aligned;
	vfres->rss_ctl_alg = vsi->rss_ctl_user_req_alg;
	vfres->rss_hash_alg = 0;	/* not used for now */

	vfres->max_mtu = nse_vc_get_max_mtu(vf);

	vfres->vsi_res.vsi_abs_id = vf->vf_vsi_abs_id;
	vfres->vsi_res.vsi_rel_id = vf->vf_vsi_rel_id;
	vfres->vsi_res.vsi_type = VIRTCHNL_VSI_SRIOV;
	vfres->vsi_res.vsi_mode = vsi->vsi_mode;
	vfres->vsi_res.num_queue_pairs = pf->vfs.num_qps_per;
	ether_addr_copy(vfres->vsi_res.default_mac_addr,
			vf->hw_lan_addr.addr);

	/* match guest capabilities */
	vf->driver_caps = vfres->vf_cap_flags;

	nse_vc_set_caps_allowlist(vf);
	nse_vc_set_working_allowlist(vf);

	set_bit(NSE_VF_STATE_ACTIVE, vf->vf_states);

err:
	/* send the response back to the VF */
	ret = nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_GET_VF_RESOURCES, v_ret,
				    (u8 *)vfres, len);

	kfree(vfres);
	return ret;
}

/**
 * nse_vc_reset_vf_msg
 * @vf: pointer to the VF info
 *
 * called from the VF to reset itself,
 * unlike other virtchnl messages, PF driver
 * doesn't send the response back to the VF
 */
static void nse_vc_reset_vf_msg(struct nse_vf *vf)
{
	struct nse_pf *pf = vf->pf;
	struct nse_hw *hw = &pf->hw;

	nse_debug(hw, NSE_DBG_SYS, "[%s] receive vch-req(OP_RESET_VF) from my VF (rel_id=%d, abs_id=%d), vsi(rel_id=%d, abs_id=%d)\n",
								__func__,
								vf->vf_id, nse_abs_vf_id(hw,
											 vf->vf_id),
								vf->vf_vsi_rel_id,
									vf->vf_vsi_abs_id);

	if (test_bit(NSE_VF_STATE_INIT, vf->vf_states))
		nse_reset_vf(vf, 0);
}

static void nse_vc_reset_vf_rdma_msg(struct nse_vf *vf)
{
	struct nse_pf *pf = vf->pf;
	struct nse_hw *hw = &pf->hw;
	enum nse_status status;

	nse_debug(hw, NSE_DBG_RDMA, "[%s] receive vch-req(OP_RESET_VF_RDMA) from my VF (rel_id=%d, abs_id=%d), vsi(rel_id=%d, abs_id=%d)\n",
								__func__,
								vf->vf_id, nse_abs_vf_id(hw,
											 vf->vf_id),
								vf->vf_vsi_rel_id,
									vf->vf_vsi_abs_id);

	if (!test_bit(NSE_VF_STATE_INIT, vf->vf_states)) {
		nse_debug(hw, NSE_DBG_RDMA,
			  "[%s] return early because VF_STATE_INIT=false\n", __func__);
		return;
	}

	lockdep_assert_held(&vf->cfg_lock);

	nse_send_vf_reset_to_aux(pf, nse_find_cdev_info_by_id(pf, IIDC_RDMA_ID),
				 nse_abs_vf_id(hw, vf->vf_id));

	nse_debug(hw, NSE_DBG_RDMA,
		  "[%s] send_vf_reset_to_aux(IIDC_EVENT_VF_RESET) - done\n", __func__);

	nse_debug(hw, NSE_DBG_RDMA, "[%s] aq_request_reset_rdma() - begin\n", __func__);

	status = nse_aq_request_reset_rdma(hw, true, vf->vf_vsi_abs_id);

	nse_debug(hw, NSE_DBG_RDMA, "[%s] aq_request_reset_rdma() - done, status=%d\n",
		  __func__, status);
}

/**
 * nse_vc_isvalid_vsi_id
 * @vf: pointer to the VF info
 * @vsi_id: VF relative VSI ID
 *
 * check for the valid VSI ID
 */
bool nse_vc_isvalid_vsi_abs_id(struct nse_vf *vf, u16 vsi_abs_id)
{
	struct nse_pf *pf = vf->pf;
	struct nse_vsi *vsi;

	vsi = nse_find_vsi_by_abs_id(pf, vsi_abs_id);

	return (vsi && vsi->vf == vf);
}

bool nse_vc_isvalid_vsi_rel_id(struct nse_vf *vf, u16 vsi_rel_id)
{
	struct nse_pf *pf = vf->pf;
	struct nse_vsi *vsi;

	vsi = nse_find_vsi_by_rel_id(pf, vsi_rel_id);

	return (vsi && vsi->vf == vf);
}

/**
 * nse_vc_isvalid_q_id
 * @vf: pointer to the VF info
 * @vsi_id: VSI ID
 * @qid: VSI relative queue ID
 *
 * check for the valid queue ID
 */
static bool nse_vc_isvalid_q_id(struct nse_vf *vf, u16 vsi_rel_id, u8 qid)
{
	struct nse_vsi *vsi = nse_find_vsi_by_rel_id(vf->pf, vsi_rel_id);
	/* allocated Tx and Rx queues should be always equal for VF VSI */
	return (vsi && (qid < vsi->alloc_txq));
}

static bool nse_vc_isvalid_txcq_id(struct nse_vf *vf, u16 vsi_rel_id, u8 qid)
{
	struct nse_vsi *vsi = nse_find_vsi_by_rel_id(vf->pf, vsi_rel_id);
	/* allocated Tx and Rx queues should be always equal for VF VSI */
	return (vsi && (qid < vsi->alloc_txcq));
}

/**
 * nse_vc_isvalid_ring_len
 * @ring_len: length of ring
 *
 * check for the valid ring count, should be multiple of NSE_REQ_DESC_MULTIPLE
 * or zero
 */
static bool nse_vc_isvalid_ring_len(u16 ring_len)
{
	return ring_len == 0 ||
	       (ring_len >= NSE_MIN_NUM_DESC &&
		ring_len <= NSE_MAX_NUM_DESC &&
		!(ring_len % NSE_REQ_DESC_MULTIPLE));
}

static bool nse_vc_isvalid_txcq_ring_len(u32 ring_len)	/* use u32 instead of u16 */
{
	if (!ring_len)
		return false;

	if (ring_len > NSE_DFLT_NUM_CQ_DESC)
		return false;

	if (ring_len % LAN_TXCQ_QLEN_MULTIPLE)
		return false;

	return true;
}

/**
 * nse_vc_config_rss_key
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * Configure the VF's RSS key
 */
static int nse_vc_config_rss_key(struct nse_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_rss_key *vrk =
		(struct virtchnl_rss_key *)msg;
	struct nse_vsi *vsi;

	if (!test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!nse_vc_isvalid_vsi_abs_id(vf, vrk->vsi_abs_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (vrk->key_len != NSE_RSS_KEY_SIZE) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!test_bit(NSE_FLAG_RSS_CAPABLE, vf->pf->flags)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (nse_set_rss_key(vsi, vrk->key))
		v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
error_param:
	return nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_RSS_KEY, v_ret,
				     NULL, 0);
}

/**
 * nse_vc_config_rss_lut
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * Configure the VF's RSS LUT
 */
static int nse_vc_config_rss_lut(struct nse_vf *vf, u8 *msg)
{
	struct virtchnl_rss_lut *vrl = (struct virtchnl_rss_lut *)msg;
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct nse_vsi *vsi;
	struct nse_pf *pf = vf->pf;
	struct device *dev = nse_pf_to_dev(pf);

	if (!test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!nse_vc_isvalid_vsi_abs_id(vf, vrl->vsi_abs_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (vrl->lut_entries != vsi->rss_lut_size_aligned) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!test_bit(NSE_FLAG_RSS_CAPABLE, vf->pf->flags)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!vsi->rss_lut_user)
		vsi->rss_lut_user = devm_kzalloc(dev, sizeof(u16) * vsi->rss_lut_size_aligned,
						 GFP_KERNEL);

	if (nse_set_rss_lut(vsi, vrl->lut, vrl->lut_entries))
		v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;

	if (!v_ret && vsi->rss_lut_user) {
		/* save VF input into rss_lut_user */
		memcpy(vsi->rss_lut_user, vrl->lut, sizeof(u16) * vsi->rss_lut_size_aligned);
	}

error_param:
	return nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_RSS_LUT, v_ret,
				     NULL, 0);
}

/* don't care about return value */
static void nse_vc_update_rss_lut(struct nse_vf *vf, struct nse_vsi *vsi)
{
	u16 *lut = NULL;
	int i, vf_qid, first_active_vf_qid;

	if (!bitmap_weight(vf->rxq_ena, NSE_MAX_QS_PER_VF))
		return;

	lut = kcalloc(vsi->rss_lut_size_aligned, sizeof(u16), GFP_KERNEL);
	if (!lut)
		return;

	if (vsi->rss_lut_user)
		memcpy(lut, vsi->rss_lut_user, sizeof(u16) * vsi->rss_lut_size_aligned);
	else
		nse_fill_rss_lut(lut, vsi->rss_lut_size_aligned, vsi->num_rxq);

	for (vf_qid = 0; vf_qid < NSE_MAX_QS_PER_VF; vf_qid++) {
		if (test_bit(vf_qid, vf->rxq_ena)) {
			first_active_vf_qid = vf_qid;
			break;
		}
	}

	for (i = 0; i < vsi->rss_lut_size_aligned; i++) {
		vf_qid = lut[i];

		/* The RXQ pointed by RSS LUT entry is not active.
		 *
		 * So overwrite this RSS LUT entry to be first_active_vf_qid
		 */
		if (!test_bit(vf_qid, vf->rxq_ena))
			lut[i] = first_active_vf_qid;
	}

	(void)nse_set_rss_lut(vsi, lut, vsi->rss_lut_size_aligned);

	kfree(lut);
}

static int nse_vc_config_rss_alg(struct nse_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_rss_alg *vra =
		(struct virtchnl_rss_alg *)msg;
	struct nse_vsi *vsi;
	u32 old_alg, new_alg;

	if (!test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!nse_vc_isvalid_vsi_abs_id(vf, vra->vsi_abs_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!test_bit(NSE_FLAG_RSS_CAPABLE, vf->pf->flags)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	old_alg = vsi->rss_ctl_user_req_alg;
	new_alg = vra->ctl_alg;

	if (new_alg != old_alg) {
		vsi->rss_ctl_user_req_alg = new_alg;

		if (nse_vsi_cfg_rss_ctl(vsi)) {
			vsi->rss_ctl_user_req_alg = old_alg;

			v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
		}
	}

error_param:
	return nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_RSS_ALG, v_ret,
				     NULL, 0);
}

static int nse_vc_set_fdir_input_mask(struct nse_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_fdir_input_mask *vfim =
		(struct virtchnl_fdir_input_mask *)msg;
	struct nse_vsi *vsi;
	struct nse_pf *pf = vf->pf;
	struct nse_hw *hw = &pf->hw;
	struct nse_aqc_fdir_get_set_vsi_input_mask *cmd_buf;
	enum nse_status status;

	if (!test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!nse_vc_isvalid_vsi_abs_id(vf, vfim->vsi_abs_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!pf->sw_conf.fdir_ena || !pf->sw_conf.fdir_ena_for_vf || !vsi->sw_conf.fdir_ena) {
		v_ret = VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
		goto error_param;
	}

	cmd_buf = kzalloc(sizeof(*cmd_buf), GFP_ATOMIC);
	if (!cmd_buf) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	cmd_buf->flex_cfg = vfim->flex_cfg;

	memcpy(cmd_buf->mask, vfim->mask, sizeof(cmd_buf->mask));

	status = nse_aq_fdir_set_vsi_input_mask(hw, vsi->vsi_abs_num, cmd_buf);
	if (status) {
		v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
		kfree(cmd_buf);
		goto error_param;
	}

	kfree(cmd_buf);

error_param:
	return nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_SET_FDIR_INPUT_MASK, v_ret,
				     NULL, 0);
}

static int nse_vc_set_logall(struct nse_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_logall_ctl *lga_ctl =
		(struct virtchnl_logall_ctl *)msg;
	struct nse_hw *hw = &vf->pf->hw;
	struct nse_pf *pf = vf->pf;
	struct device *dev = nse_pf_to_dev(pf);
	int timeout = 50, i;
	struct nse_aqc_set_logall *cmd_buf;
	enum nse_status status;

	if (!test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err_alloc_buf;
	}

	if (!nse_vc_isvalid_vsi_abs_id(vf, lga_ctl->vsi_abs_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err_alloc_buf;
	}

	cmd_buf = kzalloc(sizeof(*cmd_buf), GFP_ATOMIC);
	if (!cmd_buf) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		goto err_alloc_buf;
	}

	/* wait 50ms to get access */
	while (test_and_set_bit(NSE_LOGALL_INPROGRESS, pf->state)) {
		timeout--;
		if (!timeout) {
			v_ret = VIRTCHNL_STATUS_ERR_TIMEOUT;
			goto err_get_lock;
		}
		usleep_range(1000, 2000);
	}

	/* manage logall array */
	if (lga_ctl->bitmap_len != 0) {
		/* bitmap_len != 0, enable logall, add entry to array */
		/* check if exist available entry */
		for (i = 0; i < 8; i++) {
			/* cover entry if they share the same vsi id */
			if (hw->logall_ctl_array[i].vsi_id == lga_ctl->vsi_abs_id) {
				hw->logall_ctl_array[i].bitmap_addr = lga_ctl->bitmap_addr;
				hw->logall_ctl_array[i].bitmap_len = lga_ctl->bitmap_len;
				hw->logall_ctl_array[i].entry_sts = NSE_LOGALL_INFO_ENTRY_OCCUPIED;
				break;
			} else if (hw->logall_ctl_array[i].entry_sts == 0) {
				hw->logall_ctl_array[i].bitmap_addr = lga_ctl->bitmap_addr;
				hw->logall_ctl_array[i].bitmap_len = lga_ctl->bitmap_len;
				hw->logall_ctl_array[i].vsi_id = lga_ctl->vsi_abs_id;
				hw->logall_ctl_array[i].entry_sts = NSE_LOGALL_INFO_ENTRY_OCCUPIED;
				break;
			}
		}
		if (i == 8) {
			dev_info(dev, "VF %d is attempting to enable new entry to a full logall array\n",
				vf->vf_id);
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto out;
		}
	} else {
		/* bitmap_len == 0, disable logall, del entry from array */
		for (i = 0; i < 8; i++) {
			/* search entry */
			if (hw->logall_ctl_array[i].entry_sts == NSE_LOGALL_INFO_ENTRY_OCCUPIED) {
				if (hw->logall_ctl_array[i].vsi_id == lga_ctl->vsi_abs_id) {
					hw->logall_ctl_array[i].bitmap_addr = 0;
					hw->logall_ctl_array[i].bitmap_len = 0;
					hw->logall_ctl_array[i].vsi_id = 0;
					hw->logall_ctl_array[i].entry_sts = 0;
					break;
				}
			}
		}
		if (i == 8) {
			dev_info(dev, "VF %d is attempting to disable non-existed entry\n",
				vf->vf_id);
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto out;
		}
	}

	/* copy logall array to aqc cmd buf */
	for (i = 0; i < 8; i++) {
		if (hw->logall_ctl_array[i].entry_sts == NSE_LOGALL_INFO_ENTRY_OCCUPIED) {
			cmd_buf->lga_info[i].bitmap_addr = hw->logall_ctl_array[i].bitmap_addr;
			cmd_buf->lga_info[i].bitmap_len = hw->logall_ctl_array[i].bitmap_len;
			cmd_buf->lga_info[i].vsi_id = hw->logall_ctl_array[i].vsi_id;
			cmd_buf->lga_info[i].vsi_vld = 1;
			cmd_buf->lga_info[i].hm_vld = 1;
		}
		/* page_size set to default 4KB */
		cmd_buf->page_size = NSE_AQC_LOGALL_CTL_PAGE_SIZE_4KB;
		cmd_buf->req_type = 0xFFFFFFFF;
	}

	/* send adminq cmd to FW */
	status = nse_aqc_lan_set_logall(hw, cmd_buf);
	if (status) {
		v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
		goto out;
	}

out:
	clear_bit(NSE_LOGALL_INPROGRESS, pf->state);
err_get_lock:
	kfree(cmd_buf);
err_alloc_buf:
	return  nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_SET_LOGALL_BITMAP, v_ret,
				     NULL, 0);
}

/**
 * ice_vc_cfg_promiscuous_mode_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * called from the VF to configure VF VSIs promiscuous mode
 */
static int nse_vc_cfg_promiscuous_mode_msg(struct nse_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	bool rm_promisc, alluni = false, allmulti = false;
	struct virtchnl_promisc_info *info =
	    (struct virtchnl_promisc_info *)msg;
	struct nse_vsi_vlan_ops *vlan_ops;
	int mcast_err = 0, ucast_err = 0;
	struct nse_pf *pf = vf->pf;
	struct nse_vsi *vsi;
	u8 mcast_m, ucast_m;
	struct device *dev;
	int ret = 0;

	if (!test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!nse_vc_isvalid_vsi_rel_id(vf, info->vsi_rel_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	dev = nse_pf_to_dev(pf);
	if (!nse_is_vf_trusted(vf)) {
		dev_err(dev, "Unprivileged VF %d is attempting to configure promiscuous mode\n",
			vf->vf_id);
		/* Leave v_ret alone, lie to the VF on purpose. */
		goto error_param;
	}

	if (info->flags & FLAG_VF_UNICAST_PROMISC)
		alluni = true;

	if (info->flags & FLAG_VF_MULTICAST_PROMISC)
		allmulti = true;

	rm_promisc = !allmulti && !alluni;

	vlan_ops = nse_get_compat_vsi_vlan_ops(vsi);
	if (rm_promisc)
		ret = vlan_ops->ena_rx_filtering(vsi);
	else
		ret = vlan_ops->dis_rx_filtering(vsi);
	if (ret) {
		dev_err(dev, "Failed to configure VLAN pruning in promiscuous mode\n");
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	nse_vf_get_promisc_masks(vf, vsi, &ucast_m, &mcast_m);

	if (!test_bit(NSE_FLAG_VF_TRUE_PROMISC_ENA, pf->flags)) {
		if (alluni)
			ret = nse_set_dflt_vsi(vsi);
		else
			ret = nse_clear_dflt_vsi(vsi);

		/* in this case we're turning on/off only
		 * allmulticast
		 */
		if (allmulti)
			mcast_err = nse_vf_set_vsi_promisc(vf, vsi, mcast_m);
		else
			mcast_err = nse_vf_clear_vsi_promisc(vf, vsi, mcast_m);

		if (ret) {
			nse_dev_err_errno(dev, ret,
					  "Turning on/off promiscuous mode for VF %d failed",
					  vf->vf_id);
			v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
			goto error_param;
		}
	} else {
		if (alluni)
			ucast_err = nse_vf_set_vsi_promisc(vf, vsi, ucast_m);
		else
			ucast_err = nse_vf_clear_vsi_promisc(vf, vsi, ucast_m);

		if (allmulti)
			mcast_err = nse_vf_set_vsi_promisc(vf, vsi, mcast_m);
		else
			mcast_err = nse_vf_clear_vsi_promisc(vf, vsi, mcast_m);
	}

	if (!mcast_err) {
		if (allmulti &&
		    !test_and_set_bit(NSE_VF_STATE_MC_PROMISC, vf->vf_states))
			dev_info(dev, "VF %u successfully set multicast promiscuous mode\n",
				 vf->vf_id);
		else if (!allmulti &&
			 test_and_clear_bit(NSE_VF_STATE_MC_PROMISC,
					    vf->vf_states))
			dev_info(dev, "VF %u successfully unset multicast promiscuous mode\n",
				 vf->vf_id);
	} else {
		nse_dev_err_errno(dev, mcast_err,
				  "Error while modifying multicast promiscuous mode for VF %u",
				  vf->vf_id);
	}

	if (!ucast_err) {
		if (alluni &&
		    !test_and_set_bit(NSE_VF_STATE_UC_PROMISC, vf->vf_states))
			dev_info(dev, "VF %u successfully set unicast promiscuous mode\n",
				 vf->vf_id);
		else if (!alluni &&
			 test_and_clear_bit(NSE_VF_STATE_UC_PROMISC,
					    vf->vf_states))
			dev_info(dev, "VF %u successfully unset unicast promiscuous mode\n",
				 vf->vf_id);
	} else {
		nse_dev_err_errno(dev, ucast_err,
				  "Error while modifying unicast promiscuous mode for VF %u",
				  vf->vf_id);
	}

error_param:
	return nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE,
				     v_ret, NULL, 0);
}

/**
 * nse_vc_get_stats_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * called from the VF to get VSI stats
 */
static int nse_vc_get_stats_msg(struct nse_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_queue_select *vqs =
		(struct virtchnl_queue_select *)msg;
	struct nse_vsi *vsi;

	if (!test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!nse_vc_isvalid_vsi_rel_id(vf, vqs->vsi_rel_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	nse_update_vsi_hw_stats(vsi);

error_param:
	/* send the response to the VF */
	return nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_GET_STATS, v_ret,
				     (u8 *)&vsi->hw_stats, sizeof(vsi->hw_stats));
}

/**
 * nse_vf_q_id_get_vsi_q_id
 * @vf: pointer to the VF info
 * @vf_q_id: VF relative queue ID
 * @t_tc: traffic class for indexing the VSIs
 * @vqs: the VFs virtual queue selection
 * @vsi_p: pointer to VSI pointer, which changes based on TC for ADQ
 * @vsi_id: VSI ID specific to desired queue ID
 * @q_id: queue ID of the VSI
 *
 * provides ADQ queue enablement support by mapping the VF queue ID and TC to
 * VSI ID and queue ID. call while iterating through VF queue IDs, VF VSIs and
 * TCs.
 */
void nse_vf_q_id_get_vsi_q_id(struct nse_vf *vf, u16 vf_q_id, u16 *t_tc,
			      struct virtchnl_queue_select *vqs,
			      struct nse_vsi **vsi_p, u16 *vsi_rel_id,
			      u16 *q_id)
{
	struct nse_vsi *vsi = *vsi_p;
	u16 tc = *t_tc;

		*vsi_rel_id = vqs->vsi_rel_id;
		*q_id = vf_q_id;

	*vsi_p = vsi;
	*t_tc = tc;
}

/**
 * nse_vc_validate_vqs_bitmaps - validate Rx/Tx queue bitmaps from VIRTCHNL
 * @vqs: virtchnl_queue_select structure containing bitmaps to validate
 *
 * Return true on successful validation, else false
 */
static bool nse_vc_validate_vqs_bitmaps(struct virtchnl_queue_select *vqs)
{
	if ((!vqs->rx_queues && !vqs->tx_queues) ||
	    vqs->rx_queues >= BIT(NSE_MAX_DFLT_QS_PER_VF) ||
	    vqs->tx_queues >= BIT(NSE_MAX_DFLT_QS_PER_VF))
		return false;

	return true;
}

/**
 * nse_vf_ena_txq_interrupt - enable Tx queue interrupt via QINT_TQCTL
 * @vsi: VSI of the VF to configure
 * @q_idx: VF queue index used to determine the queue in the PF's space
 */
static void nse_vf_ena_txq_interrupt(struct nse_vsi *vsi, u32 q_idx)
{
}

/**
 * nse_vf_ena_rxq_interrupt - enable Tx queue interrupt via QINT_RQCTL
 * @vsi: VSI of the VF to configure
 * @q_idx: VF queue index used to determine the queue in the PF's space
 */
static void nse_vf_ena_rxq_interrupt(struct nse_vsi *vsi, u32 q_idx)
{
}

/**
 * nse_vf_vsi_ena_single_rxq - enable single Rx queue based on relative q_id
 * @vf: VF to enable queue for
 * @vsi: VSI for the VF
 * @q_id: VSI relative (0-based) queue ID
 * @vf_q_id: VF relative (0-based) queue ID
 *
 * Attempt to enable the Rx queue passed in. If the Rx queue was successfully
 * enabled then set q_id bit in the enabled queues bitmap and return success.
 * Otherwise return error.
 */
static int
nse_vf_vsi_ena_single_rxq(struct nse_vf *vf, struct nse_vsi *vsi,
			  u16 vf_q_id)
{
	struct nse_hw *hw = &vf->pf->hw;
	int err;

	nse_debug(hw, NSE_DBG_SRIOV, "[%s] VF (vf_id=%d), vf_q_id=%d, test_bit(vf_q_id, vf->rxq_ena)=%d\n",
								__func__, vf->vf_id, vf_q_id,
									test_bit(vf_q_id,
										 vf->rxq_ena));

	if (test_bit(vf_q_id, vf->rxq_ena))
		return 0;

	err = nse_vsi_ctrl_one_rx_ring(vsi, true, vf_q_id);
	if (err) {
		dev_err(nse_pf_to_dev(vsi->back), "Failed to enable Rx ring %d on VF-VSI(vsi_abs_id=%d)\n",
			vf_q_id, vsi->vsi_abs_num);
		return err;
	}

	nse_vf_ena_rxq_interrupt(vsi, vf_q_id);
	set_bit(vf_q_id, vf->rxq_ena);

	return 0;
}

static int
nse_vf_vsi_ena_dis_rxq_bulk(struct nse_vf *vf, struct nse_vsi *vsi, unsigned long q_map, bool ena)
{
	struct nse_pf *pf = vsi->back;
	struct nse_ring *ring = NULL;
	u16 vf_q_id, firstq, lastq, qcnt;
	u16 *irqll = NULL;
	u16 i;
	enum nse_status status;
	int v_ret;

	for_each_set_bit(vf_q_id, &q_map, NSE_MAX_DFLT_QS_PER_VF) {
		if (!nse_vc_isvalid_q_id(vf, vsi->vsi_rel_num, vf_q_id)) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto out;
		}
	}

	qcnt = bitmap_weight(&q_map, NSE_MAX_DFLT_QS_PER_VF);
	if (!qcnt) {
		v_ret = 0;
		goto out;
	}

	irqll = kzalloc((sizeof(u16) * qcnt), GFP_KERNEL);
	if (irqll == NULL) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		goto out;
	}

	firstq = vsi->vsi_rxq_space_start + pf->lan_rxq_space_start;
	lastq = (vsi->vsi_rxq_space_start + qcnt - 1);

	nse_for_each_rxq(vsi, i) {
		ring = vsi->rx_rings[i];
		irqll[i] = NSE_AQC_CONF_IRQLL_INVALID_MSIX;

		if (i >= qcnt)
			break;

		if (!ring)
			continue;

		if (ring->need_irqll) {
			/* if to enable Q && already_in_irqll == 0, then need to add to irqll.
			 *
			 * if to disable Q && already_in_irqll == 1, then need to del from irqll
			 */
			if ((ena && !ring->already_in_irqll) ||
				(!ena && ring->already_in_irqll))
				irqll[i] = ring->irqll_msix;
		}
	}

	if (ena)
		status = nse_aq_lan_ena_rxq_many(&pf->hw, firstq, lastq, irqll);
	else
		status = nse_aq_lan_dis_rxq_many(&pf->hw, firstq, lastq, irqll);

	if (!status) {
		nse_for_each_rxq(vsi, i) {
			ring = vsi->rx_rings[i];
			if (i >= qcnt)
				break;

			if (!ring)
				continue;

			if (ena && ring->need_irqll)
				ring->already_in_irqll = true;
			else
				ring->already_in_irqll = false;
		}

	} else {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	for_each_set_bit(vf_q_id, &q_map, NSE_MAX_DFLT_QS_PER_VF) {
		if (ena) {
			nse_vf_ena_rxq_interrupt(vsi, vf_q_id);
			set_bit(vf_q_id, vf->rxq_ena);
		} else {
			clear_bit(vf_q_id, vf->rxq_ena);
		}
	}

	v_ret = 0;

out:
	kfree(irqll);

	return v_ret;
}

/**
 * nse_vf_vsi_ena_single_txq - enable single Tx queue based on relative q_id
 * @vf: VF to enable queue for
 * @vsi: VSI for the VF
 * @q_id: VSI relative (0-based) queue ID
 * @vf_q_id: VF relative (0-based) queue ID
 *
 * Enable the Tx queue's interrupt then set the q_id bit in the enabled queues
 * bitmap. Note that the Tx queue(s) should have already been
 * configurated/enabled in VIRTCHNL_OP_CONFIG_QUEUES so this function only
 * enables the interrupt associated with the q_id.
 */
static int
nse_vf_vsi_ena_single_txq(struct nse_vf *vf, struct nse_vsi *vsi,
			  u16 vf_q_id)
{
	struct nse_hw *hw = &vf->pf->hw;
	int err;

	nse_debug(hw, NSE_DBG_SRIOV, "[%s] VF (vf_id=%d), vf_q_id=%d, test_bit(vf_q_id, vf->txq_ena)=%d\n",
								__func__, vf->vf_id, vf_q_id,
									test_bit(vf_q_id,
										 vf->txq_ena));

	if (test_bit(vf_q_id, vf->txq_ena))
		return 0;

	err = nse_vsi_ctrl_one_tx_ring(vsi, true, vf_q_id);
	if (err) {
		dev_err(nse_pf_to_dev(vsi->back), "Failed to enable Tx ring %d on VF-VSI(vsi_abs_id=%d)\n",
			vf_q_id, vsi->vsi_abs_num);
		return err;
	}

	nse_vf_ena_txq_interrupt(vsi, vf_q_id);
	set_bit(vf_q_id, vf->txq_ena);

	return 0;
}

static int
nse_vf_vsi_ena_dis_txq_bulk(struct nse_vf *vf, struct nse_vsi *vsi, unsigned long q_map, bool ena)
{
	struct nse_pf *pf = vsi->back;
	u16 vf_q_id, firstq, lastq, qcnt;
	u16 *irqll = NULL;
	int i;
	struct nse_txq_meta txq_meta = { 0 };
	struct nse_ring *txq;
	enum nse_status status;
	int v_ret;

	for_each_set_bit(vf_q_id, &q_map, NSE_MAX_DFLT_QS_PER_VF) {
		if (!nse_vc_isvalid_q_id(vf, vsi->vsi_rel_num, vf_q_id)) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto out;
		}
	}

	qcnt = bitmap_weight(&q_map, NSE_MAX_DFLT_QS_PER_VF);
	if (!qcnt) {
		v_ret = 0;
		goto out;
	}

	irqll = kzalloc((sizeof(u16) * qcnt), GFP_KERNEL);
	if (irqll == NULL) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		goto out;
	}

	firstq = vsi->vsi_txq_space_start + pf->lan_txq_space_start;
	lastq = (vsi->vsi_txq_space_start + qcnt - 1);

	nse_for_each_txq(vsi, i) {
		txq = vsi->tx_rings[i];
		irqll[i] = NSE_AQC_CONF_IRQLL_INVALID_MSIX;

		if (i >= qcnt)
			break;

		if (!txq)
			continue;

		if (txq->need_irqll) {
			/* if to enable Q && already_in_irqll == 0, then need to add to irqll.
			 *
			 * if to disable Q && already_in_irqll == 1, then need to del from irqll
			 */
			if ((ena && !txq->already_in_irqll) ||
				(!ena && txq->already_in_irqll))
				irqll[i] = txq->irqll_msix;
		}
	}

	/* TDM-level enable / disable TXQ */
	if (ena)
		status = nse_aq_lan_ena_txq_many(&pf->hw, firstq, lastq, irqll);
	else
		status = nse_aq_lan_dis_txq_many(&pf->hw, firstq, lastq, irqll);

	if (!status) {
		nse_for_each_txq(vsi, i) {
			txq = vsi->tx_rings[i];

			if (i >= qcnt)
				break;

			if (!txq)
				continue;

			if (ena && txq->need_irqll)
				txq->already_in_irqll = true;
			else
				txq->already_in_irqll = false;
		}

	} else {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	if (!ena) {
		for (i = (NSE_MAX_DFLT_QS_PER_VF - 1); i >= 0; i--) {
			if (!(q_map & BIT(i)))
				continue;

			vf_q_id = i;

			txq = vsi->tx_rings[vf_q_id];
			if (!txq)
				continue;

			nse_fill_txq_meta(vsi, txq, &txq_meta);

			/* don't care about retval */
			/* tdm_stopped = true, because of above nse_aq_lan_dis_txq_many() */
			(void)nse_vsi_stop_tx_ring(vsi, txq, &txq_meta, true);
		}
	}

	for_each_set_bit(vf_q_id, &q_map, NSE_MAX_DFLT_QS_PER_VF) {
		if (ena) {
			nse_vf_ena_txq_interrupt(vsi, vf_q_id);
			set_bit(vf_q_id, vf->txq_ena);
		} else {
			clear_bit(vf_q_id, vf->txq_ena);
		}
	}

	v_ret = 0;

out:
	kfree(irqll);

	return v_ret;
}

static int
nse_vf_vsi_ena_single_txcq(struct nse_vf __always_unused *vf, struct nse_vsi *vsi,
			  u16 q_id)
{
	int err;

	err = nse_vsi_ctrl_one_txcq_ring(vsi, true, q_id);
	if (err) {
		dev_err(nse_pf_to_dev(vsi->back), "Failed to enable TX-CQ ring %d on VF-VSI(vsi_abs_id=%d)\n",
			q_id, vsi->vsi_abs_num);
		return err;
	}

	return 0;
}

/**
 * nse_vc_ena_qs_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * called from the VF to enable all or specific queue(s)
 */
static int nse_vc_ena_qs_msg(struct nse_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_queue_select *vqs =
	    (struct virtchnl_queue_select *)msg;
	struct nse_vsi *vsi;
	struct nse_pf *pf = vf->pf;
	struct nse_hw *hw = &pf->hw;
	unsigned long q_map;
	u16 vf_q_id = 0;

	if (!test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!nse_vc_isvalid_vsi_rel_id(vf, vqs->vsi_rel_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!nse_vc_validate_vqs_bitmaps(vqs)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	q_map = vqs->rx_queues;

	nse_debug(hw, NSE_DBG_SRIOV, "[%s]: VF-VSI (rel_id=%d, abs_id=%d), q_map = vqs->rx_queues = 0x%lX\n",
				__func__, vsi->vsi_rel_num, vsi->vsi_abs_num, q_map);

	if (nse_lan_bulk_ena_dis &&		/* bulk enable */
		/* requires rx_queues to be b' 111 pattern (bit set from bit-0, no hole) */
		!(q_map & (q_map + 0x1))) {
		if (nse_vf_vsi_ena_dis_rxq_bulk(vf, vsi, q_map, true)) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}
	} else {
		for_each_set_bit(vf_q_id, &q_map, NSE_MAX_DFLT_QS_PER_VF) {
			if (!nse_vc_isvalid_q_id(vf, vsi->vsi_rel_num, vf_q_id)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}

			if (nse_vf_vsi_ena_single_rxq(vf, vsi, vf_q_id)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
		}
	}

	nse_vc_update_rss_lut(vf, vsi);

	q_map = vqs->tx_queues;

	nse_debug(hw, NSE_DBG_SRIOV, "[%s]: VF-VSI (rel_id=%d, abs_id=%d), q_map = vqs->tx_queues = 0x%lX\n",
				__func__, vsi->vsi_rel_num, vsi->vsi_abs_num, q_map);

	if (nse_lan_bulk_ena_dis &&		/* bulk enable */
		/* requires rx_queues to be b' 111 pattern (bit set from bit-0, no hole) */
		!(q_map & (q_map + 0x1))) {
		if (nse_vf_vsi_ena_dis_txq_bulk(vf, vsi, q_map, true)) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}
	} else {
		for_each_set_bit(vf_q_id, &q_map, NSE_MAX_DFLT_QS_PER_VF) {
			if (!nse_vc_isvalid_q_id(vf, vsi->vsi_rel_num, vf_q_id)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}

			if (nse_vf_vsi_ena_single_txq(vf, vsi, vf_q_id)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
		}
	}

	if (vsi->sw_conf.lan_tx_use_cq) {
		q_map = vqs->txcq_queues;

		for_each_set_bit(vf_q_id, &q_map, vsi->alloc_txcq) {
			if (nse_vf_vsi_ena_single_txcq(vf, vsi, vf_q_id)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
		}
	}

	/* Set flag to indicate that queues are enabled */
	if (v_ret == VIRTCHNL_STATUS_SUCCESS) {
		set_bit(NSE_VF_STATE_QS_ENA, vf->vf_states);
		if (vf->repr)
			netif_carrier_on(vf->repr->netdev);
	}

error_param:
	/* send the response to the VF */
	return nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_ENABLE_QUEUES, v_ret,
				     NULL, 0);
}

/**
 * nse_vf_vsi_dis_single_txq - disable a single Tx queue
 * @vf: VF to disable queue for
 * @vsi: VSI for the VF
 * @q_id: VSI relative (0-based) queue ID
 * @vf_q_id: VF relative (0-based) queue ID
 *
 * Attempt to disable the Tx queue passed in. If the Tx queue was successfully
 * disabled then clear q_id bit in the enabled queues bitmap and return
 * success. Otherwise return error.
 */
int
nse_vf_vsi_dis_single_txq(struct nse_vf *vf, struct nse_vsi *vsi,
			  u16 vf_q_id)
{
	struct nse_pf *pf = vsi->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_txq_meta txq_meta = { 0 };
	struct nse_ring *ring;
	int err;

	if (!test_bit(vf_q_id, vf->txq_ena))
		dev_info(dev, "TXQ %u on VF-VSI(vsi_abs_id=%u) is not enabled, but stopping it anyway\n",
			vf_q_id, vsi->vsi_abs_num);

	ring = vsi->tx_rings[vf_q_id];
	if (!ring)
		return -EINVAL;

	nse_fill_txq_meta(vsi, ring, &txq_meta);

	err = nse_vsi_stop_tx_ring(vsi, ring, &txq_meta, false);
	if (err) {
		dev_err(dev, "Failed to stop Tx ring %d on VSI(vsi_abs_id=%d)\n",
			vf_q_id, vsi->vsi_abs_num);
	}

	/* Clear enabled queues flag */
	clear_bit(vf_q_id, vf->txq_ena);

	return err;
}

/**
 * nse_vf_vsi_dis_single_rxq - disable a Rx queue for VF on relative queue ID
 * @vf: VF to disable queue for
 * @vsi: VSI for the VF
 * @q_id: VSI relative (0-based) queue ID
 * @vf_q_id: VF relative (0-based) queue ID
 *
 * Attempt to disable the Rx queue passed in. If the Rx queue was successfully
 * disabled then clear q_id bit in the enabled queues bitmap and return success.
 * Otherwise return error.
 */
static int
nse_vf_vsi_dis_single_rxq(struct nse_vf *vf, struct nse_vsi *vsi,
			  u16 vf_q_id)
{
	int err;

	if (!test_bit(vf_q_id, vf->rxq_ena))
		dev_info(nse_pf_to_dev(vsi->back), "RXQ %u on VF-VSI(vsi_abs_id=%u) is not enabled, but stopping it anyway\n",
			vf_q_id, vsi->vsi_abs_num);

	err = nse_vsi_ctrl_one_rx_ring(vsi, false, vf_q_id);
	if (err) {
		dev_err(nse_pf_to_dev(vsi->back), "Failed to stop Rx ring %d on VF-VSI(vsi_abs_id=%d)\n",
			vf_q_id, vsi->vsi_abs_num);
		return err;
	}

	/* Clear enabled queues flag */
	clear_bit(vf_q_id, vf->rxq_ena);

	return 0;
}

static int
nse_vf_vsi_dis_single_txcq(struct nse_vf __always_unused *vf, struct nse_vsi *vsi,
			  u16 q_id)
{
	int err;

	err = nse_vsi_ctrl_one_txcq_ring(vsi, false, q_id);
	if (err) {
		dev_err(nse_pf_to_dev(vsi->back), "Failed to disable TX-CQ ring %d on VF-VSI(vsi_abs_id=%d)\n",
			q_id, vsi->vsi_abs_num);
		return err;
	}

	return 0;
}

/**
 * nse_vc_dis_qs_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * called from the VF to disable all or specific
 * queue(s)
 */
static int nse_vc_dis_qs_msg(struct nse_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_queue_select *vqs =
	    (struct virtchnl_queue_select *)msg;
	struct nse_hw *hw = &vf->pf->hw;
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_vsi *vsi;
	unsigned long q_map;
	int i;
	u16 vf_q_id = 0;

	if (!test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states) &&
	    !test_bit(NSE_VF_STATE_QS_ENA, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!nse_vc_isvalid_vsi_rel_id(vf, vqs->vsi_rel_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!nse_vc_validate_vqs_bitmaps(vqs)) {
		dev_err(dev,
			"BAD: vc_validate_vqs_bitmaps(), vqs->rx_queues=0x%X, tx_queues=0x%X\n",
			vqs->rx_queues, vqs->tx_queues);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	q_map = vqs->tx_queues;

	nse_debug(hw, NSE_DBG_SRIOV, "[%s]: VF-VSI (rel_id=%d, abs_id=%d), q_map = vqs->tx_queues = 0x%lX\n",
				__func__, vsi->vsi_rel_num, vsi->vsi_abs_num, q_map);

	if (q_map) {
		if (nse_lan_bulk_ena_dis &&		/* bulk disable */
			/* requires rx_queues to be b' 111 pattern (bit set from bit-0, no hole) */
			!(q_map & (q_map + 0x1))) {
			if (nse_vf_vsi_ena_dis_txq_bulk(vf, vsi, q_map, false)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
		} else {
			for (i = (NSE_MAX_DFLT_QS_PER_VF - 1); i >= 0; i--) {
				if (!(q_map & BIT(i)))
					continue;

				vf_q_id = i;

				if (!nse_vc_isvalid_q_id(vf, vsi->vsi_rel_num, vf_q_id)) {
					v_ret = VIRTCHNL_STATUS_ERR_PARAM;
					goto error_param;
				}

				if (nse_vf_vsi_dis_single_txq(vf, vsi, vf_q_id)) {
					v_ret = VIRTCHNL_STATUS_ERR_PARAM;
					goto error_param;
				}
			}
		}
	}

	q_map = vqs->rx_queues;

	nse_debug(hw, NSE_DBG_SRIOV, "[%s]: VF-VSI (rel_id=%d, abs_id=%d), q_map = vqs->rx_queues = 0x%lX\n",
				__func__, vsi->vsi_rel_num, vsi->vsi_abs_num, q_map);

	/* speed up Rx queue disable by batching them if possible */
	if (q_map &&
	    bitmap_equal(&q_map, vf->rxq_ena, NSE_MAX_DFLT_QS_PER_VF)) {
		if (nse_vsi_stop_all_rx_rings(vsi, false)) {
			dev_err(nse_pf_to_dev(vsi->back), "Failed to stop all Rx rings on VF-VSI(vsi_abs_id=%d)\n",
				vsi->vsi_abs_num);
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		bitmap_zero(vf->rxq_ena, NSE_MAX_DFLT_QS_PER_VF);

	} else if (q_map) {
		if (nse_lan_bulk_ena_dis &&		/* bulk disable */
			/* requires rx_queues to be b' 111 pattern (bit set from bit-0, no hole) */
			!(q_map & (q_map + 0x1))) {
			if (nse_vf_vsi_ena_dis_rxq_bulk(vf, vsi, q_map, false)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
		} else {
			for_each_set_bit(vf_q_id, &q_map, NSE_MAX_DFLT_QS_PER_VF) {
				if (!nse_vc_isvalid_q_id(vf, vsi->vsi_rel_num, vf_q_id)) {
					v_ret = VIRTCHNL_STATUS_ERR_PARAM;
					goto error_param;
				}

				if (nse_vf_vsi_dis_single_rxq(vf, vsi, vf_q_id)) {
					v_ret = VIRTCHNL_STATUS_ERR_PARAM;
					goto error_param;
				}
			}
		}
	}

	nse_vc_update_rss_lut(vf, vsi);

	if (vsi->sw_conf.lan_tx_use_cq) {
		q_map = vqs->txcq_queues;

		for_each_set_bit(vf_q_id, &q_map, vsi->alloc_txcq) {
			if (nse_vf_vsi_dis_single_txcq(vf, vsi, vf_q_id)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
		}
	}

	/* Clear enabled queues flag */
	if (v_ret == VIRTCHNL_STATUS_SUCCESS && nse_vf_has_no_qs_ena(vf)) {
		clear_bit(NSE_VF_STATE_QS_ENA, vf->vf_states);
		if (vf->repr)
			netif_carrier_off(vf->repr->netdev);
	}

error_param:
	/* send the response to the VF */
	return nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DISABLE_QUEUES, v_ret,
				     NULL, 0);
}

/**
 * nse_cfg_interrupt
 * @vf: pointer to the VF info
 * @vsi: the VSI being configured
 * @tc: traffic class number for ADQ
 * @map: vector map for mapping vectors to queues
 * @q_vector: structure for interrupt vector
 * configure the IRQ to queue map
 */
static int
nse_cfg_interrupt(struct nse_vf *vf, struct nse_vsi *vsi,
		  u8 __maybe_unused tc, struct virtchnl_vector_map *map,
		  struct nse_q_vector *q_vector)
{
	unsigned long qmap;
	u16 vsi_q_id_idx;

	q_vector->num_ring_rx = 0;
	q_vector->num_ring_tx = 0;

	qmap = map->rxq_map;
	for_each_set_bit(vsi_q_id_idx, &qmap, NSE_MAX_DFLT_QS_PER_VF) {
		u16 vsi_q_id = vsi_q_id_idx;

		if (!nse_vc_isvalid_q_id(vf, vsi->vsi_rel_num, vsi_q_id))
			return VIRTCHNL_STATUS_ERR_PARAM;

		q_vector->num_ring_rx++;
		vsi->rx_rings[vsi_q_id]->q_vector = q_vector;
		nse_cfg_rxq_interrupt(vsi, vsi_q_id,
				      q_vector->v_idx + vsi->base_vector);
	}

	qmap = map->txq_map;
	for_each_set_bit(vsi_q_id_idx, &qmap, NSE_MAX_DFLT_QS_PER_VF) {
		u16 vsi_q_id = vsi_q_id_idx;

		if (!nse_vc_isvalid_q_id(vf, vsi->vsi_rel_num, vsi_q_id))
			return VIRTCHNL_STATUS_ERR_PARAM;

		q_vector->num_ring_tx++;
		vsi->tx_rings[vsi_q_id]->q_vector = q_vector;
		nse_cfg_txq_interrupt(vsi, vsi_q_id,
				      q_vector->v_idx + vsi->base_vector);
	}

	return VIRTCHNL_STATUS_SUCCESS;
}

/**
 * nse_vc_cfg_irq_map_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * called from the VF to configure the IRQ to queue map
 */
static int nse_vc_cfg_irq_map_msg(struct nse_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	int ret;
	struct virtchnl_irq_map_info *irqmap_info;
	struct virtchnl_vector_map *map;
	struct nse_pf *pf = vf->pf;
	u16 num_q_vectors_mapped;
	struct nse_vsi *vsi;
	u16 tc = 0;
	int i;

	irqmap_info = (struct virtchnl_irq_map_info *)msg;
	num_q_vectors_mapped = irqmap_info->num_vectors;

	/* Check to make sure number of VF vectors mapped is not greater than
	 * number of VF vectors originally allocated, and check that
	 * there is actually at least a single VF queue vector mapped
	 */
	if (!test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states) ||
	    pf->vfs.num_msix_per < num_q_vectors_mapped ||
	    !num_q_vectors_mapped) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	/* inside nse_vsi_map_txcq_rings_to_vectors_for_vf() */
	ret = nse_vsi_map_txcq_rings_to_vectors(vsi);
	if (ret) {
		dev_err(nse_pf_to_dev(pf), "[%s] FAIL: vsi_map_txcq_rings_to_vectors() -> vsi_map_txcq_rings_to_vectors_for_vf()\n",
									__func__);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	for (i = 0; i < num_q_vectors_mapped; i++) {
		struct nse_q_vector *q_vector;
		u16 vsi_abs_id, vector_id;

		map = &irqmap_info->vecmap[i];

		vector_id = map->vector_id;
		vsi_abs_id = map->vsi_abs_id;

		/* vector_id is always 0-based for each VF, and can never be
		 * larger than or equal to the max allowed interrupts per VF
		 */
		if (!(vector_id < pf->vfs.num_msix_per) ||
		    !nse_vc_isvalid_vsi_abs_id(vf, vsi_abs_id) ||
		    (!vector_id && (map->rxq_map || map->txq_map))) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		/* No need to map VF miscellaneous or rogue vector */
		if (!vector_id)
			continue;

		if ((vector_id - NSE_NONQ_VECS_VF) >= vsi->num_q_vectors) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		q_vector = vf->vf_ops->get_q_vector(vf, vsi, vector_id);

		if (!q_vector) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		/* lookout for the invalid queue index */
		v_ret = (enum virtchnl_status_code)
			nse_cfg_interrupt(vf, vsi, tc, map, q_vector);
		if (v_ret)
			goto error_param;
	}

error_param:
	/* send the response to the VF */
	return nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_IRQ_MAP, v_ret,
				     NULL, 0);
}

/**
 * nse_vc_get_max_allowed_qpairs - get max allowed queue pairs
 * @vf: VF used to get max queue pairs allowed
 *
 * The maximum allowed queues is determined based on whether
 * VIRTCHNL_VF_LARGE_NUM_QPAIRS was negotiated.
 */
static int nse_vc_get_max_allowed_qpairs(struct nse_vf *vf)
{
	return NSE_MAX_DFLT_QS_PER_VF;
}

/**
 * nse_vc_cfg_qs_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * called from the VF to configure the Rx/Tx queues
 */
static int nse_vc_cfg_qs_msg(struct nse_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_vsi_queue_config_info *qci =
	    (struct virtchnl_vsi_queue_config_info *)msg;
	struct virtchnl_queue_pair_info *qpi;
	struct virtchnl_lan_txcq_info *cqpi;
	struct nse_pf *pf = vf->pf;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vsi *vsi;
	u16 queue_id_tmp, tc;
	int i, q_idx;
	int err;

	if (!test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states)) {
		nse_debug(hw, NSE_DBG_SRIOV, "[%s, %d] bad VF state (vf_id=%d)",
										__func__,
											__LINE__,
											vf->vf_id);

		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!nse_vc_isvalid_vsi_rel_id(vf, qci->vsi_rel_id)) {
		nse_debug(hw, NSE_DBG_SRIOV, "[%s, %d] bad VF-VSI ID (vf_id=%d, vsi_rel_id=%d)",
			  __func__, __LINE__, vf->vf_id, qci->vsi_rel_id);

		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		nse_debug(hw, NSE_DBG_SRIOV, "[%s, %d] no VF-VSI (vf_id=%d, vsi_rel_id=%d)",
			  __func__, __LINE__, vf->vf_id, qci->vsi_rel_id);

		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (qci->num_queue_pairs > nse_vc_get_max_allowed_qpairs(vf) ||
	    qci->num_queue_pairs > min_t(u16, vsi->alloc_txq, vsi->alloc_rxq)) {
		dev_err(dev, "VF-%d trying to configure more than allocated number of queues: %d\n",
			vf->vf_id, min_t(u16, vsi->alloc_txq, vsi->alloc_rxq));
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (qci->vsi_mode == VIRTCHNL_VSI_MODE_NATIVE) {
		vsi->vsi_mode = NSE_VSI_MODE_NATIVE;
	} else if (qci->vsi_mode == VIRTCHNL_VSI_MODE_VIRTIO) {
		vsi->vsi_mode = NSE_VSI_MODE_VIRTIO;
	} else {
		dev_err(dev, "VF-%d trying to give a bad vsi_mode: %d\n",
			vf->vf_id, qci->vsi_mode);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if ((qci->lan_tx_use_cq && !vsi->sw_conf.lan_tx_use_cq) ||
		(!qci->lan_tx_use_cq && vsi->sw_conf.lan_tx_use_cq)) {
		dev_err(dev, "[%s, %d]: BAD: VF-%d(VF-VSI-%d): qci->lan_tx_use_cq=%d != vsi_sw_conf->lan_tx_use_cq=%d\n",
						__func__, __LINE__,
						vf->vf_id, vsi->vsi_abs_num,
						qci->lan_tx_use_cq, vsi->sw_conf.lan_tx_use_cq);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	queue_id_tmp = 0;
	tc = 0;

	for (i = 0; i < qci->num_queue_pairs; i++) {
		qpi = &qci->qpair[i];

		if (qpi->txq.vsi_rel_id != qci->vsi_rel_id ||
		    qpi->rxq.vsi_rel_id != qci->vsi_rel_id ||
		    qpi->rxq.queue_id != qpi->txq.queue_id ||
		    !nse_vc_isvalid_ring_len(qpi->txq.ring_len) ||
		    !nse_vc_isvalid_ring_len(qpi->rxq.ring_len) ||
		    !nse_vc_isvalid_q_id(vf, qci->vsi_rel_id, qpi->txq.queue_id)) {
			nse_debug(hw, NSE_DBG_SRIOV, "[%s, %d] bad request from VF (vf_id=%d):\n",
				  __func__, __LINE__, vf->vf_id);

			nse_debug(hw, NSE_DBG_SRIOV, "\t qpi->txq.vsi_rel_id=%d, qci->vsi_rel_id=%d\n",
				  qpi->txq.vsi_rel_id, qci->vsi_rel_id);

			nse_debug(hw, NSE_DBG_SRIOV, "\t qpi->rxq.vsi_rel_id=%d, qci->vsi_rel_id=%d\n",
				  qpi->rxq.vsi_rel_id, qci->vsi_rel_id);

			nse_debug(hw, NSE_DBG_SRIOV, "\t qpi->rxq.queue_id=%d, qpi->txq.queue_id=%d\n",
				  qpi->rxq.queue_id, qpi->txq.queue_id);

			nse_debug(hw, NSE_DBG_SRIOV, "\t vc_isvalid_ring_len(qpi->txq.ring_len=%d)=%d\n",
				  qpi->txq.ring_len, nse_vc_isvalid_ring_len(qpi->txq.ring_len));

			nse_debug(hw, NSE_DBG_SRIOV, "\t vc_isvalid_ring_len(qpi->rxq.ring_len=%d)=%d\n",
				  qpi->rxq.ring_len, nse_vc_isvalid_ring_len(qpi->rxq.ring_len));

			nse_debug(hw, NSE_DBG_SRIOV, "\t vc_isvalid_q_id(qpi->txq.queue_id=%d)=%d\n",
				  qpi->txq.queue_id, nse_vc_isvalid_q_id(vf, qci->vsi_rel_id,
									 qpi->txq.queue_id));

			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		q_idx = qpi->rxq.queue_id;

		/* make sure selected "q_idx" is in valid range of queues
		 * for selected "vsi" (which could be main VF VSI or
		 * VF ADQ VSI
		 */
		if (q_idx >= vsi->alloc_txq || q_idx >= vsi->alloc_rxq) {
			nse_debug(hw, NSE_DBG_SRIOV, "[%s, %d] bad q_idx=%d\n",
				  __func__, __LINE__, q_idx);

			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		/* copy Tx queue info from VF into VSI */
		if (qpi->txq.ring_len > 0) {
			nse_debug(hw, NSE_DBG_SRIOV, "[%s, %d] cfg txq (idx=%d)\n",
							__func__, __LINE__, q_idx);

			vsi->tx_rings[q_idx]->dma = qpi->txq.dma_ring_addr;
			vsi->tx_rings[q_idx]->count = qpi->txq.ring_len;

			if (vsi->vsi_mode == NSE_VSI_MODE_VIRTIO) {
				vsi->tx_rings[q_idx]->vtio_dma_drv_addr = qpi->txq.dma_drv_addr;
				vsi->tx_rings[q_idx]->vtio_dma_dev_addr = qpi->txq.dma_dev_addr;
				vsi->tx_rings[q_idx]->vtio_head = qpi->txq.tx_head;
				vsi->tx_rings[q_idx]->vtio_tail = qpi->txq.tx_tail;
			}

			/* Disable any existing queue first */
			if (nse_lan_disable_q_before_cfg) {
				if (nse_vf_vsi_dis_single_txq(vf, vsi, qpi->txq.queue_id)) {
					nse_debug(hw, NSE_DBG_SRIOV, "[%s, %d] fail: vf_vsi_dis_single_txq(queue_id=%d)\n",
				       __func__, __LINE__, qpi->txq.queue_id);

					v_ret = VIRTCHNL_STATUS_ERR_PARAM;
					goto error_param;
				}
			}

			/* Configure a queue with the requested settings */
			if (nse_vsi_cfg_single_txq(vsi, vsi->tx_rings, q_idx)) {
				nse_debug(hw, NSE_DBG_SRIOV, "[%s, %d] fail: vsi_cfg_single_txq(queue_id=%d)\n",
				       __func__, __LINE__, q_idx);

				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
		}

		/* copy Rx queue info from VF into VSI */
		if (qpi->rxq.ring_len > 0) {
			u16 max_frame_size = nse_vc_get_max_frame_size(vf);
			u32 rxdid;

			nse_debug(hw, NSE_DBG_SRIOV, "[%s, %d] cfg rxq (idx=%d)\n",
							__func__, __LINE__, q_idx);

			vsi->rx_rings[q_idx]->dma = qpi->rxq.dma_ring_addr;
			vsi->rx_rings[q_idx]->count = qpi->rxq.ring_len;

			if (vsi->vsi_mode == NSE_VSI_MODE_VIRTIO) {
				vsi->rx_rings[q_idx]->vtio_dma_drv_addr = qpi->rxq.dma_drv_addr;
				vsi->rx_rings[q_idx]->vtio_dma_dev_addr = qpi->rxq.dma_dev_addr;
				vsi->rx_rings[q_idx]->vtio_head = qpi->rxq.rx_head;
				vsi->rx_rings[q_idx]->vtio_tail = qpi->rxq.rx_tail;
			}

			if (qpi->rxq.databuffer_size != 0 &&
			    (qpi->rxq.databuffer_size > NSE_AQ_SET_MAC_FRAME_SIZE_MAX ||
			     qpi->rxq.databuffer_size < 1024)) {
				nse_debug(hw, NSE_DBG_SRIOV, "[%s, %d] bad qpi->rxq.databuffer_size=%d\n",
				       __func__, __LINE__, qpi->rxq.databuffer_size);

				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
			vsi->rx_buf_len = qpi->rxq.databuffer_size;
			vsi->rx_rings[q_idx]->rx_buf_len = vsi->rx_buf_len;
			if (qpi->rxq.max_pkt_size > max_frame_size ||
			    qpi->rxq.max_pkt_size < 64) {
				nse_debug(hw, NSE_DBG_SRIOV, "[%s, %d] bad qpi->rxq.max_pkt_size=%d\n",
				       __func__, __LINE__, qpi->rxq.max_pkt_size);

				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}

			vsi->max_frame = qpi->rxq.max_pkt_size;

			if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC) {
				rxdid = qpi->rxq.rxdid;
				if (!(BIT(rxdid) & pf->supported_rxdids)) {
					nse_debug(hw, NSE_DBG_SRIOV, "[%s, %d] bad qpi->rxq.rxdid=%d\n",
				       __func__, __LINE__, qpi->rxq.rxdid);

					v_ret = VIRTCHNL_STATUS_ERR_PARAM;
					goto error_param;
				}
			} else {
				rxdid = NSE_RXDID_FLEX_NIC;
			}

			vsi->rxdid = rxdid;

			if (nse_lan_disable_q_before_cfg) {
				if (nse_vf_vsi_dis_single_rxq(vf, vsi, qpi->rxq.queue_id)) {
					nse_debug(hw, NSE_DBG_SRIOV, "[%s, %d] fail: vf_vsi_dis_single_rxq(queue_id=%d)\n",
				       __func__, __LINE__, qpi->rxq.queue_id);

					v_ret = VIRTCHNL_STATUS_ERR_PARAM;
					goto error_param;
				}
			}

			if (nse_vsi_cfg_single_rxq(vsi, q_idx)) {
				nse_debug(hw, NSE_DBG_SRIOV, "[%s, %d] fail: vsi_cfg_single_rxq(queue_id=%d)\n",
				       __func__, __LINE__, q_idx);

				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}

			err = nse_vsi_cfg_rx_max(vsi, vsi->max_frame);
			if (err) {
				dev_err(dev, "[%s] FAIL: vsi_cfg_rx_max(), vsi abs id=%d, max_frame=%d ret=%d\n",
							__func__, vsi->vsi_abs_num,
								vsi->max_frame, err);
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
		}
	}

	if (qci->lan_tx_use_cq) {
		if (!qci->num_txcq) {
			dev_err(dev, "[%s, %d]: BAD: VF-%d(VF-VSI-%d): qci->lan_tx_use_cq=true, but qci->num_txcq = 0\n",
						__func__, __LINE__,
						vf->vf_id, vsi->vsi_abs_num);
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		if (qci->num_txcq > vsi->num_txcq) {
			dev_err(dev, "[%s, %d]: BAD: VF-%d(VF-VSI-%d): qci->num_txcq = %d >= vsi->num_txcq=%d\n",
						__func__, __LINE__,
						vf->vf_id, vsi->vsi_abs_num,
						qci->num_txcq, vsi->num_txcq);
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		cqpi = (struct virtchnl_lan_txcq_info *)(qpi + 1);

		for (i = 0; i < qci->num_txcq; i++) {
			struct nse_txcq_ring *cq_ring;

			if (cqpi->vsi_rel_id != qci->vsi_rel_id ||
				!nse_vc_isvalid_txcq_id(vf, qci->vsi_rel_id, cqpi->queue_id) ||
				!nse_vc_isvalid_txcq_ring_len(cqpi->ring_len)) {
				dev_err(dev, "[%s, %d]: BAD: VF-%d(VF-VSI-%d): cqpi->vsi_rel_id(%d), qci->vsi_rel_id(%d)\n",
							__func__, __LINE__,
							vf->vf_id, vsi->vsi_abs_num,
							cqpi->vsi_rel_id, qci->vsi_rel_id);
				dev_err(dev, "\t vc_isvalid_txcq_id(cqpi->queue_id=%d)=%s, vc_isvalid_txcq_ring_len(cqpi->ring_len=%d)=%s\n",
								cqpi->queue_id,
				       nse_vc_isvalid_txcq_id(vf, qci->vsi_rel_id,
							      cqpi->queue_id) ? "true" : "false",
								cqpi->ring_len,
				       nse_vc_isvalid_txcq_ring_len(cqpi->ring_len) ?
					       "true" : "false");
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}

			q_idx = cqpi->queue_id;
			cq_ring = vsi->txcq_rings[q_idx];

			cq_ring->dma = cqpi->dma_ring_addr;
			cq_ring->count = cqpi->ring_len;

/* no need, because nse_vsi_cfg_lan_txcq() -> nse_setup_lan_txcq_ctx() internally would do this */

			/* Configure a queue with the requested settings */
			if (nse_vsi_cfg_lan_txcq(cq_ring)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}

			cqpi++;
		}
	}

error_param:
	nse_debug(hw, NSE_DBG_SRIOV, "[%s, %d] send back vch-rsp(v_ret=%d)\n",
										__func__,
											__LINE__,
											v_ret);

	/* send the response to the VF */
	return nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_VSI_QUEUES, v_ret,
				     NULL, 0);
}

static int nse_vf_vsi_get_txq_info(struct nse_vf *vf, struct virtchnl_txq_info *txq,
									u16 queue_id)
{
	struct nse_pf *pf = vf->pf;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vsi *vsi;
	struct nse_ring *tx_ring;
	struct nse_hw *hw;
	struct nse_lan_txq_ctx *txq_ctx = NULL;
	struct nse_lan_txq_ctx_amber *txq_ctx_amber = NULL;	//ugly
	int ret = 0;

	vsi = nse_get_vf_vsi(vf);
	if (!vsi)
		return -EIO;

	tx_ring = vsi->tx_rings[queue_id];
	hw = &vsi->back->hw;

	if (hw->mac_type != NSE_MAC_TYPE_AMBER) {
		dev_err(dev, "[%s] BAD: only Amber support this op\n", __func__);
		return -EIO;
	}

	if (txq == NULL || tx_ring == NULL)
		return -EIO;

	txq->vsi_abs_id = vf->vf_vsi_abs_id;
	txq->vsi_rel_id = vf->vf_vsi_rel_id;

	txq->queue_id = queue_id;
	txq->ring_len = tx_ring->count;
	txq->dma_ring_addr = tx_ring->dma;

	if (vsi->vsi_mode == NSE_VSI_MODE_VIRTIO) {
		/* update txq vtio head tail */
		txq_ctx = kzalloc(sizeof(*txq_ctx), GFP_KERNEL);
		if (!txq_ctx)
			return -ENOMEM;

		if (!nse_read_txq_ctx(hw, txq_ctx, tx_ring->abs_id)) {
			txq_ctx_amber = &txq_ctx->amber;

			txq->dma_drv_addr = (u64)(txq_ctx_amber->data[6]) |
								(((u64)txq_ctx_amber->data[7]) <<
								 32);
			txq->tx_head =
					(u16)(((txq_ctx_amber->data[9] >>
					      AMBER_LAN_TXQ_CTX_RPTR_S) & 0x1FFF) |
						  ((txq_ctx_amber->data[8] >>
						   AMBER_LAN_TXQ_CTX_WBPTR_S) & 0x8000));
			txq->tx_tail = txq->tx_head;
			tx_ring->vtio_dma_drv_addr = txq->dma_drv_addr;
			tx_ring->vtio_head = txq->tx_head;
			tx_ring->vtio_tail = txq->tx_tail;
			txq->dma_dev_addr = tx_ring->vtio_dma_dev_addr;
		} else {
			dev_err(dev, "TXQ-%d context: get_txq_info FAIL to read\n",
							vf->vf_vsi_abs_id);
			ret = -EIO;
			goto err_read_ctx;
		}
	} else {
		txq->dma_drv_addr = 0;
		txq->dma_dev_addr = 0;
		txq->tx_head = 0;
		txq->tx_tail = 0;
	}

err_read_ctx:
	kfree(txq_ctx);
	return ret;
}

static int nse_vf_vsi_get_rxq_info(struct nse_vf *vf, struct virtchnl_rxq_info *rxq,
									u16 queue_id)
{
	struct nse_pf *pf = vf->pf;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vsi *vsi;
	struct nse_ring *rx_ring;
	struct nse_hw *hw;
	struct nse_lan_rxq_ctx *rxq_ctx = NULL;
	struct nse_lan_rxq_ctx_amber *rxq_ctx_amber = NULL;	//ugly
	int ret = 0;

	vsi = nse_get_vf_vsi(vf);
	if (!vsi)
		return -EIO;

	rx_ring = vsi->rx_rings[queue_id];
	hw = &vsi->back->hw;

	if (hw->mac_type != NSE_MAC_TYPE_AMBER) {
		dev_err(dev, "[%s] BAD: only Amber support this op\n", __func__);
		return -EIO;
	}

	if (rxq == NULL || rx_ring == NULL)
		return -EIO;

	rxq->vsi_abs_id = vf->vf_vsi_abs_id;
	rxq->vsi_rel_id = vf->vf_vsi_rel_id;

	rxq->queue_id = queue_id;
	rxq->ring_len = rx_ring->count;
	rxq->databuffer_size = vsi->rx_buf_len;
	rxq->max_pkt_size = vsi->max_frame;
	rxq->rxdid = vsi->rxdid;
	rxq->dma_ring_addr = rx_ring->dma;

	if (vsi->vsi_mode == NSE_VSI_MODE_VIRTIO) {
		/* update rxq vtio head tail */
		rxq_ctx = kzalloc(sizeof(*rxq_ctx), GFP_KERNEL);
		if (!rxq_ctx)
			return -ENOMEM;

		if (!nse_read_rxq_ctx(hw, rxq_ctx, rx_ring->abs_id)) {
			rxq_ctx_amber = &rxq_ctx->amber;

			rxq->dma_drv_addr = (u64)(rxq_ctx_amber->data[5]) |
								(((u64)rxq_ctx_amber->data[6]) <<
								 32);
			rxq->rx_head = (u16)(rxq_ctx_amber->data[7] >> AMBER_LAN_RXQ_CTX_HEAD_S);
			rxq->rx_tail = rxq->rx_head;
			rx_ring->vtio_dma_drv_addr = rxq->dma_drv_addr;
			rx_ring->vtio_head = rxq->rx_head;
			rx_ring->vtio_tail = rxq->rx_tail;
			rxq->dma_dev_addr = rx_ring->vtio_dma_dev_addr;
		} else {
			dev_err(dev, "RXQ-%d context: get_rxq_info FAIL to read\n",
							vf->vf_vsi_abs_id);
			ret = -EIO;
			goto err_read_ctx;
		}
	} else {
		rxq->dma_drv_addr = 0;
		rxq->dma_dev_addr = 0;
		rxq->rx_head = 0;
		rxq->rx_tail = 0;
	}

err_read_ctx:
	kfree(rxq_ctx);
	return ret;
}

static int nse_vc_get_queue_info(struct nse_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_vsi_query_queue_info *qqi =
	    (struct virtchnl_vsi_query_queue_info *)msg;
	struct virtchnl_vsi_query_queue_info *rqi = NULL;
	struct nse_pf *pf = vf->pf;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vsi *vsi;
	u16 i, qidx = 0;
	bool bulk_mode = false;
	int len = 0, num_qpair, ret;

	if (!nse_is_hw_static_fea_set(&pf->hw, NSE_HW_STATIC_FEA_MISC_SUPPORT_VIRTIO)) {
		dev_err(dev, "[%s] driver does not (need to) support this vch-op (from VF-%d)\n",
						__func__, vf->vf_id);
		goto error_param;
	}

	if (!test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (qqi == NULL) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		dev_err(dev, "VF-%d send a NULL message\n",
							vf->vf_id);
		goto error_param;
	}

	if (!nse_vc_isvalid_vsi_rel_id(vf, qqi->vsi_rel_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (qqi->num_qps > 1)
		bulk_mode = true;

	if (bulk_mode) {
		if (qqi->num_qps > NSE_MAX_DFLT_QS_PER_VF) {
			dev_err(dev, "VF-%d alloc txq/rxq exceed the maximum qpair num\n",
							vf->vf_id);
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		num_qpair = min_t(u16, vsi->alloc_txq, vsi->alloc_rxq);
		num_qpair = min_t(u16, num_qpair, qqi->num_qps);
		len = sizeof(struct virtchnl_vsi_query_queue_info) +
			  sizeof(struct virtchnl_queue_pair_info) * num_qpair;

		rqi = kzalloc(len, GFP_KERNEL);
		if (!rqi) {
			v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
			len = 0;
			goto error_param;
		}

		/* reply actual qpair number */
		rqi->num_qps = num_qpair;
		for (i = 0; i < num_qpair; i++) {
			ret = nse_vf_vsi_get_txq_info(vf, &rqi->qpair[i].txq, i);
			if (ret) {
				v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
				goto error_out;
			}
		}

		for (i = 0; i < num_qpair; i++) {
			ret = nse_vf_vsi_get_rxq_info(vf, &rqi->qpair[i].rxq, i);
			if (ret) {
				v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
				goto error_out;
			}
		}
	} else {
		/* define txq.queue_id as queuepair id */
		qidx = qqi->qpair[0].txq.queue_id;
		if ((qidx > vsi->alloc_txq) || (qidx > vsi->alloc_rxq)) {
			dev_err(dev, "VF-%d query queue pair id exceed the allocated max\n",
				vf->vf_id);
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		len = sizeof(struct virtchnl_vsi_query_queue_info) +
			  sizeof(struct virtchnl_queue_pair_info);
		rqi = kzalloc(len, GFP_KERNEL);
		if (!rqi) {
			v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
			len = 0;
			goto error_param;
		}

		rqi->num_qps = 1;
		ret = nse_vf_vsi_get_txq_info(vf, &rqi->qpair[0].txq, qidx);
		if (ret) {
			v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
			goto error_out;
		}

		ret = nse_vf_vsi_get_rxq_info(vf, &rqi->qpair[0].rxq, qidx);
		if (ret) {
			v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
			goto error_out;
		}
	}

error_out:
	/* send the response to the VF */
	ret = nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_QUERY_QUEUE_INFO, v_ret,
						(u8 *)rqi, len);
	kfree(rqi);

error_param:
	return ret;
}

/**
 * nse_can_vf_change_mac
 * @vf: pointer to the VF info
 *
 * Return true if the VF is allowed to change its MAC filters, false otherwise
 */
static bool nse_can_vf_change_mac(struct nse_vf *vf)
{
	/* If the VF MAC address has been set administratively (via the
	 * ndo_set_vf_mac command), then deny permission to the VF to
	 * add/delete unicast MAC addresses, unless the VF is trusted
	 */
	if (vf->pf_set_mac && !nse_is_vf_trusted(vf))
		return false;

	return true;
}

/**
 * nse_vc_ether_addr_type - get type of virtchnl_ether_addr
 * @vc_ether_addr: used to extract the type
 */
static u8 nse_vc_ether_addr_type(struct virtchnl_ether_addr *vc_ether_addr)
{
	return (vc_ether_addr->type & VIRTCHNL_ETHER_ADDR_TYPE_MASK);
}

/**
 * nse_is_vc_addr_legacy - check if the MAC address is from an older VF
 * @vc_ether_addr: VIRTCHNL structure that contains MAC and type
 */
static bool nse_is_vc_addr_legacy(struct virtchnl_ether_addr *vc_ether_addr)
{
	u8 type = nse_vc_ether_addr_type(vc_ether_addr);

	return (type == VIRTCHNL_ETHER_ADDR_LEGACY);
}

/**
 * nse_is_vc_addr_primary - check if the MAC address is the VF's primary MAC
 * @vc_ether_addr: VIRTCHNL structure that contains MAC and type
 *
 * This function should only be called when the MAC address in
 * virtchnl_ether_addr is a valid unicast MAC
 */
static bool nse_is_vc_addr_primary(struct virtchnl_ether_addr *vc_ether_addr)
{
	u8 type = nse_vc_ether_addr_type(vc_ether_addr);

	return (type == VIRTCHNL_ETHER_ADDR_PRIMARY);
}

/**
 * nse_vfhw_mac_add - update the VF's cached hardware MAC if allowed
 * @vf: VF to update
 * @vc_ether_addr: structure from VIRTCHNL with MAC to add
 */
static void
nse_vfhw_mac_add(struct nse_vf *vf, struct virtchnl_ether_addr *vc_ether_addr)
{
	u8 *mac_addr = vc_ether_addr->addr;

	if (!is_valid_ether_addr(mac_addr))
		return;

	/* only allow legacy VF drivers to set the device and hardware MAC if it
	 * is zero and allow new VF drivers to set the hardware MAC if the type
	 * was correctly specified over VIRTCHNL
	 */
	if ((nse_is_vc_addr_legacy(vc_ether_addr) &&
	     is_zero_ether_addr(vf->hw_lan_addr.addr)) ||
	    nse_is_vc_addr_primary(vc_ether_addr)) {
		ether_addr_copy(vf->dev_lan_addr.addr, mac_addr);
		ether_addr_copy(vf->hw_lan_addr.addr, mac_addr);
	}

	/* hardware and device MACs are already set, but its possible that the
	 * VF driver sent the VIRTCHNL_OP_ADD_ETH_ADDR message before the
	 * VIRTCHNL_OP_DEL_ETH_ADDR when trying to update its MAC, so save it
	 * away for the legacy VF driver case as it will be updated in the
	 * delete flow for this case
	 */
	if (nse_is_vc_addr_legacy(vc_ether_addr)) {
		ether_addr_copy(vf->legacy_last_added_umac.addr,
				mac_addr);
		vf->legacy_last_added_umac.time_modified = jiffies;
	}
}

/**
 * nse_vc_add_mac_addr - attempt to add the MAC address passed in
 * @vf: pointer to the VF info
 * @vsi: pointer to the VF's VSI
 * @vc_ether_addr: VIRTCHNL MAC address structure used to add MAC
 */
static int
nse_vc_add_mac_addr(struct nse_vf *vf, struct nse_vsi *vsi,
		    struct virtchnl_ether_addr *vc_ether_addr)
{
	struct device *dev = nse_pf_to_dev(vf->pf);
	u8 *mac_addr = vc_ether_addr->addr;
	enum nse_status status;
	int ret = 0;

	/* device MAC already added */
	if (!ether_addr_equal(mac_addr, vf->dev_lan_addr.addr)) {
		if (is_unicast_ether_addr(mac_addr) &&
		    !nse_can_vf_change_mac(vf)) {
			dev_err(dev, "VF attempting to override administratively set MAC address, bring down and up the VF interface to resume normal operation\n");
			return -EPERM;
		}

		status = nse_fltr_add_mac(vsi, mac_addr, NSE_FWD_TO_VSI);
		if (status == NSE_ERR_ALREADY_EXISTS) {
			dev_dbg(dev, "MAC %pM already exists for VF %d\n",
				mac_addr, vf->vf_id);
			/* don’t return since we might need to update
			 * the primary MAC in nse_vfhw_mac_add() below
			 */
			ret = -EEXIST;
		} else if (status) {
			dev_err(dev, "Failed to add MAC %pM for VF %d\n, error %s\n",
				mac_addr, vf->vf_id, nse_stat_str(status));
			ret = -EIO;
			goto out;
		} else {
			vf->num_mac++;
		}

		nse_vfhw_mac_add(vf, vc_ether_addr);
	}
out:
	return ret;
}

/**
 * nse_is_legacy_umac_expired - check if last added legacy unicast MAC expired
 * @last_added_umac: structure used to check expiration
 */
static bool nse_is_legacy_umac_expired(struct nse_time_mac *last_added_umac)
{
#define NSE_LEGACY_VF_MAC_CHANGE_EXPIRE_TIME	msecs_to_jiffies(3000)
	return time_is_before_jiffies(last_added_umac->time_modified +
				      NSE_LEGACY_VF_MAC_CHANGE_EXPIRE_TIME);
}

/**
 * nse_update_legacy_cached_mac - update cached hardware MAC for legacy VF
 * @vf: VF to update
 * @vc_ether_addr: structure from VIRTCHNL with MAC to check
 *
 * only update cached hardware MAC for legacy VF drivers on delete
 * because we cannot guarantee order/type of MAC from the VF driver
 */
static void
nse_update_legacy_cached_mac(struct nse_vf *vf,
			     struct virtchnl_ether_addr *vc_ether_addr)
{
	if (!nse_is_vc_addr_legacy(vc_ether_addr) ||
	    nse_is_legacy_umac_expired(&vf->legacy_last_added_umac))
		return;

	ether_addr_copy(vf->dev_lan_addr.addr, vf->legacy_last_added_umac.addr);
	ether_addr_copy(vf->hw_lan_addr.addr, vf->legacy_last_added_umac.addr);
}

/**
 * nse_vfhw_mac_del - update the VF's cached hardware MAC if allowed
 * @vf: VF to update
 * @vc_ether_addr: structure from VIRTCHNL with MAC to delete
 */
static void
nse_vfhw_mac_del(struct nse_vf *vf, struct virtchnl_ether_addr *vc_ether_addr)
{
	u8 *mac_addr = vc_ether_addr->addr;

	if (!is_valid_ether_addr(mac_addr) ||
	    !ether_addr_equal(vf->dev_lan_addr.addr, mac_addr))
		return;

	/* allow the device MAC to be repopulated in the add flow and don't
	 * clear the hardware MAC (i.e. hw_lan_addr.addr) here as that is meant
	 * to be persistent on VM reboot and across driver unload/load, which
	 * won't work if we clear the hardware MAC here
	 */
	eth_zero_addr(vf->dev_lan_addr.addr);

	nse_update_legacy_cached_mac(vf, vc_ether_addr);
}

/**
 * nse_vc_del_mac_addr - attempt to delete the MAC address passed in
 * @vf: pointer to the VF info
 * @vsi: pointer to the VF's VSI
 * @vc_ether_addr: VIRTCHNL MAC address structure used to delete MAC
 */
static int
nse_vc_del_mac_addr(struct nse_vf *vf, struct nse_vsi *vsi,
		    struct virtchnl_ether_addr *vc_ether_addr)
{
	struct device *dev = nse_pf_to_dev(vf->pf);
	u8 *mac_addr = vc_ether_addr->addr;
	enum nse_status status;

	if (!nse_can_vf_change_mac(vf) &&
	    ether_addr_equal(vf->dev_lan_addr.addr, mac_addr))
		return 0;

	status = nse_fltr_remove_mac(vsi, mac_addr, NSE_FWD_TO_VSI);
	if (status == NSE_ERR_DOES_NOT_EXIST) {
		dev_err(dev, "MAC %pM does not exist for VF %d\n", mac_addr,
			vf->vf_id);
		return -ENOENT;
	} else if (status) {
		dev_err(dev, "Failed to delete MAC %pM for VF %d, error %s\n",
			mac_addr, vf->vf_id, nse_stat_str(status));
		return -EIO;
	}

	nse_vfhw_mac_del(vf, vc_ether_addr);

	vf->num_mac--;

	return 0;
}

/**
 * nse_vc_handle_mac_addr_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 * @set: true if MAC filters are being set, false otherwise
 *
 * add guest MAC address filter
 */
static int
nse_vc_handle_mac_addr_msg(struct nse_vf *vf, u8 *msg, bool set)
{
	int (*nse_vc_cfg_mac)
		(struct nse_vf *vf, struct nse_vsi *vsi,
		 struct virtchnl_ether_addr *virtchnl_ether_addr);
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_ether_addr_list *al =
	    (struct virtchnl_ether_addr_list *)msg;
	struct nse_pf *pf = vf->pf;
	enum virtchnl_ops vc_op;
	struct nse_vsi *vsi;
	int i;

	if (set) {
		vc_op = VIRTCHNL_OP_ADD_ETH_ADDR;
		nse_vc_cfg_mac = nse_vc_add_mac_addr;
	} else {
		vc_op = VIRTCHNL_OP_DEL_ETH_ADDR;
		nse_vc_cfg_mac = nse_vc_del_mac_addr;
	}

	if (!test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states) ||
	    !nse_vc_isvalid_vsi_rel_id(vf, al->vsi_rel_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto handle_mac_exit;
	}

	/* If this VF is not privileged, then we can't add more than a
	 * limited number of addresses. Check to make sure that the
	 * additions do not push us over the limit.
	 */
	if (set && !nse_is_vf_trusted(vf) &&
	    (vf->num_mac + al->num_elements) > NSE_MAX_MACADDR_PER_VF) {
		dev_err(nse_pf_to_dev(pf), "Can't add more MAC addresses, because VF-%d is not trusted, switch the VF to trusted mode in order to add more functionalities\n",
			vf->vf_id);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto handle_mac_exit;
	}

	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto handle_mac_exit;
	}

	for (i = 0; i < al->num_elements; i++) {
		u8 *mac_addr = al->list[i].addr;
		int result;

		if (is_broadcast_ether_addr(mac_addr) ||
		    is_zero_ether_addr(mac_addr))
			continue;

		result = nse_vc_cfg_mac(vf, vsi, &al->list[i]);
		if (result == -EEXIST || result == -ENOENT) {
			continue;
		} else if (result) {
			v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
			goto handle_mac_exit;
		}
	}

handle_mac_exit:
	/* send the response to the VF */
	return nse_vc_send_msg_to_vf(vf, vc_op, v_ret, NULL, 0);
}

/**
 * nse_vc_add_mac_addr_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * add guest MAC address filter
 */
static int nse_vc_add_mac_addr_msg(struct nse_vf *vf, u8 *msg)
{
	return nse_vc_handle_mac_addr_msg(vf, msg, true);
}

/**
 * nse_vc_del_mac_addr_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * remove guest MAC address filter
 */
static int nse_vc_del_mac_addr_msg(struct nse_vf *vf, u8 *msg)
{
	return nse_vc_handle_mac_addr_msg(vf, msg, false);
}

/**
 * nse_vc_query_rxdid - query RXDID supported
 * @vf: pointer to VF info
 *
 * Called from VF to query a bitmap of supported flexible
 * descriptor RXDIDs.
 */
static int nse_vc_query_rxdid(struct nse_vf *vf)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_supported_rxdids *rxdid = NULL;
	struct nse_pf *pf = vf->pf;
	int len = 0;
	int ret;

	if (!test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (!(vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	len = sizeof(struct virtchnl_supported_rxdids);
	rxdid = kzalloc(len, GFP_KERNEL);
	if (!rxdid) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		len = 0;
		goto err;
	}

	rxdid->supported_rxdids |= BIT(NSE_RXDID_FLEX_BLANK);
	rxdid->supported_rxdids |= BIT(NSE_RXDID_FLEX_NIC);

	pf->supported_rxdids = rxdid->supported_rxdids;

err:
	ret = nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_GET_SUPPORTED_RXDIDS,
				    v_ret, (u8 *)rxdid, len);
	kfree(rxdid);
	return ret;
}

/**
 * nse_vf_init_vlan_stripping - enable/disable VLAN stripping on initialization
 * @vf: VF to enable/disable VLAN stripping for on initialization
 *
 * Set the default for VLAN stripping based on whether a port VLAN is configured
 * and the current VLAN mode of the device.
 */
static int nse_vf_init_vlan_stripping(struct nse_vf *vf)
{
	struct nse_vsi *vsi = nse_get_vf_vsi(vf);

	vf->vlan_strip_ena = 0;

	if (!vsi)
		return -EINVAL;

	return vsi->inner_vlan_ops.dis_stripping(vsi);
}

static u16 nse_vc_get_max_vlan_fltrs(struct nse_vf *vf)
{
	if (vf->trusted)
		return VLAN_N_VID;
	else
		return NSE_MAX_VLAN_PER_VF;
}

/**
 * nse_vf_outer_vlan_not_allowed - check if outer VLAN can be used
 * @vf: VF that being checked for
 *
 * When the device is in double VLAN mode, check whether or not the outer VLAN
 * is allowed.
 */
static bool nse_vf_outer_vlan_not_allowed(struct nse_vf *vf)
{
	if (nse_vf_is_port_vlan_ena(vf))
		return true;

	return false;
}

/**
 * nse_vc_set_dvm_caps - set VLAN capabilities when the device is in DVM
 * @vf: VF that capabilities are being set for
 * @caps: VLAN capabilities to populate
 *
 * Determine VLAN capabilities support based on whether a port VLAN is
 * configured. If a port VLAN is configured then the VF should use the inner
 * filtering/offload capabilities since the port VLAN is using the outer VLAN
 * capabilies.
 */
static void
nse_vc_set_dvm_caps(struct nse_vf *vf, struct virtchnl_vlan_caps *caps)
{
	struct virtchnl_vlan_supported_caps *supported_caps;
	struct nse_hw *hw = &vf->pf->hw;
	u32 stag_ether_type_flag = (hw->stag_ethertype == ETH_P_8021AD) ?
		VIRTCHNL_VLAN_ETHERTYPE_88A8 : VIRTCHNL_VLAN_ETHERTYPE_8100;

	if (nse_vf_outer_vlan_not_allowed(vf)) {
		supported_caps = &caps->filtering.filtering_support;
		supported_caps->inner = VIRTCHNL_VLAN_UNSUPPORTED;

		supported_caps = &caps->offloads.stripping_support;
		supported_caps->inner = VIRTCHNL_VLAN_ETHERTYPE_8100 |
					VIRTCHNL_VLAN_TOGGLE |
					VIRTCHNL_VLAN_TAG_LOCATION_L2TAG2_2ND;
		supported_caps->outer = VIRTCHNL_VLAN_UNSUPPORTED;

		supported_caps = &caps->offloads.insertion_support;
		supported_caps->inner = VIRTCHNL_VLAN_ETHERTYPE_8100 |
					VIRTCHNL_VLAN_TOGGLE |
					VIRTCHNL_VLAN_TAG_LOCATION_L2TAG1;
		supported_caps->outer = VIRTCHNL_VLAN_UNSUPPORTED;

		caps->offloads.ethertype_init = VIRTCHNL_VLAN_ETHERTYPE_8100;
		caps->offloads.ethertype_match =
			VIRTCHNL_ETHERTYPE_STRIPPING_MATCHES_INSERTION;
	} else {
		supported_caps = &caps->filtering.filtering_support;
		supported_caps->inner = VIRTCHNL_VLAN_UNSUPPORTED;
		supported_caps->outer = stag_ether_type_flag;
		caps->filtering.ethertype_init = stag_ether_type_flag;

		supported_caps = &caps->offloads.stripping_support;
		supported_caps->inner = VIRTCHNL_VLAN_TOGGLE |
					VIRTCHNL_VLAN_ETHERTYPE_8100 |
					VIRTCHNL_VLAN_TAG_LOCATION_L2TAG1;
		supported_caps->outer = VIRTCHNL_VLAN_TOGGLE |
					stag_ether_type_flag |
					VIRTCHNL_VLAN_TAG_LOCATION_L2TAG2_2ND;

		supported_caps = &caps->offloads.insertion_support;

		if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_TDM_ONLY_HANDLE_L2TAG1)) {
			supported_caps->inner = VIRTCHNL_VLAN_UNSUPPORTED;
			supported_caps->outer = VIRTCHNL_VLAN_TOGGLE |
						stag_ether_type_flag |
						VIRTCHNL_VLAN_TAG_LOCATION_L2TAG1;

		} else {	/* default */
			supported_caps->inner = VIRTCHNL_VLAN_TOGGLE |
						VIRTCHNL_VLAN_ETHERTYPE_8100 |
						VIRTCHNL_VLAN_TAG_LOCATION_L2TAG1;
			supported_caps->outer = VIRTCHNL_VLAN_TOGGLE |
						stag_ether_type_flag |
						VIRTCHNL_VLAN_TAG_LOCATION_L2TAG2;
		}

		caps->offloads.ethertype_init = stag_ether_type_flag;

		caps->offloads.ethertype_match =
			VIRTCHNL_ETHERTYPE_STRIPPING_MATCHES_INSERTION;
	}

	caps->filtering.max_filters = nse_vc_get_max_vlan_fltrs(vf);
}

/**
 * nse_vc_get_offload_vlan_v2_caps - determine VF's VLAN capabilities
 * @vf: VF to determine VLAN capabilities for
 *
 * This will only be called if the VF and PF successfully negotiated
 * VIRTCHNL_VF_OFFLOAD_VLAN_V2.
 *
 * Set VLAN capabilities based on the current VLAN mode and whether a port VLAN
 * is configured or not.
 */
static int nse_vc_get_offload_vlan_v2_caps(struct nse_vf *vf)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_vlan_caps *caps = NULL;
	int err, len = 0;

	if (!test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	caps = kzalloc(sizeof(*caps), GFP_KERNEL);
	if (!caps) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		goto out;
	}
	len = sizeof(*caps);

	nse_vc_set_dvm_caps(vf, caps);

	/* store negotiated caps to prevent invalid VF messages */
	memcpy(&vf->vlan_v2_caps, caps, sizeof(*caps));

out:
	err = nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS,
				    v_ret, (u8 *)caps, len);
	kfree(caps);
	return err;
}

/**
 * nse_is_vlan_promisc_allowed - check if VLAN promiscuous config is allowed
 * @vf: VF used to determine if VLAN promiscuous config is allowed
 */
static bool nse_is_vlan_promisc_allowed(struct nse_vf *vf)
{
	if ((test_bit(NSE_VF_STATE_UC_PROMISC, vf->vf_states) ||
	     test_bit(NSE_VF_STATE_MC_PROMISC, vf->vf_states)) &&
	    test_bit(NSE_FLAG_VF_TRUE_PROMISC_ENA, vf->pf->flags))
		return true;

	return false;
}

/**
 * nse_vf_ena_vlan_promisc - Enable Tx/Rx VLAN promiscuous for the VLAN
 * @vf: VF to enable VLAN promisc on
 * @vsi: VF's VSI used to enable VLAN promiscuous mode
 * @vlan: VLAN used to enable VLAN promiscuous
 *
 * This function should only be called if VLAN promiscuous mode is allowed,
 * which can be determined via nse_is_vlan_promisc_allowed().
 */
static int
nse_vf_ena_vlan_promisc(struct nse_vf *vf, struct nse_vsi *vsi,
			struct nse_vlan *vlan)
{
	enum nse_status status;
	u8 promisc_m = 0;

	if (test_bit(NSE_VF_STATE_UC_PROMISC, vf->vf_states))
		promisc_m |= NSE_VF_UCAST_VLAN_PROMISC_BITS;
	if (test_bit(NSE_VF_STATE_MC_PROMISC, vf->vf_states))
		promisc_m |= NSE_MCAST_VLAN_PROMISC_BITS;

	if (!promisc_m)
		return 0;

	status = nse_fltr_set_vsi_promisc(&vsi->back->hw, vsi->idx, promisc_m,
					  vlan->vid);
	if (status && status != NSE_ERR_ALREADY_EXISTS)
		return nse_status_to_errno(status);

	return 0;
}

/**
 * nse_vf_dis_vlan_promisc - Disable Tx/Rx VLAN promiscuous for the VLAN
 * @vf: VF to disable VLAN promisc on
 * @vsi: VF's VSI used to disable VLAN promiscuous mode for
 * @vlan: VLAN used to disable VLAN promiscuous
 *
 * This function should only be called if VLAN promiscuous mode is allowed,
 * which can be determined via nse_is_vlan_promisc_allowed().
 */
static int
nse_vf_dis_vlan_promisc(struct nse_vf *vf, struct nse_vsi *vsi,
			struct nse_vlan *vlan)
{
	u8 promisc_m = NSE_VF_UCAST_VLAN_PROMISC_BITS |
		NSE_MCAST_VLAN_PROMISC_BITS;
	enum nse_status status;

	status = nse_fltr_clear_vsi_promisc(&vsi->back->hw, vsi->idx, promisc_m,
					    vlan->vid);
	if (status && status != NSE_ERR_DOES_NOT_EXIST)
		return nse_status_to_errno(status);

	return 0;
}

/**
 * nse_vc_validate_vlan_tpid - validate VLAN TPID
 * @filtering_caps: negotiated/supported VLAN filtering capabilities
 * @tpid: VLAN TPID used for validation
 *
 * Convert the VLAN TPID to a VIRTCHNL_VLAN_ETHERTYPE_* and then compare against
 * the negotiated/supported filtering caps to see if the VLAN TPID is valid.
 */
static bool nse_vc_validate_vlan_tpid(u16 filtering_caps, u16 tpid)
{
	enum virtchnl_vlan_support vlan_ethertype = VIRTCHNL_VLAN_UNSUPPORTED;

	switch (tpid) {
	case ETH_P_8021Q:
		vlan_ethertype = VIRTCHNL_VLAN_ETHERTYPE_8100;
		break;
	case ETH_P_8021AD:
		vlan_ethertype = VIRTCHNL_VLAN_ETHERTYPE_88A8;
		break;
	}

	if (!(filtering_caps & vlan_ethertype))
		return false;

	return true;
}

/**
 * nse_vc_is_valid_vlan - validate the virtchnl_vlan
 * @vc_vlan: virtchnl_vlan to validate
 *
 * If the VLAN TCI and VLAN TPID are 0, then this filter is invalid, so return
 * false. Otherwise return true.
 */
static bool nse_vc_is_valid_vlan(struct virtchnl_vlan *vc_vlan)
{
	if (!vc_vlan->tci || !vc_vlan->tpid)
		return false;

	return true;
}

/**
 * nse_vc_validate_vlan_filter_list - validate the filter list from the VF
 * @vfc: negotiated/supported VLAN filtering capabilities
 * @vfl: VLAN filter list from VF to validate
 *
 * Validate all of the filters in the VLAN filter list from the VF. If any of
 * the checks fail then return false. Otherwise return true.
 */
static bool
nse_vc_validate_vlan_filter_list(struct virtchnl_vlan_filtering_caps *vfc,
				 struct virtchnl_vlan_filter_list_v2 *vfl)
{
	u16 i;

	if (!vfl->num_elements)
		return false;

	for (i = 0; i < vfl->num_elements; i++) {
		struct virtchnl_vlan_supported_caps *filtering_support =
			&vfc->filtering_support;
		struct virtchnl_vlan_filter *vlan_fltr = &vfl->filters[i];
		struct virtchnl_vlan *outer = &vlan_fltr->outer;
		struct virtchnl_vlan *inner = &vlan_fltr->inner;

		if ((nse_vc_is_valid_vlan(outer) &&
		     filtering_support->outer == VIRTCHNL_VLAN_UNSUPPORTED) ||
		    (nse_vc_is_valid_vlan(inner) &&
		     filtering_support->inner == VIRTCHNL_VLAN_UNSUPPORTED))
			return false;

		if ((outer->tci_mask &&
		     !(filtering_support->outer & VIRTCHNL_VLAN_FILTER_MASK)) ||
		    (inner->tci_mask &&
		     !(filtering_support->inner & VIRTCHNL_VLAN_FILTER_MASK)))
			return false;

		if (((outer->tci & VLAN_PRIO_MASK) &&
		     !(filtering_support->outer & VIRTCHNL_VLAN_PRIO)) ||
		    ((inner->tci & VLAN_PRIO_MASK) &&
		     !(filtering_support->inner & VIRTCHNL_VLAN_PRIO)))
			return false;

		if ((nse_vc_is_valid_vlan(outer) &&
		     !nse_vc_validate_vlan_tpid(filtering_support->outer,
						outer->tpid)) ||
		    (nse_vc_is_valid_vlan(inner) &&
		     !nse_vc_validate_vlan_tpid(filtering_support->inner,
						inner->tpid)))
			return false;
	}

	return true;
}

/**
 * nse_vc_to_vlan - transform from struct virtchnl_vlan to struct nse_vlan
 * @vc_vlan: struct virtchnl_vlan to transform
 */
static struct nse_vlan nse_vc_to_vlan(struct virtchnl_vlan *vc_vlan)
{
	struct nse_vlan vlan = { 0 };

	vlan.prio = (vc_vlan->tci & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT;
	vlan.vid = vc_vlan->tci & VLAN_VID_MASK;
	vlan.tpid = vc_vlan->tpid;

	return vlan;
}

/**
 * nse_vc_vlan_action - action to perform on the virthcnl_vlan
 * @vsi: VF's VSI used to perform the action
 * @vlan_action: function to perform the action with (i.e. add/del)
 * @vlan: VLAN filter to perform the action with
 */
static int
nse_vc_vlan_action(struct nse_vsi *vsi,
		   int (*vlan_action)(struct nse_vsi *, struct nse_vlan *),
		   struct nse_vlan *vlan)
{
	int err;

	err = vlan_action(vsi, vlan);
	if (err)
		return err;

	return 0;
}

/**
 * nse_vc_del_vlans - delete VLAN(s) from the virtchnl filter list
 * @vf: VF used to delete the VLAN(s)
 * @vsi: VF's VSI used to delete the VLAN(s)
 * @vfl: virthchnl filter list used to delete the filters
 */
static int
nse_vc_del_vlans(struct nse_vf *vf, struct nse_vsi *vsi,
		 struct virtchnl_vlan_filter_list_v2 *vfl)
{
	bool vlan_promisc = nse_is_vlan_promisc_allowed(vf);
	int err;
	u16 i;

	for (i = 0; i < vfl->num_elements; i++) {
		struct virtchnl_vlan_filter *vlan_fltr = &vfl->filters[i];
		struct virtchnl_vlan *vc_vlan;

		vc_vlan = &vlan_fltr->outer;
		if (nse_vc_is_valid_vlan(vc_vlan)) {
			struct nse_vlan vlan = nse_vc_to_vlan(vc_vlan);

			err = nse_vc_vlan_action(vsi,
						 vsi->outer_vlan_ops.del_vlan,
						 &vlan);
			if (err)
				return err;

			if (vlan_promisc)
				nse_vf_dis_vlan_promisc(vf, vsi, &vlan);
		}

		vc_vlan = &vlan_fltr->inner;
		if (nse_vc_is_valid_vlan(vc_vlan)) {
			struct nse_vlan vlan = nse_vc_to_vlan(vc_vlan);

			err = nse_vc_vlan_action(vsi,
						 vsi->inner_vlan_ops.del_vlan,
						 &vlan);
			if (err)
				return err;
		}
	}

	return 0;
}

/**
 * nse_vc_remove_vlan_v2_msg - virtchnl handler for VIRTCHNL_OP_DEL_VLAN_V2
 * @vf: VF the message was received from
 * @msg: message received from the VF
 */
static int nse_vc_remove_vlan_v2_msg(struct nse_vf *vf, u8 *msg)
{
	struct virtchnl_vlan_filter_list_v2 *vfl =
		(struct virtchnl_vlan_filter_list_v2 *)msg;
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct nse_vsi *vsi;

	if (!nse_vc_validate_vlan_filter_list(&vf->vlan_v2_caps.filtering,
					      vfl)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	if (!nse_vc_isvalid_vsi_rel_id(vf, vfl->vsi_rel_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	if (nse_vc_del_vlans(vf, vsi, vfl))
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;

out:
	return nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DEL_VLAN_V2, v_ret, NULL,
				     0);
}

/**
 * nse_vc_add_vlans - add VLAN(s) from the virtchnl filter list
 * @vf: VF used to add the VLAN(s)
 * @vsi: VF's VSI used to add the VLAN(s)
 * @vfl: virthchnl filter list used to add the filters
 */
static int
nse_vc_add_vlans(struct nse_vf *vf, struct nse_vsi *vsi,
		 struct virtchnl_vlan_filter_list_v2 *vfl)
{
	bool vlan_promisc = nse_is_vlan_promisc_allowed(vf);
	int err;
	u16 i;

	for (i = 0; i < vfl->num_elements; i++) {
		struct virtchnl_vlan_filter *vlan_fltr = &vfl->filters[i];
		struct virtchnl_vlan *vc_vlan;

		vc_vlan = &vlan_fltr->outer;
		if (nse_vc_is_valid_vlan(vc_vlan)) {
			struct nse_vlan vlan = nse_vc_to_vlan(vc_vlan);

			err = nse_vc_vlan_action(vsi,
						 vsi->outer_vlan_ops.add_vlan,
						 &vlan);
			if (err)
				return err;

			if (vlan_promisc) {
				err = nse_vf_ena_vlan_promisc(vf, vsi, &vlan);
				if (err)
					return err;
			}
		}

		vc_vlan = &vlan_fltr->inner;
		if (nse_vc_is_valid_vlan(vc_vlan)) {
			struct nse_vlan vlan = nse_vc_to_vlan(vc_vlan);

			err = nse_vc_vlan_action(vsi,
						 vsi->inner_vlan_ops.add_vlan,
						 &vlan);
			if (err)
				return err;
		}
	}

	return 0;
}

/**
 * nse_vc_validate_add_vlan_filter_list - validate add filter list from the VF
 * @vsi: VF VSI used to get number of existing VLAN filters
 * @vfc: negotiated/supported VLAN filtering capabilities
 * @vfl: VLAN filter list from VF to validate
 *
 * Validate all of the filters in the VLAN filter list from the VF during the
 * VIRTCHNL_OP_ADD_VLAN_V2 opcode. If any of the checks fail then return false.
 * Otherwise return true.
 */
static bool
nse_vc_validate_add_vlan_filter_list(struct nse_vsi *vsi,
				     struct virtchnl_vlan_filtering_caps *vfc,
				     struct virtchnl_vlan_filter_list_v2 *vfl)
{
	u16 num_requested_filters = nse_vsi_num_non_zero_vlans(vsi) +
		vfl->num_elements;

	if (num_requested_filters > vfc->max_filters)
		return false;

	return nse_vc_validate_vlan_filter_list(vfc, vfl);
}

/**
 * nse_vc_add_vlan_v2_msg - virtchnl handler for VIRTCHNL_OP_ADD_VLAN_V2
 * @vf: VF the message was received from
 * @msg: message received from the VF
 */
static int nse_vc_add_vlan_v2_msg(struct nse_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_vlan_filter_list_v2 *vfl =
		(struct virtchnl_vlan_filter_list_v2 *)msg;
	struct nse_vsi *vsi;

	if (!test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	if (!nse_vc_isvalid_vsi_rel_id(vf, vfl->vsi_rel_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	if (!nse_vc_validate_add_vlan_filter_list(vsi,
						  &vf->vlan_v2_caps.filtering,
						  vfl)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	if (nse_vc_add_vlans(vf, vsi, vfl))
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;

out:
	return nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_ADD_VLAN_V2, v_ret, NULL,
				     0);
}

/**
 * nse_vc_valid_vlan_setting - validate VLAN setting
 * @negotiated_settings: negotiated VLAN settings during VF init
 * @ethertype_setting: ethertype(s) requested for the VLAN setting
 */
static bool
nse_vc_valid_vlan_setting(u32 negotiated_settings, u32 ethertype_setting)
{
	if (ethertype_setting && !(negotiated_settings & ethertype_setting))
		return false;

	/* only allow a single VIRTCHNL_VLAN_ETHERTYPE if
	 * VIRTHCNL_VLAN_ETHERTYPE_AND is not negotiated/supported
	 */
	if (hweight32(ethertype_setting) > 1)
		return false;

	/* ability to modify the VLAN setting was not negotiated */
	if (!(negotiated_settings & VIRTCHNL_VLAN_TOGGLE))
		return false;

	return true;
}

/**
 * nse_vc_valid_vlan_setting_msg - validate the VLAN setting message
 * @caps: negotiated VLAN settings during VF init
 * @msg: message to validate
 *
 * Used to validate any VLAN virtchnl message sent as a
 * virtchnl_vlan_setting structure. Validates the message against the
 * negotiated/supported caps during VF driver init.
 */
static bool
nse_vc_valid_vlan_setting_msg(struct virtchnl_vlan_supported_caps *caps,
			      struct virtchnl_vlan_setting *msg)
{
	if ((!msg->outer_ethertype_setting &&
	     !msg->inner_ethertype_setting) ||
	    (!caps->outer && !caps->inner))
		return false;

	if (msg->outer_ethertype_setting &&
	    !nse_vc_valid_vlan_setting(caps->outer,
				       msg->outer_ethertype_setting))
		return false;

	if (msg->inner_ethertype_setting &&
	    !nse_vc_valid_vlan_setting(caps->inner,
				       msg->inner_ethertype_setting))
		return false;

	return true;
}

/**
 * nse_vc_get_tpid - transform from VIRTCHNL_VLAN_ETHERTYPE_* to VLAN TPID
 * @ethertype_setting: VIRTCHNL_VLAN_ETHERTYPE_* used to get VLAN TPID
 * @tpid: VLAN TPID to populate
 */
static int nse_vc_get_tpid(u32 ethertype_setting, u16 *tpid)
{
	switch (ethertype_setting) {
	case VIRTCHNL_VLAN_ETHERTYPE_8100:
		*tpid = ETH_P_8021Q;
		break;
	case VIRTCHNL_VLAN_ETHERTYPE_88A8:
		*tpid = ETH_P_8021AD;
		break;
	default:
		*tpid = 0;
		return -EINVAL;
	}

	return 0;
}

/**
 * nse_vc_ena_vlan_offload - enable VLAN offload based on the ethertype_setting
 * @vsi: VF's VSI used to enable the VLAN offload
 * @ena_offload: function used to enable the VLAN offload
 * @ethertype_setting: VIRTCHNL_VLAN_ETHERTYPE_* to enable offloads for
 */
static int
nse_vc_ena_vlan_offload(struct nse_vsi *vsi,
			int (*ena_offload)(struct nse_vsi *vsi, u16 tpid),
			u32 ethertype_setting)
{
	u16 tpid;
	int err;

	err = nse_vc_get_tpid(ethertype_setting, &tpid);
	if (err)
		return err;

	err = ena_offload(vsi, tpid);
	if (err)
		return err;

	return 0;
}

/**
 * nse_vc_ena_vlan_stripping_v2_msg
 * @vf: VF the message was received from
 * @msg: message received from the VF
 *
 * virthcnl handler for VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2
 */
static int nse_vc_ena_vlan_stripping_v2_msg(struct nse_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_vlan_supported_caps *stripping_support;
	struct virtchnl_vlan_setting *strip_msg =
		(struct virtchnl_vlan_setting *)msg;
	u32 ethertype_setting;
	struct nse_vsi *vsi;

	if (!test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	if (!nse_vc_isvalid_vsi_rel_id(vf, strip_msg->vsi_rel_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	stripping_support = &vf->vlan_v2_caps.offloads.stripping_support;
	if (!nse_vc_valid_vlan_setting_msg(stripping_support, strip_msg)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	ethertype_setting = strip_msg->outer_ethertype_setting;
	if (ethertype_setting) {
		if (nse_vc_ena_vlan_offload(vsi,
					    vsi->outer_vlan_ops.ena_stripping,
					    ethertype_setting)) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto out;
		} else {
			vf->vlan_strip_ena |= NSE_OUTER_VLAN_STRIP_ENA;
		}
	}

	ethertype_setting = strip_msg->inner_ethertype_setting;
	if (ethertype_setting &&
	    nse_vc_ena_vlan_offload(vsi, vsi->inner_vlan_ops.ena_stripping,
				    ethertype_setting)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	if (ethertype_setting)
		vf->vlan_strip_ena |= NSE_INNER_VLAN_STRIP_ENA;

out:
	return nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2,
				     v_ret, NULL, 0);
}

/**
 * nse_vc_dis_vlan_stripping_v2_msg
 * @vf: VF the message was received from
 * @msg: message received from the VF
 *
 * virthcnl handler for VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2
 */
static int nse_vc_dis_vlan_stripping_v2_msg(struct nse_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_vlan_supported_caps *stripping_support;
	struct virtchnl_vlan_setting *strip_msg =
		(struct virtchnl_vlan_setting *)msg;
	u32 ethertype_setting;
	struct nse_vsi *vsi;

	if (!test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	if (!nse_vc_isvalid_vsi_rel_id(vf, strip_msg->vsi_rel_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	stripping_support = &vf->vlan_v2_caps.offloads.stripping_support;
	if (!nse_vc_valid_vlan_setting_msg(stripping_support, strip_msg)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	ethertype_setting = strip_msg->outer_ethertype_setting;
	if (ethertype_setting) {
		if (vsi->outer_vlan_ops.dis_stripping(vsi)) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto out;
		} else {
			vf->vlan_strip_ena &= ~NSE_OUTER_VLAN_STRIP_ENA;
		}
	}

	ethertype_setting = strip_msg->inner_ethertype_setting;
	if (ethertype_setting && vsi->inner_vlan_ops.dis_stripping(vsi)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	if (ethertype_setting)
		vf->vlan_strip_ena &= ~NSE_INNER_VLAN_STRIP_ENA;

out:
	return nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2,
				     v_ret, NULL, 0);
}

/**
 * nse_vc_ena_vlan_insertion_v2_msg
 * @vf: VF the message was received from
 * @msg: message received from the VF
 *
 * virthcnl handler for VIRTCHNL_OP_ENABLE_VLAN_INSERTION_V2
 */
static int nse_vc_ena_vlan_insertion_v2_msg(struct nse_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_vlan_supported_caps *insertion_support;
	struct virtchnl_vlan_setting *insertion_msg =
		(struct virtchnl_vlan_setting *)msg;
	u32 ethertype_setting;
	struct nse_vsi *vsi;

	if (!test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	if (!nse_vc_isvalid_vsi_rel_id(vf, insertion_msg->vsi_rel_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	insertion_support = &vf->vlan_v2_caps.offloads.insertion_support;
	if (!nse_vc_valid_vlan_setting_msg(insertion_support, insertion_msg)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	ethertype_setting = insertion_msg->outer_ethertype_setting;
	if (ethertype_setting &&
	    nse_vc_ena_vlan_offload(vsi, vsi->outer_vlan_ops.ena_insertion,
				    ethertype_setting)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	ethertype_setting = insertion_msg->inner_ethertype_setting;
	if (ethertype_setting &&
	    nse_vc_ena_vlan_offload(vsi, vsi->inner_vlan_ops.ena_insertion,
				    ethertype_setting)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

out:
	return nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_ENABLE_VLAN_INSERTION_V2,
				     v_ret, NULL, 0);
}

/**
 * nse_vc_dis_vlan_insertion_v2_msg
 * @vf: VF the message was received from
 * @msg: message received from the VF
 *
 * virthcnl handler for VIRTCHNL_OP_DISABLE_VLAN_INSERTION_V2
 */
static int nse_vc_dis_vlan_insertion_v2_msg(struct nse_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_vlan_supported_caps *insertion_support;
	struct virtchnl_vlan_setting *insertion_msg =
		(struct virtchnl_vlan_setting *)msg;
	u32 ethertype_setting;
	struct nse_vsi *vsi;

	if (!test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	if (!nse_vc_isvalid_vsi_rel_id(vf, insertion_msg->vsi_rel_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	insertion_support = &vf->vlan_v2_caps.offloads.insertion_support;
	if (!nse_vc_valid_vlan_setting_msg(insertion_support, insertion_msg)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	ethertype_setting = insertion_msg->outer_ethertype_setting;
	if (ethertype_setting && vsi->outer_vlan_ops.dis_insertion(vsi)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

	ethertype_setting = insertion_msg->inner_ethertype_setting;
	if (ethertype_setting && vsi->inner_vlan_ops.dis_insertion(vsi)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto out;
	}

out:
	return nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DISABLE_VLAN_INSERTION_V2,
				     v_ret, NULL, 0);
}

/**
 * nse_vc_rdma_msg - send msg to RDMA PF from VF
 * @vf: pointer to VF info
 * @msg: pointer to msg buffer
 * @len: length of the message
 *
 * This function is called indirectly from the AQ clean function.
 */
static int nse_vc_rdma_msg(struct nse_vf *vf, u8 *msg, u16 len)
{
	struct nse_pf *pf = vf->pf;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	struct iidc_core_dev_info *rcdi;
	struct iidc_auxiliary_drv *iadrv;
	int ret = -ENODEV;

	nse_debug(hw, NSE_DBG_RDMA, "[%s] vf (id=%d)\n", __func__, vf->vf_id);

	rcdi = nse_find_cdev_info_by_id(vf->pf, IIDC_RDMA_ID);
	if (!rcdi) {
		dev_err(dev, "[%s] Invalid RDMA peer attempted to send message to peer\n",
			__func__);
		return -EIO;
	}

	mutex_lock(&vf->pf->adev_mutex);
	device_lock(&rcdi->adev->dev);
	iadrv = nse_get_auxiliary_drv(rcdi);

	nse_debug(hw, NSE_DBG_RDMA, "[%s] iadrv=%p\n", __func__, iadrv);

	if (iadrv && iadrv->vc_receive) {
		u16 vf_abs_id = nse_abs_vf_id(&vf->pf->hw, vf->vf_id);

		nse_debug(hw, NSE_DBG_RDMA, "[%s] iadrv->vc_receive(vf_abs_id=%d)\n",
			  __func__, vf_abs_id);

		ret = iadrv->vc_receive(rcdi, vf_abs_id, msg, len);
	}
	device_unlock(&rcdi->adev->dev);
	mutex_unlock(&vf->pf->adev_mutex);
	if (ret)
		dev_err(dev, "[%s] Failed to send message to RDMA peer, ret=%d\n",
			__func__, ret);

	return ret;
}

/**
 * ice_vc_cfg_rdma_irq_map_msg - MSIX mapping of RDMA control queue interrupts
 * @vf: VF structure associated to the VF that requested the mapping
 * @msg: Message from the VF used to configure the RDMA mapping
 *
 * Handler for the VIRTCHNL_OP_CONFIG_RDMA_IRQ_MAP opcode in virtchnl. This
 * causes the specified control queues to be mapped to the specified MSIX
 * indices and ITR indices. Also, the control queue's interrupt will be
 * enabled.
 */
static int nse_vc_cfg_rdma_irq_map_msg(struct nse_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_rdma_qvlist_info *qvlist =
		(struct virtchnl_rdma_qvlist_info *)msg;
	const struct nse_vf_ops *ops = vf->vf_ops;
	u16 num_msix_per_vf;
	u32 i;

	if (!test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	num_msix_per_vf = vf->pf->vfs.num_msix_per;
	if (qvlist->num_vectors > num_msix_per_vf) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	for (i = 0; i < qvlist->num_vectors; i++) {
		struct virtchnl_rdma_qv_info *qv_info = &qvlist->qv_info[i];

		if (qv_info->v_idx >= num_msix_per_vf) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto err;
		}

		if (qv_info->ceq_idx == VIRTCHNL_RDMA_INVALID_QUEUE_IDX &&
		    qv_info->aeq_idx == VIRTCHNL_RDMA_INVALID_QUEUE_IDX) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto err;
		}

		if (qv_info->ceq_idx != VIRTCHNL_RDMA_INVALID_QUEUE_IDX &&
		    qv_info->ceq_idx >= num_msix_per_vf) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto err;
		}

		if (qv_info->aeq_idx != VIRTCHNL_RDMA_INVALID_QUEUE_IDX &&
		    qv_info->aeq_idx >= num_msix_per_vf) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto err;
		}
	}

	for (i = 0; i < qvlist->num_vectors; i++) {
		struct virtchnl_rdma_qv_info *qv_info = &qvlist->qv_info[i];

		ops->cfg_rdma_irq_map(vf, qv_info);
	}

err:
	return nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_RDMA_IRQ_MAP,
				     v_ret, NULL, 0);
}

/**
 * nse_vc_clear_rdma_irq_map - clear mapped RDMA control queue interrupts
 * @vf: VF structure associated to the VF that requested to release the mapping
 *
 * Handler for the VIRTCHNL_OP_RELEASE_RDMA_IRQ_MAP opcode in virtchnl. This
 * causes all of the MSIX mapping of all the RDMA control queues to be cleared
 * and disabled.
 */
static int nse_vc_clear_rdma_irq_map(struct nse_vf *vf)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	const struct nse_vf_ops *ops = vf->vf_ops;

	if (!test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	ops->clear_rdma_irq_map(vf);

err:
	return nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_RELEASE_RDMA_IRQ_MAP,
				     v_ret, NULL, 0);
}

static const struct nse_virtchnl_ops nse_virtchnl_dflt_ops = {
	.get_ver_msg = nse_vc_get_ver_msg,
	.get_vf_res_msg = nse_vc_get_vf_res_msg,
	.reset_vf = nse_vc_reset_vf_msg,
	.reset_vf_rdma = nse_vc_reset_vf_rdma_msg,
	.add_mac_addr_msg = nse_vc_add_mac_addr_msg,
	.del_mac_addr_msg = nse_vc_del_mac_addr_msg,
	.cfg_qs_msg = nse_vc_cfg_qs_msg,
	.ena_qs_msg = nse_vc_ena_qs_msg,
	.dis_qs_msg = nse_vc_dis_qs_msg,
	.get_qp_info = nse_vc_get_queue_info,
	.cfg_irq_map_msg = nse_vc_cfg_irq_map_msg,
	.config_rss_key = nse_vc_config_rss_key,
	.config_rss_lut = nse_vc_config_rss_lut,
	.config_rss_alg = nse_vc_config_rss_alg,
	.set_fdir_input_mask = nse_vc_set_fdir_input_mask,
	.set_logall_bitmap = nse_vc_set_logall,
	.get_stats_msg = nse_vc_get_stats_msg,
	.cfg_promiscuous_mode_msg = nse_vc_cfg_promiscuous_mode_msg,
	.query_rxdid = nse_vc_query_rxdid,
	.rdma_msg = nse_vc_rdma_msg,
	.cfg_rdma_irq_map_msg = nse_vc_cfg_rdma_irq_map_msg,
	.clear_rdma_irq_map = nse_vc_clear_rdma_irq_map,
	.get_offload_vlan_v2_caps = nse_vc_get_offload_vlan_v2_caps,
	.add_vlan_v2_msg = nse_vc_add_vlan_v2_msg,
	.remove_vlan_v2_msg = nse_vc_remove_vlan_v2_msg,
	.ena_vlan_stripping_v2_msg = nse_vc_ena_vlan_stripping_v2_msg,
	.dis_vlan_stripping_v2_msg = nse_vc_dis_vlan_stripping_v2_msg,
	.ena_vlan_insertion_v2_msg = nse_vc_ena_vlan_insertion_v2_msg,
	.dis_vlan_insertion_v2_msg = nse_vc_dis_vlan_insertion_v2_msg,
};

/**
 * nse_virtchnl_set_dflt_ops - Switch to default virtchnl ops
 * @vf: the VF to switch ops
 */
void nse_virtchnl_set_dflt_ops(struct nse_vf *vf)
{
	vf->virtchnl_ops = &nse_virtchnl_dflt_ops;
}

/**
 * nse_vc_repr_add_mac
 * @vf: pointer to VF
 * @msg: virtchannel message
 *
 * When port representors are created, we do not add MAC rule
 * to firmware, we store it so that PF could report same
 * MAC as VF.
 */
static int nse_vc_repr_add_mac(struct nse_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_ether_addr_list *al =
	    (struct virtchnl_ether_addr_list *)msg;
	struct nse_vsi *vsi;
	struct nse_pf *pf;
	int i;

	if (!test_bit(NSE_VF_STATE_ACTIVE, vf->vf_states) ||
	    !nse_vc_isvalid_vsi_rel_id(vf, al->vsi_rel_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto handle_mac_exit;
	}

	pf = vf->pf;

	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto handle_mac_exit;
	}

	for (i = 0; i < al->num_elements; i++) {
		u8 *mac_addr = al->list[i].addr;

		if (!is_unicast_ether_addr(mac_addr) ||
		    ether_addr_equal(mac_addr, vf->hw_lan_addr.addr))
			continue;

		if (vf->pf_set_mac) {
			dev_err(nse_pf_to_dev(pf), "VF attempting to override administratively set MAC address\n");
			v_ret = VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
			goto handle_mac_exit;
		}

		nse_vfhw_mac_add(vf, &al->list[i]);
		vf->num_mac++;
		break;
	}

handle_mac_exit:
	return nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_ADD_ETH_ADDR,
				     v_ret, NULL, 0);
}

/**
 * nse_vc_repr_del_mac - response with success for deleting MAC
 * @vf: pointer to VF
 * @msg: virtchannel message
 *
 * Respond with success to not break normal VF flow.
 * For legacy VF driver try to update cached MAC address.
 */
static int
nse_vc_repr_del_mac(struct nse_vf *vf, u8 *msg)
{
	struct virtchnl_ether_addr_list *al =
		(struct virtchnl_ether_addr_list *)msg;

	nse_update_legacy_cached_mac(vf, &al->list[0]);

	return nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DEL_ETH_ADDR,
				     VIRTCHNL_STATUS_SUCCESS, NULL, 0);
}

static int
nse_vc_repr_cfg_promiscuous_mode(struct nse_vf *vf, u8 __always_unused *msg)
{
	dev_info(nse_pf_to_dev(vf->pf),
		"Can't config promiscuous mode in switchdev mode for VF %d\n",
		vf->vf_id);
	return nse_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE,
				     VIRTCHNL_STATUS_ERR_NOT_SUPPORTED,
				     NULL, 0);
}

static const struct nse_virtchnl_ops nse_virtchnl_repr_ops = {
	.get_ver_msg = nse_vc_get_ver_msg,
	.get_vf_res_msg = nse_vc_get_vf_res_msg,
	.reset_vf = nse_vc_reset_vf_msg,
	.reset_vf_rdma = nse_vc_reset_vf_rdma_msg,
	.add_mac_addr_msg = nse_vc_repr_add_mac,
	.del_mac_addr_msg = nse_vc_repr_del_mac,
	.cfg_qs_msg = nse_vc_cfg_qs_msg,
	.ena_qs_msg = nse_vc_ena_qs_msg,
	.dis_qs_msg = nse_vc_dis_qs_msg,
	.get_qp_info = nse_vc_get_queue_info,
	.cfg_irq_map_msg = nse_vc_cfg_irq_map_msg,
	.config_rss_key = nse_vc_config_rss_key,
	.config_rss_lut = nse_vc_config_rss_lut,
	.config_rss_alg = nse_vc_config_rss_alg,
	.set_fdir_input_mask = nse_vc_set_fdir_input_mask,
	.set_logall_bitmap = nse_vc_set_logall,
	.get_stats_msg = nse_vc_get_stats_msg,
	.cfg_promiscuous_mode_msg = nse_vc_repr_cfg_promiscuous_mode,
	.query_rxdid = nse_vc_query_rxdid,
	.rdma_msg = nse_vc_rdma_msg,
	.cfg_rdma_irq_map_msg = nse_vc_cfg_rdma_irq_map_msg,
	.clear_rdma_irq_map = nse_vc_clear_rdma_irq_map,
	.get_offload_vlan_v2_caps = nse_vc_get_offload_vlan_v2_caps,
	.add_vlan_v2_msg = nse_vc_add_vlan_v2_msg,
	.remove_vlan_v2_msg = nse_vc_remove_vlan_v2_msg,
	.ena_vlan_stripping_v2_msg = nse_vc_ena_vlan_stripping_v2_msg,
	.dis_vlan_stripping_v2_msg = nse_vc_dis_vlan_stripping_v2_msg,
	.ena_vlan_insertion_v2_msg = nse_vc_ena_vlan_insertion_v2_msg,
	.dis_vlan_insertion_v2_msg = nse_vc_dis_vlan_insertion_v2_msg,
};

/**
 * nse_virtchnl_set_repr_ops - Switch to representor virtchnl ops
 * @vf: the VF to switch ops
 */
void nse_virtchnl_set_repr_ops(struct nse_vf *vf)
{
	vf->virtchnl_ops = &nse_virtchnl_repr_ops;
}

/**
 * nse_vc_process_vf_msg - Process request from VF
 * @pf: pointer to the PF structure
 * @event: pointer to the AQ event
 *
 * called from the common asq/arq handler to
 * process request from VF
 */
void nse_vc_process_vf_msg(struct nse_pf *pf, struct nse_rq_event_info *event)
{
	struct nse_hw *hw = &pf->hw;
	u16 msglen = event->msg_len;
	u8 *msg = event->msg_buf;
	u16 real_msglen;
	u8 *real_msg;
	u32 v_opcode;
	u16 vsi_abs_id = le16_to_cpu(event->desc.mailbox_id);
	const struct nse_virtchnl_ops *ops;
	struct nse_aqc_mbx_cmd_buff_hdr *hdr = NULL;
	struct nse_vf *vf = NULL;
	struct device *dev = nse_pf_to_dev(pf);
	int vc_err = 0;
	int err = 0;

	if (msglen < sizeof(struct nse_aqc_mbx_cmd_buff_hdr) || msg == NULL) {
		dev_err(dev, "No valid msg buff from VF (vf_vsi_abs_id=%d), len %d\n",
			vsi_abs_id, msglen);
		return;
	}

	hdr = (struct nse_aqc_mbx_cmd_buff_hdr *)msg;
	v_opcode = le32_to_cpu(hdr->cookie_high);

	/* for clearness, not use (hdr + 1) */
	real_msg = msg + sizeof(struct nse_aqc_mbx_cmd_buff_hdr);
	real_msglen = msglen - sizeof(struct nse_aqc_mbx_cmd_buff_hdr);

	vf = nse_get_vf_by_vsi_abs_id(pf, vsi_abs_id);
	if (!vf) {
		dev_err(dev, "Unable to locate VF for message from vf_vsi_abs_id=%d, opcode %d, len %d\n",
			vsi_abs_id, v_opcode, msglen);
		return;
	}

	if (event->src == NSE_RQ_EVENT_INFO_SRC_MSGBOX)
		vf->use_pv_msgbox = 1;
	else
		vf->use_pv_msgbox = 0;

	mutex_lock(&vf->cfg_lock);

	/* Check if VF is disabled. */
	if (test_bit(NSE_VF_STATE_DIS, vf->vf_states)) {
		dev_err(dev, "Unable to serve VF (vf_vsi_abs_id=%d), its vf_states is VF_STATE_DIS\n",
			vsi_abs_id);
		err = -EPERM;
		vc_err = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_handler;
	}

	ops = vf->virtchnl_ops;

	/* Perform basic checks on the msg */
	vc_err = virtchnl_vc_validate_vf_msg(&vf->vf_ver, v_opcode, real_msg, real_msglen);
	if (vc_err) {
		nse_debug(hw, NSE_DBG_SRIOV, "[%s] fail: vc_validate_vf_msg(vf=%d, v_opcode=%d, real_msglen=%d), ret=%d",
								__func__, vf->vf_id, v_opcode,
									real_msglen, vc_err);

		if (vc_err == VIRTCHNL_STATUS_ERR_PARAM)
			err = -EPERM;
		else
			err = -EINVAL;
	}

error_handler:
	if (err) {
		nse_vc_send_msg_to_vf(vf, v_opcode, vc_err,
				      NULL, 0);
		nse_dev_err_errno(dev, err,
				  "Invalid message from VF (vf_vsi_abs_id=%d), opcode %d, msglen %d, real_msglen %d, vc_err %d",
				  vsi_abs_id, v_opcode, msglen, real_msglen, vc_err);
		goto finish;
	}

	if (!nse_vc_is_opcode_allowed(vf, v_opcode)) {
		dev_err(dev, "Unallowed op (%d) from VF (vf_vsi_abs_id=%d)\n",
			v_opcode, vsi_abs_id);
		nse_vc_send_msg_to_vf(vf, v_opcode,
				      VIRTCHNL_STATUS_ERR_NOT_SUPPORTED, NULL,
				      0);
		goto finish;
	}

	nse_debug(hw, NSE_DBG_SRIOV, "[%s] handle vch-req: %d (%s), from VF (vf_id=%d)\n",
								__func__, v_opcode,
									virtchnl_op_str(v_opcode),
									vf->vf_id);

	switch (v_opcode) {
	case VIRTCHNL_OP_VERSION:
		err = ops->get_ver_msg(vf, real_msg);
		break;
	case VIRTCHNL_OP_GET_VF_RESOURCES:
		err = ops->get_vf_res_msg(vf, real_msg);
		if (nse_vf_init_vlan_stripping(vf))
			dev_dbg(dev, "Failed to initialize VLAN stripping for VF %d\n",
				vf->vf_id);
		/*  don't send link state for now, if VF is using PV msgbox, otherwise would mess VF
		 * nsevf_init_process_extended_caps()
		 */
		if (!vf->use_pv_msgbox)
			nse_vc_notify_vf_link_state(vf, false);

		break;
	case VIRTCHNL_OP_RESET_VF:
		ops->reset_vf(vf);
		break;
	case VIRTCHNL_OP_RESET_VF_RDMA:
		ops->reset_vf_rdma(vf);
		break;
	case VIRTCHNL_OP_ADD_ETH_ADDR:
		err = ops->add_mac_addr_msg(vf, real_msg);
		break;
	case VIRTCHNL_OP_DEL_ETH_ADDR:
		err = ops->del_mac_addr_msg(vf, real_msg);
		break;
	case VIRTCHNL_OP_CONFIG_VSI_QUEUES:
		err = ops->cfg_qs_msg(vf, real_msg);
		break;
	case VIRTCHNL_OP_ENABLE_QUEUES:
		err = ops->ena_qs_msg(vf, real_msg);
		/* don't send link state for now, if VF is using PV msgbox, otherwise would
		 * mess VF nsevf_init_process_extended_caps()
		 */
		if (!vf->use_pv_msgbox)
			nse_vc_notify_vf_link_state(vf, true);
		break;
	case VIRTCHNL_OP_DISABLE_QUEUES:
		err = ops->dis_qs_msg(vf, real_msg);
		break;
	case VIRTCHNL_OP_QUERY_QUEUE_INFO:
		err = ops->get_qp_info(vf, real_msg);
		break;
	case VIRTCHNL_OP_CONFIG_IRQ_MAP:
		err = ops->cfg_irq_map_msg(vf, real_msg);
		break;
	case VIRTCHNL_OP_CONFIG_RSS_KEY:
		err = ops->config_rss_key(vf, real_msg);
		break;
	case VIRTCHNL_OP_CONFIG_RSS_LUT:
		err = ops->config_rss_lut(vf, real_msg);
		break;
	case VIRTCHNL_OP_CONFIG_RSS_ALG:
		err = ops->config_rss_alg(vf, real_msg);
		break;
	case VIRTCHNL_OP_SET_FDIR_INPUT_MASK:
		err = ops->set_fdir_input_mask(vf, real_msg);
		break;
	case VIRTCHNL_OP_SET_LOGALL_BITMAP:
		err = ops->set_logall_bitmap(vf, real_msg);
		break;
	case VIRTCHNL_OP_GET_STATS:
		err = ops->get_stats_msg(vf, real_msg);
		break;
	case VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE:
		err = ops->cfg_promiscuous_mode_msg(vf, real_msg);
		break;
	case VIRTCHNL_OP_GET_SUPPORTED_RXDIDS:
		err = ops->query_rxdid(vf);
		break;
	case VIRTCHNL_OP_RDMA:
		err = ops->rdma_msg(vf, real_msg, real_msglen);
		break;
	case VIRTCHNL_OP_CONFIG_RDMA_IRQ_MAP:
		err = ops->cfg_rdma_irq_map_msg(vf, real_msg);
		break;
	case VIRTCHNL_OP_RELEASE_RDMA_IRQ_MAP:
		err = ops->clear_rdma_irq_map(vf);
		break;
	case VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS:
		err = ops->get_offload_vlan_v2_caps(vf);
		break;
	case VIRTCHNL_OP_ADD_VLAN_V2:
		err = ops->add_vlan_v2_msg(vf, real_msg);
		break;
	case VIRTCHNL_OP_DEL_VLAN_V2:
		err = ops->remove_vlan_v2_msg(vf, real_msg);
		break;
	case VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2:
		err = ops->ena_vlan_stripping_v2_msg(vf, real_msg);
		break;
	case VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2:
		err = ops->dis_vlan_stripping_v2_msg(vf, real_msg);
		break;
	case VIRTCHNL_OP_ENABLE_VLAN_INSERTION_V2:
		err = ops->ena_vlan_insertion_v2_msg(vf, real_msg);
		break;
	case VIRTCHNL_OP_DISABLE_VLAN_INSERTION_V2:
		err = ops->dis_vlan_insertion_v2_msg(vf, real_msg);
		break;
	case VIRTCHNL_OP_UNKNOWN:
	default:
		dev_err(dev, "Unsupported opcode %d from VF(vf_id=%d, vf_vsi_abs_id=%d)\n",
			v_opcode,
			vf->vf_id, vf->vf_vsi_abs_id);
		err = nse_vc_send_msg_to_vf(vf, v_opcode,
					    VIRTCHNL_STATUS_ERR_NOT_SUPPORTED,
					    NULL, 0);
		break;
	}
	if (err) {
		/* Helper function cares less about error return values here
		 * as it is busy with pending work.
		 */
		dev_info(dev, "PF failed to honor VF(vf_id=%d, vf_vsi_abs_id=%d), opcode %d, error %d\n",
			 vf->vf_id, vf->vf_vsi_abs_id, v_opcode, err);
	}

finish:
	mutex_unlock(&vf->cfg_lock);
	nse_put_vf(vf);
}

