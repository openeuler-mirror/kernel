// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include "mce.h"
#include "mce_virtchnl.h"

int mce_broadcast_event_to_vf(struct mce_pf *pf, enum PF2VF_EVENT_ID event,
			      int timeout_us)
{
	int ret = 0, vfd;

	pf->hw.ops->update_pf_stat(&pf->hw);

	for (vfd = 0; vfd < pf->num_vfs; vfd++) {
		ret |= mce_mbx_send_event_to_vf(&pf->hw, vfd, event,
						timeout_us);
	}
	return ret;
}

int mce_broadcast_cmd_to_vf(struct mce_pf *pf, enum PF2VF_OPCODE opcode,
			    int *data, int data_bytes, int timeout_us)
{
	int vfd, ret = 0;

	pf->hw.ops->update_pf_stat(&pf->hw);

	for (vfd = 0; vfd < pf->num_vfs; vfd++) {
		ret |= mce_mbx_send_cmd_to_vf(&pf->hw, vfd, opcode, data,
					      data_bytes, NULL, timeout_us);
	}
	return ret;
}

int mce_mbx_send_reset_vf_cmd(struct mce_pf *pf, int vfd)
{
	struct mce_mbx_info *mbx = &pf->hw.vf_mbx[vfd];

	mce_mbx_clear_vf_reset_done_stat(mbx);
	return mce_mbx_send_event_to_vf(&pf->hw, vfd, EVT_PF_RESET_VF, 1000);
}

void mce_vf_notify_link_state(struct mce_pf *pf)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);
	enum PF2VF_EVENT_ID event;
	int vfid;

	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return;

	mce_for_each_vf_id(pf, vfid) {
		switch (vf->vfinfo[vfid].link_state) {
		case mce_link_state_on:
			event = EVT_PF_FORCE_VF_LINK_UP;
			break;
		case mce_link_state_off:
			event = EVT_PF_FORCE_VF_LINK_DOWN;
			break;
		case mce_link_state_auto:
			event = EVT_PF_LINK_CHANGED;
			break;
		default:
			event = EVT_PF_FORCE_VF_LINK_UP;
			break;
		}
		mce_mbx_send_event_to_vf(&pf->hw, vfid, event, 1000);
	}
}

void mce_vf_notify_fcs_state(struct mce_pf *pf, bool on)
{
	enum PF2VF_EVENT_ID event;
	int vfid;

	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return;
	event = on ? EVT_PF_FORECE_FCS_ON : EVT_PF_FORECE_FCS_OFF;
	mce_for_each_vf_id(pf, vfid)
		mce_mbx_send_event_to_vf(&pf->hw, vfid, event, 1000);
}

void mce_vf_notify_spoof_state(struct mce_pf *pf, int vfid, bool on)
{
	enum PF2VF_EVENT_ID event;

	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return;
	event = on ? EVT_PF_FORECE_SPOOF_ON : EVT_PF_FORECE_SPOOF_OFF;
	mce_mbx_send_event_to_vf(&pf->hw, vfid, event, 1000);
}

void mce_vf_notify_dscp_state(struct mce_pf *pf, int vfid, bool on)
{
	enum PF2VF_EVENT_ID event;

	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return;
	event = on ? EVT_PF_DSCP_ON : EVT_PF_DSCP_OFF;
	mce_mbx_send_event_to_vf(&pf->hw, vfid, event, 1000);
}

void mce_vf_notify_trust_state(struct mce_pf *pf, int vfid, bool on)
{
	enum PF2VF_EVENT_ID event;

	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return;
	event = on ? EVT_PF_TRUST_ON : EVT_PF_TRUST_OFF;
	mce_mbx_send_event_to_vf(&pf->hw, vfid, event, 1000);
}

static int mce_vf_reset_msg(struct mce_hw *hw, u32 vfid, struct mbx_req *req,
			    struct mbx_resp *resp, struct vf_info *vfinfo)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct net_device *netdev = mce_get_main_net_dev(pf);
	u8 *mac_addr = (u8 *)(&resp->data[F_VF_MAC_ADDR]);
	unsigned char *vf_mac = vfinfo->vf_mac_addr;
	struct mce_port_info *pi = hw->port_info;
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct mce_dcb *dcb = pf->dcb;
	u32 t_data = 0;

	/* Clear VF IPv4 address on driver reload */
	vfinfo->vf_ipv4_addr = 0;

	if (is_valid_ether_addr(vf_mac)) {
		memcpy(mac_addr, vf_mac, ETH_ALEN);
	} else {
		dev_warn(mce_hw_to_dev(hw),
			 "VF %d has no MAC address assigned,use random mac-addr\n",
			vfid);
		eth_random_addr(vfinfo->vf_mac_addr);
		vfinfo->vf_mac_addr[4] = vfid | (hw->pfvfnum.pf << 7);
		memcpy(mac_addr, vf_mac, ETH_ALEN);
	}

	/* enable VF mailbox for further messages */
	resp->data[F_VF_RESET_RING_MAX_CNT] = hw->ring_max_cnt;
	resp->data[F_VF_RESET_FW_VERSION] = hw->fw_version;
	resp->data[F_VF_RESET_VLAN] = vfinfo->pf_vlan & 0xfff;
	if (vfinfo->pf_vlan_proto == ETH_P_8021AD)
		resp->data[F_VF_RESET_VLAN] |= BIT(31);
	t_data = pi->link_speed;
	t_data |= MCE_PF_LINK_UP;
	resp->data[F_VF_RESET_LINK_ST] = t_data;
	resp->data[F_VF_RESET_AXI_MHZ] = hw->axi_mhz;
	resp->data[F_VF_NR_PF] = hw->nr_pf;
	resp->data[F_VF_STATE] = 0;
	if (netdev->features & NETIF_F_RXFCS)
		resp->data[F_VF_STATE] |= BIT(VF_FCS_BIT);
	if (vfinfo->spoofchk_enabled)
		resp->data[F_VF_STATE] |= BIT(VF_SPOOF_BIT);
	if (vfinfo->trusted)
		resp->data[F_VF_STATE] |= BIT(VF_TRUST_BIT);
	if (hw->rdma_bar_base)
		resp->data[F_VF_STATE] |= BIT(VF_RDMA_BIT);
	if (test_bit(MCE_DSCP_EN, dcb->flags))
		resp->data[F_VF_STATE] |= BIT(VF_DSCP_BIT);

	if (test_bit(MCE_PFC_EN, dcb->flags)) {
		resp->data[F_VF_STATE] |= BIT(VF_PFC_BIT);
		/* copy pfc setup */
	}
	resp->cmd.arg_cnts = F_VF_RESET_RESP_CNT;

	ether_addr_copy(vf->t_info.macaddr, vf_mac);

	if (!pf->switchdev.is_running) {
		vf->t_info.bcmc_bitmap = MCE_F_SET;
		mce_vf_set_veb_misc_rule(hw, vfid, VEB_POLICY_TYPE_UC_ADD_MACADDR_WITH_ACT);
	}

	hw->ops->update_pf_stat(hw);
	hw->ops->update_fw_stat(hw);
	return 0;
}

static int mce_vf_qos_msg(struct mce_hw *hw, struct mbx_req *req,
			  struct mbx_resp *resp)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct mce_dcb *dcb = pf->dcb;
	struct mce_tc_cfg *tccfg = &dcb->cur_tccfg;

	/* copy pfc setup */
	memcpy((u8 *)&resp->data[F_VF_PFC_BASE], tccfg->pfc_txq_base[0], 16);
	memcpy((u8 *)&resp->data[F_VF_PFC_COUNT], tccfg->pfc_txq_count[0], 16);
	resp->data[F_VF_VALID_PRIO] = vsi->valid_prio;
	resp->cmd.arg_cnts = F_VF_QOS_RESP_CNT;

	return 0;
}

static int mce_vf_dscp_msg(struct mce_hw *hw, struct mbx_req *req,
			   struct mbx_resp *resp, bool is_low)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_dcb *dcb = pf->dcb;

	/* copy dscp setup */
	if (is_low)
		memcpy((u8 *)&resp->data[0], dcb->dscp_map, 32);
	else
		memcpy((u8 *)&resp->data[0], dcb->dscp_map + 32, 32);
	/* 32 bytes data */
	resp->cmd.arg_cnts = 8;

	return 0;
}

static int mce_vc_set_vlan(struct mce_pf *pf, int vfid, unsigned int *msg)
{
	int add = msg[0];
	int vid = msg[1];
	int err = 0;

	if (vid) {
		if (add)
			err = mce_vf_setup_flr_vlan(pf, vfid, vid);
		else
			err = mce_vf_del_flr_vlan(pf, vfid, vid);
	}
	return err;
}

static int mce_vc_set_vlan_strip(struct mce_pf *pf, int vfid, unsigned int *msg)
{
	/* VF VLAN stripping is not implemented yet. */
	return 0;
}

static int mce_vc_set_mac_addr(struct mce_pf *pf, int vfid, unsigned int *msg)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct mce_hw *hw = &pf->hw;
	struct vf_info *vfinfo;
	u8 *mac_addr;

	if (pf->switchdev.is_running)
		return -EOPNOTSUPP;

	mac_addr = (u8 *)(&msg[0]);
	if (!is_valid_ether_addr(mac_addr)) {
		dev_err(mce_hw_to_dev(hw),
			"VF %d attempted to set invalid mac addr\n", vfid);
		return -EINVAL;
	}

	vfinfo = &vf->vfinfo[vfid];

	if (mce_check_vf_mac_conflict(pf, vfid, mac_addr, vfinfo->pf_vlan))
		return -EEXIST;

	ether_addr_copy(vfinfo->vf_mac_addr, mac_addr);
	ether_addr_copy(vf->t_info.macaddr, mac_addr);
	vf->t_info.bcmc_bitmap = MCE_F_HOLD;

	mce_vf_set_veb_misc_rule(hw, vfid,
				 VEB_POLICY_TYPE_UC_ADD_MACADDR_WITH_ACT);
	/* Update antispoof mac addr */
	hw->vf.ops->set_vf_spoofchk_mac(hw, vfid, vfinfo->spoofchk_enabled,
					true);
	return 0;
}

static int mce_vc_set_promisc_mode(struct mce_pf *pf, int vfid,
				   unsigned int *msg)
{
	u32 flags = msg[0];

	switch (flags) {
	case FLAG_VF_NONE_PROMISC:
		break;
	case FLAG_VF_MULTICAST_PROMISC:
		break;
	case FLAG_VF_UNICAST_PROMISC | FLAG_VF_MULTICAST_PROMISC:
		break;

	default:
		break;
	}
	return 0;
}

static int mce_vc_handle_macvlan_addr(struct mce_hw *hw, int vfid,
				      unsigned int *msg, bool add)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	enum veb_policy_type type;
	u8 *mac_addr;

	mac_addr = (u8 *)(&msg[1]);
	if (!is_valid_ether_addr(mac_addr)) {
		dev_err(mce_hw_to_dev(hw),
			"VF %d attempted to set invalid mac addr\n", vfid);
		return -EINVAL;
	}

	ether_addr_copy(vf->t_info.macaddr, mac_addr);
	vf->t_info.index = msg[0];
	vf->t_info.bcmc_bitmap = MCE_F_HOLD;

	if (add)
		type = VEB_POLICY_TYPE_MACVLAN_ADD_MACADDR_WITH_ACT;
	else
		type = VEB_POLICY_TYPE_MACVLAN_DEL_MACADDR_WITH_ACT;
	return mce_vf_set_veb_misc_rule(hw, vfid, type);
}

static int mce_vc_notify_ring_cnt(struct mce_hw *hw, int vfid,
				  unsigned int *msg)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int ring_cnt = msg[0];

	if (mce_check_vf_redir_filters_active(&vf->vfinfo[vfid]))
		return -1;
	vf->vfinfo[vfid].ring_cnt = ring_cnt;
	if (test_bit(MCE_FLAG_VF_TX_MAXRATE_ENA, vf->vfinfo[vfid].flags))
		hw->vf.ops->set_vf_bw_qg_ctrl(pf, vfid, ring_cnt);
	return 0;
}

static int mce_vc_set_ipv4_addr(struct mce_pf *pf, int vfid, unsigned int *msg)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct mce_hw *hw = &pf->hw;
	struct vf_info *vfinfo;
	int err = 0, ovf;
	__be32 ipv4_addr;

	vfinfo = &vf->vfinfo[vfid];
	ipv4_addr = (__force __be32)msg[0];

	/* Check for IP address conflict within the same VLAN */
	ovf = mce_vc_check_ipv4_conflict_with_vf(pf, vfid, ipv4_addr);
	if (ovf >= 0) {
		if (ovf == PFINFO_IDX)
			dev_err(mce_hw_to_dev(hw),
				"VF %d IP address %pI4 conflicts with PF in VLAN %d\n",
				vfid, &ipv4_addr, vfinfo->pf_vlan);
		else
			dev_err(mce_hw_to_dev(hw),
				"VF %d IP address %pI4 conflicts with another VF: %d in VLAN %d\n",
				vfid, &ipv4_addr, ovf, vfinfo->pf_vlan);
		err = -EEXIST;
	}

	/* Update VF's IP address */
	vfinfo->vf_ipv4_addr = ipv4_addr;

	return err;
}

void mce_mbx_vf_req_isr(struct mce_mbx_info *mbx, struct mbx_req *req)
{
	struct vf_info *vfinfo = mbx->vfinfo;
	enum MBX_REQ_STAT stat = RESP_OR_ACK;
	int opcode = req->cmd.opcode;
	struct mce_hw *hw = mbx->hw;
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	struct mbx_resp resp = {};
	int vfid = mbx->nr_vf;
	int err;

	resp.cmd.v = req->cmd.v;
	resp.cmd.err_code = 0;
	resp.cmd.flag_no_resp = 1; /* default no resp */

	if (test_bit(MCE_REMOVED, pf->state) ||
	    test_bit(MCE_FLAG_PF_RESET_ENA, pf->flags)) {
		stat = HAS_ERR;
		goto quit;
	}

	mbx_logd(LOG_MBX_IN_REQ,
		 "%s: req-opcode:%d 0x%08x 0x%08x 0x%08x 0x%08x\n", mbx->name,
		 req->cmd.opcode, req->data[0], req->data[1], req->data[2],
		 req->data[3]);

	switch (opcode) {
	case MCE_VF_RESET:
		resp.cmd.flag_no_resp = 0;
		err = mce_vf_reset_msg(mbx->hw, vfid, req, &resp, vfinfo);
		if (err)
			resp.cmd.err_code = err;
		break;
	case MCE_VF_SET_VLAN:
		err = mce_vc_set_vlan(pf, vfid, req->data);
		if (err)
			stat = HAS_ERR;
		break;
	case MCE_VF_SET_VLAN_STRIP:
		err = mce_vc_set_vlan_strip(pf, vfid, req->data);
		break;
	case MCE_VF_SET_MAC_ADDR:
		err = mce_vc_set_mac_addr(pf, vfid, req->data);
		if (err)
			stat = HAS_ERR;
		break;
	case MCE_VF_SET_PROMISC_MODE:
		err = mce_vc_set_promisc_mode(pf, vfid, req->data);
		break;
	case MCE_VF_SET_MACVLAN_ADDR:
		err = mce_vc_handle_macvlan_addr(hw, vfid, req->data, true);
		if (err)
			stat = HAS_ERR;
		break;
	case MCE_VF_DEL_MACVLAN_ADDR:
		err = mce_vc_handle_macvlan_addr(hw, vfid, req->data, false);
		break;
	case MCE_VF_NOTIFY_RING_CNT:
		err = mce_vc_notify_ring_cnt(hw, vfid, req->data);
		if (err)
			stat = HAS_ERR;
		break;
	case MCE_VF_SET_IPV4_ADDR:
		err = mce_vc_set_ipv4_addr(pf, vfid, req->data);
		if (err)
			stat = HAS_ERR;
		break;
	case MCE_VF_CHECK_IPV4_ADDR_CONFLICT:
		err = mce_vc_check_ipv4_conflict_with_vf(pf, vfid,
							 (__force __be32)req->data[0]);
		if (err >= 0)
			stat = HAS_ERR;
		break;
	case MCE_VF_GET_QOS:
		resp.cmd.flag_no_resp = 0;
		err = mce_vf_qos_msg(mbx->hw, req, &resp);
		if (err)
			resp.cmd.err_code = err;
		break;
	case MCE_VF_GET_DSCP_LOW:
		resp.cmd.flag_no_resp = 0;
		err = mce_vf_dscp_msg(mbx->hw, req, &resp, true);
		if (err)
			resp.cmd.err_code = err;
		break;
	case MCE_VF_GET_DSCP_HIGH:
		resp.cmd.flag_no_resp = 0;
		err = mce_vf_dscp_msg(mbx->hw, req, &resp, false);
		if (err)
			resp.cmd.err_code = err;
		break;
	default:
		stat = HAS_ERR;
		if (test_bit(MCE_REMOVED, pf->state) ||
		    test_bit(MCE_FLAG_PF_RESET_ENA, pf->flags)) {
			break;
		}
		dev_err(mce_hw_to_dev(hw),
			"recv vf unknown cmd, vfnum:%d opcode:%8.8x\n", vfid,
			opcode);

		break;
	}
	if (!resp.cmd.flag_no_resp)
		mce_mbx_send_resp_isr(mbx, &resp);
quit:
	mce_mbx_clear_peer_req_irq_with_stat(mbx, stat);
}

void mce_mbx_vf_event_req_isr(struct mce_mbx_info *mbx, int event_id)
{
	struct vf_info *vfinfo = mbx->vfinfo;

	mbx_logd(LOG_MBX_IN_REQ, "%s: event_id:%d\n", mbx->name, event_id);

	switch (event_id) {
	case EVT_VF_INIT_DONE:
		vfinfo->init_done = true;
		break;
	case EVT_VF_DRV_REMOVED:
		vfinfo->init_done = false;
		vfinfo->vf_ipv4_addr = 0;
		/* reboot no need clear, vf will clear all vlan by self through mbx */
		break;
	}
}
