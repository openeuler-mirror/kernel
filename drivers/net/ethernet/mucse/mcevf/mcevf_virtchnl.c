// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2020 - 2026 Mucse Corporation. */

#include "mcevf.h"
#include "mcevf_mbx.h"
#include "mcevf_virtchnl.h"
#include "mcevf_lib.h"

static int mcevf_set_mbx_promisc_mode(struct mcevf_hw *hw, bool en)
{
	struct net_device *netdev = mcevf_hw_to_netdev(hw);
	struct mcevf_netdev_priv *np = netdev_priv(netdev);
	struct mcevf_vsi *vsi = np->vsi;
	struct mcevf_pf *pf = vsi->back;
	u32 flags;

	if (vsi->changed_flags & (IFF_PROMISC | IFF_ALLMULTI)) {
		dev_info(mcevf_pf_to_dev(pf),
			 "No change in promiscuous mode\n");
		return 0;
	}

	/* there are 2 bits, but only 3 states */
	if (!(vsi->current_netdev_flags & IFF_PROMISC) &&
	    vsi->current_netdev_flags & IFF_ALLMULTI) {
		/* State 1  - only multicast promiscuous mode enabled
		 * - !IFF_PROMISC && IFF_ALLMULTI
		 */
		flags = FLAG_VF_MULTICAST_PROMISC;
		dev_info(mcevf_pf_to_dev(pf),
			 "Entering multicast promiscuous mode\n");
	} else if (!(vsi->current_netdev_flags & IFF_PROMISC) &&
		   !(vsi->current_netdev_flags & IFF_ALLMULTI)) {
		/* State 2 - unicast/multicast promiscuous mode disabled
		 * - !IFF_PROMISC && !IFF_ALLMULTI
		 */
		flags = FLAG_VF_NONE_PROMISC;
		dev_info(mcevf_pf_to_dev(pf),
			 "Leaving promiscuous mode\n");
	} else {
		/* State 3 - unicast/multicast promiscuous mode enabled
		 * - IFF_PROMISC && IFF_ALLMULTI
		 * - IFF_PROMISC && !IFF_ALLMULTI
		 */
		flags = FLAG_VF_UNICAST_PROMISC |
			FLAG_VF_MULTICAST_PROMISC;
		dev_info(mcevf_pf_to_dev(pf),
			 "Entering promiscuous mode\n");
	}

	/* set vport attr on vf addr workspace */
	if (flags & FLAG_VF_UNICAST_PROMISC)
		hw->ops->set_uc_promisc(hw, true);
	else
		hw->ops->set_uc_promisc(hw, false);

	if (flags & FLAG_VF_MULTICAST_PROMISC)
		hw->ops->set_mc_promisc(hw, true);
	else
		hw->ops->set_mc_promisc(hw, false);
	return 0;
}

static int mcevf_set_mbx_unicast_addr(struct mcevf_hw *hw, u8 *addr)
{
	int err;
	struct mcevf_mbx_info *mbx = &hw->pf_mbx;
	u32 msgbuf[2] = {};
	u8 *mac_addr = (u8 *)(&msgbuf[0]);

	memcpy(mac_addr, addr, 6);

	err = mcevf_mbx_send_req(mbx, MCE_VF_SET_MAC_ADDR, msgbuf, sizeof(msgbuf), NULL, 5 * 1000);

	hw_logd(LOG_MBX_REQ_OUT, "%s: %s mac-addr:%pM err:%d\n", __func__,
		mbx->name, addr, err);
	return err;
}

static int mcevf_set_mbx_ipv4_addr(struct mcevf_hw *hw, __be32 ipv4_addr)
{
	struct mcevf_mbx_info *mbx = &hw->pf_mbx;
	u32 msgbuf[1];
	int err;

	msgbuf[0] = (__force u32)ipv4_addr;

	err = mcevf_mbx_send_req(mbx, MCE_VF_SET_IPV4_ADDR, msgbuf,
				 sizeof(msgbuf), NULL, 5 * 1000);

	if (ipv4_addr) {
		char ip_str[16];

		snprintf(ip_str, sizeof(ip_str), "%pI4", &ipv4_addr);
		hw_logd(LOG_MBX_REQ_OUT, "%s: %s IPv4 address: %s err:%d\n",
			__func__, mbx->name, ip_str, err);
	} else {
		hw_logd(LOG_MBX_REQ_OUT, "%s: %s clear IPv4 address err:%d\n",
			__func__, mbx->name, err);
	}
	return err;
}

static int mcevf_check_mbx_ipv4_addr_conflict(struct mcevf_hw *hw,
					      __be32 ipv4_addr)
{
	struct mcevf_mbx_info *mbx = &hw->pf_mbx;
	__be32 msgbuf[1];
	int err;

	msgbuf[0] = ipv4_addr;
	err = mcevf_mbx_send_req(mbx, MCE_VF_CHECK_IPV4_ADDR_CONFLICT, msgbuf,
				 sizeof(msgbuf), NULL, 5 * 1000);

	if (ipv4_addr) {
		char ip_str[16];

		snprintf(ip_str, sizeof(ip_str), "%pI4", &ipv4_addr);
		hw_logd(LOG_MBX_REQ_OUT, "%s: %s IPv4 address: %s err:%d\n",
			__func__, mbx->name, ip_str, err);
	} else {
		hw_logd(LOG_MBX_REQ_OUT, "%s: %s clear IPv4 address err:%d\n",
			__func__, mbx->name, err);
	}
	return err;
}

static int mcevf_set_mbx_vlan_vfta(struct mcevf_hw *hw, u32 vlan, u32 vind,
				   bool vlan_on)
{
	int err;
	struct mcevf_mbx_info *mbx = &hw->pf_mbx;
	u32 msgbuf[2];

	msgbuf[0] = vlan_on;
	msgbuf[1] = vlan;
	err = mcevf_mbx_send_req(mbx, MCE_VF_SET_VLAN, msgbuf, sizeof(msgbuf), NULL, 5 * 1000);

	hw_logd(LOG_MBX_REQ_OUT, "%s: %s vlan:%d vind:%d vlan_on:%d\n",
		__func__, mbx->name, vlan, vind, vlan_on);
	return err;
}

static int mcevf_set_add_uc_filter(struct mcevf_hw *hw, const u8 *addr)
{
	int err;
	struct mcevf_mbx_info *mbx = &hw->pf_mbx;
	u32 msgbuf[3] = {};
	u8 *mac_addr = (u8 *)(&msgbuf[1]);

	msgbuf[0] = 0;
	memcpy(mac_addr, addr, 6);

	err = mcevf_mbx_send_req(mbx, MCE_VF_SET_MACVLAN_ADDR, msgbuf,
				 sizeof(msgbuf), NULL, 5 * 1000);

	hw_logd(LOG_MBX_REQ_OUT, "%s: %s mac-addr:%pM err:%d\n", __func__,
		mbx->name, addr, err);
	return err;
}

static int mcevf_set_del_uc_filter(struct mcevf_hw *hw, const u8 *addr)
{
	int err;
	struct mcevf_mbx_info *mbx = &hw->pf_mbx;
	u32 msgbuf[3] = {};
	u8 *mac_addr = (u8 *)(&msgbuf[1]);

	msgbuf[0] = 0;
	memcpy(mac_addr, addr, 6);

	err = mcevf_mbx_send_req(mbx, MCE_VF_DEL_MACVLAN_ADDR, msgbuf,
				 sizeof(msgbuf), NULL, 5 * 1000);

	hw_logd(LOG_MBX_REQ_OUT, "%s: %s mac-addr:%pM err:%d\n", __func__,
		mbx->name, addr, err);
	return err;
}

static int mcevf_set_notify_promisc_mode(struct mcevf_hw *hw, u32 flags)
{
	struct mcevf_mbx_info *mbx = &hw->pf_mbx;
	u32 msgbuf[] = {flags};
	int err = 0;

	hw_logd(LOG_MBX_REQ_OUT, "%s: %s flags:0x%x\n", __func__, mbx->name,
		flags);

	err = mcevf_mbx_send_req(mbx, MCE_VF_SET_PROMISC_MODE, msgbuf,
				 sizeof(msgbuf), NULL, 5 * 1000);
	return err;
}

static int mcevf_send_mbx_reset_msg(struct mcevf_hw *hw)
{
	int err = 0, try_cnt = 1;
	struct mcevf_mbx_info *mbx = &hw->pf_mbx;
	struct mcevf_pf *pf = hw->back;
	struct mcevf_dcb *dcb = pf->dcb;
	//struct mcevf_tc_cfg *tccfg = &(dcb->cur_tccfg);
	struct mbx_resp resp = {};
	int *resp_data = resp.data;

	mbx_logd(LOG_MBX_REQ_OUT, "%s: vfid:%d L%d\n", __func__, hw->vfnum,
		 __LINE__);

	while (try_cnt--) {
		err = mcevf_mbx_send_req(mbx, MCE_VF_RESET, NULL, 0, &resp,
					 1000 * 1000);
		if (!err)
			break;
		usleep_range(1000, 2000);
	}
	if (err) {
		dev_err(hw->dev, "send VF_RESET to pf timeout\n");
		return err;
	}

	/* we get mac address from mailbox */
	memcpy(hw->mac.perm_addr, &resp_data[F_VF_MAC_ADDR], ETH_ALEN);
	if (!is_valid_ether_addr(hw->mac.perm_addr)) {
		dev_warn(hw->dev, "invalid mac address:%pM, gen random mac addr\n",
			 hw->mac.perm_addr);
		eth_random_addr(hw->mac.perm_addr);
	}

	hw->ring_max_cnt = resp_data[F_VF_RESET_RING_MAX_CNT];
	hw->axi_mhz = resp_data[F_VF_RESET_AXI_MHZ];
	hw->nr_pf = resp_data[F_VF_NR_PF];
	hw->fw_version = resp_data[F_VF_RESET_FW_VERSION];
	dev_info(hw->dev,
		 "macaddr %pM ring_max_cnt:%d fw-version:0x%08x axi_mhz:%d\n",
		 hw->mac.perm_addr, hw->ring_max_cnt, hw->fw_version,
		 hw->axi_mhz);
	if (hw->ring_max_cnt <= 0 || hw->ring_max_cnt > 128) {
		dev_info(hw->dev, "vf ring_max_cnt:%d is invalid!\n", hw->ring_max_cnt);
		return -EINVAL;
	}
	pf->vf_vlan = resp_data[F_VF_RESET_VLAN] & 0xfff;
	if (resp_data[F_VF_RESET_VLAN] & BIT(31))
		pf->vf_vlan_proto = MCEVF_VLAN_TYPE_88A8;
	else
		pf->vf_vlan_proto = MCEVF_VLAN_TYPE_8100;
	dev_info(hw->dev, "vf reset pf vlan:%d proto:%s\n", pf->vf_vlan,
		 pf->vf_vlan_proto ? "0x88a8" : "0x8100");
	set_bit(MCEVF_FLAG_PF_UPDATE_VLAN, pf->flags);

	//if (resp_data[F_VF_FCS_STATE])
	if (resp_data[F_VF_STATE] & BIT(VF_FCS_BIT))
		set_bit(MCEVF_FLAG_NETDEV_STATE_FCS_ENA, pf->flags);
	//if (resp_data[F_VF_SPOOF_STATE])
	if (resp_data[F_VF_STATE] & BIT(VF_SPOOF_BIT))
		set_bit(MCEVF_FLAG_SPOOF_ON, pf->flags);
	//if (resp_data[F_VF_TRUST_STATE])
	if (resp_data[F_VF_STATE] & BIT(VF_TRUST_BIT))
		set_bit(MCEVF_FLAG_TRUST_ON, pf->flags);
	//if (resp_data[F_VF_RDMA_STATE])
	if (resp_data[F_VF_STATE] & BIT(VF_RDMA_BIT))
		hw->rdma_state = true;
	else
		hw->rdma_state = false;

	if (resp_data[F_VF_STATE] & BIT(VF_PFC_BIT)) {
		set_bit(MCEVF_PFC_EN, dcb->flags);
		set_bit(MCEVF_FLAG_PFC_ENA, pf->flags);
		//memcpy(tccfg->pfc_txq_base[0], (u8 *)&resp_data[F_VF_PFC_BASE], 16);
		//memcpy(tccfg->pfc_txq_count[0], (u8 *)&resp_data[F_VF_PFC_COUNT], 16);
	} else {
		clear_bit(MCEVF_PFC_EN, dcb->flags);
		clear_bit(MCEVF_FLAG_PFC_ENA, pf->flags);
	}

	if (resp_data[F_VF_STATE] & BIT(VF_DSCP_BIT)) {
		set_bit(MCEVF_DSCP_EN, dcb->flags);
		set_bit(MCEVF_FLAG_DSCP_ENA, pf->flags);
	} else {
		clear_bit(MCEVF_DSCP_EN, dcb->flags);
		clear_bit(MCEVF_FLAG_DSCP_ENA, pf->flags);
	}
	//pf->valid_prio = resp_data[F_VF_VALID_PRIO];
	/* get link state from pf */
	hw->port_info->link_up = !!(resp_data[F_VF_RESET_LINK_ST] & MCEVF_PF_LINK_UP);
	hw->port_info->link_speed = resp_data[F_VF_RESET_LINK_ST] &
				    GENMASK(30, 0);
	dev_info(mcevf_hw_to_dev(hw), "vf reset linkup:%d speed:%d\n",
		 hw->port_info->link_up, hw->port_info->link_speed);
	return 0;
}

static int mcevf_get_qos_info(struct mcevf_hw *hw)
{
	int err = 0, try_cnt = 1;
	struct mcevf_mbx_info *mbx = &hw->pf_mbx;
	struct mcevf_pf *pf = hw->back;
	struct mcevf_dcb *dcb = pf->dcb;
	struct mcevf_tc_cfg *tccfg = &dcb->cur_tccfg;
	struct mbx_resp resp = {};
	int *resp_data = resp.data;

	mbx_logd(LOG_MBX_REQ_OUT, "%s: vfid:%d L%d\n", __func__, hw->vfnum,
		 __LINE__);

	while (try_cnt--) {
		err = mcevf_mbx_send_req(mbx, MCE_VF_GET_QOS, NULL, 0, &resp,
					 1000 * 1000);
		if (!err)
			break;
		usleep_range(1000, 2000);
	}
	if (err) {
		dev_err(hw->dev, "send VF_GET_QOS to pf timeout\n");
		return err;
	}
	memcpy(tccfg->pfc_txq_base[0], (u8 *)&resp_data[F_VF_PFC_BASE], 16);
	memcpy(tccfg->pfc_txq_count[0], (u8 *)&resp_data[F_VF_PFC_COUNT], 16);
	pf->valid_prio = resp_data[F_VF_VALID_PRIO];

	// get dscp setup
	try_cnt = 1;
	while (try_cnt--) {
		err = mcevf_mbx_send_req(mbx, MCE_VF_GET_DSCP_LOW, NULL, 0, &resp,
					 1000 * 1000);
		if (!err)
			break;
		usleep_range(1000, 2000);
	}
	if (err) {
		dev_err(hw->dev, "send VF_GET_DSCP_LOW to pf timeout\n");
		return err;
	}
	memcpy(dcb->dscp_map, (u8 *)&resp_data[0], 32);

	// get dscp setup
	try_cnt = 1;
	while (try_cnt--) {
		err = mcevf_mbx_send_req(mbx, MCE_VF_GET_DSCP_HIGH, NULL, 0, &resp,
					 1000 * 1000);
		if (!err)
			break;
		usleep_range(1000, 2000);
	}
	if (err) {
		dev_err(hw->dev, "send VF_GET_DSCP_LOW to pf timeout\n");
		return err;
	}
	memcpy(dcb->dscp_map + 32, (u8 *)&resp_data[0], 32);

	return 0;
}

static int mcevf_set_mbx_init_done(struct mcevf_hw *hw, bool en)
{
	enum VF2PF_EVENT_ID event;

	mcevf_mbx_set_vf_stat(&hw->pf_mbx);
	event = en ? EVT_VF_INIT_DONE : EVT_VF_DRV_REMOVED;
	mcevf_mbx_send_event(&hw->pf_mbx, event, 5000);
	return 0;
}

void mcevf_mbx_pf_event_req_isr(struct mcevf_mbx_info *mbx, int event_id)
{
	struct mcevf_hw *hw = mbx->hw;
	struct mcevf_pf *pf = hw->back;
	struct mcevf_dcb *dcb = pf->dcb;
	struct mcevf_port_info *pi = hw->port_info;
	struct net_device *netdev = mcevf_hw_to_netdev(hw);
	int v;

	mbx_logd(LOG_MBX_IN_REQ, "%s: event_id:%d\n", mbx->name, event_id);

	switch (event_id) {
	case EVT_PF_LINK_CHANGED:
		v = mcevf_mbx_get_pf_stat(mbx, PF_LINKUP);
		if (v < 0) {
			dev_err(mbx->hw->dev,
				"%s:%s mcevf_mbx_get_pf_stat failed!\n",
				__func__, mbx->name);
		} else {
			if (v > 0) {
				pi->link_up = true;
				pi->link_speed =
					mcevf_mbx_get_pf_stat(mbx, PF_SPEED);
			} else {
				pi->link_up = false;
				pi->link_speed = 0;
			}
			set_bit(MCEVF_FLAG_PF_UPDATE_LINK, pf->flags);
		}
		break;
	case EVT_PF_RESET_VF:
		dev_info(hw->dev, "%s get reset from pf\n", mbx->name);
		mcevf_pf_flags_reset_set(pf);
		break;
	case EVT_PF_DRV_REMOVE:
		break;
	case EVT_PF_FORCE_VF_LINK_UP:
		pi->link_up = true;
		pi->link_speed = mcevf_mbx_get_pf_stat(mbx, PF_SPEED);
		set_bit(MCEVF_FLAG_PF_UPDATE_LINK, pf->flags);
		break;
	case EVT_PF_FORCE_VF_LINK_DOWN:
		pi->link_up = false;
		pi->link_speed = 0;
		set_bit(MCEVF_FLAG_PF_UPDATE_LINK, pf->flags);
		break;
	case EVT_PF_FORECE_VF_CLOESE:
		set_bit(MCEVF_FLAG_FORCE_CLOSE, pf->flags);
		break;
	case EVT_PF_FORECE_VF_OPEN:
		set_bit(MCEVF_FLAG_FORCE_OPEN, pf->flags);
		break;
	case EVT_PF_FORECE_FCS_ON:
		set_bit(MCEVF_FLAG_NETDEV_STATE_FCS_ENA, pf->flags);
		set_bit(MCEVF_FLAG_PF_UPDATE_FCS, pf->flags);
		break;
	case EVT_PF_FORECE_FCS_OFF:
		clear_bit(MCEVF_FLAG_NETDEV_STATE_FCS_ENA, pf->flags);
		set_bit(MCEVF_FLAG_PF_UPDATE_FCS, pf->flags);
		break;
	case EVT_PF_FORECE_SPOOF_ON:
		set_bit(MCEVF_FLAG_SPOOF_ON, pf->flags);
		dev_info(hw->dev, "now spoof on\n");
		break;
	case EVT_PF_FORECE_SPOOF_OFF:
		clear_bit(MCEVF_FLAG_SPOOF_ON, pf->flags);
		dev_info(hw->dev, "now spoof off\n");
		break;
	case EVT_PF_TRUST_ON:
		set_bit(MCEVF_FLAG_TRUST_ON, pf->flags);
		if (netdev->flags & (IFF_PROMISC | IFF_ALLMULTI))
			dev_info(hw->dev, "now trust on, promisc effect\n");
		break;
	case EVT_PF_TRUST_OFF:
		clear_bit(MCEVF_FLAG_TRUST_ON, pf->flags);
		if (netdev->flags & (IFF_PROMISC | IFF_ALLMULTI))
			dev_err(hw->dev, "now trust off, promisc no-effect\n");
		break;
	case EVT_PF_DSCP_ON:
		set_bit(MCEVF_DSCP_EN, dcb->flags);
		set_bit(MCEVF_FLAG_DSCP_ENA, pf->flags);
		break;
	case EVT_PF_DSCP_OFF:
		clear_bit(MCEVF_DSCP_EN, dcb->flags);
		clear_bit(MCEVF_FLAG_DSCP_ENA, pf->flags);
		break;
	default:
		break;
	}
}

void mcevf_mbx_pf_req_isr(struct mcevf_mbx_info *mbx, struct mbx_req *req)
{
	struct mcevf_hw *hw = mbx->hw;
	struct mcevf_pf *pf = hw->back;
	struct mcevf_dcb *dcb = pf->dcb;
	struct mbx_resp resp = {};
	int opcode = req->cmd.opcode;
	enum MBX_REQ_STAT stat = RESP_OR_ACK;
	// int err = 0;

	resp.cmd.v = req->cmd.v;
	resp.cmd.err_code = 0;
	resp.cmd.flag_no_resp = 1;  // default no resp

	if (test_bit(MCEVF_SHUTTING_DOWN, pf->state)) {
		stat = HAS_ERR;
		goto quit;
	}

	mbx_logd(LOG_MBX_IN_REQ,
		 "%s: req-opcode:%d d:0x%08x 0x%08x 0x%08x 0x%08x\n", mbx->name,
		 req->cmd.opcode, req->data[0], req->data[1], req->data[2],
		 req->data[3]);

	switch (opcode) {
	case MCE_PF2VF_SET_VLAN:
		resp.cmd.flag_no_resp = 0;

		pf->vf_vlan = req->data[0];
		pf->vf_vlan_qos = req->data[1];
		pf->vf_vlan_proto = req->data[2] == ETH_P_8021AD ?
					    MCEVF_VLAN_TYPE_88A8 :
					    MCEVF_VLAN_TYPE_8100;
		dev_info(hw->dev, "%s: pf set vlan:%d proto:0x%x\n", mbx->name,
			 pf->vf_vlan, req->data[2]);
		set_bit(MCEVF_FLAG_PF_UPDATE_VLAN, pf->flags);
		break;
	case MCE_PF2VF_SET_DSCP:
		resp.cmd.flag_no_resp = 0;

		if (req->data[0] >= MCEVF_MAX_DSCP) {
			stat = HAS_ERR;
			break;
		}
		dcb->dscp_map[req->data[0]] = req->data[1];
		//pf->vf_vlan = req->data[0];
		dev_info(hw->dev, "%s: pf set dscp:%d: prio %d\n", mbx->name,
			 req->data[0], req->data[1]);
		break;
	}
	mcevf_mbx_send_resp_isr(mbx, &resp);
quit:
	mcevf_mbx_clear_peer_req_irq_with_stat(mbx, stat);
}

static int mcevf_mbx_notify_ring_cnt(struct mcevf_hw *hw, int ring_cnt)
{
	struct mcevf_mbx_info *mbx = &hw->pf_mbx;
	u32 msgbuf[1];
	int err;

	msgbuf[0] = ring_cnt;
	err = mcevf_mbx_send_req(mbx, MCE_VF_NOTIFY_RING_CNT, msgbuf,
				 sizeof(msgbuf), NULL, 5 * 1000);
	hw_logd(LOG_MBX_REQ_OUT, "%s: %s ring_cnt:%d\n", __func__, mbx->name,
		ring_cnt);
	return err;
}

struct mcevf_virtchnl_operations virtchnl_ops = {
	.set_init_done = mcevf_set_mbx_init_done,
	.set_promisc_mode = mcevf_set_mbx_promisc_mode,
	.set_unicast_addr = mcevf_set_mbx_unicast_addr,
	.set_ipv4_addr = mcevf_set_mbx_ipv4_addr,
	.check_mbx_ipv4_addr_conflict = mcevf_check_mbx_ipv4_addr_conflict,
	.set_vlan_vfta = mcevf_set_mbx_vlan_vfta,
	.set_add_uc_filter = mcevf_set_add_uc_filter,
	.set_del_uc_filter = mcevf_set_del_uc_filter,
	.set_notify_promisc_mode = mcevf_set_notify_promisc_mode,
	.send_reset_msg = mcevf_send_mbx_reset_msg,
	.get_qos_info = mcevf_get_qos_info,
	.notify_ring_cnt = mcevf_mbx_notify_ring_cnt,
};
