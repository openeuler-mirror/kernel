// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 - 2024 Mucse Corporation. */

#include "vf.h"
#include "rnpvf.h"

static int rnpvf_reset_pf(struct rnpvf_hw *hw)
{
	struct rnp_mbx_info *mbx = &hw->mbx;
	u32 msgbuf[2];
	s32 ret_val;

	memset(msgbuf, 0, sizeof(msgbuf));
	msgbuf[0] = RNP_VF_RESET_PF;

	ret_val = mbx->ops.write_posted(hw, msgbuf, 2, false);

	if (!ret_val)
		ret_val = mbx->ops.read_posted(hw, msgbuf, 2, false);

	return ret_val;
}

static int rnpvf_get_mtu(struct rnpvf_hw *hw)
{
	struct rnp_mbx_info *mbx = &hw->mbx;
	u32 msgbuf[2];
	s32 ret_val;

	memset(msgbuf, 0, sizeof(msgbuf));
	msgbuf[0] = RNP_VF_GET_MTU;

	ret_val = mbx->ops.write_posted(hw, msgbuf, 2, false);

	if (!ret_val)
		ret_val = mbx->ops.read_posted(hw, msgbuf, 2, false);

	msgbuf[0] &= ~RNP_VT_MSGTYPE_CTS;

	/* if nacked the address was rejected, use "perm_addr" */
	if (!ret_val &&
	    (msgbuf[0] == (RNP_VF_SET_MTU | RNP_VT_MSGTYPE_NACK)))
		return -1;
	hw->mtu = msgbuf[1];

	return ret_val;
}

static int rnpvf_set_mtu(struct rnpvf_hw *hw, int mtu)
{
	struct rnp_mbx_info *mbx = &hw->mbx;
	u32 msgbuf[2];
	s32 ret_val;

	memset(msgbuf, 0, sizeof(msgbuf));
	msgbuf[0] = RNP_VF_SET_MTU;
	msgbuf[1] = mtu;

	ret_val = mbx->ops.write_posted(hw, msgbuf, 2, false);

	if (!ret_val)
		ret_val = mbx->ops.read_posted(hw, msgbuf, 2, false);

	msgbuf[0] &= ~RNP_VT_MSGTYPE_CTS;

	/* if nacked the address was rejected, use "perm_addr" */
	if (!ret_val &&
	    (msgbuf[0] == (RNP_VF_SET_MTU | RNP_VT_MSGTYPE_NACK))) {
		// set mtu failed
		return -1;
	}

	return ret_val;
}

static int rnpvf_read_eth_reg(struct rnpvf_hw *hw, int reg, u32 *value)
{
	struct rnp_mbx_info *mbx = &hw->mbx;
	u32 msgbuf[2];
	int err;

	msgbuf[0] = RNP_VF_REG_RD;
	msgbuf[1] = reg;

	err = mbx->ops.write_posted(hw, msgbuf, 2, false);
	if (err)
		goto mbx_err;

	err = mbx->ops.read_posted(hw, msgbuf, 2, false);
	if (err)
		goto mbx_err;

	/* remove extra bits from the message */
	msgbuf[0] &= ~RNP_VT_MSGTYPE_CTS;
	msgbuf[0] &= ~(0xFF << RNP_VT_MSGINFO_SHIFT);

	if (msgbuf[0] != (RNP_VF_REG_RD | RNP_VT_MSGTYPE_ACK))
		err = RNP_ERR_INVALID_ARGUMENT;

	*value = msgbuf[1];

mbx_err:
	return err;
}

/**
 *  rnpvf_start_hw_vf - Prepare hardware for Tx/Rx
 *  @hw: pointer to hardware structure
 *
 *  Starts the hardware by filling the bus info structure and media type, clears
 *  all on chip counters, initializes receive address registers, multicast
 *  table, VLAN filter table, calls routine to set up link and flow control
 *  settings, and leaves transmit and receive units disabled and uninitialized
 **/
static s32 rnpvf_start_hw_vf(struct rnpvf_hw *hw)
{
	/* Clear adapter stopped flag */
	hw->adapter_stopped = false;

	return 0;
}

/**
 *  rnpvf_init_hw_vf - virtual function hardware initialization
 *  @hw: pointer to hardware structure
 *
 *  Initialize the hardware by resetting the hardware and then starting
 *  the hardware
 **/
static s32 rnpvf_init_hw_vf(struct rnpvf_hw *hw)
{
	s32 status;

	status = hw->mac.ops.start_hw(hw);

	hw->mac.ops.get_mac_addr(hw, hw->mac.addr);

	return status;
}

/**
 *  rnpvf_reset_hw_vf - Performs hardware reset
 *  @hw: pointer to hardware structure
 *
 *  Resets the hardware by resetting the transmit and receive units, masks and
 *  clears all interrupts.
 **/
static s32 rnpvf_reset_hw_vf(struct rnpvf_hw *hw)
{
	struct rnp_mbx_info *mbx = &hw->mbx;
	struct rnpvf_adapter *adapter = hw->back;
	// u32 timeout = RNP_VF_INIT_TIMEOUT;
	s32 ret_val = RNP_ERR_INVALID_MAC_ADDR;
	u32 msgbuf[RNP_VF_PERMADDR_MSG_LEN];
	u8 *addr = (u8 *)(&msgbuf[1]);
	u32 vlan;
	int try_cnt = 10;

	/* Call adapter stop to disable tx/rx and clear interrupts */
	hw->mac.ops.stop_adapter(hw);

	/* reset the api version */
	hw->api_version = 0;

	/* mailbox timeout can now become active */
	mbx->timeout = RNP_VF_MBX_INIT_TIMEOUT;

	while (try_cnt--) {
		msgbuf[0] = RNP_VF_RESET;
		mbx->ops.write_posted(hw, msgbuf, 1, false);
		/* ack write back maybe too fast */
		mdelay(20);

		/* set our "perm_addr" based on info provided by PF */
		/* also set up the mc_filter_type which is piggy backed
		 * on the mac address in word 3
		 */
		ret_val = mbx->ops.read_posted(hw, msgbuf,
					       RNP_VF_PERMADDR_MSG_LEN,
					       false);
		if (ret_val == 0)
			break;
	}
	if (ret_val)
		return ret_val;

	/* New versions of the PF may NACK the reset return message
	 * to indicate that no MAC address has yet been assigned for
	 * the VF.
	 */
	if (msgbuf[0] != (RNP_VF_RESET | RNP_VT_MSGTYPE_ACK) &&
	    msgbuf[0] != (RNP_VF_RESET | RNP_VT_MSGTYPE_NACK))
		return RNP_ERR_INVALID_MAC_ADDR;
	/* we get mac address from mailbox */

	memcpy(hw->mac.perm_addr, addr, ETH_ALEN);
	hw->mac.mc_filter_type = msgbuf[RNP_VF_MC_TYPE_WORD] & 0xff;

	/* ft padding */
	if ((msgbuf[RNP_VF_MC_TYPE_WORD] >> 8) & 0xff)
		adapter->priv_flags |= RNPVF_PRIV_FLAG_FT_PADDING;
	else
		adapter->priv_flags = 0;
	/* fc mode */
	hw->fc.current_mode = (msgbuf[RNP_VF_MC_TYPE_WORD] >> 16) & 0xff;

	/* phy status */
	hw->phy_type = (msgbuf[RNP_VF_PHY_TYPE_WORD] & 0xffff);

	hw->mac.dma_version = msgbuf[RNP_VF_DMA_VERSION_WORD];
	hw->dma_version = hw->mac.dma_version;

	/* vlan status */
	vlan = msgbuf[RNP_VF_VLAN_WORD];
	if (vlan & 0xffff) {
		adapter->vf_vlan = vlan & 0xffff;
		adapter->flags |= RNPVF_FLAG_PF_SET_VLAN;
	}
	hw->ops.set_veb_vlan(hw, vlan, VFNUM(mbx, hw->vfnum));
	hw->fw_version = msgbuf[RNP_VF_FW_VERSION_WORD];

	if (msgbuf[RNP_VF_LINK_STATUS_WORD] & RNP_PF_LINK_UP) {
		hw->link = true;
		hw->speed = msgbuf[RNP_VF_LINK_STATUS_WORD] & 0xffff;

	} else {
		hw->link = false;
		hw->speed = 0;
	}

	hw->usecstocount = msgbuf[RNP_VF_AXI_MHZ];

	DPRINTK(PROBE, INFO, "dma_versioin:%x vlan %d\n",
		hw->mac.dma_version, adapter->vf_vlan);
	DPRINTK(PROBE, INFO, "axi:%x\n", hw->usecstocount);
	DPRINTK(PROBE, INFO, "firmware :%x\n", hw->fw_version);
	DPRINTK(PROBE, INFO, "link speed :%x\n", hw->speed);
	DPRINTK(PROBE, INFO, "link status :%s\n",
		hw->link ? "up" : "down");
	hw->pf_feature = msgbuf[RNP_VF_FEATURE];

	return 0;
}

/**
 *  rnpvf_stop_hw_vf - Generic stop Tx/Rx units
 *  @hw: pointer to hardware structure
 *
 *  Sets the adapter_stopped flag within rnpvf_hw struct. Clears interrupts,
 *  disables transmit and receive units. The adapter_stopped flag is used by
 *  the shared code and drivers to determine if the adapter is in a stopped
 *  state and should not touch the hardware.
 **/
static s32 rnpvf_stop_hw_vf(struct rnpvf_hw *hw)
{
	u32 number_of_queues;
	u16 i;
	struct rnpvf_adapter *adapter = hw->back;
	struct rnpvf_ring *ring;

	/* Set the adapter_stopped flag so other driver functions stop touching
	 * the hardware
	 */
	hw->adapter_stopped = true;

	/* Disable the receive unit by stopped each queue */
	for (i = 0; i < adapter->num_rx_queues; i++) {
		ring = adapter->rx_ring[i];
		ring_wr32(ring, RNP_DMA_RX_START, 0);
	}

	/* Disable the transmit unit.  Each queue must be disabled. */
	number_of_queues = hw->mac.max_tx_queues;

	return 0;
}

/**
 *  rnpvf_mta_vector - Determines bit-vector in multicast table to set
 *  @hw: pointer to hardware structure
 *  @mc_addr: the multicast address
 *
 *  Extracts the 12 bits, from a multicast address, to determine which
 *  bit-vector to set in the multicast table. The hardware uses 12 bits, from
 *  incoming rx multicast addresses, to determine the bit-vector to check in
 *  the MTA. Which of the 4 combination, of 12-bits, the hardware uses is set
 *  by the MO field of the MCSTCTRL. The MO field is set during initialization
 *  to mc_filter_type.
 **/
static s32 rnpvf_mta_vector(struct rnpvf_hw *hw, u8 *mc_addr)
{
	u32 vector = 0;

	switch (hw->mac.mc_filter_type) {
	case 0: /* use bits [47:36] of the address */
		vector = ((mc_addr[4] << 8) | (((u16)mc_addr[5])));
		break;
	case 1: /* use bits [46:35] of the address */
		vector = ((mc_addr[4] << 7) | (((u16)mc_addr[5]) >> 1));
		break;
	case 2: /* use bits [45:34] of the address */
		vector = ((mc_addr[4] << 6) | (((u16)mc_addr[5]) >> 2));
		break;
	case 3: /* use bits [43:32] of the address */
		vector = ((mc_addr[4]) << 4 | (((u16)mc_addr[5]) >> 4));
		break;
	case 4: /* use bits [32:43] of the address */
		vector = ((mc_addr[0] << 8) | (((u16)mc_addr[1])));
		vector = (vector >> 4);
		break;
	case 5: /* use bits [32:43] of the address */
		vector = ((mc_addr[0] << 8) | (((u16)mc_addr[1])));
		vector = (vector >> 3);
		break;
	case 6: /* use bits [32:43] of the address */
		vector = ((mc_addr[0] << 8) | (((u16)mc_addr[1])));
		vector = (vector >> 2);
		break;
	case 7: /* use bits [32:43] of the address */
		vector = ((mc_addr[0] << 8) | (((u16)mc_addr[1])));
		break;
	default: /* Invalid mc_filter_type */
		break;
	}

	/* vector can only be 12-bits or boundary will be exceeded */
	vector &= 0xFFF;
	return vector;
}

/**
 *  rnpvf_get_mac_addr_vf - Read device MAC address
 *  @hw: pointer to the HW structure
 *  @mac_addr: pointer to storage for retrieved MAC address
 **/
static s32 rnpvf_get_mac_addr_vf(struct rnpvf_hw *hw, u8 *mac_addr)
{
	// memcpy(mac_addr, hw->mac.perm_addr, ETH_ALEN);
	struct rnp_mbx_info *mbx = &hw->mbx;
	u32 msgbuf[3];
	u8 *msg_addr = (u8 *)(&msgbuf[1]);
	s32 ret_val = 0;

	memset(msgbuf, 0, sizeof(msgbuf));
	/* If index is one then this is the start of a new list and needs
	 * indication to the PF so it can do it's own list management.
	 * If it is zero then that tells the PF to just clear all of
	 * this VF's macvlans and there is no new list.
	 */
	msgbuf[0] |= RNP_VF_SET_MACVLAN;
	ret_val = mbx->ops.write_posted(hw, msgbuf, 1, false);

	if (!ret_val)
		ret_val = mbx->ops.read_posted(hw, msgbuf, 3, false);

	msgbuf[0] &= ~RNP_VT_MSGTYPE_CTS;

	if (!ret_val)
		if (msgbuf[0] ==
		    (RNP_VF_GET_MACVLAN | RNP_VT_MSGTYPE_NACK))
			ret_val = -ENOMEM;

	memcpy(mac_addr, msg_addr, 6);

	return 0;
}

/**
 *  rnpvf_get_queues_vf - Read device MAC address
 *  @hw: pointer to the HW structure
 *  @mac_addr: pointer to storage for retrieved MAC address
 **/
static s32 rnpvf_get_queues_vf(struct rnpvf_hw *hw)
{
	struct rnp_mbx_info *mbx = &hw->mbx;
	s32 ret_val = 0;
	u32 msgbuf[7];

	memset(msgbuf, 0, sizeof(msgbuf));
	msgbuf[0] |= RNP_VF_GET_QUEUE;

	ret_val = mbx->ops.write_posted(hw, msgbuf, 1, false);

	mdelay(10);

	if (!ret_val)
		ret_val = mbx->ops.read_posted(hw, msgbuf, 7, false);

	msgbuf[0] &= ~RNP_VT_MSGTYPE_CTS;

	if (!ret_val)
		if (msgbuf[0] == (RNP_VF_GET_QUEUE | RNP_VT_MSGTYPE_NACK))
			ret_val = -ENOMEM;
#define MSG_TX_NUM_WORD 1
#define MSG_RX_NUM_WORD 2
#define MSG_RING_BASE_WORD 5
#define MSG_RING_DEPTH 6

	hw->queue_ring_base = msgbuf[MSG_RING_BASE_WORD];
	hw->mac.max_tx_queues = msgbuf[MSG_TX_NUM_WORD];
	hw->mac.max_rx_queues = msgbuf[MSG_RX_NUM_WORD];
	hw->tx_items_count = 0xffff & (msgbuf[MSG_RING_DEPTH] >> 16);
	hw->rx_items_count = 0xffff & (msgbuf[MSG_RING_DEPTH] >> 0);

	return 0;
}

static s32 rnpvf_set_uc_addr_vf(struct rnpvf_hw *hw, u32 index, u8 *addr)
{
	struct rnp_mbx_info *mbx = &hw->mbx;
	u32 msgbuf[3];
	u8 *msg_addr = (u8 *)(&msgbuf[1]);
	s32 ret_val = 0;

	memset(msgbuf, 0, sizeof(msgbuf));
	/* If index is one then this is the start of a new list and needs
	 * indication to the PF so it can do it's own list management.
	 * If it is zero then that tells the PF to just clear all of
	 * this VF's macvlans and there is no new list.
	 */
	msgbuf[0] |= index << RNP_VT_MSGINFO_SHIFT;
	msgbuf[0] |= RNP_VF_SET_MACVLAN;
	if (addr)
		memcpy(msg_addr, addr, 6);
	ret_val = mbx->ops.write_posted(hw, msgbuf, 3, false);

	if (!ret_val)
		ret_val = mbx->ops.read_posted(hw, msgbuf, 3, false);

	msgbuf[0] &= ~RNP_VT_MSGTYPE_CTS;

	if (!ret_val)
		if (msgbuf[0] ==
		    (RNP_VF_SET_MACVLAN | RNP_VT_MSGTYPE_NACK))
			ret_val = -ENOMEM;
	return ret_val;
}

/**
 *  rnpvf_set_rar_vf - set device MAC address
 *  @hw: pointer to hardware structure
 *  @index: Receive address register to write
 *  @addr: Address to put into receive address register
 *  @vmdq: Unused in this implementation
 **/
static s32 rnpvf_set_rar_vf(struct rnpvf_hw *hw, u32 index, u8 *addr,
			    u32 vmdq)
{
	struct rnp_mbx_info *mbx = &hw->mbx;
	u32 msgbuf[3];
	u8 *msg_addr = (u8 *)(&msgbuf[1]);
	s32 ret_val;

	memset(msgbuf, 0, sizeof(msgbuf));
	msgbuf[0] = RNP_VF_SET_MAC_ADDR;
	memcpy(msg_addr, addr, 6);
	ret_val = mbx->ops.write_posted(hw, msgbuf, 3, false);

	if (!ret_val)
		ret_val = mbx->ops.read_posted(hw, msgbuf, 3, false);

	msgbuf[0] &= ~RNP_VT_MSGTYPE_CTS;

	/* if nacked the address was rejected, use "perm_addr" */
	if (!ret_val &&
	    (msgbuf[0] == (RNP_VF_SET_MAC_ADDR | RNP_VT_MSGTYPE_NACK))) {
		rnpvf_get_mac_addr_vf(hw, hw->mac.addr);
		return -1;
	}

	return ret_val;
}

static void rnpvf_write_msg_read_ack(struct rnpvf_hw *hw, u32 *msg,
				     u16 size)
{
	u32 retmsg[RNP_VFMAILBOX_SIZE];
	s32 retval;
	struct rnp_mbx_info *mbx = &hw->mbx;

	retval = mbx->ops.write_posted(hw, msg, size, false);
	if (!retval)
		mbx->ops.read_posted(hw, retmsg, size, false);
}

u8 *rnpvf_addr_list_itr(struct rnpvf_hw __maybe_unused *hw,
			u8 **mc_addr_ptr)
{
	struct netdev_hw_addr *mc_ptr;
	u8 *addr = *mc_addr_ptr;

	mc_ptr = container_of(addr, struct netdev_hw_addr, addr[0]);
	if (mc_ptr->list.next) {
		struct netdev_hw_addr *ha;

		ha = list_entry(mc_ptr->list.next, struct netdev_hw_addr,
				list);
		*mc_addr_ptr = ha->addr;
	} else {
		*mc_addr_ptr = NULL;
	}

	return addr;
}

/**
 *  rnpvf_update_mc_addr_list_vf - Update Multicast addresses
 *  @hw: pointer to the HW structure
 *  @netdev: pointer to net device structure
 *
 *  Updates the Multicast Table Array.
 **/
static s32 rnpvf_update_mc_addr_list_vf(struct rnpvf_hw *hw,
					struct net_device *netdev)
{
	struct netdev_hw_addr *ha;
	u32 msgbuf[RNP_VFMAILBOX_SIZE];
	u16 *vector_list = (u16 *)&msgbuf[1];
	u32 cnt, i;
	int addr_count = 0;
	u8 *addr_list = NULL;

	/* Each entry in the list uses 1 16 bit word.  We have 30
	 * 16 bit words available in our HW msg buffer (minus 1 for the
	 * msg type).  That's 30 hash values if we pack 'em right.  If
	 * there are more than 30 MC addresses to add then punt the
	 * extras for now and then add code to handle more than 30 later.
	 * It would be unusual for a server to request that many multi-cast
	 * addresses except for in large enterprise network environments.
	 */

	cnt = netdev_mc_count(netdev);
	if (cnt > 30)
		cnt = 30;
	msgbuf[0] = RNP_VF_SET_MULTICAST;
	msgbuf[0] |= cnt << RNP_VT_MSGINFO_SHIFT;

	addr_count = netdev_mc_count(netdev);

	ha = list_first_entry(&netdev->mc.list, struct netdev_hw_addr,
			      list);
	addr_list = ha->addr;
	for (i = 0; i < addr_count; i++) {
		vector_list[i] = rnpvf_mta_vector(hw,
						  rnpvf_addr_list_itr(hw, &addr_list));
	}

	rnpvf_write_msg_read_ack(hw, msgbuf, RNP_VFMAILBOX_SIZE);

	return 0;
}

/**
 *  rnpvf_set_vfta_vf - Set/Unset vlan filter table address
 *  @hw: pointer to the HW structure
 *  @vlan: 12 bit VLAN ID
 *  @vind: unused by VF drivers
 *  @vlan_on: if true then set bit, else clear bit
 **/
static s32 rnpvf_set_vfta_vf(struct rnpvf_hw *hw, u32 vlan, u32 vind,
			     bool vlan_on)
{
	struct rnp_mbx_info *mbx = &hw->mbx;
	u32 msgbuf[2];
	s32 err;

	msgbuf[0] = RNP_VF_SET_VLAN;
	msgbuf[1] = vlan;
	/* Setting the 8 bit field MSG INFO to TRUE indicates "add" */
	msgbuf[0] |= vlan_on << RNP_VT_MSGINFO_SHIFT;

	err = mbx->ops.write_posted(hw, msgbuf, 2, false);
	if (err)
		goto mbx_err;

	err = mbx->ops.read_posted(hw, msgbuf, 2, false);
	if (err)
		goto mbx_err;

	/* remove extra bits from the message */
	msgbuf[0] &= ~RNP_VT_MSGTYPE_CTS;
	msgbuf[0] &= ~(0xFF << RNP_VT_MSGINFO_SHIFT);

	if (msgbuf[0] != (RNP_VF_SET_VLAN | RNP_VT_MSGTYPE_ACK))
		err = RNP_ERR_INVALID_ARGUMENT;

mbx_err:
	return err;
}

static s32 rnpvf_set_vlan_strip(struct rnpvf_hw *hw, bool vlan_on)
{
	struct rnp_mbx_info *mbx = &hw->mbx;
	struct rnpvf_adapter *adapter = (struct rnpvf_adapter *)hw->back;
	u32 msgbuf[4];
	s32 err;
	int i;

	if (adapter->num_rx_queues > 2) {
		err = -EINVAL;
		goto mbx_err;
	}

	msgbuf[0] = RNP_VF_SET_VLAN_STRIP;
	msgbuf[1] = (vlan_on << 31) | adapter->num_rx_queues;

	for (i = 0; i < adapter->num_rx_queues; i++)
		msgbuf[2 + i] = adapter->rx_ring[i]->rnpvf_queue_idx;

	err = mbx->ops.write_posted(hw, msgbuf, 2 + adapter->num_rx_queues,
				    false);
	if (err)
		goto mbx_err;

	err = mbx->ops.read_posted(hw, msgbuf, 1, false);
	if (err)
		goto mbx_err;

	/* remove extra bits from the message */
	msgbuf[0] &= ~RNP_VT_MSGTYPE_CTS;
	msgbuf[0] &= ~(0xFF << RNP_VT_MSGINFO_SHIFT);

	if (msgbuf[0] != (RNP_VF_SET_VLAN_STRIP | RNP_VT_MSGTYPE_ACK))
		err = RNP_ERR_INVALID_ARGUMENT;

mbx_err:
	return err;
}

/**
 *  rnpvf_setup_mac_link_vf - Setup MAC link settings
 *  @hw: pointer to hardware structure
 *  @speed: Unused in this implementation
 *  @autoneg: Unused in this implementation
 *  @autoneg_wait_to_complete: Unused in this implementation
 *
 *  Do nothing and return success.  VF drivers are not allowed to change
 *  global settings.  Maintained for driver compatibility.
 **/
static s32 rnpvf_setup_mac_link_vf(struct rnpvf_hw *hw,
				   rnp_link_speed speed, bool autoneg,
				   bool autoneg_wait_to_complete)
{
	return 0;
}

/**
 *  rnpvf_check_mac_link_vf - Get link/speed status
 *  @hw: pointer to hardware structure
 *  @speed: pointer to link speed
 *  @link_up: true is link is up, false otherwise
 *  @autoneg_wait_to_complete: true when waiting for completion is needed
 *
 *  Reads the links register to determine if link is up and the current speed
 **/
static s32 rnpvf_check_mac_link_vf(struct rnpvf_hw *hw,
				   rnp_link_speed *speed, bool *link_up,
				   bool autoneg_wait_to_complete)
{
	*speed = hw->speed;
	*link_up = hw->link;

	return 0;
}

/**
 *  rnpvf_rlpml_set_vf - Set the maximum receive packet length
 *  @hw: pointer to the HW structure
 *  @max_size: value to assign to max frame size
 **/
void rnpvf_rlpml_set_vf(struct rnpvf_hw *hw, u16 max_size)
{
	u32 msgbuf[2];

	msgbuf[0] = RNP_VF_SET_LPE;
	msgbuf[1] = max_size;
	rnpvf_write_msg_read_ack(hw, msgbuf, 2);
}

/**
 *  rnpvf_negotiate_api_version - Negotiate supported API version
 *  @hw: pointer to the HW structure
 *  @api: integer containing requested API version
 **/
int rnpvf_negotiate_api_version(struct rnpvf_hw *hw, int api)
{
	return 0;
}

int rnpvf_get_queues(struct rnpvf_hw *hw, unsigned int *num_tcs,
		     unsigned int *default_tc)
{
	return -1;
}

void rnpvf_set_veb_mac_n10(struct rnpvf_hw *hw, u8 *mac, u32 vfnum,
			   u32 ring)
{
	int port;
	u32 maclow, machi;

	maclow = (mac[2] << 24) | (mac[3] << 16) | (mac[4] << 8) | mac[5];
	machi = (mac[0] << 8) | mac[1];
	for (port = 0; port < 4; port++) {
		maclow = (mac[2] << 24) | (mac[3] << 16) | (mac[4] << 8) |
			 mac[5];
		machi = (mac[0] << 8) | mac[1];

		wr32(hw, RNP_DMA_PORT_VBE_MAC_LO_TBL_N10(port, vfnum),
		     maclow);
		wr32(hw, RNP_DMA_PORT_VBE_MAC_HI_TBL_N10(port, vfnum),
		     machi);
		wr32(hw, RNP_DMA_PORT_VEB_VF_RING_TBL_N10(port, vfnum),
		     ring);
	}
}

void rnpvf_set_vlan_n10(struct rnpvf_hw *hw, u16 vid, u32 vf_num)
{
	int port;

	for (port = 0; port < 4; port++)
		wr32(hw, RNP_DMA_PORT_VEB_VID_TBL_N10(port, vf_num), vid);
}

static const struct rnpvf_hw_operations rnpvf_hw_ops_n10 = {
	.set_veb_mac = rnpvf_set_veb_mac_n10,
	.set_veb_vlan = rnpvf_set_vlan_n10,
};

static s32 rnpvf_get_invariants_n10(struct rnpvf_hw *hw)
{
	struct rnp_mbx_info *mbx = &hw->mbx;
#ifdef FIX_MAC_PADDIN
	struct rnpvf_adapter *adapter = (struct rnpvf_adapter *)hw->back;
#endif

	hw->feature_flags |=
		RNPVF_NET_FEATURE_SG | RNPVF_NET_FEATURE_TX_CHECKSUM |
		RNPVF_NET_FEATURE_RX_CHECKSUM | RNPVF_NET_FEATURE_TSO |
		RNPVF_NET_FEATURE_TX_UDP_TUNNEL |
		RNPVF_NET_FEATURE_VLAN_OFFLOAD | RNPVF_NET_FEATURE_RX_HASH;

	mbx->pf2vf_mbox_vec_base = 0xa5000;
	mbx->vf2pf_mbox_vec_base = 0xa5100;
	mbx->cpu2vf_mbox_vec_base = 0xa5200;
	mbx->cpu2pf_mbox_vec = 0xa5300;
	mbx->pf_vf_shm_base = 0xa6000;
	mbx->cpu_vf_shm_base = 0xa8000;
	mbx->vf2cpu_mbox_ctrl_base = 0xa9000;
	mbx->cpu_vf_mbox_mask_lo_base = 0xa9200;
	mbx->cpu_vf_mbox_mask_hi_base = 0xa9300;
	mbx->mbx_mem_size = 64;

	mbx->vf2pf_mbox_ctrl_base = 0xa7000;
	mbx->pf2vf_mbox_ctrl_base = 0xa7100;
	mbx->pf_vf_mbox_mask_lo = 0xa7200;
	mbx->pf_vf_mbox_mask_hi = 0xa7300;

	mbx->cpu_pf_shm_base = 0xaa000;
	mbx->pf2cpu_mbox_ctrl = 0xaa100;
	mbx->pf2cpu_mbox_mask = 0xaa300;

	mbx->vf_num_mask = 0x3f;

	hw->min_length = RNPVF_MIN_MTU;
	hw->max_length = RNPVF_N10_MAX_JUMBO_FRAME_SIZE;

#ifdef FIX_MAC_PADDIN
	adapter->priv_flags |= RNPVF_PRIV_FLAG_TX_PADDING;
#endif

	memcpy(&hw->ops, &rnpvf_hw_ops_n10, sizeof(hw->ops));

	return 0;
}

static const struct rnp_mac_operations rnpvf_mac_ops = {
	.init_hw = rnpvf_init_hw_vf,
	.reset_hw = rnpvf_reset_hw_vf,
	.start_hw = rnpvf_start_hw_vf,
	.get_mac_addr = rnpvf_get_mac_addr_vf,
	.get_queues = rnpvf_get_queues_vf,
	.stop_adapter = rnpvf_stop_hw_vf,
	.setup_link = rnpvf_setup_mac_link_vf,
	.check_link = rnpvf_check_mac_link_vf,
	.set_rar = rnpvf_set_rar_vf,
	.update_mc_addr_list = rnpvf_update_mc_addr_list_vf,
	.set_uc_addr = rnpvf_set_uc_addr_vf,
	.set_vfta = rnpvf_set_vfta_vf,
	.set_vlan_strip = rnpvf_set_vlan_strip,
	.read_eth_reg = rnpvf_read_eth_reg,
	.get_mtu = rnpvf_get_mtu,
	.set_mtu = rnpvf_set_mtu,
	.req_reset_pf = rnpvf_reset_pf,
};

const struct rnpvf_info rnp_n10_vf_info = {
	.mac = rnp_mac_2port_40G,
	.mac_ops = &rnpvf_mac_ops,
	.board_type = rnp_board_n10,
	.get_invariants = &rnpvf_get_invariants_n10,
};
