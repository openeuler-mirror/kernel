// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 - 2024 Mucse Corporation. */

#include "vf.h"
#include "rnpgbevf.h"

static int rnpgbevf_reset_pf(struct rnpgbevf_hw *hw)
{
	struct rnp_mbx_info *mbx = &hw->mbx;
	u32 msgbuf[2];
	s32 ret_val;

	memset(msgbuf, 0, sizeof(msgbuf));
	msgbuf[0] = RNPGBE_VF_RESET_PF;

	ret_val = mbx->ops.write_posted(hw, msgbuf, 2, false);

	if (!ret_val)
		ret_val = mbx->ops.read_posted(hw, msgbuf, 2, false);

	return ret_val;
}

static int rnpgbevf_get_mtu(struct rnpgbevf_hw *hw)
{
	struct rnp_mbx_info *mbx = &hw->mbx;
	u32 msgbuf[2];
	s32 ret_val;

	memset(msgbuf, 0, sizeof(msgbuf));
	msgbuf[0] = RNPGBE_VF_GET_MTU;

	ret_val = mbx->ops.write_posted(hw, msgbuf, 2, false);

	if (!ret_val)
		ret_val = mbx->ops.read_posted(hw, msgbuf, 2, false);

	msgbuf[0] &= ~RNPGBE_VT_MSGTYPE_CTS;

	/* if nacked the address was rejected, use "perm_addr" */
	if (!ret_val &&
	    (msgbuf[0] == (RNPGBE_VF_GET_MTU | RNPGBE_VT_MSGTYPE_NACK))) {
		return -1;
	}
	hw->mtu = msgbuf[1];

	return ret_val;
}

static int rnpgbevf_set_mtu(struct rnpgbevf_hw *hw, int mtu)
{
	struct rnp_mbx_info *mbx = &hw->mbx;
	u32 msgbuf[2];
	s32 ret_val;

	memset(msgbuf, 0, sizeof(msgbuf));
	msgbuf[0] = RNPGBE_VF_SET_MTU;
	msgbuf[1] = mtu;

	ret_val = mbx->ops.write_posted(hw, msgbuf, 2, false);

	if (!ret_val)
		ret_val = mbx->ops.read_posted(hw, msgbuf, 2, false);

	msgbuf[0] &= ~RNPGBE_VT_MSGTYPE_CTS;

	/* if nacked the address was rejected, use "perm_addr" */
	if (!ret_val &&
	    (msgbuf[0] == (RNPGBE_VF_SET_MTU | RNPGBE_VT_MSGTYPE_NACK))) {
		return -1;
	}

	return ret_val;
}

static int rnpgbevf_read_eth_reg(struct rnpgbevf_hw *hw, int reg, u32 *value)
{
	struct rnp_mbx_info *mbx = &hw->mbx;
	u32 msgbuf[2];
	int err;

	msgbuf[0] = RNPGBE_VF_REG_RD;
	msgbuf[1] = reg;

	err = mbx->ops.write_posted(hw, msgbuf, 2, false);
	if (err)
		goto mbx_err;

	err = mbx->ops.read_posted(hw, msgbuf, 2, false);
	if (err)
		goto mbx_err;

	/* remove extra bits from the message */
	msgbuf[0] &= ~RNPGBE_VT_MSGTYPE_CTS;
	msgbuf[0] &= ~(0xFF << RNPGBE_VT_MSGINFO_SHIFT);

	if (msgbuf[0] != (RNPGBE_VF_REG_RD | RNPGBE_VT_MSGTYPE_ACK))
		err = RNPGBE_ERR_INVALID_ARGUMENT;

	*value = msgbuf[1];

mbx_err:
	return err;
}

/**
 *  rnpgbevf_start_hw_vf - Prepare hardware for Tx/Rx
 *  @hw: pointer to hardware structure
 *
 *  Starts the hardware by filling the bus info structure and media type, clears
 *  all on chip counters, initializes receive address registers, multicast
 *  table, VLAN filter table, calls routine to set up link and flow control
 *  settings, and leaves transmit and receive units disabled and uninitialized
 **/
static s32 rnpgbevf_start_hw_vf(struct rnpgbevf_hw *hw)
{
	/* Clear adapter stopped flag */
	hw->adapter_stopped = false;

	return 0;
}

/**
 *  rnpgbevf_init_hw_vf - virtual function hardware initialization
 *  @hw: pointer to hardware structure
 *
 *  Initialize the hardware by resetting the hardware and then starting
 *  the hardware
 **/
static s32 rnpgbevf_init_hw_vf(struct rnpgbevf_hw *hw)
{
	s32 status;

	status = hw->mac.ops.start_hw(hw);

	hw->mac.ops.get_mac_addr(hw, hw->mac.addr);

	return status;
}

/**
 *  rnpgbevf_reset_hw_vf - Performs hardware reset
 *  @hw: pointer to hardware structure
 *
 *  Resets the hardware by resetting the transmit and receive units, masks and
 *  clears all interrupts.
 **/
static s32 rnpgbevf_reset_hw_vf(struct rnpgbevf_hw *hw)
{
	struct rnp_mbx_info *mbx = &hw->mbx;
	struct rnpgbevf_adapter *adapter = hw->back;
	s32 ret_val = RNPGBE_ERR_INVALID_MAC_ADDR;
	u32 msgbuf[RNPGBE_VF_PERMADDR_MSG_LEN];
	u8 *addr = (u8 *)(&msgbuf[1]);
	u32 vlan;
	int try_cnt = 10;

	/* Call adapter stop to disable tx/rx and clear interrupts */
	hw->mac.ops.stop_adapter(hw);

	/* reset the api version */
	hw->api_version = 0;

	/* mailbox timeout can now become active */
	mbx->timeout = RNPGBE_VF_MBX_INIT_TIMEOUT;

	while (try_cnt--) {
		msgbuf[0] = RNPGBE_VF_RESET;
		mbx->ops.write_posted(hw, msgbuf, 1, false);
		/* ack write back maybe too fast */
		mdelay(20);

		/* set our "perm_addr" based on info provided by PF */
		/* also set up the mc_filter_type which is piggy backed
		 * on the mac address in word 3
		 */
		ret_val = mbx->ops.read_posted(hw, msgbuf,
					       RNPGBE_VF_PERMADDR_MSG_LEN,
					       false);
		if (ret_val == 0)
			break;
	}
	if (ret_val) {
		dev_info(&hw->pdev->dev, "echo vf reset timeout\n");
		return ret_val;
	}

	/* New versions of the PF may NACK the reset return message
	 * to indicate that no MAC address has yet been assigned for
	 * the VF.
	 */
	if (msgbuf[0] != (RNPGBE_VF_RESET | RNPGBE_VT_MSGTYPE_ACK) &&
	    msgbuf[0] != (RNPGBE_VF_RESET | RNPGBE_VT_MSGTYPE_NACK))
		return RNPGBE_ERR_INVALID_MAC_ADDR;
	/* we get mac address from mailbox */

	memcpy(hw->mac.perm_addr, addr, ETH_ALEN);
	hw->mac.mc_filter_type = msgbuf[RNPGBE_VF_MC_TYPE_WORD] & 0xff;

	/* ft padding */
	if ((msgbuf[RNPGBE_VF_MC_TYPE_WORD] >> 8) & 0xff)
		adapter->priv_flags |= RNPVF_PRIV_FLAG_FT_PADDING;
	else
		adapter->priv_flags = 0;
	/* fc mode */
	hw->fc.current_mode = (msgbuf[RNPGBE_VF_MC_TYPE_WORD] >> 16) & 0xff;

	/* phy status */
	hw->phy_type = (msgbuf[RNPGBE_VF_PHY_TYPE_WORD] & 0xffff);

	hw->mac.dma_version = msgbuf[RNPGBE_VF_DMA_VERSION_WORD];

	hw->dma_version = hw->mac.dma_version;
	/* vlan status */
	vlan = msgbuf[RNPGBE_VF_VLAN_WORD];

	if (vlan & 0xffff) {
		adapter->vf_vlan = vlan & 0xffff;
		adapter->flags |= RNPVF_FLAG_PF_SET_VLAN;
	}

	hw->ops.set_veb_vlan(hw, vlan, VFNUM(mbx, hw->vfnum));
	hw->fw_version = msgbuf[RNPGBE_VF_FW_VERSION_WORD];

	if (msgbuf[RNPGBE_VF_LINK_STATUS_WORD] & RNPGBE_PF_LINK_UP) {
		hw->link = true;
		hw->speed = msgbuf[RNPGBE_VF_LINK_STATUS_WORD] & 0xffff;

	} else {
		hw->link = false;
		hw->speed = 0;
	}

	hw->usecstocount = msgbuf[RNPGBE_VF_AXI_MHZ];

	DPRINTK(PROBE, INFO, "dma_version:%x vlan %d\n", hw->mac.dma_version,
		adapter->vf_vlan);
	DPRINTK(PROBE, INFO, "axi:%x\n", hw->usecstocount);
	DPRINTK(PROBE, INFO, "firmware :%x\n", hw->fw_version);
	DPRINTK(PROBE, INFO, "link speed :%x\n", hw->speed);
	DPRINTK(PROBE, INFO, "link status :%s\n", hw->link ? "up" : "down");
	hw->pf_feature = msgbuf[RNPGBE_VF_FEATURE];

	return 0;
}

/**
 *  rnpgbevf_stop_hw_vf - Generic stop Tx/Rx units
 *  @hw: pointer to hardware structure
 *
 *  Sets the adapter_stopped flag within rnpgbevf_hw struct. Clears interrupts,
 *  disables transmit and receive units. The adapter_stopped flag is used by
 *  the shared code and drivers to determine if the adapter is in a stopped
 *  state and should not touch the hardware.
 **/
static s32 rnpgbevf_stop_hw_vf(struct rnpgbevf_hw *hw)
{
	u32 number_of_queues;
	u16 i;
	struct rnpgbevf_adapter *adapter = hw->back;
	struct rnpgbevf_ring *ring;

	/* Set the adapter_stopped flag so other driver functions stop touching
	 * the hardware
	 */
	hw->adapter_stopped = true;

	/* Disable the receive unit by stopped each queue */
	for (i = 0; i < adapter->num_rx_queues; i++) {
		ring = adapter->rx_ring[i];
		ring_wr32(ring, RNPGBE_DMA_RX_START, 0);
	}

	/* Disable the transmit unit.  Each queue must be disabled. */
	number_of_queues = hw->mac.max_tx_queues;

	return 0;
}

/**
 *  rnpgbevf_mta_vector - Determines bit-vector in multicast table to set
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
static s32 rnpgbevf_mta_vector(struct rnpgbevf_hw *hw, u8 *mc_addr)
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
 *  rnpgbevf_get_mac_addr_vf - Read device MAC address
 *  @hw: pointer to the HW structure
 *  @mac_addr: pointer to storage for retrieved MAC address
 **/
static s32 rnpgbevf_get_mac_addr_vf(struct rnpgbevf_hw *hw, u8 *mac_addr)
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
	msgbuf[0] |= RNPGBE_VF_SET_MACVLAN;
	ret_val = mbx->ops.write_posted(hw, msgbuf, 1, false);

	if (!ret_val)
		ret_val = mbx->ops.read_posted(hw, msgbuf, 3, false);

	msgbuf[0] &= ~RNPGBE_VT_MSGTYPE_CTS;

	if (!ret_val) {
		if (msgbuf[0] ==
		    (RNPGBE_VF_GET_MACVLAN | RNPGBE_VT_MSGTYPE_NACK))
			ret_val = -ENOMEM;
	}

	memcpy(mac_addr, msg_addr, 6);

	return 0;
}

/**
 *  rnpgbevf_get_queues_vf - Read device MAC address
 *  @hw: pointer to the HW structure
 *  @mac_addr: pointer to storage for retrieved MAC address
 **/
static s32 rnpgbevf_get_queues_vf(struct rnpgbevf_hw *hw)
{
	struct rnp_mbx_info *mbx = &hw->mbx;
	s32 ret_val = 0;
	u32 msgbuf[7];

	memset(msgbuf, 0, sizeof(msgbuf));
	msgbuf[0] |= RNPGBE_VF_GET_QUEUE;

	ret_val = mbx->ops.write_posted(hw, msgbuf, 1, false);

	mdelay(10);

	if (!ret_val)
		ret_val = mbx->ops.read_posted(hw, msgbuf, 7, false);

	msgbuf[0] &= ~RNPGBE_VT_MSGTYPE_CTS;

	if (!ret_val)
		if (msgbuf[0] == (RNPGBE_VF_GET_QUEUE | RNPGBE_VT_MSGTYPE_NACK))
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

static s32 rnpgbevf_set_uc_addr_vf(struct rnpgbevf_hw *hw, u32 index, u8 *addr)
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
	msgbuf[0] |= index << RNPGBE_VT_MSGINFO_SHIFT;
	msgbuf[0] |= RNPGBE_VF_SET_MACVLAN;
	if (addr)
		memcpy(msg_addr, addr, 6);
	ret_val = mbx->ops.write_posted(hw, msgbuf, 3, false);

	if (!ret_val)
		ret_val = mbx->ops.read_posted(hw, msgbuf, 3, false);

	msgbuf[0] &= ~RNPGBE_VT_MSGTYPE_CTS;

	if (!ret_val)
		if (msgbuf[0] ==
		    (RNPGBE_VF_SET_MACVLAN | RNPGBE_VT_MSGTYPE_NACK))
			ret_val = -ENOMEM;
	return ret_val;
}

/**
 *  rnpgbevf_set_rar_vf - set device MAC address
 *  @hw: pointer to hardware structure
 *  @index: Receive address register to write
 *  @addr: Address to put into receive address register
 *  @vmdq: Unused in this implementation
 **/
static s32 rnpgbevf_set_rar_vf(struct rnpgbevf_hw *hw, u32 index, u8 *addr,
			       u32 vmdq)
{
	struct rnp_mbx_info *mbx = &hw->mbx;
	u32 msgbuf[3];
	u8 *msg_addr = (u8 *)(&msgbuf[1]);
	s32 ret_val;

	memset(msgbuf, 0, sizeof(msgbuf));
	msgbuf[0] = RNPGBE_VF_SET_MAC_ADDR;
	memcpy(msg_addr, addr, 6);
	ret_val = mbx->ops.write_posted(hw, msgbuf, 3, false);

	if (!ret_val)
		ret_val = mbx->ops.read_posted(hw, msgbuf, 3, false);

	msgbuf[0] &= ~RNPGBE_VT_MSGTYPE_CTS;

	/* if nacked the address was rejected, use "perm_addr" */
	if (!ret_val &&
	    (msgbuf[0] == (RNPGBE_VF_SET_MAC_ADDR | RNPGBE_VT_MSGTYPE_NACK))) {
		rnpgbevf_get_mac_addr_vf(hw, hw->mac.addr);
		return -1;
	}

	return ret_val;
}

static void rnpgbevf_write_msg_read_ack(struct rnpgbevf_hw *hw, u32 *msg,
					u16 size)
{
	u32 retmsg[RNPGBE_VFMAILBOX_SIZE];
	s32 retval;
	struct rnp_mbx_info *mbx = &hw->mbx;

	retval = mbx->ops.write_posted(hw, msg, size, false);
	if (!retval)
		mbx->ops.read_posted(hw, retmsg, size, false);
}

u8 *rnpgbevf_addr_list_itr(struct rnpgbevf_hw __maybe_unused *hw,
			   u8 **mc_addr_ptr)
{
	struct netdev_hw_addr *mc_ptr;
	u8 *addr = *mc_addr_ptr;

	mc_ptr = container_of(addr, struct netdev_hw_addr, addr[0]);
	if (mc_ptr->list.next) {
		struct netdev_hw_addr *ha;

		ha = list_entry(mc_ptr->list.next, struct netdev_hw_addr, list);
		*mc_addr_ptr = ha->addr;
	} else {
		*mc_addr_ptr = NULL;
	}

	return addr;
}

/**
 *  rnpgbevf_update_mc_addr_list_vf - Update Multicast addresses
 *  @hw: pointer to the HW structure
 *  @netdev: pointer to net device structure
 *
 *  Updates the Multicast Table Array.
 **/
static s32 rnpgbevf_update_mc_addr_list_vf(struct rnpgbevf_hw *hw,
					   struct net_device *netdev)
{
	struct netdev_hw_addr *ha;
	u32 msgbuf[RNPGBE_VFMAILBOX_SIZE];
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
	msgbuf[0] = RNPGBE_VF_SET_MULTICAST;
	msgbuf[0] |= cnt << RNPGBE_VT_MSGINFO_SHIFT;

	addr_count = netdev_mc_count(netdev);

	ha = list_first_entry(&netdev->mc.list, struct netdev_hw_addr, list);
	addr_list = ha->addr;
	for (i = 0; i < addr_count; i++) {
		vector_list[i] = rnpgbevf_mta_vector(hw,
				rnpgbevf_addr_list_itr(hw, &addr_list));
	}

	rnpgbevf_write_msg_read_ack(hw, msgbuf, RNPGBE_VFMAILBOX_SIZE);

	return 0;
}

/**
 *  rnpgbevf_set_vfta_vf - Set/Unset vlan filter table address
 *  @hw: pointer to the HW structure
 *  @vlan: 12 bit VLAN ID
 *  @vind: unused by VF drivers
 *  @vlan_on: if true then set bit, else clear bit
 **/
static s32 rnpgbevf_set_vfta_vf(struct rnpgbevf_hw *hw, u32 vlan, u32 vind,
				bool vlan_on)
{
	struct rnp_mbx_info *mbx = &hw->mbx;
	u32 msgbuf[2];
	s32 err;

	msgbuf[0] = RNPGBE_VF_SET_VLAN;
	msgbuf[1] = vlan;
	/* Setting the 8 bit field MSG INFO to TRUE indicates "add" */
	msgbuf[0] |= vlan_on << RNPGBE_VT_MSGINFO_SHIFT;

	err = mbx->ops.write_posted(hw, msgbuf, 2, false);
	if (err)
		goto mbx_err;

	err = mbx->ops.read_posted(hw, msgbuf, 2, false);
	if (err)
		goto mbx_err;

	/* remove extra bits from the message */
	msgbuf[0] &= ~RNPGBE_VT_MSGTYPE_CTS;
	msgbuf[0] &= ~(0xFF << RNPGBE_VT_MSGINFO_SHIFT);

	if (msgbuf[0] != (RNPGBE_VF_SET_VLAN | RNPGBE_VT_MSGTYPE_ACK))
		err = RNPGBE_ERR_INVALID_ARGUMENT;

mbx_err:
	return err;
}

static s32 rnpgbevf_set_vlan_strip(struct rnpgbevf_hw *hw, bool vlan_on)
{
	struct rnp_mbx_info *mbx = &hw->mbx;
	struct rnpgbevf_adapter *adapter = (struct rnpgbevf_adapter *)hw->back;
	u32 msgbuf[4];
	s32 err;
	int i;

	if (adapter->num_rx_queues > 2) {
		err = -EINVAL;
		goto mbx_err;
	}

	msgbuf[0] = RNPGBE_VF_SET_VLAN_STRIP;
	msgbuf[1] = (vlan_on << 31) | adapter->num_rx_queues;

	for (i = 0; i < adapter->num_rx_queues; i++)
		msgbuf[2 + i] = adapter->rx_ring[i]->rnpgbevf_queue_idx;

	err = mbx->ops.write_posted(hw, msgbuf, 2 + adapter->num_rx_queues,
				    false);
	if (err)
		goto mbx_err;

	err = mbx->ops.read_posted(hw, msgbuf, 1, false);
	if (err)
		goto mbx_err;

	/* remove extra bits from the message */
	msgbuf[0] &= ~RNPGBE_VT_MSGTYPE_CTS;
	msgbuf[0] &= ~(0xFF << RNPGBE_VT_MSGINFO_SHIFT);

	if (msgbuf[0] != (RNPGBE_VF_SET_VLAN_STRIP | RNPGBE_VT_MSGTYPE_ACK))
		err = RNPGBE_ERR_INVALID_ARGUMENT;

mbx_err:
	return err;
}

/**
 *  rnpgbevf_setup_mac_link_vf - Setup MAC link settings
 *  @hw: pointer to hardware structure
 *  @speed: Unused in this implementation
 *  @autoneg: Unused in this implementation
 *  @autoneg_wait_to_complete: Unused in this implementation
 *
 *  Do nothing and return success.  VF drivers are not allowed to change
 *  global settings.  Maintained for driver compatibility.
 **/
static s32 rnpgbevf_setup_mac_link_vf(struct rnpgbevf_hw *hw,
				      rnp_link_speed speed, bool autoneg,
				      bool autoneg_wait_to_complete)
{
	return 0;
}

/**
 *  rnpgbevf_check_mac_link_vf - Get link/speed status
 *  @hw: pointer to hardware structure
 *  @speed: pointer to link speed
 *  @link_up: true is link is up, false otherwise
 *  @autoneg_wait_to_complete: true when waiting for completion is needed
 *
 *  Reads the links register to determine if link is up and the current speed
 **/
static s32 rnpgbevf_check_mac_link_vf(struct rnpgbevf_hw *hw,
				      rnp_link_speed *speed, bool *link_up,
				      bool autoneg_wait_to_complete)
{
	*speed = hw->speed;
	*link_up = hw->link;

	return 0;
}

/**
 *  rnpgbevf_rlpml_set_vf - Set the maximum receive packet length
 *  @hw: pointer to the HW structure
 *  @max_size: value to assign to max frame size
 **/
void rnpgbevf_rlpml_set_vf(struct rnpgbevf_hw *hw, u16 max_size)
{
	u32 msgbuf[2];

	msgbuf[0] = RNPGBE_VF_SET_LPE;
	msgbuf[1] = max_size;
	rnpgbevf_write_msg_read_ack(hw, msgbuf, 2);
}

/**
 *  rnpgbevf_negotiate_api_version - Negotiate supported API version
 *  @hw: pointer to the HW structure
 *  @api: integer containing requested API version
 **/
int rnpgbevf_negotiate_api_version(struct rnpgbevf_hw *hw, int api)
{
	return 0;
}

int rnpgbevf_get_queues(struct rnpgbevf_hw *hw, unsigned int *num_tcs,
			unsigned int *default_tc)
{
	return -1;
}

void rnpgbevf_set_veb_mac_n500(struct rnpgbevf_hw *hw, u8 *mac, u32 vf_num,
			       u32 ring)
{
	u32 maclow, machi;

	maclow = (mac[2] << 24) | (mac[3] << 16) | (mac[4] << 8) | mac[5];
	machi = (mac[0] << 8) | mac[1];

	wr32(hw, RNPGBE_DMA_PORT_VBE_MAC_LO_TBL_N500, maclow);
	wr32(hw, RNPGBE_DMA_PORT_VBE_MAC_HI_TBL_N500, machi);
	wr32(hw, RNPGBE_DMA_PORT_VEB_VF_RING_TBL_N500, ring);
}

void rnpgbevf_set_vlan_n500(struct rnpgbevf_hw *hw, u16 vid, u32 vf_num)
{
	wr32(hw, RNPGBE_DMA_PORT_VEB_VID_TBL_N500, vid);
}

static const struct rnpgbevf_hw_operations rnpgbevf_hw_ops_n500 = {
	.set_veb_mac = rnpgbevf_set_veb_mac_n500,
	.set_veb_vlan = rnpgbevf_set_vlan_n500,
};

static s32 rnpgbevf_get_invariants_n500(struct rnpgbevf_hw *hw)
{
	struct rnp_mbx_info *mbx = &hw->mbx;

	hw->feature_flags |=
		RNPVF_NET_FEATURE_SG | RNPVF_NET_FEATURE_TX_CHECKSUM |
		RNPVF_NET_FEATURE_RX_CHECKSUM | RNPVF_NET_FEATURE_TSO |
		RNPVF_NET_FEATURE_VLAN_OFFLOAD |
		RNPVF_NET_FEATURE_STAG_OFFLOAD | RNPVF_NET_FEATURE_USO |
		RNPVF_NET_FEATURE_RX_HASH;

	mbx->pf2vf_mbox_vec_base = 0x28800;
	mbx->vf2pf_mbox_vec_base = 0x28900;
	mbx->cpu2vf_mbox_vec_base = 0x28a00;
	mbx->cpu2pf_mbox_vec = 0x28b00;
	mbx->pf_vf_shm_base = 0x29000;
	mbx->cpu_vf_shm_base = 0x2b000;
	mbx->vf2cpu_mbox_ctrl_base = 0x2c000;
	mbx->cpu_vf_mbox_mask_lo_base = 0x2c200;
	mbx->cpu_vf_mbox_mask_hi_base = 0;
	mbx->mbx_mem_size = 64;

	mbx->vf2pf_mbox_ctrl_base = 0x2a000;
	mbx->pf2vf_mbox_ctrl_base = 0x2a100;
	mbx->pf_vf_mbox_mask_lo = 0x2a200;
	mbx->pf_vf_mbox_mask_hi = 0;

	mbx->cpu_pf_shm_base = 0x2d040;
	mbx->pf2cpu_mbox_ctrl = 0x2e000;
	mbx->pf2cpu_mbox_mask = 0x2e200;

	mbx->vf_num_mask = 0x1f;

	hw->min_length = RNPVF_MIN_MTU;
	hw->max_length = RNPVF_N500_MAX_JUMBO_FRAME_SIZE;

	memcpy(&hw->ops, &rnpgbevf_hw_ops_n500, sizeof(hw->ops));

	return 0;
}

static s32 rnpgbevf_get_invariants_n210(struct rnpgbevf_hw *hw)
{
	struct rnp_mbx_info *mbx = &hw->mbx;

	hw->feature_flags |=
		RNPVF_NET_FEATURE_SG | RNPVF_NET_FEATURE_TX_CHECKSUM |
		RNPVF_NET_FEATURE_RX_CHECKSUM | RNPVF_NET_FEATURE_TSO |
		RNPVF_NET_FEATURE_VLAN_OFFLOAD |
		RNPVF_NET_FEATURE_STAG_OFFLOAD | RNPVF_NET_FEATURE_USO |
		RNPVF_NET_FEATURE_RX_HASH;

	mbx->pf2vf_mbox_vec_base = 0x29100;
	mbx->vf2pf_mbox_vec_base = 0x29200;
	mbx->cpu2vf_mbox_vec_base = 0x29300;
	mbx->cpu2pf_mbox_vec = 0x29400;
	mbx->pf_vf_shm_base = 0x29900;
	mbx->cpu_vf_shm_base = 0x2b900;
	mbx->vf2cpu_mbox_ctrl_base = 0x2c900;
	mbx->cpu_vf_mbox_mask_lo_base = 0x2cb00;
	mbx->cpu_vf_mbox_mask_hi_base = 0;
	mbx->mbx_mem_size = 64;

	mbx->vf2pf_mbox_ctrl_base = 0x2a900;
	mbx->pf2vf_mbox_ctrl_base = 0x2aa00;
	mbx->pf_vf_mbox_mask_lo = 0x2a200;
	mbx->pf_vf_mbox_mask_hi = 0;

	mbx->cpu_pf_shm_base = 0x2d940;
	mbx->pf2cpu_mbox_ctrl = 0x2e900;
	mbx->pf2cpu_mbox_mask = 0x2eb00;

	mbx->vf_num_mask = 0x1f;

	hw->min_length = RNPVF_MIN_MTU;
	hw->max_length = RNPVF_N500_MAX_JUMBO_FRAME_SIZE;

	memcpy(&hw->ops, &rnpgbevf_hw_ops_n500, sizeof(hw->ops));

	return 0;
}

static const struct rnp_mac_operations rnpgbevf_mac_ops = {
	.init_hw = rnpgbevf_init_hw_vf,
	.reset_hw = rnpgbevf_reset_hw_vf,
	.start_hw = rnpgbevf_start_hw_vf,
	.get_mac_addr = rnpgbevf_get_mac_addr_vf,
	.get_queues = rnpgbevf_get_queues_vf,
	.stop_adapter = rnpgbevf_stop_hw_vf,
	.setup_link = rnpgbevf_setup_mac_link_vf,
	.check_link = rnpgbevf_check_mac_link_vf,
	.set_rar = rnpgbevf_set_rar_vf,
	.update_mc_addr_list = rnpgbevf_update_mc_addr_list_vf,
	.set_uc_addr = rnpgbevf_set_uc_addr_vf,
	.set_vfta = rnpgbevf_set_vfta_vf,
	.set_vlan_strip = rnpgbevf_set_vlan_strip,
	.read_eth_reg = rnpgbevf_read_eth_reg,
	.get_mtu = rnpgbevf_get_mtu,
	.set_mtu = rnpgbevf_set_mtu,
	.req_reset_pf = rnpgbevf_reset_pf,
};

const struct rnpgbevf_info rnp_n500_vf_info = {
	.mac = rnp_mac_2port_40G,
	.mac_ops = &rnpgbevf_mac_ops,
	.board_type = rnp_board_n500,
	.get_invariants = &rnpgbevf_get_invariants_n500,
};

const struct rnpgbevf_info rnp_n210_vf_info = {
	.mac = rnp_mac_2port_40G,
	.mac_ops = &rnpgbevf_mac_ops,
	.board_type = rnp_board_n210,
	.get_invariants = &rnpgbevf_get_invariants_n210,
};
