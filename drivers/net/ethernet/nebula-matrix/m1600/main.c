// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author: Monte Song <monte.song@nebula-matrix.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/pci.h>
#include <linux/device.h>
#include <linux/aer.h>

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>

#include "hw.h"
#include "common.h"
#include "ethtool.h"
#include "interrupt.h"
#include "txrx.h"
#include "mailbox.h"
#include "hwmon.h"
#include "macvlan.h"
#include "sriov.h"

/* workqueue 1 is used to process mailbox work or others conflict with
 * works in workqueue 2, and workqueue 2 is used to process link status
 * monitoring task. We use two different workqueue because works like
 * link status monitoring wait for mailbox work to complete. If these
 * works is added to the same workqueue, deadlock arises.
 */
#define NBL_X4_WQ1 "nbl_X4_wq1"
#define NBL_X4_WQ2 "nbl_X4_wq2"
static struct workqueue_struct *nbl_wq1;
static struct workqueue_struct *nbl_wq2;

static int debug = -1;
module_param(debug, int, 0);
MODULE_PARM_DESC(debug, "Network interface message level setting");

static u32 ring_num = NBL_DEFAULT_RING_NUM;
module_param(ring_num, uint, 0444);
MODULE_PARM_DESC(ring_num, "Netdev ring num setting, with a maximum value of 16");

static u32 vf_ring_num = NBL_VF_DEFAULT_RING_NUM;
module_param(vf_ring_num, uint, 0444);
MODULE_PARM_DESC(vf_ring_num, "Netdev ring num setting of VF, with a maximum value of 16");

#define DEFAULT_MSG_ENABLE (NETIF_MSG_DRV | NETIF_MSG_PROBE | NETIF_MSG_LINK | \
			    NETIF_MSG_IFDOWN | NETIF_MSG_IFUP)

void nbl_af_write_mac_to_logic(struct nbl_hw *hw, u8 eth_port_id, u8 *mac_addr)
{
	struct nbl_ped_port_smac ped_port_smac = { 0 };
	u32 *smac = (u32 *)&ped_port_smac;

	memcpy(ped_port_smac.smac, mac_addr, ETH_ALEN);
	wr32(hw, NBL_PED_PORT_SMAC_REG_L(eth_port_id), *smac);
	wr32(hw, NBL_PED_PORT_SMAC_REG_H(eth_port_id), *(smac + 1));
}

static void nbl_mac_addr_random_init(u8 *mac_addr)
{
	mac_addr[0] = 0x68;
	mac_addr[1] = 0xbe;
	mac_addr[2] = 0x49;
	mac_addr[3] = 0x10;

	get_random_bytes(&mac_addr[4], ETH_ALEN - 4);
}

int nbl_af_get_board_info(struct nbl_hw *hw, u8 eth_port_id, union nbl_board_info *board_info)
{
	u8 *addr = (u8 *)board_info;
	u32 i;
	int ret;

	for (i = 0; i < sizeof(union nbl_board_info); i++, addr++) {
		ret = nbl_read_eeprom_byte(hw, i, addr);
		if (ret < 0)
			return ret;
	}

	return ret;
}

static bool nbl_check_board_info(u8 *addr, u8 *magic, u32 len, u32 crc)
{
	u32 checksum = 0;
	u32 i;

	if (strncmp((char *)magic, NBL_MAC_X4_MAGIC, NBL_MAC_MAGIC_LEN))
		return false;

	for (i = 0; i < (len - sizeof(u32)); i++) {
		checksum += *addr;
		addr++;
	}

	return checksum == crc;
}

void nbl_write_mac_to_logic(struct nbl_hw *hw, u8 *mac_addr)
{
	if (is_af(hw))
		nbl_af_write_mac_to_logic(hw, hw->eth_port_id, mac_addr);
	else
		nbl_mailbox_req_write_mac_to_logic(hw, hw->eth_port_id, mac_addr);
}

static void nbl_mac_addr_init(struct nbl_adapter *adapter, u8 *mac_addr)
{
	union nbl_board_info board_info = { 0 };
	u8 eth_port_id = adapter->hw.eth_port_id;
	struct nbl_hw *hw = &adapter->hw;
	int err;

	if (is_vf(hw)) {
		nbl_mac_addr_random_init(mac_addr);
		return;
	}

	if (is_af(hw))
		err = nbl_af_get_board_info(hw, eth_port_id, &board_info);
	else
		err = nbl_mailbox_req_get_board_info(hw, eth_port_id, &board_info);

	if (err || !nbl_check_board_info((u8 *)&board_info, board_info.magic,
					 sizeof(union nbl_board_info), board_info.crc)) {
		nbl_mac_addr_random_init(mac_addr);
	} else {
		if (eth_port_id == 0)
			memcpy(mac_addr, board_info.mac1, ETH_ALEN);
		else if (eth_port_id == 1)
			memcpy(mac_addr, board_info.mac2, ETH_ALEN);
		else if (eth_port_id == 2)
			memcpy(mac_addr, board_info.mac3, ETH_ALEN);
		else if (eth_port_id == 3)
			memcpy(mac_addr, board_info.mac4, ETH_ALEN);
	}

	/* write mac addr to logic for sending pause frame */
	nbl_write_mac_to_logic(hw, mac_addr);
}

void nbl_service_task1_schedule(struct nbl_adapter *adapter)
{
	queue_work(nbl_wq1, &adapter->serv_task1);
}

void nbl_service_task2_schedule(struct nbl_adapter *adapter)
{
	if (test_bit(NBL_MAILBOX_READY, adapter->state))
		queue_work(nbl_wq2, &adapter->serv_task2);
}

void nbl_service_task_schedule(struct nbl_adapter *adapter)
{
	queue_work(nbl_wq1, &adapter->serv_task1);

	if (test_bit(NBL_MAILBOX_READY, adapter->state))
		queue_work(nbl_wq2, &adapter->serv_task2);
}

static void nbl_service_timer(struct timer_list *t)
{
	struct nbl_adapter *adapter = from_timer(adapter, t, serv_timer);

	mod_timer(&adapter->serv_timer, round_jiffies(adapter->serv_timer_period + jiffies));
	nbl_service_task_schedule(adapter);
}

enum NBL_MODULE_INPLACE_STATUS nbl_af_check_module_inplace(struct nbl_hw *hw, u8 eth_port_id)
{
	/* low means module inplace */
	if (!(rd32(hw, NBL_LSP_SFP_MOD_REG(eth_port_id)) & BIT(0)))
		return NBL_MODULE_INPLACE;

	return NBL_MODULE_NOT_INPLACE;
}

static inline enum NBL_MODULE_INPLACE_STATUS
nbl_check_module_inplace(struct nbl_hw *hw, u8 eth_port_id)
{
	if (is_af(hw))
		return nbl_af_check_module_inplace(hw, eth_port_id);
	else
		return nbl_mailbox_req_check_module_inplace(hw, eth_port_id);
}

static int nbl_get_module_eeprom_by_offset(struct nbl_hw *hw, u8 eth_port_id,
					   unsigned int offset, u8 *data, unsigned int len)
{
	struct ethtool_eeprom eeprom;

	eeprom.offset = offset;
	eeprom.len = len;

	if (is_af(hw))
		return nbl_af_get_module_eeprom(hw, eth_port_id, &eeprom, data);
	else
		return nbl_mailbox_req_get_module_eeprom(hw, eth_port_id, &eeprom, data);
}

static bool nbl_check_module_identifier(struct nbl_hw *hw, u8 eth_port_id)
{
	u8 identifier;
	int ret;

	ret = nbl_get_module_eeprom_by_offset(hw, eth_port_id, SFF_8472_IDENTIFIER,
					      &identifier, sizeof(identifier));
	if (ret) {
		pr_err("Read SFF_8472_IDENTIFIER register failed, eth_port: %d, ret: %d\n",
		       eth_port_id, ret);
		return 0;
	}

	return (identifier == SFF_IDENTIFIER_SFP);
}

static int nbl_get_module_bitrate(struct nbl_hw *hw, u8 eth_port_id)
{
	int ret;
	int bit_rate;
	u8 br_nom;
	u8 br_max;

	ret = nbl_get_module_eeprom_by_offset(hw, eth_port_id, SFF_8472_SIGNALING_RATE,
					      &br_nom, sizeof(br_nom));
	if (ret) {
		pr_err("Read SFF_8472_SIGNALING_RATE register failed, eth_port: %d\n",
		       eth_port_id);
		return ret;
	}

	ret = nbl_get_module_eeprom_by_offset(hw, eth_port_id, SFF_8472_SIGNALING_RATE_MAX,
					      &br_max, sizeof(br_max));
	if (ret) {
		pr_err("Read SFF_8472_SIGNALING_RATE_MAX register failed, eth_port: %d\n",
		       eth_port_id);
		return ret;
	}

	/* sff-8472 section 5.6 */
	if (br_nom == 0xFF)
		bit_rate = (u32)br_max * 250;
	else if (br_nom == 0)
		bit_rate = 0;
	else
		bit_rate = (u32)br_nom * 100;

	return bit_rate;
}

static int nbl_query_module_speed(struct nbl_hw *hw, u8 eth_port_id,
				  bool *support_10g, bool *support_1g)
{
	int ret;
	u8 capa_10g;
	u8 capa_1g;
	u8 cable_tech;
	int bit_rate;

	ret = nbl_get_module_eeprom_by_offset(hw, eth_port_id, SFF_8472_10GB_CAPABILITY,
					      &capa_10g, sizeof(capa_10g));
	if (ret) {
		pr_err("Read SFF_8472_10GB_CAPABILITY register failed, eth_port: %d\n",
		       eth_port_id);
		return ret;
	}

	/* check for support of 10G capability */
	if (capa_10g & BIT(SFF_8472_10G_SR_BIT) || capa_10g & BIT(SFF_8472_10G_LR_BIT) ||
	    capa_10g & BIT(SFF_8472_10G_LRM_BIT) || capa_10g & BIT(SFF_8472_10G_ER_BIT))
		*support_10g = true;

	ret = nbl_get_module_eeprom_by_offset(hw, eth_port_id, SFF_8472_1GB_CAPABILITY,
					      &capa_1g, sizeof(capa_1g));
	if (ret) {
		pr_err("Read SFF_8472_1GB_CAPABILITY register failed, eth_port: %d\n",
		       eth_port_id);
		return ret;
	}

	/* check for support of 1G capability */
	if (capa_1g & BIT(SFF_8472_1G_SX_BIT) || capa_1g & BIT(SFF_8472_1G_LX_BIT) ||
	    capa_1g & BIT(SFF_8472_1G_CX_BIT) || capa_1g & BIT(SFF_8472_1G_T_BIT))
		*support_1g = true;

	bit_rate = nbl_get_module_bitrate(hw, eth_port_id);
	if (bit_rate < 0) {
		pr_warn("Eth module %d read bit_rate failed\n", eth_port_id);
		return bit_rate;
	}

	switch (bit_rate / 1000) {
	case 10:
		*support_10g = true;
		break;
	case 1:
		*support_1g = true;
		break;
	default:
		pr_warn("Read module bit rate not 10G or 1G, eth port: %d\n", eth_port_id);
		break;
	}

	if (!(*support_10g) && !(*support_1g)) {
		/* if it is passive cable, set to 10G */
		ret = nbl_get_module_eeprom_by_offset(hw, eth_port_id, SFF_8472_CABLE_TECHNOLOGY,
						      &cable_tech, sizeof(cable_tech));
		if (ret) {
			pr_err("Read SFF_8472_CABLE_TECHNOLOGY register failed, eth_port: %d\n",
			       eth_port_id);
			return ret;
		}

		if (cable_tech & SFF_PASSIVE_CABLE)
			*support_10g = true;
	}

	return 0;
}

int nbl_af_config_module_speed(struct nbl_hw *hw, u8 target_speed, u8 eth_port_id)
{
	int speed_sel;
	u32 timeout = 100;
	enum nbl_eth_speed_mode current_speed;
	struct nbl_loopback_mode loopback_mode;
	struct nbl_eth_rx_stat eth_rx_stat;

	if (target_speed == NBL_MODULE_SPEED_1G)
		speed_sel = NBL_ETH_SPEED_MODE_1G;
	else
		speed_sel = NBL_ETH_SPEED_MODE_10G;

	rd32_for_each(hw, NBL_ETH_LOOPBACK_MODE_REG(eth_port_id),
		      (u32 *)&loopback_mode, sizeof(loopback_mode));
	current_speed = loopback_mode.speed_stat;

	if (speed_sel == current_speed)
		return current_speed;

	/* config registor to switch speed */
	loopback_mode.speed_sel = speed_sel;
	wr32_for_each(hw, NBL_ETH_LOOPBACK_MODE_REG(eth_port_id),
		      (u32 *)&loopback_mode, sizeof(loopback_mode));

	/* reset eth after change speed */
	wr32(hw, NBL_ETH_RESET_REG(eth_port_id), 0x1E);
	wr32(hw, NBL_ETH_RESET_REG(eth_port_id), 0x0);

	/* make sure registor loopback_bode.speed_sel is configed */
	mb();

	/* switching serdes speed */
	while (timeout) {
		rd32_for_each(hw, NBL_ETH_RX_STAT_REG(eth_port_id),
			      (u32 *)&eth_rx_stat, sizeof(eth_rx_stat));

		if (eth_rx_stat.switching == 0)
			break;

		usleep_range(100, 200);
		timeout--;
	}
	if (timeout == 0) {
		pr_warn("Wait switching serdes speed timeout, eth port: %d\n", eth_port_id);
		return -ETIMEDOUT;
	}

	/* check speed switch success or not */
	rd32_for_each(hw, NBL_ETH_LOOPBACK_MODE_REG(eth_port_id),
		      (u32 *)&loopback_mode, sizeof(loopback_mode));
	if (loopback_mode.speed_stat != speed_sel) {
		pr_err("Module speed set failed, eth port: %d\n", eth_port_id);
		return -ERANGE;
	}

	return speed_sel;
}

static void nbl_config_module_speed(struct nbl_hw *hw, u8 target_speed)
{
	int speed_stat;
	u8 eth_port_id = hw->eth_port_id;

	if (is_af(hw))
		speed_stat = nbl_af_config_module_speed(hw, target_speed, eth_port_id);
	else
		speed_stat = nbl_mailbox_req_config_module_speed(hw, target_speed, eth_port_id);

	if (speed_stat == NBL_ETH_SPEED_MODE_10G) {
		pr_info("Eth port %d speed mode: 10G", eth_port_id);
		__clear_bit(ETHTOOL_LINK_MODE_1000baseT_Full_BIT, hw->advertising);
		__clear_bit(ETHTOOL_LINK_MODE_1000baseKX_Full_BIT, hw->advertising);
		__set_bit(ETHTOOL_LINK_MODE_10000baseT_Full_BIT, hw->advertising);
		__set_bit(ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT, hw->advertising);
		__set_bit(ETHTOOL_LINK_MODE_10000baseKR_Full_BIT, hw->advertising);
	} else if (speed_stat == NBL_ETH_SPEED_MODE_1G) {
		pr_info("Eth port %d speed mode: 1G", eth_port_id);
		__clear_bit(ETHTOOL_LINK_MODE_10000baseT_Full_BIT, hw->advertising);
		__clear_bit(ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT, hw->advertising);
		__clear_bit(ETHTOOL_LINK_MODE_10000baseKR_Full_BIT, hw->advertising);
		__set_bit(ETHTOOL_LINK_MODE_1000baseT_Full_BIT, hw->advertising);
		__set_bit(ETHTOOL_LINK_MODE_1000baseKX_Full_BIT, hw->advertising);
	} else {
		pr_err("Speed set failed with err: %d, eth_port: %d\n", speed_stat, eth_port_id);
	}
}

void nbl_set_module_speed(struct nbl_hw *hw, u8 target_speed)
{
	u8 module_support = hw->module_support_speed;

	/* target_speed only use when support both 1G and 10G */
	switch (module_support) {
	case (NBL_MODULE_SPEED_10G | NBL_MODULE_SPEED_1G):
		nbl_config_module_speed(hw, target_speed);
		break;
	case NBL_MODULE_SPEED_1G:
		nbl_config_module_speed(hw, NBL_MODULE_SPEED_1G);
		break;
	case NBL_MODULE_SPEED_10G:
	default:
		nbl_config_module_speed(hw, NBL_MODULE_SPEED_10G);
		break;
	}
}

void nbl_check_and_set_module_info(struct nbl_hw *hw)
{
	int ret;
	enum NBL_MODULE_INPLACE_STATUS inplace;
	bool support_10g = false;
	bool support_1g = false;
	u8 eth_port_id = hw->eth_port_id;

	inplace = nbl_check_module_inplace(hw, eth_port_id);

	hw->module_inplace = inplace;

	if (inplace == NBL_MODULE_NOT_INPLACE) {
		hw->module_support_speed = 0;
		return;
	}
	if (!nbl_check_module_identifier(hw, eth_port_id)) {
		pr_warn("Module identifier check failed, eth port: %d\n", eth_port_id);
		return;
	}

	ret = nbl_query_module_speed(hw, eth_port_id, &support_10g, &support_1g);
	if (ret) {
		pr_warn("Get module speed failed with ret: %d, eth port: %d\n",
			ret, eth_port_id);
		return;
	}

	if (support_10g)
		hw->module_support_speed |= NBL_MODULE_SPEED_10G;

	if (support_1g)
		hw->module_support_speed |= NBL_MODULE_SPEED_1G;

	nbl_set_module_speed(hw, hw->module_support_speed);
}

static void nbl_check_module_subtask(struct nbl_hw *hw)
{
	enum NBL_MODULE_INPLACE_STATUS inplace;

	inplace = nbl_check_module_inplace(hw, hw->eth_port_id);
	if (inplace == hw->module_inplace)
		return;
	else if (inplace == NBL_MODULE_INPLACE)
		pr_info("Eth port %d module plugged in\n", hw->eth_port_id);
	else
		pr_info("Eth port %d module pulled out\n", hw->eth_port_id);

	nbl_check_and_set_module_info(hw);
}

u32 nbl_af_get_rxlos(struct nbl_hw *hw, u8 eth_port_id)
{
	return rd32(hw, NBL_LSP_SFP_RXLOS_REG(eth_port_id));
}

static u32 nbl_get_rxlos(struct nbl_hw *hw)
{
	if (is_af(hw))
		return nbl_af_get_rxlos(hw, hw->eth_port_id);
	else
		return nbl_mailbox_req_get_rxlos(hw, hw->eth_port_id);
}

static bool nbl_eth_status_correct(struct nbl_hw *hw)
{
	u32 rxlos;

	if (nbl_query_link_status(hw))
		return true;

	rxlos = nbl_get_rxlos(hw);
	return (bool)(rxlos & BIT(0));
}

void nbl_af_reset_eth(struct nbl_hw *hw, u8 eth_port_id)
{
	wr32(hw, NBL_ETH_RESET_REG(eth_port_id), 0x1E);
	wr32(hw, NBL_ETH_RESET_REG(eth_port_id), 0x00);
}

static void nbl_reset_eth(struct nbl_hw *hw, u8 eth_port_id)
{
	if (is_af(hw))
		nbl_af_reset_eth(hw, eth_port_id);
	else
		nbl_mailbox_req_reset_eth(hw, eth_port_id);
}

static void nbl_eth_self_healing_subtask(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	u8 eth_port_id = hw->eth_port_id;
	struct nbl_healing_var *healing_var = &adapter->healing_var;

	if (is_vf(hw))
		return;

	if (healing_var->status_chk_timer >= 5) {
		healing_var->status_chk_timer = 0;
		if (!nbl_eth_status_correct(hw)) {
			healing_var->bad_code_increase = 0;
			nbl_reset_eth(hw, eth_port_id);
			adapter->stats.err_status_reset++;
			return;
		}
	}
	healing_var->status_chk_timer++;

	if (healing_var->bad_code_increase == 0) {
		healing_var->former_bad_code = adapter->stats.rx_bad_code;
		healing_var->bad_code_increase++;
		return;
	}

	if (healing_var->former_bad_code == adapter->stats.rx_bad_code) {
		healing_var->bad_code_increase = 0;
	} else {
		healing_var->former_bad_code = adapter->stats.rx_bad_code;
		healing_var->bad_code_increase++;
	}

	if (healing_var->bad_code_increase > 3) {
		healing_var->bad_code_increase = 0;
		nbl_reset_eth(hw, eth_port_id);
		adapter->stats.bad_code_reset++;
	}
}

static void nbl_service_task1(struct work_struct *work)
{
	struct nbl_adapter *adapter = container_of(work, struct nbl_adapter, serv_task1);

	nbl_clean_mailbox_subtask(adapter);
}

static void nbl_service_task2(struct work_struct *work)
{
	struct nbl_adapter *adapter = container_of(work, struct nbl_adapter, serv_task2);

	nbl_reset_subtask(adapter);
	nbl_query_link_status_subtask(adapter);
	nbl_update_stats_subtask(adapter);
	nbl_check_module_subtask(&adapter->hw);
	nbl_eth_self_healing_subtask(adapter);
}

static void nbl_adapter_init(struct nbl_adapter *adapter, unsigned int req_ring_num)
{
	adapter->num_txq = (u8)req_ring_num;
	adapter->num_rxq = (u8)req_ring_num;

	adapter->tx_desc_num = NBL_DEFAULT_TX_DESC_NUM;
	adapter->rx_desc_num = NBL_DEFAULT_RX_DESC_NUM;

	timer_setup(&adapter->serv_timer, nbl_service_timer, 0);
	adapter->serv_timer_period = HZ;
	INIT_WORK(&adapter->serv_task1, nbl_service_task1);
	INIT_WORK(&adapter->serv_task2, nbl_service_task2);
}

static void nbl_config_netdev(struct net_device *netdev)
{
	netdev_features_t csum_features;
#ifdef NBL_TSO
	netdev_features_t tso_features;
#endif

	netdev->features |= NETIF_F_SG;
	netdev->features |= NETIF_F_HW_VLAN_CTAG_FILTER;
	netdev->hw_features = netdev->features;
#ifdef NBL_TSO
	tso_features = NETIF_F_TSO | NETIF_F_TSO6 | NETIF_F_GSO_UDP_L4;
#endif
	csum_features = NETIF_F_IP_CSUM | NETIF_F_RXCSUM | NETIF_F_IPV6_CSUM;

	netdev->features |= csum_features;
	netdev->hw_features |= csum_features;
}

static void nbl_start_service_task(struct nbl_adapter *adapter)
{
	mod_timer(&adapter->serv_timer, round_jiffies(jiffies + adapter->serv_timer_period));
}

static void nbl_stop_service_task(struct nbl_adapter *adapter)
{
	del_timer_sync(&adapter->serv_timer);

	cancel_work_sync(&adapter->serv_task2);
	cancel_work_sync(&adapter->serv_task1);
}

static void nbl_up_complete(struct nbl_adapter *adapter)
{
	struct nbl_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;
	bool link_up;

	nbl_enable_all_napis(adapter);

	nbl_configure_msix_irqs(adapter);

	nbl_start_all_tx_rings(adapter);
	nbl_start_all_rx_rings(adapter);

	nbl_eth_tx_enable(adapter);
	nbl_eth_rx_enable(adapter);

	/* WARNING: Cannot call netif_carrier_on before
	 *          ndo_start_xmit netdev ops is implemented.
	 *          Otherwise, the whole system will crash without
	 *          any dmesg information.
	 */
	netif_tx_start_all_queues(netdev);
	link_up = nbl_query_link_status(hw);
	if (link_up)
		netif_carrier_on(netdev);

	clear_bit(NBL_DOWN, adapter->state);
}

int nbl_open(struct net_device *netdev)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	int err;

	netif_carrier_off(netdev);

	err = nbl_setup_rings(adapter);
	if (err)
		return err;

	nbl_hw_config_rings(adapter);

	nbl_alloc_all_rx_bufs(adapter);

	err = nbl_request_irq(adapter);
	if (err)
		goto request_irq_err;

	err = netif_set_real_num_tx_queues(netdev, adapter->num_txq);
	if (err)
		goto set_queue_num_err;
	err = netif_set_real_num_rx_queues(netdev, adapter->num_rxq);
	if (err)
		goto set_queue_num_err;

	nbl_up_complete(adapter);

	return 0;

set_queue_num_err:
	nbl_free_irq(adapter);
request_irq_err:
	nbl_free_all_rx_bufs(adapter);
	nbl_teardown_rings(adapter);

	return err;
}

static void nbl_down(struct nbl_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

	set_bit(NBL_DOWN, adapter->state);

	netif_carrier_off(netdev);
	netif_tx_disable(netdev);

	nbl_eth_rx_disable(adapter);

	nbl_stop_all_tx_rings(adapter);
	nbl_stop_all_rx_rings(adapter);

	nbl_clear_msix_irqs_conf(adapter);

	nbl_disable_all_napis(adapter);

	nbl_eth_tx_disable(adapter);
}

int nbl_stop(struct net_device *netdev)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);

	nbl_down(adapter);

	nbl_free_irq(adapter);

	nbl_free_all_tx_bufs(adapter);
	nbl_free_all_rx_bufs(adapter);

	nbl_teardown_rings(adapter);

	return 0;
}

void nbl_do_reset(struct nbl_adapter *adapter)
{
	while (test_and_set_bit(NBL_RESETTING, adapter->state))
		usleep_range(1000, 2000);

	nbl_down(adapter);
	nbl_free_all_tx_bufs(adapter);
	nbl_free_all_rx_bufs(adapter);

	nbl_alloc_all_rx_bufs(adapter);
	nbl_up_complete(adapter);

	clear_bit(NBL_RESETTING, adapter->state);
}

static int nbl_change_mtu(struct net_device *netdev, int new_mtu)
{
	netdev->mtu = new_mtu;
	return 0;
}

static void nbl_get_stats64(struct net_device *netdev, struct rtnl_link_stats64 *stats)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	struct nbl_ring *ring;
	u64 bytes;
	u64 packets;
	unsigned int start;
	int i;

	rcu_read_lock();
	for (i = 0; i < adapter->num_rxq; i++) {
		ring = READ_ONCE(adapter->rx_rings[i]);

		if (ring) {
			do {
				start = u64_stats_fetch_begin_irq(&ring->syncp);
				packets = ring->stats.packets;
				bytes = ring->stats.bytes;
			} while (u64_stats_fetch_retry_irq(&ring->syncp, start));
			stats->rx_packets += packets;
			stats->rx_bytes += bytes;
		}
	}

	for (i = 0; i < adapter->num_txq; i++) {
		ring = READ_ONCE(adapter->tx_rings[i]);

		if (ring) {
			do {
				start = u64_stats_fetch_begin_irq(&ring->syncp);
				packets = ring->stats.packets;
				bytes = ring->stats.bytes;
			} while (u64_stats_fetch_retry_irq(&ring->syncp, start));
			stats->tx_packets += packets;
			stats->tx_bytes += bytes;
		}
	}
	rcu_read_unlock();

	mutex_lock(&adapter->stats.lock);
	stats->multicast = adapter->stats.rx_multicast;
	stats->rx_errors = adapter->stats.rx_error_packets;
	stats->tx_errors = adapter->stats.tx_error_packets;
	stats->rx_length_errors = adapter->stats.rx_oversize + adapter->stats.rx_undersize;
	stats->rx_crc_errors = adapter->stats.rx_bad_fcs;
	stats->rx_frame_errors = adapter->stats.rx_frame_err;
	stats->rx_dropped = 0;
	stats->tx_dropped = 0;
	mutex_unlock(&adapter->stats.lock);
}

static void nbl_init_link_setting(struct nbl_hw *hw)
{
	__set_bit(ETHTOOL_LINK_MODE_10000baseT_Full_BIT, hw->supported);
	__set_bit(ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT, hw->supported);
	__set_bit(ETHTOOL_LINK_MODE_10000baseKR_Full_BIT, hw->supported);
	__set_bit(ETHTOOL_LINK_MODE_1000baseT_Full_BIT, hw->supported);
	__set_bit(ETHTOOL_LINK_MODE_1000baseKX_Full_BIT, hw->supported);
	__set_bit(ETHTOOL_LINK_MODE_10000baseT_Full_BIT, hw->advertising);
	__set_bit(ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT, hw->advertising);
	__set_bit(ETHTOOL_LINK_MODE_10000baseKR_Full_BIT, hw->advertising);
	__set_bit(ETHTOOL_LINK_MODE_FEC_NONE_BIT, hw->supported);
	__set_bit(ETHTOOL_LINK_MODE_FEC_NONE_BIT, hw->advertising);
	__set_bit(ETHTOOL_LINK_MODE_FIBRE_BIT, hw->supported);
	__set_bit(ETHTOOL_LINK_MODE_FIBRE_BIT, hw->advertising);
	__set_bit(ETHTOOL_LINK_MODE_Pause_BIT, hw->supported);
	__set_bit(ETHTOOL_LINK_MODE_Pause_BIT, hw->advertising);

	nbl_check_and_set_module_info(hw);
}

void nbl_af_set_pauseparam(struct nbl_hw *hw, u8 eth_port_id, struct nbl_fc_info fc)
{
	u32 rx_pause_reg_value;
	u32 tx_pause_reg_value;

	rx_pause_reg_value = rd32(hw, NBL_PA_PAUSE_RX_EN);
	rx_pause_reg_value &= ~(1 << (eth_port_id << 1));
	rx_pause_reg_value |= fc.rx_pause << (eth_port_id << 1);
	wr32(hw, NBL_PA_PAUSE_RX_EN, rx_pause_reg_value);

	tx_pause_reg_value = rd32(hw, NBL_QM_PORT_TX_PAUSE_EN);
	tx_pause_reg_value &= ~(1 << eth_port_id);
	tx_pause_reg_value |= fc.tx_pause << eth_port_id;
	wr32(hw, NBL_QM_PORT_TX_PAUSE_EN, tx_pause_reg_value);
}

static void nbl_init_pauseparam(struct nbl_hw *hw)
{
	if (is_vf(hw))
		return;

	hw->fc.rx_pause = 1;
	hw->fc.tx_pause = 1;
	if (is_af(hw))
		nbl_af_set_pauseparam(hw, hw->eth_port_id, hw->fc);
	else
		nbl_mailbox_req_set_pauseparam(hw, hw->eth_port_id, hw->fc);
}

static int nbl_set_mac_address(struct net_device *netdev, void *p)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	struct nbl_hw *hw = &adapter->hw;
	struct sockaddr *addr = p;
	u8 vsi_id;
	int err;

	vsi_id = hw->vsi_id;
	if (vsi_id >= NBL_MAX_PF_FUNC) {
		pr_err("It is not allowed to change mac address of VF\n");
		return -EOPNOTSUPP;
	}

	if (!is_valid_ether_addr(addr->sa_data)) {
		pr_err("We can not change to invalid mac address %pM\n", addr->sa_data);
		return -EADDRNOTAVAIL;
	}

	if (ether_addr_equal(netdev->dev_addr, addr->sa_data)) {
		pr_info("We are already using mac address %pM\n", addr->sa_data);
		return 0;
	}

	err = nbl_change_mac_addr(hw, addr->sa_data);
	if (err) {
		pr_err("Failed to change mac address to %pM with error %d\n", addr->sa_data, err);
		return err;
	}

	ether_addr_copy(netdev->dev_addr, addr->sa_data);

	nbl_write_mac_to_logic(hw, (u8 *)addr->sa_data);

	return 0;
}

static void nbl_tx_timeout(struct net_device *netdev, unsigned int txqueue)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);

	if (!test_bit(NBL_DOWN, adapter->state)) {
		set_bit(NBL_RESET_REQUESTED, adapter->state);

		nbl_service_task2_schedule(adapter);
	}
}

static int nbl_vlan_rx_add_vid(struct net_device *netdev,
			       __always_unused __be16 proto,
			       u16 vid)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	struct nbl_hw *hw = &adapter->hw;

	if (vid >= VLAN_N_VID)
		return -EINVAL;

	if (vid == NBL_DEFAULT_VLAN_ID)
		return 0;

	return nbl_add_vlan_id(hw, vid);
}

static int nbl_vlan_rx_kill_vid(struct net_device *netdev,
				__always_unused __be16 proto,
				u16 vid)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	struct nbl_hw *hw = &adapter->hw;

	if (vid >= VLAN_N_VID)
		return -EINVAL;

	if (vid == NBL_DEFAULT_VLAN_ID)
		return 0;

	return nbl_delete_vlan_id(hw, vid);
}

static void nbl_set_rx_mode(struct net_device *netdev)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	struct nbl_hw *hw = &adapter->hw;

	if (netdev->flags & IFF_PROMISC)
		nbl_enable_promisc(hw);
	else
		nbl_disable_promisc(hw);
}

static netdev_features_t nbl_features_check(struct sk_buff *skb,
					    struct net_device *dev,
					    netdev_features_t features)
{
	u32 l4_len, tot_len;
	union {
		struct iphdr *v4;
		struct ipv6hdr *v6;
		unsigned char *hdr;
	} ip;
	union {
		struct tcphdr *tcp;
		struct udphdr *udp;
		unsigned char *hdr;
	} l4;
	unsigned char *exthdr;
	__be16 protocol, frag_off;
	u8 l4_proto;
	int ret;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return features;

	if (skb_is_gso(skb) && (skb_shinfo(skb)->gso_size < NBL_TX_MIN_GSO_SIZE))
		features &= ~NETIF_F_GSO_MASK;

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);

	protocol = vlan_get_protocol(skb);

	if (skb->encapsulation) {
		if (protocol == htons(ETH_P_IP)) {
			l4_proto = ip.v4->protocol;
			/* Only support IPV4 with no opt */
			if (ip.v4->ihl > 5)
				goto out_rm_features;
		} else if (protocol == htons(ETH_P_IPV6)) {
			/* Now skip ipv6 with opt */
			if (ip.v6->nexthdr != NEXTHDR_NONE)
				goto out_rm_features;
			exthdr = ip.hdr + sizeof(*ip.v6);
			l4_proto = ip.v6->nexthdr;
			ret = ipv6_skip_exthdr(skb, exthdr - skb->data,
					       &l4_proto, &frag_off);
			if (ret < 0)
				goto out_rm_features;
		} else {
			goto out_rm_features;
		}

		switch (l4_proto) {
		case IPPROTO_UDP:
		case IPPROTO_GRE:
			break;
		default:
			goto out_rm_features;
		}

		ip.hdr = skb_inner_network_header(skb);
		l4.hdr = skb_inner_transport_header(skb);

		if (ip.v4->version == 4)
			protocol = htons(ETH_P_IP);
		if (ip.v6->version == 6)
			protocol = htons(ETH_P_IPV6);
	}

	if (protocol == htons(ETH_P_IP)) {
		l4_proto = ip.v4->protocol;
	} else if (protocol == htons(ETH_P_IPV6)) {
		/* Skip inner pkt ipv6 with opt */
		if (ip.v6->nexthdr != NEXTHDR_NONE)
			goto out_rm_features;
		exthdr = ip.hdr + sizeof(*ip.v6);
		l4_proto = ip.v6->nexthdr;
		if (l4.hdr != exthdr)
			ipv6_skip_exthdr(skb, exthdr - skb->data,
					 &l4_proto, &frag_off);
	} else {
		goto out_rm_features;
	}

	switch (l4_proto) {
	case IPPROTO_TCP:
		l4_len = (l4.tcp->doff) << 2;
		break;
	case IPPROTO_UDP:
		l4_len = sizeof(struct udphdr);
		break;
	default:
		goto out_rm_features;
	}

	tot_len = l4.hdr - skb->data;
	tot_len += l4_len;

	if (tot_len > NBL_TX_MAX_OFFLOAD_HEADER_LEN)
		goto out_rm_features;

	return features;

out_rm_features:
	return features & ~(NETIF_F_CSUM_MASK | NETIF_F_GSO_MASK);
}

static const struct net_device_ops nbl_netdev_ops = {
	.ndo_open = nbl_open,
	.ndo_stop = nbl_stop,
	.ndo_start_xmit = nbl_start_xmit,
	.ndo_get_stats64 = nbl_get_stats64,
	.ndo_change_mtu = nbl_change_mtu,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_set_mac_address = nbl_set_mac_address,
	.ndo_tx_timeout = nbl_tx_timeout,
	.ndo_vlan_rx_add_vid = nbl_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid = nbl_vlan_rx_kill_vid,
	.ndo_set_rx_mode = nbl_set_rx_mode,
	.ndo_features_check = nbl_features_check,
};

static const struct pci_device_id nbl_id_table[] = {
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_X4_PF) },
	{ PCI_DEVICE(NBL_VENDOR_ID, NBL_DEVICE_ID_X4_VF) },
	/* required as sentinel */
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, nbl_id_table);

static int nbl_probe(struct pci_dev *pdev, const struct pci_device_id __always_unused *id)
{
	struct device *dev = &pdev->dev;
	struct net_device *netdev;
	struct nbl_adapter *adapter;
	struct nbl_hw *hw;
	u8 mac_addr[ETH_ALEN];
	int bar_mask;
	int pci_using_dac;
	u8 function_id;
	enum nbl_func_type func_type;
	unsigned int req_ring_num;
	int err;
	bool golden;

	err = pci_enable_device(pdev);
	if (err)
		return err;

	bar_mask = BIT(NBL_X4_MEMORY_BAR) | BIT(NBL_X4_MAILBOX_BAR);
	err = pci_request_selected_regions(pdev, bar_mask, NBL_X4_DRIVER_NAME);
	if (err) {
		dev_err(dev, "Request memory bar and mailbox bar failed, err = %d\n", err);
		goto request_bar_region_err;
	}

	pci_using_dac = 1;
	err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (err) {
		dev_err(dev, "Configure DMA 64 bit mask failed, err = %d\n", err);
		pci_using_dac = 0;
		err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32));
	}
	if (err) {
		dev_err(dev, "Configure DMA 32 bit mask failed, err = %d\n", err);
		goto configure_dma_err;
	}

	pci_set_master(pdev);

	pci_enable_pcie_error_reporting(pdev);
	pci_save_state(pdev);

	function_id = PCI_FUNC(pdev->devfn);
	if (pdev->device == NBL_DEVICE_ID_X4_PF && !function_id)
		func_type = NBL_X4_AF;
	else if (pdev->device == NBL_DEVICE_ID_X4_PF)
		func_type = NBL_X4_PF;
	else
		func_type = NBL_X4_VF;

	if (func_type == NBL_X4_VF)
		req_ring_num = vf_ring_num;
	else
		req_ring_num = ring_num;

	if (req_ring_num > NBL_MAX_RING_NUM)
		req_ring_num = NBL_MAX_RING_NUM;
	/* We can allocate 16 tx/rx queues for each function
	 * at most, but for AF we must reserve a tx/rx queue
	 * pair which is a software forward queue used in
	 * SRIOV case.
	 */
	if (func_type == NBL_X4_AF && req_ring_num > NBL_MAX_RING_NUM - 1)
		req_ring_num = NBL_MAX_RING_NUM - 1;
	if (req_ring_num > num_online_cpus())
		req_ring_num = num_online_cpus();
	if (!req_ring_num) {
		if (func_type == NBL_X4_VF)
			req_ring_num = NBL_VF_DEFAULT_RING_NUM;
		else
			req_ring_num = NBL_DEFAULT_RING_NUM;
	}

	netdev = alloc_etherdev_mqs(sizeof(struct nbl_adapter), req_ring_num, req_ring_num);
	if (!netdev) {
		pr_err("Allocate net device failed\n");
		err = -ENOMEM;
		goto alloc_netdev_err;
	}

	nbl_config_netdev(netdev);

	SET_NETDEV_DEV(netdev, &pdev->dev);
	pci_set_drvdata(pdev, netdev);

	adapter = netdev_priv(netdev);
	adapter->pdev = pdev;
	adapter->netdev = netdev;
	adapter->msg_enable = netif_msg_init(debug, DEFAULT_MSG_ENABLE);
	mutex_init(&adapter->stats.lock);
	hw = &adapter->hw;
	hw->back = adapter;
	hw->function = function_id;
	hw->devid = PCI_SLOT(pdev->devfn);
	hw->bus = pdev->bus->number;
	hw->func_type = func_type;

	set_bit(NBL_DOWN, adapter->state);

	hw->hw_addr = pci_ioremap_bar(pdev, NBL_X4_MEMORY_BAR);
	if (!hw->hw_addr) {
		dev_err(dev, "Memory bar ioremap failed\n");
		err = -EIO;
		goto ioremap_err;
	}

	hw->mailbox_bar_hw_addr = pci_ioremap_bar(pdev, NBL_X4_MAILBOX_BAR);
	if (!hw->mailbox_bar_hw_addr) {
		dev_err(dev, "Mailbox bar ioremap failed\n");
		err = -EIO;
		goto mailbox_ioremap_err;
	}

	hw->msix_bar_hw_addr = pci_ioremap_bar(pdev, NBL_X4_MSIX_BAR);
	if (!hw->msix_bar_hw_addr) {
		dev_err(dev, "MSIX bar ioremap failed\n");
		err = -EIO;
		goto msix_ioremap_err;
	}

	nbl_adapter_init(adapter, req_ring_num);

	if (is_af(hw)) {
		nbl_firmware_init(hw);

		nbl_af_configure_fc_cplh_up_th(hw);

		nbl_af_configure_captured_packets(hw);

		nbl_af_set_mailbox_bdf_for_all_func(hw);

		err = nbl_af_res_mng_init(hw);
		if (err)
			goto res_mng_init_err;
	}

	golden = nbl_check_golden_version(hw);
	if (golden) {
		dev_info(dev, "The firmware is golden version, please use regular version\n");
		err = -EINVAL;
		goto golden_version_err;
	}

	err = nbl_setup_mailbox(hw);
	if (err)
		goto golden_version_err;

	/* NOTICE: AF must be probed successfully first */
	err = nbl_configure_msix_map(hw);
	if (err)
		goto config_msix_map_err;

	err = nbl_init_interrupt_scheme(adapter);
	if (err)
		goto init_intr_err;

	nbl_start_service_task(adapter);

	err = nbl_mailbox_request_irq(adapter);
	if (err)
		goto mailbox_req_irq_err;

	nbl_mailbox_enable_irq(adapter);

	set_bit(NBL_MAILBOX_READY, adapter->state);

	err = nbl_get_vsi_id(hw);
	if (err)
		goto get_vsi_id_err;

	if (hw->vsi_id < NBL_MAX_PF_FUNC)
		hw->eth_port_id = hw->vsi_id;
	else
		hw->eth_port_id = (hw->vsi_id - NBL_MAX_PF_FUNC) / NBL_MAX_VF_PER_PF;

	err = nbl_register_vf_bar_info(hw);
	if (err)
		goto get_vsi_id_err;

	err = nbl_configure_notify_addr(hw);
	if (err)
		goto get_vsi_id_err;

	err = nbl_alloc_q_vectors(adapter);
	if (err)
		goto alloc_q_vectors_err;

	err = nbl_alloc_rings(adapter);
	if (err)
		goto alloc_rings_err;

	nbl_map_rings_to_vectors(adapter);

	nbl_datapath_init(hw);

	netdev->netdev_ops = &nbl_netdev_ops;
	nbl_set_ethtool_ops(netdev);

	netdev->watchdog_timeo = 5 * HZ;

	if (pci_using_dac)
		netdev->features |= NETIF_F_HIGHDMA;

	netdev->max_mtu = NBL_MAX_MTU;
	netdev->min_mtu = ETH_MIN_MTU;

	nbl_init_pkt_len_limit(hw);

	nbl_mac_addr_init(adapter, mac_addr);
	if (!is_valid_ether_addr(mac_addr)) {
		pr_err("MAC address %02X:%02X:%02X:%02X:%02X:%02X is invalid\n",
		       mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4],
		       mac_addr[5]);
	}
	ether_addr_copy(netdev->dev_addr, mac_addr);
	err = nbl_configure_mac_addr(hw, mac_addr);
	if (err)
		pr_err("Configure mac address into hardware device failed with error %d\n", err);

	err = register_netdev(netdev);
	if (err) {
		pr_err("Register net device failed\n");
		goto register_netdev_err;
	}
	netif_carrier_off(netdev);

	err = nbl_activate_af_forward_queue(adapter);
	if (err) {
		pr_err("Start AF forward queue failed with error %d\n", err);
		goto activate_forward_queue_err;
	}

	err = nbl_hwmon_init(adapter);
	if (err) {
		pr_err("Unable to register hwmon device with error %d\n", err);
		goto register_hwmon_err;
	}

	nbl_debugfs_hw_init(hw);

	nbl_init_pauseparam(hw);

	nbl_init_link_setting(hw);

	nbl_init_hw_stats(hw);

	return 0;

register_hwmon_err:
	nbl_deactivate_af_forward_queue(adapter);
activate_forward_queue_err:
	unregister_netdev(netdev);
	err = nbl_clear_mac_addr(hw);
	if (err)
		pr_err("Failed to clear mac address when error occurs\n");
register_netdev_err:
	nbl_free_rings(adapter);
alloc_rings_err:
	nbl_free_q_vectors(adapter);
alloc_q_vectors_err:
	nbl_clear_notify_addr(hw);
get_vsi_id_err:
	clear_bit(NBL_MAILBOX_READY, adapter->state);
	cancel_work_sync(&adapter->serv_task2);

	nbl_mailbox_disable_irq(adapter);
	nbl_mailbox_free_irq(adapter);
mailbox_req_irq_err:
	nbl_stop_service_task(adapter);
	nbl_fini_interrupt_scheme(adapter);
init_intr_err:
	nbl_destroy_msix_map(hw);
config_msix_map_err:
	nbl_teardown_mailbox(hw);
golden_version_err:
	if (is_af(hw))
		nbl_af_free_res(hw);
res_mng_init_err:
	iounmap(hw->msix_bar_hw_addr);
msix_ioremap_err:
	iounmap(hw->mailbox_bar_hw_addr);
mailbox_ioremap_err:
	iounmap(hw->hw_addr);
ioremap_err:
	free_netdev(netdev);
alloc_netdev_err:
	pci_disable_pcie_error_reporting(pdev);
	pci_clear_master(pdev);
configure_dma_err:
	pci_release_selected_regions(pdev, bar_mask);
request_bar_region_err:
	pci_disable_device(pdev);
	return err;
}

static void nbl_wait_other_functions_removed(struct nbl_hw *hw)
{
	struct nbl_af_res_info *af_res;
	struct nbl_func_res *func_res;
	bool all_removed;
	int i;

	af_res = hw->af_res;
	all_removed = true;
	/* Do not consider AF itself */
	for (i = 1; i < NBL_MAX_FUNC; i++) {
		func_res = af_res->res_record[i];
		if (func_res->txrx_queues) {
			all_removed = false;
			pr_warn("Please remove all other PF/VFs before remove AF\n");
			break;
		}
	}

	while (!all_removed) {
		cpu_relax();
		ssleep(1);

		all_removed = true;
		for (i = 1; i < NBL_MAX_FUNC; i++) {
			func_res = af_res->res_record[i];
			if (func_res->txrx_queues) {
				all_removed = false;
				break;
			}
		}
	}
}

static void nbl_remove(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct nbl_adapter *adapter = netdev_priv(netdev);
	struct nbl_hw *hw = &adapter->hw;
	int bar_mask;
	int err;

	if (is_af(hw))
		nbl_wait_other_functions_removed(hw);

	/* NOTICE: cancel work to prevent update statistics
	 *         work from referencing tx/rx ring pointer
	 *         after it is freed by nbl_remove already.
	 */
	cancel_work_sync(&adapter->serv_task2);

	bar_mask = BIT(NBL_X4_MEMORY_BAR) | BIT(NBL_X4_MAILBOX_BAR);

	nbl_debugfs_hw_exit(hw);

	nbl_hwmon_fini(adapter);

	nbl_deactivate_af_forward_queue(adapter);

	unregister_netdev(netdev);

	err = nbl_clear_mac_addr(hw);
	if (err)
		pr_err("Failed to clear mac address when remove module\n");

	nbl_free_rings(adapter);

	nbl_free_q_vectors(adapter);

	nbl_clear_notify_addr(hw);

	clear_bit(NBL_MAILBOX_READY, adapter->state);
	cancel_work_sync(&adapter->serv_task2);

	/* NOTICE: AF must be removed last */
	nbl_mailbox_disable_irq(adapter);
	nbl_mailbox_free_irq(adapter);

	nbl_stop_service_task(adapter);

	nbl_fini_interrupt_scheme(adapter);

	nbl_destroy_msix_map(hw);

	nbl_teardown_mailbox(hw);

	if (is_af(hw)) {
		nbl_af_clear_captured_packets_conf(hw);
		nbl_af_free_res(hw);
	}

	iounmap(hw->msix_bar_hw_addr);
	iounmap(hw->mailbox_bar_hw_addr);
	iounmap(hw->hw_addr);

	free_netdev(netdev);

	pci_disable_pcie_error_reporting(pdev);
	pci_clear_master(pdev);
	pci_release_selected_regions(pdev, bar_mask);
	pci_disable_device(pdev);
}

static struct pci_driver nbl_driver = {
	.name = NBL_X4_DRIVER_NAME,
	.id_table = nbl_id_table,
	.probe = nbl_probe,
	.remove = nbl_remove,
	.sriov_configure = nbl_sriov_configure,
};

static int __init nbl_module_init(void)
{
	int status;

	nbl_debugfs_init();

	status = -ENOMEM;
	nbl_wq1 = create_singlethread_workqueue(NBL_X4_WQ1);
	if (!nbl_wq1) {
		pr_err("Failed to create workqueue for %s\n", NBL_X4_WQ1);
		return status;
	}

	nbl_wq2 = create_singlethread_workqueue(NBL_X4_WQ2);
	if (!nbl_wq2) {
		pr_err("Failed to create workqueue for %s\n", NBL_X4_WQ2);
		goto create_wq2_err;
	}

	status = pci_register_driver(&nbl_driver);
	if (status) {
		pr_err("Failed to register PCI driver, err = %d\n", status);
		goto register_driver_err;
	}

	return 0;

register_driver_err:
	destroy_workqueue(nbl_wq2);
create_wq2_err:
	destroy_workqueue(nbl_wq1);

	return status;
}

static void __exit nbl_module_exit(void)
{
	pci_unregister_driver(&nbl_driver);
	destroy_workqueue(nbl_wq2);
	destroy_workqueue(nbl_wq1);
	nbl_debugfs_exit();
	pr_info("nbl module unloaded\n");
}

module_init(nbl_module_init);
module_exit(nbl_module_exit);
MODULE_LICENSE("GPL v2");
MODULE_VERSION(NBL_X4_DRIVER_VERSION);
