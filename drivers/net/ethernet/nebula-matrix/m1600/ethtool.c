// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author: Monte Song <monte.song@nebula-matrix.com>
 */

#include <linux/netdevice.h>
#include <linux/ethtool.h>

#include "hw.h"
#include "common.h"
#include "txrx.h"
#include "mailbox.h"
#include "ethtool.h"

static void nbl_get_drvinfo(struct net_device *netdev, struct ethtool_drvinfo *drvinfo)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	struct nbl_hw *hw = &adapter->hw;
	u32 firmware_version;

	if (is_af(hw))
		firmware_version = nbl_af_get_firmware_version(hw);
	else
		firmware_version = nbl_mailbox_req_get_firmware_version(hw);

	strscpy(drvinfo->driver, NBL_X4_DRIVER_NAME, sizeof(drvinfo->driver));
	strscpy(drvinfo->version, NBL_X4_DRIVER_VERSION, sizeof(drvinfo->version));
	snprintf(drvinfo->fw_version, sizeof(drvinfo->fw_version), "%x", firmware_version);
	strscpy(drvinfo->bus_info, pci_name(adapter->pdev), sizeof(drvinfo->bus_info));

	drvinfo->regdump_len = 0;
}

static u32 nbl_get_link(struct net_device *netdev)
{
	return netif_carrier_ok(netdev) ? 1 : 0;
}

static int nbl_get_regs_len(struct net_device *netdev)
{
	return ARRAY_SIZE(nbl_regs_dump_list) * sizeof(u32);
}

void nbl_af_get_ethtool_dump_regs(struct nbl_hw *hw, u32 *regs_buff, u32 count)
{
	int i;

	for (i = 0; i < count; ++i)
		regs_buff[i] = rd32(hw, nbl_regs_dump_list[i]);
}

static void nbl_get_ethtool_dump_regs(struct net_device *netdev, struct ethtool_regs *regs, void *p)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	struct nbl_hw *hw = &adapter->hw;
	u32 *regs_buff = (u32 *)p;
	u32 count = ARRAY_SIZE(nbl_regs_dump_list);
	int err;

	regs->version = (u32)hw->devid;

	if (is_af(hw)) {
		nbl_af_get_ethtool_dump_regs(hw, regs_buff, count);
	} else {
		err = nbl_mailbox_req_get_ethtool_dump_regs(hw, regs_buff, count);
		if (err)
			pr_err("Ethtool mailbox req get regs error!\n");
	}
}

static void nbl_get_ringparam(struct net_device *netdev, struct ethtool_ringparam *ringparam,
			      struct kernel_ethtool_ringparam __always_unused *k_ringparam,
			      struct netlink_ext_ack __always_unused *extack)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);

	ringparam->tx_max_pending = NBL_MAX_TX_DESC_NUM;
	ringparam->rx_max_pending = NBL_MAX_RX_DESC_NUM;
	ringparam->rx_pending = adapter->rx_rings[0]->desc_num;
	ringparam->tx_pending = adapter->tx_rings[0]->desc_num;
}

static int nbl_check_set_ringparam(struct net_device *netdev, struct ethtool_ringparam *ringparam)
{
	/* check if tx_pending is out of range or power of 2 */
	if (ringparam->tx_pending > NBL_MAX_TX_DESC_NUM ||
	    ringparam->tx_pending < NBL_MIN_TX_DESC_NUM) {
		pr_err("Tx descriptors requested: %d, out of range[%d-%d]\n",
		       ringparam->tx_pending, NBL_MIN_TX_DESC_NUM, NBL_MAX_TX_DESC_NUM);
		return -EINVAL;
	}
	if (ringparam->tx_pending & (ringparam->tx_pending - 1)) {
		pr_err("Tx descriptors requested: %d is not power of 2\n",
		       ringparam->tx_pending);
		return -EINVAL;
	}

	/* check if rx_pending is out of range or power of 2 */
	if (ringparam->rx_pending > NBL_MAX_RX_DESC_NUM ||
	    ringparam->rx_pending < NBL_MIN_RX_DESC_NUM) {
		pr_err("Rx descriptors requested: %d, out of range[%d-%d]\n",
		       ringparam->rx_pending, NBL_MIN_RX_DESC_NUM, NBL_MAX_RX_DESC_NUM);
		return -EINVAL;
	}
	if (ringparam->rx_pending & (ringparam->rx_pending - 1)) {
		pr_err("Rx descriptors requested: %d is not power of 2\n",
		       ringparam->rx_pending);
		return -EINVAL;
	}

	if (ringparam->rx_jumbo_pending || ringparam->rx_mini_pending) {
		pr_err("rx_jumbo_pending or rx_mini_pending is not supported\n");
		return -EINVAL;
	}

	return 0;
}

static int nbl_pre_set_ringparam(struct net_device *netdev, struct ethtool_ringparam *ringparam)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	int timeout = 50;

	if (ringparam->rx_pending == adapter->rx_desc_num &&
	    ringparam->tx_pending == adapter->tx_desc_num) {
		pr_debug("Nothing to change, descriptor count is same as requested\n");
		return 0;
	}

	while (test_and_set_bit(NBL_RESETTING, adapter->state)) {
		timeout--;
		if (!timeout) {
			pr_err("Timeout while resetting in set ringparam\n");
			return -EBUSY;
		}
		usleep_range(1000, 2000);
	}

	/* configure params later */
	return 1;
}

static int nbl_set_ringparam(struct net_device *netdev, struct ethtool_ringparam *ringparam,
			     struct kernel_ethtool_ringparam __always_unused *k_ringparam,
			     struct netlink_ext_ack __always_unused *extack)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	u16 new_tx_count;
	u16 new_rx_count;
	int was_running;
	int i;
	int err;

	err = nbl_check_set_ringparam(netdev, ringparam);
	if (err < 0)
		return err;

	err = nbl_pre_set_ringparam(netdev, ringparam);
	/* if either error occur or nothing to change, return */
	if (err <= 0)
		return err;

	new_tx_count = ringparam->tx_pending;
	new_rx_count = ringparam->rx_pending;

	was_running = netif_running(netdev);

	if (was_running) {
		err = nbl_stop(netdev);
		if (err) {
			pr_err("Netdev stop failed while setting ringparam\n");
			clear_bit(NBL_RESETTING, adapter->state);
			return err;
		}
	}

	if (adapter->tx_desc_num != new_tx_count) {
		adapter->tx_desc_num = new_tx_count;
		for (i = 0; i < adapter->num_txq; i++)
			adapter->tx_rings[i]->desc_num = new_tx_count;
	}

	if (adapter->rx_desc_num != new_rx_count) {
		adapter->rx_desc_num = new_rx_count;
		for (i = 0; i < adapter->num_rxq; i++)
			adapter->rx_rings[i]->desc_num = new_rx_count;
	}

	if (was_running) {
		err = nbl_open(netdev);
		if (err) {
			pr_err("Netdev open failed after setting ringparam\n");
			clear_bit(NBL_RESETTING, adapter->state);
			return err;
		}
	}

	clear_bit(NBL_RESETTING, adapter->state);

	return 0;
}

static int nbl_read_reg_i2c(struct nbl_hw *hw, u32 offset, u8 *data, u8 data_len,
			    u16 sff_8472_addr, const struct nbl_iic_phy_regs *regs)
{
	u32 status;
	u32 timeout = 50;
	struct nbl_sfp_iic_data sfp_iic_reg;
	u32 *reg_value;
	u32 i;
	u32 sfp_iic_data;

	if (sff_8472_addr != SFF_8472_A0 && sff_8472_addr != SFF_8472_A2) {
		pr_err("I2C read SFP module with wrong slave address\n");
		return -EIO;
	}

	if (offset >= ETH_MODULE_SFF_8472_LEN) {
		pr_err("I2C read SFP module with offset %u which is larger than module length %u",
		       offset, ETH_MODULE_SFF_8472_LEN);
		return -EIO;
	}

	if (data_len > NBL_SFP_READ_MAXLEN_ONE_TIME) {
		pr_err("I2C read SFP module with data len %u which is larger than max read len %u\n",
		       data_len, NBL_SFP_READ_MAXLEN_ONE_TIME);
		return -EIO;
	}

	sfp_iic_reg.slave_addr = sff_8472_addr;
	sfp_iic_reg.rw_mode = SFF_I2C_READ;
	sfp_iic_reg.target_addr = offset;
	sfp_iic_reg.access_bytes = data_len;
	sfp_iic_reg.iic_chn = 0; /* kernel driver uses chn0 to rw sfp eeprom */

	reg_value = (u32 *)&sfp_iic_reg;

	wr32(hw, regs->request, *reg_value);

	/* check job done: loop and query the done register bit */
	do {
		timeout--;
		if (timeout == 0) {
			pr_err("Failed to read SFP module registers with I2C with slave address %u offset value %u and data len %u\n",
			       sff_8472_addr, offset, data_len);
			return -EIO;
		}
		usleep_range(50, 100);
		status = rd32(hw, regs->done) & NBL_SFP_RW_DONE_CHN0_MASK;
	} while (!status);

	sfp_iic_data = rd32(hw, regs->rdata);

	for (i = 0; i < data_len; i++)
		/* adjust endianness */
		data[data_len - i - 1] = (sfp_iic_data >> (i * 8)) & 0xff;

	return 0;
}

static int __maybe_unused nbl_write_reg_i2c(struct nbl_hw *hw, u32 offset, u8 data,
					    u16 sff_8472_addr,
					    const struct nbl_iic_phy_regs *regs)
{
	int status = 0;
	u32 timeout = 100;
	struct nbl_sfp_iic_data sfp_iic_reg;
	u32 *reg_value;

	if (sff_8472_addr != SFF_8472_A0 && sff_8472_addr != SFF_8472_A2) {
		pr_err("I2C write SFP module with wrong slave address\n");
		return -EIO;
	}

	if (offset >= ETH_MODULE_SFF_8472_LEN) {
		pr_err("I2C write SFP module with offset %u which is larger than module length %u",
		       offset, ETH_MODULE_SFF_8472_LEN);
		return -EIO;
	}

	sfp_iic_reg.slave_addr = sff_8472_addr;
	sfp_iic_reg.rw_mode = SFF_I2C_WRITE;
	sfp_iic_reg.target_addr = offset;
	sfp_iic_reg.access_bytes = 1; /* write 1 byte at 1 time */
	sfp_iic_reg.iic_chn = 0; /* kernel driver used chn0 to rw sfp eeprom */
	sfp_iic_reg.wdata = data;

	reg_value = (u32 *)&sfp_iic_reg;
	wr32(hw, regs->request, *reg_value);

	/* check job done: loop and query the done register bit */
	do {
		timeout--;
		if (timeout == 0) {
			pr_err("Failed to write SFP module registers with I2C with slave address %u offset value %u\n",
			       sff_8472_addr, offset);
			return -EIO;
		}
		usleep_range(100, 200);
		status = rd32(hw, regs->done) & NBL_SFP_RW_DONE_CHN0_MASK;
	} while (!status);

	return 0;
}

int nbl_af_get_module_info(struct nbl_hw *hw, u8 eth_port_id, struct ethtool_modinfo *info)
{
	struct nbl_iic_phy_regs iic_phy_regs;
	int status;
	u8 sff8472_rev;
	u8 addr_mode;
	bool page_swap = false;

	/* low signal means module inplace */
	if (rd32(hw, NBL_LSP_SFP_MOD_REG(eth_port_id)) & BIT(0)) {
		pr_debug("Optical module of ETH port %u is not inplace\n", eth_port_id);
		return -EIO;
	}

	iic_phy_regs.request = NBL_LSP_SFP_I2C_REQUEST_REG(eth_port_id);
	iic_phy_regs.rdata = NBL_LSP_SFP_I2C_RDATA_CHN_REG(eth_port_id, 0);
	iic_phy_regs.done = NBL_LSP_SFP_I2C_DONE_REG(eth_port_id);

	/* SFF-8472 specification revision edition */
	status = nbl_read_reg_i2c(hw, SFF_8472_COMPLIANCE, &sff8472_rev, 1,
				  SFF_8472_A0, &iic_phy_regs);
	if (status) {
		pr_debug("Port %d failed to get SFP module revision information\n", eth_port_id);
		return -EIO;
	}

	/* check if addressing mode is supported */
	status = nbl_read_reg_i2c(hw, SFF_8472_DIAGNOSTIC, &addr_mode, 1,
				  SFF_8472_A0, &iic_phy_regs);
	if (status) {
		pr_debug("Port %d failed to get SFP module addressing mode information\n",
			 eth_port_id);
		return -EIO;
	}

	/* check if can access page 0xA2 directly, see sff-8472 */
	if (addr_mode & SFF_8472_ADDRESSING_MODE) {
		pr_err("Port %d address change required to access page 0xA2 which is not supported\n",
		       eth_port_id);
		page_swap = true;
	}

	if ((sff8472_rev & 0xFF) == SFF_8472_UNSUPPORTED || page_swap ||
	    !(addr_mode & SFF_DDM_IMPLEMENTED)) {
		/* We have an SFP, but it does not support SFF-8472 */
		info->type = ETH_MODULE_SFF_8079;
		info->eeprom_len = ETH_MODULE_SFF_8079_LEN;
	} else {
		/* We have an SFP which supports a revision of SFF-8472 */
		info->type = ETH_MODULE_SFF_8472;
		info->eeprom_len = ETH_MODULE_SFF_8472_LEN;
	}

	return 0;
}

static int nbl_get_module_info(struct net_device *netdev, struct ethtool_modinfo *info)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	struct nbl_hw *hw = &adapter->hw;
	u8 eth_port_id = hw->eth_port_id;
	int err;

	if (is_af(hw))
		err = nbl_af_get_module_info(hw, eth_port_id, info);
	else
		err = nbl_mailbox_req_get_module_info(hw, eth_port_id, info);

	return err;
}

int nbl_af_get_module_eeprom(struct nbl_hw *hw, u8 eth_port_id,
			     struct ethtool_eeprom *eeprom, u8 *data)
{
	struct nbl_iic_phy_regs iic_phy_regs;
	int status;
	u8 databyte[4];
	int i;
	u8 len;

	if (eeprom->len == 0)
		return -EINVAL;

	/* low signal means module inplace */
	if (rd32(hw, NBL_LSP_SFP_MOD_REG(eth_port_id)) & BIT(0)) {
		pr_debug("Optical module of ETH port %u is not inplace\n", eth_port_id);
		return -EIO;
	}

	iic_phy_regs.request = NBL_LSP_SFP_I2C_REQUEST_REG(eth_port_id);
	iic_phy_regs.rdata = NBL_LSP_SFP_I2C_RDATA_CHN_REG(eth_port_id, 0);
	iic_phy_regs.done = NBL_LSP_SFP_I2C_DONE_REG(eth_port_id);

	for (i = eeprom->offset; i < eeprom->offset + eeprom->len;
	     i += NBL_SFP_READ_MAXLEN_ONE_TIME) {
		if (eeprom->offset + eeprom->len - i >= NBL_SFP_READ_MAXLEN_ONE_TIME)
			len = NBL_SFP_READ_MAXLEN_ONE_TIME;
		else
			len = eeprom->offset + eeprom->len - i;

		if (i < ETH_MODULE_SFF_8079_LEN)
			status = nbl_read_reg_i2c(hw, i, databyte, len,
						  SFF_8472_A0, &iic_phy_regs);
		else
			status = nbl_read_reg_i2c(hw, i, databyte, len,
						  SFF_8472_A2, &iic_phy_regs);

		if (status) {
			pr_debug("Port %d get SPF module eeprom failed for read module register %d failed\n",
				 eth_port_id, i);
			return -EIO;
		}

		memcpy(data + i - eeprom->offset, databyte, len);
	}

	return 0;
}

static int nbl_get_module_eeprom(struct net_device *netdev,
				 struct ethtool_eeprom *eeprom, u8 *data)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	struct nbl_hw *hw = &adapter->hw;
	u8 eth_port_id = hw->eth_port_id;
	int err;

	if (is_af(hw))
		err = nbl_af_get_module_eeprom(hw, eth_port_id, eeprom, data);
	else
		err = nbl_mailbox_req_get_module_eeprom(hw, eth_port_id, eeprom, data);

	return err;
}

int nbl_read_eeprom_byte(struct nbl_hw *hw, u32 addr, u8 *data)
{
	struct nbl_eeprom_status status;
	u32 value;
	u32 i = 0;

	/* There is no need to write slave addr reg, the default value is ok. */
	wr32(hw, NBL_LSP_EEPROM_ADDR_REG, addr);

	wr32(hw, NBL_LSP_EEPROM_RW_REG, NBL_EEPROM_READ);

	/* Use rising edge to trigger read operation. */
	wr32(hw, NBL_LSP_EEPROM_REQ_REG, 0);
	wr32(hw, NBL_LSP_EEPROM_REQ_REG, 1);
	do {
		*(u32 *)&status = rd32(hw, NBL_LSP_EEPROM_STATUS_REG);
		if (status.done)
			break;
		i++;
		if (!(i % 1000)) {
			pr_err("Wait too long for EEPROM read done\n");
			return -EIO;
		}
		usleep_range(50, 100);
	} while (true);

	value = rd32(hw, NBL_LSP_EEPROM_RDATA_REG);
	*data = (u8)value;

	return 0;
}

static int __maybe_unused nbl_write_eeprom_byte(struct nbl_hw *hw, u32 addr, u8 data)
{
	struct nbl_eeprom_status status;
	u32 i = 0;
	u32 write_data = data & 0xff;

	/* There is no need to write slave addr reg, the default value is ok. */
	wr32(hw, NBL_LSP_EEPROM_ADDR_REG, addr);

	wr32(hw, NBL_LSP_EEPROM_RW_REG, NBL_EEPROM_WRITE);

	wr32(hw, NBL_LSP_EEPROM_WDATA_REG, write_data);

	/* Use rising edge to trigger read operation. */
	wr32(hw, NBL_LSP_EEPROM_REQ_REG, 0);
	wr32(hw, NBL_LSP_EEPROM_REQ_REG, 1);

	do {
		*(u32 *)&status = rd32(hw, NBL_LSP_EEPROM_STATUS_REG);
		if (status.done)
			break;
		i++;
		if (!(i % 1000)) {
			pr_err("Wait too long for EEPROM write addr %x done\n", addr);
			return -EIO;
		}

		usleep_range(100, 200);
	} while (true);

	return 0;
}

int nbl_get_eeprom_len(struct net_device *netdev)
{
	return NBL_EEPROM_LENGTH;
}

int nbl_af_get_eeprom(struct nbl_hw *hw, u32 offset, u32 length, u8 *bytes)
{
	int total_length;
	u32 i;
	int ret;

	total_length = nbl_get_eeprom_len(NULL);
	if ((u32)total_length <= offset || (u32)total_length - offset < length) {
		pr_debug("Try to access invalid EEPROM range\n");
		return -EINVAL;
	}

	for (i = 0; i < length; i++) {
		ret = nbl_read_eeprom_byte(hw, offset + i, bytes + i);
		if (ret < 0) {
			pr_info("Get EEPROM content failed\n");
			return ret;
		}
	}

	return 0;
}

static int nbl_get_eeprom(struct net_device *netdev, struct ethtool_eeprom *eeprom, u8 *bytes)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	struct nbl_hw *hw = &adapter->hw;
	int ret;

	if (is_af(hw))
		ret = nbl_af_get_eeprom(hw, eeprom->offset, eeprom->len, bytes);
	else
		ret = nbl_mailbox_req_get_eeprom(hw, eeprom->offset, eeprom->len, bytes);

	return ret;
}

static int nbl_get_port_type(struct nbl_hw *hw)
{
	u8 cable_tech;
	u8 cable_comp;
	struct ethtool_eeprom eeprom = { 0 };
	int ret;

	eeprom.offset = SFF_8472_CABLE_TECHNOLOGY;
	eeprom.len = sizeof(cable_tech);
	if (is_af(hw))
		ret = nbl_af_get_module_eeprom(hw, hw->eth_port_id, &eeprom, &cable_tech);
	else
		ret = nbl_mailbox_req_get_module_eeprom(hw, hw->eth_port_id, &eeprom, &cable_tech);

	if (ret) {
		pr_err("Read SFF_8472_CABLE_TECHNOLOGY register in passive cable case failed, port: %d\n",
		       hw->eth_port_id);
		return PORT_OTHER;
	}

	if (cable_tech & SFF_PASSIVE_CABLE) {
		eeprom.offset = SFF_8472_CABLE_SPEC_COMP;
		eeprom.len = sizeof(cable_comp);
		if (is_af(hw))
			ret = nbl_af_get_module_eeprom(hw, hw->eth_port_id, &eeprom, &cable_comp);
		else
			ret =  nbl_mailbox_req_get_module_eeprom(hw, hw->eth_port_id,
								 &eeprom, &cable_comp);

		if (ret) {
			pr_err("Read SFF_8472_CABLE_SPEC_COMP register in passive cable case failed, port: %d\n",
			       hw->eth_port_id);
			return PORT_OTHER;
		}

		/* determine if the port is a cooper cable */
		if (cable_comp == SFF_COPPER_UNSPECIFIED ||
		    cable_comp == SFF_COPPER_8431_APPENDIX_E)
			return PORT_DA;
		else
			return PORT_FIBRE;
	} else if (cable_tech & SFF_ACTIVE_CABLE) {
		eeprom.offset = SFF_8472_CABLE_SPEC_COMP;
		eeprom.len = sizeof(cable_comp);
		if (is_af(hw))
			ret = nbl_af_get_module_eeprom(hw, hw->eth_port_id, &eeprom, &cable_comp);
		else
			ret =  nbl_mailbox_req_get_module_eeprom(hw, hw->eth_port_id,
								 &eeprom, &cable_comp);

		if (ret) {
			pr_err("Read SFF_8472_CABLE_SPEC_COMP register in active cable case failed, port: %d\n",
			       hw->eth_port_id);
			return PORT_OTHER;
		}

		/* determine if the port is a cooper cable */
		if (cable_comp == SFF_COPPER_UNSPECIFIED ||
		    cable_comp == SFF_COPPER_8431_APPENDIX_E ||
		    cable_comp == SFF_COPPER_8431_LIMITING)
			return PORT_DA;
		else
			return PORT_FIBRE;
	} else {
		return PORT_FIBRE;
	}
}

static void
nbl_get_ksettings(const struct nbl_hw *hw, struct ethtool_link_ksettings *cmd)
{
	unsigned int size = BITS_TO_LONGS(__ETHTOOL_LINK_MODE_MASK_NBITS);
	unsigned int idx = 0;

	cmd->base.autoneg = AUTONEG_DISABLE;

	for (; idx < size; idx++) {
		cmd->link_modes.supported[idx] = hw->supported[idx];
		cmd->link_modes.advertising[idx] = hw->advertising[idx];
	}
}

int nbl_af_query_link_speed(struct nbl_hw *hw, u8 eth_port_id, u32 *speed_stat)
{
	struct nbl_loopback_mode loopback_mode = {0};

	rd32_for_each(hw, NBL_ETH_LOOPBACK_MODE_REG(eth_port_id),
		      (u32 *)&loopback_mode, sizeof(loopback_mode));

	*speed_stat = loopback_mode.speed_stat;

	return 0;
}

u32 nbl_query_link_speed(struct nbl_hw *hw)
{
	u32 speed_stat;
	u8 eth_port_id = hw->eth_port_id;
	int ret;

	if (is_af(hw))
		ret = nbl_af_query_link_speed(hw, eth_port_id, &speed_stat);
	else
		ret = nbl_mailbox_req_link_speed(hw, eth_port_id, &speed_stat);

	if (ret) {
		pr_err("Failed to get link speed, port id: %d\n", eth_port_id);
		return NBL_MODULE_SPEED_NOT_SUPPORT;
	}

	if (speed_stat == NBL_ETH_SPEED_MODE_10G)
		return NBL_MODULE_SPEED_10G;
	else if (speed_stat == NBL_ETH_SPEED_MODE_1G)
		return NBL_MODULE_SPEED_1G;
	else
		return NBL_MODULE_SPEED_NOT_SUPPORT;
}

static int
nbl_get_link_ksettings(struct net_device *netdev, struct ethtool_link_ksettings *cmd)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	struct nbl_hw *hw = &adapter->hw;
	u32 link_stat;
	u32 link_speed;

	nbl_get_ksettings(hw, cmd);

	link_stat = nbl_get_link(netdev);
	if (!link_stat) {
		cmd->base.speed = SPEED_UNKNOWN;
		cmd->base.duplex = DUPLEX_UNKNOWN;
		cmd->base.port = PORT_OTHER;
		return 0;
	}

	link_speed = nbl_query_link_speed(hw);
	switch (link_speed) {
	case NBL_MODULE_SPEED_10G:
		cmd->base.speed = SPEED_10000;
		cmd->base.duplex = DUPLEX_FULL;
		cmd->base.port = nbl_get_port_type(hw);
		break;
	case NBL_MODULE_SPEED_1G:
		cmd->base.speed = SPEED_1000;
		cmd->base.duplex = DUPLEX_FULL;
		cmd->base.port = nbl_get_port_type(hw);
		break;
	default:
		cmd->base.speed = SPEED_UNKNOWN;
		cmd->base.duplex = DUPLEX_UNKNOWN;
		cmd->base.port = PORT_OTHER;
		break;
	}

	return 0;
}

static int nbl_set_link_ksettings(struct net_device *netdev,
				  const struct ethtool_link_ksettings *cmd)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	struct nbl_hw *hw = &adapter->hw;

	if (cmd->base.duplex == DUPLEX_HALF) {
		pr_warn("Half duplex mode is not supported\n");
		return -EINVAL;
	}

	if (cmd->base.autoneg == AUTONEG_ENABLE) {
		pr_warn("Autoneg is not supported\n");
		return -EINVAL;
	}

	if (cmd->base.speed == SPEED_10000) {
		if (hw->module_support_speed & NBL_MODULE_SPEED_10G) {
			nbl_set_module_speed(hw, NBL_MODULE_SPEED_10G);
		} else {
			pr_warn("Port %d module doesn't support 10G mode\n", hw->eth_port_id);
			return -EINVAL;
		}
	} else if (cmd->base.speed == SPEED_1000) {
		if (hw->module_support_speed & NBL_MODULE_SPEED_1G) {
			nbl_set_module_speed(hw, NBL_MODULE_SPEED_1G);
		} else {
			pr_warn("Port %d module doesn't support 1G mode\n", hw->eth_port_id);
			return -EINVAL;
		}
	} else {
		pr_warn("Port %d speed mode is not supported\n", hw->eth_port_id);
		return -EINVAL;
	}

	return 0;
}

static u32 nbl_get_msglevel(struct net_device *netdev)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);

	return adapter->msg_enable;
}

static void nbl_set_msglevel(struct net_device *netdev, u32 msglevel)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);

	adapter->msg_enable = msglevel;
}

static u64 nbl_link_test(struct nbl_hw *hw)
{
	bool link_up;

	link_up = nbl_query_link_status(hw);
	if (link_up)
		return 0;
	else
		return 1;
}

u64 nbl_af_reg_test(struct nbl_hw *hw, u8 eth_port_id)
{
	u32 tmp_val;
	u32 reserve;
	int i;
	const u32 patterns[NBL_TEST_PATTERN_NUM] = {
		NBL_REG_TEST_PATTERN_0,
		NBL_REG_TEST_PATTERN_1,
		NBL_REG_TEST_PATTERN_2,
		NBL_REG_TEST_PATTERN_3
	};

	reserve = rd32(hw, NBL_ETH_SELF_STIMU_REG2(eth_port_id));

	for (i = 0; i < NBL_TEST_PATTERN_NUM; i++) {
		wr32(hw, NBL_ETH_SELF_STIMU_REG2(eth_port_id), patterns[i]);
		tmp_val = rd32(hw, NBL_ETH_SELF_STIMU_REG2(eth_port_id));

		if (tmp_val != patterns[i]) {
			wr32(hw, NBL_ETH_SELF_STIMU_REG2(eth_port_id), reserve);
			return 1;
		}
	}
	/* restore register value */
	wr32(hw, NBL_ETH_SELF_STIMU_REG2(eth_port_id), reserve);

	return 0;
}

static u64 nbl_reg_test(struct nbl_hw *hw, u8 eth_port_id)
{
	u64 ret;

	if (is_af(hw))
		ret = nbl_af_reg_test(hw, eth_port_id);
	else
		ret = nbl_mailbox_req_reg_test(hw, eth_port_id);

	return ret;
}

static void nbl_self_test(struct net_device *netdev, struct ethtool_test *eth_test, u64 *data)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	struct nbl_hw *hw = &adapter->hw;
	u8 eth_port_id = hw->eth_port_id;
	bool if_running = netif_running(netdev);
	int status;

	if (eth_test->flags == ETH_TEST_FL_OFFLINE) {
		/* if online, take if offline */
		if (if_running)
			nbl_stop(netdev);

		data[NBL_ETH_TEST_LINK] = nbl_link_test(hw);
		data[NBL_ETH_TEST_REG] = nbl_reg_test(hw, eth_port_id);

		if (data[NBL_ETH_TEST_LINK] ||
		    data[NBL_ETH_TEST_REG])
			eth_test->flags |= ETH_TEST_FL_FAILED;

		if (if_running) {
			status = nbl_open(netdev);
			if (status) {
				netdev_err(netdev, "Could not open device %s, err %d\n",
					   pci_name(adapter->pdev), status);
			}
		}
	} else {
		/* Online test */
		data[NBL_ETH_TEST_LINK] = nbl_link_test(hw);

		if (data[NBL_ETH_TEST_LINK])
			eth_test->flags |= ETH_TEST_FL_FAILED;

		/* Only test offlined, pass by default */
		data[NBL_ETH_TEST_REG] = 0;
	}
}

int nbl_af_set_phys_id(struct nbl_hw *hw, u8 eth_port_id, enum ethtool_phys_id_state state)
{
	u32 led_reg_ctrl;
	u32 led_reg_addr = NBL_ETH_LED_CTRL_REG(eth_port_id);

	switch (state) {
	case ETHTOOL_ID_ACTIVE:
		led_reg_ctrl = rd32(hw, led_reg_addr);
		led_reg_ctrl |= NBL_FORCE_LED_EN;
		wr32(hw, led_reg_addr, led_reg_ctrl);
		return NBL_LED_FLICKER_FREQUENCY;
	case ETHTOOL_ID_ON:
		led_reg_ctrl = rd32(hw, led_reg_addr);
		led_reg_ctrl |= NBL_FORCE_ACT_LED_LEVEL;
		wr32(hw, led_reg_addr, led_reg_ctrl);
		break;
	case ETHTOOL_ID_OFF:
		led_reg_ctrl = rd32(hw, led_reg_addr);
		led_reg_ctrl &= ~((u32)NBL_FORCE_ACT_LED_LEVEL);
		wr32(hw, led_reg_addr, led_reg_ctrl);
		break;
	case ETHTOOL_ID_INACTIVE:
		led_reg_ctrl = rd32(hw, led_reg_addr);
		led_reg_ctrl &= ~((u32)NBL_FORCE_LED_EN);
		wr32(hw, led_reg_addr, led_reg_ctrl);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int
nbl_set_phys_id(struct net_device *netdev, enum ethtool_phys_id_state state)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	struct nbl_hw *hw = &adapter->hw;
	int ret;

	if (is_af(hw))
		ret = nbl_af_set_phys_id(hw, hw->eth_port_id, state);
	else
		ret = nbl_mailbox_req_set_phy_id(hw, hw->eth_port_id, state);

	return ret;
}

static int
nbl_set_pauseparam(struct net_device *netdev, struct ethtool_pauseparam *param)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	struct nbl_hw *hw = &adapter->hw;

	if (param->autoneg == AUTONEG_ENABLE) {
		pr_debug("autoneg is not support\n");
		return -EINVAL;
	}

	if (param->rx_pause == hw->fc.rx_pause && param->tx_pause == hw->fc.tx_pause) {
		pr_debug("autoneg param is not changed\n");
		return 0;
	}

	hw->fc.rx_pause = param->rx_pause;
	hw->fc.tx_pause = param->tx_pause;
	if (is_af(hw))
		nbl_af_set_pauseparam(hw, hw->eth_port_id, hw->fc);
	else
		nbl_mailbox_req_set_pauseparam(hw, hw->eth_port_id, hw->fc);

	if (hw->fc.rx_pause && hw->fc.tx_pause) {
		__clear_bit(ETHTOOL_LINK_MODE_Asym_Pause_BIT, hw->advertising);
		__set_bit(ETHTOOL_LINK_MODE_Pause_BIT, hw->advertising);
	} else if (!hw->fc.rx_pause && !hw->fc.tx_pause) {
		__clear_bit(ETHTOOL_LINK_MODE_Pause_BIT, hw->advertising);
		__clear_bit(ETHTOOL_LINK_MODE_Asym_Pause_BIT, hw->advertising);
	} else if (hw->fc.rx_pause && !hw->fc.tx_pause) {
		__set_bit(ETHTOOL_LINK_MODE_Asym_Pause_BIT, hw->advertising);
		__set_bit(ETHTOOL_LINK_MODE_Pause_BIT, hw->advertising);
	} else if (!hw->fc.rx_pause && hw->fc.tx_pause) {
		__set_bit(ETHTOOL_LINK_MODE_Asym_Pause_BIT, hw->advertising);
		__clear_bit(ETHTOOL_LINK_MODE_Pause_BIT, hw->advertising);
	}

	return 0;
}

static void
nbl_get_pauseparam(struct net_device *netdev, struct ethtool_pauseparam *param)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	struct nbl_hw *hw = &adapter->hw;

	param->autoneg = AUTONEG_DISABLE;
	param->rx_pause = hw->fc.rx_pause;
	param->tx_pause = hw->fc.tx_pause;
}

void nbl_af_get_pause_stats(struct nbl_hw *hw, u8 eth_port_id, struct ethtool_pause_stats *stats)
{
	struct nbl_pause_cnt pause_cnt;

	rd32_for_each(hw, NBL_PA_PAUSE_RX_CNT,
		      (u32 *)&pause_cnt, sizeof(pause_cnt));
	stats->rx_pause_frames = pause_cnt.eth_pause_cnt[eth_port_id];

	rd32_for_each(hw, NBL_PED_PAUSE_TX_CNT,
		      (u32 *)&pause_cnt, sizeof(pause_cnt));
	stats->tx_pause_frames = pause_cnt.eth_pause_cnt[eth_port_id];
}

static void nbl_get_pause_stats(struct net_device *netdev, struct ethtool_pause_stats *stats)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	struct nbl_hw *hw = &adapter->hw;

	if (is_af(hw))
		nbl_af_get_pause_stats(hw, hw->eth_port_id, stats);
	else
		nbl_mailbox_req_get_pause_stats(hw, hw->eth_port_id, stats);
}

static void nbl_stats_fill_strings(struct nbl_adapter *adapter, u8 *data)
{
	char *p = (char *)data;
	u8 i;

	for (i = 0; i < NBL_GLOBAL_STATS_LEN; i++) {
		snprintf(p, ETH_GSTRING_LEN, "%s", nbl_gstrings_stats[i].stat_string);
		p += ETH_GSTRING_LEN;
	}

	for (i = 0; i < adapter->num_txq; i++) {
		snprintf(p, ETH_GSTRING_LEN, "tx_queue_%u_packets", i);
		p += ETH_GSTRING_LEN;
		snprintf(p, ETH_GSTRING_LEN, "tx_queue_%u_bytes", i);
		p += ETH_GSTRING_LEN;
	}

	for (i = 0; i < adapter->num_rxq; i++) {
		snprintf(p, ETH_GSTRING_LEN, "rx_queue_%u_packets", i);
		p += ETH_GSTRING_LEN;
		snprintf(p, ETH_GSTRING_LEN, "rx_queue_%u_bytes", i);
		p += ETH_GSTRING_LEN;
	}
}

static void nbl_priv_flags_fill_strings(struct nbl_adapter *adapter, u8 *data)
{
	char *p = (char *)data;
	unsigned int i;

	for (i = 0; i < NBL_PRIV_FLAG_ARRAY_SIZE; i++) {
		snprintf(p, ETH_GSTRING_LEN, "%s", nbl_priv_flags[i]);
		p += ETH_GSTRING_LEN;
	}
}

static void nbl_get_strings(struct net_device *netdev, u32 stringset, u8 *data)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);

	switch (stringset) {
	case ETH_SS_TEST:
		memcpy(data, nbl_gstrings_test, NBL_TEST_LEN * ETH_GSTRING_LEN);
		break;
	case ETH_SS_STATS:
		nbl_stats_fill_strings(adapter, data);
		break;
	case ETH_SS_PRIV_FLAGS:
		nbl_priv_flags_fill_strings(adapter, data);
		break;
	}
}

static int nbl_get_sset_count(struct net_device *netdev, int sset)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	u8 total_queues;

	switch (sset) {
	case ETH_SS_TEST:
		return NBL_TEST_LEN;
	case ETH_SS_STATS:
		total_queues = adapter->num_txq + adapter->num_rxq;
		return NBL_GLOBAL_STATS_LEN + total_queues * NBL_QUEUE_STAT_ENTRIES;
	case ETH_SS_PRIV_FLAGS:
		return NBL_PRIV_FLAG_ARRAY_SIZE;
	default:
		return -EOPNOTSUPP;
	}
}

static void
nbl_get_ethtool_stats(struct net_device *netdev, struct ethtool_stats *stats, u64 *data)
{
	struct rtnl_link_stats64 temp_stats;
	struct nbl_adapter *adapter = netdev_priv(netdev);
	struct rtnl_link_stats64 *net_stats;
	struct nbl_ring *ring;
	unsigned int start;
	char *p = NULL;
	int i;
	int j;

	nbl_update_stats_subtask(adapter);
	net_stats = dev_get_stats(netdev, &temp_stats);
	for (i = 0; i < NBL_GLOBAL_STATS_LEN; i++) {
		switch (nbl_gstrings_stats[i].type) {
		case NBL_NETDEV_STATS:
			p = (char *)net_stats +
			     nbl_gstrings_stats[i].stat_offset;
			break;
		case NBL_ETH_STATS:
		case NBL_PRIV_STATS:
			p = (char *)adapter +
			     nbl_gstrings_stats[i].stat_offset;
			break;
		default:
			data[i] = 0;
			continue;
		}

		data[i] = (nbl_gstrings_stats[i].sizeof_stat ==
			   sizeof(u64)) ? *(u64 *)p : *(u32 *)p;
	}

	for (j = 0; j < adapter->num_txq; j++) {
		ring = adapter->tx_rings[j];
		do {
			start = u64_stats_fetch_begin_irq(&ring->syncp);
			data[i] = ring->stats.packets;
			data[i + 1] = ring->stats.bytes;
		} while (u64_stats_fetch_retry_irq(&ring->syncp, start));
		i += 2;
	}

	for (j = 0; j < adapter->num_rxq; j++) {
		ring = adapter->rx_rings[j];
		do {
			start = u64_stats_fetch_begin_irq(&ring->syncp);
			data[i] = ring->stats.packets;
			data[i + 1] = ring->stats.bytes;
		} while (u64_stats_fetch_retry_irq(&ring->syncp, start));
		i += 2;
	}
}

int nbl_af_get_coalesce(struct nbl_hw *hw, struct ethtool_coalesce *ec,
			u16 func_id, u16 local_vector_id)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	u32 regval;
	u16 global_vector_id;

	WARN_ON(!func_res);
	WARN_ON(local_vector_id >= func_res->num_interrupts);
	global_vector_id = func_res->interrupts[local_vector_id];

	regval = rd32(hw, NBL_PADPT_MSIX_INFO_REG_ARR(global_vector_id));

	ec->rx_max_coalesced_frames = (regval & NBL_MSIX_INTR_CTRL_PNUM_MASK) >>
				      NBL_MSIX_INTR_CTRL_PNUM_SHIFT;
	ec->rx_coalesce_usecs = ((regval & NBL_MSIX_INTR_CTRL_RATE_MASK) >>
				NBL_MSIX_INTR_CTRL_RATE_SHIFT) *
				NBL_MSIX_INTR_CTRL_RATE_GRANUL;

	return 0;
}

static int nbl_get_coalesce(struct net_device *netdev, struct ethtool_coalesce *ec,
			    struct kernel_ethtool_coalesce __always_unused *kernel_coal,
			    struct netlink_ext_ack __always_unused *extack)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	struct nbl_hw *hw = &adapter->hw;
	int err;
	u16 local_vector_id;

	local_vector_id = adapter->rx_rings[0]->q_vector->q_vector_id;

	if (is_af(hw))
		err = nbl_af_get_coalesce(hw, ec, 0, local_vector_id);
	else
		err = nbl_mailbox_req_get_coalesce(hw, ec, local_vector_id);

	return err;
}

int nbl_af_set_coalesce(struct nbl_hw *hw, u16 func_id, u16 local_vector_id,
			u16 num_q_vectors, u32 regval)
{
	struct nbl_af_res_info *af_res = hw->af_res;
	struct nbl_func_res *func_res = af_res->res_record[func_id];
	u16 global_vector_id;
	int i;

	WARN_ON(!func_res);
	WARN_ON(local_vector_id + num_q_vectors > func_res->num_interrupts);

	for (i = 0; i < num_q_vectors; i++) {
		global_vector_id = func_res->interrupts[local_vector_id + i];
		wr32(hw, NBL_PADPT_MSIX_INFO_REG_ARR(global_vector_id), regval);
	}

	return 0;
}

static int nbl_set_coalesce(struct net_device *netdev, struct ethtool_coalesce *ec,
			    struct kernel_ethtool_coalesce __always_unused *kernel_coal,
			    struct netlink_ext_ack __always_unused *extack)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	struct nbl_hw *hw = &adapter->hw;
	u16 pnum;
	u16 rate;
	u32 regval;
	int err;
	u16 local_vector_id;
	u16 num_q_vectors;

	num_q_vectors = adapter->num_q_vectors;
	local_vector_id = adapter->rx_rings[0]->q_vector->q_vector_id;

	if (ec->rx_max_coalesced_frames > U16_MAX) {
		pr_err("rx_frames %d out of range: [0 - %d]\n",
		       ec->rx_max_coalesced_frames, U16_MAX);
		return -EINVAL;
	}

	if (ec->rx_coalesce_usecs % NBL_MSIX_INTR_CTRL_RATE_GRANUL) {
		pr_err("rx_usecs should be integral multiple of %d\n",
		       NBL_MSIX_INTR_CTRL_RATE_GRANUL);
		return -EINVAL;
	} else if ((ec->rx_coalesce_usecs / NBL_MSIX_INTR_CTRL_RATE_GRANUL) > U16_MAX) {
		pr_err("rx_frames %d out of range: [0 - %d]\n",
		       ec->rx_coalesce_usecs, U16_MAX * NBL_MSIX_INTR_CTRL_RATE_GRANUL);
		return -EINVAL;
	}

	pnum = (u16)ec->rx_max_coalesced_frames;
	rate = (u16)(ec->rx_coalesce_usecs / NBL_MSIX_INTR_CTRL_RATE_GRANUL);

	regval = ((pnum << NBL_MSIX_INTR_CTRL_PNUM_SHIFT) & NBL_MSIX_INTR_CTRL_PNUM_MASK) |
		 ((rate << NBL_MSIX_INTR_CTRL_RATE_SHIFT) & NBL_MSIX_INTR_CTRL_RATE_MASK);

	if (is_af(hw))
		err = nbl_af_set_coalesce(hw, 0, local_vector_id, num_q_vectors, regval);
	else
		err = nbl_mailbox_req_set_coalesce(hw, local_vector_id, num_q_vectors, regval);

	return err;
}

static u32 nbl_get_max_combined(struct nbl_adapter *adapter)
{
	return min_t(u32, NBL_MAX_RING_NUM, (u16)num_online_cpus());
}

static u32 nbl_get_combined_cnt(struct nbl_adapter *adapter)
{
	int i;
	u32 combined = 0;
	u16 num = adapter->num_q_vectors;

	for (i = 0; i < num; i++) {
		struct nbl_q_vector *q_vector = adapter->q_vectors[i];

		if (q_vector->num_ring_rx && q_vector->num_ring_tx)
			combined++;
	}

	return combined;
}

static void nbl_get_channels(struct net_device *dev, struct ethtool_channels *channels)
{
	struct nbl_adapter *adapter = netdev_priv(dev);

	channels->max_combined = nbl_get_max_combined(adapter);

	channels->combined_count = nbl_get_combined_cnt(adapter);
}

static u32 nbl_get_priv_flags(struct net_device *netdev)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	u32 ret_flags = 0;

	if (adapter->flags & BIT(NBL_ADAPTER_SRIOV_ENA))
		ret_flags |= BIT(NBL_ADAPTER_SRIOV_ENA);

	return ret_flags;
}

static int nbl_set_priv_flags(struct net_device *netdev, u32 priv_flags)
{
	struct nbl_adapter *adapter = netdev_priv(netdev);
	u32 flags = adapter->flags;

	flags &= ~(1 << NBL_ADAPTER_SRIOV_ENA);
	if (priv_flags & (1 << NBL_ADAPTER_SRIOV_ENA))
		flags |= (1 << NBL_ADAPTER_SRIOV_ENA);

	if (flags != adapter->flags)
		adapter->flags = flags;

	return 0;
}

static const struct ethtool_ops nbl_ethtool_ops = {
#ifdef ETHTOOL_COALESCE_RX_USECS
	.supported_coalesce_params = ETHTOOL_COALESCE_RX_USECS | ETHTOOL_COALESCE_RX_MAX_FRAMES,
#endif /* ETHTOOL_COALESCE_USECS */
	.get_drvinfo		= nbl_get_drvinfo,
	.get_link		= nbl_get_link,
	.get_regs_len		= nbl_get_regs_len,
	.get_regs		= nbl_get_ethtool_dump_regs,
	.get_ringparam		= nbl_get_ringparam,
	.set_ringparam		= nbl_set_ringparam,
	.get_link_ksettings	= nbl_get_link_ksettings,
	.set_link_ksettings	= nbl_set_link_ksettings,
	.get_msglevel		= nbl_get_msglevel,
	.set_msglevel		= nbl_set_msglevel,
	.self_test		= nbl_self_test,
	.get_module_eeprom	= nbl_get_module_eeprom,
	.get_module_info	= nbl_get_module_info,
	.get_eeprom_len		= nbl_get_eeprom_len,
	.get_eeprom		= nbl_get_eeprom,
	.set_phys_id		= nbl_set_phys_id,
	.set_pauseparam		= nbl_set_pauseparam,
	.get_pauseparam		= nbl_get_pauseparam,
	.get_pause_stats	= nbl_get_pause_stats,
	.get_strings		= nbl_get_strings,
	.get_sset_count		= nbl_get_sset_count,
	.get_ethtool_stats	= nbl_get_ethtool_stats,
	.get_coalesce		= nbl_get_coalesce,
	.set_coalesce		= nbl_set_coalesce,
	.get_channels		= nbl_get_channels,
	.get_priv_flags		= nbl_get_priv_flags,
	.set_priv_flags		= nbl_set_priv_flags,
};

void nbl_set_ethtool_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = &nbl_ethtool_ops;
}
