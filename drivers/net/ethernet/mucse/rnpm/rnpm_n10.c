// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 - 2024 Mucse Corporation. */

#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/sched.h>

#include "rnpm.h"
#include "rnpm_phy.h"
#include "rnpm_mbx.h"
#include "rnpm_pcs.h"
#include "rnpm_mbx_fw.h"

#define RNPM_N10_MAX_TX_QUEUES 128
#define RNPM_N10_MAX_RX_QUEUES 128

#define RNPM_N400_MAX_TX_QUEUES 16
#define RNPM_N400_MAX_RX_QUEUES 16

#define RNPM_N10_NCSI_RAR_ENTRIES (hw->ncsi_rar_entries) /*4*/
#define RNPM_N10_RAR_ENTRIES (128 - RNPM_N10_NCSI_RAR_ENTRIES)
#define RNPM_N10_MC_TBL_SIZE 128
#define RNPM_N10_MC_TBL_SIZE_MAC 8
#define RNPM_N10_VFT_TBL_SIZE 128
#define RNPM_N10_VFT_TBL_SIZE_MAC 1
#define RNPM_N10_RX_PB_SIZE 512
#define RNPM_N10_MSIX_VECTORS 64

#define NET_FEATURE_TCAM 1

static bool rnpm_mng_enabled(struct rnpm_hw *hw)
{
	return false;
}
__maybe_unused static void rnpm_init_mac_link_ops_n10(struct rnpm_hw *hw)
{
}

static s32 rnpm_get_invariants_n10(struct rnpm_hw *hw)
{
	struct rnpm_mac_info *mac = &hw->mac;

	// rnpm_init_mac_link_ops_n10(hw);
	//  mode is setup here
	switch (hw->mode) {
	case MODE_NIC_MODE_1PORT_40G:
	case MODE_NIC_MODE_1PORT:
		mac->mc_location = rnpm_mc_location_nic;
		mac->mcft_size = RNPM_N10_MC_TBL_SIZE;
		mac->mc_filter_type = rnpm_mc_filter_type0;
		mac->vlan_location = rnpm_vlan_location_nic;
		mac->vft_size = RNPM_N10_VFT_TBL_SIZE;
		break;
	case MODE_NIC_MODE_2PORT:
	case MODE_NIC_MODE_4PORT:
		mac->mc_filter_type = rnpm_mc_filter_type4;
		mac->mc_location = rnpm_mc_location_mac;
		mac->mcft_size = RNPM_N10_MC_TBL_SIZE_MAC;
		mac->vlan_location = rnpm_vlan_location_mac;
		mac->vft_size = RNPM_N10_VFT_TBL_SIZE_MAC;

		break;
	}

	hw->usecstocount = hw->axi_mhz;
	hw->dma_split_size = RNPM_RXBUFFER_1536;
	hw->ncsi_vf_cpu_shm_pf_base = RNPM_VF_CPU_SHM_BASE_NR62;
	hw->ncsi_mc_count = RNPM_NCSI_MC_COUNT;
	hw->ncsi_vlan_count = RNPM_NCSI_VLAN_COUNT;
	mac->num_rar_entries = RNPM_N10_RAR_ENTRIES;
	mac->max_rx_queues = RNPM_N10_MAX_RX_QUEUES;
	mac->max_tx_queues = RNPM_N10_MAX_TX_QUEUES;
	// mac->max_msix_vectors = rnpm_get_pcie_msix_count_generic(hw);
	mac->max_msix_vectors = RNPM_N10_MSIX_VECTORS;
	hw->wol_supported = WAKE_MAGIC;
	hw->feature_flags |=
		RNPM_NET_FEATURE_SG | RNPM_NET_FEATURE_TX_CHECKSUM |
		RNPM_NET_FEATURE_RX_CHECKSUM | RNPM_NET_FEATURE_TSO |
		RNPM_NET_FEATURE_TX_UDP_TUNNEL | RNPM_NET_FEATURE_VLAN_FILTER |
		/*RNPM_NET_FEATURE_VLAN_OFFLOAD |*/ RNPM_NET_FEATURE_TCAM |
		RNPM_NET_FEATURE_RX_HASH | RNPM_NET_FEATURE_RX_FCS;
	if (!hw->ncsi_en)
		hw->feature_flags |= RNPM_NET_FEATURE_VLAN_OFFLOAD;

	return 0;
}

static s32 rnpm_get_invariants_n400(struct rnpm_hw *hw)
{
	struct rnpm_mac_info *mac = &hw->mac;

	// rnpm_init_mac_link_ops_n10(hw);
	//  mode is setup here
	switch (hw->mode) {
	case MODE_NIC_MODE_1PORT_40G:
	case MODE_NIC_MODE_1PORT:
		mac->mc_location = rnpm_mc_location_nic;
		mac->mcft_size = RNPM_N10_MC_TBL_SIZE;
		mac->mc_filter_type = rnpm_mc_filter_type0;
		mac->vlan_location = rnpm_vlan_location_nic;
		mac->vft_size = RNPM_N10_VFT_TBL_SIZE;
		break;
	case MODE_NIC_MODE_2PORT:
	case MODE_NIC_MODE_4PORT:
		mac->mc_filter_type = rnpm_mc_filter_type4;
		mac->mc_location = rnpm_mc_location_mac;
		mac->mcft_size = RNPM_N10_MC_TBL_SIZE_MAC;
		mac->vlan_location = rnpm_vlan_location_mac;
		mac->vft_size = RNPM_N10_VFT_TBL_SIZE_MAC;

		break;
	}

	hw->usecstocount = hw->axi_mhz;
	hw->dma_split_size = RNPM_RXBUFFER_1536;
	hw->ncsi_vf_cpu_shm_pf_base = RNPM_VF_CPU_SHM_BASE_NR62;
	hw->ncsi_mc_count = RNPM_NCSI_MC_COUNT;
	hw->ncsi_vlan_count = RNPM_NCSI_VLAN_COUNT;
	mac->num_rar_entries = RNPM_N10_RAR_ENTRIES;
	mac->max_rx_queues = RNPM_N400_MAX_RX_QUEUES;
	mac->max_tx_queues = RNPM_N400_MAX_TX_QUEUES;
	// mac->max_msix_vectors = rnpm_get_pcie_msix_count_generic(hw);
	mac->max_msix_vectors = RNPM_N10_MSIX_VECTORS;
	hw->wol_supported = WAKE_MAGIC;
	hw->feature_flags |=
		RNPM_NET_FEATURE_SG | RNPM_NET_FEATURE_TX_CHECKSUM |
		RNPM_NET_FEATURE_RX_CHECKSUM | RNPM_NET_FEATURE_TSO |
		RNPM_NET_FEATURE_TX_UDP_TUNNEL | RNPM_NET_FEATURE_VLAN_FILTER |
		/*RNPM_NET_FEATURE_VLAN_OFFLOAD |*/ RNPM_NET_FEATURE_TCAM |
		RNPM_NET_FEATURE_RX_HASH | RNPM_NET_FEATURE_RX_FCS;
	if (!hw->ncsi_en)
		hw->feature_flags |= RNPM_NET_FEATURE_VLAN_OFFLOAD;

	return 0;
}

/**
 *  rnpm_init_phy_ops_n10 - PHY/SFP specific init
 *  @hw: pointer to hardware structure
 *
 *  Initialize any function pointers that were not able to be
 *  set during get_invariants because the PHY/SFP type was
 *  not known.  Perform the SFP init if necessary.
 *
 **/
static s32 rnpm_init_phy_ops_n10(struct rnpm_hw *hw)
{
	s32 ret_val = 0;

	hw->phy.sfp_setup_needed = true;
	return ret_val;
}

static s32 rnpm_setup_sfp_modules_n10(struct rnpm_hw *hw)
{
	return 0;
}

/**
 *  rnpm_reinit_fdir_tables_n10 - Reinitialize Flow Director tables.
 *  @hw: pointer to hardware structure
 **/
s32 rnpm_reinit_fdir_tables_n10(struct rnpm_hw *hw)
{
	return 0;
}

/**
 *  rnpm_fdir_enable_n10 - Initialize Flow Director control registers
 *  @hw: pointer to hardware structure
 *  @fdirctrl: value to write to flow director control register
 **/
__maybe_unused static void rnpm_fdir_enable_n10(struct rnpm_hw *hw,
						u32 fdirctrl)
{
}

/**
 *  rnpm_init_fdir_signature_n10 - Initialize Flow Director signature filters
 *  @hw: pointer to hardware structure
 *  @fdirctrl: value to write to flow director control register, initially
 *             contains just the value of the Rx packet buffer allocation
 **/
s32 rnpm_init_fdir_signature_n10(struct rnpm_hw *hw, u32 fdirctrl)
{
	return 0;
}

/**
 *  rnpm_init_fdir_perfect_n10 - Initialize Flow Director perfect filters
 *  @hw: pointer to hardware structure
 *  @fdirctrl: value to write to flow director control register, initially
 *             contains just the value of the Rx packet buffer allocation
 **/
s32 rnpm_init_fdir_perfect_n10(struct rnpm_hw *hw, u32 fdirctrl)
{
	return 0;
}

/* These defines allow us to quickly generate all of the necessary instructions
 * in the function below by simply calling out RNPM_COMPUTE_SIG_HASH_ITERATION
 * for values 0 through 15
 */
#define RNPM_ATR_COMMON_HASH_KEY                                               \
	(RNPM_ATR_BUCKET_HASH_KEY & RNPM_ATR_SIGNATURE_HASH_KEY)
#define RNPM_COMPUTE_SIG_HASH_ITERATION(_n)                                    \
	do {                                                                   \
	} while (0)

/**
 *  rnpm_atr_compute_sig_hash_n10 - Compute the signature hash
 *  @stream: input bitstream to compute the hash on
 *
 *  This function is almost identical to the function above but contains
 *  several optomizations such as unwinding all of the loops, letting the
 *  compiler work out all of the conditional ifs since the keys are static
 *  defines, and computing two keys at once since the hashed dword stream
 *  will be the same for both keys.
 **/
__maybe_unused static u32
rnpm_atr_compute_sig_hash_n10(union rnpm_atr_hash_dword input,
			      union rnpm_atr_hash_dword common)
{
	return 0;
}

/**
 *  rnpm_atr_add_signature_filter_n10 - Adds a signature hash filter
 *  @hw: pointer to hardware structure
 *  @input: unique input dword
 *  @common: compressed common input dword
 *  @queue: queue index to direct traffic to
 **/
s32 rnpm_fdir_add_signature_filter_n10(struct rnpm_hw *hw,
				       union rnpm_atr_hash_dword input,
				       union rnpm_atr_hash_dword common,
				       u8 queue)
{
	return 0;
}

#define RNPM_COMPUTE_BKT_HASH_ITERATION(_n)                                    \
	do {                                                                   \
		u32 n = (_n);                                                  \
		if (RNPM_ATR_BUCKET_HASH_KEY & (0x01 << n))                    \
			bucket_hash ^= lo_hash_dword >> n;                     \
		if (RNPM_ATR_BUCKET_HASH_KEY & (0x01 << (n + 16)))             \
			bucket_hash ^= hi_hash_dword >> n;                     \
	} while (0)

/**
 *  rnpm_atr_compute_perfect_hash_n10 - Compute the perfect filter hash
 *  @atr_input: input bitstream to compute the hash on
 *  @input_mask: mask for the input bitstream
 *
 *  This function serves two main purposes.  First it applies the input_mask
 *  to the atr_input resulting in a cleaned up atr_input data stream.
 *  Secondly it computes the hash and stores it in the bkt_hash field at
 *  the end of the input byte stream.  This way it will be available for
 *  future use without needing to recompute the hash.
 **/
void rnpm_atr_compute_perfect_hash_n10(union rnpm_atr_input *input,
				       union rnpm_atr_input *input_mask)
{
}

/**
 *  rnpm_get_fdirtcpm_n10 - generate a tcp port from atr_input_masks
 *  @input_mask: mask to be bit swapped
 *
 *  The source and destination port masks for flow director are bit swapped
 *  in that bit 15 effects bit 0, 14 effects 1, 13, 2 etc.  In order to
 *  generate a correctly swapped value we need to bit swap the mask and that
 *  is what is accomplished by this function.
 **/
__maybe_unused static u32
rnpm_get_fdirtcpm_n10(union rnpm_atr_input *input_mask)
{
	return 0;
}

/* These two macros are meant to address the fact that we have registers
 * that are either all or in part big-endian.  As a result on big-endian
 * systems we will end up byte swapping the value to little-endian before
 * it is byte swapped again and written to the hardware in the original
 * big-endian format.
 */
#define RNPM_STORE_AS_BE32(_value)                                             \
	(((u32)(_value) >> 24) | (((u32)(_value)&0x00FF0000) >> 8) |           \
	 (((u32)(_value)&0x0000FF00) << 8) | ((u32)(_value) << 24))

#define RNPM_WRITE_REG_BE32(a, reg, value)                                     \
	RNPM_WRITE_REG((a), (reg), RNPM_STORE_AS_BE32(ntohl(value)))

#define RNPM_STORE_AS_BE16(_value)                                             \
	ntohs(((u16)(_value) >> 8) | ((u16)(_value) << 8))

s32 rnpm_fdir_set_input_mask_n10(struct rnpm_hw *hw,
				 union rnpm_atr_input *input_mask)
{
	return 0;
}

s32 rnpm_fdir_write_perfect_filter_n10(struct rnpm_hw *hw,
				       union rnpm_atr_input *input, u16 soft_id,
				       u8 queue)
{
	return 0;
}

s32 rnpm_fdir_erase_perfect_filter_n10(struct rnpm_hw *hw,
				       union rnpm_atr_input *input, u16 soft_id)
{
	s32 err = 0;

	return err;
}

/**
 *  rnpm_identify_phy_n10 - Get physical layer module
 *  @hw: pointer to hardware structure
 *
 *  Determines the physical layer module found on the current adapter.
 *  If PHY already detected, maintains current PHY type in hw struct,
 *  otherwise executes the PHY detection routine.
 **/
static s32 rnpm_identify_phy_n10(struct rnpm_hw *hw)
{
	// s32 status = RNPM_ERR_PHY_ADDR_INVALID;

	hw->phy.type = rnpm_phy_sfp;

	return 0;
}

static s32 rnpm_identify_sfp_module_n10(struct rnpm_hw *hw)
{
	hw->phy.sfp_type = rnpm_sfp_type_da_cu;

	return 0;
}

/**
 *  rnpm_enable_rx_dma_n10 - Enable the Rx DMA unit on n10
 *  @hw: pointer to hardware structure
 *  @regval: register value to write to RXCTRL
 *
 *  Enables the Rx DMA unit for n10
 **/
static s32 rnpm_enable_rx_dma_n10(struct rnpm_hw *hw, u32 regval)
{
	/* Workaround for n10 silicon errata when enabling the Rx datapath.
	 * If traffic is incoming before we enable the Rx unit, it could hang
	 * the Rx DMA unit.  Therefore, make sure the security engine is
	 * completely disabled prior to enabling the Rx unit.
	 */
	hw->mac.ops.disable_rx_buff(hw);

	// RNPM_WRITE_REG(hw, RNPM_RXCTRL, regval);

	hw->mac.ops.enable_rx_buff(hw);

	return 0;
}

/**
 *  rnpm_verify_fw_version_n10 - verify fw version for n10
 *  @hw: pointer to hardware structure
 *
 *  Verifies that installed the firmware version is 0.6 or higher
 *  for SFI devices. All n10 SFI devices should have version 0.6 or higher.
 *
 *  Returns RNPM_ERR_EEPROM_VERSION if the FW is not present or
 *  if the FW version is not supported.
 **/
static s32 rnpm_verify_fw_version_n10(struct rnpm_hw *hw)
{
	// s32 status = RNPM_ERR_EEPROM_VERSION;
	// u16 fw_offset, fw_ptp_cfg_offset;
	// u16 fw_version = 0;

	return 0;
}

/**
 *  rnpm_verify_lesm_fw_enabled_n10 - Checks LESM FW module state.
 *  @hw: pointer to hardware structure
 *
 *  Returns true if the LESM FW module is present and enabled. Otherwise
 *  returns false. Smart Speed must be disabled if LESM FW module is enabled.
 **/
bool rnpm_verify_lesm_fw_enabled_n10(struct rnpm_hw *hw)
{
	bool lesm_enabled = false;

	return lesm_enabled;
}

/**
 *  rnpm_read_eeprom_buffer_n10 - Read EEPROM word(s) using
 *  fastest available method
 *
 *  @hw: pointer to hardware structure
 *  @offset: offset of  word in EEPROM to read
 *  @words: number of words
 *  @data: word(s) read from the EEPROM
 *
 *  Retrieves 16 bit word(s) read from EEPROM
 **/
__maybe_unused static s32 rnpm_read_eeprom_buffer_n10(struct rnpm_hw *hw,
						      u16 offset, u16 words,
						      u16 *data)
{
	s32 ret_val = RNPM_ERR_CONFIG;

	return ret_val;
}

/**
 *  rnpm_read_eeprom_n10 - Read EEPROM word using
 *  fastest available method
 *
 *  @hw: pointer to hardware structure
 *  @offset: offset of  word in the EEPROM to read
 *  @data: word read from the EEPROM
 *
 *  Reads a 16 bit word from the EEPROM
 **/
__maybe_unused static s32 rnpm_read_eeprom_n10(struct rnpm_hw *hw, u16 offset,
					       u16 *data)
{
	s32 ret_val = RNPM_ERR_CONFIG;

	return ret_val;
}

/**
 * rnpm_reset_pipeline_n10 - perform pipeline reset
 *
 * @hw: pointer to hardware structure
 *
 * Reset pipeline by asserting Restart_AN together with LMS change to ensure
 * full pipeline reset.  Note - We must hold the SW/FW semaphore before writing
 * to AUTOC, so this function assumes the semaphore is held.
 **/
s32 rnpm_reset_pipeline_n10(struct rnpm_hw *hw)
{
	s32 ret_val;
	u32 i;

	/* Enable link if disabled in NVM */

	/* Write AUTOC register with toggled LMS[2] bit and Restart_AN */

	/* Wait for AN to leave state 0 */
	for (i = 0; i < 10; i++) {
		usleep_range(4000, 8000);
		break;
	}

	ret_val = 0;

	// reset_pipeline_out:
	/* Write AUTOC register with original LMS field and Restart_AN */

	return ret_val;
}

__maybe_unused static void upl_init(u8 __iomem *bar2)
{
	int data;
#define SOFT_COMMON11 (0x0007000 + 0xf2c)
#define SOFT_COMMON12 (0x0007000 + 0xf30)

	// config ulh pll
	data = ioread32((void *)(bar2 + SOFT_COMMON11));
	iowrite32(((0x3 << 29) | data),
		  (void *)(bar2 + SOFT_COMMON11)); // ulh pd is 1, bypass is 1
	data = ioread32((void *)(bar2 + SOFT_COMMON11));
	iowrite32(((0x1 << 31) | data),
		  (void *)(bar2 + SOFT_COMMON11)); // ulh reset is 1

	data = ioread32((void *)(bar2 + SOFT_COMMON12));
	iowrite32(((0x3 << 29) | data),
		  (void *)(bar2 + SOFT_COMMON12)); // ulh pd is 1, bypass is 1
	data = ioread32((void *)(bar2 + SOFT_COMMON12));
	iowrite32(((0x1 << 31) | data),
		  (void *)(bar2 + SOFT_COMMON12)); // ulh reset is 1
}

/**
 *  rnpm_reset_hw_n10 - Perform hardware reset
 *  @hw: pointer to hardware structure
 *
 *  Resets the hardware by resetting the transmit and receive units, masks
 *  and clears all interrupts, perform a PHY reset, and perform a link (MAC)
 *  reset.
 **/
static s32 rnpm_reset_hw_n10(struct rnpm_hw *hw)
{
	s32 status = 0;
	// struct rnpm_adapter *adapter = (struct rnpm_adapter *)hw->back;
	// int port = hw->num;

	/* Identify PHY and related function pointers */
	status = hw->phy.ops.init(hw);

	/* Setup SFP module if there is one present. */
	if (hw->phy.sfp_setup_needed) {
		status = hw->mac.ops.setup_sfp(hw);
		hw->phy.sfp_setup_needed = false;
	}

	/* Reset PHY */
	if (hw->phy.reset_disable == false && hw->phy.ops.reset != NULL)
		hw->phy.ops.reset(hw);

	/* Store the permanent mac address only once */
	if (!(hw->mac.mac_flags & RNPM_FLAGS_INIT_MAC_ADDRESS)) {
		rnpm_get_permtion_mac_addr(hw, hw->mac.perm_addr);
		memcpy(hw->mac.addr, hw->mac.perm_addr, ETH_ALEN);
	}

	hw->mac.num_rar_entries = RNPM_N10_RAR_ENTRIES;
	hw->mac.ops.init_rx_addrs(hw);

	return 0;
}

/**
 *  rnpm_start_hw_n10 - Prepare hardware for Tx/Rx
 *  @hw: pointer to hardware structure
 *
 *  Starts the hardware using the generic start_hw function
 *  and the generation start_hw function.
 *  Then performs revision-specific operations, if any.
 **/
static s32 rnpm_start_hw_n10(struct rnpm_hw *hw)
{
	s32 ret_val = 0;

	ret_val = rnpm_start_hw_generic(hw);
	if (ret_val != 0)
		goto out;

	ret_val = rnpm_start_hw_gen2(hw);
	if (ret_val != 0)
		goto out;

	// ETH Registers
	// wr32(hw, RNPM_ETH_ERR_MASK_VECTOR, ~ETH_IGNORE_ALL_ERR);
	// wr32(hw, RNPM_ETH_ERR_MASK_VECTOR, 0);
	wr32(hw, RNPM_ETH_ERR_MASK_VECTOR,
	     INNER_L4_BIT | PKT_LEN_ERR | HDR_LEN_ERR);
	wr32(hw, RNPM_ETH_BYPASS, 0);
	wr32(hw, RNPM_ETH_DEFAULT_RX_RING, 0);
	// DMA common Registers
	wr32(hw, RNPM_DMA_CONFIG, DMA_VEB_BYPASS);

	// enable-dma-axi
	wr32(hw, RNPM_DMA_AXI_EN, (RX_AXI_RW_EN | TX_AXI_RW_EN));

	if (ret_val == 0)
		ret_val = rnpm_verify_fw_version_n10(hw);
out:
	return ret_val;
}

/**
 *  rnpm_get_media_type_n10 - Get media type
 *  @hw: pointer to hardware structure
 *
 *  Returns the media type (fiber, copper, backplane)
 **/
static enum rnpm_media_type rnpm_get_media_type_n10(struct rnpm_hw *hw)
{
	enum rnpm_media_type media_type = rnpm_media_type_fiber;
	return media_type;
}

/**
 *  rnpm_get_supported_physical_layer_n10 - Returns physical layer type
 *  @hw: pointer to hardware structure
 *
 *  Determines physical layer capabilities of the current configuration.
 **/
static u32 rnpm_get_supported_physical_layer_n10(struct rnpm_hw *hw)
{
	u32 physical_layer = 0;

	return physical_layer;
}

static s32 rnpm_get_link_capabilities_n10(struct rnpm_hw *hw,
					  rnpm_link_speed *speed, bool *autoneg,
					  u32 *media_type)
{
	*autoneg = false;

	switch (hw->phy_type) {
	case PHY_TYPE_SGMII:
		// *media_type = rnpm_media_type_copper;
		*autoneg = true;
		break;
	default:
		*media_type = rnpm_media_type_fiber;
		*autoneg = false;

		break;
	}

	return 0;
}

static struct rnpm_phy_operations phy_ops_n10 = {
	.identify = &rnpm_identify_phy_n10,
	.identify_sfp = &rnpm_identify_sfp_module_n10,
	.init = &rnpm_init_phy_ops_n10,
	.reset = &rnpm_reset_phy_generic,
	.read_reg = &rnpm_read_phy_reg_generic,
	.write_reg = &rnpm_write_phy_reg_generic,
	.setup_link = &rnpm_setup_phy_link_generic,
	.setup_link_speed = &rnpm_setup_phy_link_speed_generic,
	.read_i2c_byte = &rnpm_read_i2c_byte_generic,
	.write_i2c_byte = &rnpm_write_i2c_byte_generic,
	.read_i2c_sff8472 = &rnpm_read_i2c_sff8472_generic,
	.read_i2c_eeprom = &rnpm_read_i2c_eeprom_generic,
	.write_i2c_eeprom = &rnpm_write_i2c_eeprom_generic,
	.check_overtemp = &rnpm_tn_check_overtemp,
};

static struct rnpm_mac_operations mac_ops_n10 = {
	.init_hw = &rnpm_init_hw_generic,
	.reset_hw = &rnpm_reset_hw_n10,
	.start_hw = &rnpm_start_hw_n10,
	.clear_hw_cntrs = &rnpm_clear_hw_cntrs_generic,
	.get_media_type = &rnpm_get_media_type_n10,
	.get_supported_physical_layer = &rnpm_get_supported_physical_layer_n10,
	.enable_rx_dma = &rnpm_enable_rx_dma_n10,
	.disable_rx_buff = &rnpm_disable_rx_buff_generic,
	.enable_rx_buff = &rnpm_enable_rx_buff_generic,
	.get_mac_addr = &rnpm_get_mac_addr_generic,
	.get_device_caps = &rnpm_get_device_caps_generic,
	.setup_link = &rnpm_setup_phy_link_speed_generic,
	.get_wwn_prefix = &rnpm_get_wwn_prefix_generic,
	.stop_adapter = &rnpm_stop_adapter_generic,
	//.set_rxpba		        = &rnpm_set_rxpba_generic,
	.check_link = &rnpm_check_mac_link_generic,
	.get_link_capabilities = &rnpm_get_link_capabilities_n10,
	.led_on = &rnpm_led_on_generic,
	.led_off = &rnpm_led_off_generic,
	.blink_led_start = &rnpm_blink_led_start_generic,
	.blink_led_stop = &rnpm_blink_led_stop_generic,
	//.get_bus_info           = &rnpm_get_bus_info_generic,
	.set_rar = &rnpm_set_rar_generic,
	.set_rar_mac = &rnpm_set_rar_mac,
	.clear_rar = &rnpm_clear_rar_generic,
	.clear_rar_mac = &rnpm_clear_rar_mac,
	.set_vmdq = &rnpm_set_vmdq_generic,
	//.set_vmdq_san_mac	= &rnpm_set_vmdq_san_mac_generic,
	.clear_vmdq = &rnpm_clear_vmdq_generic,
	.init_rx_addrs = &rnpm_init_rx_addrs_generic,
	//.update_mc_addr_list    = &rnpm_update_mc_addr_list_generic,
	.update_mc_addr_list = &rnpm_update_mutiport_mc_addr_list_generic,
	.enable_mc = &rnpm_enable_mc_generic,
	.disable_mc = &rnpm_disable_mc_generic,
	.clear_vfta = &rnpm_clear_vfta_generic,
	.set_vfta = &rnpm_set_vfta_generic,
	.set_vfta_mac = &rnpm_set_vfta_mac_generic,
	.fc_enable = &rnpm_fc_enable_generic,
	.setup_fc = &rnpm_setup_fc,
	.set_fw_drv_ver = &rnpm_set_fw_drv_ver_generic,
	.init_uta_tables = &rnpm_init_uta_tables_generic,
	.setup_sfp = &rnpm_setup_sfp_modules_n10,
	.get_thermal_sensor_data = &rnpm_get_thermal_sensor_data_generic,
	.init_thermal_sensor_thresh = &rnpm_init_thermal_sensor_thresh_generic,
	.mng_fw_enabled = &rnpm_mng_enabled,
};

//==========   n10 ===============
struct rnpm_info rnpm_n10_info = {
	.one_pf_with_two_dma = false,
	.total_queue_pair_cnts = RNPM_N10_MAX_TX_QUEUES,
	.queue_depth = RNPM_DEFAULT_TXD,
	.total_msix_table = 64,
	.coalesce.tx_work_limit = RNPM_DEFAULT_TX_WORK,
	.coalesce.rx_usecs = RNPM_DEFAULT_LOW_RX_USEC,
	.coalesce.rx_frames = 1,
	//.coalesce.rx_frames = RNPM_RX_PKT_POLL_BUDGET,
	.coalesce.tx_usecs = 100,
	.coalesce.tx_frames = RNPM_TX_PKT_POLL_BUDGET,
	.total_layer2_count = RNPM_MAX_LAYER2_FILTERS,
#if NET_FEATURE_TCAM
	.total_tuple5_count = RNPM_MAX_TCAM_FILTERS,
#else
	.total_tuple5_count = RNPM_MAX_TUPLE5_FILTERS,
#endif
#ifdef RNPM_FIX_MAC_PADDING
	.mac_padding = true,
#endif
	.adapter_cnt = 4,
	.rss_type = rnpm_rss_n10,
	.get_invariants = &rnpm_get_invariants_n10,
	.mac_ops = &mac_ops_n10,
	.phy_ops = &phy_ops_n10,
	.mbx_ops = &mbx_ops_generic,
	.pcs_ops = &pcs_ops_generic,
};

//==========   n10 ===============
struct rnpm_info rnpm_n400_4x1G_info = {
	.one_pf_with_two_dma = false,
	.total_queue_pair_cnts = RNPM_N400_MAX_TX_QUEUES,
	.queue_depth = RNPM_N400_DEFAULT_TXD,
	.total_msix_table = 17,
	.coalesce.tx_work_limit = RNPM_DEFAULT_TX_WORK,
	//.coalesce.rx_usecs = 1200,
	.coalesce.rx_usecs = RNPM_DEFAULT_LOW_RX_USEC,
	.coalesce.rx_frames = 1,
	.coalesce.tx_usecs = 100,
	.coalesce.tx_frames = RNPM_TX_PKT_POLL_BUDGET,
	.total_layer2_count = RNPM_MAX_LAYER2_FILTERS,
#if NET_FEATURE_TCAM
	.total_tuple5_count = RNPM_MAX_TCAM_FILTERS,
#else
	.total_tuple5_count = RNPM_MAX_TUPLE5_FILTERS,
#endif
#ifdef RNPM_FIX_MAC_PADDING
	.mac_padding = false,
#endif
	.adapter_cnt = 2,
	.rss_type = rnpm_rss_n10,
	.get_invariants = &rnpm_get_invariants_n400,
	.mac_ops = &mac_ops_n10,
	.phy_ops = &phy_ops_n10,
	.mbx_ops = &mbx_ops_generic,
	.pcs_ops = &pcs_ops_generic,
};
