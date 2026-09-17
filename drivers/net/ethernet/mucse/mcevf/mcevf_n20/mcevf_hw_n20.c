// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2020 - 2026 Mucse Corporation. */

#include "../mcevf.h"
#include "../mcevf_fdir.h"
#include "mcevf_hw_n20.h"
#include "../mcevf_mbx.h"
#include "../mcevf_virtchnl.h"

static int n20_reset_hw(struct mcevf_hw *hw)
{
	int err;

	mcevf_mbx_init_configure(&hw->pf_mbx);
	err = hw->virtchnl.ops->send_reset_msg(hw);
	if (err)
		return err;
	//get qos setup
	err = hw->virtchnl.ops->get_qos_info(hw);
	if (err)
		return err;
	return 0;
}

static int n20_set_unicast_addr(struct mcevf_hw *hw, u8 *addr)
{
	s32 err = 0;

	err = hw->virtchnl.ops->set_unicast_addr(hw, addr);
	if (err)
		return err;
	return err;
}

static void n20_init_hw(struct mcevf_hw *hw)
{
	struct mcevf_pf *pf = container_of(hw, struct mcevf_pf, hw);
	struct mcevf_dcb *dcb = pf->dcb;

	memcpy(hw->mac.addr, hw->mac.perm_addr, ETH_ALEN);
	memcpy(hw->port_info->mac.perm_addr, hw->mac.addr, ETH_ALEN);

	hw->bcmc_addr_offset = N20_VEB_BCMC_ADDR_ENTRY_OFF;
	/* TODO: need modify base index */
	hw->uc_addr_offset = N20_VEB_VF_ADDR_ENTRY_OFF + VF_T4_INDEX(hw->vfnum);
	hw->ops->clear_mc_filter(hw);
	/* clear vport attr table */
	wr32(hw, N20_ETH_VPORT_ATTR_TABLE(_vfnum(hw->vfnum)), 0);
	/* clear hw ring stats */
	hw->ops->clear_hw_ring_stats(hw);
	/* setup pfc status */
	if (test_bit(MCEVF_PFC_EN, dcb->flags))
		hw->ops->set_q_to_pfc(hw, dcb);
	else
		hw->ops->clr_q_to_pfc(hw);
}

static int n20_get_vfnum(struct mcevf_hw *hw)
{
	int vfnum = -1;
	u32 val;

	if (hw->is_vf_isolated_enabled)
		val = rd32(hw, N20_VFNUM_ISOLATED);
	else
		val = rd32(hw, N20_VFNUM_NO_ISOLAT);
	hw->sriov = val;
	vfnum = val & 0xff;
	return vfnum;
}

static int n20_get_queues(struct mcevf_hw *hw)
{
	hw->queue_ring_base = N20_USE_FORCE_SETUP_RING_BASE;
	return 0;
}

static int n20_init_vport_hw_attr(struct mcevf_hw *hw, bool on)
{
	u32 val;

	/* config eth vport attr table by vfnum */
	val = rd32(hw, N20_ETH_VPORT_ATTR_TABLE(_vfnum(hw->vfnum)));
	on ? F_SET_VPORT_DEFAULT_RING(val, N20_USE_VPORT_ATTR_RING_BASE) :
	     F_SET_VPORT_DEFAULT_RING(val, 0);
	wr32(hw, N20_ETH_VPORT_ATTR_TABLE(_vfnum(hw->vfnum)), val);

	return 0;
}

static void n20_cfg_vec2tqirq(struct mcevf_hw *hw, u16 ring_id, u16 irq_id)
{
	u32 val;

	val = rd32(hw, _MSIX_F_(ring_id));
	val |= BIT(31);
	MODIFY_BITFIELD(val, irq_id, 11, 11);
	MODIFY_BITFIELD(val, _vfnum(hw->vfnum), 7, 24);
	wr32(hw, _MSIX_F_(ring_id), val);
}

static void n20_cfg_vec2rqirq(struct mcevf_hw *hw, u16 ring_id, u16 irq_id)
{
	u32 val;

	val = rd32(hw, _MSIX_F_(ring_id));
	val |= BIT(31);
	MODIFY_BITFIELD(val, irq_id, 11, 0);
	MODIFY_BITFIELD(val, _vfnum(hw->vfnum), 7, 24);
	wr32(hw, _MSIX_F_(ring_id), val);
}

static void n20_set_max_pktlen(struct mcevf_hw *hw, u32 mtu)
{
	u32 value = 0;
	u32 index = _vfnum(hw->vfnum);
	u32 max_len = mtu + 14 + (4 * 3); // mtu + mac_header + vlan_header

	MCEVF_SET_USED(index);
	value = rd32(hw, N20_ETH_VPORT_ATTR_TABLE(index));
	value &= ~(F_VPORT_DROP);
	value |= F_VPORT_LIMIT_LEN_EN;
	F_SET_VPORT_MAX_LEN(value, max_len); // clean max len
	wr32(hw, N20_ETH_VPORT_ATTR_TABLE(index), value);
}

/**
 * n20_set_rx_csumofld - Enable or disable the function of the rx checksum offload at the hw level
 * @hw:  ptr to the hw
 * @features: the feature set that the stack is suggesting
 */
static void n20_set_rx_csumofld(struct mcevf_hw *hw,
				netdev_features_t features)
{
}

/**
 * n20_set_vlan_strip - Enable or disable the function of the rx vlan offload at the hw level
 * @hw:  ptr to the hw
 * @features: feature flags indicating strip enabled/disabled
 */
static s32 n20_set_vlan_strip(struct mcevf_hw *hw,
			      netdev_features_t features)
{
	struct mcevf_pf *pf = container_of(hw, struct mcevf_pf, hw);
	u32 en = 0, strip_cnt = pf->vlan_strip_cnt;
	u32 value = 0, offset = 0;
	s32 i;

	if (strip_cnt < 0 || strip_cnt > N20_VLAN_MAX_STRIP_CNT) {
		dev_warn(mcevf_hw_to_dev(hw),
			 "vf:%d vlan strip count:%d exceed!(which range is >= 0 and <= %d), force setup to 1.\n",
			_vfnum(hw->vfnum), strip_cnt, N20_VLAN_MAX_STRIP_CNT);
		strip_cnt = 1;
		pf->vlan_strip_cnt = strip_cnt;
	}

#ifdef NETIF_F_HW_VLAN_CTAG_RX
	if (test_bit(MCEVF_FLAG_PF_SET_VLAN, pf->flags))
		en = 1;
	else if (features & NETIF_F_HW_VLAN_CTAG_RX ||
		 features & NETIF_F_HW_VLAN_STAG_RX)
		en = 1;
	else if (test_bit(MCEVF_FLAG_VF_SET_DVLAN, pf->flags))
		en = 1;

	pf->vlan_strip_cnt = 0;
	if (test_bit(MCEVF_FLAG_PF_SET_VLAN, pf->flags))
		pf->vlan_strip_cnt++;
	if (features & NETIF_F_HW_VLAN_CTAG_RX ||
	    features & NETIF_F_HW_VLAN_STAG_RX)
		pf->vlan_strip_cnt++;
	strip_cnt = pf->vlan_strip_cnt;
#else
	return 0;
#endif

	offset = 0;
	for (i = offset; i < hw->func_caps.common_cap.num_txq + offset;
	     i++) {
		value = rd32(hw, N20_RSS_ACT_CONFIG_MEM(i));
		F_SET_VLAN_STRIP_EN(value, en);
		F_SET_VLAN_STRIP_CNT(value, strip_cnt);
		F_SET_RETA_HASH_QUEUE_ID(value, 0);
		wr32(hw, N20_RSS_ACT_CONFIG_MEM(i), value);
	}
	return 0;
}

static s32 n20_set_vlan_vfta(struct mcevf_hw *hw, u32 vlan, u32 vind,
			     bool vlan_on)
{
	int err;

	err = hw->virtchnl.ops->set_vlan_vfta(hw, vlan, vind, vlan_on);
	return err;
}

/**
 * n20_set_rss_hash - Enable or disable the function of RSS at the hw level
 * @hw:  ptr to the hw
 * @features: the feature set that the stack is suggesting
 */
static void n20_set_rss_hash(struct mcevf_hw *hw,
			     netdev_features_t features)
{
	struct mcevf_pf *pf = container_of(hw, struct mcevf_pf, hw);
	u32 mrqc_id = hw->func_caps.common_cap.rss_key_size / 4;
	u32 offset = _vfnum(hw->vfnum);
	u32 val;

	val = rd32(hw, N20_RSS_HASH_ENTRY(mrqc_id, offset));
	MCEVF_SET_USED(offset);
	if (features & NETIF_F_RXHASH) {
		val |= F_RSS_HASH_EN;
		if (hw->rss_hfunc == ETH_RSS_HASH_TOP)
			val &= ~F_RSS_HASH_XOR_OR_TOP_EN;
		if (hw->rss_hfunc == ETH_RSS_HASH_XOR)
			val |= F_RSS_HASH_XOR_OR_TOP_EN;
		if (test_bit(MCEVF_FLAG_RSS_MODE_ORDER, pf->flags)) {
			val &= ~F_RSS_HASH_XOR_OR_TOP_EN;
			val |= F_RSS_HASH_ORDER_EN;
		}
	} else {
		val &= ~F_RSS_HASH_EN;
	}

	wr32(hw, N20_RSS_HASH_ENTRY(mrqc_id, offset), val);
}

/**
 * n20_set_rss_key - Set RSS key to hw
 * @hw:  ptr to the hw
 */
static void n20_set_rss_key(struct mcevf_hw *hw)
{
	u32 i = 0;
	u32 tmp_rss_key = 0;
	u32 entry_size = ((hw->func_caps.common_cap.rss_key_size) / 4);
	u32 offset = _vfnum(hw->vfnum);

	MCEVF_SET_USED(offset);
	for (i = 0; i < entry_size; i++) {
		tmp_rss_key = (hw->rss_key[(i * 4)]);
		tmp_rss_key |= (hw->rss_key[(i * 4) + 1] << 8);
		tmp_rss_key |= (hw->rss_key[(i * 4) + 2] << 16);
		tmp_rss_key |= (hw->rss_key[(i * 4) + 3] << 24);
		tmp_rss_key = htonl(tmp_rss_key);
		wr32(hw, N20_RSS_HASH_ENTRY(entry_size - i - 1, offset),
		     tmp_rss_key);
	}
}

/**
 * n20_set_rss_hash_type - Set the hash type that triggers RSS
 * @hw:  ptr to the hw
 */
static void n20_set_rss_hash_type(struct mcevf_hw *hw)
{
	struct mcevf_pf *pf = container_of(hw, struct mcevf_pf, hw);
	u32 mrqc_id = ((hw->func_caps.common_cap.rss_key_size) / 4);
	u32 offset = _vfnum(hw->vfnum), val;

	MCEVF_SET_USED(offset);

	val = rd32(hw, N20_RSS_HASH_ENTRY(mrqc_id, offset));
	MODIFY_BITFIELD(val, hw->rss_hash_type, 15, 0);

	val &= ~(F_IPV4_HASH_TEID_EN | F_IPV6_HASH_TEID_EN |
		 F_IPV6_HASH_SPI_EN | F_IPV4_HASH_SPI_EN | F_RSS_HASH_PTP_EN);

	if (test_bit(MCEVF_FLAG_RSS_MISC_TYPE_PTP, pf->flags))
		val |= F_RSS_HASH_PTP_EN;
	if (test_bit(MCEVF_FLAG_RSS_MISC_TYPE_IPV4_SPI, pf->flags))
		val |= F_IPV4_HASH_SPI_EN;
	if (test_bit(MCEVF_FLAG_RSS_MISC_TYPE_IPV6_SPI, pf->flags))
		val |= F_IPV6_HASH_SPI_EN;
	if (test_bit(MCEVF_FLAG_RSS_MISC_TYPE_IPV4_TEID, pf->flags))
		val |= F_IPV4_HASH_TEID_EN;
	if (test_bit(MCEVF_FLAG_RSS_MISC_TYPE_IPV6_TEID, pf->flags))
		val |= F_IPV6_HASH_TEID_EN;

	wr32(hw, N20_RSS_HASH_ENTRY(mrqc_id, offset), val);
}

/**
 * n20_set_rss_table - Set the hash indirect table at hw level
 * @hw:  ptr to the hw
 * @q_cnt: queue count
 */
static void n20_set_rss_table(struct mcevf_hw *hw, u16 q_cnt)
{
	struct mcevf_pf *pf = hw->back;
	u32 act_reta = 0, vft_reta = 0;
	u32 table_size, val;
	u16 i = 0, offset;

	table_size = hw->func_caps.common_cap.rss_table_size;
	if (!q_cnt)
		q_cnt = table_size;

	offset = 0;
	for (i = offset; i < table_size + offset; i++) {
		if (test_bit(MCEVF_FLAG_RSS_TBL_INITED, pf->flags)) {
			val = hw->rss_table[i - offset];
		} else {
			val = (i - offset) % q_cnt;
			hw->rss_table[i - offset] = val;
		}

		if (i % 2 == 0) {
			vft_reta = val & 0xffff;
		} else {
			vft_reta |= val << 16;
			wr32(hw, N20_RSS_VFT_CONFIG_MEM(i / 2), vft_reta);
		}
		act_reta = rd32(hw, N20_RSS_ACT_CONFIG_MEM(i));
		act_reta |= F_RSS_RETA_QUEUE_EN;
		wr32(hw, N20_RSS_ACT_CONFIG_MEM(i), act_reta);
	}
	set_bit(MCEVF_FLAG_RSS_TBL_INITED, pf->flags);
}

/**
 * n20_set_uc_filter - Enable or disable the uc filter at the hw level
 * @hw:  ptr to the hw
 * @enable: true or false
 */
static void n20_set_uc_filter(struct mcevf_hw *hw, bool enable)
{
}

/**
 * n20_add_uc_filter - Add addr for uc filter at the hw level
 * @hw:  ptr to the hw
 * @addr: mac addr for uc filter
 */
static int n20_add_uc_filter(struct mcevf_hw *hw, const u8 *addr)
{
	int err;

	err = hw->virtchnl.ops->set_add_uc_filter(hw, addr);
	return err;
}

/**
 * n20_del_uc_filter - Del addr for uc filter at the hw level
 * @hw:  ptr to the hw
 * @addr: mac addr for uc filter
 */
static int n20_del_uc_filter(struct mcevf_hw *hw, const u8 *addr)
{
	int err;

	err = hw->virtchnl.ops->set_del_uc_filter(hw, addr);
	return err;
}

/**
 * n20_set_mc_filter - Enable or disable the mc filter at the hw level
 * @hw:  ptr to the hw
 * @enable: true or false
 */
static void n20_set_mc_filter(struct mcevf_hw *hw, bool enable)
{
}

#define __MCEVF_MC_FILTER_PER_BANK (8)
static bool __is_mc_filter_bank1(int avail_id)
{
	return !!(avail_id >= __MCEVF_MC_FILTER_PER_BANK);
}

static bool __config_vf_mc_mac_to_bank(struct mcevf_hw *hw, int num,
				       int avail_id, bool en,
				       const u8 *mac_addr)
{
	u32 t_mac = 0, val = 0, idx = 0;

	if (num)
		avail_id -= __MCEVF_MC_FILTER_PER_BANK;

	if (avail_id % 2) {
		idx = (avail_id / 2) * 3 + 1;
		t_mac = (u32)(mac_addr[5]) | (((u32)(mac_addr[4])) << 8);
		// t_mac <<= 16;
		if (!en)
			t_mac = 0;
		val = rd32(hw, _ETH_VF_MC_F_(num, _vfnum(hw->vfnum), idx));
		MODIFY_BITFIELD(val, t_mac, 16, 16);
		wr32(hw, _ETH_VF_MC_F_(num, _vfnum(hw->vfnum), idx), val);
		t_mac = (u32)(mac_addr[0]) << 24 |
			(u32)(mac_addr[1]) << 16 |
			(u32)(mac_addr[2]) << 8 | (u32)(mac_addr[3]) << 0;
		if (!en)
			t_mac = 0;
		wr32(hw, _ETH_VF_MC_F_(num, _vfnum(hw->vfnum), idx + 1), t_mac);
	} else {
		idx = (avail_id / 2) * 3;
		t_mac = ((u32)(mac_addr[5]) | (((u32)(mac_addr[4])) << 8) |
			 (((u32)(mac_addr[3])) << 16) |
			 (((u32)(mac_addr[2])) << 24));
		if (!en)
			t_mac = 0;
		wr32(hw, _ETH_VF_MC_F_(num, _vfnum(hw->vfnum), idx), t_mac);
		val = rd32(hw, _ETH_VF_MC_F_(num, _vfnum(hw->vfnum), idx + 1));
		t_mac = ((u32)mac_addr[1] | ((u32)(mac_addr[0])) << 8);
		if (!en)
			t_mac = 0;
		MODIFY_BITFIELD(val, t_mac, 16, 0);
		wr32(hw, _ETH_VF_MC_F_(num, _vfnum(hw->vfnum), idx + 1), val);
	}
	return 0;
}

/**
 * n20_add_mc_filter - Add addr for mc filter at the hw level
 * @hw:  ptr to the hw
 * @mac_addr: mac addr for mc filter
 */
static void n20_add_mc_filter(struct mcevf_hw *hw, const u8 *mac_addr)
{
	int avail_id;
	u32 num = 0, id;

	for (id = 0; id < MCEVF_MAX_MC_WHITE_LISTS; id++) {
		if (hw->mc_info[id].en) {
			if (ether_addr_equal(hw->mc_info[id].addr,
					     mac_addr))
				break;
		}
	}

	/* mac addr exists, do nothing */
	if (id < MCEVF_MAX_MC_WHITE_LISTS)
		return;

	avail_id = find_first_zero_bit(hw->avail_mc,
				       MCEVF_MAX_MC_WHITE_LISTS);
	if (avail_id >= MCEVF_MAX_MC_WHITE_LISTS) {
		dev_err(mcevf_hw_to_dev(hw),
			"vf:%d the multicast nums exceeds maximum allowed:%d\n",
			_vfnum(hw->vfnum), MCEVF_MAX_MC_WHITE_LISTS);
		dev_err(mcevf_hw_to_dev(hw), "the multicast addr: %pM is invalid!\n", mac_addr);
		return;
	}

	if (__is_mc_filter_bank1(avail_id))
		num = 1;
	set_bit(avail_id, hw->avail_mc);
	hw->mc_info[avail_id].en = true;
	ether_addr_copy(hw->mc_info[avail_id].addr, mac_addr);
	__config_vf_mc_mac_to_bank(hw, num, avail_id, true, mac_addr);
}

/**
 * n20_del_mc_filter - Del addr for mc filter at the hw level
 * @hw:  ptr to the hw
 * @mac_addr: mac addr for mc filter
 */
static void n20_del_mc_filter(struct mcevf_hw *hw, const u8 *mac_addr)
{
	int id, num = 0;
	u8 addr[ETH_ALEN];

	for (id = 0; id < MCEVF_MAX_MC_WHITE_LISTS; id++) {
		if (hw->mc_info[id].en) {
			if (ether_addr_equal(hw->mc_info[id].addr,
					     mac_addr))
				break;
		}
	}
	if (id >= MCEVF_MAX_MC_WHITE_LISTS) {
		dev_err(mcevf_hw_to_dev(hw),
			"vf:%d not found mc addr:%02x:%02x:%02x:%02x:%02x:%02x, cannot delete it\n",
			_vfnum(hw->vfnum), mac_addr[0], mac_addr[1],
			mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
		return;
	}
	if (__is_mc_filter_bank1(id))
		num = 1;
	__config_vf_mc_mac_to_bank(hw, num, id, false, mac_addr);
	clear_bit(id, hw->avail_mc);
	hw->mc_info[id].en = false;
	memset(addr, 0, ETH_ALEN);
	ether_addr_copy(hw->mc_info[id].addr, addr);
}

static void n20_clear_mc_filter(struct mcevf_hw *hw)
{
	u32 i, vfnum = _vfnum(hw->vfnum);

	MCEVF_SET_USED(vfnum);
	for (i = 0; i < 0x40; i += 4) {
		wr32(hw, _ETH_VF_MC_F_(0, vfnum, i / 4), 0);
		wr32(hw, _ETH_VF_MC_F_(1, vfnum, i / 4), 0);
	}
}

/**
 * n20_set_mc_promisc - Enable or disable the mc promisc at the hw level
 * @hw:  ptr to the hw
 * @enable: true or false
 */
static int n20_set_mc_promisc(struct mcevf_hw *hw, bool enable)
{
	u32 index = _vfnum(hw->vfnum);
	u32 val = rd32(hw, N20_ETH_VPORT_ATTR_TABLE(index));

	MCEVF_SET_USED(index);
	if (enable)
		val |= F_VPORT_MC_PROMISC_EN;
	else
		val &= (~F_VPORT_MC_PROMISC_EN);

	wr32(hw, N20_ETH_VPORT_ATTR_TABLE(index), val);

	return 0;
}

/**
 * n20_set_uc_promisc - Enable or disable the rx promisc at the hw level
 * @hw:  ptr to the hw
 * @enable: true or false
 */
static int n20_set_uc_promisc(struct mcevf_hw *hw, bool enable)
{
	u32 index = _vfnum(hw->vfnum);
	u32 val = rd32(hw, N20_ETH_VPORT_ATTR_TABLE(index));

	MCEVF_SET_USED(index);
	if (enable)
		val |= F_VPORT_UC_PROMISC_EN | F_VPORT_TRUE_PROMISC_EN;
	else
		val &= ~(F_VPORT_UC_PROMISC_EN | F_VPORT_TRUE_PROMISC_EN);

	wr32(hw, N20_ETH_VPORT_ATTR_TABLE(index), val);

	return 0;
}

static int n20_set_vlan_promisc(struct mcevf_hw *hw, bool enable)
{
	u32 index = _vfnum(hw->vfnum);
	u32 val = rd32(hw, N20_ETH_VPORT_ATTR_TABLE(index));

	if (enable)
		val |= F_VPORT_VLAN_PROMISC_EN;
	else
		val &= (~F_VPORT_VLAN_PROMISC_EN);

	MCEVF_SET_USED(index);
	wr32(hw, N20_ETH_VPORT_ATTR_TABLE(index), val);

	return 0;
}

static int n20_set_pf_promisc_mode(struct mcevf_hw *hw, u32 flags)
{
	int err;

	err = hw->virtchnl.ops->set_notify_promisc_mode(hw, flags);
	return err;
}

/**
 * n20_set_vlan_filter - Enable or disable vlan filter at the hw level
 * @hw:  ptr to the hw
 * @features: the feature set that the stack is suggesting
 */
static void n20_set_vlan_filter(struct mcevf_hw *hw,
				netdev_features_t features)
{
}

/**
 * n20_add_vlan_filter - Add vlan id  for vlan filter at the hw level
 * @hw:  ptr to the hw
 * @vid: vlan id for filter
 */
static void n20_add_vlan_filter(struct mcevf_hw *hw, u16 vid)
{
}

/**
 * n20_del_vlan_filter - Del vlan id  for vlan filter at the hw level
 * @hw:  ptr to the hw
 * @vid: vlan id for filter
 */
static void n20_del_vlan_filter(struct mcevf_hw *hw, u16 vid)
{
}

/**
 * n20_add_ntuple_filter - add ntuple rule to hw
 * @hw:  ptr to the hw
 * @rule: ntuple-t rule
 */
static void n20_add_ntuple_filter(struct mcevf_hw *hw,
				  struct mcevf_fdir_fltr *rule)
{
}

static void n20_del_ntuple_filter(struct mcevf_hw *hw,
				  struct mcevf_fdir_fltr *rule)
{
}

static void n20_enable_txrxring_irq(struct mcevf_ring *ring)
{
	u32 status = 0;

	if (!ring)
		return;
	CLR_BIT(F_TX_INT_MASK_EN_BIT, status);
	CLR_BIT(F_RX_INT_MASK_EN_BIT, status);
	SET_BIT(F_TX_INT_MASK_MS_BIT, status);
	SET_BIT(F_RX_INT_MASK_MS_BIT, status);
	ring_wr32(ring, N20_DMA_REG_INT_MASK, status);
}

static void n20_disable_txrxring_irq(struct mcevf_ring *ring)
{
	u32 status = 0;

	if (!ring)
		return;

	status = 0;
	SET_BIT(F_TX_INT_MASK_EN_BIT, status);
	SET_BIT(F_TX_INT_MASK_MS_BIT, status);
	SET_BIT(F_RX_INT_MASK_EN_BIT, status);
	SET_BIT(F_RX_INT_MASK_MS_BIT, status);
	ring_wr32(ring, N20_DMA_REG_INT_MASK, status);
}

static void n20_start_txring(struct mcevf_ring *tx_ring)
{
	if (!tx_ring)
		return;

	/* enable queue */
	ring_wr32(tx_ring, N20_DMA_REG_TX_START,
		  F_TX_START_FLR_EN | F_TX_START_EN);

	ring_wr32(tx_ring, N20_DMA_REG_TX_DESC_LEN, tx_ring->count);
	ring_wr32(tx_ring, N20_DMA_REG_TX_DESC_TAIL, tx_ring->next_to_use);
}

static void n20_stop_txring(struct mcevf_ring *tx_ring)
{
	u32 head = 0, tail = 0;
	u32 try_cnt = 10;

	if (!tx_ring)
		return;

	while (try_cnt--) {
		head = ring_rd32(tx_ring, N20_DMA_REG_TX_DESC_HEAD);
		tail = ring_rd32(tx_ring, N20_DMA_REG_TX_DESC_TAIL);
		if (head == tail)
			break;
		usleep_range(10000, 20000);
	}

	if (try_cnt == 0)
		dev_err(tx_ring->dev,
			"10 wait tx-%u done timeout head-%u tail-%u\n",
			tx_ring->q_index, head, tail);

	/* disable queue */
	ring_wr32(tx_ring, N20_DMA_REG_TX_START, F_TX_START_FLR_EN);

	ring_wr32(tx_ring, N20_DMA_REG_TX_DESC_LEN, tx_ring->count);
	ring_wr32(tx_ring, N20_DMA_REG_TX_DESC_TAIL, 0);
}

static void n20_set_txring_ctx(struct mcevf_ring *tx_ring,
			       struct mcevf_hw *hw)
{
	struct mcevf_vsi *vsi = tx_ring->vsi;

	if (!tx_ring || !vsi)
		return;

	tx_ring->ring_addr = hw->eth_bar_base +
			     _RING_F_(tx_ring->q_index + hw->queue_ring_base);
	tx_ring->tail = tx_ring->ring_addr + N20_DMA_REG_TX_DESC_TAIL;
	tx_ring->next_to_use =
		ring_rd32(tx_ring, N20_DMA_REG_TX_DESC_HEAD);
	tx_ring->next_to_clean = tx_ring->next_to_use;
	if (tx_ring->next_to_use >= tx_ring->count)
		return;

	/* disable queue */
	ring_wr32(tx_ring, N20_DMA_REG_TX_START, F_TX_START_FLR_EN);

	ring_wr32(tx_ring, N20_DMA_REG_TX_DESC_BASE_ADDR_LO,
		  (u32)tx_ring->dma);

	ring_wr32(tx_ring, N20_DMA_REG_TX_DESC_BASE_ADDR_HI,
		  (u32)((tx_ring->dma) >> 32));

	ring_wr32(tx_ring, N20_DMA_REG_TX_DESC_LEN, tx_ring->count);

	ring_wr32(tx_ring, N20_DMA_REG_TX_DESC_FETCH_CTRL,
		  (56 << 0) | (8 << 16));

	ring_wr32(tx_ring, N20_DMA_REG_TX_INT_DELAY_TIMER,
		  tx_ring->q_vector->tx.dim_params.usecs * hw->axi_mhz);

	ring_wr32(tx_ring, N20_DMA_REG_TX_INT_DELAY_PKTCNT,
		  tx_ring->q_vector->tx.dim_params.frames);

	ring_wr32(tx_ring, N20_DMA_REG_TX_FLOW_CTRL_TH, 0);

	ring_wr32(tx_ring, N20_DMA_REG_TX_FLOW_CTRL_TM, 0);
}

/* setup tx ring interrupt delay time and frames */
static void n20_set_txring_intr_coal(struct mcevf_ring *tx_ring)
{
	struct mcevf_hw *hw = &tx_ring->vsi->back->hw;
	struct mcevf_ring_container *tx = NULL;

	if (!tx_ring)
		return;

	tx = &tx_ring->q_vector->tx;
	if (!tx)
		return;
	if (tx->dim_params.usecs != tx->dim_params.last_usecs)
		ring_wr32(tx_ring, N20_DMA_REG_TX_INT_DELAY_TIMER,
			  tx->dim_params.usecs * hw->axi_mhz);
	if (tx->dim_params.frames != tx->dim_params.last_frames)
		ring_wr32(tx_ring, N20_DMA_REG_TX_INT_DELAY_PKTCNT,
			  tx->dim_params.frames);
	tx->dim_params.last_frames = tx->dim_params.frames;
	tx->dim_params.last_usecs = tx->dim_params.usecs;
}

static int n20_cfg_txring_bw_lmt(struct mcevf_ring *tx_ring, u32 maxrate)
{
	struct mcevf_hw *hw = &tx_ring->vsi->back->hw;
	u32 th = (maxrate * 1000) >> 3;
	u32 tm = 1000 * hw->axi_mhz;

	ring_wr32(tx_ring, N20_DMA_REG_TX_FLOW_CTRL_TH, th);
	ring_wr32(tx_ring, N20_DMA_REG_TX_FLOW_CTRL_TM, tm);

	return 0;
}

static int n20_set_txring_trig_intr(struct mcevf_ring *tx_ring)
{
	ring_wr32(tx_ring, N20_DMA_REG_INT_TRIG,
		  _F_N20_DMA_INT_CLR_TRIG_TX);
	ring_wr32(tx_ring, N20_DMA_REG_INT_TRIG,
		  _F_N20_DMA_INT_SET_TRIG_TX);
	return 0;
}

static u64 n20_get_hw_ring_stats(struct mcevf_ring *ring,
				 enum mcevf_hw_ring_stats_type type)
{
	u64 val_hi = 0, val_lo = 0;

	if (!ring || !ring->ring_addr)
		return 0;

	switch (type) {
	case MCEVF_HW_R_STATS_RX_BYTES:
		val_lo = ring_rd32(ring, N20_DMA_REG_RX_BYTES_LO);
		val_hi = ring_rd32(ring, N20_DMA_REG_RX_BYTES_HI);
		break;
	case MCEVF_HW_R_STATS_RX_UNICAST:
		val_lo = ring_rd32(ring, N20_DMA_REG_RX_UNICAST_LO);
		val_hi = ring_rd32(ring, N20_DMA_REG_RX_UNICAST_HI);
		break;
	case MCEVF_HW_R_STATS_RX_MULTICAST:
		val_lo = ring_rd32(ring, N20_DMA_REG_RX_MULTICAST_LO);
		val_hi = ring_rd32(ring, N20_DMA_REG_RX_MULTICAST_HI);
		break;
	case MCEVF_HW_R_STATS_RX_BROADCAST:
		val_lo = ring_rd32(ring, N20_DMA_REG_RX_BROADCAST_LO);
		val_hi = ring_rd32(ring, N20_DMA_REG_RX_BROADCAST_HI);
		break;
	case MCEVF_HW_R_STATS_RX_MISS_DROP:
		val_lo = ring_rd32(ring, N20_DMA_REG_RX_MISS_DROP);
		val_hi = 0;
		break;
	case MCEVF_HW_R_STATS_TX_BYTES:
		val_lo = ring_rd32(ring, N20_DMA_REG_TX_BYTES_LO);
		val_hi = ring_rd32(ring, N20_DMA_REG_TX_BYTES_HI);
		break;
	case MCEVF_HW_R_STATS_TX_UNICAST:
		val_lo = ring_rd32(ring, N20_DMA_REG_TX_UNICAST_LO);
		val_hi = ring_rd32(ring, N20_DMA_REG_TX_UNICAST_HI);
		break;
	case MCEVF_HW_R_STATS_TX_MULTICAST:
		val_lo = ring_rd32(ring, N20_DMA_REG_TX_MULTICAST_LO);
		val_hi = ring_rd32(ring, N20_DMA_REG_TX_MULTICAST_HI);
		break;
	case MCEVF_HW_R_STATS_TX_BROADCAST:
		val_lo = ring_rd32(ring, N20_DMA_REG_TX_BROADCAST_LO);
		val_hi = ring_rd32(ring, N20_DMA_REG_TX_BROADCAST_HI);
		break;
	default:
		break;
	}

	return (val_lo + (val_hi << 32));
}

static int n20_clear_hw_ring_stats(struct mcevf_hw *hw)
{
	int i = 0, q_id;

	for (i = 0; i < hw->ring_max_cnt; i++) {
		q_id = hw->queue_ring_base + i;
		/* turn on read clean switch */
		wr32(hw, N20_DMA_REG_READ_CLEAD + q_id * 0x100, 1);
		rd32(hw, N20_DMA_REG_RX_MISS_DROP + q_id * 0x100);
		rd32(hw, N20_DMA_REG_RX_BYTES_LO + q_id * 0x100);
		rd32(hw, N20_DMA_REG_RX_BYTES_HI + q_id * 0x100);
		rd32(hw, N20_DMA_REG_RX_UNICAST_LO + q_id * 0x100);
		rd32(hw, N20_DMA_REG_RX_UNICAST_HI + q_id * 0x100);
		rd32(hw, N20_DMA_REG_RX_MULTICAST_LO + q_id * 0x100);
		rd32(hw, N20_DMA_REG_RX_MULTICAST_HI + q_id * 0x100);
		rd32(hw, N20_DMA_REG_RX_BROADCAST_LO + q_id * 0x100);
		rd32(hw, N20_DMA_REG_RX_BROADCAST_HI + q_id * 0x100);
		rd32(hw, N20_DMA_REG_TX_BYTES_LO + q_id * 0x100);
		rd32(hw, N20_DMA_REG_TX_BYTES_HI + q_id * 0x100);
		rd32(hw, N20_DMA_REG_TX_UNICAST_LO + q_id * 0x100);
		rd32(hw, N20_DMA_REG_TX_UNICAST_HI + q_id * 0x100);
		rd32(hw, N20_DMA_REG_TX_MULTICAST_LO + q_id * 0x100);
		rd32(hw, N20_DMA_REG_TX_MULTICAST_HI + q_id * 0x100);
		rd32(hw, N20_DMA_REG_TX_BROADCAST_LO + q_id * 0x100);
		rd32(hw, N20_DMA_REG_TX_BROADCAST_HI + q_id * 0x100);
		/* turn off read clean switch */
		wr32(hw, N20_DMA_REG_READ_CLEAD + q_id * 0x100, 0);
	}

	return 0;
}

static void n20_set_tun_select_inner(struct mcevf_hw *hw, bool inner)
{
	int vfid = _vfnum(hw->vfnum);
	u32 val = 0;

	val = rd32(hw, N20_ETH_VPORT_ATTR_TABLE(vfid));
	if (inner)
		val |= F_VPORT_TUN_SELECT_INNER;
	else
		val &= (~F_VPORT_TUN_SELECT_INNER);
	val |= F_VPORT_TUN_SELECT_INNER_OUTER_EN;
	wr32(hw, N20_ETH_VPORT_ATTR_TABLE(vfid), val);
}

static void n20_set_q_to_pfc(struct mcevf_hw *hw,
			     struct mcevf_dcb *dcb)
{
	struct mcevf_tc_cfg *tccfg = &dcb->cur_tccfg;
	u32 val = 0;
	u16 j = 0;
	u8 i = 0;

	/* setup pfc to queue map */
	/* now only no tc */
	for (i = 0; i < MCE_MAX_PRIORITY; i++) {
		u16 base = tccfg->pfc_txq_base[0][i];
		u16 qcnt = tccfg->pfc_txq_count[0][i];

		for (j = 0; j < qcnt; j++) {
			if (base + j > hw->ring_max_cnt)
				break;
			val = rd32(hw, N20_DMA_REG_TX_PRIO_LVL + (base + j) * 0x100);
			MODIFY_BITFIELD(val, 0, 8, 0);
			val |= F_RING_PFC_EN;
			val |= (1 << i);
			wr32(hw, N20_DMA_REG_TX_PRIO_LVL + (base + j) * 0x100, val);
		}
	}
}

static void n20_clr_q_to_pfc(struct mcevf_hw *hw)
{
	u16 q_id = 0;
	u32 val = 0;

	for (q_id = 0; q_id < hw->ring_max_cnt; q_id++) {
		val = rd32(hw, N20_DMA_REG_TX_PRIO_LVL + q_id * 0x100);
		val &= ~F_RING_PFC_EN;
		MODIFY_BITFIELD(val, 0, 8, 0);
		wr32(hw, N20_DMA_REG_TX_PRIO_LVL + q_id * 0x100, val);
	}
}

static void n20_start_rxring(struct mcevf_ring *rx_ring)
{
	if (!rx_ring)
		return;

	/* enable queue */
	ring_wr32(rx_ring, N20_DMA_REG_RX_START,
		  F_RX_START_FLR_EN | F_RX_START_EN);

	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_LEN, rx_ring->count);
	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_TAIL, rx_ring->next_to_use);
}

static void n20_stop_rxring(struct mcevf_ring *rx_ring)
{
	if (!rx_ring)
		return;

	// disable rxring
	ring_wr32(rx_ring, N20_DMA_REG_RX_START, F_RX_START_FLR_EN);

	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_LEN, 0);
	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_TAIL, 0);
}

static void n20_set_rxring_ctx(struct mcevf_ring *rx_ring,
			       struct mcevf_hw *hw)
{
	struct mcevf_vsi *vsi = rx_ring->vsi;

	if (!rx_ring || !vsi)
		return;

	rx_ring->ring_addr = hw->eth_bar_base +
			     _RING_F_(rx_ring->q_index + hw->queue_ring_base);
	rx_ring->tail = rx_ring->ring_addr + N20_DMA_REG_RX_DESC_TAIL;
	rx_ring->next_to_use =
		ring_rd32(rx_ring, N20_DMA_REG_RX_DESC_HEAD);
	rx_ring->next_to_clean = rx_ring->next_to_use;

	if (rx_ring->next_to_use >= rx_ring->count)
		return;

	// disable queue
	ring_wr32(rx_ring, N20_DMA_REG_RX_START, F_RX_START_FLR_EN);

	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_BASE_ADDR_LO,
		  (u32)rx_ring->dma);

	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_BASE_ADDR_HI,
		  (u32)((rx_ring->dma) >> 32));

	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_LEN, rx_ring->count);

	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_FETCH_CTRL,
		  (48 << 0) | (16 << 16));

	ring_wr32(rx_ring, N20_DMA_REG_RX_INT_DELAY_TIMER,
		  rx_ring->q_vector->rx.dim_params.usecs * hw->axi_mhz);

	ring_wr32(rx_ring, N20_DMA_REG_RX_INT_DELAY_PKTCNT,
		  rx_ring->q_vector->rx.dim_params.frames);

	ring_wr32(rx_ring, N20_DMA_REG_RX_DESC_TIMEOUT_TH,
		  N20_VAL_RX_TIMEOUT * hw->axi_mhz);

	ring_wr32(rx_ring, N20_DMA_REG_RX_SCATTER_LENGTH,
		  DIV_ROUND_UP(rx_ring->rx_buf_len, 64));
}

static void n20_set_rxring_intr_coal(struct mcevf_ring *rx_ring)
{
	struct mcevf_hw *hw = &rx_ring->vsi->back->hw;
	struct mcevf_ring_container *rx = NULL;

	if (!rx_ring)
		return;

	rx = &rx_ring->q_vector->rx;
	if (!rx)
		return;
	if (rx->dim_params.usecs != rx->dim_params.last_usecs)
		ring_wr32(rx_ring, N20_DMA_REG_RX_INT_DELAY_TIMER,
			  rx->dim_params.usecs * hw->axi_mhz);
	if (rx->dim_params.frames != rx->dim_params.last_frames)
		ring_wr32(rx_ring, N20_DMA_REG_RX_INT_DELAY_PKTCNT,
			  rx->dim_params.frames);
	rx->dim_params.last_frames = rx->dim_params.frames;
	rx->dim_params.last_usecs = rx->dim_params.usecs;
}

static void n20_set_txring_hw_dim(struct mcevf_ring *tx_ring, bool enable)
{
	u32 reg = 0;

	if (!enable) {
		reg = ring_rd32(tx_ring, N20_DMA_REG_TX_INT_FRAMES);
		MODIFY_BITFIELD(reg, 0, 1, 31);
		ring_wr32(tx_ring, N20_DMA_REG_TX_INT_FRAMES, reg);
		return;
	}

	ring_wr32(tx_ring, N20_DMA_REG_TX_PKT_RATE_LOW, N20_IRQ_MIN_200K);
	ring_wr32(tx_ring, N20_DMA_REG_TX_PKT_RATE_HIGH, N20_IRQ_MAX_200K);
#ifdef STEP_DIM
	reg = ring_rd32(tx_ring, N20_DMA_REG_TX_INT_FRAMES);
	MODIFY_BITFIELD(reg, 1, 1, 31);
	MODIFY_BITFIELD(reg, 1, 1, 30);
	MODIFY_BITFIELD(reg, 5, 8, 20);
	ring_wr32(tx_ring, N20_DMA_REG_TX_INT_FRAMES, reg);
#else
	reg = ring_rd32(tx_ring, N20_DMA_REG_TX_INT_FRAMES);
	MODIFY_BITFIELD(reg, 1, 1, 31);
	MODIFY_BITFIELD(reg, 5, 4, 0);
	MODIFY_BITFIELD(reg, 5, 4, 4);
	MODIFY_BITFIELD(reg, 5, 4, 8);
	MODIFY_BITFIELD(reg, 6, 4, 12);
	MODIFY_BITFIELD(reg, 7, 4, 16);
	ring_wr32(tx_ring, N20_DMA_REG_TX_INT_FRAMES, reg);

	reg = ring_rd32(tx_ring, N20_DMA_REG_TX_INT_USECS);
	MODIFY_BITFIELD(reg, 6, 4, 0);
	MODIFY_BITFIELD(reg, 5, 4, 4);
	MODIFY_BITFIELD(reg, 4, 4, 8);
	MODIFY_BITFIELD(reg, 3, 4, 12);
	MODIFY_BITFIELD(reg, 2, 4, 16);
	ring_wr32(tx_ring, N20_DMA_REG_TX_INT_USECS, reg);
#endif
}

static void n20_set_rxring_hw_dim(struct mcevf_ring *rx_ring, bool enable)
{
	u32 reg = 0;

	if (!enable) {
		reg = ring_rd32(rx_ring, N20_DMA_REG_RX_INT_FRAMES);
		MODIFY_BITFIELD(reg, 0, 1, 31);
		ring_wr32(rx_ring, N20_DMA_REG_RX_INT_FRAMES, reg);
		return;
	}

	ring_wr32(rx_ring, N20_DMA_REG_RX_PKT_RATE_LOW, N20_IRQ_MIN_200K);
	ring_wr32(rx_ring, N20_DMA_REG_RX_PKT_RATE_HIGH, N20_IRQ_MAX_200K);
#ifdef STEP_DIM
	reg = ring_rd32(rx_ring, N20_DMA_REG_RX_INT_FRAMES);
	MODIFY_BITFIELD(reg, 1, 1, 31);
	MODIFY_BITFIELD(reg, 1, 1, 30);
	MODIFY_BITFIELD(reg, 5, 8, 20);
	ring_wr32(rx_ring, N20_DMA_REG_RX_INT_FRAMES, reg);
#else
	reg = ring_rd32(rx_ring, N20_DMA_REG_RX_INT_FRAMES);
	MODIFY_BITFIELD(reg, 1, 1, 31);
	/* 0x */
	MODIFY_BITFIELD(reg, 6, 4, 0);
	MODIFY_BITFIELD(reg, 6, 4, 4);
	MODIFY_BITFIELD(reg, 6, 4, 8);
	MODIFY_BITFIELD(reg, 7, 4, 12);
	MODIFY_BITFIELD(reg, 8, 4, 16);
	ring_wr32(rx_ring, N20_DMA_REG_RX_INT_FRAMES, reg);

	reg = ring_rd32(rx_ring, N20_DMA_REG_RX_INT_USECS);

	MODIFY_BITFIELD(reg, 6, 4, 0);
	MODIFY_BITFIELD(reg, 5, 4, 4);
	MODIFY_BITFIELD(reg, 4, 4, 8);
	MODIFY_BITFIELD(reg, 3, 4, 12);
	MODIFY_BITFIELD(reg, 1, 4, 16);

	ring_wr32(rx_ring, N20_DMA_REG_RX_INT_USECS, reg);
#endif
}

struct mcevf_operations n20_ops = {
	.reset_hw = n20_reset_hw,
	.init_hw = n20_init_hw,
	.get_queues = n20_get_queues,
	.init_vport_hw_attr = n20_init_vport_hw_attr,
	.set_unicast_addr = n20_set_unicast_addr,
	.cfg_vec2tqirq = n20_cfg_vec2tqirq,
	.cfg_vec2rqirq = n20_cfg_vec2rqirq,
	.set_max_pktlen = n20_set_max_pktlen,

	.set_rss_hash = n20_set_rss_hash,
	.set_rss_key = n20_set_rss_key,
	.set_rss_table = n20_set_rss_table,
	.set_rss_hash_type = n20_set_rss_hash_type,

	.set_rx_csumofld = n20_set_rx_csumofld,
	.set_vlan_strip = n20_set_vlan_strip,
	.set_vlan_vfta = n20_set_vlan_vfta,

	.set_uc_filter = n20_set_uc_filter,
	.add_uc_filter = n20_add_uc_filter,
	.del_uc_filter = n20_del_uc_filter,
	.set_mc_filter = n20_set_mc_filter,
	.add_mc_filter = n20_add_mc_filter,
	.del_mc_filter = n20_del_mc_filter,
	.clear_mc_filter = n20_clear_mc_filter,

	.set_mc_promisc = n20_set_mc_promisc,
	.set_uc_promisc = n20_set_uc_promisc,
	.set_vlan_promisc = n20_set_vlan_promisc,
	.set_pf_promisc_mode = n20_set_pf_promisc_mode,

	.set_vlan_filter = n20_set_vlan_filter,
	.add_vlan_filter = n20_add_vlan_filter,
	.del_vlan_filter = n20_del_vlan_filter,

	.add_ntuple_filter = n20_add_ntuple_filter,
	.del_ntuple_filter = n20_del_ntuple_filter,

	/* ring */
	.set_txring_ctx = n20_set_txring_ctx,
	.set_rxring_ctx = n20_set_rxring_ctx,
	.enable_txrxring_irq = n20_enable_txrxring_irq,
	.disable_txrxring_irq = n20_disable_txrxring_irq,
	.start_txring = n20_start_txring,
	.start_rxring = n20_start_rxring,
	.stop_txring = n20_stop_txring,
	.stop_rxring = n20_stop_rxring,
	.set_txring_intr_coal = n20_set_txring_intr_coal,
	.set_rxring_intr_coal = n20_set_rxring_intr_coal,
	.set_txring_hw_dim = n20_set_txring_hw_dim,
	.set_rxring_hw_dim = n20_set_rxring_hw_dim,
	.cfg_txring_bw_lmt = n20_cfg_txring_bw_lmt,
	.set_txring_trig_intr = n20_set_txring_trig_intr,
	.get_hw_ring_stats = n20_get_hw_ring_stats,
	.clear_hw_ring_stats = n20_clear_hw_ring_stats,

	.set_tun_select_inner = n20_set_tun_select_inner,
	/* pfc */
	.set_q_to_pfc = n20_set_q_to_pfc,
	.clr_q_to_pfc = n20_clr_q_to_pfc,
};

static void n20_setup_mbx_info_pf(struct mcevf_hw *hw, struct mcevf_mbx_info *mbx)
{
	mbx->hw = hw;

	mutex_init(&mbx->req_lock);
	spin_lock_init(&mbx->req_shm_lock);
	spin_lock_init(&mbx->peer_shm_lock);

	mbx->irq_enabled = 0;
	mbx->is_pf_mbx = true;

	mbx->req_shm_size = VF2PF_SHM_SIZE;
	mbx->peer_shm_size = PF2VF_SHM_SIZE;

	if (hw->is_vf_isolated_enabled) {
		mbx->peer2vf_shm = hw->eth_bar_base + PF2VF_SHM_ISOLATED;
		mbx->peer2vf_shm_lock = hw->eth_bar_base + PF2VF_SHM_LOCK_ISOLATED;
		mbx->peer2vf_ctrl = hw->eth_bar_base + PF2VF_REQ_CTRL_ISOLATED;
		mbx->peer2vf_shm_lock_msk = BIT(2);  // VFU

		mbx->vf2peer_shm = hw->eth_bar_base + VF2PF_SHM_ISOLATED;
		mbx->vf2peer_shm_lock = hw->eth_bar_base + VF2PF_SHM_LOCK_ISOLATED;
		mbx->vf2peer_ctrl = hw->eth_bar_base + VF2PF_REQ_CTRL_ISOLATED;
		mbx->vf2peer_shm_lock_msk = BIT(2);  // VFU

		mbx->mbx_vec_base = hw->eth_bar_base + PF2VF_MB_VEC_ISOLATED;

		mbx->setup_done = true;
	} else {
		int nr_vf = hw->vfnum;

		mbx->peer2vf_shm = hw->eth_bar_base + N20_MBX_BASE + PF2VF_SHM_NO_ISOLATED(nr_vf);
		mbx->peer2vf_shm_lock =
		    hw->eth_bar_base + N20_MBX_BASE + PF2VF_SHM_LOCK_NO_ISOLATED(nr_vf);
		mbx->peer2vf_ctrl =
		    hw->eth_bar_base + N20_MBX_BASE + PF2VF_REQ_CTRL_NO_ISOLATED(nr_vf);
		mbx->peer2vf_shm_lock_msk = BIT(2);  // VFU

		mbx->vf2peer_shm = hw->eth_bar_base + N20_MBX_BASE + VF2PF_SHM_NO_ISOLATED(nr_vf);
		mbx->vf2peer_shm_lock =
		    hw->eth_bar_base + N20_MBX_BASE + VF2PF_SHM_LOCK_NO_ISOLATED(nr_vf);
		mbx->vf2peer_ctrl =
		    hw->eth_bar_base + N20_MBX_BASE + VF2PF_REQ_CTRL_NO_ISOLATED(nr_vf);
		mbx->vf2peer_shm_lock_msk = BIT(2);  // VFU

		mbx->mbx_vec_base =
		    hw->eth_bar_base + N20_MBX_BASE + PF2VF_MB_VEC_NO_ISOLATED(nr_vf);

		mbx->setup_done = true;
	}

	mbx->nr_vf = hw->vfnum;
}

static void n20_init_virtchnl_info(struct mcevf_hw *hw)
{
	hw->virtchnl.ops = &virtchnl_ops;
}

static bool is_vf_isolated_enabled(struct mcevf_hw *hw)
{
	unsigned int v = readl(hw->eth_bar_base + 0x7f000);

	return (v & 0xfff00000) == 0x20200000 || (v == 0xdeadb101);
}

// #define N20_RSS_DEBUG
#ifdef N20_RSS_DEBUG
static u8 rss_default_key[N20_RSS_HASH_KEY_SIZE] = {
	0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25,
	0x3d, 0x43, 0xa3, 0x8f, 0xb0, 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b,
	0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c, 0x6a,
	0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
#endif

int mcevf_get_n20_caps(struct mcevf_hw *hw)
{
	struct mcevf_mbx_info *mbx = &hw->pf_mbx;
	int ret = 0;

	hw->is_vf_isolated_enabled = is_vf_isolated_enabled(hw);
	dev_info(hw->dev, "vf isolated enabled:%d\n",
		 hw->is_vf_isolated_enabled);

	hw->ops = &n20_ops;
	hw->vfnum = n20_get_vfnum(hw);
	hw->reset_done = false;

	n20_setup_mbx_info_pf(hw, mbx);
	/* virtchnl info */
	n20_init_virtchnl_info(hw);
	ret = mcevf_reset_hw(hw, false);
	if (ret)
		return ret;

	mbx->nr_pf = hw->nr_pf;
	snprintf(mbx->name, sizeof(mbx->name), "%s-mbx-pf%dvf%d",
		 pci_name(hw->pdev), mbx->nr_pf, mbx->nr_vf);

	if (hw->is_vf_isolated_enabled)
		hw->ring_base_addr = 0;
	else
		hw->ring_base_addr = N20_USE_FORCE_SETUP_RING_BASE;
	hw->func_caps.common_cap.drop_intr_timer_en = true;
	hw->func_caps.guar_num_vsi = 1;
	hw->func_caps.common_cap.vlan_strip_cnt = N20_VLAN_DEFAULT_STRIP_CNT;
	hw->func_caps.common_cap.num_txq = hw->ring_max_cnt;
	hw->func_caps.common_cap.num_rxq = hw->ring_max_cnt;
	hw->func_caps.common_cap.mbox_irq_base = N20_MBOX_IRQ_BASE;
	hw->func_caps.common_cap.num_mbox_irqs = N20_NUM_MBOX_IRQS;
	hw->func_caps.common_cap.qvec_irq_base = N20_QVEC_IRQ_BASE;
	hw->func_caps.common_cap.rdma_irq_base = N20_RDMA_IRQ_BASE;
	hw->func_caps.common_cap.num_rdma_irqs = N20_NUM_RDMA_IRQS;
	hw->func_caps.common_cap.max_irq_cnts = N20_MAX_IRQS;

	hw->func_caps.fd_fltr_guar = N20_MAX_FDIR_CNT;

	hw->func_caps.common_cap.rss_table_size = N20_RSS_TABLE_SIZE;
	hw->func_caps.common_cap.rss_key_size = N20_RSS_HASH_KEY_SIZE;
#ifdef N20_RSS_DEBUG
	memcpy(hw->rss_key, rss_default_key, sizeof(rss_default_key));
#else
	netdev_rss_key_fill(hw->rss_key, N20_RSS_HASH_KEY_SIZE);
#endif
	hw->rss_hash_type = N20_RSS_HASH_TYPE_CFG;
	hw->rss_hfunc = ETH_RSS_HASH_TOP;
	return ret;
}
