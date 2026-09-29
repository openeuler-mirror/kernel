/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_ETHTOOL_H_
#define _MCE_ETHTOOL_H_

struct mce_stats {
	char stat_string[ETH_GSTRING_LEN + 10];
	int sizeof_stat;
	int stat_offset;
};

#define MCE_STAT(_type, _name, _stat) { \
	.stat_string = _name, \
	.sizeof_stat = sizeof_field(_type, _stat), \
	.stat_offset = offsetof(_type, _stat) \
}

#define MCE_NETDEV_STAT(_name, _stat) \
		MCE_STAT(struct mce_vsi, _name, _stat)

#define MCE_OFLD_STAT(_name, _stat) \
		MCE_STAT(struct mce_vsi, _name, _stat)

#define MCE_HW_STAT(_name, _stat) \
		MCE_STAT(struct mce_pf, _name, _stat)

#define MCE_QUEUE_STAT(_name, _stat) \
		MCE_STAT(struct mce_ring_stats, _name, _stat)

struct mce_ring_reg {
	char stat_string[ETH_GSTRING_LEN];
	u32 reg;
	int isu64;
};

#define MCE_QUEUE_REG(_name, _offset, u64_f) {\
	.stat_string = _name,\
	.reg = _offset,\
	.isu64 = u64_f, \
}

#define MCE_MAX_INTR_TIME	(256)
#define MCE_MAX_INTR_PKTS	(256)

struct mce_phy_type_to_ethtool {
	u64 hw_link_speed;
	enum ethtool_link_mode_bit_indices link_mode;
	bool ethtool_link_mode_supported;
	u32 module_type;
};

/* Macro to make PHY type to ethtool link mode table entry.
 * The index is the PHY type.
 */
#define MCE_PHY_TYPE(MODULE_TYPE, LINK_SPEED, ETHTOOL_LINK_MODE) \
	{ MCE_FW_LINK_SPEED_##LINK_SPEED,                        \
	  ETHTOOL_LINK_MODE_##ETHTOOL_LINK_MODE##_BIT, true,     \
	  BIT(MODULE_TYPE) }

/* PHY types that do not have a supported ethtool link mode are initialized as:
 * { false, PHY_TYPE_IDX, MCE_AQ_LINK_SPEED_UNKNOWN , 0 }
 */
#define MCE_PHY_TYPE_ETHTOOL_UNSUPPORTED(MODULE_TYPE)                       \
	{ MCE_FW_LINK_SPEED_UNKNOWN, (enum ethtool_link_mode_bit_indices)0, \
	  false, MODULE_TYPE }

#define MCE_PHY_TYPE_LOW_SIZE (MCE_PHY_TYPE_LOW_MAX_INDEX + 1)

/* Lookup table mapping PHY type low to link speed and ethtool link modes */
static struct mce_phy_type_to_ethtool phy_type_lkup[] = {
	/************************ 1000M ********************************/
	MCE_PHY_TYPE(MCE_MODULE_1G_T, 1000MB, 1000baseT_Full),
	MCE_PHY_TYPE(MCE_MODULE_1G_X, 1000MB, 1000baseT_Full),
	MCE_PHY_TYPE(MCE_MODULE_1G_KX, 1000MB, 1000baseKX_Full),

	/************************  10G  ********************************/
	MCE_PHY_TYPE(MCE_MODULE_BASET, 10GB, 10000baseT_Full),
	MCE_PHY_TYPE(MCE_MODULE_CR, 10GB, 10000baseT_Full),
	MCE_PHY_TYPE(MCE_MODULE_SR, 10GB, 10000baseT_Full),
	MCE_PHY_TYPE(MCE_MODULE_LR_ER, 10GB, 10000baseT_Full),
	MCE_PHY_TYPE(MCE_MODULE_KR, 10GB, 10000baseKR_Full),

/************************  25G  ********************************/
	MCE_PHY_TYPE(MCE_MODULE_CR, 25GB, 25000baseCR_Full),
	MCE_PHY_TYPE(MCE_MODULE_SR, 25GB, 25000baseSR_Full),
	MCE_PHY_TYPE(MCE_MODULE_KR, 25GB, 25000baseKR_Full),

	/************************  40G  ********************************/
	MCE_PHY_TYPE(MCE_MODULE_CR4, 40GB, 40000baseCR4_Full),
	MCE_PHY_TYPE(MCE_MODULE_SR4, 40GB, 40000baseSR4_Full),
	MCE_PHY_TYPE(MCE_MODULE_LR4_ER4, 40GB, 40000baseLR4_Full),
	MCE_PHY_TYPE(MCE_MODULE_KR4, 40GB, 40000baseKR4_Full),

/************************ 100G  ********************************/
};

#endif /* _MCE_ETHTOOL_H_ */
