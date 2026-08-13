/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_ETHTOOL_FDIR_H_
#define _MCE_ETHTOOL_FDIR_H_

int mce_get_ethtool_fdir_entry(struct mce_hw *hw, struct ethtool_rxnfc *cmd);
int mce_get_fdir_fltr_ids(struct mce_hw *hw, struct ethtool_rxnfc *cmd, u32 *rule_locs);
int mce_add_ntuple_ethtool(struct mce_vsi *vsi, struct ethtool_rxnfc *cmd);
int mce_del_ntuple_ethtool(struct mce_vsi *vsi, struct ethtool_rxnfc *cmd);
#endif /* _MCE_ETHTOOL_FDIR_H_*/
