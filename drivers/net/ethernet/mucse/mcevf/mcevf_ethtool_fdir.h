/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2020-2026 Mucse Corporation. */

#ifndef _MCEVF_ETHTOOL_FDIR_H_
#define _MCEVF_ETHTOOL_FCIR_H_

int mcevf_get_ethtool_fdir_entry(struct mcevf_hw *hw,
				 struct ethtool_rxnfc *cmd);
int mcevf_get_fdir_fltr_ids(struct mcevf_hw *hw, struct ethtool_rxnfc *cmd,
			    u32 *rule_locs);
int mcevf_add_ntuple_ethtool(struct mcevf_vsi *vsi,
			     struct ethtool_rxnfc *cmd);
int mcevf_del_ntuple_ethtool(struct mcevf_vsi *vsi,
			     struct ethtool_rxnfc *cmd);
#endif /* _MCEVF_ETHTOOL_FCIR_H_*/
