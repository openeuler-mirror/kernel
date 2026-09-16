// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include <linux/ethtool.h>
#include <linux/random.h>

#include "nse.h"
#include "nse_adminq_cmd.h"
#include "nse_common.h"
#include "nse_dcb_lib.h"
#include "nse_lib.h"

#define LKS_LM_COPY(_dst, _dname, _src, _sname)	\
	bitmap_copy((_dst)->link_modes._dname,		\
		    (_src)->link_modes._sname,		\
		    __ETHTOOL_LINK_MODE_MASK_NBITS)

static int find_set_bit_cnt_u32(u32 val)
{
	int i = 0;
	int ret = 0;

	for (i = 0; i < 32; i++) {
		if (val & BIT(i))
			ret++;
	}

	return ret;
}

static int find_set_bit_cnt_u64(u64 val)
{
	int i = 0;
	int ret = 0;

	for (i = 0; i < 64; i++) {
		if (val & BIT_ULL(i))
			ret++;
	}

	return ret;
}

static int find_highest_bit_u32(u32 val)
{
	int i = 0;
	int ret = -1;

	for (i = 31; i >= 0; i--) {
		if (val & BIT(i)) {
			ret = i;
			break;
		}
	}

	return ret;
}

static char *fec_str(u32 fec)
{
	static char str_buf[256] = {0};
	int cur_loc = 0;

	cur_loc += sprintf(str_buf + cur_loc, "fec encoding:");

	if (fec == FEC_NONE) {
		cur_loc += sprintf(str_buf + cur_loc, "NONE");

	} else {
		if (fec & FEC_AUTO)
			cur_loc += sprintf(str_buf + cur_loc, "AUTO,");

		if (fec & FEC_RS)
			cur_loc += sprintf(str_buf + cur_loc, "RS,");

		if (fec & FEC_BASER)
			cur_loc += sprintf(str_buf + cur_loc, "BASER,");

		if (fec & FEC_OFF)
			cur_loc += sprintf(str_buf + cur_loc, "OFF");
	}

	return str_buf;
}

static u32 speed_internal_to_public(u32 speed)
{
	switch (speed) {
	case NSE_AQ_LINK_SPEED_800GB:
		return SPEED_800000;
	case NSE_AQ_LINK_SPEED_400GB:
		return SPEED_400000;
	case NSE_AQ_LINK_SPEED_200GB:
		return SPEED_200000;
	case NSE_AQ_LINK_SPEED_100GB:
		return SPEED_100000;
	case NSE_AQ_LINK_SPEED_50GB:
		return SPEED_50000;
	case NSE_AQ_LINK_SPEED_40GB:
		return SPEED_40000;
	case NSE_AQ_LINK_SPEED_25GB:
		return SPEED_25000;
	case NSE_AQ_LINK_SPEED_20GB:
		return SPEED_20000;
	case NSE_AQ_LINK_SPEED_10GB:
		return SPEED_10000;
	case NSE_AQ_LINK_SPEED_5GB:
		return SPEED_5000;
	case NSE_AQ_LINK_SPEED_2500MB:
		return SPEED_2500;
	case NSE_AQ_LINK_SPEED_1000MB:
		return SPEED_1000;
	case NSE_AQ_LINK_SPEED_100MB:
		return SPEED_100;
	case NSE_AQ_LINK_SPEED_10MB:
		return SPEED_10;

	case NSE_AQ_LINK_SPEED_UNKNOWN:
	default:
		return 0;
	}
}

static u32 speed_public_to_internal(u32 speed)
{
	switch (speed) {
	case SPEED_800000:
		return NSE_AQ_LINK_SPEED_800GB;
	case SPEED_400000:
		return NSE_AQ_LINK_SPEED_400GB;
	case SPEED_200000:
		return NSE_AQ_LINK_SPEED_200GB;
	case SPEED_100000:
		return NSE_AQ_LINK_SPEED_100GB;
	case SPEED_50000:
		return NSE_AQ_LINK_SPEED_50GB;
	case SPEED_40000:
		return NSE_AQ_LINK_SPEED_40GB;
	case SPEED_25000:
		return NSE_AQ_LINK_SPEED_25GB;
	case SPEED_20000:
		return NSE_AQ_LINK_SPEED_20GB;
	case SPEED_10000:
		return NSE_AQ_LINK_SPEED_10GB;
	case SPEED_5000:
		return NSE_AQ_LINK_SPEED_5GB;
	case SPEED_2500:
		return NSE_AQ_LINK_SPEED_2500MB;
	case SPEED_1000:
		return NSE_AQ_LINK_SPEED_1000MB;
	case SPEED_100:
		return NSE_AQ_LINK_SPEED_100MB;
	case SPEED_10:
		return NSE_AQ_LINK_SPEED_10MB;
	default:
		return NSE_AQ_LINK_SPEED_UNKNOWN;
	}
}

unsigned int nse_get_link_speed_mbps(struct nse_hw *hw)
{
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	unsigned int speed_mbps;

	speed_mbps = speed_internal_to_public(lpinfo->link_info.link_speed);

	if (speed_mbps == 0) {
		if (lpinfo->static_flags & LMAC_PHY_STATIC_FLAG_USE_TEST_PHY)
			speed_mbps = SPEED_1000;
	}

	return speed_mbps;
}

unsigned int nse_get_link_speed_kbps(struct nse_hw *hw)
{
	unsigned int speed_mbps;

	speed_mbps = nse_get_link_speed_mbps(hw);

	return speed_mbps * 1000;
}

static bool
ephy_status_is_module_present(struct nse_hw *hw, bool status_new_or_old);

int nse_get_link_ksettings(struct net_device *netdev, struct ethtool_link_ksettings *cmd)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct nse_port_info *pi = hw->port_info;
	struct nse_dcbx_cfg *dcbx_cfg = &pi->qos_cfg.local_dcbx_cfg;
	struct nse_lmac_phy_info *lpinfo = &pi->lmac_phy_info;
	struct nse_ephy_info *ephy_info = &lpinfo->ephy_info;
	int ret = 0;

	ethtool_link_ksettings_zero_link_mode(cmd, supported);
	ethtool_link_ksettings_zero_link_mode(cmd, advertising);
	ethtool_link_ksettings_zero_link_mode(cmd, lp_advertising);

/*  intentionally, not acquire this lock, to avoid possible tripple lock issue in HW-bond with RDMA
 */
//	nse_lmac_phy_lock(hw);

	if (lpinfo->link_info.link_status) {
		cmd->base.speed = nse_get_link_speed_mbps(hw);
		cmd->base.duplex = DUPLEX_FULL;
	} else {
		cmd->base.speed = SPEED_UNKNOWN;
		cmd->base.duplex = DUPLEX_UNKNOWN;
	}

	cmd->base.autoneg = lpinfo->an_info.an_enabled;

	if (nse_is_nic_use_ephy(hw->nic_type) && ephy_status_is_module_present(hw,
	    true) && ephy_info->is_supported_mod) {
		LKS_LM_COPY(cmd, supported, &ephy_info->mod_lks, supported);
		cmd->base.port = ephy_info->mod_lks.base.port;

		if (ephy_info->mod_an_supported && lpinfo->an_info.an_enabled)
			cmd->base.autoneg = AUTONEG_ENABLE;
		else
			cmd->base.autoneg = AUTONEG_DISABLE;

	} else {
		LKS_LM_COPY(cmd, supported, &lpinfo->lks, supported);
		cmd->base.port = PORT_FIBRE;
	}

	LKS_LM_COPY(cmd, advertising, &lpinfo->lks, advertising);

	ethtool_link_ksettings_add_link_mode(cmd, supported, Pause);

	if (!dcbx_cfg->pfc.pfcena) {
		/* according to AI ..... */
		if (lpinfo->fc_info.current_mode == NSE_FC_LFC_FULL)
			ethtool_link_ksettings_add_link_mode(cmd, advertising, Pause);
		else if (lpinfo->fc_info.current_mode == NSE_FC_LFC_RX_PAUSE) {
			ethtool_link_ksettings_add_link_mode(cmd, advertising, Pause);
			ethtool_link_ksettings_add_link_mode(cmd, advertising, Asym_Pause);
		} else if (lpinfo->fc_info.current_mode == NSE_FC_LFC_TX_PAUSE)
			ethtool_link_ksettings_add_link_mode(cmd, advertising, Asym_Pause);
	}

//	nse_lmac_phy_unlock(hw);

	return ret;
}

static u64 an_translate_lks_adv_to_link_types(const struct ethtool_link_ksettings *lks)
{
	u64 link_types = NSE_ETH_LINK_TYPE_UNKNOWN;

	if (ethtool_link_ksettings_test_link_mode(lks, advertising, 10000baseKR_Full) ||
		ethtool_link_ksettings_test_link_mode(lks, advertising, 10000baseR_FEC) ||
		ethtool_link_ksettings_test_link_mode(lks, advertising, 10000baseCR_Full))
		link_types |= NSE_ETH_LINK_TYPE_10GbaseR;

	if (ethtool_link_ksettings_test_link_mode(lks, advertising, 25000baseCR_Full) ||
		ethtool_link_ksettings_test_link_mode(lks, advertising, 25000baseKR_Full))
		link_types |= NSE_ETH_LINK_TYPE_25GbaseR;

	if (ethtool_link_ksettings_test_link_mode(lks, advertising, 40000baseKR4_Full) ||
		ethtool_link_ksettings_test_link_mode(lks, advertising, 40000baseCR4_Full))
		link_types |= NSE_ETH_LINK_TYPE_40GbaseR4;

	if (ethtool_link_ksettings_test_link_mode(lks, advertising, 50000baseCR2_Full) ||
		ethtool_link_ksettings_test_link_mode(lks, advertising, 50000baseKR2_Full))
		link_types |= NSE_ETH_LINK_TYPE_50GbaseR2;

	if (ethtool_link_ksettings_test_link_mode(lks, advertising, 100000baseKR4_Full) ||
		ethtool_link_ksettings_test_link_mode(lks, advertising, 100000baseCR4_Full))
		link_types |= NSE_ETH_LINK_TYPE_100GbaseR4;

	if (ethtool_link_ksettings_test_link_mode(lks, advertising, 200000baseKR4_Full) ||
		ethtool_link_ksettings_test_link_mode(lks, advertising, 200000baseCR4_Full))
		link_types |= NSE_ETH_LINK_TYPE_200GbaseR4;

	if (ethtool_link_ksettings_test_link_mode(lks, advertising, 400000baseKR4_Full) ||
	    ethtool_link_ksettings_test_link_mode(lks, advertising, 400000baseCR4_Full))
		link_types |= NSE_ETH_LINK_TYPE_400GbaseR4;

	return link_types;
}

int nse_set_link_ksettings(struct net_device *netdev, const struct ethtool_link_ksettings *cmd)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *epinfo = &lpinfo->ephy_info;
	u32 speed;
	u64 link_types;
	int ret = -EINVAL;

	nse_lmac_phy_lock(hw);

	if (cmd->base.duplex != DUPLEX_FULL) {
		netdev_err(netdev, "unsupported half-duplex\n");
		goto out;
	}

	if (!cmd->base.autoneg) {	/* set fixed link */

		speed = cmd->base.speed;

		speed = speed_public_to_internal(speed);

		if (!(lpinfo->supported_link_speeds & speed)) {
			netdev_err(netdev, "NIC does not support this speed\n");
			goto out;
		}

		if (nse_is_nic_use_ephy(hw->nic_type) && ephy_status_is_module_present(hw, true)) {
			if (!epinfo->is_supported_mod) {
				netdev_err(netdev, "external module not compatible\n");
				goto out;
			}

			if (!(speed & epinfo->mod_supported_link_speeds)) {
				netdev_err(netdev, "external module not support this speed\n");
				goto out;
			}
		}

		/* just for test subtask logic , set speed and link type all the time. */

		lpinfo->an_info.an_enabled = false;

		lpinfo->req_link_speed_from_user = speed;

		/* clear it because set fixed speed */
		lpinfo->req_link_types_from_user = NSE_ETH_LINK_TYPE_UNKNOWN;

		lpinfo->link_down_retry_whole_subtask_prev = jiffies;
		lpinfo->link_down_retry_whole_subtask_period =
			NSE_LMAC_PHY_RETRY_WHOLE_SUBTASK_PERIOD_SHORT;

	} else {	/* start AN */

		if (!lpinfo->an_info.an_supported) {
			netdev_err(netdev, "NIC not support AN\n");
			goto out;
		}

		if (nse_is_nic_use_ephy(hw->nic_type) && ephy_status_is_module_present(hw, true)) {
			if (!epinfo->is_supported_mod) {
				netdev_err(netdev, "external module not compatible\n");
				goto out;
			}

			if (!epinfo->mod_an_supported) {
				netdev_err(netdev, "external module not support AN\n");
				goto out;
			}
		}

		link_types = an_translate_lks_adv_to_link_types(cmd);

		if (link_types == NSE_ETH_LINK_TYPE_UNKNOWN)
			link_types = lpinfo->supported_link_types;

		link_types &= lpinfo->supported_link_types;

		if (link_types == NSE_ETH_LINK_TYPE_UNKNOWN) {
			netdev_err(netdev, "NIC not support specified advertise\n");
			goto out;
		}

		/* above already checked is_supported_mod and mod_an_supported */
		if (nse_is_nic_use_ephy(hw->nic_type) && ephy_status_is_module_present(hw, true)) {
			link_types &= epinfo->mod_supported_link_types;

			if (link_types == NSE_ETH_LINK_TYPE_UNKNOWN) {
				netdev_err(netdev, "external module not support specified advertise\n");
				goto out;
			}
		}

		lpinfo->an_info.an_enabled = true;

		lpinfo->req_link_types_from_user = link_types;

		/* clear it because do AN */
		lpinfo->req_link_speed_from_user = NSE_AQ_LINK_SPEED_UNKNOWN;

		lpinfo->link_down_retry_whole_subtask_prev = jiffies;
		lpinfo->link_down_retry_whole_subtask_period =
			NSE_LMAC_PHY_RETRY_WHOLE_SUBTASK_PERIOD;
	}

	lpinfo->dyn_flags |= (LMAC_PHY_DYN_FLAG_NEED_FIRST_FORCE_NOTIFY_LINK_DOWN |
						/*  if ephy not ready, then would not
						 * start_link_or_an and update_link_status
						 */
						LMAC_PHY_DYN_FLAG_NEED_UPDATE_EPHY_STATUS |
						LMAC_PHY_DYN_FLAG_NEED_START_LINK_OR_AN |
						LMAC_PHY_DYN_FLAG_NEED_UPDATE_LINK_INFO);

	nse_service_task_schedule(pf);	/* schedule lmac_phy_subtask */

	ret = 0;

out:
	nse_lmac_phy_unlock(hw);

	return ret;
}

static bool __maybe_unused
fec_is_supported_with_an_disabled(struct nse_hw *hw, u32 req_fec_from_user,
				  u32 *suggest_fec_set)
{
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	u32 link_speed;

	if (req_fec_from_user == FEC_NONE) {
		*suggest_fec_set = FEC_NONE;
		return true;
	}

	if (lpinfo->req_link_speed_from_user)
		link_speed = lpinfo->req_link_speed_from_user;
	else
		link_speed = lpinfo->req_link_speeds;

	if (link_speed == NSE_AQ_LINK_SPEED_1000MB) {
		*suggest_fec_set = FEC_NONE;

		if (req_fec_from_user != FEC_AUTO) {
			nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s, %d] bad case for 1G speed\n",
				  __func__, __LINE__);

			return false;
		} else {
			return true;
		}

	} else if (link_speed == NSE_AQ_LINK_SPEED_10GB) {
		*suggest_fec_set = FEC_BASER;				/* plus _NONE */

		if (req_fec_from_user == FEC_AUTO || req_fec_from_user == FEC_BASER)

			return true;

		else {
			nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s, %d] bad case for 10G speed\n",
				  __func__, __LINE__);

			return false;
		}

	} else if (link_speed == NSE_AQ_LINK_SPEED_25GB ||
				link_speed == NSE_AQ_LINK_SPEED_40GB ||
				link_speed == NSE_AQ_LINK_SPEED_50GB) {
		if (req_fec_from_user == FEC_AUTO) {
			*suggest_fec_set = (FEC_RS | FEC_BASER);	/* plus _NONE */
			return true;

		} else if (req_fec_from_user == FEC_BASER) {
			*suggest_fec_set = FEC_BASER;				/* plus _NONE */
			return true;

		} else if (req_fec_from_user == FEC_RS) {
			*suggest_fec_set = FEC_RS;				/* plus _NONE */
			return true;

		} else {
			nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s, %d] bad case for 25,40,50 speed\n",
				  __func__, __LINE__);

			*suggest_fec_set = (FEC_RS | FEC_BASER);	/* plus _NONE */

			return false;
		}

	} else if (link_speed >= NSE_AQ_LINK_SPEED_100GB) {
		*suggest_fec_set = FEC_RS;				/* plus _NONE */

		if (req_fec_from_user == FEC_AUTO || req_fec_from_user == FEC_RS) {
			nse_debug(hw, NSE_DBG_LMAC_PHY,
				  "[%s, %d] bad case for 100/200/400GbaseR4\n",
				__func__, __LINE__);

			return false;
		} else {
			return true;
		}
	} else {
		dev_info(nse_hw_to_dev(hw), "[%s] check logic not impl, consider false, req_link_speed=0x%X, req_fec_from_user=0x%X\n",
									__func__, link_speed,
										req_fec_from_user);

		*suggest_fec_set = FEC_NONE;

		return false;
	}
}

int nse_set_fecparam(struct net_device *netdev, struct ethtool_fecparam *fecparam)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	u32 fec_from_user = FEC_NONE;	/* new value gonna set into lpinfo->req_fec_from_user */
	int ret = 0;

	nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] an_enabled=%d, fecparam->fec=0x%X\n",
					__func__, lpinfo->an_info.an_enabled, fecparam->fec);

	if (fecparam->fec & ETHTOOL_FEC_LLRS) {
		netdev_err(netdev, "[%s] BAD input: unsupported fec setting=LLRS\n", __func__);
		ret = -EINVAL;
		goto out;
	}


	/****** NOTE: FEC_AUTO (FEC auto switch) != AN *****/

	if (fecparam->fec & ETHTOOL_FEC_BASER)		/* include: baser */
		fec_from_user |= FEC_BASER;

	if (fecparam->fec & ETHTOOL_FEC_RS)			/* include: rs */
		fec_from_user |= FEC_RS;

	if (fecparam->fec & ETHTOOL_FEC_OFF)		/* include: off */
		fec_from_user |= FEC_OFF;

	if (fecparam->fec & ETHTOOL_FEC_AUTO) {
		/* ethtool specify: auto + */

		/* in case ethtool specify only auto, give it all */
		if (fec_from_user == FEC_NONE)
			fec_from_user = (FEC_RS | FEC_BASER | FEC_OFF);

		fec_from_user |= FEC_AUTO;
	}

	if (!(fec_from_user & ~FEC_AUTO)) {
		netdev_err(netdev, "[%s] BAD input: should contains at least one in: RS/BASER/OFF, excluding AUTO\n",
			   __func__);
		ret = -EINVAL;
		goto out;
	}

	/* just for test subtask logic , set speed and link type all the time. */

	nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] req_fec_from_user change to 0x%X(%s)\n",
		  __func__, fec_from_user, fec_str(fec_from_user));

	nse_lmac_phy_lock(hw);

	lpinfo->req_fec_from_user = fec_from_user;
	lpinfo->req_fec_cur = FEC_NONE;

	/* reconfig lmac/phy */
	lpinfo->dyn_flags |= (LMAC_PHY_DYN_FLAG_NEED_FIRST_FORCE_NOTIFY_LINK_DOWN |
						/*  if ephy not ready, then would not
						 * start_link_or_an and update_link_status
						 */
						LMAC_PHY_DYN_FLAG_NEED_UPDATE_EPHY_STATUS |
						LMAC_PHY_DYN_FLAG_NEED_START_LINK_OR_AN |
						LMAC_PHY_DYN_FLAG_NEED_UPDATE_LINK_INFO);

	lpinfo->link_down_retry_whole_subtask_prev = jiffies;

	if (lpinfo->an_info.an_enabled)
		lpinfo->link_down_retry_whole_subtask_period =
			NSE_LMAC_PHY_RETRY_WHOLE_SUBTASK_PERIOD;
	else
		lpinfo->link_down_retry_whole_subtask_period =
			NSE_LMAC_PHY_RETRY_WHOLE_SUBTASK_PERIOD_SHORT;

	nse_service_task_schedule(pf);	/* schedule lmac_phy_subtask */

	nse_lmac_phy_unlock(hw);

out:
	return ret;
}

int nse_get_fecparam(struct net_device *netdev, struct ethtool_fecparam *fecparam)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *epinfo = &lpinfo->ephy_info;
	u32 supported_fec = lpinfo->supported_fec;
	u32 req_fec_from_user = lpinfo->req_fec_from_user;

	nse_lmac_phy_lock(hw);

	/* supported */
	fecparam->fec = (ETHTOOL_FEC_AUTO | ETHTOOL_FEC_OFF);

	if (nse_is_nic_use_ephy(hw->nic_type) &&
	    ephy_status_is_module_present(hw, true) && epinfo->is_supported_mod)
		supported_fec &= epinfo->mod_supported_fec;

	if (supported_fec & FEC_BASER)
		fecparam->fec |= ETHTOOL_FEC_BASER;

	if (supported_fec & FEC_RS)
		fecparam->fec |= ETHTOOL_FEC_RS;


	/* current setting */
	fecparam->active_fec = 0;

	if (req_fec_from_user & FEC_AUTO)
		fecparam->active_fec |= ETHTOOL_FEC_AUTO;

	if (req_fec_from_user & FEC_RS)
		fecparam->active_fec |= ETHTOOL_FEC_RS;

	if (req_fec_from_user & FEC_BASER)
		fecparam->active_fec |= ETHTOOL_FEC_BASER;

	if (req_fec_from_user & FEC_OFF)
		fecparam->active_fec |= ETHTOOL_FEC_OFF;

	nse_lmac_phy_unlock(hw);

	return 0;
}

enum nse_status
nse_aq_lmac_get_basic_cfg(struct nse_hw *hw, struct nse_aqc_lmac_get_set_basic_cfg *basic_cfg)
{
	struct nse_aq_desc desc;

	memset(basic_cfg, 0, sizeof(*basic_cfg));

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LMAC_PHY,
				      NSE_AQ_OPC_LMAC_GET_SET_BASIC_CFG);

	nse_aqc_fill_generic_common_hdr_dft(hw, &basic_cfg->hdr, NSE_VSI_INVAL_ID);

	basic_cfg->rw = 0;	/* for read */

	return nse_aq_send_cmd(hw, &desc, basic_cfg, sizeof(*basic_cfg), NULL);
}

enum nse_status
nse_aq_lmac_set_basic_cfg(struct nse_hw *hw, struct nse_aqc_lmac_get_set_basic_cfg *basic_cfg)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LMAC_PHY,
				      NSE_AQ_OPC_LMAC_GET_SET_BASIC_CFG);

	nse_aqc_fill_generic_common_hdr_dft(hw, &basic_cfg->hdr, NSE_VSI_INVAL_ID);

	basic_cfg->rw = 1;	/* for write */

	return nse_aq_send_cmd(hw, &desc, basic_cfg, sizeof(*basic_cfg), NULL);
}

enum nse_status
nse_aq_lmac_read_stats(struct nse_hw *hw, struct nse_aqc_lmac_stats *lmac_stats)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LMAC_PHY,
				      NSE_AQ_OPC_LMAC_READ_STATS);

	nse_aqc_fill_generic_common_hdr_dft(hw, &lmac_stats->hdr, NSE_VSI_INVAL_ID);

	return nse_aq_send_cmd(hw, &desc, lmac_stats, sizeof(*lmac_stats), NULL);
}

static enum nse_status
lmac_type1_set_basic_cfg(struct nse_hw *hw)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_aqc_lmac_get_set_basic_cfg basic_cfg;
	struct nse_aqc_lmac_get_set_basic_cfg_type1 *cfg_type1;
	u32 val;
	int highest_bit;
	u32 highest_speed, ss;
	enum nse_status status;

	status = nse_aq_lmac_get_basic_cfg(hw, &basic_cfg);
	if (status) {
		dev_err(dev, "[%s] FAIL: aq_lmac_get_basic_cfg(), status = %d(%s)\n",
					__func__, status, nse_stat_str(status));
		goto out;
	}

	cfg_type1 = &basic_cfg.cfg_type1;

	/* adjust register setting below.
	 */

	/**************
	 * lmac_tx_cfg
	 **************/
	val = le32_to_cpu(cfg_type1->lmac_tx_cfg);

	val &= ~LMAC_TYPE1_TX_CFG_CS_M;	/* databook suggest not set 1 in 100G mode */

	val &= ~LMAC_TYPE1_TX_CFG_SS_M;
	val &= ~LMAC_TYPE1_TX_CFG_SS_3_M;

	if (hw->hw_conf.hw_platform == NSE_HW_PLATFORM_ASIC) {
		if (nse_dbg_force_mac_ss == 1) {
			nse_debug(hw, NSE_DBG_LMAC_PHY,
				  "[%s, %d] force use LMAC_TYPE1_TX_CFG_SS_25G for ASIC\n",
				__func__, __LINE__);
			val |= (LMAC_TYPE1_TX_CFG_SS_25G << LMAC_TYPE1_TX_CFG_SS_S);
		} else if (nse_dbg_force_mac_ss == 2) {
			nse_debug(hw, NSE_DBG_LMAC_PHY,
				  "[%s, %d] force use LMAC_TYPE1_TX_CFG_SS_50G for ASIC\n",
				__func__, __LINE__);
			val |= (LMAC_TYPE1_TX_CFG_SS_50G << LMAC_TYPE1_TX_CFG_SS_S);
		} else if (nse_dbg_force_mac_ss == 3) {
			nse_debug(hw, NSE_DBG_LMAC_PHY,
				  "[%s, %d] force use LMAC_TYPE1_TX_CFG_SS_100G for ASIC\n",
				__func__, __LINE__);
			val |= (LMAC_TYPE1_TX_CFG_SS_100G << LMAC_TYPE1_TX_CFG_SS_S);
		} else {
			highest_bit = find_highest_bit_u32(lpinfo->req_link_speeds);

			if (highest_bit >= 0) {
				highest_speed = BIT(highest_bit);

				if (highest_speed == NSE_AQ_LINK_SPEED_1000MB)
					ss = LMAC_TYPE1_TX_CFG_SS_1_G;
				else if (highest_speed == NSE_AQ_LINK_SPEED_2500MB)
					ss = LMAC_TYPE1_TX_CFG_SS_2_5_G;
				else if (highest_speed == NSE_AQ_LINK_SPEED_5GB)
					ss = LMAC_TYPE1_TX_CFG_SS_5G;
				else if (highest_speed == NSE_AQ_LINK_SPEED_10GB)
					ss = LMAC_TYPE1_TX_CFG_SS_10G;
				else if (highest_speed == NSE_AQ_LINK_SPEED_25GB)
					ss = LMAC_TYPE1_TX_CFG_SS_25G;
				else if (highest_speed == NSE_AQ_LINK_SPEED_40GB)
					ss = LMAC_TYPE1_TX_CFG_SS_40G;
				else if (highest_speed == NSE_AQ_LINK_SPEED_50GB)
					ss = LMAC_TYPE1_TX_CFG_SS_50G;
				else if (highest_speed == NSE_AQ_LINK_SPEED_100GB)
					ss = LMAC_TYPE1_TX_CFG_SS_100G;
				else
					ss = LMAC_TYPE1_TX_CFG_SS_100G;

			} else {
				ss = LMAC_TYPE1_TX_CFG_SS_100G;
			}

			nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s, %d] init use SS=0x%X for ASIC\n",
				  __func__, __LINE__, ss);

			val |= (ss << LMAC_TYPE1_TX_CFG_SS_S);
		}

	} else {
		nse_debug(hw, NSE_DBG_LMAC_PHY,
			  "[%s] use LMAC_TYPE1_TX_CFG_SS_1_G for FPGA\n", __func__);
		val |= (LMAC_TYPE1_TX_CFG_SS_1_G << LMAC_TYPE1_TX_CFG_SS_S);
	}

	val &= ~LMAC_TYPE1_TX_CFG_SARC_M;

	/* we set JD, even we don't transmit 16383 that large packet */
	val |= LMAC_TYPE1_TX_CFG_JD_M;

	/* IFP, IPG, ISR, ISM, DDIC - keep them reset default 0 */

	val |= LMAC_TYPE1_TX_CFG_TE_M;

	cfg_type1->lmac_tx_cfg = cpu_to_le32(val);

	/**************
	 * lmac_rx_cfg
	 **************/
	val = le32_to_cpu(cfg_type1->lmac_rx_cfg);

	/* GPSL as reset 0, because we set JE=1 */
	/* HDSMS as reset 0, because we don't use this feature */
	/* S2KP as reset 0, because we set JE=1 */

	if (nse_loopback_mode == NSE_LOOPBACK_MODE_LMAC)
		val |= LMAC_TYPE1_RX_CFG_LM_M;
	else
		val &= ~LMAC_TYPE1_RX_CFG_LM_M;

	/* IPC as reset 0, because we don't use this feature */

	val |= LMAC_TYPE1_RX_CFG_JE_M;

	val &= ~LMAC_TYPE1_RX_CFG_WD_M;

	/* GPSLCE, USP, SPEN - keep them reset default 0 */

	val &= ~LMAC_TYPE1_RX_CFG_DCRCC_M;
	val |= (LMAC_TYPE1_RX_CFG_CST_M | LMAC_TYPE1_RX_CFG_ACS_M);

	val |= LMAC_TYPE1_RX_CFG_RE_M;

	cfg_type1->lmac_rx_cfg = cpu_to_le32(val);

	/**************
	 * lmac_pkt_filter
	 **************/
	val = 0;

	val |= (LMAC_TYPE1_PKT_FILTER_PCF_FORWARD_ALL_BUT_FC << LMAC_TYPE1_PKT_FILTER_PCF_S);

	val |= LMAC_TYPE1_PKT_FILTER_PM_M;

	val |= LMAC_TYPE1_PKT_FILTER_PR_M;

	cfg_type1->lmac_pkt_filter = cpu_to_le32(val);

	/**************
	 * lmac_wd_timeout
	 **************/

	cfg_type1->lmac_wd_timeout = 0;

	/**************
	 * push all the register setting again.
	 **************/
	cfg_type1->flags = cpu_to_le32(LMAC_TYPE1_BASIC_CFG_FLAGS_ALL);

	status = nse_aq_lmac_set_basic_cfg(hw, &basic_cfg);
	if (status) {
		dev_err(dev, "nse_aq_lmac_set_basic_cfg() fails, status = %d(%s)\n",
					status, nse_stat_str(status));
		goto out;
	}

out:
	return status;
}

static enum nse_status
lmac_type1_set_basic_cfg_lm(struct nse_hw *hw, bool lb_ena)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_aqc_lmac_get_set_basic_cfg basic_cfg;
	struct nse_aqc_lmac_get_set_basic_cfg_type1 *cfg_type1;
	u32 val;
	enum nse_status status;

	status = nse_aq_lmac_get_basic_cfg(hw, &basic_cfg);
	if (status) {
		dev_err(dev, "[%s] FAIL: aq_lmac_get_basic_cfg(), status = %d(%s)\n",
					__func__, status, nse_stat_str(status));
		goto out;
	}

	cfg_type1 = &basic_cfg.cfg_type1;

	/* adjust register setting below.
	 */

	/**************
	 * lmac_tx_cfg
	 **************/
	val = le32_to_cpu(cfg_type1->lmac_rx_cfg);
	if (lb_ena)
		val |= LMAC_TYPE1_RX_CFG_LM_M;
	else
		val &= ~LMAC_TYPE1_RX_CFG_LM_M;

	cfg_type1->lmac_rx_cfg = cpu_to_le32(val);

	/**************
	 * push all the register setting again.
	 **************/
	cfg_type1->flags = cpu_to_le32(LMAC_TYPE1_BASIC_CFG_FLAG_RX_CFG);

	status = nse_aq_lmac_set_basic_cfg(hw, &basic_cfg);
	if (status) {
		dev_err(dev, "nse_aq_lmac_set_basic_cfg_lm() fails, status = %d(%s)\n",
					status, nse_stat_str(status));
		goto out;
	}

out:
	return status;
}

static void
lmac_type1_dump_stats(struct nse_hw *hw, struct nse_aqc_lmac_stats_type1 *lmac_stats)
{
	struct device *dev = nse_hw_to_dev(hw);

#define PRINT_LMAC_TYPE1_TX_STATS(idx)	\
	dev_info(dev, "%s: 0x%X (%d)\n", #idx, le32_to_cpu(lmac_stats->tx_stats[idx]), le32_to_cpu(lmac_stats->tx_stats[idx]))

#define PRINT_LMAC_TYPE1_RX_STATS(idx)	\
	dev_info(dev, "%s: 0x%X (%d)\n", #idx, le32_to_cpu(lmac_stats->rx_stats[idx]), le32_to_cpu(lmac_stats->rx_stats[idx]))

	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_Octet_Count_Good_Bad_Low);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_Octet_Count_Good_Bad_High);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_Frame_Count_Good_Bad_Low);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_Frame_Count_Good_Bad_High);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_Broadcast_Frames_Good_Low);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_Broadcast_Frames_Good_High);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_Multicast_Frames_Good_Low);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_Multicast_Frames_Good_High);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_64Octets_Frames_Good_Bad_Low);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_64Octets_Frames_Good_Bad_High);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_65To127Octets_Frames_Good_Bad_Low);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_65To127Octets_Frames_Good_Bad_High);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_128To255Octets_Frames_Good_Bad_Low);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_128To255Octets_Frames_Good_Bad_High);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_256To511Octets_Frames_Good_Bad_Low);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_256To511Octets_Frames_Good_Bad_High);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_512To1023Octets_Frames_Good_Bad_Low);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_512To1023Octets_Frames_Good_Bad_High);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_1024ToMaxOctets_Frames_Good_Bad_Low);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_1024ToMaxOctets_Frames_Good_Bad_High);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_Unicast_Frames_Good_Bad_Low);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_Unicast_Frames_Good_Bad_High);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_Multicast_Frames_Good_Bad_Low);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_Multicast_Frames_Good_Bad_High);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_Broadcast_Frames_Good_Bad_Low);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_Broadcast_Frames_Good_Bad_High);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_Underflow_Error_Frames_Low);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_Underflow_Error_Frames_High);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_Octet_Count_Good_Low);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_Octet_Count_Good_High);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_Frame_Count_Good_Low);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_Frame_Count_Good_High);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_Pause_Frames_Low);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_Pause_Frames_High);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_VLAN_Frames_Good_Low);
	PRINT_LMAC_TYPE1_TX_STATS(LMAC_TYPE1_Tx_VLAN_Frames_Good_High);

	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_Frame_Count_Good_Bad_Low);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_Frame_Count_Good_Bad_High);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_Octet_Count_Good_Bad_Low);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_Octet_Count_Good_Bad_High);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_Octet_Count_Good_Low);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_Octet_Count_Good_High);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_Broadcast_Frames_Good_Low);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_Broadcast_Frames_Good_High);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_Multicast_Frames_Good_Low);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_Multicast_Frames_Good_High);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_CRC_Error_Frames_Low);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_CRC_Error_Frames_High);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_Runt_Error_Frames);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_Jabber_Error_Frames);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_Undersize_Frames_Good);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_Oversize_Frames_Good);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_64Octets_Frames_Good_Bad_Low);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_64Octets_Frames_Good_Bad_High);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_65To127Octets_Frames_Good_Bad_Low);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_65To127Octets_Frames_Good_Bad_High);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_128To255Octets_Frames_Good_Bad_Low);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_128To255Octets_Frames_Good_Bad_High);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_256To511Octets_Frames_Good_Bad_Low);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_256To511Octets_Frames_Good_Bad_High);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_512To1023Octets_Frames_Good_Bad_Low);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_512To1023Octets_Frames_Good_Bad_High);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_1024ToMaxOctets_Frames_Good_Bad_Low);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_1024ToMaxOctets_Frames_Good_Bad_High);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_Unicast_Frames_Good_Low);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_Unicast_Frames_Good_High);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_Length_Error_Frames_Low);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_Length_Error_Frames_High);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_OutofRange_Frames_Low);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_OutofRange_Frames_High);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_Pause_Frames_Low);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_Pause_Frames_High);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_VLAN_Frames_Good_Bad_Low);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_VLAN_Frames_Good_Bad_High);
	PRINT_LMAC_TYPE1_RX_STATS(LMAC_TYPE1_Rx_Watchdog_Error_Frames);

	dev_info(dev, "fc_lxofftxc: 0x%X\n", le32_to_cpu(lmac_stats->fc_lxofftxc));
	dev_info(dev, "fc_lxontxc: 0x%X\n", le32_to_cpu(lmac_stats->fc_lxontxc));
	dev_info(dev, "fc_pxon2xoffc[8]: 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X\n",
					le32_to_cpu(lmac_stats->fc_pxon2xoffc[0]),
					le32_to_cpu(lmac_stats->fc_pxon2xoffc[1]),
					le32_to_cpu(lmac_stats->fc_pxon2xoffc[2]),
					le32_to_cpu(lmac_stats->fc_pxon2xoffc[3]),
					le32_to_cpu(lmac_stats->fc_pxon2xoffc[4]),
					le32_to_cpu(lmac_stats->fc_pxon2xoffc[5]),
					le32_to_cpu(lmac_stats->fc_pxon2xoffc[6]),
					le32_to_cpu(lmac_stats->fc_pxon2xoffc[7]));
	dev_info(dev, "fc_pxofftxc[8]: 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X\n",
					le32_to_cpu(lmac_stats->fc_pxofftxc[0]),
					le32_to_cpu(lmac_stats->fc_pxofftxc[1]),
					le32_to_cpu(lmac_stats->fc_pxofftxc[2]),
					le32_to_cpu(lmac_stats->fc_pxofftxc[3]),
					le32_to_cpu(lmac_stats->fc_pxofftxc[4]),
					le32_to_cpu(lmac_stats->fc_pxofftxc[5]),
					le32_to_cpu(lmac_stats->fc_pxofftxc[6]),
					le32_to_cpu(lmac_stats->fc_pxofftxc[7]));
	dev_info(dev, "fc_pxontxc[8]: 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X\n",
					le32_to_cpu(lmac_stats->fc_pxontxc[0]),
					le32_to_cpu(lmac_stats->fc_pxontxc[1]),
					le32_to_cpu(lmac_stats->fc_pxontxc[2]),
					le32_to_cpu(lmac_stats->fc_pxontxc[3]),
					le32_to_cpu(lmac_stats->fc_pxontxc[4]),
					le32_to_cpu(lmac_stats->fc_pxontxc[5]),
					le32_to_cpu(lmac_stats->fc_pxontxc[6]),
					le32_to_cpu(lmac_stats->fc_pxontxc[7]));
	dev_info(dev, "fc_lxoffrxc: 0x%X\n", le32_to_cpu(lmac_stats->fc_lxoffrxc));
	dev_info(dev, "fc_lxonrxc: 0x%X\n", le32_to_cpu(lmac_stats->fc_lxonrxc));
	dev_info(dev, "fc_pxoffrxc[8]: 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X\n",
					le32_to_cpu(lmac_stats->fc_pxoffrxc[0]),
					le32_to_cpu(lmac_stats->fc_pxoffrxc[1]),
					le32_to_cpu(lmac_stats->fc_pxoffrxc[2]),
					le32_to_cpu(lmac_stats->fc_pxoffrxc[3]),
					le32_to_cpu(lmac_stats->fc_pxoffrxc[4]),
					le32_to_cpu(lmac_stats->fc_pxoffrxc[5]),
					le32_to_cpu(lmac_stats->fc_pxoffrxc[6]),
					le32_to_cpu(lmac_stats->fc_pxoffrxc[7]));
	dev_info(dev, "fc_pxonrxc[8]: 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X\n",
					le32_to_cpu(lmac_stats->fc_pxonrxc[0]),
					le32_to_cpu(lmac_stats->fc_pxonrxc[1]),
					le32_to_cpu(lmac_stats->fc_pxonrxc[2]),
					le32_to_cpu(lmac_stats->fc_pxonrxc[3]),
					le32_to_cpu(lmac_stats->fc_pxonrxc[4]),
					le32_to_cpu(lmac_stats->fc_pxonrxc[5]),
					le32_to_cpu(lmac_stats->fc_pxonrxc[6]),
					le32_to_cpu(lmac_stats->fc_pxonrxc[7]));
}

static void
lmac_type2_dump_stats(struct nse_hw *hw, struct nse_aqc_lmac_stats_type2 *lmac_stats)
{
	struct device *dev = nse_hw_to_dev(hw);

#define PRINT_LMAC_TYPE2_TX_STATS(idx)	\
	dev_info(dev, "%s: 0x%X (%d)\n", #idx, le32_to_cpu(lmac_stats->tx_stats[idx]), le32_to_cpu(lmac_stats->tx_stats[idx]))

#define PRINT_LMAC_TYPE2_RX_STATS(idx)	\
	dev_info(dev, "%s: 0x%X (%d)\n", #idx, le32_to_cpu(lmac_stats->rx_stats[idx]), le32_to_cpu(lmac_stats->rx_stats[idx]))

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_fragments_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_fragments_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_jabbers_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_jabbers_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_dummy_0_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_dummy_0_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_fcs_err_okpkt_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_fcs_err_okpkt_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_mcast_data_err_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_mcast_data_err_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_bcast_data_err_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_bcast_data_err_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_ucast_data_err_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_ucast_data_err_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_mcast_ctrl_err_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_mcast_ctrl_err_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_bcast_ctrl_err_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_bcast_ctrl_err_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_ucast_ctrl_err_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_ucast_ctrl_err_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_pause_err_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_pause_err_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_64b_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_64b_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_65to127b_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_65to127b_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_128to255b_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_128to255b_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_256to511b_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_256to511b_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_512to1023b_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_512to1023b_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_1024to1518b_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_1024to1518b_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_1519tomaxb_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_1519tomaxb_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_oversize_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_oversize_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_mcast_data_ok_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_mcast_data_ok_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_bcast_data_ok_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_bcast_data_ok_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_ucast_data_ok_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_ucast_data_ok_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_mcast_ctrl_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_mcast_ctrl_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_bcast_ctrl_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_bcast_ctrl_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_ucast_ctrl_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_ucast_ctrl_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_pause_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_pause_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_runt_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_runt_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_st_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_st_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_lenerr_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_lenerr_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_pfc_err_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_pfc_err_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_pfc_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_pfc_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_payloadoctetsok_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_payloadoctetsok_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_octetsok_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_octetsok_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_malformed_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_malformed_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_dropped_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_dropped_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_badlt_lo);
	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_badlt_hi);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_total_ptp_pkts);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_total_1step_ptp_pkts);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_total_2step_ptp_pkts);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_total_v1_ptp_pkts);

	PRINT_LMAC_TYPE2_TX_STATS(LMAC_TYPE2_cntr_tx_total_v2_ptp_pkts);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_fragments_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_fragments_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_jabbers_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_jabbers_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_dummy_0_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_dummy_0_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_fcs_err_okpkt_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_fcs_err_okpkt_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_mcast_data_err_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_mcast_data_err_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_bcast_data_err_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_bcast_data_err_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_ucast_data_err_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_ucast_data_err_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_mcast_ctrl_err_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_mcast_ctrl_err_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_bcast_ctrl_err_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_bcast_ctrl_err_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_ucast_ctrl_err_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_ucast_ctrl_err_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_pause_err_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_pause_err_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_64b_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_64b_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_65to127b_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_65to127b_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_128to255b_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_128to255b_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_256to511b_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_256to511b_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_512to1023b_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_512to1023b_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_1024to1518b_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_1024to1518b_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_1519tomaxb_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_1519tomaxb_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_oversize_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_oversize_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_mcast_data_ok_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_mcast_data_ok_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_bcast_data_ok_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_bcast_data_ok_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_ucast_data_ok_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_ucast_data_ok_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_mcast_ctrl_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_mcast_ctrl_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_bcast_ctrl_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_bcast_ctrl_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_ucast_ctrl_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_ucast_ctrl_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_pause_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_pause_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_runt_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_runt_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_st_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_st_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_lenerr_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_lenerr_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_pfc_err_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_pfc_err_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_pfc_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_pfc_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_payloadoctetsok_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_payloadoctetsok_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_octetsok_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_octetsok_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_malformed_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_malformed_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_dropped_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_dropped_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_badlt_lo);
	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_badlt_hi);

	PRINT_LMAC_TYPE2_RX_STATS(LMAC_TYPE2_cntr_rx_total_ptp_ts);
}

enum nse_status
nse_lmac_set_basic_cfg(struct nse_hw *hw)
{
	struct device *dev = nse_hw_to_dev(hw);
	enum nse_status status = NSE_SUCCESS;

	if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE) {
		nse_debug(hw, NSE_DBG_LMAC_PHY, "\t Moonstone does not need lmac_set_basic_cfg(), go to later aq_eth_set_link_ms\n");
		goto out;
	}

	if (hw->hw_conf.hw_lmac_type == NSE_HW_LMAC_TYPE_1)
		status = lmac_type1_set_basic_cfg(hw);
	else
		dev_info(dev, "[%s] Not impl in SW for hw_lmac_type=%d, wish FW early config it\n",
			 __func__, hw->hw_conf.hw_lmac_type);

out:
	return status;
}

enum nse_status
nse_lmac_set_basic_cfg_lm(struct nse_hw *hw, bool lb_ena)
{
	struct device *dev = nse_hw_to_dev(hw);
	enum nse_status status = NSE_SUCCESS;

	if (hw->hw_conf.hw_lmac_type == NSE_HW_LMAC_TYPE_1)
		status = lmac_type1_set_basic_cfg_lm(hw, lb_ena);
	else {
		dev_err(dev, "[%s] NOT impl yet or NOT support, mac_type=%d, hw_lmac_type=%d\n",
					__func__, hw->mac_type, hw->hw_conf.hw_lmac_type);
		status = NSE_ERR_NOT_IMPL;
	}

	return status;
}

void
nse_lmac_dump_stats(struct nse_hw *hw, struct nse_aqc_lmac_stats *lmac_stats)
{
	if (hw->hw_conf.hw_lmac_type == NSE_HW_LMAC_TYPE_1)
		lmac_type1_dump_stats(hw, &lmac_stats->stats_type1);
	else if (hw->hw_conf.hw_lmac_type == NSE_HW_LMAC_TYPE_2)
		lmac_type2_dump_stats(hw, &lmac_stats->stats_type2);
	else
		dev_info(nse_hw_to_dev(hw), "[%s] NOT impl or support yet\n", __func__);
}

enum nse_status
nse_aq_test_phy_startup(struct nse_hw *hw)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LMAC_PHY,
				      NSE_AQ_OPC_TEST_PHY_STARTUP);

	desc.param0 = cpu_to_le32(hw->lan_id);

	return nse_aq_send_cmd(hw, &desc, NULL, 0, NULL);
}

enum nse_status
nse_aq_test_phy_get_link_status(struct nse_hw *hw, u32 *ls, u32 *speed)
{
	struct nse_aq_desc desc;
	enum nse_status ret;

	if (nse_palladium_debug) {	/* == LMAC_PHY_STATIC_FLAG_CONSIDER_ALWAYS_LINK_UP */
		ret = 0;
		*ls = 1;
		*speed = 3;
	} else {
		nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LMAC_PHY,
					      NSE_AQ_OPC_TEST_PHY_GET_LINK_STATUS);

		desc.param0 = cpu_to_le32(hw->lan_id);

		ret = nse_aq_send_cmd(hw, &desc, NULL, 0, NULL);
		if (!ret) {
			*ls = le32_to_cpu(desc.param0);
			*speed = le32_to_cpu(desc.param1);
		}
	}

	return ret;
}

enum nse_status
nse_aq_test_phy_set_loopback(struct nse_hw *hw, u32 lb)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LMAC_PHY,
				      NSE_AQ_OPC_TEST_PHY_SET_LOOPBACK);

	desc.param0 = cpu_to_le32(hw->lan_id);
	desc.param1 = cpu_to_le32(lb);

	return nse_aq_send_cmd(hw, &desc, NULL, 0, NULL);
}

enum nse_status
nse_aq_test_phy_get_lfc_adv(struct nse_hw *hw, struct nse_aqc_fpga_phy_get_lfc_adv *adv)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LMAC_PHY,
				      NSE_AQ_OPC_TEST_PHY_GET_LFC_ADV);

	nse_aqc_fill_generic_common_hdr_dft(hw, &adv->hdr, NSE_VSI_INVAL_ID);

	return nse_aq_send_cmd(hw, &desc, adv, sizeof(*adv), NULL);
}

enum nse_status
nse_aq_test_phy_set_lfc_adv(struct nse_hw *hw, struct nse_aqc_fpga_phy_set_lfc_adv *adv)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LMAC_PHY,
				      NSE_AQ_OPC_TEST_PHY_SET_LFC_ADV);

	nse_aqc_fill_generic_common_hdr_dft(hw, &adv->hdr, NSE_VSI_INVAL_ID);

	return nse_aq_send_cmd(hw, &desc, adv, sizeof(*adv), NULL);
}

enum nse_status
nse_test_phy_set_lfc_adv(struct nse_hw *hw, enum nse_fc_mode req_mode, bool force_an, bool wait_an)
{
	struct nse_aqc_fpga_phy_set_lfc_adv *adv = NULL;
	enum nse_status status;

	adv = kzalloc(sizeof(*adv), GFP_KERNEL);
	if (!adv) {
		status = NSE_ERR_NO_MEMORY;
		goto out;
	}

	switch (req_mode) {
	case NSE_FC_LFC_NONE:
		adv->local_pause = 0;
		adv->local_asym_pause = 0;
		break;

	case NSE_FC_LFC_RX_PAUSE:
		adv->local_pause = 1;
		adv->local_asym_pause = 1;
		break;

	case NSE_FC_LFC_TX_PAUSE:
		adv->local_pause = 0;
		adv->local_asym_pause = 1;
		break;

	case NSE_FC_LFC_FULL:
		adv->local_pause = 1;
		adv->local_asym_pause = 0;
		break;

	default:
		status = NSE_ERR_NOT_SUPPORTED;
		goto out;
	}

	if (force_an)
		adv->flags = cpu_to_le32(NSE_AQC_PHY_SET_LFC_ADV_RESTART_AN);

	status = nse_aq_test_phy_set_lfc_adv(hw, adv);
	if (status)
		goto out;

	if (force_an && wait_an) {
		hw->port_info->lmac_phy_info.dyn_flags |= LMAC_PHY_DYN_FLAG_NEED_UPDATE_LINK_INFO;

		msleep(100);
	}

out:
	kfree(adv);
	return status;
}

enum nse_status
nse_aq_mdio_set_mode(struct nse_hw *hw, u32 mdio_mode)
{
	struct nse_aq_desc desc;
	struct nse_aqc_mdio_set_mode cmd = {0};
	enum nse_status status;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_MISC, NSE_AQ_OPC_MDIO_SET_MODE);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd.hdr, NSE_VSI_INVAL_ID);

	if (mdio_mode != MDIO_MODE_CL22 && mdio_mode != MDIO_MODE_CL45) {
		dev_err(nse_hw_to_dev(hw), "[%s] BAD: mdio_mode=%d, not clause22 or clause45\n",
			__func__, mdio_mode);
		status = NSE_ERR_PARAM;
		goto out;
	}

	cmd.mdio_mode = cpu_to_le32(mdio_mode);
	cmd.mdio_port = cpu_to_le32(MDIO_PORT_ALL);

	status = nse_aq_send_cmd(hw, &desc, &cmd, sizeof(cmd), NULL);

out:
	return status;
}

static enum nse_status
nse_aq_mdio_rw_reg(struct nse_hw *hw, bool rw, u32 mdio_addr, u32 mmd, u32 reg_addr, u16 *reg_val)
{
	struct nse_aq_desc desc;
	struct nse_aqc_mdio_rw_reg cmd = {0};
	enum nse_status status;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_MISC, NSE_AQ_OPC_MDIO_RW_REG);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd.hdr, NSE_VSI_INVAL_ID);

	cmd.rw = rw ? cpu_to_le32(1) : 0;

	cmd.mdio_addr = cpu_to_le32(mdio_addr);
	cmd.mmd = cpu_to_le32(mmd);
	cmd.reg_addr = cpu_to_le32(reg_addr);

	cmd.reg_val = cpu_to_le16(*reg_val);

	status = nse_aq_send_cmd(hw, &desc, &cmd, sizeof(cmd), NULL);

	if (status || cmd.result) {
		dev_err(nse_hw_to_dev(hw), "[%s] FAIL: status=%d, cmd.result=%d\n",
			__func__, status, le32_to_cpu(cmd.result));
		status = NSE_ERR_IO;
		goto out;
	}

	if (rw)
		*reg_val = le16_to_cpu(cmd.reg_val);

out:
	return status;
}

enum nse_status
nse_aq_mdio_read_reg(struct nse_hw *hw, u32 mdio_addr, u32 mmd, u32 reg_addr, u16 *reg_val)
{
	return nse_aq_mdio_rw_reg(hw, true, mdio_addr, mmd, reg_addr, reg_val);
}

enum nse_status
nse_aq_mdio_write_reg(struct nse_hw *hw, u32 mdio_addr, u32 mmd, u32 reg_addr, u16 reg_val)
{
	return nse_aq_mdio_rw_reg(hw, false, mdio_addr, mmd, reg_addr, &reg_val);
}

enum nse_status
nse_aq_led_cfg(struct nse_hw *hw, struct nse_aqc_led_cfg *led_cfg)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_MISC, NSE_AQ_OPC_LED_CFG);

	nse_aqc_fill_generic_common_hdr_dft(hw, &led_cfg->hdr, NSE_VSI_INVAL_ID);

	return nse_aq_send_cmd(hw, &desc, led_cfg, sizeof(*led_cfg), NULL);
}

static enum nse_status
nse_aq_ephy_cmd(struct nse_hw *hw, struct nse_aqc_ephy_cmd *cmd)
{
	struct nse_aq_desc desc;
	enum nse_status status;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LMAC_PHY, NSE_AQ_OPC_EPHY_CMD);

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd->hdr, NSE_VSI_INVAL_ID);

	status = nse_aq_send_cmd(hw, &desc, cmd, sizeof(*cmd), NULL);
	/* also check output result ... */
	if (!status && le32_to_cpu(cmd->result) != NSE_AQ_RC_OK) {
		dev_err(nse_hw_to_dev(hw), "[%s] FAIL: ephy_cmd->result=%d\n",
			__func__, le32_to_cpu(cmd->result));
		status = NSE_ERR_IO;
	}

	return status;
}

enum nse_status
nse_aq_ephy_cmd_sfp_tx_disable(struct nse_hw *hw, bool tx_dis)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_aqc_ephy_cmd *cmd = NULL;
	enum nse_status status;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd) {
		status = NSE_ERR_NO_MEMORY;
		goto out;
	}

	cmd->ephy_type = cpu_to_le32(EPHY_TYPE_SFP);

	cmd->sfp.cmd = cpu_to_le32(EPHY_CMD_SFP_TX_DISABLE);

	cmd->sfp.tx_disable = tx_dis ? cpu_to_le32(1) : 0;

	status = nse_aq_ephy_cmd(hw, cmd);
	if (status) {
		dev_err(dev, "[%s] FAIL: aq_ephy_cmd(), status=%d\n", __func__, status);
		goto out;
	}

out:
	kfree(cmd);

	return status;
}

/* <<SFF-8431>> / 2.5 RATE SELECT HARDWARE CONTROL */
enum nse_status
nse_aq_ephy_cmd_sfp_rate_select(struct nse_hw *hw, u32 rs0, u32 rs1)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_aqc_ephy_cmd *cmd = NULL;
	enum nse_status status;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd) {
		status = NSE_ERR_NO_MEMORY;
		goto out;
	}

	cmd->ephy_type = cpu_to_le32(EPHY_TYPE_SFP);

	cmd->sfp.cmd = cpu_to_le32(EPHY_CMD_SFP_RATE_SELECT);

	cmd->sfp.rs.rs0 = cpu_to_le32(rs0);
	cmd->sfp.rs.rs1 = cpu_to_le32(rs1);

	status = nse_aq_ephy_cmd(hw, cmd);
	if (status) {
		dev_err(dev, "[%s] FAIL: aq_ephy_cmd(), status=%d\n", __func__, status);
		goto out;
	}

out:
	kfree(cmd);

	return status;
}

enum nse_status
nse_aq_ephy_cmd_sfp_get_pin_status(struct nse_hw *hw, struct sfp_pin_status *pin_status)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_aqc_ephy_cmd *cmd = NULL;
	enum nse_status status;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd) {
		status = NSE_ERR_NO_MEMORY;
		goto out;
	}

	cmd->ephy_type = cpu_to_le32(EPHY_TYPE_SFP);

	cmd->sfp.cmd = cpu_to_le32(EPHY_CMD_SFP_GET_PIN_STATUS);

	status = nse_aq_ephy_cmd(hw, cmd);
	if (status) {
		dev_err(dev, "[%s] FAIL: aq_ephy_cmd(), status=%d\n", __func__, status);
		goto out;
	}

	pin_status->mod_abs = le32_to_cpu(cmd->sfp.pin_status.mod_abs);
	pin_status->tx_fault = le32_to_cpu(cmd->sfp.pin_status.tx_fault);
	pin_status->rx_los = le32_to_cpu(cmd->sfp.pin_status.rx_los);

out:
	kfree(cmd);

	if (status)
		pin_status->valid = false;
	else
		pin_status->valid = true;

	return status;
}

static enum nse_status
aq_ephy_cmd_sfp_read_write_bytes(struct nse_hw *hw, bool rw, bool r_in_rt,
								u8 addr, u32 mng_if_type,
								u8 bank, u8 page, u8 bytes_offset,
									u8 bytes_len,
								u8 *bytes,
									u8 *bytes_len_actually_rw)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_aqc_ephy_cmd *cmd = NULL;
	u32 bytes_len_u32;
	enum nse_status status;

	nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] rw=%d, addr=0x%X, page=%d, bytes_offset=%d, bytes_len=%d\n",
				__func__, rw, addr, page, bytes_offset, bytes_len);

	bytes_len_u32 = (u32)bytes_offset + (u32)bytes_len;
	if (bytes_len_u32 > 256) {
		dev_err(dev, "[%s] BAD: bytes_offset=%d + bytes_len=%d > 256\n",
			__func__, bytes_offset, bytes_len);
		status = NSE_ERR_PARAM;
		goto out;
	}

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd) {
		status = NSE_ERR_NO_MEMORY;
		goto out;
	}

	cmd->ephy_type = cpu_to_le32(EPHY_TYPE_SFP);

	if (rw)
		cmd->sfp.cmd = r_in_rt ? cpu_to_le32(EPHY_CMD_SFP_READ_BYTES) :
			cpu_to_le32(EPHY_CMD_SFP_READ_BYTES_IN_CBUF);
	else
		cmd->sfp.cmd = cpu_to_le32(EPHY_CMD_SFP_WRITE_BYTES);

	cmd->sfp.mng_if_type = cpu_to_le32(mng_if_type);

	cmd->sfp.rw_bytes.address = addr;
	cmd->sfp.rw_bytes.bank = bank;
	cmd->sfp.rw_bytes.page = page;
	cmd->sfp.rw_bytes.bytes_offset = bytes_offset;
	cmd->sfp.rw_bytes.bytes_len = bytes_len;

	status = nse_aq_ephy_cmd(hw, cmd);
	if (status) {
		dev_err(dev, "[%s] FAIL: aq_ephy_cmd(), status=%d\n", __func__, status);
		goto out;
	}

	*bytes_len_actually_rw = cmd->sfp.rw_bytes.bytes_len;
	if (rw && *bytes_len_actually_rw)
		memcpy(bytes, cmd->sfp.rw_bytes.bytes, *bytes_len_actually_rw);

out:
	kfree(cmd);

	return status;
}

enum nse_status
nse_aq_ephy_cmd_sfp_read_bytes(struct nse_hw *hw, bool r_in_rt,
								u8 addr, u32 mng_if_type,
								u8 bank, u8 page, u8 bytes_offset,
									u8 bytes_len,
								u8 *bytes, u8 *bytes_len_actually_r)
{
	return aq_ephy_cmd_sfp_read_write_bytes(hw, true, r_in_rt,
						addr, mng_if_type,
						bank, page, bytes_offset, bytes_len,
						bytes, bytes_len_actually_r);
}

enum nse_status
nse_aq_ephy_cmd_sfp_write_bytes(struct nse_hw *hw,
								u8 addr, u32 mng_if_type,
								u8 bank, u8 page, u8 bytes_offset,
									u8 bytes_len, u8 *bytes,
									u8 *bytes_len_actually_w)
{
	return aq_ephy_cmd_sfp_read_write_bytes(hw, false, true,
						addr, mng_if_type,
						bank, page, bytes_offset, bytes_len,
						bytes, bytes_len_actually_w);
}

enum nse_status
nse_aq_ephy_cmd_sfp_8472_addr_change(struct nse_hw *hw, u8 addr)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_aqc_ephy_cmd *cmd = NULL;
	enum nse_status status;

	nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] addr=0x%X\n", __func__, addr);

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd) {
		status = NSE_ERR_NO_MEMORY;
		goto out;
	}

	cmd->ephy_type = cpu_to_le32(EPHY_TYPE_SFP);

	cmd->sfp.cmd = cpu_to_le32(EPHY_CMD_SFP_ADDR_CHANGE);

	cmd->sfp.mng_if_type = cpu_to_le32(XSFP_MNG_IF_TYPE_SFF8472);

	cmd->sfp.addr_change.address = addr;

	status = nse_aq_ephy_cmd(hw, cmd);
	if (status) {
		dev_err(dev, "[%s] FAIL: aq_ephy_cmd(), status=%d\n", __func__, status);
		goto out;
	}

out:
	kfree(cmd);

	return status;
}

enum nse_status
nse_aq_ephy_cmd_qsfp_reset(struct nse_hw *hw)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_aqc_ephy_cmd *cmd = NULL;
	enum nse_status status;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd) {
		status = NSE_ERR_NO_MEMORY;
		goto out;
	}

	cmd->ephy_type = cpu_to_le32(EPHY_TYPE_QSFP);

	cmd->qsfp.cmd = cpu_to_le32(EPHY_CMD_QSFP_RESET);

	status = nse_aq_ephy_cmd(hw, cmd);
	if (status) {
		dev_err(dev, "[%s] FAIL: aq_ephy_cmd(), status=%d\n", __func__, status);
		goto out;
	}

out:
	kfree(cmd);

	return status;
}

enum nse_status
nse_aq_ephy_cmd_qsfp_set_lpmode(struct nse_hw *hw, bool lp)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_aqc_ephy_cmd *cmd = NULL;
	enum nse_status status;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd) {
		status = NSE_ERR_NO_MEMORY;
		goto out;
	}

	cmd->ephy_type = cpu_to_le32(EPHY_TYPE_QSFP);

	cmd->qsfp.cmd = cpu_to_le32(EPHY_CMD_QSFP_SET_LPMODE);

	cmd->qsfp.lpmode = lp ? cpu_to_le32(1) : 0;

	status = nse_aq_ephy_cmd(hw, cmd);
	if (status) {
		dev_err(dev, "[%s] FAIL: aq_ephy_cmd(), status=%d\n", __func__, status);
		goto out;
	}

out:
	kfree(cmd);

	return status;
}

enum nse_status
nse_aq_ephy_cmd_qsfp_get_pin_status(struct nse_hw *hw, struct qsfp_pin_status *pin_status)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_aqc_ephy_cmd *cmd = NULL;
	enum nse_status status;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd) {
		status = NSE_ERR_NO_MEMORY;
		goto out;
	}

	cmd->ephy_type = cpu_to_le32(EPHY_TYPE_QSFP);

	cmd->qsfp.cmd = cpu_to_le32(EPHY_CMD_QSFP_GET_PIN_STATUS);

	status = nse_aq_ephy_cmd(hw, cmd);
	if (status) {
		dev_err(dev, "[%s] FAIL: aq_ephy_cmd(), status=%d\n", __func__, status);
		goto out;
	}

	pin_status->modprsl = le32_to_cpu(cmd->qsfp.pin_status.modprsl);
	pin_status->intl = le32_to_cpu(cmd->qsfp.pin_status.intl);

out:
	kfree(cmd);

	if (status)
		pin_status->valid = false;
	else
		pin_status->valid = true;

	return status;
}

static enum nse_status
aq_ephy_cmd_qsfp_read_write_bytes(struct nse_hw *hw, bool rw, bool r_in_rt,
								u8 addr, u32 mng_if_type,
								u8 bank, u8 page, u8 bytes_offset,
									u8 bytes_len,
								u8 *bytes,
									u8 *bytes_len_actually_rw)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_aqc_ephy_cmd *cmd = NULL;
	u32 bytes_len_u32;
	enum nse_status status;

	nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] rw=%d, addr=0x%X, page=%d, bytes_offset=%d, bytes_len=%d\n",
				__func__, rw, addr, page, bytes_offset, bytes_len);

	bytes_len_u32 = (u32)bytes_offset + (u32)bytes_len;
	if (bytes_len_u32 > 256) {
		dev_err(dev, "[%s] BAD: bytes_offset=%d + bytes_len=%d > 256\n",
			__func__, bytes_offset, bytes_len);
		status = NSE_ERR_PARAM;
		goto out;
	}

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd) {
		status = NSE_ERR_NO_MEMORY;
		goto out;
	}

	cmd->ephy_type = cpu_to_le32(EPHY_TYPE_QSFP);

	if (rw)
		cmd->sfp.cmd = r_in_rt ? cpu_to_le32(EPHY_CMD_QSFP_READ_BYTES) :
			cpu_to_le32(EPHY_CMD_QSFP_READ_BYTES_IN_CBUF);
	else
		cmd->qsfp.cmd = cpu_to_le32(EPHY_CMD_QSFP_WRITE_BYTES);

	cmd->qsfp.mng_if_type = cpu_to_le32(mng_if_type);

	cmd->qsfp.rw_bytes.address = addr;
	cmd->qsfp.rw_bytes.bank = bank;
	cmd->qsfp.rw_bytes.page = page;
	cmd->qsfp.rw_bytes.bytes_offset = bytes_offset;
	cmd->qsfp.rw_bytes.bytes_len = bytes_len;

	status = nse_aq_ephy_cmd(hw, cmd);
	if (status) {
		dev_err(dev, "[%s] FAIL: aq_ephy_cmd(), status=%d\n", __func__, status);
		goto out;
	}

	*bytes_len_actually_rw = cmd->qsfp.rw_bytes.bytes_len;
	if (rw && *bytes_len_actually_rw)
		memcpy(bytes, cmd->qsfp.rw_bytes.bytes, *bytes_len_actually_rw);

out:
	kfree(cmd);

	return status;
}

enum nse_status
nse_aq_ephy_cmd_qsfp_read_bytes(struct nse_hw *hw, bool r_in_rt,
								u8 addr, u32 mng_if_type,
								u8 bank, u8 page, u8 bytes_offset,
									u8 bytes_len,
								u8 *bytes, u8 *bytes_len_actually_r)
{
	return aq_ephy_cmd_qsfp_read_write_bytes(hw, true, r_in_rt,
						 addr, mng_if_type,
						 bank, page, bytes_offset, bytes_len,
							 bytes, bytes_len_actually_r);
}

enum nse_status
nse_aq_ephy_cmd_qsfp_write_bytes(struct nse_hw *hw,
								u8 addr, u32 mng_if_type,
								u8 bank, u8 page, u8 bytes_offset,
									u8 bytes_len,
								u8 *bytes, u8 *bytes_len_actually_w)
{
	return aq_ephy_cmd_qsfp_read_write_bytes(hw, false, true,
						 addr, mng_if_type,
						 bank, page, bytes_offset, bytes_len,
							 bytes, bytes_len_actually_w);
}

/* <<SFF-8636>>
 *		/6.2.7 Rate Select
 *		/6.2.6 Control Functions (Page 00h, Bytes 86-99)	-	byte 87, 88
 */
static enum nse_status
qsfp_rate_select_sff8636(struct nse_hw *hw, u32 rx_rs0, u32 rx_rs1, u32 tx_rs0, u32 tx_rs1)
{
	/* impl by write_bytes */
	struct nse_ephy_qsfp_info *qsfp_info = &hw->port_info->lmac_phy_info.ephy_info.qsfp_info;
	u8 bytes_rs[2] = {0};
	u8 bytes_len_actually_w = 0;
	enum nse_status status = NSE_SUCCESS;

	nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] rx_rs0=%d, rx_rs1=%d, tx_rs0=%d, tx_rs1=%d, impl_rs=%d, rs_version=%d\n",
				__func__, rx_rs0, rx_rs1, tx_rs0, tx_rs1,
				qsfp_info->sff8636_info.impl_rate_select,
					qsfp_info->sff8636_info.rate_select_version);

	if (!qsfp_info->sff8636_info.impl_rate_select) {
		nse_debug(hw, NSE_DBG_LMAC_PHY,
			  "[%s] this mod does not support RS, ignore\n", __func__);
		goto out;
	}

	if (qsfp_info->sff8636_info.rate_select_version != SFF8636_RATE_SELECT_VERSION_1 &&
		qsfp_info->sff8636_info.rate_select_version != SFF8636_RATE_SELECT_VERSION_2) {
		nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] illegal rs_version=%d, ignore\n",
					__func__, qsfp_info->sff8636_info.rate_select_version);
		goto out;
	}

	if (qsfp_info->sff8636_info.rate_select_version == SFF8636_RATE_SELECT_VERSION_1) {
		if ((rx_rs0 && rx_rs1) || (tx_rs0 && tx_rs1)) {
			nse_debug(hw, NSE_DBG_LMAC_PHY,
				  "[%s] version_1 does not support rs0=rs1=1, ignore\n",
				__func__);
			goto out;
		}
	}

	if (rx_rs0)
		bytes_rs[0] |= 0xAA;
	if (rx_rs1)
		bytes_rs[0] |= 0x55;
	if (tx_rs0)
		bytes_rs[1] |= 0xAA;
	if (tx_rs1)
		bytes_rs[1] |= 0x55;

	/* SFF8636 */
	status = nse_aq_ephy_cmd_qsfp_write_bytes(hw, 0xA0, qsfp_info->mng_if_type,
						  0, 0, 87, 2, bytes_rs, &bytes_len_actually_w);
	if (status || bytes_len_actually_w != 2) {
		dev_err(nse_hw_to_dev(hw), "[%s] FAIL: aq_ephy_cmd_qsfp_write_bytes(), status=%d, bytes_len_actually_w=%d\n",
			__func__, status, bytes_len_actually_w);
		status = NSE_ERR_IO;
	}

out:
	return status;
}

enum nse_status
nse_aq_ephy_cmd_qsfp_rate_select(struct nse_hw *hw, u32 rx_rs0, u32 rx_rs1, u32 tx_rs0, u32 tx_rs1)
{
	struct nse_ephy_qsfp_info *qsfp_info = &hw->port_info->lmac_phy_info.ephy_info.qsfp_info;
	enum nse_status status = NSE_SUCCESS;

	nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] rx_rs0=%d, rx_rs1=%d, tx_rs0=%d, tx_rs1=%d\n",
				__func__, rx_rs0, rx_rs1, tx_rs0, tx_rs1);

	if (qsfp_info->pin_status.modprsl) {
		nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] mod not present, ignore\n", __func__);
		goto out;
	}

	if (qsfp_info->mng_if_type == XSFP_MNG_IF_TYPE_SFF8636)
		status = qsfp_rate_select_sff8636(hw, rx_rs0, rx_rs1, tx_rs0, tx_rs1);
	else
		nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] NOT impl for QSFP(CMIS)\n", __func__);

out:
	return status;
}

enum nse_status
nse_aq_ephy_cmd_qsfp_get_sff8636_int_status(struct nse_hw *hw,
					    struct qsfp_sff8636_int_status *int_status)
{
	struct device *dev = nse_hw_to_dev(hw);
	u8 bytes[20] = {0};
	u8 bytes_len_actually_r = 0;
	enum nse_status status = NSE_SUCCESS;

	status = nse_aq_ephy_cmd_qsfp_read_bytes(hw, true, 0xA0, XSFP_MNG_IF_TYPE_SFF8636,
											0, 0, 2, 20,
						 bytes, &bytes_len_actually_r);
	if (status || bytes_len_actually_r != 20) {
		dev_err(dev, "[%s] FAIL: aq_ephy_cmd_qsfp_read_bytes(), status=%d, bytes_len_actually_r=%d\n",
						__func__, status, bytes_len_actually_r);
		status = NSE_ERR_IO;
		goto out;
	}

	int_status->status_indicators = bytes[0];
	memcpy(int_status->interrupt_flags, &bytes[1], sizeof(int_status->interrupt_flags));

out:
	if (status)
		int_status->valid = false;
	else
		int_status->valid = true;

	return status;
}

enum nse_status
nse_aq_ephy_cmd_get_cmis_int_status(struct nse_hw *hw, struct cmis_int_status *int_status)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_ephy_info *ephy_info = &hw->port_info->lmac_phy_info.ephy_info;
	struct xsfp_cmis_info *cinfo = NULL;
	u8 *bytes = NULL;
	u8 bytes_len_out = 0;
	u8 mod_addr;
	enum nse_status (*read_bytes_func)(struct nse_hw *hw, bool r_in_rt,
					   u8 addr, u32 mng_if_type,
					   u8 bank, u8 page, u8 bytes_offset, u8 bytes_len,
					   u8 *bytes, u8 *bytes_len_actually_r);
	enum nse_status status = NSE_SUCCESS;

	nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] ephy_type=%d\n", __func__, ephy_info->ephy_type);

	if (ephy_info->ephy_type != EPHY_TYPE_SFP && ephy_info->ephy_type != EPHY_TYPE_QSFP) {
		dev_err(dev, "[%s] ephy_type=%d not right\n", __func__, ephy_info->ephy_type);
		status = NSE_ERR_PARAM;
		goto out;
	}

	bytes = kzalloc(256, GFP_KERNEL);
	if (!bytes) {
		status = NSE_ERR_NO_MEMORY;
		goto out;
	}

	mod_addr = 0xA0;

	if (ephy_info->ephy_type == EPHY_TYPE_SFP) {
		read_bytes_func = &nse_aq_ephy_cmd_sfp_read_bytes;

		cinfo = &ephy_info->sfp_info.cmis_info;

	} else {
		read_bytes_func = &nse_aq_ephy_cmd_qsfp_read_bytes;

		cinfo = &ephy_info->qsfp_info.cmis_info;
	}

	status = read_bytes_func(hw, true, mod_addr, XSFP_MNG_IF_TYPE_CMIS,
							0, 0, 3, 11, bytes, &bytes_len_out);
	if (status || bytes_len_out != 11) {
		dev_err(dev, "[%s, %d] FAIL: status=%d, bytes_len_out=%d\n",
			__func__, __LINE__, status, bytes_len_out);
		status = NSE_ERR_IO;
		goto out;
	}

	int_status->global_status = bytes[0];
	memcpy(int_status->flags_summary, &bytes[1], 4);
	memcpy(int_status->mod_level_flags, &bytes[5], 6);

	int_status->mod_fault_info = cinfo->mem_lp_up0[41];	/* lazy to ready 1 byte */

	memset(int_status->lane_specific_flags, 0, sizeof(int_status->lane_specific_flags));

	if (cinfo->mem_model)	/* Flat memory don't have Page 11h */
		goto out;

	/* don't check lane_specific_flags, we always read
	 *		Bank 0, Page 11h
	 *
	 * it is unlikely we have a CMIS module whose lane cnt > 8
	 */
	status = read_bytes_func(hw, true, mod_addr, XSFP_MNG_IF_TYPE_CMIS,
							0, 0x11, 134, 20, bytes, &bytes_len_out);
	if (status || bytes_len_out != 20) {
		dev_err(dev, "[%s, %d] FAIL: status=%d, bytes_len_out=%d\n",
			__func__, __LINE__, status, bytes_len_out);
		status = NSE_ERR_IO;
		goto out;
	}

	memcpy(int_status->lane_specific_flags, bytes, 20);

out:
	kfree(bytes);

	if (status)
		int_status->valid = false;
	else
		int_status->valid = true;

	return status;
}

enum nse_status
nse_aq_eth_get_link_status(struct nse_hw *hw, struct nse_aqc_eth_get_link_status *lk_sts)
{
	struct nse_aq_desc desc;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LMAC_PHY,
				      NSE_AQ_OPC_ETH_GET_LINK_STATUS);

	memset(lk_sts, 0, sizeof(*lk_sts));

	nse_aqc_fill_generic_common_hdr_dft(hw, &lk_sts->hdr, NSE_VSI_INVAL_ID);

	return nse_aq_send_cmd(hw, &desc, lk_sts, sizeof(*lk_sts), NULL);
}

static enum nse_status
nse_aq_eth_set_link_amber(struct nse_hw *hw, u32 speed, u64 link_type, u32 fec)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_aq_desc desc;
	struct nse_aqc_eth_set_link *cmd = NULL;
	u32 result;
	enum nse_status status = NSE_SUCCESS;

	nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] speed=0x%X, link_type=0x%lX, fec=0x%X, set_link_or_start_an_extra_flags=0x%X\n",
		  __func__, speed, (unsigned long)link_type, fec,
			  lpinfo->set_link_or_start_an_extra_flags);

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LMAC_PHY, NSE_AQ_OPC_ETH_SET_LINK);

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd) {
		status = NSE_ERR_NO_MEMORY;
		goto out;
	}

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd->hdr, NSE_VSI_INVAL_ID);

	/* add into cmd->amber.flags */
	cmd->amber.flags = cpu_to_le32(AMBER_ETH_SET_LINK_FLAG_POST_TURN_ON_LMAC |
				       AMBER_ETH_SET_LINK_FLAG_POST_TUNE_LMAC_SS |
				       lpinfo->set_link_or_start_an_extra_flags);

	/* clear it for one shot, even cmd may fail */
	lpinfo->set_link_or_start_an_extra_flags = 0;

	cmd->amber.speed = cpu_to_le32(speed);

	cmd->amber.link_type = cpu_to_le64(link_type);

	cmd->amber.fec = cpu_to_le32(fec);

	status = nse_aq_send_cmd(hw, &desc, cmd, sizeof(*cmd), NULL);
	if (status)
		dev_err(dev, "[%s] FAIL: aq_send_cmd(), status=%d\n", __func__, status);

	if (cmd->result) {	/* also check result written back */

		result = le32_to_cpu(cmd->result);

		nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] cmd->result=%d\n", __func__, result);

		if (result == NSE_AQ_RC_EINPROGRESS) {
			dev_info(dev, "[%s] in_progress consider OK\n", __func__);
			status = NSE_SUCCESS;
		} else if (result == NSE_AQ_RC_EINVAL) {
			dev_err(dev, "[%s] BAD: FW indicate invalid argument\n", __func__);
			status = NSE_ERR_PARAM;
		} else if (result == NSE_AQ_RC_ENOTSUPP) {
			dev_err(dev, "[%s] BAD: FW indicate not support this speed(0x%X) or link type(0x%lX) or fec(0x%X)\n",
							__func__, speed,
								(unsigned long)link_type, fec);
			status = NSE_ERR_NOT_SUPPORTED;
		} else {
			dev_err(dev, "[%s] un-identified cmd->result=%d, consider EIO\n",
				__func__, result);
			status = NSE_ERR_IO;
		}
	}

out:
	kfree(cmd);

	return status;
}

static enum nse_status
nse_aq_eth_set_link_ms(struct nse_hw *hw, u32 speed, u64 link_type, u32 fec)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_aq_desc desc;
	struct nse_aqc_eth_set_link *cmd = NULL;
	u32 result;
	enum nse_status status;

	nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] speed=0x%X, link_type=0x%lX, fec=0x%X\n",
		  __func__, speed, (unsigned long)link_type, fec);

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LMAC_PHY, NSE_AQ_OPC_ETH_SET_LINK);

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd) {
		status = NSE_ERR_NO_MEMORY;
		goto out;
	}

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd->hdr, NSE_VSI_INVAL_ID);

	cmd->ms.speed = cpu_to_le32(speed);

	cmd->ms.link_type = cpu_to_le64(link_type);

	cmd->ms.fec = cpu_to_le32(fec);

	nse_debug(hw, NSE_DBG_SYS, "[%s] pre: cmd->result=%d\n", __func__, cmd->result);

	status = nse_aq_send_cmd(hw, &desc, cmd, sizeof(*cmd), NULL);
	if (status)
		dev_err(dev, "[%s] FAIL: aq_send_cmd(), status=%d\n", __func__, status);

	if (cmd->result) {	/* also check result written back */

		result = le32_to_cpu(cmd->result);

		nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] cmd->result=%d\n", __func__, result);

		if (result == NSE_AQ_RC_EINPROGRESS) {
			dev_info(dev, "[%s] in_progress consider OK\n", __func__);
			status = NSE_SUCCESS;
		} else if (result == NSE_AQ_RC_EINVAL) {
			dev_err(dev, "[%s] BAD: FW indicate invalid argument\n", __func__);
			status = NSE_ERR_PARAM;
		} else if (result == NSE_AQ_RC_ENOTSUPP) {
			dev_err(dev, "[%s] BAD: FW indicate not support this speed(0x%X) or link type(0x%lX) or fec(0x%X)\n",
							__func__, speed,
								(unsigned long)link_type, fec);
			status = NSE_ERR_NOT_SUPPORTED;
		} else {
			dev_err(dev, "[%s] un-identified cmd->result=%d, consider EIO\n",
				__func__, result);
			status = NSE_ERR_IO;
		}
	}

out:
	kfree(cmd);
	return status;
}

static enum nse_status
nse_aq_eth_start_an_amber(struct nse_hw *hw, u32 speeds, u64 link_types, u32 fec_adv)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_aq_desc desc;
	struct nse_aqc_eth_start_an *cmd = NULL;
	u32 result;
	enum nse_status status;

	nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] speeds=0x%X, link_types=0x%lX, fec_adv=0x%X, set_link_or_start_an_extra_flags=0x%X\n",
		  __func__, speeds, (unsigned long)link_types, fec_adv,
			  lpinfo->set_link_or_start_an_extra_flags);

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_LMAC_PHY, NSE_AQ_OPC_ETH_START_AN);

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd) {
		status = NSE_ERR_NO_MEMORY;
		goto out;
	}

	nse_aqc_fill_generic_common_hdr_dft(hw, &cmd->hdr, NSE_VSI_INVAL_ID);

	/* add into cmd->amber.flags */
	cmd->amber.flags = cpu_to_le32(AMBER_ETH_SET_LINK_FLAG_POST_TURN_ON_LMAC |
				       AMBER_ETH_SET_LINK_FLAG_POST_TUNE_LMAC_SS |
				       lpinfo->set_link_or_start_an_extra_flags);

	/* clear it for one shot, even cmd may fail */
	lpinfo->set_link_or_start_an_extra_flags = 0;

	cmd->amber.speeds_set = cpu_to_le32(speeds);

	cmd->amber.link_types_set = cpu_to_le64(link_types);

	cmd->amber.fec_adv = cpu_to_le32(fec_adv);

	status = nse_aq_send_cmd(hw, &desc, cmd, sizeof(*cmd), NULL);
	if (status)
		dev_err(dev, "[%s] FAIL: aq_send_cmd(), status=%d\n", __func__, status);

	if (cmd->result) {	/* also check result written back */

		result = le32_to_cpu(cmd->result);

		nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] cmd->result=%d\n", __func__, result);

		if (result == NSE_AQ_RC_EINPROGRESS) {
			dev_info(dev, "[%s] in_progress consider OK\n", __func__);
			status = NSE_SUCCESS;
		} else if (result == NSE_AQ_RC_EINVAL) {
			dev_err(dev, "[%s] BAD: FW indicate invalid argument\n", __func__);
			status = NSE_ERR_PARAM;
		} else if (result == NSE_AQ_RC_ENOTSUPP) {
			dev_err(dev, "[%s] BAD: FW indicate not support this speed_set(0x%X) or link_types(0x%lX) or fec_adv(0x%X)\n",
							__func__, speeds,
								(unsigned long)link_types, fec_adv);
			status = NSE_ERR_NOT_SUPPORTED;
		} else {
			dev_err(dev, "[%s] un-identified cmd->result=%d, consider EIO\n",
				__func__, result);
			status = NSE_ERR_IO;
		}
	}

out:
	kfree(cmd);

	return status;
}

/*  if !dump_all, only dump pin status, if dump_all, then dump all status which can only be get if
 * mod is present
 */
static void
ephy_status_dump(struct nse_hw *hw, bool dump_all)
{
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *ephy_info = &lpinfo->ephy_info;
	struct device *dev = nse_hw_to_dev(hw);
	int i;

	dev_info(dev, "[%s] dump_all=%d\n", __func__, dump_all);

	if (lpinfo->static_flags & LMAC_PHY_STATIC_FLAG_EPHY_FTYPE) {
		dev_info(dev, "FTYPE:\n");
		dev_info(dev, "\t present=%d\n", ephy_info->ftype_info.status.present);
		dev_info(dev, "\t signal_ok=%d\n", ephy_info->ftype_info.status.signal_ok);

	} else if (ephy_info->ephy_type == EPHY_TYPE_SFP) {
		dev_info(dev, "SFP:\n");

		dev_info(dev, "\t mod_abs=%d\n", ephy_info->sfp_info.pin_status.mod_abs);
		dev_info(dev, "\t tx_fault=%d\n", ephy_info->sfp_info.pin_status.tx_fault);
		dev_info(dev, "\t rx_los=%d\n", ephy_info->sfp_info.pin_status.rx_los);

	} else if (ephy_info->ephy_type == EPHY_TYPE_QSFP) {
		dev_info(dev, "QSFP:\n");
		dev_info(dev, "\t modprsl=%d\n", ephy_info->qsfp_info.pin_status.modprsl);
		dev_info(dev, "\t intl=%d\n", ephy_info->qsfp_info.pin_status.intl);

		if (dump_all && !ephy_info->qsfp_info.pin_status.modprsl) {
			if (ephy_info->qsfp_info.mng_if_type == XSFP_MNG_IF_TYPE_SFF8636) {
				dev_info(dev, "\t SFF8636 int_status\n");

				dev_info(dev, "\t\t valid=%d\n",
					 ephy_info->qsfp_info.sff8636_info.int_status.valid);

				dev_info(dev, "\t\t byte[2]: status_indicators=0x%X\n",
				ephy_info->qsfp_info.sff8636_info.int_status.status_indicators);

				for (i = 0; i < 19; i++)
					dev_info(dev, "\t\t byte[%d]: interrupt_flags[%d]=0x%X\n",
		(i + 3), i, ephy_info->qsfp_info.sff8636_info.int_status.interrupt_flags[i]);

			} else if (ephy_info->qsfp_info.mng_if_type == XSFP_MNG_IF_TYPE_CMIS) {
				dev_info(dev, "\t CMIS int_status\n");

				dev_info(dev, "\t\t valid=%d\n",
					 ephy_info->qsfp_info.cmis_info.int_status.valid);

				dev_info(dev, "\t\t global_status=0x%X\n",
					 ephy_info->qsfp_info.cmis_info.int_status.global_status);

				for (i = 0; i < 4; i++)
					dev_info(dev, "\t\t flags_summary[%d]=0x%X\n", i,
					ephy_info->qsfp_info.cmis_info.int_status.flags_summary[i]);

				for (i = 0; i < 6; i++)
					dev_info(dev, "\t\t mod_level_flags[%d]=0x%X\n", i,
				ephy_info->qsfp_info.cmis_info.int_status.mod_level_flags[i]);

				dev_info(dev, "\t\t mod_fault_info=0x%X\n",
					 ephy_info->qsfp_info.cmis_info.int_status.mod_fault_info);

				for (i = 0; i < 20; i++)
					dev_info(dev, "\t\t lane_specific_flags[%d]=0x%X\n", i,
				ephy_info->qsfp_info.cmis_info.int_status.lane_specific_flags[i]);
			}
		}
	} else {
		dev_info(dev, "\t ephy_type=%d unknown or not impl\n", ephy_info->ephy_type);
	}
}

static enum nse_status
ephy_status_get_1st(struct nse_hw *hw)	/* get pin status */
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *ephy_info = &lpinfo->ephy_info;
	enum nse_status status = NSE_SUCCESS;

	nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] ephy_type=%d\n", __func__, ephy_info->ephy_type);

	if (lpinfo->static_flags & LMAC_PHY_STATIC_FLAG_EPHY_FTYPE) {
		ephy_info->ftype_info.status.valid = true;

		ephy_info->ftype_info.status.present = 1;

	} else if (ephy_info->ephy_type == EPHY_TYPE_SFP) {
		status = nse_aq_ephy_cmd_sfp_get_pin_status(hw, &ephy_info->sfp_info.pin_status);
		if (status)
			dev_err(dev, "[%s] FAIL: aq_ephy_cmd_sfp_get_pin_status(), status=%d\n",
				__func__, status);

	} else if (ephy_info->ephy_type == EPHY_TYPE_QSFP) {
		status = nse_aq_ephy_cmd_qsfp_get_pin_status(hw, &ephy_info->qsfp_info.pin_status);
		if (status)
			dev_err(dev, "[%s] FAIL: aq_ephy_cmd_qsfp_get_pin_status(), status=%d\n",
				__func__, status);

	} else {
		nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] ephy_type=%d not impl\n",
			  __func__, ephy_info->ephy_type);
	}

	return status;
}

static enum nse_status
ephy_status_get_2nd(struct nse_hw *hw)	/* get some status to determine if signal OK */
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *ephy_info = &lpinfo->ephy_info;
	enum nse_status status = NSE_SUCCESS;

	nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] ephy_type=%d\n", __func__, ephy_info->ephy_type);

	if (lpinfo->static_flags & LMAC_PHY_STATIC_FLAG_EPHY_FTYPE) {
		ephy_info->ftype_info.status.valid = true;

		ephy_info->ftype_info.status.signal_ok = 1;

	} else if (ephy_info->ephy_type == EPHY_TYPE_SFP) {
		/* SFP signal OK is determined by SFP pin_status --- even if it is CMIS */
		//if (ephy_info->sfp_info.mng_if_type == XSFP_MNG_IF_TYPE_SFF8472) {

		nse_debug(hw, NSE_DBG_LMAC_PHY,
	"[%s] do nothing for SFP, pin_status got in status_get_1st() was just enough\n", __func__);

	} else if (ephy_info->ephy_type == EPHY_TYPE_QSFP) {
		if (ephy_info->qsfp_info.mng_if_type == XSFP_MNG_IF_TYPE_SFF8636) {
			status = nse_aq_ephy_cmd_qsfp_get_sff8636_int_status(hw,
				&ephy_info->qsfp_info.sff8636_info.int_status);
			if (status)
				dev_err(dev,
	"[%s] FAIL: aq_ephy_cmd_qsfp_get_sff8636_int_status(), status=%d\n", __func__, status);

		} else if (ephy_info->qsfp_info.mng_if_type == XSFP_MNG_IF_TYPE_CMIS) {
			status = nse_aq_ephy_cmd_get_cmis_int_status(hw,
				&ephy_info->qsfp_info.cmis_info.int_status);
			if (status)
				dev_err(dev,
	"[%s] FAIL: aq_ephy_cmd_get_cmis_int_status( QSFP ), status=%d\n", __func__, status);
		}

	} else {
		nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] ephy_type=%d not impl\n",
			  __func__, ephy_info->ephy_type);
	}

	return status;
}

static bool
ephy_status_is_module_present(struct nse_hw *hw, bool status_new_or_old)
{
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *ephy_info = &lpinfo->ephy_info;
	bool ret = false;

	if (lpinfo->static_flags & LMAC_PHY_STATIC_FLAG_EPHY_FTYPE) {
		if (status_new_or_old)
			ret = ephy_info->ftype_info.status.valid &&
					ephy_info->ftype_info.status.present;
		else
			ret = ephy_info->ftype_info.status_old.valid &&
					ephy_info->ftype_info.status_old.present;

	} else if (ephy_info->ephy_type == EPHY_TYPE_SFP) {
		if (status_new_or_old)
			ret = ephy_info->sfp_info.pin_status.valid &&
					!ephy_info->sfp_info.pin_status.mod_abs;
		else
			ret = ephy_info->sfp_info.pin_status_old.valid &&
					!ephy_info->sfp_info.pin_status_old.mod_abs;

	} else if (ephy_info->ephy_type == EPHY_TYPE_QSFP) {
		if (status_new_or_old)
			ret = ephy_info->qsfp_info.pin_status.valid &&
					!ephy_info->qsfp_info.pin_status.modprsl;
		else
			ret = ephy_info->qsfp_info.pin_status_old.valid &&
					!ephy_info->qsfp_info.pin_status_old.modprsl;

	} else {	/* unknown ephy_type, consider always present */

		ret = true;
	}

	return ret;
}

static bool
ephy_status_is_signal_ok_cmis(struct nse_hw *hw, struct xsfp_cmis_info *cmis_info,
			      bool status_new_or_old)
{
	struct cmis_int_status *sts = NULL;
	bool ret = false;
	u32 val;

	nse_debug(hw, NSE_DBG_LMAC_PHY_DETAIL, "[%s] status_new_or_old=%d\n",
		  __func__, status_new_or_old);

	sts = status_new_or_old ? &cmis_info->int_status : &cmis_info->int_status_old;

	if (!sts->valid) {
		nse_debug(hw, NSE_DBG_LMAC_PHY_DETAIL,
			  "[%s, %d] not OK: valid\n", __func__, __LINE__);
		goto out;
	}

	val = ((sts->global_status & 0xE) >> 1);	/* Bits: 3-1 - ModuleState */
	if (val != 0x3) {
		nse_debug(hw, NSE_DBG_LMAC_PHY_DETAIL, "[%s, %d] not OK: ModuleState=%X\n",
			  __func__, __LINE__, val);
		goto out;
	}

	val = (sts->mod_level_flags[0] & 0x6);
	if (val) {
		nse_debug(hw, NSE_DBG_LMAC_PHY_DETAIL, "[%s, %d] not OK: DataPathFirmwareErrorFlag, ModuleFirmwareErrorFlag=%X\n", __func__, __LINE__, val);
		goto out;
	}

	if (sts->mod_fault_info) {
		nse_debug(hw, NSE_DBG_LMAC_PHY_DETAIL, "[%s, %d] not OK: ModuleFaultCause=%X\n",
			  __func__, __LINE__, sts->mod_fault_info);
		goto out;
	}

	if (sts->lane_specific_flags[1]) {
		nse_debug(hw, NSE_DBG_LMAC_PHY_DETAIL, "[%s, %d] not OK: TX Failure Flag=%X\n",
			  __func__, __LINE__, sts->lane_specific_flags[1]);
		goto out;
	}

	if (sts->lane_specific_flags[2]) {
		nse_debug(hw, NSE_DBG_LMAC_PHY_DETAIL, "[%s, %d] not OK: TX LOS Flag=%X\n",
			  __func__, __LINE__, sts->lane_specific_flags[2]);
		goto out;
	}

	if (sts->lane_specific_flags[13]) {
		nse_debug(hw, NSE_DBG_LMAC_PHY_DETAIL, "[%s, %d] not OK: RX LOS Flag=%X\n",
			  __func__, __LINE__, sts->lane_specific_flags[13]);
		goto out;
	}

	ret = true;

out:
	return ret;
}

static bool
/* media inserted, and signal OK */
ephy_status_is_signal_ok(struct nse_hw *hw, bool status_new_or_old)
{
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *ephy_info = &lpinfo->ephy_info;
	struct xsfp_cmis_info *cmis_info = NULL;
	bool ret = false;

	if (lpinfo->static_flags & LMAC_PHY_STATIC_FLAG_EPHY_FTYPE) {
		if (status_new_or_old)
			ret = ephy_info->ftype_info.status.valid &&
					ephy_info->ftype_info.status.signal_ok;
		else
			ret = ephy_info->ftype_info.status_old.valid &&
					ephy_info->ftype_info.status_old.signal_ok;

	} else if (ephy_info->ephy_type == EPHY_TYPE_SFP) {
		if (status_new_or_old)
			ret = ephy_info->sfp_info.pin_status.valid &&
					!ephy_info->sfp_info.pin_status.tx_fault &&
					!ephy_info->sfp_info.pin_status.rx_los;
		else
			ret = ephy_info->sfp_info.pin_status_old.valid &&
					!ephy_info->sfp_info.pin_status_old.tx_fault &&
					!ephy_info->sfp_info.pin_status_old.rx_los;

	} else if (ephy_info->ephy_type == EPHY_TYPE_QSFP) {
		if (ephy_info->qsfp_info.mng_if_type == XSFP_MNG_IF_TYPE_SFF8636) {
			if (status_new_or_old) {
				if (ephy_info->qsfp_info.sff8636_info.int_status.valid) {
					if (ephy_info->qsfp_info.sff8636_info.int_status.interrupt_flags[0] ||
						ephy_info->qsfp_info.sff8636_info.int_status.interrupt_flags[1])
						ret = false;
					else
						ret = true;
				} else
					ret = false;

			} else {
				if (ephy_info->qsfp_info.sff8636_info.int_status_old.valid) {
					if (ephy_info->qsfp_info.sff8636_info.int_status_old.interrupt_flags[0] ||
						ephy_info->qsfp_info.sff8636_info.int_status_old.interrupt_flags[1])
						ret = false;
					else
						ret = true;
				} else
					ret = false;
			}

		} else if (ephy_info->qsfp_info.mng_if_type == XSFP_MNG_IF_TYPE_CMIS) {
			cmis_info = &ephy_info->qsfp_info.cmis_info;

			ret = ephy_status_is_signal_ok_cmis(hw, cmis_info, status_new_or_old);
		}

	} else {
		ret = true;
	}

	return ret;
}

static void ephy_status_sync_old_new(struct nse_hw *hw)
{
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *ephy_info = &lpinfo->ephy_info;

	if (lpinfo->static_flags & LMAC_PHY_STATIC_FLAG_EPHY_FTYPE) {
		memcpy(&ephy_info->ftype_info.status_old, &ephy_info->ftype_info.status,
		       sizeof(ephy_info->ftype_info.status));

	} else if (ephy_info->ephy_type == EPHY_TYPE_SFP) {
		memcpy(&ephy_info->sfp_info.pin_status_old, &ephy_info->sfp_info.pin_status,
		       sizeof(ephy_info->sfp_info.pin_status));

		memcpy(&ephy_info->sfp_info.cmis_info.int_status_old,
				&ephy_info->sfp_info.cmis_info.int_status,
					sizeof(ephy_info->sfp_info.cmis_info.int_status));

	} else if (ephy_info->ephy_type == EPHY_TYPE_QSFP) {
		memcpy(&ephy_info->qsfp_info.pin_status_old, &ephy_info->qsfp_info.pin_status,
		       sizeof(ephy_info->qsfp_info.pin_status));

		memcpy(&ephy_info->qsfp_info.sff8636_info.int_status_old,
				&ephy_info->qsfp_info.sff8636_info.int_status,
					sizeof(ephy_info->qsfp_info.sff8636_info.int_status));

		memcpy(&ephy_info->qsfp_info.cmis_info.int_status_old,
				&ephy_info->qsfp_info.cmis_info.int_status,
					sizeof(ephy_info->qsfp_info.cmis_info.int_status));
	}
}

static void
ephy_reset_info(struct nse_hw *hw)
{
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *ephy_info = &lpinfo->ephy_info;

	ephy_info->is_supported_mod = false;

	ephy_info->mod_supported_link_speeds = 0;
	ephy_info->mod_supported_link_types = 0;
	ephy_info->mod_media_type = 0;
	ephy_info->mod_supported_fec = FEC_OFF;
	ephy_info->mod_an_supported = false;

	ephy_info->cur_temperature_valid = false;

	memset(&ephy_info->mod_lks, 0, sizeof(ephy_info->mod_lks));

	if (lpinfo->static_flags & LMAC_PHY_STATIC_FLAG_EPHY_FTYPE) {
		memset(&ephy_info->ftype_info, 0, sizeof(ephy_info->ftype_info));

	} else if (ephy_info->ephy_type == EPHY_TYPE_SFP) {
		memset(&ephy_info->sfp_info, 0, sizeof(ephy_info->sfp_info));

		/* replaced by:
		 *		pin_status / pin_status_old -> valid = false;
		 */

	} else if (ephy_info->ephy_type == EPHY_TYPE_QSFP) {
		memset(&ephy_info->qsfp_info, 0, sizeof(ephy_info->qsfp_info));

		/* replaced by:
		 *		pin_status / pin_status_old -> valid = false;
		 *
		 *		in_status / int_status_old -> valid = false;
		 */
	}
}

void nse_lmac_phy_ephy_reset_info(struct nse_hw *hw)
{
	ephy_reset_info(hw);
}

static enum nse_status
ephy_mem_read_basic_cmis(struct nse_hw *hw, u8 *bytes, u32 ephy_type)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *ephy_info = &lpinfo->ephy_info;
	struct xsfp_cmis_info *cinfo = NULL;
	u8 bytes_len_out = 0;
	u8 mod_addr;
	enum nse_status (*read_bytes_func)(struct nse_hw *hw, bool r_in_rt,
					   u8 addr, u32 mng_if_type,
					   u8 bank, u8 page, u8 bytes_offset, u8 bytes_len,
					   u8 *bytes, u8 *bytes_len_actually_r);
	enum nse_status status = NSE_SUCCESS;

	nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] ephy_type=%d\n", __func__, ephy_type);

	if (ephy_type != EPHY_TYPE_SFP && ephy_type != EPHY_TYPE_QSFP) {
		dev_err(dev, "[%s] BAD: ephy_type=%d, CMIS only work for SFP, QSFP\n",
			__func__, ephy_type);
		status = NSE_ERR_PARAM;
		goto out;
	}

	mod_addr = 0xA0;

	if (ephy_type == EPHY_TYPE_SFP) {
		read_bytes_func = &nse_aq_ephy_cmd_sfp_read_bytes;

		cinfo = &ephy_info->sfp_info.cmis_info;

	} else {
		read_bytes_func = &nse_aq_ephy_cmd_qsfp_read_bytes;

		cinfo = &ephy_info->qsfp_info.cmis_info;
	}

	/* Table 8-3 Lower Memory Overview --- skip some fields not important
	 */

	/* bytes: 0 - 41 */
	status = read_bytes_func(hw, false, mod_addr, XSFP_MNG_IF_TYPE_CMIS,
							0, 0, 0, 42, &bytes[0], &bytes_len_out);
	if (status || bytes_len_out != 42) {
		dev_err(dev, "[%s, %d] FAIL: status=%d, bytes_len_out=%d\n",
			__func__, __LINE__, status, bytes_len_out);
		status = NSE_ERR_IO;
		goto out;
	}

	/* bytes: 85 - 117 */
	status = read_bytes_func(hw, false, mod_addr, XSFP_MNG_IF_TYPE_CMIS,
							0, 0, 85, 33, &bytes[85], &bytes_len_out);
	if (status || bytes_len_out != 33) {
		dev_err(dev, "[%s, %d] FAIL: status=%d, bytes_len_out=%d\n",
			__func__, __LINE__, status, bytes_len_out);
		status = NSE_ERR_IO;
		goto out;
	}

	/* Table 8-22 Page 00h Overview --- skip some fields not important
	 */

	/* bytes: 128 - 212 */
	status = read_bytes_func(hw, false, mod_addr, XSFP_MNG_IF_TYPE_CMIS,
							0, 0, 128, 85, &bytes[128], &bytes_len_out);
	if (status || bytes_len_out != 85) {
		dev_err(dev, "[%s, %d] FAIL: status=%d, bytes_len_out=%d\n",
			__func__, __LINE__, status, bytes_len_out);
		status = NSE_ERR_IO;
		goto out;
	}

	memcpy(cinfo->mem_lp_up0, bytes, 256);

	cinfo->mem_model = cinfo->mem_lp_up0[2] & BIT(7);

	if (cinfo->mem_model)	/* Flat Memory does not have more pages */
		goto out;

	/* Table 8-36 Page 01h Overview
	 */

	/* bytes: 128 - 158 */
	status = read_bytes_func(hw, false, mod_addr, XSFP_MNG_IF_TYPE_CMIS,
							0, 1, 128, 31, &bytes[128], &bytes_len_out);
	if (status || bytes_len_out != 31) {
		dev_err(dev, "[%s, %d] FAIL: status=%d, bytes_len_out=%d\n",
			__func__, __LINE__, status, bytes_len_out);
		status = NSE_ERR_IO;
		goto out;
	}

	memcpy(cinfo->mem_up1, &bytes[128], 31);

out:
	return status;
}

static enum nse_status
ephy_mem_read_basic_sfp(struct nse_hw *hw, u8 *bytes)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *ephy_info = &lpinfo->ephy_info;
	u8 bytes_len_out = 0;
	enum nse_status status = NSE_SUCCESS;

	status = nse_aq_ephy_cmd_sfp_read_bytes(hw, false, 0xA0, XSFP_MNG_IF_TYPE_UNKNOWN,
											0, 0, 0, 1,
						bytes, &bytes_len_out);
	if (status || bytes_len_out != 1) {
		dev_err(dev, "[%s] FAIL: aq_ephy_cmd_sfp_read_bytes(dev_id), status=%d, bytes_len_out=%d\n",
						__func__, status, bytes_len_out);
		status = NSE_ERR_IO;
		goto out;
	}

	ephy_info->sfp_info.dev_id = bytes[0];

	ephy_info->sfp_info.mng_if_type = is_sff_dev_id_is_cmis(bytes[0]) ?
		XSFP_MNG_IF_TYPE_CMIS : XSFP_MNG_IF_TYPE_SFF8472;

	if (ephy_info->sfp_info.dev_id != SFF_DEV_ID_SFP_SFF8472 &&
		ephy_info->sfp_info.dev_id != SFF_DEV_ID_SFP_PLUS_CMIS) {
		dev_err(dev, "[%s] BAD: dev_id=%d, not SFP\n",
			__func__, ephy_info->sfp_info.dev_id);
		status = NSE_ERR_NOT_SUPPORTED;
		goto out;
	}

	/* CMIS read logic
	 */
	if (ephy_info->sfp_info.mng_if_type == XSFP_MNG_IF_TYPE_CMIS) {
		status = ephy_mem_read_basic_cmis(hw, bytes, EPHY_TYPE_SFP);

		if (status)
			dev_err(dev, "[%s] FAIL: mem_read_basic_cmis(), status=%d\n",
							__func__, status);
		goto out;
	}

	/* SFF-8472 read logic
	 */

	status = nse_aq_ephy_cmd_sfp_read_bytes(hw, false, 0xA0, ephy_info->sfp_info.mng_if_type,
											0, 0, 0,
												128,
						bytes, &bytes_len_out);
	if (status || bytes_len_out != 128) {
		dev_err(dev, "[%s] FAIL: aq_ephy_cmd_sfp_read_bytes(rest), status=%d, bytes_len_out=%d\n",
						__func__, status, bytes_len_out);
		goto out;
	}

	memcpy(ephy_info->sfp_info.sff8472_info.mem_a0, bytes, 128);

out:
	return status;
}

static enum nse_status
ephy_mem_read_basic_qsfp(struct nse_hw *hw, u8 *bytes)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *ephy_info = &lpinfo->ephy_info;
	u8 bytes_len_out = 0;
	enum nse_status status = NSE_SUCCESS;

	status = nse_aq_ephy_cmd_qsfp_read_bytes(hw, false, 0xA0, XSFP_MNG_IF_TYPE_UNKNOWN,
											0, 0, 0, 1,
						 bytes, &bytes_len_out);
	if (status || bytes_len_out != 1) {
		dev_err(dev, "[%s] FAIL: aq_ephy_cmd_qsfp_read_bytes(dev_id), status=%d, bytes_len_out=%d\n",
						__func__, status, bytes_len_out);
		status = NSE_ERR_IO;
		goto out;
	}

	ephy_info->qsfp_info.dev_id = bytes[0];

	ephy_info->qsfp_info.mng_if_type = is_sff_dev_id_is_cmis(bytes[0]) ?
		XSFP_MNG_IF_TYPE_CMIS : XSFP_MNG_IF_TYPE_SFF8636;

	if (ephy_info->qsfp_info.dev_id != SFF_DEV_ID_QSFP &&
		ephy_info->qsfp_info.dev_id != SFF_DEV_ID_QSFP_PLUS &&
		ephy_info->qsfp_info.dev_id != SFF_DEV_ID_QSFP28 &&
		ephy_info->qsfp_info.dev_id != SFF_DEV_ID_QSFP_PLUS_CMIS) {
		dev_err(dev, "[%s] BAD: QSFP dev_id=%d not supported.\n",
			__func__, ephy_info->qsfp_info.dev_id);
		status = NSE_ERR_NOT_SUPPORTED;
		goto out;
	}

	/* CMIS read logic
	 */
	if (ephy_info->qsfp_info.mng_if_type == XSFP_MNG_IF_TYPE_CMIS) {
		status = ephy_mem_read_basic_cmis(hw, bytes, EPHY_TYPE_QSFP);

		if (status)
			dev_err(dev, "[%s] FAIL: mem_read_basic_cmis(), status=%d\n",
							__func__, status);
		goto out;
	}

	/* SFF-8636 read logic
	 */

	status = nse_aq_ephy_cmd_qsfp_read_bytes(hw, false, 0xA0, ephy_info->qsfp_info.mng_if_type,
											0, 0, 1, 2,
						 &bytes[1], &bytes_len_out);

	if (status || bytes_len_out != 2) {
		dev_err(dev, "[%s] FAIL: aq_ephy_cmd_qsfp_read_bytes(status_indicators), status=%d, bytes_len_out=%d\n",
						__func__, status, bytes_len_out);
		status = NSE_ERR_IO;
		goto out;
	}

	/* skip read 6.2.3 Interrupt Flags (Page 00h, Bytes 3-21) because its bits is read-clear */

	status = nse_aq_ephy_cmd_qsfp_read_bytes(hw, false, 0xA0, ephy_info->qsfp_info.mng_if_type,
											0, 0, 22,
												234,
						 &bytes[22], &bytes_len_out);
	if (status || bytes_len_out != 234) {
		dev_err(dev, "[%s] FAIL: aq_ephy_cmd_qsfp_read_bytes(rest), status=%d, bytes_len_out=%d\n",
						__func__, status, bytes_len_out);
		status = NSE_ERR_IO;
		goto out;
	}

	memcpy(ephy_info->qsfp_info.sff8636_info.mem_lp_up0, bytes, 256);

out:
	return status;
}

static enum nse_status
ephy_mem_read_basic(struct nse_hw *hw)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *ephy_info = &lpinfo->ephy_info;
	u8 *bytes = NULL;
	enum nse_status status = NSE_SUCCESS;

	nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] ephy_type=%d\n", __func__, ephy_info->ephy_type);

	/* also includes ephy_type == EPHY_TYPE_GEN_1G */
	if (lpinfo->static_flags & LMAC_PHY_STATIC_FLAG_EPHY_FTYPE) {
		nse_debug(hw, NSE_DBG_LMAC_PHY,
			  "[%s] skip for STATIC_FLAG_EPHY_FTYPE\n", __func__);
		goto out;
	}

	bytes = kzalloc(256, GFP_KERNEL);
	if (!bytes) {
		status = NSE_ERR_NO_MEMORY;
		goto out;
	}

	if (ephy_info->ephy_type == EPHY_TYPE_SFP) {
		status = ephy_mem_read_basic_sfp(hw, bytes);

	} else if (ephy_info->ephy_type == EPHY_TYPE_QSFP) {
		status = ephy_mem_read_basic_qsfp(hw, bytes);

	} else {
		dev_err(dev, "[%s] FAIL: not impl for ephy_type=%d\n",
			__func__, ephy_info->ephy_type);
		status = NSE_ERR_NOT_IMPL;
	}

out:
	kfree(bytes);

	return status;
}

static void ephy_mem_dump_basic_raw_sfp_sff8472(struct nse_hw *hw, struct nse_ephy_info *ephy_info)
{
	struct device *dev = nse_hw_to_dev(hw);
	u8 *m = ephy_info->sfp_info.sff8472_info.mem_a0;
	char str[32];

	dev_info(dev, "SFP(SFF8472) mem - A0h\n");

	dev_info(dev, "\t [0] id: %X\n", m[0]);
	dev_info(dev, "\t [1] ext id: %X\n", m[1]);
	dev_info(dev, "\t [2] connector: %X\n", m[2]);

	dev_info(dev, "\t [3] 10g_eth_and_ib_compliance: %X\n", m[3]);
	dev_info(dev, "\t [6] eth_compliance: %X\n", m[6]);
	dev_info(dev, "\t [7] channel link length and channel tech: %X\n", m[7]);
	dev_info(dev, "\t [8] channel tech and cable tech: %X\n", m[8]);
	dev_info(dev, "\t [9] channel transmission media: %X\n", m[9]);
	dev_info(dev, "\t [10] channel speed: %X\n", m[10]);

	dev_info(dev, "\t [11] encoding: %X\n", m[11]);
	dev_info(dev, "\t [12] signaling rate,nominal: %X\n", m[12]);
	dev_info(dev, "\t [13] rate identifier: %X\n", m[13]);

	dev_info(dev, "\t [14] length(SMF, km): %X\n", m[14]);
	dev_info(dev, "\t [15] length(SMF): %X\n", m[15]);
	dev_info(dev, "\t [16] length(50um): %X\n", m[16]);
	dev_info(dev, "\t [17] length(62.5um): %X\n", m[17]);
	dev_info(dev, "\t [18] length(OM4 or copper cable): %X\n", m[18]);
	dev_info(dev, "\t [19] length(OM3): %X\n", m[19]);

	memset(str, 0, 32);
	memcpy(str, &m[20], 16);
	dev_info(dev, "\t [20-35] vendor name: %s\n", str);

	dev_info(dev, "\t [36] ext compliance: %X\n", m[36]);

	dev_info(dev, "\t [37-39] vendor OUI: %X %X %X\n", m[37], m[38], m[39]);

	memset(str, 0, 32);
	memcpy(str, &m[56], 4);
	dev_info(dev, "\t [56-59] vendor rev: %s\n", str);

	dev_info(dev, "\t [60-61] wave length: %X %X\n", m[60], m[61]);

	dev_info(dev, "\t [62] channel speed 2: %X\n", m[62]);

	dev_info(dev, "\t [64-65] options: %X %X\n", m[64], m[65]);

	dev_info(dev, "\t [66] BR,max: %X\n", m[66]);
	dev_info(dev, "\t [67] BR,min: %X\n", m[67]);

	memset(str, 0, 32);
	memcpy(str, &m[68], 16);
	dev_info(dev, "\t [68-83] vendor SN: %s\n", str);

	memset(str, 0, 32);
	memcpy(str, &m[84], 8);
	dev_info(dev, "\t [84-91] date code: %s\n", str);

	dev_info(dev, "\t [92] diagnostic monitoring type: %X\n", m[92]);
	dev_info(dev, "\t [93] enhanced options: %X\n", m[93]);
	dev_info(dev, "\t [94] SFF-8472 compliance: %X\n", m[94]);
}

static void ephy_mem_dump_basic_raw_qsfp_sff8636(struct nse_hw *hw, struct nse_ephy_info *ephy_info)
{
	struct device *dev = nse_hw_to_dev(hw);
	u8 *m = ephy_info->qsfp_info.sff8636_info.mem_lp_up0;
	char str[32];

	dev_info(dev, "QSFP(SFF8636) mem - A0h - lower page\n");

	dev_info(dev, "\t [0] id: %X\n", m[0]);
	dev_info(dev, "\t [1] rev compliance: %X\n", m[1]);
	dev_info(dev, "\t [2] status: %X\n", m[2]);

	dev_info(dev, "\t [100] M-Tx/M-Rx Mask: %X\n", m[100]);
	dev_info(dev, "\t [101] M-Tx Adapt EQ Fault / Transmitter Fault Mask: %X\n", m[101]);
	dev_info(dev, "\t [102] M-Tx/M-Rx CDR LOL Mask: %X\n", m[102]);
	dev_info(dev, "\t [103] M-Temp Mask: %X\n", m[103]);
	dev_info(dev, "\t [104] M-Vcc Mask: %X\n", m[104]);

	dev_info(dev, "QSFP mem(SFF8636) - A0h - upper page 0\n");

	dev_info(dev, "\t [128] id: %X\n", m[128]);
	dev_info(dev, "\t [129] ext id: %X\n", m[129]);
	dev_info(dev, "\t [130] connector: %X\n", m[130]);

	dev_info(dev, "\t [131] 10_40_100G_eth_compliance: %X\n", m[131]);
	dev_info(dev, "\t [131] 1G_eth_compliance: %X\n", m[134]);

	dev_info(dev, "\t [135] channel link length and channel tech: %X\n", m[135]);
	dev_info(dev, "\t [136] channel tech: %X\n", m[136]);
	dev_info(dev, "\t [137] channel transmission media and mod cap: %X\n", m[137]);
	dev_info(dev, "\t [138] channel speed: %X\n", m[138]);

	dev_info(dev, "\t [139] encoding: %X\n", m[139]);
	dev_info(dev, "\t [140] BR, nominal: %X\n", m[140]);
	dev_info(dev, "\t [141] ext rate select compliance: %X\n", m[141]);

	dev_info(dev, "\t [145] Length (OM1) or Copper Cable Attenuation: %X\n", m[145]);
	dev_info(dev, "\t [146] Length: Cable Assembly or Optical Fiber (OM4): %X\n", m[146]);
	dev_info(dev, "\t [147] Device Technology: %X\n", m[147]);

	memset(str, 0, 32);
	memcpy(str, &m[148], 16);
	dev_info(dev, "\t [148-163] vendor name: %s\n", str);

	dev_info(dev, "\t [165-167] vendor OUI: %X %X %X\n", m[165], m[166], m[167]);

	memset(str, 0, 32);
	memcpy(str, &m[168], 16);
	dev_info(dev, "\t [168-183] vendor PN: %s\n", str);

	memset(str, 0, 32);
	memcpy(str, &m[184], 2);
	dev_info(dev, "\t [184-185] vendor rev: %s\n", str);

	dev_info(dev, "\t [192] ext compliance: %X\n", m[192]);

	dev_info(dev, "\t [193-195] options: %X %X %X\n", m[193], m[194], m[195]);

	memset(str, 0, 32);
	memcpy(str, &m[196], 16);
	dev_info(dev, "\t [196-211] vendor SN: %s\n", str);

	memset(str, 0, 32);
	memcpy(str, &m[212], 8);
	dev_info(dev, "\t [212-219] date code: %s\n", str);

	dev_info(dev, "\t [220] diagnostic monitoring type: %X\n", m[220]);

	dev_info(dev, "\t [221] enhanced options: %X\n", m[221]);
}

static void ephy_mem_dump_basic_raw_cmis(struct nse_hw *hw,
					 struct nse_ephy_info *ephy_info, u32 ephy_type)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct xsfp_cmis_info *ci;
	u8 *m;
	char str[32];
	int i = 0, j = 0;

	if (ephy_type == EPHY_TYPE_SFP)
		ci = &ephy_info->sfp_info.cmis_info;
	else
		ci = &ephy_info->qsfp_info.cmis_info;

	m = ci->mem_lp_up0;

	dev_info(dev, "%s(CMIS) mem - lower page\n", (ephy_type == EPHY_TYPE_SFP) ? "SFP" : "QSFP");

	dev_info(dev, "\t [0] SFF8024Identifier: %X\n", m[0]);
	dev_info(dev, "\t [1] CmisRevision: %X\n", m[1]);
	dev_info(dev, "\t [2] : %X\n", m[2]);
	dev_info(dev, "\t [3] Global Status: %X\n", m[3]);
	dev_info(dev, "\t [39-40] Module Active Firmware Version: %X, %X\n", m[39], m[40]);
	dev_info(dev, "\t [41] ModuleFaultCause: %X\n", m[41]);

	dev_info(dev, "\t [85] MediaType: %X\n", m[85]);

	i = 1;
	j = 86;
	for (i = 1; i <= 8; i++) {
		dev_info(dev, "\t [%d] HostInterfaceIDApp%d: %X\n", j, i, m[j]);
		j++;
		dev_info(dev, "\t [%d] MediaInterfaceID%d: %X\n", j, i, m[j]);
		j++;
		dev_info(dev, "\t [%d] HostLaneCountApp%d,  MediaLaneCountApp%d: %X\n",
			 j, i, i, m[j]);
		j++;
		dev_info(dev, "\t [%d] HostLaneAssignmentOptionsApp%d: %X\n", j, i, m[j]);
		j++;
	}

	dev_info(dev, "%s(CMIS) mem - page 00\n", (ephy_type == EPHY_TYPE_SFP) ? "SFP" : "QSFP");

	memset(str, 0, 32);
	memcpy(str, &m[129], 16);
	dev_info(dev, "\t [129-144] VendorName: %s\n", str);

	dev_info(dev, "\t [145-147] VendorOUI: %X %X %X\n", m[145], m[146], m[147]);

	memset(str, 0, 32);
	memcpy(str, &m[148], 16);
	dev_info(dev, "\t [148-163] VendorPN: %s\n", str);

	memset(str, 0, 32);
	memcpy(str, &m[166], 16);
	dev_info(dev, "\t [166-181] VendorSN: %s\n", str);

	memset(str, 0, 32);
	memcpy(str, &m[182], 8);
	dev_info(dev, "\t [182-189] DateCode: %s\n", str);

	memset(str, 0, 32);
	memcpy(str, &m[190], 10);
	dev_info(dev, "\t [190-199] CLEICode: %s\n", str);

	dev_info(dev, "\t [200] ModulePowerClass: %X\n", m[200]);
	dev_info(dev, "\t [201] MaxPower: %X\n", m[201]);

	dev_info(dev, "\t [203] ConnectorType: %X\n", m[203]);

	dev_info(dev, "\t [210] MediaLaneInformation: %X\n", m[210]);

	dev_info(dev, "\t [212] MediaInterfaceTechnology: %X\n", m[212]);

	if (m[2] & BIT(7))	/* flat memory, no other pages */
		return;

	m = ci->mem_up1;

	dev_info(dev, "%s(CMIS) mem - page 01\n", (ephy_type == EPHY_TYPE_SFP) ? "SFP" : "QSFP");

	dev_info(dev, "\t [142] Supported Pages: %X\n", m[142 - 128]);

	dev_info(dev, "\t [157-158] Supported Flags: %X, %X\n", m[157 - 128], m[158 - 128]);
}

static void ephy_mem_dump_basic_raw(struct nse_hw *hw)
{
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *ephy_info = &lpinfo->ephy_info;

	if (lpinfo->static_flags &
	    (LMAC_PHY_STATIC_FLAG_EPHY_FTYPE | LMAC_PHY_STATIC_FLAG_USE_TEST_PHY)) {
		dev_info(nse_hw_to_dev(hw), "FTYPE or TEST_PHY: no data\n");
		return;
	}

	if (ephy_info->ephy_type == EPHY_TYPE_SFP) {
		if (ephy_info->sfp_info.mng_if_type == XSFP_MNG_IF_TYPE_SFF8472)
			ephy_mem_dump_basic_raw_sfp_sff8472(hw, ephy_info);
		else if (ephy_info->sfp_info.mng_if_type == XSFP_MNG_IF_TYPE_CMIS)
			ephy_mem_dump_basic_raw_cmis(hw, ephy_info, EPHY_TYPE_SFP);

	} else if (ephy_info->ephy_type == EPHY_TYPE_QSFP) {
		if (ephy_info->qsfp_info.mng_if_type == XSFP_MNG_IF_TYPE_SFF8636)
			ephy_mem_dump_basic_raw_qsfp_sff8636(hw, ephy_info);
		else if (ephy_info->sfp_info.mng_if_type == XSFP_MNG_IF_TYPE_CMIS)
			ephy_mem_dump_basic_raw_cmis(hw, ephy_info, EPHY_TYPE_QSFP);

	} else
		dev_info(nse_hw_to_dev(hw), "[%s] not impl for ephy_type=%d\n",
			 __func__, ephy_info->ephy_type);
}

static void ephy_mem_dump_basic_parsing_result_sfp_sff8472(struct nse_hw *hw,
							   struct nse_ephy_info *ephy_info)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_ephy_sfp_info *sfp_info = &ephy_info->sfp_info;

	dev_info(dev, "SFP(SFF8472) parsing info\n");

	dev_info(dev, "\t dev_id=%X\n", sfp_info->dev_id);
//	dev_info(dev, "\t dev_ext_id=%X\n", sfp_info->sff8472_info.dev_ext_id);

	dev_info(dev, "\t impl_rate_select=%d\n", sfp_info->sff8472_info.impl_rate_select);
	dev_info(dev, "\t impl_tx_disable=%d\n", sfp_info->sff8472_info.impl_tx_disable);
	dev_info(dev, "\t impl_tx_fault=%d\n", sfp_info->sff8472_info.impl_tx_fault);
	dev_info(dev, "\t impl_rx_los=%d\n", sfp_info->sff8472_info.impl_rx_los);

	dev_info(dev, "\t need_addr_change=%d\n", sfp_info->sff8472_info.need_addr_change);

	dev_info(dev, "\t cable_tech=%d\n", sfp_info->sff8472_info.cable_tech);

	dev_info(dev, "\t compliance_ext_code=0x%X\n", sfp_info->sff8472_info.compliance_ext_code);
	dev_info(dev, "\t compliance_10g_eth_codes=0x%X\n",
		 sfp_info->sff8472_info.compliance_10g_eth_codes);
}

static void ephy_mem_dump_basic_parsing_result_qsfp_sff8636(struct nse_hw *hw,
							    struct nse_ephy_info *ephy_info)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_ephy_qsfp_info *qsfp_info = &ephy_info->qsfp_info;

	dev_info(dev, "QSFP(SFF8636) parsing info\n");

	dev_info(dev, "\t dev_id=%X\n", qsfp_info->dev_id);

	dev_info(dev, "\t impl_rate_select=%d\n", qsfp_info->sff8636_info.impl_rate_select);
	dev_info(dev, "\t rate_select_version=%d\n", qsfp_info->sff8636_info.rate_select_version);
	dev_info(dev, "\t impl_tx_disable=%d\n", qsfp_info->sff8636_info.impl_tx_disable);
	dev_info(dev, "\t impl_tx_fault=%d\n", qsfp_info->sff8636_info.impl_tx_fault);
	dev_info(dev, "\t impl_tx_los=%d\n", qsfp_info->sff8636_info.impl_tx_los);

	dev_info(dev, "\t compliance_10g_40g_100g_eth_codes=0x%X\n",
		 qsfp_info->sff8636_info.compliance_10g_40g_100g_eth_codes);
	dev_info(dev, "\t compliance_ext_code=0x%X\n", qsfp_info->sff8636_info.compliance_ext_code);
}

static void ephy_mem_dump_basic_parsing_result_cmis(struct nse_hw *hw,
						    struct nse_ephy_info *ephy_info, u32 ephy_type)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct xsfp_cmis_info *ci;

	dev_info(dev, "%s(CMIS) parsing info\n", (ephy_type == EPHY_TYPE_SFP) ? "SFP" : "QSFP");

	if (ephy_type == EPHY_TYPE_SFP) {
		ci = &ephy_info->sfp_info.cmis_info;

		dev_info(dev, "\t dev_id=%X\n", ephy_info->sfp_info.dev_id);
	} else {
		ci = &ephy_info->qsfp_info.cmis_info;

		dev_info(dev, "\t dev_id=%X\n", ephy_info->qsfp_info.dev_id);
	}

	dev_info(dev, "\t mem_model=%X\n", ci->mem_model);

	dev_info(dev, "\t host_if_id=%X\n", ci->host_if_id);
	dev_info(dev, "\t media_if_id=%X\n", ci->media_if_id);
	dev_info(dev, "\t host_lane_cnt=%X\n", ci->host_lane_cnt);
	dev_info(dev, "\t media_lane_cnt=%X\n", ci->media_lane_cnt);
	dev_info(dev, "\t media_lane_info=%X\n", ci->media_lane_info);
	dev_info(dev, "\t media_if_tech=%X\n", ci->media_if_tech);
	dev_info(dev, "\t supported_pages_adv=%X\n", ci->supported_pages_adv);

	dev_info(dev, "\t impl_tx_los=%d\n", ci->impl_tx_los);
	dev_info(dev, "\t impl_tx_fault=%d\n", ci->impl_tx_fault);
	dev_info(dev, "\t impl_rx_los=%d\n", ci->impl_rx_los);
}

static void ephy_mem_dump_basic_parsing_result(struct nse_hw *hw)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *ephy_info = &lpinfo->ephy_info;

	dev_info(dev, "is_supported_mod=%d\n", ephy_info->is_supported_mod);

	dev_info(dev, "mod_supported_link_speeds=0x%X\n", ephy_info->mod_supported_link_speeds);
	dev_info(dev, "mod_supported_link_types=0x%lX\n",
		 (unsigned long)ephy_info->mod_supported_link_types);
	dev_info(dev, "mod_media_type=0x%X\n", ephy_info->mod_media_type);
	dev_info(dev, "mod_an_supported=%d\n", ephy_info->mod_an_supported);
	dev_info(dev, "mod_supported_fec=0x%X(%s)\n", ephy_info->mod_supported_fec,
		 fec_str(ephy_info->mod_supported_fec));

	if (lpinfo->static_flags &
	    (LMAC_PHY_STATIC_FLAG_EPHY_FTYPE | LMAC_PHY_STATIC_FLAG_USE_TEST_PHY))
		return;


	if (ephy_info->ephy_type == EPHY_TYPE_SFP) {
		if (ephy_info->sfp_info.mng_if_type == XSFP_MNG_IF_TYPE_SFF8472)
			ephy_mem_dump_basic_parsing_result_sfp_sff8472(hw, ephy_info);
		else if (ephy_info->sfp_info.mng_if_type == XSFP_MNG_IF_TYPE_CMIS)
			ephy_mem_dump_basic_parsing_result_cmis(hw, ephy_info, EPHY_TYPE_SFP);

	} else if (ephy_info->ephy_type == EPHY_TYPE_QSFP) {
		if (ephy_info->qsfp_info.mng_if_type == XSFP_MNG_IF_TYPE_SFF8636)
			ephy_mem_dump_basic_parsing_result_qsfp_sff8636(hw, ephy_info);
		else if (ephy_info->sfp_info.mng_if_type == XSFP_MNG_IF_TYPE_CMIS)
			ephy_mem_dump_basic_parsing_result_cmis(hw, ephy_info, EPHY_TYPE_QSFP);

	} else
		dev_info(nse_hw_to_dev(hw), "[%s] not impl for ephy_type=%d\n",
			 __func__, ephy_info->ephy_type);
}

static void ephy_mem_parse_basic_cmis(struct nse_hw *hw,
				      struct nse_ephy_info *ephy_info, u32 ephy_type)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct ethtool_link_ksettings *mod_lks = &ephy_info->mod_lks;
	struct xsfp_cmis_info *ci;
	u8 *m;
	int i = 0, j = 0;

	ephy_info->mod_supported_link_speeds = 0;
	ephy_info->mod_supported_link_types = 0;
	ephy_info->mod_media_type = MEDIA_FIBER;	/* default, may be overwritten later */
	ephy_info->mod_supported_fec = FEC_OFF;
	ephy_info->mod_an_supported = false;

	if (ephy_type == EPHY_TYPE_SFP)
		ci = &ephy_info->sfp_info.cmis_info;
	else
		ci = &ephy_info->qsfp_info.cmis_info;

	m = ci->mem_lp_up0;

	ci->media_type = m[85];

	/* App1*/
	i = 1;
	j = 86;
	for (i = 1; i <= 8; i++) {
		ci->host_if_id = m[j];
		j++;

		ci->media_if_id = m[j];
		j++;

		ci->host_lane_cnt = m[j] >> 4;
		ci->media_lane_cnt = m[j] & 0xF;
		j++;

		j++;	/* skip HostLaneAssignmentOptions */

		if (ci->host_if_id != 0xFF)	/* first non-empty one */
			break;
	}

	ci->media_lane_info = m[210];

	ci->media_if_tech = m[212];

	if (!ci->mem_model) {	/* Paged memory */
		m = ci->mem_up1;

		ci->supported_pages_adv = m[(142 - 128)];

		ci->impl_tx_los = !!(m[(157 - 128)] & BIT(1));
		ci->impl_tx_fault = !!(m[(157 - 128)] & BIT(0));
		ci->impl_rx_los = !!(m[(158 - 128)] & BIT(1));
	}

	ethtool_link_ksettings_add_link_mode(mod_lks, supported, FIBRE);

	if (ci->media_type == 0x1 || ci->media_type == 0x2) {
		ephy_info->mod_media_type = MEDIA_FIBER;
		mod_lks->base.port = PORT_FIBRE;

	} else if (ci->media_type == 0x3 || ci->media_type == 0x4) {
		ephy_info->mod_media_type = MEDIA_DAC;
		mod_lks->base.port = PORT_DA;
	} else {
		dev_err(dev, "[%s] CMIS media_type=%X, not supported by us\n",
			__func__, ci->media_type);
		return;
	}

	/* <<SFF-8024>> / 4.6.1 Host Electrical Interface IDs*/
	if (ci->host_if_id == 0x14 ||
		ci->host_if_id == 0x15 ||
		ci->host_if_id == 0x16) {
		ephy_info->mod_supported_link_speeds = NSE_AQ_LINK_SPEED_25GB;
		ephy_info->mod_supported_link_types = NSE_ETH_LINK_TYPE_25GbaseR;

		if (ci->host_if_id == 0x14)
			ephy_info->mod_supported_fec |= FEC_RS;
		else if (ci->host_if_id == 0x16)
			ephy_info->mod_supported_fec |= FEC_OFF;

	} else if (ci->host_if_id == 0x17) {
		ephy_info->mod_supported_link_speeds = NSE_AQ_LINK_SPEED_40GB;
		ephy_info->mod_supported_link_types = NSE_ETH_LINK_TYPE_40GbaseR4;

	} else if (ci->host_if_id == 0x43 ||
				ci->host_if_id == 0x44 ||
				ci->host_if_id == 0x45) {
		ephy_info->mod_supported_link_speeds = NSE_AQ_LINK_SPEED_50GB;
		ephy_info->mod_supported_link_types = NSE_ETH_LINK_TYPE_50GbaseR2;

		if (ci->host_if_id == 0x43)
			ephy_info->mod_supported_fec |= FEC_RS;
		else if (ci->host_if_id == 0x44)
			ephy_info->mod_supported_fec |= FEC_BASER;
		else
			ephy_info->mod_supported_fec |= FEC_OFF;

	} else if (ci->host_if_id == 0x18) {
		ephy_info->mod_supported_link_speeds = NSE_AQ_LINK_SPEED_50GB;
		ephy_info->mod_supported_link_types = NSE_ETH_LINK_TYPE_50GbaseR1;

	} else if (ci->host_if_id == 0x1A) {
		ephy_info->mod_supported_link_speeds = NSE_AQ_LINK_SPEED_100GB;
		ephy_info->mod_supported_link_types = NSE_ETH_LINK_TYPE_100GbaseR4;

	} else if (ci->host_if_id == 0x1C) {
		ephy_info->mod_supported_link_speeds = NSE_AQ_LINK_SPEED_200GB;
		ephy_info->mod_supported_link_types = NSE_ETH_LINK_TYPE_200GbaseR4;

	} else if (ci->host_if_id == 0x48) {
		ephy_info->mod_supported_link_speeds = NSE_AQ_LINK_SPEED_400GB;
		ephy_info->mod_supported_link_types = NSE_ETH_LINK_TYPE_400GbaseR4;

	} else {
		dev_err(dev, "[%s] CMIS host_if_id=%X, not supported by us\n",
			__func__, ci->host_if_id);

		return;
	}

	/* should check <<SFF-8024>> / 4.6.2 Media Interface IDs, according to MediaType */
	/* but lazy - just do this coarse setting */
	if (mod_lks->base.port == PORT_FIBRE) {
		if (ephy_info->mod_supported_link_types & NSE_ETH_LINK_TYPE_25GbaseR)
			ethtool_link_ksettings_add_link_mode(mod_lks, supported, 25000baseSR_Full);

		if (ephy_info->mod_supported_link_types & NSE_ETH_LINK_TYPE_40GbaseR4) {
			ethtool_link_ksettings_add_link_mode(mod_lks, supported, 40000baseSR4_Full);
			ethtool_link_ksettings_add_link_mode(mod_lks, supported, 40000baseLR4_Full);
		}

		if (ephy_info->mod_supported_link_types & NSE_ETH_LINK_TYPE_50GbaseR2)
			ethtool_link_ksettings_add_link_mode(mod_lks, supported, 50000baseSR2_Full);

		if (ephy_info->mod_supported_link_types & NSE_ETH_LINK_TYPE_50GbaseR1) {
			ethtool_link_ksettings_add_link_mode(mod_lks, supported, 50000baseSR_Full);
			ethtool_link_ksettings_add_link_mode(mod_lks, supported,
							     50000baseLR_ER_FR_Full);
			ethtool_link_ksettings_add_link_mode(mod_lks, supported, 50000baseDR_Full);
		}

		if (ephy_info->mod_supported_link_types & NSE_ETH_LINK_TYPE_100GbaseR4) {
			ethtool_link_ksettings_add_link_mode(mod_lks, supported,
							     100000baseSR4_Full);
			ethtool_link_ksettings_add_link_mode(mod_lks, supported,
							     100000baseLR4_ER4_Full);
		}

		if (ephy_info->mod_supported_link_types & NSE_ETH_LINK_TYPE_200GbaseR4) {
			ethtool_link_ksettings_add_link_mode(mod_lks, supported,
							     200000baseSR4_Full);
			ethtool_link_ksettings_add_link_mode(mod_lks, supported,
							     200000baseLR4_ER4_FR4_Full);
			ethtool_link_ksettings_add_link_mode(mod_lks, supported,
							     200000baseDR4_Full);
		}

		if (ephy_info->mod_supported_link_types & NSE_ETH_LINK_TYPE_400GbaseR4) {
			ethtool_link_ksettings_add_link_mode(mod_lks, supported,
							     400000baseSR4_Full);
			ethtool_link_ksettings_add_link_mode(mod_lks, supported,
							     400000baseLR4_ER4_FR4_Full);
			ethtool_link_ksettings_add_link_mode(mod_lks, supported,
							     400000baseDR4_Full);
		}
	} else {	/* PORT_DA */

		if (ephy_info->mod_supported_link_types & NSE_ETH_LINK_TYPE_25GbaseR)
			ethtool_link_ksettings_add_link_mode(mod_lks, supported, 25000baseCR_Full);

		if (ephy_info->mod_supported_link_types & NSE_ETH_LINK_TYPE_40GbaseR4)
			ethtool_link_ksettings_add_link_mode(mod_lks, supported, 40000baseCR4_Full);

		if (ephy_info->mod_supported_link_types & NSE_ETH_LINK_TYPE_50GbaseR2)
			ethtool_link_ksettings_add_link_mode(mod_lks, supported, 50000baseCR2_Full);

		if (ephy_info->mod_supported_link_types & NSE_ETH_LINK_TYPE_50GbaseR1)
			ethtool_link_ksettings_add_link_mode(mod_lks, supported, 50000baseCR_Full);

		if (ephy_info->mod_supported_link_types & NSE_ETH_LINK_TYPE_100GbaseR4) {
			ethtool_link_ksettings_add_link_mode(mod_lks, supported,
							     100000baseCR4_Full);
		}

		if (ephy_info->mod_supported_link_types & NSE_ETH_LINK_TYPE_200GbaseR4) {
			ethtool_link_ksettings_add_link_mode(mod_lks, supported,
							     200000baseCR4_Full);
		}

		if (ephy_info->mod_supported_link_types & NSE_ETH_LINK_TYPE_400GbaseR4) {
			ethtool_link_ksettings_add_link_mode(mod_lks, supported,
							     400000baseCR4_Full);
		}
	}

	if (ephy_info->mod_supported_fec & FEC_RS)
		ethtool_link_ksettings_add_link_mode(mod_lks, supported, FEC_RS);
	if (ephy_info->mod_supported_fec & FEC_BASER)
		ethtool_link_ksettings_add_link_mode(mod_lks, supported, FEC_BASER);
}

static void ephy_mem_parse_basic_sfp_sff8472(struct nse_hw *hw, struct nse_ephy_info *ephy_info)
{
	struct nse_ephy_sfp_info *sfp_info = &ephy_info->sfp_info;
	struct sfp_sff8472_info *sff8472_info = &sfp_info->sff8472_info;
	struct ethtool_link_ksettings *mod_lks = &ephy_info->mod_lks;
	u8 *m = sfp_info->sff8472_info.mem_a0;

	ephy_info->mod_supported_link_speeds = 0;
	ephy_info->mod_supported_link_types = 0;
	ephy_info->mod_media_type = MEDIA_FIBER;	/* default, overwritten later */
	ephy_info->mod_supported_fec = FEC_OFF;
	ephy_info->mod_an_supported = false;

	sff8472_info->impl_rate_select = !!(m[65] & BIT(5));
	sff8472_info->impl_tx_disable = !!(m[65] & BIT(4));
	sff8472_info->impl_tx_fault = !!(m[65] & BIT(3));
	sff8472_info->impl_rx_los = !!(m[65] & BIT(1));

	sff8472_info->need_addr_change = !!(m[92] & BIT(2));

	sff8472_info->cable_tech = m[8];

	sff8472_info->compliance_10g_eth_codes = (m[3] & 0xF0);	/* bits: 7,6,5,4 */
	sff8472_info->compliance_ext_code = m[36];

	ethtool_link_ksettings_add_link_mode(mod_lks, supported, FIBRE);

	/* Active Cable, Passive Cable, then means this mod is DAC */
	if (sff8472_info->cable_tech & (BIT(3) | BIT(2))) {
		ephy_info->mod_media_type = MEDIA_DAC;

		ephy_info->mod_an_supported = true;

		mod_lks->base.port = PORT_DA;

		ethtool_link_ksettings_add_link_mode(mod_lks, supported, Autoneg);

	} else {
		ephy_info->mod_media_type = MEDIA_FIBER;

		mod_lks->base.port = PORT_FIBRE;
	}

	if (sff8472_info->compliance_10g_eth_codes) {
		ephy_info->mod_supported_link_speeds |= NSE_AQ_LINK_SPEED_10GB;
		ephy_info->mod_supported_link_types |= NSE_ETH_LINK_TYPE_10GbaseR;

		ephy_info->mod_supported_fec |= FEC_BASER;		/* 10G only support BASER */

		if (sff8472_info->cable_tech & (BIT(3) | BIT(2))) {	/* DAC */

			ethtool_link_ksettings_add_link_mode(mod_lks, supported, 10000baseCR_Full);

		} else {
			if (sff8472_info->compliance_10g_eth_codes & BIT(7))
				ethtool_link_ksettings_add_link_mode(mod_lks, supported,
								     10000baseER_Full);

			if (sff8472_info->compliance_10g_eth_codes & BIT(6))
				ethtool_link_ksettings_add_link_mode(mod_lks, supported,
								     10000baseLRM_Full);

			if (sff8472_info->compliance_10g_eth_codes & BIT(5))
				ethtool_link_ksettings_add_link_mode(mod_lks, supported,
								     10000baseLR_Full);

			if (sff8472_info->compliance_10g_eth_codes & BIT(4))
				ethtool_link_ksettings_add_link_mode(mod_lks, supported,
								     10000baseSR_Full);
		}
	}

	if (sff8472_info->compliance_ext_code == SFF_EXT_COMPLIANCE_25GbaseSR ||
		sff8472_info->compliance_ext_code == SFF_EXT_COMPLIANCE_25GbaseLR ||
		sff8472_info->compliance_ext_code == SFF_EXT_COMPLIANCE_25GbaseER ||
		sff8472_info->compliance_ext_code == SFF_EXT_COMPLIANCE_25GbaseCR_RS_FEC ||
		sff8472_info->compliance_ext_code == SFF_EXT_COMPLIANCE_25GbaseCR_BASER_FEC ||
		sff8472_info->compliance_ext_code == SFF_EXT_COMPLIANCE_25GbaseCR_NO_FEC) {
		ephy_info->mod_supported_link_speeds |= NSE_AQ_LINK_SPEED_25GB;
		ephy_info->mod_supported_link_types |= NSE_ETH_LINK_TYPE_25GbaseR;

		if (sff8472_info->compliance_ext_code == SFF_EXT_COMPLIANCE_25GbaseSR ||
			sff8472_info->compliance_ext_code == SFF_EXT_COMPLIANCE_25GbaseLR ||
			sff8472_info->compliance_ext_code == SFF_EXT_COMPLIANCE_25GbaseER) {
			/* 25G support BASER and RS */
			ephy_info->mod_supported_fec |= (FEC_BASER | FEC_RS);

			/* linux only define this */
			ethtool_link_ksettings_add_link_mode(mod_lks, supported, 25000baseSR_Full);

		} else {
			ethtool_link_ksettings_add_link_mode(mod_lks, supported, 25000baseCR_Full);

			if (sff8472_info->compliance_ext_code ==
			    SFF_EXT_COMPLIANCE_25GbaseCR_RS_FEC)
				ephy_info->mod_supported_fec |= FEC_RS;
			else if (sff8472_info->compliance_ext_code ==
				 SFF_EXT_COMPLIANCE_25GbaseCR_BASER_FEC)
				ephy_info->mod_supported_fec |= FEC_BASER;
			else if (sff8472_info->compliance_ext_code ==
				 SFF_EXT_COMPLIANCE_25GbaseCR_NO_FEC)
				ephy_info->mod_supported_fec = FEC_OFF;
		}
	}

	if (ephy_info->mod_supported_fec & FEC_RS)
		ethtool_link_ksettings_add_link_mode(mod_lks, supported, FEC_RS);
	if (ephy_info->mod_supported_fec & FEC_BASER)
		ethtool_link_ksettings_add_link_mode(mod_lks, supported, FEC_BASER);
}

static void ephy_mem_parse_basic_sfp(struct nse_hw *hw, struct nse_ephy_info *ephy_info)
{
	if (ephy_info->sfp_info.mng_if_type == XSFP_MNG_IF_TYPE_SFF8472)
		ephy_mem_parse_basic_sfp_sff8472(hw, ephy_info);
	else if (ephy_info->sfp_info.mng_if_type == XSFP_MNG_IF_TYPE_CMIS)
		ephy_mem_parse_basic_cmis(hw, ephy_info, EPHY_TYPE_SFP);
}

static void ephy_mem_parse_basic_qsfp_sff8636(struct nse_hw *hw, struct nse_ephy_info *ephy_info)
{
	struct nse_ephy_qsfp_info *qsfp_info = &ephy_info->qsfp_info;
	struct qsfp_sff8636_info *sff8636_info = &qsfp_info->sff8636_info;
	struct ethtool_link_ksettings *mod_lks = &ephy_info->mod_lks;
	u8 *m = qsfp_info->sff8636_info.mem_lp_up0;
	u8 val;

	ephy_info->mod_supported_link_speeds = 0;
	ephy_info->mod_supported_link_types = 0;
	ephy_info->mod_media_type = MEDIA_FIBER;	/* default, may be overwritten later */
	ephy_info->mod_supported_fec = FEC_OFF;
	ephy_info->mod_an_supported = false;

	ethtool_link_ksettings_add_link_mode(mod_lks, supported, FIBRE);
	mod_lks->base.port = PORT_FIBRE;

	sff8636_info->mem_model = m[2] & BIT(2);

	sff8636_info->impl_rate_select = !!(m[195] & BIT(5));
	sff8636_info->rate_select_version = m[141];
	sff8636_info->impl_tx_disable = !!(m[195] & BIT(4));
	sff8636_info->impl_tx_fault = !!(m[195] & BIT(3));
	sff8636_info->impl_tx_los = !!(m[195] & BIT(1));

	sff8636_info->compliance_10g_40g_100g_eth_codes = m[131];
	sff8636_info->compliance_ext_code = m[192];

	sff8636_info->connector_type = m[130];
	sff8636_info->length_ca_or_of = m[146];
	sff8636_info->dev_tech = m[147];

	if (sff8636_info->compliance_10g_40g_100g_eth_codes & 0x70) {	/* BIT(6,5,4)*/
		ephy_info->mod_supported_link_speeds |= NSE_AQ_LINK_SPEED_10GB;
		ephy_info->mod_supported_link_types |= NSE_ETH_LINK_TYPE_10GbaseR;

		ephy_info->mod_supported_fec |= FEC_BASER;

		if (sff8636_info->compliance_10g_40g_100g_eth_codes & BIT(6))
			ethtool_link_ksettings_add_link_mode(mod_lks, supported, 10000baseLRM_Full);

		if (sff8636_info->compliance_10g_40g_100g_eth_codes & BIT(5))
			ethtool_link_ksettings_add_link_mode(mod_lks, supported, 10000baseLR_Full);

		if (sff8636_info->compliance_10g_40g_100g_eth_codes & BIT(4))
			ethtool_link_ksettings_add_link_mode(mod_lks, supported, 10000baseSR_Full);
	}

	if (sff8636_info->compliance_10g_40g_100g_eth_codes & 0xF) {	/* BIT(3,2,1,0) */
		ephy_info->mod_supported_link_speeds |= NSE_AQ_LINK_SPEED_40GB;
		ephy_info->mod_supported_link_types |= NSE_ETH_LINK_TYPE_40GbaseR4;

		ephy_info->mod_supported_fec |= (FEC_BASER | FEC_RS);

		if (sff8636_info->compliance_10g_40g_100g_eth_codes & BIT(3)) {
			ephy_info->mod_an_supported = true;

			ethtool_link_ksettings_add_link_mode(mod_lks, supported, 40000baseCR4_Full);

		} else {
			if (sff8636_info->compliance_10g_40g_100g_eth_codes & BIT(2))
				ethtool_link_ksettings_add_link_mode(mod_lks, supported,
								     40000baseSR4_Full);

			if (sff8636_info->compliance_10g_40g_100g_eth_codes & BIT(1))
				ethtool_link_ksettings_add_link_mode(mod_lks, supported,
								     40000baseLR4_Full);
		}
	}

	if (sff8636_info->compliance_10g_40g_100g_eth_codes & BIT(7)) {
		if (sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_100GbaseSR4 ||
			sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_100GbaseLR4 ||
			sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_100GbaseER4 ||
			sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_100GbaseCR4 ||
			sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_100G_CWDM4 ||
			sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_100G_SWDM4) {
			ephy_info->mod_supported_link_speeds |= NSE_AQ_LINK_SPEED_100GB;
			ephy_info->mod_supported_link_types |= NSE_ETH_LINK_TYPE_100GbaseR4;

			ephy_info->mod_supported_fec |= FEC_RS;

			if (sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_100GbaseSR4 ||
			    sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_100G_CWDM4 ||
				sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_100G_SWDM4)
				ethtool_link_ksettings_add_link_mode(mod_lks, supported,
								     100000baseSR4_Full);

			if (sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_100GbaseLR4 ||
				sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_100GbaseER4)
				ethtool_link_ksettings_add_link_mode(mod_lks, supported,
								     100000baseLR4_ER4_Full);

			/* SFF_EXT_COMPLIANCE_100GbaseCR4_25GbaseCR_50GbaseCR2_RS_FEC */
			if (sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_100GbaseCR4) {
				ephy_info->mod_an_supported = true;

				ethtool_link_ksettings_add_link_mode(mod_lks, supported,
								     100000baseCR4_Full);
			}

		} else if (sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_200GbaseCR4 ||
			sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_200GbaseSR4 ||
			sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_200GbaseDR4 ||
			sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_200GbaseLR4) {
			ephy_info->mod_supported_link_speeds |= NSE_AQ_LINK_SPEED_200GB;
			ephy_info->mod_supported_link_types |= NSE_ETH_LINK_TYPE_200GbaseR4;

			ephy_info->mod_supported_fec |= FEC_RS;

			if (sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_200GbaseCR4) {
				ephy_info->mod_an_supported = true;

				ethtool_link_ksettings_add_link_mode(mod_lks, supported,
								     200000baseCR4_Full);
			}

			if (sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_200GbaseSR4)
				ethtool_link_ksettings_add_link_mode(mod_lks, supported,
								     200000baseSR4_Full);

			if (sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_200GbaseDR4)
				ethtool_link_ksettings_add_link_mode(mod_lks, supported,
								     200000baseDR4_Full);

			if (sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_200GbaseLR4)
				ethtool_link_ksettings_add_link_mode(mod_lks, supported,
								     200000baseLR4_ER4_FR4_Full);

		} else if (sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_400GbaseCR4 ||
			sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_400GbaseDR4 ||
			sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_400GbaseFR4 ||
			sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_400GbaseLR4) {
			ephy_info->mod_supported_link_speeds |= NSE_AQ_LINK_SPEED_400GB;
			ephy_info->mod_supported_link_types |= NSE_ETH_LINK_TYPE_400GbaseR4;

			ephy_info->mod_supported_fec |= FEC_RS;

			if (sff8636_info->compliance_ext_code == SFF_EXT_COMPLIANCE_400GbaseCR4) {
				ephy_info->mod_an_supported = true;

				ethtool_link_ksettings_add_link_mode(mod_lks, supported,
								     400000baseCR4_Full);

			} else {
				ethtool_link_ksettings_add_link_mode(mod_lks, supported,
								     400000baseSR4_Full);

				if (sff8636_info->compliance_ext_code ==
				    SFF_EXT_COMPLIANCE_400GbaseDR4)
					ethtool_link_ksettings_add_link_mode(mod_lks, supported,
									     400000baseDR4_Full);

				if (sff8636_info->compliance_ext_code ==
				    SFF_EXT_COMPLIANCE_400GbaseFR4 ||
				    sff8636_info->compliance_ext_code ==
				    SFF_EXT_COMPLIANCE_400GbaseLR4)
					ethtool_link_ksettings_add_link_mode(mod_lks, supported,
						400000baseLR4_ER4_FR4_Full);
			}
		}
	} else {
		nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] INFO: qsfp_mod, byte 131=%X, BIT(7)=false, does not any compliance_ext_code\n",
					__func__,
						sff8636_info->compliance_10g_40g_100g_eth_codes);
	}

	val = (sff8636_info->dev_tech >> 4);	/* Transmitter technology */
	if (val >= 0xA) {	/* Table 6-20 Transmitter Technology (Page 00h Byte 147 Bits 7-4) */
		ephy_info->mod_media_type = MEDIA_DAC;
		ephy_info->mod_an_supported = true;

		mod_lks->base.port = PORT_DA;

		ethtool_link_ksettings_add_link_mode(mod_lks, supported, Autoneg);
	}

	if (ephy_info->mod_supported_fec & FEC_RS)
		ethtool_link_ksettings_add_link_mode(mod_lks, supported, FEC_RS);
	if (ephy_info->mod_supported_fec & FEC_BASER)
		ethtool_link_ksettings_add_link_mode(mod_lks, supported, FEC_BASER);
}

static void ephy_mem_parse_basic_qsfp(struct nse_hw *hw, struct nse_ephy_info *ephy_info)
{
	if (ephy_info->qsfp_info.mng_if_type == XSFP_MNG_IF_TYPE_SFF8636)
		ephy_mem_parse_basic_qsfp_sff8636(hw, ephy_info);
	else if (ephy_info->qsfp_info.mng_if_type == XSFP_MNG_IF_TYPE_CMIS)
		ephy_mem_parse_basic_cmis(hw, ephy_info, EPHY_TYPE_QSFP);
}

static void ephy_mem_parse_basic_ftype(struct nse_hw *hw, struct nse_ephy_info *ephy_info)
{
	struct ethtool_link_ksettings *mod_lks = &ephy_info->mod_lks;
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;

	ephy_info->mod_supported_link_speeds = lpinfo->supported_link_speeds;
	ephy_info->mod_supported_link_types = lpinfo->supported_link_types;

	ephy_info->mod_supported_fec = lpinfo->supported_fec;

	ephy_info->mod_an_supported = false;

	if (ephy_info->ephy_type == EPHY_TYPE_GEN_1G) {
		ephy_info->mod_media_type = MEDIA_BASET;

		ethtool_link_ksettings_add_link_mode(mod_lks, supported, TP);

		ethtool_link_ksettings_add_link_mode(mod_lks, supported, 1000baseT_Full);

		ethtool_link_ksettings_add_link_mode(mod_lks, supported, FEC_NONE);

	} else if (ephy_info->ephy_type == EPHY_TYPE_SFP) {
		ephy_info->mod_media_type = MEDIA_FIBER;

		ethtool_link_ksettings_add_link_mode(mod_lks, supported, FIBRE);

		ethtool_link_ksettings_add_link_mode(mod_lks, supported, 25000baseSR_Full);

		ethtool_link_ksettings_add_link_mode(mod_lks, supported, FEC_RS);
		ethtool_link_ksettings_add_link_mode(mod_lks, supported, FEC_BASER);

	} else if (ephy_info->ephy_type == EPHY_TYPE_QSFP) {
		ephy_info->mod_media_type = MEDIA_FIBER;

		ethtool_link_ksettings_add_link_mode(mod_lks, supported, FIBRE);

		if (ephy_info->mod_supported_link_types & NSE_ETH_LINK_TYPE_100GbaseR4) {
			ethtool_link_ksettings_add_link_mode(mod_lks, supported,
							     100000baseSR4_Full);
			ethtool_link_ksettings_add_link_mode(mod_lks, supported,
							     100000baseCR4_Full);
		}

		if (ephy_info->mod_supported_link_types & NSE_ETH_LINK_TYPE_200GbaseR4) {
			ethtool_link_ksettings_add_link_mode(mod_lks, supported,
							     200000baseSR4_Full);
			ethtool_link_ksettings_add_link_mode(mod_lks, supported,
							     200000baseCR4_Full);
		}

		if (ephy_info->mod_supported_link_types & NSE_ETH_LINK_TYPE_400GbaseR4) {
			ethtool_link_ksettings_add_link_mode(mod_lks, supported,
							     400000baseSR4_Full);
			ethtool_link_ksettings_add_link_mode(mod_lks, supported,
							     400000baseCR4_Full);
		}

		ethtool_link_ksettings_add_link_mode(mod_lks, supported, FEC_RS);
	}
}

static void ephy_mem_parse_basic(struct nse_hw *hw)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *ephy_info = &lpinfo->ephy_info;

	ephy_info->is_supported_mod = true;

	/* also includes ephy_type == EPHY_TYPE_GEN_1G */
	if (lpinfo->static_flags & LMAC_PHY_STATIC_FLAG_EPHY_FTYPE) {
		ephy_mem_parse_basic_ftype(hw, ephy_info);
	} else if (ephy_info->ephy_type == EPHY_TYPE_SFP)
		ephy_mem_parse_basic_sfp(hw, ephy_info);
	else if (ephy_info->ephy_type == EPHY_TYPE_QSFP)
		ephy_mem_parse_basic_qsfp(hw, ephy_info);
	else
		dev_info(dev, "[%s] not impl for ephy_type=%d\n",
			 __func__, ephy_info->ephy_type);

	/* various sanity check */
	if (!(ephy_info->mod_supported_link_speeds & lpinfo->supported_link_speeds)) {
		dev_err(dev, "[%s] mod_supported_link_speeds (%X) and lp supported_link_speeds (%X) has no interset\n",
						__func__, ephy_info->mod_supported_link_speeds,
							lpinfo->supported_link_speeds);
		ephy_info->is_supported_mod = false;
	}

	if (!(ephy_info->mod_supported_link_types & lpinfo->supported_link_types)) {
		dev_err(dev, "[%s] mod_supported_link_types (%lX) and lp supported_link_types (%lX) has no interset\n",
			__func__, (unsigned long)ephy_info->mod_supported_link_types,
				(unsigned long)lpinfo->supported_link_types);
		ephy_info->is_supported_mod = false;
	}

	if (!(ephy_info->mod_media_type & lpinfo->supported_media_types)) {
		dev_err(dev, "[%s] mod_media_type (%X) and lp supported_media_types (%X) has no interset\n",
						__func__, ephy_info->mod_media_type,
							lpinfo->supported_media_types);
		ephy_info->is_supported_mod = false;
	}
}

enum nse_status
ephy_prepare_for_link(struct nse_hw *hw)	//on module present
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *ephy_info = &lpinfo->ephy_info;
	enum nse_status status = NSE_SUCCESS;

	/* also includes ephy_type == EPHY_TYPE_GEN_1G */
	if (lpinfo->static_flags & LMAC_PHY_STATIC_FLAG_EPHY_FTYPE) {
		nse_debug(hw, NSE_DBG_LMAC_PHY,
			  "[%s] skip for STATIC_FLAG_EPHY_FTYPE\n", __func__);
		goto out;
	}

	if (ephy_info->ephy_type == EPHY_TYPE_SFP) {
		status = nse_aq_ephy_cmd_sfp_tx_disable(hw, false);
		if (status) {
			dev_err(dev, "[%s] FAIL: sfp_tx_disable(false), status=%d\n",
				__func__, status);
			goto out;
		}

		status = nse_aq_ephy_cmd_sfp_rate_select(hw, 1, 1);
		if (status) {
			dev_err(dev, "[%s] FAIL: sfp_rate_select(rs0=1, rs1=1), status=%d\n",
				__func__, status);
			goto out;
		}

	} else if (ephy_info->ephy_type == EPHY_TYPE_QSFP) {
		status = nse_aq_ephy_cmd_qsfp_set_lpmode(hw, false);
		if (status) {
			dev_err(dev, "[%s] FAIL: qsfp_set_lpmode(false), status=%d\n",
				__func__, status);
			goto out;
		}

		status = nse_aq_ephy_cmd_qsfp_rate_select(hw, 1, 1, 1, 1);
		if (status) {
			dev_err(dev, "[%s] FAIL: qsfp_rate_select(rx_rs0=1, rx_rs1=1, tx_rs0=1, tx_rs1=1), status=%d\n", __func__, status);
			goto out;
		}

	} else {
		dev_err(dev, "[%s] not impl for ephy_type=%d\n",
			__func__, ephy_info->ephy_type);

		status = NSE_ERR_NOT_IMPL;
	}

out:
	return status;
}

static enum nse_status
read_temperature_sfp(struct nse_hw *hw)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *epinfo = &lpinfo->ephy_info;
	struct nse_ephy_sfp_info *sfp_info = &epinfo->sfp_info;
	u8 bytes[2] = {0};
	u8 bytes_len_out = 0;
	enum nse_status status = NSE_SUCCESS;

	if (sfp_info->mng_if_type != XSFP_MNG_IF_TYPE_SFF8472) {
		dev_err(dev, "[%s] not impl for mng_if_type=%d\n",
			__func__, sfp_info->mng_if_type);
		status = NSE_ERR_NOT_IMPL;
		goto out;
	}

	/* SFF-8472 logic
	 *
	 * /9.2 Internal Calibration
	 *		/Table 9-1 Bit Weights for Temperature Reporting Registers
	 *		/Table 9-2 Digital Temperature Format
	 *
	 * /9.8 Real Time Diagnostic and Control Registers [Address A2h, Bytes 96-111]
	 *
	 *
	 * we only care about Decimal (byte 96), not Fraction (byte 97)
	 */

	if (sfp_info->sff8472_info.need_addr_change) {
		status = nse_aq_ephy_cmd_sfp_8472_addr_change(hw, 0xA2);
		if (status) {
			dev_err(dev, "[%s. %d] FAIL: sfp_8472_addr_change(0xA2), status=%d\n",
				__func__, __LINE__, status);
			goto out;
		}
	}

	status = nse_aq_ephy_cmd_sfp_read_bytes(hw, true, 0xA2, XSFP_MNG_IF_TYPE_SFF8472,
											0, 0, 96, 2,
						bytes, &bytes_len_out);
	if (status) {
		dev_err(dev, "[%s. %d] FAIL: sfp_read_bytes(), status=%d\n",
			__func__, __LINE__, status);
		goto out;
	}

	epinfo->cur_temperature = (bytes[0] & 0x7F);
	if (bytes[0] & BIT(7))
		epinfo->cur_temperature = -(epinfo->cur_temperature);

	if (sfp_info->sff8472_info.need_addr_change) {
		status = nse_aq_ephy_cmd_sfp_8472_addr_change(hw, 0xA0);
		if (status) {
			dev_err(dev, "[%s. %d] FAIL: sfp_8472_addr_change(0xA0), status=%d\n",
				__func__, __LINE__, status);
			goto out;
		}
	}

out:
	return status;
}

static enum nse_status
read_temperature_qsfp(struct nse_hw *hw)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *epinfo = &lpinfo->ephy_info;
	struct nse_ephy_qsfp_info *qsfp_info = &epinfo->qsfp_info;
	u8 bytes[22] = {0};
	u8 bytes_len_out = 0;
	enum nse_status status = NSE_SUCCESS;

	if (qsfp_info->mng_if_type != XSFP_MNG_IF_TYPE_SFF8636) {
		dev_err(dev, "[%s] not impl for mng_if_type=%d\n",
			__func__, qsfp_info->mng_if_type);
		status = NSE_ERR_NOT_IMPL;
		goto out;
	}

	/* SFF-8636 logic
	 *
	 * /6.2.4 Free Side Device Monitors (Page 00h, Bytes 22-33)
	 *
	 *
	 * we only care about Decimal (byte 22), not Fraction (byte 23)
	 *
	 *
	 *  for unknown reason (maybe mod issue), if we read Bytes 22, 23 alone, IntL would change,
	 * making FW issue ephy evt.
	 * So as a workaround, we read Byte 2 - 23, then workaround this.
	 */

	status = nse_aq_ephy_cmd_qsfp_read_bytes(hw, true, 0xA0, XSFP_MNG_IF_TYPE_SFF8636,
											0, 0, 2, 22,
						 bytes, &bytes_len_out);
	if (status) {
		dev_err(dev, "[%s. %d] FAIL: sfp_read_bytes(), status=%d\n",
			__func__, __LINE__, status);
		goto out;
	}

	epinfo->cur_temperature = (bytes[20] & 0x7F);
	if (bytes[20] & BIT(7))
		epinfo->cur_temperature = -(epinfo->cur_temperature);

out:
	return status;
}

static enum nse_status
ephy_read_temperature(struct nse_hw *hw)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *epinfo = &lpinfo->ephy_info;
	enum nse_status status = NSE_SUCCESS;

	epinfo->cur_temperature_valid = false;

	if (lpinfo->static_flags & LMAC_PHY_STATIC_FLAG_EPHY_FTYPE)
		return NSE_SUCCESS;

	if (epinfo->ephy_type == EPHY_TYPE_SFP) {
		status = read_temperature_sfp(hw);
		if (status)
			dev_err(dev, "[%s] FAIL: read_temp_sfp(), status=%d\n",
				__func__, status);

	} else if (epinfo->ephy_type == EPHY_TYPE_QSFP) {
		status = read_temperature_qsfp(hw);
		if (status)
			dev_err(dev, "[%s] FAIL: read_temp_sfp(), status=%d\n",
				__func__, status);

	} else {
		dev_err(dev, "[%s] not impl for ephy_type=%d\n", __func__, epinfo->ephy_type);

		status = NSE_ERR_NOT_IMPL;
	}

	if (!status)
		epinfo->cur_temperature_valid = true;

	return status;
}

enum nse_status
nse_lmac_phy_ephy_read_temperature(struct nse_hw *hw, int *temperature)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_ephy_info *epinfo = &hw->port_info->lmac_phy_info.ephy_info;
	enum nse_status status = NSE_SUCCESS;

	*temperature = 0;

	nse_lmac_phy_lock(hw);

	if (hw->nic_type != NSE_NIC_TYPE_SFP && hw->nic_type != NSE_NIC_TYPE_QSFP)
		goto out;

	if (!ephy_status_is_module_present(hw, true))
		goto out;

	status = ephy_read_temperature(hw);
	if (status) {
		dev_warn(dev, "[%s] FAIL: ephy_read_temp(), status=%d\n", __func__, status);
		goto out;
	}

	if (epinfo->cur_temperature_valid)
		*temperature = epinfo->cur_temperature;

out:
	nse_lmac_phy_unlock(hw);

	return status;
}

void nse_lmac_phy_ephy_dump_info(struct nse_hw *hw)
{
	struct device *dev = nse_hw_to_dev(hw);

	if (nse_is_nic_use_ephy(hw->nic_type)) {
		dev_info(dev, "This NIC does not use ephy\n");
		return;
	}

	if (!ephy_status_is_module_present(hw, true)) {
		dev_info(dev, "ephy not present\n");
		return;
	}

	nse_lmac_phy_lock(hw);

	dev_info(dev, "=== ephy status\n");
	ephy_status_dump(hw, true);

	dev_info(dev, "=== ephy raw info\n");
	ephy_mem_dump_basic_raw(hw);

	dev_info(dev, "=== ephy parsed info\n");
	ephy_mem_dump_basic_parsing_result(hw);

	nse_lmac_phy_unlock(hw);
}

static enum nse_status
lmac_phy_eth_set_link(struct nse_hw *hw, u32 speed, u64 link_type, u32 fec)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	int i;
	enum nse_status status = NSE_SUCCESS;

	nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] speed=0x%X, link_type=0x%lX, fec=0x%X\n",
		  __func__, speed, (unsigned long)link_type, fec);

	i = find_set_bit_cnt_u32(speed);
	if (i != 1) {
		dev_err(dev, "[%s] BAD param: speed(0x%X) contains not 1 bit\n",
			__func__, speed);
		status = NSE_ERR_PARAM;
		goto out;
	}

	i = find_set_bit_cnt_u64(link_type);
	if (i != 1) {
		dev_err(dev, "[%s] BAD param: link_type(0x%lX) contains not 1 bit\n",
			__func__, (unsigned long)speed);
		status = NSE_ERR_PARAM;
		goto out;
	}

	if (lpinfo->static_flags & LMAC_PHY_STATIC_FLAG_USE_TEST_PHY) {
		if (nse_palladium_debug) {
			nse_debug(hw, NSE_DBG_LMAC_PHY, "\t PLDM does not need to test_phy_startup()\n");
		} else {
			status = nse_aq_test_phy_startup(hw);
			if (status) {
				nse_debug(hw, NSE_DBG_LMAC_PHY,
					  "\t even test_phy_startup() status=%d, consider it OK\n",
					status);
				status = NSE_SUCCESS;
			}
		}

		goto out;
	}

	if (hw->mac_type == NSE_MAC_TYPE_AMBER) {
		/* here, we are real ASIC, not FPGA and PLDM (which is USE_TEST_PHY)
		 */
		status = nse_aq_eth_set_link_amber(hw, speed, link_type, fec);

	} else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE) {
		status = nse_aq_eth_set_link_ms(hw, speed, link_type, fec);

	} else {
		dev_err(dev, "[%s] BAD: not impl for this mac_type(%d)\n",
			__func__, hw->mac_type);
		status = NSE_ERR_NOT_IMPL;
	}

out:
	return status;
}

static enum nse_status
lmac_phy_eth_start_an(struct nse_hw *hw, u32 speeds, u64 link_types, u32 fec_adv)
{
	struct device *dev = nse_hw_to_dev(hw);
	enum nse_status status = NSE_SUCCESS;

	nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] speeds=0x%X, link_types=0x%lX, fec=0x%X\n",
		  __func__, speeds, (unsigned long)link_types, fec_adv);

	if (hw->mac_type == NSE_MAC_TYPE_AMBER) {
		/* here, we are real ASIC, not FPGA and PLDM (which is USE_TEST_PHY)
		 */
		status = nse_aq_eth_start_an_amber(hw, speeds, link_types, fec_adv);

	} else {
		dev_err(dev, "[%s] BAD: not impl for this mac_type(%d)\n",
			__func__, hw->mac_type);
		status = NSE_ERR_NOT_IMPL;
	}

	return status;
}

static void
select_fec_with_an_disabled(struct nse_hw *hw)
{
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *ephy_info = &lpinfo->ephy_info;
	bool is_auto = !!(lpinfo->req_fec_from_user & FEC_AUTO);
	u32 req_fec_set = lpinfo->req_fec_from_user & ~FEC_AUTO;
	u32 fec_cur = FEC_OFF;
	int i;

	req_fec_set &= lpinfo->supported_fec;

	if (nse_is_nic_use_ephy(hw->nic_type) && ephy_status_is_module_present(hw,
	    true) && ephy_info->is_supported_mod) {
		nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s, %d] external mod_supported_fec=0x%X(%s)\n",
			  __func__, __LINE__, ephy_info->mod_supported_fec,
			  fec_str(ephy_info->mod_supported_fec));

		req_fec_set &= ephy_info->mod_supported_fec;
	}

	if (lpinfo->req_link_speeds >= NSE_AQ_LINK_SPEED_100GB)
		req_fec_set &= ~FEC_BASER;

	if (lpinfo->req_link_speeds <= NSE_AQ_LINK_SPEED_20GB)
		req_fec_set &= ~FEC_RS;


	/* determine req_fec_cur */

	if (req_fec_set == FEC_NONE) {
		fec_cur = FEC_OFF;

	} else {
		/* at least 1 bit in (_RS, _BASER, _OFF) is set */

		if (req_fec_set == FEC_OFF) {
			/* only _OFF, then no need set _AUTO */

			fec_cur = FEC_OFF;

		} else {
			/* at least 1 bit in (_RS, _BASER) is set, might also contains _OFF */

			if (is_auto) {
				i = find_set_bit_cnt_u32(req_fec_set);
				/* if just 1 bit (RS or BASR), then add a extra
				 * _OFF for auto switch logic
				 */
				if (i == 1)
					req_fec_set |= FEC_OFF;

				/* allow multi bits inside */
				fec_cur = FEC_AUTO | req_fec_set;

			} else {
				/* is_auto = false, then fix_bit: just allow 1 bit
				 * - let it be highest bit
				 */

				/* must be >=0, RS or BASR */
				i = find_highest_bit_u32(req_fec_set);

				fec_cur = BIT(i);
			}
		}
	}

	lpinfo->req_fec_cur = fec_cur;

	nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s, %d] req_fec_from_user=0x%X(%s), req_fec_cur=0x%X(%s)\n",
		  __func__, __LINE__,
		  lpinfo->req_fec_from_user, fec_str(lpinfo->req_fec_from_user),
		  fec_cur, fec_str(fec_cur));
}

static enum nse_status
/* select just one speed and one link_type */
select_link_speed_type_with_an_disabled(struct nse_hw *hw)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *ephy_info = &lpinfo->ephy_info;
	u32 link_speed = NSE_AQ_LINK_SPEED_UNKNOWN;
	u64 link_type = NSE_ETH_LINK_TYPE_UNKNOWN;
	int val;
	enum nse_status status = NSE_ERR_NOT_SUPPORTED;

	/*  AN disabled, select req_link_types according to req_link_speed ( which might be from
	 * ethtool -s speed)
	 *
	 * select just one speed and one link_type
	 */

	link_speed = lpinfo->req_link_speed_from_user;

	if (nse_is_nic_use_ephy(hw->nic_type) && ephy_status_is_module_present(hw, true)) {
		if (!ephy_info->is_supported_mod) {
			dev_err(dev, "[%s, %d] external module not compatible\n",
				__func__, __LINE__);
			goto out;
		}

		link_speed &= ephy_info->mod_supported_link_speeds;
	}

	if (link_speed == NSE_AQ_LINK_SPEED_UNKNOWN)	//0, then wish to choose highest speed
		link_speed = lpinfo->supported_link_speeds;
	else
		link_speed &= lpinfo->supported_link_speeds;

	/* previously already checked is_supported_mod, so must have a interset */
	if (nse_is_nic_use_ephy(hw->nic_type) && ephy_status_is_module_present(hw, true))
		link_speed &= ephy_info->mod_supported_link_speeds;

	val = find_highest_bit_u32(link_speed);
	if (val < 0) {
		dev_err(dev, "[%s, %d] BAD: link_speed=%X\n", __func__, __LINE__, link_speed);
		goto out;
	}

	link_speed = BIT(val);

	if (hw->nic_type == NSE_NIC_TYPE_1000BASE_T) {
		if (link_speed == NSE_AQ_LINK_SPEED_1000MB) {
			link_type = NSE_ETH_LINK_TYPE_1GBaseT;

		} else {
			dev_err(dev, "[%s, %d] BAD: link_speed=%X\n",
				__func__, __LINE__, link_speed);
			goto out;
		}

	} else if (hw->nic_type == NSE_NIC_TYPE_SFP) {
		if (link_speed == NSE_AQ_LINK_SPEED_25GB) {
			link_type = NSE_ETH_LINK_TYPE_25GbaseR;

		} else if (link_speed == NSE_AQ_LINK_SPEED_10GB) {
			link_type = NSE_ETH_LINK_TYPE_10GbaseR;

		} else {
			dev_err(dev, "[%s, %d] BAD: SFP link_speed=%X\n",
				__func__, __LINE__, link_speed);
			goto out;
		}

	} else if (hw->nic_type == NSE_NIC_TYPE_QSFP) {
		if (link_speed == NSE_AQ_LINK_SPEED_100GB) {
			link_type = NSE_ETH_LINK_TYPE_100GbaseR4;

		} else if (link_speed == NSE_AQ_LINK_SPEED_50GB) {
			link_type = NSE_ETH_LINK_TYPE_50GbaseR2;

		} else if (link_speed == NSE_AQ_LINK_SPEED_40GB) {
			link_type = NSE_ETH_LINK_TYPE_40GbaseR4;

		} else if (link_speed == NSE_AQ_LINK_SPEED_25GB) {
			link_type = NSE_ETH_LINK_TYPE_25GbaseR;

		} else if (link_speed == NSE_AQ_LINK_SPEED_200GB) {
			link_type = NSE_ETH_LINK_TYPE_200GbaseR4;

		} else if (link_speed == NSE_AQ_LINK_SPEED_400GB) {
			link_type = NSE_ETH_LINK_TYPE_400GbaseR4;

		} else {
			dev_err(dev, "[%s, %d] BAD: QSFP link_speed=%X not supported\n",
				__func__, __LINE__, link_speed);
			goto out;
		}

	} else {
		dev_err(dev, "[%s, %d] not impl for nic_type=%d\n",
			__func__, __LINE__, hw->nic_type);
		status = NSE_ERR_NOT_IMPL;
		goto out;
	}

	lpinfo->req_link_speeds = link_speed;
	lpinfo->req_link_types = link_type;

	status = NSE_SUCCESS;

out:
	return status;
}

static void
select_fec_with_an_enabled(struct nse_hw *hw)
{
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *ephy_info = &lpinfo->ephy_info;
	bool is_auto = !!(lpinfo->req_fec_from_user & FEC_AUTO);
	u32 req_fec_set = lpinfo->req_fec_from_user & ~FEC_AUTO;
	u32 fec_cur = FEC_OFF;
	int i;

	req_fec_set &= lpinfo->supported_fec;

	if (nse_is_nic_use_ephy(hw->nic_type) && ephy_status_is_module_present(hw,
	    true) && ephy_info->is_supported_mod) {
		nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s, %d] external mod_supported_fec=0x%X(%s)\n",
			  __func__, __LINE__, ephy_info->mod_supported_fec,
			  fec_str(ephy_info->mod_supported_fec));

		req_fec_set &= ephy_info->mod_supported_fec;
	}

	/* determine req_fec_cur */

	if (req_fec_set == FEC_NONE) {
		fec_cur = FEC_OFF;

	} else {
		/* at least 1 bit in (_RS, _BASER, _OFF) is set */

		if (req_fec_set == FEC_OFF) {
			/* only _OFF, then no need set _AUTO */

			fec_cur = FEC_OFF;

		} else {
			/* at least 1 bit in (_RS, _BASER) is set, might also contains _OFF */

			if (is_auto) {
				i = find_set_bit_cnt_u32(req_fec_set);
				/* if just 1 bit (RS or BASR), then add a extra
				 * _OFF for auto switch logic
				 */
				if (i == 1)
					req_fec_set |= FEC_OFF;

				/* allow multi bits inside */
				fec_cur = FEC_AUTO | req_fec_set;

			} else {
				/* is_auto = false, but fec_cur might contain 1
				 * bit _OFF, this would cause sematics
				 * confusion, clear it
				 */

				req_fec_set &= ~(FEC_OFF);

				fec_cur = req_fec_set;
			}
		}
	}

	lpinfo->req_fec_cur = fec_cur;

	nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s, %d] req_fec_from_user=0x%X(%s), req_fec_cur=0x%X(%s)\n",
		  __func__, __LINE__,
		  lpinfo->req_fec_from_user, fec_str(lpinfo->req_fec_from_user),
		  fec_cur, fec_str(fec_cur));
}

static enum nse_status
select_link_types_speeds_with_an_enabled(struct nse_hw *hw)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *epinfo = &lpinfo->ephy_info;
	u64 link_types = NSE_ETH_LINK_TYPE_UNKNOWN;
	u32 link_speeds = NSE_AQ_LINK_SPEED_UNKNOWN;
	enum nse_status status = NSE_ERR_NOT_SUPPORTED;

	/*  AN enabled, select req_link_types and req_link_speed according to lks->advertising from
	 * ethtool -s
	 */

	link_types = lpinfo->req_link_types_from_user;

	if (nse_is_nic_use_ephy(hw->nic_type) && ephy_status_is_module_present(hw, true)) {
		if (!epinfo->is_supported_mod) {	// we should have true, but just in case
			dev_err(dev, "[%s, %d] external module not compatible\n",
				__func__, __LINE__);
			goto out;
		}

		link_types &= epinfo->mod_supported_link_types;

		link_types &= lpinfo->supported_link_types;

		if (link_types == NSE_ETH_LINK_TYPE_UNKNOWN)
			link_types = lpinfo->supported_link_types &
				epinfo->mod_supported_link_types;

	} else {
		link_types &= lpinfo->supported_link_types;

		if (link_types == NSE_ETH_LINK_TYPE_UNKNOWN)
			link_types = lpinfo->supported_link_types;
	}

	if (link_types == NSE_ETH_LINK_TYPE_UNKNOWN) {
		dev_err(dev, "[%s, %d] bad case #0\n", __func__, __LINE__);
		goto out;
	}

	if (link_types & NSE_ETH_LINK_TYPE_10GbaseR)
		link_speeds |= NSE_AQ_LINK_SPEED_10GB;

	if (link_types & NSE_ETH_LINK_TYPE_25GbaseR)
		link_speeds |= NSE_AQ_LINK_SPEED_25GB;

	if (link_types & NSE_ETH_LINK_TYPE_40GbaseR4)
		link_speeds |= NSE_AQ_LINK_SPEED_40GB;

	if (link_types & NSE_ETH_LINK_TYPE_100GbaseR4)
		link_speeds |= NSE_AQ_LINK_SPEED_100GB;

	if (link_types & NSE_ETH_LINK_TYPE_200GbaseR4)
		link_speeds |= NSE_AQ_LINK_SPEED_200GB;

	if (link_types & NSE_ETH_LINK_TYPE_400GbaseR4)
		link_speeds |= NSE_AQ_LINK_SPEED_400GB;

	nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] link_types=0x%lX, link_speed=0x%X\n",
		  __func__, (unsigned long)link_types, link_speeds);

	lpinfo->req_link_types = link_types;
	lpinfo->req_link_speeds = link_speeds;

	status = NSE_SUCCESS;

out:
	return status;
}

enum nse_status
nse_lmac_phy_eth_start_link_or_an(struct nse_hw *hw)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_ephy_info *epinfo = &lpinfo->ephy_info;
	bool start_an = false;
	enum nse_status status = NSE_SUCCESS;

	if (nse_loopback_mode) {
		nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] skip and return early because loopback_mode=%d\n",
			  __func__, nse_loopback_mode);
		goto out;
	}

	if (lpinfo->an_info.an_supported && lpinfo->an_info.an_enabled) {
		if (nse_is_nic_use_ephy(hw->nic_type)) {
			if (ephy_status_is_module_present(hw, true) && epinfo->is_supported_mod) {
				if (epinfo->mod_an_supported)
					start_an = true;
				else
					start_an = false;

			/* mod not present, don't try AN, but try fixed highest speed */
			} else {
				start_an = false;
			}

		} else
			start_an = true;
	}

	if (start_an) {
		status = select_link_types_speeds_with_an_enabled(hw);
		if (status) {
			dev_err(dev,
	"[%s] FAIL: select_link_types_speeds_with_an_enabled(), status=%d\n", __func__, status);
			goto out;
		}

		select_fec_with_an_enabled(hw);

		status = lmac_phy_eth_start_an(hw, lpinfo->req_link_speeds,
					       lpinfo->req_link_types, lpinfo->req_fec_cur);
		if (status) {
			dev_err(dev, "[%s] FAIL: eth_start_an(), status=%d\n",
				__func__, status);
			goto out;
		}

		nse_debug(hw, NSE_DBG_LMAC_PHY,
			  "[%s] DONE: eth_start_an(), see later if can get eth link evt\n",
			__func__);

	} else {
		status = select_link_speed_type_with_an_disabled(hw);
		if (status) {
			dev_err(dev,
				"[%s] FAIL: select_link_speed_type_with_an_disabled(), status=%d\n",
				__func__, status);
			goto out;
		}

		select_fec_with_an_disabled(hw);

		status = lmac_phy_eth_set_link(hw, lpinfo->req_link_speeds,
					       lpinfo->req_link_types, lpinfo->req_fec_cur);
		if (status) {
			dev_err(dev, "[%s] FAIL: eth_set_link(), status=%d\n",
				__func__, status);
			goto out;
		}

		nse_debug(hw, NSE_DBG_LMAC_PHY,
			  "[%s] DONE: eth_set_link(), see later if can get eth link evt\n",
			__func__);
	}

out:
	return status;
}

static enum nse_status
test_phy_link_info_update(struct nse_hw *hw)
{
	struct nse_link_info *li;
	u32 ls, speed;
	enum nse_status status;

	li = &hw->port_info->lmac_phy_info.link_info;
	li->link_status = 0;

	status = nse_aq_test_phy_get_link_status(hw, &ls, &speed);

	if (!status) {
		/* update current link status information */

		li->link_status = ls ? NSE_AQ_LINK_UP : 0;

		switch (speed) {
		case 1:
			li->link_speed = NSE_AQ_LINK_SPEED_10MB;
			break;
		case 2:
			li->link_speed = NSE_AQ_LINK_SPEED_100MB;
			break;
		case 3:
			li->link_speed = NSE_AQ_LINK_SPEED_1000MB;
			break;
		default:
			li->link_speed = NSE_AQ_LINK_SPEED_UNKNOWN;
			break;
		}

		if (li->link_speed != NSE_AQ_LINK_SPEED_1000MB) {
			nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] test_phy speed=0x%X, not 1000MB, consider link DOWN\n",
									__func__,
										li->link_speed);
			li->link_status = 0;
		}
	}

	return status;
}

/* use to overwrite link_info, for some logic */
void nse_lmac_phy_link_info_overwrite(struct nse_hw *hw, bool link_up, u32 link_speed)
{
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_link_info *li = &lpinfo->link_info;

	nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] link_up=%d, link_speed=0x%X\n",
				__func__, link_up, link_speed);

	li->link_status = link_up ? NSE_AQ_LINK_UP : 0;
	li->link_speed = link_speed;
}

enum nse_status nse_lmac_phy_link_info_update(struct nse_hw *hw)
{
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct nse_link_info *li = &lpinfo->link_info;
	struct nse_aqc_eth_get_link_status lk_sts;
	enum nse_status status;

	if (lpinfo->static_flags & LMAC_PHY_STATIC_FLAG_USE_TEST_PHY) {
		status = test_phy_link_info_update(hw);

	/* for Amber PLDM */
	} else if (lpinfo->static_flags & LMAC_PHY_STATIC_FLAG_CONSIDER_ALWAYS_LINK_UP) {
		nse_debug(hw, NSE_DBG_LMAC_PHY_DETAIL, "[%s, %d] mac_type=%d, now consider always link UP and link speed=100G\n",
			  __func__, __LINE__, hw->mac_type);

		li->link_status = NSE_AQ_LINK_UP;
		li->link_speed = NSE_AQ_LINK_SPEED_100GB;

		status = NSE_SUCCESS;

	} else {
		status = nse_aq_eth_get_link_status(hw, &lk_sts);
		if (!status) {
			li->link_status = le32_to_cpu(lk_sts.link_status);
			li->link_speed = le32_to_cpu(lk_sts.link_speed);
		}
	}

	return status;
}

static void vsi_print_link_msg(struct nse_hw *hw, struct nse_vsi *vsi, bool isup)
{
	if (!vsi)
		return;

	if (vsi->current_isup == isup)
		return;

	vsi->current_isup = isup;

	if (!isup)
		netdev_info(vsi->netdev, "NIC Link is Down\n");
	else
		netdev_info(vsi->netdev, "NIC Link is UP\n");
}

/**
 * vsi_link_event - update the VSI's netdev
 * @vsi: the VSI on which the link event occurred
 * @link_up: whether or not the VSI needs to be set up or down
 */
static void vsi_link_event(struct nse_hw *hw, struct nse_vsi *vsi, bool link_up)
{
	if (!vsi)
		return;

	if (test_bit(NSE_VSI_DOWN, vsi->state) || !vsi->netdev)
		return;

	if (vsi->type == NSE_VSI_PF) {
		if (link_up == netif_carrier_ok(vsi->netdev))
			return;

		nse_debug(hw, NSE_DBG_LMAC_PHY_DETAIL, "[%s] notify link_up=%d to stack\n",
										__func__,
											link_up);

		if (link_up) {
			nse_debug(hw, NSE_DBG_LMAC_PHY_DETAIL, "[%s, %d] before netif_carrier_on()\n",
				  __func__, __LINE__);

			netif_carrier_on(vsi->netdev);

			nse_debug(hw, NSE_DBG_LMAC_PHY_DETAIL, "[%s, %d] before netif_tx_wake_all_queues()\n",
				  __func__, __LINE__);

			netif_tx_wake_all_queues(vsi->netdev);

		} else {
			nse_debug(hw, NSE_DBG_LMAC_PHY_DETAIL, "[%s, %d] before netif_carrier_off()\n",
				  __func__, __LINE__);

			netif_carrier_off(vsi->netdev);

			nse_debug(hw, NSE_DBG_LMAC_PHY_DETAIL, "[%s, %d] before netif_tx_stop_all_queues()\n",
				  __func__, __LINE__);

			netif_tx_stop_all_queues(vsi->netdev);
		}

		nse_debug(hw, NSE_DBG_LMAC_PHY_DETAIL, "[%s] notify link_up=%d to stack --- done\n",
										__func__,
											link_up);
	}
}

int nse_lmac_phy_link_info_notify(struct nse_hw *hw, bool force)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct iidc_event *iev;
	struct nse_vsi *vsi;
	bool old_link, new_link;
	int ret = 0;

	vsi = nse_get_main_vsi(pf);
	if (!vsi || !vsi->port_info) {
		ret = -EINVAL;
		goto out;
	}

	old_link = !!(lpinfo->link_info_old.link_status);

	new_link = !!(lpinfo->link_info.link_status);

	nse_debug(hw, NSE_DBG_LMAC_PHY_DETAIL, "[%s] old_link=%d, new_link=%d, link_speed=0x%X, force=%d\n",
		  __func__, old_link, new_link, lpinfo->link_info.link_speed, force);

	/* if the old link up/down and speed is the same as the new */
	if (!force && (new_link == old_link))
		goto out;

	iev = kzalloc(sizeof(*iev), GFP_KERNEL);
	if (!iev) {
		ret = -ENOMEM;
		goto out;
	}

	lpinfo->prev_notify_link_down = !new_link;

	nse_debug(hw, NSE_DBG_LMAC_PHY_DETAIL, "[%s, %d] notify IIDC_EVENT_LINK_CHNG to auxs --- start\n",
								__func__, __LINE__);

	set_bit(IIDC_EVENT_LINK_CHNG, iev->type);
	iev->info.link_up = new_link;
	nse_send_event_to_auxs(pf, iev);

	kfree(iev);

	nse_debug(hw, NSE_DBG_LMAC_PHY_DETAIL, "[%s, %d] notify IIDC_EVENT_LINK_CHNG to auxs --- done\n",
								__func__, __LINE__);

	vsi_link_event(hw, vsi, new_link);

	vsi_print_link_msg(hw, vsi, new_link);

	nse_vc_notify_link_state(pf, force);

	lpinfo->link_info_old = lpinfo->link_info;	//save current link_info as old.

out:
	return ret;
}

void nse_lmac_phy_handle_event(struct nse_pf *pf, struct nse_rq_event_info *event)
{
	struct nse_hw *hw = &pf->hw;
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_aqc_lmac_phy_event *evt = (struct nse_aqc_lmac_phy_event *)event->msg_buf;
	struct nse_aqc_lmac_phy_event_eth *evt_eth = NULL;
	struct nse_aqc_lmac_phy_event_ephy *evt_ephy = NULL;
	u32 evt_src = le32_to_cpu(evt->evt_src);
	u32 evt_id;
	u32 ephy_type;

	nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] enter: lan_id=%d, evt_src=%d\n",
									__func__,
										evt->hdr.lan_id,
										evt->evt_src);

	nse_lmac_phy_lock(hw);

	if (evt->hdr.lan_id != hw->lan_id) {
		dev_info(dev, "[%s] BAD: evt lan_id=%d is not my lan_id=%d\n",
						__func__, evt->hdr.lan_id, hw->lan_id);
		goto out;
	}

	if (evt_src == NSE_AQC_LMAC_PHY_EVT_SRC_ETH) {
		evt_eth = (struct nse_aqc_lmac_phy_event_eth *)&evt->evt_eth;

		evt_id = le32_to_cpu(evt_eth->evt_id);

		nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] evt_eth, evt_id=%d\n", __func__, evt_id);

		if (evt_id == NSE_AQC_LMAC_PHY_EVT_ETH_LSC)
			lpinfo->dyn_flags |= LMAC_PHY_DYN_FLAG_NEED_UPDATE_LINK_INFO;

		else
			dev_info(dev, "[%s] unknown evt_eth evt_id=%d\n", __func__, evt_id);

	} else if (evt_src == NSE_AQC_LMAC_PHY_EVT_SRC_EPHY) {
		evt_ephy = (struct nse_aqc_lmac_phy_event_ephy *)&evt->evt_ephy;

		ephy_type = le32_to_cpu(evt_ephy->ephy_type);

		nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] evt_ephy\n", __func__);

		if (nse_is_nic_use_ephy(hw->nic_type))
			lpinfo->dyn_flags |= (LMAC_PHY_DYN_FLAG_NEED_UPDATE_EPHY_STATUS |
					      LMAC_PHY_DYN_FLAG_NEED_UPDATE_LINK_INFO);
		else
			dev_info(dev,
"[%s] bad, nic_type=0x%X does not have ephy but receive evt_ephy\n", __func__, hw->nic_type);

	} else {
		dev_info(dev, "[%s] unimpl evt_src=%d\n", __func__, evt_src);
	}

out:
	nse_lmac_phy_unlock(hw);
}

void nse_test_phy_handle_link_event(struct nse_pf *pf, struct nse_rq_event_info *event)
{
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_aqc_fpga_phy_lse *link_data = (struct nse_aqc_fpga_phy_lse *)event->msg_buf;

	if (link_data->lan_id != hw->lan_id) {	//not my LSE ?
		dev_warn(dev, "[%s] not my LSE, my lan_id is %d, but LSE lan_id is %d\n",
						__func__, hw->lan_id, link_data->lan_id);
		return;
	}

	hw->port_info->lmac_phy_info.dyn_flags |= LMAC_PHY_DYN_FLAG_NEED_UPDATE_LINK_INFO;
}

/* ugly, moonstone specific logic */
static void ms_check_sync_lmac_fc_register(struct nse_hw *hw)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_aqc_qos_db_cfg *saved_cfg = &hw->port_info->qos_cfg.fc_chk_saved_db_cfg;
	struct nse_aqc_qos_db_cfg *polled_cfg = &hw->port_info->qos_cfg.fc_chk_poll_db_cfg;
	enum nse_status status;

	if (hw->mac_type != NSE_MAC_TYPE_MOONSTONE)
		return;

	status = nse_aq_qos_db_get_cfg(hw, polled_cfg);
	if (status)
		return;

	if (polled_cfg->ms.lmac_tx_pause_en_value != saved_cfg->ms.lmac_tx_pause_en_value ||
	    polled_cfg->ms.lmac_txsfc_ehip_cfg_value != saved_cfg->ms.lmac_txsfc_ehip_cfg_value ||
	    polled_cfg->ms.lmac_rx_pause_enable_value != saved_cfg->ms.lmac_rx_pause_enable_value ||
		polled_cfg->ms.lmac_rx_pause_fwd_value != saved_cfg->ms.lmac_rx_pause_fwd_value ||
	    polled_cfg->ms.lmac_rxsfc_ehip_cfg_value != saved_cfg->ms.lmac_rxsfc_ehip_cfg_value) {
		dev_info(dev, "[%s] need to reconfig LMAC FC\n", __func__);

		status = nse_set_dcb_cfg_lw(hw->port_info, NSE_DCB_CFG_CHG_TYPE_PFC);
		if (status) {
			dev_info(dev, "[%s] FAIL reconfig LMAC FC, status=%d, retry next time\n",
				 __func__, status);
		}
	}
}

void nse_lmac_phy_subtask(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	bool link_status = false;
	u32 link_speed = NSE_AQ_LINK_SPEED_UNKNOWN;
	bool overwrite_link_info = false;
	bool notify_by_force = false;
	unsigned long random_delta;
	enum nse_status status;
	int ret;

	/* if interface is down do nothing */
	if (test_bit(NSE_DOWN, pf->state) ||
	    test_bit(NSE_CFG_BUSY, pf->state))
		return;

	if (lpinfo->dyn_flags)
		nse_debug(hw, NSE_DBG_LMAC_PHY_DETAIL, "[%s] dyn_flags=0x%X\n",
			  __func__, lpinfo->dyn_flags);

	if (lpinfo->dyn_flags & LMAC_PHY_DYN_FLAG_NOT_RUN_SUBTASK) {
		nse_debug(hw, NSE_DBG_LMAC_PHY_DETAIL,
			  "[%s] return early because NOT_RUN_SUBTASK flag\n", __func__);
		return;
	}

	nse_lmac_phy_lock(hw);

	lpinfo->link_down_reason = NSE_LMAC_PHY_LINK_DOWN_REASON_UNKNOWN;

	if (lpinfo->dyn_flags & LMAC_PHY_DYN_FLAG_NEED_FIRST_FORCE_NOTIFY_LINK_DOWN) {
		nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s, %d] NEED_FIRST_FORCE_NOTIFY_LINK_DOWN\n",
			  __func__, __LINE__);

		/* link_status = false, speed = UNKNOWN */
		nse_lmac_phy_link_info_overwrite(hw, link_status, link_speed);

		(void)nse_lmac_phy_link_info_notify(hw, true);
	}

	lpinfo->dyn_flags &= ~(LMAC_PHY_DYN_FLAG_NEED_FIRST_FORCE_NOTIFY_LINK_DOWN);

	/**************
	 * logic block: handle ephy
	 **************/

	if ((lpinfo->dyn_flags & LMAC_PHY_DYN_FLAG_NEED_UPDATE_EPHY_STATUS) &&
	    nse_is_nic_use_ephy(hw->nic_type)) {
		nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s, %d] NEED_UPDATE_EPHY_STATUS\n",
			  __func__, __LINE__);

		status = ephy_status_get_1st(hw);	/* get latest ephy pin status */
		if (status) {
			dev_err(dev,
				"[%s, %d] FAIL: ephy_status_get_1st(), status=%d, retry again\n",
				__func__, __LINE__, status);

			ephy_reset_info(hw);

			overwrite_link_info = true;	/* link_status = false, speed = UNKNOWN */

			lpinfo->link_down_reason = NSE_LMAC_PHY_LINK_DOWN_REASON_EPHY_NOT_READY;

			goto notify_link_info;		/* link_status=false */
		}

		if (hw->debug_mask & NSE_DBG_LMAC_PHY)
			ephy_status_dump(hw, false);

		/* module not represent */
		if (!ephy_status_is_module_present(hw, true)) {
			nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s, %d] ephy mod not present\n",
				  __func__, __LINE__);

			ephy_reset_info(hw);

			overwrite_link_info = true;

			lpinfo->link_down_reason = NSE_LMAC_PHY_LINK_DOWN_REASON_EPHY_NOT_READY;

			goto notify_link_info;	/* link_status=false */
		}

		/* new module inserted - read module mem registers (basic) and parse it */
		if (ephy_status_is_module_present(hw, true) &&
		    !ephy_status_is_module_present(hw, false)) {
			status = ephy_mem_read_basic(hw);
			if (status) {
				dev_err(dev,
"[%s, %d] FAIL: ephy mem_read_basic(), status=%d, retry again\n", __func__, __LINE__, status);

				ephy_reset_info(hw);

				overwrite_link_info = true;

				lpinfo->link_down_reason =
					NSE_LMAC_PHY_LINK_DOWN_REASON_EPHY_NOT_READY;

				goto notify_link_info;	/* link_status=false */
			}

			if (hw->debug_mask & NSE_DBG_LMAC_PHY)
				ephy_mem_dump_basic_raw(hw);

			ephy_mem_parse_basic(hw);

			if (hw->debug_mask & NSE_DBG_LMAC_PHY)
				ephy_mem_dump_basic_parsing_result(hw);

			/*  if after parsing mem, is_supported_mod == false , then should not
			 * configure it
			 */
			if (!lpinfo->ephy_info.is_supported_mod) {
				dev_err(dev,
					"[%s, %d] ephy mod is_supported=false, check next time\n",
					__func__, __LINE__);

				ephy_reset_info(hw);

				overwrite_link_info = true;

				lpinfo->link_down_reason =
					NSE_LMAC_PHY_LINK_DOWN_REASON_EPHY_NOT_READY;

				goto notify_link_info;	/* link_status=false */
			}

			/* tune these into valid range */
			if (lpinfo->an_info.an_enabled) {
				/* might be LINK_TYPE_UNKNOWN */
				if (lpinfo->ephy_info.mod_an_supported)
					lpinfo->req_link_types_from_user &= lpinfo->ephy_info.mod_supported_link_types;

			} else {
				/* might become SPEED_UNKNOWN*/
				lpinfo->req_link_speed_from_user &= lpinfo->ephy_info.mod_supported_link_speeds;
			}

			status = ephy_prepare_for_link(hw);
			if (status) {
				dev_err(dev, "[%s, %d] FAIL: ephy prepare_for_link(), status=%d\n",
					__func__, __LINE__, status);

				ephy_reset_info(hw);

				overwrite_link_info = true;

				lpinfo->link_down_reason =
					NSE_LMAC_PHY_LINK_DOWN_REASON_EPHY_NOT_READY;

				goto notify_link_info;	/* link_status=false */
			}
		}

		status = ephy_status_get_2nd(hw);
		if (status) {
			dev_err(dev, "[%s, %d] FAIL: ephy status_get_2nd(), status=%d\n",
				__func__, __LINE__, status);

			ephy_reset_info(hw);

			overwrite_link_info = true;

			lpinfo->link_down_reason = NSE_LMAC_PHY_LINK_DOWN_REASON_EPHY_NOT_READY;

			goto notify_link_info;	/* link_status=false */
		}

		/* check signal OK */
		if (ephy_status_is_signal_ok(hw, true) && !ephy_status_is_signal_ok(hw, false)) {
			/* signal now OK ( old not OK ) */

			nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s, %d] ephy signal become OK, is_supported=true, need to start_link_or_an\n", __func__, __LINE__);

			lpinfo->dyn_flags |= LMAC_PHY_DYN_FLAG_NEED_START_LINK_OR_AN;

		} else if (!ephy_status_is_signal_ok(hw, true)) {
			/* signal now NOT OK */

			nse_debug(hw, NSE_DBG_LMAC_PHY,
				  "[%s, %d] ephy signal not OK, maybe media not ready\n",
				__func__, __LINE__);

			ephy_status_sync_old_new(hw);

			overwrite_link_info = true;

			lpinfo->link_down_reason = NSE_LMAC_PHY_LINK_DOWN_REASON_EPHY_NOT_READY;

			goto notify_link_info;	/* link_status=false */
		}

		ephy_status_sync_old_new(hw);
	}

	lpinfo->dyn_flags &= ~(LMAC_PHY_DYN_FLAG_NEED_UPDATE_EPHY_STATUS);

	/**************
	 * logic block: start_link_or_an
	 **************/

	if (lpinfo->dyn_flags & LMAC_PHY_DYN_FLAG_NEED_START_LINK_OR_AN) {
		nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s, %d] NEED_START_LINK_OR_AN\n",
			  __func__, __LINE__);

		status = nse_lmac_phy_eth_start_link_or_an(hw);
		if (status) {
			dev_err(dev,
				"[%s, %d] FAIL: eth_start_link_or_an(), status=%d, retry again\n",
				__func__, __LINE__, status);

			overwrite_link_info = true;

			lpinfo->link_down_reason =
				NSE_LMAC_PHY_LINK_DOWN_REASON_START_LINK_OR_AN_FAIL;

			goto notify_link_info;	/* link_status=false */
		}

		lpinfo->dyn_flags |= LMAC_PHY_DYN_FLAG_NEED_UPDATE_LINK_INFO;
	}

	lpinfo->dyn_flags &= ~(LMAC_PHY_DYN_FLAG_NEED_START_LINK_OR_AN);

	/**************
	 * logic block: update_link_info
	 **************/

	if ((lpinfo->dyn_flags & LMAC_PHY_DYN_FLAG_NEED_UPDATE_LINK_INFO) ||
		time_after_eq(jiffies, lpinfo->poll_link_info_prev +
			      lpinfo->poll_link_info_period)) {
		nse_debug(hw, NSE_DBG_LMAC_PHY_DETAIL, "[%s, %d] poll_link_info_prev=%ld, jiffies=%ld, dyn_flags=0x%X\n",
			  __func__, __LINE__, lpinfo->poll_link_info_prev,
				  jiffies, lpinfo->dyn_flags);

		lpinfo->poll_link_info_prev = jiffies;

		status = nse_lmac_phy_link_info_update(hw);

		if (status) {
			dev_err(dev,
				"[%s] FAIL: update_link_status(), status=%d, gonna retry again\n",
				__func__, status);

			lpinfo->link_info.link_status = 0;
			lpinfo->link_info.link_speed = NSE_AQ_LINK_SPEED_UNKNOWN;

			lpinfo->link_down_reason =
				NSE_LMAC_PHY_LINK_DOWN_READON_UPDATE_LINK_INFO_FAIL;

		} else {
			nse_debug(hw, NSE_DBG_LMAC_PHY_DETAIL, "[%s, %d] link_status=%d, link_speed=%X\n",
				  __func__, __LINE__,
				  lpinfo->link_info.link_status, lpinfo->link_info.link_speed);

			if (lpinfo->link_info.link_status)
				lpinfo->link_down_reason = NSE_LMAC_PHY_LINK_DOWN_REASON_ALEADY_UP;
			else
				lpinfo->link_down_reason = NSE_LMAC_PHY_LINK_DOWN_REASON_NOT_UP_YET;
		}

		link_status = !!(lpinfo->link_info.link_status);
		link_speed = lpinfo->link_info.link_speed;

		/* ugly, moonstone specific logic */
		ms_check_sync_lmac_fc_register(hw);

notify_link_info:

		if (overwrite_link_info)
			nse_lmac_phy_link_info_overwrite(hw, link_status, link_speed);

		if (!link_status)
			/* previously already notify DOWN, may ignore repeatedly notify */
			notify_by_force = !lpinfo->prev_notify_link_down;
		else
			notify_by_force = (lpinfo->dyn_flags &
					   LMAC_PHY_DYN_FLAG_NEED_UPDATE_LINK_INFO);

		ret = nse_lmac_phy_link_info_notify(hw, notify_by_force);
		if (ret) {
			dev_err(dev,
	"[%s] FAIL: lmac_phy_link_info_notify(), ret=%d, gonna retry again\n", __func__, ret);

			lpinfo->link_info.link_status = 0;
			lpinfo->link_info.link_speed = NSE_AQ_LINK_SPEED_UNKNOWN;

			//= !!(lpinfo->link_info.link_status), for later if (!link_status) logic
			link_status = false;

			lpinfo->prev_notify_link_down = false;

			if (lpinfo->link_down_reason == NSE_LMAC_PHY_LINK_DOWN_REASON_UNKNOWN)
				lpinfo->link_down_reason =
					NSE_LMAC_PHY_LINK_DOWN_READON_NOTIFY_LINK_INFO_FAIL;
		}

		lpinfo->dyn_flags &= ~(LMAC_PHY_DYN_FLAG_NEED_UPDATE_LINK_INFO);

		if (!link_status) {
			switch (lpinfo->link_down_reason) {
			case NSE_LMAC_PHY_LINK_DOWN_REASON_EPHY_NOT_READY:
				lpinfo->dyn_flags |= LMAC_PHY_DYN_FLAG_NEED_UPDATE_EPHY_STATUS;
				break;

			case NSE_LMAC_PHY_LINK_DOWN_REASON_START_LINK_OR_AN_FAIL:
			case NSE_LMAC_PHY_LINK_DOWN_REASON_AN_TIMEOUT:
				lpinfo->dyn_flags |= LMAC_PHY_DYN_FLAG_NEED_START_LINK_OR_AN;
				break;

			case NSE_LMAC_PHY_LINK_DOWN_READON_UPDATE_LINK_INFO_FAIL:
			case NSE_LMAC_PHY_LINK_DOWN_READON_NOTIFY_LINK_INFO_FAIL:
			case NSE_LMAC_PHY_LINK_DOWN_REASON_NOT_UP_YET:
				lpinfo->dyn_flags |= LMAC_PHY_DYN_FLAG_NEED_UPDATE_LINK_INFO;
				break;

			default:
				lpinfo->dyn_flags |= LMAC_PHY_DYN_FLAG_NEED_UPDATE_LINK_INFO;
				break;
			}

			random_delta = (unsigned long)get_random_u64() %
				       NSE_LMAC_PHY_RETRY_WHOLE_SUBTASK_PERIOD_RANDOM_DELTA;

			if (time_after_eq(jiffies,
					  (lpinfo->link_down_retry_whole_subtask_prev +
					   lpinfo->link_down_retry_whole_subtask_period -
					   random_delta))) {
				nse_debug(hw, NSE_DBG_LMAC_PHY,
	"[%s, %d] link down for long time, would retry the whole subtask\n", __func__, __LINE__);

				lpinfo->link_down_retry_whole_subtask_prev = jiffies;

				/*  if ephy not ready, then would not start_link_or_an and
				 * update_link_status
				 */
				lpinfo->dyn_flags |= (LMAC_PHY_DYN_FLAG_NEED_UPDATE_EPHY_STATUS |
						      LMAC_PHY_DYN_FLAG_NEED_START_LINK_OR_AN |
						      LMAC_PHY_DYN_FLAG_NEED_UPDATE_LINK_INFO);
			}

		} else {
			lpinfo->link_down_reason = NSE_LMAC_PHY_LINK_DOWN_REASON_ALEADY_UP;

			lpinfo->link_down_retry_whole_subtask_prev = jiffies;
		}
	}

	nse_lmac_phy_unlock(hw);
}

static void
init_lks_amber(struct nse_hw *hw, struct nse_lmac_phy_info *lpinfo)
{
	struct ethtool_link_ksettings *lks = &lpinfo->lks;

	/***************************
	 * init lks->supported --- should match lmac_phy_init_early_amber()
	 ***************************/

	ethtool_link_ksettings_zero_link_mode(lks, supported);

	if (lpinfo->an_info.an_supported)
		ethtool_link_ksettings_add_link_mode(lks, supported, Autoneg);

	ethtool_link_ksettings_add_link_mode(lks, supported, Pause);

	if (hw->nic_type == NSE_NIC_TYPE_SFP) {
		ethtool_link_ksettings_add_link_mode(lks, supported, FIBRE);

		ethtool_link_ksettings_add_link_mode(lks, supported, 10000baseCR_Full);

		if (hw->device_id == NSE_DEV_ID_AMBER_DQATACXX) {
			ethtool_link_ksettings_add_link_mode(lks, supported, 10000baseR_FEC);
			ethtool_link_ksettings_add_link_mode(lks, supported, 10000baseSR_Full);
		} else {
			ethtool_link_ksettings_add_link_mode(lks, supported, 25000baseSR_Full);
			ethtool_link_ksettings_add_link_mode(lks, supported, 25000baseCR_Full);

			ethtool_link_ksettings_add_link_mode(lks, supported, FEC_RS);
		}

		ethtool_link_ksettings_add_link_mode(lks, supported, FEC_BASER);

	} else if (hw->nic_type == NSE_NIC_TYPE_QSFP) {
		ethtool_link_ksettings_add_link_mode(lks, supported, FIBRE);

		/* not use 100000baseCR4_Full */
		ethtool_link_ksettings_add_link_mode(lks, supported, 100000baseSR4_Full);

		ethtool_link_ksettings_add_link_mode(lks, supported, 100000baseCR4_Full);
		ethtool_link_ksettings_add_link_mode(lks, supported, 50000baseCR2_Full);
		ethtool_link_ksettings_add_link_mode(lks, supported, 25000baseCR_Full);

		ethtool_link_ksettings_add_link_mode(lks, supported, FEC_RS);
		ethtool_link_ksettings_add_link_mode(lks, supported, FEC_BASER);

	} else if (hw->nic_type == NSE_NIC_TYPE_1000BASE_T) {	/* fpga / pldm */

		ethtool_link_ksettings_add_link_mode(lks, supported, TP);

		ethtool_link_ksettings_add_link_mode(lks, supported, 1000baseT_Full);

		ethtool_link_ksettings_add_link_mode(lks, supported, FEC_NONE);
	}

	/***************************
	 * init lks->advertising --- copy from supported
	 ***************************/
	LKS_LM_COPY(lks, advertising, lks, supported);
}

static void __maybe_unused
led_init_early_amber(struct nse_hw *hw, struct nse_led_info *led_info)
{
	u32 i = 0;
	u32 val;
	u32 led_a, led_b;
	enum nse_status status;

	memset(led_info, 0, sizeof(*led_info));

	for (i = 0; i < 8; i++) {
		val = BIT(11);				/* blink_at_any_speed */
		val |= NSE_M(0x2, 8);		/* max_link_speed */
		val |= NSE_M((i >> 1), 5);	/* src_port */

		led_info->init.amber.cfg0[i] = cpu_to_le32(val);

		val = NSE_M(0x5, 16);		/* timerA */
		val |= NSE_M(0x5, 0);		/* timerB */

		led_info->init.amber.cfg1[i] = cpu_to_le32(val);
	}

	memcpy(&led_info->dft, &led_info->init, sizeof(led_info->init));

	/* default of this LAN port:
	 *
	 *		led-a: always on
	 *
	 *		led-b: blink when eth_link==1 and mac_busy==1
	 */
	led_a = (hw->lan_id << 1);
	led_b = led_a + 1;

	val = le32_to_cpu(led_info->dft.amber.cfg0[led_a]);

	val &= ~(NSE_M(0x7, 13));
	val |= BIT(1);

	led_info->dft.amber.cfg0[led_a] = cpu_to_le32(val);

	val = le32_to_cpu(led_info->dft.amber.cfg1[led_a]);

	val |= BIT(31);

	led_info->dft.amber.cfg1[led_a] = cpu_to_le32(val);

	val = le32_to_cpu(led_info->dft.amber.cfg0[led_b]);

	val &= ~(NSE_M(0x7, 13));
	val |= (NSE_M(0x3, 13));

	led_info->dft.amber.cfg0[led_b] = cpu_to_le32(val);

	led_info->dft.amber.rw = 0;

	val = BIT(led_a) | BIT(led_b);

	led_info->dft.amber.w_bitmap = cpu_to_le32(val);

	status = nse_aq_led_cfg(hw, &led_info->dft);
	if (status)
		nse_debug(hw, NSE_DBG_MISC, "[%s] ignorable fail: aq_led_cfg(dft), status=%d\n",
			  __func__, status);

	memcpy(&led_info->cur, &led_info->dft, sizeof(led_info->dft));
}

static void __maybe_unused
led_rebuild(struct nse_hw *hw)
{
	struct nse_led_info *led_info = &hw->port_info->lmac_phy_info.led_info;
	enum nse_status status;

	status = nse_aq_led_cfg(hw, &led_info->cur);
	if (status)
		nse_debug(hw, NSE_DBG_MISC, "[%s] ignorable fail: aq_led_cfg(dft), status=%d\n",
			  __func__, status);
}

static enum nse_status
lmac_phy_init_early_amber(struct nse_hw *hw, struct nse_lmac_phy_info *lpinfo)
{
	struct device *dev = nse_hw_to_dev(hw);
	enum nse_status status = NSE_SUCCESS;

	if (hw->hw_conf.hw_platform == NSE_HW_PLATFORM_ASIC) {
		if (nse_palladium_debug) {
			hw->nic_type = NSE_NIC_TYPE_1000BASE_T;

			lpinfo->static_flags = (LMAC_PHY_STATIC_FLAG_USE_TEST_PHY |
						LMAC_PHY_STATIC_FLAG_EPHY_FTYPE |
						LMAC_PHY_STATIC_FLAG_CONSIDER_ALWAYS_LINK_UP);

		} else {
			if (hw->device_id == NSE_DEV_ID_AMBER_FDBTACXX ||
				hw->device_id == NSE_DEV_ID_AMBER_FDBTACRX)
				hw->nic_type = NSE_NIC_TYPE_QSFP;
			else if (hw->device_id == NSE_DEV_ID_AMBER_DDATACRX ||
					hw->device_id == NSE_DEV_ID_AMBER_DDATAIRX ||
					hw->device_id == NSE_DEV_ID_AMBER_FQATACRX ||
					hw->device_id == NSE_DEV_ID_AMBER_DQATACXX)
				hw->nic_type = NSE_NIC_TYPE_SFP;
			/* just for temp debug in case FW not set pci device_id properly */
			else if (hw->device_id == NSE_DEV_ID_AMBER_FPGA)
				hw->nic_type = NSE_NIC_TYPE_QSFP;
			else {
				dev_err(dev, "[%s] BAD: unknown device_id=%X\n",
					__func__, hw->device_id);
				status = NSE_ERR_NOT_SUPPORTED;
				goto out;
			}
		}

	} else {	/* FPGA */

		hw->nic_type = NSE_NIC_TYPE_1000BASE_T;

		lpinfo->static_flags = (LMAC_PHY_STATIC_FLAG_USE_TEST_PHY |
								LMAC_PHY_STATIC_FLAG_EPHY_FTYPE);
	}

	/* todo: after AN stable, would change an_supported, an_enable = true */
	lpinfo->an_info.an_supported = false;
	lpinfo->an_info.an_enabled = false;

	if (nse_lmac_phy_ephy_ftype)
		lpinfo->static_flags |= LMAC_PHY_STATIC_FLAG_EPHY_FTYPE;

	if (nse_loopback_mode)
		lpinfo->static_flags |= (LMAC_PHY_STATIC_FLAG_EPHY_FTYPE |
					 LMAC_PHY_STATIC_FLAG_CONSIDER_ALWAYS_LINK_UP);

	if (hw->nic_type == NSE_NIC_TYPE_SFP) {
		if (hw->device_id == NSE_DEV_ID_AMBER_DQATACXX) {
			/* 10GbaseR */
			lpinfo->supported_link_types = (NSE_ETH_LINK_TYPE_10GbaseR);

			lpinfo->supported_link_speeds = NSE_AQ_LINK_SPEED_10GB;

			lpinfo->supported_fec = (FEC_BASER | FEC_OFF);	/* 10G */

			lpinfo->req_link_types = NSE_ETH_LINK_TYPE_10GbaseR;
			lpinfo->req_link_speeds = NSE_AQ_LINK_SPEED_10GB;

		} else {
			/* 25GbaseR */
			lpinfo->supported_link_types = (NSE_ETH_LINK_TYPE_25GbaseR |
							NSE_ETH_LINK_TYPE_10GbaseR);

			lpinfo->supported_link_speeds = (NSE_AQ_LINK_SPEED_25GB |
							 NSE_AQ_LINK_SPEED_10GB);

			lpinfo->supported_fec = (FEC_RS | FEC_BASER | FEC_OFF);	/* 25G */

			lpinfo->req_link_types = NSE_ETH_LINK_TYPE_25GbaseR;
			lpinfo->req_link_speeds = NSE_AQ_LINK_SPEED_25GB;
		}

		lpinfo->supported_media_types = (MEDIA_FIBER | MEDIA_DAC);

		lpinfo->req_fec_from_user = FEC_AUTO | lpinfo->supported_fec;
		lpinfo->req_fec_cur = FEC_NONE;

		lpinfo->ephy_info.ephy_type = EPHY_TYPE_SFP;

	} else if (hw->nic_type == NSE_NIC_TYPE_QSFP) {
		lpinfo->supported_link_types = (NSE_ETH_LINK_TYPE_100GbaseR4 |
						NSE_ETH_LINK_TYPE_40GbaseR4 |
						NSE_ETH_LINK_TYPE_25GbaseR |
						NSE_ETH_LINK_TYPE_10GbaseR);

		lpinfo->supported_link_speeds = (NSE_AQ_LINK_SPEED_100GB |
						 NSE_AQ_LINK_SPEED_40GB |
						 NSE_AQ_LINK_SPEED_25GB |
						 NSE_AQ_LINK_SPEED_10GB);

		lpinfo->supported_fec = (FEC_RS | FEC_BASER | FEC_OFF);	/* 100G */

		lpinfo->supported_media_types = (MEDIA_FIBER | MEDIA_DAC);

		lpinfo->req_link_types = NSE_ETH_LINK_TYPE_100GbaseR4;	/* initial */
		lpinfo->req_link_speeds = NSE_AQ_LINK_SPEED_100GB;		/* initial */

		lpinfo->req_fec_from_user = FEC_AUTO | lpinfo->supported_fec;
		lpinfo->req_fec_cur = FEC_NONE;

		lpinfo->ephy_info.ephy_type = EPHY_TYPE_QSFP;

	} else if (hw->nic_type == NSE_NIC_TYPE_1000BASE_T) {
		lpinfo->an_info.an_supported = false;
		lpinfo->an_info.an_enabled = false;

		lpinfo->supported_link_types = (NSE_ETH_LINK_TYPE_1GBaseT);

		/* not support 10MB,100MB, because lmac does not support */
		lpinfo->supported_link_speeds = NSE_AQ_LINK_SPEED_1000MB;

		lpinfo->supported_fec = FEC_OFF;

		lpinfo->supported_media_types = MEDIA_BASET;

		lpinfo->req_link_types = NSE_ETH_LINK_TYPE_1GBaseT;
		lpinfo->req_link_speeds = NSE_AQ_LINK_SPEED_1000MB;

		lpinfo->req_fec_from_user = FEC_OFF;
		lpinfo->req_fec_cur = FEC_OFF;

		lpinfo->ephy_info.ephy_type = EPHY_TYPE_GEN_1G;

	} else {
		dev_err(dev, "[%s] BAD: nic_type=%d not impl yet, or device_id=%X not identified\n",
						__func__, hw->nic_type, hw->device_id);

		status = NSE_ERR_NOT_IMPL;

		goto out;
	}

	ephy_reset_info(hw);

	init_lks_amber(hw, lpinfo);


out:
	return status;
};

static void
init_lks_ms(struct nse_hw *hw, struct nse_lmac_phy_info *lpinfo)
{
	struct ethtool_link_ksettings *lks = &lpinfo->lks;

	/***************************
	 * init lks->supported --- should match lmac_phy_init_early_ms()
	 ***************************/

	ethtool_link_ksettings_zero_link_mode(lks, supported);

	ethtool_link_ksettings_add_link_mode(lks, supported, Pause);

	if (lpinfo->supported_link_speeds == NSE_AQ_LINK_SPEED_200GB) {
		ethtool_link_ksettings_add_link_mode(lks, supported, 200000baseSR4_Full);
		ethtool_link_ksettings_add_link_mode(lks, supported, 200000baseCR4_Full);
	} else {
		ethtool_link_ksettings_add_link_mode(lks, supported, 400000baseSR4_Full);
		ethtool_link_ksettings_add_link_mode(lks, supported, 400000baseCR4_Full);
	}

	ethtool_link_ksettings_add_link_mode(lks, supported, FEC_RS);

	/***************************
	 * init lks->advertising --- copy from supported
	 ***************************/
	bitmap_copy(lks->link_modes.advertising, lks->link_modes.supported,
		    __ETHTOOL_LINK_MODE_MASK_NBITS);
}

static enum nse_status
lmac_phy_init_early_ms(struct nse_hw *hw, struct nse_lmac_phy_info *lpinfo)
{
	struct device *dev = nse_hw_to_dev(hw);
	enum nse_status status = NSE_SUCCESS;

	hw->nic_type = NSE_NIC_TYPE_QSFP;

	if (hw->func_caps.supported_link_types_speeds_from_fw) {
		lpinfo->supported_link_speeds = hw->func_caps.supported_link_speeds;
		lpinfo->supported_link_types = hw->func_caps.supported_link_types;

	} else {
		dev_err(dev,
	"[%s] BAD: Moonstone rely link_types_speeds told by FW, but FW does not tell\n", __func__);

		status = NSE_ERR_FW_API_VER;
		goto out;
	}

	if (lpinfo->supported_link_speeds != NSE_AQ_LINK_SPEED_200GB &&
		lpinfo->supported_link_speeds != NSE_AQ_LINK_SPEED_400GB) {
		dev_err(dev, "[%s] BAD: link_speeds(0x%X) is NOT 200GB or 400GB\n",
					__func__, lpinfo->supported_link_speeds);

		status = NSE_ERR_FW_API_VER;
		goto out;
	}

	if (lpinfo->supported_link_types != NSE_ETH_LINK_TYPE_200GbaseR4 &&
		lpinfo->supported_link_types != NSE_ETH_LINK_TYPE_400GbaseR4) {
		dev_err(dev, "[%s] BAD: link_types(0x%lX) is NOT 200GB(0x%lX - bit:%d) or 400GB(0x%lX - bit:%d)\n",
					__func__, (unsigned long)lpinfo->supported_link_types,
					(unsigned long)NSE_ETH_LINK_TYPE_200GbaseR4,
						NSE_ETH_LINK_TYPE_200GbaseR4_BIT,
					(unsigned long)NSE_ETH_LINK_TYPE_400GbaseR4,
						NSE_ETH_LINK_TYPE_400GbaseR4_BIT);

		status = NSE_ERR_FW_API_VER;
		goto out;
	}

	lpinfo->static_flags = (LMAC_PHY_STATIC_FLAG_EPHY_FTYPE);

	lpinfo->an_info.an_supported = false;
	lpinfo->an_info.an_enabled = false;

	if (lpinfo->supported_link_speeds == NSE_AQ_LINK_SPEED_200GB) {
		lpinfo->req_link_speeds = NSE_AQ_LINK_SPEED_200GB;
		lpinfo->req_link_types = NSE_ETH_LINK_TYPE_200GbaseR4;
	} else {
		lpinfo->req_link_speeds = NSE_AQ_LINK_SPEED_400GB;
		lpinfo->req_link_types = NSE_ETH_LINK_TYPE_400GbaseR4;
	}

	lpinfo->supported_fec = FEC_RS;		/* 200G/400G not support _OFF */

	lpinfo->supported_media_types = (MEDIA_FIBER | MEDIA_DAC);

	lpinfo->req_fec_from_user = FEC_RS;	/* ms: not add _AUTO */
	lpinfo->req_fec_cur = FEC_RS;

	lpinfo->ephy_info.ephy_type = EPHY_TYPE_QSFP;

	ephy_reset_info(hw);

	init_lks_ms(hw, lpinfo);

out:
	return status;
}

enum nse_status
nse_lmac_phy_init_early(struct nse_hw *hw)
{
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	struct device *dev = nse_hw_to_dev(hw);
	enum nse_status status;

	lpinfo->hw = (void *)hw;

	mutex_init(&lpinfo->mtx);

	lpinfo->poll_link_info_prev = jiffies;
	lpinfo->poll_link_info_period = NSE_LMAC_PHY_POLL_LINK_INFO_PERIOD;
	if (hw->mac_type == NSE_MAC_TYPE_AMBER) {
		if (nse_palladium_debug)
			lpinfo->poll_link_info_period =
				NSE_LMAC_PHY_POLL_LINK_INFO_PERIOD_VERY_LONG;
	}

	lpinfo->req_link_speed_from_user = NSE_AQ_LINK_SPEED_UNKNOWN;
	lpinfo->req_link_types_from_user = NSE_ETH_LINK_TYPE_UNKNOWN;

	/* init lmac_phy_info RO fields */
	if (hw->mac_type == NSE_MAC_TYPE_AMBER)
		status = lmac_phy_init_early_amber(hw, lpinfo);
	else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE)
		status = lmac_phy_init_early_ms(hw, lpinfo);
	else {
		status = NSE_ERR_NOT_SUPPORTED;
		dev_err(dev, "[%s] BAD: unsupported mac_type=%d\n", __func__, hw->mac_type);
	}

	if (status) {
		dev_err(dev, "[%s] FAIL: status=%d\n", __func__, status);
		goto out;
	}

	lpinfo->link_down_retry_whole_subtask_prev = jiffies;

	if (lpinfo->an_info.an_enabled)
		lpinfo->link_down_retry_whole_subtask_period =
			NSE_LMAC_PHY_RETRY_WHOLE_SUBTASK_PERIOD;
	else
		lpinfo->link_down_retry_whole_subtask_period =
			NSE_LMAC_PHY_RETRY_WHOLE_SUBTASK_PERIOD_SHORT;

	/* also set in nse_init_pf_dcb() */
	lpinfo->fc_info.current_mode = NSE_FC_LFC_FULL;
	lpinfo->fc_info.req_mode = NSE_FC_LFC_FULL;
	lpinfo->fc_info.autoneg_lfc = true;

	hw->hw_conf.hw_lphy_external_type = lpinfo->ephy_info.ephy_type;

	/* enable jumbo frame support at MAC level */
	status = nse_lmac_set_basic_cfg(hw);
	if (status) {
		dev_err(dev, "[%s] FAIL: lmac_set_basic_cfg(), status=%d(%s)\n",
					__func__, status, nse_stat_str(status));
		goto out;
	}

	/* let serv_tmr and serv_task started in probe() to run subtask and handle this flags */
	lpinfo->dyn_flags = (LMAC_PHY_DYN_FLAG_NEED_UPDATE_EPHY_STATUS |
						/*  if ephy not ready, then would not
						 * start_link_or_an
						 */
						LMAC_PHY_DYN_FLAG_NEED_START_LINK_OR_AN |
						LMAC_PHY_DYN_FLAG_NEED_UPDATE_LINK_INFO);

out:
	return status;
}

void
nse_lmac_phy_prepare_for_reset(struct nse_hw *hw, enum nse_reset_req reset_type)
{
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;

	nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] enter, reset_type=%d\n", __func__, reset_type);

	nse_lmac_phy_lock(hw);

	ephy_reset_info(hw);

	lpinfo->dyn_flags = LMAC_PHY_DYN_FLAG_NOT_RUN_SUBTASK;

	lpinfo->prev_notify_link_down = false;

	nse_lmac_phy_unlock(hw);
}

enum nse_status
nse_lmac_phy_rebuild(struct nse_hw *hw, enum nse_reset_req reset_type)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_lmac_phy_info *lpinfo = &hw->port_info->lmac_phy_info;
	enum nse_status status = NSE_SUCCESS;

	nse_debug(hw, NSE_DBG_LMAC_PHY, "[%s] enter, reset_type=%d\n", __func__, reset_type);

	nse_lmac_phy_lock(hw);

	if (nse_is_high_reset_type(reset_type)) {
		status = nse_lmac_set_basic_cfg(hw);
		if (status) {
			dev_err(dev, "[%s] FAIL: lmac_set_basic_cfg(), status=%d(%s)\n",
						__func__, status, nse_stat_str(status));
			goto out;
		}

		/* set LAN/WoL address to HW */
		if (!hw->is_mh_dpu_secondary_pf) {
			u16 wflags;

			wflags = NSE_AQC_MAN_MAC_WFLAG_UPDATE_LMAC_ADDR;
			if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_MISC_SUPPORT_WOL))
				wflags |= NSE_AQC_MAN_MAC_WFLAG_UPDATE_WOL_ADDR;

			(void)nse_aq_manage_mac_write(hw, hw->port_info->mac.lan_addr,
											wflags, 0);
		}

	}

	lpinfo->prev_notify_link_down = false;

	lpinfo->link_down_retry_whole_subtask_prev = jiffies;

	lpinfo->dyn_flags = (LMAC_PHY_DYN_FLAG_NEED_UPDATE_EPHY_STATUS |
						/*  if ephy not ready, then would not
						 * start_link_or_an
						 */
						LMAC_PHY_DYN_FLAG_NEED_START_LINK_OR_AN |
						LMAC_PHY_DYN_FLAG_NEED_UPDATE_LINK_INFO);

out:
	nse_lmac_phy_unlock(hw);

	return status;
}
