// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include "mce.h"
#include "mce_base.h"
#include "mce_lib.h"
#include "mce_sriov.h"
#include "mce_virtchnl.h"
#include "mce_n20/mce_hw_n20.h"
#include "mce_dcbnl.h"
#include "mce_dcb.h"
#include "mce_eswitch.h"
#include "mce_fwchnl.h"
#include "mce_arfs.h"

static void mce_sriov_pf_resyc_list(struct mce_pf *pf)
{
	bool sriov_on = !!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags);

	mce_vf_resync_mc_list(pf, sriov_on);
	mce_vf_resync_vlan_list(pf, sriov_on);
}

static int __maybe_unused mce_sriov_reinit(struct mce_pf *pf)
{
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	int timeout = 50;

	while (test_and_set_bit(MCE_CFG_BUSY, pf->state)) {
		timeout--;
		if (!timeout)
			return -EBUSY;
		usleep_range(1000, 2000);
	}

	/* set for the next time the netdev is started */
	if (!netif_running(vsi->netdev)) {
		mce_vsi_rebuild(vsi);
		dev_dbg(mce_pf_to_dev(pf),
			"Link is down, queue count change happens when link is brought up\n");
		goto done;
	}

	rtnl_lock();
	mce_vsi_close(vsi);
	mce_vsi_rebuild(vsi);
	mce_vsi_open(vsi);
	/* nic_reset called before, set status again */
	mce_notify_fw_ifup_down(pf, true);
	rtnl_unlock();
done:
	clear_bit(MCE_CFG_BUSY, pf->state);
	return 0;
}

/**
 * mce_reset_vf - Reset a virtual function.
 * @netdev: network interface device structure
 *
 * program reset vf
 * Returns: The result of the operation.
 */
int mce_reset_vf(struct net_device *netdev)
{
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int timeout = 50;
	int vf_id;

	/* if sriov not open, or disabled, nothing todo */
	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return 0;

	while (test_and_set_bit(MCE_FLAG_VFIO_VISIT, pf->flags)) {
		timeout--;
		if (!timeout)
			return -EINVAL;
		usleep_range(100, 200);
	}

	if (!vf) {
		clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);
		return -EINVAL;
	}

	mce_for_each_vf_id(pf, vf_id) {
		if (mce_check_vf_no_ready_for_cfg(&vf->vfinfo[vf_id])) {
			clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);
			return 0;
		}

		mce_mbx_send_reset_vf_cmd(pf, vf_id);
	}

	clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);

	return 0;
}

/**
 * mce_set_vf_mac - Set the MAC address of a virtual function.
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @mac: MAC address
 *
 * program VF MAC address
 * Returns: The result of the operation.
 */
int mce_set_vf_mac(struct net_device *netdev, int vf_id, u8 *mac)
{
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct vf_info *vfinfo;
	int timeout = 50;
	int ret;

	if (is_multicast_ether_addr(mac)) {
		netdev_err(netdev, "%pM not a valid unicast address\n", mac);
		return -EINVAL;
	}

	/* if sriov not open, or disabled, nothing todo */
	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return 0;

	while (test_and_set_bit(MCE_FLAG_VFIO_VISIT, pf->flags)) {
		timeout--;
		if (!timeout)
			return -EINVAL;
		usleep_range(100, 200);
	}

	if (vf_id >= pf->num_vfs || !vf) {
		clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);
		return -EINVAL;
	}

	if (is_zero_ether_addr(mac)) {
		/* VF will send VIRTCHNL_OP_ADD_ETH_ADDR message with its MAC */
		vf->vfinfo[vf_id].pf_set_mac = false;
		netdev_info(netdev,
			    "Removing MAC on VF %d. VF driver will be reinitialized\n",
			vf_id);
	} else {
		/* PF will add MAC rule for the VF */
		vf->vfinfo[vf_id].pf_set_mac = true;

		/* Check for MAC address conflict within the same VLAN */
		vfinfo = &vf->vfinfo[vf_id];
		ret = mce_check_vf_mac_conflict(pf, vf_id, mac,
						vfinfo->pf_vlan);
		if (ret) {
			clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);
			return ret;
		}

		netdev_info(netdev,
			    "Setting MAC %pM on VF %d. VF driver will be reinitialized\n",
			mac, vf_id);
	}
	memcpy(vf->vfinfo[vf_id].vf_mac_addr, mac, ETH_ALEN);

	if (mce_check_vf_no_ready_for_cfg(&vf->vfinfo[vf_id])) {
		clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);
		return 0;
	}
	/* update VEB mac entry */
	mce_mbx_send_reset_vf_cmd(pf, vf_id);

	clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);

	return 0;
}

/**
 * mce_is_supported_port_vlan_proto - make sure the vlan_proto is supported
 * @hw: hardware structure used to check the VLAN mode
 * @vlan_proto: VLAN TPID being checked
 *
 * If the device is configured in Double VLAN Mode (DVM), then both ETH_P_8021Q
 * and ETH_P_8021AD are supported. If the device is configured in Single VLAN
 * Mode (SVM), then only ETH_P_8021Q is supported.
 * Returns: The result of the operation.
 */
static bool mce_is_supported_port_vlan_proto(struct mce_hw *hw, u16 vlan_proto)
{
	bool is_supported = false;

	switch (vlan_proto) {
	case ETH_P_8021Q:
		is_supported = true;
		break;
	case ETH_P_8021AD:
		is_supported = true;
		break;
	}

	return is_supported;
}

/**
 * mce_get_vf_cfg - Get the configuration of a virtual function.
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @ivi: VF configuration structure
 *
 * return VF configuration
 * Returns: The result of the operation.
 */
int mce_get_vf_cfg(struct net_device *netdev, int vf_id,
		   struct ifla_vf_info *ivi)
{
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int timeout = 50;

	if (vf_id >= pf->num_vfs || !vf)
		return -EINVAL;

	/* if sriov not open, or disabled, nothing todo */
	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return 0;

	while (test_and_set_bit(MCE_FLAG_VFIO_VISIT, pf->flags)) {
		timeout--;
		if (!timeout)
			return -EINVAL;
		usleep_range(100, 200);
	}

	ivi->vf = vf_id;
	ether_addr_copy(ivi->mac, vf->vfinfo[vf_id].vf_mac_addr);
	ivi->max_tx_rate = vf->vfinfo[vf_id].tx_rate;
	ivi->vlan = vf->vfinfo[vf_id].pf_vlan;
	ivi->qos = vf->vfinfo[vf_id].pf_vlan_qos;
	if (vf->vfinfo[vf_id].pf_vlan_proto) {
		if (!mce_is_supported_port_vlan_proto(&pf->hw, vf->vfinfo[vf_id].pf_vlan_proto)) {
			netdev_err(netdev,
				   "VF %d has unsupported VLAN proto 0x%04x\n",
				   vf_id, vf->vfinfo[vf_id].pf_vlan_proto);
			ivi->vlan_proto = 0;
		} else {
			ivi->vlan_proto =
				cpu_to_be16(vf->vfinfo[vf_id].pf_vlan_proto);
		}
	} else {
		ivi->vlan_proto = 0;
	}

	ivi->spoofchk = vf->vfinfo[vf_id].spoofchk_enabled;
	clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);

	return 0;
}

/**
 * mce_set_vf_dscp_prio - Set the DSCP priority mapping for a virtual function.
 * @netdev: network interface device structure
 * @dscp: dscp value
 * @prio: prio for this dscp value
 *
 * Returns: The result of the operation.
 */
int mce_set_vf_dscp_prio(struct net_device *netdev, u8 dscp,
			 u8 prio)
{
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int data[2] = { dscp, prio };
	struct mce_hw *hw = &pf->hw;
	struct mce_mbx_info *vf_mbx;
	int timeout = 50;
	int vf_id;

	/* if sriov not open, or disabled, nothing todo */
	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return 0;

	while (test_and_set_bit(MCE_FLAG_VFIO_VISIT, pf->flags)) {
		timeout--;
		if (!timeout)
			return -EINVAL;
		usleep_range(100, 200);
	}

	if (!vf) {
		clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);
		return -EINVAL;
	}

	mce_for_each_vf_id(pf, vf_id) {
		vf_mbx = mce_get_vf_mbx(hw, vf_id);
		if (mce_check_vf_no_ready_for_cfg(&vf->vfinfo[vf_id])) {
			clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);
			return 0;
		}

		if (!vf_mbx) {
			clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);
			return -EINVAL;
		}

		/* Keep the existing no-op-on-error behavior. */
		(void)mce_mbx_send_req(vf_mbx, SET_VF_DSCP, data,
				       sizeof(data), NULL, 1000);
	}

	clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);
	return 0;
}

/**
 * mce_set_vf_port_vlan - Set the port VLAN configuration of a virtual function.
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @vlan_id: VLAN ID being set
 * @qos: priority setting
 * @vlan_proto: VLAN protocol
 *
 * program VF Port VLAN ID and/or QoS
 * Returns: The result of the operation.
 */
int mce_set_vf_port_vlan(struct net_device *netdev, int vf_id, u16 vlan_id,
			 u8 qos, __be16 vlan_proto)
{
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_hw *hw = &pf->hw;
	u16 local_vlan_proto = ntohs(vlan_proto);
	struct mce_mbx_info *vf_mbx = mce_get_vf_mbx(hw, vf_id);
	int data[3] = { vlan_id, qos, local_vlan_proto };
	struct device *dev = mce_pf_to_dev(pf);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int timeout = 50;
	int ret;

	/* if sriov not open, or disabled, nothing todo */
	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return 0;

	while (test_and_set_bit(MCE_FLAG_VFIO_VISIT, pf->flags)) {
		timeout--;
		if (!timeout)
			return -EINVAL;
		usleep_range(100, 200);
	}

	if (vf_id >= pf->num_vfs || !vf || !vf_mbx) {
		clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);
		return -EINVAL;
	}

	if (vlan_id >= VLAN_N_VID || qos > 7) {
		clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);
		dev_err(dev,
			"Invalid Port VLAN parameters for VF %d, ID %d, QoS %d\n",
			vf_id, vlan_id, qos);
		return -EINVAL;
	}

	if (!mce_is_supported_port_vlan_proto(&pf->hw, local_vlan_proto)) {
		clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);
		dev_err(dev, "VF VLAN protocol 0x%04x is not supported\n",
			local_vlan_proto);
		return -EPROTONOSUPPORT;
	}

	/* Check for MAC address conflict if VLAN is changing */
	if (vlan_id != vf->vfinfo[vf_id].pf_vlan) {
		ret = mce_check_vf_mac_conflict(pf, vf_id,
						vf->vfinfo[vf_id].vf_mac_addr,
						vlan_id);
		if (ret) {
			clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);
			return ret;
		}
	}

	if (vlan_id != 0 && vlan_id != vf->vfinfo[vf_id].pf_vlan &&
	    vf->vfinfo[vf_id].pf_vlan) {
		set_bit(MCE_FLAG_PF_SET_VF_VLAN, pf->flags);
		/* when pf_vlan had setuped, need del it first */
		mce_vf_del_flr_vlan(pf, vf_id, vf->vfinfo[vf_id].pf_vlan);
		clear_bit(MCE_FLAG_PF_SET_VF_VLAN, pf->flags);
	}

	if (vlan_id) {
		set_bit(MCE_FLAG_PF_SET_VF_VLAN, pf->flags);
		mce_vf_setup_flr_vlan(pf, vf_id, vlan_id);
		mce_vf_setup_veb_vlan(pf, vf_id, vlan_id);
		clear_bit(MCE_FLAG_PF_SET_VF_VLAN, pf->flags);
	} else {
		set_bit(MCE_FLAG_PF_SET_VF_VLAN, pf->flags);
		mce_vf_del_flr_vlan(pf, vf_id, vf->vfinfo[vf_id].pf_vlan);
		clear_bit(MCE_FLAG_PF_SET_VF_VLAN, pf->flags);
		mce_vf_del_veb_vlan(pf, vf_id, vf->vfinfo[vf_id].pf_vlan);
	}

	vf->vfinfo[vf_id].pf_vlan_qos = qos;
	vf->vfinfo[vf_id].pf_vlan = vlan_id;
	vf->vfinfo[vf_id].pf_vlan_proto = local_vlan_proto;
	/* update spoofchk vlan */

	if (mce_check_vf_no_ready_for_cfg(&vf->vfinfo[vf_id])) {
		clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);
		return 0;
	}

	/* Keep the existing no-op-on-error behavior. */
	(void)mce_mbx_send_req(vf_mbx, SET_VF_VLAN, data, sizeof(data),
			       NULL, 1000);

	clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);
	return 0;
}

/**
 * mce_set_vf_bw - set min/max VF bandwidth
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @max_tx_rate: Maximum Tx rate in Mbps
 * Returns: The result of the operation.
 */
int mce_set_vf_bw(struct net_device *netdev, int vf_id, int max_tx_rate)
{
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct device *dev = mce_pf_to_dev(pf);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct mce_dcb *dcb = pf->dcb;
	int timeout = 50;
	int ret = 0;

	/* if sriov not open, or disabled, nothing todo */
	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return 0;

	while (test_and_set_bit(MCE_FLAG_VFIO_VISIT, pf->flags)) {
		timeout--;
		if (!timeout)
			return -EINVAL;
		usleep_range(100, 200);
	}

	if (vf_id >= pf->num_vfs || !vf) {
		clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);
		return -EINVAL;
	}

	if (test_bit(MCE_DCB_EN, dcb->flags)) {
		clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);
		dev_err(dev,
			"DCB on PF is currently enabled. VF MAX Tx rate limiting"
			" not allowed on this PF.\n");
		return -EOPNOTSUPP;
	}
	if (vf->vfinfo[vf_id].tx_rate != (unsigned int)max_tx_rate) {
		if (!test_bit(MCE_VF_BW_INITED, pf->state))
			mce_set_bw_limit_init(pf);
		ret = mce_set_max_bw_limit(pf, vf_id,
					   (u64)max_tx_rate * 1000 * 1000,
					   vf->vfinfo[vf_id].ring_cnt);
		if (ret) {
			dev_err(dev, "Unable to set max-tx-rate for VF %d\n",
				vf_id);
			goto err;
		}
		vf->vfinfo[vf_id].tx_rate = max_tx_rate;
		mce_vf_cfg_txring_bw_lmt(pf, vf_id, max_tx_rate);
		set_bit(MCE_FLAG_VF_TX_MAXRATE_ENA, vf->vfinfo[vf_id].flags);
	}
err:
	clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);
	return ret;
}

/**
 * mce_set_vf_dscp - enable or disable VF DSCP handling
 * @netdev: network interface device structure
 * @ena: flag to enable or disable feature
 *
 * Enable or disable VF spoof checking
 * Returns: The result of the operation.
 */
int mce_set_vf_dscp(struct net_device *netdev, bool ena)
{
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int ret = 0, vf_id;
	int timeout = 50;

	/* if sriov not open, or disabled, nothing todo */
	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return 0;

	while (test_and_set_bit(MCE_FLAG_VFIO_VISIT, pf->flags)) {
		timeout--;
		if (!timeout)
			return -EINVAL;
		usleep_range(100, 200);
	}

	if (!vf) {
		clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);
		return -EINVAL;
	}

	/* echo all vfs */
	mce_for_each_vf_id(pf, vf_id)
		mce_vf_notify_dscp_state(pf, vf_id, ena);

	clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);

	return ret;
}

/**
 * mce_set_vf_spoofchk - Set spoof checking for a virtual function.
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @ena: flag to enable or disable feature
 *
 * Enable or disable VF spoof checking
 * Returns: The result of the operation.
 */
int mce_set_vf_spoofchk(struct net_device *netdev, int vf_id, bool ena)
{
	struct mce_pf *pf = mce_netdev_to_pf(netdev);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	int timeout = 50;
	int ret;

	/* if sriov not open, or disabled, nothing todo */
	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return 0;

	if (!ena && test_bit(MCE_FLAG_EVB_VEPA_ENA, pf->flags)) {
		dev_warn(mce_pf_to_dev(pf),
			 "VF:%d cannot turn off anti-spoof in evb vepa mode!\n",
			 vf_id);
		return -EOPNOTSUPP;
	}

	while (test_and_set_bit(MCE_FLAG_VFIO_VISIT, pf->flags)) {
		timeout--;
		if (!timeout)
			return -EINVAL;
		usleep_range(100, 200);
	}

	if (vf_id >= pf->num_vfs || !vf) {
		clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);
		return -EINVAL;
	}

	if (ena == vf->vfinfo[vf_id].spoofchk_enabled) {
		dev_dbg(mce_pf_to_dev(pf), "VF:%d spoofchk already %s\n", vf_id,
			ena ? "ON" : "OFF");
		ret = 0;
		goto out;
	}

	vf->vfinfo[vf_id].spoofchk_enabled = ena;
	ret = mce_vf_apply_spoofchk(pf, vf_id, ena);
	mce_vf_notify_spoof_state(pf, vf_id, ena);

out:
	clear_bit(MCE_FLAG_VFIO_VISIT, pf->flags);

	return ret;
}

#ifdef CONFIG_PCI_IOV

static int __mce_enable_sriov(struct mce_pf *pf, unsigned int num_vfs)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);

	/* Allocate memory for per VF control structures */
	vf->vfinfo = kcalloc(PFVF_TOTAL_NUM(num_vfs), sizeof(struct vf_info),
			     GFP_KERNEL);

	if (!vf->vfinfo)
		return -ENOMEM;

	pf->hw.num_vfs = num_vfs;

	mce_realloc_and_fill_pfinfo(pf, true);
	mce_sriov_init_hw(pf);
	return 0;
}

/**
 * mce_generate_vf_mac_addr - Generate a unique MAC address for VF
 * @pf: PF containing the VF state
 * @vfn: VF number to generate a MAC address for
 * @vf_mac_addr: buffer to store the generated MAC address
 *
 * Generates a random MAC address and ensures it doesn't collide with
 * the PF's port MAC or any previously assigned VF MAC addresses.
 */
static void mce_generate_vf_mac_addr(struct mce_pf *pf, int vfn,
				     unsigned char *vf_mac_addr)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct mce_vsi *vsi;
	bool duplicate;
	int j;

	vsi = mce_get_main_vsi(pf);
	do {
		eth_random_addr(vf_mac_addr);
		duplicate = ether_addr_equal(vf_mac_addr,
					     vsi->port_info->addr);
		if (!duplicate) {
			for (j = 0; j < vfn && !duplicate; j++) {
				duplicate = ether_addr_equal(vf_mac_addr,
							     vf->vfinfo[j].vf_mac_addr);
			}
		}
	} while (duplicate);
}

static int mce_vf_configuration(struct mce_pf *pf, int vfn)
{
	struct mce_vf *vf = mce_pf_to_vf(pf);
	unsigned char vf_mac_addr[ETH_ALEN];
	struct mce_hw *hw = &pf->hw;
	struct mce_vsi *vsi;

	vsi = mce_get_main_vsi(pf);
	if (vfn != PFINFO_IDX) {
		struct mce_mbx_info *mbx = &hw->vf_mbx[vfn];

		mbx->vfinfo = &vf->vfinfo[vfn];
		hw->ops->mbx_init_vf(hw, mbx, vfn);
		mce_generate_vf_mac_addr(pf, vfn, vf_mac_addr);
		memcpy(vf->vfinfo[vfn].vf_mac_addr, vf_mac_addr, ETH_ALEN);
		vf->vfinfo[vfn].pf_vlan_entry = MCE_VF_UNUSED;
		vf->vfinfo[vfn].spoofchk_enabled = true;
		vf->vfinfo[vfn].trusted = false;
		hw->vf.ops->set_vf_spoofchk_mac(hw, vfn, true, true);
		hw->vf.ops->set_vf_spoofchk_vlan(hw, vfn, false,
						 MCE_VF_ANTI_VLAN_CLEAR);
		vf->vfinfo[vfn].ring_cnt = hw->vf_max_ring;
	} else {
		memcpy(vf->vfinfo[vfn].vf_mac_addr, vsi->port_info->addr,
		       ETH_ALEN);
		vf->vfinfo[vfn].vf_ipv4_addr = pf->ipv4_addr;
		vf->vfinfo[vfn].pf_vlan_entry = MCE_VF_UNUSED;
		vf->vfinfo[vfn].spoofchk_enabled = true;
		vf->vfinfo[vfn].trusted = false;

		/* update pf anti mac */
		if (test_bit(MCE_FLAG_PF_ANTISPOOF, pf->flags))
			hw->vf.ops->set_vf_spoofchk_mac(hw, vfn, true, true);
		else
			hw->vf.ops->set_vf_spoofchk_mac(hw, vfn, false, true);
		hw->vf.ops->set_vf_spoofchk_vlan(hw, vfn, false,
						 MCE_VF_ANTI_VLAN_CLEAR);
	}

	return 0;
}

int mce_sriov_deinit_hw(struct mce_pf *pf)
{
	struct mce_hw *hw = &pf->hw;

	hw->ops->set_fd_fltr_guar(hw);
	rdma_wr32(hw, N20_RDMA_REG_FUNC_SIZE, 0);
	rdma_wr32(hw, N20_RDMA_REG_PF_ID_ADDR, 0);
	hw->vf.ops->set_vf_rebase_ring_base(hw);
	hw->vf.ops->unset_vf_virtual_config(hw);
	hw->vf.ops->set_vf_virtual_config(hw, false);
	hw->vf.ops->set_vf_dma_max_queue_size(hw, N20_VF_DEFAULT_QUEUE_CNT);
	hw->vf.ops->set_vf_emac_post_ctrl(hw, MCE_VF_VEB_VLAN_OUTER1, true,
					  MCE_VF_POST_CTRL_NORMAL, true);
	/* when turn on sriov, pf take as vf, so we need close uc/mc L2 filter */
	hw->promisc_no_permit = false;
	/* when turn off sriov, need restore promic to real setup*/
	mce_setup_L2_filter(pf);
	hw->vf.ops->set_vf_trusted(hw, PFINFO_IDX, false);
	/* reset pf default vport */
	hw->vf.ops->set_vf_default_vport(hw, PFINFO_IDX);
	hw->vf.ops->set_vf_set_vlan_promisc(hw, PFINFO_IDX, true);
	hw->vf.ops->set_vf_set_vtag_vport_en(hw, 0, false);
	hw->ops->set_tun_select_inner(hw, pf->tun_inner);
	return 0;
}

int mce_sriov_init_hw(struct mce_pf *pf)
{
	struct mce_hw *hw = &pf->hw;
	int val, i;
	bool on;

	hw->ops->set_fd_fltr_guar(hw);

	hw->vf.ops->set_vf_rebase_ring_base(hw);
	hw->vf.ops->set_vf_virtual_config(hw, true);
	hw->vf.ops->set_vf_dma_max_queue_size(hw, hw->vf_max_ring);
	hw->vf.ops->set_vf_emac_post_ctrl(hw, MCE_VF_VEB_VLAN_OUTER1, true,
					  MCE_VF_POST_CTRL_FILTER_TX_TO_RX,
					  true);
	hw->vf.ops->set_vf_trust_vport_en(hw, false);
	hw->vf.ops->set_vf_trusted(hw, PFINFO_IDX, true);
	hw->vf.ops->set_vf_default_vport(hw, PFINFO_IDX);

	val = 0;
	while ((1 << val) < (pf->num_vfs + 1))
		val++;
	rdma_wr32(hw, N20_RDMA_REG_FUNC_SIZE, val);
	/* setup pf default_vport to rdma */
	rdma_wr32(hw, N20_RDMA_REG_PF_ID_ADDR, pf->num_vfs);

	/* when turn on sriov, pf take as vf, so we need close uc/mc L2 filter.
	 * used vf vlan filter table.
	 */
	hw->promisc_no_permit = false;
	hw->ops->set_uc_filter(hw, true);
	hw->ops->set_mc_filter(hw, true);
	hw->ops->set_vlan_filter(hw, false);
	hw->vf.ops->set_vf_set_vlan_promisc(hw, PFINFO_IDX, false);
	hw->vf.ops->set_vf_set_vtag_vport_en(hw, 0, true);
	hw->promisc_no_permit = true;
	hw->ops->set_tun_select_inner(hw, pf->tun_inner);
	mce_for_each_pf_vf_id(pf, i)
		mce_vf_configuration(pf, i);
	/* restore vepa */
	on = !!test_bit(MCE_FLAG_EVB_VEPA_ENA, pf->flags);
	mce_vf_set_evb_vepa_mode(hw, on);
	return 0;
}

static void mce_restore_aux_dev(struct mce_pf *pf)
{
	int err;

	if (!test_and_clear_bit(MCE_FLAG_AUX_REMOVED_FOR_SRIOV, pf->flags))
		return;

	if (test_bit(MCE_REMOVED, pf->state) || pf->bond_linked)
		return;

	err = mce_plug_aux_dev(pf);
	if (err)
		dev_warn(mce_pf_to_dev(pf),
			 "failed to restore auxiliary device after SR-IOV disable: %d\n",
			 err);
}

int mce_disable_sriov(struct mce_pf *pf)
{
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct device *dev = mce_pf_to_dev(pf);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct iidc_event *event = NULL;
	struct mce_hw *hw = &pf->hw;
	int timeout = 50;

	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return -EINVAL;
	clear_bit(MCE_FLAG_SRIOV_ENA, pf->flags);

	event = kzalloc(sizeof(*event), GFP_KERNEL);
	if (!event) {
		set_bit(MCE_FLAG_SRIOV_ENA, pf->flags);
		return -ENOMEM;
	}

	/* force close dcb */
	if (!test_bit(MCE_REMOVED, pf->state))
		mce_force_close_dcb(pf);
	set_bit(IIDC_EVENT_BEFORE_SRIOV_DISABLE, event->type);
	mce_send_event_to_auxs(pf, event);
	clear_bit(IIDC_EVENT_BEFORE_SRIOV_DISABLE, event->type);

	/* when disable sriov, need notify hw and set flags disabled */
#ifdef CONFIG_PCI_IOV
	if (pci_vfs_assigned(pf->pdev)) {
		kfree(event);
		dev_err(dev,
			"Unloading driver while VFs are assigned - VFs will not be deallocated\n");
		return -EPERM;
	}
#endif
	mce_notify_fw_ifup_down(pf, false);
	rtnl_lock();
	if (test_bit(MCE_REMOVED, pf->state))
		mce_vsi_close_hw_transmit(vsi);
	else if (netif_running(vsi->netdev))
		mce_vsi_close(vsi);
	rtnl_unlock();
#ifdef CONFIG_PCI_IOV
	/* disable iov and allow time for transactions to clear */
	pci_disable_sriov(pf->pdev);
#endif

	/* cleanup pf macvlan entries before reset */
	mce_cleanup_pf_macvlan_fltr(hw);

	/*  reset and restore hw */
	mce_reset_hw(hw);
	mce_reset_prev_stats(pf);
	mce_restore_hw(hw);

	mce_sriov_deinit_hw(pf);
	mce_sriov_pf_resyc_list(pf);
	mce_eswitch_release(pf);
	mce_eswitch_free_vfs(pf);
	/* realloc vfinfo and free vfinfo*/
	mce_realloc_and_fill_pfinfo(pf, false);
	/* wait for visit vf->vfino not used */
	while (test_bit(MCE_FLAG_VFIO_VISIT, pf->flags)) {
		timeout--;
		if (!timeout) {
			dev_err(dev, "wait vfinfo safe timeout\n");
			break;
		}
		usleep_range(100, 200);
	}

	kfree(vf->vfinfo);
	vf->vfinfo = NULL;

	mce_set_pf_caps(pf);
	if (!test_bit(MCE_REMOVED, pf->state)) {
		/* if not user setup force clean req */
		if (!test_bit(MCE_FLAG_USR_CHANGE_QNUM_ENA, pf->flags)) {
			vsi->req_txq = 0;
			vsi->req_rxq = 0;
		}
		rtnl_lock();
		mce_vsi_rebuild(vsi);
		rtnl_unlock();
	}

	hw->max_vfs = 0;
	pf->num_vfs = 0;
	pf->hw.num_vfs = 0;
	set_bit(IIDC_EVENT_AFTER_SRIOV_DISABLE, event->type);
	mce_send_event_to_auxs(pf, event);
	kfree(event);

	rtnl_lock();
	if (netif_running(vsi->netdev) && !test_bit(MCE_REMOVED, pf->state)) {
		/* delay up */
		set_bit(MCE_NO_LINK, pf->state);
		mce_vsi_open(vsi);
	}
	rtnl_unlock();
	if (!test_bit(MCE_REMOVED, pf->state))
		mce_recover_dcb(pf);
	mce_notify_fw_ifup_down(pf, true);
	clear_bit(MCE_NO_LINK, pf->state);
	/* take a breather then clean up driver data */
	msleep(100);
	mce_restore_aux_dev(pf);

	return 0;
}
#endif
static int mce_pci_sriov_enable(struct mce_pf *pf, int num_vfs)
{
#ifdef CONFIG_PCI_IOV
	int pre_existing_vfs = pci_num_vf(pf->pdev);
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct device *dev = mce_pf_to_dev(pf);
	struct iidc_event *event = NULL;
	struct mce_hw *hw = &pf->hw;
	int rollback_err;
	int err = 0;

	if (pf->num_vfs == num_vfs)
		return -EINVAL;

	if (pre_existing_vfs && pre_existing_vfs != num_vfs) {
		if (test_bit(MCE_FLAG_AUX_REMOVED_FOR_SRIOV, pf->flags)) {
			clear_bit(MCE_FLAG_AUX_REMOVED_FOR_SRIOV, pf->flags);
			err = mce_disable_sriov(pf);
			set_bit(MCE_FLAG_AUX_REMOVED_FOR_SRIOV, pf->flags);
		} else {
			err = mce_disable_sriov(pf);
		}
	} else if (pre_existing_vfs && pre_existing_vfs == num_vfs) {
		goto out;
	}
	if (err)
		goto err_exit;

	set_bit(MCE_FLAG_SRIOV_DOING, pf->flags);
	if (!mce_wait_rdma_script_done(hw)) {
		dev_err(dev, "sriov enable wait rdma script done timeout\n");
		err = -ETIMEDOUT;
		goto err_exit;
	}

	if (mce_aux_dev_is_bound(pf)) {
		dev_err(dev,
			"cannot enable SR-IOV while the auxiliary device is in use\n");
		err = -EBUSY;
		goto err_exit;
	}

	if (mce_aux_dev_is_registered(pf)) {
		mce_unplug_aux_dev(pf);
		set_bit(MCE_FLAG_AUX_REMOVED_FOR_SRIOV, pf->flags);
	}

	event = kzalloc(sizeof(*event), GFP_KERNEL);
	if (!event) {
		err = -ENOMEM;
		goto err_exit;
	}

	set_bit(MCE_FLAG_SRIOV_ENA, pf->flags);
	set_bit(IIDC_EVENT_BEFORE_SRIOV_ENABLE, event->type);
	mce_send_event_to_auxs(pf, event);
	clear_bit(IIDC_EVENT_BEFORE_SRIOV_ENABLE, event->type);

	if (test_bit(MCE_FLAG_CAPTURE_RDMA_ENA, pf->flags)) {
		hw->ops->set_capture_rdma(hw, false);
		clear_bit(MCE_FLAG_CAPTURE_RDMA_ENA, pf->flags);
	}
	/* force close dcb */
	mce_force_close_dcb(pf);

	mce_notify_fw_ifup_down(pf, false);
	rtnl_lock();
	if (test_bit(MCE_REMOVED, pf->state))
		mce_vsi_close_hw_transmit(vsi);
	else if (netif_running(vsi->netdev))
		mce_vsi_close(vsi);
	rtnl_unlock();

	/* set this before unset_vf_virtual_config to clear vf0 attr */
	hw->max_vfs = num_vfs;
	hw->vf.ops->unset_vf_virtual_config(hw);
	if (test_and_clear_bit(MCE_FLAG_PF_SET_VF_MAX_RING_PENDING, pf->flags))
		hw->vf.ops->init_vf_params(hw, hw->vf_max_ring);
	mce_set_pf_caps(pf);
	hw->max_vfs = num_vfs;
	pf->num_vfs = hw->max_vfs;
	err = __mce_enable_sriov(pf, num_vfs);
	if (err)
		goto err_out;

	mce_sriov_pf_resyc_list(pf);
	if (!test_bit(MCE_REMOVED, pf->state)) {
		rtnl_lock();
		mce_vsi_rebuild(vsi);
		rtnl_unlock();
	}

	err = mce_eswitch_alloc_vfs(pf);
	if (err) {
		dev_err(dev, "Failed to alloc eswitch vfs, err %d\n", err);
		goto err_eswitch;
	}

	err = mce_eswitch_configure(pf);
	if (err) {
		dev_err(dev, "Failed to configure eswitch, err %d\n", err);
		goto err_eswitch;
	}

	/* first reinit mrdma, then sriov */
	set_bit(IIDC_EVENT_AFTER_SRIOV_ENABLE, event->type);
	mce_send_event_to_auxs(pf, event);

	err = pci_enable_sriov(pf->pdev, num_vfs);
	if (err) {
		dev_err(dev, "Failed to enable PCI sriov: %d num %d\n", err,
			num_vfs);
		goto err_eswitch;
	}

	rtnl_lock();
	if (netif_running(vsi->netdev) && !test_bit(MCE_REMOVED, pf->state)) {
		/* delay up */
		set_bit(MCE_NO_LINK, pf->state);
		mce_vsi_open(vsi);
	}
	rtnl_unlock();
	mce_recover_dcb(pf);
	mce_notify_fw_ifup_down(pf, true);
	clear_bit(MCE_NO_LINK, pf->state);
	mce_restore_pf_macvlan_fltr(hw);
out:
	clear_bit(MCE_FLAG_SRIOV_DOING, pf->flags);
	kfree(event);
	return num_vfs;
err_eswitch:
	rollback_err = mce_disable_sriov(pf);
	kfree(event);
	if (!rollback_err)
		goto err_exit;
	dev_warn(dev, "Failed to roll back SR-IOV: %d\n", rollback_err);
err_out:
	if (mce_pf_to_vf(pf)->vfinfo)
		kfree(mce_pf_to_vf(pf)->vfinfo);
	rtnl_lock();
	if (netif_running(vsi->netdev) && !test_bit(MCE_REMOVED, pf->state))
		mce_vsi_open(vsi);
	rtnl_unlock();
	mce_notify_fw_ifup_down(pf, true);
	clear_bit(MCE_FLAG_SRIOV_ENA, pf->flags);
err_exit:
	mce_restore_aux_dev(pf);
	clear_bit(MCE_FLAG_SRIOV_DOING, pf->flags);
	return err;
#endif /* CONFIG_PCI_IOV */
	return 0;
}

static int mce_pci_sriov_disable(struct mce_pf *pf)
{
	struct mce_hw *hw = &pf->hw;
	int err;

	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return -EINVAL;

	set_bit(MCE_FLAG_SRIOV_DOING, pf->flags);
	if (!mce_wait_rdma_script_done(hw)) {
		dev_err(mce_pf_to_dev(pf),
			"sriov disable wait rdma script done timeout\n");
		err = -ETIMEDOUT;
		goto err_exit;
	}
	err = mce_disable_sriov(pf);
err_exit:
	clear_bit(MCE_FLAG_SRIOV_DOING, pf->flags);
	return err;
}

static bool mce_pci_ari_enabled(struct pci_dev *dev)
{
	struct pci_bus *bus = dev->bus;

	return bus->self && bus->self->ari_enabled;
}

/**
 * mce_check_sriov_allowed - check if SR-IOV is allowed based on various checks
 * @pf: PF to enabled SR-IOV on
 * @num_vfs: number of VFs requested
 * Returns: The result of the operation.
 */
static int mce_check_sriov_allowed(struct mce_pf *pf, int num_vfs)
{
	struct mce_vlan_list_entry *vlan_entry = NULL;
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct net_device *netdev = vsi->netdev;
	struct device *dev = mce_pf_to_dev(pf);
	struct mce_hw *hw = &pf->hw;
	int vlan_cnt = 0;

	if (!test_bit(MCE_FLAG_SRIOV_CAPABLE, pf->flags)) {
		dev_err(dev, "This device is not capable of sriov.\n");
		return -EOPNOTSUPP;
	}

	if (num_vfs > (N20_MAX_Q_CNT / hw->vf_max_ring - 1)) {
		dev_err(dev,
			"Numerical result out of range. max support vfs is:%d\n",
			N20_MAX_Q_CNT / hw->vf_max_ring - 1);
		return -ERANGE;
	}

	if (!mce_pci_ari_enabled(hw->pdev) && num_vfs > 3) {
		dev_err(dev,
			"Numerical result out of range. pci no-ari max support vfs is 3\n");
		return -ERANGE;
	}

	if (netdev_mc_count(netdev) > MCE_MAX_MC_WHITE_LISTS) {
		dev_err(dev,
			"The multicast nums cannot exceeds maximum allowed: %d"
			" before turn on sriov.\n",
			MCE_MAX_MC_WHITE_LISTS);
		return -EOPNOTSUPP;
	}

	list_for_each_entry(vlan_entry, &hw->vlan_list_head, vlan_node) {
		vlan_cnt++;
		if (vlan_cnt > MCE_MAX_VF_VLAN_WHITE_LISTS) {
			dev_err(dev,
				"The vlan nums cannot exceeds maximum allowed: %d"
				" before turn on sriov.\n",
				MCE_MAX_VF_VLAN_WHITE_LISTS);
			return -EOPNOTSUPP;
		}
	}

	if (hw->fdir_active_fltr) {
		dev_err(dev,
			"The ntuple or etype rules must be cleared before turn on/off sriov.\n");
		return -EOPNOTSUPP;
	}

	if (num_vfs && mce_is_arfs_enabled(pf)) {
		dev_err(dev, "aRFS must be disabled before enabling SR-IOV.\n");
		return -EOPNOTSUPP;
	}

	if (test_bit(MCE_FLAG_PF_RQA_TCPSYNC_ENA, pf->flags)) {
		dev_err(dev,
			"The tcpsync rules must be cleared before turn on/off sriov.\n");
		return -EOPNOTSUPP;
	}
	return 0;
}

/**
 * mce_sriov_configure - Enable or change number of VFs via sysfs
 * @pdev: pointer to a pci_dev structure
 * @num_vfs: number of VFs to allocate or 0 to free VFs
 *
 * This function is called when the user updates the number of VFs in sysfs. On
 * success return whatever num_vfs was set to by the caller. Return negative on
 * failure.
 * Returns: The result of the operation.
 */
int mce_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	struct mce_pf *pf = pci_get_drvdata(pdev);
	int err;

	err = mce_check_sriov_allowed(pf, num_vfs);
	if (err)
		return err;
	if (num_vfs == 0)
		return mce_pci_sriov_disable(pf);
	else
		return mce_pci_sriov_enable(pf, num_vfs);
}
