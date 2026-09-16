// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

/* WangXun(R) Ethernet Connection AM Series Linux Driver */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/debugfs.h>
#include <linux/firmware.h>

#include "nse.h"
#include "nse_base.h"
#include "nse_lib.h"
#include "nse_fltr.h"
#include "nse_fdir.h"
#include "nse_fwmng.h"
#include "nse_dcb_lib.h"
#include "nse_dcb_nl.h"
#include "nse_devlink.h"
#include "nse_eswitch.h"
/* Including nse_trace.h with CREATE_TRACE_POINTS defined will generate the
 * nse tracepoint functions. This must be done exactly once across the
 * nse driver.
 */
#define CREATE_TRACE_POINTS
#include "nse_trace.h"
#undef CREATE_TRACE_POINTS
#include "nse_tc_lib.h"
#include "nse_neigh.h"
#include "nse_vsi_vlan_ops.h"
#include "nse_vsi_vlan_lib.h"
#include "nse_irq.h"
#include "nse_ptp.h"
#include "nse_sched_aqc.h"
#ifdef CONFIG_PCI_IOV
#include "nse_vf_lib_private.h"
#endif

const char nse_drv_ver[] = DRV_VERSION DRV_VERSION_EXTRA;
static const char nse_driver_string[] = DRV_SUMMARY;
static const char nse_copyright[] = "Copyright (c) 2018 -2021 Beijing WangXun Technology Co., Ltd";

#define NSE_DDP_PKG_PATH	"wangxun/nse/ddp/"
#define NSE_DDP_PKG_FILE	NSE_DDP_PKG_PATH "nse.ddp"

MODULE_AUTHOR("Beijing WangXun Technology Co., Ltd, <linux.nic@trustnetic.com>");
MODULE_DESCRIPTION(DRV_SUMMARY);
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION DRV_VERSION_EXTRA);

static int debug = -1;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "netif level (0=none,...,16=all), hw debug_mask (0x8XXXXXXX)");

unsigned int nse_bypass_sched;
module_param(nse_bypass_sched, uint, 0644);
MODULE_PARM_DESC(nse_bypass_sched, "bypass tx-scheduler (0:not bypass, non-0: bypass");

unsigned int nse_bypass_switch;
module_param(nse_bypass_switch, uint, 0644);
MODULE_PARM_DESC(nse_bypass_switch, "bypass switch (0:not bypass, non-0: bypass (default for 1st FGPA test)");

unsigned int nse_tcam_less = 1;
module_param(nse_tcam_less, uint, 0644);
MODULE_PARM_DESC(nse_tcam_less, "tcam less (0: has tcam, non-0: has no tcam (default)");

unsigned int nse_bypass_qos_db_flush_disable = 1;
module_param(nse_bypass_qos_db_flush_disable, uint, 0644);
MODULE_PARM_DESC(nse_bypass_qos_db_flush_disable, "bypass RDB/RPB/TDB/TRT reset and disable logic during driver load (0:not bypass, 1: bypass (default for 1st FGPA test)");

unsigned int nse_loopback_mode;
module_param(nse_loopback_mode, uint, 0644);
MODULE_PARM_DESC(nse_loopback_mode, "loopback mode (0(default): no loopback, 1: loopback in switch, 2: loopback in lmac, 3: loopback in PHY");

unsigned int nse_palladium_debug;
module_param(nse_palladium_debug, uint, 0644);
MODULE_PARM_DESC(nse_palladium_debug, "palladium debug (0:fpga test, non-0: palladium test (default FGPA test)");

unsigned int nse_no_reset;
module_param(nse_no_reset, uint, 0644);
MODULE_PARM_DESC(nse_no_reset, "for early dev debug (0: no reset, 1: with reset");

unsigned int nse_no_irq;
module_param(nse_no_irq, uint, 0644);
MODULE_PARM_DESC(nse_no_irq, "for early dev debug (0: not init IRQ, 1: init IRQ");

unsigned int nse_polling_mod;
module_param(nse_polling_mod, uint, 0644);
MODULE_PARM_DESC(nse_polling_mod, "pmd (0:napi, non-0: pmd (default napi)");

unsigned int nse_rdma_ena = 1;
module_param(nse_rdma_ena, uint, 0644);
MODULE_PARM_DESC(nse_rdma_ena, "enable RDMA (default: 1)");

unsigned int nse_main_vsi_max_lanq_num;
module_param(nse_main_vsi_max_lanq_num, uint, 0644);
MODULE_PARM_DESC(nse_main_vsi_max_lanq_num, "limit LAN RXQ/TXQ pairs number used by PF-main-VSI (default: 0 - default setting)");

unsigned int nse_main_vsi_max_lanirq_num;
module_param(nse_main_vsi_max_lanirq_num, uint, 0644);
MODULE_PARM_DESC(nse_main_vsi_max_lanirq_num, "limit max lan-irq-vectors of PF-main-VSI (default: 0 - default setting)");

unsigned int nse_vf_vsi_max_lanq_num;
module_param(nse_vf_vsi_max_lanq_num, uint, 0644);
MODULE_PARM_DESC(nse_vf_vsi_max_lanq_num, "limit LAN RXQ/TXQ pairs number used by VF-VSI (default: 1, and 0 for default setting)");

unsigned int nse_vf_vsi_max_lanirq_num;
module_param(nse_vf_vsi_max_lanirq_num, uint, 0644);
MODULE_PARM_DESC(nse_vf_vsi_max_lanirq_num, "limit irqvec used by VF LAN-RXQ/TXQ, leaving more for VF-RDMA (default: 0)");

unsigned int nse_sriov_vf_res_alloc_from_tail = 1;
module_param(nse_sriov_vf_res_alloc_from_tail, uint, 0644);
MODULE_PARM_DESC(nse_sriov_vf_res_alloc_from_tail, "Alloc VF resource (VSI/RXQ/TXQ/IRQ) from PF space tail (default: 1)");

unsigned int nse_lan_tx_select_q_dport;
module_param(nse_lan_tx_select_q_dport, uint, 0644);
MODULE_PARM_DESC(nse_lan_tx_select_q_dport, "Select TXQ based on TCP/UDP dport (default: 0)");

unsigned int nse_lan_tx_select_q_default;
module_param(nse_lan_tx_select_q_default, uint, 0644);
MODULE_PARM_DESC(nse_lan_tx_select_q_default, "Select TXQ default for non-TCP,UDP,ICMP packet (default: 0)");

unsigned int nse_lan_tx_no_bql = 1;
module_param(nse_lan_tx_no_bql, uint, 0644);
MODULE_PARM_DESC(nse_lan_tx_no_bql, "Do not call linux CONFIG_BQL related functions (default: 1)");

unsigned int nse_lan_tx_not_use_ctx_desc;
module_param(nse_lan_tx_not_use_ctx_desc, uint, 0644);
MODULE_PARM_DESC(nse_lan_tx_not_use_ctx_desc, "only for early debug, not use tx-context-desc (default: 0)");

static unsigned int nse_lan_tx_use_cq;
module_param(nse_lan_tx_use_cq, uint, 0644);
MODULE_PARM_DESC(nse_lan_tx_use_cq, "use LAN CompletionQ to handle TX-done release (default: 0)");

static unsigned int nse_lan_tx_use_cq_for_vf;
module_param(nse_lan_tx_use_cq_for_vf, uint, 0644);
MODULE_PARM_DESC(nse_lan_tx_use_cq_for_vf, "try to grant CQ to VFs (default: 0)");

unsigned int nse_lan_txcq_initial_hw_gen;
module_param(nse_lan_txcq_initial_hw_gen, uint, 0644);
MODULE_PARM_DESC(nse_lan_txcq_initial_hw_gen, "LAN CompletionQ initial generation bit setting (0|1, default: 0)");

static unsigned int nse_lan_rx_ena_rsc = 1;
module_param(nse_lan_rx_ena_rsc, uint, 0644);
MODULE_PARM_DESC(nse_lan_rx_ena_rsc, "LAN RX - using RSC for small packet RX optimization (0|1, default: 1)");

#if defined(NSE_DEBUG_EXT)
unsigned int nse_lan_rx_force_rxdid;
module_param(nse_lan_rx_force_rxdid, uint, 0644);
MODULE_PARM_DESC(nse_lan_rx_force_rxdid, "force PF-main-VSI and VF-VSI to use this RX RXDID(default: 0 - not force)");
#endif

#if defined(NSE_DEBUG_EXT)
/* This is just to test port-based VLAN in PF driver.
 *
 * Official port-based VLAN is only configured for VF, and need test VF driver.
 *
 * But official configuration of VF involves VF reset procedure (which is not code ready),
 * and many vch protocol back-and-forth.
 *
 * So this kmod param is a hack method, to help test port-based VLAN in PF driver and PF-main-VSI.
 */
unsigned int nse_lan_vlan_pvid_inner_strip;
module_param(nse_lan_vlan_pvid_inner_strip, uint, 0644);
MODULE_PARM_DESC(nse_lan_vlan_pvid_inner_strip, "if configure port-based VLAN, then inner tag strip to RX-desc L2TAG1, otherwise, not strip (default: 0)");
#endif

/* Linux TX checksum offload logic only offload L4 checksum computation.
 * But compute L3 checksum (outer or inner ) itself in SW-level.
 *
 * In order to test HW feature, we need to let HW compute L3 checksum.
 *
 *
 * This is not defined as kmod param, but a tunable param by debugfs.
 */
unsigned int nse_lan_tcsum_force_l3;

unsigned int nse_lan_no_xmit;
module_param(nse_lan_no_xmit, uint, 0644);
MODULE_PARM_DESC(nse_lan_no_xmit, "for LAN test, don't TX (default: 0)");

/* should become default 1 after full test */
unsigned int nse_lan_disable_q_before_cfg;
module_param(nse_lan_disable_q_before_cfg, uint, 0644);
MODULE_PARM_DESC(nse_lan_disable_q_before_cfg, "for LAN test, pause and disable CQ/RXQ/TXQ before configure (default: 0)");

/* try to use aq-cmd: NSE_AQ_OPC_ENA_DIS_LAN_RXQ_TXQ_MANY for bulk operation
 */
unsigned int nse_lan_bulk_ena_dis;
module_param(nse_lan_bulk_ena_dis, uint, 0644);
MODULE_PARM_DESC(nse_lan_bulk_ena_dis, "try to enable or disable LAN-RXQ/TXQ in bulk way (default: 0)");

unsigned int nse_lan_no_irqll;
module_param(nse_lan_no_irqll, uint, 0644);
MODULE_PARM_DESC(nse_lan_no_irqll, "disable IRQ linked logic(default: 0)");

unsigned int nse_aq_cmd_timeout = NSE_CTL_Q_SQ_CMD_TIMEOUT_BASE;
module_param(nse_aq_cmd_timeout, uint, 0644);
MODULE_PARM_DESC(nse_aq_cmd_timeout, "count of timeout_tick of checking aq_cmd timeout");

unsigned int nse_aq_cmd_check_dd = 1;
module_param(nse_aq_cmd_check_dd, uint, 0644);
MODULE_PARM_DESC(nse_aq_cmd_check_dd, "check DD flag in write-back descriptor, instead of HEAD (default: 1)");

unsigned int nse_aq_cmd_wait_method;
module_param(nse_aq_cmd_wait_method, uint, 0644);
MODULE_PARM_DESC(nse_aq_cmd_wait_method, "AQM poll method (default 0 for sleep, 1 for delay)");

/* The AQM RQ lock is initialised, and the serv_bh tasklet is set up, according
 * to this value, while nse_aq_rq_lock()/nse_aq_rq_unlock() pick the lock
 * primitive from it on every call.  It must therefore not change after load,
 * hence the read-only module parameter.
 */
unsigned int nse_aq_rq_rx_method = 1;
module_param(nse_aq_rq_rx_method, uint, 0444);
MODULE_PARM_DESC(nse_aq_rq_rx_method, "AQM RQ rx method, fixed at load time");

unsigned int nse_timeout_scale;
module_param(nse_timeout_scale, uint, 0644);
MODULE_PARM_DESC(nse_timeout_scale, "scale for various timeout (including aq, reset, etc)");

static unsigned int nse_aq_verbose;
module_param(nse_aq_verbose, uint, 0644);
MODULE_PARM_DESC(nse_aq_verbose, "print more verbose log when doing aq_cmd (default: 0)");

static unsigned int nse_conf_verbose;
module_param(nse_conf_verbose, uint, 0644);
MODULE_PARM_DESC(nse_conf_verbose, "print more verbose log when doing configuration (default: 0)");

static unsigned int download_ddp;
module_param(download_ddp, uint, 0644);
MODULE_PARM_DESC(download_ddp, "download DDP when PF-0 starts (default: 0)");

unsigned int nse_lan_tdm_check_desc_err;
module_param(nse_lan_tdm_check_desc_err, uint, 0644);
MODULE_PARM_DESC(nse_lan_tdm_check_desc_err, "some debug logic to check TDM descriptor error in both HW and SW-level (default: 1)");

unsigned int nse_lan_desc_cache = NSE_LAN_DESC_CACHE_RX;
module_param(nse_lan_desc_cache, uint, 0644);
MODULE_PARM_DESC(nse_lan_desc_cache, "try to use LAN desc cache (0 for not, 1 for tx, 2 for rx, 3 for both tx/rx)");

unsigned int nse_lan_tx_rs_optimize = 1;
module_param(nse_lan_tx_rs_optimize, uint, 0644);
MODULE_PARM_DESC(nse_lan_tx_rs_optimize, "TX RS writeback optimize (default: 1)");

unsigned int nse_sch_tree_scheme = NSE_SCH_TREE_SCHEME_10_LAYERS;
module_param(nse_sch_tree_scheme, uint, 0644);
MODULE_PARM_DESC(nse_sch_tree_scheme, "8|10 layers [default: 10]");

unsigned int nse_sch_use_cir_transfer = 1;
module_param(nse_sch_use_cir_transfer, uint, 0644);
MODULE_PARM_DESC(nse_sch_use_cir_transfer, "use HW CIR transfer [default: 1]\n");

unsigned int nse_fdir_ena = 1;
module_param(nse_fdir_ena, uint, 0644);
MODULE_PARM_DESC(nse_fdir_ena, "Enable FDir, including all its logic (default: 1)");

unsigned int nse_fdir_use_utilq = 1;
module_param(nse_fdir_use_utilq, uint, 0644);
MODULE_PARM_DESC(nse_fdir_use_utilq, "Program FDir filter using utilQ (default: 0)");

unsigned int nse_fdir_ena_for_vf = 1;
module_param(nse_fdir_ena_for_vf, uint, 0644);
MODULE_PARM_DESC(nse_fdir_ena_for_vf, "Enable FDir for VF (default: 0)");

unsigned int nse_ptp_fine_mode = 1;
module_param(nse_ptp_fine_mode, uint, 0644);
MODULE_PARM_DESC(nse_ptp_fine_mode, "using Fine Update Mode (default: 1)");

unsigned int nse_qos_db_use_share = 1;
module_param(nse_qos_db_use_share, uint, 0644);
MODULE_PARM_DESC(nse_qos_db_use_share, "For QoS DB modules, use shared buffer instead of dedicated buffer (default: 1)");

#if defined(NSE_DEBUG_EXT)

unsigned int nse_qos_db_test_fc_tx;
module_param(nse_qos_db_test_fc_tx, uint, 0644);
MODULE_PARM_DESC(nse_qos_db_test_fc_tx, "For QoS DB modules test (default: 0)");

unsigned int nse_lan_vlan_force_up;
module_param(nse_lan_vlan_force_up, uint, 0644);
MODULE_PARM_DESC(nse_lan_vlan_force_up, "For QoS DB modules test (default: 0)");
#endif

unsigned int nse_macvlan_ena;
module_param(nse_macvlan_ena, uint, 0644);
MODULE_PARM_DESC(nse_macvlan_ena, "feature: macvlan offload ON/OFF (default: 0)");

#if defined(NSE_DEBUG_EXT)
unsigned int nse_lan_debug_hw_qstat;
module_param(nse_lan_debug_hw_qstat, uint, 0644);
MODULE_PARM_DESC(nse_lan_debug_hw_qstat, "dump HW LAN per-Q stats (default: 0)");
#endif

unsigned int nse_fw_lldp;
module_param(nse_fw_lldp, uint, 0644);
MODULE_PARM_DESC(nse_fw_lldp, "try enable FW-LLDP logic (default: 0)");

unsigned int nse_chip_dbg_mode = 1;
module_param(nse_chip_dbg_mode, uint, 0644);
MODULE_PARM_DESC(nse_chip_dbg_mode, "Chip debug mode on (default: 1 on Amber FPGA and PST, 0 for rest case)");

/* 1 - 25G, 2 - 50G, 3 - 100G */
unsigned int nse_dbg_force_mac_ss;
module_param(nse_dbg_force_mac_ss, uint, 0644);
MODULE_PARM_DESC(nse_dbg_force_mac_ss, "force set XLGMAC TX_Configuration -> SS");

unsigned int nse_misc_check_temp;
module_param(nse_misc_check_temp, uint, 0644);
MODULE_PARM_DESC(nse_misc_check_temp, "check chip and external module temperature and slow down on overheat (default: 0)\n");

unsigned int nse_lmac_phy_ephy_ftype;
module_param(nse_lmac_phy_ephy_ftype, uint, 0644);
MODULE_PARM_DESC(nse_lmac_phy_ephy_ftype, "force use ephy_ftype (default: 0)\n");

/**
 * nse_hw_to_dev - Get device pointer from the hardware structure
 * @hw: pointer to the device HW structure
 *
 * Used to access the device pointer from compilation units which can't easily
 * include the definition of struct nse_pf without leading to circular header
 * dependencies.
 */
struct device *nse_hw_to_dev(struct nse_hw *hw)
{
	struct nse_pf *pf = container_of(hw, struct nse_pf, hw);

	return &pf->pdev->dev;
}

struct workqueue_struct *nse_wq;

static const struct net_device_ops nse_netdev_ops;
static const struct udp_tunnel_nic_info nse_udp_tunnels;

static void nse_ctrlq_rq_flush_bh(struct nse_ctl_q_info *cq);

bool netif_is_nse(struct net_device *dev)
{
	return dev && (dev->netdev_ops == &nse_netdev_ops);
}

static struct nse_vsi *
nse_macvlan_vsi_setup(struct nse_pf *pf, struct nse_port_info *pi);

static void nse_napi_add(struct nse_vsi *vsi);

/**
 * nse_vsi_cfg_netdev_tc0 - Setup the netdev TC 0 configuration
 * @vsi: the VSI being configured
 *
 * This function configures netdev parameters for traffic class 0
 */
int nse_vsi_cfg_netdev_tc0(struct nse_vsi *vsi)
{
	struct net_device *netdev = vsi->netdev;
	int ret;

	if (!netdev)
		return -EINVAL;

	ret = netdev_set_num_tc(netdev, 1);
	if (ret) {
		netdev_err(netdev, "Error setting num TC\n");
		return ret;
	}

	/* Set queue information for lowerdev */
	ret = netdev_set_tc_queue(netdev, 0, vsi->num_txq, 0);
	if (ret) {
		netdev_err(netdev, "Error setting TC queue\n");
		goto set_tc_queue_err;
	}

	return 0;
set_tc_queue_err:
	netdev_set_num_tc(netdev, 0);
	return ret;
}

/**
 * nse_fwd_add_macvlan - Configure MACVLAN interface
 * @netdev: Main net device to configure
 * @vdev: MACVLAN subordinate device
 */
static void *
nse_fwd_add_macvlan(struct net_device *netdev, struct net_device *vdev)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *parent_vsi = np->vsi, *vsi;
	struct nse_pf *pf = parent_vsi->back;
	struct nse_macvlan *mv = NULL;
	int avail_id, ret, offset, i;
	enum nse_status status;
	struct device *dev;
	u8 mac[ETH_ALEN];

	dev = nse_pf_to_dev(pf);

	if (pf->num_macvlan == pf->max_num_macvlan) {
		netdev_err(netdev, "MACVLAN offload limit reached\n");
		return ERR_PTR(-ENOSPC);
	}

	if (vdev->num_rx_queues != 1 || vdev->num_tx_queues != 1) {
		netdev_err(netdev, "Can't do MACVLAN offload. %s has multiple queues\n",
			   vdev->name);
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (nse_get_avail_txq_count(pf) < NSE_DFLT_TXQ_VMDQ_VSI ||
	    nse_get_avail_rxq_count(pf) < NSE_DFLT_RXQ_VMDQ_VSI) {
		netdev_err(netdev, "Can't do MACVLAN offload. Not enough queues\n");
		return ERR_PTR(-ENOSPC);
	}

	avail_id = find_first_zero_bit(pf->avail_macvlan, pf->max_num_macvlan);

	vsi = nse_macvlan_vsi_setup(pf, pf->hw.port_info);
	if (!vsi) {
		netdev_err(netdev, "Failed to create MACVLAN offload (VMDQ) VSI\n");
		return ERR_PTR(-EIO);
	}

	pf->num_macvlan++;
	offset = parent_vsi->alloc_txq + avail_id;

	ret = netdev_set_sb_channel(vdev, avail_id + 1);
	if (ret) {
		netdev_err(netdev, "Error setting netdev_set_sb_channel %d\n",
			   ret);
		goto set_sb_channel_err;
	}

	/* configure sbdev with the number of queues and offset within PF
	 * queues range
	 */
	ret = netdev_bind_sb_channel_queue(netdev, vdev, 0, vsi->num_txq,
					   offset);
	if (ret) {
		netdev_err(netdev, "Error setting netdev_bind_sb_channel_queue %d\n",
			   ret);
		goto bind_sb_channel_err;
	}

	vsi->netdev = vdev;
	/* Set MACVLAN ring in root device Tx rings */
	nse_for_each_txq(vsi, i)
		parent_vsi->tx_rings[offset + i] = vsi->tx_rings[i];

	nse_napi_add(vsi);

	ret = nse_vsi_open(vsi);
	if (ret)
		goto vsi_open_err;

	ether_addr_copy(mac, vdev->dev_addr);
	status = nse_fltr_add_mac(vsi, mac, NSE_FWD_TO_VSI);
	if (status == NSE_ERR_ALREADY_EXISTS) {
		dev_info(dev, "can't add MAC filters %pM for VSI %d, error %s\n",
			 mac, vsi->idx, nse_stat_str(status));
	} else if (status) {
		dev_err(dev, "can't add MAC filters %pM for VSI %d, error %s\n",
			mac, vsi->idx, nse_stat_str(status));
		ret = -ENOMEM;
		goto add_mac_err;
	}

	mv = devm_kzalloc(dev, sizeof(*mv), GFP_KERNEL);
	if (!mv) {
		ret = -ENOMEM;
		goto mv_init_err;
	}
	INIT_LIST_HEAD(&mv->list);
	mv->parent_vsi = parent_vsi;
	mv->vsi = vsi;
	mv->id = avail_id;
	mv->vdev = vdev;
	ether_addr_copy(mv->mac, mac);
	list_add(&mv->list, &pf->macvlan_list);

	set_bit(avail_id, pf->avail_macvlan);

	if (vsi->vsi_dbgfs_dir) {
		vsi->vsi_netdev_symlink = debugfs_create_symlink(vdev->name, pf->pf_dbgfs_dir,
								 vsi->vsi_dbgfs_dir->d_iname);
		if (IS_ERR(vsi->vsi_netdev_symlink))
			vsi->vsi_netdev_symlink = NULL;
	}

	netdev_info(netdev, "MACVLAN offloads for %s are on\n", vdev->name);

	return mv;

mv_init_err:
	nse_fltr_remove_all(vsi);
add_mac_err:
	nse_vsi_close(vsi);
vsi_open_err:
	nse_napi_del(vsi);
	vsi->netdev = NULL;
	netdev_unbind_sb_channel(netdev, vdev);
bind_sb_channel_err:
	netdev_set_sb_channel(vdev, 0);
set_sb_channel_err:
	pf->num_macvlan--;
	nse_vsi_release(vsi);
	return ERR_PTR(ret);
}

/**
 * nse_fwd_del_macvlan - Delete MACVLAN interface resources
 * @netdev: Main net device
 * @accel_priv: MACVLAN sub ordinate device
 */
static void nse_fwd_del_macvlan(struct net_device *netdev, void *accel_priv)
{
	struct nse_macvlan *mv = (struct nse_macvlan *)accel_priv;
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *parent_vsi = np->vsi;
	struct nse_pf *pf = parent_vsi->back;
	struct net_device *vdev = mv->vdev;

	netdev_unbind_sb_channel(netdev, vdev);
	netdev_set_sb_channel(vdev, 0);

	nse_vsi_release(mv->vsi);
	parent_vsi->tx_rings[parent_vsi->num_txq + mv->id] = NULL;

	pf->num_macvlan--;

	clear_bit(mv->id, pf->avail_macvlan);
	list_del(&mv->list);
	devm_kfree(nse_pf_to_dev(pf), mv);

	netdev_info(netdev, "MACVLAN offloads for %s are off\n", vdev->name);
}

/**
 * nse_init_macvlan - Configure PF VSI to be able to offload MACVLAN
 * @vsi: Main VSI pointer where sb_dev is attached to
 * @init: Set to false when called in replay path otherwise true
 */
static int nse_init_macvlan(struct nse_vsi *vsi, bool init)
{
	struct net_device *netdev = vsi->netdev;
	struct nse_pf *pf = vsi->back;
	struct nse_ring **tmp_rings;
	unsigned int total_rings;
	u16 free_res_cnt;
	struct device *dev;
	int i, ret;

	dev = nse_pf_to_dev(pf);
	if (!test_bit(NSE_FLAG_VMDQ_ENA, pf->flags)) {	/* equal to pf->sw_conf.max_macvlans > 0 */
		dev_err(dev, "MACVLAN offload cannot be supported - VMDQ is disabled\n");
		return -EPERM;
	}

	if (nse_is_eswitch_mode_switchdev(pf)) {
		dev_err(dev, "MACVLAN offload cannot be configured - switchdev is enabled\n");
		return -EOPNOTSUPP;
	}

	pf->avail_macvlan = bitmap_zalloc(pf->sw_conf.max_macvlans, GFP_KERNEL);
	if (!pf->avail_macvlan) {
		dev_err(dev, "FAIL: memory alloc for avail_macvlan bitmap\n");
		return -ENOMEM;
	}

	pf->max_num_macvlan = min3(nse_get_avail_txq_count(pf),
				   nse_get_avail_rxq_count(pf),
				   (u16)pf->sw_conf.max_macvlans);

	mutex_lock(&pf->vsi_tracker_mutex);
	free_res_cnt = nse_get_free_res_count(pf->vsi_tracker);
	mutex_unlock(&pf->vsi_tracker_mutex);

	if (pf->max_num_macvlan > free_res_cnt)
		pf->max_num_macvlan = free_res_cnt;

	total_rings = vsi->alloc_txq + pf->max_num_macvlan;

	/* Allocate memory for Tx and MACVLAN ring pointers */
	tmp_rings = devm_kcalloc(dev, total_rings, sizeof(*tmp_rings),
				 GFP_KERNEL);
	if (!tmp_rings) {
		ret = -ENOMEM;
		goto alloc_ring_err;
	}

	/* Copy existing ring pointers to new temporary ones */
	for (i = 0; i < vsi->alloc_txq; i++)
		tmp_rings[i] = vsi->tx_rings[i];
	vsi->base_tx_rings = vsi->tx_rings;
	vsi->tx_rings = tmp_rings;

	if (!init)
		return 0;

	ret = netif_set_real_num_tx_queues(netdev, total_rings);
	if (ret) {
		netdev_err(netdev, "Error setting real num queue\n");
		goto set_num_real_txq_err;
	}

	ret = nse_vsi_cfg_netdev_tc0(vsi);
	if (ret)
		goto set_num_tc_err;

	INIT_LIST_HEAD(&pf->macvlan_list);
	set_bit(NSE_FLAG_MACVLAN_ENA, pf->flags);

	return 0;

set_num_tc_err:
	netif_set_real_num_tx_queues(netdev, vsi->num_txq);
set_num_real_txq_err:
	vsi->tx_rings = vsi->base_tx_rings;
	vsi->base_tx_rings = NULL;
	devm_kfree(dev, tmp_rings);
alloc_ring_err:
	pf->max_num_macvlan = 0;

	if (pf->avail_macvlan)
		bitmap_free(pf->avail_macvlan);

	pf->avail_macvlan = NULL;

	return ret;
}

/**
 * nse_deinit_macvlan - Release and cleanup MACVLAN resources
 * @vsi: Main VSI pointer where sb_dev is attached to
 */
static void nse_deinit_macvlan(struct nse_vsi *vsi)
{
	struct nse_macvlan *mv, *mv_tmp;
	struct nse_pf *pf = vsi->back;
	struct nse_ring **tmp_rings;

	clear_bit(NSE_FLAG_MACVLAN_ENA, pf->flags);

	/* Remove offload from existing MACVLANs; clear software book-keeping
	 * structures and reclaim hardware resources
	 */
	list_for_each_entry_safe(mv, mv_tmp, &pf->macvlan_list, list) {
		nse_fltr_remove_mac(mv->vsi, mv->mac, NSE_FWD_TO_VSI);
		macvlan_release_l2fw_offload(mv->vdev);
		nse_fwd_del_macvlan(mv->parent_vsi->netdev, mv);
	}

	netdev_set_num_tc(vsi->netdev, 0);

	netif_set_real_num_tx_queues(vsi->netdev, vsi->num_txq);
	pf->max_num_macvlan = 0;

	/* Restore original Tx ring pointers */
	tmp_rings = vsi->tx_rings;
	vsi->tx_rings = vsi->base_tx_rings;
	devm_kfree(nse_pf_to_dev(pf), tmp_rings);

	if (pf->avail_macvlan)
		bitmap_free(pf->avail_macvlan);

	pf->avail_macvlan = NULL;
}

/**
 * nse_vsi_replay_macvlan - Configure MACVLAN netdev settings after reset
 * @pf: board private structure
 */
static void nse_vsi_replay_macvlan(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_macvlan *mv, *mv_temp;

	list_for_each_entry_safe(mv, mv_temp, &pf->macvlan_list, list) {
		struct nse_vsi *vsi = mv->parent_vsi;
		int offset = vsi->alloc_txq + mv->id;
		int ret;
		int i;

		nse_for_each_txq(mv->vsi, i)
			vsi->tx_rings[offset + i] = mv->vsi->tx_rings[i];

		ret = netdev_set_sb_channel(mv->vdev, mv->id + 1);
		if (ret) {
			dev_dbg(dev, "Error setting netdev_set_sb_channel %d\n",
				ret);
			/* Do not return error, try to configure as many as
			 * possible
			 */
			nse_fltr_remove_mac(mv->vsi, mv->mac, NSE_FWD_TO_VSI);
			macvlan_release_l2fw_offload(mv->vdev);
			nse_fwd_del_macvlan(mv->parent_vsi->netdev, mv);
			continue;
		}

		ret = netdev_bind_sb_channel_queue(vsi->netdev, mv->vdev, 0,
						   mv->vsi->num_txq, offset);
		if (ret) {
			dev_dbg(dev, "Error setting netdev_bind_sb_channel_queue %d\n",
				ret);
			/* Do not return error, try to configure as many as
			 * possible
			 */
			nse_fltr_remove_mac(mv->vsi, mv->mac, NSE_FWD_TO_VSI);
			macvlan_release_l2fw_offload(mv->vdev);
			nse_fwd_del_macvlan(mv->parent_vsi->netdev, mv);
			continue;
		}
	}
}

void nse_download_ddp(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	const unsigned int *ddp_data;
	int err = 0;
	enum nse_status status;

	if (!download_ddp)
		return;

	if (!nse_is_fw_fea_set(hw, NSE_FW_FEA_SUPPORT_DDP))
		return;

	/* only PF-0 is allowd to do this operation */
	if (hw->pcore_id != 0 || hw->pcore_pf_id != 0)
		return;

	nse_debug(hw, NSE_DBG_SYS, "[%s] enter, pcore_id=%d, pcore_pf_id=%d\n",
		  __func__, hw->pcore_id, hw->pcore_pf_id);

	if (!pf->ddp) {
		err = request_firmware(&pf->ddp, NSE_DDP_PKG_FILE, dev);
		if (err) {
			dev_info(dev, "[%s] DDP file (%s) can not be read\n",
				 __func__, NSE_DDP_PKG_FILE);
			pf->ddp = NULL;
			return;
		}
	}

	ddp_data = (const unsigned int *)pf->ddp->data;

	nse_debug(hw, NSE_DBG_SYS, "[%s] first 4 DWORD of DDP: %X %X %X %X\n",
							__func__, ddp_data[0], ddp_data[1],
								ddp_data[2], ddp_data[3]);

	status = nse_aq_write_ddp(hw, pf->ddp->data, pf->ddp->size);
	if (status)
		dev_info(dev, "[%s] fail, status=%d(%s)\n",
			 __func__, status, nse_stat_str(status));
	else
		dev_info(dev, "[%s] OK\n", __func__);
}

static int
nse_indr_setup_tc_cb(struct net_device *netdev, struct Qdisc *sch,
		     void *cb_priv, enum tc_setup_type type, void *type_data,
		     void *data,
		     void (*cleanup)(struct flow_block_cb *block_cb));

/**
 * nse_init_mac_fltr - Set initial MAC filters
 * @pf: board private structure
 *
 * Set initial set of MAC filters for PF VSI; configure filters for permanent
 * address and broadcast address. If an error is encountered, netdevice will be
 * unregistered.
 */
static int nse_init_mac_fltr(struct nse_pf *pf)
{
	enum nse_status status;
	struct nse_vsi *vsi;
	u8 *lan_addr;

	vsi = nse_get_main_vsi(pf);
	if (!vsi)
		return -EINVAL;

	lan_addr = vsi->port_info->mac.perm_addr;
	status = nse_fltr_add_mac_and_broadcast(vsi, lan_addr, NSE_FWD_TO_VSI);
	if (status)
		return -EIO;

	return 0;
}

/**
 * nse_add_mac_to_sync_list - creates list of MAC addresses to be synced
 * @netdev: the net device on which the sync is happening
 * @addr: MAC address to sync
 *
 * This is a callback function which is called by the in kernel device sync
 * functions (like __dev_uc_sync, __dev_mc_sync, etc). This function only
 * populates the tmp_sync_list, which is later used by nse_add_mac to add the
 * MAC filters from the hardware.
 */
static int nse_add_mac_to_sync_list(struct net_device *netdev, const u8 *addr)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;

	if (nse_fltr_add_mac_to_list(vsi, &vsi->tmp_sync_list, addr,
				     NSE_FWD_TO_VSI))
		return -EINVAL;

	return 0;
}

/**
 * nse_add_mac_to_unsync_list - creates list of MAC addresses to be unsynced
 * @netdev: the net device on which the unsync is happening
 * @addr: MAC address to unsync
 *
 * This is a callback function which is called by the in kernel device unsync
 * functions (like __dev_uc_unsync, __dev_mc_unsync, etc). This function only
 * populates the tmp_unsync_list, which is later used by nse_remove_mac to
 * delete the MAC filters from the hardware.
 */
static int nse_add_mac_to_unsync_list(struct net_device *netdev, const u8 *addr)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;

	/* Under some circumstances, we might receive a request to delete our
	 * own device address from our uc list. Because we store the device
	 * address in the VSI's MAC filter list, we need to ignore such
	 * requests and not delete our device address from this list.
	 */
	if (ether_addr_equal(addr, netdev->dev_addr))
		return 0;

	if (nse_fltr_add_mac_to_list(vsi, &vsi->tmp_unsync_list, addr,
				     NSE_FWD_TO_VSI))
		return -EINVAL;

	return 0;
}

/**
 * nse_vsi_fltr_changed - check if filter state changed
 * @vsi: VSI to be checked
 *
 * returns true if filter state has changed, false otherwise.
 */
static bool nse_vsi_fltr_changed(struct nse_vsi *vsi)
{
	return test_bit(NSE_VSI_UMAC_FLTR_CHANGED, vsi->state) ||
	       test_bit(NSE_VSI_MMAC_FLTR_CHANGED, vsi->state);
}

/**
 * nse_set_promisc - Enable promiscuous mode for a given PF
 * @vsi: the VSI being configured
 * @promisc_m: mask of promiscuous config bits
 *
 */
static int nse_set_promisc(struct nse_vsi *vsi, u8 promisc_m)
{
	int status;

	if (vsi->type != NSE_VSI_PF)
		return 0;

	if (nse_vsi_has_non_zero_vlans(vsi)) {
		promisc_m |= (NSE_PROMISC_VLAN_RX | NSE_PROMISC_VLAN_TX);
		status = nse_fltr_set_vlan_vsi_promisc(&vsi->back->hw, vsi,
						       promisc_m);
	} else {
		status = nse_fltr_set_vsi_promisc(&vsi->back->hw, vsi->idx,
						  promisc_m, 0);
	}

	if (status && status != -EEXIST)
		return -EIO;

	return 0;
}

/**
 * nse_clear_promisc - Disable promiscuous mode for a given PF
 * @vsi: the VSI being configured
 * @promisc_m: mask of promiscuous config bits
 *
 */
static int nse_clear_promisc(struct nse_vsi *vsi, u8 promisc_m)
{
	int status;

	if (vsi->type != NSE_VSI_PF)
		return 0;

	if (nse_vsi_has_non_zero_vlans(vsi)) {
		promisc_m |= (NSE_PROMISC_VLAN_RX | NSE_PROMISC_VLAN_TX);
		status = nse_fltr_clear_vlan_vsi_promisc(&vsi->back->hw, vsi,
							 promisc_m);
	} else {
		status = nse_fltr_clear_vsi_promisc(&vsi->back->hw, vsi->idx,
						    promisc_m, 0);
	}

	return status;
}

/**
 * nse_vsi_sync_fltr - Update the VSI filter list to the HW
 * @vsi: ptr to the VSI
 *
 * Push any outstanding VSI filter changes through the AdminQ.
 */
static int nse_vsi_sync_fltr(struct nse_vsi *vsi)
{
	struct nse_vsi_vlan_ops *vlan_ops = nse_get_compat_vsi_vlan_ops(vsi);
	struct device *dev = nse_pf_to_dev(vsi->back);
	struct net_device *netdev = vsi->netdev;
	bool promisc_forced_on = false;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	u32 changed_flags = 0;
	int err;

	if (!vsi->netdev)
		return NSE_ERR_PARAM;

	while (test_and_set_bit(NSE_CFG_BUSY, vsi->state))
		usleep_range(1000, 2000);

	changed_flags = vsi->current_netdev_flags ^ vsi->netdev->flags;
	vsi->current_netdev_flags = vsi->netdev->flags;

	INIT_LIST_HEAD(&vsi->tmp_sync_list);
	INIT_LIST_HEAD(&vsi->tmp_unsync_list);

	if (nse_vsi_fltr_changed(vsi)) {
		clear_bit(NSE_VSI_UMAC_FLTR_CHANGED, vsi->state);
		clear_bit(NSE_VSI_MMAC_FLTR_CHANGED, vsi->state);

		/* grab the netdev's addr_list_lock */
		netif_addr_lock_bh(netdev);
		__dev_uc_sync(netdev, nse_add_mac_to_sync_list,
			      nse_add_mac_to_unsync_list);
		__dev_mc_sync(netdev, nse_add_mac_to_sync_list,
			      nse_add_mac_to_unsync_list);
		/* our temp lists are populated. release lock */
		netif_addr_unlock_bh(netdev);
	}

	/* Remove MAC addresses in the unsync list */
	err = nse_fltr_remove_mac_list(vsi, &vsi->tmp_unsync_list);
	nse_fltr_free_list(dev, &vsi->tmp_unsync_list);
	if (err) {
		netdev_err(netdev, "Failed to delete MAC filters\n");
		/* if we failed because of alloc failures, just bail */
		if (err == NSE_ERR_NO_MEMORY)
			goto out;
	}

	/* Add MAC addresses in the sync list */
	err = nse_fltr_add_mac_list(vsi, &vsi->tmp_sync_list);
	nse_fltr_free_list(dev, &vsi->tmp_sync_list);
	/* If filter is added successfully or already exists, do not go into
	 * 'if' condition and report it as error. Instead continue processing
	 * rest of the function.
	 */
	if (err && err != NSE_ERR_ALREADY_EXISTS) {
		netdev_err(netdev, "Failed to add MAC filters\n");
		/* If there is no more space for new umac filters, VSI
		 * should go into promiscuous mode. There should be some
		 * space reserved for promiscuous filters.
		 */
		if (hw->adminq.sq_last_status == NSE_AQ_RC_ENOSPC &&
		    !test_and_set_bit(NSE_FLTR_OVERFLOW_PROMISC,
				      vsi->state)) {
			promisc_forced_on = true;
			netdev_warn(netdev, "Reached MAC filter limit, forcing promisc mode on VSI %d\n",
						 vsi->vsi_abs_num);
		} else {
			goto out;
		}
	}
	err = 0;
	/* check for changes in promiscuous modes */
	if (changed_flags & IFF_ALLMULTI) {
		if (vsi->current_netdev_flags & IFF_ALLMULTI) {
			err = nse_set_promisc(vsi, NSE_MCAST_PROMISC_BITS);
			if (err) {
				vsi->current_netdev_flags &= ~IFF_ALLMULTI;
				goto out_promisc;
			}
		} else {
			/* !(vsi->current_netdev_flags & IFF_ALLMULTI) */
			err = nse_clear_promisc(vsi, NSE_MCAST_PROMISC_BITS);
			if (err) {
				vsi->current_netdev_flags |= IFF_ALLMULTI;
				goto out_promisc;
			}
		}
	}

	if (((changed_flags & IFF_PROMISC) || promisc_forced_on) ||
	    test_bit(NSE_VSI_PROMISC_CHANGED, vsi->state)) {
		clear_bit(NSE_VSI_PROMISC_CHANGED, vsi->state);
		if (vsi->current_netdev_flags & IFF_PROMISC) {
			/* Apply Rx filter rule to get traffic from wire */
			err = nse_set_dflt_vsi(vsi);
			if (err) {
				netdev_err(netdev, "Error %d setting default VSI %i Rx rule\n",
					   err, vsi->vsi_abs_num);
				vsi->current_netdev_flags &= ~IFF_PROMISC;
				goto out_promisc;
			}

			vlan_ops->dis_rx_filtering(vsi);

			/* promiscuous mode implies allmulticast so that VSIs
			 * that are in promiscuous mode are subscribed to
			 * multicast packets coming to the port
			 */
			err = nse_set_promisc(vsi, NSE_MCAST_PROMISC_BITS);
			if (err)
				goto out_promisc;
		} else {
			/* Clear Rx filter to remove traffic from wire */
			err = nse_clear_dflt_vsi(vsi);
			if (err) {
				netdev_err(netdev, "Error %d clearing default VSI %i Rx rule\n",
					   err, vsi->vsi_abs_num);
				vsi->current_netdev_flags |=
					IFF_PROMISC;
				goto out_promisc;
			}

			if (vsi->netdev->features &
				NETIF_F_HW_VLAN_CTAG_FILTER)
				vlan_ops->ena_rx_filtering(vsi);

			/* disable allmulti here, but only if allmulti is not
			 * still enabled for the netdev
			 */
			if (!(vsi->current_netdev_flags & IFF_ALLMULTI)) {
				err = nse_clear_promisc(vsi, NSE_MCAST_PROMISC_BITS);
				if (err) {
					netdev_err(netdev, "Error %d clearing multicast promiscuous on VSI %i\n",
						   err, vsi->vsi_abs_num);
				}
			}
		}
	}
	goto exit;

out_promisc:
	set_bit(NSE_VSI_PROMISC_CHANGED, vsi->state);
	goto exit;
out:
	/* if something went wrong then set the changed flag so we try again */
	set_bit(NSE_VSI_UMAC_FLTR_CHANGED, vsi->state);
	set_bit(NSE_VSI_MMAC_FLTR_CHANGED, vsi->state);
exit:
	clear_bit(NSE_CFG_BUSY, vsi->state);
	return err;
}

/**
 * nse_sync_fltr_subtask - Sync the VSI filter list with HW
 * @pf: board private structure
 */
static void nse_sync_fltr_subtask(struct nse_pf *pf)
{
	int v;

	if (nse_bypass_switch)
		return;

	if (!pf || !(test_bit(NSE_FLAG_FLTR_SYNC, pf->flags)))
		return;

	clear_bit(NSE_FLAG_FLTR_SYNC, pf->flags);

	nse_for_each_vsi(pf, v)
		if (pf->vsi[v] && nse_vsi_fltr_changed(pf->vsi[v]) &&
		    nse_vsi_sync_fltr(pf->vsi[v])) {
			/* come back and try again later */
			set_bit(NSE_FLAG_FLTR_SYNC, pf->flags);
			break;
		}
}

/**
 * nse_pf_dis_all_vsi - Pause all VSIs on a PF
 * @pf: the PF
 * @locked: is the rtnl_lock already held
 */
void nse_dis_all_vsi_under_pf_drv(struct nse_pf *pf, bool locked)
{
	struct nse_hw *hw = &pf->hw;
	int v;

	nse_for_each_vsi(pf, v) {
		if (!pf->vsi[v])
			continue;

		if (!nse_is_vsi_type_under_pf_drv(pf->vsi[v]->type))
			continue;

		nse_dis_vsi_under_pf_drv(hw, pf->vsi[v], locked);
	}
}

#ifdef CONFIG_PCI_IOV
void nse_dis_all_vsi_under_vf_drv(struct nse_pf *pf)
{
	struct nse_vf *vf;
	unsigned int bkt;

	if (!nse_has_vfs(pf))
		return;

	nse_for_each_vf(pf, bkt, vf) {
		mutex_lock(&vf->cfg_lock);

		nse_dis_vf_qs(vf, false);

		nse_dis_vf_mappings(vf);

		mutex_unlock(&vf->cfg_lock);
	}
}
#else
static inline void nse_dis_all_vsi_under_vf_drv(struct nse_pf *pf) { }
#endif

/**
 * nse_remove_tc_fltr_vlist
 *	- clear TC filters vsi list software bookkeeping information
 * @hw: pointer to the hardware structure
 * @tc_action: current fltr actions information
 *
 */
static void nse_remove_tc_fltr_vlist(struct nse_hw *hw,
		struct nse_tc_flower_action *tc_action)
{
	struct nse_vsi_list_map_info *vsi_list_info;

	if (tc_action->vsi_list_id != NSE_TC_FLWR_VSI_LIST_ID_INVALID &&
		tc_action->vsi_list_info) {
		vsi_list_info = tc_action->vsi_list_info;
		if (refcount_dec_and_test(&vsi_list_info->ref_cnt)) {
			mutex_lock(&hw->switch_info->vsi_list_lock);
			list_del(&vsi_list_info->list_entry);
			mutex_unlock(&hw->switch_info->vsi_list_lock);
			devm_kfree(nse_hw_to_dev(hw), vsi_list_info);
		}
		tc_action->vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;
		tc_action->vsi_list_info = NULL;
	}
}

/**
 * nse_free_tc_fltr_sw_counter_p
 *	- clear TC filters counter pair software bookkeeping information
 * @hw: pointer to the hardware structure
 * @tc_action: current fltr actions information
 *
 */
static void nse_free_tc_fltr_sw_counter_p(struct nse_hw *hw,
		struct nse_sw_counter_pair *counter_p)
{
	struct nse_switch_info *sw = hw->switch_info;
	struct nse_sw_stats *sw_stats = &sw->sw_stats;

	mutex_lock(&sw_stats->rd_lock);
	nse_sw_stats_remove_pair(hw, counter_p);
	mutex_unlock(&sw_stats->rd_lock);
	devm_kfree(nse_hw_to_dev(hw), counter_p);
}

/**
 * nse_remove_tc_fltr_counter_p
 *	- clear TC filters counter pair software bookkeeping information
 * @hw: pointer to the hardware structure
 * @tc_action: current fltr actions information
 *
 */
static void nse_remove_tc_fltr_counter_p(struct nse_hw *hw,
		struct nse_tc_flower_action *tc_action)
{
	if (tc_action->counter_p) {
		nse_free_tc_fltr_sw_counter_p(hw, tc_action->counter_p);
		tc_action->counter_p = NULL;
	}
}

/**
 * nse_remove_tc_fltr_task_list
 *	- clear TC filters task list software bookkeeping information
 * @hw: pointer to the hardware structure
 * @tc_action: current fltr actions information
 *
 */
static void nse_remove_tc_fltr_task_list(struct nse_hw *hw,
		struct nse_tc_flower_action *tc_action)
{
	struct nse_sw_task_list *task_list;

	if (tc_action->task_list) {
		task_list = tc_action->task_list;
		if (refcount_dec_and_test(&task_list->ref_cnt)) {
			mutex_lock(&hw->switch_info->task_list_lock);
			list_del(&task_list->list_entry);
			mutex_unlock(&hw->switch_info->task_list_lock);
			devm_kfree(nse_hw_to_dev(hw), task_list);
		}
		tc_action->task_list = NULL;
	}
}

/**
 * nse_remove_tc_fltr_sflow
 *	- clear TC filters sflow software bookkeeping information
 * @hw: pointer to the hardware structure
 * @tc_action: current fltr actions information
 *
 */
static void nse_remove_tc_fltr_sflow(struct nse_hw *hw,
		struct nse_tc_flower_action *tc_action)
{
#ifdef NSE_TC_FLWR_SFLOW
	struct nse_sw_sflow *sflow;

	if (tc_action->sflow) {
		sflow = tc_action->sflow;
		if (refcount_dec_and_test(&sflow->ref_cnt)) {
			devm_kfree(nse_hw_to_dev(hw), sflow);
			hw->switch_info->sflow = NULL;
		}
		tc_action->sflow = NULL;
	}
#endif
}

/**
 * nse_remove_tc_fltr_meter
 *	- clear TC filters meter software bookkeeping information
 * @hw: pointer to the hardware structure
 * @tc_action: current fltr actions information
 *
 */
static void nse_remove_tc_fltr_meter(struct nse_hw *hw,
		struct nse_tc_flower_action *tc_action)
{
	struct nse_sw_meter *meter;

	if (tc_action->meter) {
		meter = tc_action->meter;
		if (refcount_dec_and_test(&meter->ref_cnt)) {
			if (meter->red_cnt_p) {
				nse_free_tc_fltr_sw_counter_p(hw, meter->red_cnt_p);
				meter->red_cnt_p = NULL;
			}

			if (meter->green_cnt_p) {
				nse_free_tc_fltr_sw_counter_p(hw, meter->green_cnt_p);
				meter->green_cnt_p = NULL;
			}

			mutex_lock(&hw->switch_info->meter_list_lock);
			list_del(&meter->list_entry);
			mutex_unlock(&hw->switch_info->meter_list_lock);
			devm_kfree(nse_hw_to_dev(hw), meter);
		}
		tc_action->meter = NULL;
	}
}

/**
 * nse_remove_tc_fltr_du_data
 *	- clear TC filters du data software bookkeeping information
 * @hw: pointer to the hardware structure
 * @tc_action: current fltr actions information
 *
 */
static void nse_remove_tc_fltr_du_data(struct nse_hw *hw,
		struct nse_tc_flower_action *tc_action)
{
	struct nse_sw_du_data *du_data;

	if (tc_action->du_data) {
		du_data = tc_action->du_data;

		mutex_lock(&hw->switch_info->du_data_lock);
		list_del(&du_data->list_entry);
		mutex_unlock(&hw->switch_info->du_data_lock);
		devm_kfree(nse_hw_to_dev(hw), du_data);

		tc_action->du_data = NULL;
	}
}

/**
 * nse_remove_tc_fltr_single_encap
 *	- clear TC filters single encap software bookkeeping information
 * @hw: pointer to the hardware structure
 * @tc_action: current fltr actions information
 *
 */
static void nse_remove_tc_fltr_single_encap(struct nse_hw *hw,
			struct nse_sw_encap_entry **encap_entry_p)
{
	struct nse_sw_encap_entry *encap_entry;

	encap_entry = *encap_entry_p;

	if (*encap_entry_p) {
		if (refcount_dec_and_test(&encap_entry->ref_cnt)) {
			mutex_lock(&hw->switch_info->encap_tbl_lock);
			list_del(&encap_entry->list_entry);
			mutex_unlock(&hw->switch_info->encap_tbl_lock);
			nse_encap_entry_detach_neigh(hw, encap_entry);
			kfree(encap_entry->tun_info);
			devm_kfree(nse_hw_to_dev(hw), encap_entry);
		}
		*encap_entry_p = NULL;
	}
}

/**
 * nse_remove_tc_fltr_multi_encap
 *	- clear TC filters multi encap software bookkeeping information
 * @hw: pointer to the hardware structure
 * @tc_action: current fltr actions information
 *
 */
static void nse_remove_tc_fltr_multi_encap(struct nse_hw *hw,
			struct nse_tc_flower_action *tc_action)
{
	struct nse_sw_m_encap_entry *m_encap_entry;
	int i;

	m_encap_entry = tc_action->m_encap_entry;

	for (i = 0; i < m_encap_entry->encap_cnt; i++)
		nse_remove_tc_fltr_single_encap(hw,
						&m_encap_entry->encap_entry[i]);

	if (refcount_dec_and_test(&m_encap_entry->ref_cnt)) {
		mutex_lock(&hw->switch_info->m_encap_lock);
		list_del(&m_encap_entry->list_entry);
		mutex_unlock(&hw->switch_info->m_encap_lock);
		devm_kfree(nse_hw_to_dev(hw), m_encap_entry);
	}

	tc_action->m_encap_entry = NULL;
}

/**
 * nse_remove_tc_fltr_encap
 *	- clear TC filters encap software bookkeeping information
 * @hw: pointer to the hardware structure
 * @tc_action: current fltr actions information
 *
 */
static void nse_remove_tc_fltr_encap(struct nse_hw *hw,
		struct nse_tc_flower_action *tc_action)
{
	int i;

	if (tc_action->encap_cnt) {
		for (i = 0; i < tc_action->dest_cnt; i++) {
			kfree(tc_action->dests[i].tun_info);
			tc_action->dests[i].tun_info = NULL;
		}

		for (i = 0; i < tc_action->encap_cnt; i++)
			nse_tc_fltr_detach_encap(&tc_action->encaps[i]);

		nse_remove_tc_fltr_single_encap(hw, &tc_action->encap_entry);
		nse_remove_tc_fltr_multi_encap(hw, tc_action);
	}
}

/**
 * nse_remove_tc_fltrs - clear TC filters configuration
 * @pf: ptr to PF, TC-flower based filter are tracked at PF level
 * @remove_from_list: true if filter to be removed from tc_fltr list
 *
 * Remove all advanced TC flower switch filters from software bookkeeping.
 * If 'remove_from_list' parameter is set to true, all filters are also
 * removed from PF's tc_flower_fltr_list list and it's not possible to
 * restore them (after the reset for example).
 */
static void nse_remove_tc_fltrs(struct nse_pf *pf, bool remove_from_list)
{
	struct nse_tc_flower_fltr *fltr;
	struct hlist_node *node2;
	struct nse_hw *hw = &pf->hw;

	if (nse_bypass_switch)
		return;

	mutex_lock(&pf->tc_flower_mutex);

	hlist_for_each_entry_safe(fltr, node2,
				  &pf->tc_flower_fltr_list,
				  tc_flower_node) {
		struct nse_adv_fltr_mgmt_list_entry *entry, *tmp;
		struct list_head *list_head;
		struct mutex *rule_lock;
		struct nse_switch_info *sw;
		struct nse_tc_flower_action *tc_action = &fltr->action;

		sw = pf->hw.switch_info;
		if (!sw->lut_list[fltr->lut_id].lut_created)
			continue;

		rule_lock = &sw->lut_list[fltr->lut_id].filt_rule_lock;
		list_head = &sw->lut_list[fltr->lut_id].filt_rules;

		list_for_each_entry_safe(entry, tmp, list_head, list_entry) {
			if (entry->node_info.fltr_node_id == fltr->node_id) {
				mutex_lock(rule_lock);
				list_del(&entry->list_entry);
				devm_kfree(nse_pf_to_dev(pf), entry->lkups);
				devm_kfree(nse_pf_to_dev(pf), entry);
				if (list_empty(&sw->lut_list[fltr->lut_id].filt_rules))
					sw->lut_list[fltr->lut_id].adv_rule = false;
				mutex_unlock(rule_lock);
				break;
			}
		}

		nse_remove_tc_fltr_vlist(hw, tc_action);
		nse_remove_tc_fltr_counter_p(hw, tc_action);
		nse_remove_tc_fltr_task_list(hw, tc_action);
		nse_remove_tc_fltr_sflow(hw, tc_action);
		nse_remove_tc_fltr_meter(hw, tc_action);
		nse_remove_tc_fltr_du_data(hw, tc_action);
		nse_remove_tc_fltr_encap(hw, tc_action);

		tc_action->large_act_id = NSE_TC_FLWR_LARGE_ACTION_INVALID;
		tc_action->vsi_list_id = NSE_TC_FLWR_VSI_LIST_ID_INVALID;
		tc_action->meter_param.mode = NSE_RATE_LIMIT_INVLID;

		memset(&tc_action->node_state, 0, sizeof(tc_action->node_state));

		if (remove_from_list) {
			hlist_del(&fltr->tc_flower_node);
			kfree(fltr);
		}
	}

	mutex_unlock(&pf->tc_flower_mutex);
}

/**
 * nse_clear_sw_rcp_per_profile - clear software recipe bookkeeping per profile
 * @pf: board private structure
 *
 */
static void nse_clear_sw_rcp_per_profile(struct nse_pf *pf)
{
	struct nse_switch_info *sw;
	struct nse_profile_info *profile;
	u16 offset;

	if (nse_bypass_switch)
		return;

	sw = pf->hw.switch_info;

	for (offset = 0; offset < sw->max_used_prof_index + 1; offset++) {
		u8 del_recps = 0, lut_id, recp_id;
		int i;

		profile = &sw->profile_list[offset];

		if (profile->used_recipe_num <= profile->local_rcp)
			continue;

		del_recps = profile->used_recipe_num - profile->local_rcp;

		for (i = 0; i < del_recps; i++) {
			recp_id = profile->used_recipe_num - i - 1;
			lut_id = profile->lut_id[recp_id];
			clear_bit(lut_id, profile->lut_bitmap);
			profile->lut_id[recp_id] = 0;
		}
		profile->used_recipe_num -= del_recps;
	}
}

/**
 * nse_clear_sw_switch_luts - clear switch luts
 * @pf: board private structure
 *
 * Mark switch luts as not created in sw structures. There are cases where
 * rules (especially advanced rules) need to be restored, either re-read from
 * hardware or added again. For example after the reset. 'lut_created' flag
 * prevents from doing that and need to be cleared upfront.
 */
static void nse_clear_sw_switch_luts(struct nse_pf *pf)
{
	struct nse_lut_info *lut;
	struct nse_adv_fltr_mgmt_list_entry *tmp_entry;
	struct nse_adv_fltr_mgmt_list_entry *lst_itr;
	struct nse_lut_grp_entry *lut_entry, *lut_tmp;
	struct nse_sw_fv_list_entry *fv_entry, *fv_tmp;
	u16 i;

	if (nse_bypass_switch)
		return;

	lut = pf->hw.switch_info->lut_list;
	for (i = 0; i < NSE_MAX_NUM_LUTS; i++) {
		if (!lut[i].lut_created || lut[i].is_lpm)
			continue;

		lut[i].lut_created = false;

		if (lut[i].adv_rule) {
			mutex_lock(&lut[i].filt_rule_lock);
			list_for_each_entry_safe(lst_itr, tmp_entry,
						 &lut[i].filt_rules, list_entry) {
				list_del(&lst_itr->list_entry);
				devm_kfree(nse_pf_to_dev(pf), lst_itr->lkups);
				devm_kfree(nse_pf_to_dev(pf), lst_itr);
			}
			mutex_unlock(&lut[i].filt_rule_lock);
		} else
			dev_info(nse_pf_to_dev(pf),
				"[%s, %d] Lut[%d] is a NULL Lkup Table\n",
				__func__, __LINE__, lut[i].lut_id);

		/*reinit software bookkeeping of lut information*/
		list_for_each_entry_safe(lut_entry, lut_tmp,
			&lut[i].lut_group_list, l_entry) {
			list_del(&lut_entry->l_entry);
			devm_kfree(nse_pf_to_dev(pf), lut_entry);
		}

		list_for_each_entry_safe(fv_entry, fv_tmp,
			&lut[i].fv_list, list_entry) {
			list_del(&fv_entry->list_entry);
			devm_kfree(nse_pf_to_dev(pf), fv_entry);
		}
	}
}

/**
 * nse_prepare_for_reset - prep for reset
 * @pf: board private structure
 * @reset_type: reset type requested
 *
 * Inform or close all dependent features in prep for reset.
 */
void
nse_prepare_for_reset(struct nse_pf *pf, enum nse_reset_req reset_type, bool initiate_by_me)
{
	struct nse_hw *hw = &pf->hw;
	struct nse_vf *vf;
	struct nse_vsi *vsi;
	unsigned int bkt, i;
	unsigned int reset_wait_flags;
	unsigned int unplug_preset_reset = 0;
	enum nse_status status;

	nse_debug(hw, NSE_DBG_SYS, "[%s] - enter: reset_type=%d, high_reset_ongoing=%d, initiate_by_me=%d\n",
				__func__, reset_type, hw->high_reset_ongoing, initiate_by_me);

	/* already prepared for reset */
	if (test_bit(NSE_PREPARED_FOR_RESET, pf->state)) {
		nse_debug(hw, NSE_DBG_SYS,
			  "[%s] - exit: return early because flag PREPARED_FOR_RESET already set\n",
			__func__);
		return;
	}

	nse_lmac_phy_prepare_for_reset(hw, reset_type);

	if (nse_is_high_reset_type(reset_type) && !initiate_by_me) {
		reset_wait_flags = (NSE_RESET_WAIT_FLAG_WAIT_FWMNG |
				    NSE_RESET_WAIT_FLAG_WAIT_FRTRIG |
							NSE_RESET_WAIT_FLAG_WAIT_ST_MNG);

		status = nse_reset_wait_complete(hw, false, reset_wait_flags);

		if (status)
			nse_debug(hw, NSE_DBG_SYS,
				  "[%s] timeout wait_for_high_reset_fw_cleanup, continue anyway\n",
				__func__);
		else
			nse_debug(hw, NSE_DBG_SYS,
				  "[%s] DONE wait_for_high_reset_fw_cleanup\n", __func__);

		/* if global reset not initiate_by_me but by other PF or FW,
		 * then after I wait_complete, I know underlying HW/FW is all cleaned up
		 */
		unplug_preset_reset = 1;
	}

	if (nse_aq_rq_rx_method)
		nse_ctrlq_rq_flush_bh(&hw->adminq);

	nse_unplug_aux_devs(pf, unplug_preset_reset, 1);

	/* Notify VFs of impending reset */
	if (nse_check_sq_alive(hw, &hw->adminq, NULL) && initiate_by_me)
		nse_vc_notify_reset(pf, reset_type);

	mutex_lock(&pf->vfs.table_lock);
	nse_for_each_vf(pf, bkt, vf) {
		/* Disable VFs until reset is completed */
		nse_set_vf_state_qs_dis(vf);

		if (vf->vf_ops->clear_reset_state)
			vf->vf_ops->clear_reset_state(vf);
	}
	mutex_unlock(&pf->vfs.table_lock);

	if (nse_is_eswitch_mode_switchdev(pf) &&
		nse_is_high_reset_type(reset_type)) {
		nse_debug(hw, NSE_DBG_SW, "[%s, %d] high_reset, switchdev=true, remove_tc_fltrs and clear_sw_switch_luts\n",
									__func__, __LINE__);

		nse_remove_tc_fltrs(pf, false);

		nse_clear_sw_rcp_per_profile(pf);

		nse_clear_sw_switch_luts(pf);

		nse_debug(hw, NSE_DBG_SW, "[%s, %d] DONE: remove_tc_fltrs and clear_sw_switch_luts\n",
									__func__, __LINE__);
	}

	nse_for_each_vsi(pf, i) {
		vsi = pf->vsi[i];
		if (!vsi)
			continue;

		nse_vsi_clear_q_irqll_status(vsi);
	}

	/* Make sure the IRQLL status of every VSI is cleared before any
	 * VSI is disabled.
	 */
	wmb();

	nse_dis_all_vsi_under_pf_drv(pf, false);

	nse_dis_all_vsi_under_vf_drv(pf);

	nse_fdir_prepare_for_reset(hw);

	if (test_bit(NSE_FLAG_PTP_SUPPORTED, pf->flags))
		nse_ptp_prepare_for_reset(pf, reset_type);

	if (hw->port_info)
		nse_sched_clear_port(hw->port_info);

	/* insert a barrier here, because see log out-of-order, maybe CPU out-of-order execution. */
	wmb();

	nse_shutdown_all_ctrlq(hw, false);

	set_bit(NSE_PREPARED_FOR_RESET, pf->state);

	nse_debug(hw, NSE_DBG_SYS, "[%s] - exit\n", __func__);
}

/**
 * nse_vsi_rebuild_by_type - Rebuild VSI of a given type
 * @pf: pointer to the PF instance
 * @type: VSI type to rebuild
 *
 * Iterates through the pf->vsi array and rebuilds VSIs of the requested type
 */
int nse_rebuild_vsi_under_pf_drv_by_type(struct nse_pf *pf,
					 enum nse_vsi_type vsi_type,
					 enum nse_reset_req reset_type,
										bool reopen)
{
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status status;
	int i, err;

	nse_debug(hw, NSE_DBG_SYS, "[%s] reset_type=%d, vsi_type=%d, reopen=%d\n",
								__func__, reset_type,
									vsi_type, reopen);

	if (!nse_is_vsi_type_under_pf_drv(vsi_type)) {
		dev_err(dev, "[%s] wrong VSI type (%d) for this function\n",
						__func__, vsi_type);
		return -EINVAL;
	}

	nse_for_each_vsi(pf, i) {
		struct nse_vsi *vsi = pf->vsi[i];

		if (!vsi || vsi->type != vsi_type)
			continue;

		/* rebuild the VSI */
		err = nse_vsi_rebuild(hw, vsi, false);
		if (err) {
			dev_err(dev, "[%s] FAIL: vsi_rebuild() err=%d, VSI index %d, type %s\n",
							__func__, err, vsi->idx,
								nse_vsi_type_str(vsi_type));
			return err;
		}

		/* replay filters for the VSI */
		status = nse_replay_vsi(hw, vsi->idx, reset_type);
		if (status) {
			dev_err(dev, "[%s] FAIL: replay_vsi() status=%s, VSI index %d, type %s\n",
							__func__, nse_stat_str(status),
								vsi->idx,
								nse_vsi_type_str(vsi_type));
			return -EIO;
		}

		/* enable the VSI */
		if (reopen) {
			err = nse_ena_vsi_under_pf_drv(hw, vsi, false);
			if (err) {
				dev_err(dev, "[%s] FAIL: ena_vsi_under_pf_drv() err=%d, VSI index %d, type %s\n",
								__func__, err, vsi->idx,
									nse_vsi_type_str(vsi_type));
				return err;
			}
		}

		dev_info(dev, "[%s] SUCCESS: VSI rebuilt. VSI index %d, type %s\n",
						__func__, vsi->idx, nse_vsi_type_str(vsi_type));
	}

	return 0;
}

/* forward declare */
static void nse_pf_reset_stats(struct nse_pf *pf);
static int nse_req_irq_msix_misc(struct nse_pf *pf);

/**
 * nse_rebuild - rebuild after reset
 * @pf: PF to rebuild
 * @reset_type: type of reset
 *
 * Do not rebuild VF VSI in this flow because that is already handled via
 * nse_reset_all_vfs(). This is because requirements for resetting a VF after a
 * PFR/CORER/GLOBER/etc. are different than the normal flow. Also, we don't want
 * to reset/rebuild all the VF VSI twice.
 */
void nse_rebuild(struct nse_pf *pf, enum nse_reset_req reset_type)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	enum nse_status status = NSE_SUCCESS;
	int err = 0;
	struct nse_vsi *vsi = NULL;

	nse_debug(hw, NSE_DBG_SYS, "[%s] reset_type=%d, Enter\n", __func__, reset_type);

	if (test_bit(NSE_DOWN, pf->state))
		goto clear_recovery;

	nse_debug(hw, NSE_DBG_SYS, "[%s] reset_type=%d, BEGIN\n", __func__, reset_type);

	status = nse_init_all_ctrlq(hw);
	if (status) {
		dev_err(dev, "[%s] FAIL: init control queues, %d (%s)\n",
					__func__, status, nse_stat_str(status));
		goto err_init_ctrlq;
	}

	if (nse_is_high_reset_type(reset_type)) {
		nse_download_ddp(pf);

		nse_rebuild_pf_fw_ot_features(pf, reset_type);
	}

	status = nse_clear_pf_cfg(hw);
	if (status) {
		dev_err(dev, "[%s] FAIL: clear PF configuration, %d (%s)\n",
						__func__, status, nse_stat_str(status));
		goto err_init_ctrlq;
	}

	status = nse_sched_init(hw);
	if (status) {
		dev_err(dev, "[%s] FAIL: sched_init(): %d (%s)\n",
						__func__, status, nse_stat_str(status));
		goto err_sched_init;
	}

	status = nse_lmac_phy_rebuild(hw, reset_type);
	if (status) {
		dev_err(dev, "[%s] FAIL: lmac_phy_rebuild(): %d (%s)\n",
						__func__, status, nse_stat_str(status));
		goto err_sched_init;
	}

	/* start misc vector */
	err = nse_req_irq_msix_misc(pf);
	if (err) {
		dev_err(dev, "[%s] FAIL: req_irq_msix_misc(): %d\n",
						__func__, err);
		goto err_sched_init;
	}

	if (nse_is_high_reset_type(reset_type)) {
		if (pf->sw_conf.lan_rx_ena_rsc) {
			status = nse_lan_set_rsc_ctrl(hw, RSC_CTRL_DISALLOW_PURE_ACK_M);
			if (status) {
				dev_warn(dev, "WARN: set_rsc_ctrl() fails, status=%d(%s), RSC logic would not run for this PF\n",
						status, nse_stat_str(status));

				/* not a fatal error, just not run RSC */
				status = 0;
			}
		}

		status = nse_lan_set_tdm_legacy_wb_mode(&pf->hw, 1);
		if (status)
			dev_warn(dev, "[%s] WARN: lan_set_tdm_legacy_wb_mode(1) fails, status=%d, tdm wb perf may be lower a little bit\n",
						__func__, status);
		status = 0;

		nse_lan_reinstall_tso_hsb(pf);

		nse_udp_tunnels_rebuild(pf);
	}

	nse_dcb_rebuild(pf, reset_type);

	nse_replay_pre_init(hw, reset_type);

	if (nse_is_high_reset_type(reset_type)) {
		nse_pf_reset_stats(pf);
		nse_update_pf_stats(pf);
	}

	/* rebuild PF-main-VSI */
	err = nse_rebuild_vsi_under_pf_drv_by_type(pf, NSE_VSI_PF, reset_type, true);
	if (err) {
		dev_err(dev, "[%s] FAIL: rebuild_vsi_under_pf_drv_by_type(PF-main-VSI), err=%d\n",
						__func__, err);
		goto err_vsi_rebuild;
	}

	if (test_bit(NSE_FLAG_PTP_SUPPORTED, pf->flags))
		nse_ptp_rebuild(pf, reset_type);

	vsi = nse_get_main_vsi(pf);

	nse_cdev_info_update_vsi(nse_find_cdev_info_by_id(pf, IIDC_RDMA_ID), vsi);

	if (nse_bypass_switch && pf->bypass_switch_vsi_abs_id != NSE_VSI_INVAL_ID) {
		status = nse_switch_rpp_set_bypass(&pf->hw, true,
						   pf->bypass_switch_vsi_abs_id, 0xFF);

		if (status) {
			dev_info(dev, "switch_rpp_set_bypass(true) fails, status: %d(%s)\n",
							status, nse_stat_str(status));
			goto err_vsi_rebuild;
		}
	} else {
		status = nse_switch_rpp_set_bypass(&pf->hw, false, 0, 0);

		if (status) {
			dev_info(dev, "switch_rpp_set_bypass(false) fails, status: %d(%s)\n",
							status, nse_stat_str(status));
			goto err_vsi_rebuild;
		}
	}

	if (test_bit(NSE_FLAG_MACVLAN_ENA, pf->flags)) {
		err = nse_rebuild_vsi_under_pf_drv_by_type(pf, NSE_VSI_OFFLOAD_MACVLAN,
							   reset_type, true);
		if (err) {
			dev_err(dev, "[%s] FAIL: rebuild_vsi_under_pf_drv_by_type(MACVLAN), err=%d\n",
							__func__, err);
			goto err_vsi_rebuild;
		}

		err = nse_init_macvlan(vsi, false);
		if (err) {
			dev_err(dev, "[%s] FAIL: init_macvlan()\n", __func__);
			goto err_vsi_rebuild;
		}

		nse_vsi_replay_macvlan(pf);
	}

	err = nse_rebuild_vsi_under_pf_drv_by_type(pf, NSE_VSI_SWITCHDEV_CTRL, reset_type, false);
	if (err) {
		dev_err(dev, "[%s] FAIL: rebuild_vsi_under_pf_drv_by_type(SWITCHDEV_CTRL), err=%d\n",
							__func__, err);
		goto err_vsi_rebuild;
	}

	nse_fdir_rebuild(hw, reset_type);

	nse_replay_post(hw, reset_type);

	/* misc logic */
	pf->in_high_temp = false;
	pf->check_temp_force_cancel_rl_after_reset = true;
	pf->wd_subtask_check_temp_prev = 0;	/* let it run fast */

	/* if we get here, reset flow is successful */
	clear_bit(NSE_RESET_FAILED, pf->state);

	set_bit(NSE_FLAG_PLUG_AUX_DEV, pf->flags);

	nse_debug(hw, NSE_DBG_SYS, "[%s] reset_type=%d, DONE success\n", __func__, reset_type);

	return;

err_vsi_rebuild:

err_sched_init:
	nse_sched_cleanup_all(hw);
err_init_ctrlq:
	nse_shutdown_all_ctrlq(hw, true);
	set_bit(NSE_RESET_FAILED, pf->state);
clear_recovery:
	/* set this bit in PF state to control service task scheduling */
	set_bit(NSE_NEEDS_RESTART, pf->state);
	dev_err(dev, "[%s]: FAIL Rebuild, unload and reload driver\n", __func__);
}

/**
 * nse_do_reset - Initiate one of many types of resets
 * @pf: board private structure
 * @reset_type: reset type requested before this function was called.
 */
void nse_do_reset(struct nse_pf *pf, enum nse_reset_req reset_type)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;

	nse_debug(hw, NSE_DBG_SYS, "[%s] reset_type 0x%x requested\n", __func__, reset_type);

	nse_prepare_for_reset(pf, reset_type, true);

	/* trigger the reset */
	if (nse_reset(hw, reset_type)) {
		dev_err(dev, "[%s, %d] _reset(reset_type=%d) failed\n",
			__func__, __LINE__, reset_type);
		set_bit(NSE_RESET_FAILED, pf->state);
		clear_bit(NSE_RESET_OICR_RECV, pf->state);
		clear_bit(NSE_PREPARED_FOR_RESET, pf->state);
		clear_bit(NSE_PFR_REQ, pf->state);
		clear_bit(NSE_HIGH_RESET_CORER_REQ, pf->state);
		wake_up(&pf->reset_wait_queue);
		return;
	}

	/* PFR is a bit of a special case because it doesn't result in an OICR
	 * interrupt. So for PFR, rebuild after the reset and clear the reset-
	 * associated state bits.
	 */
	if (reset_type == NSE_RESET_PFR) {
		pf->pf_reset_count++;
		nse_rebuild(pf, reset_type);
		clear_bit(NSE_PREPARED_FOR_RESET, pf->state);
		clear_bit(NSE_PFR_REQ, pf->state);
		wake_up(&pf->reset_wait_queue);
		nse_reset_all_vfs(pf, reset_type);
	}
}

/**
 * nse_reset_subtask - Set up for resetting the device and driver
 * @pf: board private structure
 */
static void nse_reset_subtask(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	unsigned int reset_wait_flags;
	enum nse_reset_req reset_type = NSE_RESET_INVAL;

	if (test_bit(NSE_RESET_OICR_RECV, pf->state)) {
		nse_debug(hw, NSE_DBG_SYS,
			  "[%s] - block #1: handling RESET_OICR_RECV\n", __func__);

		/* Perform the largest reset requested */
		if (test_and_clear_bit(NSE_HIGH_RESET_CORER_RECV, pf->state))
			reset_type = NSE_RESET_HIGH_RESET_CORER;

		/* return if no valid reset type requested */
		if (reset_type == NSE_RESET_INVAL) {
			dev_warn(dev,
"[%s, %d] RESET_OICR_RECV set, but NO valid high_reset type detected\n", __func__, __LINE__);
			return;
		}

		nse_debug(hw, NSE_DBG_SYS, "\t reset_type=%d\n", reset_type);

		nse_prepare_for_reset(pf, reset_type, false);

		/* here intentionally, NOT wait_fwmng */
		reset_wait_flags = (NSE_RESET_WAIT_FLAG_WAIT_FRTRIG |
				    NSE_RESET_WAIT_FLAG_WAIT_ST_MNG);

		/* make sure we are ready to rebuild */
		if (nse_reset_wait_complete(hw, false, reset_wait_flags)) {
			dev_err(dev, "[%s, %d] FAIL: reset_wait_complete( high-reset ), now....\n",
				__func__, __LINE__);

			set_bit(NSE_RESET_FAILED, pf->state);
			clear_bit(NSE_RESET_OICR_RECV, pf->state);
			clear_bit(NSE_PREPARED_FOR_RESET, pf->state);
			clear_bit(NSE_PFR_REQ, pf->state);
			clear_bit(NSE_HIGH_RESET_CORER_REQ, pf->state);

			wake_up(&pf->reset_wait_queue);

			return;
		}

		nse_debug(hw, NSE_DBG_SYS, "[%s, %d] clear fwmng\n", __func__, __LINE__);

		fwmng_clear_rsp(hw, false, NSE_FWMNG_CLEAR_RSP_ALL);

		msleep(500);

		/* done with reset. start rebuild */
		hw->high_reset_ongoing = false;

		nse_rebuild(pf, reset_type);

		/* clear bit to resume normal operations, but
		 * NSE_NEEDS_RESTART bit is set in case rebuild failed
		 */
		clear_bit(NSE_RESET_OICR_RECV, pf->state);
		clear_bit(NSE_PREPARED_FOR_RESET, pf->state);
		clear_bit(NSE_PFR_REQ, pf->state);
		clear_bit(NSE_HIGH_RESET_CORER_REQ, pf->state);

		wake_up(&pf->reset_wait_queue);

		nse_reset_all_vfs(pf, reset_type);

		return;
	}

	/* No pending resets to finish processing. Check for new resets */
	if (test_bit(NSE_PFR_REQ, pf->state))
		reset_type = NSE_RESET_PFR;

	if (test_bit(NSE_HIGH_RESET_CORER_REQ, pf->state))
		reset_type = NSE_RESET_HIGH_RESET_CORER;

	/* If no valid reset type requested just return */
	if (reset_type == NSE_RESET_INVAL)
		return;

	nse_debug(hw, NSE_DBG_SYS, "[%s] - block #2: handling reset_type=%d\n",
						__func__, reset_type);

	/* reset if not already down or busy */
	if (!test_bit(NSE_DOWN, pf->state) &&
	    !test_bit(NSE_CFG_BUSY, pf->state)) {
		nse_do_reset(pf, reset_type);
	}
}

/* in case don't have HAVE_UDP_TUNNEL_NIC_INFO_MAY_SLEEP */
static void nse_udp_tunnel_sync_ports(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	struct nse_aqc_psr_set_ctrl psr_cmd_buf;
	u32 flags;
	__be16 vxlan_port;
	__be16 vxlan_gpe_port;
	__be16 geneve_port;
	__le16 port_le;
	enum nse_status status;

	spin_lock_bh(&pf->udp_tnl_lock);

	flags = pf->udp_tnl_flags;
	vxlan_port = pf->vxlan_port;
	vxlan_gpe_port = pf->vxlan_gpe_port;
	geneve_port = pf->geneve_port;

	pf->udp_tnl_flags = 0;

	spin_unlock_bh(&pf->udp_tnl_lock);

	if (!flags)
		return;

	memset(&psr_cmd_buf, 0, sizeof(psr_cmd_buf));

	psr_cmd_buf.flags = cpu_to_le32(NSE_AQC_PSR_SET_CTRL_FLAG_RPSR |
					NSE_AQC_PSR_SET_CTRL_FLAG_TPSR);

	if (flags & UDP_TNL_FLAG_SYNC_VXLAN_PORT) {
		port_le = cpu_to_le16(be16_to_cpu(vxlan_port));

		psr_cmd_buf.port_or_etype = port_le;

		if (port_le)
			psr_cmd_buf.dis_or_en = 0;		/* dis = 0 */
		else
			psr_cmd_buf.dis_or_en = 1;		/* dis = 1 */

		psr_cmd_buf.ctrl_type = NSE_AQC_PSR_CTRL_TYPE_VXLAN_UDP;

		nse_debug(hw, NSE_DBG_LAN, "[%s] sync_vxlan_port, port_le=%d\n", __func__, port_le);

		status = nse_aq_psr_set_ctrl(hw, &psr_cmd_buf);
		if (status)
			dev_info(dev, "FAIL: sync_vxlan_port, status=%d, try next round\n", status);
		else
			flags &= ~UDP_TNL_FLAG_SYNC_VXLAN_PORT;
	}

	if (flags & UDP_TNL_FLAG_SYNC_VXLAN_GPE_PORT) {
		port_le = cpu_to_le16(be16_to_cpu(vxlan_gpe_port));

		psr_cmd_buf.port_or_etype = port_le;

		if (port_le)
			psr_cmd_buf.dis_or_en = 0;		/* dis = 0 */
		else
			psr_cmd_buf.dis_or_en = 1;		/* dis = 1 */

		psr_cmd_buf.ctrl_type = NSE_AQC_PSR_CTRL_TYPE_VXLAN_GPE_UDP;

		nse_debug(hw, NSE_DBG_LAN, "[%s] sync_vxlan_gpe_port, port_le=%d\n",
			  __func__, port_le);

		status = nse_aq_psr_set_ctrl(hw, &psr_cmd_buf);
		if (status)
			dev_info(dev, "FAIL: sync_vxlan_gpe_port, status=%d, try next round\n",
				 status);
		else
			flags &= ~UDP_TNL_FLAG_SYNC_VXLAN_GPE_PORT;
	}

	if (flags & UDP_TNL_FLAG_SYNC_GENEVE_PORT) {
		port_le = cpu_to_le16(be16_to_cpu(geneve_port));

		psr_cmd_buf.port_or_etype = port_le;

		if (port_le)
			psr_cmd_buf.dis_or_en = 0;		/* dis = 0 */
		else
			psr_cmd_buf.dis_or_en = 1;		/* dis = 1 */

		psr_cmd_buf.ctrl_type = NSE_AQC_PSR_CTRL_TYPE_GENEVE_UDP;

		nse_debug(hw, NSE_DBG_LAN, "[%s] sync_vxlan_gpe_port, port_le=%d\n",
			  __func__, port_le);

		status = nse_aq_psr_set_ctrl(hw, &psr_cmd_buf);
		if (status)
			dev_info(dev, "FAIL: sync_vxlan_gpe_port, status=%d, try next round\n",
				 status);
		else
			flags &= ~UDP_TNL_FLAG_SYNC_VXLAN_GPE_PORT;
	}

	if (flags) {	/* if any unhandled flags, handle it next round */
		spin_lock_bh(&pf->udp_tnl_lock);
		pf->udp_tnl_flags |= flags;
		spin_unlock_bh(&pf->udp_tnl_lock);
	}
}

static void nse_misc_subtask(struct nse_pf *pf)
{
	/* if interface is down do nothing */
	if (test_bit(NSE_DOWN, pf->state) ||
	    test_bit(NSE_CFG_BUSY, pf->state))
		return;

	nse_udp_tunnel_sync_ports(pf);
}

int wd_subtask_check_temp_chip_high_thres = WD_SUBTASK_CHECK_TEMP_CHIP_HIGH_THRES;
int wd_subtask_check_temp_chip_low_thres = WD_SUBTASK_CHECK_TEMP_CHIP_LOW_THRES;
int wd_subtask_check_temp_ephy_high_thres = WD_SUBTASK_CHECK_TEMP_EPHY_HIGH_THRES;
int wd_subtask_check_temp_ephy_low_thres = WD_SUBTASK_CHECK_TEMP_EPHY_LOW_THRES;

/**
 * nse_watchdog_subtask - periodic tasks not using event driven scheduling
 * @pf: board private structure
 */
static void nse_watchdog_subtask(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	int chip_temp = 0, ephy_temp = 0;
	bool in_high_temp_old, in_high_temp_now;
	enum nse_status status;
	int i;

	/* if interface is down do nothing */
	if (test_bit(NSE_DOWN, pf->state) ||
	    test_bit(NSE_CFG_BUSY, pf->state))
		return;

	if (pf->wd_subtask_flags >= WD_SUBTASK_FLAG_RUN_NOW)
		goto run_now;

	/* make sure we don't do these things too often */
	if (time_before(jiffies,
			pf->serv_tmr_prev + pf->serv_tmr_period))
		return;

run_now:

	pf->serv_tmr_prev = jiffies;

	if (!nse_misc_check_temp)
		pf->wd_subtask_flags &= ~WD_SUBTASK_FLAG_OICR_OVERHEAT_RECV;

	if (nse_misc_check_temp && ((pf->wd_subtask_flags & WD_SUBTASK_FLAG_OICR_OVERHEAT_RECV) ||
		time_after_eq(jiffies, pf->wd_subtask_check_temp_prev +
			      pf->wd_subtask_check_temp_period))) {
		pf->wd_subtask_check_temp_prev = jiffies;

		pf->check_temp_run_cnt++;

		in_high_temp_old = pf->in_high_temp;
		in_high_temp_now = false;

		status = nse_aq_read_chip_temperature(hw, &chip_temp);
		if (!status && chip_temp >= wd_subtask_check_temp_chip_high_thres) {
			nse_debug(hw, NSE_DBG_SYS, "[%s, %d] chip_temp=%d, overheat (high-thres=%d)\n",
				  __func__, __LINE__, chip_temp,
					  wd_subtask_check_temp_chip_high_thres);

			in_high_temp_now = true;
		}

		if (nse_is_nic_use_ephy(hw->nic_type)) {
			status = nse_lmac_phy_ephy_read_temperature(hw, &ephy_temp);
			if (!status && ephy_temp >= wd_subtask_check_temp_ephy_high_thres) {
				nse_debug(hw, NSE_DBG_SYS, "[%s, %d] ephy_temp=%d, overheat (high-thres=%d)\n",
					  __func__, __LINE__, ephy_temp,
						  wd_subtask_check_temp_ephy_high_thres);

				in_high_temp_now = true;
			}
		}

		if (in_high_temp_now) {
			pf->in_high_temp = true;

			if (!in_high_temp_old) {	/* apply rate limiting */

				dev_warn(dev, "[%s] abnormal: chip temperature=%d (high-thres=%d), external module temperature=%d (high-thres=%d), apply rate limit\n",
					 __func__, chip_temp,
						 wd_subtask_check_temp_chip_high_thres, ephy_temp,
						 wd_subtask_check_temp_ephy_high_thres);

				pf->check_temp_high_cnt++;

				pf->oicr_ena &= ~(NSE_REG_OICR_OVERHEAT_M);
				wr32(hw, NSE_REG_OICR_ENA, pf->oicr_ena);
				wr32(hw, NSE_REG_OICR_MASK, ~(pf->oicr_ena));

				status = nse_sched_set_port_node_pir(hw->port_info, false);
				if (status)
					dev_warn(dev,
	"[%s, %d] FAIL: apply rate limit, status=%d --- then ...\n", __func__, __LINE__, status);
			}

			pf->wd_subtask_flags &= ~WD_SUBTASK_FLAG_OICR_OVERHEAT_RECV;

		} else {	/* !in_high_temp_now */

			/* cancel rate limiting if below low-thres */
			if ((in_high_temp_old || pf->check_temp_force_cancel_rl_after_reset ||
			    (pf->wd_subtask_flags & WD_SUBTASK_FLAG_OICR_OVERHEAT_RECV)) &&
				chip_temp <= wd_subtask_check_temp_chip_low_thres &&
				ephy_temp <= wd_subtask_check_temp_ephy_low_thres) {
				dev_warn(dev, "[%s] chip temperature=%d (low-thres=%d), external module temperature=%d (low-thres=%d), back to normal, cancel rate limit\n",
					 __func__, chip_temp,
						 wd_subtask_check_temp_chip_low_thres, ephy_temp,
						 wd_subtask_check_temp_ephy_low_thres);

				pf->check_temp_low_cnt++;

				status = nse_sched_set_port_node_pir(hw->port_info, true);
				if (status)
					dev_warn(dev,
"[%s, %d] FAIL: cancel rate limit, status=%d, would retry next time\n", __func__, __LINE__, status);
				else {
					pf->oicr_ena |= NSE_REG_OICR_OVERHEAT_M;
					wr32(hw, NSE_REG_OICR_ENA, pf->oicr_ena);
					wr32(hw, NSE_REG_OICR_MASK, ~(pf->oicr_ena));

					pf->in_high_temp = false;

					pf->check_temp_force_cancel_rl_after_reset = false;

					pf->wd_subtask_flags &= ~WD_SUBTASK_FLAG_OICR_OVERHEAT_RECV;
				}
			}
		}
	}

	if (pf->wd_subtask_flags & WD_SUBTASK_FLAG_UPDATE_PF_STATS_NOW) {
		nse_update_pf_stats(pf);

		pf->wd_subtask_flags &= ~(WD_SUBTASK_FLAG_UPDATE_PF_STATS_NOW);
	}

	if (pf->wd_subtask_flags & WD_SUBTASK_FLAG_UPDATE_VSI_STATS_NOW) {
		nse_for_each_vsi(pf, i) {
			if (!pf->vsi[i])
				continue;

			if (pf->vsi[i]->wd_subtask_update_vsi_stats_now)
				nse_update_vsi_stats(pf->vsi[i]);

			pf->vsi[i]->wd_subtask_update_vsi_stats_now = false;
		}

		pf->wd_subtask_flags &= ~(WD_SUBTASK_FLAG_UPDATE_VSI_STATS_NOW);
	}
}

enum nse_aq_task_state {
	NSE_AQ_TASK_WAITING = 0,
	NSE_AQ_TASK_COMPLETE,
	NSE_AQ_TASK_CANCELED,
};

struct nse_aq_task {
	struct hlist_node entry;

	u16 opcode;
	struct nse_rq_event_info *event;
	enum nse_aq_task_state state;
};

/**
 * nse_aq_wait_for_event - Wait for an AdminQ event from firmware
 * @pf: pointer to the PF private structure
 * @opcode: the opcode to wait for
 * @timeout: how long to wait, in jiffies
 * @event: storage for the event info
 *
 * Waits for a specific AdminQ completion event on the ARQ for a given PF. The
 * current thread will be put to sleep until the specified event occurs or
 * until the given timeout is reached.
 *
 * To obtain only the descriptor contents, pass an event without an allocated
 * msg_buf. If the complete data buffer is desired, allocate the
 * event->msg_buf with enough space ahead of time.
 *
 * Returns: zero on success, or a negative error code on failure.
 */
int nse_aq_wait_for_event(struct nse_pf *pf, u16 opcode, unsigned long timeout,
			  struct nse_rq_event_info *event)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_aq_task *task;
	unsigned long start;
	long ret;
	int err;

	task = kzalloc(sizeof(*task), GFP_KERNEL);
	if (!task)
		return -ENOMEM;

	INIT_HLIST_NODE(&task->entry);
	task->opcode = opcode;
	task->event = event;
	task->state = NSE_AQ_TASK_WAITING;

	spin_lock_bh(&pf->aq_wait_lock);
	hlist_add_head(&task->entry, &pf->aq_wait_list);
	spin_unlock_bh(&pf->aq_wait_lock);

	start = jiffies;

#ifdef __CHECKER__
	/* Suppress sparse warning from kernel macro:
	 * warning: symbol '__ret' shadows an earlier one
	 */
	ret = timeout;
#else
	ret = wait_event_interruptible_timeout(pf->aq_wait_queue, task->state,
					       timeout);
#endif
	switch (task->state) {
	case NSE_AQ_TASK_WAITING:
		err = ret < 0 ? ret : -ETIMEDOUT;
		break;
	case NSE_AQ_TASK_CANCELED:
		err = ret < 0 ? ret : -ECANCELED;
		break;
	case NSE_AQ_TASK_COMPLETE:
		err = ret < 0 ? ret : 0;
		break;
	default:
		WARN(1, "Unexpected AdminQ wait task state %u", task->state);
		err = -EINVAL;
		break;
	}

	dev_dbg(dev, "Waited %u msecs (max %u msecs) for firmware response to op 0x%04x\n",
		jiffies_to_msecs(jiffies - start),
		jiffies_to_msecs(timeout),
		opcode);

	spin_lock_bh(&pf->aq_wait_lock);
	hlist_del(&task->entry);
	spin_unlock_bh(&pf->aq_wait_lock);
	kfree(task);

	return err;
}

/**
 * nse_aq_check_events - Check if any thread is waiting for an AdminQ event
 * @pf: pointer to the PF private structure
 * @opcode: the opcode of the event
 * @event: the event to check
 *
 * Loops over the current list of pending threads waiting for an AdminQ event.
 * For each matching task, copy the contents of the event into the task
 * structure and wake up the thread.
 *
 * If multiple threads wait for the same opcode, they will all be woken up.
 *
 * Note that event->msg_buf will only be duplicated if the event has a buffer
 * with enough space already allocated. Otherwise, only the descriptor and
 * message length will be copied.
 *
 * Returns: true if an event was found, false otherwise
 */
static void nse_aq_check_events(struct nse_pf *pf, u16 opcode,
				struct nse_rq_event_info *event)
{
	struct nse_aq_task *task;
	bool found = false;

	spin_lock_bh(&pf->aq_wait_lock);
	hlist_for_each_entry(task, &pf->aq_wait_list, entry) {
		if (task->state || task->opcode != opcode)
			continue;

		memcpy(&task->event->desc, &event->desc, sizeof(event->desc));
		task->event->msg_len = event->msg_len;

		/* Only copy the data buffer if a destination was set */
		if (task->event->msg_buf &&
		    task->event->buf_len > event->buf_len) {
			memcpy(task->event->msg_buf, event->msg_buf,
			       event->buf_len);
			task->event->buf_len = event->buf_len;
		}

		task->state = NSE_AQ_TASK_COMPLETE;
		found = true;
	}
	spin_unlock_bh(&pf->aq_wait_lock);

	if (found)
		wake_up(&pf->aq_wait_queue);
}

/**
 * nse_aq_cancel_waiting_tasks - Immediately cancel all waiting tasks
 * @pf: the PF private structure
 *
 * Set all waiting tasks to NSE_AQ_TASK_CANCELED, and wake up their threads.
 * This will then cause nse_aq_wait_for_event to exit with -ECANCELED.
 */
static void nse_aq_cancel_waiting_tasks(struct nse_pf *pf)
{
	struct nse_aq_task *task;

	spin_lock_bh(&pf->aq_wait_lock);
	hlist_for_each_entry(task, &pf->aq_wait_list, entry)
		task->state = NSE_AQ_TASK_CANCELED;
	spin_unlock_bh(&pf->aq_wait_lock);

	wake_up(&pf->aq_wait_queue);
}

u16 nse_aqc_opc_test_phy_lse = MAKE_AQC_OPCODE(NSE_AQ_OPC_CATEGORY_LMAC_PHY,
					       NSE_AQ_OPC_TEST_PHY_LSE);

u16 nse_aqc_opc_event_lan_overflow = MAKE_AQC_OPCODE(NSE_AQ_OPC_CATEGORY_LAN,
						     NSE_AQ_OPC_EVENT_LAN_OVERFLOW);
u16 nse_aqc_opc_send_msg_to_pf = MAKE_AQC_OPCODE(NSE_AQ_OPC_CATEGORY_COMM,
						 NSE_AQ_OPC_SEND_MSG_TO_PF);
u16 nse_aqc_opc_qos_dcbx_cfg_chg_event = MAKE_AQC_OPCODE(NSE_AQ_OPC_CATEGORY_QOS,
							 NSE_AQ_OPC_QOS_DCBX_CFG_CHG_EVENT);
u16 nse_aqc_opc_dbg_ping_fw_rq_rsp = MAKE_AQC_OPCODE(NSE_AQ_OPC_CATEGORY_DBG,
						     NSE_AQ_OPC_DBG_PING_FW_RQ_RSP);
u16 nse_aqc_opc_dbg_dummy_event = MAKE_AQC_OPCODE(NSE_AQ_OPC_CATEGORY_DBG,
						  NSE_AQ_OPC_DBG_DUMMY_EVENT);
u16 nse_aqc_opc_fdir_reinit_event = MAKE_AQC_OPCODE(NSE_AQ_OPC_CATEGORY_RCF,
						    NSE_AQ_OPC_FDIR_REINIT_EVENT);
u16 nse_aqc_opc_ptp_tx_ts_event = MAKE_AQC_OPCODE(NSE_AQ_OPC_CATEGORY_MISC,
						  NSE_AQ_OPC_PTP_TX_TS_EVENT);
u16 nse_aqc_opc_dma_get_cnt_event = MAKE_AQC_OPCODE(NSE_AQ_OPC_CATEGORY_SWITCH,
						    NSE_AQ_OPC_GET_COUNTER);
u16 nse_aqc_opc_set_bmc_mac_event = MAKE_AQC_OPCODE(NSE_AQ_OPC_CATEGORY_SWITCH,
						    NSE_AQ_OPC_UPDATE_LUT_NODE);
u16 nse_aqc_opc_vflr_event = MAKE_AQC_OPCODE(NSE_AQ_OPC_CATEGORY_BASIC, NSE_AQ_OPC_VFLR_EVENT);
u16 nse_aqc_opc_vflr_event_mini = MAKE_AQC_OPCODE(NSE_AQ_OPC_CATEGORY_BASIC,
						  NSE_AQ_OPC_VFLR_EVENT_MINI);
u16 nse_aqc_opc_lmac_phy_event = MAKE_AQC_OPCODE(NSE_AQ_OPC_CATEGORY_LMAC_PHY,
						 NSE_AQ_OPC_LMAC_PHY_EVENT);

static void
__nse_ctrlq_rq_handle_one_event(struct nse_pf *pf, struct nse_rq_event_info *event)
{
	struct device *dev = nse_pf_to_dev(pf);
	u16 opcode;

	opcode = le16_to_cpu(event->desc.opcode);

	/* Notify any thread that might be waiting for this event */
	nse_aq_check_events(pf, opcode, event);

	if (opcode == nse_aqc_opc_lmac_phy_event)
		nse_lmac_phy_handle_event(pf, event);
	else if (opcode == nse_aqc_opc_test_phy_lse)
		nse_test_phy_handle_link_event(pf, event);
	else if (opcode == nse_aqc_opc_ptp_tx_ts_event)
		nse_ptp_process_ts(pf, event);
	else if (opcode == nse_aqc_opc_event_lan_overflow)
		nse_vf_lan_overflow_event(pf, event);
	else if (opcode == nse_aqc_opc_send_msg_to_pf)
		nse_vc_process_vf_msg(pf, event);
	else if (opcode == nse_aqc_opc_qos_dcbx_cfg_chg_event)
		nse_dcb_process_dcbx_cfg_chg_event(pf, event);
	else if (opcode == nse_aqc_opc_dbg_ping_fw_rq_rsp)
		nse_aq_handle_dbg_ping_fw_rq_rsp(&pf->hw, event);
	else if (opcode == nse_aqc_opc_dbg_dummy_event)
		nse_aq_handle_dbg_dummy_event(&pf->hw, event);
	else if (opcode == nse_aqc_opc_fdir_reinit_event)
		nse_fdir_process_reinit_event(&pf->hw, event);
	else if (opcode == nse_aqc_opc_dma_get_cnt_event)
		nse_sw_stats_read_event(&pf->hw, event);
	else if (opcode == nse_aqc_opc_set_bmc_mac_event)
		nse_fltr_set_bmc_mac_event(&pf->hw, event);
	else if (opcode == nse_aqc_opc_vflr_event)
		nse_process_vflr_event(pf, event);
	else if (opcode == nse_aqc_opc_vflr_event_mini)
		nse_process_vflr_event_mini(pf, event);
	else
		dev_info(dev, "Receive Queue unknown event 0x%04x ignored\n", opcode);
}

/**
 * __nse_clean_ctrlq - helper function to clean controlq rings
 * @pf: ptr to struct nse_pf
 * @q_type: specific Control queue type
 */
static int __nse_clean_ctrlq_dflt(struct nse_pf *pf, enum nse_ctl_q q_type)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_rq_event_info event;
	struct nse_hw *hw = &pf->hw;
	struct nse_ctl_q_info *cq;
	u16 pending, i = 0;
	enum nse_status rq_ret;
	const char *qtype;
	u32 oldval, val;

	/* Do not clean control queue if/when PF reset fails */
	if (test_bit(NSE_RESET_FAILED, pf->state) || nse_is_reset_in_progress(pf->state))
		return 0;

	switch (q_type) {
	case NSE_CTL_Q_ADMIN:
		cq = &hw->adminq;
		qtype = "Admin";
		break;
	default:
		dev_warn(dev, "Unknown or Unsupported control queue type 0x%x\n", q_type);
		return 0;
	}

	/* check for error indications - PF_xx_AxQLEN register layout for
	 * FW/MBX/SB are identical so just use defines for PF_FW_AxQLEN.
	 */
	val = rd32(hw, cq->rq.len);
	if (val & (NSE_REG_PMBX_ARQLEN_VFE_M | NSE_REG_PMBX_ARQLEN_OVFL_M |
		   NSE_REG_PMBX_ARQLEN_CRIT_M)) {
		oldval = val;
		if (val & NSE_REG_PMBX_ARQLEN_VFE_M)
			dev_dbg(dev, "%s Receive Queue VF Error detected\n",
				qtype);
		if (val & NSE_REG_PMBX_ARQLEN_OVFL_M) {
			dev_dbg(dev, "%s Receive Queue Overflow Error detected\n",
				qtype);
		}
		if (val & NSE_REG_PMBX_ARQLEN_CRIT_M)
			dev_dbg(dev, "%s Receive Queue Critical Error detected\n",
				qtype);
		val &= ~(NSE_REG_PMBX_ARQLEN_VFE_M | NSE_REG_PMBX_ARQLEN_OVFL_M |
			 NSE_REG_PMBX_ARQLEN_CRIT_M);
		if (oldval != val)
			wr32(hw, cq->rq.len, val);
	}

	val = rd32(hw, cq->sq.len);
	if (val & (NSE_REG_PMBX_ATQLEN_VFE_M | NSE_REG_PMBX_ATQLEN_OVFL_M |
		   NSE_REG_PMBX_ATQLEN_CRIT_M)) {
		oldval = val;
		if (val & NSE_REG_PMBX_ATQLEN_VFE_M)
			dev_dbg(dev, "%s Send Queue VF Error detected\n",
				qtype);
		if (val & NSE_REG_PMBX_ATQLEN_OVFL_M) {
			dev_dbg(dev, "%s Send Queue Overflow Error detected\n",
				qtype);
		}
		if (val & NSE_REG_PMBX_ATQLEN_CRIT_M)
			dev_dbg(dev, "%s Send Queue Critical Error detected\n",
				qtype);
		val &= ~(NSE_REG_PMBX_ATQLEN_VFE_M | NSE_REG_PMBX_ATQLEN_OVFL_M |
			 NSE_REG_PMBX_ATQLEN_CRIT_M);
		if (oldval != val)
			wr32(hw, cq->sq.len, val);
	}

	memset(&event, 0, sizeof(event));

	event.buf_len = cq->rq_buf_size;
	event.msg_buf = kzalloc(event.buf_len, GFP_KERNEL);
	if (!event.msg_buf)
		return 0;

	do {
		rq_ret = nse_clean_rq_elem(hw, cq, &event, &pending);
		if (rq_ret == NSE_ERR_AQ_NO_WORK)
			break;
		if (rq_ret) {
			dev_err(dev, "%s Receive Queue event error %s\n", qtype,
				nse_stat_str(rq_ret));
			break;
		}

		if (nse_is_reset_in_progress(pf->state))
			break;

		__nse_ctrlq_rq_handle_one_event(pf, &event);

	} while (pending && (i++ < NSE_DFLT_IRQ_WORK));

	kfree(event.msg_buf);

	return pending && (i == NSE_DFLT_IRQ_WORK);
}

static inline bool nse_rq_evt_is_need_ll(u16 opc)
{
	if (opc == nse_aqc_opc_ptp_tx_ts_event)
		return true;

	return false;
}

int __nse_clean_ctrlq_rq_in_bh(struct nse_pf *pf, enum nse_ctl_q q_type)
{
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_rq_event_info *event = NULL;
	struct nse_ctl_q_info *cq;
	u16 pending, i = 0;
	enum nse_status rq_ret;
	u16 opcode;

	/* Do not clean control queue if/when PF reset fails */
	if (test_bit(NSE_RESET_FAILED, pf->state) || nse_is_reset_in_progress(pf->state))
		return 0;

	switch (q_type) {
	case NSE_CTL_Q_ADMIN:
		cq = &hw->adminq;
		break;
	default:
		dev_warn(dev, "[%s]: Unknown or Unsupported control queue type 0x%x\n",
			 __func__, q_type);
		return 0;
	}

	do {
		event = kzalloc(sizeof(*event), GFP_ATOMIC);
		if (!event)
			break;

		event->buf_len = cq->rq_buf_size;
		event->msg_buf = kzalloc(event->buf_len, GFP_ATOMIC);
		if (!event->msg_buf)
			break;

		INIT_LIST_HEAD(&event->list);

		rq_ret = nse_clean_rq_elem(hw, cq, event, &pending);
		if (rq_ret == NSE_ERR_AQ_NO_WORK)
			break;
		if (rq_ret) {
			dev_warn(dev, "[%s]: Receive Queue event error %s\n",
				 __func__, nse_stat_str(rq_ret));
			break;
		}

		if (nse_is_reset_in_progress(pf->state))
			break;

		opcode = le16_to_cpu(event->desc.opcode);

		if (nse_rq_evt_is_need_ll(opcode)) {
			nse_debug(hw, NSE_DBG_AQM_MSG, "[%s] receive ll rq_evt (%X)\n",
				  __func__, opcode);

			/* Notify any thread that might be waiting for this event */
			nse_aq_check_events(pf, opcode, event);

			if (opcode == nse_aqc_opc_ptp_tx_ts_event) {
				nse_ptp_process_ts(pf, event);

			} else {
				nse_debug(hw, NSE_DBG_AQM_MSG,
					  "\t [%s] ignore unknown ll rq_evt (%X)\n",
					__func__, opcode);
			}

			/* consumed */
			kfree(event);
		} else {
			spin_lock_bh(&cq->rq_evt_list_lock);
			list_add_tail(&event->list, &cq->rq_evt_list);
			spin_unlock_bh(&cq->rq_evt_list_lock);

			/* consider consumed */
		}

		event = NULL;

	} while (pending && (i++ < NSE_DFLT_IRQ_WORK));

	if (event) {
		kfree(event->msg_buf);

		kfree(event);
	}

	return pending && (i == NSE_DFLT_IRQ_WORK);
}

int __nse_clean_ctrlq_rq_in_task(struct nse_pf *pf, enum nse_ctl_q q_type)
{
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_rq_event_info *event = NULL;
	struct nse_ctl_q_info *cq;
	struct list_head tmp_rq_evt_list;
	bool skip_actual_handling = false;
	const char *qtype;
	u32 oldval, val;

	switch (q_type) {
	case NSE_CTL_Q_ADMIN:
		cq = &hw->adminq;
		qtype = "Admin";
		break;
	default:
		dev_warn(dev, "[%s]: Unknown or Unsupported control queue type 0x%x\n",
			 __func__, q_type);
		return 0;
	}

	INIT_LIST_HEAD(&tmp_rq_evt_list);

	spin_lock_bh(&cq->rq_evt_list_lock);
	list_splice_init(&cq->rq_evt_list, &tmp_rq_evt_list);
	spin_unlock_bh(&cq->rq_evt_list_lock);

	/* Do not clean control queue if/when PF reset fails */
	if (test_bit(NSE_RESET_FAILED, pf->state) || nse_is_reset_in_progress(pf->state)) {
		skip_actual_handling = true;
		goto handle_rq_evt_list;
	}

	/* check for error indications - PF_xx_AxQLEN register layout for
	 * FW/MBX/SB are identical so just use defines for PF_FW_AxQLEN.
	 */
	val = rd32(hw, cq->rq.len);
	if (val & (NSE_REG_PMBX_ARQLEN_VFE_M | NSE_REG_PMBX_ARQLEN_OVFL_M |
		   NSE_REG_PMBX_ARQLEN_CRIT_M)) {
		oldval = val;
		if (val & NSE_REG_PMBX_ARQLEN_VFE_M)
			dev_dbg(dev, "%s Receive Queue VF Error detected\n",
				qtype);
		if (val & NSE_REG_PMBX_ARQLEN_OVFL_M) {
			dev_dbg(dev, "%s Receive Queue Overflow Error detected\n",
				qtype);
		}
		if (val & NSE_REG_PMBX_ARQLEN_CRIT_M)
			dev_dbg(dev, "%s Receive Queue Critical Error detected\n",
				qtype);
		val &= ~(NSE_REG_PMBX_ARQLEN_VFE_M | NSE_REG_PMBX_ARQLEN_OVFL_M |
			 NSE_REG_PMBX_ARQLEN_CRIT_M);
		if (oldval != val)
			wr32(hw, cq->rq.len, val);
	}

	val = rd32(hw, cq->sq.len);
	if (val & (NSE_REG_PMBX_ATQLEN_VFE_M | NSE_REG_PMBX_ATQLEN_OVFL_M |
		   NSE_REG_PMBX_ATQLEN_CRIT_M)) {
		oldval = val;
		if (val & NSE_REG_PMBX_ATQLEN_VFE_M)
			dev_dbg(dev, "%s Send Queue VF Error detected\n",
				qtype);
		if (val & NSE_REG_PMBX_ATQLEN_OVFL_M) {
			dev_dbg(dev, "%s Send Queue Overflow Error detected\n",
				qtype);
		}
		if (val & NSE_REG_PMBX_ATQLEN_CRIT_M)
			dev_dbg(dev, "%s Send Queue Critical Error detected\n",
				qtype);
		val &= ~(NSE_REG_PMBX_ATQLEN_VFE_M | NSE_REG_PMBX_ATQLEN_OVFL_M |
			 NSE_REG_PMBX_ATQLEN_CRIT_M);
		if (oldval != val)
			wr32(hw, cq->sq.len, val);
	}

handle_rq_evt_list:

	while (!list_empty(&tmp_rq_evt_list)) {
		event = list_first_entry(&tmp_rq_evt_list, struct nse_rq_event_info, list);

		list_del_init(&event->list);

		if (nse_is_reset_in_progress(pf->state))
			skip_actual_handling = true;

		if (!skip_actual_handling)
			__nse_ctrlq_rq_handle_one_event(pf, event);

		kfree(event->msg_buf);
		kfree(event);
	}

	return !list_empty_careful(&cq->rq_evt_list);
}

static bool nse_ctrlq_rq_pending_in_bh(struct nse_ctl_q_info *cq)
{
	return !list_empty_careful(&cq->rq_evt_list);
}

static void nse_ctrlq_rq_flush_bh(struct nse_ctl_q_info *cq)
{
	struct nse_rq_event_info *event = NULL;

	spin_lock_bh(&cq->rq_evt_list_lock);

	while (!list_empty(&cq->rq_evt_list)) {
		event = list_first_entry(&cq->rq_evt_list, struct nse_rq_event_info, list);

		list_del_init(&event->list);

		kfree(event->msg_buf);
		kfree(event);
	}

	spin_unlock_bh(&cq->rq_evt_list_lock);
}

/**
 * nse_ctrlq_pending - check if there is a difference between ntc and ntu
 * @hw: pointer to hardware info
 * @cq: control queue information
 *
 * returns true if there are pending messages in a queue, false if there aren't
 */
static bool nse_ctrlq_pending(struct nse_hw *hw, struct nse_ctl_q_info *cq)
{
	u32 rq_head;
	u16 ntu;

	rq_head = rd32(hw, cq->rq.head);
	if (nse_is_regval_reset_magic(rq_head))
		return false;

	ntu = (u16)(rq_head & cq->rq.head_mask);
	return cq->rq.next_to_clean != ntu;
}

/**
 * nse_clean_adminq_subtask - clean the AdminQ rings
 * @pf: board private structure
 */
static void nse_clean_adminq_subtask(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;

	if (!test_bit(NSE_ADMINQ_EVENT_PENDING, pf->state))
		return;

	if (nse_aq_rq_rx_method) {
		if (__nse_clean_ctrlq_rq_in_task(pf, NSE_CTL_Q_ADMIN))
			return;

		clear_bit(NSE_ADMINQ_EVENT_PENDING, pf->state);

		if (nse_ctrlq_rq_pending_in_bh(&hw->adminq))
			__nse_clean_ctrlq_rq_in_task(pf, NSE_CTL_Q_ADMIN);
	} else {
		if (__nse_clean_ctrlq_dflt(pf, NSE_CTL_Q_ADMIN))
			return;

		clear_bit(NSE_ADMINQ_EVENT_PENDING, pf->state);

		/* There might be a situation where new messages arrive to a control
		 * queue between processing the last message and clearing the
		 * EVENT_PENDING bit. So before exiting, check queue head again (using
		 * nse_ctrlq_pending) and process new messages if any.
		 */
		if (nse_ctrlq_pending(hw, &hw->adminq))
			__nse_clean_ctrlq_dflt(pf, NSE_CTL_Q_ADMIN);
	}
}

/**
 * nse_service_task_schedule - schedule the service task to wake up
 * @pf: board private structure
 *
 * If not already scheduled, this puts the task into the work queue.
 */
void nse_service_task_schedule(struct nse_pf *pf)
{
	if (!test_bit(NSE_SERVICE_DIS, pf->state) &&
	    !test_and_set_bit(NSE_SERVICE_SCHED, pf->state) &&
	    !test_bit(NSE_NEEDS_RESTART, pf->state))
		queue_work(nse_wq, &pf->serv_task);
}

/**
 * nse_service_task_complete - finish up the service task
 * @pf: board private structure
 */
static void nse_service_task_complete(struct nse_pf *pf)
{
	WARN_ON(!test_bit(NSE_SERVICE_SCHED, pf->state));

	/* force memory (pf->state) to sync before next service task */
	smp_mb__before_atomic();
	clear_bit(NSE_SERVICE_SCHED, pf->state);
}

/**
 * nse_service_task_stop - stop service task and cancel works
 * @pf: board private structure
 *
 * Return 0 if the NSE_SERVICE_DIS bit was not already set,
 * 1 otherwise.
 */
static int nse_service_task_stop(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;
	int ret;

	ret = test_and_set_bit(NSE_SERVICE_DIS, pf->state);

	if (pf->serv_tmr.function)
		del_timer_sync(&pf->serv_tmr);
	if (nse_aq_rq_rx_method && pf->serv_bh.func) {
		tasklet_kill(&pf->serv_bh);
		nse_ctrlq_rq_flush_bh(&hw->adminq);
	}
	if (pf->serv_task.func)
		cancel_work_sync(&pf->serv_task);

	clear_bit(NSE_SERVICE_SCHED, pf->state);
	return ret;
}

/**
 * nse_service_task_restart - restart service task and schedule works
 * @pf: board private structure
 *
 * This function is needed for suspend and resume works (e.g WoL scenario)
 */
static void nse_service_task_restart(struct nse_pf *pf)
{
	clear_bit(NSE_SERVICE_DIS, pf->state);
	nse_service_task_schedule(pf);
}

/**
 * nse_service_timer - timer callback to schedule service task
 * @t: pointer to timer_list
 */
static void nse_service_timer(struct timer_list *t)
{
	struct nse_pf *pf = from_timer(pf, t, serv_tmr);

	pf->serv_tmr_run_cnt++;

	mod_timer(&pf->serv_tmr, round_jiffies(pf->serv_tmr_period + jiffies));
	nse_service_task_schedule(pf);
}

static void nse_polling_timer(struct timer_list *t)
{
	struct nse_pf *pf = from_timer(pf, t, polling_tmr);
	unsigned long next_event_offset = HZ / 1000;
	struct nse_vsi *vsi;
	struct nse_vsi *ctrl_vsi = pf->switchdev.control_vsi;
	int q_idx;
	int budget;
	int poll_cnt;

	mod_timer(&pf->polling_tmr, round_jiffies(next_event_offset + jiffies));

	if (nse_is_reset_in_progress(pf->state) ||
	    test_bit(NSE_SUSPENDED, pf->state) ||
	    test_bit(NSE_NEEDS_RESTART, pf->state) ||
	    test_bit(NSE_DOWN, pf->state)
	    ) {
		return;
	}

	vsi = nse_get_main_vsi(pf);
	if (!vsi)
		return;

	nse_for_each_q_vector(vsi, q_idx) {
		struct nse_q_vector *q_vector = vsi->q_vectors[q_idx];

		if (q_vector == NULL)
			return;

		poll_cnt = 0;
		do {
			budget = nse_polling(q_vector, 64);
			poll_cnt++;
//			printk("-----polling one time----\n");
		} while ((budget == 64) && (poll_cnt < 100));
	}

	if (ctrl_vsi == NULL)
		return;

	nse_for_each_q_vector(ctrl_vsi, q_idx) {
		struct nse_q_vector *qvector = ctrl_vsi->q_vectors[q_idx];

		if (qvector == NULL)
			return;

		poll_cnt = 0;
		do {
			budget = nse_polling(qvector, 64);
			poll_cnt++;
//			printk("-----polling one time----\n");
		} while ((budget == 64) && (poll_cnt < 100));
	}
}

/**
 * nse_service_task - manage and run subtasks
 * @work: pointer to work_struct contained by the PF struct
 */
static void nse_service_task(struct work_struct *work)
{
	struct nse_pf *pf = container_of(work, struct nse_pf, serv_task);
	unsigned long start_time = jiffies;

	pf->serv_task_run_cnt++;

	/* subtasks */

	/* process reset requests first */
	nse_reset_subtask(pf);

	/* bail if a reset/recovery cycle is pending or rebuild failed */
	if (nse_is_reset_in_progress(pf->state) ||
	    test_bit(NSE_SUSPENDED, pf->state) ||
	    test_bit(NSE_NEEDS_RESTART, pf->state)) {
		nse_service_task_complete(pf);
		return;
	}

	if (test_and_clear_bit(NSE_FLAG_MTU_CHANGED, pf->flags)) {
		struct iidc_event *event;

		event = kzalloc(sizeof(*event), GFP_KERNEL);
		if (event) {
			set_bit(IIDC_EVENT_AFTER_MTU_CHANGE, event->type);
			nse_send_event_to_auxs(pf, event);
			kfree(event);
		}
	}

	if (test_and_clear_bit(NSE_FLAG_UNPLUG_AUX_DEV, pf->flags))
		nse_unplug_aux_devs(pf, 0, 1);

	if (test_and_clear_bit(NSE_FLAG_PLUG_AUX_DEV, pf->flags))
		nse_plug_aux_devs(pf);

	nse_clean_adminq_subtask(pf);

	nse_msgbox_clean_v2p_subtask(pf);

	nse_sync_fltr_subtask(pf);

	nse_lmac_phy_subtask(pf);

	nse_misc_subtask(pf);

	nse_watchdog_subtask(pf);

	/* Clear NSE_SERVICE_SCHED flag to allow scheduling next event */
	nse_service_task_complete(pf);

	/* If the tasks have taken longer than one service timer period
	 * or there is more work to be done, reset the service timer to
	 * schedule the service task now.
	 */
	if (time_after(jiffies, (start_time + pf->serv_tmr_period)) ||
	    test_bit(NSE_MDD_EVENT_PENDING, pf->state) ||
	    test_bit(NSE_ADMINQ_EVENT_PENDING, pf->state)) {
		pf->serv_task_resched_imm_cnt++;

		mod_timer(&pf->serv_tmr, jiffies);
	}
}

static void nse_service_bh(struct tasklet_struct *task)
{
	struct nse_pf *pf = from_tasklet(pf, task, serv_bh);
	struct nse_hw *hw = &pf->hw;
	int aq_rq_more = 0;

	pf->serv_bh_run_cnt++;

	if (!nse_aq_rq_rx_method ||
		nse_is_reset_in_progress(pf->state))
		return;

	aq_rq_more = __nse_clean_ctrlq_rq_in_bh(pf, NSE_CTL_Q_ADMIN);

	if (nse_ctrlq_rq_pending_in_bh(&hw->adminq))
		set_bit(NSE_ADMINQ_EVENT_PENDING, pf->state);

	/* more to handle in next BH round */
	if (aq_rq_more)
		tasklet_schedule(&pf->serv_bh);
}

/**
 * nse_set_ctrlq_len - helper function to set controlq length
 * @hw: pointer to the HW instance
 */
static void nse_set_ctrlq_len(struct nse_hw *hw)
{
	hw->adminq.num_rq_entries = NSE_ADMINQ_RQ_LEN;
	hw->adminq.num_sq_entries = NSE_ADMINQ_SQ_LEN;
	hw->adminq.rq_buf_size = NSE_AQ_MAX_BUF_LEN;
	hw->adminq.sq_buf_size = NSE_AQ_MAX_BUF_LEN;
}

/**
 * nse_schedule_reset - schedule a reset
 * @pf: board private structure
 * @reset: reset being requested
 */
int nse_schedule_reset(struct nse_pf *pf, enum nse_reset_req reset)
{
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);

	nse_debug(hw, NSE_DBG_SYS, "[%s] reset_req=%d\n", __func__, reset);

	/* bail out if earlier reset has failed */
	if (test_bit(NSE_RESET_FAILED, pf->state)) {
		dev_err(dev, "[%s, %d] earlier reset has failed\n", __func__, __LINE__);
		return -EIO;
	}
	/* bail if reset/recovery already in progress */
	if (nse_is_reset_in_progress(pf->state)) {
		dev_warn(dev, "[%s, %d] Reset already in progress\n", __func__, __LINE__);
		return -EBUSY;
	}

	switch (reset) {
	case NSE_RESET_PFR:
		dev_info(dev, "[%s, %d] schedule reset=PFR\n", __func__, __LINE__);
		set_bit(NSE_PFR_REQ, pf->state);
		break;

	case NSE_RESET_HIGH_RESET_CORER:
		dev_info(dev, "[%s, %d] schedule reset=CORER\n", __func__, __LINE__);
		set_bit(NSE_HIGH_RESET_CORER_REQ, pf->state);
		break;

	default:
		dev_err(dev, "[%s, %d] unsupported reset_req=%d\n", __func__, __LINE__, reset);
		return -EINVAL;
	}

	nse_service_task_schedule(pf);
	return 0;
}

/**
 * nse_irq_affinity_notify - Callback for affinity changes
 * @notify: context as to what irq was changed
 * @mask: the new affinity mask
 *
 * This is a callback function used by the irq_set_affinity_notifier function
 * so that we may register to receive changes to the irq affinity masks.
 */
static void
nse_irq_affinity_notify(struct irq_affinity_notify *notify,
			const cpumask_t *mask)
{
	struct nse_q_vector *q_vector =
		container_of(notify, struct nse_q_vector, affinity_notify);

	cpumask_copy(&q_vector->affinity_mask, mask);
}

/**
 * nse_irq_affinity_release - Callback for affinity notifier release
 * @ref: internal core kernel usage
 *
 * This is a callback function used by the irq_set_affinity_notifier function
 * to inform the current notification subscriber that they will no longer
 * receive notifications.
 */
static void nse_irq_affinity_release(struct kref __always_unused *ref) {}

/**
 * nse_vsi_ena_irq - Enable IRQ for the given VSI
 * @vsi: the VSI being configured
 */
static int nse_vsi_ena_irq(struct nse_vsi *vsi)
{
	struct nse_hw *hw = &vsi->back->hw;
	int i;

	nse_for_each_q_vector(vsi, i)
		nse_irq_dynamic_ena(hw, vsi, vsi->q_vectors[i]);

	nse_flush(hw);
	return 0;
}

/**
 * nse_vsi_req_irq_msix - get MSI-X vectors from the OS for the VSI
 * @vsi: the VSI being configured
 * @basename: name for the vector
 */
static int nse_vsi_req_irq_msix(struct nse_vsi *vsi, char *basename)
{
	int q_vectors = vsi->num_q_vectors;
	struct nse_pf *pf = vsi->back;
	int base = vsi->base_vector;
	struct device *dev = nse_pf_to_dev(pf);
	int rx_int_idx = 0;
	int tx_int_idx = 0;
	int vector, err;
	int irq_num;
	int cpu;

	if (nse_no_irq)
		return 0;

	for (vector = 0; vector < q_vectors; vector++) {
		struct nse_q_vector *q_vector = vsi->q_vectors[vector];

		irq_num = nse_get_irq_num(pf, base + vector);

		if (q_vector->tx.ring && q_vector->rx.ring) {
			if (q_vector->num_ring_rx == 1) {
				snprintf(q_vector->name,
					 sizeof(q_vector->name) - 1,
					 "%s-%s-%d", basename, "TxRx",
					 rx_int_idx++);
					 tx_int_idx++;
			} else {
				int num_rx = q_vector->num_ring_rx;

				snprintf(q_vector->name,
					 sizeof(q_vector->name) - 1,
					 "%s-%s-%d-%d", basename, "TxRx",
					 rx_int_idx, rx_int_idx + num_rx - 1);
					 rx_int_idx = rx_int_idx + num_rx;
					 tx_int_idx = rx_int_idx;
			}
		} else if (q_vector->rx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%d", basename, "Rx", rx_int_idx++);
		} else if (q_vector->tx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%d", basename, "Tx", tx_int_idx++);
		} else {
			/* skip this unused q_vector */
			continue;
		}

		err = devm_request_irq(dev, irq_num, vsi->irq_handler,
					       0, q_vector->name, q_vector);
		if (err) {
			netdev_err(vsi->netdev, "MSIX request_irq failed, error: %d\n",
				   err);
			goto free_q_irqs;
		}

		/* register for affinity change notifications */
		q_vector->affinity_notify.notify = nse_irq_affinity_notify;
		q_vector->affinity_notify.release = nse_irq_affinity_release;
		irq_set_affinity_notifier(irq_num, &q_vector->affinity_notify);

		/* assign the mask for this irq */
		cpu = cpumask_local_spread(q_vector->v_idx, -1);
		irq_set_affinity_hint(irq_num, get_cpu_mask(cpu));
	}

	vsi->irqs_ready = true;
	return 0;

free_q_irqs:
	while (vector) {
		vector--;
		irq_num = nse_get_irq_num(pf, base + vector);

		irq_set_affinity_notifier(irq_num, NULL);
		irq_set_affinity_hint(irq_num, NULL);

		devm_free_irq(dev, irq_num, &vsi->q_vectors[vector]);
	}
	return err;
}

/**
 * nse_xdp_alloc_setup_rings - Allocate and setup Tx rings for XDP
 * @vsi: VSI to setup Tx rings used by XDP
 *
 * Return 0 on success and negative value on error
 */
static int nse_xdp_alloc_setup_rings(struct nse_vsi *vsi)
{
	struct device *dev = nse_pf_to_dev(vsi->back);
	int i;

	for (i = 0; i < vsi->num_xdp_txq; i++) {
		u16 xdp_q_idx = vsi->alloc_txq + i;
		struct nse_ring *xdp_ring;

		xdp_ring = kzalloc(sizeof(*xdp_ring), GFP_KERNEL);

		if (!xdp_ring)
			goto free_xdp_rings;

		xdp_ring->q_index = xdp_q_idx;
		xdp_ring->reg_idx = vsi->vsi_xdp_txq_start + i;
		xdp_ring->abs_id = xdp_ring->reg_idx + vsi->back->lan_txq_space_start;
		xdp_ring->vsi = vsi;
		xdp_ring->netdev = NULL;
		xdp_ring->dev = dev;
		xdp_ring->count = vsi->num_tx_desc;
		WRITE_ONCE(vsi->xdp_rings[i], xdp_ring);
		if (nse_setup_tx_ring(xdp_ring))
			goto free_xdp_rings;
		nse_set_ring_xdp(xdp_ring);
		xdp_ring->xsk_pool = nse_xsk_umem(xdp_ring);
	}

	return 0;

free_xdp_rings:
	for (; i >= 0; i--)
		if (vsi->xdp_rings[i] && vsi->xdp_rings[i]->desc)
			nse_free_tx_ring(vsi->xdp_rings[i]);
	return -ENOMEM;
}

/**
 * nse_vsi_assign_bpf_prog - set or clear bpf prog pointer on VSI
 * @vsi: VSI to set the bpf prog on
 * @prog: the bpf prog pointer
 */
static void nse_vsi_assign_bpf_prog(struct nse_vsi *vsi, struct bpf_prog *prog)
{
	struct bpf_prog *old_prog;
	int i;

	old_prog = xchg(&vsi->xdp_prog, prog);
	if (old_prog && old_prog != prog)
		bpf_prog_put(old_prog);

	nse_for_each_rxq(vsi, i)
		WRITE_ONCE(vsi->rx_rings[i]->xdp_prog, vsi->xdp_prog);
}

#ifdef NSE_ADD_PROBES
/**
 * nse_clear_xdp_stats - clear all Rx XDP statistics on VSI
 * @vsi: VSI to clear Rx XDP statistics on
 */
static void nse_clear_xdp_stats(struct nse_vsi *vsi)
{
	int i;
	struct nse_ring *ring;

	nse_for_each_alloc_rxq(vsi, i) {
		ring = vsi->rx_rings[i];
		if (ring)
			memset(&ring->xdp_stats, 0, sizeof(ring->xdp_stats));
	}
}
#endif /* NSE_ADD_PROBES */

/**
 * nse_prepare_xdp_rings - Allocate, configure and setup Tx rings for XDP
 * @vsi: VSI to bring up Tx rings used by XDP
 * @prog: bpf program that will be assigned to VSI
 *
 * Return 0 on success and negative value on error
 */
int nse_prepare_xdp_rings(struct nse_vsi *vsi, struct bpf_prog *prog)
{
	u16 max_txqs[NSE_MAX_TRAFFIC_CLASS] = { 0 };
	int xdp_rings_rem = vsi->num_xdp_txq;
	struct nse_pf *pf = vsi->back;
	enum nse_status status;
	struct device *dev = nse_pf_to_dev(pf);
	int i, v_idx;
	u16 xdp_txq_owner_id;
	int ret = 0;

	/* init this field in advanced */
	vsi->vsi_xdp_txq_start = NSE_INVAL_Q_ID;

	/* determine xdp_txq_owner_id, which is gonna be used in lan_txq_tracker */
	if (vsi->type != NSE_VSI_PF || nse_nonvf_vsi_lan_txq_res_owner_id(vsi,
	    true, &xdp_txq_owner_id)) {
		ret = -EOPNOTSUPP;
		goto err;
	}

	/* request num_xdp_txq from lan_txq_tracker */
	mutex_lock(&pf->lan_txq_tracker_mutex);

	ret = nse_get_res(pf, pf->lan_txq_tracker, vsi->num_xdp_txq, xdp_txq_owner_id);

	if (ret < 0) {
		mutex_unlock(&pf->lan_txq_tracker_mutex);
		goto err;
	}

	mutex_unlock(&pf->lan_txq_tracker_mutex);

	vsi->vsi_xdp_txq_start = ret;
	vsi->xdp_txq_owner_id = xdp_txq_owner_id;

	/* allocate xdp_rings[] array */
	vsi->xdp_rings = devm_kcalloc(dev, vsi->num_xdp_txq,
				      sizeof(*vsi->xdp_rings), GFP_KERNEL);
	if (!vsi->xdp_rings) {
		ret = -ENOMEM;
		goto err_release_tracker;
	}

	/* allocate elements in xdp_rings[] */
	if (nse_xdp_alloc_setup_rings(vsi))
		goto clear_xdp_rings;

	/* follow the logic from nse_vsi_map_rings_to_vectors */
	nse_for_each_q_vector(vsi, v_idx) {
		struct nse_q_vector *q_vector = vsi->q_vectors[v_idx];
		int xdp_rings_per_v, q_id, q_base;

		xdp_rings_per_v = DIV_ROUND_UP(xdp_rings_rem,
					       vsi->num_q_vectors - v_idx);
		q_base = vsi->num_xdp_txq - xdp_rings_rem;

		for (q_id = q_base; q_id < (q_base + xdp_rings_per_v); q_id++) {
			struct nse_ring *xdp_ring = vsi->xdp_rings[q_id];

			xdp_ring->q_vector = q_vector;
			xdp_ring->next = q_vector->tx.ring;
			q_vector->tx.ring = xdp_ring;
		}
		xdp_rings_rem -= xdp_rings_per_v;
	}

	/* omit the scheduler update if in reset path; XDP queues will be
	 * taken into account at the end of nse_vsi_rebuild, where
	 * nse_cfg_vsi_lan is being called
	 */
	if (nse_is_reset_in_progress(pf->state))
		return 0;

	/* tell the Tx scheduler that right now we have
	 * additional queues
	 */
	for (i = 0; i < vsi->tc_cfg.numtc; i++)
		max_txqs[i] = vsi->num_txq + vsi->num_xdp_txq;

	status = nse_cfg_vsi_lan(vsi->port_info, vsi->idx, vsi->tc_cfg.ena_tc,
				 max_txqs);
	if (status) {
		dev_err(dev, "FAIL: cfg_vsi_lan(), for XDP_tx_ring, error: %d(%s)\n",
						status, nse_stat_str(status));
		goto clear_xdp_rings;
	}

	nse_vsi_assign_bpf_prog(vsi, prog);

	return 0;	//ret = 0

clear_xdp_rings:

	for (i = 0; i < vsi->num_xdp_txq; i++)
		if (vsi->xdp_rings[i]) {
			kfree_rcu(vsi->xdp_rings[i], rcu);
			vsi->xdp_rings[i] = NULL;
		}

	if (vsi->xdp_rings) {
		devm_kfree(dev, vsi->xdp_rings);
		vsi->xdp_rings = NULL;
	}

err_release_tracker:
	if (vsi->vsi_xdp_txq_start != NSE_INVAL_Q_ID) {
		mutex_lock(&pf->lan_txq_tracker_mutex);

		(void)nse_free_res(pf->lan_txq_tracker, vsi->vsi_xdp_txq_start, xdp_txq_owner_id);

		mutex_unlock(&pf->lan_txq_tracker_mutex);
	}

err:
	/* reset these fields */
	vsi->num_xdp_txq = 0;
	vsi->vsi_xdp_txq_start = NSE_INVAL_Q_ID;
	vsi->xdp_txq_owner_id = 0;	//agly, should define a invalid value.

	return ret;
}

/**
 * nse_destroy_xdp_rings - undo the configuration made by nse_prepare_xdp_rings
 * @vsi: VSI to remove XDP rings
 *
 * Detach XDP rings from irq vectors, clean up the PF bitmap and free
 * resources
 */
int nse_destroy_xdp_rings(struct nse_vsi *vsi)
{
	u16 max_txqs[NSE_MAX_TRAFFIC_CLASS] = { 0 };
	struct nse_pf *pf = vsi->back;
	int i, v_idx;

	if (vsi->type != NSE_VSI_PF)	/* in PF driver, only PF-main-VSI support XDP */
		return 0;

	/* q_vectors are freed in reset path so there's no point in detaching
	 * rings; in case of rebuild being triggered not from reset bits
	 * in pf->state won't be set, so additionally check first q_vector
	 * against NULL
	 */
	if (nse_is_reset_in_progress(pf->state) || !vsi->q_vectors[0])
		goto free_qmap;

	nse_for_each_q_vector(vsi, v_idx) {
		struct nse_q_vector *q_vector = vsi->q_vectors[v_idx];
		struct nse_ring *ring;

		nse_for_each_ring(ring, q_vector->tx)
			if (!ring->tx_buf || !nse_ring_is_xdp(ring))
				break;

		/* restore the value of last node prior to XDP setup */
		q_vector->tx.ring = ring;
	}

free_qmap:

	if (vsi->vsi_xdp_txq_start != NSE_INVAL_Q_ID &&
	    vsi->xdp_txq_owner_id == NSE_RES_LAN_TXQ_ID_PF_XDP) {
		mutex_lock(&pf->lan_txq_tracker_mutex);

		(void)nse_free_res(pf->lan_txq_tracker, vsi->vsi_xdp_txq_start,
				   vsi->xdp_txq_owner_id);

		mutex_unlock(&pf->lan_txq_tracker_mutex);

		/* reset these fields */
		vsi->vsi_xdp_txq_start = NSE_INVAL_Q_ID;
		vsi->xdp_txq_owner_id = 0;	//agly, should define a invalid value.
	}

	for (i = 0; i < vsi->num_xdp_txq; i++)
		if (vsi->xdp_rings[i]) {
			if (vsi->xdp_rings[i]->desc)
				nse_free_tx_ring(vsi->xdp_rings[i]);
			kfree_rcu(vsi->xdp_rings[i], rcu);
			vsi->xdp_rings[i] = NULL;
		}

	devm_kfree(nse_pf_to_dev(pf), vsi->xdp_rings);
	vsi->xdp_rings = NULL;

	if (nse_is_reset_in_progress(pf->state) || !vsi->q_vectors[0])
		return 0;

	nse_vsi_assign_bpf_prog(vsi, NULL);

	/* notify Tx scheduler that we destroyed XDP queues and bring
	 * back the old number of child nodes
	 */
	for (i = 0; i < vsi->tc_cfg.numtc; i++)
		max_txqs[i] = vsi->num_txq;

	/* change number of XDP Tx queues to 0 */
	vsi->num_xdp_txq = 0;

	return nse_cfg_vsi_lan(vsi->port_info, vsi->idx, vsi->tc_cfg.ena_tc,
			       max_txqs);
}

/**
 * nse_vsi_rx_napi_schedule - Schedule napi on RX queues from VSI
 * @vsi: VSI to schedule napi on
 */
static void nse_vsi_rx_napi_schedule(struct nse_vsi *vsi)
{
	int i;

	nse_for_each_rxq(vsi, i) {
		struct nse_ring *rx_ring = vsi->rx_rings[i];

		if (rx_ring->xsk_pool)
			napi_schedule(&rx_ring->q_vector->napi);
	}
}

/**
 * nse_xdp_setup_prog - Add or remove XDP eBPF program
 * @vsi: VSI to setup XDP for
 * @prog: XDP program
 * @extack: netlink extended ack
 */
static int
nse_xdp_setup_prog(struct nse_vsi *vsi, struct bpf_prog *prog,
		   struct netlink_ext_ack *extack)
{
	int frame_size = vsi->netdev->mtu + ETH_HLEN + ETH_FCS_LEN + VLAN_HLEN;
	bool if_up = (vsi->netdev->flags & IFF_UP);
	int ret = 0, xdp_ring_err = 0;

	if (frame_size > vsi->rx_buf_len) {
		NL_SET_ERR_MSG_MOD(extack, "MTU too large for loading XDP");
		return -EOPNOTSUPP;
	}

	if (vsi->netdev->features & NETIF_F_LRO) {
		NL_SET_ERR_MSG_MOD(extack, "LRO is enabled on netdev, disable it first.\n");
		return -EOPNOTSUPP;
	}

	/* need to stop netdev while setting up the program for Rx rings */
	if (if_up && !test_and_set_bit(NSE_VSI_DOWN, vsi->state)) {
		ret = nse_down(vsi);
		if (ret) {
			NL_SET_ERR_MSG_MOD(extack, "Preparing device for XDP attach failed");
			return ret;
		}
	}

	if (!nse_is_xdp_ena_vsi(vsi) && prog) {
		vsi->num_xdp_txq = vsi->alloc_rxq;
		xdp_ring_err = nse_prepare_xdp_rings(vsi, prog);
		if (xdp_ring_err)
			NL_SET_ERR_MSG_MOD(extack, "Setting up XDP Tx resources failed");
#ifdef NSE_ADD_PROBES
		nse_clear_xdp_stats(vsi);
#endif /* NSE_ADD_PROBES */
	} else if (nse_is_xdp_ena_vsi(vsi) && !prog) {
		xdp_ring_err = nse_destroy_xdp_rings(vsi);
		if (xdp_ring_err)
			NL_SET_ERR_MSG_MOD(extack, "Freeing XDP Tx resources failed");
	} else {
		nse_vsi_assign_bpf_prog(vsi, prog);
	}

	if (if_up)
		ret = nse_up(vsi);

	if (!ret && prog)
		nse_vsi_rx_napi_schedule(vsi);

	return (ret || xdp_ring_err) ? -ENOMEM : 0;
}

/**
 * nse_xdp - implements XDP handler
 * @dev: netdevice
 * @xdp: XDP command
 */
static int nse_xdp(struct net_device *dev, struct netdev_bpf *xdp)
{
	struct nse_netdev_priv *np = netdev_priv(dev);
	struct nse_vsi *vsi = np->vsi;

	if (vsi->type != NSE_VSI_PF) {
		NL_SET_ERR_MSG_MOD(xdp->extack, "XDP can be loaded only on PF VSI");
		return -EINVAL;
	}

	switch (xdp->command) {
	case XDP_SETUP_PROG:
		return nse_xdp_setup_prog(vsi, xdp->prog, xdp->extack);
	case XDP_SETUP_XSK_POOL:
		return nse_xsk_umem_setup(vsi, xdp->xsk.pool,
					  xdp->xsk.queue_id);
	default:
		return -EINVAL;
	}
}

/**
 * nse_ena_misc_vector - enable the non-queue interrupts
 * @pf: board private structure
 */
static void nse_ena_misc_vector(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;
	u32 val;

	/* clear things first */
	wr32(hw, NSE_REG_OICR_ENA, 0);	/* disable all first */
	wr32(hw, NSE_REG_OICR, 0xFFFFFFFF);	/* write one to clear */

	/* Make sure the clear writes above complete before the interrupt
	 * enable below.
	 */
	wmb();
	nse_flush(hw);

	val = (NSE_REG_OICR_CORE_RESET_M |
			NSE_REG_OICR_REG_TIMEOUT_M |
			NSE_REG_OICR_HI_INT_M |
			NSE_REG_OICR_ME_INT_M |
			NSE_REG_OICR_LO_INT_M |
			NSE_REG_OICR_PCORE_EVENT_M |
			NSE_REG_OICR_TSC_REKEY_M |
			NSE_REG_OICR_FDIR_M |
			NSE_REG_OICR_HMC_ERR_M |
			NSE_REG_OICR_PEC_WDT_M |
			NSE_REG_OICR_MAL_DETECT_M);

	if (!pf->oicr_sw_int_tmp_poll)
		val |= NSE_REG_OICR_SWINT_M;

	if (nse_misc_check_temp && !pf->in_high_temp &&
	    !(pf->wd_subtask_flags & WD_SUBTASK_FLAG_OICR_OVERHEAT_RECV))
		val |= NSE_REG_OICR_OVERHEAT_M;

	pf->oicr_ena = val;	/* save it here, so can be used in nse_unmask_oicr() */

	wr32(hw, NSE_REG_OICR_ENA, pf->oicr_ena);
	wr32(hw, NSE_REG_OICR_MASK, ~(pf->oicr_ena));	/* unmask all ENA, mask !ENA */

	/* Make sure the OICR enable above is written before the interrupt
	 * vector is unmasked below.
	 */
	wmb();
	nse_flush(hw);

	val = (NSE_REG_INT_DYN_CTLN_INTMSK_VLD_M | NSE_REG_INT_DYN_CTLN_INTMSK_M);

	wr32(hw, NSE_REG_INT_DYN_CTLN(pf->misc_irq_idx), val);

	nse_flush(hw);
}

static void nse_unmask_oicr(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;

	wr32(hw, NSE_REG_OICR_MASK, ~(pf->oicr_ena));
}

extern void nse_misc_intr_handle_oicr_swint(struct nse_hw *hw);

/**
 * nse_misc_intr - misc interrupt handler
 * @irq: interrupt number
 * @data: pointer to a q_vector
 */
static irqreturn_t nse_misc_intr(int __always_unused irq, void *data)
{
	struct nse_pf *pf = (struct nse_pf *)data;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	u32 oicr, oicr_ena, oicr_remain;
	irqreturn_t ret = IRQ_NONE;

	pf->misc_intr_run_cnt++;

	oicr = rd32(hw, NSE_REG_OICR);

	oicr_ena = rd32(hw, NSE_REG_OICR_ENA);
	if (oicr_ena != pf->oicr_ena) {
		dev_warn(dev, "some configuration mismatch between OICR_ENA register and pf->oicr_ena\n");
		dev_warn(dev, "\t OICR_ENA register: %X\n", oicr_ena);
		dev_warn(dev, "\t pf->oicr_ena: %X\n", pf->oicr_ena);
	}

	if (oicr & (NSE_REG_OICR_HI_INT_M |
				NSE_REG_OICR_ME_INT_M |
				NSE_REG_OICR_LO_INT_M)) {
		oicr_ena &= ~(NSE_REG_OICR_HI_INT_M |
			      NSE_REG_OICR_ME_INT_M | NSE_REG_OICR_LO_INT_M);

		if (oicr & NSE_REG_OICR_HI_INT_M) {
			pf->oicr_hi_int_cnt++;
			dev_err(dev,
		"[%s] receive HI_INT, expect FW should start high-reset flow soon\n", __func__);
		}

		if (oicr & NSE_REG_OICR_ME_INT_M) {
			pf->oicr_me_int_cnt++;
			nse_debug(hw, NSE_DBG_SYS, "[%s, %d] receive ME_INT, can ignore\n",
				  __func__, __LINE__);
		}

		if (oicr & NSE_REG_OICR_LO_INT_M) {
			pf->oicr_lo_int_cnt++;
			nse_debug(hw, NSE_DBG_SYS, "[%s, %d] receive LO_INT, can ignore\n",
				  __func__, __LINE__);
		}
	}

	if (nse_misc_check_temp && (oicr & NSE_REG_OICR_OVERHEAT_M)) {
		oicr_ena &= ~NSE_REG_OICR_OVERHEAT_M;

		/* don't unmask it in later nse_irq_dynamic_ena() */
		pf->oicr_ena &= ~NSE_REG_OICR_OVERHEAT_M;

		pf->wd_subtask_flags |= WD_SUBTASK_FLAG_OICR_OVERHEAT_RECV;

		dev_warn(dev, "[%s] receive OICR->overheat (temperature)\n", __func__);
	}

	if (oicr & NSE_REG_OICR_SWINT_M) {
		oicr_ena &= ~NSE_REG_OICR_SWINT_M;
		pf->oicr_sw_int_cnt++;

		nse_misc_intr_handle_oicr_swint(hw);
	}

	if (oicr & NSE_REG_OICR_MAL_DETECT_M) {
		oicr_ena &= ~NSE_REG_OICR_MAL_DETECT_M;
		set_bit(NSE_MDD_EVENT_PENDING, pf->state);
	}

	if (oicr & NSE_REG_OICR_CORE_RESET_M) {
		/* we have a reset warning */

		oicr_ena &= ~NSE_REG_OICR_CORE_RESET_M;

		nse_high_reset_detect_on_oicr_core_reset(hw);
	}

/*  @renjunlin - todo: PE/RDMA - nse_misc_intr() - maybe NSE_REG_OICR_HMC_ERR_M,
 * NSE_REG_OICR_PEC_WDT_M for us
 */

	/* Report any remaining unexpected interrupts */
	oicr_remain = oicr & oicr_ena;
	if (oicr_remain)
		dev_err(dev, "unhandled interrupt oicr=0x%08x\n", oicr_remain);

	wr32(hw, NSE_REG_OICR, oicr);	/* write one to clear */

	ret = IRQ_HANDLED;

	if (nse_aq_rq_rx_method)
		tasklet_schedule(&pf->serv_bh);
	else
		set_bit(NSE_ADMINQ_EVENT_PENDING, pf->state);

	nse_service_task_schedule(pf);
	nse_irq_dynamic_ena(hw, NULL, NULL);

	return ret;
}

/**
 * nse_dis_ctrlq_interrupts - disable control queue interrupts
 * @hw: pointer to HW structure
 */
static void nse_dis_ctrlq_interrupts(struct nse_hw *hw)
{
	/* disable Admin queue Interrupt causes */
	wr32(hw, NSE_REG_PMBX_CTL,
	     rd32(hw, NSE_REG_PMBX_CTL) & ~NSE_REG_PMBX_CTL_CAUSE_EN_M);

	/* disable OICR Interrupt causes */
	wr32(hw, NSE_REG_OICR_CTL,
	     rd32(hw, NSE_REG_OICR_CTL) & ~NSE_REG_OICR_CTL_CAUSE_ENA_M);

	nse_flush(hw);
}

/**
 * nse_free_irq_msix_misc - Unroll misc vector setup
 * @pf: board private structure
 */
static void nse_free_irq_msix_misc(struct nse_pf *pf)
{
	int irq_num;
	struct nse_hw *hw = &pf->hw;

	nse_msgbox_dis_interrupt(hw);

	nse_dis_ctrlq_interrupts(hw);

	/* disable OICR interrupt */
	wr32(hw, NSE_REG_OICR_ENA, 0);
	nse_flush(hw);

	if (!nse_no_irq) {
		irq_num = nse_get_irq_num(pf, pf->misc_irq_idx);
		synchronize_irq(irq_num);
		devm_free_irq(nse_pf_to_dev(pf), irq_num, pf);
	}

	pf->num_avail_sw_msix += 1;
	(void)nse_free_res(pf->irq_tracker_self_region, pf->misc_irq_idx, NSE_RES_IRQ_ID_MISC);
}

static void nse_ena_ctrlq_interrupts(struct nse_hw *hw, u32 reg_idx)
{
	u32 val;

	/* bind and enable OICR as irq-source */
	val = (((reg_idx << NSE_REG_OICR_CTL_MSIX_INDEX_S) & NSE_REG_OICR_CTL_MSIX_INDEX_M) |
			NSE_REG_OICR_CTL_CAUSE_ENA_M);
	wr32(hw, NSE_REG_OICR_CTL, val);

	/* bind and enable adminq as irq-source */
	val = (((reg_idx << NSE_REG_PMBX_CTL_MSIX_IDX_S) & NSE_REG_PMBX_CTL_MSIX_IDX_M) |
			NSE_REG_PMBX_CTL_CAUSE_EN_M |
			(((u32)hw->pcore_pf_id <<
			 NSE_REG_PMBX_CTL_PF_IDX_S) & NSE_REG_PMBX_CTL_PF_IDX_M));
	wr32(hw, NSE_REG_PMBX_CTL, val);

	nse_flush(hw);
}

/**
 * nse_req_irq_msix_misc - Setup the misc vector to handle non queue events
 * @pf: board private structure
 *
 * This sets up the handler for MSIX 0, which is used to manage the
 * non-queue interrupts, e.g. AdminQ and errors. This is not used
 * when in MSI or Legacy interrupt mode.
 */
static int nse_req_irq_msix_misc(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	int misc_irq_idx, err = 0;

	if (!pf->int_name[0])
		snprintf(pf->int_name, sizeof(pf->int_name) - 1, "%s-%s:misc",
			 dev_driver_string(dev), dev_name(dev));

	/* Do not request IRQ but do enable OICR interrupt since settings are
	 * lost during reset. Note that this function is called only during
	 * rebuild path and not while reset is in progress.
	 */
	if (nse_is_reset_in_progress(pf->state))
		goto skip_req_irq;

	/* reserve one vector in irq_tracker for misc interrupts */
	misc_irq_idx = nse_get_res(pf, pf->irq_tracker_self_region, 1, NSE_RES_IRQ_ID_MISC);
	if (misc_irq_idx < 0)
		return misc_irq_idx;

	pf->num_avail_sw_msix -= 1;
	pf->misc_irq_idx = (u16)misc_irq_idx;

	if (pf->sw_conf.min_itr_no_intrl)
		(void)nse_set_itr_interval(hw, pf->misc_irq_idx, NSE_ITR_INTERVAL_MIN_USEC);
	else
		(void)nse_set_itr_interval(hw, pf->misc_irq_idx, NSE_ITR_INTERVAL_20K);

	(void)nse_set_intrl_interval(hw, pf->misc_irq_idx, 0);

	if (!nse_no_irq)
		err = devm_request_irq(dev, nse_get_irq_num(pf, pf->misc_irq_idx),
								nse_misc_intr, 0, pf->int_name, pf);
	if (err) {
		nse_dev_err_errno(dev, err, "devm_request_irq for %s failed",
				  pf->int_name);
		(void)nse_free_res(pf->irq_tracker_self_region,
				   pf->misc_irq_idx, NSE_RES_IRQ_ID_MISC);
		pf->num_avail_sw_msix += 1;
		return err;
	}

skip_req_irq:
	nse_ena_misc_vector(pf);

	nse_ena_ctrlq_interrupts(hw, pf->misc_irq_idx);

	nse_msgbox_ena_interrupt(hw, pf->misc_irq_idx);

	nse_flush(hw);

	nse_irq_dynamic_ena(hw, NULL, NULL);

	nse_flush(hw);

	return 0;
}

/**
 * nse_irq_dynamic_ena - Enable default interrupt generation settings
 * @hw: pointer to HW struct
 * @vsi: pointer to VSI struct, can be NULL
 * @q_vector: pointer to q_vector, can be NULL
 */
void
nse_irq_dynamic_ena(struct nse_hw *hw, struct nse_vsi *vsi,
		    struct nse_q_vector *q_vector)
{
	u32 vector = (vsi && q_vector) ? q_vector->reg_idx :
				((struct nse_pf *)hw->back)->misc_irq_idx;
	u32 val;

	/* clear the PBA here, as this function is meant to clean out all
	 * previous interrupts and enable the interrupt
	 *
	 * set (INTMSK_VLD=1, INTMSK = 0), so as to enable / unmask this irq-vector
	 */
	val = (NSE_REG_INT_DYN_CTLN_CLEARPBA_M |
			NSE_REG_INT_DYN_CTLN_INTMSK_VLD_M);
	if (vsi)
		if (test_bit(NSE_VSI_DOWN, vsi->state))
			return;
	wr32(hw, NSE_REG_INT_DYN_CTLN(vector), val);

	/* Make sure the vector is unmasked above before the OICR is
	 * unmasked below.
	 */
	wmb();

	if (!vsi || !q_vector)
		nse_unmask_oicr(hw);
}

/**
 * nse_napi_add - register NAPI handler for the VSI
 * @vsi: VSI for which NAPI handler is to be registered
 *
 * This function is only called in the driver's load path. Registering the NAPI
 * handler is done in nse_vsi_alloc_q_vector() for all other cases (i.e. resume,
 * reset/rebuild, etc.)
 */
static void nse_napi_add(struct nse_vsi *vsi)
{
	int v_idx;

	if (!vsi->netdev)
		return;

	nse_for_each_q_vector(vsi, v_idx)
		netif_napi_add(vsi->netdev, &vsi->q_vectors[v_idx]->napi,
			       nse_napi_poll);
}

/**
 * nse_napi_del - Remove NAPI handler for the VSI
 * @vsi: VSI for which NAPI handler is to be removed
 */
void nse_napi_del(struct nse_vsi *vsi)
{
	int v_idx;

	if (!vsi->netdev)
		return;

	nse_for_each_q_vector(vsi, v_idx)
		netif_napi_del(&vsi->q_vectors[v_idx]->napi);
}

/**
 * nse_set_ops - set netdev and ethtools ops for the given netdev
 * @netdev: netdev instance
 */
static void nse_set_ops(struct net_device *netdev)
{
	struct nse_pf *pf = nse_netdev_to_pf(netdev);
	struct nse_hw *hw = &pf->hw;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_PSR_SUPPORT_TNL) &&
	    !hw->is_mh_dpu_secondary_pf)
		netdev->udp_tunnel_nic_info = &nse_udp_tunnels;

	netdev->netdev_ops = &nse_netdev_ops;

	nse_set_ethtool_ops(netdev);
}

/**
 * nse_set_netdev_features - set features for the given netdev
 * @netdev: netdev instance
 */
static void nse_set_netdev_features(struct net_device *netdev)
{
	struct nse_pf *pf = nse_netdev_to_pf(netdev);
	struct nse_hw *hw = &pf->hw;
	struct nse_vsi *main_vsi = NULL;
	netdev_features_t csumo_features;
	netdev_features_t vlano_features;
	netdev_features_t dflt_features;
	netdev_features_t tso_features;

	main_vsi = nse_get_main_vsi(pf);

	dflt_features = NETIF_F_SG	|
			NETIF_F_HIGHDMA	|
			NETIF_F_RXHASH;

#ifdef NETIF_F_RX_UDP_TUNNEL_PORT
	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_PSR_SUPPORT_TNL) &&
	    !hw->is_mh_dpu_secondary_pf)
		dflt_features |= NETIF_F_RX_UDP_TUNNEL_PORT;
#endif

	if (main_vsi->sw_conf.fdir_ena)
		dflt_features |= NETIF_F_NTUPLE;

	csumo_features = NETIF_F_RXCSUM |
			 NETIF_F_IP_CSUM |
			 NETIF_F_IPV6_CSUM;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_MISC_SUPPORT_SCTP_CRC))
		csumo_features |= NETIF_F_SCTP_CRC;

	if (pf->hw.stag_ethertype == ETH_P_8021AD) {
		vlano_features = NETIF_F_HW_VLAN_STAG_FILTER |
			NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX;
	} else {	/* ETH_P_8021Q */
		vlano_features = NETIF_F_HW_VLAN_CTAG_FILTER |
			NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_TX;
	}

	tso_features = NETIF_F_TSO		|
					NETIF_F_GSO_UDP_L4	|
					NETIF_F_TSO_ECN		|
					NETIF_F_TSO6;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_TDM_SUPPORT_TNL_TSO)) {
		tso_features |= NETIF_F_GSO_GRE				|
						NETIF_F_GSO_UDP_TUNNEL		|
						NETIF_F_GSO_GRE_CSUM		|
						NETIF_F_GSO_UDP_TUNNEL_CSUM	|
						NETIF_F_GSO_PARTIAL			|
						NETIF_F_GSO_IPXIP4			|
						NETIF_F_GSO_IPXIP6			|
						0;

		netdev->gso_partial_features |= NETIF_F_GSO_UDP_TUNNEL_CSUM |
						NETIF_F_GSO_GRE_CSUM;
	}

	if (!pf->tso_hsb_usable || nse_lan_tx_not_use_ctx_desc) {
		tso_features = 0;
		netdev->gso_partial_features = 0;
	}

	if (nse_lan_tx_not_use_ctx_desc) {
		csumo_features &= ~(NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM | NETIF_F_SCTP_CRC);
		vlano_features &= ~(NETIF_F_HW_VLAN_STAG_TX | NETIF_F_HW_VLAN_CTAG_TX);
	}

	/* set features that user can change */
	netdev->hw_features = dflt_features | csumo_features |
			      vlano_features | tso_features;

	/* enable features */
	netdev->features |= netdev->hw_features;
	/* encap and VLAN devices inherit default, csumo and tso features */
	netdev->hw_enc_features |= dflt_features | csumo_features |
				   tso_features;
	netdev->vlan_features |= dflt_features | csumo_features |
				 tso_features;

	netdev->hw_enc_features |= (vlano_features & (NETIF_F_HW_VLAN_CTAG_TX |
				    NETIF_F_HW_VLAN_STAG_TX));

	netdev->hw_features |= NETIF_F_HW_TC;

	/* Enable macvlan offloads */
	if (test_bit(NSE_FLAG_VMDQ_ENA, pf->flags))
		netdev->hw_features |= NETIF_F_HW_L2FW_DOFFLOAD;

	if (pf->sw_conf.lan_rx_ena_rsc) {
		main_vsi->sw_conf.lan_rx_ena_rsc = pf->sw_conf.lan_rx_ena_rsc;

		netdev->hw_features |= NETIF_F_LRO;

		if (netdev->features & NETIF_F_RXCSUM)
			netdev->features |= NETIF_F_LRO;
	}
}

/**
 * nse_cfg_netdev - Allocate, configure and register a netdev
 * @vsi: the VSI associated with the new netdev
 *
 * Returns 0 on success, negative value on failure
 */
static int nse_cfg_netdev(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct nse_netdev_priv *np;
	struct net_device *netdev;
	unsigned int netdev_max_txqs, netdev_max_rxqs;
	u8 mac_addr[ETH_ALEN];

	netdev_max_txqs = pf->main_vsi_lan_txqs_max;
	netdev_max_rxqs = pf->main_vsi_lan_rxqs_max;

	netdev_max_txqs += pf->sw_conf.max_macvlans;
	netdev_max_rxqs += pf->sw_conf.max_macvlans;

	netdev = alloc_etherdev_mqs(sizeof(*np), netdev_max_txqs, netdev_max_rxqs);

	if (!netdev)
		return -ENOMEM;

	set_bit(NSE_VSI_NETDEV_ALLOCD, vsi->state);
	vsi->netdev = netdev;
	np = netdev_priv(netdev);
	np->vsi = vsi;

	nse_set_netdev_features(netdev);

	nse_set_ops(netdev);

	if (vsi->type == NSE_VSI_PF) {
		SET_NETDEV_DEV(netdev, nse_pf_to_dev(vsi->back));
		ether_addr_copy(mac_addr, vsi->port_info->mac.lan_addr);
		eth_hw_addr_set(netdev, mac_addr);
		ether_addr_copy(netdev->perm_addr, vsi->port_info->mac.lan_addr);
	}

	netdev->priv_flags |= IFF_UNICAST_FLT;

	/* Setup netdev TC information */
	nse_vsi_cfg_netdev_tc(vsi, vsi->tc_cfg.ena_tc);

	/* setup watchdog timeout value to be 5 second */
	netdev->watchdog_timeo = 5 * HZ;

	netdev->min_mtu = ETH_MIN_MTU;
	netdev->max_mtu = NSE_MAX_MTU;
	if (hw->mac_type == NSE_MAC_TYPE_AMBER &&
	    hw->hw_conf.hw_platform == NSE_HW_PLATFORM_FPGA && !nse_qos_db_use_share)
		netdev->max_mtu = ETH_DATA_LEN;

	return 0;
}

#define NETIF_VLAN_OFFLOAD_FEATURES	(NETIF_F_HW_VLAN_CTAG_RX | \
					 NETIF_F_HW_VLAN_CTAG_TX | \
					 NETIF_F_HW_VLAN_STAG_RX | \
					 NETIF_F_HW_VLAN_STAG_TX)

#define NETIF_VLAN_FILTERING_FEATURES	(NETIF_F_HW_VLAN_CTAG_FILTER | \
					 NETIF_F_HW_VLAN_STAG_FILTER)

/**
 * nse_set_vlan_offload_features - set VLAN offload features for the PF VSI
 * @vsi: PF's VSI
 * @features: features used to determine VLAN offload settings
 *
 * First, determine the vlan_ethertype based on the VLAN offload bits in
 * features. Then determine if stripping and insertion should be enabled or
 * disabled. Finally enable or disable VLAN stripping and insertion.
 */
static int
nse_set_vlan_offload_features(struct nse_vsi *vsi, netdev_features_t features)
{
	bool enable_stripping = true, enable_insertion = true;
	struct nse_vsi_vlan_ops *vlan_ops;
	int strip_err = 0, insert_err = 0;
	u16 vlan_ethertype = 0;

	vlan_ops = nse_get_compat_vsi_vlan_ops(vsi);

	if (features & (NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX))
		vlan_ethertype = ETH_P_8021AD;
	else if (features & (NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_TX))
		vlan_ethertype = ETH_P_8021Q;

	if (!(features & (NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_CTAG_RX)))
		enable_stripping = false;
	if (!(features & (NETIF_F_HW_VLAN_STAG_TX | NETIF_F_HW_VLAN_CTAG_TX)))
		enable_insertion = false;

#if defined(NSE_DEBUG_EXT)
	if (nse_lan_vlan_pvid_inner_strip) {
		if (enable_stripping)
			strip_err = nse_vsi_ena_inner_stripping(vsi, vlan_ethertype);
		else
			strip_err = nse_vsi_dis_inner_stripping(vsi);

		if (enable_insertion)
			insert_err = nse_vsi_ena_inner_insertion(vsi, vlan_ethertype);
		else
			insert_err = nse_vsi_dis_inner_insertion(vsi);

		if (strip_err || insert_err)
			return -EIO;

		return 0;
	}
#endif

	if (enable_stripping)
		strip_err = vlan_ops->ena_stripping(vsi, vlan_ethertype);
	else
		strip_err = vlan_ops->dis_stripping(vsi);

	if (enable_insertion)
		insert_err = vlan_ops->ena_insertion(vsi, vlan_ethertype);
	else
		insert_err = vlan_ops->dis_insertion(vsi);

	if (strip_err || insert_err)
		return -EIO;

	return 0;
}

/**
 * nse_set_vlan_filtering_features - set VLAN filtering features for the PF VSI
 * @vsi: PF's VSI
 * @features: features used to determine VLAN filtering settings
 *
 * Enable or disable Rx VLAN filtering based on the VLAN filtering bits in the
 * features.
 */
static int
nse_set_vlan_filtering_features(struct nse_vsi *vsi, netdev_features_t features)
{
	struct nse_vsi_vlan_ops *vlan_ops = nse_get_compat_vsi_vlan_ops(vsi);
	int err = 0;

	/* support Single VLAN Mode (SVM) and Double VLAN Mode (DVM) by checking
	 * if either bit is set
	 */
	if (features &
	    (NETIF_F_HW_VLAN_CTAG_FILTER | NETIF_F_HW_VLAN_STAG_FILTER))
		err = vlan_ops->ena_rx_filtering(vsi);
	else
		err = vlan_ops->dis_rx_filtering(vsi);

	return err;
}

/**
 * nse_set_vlan_features - set VLAN settings based on suggested feature set
 * @netdev: ptr to the netdev being adjusted
 * @features: the feature set that the stack is suggesting
 *
 * Only update VLAN settings if the requested_vlan_features are different than
 * the current_vlan_features.
 */
static int
nse_set_vlan_features(struct net_device *netdev, netdev_features_t features)
{
	netdev_features_t current_vlan_features, requested_vlan_features;
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	int err;

	current_vlan_features = netdev->features & NETIF_VLAN_OFFLOAD_FEATURES;
	requested_vlan_features = features & NETIF_VLAN_OFFLOAD_FEATURES;
	if (current_vlan_features ^ requested_vlan_features) {
		err = nse_set_vlan_offload_features(vsi, features);
		if (err)
			return err;
	}

	current_vlan_features = netdev->features &
		NETIF_VLAN_FILTERING_FEATURES;
	requested_vlan_features = features & NETIF_VLAN_FILTERING_FEATURES;
	if (current_vlan_features ^ requested_vlan_features) {
		err = nse_set_vlan_filtering_features(vsi, features);
		if (err)
			return err;
	}

	return 0;
}

/**
 * nse_vsi_vlan_setup - Setup VLAN offload properties on a PF VSI
 * @vsi: VSI to setup VLAN properties for
 */
static int nse_vsi_vlan_setup(struct nse_vsi *vsi)
{
	int err;

	err = nse_set_vlan_offload_features(vsi, vsi->netdev->features);
	if (err)
		return err;

	err = nse_set_vlan_filtering_features(vsi, vsi->netdev->features);
	if (err)
		return err;

	return nse_vsi_add_vlan_zero(vsi);
}

static void nse_set_rx_mode(struct net_device *netdev);

/**
 * nse_vsi_cfg - Setup the VSI
 * @vsi: the VSI being configured
 *
 * Return 0 on success and negative value on error
 */
int nse_vsi_cfg(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	int err;

	nse_debug(hw, NSE_DBG_LAN, "[%s] vsi=(rel_id:%d, abs_id=%d)\n",
								__func__, vsi->vsi_rel_num,
									vsi->vsi_abs_num);

	if (vsi->netdev && vsi->type == NSE_VSI_PF) {
		nse_set_rx_mode(vsi->netdev);

		err = nse_vsi_vlan_setup(vsi);

		if (err) {
			dev_err(dev, "FAIL: nse_vsi_vlan_setup(vsi, rel_id=%d, abs_id=%d), err=%d\n",
						vsi->vsi_rel_num, vsi->vsi_abs_num, err);
			return err;
		}
	}

	nse_vsi_cfg_dcb_rings(vsi);

	err = nse_vsi_cfg_lan_txcqs(vsi);
	if (err) {
		dev_err(dev, "FAIL: vsi_cfg_lan_txcqs(vsi, rel_id=%d, abs_id=%d), err=%d\n",
					vsi->vsi_rel_num, vsi->vsi_abs_num, err);
		return err;
	}

	err = nse_vsi_cfg_lan_txqs(vsi);
	if (err) {
		dev_err(dev, "FAIL: vsi_cfg_lan_txqs(vsi, rel_id=%d, abs_id=%d), err=%d\n",
					vsi->vsi_rel_num, vsi->vsi_abs_num, err);
		return err;
	}

	if (nse_is_xdp_ena_vsi(vsi)) {
		err = nse_vsi_cfg_xdp_txqs(vsi);
		if (err) {
			dev_err(dev, "FAIL: vsi_cfg_xdp_txqs(vsi, rel_id=%d, abs_id=%d), err=%d\n",
						vsi->vsi_rel_num, vsi->vsi_abs_num, err);
			return err;
		}
	}

	err = nse_vsi_cfg_rxqs(vsi);
	if (err) {
		dev_err(dev, "FAIL: vsi_cfg_rxqs(vsi, rel_id=%d, abs_id=%d), err=%d\n",
					vsi->vsi_rel_num, vsi->vsi_abs_num, err);
		return err;
	}

	return 0;
}

/* THEORY OF MODERATION:
 * The nse driver hardware works differently than the hardware that DIMLIB was
 * originally made for. nse hardware doesn't have packet count limits that
 * can trigger an interrupt, but it *does* have interrupt rate limit support,
 * which is hard-coded to a limit of 250,000 ints/second.
 * If not using dynamic moderation, the INTRL value can be modified
 * by ethtool rx-usecs-high.
 */
struct nse_dim {
	/* the throttle rate for interrupts, basically worst case delay before
	 * an initial interrupt fires, value is stored in microseconds.
	 */
	u16 itr;
};

/* Make a different profile for Rx that doesn't allow quite so aggressive
 * moderation at the high end (it maxes out at 126us or about 8k interrupts a
 * second.
 *
 * in unit of us --- when set to HW, translate to 2us unit.
 */
static const struct nse_dim nse_dim_profile[] = {
	{2},		/* 500,000 ints/s */
	{4},		/* 250,000 ints/s */
	{16},		/*  62,500 ints/s */
	{32},
	{64}
};

#define NSE_DIM_DEFAULT_PROFILE_IX 1

static void nse_dim_work(struct work_struct *work)
{
	struct nse_q_vector *q_vector;
	struct dim *dim;
	u16 itr;
	u8 profile_ix;

	dim = container_of(work, struct dim, work);
	q_vector = (struct nse_q_vector *)dim->priv;

	profile_ix = dim->profile_ix;

	WARN_ON(profile_ix >= ARRAY_SIZE(nse_dim_profile));
	if (profile_ix >= ARRAY_SIZE(nse_dim_profile))
		profile_ix = NSE_DIM_DEFAULT_PROFILE_IX;

	/* look up the values in our local table */
	itr = nse_dim_profile[dim->profile_ix].itr;

	nse_trace(dim_work, q_vector, dim);

	q_vector->dyn_itr_val = (itr >> 1);	/* translate into 2us ( NSE_ITR_GRAN_FIXED ) unit */
	q_vector->dyn_itr_refresh = true;

	dim->state = DIM_START_MEASURE;
}

/**
 * nse_init_moderation - set up interrupt moderation
 * @q_vector: the vector containing rings to be configured
 *
 * Set up interrupt moderation registers, with the intent to do the right thing
 * when called from reset or from probe, and whether or not dynamic moderation
 * is enabled or not. Take special care to write all the registers in both
 * dynamic moderation mode or not in order to make sure hardware is in a known
 * state.
 */
static void nse_init_moderation(struct nse_q_vector *q_vector)
{
	INIT_WORK(&q_vector->dim.work, nse_dim_work);
	q_vector->dim.mode = DIM_CQ_PERIOD_MODE_START_FROM_EQE;
	q_vector->dim.profile_ix = NSE_DIM_DEFAULT_PROFILE_IX;
	q_vector->dim.priv = q_vector;

	/* set the initial ITR to match the above */
	nse_write_itr(q_vector, ITR_IS_DYNAMIC(q_vector) ?
		      nse_dim_profile[q_vector->dim.profile_ix].itr : q_vector->itr_setting);

	nse_set_q_vector_intrl(q_vector);
}

/**
 * nse_napi_enable_all - Enable NAPI for all q_vectors in the VSI
 * @vsi: the VSI being configured
 */
static void nse_napi_enable_all(struct nse_vsi *vsi)
{
	int q_idx;

	if (!vsi->netdev)
		return;

	nse_for_each_q_vector(vsi, q_idx) {
		struct nse_q_vector *q_vector = vsi->q_vectors[q_idx];

		nse_init_moderation(q_vector);

		if (q_vector->rx.ring || q_vector->tx.ring)
			napi_enable(&q_vector->napi);
	}
}

/**
 * nse_up_complete - Finish the last steps of bringing up a connection
 * @vsi: The VSI being configured
 *
 * Return 0 on success and negative value on error
 */
static int nse_up_complete(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	int err;

	nse_debug(hw, NSE_DBG_LAN, "[%s] vsi=(rel_id:%d, abs_id=%d)\n",
								__func__, vsi->vsi_rel_num,
									vsi->vsi_abs_num);

	nse_vsi_cfg_msix(vsi);

	err = nse_vsi_start_lan_txcq_rings(vsi);
	if (err) {
		dev_err(dev, "FAIL: vsi_start_lan_txcq_rings(vsi, rel_id=%d, abs_id=%d), err=%d\n",
					vsi->vsi_rel_num, vsi->vsi_abs_num, err);
		return err;
	}

	err = nse_vsi_start_all_rx_rings(vsi);
	if (err) {
		dev_err(dev, "FAIL: vsi_start_all_rx_rings(vsi, rel_id=%d, abs_id=%d), err=%d\n",
					vsi->vsi_rel_num, vsi->vsi_abs_num, err);
		return err;
	}

	err = nse_vsi_start_lan_tx_rings(vsi);
	if (err) {
		dev_err(dev, "FAIL: vsi_start_lan_tx_rings(vsi, rel_id=%d, abs_id=%d), err=%d\n",
					vsi->vsi_rel_num, vsi->vsi_abs_num, err);
		return err;
	}

	err = nse_vsi_start_xdp_tx_rings(vsi);
	if (err) {
		dev_err(dev, "FAIL: vsi_start_xdp_tx_rings(vsi, rel_id=%d, abs_id=%d), err=%d\n",
					vsi->vsi_rel_num, vsi->vsi_abs_num, err);
		return err;
	}

	clear_bit(NSE_VSI_DOWN, vsi->state);
	if (!nse_polling_mod) {
		nse_napi_enable_all(vsi);
		/* Make sure NAPI is enabled before the interrupts are enabled. */
		mb();
		nse_vsi_ena_irq(vsi);
	}

	/*  before sync_tail() (after Q enable), to avoid host CPU to reorder sync_tail() and
	 * ena_irq()
	 */
	mb();

	nse_vsi_sync_tail_all_rx_rings(vsi);

	/* Perform an initial read of the statistics registers now to
	 * set the baseline so counters are ready when interface is up
	 */
	nse_update_vsi_stats(vsi);

	if (vsi->type == NSE_VSI_PF)
		nse_service_task_schedule(pf);

	if (nse_polling_mod)
		mod_timer(&pf->polling_tmr, round_jiffies(jiffies + pf->serv_tmr_period));

	return 0;
}

/**
 * nse_up - Bring the connection back up after being down
 * @vsi: VSI being configured
 */
int nse_up(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	int err;

	err = nse_vsi_cfg(vsi);
	if (!err)
		err = nse_up_complete(vsi);

	if (!err && vsi->type == NSE_VSI_PF)
		hw->port_info->lmac_phy_info.dyn_flags |= LMAC_PHY_DYN_FLAG_NEED_UPDATE_LINK_INFO;

	return err;
}

/**
 * nse_napi_disable_all - Disable NAPI for all q_vectors in the VSI
 * @vsi: VSI having NAPI disabled
 */
static void nse_napi_disable_all(struct nse_vsi *vsi)
{
	int q_idx;

	if (!vsi->netdev)
		return;

	nse_for_each_q_vector(vsi, q_idx) {
		struct nse_q_vector *q_vector = vsi->q_vectors[q_idx];

		if (q_vector->rx.ring || q_vector->tx.ring)
			napi_disable(&q_vector->napi);

		cancel_work_sync(&q_vector->dim.work);
	}
}

/**
 * nse_down - Shutdown the connection
 * @vsi: The VSI being stopped
 *
 * Caller of this function is expected to set the vsi->state NSE_DOWN bit
 */
int nse_down(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	int link_err = 0, vlan_err = 0;
	int i, tx_err = 0, rx_err = 0, txcq_err = 0;

	nse_debug(hw, NSE_DBG_LAN, "[%s] vsi=(rel_id:%d, abs_id=%d)\n",
								__func__, vsi->vsi_rel_num,
									vsi->vsi_abs_num);

	WARN_ON(!test_bit(NSE_VSI_DOWN, vsi->state));

	if (nse_polling_mod) {
		del_timer_sync(&pf->polling_tmr);
		msleep(100);
	}

	if (vsi->netdev && vsi->type == NSE_VSI_PF) {
		vlan_err = nse_vsi_del_vlan_zero(vsi);
		netif_carrier_off(vsi->netdev);
		netif_tx_disable(vsi->netdev);
	} else if (vsi->type == NSE_VSI_SWITCHDEV_CTRL) {
		nse_eswitch_stop_all_tx_queues(vsi->back);
	}

	nse_vsi_dis_irq(vsi);

	if (nse_is_xdp_ena_vsi(vsi)) {
		tx_err = nse_vsi_stop_xdp_tx_rings(vsi);
		if (tx_err)
			netdev_err(vsi->netdev, "Failed stop XDP rings, VSI(abs_id=%d, rel_id=%d) error %d\n",
				   vsi->vsi_abs_num, vsi->vsi_rel_num, tx_err);
	}

	tx_err = nse_vsi_stop_lan_tx_rings(vsi, false);
	if (tx_err)
		netdev_err(vsi->netdev, "Failed stop Tx rings, VSI(abs_id=%d, rel_id=%d) error %d\n",
			   vsi->vsi_abs_num, vsi->vsi_rel_num, tx_err);

	rx_err = nse_vsi_stop_all_rx_rings(vsi, false);
	if (rx_err)
		netdev_err(vsi->netdev, "Failed stop Rx rings, VSI(abs_id=%d, rel_id=%d) error %d\n",
			   vsi->vsi_abs_num, vsi->vsi_rel_num, rx_err);

	txcq_err = nse_vsi_stop_lan_txcq_rings(vsi);
	if (txcq_err)
		netdev_err(vsi->netdev, "Failed stop LAN-TX-CQ rings, VSI(abs_id=%d, rel_id=%d) error %d\n",
			   vsi->vsi_abs_num, vsi->vsi_rel_num, txcq_err);

	if (!nse_polling_mod)
		nse_napi_disable_all(vsi);

	if (tx_err || rx_err || txcq_err || link_err || vlan_err) {
		netdev_err(vsi->netdev, "Failed to close VSI(abs_id=%d, rel_id=%d) on switch 0x%04X\n",
			   vsi->vsi_abs_num, vsi->vsi_rel_num, vsi->vsw->sw_id);
		return -EIO;
	}

	nse_for_each_txq(vsi, i)
		nse_clean_tx_ring(vsi->tx_rings[i]);

	nse_for_each_rxq(vsi, i)
		nse_clean_rx_ring(vsi->rx_rings[i]);

	if (vsi->sw_conf.lan_tx_use_cq) {
		nse_for_each_lan_txcq(vsi, i)
			nse_clean_lan_txcq_ring(vsi->txcq_rings[i]);
	}

	nse_vsi_reset_stats(vsi);

	return 0;
}

/**
 * nse_vsi_setup_tx_rings - Allocate VSI Tx queue resources
 * @vsi: VSI having resources allocated
 *
 * Return 0 on success, negative on failure
 */
int nse_vsi_setup_tx_rings(struct nse_vsi *vsi)
{
	int i, err = 0;

	if (!vsi->num_txq) {
		dev_err(nse_pf_to_dev(vsi->back), "VSI(abs_id=%d, rel_id=%d) has 0 Tx queues\n",
			vsi->vsi_abs_num, vsi->vsi_rel_num);
		return -EINVAL;
	}

	nse_for_each_txq(vsi, i) {
		struct nse_ring *tx_ring = vsi->tx_rings[i];

		if (!tx_ring)
			return -EINVAL;

		if (vsi->netdev)
			tx_ring->netdev = vsi->netdev;

		err = nse_setup_tx_ring(tx_ring);
		if (err)
			break;
	}

	return err;
}

/**
 * nse_vsi_setup_rx_rings - Allocate VSI Rx queue resources
 * @vsi: VSI having resources allocated
 *
 * Return 0 on success, negative on failure
 */
int nse_vsi_setup_rx_rings(struct nse_vsi *vsi)
{
	int i, err = 0;

	if (!vsi->num_rxq) {
		dev_err(nse_pf_to_dev(vsi->back), "VSI(abs_id=%d, rel_id=%d) has 0 Rx queues\n",
			vsi->vsi_abs_num, vsi->vsi_rel_num);
		return -EINVAL;
	}

	nse_for_each_rxq(vsi, i) {
		struct nse_ring *ring = vsi->rx_rings[i];

		if (!ring)
			return -EINVAL;
		if (vsi->netdev)
			ring->netdev = vsi->netdev;
		err = nse_setup_rx_ring(ring);
		if (err)
			break;
	}

	return err;
}

int nse_vsi_setup_lan_txcq_rings(struct nse_vsi *vsi)
{
	int i, err = 0;

	if (!vsi->sw_conf.lan_tx_use_cq)
		return 0;

	nse_for_each_lan_txcq(vsi, i) {
		struct nse_txcq_ring *cq_ring = vsi->txcq_rings[i];

		if (!cq_ring)
			return -EINVAL;

		if (vsi->netdev)
			cq_ring->netdev = vsi->netdev;

		err = nse_setup_lan_txcq_ring(cq_ring);
		if (err)
			break;
	}

	return err;
}

/**
 * nse_vsi_open - Called when a network interface is made active
 * @vsi: the VSI to open
 *
 * Initialization of the VSI
 *
 * Returns 0 on success, negative value on error
 */
int nse_vsi_open(struct nse_vsi *vsi)
{
	char int_name[NSE_INT_NAME_STR_LEN];
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	int err;

	nse_debug(hw, NSE_DBG_LAN, "[%s] vsi=(rel_id:%d, abs_id=%d)\n",
								__func__, vsi->vsi_rel_num,
									vsi->vsi_abs_num);

	/* allocate descriptors */
	err = nse_vsi_setup_tx_rings(vsi);
	if (err) {
		dev_err(dev, "FAIL: vsi_setup_tx_rings, ret=%d\n", err);
		goto err_setup_tx;
	}

	err = nse_vsi_setup_rx_rings(vsi);
	if (err) {
		dev_err(dev, "FAIL: vsi_setup_rx_rings, ret=%d\n", err);
		goto err_setup_rx;
	}

	err = nse_vsi_setup_lan_txcq_rings(vsi);
	if (err) {
		dev_err(dev, "FAIL: setup_lan_txcq_rings, ret=%d\n", err);
		goto err_setup_lan_txcq;
	}

	err = nse_vsi_cfg(vsi);
	if (err) {
		dev_err(dev, "FAIL: vsi_cfg, ret=%d\n", err);
		goto err_setup_rx;
	}

	if (vsi->netdev) {
		snprintf(int_name, sizeof(int_name) - 1, "%s-%s",
			 dev_driver_string(nse_pf_to_dev(pf)), vsi->netdev->name);
	} else if (vsi->type == NSE_VSI_SWITCHDEV_CTRL) {
		snprintf(int_name, sizeof(int_name) - 1, "%s-%s",
			 dev_driver_string(nse_pf_to_dev(pf)), "swd-ctrl");
	} else {
		snprintf(int_name, sizeof(int_name) - 1, "%s-vsi-%d",
			 dev_driver_string(nse_pf_to_dev(pf)), vsi->idx);
	}

	err = nse_vsi_req_irq_msix(vsi, int_name);
	if (err)
		goto err_setup_rx;

	if (vsi->type == NSE_VSI_PF) {
		unsigned int total_qs = vsi->num_txq;

		if (test_bit(NSE_FLAG_MACVLAN_ENA, pf->flags))
			total_qs = vsi->alloc_txq + pf->max_num_macvlan;

		/* Notify the stack of the actual queue counts. */
		err = netif_set_real_num_tx_queues(vsi->netdev, total_qs);
		if (err)
			goto err_set_qs;

		err = netif_set_real_num_rx_queues(vsi->netdev, vsi->num_rxq);
		if (err)
			goto err_set_qs;
	}

	err = nse_up_complete(vsi);
	if (err) {
		dev_err(dev, "FAIL: up_complete(vsi, rel_id=%d, abs_id=%d), err=%d\n",
					vsi->vsi_rel_num, vsi->vsi_abs_num, err);
		goto err_up_complete;
	}

	return 0;

err_up_complete:
	nse_down(vsi);
err_set_qs:
	nse_vsi_free_irq(vsi);
err_setup_lan_txcq:
	nse_vsi_free_lan_txcq_rings(vsi);
err_setup_rx:
	nse_vsi_free_rx_rings(vsi);
err_setup_tx:
	nse_vsi_free_tx_rings(vsi);

	return err;
}

/**
 * nse_vsi_release_all - Delete all VSIs
 * @pf: PF from which all VSIs are being removed
 */
static void nse_vsi_release_all(struct nse_pf *pf)
{
	int err, i;

	if (!pf->vsi)
		return;

	nse_for_each_vsi(pf, i) {
		if (!pf->vsi[i])
			continue;

		err = nse_vsi_release(pf->vsi[i]);
		if (err)
			dev_dbg(nse_pf_to_dev(pf), "Failed to release pf->vsi[%d], err %d, vsi_abs_num = %d\n",
				i, err, pf->vsi[i]->vsi_abs_num);
	}
}

/**
 * nse_aq_str - convert AQ err code to a string
 * @aq_err: the AQ error code to convert
 */
const char *nse_aq_str(enum nse_aq_err aq_err)
{
	switch (aq_err) {
	case NSE_AQ_RC_OK:
		return "NSE_AQ_RC_OK";
	case NSE_AQ_RC_EIO:
		return "NSE_AQ_RC_EIO";
	case NSE_AQ_RC_EINVAL:
		return "NSE_AQ_RC_EINVAL";
	case NSE_AQ_RC_ERANGE:
		return "NSE_AQ_RC_ERANGE";
	case NSE_AQ_RC_EPERM:
		return "NSE_AQ_RC_EPERM";
	case NSE_AQ_RC_EFAULT:
		return "NSE_AQ_RC_EFAULT";
	case NSE_AQ_RC_ENOENT:
		return "NSE_AQ_RC_ENOENT";
	case NSE_AQ_RC_EEXIST:
		return "NSE_AQ_RC_EEXIST";
	case NSE_AQ_RC_EAGAIN:
		return "NSE_AQ_RC_EAGAIN";
	case NSE_AQ_RC_EBUSY:
		return "NSE_AQ_RC_EBUSY";
	case NSE_AQ_RC_EINPROGRESS:
		return "NSE_AQ_RC_EINPROGRESS";
	case NSE_AQ_RC_ENOMEM:
		return "NSE_AQ_RC_ENOMEM";
	case NSE_AQ_RC_ENOSPC:
		return "NSE_AQ_RC_ENOSPC";
	case NSE_AQ_RC_ENOTSUPP:
		return "NSE_AQ_RC_ENOTSUPP";

	case NSE_AQ_RC_EACCES_FW_IN_UPDATE:
		return "NSE_AQ_RC_EACCES_FW_IN_UPDATE";

	default:
		return "NSE_AQ_RC_UNKNOWN";
	}
}

/**
 * nse_stat_str - convert status err code to a string
 * @stat_err: the status error code to convert
 */
const char *nse_stat_str(enum nse_status stat_err)
{
	switch (stat_err) {
	case NSE_SUCCESS:
		return "NSE_SUCCESS";
	case NSE_ERR_PARAM:
		return "NSE_ERR_PARAM";
	case NSE_ERR_NOT_IMPL:
		return "NSE_ERR_NOT_IMPL";
	case NSE_ERR_NOT_READY:
		return "NSE_ERR_NOT_READY";
	case NSE_ERR_NOT_SUPPORTED:
		return "NSE_ERR_NOT_SUPPORTED";
	case NSE_ERR_BAD_PTR:
		return "NSE_ERR_BAD_PTR";
	case NSE_ERR_INVAL_SIZE:
		return "NSE_ERR_INVAL_SIZE";
	case NSE_ERR_EPERM:
		return "NSE_ERR_EPERM";
	case NSE_ERR_DEVICE_NOT_SUPPORTED:
		return "NSE_ERR_DEVICE_NOT_SUPPORTED";
	case NSE_ERR_RESET_FAILED:
		return "NSE_ERR_RESET_FAILED";
	case NSE_ERR_FW_API_VER:
		return "NSE_ERR_FW_API_VER";
	case NSE_ERR_NO_MEMORY:
		return "NSE_ERR_NO_MEMORY";
	case NSE_ERR_CFG:
		return "NSE_ERR_CFG";
	case NSE_ERR_OUT_OF_RANGE:
		return "NSE_ERR_OUT_OF_RANGE";
	case NSE_ERR_ALREADY_EXISTS:
		return "NSE_ERR_ALREADY_EXISTS";
	case NSE_ERR_DOES_NOT_EXIST:
		return "NSE_ERR_DOES_NOT_EXIST";
	case NSE_ERR_IN_USE:
		return "NSE_ERR_IN_USE";
	case NSE_ERR_MAX_LIMIT:
		return "NSE_ERR_MAX_LIMIT";
	case NSE_ERR_HIGH_RESET_ONGOING:
		return "NSE_ERR_HIGH_RESET_ONGOING";
	case NSE_ERR_HW_TABLE:
		return "NSE_ERR_HW_TABLE";
	case NSE_ERR_AGAIN:
		return "NSE_ERR_AGAIN";
	case NSE_ERR_BUSY:
		return "NSE_ERR_BUSY";
	case NSE_ERR_IN_PROGRESS:
		return "NSE_ERR_IN_PROGRESS";
	case NSE_ERR_IO:
		return "NSE_ERR_IO";

	case NSE_ERR_NVM:
		return "NSE_ERR_NVM";
	case NSE_ERR_NVM_CHECKSUM:
		return "NSE_ERR_NVM_CHECKSUM";
	case NSE_ERR_BUF_TOO_SHORT:
		return "NSE_ERR_BUF_TOO_SHORT";

	case NSE_ERR_FW_IN_UPDATE:
		return "NSE_ERR_FW_IN_UPDATE";

	case NSE_ERR_AQ_ERROR:
		return "NSE_ERR_AQ_ERROR";
	case NSE_ERR_AQ_TIMEOUT:
		return "NSE_ERR_AQ_TIMEOUT";
	case NSE_ERR_AQ_FULL:
		return "NSE_ERR_AQ_FULL";
	case NSE_ERR_AQ_NO_WORK:
		return "NSE_ERR_AQ_NO_WORK";
	case NSE_ERR_AQ_EMPTY:
		return "NSE_ERR_AQ_EMPTY";
	case NSE_ERR_AQ_FW_CRITICAL:
		return "NSE_ERR_AQ_FW_CRITICAL";

	default:
		return "NSE_ERR_UNKNOWN";
	}
}

const char *nse_pf_flag_str(unsigned int f)
{
	switch (f) {
	case NSE_FLAG_FLTR_SYNC:
		return "NSE_FLAG_FLTR_SYNC";
	case NSE_FLAG_VMDQ_ENA:
		return "NSE_FLAG_VMDQ_ENA";
	case NSE_FLAG_MACVLAN_ENA:
		return "NSE_FLAG_MACVLAN_ENA";
	case NSE_FLAG_ROCE_ENA:
		return "NSE_FLAG_ROCE_ENA";
	case NSE_FLAG_RSS_CAPABLE:
		return "NSE_FLAG_RSS_CAPABLE";
	case NSE_FLAG_SRIOV_ENA:
		return "NSE_FLAG_SRIOV_ENA";
	case NSE_FLAG_SRIOV_CAPABLE:
		return "NSE_FLAG_SRIOV_CAPABLE";
	case NSE_FLAG_SIOV_ENA:
		return "NSE_FLAG_SIOV_ENA";
	case NSE_FLAG_SIOV_CAPABLE:
		return "NSE_FLAG_SIOV_CAPABLE";
	case NSE_FLAG_DCB_CAPABLE:
		return "NSE_FLAG_DCB_CAPABLE";
	case NSE_FLAG_DCB_ENA:
		return "NSE_FLAG_DCB_ENA";
	case NSE_FLAG_PTP_SUPPORTED:
		return "NSE_FLAG_PTP_SUPPORTED";
	case NSE_FLAG_PTP:
		return "NSE_FLAG_PTP";
	case NSE_FLAG_AUX_ENA:
		return "NSE_FLAG_AUX_ENA";
	case NSE_FLAG_PLUG_AUX_DEV:
		return "NSE_FLAG_PLUG_AUX_DEV";
	case NSE_FLAG_UNPLUG_AUX_DEV:
		return "NSE_FLAG_UNPLUG_AUX_DEV";
	case NSE_FLAG_MTU_CHANGED:
		return "NSE_FLAG_MTU_CHANGED";
	case NSE_FLAG_CLS_FLOWER:
		return "NSE_FLAG_CLS_FLOWER";
	case NSE_FLAG_LINK_DOWN_ON_CLOSE_ENA:
		return "NSE_FLAG_LINK_DOWN_ON_CLOSE_ENA";
	case NSE_FLAG_TOTAL_PORT_SHUTDOWN_ENA:
		return "NSE_FLAG_TOTAL_PORT_SHUTDOWN_ENA";
	case NSE_FLAG_FW_LLDP_AGENT_DFLT_ENA:
		return "NSE_FLAG_FW_LLDP_AGENT_DFLT_ENA";
	case NSE_FLAG_FW_LLDP_AGENT_ENA:
		return "NSE_FLAG_FW_LLDP_AGENT_ENA";
	case NSE_FLAG_FW_LLDP_DCBX_SUBAGENT_ENA:
		return "NSE_FLAG_FW_LLDP_DCBX_SUBAGENT_ENA";
	case NSE_FLAG_ETHTOOL_CTXT:
		return "NSE_FLAG_ETHTOOL_CTXT";
	case NSE_FLAG_LEGACY_RX:
		return "NSE_FLAG_LEGACY_RX";
	case NSE_FLAG_VF_TRUE_PROMISC_ENA:
		return "NSE_FLAG_VF_TRUE_PROMISC_ENA";
	case NSE_FLAG_MDD_AUTO_RESET_VF:
		return "NSE_FLAG_MDD_AUTO_RESET_VF";
	case NSE_FLAG_VF_VLAN_PRUNING:
		return "NSE_FLAG_VF_VLAN_PRUNING";
	case NSE_FLAG_ESWITCH_CAPABLE:
		return "NSE_FLAG_ESWITCH_CAPABLE";
	default:
		return "--unknown--";
	}
}

const char *nse_pf_state_str(unsigned int s)
{
	switch (s) {
	case NSE_TESTING:
		return "NSE_TESTING";
	case NSE_DOWN:
		return "NSE_DOWN";
	case NSE_NEEDS_RESTART:
		return "NSE_NEEDS_RESTART";
	case NSE_PREPARED_FOR_RESET:
		return "NSE_PREPARED_FOR_RESET";
	case NSE_RESET_OICR_RECV:
		return "NSE_RESET_OICR_RECV";
	case NSE_PFR_REQ:
		return "NSE_PFR_REQ";
	case NSE_HIGH_RESET_CORER_REQ:
		return "NSE_HIGH_RESET_CORER_REQ";
	case NSE_HIGH_RESET_CORER_RECV:
		return "NSE_HIGH_RESET_CORER_RECV";
	case NSE_SUSPENDED:
		return "NSE_SUSPENDED";
	case NSE_RESET_FAILED:
		return "NSE_RESET_FAILED";
	case NSE_STATE_NOMINAL_CHECK_BITS:
		return "NSE_STATE_NOMINAL_CHECK_BITS";
	case NSE_ADMINQ_EVENT_PENDING:
		return "NSE_ADMINQ_EVENT_PENDING";
	case NSE_MDD_EVENT_PENDING:
		return "NSE_MDD_EVENT_PENDING";
	case NSE_FLTR_OVERFLOW_PROMISC:
		return "NSE_FLTR_OVERFLOW_PROMISC";
	case NSE_VF_DIS:
		return "NSE_VF_DIS";
	case NSE_CFG_BUSY:
		return "NSE_CFG_BUSY";
	case NSE_SERVICE_SCHED:
		return "NSE_SERVICE_SCHED";
	case NSE_SERVICE_DIS:
		return "NSE_SERVICE_DIS";
	case NSE_OICR_INTR_DIS:
		return "NSE_OICR_INTR_DIS";
	case NSE_MDD_VF_PRINT_PENDING:
		return "NSE_MDD_VF_PRINT_PENDING";
	case NSE_VF_RESETS_DISABLED:
		return "NSE_VF_RESETS_DISABLED";
	case NSE_LINK_DEFAULT_OVERRIDE_PENDING:
		return "NSE_LINK_DEFAULT_OVERRIDE_PENDING";
	case NSE_PHY_INIT_COMPLETE:
		return "NSE_PHY_INIT_COMPLETE";
	case NSE_LOGALL_INPROGRESS:
		return "NSE_LOGALL_INPROGRESS";
	case NSE_RDMA_IS_RUNNING:
		return "NSE_RDMA_IS_RUNNING";
	default:
		return "--unknown--";
	}
}

/**
 * nse_get_rss_key - Get RSS key
 * @vsi: Pointer to VSI structure
 * @seed: Buffer to store the key in
 *
 * Returns 0 on success, negative on failure
 */
int nse_get_rss_key(struct nse_vsi *vsi, u8 *seed)
{
	struct nse_hw *hw = &vsi->back->hw;
	enum nse_status status;

	if (!seed)
		return -EINVAL;

	status = nse_aq_rss_get_key(vsi, seed);
	if (status) {
		dev_err(nse_pf_to_dev(vsi->back), "Cannot get RSS key, err %s aq_err %s\n",
			nse_stat_str(status),
			nse_aq_str(hw->adminq.sq_last_status));
		return -EIO;
	}

	return 0;
}

/**
 * nse_set_rss_key - Set RSS key
 * @vsi: Pointer to the VSI structure
 * @seed: RSS hash seed
 *
 * Returns 0 on success, negative on failure
 */
int nse_set_rss_key(struct nse_vsi *vsi, u8 *seed)
{
	struct nse_hw *hw = &vsi->back->hw;
	enum nse_status status;

	if (!seed)
		return -EINVAL;

	status = nse_aq_rss_set_key(vsi, seed);
	if (status) {
		dev_err(nse_pf_to_dev(vsi->back), "Cannot set RSS key, err %s aq_err %s\n",
			nse_stat_str(status),
			nse_aq_str(hw->adminq.sq_last_status));
		return -EIO;
	}

	return 0;
}

/**
 * nse_get_rss_lut - Get RSS LUT
 * @vsi: Pointer to VSI structure
 * @lut: Buffer to store the lookup table entries
 * @lut_size: Size of buffer to store the lookup table entries
 *
 * Returns 0 on success, negative on failure
 */
int nse_get_rss_lut(struct nse_vsi *vsi, u16 *lut, u16 lut_size)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	u16 i = 0, rel_id = 0;
	enum nse_status status;

	if (!lut || !lut_size)
		return -EINVAL;

	if (lut_size > vsi->rss_lut_size_aligned)	/* not allow to get beyond my part */
		return -EINVAL;

	status = nse_aq_rss_get_lut(vsi, vsi->rss_lut_start + pf->rss_lut_start, lut_size, lut);
	if (status) {
		dev_err(nse_pf_to_dev(pf), "Cannot get RSS lut, err %s aq_err %s\n",
			nse_stat_str(status),
			nse_aq_str(hw->adminq.sq_last_status));
		return -EIO;
	}

	for (i = 0; i < lut_size; i++) {
		rel_id = lut[i] - (pf->lan_rxq_space_start + vsi->vsi_rxq_space_start);

		if (rel_id >= vsi->alloc_rxq) {		/* or num_rxq is better ? */

			dev_err(nse_pf_to_dev(pf), "RSS lut out of range, lut[%d]=%d\n",
				i, lut[i]);

			return -ERANGE;
		}

		lut[i] = rel_id;
	}

	return 0;
}

/**
 * ice_set_rss_lut - Set RSS LUT
 * @vsi: Pointer to VSI structure
 * @lut: Lookup table
 * @lut_size: Lookup table size
 *
 * Returns 0 on success, negative on failure
 */
int nse_set_rss_lut(struct nse_vsi *vsi, u16 *lut, u16 lut_size)
{
	struct nse_pf *pf = vsi->back;
	u16 i = 0;
	enum nse_status status;
	int ret;
	u16 *abs_lut = NULL;

	if (!lut || !lut_size) {
		ret = -EINVAL;
		goto out;
	}

	if (lut_size > vsi->rss_lut_size_aligned) {	/* not allow to set beyond my part */
		ret = -EINVAL;
		goto out;
	}

	abs_lut = kcalloc(lut_size, sizeof(u16), GFP_KERNEL);
	if (!abs_lut) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < lut_size; i++) {
		if (lut[i] >= vsi->num_rxq) {
			dev_warn(nse_pf_to_dev(pf), "RSS lut out of range, lut[%d]=%d, adjust it to 0\n",
				i, lut[i]);

			abs_lut[i] = pf->lan_rxq_space_start + vsi->vsi_rxq_space_start;
		} else {
			abs_lut[i] = pf->lan_rxq_space_start + vsi->vsi_rxq_space_start + lut[i];
		}
	}

	status = nse_aq_rss_set_lut(vsi, vsi->rss_lut_start + pf->rss_lut_start, lut_size, abs_lut);
	if (status) {
		dev_err(nse_pf_to_dev(pf), "Cannot set RSS lut, err: %d (%s)\n",
			status, nse_stat_str(status));
		ret = -EIO;
		goto out;
	}

	ret = 0;

out:
	kfree(abs_lut);

	return ret;
}

/**
 * nse_fill_rss_lut - Fill the RSS lookup table with default values
 * @lut: Lookup table
 * @rss_table_size: Lookup table size
 * @rss_size: Range of queue number for hashing
 */
void nse_fill_rss_lut(u16 *lut, u16 rss_table_size, u16 rss_size)
{
	u16 i;

	for (i = 0; i < rss_table_size; i++) {
		if (rss_size)
			lut[i] = i % rss_size;
		else
			lut[i] = 0;
	}
}

/**
 * nse_pf_vsi_setup - Set up a PF VSI
 * @pf: board private structure
 * @pi: pointer to the port_info instance
 *
 * Returns pointer to the successfully allocated VSI software struct
 * on success, otherwise returns NULL on failure.
 */
static struct nse_vsi *
nse_pf_vsi_setup(struct nse_pf *pf, struct nse_port_info *pi)
{
	return nse_vsi_setup(pf, pi, NSE_VSI_PF, NULL, 0);
}

/**
 * nse_macvlan_vsi_setup - Set up a MACVLAN VSI
 * @pf: board private structure
 * @pi: pointer to the port_info instance
 *
 * Returns pointer to the successfully allocated VSI software struct
 * on success, otherwise returns NULL on failure.
 */
static struct nse_vsi *
nse_macvlan_vsi_setup(struct nse_pf *pf, struct nse_port_info *pi)
{
	return nse_vsi_setup(pf, pi, NSE_VSI_OFFLOAD_MACVLAN, NULL, 0);
}

/**
 * nse_lb_vsi_setup - Set up a loopback VSI
 * @pf: board private structure
 * @pi: pointer to the port_info instance
 *
 * Returns pointer to the successfully allocated VSI software struct
 * on success, otherwise returns NULL on failure.
 */
struct nse_vsi *
nse_lb_vsi_setup(struct nse_pf *pf, struct nse_port_info *pi)
{
	return nse_vsi_setup(pf, pi, NSE_VSI_LB, NULL, 0);
}

/**
 * nse_pf_reset_stats - Reset all of the stats for the given PF
 * @pf: board private structure
 */
static void nse_pf_reset_stats(struct nse_pf *pf)
{
	memset(&pf->stats_prev, 0, sizeof(pf->stats_prev));
	memset(&pf->stats_new, 0, sizeof(pf->stats_new));
	pf->stat_prev_loaded = false;

#ifdef NSE_ADD_PROBES
	pf->tcp_segs = 0;
	pf->udp_segs = 0;
	pf->tx_tcp_cso = 0;
	pf->tx_udp_cso = 0;
	pf->tx_sctp_cso = 0;
	pf->tx_ip4_cso = 0;
	pf->tx_l3_cso_err = 0;
	pf->tx_l4_cso_err = 0;
	pf->rx_tcp_cso = 0;
	pf->rx_udp_cso = 0;
	pf->rx_sctp_cso = 0;
	pf->rx_ip4_cso = 0;
	pf->rx_ip4_cso_err = 0;
	pf->rx_tcp_cso_err = 0;
	pf->rx_udp_cso_err = 0;
	pf->rx_sctp_cso_err = 0;
	pf->tx_q_vlano = 0;
	pf->rx_q_vlano = 0;
	pf->tx_ad_vlano = 0;
	pf->rx_ad_vlano = 0;
#endif
}

/**
 * nse_rep_indr_tc_block_unbind
 * @cb_priv: indirection block private data
 */
static void nse_rep_indr_tc_block_unbind(void *cb_priv)
{
	struct nse_indr_block_priv *indr_priv = cb_priv;

	list_del(&indr_priv->list);
	devm_kfree(&indr_priv->netdev->dev, indr_priv);
}

/**
 * nse_tc_indir_block_unregister - Unregister TC indirect block notifications
 * @vsi: VSI struct which has the netdev
 */
static void nse_tc_indir_block_unregister(struct nse_vsi *vsi)
{
	struct nse_netdev_priv *np = netdev_priv(vsi->netdev);

	flow_indr_dev_unregister(nse_indr_setup_tc_cb, np,
				 nse_rep_indr_tc_block_unbind);
}

/**
 * nse_tc_indir_block_remove - clean indirect TC block notifications
 * @pf: PF structure
 */
static void nse_tc_indir_block_remove(struct nse_pf *pf)
{
	struct nse_vsi *pf_vsi = nse_get_main_vsi(pf);

	if (!pf_vsi)
		return;

	nse_tc_indir_block_unregister(pf_vsi);
}

/**
 * nse_tc_indir_block_register - Register TC indirect block notifications
 * @vsi: VSI struct which has the netdev
 *
 * Returns 0 on success, negative value on failure
 */
static int nse_tc_indir_block_register(struct nse_vsi *vsi)
{
	struct nse_netdev_priv *np;
	struct nse_pf *pf = (struct nse_pf *)vsi->back;
	struct device *dev = nse_pf_to_dev(pf);

	if (!vsi || !vsi->netdev)
		return -EINVAL;

	np = netdev_priv(vsi->netdev);

	INIT_LIST_HEAD(&np->tc_indr_block_priv_list);
	dev_info(dev, "Start to register indrect netdev tc\n");
	return flow_indr_dev_register(nse_indr_setup_tc_cb, np);
}

/**
 * nse_setup_default_rules - Setup default ICE rules
 * @vsi: VSI struct to set up the default rules for
 *
 * Returns 0 on success, negative value on failure
 */
static int nse_setup_default_rules(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct device *dev;

	dev = nse_pf_to_dev(pf);

	if (nse_init_mac_fltr(pf)) {
		dev_err(dev, "error initializing MAC filter\n");
		return -EINVAL;
	}
	return 0;
}

static void
nse_determine_main_vsi_q_limit(struct nse_pf *pf)
{
	pf->main_vsi_lan_qps_dflt = min_t(u16, num_online_cpus(), NSE_MAIN_VSI_MAX_QPS);

	pf->main_vsi_lan_rxqs_max = min_t(u16, pf->lan_rxq_space_size, NSE_MAIN_VSI_MAX_QPS);

	pf->main_vsi_lan_txqs_max = min_t(u16, pf->lan_txq_space_size, NSE_MAIN_VSI_MAX_QPS);

	/* pf->main_vsi_max_lanq_num is from kmod param, not set here */
}

/**
 * nse_setup_pf_sw - Setup the HW switch on startup or after reset
 * @pf: board private structure
 *
 * Returns 0 on success, negative value on failure
 */
static int nse_setup_pf_sw(struct nse_pf *pf)
{
	struct nse_vsi *vsi;
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status status;
	int ret;

	if (nse_is_reset_in_progress(pf->state))
		return -EBUSY;

	status = nse_aq_set_port_params(&pf->hw, 0, false, false);
	if (status) {
		dev_info(dev, "nse_aq_set_port_params() fails, status: %d(%s), but not a fatal configuration error\n",
						status, nse_stat_str(status));
		status = 0;
	}

	nse_determine_main_vsi_q_limit(pf);

	vsi = nse_pf_vsi_setup(pf, pf->hw.port_info);
	if (!vsi) {
		dev_err(dev, "[%s] FAIL: pf_vsi_setup()\n", __func__);
		return -ENOMEM;
	}

	pf->bypass_switch_vsi_abs_id = NSE_VSI_INVAL_ID;

	if (nse_bypass_switch) {
		status = nse_switch_rpp_set_bypass(&pf->hw, true, vsi->vsi_abs_num, 0xFF);

		if (status) {
			dev_info(dev, "switch_rpp_set_bypass(true) fails, status: %d(%s)\n",
							status, nse_stat_str(status));

			ret = -EIO;
			goto unroll_vsi_setup;
		}

		pf->bypass_switch_vsi_abs_id = vsi->vsi_abs_num;

	} else {
		status = nse_switch_rpp_set_bypass(&pf->hw, false, 0, 0);

		if (status) {
			dev_info(dev, "switch_rpp_set_bypass(false) fails, status: %d(%s)\n",
							status, nse_stat_str(status));

			ret = -EIO;
			goto unroll_vsi_setup;
		}
	}

	ret = nse_cfg_netdev(vsi);
	if (ret) {
		dev_err(dev, "[%s] FAIL: cfg_netdev(), ret=%d\n", __func__, ret);
		goto unroll_vsi_setup;
	}

	/* netdev has to be configured before setting frame size */
	nse_vsi_cfg_frame_size(vsi);

	/* init indirect block notifications */
	ret = nse_tc_indir_block_register(vsi);
	if (ret) {
		dev_err(dev, "Failed to register netdev notifier, ret=%d\n", ret);
		goto unroll_cfg_netdev;
	}

	/* Setup DCB netlink interface */
	nse_dcbnl_setup(vsi);

	/* registering the NAPI handler requires both the queues and
	 * netdev to be created, which are done in nse_pf_vsi_setup()
	 * and nse_cfg_netdev() respectively
	 */
	nse_napi_add(vsi);

	ret = nse_setup_default_rules(vsi);

	if (ret) {
		dev_err(dev, "nse_setup_default_rules() fails, ret=%d\n", ret);
		goto unroll_napi_add;
	}

	return ret;

unroll_napi_add:
	nse_napi_del(vsi);
	nse_tc_indir_block_unregister(vsi);
unroll_cfg_netdev:
	if (vsi->netdev) {
		clear_bit(NSE_VSI_NETDEV_ALLOCD, vsi->state);
		free_netdev(vsi->netdev);
		vsi->netdev = NULL;
	}
unroll_vsi_setup:
	nse_vsi_release(vsi);

	return ret;
}

/**
 * nse_get_avail_rxq_count - Get count of Rx queues in use
 * @pf: pointer to an nse_pf instance
 */
u16 nse_get_avail_rxq_count(struct nse_pf *pf)
{
	u16 ret;

	mutex_lock(&pf->lan_rxq_tracker_mutex);
	ret = nse_get_free_res_count(pf->lan_rxq_tracker);
	mutex_unlock(&pf->lan_rxq_tracker_mutex);

	return ret;
}

/**
 * nse_get_avail_txq_count - Get count of Tx queues in use
 * @pf: pointer to an nse_pf instance
 */
u16 nse_get_avail_txq_count(struct nse_pf *pf)
{
	u16 ret;

	mutex_lock(&pf->lan_txq_tracker_mutex);
	ret = nse_get_free_res_count(pf->lan_txq_tracker);
	mutex_unlock(&pf->lan_txq_tracker_mutex);

	return ret;
}

u16 nse_get_avail_rxq_count_max_contig(struct nse_pf *pf)
{
	u16 ret;

	mutex_lock(&pf->lan_rxq_tracker_mutex);
	ret = nse_get_free_res_count_max_contig(pf->lan_rxq_tracker);
	mutex_unlock(&pf->lan_rxq_tracker_mutex);

	return ret;
}
u16 nse_get_avail_txq_count_max_contig(struct nse_pf *pf)
{
	u16 ret;

	mutex_lock(&pf->lan_txq_tracker_mutex);
	ret = nse_get_free_res_count_max_contig(pf->lan_txq_tracker);
	mutex_unlock(&pf->lan_txq_tracker_mutex);

	return ret;
}

u16 nse_get_avail_rxq_count_contig_from_offset(struct nse_pf *pf, u16 offset)
{
	u16 ret;

	mutex_lock(&pf->lan_rxq_tracker_mutex);
	ret = nse_get_free_res_count_contig_from_offset(pf->lan_rxq_tracker, offset);
	mutex_unlock(&pf->lan_rxq_tracker_mutex);

	return ret;
}
u16 nse_get_avail_txq_count_contig_from_offset(struct nse_pf *pf, u16 offset)
{
	u16 ret;

	mutex_lock(&pf->lan_txq_tracker_mutex);
	ret = nse_get_free_res_count_contig_from_offset(pf->lan_txq_tracker, offset);
	mutex_unlock(&pf->lan_txq_tracker_mutex);

	return ret;
}

u16 nse_get_avail_rxq_count_contig_before_offset(struct nse_pf *pf, u16 offset)
{
	u16 ret;

	mutex_lock(&pf->lan_rxq_tracker_mutex);
	ret = nse_get_free_res_count_contig_before_offset(pf->lan_rxq_tracker, offset);
	mutex_unlock(&pf->lan_rxq_tracker_mutex);

	return ret;
}
u16 nse_get_avail_txq_count_contig_before_offset(struct nse_pf *pf, u16 offset)
{
	u16 ret;

	mutex_lock(&pf->lan_txq_tracker_mutex);
	ret = nse_get_free_res_count_contig_before_offset(pf->lan_txq_tracker, offset);
	mutex_unlock(&pf->lan_txq_tracker_mutex);

	return ret;
}

u16 nse_get_avail_txcq_count(struct nse_pf *pf)
{
	u16 ret;

	if (!pf->lan_txcq_tracker)
		return 0;

	mutex_lock(&pf->lan_txcq_tracker_mutex);
	ret = nse_get_free_res_count(pf->lan_txcq_tracker);
	mutex_unlock(&pf->lan_txcq_tracker_mutex);

	return ret;
}

u16 nse_get_avail_txcq_count_max_contig(struct nse_pf *pf)
{
	u16 ret;

	if (!pf->lan_txcq_tracker)
		return 0;

	mutex_lock(&pf->lan_txcq_tracker_mutex);
	ret = nse_get_free_res_count_max_contig(pf->lan_txcq_tracker);
	mutex_unlock(&pf->lan_txcq_tracker_mutex);

	return ret;
}

/* nse_init_pf_post() <-> nse_deinit_pf_early() */
static void nse_deinit_pf_early(struct nse_pf *pf)
{
	nse_fdir_deinit(pf);
}

/**
 * nse_deinit_pf - Unrolls initialziations done by nse_init_pf
 * @pf: board private structure to initialize
 */
static void nse_deinit_pf(struct nse_pf *pf)
{
	nse_service_task_stop(pf);

	del_timer_sync(&pf->oicr_sw_int_tmp_poll_timer);

	mutex_destroy(&pf->adev_mutex);
	mutex_destroy(&pf->sw_mutex);
	mutex_destroy(&pf->tc_mutex);
	mutex_destroy(&pf->tc_flower_mutex);
	mutex_destroy(&pf->vfs.table_lock);

	nse_lan_deinit_tso_hsb(pf);

	nse_msgbox_exit(pf);

	if (pf->avail_macvlan)
		bitmap_free(pf->avail_macvlan);

	pf->avail_macvlan = NULL;

	if (pf->ddp)
		release_firmware(pf->ddp);

	pf->ddp = NULL;
}

#define NSE_PF_PCI_BAR_0 0
/**
 * nse_set_siov_cap - enable S-IOV in PF flags
 * @pf: PF struct
 */
static void nse_set_siov_cap(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	u64 size;
	int pos;

	if (!nse_is_hw_static_fea_set(&pf->hw, NSE_HW_STATIC_FEA_MISC_SUPPORT_SIOV)) {
		clear_bit(NSE_FLAG_SIOV_CAPABLE, pf->flags);
		return;
	}

	pos = pci_find_ext_capability(pf->pdev, PCI_EXT_CAP_ID_PASID);
	size = pci_resource_len(pf->pdev, NSE_PF_PCI_BAR_0);
	if (pos && size >= SZ_128M) {
		set_bit(NSE_FLAG_SIOV_CAPABLE, pf->flags);
		dev_dbg(dev, "Device supports Scalable IOV\n");
	}
}

/**
 * nse_set_pf_caps - set PFs capability flags
 * @pf: pointer to the PF instance
 */
static void nse_set_pf_caps(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;
	struct nse_hw_func_caps *func_caps = &pf->hw.func_caps;

	clear_bit(NSE_FLAG_PTP_SUPPORTED, pf->flags);

	if (!hw->is_mh_dpu_secondary_pf)
		set_bit(NSE_FLAG_PTP_SUPPORTED, pf->flags);

	if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE) {	/* moonstone-todo: @FW-impl PTP */
		clear_bit(NSE_FLAG_PTP_SUPPORTED, pf->flags);
	}

	/* we limit some capability to primary_pf only */
	clear_bit(NSE_FLAG_VMDQ_ENA, pf->flags);
	clear_bit(NSE_FLAG_ROCE_ENA, pf->flags);
	clear_bit(NSE_FLAG_AUX_ENA, pf->flags);
	if (!hw->is_mh_dpu_secondary_pf) {
		set_bit(NSE_FLAG_VMDQ_ENA, pf->flags);

		/* RDMA */
		set_bit(NSE_FLAG_ROCE_ENA, pf->flags);
		set_bit(NSE_FLAG_AUX_ENA, pf->flags);
	}

	if (!nse_rdma_ena || !pf->rdma_qset_space_valid ||
	    !nse_is_hw_dyn_fea_set(hw, NSE_HW_DYN_FEA_SUPPORT_RDMA)) {
		clear_bit(NSE_FLAG_ROCE_ENA, pf->flags);
		clear_bit(NSE_FLAG_AUX_ENA, pf->flags);
	}

	if (!pf->sw_conf.max_macvlans) {
		clear_bit(NSE_FLAG_VMDQ_ENA, pf->flags);
		clear_bit(NSE_FLAG_MACVLAN_ENA, pf->flags);
	}

	clear_bit(NSE_FLAG_DCB_CAPABLE, pf->flags);
	if (!hw->is_mh_dpu_secondary_pf)
		set_bit(NSE_FLAG_DCB_CAPABLE, pf->flags);

	clear_bit(NSE_FLAG_SRIOV_CAPABLE, pf->flags);
	clear_bit(NSE_FLAG_ESWITCH_CAPABLE, pf->flags);

	if (func_caps->vf_space_valid && func_caps->vf_num) {
		set_bit(NSE_FLAG_SRIOV_CAPABLE, pf->flags);

		pf->vfs.num_supported = min_t(int, func_caps->vf_num,
					      NSE_MAX_SRIOV_VFS);

		if (hw->pf_type == NSE_PF_TYPE_NORMAL)
			set_bit(NSE_FLAG_ESWITCH_CAPABLE, pf->flags);

		if (!nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX) ||
		    nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
			clear_bit(NSE_FLAG_ESWITCH_CAPABLE, pf->flags);
	}

	nse_set_siov_cap(pf);

	set_bit(NSE_FLAG_RSS_CAPABLE, pf->flags);

	/* NSE_FLAG_FDIR_CAPABLE set in later nse_fdir_init() */
}

extern void nse_oicr_sw_int_tmp_poll_timer(struct timer_list *t);

static void nse_init_pf_resource_space_info(struct nse_pf *pf)	/* save info from hw->func_caps */
{
	struct nse_hw *hw = &pf->hw;

	pf->rdma_qset_space_valid = 0;

	if (hw->func_caps.rdma_qset_space_valid) {
		pf->rdma_qset_space_valid = 1;
		pf->rdma_qset_space_start = hw->func_caps.first_rdma_qset;
		pf->rdma_qset_space_size = hw->func_caps.last_rdma_qset -
			hw->func_caps.first_rdma_qset + 1;
	}

	/* we already did the check in nse_sanity_check_caps() */

	pf->vsi_space_start = hw->func_caps.first_vsi;
	pf->vsi_space_size = hw->func_caps.last_vsi - hw->func_caps.first_vsi + 1;

	pf->lan_rxq_space_start = hw->func_caps.first_lanrxq;
	pf->lan_rxq_space_size = hw->func_caps.last_lanrxq - hw->func_caps.first_lanrxq + 1;

	pf->lan_txq_space_start = hw->func_caps.first_lantxq;
	pf->lan_txq_space_size = hw->func_caps.last_lantxq - hw->func_caps.first_lantxq + 1;

	if (hw->func_caps.lan_txcq_space_valid) {
		pf->lan_txcq_space_valid = 1;
		pf->lan_txcq_space_start = hw->func_caps.first_lan_txcq;
		pf->lan_txcq_space_size = hw->func_caps.last_lan_txcq -
			hw->func_caps.first_lan_txcq + 1;
	}

	/* 4096 / 1024 = 4 */
	pf->rss_lut_start = pf->lan_rxq_space_start * NSE_RXQ_RSS_LUT_SCALE;
	pf->rss_lut_size = pf->lan_rxq_space_size * NSE_RXQ_RSS_LUT_SCALE;

	pf->irq_space_start = hw->func_caps.first_irq;
	pf->irq_space_size = hw->func_caps.last_irq - hw->func_caps.first_irq + 1;
}

static int nse_init_pf_sw_conf(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	struct nse_pf_sw_conf *pf_sw_conf = &pf->sw_conf;
	int ret = 0;

	memset(pf_sw_conf, 0, sizeof(*pf_sw_conf));

	pf_sw_conf->lan_tx_use_cq = nse_lan_tx_use_cq;
	pf_sw_conf->lan_tx_use_cq_for_vf = nse_lan_tx_use_cq_for_vf;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_TDM_ONLY_CQ_WB)) {
		pf_sw_conf->lan_tx_use_cq = 1;			/* MUST */
		pf_sw_conf->lan_tx_use_cq_for_vf = 1;	/* MUST */
	}

	pf_sw_conf->lan_rx_ena_rsc = nse_lan_rx_ena_rsc;

	if (!nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_RDM_HAVE_RSC))
		pf_sw_conf->lan_rx_ena_rsc = 0;

	pf_sw_conf->lan_txq_dflt_len = 2048;
	pf_sw_conf->lan_rxq_dflt_len = 2048;
	if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE) {
		pf_sw_conf->lan_txq_dflt_len = 4096;
		pf_sw_conf->lan_rxq_dflt_len = 4096;
	}

	pf_sw_conf->fdir_ena = nse_fdir_ena;
	pf_sw_conf->fdir_ena_for_vf = nse_fdir_ena_for_vf;
	pf_sw_conf->fdir_use_utilq = nse_fdir_use_utilq;

	if (!nse_is_hw_static_fea_set(hw,
	    NSE_HW_STATIC_FEA_RCF_HAVE_FDIR) || hw->is_mh_dpu_secondary_pf) {
		pf_sw_conf->fdir_ena = 0;
		pf_sw_conf->fdir_ena_for_vf = 0;
		pf_sw_conf->fdir_use_utilq = 0;
	}

	if (nse_is_hw_static_fea_set(hw,
	    NSE_HW_STATIC_FEA_PTP_SUPPORT_FINE_MODE) && nse_ptp_fine_mode)
		pf_sw_conf->ptp_fine_mode = 1;
	else
		pf_sw_conf->ptp_fine_mode = 0;

	if (nse_macvlan_ena) {
		pf_sw_conf->max_macvlans = pf->vsi_space_size / 2;
		if (pf_sw_conf->max_macvlans > NSE_MAX_MACVLANS)
			pf_sw_conf->max_macvlans = NSE_MAX_MACVLANS;
	}

	if (nse_palladium_debug)
		pf_sw_conf->min_itr_no_intrl = 1;

	/************************
	 * sanity check
	 ***********************/

	if (pf_sw_conf->lan_tx_use_cq &&
		(!pf->lan_txcq_space_valid || !pf->lan_txcq_space_size)) {
		dev_info(dev, "[%s] must use LAN-CQ, but LAN-CQ space not available\n",
			 __func__);

		ret = -EOPNOTSUPP;
		goto out;
	}

out:
	return ret;
}

/**
 * nse_init_pf - Initialize general software structures (struct nse_pf)
 * @pf: board private structure to initialize
 */
static int nse_init_pf(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status status;
	int ret = 0;

	nse_init_pf_resource_space_info(pf);

	ret = nse_init_pf_sw_conf(pf);
	if (ret) {
		dev_err(dev, "[%s] FAIL: init_pf_sw_conf(), ret=%d\n", __func__, ret);
		goto out;
	}

	nse_set_pf_caps(pf);

	nse_debugfs_pf_init(pf);	//after init_pf_sw_conf

	mutex_init(&pf->sw_mutex);
	mutex_init(&pf->tc_mutex);
	mutex_init(&pf->tc_flower_mutex);
	mutex_init(&pf->adev_mutex);

	INIT_HLIST_HEAD(&pf->aq_wait_list);
	spin_lock_init(&pf->aq_wait_lock);
	init_waitqueue_head(&pf->aq_wait_queue);

	spin_lock_init(&pf->udp_tnl_lock);

	init_waitqueue_head(&pf->reset_wait_queue);

	/* setup service timer and periodic service task */
	timer_setup(&pf->serv_tmr, nse_service_timer, 0);
	pf->serv_tmr_period = HZ;
	INIT_WORK(&pf->serv_task, nse_service_task);

	tasklet_setup(&pf->serv_bh, nse_service_bh);

	timer_setup(&pf->oicr_sw_int_tmp_poll_timer, nse_oicr_sw_int_tmp_poll_timer, 0);

	pf->in_high_temp = false;
	pf->wd_subtask_check_temp_prev = jiffies;
	pf->wd_subtask_check_temp_period = WD_SUBTASK_CHECK_TEMP_PERIOD;

	clear_bit(NSE_SERVICE_SCHED, pf->state);

	if (nse_polling_mod)
		timer_setup(&pf->polling_tmr, nse_polling_timer, 0);

	mutex_init(&pf->vfs.table_lock);
	hash_init(pf->vfs.table);

	(void)nse_lan_init_tso_hsb(pf);

	ret = nse_fdir_init_pre(pf);
	if (ret) {
		dev_err(dev, "[%s] FAIL: fdir_init_pre(), ret=%d\n", __func__, ret);
		goto out;
	}

	ret = nse_msgbox_init(pf);
	if (ret) {
		dev_err(dev, "[%s] FAIL: msgbox_init(), ret=%d\n", __func__, ret);
		goto out;
	}

	if (pf->sw_conf.lan_rx_ena_rsc) {	//also stands for: NSE_HW_STATIC_FEA_RDM_HAVE_RSC

		status = nse_lan_set_rsc_ctrl(&pf->hw, RSC_CTRL_DISALLOW_PURE_ACK_M);
		if (status) {
			dev_warn(dev, "[%s] WARN: set_rsc_ctrl() fails, status=%d(%s), RSC logic would not run for this PF\n",
							__func__, status, nse_stat_str(status));

			pf->sw_conf.lan_rx_ena_rsc = 0;	//disable it
		}
	}

	status = nse_lan_set_tdm_legacy_wb_mode(&pf->hw, 1);
	if (status)
		dev_warn(dev, "[%s] WARN: lan_set_tdm_legacy_wb_mode(1) fails, status=%d, tdm wb perf may be lower a little bit\n",
						__func__, status);

out:
	return ret;
}

/* nse_init_pf_post() <-> nse_deinit_pf_early() */
static int nse_init_pf_post(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	int ret = 0;

	ret = nse_fdir_init_post(pf);
	if (ret) {
		dev_err(dev, "[%s] FAIL: fdir_init_post(), ret=%d\n", __func__, ret);
		goto out;
	}

out:
	return ret;
}

/**
 * nse_is_wol_supported - check if WoL is supported
 * @hw: pointer to hardware info
 *
 * Check if WoL is supported based on the HW configuration.
 * Returns true if NVM supports and enables WoL for this port, false otherwise
 */
bool nse_is_wol_supported(struct nse_hw *hw)
{
	return nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_MISC_SUPPORT_WOL);
}

static void nse_set_wake(struct nse_pf *pf)
{
	/* @xzhao - todo-2: WoL - nse_set_wake()
	 */
}

/**
 * nse_setup_mc_magic_wake - setup device to wake on multicast magic packet
 * @pf: pointer to the PF struct
 *
 * Issue firmware command to enable multicast magic wake, making
 * sure that any locally administered address (LAA) is used for
 * wake, and that PF reset doesn't undo the LAA.
 */
static void nse_setup_mc_magic_wake(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_hw *hw = &pf->hw;
	enum nse_status status;
	u8 mac_addr[ETH_ALEN];
	struct nse_vsi *vsi;
	u16 wflags;

	if (!pf->wol_ena || !nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_MISC_SUPPORT_WOL))
		return;

	vsi = nse_get_main_vsi(pf);
	if (!vsi)
		return;

	/* Get current MAC address in case it's an LAA */
	if (vsi->netdev)
		ether_addr_copy(mac_addr, vsi->netdev->dev_addr);
	else
		ether_addr_copy(mac_addr, vsi->port_info->mac.perm_addr);

	if (hw->is_mh_dpu_secondary_pf)
		wflags = NSE_AQC_MAN_MAC_WFLAG_UPDATE_WOL_MPE;
	else
		wflags = (NSE_AQC_MAN_MAC_WFLAG_UPDATE_LMAC_ADDR |
					NSE_AQC_MAN_MAC_WFLAG_UPDATE_WOL_ADDR |
					NSE_AQC_MAN_MAC_WFLAG_UPDATE_WOL_MPE);

	status = nse_aq_manage_mac_write(hw, mac_addr, wflags, 1);

	if (status)
		dev_err(dev, "Failed to enable Multicast Magic Packet wake, err %s aq_err %s\n",
			nse_stat_str(status),
			nse_aq_str(hw->adminq.sq_last_status));
}

/**
 * nse_vsi_recfg_qs - Change the number of queues on a VSI
 * @vsi: VSI being changed
 * @new_rx: new number of Rx queues
 * @new_tx: new number of Tx queues
 *
 * Only change the number of queues if new_tx, or new_rx is non-0.
 *
 * Returns 0 on success.
 */
int nse_vsi_recfg_qs(struct nse_vsi *vsi, int new_rx, int new_tx)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	int err = 0, timeout = 50;

	if (!new_rx && !new_tx)
		return -EINVAL;

	if (new_rx > pf->main_vsi_lan_rxqs_max ||
		new_tx > pf->main_vsi_lan_txqs_max)
		return -EINVAL;

	while (test_and_set_bit(NSE_CFG_BUSY, pf->state)) {
		timeout--;
		if (!timeout)
			return -EBUSY;
		usleep_range(1000, 2000);
	}

	if (new_tx)
		vsi->req_txq = (u16)new_tx;
	if (new_rx)
		vsi->req_rxq = (u16)new_rx;

	/* set for the next time the netdev is started */
	if (!(vsi->netdev->flags & IFF_UP)) {
		nse_vsi_rebuild(hw, vsi, false);
		dev_dbg(nse_pf_to_dev(pf), "Link is down, queue count change happens when link is brought up\n");
		goto done;
	}

	nse_vsi_close(vsi);
	nse_vsi_rebuild(hw, vsi, false);
	nse_pf_dcb_recfg(pf);
	nse_vsi_open(vsi);

	if (vsi->type == NSE_VSI_PF)
		hw->port_info->lmac_phy_info.dyn_flags |= LMAC_PHY_DYN_FLAG_NEED_UPDATE_LINK_INFO;

done:
	clear_bit(NSE_CFG_BUSY, pf->state);
	return err;
}

/**
 * nse_register_netdev - register netdev and devlink port
 * @pf: pointer to the PF struct
 */
static int nse_register_netdev(struct nse_pf *pf)
{
	struct nse_vsi *vsi;
	int err = 0;

	vsi = nse_get_main_vsi(pf);
	if (!vsi || !vsi->netdev)
		return -EIO;

#if IS_ENABLED(CONFIG_NET_DEVLINK)
	err = nse_devlink_create_pf_port(pf);
	if (err)
		goto err_devlink_create;

	SET_NETDEV_DEVLINK_PORT(vsi->netdev, &pf->devlink_port);

#endif /* CONFIG_NET_DEVLINK */

	err = register_netdev(vsi->netdev);
	if (err)
		goto err_register_netdev;

	set_bit(NSE_VSI_NETDEV_REGISTERED, vsi->state);
	netif_carrier_off(vsi->netdev);
	netif_tx_stop_all_queues(vsi->netdev);

	return 0;

err_register_netdev:
#if IS_ENABLED(CONFIG_NET_DEVLINK)
	nse_devlink_destroy_pf_port(pf);
#endif
	free_netdev(vsi->netdev);
	vsi->netdev = NULL;
	clear_bit(NSE_VSI_NETDEV_REGISTERED, vsi->state);
	clear_bit(NSE_VSI_NETDEV_ALLOCD, vsi->state);

#if IS_ENABLED(CONFIG_NET_DEVLINK)
err_devlink_create:
#endif /* CONFIG_NET_DEVLINK */
	return err;
}

static ssize_t oicr_sw_int_tmp_poll_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	struct nse_pf *pf = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", pf->oicr_sw_int_tmp_poll);
}

static ssize_t oicr_sw_int_tmp_poll_store(struct device *dev, struct device_attribute *attr,
			     const char *buf, size_t count)
{
	struct nse_pf *pf = dev_get_drvdata(dev);
	struct nse_hw *hw = &pf->hw;
	u32 val = 0;

	if (kstrtouint(buf, 10, &val)) {
		count = -EINVAL;
		goto out;
	}

	val = !!val;

	if (pf->oicr_sw_int_tmp_poll != val) {
		nse_debug(hw, NSE_DBG_SYS, "[%s] oicr_sw_int_tmp_poll change from %d to %d\n",
								__func__,
									pf->oicr_sw_int_tmp_poll,
									val);

		if (!val) {
			del_timer_sync(&pf->oicr_sw_int_tmp_poll_timer);
			pf->oicr_ena |= NSE_REG_OICR_SWINT_M;
		} else {
			mod_timer(&pf->oicr_sw_int_tmp_poll_timer, (jiffies + 64));
			pf->oicr_ena &= ~(NSE_REG_OICR_SWINT_M);
		}

		wr32(hw, NSE_REG_OICR_ENA, pf->oicr_ena);
		wr32(hw, NSE_REG_OICR_MASK, ~(pf->oicr_ena));	/* unmask all ENA, mask !ENA */

		pf->oicr_sw_int_tmp_poll = val;
	}

out:
	return count;
}

static DEVICE_ATTR_RW(oicr_sw_int_tmp_poll);

static struct attribute *nse_sysfs_entries[] = {
	&dev_attr_oicr_sw_int_tmp_poll.attr,
	NULL,
};

static struct attribute_group nse_attribute_group = {
	.name = "nse",
	.attrs = nse_sysfs_entries,
};

static int nse_sysfs_init(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);	/* struct pci_dev *pdev */
	int err;

	err = sysfs_create_group(&dev->kobj, &nse_attribute_group);
	if (err) {
		dev_err(dev, "[%s] FAIL: create_group(), err=%d\n", __func__, err);
		goto out;
	}

	err = nse_sriov_sysfs_init(pf);
	if (err) {
		dev_err(dev, "[%s] FAIL: sriov_sysfs_init(), err=%d\n", __func__, err);

		sysfs_remove_group(&dev->kobj, &nse_attribute_group);

		goto out;
	}

	err = 0;

out:
	return err;
}

static void nse_sysfs_deinit(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);	/* struct pci_dev *pdev */

	nse_sriov_sysfs_cleanup(pf);

	sysfs_remove_group(&dev->kobj, &nse_attribute_group);
}

static int nse_init_devlink(struct nse_pf *pf)
{
	nse_devlink_init_regions(pf);
	nse_devlink_register(pf);

	return 0;
}

static void nse_deinit_devlink(struct nse_pf *pf)
{
	nse_devlink_unregister(pf);
	nse_devlink_destroy_regions(pf);
}

/**
 * nse_probe - Device initialization routine
 * @pdev: PCI device information struct
 * @ent: entry in nse_pci_tbl
 *
 * Returns 0 on success, negative on failure
 */
static int
nse_probe(struct pci_dev *pdev, const struct pci_device_id __always_unused *ent)
{
	struct device *dev = &pdev->dev;
	struct nse_pf *pf;
	struct nse_hw *hw;
	int bar_mask;
	enum nse_status status;
	int err;

	if (pdev->is_virtfn) {
		dev_err(dev, "can't probe a virtual function\n");
		return -EINVAL;
	}

	/* this driver uses devres, see
	 * Documentation/driver-api/driver-model/devres.rst
	 */
	err = pcim_enable_device(pdev);
	if (err)
		return err;

	bar_mask = BIT(NSE_BAR0);
	err = pcim_iomap_regions(pdev, bar_mask, dev_driver_string(dev));
	if (err) {
		nse_dev_err_errno(dev, err, "BAR0 I/O map error");
		return err;
	}

	bar_mask = BIT(NSE_BAR2);
	err = pcim_iomap_regions(pdev, bar_mask, dev_driver_string(dev));
	if (err) {
		nse_dev_info_errno(dev, err,
				   "BAR2 I/O map error, functionality around BAR2 not available");
	}

	pf = nse_allocate_pf(dev);
	if (!pf)
		return -ENOMEM;

	/* set up for high or low DMA */
	err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (err)
		err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32));
	if (err) {
		dev_err(dev, "DMA configuration failed: 0x%x\n", err);
		return err;
	}

	pci_set_master(pdev);

	pf->pdev = pdev;
	pci_set_drvdata(pdev, pf);
	set_bit(NSE_DOWN, pf->state);
	/* Disable service task until DOWN bit is cleared */
	set_bit(NSE_SERVICE_DIS, pf->state);

	hw = &pf->hw;
	hw->hw_addr = pcim_iomap_table(pdev)[NSE_BAR0];
	hw->hw_addr_bar2 = pcim_iomap_table(pdev)[NSE_BAR2];

	pci_save_state(pdev);

	hw->back = pf;
	hw->vendor_id = pdev->vendor;
	hw->device_id = pdev->device;
	pci_read_config_byte(pdev, PCI_REVISION_ID, &hw->revision_id);
	hw->subsystem_vendor_id = pdev->subsystem_vendor;
	hw->subsystem_device_id = pdev->subsystem_device;
	hw->bus.device = PCI_SLOT(pdev->devfn);
	hw->bus.func = PCI_FUNC(pdev->devfn);

	nse_set_ctrlq_len(hw);

	mutex_init(&hw->fwmng_lock);

	pf->msg_enable = netif_msg_init(debug, NSE_DFLT_NETIF_M);

	if (debug < -1)
		hw->debug_mask = debug;

	if (nse_conf_verbose)
		hw->debug_mask |= (NSE_DBG_SYS |
							NSE_DBG_MISC |
							NSE_DBG_FW |
							NSE_DBG_LAN |
							NSE_DBG_RCF |
							NSE_DBG_DCB |
							NSE_DBG_SW |
							NSE_DBG_SCHED |
							NSE_DBG_LMAC_PHY |
							NSE_DBG_SRIOV |
							NSE_DBG_RDMA);

	//hw->debug_mask |= NSE_DBG_SCHED_AQC;

	//hw->debug_mask |= NSE_DBG_LMAC_PHY_DETAIL;
	//hw->debug_mask |= NSE_DBG_MISC_DETAIL;

	if (nse_aq_verbose)
		hw->debug_mask |= NSE_DBG_AQM_MSG;

	status = nse_init_hw(hw);
	if (status) {
		dev_err(dev, "[%s] FAIL: init_hw(), status=%d(%s)\n",
						__func__, status, nse_stat_str(status));
		err = -EIO;
		goto err_exit_unroll;
	}

	nse_set_umac_shared(hw);

	err = nse_init_pf(pf);
	if (err) {
		nse_dev_err_errno(dev, err, "FAIL: init_pf()");
		goto err_init_pf_unroll;
	}

	nse_init_pf_fw_opt_features(pf);

	err = nse_init_devlink(pf);
	if (err) {
		nse_dev_err_errno(dev, err, "FAIL: init_devlink()");
		goto err_init_devlink_unroll;
	}

	err = nse_init_vsi_scheme(pf);
	if (err) {
		nse_dev_err_errno(dev, err, "FAIL: init_vsi_scheme()");
		goto err_init_vsi_unroll;
	}

	err = nse_init_lanq_scheme(pf);
	if (err) {
		nse_dev_err_errno(dev, err, "FAIL: init_lanq_scheme()");
		goto err_init_lanq_unroll;
	}

	err = nse_init_rss_scheme(pf);
	if (err) {
		nse_dev_err_errno(dev, err, "FAIL: init_rss_scheme()");
		goto err_init_rss_unroll;
	}

	err = nse_init_interrupt_scheme(pf);
	if (err) {
		nse_dev_err_errno(dev, err, "FAIL: init_interrupt_scheme()");
		err = -EIO;
		goto err_init_interrupt_unroll;
	}

	err = nse_init_pf_post(pf);
	if (err) {
		nse_dev_err_errno(dev, err, "FAIL: init_pf_post()");
		goto err_init_pf_post_unroll;
	}

	/* In case of MSIX we are going to setup the misc vector right here
	 * to handle admin queue events etc. In case of legacy and MSI
	 * the misc functionality and queue processing is combined in
	 * the same vector and that gets setup at open.
	 */
	err = nse_req_irq_msix_misc(pf);
	if (err) {
		nse_dev_err_errno(dev, err, "FAIL: req_irq_msix_misc()");
		goto err_msix_misc_unroll;
	}

	/* create switch struct for the switch element created by FW on boot */
	pf->first_sw = devm_kzalloc(dev, sizeof(*pf->first_sw), GFP_KERNEL);
	if (!pf->first_sw) {
		err = -ENOMEM;
		goto err_alloc_sw_unroll;
	}

	if (hw->evb_veb)
		pf->first_sw->bridge_mode = BRIDGE_MODE_VEB;
	else
		pf->first_sw->bridge_mode = BRIDGE_MODE_VEPA;

	pf->first_sw->pf = pf;

	/* record the sw_id available for later use */
	pf->first_sw->sw_id = hw->port_info->sw_id;

	err = nse_setup_pf_sw(pf);
	if (err) {
		nse_dev_err_errno(dev, err, "FAIL: setup_pf_sw()");
		goto err_alloc_sw_unroll;
	}

	clear_bit(NSE_SERVICE_DIS, pf->state);

	/* tell the firmware we are up */
	err = nse_aq_xchg_sw_fw_ver(&pf->hw);
	if (err) {
		dev_err(dev, "FAIL: sending driver version %s. error: %d\n", nse_drv_ver, err);
		goto err_send_version_unroll;
	}

	/* Disable WoL at init, wait for user to enable */
	device_set_wakeup_enable(dev, false);

	if (test_bit(NSE_FLAG_PTP_SUPPORTED, pf->flags))
		nse_ptp_init(pf);

	err = nse_init_pf_dcb(pf, true, false);
	if (err) {
		clear_bit(NSE_FLAG_DCB_CAPABLE, pf->flags);
		clear_bit(NSE_FLAG_DCB_ENA, pf->flags);

		dev_err(dev, "FAIL: init_pf_dcb(), ret=%d\n", err);

		goto err_init_pf_dcb;
	}

	if (nse_init_lag(pf)) {
		dev_err(dev, "Failed to init link aggregation support\n");
		goto err_init_lag;
	}

	err = nse_sysfs_init(pf);
	if (err) {
		dev_err(dev, "FAIL: sysfs_init(), err=%d\n", err);
		goto err_sysfs_init;
	}

	/* print PCI link speed and width */
	pcie_print_link_status(pf->pdev);

	err = nse_register_netdev(pf);
	if (err)
		goto err_netdev_reg;

	/* ready to go, so clear down state bit */
	clear_bit(NSE_DOWN, pf->state);

	/* since everything is good, start the service timer */
	mod_timer(&pf->serv_tmr, round_jiffies(jiffies + pf->serv_tmr_period));

	/* init peers only if supported */
	if (nse_is_aux_ena(pf)) {
		pf->cdev_infos = devm_kcalloc(dev, IIDC_MAX_NUM_AUX,
					      sizeof(*pf->cdev_infos),
					      GFP_KERNEL);
		if (!pf->cdev_infos) {
			err = -ENOMEM;
			goto err_netdev_reg;
		}

		err = nse_init_aux_devices(pf);
		if (err) {
			dev_err(dev, "Failed to initialize aux devs: %d\n",
				err);
			err = -EIO;
			goto err_init_aux_unroll;
		}

		nse_service_task_schedule(pf);	/* for quick plug */
	} else {
		dev_warn(dev, "Aux drivers are not supported on this device\n");
	}

	nse_pf_reset_stats(pf);
	nse_update_pf_stats(pf);

	return 0;

	/* Unwind non-managed device resources, etc. if something failed */
err_init_aux_unroll:
	if (nse_is_aux_ena(pf)) {
		nse_aux_iterate(pf, NULL, nse_unroll_cdev_info);
		pf->cdev_infos = NULL;
	}
err_netdev_reg:
	nse_sysfs_deinit(pf);
err_sysfs_init:
err_init_lag:
	nse_deinit_lag(pf);
err_init_pf_dcb:
	if (test_bit(NSE_FLAG_PTP_SUPPORTED, pf->flags))
		nse_ptp_release(pf);
err_send_version_unroll:
	nse_vsi_release_all(pf);
err_alloc_sw_unroll:
	set_bit(NSE_SERVICE_DIS, pf->state);
	set_bit(NSE_DOWN, pf->state);
	if (pf->first_sw)
		devm_kfree(dev, pf->first_sw);
	pf->first_sw = NULL;
	nse_free_irq_msix_misc(pf);
err_msix_misc_unroll:
	nse_deinit_pf_early(pf);
err_init_pf_post_unroll:
	nse_clear_interrupt_scheme(pf);
err_init_interrupt_unroll:
	nse_clear_rss_scheme(pf);
err_init_rss_unroll:
	nse_clear_lanq_scheme(pf);
err_init_lanq_unroll:
	nse_clear_vsi_scheme(pf);
err_init_vsi_unroll:
	nse_deinit_devlink(pf);
err_init_devlink_unroll:
	nse_deinit_pf(pf);

err_init_pf_unroll:

	nse_deinit_hw(hw);
	hw->hw_addr = NULL;
err_exit_unroll:
	nse_debugfs_pf_exit(pf);
	pci_disable_device(pdev);
	return err;
}

/**
 * nse_remove - Device removal routine
 * @pdev: PCI device information struct
 */
static void nse_remove(struct pci_dev *pdev)
{
	struct nse_pf *pf = pci_get_drvdata(pdev);
	struct device *dev = &pf->pdev->dev;
	struct nse_hw *hw;
	int i;

	if (!pf)
		return;

	hw = &pf->hw;

	for (i = 0; i < NSE_MAX_RESET_WAIT; i++) {
		if (!nse_is_reset_in_progress(pf->state))
			break;
		msleep(100);
	}

	/* clear indirect block notification before cleaning up of ADQ
	 * resources
	 */
	nse_tc_indir_block_remove(pf);

	if (test_bit(NSE_FLAG_SRIOV_ENA, pf->flags)) {
		set_bit(NSE_VF_RESETS_DISABLED, pf->state);
		nse_free_vfs(pf);
	}

	nse_unplug_aux_devs(pf, 0, 0);
	nse_aux_iterate(pf, NULL, nse_unroll_cdev_info);
	if (pf->cdev_infos) {
		devm_kfree(dev, pf->cdev_infos);
		pf->cdev_infos = NULL;
	}

	nse_service_task_stop(pf);

	nse_aq_cancel_waiting_tasks(pf);

	set_bit(NSE_DOWN, pf->state);

	nse_sysfs_deinit(pf);

	nse_deinit_lag(pf);

	if (test_bit(NSE_FLAG_PTP_SUPPORTED, pf->flags))
		nse_ptp_release(pf);

	nse_setup_mc_magic_wake(pf);
	nse_set_wake(pf);

	nse_vsi_release_all(pf);

	nse_free_irq_msix_misc(pf);
	nse_for_each_vsi(pf, i) {
		if (!pf->vsi[i])
			continue;
		nse_vsi_free_q_vectors(pf->vsi[i]);
	}

	nse_deinit_pf_early(pf);

	nse_deinit_pf(pf);

	nse_deinit_pf_fw_opt_features(pf);

	nse_deinit_devlink(pf);

	nse_deinit_hw(hw);

	nse_debugfs_pf_exit(pf);

	/* Issue a PFR as part of the prescribed driver unload flow.  Do not
	 * do it via nse_schedule_reset() since there is no need to rebuild
	 * and the service task is already stopped.
	 */
	nse_reset(hw, NSE_RESET_PFR);
	pci_wait_for_pending_transaction(pdev);

	nse_clear_interrupt_scheme(pf);

	nse_clear_rss_scheme(pf);
	nse_clear_lanq_scheme(pf);
	nse_clear_vsi_scheme(pf);

	pci_disable_device(pdev);
}

/**
 * nse_shutdown - PCI callback for shutting down device
 * @pdev: PCI device information struct
 */
static void nse_shutdown(struct pci_dev *pdev)
{
	struct nse_pf *pf = pci_get_drvdata(pdev);

	nse_remove(pdev);

	if (system_state == SYSTEM_POWER_OFF) {
		pci_wake_from_d3(pdev, pf->wol_ena);
		pci_set_power_state(pdev, PCI_D3hot);
	}
}

#ifdef CONFIG_PM
/**
 * ice_prepare_for_shutdown - prep for PCI shutdown
 * @pf: board private structure
 *
 * Inform or close all dependent features in prep for PCI device shutdown
 */
static void nse_prepare_for_shutdown(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;

	nse_debug(hw, NSE_DBG_SYS, "[%s] - enter\n", __func__);

	/* Notify VFs of impending reset */
	if (nse_check_sq_alive(hw, &hw->adminq, NULL))
		nse_vc_notify_reset(pf, NSE_RESET_PFR);

	dev_dbg(nse_pf_to_dev(pf), "Tearing down internal switch for shutdown\n");

	/* disable the VSIs and their queues that are not already DOWN */
	nse_dis_all_vsi_under_pf_drv(pf, false);

	nse_dis_all_vsi_under_vf_drv(pf);

	nse_shutdown_all_ctrlq(hw, false);

	nse_debug(hw, NSE_DBG_SYS, "[%s] - exit\n", __func__);
}

/**
 * ice_reinit_interrupt_scheme - Reinitialize interrupt scheme
 * @pf: board private structure to reinitialize
 *
 * This routine reinitialize interrupt scheme that was cleared during
 * power management suspend callback.
 *
 * This should be called during resume routine to re-allocate the q_vectors
 * and reacquire interrupts.
 */
static int nse_reinit_interrupt_scheme(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	int ret, v;

	/* Since we clear MSIX flag during suspend, we need to
	 * set it back during resume...
	 */

	ret = nse_init_interrupt_scheme(pf);
	if (ret) {
		nse_dev_err_errno(dev, ret,
				  "Failed to re-initialize interrupt");
		return ret;
	}

	/* Remap vectors and rings, after successful re-init interrupts */
	nse_for_each_vsi(pf, v) {
		if (!pf->vsi[v])
			continue;

		ret = nse_vsi_alloc_q_vectors(pf->vsi[v]);
		if (ret)
			goto err_reinit;

		ret = nse_vsi_map_rings_to_vectors(pf->vsi[v]);
		if (ret)
			goto err_reinit;
	}

	ret = nse_req_irq_msix_misc(pf);
	if (ret) {
		nse_dev_err_errno(dev, ret,
				  "Setting up misc vector failed after device suspend");
		goto err_reinit;
	}

	return 0;

err_reinit:
	while (v--)
		if (pf->vsi[v])
			nse_vsi_free_q_vectors(pf->vsi[v]);

	return ret;
}

/**
 * nse_suspend
 * @dev: generic device information structure
 *
 * Power Management callback to quiesce the device and prepare
 * for D3 transition.
 */
static int __maybe_unused nse_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct nse_pf *pf;
	int disabled, v;

	pf = pci_get_drvdata(pdev);

	if (!nse_pf_state_is_nominal(pf)) {
		dev_err(dev, "Device is not ready, no need to suspend it\n");
		return -EBUSY;
	}

	/* Stop watchdog tasks until resume completion.
	 * Even though it is most likely that the service task is
	 * disabled if the device is suspended or down, the service task's
	 * state is controlled by a different state bit, and we should
	 * store and honor whatever state that bit is in at this point.
	 */
	disabled = nse_service_task_stop(pf);

	nse_unplug_aux_devs(pf, 0, 0);

	/* Already suspended?, then there is nothing to do */
	if (test_and_set_bit(NSE_SUSPENDED, pf->state)) {
		if (!disabled)
			nse_service_task_restart(pf);
		return 0;
	}

	if (test_bit(NSE_DOWN, pf->state) ||
	    nse_is_reset_in_progress(pf->state)) {
		dev_err(dev, "can't suspend device in reset or already down\n");
		if (!disabled)
			nse_service_task_restart(pf);
		return 0;
	}

	nse_setup_mc_magic_wake(pf);

	nse_set_wake(pf);

	nse_prepare_for_shutdown(pf);

	/* Free vectors, clear the interrupt scheme and release IRQs
	 * for proper hibernation, especially with large number of CPUs.
	 * Otherwise hibernation might fail when mapping all the vectors back
	 * to CPU0.
	 */
	nse_free_irq_msix_misc(pf);
	nse_for_each_vsi(pf, v) {
		if (!pf->vsi[v])
			continue;
		nse_vsi_free_q_vectors(pf->vsi[v]);
	}

	nse_clear_interrupt_scheme(pf);

	pci_save_state(pdev);
	pci_wake_from_d3(pdev, pf->wol_ena);
	pci_set_power_state(pdev, PCI_D3hot);
	return 0;
}

/**
 * nse_resume - PM callback for waking up from D3
 * @dev: generic device information structure
 */
static int __maybe_unused nse_resume(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct nse_pf *pf;
	struct nse_hw *hw;
	int ret;

	pci_set_power_state(pdev, PCI_D0);
	pci_restore_state(pdev);
	pci_save_state(pdev);

	if (!pci_device_is_present(pdev))
		return -ENODEV;

	ret = pci_enable_device_mem(pdev);
	if (ret) {
		dev_err(dev, "Cannot enable device after suspend\n");
		return ret;
	}

	pf = pci_get_drvdata(pdev);
	hw = &pf->hw;

	/* We cleared the interrupt scheme when we suspended, so we need to
	 * restore it now to resume device functionality.
	 */
	ret = nse_reinit_interrupt_scheme(pf);
	if (ret)
		nse_dev_err_errno(dev, ret, "Cannot restore interrupt scheme");

	nse_cdev_info_refresh_msix(pf);

	clear_bit(NSE_DOWN, pf->state);

	/* re-enable service task for reset, but allow reset to schedule it */
	clear_bit(NSE_SERVICE_DIS, pf->state);

	/* Now perform PF reset and rebuild */
	if (nse_schedule_reset(pf, NSE_RESET_PFR))
		dev_err(dev, "Reset during resume failed.\n");

	clear_bit(NSE_SUSPENDED, pf->state);
	nse_service_task_restart(pf);

	/* Restart the service task */
	mod_timer(&pf->serv_tmr, round_jiffies(jiffies + pf->serv_tmr_period));

	return 0;
}
#endif /* CONFIG_PM */

/**
 * nse_pci_err_detected - warning that PCI error has been detected
 * @pdev: PCI device information struct
 * @err: the type of PCI error
 *
 * Called to warn that something happened on the PCI bus and the error handling
 * is in progress.  Allows the driver to gracefully prepare/handle PCI errors.
 */
static pci_ers_result_t
nse_pci_err_detected(struct pci_dev *pdev, pci_channel_state_t err)
{
	struct nse_pf *pf = pci_get_drvdata(pdev);
	struct nse_hw *hw;

	if (!pf) {
		dev_err(&pdev->dev, "%s: unrecoverable device error %d\n",
			__func__, err);
		return PCI_ERS_RESULT_DISCONNECT;
	}

	hw = &pf->hw;
	nse_debug(hw, NSE_DBG_SYS, "[%s] - enter: pci_channel_state=%d\n",
		  __func__, (unsigned int)err);

	if (!test_bit(NSE_SUSPENDED, pf->state)) {
		nse_service_task_stop(pf);

		if (!test_bit(NSE_PREPARED_FOR_RESET, pf->state)) {
			set_bit(NSE_PFR_REQ, pf->state);
			nse_prepare_for_reset(pf, NSE_RESET_PFR, true);
		} else {
			nse_debug(hw, NSE_DBG_SYS, "[%s, %d] not call prepare_for_reset() because flag PREPARED_FOR_RESET already set\n",
										__func__,
											__LINE__);
		}
	} else {
		nse_debug(hw, NSE_DBG_SYS, "[%s, %d] flag SUSPENDED already set\n",
			  __func__, __LINE__);
	}

	nse_debug(hw, NSE_DBG_SYS, "[%s] - exit\n", __func__);

	return PCI_ERS_RESULT_NEED_RESET;
}

/**
 * nse_pci_err_slot_reset - a PCI slot reset has just happened
 * @pdev: PCI device information struct
 *
 * Called to determine if the driver can recover from the PCI slot reset by
 * using a register read to determine if the device is recoverable.
 */
static pci_ers_result_t nse_pci_err_slot_reset(struct pci_dev *pdev)
{
	struct nse_pf *pf = pci_get_drvdata(pdev);
	struct nse_hw *hw = &pf->hw;
	pci_ers_result_t result;
	int err;

	nse_debug(hw, NSE_DBG_SYS, "[%s] - enter\n", __func__);

	err = pci_enable_device_mem(pdev);
	if (err) {
		nse_dev_err_errno(&pdev->dev, err,
				  "Cannot re-enable PCI device after reset");
		result = PCI_ERS_RESULT_DISCONNECT;
	} else {
		pci_set_master(pdev);
		pci_restore_state(pdev);
		pci_save_state(pdev);
		pci_wake_from_d3(pdev, false);

		result = PCI_ERS_RESULT_RECOVERED;
	}

	err = pci_aer_clear_nonfatal_status(pdev);
	if (err)
		nse_dev_dbg_errno(&pdev->dev, err,
				  "pci_aer_clear_nonfatal_status failed");
		/* non-fatal, continue */

	nse_debug(hw, NSE_DBG_SYS, "[%s] - exit: result=%d\n", __func__, (unsigned int)result);

	return result;
}

/**
 * nse_pci_err_resume - restart operations after PCI error recovery
 * @pdev: PCI device information struct
 *
 * Called to allow the driver to bring things back up after PCI error and/or
 * reset recovery have finished
 */
static void nse_pci_err_resume(struct pci_dev *pdev)
{
	struct nse_pf *pf = pci_get_drvdata(pdev);
	struct nse_hw *hw = NULL;

	if (!pf) {
		dev_err(&pdev->dev, "%s failed, device is unrecoverable\n",
			__func__);
		return;
	}

	hw = &pf->hw;
	nse_debug(hw, NSE_DBG_SYS, "[%s] - enter\n", __func__);

	if (test_bit(NSE_SUSPENDED, pf->state)) {
		dev_info(&pdev->dev, "%s failed to resume normal operations because now in PM suspend state\n",
			__func__);
		return;
	}

	nse_restore_all_vfs_msi_state(pdev);

	nse_do_reset(pf, NSE_RESET_PFR);
	nse_service_task_restart(pf);
	mod_timer(&pf->serv_tmr, round_jiffies(jiffies + pf->serv_tmr_period));

	nse_debug(hw, NSE_DBG_SYS, "[%s] - exit\n", __func__);
}

/**
 * nse_pci_err_reset_prepare - prepare device driver for PCI reset
 * @pdev: PCI device information struct
 */
static void nse_pci_err_reset_prepare(struct pci_dev *pdev)
{
	struct nse_pf *pf = pci_get_drvdata(pdev);
	struct nse_hw *hw = &pf->hw;

	nse_debug(hw, NSE_DBG_SYS, "[%s] - enter\n", __func__);

	if (!test_bit(NSE_SUSPENDED, pf->state)) {
		pf->pflr_count++;

		nse_service_task_stop(pf);

		if (!test_bit(NSE_PREPARED_FOR_RESET, pf->state)) {
			set_bit(NSE_PFR_REQ, pf->state);
			nse_prepare_for_reset(pf, NSE_RESET_PFR, true);
		} else {
			nse_debug(hw, NSE_DBG_SYS, "[%s, %d] not call prepare_for_reset() because flag PREPARED_FOR_RESET already set\n",
										__func__,
											__LINE__);
		}
	} else {
		nse_debug(hw, NSE_DBG_SYS, "[%s, %d] flag SUSPENDED already set\n",
			  __func__, __LINE__);
	}

	nse_debug(hw, NSE_DBG_SYS, "[%s] - exit\n", __func__);
}

/**
 * nse_pci_err_reset_done - PCI reset done, device driver reset can begin
 * @pdev: PCI device information struct
 */
static void nse_pci_err_reset_done(struct pci_dev *pdev)
{
	struct nse_pf *pf = pci_get_drvdata(pdev);
	struct nse_hw *hw = &pf->hw;

	nse_debug(hw, NSE_DBG_SYS, "[%s] - enter\n", __func__);

	nse_pci_err_resume(pdev);

	nse_debug(hw, NSE_DBG_SYS, "[%s] - exit\n", __func__);
}

/* nse_pci_tbl - PCI Device ID Table
 *
 * Wildcard entries (PCI_ANY_ID) should come last
 * Last entry must be all 0s
 *
 * { Vendor ID, Device ID, SubVendor ID, SubDevice ID,
 *   Class, Class Mask, private data (not used) }
 */
static const struct pci_device_id nse_pci_tbl[] = {
	{ PCI_VDEVICE(TRUSTNETIC, NSE_DEV_ID_AMBER_FPGA), 0 },
	{ PCI_VDEVICE(TRUSTNETIC, NSE_DEV_ID_AMBER_FDBTACXX), 0 },
	{ PCI_VDEVICE(TRUSTNETIC, NSE_DEV_ID_AMBER_FDBTACRX), 0 },
	{ PCI_VDEVICE(TRUSTNETIC, NSE_DEV_ID_AMBER_DDATACRX), 0 },
	{ PCI_VDEVICE(TRUSTNETIC, NSE_DEV_ID_AMBER_DDATAIRX), 0 },
	{ PCI_VDEVICE(TRUSTNETIC, NSE_DEV_ID_AMBER_FQATACRX), 0 },
	{ PCI_VDEVICE(TRUSTNETIC, NSE_DEV_ID_AMBER_DQATACXX), 0 },
	{ PCI_VDEVICE(TRUSTNETIC, NSE_DEV_ID_MOONSTONE), 0 },
	/* required last entry */
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, nse_pci_tbl);

static __maybe_unused SIMPLE_DEV_PM_OPS(nse_pm_ops, nse_suspend, nse_resume);

static const struct pci_error_handlers nse_pci_err_handler = {
	.error_detected = nse_pci_err_detected,
	.slot_reset = nse_pci_err_slot_reset,
	.reset_prepare = nse_pci_err_reset_prepare,
	.reset_done = nse_pci_err_reset_done,
	.resume = nse_pci_err_resume
};

static struct pci_driver nse_driver = {
	.name = KBUILD_MODNAME,
	.id_table = nse_pci_tbl,
	.probe = nse_probe,
	.remove = nse_remove,
#ifdef CONFIG_PM
	.driver.pm = &nse_pm_ops,
#endif /* CONFIG_PM */
	.shutdown = nse_shutdown,
	.sriov_configure = nse_sriov_configure,
	.err_handler = &nse_pci_err_handler
};

static void nse_module_params_fix(void)
{
	unsigned int val;

	if (nse_no_irq)
		nse_polling_mod = 1;

	if (nse_lan_no_irqll) {
		pr_info("[%s]: no_irqll=1 (IRQLL logic disabled), should disable RSC\n",
			__func__);
		nse_lan_rx_ena_rsc = 0;

		pr_info("[%s]: no_irqll=1 (IRQLL logic disabled), should disable desc_cache\n",
			__func__);
		nse_lan_desc_cache = 0;
	}

	if (nse_lan_tx_use_cq_for_vf && !nse_lan_tx_use_cq)
		nse_lan_tx_use_cq_for_vf = 0;

	if (nse_fdir_ena_for_vf && !nse_fdir_ena)
		nse_fdir_ena_for_vf = 0;

	if (nse_aq_cmd_timeout < NSE_CTL_Q_SQ_CMD_TIMEOUT_BASE)
		nse_aq_cmd_timeout = NSE_CTL_Q_SQ_CMD_TIMEOUT_BASE;

	val = (nse_aq_cmd_timeout / NSE_CTL_Q_SQ_CMD_TIMEOUT_BASE);

	if (nse_timeout_scale < val)
		nse_timeout_scale = val;
}

/**
 * nse_module_init - Driver registration routine
 *
 * nse_module_init is the first routine called when the driver is
 * loaded. All it does is register with the PCI subsystem.
 */
static int __init nse_module_init(void)
{
	int status;

	pr_info("%s - version %s\n", nse_driver_string, nse_drv_ver);
	pr_info("%s\n", nse_copyright);

	pr_info("sizeof(struct nse_aqc_vsi_props)=%zu\n", sizeof(struct nse_aqc_vsi_props));
	pr_info("offsetof(struct nse_aqc_vsi_props, rpp_per_vsi_ctxt)=%zu\n",
		offsetof(struct nse_aqc_vsi_props, rpp_per_vsi_ctxt));
	pr_info("offsetof(struct nse_aqc_vsi_props, tpp_per_vsi_ctxt)=%zu\n",
		offsetof(struct nse_aqc_vsi_props, tpp_per_vsi_ctxt));

	nse_module_params_fix();

	/* give our workQ high thread priority */
	nse_wq = alloc_workqueue("%s", (WQ_HIGHPRI | WQ_SYSFS), 0, KBUILD_MODNAME);
	if (!nse_wq) {
		pr_err("Failed to create workqueue\n");
		return -ENOMEM;
	}

	nse_debugfs_init();

	status = pci_register_driver(&nse_driver);
	if (status) {
		pr_err("failed to register PCI driver, err %d\n", status);
		destroy_workqueue(nse_wq);
		nse_debugfs_exit();
	}

	return status;
}
module_init(nse_module_init);

/**
 * nse_module_exit - Driver exit cleanup routine
 *
 * nse_module_exit is called just before the driver is removed
 * from memory.
 */
static void __exit nse_module_exit(void)
{
	pci_unregister_driver(&nse_driver);
	destroy_workqueue(nse_wq);
	nse_debugfs_exit();

	pr_info("module unloaded\n");
}
module_exit(nse_module_exit);

/**
 * nse_set_rx_mode - NDO callback to set the netdev filters
 * @netdev: network interface device structure
 */
static void nse_set_rx_mode(struct net_device *netdev)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;

	if (!vsi)
		return;

	/* Set the flags to synchronize filters
	 * ndo_set_rx_mode may be triggered even without a change in netdev
	 * flags
	 */
	set_bit(NSE_VSI_UMAC_FLTR_CHANGED, vsi->state);
	set_bit(NSE_VSI_MMAC_FLTR_CHANGED, vsi->state);
	set_bit(NSE_FLAG_FLTR_SYNC, vsi->back->flags);

	/* schedule our worker thread which will take care of
	 * applying the new filter changes
	 */
	nse_service_task_schedule(vsi->back);
}

/**
 * nse_open - Called when a network interface becomes active
 * @netdev: network interface device structure
 *
 * The open entry point is called when a network interface is made
 * active by the system (IFF_UP). At this point all resources needed
 * for transmit and receive operations are allocated, the interrupt
 * handler is registered with the OS, the netdev watchdog is enabled,
 * and the stack is notified that the interface is ready.
 *
 * Returns 0 on success, negative value on failure
 */
int nse_open(struct net_device *netdev)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_pf *pf = np->vsi->back;

	if (nse_is_reset_in_progress(pf->state)) {
		netdev_err(netdev, "can't open net device while reset is in progress");
		return -EBUSY;
	}

	return nse_open_internal(netdev);
}

/**
 * nse_open_internal - Called when a network interface becomes active
 * @netdev: network interface device structure
 *
 * Internal nse_open implementation. Should not be used directly except for nse_open and reset
 * handling routine
 *
 * Returns 0 on success, negative value on failure
 */
int nse_open_internal(struct net_device *netdev)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	int err;

	if (test_bit(NSE_NEEDS_RESTART, pf->state)) {
		netdev_err(netdev, "driver needs to be unloaded and reloaded\n");
		return -EIO;
	}

	netif_carrier_off(netdev);

	err = nse_vsi_open(vsi);
	if (err)
		netdev_err(netdev, "Failed to open VSI(abs_id=%d, rel_id=%d) on switch 0x%04X\n",
			   vsi->vsi_abs_num, vsi->vsi_rel_num, vsi->vsw->sw_id);

	/* Update existing tunnels information */
	udp_tunnel_get_rx_info(netdev);

	if (!err)
		hw->port_info->lmac_phy_info.dyn_flags |= LMAC_PHY_DYN_FLAG_NEED_UPDATE_LINK_INFO;

	return err;
}

/**
 * nse_stop - Disables a network interface
 * @netdev: network interface device structure
 *
 * The stop entry point is called when an interface is de-activated by the OS,
 * and the netdevice enters the DOWN state. The hardware is still under the
 * driver's control, but the netdev interface is disabled.
 *
 * Returns success only - not allowed to fail
 */
int nse_stop(struct net_device *netdev)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;

	if (nse_is_reset_in_progress(pf->state)) {
		netdev_err(netdev, "can't stop net device while reset is in progress");
		return -EBUSY;
	}

	nse_vsi_close(vsi);

	return 0;
}

#if defined(NSE_DEBUG_EXT)
extern void locate_final_l3_l4_hdr(struct sk_buff *skb,
		void **ret_l4_hdr,	/* tcp or udp */
		void **ret_l3_hdr,
		void **ret_1st_vlan_hdr,
		u16 *l3_proto,
		u8 *l4_proto);
#endif

u16
nse_select_queue(struct net_device *netdev, struct sk_buff *skb,
		 struct net_device *sb_dev)
{
#if defined(NSE_DEBUG_EXT)
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	u16 dport;
	u16 ret = 0;

	if (nse_lan_tx_select_q_dport &&
		!sb_dev &&
		vsi->num_txq > 1) {
		void *l4h = NULL, *l3h = NULL, *vh = NULL;
		u16 l3_proto;
		u8 l4_proto;
		struct iphdr *iph = NULL;
		struct ipv6hdr *ip6h = NULL;
		struct tcphdr *tcph = NULL;

		locate_final_l3_l4_hdr(skb, &l4h, &l3h, &vh, &l3_proto, &l4_proto);

		if (l3_proto == ETH_P_IP && l4h && l3h) {
			iph = (struct iphdr *)l3h;

			if (l4_proto == IPPROTO_TCP ||
				l4_proto == IPPROTO_UDP) {
				tcph = (struct tcphdr *)l4h;
				dport = be16_to_cpu(tcph->dest);

				if (dport >= 10000) {
					dport -= 10000;
					ret = dport % vsi->num_txq;
					goto out;
				} else {
					ret = dport % vsi->num_txq;
					goto out;
				}
			} else if (l4_proto == IPPROTO_ICMP) {
				ret = iph->tos % vsi->num_txq;
				goto out;
			} else {
				ret = nse_lan_tx_select_q_default % vsi->num_txq;
				goto out;
			}
		} else if (l3_proto == ETH_P_IPV6 && l4h && l3h) {
			ip6h = (struct ipv6hdr *)l3h;

			if (l4_proto == IPPROTO_TCP ||
				l4_proto == IPPROTO_UDP) {
				tcph = (struct tcphdr *)l4h;
				dport = be16_to_cpu(tcph->dest);

				if (dport >= 10000) {
					dport -= 10000;
					ret = dport % vsi->num_txq;
					goto out;
				} else {
					ret = dport % vsi->num_txq;
					goto out;
				}
			} else if (l4_proto == IPPROTO_ICMPV6) {
				ret = ip6h->priority % vsi->num_txq;
				goto out;
			} else {
				ret = nse_lan_tx_select_q_default % vsi->num_txq;
				goto out;
			}
		} else {
			ret = nse_lan_tx_select_q_default % vsi->num_txq;
			goto out;
		}
	}

	return netdev_pick_tx(netdev, skb, sb_dev);
out:
	return ret;
#endif

	return netdev_pick_tx(netdev, skb, sb_dev);
}

static netdev_features_t
nse_fix_features(struct net_device *netdev, netdev_features_t features)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;

	/* If Rx checksum is disabled, then RSC/LRO should also be disabled */
	if (!(features & NETIF_F_RXCSUM))
		features &= ~NETIF_F_LRO;

	if (!pf->sw_conf.lan_rx_ena_rsc)
		features &= ~NETIF_F_LRO;

	if (nse_is_xdp_ena_vsi(vsi) && (features & NETIF_F_LRO))
		features &= ~NETIF_F_LRO;

	return features;
}

/**
 * nse_set_features - set the netdev feature flags
 * @netdev: ptr to the netdev being adjusted
 * @features: the feature set that the stack is suggesting
 */
static int
nse_set_features(struct net_device *netdev, netdev_features_t features)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	bool need_down_up = false;
	bool if_up = (netdev->flags & IFF_UP);
	int ret = 0;

	/* Do not change setting during reset */
	if (nse_is_reset_in_progress(pf->state)) {
		dev_err(dev, "Device is resetting, changing advanced netdev features temporarily unavailable.\n");
		return -EBUSY;
	}

	/* Multiple features can be changed in one call so keep features in
	 * separate if/else statements to guarantee each feature is checked
	 */

	if (pf->sw_conf.lan_rx_ena_rsc) {
		if (features & NETIF_F_LRO) {
			/* request turn on LRO/RSC on PF-main-VSI */
			if (!(netdev->features & NETIF_F_LRO) &&
					!vsi->sw_conf.lan_rx_ena_rsc) {
				vsi->sw_conf.lan_rx_ena_rsc = true;

				need_down_up = true;
			}
		} else if (!(features & NETIF_F_LRO)) {
			/* request turn off LRO/RSC on PF-main-VSI */
			if ((netdev->features & NETIF_F_LRO) &&
				vsi->sw_conf.lan_rx_ena_rsc) {
				vsi->sw_conf.lan_rx_ena_rsc = false;

				need_down_up = true;
			}
		}
	}

	/*  need_down_up place here, because later rxhash / vlan / HW_L2FW_DOFFLOAD changes doesn't
	 * need down_up
	 */
	if (need_down_up) {
		if (if_up && !test_and_set_bit(NSE_VSI_DOWN, vsi->state)) {
			ret = nse_down(vsi);
			if (ret) {
				dev_err(dev, "[%s, %d] FAIL: DOWN(VSI)\n",
						__func__, __LINE__);
				return ret;
			}
		}

		if (if_up) {
			ret = nse_up(vsi);
			if (ret) {
				dev_err(dev, "[%s, %d] FAIL: UP(VSI)\n",
						__func__, __LINE__);
				return ret;
			}
		}
	}

	if (features & NETIF_F_RXHASH && !(netdev->features & NETIF_F_RXHASH))
		nse_vsi_manage_rss_lut(vsi, true);
	else if (!(features & NETIF_F_RXHASH) &&
		 netdev->features & NETIF_F_RXHASH)
		nse_vsi_manage_rss_lut(vsi, false);

	ret = nse_set_vlan_features(netdev, features);
	if (ret)
		return ret;

	if ((features & NETIF_F_HW_L2FW_DOFFLOAD) &&
	    !(netdev->features & NETIF_F_HW_L2FW_DOFFLOAD)) {
		ret = nse_init_macvlan(vsi, true);
		if (ret)
			return ret;
	} else if (!(features & NETIF_F_HW_L2FW_DOFFLOAD) &&
		 (netdev->features & NETIF_F_HW_L2FW_DOFFLOAD)) {
		nse_deinit_macvlan(vsi);
	}

	if ((features & NETIF_F_NTUPLE) &&
	    !(netdev->features & NETIF_F_NTUPLE)) {
		dev_info(dev, "NETIF_F_NTUPLE: off->on\n");
	} else if (!(features & NETIF_F_NTUPLE) &&
		 (netdev->features & NETIF_F_NTUPLE)) {
		dev_info(dev, "NETIF_F_NTUPLE: on->off\n");
		nse_del_ethool_ntuple_all(hw);
	}

	if ((features & NETIF_F_HW_TC) &&
	    !(netdev->features & NETIF_F_HW_TC))
		set_bit(NSE_FLAG_CLS_FLOWER, pf->flags);
	else
		clear_bit(NSE_FLAG_CLS_FLOWER, pf->flags);

	return 0;
}

/**
 * nse_set_mac_address - NDO callback to set MAC address
 * @netdev: network interface device structure
 * @pi: pointer to an address structure
 *
 * Returns 0 on success, negative on failure
 */
static int nse_set_mac_address(struct net_device *netdev, void *pi)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct sockaddr *addr = pi;
	enum nse_status status;
	u8 old_mac[ETH_ALEN];
	u8 wflags = 0;
	int err = 0;
	u8 *mac;

	mac = (u8 *)addr->sa_data;

	if (!is_valid_ether_addr(mac))
		return -EADDRNOTAVAIL;

	if (ether_addr_equal(netdev->dev_addr, mac)) {
		netdev_dbg(netdev, "already using mac %pM\n", mac);
		return 0;
	}

	if (test_bit(NSE_DOWN, pf->state) ||
	    nse_is_reset_in_progress(pf->state)) {
		netdev_err(netdev, "can't set mac %pM. device not ready\n",
			   mac);
		return -EBUSY;
	}

	netif_addr_lock_bh(netdev);
	ether_addr_copy(old_mac, netdev->dev_addr);
	/* change the netdev's MAC address */
	eth_hw_addr_set(netdev, mac);
	netif_addr_unlock_bh(netdev);

	/* Clean up old MAC filter. Not an error if old filter doesn't exist */
	status = nse_fltr_remove_mac(vsi, old_mac, NSE_FWD_TO_VSI);
	if (status && status != NSE_ERR_DOES_NOT_EXIST) {
		err = -EADDRNOTAVAIL;
		goto err_update_filters;
	}

	/* Add filter for new MAC. If filter exists, return success */
	status = nse_fltr_add_mac(vsi, mac, NSE_FWD_TO_VSI);
	if (status == NSE_ERR_ALREADY_EXISTS) {
		/* Although this MAC filter is already present in hardware it's
		 * possible in some cases (e.g. bonding) that dev_addr was
		 * modified outside of the driver and needs to be restored back
		 * to this value.
		 */
		netdev_dbg(netdev, "filter for MAC %pM already exists\n", mac);
		return 0;
	} else if (status) {
		/* error if the new filter addition failed */
		err = -EADDRNOTAVAIL;
	}

err_update_filters:
	if (err) {
		netdev_err(netdev, "can't set MAC %pM. filter update failed\n",
			   mac);
		netif_addr_lock_bh(netdev);
		eth_hw_addr_set(netdev, old_mac);
		netif_addr_unlock_bh(netdev);
		return err;
	}

	netdev_dbg(vsi->netdev, "updated MAC address to %pM\n",
		   netdev->dev_addr);

	/* write new MAC address to the firmware */
	wflags = NSE_AQC_MAN_MAC_WFLAG_UPDATE_LMAC_ADDR;
	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_MISC_SUPPORT_WOL))
		wflags |= NSE_AQC_MAN_MAC_WFLAG_UPDATE_WOL_ADDR;

	status = nse_aq_manage_mac_write(hw, mac, wflags, 0);
	if (status) {
		netdev_err(netdev, "can't set MAC %pM. write to firmware failed error %s\n",
			   mac, nse_stat_str(status));
	}
	return 0;
}

/**
 * nse_max_xdp_frame_size - returns the maximum allowed frame size for XDP
 * @vsi: Pointer to VSI structure
 */
static int nse_max_xdp_frame_size(struct nse_vsi *vsi)
{
	if (PAGE_SIZE >= 8192 || test_bit(NSE_FLAG_LEGACY_RX, vsi->back->flags))
		return NSE_RXBUF_2048 - XDP_PACKET_HEADROOM;
	else
		return NSE_RXBUF_3072;
}

/**
 * nse_check_mtu_valid - check if specified MTU can be set for a netdev
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 if MTU is valid, negative otherwise
 */
int nse_check_mtu_valid(struct net_device *netdev, int new_mtu)
{
	if (new_mtu < (int)netdev->min_mtu) {
		netdev_err(netdev, "new MTU invalid. min_mtu is %d\n",
			   netdev->min_mtu);
		return -EINVAL;
	} else if (new_mtu > (int)netdev->max_mtu) {
		netdev_err(netdev, "new MTU invalid. max_mtu is %d\n",
			   netdev->min_mtu);
		return -EINVAL;
	}

	return 0;
}

/**
 * nse_change_mtu - NDO callback to change the MTU
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 on success, negative on failure
 */
static int nse_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;
	u8 count = 0;
	int err = 0;

	if (new_mtu == (int)netdev->mtu) {
		netdev_warn(netdev, "MTU is already %u\n", netdev->mtu);
		return 0;
	}

	if (nse_is_xdp_ena_vsi(vsi)) {
		int frame_size = nse_max_xdp_frame_size(vsi);

		if (new_mtu + NSE_ETH_PKT_HDR_PAD > frame_size) {
			netdev_err(netdev, "max MTU for XDP usage is %d\n",
				   frame_size - NSE_ETH_PKT_HDR_PAD);
			return -EINVAL;
		}
	}

	err = nse_check_mtu_valid(netdev, new_mtu);
	if (err)
		return err;

	/* if a reset is in progress, wait for some time for it to complete */
	do {
		if (nse_is_reset_in_progress(pf->state)) {
			count++;
			usleep_range(1000, 2000);
		} else {
			break;
		}

	} while (count < 100);

	if (count == 100) {
		netdev_err(netdev, "can't change MTU. Device is busy\n");
		return -EBUSY;
	}

	netdev->mtu = (unsigned int)new_mtu;

	/* if VSI is up, bring it down and then back up */
	if (!test_and_set_bit(NSE_VSI_DOWN, vsi->state)) {
		err = nse_down(vsi);
		if (err) {
			netdev_err(netdev, "change MTU if_down err %d\n", err);
			return err;
		}

		err = nse_up(vsi);
		if (err) {
			netdev_err(netdev, "change MTU if_up err %d\n", err);
			return err;
		}
	}

	netdev_dbg(netdev, "changed MTU to %d\n", new_mtu);
	set_bit(NSE_FLAG_MTU_CHANGED, pf->flags);

	return 0;
}

/**
 * nse_fetch_u64_stats_per_ring - get packets and bytes stats per ring
 * @ring: Tx or Rx ring to read stats from
 * @pkts: packets stats counter
 * @bytes: bytes stats counter
 *
 * This function fetches stats from the ring considering the atomic operations
 * that needs to be performed to read u64 values in 32 bit machine.
 */
void
nse_fetch_u64_stats_per_ring(struct nse_ring *ring, u64 *pkts, u64 *bytes)
{
	unsigned int start;
	*pkts = 0;
	*bytes = 0;

	if (!ring)
		return;
	do {
		start = u64_stats_fetch_begin(&ring->syncp);
		*pkts = ring->stats.pkts;
		*bytes = ring->stats.bytes;
	} while (u64_stats_fetch_retry(&ring->syncp, start));
}

/**
 * nse_update_vsi_tx_ring_stats - Update VSI Tx ring stats counters
 * @vsi: the VSI to be updated
 * @vsi_stats: the stats struct to be updated
 * @rings: rings to work on
 * @count: number of rings
 */
static void
nse_update_vsi_tx_ring_stats(struct nse_vsi __always_unused *vsi,
				struct nse_vsi_sw_stats *ss,
				struct nse_ring **rings,
				u16 count)
{
	struct nse_ring *ring;
	u64 pkts, bytes;
	u16 i;

	if (!rings)
		return;

	for (i = 0; i < count; i++) {
		ring = rings[i];

		if (!ring)
			continue;

		nse_fetch_u64_stats_per_ring(ring, &pkts, &bytes);
		ss->tx_pkts += pkts;
		ss->tx_bytes += bytes;

		ss->tx_restart += ring->tx_stats.restart_q;
		ss->tx_busy += ring->tx_stats.tx_busy;
		ss->tx_linearize += ring->tx_stats.tx_linearize;
	}
}

static void
nse_update_vsi_rx_ring_stats(struct nse_vsi __always_unused *vsi,
				struct nse_vsi_sw_stats *ss,
				struct nse_ring **rings,
				u16 count)
{
	struct nse_ring *ring;
	u64 pkts, bytes;
	u16 i;

	if (!rings)
		return;

	for (i = 0; i < count; i++) {
		ring = rings[i];

		if (!ring)
			continue;

		nse_fetch_u64_stats_per_ring(ring, &pkts, &bytes);
		ss->rx_pkts += pkts;
		ss->rx_bytes += bytes;

		ss->rx_csum_good += ring->rx_stats.rx_csum_good;
		ss->rx_csum_bad += ring->rx_stats.rx_csum_bad;

		ss->fdir_match += ring->rx_stats.qsrc_cnt[NSE_RXD_QSRC_FD];
		ss->fdir_miss += ring->rx_stats.qsrc_cnt[NSE_RXD_QSRC_RSS];

		ss->rx_buf_failed += ring->rx_stats.alloc_buf_failed;
		ss->rx_page_failed += ring->rx_stats.alloc_page_failed;
#ifdef NSE_ADD_PROBES
		ss->rx_page_reuse += ring->rx_stats.page_reuse;
#endif /* NSE_ADD_PROBES */
	}
}

/**
 * nse_update_vsi_sw_stats - Update VSI sw_stats counters
 * @vsi: the VSI to be updated
 */
void nse_update_vsi_sw_stats(struct nse_vsi *vsi)
{
	struct nse_vsi_sw_stats *cur_ss, *prev_ss, *new_ss;

	cur_ss = &vsi->sw_stats;
	prev_ss = &vsi->sw_stats_prev;
	new_ss = &vsi->sw_stats_new;

	memset(new_ss, 0, sizeof(*new_ss));

	if (!nse_is_vsi_type_under_pf_drv(vsi->type)) {
		new_ss->rx_pkts = vsi->hw_stats.rx_gpkt;
		new_ss->rx_bytes = vsi->hw_stats.rx_goct;
		new_ss->tx_pkts = vsi->hw_stats.tx_gptc;
		new_ss->tx_bytes = vsi->hw_stats.tx_gotc;
	} else {
		rcu_read_lock();

		/* update Tx rings counters */
		nse_update_vsi_tx_ring_stats(vsi, new_ss, vsi->tx_rings, vsi->num_txq);

		/* update Rx rings counters */
		nse_update_vsi_rx_ring_stats(vsi, new_ss, vsi->rx_rings, vsi->num_rxq);

		/* update XDP Tx rings counters */
		if (nse_is_xdp_ena_vsi(vsi))
			nse_update_vsi_tx_ring_stats(vsi, new_ss, vsi->xdp_rings, vsi->num_xdp_txq);

		rcu_read_unlock();
	}

	nse_stat_update64(new_ss->rx_pkts, vsi->sw_stats_prev_loaded,
						&prev_ss->rx_pkts, &cur_ss->rx_pkts);
	nse_stat_update64(new_ss->rx_bytes, vsi->sw_stats_prev_loaded,
						&prev_ss->rx_bytes, &cur_ss->rx_bytes);
	nse_stat_update64(new_ss->tx_pkts, vsi->sw_stats_prev_loaded,
						&prev_ss->tx_pkts, &cur_ss->tx_pkts);
	nse_stat_update64(new_ss->tx_bytes, vsi->sw_stats_prev_loaded,
						&prev_ss->tx_bytes, &cur_ss->tx_bytes);
	nse_stat_update64(new_ss->tx_linearize, vsi->sw_stats_prev_loaded,
						&prev_ss->tx_linearize, &cur_ss->tx_linearize);
	nse_stat_update64(new_ss->tx_restart, vsi->sw_stats_prev_loaded,
						&prev_ss->tx_restart, &cur_ss->tx_restart);
	nse_stat_update64(new_ss->tx_busy, vsi->sw_stats_prev_loaded,
						&prev_ss->tx_busy, &cur_ss->tx_busy);
	nse_stat_update64(new_ss->rx_csum_good, vsi->sw_stats_prev_loaded,
						&prev_ss->rx_csum_good, &cur_ss->rx_csum_good);
	nse_stat_update64(new_ss->rx_csum_bad, vsi->sw_stats_prev_loaded,
						&prev_ss->rx_csum_bad, &cur_ss->rx_csum_bad);
	nse_stat_update64(new_ss->fdir_match, vsi->sw_stats_prev_loaded,
						&prev_ss->fdir_match, &cur_ss->fdir_match);
	nse_stat_update64(new_ss->fdir_miss, vsi->sw_stats_prev_loaded,
						&prev_ss->fdir_miss, &cur_ss->fdir_miss);
	nse_stat_update64(new_ss->rx_buf_failed, vsi->sw_stats_prev_loaded,
						&prev_ss->rx_buf_failed, &cur_ss->rx_buf_failed);
	nse_stat_update64(new_ss->rx_page_failed, vsi->sw_stats_prev_loaded,
						&prev_ss->rx_page_failed, &cur_ss->rx_page_failed);
#ifdef NSE_ADD_PROBES
	nse_stat_update64(new_ss->rx_page_reuse, vsi->sw_stats_prev_loaded,
						&prev_ss->rx_page_reuse, &cur_ss->rx_page_reuse);
#endif

	vsi->sw_stats_prev_loaded = true;
}

static void nse_update_vsi_net_stats(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_vsi_hw_stats *cur_hs = &vsi->hw_stats;
	struct nse_vsi_sw_stats *cur_ss = &vsi->sw_stats;
	struct rtnl_link_stats64 *cur_ns = &vsi->net_stats;

	/* use sw_stats or hw_stats */
	if (nse_is_vsi_type_under_pf_drv(vsi->type)) {
		cur_ns->rx_packets = cur_ss->rx_pkts;
		cur_ns->rx_bytes = cur_ss->rx_bytes;
		cur_ns->tx_packets = cur_ss->tx_pkts;
		cur_ns->tx_bytes = cur_ss->tx_bytes;

	} else {
		cur_ns->rx_packets = cur_hs->rx_gpkt;
		cur_ns->tx_packets = cur_hs->tx_gptc;
		cur_ns->rx_bytes = cur_hs->rx_goct;
		cur_ns->tx_bytes = cur_hs->tx_gotc;
	}

	cur_ns->tx_errors = cur_hs->tx_dptc;
	cur_ns->rx_dropped = cur_hs->rx_dpkt;
	cur_ns->tx_dropped = cur_hs->tx_dptc;
	cur_ns->multicast = cur_hs->rx_mpkt + cur_hs->rx_bpkt;

	/* update some more netdev stats if this is main VSI */
	if (vsi->type == NSE_VSI_PF) {
		/* record drops from the port level */
		cur_ns->rx_errors = pf->stats.rx_crc_error +
				    pf->stats.rx_runt_error +
				    pf->stats.rx_jabber_error +
				    pf->stats.rx_length_error;

		cur_ns->rx_length_errors = pf->stats.rx_length_error;

		cur_ns->rx_crc_errors = pf->stats.rx_crc_error;
	}
}

/**
 * nse_update_vsi_stats - Update VSI stats counters
 * @vsi: the VSI to be updated
 */
void nse_update_vsi_stats(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;

	if (test_bit(NSE_VSI_DOWN, vsi->state) ||
	    test_bit(NSE_CFG_BUSY, pf->state))
		return;

	/* get VSI stats as recorded by the hardware */
	nse_update_vsi_hw_stats(vsi);

	/* get stats as recorded by Tx/Rx rings */
	nse_update_vsi_sw_stats(vsi);

	/* update vsi -> struct rtnl_link_stats64 net_stats; for network stack */
	nse_update_vsi_net_stats(vsi);
}

static void pf_stats_raw_2_normalized_lmac_type1(struct nse_hw_port_stats *cur,
						 struct nse_hw_port_stats *dst,
	struct nse_hw_port_stats_raw *src)
{
	struct nse_aqc_lmac_stats_type1 *raw_lmac_stats = &src->raw_lmac_stats.stats_type1;
	struct nse_aqc_rc_dma_chan_total_stats *raw_dma_chan_total_stats
			       = &src->raw_dma_chan_total_stats;
	int i;

	memset(dst, 0, sizeof(*dst));

#define RAW_LMAC_TYPE1_TX_STATS_LO_HI_SRC_2_DST(dst_field_name, src_idx_name)	\
		(dst->dst_field_name = \
		 ((u64)le32_to_cpu(raw_lmac_stats->tx_stats[LMAC_TYPE1_##src_idx_name##_Low])) \
	| ((u64)le32_to_cpu(raw_lmac_stats->tx_stats[LMAC_TYPE1_##src_idx_name##_High]) << 32))

	RAW_LMAC_TYPE1_TX_STATS_LO_HI_SRC_2_DST(tx_bytes_good_bad, Tx_Octet_Count_Good_Bad);
	RAW_LMAC_TYPE1_TX_STATS_LO_HI_SRC_2_DST(tx_pkts_good_bad, Tx_Frame_Count_Good_Bad);
	RAW_LMAC_TYPE1_TX_STATS_LO_HI_SRC_2_DST(tx_broadcast_good, Tx_Broadcast_Frames_Good);
	RAW_LMAC_TYPE1_TX_STATS_LO_HI_SRC_2_DST(tx_multicast_good, Tx_Multicast_Frames_Good);
	RAW_LMAC_TYPE1_TX_STATS_LO_HI_SRC_2_DST(tx_64_good_bad, Tx_64Octets_Frames_Good_Bad);
	RAW_LMAC_TYPE1_TX_STATS_LO_HI_SRC_2_DST(tx_64_to_127_good_bad,
						Tx_65To127Octets_Frames_Good_Bad);
	RAW_LMAC_TYPE1_TX_STATS_LO_HI_SRC_2_DST(tx_128_to_255_good_bad,
						Tx_128To255Octets_Frames_Good_Bad);
	RAW_LMAC_TYPE1_TX_STATS_LO_HI_SRC_2_DST(tx_256_to_511_good_bad,
						Tx_256To511Octets_Frames_Good_Bad);
	RAW_LMAC_TYPE1_TX_STATS_LO_HI_SRC_2_DST(tx_512_to_1023_good_bad,
						Tx_512To1023Octets_Frames_Good_Bad);
	RAW_LMAC_TYPE1_TX_STATS_LO_HI_SRC_2_DST(tx_1024_to_max_good_bad,
						Tx_1024ToMaxOctets_Frames_Good_Bad);
	RAW_LMAC_TYPE1_TX_STATS_LO_HI_SRC_2_DST(tx_unicast_good_bad, Tx_Unicast_Frames_Good_Bad);
	RAW_LMAC_TYPE1_TX_STATS_LO_HI_SRC_2_DST(tx_multicast_good_bad,
						Tx_Multicast_Frames_Good_Bad);
	RAW_LMAC_TYPE1_TX_STATS_LO_HI_SRC_2_DST(tx_broadcast_good_bad,
						Tx_Broadcast_Frames_Good_Bad);
	RAW_LMAC_TYPE1_TX_STATS_LO_HI_SRC_2_DST(tx_underflow_error, Tx_Underflow_Error_Frames);
	RAW_LMAC_TYPE1_TX_STATS_LO_HI_SRC_2_DST(tx_bytes_good, Tx_Octet_Count_Good);
	RAW_LMAC_TYPE1_TX_STATS_LO_HI_SRC_2_DST(tx_pkts_good, Tx_Frame_Count_Good);
	RAW_LMAC_TYPE1_TX_STATS_LO_HI_SRC_2_DST(tx_lfc, Tx_Pause_Frames);

#define RAW_LMAC_TYPE1_RX_STATS_LO_HI_SRC_2_DST(dst_field_name, src_idx_name)	\
		(dst->dst_field_name = \
		 ((u64)le32_to_cpu(raw_lmac_stats->rx_stats[LMAC_TYPE1_##src_idx_name##_Low])) \
	| ((u64)le32_to_cpu(raw_lmac_stats->rx_stats[LMAC_TYPE1_##src_idx_name##_High]) << 32))

	RAW_LMAC_TYPE1_RX_STATS_LO_HI_SRC_2_DST(rx_pkts_good_bad, Rx_Frame_Count_Good_Bad);
	RAW_LMAC_TYPE1_RX_STATS_LO_HI_SRC_2_DST(rx_bytes_good_bad, Rx_Octet_Count_Good_Bad);
	RAW_LMAC_TYPE1_RX_STATS_LO_HI_SRC_2_DST(rx_bytes_good, Rx_Octet_Count_Good);
	RAW_LMAC_TYPE1_RX_STATS_LO_HI_SRC_2_DST(rx_broadcast_good, Rx_Broadcast_Frames_Good);
	RAW_LMAC_TYPE1_RX_STATS_LO_HI_SRC_2_DST(rx_multicast_good, Rx_Multicast_Frames_Good);
	RAW_LMAC_TYPE1_RX_STATS_LO_HI_SRC_2_DST(rx_crc_error, Rx_CRC_Error_Frames);
	dst->rx_runt_error =
		(u64)le32_to_cpu(raw_lmac_stats->rx_stats[LMAC_TYPE1_Rx_Runt_Error_Frames]);
	dst->rx_jabber_error =
		(u64)le32_to_cpu(raw_lmac_stats->rx_stats[LMAC_TYPE1_Rx_Jabber_Error_Frames]);
	dst->rx_undersize_good =
		(u64)le32_to_cpu(raw_lmac_stats->rx_stats[LMAC_TYPE1_Rx_Undersize_Frames_Good]);
	dst->rx_oversize_good =
		(u64)le32_to_cpu(raw_lmac_stats->rx_stats[LMAC_TYPE1_Rx_Oversize_Frames_Good]);
	RAW_LMAC_TYPE1_RX_STATS_LO_HI_SRC_2_DST(rx_64_good_bad, Rx_64Octets_Frames_Good_Bad);
	RAW_LMAC_TYPE1_RX_STATS_LO_HI_SRC_2_DST(rx_64_to_127_good_bad,
						Rx_65To127Octets_Frames_Good_Bad);
	RAW_LMAC_TYPE1_RX_STATS_LO_HI_SRC_2_DST(rx_128_to_255_good_bad,
						Rx_128To255Octets_Frames_Good_Bad);
	RAW_LMAC_TYPE1_RX_STATS_LO_HI_SRC_2_DST(rx_256_to_511_good_bad,
						Rx_256To511Octets_Frames_Good_Bad);
	RAW_LMAC_TYPE1_RX_STATS_LO_HI_SRC_2_DST(rx_512_to_1023_good_bad,
						Rx_512To1023Octets_Frames_Good_Bad);
	RAW_LMAC_TYPE1_RX_STATS_LO_HI_SRC_2_DST(rx_1024_to_max_good_bad,
						Rx_1024ToMaxOctets_Frames_Good_Bad);
	RAW_LMAC_TYPE1_RX_STATS_LO_HI_SRC_2_DST(rx_unicast_good, Rx_Unicast_Frames_Good);
	RAW_LMAC_TYPE1_RX_STATS_LO_HI_SRC_2_DST(rx_length_error, Rx_Length_Error_Frames);
	RAW_LMAC_TYPE1_RX_STATS_LO_HI_SRC_2_DST(rx_out_of_range, Rx_OutofRange_Frames);
	RAW_LMAC_TYPE1_RX_STATS_LO_HI_SRC_2_DST(rx_lfc, Rx_Pause_Frames);

	dst->fdir_match = cur->fdir_match + le32_to_cpu(raw_dma_chan_total_stats->fdir_match_cnt);
	dst->fdir_miss = cur->fdir_miss + le32_to_cpu(raw_dma_chan_total_stats->fdir_miss_cnt);

	dst->tx_lfc_xoff = le32_to_cpu(raw_lmac_stats->fc_lxofftxc);
	dst->tx_lfc_xon = le32_to_cpu(raw_lmac_stats->fc_lxontxc);
	dst->rx_lfc_xoff = le32_to_cpu(raw_lmac_stats->fc_lxoffrxc);
	dst->rx_lfc_xon = le32_to_cpu(raw_lmac_stats->fc_lxonrxc);

	for (i = 0; i < 8; i++) {
		dst->tx_pfc_xoff[i] = le32_to_cpu(raw_lmac_stats->fc_pxofftxc[i]);
		dst->tx_pfc_xon[i] = le32_to_cpu(raw_lmac_stats->fc_pxontxc[i]);
		dst->rx_pfc_xoff[i] = le32_to_cpu(raw_lmac_stats->fc_pxoffrxc[i]);
		dst->rx_pfc_xon[i] = le32_to_cpu(raw_lmac_stats->fc_pxonrxc[i]);
	}
}

static void pf_stats_raw_2_normalized_and_update_lmac_type1(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_hw_port_stats *prev_ps, *cur_ps, *new_ps;
	int i;

	cur_ps = &pf->stats;
	prev_ps = &pf->stats_prev;
	new_ps = &pf->stats_new;

	pf_stats_raw_2_normalized_lmac_type1(cur_ps, new_ps, &pf->stats_raw);

//	nse_dump_pf_stats(pf, new_ps);

#define UPDATE_PF_STATS_ONE_COUNTER(cname)	\
	nse_stat_update64(new_ps->cname, pf->stat_prev_loaded,\
				&prev_ps->cname,\
				&cur_ps->cname)

	UPDATE_PF_STATS_ONE_COUNTER(tx_bytes_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(tx_pkts_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(tx_broadcast_good);
	UPDATE_PF_STATS_ONE_COUNTER(tx_multicast_good);
	UPDATE_PF_STATS_ONE_COUNTER(tx_64_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(tx_64_to_127_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(tx_128_to_255_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(tx_256_to_511_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(tx_512_to_1023_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(tx_1024_to_max_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(tx_unicast_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(tx_multicast_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(tx_broadcast_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(tx_underflow_error);
	UPDATE_PF_STATS_ONE_COUNTER(tx_bytes_good);
	UPDATE_PF_STATS_ONE_COUNTER(tx_pkts_good);
	UPDATE_PF_STATS_ONE_COUNTER(tx_lfc);

	UPDATE_PF_STATS_ONE_COUNTER(rx_pkts_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(rx_bytes_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(rx_bytes_good);
	UPDATE_PF_STATS_ONE_COUNTER(rx_broadcast_good);
	UPDATE_PF_STATS_ONE_COUNTER(rx_multicast_good);
	UPDATE_PF_STATS_ONE_COUNTER(rx_crc_error);
	UPDATE_PF_STATS_ONE_COUNTER(rx_runt_error);
	UPDATE_PF_STATS_ONE_COUNTER(rx_jabber_error);
	UPDATE_PF_STATS_ONE_COUNTER(rx_undersize_good);
	UPDATE_PF_STATS_ONE_COUNTER(rx_oversize_good);
	UPDATE_PF_STATS_ONE_COUNTER(rx_64_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(rx_64_to_127_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(rx_128_to_255_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(rx_256_to_511_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(rx_512_to_1023_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(rx_1024_to_max_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(rx_unicast_good);
	UPDATE_PF_STATS_ONE_COUNTER(rx_length_error);
	UPDATE_PF_STATS_ONE_COUNTER(rx_out_of_range);
	UPDATE_PF_STATS_ONE_COUNTER(rx_lfc);

	UPDATE_PF_STATS_ONE_COUNTER(tx_lfc_xoff);
	UPDATE_PF_STATS_ONE_COUNTER(tx_lfc_xon);
	UPDATE_PF_STATS_ONE_COUNTER(rx_lfc_xoff);
	UPDATE_PF_STATS_ONE_COUNTER(rx_lfc_xon);

	for (i = 0; i < 8; i++) {
		UPDATE_PF_STATS_ONE_COUNTER(tx_pfc_xoff[i]);
		UPDATE_PF_STATS_ONE_COUNTER(tx_pfc_xon[i]);
		UPDATE_PF_STATS_ONE_COUNTER(rx_pfc_xoff[i]);
		UPDATE_PF_STATS_ONE_COUNTER(rx_pfc_xon[i]);
	}

	cur_ps->rx_error = cur_ps->rx_length_error + cur_ps->rx_crc_error
						+ cur_ps->rx_runt_error + cur_ps->rx_jabber_error;

	if (cur_ps->tx_bytes_good_bad > cur_ps->tx_bytes_good)
		cur_ps->tx_bytes_bad = (cur_ps->tx_bytes_good_bad - cur_ps->tx_bytes_good);

	if (cur_ps->tx_pkts_good_bad > cur_ps->tx_pkts_good)
		cur_ps->tx_pkts_bad = (cur_ps->tx_pkts_good_bad - cur_ps->tx_pkts_good);

	if (cur_ps->tx_broadcast_good_bad > cur_ps->tx_broadcast_good)
		cur_ps->tx_broadcast_bad = (cur_ps->tx_broadcast_good_bad -
					    cur_ps->tx_broadcast_good);

	if (cur_ps->tx_multicast_good_bad > cur_ps->tx_multicast_good)
		cur_ps->tx_multicast_bad = (cur_ps->tx_multicast_good_bad -
					    cur_ps->tx_multicast_good);

	if (cur_ps->tx_pkts_good > (cur_ps->tx_broadcast_good + cur_ps->tx_multicast_good))
		cur_ps->tx_unicast_good = (cur_ps->tx_pkts_good - cur_ps->tx_broadcast_good -
					   cur_ps->tx_multicast_good);

	if (cur_ps->tx_unicast_good_bad > cur_ps->tx_unicast_good)
		cur_ps->tx_unicast_bad = (cur_ps->tx_unicast_good_bad - cur_ps->tx_unicast_good);

	cur_ps->rx_pkts_good = cur_ps->rx_broadcast_good +
		cur_ps->rx_multicast_good + cur_ps->rx_unicast_good;

	if (cur_ps->rx_pkts_good_bad > cur_ps->rx_pkts_good)
		cur_ps->rx_pkts_bad = (cur_ps->rx_pkts_good_bad - cur_ps->rx_pkts_good);

	if (cur_ps->rx_bytes_good_bad > cur_ps->rx_bytes_good)
		cur_ps->rx_bytes_bad = (cur_ps->rx_bytes_good_bad - cur_ps->rx_bytes_good);

	/*  type1 can't calculate, if a rx_pkt is bad, then can not differentiate if it is BC/MC/UC
	 */
	cur_ps->rx_broadcast_bad = 0;
	cur_ps->rx_multicast_bad = 0;
	cur_ps->rx_unicast_bad = 0;

	cur_ps->rx_unicast_good_bad = cur_ps->rx_unicast_good;

//	nse_dump_pf_stats(pf, cur_ps);
}

static void pf_stats_raw_2_normalized_lmac_type2(struct nse_hw_port_stats *cur,
						 struct nse_hw_port_stats *dst,
	struct nse_hw_port_stats_raw *src)
{
	struct nse_aqc_lmac_stats_type2 *raw_lmac_stats = &src->raw_lmac_stats.stats_type2;

	memset(dst, 0, sizeof(*dst));

#define RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(dst_field_name, src_idx_name)	\
		(dst->dst_field_name += \
		 (((u64)le32_to_cpu(raw_lmac_stats->tx_stats[LMAC_TYPE2_##src_idx_name##_lo])) \
	| ((u64)le32_to_cpu(raw_lmac_stats->tx_stats[LMAC_TYPE2_##src_idx_name##_hi]) << 32)))

	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_64_good_bad, cntr_tx_64b);
	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_64_to_127_good_bad, cntr_tx_65to127b);
	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_128_to_255_good_bad, cntr_tx_128to255b);
	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_256_to_511_good_bad, cntr_tx_256to511b);
	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_512_to_1023_good_bad, cntr_tx_512to1023b);
	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_1024_to_max_good_bad, cntr_tx_1024to1518b);
	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_1024_to_max_good_bad, cntr_tx_1519tomaxb);

	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_unicast_good_bad, cntr_tx_ucast_data_err);
	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_unicast_good_bad, cntr_tx_ucast_ctrl_err);
	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_unicast_good_bad, cntr_tx_ucast_data_ok);
	//ctrl_ok
	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_unicast_good_bad, cntr_tx_ucast_ctrl);

	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_unicast_good, cntr_tx_ucast_data_ok);
	//ctrl_ok
	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_unicast_good, cntr_tx_ucast_ctrl);

	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_unicast_bad, cntr_tx_ucast_data_err);
	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_unicast_bad, cntr_tx_ucast_ctrl_err);

	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_multicast_good_bad, cntr_tx_mcast_data_err);
	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_multicast_good_bad, cntr_tx_mcast_ctrl_err);
	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_multicast_good_bad, cntr_tx_mcast_data_ok);
	//ctrl_ok
	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_multicast_good_bad, cntr_tx_mcast_ctrl);

	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_multicast_good, cntr_tx_mcast_data_ok);
	//ctrl_ok
	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_multicast_good, cntr_tx_mcast_ctrl);

	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_multicast_bad, cntr_tx_mcast_data_err);
	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_multicast_bad, cntr_tx_mcast_ctrl_err);

	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_broadcast_good_bad, cntr_tx_bcast_data_err);
	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_broadcast_good_bad, cntr_tx_bcast_ctrl_err);
	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_broadcast_good_bad, cntr_tx_bcast_data_ok);
	//ctrl_ok
	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_broadcast_good_bad, cntr_tx_bcast_ctrl);

	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_broadcast_good, cntr_tx_bcast_data_ok);
	//ctrl_ok
	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_broadcast_good, cntr_tx_bcast_ctrl);

	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_broadcast_bad, cntr_tx_bcast_data_err);
	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_broadcast_bad, cntr_tx_bcast_ctrl_err);

	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_lfc, cntr_tx_pause);
	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_pfc, cntr_tx_pfc);

	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_bytes_good_bad, cntr_tx_octetsok);

	RAW_LMAC_TYPE2_TX_STATS_SRC_ADD_TO_DST_LO_HI(tx_bytes_good, cntr_tx_payloadoctetsok);

#define RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(dst_field_name, src_idx_name)	\
		(dst->dst_field_name += \
		 (((u64)le32_to_cpu(raw_lmac_stats->rx_stats[LMAC_TYPE2_##src_idx_name##_lo])) \
	| ((u64)le32_to_cpu(raw_lmac_stats->rx_stats[LMAC_TYPE2_##src_idx_name##_hi]) << 32)))

	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_64_good_bad, cntr_rx_64b);
	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_64_to_127_good_bad, cntr_rx_65to127b);
	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_128_to_255_good_bad, cntr_rx_128to255b);
	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_256_to_511_good_bad, cntr_rx_256to511b);
	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_512_to_1023_good_bad, cntr_rx_512to1023b);
	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_1024_to_max_good_bad, cntr_rx_1024to1518b);
	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_1024_to_max_good_bad, cntr_rx_1519tomaxb);

	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_broadcast_good, cntr_rx_bcast_data_ok);
	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_broadcast_good, cntr_rx_bcast_ctrl);

	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_broadcast_bad, cntr_rx_bcast_data_err);
	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_broadcast_bad, cntr_rx_bcast_ctrl_err);

	dst->rx_broadcast_good_bad = dst->rx_broadcast_good + dst->rx_broadcast_bad;

	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_multicast_good, cntr_rx_mcast_data_ok);
	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_multicast_good, cntr_rx_mcast_ctrl);

	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_multicast_bad, cntr_rx_mcast_data_err);
	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_multicast_bad, cntr_rx_mcast_ctrl_err);

	dst->rx_multicast_good_bad = dst->rx_multicast_good + dst->rx_multicast_bad;

	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_unicast_good, cntr_rx_ucast_data_ok);
	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_unicast_good, cntr_rx_ucast_ctrl);

	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_unicast_bad, cntr_rx_ucast_data_err);
	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_unicast_bad, cntr_rx_ucast_ctrl_err);

	dst->rx_unicast_good_bad = dst->rx_unicast_good + dst->rx_unicast_bad;

	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_lfc, cntr_rx_pause);
	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_pfc, cntr_rx_pfc);

	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_crc_error, cntr_rx_fcs_err_okpkt);

	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_runt_error, cntr_rx_runt);

	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_jabber_error, cntr_rx_jabbers);

	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_oversize_good, cntr_rx_oversize);

	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_length_error, cntr_rx_lenerr);
	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_out_of_range, cntr_rx_lenerr);

	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_bytes_good_bad, cntr_rx_octetsok);

	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_bytes_good, cntr_rx_payloadoctetsok);

	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_error, cntr_rx_fragments);
	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_error, cntr_rx_jabbers);
	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_error, cntr_rx_fcs_err_okpkt);
	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_error, cntr_rx_pause_err);
	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_error, cntr_rx_lenerr);
	RAW_LMAC_TYPE2_RX_STATS_SRC_ADD_TO_DST_LO_HI(rx_error, cntr_rx_pfc_err);
}

static void pf_stats_raw_2_normalized_and_update_lmac_type2(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_hw_port_stats *prev_ps, *cur_ps, *new_ps;

	cur_ps = &pf->stats;
	prev_ps = &pf->stats_prev;
	new_ps = &pf->stats_new;

	pf_stats_raw_2_normalized_lmac_type2(cur_ps, new_ps, &pf->stats_raw);

//	nse_dump_pf_stats(pf, new_ps);

	UPDATE_PF_STATS_ONE_COUNTER(tx_bytes_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(tx_bytes_good);
	UPDATE_PF_STATS_ONE_COUNTER(tx_broadcast_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(tx_broadcast_good);
	UPDATE_PF_STATS_ONE_COUNTER(tx_broadcast_bad);
	UPDATE_PF_STATS_ONE_COUNTER(tx_multicast_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(tx_multicast_good);
	UPDATE_PF_STATS_ONE_COUNTER(tx_multicast_bad);
	UPDATE_PF_STATS_ONE_COUNTER(tx_unicast_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(tx_unicast_good);
	UPDATE_PF_STATS_ONE_COUNTER(tx_unicast_bad);
	UPDATE_PF_STATS_ONE_COUNTER(tx_64_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(tx_64_to_127_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(tx_128_to_255_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(tx_256_to_511_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(tx_512_to_1023_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(tx_1024_to_max_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(tx_lfc);
	UPDATE_PF_STATS_ONE_COUNTER(tx_pfc);

	cur_ps->tx_pkts_good_bad = cur_ps->tx_broadcast_good_bad +
								cur_ps->tx_multicast_good_bad +
								cur_ps->tx_unicast_good_bad;

	cur_ps->tx_pkts_good = cur_ps->tx_broadcast_good +
								cur_ps->tx_multicast_good +
								cur_ps->tx_unicast_good;

	if (cur_ps->tx_pkts_good_bad > cur_ps->tx_pkts_good)
		cur_ps->tx_pkts_bad = cur_ps->tx_pkts_good_bad - cur_ps->tx_pkts_good;

	if (cur_ps->tx_bytes_good_bad > cur_ps->tx_bytes_good)
		cur_ps->tx_bytes_bad = cur_ps->tx_bytes_good_bad - cur_ps->tx_bytes_good;

	UPDATE_PF_STATS_ONE_COUNTER(rx_bytes_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(rx_bytes_good);
	UPDATE_PF_STATS_ONE_COUNTER(rx_broadcast_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(rx_broadcast_good);
	UPDATE_PF_STATS_ONE_COUNTER(rx_broadcast_bad);
	UPDATE_PF_STATS_ONE_COUNTER(rx_multicast_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(rx_multicast_good);
	UPDATE_PF_STATS_ONE_COUNTER(rx_multicast_bad);
	UPDATE_PF_STATS_ONE_COUNTER(rx_unicast_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(rx_unicast_good);
	UPDATE_PF_STATS_ONE_COUNTER(rx_unicast_bad);
	UPDATE_PF_STATS_ONE_COUNTER(rx_crc_error);
	UPDATE_PF_STATS_ONE_COUNTER(rx_runt_error);
	UPDATE_PF_STATS_ONE_COUNTER(rx_jabber_error);
	UPDATE_PF_STATS_ONE_COUNTER(rx_length_error);
	UPDATE_PF_STATS_ONE_COUNTER(rx_out_of_range);
	UPDATE_PF_STATS_ONE_COUNTER(rx_oversize_good);
	UPDATE_PF_STATS_ONE_COUNTER(rx_64_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(rx_64_to_127_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(rx_128_to_255_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(rx_256_to_511_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(rx_512_to_1023_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(rx_1024_to_max_good_bad);
	UPDATE_PF_STATS_ONE_COUNTER(rx_lfc);
	UPDATE_PF_STATS_ONE_COUNTER(rx_pfc);

	cur_ps->rx_pkts_good_bad = cur_ps->rx_broadcast_good_bad +
								cur_ps->rx_multicast_good_bad +
								cur_ps->rx_unicast_good_bad;

	cur_ps->rx_pkts_good = cur_ps->rx_broadcast_good +
								cur_ps->rx_multicast_good +
								cur_ps->rx_unicast_good;

	if (cur_ps->rx_pkts_good_bad > cur_ps->rx_pkts_good)
		cur_ps->rx_pkts_bad = cur_ps->rx_pkts_good_bad - cur_ps->rx_pkts_good;

	if (cur_ps->rx_bytes_good_bad > cur_ps->rx_bytes_good)
		cur_ps->rx_bytes_bad = cur_ps->rx_bytes_good_bad - cur_ps->rx_bytes_good;

//	nse_dump_pf_stats(pf, cur_ps);
}

static void pf_stats_raw_2_normalized_and_update(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;

	if (hw->hw_conf.hw_lmac_type == NSE_HW_LMAC_TYPE_1)
		pf_stats_raw_2_normalized_and_update_lmac_type1(hw);
	else if (hw->hw_conf.hw_lmac_type == NSE_HW_LMAC_TYPE_2)
		pf_stats_raw_2_normalized_and_update_lmac_type2(hw);

	pf->stat_prev_loaded = true;
}

/**
 * nse_update_pf_stats - Update PF port stats counters
 * @pf: PF whose stats needs to be updated
 */
void nse_update_pf_stats(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;
	enum nse_status status;

	if (preempt_count() != 0 || rcu_preempt_depth()) {
		nse_debug(hw, NSE_DBG_MISC_DETAIL, "[%s] in atomic or rcu critical section, don't update_pf_stats() for now, leaving for watchdog_task\n", __func__);

		pf->wd_subtask_flags |= WD_SUBTASK_FLAG_UPDATE_PF_STATS_NOW;

		return;
	}

	status = nse_aq_lmac_read_stats(hw, &pf->stats_raw.raw_lmac_stats);
	if (status) {
		dev_info(nse_pf_to_dev(pf), "[%s, %d] aq_lmac_read_stats() fails, %d(%s)\n",
				__func__, __LINE__,
				status, nse_stat_str(status));
		return;
	}

	status = nse_read_dma_chan_total_stats(hw, &pf->stats_raw.raw_dma_chan_total_stats);
	if (status) {
		dev_info(nse_pf_to_dev(pf), "[%s, %d] read_lan_channel_total_stats() fails, %d(%s)\n",
				__func__, __LINE__,
				status, nse_stat_str(status));
		return;
	}

	pf_stats_raw_2_normalized_and_update(hw);
}

void nse_dump_pf_stats(struct nse_pf *pf, struct nse_hw_port_stats *stats)
{
	struct device *dev = nse_pf_to_dev(pf);
	int i;

#define DUMP_PF_STATS_ONE_COUNTER(cname)	\
	dev_info(dev, #cname ": %ld\n", (unsigned long)stats->cname)

	DUMP_PF_STATS_ONE_COUNTER(tx_pkts_good_bad);
	DUMP_PF_STATS_ONE_COUNTER(tx_pkts_good);
	DUMP_PF_STATS_ONE_COUNTER(tx_pkts_bad);
	DUMP_PF_STATS_ONE_COUNTER(tx_bytes_good_bad);
	DUMP_PF_STATS_ONE_COUNTER(tx_bytes_good);
	DUMP_PF_STATS_ONE_COUNTER(tx_bytes_bad);
	DUMP_PF_STATS_ONE_COUNTER(tx_broadcast_good_bad);
	DUMP_PF_STATS_ONE_COUNTER(tx_broadcast_good);
	DUMP_PF_STATS_ONE_COUNTER(tx_broadcast_bad);
	DUMP_PF_STATS_ONE_COUNTER(tx_multicast_good_bad);
	DUMP_PF_STATS_ONE_COUNTER(tx_multicast_good);
	DUMP_PF_STATS_ONE_COUNTER(tx_multicast_bad);
	DUMP_PF_STATS_ONE_COUNTER(tx_unicast_good_bad);
	DUMP_PF_STATS_ONE_COUNTER(tx_unicast_good);
	DUMP_PF_STATS_ONE_COUNTER(tx_unicast_bad);
	DUMP_PF_STATS_ONE_COUNTER(tx_64_good_bad);
	DUMP_PF_STATS_ONE_COUNTER(tx_64_to_127_good_bad);
	DUMP_PF_STATS_ONE_COUNTER(tx_128_to_255_good_bad);
	DUMP_PF_STATS_ONE_COUNTER(tx_256_to_511_good_bad);
	DUMP_PF_STATS_ONE_COUNTER(tx_512_to_1023_good_bad);
	DUMP_PF_STATS_ONE_COUNTER(tx_1024_to_max_good_bad);
	DUMP_PF_STATS_ONE_COUNTER(tx_underflow_error);
	DUMP_PF_STATS_ONE_COUNTER(tx_lfc);
	DUMP_PF_STATS_ONE_COUNTER(tx_pfc);

	DUMP_PF_STATS_ONE_COUNTER(rx_pkts_good_bad);
	DUMP_PF_STATS_ONE_COUNTER(rx_pkts_good);
	DUMP_PF_STATS_ONE_COUNTER(rx_pkts_bad);
	DUMP_PF_STATS_ONE_COUNTER(rx_bytes_good_bad);
	DUMP_PF_STATS_ONE_COUNTER(rx_bytes_good);
	DUMP_PF_STATS_ONE_COUNTER(rx_bytes_bad);
	DUMP_PF_STATS_ONE_COUNTER(rx_broadcast_good_bad);
	DUMP_PF_STATS_ONE_COUNTER(rx_broadcast_good);
	DUMP_PF_STATS_ONE_COUNTER(rx_broadcast_bad);
	DUMP_PF_STATS_ONE_COUNTER(rx_multicast_good_bad);
	DUMP_PF_STATS_ONE_COUNTER(rx_multicast_good);
	DUMP_PF_STATS_ONE_COUNTER(rx_multicast_bad);
	DUMP_PF_STATS_ONE_COUNTER(rx_unicast_good_bad);
	DUMP_PF_STATS_ONE_COUNTER(rx_unicast_good);
	DUMP_PF_STATS_ONE_COUNTER(rx_unicast_bad);
	DUMP_PF_STATS_ONE_COUNTER(rx_64_good_bad);
	DUMP_PF_STATS_ONE_COUNTER(rx_64_to_127_good_bad);
	DUMP_PF_STATS_ONE_COUNTER(rx_128_to_255_good_bad);
	DUMP_PF_STATS_ONE_COUNTER(rx_256_to_511_good_bad);
	DUMP_PF_STATS_ONE_COUNTER(rx_512_to_1023_good_bad);
	DUMP_PF_STATS_ONE_COUNTER(rx_1024_to_max_good_bad);
	DUMP_PF_STATS_ONE_COUNTER(rx_undersize_good);
	DUMP_PF_STATS_ONE_COUNTER(rx_oversize_good);
	DUMP_PF_STATS_ONE_COUNTER(rx_crc_error);
	DUMP_PF_STATS_ONE_COUNTER(rx_runt_error);
	DUMP_PF_STATS_ONE_COUNTER(rx_jabber_error);
	DUMP_PF_STATS_ONE_COUNTER(rx_length_error);
	DUMP_PF_STATS_ONE_COUNTER(rx_out_of_range);
	DUMP_PF_STATS_ONE_COUNTER(rx_error);
	DUMP_PF_STATS_ONE_COUNTER(rx_lfc);
	DUMP_PF_STATS_ONE_COUNTER(rx_pfc);

	DUMP_PF_STATS_ONE_COUNTER(fdir_match);
	DUMP_PF_STATS_ONE_COUNTER(fdir_miss);

	DUMP_PF_STATS_ONE_COUNTER(tx_lfc_xoff);
	DUMP_PF_STATS_ONE_COUNTER(tx_lfc_xon);
	DUMP_PF_STATS_ONE_COUNTER(rx_lfc_xoff);
	DUMP_PF_STATS_ONE_COUNTER(rx_lfc_xon);

	for (i = 0; i < 8; i++) {
		DUMP_PF_STATS_ONE_COUNTER(tx_pfc_xoff[i]);
		DUMP_PF_STATS_ONE_COUNTER(tx_pfc_xon[i]);
		DUMP_PF_STATS_ONE_COUNTER(rx_pfc_xoff[i]);
		DUMP_PF_STATS_ONE_COUNTER(rx_pfc_xon[i]);
	}
}

/**
 * nse_get_stats64 - get statistics for network device structure
 * @netdev: network interface device structure
 * @stats: main device statistics structure
 */
static
void nse_get_stats64(struct net_device *netdev, struct rtnl_link_stats64 *stats)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct rtnl_link_stats64 *net_stats;
	struct nse_vsi *vsi = np->vsi;

	net_stats = &vsi->net_stats;

	if (!vsi->num_txq || !vsi->num_rxq)
		return;

	/* netdev packet/byte stats come from ring counter. These are obtained
	 * by summing up ring counters (done by nse_update_vsi_ring_stats).
	 * But, only call the update routine and read the registers if VSI is
	 * not down.
	 */
	if (!test_bit(NSE_VSI_DOWN, vsi->state))
		nse_update_vsi_stats(vsi);

	memcpy(stats, &vsi->net_stats, sizeof(*stats));
}

/**
 * nse_set_tx_maxrate - NDO callback to set the maximum per-queue bitrate
 * @netdev: network interface device structure
 * @queue_index: Queue ID
 * @maxrate: maximum bandwidth in Mbps
 */
static int
nse_set_tx_maxrate(struct net_device *netdev, int queue_index, u32 maxrate)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	struct nse_port_info *pi = vsi->port_info;
	enum nse_status status;
	u16 q_handle;
	u8 tc;

	/* maxrate is in Mbps, our logic is based on Kbps */

	/* Validate maxrate requested is within permitted range */
	if (maxrate && (maxrate > (pi->sched_info.max_bandwidth_per_lan_port/ 1000))) {
		netdev_err(netdev, "Invalid max rate %d specified for the queue %d\n",
			   maxrate, queue_index);
		return -EINVAL;
	}

	q_handle = vsi->tx_rings[queue_index]->q_handle;
	tc = nse_dcb_get_tc(vsi, queue_index);

	status = nse_sched_set_q_pir(vsi->port_info, vsi->idx, tc,
								q_handle, maxrate * 1000);
	if (status) {
		netdev_err(netdev, "Unable to set Tx max rate, error %s\n",
			   nse_stat_str(status));
		return -EIO;
	}

	return 0;
}

/**
 * nse_eth_ioctl - Access the hwtstamp interface
 * @netdev: network interface device structure
 * @ifr: interface request data
 * @cmd: ioctl command
 */
static int nse_eth_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_pf *pf = np->vsi->back;

	switch (cmd) {
	case SIOCGHWTSTAMP:
		return nse_ptp_get_ts_config(pf, ifr);
	case SIOCSHWTSTAMP:
		return nse_ptp_set_ts_config(pf, ifr);
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * nse_vlan_rx_add_vid - Add a VLAN ID filter to HW offload
 * @netdev: network interface to be adjusted
 * @proto: VLAN TPID
 * @vid: VLAN ID to be added
 *
 * net_devnse_ops implementation for adding VLAN IDs
 */
static int
nse_vlan_rx_add_vid(struct net_device *netdev, __be16 proto, u16 vid)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi_vlan_ops *vlan_ops;
	struct nse_vsi *vsi = np->vsi;
	struct nse_vlan vlan;
	int ret;

	if (!vid)
		return 0;

	vlan_ops = nse_get_compat_vsi_vlan_ops(vsi);

	/* Add a switch rule for this VLAN ID so its corresponding VLAN tagged
	 * packets aren't pruned by the device's internal switch on Rx
	 */
	vlan = NSE_VLAN(be16_to_cpu(proto), vid, 0, NSE_FWD_TO_VSI);
	ret = vlan_ops->add_vlan(vsi, &vlan);
	if (!ret)
		set_bit(NSE_VSI_VLAN_FLTR_CHANGED, vsi->state);

	return ret;
}

/**
 * nse_vlan_rx_kill_vid - Remove a VLAN ID filter from HW offload
 * @netdev: network interface to be adjusted
 * @proto: VLAN TPID
 * @vid: VLAN ID to be removed
 *
 * net_devnse_ops implementation for removing VLAN IDs
 */
static int
nse_vlan_rx_kill_vid(struct net_device *netdev, __be16 proto, u16 vid)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi_vlan_ops *vlan_ops;
	struct nse_vsi *vsi = np->vsi;
	struct nse_vlan vlan;
	int ret;

	if (!vid)
		return 0;

	ret = nse_fltr_clear_vsi_promisc(&vsi->back->hw, vsi->idx,
						NSE_MCAST_VLAN_PROMISC_BITS, vid);
	if (ret) {
		netdev_err(netdev, "Error clearing Multicast promiscuous mode on VSI %i\n",
			   vsi->vsi_abs_num);
		vsi->current_netdev_flags |= IFF_ALLMULTI;
	}
	vlan_ops = nse_get_compat_vsi_vlan_ops(vsi);

	/* Make sure VLAN delete is successful before updating VLAN
	 * information
	 */
	vlan = NSE_VLAN(be16_to_cpu(proto), vid, 0, NSE_FWD_TO_VSI);
	ret = vlan_ops->del_vlan(vsi, &vlan);
	if (ret)
		return ret;

	set_bit(NSE_VSI_VLAN_FLTR_CHANGED, vsi->state);
	return 0;
}

/**
 * nse_setup_tc_cls_flower - flower classifier offloads
 * @np: net device to configure
 * @filter_dev: device on which filter is added
 * @cls_flower: offload data
 *
 *	it is a unified entrance function for tc flower rule add/remove
 *	including direct way(pf or repr) and indirect way(vxlan/vlan so on)
 *
 *	if @filter_dev is virtual netdev like vxlan, @np is pf netdev private data
 */
static int
nse_setup_tc_cls_flower(struct nse_netdev_priv *np,
			struct net_device *filter_dev,
			struct flow_cls_offload *cls_flower)
{
	struct nse_vsi *vsi = np->vsi;
	int max_chain;

	if (nse_tcam_less)
		max_chain = 0;
	else
		max_chain = NSE_MAX_CHAIN_NUM - 1;
	if (cls_flower->common.chain_index > max_chain) {
		netdev_err(filter_dev,
			"netdev(%s): chain id bigger than %d is not supported\n",
			filter_dev->name, max_chain);
		return -EOPNOTSUPP;
	}

	switch (cls_flower->command) {
	case FLOW_CLS_REPLACE:
		return nse_add_cls_flower(filter_dev, vsi, cls_flower);
	case FLOW_CLS_DESTROY:
		return nse_del_cls_flower(vsi, cls_flower);
	case FLOW_CLS_STATS:
		return nse_stats_cls_flower(vsi, cls_flower);
	default:
		netdev_err(filter_dev,
			"netdev(%s) don't support to tc flower cmd: %d!\n",
				filter_dev->name, cls_flower->command);
		return -EINVAL;
	}
}

static LIST_HEAD(nse_block_cb_list);

/**
 * nse_setup_tc_block_cb - callback handler registered for TC block
 * @type: TC SETUP type
 * @type_data: TC flower offload data that contains user input
 * @cb_priv: netdev private data
 */
static int
nse_setup_tc_block_cb(enum tc_setup_type type, void *type_data, void *cb_priv)
{
	struct nse_netdev_priv *np = cb_priv;

	switch (type) {
	case TC_SETUP_CLSFLOWER:
		return nse_setup_tc_cls_flower(np, np->vsi->netdev,
					       type_data);
	default:
		return -EOPNOTSUPP;
	}
}

static int
nse_setup_tc(struct net_device *netdev, enum tc_setup_type type,
	     void *type_data)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);

	switch (type) {
	case TC_SETUP_BLOCK:
		netdev_info(netdev, "netdev(%s) tc setup block callback\n", netdev->name);
		return flow_block_cb_setup_simple(type_data,
						  &nse_block_cb_list,
						  nse_setup_tc_block_cb,
						  np, np, true);
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * Start of indirect callback implement here
 *
 * HAVE_TC_INDIR_BLOCK is for indirect callback of ndo_setup_tc,
 * indirect cb way is used for special virtual netdev, such as vxlan/vlan netdev.
 */
static struct nse_indr_block_priv *
nse_indr_block_priv_lookup(struct nse_netdev_priv *np,
			   struct net_device *netdev)
{
	struct nse_indr_block_priv *cb_priv;

	/* All callback list access should be protected by RTNL. */
	ASSERT_RTNL();

	list_for_each_entry(cb_priv, &np->tc_indr_block_priv_list, list) {
		if (!cb_priv->netdev)
			return NULL;
		if (cb_priv->netdev == netdev)
			return cb_priv;
	}
	return NULL;
}

static int
nse_indr_setup_block_cb(enum tc_setup_type type, void *type_data,
			void *indr_priv)
{
	struct nse_indr_block_priv *priv = indr_priv;
	struct nse_netdev_priv *np = priv->np;
	struct flow_cls_offload *cls_flower =
		(struct flow_cls_offload *)type_data;

	switch (type) {
	case TC_SETUP_CLSFLOWER:
		if (cls_flower->command == FLOW_CLS_REPLACE) {
			netdev_info(priv->netdev,
				"netdev(%s) add indr tc flower rule, cookie = %lx\n",
				priv->netdev->name, cls_flower->cookie);
		} else if (cls_flower->command == FLOW_CLS_DESTROY) {
			netdev_info(priv->netdev,
				"netdev(%s) del indr tc flower rule, cookie = %lx\n",
				priv->netdev->name, cls_flower->cookie);
		}
		return nse_setup_tc_cls_flower(np, priv->netdev,
					       (struct flow_cls_offload *)
					       type_data);
	default:
		netdev_err(priv->netdev,
			"netdev(%s) unsupported indr tc flower type, type = %d\n",
			priv->netdev->name, type);
		dump_stack();
		return -EOPNOTSUPP;
	}
}

static int
nse_indr_setup_tc_block(struct net_device *netdev, struct Qdisc *sch,
			struct nse_netdev_priv *np,
			struct flow_block_offload *f, void *data,
			void (*cleanup)(struct flow_block_cb *block_cb))
{
	struct nse_indr_block_priv *indr_priv;
	struct flow_block_cb *block_cb;

	/* 1. here netdev para is virtual, but np is pf private data.
	 * 2. both pf driver instances can receive one same virtual netdev,
	 * should be checked
	 * for vlan, it has real physical netdev, real netdev should be same as pf netdev.
	 * for vxlan, maybe handled by both pf driver instances.
	 */
	int tunnel_type = nse_tc_tun_get_type(netdev, NULL);

	if (tunnel_type != TNL_VXLAN &&
		!(is_vlan_dev(netdev) && vlan_dev_real_dev(netdev) == np->vsi->netdev)) {
		netdev_info(netdev,
			"netdev(%s) is unsupported to offload tc flower, cmd = %d\n",
			netdev->name, f->command);
		return -EOPNOTSUPP;
	}

	if (f->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS) {
		netdev_err(netdev,
		"netdev(%s) only CLSACT_INGRESS tc block can be binded, cmd = %d\n",
		netdev->name, f->command);
		return -EOPNOTSUPP;
	}
	netdev_info(netdev,
		"netdev(%s) Start to handle block bind/unbind cmd: %d\n",
		netdev->name, f->command);

	switch (f->command) {
	case FLOW_BLOCK_BIND:
		indr_priv = nse_indr_block_priv_lookup(np, netdev);
		if (indr_priv)
			return -EEXIST;

		indr_priv = devm_kzalloc(&netdev->dev, sizeof(*indr_priv),
					 GFP_KERNEL);
		if (!indr_priv)
			return -ENOMEM;

		indr_priv->netdev = netdev;
		indr_priv->np = np;
		list_add(&indr_priv->list, &np->tc_indr_block_priv_list);

		block_cb =
			flow_indr_block_cb_alloc(nse_indr_setup_block_cb,
						 indr_priv, indr_priv,
						 nse_rep_indr_tc_block_unbind,
						 f, netdev, sch, data, np,
						 cleanup);
		if (IS_ERR(block_cb)) {
			list_del(&indr_priv->list);
			devm_kfree(&netdev->dev, indr_priv);
			netdev_err(netdev,
				"netdev(%s) Failed to alloc indr block callback\n",
				netdev->name);
			return PTR_ERR(block_cb);
		}
		netdev_info(netdev,
			"netdev(%s) Success to alloc indr block callback\n",
			netdev->name);
		flow_block_cb_add(block_cb, f);
		list_add_tail(&block_cb->driver_list, &nse_block_cb_list);
		return 0;
	case FLOW_BLOCK_UNBIND:
		indr_priv = nse_indr_block_priv_lookup(np, netdev);
		if (!indr_priv)
			return -ENOENT;

		block_cb = flow_block_cb_lookup(f->block,
						nse_indr_setup_block_cb,
						indr_priv);
		if (!block_cb)
			return -ENOENT;

		flow_indr_block_cb_remove(block_cb, f);
		list_del(&block_cb->driver_list);
		return 0;
	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

static int
nse_indr_setup_action(struct nse_netdev_priv *np,
			 struct flow_offload_action *fl_act)
{
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;
	struct flow_action_entry *action;
	int i;

	switch (fl_act->command) {
	case FLOW_ACT_REPLACE:
		flow_action_for_each(i, action, &fl_act->action)
			dev_info(nse_pf_to_dev(pf),
					"Start to add tc action, action_id = %d, is_police = %d\n",
					action->id, action->id == FLOW_ACTION_POLICE);
		return nse_add_fl_action(np, fl_act);

	case FLOW_ACT_DESTROY:
		dev_info(nse_pf_to_dev(pf),
				"Start to del tc action, action_id = %d, is_police = %d\n",
				fl_act->id, fl_act->id == FLOW_ACTION_POLICE);
		return nse_del_fl_action(np, fl_act);

	case FLOW_ACT_STATS:
		return nse_get_stats_fl_action(np, fl_act);

	default:
		return -EOPNOTSUPP;
	}
}

static int
nse_indr_no_dev_setup(struct nse_netdev_priv *np,
	enum tc_setup_type type, void *data)
{
	if (!data)
		return -EOPNOTSUPP;

	switch (type) {
	case TC_SETUP_ACT:
		return nse_indr_setup_action(np, data);
	default:
		return -EOPNOTSUPP;
	}
}

static int
nse_indr_setup_tc_cb(struct net_device *netdev, struct Qdisc *sch,
		     void *cb_priv, enum tc_setup_type type, void *type_data,
		     void *data,
		     void (*cleanup)(struct flow_block_cb *block_cb))
{
	if (!netdev)
		return nse_indr_no_dev_setup(cb_priv, type, data);

	switch (type) {
	case TC_SETUP_BLOCK:
		netdev_info(netdev,
			"netdev(%s) start to setup tc block\n",
			netdev->name);
		return nse_indr_setup_tc_block(netdev, sch, cb_priv, type_data,
					       data, cleanup);

	default:
		return -EOPNOTSUPP;
	}
}

/**
 * nse_fdb_add - add an entry to the hardware database
 * @ndm: the input from the stack
 * @tb: pointer to array of nladdr (unused)
 * @dev: the net device pointer
 * @addr: the MAC address entry being added
 * @vid: VLAN ID
 * @flags: instructions from stack about fdb operation
 * @extack: netlink extended ack
 */
static int
nse_fdb_add(struct ndmsg *ndm, struct nlattr __always_unused *tb[],
	    struct net_device *dev, const unsigned char *addr,
	    u16 vid,
	    u16 flags
	    , struct netlink_ext_ack __always_unused *extack
)
{
	int err;

	if (vid) {
		netdev_err(dev, "VLANs aren't supported yet for dev_uc|mc_add()\n");
		return -EINVAL;
	}

	if (ndm->ndm_state && !(ndm->ndm_state & NUD_PERMANENT)) {
		netdev_err(dev, "FDB only supports static addresses\n");
		return -EINVAL;
	}

	if (is_unicast_ether_addr(addr) || is_link_local_ether_addr(addr))
		err = dev_uc_add_excl(dev, addr);
	else if (is_multicast_ether_addr(addr))
		err = dev_mc_add_excl(dev, addr);
	else
		err = -EINVAL;

	/* Only return duplicate errors if NLM_F_EXCL is set */
	if (err == -EEXIST && !(flags & NLM_F_EXCL))
		err = 0;

	return err;
}

/**
 * nse_fdb_del - delete an entry from the hardware database
 * @ndm: the input from the stack
 * @tb: pointer to array of nladdr (unused)
 * @dev: the net device pointer
 * @addr: the MAC address entry being added
 * @vid: VLAN ID
 */
static int
nse_fdb_del(struct ndmsg *ndm,
			struct nlattr *tb[],
			struct net_device *dev,
			const unsigned char *addr,
			u16 vid, struct netlink_ext_ack *extack)
{
	int err;

	if (ndm->ndm_state & NUD_PERMANENT) {
		netdev_err(dev, "FDB only supports static addresses\n");
		return -EINVAL;
	}

	if (is_unicast_ether_addr(addr))
		err = dev_uc_del(dev, addr);
	else if (is_multicast_ether_addr(addr))
		err = dev_mc_del(dev, addr);
	else
		err = -EINVAL;

	return err;
}

/**
 * nse_tx_timeout - Respond to a Tx Hang
 * @netdev: network interface device structure
 * @txqueue: Tx queue
 */
static void nse_tx_timeout(struct net_device *netdev, unsigned int txqueue)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_ring *tx_ring = NULL;
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	unsigned int i;
	u32 reg;

	pf->tx_timeout_count++;

/*  @xzhao - todo-5: nse_tx_timeout() - nse_is_pfc_causing_hung_q() we have no easy way to check
 * like E810, because no in BAR0.
 */

	/* now that we have an index, find the tx_ring struct */
	for (i = 0; i < vsi->num_txq; i++) {
		if (vsi->tx_rings[i] && vsi->tx_rings[i]->desc) {
			if (txqueue == vsi->tx_rings[i]->q_index) {
				tx_ring = vsi->tx_rings[i];
				break;
			}
		}
	}

	if (!tx_ring) {
		dev_info(dev, "netdev (%s), tx_timeout: no hung queue found\n", netdev->name);
		return;
	}

	/* Reset recovery level if enough time has elapsed after last timeout.
	 * Also ensure no new reset action happens before next timeout period.
	 */
	if (time_after(jiffies, (pf->tx_timeout_last_recovery + HZ * 20)))
		pf->tx_timeout_recovery_level = 1;
	else if (time_before(jiffies, (pf->tx_timeout_last_recovery +
				       netdev->watchdog_timeo)))
		return;

	reg = rd32(hw, NSE_REG_INT_DYN_CTLN(tx_ring->q_vector->reg_idx));

	dev_info(dev, "netdev (%s), tx_timeout: VSI_abs_num: %d, Q %u, NTC: 0x%x, NTU: 0x%x, INT_DYN_CTLN: 0x%x\n",
				netdev->name, vsi->vsi_abs_num, tx_ring->q_index,
			    tx_ring->next_to_clean, tx_ring->next_to_use,
			    reg);

	pf->tx_timeout_last_recovery = jiffies;
	dev_info(dev, "netdev (%s), tx_timeout recovery level %d, txqueue %u\n",
				netdev->name, pf->tx_timeout_recovery_level, txqueue);

	nse_service_task_schedule(pf);
	pf->tx_timeout_recovery_level++;
}

/**
 * nse_features_check - Validate encapsulated packet conforms to limits
 * @skb: skb buffer
 * @netdev: This port's netdev
 * @features: Offload features that the stack believes apply
 */
static netdev_features_t
nse_features_check(struct sk_buff *skb,
		   struct net_device *netdev,
		   netdev_features_t features)
{
	struct nse_pf *pf = nse_netdev_to_pf(netdev);
	struct nse_hw *hw = &pf->hw;
	bool gso = skb_is_gso(skb);
	size_t len;

	/* No point in doing any of this if neither checksum nor GSO are
	 * being requested for this frame. We can rule out both by just
	 * checking for CHECKSUM_PARTIAL
	 */
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return features;

	/* also refuse encap TSO */
	if (skb->encapsulation && !nse_is_hw_static_fea_set(hw,
	    NSE_HW_STATIC_FEA_TDM_SUPPORT_TNL_CSUM))
		goto out_rm_features;

	/* We cannot support GSO if the MSS is going to be less than
	 * 64 bytes. If it is then we need to drop support for GSO.
	 */
	if (gso && (skb_shinfo(skb)->gso_size < NSE_TXD_CTX_MSS_MIN))
		features &= ~NETIF_F_GSO_MASK;

	/* We cannot support GSO if the MSS is too large,
	 * If it is then we need to drop support for GSO.
	 */
	if (gso && (skb_shinfo(skb)->gso_size > NSE_TXD_CTX_MSS_MAX))
		features &= ~NETIF_F_GSO_MASK;

	if (!pf->tso_hsb_usable)
		features &= ~NETIF_F_GSO_MASK;

	len = skb_network_offset(skb);
	if (len > NSE_TXD_CTX_MACLEN_MAX_IN_BYTE || len & 0x1)
		goto out_rm_features;

	len = skb_network_header_len(skb);
	if (len > NSE_TXD_IPLEN_MAX_IN_BYTE || len & 0x3)
		goto out_rm_features;

	if (skb->encapsulation) {
		/* this must work for VXLAN frames AND IPIP/SIT frames, and in
		 * the case of IPIP frames, the transport header pointer is
		 * after the inner header! So check to make sure that this
		 * is a GRE or UDP_TUNNEL frame before doing that math.
		 */
		if (gso && (skb_shinfo(skb)->gso_type &
			    (SKB_GSO_GRE | SKB_GSO_UDP_TUNNEL))) {
			len = skb_inner_network_header(skb) -
			      skb_transport_header(skb);
			if (len > NSE_TXD_L4LEN_MAX_IN_BYTE || len & 0x1)
				goto out_rm_features;
		}

		len = skb_inner_network_header_len(skb);
		if (len > NSE_TXD_IPLEN_MAX_IN_BYTE || len & 0x3)
			goto out_rm_features;
	}

	return features;
out_rm_features:
	return features & ~(NETIF_F_CSUM_MASK | NETIF_F_GSO_MASK);
}

/**
 * nse_udp_tunnel_add - Get notifications about UDP tunnel ports that come up
 * @netdev: This physical port's netdev
 * @ti: Tunnel endpoint information
 */
static int
nse_udp_tunnel_add(struct net_device *netdev, struct udp_tunnel_info *ti)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	__be16 port = ti->port;
	bool kick_subtask = false;
	int ret = 0;

	nse_debug(hw, NSE_DBG_LAN, "[%s] ti->type=0x%X, port=%d\n",
		  __func__, ti->type, ntohs(port));

	if (!nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_PSR_SUPPORT_TNL) ||
	    hw->is_mh_dpu_secondary_pf) {
		/* silently do nothing */
		goto out;
	}

	switch (ti->type) {
	case UDP_TUNNEL_TYPE_VXLAN:
		if (pf->vxlan_port == port)
			goto out;

		if (pf->vxlan_port) {
			netdev_info(netdev,
				    "VXLAN port %d set, not adding port %d\n",
				    ntohs(pf->vxlan_port),
				    ntohs(port));

			ret = -EBUSY;
			goto out;
		}

		spin_lock_bh(&pf->udp_tnl_lock);

		pf->vxlan_port = port;
		pf->udp_tnl_flags |= UDP_TNL_FLAG_SYNC_VXLAN_PORT;

		kick_subtask = true;

		spin_unlock_bh(&pf->udp_tnl_lock);

		break;

	case UDP_TUNNEL_TYPE_VXLAN_GPE:

		if (pf->vxlan_gpe_port == port)
			goto out;

		if (pf->vxlan_gpe_port) {
			netdev_info(netdev,
				    "VXLAN_GPE port %d set, not adding port %d\n",
				    ntohs(pf->geneve_port),
				    ntohs(port));

			ret = -EBUSY;
			goto out;
		}

		spin_lock_bh(&pf->udp_tnl_lock);

		pf->vxlan_gpe_port = port;
		pf->udp_tnl_flags |= UDP_TNL_FLAG_SYNC_VXLAN_GPE_PORT;

		kick_subtask = true;

		spin_unlock_bh(&pf->udp_tnl_lock);

		break;

	case UDP_TUNNEL_TYPE_GENEVE:

		if (pf->geneve_port == port)
			goto out;

		if (pf->geneve_port) {
			netdev_info(netdev,
				    "GENEVE port %d set, not adding port %d\n",
				    ntohs(pf->geneve_port),
				    ntohs(port));

			ret = -EBUSY;
			goto out;
		}

		spin_lock_bh(&pf->udp_tnl_lock);

		pf->geneve_port = port;
		pf->udp_tnl_flags |= UDP_TNL_FLAG_SYNC_GENEVE_PORT;

		kick_subtask = true;

		spin_unlock_bh(&pf->udp_tnl_lock);

		break;

	default:
		netdev_err(netdev, "Unknown tunnel type\n");
		ret = -EINVAL;
		goto out;
	}

out:
	if (kick_subtask)
		nse_service_task_schedule(pf);

	return ret;
}

/**
 * nse_udp_tunnel_del - Get notifications about UDP tunnel ports that go away
 * @netdev: This physical port's netdev
 * @ti: Tunnel endpoint information
 */
static int
nse_udp_tunnel_del(struct net_device *netdev, struct udp_tunnel_info *ti)
{
	struct nse_netdev_priv *np = netdev_priv(netdev);
	struct nse_vsi *vsi = np->vsi;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	__be16 port = ti->port;
	bool kick_subtask = false;
	int ret = 0;

	nse_debug(hw, NSE_DBG_LAN, "[%s] ti->type=0x%X, port=%d\n",
		  __func__, ti->type, ntohs(port));

	if (!nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_PSR_SUPPORT_TNL) ||
	    hw->is_mh_dpu_secondary_pf) {
		/* silently do nothing */
		goto out;
	}

	switch (ti->type) {
	case UDP_TUNNEL_TYPE_VXLAN:

		if (pf->vxlan_port != port) {
			netdev_info(netdev, "VXLAN port %d not found\n", ntohs(port));
			ret = -EINVAL;
			goto out;
		}

		spin_lock_bh(&pf->udp_tnl_lock);

		pf->vxlan_port = 0;

		pf->udp_tnl_flags |= UDP_TNL_FLAG_SYNC_VXLAN_PORT;

		kick_subtask = true;

		spin_unlock_bh(&pf->udp_tnl_lock);

		break;

	case UDP_TUNNEL_TYPE_VXLAN_GPE:

		if (pf->vxlan_gpe_port != port) {
			netdev_info(netdev, "VXLAN_GPE port %d not found\n", ntohs(port));
			ret = -EINVAL;
			goto out;
		}

		spin_lock_bh(&pf->udp_tnl_lock);

		pf->vxlan_gpe_port = 0;

		pf->udp_tnl_flags |= UDP_TNL_FLAG_SYNC_VXLAN_GPE_PORT;

		kick_subtask = true;

		spin_unlock_bh(&pf->udp_tnl_lock);

		break;

	case UDP_TUNNEL_TYPE_GENEVE:

		if (pf->geneve_port != port) {
			netdev_info(netdev, "GENEVE port %d not found\n", ntohs(port));
			ret = -EINVAL;
			goto out;
		}

		spin_lock_bh(&pf->udp_tnl_lock);

		pf->geneve_port = 0;

		pf->udp_tnl_flags |= UDP_TNL_FLAG_SYNC_GENEVE_PORT;

		kick_subtask = true;

		spin_unlock_bh(&pf->udp_tnl_lock);

		break;

	default:
		netdev_err(netdev, "Unknown tunnel type\n");
		ret = -EINVAL;
		goto out;
	}

out:
	if (kick_subtask)
		nse_service_task_schedule(pf);

	return ret;
}

static int nse_udp_tunnel_set(struct net_device *dev,
				unsigned int table, unsigned int entry,
				struct udp_tunnel_info *ti)
{
	return nse_udp_tunnel_add(dev, ti);
}

static int nse_udp_tunnel_unset(struct net_device *dev,
				  unsigned int table, unsigned int entry,
				  struct udp_tunnel_info *ti)
{
	return nse_udp_tunnel_del(dev, ti);
}

static const struct udp_tunnel_nic_info nse_udp_tunnels = {
	.set_port       = nse_udp_tunnel_set,
	.unset_port     = nse_udp_tunnel_unset,
	.flags          = UDP_TUNNEL_NIC_INFO_MAY_SLEEP,
	.tables         = {
		{ .n_entries = 1, .tunnel_types = UDP_TUNNEL_TYPE_VXLAN,  },
		{ .n_entries = 1, .tunnel_types = UDP_TUNNEL_TYPE_GENEVE, },
		{ .n_entries = 1, .tunnel_types = UDP_TUNNEL_TYPE_VXLAN_GPE, },
	},
};

void nse_udp_tunnels_rebuild(struct nse_pf *pf)
{
	struct nse_hw *hw = &pf->hw;
	struct nse_aqc_psr_set_ctrl psr_cmd_buf;

	if (!nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_PSR_SUPPORT_TNL) ||
	    hw->is_mh_dpu_secondary_pf)
		return;

	memset(&psr_cmd_buf, 0, sizeof(psr_cmd_buf));

	psr_cmd_buf.flags = cpu_to_le32(NSE_AQC_PSR_SET_CTRL_FLAG_RPSR |
					NSE_AQC_PSR_SET_CTRL_FLAG_TPSR);
	psr_cmd_buf.dis_or_en = 0;		/* dis = 0 */

	if (pf->vxlan_port) {
		psr_cmd_buf.ctrl_type = NSE_AQC_PSR_CTRL_TYPE_VXLAN_UDP;
		psr_cmd_buf.port_or_etype = cpu_to_le16(be16_to_cpu(pf->vxlan_port));

		(void)nse_aq_psr_set_ctrl(hw, &psr_cmd_buf);
	}

	if (pf->geneve_port) {
		psr_cmd_buf.ctrl_type = NSE_AQC_PSR_CTRL_TYPE_GENEVE_UDP;
		psr_cmd_buf.port_or_etype = cpu_to_le16(be16_to_cpu(pf->geneve_port));

		(void)nse_aq_psr_set_ctrl(hw, &psr_cmd_buf);
	}
}

static const struct net_device_ops nse_netdev_ops = {
	.ndo_open = nse_open,
	.ndo_stop = nse_stop,
	.ndo_start_xmit = nse_start_xmit,
	.ndo_select_queue = nse_select_queue,
	.ndo_features_check = nse_features_check,
	.ndo_fix_features = nse_fix_features,
	.ndo_set_features = nse_set_features,
	.ndo_set_rx_mode = nse_set_rx_mode,
	.ndo_set_mac_address = nse_set_mac_address,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_change_mtu = nse_change_mtu,
	.ndo_get_stats64 = nse_get_stats64,
	.ndo_set_tx_maxrate = nse_set_tx_maxrate,
	.ndo_eth_ioctl = nse_eth_ioctl,
	.ndo_set_vf_spoofchk = nse_set_vf_spoofchk,
	.ndo_set_vf_mac = nse_set_vf_mac,
	.ndo_get_vf_config = nse_get_vf_cfg,
	.ndo_set_vf_trust = nse_set_vf_trust,
	.ndo_set_vf_vlan = nse_set_vf_port_vlan,
	.ndo_set_vf_link_state = nse_set_vf_link_state,
	.ndo_get_vf_stats = nse_get_vf_stats,
	.ndo_set_vf_rate = nse_set_vf_bw,
	.ndo_vlan_rx_add_vid = nse_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid = nse_vlan_rx_kill_vid,
	.ndo_setup_tc = nse_setup_tc,
	.ndo_fdb_add = nse_fdb_add,
	.ndo_fdb_del = nse_fdb_del,
#ifdef CONFIG_RFS_ACCEL
	.ndo_rx_flow_steer = nse_rx_flow_steer,
#endif
	.ndo_tx_timeout = nse_tx_timeout,
	.ndo_bpf = nse_xdp,
	.ndo_xdp_xmit = nse_xdp_xmit,
	.ndo_xsk_wakeup = nse_xsk_wakeup,
	.ndo_dfwd_add_station = nse_fwd_add_macvlan,
	.ndo_dfwd_del_station = nse_fwd_del_macvlan,
};
