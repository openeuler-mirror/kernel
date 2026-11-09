// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2018 - 2025 Beijing WangXun Technology Co., Ltd. */
#include "main.h"
/* TODO: Adding this here is not ideal. Can we remove this warning now? */
#include "nserdma_hw.h"

#define DRV_VER_MAJOR 1
#define DRV_VER_MINOR 0
#define DRV_VER_BUILD 2
#define DRV_VER "1.0.3oe"
const char nser_driver_version[] = DRV_VER;

static u8 resource_profile;
module_param(resource_profile, byte, 0444);
MODULE_PARM_DESC(resource_profile, "Resource Profile: 0=2pf, 1=1pf, 2=2pf & 2*8vf:favor mode, 3=2pf & 2*8vf:equal mode, 4=2pf & 2*16vf:favor mode, 5=2pf & 2*16vf:equal mode, 6=4pf, 7=4pf & 4*16vf:favor mode, 8=4pf & 4*16vf:equal mode");

static u8 max_rdma_vfs = NSER_MAX_PE_ENA_VF_COUNT;
module_param(max_rdma_vfs, byte, 0444);
MODULE_PARM_DESC(max_rdma_vfs, "Maximum VF count: 0-32, default=32");

bool nser_upload_context;
module_param(nser_upload_context, bool, 0644);
MODULE_PARM_DESC(nser_upload_context, "Upload QP context, default=false");

static u8 fragment_count_limit = 12;
module_param(fragment_count_limit, byte, 0444);
MODULE_PARM_DESC(fragment_count_limit, "Adjust maximum values for queue depth and inline data size, Range: 2-12, default=12");

bool nser_hmc_on_chip;
module_param(nser_hmc_on_chip, bool, 0644);
MODULE_PARM_DESC(nser_hmc_on_chip, "Support hmc objects place on hardware chip, only support for Moonstone NIC, default=false");

bool nser_mirror_ena;
module_param(nser_mirror_ena, bool, 0644);
MODULE_PARM_DESC(nser_mirror_ena, "support mirror rocev2 packet to tcpdump, default=false");

/******************Advanced RoCEv2 congestion knobs***********************************************/
static bool dcqcn_enable;
static bool timely_enable;

module_param(dcqcn_enable, bool, 0644);
MODULE_PARM_DESC(dcqcn_enable, "Enables DCQCN algorithm for RoCEv2 on all ports, default=false");

static bool dcqcn_cc_cfg_valid;
module_param(dcqcn_cc_cfg_valid, bool, 0444);
MODULE_PARM_DESC(dcqcn_cc_cfg_valid, "Set DCQCN parameters to be valid, default=false");

static u8 dcqcn_F;
module_param(dcqcn_F, byte, 0444);
MODULE_PARM_DESC(dcqcn_F, "Set number of times to stay in each stage of bandwidth recovery, default=0");

static unsigned short dcqcn_T;
module_param(dcqcn_T, ushort, 0444);
MODULE_PARM_DESC(dcqcn_T, "Set number of usecs that should elapse before increasing the CWND in DCQCN mode, default=0");

static unsigned int dcqcn_B;
module_param(dcqcn_B, uint, 0444);
MODULE_PARM_DESC(dcqcn_B, "Set number of MSS to add to the congestion window in additive increase mode, default=0");

static unsigned int dcqcn_alpha_min = 8;
module_param(dcqcn_alpha_min, uint, 0444);
MODULE_PARM_DESC(dcqcn_alpha_min, "Set number of minimum threshold congestion factor alpha in DCQCN mode, default=8");

static unsigned int dcqcn_alpha_init_value = 1023;
module_param(dcqcn_alpha_init_value, uint, 0444);
MODULE_PARM_DESC(dcqcn_alpha_init_value, "Set alpha init value in DCQCN mode, default=1023");

static unsigned int dcqcn_rreduce_mperiod;
module_param(dcqcn_rreduce_mperiod, uint, 0444);
MODULE_PARM_DESC(dcqcn_rreduce_mperiod, "Set minimum time between 2 consecutive rate reductions for a single flow, default=0");

static unsigned int dcqcn_alpha = 1019;
module_param(dcqcn_alpha, uint, 0444);
MODULE_PARM_DESC(dcqcn_alpha, "Set qp level alpha value in DCQCN mode, default=1019");

static u8 dcqcn_rpg_gd = 11;
module_param(dcqcn_rpg_gd, byte, 0444);
MODULE_PARM_DESC(dcqcn_rpg_gd, "Set gradient denominator value of rate proble gradient in DCQCN mode, default=11");

static unsigned int dcqcn_g = 768;
module_param(dcqcn_g, uint, 0444);
MODULE_PARM_DESC(dcqcn_g, "DCQCN gain factor g for alpha EWMA update, Controls convergence speed of congestion factor α, default=768");

static unsigned int dcqcn_recovery_bcnt_period = 12288;
module_param(dcqcn_recovery_bcnt_period, uint, 0444);
MODULE_PARM_DESC(dcqcn_recovery_bcnt_period, "DCQCN recovery phase byte counter threshold. Rate increase triggered after transmitting this amount of bytes without CNP, default=12288");

static unsigned int dcqcn_clamp_tar_rate;
module_param(dcqcn_clamp_tar_rate, uint, 0444);
MODULE_PARM_DESC(dcqcn_clamp_tar_rate, "DCQCN clamp target rate flag value, default=0");

static unsigned int dcqcn_alpha_period = 5000;
module_param(dcqcn_alpha_period, uint, 0444);
MODULE_PARM_DESC(dcqcn_alpha_period, "DCQCN alpha EWMA statistics period. Interval to sample congestion status and update congestion factor α, default=5000");

static unsigned int dcqcn_recovery_time_period = 5500;
module_param(dcqcn_recovery_time_period, uint, 0444);
MODULE_PARM_DESC(dcqcn_recovery_time_period, "DCQCN recovery phase time period. Time threshold to trigger rate increment as backup condition, default=5500");

static unsigned int dcqcn_tar_work_rate = 100000;
module_param(dcqcn_tar_work_rate, uint, 0444);
MODULE_PARM_DESC(dcqcn_tar_work_rate, "DCQCN Steady-state reference target rate for congestion convergence, default=100000");

module_param(timely_enable, bool, 0644);
MODULE_PARM_DESC(timely_enable, "Enables Timely algorithm for RoCEv2 on all ports, default=false ");

static bool timely_cc_cfg_valid;
module_param(timely_cc_cfg_valid, bool, 0444);
MODULE_PARM_DESC(timely_cc_cfg_valid, "Set Timely parameters to be valid, default=false");

static u8 cc_min_dec = 5;
module_param(cc_min_dec, byte, 0444);
MODULE_PARM_DESC(cc_min_dec, "Set Minimum rate reduction step for congestion control, default=5 units");

static u8 cc_max_dec = 50;
module_param(cc_max_dec, byte, 0444);
MODULE_PARM_DESC(cc_max_dec, "Set Maximum rate reduction step for congestion control, default=50 units");

static u8 cc_f = 5;
module_param(cc_f, byte, 0444);
MODULE_PARM_DESC(cc_f, "Set Feedback factors for congestion control, default=5 units");

static unsigned int rai_factor = 50;
module_param(rai_factor, uint, 0444);
MODULE_PARM_DESC(rai_factor, "Set Rate increase factor for congestion control, default=50");

static unsigned int hai_factor = 100;
module_param(hai_factor, uint, 0444);
MODULE_PARM_DESC(hai_factor, "Set Rate reduction factor for congestion control, default=100");

static unsigned short timely_beta = 512;
module_param(timely_beta, ushort, 0444);
MODULE_PARM_DESC(timely_beta, "Set Parameters beta in Timely algorithm, default=512");

static unsigned short timely_alpha = 818;
module_param(timely_alpha, ushort, 0444);
MODULE_PARM_DESC(timely_alpha, "Set Parameters alpha in Timely algorithm, default=818");

static unsigned int timely_min_rtt = 50;
module_param(timely_min_rtt, uint, 0444);
MODULE_PARM_DESC(timely_min_rtt, "Set Minimum Round Trip Time (RTT) in Timely algorithm, default=50");

static unsigned int timely_tlow = 50;
module_param(timely_tlow, uint, 0444);
MODULE_PARM_DESC(timely_tlow, "Set Low Threshold (Tlow) in Timely algorithm, default=50");

static unsigned int timely_thigh = 500;
module_param(timely_thigh, uint, 0444);
MODULE_PARM_DESC(timely_thigh, "Set High threshold in Timely algorithm (Thigh), default=500");

static unsigned int cc_working_rate = 100000;
module_param(cc_working_rate, uint, 0444);
MODULE_PARM_DESC(cc_working_rate, "Set Current sending rate for congestion control, default=100000");

static unsigned int cc_min_work_rate = 25;
module_param(cc_min_work_rate, uint, 0444);
MODULE_PARM_DESC(cc_min_work_rate, "Set minimum sending rate for congestion control, default=25");

static unsigned int cc_max_work_rate = 100000;
module_param(cc_max_work_rate, uint, 0444);
MODULE_PARM_DESC(cc_max_work_rate, "Set maximum sending rate for congestion control, default=100000");

/*********************new add reset operation****************************/

static bool rf_reset;
#define MAX_NUMOF_RESET_IB_DEVICES 36
static struct nser_device *g_iwdev[MAX_NUMOF_RESET_IB_DEVICES] = {NULL,};
static unsigned long iwdev_array[BITS_TO_LONGS(MAX_NUMOF_RESET_IB_DEVICES)] = {0};
static spinlock_t iwdev_lock;

static int rf_reset_set(const char *val, const struct kernel_param *kp)
{
	struct nser_pci_f *rf;
	int i;

	param_set_bool(val, kp);
	rf_reset = *(bool *)kp->arg;
	for (i = 0; i < MAX_NUMOF_RESET_IB_DEVICES; i++) {
		if (rf_reset && g_iwdev[i]) {
			rf = g_iwdev[i]->rf;
			if (rf && !rf->reset) {
				rf->reset = true;
				rf->gen_ops.request_reset(rf);
			}
		}
	}

	return 0;
}

static const struct kernel_param_ops rf_reset_ops = {
	.set = rf_reset_set,
	.get = param_get_bool,
};

module_param_cb(rf_reset, &rf_reset_ops, &rf_reset, 0644);
MODULE_PARM_DESC(rf_reset, "enable or disable rf reset function");

MODULE_ALIAS("nser");
MODULE_AUTHOR("Wangxun Corporation tom ren");
MODULE_DESCRIPTION("Wangxun(R) Ethernet Protocol Driver for RDMA");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRV_VER);

/**
 * nser_set_rf_user_cfg_params - Setup RF configurations from module parameters
 * @rf: RDMA PCI function
 */
void nser_set_rf_user_cfg_params(struct nser_pci_f *rf)
{
	if (resource_profile == NSER_HMC_PROFILE_0) {
		if (rf->port_num == IIDC_RDMA_NIC_PORT_NUM_1)
			rf->rsrc_profile = NSER_HMC_PROFILE_1; // 1pf
		else if (rf->port_num == IIDC_RDMA_NIC_PORT_NUM_4)
			rf->rsrc_profile = NSER_HMC_PROFILE_6; // 4pf
		else
			rf->rsrc_profile = NSER_HMC_PROFILE_0; // 2pf
	} else {
		rf->rsrc_profile = resource_profile;
	}
	if (max_rdma_vfs > NSER_MAX_PE_ENA_VF_COUNT) {
		pr_warn_once("nser: Requested VF count [%d] is above max supported. Setting to %d.",
			     max_rdma_vfs, NSER_MAX_PE_ENA_VF_COUNT);
		max_rdma_vfs = NSER_MAX_PE_ENA_VF_COUNT;
	}
	rf->max_rdma_vfs = (rf->rsrc_profile != NSER_HMC_PROFILE_0 &&
						rf->rsrc_profile != NSER_HMC_PROFILE_1 &&
						rf->rsrc_profile != NSER_HMC_PROFILE_6) ?
						max_rdma_vfs : 0;
	rf->fragcnt_limit = fragment_count_limit;
	if (rf->fragcnt_limit > 12 || rf->fragcnt_limit < 2) {
		rf->fragcnt_limit = 12;
		pr_warn_once("nser: Requested [%d] fragment count limit out of range (2-12), setting to default=12.",
					fragment_count_limit);
	}

	rf->dcqcn_ena = dcqcn_enable;
	rf->timely_ena = timely_enable;

	if (dcqcn_enable || timely_enable) {
		rf->cc_params.cc_f = cc_f;
		rf->cc_params.cc_max_dec = cc_max_dec;
		rf->cc_params.cc_max_work_rate = cc_max_work_rate;
		rf->cc_params.cc_min_dec = cc_min_dec;
		rf->cc_params.cc_min_work_rate = cc_min_work_rate;
		rf->cc_params.cc_working_rate = cc_working_rate;
		rf->cc_params.hai_factor = hai_factor;
		rf->cc_params.rai_factor = rai_factor;
	}

	if (dcqcn_enable) {

		rf->cc_params.dcqcn_params.cc_cfg_valid = dcqcn_cc_cfg_valid;
		rf->cc_params.dcqcn_params.dcqcn_b = dcqcn_B;

#define DCQCN_B_MAX GENMASK(25, 0)
		if (rf->cc_params.dcqcn_params.dcqcn_b > DCQCN_B_MAX) {
			rf->cc_params.dcqcn_params.dcqcn_b = DCQCN_B_MAX;
			pr_warn_once("nser: Requested [%d] dcqcn_b value too high, setting to %d.",
			     dcqcn_B, rf->cc_params.dcqcn_params.dcqcn_b);
		}

#define DCQCN_F_MAX 8
		rf->cc_params.dcqcn_params.dcqcn_f = dcqcn_F;
		if (dcqcn_F > DCQCN_F_MAX) {
			rf->cc_params.dcqcn_params.dcqcn_f = DCQCN_F_MAX;
			pr_warn_once("nser: Requested [%d] dcqcn_f value too high, setting to %d.",
			     dcqcn_F, DCQCN_F_MAX);
		}

		rf->cc_params.dcqcn_params.dcqcn_t = dcqcn_T;
		rf->cc_params.dcqcn_params.rreduce_mperiod = dcqcn_rreduce_mperiod;
		rf->cc_params.dcqcn_params.dcqcn_alpha_min = dcqcn_alpha_min;
		rf->cc_params.dcqcn_params.dcqcn_alpha_init_value = dcqcn_alpha_init_value;

		rf->cc_params.dcqcn_params.dcqcn_alpha = dcqcn_alpha;
		rf->cc_params.dcqcn_params.dcqcn_recovery_bcnt_period = dcqcn_recovery_bcnt_period;
		rf->cc_params.dcqcn_params.dcqcn_g = dcqcn_g;
		rf->cc_params.dcqcn_params.dcqcn_rpg_gd = dcqcn_rpg_gd;
		rf->cc_params.dcqcn_params.dcqcn_clamp_tar_rate = dcqcn_clamp_tar_rate;
		rf->cc_params.dcqcn_params.dcqcn_alpha_period = dcqcn_alpha_period;
		rf->cc_params.dcqcn_params.dcqcn_recovery_time_period = dcqcn_recovery_time_period;
		rf->cc_params.dcqcn_params.dcqcn_tar_work_rate = dcqcn_tar_work_rate;
	}
	if (timely_enable) {
		rf->cc_params.timely_params.cc_cfg_valid = timely_cc_cfg_valid;
		rf->cc_params.timely_params.timely_alpha = timely_alpha;
		rf->cc_params.timely_params.timely_beta = timely_beta;
		rf->cc_params.timely_params.timely_min_rtt = timely_min_rtt;
		rf->cc_params.timely_params.timely_thigh = timely_thigh;
		rf->cc_params.timely_params.timely_tlow = timely_tlow;

	}
}

static int nser_init_dbg_and_configfs(void)
{
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
	int ret;
#endif /* CONFIG_CONFIGFS_FS */

#ifdef CONFIG_DEBUG_FS
	nser_dbg_init();
#endif

#if IS_ENABLED(CONFIG_CONFIGFS_FS)
	ret = nser_configfs_init();
	if (ret) {
		pr_err("Failed to register nser to configfs subsystem\n");
#ifdef CONFIG_DEBUG_FS
		nser_dbg_exit();
#endif
		return ret;
	}
#endif /* CONFIG_CONFIGFS_FS */

	return 0;
}

static inline void nser_deinit_dbg_and_configfs(void)
{
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
		nser_configfs_exit();
#endif
#ifdef CONFIG_DEBUG_FS
		nser_dbg_exit();
#endif
}

static int nser_vc_receive(struct iidc_core_dev_info *cdev_info, u32 vf_id,
			    u8 *msg, u16 len)
{
	struct nser_device *iwdev = dev_get_drvdata(&cdev_info->adev->dev);
	struct nser_sc_dev *dev = &iwdev->rf->sc_dev;

	if (!len || !msg)
		return -EINVAL;

	if (!dev->vchnl_if->vchnl_recv)
		return -EOPNOTSUPP;

	return dev->vchnl_if->vchnl_recv(dev, (u16)vf_id, msg, len);
}

static int nser_vc_send(struct nser_sc_dev *dev, u16 vf_id, u8 *msg, u16 len)
{
	struct iidc_core_dev_info *cdev_info = dev_to_rf(dev)->cdev;

	cdev_info->ops->vc_send(cdev_info, vf_id, msg, len);

	return 0;
}

static int nser_vc_send_sync(struct nser_sc_dev *dev, u8 *msg, u16 len,
			      u8 *recv_msg, u16 *recv_len)
{
	struct iidc_core_dev_info *cdev_info = dev_to_rf(dev)->cdev;
	int ret;

	ret = cdev_info->ops->vc_send_sync(cdev_info, msg, len, recv_msg, recv_len);
	if (ret == -ETIMEDOUT) {
		dev_err(idev_to_dev(dev),
			"VF <-> PF channel completion timeout = 0x%x\n", ret);
		dev->vchnl_up = false;
		return ret;
	}

	return 0;
}

static struct nser_vchnl_if nser_vchnl_if = {
	.vchnl_recv = nser_vchnl_recv_pf,
	.vchnl_send = nser_vc_send,
};

static struct nser_vchnl_if nser_vchnl_if_vf = {
	.vchnl_recv = nser_vchnl_recv_vf,
	.vchnl_send = nser_vc_send,
	.vchnl_send_sync = nser_vc_send_sync,
};

static inline int nser_set_global_iwdev(struct nser_device *iwdev)
{
	u32 index;
	unsigned long flags;

	spin_lock_irqsave(&iwdev_lock, flags);
	index = find_first_zero_bit(iwdev_array, MAX_NUMOF_RESET_IB_DEVICES);
	if (index >= MAX_NUMOF_RESET_IB_DEVICES) {
		pr_warn("ERR: set nser_device into global iwdev failed\n");
		spin_unlock_irqrestore(&iwdev_lock, flags);
		return -EOVERFLOW;
	}

	g_iwdev[index] = iwdev;
	__set_bit(index, iwdev_array);
	spin_unlock_irqrestore(&iwdev_lock, flags);

	return 0;
}

static inline void nser_clean_global_iwdev(struct nser_device *iwdev)
{
	int index;
	unsigned long flags;

	spin_lock_irqsave(&iwdev_lock, flags);
	for (index = 0; index < MAX_NUMOF_RESET_IB_DEVICES; index++) {
		if (g_iwdev[index] == iwdev) {
			g_iwdev[index] = NULL;
			__clear_bit(index, iwdev_array);
			spin_unlock_irqrestore(&iwdev_lock, flags);
			return;
		}
	}
	spin_unlock_irqrestore(&iwdev_lock, flags);
}

static void nser_prep_tc_change(struct nser_device *iwdev)
{
	iwdev->vsi.tc_change_pending = true;
	nser_sc_suspend_resume_qps(&iwdev->vsi, NSER_OP_SUSPEND);

	/* Wait for all qp's to suspend */
	wait_event_timeout(iwdev->suspend_wq,
			   !atomic_read(&iwdev->vsi.qp_suspend_reqs),
			   msecs_to_jiffies(NSER_EVENT_TIMEOUT_MS));
	nser_ws_reset(&iwdev->vsi);
}

static void nser_log_invalid_mtu(u16 mtu, struct nser_sc_dev *dev)
{
	if (mtu < NSER_MIN_MTU_IPV4)
		dev_warn(idev_to_dev(dev),
				"MTU setting [%d] too low for RDMA traffic. Minimum MTU is 576 for IPv4\n",
				mtu);
	else if (mtu < NSER_MIN_MTU_IPV6)
		dev_warn(idev_to_dev(dev),
				"MTU setting [%d] too low for RDMA traffic. Minimum MTU is 1280 for IPv6\\n",
				mtu);
}

static void nser_fill_qos_info(struct nser_l2params *l2params,
				struct iidc_qos_params *qos_info)
{
	int i;

	l2params->num_tc = qos_info->num_tc;
	l2params->vsi_prio_type = qos_info->vport_priority_type;
	l2params->vsi_rel_bw = qos_info->vport_relative_bw;
	for (i = 0; i < l2params->num_tc; i++) {
		l2params->tc_info[i].egress_virt_up =
			qos_info->tc_info[i].egress_virt_up;
		l2params->tc_info[i].ingress_virt_up =
			qos_info->tc_info[i].ingress_virt_up;
		l2params->tc_info[i].prio_type = qos_info->tc_info[i].prio_type;
		l2params->tc_info[i].rel_bw = qos_info->tc_info[i].rel_bw;
		l2params->tc_info[i].tc_ctx = qos_info->tc_info[i].tc_ctx;
	}
	for (i = 0; i < IIDC_MAX_USER_PRIORITY; i++)
		l2params->up2tc[i] = qos_info->up2tc[i];

	if (qos_info->pfc_mode == IIDC_DSCP_PFC_MODE) {
		l2params->dscp_mode = true;
		memcpy(l2params->dscp_map, qos_info->dscp_map, sizeof(l2params->dscp_map));
	}
}

static void nser_free_one_vf(struct nser_vfdev *vf_dev)
{
	struct nser_sc_dev *dev = vf_dev->pf_dev;

	nser_ws_reset(vf_dev->vf_vsi);
	nser_del_hmc_objects(dev, &vf_dev->hmc_info, true, false);
	nser_pf_put_vf_hmc_fcn(dev, vf_dev);
	nser_put_vfdev(dev, vf_dev);
}

static void nser_free_all_vf_rsrc(struct nser_sc_dev *dev)
{
	u16 vf_idx;

	for (vf_idx = 0; vf_idx < dev->num_vfs; vf_idx++) {
		if (dev->vf_dev[vf_idx]) {
			struct nser_vfdev *vf_dev;

			vf_dev = nser_find_vf_dev(dev, dev->vf_dev[vf_idx]->vf_id);
			if (vf_dev)
				nser_free_one_vf(vf_dev);
		}
	}
}

static void nser_iidc_event_handler(struct iidc_core_dev_info *cdev_info, struct iidc_event *event)
{
	struct nser_device *iwdev = dev_get_drvdata(&cdev_info->adev->dev);
	struct nser_l2params l2params = {};

	if (iwdev->rf->reset)
		return;

	if (*event->type & BIT(IIDC_EVENT_AFTER_MTU_CHANGE)) {
		nser_dbg(&iwdev->rf->sc_dev, "CLNT: new MTU = %d\n",
			  iwdev->netdev->mtu);
		if (iwdev->vsi.mtu != iwdev->netdev->mtu) {
			l2params.mtu = iwdev->netdev->mtu;
			l2params.mtu_changed = true;
			nser_log_invalid_mtu(l2params.mtu, &iwdev->rf->sc_dev);
			if (iwdev->vsi.tc_change_pending) {
				iwdev->vsi.mtu_change_pending = true;
				iwdev->vsi.mtu = iwdev->netdev->mtu;
				return;
			}
			nser_change_l2params(&iwdev->vsi, &l2params);
		}
	} else if (*event->type & BIT(IIDC_EVENT_VF_RESET)) {
		struct nser_sc_dev *dev = &iwdev->rf->sc_dev;
		struct nser_vfdev *vf_dev = nser_find_vf_dev(dev, event->info.vf_id);

		if (vf_dev)
			nser_free_one_vf(vf_dev);
	} else if (*event->type & BIT(IIDC_EVENT_BEFORE_TC_CHANGE)) {
		if (iwdev->vsi.tc_change_pending)
			return;

		nser_prep_tc_change(iwdev);
	} else if (*event->type & BIT(IIDC_EVENT_AFTER_TC_CHANGE)) {

		if (!iwdev->vsi.tc_change_pending)
			return;

		if (iwdev->vsi.mtu_change_pending) {
			iwdev->vsi.mtu_change_pending = false;
			l2params.mtu = iwdev->vsi.mtu;
			l2params.mtu_changed = true;
		}

		l2params.tc_changed = true;
		nser_dbg(&iwdev->rf->sc_dev, "CLNT: TC Change\n");

		nser_fill_qos_info(&l2params, &cdev_info->qos_info);
		iwdev->dcb_vlan_mode = l2params.num_tc > 1 && !l2params.dscp_mode;
		if (iwdev->rf->sc_dev.privileged)
			nser_check_fc_for_tc_update(&iwdev->vsi, &l2params);
		nser_change_l2params(&iwdev->vsi, &l2params);
	} else if (*event->type & BIT(IIDC_EVENT_CRIT_ERR)) {
		ibdev_warn(&iwdev->ibdev, "ICE OICR event notification: oicr = 0x%08x\n",
			   event->info.reg);
		if (event->info.reg & NSERPFINT_OICR_HMC_ERR_M) {
			ibdev_err(&iwdev->ibdev, "HMC Error\n");
			iwdev->rf->reset = true;
		}
		if (event->info.reg & NSERPFINT_OICR_PE_PUSH_M) {
			ibdev_err(&iwdev->ibdev, "PE Push Error\n");
			iwdev->rf->reset = true;
		}
		if (iwdev->rf->reset)
			iwdev->rf->gen_ops.request_reset(iwdev->rf);
	}
}

/**
 * nser_request_reset - Request a reset
 * @rf: RDMA PCI function
 */
static void nser_request_reset(struct nser_pci_f *rf)
{
	u32 statuspec, pe_ready;
	struct iidc_core_dev_info *cdev_info = rf->cdev;

	dev_warn(idev_to_dev(&rf->sc_dev), "Requesting a reset\n");
	rf->sc_dev.vchnl_up = false;
	statuspec = readl(rf->cqp.sc_cqp.dev->hw_regs[NSER_GLPE_PECSTATUS]);
	pe_ready = FIELD_GET(NSER_GLPE_PEC_READY, statuspec);
	statuspec = FIELD_PREP(NSER_GLPE_PEC_READY, pe_ready);
	writel(statuspec, rf->cqp.sc_cqp.dev->hw_regs[NSER_GLPE_PECSTATUS]);
	dev_warn(idev_to_dev(&rf->sc_dev),
			"write statuspec:%x to NSER_GLPE_PECSTATUS register!!!\n", statuspec);
	cdev_info->ops->request_reset(rf->cdev, IIDC_PFR);
}

/*
 * nser_lan_register_qset - Register qset with LAN driver
 * @vsi: vsi structure
 * @tc_node: Traffic class node
 */
static int nser_lan_register_qset(struct nser_sc_vsi *vsi,
				   struct nser_ws_node *tc_node)
{
	struct nser_device *iwdev = vsi->back_vsi;
	struct iidc_core_dev_info *cdev_info = iwdev->rf->cdev;
	struct iidc_rdma_qset_params qset = {};
	int ret;

	qset.qs_handle = tc_node->qs_handle;
	qset.tc = tc_node->traffic_class;
	qset.vsi_abs_id = vsi->vsi_idx;
	ret = cdev_info->ops->alloc_res(cdev_info, &qset);
	if (ret) {
		nser_dbg(vsi->dev,
			  "WS: LAN alloc_res for rdma qset failed.\n");
		return ret;
	}

	tc_node->l2_sched_node_id = qset.teid;
	vsi->qos[tc_node->user_pri].l2_sched_node_id = qset.teid;

	return 0;
}

/**
 * nser_lan_unregister_qset - Unregister qset with LAN driver
 * @vsi: vsi structure
 * @tc_node: Traffic class node
 */
static void nser_lan_unregister_qset(struct nser_sc_vsi *vsi,
				      struct nser_ws_node *tc_node)
{
	struct nser_device *iwdev = vsi->back_vsi;
	struct iidc_core_dev_info *cdev_info = iwdev->rf->cdev;
	struct iidc_rdma_qset_params qset = {};

	qset.qs_handle = tc_node->qs_handle;
	qset.tc = tc_node->traffic_class;
	qset.vsi_abs_id = vsi->vsi_idx;
	qset.teid = tc_node->l2_sched_node_id;

	if (cdev_info->ops->free_res(cdev_info, &qset))
		nser_dbg(vsi->dev, "WS: LAN free_res for rdma qset failed.\n");
}

void nser_cleanup_dead_qps(struct nser_sc_vsi *vsi)
{
	struct nser_sc_qp *qp = NULL;
	struct nser_qp *iwqp;
	struct nser_pci_f *rf;
	u8 i;

	for (i = 0; i < NSER_MAX_USER_PRIORITY; i++) {
		qp = nser_get_qp_from_list(&vsi->qos[i].qplist, qp);
		while (qp) {
			iwqp = qp->qp_uk.back_qp;
			rf = iwqp->iwdev->rf;
			dma_free_coherent(rf->hw.device,
					  iwqp->qp_ctx_mem.size,
					  iwqp->qp_ctx_mem.va,
					  iwqp->qp_ctx_mem.pa);
			dma_free_coherent(rf->hw.device,
					  iwqp->kqp.dma_mem.size,
					  iwqp->kqp.dma_mem.va,
					  iwqp->kqp.dma_mem.pa);
			kfree(iwqp->kqp.sq_wrid_mem);
			kfree(iwqp->kqp.rq_wrid_mem);
			qp = nser_get_qp_from_list(&vsi->qos[i].qplist, qp);
			kfree(iwqp);
		}
	}
}

/**
 * nser_wait_pe_rst_finish - Check if pe reset finish
 * @dev: provides access to registers
 */
static int nser_wait_pe_rst_finish(struct nser_sc_dev *dev)
{
	u32 statuspec;
	u32 pe_rst_finish;
	u32 pe_ready;
	u32 retrycount = 0;

	do {
		statuspec = readl(dev->hw_regs[NSER_GLPE_PECSTATUS]);
		pe_rst_finish = FIELD_GET(NSER_GLPE_PE_RST_FINISH, statuspec);
		pe_ready = FIELD_GET(NSER_GLPE_PEC_READY, statuspec);
		if (pe_rst_finish) {
			statuspec = FIELD_PREP(NSER_GLPE_PEC_READY, pe_ready);
			writel(statuspec, dev->hw_regs[NSER_GLPE_PECSTATUS]);
			return 0;
		}
		mdelay(1000);
	} while (retrycount++ < dev->hw_attrs.max_pe_ready_count);
	return -1;
}

static void nser_remove(struct auxiliary_device *aux_dev)
{
	struct iidc_auxiliary_dev *iidc_adev = container_of(aux_dev,
							    struct iidc_auxiliary_dev,
							    adev);
	struct iidc_core_dev_info *cdev_info = iidc_adev->cdev_info;
	struct nser_device *iwdev = dev_get_drvdata(&aux_dev->dev);

	if (cdev_info->unplug_preset_reset) {
		iwdev->rf->reset = 1;
		iwdev->rf->sc_dev.vchnl_up = 0;
	}
	if (iwdev->rf->sc_dev.privileged)
		nser_free_all_vf_rsrc(&iwdev->rf->sc_dev);
	if (!iwdev->rf->reset) {
		if (iwdev->up_map_en) {
			struct nser_up_info up_map_info = {};

			*((u64 *)up_map_info.map) = NSER_DEFAULT_UP_UP_MAP;
			up_map_info.use_cnp_up_override = false;
			up_map_info.cnp_up_override = 0;
			up_map_info.hmc_fcn_idx = iwdev->rf->sc_dev.hmc_fn_id;
			nser_cqp_up_map_cmd(&iwdev->rf->sc_dev,
					     NSER_OP_SET_UP_MAP,
					     &up_map_info);
		}
		if (iwdev->vsi.tc_change_pending) {
			iwdev->vsi.tc_change_pending = false;
			nser_sc_suspend_resume_qps(&iwdev->vsi,
						    NSER_OP_RESUME);
		}

	} else {
		nser_wait_pe_rst_finish(&iwdev->rf->sc_dev);
	}

	//follow code is test code ,later will be deleted
	nser_clean_global_iwdev(iwdev);

	nser_ib_unregister_device(iwdev);
	if (iwdev->rf->sc_dev.privileged)
		cdev_info->ops->update_vport_filter(cdev_info, iwdev->vsi_num, false);

	pr_debug("INIT: Gen2 PF[%d] device remove success\n", PCI_FUNC(cdev_info->pdev->devfn));
}

static void nser_fill_device_info(struct nser_device *iwdev, struct iidc_core_dev_info *cdev_info)
{
	struct nser_pci_f *rf = iwdev->rf;

	if (cdev_info->ver.major == 10 && cdev_info->ver.minor == 0) {
		u32 val;
#define PF_FUNC_RID 0x0009E880
#define PF_FUNC_RID_FUNCTION_NUMBER GENMASK(2, 0)
		rf->hw.hw_addr = cdev_info->hw_addr;
		val = rd32(&rf->hw, PF_FUNC_RID);
		rf->pf_id = (u8)FIELD_GET(PF_FUNC_RID_FUNCTION_NUMBER, val);
	} else {
		rf->pf_id = cdev_info->pf_id;
	}

	if (!cdev_info->ftype) {
		rf->gen_ops.register_qset = nser_lan_register_qset;
		rf->gen_ops.unregister_qset = nser_lan_unregister_qset;
	}

	rf->cdev = cdev_info;
	rf->hw.hw_addr = cdev_info->hw_addr;
	rf->pcidev = cdev_info->pdev;
	rf->ftype = cdev_info->ftype;
	rf->msix_count = cdev_info->msix_count;
	rf->msix_entries = cdev_info->msix_entries;
	rf->default_vsi.vsi_idx = cdev_info->vsi_abs_id;
	rf->rsrc_profile = NSER_HMC_PROFILE_0;
	rf->rst_to = NSER_RST_TIMEOUT_HZ;
	rf->gen_ops.request_reset = nser_request_reset;
	rf->check_fc = nser_check_fc_for_qp;
	rf->sc_dev.hw_attrs.uk_attrs.hw_rev = cdev_info->rdma_caps.gen;
	rf->port_num = cdev_info->rdma_caps.protocols;
	rf->hmc_va = cdev_info->hmc_va;

	if (!cdev_info->ftype)
		rf->sc_dev.vchnl_if = &nser_vchnl_if;
	else
		rf->sc_dev.vchnl_if = &nser_vchnl_if_vf;

	nser_set_rf_user_cfg_params(rf);
	rf->iwdev = iwdev;

	mutex_init(&iwdev->ah_list_lock);

	rcu_read_lock();
	iwdev->netdev =  netdev_master_upper_dev_get_rcu(cdev_info->netdev);
	rcu_read_unlock();
	if (!iwdev->netdev || !cdev_info->is_lag)
		iwdev->netdev = cdev_info->netdev;
	else
		iwdev->is_lag = true;

	iwdev->vsi_num = cdev_info->vsi_abs_id;
	iwdev->init_state = INITIAL_STATE;
	iwdev->roce_cwnd = NSER_ROCE_CWND_DEFAULT;
	iwdev->roce_ackcreds = NSER_ROCE_ACKCREDS_DEFAULT;
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
	iwdev->up_up_map = NSER_DEFAULT_UP_UP_MAP;
#endif
	iwdev->roce_dcqcn_en = iwdev->rf->dcqcn_ena;
	iwdev->roce_timely_en = iwdev->rf->timely_ena;
	iwdev->cnp_en = true;
	iwdev->cnp_802p_prio = DEF_CNP_802P_PRIO;
	iwdev->cnp_dscp = DEF_CNP_DSCP;

}

static int nser_probe(struct auxiliary_device *aux_dev, const struct auxiliary_device_id *id)
{
	struct iidc_auxiliary_dev *iidc_adev = container_of(aux_dev,
							    struct iidc_auxiliary_dev,
							    adev);
	struct iidc_core_dev_info *cdev_info = iidc_adev->cdev_info;
	struct nser_device *iwdev;
	struct nser_pci_f *rf;
	struct nser_l2params l2params = {};
	int err;
	struct nser_handler *hdl;

	if (cdev_info->ver.major != IIDC_MAJOR_VER) {
		pr_err("version mismatch:\n");
		pr_err("expected major ver %d, caller specified major ver %d\n",
		       IIDC_MAJOR_VER, cdev_info->ver.major);
		pr_err("expected minor ver %d, caller specified minor ver %d\n",
		       IIDC_MINOR_VER, cdev_info->ver.minor);
		return -EINVAL;
	}
	if (cdev_info->ver.minor != IIDC_MINOR_VER)
		pr_info("probe: minor version mismatch: expected %0d.%0d caller specified %0d.%0d\n",
			IIDC_MAJOR_VER, IIDC_MINOR_VER, cdev_info->ver.major,
			cdev_info->ver.minor);

	pr_info("probe: cdev_info=%p, cdev_info->dev.aux_dev.bus->number=%d, cdev_info->netdev=%p %04x:%02x:%02x.%d\n",
			cdev_info,
			cdev_info->pdev->bus->number,
			cdev_info->netdev,
			pci_domain_nr(cdev_info->pdev->bus),
			cdev_info->pdev->bus->number,
			PCI_SLOT(cdev_info->pdev->devfn),
			PCI_FUNC(cdev_info->pdev->devfn));

	iwdev = ib_alloc_device(nser_device, ibdev);
	if (!iwdev)
		return -ENOMEM;
	iwdev->rf = kzalloc(sizeof(*rf), GFP_KERNEL);
	if (!iwdev->rf) {
		ib_dealloc_device(&iwdev->ibdev);
		return -ENOMEM;
	}

	nser_fill_device_info(iwdev, cdev_info);
	rf = iwdev->rf;

	hdl = kzalloc(sizeof(*hdl), GFP_KERNEL);
	if (!hdl) {
		kfree(iwdev->rf);
		ib_dealloc_device(&iwdev->ibdev);
		return -ENOMEM;
	}

	hdl->iwdev = iwdev;
	iwdev->hdl = hdl;
	err = nser_ctrl_init_hw(rf);
	if (err)
		goto err_ctrl_init;

	if (nser_set_attr_from_fragcnt(&rf->sc_dev, rf->fragcnt_limit))
		dev_warn(idev_to_dev(&rf->sc_dev),
			 "device limit update failed for fragment count %d\n",
			 rf->fragcnt_limit);
	l2params.mtu = iwdev->netdev->mtu;
	nser_fill_qos_info(&l2params, &cdev_info->qos_info);
	iwdev->dcb_vlan_mode = l2params.num_tc > 1 && !l2params.dscp_mode;
	err = nser_rt_init_hw(iwdev, &l2params);
	if (err)
		goto err_rt_init;

	err = nser_ib_register_device(iwdev);
	if (err)
		goto err_ibreg;

	err = nser_register_notifiers(iwdev);
	if (err)
		goto err_all;

	if (rf->sc_dev.privileged)
		cdev_info->ops->update_vport_filter(cdev_info, iwdev->vsi_num, true);

	nser_add_handler(hdl);
#ifdef CONFIG_DEBUG_FS
	nser_dbg_pf_init(hdl);
#endif
	nser_dbg(&rf->sc_dev, "INIT: Gen2 PF[%d] device probe success\n",
		  PCI_FUNC(rf->pcidev->devfn));

	dev_set_drvdata(&aux_dev->dev, iwdev);
	/*the following assign statement for rf reset test use*/
	nser_set_global_iwdev(iwdev);

	return 0;

err_all:
	nser_ib_unregister_device(iwdev);
err_ibreg:
	nser_rt_deinit_hw(iwdev);
err_rt_init:
	nser_ctrl_deinit_hw(rf);
err_ctrl_init:
	kfree(hdl);
	kfree(iwdev->rf);
	ib_dealloc_device(&iwdev->ibdev);

	return err;
}

static const struct auxiliary_device_id nser_auxiliary_id_table[] = {
	{.name = "nse.roce", },
	{.name = "nsevf.roce", },
	{},
};

MODULE_DEVICE_TABLE(auxiliary, nser_auxiliary_id_table);

static struct iidc_auxiliary_drv nser_auxiliary_drv = {
	.adrv = {
	    .id_table = nser_auxiliary_id_table,
	    .probe = nser_probe,
	    .remove = nser_remove,
	},
	.event_handler = nser_iidc_event_handler,
	.vc_receive = nser_vc_receive,
};

static int __init nser_init_module(void)
{
	int ret;

	pr_info("nser driver version: %s\n", nser_driver_version);

	ret = nser_init_dbg_and_configfs();
	if (ret)
		return ret;

	ret = auxiliary_driver_register(&nser_auxiliary_drv.adrv);
	if (ret) {
		pr_err("Failed nser auxiliary_driver_register() ret=%d\n",
		       ret);
		nser_deinit_dbg_and_configfs();
		return ret;
	}

	spin_lock_init(&iwdev_lock);

	return 0;
}

static void __exit nser_exit_module(void)
{
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
	nser_configfs_exit();
#endif
	auxiliary_driver_unregister(&nser_auxiliary_drv.adrv);
#ifdef CONFIG_DEBUG_FS
	nser_dbg_exit();
#endif
	pr_info("nser module unloaded\n");
}

module_init(nser_init_module);
module_exit(nser_exit_module);
