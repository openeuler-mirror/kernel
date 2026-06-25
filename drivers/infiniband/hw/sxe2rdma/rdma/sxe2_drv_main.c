// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_main.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/ktime.h>
#include <linux/dma-mapping.h>
#include <linux/bitmap.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/bug.h>
#include <linux/sysfs.h>
#include <linux/rcupdate.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/inetdevice.h>
#include <linux/socket.h>
#include <linux/rtc.h>
#include <linux/kernel.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_mad.h>
#include <rdma/ib_user_ioctl_verbs.h>
#include <rdma/ib_addr.h>
#include <net/addrconf.h>
#include <net/netevent.h>
#include <net/neighbour.h>
#include <net/if_inet6.h>
#include <linux/processor.h>
#include "sxe2_drv_main.h"
#include "sxe2_drv_common_debugfs.h"
#ifdef NOT_SUPPORT_AUXILIARY_BUS
#include "auxiliary_bus.h"
#else
#include <linux/auxiliary_bus.h>
#endif
#include "sxe2_version.h"
#include "sxe2_drv_aux.h"
#include "sxe2_drv_mq.h"
#include "sxe2_drv_db.h"
#include "sxe2_drv_stats.h"
#include "sxe2_drv_rdma_common.h"
#include "sxe2_drv_rdma_virtchnl.h"
#include "sxe2_drv_hw.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_rdma_pble.h"
#include "sxe2_drv_rdma_device_port.h"
#include "sxe2_drv_cq.h"
#include "sxe2_drv_eq.h"
#include "sxe2_drv_mr.h"
#include "sxe2_drv_pd.h"
#include "sxe2_drv_rdma_rcms.h"
#include "sxe2_drv_rdma_qos.h"
#include "sxe2_drv_ah.h"
#include "sxe2_drv_io.h"
#include "sxe2_drv_rdma_debugfs.h"
#include "sxe2_drv_srq.h"
#include "sxe2_drv_qp.h"
#include "sxe2_drv_qos_debugfs.h"
#include "sxe2_drv_mc.h"
#include "sxe2_drv_rdma_inject.h"
#include "sxe2_drv_rdma_inject_debugfs.h"
#include "sxe2_drv_rdma_inject_reg.h"
#include "sxe2_drv_cc_debugfs.h"
#include "sxe2_drv_rdma_configfs.h"

#define DRV_VER_MAJOR 1
#define DRV_VER_MINOR 1
#define DRV_VER_BUILD 1
#define DRV_VER                                                                \
	__stringify(DRV_VER_MAJOR) "." __stringify(                            \
		DRV_VER_MINOR) "." __stringify(DRV_VER_BUILD)
#define FUNCTION_ENABLE  1
#define FUNCTION_DISABLE 0

static u8 resource_profile;
module_param(resource_profile, byte, 0444);
MODULE_PARM_DESC(
	resource_profile,
	"Resource Profile: 0=PF only(default), 1=Weighted VF, 2=Even Distribution");

unsigned short max_rdma_vfs = SXE2_MAX_PE_ENA_VF_COUNT;
module_param(max_rdma_vfs, ushort, 0444);
MODULE_PARM_DESC(max_rdma_vfs, "Maximum VF count, Range: 0-32, default=32");

unsigned int limits_sel = SXE2_LIMITS_SEL_DEFAULT;
module_param(limits_sel, uint, 0444);
MODULE_PARM_DESC(limits_sel, "Resource limits selector, Range: 0-7, default=3");

u8 fragment_count_limit = SXE2_FRAGCNT_LIMIT_DEFAULT;
module_param(fragment_count_limit, byte, 0444);
MODULE_PARM_DESC(
	fragment_count_limit,
	"adjust maximum values for queue depth and inline data size, Range: 2-13, default=6");

u8 rcms_mode = SXE2_RCMS_MODE_2M;
module_param(rcms_mode, byte, 0444);
MODULE_PARM_DESC(
	rcms_mode,
	"rcms init mode 1:2MB page mode, 2: 4KB page mode, Range: 1-2, default=1");

static u8 hygon_cpu_en;
module_param(hygon_cpu_en, byte, 0444);
MODULE_PARM_DESC(
	hygon_cpu_en,
	"hygon_cpu_en 0:auto 1:enable 2:disable, Range: 0-2, default=0");

module_param_named(rdma_dmesg_level, g_sxe2_rdma_dmesg_level, uint, 0644);
MODULE_PARM_DESC(
	rdma_dmesg_level,
	"modify sxe2 rdma dmesg log level,\n"
	"\tRange: 0(LEVEL_EMERG)-7(LEVEL_DEBUG), default=4(WARNING)");

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
static unsigned int inject_sleep_time;
module_param(inject_sleep_time, uint, 0444);
MODULE_PARM_DESC(inject_sleep_time, "set inject_sleep_time, default=0");
#endif

static bool dcqcn_enable;
module_param(dcqcn_enable, bool, 0444);
MODULE_PARM_DESC(
	dcqcn_enable,
	"enables DCQCN algorithm for RoCEv2 on all ports, default=false");

bool dcqcn_cfg_valid;
module_param(dcqcn_cfg_valid, bool, 0444);
MODULE_PARM_DESC(dcqcn_cfg_valid,
		 "set DCQCN parameters to be valid, default=false");

u8 dcqcn_min_dec_factor = SXE2_CC_DCQCN_MIN_DEC_FACTOR_DEFAULT;
module_param(dcqcn_min_dec_factor, byte, 0444);
MODULE_PARM_DESC(
	dcqcn_min_dec_factor,
	"set minimum percentage factor by which tx\n"
	"\trate can be changed for CNP, Range: 2-100, interval 2, default=2");
u8 dcqcn_min_rate = SXE2_CC_DCQCN_MIN_RATE_DEFAULT;
module_param(dcqcn_min_rate, byte, 0444);
MODULE_PARM_DESC(
	dcqcn_min_rate,
	"set minimum rate percentage limit value Range: 2-100, interval 2, default=2");
u8 dcqcn_F = SXE2_CC_DCQCN_F_DEFAULT;
module_param(dcqcn_F, byte, 0444);
MODULE_PARM_DESC(
	dcqcn_F,
	"set number of times to stay in each stage of bandwidth recovery, Range 0-15, default=5");
unsigned short dcqcn_T = SXE2_CC_DCQCN_T_DEFAULT;
module_param(dcqcn_T, ushort, 0444);
MODULE_PARM_DESC(
	dcqcn_T,
	"set number of usecs that should elapse before\n"
	"\tincreasing rate in DCQCN mode, Range: 0x1-0xFFFF, default=120");
unsigned int dcqcn_B = SXE2_CC_DCQCN_B_DEFAULT;
module_param(dcqcn_B, uint, 0444);
MODULE_PARM_DESC(
	dcqcn_B,
	"The number of B to transmit before increasing rate in DCQCN mode,\n"
	"\tRange: 0x0-0xFFFFFF, default=131072");
u8 dcqcn_timely_rai_factor = SXE2_CC_DCQCN_TIMELY_RAI_DEFAULT;
module_param(dcqcn_timely_rai_factor, byte, 0444);
MODULE_PARM_DESC(
	dcqcn_timely_rai_factor,
	"set increasing rate factor percentage in additive increase mode,\n"
	"\tRange: 2-100, interval 2, default=18");

u8 dcqcn_rhai_factor = SXE2_CC_DCQCN_RHAI_DEFAULT;
module_param(dcqcn_rhai_factor, byte, 0444);
MODULE_PARM_DESC(
	dcqcn_rhai_factor,
	"set increasing rate factor percentage in hyperactive increase\n"
	"\tmode rhai > rai,Range: 2-100,interval 2,default=34");
unsigned short dcqcn_rreduce_mperiod =
	SXE2_CC_DCQCN_RREDUCE_MPERIOD_DEFAULT;
module_param(dcqcn_rreduce_mperiod, ushort, 0444);
MODULE_PARM_DESC(
	dcqcn_rreduce_mperiod,
	"set minimum time (usecs) between 2 consecutive rate reductions\n"
	"\tfor a single flow, Range: 0x1-0xFFFF, default=60");

static bool timely_enable;
module_param(timely_enable, bool, 0444);
MODULE_PARM_DESC(
	timely_enable,
	"enables Timely algorithm for RoCEv2 on all ports, default=false");

bool timely_cfg_valid;
module_param(timely_cfg_valid, bool, 0444);
MODULE_PARM_DESC(timely_cfg_valid,
		 "set Timely parameters to be valid, default=false");

unsigned short timely_min_rtt = SXE2_CC_TIMELY_MIN_RTT_DEFAULT;
module_param(timely_min_rtt, ushort, 0444);
MODULE_PARM_DESC(timely_min_rtt,
		 "set min rtt in Timely mode, Range: 0x1-0xFFFF, default=500");

unsigned short timely_tlow = SXE2_CC_TIMELY_TLOW_DEFAULT;
module_param(timely_tlow, ushort, 0444);
MODULE_PARM_DESC(
	timely_tlow,
	"set rtt low threshold in Timely mode, Range: 0x1-0xFFFF, default=300");

unsigned short timely_thigh = SXE2_CC_TIMELY_THIGH_DEFAULT;
module_param(timely_thigh, ushort, 0444);
MODULE_PARM_DESC(
	timely_thigh,
	"set rtt high threshold in Timely mode, Range: 0x1-0xFFFF, default=1000");

LIST_HEAD(sxe2_handlers);
DEFINE_SPINLOCK(sxe2_handler_lock);

struct sxe2_reset_debug g_reset_debug;

#ifndef SXE2_NATIVE_CPUID_NOT_SUPPORT
bool sxe2_rdma_get_cpu_vendor(struct sxe2_rdma_device *rdma_dev)
{
	u32 eax = 0, ebx = 0, ecx = 0, edx = 0;
	s8 cpu_vendor_id[SXE2_VENDOR_ID_SIZE] = "Unknown";
	bool ret			      = false;

	eax = SXE2_CPU_ID_GET_VENDOR_ID;

	native_cpuid(&eax, &ebx, &ecx, &edx);

	memcpy(cpu_vendor_id, &ebx, 4);
	memcpy(cpu_vendor_id + 4, &edx, 4);
	memcpy(cpu_vendor_id + 8, &ecx, 4);
	cpu_vendor_id[12] = '\0';
	DRV_RDMA_LOG_DEV_DEBUG("cpu:get cpu vendor=%s\n", cpu_vendor_id);

	if (strcmp(cpu_vendor_id, "HygonGenuine") == 0) {
		DRV_RDMA_LOG_DEV_DEBUG("cpu:Hygon cpu config en\n");
		ret = true;
	} else {
		DRV_RDMA_LOG_DEV_DEBUG("cpu:normal cpu config en\n");
	}

	return ret;
}
#endif

void sxe2_rdma_free_one_vf(struct sxe2_rdma_vchnl_dev *vc_dev)
{
	struct sxe2_rdma_ctx_dev *dev	 = vc_dev->pf_dev;
	struct sxe2_rdma_ctx_vsi *vf_vsi = vc_dev->vf_vsi;
	int i;

	vc_dev->reset_en = true;
	for (i = 0; i < SXE2_MAX_UESER_PRIORITY; i++)
		vf_vsi->unregister_qsets(vf_vsi, &vf_vsi->qos[i].qset[0], NULL);

	sxe2_vchnl_pf_put_vf_rcms_fcn(dev, &vc_dev);
	sxe2_vchnl_put_vf_dev(&vc_dev);
}

static void sxe2_rdma_free_all_vf_rsrc(struct sxe2_rdma_ctx_dev *dev)
{
	u16 vf_idx;

	for (vf_idx = 0; vf_idx < dev->num_vfs; vf_idx++) {
		if (dev->vc_dev[vf_idx])
			sxe2_rdma_free_one_vf(dev->vc_dev[vf_idx]);
	}
}

#ifdef SXE2_CFG_DEBUG
static inline void sxe2_rdma_debug_get_time(char *buff, int buf_len)
{
	struct timespec64 tv;
	struct tm td;

	ktime_get_real_ts64(&tv);
	time64_to_tm(tv.tv_sec, -sys_tz.tz_minuteswest * 60, &td);
	snprintf(buff, buf_len, "[%04ld-%02d-%02d;%02d:%02d:%02d.%ld]",
		 (long)td.tm_year + 1900, td.tm_mon + 1, td.tm_mday, td.tm_hour,
		 td.tm_min, td.tm_sec, tv.tv_nsec * 1000);
}
#endif

static void sxe2_rdma_fill_qos_info(struct sxe2_rdma_l2params *l2params,
				    struct aux_qos_params *qos_info)
{
	int i;
	int index;

	for (index = 0; index < QOS_MAX_QSET_NUM_PER_USER_PRI; index++) {
		l2params[index].num_tc	= qos_info[index].num_tc;
		l2params[index].vsi_prio_type = qos_info[index].vport_priority_type;
		l2params[index].vsi_rel_bw	= qos_info[index].vport_relative_bw;
		DRV_RDMA_LOG_DEBUG(
			"%s: num_tc:%u, vport_priority_type:%u, vport_relative_bw:%u\n",
			__func__, qos_info[index].num_tc, qos_info[index].vport_priority_type,
			qos_info[index].vport_relative_bw);
		for (i = 0; i < l2params[index].num_tc; i++) {
			l2params[index].tc_info[i].egress_virt_up =
				qos_info[index].tc_info[i].egress_virt_up;
			l2params[index].tc_info[i].ingress_virt_up =
				qos_info[index].tc_info[i].ingress_virt_up;
			l2params[index].tc_info[i].prio_type = qos_info[index].tc_info[i].prio_type;
			l2params[index].tc_info[i].rel_bw    = qos_info[index].tc_info[i].rel_bw;
			l2params[index].tc_info[i].tc_ctx    = qos_info[index].tc_info[i].tc_ctx;
			DRV_RDMA_LOG_DEBUG(
				"%s: index:%u, egress_virt_up:%u, ingress_virt_up:%u,\n"
				"\tprio_type:%u, rel_bw:%u, tc_ctx:%u\n",
				__func__, i, qos_info[index].tc_info[i].egress_virt_up,
				qos_info[index].tc_info[i].ingress_virt_up,
				qos_info[index].tc_info[i].prio_type,
				qos_info[index].tc_info[i].rel_bw,
				qos_info[index].tc_info[i].tc_ctx);
		}
		for (i = 0; i < SXE2_MAX_USER_PRIORITY; i++) {
			DRV_RDMA_LOG_DEBUG("%s: index:%u up2tc:%u\n", __func__, i,
					qos_info[index].up2tc[i]);
			l2params[index].up2tc[i] = qos_info[index].up2tc[i];
		}
		if (qos_info[index].pfc_mode == SXE2_AUX_DSCP_PFC_MODE) {
			l2params[index].dscp_mode = true;
			memcpy(l2params[index].dscp_map, qos_info[index].dscp_map,
				sizeof(l2params[index].dscp_map));
		}
	}

}

static void sxe2_aux_event_handler(struct aux_core_dev_info *cdev_info,
				   struct sxe2_rdma_event_info *event)
{
	struct sxe2_rdma_device *rdma_dev =
		dev_get_drvdata(&cdev_info->adev->dev);
	struct sxe2_rdma_vchnl_dev *vc_dev;
	struct sxe2_rdma_l2params l2params[QOS_MAX_QSET_NUM_PER_USER_PRI] = {0};
	bool dscp_change_flag;
#ifdef SXE2_CFG_DEBUG
	struct sxe2_reset_debug_func_info *reset_func_info;
#endif

	if (!rdma_dev || rdma_dev->rdma_func->reset) {
		DRV_RDMA_LOG_DEBUG(
			"aux_event_handler:rdma dev is null or reset\n"
			"ready rdma_dev ptr=%p\n",
			(void *)rdma_dev);
		return;
	}

	if (*event->type & BIT(SXE2_EVENT_NOTIFY_RESET)) {
		DRV_RDMA_LOG_DEV_DEBUG(
			"aux_event_handler:get WARN RESET event\n");
		rdma_dev->rdma_func->reset	      = true;
		rdma_dev->rdma_func->ctx_dev.vchnl_up = false;
#ifdef SXE2_CFG_DEBUG
		reset_func_info = rdma_dev->reset_func_info;

		mutex_lock(&g_reset_debug.reset_debug_mutex);
		if (reset_func_info) {
			if (reset_func_info->reset_info_idx <
			    MAX_RESET_INFO_CNT) {
				reset_func_info->reset_cnt++;
				reset_func_info
					->reset_info[reset_func_info
							     ->reset_info_idx]
					.reset_type = FUNC_WARNING_RESET;
				sxe2_rdma_debug_get_time(
					reset_func_info
						->reset_info
							[reset_func_info
								 ->reset_info_idx]
						.time,
					MAX_TIME_BUF_SIZE);
				reset_func_info->reset_info_idx++;
				if (reset_func_info->reset_info_idx ==
				    MAX_RESET_INFO_CNT) {
					reset_func_info->reset_info_idx = 0;
				}
				DRV_RDMA_LOG_DEV_DEBUG(
					"rdma:reset cnt=%u reset info idx=%u reset info ptr=%p\n",
					reset_func_info->reset_cnt,
					reset_func_info->reset_info_idx,
					reset_func_info);
			}
		}
		mutex_unlock(&g_reset_debug.reset_debug_mutex);
#endif
	} else if (*event->type & BIT(SXE2_EVENT_MTU_CHANGED)) {
		if (rdma_dev->vsi.mtu != rdma_dev->netdev->mtu) {
			rdma_dev->vsi.mtu = (u16)rdma_dev->netdev->mtu;
			DRV_RDMA_LOG_DEV_DEBUG(
				"aux_event_handler:new net dev mtu=%u\n",
				rdma_dev->vsi.mtu);
		}
	} else if (*event->type & BIT(SXE2_EVENT_VF_RESET)) {
		DRV_RDMA_LOG_DEV_DEBUG("aux_event_handler:vf %u reset\n",
				       event->vf_id);
		vc_dev = sxe2_vchnl_find_vc_dev(&rdma_dev->rdma_func->ctx_dev,
						event->vf_id);
		if (vc_dev)
			sxe2_rdma_free_one_vf(vc_dev);
	} else if (*event->type & BIT(SXE2_EVENT_AEQ_OVERFLOW)) {
		DRV_RDMA_LOG_DEV_DEBUG(
			"aux_event_handler:get AEQ OVERFLOW event\n");
		if (!rdma_dev->rdma_func->reset) {
			rdma_dev->rdma_func->reset = true;
			rdma_dev->rdma_func->gen_ops.request_reset(
				rdma_dev->rdma_func);
		}
	} else if (*event->type & BIT(SXE2_EVENT_FAILOVER)) {
		DRV_RDMA_LOG_DEBUG_BDF(
			"FAILOVER_FINISH:lag_mode %d, bitmap = 0x%x\n",
			rdma_dev->lag_mode, cdev_info->rdma_pf_bitmap);
		rdma_dev->vsi.lag_port_bitmap = cdev_info->rdma_pf_bitmap;
		sxe2_rdma_qos_failover_complete(rdma_dev);
	} else if (*event->type & BIT(SXE2_EVENT_TC_CHANGE)) {
		DRV_RDMA_LOG_DEV_DEBUG(
			"aux_event_handler:get tc change event,\n"
			"\tpfc_mode: %u %u, tc_num:%u %u, app_num:%u %u\n",
			cdev_info->qos_info[0].pfc_mode,
			cdev_info->qos_info[1].pfc_mode,
			cdev_info->qos_info[0].num_tc,
			cdev_info->qos_info[1].num_tc,
			cdev_info->qos_info[0].num_apps,
			cdev_info->qos_info[1].num_apps);
		sxe2_rdma_fill_qos_info(l2params, cdev_info->qos_info);

		if (rdma_dev->vsi.lag_aa)
			dscp_change_flag = ((rdma_dev->vsi.dscp_mode[0] != l2params[0].dscp_mode) ||
						(rdma_dev->vsi.dscp_mode[1]
						!= l2params[1].dscp_mode));
		else
			dscp_change_flag = (rdma_dev->vsi.dscp_mode[0] != l2params[0].dscp_mode);
		if (dscp_change_flag)
			sxe2_rdma_update_qos_info(&rdma_dev->vsi, l2params);
		else
			sxe2_rdma_qos_move_qset(&rdma_dev->vsi, l2params);
	}
}

static int sxe2_dbg_and_configs_init(void)
{
		int ret = 0;
#ifdef SXE2_SUPPORT_CONFIGFS
	ret = sxe2_configfs_init();
	if (ret) {
		DRV_RDMA_LOG_ERROR(
			"ERR: Failed to register sxe2 to configfs subsystem\n",
			ret);
		goto out;
	}
#endif
	memset(&g_reset_debug, 0x0, sizeof(g_reset_debug));
	mutex_init(&g_reset_debug.reset_debug_mutex);
	ret = sxe2_rdma_dbg_init();
	if (ret) {
		DRV_RDMA_LOG_ERROR("debugfs init failed. ret:%d\n", ret);
		goto err_destroy_mutex_configfs;
	}

	goto out;
err_destroy_mutex_configfs:
#ifdef SXE2_SUPPORT_CONFIGFS
	sxe2_configfs_exit();
#endif
out:
	return ret;
}

static void sxe2_dbg_and_configs_exit(void)
{
#ifdef SXE2_SUPPORT_CONFIGFS
	sxe2_configfs_exit();
#endif
	sxe2_rdma_dbg_exit();
}

static void sxe2_rdma_request_reset(struct sxe2_rdma_pci_f *rdma_func)
{
	struct aux_core_dev_info *cdev_info = rdma_func->cdev;
	struct sxe2_rdma_device *rdma_dev   = to_rdmadev(&rdma_func->ctx_dev);
#ifdef SXE2_CFG_DEBUG
	struct sxe2_reset_debug_func_info *reset_func_info;
#endif
	DRV_RDMA_LOG_DEV_DEBUG("rdma:request reset\n");
	rdma_func->ctx_dev.vchnl_up = false;
#ifdef SXE2_CFG_DEBUG
	reset_func_info = rdma_dev->reset_func_info;

	mutex_lock(&g_reset_debug.reset_debug_mutex);

	if (reset_func_info) {
		if (reset_func_info->reset_info_idx < MAX_RESET_INFO_CNT) {
			reset_func_info->reset_cnt++;
			reset_func_info
				->reset_info[reset_func_info->reset_info_idx]
				.reset_type = FUNC_REQUEST_RESET;
			sxe2_rdma_debug_get_time(
				reset_func_info
					->reset_info[reset_func_info
							     ->reset_info_idx]
					.time,
				MAX_TIME_BUF_SIZE);
			reset_func_info->reset_info_idx++;
			if (reset_func_info->reset_info_idx ==
			    MAX_RESET_INFO_CNT) {
				reset_func_info->reset_info_idx = 0;
			}
			DRV_RDMA_LOG_DEV_DEBUG(
				"rdma:reset cnt=%u reset info idx=%u reset info ptr=%p\n",
				reset_func_info->reset_cnt,
				reset_func_info->reset_info_idx,
				reset_func_info);
		}
	}

	mutex_unlock(&g_reset_debug.reset_debug_mutex);
#endif
	cdev_info->ops->request_reset(rdma_func->cdev, AUX_PFR);
}

void sxe2_rdma_cc_dcqcn_set_params(struct sxe2_rdma_pci_f *rdma_func)
{
	struct sxe2_rdma_cc_dcqcn_params *dcqcn_p =
		&rdma_func->cc_params.dcqcn_params;

	dcqcn_p->b = dcqcn_B;
	if (dcqcn_p->b > SXE2_CC_DCQCN_B_MAX) {
		dcqcn_p->b = SXE2_CC_DCQCN_B_MAX;
		pr_warn_once(
			"sxe2_rdma: Requested [%u] dcqcn_b value out of range(%u-%u), setting to %u.\n",
			dcqcn_B, SXE2_CC_DCQCN_B_MIN, SXE2_CC_DCQCN_B_MAX,
			dcqcn_p->b);
	}

	dcqcn_p->t_interval = dcqcn_T;
	if (dcqcn_p->t_interval < SXE2_CC_DCQCN_T_MIN) {
		dcqcn_p->t_interval = SXE2_CC_DCQCN_T_DEFAULT;
		pr_warn_once(
			"sxe2_rdma: Requested [%u] dcqcn_t value out of range(%u-%u), setting to %u.\n",
			dcqcn_T, SXE2_CC_DCQCN_T_MIN, SXE2_CC_DCQCN_T_MAX,
			dcqcn_p->t_interval);
	}

	dcqcn_p->f = dcqcn_F;
	if (dcqcn_p->f > SXE2_CC_DCQCN_F_MAX) {
		dcqcn_p->f = SXE2_CC_DCQCN_F_MAX;
		pr_warn_once(
			"sxe2_rdma: Requested [%u] dcqcn_f value too high, setting to %u.\n",
			dcqcn_F, dcqcn_p->f);
	}

	dcqcn_p->rai_factor = dcqcn_timely_rai_factor;
	if (dcqcn_p->rai_factor > SXE2_CC_DCQCN_TIMELY_RAI_MAX ||
	    dcqcn_p->rai_factor < SXE2_CC_DCQCN_TIMELY_RAI_MIN) {
		dcqcn_p->rai_factor = SXE2_CC_DCQCN_TIMELY_RAI_DEFAULT;
		pr_warn_once(
			"sxe2_rdma: Requested [%u] dcqcn_rai_factor value out of range(%u-%u), setting to %u.\n",
			dcqcn_timely_rai_factor, SXE2_CC_DCQCN_TIMELY_RAI_MIN,
			SXE2_CC_DCQCN_TIMELY_RAI_MAX, dcqcn_p->rai_factor);
	}

	dcqcn_p->rhai_factor = dcqcn_rhai_factor;
	if (dcqcn_p->rhai_factor > SXE2_CC_DCQCN_RHAI_MAX ||
	    dcqcn_p->rhai_factor < SXE2_CC_DCQCN_RHAI_MIN) {
		dcqcn_p->rhai_factor = SXE2_CC_DCQCN_RHAI_DEFAULT;
		pr_warn_once(
			"sxe2_rdma: Requested [%u] dcqcn_rhai value out of range(%u-%u), setting to %u.\n",
			dcqcn_rhai_factor, SXE2_CC_DCQCN_RHAI_MIN,
			SXE2_CC_DCQCN_RHAI_MAX, dcqcn_p->rhai_factor);
	}

	dcqcn_p->min_dec_factor = dcqcn_min_dec_factor;
	if (dcqcn_p->min_dec_factor > SXE2_CC_DCQCN_MIN_DEC_FACTOR_MAX ||
	    dcqcn_p->min_dec_factor < SXE2_CC_DCQCN_MIN_DEC_FACTOR_MIN) {
		dcqcn_p->min_dec_factor = SXE2_CC_DCQCN_MIN_DEC_FACTOR_DEFAULT;
		pr_warn_once(
			"sxe2_rdma: Requested [%u] dcqcn_min_dec_factor out of range (%u-%u), setting to %u.\n",
			dcqcn_min_dec_factor, SXE2_CC_DCQCN_MIN_DEC_FACTOR_MIN,
			SXE2_CC_DCQCN_MIN_DEC_FACTOR_MAX,
			dcqcn_p->min_dec_factor);
	}

	dcqcn_p->rreduce_mperiod = dcqcn_rreduce_mperiod;
	if (dcqcn_p->rreduce_mperiod > SXE2_CC_DCQCN_RREDUCE_MPERIOD_MAX ||
	    dcqcn_p->rreduce_mperiod < SXE2_CC_DCQCN_RREDUCE_MPERIOD_MIN) {
		dcqcn_p->rreduce_mperiod =
			SXE2_CC_DCQCN_RREDUCE_MPERIOD_DEFAULT;
		pr_warn_once(
			"sxe2_rdma: Requested [%u] dcqcn_rreduce_mperiod out of range (%u-%u), setting to %u.\n",
			dcqcn_rreduce_mperiod,
			SXE2_CC_DCQCN_RREDUCE_MPERIOD_MIN,
			SXE2_CC_DCQCN_RREDUCE_MPERIOD_MAX,
			dcqcn_p->rreduce_mperiod);
	}

	dcqcn_p->min_rate = dcqcn_min_rate;
	if (dcqcn_p->min_rate > SXE2_CC_DCQCN_MIN_RATE_MAX ||
	    dcqcn_p->min_rate < SXE2_CC_DCQCN_MIN_RATE_MIN) {
		dcqcn_p->min_rate = SXE2_CC_DCQCN_MIN_RATE_DEFAULT;
		pr_warn_once(
			"sxe2_rdma: Requested [%u] dcqcn_min_rate out of range (%u-%u), setting to %u.\n",
			dcqcn_min_rate, SXE2_CC_DCQCN_MIN_RATE_MIN,
			SXE2_CC_DCQCN_MIN_RATE_MAX, dcqcn_p->min_rate);
	}
}

void sxe2_rdma_cc_timely_set_params(struct sxe2_rdma_pci_f *rdma_func)
{
	struct sxe2_rdma_cc_timely_params *timely_p =
		&rdma_func->cc_params.timely_params;

	timely_p->rai_factor = dcqcn_timely_rai_factor;
	if (timely_p->rai_factor > SXE2_CC_DCQCN_TIMELY_RAI_MAX ||
	    timely_p->rai_factor < SXE2_CC_DCQCN_TIMELY_RAI_MIN) {
		timely_p->rai_factor = SXE2_CC_DCQCN_TIMELY_RAI_DEFAULT;
		pr_warn_once(
			"sxe2_rdma: Requested [%u] dcqcn_rai_factor value out of range(%u-%u), setting to %u.\n",
			dcqcn_timely_rai_factor, SXE2_CC_DCQCN_TIMELY_RAI_MIN,
			SXE2_CC_DCQCN_TIMELY_RAI_MAX, timely_p->rai_factor);
	}

	timely_p->min_rtt = timely_min_rtt;
	if (timely_p->min_rtt < SXE2_CC_TIMELY_MIN_RTT_MIN) {
		timely_p->min_rtt = SXE2_CC_TIMELY_MIN_RTT_DEFAULT;
		pr_warn_once(
			"sxe2_rdma: Requested [%u] timely_min_rtt out of range (%u-%u), setting to %u.\n",
			timely_min_rtt, SXE2_CC_TIMELY_MIN_RTT_MIN,
			SXE2_CC_TIMELY_MIN_RTT_MAX, timely_p->min_rtt);
	}

	timely_p->tlow = timely_tlow;
	if (timely_p->tlow < SXE2_CC_TIMELY_TLOW_MIN) {
		timely_p->tlow = SXE2_CC_TIMELY_TLOW_DEFAULT;
		pr_warn_once(
			"sxe2_rdma: Requested [%u] timely_tlow out of range (%u-%u), setting to %u.\n",
			timely_tlow, SXE2_CC_TIMELY_TLOW_MIN,
			SXE2_CC_TIMELY_TLOW_MAX, timely_p->tlow);
	}

	timely_p->thigh = timely_thigh;
	if (timely_p->thigh < SXE2_CC_TIMELY_THIGH_MIN) {
		timely_p->thigh = SXE2_CC_TIMELY_THIGH_DEFAULT;
		pr_warn_once(
			"sxe2_rdma: Requested [%u] timely_thigh out of range (%u-%u), setting to %u.\n",
			timely_thigh, SXE2_CC_TIMELY_THIGH_MIN,
			SXE2_CC_TIMELY_THIGH_MAX, timely_p->thigh);
	}
}

void
sxe2_rdma_set_func_user_cfg_params(struct sxe2_rdma_pci_f *rdma_func)

{
	if (limits_sel > SXE2_LIMITS_SEL_MAX)
		limits_sel = SXE2_LIMITS_SEL_MAX;

	rdma_func->limits_sel = limits_sel;
	rdma_func->rsrc_profile =
		(resource_profile < SXE2_RCMS_PROFILE_EQUAL) ?
			(u8)resource_profile + SXE2_RCMS_PROFILE_DEFAULT :
			SXE2_RCMS_PROFILE_DEFAULT;
	if (max_rdma_vfs > SXE2_MAX_PE_ENA_VF_COUNT) {
		pr_warn_once("sxe2_rdma: Requested VF count [%d] is above max\n"
			     "\tsupported. Setting to %d.\n",
			     max_rdma_vfs, SXE2_MAX_PE_ENA_VF_COUNT);
		max_rdma_vfs = SXE2_MAX_PE_ENA_VF_COUNT;
	}
	rdma_func->max_rdma_vfs =
		(rdma_func->rsrc_profile != SXE2_RCMS_PROFILE_DEFAULT) ?
			max_rdma_vfs :
			0;
	rdma_func->fragcnt_limit       = fragment_count_limit;
	if (rdma_func->fragcnt_limit > SXE2_FRAGCNT_LIMIT_MAX
		|| rdma_func->fragcnt_limit < SXE2_FRAGCNT_LIMIT_MIN) {
		rdma_func->fragcnt_limit = SXE2_FRAGCNT_LIMIT_DEFAULT;
		pr_warn_once(
			"sxe2_rdma: Requested [%d] fragment count limit out of\n"
			"\trange (2-13), setting to default=6.\n",
			fragment_count_limit);
	}
	if (rcms_mode > SXE2_RCMS_MODE_4K || rcms_mode == 0) {
		rcms_mode = SXE2_RCMS_MODE_2M;
		pr_warn_once(
			"sxe2_rdma: Requested [%d] rcms init mode limit out of\n"
			"\trange (1-2), setting to default=1.\n",
			rcms_mode);
	}

	if (rcms_mode == 1) {
		rdma_func->rcms_mode.ctx_mode = SXE2_RCMS_FIRST_INIT_MODE;
		rdma_func->rcms_mode.pbl_mode = SXE2_PBL_SECOND_INIT_MODE;
	} else if (rcms_mode == 2) {
		rdma_func->rcms_mode.ctx_mode = SXE2_RCMS_SECOND_INIT_MODE;
		rdma_func->rcms_mode.pbl_mode = SXE2_PBL_THIRD_INIT_MODE;
	}

	rdma_func->cc_params.dcqcn_enable = dcqcn_enable;
	rdma_func->cc_params.dcqcn_cfg_valid = dcqcn_cfg_valid;
	rdma_func->cc_params.cnp_ecn	     = SXE2_QP_CC_CNP_ECN_ENABLE;
	rdma_func->cc_params.ecn	     = SXE2_QP_CC_ECN_ENABLE;
	if (dcqcn_cfg_valid) {
		sxe2_rdma_cc_dcqcn_set_params(rdma_func);
	} else {
		rdma_func->cc_params.dcqcn_params.t_interval =
			SXE2_CC_DCQCN_T_DEFAULT;
		rdma_func->cc_params.dcqcn_params.b = SXE2_CC_DCQCN_B_DEFAULT;
		rdma_func->cc_params.dcqcn_params.f = SXE2_CC_DCQCN_F_DEFAULT;
		rdma_func->cc_params.dcqcn_params.rai_factor =
			SXE2_CC_DCQCN_TIMELY_RAI_DEFAULT;
		rdma_func->cc_params.dcqcn_params.rhai_factor =
			SXE2_CC_DCQCN_RHAI_DEFAULT;
		rdma_func->cc_params.dcqcn_params.rreduce_mperiod =
			SXE2_CC_DCQCN_RREDUCE_MPERIOD_DEFAULT;
		rdma_func->cc_params.dcqcn_params.min_dec_factor =
			SXE2_CC_DCQCN_MIN_DEC_FACTOR_DEFAULT;
		rdma_func->cc_params.dcqcn_params.min_rate =
			SXE2_CC_DCQCN_MIN_RATE_DEFAULT;
	}

	rdma_func->cc_params.timely_enable    = timely_enable;
	rdma_func->cc_params.timely_cfg_valid = timely_cfg_valid;
	if (timely_cfg_valid) {
		sxe2_rdma_cc_timely_set_params(rdma_func);
	} else {
		rdma_func->cc_params.timely_params.rai_factor =
			SXE2_CC_DCQCN_TIMELY_RAI_DEFAULT;
		rdma_func->cc_params.timely_params.min_rtt =
			SXE2_CC_TIMELY_MIN_RTT_DEFAULT;
		rdma_func->cc_params.timely_params.tlow =
			SXE2_CC_TIMELY_TLOW_DEFAULT;
		rdma_func->cc_params.timely_params.thigh =
			SXE2_CC_TIMELY_THIGH_DEFAULT;
	}
}

void sxe2_rdma_init_cc_params(struct sxe2_rdma_pci_f *rdma_func)
{
	struct sxe2_rdma_cc_dcqcn_params *dcqcn_params =
		&rdma_func->cc_params.dcqcn_params;
	struct sxe2_rdma_cc_timely_params *timely_params =
		&rdma_func->cc_params.timely_params;
	dcqcn_params->k	    = SXE2_CC_DCQCN_K_VAL;
	dcqcn_params->bc    = SXE2_CC_DCQCN_BC_VAL;
	dcqcn_params->tc    = SXE2_CC_DCQCN_TC_VAL;
	dcqcn_params->g	    = SXE2_CC_DCQCN_G_VAL;
	dcqcn_params->rt    = SXE2_CC_DCQCN_RT_VAL;
	dcqcn_params->rc    = SXE2_CC_DCQCN_RC_VAL;
	dcqcn_params->alpha = SXE2_CC_DCQCN_ALPHA_VAL;
	dcqcn_params->rreduce_next_node_info =
		SXE2_CC_DCQCN_RREDUCE_NEXT_NODE_INFO_VAL;
	dcqcn_params->decrease_rate_valid =
		SXE2_CC_DCQCN_DECREASE_RATE_VALID_VAL;
	dcqcn_params->t_next_node_info = SXE2_CC_DCQCN_T_NEXT_NODE_INFO_VAL;
	dcqcn_params->byte_counter     = SXE2_CC_DCQCN_BYTE_COUNTER_VAL;
	timely_params->pre_rtt	= SXE2_CC_TIMELY_PRE_RTT_VAL;
	timely_params->beta	= SXE2_CC_TIMELY_BETA_VAL;
	timely_params->alpha	= SXE2_CC_TIMELY_ALPHA_VAL;
	timely_params->rtt_diff = SXE2_CC_TIMELY_RTT_DIFF_VAL;
}

int sxe2_rdma_save_msix_info(struct sxe2_rdma_pci_f *rdma_func)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev = rdma_func->rdma_dev;
	struct sxe2_rdma_qvlist_info *sxe2_qvlist;
	struct sxe2_rdma_qv_info *sxe2_qvinfo;
	struct msix_entry *pmsix;
	u16 ceq_idx;
	u32 i;
	u32 size;

	if (!rdma_func->msix_count) {
		DRV_RDMA_LOG_DEV_ERR(
			"probe:no msi-x vector reserved for rdma\n");
		ret = -EINVAL;
		goto end;
	}

	DRV_RDMA_LOG_DEV_DEBUG("rdma_func->msix_count : %d\n",
			       rdma_func->msix_count);
	size = (u32)(sizeof(struct sxe2_rdma_msix_vector) *
		     rdma_func->msix_count);
	size += sizeof(*sxe2_qvlist);
	size += sizeof(*sxe2_qvinfo) * rdma_func->msix_count - 1;
	rdma_func->sxe2_msixtbl = kzalloc(size, GFP_KERNEL);
	if (!rdma_func->sxe2_msixtbl) {
		DRV_RDMA_LOG_DEV_ERR(
			"probe:no msi-x vector reserved for rdma\n");
		ret = -ENOMEM;
		goto end;
	}
	rdma_func->sxe2_qvlist =
		(struct sxe2_rdma_qvlist_info
			 *)(&rdma_func->sxe2_msixtbl[rdma_func->msix_count]);
	sxe2_qvlist		 = rdma_func->sxe2_qvlist;
	sxe2_qvinfo		 = sxe2_qvlist->qv_info;
	sxe2_qvlist->num_vectors = rdma_func->msix_count;

	if (rdma_func->msix_count <= num_online_cpus())
		rdma_func->msix_shared = true;
	else if (rdma_func->msix_count > num_online_cpus() + 1)
		rdma_func->msix_count = num_online_cpus() + 1;

	pmsix = rdma_func->msix_entries;
	for (i = 0, ceq_idx = 0; i < rdma_func->msix_count;
	     i++, sxe2_qvinfo++) {
		DRV_RDMA_LOG_DEV_DEBUG(
			"rdma_func->msix_entries[%d]  vector: %d entry:%d\n", i,
			pmsix->vector, pmsix->entry);
		rdma_func->sxe2_msixtbl[i].idx		= pmsix->entry;
		rdma_func->sxe2_msixtbl[i].irq		= pmsix->vector;
		rdma_func->sxe2_msixtbl[i].cpu_affinity = ceq_idx;
		if (!i) {
			sxe2_qvinfo->aeq_idx = 0;
			if (rdma_func->msix_shared)
				sxe2_qvinfo->ceq_idx = ceq_idx++;
			else
				sxe2_qvinfo->ceq_idx = SXE2_Q_INVALID_IDX;
		} else {
			sxe2_qvinfo->aeq_idx = SXE2_Q_INVALID_IDX;
			sxe2_qvinfo->ceq_idx = ceq_idx++;
		}
		sxe2_qvinfo->itr_idx = SXE2_IDX_NOITR;
		sxe2_qvinfo->v_idx   = rdma_func->sxe2_msixtbl[i].idx;
		pmsix++;
	}
end:
	return ret;
}

void sxe2_rdma_disassociate_ucontext(struct ib_ucontext *ibctx)
{
	(void)ibctx;
}

#ifdef HAVE_NO_IB_DEVICE_OPS
static const struct ib_device
#else
static const struct ib_device_ops
#endif
	sxe2_rdma_dev_ops = {

	.owner		  = THIS_MODULE,
	.driver_id	  = RDMA_DRIVER_SXE2,
	.uverbs_abi_ver	  = 1,
	.alloc_ucontext	  = sxe2_rdma_kalloc_ucontext,
	.dealloc_ucontext = sxe2_rdma_kdealloc_ucontext,
	.query_device	  = sxe2_rdma_kquery_device,
	.query_port	  = sxe2_rdma_kquery_port,
	.query_gid	  = sxe2_rdma_kquery_gid,
	.get_link_layer	  = sxe2_rdma_kget_link_layer,
	.query_pkey	  = sxe2_query_pkey,
	.get_dev_fw_str	  = sxe2_rdma_kget_dev_fw_str,
#ifndef CREATE_AH_NOT_SUPPORT
	.create_user_ah = sxe2_kcreate_ah,
#endif
	.create_ah     = sxe2_kcreate_ah,
	.query_ah      = sxe2_kquery_ah,
	.destroy_ah    = sxe2_kdestroy_ah,
	.alloc_mr      = sxe2_kalloc_mr,
	.reg_user_mr   = sxe2_kreg_user_mr,
	.rereg_user_mr = sxe2_krereg_user_mr,
	.get_dma_mr    = sxe2_kget_dma_mr,
	.dereg_mr      = sxe2_kdereg_mr,
#ifndef REG_USER_MR_DMABUF_VER_1
	.reg_user_mr_dmabuf = sxe2_kreg_user_mr_dmabuf,
#endif
	.poll_cq	    = sxe2_kpoll_cq,
	.post_recv	    = sxe2_kpost_recv,
	.post_send	    = sxe2_kpost_send,
	.post_srq_recv	    = sxe2_kpost_srq_recv,
	.req_notify_cq	    = sxe2_kreq_notify_cq,
	.map_mr_sg	    = sxe2_kmap_mr_sg,
	.get_port_immutable = sxe2_kget_port_immutable,
	.create_qp	    = sxe2_kcreate_qp,
	.destroy_qp	    = sxe2_kdestroy_qp,
	.modify_qp	    = sxe2_kmodify_qp,
	.query_qp	    = sxe2_kquery_qp,
	.create_srq	    = sxe2_kcreate_srq,
	.modify_srq	    = sxe2_kmodify_srq,
	.query_srq	    = sxe2_kquery_srq,
	.destroy_srq	    = sxe2_kdestroy_srq,
#ifdef ALLOC_HW_STATS_V1
	.alloc_hw_stats = sxe2_kalloc_hw_port_stats,
#else
	.alloc_hw_port_stats = sxe2_kalloc_hw_port_stats,
#endif
	.get_hw_stats = sxe2_kget_hw_stats,
	.mmap	      = sxe2_kmmap,
#ifndef RDMA_MMAP_DB_NOT_SUPPORT
	.mmap_free = sxe2_kmmap_free,
#endif
	.alloc_pd	       = sxe2_kalloc_pd,
	.dealloc_pd	       = sxe2_kdealloc_pd,
	.create_cq	       = sxe2_kcreate_cq,
	.modify_cq	       = sxe2_kmodify_cq,
	.destroy_cq	       = sxe2_kdestroy_cq,
	.modify_port	       = sxe2_rdma_kmodify_port,
	.get_netdev	       = sxe2_rdma_kget_net_dev,
	.disassociate_ucontext = sxe2_rdma_disassociate_ucontext,
	.attach_mcast	       = sxe2_kattach_mcast,
	.detach_mcast	       = sxe2_kdetach_mcast,

#ifndef GLOBAL_WM_MEM_NOT_SUPPORT
	INIT_RDMA_OBJ_SIZE(ib_mw, sxe2_mr, ibmw),
#endif
#ifndef GLOBAL_QP_MEM_NOT_SUPPORT
	INIT_RDMA_OBJ_SIZE(ib_qp, sxe2_rdma_qp, ibqp),
#endif
#ifndef HAVE_NO_DEFINE_STRUCT
	INIT_RDMA_OBJ_SIZE(ib_ah, sxe2_ah, ibah),
	INIT_RDMA_OBJ_SIZE(ib_cq, sxe2_rdma_cq, ibcq),
	INIT_RDMA_OBJ_SIZE(ib_pd, sxe2_rdma_pd, ibpd),
	INIT_RDMA_OBJ_SIZE(ib_srq, sxe2_rdma_srq, ibsrq),
	INIT_RDMA_OBJ_SIZE(ib_ucontext, sxe2_rdma_kcontext, ibucontext),
#endif
};

static void sxe2_add_handler(struct sxe2_rdma_handler *hdl)
{
	unsigned long flags = 0;

	spin_lock_irqsave(&sxe2_handler_lock, flags);
	list_add(&hdl->list, &sxe2_handlers);
	spin_unlock_irqrestore(&sxe2_handler_lock, flags);
}

static void sxe2_del_handler(struct sxe2_rdma_handler *hdl)
{
	unsigned long flags = 0;

	spin_lock_irqsave(&sxe2_handler_lock, flags);
	if (!list_empty(&hdl->list))
		list_del(&hdl->list);
	spin_unlock_irqrestore(&sxe2_handler_lock, flags);
}

static unsigned int sxe2_calc_mem_rsrc_size(struct sxe2_rdma_pci_f *rf)
{
	unsigned int rsrc_size;

	rsrc_size = (unsigned int)(sizeof(unsigned long) *
				   BITS_TO_LONGS(rf->max_qp));
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_mr);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_cq);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_pd);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_ah);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_qsets);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_dbs);
	rsrc_size += sizeof(unsigned long) * BITS_TO_LONGS(rf->max_srq);

	rsrc_size += sizeof(struct sxe2_rdma_qp **) * rf->max_qp;
	rsrc_size += sizeof(struct sxe2_rdma_cq **) * rf->max_cq;
	rsrc_size += sizeof(struct sxe2_rdma_srq **) * rf->max_srq;

	return rsrc_size;
}

static void sxe2_rdma_set_hw_rsrc(struct sxe2_rdma_pci_f *rf)
{
	rf->allocated_qps  = (void *)rf->mem_rsrc;
	rf->allocated_cqs  = &rf->allocated_qps[BITS_TO_LONGS(rf->max_qp)];
	rf->allocated_srqs = &rf->allocated_cqs[BITS_TO_LONGS(rf->max_cq)];
	rf->allocated_mrs  = &rf->allocated_srqs[BITS_TO_LONGS(rf->max_srq)];
	rf->allocated_pds  = &rf->allocated_mrs[BITS_TO_LONGS(rf->max_mr)];
	rf->allocated_ahs  = &rf->allocated_pds[BITS_TO_LONGS(rf->max_pd)];
	rf->allocated_qset = &rf->allocated_ahs[BITS_TO_LONGS(rf->max_ah)];
	rf->allocated_dbs  = &rf->allocated_qset[BITS_TO_LONGS(rf->max_qsets)];
	rf->qp_table =
		(struct sxe2_rdma_qp *
			 *)(&rf->allocated_dbs[BITS_TO_LONGS(rf->max_dbs)]);
	rf->cq_table  = (struct sxe2_rdma_cq **)(&rf->qp_table[rf->max_qp]);
	rf->srq_table = (struct sxe2_rdma_srq **)(&rf->cq_table[rf->max_cq]);

	spin_lock_init(&rf->rsrc_lock);
	spin_lock_init(&rf->qptable_lock);
	spin_lock_init(&rf->cqtable_lock);
	spin_lock_init(&rf->srqtable_lock);
	spin_lock_init(&rf->qh_list_lock);
}

static int sxe2_init_hw_rsrc(struct sxe2_rdma_device *rdma_dev)
{
	unsigned int rsrc_size;
	unsigned int mrdrvbits	   = 0;
	int ret			   = 0;
	struct sxe2_rdma_pci_f *rf = rdma_dev->rdma_func;
	int count_order		   = 0;

	rf->bar_db_addr = (phys_addr_t)(pci_resource_start(rf->pcidev, 0) +
					rf->ctx_dev.rcms_info->db_bar_addr);

	rf->max_cqe = rf->ctx_dev.hw_attrs.uk_attrs.max_hw_cq_size;
	rf->max_qp  = rf->ctx_dev.rcms_info->rcms_obj[SXE2_RCMS_OBJ_QP].cnt;
	rf->max_mr  = rf->ctx_dev.rcms_info->rcms_obj[SXE2_RCMS_OBJ_MR].cnt;
	rf->max_cq  = rf->ctx_dev.rcms_info->rcms_obj[SXE2_RCMS_OBJ_CQ].cnt;
	rf->max_pd  = rf->ctx_dev.hw_attrs.max_hw_pds;
	rf->max_ah  = rf->ctx_dev.rcms_info->rcms_obj[SXE2_RCMS_OBJ_AH].cnt;
	rf->max_dbs = rf->ctx_dev.rcms_info->max_db_page_num;
	rf->max_srq = rf->ctx_dev.rcms_info->rcms_obj[SXE2_RCMS_OBJ_SRQ].cnt;
	rf->max_cc_qp_cnt = rf->ctx_dev.rcms_info->max_cc_qp_cnt;
	if (!rf->ftype)
		rf->max_qsets = SXE2_PF_MAX_QSET_CNT;
	else
		rf->max_qsets = SXE2_VF_MAX_QSET_CNT;

	rsrc_size = sxe2_calc_mem_rsrc_size(rf);

	rf->mem_rsrc = vzalloc(rsrc_size);
	if (!rf->mem_rsrc) {
		ret = -ENOMEM;
		goto end;
	}

	sxe2_rdma_set_hw_rsrc(rf);

	set_bit(0, rf->allocated_mrs);
	set_bit(0, rf->allocated_qps);
	set_bit(0, rf->allocated_cqs);
	set_bit(0, rf->allocated_pds);
	set_bit(0, rf->allocated_ahs);
	set_bit(1, rf->allocated_qps);

	set_bit(1, rf->allocated_dbs);

	count_order	= get_count_order(rf->max_mr);
	mrdrvbits	= 24 - max(count_order, 14);
	rf->mr_stagmask = ~(u32)(((1 << mrdrvbits) - 1) << (32 - mrdrvbits));
	atomic_set(&rf->cc_refcount.cc_qp_refcount, 0);
	mutex_init(&rf->cc_refcount.refcount_lock);
end:
	return ret;
}

static int sxe2_init_rsrc_wq(struct sxe2_rdma_device *rdma_dev)
{
	int ret = 0;

	rdma_dev->cleanup_wq = alloc_workqueue(
		"sxe2rdma-cleanup-wq", WQ_UNBOUND, WQ_UNBOUND_MAX_ACTIVE);
	if (!rdma_dev->cleanup_wq) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("cleanup-wq alloc failed. ret:%d\n", ret);
		goto end;
	}

	rdma_dev->rdma_func->used_pds =
		(u32)find_first_zero_bit(rdma_dev->rdma_func->allocated_pds,
					 rdma_dev->rdma_func->max_pd);
	rdma_dev->rdma_func->used_qps =
		(u32)find_first_zero_bit(rdma_dev->rdma_func->allocated_qps,
					 rdma_dev->rdma_func->max_qp);
	rdma_dev->rdma_func->used_cqs =
		(u32)find_first_zero_bit(rdma_dev->rdma_func->allocated_cqs,
					 rdma_dev->rdma_func->max_cq);
	rdma_dev->rdma_func->used_mrs =
		(u32)find_first_zero_bit(rdma_dev->rdma_func->allocated_mrs,
					 rdma_dev->rdma_func->max_mr);
	rdma_dev->rdma_func->used_srqs =
		(u32)find_first_zero_bit(rdma_dev->rdma_func->allocated_srqs,
					 rdma_dev->rdma_func->max_srq);

	init_waitqueue_head(&rdma_dev->suspend_wq);

end:
	return ret;
}

static int sxe2_rdma_wait_fw_ready(struct sxe2_rdma_ctx_dev *dev)
{
	int ret = SXE2_OK;
	return ret;
}

static struct sxe2_rdma_vchnl_if sxe2_vchnl_if_pf = {
	.vchnl_recv = sxe2_vchnl_recv_pf,
};

static struct sxe2_rdma_vchnl_if sxe2_vchnl_if_vf = {
	.vchnl_recv = sxe2_vchnl_recv_vf,
};

static int sxe2_rdma_vchnl_init(struct sxe2_rdma_device *rdma_dev,
				struct aux_core_dev_info *cdev_info,
				u8 *rdma_ver)
{
	int ret = SXE2_OK;
	struct sxe2_vchnl_init_info virt_info;
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;
	u8 gen				  = cdev_info->rdma_caps.gen;

	rdma_func->vchnl_wq =
		alloc_ordered_workqueue("sxe2rdma-virtchnl-wq", 0);
	if (!rdma_func->vchnl_wq) {
		DRV_RDMA_LOG_ERROR_BDF("probe:alloc vchnl wq err ret=%d\n", ret);
		ret = -ENOMEM;
		goto end;
	}

	mutex_init(&rdma_func->ctx_dev.vchnl_mutex);
	virt_info.hw_rev = !gen ? SXE2_RDMA_GEN_1 : gen;
	if (cdev_info->ftype)
		virt_info.privileged = false;
	else
		virt_info.privileged = true;

	virt_info.vchnl_if =
		virt_info.privileged ? &sxe2_vchnl_if_pf : &sxe2_vchnl_if_vf;
	virt_info.vchnl_wq = rdma_func->vchnl_wq;
	ret = sxe2_vchnl_ctx_init(&rdma_func->ctx_dev, &virt_info);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_ERROR_BDF("probe:vchnl ctx init err ret=%d\n", ret);
		goto vchnl_ctx_init_err;
	}
	*rdma_ver = rdma_func->ctx_dev.hw_attrs.uk_attrs.hw_rev;
	goto end;

vchnl_ctx_init_err:
	destroy_workqueue(rdma_func->vchnl_wq);
end:
	return ret;
}

int sxe2_rdma_init_ctx_dev(struct sxe2_rdma_ctx_dev *dev,
				  struct sxe2_rdma_device_init_info *info)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);

	INIT_LIST_HEAD(&dev->mq_cmd_head);
	mutex_init(&dev->lag_mutex);
	dev->rcms_fn_id	       = info->rcms_fn_id;
	dev->num_vfs	       = info->max_vfs;
	dev->fpm_query_buf_pa  = info->fpm_query_buf_pa;
	dev->fpm_query_buf     = info->fpm_query_buf;
	dev->fpm_commit_buf_pa = info->fpm_commit_buf_pa;
	dev->fpm_commit_buf    = info->fpm_commit_buf;
	dev->hw		       = info->hw;
	dev->hw->hw_addr       = info->bar0;
	dev->hw_attrs.min_hw_qp_id	       = SXE2_MIN_IW_QP_ID;
	dev->hw_attrs.min_hw_srq_id	       = SXE2_MIN_IW_SRQ_ID;
	dev->hw_attrs.min_hw_aeq_size	       = SXE2_MIN_AEQ_ENTRIES;
	dev->hw_attrs.max_hw_aeq_size	       = SXE2_MAX_AEQ_ENTRIES;
	dev->hw_attrs.min_hw_ceq_size	       = SXE2_MIN_CEQ_ENTRIES;
	dev->hw_attrs.max_hw_ceq_size	       = SXE2_MAX_CEQ_ENTRIES;
	dev->hw_attrs.uk_attrs.min_hw_cq_size  = SXE2_MIN_CQ_SIZE;
	dev->hw_attrs.uk_attrs.max_hw_cq_size  = SXE2_MAX_CQ_SIZE;
	dev->hw_attrs.max_mr_size	       = SXE2_MAX_MR_SIZE;
	dev->hw_attrs.max_hw_outbound_msg_size = SXE2_MAX_OUTBOUND_MSG_SIZE;
	dev->hw_attrs.max_hw_inbound_msg_size  = SXE2_MAX_INBOUND_MSG_SIZE;
	dev->hw_attrs.uk_attrs.max_hw_inline   = SXE2_MAX_INLINE_DATA_SIZE;
	dev->hw_attrs.max_hw_wqes	       = SXE2_MAX_WQ_ENTRIES;
	dev->hw_attrs.max_qp_wr = SXE2_MAX_QP_WRS(SXE2_MAX_QUANTA_PER_WR);
	dev->hw_attrs.uk_attrs.max_hw_rq_quanta = SXE2_QP_SW_MAX_RQ_QUANTA;
	dev->hw_attrs.uk_attrs.max_hw_wq_quanta = SXE2_QP_SW_MAX_WQ_QUANTA;
	dev->hw_attrs.max_hw_pds		= SXE2_MAX_PDS;
	dev->hw_attrs.max_hw_ena_vf_count	= SXE2_MAX_PE_ENA_VF_COUNT;
	dev->hw_attrs.max_pe_ready_count	= 14;
	dev->hw_attrs.max_done_count		= SXE2_DONE_COUNT;
	dev->hw_attrs.max_sleep_count		= SXE2_SLEEP_COUNT;
	dev->hw_attrs.max_mq_compl_wait_time_ms = SXE2_MQ_COMPL_WAIT_TIME_MS;
	dev->hw_attrs.uk_attrs.max_hw_srq_quanta = SXE2_SRQ_SW_MAX_SRQ_QUANTA;
	dev->hw_attrs.uk_attrs.max_hw_srq_wr = SXE2_MAX_SRQ_WRS;
	if (!dev->privileged) {
		ret = sxe2_vchnl_req_get_rcms_fcn(dev);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR(
				"probe:vchnl get rcms fcn err ret=%d\n", ret);
			goto end;
		}
	}
	spin_lock_init(&dev->vc_dev_lock);
	sxe2_rdma_init_hw(dev);

	if (dev->privileged) {
		if (sxe2_rdma_wait_fw_ready(dev)) {
			DRV_RDMA_LOG_DEV_ERR(
				"probe:fw is not read err ret=%d\n", ret);
			ret = -ETIMEDOUT;
			goto end;
		}
	}

end:
	return ret;
}

int sxe2_rdma_initialize_dev(struct sxe2_rdma_pci_f *rdma_func)
{
	int ret				       = SXE2_OK;
	struct sxe2_rdma_ctx_dev *dev	       = &rdma_func->ctx_dev;
	struct sxe2_rdma_device_init_info info = {};
	struct sxe2_rdma_dma_mem mem;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	u32 size;

	size = sizeof(struct sxe2_pbl_pble_rsrc) +
	       (sizeof(struct sxe2_rcms_obj_info) * SXE2_RCMS_OBJ_MAX);
	rdma_func->rcms_info_mem = kzalloc(size, GFP_KERNEL);
	if (!rdma_func->rcms_info_mem) {
		DRV_RDMA_LOG_DEV_ERR("probe:alloc rcms pbl mem err\n");
		ret = -ENOMEM;
		goto end;
	}

	rdma_func->pble_rsrc =
		(struct sxe2_pbl_pble_rsrc *)rdma_func->rcms_info_mem;
	dev->rcms_info = &rdma_func->hw.rcms;
	dev->rcms_info->rcms_obj =
		(struct sxe2_rcms_obj_info *)(rdma_func->pble_rsrc + 1);
	ret = sxe2_kget_aligned_mem(rdma_func, &mem, SXE2_QUERY_FPM_BUF_SIZE,
				    SXE2_FPM_QUERY_BUF_ALIGNMENT_M);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR(
			"probe:query buffer aligned mem err ret=%d\n", ret);
		goto error;
	}
	info.fpm_query_buf_pa = mem.pa;
	info.fpm_query_buf    = mem.va;

	ret = sxe2_kget_aligned_mem(rdma_func, &mem, SXE2_COMMIT_FPM_BUF_SIZE,
				    SXE2_FPM_COMMIT_BUF_ALIGNMENT_M);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR(
			"probe:commit buffer aligned mem err ret=%d\n", ret);
		goto error;
	}
	info.fpm_commit_buf_pa = mem.pa;
	info.fpm_commit_buf    = mem.va;
	info.bar0	       = rdma_func->hw.hw_addr;
	info.rcms_fn_id	       = rdma_func->pf_id;
	info.max_vfs	       = rdma_func->max_rdma_vfs;
	info.hw		       = &rdma_func->hw;
	ret = sxe2_rdma_init_ctx_dev(&rdma_func->ctx_dev, &info);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR("probe:init ctx dev err ret=%d\n", ret);
		goto error;
	}
	if (!rdma_func->ctx_dev.privileged) {
		ret = sxe2_vchnl_req_get_vlan_parsing_cfg(
			&rdma_func->ctx_dev, &rdma_func->vlan_parse_en);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR(
				"probe:vf vchnl vlan parsing err ret=%d\n",
				ret);
			goto error;
		}
	} else {
		rdma_func->vlan_parse_en = 1;
	}
	goto end;
error:
	kfree(rdma_func->rcms_info_mem);
	rdma_func->rcms_info_mem = NULL;
end:
	return ret;
}

static void sxe2_destroy_rsrc_wq(struct sxe2_rdma_device *rdma_dev)
{
	if (rdma_dev->cleanup_wq)
		destroy_workqueue(rdma_dev->cleanup_wq);
}
static void sxe2_rdma_init_device(struct sxe2_rdma_device *rdma_dev)
{
	rdma_dev->ibdev.node_type = RDMA_NODE_IB_CA;
#ifdef UVERBS_CMD_MASK
	kc_set_rdma_uverbs_cmd_mask(&rdma_dev->ibdev);
#endif
	addrconf_addr_eui48((u8 *)&rdma_dev->ibdev.node_guid,
			    rdma_dev->netdev->dev_addr);
	rdma_dev->ibdev.phys_port_cnt	 = 1;
	rdma_dev->ibdev.num_comp_vectors = (int)rdma_dev->rdma_func->ceqs_count;
	rdma_dev->ibdev.dev.parent	 = &rdma_dev->rdma_func->pcidev->dev;

#ifdef HAVE_NO_IB_DEVICE_OPS
	sxe2_set_device_ops(&rdma_dev->ibdev);
#else
	ib_set_device_ops(&rdma_dev->ibdev, &sxe2_rdma_dev_ops);
#endif
}

static void sxe2_port_ibevent(struct sxe2_rdma_device *rdma_dev)
{
	struct ib_event event;

	event.device	       = &rdma_dev->ibdev;
	event.element.port_num = 1;
	event.event =
		rdma_dev->iw_status ? IB_EVENT_PORT_ACTIVE : IB_EVENT_PORT_ERR;
	ib_dispatch_event(&event);
}

static void sxe2_set_ib_devname(struct sxe2_rdma_device *rdma_dev)
{
	const char *name = rdma_dev->lag_mode ? "sxe2rdma_bond%d" : "sxe2rdma%d";

	strscpy(rdma_dev->ib_devname, name, sizeof(rdma_dev->ib_devname));
}

static int sxe2_ib_register_device(struct sxe2_rdma_device *rdma_dev)
{
	int ret = 0;

	sxe2_set_ib_devname(rdma_dev);

	sxe2_rdma_init_device(rdma_dev);
#ifdef NETDEV_SET_NOT_SUPPORT
	dev_hold(rdma_dev->netdev);
#else
	ret = ib_device_set_netdev(&rdma_dev->ibdev, rdma_dev->netdev, 1);
#endif
	if (ret != 0)
		goto end;

	strscpy(rdma_dev->ibdev.name, rdma_dev->ib_devname,
		sizeof(rdma_dev->ibdev.name));

	dma_set_max_seg_size(rdma_dev->rdma_func->hw.device, UINT_MAX);
#ifdef REGISTER_DEV_NEED_2_PARAMS
	ret = ib_register_device(&rdma_dev->ibdev, rdma_dev->ib_devname);
#elif defined REGISTER_DEV_NEED_CHAR_PARAM
	ret = ib_register_device(&rdma_dev->ibdev, NULL);
#else
	ret = ib_register_device(&rdma_dev->ibdev, rdma_dev->ib_devname,
				 rdma_dev->rdma_func->hw.device);
#endif
	if (ret != 0)
		goto end;

	rdma_dev->iw_status = 1;
	sxe2_port_ibevent(rdma_dev);

end:
	return ret;
}

void sxe2_rdma_set_qos_info(struct sxe2_rdma_ctx_vsi *vsi,
			    struct sxe2_rdma_l2params *l2p)
{
	u8 i;
	u8 index;

	for (index = 0; index < QOS_MAX_QSET_NUM_PER_USER_PRI; index++) {
		vsi->qos_rel_bw[index]	   = l2p[index].vsi_rel_bw;
		vsi->qos_prio_type[index] = l2p[index].vsi_prio_type;
		vsi->dscp_mode[index]	   = l2p[index].dscp_mode;
		if (l2p[index].dscp_mode)
			memcpy(vsi->dscp_map[index], l2p[index].dscp_map,
			sizeof(vsi->dscp_map[index]));
		for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++)
			vsi->tc_print_warning[i] = true;

		for (i = 0; i < SXE2_MAX_USER_PRIORITY; i++) {
			vsi->qos[i].qset[index].traffic_class = l2p[index].up2tc[i];
			vsi->qos[i].rel_bw[index] =
				l2p[index].tc_info[vsi->qos[i].qset[index].traffic_class].rel_bw;
			vsi->qos[i].prio_type[index] =
				l2p[index].tc_info[vsi->qos[i].qset[index].traffic_class].prio_type;
			vsi->qos[i].valid = false;
		}
	}

}

static int sxe2_rdma_fill_device_info(struct sxe2_rdma_device *rdma_dev,
				      struct aux_core_dev_info *cdev_info)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;

	rdma_func->ctx_dev.hw		    = &rdma_func->hw;
	rdma_func->rdma_dev		    = rdma_dev;
	rdma_func->cdev			    = cdev_info;
	rdma_func->hw.hw_addr		    = cdev_info->hw_addr;
	rdma_func->pcidev		    = cdev_info->pdev;
	rdma_func->hw.device		    = &rdma_func->pcidev->dev;
	rdma_func->ftype		    = cdev_info->ftype;
	rdma_func->msix_count		    = cdev_info->msix_count;
	rdma_func->msix_entries		    = cdev_info->msix_entries;
	rdma_func->vfid_base		    = cdev_info->vfid_base;
	rdma_func->ack_mode		        = 0;
	rdma_func->scqe_break_moderation_en = 0;
	rdma_func->log_ack_req_freq	   = 8;
	rdma_func->aeq_pble_en		   = false;
	rdma_func->hygon_cpu_en		   = hygon_cpu_en;
	rdma_func->app_mod_all_flush   = FUNCTION_ENABLE;
	rdma_func->en_rem_endpoint_trk = FUNCTION_DISABLE;
	rdma_func->oi			       = FUNCTION_DISABLE;
	rdma_func->pf_cnt		       = cdev_info->pf_cnt;
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	rdma_func->inject_qos.apply_qset_err_code   = 0;
	rdma_func->inject_qos.qp_bind_qset_err_code = 0;
	rdma_func->inject_qos.release_qset_err_code = 0;
	rdma_func->inject_sleep_time		    = inject_sleep_time;
#endif
	ret = sxe2_rdma_vchnl_init(rdma_dev, cdev_info, &rdma_func->rdma_ver);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR("probe:virtual channel init  err ret=%d\n",
				     ret);
		goto end;
	}
	rdma_func->pf_id = cdev_info->pf_id;
	if (!cdev_info->ftype) {
		rdma_func->gen_ops.register_qsets = sxe2_qos_lan_register_qsets;
		rdma_func->gen_ops.unregister_qsets =
			sxe2_qos_lan_unregister_qsets;
	}

	rdma_func->default_vsi.vsi_idx = cdev_info->vport_id;
	rdma_func->protocol_used = SXE2_ROCE_PROTOCOL_ONLY;
	rdma_func->rsrc_profile	 = SXE2_RCMS_PROFILE_DEFAULT;

	rdma_func->gen_ops.request_reset = sxe2_rdma_request_reset;
	sxe2_rdma_set_func_user_cfg_params(rdma_func);
	sxe2_rdma_init_cc_params(rdma_func);
	mutex_init(&rdma_dev->ah_tbl_lock);

	rdma_dev->lag_mode = cdev_info->bond_mode;
	DRV_RDMA_LOG_DEV_DEBUG("get lag_mode %d\n", rdma_dev->lag_mode);
	if (rdma_dev->lag_mode) {
		rcu_read_lock();
		rdma_dev->netdev =
			netdev_master_upper_dev_get_rcu(cdev_info->netdev);
		rcu_read_unlock();
	}

	if (!rdma_dev->netdev) {
		rdma_dev->netdev = cdev_info->netdev;
		DRV_RDMA_LOG_DEV_DEBUG(
			"get netdev from cdev: rdma_pf_bitmap %#x\n",
			cdev_info->rdma_pf_bitmap);
	}
	rdma_dev->vsi_num	= cdev_info->vport_id;
	rdma_dev->roce_cwnd	= SXE2_ROCE_CWND_DEFAULT;
	rdma_dev->roce_ackcreds = SXE2_ROCE_ACKCREDS_DEFAULT;
	rdma_dev->rcv_wnd	= SXE2_CM_DEFAULT_RCV_WND_SCALED;
	rdma_dev->rcv_wscale	= SXE2_CM_DEFAULT_RCV_WND_SCALE;
	rdma_dev->kernel_llwqe_mode = 0;
	rdma_dev->roce_dcqcn_en = rdma_dev->rdma_func->cc_params.dcqcn_enable;
	rdma_dev->roce_mode	= true;

end:
	return ret;
}

static void sxe2_init_dflt_pkey(struct sxe2_rdma_ctx_dev *dev, u32 pf_id)
{
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	union sxe2_rdma_cfg_pkey_bar cfg_pkey_bar;
	u32 __iomem *addr;
	int i;

	cfg_pkey_bar.bar_val	       = SXE2_PEKY_REG_INVALID_VAL;
	cfg_pkey_bar.pkey_bar.pkey     = SXE2_DEFAULT_PKEY_VAL;
	cfg_pkey_bar.pkey_bar.pkey_vld = true;
	for (i = 0; i < SXE2_MAX_PORT_CNT; i++) {
		cfg_pkey_bar.pkey_bar.pkey_port = (u32)i;
		addr = SXE2_PKEY_TBLE_BAR_ADDR(dev->hw_regs[RDMA_CONFIG_PKEY],
					       i);
		SXE2_BAR_WRITE_32(cfg_pkey_bar.bar_val, addr);
	}

	for (i = SXE2_MAX_PORT_CNT; i < SXE2_MAX_PKEY_CNT; i++) {
		cfg_pkey_bar.pkey_bar.pkey_port = pf_id;
		addr = SXE2_PKEY_TBLE_BAR_ADDR(dev->hw_regs[RDMA_CONFIG_PKEY],
					       i);
		SXE2_BAR_WRITE_32(cfg_pkey_bar.bar_val, addr);
	}
	DRV_RDMA_LOG_DEV_DEBUG("probe:config pkey port val=%u\n",
			       cfg_pkey_bar.bar_val);
}

static void sxe2_invalid_dflt_pkey(struct sxe2_rdma_ctx_dev *dev)
{
	union sxe2_rdma_cfg_pkey_bar cfg_pkey_bar;
	u32 __iomem *addr;
	int i;

	cfg_pkey_bar.bar_val = SXE2_PEKY_REG_INVALID_VAL;

	for (i = 0; i < SXE2_MAX_PKEY_CNT; i++) {
		addr = SXE2_PKEY_TBLE_BAR_ADDR(dev->hw_regs[RDMA_CONFIG_PKEY],
					       i);
		SXE2_BAR_WRITE_32(cfg_pkey_bar.bar_val, addr);
	}
}

bool sxe2_get_hw_rsrc_clean_flag(struct sxe2_rdma_ctx_dev *dev)
{
	union sxe2_rdma_cfg_pkey_bar cfg_pkey_bar;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	bool ret			  = false;

	cfg_pkey_bar.bar_val = SXE2_BAR_READ_32(dev->hw_regs[RDMA_CONFIG_PKEY]);
	if (cfg_pkey_bar.bar_val == SXE2_BAR_REG_AUTO_RESP_VAL) {
		DRV_RDMA_LOG_DEV_DEBUG(
			"probe:pcie start automated response hw rsrc clean\n");
		ret = true;
	} else if (!dev->privileged &&
		   cfg_pkey_bar.bar_val == SXE2_BAR_REG_INVALID_VAL) {
		DRV_RDMA_LOG_DEV_DEBUG("probe:hw rsrc clean\n");
		ret = true;
	}
	if (cfg_pkey_bar.pkey_bar.pkey_vld == false) {
		DRV_RDMA_LOG_DEV_DEBUG("probe:hw rsrc clean\n");
		ret = true;
	} else {
		DRV_RDMA_LOG_DEV_DEBUG("probe:hw rsrc not clean\n");
	}

	if (ret && !rdma_dev->rdma_func->reset) {
		DRV_RDMA_LOG_DEV_WARN("func reset status=[%d] and resource dead!\n",
								rdma_dev->rdma_func->reset);
		rdma_dev->rdma_func->reset = true;
	}

	return ret;
}

int sxe2_rdma_setup_init_state(struct sxe2_rdma_device *rdma_dev)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;

	ret = sxe2_rdma_save_msix_info(rdma_func);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR("probe:save msix info err ret=%d\n", ret);
		goto end;
	}
	rdma_func->obj_mem.size = SXE2_RDMA_MCQ_HW_PAGE_SIZE;
	rdma_func->obj_mem.va =
		dma_alloc_coherent(rdma_func->hw.device,
				   rdma_func->obj_mem.size,
				   &rdma_func->obj_mem.pa, GFP_KERNEL);
	if (!rdma_func->obj_mem.va) {
		DRV_RDMA_LOG_DEV_ERR("probe:alloc obj mem err ret=%d\n", ret);
		ret = -ENOMEM;
		goto clean_msixtbl;
	}

	rdma_func->obj_next = rdma_func->obj_mem;
	ret		    = sxe2_rdma_initialize_dev(rdma_func);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR("probe:initialize dev err ret=%d\n", ret);
		goto clean_obj_mem;
	}
	sxe2_init_dflt_pkey(&rdma_func->ctx_dev, rdma_func->pf_id);
	goto end;

clean_obj_mem:
	dma_free_coherent(rdma_func->hw.device, rdma_func->obj_mem.size,
			  rdma_func->obj_mem.va, rdma_func->obj_mem.pa);
	rdma_func->obj_mem.va = NULL;
clean_msixtbl:
	kfree(rdma_func->sxe2_msixtbl);
	rdma_func->sxe2_msixtbl = NULL;
end:
	return ret;
}

static int sxe2_rdma_init_vsi_ctx(struct sxe2_rdma_device *rdma_dev)
{
	int ret				  = SXE2_OK;
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;
	struct aux_core_dev_info *cdev_info =
		(struct aux_core_dev_info *)rdma_func->cdev;
	struct sxe2_rdma_l2params l2params[QOS_MAX_QSET_NUM_PER_USER_PRI] = {0};
	struct sxe2_rdma_ctx_dev *dev	   = &rdma_func->ctx_dev;
	struct sxe2_rdma_ctx_vsi *vsi	   = &rdma_dev->vsi;
	u8 i;

	l2params[0].mtu = (u16)rdma_dev->netdev->mtu;
	sxe2_rdma_fill_qos_info(l2params, cdev_info->qos_info);
	vsi->dev	      = dev;
	vsi->back_vsi	      = rdma_dev;
	vsi->register_qsets   = rdma_func->gen_ops.register_qsets;
	vsi->unregister_qsets = rdma_func->gen_ops.unregister_qsets;
	vsi->mtu	      = l2params[0].mtu;
	vsi->exception_lan_q  = 2;
	vsi->vsi_idx	      = rdma_dev->vsi_num;
	vsi->lag_aa	      = rdma_dev->lag_mode == SXE2_LAG_ACTIVE_ACTIVE;
	vsi->lag_backup   = rdma_dev->lag_mode == SXE2_LAG_ACTIVE_PASSIVE;
	atomic_set(&vsi->port1_qp_cnt, 0);
	atomic_set(&vsi->port2_qp_cnt, 0);

	if (vsi->lag_aa && !rdma_func->ftype)
		rdma_func->max_qsets = SXE2_PF_MAX_QSET_CNT;
	else
		rdma_func->max_qsets = SXE2_PF_MAX_QSET_CNT_NO_LAG_AA;

	vsi->vm_vf_type = rdma_func->ftype ? SXE2_VF_TYPE : SXE2_PF_TYPE;
	sxe2_rdma_set_qos_info(vsi, l2params);
	for (i = 0; i < SXE2_MAX_USER_PRIORITY; i++) {
		mutex_init(&vsi->qos[i].qos_mutex);
		INIT_LIST_HEAD(&vsi->qos[i].qset[0].qp_list);
		INIT_LIST_HEAD(&vsi->qos[i].qset[1].qp_list);
	}

	ret = drv_rdma_debug_qos_add(rdma_dev);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR(
			"ERR: failed adding qos to debug file system ret=%d\n",
			ret);
	}
#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)
	ret = drv_rdma_qos_err_code_inject_add(rdma_dev);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR(
			"ERR: failed adding qos inject errcode to debug file system ret=%d\n",
			ret);
	}
#endif

	return ret;
}

static void sxe2_rdma_del_vsi_ctx(struct sxe2_rdma_device *rdma_dev)
{
	struct sxe2_rdma_ctx_vsi *vsi = &rdma_dev->vsi;
	u8 i;

	for (i = 0; i < SXE2_MAX_USER_PRIORITY; i++)
		mutex_destroy(&vsi->qos[i].qos_mutex);
}

static void sxe2_rdma_del_init_mem(struct sxe2_rdma_device *rdma_dev)
{
	struct sxe2_rdma_pci_f *rdma_func = rdma_dev->rdma_func;

	sxe2_invalid_dflt_pkey(&rdma_func->ctx_dev);
	if (!rdma_func->ctx_dev.privileged)
		sxe2_vchnl_req_put_rcms_fcn(&rdma_func->ctx_dev);

	if (rdma_func->mem_rsrc != NULL) {
		vfree(rdma_func->mem_rsrc);
		rdma_func->mem_rsrc = NULL;
	}

	if (rdma_func->obj_mem.va != NULL) {
		dma_free_coherent(rdma_func->hw.device, rdma_func->obj_mem.size,
				  rdma_func->obj_mem.va, rdma_func->obj_mem.pa);
		rdma_func->obj_mem.va = NULL;
	}
	if (rdma_func->ceqlist != NULL) {
		kfree(rdma_func->ceqlist);
		rdma_func->ceqlist = NULL;
	}
	if (rdma_func->sxe2_msixtbl != NULL) {
		kfree(rdma_func->sxe2_msixtbl);
		rdma_func->sxe2_msixtbl = NULL;
	}
	if (rdma_func->rcms_info_mem != NULL) {
		kfree(rdma_func->rcms_info_mem);
		rdma_func->rcms_info_mem = NULL;
	}
}
static void sxe2_ib_unregister_device(struct sxe2_rdma_device *rdma_dev)
{
	rdma_dev->iw_status = 0;
	DRV_RDMA_LOG_DEV_DEBUG("remove:start unregister device\n");
	sxe2_port_ibevent(rdma_dev);

	ib_unregister_device(&rdma_dev->ibdev);
#ifdef NETDEV_SET_NOT_SUPPORT
	dev_put(rdma_dev->netdev);
#endif
	DRV_RDMA_LOG_DEV_DEBUG("remove:unregister device finish\n");
}

static void sxe2_gid_change_event(struct ib_device *ibdev)
{
	struct ib_event ib_event;

	ib_event.event		  = IB_EVENT_GID_CHANGE;
	ib_event.device		  = ibdev;
	ib_event.element.port_num = 1;
	ib_dispatch_event(&ib_event);
}

static int sxe2_khandle_inetaddr_event(struct notifier_block *notifier,
				       unsigned long event, void *ptr)
{
	struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
	struct net_device *real_dev, *netdev = ifa->ifa_dev->dev;
	struct sxe2_rdma_device *rdma_dev;
	u32 local_ipaddr[4] = {};
	int ret;

	real_dev = rdma_vlan_dev_real_dev(netdev);
	if (!real_dev)
		real_dev = netdev;

	rdma_dev = container_of(notifier, struct sxe2_rdma_device,
				nb_inetaddr_event);
	if (rdma_dev->netdev != real_dev) {
		ret = NOTIFY_DONE;
		goto end;
	}

	local_ipaddr[0] = ntohl(ifa->ifa_address);
	DRV_RDMA_LOG_DEV_INFO(
		"DEV: netdev %s event %lu local_ip=%pI4 MAC=%pM\n",
		netdev_name(netdev), event, &local_ipaddr, netdev->dev_addr);
	switch (event) {
	case NETDEV_DOWN:
		sxe2_gid_change_event(&rdma_dev->ibdev);
		break;
	case NETDEV_UP:
	case NETDEV_CHANGEADDR:
		sxe2_gid_change_event(&rdma_dev->ibdev);
		break;
	default:
		break;
	}

	ret = NOTIFY_DONE;

end:
	return ret;
}

static int sxe2_khandle_inet6addr_event(struct notifier_block *notifier,
					unsigned long event, void *ptr)
{
	struct inet6_ifaddr *ifa    = (struct inet6_ifaddr *)ptr;
	struct net_device *real_dev = NULL;
	struct net_device *netdev   = NULL;
	struct sxe2_rdma_device *rdma_dev;
	u32 local_ipaddr6[4];
	int ret;

	netdev	 = ifa->idev->dev;
	real_dev = rdma_vlan_dev_real_dev(netdev);
	if (!real_dev)
		real_dev = netdev;

	rdma_dev = container_of(notifier, struct sxe2_rdma_device,
				nb_inet6addr_event);
	if (rdma_dev->netdev != real_dev) {
		ret = NOTIFY_DONE;
		goto end;
	}

	sxe2_copy_ip_ntohl(local_ipaddr6, ifa->addr.in6_u.u6_addr32);
	DRV_RDMA_LOG_DEV_INFO(
		"DEV: netdev %s event %lu local_ip=%pI6 MAC=%pM\n",
		netdev_name(netdev), event, local_ipaddr6, netdev->dev_addr);

	switch (event) {
	case NETDEV_DOWN:
		sxe2_gid_change_event(&rdma_dev->ibdev);
		break;
	case NETDEV_UP:
	case NETDEV_CHANGEADDR:
		sxe2_gid_change_event(&rdma_dev->ibdev);
		break;
	default:
		break;
	}

	ret = NOTIFY_DONE;

end:
	return ret;
}

static int sxe2_khandle_net_event(struct notifier_block *notifier,
				  unsigned long event, void *ptr)
{
	struct neighbour *neigh		  = (struct neighbour *)ptr;
	struct net_device *real_dev	  = NULL;
	struct net_device *netdev	  = (struct net_device *)neigh->dev;
	struct sxe2_rdma_device *rdma_dev = NULL;
	__be32 *p;
	u32 local_ipaddr[4] = {};
	int ret;

	switch (event) {
	case NETEVENT_NEIGH_UPDATE:
		real_dev = rdma_vlan_dev_real_dev(netdev);
		if (!real_dev)
			real_dev = netdev;

		rdma_dev = container_of(notifier, struct sxe2_rdma_device,
					nb_net_event);
		if (rdma_dev->netdev != real_dev) {
			ret = NOTIFY_DONE;
			goto end;
		}

		p = (__be32 *)neigh->primary_key;
		if (neigh->tbl->family == AF_INET6)
			sxe2_copy_ip_ntohl(local_ipaddr, p);
		else
			local_ipaddr[0] = ntohl(*p);

		DRV_RDMA_LOG_DEV_INFO(
			"DEV: netdev %s state %d local_ip=%pI4 MAC=%pM\n",
			netdev_name(rdma_dev->netdev), neigh->nud_state,
			local_ipaddr, neigh->ha);
	default:
		break;
	}

	ret = NOTIFY_DONE;

end:
	return ret;
}

static int sxe2_khandle_netdevice_event(struct notifier_block *notifier,
					unsigned long event, void *ptr)
{
	struct sxe2_rdma_device *rdma_dev = NULL;
	struct net_device *netdev	  = netdev_notifier_info_to_dev(ptr);
	int ret;

	rdma_dev = container_of(notifier, struct sxe2_rdma_device,
				nb_netdevice_event);
	if (rdma_dev->netdev != netdev) {
		ret = NOTIFY_DONE;
		goto end;
	}

	rdma_dev->iw_status = 1;
	switch (event) {
	case NETDEV_DOWN:
		rdma_dev->iw_status = 0;
		DRV_RDMA_LOG_DEV_INFO("DEV: netdev %s event %lu status %u\n",
				      netdev_name(rdma_dev->netdev), event,
				      rdma_dev->iw_status);
		fallthrough;
	case NETDEV_UP:
		DRV_RDMA_LOG_DEV_INFO("DEV: netdev %s event %lu status %u\n",
				      netdev_name(rdma_dev->netdev), event,
				      rdma_dev->iw_status);
		sxe2_port_ibevent(rdma_dev);
		break;
	default:
		break;
	}

	ret = NOTIFY_DONE;

end:
	return ret;
}

void sxe2_kunregister_notifiers(struct sxe2_rdma_device *rdma_dev)
{
	int ret;

	ret = unregister_netdevice_notifier(&rdma_dev->nb_netdevice_event);
	if (ret)
		DRV_RDMA_LOG_DEV_ERR("unregister_netdevice_notifier failed, ret %d\n", ret);
	ret = unregister_netevent_notifier(&rdma_dev->nb_net_event);
	if (ret)
		DRV_RDMA_LOG_DEV_ERR("unregister_netevent_notifier failed, ret %d\n", ret);
	ret = unregister_inet6addr_notifier(&rdma_dev->nb_inet6addr_event);
	if (ret)
		DRV_RDMA_LOG_DEV_ERR("unregister_inet6addr_notifier failed, ret %d\n", ret);
	ret = unregister_inetaddr_notifier(&rdma_dev->nb_inetaddr_event);
	if (ret)
		DRV_RDMA_LOG_DEV_ERR("unregister_inetaddr_notifier failed, ret %d\n", ret);
}

static int sxe2_kregister_notifiers(struct sxe2_rdma_device *rdma_dev)
{
	int ret;
	int tmp_ret;

	rdma_dev->nb_netdevice_event.notifier_call =
		sxe2_khandle_netdevice_event;
	ret = register_netdevice_notifier(&rdma_dev->nb_netdevice_event);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"register_netdevice_notifier failed, ret %d\n", ret);
		return ret;
	}

	rdma_dev->nb_net_event.notifier_call = sxe2_khandle_net_event;
	ret = register_netevent_notifier(&rdma_dev->nb_net_event);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"register_netevent_notifier failed, ret %d\n", ret);
		goto netevent_error;
	}

	rdma_dev->nb_inet6addr_event.notifier_call =
		sxe2_khandle_inet6addr_event;
	ret = register_inet6addr_notifier(&rdma_dev->nb_inet6addr_event);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"register_inet6addr_notifier failed, ret %d\n", ret);
		goto inet6addr_error;
	}

	rdma_dev->nb_inetaddr_event.notifier_call = sxe2_khandle_inetaddr_event;
	ret = register_inetaddr_notifier(&rdma_dev->nb_inetaddr_event);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"register_inetaddr_notifier failed, ret %d\n", ret);
		goto inetaddr_error;
	}

	return 0;

inetaddr_error:
	tmp_ret = unregister_inet6addr_notifier(&rdma_dev->nb_inet6addr_event);
	if (tmp_ret)
		DRV_RDMA_LOG_DEV_ERR("unregister_inet6addr_notifier failed, ret %d\n", tmp_ret);
inet6addr_error:
	tmp_ret = unregister_netevent_notifier(&rdma_dev->nb_net_event);
	if (tmp_ret)
		DRV_RDMA_LOG_DEV_ERR("unregister_netevent_notifier failed, ret %d\n", tmp_ret);
netevent_error:
	tmp_ret = unregister_netdevice_notifier(&rdma_dev->nb_netdevice_event);
	if (tmp_ret)
		DRV_RDMA_LOG_DEV_ERR("unregister_netdevice_notifier failed, ret %d\n", tmp_ret);
	return ret;
}

static int sxe2_pf_func_table_init(struct sxe2_rdma_device *rdma_dev)
{
	int ret				    = SXE2_OK;
	struct aux_core_dev_info *cdev_info = rdma_dev->rdma_func->cdev;
	struct sxe2_pf_func_table_init_info info;

	info.pf_id = cpu_to_le32(rdma_dev->rdma_func->pf_id);
	ret = sxe2_rdma_adminq_send(cdev_info, SXE2_CMD_RDMA_PF_FUNC_TABLE_INIT,
					    (u8 *)&info, (u16)sizeof(info),
					    NULL, 0);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"probe:aq send pf func table init err ret=%d\n", ret);
		goto end;
	}

end:
	return ret;
}

static const struct sxe2_rdma_profile drv_profile = {
	STAGE_CREATE(SXE2_RDMA_STAGE_SETUP_INITINFO, sxe2_rdma_setup_init_state,
		     sxe2_rdma_del_init_mem),
	STAGE_CREATE(SXE2_RDMA_STAGE_DEBUG, sxe2_rdma_dbg_pf_init,
		     sxe2_rdma_dgb_pf_exit),
	STAGE_CREATE(SXE2_RDMA_STAGE_CREATE_MQ, sxe2_kcreate_mq,
		     sxe2_kdestroy_mq),
	STAGE_CREATE(SXE2_RDMA_STAGE_GET_FEATURES, sxe2_kget_rdma_features,
		     NULL),
	STAGE_CREATE(SXE2_RDMA_STAGE_RCMS_SETUP, sxe2_rcms_setup,
		     sxe2_rcms_exit),
	STAGE_CREATE(SXE2_RDMA_STAGE_PBLE, sxe2_pbl_init, sxe2_pbl_exit),
	STAGE_CREATE(SXE2_RDMA_STAGE_HW_RSRC, sxe2_init_hw_rsrc, NULL),
	STAGE_CREATE(SXE2_RDMA_STAGE_DB_INIT, sxe2_kinit_doorbell,
		     sxe2_kfree_doorbell),
	STAGE_CREATE(SXE2_RDMA_STAGE_CREATE_MCQ, sxe2_create_mcq,
		     sxe2_destroy_mcq),
	STAGE_CREATE(SXE2_RDMA_STAGE_CREATE_MCEQ, sxe2_setup_mceq,
		     sxe2_del_mceq),
	STAGE_CREATE(SXE2_RDMA_STAGE_MQ_HDL, sxe2_kinit_mq_handler,
			NULL),
	STAGE_CREATE(SXE2_RDMA_STAGE_SET_ATTR, sxe2_kset_attr_from_fragcnt,
		     NULL),
	STAGE_CREATE(SXE2_RDMA_STAGE_VSI, sxe2_rdma_init_vsi_ctx,
		     sxe2_rdma_del_vsi_ctx),
	STAGE_CREATE(SXE2_RDMA_STAGE_VSI_STATS, sxe2_kinit_vsi_stats,
		     sxe2_kfree_vsi_stats),
	STAGE_CREATE(SXE2_RDMA_STAGE_CREATE_CEQS, sxe2_setup_ceqs,
		     sxe2_del_ceqs),
	STAGE_CREATE(SXE2_RDMA_STAGE_CREATE_AEQ, sxe2_setup_aeq, sxe2_del_aeq),
	STAGE_CREATE(SXE2_RDMA_STAGE_RCRC_WQ, sxe2_init_rsrc_wq,
		     sxe2_destroy_rsrc_wq),
};

static int sxe2_drv_add(struct sxe2_rdma_device *rdma_dev,
			const struct sxe2_rdma_profile *profile)
{
	int ret = 0;
	int i;

	rdma_dev->profile = profile;

	for (i = 0; i < SXE2_RDMA_STAGE_MAX; i++) {
		if (profile->stage[i].init) {
			ret = profile->stage[i].init(rdma_dev);
			if (ret) {
				ret = -ENOMEM;
				DRV_RDMA_LOG_DEV_ERR(
					"SXE2 DRV add fail in stage:%d, ret %d\n",
					i, ret);
				goto err_out;
			}
		}
	}

	ret = drv_rdma_debug_cc_add(rdma_dev);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_ERROR_BDF(
			"ERR: failed adding cc to debug file system ret=%d\n",
			ret);
		goto end;
	}
	ret = drv_rdma_debug_common_add(rdma_dev);
	if (ret != SXE2_OK) {
		DRV_RDMA_LOG_DEV_ERR(
			"ERR: failed adding common to debug file system ret=%d\n",
			ret);
		goto end;
	}
	goto end;
err_out:
	while (i) {
		i--;
		if (profile->stage[i].cleanup)
			profile->stage[i].cleanup(rdma_dev);
	}

end:
	return ret;
}

static void sxe2_drv_remove(struct sxe2_rdma_device *rdma_dev,
			    const struct sxe2_rdma_profile *profile, int stage)
{
	DRV_RDMA_LOG_DEV_DEBUG("remove: remove stag start\n");
	while (stage) {
		stage--;
		if (profile->stage[stage].cleanup)
			profile->stage[stage].cleanup(rdma_dev);
	}
}
#ifdef SXE2_CFG_DEBUG
static void sxe2_rdma_probe_init_reset_info(struct sxe2_rdma_device *rdma_dev,
					    struct aux_core_dev_info *cdev_info)
{
	int i;

	rdma_dev->reset_func_info = NULL;
	mutex_lock(&g_reset_debug.reset_debug_mutex);
	if (!cdev_info->ftype) {
		rdma_dev->reset_func_info = &(
			g_reset_debug.pf_info[cdev_info->pf_id].pf_reset_info);
		if (!rdma_dev->reset_func_info->valid) {
			memcpy(rdma_dev->reset_func_info->bdf, rdma_dev->bdf,
			       MAX_BDF_SIZE);
			rdma_dev->reset_func_info->valid	  = true;
			rdma_dev->reset_func_info->reset_cnt	  = 0;
			rdma_dev->reset_func_info->reset_info_idx = 0;
		}
		DRV_RDMA_LOG_DEV_DEBUG(
			"probe:pf reset cnt=%u reset info idx=%u bdf=%s reset info ptr=%p\n",
			rdma_dev->reset_func_info->reset_cnt,
			rdma_dev->reset_func_info->reset_info_idx,
			rdma_dev->reset_func_info->bdf,
			rdma_dev->reset_func_info);
	} else {
		for (i = 0; i < MAX_VF_FUNC_CNT; i++) {
			if (g_reset_debug.pf_info[cdev_info->pf_id]
				    .vf_info[i]
				    .valid &&
			    (strcmp(g_reset_debug.pf_info[cdev_info->pf_id]
					    .vf_info[i]
					    .bdf,
				    rdma_dev->bdf) == 0)) {
				rdma_dev->reset_func_info =
					&g_reset_debug.pf_info[cdev_info->pf_id]
						 .vf_info[i];
				DRV_RDMA_LOG_DEV_DEBUG(
					"probe:vf reset info pf id=%u vf idx=%u\n",
					cdev_info->pf_id, i);
				DRV_RDMA_LOG_DEV_DEBUG(
					"probe:vf reset cnt=%u reset info\n"
					"\tidx=%u bdf=%s reset info ptr=%p\n",
					rdma_dev->reset_func_info->reset_cnt,
					rdma_dev->reset_func_info
						->reset_info_idx,
					rdma_dev->reset_func_info->bdf,
					rdma_dev->reset_func_info);
				break;
			}
		}

		if (!rdma_dev->reset_func_info) {
			for (i = 0; i < MAX_VF_FUNC_CNT; i++) {
				if (!g_reset_debug.pf_info[cdev_info->pf_id]
					     .vf_info[i]
					     .valid) {
					rdma_dev->reset_func_info =
						&g_reset_debug
							 .pf_info[cdev_info->pf_id]
							 .vf_info[i];
					memcpy(rdma_dev->reset_func_info->bdf,
					       rdma_dev->bdf, MAX_BDF_SIZE);
					rdma_dev->reset_func_info->valid = true;
					rdma_dev->reset_func_info->reset_cnt =
						0;
					rdma_dev->reset_func_info
						->reset_info_idx = 0;
					DRV_RDMA_LOG_DEV_DEBUG(
						"probe:vf reset info pf id=%u vf idx=%u\n",
						cdev_info->pf_id, i);
					DRV_RDMA_LOG_DEV_DEBUG(
						"probe:vf reset cnt=%u reset info idx=%u\n"
						"\tbdf=%s reset info ptr=%p\n",
						rdma_dev->reset_func_info
							->reset_cnt,
						rdma_dev->reset_func_info
							->reset_info_idx,
						rdma_dev->reset_func_info->bdf,
						rdma_dev->reset_func_info);
					break;
				}
			}
		}
	}
	mutex_unlock(&g_reset_debug.reset_debug_mutex);
}
#endif

static int sxe2_rdma_probe_init(struct auxiliary_device *adev,
				struct aux_core_dev_info *cdev_info,
				struct sxe2_rdma_device **rdma_dev_o)
{
	int ret = 0;
#ifdef NEED_ONE_PARAM_ALLOC_DEVICE
	struct ib_device  ibdev;
#endif

	struct sxe2_rdma_device *rdma_dev;
	u32  value		 = 0;
	u16  major_value = 0;
	u16  minor_value = 0;
	u32 __iomem *firmware_version;

	if (!cdev_info) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR("cdev info is null\n");
		goto end;
	}

	if (!cdev_info->ftype) {
		firmware_version = (u32 __iomem *)(cdev_info->hw_addr + SXE2_TOP_REG_COMPAT_OFFSET);
		value = SXE2_BAR_READ_32(firmware_version);
		major_value = RS_32_1(value, 16) & 0xffff;
		minor_value = value & 0xffff;

		if (major_value != SXE2_FW_COMP_MAJOR_VER) {
			DRV_RDMA_LOG_ERROR("firmware version %d mismatch.rdma %d\n",
								major_value,
								SXE2_FW_COMP_MAJOR_VER);
			ret = -EINVAL;
			goto end;
		}

		if (minor_value != SXE2_FW_COMP_MINOR_VER) {
			DRV_RDMA_LOG_WARN("firmware minor version %d mismatch.rdma %d\n",
								minor_value,
								SXE2_FW_COMP_MINOR_VER);
		}
	}

	if (strcmp(cdev_info->drv_ver, SXE2_VERSION) != 0) {
		ret =  -EINVAL;
		DRV_RDMA_LOG_ERROR("RoCE cannot be enabled because of a driver version mismatch\n");
		DRV_RDMA_LOG_ERROR("sxe driver version [%s]\n"
			"\tRoCE diver version [%s] please ensure version matching!\n",
			cdev_info->drv_ver, SXE2_VERSION);
		goto end;
	}

	DRV_RDMA_LOG_INFO(
		"probe: cdev_info:%p, cdev_info->dev.aux_dev.bus->number:%d,\n"
		"netdev:%p\n",
		cdev_info, cdev_info->pdev->bus->number,
		netdev_name(cdev_info->netdev));

#ifdef NEDD_ONE_PARAM_ALLOC
	rdma_dev = sxe2_ib_alloc_device(sxe2_rdma_device, ibdev);
#else
	rdma_dev = ib_alloc_device(sxe2_rdma_device, ibdev);
#endif
	if (!rdma_dev) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_ERROR("rdma device alloc failed. ret:%d\n", ret);
		goto end;
	}
	snprintf(rdma_dev->bdf, 16, "%02x:%02x.%x",
		 cdev_info->pdev->bus->number, PCI_SLOT(cdev_info->pdev->devfn),
		 PCI_FUNC(cdev_info->pdev->devfn));

	if (!cdev_info->ftype) {
		rdma_dev->fw_ver.major = major_value;
		rdma_dev->fw_ver.minor = minor_value;
	}
	rdma_dev->aux_dev = adev;
#ifdef SXE2_CFG_DEBUG
	sxe2_rdma_probe_init_reset_info(rdma_dev, cdev_info);
#endif
	rdma_dev->rdma_func =
		kzalloc(sizeof(struct sxe2_rdma_pci_f), GFP_KERNEL);
	if (!rdma_dev->rdma_func) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("rdma device rf alloc failed. ret:%d\n",
				     ret);
		goto err_rf;
	}
	ret = sxe2_rdma_fill_device_info(rdma_dev, cdev_info);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("rdma device info fill err. ret:%d\n",
				     ret);
		goto err_fill_devinfo;
	}
	*rdma_dev_o = rdma_dev;
	goto end;
err_fill_devinfo:
	kfree(rdma_dev->rdma_func);
err_rf:
	ib_dealloc_device(&rdma_dev->ibdev);
end:
	return ret;
}

static int sxe2_rdma_probe_notify(struct aux_core_dev_info *cdev_info, u32 status)
{
	struct sxe2_rdma_notify_status_info rdma_status;
	int ret = 0;

	rdma_status.rdma_status = status;
	ret = sxe2_rdma_adminq_send(
		cdev_info, SXE2_CMD_RDMA_NOTIFY_STATUS,
		(u8 *)&rdma_status, (u16)sizeof(rdma_status),
		NULL, 0);
	return ret;
}

static int sxe2_rdma_probe(struct auxiliary_device *adev,
			   const struct auxiliary_device_id *id)
{
	struct sxe2_auxiliary_device *aux_adev =
		container_of(adev, struct sxe2_auxiliary_device, adev);
	struct aux_core_dev_info *cdev_info = aux_adev->cdev_info;
	struct sxe2_rdma_device *rdma_dev;
	struct sxe2_rdma_handler *hdl;
	int ret = 0;
	(void)id;
	DRV_RDMA_LOG_INFO("rdma probe start\n");
	ret = sxe2_rdma_probe_init(adev, cdev_info, &rdma_dev);
	if (ret) {
		DRV_RDMA_LOG_INFO("rdma probe sxe2_rdma_probe_init error\n");
		goto end;
	}
	if (!rdma_dev->rdma_func->ftype) {
		ret = sxe2_pf_func_table_init(rdma_dev);
		if (ret != SXE2_OK) {
			DRV_RDMA_LOG_DEV_ERR(
				"pf %u func table init err ret:%d\n",
				rdma_dev->rdma_func->pf_id, ret);
			goto err_alloc_hdl;
		}
	}
	hdl = kzalloc(sizeof(*hdl), GFP_KERNEL);
	if (!hdl) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"rdma device handler alloc failed. ret:%d\n", ret);
		goto err_alloc_hdl;
	}
	hdl->dev      = rdma_dev;
	rdma_dev->hdl = hdl;
	sxe2_add_handler(hdl);

	atomic_set(&rdma_dev->rdma_func->aeq_created, 0);
#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)
	ret = INJECT_INIT(rdma_dev->rdma_func);
	if (ret) {
		DRV_RDMA_LOG_ERROR_BDF("inject init fail, ret %d\n", ret);
		goto err_add;
	}
	ret = sxe2_drv_inject_reg(rdma_dev->rdma_func);
	if (ret) {
		DRV_RDMA_LOG_ERROR_BDF("core inject reg fail, ret %d", ret);
		goto err_inject_reg;
	}
#endif

	ret = sxe2_drv_add(rdma_dev, &drv_profile);
	if (ret < 0) {
		DRV_RDMA_LOG_DEV_ERR("rdma device add failed. ret:%d\n", ret);
#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)
		goto err_inject_reg;
#else
		goto err_add;
#endif
	}
	rdma_dev->vsi.lag_port_bitmap = cdev_info->rdma_pf_bitmap;
	DRV_RDMA_LOG_DEV_DEBUG("rdma_pf_bitmap = 0x%x\n",
			       cdev_info->rdma_pf_bitmap);

	ret = sxe2_ib_register_device(rdma_dev);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR("rdma device register failed. ret:%d\n",
				     ret);
		goto err_reg_device;
	}
	ret = sxe2_kregister_notifiers(rdma_dev);
	if (ret != 0) {
		DRV_RDMA_LOG_DEV_ERR(
			"SXE2 DRV register notifiers failed, ret %d.\n", ret);
		goto err_reg_notifiers;
	}

	auxiliary_set_drvdata(adev, rdma_dev);
#ifdef SXE2_SUPPORT_CONFIGFS
	ret = sxe2_rdma_create_configfs_subdir(rdma_dev->bdf, rdma_dev);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR(
			"create configfs subdir %s failed, ret %d\n",
			rdma_dev->bdf, ret);
		goto err_probe_notify;
	}
#endif
	if (rdma_dev->rdma_func->ctx_dev.privileged) {
		ret = sxe2_rdma_probe_notify(cdev_info, SXE2_RDMA_PROBE);
		if (ret) {
			DRV_RDMA_LOG_DEV_ERR("notify rdma probe failed, ret %d\n", ret);
			goto err_remove_configfs;
		}
		cdev_info->ops->notify_rdma_load(cdev_info, true);
	}

	DRV_RDMA_LOG_DEV_INFO("rdma probe success\n");
	goto end;
err_remove_configfs:
#ifdef SXE2_SUPPORT_CONFIGFS
	sxe2_rdma_remove_configfs_subdir(rdma_dev->bdf);
err_probe_notify:
#endif
	sxe2_kunregister_notifiers(rdma_dev);
err_reg_notifiers:
	sxe2_ib_unregister_device(rdma_dev);
err_reg_device:
	sxe2_drv_remove(rdma_dev, &drv_profile, SXE2_RDMA_STAGE_MAX);
#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)
err_inject_reg:
	INJECT_UNINIT(rdma_dev->rdma_func);
#endif
err_add:
	sxe2_del_handler(rdma_dev->hdl);
	kfree(hdl);
err_alloc_hdl:
	destroy_workqueue(rdma_dev->rdma_func->vchnl_wq);
	kfree(rdma_dev->rdma_func);
	ib_dealloc_device(&rdma_dev->ibdev);
end:
	return ret;
}

#ifdef HAVE_AUXILIARY_DRIVER_INT_REMOVE
static int sxe2_rdma_remove(struct auxiliary_device *adev)
#else
static void sxe2_rdma_remove(struct auxiliary_device *adev)
#endif
{
	struct sxe2_rdma_device *rdma_dev = auxiliary_get_drvdata(adev);
	struct sxe2_auxiliary_device *aux_adev =
		container_of(adev, struct sxe2_auxiliary_device, adev);
	struct aux_core_dev_info *cdev_info = aux_adev->cdev_info;

	if (!rdma_dev) {
		DRV_RDMA_LOG_ERROR(
			"auxiliary device is not exist, skips shca_drv_ib_remove()\n");
		goto end;
	}
	DRV_RDMA_LOG_DEV_INFO("rdma remove start\n");
#ifdef SXE2_SUPPORT_CONFIGFS
	sxe2_rdma_remove_configfs_subdir(rdma_dev->bdf);
#endif
	if (rdma_dev->rdma_func->ctx_dev.privileged) {
		cdev_info->ops->notify_rdma_load(cdev_info, false);
		sxe2_rdma_probe_notify(cdev_info, SXE2_RDMA_REMOVE);
		sxe2_rdma_free_all_vf_rsrc(&rdma_dev->rdma_func->ctx_dev);
	}
	sxe2_kunregister_notifiers(rdma_dev);

	sxe2_ib_unregister_device(rdma_dev);
	sxe2_drv_remove(rdma_dev, rdma_dev->profile, SXE2_RDMA_STAGE_MAX);
	sxe2_del_handler(rdma_dev->hdl);
	kfree(rdma_dev->hdl);
	rdma_dev->hdl = NULL;
	if (rdma_dev->rdma_func->vchnl_wq)
		destroy_workqueue(rdma_dev->rdma_func->vchnl_wq);
#if defined(SXE2_SUPPORT_INJECT) && defined(SXE2_CFG_DEBUG)
	INJECT_UNINIT(rdma_dev->rdma_func);
#endif
	kfree(rdma_dev->rdma_func);
	rdma_dev->rdma_func = NULL;
	ib_dealloc_device(&rdma_dev->ibdev);

end:
#ifdef HAVE_AUXILIARY_DRIVER_INT_REMOVE
	return 0;
#else
	return;
#endif
}

static const struct auxiliary_device_id sxe2_auxiliary_id_table[] = {
	{
		.name = "sxe2.roce",
	},
	{
		.name = "sxe2vf.roce",
	},
	{},
};

MODULE_DEVICE_TABLE(auxiliary, sxe2_auxiliary_id_table);

struct sxe2_auxiliary_drv sxe2_auxiliary_drv = {
	.adrv = {
			.id_table = sxe2_auxiliary_id_table,
			.probe	  = sxe2_rdma_probe,
			.remove	  = sxe2_rdma_remove,
		},
	.aux_ops.event_handler = sxe2_aux_event_handler,
	.aux_ops.vc_receive	   = sxe2_vchnl_receive,
};

struct mutex func_lock;

static int __init sxe2_drv_init(void)
{
	int ret;

	mutex_init(&func_lock);

#ifndef SXE2_CFG_RELEASE
	ret = sxe2_log_init(false);
	if (ret < 0) {
		DRV_RDMA_LOG_PR_ERR("sxe2 log init fail.(err:%d)\n", ret);
		goto destroy_lock;
	}
#endif

	DRV_RDMA_LOG_INFO("%s start, version[%s], commit_id[%s],\n"
		    "\tbranch[%s], build_time[%s]\n", __func__,
		    SXE2_VERSION, SXE2_COMMIT_ID,
		    SXE2_BRANCH, SXE2_BUILD_TIME);
	ret = sxe2_dbg_and_configs_init();
	if (ret) {
		DRV_RDMA_LOG_ERROR("dbg and configs init failed. ret:%d\n",
				   ret);
#ifndef SXE2_CFG_RELEASE
		goto free_log;
#else
		goto destroy_lock;
#endif
	}

	ret = auxiliary_driver_register(&sxe2_auxiliary_drv.adrv);
	if (ret) {
		DRV_RDMA_LOG_ERROR("driver register failed. ret:%d\n", ret);
		goto dbg_config_exit;
	}
	goto end;

dbg_config_exit:
	sxe2_dbg_and_configs_exit();
#ifndef SXE2_CFG_RELEASE
free_log:
	sxe2_log_exit();
#endif
destroy_lock:
	mutex_destroy(&func_lock);
end:
	return ret;
}

static void __exit sxe2_drv_cleanup(void)
{
	auxiliary_driver_unregister(&sxe2_auxiliary_drv.adrv);

	sxe2_dbg_and_configs_exit();

#ifndef SXE2_CFG_RELEASE
	sxe2_log_exit();
#endif
	mutex_destroy(&func_lock);
}

MODULE_INFO(build_time, SXE2_BUILD_TIME);
MODULE_INFO(branch, SXE2_BRANCH);
MODULE_INFO(arch, SXE2_DRV_ARCH);
MODULE_INFO(commit_id, SXE2_COMMIT_ID);
MODULE_AUTHOR("SXE2");
MODULE_DESCRIPTION("SXE2 RDMA Driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(SXE2_VERSION);
MODULE_ALIAS("auxiliary:sxe2.rdma");

module_init(sxe2_drv_init);
module_exit(sxe2_drv_cleanup);
