// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#define dev_fmt(fmt) "unic: (pid %d) " fmt, current->pid

#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <net/rtnetlink.h>
#if IS_ENABLED(CONFIG_UB_UNIC_UBL)
#include <net/ub/ubl.h>
#endif
#include <ub/ubase/ubase_comm_cmd.h>
#include <ub/ubase/ubase_comm_eq.h>
#include <ub/ubase/ubase_comm_qos.h>

#include "unic_bond.h"
#include "unic_cmd.h"
#include "unic_dcbnl.h"
#include "unic_ethtool.h"
#include "unic_event.h"
#include "unic_guid.h"
#include "unic_hw.h"
#include "unic_ip.h"
#include "unic_mac.h"
#include "unic_netdev.h"
#include "unic_vlan.h"
#include "unic_dev.h"

#define UNIC_WATCHDOG_TIMEOUT (30 * HZ)

#ifndef UB_DATA_LEN
#define UB_DATA_LEN 1500
#endif

static int netif_debug = -1;
module_param(netif_debug, int, 0);
MODULE_PARM_DESC(netif_debug, "network interface message level setting");

static int unic_debug;
module_param_named(debug, unic_debug, int, 0644);
MODULE_PARM_DESC(debug, "enable unic debug log, 0:disable, others:enable, default:0");

#define DEFAULT_MSG_LEVEL (NETIF_MSG_PROBE | NETIF_MSG_LINK | \
			   NETIF_MSG_IFDOWN | NETIF_MSG_IFUP)
#define DEFAULT_RSS_SIZE 1

static struct workqueue_struct *unic_wq;

int unic_dbg_log(void)
{
	return unic_debug;
}

u32 unic_channels_max_num(struct auxiliary_device *adev)
{
	struct ubase_adev_caps *unic_caps = ubase_get_unic_caps(adev);
	u32 jfs_num = unic_caps->jfs.max_cnt;
	u32 jfr_num = unic_caps->jfr.max_cnt;
	u32 jfc_num = unic_caps->jfc.max_cnt;

	return min(min(jfs_num, jfr_num), jfc_num >> 1);
}

u32 unic_get_max_rss_size(struct unic_dev *unic_dev)
{
	u8 vl_num = unic_dev->channels.rss_vl_num;

	return unic_channels_max_num(unic_dev->comdev.adev) / vl_num;
}

void unic_update_queue_info(struct unic_dev *unic_dev)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct ubase_adev_qos *qos = ubase_get_adev_qos(adev);
	struct unic_channels *channels = &unic_dev->channels;
	struct unic_vl *vl = &channels->vl;
	u32 i;

	for (i = 0; i < qos->nic_vl_num; i++) {
		if (i < channels->rss_vl_num) {
			vl->queue_count[i] = channels->rss_size;
			vl->queue_offset[i] = i * channels->rss_size;
		} else {
			vl->queue_count[i] = 0;
			vl->queue_offset[i] = channels->rss_vl_num *
						   channels->rss_size;
		}
	}
}

static int unic_update_vl_sl_map(struct unic_dev *unic_dev)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct ubase_adev_qos *qos = ubase_get_adev_qos(adev);
	u8 i;

	if (!qos) {
		dev_err(adev->dev.parent, "failed to get qos info\n");
		return -ENODATA;
	}

	for (i = 0; i < UBASE_MAX_SL_NUM; i++) {
		if (qos->ue_sl_vl[i] >= UBASE_MAX_VL_NUM) {
			dev_err(adev->dev.parent,
				"the sl(%u) map to vl(%u) exceed max_vl_num(%u).\n",
				i, qos->ue_sl_vl[i], UBASE_MAX_VL_NUM);
			return -EINVAL;
		}

		unic_dev->channels.vl.vl_sl[qos->ue_sl_vl[i]] = i;
	}

	return 0;
}

static inline void unic_get_hw_prio_vl(struct ubase_caps *caps, u8 *sw_prio_vl,
				       u8 *hw_prio_vl)
{
	int i;

	for (i = 0; i < UNIC_MAX_PRIO_NUM; i++)
		hw_prio_vl[i] = caps->req_vl[sw_prio_vl[i]];
}

static inline void unic_get_hw_dscp_vl(struct ubase_caps *caps, u8 *hw_prio_vl,
				       u8 *dscp_prio, u8 *hw_dscp_vl)
{
	int i;

	for (i = 0; i < UBASE_MAX_DSCP; i++)
		hw_dscp_vl[i] = dscp_prio[i] == UNIC_INVALID_PRIORITY ?
				caps->req_vl[0] : hw_prio_vl[dscp_prio[i]];
}

int unic_set_vl_map(struct unic_dev *unic_dev, u8 *dscp_prio, u8 *prio_vl,
		    u8 map_type)
{
	struct ubase_caps *caps = ubase_get_dev_caps(unic_dev->comdev.adev);
	u8 hw_prio_vl[UNIC_MAX_PRIO_NUM];
	u8 hw_dscp_vl[UBASE_MAX_DSCP];
	int ret;

	unic_get_hw_prio_vl(caps, prio_vl, hw_prio_vl);
	unic_get_hw_dscp_vl(caps, hw_prio_vl, dscp_prio, hw_dscp_vl);

	if (unic_dev_ets_supported(unic_dev) &&
	    !unic_dev_ubl_supported(unic_dev)) {
		ret = unic_set_hw_vl_map(unic_dev, hw_dscp_vl, hw_prio_vl,
					 map_type);
		if (ret)
			return ret;
	}

	ubase_update_udma_dscp_vl(unic_dev->comdev.adev, hw_dscp_vl,
				  UBASE_MAX_DSCP);

	return 0;
}

static int unic_init_vl_map(struct unic_dev *unic_dev)
{
	struct unic_vl *vl = &unic_dev->channels.vl;
	int i;

	for (i = 0; i < UBASE_MAX_DSCP; i++)
		vl->dscp_prio[i] = UNIC_INVALID_PRIORITY;

	return unic_set_vl_map(unic_dev, vl->dscp_prio,
			       vl->prio_vl, UNIC_PRIO_VL_MAP);
}

static void unic_vl_bitmap_init(struct unic_dev *unic_dev)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct ubase_caps *caps = ubase_get_dev_caps(adev);
	u8 i;

	for (i = 0; i < caps->vl_num; i++) {
		unic_dev->channels.vl.vl_bitmap |= 1 << caps->req_vl[i];
		unic_dev->channels.vl.vl_bitmap |= 1 << caps->resp_vl[i];
	}
}

static void unic_init_vl_sch(struct unic_dev *unic_dev)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct ubase_caps *caps = ubase_get_dev_caps(adev);
	struct unic_vl *vl = &unic_dev->channels.vl;
	struct ubase_initial_qset_qos *initial_qos;
	u32 i;

	if (!unic_dev_ets_supported(unic_dev))
		return;

	initial_qos = ubase_get_initial_qset_qos(adev);
	for (i = 0; i < caps->vl_num; i++) {
		vl->vl_tsa[i] = initial_qos->qset_weight[caps->req_vl[i]] ?
				UNIC_VL_TSA_DWRR : 0;
		vl->vl_bw[i] = initial_qos->qset_weight[caps->req_vl[i]];
	}
}

static void unic_init_vl_maxrate(struct unic_dev *unic_dev)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct ubase_caps *caps = ubase_get_dev_caps(adev);
	struct unic_vl *vl = &unic_dev->channels.vl;
	struct ubase_initial_qset_qos *initial_qos;
	u8 i;

	if (!unic_dev_ets_supported(unic_dev) ||
	    !unic_dev_tc_speed_limit_supported(unic_dev))
		return;

	initial_qos = ubase_get_initial_qset_qos(adev);
	for (i = 0; i < caps->vl_num; i++) {
		vl->vl_maxrate[i] = (u64)initial_qos->rate[caps->req_vl[i]] *
				    UNIC_MBYTE_PER_SEND;
		vl->maxrate = max(vl->maxrate, initial_qos->rate[caps->req_vl[i]]);
	}
}

static int unic_init_pause(struct unic_dev *unic_dev)
{
	struct unic_pfc_info *pfc_info = &unic_dev->channels.vl.pfc_info;
	int ret;

	if (!unic_dev_pause_supported(unic_dev))
		return 0;

	ret = unic_mac_pause_en_cfg(unic_dev, UNIC_RX_TX_PAUSE_ON,
				    UNIC_RX_TX_PAUSE_ON);
	if (ret)
		return ret;

	pfc_info->fc_mode = UNIC_TX_PAUSE_EN | UNIC_RX_PAUSE_EN;

	return ret;
}

static int unic_init_pfc(struct unic_dev *unic_dev)
{
	if (!unic_dev_pfc_supported(unic_dev))
		return 0;

	return unic_pfc_pause_cfg(unic_dev, 0);
}

static int unic_init_fc_mode(struct unic_dev *unic_dev)
{
	int ret;

	ret = unic_init_pause(unic_dev);
	if (ret)
		return ret;

	return unic_init_pfc(unic_dev);
}

static int unic_init_vl_info(struct unic_dev *unic_dev)
{
	int ret;

	unic_vl_bitmap_init(unic_dev);
	unic_update_queue_info(unic_dev);

	ret = unic_update_vl_sl_map(unic_dev);
	if (ret)
		return ret;

	ret = unic_init_vl_map(unic_dev);
	if (ret)
		return ret;

	unic_init_vl_maxrate(unic_dev);
	unic_init_vl_sch(unic_dev);
	return 0;
}

static int unic_init_channels_attr(struct unic_dev *unic_dev)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct unic_channels *channels = &unic_dev->channels;
	struct ubase_adev_caps *unic_caps;
	int ret;

	mutex_init(&channels->mutex);

	unic_caps = ubase_get_unic_caps(adev);

	channels->vl.vl_num = 1;
	channels->rss_vl_num = 1;
	channels->rss_size = DEFAULT_RSS_SIZE;
	channels->num = channels->rss_size * channels->rss_vl_num;
	channels->sqebb_depth = unic_caps->jfs.depth;
	channels->rqe_depth = unic_caps->jfr.depth;
	channels->sq_cqe_depth = unic_caps->jfc.depth;
	channels->rq_cqe_depth = unic_caps->jfc.depth;
	channels->cqe_size = unic_caps->cqe_size;
	channels->rx_buff_len = unic_dev->caps.rx_buff_len;
	channels->sqebb_shift = ilog2(roundup_pow_of_two(channels->sqebb_depth));
	channels->sq_jfc_shift = ilog2(roundup_pow_of_two(channels->sq_cqe_depth));
	channels->rq_jfc_shift = ilog2(roundup_pow_of_two(channels->rq_cqe_depth));

	ret = unic_init_vl_info(unic_dev);
	if (ret)
		mutex_destroy(&channels->mutex);

	return ret;
}

static void unic_uninit_channels_attr(struct unic_dev *unic_dev)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct unic_channels *channels = &unic_dev->channels;

	/* Prevent residual QoS configurations caused by the unic driver. */
	ubase_restore_initial_qset_qos(adev);

	mutex_destroy(&channels->mutex);
}

u16 unic_cqe_period_round_down(u16 cqe_period)
{
	u16 period[] = {
		UNIC_CQE_PERIOD_0,
		UNIC_CQE_PERIOD_4,
		UNIC_CQE_PERIOD_16,
		UNIC_CQE_PERIOD_64,
		UNIC_CQE_PERIOD_256,
		UNIC_CQE_PERIOD_1024,
		UNIC_CQE_PERIOD_4096,
		UNIC_CQE_PERIOD_16384,
		UNIC_CQE_PERIOD_ERR
	};
	u16 i;

	for (i = 0; i < ARRAY_SIZE(period) - 1; i++) {
		if (cqe_period >= period[i] &&
		    cqe_period < period[i + 1])
			return period[i];
	}

	return UNIC_CQE_PERIOD_ERR;
}

int unic_init_tx(struct unic_dev *unic_dev, u32 num)
{
	struct unic_channel *c;
	u32 i, j;
	int ret;

	for (i = 0; i < num; i++) {
		ret = unic_create_cq(unic_dev, i, UNIC_CQ_SQ);
		if (ret) {
			dev_err(unic_dev->comdev.adev->dev.parent,
				"failed to init tx cq(%u), ret=%d.\n", i, ret);
			goto err_create_cq;
		}
	}

	for (j = 0; j < num; j++) {
		ret = unic_create_sq(unic_dev, j);
		if (ret) {
			dev_err(unic_dev->comdev.adev->dev.parent,
				"failed to init tx sq(%u), ret=%d.\n", j, ret);
			goto err_create_sq;
		}
		c = &unic_dev->channels.c[j];
		c->sq->cq = c->sq_cq;
	}

	set_bit(UNIC_TX_INITED, &unic_dev->channels.state);

	return 0;

err_create_sq:
	unic_destroy_sq(unic_dev, j);
err_create_cq:
	unic_destroy_cq(unic_dev, i, UNIC_CQ_SQ);
	return ret;
}

int unic_init_rx(struct unic_dev *unic_dev, u32 num)
{
	struct unic_channel *c;
	u32 i, j;
	int ret;

	for (i = 0; i < num; i++) {
		ret = unic_create_cq(unic_dev, i, UNIC_CQ_RQ);
		if (ret) {
			dev_err(unic_dev->comdev.adev->dev.parent,
				"failed to init rx cq(%u), ret=%d.\n", i, ret);
				goto err_create_cq;
		}
	}

	for (j = 0; j < num; j++) {
		ret = unic_create_rq(unic_dev, j);
		if (ret) {
			dev_err(unic_dev->comdev.adev->dev.parent,
				"failed to init rx rq(%u), ret=%d.\n", j, ret);
			goto err_create_rq;
		}
		c = &unic_dev->channels.c[j];
		c->rq->cq = c->rq_cq;
	}

	set_bit(UNIC_RX_INITED, &unic_dev->channels.state);

	return 0;

err_create_rq:
	unic_destroy_rq(unic_dev, j);
err_create_cq:
	unic_destroy_cq(unic_dev, i, UNIC_CQ_RQ);
	return ret;
}

static int unic_init_jetty(struct unic_dev *unic_dev, u32 num)
{
	int ret;

	ret = unic_init_rx(unic_dev, num);
	if (ret)
		return ret;

	ret = unic_init_tx(unic_dev, num);
	if (ret)
		unic_destroy_rx(unic_dev, num);

	return ret;
}

void unic_destroy_tx(struct unic_dev *unic_dev, u32 num)
{
	if (!test_and_clear_bit(UNIC_TX_INITED, &unic_dev->channels.state))
		return;

	unic_destroy_sq(unic_dev, num);
	unic_destroy_cq(unic_dev, num, UNIC_CQ_SQ);
}

void unic_destroy_rx(struct unic_dev *unic_dev, u32 num)
{
	if (!test_and_clear_bit(UNIC_RX_INITED, &unic_dev->channels.state))
		return;

	unic_destroy_rq(unic_dev, num);
	unic_destroy_cq(unic_dev, num, UNIC_CQ_RQ);
}

static void unic_destroy_jetty(struct unic_dev *unic_dev, u32 num)
{
	unic_destroy_tx(unic_dev, num);
	unic_destroy_rx(unic_dev, num);
}

static inline int unic_init_rss(struct unic_dev *unic_dev)
{
	return unic_set_rss_tc_mode(unic_dev, UNIC_RSS_TC_VALID);
}

static int __unic_init_channels(struct unic_dev *unic_dev, u32 channels_num)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct unic_channels *channels = &unic_dev->channels;
	int ret;
	u32 i;

	channels->num = channels_num;
	channels->c = kcalloc(channels_num, sizeof(*channels->c), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(channels->c))
		return -ENOMEM;

	ret = unic_init_jetty(unic_dev, channels->num);
	if (ret) {
		dev_err(adev->dev.parent,
			"failed to init jetty, ret = %d.\n", ret);
		goto err_init_jetty;
	}

	for (i = 0; i < channels->num; i++)
		netif_napi_add(unic_dev->comdev.netdev, &channels->c[i].napi,
			       unic_napi_poll);

	ret = unic_init_rss(unic_dev);
	if (ret) {
		dev_err(adev->dev.parent,
			"failed to init rss, ret = %d.\n", ret);
		goto err_init_rss;
	}

	return 0;

err_init_rss:
	for (; i > 0; i--)
		netif_napi_del(&channels->c[i - 1].napi);
	unic_destroy_jetty(unic_dev, channels->num);

err_init_jetty:
	kfree(channels->c);
	channels->c = NULL;

	return ret;
}

int unic_init_channels(struct unic_dev *unic_dev, u32 channels_num)
{
	struct unic_channels *channels = &unic_dev->channels;
	int ret;

	mutex_lock(&channels->mutex);

	ret = __unic_init_channels(unic_dev, channels_num);
	if (!ret)
		clear_bit(UNIC_STATE_CHANNEL_INVALID, &unic_dev->state);

	mutex_unlock(&channels->mutex);
	return ret;
}

static inline void unic_uninit_rss(struct unic_dev *unic_dev)
{
	unic_set_rss_tc_mode(unic_dev, UNIC_RSS_TC_INVALID);
}

static void __unic_uninit_channels(struct unic_dev *unic_dev)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	struct unic_channels *channels = &unic_dev->channels;
	u32 i;

	unic_uninit_rss(unic_dev);

	if (!channels->c)
		return;

	if (!ubase_adev_shutting_down(adev)) {
		for (i = 0; i < channels->num; i++)
			netif_napi_del(&channels->c[i].napi);
	}

	unic_destroy_jetty(unic_dev, channels->num);

	kfree(channels->c);

	channels->c = NULL;
}

void unic_uninit_channels(struct unic_dev *unic_dev)
{
	struct unic_channels *channels = &unic_dev->channels;

	mutex_lock(&channels->mutex);

	set_bit(UNIC_STATE_CHANNEL_INVALID, &unic_dev->state);
	__unic_uninit_channels(unic_dev);

	mutex_unlock(&channels->mutex);
}

static void unic_set_netdev_attr(struct net_device *netdev)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);

	netdev->watchdog_timeo = UNIC_WATCHDOG_TIMEOUT;
	netdev->priv_flags |= IFF_UNICAST_FLT;

	if (unic_dev_ubl_supported(unic_dev)) {
		netdev->features |= NETIF_F_VLAN_CHALLENGED;
		netdev->flags &= ~(IFF_BROADCAST | IFF_MULTICAST);
	} else {
		netdev->flags |= IFF_BROADCAST | IFF_MULTICAST;
		netdev->features |= NETIF_F_HW_VLAN_CTAG_FILTER;
	}

	if (!unic_dev_cfg_vlan_filter_supported(unic_dev)) {
		netdev->features |= NETIF_F_VLAN_CHALLENGED;
		netdev->features &= ~NETIF_F_HW_VLAN_CTAG_FILTER;
	}

	if (unic_dev_tx_csum_offload_supported(unic_dev))
		netdev->features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;

	if (unic_dev_rx_csum_offload_supported(unic_dev))
		netdev->features |= NETIF_F_RXCSUM;

	netdev->hw_features |= netdev->features;

	netdev->vlan_features |= netdev->features &
				 ~NETIF_F_HW_VLAN_CTAG_FILTER;
}

static int unic_dev_init_mtu(struct unic_dev *unic_dev)
{
	struct net_device *netdev = unic_dev->comdev.netdev;
	struct unic_caps *caps = &unic_dev->caps;

	netdev->mtu = UB_DATA_LEN;
	netdev->max_mtu = caps->max_trans_unit;
	netdev->min_mtu = caps->min_trans_unit;

	return unic_config_mtu(unic_dev, netdev->mtu);
}

static int unic_init_mac(struct unic_dev *unic_dev)
{
	struct unic_link_stats *record = &unic_dev->stats.link_record;
	struct unic_mac *mac = &unic_dev->hw.mac;
	int ret;

	mac->duplex = DUPLEX_FULL;
	mac->link_status = UNIC_LINK_STATUS_DOWN;

	ret = unic_set_mac_speed_duplex(unic_dev, mac->speed, mac->duplex,
					mac->lanes);
	if (ret)
		return ret;

	ret = unic_set_mac_autoneg(unic_dev, mac->autoneg);
	if (ret)
		return ret;

	ret = unic_dev_init_mtu(unic_dev);
	if (ret) {
		dev_err(unic_dev->comdev.adev->dev.parent,
			"failed to set initial mtu, ret = %d.\n", ret);
		return ret;
	}

	ret = unic_init_fc_mode(unic_dev);
	if (ret)
		return ret;

	mutex_init(&record->lock);
	return 0;
}

static void unic_uninit_mac(struct unic_dev *unic_dev)
{
	struct unic_link_stats *record = &unic_dev->stats.link_record;

	mutex_destroy(&record->lock);
}

static void unic_uninit_dev_addr(struct unic_dev *unic_dev)
{
	if (unic_dev_eth_mac_supported(unic_dev))
		unic_uninit_mac_addr(unic_dev);
}

int unic_set_mtu(struct unic_dev *unic_dev, int new_mtu)
{
	u16 max_frame_size;
	int ret;

	new_mtu = max(new_mtu, UB_DATA_LEN);

	ret = unic_check_validate_dump_mtu(unic_dev, new_mtu, &max_frame_size);
	if (ret) {
		unic_err(unic_dev, "invalid MTU(%d), please check, ret = %d.\n",
			 new_mtu, ret);
		return -EINVAL;
	}

	ret = unic_config_mtu(unic_dev, new_mtu);
	if (ret)
		unic_err(unic_dev,
			 "failed to change MTU to %d, ret = %d.\n", new_mtu, ret);

	return ret;
}

static void unic_update_stats_for_all(struct unic_dev *unic_dev)
{
	if (!unic_dev_ubl_supported(unic_dev) &&
	    unic_dev_fec_stats_supported(unic_dev) &&
	    unic_dev->hw.mac.fec_mode != ETHTOOL_FEC_OFF)
		unic_update_fec_stats(unic_dev);
}

static void unic_task_schedule(struct unic_dev *unic_dev,
			       unsigned long delay_time)
{
	if (!test_bit(UNIC_STATE_REMOVING, &unic_dev->state))
		mod_delayed_work(unic_wq, &unic_dev->service_task, delay_time);
}

static void unic_sync_bond_port(struct unic_dev *unic_dev)
{
	struct net_device *netdev = unic_dev->comdev.netdev;

	if (test_and_clear_bit(UNIC_STATE_SYNC_BOND_PORT, &unic_dev->state)) {
		if (unic_sync_bond_status(netdev))
			set_bit(UNIC_STATE_SYNC_BOND_PORT, &unic_dev->state);
	}
}

static void unic_periodic_service_task(struct unic_dev *unic_dev)
{
#define UNIC_UPDATE_STATS_TIMER_INTERVAL	300UL

	unsigned long delta = round_jiffies_relative(HZ);

	unic_link_status_update(unic_dev);
	unic_update_port_info(unic_dev);
	unic_sync_ip_table(unic_dev);
	unic_sync_bond_ip_table(unic_dev);

	if (unic_dev_eth_mac_supported(unic_dev)) {
		unic_sync_mac_table(unic_dev);
		unic_sync_bond_port(unic_dev);
	}

	unic_sync_promisc_mode(unic_dev);
	unic_sync_vlan_filter(unic_dev);

	if (!(unic_dev->serv_processed_cnt % UNIC_UPDATE_STATS_TIMER_INTERVAL))
		unic_update_stats_for_all(unic_dev);

	unic_dev->serv_processed_cnt++;
	unic_task_schedule(unic_dev, delta);
}

static void unic_service_task(struct work_struct *work)
{
	struct unic_dev *unic_dev =
		container_of(work, struct unic_dev, service_task.work);

	unic_periodic_service_task(unic_dev);
}

static void unic_init_vport_info(struct unic_dev *unic_dev)
{
	unic_dev->vport.back = unic_dev;

	INIT_LIST_HEAD(&unic_dev->vport.addr_tbl.tmp_ip_list);
	spin_lock_init(&unic_dev->vport.addr_tbl.tmp_ip_lock);
	INIT_LIST_HEAD(&unic_dev->vport.addr_tbl.ip_list);
	spin_lock_init(&unic_dev->vport.addr_tbl.ip_list_lock);
	INIT_LIST_HEAD(&unic_dev->vport.addr_tbl.bond_ip_list);
	spin_lock_init(&unic_dev->vport.addr_tbl.bond_ip_list_lock);

	if (unic_dev_eth_mac_supported(unic_dev)) {
		INIT_LIST_HEAD(&unic_dev->vport.addr_tbl.uc_mac_list);
		INIT_LIST_HEAD(&unic_dev->vport.addr_tbl.mc_mac_list);
		spin_lock_init(&unic_dev->vport.addr_tbl.mac_list_lock);
	}
}

static int unic_alloc_vport_buf(struct unic_dev *unic_dev)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	u8 i;

	for (i = 0; i < unic_dev->caps.vport_buf_num; i++) {
		unic_dev->vbuf[i].buf = dma_alloc_coherent(adev->dev.parent,
							   unic_dev->caps.vport_buf_size,
							   &unic_dev->vbuf[i].dma_addr, GFP_KERNEL);
		if (!unic_dev->vbuf[i].buf) {
			dev_err(adev->dev.parent,
				"failed to alloc vport buffer.\n");
			goto alloc_err;
		}
	}

	return 0;

alloc_err:
	for (; i > 0; i--)
		dma_free_coherent(adev->dev.parent,
				  unic_dev->caps.vport_buf_size,
				  unic_dev->vbuf[i - 1].buf, unic_dev->vbuf[i - 1].dma_addr);
	return -ENOMEM;
}

static void unic_free_vport_buf(struct unic_dev *unic_dev)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	u32 i;

	for (i = 0; i < unic_dev->caps.vport_buf_num; i++)
		dma_free_coherent(adev->dev.parent,
				  unic_dev->caps.vport_buf_size,
				  unic_dev->vbuf[i].buf, unic_dev->vbuf[i].dma_addr);
}

static int unic_init_vport_buf(struct unic_dev *unic_dev)
{
	struct auxiliary_device *adev = unic_dev->comdev.adev;
	int ret;

	if (!unic_dev->caps.vport_buf_size || !unic_dev->caps.vport_buf_num)
		return 0;

	if (unic_dev->caps.vport_buf_num > UNIC_MAX_VPORT_BUF_NUM) {
		dev_err(adev->dev.parent,
			"vport_buf_num(%hhu) exceeded the maximum(%d).\n",
			unic_dev->caps.vport_buf_num, UNIC_MAX_VPORT_BUF_NUM);
		return -EINVAL;
	}

	ret = unic_alloc_vport_buf(unic_dev);
	if (ret)
		return ret;

	ret = unic_cfg_vport_buf(unic_dev, true);
	if (ret)
		unic_free_vport_buf(unic_dev);

	return ret;
}

static void unic_uninit_vport_buf(struct unic_dev *unic_dev)
{
	if (!unic_dev->caps.vport_buf_size || !unic_dev->caps.vport_buf_num)
		return;

	unic_cfg_vport_buf(unic_dev, false);
	unic_free_vport_buf(unic_dev);
}

static int unic_init_vport(struct unic_dev *unic_dev)
{
	int ret;

	ret = unic_init_vport_buf(unic_dev);
	if (ret)
		return ret;

	unic_init_vport_info(unic_dev);

	ret = unic_init_vlan_config(unic_dev);
	if (ret)
		unic_uninit_vport_buf(unic_dev);

	return ret;
}

static void unic_uninit_vport(struct unic_dev *unic_dev)
{
	unic_uninit_ip_table(unic_dev);
	unic_uninit_bond_ip_table(unic_dev);

	if (unic_dev_eth_mac_supported(unic_dev)) {
		unic_uninit_mac_table(unic_dev);
		unic_uninit_vlan_config(unic_dev);
	}

	unic_uninit_vport_buf(unic_dev);
}

static void unic_init_netdev_info(struct net_device *netdev)
{
	struct unic_dev *unic_dev = netdev_priv(netdev);

	unic_set_netdev_attr(netdev);
	unic_set_netdev_ops(netdev);
	unic_set_ethtool_ops(netdev);
	unic_set_dcbnl_ops(netdev);

	SET_NETDEV_DEV(netdev, unic_dev->comdev.adev->dev.parent);
}

static int unic_init_dev_addr(struct unic_dev *unic_dev)
{
	if (unic_dev_ubl_supported(unic_dev))
		return unic_init_guid(unic_dev);

	return unic_init_mac_addr(unic_dev);
}

static int unic_init_netdev_priv(struct net_device *netdev,
				 struct auxiliary_device *adev)
{
	struct unic_dev *priv = netdev_priv(netdev);
	int ret;

	priv->comdev.netdev = netdev;
	priv->comdev.adev = adev;
	priv->msg_enable = netif_msg_init(netif_debug, DEFAULT_MSG_LEVEL);
	priv->tid = ubase_get_dev_caps(adev)->tid;
	mutex_init(&priv->act_info.mutex);

	ret = unic_query_dev_res(priv);
	if (ret)
		goto destroy_lock;

	ret = unic_init_vport(priv);
	if (ret)
		goto destroy_lock;

	ret = unic_update_port_info(priv);
	if (ret) {
		dev_err(adev->dev.parent,
			"failed to update port info, ret = %d.\n", ret);
		goto err_uninit_vport;
	}

	ret = unic_init_mac(priv);
	if (ret)
		goto err_uninit_vport;

	ret = unic_init_dev_addr(priv);
	if (ret)
		goto unic_unint_mac;

	ret = unic_init_channels_attr(priv);
	if (ret)
		goto err_uninit_dev_addr;

	ret = unic_init_channels(priv, priv->channels.num);
	if (ret) {
		dev_err(adev->dev.parent,
			"failed to init channels, ret = %d.\n", ret);
		goto err_uninit_channels_attr;
	}

	set_bit(UNIC_STATE_DOWN, &priv->state);
	return 0;

err_uninit_channels_attr:
	unic_uninit_channels_attr(priv);
err_uninit_dev_addr:
	unic_uninit_dev_addr(priv);
unic_unint_mac:
	unic_uninit_mac(priv);
err_uninit_vport:
	unic_uninit_vport(priv);
destroy_lock:
	mutex_destroy(&priv->act_info.mutex);

	return ret;
}

static void unic_uninit_netdev_priv(struct net_device *netdev)
{
	struct unic_dev *priv = netdev_priv(netdev);

	unic_uninit_channels(priv);
	unic_uninit_channels_attr(priv);
	unic_uninit_dev_addr(priv);
	unic_uninit_mac(priv);
	unic_uninit_vport(priv);
	mutex_destroy(&priv->act_info.mutex);
}

int unic_init_wq(void)
{
	unic_wq = alloc_workqueue("%s", WQ_UNBOUND, 0, "unic");
	if (!unic_wq)
		return -ENOMEM;

	return 0;
}

void unic_destroy_wq(void)
{
	destroy_workqueue(unic_wq);
}

static void unic_init_period_task(struct net_device *netdev)
{
	struct unic_dev *priv = netdev_priv(netdev);

	INIT_DELAYED_WORK(&priv->service_task, unic_service_task);
}

void unic_start_period_task(struct net_device *netdev)
{
	unsigned long delta = round_jiffies_relative(HZ);
	struct unic_dev *unic_dev = netdev_priv(netdev);

	unic_task_schedule(unic_dev, delta);
}

void unic_remove_period_task(struct unic_dev *unic_dev)
{
	if (unic_dev->service_task.work.func)
		cancel_delayed_work_sync(&unic_dev->service_task);
}

bool unic_rss_vl_num_changed(struct unic_dev *unic_dev, u8 vl_num)
{
	struct unic_channels *channels = &unic_dev->channels;

	return channels->rss_vl_num != unic_get_rss_vl_num(unic_dev, vl_num);
}

int unic_change_rss_size(struct unic_dev *unic_dev, u32 new_rss_size,
			 u32 org_rss_size)
{
	struct unic_channels *channels = &unic_dev->channels;
	int ret;

	mutex_lock(&channels->mutex);

	set_bit(UNIC_STATE_CHANNEL_INVALID, &unic_dev->state);
	__unic_uninit_channels(unic_dev);

	channels->rss_size = new_rss_size;
	channels->num = channels->rss_size * channels->rss_vl_num;

	unic_update_queue_info(unic_dev);

	ret = __unic_init_channels(unic_dev, channels->num);
	if (ret)
		dev_err(unic_dev->comdev.adev->dev.parent,
			"failed to change rss_size, ret = %d.\n", ret);
	else
		clear_bit(UNIC_STATE_CHANNEL_INVALID, &unic_dev->state);

	mutex_unlock(&channels->mutex);

	return ret;
}

int unic_update_channels(struct unic_dev *unic_dev, u8 vl_num)
{
	struct unic_channels *channels = &unic_dev->channels;
	u32 old_rss_size = channels->rss_size;

	channels->rss_vl_num = unic_get_rss_vl_num(unic_dev, vl_num);

	return unic_change_rss_size(unic_dev, DEFAULT_RSS_SIZE, old_rss_size);
}

static struct net_device *unic_alloc_netdev(struct auxiliary_device *adev)
{
	struct ubase_caps *caps = ubase_get_dev_caps(adev);
	u32 channel_num = unic_channels_max_num(adev);
	struct net_device *netdev = NULL;
	char name[IFNAMSIZ] = {0};

	if (!channel_num)
		channel_num = UNIC_DEFAULT_CHANNEL_NUM;

	if (ubase_adev_ubl_supported(adev)) {
#if IS_ENABLED(CONFIG_UB_UNIC_UBL)
		snprintf(name, IFNAMSIZ, "ublc%ud%ue%u", caps->chip_id,
			 caps->die_id, caps->ue_id);
		netdev = alloc_netdev_mq(sizeof(struct unic_dev), name,
					 NET_NAME_USER, ubl_setup, channel_num);
#else
		dev_warn(adev->dev.parent,
			 "failed to alloc netdev because of CONFIG_UB_UNIC_UBL is not enabled.\n");
#endif
	} else {
		snprintf(name, IFNAMSIZ, "ethc%ud%ue%u", caps->chip_id,
			 caps->die_id, caps->ue_id);
		netdev = alloc_netdev_mq(sizeof(struct unic_dev), name,
					 NET_NAME_USER, ether_setup, channel_num);
	}

	return netdev;
}

static void unic_start_dev_period_task(struct net_device *netdev)
{
	unic_init_period_task(netdev);
	unic_start_period_task(netdev);
}

int unic_dev_init(struct auxiliary_device *adev)
{
	struct net_device *netdev;
	int ret;

	netdev = unic_alloc_netdev(adev);
	if (!netdev)
		return -ENOMEM;

	dev_set_drvdata(&adev->dev, netdev_priv(netdev));

	ret = unic_init_netdev_priv(netdev, adev);
	if (ret) {
		dev_err(adev->dev.parent,
			"failed to init netdev_priv, ret = %d.\n", ret);
		goto err_free_netdev;
	}
	unic_init_netdev_info(netdev);

	ret = unic_register_event(adev);
	if (ret)
		goto err_uninit_netdev_priv;

	ret = register_netdev(netdev);
	if (ret) {
		dev_err(adev->dev.parent,
			"failed to register netdev, ret = %d.\n", ret);
		goto err_unregister_event;
	}

	unic_query_ip_addr(adev);
	unic_start_dev_period_task(netdev);

	return 0;

err_unregister_event:
	unic_unregister_event(adev);
err_uninit_netdev_priv:
	unic_uninit_netdev_priv(netdev);
err_free_netdev:
	free_netdev(netdev);
	return ret;
}

static void unic_uninit_netdev(struct auxiliary_device *adev)
{
	struct unic_dev *priv = (struct unic_dev *)dev_get_drvdata(&adev->dev);
	struct net_device *netdev = priv->comdev.netdev;

	if (netdev->reg_state != NETREG_UNINITIALIZED) {
		if (ubase_adev_shutting_down(adev)) {
			rtnl_lock();
			netif_device_detach(netdev);
			dev_close(netdev);
			rtnl_unlock();
		} else {
			unregister_netdev(netdev);
		}
	}

	unic_uninit_netdev_priv(netdev);

	if (!ubase_adev_shutting_down(adev))
		free_netdev(netdev);
}

void unic_dev_uninit(struct auxiliary_device *adev)
{
	struct unic_dev *priv = (struct unic_dev *)dev_get_drvdata(&adev->dev);
	struct unic_promisc_en promisc_en = {0};

	/* cancel service task and wait it finish before release resources. */
	unic_remove_period_task(priv);

	/* Ensure that the link status change is processed before
	 * unregister_netdev. Prevent the kernel from accessing the released
	 * netdev address.
	 */
	unic_unregister_event(adev);

	/* Explicitly disable promisc to avoid hardware promisc residue */
	unic_set_promisc_mode(priv, &promisc_en);

	unic_uninit_netdev(adev);

	dev_set_drvdata(&adev->dev, NULL);
}
