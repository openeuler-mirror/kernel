/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_ptp.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#include <linux/skbuff.h>
#include <linux/ptp_clock_kernel.h>
#include "ossl_knl.h"
#include "hinic5_nic_dev.h"
#include "hinic5_mt.h"
#include "hinic5_tx.h"
#include "hinic5_hw.h"
#include "hinic5_nic_event.h"
#include "hinic5_ptp.h"

static unsigned int ptp_clock_pf;
module_param(ptp_clock_pf, uint, 0444);
MODULE_PARM_DESC(ptp_clock_pf, "ptp_clock_pf, 0: pf0, 1: pf1, 2: pf2, 3: pf3 (default=0)");

static int hinic5_ptp_gettime64(struct ptp_clock_info *ptp_info, struct timespec64 *ts)
{
	int ret;
	struct hinic5_ptp_ctrl *ptp_ctrl = container_of(ptp_info, struct hinic5_ptp_ctrl, ptp_info);

	spin_lock_bh(&ptp_ctrl->ptp_clock_lock);
	ret = hinic5_ts_up_en(ptp_ctrl->hwdev, PTP_RD_UP_EN_FLAG);
	if (ret == 0)
		hinic5_read_ts_data(ptp_ctrl->hwdev, ts);

	spin_unlock_bh(&ptp_ctrl->ptp_clock_lock);
	return ret;
}

#ifdef HAVE_PTP_INFO_GETTIMEX64
static int hinic5_ptp_gettimex64(struct ptp_clock_info *ptp_info, struct timespec64 *ts,
				 struct ptp_system_timestamp *sts)
{
	int ret;
	struct hinic5_ptp_ctrl *ptp_ctrl = container_of(ptp_info, struct hinic5_ptp_ctrl, ptp_info);

	spin_lock_bh(&ptp_ctrl->ptp_clock_lock);
	ptp_read_system_prets(sts);
	ret = hinic5_ts_up_en(ptp_ctrl->hwdev, PTP_RD_UP_EN_FLAG);
	ptp_read_system_postts(sts);

	if (ret == 0)
		hinic5_read_ts_data(ptp_ctrl->hwdev, ts);

	spin_unlock_bh(&ptp_ctrl->ptp_clock_lock);
	return ret;
}
#endif

static int hinic5_ptp_settime64(struct ptp_clock_info *ptp_info, const struct timespec64 *ts)
{
	struct hinic5_ptp_ctrl *ptp_ctrl = container_of(ptp_info, struct hinic5_ptp_ctrl, ptp_info);

	spin_lock_bh(&ptp_ctrl->ptp_clock_lock);
	hinic5_write_ts_data(ptp_ctrl->hwdev, ts);
	spin_unlock_bh(&ptp_ctrl->ptp_clock_lock);
	return 0;
}

static int hinic5_ptp_adjtime(struct ptp_clock_info *ptp_info, s64 delta)
{
	int ret;
	s32 update_val;
	struct timespec64 ts, delta_ts;
	struct hinic5_ptp_ctrl *ptp_ctrl = container_of(ptp_info, struct hinic5_ptp_ctrl, ptp_info);

	if (delta > PTP_CLOCK_MAX_ADJ_TIME_VALUE || -delta > PTP_CLOCK_MAX_ADJ_TIME_VALUE) {
		delta_ts = ns_to_timespec64(delta);
		ret = hinic5_ptp_gettime64(ptp_info, &ts);
		if (ret != 0)
			return ret;

		ts = timespec64_add(ts, delta_ts);
		hinic5_ptp_settime64(ptp_info, &ts);
		return 0;
	}

	if (delta >= 0)
		update_val = (s32)delta;
	else
		update_val = -(s32)(-delta);

	spin_lock_bh(&ptp_ctrl->ptp_clock_lock);
	hinic5_ptp_ts_update(ptp_ctrl->hwdev, update_val);
	spin_unlock_bh(&ptp_ctrl->ptp_clock_lock);
	return 0;
}

static void hinic5_ptp_set_inc_per_cycle(struct hinic5_ptp_ctrl *ptp_ctrl, u32 inc_val)
{
	spin_lock_bh(&ptp_ctrl->ptp_clock_lock);
	hinic5_set_ptp_inc(ptp_ctrl->hwdev, inc_val);
	spin_unlock_bh(&ptp_ctrl->ptp_clock_lock);
}

static int hinic5_ptp_adjfine(struct ptp_clock_info *ptp_info, long scaled_ppm)
{
	struct hinic5_ptp_ctrl *ptp_ctrl = container_of(ptp_info, struct hinic5_ptp_ctrl, ptp_info);
	u32 adj_inc_val = (u32)adjust_by_scaled_ppm(ptp_ctrl->inc_val, scaled_ppm);

	hinic5_ptp_set_inc_per_cycle(ptp_ctrl, adj_inc_val);
	return 0;
}

static void hinic5_ptp_tx_time_out(struct hinic5_nic_dev *nic_dev)
{
	struct sk_buff *skb = nic_dev->ptp_ctrl.tx_saved_skb;

	if (time_is_after_jiffies(nic_dev->ptp_ctrl.tx_start + HZ) != 0)
		return;

	nic_dev->ptp_ctrl.tx_saved_skb = NULL;
	clear_bit(HINIC5_PTP_TX_BUSY, &nic_dev->ptp_ctrl.flags);
	dev_kfree_skb_any(skb);
}

int hinic5_ptp_tx_process(struct hinic5_nic_dev *nic_dev, struct sk_buff *skb)
{
	if (!nic_dev->hwdev || test_bit(HINIC5_PTP_CLOCK, &nic_dev->flags) == 0 ||
	    nic_dev->ptp_ctrl.tx_enable == 0)
		return -EINVAL;

	if (test_and_set_bit(HINIC5_PTP_TX_BUSY, &nic_dev->ptp_ctrl.flags)) {
		hinic5_ptp_tx_time_out(nic_dev);
		if (test_and_set_bit(HINIC5_PTP_TX_BUSY, &nic_dev->ptp_ctrl.flags))
			return -EBUSY;
	}

	skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
	nic_dev->ptp_ctrl.tx_saved_skb = skb_get(skb);
	nic_dev->ptp_ctrl.tx_start = jiffies;
	return 0;
}

u8 hinic5_ptp_tx_event_handle(void *dev, u8 event, const u8 *data)
{
	struct hinic5_nic_dev *nic_dev = (struct hinic5_nic_dev *)dev;
	struct timespec64 ts = {0};
	struct skb_shared_hwtstamps shhwtstamps;
	union hinic5_hw_ts32 hw_ts = { .val = *(u32 *)data };
	struct sk_buff *skb = nic_dev->ptp_ctrl.tx_saved_skb;

	if (test_bit(HINIC5_PTP_CLOCK, &nic_dev->flags) == 0 || !skb)
		return 0;

	hinic5_ptp_gettime64(&nic_dev->ptp_ctrl.ptp_info, &ts);
	ts.tv_nsec = hw_ts.time_ns;
	if (((u32)ts.tv_sec & 0x3) < hw_ts.time_s && ts.tv_sec != 0) {  // 0x3 :lower 2bit sec
		ts.tv_sec--;
	}
	/* 0x3 :lower 2bit sec */
	ts.tv_sec = (u32)(ts.tv_sec - ((u32)ts.tv_sec & 0x3)) + hw_ts.time_s;
	nic_dev->ptp_ctrl.tx_saved_skb = NULL;
	clear_bit(HINIC5_PTP_TX_BUSY, &nic_dev->ptp_ctrl.flags);
	shhwtstamps.hwtstamp = timespec64_to_ktime(ts);
	skb_tstamp_tx(skb, &shhwtstamps);
	dev_kfree_skb_any(skb);
	return 0;
}

void hinic5_ptp_rx_hwtstamp(struct hinic5_nic_dev *nic_dev, struct sk_buff *skb)
{
	struct timespec64 ts = {0};
	union hinic5_hw_ts32 hw_ts32;

	if (test_bit(HINIC5_PTP_CLOCK, &nic_dev->flags) == 0 || nic_dev->ptp_ctrl.rx_enable == 0)
		return;

	hinic5_ptp_gettime64(&nic_dev->ptp_ctrl.ptp_info, &ts);

	hw_ts32 = *(union hinic5_hw_ts32 *)(skb_tail_pointer(skb) - sizeof(union hinic5_hw_ts32));
	/* Timestamp is filled at the end of the packet, removed after conversion */
	skb->len = skb->len - PTP_SKB_HWTSTAMPS_LENGTH;
	skb_set_tail_pointer(skb, (int)(skb->len));
	hw_ts32.val = be32_to_cpu(hw_ts32.val);
	/* 0x3 :lower 2bit sec */
	if (((u32)ts.tv_sec & 0x3) < hw_ts32.time_s && ts.tv_sec != 0)
		ts.tv_sec--;
	/* 0x3 :lower 2bit sec */
	ts.tv_sec = (u32)(ts.tv_sec - ((u32)ts.tv_sec & 0x3)) + hw_ts32.time_s;
	ts.tv_nsec = hw_ts32.time_ns;

	skb_hwtstamps(skb)->hwtstamp = timespec64_to_ktime(ts);
}

int hinic5_ptp_get_ts_config(struct hinic5_nic_dev *nic_dev, struct ifreq *ifr)
{
	if (test_bit(HINIC5_PTP_CLOCK, &nic_dev->flags) == 0)
		return -EOPNOTSUPP;

	return copy_to_user(ifr->ifr_data, &nic_dev->ptp_ctrl.config,
			    sizeof(struct hwtstamp_config)) != 0 ? -EFAULT : 0;
}

static int hinic5_ptp_set_config(struct hinic5_nic_dev *nic_dev, struct hwtstamp_config *config)
{
	if (config->tx_type == HWTSTAMP_TX_ON)
		nic_dev->ptp_ctrl.tx_enable = 1;
	else if (config->tx_type == HWTSTAMP_TX_OFF)
		nic_dev->ptp_ctrl.tx_enable = 0;
	else
		return -ERANGE;

	if (config->rx_filter != HWTSTAMP_FILTER_NONE) {
		config->rx_filter = HWTSTAMP_FILTER_PTP_V2_EVENT;
	}

	return 0;
}

int hinic5_ptp_set_ts_config(struct hinic5_nic_dev *nic_dev, struct ifreq *ifr)
{
	struct hwtstamp_config config;
	int err;

	if (test_bit(HINIC5_PTP_CLOCK, &nic_dev->flags) == 0)
		return -EOPNOTSUPP;

	if (copy_from_user(&config, ifr->ifr_data, sizeof(config)) != 0)
		return -EFAULT;

	err = hinic5_ptp_set_config(nic_dev, &config);
	if (err != 0)
		return err;

	nic_dev->ptp_ctrl.config = config;

	return copy_to_user(ifr->ifr_data, &config, sizeof(config)) != 0 ?
		-EFAULT : 0;
}

void hinic5_ptp_init(struct hinic5_nic_dev *nic_dev)
{
	struct timespec64 ts;
	struct ptp_clock_info *ptp_info = NULL;

	if (!nic_dev->hwdev || hinic5_global_func_id(nic_dev->hwdev) != ptp_clock_pf ||
	    !HINIC5_SUPPORT_PTP_1588_V2(nic_dev->hwdev))
		return;

	ptp_info = &nic_dev->ptp_ctrl.ptp_info;
	nic_dev->ptp_ctrl.hwdev = nic_dev->hwdev;
	strscpy(ptp_info->name, HINIC5_CHIP_NAME, sizeof(ptp_info->name) - 1);

	ptp_info->name[sizeof(ptp_info->name) - 1] = '\0';
	ptp_info->owner = THIS_MODULE;
	ptp_info->max_adj = PTP_CLOCK_MAX_ADJ_TIME_VALUE;
	ptp_info->settime64 = hinic5_ptp_settime64;
	ptp_info->gettime64 = hinic5_ptp_gettime64;
#ifdef HAVE_PTP_INFO_GETTIMEX64
	ptp_info->gettimex64 = hinic5_ptp_gettimex64;
#endif
	ptp_info->adjfine = hinic5_ptp_adjfine;
	ptp_info->adjtime = hinic5_ptp_adjtime;
	spin_lock_init(&nic_dev->ptp_ctrl.ptp_clock_lock);

	nic_dev->ptp_ctrl.ptp_clock = ptp_clock_register(ptp_info, nic_dev->lld_dev->dev);
	if (IS_ERR(nic_dev->ptp_ctrl.ptp_clock))
		return;

	nic_dev->ptp_ctrl.flags = 0;
	nic_dev->ptp_ctrl.config.flags = 0;
	nic_dev->ptp_ctrl.config.rx_filter = HWTSTAMP_FILTER_NONE;
	nic_dev->ptp_ctrl.config.tx_type = HWTSTAMP_TX_OFF;
	// lower 16bit: 0.xx ns , 2: 2ns per cycle
	nic_dev->ptp_ctrl.inc_val = 2 << 16;
	nic_dev->ptp_ctrl.tx_saved_skb = NULL;
	/* Software 1588 mode also needs to strip the 4B timestamp from the end of the packet */
	nic_dev->ptp_ctrl.rx_enable = 1;
	hinic5_ptp_set_config(nic_dev, &nic_dev->ptp_ctrl.config);
	hinic5_ptp_set_inc_per_cycle(&nic_dev->ptp_ctrl, nic_dev->ptp_ctrl.inc_val);

	ktime_get_real_ts64(&ts);
	hinic5_ptp_settime64(&nic_dev->ptp_ctrl.ptp_info, &ts);
	hinic5_nic_aeq_register_swe_cb(nic_dev->hwdev, nic_dev, HINIC5_HTN_PTP_EVENT,
				       (hinic5_aeq_swe_cb)hinic5_ptp_tx_event_handle);
	set_bit(HINIC5_PTP_CLOCK, &nic_dev->flags);
}

void hinic5_ptp_deinit(struct hinic5_nic_dev *nic_dev)
{
	struct sk_buff *skb = NULL;

	if (nic_dev->ptp_ctrl.tx_saved_skb) {
		skb = nic_dev->ptp_ctrl.tx_saved_skb;
		nic_dev->ptp_ctrl.tx_saved_skb = NULL;
		clear_bit(HINIC5_PTP_TX_BUSY, &nic_dev->ptp_ctrl.flags);
		dev_kfree_skb_any(skb);
	}
	if (nic_dev->ptp_ctrl.ptp_clock) {
		nic_dev->ptp_ctrl.tx_enable = 0;
		nic_dev->ptp_ctrl.rx_enable = 0;
		ptp_clock_unregister(nic_dev->ptp_ctrl.ptp_clock);
		hinic5_nic_aeq_unregister_swe_cb(nic_dev->hwdev, HINIC5_HTN_PTP_EVENT);
		nic_dev->ptp_ctrl.ptp_clock = NULL;
	}
}
