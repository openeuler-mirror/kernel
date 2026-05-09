// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_ptp.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/rtc.h>
#include <linux/delay.h>

#include "sxe2_host_regs.h"
#include "sxe2.h"

#include "sxe2_ptp.h"

#include "sxe2_common.h"
#include "sxe2_log.h"
#include "sxe2_rx.h"

#define SXE2_PTP_MAX_ADJ		(100000000)
#define SXE2_MAX_CLKO_VALUE		(0x3B9AC9FF)
#define SXE2_PTP_BUSY_MAX_RETRY		(10)
#define SXE2_PTP_SLEEP_MAX		(10000)
#define SXE2_PTP_SLEEP_MIN		(5000)
#define SXE2_PTP_PERIOD_NORMAL		(500)
#define SXE2_PTP_PERIOD_UNNORMAL	(50)
#define PTP_TIME_OFFSET			(13)
#define PTP_TIME_DIV			(125)

#define SXE2_NS_PER_SEC			(1000000000ULL)

#define SXE2_PTP_INGRESS_CORR_NANO	(0x47)
#define SXE2_PTP_INGRESS_CORR_SUBNANO	(0x0700)
#define SXE2_PTP_INGRESS_CORR		(0x80001f07)
#define SXE2_PTP_EGRESS_CORR_NANO	(0x11c)
#define SXE2_PTP_EGRESS_CORR_SUBNANO	(0x1f00)
#define SXE2_PTP_EGRESS_CORR		(0x80001f07)
#define SXE2_PTP_SAMPLE_TYPE_ALL	(0xc)
#define SXE2_PTP_SAMPLE_TYPE_ALL_EVENT	(0x1)
#define SXE2_PTP_FILTER_TYPE_ALL	(3)

#define SXE2_PTP_WAIT_RETRY_CNT		(10)
static void sxe2_ptp_schedule_periodic_work(struct sxe2_ptp_context *ptp,
					    unsigned long delay);
static void sxe2_ptp_all_perout_restore(struct sxe2_adapter *adapter);
static void sxe2_ptp_all_perout_disable(struct sxe2_adapter *adapter);
static void sxe2_ptp_cancel_periodic_work(struct sxe2_ptp_context *ptp);

static struct mutex sxe2_ptp_owner_mtx;
static struct sxe2_ptp_owner_list sxe2_ptp_owner_head;

void sxe2_ptp_owner_init_once(void)
{
	mutex_init(&sxe2_ptp_owner_mtx);
	INIT_LIST_HEAD(&sxe2_ptp_owner_head.node);
}

void sxe2_ptp_owner_deinit_once(void)
{
	mutex_destroy(&sxe2_ptp_owner_mtx);
}

s32 sxe2_ptp_clock_idx_get(struct sxe2_adapter *adapter)
{
	s32 ret = -1;
	struct list_head *tmp;
	struct list_head *n;
	struct sxe2_ptp_owner_list *entry = NULL;

	mutex_lock(&sxe2_ptp_owner_mtx);
	list_for_each_safe(tmp, n, &sxe2_ptp_owner_head.node) {
		entry = list_entry(tmp, struct sxe2_ptp_owner_list, node);
		if (!entry->owner_adapter)
			continue;

		if (memcmp(adapter->serial_num,
			   entry->owner_adapter->serial_num, SXE2_SERIAL_NUM_LEN) == 0) {
			if (entry->owner_adapter->ptp_ctxt.clock)
				ret = ptp_clock_index(entry->owner_adapter->ptp_ctxt.clock);

			break;
		}
	}
	mutex_unlock(&sxe2_ptp_owner_mtx);
	return ret;
}

STATIC s32 sxe2_ptp_owner_adapter_add(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2_ptp_owner_list *entry;

	mutex_lock(&sxe2_ptp_owner_mtx);
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		LOG_ERROR_BDF("alloc lag list node failed.\n");
		ret = -ENOMEM;
		goto out;
	}
	entry->owner_adapter = adapter;
	list_add(&entry->node, &sxe2_ptp_owner_head.node);

out:
	mutex_unlock(&sxe2_ptp_owner_mtx);
	return ret;
}

STATIC void sxe2_ptp_owner_adapter_delete(struct sxe2_adapter *adapter)
{
	struct list_head *tmp;
	struct list_head *n;
	struct sxe2_ptp_owner_list *entry = NULL;

	mutex_lock(&sxe2_ptp_owner_mtx);

	list_for_each_safe(tmp, n, &sxe2_ptp_owner_head.node) {
		entry = list_entry(tmp, struct sxe2_ptp_owner_list, node);
		if (entry->owner_adapter == adapter) {
			list_del(&entry->node);
			break;
		}

		entry = NULL;
	}

	kfree(entry);

	mutex_unlock(&sxe2_ptp_owner_mtx);
}

static inline struct sxe2_vsi *sxe2_get_main_vsi(struct sxe2_adapter *adapter)
{
	return adapter->vsi_ctxt.main_vsi;
}

static inline struct sxe2_adapter *
sxe2_ptp_to_adapter(struct ptp_clock_info *clock_info)
{
	struct sxe2_ptp_context *ptpinfo;

	ptpinfo = container_of(clock_info, struct sxe2_ptp_context, info);
	(void)ptpinfo;

	return container_of(ptpinfo, struct sxe2_adapter, ptp_ctxt);
}

#ifdef SXE2_CFG_DEBUG
static void timespec64_to_localtime(const struct timespec64 *time,
				    struct rtc_time *tm)
{
	time64_t local_time;

	local_time = time->tv_sec - (sys_tz.tz_minuteswest * 60);
	rtc_time64_to_tm(local_time, tm);
	tm->tm_mon += 1;
	tm->tm_year += 1900;
}
#endif

static void dump_timespec64(struct sxe2_adapter *adapter,
			    const struct timespec64 *ts)
{
#ifdef SXE2_CFG_DEBUG
	struct rtc_time tm;
	time64_t sec  = ts->tv_sec;
	time64_t nsec = ts->tv_nsec;

	timespec64_to_localtime(ts, &tm);
	LOG_DEBUG_BDF("Time: %lld:%06lld\n", sec, nsec);
	LOG_DEBUG_BDF("Readable Time:(%04d-%02d-%02d %02d:%02d:%02d.%ld)\n",
		      tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min,
		      tm.tm_sec, ts->tv_nsec);
#endif
}

static bool sxe2_ptp_sem_acquire(struct sxe2_adapter *adapter)
{
	int cnt	   = 0;
	bool value = false;

	for (cnt = 0; cnt < SXE2_PTP_BUSY_MAX_RETRY; cnt++) {
		value = sxe2_hw_ptp_acquire_1588_lock(&adapter->hw);
		if (value)
			break;

		(void)usleep_range(SXE2_PTP_SLEEP_MIN, SXE2_PTP_SLEEP_MAX);
	}

	return value;
}

static void sxe2_ptp_sem_release(struct sxe2_adapter *adapter)
{
	sxe2_hw_ptp_release_1588_lock(&adapter->hw);
}

static int sxe2_ptp_primary_timer_set(struct sxe2_adapter *adapter,
				      struct timespec64 tstamp)
{
	if (!sxe2_ptp_sem_acquire(adapter))
		return -EBUSY;

	sxe2_hw_ptp_1588_timestamp_write(&adapter->hw, (u64)tstamp.tv_sec,
					 (u32)tstamp.tv_nsec);
	sxe2_ptp_sem_release(adapter);

	return 0;
}

static int sxe2_ptp_primary_timer_adjust(struct sxe2_adapter *adapter, s64 adj)
{
	u32 adj_nano;
	bool neg = false;

	if (adj < 0) {
		neg	 = true;
		adj_nano = (u32)(-adj);
	} else {
		adj_nano = (u32)(adj);
	}

	if (!sxe2_ptp_sem_acquire(adapter))
		return -EBUSY;

	sxe2_hw_ptp_1588_timestamp_adjust(&adapter->hw, adj_nano, neg);
	sxe2_ptp_sem_release(adapter);

	return 0;
}

bool sxe2_ptp_primary_timer_read(struct sxe2_adapter *adapter,
				 struct timespec64 *hwts)
{
	u64 ns;
	u64 second;

	if (!sxe2_ptp_sem_acquire(adapter)) {
		LOG_ERROR_BDF("Failed to get ptp sem.\n");
		return false;
	}

	sxe2_hw_ptp_1588_timestamp_read(&adapter->hw, &second, &ns);
	sxe2_ptp_sem_release(adapter);
	hwts->tv_nsec = (time64_t)ns;
	hwts->tv_sec = (long)second;

	return true;
}

bool sxe2_ptp_owned(struct sxe2_adapter *adapter)
{
	return adapter->ptp_ctxt.ptp_owned;
}

STATIC void sxe2_ptp_txts_enable(struct sxe2_adapter *adapter)
{
	struct sxe2_vsi *vsi;

	vsi = sxe2_get_main_vsi(adapter);
	if (!vsi)
		return;

	adapter->ptp_ctxt.ptp_tx_enable = true;
	sxe2_hw_ptp_tsyn_switch(&adapter->hw, true);
}

STATIC void sxe2_ptp_txts_disable(struct sxe2_adapter *adapter)
{
	struct sxe2_vsi *vsi;

	vsi = sxe2_get_main_vsi(adapter);
	if (!vsi)
		return;

	adapter->ptp_ctxt.ptp_tx_enable = false;

	sxe2_hw_ptp_tsyn_switch(&adapter->hw, false);
}

STATIC void sxe2_ptp_rxts_enable(struct sxe2_adapter *adapter)
{
	struct sxe2_vsi *vsi;

	vsi = sxe2_get_main_vsi(adapter);
	if (!vsi)
		return;

	adapter->ptp_ctxt.ptp_rx_enable = true;
}

STATIC void sxe2_ptp_rxts_disable(struct sxe2_adapter *adapter)
{
	struct sxe2_vsi *vsi;

	vsi = sxe2_get_main_vsi(adapter);
	if (!vsi)
		return;

	adapter->ptp_ctxt.ptp_rx_enable = false;
}

STATIC void sxe2_ptp_rxts_restore(struct sxe2_adapter *adapter)
{
	if (adapter->ptp_ctxt.tstamp_config.rx_filter == HWTSTAMP_FILTER_PTP_V2_EVENT)
		sxe2_ptp_rxts_enable(adapter);
	else
		sxe2_ptp_rxts_disable(adapter);
}

STATIC void sxe2_ptp_txts_restore(struct sxe2_adapter *adapter)
{
	if (adapter->ptp_ctxt.tstamp_config.tx_type == HWTSTAMP_TX_ON)
		sxe2_ptp_txts_enable(adapter);
	else
		sxe2_ptp_txts_disable(adapter);
}

int sxe2_ptp_hwts_get(struct sxe2_adapter *adapter, struct ifreq *ifr)
{
	if (adapter->ptp_ctxt.status != PTP_READY)
		return -EIO;

	return copy_to_user(ifr->ifr_data, &adapter->ptp_ctxt.tstamp_config,
			    sizeof(struct hwtstamp_config)) ? -EFAULT : 0;
}

static int sxe2_ptp_ts_mode_set(struct sxe2_adapter *adapter,
				struct hwtstamp_config *config)
{
	if (!config)
		return -EINVAL;

	switch (config->tx_type) {
	case HWTSTAMP_TX_OFF:
		adapter->ptp_ctxt.tstamp_config.tx_type = HWTSTAMP_TX_OFF;
		sxe2_ptp_txts_disable(adapter);
		break;
	case HWTSTAMP_TX_ON:
		adapter->ptp_ctxt.tstamp_config.tx_type = HWTSTAMP_TX_ON;
		sxe2_ptp_txts_enable(adapter);
		break;
	default:
		return -ERANGE;
	}

	switch (config->rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		sxe2_ptp_rxts_disable(adapter);
		adapter->ptp_ctxt.tstamp_config.rx_filter = HWTSTAMP_FILTER_NONE;
		break;
	case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
#ifdef HWTSTAMP_FILTER_NTP_ALL
	case HWTSTAMP_FILTER_NTP_ALL:
#endif
	case HWTSTAMP_FILTER_ALL:
		return -ERANGE;
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
		sxe2_ptp_rxts_enable(adapter);
		adapter->ptp_ctxt.tstamp_config.rx_filter = HWTSTAMP_FILTER_PTP_V2_EVENT;
		break;
	default:
		return -ERANGE;
	}

	return 0;
}

int sxe2_ptp_hwts_set(struct sxe2_adapter *adapter, struct ifreq *ifr)
{
	struct hwtstamp_config config;
	int err;

	if (adapter->ptp_ctxt.status != PTP_READY)
		return -EAGAIN;

	if (copy_from_user(&config, ifr->ifr_data, sizeof(config)))
		return -EFAULT;

	err = sxe2_ptp_ts_mode_set(adapter, &config);
	if (err)
		return err;

	config = adapter->ptp_ctxt.tstamp_config;

	return copy_to_user(ifr->ifr_data, &config, sizeof(config)) ? -EFAULT : 0;
}

static int sxe2_extts_configure(struct ptp_clock_info *ptp,
				struct ptp_clock_request *rq, int on)
{
	struct sxe2_adapter *adapter = sxe2_ptp_to_adapter(ptp);
	u32 aux_in_value	     = 0;

	if (rq->extts.index > SXE2_EXTTS_COUNT)
		return -EINVAL;

	if (on) {
		sxe2_hw_ptp_tsyn_event_switch(&adapter->hw, true);
		aux_in_value = GLTSYN_AUXIN_ENABLE;
		if (rq->extts.flags & PTP_RISING_EDGE)
			aux_in_value |= GLTSYN_AUXIN_RISING_EDGE;

		if (rq->extts.flags & PTP_FALLING_EDGE)
			aux_in_value |= GLTSYN_AUXIN_FALLING_EDGE;

		sxe2_hw_ptp_aux_in_set(&adapter->hw, rq->extts.index,
				       aux_in_value);
		set_bit((int)(rq->extts.index), adapter->ptp_ctxt.extts.chan);

	} else {
		sxe2_hw_ptp_aux_in_set(&adapter->hw, rq->extts.index, aux_in_value);
		clear_bit((int)(rq->extts.index), adapter->ptp_ctxt.extts.chan);
		if (bitmap_empty(adapter->ptp_ctxt.extts.chan,
				 SXE2_EXTTS_COUNT)) {
			sxe2_hw_ptp_tsyn_event_switch(&adapter->hw, false);
		}
	}

	return 0;
}

static void sxe2_ptp_all_perout_restore(struct sxe2_adapter *adapter)
{
	u32 index;
	u64 period = 0;
	u32 value;

	for (index = 0; index < SXE2_PEROUT_COUNT; index++) {
		struct sxe2_ptp_perout_context *perout = &adapter->ptp_ctxt.perout[index];

		if (perout->on) {
			value = sxe2_hw_ptp_auxout_get(&adapter->hw, index);
			value |= GLTSYN_AUXOUT_OUT_ENA;
			value |= GLTSYN_AUXOUT_INT_ENA;
			sxe2_hw_ptp_auxout_set(&adapter->hw, index, value);
			period = (u64)((perout->start.tv_sec *
					NSEC_PER_SEC) +
				       perout->start.tv_nsec);
			period >>= 1;

			sxe2_hw_ptp_1588_clockout_write(&adapter->hw, index, period,
							(u64)perout->start.tv_sec,
							(u64)perout->start.tv_nsec);

		} else {
			value = sxe2_hw_ptp_auxout_get(&adapter->hw, index);
			value &= ~GLTSYN_AUXOUT_OUT_ENA;
			value &= ~GLTSYN_AUXOUT_INT_ENA;
			sxe2_hw_ptp_auxout_set(&adapter->hw, index, value);
			sxe2_hw_ptp_1588_clockout_write(&adapter->hw, index, 0, 0, 0);
		}
	}
}

static void sxe2_ptp_all_perout_disable(struct sxe2_adapter *adapter)
{
	u32 index;
	u32 value;

	for (index = 0; index < SXE2_PEROUT_COUNT; index++) {
		value = sxe2_hw_ptp_auxout_get(&adapter->hw, index);
		value &= ~GLTSYN_AUXOUT_OUT_ENA;
		value &= ~GLTSYN_AUXOUT_INT_ENA;
		sxe2_hw_ptp_auxout_set(&adapter->hw, index, value);
		sxe2_hw_ptp_1588_clockout_write(&adapter->hw, index, 0, 0, 0);
	}
}

static int sxe2_perout_configure(struct ptp_clock_info *ptp,
				 struct ptp_clock_request *rq, int on)
{
	u32 value;
	u64 period		     = 0;
	struct sxe2_adapter *adapter = sxe2_ptp_to_adapter(ptp);
	u32 index = rq->perout.index;

	period = (u64)((rq->perout.period.sec * NSEC_PER_SEC) +
		       rq->perout.period.nsec);
	if (period & 0x1) {
		LOG_DEV_ERR("CLKO period is illegal\n");
		return -EIO;
	}

	period >>= 1;
	if (period > SXE2_MAX_CLKO_VALUE) {
		LOG_DEV_ERR("CLKO period is illegal\n");
		return -EIO;
	}

	value = sxe2_hw_ptp_auxout_get(&adapter->hw, index);
	if (on && period) {
		adapter->ptp_ctxt.perout[index].period.tv_sec =
			rq->perout.period.sec;
		adapter->ptp_ctxt.perout[index].period.tv_nsec =
			rq->perout.period.nsec;
		adapter->ptp_ctxt.perout[index].start.tv_sec =
			rq->perout.start.sec;
		adapter->ptp_ctxt.perout[index].start.tv_nsec =
			rq->perout.start.nsec;
		adapter->ptp_ctxt.perout[index].on = true;
		value |= GLTSYN_AUXOUT_OUT_ENA;
		value |= GLTSYN_AUXOUT_INT_ENA;
		sxe2_hw_ptp_auxout_set(&adapter->hw, index, value);
	} else {
		adapter->ptp_ctxt.perout[index].period.tv_sec  = 0;
		adapter->ptp_ctxt.perout[index].period.tv_nsec = 0;
		adapter->ptp_ctxt.perout[index].start.tv_sec   = 0;
		adapter->ptp_ctxt.perout[index].start.tv_nsec  = 0;
		adapter->ptp_ctxt.perout[index].on	       = false;
		value &= ~GLTSYN_AUXOUT_OUT_ENA;
		value &= ~GLTSYN_AUXOUT_INT_ENA;
		sxe2_hw_ptp_auxout_set(&adapter->hw, index, value);
	}

	sxe2_hw_ptp_1588_clockout_write(&adapter->hw, index, period,
					(u64)adapter->ptp_ctxt.perout[index].start.tv_sec,
					(u64)adapter->ptp_ctxt.perout[index].start.tv_nsec);

	return 0;
}

int sxe2_ptp_enable(struct ptp_clock_info *ptp,
		    struct ptp_clock_request *request, int on)
{
	int ret;

	switch (request->type) {
	case PTP_CLK_REQ_EXTTS:
		ret = sxe2_extts_configure(ptp, request, !!on);
		break;
	case PTP_CLK_REQ_PEROUT:
		ret = sxe2_perout_configure(ptp, request, !!on);
		break;
	case PTP_CLK_REQ_PPS:
	default:
		ret = -EOPNOTSUPP;
		break;
	}

	return ret;
}

STATIC void sxe2_ptp_update_timespec(struct sxe2_adapter *adapter,
				     const struct timespec64 *ts)
{
	unsigned long flags = 0;

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2_VSI_S_DISABLE, adapter->vsi_ctxt.main_vsi->state)) {
		LOG_ERROR_BDF("vsi is disable, do not use queues' context.\n");
		goto l_unlock;
	}

	spin_lock_irqsave(&adapter->ptp_ctxt.cached_ts_lock, flags);
	adapter->ptp_ctxt.cached_phc_time = *ts;
	spin_unlock_irqrestore(&adapter->ptp_ctxt.cached_ts_lock, flags);

l_unlock:
	mutex_unlock(&adapter->vsi_ctxt.lock);
}

int sxe2_ptp_gettimex64(struct ptp_clock_info *ptp, struct timespec64 *ts,
			struct ptp_system_timestamp *sts)
{
	int ret = 0;
	struct sxe2_adapter *adapter = sxe2_ptp_to_adapter(ptp);

	ptp_read_system_prets(sts);

	if (!sxe2_ptp_primary_timer_read(adapter, ts)) {
		LOG_ERROR_BDF("failed to read 1588 timer.\n");
		ret = -EIO;
	}

	ptp_read_system_postts(sts);
	return ret;
}

static int sxe2_ptp_gettime(struct ptp_clock_info *info, struct timespec64 *ts)
{
	return sxe2_ptp_gettimex64(info, ts, NULL);
}

int sxe2_ptp_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct sxe2_adapter *adapter = sxe2_ptp_to_adapter(ptp);
	struct timespec64 now, then;
	int err;

	if (delta > SXE2_MAX_CLKO_VALUE || delta < S32_MIN) {
		then = ns_to_timespec64(delta);
		err  = sxe2_ptp_gettimex64(ptp, &now, NULL);
		if (err) {
			LOG_ERROR_BDF("Failed to get current phc time.\n");
			return err;
		}

		now = timespec64_add(now, then);
		return sxe2_ptp_settime(ptp, (const struct timespec64 *)&now);
	}

	sxe2_ptp_all_perout_disable(adapter);
	(void)sxe2_ptp_primary_timer_adjust(adapter, delta);
	sxe2_ptp_all_perout_restore(adapter);

	(void)sxe2_ptp_gettimex64(ptp, &now, NULL);
	sxe2_ptp_update_timespec(adapter, &now);

	return 0;
}

int sxe2_ptp_adjfine(struct ptp_clock_info *ptp, long scaled_ppm)
{
	struct sxe2_adapter *adapter = sxe2_ptp_to_adapter(ptp);
	u64 incval		     = SXE2_PTP_NOMINAL_INCVAL_TUCANA;
	bool neg_adj		     = false;
	u64 diff;

	if (scaled_ppm < 0) {
		neg_adj	   = true;
		scaled_ppm = -scaled_ppm;
	}

	diff = mul_u64_u64_div_u64(incval, (u64)scaled_ppm, 1000000ULL << 16);
	if (neg_adj)
		incval -= diff;
	else
		incval += diff;

	LOG_DEBUG_BDF("calculate incval is %llu[0x%llx]\n", incval, incval);
	if (!sxe2_ptp_sem_acquire(adapter))
		return -EBUSY;

	sxe2_hw_ptp_init_incval(&adapter->hw, incval);
	sxe2_ptp_sem_release(adapter);

	return 0;
}

#ifndef HAVE_PTP_CLOCK_INFO_ADJFINE
static int sxe2_ptp_adjfreq(struct ptp_clock_info *info, s32 ppb)
{
	long scaled_ppm;

	scaled_ppm = ((long)ppb << PTP_TIME_OFFSET) / PTP_TIME_DIV;
	return sxe2_ptp_adjfine(info, scaled_ppm);
}
#endif

int sxe2_ptp_settime(struct ptp_clock_info *ptp, const struct timespec64 *ts)
{
	int err;
	struct sxe2_adapter *adapter = sxe2_ptp_to_adapter(ptp);

	sxe2_ptp_all_perout_disable(adapter);

	err = sxe2_ptp_primary_timer_set(adapter, *ts);
	if (!err) {
		dump_timespec64(adapter, ts);
		sxe2_ptp_update_timespec(adapter, ts);
	} else {
		LOG_ERROR_BDF("failed to set time.\n");
	}

	sxe2_ptp_all_perout_restore(adapter);

	return 0;
}

static u64 sxe2_ptp_32bit_to_realtime(u64 cached_time, u64 rawtstamp)
{
	u64 realtime;
	u32 tstamp_ns = (u32)(rawtstamp);
	u32 cached_ns = cached_time % SXE2_NS_PER_SEC;

	if (tstamp_ns > cached_ns) {
		realtime = cached_time / SXE2_NS_PER_SEC * SXE2_NS_PER_SEC + tstamp_ns;
	} else {
		realtime = cached_time / SXE2_NS_PER_SEC * SXE2_NS_PER_SEC + SXE2_NS_PER_SEC +
			   tstamp_ns;
	}

	return realtime;
}

#define SXE2_RX_WB_RXDID_MASK (0x7)
#define SXE2_RX_DESC_TYPE_1588 (0x2)
void sxe2_ptp_rxts_request(struct sxe2_queue *rxq,
			   union sxe2_rx_desc_1588 *desc, struct sk_buff *skb)
{
	struct sxe2_adapter *adapter = rxq->vsi->adapter;
	struct skb_shared_hwtstamps *hwtstamps;
	u64 ts;
	u64 raw_cached_ns;
	u32 rx_ns;
	u32 rx_subns;
	u8 rxdid;
	u32 valid;
	struct timespec64 cached_timespec64;
	unsigned long flags = 0;

	if (!adapter->ptp_ctxt.ptp_rx_enable)
		return;

	rxdid = desc->wb.rxdid_src_fd_eudpe & SXE2_RX_WB_RXDID_MASK;
	if (rxdid != SXE2_RX_DESC_TYPE_1588)
		return;

	rx_ns = le32_to_cpu(desc->wb.ts_h);
	rx_subns = le32_to_cpu(desc->wb.ts_l);
	valid = rx_subns & BIT(0);
	spin_lock_irqsave(&adapter->ptp_ctxt.cached_ts_lock, flags);
	cached_timespec64 = adapter->ptp_ctxt.cached_phc_time;
	spin_unlock_irqrestore(&adapter->ptp_ctxt.cached_ts_lock, flags);
	raw_cached_ns = (u64)timespec64_to_ns(&cached_timespec64);

#ifdef SXE2_CFG_DEBUG
	if (test_bit(SXE2_DATAPATH_LOG_ENABLE, adapter->flags)) {
		dump_timespec64(adapter, &cached_timespec64);
		LOG_DEBUG_BDF("Rx timestamp is 0x%x.0x%x,valid:%d,Cached time:%llu\n",
			      rx_ns, rx_subns, valid, raw_cached_ns);
	}
#endif

	ts = sxe2_ptp_32bit_to_realtime(raw_cached_ns, rx_ns);
	if (!ts) {
		LOG_ERROR_BDF("failed to get rx timestamp.\n");
		return;
	}

	hwtstamps = skb_hwtstamps(skb);
	(void)memset(hwtstamps, 0, sizeof(*hwtstamps));
	hwtstamps->hwtstamp = ns_to_ktime(ts);
}

s32 sxe2_ptp_txts_request(struct sxe2_ptp_tx *tx, struct sk_buff *skb)
{
	u32 index;
	unsigned long flags;

	spin_lock_irqsave(&tx->ptp_lock, flags);

	index = (u32)find_first_zero_bit(tx->in_use, SXE2_INDEX_PER_PORT);
	if (index < SXE2_INDEX_PER_PORT) {
		set_bit((int)index, tx->in_use);
		tx->descs[index].start = jiffies;
		tx->descs[index].skb   = skb_get(skb);
		skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
	} else {
		spin_unlock_irqrestore(&tx->ptp_lock, flags);
		return -EINVAL;
	}

	spin_unlock_irqrestore(&tx->ptp_lock, flags);

	return (s32)index;
}

static s32 sxe2_ptp_tx_timestamp_get(struct sxe2_adapter *adapter, u32 index,
				     u64 *ns)
{
	u64 tx_mem_ns;
	u64 cached_ns;
	bool ret;
	struct timespec64 cached_timespec64;
	unsigned long flags = 0;

	ret = sxe2_hw_ptp_tx_tstamp_read(&adapter->hw, adapter->port_idx, index, &tx_mem_ns);
	if (!ret) {
		LOG_ERROR_BDF("Failed to read tx timestamp.\n");
		return -EINVAL;
	}

	spin_lock_irqsave(&adapter->ptp_ctxt.cached_ts_lock, flags);
	cached_timespec64 = adapter->ptp_ctxt.cached_phc_time;
	spin_unlock_irqrestore(&adapter->ptp_ctxt.cached_ts_lock, flags);

	cached_ns = (u64)timespec64_to_ns(&cached_timespec64);
	*ns = sxe2_ptp_32bit_to_realtime(cached_ns, tx_mem_ns);
#ifdef SXE2_CFG_DEBUG
	LOG_DEBUG_BDF("Tx Get ts:cached:%lld.%ld ,total ns:%lld,read:%lld\n",
		      cached_timespec64.tv_sec,
		      cached_timespec64.tv_nsec, cached_ns,
		      tx_mem_ns);
#endif

	return 0;
}

static struct sk_buff *sxe2_ptp_tstamp_skb_get(struct sxe2_adapter *adapter, u64 index)
{
	struct sk_buff *skb = NULL;
	struct sxe2_ptp_tx *ptp_tx = &adapter->ptp_ctxt.tx;
	unsigned long flags;

	spin_lock_irqsave(&ptp_tx->ptp_lock, flags);
	clear_bit((int)index, ptp_tx->in_use);
	skb = ptp_tx->descs[index].skb;
	ptp_tx->descs[index].skb = NULL;
	sxe2_hw_ptp_tx_tstamp_discard(&adapter->hw, adapter->port_idx, (u32)index);
	spin_unlock_irqrestore(&ptp_tx->ptp_lock, flags);

	return skb;
}

static void sxe2_ptp_tx_tstamp_clean(struct sxe2_adapter *adapter)
{
	u64 index;
	u64 ns;
	s32 ret;
	struct skb_shared_hwtstamps shhwtstamps;
	struct sxe2_ptp_tx *ptp_tx = &adapter->ptp_ctxt.tx;
	struct sk_buff *skb;

	for_each_set_bit(index, ptp_tx->in_use, SXE2_INDEX_PER_PORT) {
		if (time_is_before_jiffies((unsigned long)ptp_tx->descs[index].start + 2 * HZ)) {
			LOG_ERROR_BDF("tx timestamp request timeout\n");
			skb = sxe2_ptp_tstamp_skb_get(adapter, index);
			if (skb)
				dev_kfree_skb_any(skb);

			continue;
		}

		ret = sxe2_ptp_tx_timestamp_get(adapter, (u32)index, &ns);
		if (ret) {
			LOG_ERROR_BDF("failed to get tx timestamp\n");
			continue;
		}

		skb = sxe2_ptp_tstamp_skb_get(adapter, index);
		if (!skb) {
			LOG_DEBUG_BDF("NULL skb in tx work handler:%llu\n", index);
			continue;
		}

		shhwtstamps.hwtstamp = ns_to_ktime(ns);
		skb_tstamp_tx(skb, &shhwtstamps);
		dev_kfree_skb_any(skb);
	}
}

void sxe2_ptp_txts_process(struct sxe2_adapter *adapter)
{
	if (adapter->ptp_ctxt.status != PTP_READY)
		return;

	sxe2_ptp_tx_tstamp_clean(adapter);
}

static void sxe2_ptp_schedule_periodic_work(struct sxe2_ptp_context *ptp,
					    unsigned long delay)
{
	(void)kthread_queue_delayed_work(ptp->kworker, &ptp->period_work, delay);
}

static void sxe2_ptp_cancel_periodic_work(struct sxe2_ptp_context *ptp)
{
	(void)kthread_cancel_delayed_work_sync(&ptp->period_work);
}

void sxe2_ptp_extts_intr(struct sxe2_adapter *adapter)
{
	struct sxe2_ptp_extts_context *extts = &adapter->ptp_ctxt.extts;
	u32 index;
	struct ptp_clock_event event;
	struct timespec64 ts;

	for (index = 0; index < SXE2_EXTTS_COUNT; index++) {
		if (test_bit((int)index, extts->chan)) {
			if (!test_bit((int)index, extts->irq))
				continue;

			ts.tv_sec = (time64_t)sxe2_hw_ptp_get_event_second(&adapter->hw, index);
			ts.tv_nsec =
				(long)sxe2_hw_ptp_get_event_nanosecond(&adapter->hw, index);
			event.timestamp = (u64)timespec64_to_ns(&ts);
			event.type	= PTP_CLOCK_EXTTS;
			event.index	= (int)index;
			ptp_clock_event(adapter->ptp_ctxt.clock, &event);
			clear_bit((int)index, extts->irq);
		}
	}
}

static bool sxe2_ptp_enabled(struct sxe2_adapter *adapter)
{
	bool ret = false;

	if (!sxe2_ptp_sem_acquire(adapter))
		goto error;

	ret = sxe2_hw_ptp_main_is_enabled(&adapter->hw);
	sxe2_ptp_sem_release(adapter);

error:
	return ret;
}

static void sxe2_ptp_period_work(struct kthread_work *work)
{
	struct sxe2_adapter *adapter = container_of(work, struct sxe2_adapter,
						    ptp_ctxt.period_work.work);
	u32 period;
	struct timespec64 ts;

	if (sxe2_ptp_enabled(adapter) == false) {
		period = SXE2_PTP_PERIOD_NORMAL;
		goto out;
	}

	if (sxe2_ptp_primary_timer_read(adapter, &ts)) {
		period = SXE2_PTP_PERIOD_NORMAL;
		sxe2_ptp_update_timespec(adapter, &ts);

		adapter->ptp_ctxt.last_is_failed = false;
	} else {
		if (!adapter->ptp_ctxt.last_is_failed)
			LOG_ERROR_BDF("failed to read 1588 timer.\n");

		adapter->ptp_ctxt.last_is_failed = true;

		period = SXE2_PTP_PERIOD_UNNORMAL;
	}

out:
	sxe2_ptp_schedule_periodic_work(&adapter->ptp_ctxt,
					msecs_to_jiffies(period));
}

static s32 sxe2_fwc_ptp_mac_init(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_cmd_params cmd	 = { 0 };
	struct sxe2_fwc_ptp_init_req req = { 0 };

	req.corr.ingress_corr_nanosec = SXE2_PTP_INGRESS_CORR_NANO;
	req.corr.ingress_corr_subnanosec = SXE2_PTP_INGRESS_CORR_SUBNANO;
	req.corr.ingress_sync_corr = SXE2_PTP_INGRESS_CORR;
	req.corr.egress_corr_nanosec = SXE2_PTP_EGRESS_CORR_NANO;
	req.corr.egress_corr_subnanosec = SXE2_PTP_EGRESS_CORR_SUBNANO;
	req.corr.egress_sync_corr = SXE2_PTP_EGRESS_CORR;
	req.filter_addr.filter_type = SXE2_PTP_FILTER_TYPE_ALL;
	req.sample_type = SXE2_PTP_SAMPLE_TYPE_ALL;
	req.threshold = 0;

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_PTP_INIT, &req, sizeof(req), NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("ptp fw init fail, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

static s32 sxe2_ptp_clock_create(struct sxe2_adapter *adapter)
{
	struct ptp_clock_info *info = &adapter->ptp_ctxt.info;
	struct device *dev	    = (&((adapter)->pdev->dev));

	if (adapter->ptp_ctxt.clock)
		return 0;

	(void)snprintf(info->name, sizeof(info->name) - 1, "%s-%s-clk",
		       dev_driver_string(dev), dev_name(dev));
	info->owner	 = THIS_MODULE;
	info->max_adj	 = SXE2_PTP_MAX_ADJ;
	info->adjtime	 = sxe2_ptp_adjtime;
#ifdef HAVE_PTP_CLOCK_INFO_ADJFINE
	info->adjfine	 = sxe2_ptp_adjfine;
#else
	info->adjfreq    = sxe2_ptp_adjfreq;
#endif
#ifdef HAVE_PTP_CLOCK_INFO_GETTIMEX64
	info->gettimex64 = sxe2_ptp_gettimex64;
#endif
	info->gettime64  = sxe2_ptp_gettime;

	info->settime64	 = sxe2_ptp_settime;
	info->enable	 = sxe2_ptp_enable;
	info->n_per_out	 = SXE2_PEROUT_COUNT;
	info->n_ext_ts	 = SXE2_EXTTS_COUNT;

	adapter->ptp_ctxt.clock = ptp_clock_register(info, dev);
	if (IS_ERR(adapter->ptp_ctxt.clock)) {
		LOG_ERROR_BDF("failed to create ptp clock,err:%ld.\n",
			      PTR_ERR(adapter->ptp_ctxt.clock));
		return (s32)PTR_ERR(adapter->ptp_ctxt.clock);
	}
	return 0;
}

STATIC s32 sxe2_fwc_ptp_sem_clean(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_cmd_params cmd = { 0 };

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_PTP_SEM_CLEAN, NULL, 0, NULL, 0);

	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_ERROR_BDF("ptp sem clean fail, ret=%d\n", ret);
		ret = -EIO;
	}

	return ret;
}

static int sxe2_ptp_1588_init(struct sxe2_adapter *adapter)
{
	int err = 0;
	struct timespec64 ts;

	err = sxe2_fwc_ptp_sem_clean(adapter);
	if (err) {
		LOG_ERROR_BDF("failed to release ptp lock force, err:%d.\n", err);
		goto error;
	};

	if (!sxe2_ptp_sem_acquire(adapter)) {
		err = -EBUSY;
		goto error;
	}

	sxe2_hw_ptp_main_enable(&adapter->hw);

	ts = ktime_to_timespec64(ktime_get_real());
	sxe2_hw_ptp_init_incval(&adapter->hw, SXE2_PTP_NOMINAL_INCVAL_TUCANA);
	sxe2_hw_ptp_1588_timestamp_write(&adapter->hw, (u64)ts.tv_sec,
					 (u32)ts.tv_nsec);
	sxe2_ptp_sem_release(adapter);

error:
	return err;
}

int sxe2_ptp_init(struct sxe2_adapter *adapter)
{
	struct kthread_worker *kworker;
	int ret = 0;
	struct device *dev = &((adapter)->pdev->dev);

	adapter->ptp_ctxt.status = PTP_UNINITIALIZED;

	if (sxe2_ptp_owned(adapter)) {
		LOG_DEBUG_BDF("current pf[%d] owns the 1588 timer\n",
			      adapter->pf_idx);
		ret = sxe2_ptp_1588_init(adapter);
		if (ret) {
			LOG_ERROR_BDF("failed to create ptp clock\n");
			goto clock_err;
		}

		ret = sxe2_ptp_clock_create(adapter);
		if (ret) {
			LOG_ERROR_BDF("failed to create ptp clock\n");
			ret = -ENOMEM;
			goto clock_err;
		}

		ret = sxe2_ptp_owner_adapter_add(adapter);
		if (ret) {
			LOG_ERROR_BDF("failed to add ptp owner adapter\n");
			goto set_owner_err;
		}
	}

	ret = sxe2_fwc_ptp_mac_init(adapter);
	if (ret) {
		LOG_DEV_ERR("failed to initial ptp.%d\n", ret);
		goto set_owner_err;
	}

	bitmap_zero(adapter->ptp_ctxt.tx.in_use, SXE2_INDEX_PER_PORT);
	spin_lock_init(&adapter->ptp_ctxt.tx.ptp_lock);
	spin_lock_init(&adapter->ptp_ctxt.cached_ts_lock);
	kthread_init_delayed_work(&adapter->ptp_ctxt.period_work,
				  sxe2_ptp_period_work);

	kworker = kthread_create_worker(0, "sxe2-ptp%d-%s",
					adapter->pf_idx, dev_name(dev));
	if (IS_ERR(kworker)) {
		LOG_DEV_ERR("failed to create ptp worker\n");
		ret = (int)PTR_ERR(kworker);
		goto init_mac_err;
	}

	adapter->ptp_ctxt.kworker = kworker;
	sxe2_ptp_schedule_periodic_work(&adapter->ptp_ctxt, 0);

	sxe2_ptp_txts_disable(adapter);
	sxe2_ptp_rxts_disable(adapter);
	adapter->ptp_ctxt.tstamp_config.rx_filter = HWTSTAMP_FILTER_NONE;
	adapter->ptp_ctxt.tstamp_config.tx_type = HWTSTAMP_TX_OFF;
	adapter->ptp_ctxt.last_is_failed = false;
	adapter->ptp_ctxt.status = PTP_READY;

	LOG_DEBUG_BDF("Ptp init success!,pfid:%d\n", adapter->pf_idx);

	return 0;

init_mac_err:
	if (sxe2_ptp_owned(adapter))
		sxe2_ptp_owner_adapter_delete(adapter);

set_owner_err:
	if (adapter->ptp_ctxt.clock) {
		(void)ptp_clock_unregister(adapter->ptp_ctxt.clock);
		adapter->ptp_ctxt.clock = NULL;
	}

clock_err:
	adapter->ptp_ctxt.status = PTP_ERROR;

	return ret;
}

void sxe2_ptp_deinit(struct sxe2_adapter *adapter)
{
	struct sxe2_ptp_tx *tx = &adapter->ptp_ctxt.tx;
	struct sk_buff *skb;
	u64 index;

	if (!adapter->ptp_ctxt.kworker) {
		LOG_ERROR_BDF("pf %d kworker is null\n", adapter->pf_idx);
		return;
	}

	adapter->ptp_ctxt.status = PTP_UNINITIALIZED;

	if (sxe2_ptp_owned(adapter)) {
		LOG_DEBUG_BDF("current pf[%d] owns the 1588 timer\n",
			      adapter->pf_idx);
		sxe2_ptp_owner_adapter_delete(adapter);
		if (adapter->ptp_ctxt.clock) {
			(void)ptp_clock_unregister(adapter->ptp_ctxt.clock);
			adapter->ptp_ctxt.clock = NULL;
		}
	}

	for_each_set_bit(index, tx->in_use, SXE2_INDEX_PER_PORT) {
		skb = sxe2_ptp_tstamp_skb_get(adapter, index);
		if (skb) {
			dev_kfree_skb_any(skb);
			skb = NULL;
		}
	}

	sxe2_ptp_cancel_periodic_work(&adapter->ptp_ctxt);

	kthread_destroy_worker(adapter->ptp_ctxt.kworker);

	sxe2_ptp_txts_disable(adapter);
	sxe2_ptp_rxts_disable(adapter);
	adapter->ptp_ctxt.tstamp_config.rx_filter = HWTSTAMP_FILTER_NONE;
	adapter->ptp_ctxt.tstamp_config.tx_type = HWTSTAMP_TX_OFF;
}

void sxe2_ptp_stop(struct sxe2_adapter *adapter)
{
	u64 index;
	struct sxe2_ptp_tx *tx	     = &adapter->ptp_ctxt.tx;
	struct sxe2_ptp_context *ptp = &adapter->ptp_ctxt;
	struct sk_buff *skb;

	if (ptp->status != PTP_READY)
		return;

	ptp->status = PTP_RESETTING;

	for_each_set_bit(index, tx->in_use, SXE2_INDEX_PER_PORT) {
		skb = sxe2_ptp_tstamp_skb_get(adapter, index);
		if (skb) {
			dev_kfree_skb_any(skb);
			skb = NULL;
		}
	}

	sxe2_ptp_txts_disable(adapter);
	sxe2_ptp_rxts_disable(adapter);
	sxe2_ptp_all_perout_disable(adapter);

	sxe2_ptp_cancel_periodic_work(ptp);
}

int sxe2_ptp_rebuild(struct sxe2_adapter *adapter)
{
	s32 err = 0;
	struct timespec64 ts;
	struct sxe2_ptp_context *ptp = &adapter->ptp_ctxt;

	if (!adapter->ptp_ctxt.kworker) {
		LOG_ERROR_BDF("pf %d kworker is null\n",
			      adapter->pf_idx);
		return -EINVAL;
	}

	if (sxe2_ptp_owned(adapter)) {
		if (!sxe2_ptp_sem_acquire(adapter)) {
			LOG_ERROR_BDF("failed to get ptp lock\n");
			err = -EINVAL;
			goto error;
		}
		sxe2_hw_ptp_main_enable(&adapter->hw);
		sxe2_hw_ptp_init_incval(&adapter->hw,
					SXE2_PTP_NOMINAL_INCVAL_TUCANA);
		sxe2_ptp_sem_release(adapter);
		ts = ktime_to_timespec64(ktime_get_real());
		if (sxe2_ptp_primary_timer_set(adapter, ts)) {
			LOG_ERROR_BDF("failed to re init 1588 time\n");
			err = -EINVAL;
			goto error;
		}
	}

	sxe2_ptp_all_perout_restore(adapter);
	sxe2_ptp_schedule_periodic_work(ptp, 0);
	sxe2_ptp_txts_restore(adapter);
	sxe2_ptp_rxts_restore(adapter);

	ptp->status = PTP_READY;
	LOG_DEBUG_BDF("rebuild ptp ok\n");
	return 0;

error:
	ptp->status = PTP_ERROR;
	return err;
}
