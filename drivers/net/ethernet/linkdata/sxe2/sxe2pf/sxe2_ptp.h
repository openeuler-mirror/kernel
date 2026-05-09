/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_ptp.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_PTP_H__
#define __SXE2_PTP_H__

#include <linux/seqlock.h>
#include <linux/if.h>
#include <linux/kthread.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/net_tstamp.h>

#define SXE2_EXTTS_COUNT 3
#define SXE2_PEROUT_COUNT 4
#define SXE2_INDEX_PER_PORT 64
#define SXE2_PTP_NOMINAL_INCVAL_TUCANA (0x1B4E89B4EULL)

struct sxe2_adapter;
struct sxe2_queue;
union sxe2_rx_desc_1588;

enum sxe2_ptp_status {
	PTP_UNINITIALIZED = 0,
	PTP_ERROR,
	PTP_READY,
	PTP_RESETTING
};

struct sxe2_ptp_perout_context {
	bool on;
	int gpio;
	struct timespec64 period;
	struct timespec64 start;
};

struct sxe2_ptp_extts_context {
	DECLARE_BITMAP(chan, SXE2_EXTTS_COUNT);
	DECLARE_BITMAP(irq, SXE2_EXTTS_COUNT);
};

struct sxe2_ptp_descriptor {
	struct sk_buff *skb;
	u64 start;
};

struct sxe2_ptp_tx {
	/* in order to protect the data */
	spinlock_t ptp_lock;
	struct sxe2_ptp_descriptor descs[SXE2_INDEX_PER_PORT];
	DECLARE_BITMAP(in_use, SXE2_INDEX_PER_PORT);
};

struct sxe2_ptp_context {
	enum sxe2_ptp_status status;
	bool ptp_owned;
	bool ptp_tx_enable;
	bool ptp_rx_enable;

	struct kthread_delayed_work period_work;
	struct kthread_worker *kworker;
	/* in order to protect the data */
	spinlock_t cached_ts_lock;
	struct timespec64 cached_phc_time;
	bool last_is_failed;

	struct sxe2_ptp_tx tx;

	struct sxe2_ptp_extts_context extts;

	struct sxe2_ptp_perout_context perout[SXE2_PEROUT_COUNT];

	struct ptp_clock_info info;
	struct ptp_clock *clock;
	struct hwtstamp_config tstamp_config;
};

struct sxe2_ptp_owner_list {
	struct list_head node;
	struct sxe2_adapter *owner_adapter;
};

int sxe2_ptp_init(struct sxe2_adapter *adapter);

void sxe2_ptp_deinit(struct sxe2_adapter *adapter);

void sxe2_ptp_rxts_request(struct sxe2_queue *rxq,
			   union sxe2_rx_desc_1588 *desc, struct sk_buff *skb);

s32 sxe2_ptp_txts_request(struct sxe2_ptp_tx *tx, struct sk_buff *skb);

void sxe2_ptp_txts_process(struct sxe2_adapter *adapter);

int sxe2_ptp_hwts_get(struct sxe2_adapter *adapter, struct ifreq *ifr);

int sxe2_ptp_hwts_set(struct sxe2_adapter *adapter, struct ifreq *ifr);

void sxe2_ptp_stop(struct sxe2_adapter *adapter);

int sxe2_ptp_rebuild(struct sxe2_adapter *adapter);

int sxe2_ptp_adjtime(struct ptp_clock_info *ptp, s64 delta);

int sxe2_ptp_adjfine(struct ptp_clock_info *ptp, long scaled_ppm);

int sxe2_ptp_gettimex64(struct ptp_clock_info *ptp, struct timespec64 *ts,
			struct ptp_system_timestamp *sts);

int sxe2_ptp_settime(struct ptp_clock_info *ptp, const struct timespec64 *ts);

int sxe2_ptp_enable(struct ptp_clock_info *ptp,
		    struct ptp_clock_request *request, int on);
bool sxe2_ptp_owned(struct sxe2_adapter *adapter);

bool sxe2_ptp_primary_timer_read(struct sxe2_adapter *adapter,
				 struct timespec64 *hwts);
void sxe2_ptp_owner_init_once(void);

void sxe2_ptp_owner_deinit_once(void);

s32 sxe2_ptp_clock_idx_get(struct sxe2_adapter *adapter);

void sxe2_ptp_extts_intr(struct sxe2_adapter *adapter);

#endif
