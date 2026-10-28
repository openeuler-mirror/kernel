/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_PTP_H_
#define _NSE_PTP_H_

#include <linux/clocksource.h>
#include <linux/net_tstamp.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/ptp_classify.h>
#include <linux/highuid.h>

#include "nse_controlq.h"
#include "nse_lan_tx_rx.h"

struct nse_tx_tstamp {
	struct sk_buff *skb;
	unsigned long start;
};

struct nse_ptp_tx {
	spinlock_t lock; /* protects access to in_use bitmap */
	struct nse_tx_tstamp *tstamps;
	unsigned long *in_use;
	unsigned long *report;
	u8 len;
	u8 init;
};

#define TSYN_REG_NUM_PER_PORT		64

struct nse_ptp_port {
	struct nse_ptp_tx tx;
	u8 port_num;
};

#if defined(NSE_DEBUG_EXT)
struct debug_rx_ts_s {
	u32 desc_ts_high;
	u16 desc_md4;
	u16 desc_md5;
	u32 desc_ts_low;
	union {
		struct {
			u32 desc_7b_sec_part;
			u32 desc_nsec_part;
		} amber;

		struct {
			u32 desc_h_32b_part;
			u32 desc_l_7b_part;
		} ms;
	};
	u64 desc_ns;
	u64 os_ns;
	union nse_32b_rx_desc saved_desc;
};
#endif

struct nse_ptp {
	struct nse_ptp_port port;
	struct kthread_worker *kworker;
	struct kthread_delayed_work work;
	u64 cached_phc_time;
	u32 cached_phc_time_sec_part;
	u32 cached_phc_time_nsec_part;
	unsigned long cached_last_update;

	u32 ref_freq;
	u32 ptp_freq;

	union {
		struct {
			u32 nsec_part;
			u32 subnsec_part;
		} amber;

		struct {
			u16 period_part;		/* period is, fix, unchanged */
			u16 value_part;
#define MS_PTP_DFLT_INC_PERIOD	2
#define MS_PTP_DFLT_INC_VALUE	10
		} ms;	/* for moonstone */

	} dflt_incval;			/* as base */

	u32 dflt_fine_addend;	/* as base */

	struct ptp_clock_info info;
	struct ptp_clock *clock;
	struct hwtstamp_config tstamp_config;

	bool user_rx_ts_sample_status;
	bool user_tx_ts_sample_status;

	u64 reset_time;

#if defined(NSE_DEBUG_EXT)
	struct debug_rx_ts_s __percpu *debug_rx_ts;
#endif
};

static inline struct nse_ptp *__ptp_port_to_ptp(struct nse_ptp_port *p)
{
	return container_of(p, struct nse_ptp, port);
}

#define ptp_port_to_pf(p) \
	container_of(__ptp_port_to_ptp((p)), struct nse_pf, ptp)

static inline struct nse_ptp *__ptp_info_to_ptp(struct ptp_clock_info *i)
{
	return container_of(i, struct nse_ptp, info);
}

#define ptp_info_to_pf(i) \
	container_of(__ptp_info_to_ptp((i)), struct nse_pf, ptp)

/* valid bit in: nse_32b_rx_desc -> wb -> ts_low
 */
#define NSE_PTP_TS_VALID		BIT(0)

#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
struct nse_pf;
int nse_ptp_set_ts_config(struct nse_pf *pf, struct ifreq *ifr);
int nse_ptp_get_ts_config(struct nse_pf *pf, struct ifreq *ifr);
void nse_ptp_cfg_timestamp(struct nse_pf *pf, bool ena);
int nse_get_ptp_clock_index(struct nse_pf *pf);

s8 nse_ptp_request_ts(struct nse_ptp_tx *tx, struct sk_buff *skb);
void nse_ptp_process_ts(struct nse_pf *pf, struct nse_rq_event_info *event);

enum nse_status
nse_ptp_read_src_clk_reg(struct nse_pf *pf, struct ptp_system_timestamp *sts,
			 u32 *sec_part, u32 *nsec_part, u64 *raw_nsec);
void nse_ptp_rx_hwtstamp(struct nse_ring *rx_ring, union nse_32b_rx_desc *rx_desc,
			 struct sk_buff *skb);
void nse_ptp_prepare_for_reset(struct nse_pf *pf, enum nse_reset_req reset_type);
void nse_ptp_rebuild(struct nse_pf *pf, enum nse_reset_req reset_type);
void nse_ptp_init(struct nse_pf *pf);
void nse_ptp_release(struct nse_pf *pf);
#else /* IS_ENABLED(CONFIG_PTP_1588_CLOCK) */
static inline int nse_ptp_set_ts_config(struct nse_pf __always_unused *pf,
					struct ifreq __always_unused *ifr)
{
	return 0;
}

static inline int nse_ptp_get_ts_config(struct nse_pf __always_unused *pf,
					struct ifreq __always_unused *ifr)
{
	return 0;
}

static inline void nse_ptp_cfg_timestamp(struct nse_pf *pf, bool ena) { }

static inline s8 nse_ptp_request_ts(struct nse_ptp_tx *tx, struct sk_buff *skb)
{
	return -1;
}

static inline nse_ptp_process_ts(struct nse_pf *pf, struct nse_rq_event_info *event) { }

static inline int nse_get_ptp_clock_index(struct nse_pf __always_unused *pf)
{
	return 0;
}
static inline void nse_clean_ptp_subtask(struct nse_pf *pf) { }
static inline void nse_ptp_rx_hwtstamp(struct nse_ring *rx_ring,
				       union nse_32b_rx_flex_desc *rx_desc,
				       struct sk_buff *skb) { }
static inline void nse_ptp_init(struct nse_pf *pf) { }
static inline void nse_ptp_rebuild(struct nse_pf *pf, enum nse_reset_req reset_type) { }
static inline void nse_ptp_release(struct nse_pf *pf) { }
static inline void nse_ptp_prepare_for_reset(struct nse_pf *pf, enum nse_reset_req reset_type) { }
#endif /* IS_ENABLED(CONFIG_PTP_1588_CLOCK) */

#endif	/* _NSE_PTP_H */

