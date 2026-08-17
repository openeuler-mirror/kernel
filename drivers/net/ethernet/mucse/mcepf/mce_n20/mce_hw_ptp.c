// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include "../mce.h"
#include "../mce_base.h"
#include "mce_hw_n20.h"
#include <linux/ptp_classify.h>
#include "mce_hw_ptp.h"

static void config_close_tstamping(struct mce_hw *hw)
{
	u32 value;

	value = rd32(hw, N20_PTP_OFF(N20_PTP_CFG));
	value &= (~(N20_PTP_TX_EN | N20_PTP_RX_EN));
	wr32(hw, N20_PTP_OFF(N20_PTP_CFG), value);
}

void n20_get_systime(struct mce_hw *hw, u64 *systime)
{
	u64 ns;

	if (!systime)
		return;

	ns = rd32(hw, N20_PTP_OFF(N20_TS_GET_NS));
	ns += rd32(hw, N20_PTP_OFF(N20_TS_GET_S)) * 1000000000ULL;
	*systime = ns;
	hw_logd(LOG_PTP_HW, "%s systime:%llu\n", __func__, *systime);
}

int n20_init_systime(struct mce_hw *hw, u32 sec, u32 nsec)
{
	wr32(hw, N20_PTP_OFF(N20_TS_CFG_S), sec);
	wr32(hw, N20_PTP_OFF(N20_TS_CFG_NS), nsec);

	wr32(hw, N20_PTP_OFF(N20_INITIAL_UPDATE_CMD), BIT(0));
	hw_logd(LOG_PTP_HW, "%s sec:%u nsec:%u\n", __func__, sec, nsec);

	return 0;
}

int n20_adjust_systime(struct mce_hw *hw, u32 sec, u32 nsec, int add_sub)
{
	if (add_sub) {
		/* if sub */
		nsec = 1000000000 - nsec;
		nsec |= BIT(31);
	}

	hw_logd(LOG_PTP_HW, "%s nsec:%u add:%d\n", __func__, nsec, add_sub);

	wr32(hw, N20_PTP_OFF(N20_TS_CFG_S), sec);
	wr32(hw, N20_PTP_OFF(N20_TS_CFG_NS), nsec);
	/* update time */
	wr32(hw, N20_PTP_OFF(N20_INITIAL_UPDATE_CMD), BIT(1));

	return 0;
}

/* do adjfine */
int n20_adjfine(struct mce_hw *hw, long scaled_ppm)
{
	bool neg_adj = false;
	u64 scaled_ppm_u;
	u32 temp, temp1;
	u64 comp;
	u64 adj;

	if (scaled_ppm < 0) {
		neg_adj = true;
		scaled_ppm = -scaled_ppm;
	}

	hw_logd(LOG_PTP_HW, "%s scaled_ppm:%ld\n", __func__, scaled_ppm);

	/* The hardware adds the clock compensation value to the PTP clock
	 * on every coprocessor clock cycle. Typical convention is that it
	 * represent number of nanosecond between each cycle. In this
	 * convention compensation value is in 64 bit fixed-point
	 * representation where upper 32 bits are number of nanoseconds
	 * and lower is fractions of nanosecond.
	 * The scaled_ppm represent the ratio in "parts per billion" by which the
	 * compensation value should be corrected.
	 * To calculate new compensation value we use 64bit fixed point
	 * arithmetic on following formula
	 * comp = tbase + tbase * scaled_ppm / (1M * 2^16)
	 * where tbase is the basic compensation value calculated initially
	 * in cavium_ptp_init() -> tbase = 1/Hz. Then we use endian
	 * independent structure definition to write data to PTP register.
	 */
	comp = ((u64)1000000000ull << 32) / hw->clk_ptp_rate;
	/* Split scaled_ppm to avoid overflowing comp * scaled_ppm. */
	scaled_ppm_u = scaled_ppm;
	adj = div_u64(comp * (scaled_ppm_u >> 16), 1000000ULL);
	adj += div64_u64(comp * (scaled_ppm_u & 0xffff),
			 1000000ULL << 16);
	comp = neg_adj ? comp - adj : comp + adj;
	/* upper 32 is nsec, lower is the fractions of nanosecond */
	temp = (u32)(comp >> 32);

	/* low32 is fractions part, hw must 2 base with 16 bits;
	 * 0.xxxx * 2^16
	 * so we can do it use this :
	 * low32 >> 32 * 2^16 = low32 >> 16
	 */
	wr32(hw, N20_PTP_OFF(N20_TS_INCR_CNT), (temp << 16) | temp);
	temp1 = (u32)((comp & 0xffffffff));
	wr32(hw, N20_PTP_OFF(N20_INCR_CNT_NS_FINE), temp1);
	wr32(hw, N20_PTP_OFF(N20_INCR_CNT_NS_FINE_2), temp1);
	/* trig to hw INITIAL_UPDATE_CMD bit2 */
	wr32(hw, N20_PTP_OFF(N20_INITIAL_UPDATE_CMD), BIT(2));
	return 0;
}

int n20_ptp_init_counter(struct mce_hw *hw)
{
	u32 temp;
	u64 comp;

	/* Keep the PHC counter running independently of packet timestamping. */
	wr32(hw, N20_PTP_OFF(N20_PTP_CFG_1), 0x40);
	temp = rd32(hw, N20_M_CFG);
	temp &= ~BYPASS_PTP_TIMER_EN;
	wr32(hw, N20_M_CFG, temp);
	wr32(hw, N20_PTP_OFF(N20_PTP_CFG), N20_PTP_TCR_TSENA);

	comp = ((u64)1000000000ULL << 32) / hw->clk_ptp_rate;
	temp = (u32)(comp >> 32);
	wr32(hw, N20_PTP_OFF(N20_TS_INCR_CNT), (temp << 16) | temp);
	hw->ptp_default_int = temp;
	temp = (u32)(comp & 0xffffffff);
	wr32(hw, N20_PTP_OFF(N20_INCR_CNT_NS_FINE), temp);
	wr32(hw, N20_PTP_OFF(N20_INCR_CNT_NS_FINE_2), temp);
	wr32(hw, N20_PTP_OFF(N20_INITIAL_UPDATE_CMD), BIT(2));
	wr32(hw, N20_PTP_OFF(N20_TS_COMP), 0);

	return 0;
}

/* get tx status */
int n20_ptp_tx_status(struct mce_hw *hw)
{
	u32 value;

	value = rd32(hw, N20_ETH_PTP_TX_TSVALUE_STATUS);
	return (value & BIT(0));
}

int n20_ptp_set_ts_config(struct mce_hw *hw, struct hwtstamp_config *in_config)
{
	struct hwtstamp_config config;
	u32 ptp_over_ipv4_udp = 0;
	u32 ptp_over_ipv6_udp = 0;
	u32 ptp_over_ethernet = 0;
	u32 ts_event_en = 0;
	u32 tstamp_all = 0;
	u32 value = 0;

	/* copy old value */
	memcpy(&config, in_config, sizeof(config));

	/* reserved for future extensions */
	if (config.flags)
		return -EINVAL;

	if (config.tx_type != HWTSTAMP_TX_OFF &&
	    config.tx_type != HWTSTAMP_TX_ON)
		return -ERANGE;

	switch (config.rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		/* time stamp no incoming packet at all */
		config.rx_filter = HWTSTAMP_FILTER_NONE;
		break;

	case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
		/* PTP v1, UDP, any kind of event packet */
		config.rx_filter = HWTSTAMP_FILTER_PTP_V1_L4_EVENT;
		/* 'mac' hardware can support Sync, Pdelay_Req and
		 * Pdelay_resp by setting bit14 and bits17/16 to 01
		 * This leaves Delay_Req timestamps out.
		 * Enable all events *and* general purpose message
		 * timestamping
		 */
		ptp_over_ipv4_udp = N20_PTP_TCR_TSIPV4ENA;
		ptp_over_ipv6_udp = N20_PTP_TCR_TSIPV6ENA;
		break;

	case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
		/* PTP v1, UDP, Sync packet */
		config.rx_filter = HWTSTAMP_FILTER_PTP_V1_L4_SYNC;
		/* take time stamp for SYNC messages only */
		ts_event_en = N20_PTP_TCR_TSEVNTENA;

		ptp_over_ipv4_udp = N20_PTP_TCR_TSIPV4ENA;
		ptp_over_ipv6_udp = N20_PTP_TCR_TSIPV6ENA;
		break;

	case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
		/* PTP v1, UDP, Delay_req packet */
		config.rx_filter = HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ;
		/* take time stamp for Delay_Req messages only */
		ts_event_en = N20_PTP_TCR_TSEVNTENA;

		ptp_over_ipv4_udp = N20_PTP_TCR_TSIPV4ENA;
		ptp_over_ipv6_udp = N20_PTP_TCR_TSIPV6ENA;
		break;

	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
		/* PTP v2, UDP, any kind of event packet */
		config.rx_filter = HWTSTAMP_FILTER_PTP_V2_L4_EVENT;

		/* take time stamp for all event messages */
		ptp_over_ipv4_udp = N20_PTP_TCR_TSIPV4ENA;
		ptp_over_ipv6_udp = N20_PTP_TCR_TSIPV6ENA;
		break;

	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
		/* PTP v2, UDP, Sync packet */
		config.rx_filter = HWTSTAMP_FILTER_PTP_V2_L4_SYNC;
		/* take time stamp for SYNC messages only */
		ts_event_en = N20_PTP_TCR_TSEVNTENA;
		ptp_over_ipv4_udp = N20_PTP_TCR_TSIPV4ENA;
		ptp_over_ipv6_udp = N20_PTP_TCR_TSIPV6ENA;
		break;

	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
		/* PTP v2, UDP, Delay_req packet */
		config.rx_filter = HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ;
		/* take time stamp for Delay_Req messages only */
		ts_event_en = N20_PTP_TCR_TSEVNTENA;
		ptp_over_ipv4_udp = N20_PTP_TCR_TSIPV4ENA;
		ptp_over_ipv6_udp = N20_PTP_TCR_TSIPV6ENA;
		break;

	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
		config.rx_filter = HWTSTAMP_FILTER_PTP_V2_L2_EVENT;
		ptp_over_ethernet = N20_PTP_TCR_TSIPENA;
		break;

	case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
		config.rx_filter = HWTSTAMP_FILTER_PTP_V2_L2_SYNC;
		ts_event_en = N20_PTP_TCR_TSEVNTENA;
		ptp_over_ethernet = N20_PTP_TCR_TSIPENA;
		break;

	case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
		config.rx_filter = HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ;
		ts_event_en = N20_PTP_TCR_TSEVNTENA;
		ptp_over_ethernet = N20_PTP_TCR_TSIPENA;
		break;

	case HWTSTAMP_FILTER_PTP_V2_EVENT:
		/* PTP v2/802.AS1 any layer, any kind of event packet */
		config.rx_filter = HWTSTAMP_FILTER_PTP_V2_EVENT;
		ts_event_en = N20_PTP_TCR_TSEVNTENA;
		ptp_over_ipv4_udp = N20_PTP_TCR_TSIPV4ENA;
		ptp_over_ipv6_udp = N20_PTP_TCR_TSIPV6ENA;
		ptp_over_ethernet = N20_PTP_TCR_TSIPENA;
		break;

	case HWTSTAMP_FILTER_PTP_V2_SYNC:
		/* PTP v2/802.AS1, any layer, Sync packet */
		config.rx_filter = HWTSTAMP_FILTER_PTP_V2_SYNC;
		/* take time stamp for SYNC messages only */
		ts_event_en = N20_PTP_TCR_TSEVNTENA;
		ptp_over_ipv4_udp = N20_PTP_TCR_TSIPV4ENA;
		ptp_over_ipv6_udp = N20_PTP_TCR_TSIPV6ENA;
		ptp_over_ethernet = N20_PTP_TCR_TSIPENA;
		break;

	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
		/* PTP v2/802.AS1, any layer, Delay_req packet */
		config.rx_filter = HWTSTAMP_FILTER_PTP_V2_DELAY_REQ;
		/* take time stamp for Delay_Req messages only */
		ts_event_en = N20_PTP_TCR_TSEVNTENA;
		ptp_over_ipv4_udp = N20_PTP_TCR_TSIPV4ENA;
		ptp_over_ipv6_udp = N20_PTP_TCR_TSIPV6ENA;
		ptp_over_ethernet = N20_PTP_TCR_TSIPENA;
		break;

	case HWTSTAMP_FILTER_NTP_ALL:
	case HWTSTAMP_FILTER_ALL:
		/* time stamp any incoming packet */
		config.rx_filter = HWTSTAMP_FILTER_ALL;
		tstamp_all = N20_PTP_TCR_TSENALL;
		break;

	default:
		return -ERANGE;
	}

	hw_logd(LOG_PTP_HW, "%s rx_filter:%d tx_type:%d\n", __func__,
		config.rx_filter, config.tx_type);

	if (config.rx_filter == HWTSTAMP_FILTER_NONE && config.tx_type != HWTSTAMP_TX_ON) {
		/*rx and tx is not use hardware ts so clear the ptp register */
		config_close_tstamping(hw);
	} else {
		value = (N20_PTP_TCR_TSENA | N20_PTP_TX_EN | N20_PTP_RX_EN |
			 tstamp_all |
			 ptp_over_ethernet | ptp_over_ipv6_udp |
			 ptp_over_ipv4_udp | ts_event_en);
		wr32(hw, N20_PTP_OFF(N20_PTP_CFG), value);
	}
	memcpy(in_config, &config, sizeof(config));

	return 0;
}

/* get tx hwstamp and clear flags */
int n20_ptp_tx_stamp(struct mce_hw *hw, u64 *sec, u64 *nsec)
{
	u32 temp;
	/* read tx stamp */
	*nsec = rd32(hw, N20_ETH_PTP_TX_LTIMES);
	*sec = rd32(hw, N20_ETH_PTP_TX_HTIMES);

	/* clean tx */
#define CLEAR_MASK BIT(15)
	temp = rd32(hw, N20_ETH_PTP_TX_CLEAR);
	temp |= CLEAR_MASK;
	wr32(hw, N20_ETH_PTP_TX_CLEAR, temp);
	/* Ensure the clear command reaches hardware before deasserting it. */
	wmb();
	temp &= (~CLEAR_MASK);
	wr32(hw, N20_ETH_PTP_TX_CLEAR, temp);

	hw_logd(LOG_PTP_WORK, "%s *sec:%llu *nsec:%llu\n", __func__, *sec,
		*nsec);

	return 0;
}
