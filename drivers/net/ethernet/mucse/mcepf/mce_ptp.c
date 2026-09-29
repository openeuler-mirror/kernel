// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include <linux/netdevice.h>
#include "mce.h"
#include "mce_ptp.h"
#include "mce_txrx_lib.h"

static int mce_ptp_adjfine(struct ptp_clock_info *ptp, long scaled_ppm)
{
	struct mce_pf *pf =
		container_of(ptp, struct mce_pf, ptp_clock_ops);
	struct mce_hw *hw = &pf->hw;
	unsigned long flags;

	spin_lock_irqsave(&pf->ptp_lock, flags);
	hw->ops->ptp_adjfine(hw, scaled_ppm);
	spin_unlock_irqrestore(&pf->ptp_lock, flags);

	return 0;
}

static int mce_ptp_adjfreq(struct ptp_clock_info *ptp, s32 ppb)
{
	long scaled_ppm;

	/* We want to calculate
	 *
	 *    scaled_ppm = ppb * 2^16 / 1000
	 *
	 * which simplifies to
	 *
	 *    scaled_ppm = ppb * 2^13 / 125
	 */
	scaled_ppm = ((long)ppb << 13) / 125;
	return mce_ptp_adjfine(ptp, scaled_ppm);
}

static int mce_ptp_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct mce_pf *pf =
		container_of(ptp, struct mce_pf, ptp_clock_ops);
	struct mce_hw *hw = &pf->hw;
	u32 quotient, reminder;
	unsigned long flags;
	int neg_adj = 0;
	u32 sec, nsec;

	if (delta < 0) {
		neg_adj = 1;
		delta = -delta;
	}

	if (delta == 0)
		return 0;

	quotient = div_u64_rem(delta, 1000000000ULL, &reminder);
	sec = quotient;
	nsec = reminder;

	spin_lock_irqsave(&pf->ptp_lock, flags);
	hw->ops->ptp_adjust_systime(hw, sec, nsec, neg_adj);
	spin_unlock_irqrestore(&pf->ptp_lock, flags);

	return 0;
}

static int mce_ptp_gettime(struct ptp_clock_info *ptp, struct timespec64 *ts)
{
	struct mce_pf *pf =
		container_of(ptp, struct mce_pf, ptp_clock_ops);
	struct mce_hw *hw = &pf->hw;
	unsigned long flags;
	u64 ns = 0;

	spin_lock_irqsave(&pf->ptp_lock, flags);
	hw->ops->ptp_get_systime(hw, &ns);
	spin_unlock_irqrestore(&pf->ptp_lock, flags);
	*ts = ns_to_timespec64(ns);

	return 0;
}

static int mce_ptp_settime(struct ptp_clock_info *ptp,
			   const struct timespec64 *ts)
{
	struct mce_pf *pf =
		container_of(ptp, struct mce_pf, ptp_clock_ops);
	struct mce_hw *hw = &pf->hw;
	unsigned long flags;

	spin_lock_irqsave(&pf->ptp_lock, flags);
	hw->ops->ptp_init_systime(hw, ts->tv_sec, ts->tv_nsec);
	spin_unlock_irqrestore(&pf->ptp_lock, flags);

	return 0;
}

static int mce_ptp_feature_enable(struct ptp_clock_info *ptp,
				  struct ptp_clock_request *rq, int on)
{
	(void)ptp;
	(void)rq;
	(void)on;

	/*TODO add support for enable the option 1588 feature PPS Auxiliary */
	return -EOPNOTSUPP;
}

int mce_ptp_get_ts_config(struct mce_pf *pf, struct ifreq *ifr)
{
	struct hwtstamp_config *config = &pf->tstamp_config;

	return copy_to_user(ifr->ifr_data, config, sizeof(*config)) ? -EFAULT :
								      0;
}

int mce_ptp_set_ts_config(struct mce_pf *pf, struct ifreq *ifr)
{
	struct mce_hw *hw = &pf->hw;
	struct hwtstamp_config config;
	unsigned long flags;
	int err;

	if (!(pf->flags2 & MCE_FLAG2_PTP_ENABLED)) {
		dev_err(&pf->pdev->dev, "No support for HW time stamping\n");
		pf->ptp_tx_en = 0;
		pf->ptp_rx_en = 0;

		return -EOPNOTSUPP;
	}

	if (copy_from_user(&config, ifr->ifr_data, sizeof(config)))
		return -EFAULT;

	dev_info(&pf->pdev->dev,
		 "%s config flags:0x%x, tx_type:0x%x, rx_filter:0x%x\n",
		    __func__, config.flags, config.tx_type, config.rx_filter);
	/* reserved for future extensions */
	if (config.flags)
		return -EINVAL;

	if (config.tx_type != HWTSTAMP_TX_OFF &&
	    config.tx_type != HWTSTAMP_TX_ON)
		return -ERANGE;

	spin_lock_irqsave(&pf->ptp_lock, flags);
	err = hw->ops->ptp_set_ts_config(hw, &config);
	if (!err)
		pf->tstamp_config = config;
	spin_unlock_irqrestore(&pf->ptp_lock, flags);
	if (err)
		return -ERANGE;

	pf->ptp_rx_en = ((config.rx_filter == HWTSTAMP_FILTER_NONE) ? 0 : 1);
	pf->ptp_tx_en = config.tx_type == HWTSTAMP_TX_ON;

	dev_info(&pf->pdev->dev,
		 "ptp config rx filter 0x%.2x tx_type 0x%.2x rx_en[%d] tx_en[%d]\n",
		config.rx_filter, config.tx_type, pf->ptp_rx_en, pf->ptp_tx_en);
	return copy_to_user(ifr->ifr_data, &config, sizeof(config)) ? -EFAULT : 0;
}

/* maybe use axi_mhz ? */
#define FRQU_NOW (500000000)
/* structure describing a PTP hardware clock */
/* initernal ops for ptp */
static struct ptp_clock_info mce_ptp_clock_ops = {
	.owner = THIS_MODULE,
	.name = "mce_ptp",
	.max_adj = FRQU_NOW,
	.n_alarm = 0,
	.n_ext_ts = 0,
	.n_per_out = 0,
	.n_pins = 0,
	/* should be 0 if not set */
	.adjfreq = mce_ptp_adjfreq,
	.adjtime = mce_ptp_adjtime,

	.gettime64 = mce_ptp_gettime,
	.settime64 = mce_ptp_settime,

	.enable = mce_ptp_feature_enable,
};

static int mce_ptp_init_hw(struct mce_pf *pf)
{
	struct mce_hw *hw = &pf->hw;
	struct hwtstamp_config config;
	struct timespec64 now;
	unsigned long flags;
	int err;

	ktime_get_real_ts64(&now);

	spin_lock_irqsave(&pf->ptp_lock, flags);
	config = pf->tstamp_config;
	err = hw->ops->ptp_init_counter(hw);
	if (!err)
		err = hw->ops->ptp_init_systime(hw, (u32)now.tv_sec,
					  now.tv_nsec);
	if (!err)
		err = hw->ops->ptp_set_ts_config(hw, &config);
	spin_unlock_irqrestore(&pf->ptp_lock, flags);

	return err;
}

int mce_ptp_restore(struct mce_pf *pf)
{
	if (!(pf->flags2 & MCE_FLAG2_PTP_ENABLED))
		return 0;

	/* Hardware reset clears the PHC counter. Reinitialize it from
	 * CLOCK_REALTIME, then restore the packet timestamping filters.
	 */
	return mce_ptp_init_hw(pf);
}

/* register it */
/* it is only belong to pf, since we can support 1 hardware ptp each pf */
int mce_ptp_register(struct mce_pf *pf)
{
	struct mce_hw *hw = &pf->hw;
	int ret;

	pf->ptp_tx_en = 0;
	pf->ptp_rx_en = 0;

	pf->ptp_clock_ops = mce_ptp_clock_ops;
	hw->clk_ptp_rate = FRQU_NOW;

	spin_lock_init(&pf->ptp_lock);
	ret = mce_ptp_init_hw(pf);
	if (ret)
		return ret;

	pf->flags2 |= MCE_FLAG2_PTP_ENABLED;
	pf->ptp_clock = ptp_clock_register(&pf->ptp_clock_ops, &pf->pdev->dev);
	if (IS_ERR(pf->ptp_clock)) {
		ret = PTR_ERR(pf->ptp_clock);
		pci_err(pf->pdev, "ptp_clock_register failed\n");
		pf->ptp_clock = NULL;
		pf->flags2 &= ~MCE_FLAG2_PTP_ENABLED;
		return ret;
	}
	if (!pf->ptp_clock) {
		pf->flags2 &= ~MCE_FLAG2_PTP_ENABLED;
		return -ENODEV;
	}
	pf->ptp_rx_en = pf->tstamp_config.rx_filter != HWTSTAMP_FILTER_NONE;
	pf->ptp_tx_en = pf->tstamp_config.tx_type == HWTSTAMP_TX_ON;
	pci_info(pf->pdev, "registered PTP clock\n");
	pf_logd(LOG_PTP_WORK, "%s ptp register, clk rate:%lld\n", __func__,
		hw->clk_ptp_rate);
	return 0;
}

void mce_ptp_unregister(struct mce_pf *pf)
{
	cancel_delayed_work_sync(&pf->tx_hwtstamp_work);
	if (pf->ptp_tx_skb) {
		dev_kfree_skb_any(pf->ptp_tx_skb);
		pf->ptp_tx_skb = NULL;
	}
	clear_bit_unlock(MCE_PTP_TX_IN_PROGRESS, pf->state);
	pf->ptp_tx_en = 0;
	pf->ptp_rx_en = 0;
	pf->flags2 &= ~MCE_FLAG2_PTP_ENABLED;

	if (pf->ptp_clock) {
		ptp_clock_unregister(pf->ptp_clock);
		pf->ptp_clock = NULL;
	}
}

void mce_tx_hwtstamp_work(struct work_struct *work)
{
	struct mce_pf *pf =
		container_of(to_delayed_work(work), struct mce_pf,
			     tx_hwtstamp_work);
	struct mce_hw *hw = &pf->hw;

	/* 1. read port belone timestatmp status reg */
	/* 2. status enabled read nsec and sec reg*/
	/* 3. */
	u64 nanosec = 0, sec = 0;

	if (!pf->ptp_tx_skb) {
		clear_bit_unlock(MCE_PTP_TX_IN_PROGRESS, pf->state);
		return;
	}

	pf_logd(LOG_PTP_WORK, "%s state:%d\n", __func__,
		hw->ops->ptp_tx_state(hw));

	if (hw->ops->ptp_tx_state(hw)) {
		struct skb_shared_hwtstamps shhwtstamps;
		struct sk_buff *skb = pf->ptp_tx_skb;
		u64 txstmp = 0;
		/* read and add nsec, sec turn to nsec*/
		hw->ops->ptp_tx_stamp(hw, &sec, &nanosec);
		/* when we read the timestamp finish need to notice the hardware
		 * that the timestamp need to update via set tx_hwts_clear-reg
		 * from high to low
		 */
		txstmp = nanosec & PTP_HWTX_TIME_VALUE_MASK;
		txstmp += (sec & PTP_HWTX_TIME_VALUE_MASK) * 1000000000ULL;

		/* Clear the global tx_hwtstamp_skb pointer and force writes
		 * prior to notifying the stack of a Tx timestamp.
		 */
		memset(&shhwtstamps, 0, sizeof(shhwtstamps));
		shhwtstamps.hwtstamp = ns_to_ktime(txstmp);
		pf->ptp_tx_skb = NULL;
		/* force write prior to skb_tstamp_tx
		 * because the xmit will re used the point to store ptp skb
		 */
		wmb();

		skb_tstamp_tx(skb, &shhwtstamps);
		dev_consume_skb_any(skb);
		clear_bit_unlock(MCE_PTP_TX_IN_PROGRESS, pf->state);
	} else if (time_after(jiffies,
			      pf->tx_hwtstamp_start +
				      pf->tx_timeout_factor * HZ)) {
		/* this function will mark the skb drop*/
		if (pf->ptp_tx_skb)
			dev_kfree_skb_any(pf->ptp_tx_skb);
		pf->ptp_tx_skb = NULL;
		pf->tx_hwtstamp_timeouts++;
		clear_bit_unlock(MCE_PTP_TX_IN_PROGRESS, pf->state);
		dev_warn(&pf->pdev->dev, "clearing Tx timestamp hang\n");
	} else {
		/* reschedule to check later */
		schedule_delayed_work(&pf->tx_hwtstamp_work, 1);
	}
}

/* get rx hwstamps */
void mce_ptp_get_rx_hwstamp(struct mce_pf *pf, struct mce_rx_desc_up *desc,
			    struct sk_buff *skb)
{
	struct skb_shared_hwtstamps *hwtstamps = NULL;
	u64 tsvalueh = 0, tsvaluel = 0;
	u64 ns = 0;

	if (!skb || !pf->ptp_rx_en) {
		dev_warn(&pf->pdev->dev,
			 "hwstamp skb is null or rx_en iszero %u\n",
			   pf->ptp_rx_en);
		return;
	}

	if (likely(!(desc->cmd & cpu_to_le32(MCE_RXD_STAT_PTP))))
		return;
	hwtstamps = skb_hwtstamps(skb);
	/* because of rx hwstamp store before the mac head
	 * skb->head and skb->data is point to same location when call alloc_skb
	 * so we must move 16 bytes the skb->data to the mac head location
	 * but for the head point if we need move the skb->head need to be diss
	 */
	/* low8bytes is null high8bytes is timestamp
	 * high32bit is seconds low32bits is nanoseconds
	 */
	tsvalueh = le32_to_cpu(desc->timestamp_h_vlan_tag2);
	tsvaluel = le32_to_cpu(desc->timestamp_l);

	ns = tsvaluel & MCE_RX_NSEC_MASK;
	ns += ((tsvalueh & MCE_RX_SEC_MASK) * 1000000000ULL);

	hwtstamps->hwtstamp = ns_to_ktime(ns);
	pf_logd(LOG_PTP_WORK, "%s ns:%lld\n", __func__, ns);
}
