/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _HISI_CORE_MMC_H
#define _HISI_CORE_MMC_H

struct mmc_card;

#ifdef CONFIG_ASCEND_HISI_MMC

#ifdef CONFIG_MMC_CQ_HCI
extern void mmc_blk_cmdq_dishalt(struct mmc_card *card);
extern int cmdq_is_reset(struct mmc_host *host);
extern int mmc_blk_cmdq_halt(struct mmc_card *card);
#endif

void mmc_decode_ext_csd_emmc50(struct mmc_card *card, u8 *ext_csd);
void mmc_decode_ext_csd_emmc51(struct mmc_card *card, u8 *ext_csd);

void mmc_select_new_sd(struct mmc_card *card);
int mmc_init_card_enable_feature(struct mmc_card *card);
int mmc_suspend_hisi_operation(struct mmc_host *host);
int mmc_card_sleepawake(struct mmc_host *host, int sleep);
int mmc_sd_reset(struct mmc_host *host);

int hisi_mmc_reset(struct mmc_host *host);
#else
static inline void mmc_decode_ext_csd_emmc51(struct mmc_card *card, u8 *ext_csd)
{

}
static inline void mmc_decode_ext_csd_emmc50(struct mmc_card *card, u8 *ext_csd)
{

}
static inline void mmc_select_new_sd(struct mmc_card *card) {}
static inline int mmc_init_card_enable_feature(struct mmc_card *card)
{
	return 0;
}
static inline int mmc_suspend_hisi_operation(struct mmc_host *host)
{
	return 0;
}
static inline int mmc_card_sleepawake(struct mmc_host *host, int sleep)
{
	return 0;
}
static inline int mmc_sd_reset(struct mmc_host *host)
{
	return 0;
}
#endif /* CONFIG_ASCEND_HISI_MMC */
#endif /* _HISI_CORE_MMC_H */
