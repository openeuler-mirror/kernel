/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _DW_MMC_EXTERN_H
#define _DW_MMC_EXTERN_H

#include <linux/device.h>
#include <linux/workqueue.h>
#include <linux/timer.h>

#include "dw_mmc.h"

#ifdef CONFIG_MMC_DW_HI3XXX_MODULE
extern void dw_mci_reg_dump(struct dw_mci *host);
extern void dw_mci_set_timeout(struct dw_mci *host);
extern bool dw_mci_stop_abort_cmd(struct mmc_command *cmd);
extern bool dw_mci_wait_reset(struct device *dev, struct dw_mci *host,
					unsigned int reset_val);
extern void dw_mci_ciu_reset(struct device *dev, struct dw_mci *host);
extern bool dw_mci_fifo_reset(struct device *dev, struct dw_mci *host);
extern u32 dw_mci_prep_stop(struct dw_mci *host, struct mmc_command *cmd);
extern bool dw_mci_wait_data_busy(struct dw_mci *host, struct mmc_request *mrq);
extern int dw_mci_start_signal_voltage_switch(struct mmc_host *mmc,
					struct mmc_ios *ios);
extern void dw_mci_slowdown_clk(struct mmc_host *mmc, int timing);
extern void dw_mci_timeout_timer(struct timer_list *t);
extern void dw_mci_work_routine_card(struct work_struct *work);
extern bool mci_wait_reset(struct device *dev, struct dw_mci *host);
/* only for SD voltage switch on hi3650 FPGA */
extern int gpio_direction_output(unsigned int gpio, int value);

#else

static inline void dw_mci_reg_dump(struct dw_mci *host) {}
static inline void dw_mci_set_timeout(struct dw_mci *host) {}
static inline void dw_mci_timeout_timer(struct timer_list *t) {}
static inline void dw_mci_work_routine_card(struct work_struct *work) {}
static inline void dw_mci_slowdown_clk(struct mmc_host *mmc, int timing) {}
static inline void dw_mci_ciu_reset(struct device *dev, struct dw_mci *host) {}

static inline bool dw_mci_stop_abort_cmd(struct mmc_command *cmd)
{
	return 0;
}
static inline bool dw_mci_wait_reset(struct device *dev, struct dw_mci *host,
					unsigned int reset_val)
{
	return 0;
}
static inline bool dw_mci_fifo_reset(struct device *dev, struct dw_mci *host)
{
	return 0;
}
static inline u32 dw_mci_prep_stop(struct dw_mci *host,
				struct mmc_command *cmd)
{
	return 0;
}
static inline bool dw_mci_wait_data_busy(struct dw_mci *host,
					struct mmc_request *mrq)
{
	return 0;
}
static inline int dw_mci_start_signal_voltage_switch(struct mmc_host *mmc,
					struct mmc_ios *ios)
{
	return 0;
}
static inline bool mci_wait_reset(struct device *dev, struct dw_mci *host)
{
	return 0;
}
int hisi_dw_mci_get_cd(struct mmc_host *mmc);
/* only for SD voltage switch on hi3650 FPGA */
extern int gpio_direction_output(unsigned int gpio, int value);
#endif

#endif
