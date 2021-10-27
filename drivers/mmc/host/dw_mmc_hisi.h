/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _DW_MMC_HISI_
#define _DW_MMC_HISI_
#include <linux/pinctrl/consumer.h>
#include <linux/workqueue.h>
#include <linux/of_address.h>
#include <asm/cacheflush.h>
#include <linux/pm_runtime.h>

#ifdef CONFIG_MMC_HISI_TRACE
#include <linux/hisi/mmc_trace.h>
#endif
#include <linux/version.h>

#define SDMMC_UHS_REG_EXT	0x108
#define SDMMC_ENABLE_SHIFT	0x110

#define SDMMC_64_BIT_DMA		1
#define SDMMC_32_BIT_DMA		0

#define SDMMC_CMD_ONLY_CLK		(SDMMC_CMD_START | SDMMC_CMD_UPD_CLK | \
						SDMMC_CMD_PRV_DAT_WAIT)

#define CTRL_RESET	(0x1 << 0) /* Reset DWC_mobile_storage controller */
#define FIFO_RESET	(0x1 << 1) /* Reset FIFO */
#define DMA_RESET	(0x1 << 2) /* Reset DMA interface */
#define INT_ENABLE	(0x1 << 4) /* Global interrupt enable/disable bit */
#define DMA_ENABLE	(0x1 << 5) /* DMA transfer mode enable/disable bit */
#define ENABLE_IDMAC	(0x1 << 25)


#define INTMSK_ALL	0xFFFFFFFF
#define INTMSK_CDETECT	(0x1 << 0)
#define INTMSK_RE	(0x1 << 1)
#define INTMSK_CDONE	(0x1 << 2)
#define INTMSK_DTO	(0x1 << 3)
#define INTMSK_TXDR	(0x1 << 4)
#define INTMSK_RXDR	(0x1 << 5)
#define INTMSK_RCRC	(0x1 << 6)
#define INTMSK_DCRC	(0x1 << 7)
#define INTMSK_RTO	(0x1 << 8)
#define INTMSK_DRTO	(0x1 << 9)
#define INTMSK_HTO	(0x1 << 10)
#define INTMSK_VOLT_SWITCH	(0x1 << 10)
#define INTMSK_FRUN	(0x1 << 11)
#define INTMSK_HLE	(0x1 << 12)
#define INTMSK_SBE	(0x1 << 13)
#define INTMSK_ACD	(0x1 << 14)
#define INTMSK_EBE	(0x1 << 15)
#define INTMSK_DMA	(INTMSK_ACD | INTMSK_RXDR | INTMSK_TXDR)

#define INT_SRC_IDMAC	(0x0)
#define INT_SRC_MINT	(0x1)


#define CMD_RESP_EXP_BIT	(0x1 << 6)
#define CMD_RESP_LENGTH_BIT	(0x1 << 7)
#define CMD_CHECK_CRC_BIT	(0x1 << 8)
#define CMD_DATA_EXP_BIT	(0x1 << 9)
#define CMD_RW_BIT		(0x1 << 10)
#define CMD_TRANSMODE_BIT	(0x1 << 11)
#define CMD_WAIT_PRV_DAT_BIT	(0x1 << 13)
#define CMD_STOP_ABORT_CMD	(0x1 << 14)
#define CMD_SEND_INITIALIZATION	(0x1 << 15)
#define CMD_SEND_CLK_ONLY	(0x1 << 21)
#define CMD_VOLT_SWITCH     (0x1 << 28)
#define CMD_USE_HOLD_REG    (0x1 << 29)
#define CMD_STRT_BIT		(0x1 << 31)
#define CMD_ONLY_CLK		(CMD_STRT_BIT | CMD_SEND_CLK_ONLY | \
						CMD_WAIT_PRV_DAT_BIT)

#define CLK_ENABLE	(0x1 << 0)
#define CLK_DISABLE	(0x0 << 0)

#define BOARDTYPE_SFT  (1)

#define STATE_KEEP_PWR		(1)
#define STATE_LEGACY		(0)

/* BEGIN PN: , Modified by , 2014/06/11 */
#define SD_SLOT_VOL_OPEN 1
#define SD_SLOT_VOL_CLOSE 0
/* END PN: , Modified by , 2014/06/11 */

#define SDMMC_ASIC_PLATFORM  (-1)
#define SDMMC_FPGA_PLATFORM  (0x5a5a5a5a)

#define PLL5_EMMC_DIV_MAX  16
#define PLL5_CLK_FREQ_MAX  1600000000
#define PLL5_CLK_DEFAULT_FREQ  3200000


#define DW_MCI_DESC_SZ 1
#define DW_MCI_DESC_SZ_64BIT 2

#define DRIVER_NAME "dwmmc_hs"

#define DW_MCI_EMMC_ID    (0x00)
#define DW_MCI_SD_ID      (0x01)
#define DW_MCI_SDIO_ID    (0x02)

#define EMMC_BUS_WIDTH_8_BIT    0x08
#define EMMC_BUS_WIDTH_4_BIT    0x04
#define EMMC_BUS_WIDTH_1_BIT    0x01

#define HIXX51_EMMC_CLK_SEL_PLL_OFF 0xffffff0f
#define HIXX51_EMMC_CLK_SEL_PLL_VAL 0x00000010
#define HIXX51_EMMC_CLK_SEL_PLL_L_S 0x4
/* davinci mmc reset reg */
#define HIXX51_PERI_SC_EMMC_RST_REQ        (0xa30) //controller soft reset
#define HIXX51_PERI_SC_EMMC_RST_DREQ       (0xa34) //controller soft disreset
#define HIXX51_PERI_SC_EMMC_ICG_EN         (0x398) //clock enable
#define HIXX51_PERI_SC_EMMC_ICG_DIS        (0x39c) //clock disable
#define HIXX51_PERI_SC_EMMC_CLK_SEL        (0x104) // input clock select
#define HIXX51_SC_USER1_EMMC               (0x2204) //eMMC user area configre
#define HIXX51_SC_AXI_EMMC                 (0x2210) //usb axi area configre
#define HIXX51_SC_BIAS_CTRL                (0x3780)
#define HIXX51_SC_PLL_PROF_CFG0            (0x3688)

#define HIXX10_PERI_SC_EMMC_RST_REQ        (0xcb0)
#define HIXX10_PERI_SC_EMMC_RST_DREQ       (0xcb4)
#define HIXX10_PERI_SC_EMMC_ICG_EN         (0x5c0)
#define HIXX10_PERI_SC_EMMC_ICG_DIS        (0x5c4)
#define HIXX10_PERI_SC_EMMC_CLK_SEL        (0x3500)
#define HIXX10_SC_BIAS_CTRL                (0x3780)
#define HIXX10_SC_PLL_PROF_CFG0            (0x3688)

#define PERI_CRG_CLKDIV4  (0xb8)
#define PERI_CRG_CLKDIV6  (0xc0)

enum {
	PERI_SC_EMMC_RST_REQ = 0,
	PERI_SC_EMMC_RST_DREQ,
	PERI_SC_EMMC_ICG_EN,
	PERI_SC_EMMC_ICG_DIS,
	PERI_SC_EMMC_CLK_SEL,
	SC_BIAS_CTRL,
	SC_PLL_PROF_CFG0,
	SC_USER1_EMMC,
	SC_AXI_EMMC,
	REG_MAX_NUM,
};

enum {
	CHIP_HIXX10 = 0,
	CHIP_HIXX51,
	CHIP_TYPE_MAX_NUM,
};

/* mmc1 sys ctrl, start from kirin980 */
#define MMC1_SYSCTRL_PEREN0		(0x300)
#define MMC1_SYSCTRL_PERDIS0		(0x304)
#define MMC1_SYSCTRL_PERCLKEN0		(0x308)
#define MMC1_SYSCTRL_PERSTAT0		(0x30C)
#define GT_HCLK_SDIO1_BIT	(0x1)

#define MMC1_SYSCTRL_PERRSTEN0		(0x310)
#define MMC1_SYSCTRL_PERRSTDIS0		(0x314)
#define MMC1_SYSCTRL_PERRSTSTAT0	(0x318)
#define  BIT_HRST_SDIO_ATLANTA	(0x1)
#define  BIT_RST_SDIO_ATLANTA	(0x1 << 1)
/* mmc1 sys ctrl end*/

#define HI3660_FPGA 1
#define PERI_CRG_PERSTAT4 (0x04c)

#define GTCLK_SD_EN (0x20000)

#define BIT_VOLT_OFFSET         (0x314)
#define BIT_VOLT_OFFSET_AUSTIN  (0x214)
#define BIT_VOLT_VALUE_18       (0x4)

#define BIT_RST_EMMC            (1<<0)
#define BIT_RST_SD              (1<<0)
#define BIT_RST_SDIO            (1<<0)

#define BIT_RST_SDIO_CHICAGO    (1<<20)
#define BIT_RST_SDIO_BOSTON    (1<<20)

#define GPIO_CLK_DIV(x) (((x) & 0xf) << 8)
#define GPIO_USE_SAMPLE_DLY(x) (((x) & 0x1) << 13)

#define GPIO_CLK_ENABLE (0x1 << 16)
#define UHS_REG_EXT_SAMPLE_PHASE(x) (((x) & 0x1f) << 16)
#define UHS_REG_EXT_SAMPLE_DLY(x) (((x) & 0x1f) << 26)
#define UHS_REG_EXT_SAMPLE_DRVPHASE(x) (((x) & 0x1f) << 21)
#define SDMMC_UHS_REG_EXT_VALUE(x, y, z)       \
		(UHS_REG_EXT_SAMPLE_PHASE(x) | \
		UHS_REG_EXT_SAMPLE_DLY(y) | UHS_REG_EXT_SAMPLE_DRVPHASE(z))
#define SDMMC_GPIO_VALUE(x, y)                                              \
		(GPIO_CLK_DIV(x) | GPIO_USE_SAMPLE_DLY(y))

/*Reduce Max tuning loop,200 loops may case the watch dog timeout*/
#define MAX_TUNING_LOOP 32

struct dw_mci_hs_priv_data {
	int				id;
	int				old_timing;
	int				gpio_cd;
	int				gpio_sw;
	int				sw_value;
	int				old_signal_voltage;
	int				old_power_mode;
	unsigned int		priv_bus_hz;
	unsigned int		cd_vol;
/* BEGIN PN: , Modified by , 2014/06/11 */
	unsigned int sd_slot_ldo10_status;
/* END PN: , Modified by , 2014/06/11 */
	int				dw_mmc_bus_clk;
	int				dw_voltage_switch_gpio;
	int				chip_platform;
	u32				chip_type;
	int				hi3660_sd_ioset_sd_sel;
	int				hi3660_sd_ioset_jtag_sd_sel;
	int				hi3660_fpga_sd_ioset;
	int				cs;
	int				in_resume;
	void __iomem *ao_sysctrl;
	void __iomem *peri_sysctrl;
	void __iomem *ioc_off;
};

struct dw_mci_tuning_data {
	const u8 *blk_pattern;
	unsigned int blksz;
};

#ifdef CONFIG_MMC_DW_IDMAC
#define IDMAC_INT_CLR		(SDMMC_IDMAC_INT_AI | SDMMC_IDMAC_INT_NI | \
				 SDMMC_IDMAC_INT_CES | SDMMC_IDMAC_INT_DU | \
				 SDMMC_IDMAC_INT_FBE | SDMMC_IDMAC_INT_RI | \
				 SDMMC_IDMAC_INT_TI)
#endif
enum himntnEnum {
	HIMNTN_NVE_VALID = 0,
	HIMNTN_WDT_MIN,
	HIMNTN_AP_WDT = HIMNTN_WDT_MIN,
	HIMNTN_GLOBAL_WDT,
	HIMNTN_MODEM_WDT,
	HIMNTN_LPM3_WDT,
	HIMNTN_IOM3_WDT,
	HIMNTN_HIFI_WDT,
	HIMNTN_SECOS_WDT,
	HIMNTN_ISP_WDT,
	HIMNTN_IVP_WDT,
	HIMNTN_OCBC_WDT = 10,
	HIMNTN_UCE_WDT,
	HIMNTN_RESERVED_WDT3,
	HIMNTN_WDT_MAX = HIMNTN_RESERVED_WDT3,
	HIMNTN_FST_DUMP_MEM,
	HIMNTN_MNTN_DUMP_MEM,
	HIMNTN_SD2JTAG,
	HIMNTN_PRESS_KEY_TO_FASTBOOT,
	HIMNTN_PANIC_INTO_LOOP,
	HIMNTN_GOBAL_RESETLOG,
	HIMNTN_NOC_INT_HAPPEN,
	HIMNTN_NOC_ERROR_REBOOT = 20,
	HIMNTN_DFXPARTITION_TO_FILE,
	HIMNTN_DDR_ERROR_REBOOT,
	HIMNTN_HISEE,
	HIMNTN_WATCHPOINT_EN,
	HIMNTN_KMEMLEAK_SWITCH,
	HIMNTN_FB_PANIC_REBOOT,
	HIMNTN_MEM_TRACE = 27, /*Bit:27: Memory Trace hook switch.*/
	HIMNTN_FTRACE,
	HIMNTN_EAGLE_EYE,
	/*Hook switch is the same one of kdump.*/
	HIMNTN_KERNEL_DUMP_ENABLE = 30,
	HIMNTN_SD2DJTAG,
	HIMNTN_MMC_TRACE,
	HIMNTN_LPM3_PANIC_INTO_LOOP,
	HIMNTN_TRACE_CLK_REGULATOR,
	HIMNTN_CORESIGHT,
	HIMNTN_DMSSPT,
	HIMNTN_HHEE,
	HIMNTN_KASLR,
	HIMNTN_SD2UART6,
	/*Add above, and keep the same as*/
	/*definition in reboot_reason.h in fastboot !!!!*/
	HIMNTN_BOTTOM
};

enum {
	MEM_EMMC_IOBASE,
	MEM_PERI_SUBCTRL_IOBASE,
	MEM_SYSCTRL_IOBASE,
	MEM_GPIO_IOBASE,
	MEM_IOBASE_MAX,
};

#endif /* _DW_MMC_HISI_ */
