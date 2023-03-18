/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Loongson Corporation
 */

/*
 * Authors:
 *      Sui Jingfeng <suijingfeng@loongson.cn>
 */

#ifndef __LSDC_REGS_H__
#define __LSDC_REGS_H__

#include <linux/bitops.h>
#include <linux/types.h>

/*
 * PIXEL PLL
 */
#define LSDC_PLL_REF_CLK                100000           /* kHz */

/*
 * Those PLL registers are not located at DC reg bar space,
 * there are relative to LSXXXXX_CFG_REG_BASE.
 * XXXXX = 7A1000, 2K1000, 2K0500
 */

/* LS2K1000 */
#define LS2K1000_PIX_PLL0_REG           0x04B0
#define LS2K1000_PIX_PLL1_REG           0x04C0
#define LS2K1000_CFG_REG_BASE           0x1fe10000

/* LS7A1000 */
#define LS7A1000_PIX_PLL0_REG           0x04B0
#define LS7A1000_PIX_PLL1_REG           0x04C0
#define LS7A1000_CFG_REG_BASE           0x10010000

/* LS2K0500 */
#define LS2K0500_PIX_PLL0_REG           0x0418
#define LS2K0500_PIX_PLL1_REG           0x0420
#define LS2K0500_CFG_REG_BASE           0x1fe10000

/*
 *  CRTC CFG REG
 */
#define CFG_PIX_FMT_MASK                GENMASK(2, 0)

enum lsdc_pixel_format {
	LSDC_PF_NONE = 0,
	LSDC_PF_ARGB4444 = 1,  /* ARGB A:4 bits R/G/B: 4 bits each [16 bits] */
	LSDC_PF_ARGB1555 = 2,  /* ARGB A:1 bit RGB:15 bits [16 bits] */
	LSDC_PF_RGB565 = 3,    /* RGB [16 bits] */
	LSDC_PF_XRGB8888 = 4,  /* XRGB [32 bits] */
};

/* Each CRTC has two FB address registers, CFG_FB_IDX_BIT specify
 * which fb address register is currently in using by the CRTC.
 * Setting CFG_PAGE_FLIP_BIT bit will triger the switch. The switch
 * finished at the vblank and if you want switch back you can set
 * CFG_PAGE_FLIP_BIT again.
 */
#define CFG_PAGE_FLIP_BIT               BIT(7)
#define CFG_OUTPUT_EN_BIT               BIT(8)
/* CRTC0 clone from CRTC1 or CRTC1 clone from CRTC0 using hardware logic */
#define CFG_PANEL_SWITCH                BIT(9)
/* Indicate witch fb addr reg is in using, currently */
#define CFG_FB_IDX_BIT                  BIT(11)
#define CFG_GAMMAR_EN_BIT               BIT(12)

/* CRTC get soft reset if voltage level change from 1 -> 0 */
#define CFG_RESET_BIT                   BIT(20)

#define EN_HSYNC_BIT                    BIT(30)
#define INV_HSYNC_BIT                   BIT(31)
#define EN_VSYNC_BIT                    BIT(30)
#define INV_VSYNC_BIT                   BIT(31)

/******** CRTC0 & DVO0 ********/
#define LSDC_CRTC0_CFG_REG              0x1240
#define LSDC_CRTC0_FB0_LO_ADDR_REG      0x1260
#define LSDC_CRTC0_FB0_HI_ADDR_REG      0x15A0
#define LSDC_CRTC0_STRIDE_REG           0x1280
#define LSDC_CRTC0_FB_ORIGIN_REG        0x1300
#define LSDC_CRTC0_HDISPLAY_REG         0x1400
#define LSDC_CRTC0_HSYNC_REG            0x1420
#define LSDC_CRTC0_VDISPLAY_REG         0x1480
#define LSDC_CRTC0_VSYNC_REG            0x14A0
#define LSDC_CRTC0_GAMMA_INDEX_REG      0x14E0
#define LSDC_CRTC0_GAMMA_DATA_REG       0x1500
#define LSDC_CRTC0_FB1_LO_ADDR_REG      0x1580
#define LSDC_CRTC0_FB1_HI_ADDR_REG      0x15C0

/******** CTRC1 & DVO1 ********/
#define LSDC_CRTC1_CFG_REG              0x1250
#define LSDC_CRTC1_FB0_LO_ADDR_REG      0x1270
#define LSDC_CRTC1_FB0_HI_ADDR_REG      0x15B0
#define LSDC_CRTC1_STRIDE_REG           0x1290
#define LSDC_CRTC1_FB_ORIGIN_REG        0x1310
#define LSDC_CRTC1_HDISPLAY_REG         0x1410
#define LSDC_CRTC1_HSYNC_REG            0x1430
#define LSDC_CRTC1_VDISPLAY_REG         0x1490
#define LSDC_CRTC1_VSYNC_REG            0x14B0
#define LSDC_CRTC1_GAMMA_INDEX_REG      0x14F0
#define LSDC_CRTC1_GAMMA_DATA_REG       0x1510
#define LSDC_CRTC1_FB1_LO_ADDR_REG      0x1590
#define LSDC_CRTC1_FB1_HI_ADDR_REG      0x15D0

/*
 * In gross, LSDC_CRTC1_XXX_REG - LSDC_CRTC0_XXX_REG = 0x10, but not all of
 * the registers obey this rule, LSDC_CURSORx_XXX_REG just don't honor this.
 * This is the root cause we can't untangle the code by manpulating offset
 * of the register access simply. Our hardware engineers are lack experiance
 * when they design this...
 */
#define CRTC_PIPE_OFFSET                0x10

/*
 * Hardware cursor
 * There is only one hardware cursor shared by two CRTC in ls7a1000,
 * ls2k1000 and ls2k0500.
 */
#define LSDC_CURSOR0_CFG_REG             0x1520
#define LSDC_CURSOR0_ADDR_REG            0x1530
#define LSDC_CURSOR0_POSITION_REG        0x1540
#define LSDC_CURSOR0_BG_COLOR_REG        0x1550  /* background color */
#define LSDC_CURSOR0_FG_COLOR_REG        0x1560  /* foreground color */

#define LSDC_CURS_MIN_SIZE              1
#define LSDC_CURS_MAX_SIZE              64
#define CURSOR_FORMAT_MASK              GENMASK(1, 0)
#define CURSOR_FORMAT_DISABLE           0
#define CURSOR_FORMAT_MONOCHROME        1
#define CURSOR_FORMAT_ARGB8888          2
#define CURSOR_SIZE_64X64               BIT(2)
#define CURSOR_LOCATION_BIT             BIT(4)

/* LS7A2000 have two hardware cursor */

#define LSDC_CURSOR1_CFG_REG            0x1670
#define LSDC_CURSOR1_ADDR_REG           0x1680
#define LSDC_CURSOR1_POSITION_REG       0x1690
#define LSDC_CURSOR1_BG_COLOR_REG       0x16A0  /* background color */
#define LSDC_CURSOR1_FG_COLOR_REG       0x16B0  /* foreground color */

/*
 * DC Interrupt Control Register, 32bit, Address Offset: 1570
 *
 * Bits  0:10 inidicate the interrupt type, read only
 * Bits 16:26 control if the specific interrupt corresponding to bit 0~10
 * is enabled or not. Write 1 to enable, write 0 to disable
 *
 * RF: Read Finished
 * IDBU : Internal Data Buffer Underflow
 * IDBFU : Internal Data Buffer Fatal Underflow
 *
 *
 * +-------+-------------------------------+-------+--------+--------+-------+
 * | 31:27 |            26:16              | 15:11 |   10   |   9    |   8   |
 * +-------+-------------------------------+-------+--------+--------+-------+
 * |  N/A  | Interrupt Enable Control Bits |  N/A  | IDBFU0 | IDBFU1 | IDBU0 |
 * +-------+-------------------------------+-------+--------+--------+-------+
 *
 * Bit 4 is cursor buffer read finished, no use.
 *
 * +-------+-----+-----+-----+--------+--------+--------+--------+
 * |   7   |  6  |  5  |  4  |   3    |   2    |   1    |   0    |
 * +-------+-----+-----+-----+--------+--------+--------+--------+
 * | IDBU1 | RF0 | RF1 |     | HSYNC0 | VSYNC0 | HSYNC1 | VSYNC1 |
 * +-------+-----+-----+-----+--------+--------+--------+--------+
 *
 */

#define LSDC_INT_REG                           0x1570

#define INT_CRTC0_VS                           BIT(2)
#define INT_CRTC0_HS                           BIT(3)
#define INT_CRTC0_RF                           BIT(6)
#define INT_CRTC0_IDBU                         BIT(8)
#define INT_CRTC0_IDBFU                        BIT(10)

#define INT_CURSOR_RF                          BIT(4)

#define INT_CRTC1_VS                           BIT(0)
#define INT_CRTC1_HS                           BIT(1)
#define INT_CRTC1_RF                           BIT(5)
#define INT_CRTC1_IDBU                         BIT(7)
#define INT_CRTC1_IDBFU                        BIT(9)

#define INT_CRTC0_VS_EN                        BIT(18)
#define INT_CRTC0_HS_EN                        BIT(19)
#define INT_CRTC0_RF_EN                        BIT(22)
#define INT_CRTC0_IDBU_EN                      BIT(24)
#define INT_CRTC0_IDBFU_EN                     BIT(26)

#define INT_CURSOR_RF_EN                       BIT(20)

#define INT_CRTC1_VS_EN                        BIT(16)
#define INT_CRTC1_HS_EN                        BIT(17)
#define INT_CRTC1_RF_EN                        BIT(21)
#define INT_CRTC1_IDBU_EN                      BIT(23)
#define INT_CRTC1_IDBFU_EN                     BIT(25)

#define INT_STATUS_MASK                        GENMASK(10, 0)

/*
 * LS7A1000 have 4 gpios which is under control of the LS7A_DC_GPIO_DAT_REG
 * and LS7A_DC_GPIO_DIR_REG register, it has no relationship whth the general
 * GPIO hardware. Those registers are in the DC register space on LS7A1000.
 *
 * Those GPIOs are used to emulated I2C, for reading edid and monitor detection
 *
 * LS2k1000 and LS2K0500 don't have those registers, they use hardware i2c or
 * generial GPIO emulated i2c from other module.
 *
 * GPIO data register
 *  Address offset: 0x1650
 *   +---------------+-----------+-----------+
 *   | 7 | 6 | 5 | 4 |  3  |  2  |  1  |  0  |
 *   +---------------+-----------+-----------+
 *   |               |    DVO1   |    DVO0   |
 *   +      N/A      +-----------+-----------+
 *   |               | SCL | SDA | SCL | SDA |
 *   +---------------+-----------+-----------+
 */
#define LS7A_DC_GPIO_DAT_REG                   0x1650

/*
 *  GPIO Input/Output direction control register
 *  Address offset: 0x1660
 *  write 1 for Input, 0 for Output.
 */
#define LS7A_DC_GPIO_DIR_REG                   0x1660

/*
 *  LS7A2000 Built-in HDMI Encoder
 */
#define HDMI_EN                 BIT(0)
#define HDMI_PACKET_EN          BIT(1)

#define HDMI0_ZONE_REG          0x1700
#define HDMI1_ZONE_REG          0x1710

#define HDMI0_CTRL_REG          0x1720
#define HDMI1_CTRL_REG          0x1730

#define HDMI_PLL_EN             BIT(0)
#define HDMI_PLL_LOCKED         BIT(16)

#define HDMI0_PHY_CTRL_REG      0x1800
#define HDMI0_PLL_REG           0x1820

#define HDMI1_PHY_CTRL_REG      0x1810
#define HDMI1_PLL_REG           0x1830

#define LS7A2000_DMA_STEP_MASK  GENMASK(17, 16)
#define DMA_STEP_256_BYTE       (0 << 16)
#define DMA_STEP_128_BYTE       (1 << 16)
#define DMA_STEP_64_BYTE        (2 << 16)
#define DMA_STEP_32_BYTE        (3 << 16)

/* LS7A2000/LS2K2000 has hpd status reg, while the two hdmi's status
 * located at the one register again.
 */
#define LSDC_HDMI_HPD_STATUS_REG        0x1BA0
#define HDMI0_HPD_FLAG                  BIT(0)
#define HDMI1_HPD_FLAG                  BIT(1)

#endif
