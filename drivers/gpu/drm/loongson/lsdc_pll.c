// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Loongson Corporation
 */

/*
 * Authors:
 *      Sui Jingfeng <suijingfeng@loongson.cn>
 */

#include "lsdc_drv.h"
#include "lsdc_regs.h"
#include "lsdc_pll.h"

/*
 * The structure of the pixel PLL register is evolved with times.
 * All loongson's cpu is little endian.
 */

/* u64 */
struct ls7a1000_pixpll_bitmap {
	/* Byte 0 ~ Byte 3 */
	unsigned div_out      : 7;   /*  0 : 6     output clock divider  */
	unsigned reserved_1   : 14;  /*  7 : 20                          */
	unsigned loopc        : 9;   /* 21 : 29                          */
	unsigned reserved_2   : 2;   /* 30 : 31                          */

	/* Byte 4 ~ Byte 7 */
	unsigned div_ref      : 7;   /*  0 : 6     input clock divider   */
	unsigned locked       : 1;   /*  7         PLL locked flag       */
	unsigned sel_out      : 1;   /*  8         output clk selector   */
	unsigned reserved_3   : 2;   /*  9 : 10    reserved              */
	unsigned set_param    : 1;   /*  11        set pll param         */
	unsigned bypass       : 1;   /*  12                              */
	unsigned powerdown    : 1;   /*  13                              */
	unsigned reserved_4   : 18;  /*  14 : 31                         */
};

/* u128 */
struct ls2k1000_pixpll_bitmap {
	/* Byte 0 ~ Byte 3 */
	unsigned sel_out      :  1;  /*  0      select this PLL          */
	unsigned reserved_1   :  1;  /*  1                               */
	unsigned sw_adj_en    :  1;  /*  2      allow software adjust    */
	unsigned bypass       :  1;  /*  3      bypass L1 PLL            */
	unsigned reserved_2   :  3;  /*  4:6                             */
	unsigned lock_en      :  1;  /*  7      enable lock L1 PLL       */
	unsigned reserved_3   :  2;  /*  8:9                             */
	unsigned lock_check   :  2;  /* 10:11   precision check          */
	unsigned reserved_4   :  4;  /* 12:15                            */

	unsigned locked       :  1;  /* 16      PLL locked flag bit      */
	unsigned reserved_5   :  2;  /* 17:18                            */
	unsigned powerdown    :  1;  /* 19      powerdown the pll if set */
	unsigned reserved_6   :  6;  /* 20:25                            */
	unsigned div_ref      :  6;  /* 26:31   L1 Prescaler             */

	/* Byte 4 ~ Byte 7 */
	unsigned loopc        : 10;  /* 32:41   Clock Multiplier         */
	unsigned l1_div       :  6;  /* 42:47   not used                 */
	unsigned reserved_7   : 16;  /* 48:63                            */

	/* Byte 8 ~ Byte 15 */
	unsigned div_out      :  6;  /* 0 : 5   output clock divider     */
	unsigned reserved_8   : 26;  /* 6 : 31                           */
	unsigned reserved_9   : 32;  /* 70: 127                          */
};

/* u32 */
struct ls2k0500_pixpll_bitmap {
	/* Byte 0 ~ Byte 1 */
	unsigned sel_out      : 1;
	unsigned reserved_1   : 2;
	unsigned sw_adj_en    : 1;   /* allow software adjust              */
	unsigned bypass       : 1;   /* bypass L1 PLL                      */
	unsigned powerdown    : 1;   /* write 1 to powerdown the PLL       */
	unsigned reserved_2   : 1;
	unsigned locked       : 1;   /*  7     Is L1 PLL locked, read only */
	unsigned div_ref      : 6;   /*  8:13  ref clock divider           */
	unsigned reserved_3   : 2;   /* 14:15                              */
	/* Byte 2 ~ Byte 3 */
	unsigned loopc        : 8;   /* 16:23   Clock Multiplier           */
	unsigned div_out      : 6;   /* 24:29   output clock divider       */
	unsigned reserved_4   : 2;   /* 30:31                              */
};

union lsdc_pixpll_bitmap {
	struct ls7a1000_pixpll_bitmap ls7a2000;
	struct ls7a1000_pixpll_bitmap ls7a1000;
	struct ls2k1000_pixpll_bitmap ls2k1000;
	struct ls2k0500_pixpll_bitmap ls2k0500;

	u32 dword[4];
};

struct pixclk_to_pll_parm {
	/* kHz */
	unsigned int clock;

	/* unrelated information */
	unsigned short width;
	unsigned short height;
	unsigned short vrefresh;

	/* Stores parameters for programming the Hardware PLLs */
	unsigned short div_out;
	unsigned short loopc;
	unsigned short div_ref;
};

/*
 * Pixel clock to PLL parameters translation table.
 * Small static cached value to speed up PLL parameters calculation.
 */
static const struct pixclk_to_pll_parm pll_param_table[] = {
	{148500, 1920, 1080, 60, 11, 49,  3},   /* 1920x1080@60Hz */
						/* 1920x1080@50Hz */
	{174500, 1920, 1080, 75, 17, 89,  3},   /* 1920x1080@75Hz */
	{181250, 2560, 1080, 75,  8, 58,  4},   /* 2560x1080@75Hz */
	{146250, 1680, 1050, 60, 16, 117, 5},   /* 1680x1050@60Hz */
	{135000, 1280, 1024, 75, 10, 54,  4},   /* 1280x1024@75Hz */

	{108000, 1600, 900,  60, 15, 81,  5},   /* 1600x900@60Hz  */
						/* 1280x1024@60Hz */
						/* 1280x960@60Hz */
						/* 1152x864@75Hz */

	{106500, 1440, 900,  60, 19, 81,  4},   /* 1440x900@60Hz */
	{88750,  1440, 900,  60, 16, 71,  5},   /* 1440x900@60Hz */
	{83500,  1280, 800,  60, 17, 71,  5},   /* 1280x800@60Hz */
	{71000,  1280, 800,  60, 20, 71,  5},   /* 1280x800@60Hz */

	{74250,  1280, 720,  60, 22, 49,  3},   /* 1280x720@60Hz */
						/* 1280x720@50Hz */

	{78750,  1024, 768,  75, 16, 63,  5},   /* 1024x768@75Hz */
	{75000,  1024, 768,  70, 29, 87,  4},   /* 1024x768@70Hz */
	{65000,  1024, 768,  60, 20, 39,  3},   /* 1024x768@60Hz */

	{51200,  1024, 600,  60, 25, 64,  5},   /* 1024x600@60Hz */

	{57284,  832,  624,  75, 24, 55,  4},   /* 832x624@75Hz */
	{49500,  800,  600,  75, 40, 99,  5},   /* 800x600@75Hz */
	{50000,  800,  600,  72, 44, 88,  4},   /* 800x600@72Hz */
	{40000,  800,  600,  60, 30, 36,  3},   /* 800x600@60Hz */
	{36000,  800,  600,  56, 50, 72,  4},   /* 800x600@56Hz */
	{31500,  640,  480,  75, 40, 63,  5},   /* 640x480@75Hz */
						/* 640x480@73Hz */

	{30240,  640,  480,  67, 62, 75,  4},   /* 640x480@67Hz */
	{27000,  720,  576,  50, 50, 54,  4},   /* 720x576@60Hz */
	{25175,  640,  480,  60, 85, 107, 5},   /* 640x480@60Hz */
	{25200,  640,  480,  60, 50, 63,  5},   /* 640x480@60Hz */
						/* 720x480@60Hz */
};

/**
 * lsdc_pixpll_setup - ioremap the device dependent PLL registers
 *
 * @this: point to the object which this function is called from
 */
static int lsdc_pixpll_setup(struct lsdc_pll * const this)
{
	this->mmio = ioremap(this->reg_base, this->reg_size);

	return 0;
}

/*
 * Find a set of pll parameters (to generate pixel clock) from a static
 * local table, which avoid to compute the pll parameter eachtime a
 * modeset is triggered.
 *
 * @this: point to the object which this function is called from
 * @clock: the desired output pixel clock, the unit is kHz
 * @pout: point to where the parameters to store if found
 *
 *  Return true if hit, otherwise return false.
 */
static bool lsdc_pixpll_find(struct lsdc_pll * const this,
			     unsigned int clock,
			     struct lsdc_pll_core_values * const pout)
{
	unsigned int num = ARRAY_SIZE(pll_param_table);
	unsigned int i;

	for (i = 0; i < num; i++) {
		if (clock != pll_param_table[i].clock)
			continue;

		pout->div_ref = pll_param_table[i].div_ref;
		pout->loopc   = pll_param_table[i].loopc;
		pout->div_out = pll_param_table[i].div_out;

		return true;
	}

	drm_dbg(this->ddev, "pixel clock %u: miss\n", clock);

	return false;
}

/*
 * Find a set of pll parameters which have minimal difference with the desired
 * pixel clock frequency. It does that by computing all of the possible
 * combination. Compute the diff and find the combination with minimal diff.
 *
 *  clock_out = refclk / div_ref * loopc / div_out
 *
 *  refclk is fixed as 100MHz in ls7a1000, ls2k1000 and ls2k0500
 *
 * @this: point to the object from which this function is called
 * @clk: the desired output pixel clock, the unit is kHz
 * @pout: point to where the parameters to store if success
 *
 *  Return true if a parameter is found, otherwise return false
 */
static bool lsdc_pixpll_compute(struct lsdc_pll * const this,
				unsigned int clk,
				struct lsdc_pll_core_values *pout)
{
	unsigned int refclk = this->ref_clock;
	const unsigned int tolerance = 1000;
	unsigned int min = tolerance;
	unsigned int div_out, loopc, div_ref;

	if (lsdc_pixpll_find(this, clk, pout))
		return true;

	for (div_out = 6; div_out < 64; div_out++) {
		for (div_ref = 3; div_ref < 6; div_ref++) {
			for (loopc = 6; loopc < 161; loopc++) {
				int diff;

				if (loopc < 12 * div_ref)
					continue;
				if (loopc > 32 * div_ref)
					continue;

				diff = clk * div_out - refclk * loopc / div_ref;

				if (diff < 0)
					diff = -diff;

				if (diff < min) {
					min = diff;
					pout->div_ref = div_ref;
					pout->div_out = div_out;
					pout->loopc = loopc;

					if (diff == 0)
						return true;
				}
			}
		}
	}

	return min < tolerance;
}

/*
 * Update the pll parameters to hardware, target to the pixpll in ls7a1000
 *
 * @this: point to the object from which this function is called
 * @param: point to the core parameters passed in
 *
 * return 0 if successful.
 */
static int ls7a1000_pixpll_param_update(struct lsdc_pll * const this,
					struct lsdc_pll_core_values const *param)
{
	void __iomem *reg = this->mmio;
	unsigned int counter = 0;
	bool locked;
	u32 val;

	/* Bypass the software configured PLL, using refclk directly */
	val = readl(reg + 0x4);
	val &= ~(1 << 8);
	writel(val, reg + 0x4);

	/* Powerdown the PLL */
	val = readl(reg + 0x4);
	val |= (1 << 13);
	writel(val, reg + 0x4);

	/* Clear the pll parameters */
	val = readl(reg + 0x4);
	val &= ~(1 << 11);
	writel(val, reg + 0x4);

	/* clear old value & config new value */
	val = readl(reg + 0x04);
	val &= ~0x7F;
	val |= param->div_ref;        /* div_ref */
	writel(val, reg + 0x4);

	val = readl(reg);
	val &= ~0x7f;
	val |= param->div_out;        /* div_out */

	val &= ~(0x1ff << 21);
	val |= param->loopc << 21;    /* loopc */
	writel(val, reg);

	/* Set the pll the parameters */
	val = readl(reg + 0x4);
	val |= (1 << 11);
	writel(val, reg + 0x4);

	/* Powerup the PLL */
	val = readl(reg + 0x4);
	val &= ~(1 << 13);
	writel(val, reg + 0x4);

	/* Wait the PLL lock */
	do {
		val = readl(reg + 0x4);
		locked = val & 0x80;
		counter++;
	} while (!locked && (counter < 10000));

	drm_dbg(this->ddev, "%u loop waited\n", counter);

	/* Switch to the software configured pll */
	val = readl(reg + 0x4);
	val |= (1UL << 8);
	writel(val, reg + 0x4);

	return 0;
}

/*
 * Update the pll parameters to hardware, target to the pixpll in ls2k1000
 *
 * @this: point to the object from which this function is called
 * @param: pointer to where the parameter is passed in
 *
 * return 0 if successful.
 */
static int ls2k1000_pixpll_param_update(struct lsdc_pll * const this,
					struct lsdc_pll_core_values const *param)
{
	void __iomem *reg = this->mmio;
	unsigned int counter = 0;
	bool locked = false;
	u32 val;

	val = readl(reg);
	/* Bypass the software configured PLL, using refclk directly */
	val &= ~(1 << 0);
	writel(val, reg);

	/* Powerdown the PLL */
	val |= (1 << 19);
	writel(val, reg);

	/* Allow the software configuration */
	val &= ~(1 << 2);
	writel(val, reg);

	/* allow L1 PLL lock */
	val = (1L << 7) | (3L << 10);
	writel(val, reg);

	/* clear div_ref bit field */
	val &= ~(0x3f << 26);
	/* set div_ref bit field */
	val = val | (param->div_ref << 26);
	writel(val, reg);

	val = readl(reg + 4);
	/* clear loopc bit field */
	val &= ~0x0fff;
	/* set loopc bit field */
	val |= param->loopc;
	writel(val, reg + 4);

	/* set div_out */
	writel(param->div_out, reg + 8);

	val = readl(reg);
	/* use the software configure param */
	val |= (1 << 2);
	/* powerup the PLL */
	val &= ~(1 << 19);
	writel(val, reg);

	/* wait pll setup and locked */
	do {
		val = readl(reg);
		locked = val & 0x10000;
		counter++;
	} while (!locked && (counter < 10000));

	drm_dbg(this->ddev, "%u loop waited\n", counter);

	/* Switch to the above software configured PLL instead of refclk */
	val |= 1;
	writel(val, reg);

	return 0;
}

/*
 * Update the pll parameters to hardware, target to the pixpll in ls2k0500
 *
 * @this: point to the object which calling this function
 * @param: pointer to where the parameters passed in
 *
 * return 0 if successful.
 */
static int ls2k0500_pixpll_param_update(struct lsdc_pll * const this,
					struct lsdc_pll_core_values const *param)
{
	void __iomem *reg = this->mmio;
	unsigned int counter = 0;
	bool locked = false;
	u32 val;

	/* Bypass the software configured PLL, using refclk directly */
	val = readl(reg);
	val &= ~(1 << 0);
	writel(val, reg);

	/* Powerdown the PLL */
	val = readl(reg);
	val |= (1 << 5);
	writel(val, reg);

	/* Allow the software configuration */
	val |= (1 << 3);
	writel(val, reg);

	/* Update the pll params */
	val = (param->div_out << 24) |
	      (param->loopc << 16) |
	      (param->div_ref << 8);

	writel(val, reg);

	/* Powerup the PLL */
	val = readl(reg);
	val &= ~(1 << 5);
	writel(val, reg);

	/* wait pll setup and locked */
	do {
		val = readl(reg);
		locked = val & 0x80;
		counter++;
	} while (!locked && (counter < 10000));

	drm_dbg(this->ddev, "%u loop waited\n", counter);

	/* Switch to the above software configured PLL instead of refclk */
	writel((val | 1), reg);

	return 0;
}

static unsigned int lsdc_get_clock_rate(struct lsdc_pll * const this,
					struct lsdc_pll_core_values *pout)
{
	struct drm_device *ddev = this->ddev;
	struct lsdc_device *ldev = to_lsdc(ddev);
	const struct lsdc_chip_desc * const desc = ldev->desc;
	unsigned int out;
	union lsdc_pixpll_bitmap parms;

	if (desc->chip == LSDC_CHIP_7A2000) {
		struct ls7a1000_pixpll_bitmap *obj = &parms.ls7a2000;

		parms.dword[0] = readl(this->mmio);
		parms.dword[1] = readl(this->mmio + 4);
		out = this->ref_clock / obj->div_ref * obj->loopc / obj->div_out;
		if (pout) {
			pout->div_ref = obj->div_ref;
			pout->loopc = obj->loopc;
			pout->div_out = obj->div_out;
		}
	} else if (desc->chip == LSDC_CHIP_7A1000) {
		struct ls7a1000_pixpll_bitmap *obj = &parms.ls7a1000;

		parms.dword[0] = readl(this->mmio);
		parms.dword[1] = readl(this->mmio + 4);
		out = this->ref_clock / obj->div_ref * obj->loopc / obj->div_out;
		if (pout) {
			pout->div_ref = obj->div_ref;
			pout->loopc = obj->loopc;
			pout->div_out = obj->div_out;
		}
	} else if (desc->chip == LSDC_CHIP_2K1000) {
		struct ls2k1000_pixpll_bitmap *obj = &parms.ls2k1000;

		parms.dword[0] = readl(this->mmio);
		parms.dword[1] = readl(this->mmio + 4);
		parms.dword[2] = readl(this->mmio + 8);
		parms.dword[3] = readl(this->mmio + 12);
		out = this->ref_clock / obj->div_ref * obj->loopc / obj->div_out;
		if (pout) {
			pout->div_ref = obj->div_ref;
			pout->loopc = obj->loopc;
			pout->div_out = obj->div_out;
		}
	} else if (desc->chip == LSDC_CHIP_2K0500) {
		struct ls2k0500_pixpll_bitmap *obj = &parms.ls2k0500;

		parms.dword[0] = readl(this->mmio);
		out = this->ref_clock / obj->div_ref * obj->loopc / obj->div_out;
		if (pout) {
			pout->div_ref = obj->div_ref;
			pout->loopc = obj->loopc;
			pout->div_out = obj->div_out;
		}
	} else {
		drm_err(ddev, "unknown chip, the driver need update\n");
		return 0;
	}

	return out;
}

static const struct lsdc_pixpll_funcs ls7a2000_pixpll_funcs = {
	.setup = lsdc_pixpll_setup,
	.compute = lsdc_pixpll_compute,
	.update = ls7a1000_pixpll_param_update,
	.get_clock_rate = lsdc_get_clock_rate,
};

static const struct lsdc_pixpll_funcs ls7a1000_pixpll_funcs = {
	.setup = lsdc_pixpll_setup,
	.compute = lsdc_pixpll_compute,
	.update = ls7a1000_pixpll_param_update,
	.get_clock_rate = lsdc_get_clock_rate,
};

static const struct lsdc_pixpll_funcs ls2k1000_pixpll_funcs = {
	.setup = lsdc_pixpll_setup,
	.compute = lsdc_pixpll_compute,
	.update = ls2k1000_pixpll_param_update,
	.get_clock_rate = lsdc_get_clock_rate,
};

static const struct lsdc_pixpll_funcs ls2k0500_pixpll_funcs = {
	.setup = lsdc_pixpll_setup,
	.compute = lsdc_pixpll_compute,
	.update = ls2k0500_pixpll_param_update,
	.get_clock_rate = lsdc_get_clock_rate,
};

int lsdc_pixpll_init(struct lsdc_pll * const this,
		     struct drm_device *ddev,
		     unsigned int index)
{
	struct lsdc_device *ldev = to_lsdc(ddev);
	const struct lsdc_chip_desc * const descp = ldev->desc;

	this->ddev = ddev;
	this->index = index;
	this->ref_clock = LSDC_PLL_REF_CLK;

	if (descp->chip == LSDC_CHIP_7A2000) {
		if (index == 0)
			this->reg_base = LS7A1000_CFG_REG_BASE + LS7A1000_PIX_PLL0_REG;
		else if (index == 1)
			this->reg_base = LS7A1000_CFG_REG_BASE + LS7A1000_PIX_PLL1_REG;
		this->reg_size = 8;
		this->funcs = &ls7a2000_pixpll_funcs;
	} else if (descp->chip == LSDC_CHIP_7A1000) {
		if (index == 0)
			this->reg_base = LS7A1000_CFG_REG_BASE + LS7A1000_PIX_PLL0_REG;
		else if (index == 1)
			this->reg_base = LS7A1000_CFG_REG_BASE + LS7A1000_PIX_PLL1_REG;
		this->reg_size = 8;
		this->funcs = &ls7a1000_pixpll_funcs;
	} else if (descp->chip == LSDC_CHIP_2K1000) {
		if (index == 0)
			this->reg_base = LS2K1000_CFG_REG_BASE + LS2K1000_PIX_PLL0_REG;
		else if (index == 1)
			this->reg_base = LS2K1000_CFG_REG_BASE + LS2K1000_PIX_PLL1_REG;

		this->reg_size = 16;
		this->funcs = &ls2k1000_pixpll_funcs;
	} else if (descp->chip == LSDC_CHIP_2K0500) {
		if (index == 0)
			this->reg_base = LS2K0500_CFG_REG_BASE + LS2K0500_PIX_PLL0_REG;
		else if (index == 1)
			this->reg_base = LS2K0500_CFG_REG_BASE + LS2K0500_PIX_PLL1_REG;

		this->reg_size = 4;
		this->funcs = &ls2k0500_pixpll_funcs;
	} else {
		drm_err(this->ddev, "unknown chip, the driver need update\n");
		return -ENOENT;
	}

	return this->funcs->setup(this);
}
