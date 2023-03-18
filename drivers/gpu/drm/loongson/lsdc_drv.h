/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Loongson Corporation
 */

/*
 * Authors:
 *      Sui Jingfeng <suijingfeng@loongson.cn>
 */

#ifndef __LSDC_DRV_H__
#define __LSDC_DRV_H__

#include <drm/drm_print.h>
#include <drm/drm_device.h>
#include <drm/drm_crtc.h>
#include <drm/drm_plane.h>
#include <drm/drm_connector.h>
#include <drm/drm_encoder.h>
#include <drm/drm_drv.h>
#include <drm/drm_atomic.h>

#include "lsdc_pll.h"
#include "lsdc_regs.h"

#define DRIVER_AUTHOR		"Sui Jingfeng <suijingfeng@loongson.cn>"
#define DRIVER_NAME		"lsdc"
#define DRIVER_DESC		"drm driver for loongson's display controller"
#define DRIVER_DATE		"20200701"
#define DRIVER_MAJOR		1
#define DRIVER_MINOR		0
#define DRIVER_PATCHLEVEL	0

#define LSDC_NUM_CRTC           2

enum loongson_dc_family {
	LSDC_CHIP_UNKNOWN = 0,
	LSDC_CHIP_2K1000 = 1,  /* 2-Core Mips64r2 compatible SoC */
	LSDC_CHIP_7A1000 = 2,  /* North bridge of LS3A3000/LS3A4000/LS3A5000 */
	LSDC_CHIP_2K0500 = 3,  /* Single core, reduced version of LS2K1000 */
	LSDC_CHIP_7A2000 = 4,  /* Enhancement version of LS7a1000 */
	LSDC_CHIP_LAST,
};

struct lsdc_chip_desc {
	enum loongson_dc_family chip;
	u32 num_of_crtc;
	u32 max_pixel_clk;
	u32 max_width;
	u32 max_height;
	u32 num_of_hw_cursor;
	u32 hw_cursor_w;
	u32 hw_cursor_h;
	/* DMA alignment constraint (must be multiple of 256 bytes) */
	u32 stride_alignment;
	bool has_builtin_i2c;
	bool has_vram;
	bool broken_gamma;
};

/*
 * struct lsdc_display_pipe - Abstraction of hardware display pipeline.
 * @crtc: CRTC control structure
 * @plane: Plane control structure
 * @encoder: Encoder control structure
 * @pixpll: Pll control structure
 * @connector: point to connector control structure this display pipe bind
 * @index: the index corresponding to the hardware display pipe
 * @available: is this display pipe is available on the motherboard, The
 *  downstream mother board manufacturer may use only one of them.
 *  For example, LEMOTE LX-6901 board just has only one VGA output.
 *
 * Display pipeline with planes, crtc, pll and output collapsed into one entity.
 */
struct lsdc_display_pipe {
	struct drm_crtc crtc;
	struct drm_plane primary;
	struct drm_plane cursor;
	struct lsdc_pll pixpll;
	struct drm_encoder encoder;
	struct drm_connector connector;
	struct lsdc_i2c *li2c;
	int index;
	bool available;
};

static inline struct lsdc_display_pipe *
crtc_to_display_pipe(struct drm_crtc *crtc)
{
	return container_of(crtc, struct lsdc_display_pipe, crtc);
}

static inline struct lsdc_display_pipe *
primary_to_display_pipe(struct drm_plane *plane)
{
	return container_of(plane, struct lsdc_display_pipe, primary);
}

static inline struct lsdc_display_pipe *
cursor_to_display_pipe(struct drm_plane *plane)
{
	return container_of(plane, struct lsdc_display_pipe, cursor);
}

static inline struct lsdc_display_pipe *
connector_to_display_pipe(struct drm_connector *connector)
{
	return container_of(connector, struct lsdc_display_pipe, connector);
}

static inline struct lsdc_display_pipe *
encoder_to_display_pipe(struct drm_encoder *encoder)
{
	return container_of(encoder, struct lsdc_display_pipe, encoder);
}

struct lsdc_crtc_state {
	struct drm_crtc_state base;
	struct lsdc_pll_core_values pparams;
};

struct lsdc_device {
	struct drm_device ddev;
	/* @desc: device dependent data and feature descriptions */
	const struct lsdc_chip_desc *desc;

	/* LS7A1000/LS7A2000 has a dediacted video RAM */
	void __iomem *reg_base;
	void __iomem *vram;
	resource_size_t vram_base;
	resource_size_t vram_size;

	struct lsdc_display_pipe dispipe[LSDC_NUM_CRTC];

	/* @reglock: protects concurrent register access */
	spinlock_t reglock;

	/*
	 * @num_output: count the number of active display pipe.
	 */
	unsigned int num_output;

	int irq;
	u32 irq_status;

	/*
	 * @use_vram_helper: using vram helper base solution instead of
	 * CMA helper based solution. The DC scanout from the VRAM is
	 * proved to be more reliable, but graphic application is may
	 * become slow when using this driver mode.
	 */
	bool use_vram_helper;
	/*
	 * @enable_gamma: control whether hardware gamma support should be
	 * enabled or not. It is broken though, but you can know that only
	 * when you can enable it.
	 */
	bool enable_gamma;
	/* @relax_alignment: for 800x480, 1366x768 resulotion support */
	bool relax_alignment;
	/* @has_dt: true if there are DT support*/
	bool has_dt;
	/* @has_ports_node: true if there are OF graph in the DT */
	bool has_ports_node;
};

static inline struct lsdc_device *to_lsdc(struct drm_device *ddev)
{
	return container_of(ddev, struct lsdc_device, ddev);
}

static inline struct lsdc_crtc_state *
to_lsdc_crtc_state(struct drm_crtc_state *base)
{
	return container_of(base, struct lsdc_crtc_state, base);
}

int lsdc_crtc_init(struct drm_device *ddev,
		   struct drm_crtc *crtc,
		   unsigned int index,
		   struct drm_plane *primary,
		   struct drm_plane *cursor);

int lsdc_plane_init(struct lsdc_device *ldev, struct drm_plane *plane,
		    enum drm_plane_type type, unsigned int index);

const struct lsdc_chip_desc *
lsdc_detect_chip(struct pci_dev *pdev, const struct pci_device_id * const ent);

extern struct platform_driver lsdc_platform_driver;

static inline u32 lsdc_rreg32(struct lsdc_device *ldev, u32 offset)
{
	return readl(ldev->reg_base + offset);
}

static inline void lsdc_wreg32(struct lsdc_device *ldev, u32 offset, u32 val)
{
	writel(val, ldev->reg_base + offset);
}

static inline void lsdc_ureg32_set(struct lsdc_device *ldev,
				   u32 offset,
				   u32 bit)
{
	void __iomem *addr = ldev->reg_base + offset;
	u32 val = readl(addr);

	writel(val | bit, addr);
}

static inline void lsdc_ureg32_clr(struct lsdc_device *ldev,
				   u32 offset,
				   u32 bit)
{
	void __iomem *addr = ldev->reg_base + offset;
	u32 val = readl(addr);

	writel(val & ~bit, addr);
}

static inline u32 lsdc_pipe_rreg32(struct lsdc_device *ldev,
				   u32 offset,
				   u32 pipe)
{
	return readl(ldev->reg_base + offset + pipe * CRTC_PIPE_OFFSET);
}

#define lsdc_hdmi_rreg32 lsdc_pipe_rreg32
#define lsdc_crtc_rreg32 lsdc_pipe_rreg32

static inline void lsdc_pipe_wreg32(struct lsdc_device *ldev,
				    u32 offset,
				    u32 pipe,
				    u32 val)
{
	writel(val, ldev->reg_base + offset + pipe * CRTC_PIPE_OFFSET);
}

#define lsdc_hdmi_wreg32 lsdc_pipe_wreg32
#define lsdc_crtc_wreg32 lsdc_pipe_wreg32

static inline void lsdc_crtc_ureg32_set(struct lsdc_device *ldev,
					u32 offset,
					u32 pipe,
					u32 bit)
{
	void __iomem *addr;
	u32 val;

	addr = ldev->reg_base + offset + pipe * CRTC_PIPE_OFFSET;
	val = readl(addr);
	writel(val | bit, addr);
}

static inline void lsdc_crtc_ureg32_clr(struct lsdc_device *ldev,
					u32 offset,
					u32 pipe,
					u32 bit)
{
	void __iomem *addr;
	u32 val;

	addr = ldev->reg_base + offset + pipe * CRTC_PIPE_OFFSET;
	val = readl(addr);
	writel(val & ~bit, addr);
}

#endif
