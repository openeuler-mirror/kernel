// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Loongson Corporation
 */

/*
 * Authors:
 *      Sui Jingfeng <suijingfeng@loongson.cn>
 */

#include <drm/drm_file.h>
#include <drm/drm_device.h>
#include <drm/drm_debugfs.h>
#include <drm/drm_vma_manager.h>
#include <drm/drm_gem_vram_helper.h>

#include "lsdc_drv.h"
#include "lsdc_pll.h"
#include "lsdc_regs.h"
#include "lsdc_debugfs.h"

#ifdef CONFIG_DEBUG_FS

static int lsdc_show_clock(struct seq_file *m, void *arg)
{
	struct drm_info_node *node = (struct drm_info_node *)m->private;
	struct drm_device *ddev = node->minor->dev;
	struct drm_crtc *crtc;

	drm_for_each_crtc(crtc, ddev) {
		struct lsdc_display_pipe *pipe;
		struct lsdc_pll *pixpll;
		const struct lsdc_pixpll_funcs *funcs;
		struct lsdc_pll_core_values params;
		unsigned int out_khz;
		struct drm_display_mode *adj;

		pipe = container_of(crtc, struct lsdc_display_pipe, crtc);
		if (!pipe->available)
			continue;

		adj = &crtc->state->adjusted_mode;

		pixpll = &pipe->pixpll;
		funcs = pixpll->funcs;
		out_khz = funcs->get_clock_rate(pixpll, &params);

		seq_printf(m, "Display pipe %u: %dx%d\n",
			   pipe->index, adj->hdisplay, adj->vdisplay);

		seq_printf(m, "Frequency actually output: %u kHz\n", out_khz);
		seq_printf(m, "Pixel clock required: %d kHz\n", adj->clock);
		seq_printf(m, "diff: %d kHz\n", adj->clock);

		seq_printf(m, "div_ref=%u, loopc=%u, div_out=%u\n",
			   params.div_ref, params.loopc, params.div_out);

		seq_printf(m, "hsync_start=%d, hsync_end=%d, htotal=%d\n",
			   adj->hsync_start, adj->hsync_end, adj->htotal);
		seq_printf(m, "vsync_start=%d, vsync_end=%d, vtotal=%d\n\n",
			   adj->vsync_start, adj->vsync_end, adj->vtotal);
	}

	return 0;
}

static int lsdc_show_mm(struct seq_file *m, void *arg)
{
	struct drm_info_node *node = (struct drm_info_node *)m->private;
	struct drm_device *ddev = node->minor->dev;
	struct drm_printer p = drm_seq_file_printer(m);

	drm_mm_print(&ddev->vma_offset_manager->vm_addr_space_mm, &p);

	return 0;
}

#define REGDEF(reg) { __stringify_1(LSDC_##reg##_REG), LSDC_##reg##_REG }
static const struct {
	const char *name;
	u32 reg_offset;
} lsdc_regs_array[] = {
	REGDEF(INT),
	REGDEF(CRTC0_CFG),
	REGDEF(CRTC0_FB0_LO_ADDR),
	REGDEF(CRTC0_FB0_HI_ADDR),
	REGDEF(CRTC0_FB1_LO_ADDR),
	REGDEF(CRTC0_FB1_HI_ADDR),
	REGDEF(CRTC0_STRIDE),
	REGDEF(CRTC0_FB_ORIGIN),
	REGDEF(CRTC0_HDISPLAY),
	REGDEF(CRTC0_HSYNC),
	REGDEF(CRTC0_VDISPLAY),
	REGDEF(CRTC0_VSYNC),
	REGDEF(CRTC0_GAMMA_INDEX),
	REGDEF(CRTC0_GAMMA_DATA),
	REGDEF(CRTC1_CFG),
	REGDEF(CRTC1_FB0_LO_ADDR),
	REGDEF(CRTC1_FB0_HI_ADDR),
	REGDEF(CRTC1_FB1_LO_ADDR),
	REGDEF(CRTC1_FB1_HI_ADDR),
	REGDEF(CRTC1_STRIDE),
	REGDEF(CRTC1_FB_ORIGIN),
	REGDEF(CRTC1_HDISPLAY),
	REGDEF(CRTC1_HSYNC),
	REGDEF(CRTC1_VDISPLAY),
	REGDEF(CRTC1_VSYNC),
	REGDEF(CRTC1_GAMMA_INDEX),
	REGDEF(CRTC1_GAMMA_DATA),
	REGDEF(CURSOR0_CFG),
	REGDEF(CURSOR0_ADDR),
	REGDEF(CURSOR0_POSITION),
	REGDEF(CURSOR0_BG_COLOR),
	REGDEF(CURSOR0_FG_COLOR),
};

static int lsdc_show_regs(struct seq_file *m, void *arg)
{
	struct drm_info_node *node = (struct drm_info_node *)m->private;
	struct drm_device *ddev = node->minor->dev;
	struct lsdc_device *ldev = to_lsdc(ddev);
	int i;

	for (i = 0; i < ARRAY_SIZE(lsdc_regs_array); i++) {
		u32 offset = lsdc_regs_array[i].reg_offset;
		const char *name = lsdc_regs_array[i].name;

		seq_printf(m, "%s (0x%04x): 0x%08x\n",
			   name, offset,
			   readl(ldev->reg_base + offset));
	}

	return 0;
}

static const struct drm_info_list lsdc_debugfs_list[] = {
	{ "clocks", lsdc_show_clock, 0 },
	{ "mm",     lsdc_show_mm,   0, NULL },
	{ "regs",   lsdc_show_regs, 0 },
};

void lsdc_debugfs_init(struct drm_minor *minor)
{
	drm_debugfs_create_files(lsdc_debugfs_list,
				 ARRAY_SIZE(lsdc_debugfs_list),
				 minor->debugfs_root,
				 minor);
}

/*
 * vram debugfs related.
 */
static int lsdc_vram_mm_show(struct seq_file *m, void *data)
{
	struct drm_info_node *node = (struct drm_info_node *)m->private;
	struct drm_vram_mm *vmm = node->minor->dev->vram_mm;
	struct ttm_resource_manager *man = ttm_manager_type(&vmm->bdev, TTM_PL_VRAM);
	struct drm_printer p = drm_seq_file_printer(m);

	ttm_resource_manager_debug(man, &p);
	return 0;
}

static const struct drm_info_list lsdc_vram_mm_debugfs_list[] = {
	{ "clocks", lsdc_show_clock, 0 },
	{ "vram-mm", lsdc_vram_mm_show, 0, NULL },
	{ "regs",   lsdc_show_regs, 0 },
};

void lsdc_vram_mm_debugfs_init(struct drm_minor *minor)
{
	drm_debugfs_create_files(lsdc_vram_mm_debugfs_list,
				 ARRAY_SIZE(lsdc_vram_mm_debugfs_list),
				 minor->debugfs_root,
				 minor);
}

#endif
