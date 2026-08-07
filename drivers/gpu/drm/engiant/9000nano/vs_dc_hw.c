// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 VeriSilicon Holdings Co., Ltd.
 *
 * Modified: 2025-01-06
 *   - Fixed mouse hotspot to (0,0)
 *   - Updated ALPHA_BLEND config flow
 * Modified: 2025-02-17
 *   - Added DC reset before display_set_mode
 * Modified: 2025-03-11
 *   - Set command mode when display_mode not enabled
 * Modified: 2025-02-20
 *   - Fixed Intel G6 flicker: sorted gamma table ascending
 */

#include <linux/bits.h>
#include <linux/media-bus-format.h>
#include <linux/delay.h>

#include "vs_egt_drm.h"
#include "vs_egt_drm_fourcc.h"
#include "vs_dc_hw.h"
#include "vs_dc_reg.h"
#include "vs_type.h"
#include "postprocess/vs_dc_postprocess.h"
#include "preprocess/vs_dc_plane_blender.h"
#include "preprocess/vs_dc_preprocess.h"
#include "vs_dc_reg.h"

#ifdef CONFIG_ENGIANT_VS_QSPI
#include "vs_dc_qspi.h"
#endif

#ifdef CONFIG_ENGIANT_VS_DEBUG
#include "vs_debug.h"
#endif

#define FRAC_16_16(mult, div) (((mult) << 16) / (div))
#define PCI_INTR_MASK_REG_OFFSET    0x188

static const struct dc_hw_funcs hw_func;
#define HOT_X 0
#define HOT_Y 0

inline void egt_dc_write(struct dc_hw *hw, u32 reg, u32 value)
{
	//pr_err("%s: 0x%08x = 0x%08x\n", __func__, reg, value);
	writel(value, hw->reg_base + reg);
#ifdef CONFIG_ENGIANT_VS_DEBUG
	vs_egt_debug_dump_capture(hw->dc_capture_fp, reg, value, false);
#endif
}

inline void egt_pcie_write(struct dc_hw *hw, u32 reg, u32 value)
{
	//pr_err("%s: 0x%08x = 0x%08x\n", __func__, reg, value);
	writel(value, hw->pcie_reg_base + reg);
}

u32 vs_egt_dc_hw_read(struct dc_hw *hw, u32 reg)
{
	u32 value;

	value = dc_read(hw, reg);

	return value;
}

static void dc_coef_reverse(uint32_t *rgb2yuv_coef, u32 coefA, u32 coefB)
{
		u32 temp = rgb2yuv_coef[coefA];

		rgb2yuv_coef[coefA] = rgb2yuv_coef[coefB];
		rgb2yuv_coef[coefB] = temp;
}

void egt_dc_write_u32_blob(struct dc_hw *hw, u32 reg, const u32 *data, u32 size)
{
	const u32 u32_stride = sizeof(u32);
	uint32_t rgb2yuv_coef[20];
	u32 i;

	for (i = 0; i < size; i++)
		rgb2yuv_coef[i] = data[i];

	if (hw->coef_change) {
		dc_coef_reverse(rgb2yuv_coef, 3, 6);
		dc_coef_reverse(rgb2yuv_coef, 4, 7);
		dc_coef_reverse(rgb2yuv_coef, 5, 8);
		dc_coef_reverse(rgb2yuv_coef, 12, 13);

		for (i = 0; i < size; i++)
			egt_dc_write(hw, reg + u32_stride * i, rgb2yuv_coef[i]);
	} else {
		for (i = 0; i < size; i++)
			egt_dc_write(hw, reg + u32_stride * i, data[i]);
	}

}

/* Get the plane address offset based on HW_PLANE_0 */
static u32 _get_plane_offset(u32 hw_id)
{
	u32 offset = 0x0;
	u32 base_offset = DCREG_SH_LAYER1_CONFIG_Address - DCREG_SH_LAYER0_CONFIG_Address;

	offset = hw_id * base_offset;

	return offset;
}

/* Get the plane output path addr offset based on HW_PLANE_0
 *static u32 _get_plane_out_offset(u32 hw_id)
 *{
 *	u32 offset = 0;
 *	return offset;
 *}
 */

/************************************************************************
 * Below are the main hw interfaces.
 ************************************************************************/
static void load_filter(__maybe_unused struct dc_hw *hw, __maybe_unused u8 hw_id,
			__maybe_unused u16 *coef)
{
}

static void load_be_default_filter(__maybe_unused struct dc_hw *hw, __maybe_unused u8 hw_id)
{
}

void egt_dc_hw_reset(struct dc_hw *hw)
{
	egt_dc_write(hw, DCREG_CURSOR_LAYER_CONFIG_Address, 0x2);
	egt_dc_write(hw, DCREG_SH_CURSOR_LAYER_CONFIG_Address, 0x0);
	egt_dc_write(hw, DCREG_LAYER0_CONFIG_Address, 0x1);
	egt_dc_write(hw, DCREG_PANEL0_CONFIG_Address, 0x1);
	egt_dc_write(hw, DCREG_PANEL0_OUTPUT_CONFIG_Address, 0x1);
	egt_dc_write(hw, DCREG_CURSOR_LAYER_CONFIG_Address, 0x1);

	egt_dc_hw_do_reset(hw);
}

int egt_dc_hw_init(struct dc_hw *hw)
{
	int ret = 0;
	u8 i, hw_id;
	u32 chip_id, revision, pid, cid;

	const struct vs_plane_info *plane_info;
	const struct vs_display_info *display_info;

	chip_id = dc_read(hw, GCREG_DC_CHIP_ID_Address);
	revision = dc_read(hw, GCREG_DC_CHIP_REV_Address);
	pid = dc_read(hw, GCREG_DC_PRODUCT_ID_Address);
	cid = dc_read(hw, GCREG_DC_CUSTOMER_ID_Address);

	hw->info = vs_egt_dc_get_chip_info();
	hw->output_info = vs_egt_dc_get_output_info();

	pr_debug("chip_id = %x\n", chip_id);
	pr_debug("revision = %x\n", revision);
	pr_debug("pid = %x\n", pid);
	pr_debug("cid = %x\n", cid);

	if (hw->info->chip_id != chip_id || hw->info->revision != revision ||
		hw->info->pid != pid || hw->info->cid != cid) {
		pr_err("Could not find matched hw.\n");
		pr_err("chip_id = %x\n", chip_id);
		pr_err("revision = %x\n", revision);
		pr_err("pid = %x\n", pid);
		pr_err("cid = %x\n", cid);

		ret = -EPERM;
		goto err_cleanup;
	}

	hw->func = (struct dc_hw_funcs *)&hw_func;

	for (i = 0; i < hw->info->layer_num; i++) {
		plane_info = &hw->info->planes[i];
		hw->plane[i].info = plane_info;
		hw_id = plane_info->id;

		if (plane_info->min_scale != DRM_PLANE_HELPER_NO_SCALING ||
			plane_info->max_scale != DRM_PLANE_HELPER_NO_SCALING)
			load_filter(hw, hw_id, NULL);

		/* Initialize property states */
		if (!vs_egt_dc_register_plane_blender_states(&hw->plane[i].states, plane_info)) {
			pr_err("%s: Failed to register plane blender states.\n", __func__);
			ret = -ENOMEM;
			goto err_cleanup;
		}
		if (!vs_egt_dc_register_preprocess_states(&hw->plane[i].states, plane_info)) {
			pr_err("%s: Failed to register preprocess.\n", __func__);
			ret = -ENOMEM;
			goto err_cleanup;
		}

		if (!vs_egt_dc_initialize_property_states(&hw->plane[i].states)) {
			pr_err("%s: Failed to initialize plane property states.\n", __func__);
			ret = -ENOMEM;
			goto err_cleanup;
		}
		pr_debug("%s: Alloc states mem %zu for plane %u\n", __func__,
			 hw->plane[i].states.mem.total_size, i);
	}

	for (i = 0; i < hw->info->display_num; i++) {
		display_info = &hw->info->displays[i];
		hw->display[i].info = display_info;
		hw_id = display_info->id;

		if (display_info->min_scale != FRAC_16_16(1, 1) ||
			display_info->max_scale != FRAC_16_16(1, 1))
			load_be_default_filter(hw, hw_id);
		if (!vs_egt_dc_register_postprocess_states(&hw->display[i].states, display_info)) {
			pr_err("%s: Failed to register postprocess.\n", __func__);
			ret = -ENOMEM;
			goto err_cleanup;
		}
		if (!vs_egt_dc_initialize_property_states(&hw->display[i].states)) {
			pr_err("%s: Failed to initialize display property states.\n", __func__);
			ret = -ENOMEM;
			goto err_cleanup;
		}
		pr_debug("%s: Alloc states mem %zu for display %u\n", __func__,
			 hw->display[i].states.mem.total_size, i);
	}

	return ret;
err_cleanup:
	return ret;
}

void egt_dc_hw_deinit(struct dc_hw *hw)
{
	int i;

	for (i = 0; i < hw->info->layer_num; i++)
		vs_egt_dc_deinitialize_property_states(&hw->plane[i].states);

	for (i = 0; i < hw->info->display_num; i++)
		vs_egt_dc_deinitialize_property_states(&hw->display[i].states);
}

void egt_dc_hw_update_plane(struct dc_hw *hw, u8 id, struct dc_hw_fb *fb)
{
	struct dc_hw_plane *plane = &hw->plane[id];

	if (plane && fb) {
		if (!fb->enable)
			plane->fb.enable = false;
		else
			memcpy(&plane->fb, fb, sizeof(*fb) - sizeof(fb->dirty));
		plane->fb.dirty = true;
	}
}

void egt_dc_hw_update_plane_position(struct dc_hw *hw, u8 id, struct dc_hw_position *pos)
{
	struct dc_hw_plane *plane = &hw->plane[id];

	if (plane && pos) {
		memcpy(&plane->pos, pos, sizeof(*pos) - sizeof(pos->dirty));
		plane->pos.dirty = true;
		plane->pos.enable = true;
	}
}

void egt_dc_hw_update_plane_y2r(struct dc_hw *hw, u8 id, struct dc_hw_y2r *y2r_conf)
{
	struct dc_hw_plane *plane = &hw->plane[id];

	if (plane && y2r_conf) {
		memcpy(&plane->y2r, y2r_conf, sizeof(*y2r_conf) - sizeof(y2r_conf->dirty));
		plane->y2r.dirty = true;
		plane->y2r.enable = true;
	}
}

void egt_dc_hw_update_plane_std_bld(struct dc_hw *hw, u8 zpos, struct dc_hw_std_bld *std_bld)
{
	struct dc_hw_std_bld *std_blend = &hw->std_bld[zpos];

	if (std_blend && std_bld) {
		memcpy(std_blend, std_bld, sizeof(*std_bld) - sizeof(std_bld->dirty));
		std_blend->dirty = true;
		std_blend->enable = true;
	}
}

void egt_dc_hw_update_cursor(struct dc_hw *hw, u8 id, struct dc_hw_cursor *cursor)
{
	memcpy(&hw->cursor[id], cursor, sizeof(*cursor) - sizeof(cursor->dirty));
	hw->cursor[id].dirty = true;
}

void egt_dc_hw_update_gamma(struct dc_hw *hw, u8 id, u16 index, u16 r, u16 g, u16 b)
{
	if (index >= hw->info->max_gamma_size)
		return;

	hw->display[id].gamma.gamma[index][0] = r;
	hw->display[id].gamma.gamma[index][1] = g;
	hw->display[id].gamma.gamma[index][2] = b;
	hw->display[id].gamma.dirty = true;
}

void egt_dc_hw_enable_gamma(struct dc_hw *hw, u8 id, bool enable)
{
	hw->display[id].gamma.enable = enable;
	hw->display[id].gamma.dirty = true;
}

void egt_dc_hw_setup_display_mode(struct dc_hw *hw, u8 id, struct dc_hw_display_mode *mode)
{
	struct dc_hw_display *display = &hw->display[id];
	u8 output_id = 0;

	if (display && mode) {
		if (!mode->enable)
			display->mode.enable = false;
		else
			memcpy(&display->mode, mode, sizeof(*mode));

		output_id = display->output_id;
		hw->func->set_mode(hw, output_id, display, &display->mode);
	}
}

void egt_dc_hw_config_plane_status(struct dc_hw *hw, u8 id, bool config)
{
	struct dc_hw_plane *plane = &hw->plane[id];

	if (plane)
		plane->config_status = !!config;
}

void egt_dc_hw_config_display_status(struct dc_hw *hw, u8 id, bool config)
{
	struct dc_hw_display *display = &hw->display[id];

	if (display)
		display->config_status = !!config;
}

void egt_dc_hw_enable_vblank(struct dc_hw *hw, bool enable)
{
	if (enable) {
		egt_dc_write(hw, DCREG_BE_INTR_ENABLE_Address, DCREG_BE_INTR_ENABLE_WriteMask);
		egt_dc_write(hw, DCREG_BE_INTR_ENABLE1_Address, DCREG_BE_INTR_ENABLE1_WriteMask);
		/*Enable pcie mask of dc*/
		egt_pcie_write(hw, PCI_INTR_MASK_REG_OFFSET, hw->pcie_mask_value);
	} else {
		egt_dc_write(hw, DCREG_BE_INTR_ENABLE_Address, DCREG_BE_INTR_ENABLE_ResetValue);
		egt_dc_write(hw, DCREG_BE_INTR_ENABLE1_Address, DCREG_BE_INTR_ENABLE1_ResetValue);
	}
}

u32 egt_dc_hw_get_vblank_count(struct dc_hw *hw, u8 id)
{
	return hw->display[id].vblank_count;
}

int egt_dc_hw_get_interrupt(struct dc_hw *hw, struct dc_hw_interrupt_status *status)
{
	u32 intr_status = 0, intr_status1 = 0, intr_status2 = 0;

	char intr_event[MAX_DC_INTR_EVENT_SIZE - 20] = { 0 };

	intr_status = dc_read(hw, DCREG_BE_INTR_STATUS_Address);
	intr_status1 = dc_read(hw, DCREG_BE_INTR_STATUS1_Address);
	intr_status2 = dc_read(hw, DCREG_FE0_INTR_STATUS_Address);

	if (intr_status == 0xffffffff || intr_status1 == 0xffffffff || intr_status2 == 0xffffffff) {
		pr_err("intr_status = 0x%x intr_status1 = 0x%x intr_status2 = 0x%x\n",
				intr_status, intr_status1, intr_status2);
		return 1;
	}

	if (intr_status || intr_status1) {
		if (VS_GET_INTR_FIELD(intr_status, DCREG_BE_INTR_STATUS, OUTPATH0_FRM_DONE)) {
			status->display_frm_done |= BIT(0);
			hw->display[0].vblank_count++;
			//VS_INTR_EVENT_DEBUG();
		}

		if (VS_GET_INTR_FIELD(intr_status1, DCREG_BE_INTR_STATUS1, OUTIF0_UNDERFLOW)) {
			status->display_underflow |= BIT(0);
			pr_err("%s:received underflow intr!", __func__);
			VS_INTR_EVENT_DEBUG();
		}

		if (VS_GET_INTR_FIELD(intr_status1, DCREG_BE_INTR_STATUS1,
					  OUTIF0_AXI_FREQUENCY_TOO_SLOW)) {
			status->display_axi_slow |= BIT(0);
			pr_err("%s:received axi frequency too slow intr!", __func__);
			VS_INTR_EVENT_DEBUG();
		}

		egt_dc_write(hw, DCREG_BE_INTR_STATUS_Address, intr_status);
		egt_dc_write(hw, DCREG_BE_INTR_STATUS1_Address, intr_status1);
	}

	return 0;
}

int vs_egt_dpu_hw_enable_interrupt(struct dc_hw *hw)
{
	egt_dc_write(hw, DCREG_BE_INTR_ENABLE_Address, DCREG_BE_INTR_ENABLE_WriteMask);
	return 0;
}

bool egt_dc_hw_check_underflow(__maybe_unused struct dc_hw *hw)
{
	return false;
}

#ifdef CONFIG_DEBUG_FS
void egt_dc_hw_set_plane_crc(struct dc_hw *hw, u8 id, struct dc_hw_crc *crc)
{
	struct dc_hw_plane *plane = &hw->plane[id];
	u8 hw_id = hw->info->planes[id].id;
	u32 config = 0;

	memcpy(&plane->crc, crc, sizeof(*crc));

	config = VS_SET_FIELD(0, DCREG_LAYER0_CRC_START, START, crc->enable);
	egt_dc_write(hw, VS_SET_FE_FIELD(DCREG_LAYER, hw_id, CRC_START_Address), config);

	if (!crc->enable)
		return;

	switch (crc->pos) {
	case VS_PLANE_CRC_DMA:
		egt_dc_write(hw, VS_SET_FE_FIELD(DCREG_LAYER, hw_id, DMA_ALPHA_CRC_SEED_Address),
			 crc->seed.a);
		egt_dc_write(hw, VS_SET_FE_FIELD(DCREG_LAYER, hw_id, DMA_RED_CRC_SEED_Address),
			 crc->seed.r);
		egt_dc_write(hw, VS_SET_FE_FIELD(DCREG_LAYER, hw_id, DMA_GREEN_CRC_SEED_Address),
			 crc->seed.g);
		egt_dc_write(hw, VS_SET_FE_FIELD(DCREG_LAYER, hw_id, DMA_BLUE_CRC_SEED_Address),
			 crc->seed.b);
		break;
	case VS_PLANE_CRC_PRE_BLEND:
		egt_dc_write(hw,
			VS_SET_FE_FIELD(DCREG_LAYER, hw_id, PRE_BLEND_ALPHA_CRC_SEED_Address),
			crc->seed.a);
		egt_dc_write(hw,
			VS_SET_FE_FIELD(DCREG_LAYER, hw_id, PRE_BLEND_RED_CRC_SEED_Address),
			crc->seed.r);
		egt_dc_write(hw,
			VS_SET_FE_FIELD(DCREG_LAYER, hw_id, PRE_BLEND_GREEN_CRC_SEED_Address),
			crc->seed.g);
		egt_dc_write(hw,
			VS_SET_FE_FIELD(DCREG_LAYER, hw_id, PRE_BLEND_BLUE_CRC_SEED_Address),
			crc->seed.b);
		break;
	default:
		break;
	}
}

void egt_dc_hw_get_plane_crc(struct dc_hw *hw, u8 id, struct dc_hw_crc *crc)
{
	struct dc_hw_plane *plane = &hw->plane[id];
	u8 hw_id = hw->info->planes[id].id;

	switch (plane->crc.pos) {
	case VS_PLANE_CRC_DMA:
		plane->crc.result.a = dc_read(hw, VS_SET_FE_FIELD(DCREG_LAYER, hw_id,
							DMA_ALPHA_CRC_VALUE_Address));
		plane->crc.result.r = dc_read(hw,
				VS_SET_FE_FIELD(DCREG_LAYER, hw_id, DMA_RED_CRC_VALUE_Address));
		plane->crc.result.g = dc_read(hw, VS_SET_FE_FIELD(DCREG_LAYER, hw_id,
							DMA_GREEN_CRC_VALUE_Address));
		plane->crc.result.b = dc_read(hw, VS_SET_FE_FIELD(DCREG_LAYER, hw_id,
							DMA_BLUE_CRC_VALUE_Address));
		break;
	case VS_PLANE_CRC_PRE_BLEND:
		plane->crc.result.a = dc_read(hw,
			VS_SET_FE_FIELD(DCREG_LAYER, hw_id, PRE_BLEND_ALPHA_CRC_VALUE_Address));
		plane->crc.result.r = dc_read(hw, VS_SET_FE_FIELD(DCREG_LAYER, hw_id,
							PRE_BLEND_RED_CRC_VALUE_Address));
		plane->crc.result.g = dc_read(hw,
			VS_SET_FE_FIELD(DCREG_LAYER, hw_id, PRE_BLEND_GREEN_CRC_VALUE_Address));
		plane->crc.result.b = dc_read(hw,
			VS_SET_FE_FIELD(DCREG_LAYER, hw_id, PRE_BLEND_BLUE_CRC_VALUE_Address));
		break;
	default:
		break;
	}

	memcpy(&crc->result, &plane->crc.result, sizeof(plane->crc.result));
}

void egt_dc_hw_get_plane_crc_config(struct dc_hw *hw, u8 id, struct dc_hw_crc *crc)
{
	struct dc_hw_plane *plane = &hw->plane[id];

	if (plane && crc)
		memcpy(crc, &plane->crc, sizeof(plane->crc));
}

void egt_dc_hw_set_display_crc(struct dc_hw *hw, u8 hw_id, struct dc_hw_disp_crc *crc)
{
	struct dc_hw_display *display = &hw->display[hw_id];

	memcpy(&display->crc, crc, sizeof(*crc));

	switch (hw_id) {
	case HW_DISPLAY_0:
		switch (crc->pos) {
		case VS_EGT_DISP_CRC_BLD:
		case VS_EGT_DISP_CRC_OFIFO_OUT:
			egt_dc_write(hw, VS_SET_PANEL_FIELD(DCREG_PANEL0, CRC_START_Address),
				 crc->enable);
			break;
		default:
			break;
		}
	default:
		break;
	}

	if (!crc->enable)
		return;

	switch (crc->pos) {
	case VS_EGT_DISP_CRC_BLD:
		switch (hw_id) {
		case HW_DISPLAY_0:
			egt_dc_write(hw,
				VS_SET_PANEL_FIELD(DCREG_PANEL0, BLEND_ALPHA_CRC_SEED_Address),
				crc->seed[0].a);
			egt_dc_write(hw,
				VS_SET_PANEL_FIELD(DCREG_PANEL0, BLEND_RED_CRC_SEED_Address),
				crc->seed[0].r);
			egt_dc_write(hw,
				VS_SET_PANEL_FIELD(DCREG_PANEL0, BLEND_GREEN_CRC_SEED_Address),
				crc->seed[0].g);
			egt_dc_write(hw,
				VS_SET_PANEL_FIELD(DCREG_PANEL0, BLEND_BLUE_CRC_SEED_Address),
				crc->seed[0].b);
			break;
		default:
			break;
		}
		break;

	case VS_EGT_DISP_CRC_OFIFO_OUT:
		switch (hw_id) {
		case HW_DISPLAY_0:
			egt_dc_write(hw,
				VS_SET_PANEL_FIELD(DCREG_PANEL0, OFIFO_ALPHA_CRC_SEED_Address),
				crc->seed[0].a);
			egt_dc_write(hw,
				VS_SET_PANEL_FIELD(DCREG_PANEL0, OFIFO_RED_CRC_SEED_Address),
				crc->seed[0].r);
			egt_dc_write(hw,
				VS_SET_PANEL_FIELD(DCREG_PANEL0, OFIFO_GREEN_CRC_SEED_Address),
				crc->seed[0].g);
			egt_dc_write(hw,
				VS_SET_PANEL_FIELD(DCREG_PANEL0, OFIFO_BLUE_CRC_SEED_Address),
				crc->seed[0].b);
			break;
		default:
			break;
		}
		break;

	default:
		break;
	}
}

void egt_dc_hw_get_display_crc(struct dc_hw *hw, u8 hw_id, struct dc_hw_disp_crc *crc)
{
	switch (crc->pos) {
	case VS_EGT_DISP_CRC_BLD:
		switch (hw_id) {
		case HW_DISPLAY_0:
			crc->result[0].a = dc_read(hw, VS_SET_PANEL_FIELD(DCREG_PANEL0,
						BLEND_ALPHA_CRC_VALUE_Address));
			crc->result[0].r = dc_read(hw, VS_SET_PANEL_FIELD(DCREG_PANEL0,
						BLEND_RED_CRC_VALUE_Address));
			crc->result[0].g = dc_read(hw, VS_SET_PANEL_FIELD(DCREG_PANEL0,
						BLEND_GREEN_CRC_VALUE_Address));
			crc->result[0].b = dc_read(hw, VS_SET_PANEL_FIELD(DCREG_PANEL0,
						BLEND_BLUE_CRC_VALUE_Address));
			break;
		default:
			break;
		}
		break;

	case VS_EGT_DISP_CRC_OFIFO_OUT:
		switch (hw_id) {
		case HW_DISPLAY_0:
			crc->result[1].a = dc_read(hw, VS_SET_PANEL_FIELD(DCREG_PANEL0,
						OFIFO_ALPHA_CRC_VALUE_Address));
			crc->result[1].r = dc_read(hw, VS_SET_PANEL_FIELD(DCREG_PANEL0,
						OFIFO_RED_CRC_VALUE_Address));
			crc->result[1].g = dc_read(hw, VS_SET_PANEL_FIELD(DCREG_PANEL0,
						OFIFO_GREEN_CRC_VALUE_Address));
			crc->result[1].b = dc_read(hw, VS_SET_PANEL_FIELD(DCREG_PANEL0,
						OFIFO_BLUE_CRC_VALUE_Address));
			break;
		default:
			break;
		}
		break;

	default:
		break;
	}
}

void egt_dc_hw_get_display_crc_config(struct dc_hw *hw, u8 id, struct dc_hw_disp_crc *crc)
{
	struct dc_hw_display *display = &hw->display[id];

	if (display && crc)
		memcpy(crc, &display->crc, sizeof(display->crc));
}

#endif /* CONFIG_DEBUG_FS */

void egt_dc_hw_enable_shadow_register(struct dc_hw *hw, u8 display_id, bool enable)
{
	u32 i, hw_id, config = 0;

	/* for layer */
	for (i = 0; i < hw->info->layer_num; i++) {
		if (!hw->plane[i].config_status || (hw->plane[i].fb.display_id != display_id))
			continue;

		hw_id = hw->info->planes[i].id;
		config = dc_read(hw, VS_SET_FE_FIELD(DCREG_LAYER, hw_id, CONFIG_Address));
		egt_dc_write(hw, VS_SET_FE_FIELD(DCREG_LAYER, hw_id, CONFIG_Address),
			 VS_SET_FIELD(config, DCREG_LAYER0_CONFIG, REG_SWITCH, enable));
	}

	/* for display & interface */
	for (i = 0; i < hw->info->display_num; i++) {
		if (!hw->display[i].config_status || (hw->info->displays[i].id != display_id))
			continue;

		hw_id = hw->info->displays[i].id;

		config = dc_read(hw, DCREG_PANEL0_CONFIG_Address);
		egt_dc_write(hw, DCREG_PANEL0_CONFIG_Address,
			 VS_SET_FIELD(config, DCREG_PANEL0_CONFIG, REG_SWITCH, enable));

		/* for output */
		config = dc_read(hw, DCREG_PANEL0_OUTPUT_CONFIG_Address);
		egt_dc_write(hw, DCREG_PANEL0_OUTPUT_CONFIG_Address,
			 VS_SET_FIELD(config, DCREG_PANEL0_OUTPUT_CONFIG, REG_SWITCH, enable));
	}

	/* for cursor */
	for (i = 0; i < DC_CURSOR_NUM; i++) {
		if (hw->cursor[i].display_id != display_id)
			continue;

		config = dc_read(hw, DCREG_CURSOR_LAYER_CONFIG_Address);
		egt_dc_write(hw, DCREG_CURSOR_LAYER_CONFIG_Address,
			 VS_SET_FIELD(config, DCREG_CURSOR_LAYER_CONFIG, REG_SWITCH, enable));
	}
}

void egt_dc_hw_start_trigger(struct dc_hw *hw, u8 display_id)
{
	u32 i = 0;
	bool is_cmd_mode = false;

	for (i = 0; i < hw->info->display_num; i++) {
		if (!hw->display[i].config_status || (hw->info->displays[i].id != display_id))
			continue;

		is_cmd_mode = hw->display[i].mode.output_mode & VS_SIMPLE_ENC_OUTPUT_MODE_CMD;
		if ((hw->display[i].mode.out == OUT_DPI || hw->display[i].mode.out == OUT_DP) &&
			(is_cmd_mode || !hw->display[i].running)) {
			if (hw->display[i].mode.enable) {
				egt_dc_write(hw, DCREG_PANEL0_TRIGGER_Address,
					 VS_SET_FIELD(0, DCREG_PANEL0_TRIGGER, MODE,
							  hw->display[i].mode.out));
			}

			/* video mode only need to be triggered at the first frame,
			 * cmd mode need to be triggered at every frame.
			 */
			if (!is_cmd_mode)
				hw->display[i].running = true;
			else
				hw->display[i].running = false;
		}

#ifdef CONFIG_ENGIANT_VS_QSPI
		else if (hw->display[i].mode.out == OUT_SPI)
			egt_qspi_start_trigger(hw, &hw->display[i].mode);
#endif
	}
}

void egt_dc_hw_do_fe_reset(struct dc_hw *hw)
{
	pr_debug("@@@@@@@@ FE reset\n");
	egt_dc_write(hw, DCREG_FE0_SW_RESET_Address,
		 VS_SET_FIELD_PREDEF(0, DCREG_FE0_SW_RESET, RESET, RESET));
	msleep(1000);
	egt_dc_write(hw, DCREG_FE1_SW_RESET_Address,
		 VS_SET_FIELD_PREDEF(0, DCREG_FE1_SW_RESET, RESET, RESET));
	msleep(1000);
}
void egt_dc_hw_do_be_reset(struct dc_hw *hw)
{
	pr_debug("@@@@@@@@ BE reset\n");
	egt_dc_write(hw, DCREG_BE_SW_RESET_Address,
		 VS_SET_FIELD_PREDEF(0, DCREG_BE_SW_RESET, RESET, RESET));
	msleep(1000);
}

void egt_dc_hw_do_reset(struct dc_hw *hw)
{
	/*enable be interrupt mask which closed by bios*/
	egt_dc_write(hw, DCREG_BE_INTR_MASK_Address, 0x0);

	egt_dc_hw_do_fe_reset(hw);

	egt_dc_hw_do_be_reset(hw);

#ifdef CONFIG_ENGIANT_VS_PCIE_GEN7
	vs_egt_dpu_hw_enable_interrupt(hw);
#endif
}

#ifdef CONFIG_ENGIANT_VS_DEC
void egt_dc_hw_set_plane_fbc_dec(struct dc_hw *hw, u8 id, bool enable, u8 dec_mod)
{
	u32 offset = _get_plane_offset((u32)id);
	u32 config = 0;

	if (enable) {
		config = dc_read(hw, DCREG_SH_LAYER0_CONFIG_Address + offset);
		config = VS_SET_FIELD(config, DCREG_SH_LAYER0_CONFIG, DEC_MODE, dec_mod);
		egt_dc_write(hw, DCREG_SH_LAYER0_CONFIG_Address + offset, config);
	} else {
		config = dc_read(hw, DCREG_SH_LAYER0_CONFIG_Address + offset);
		config = VS_SET_FIELD_PREDEF(config, DCREG_SH_LAYER0_CONFIG, DEC_MODE, DISABLE);
		egt_dc_write(hw, DCREG_SH_LAYER0_CONFIG_Address + offset, config);
	}
}
#endif

static void plane_set_fb(struct dc_hw *hw, u8 hw_id, struct dc_hw_fb *fb)
{
	u32 offset = _get_plane_offset(hw_id);
	u32 config = 0;

	if (fb->enable) {
		/* address configuration */
		egt_dc_write(hw, DCREG_SH_LAYER0_ADDRESS_Address + offset,
			 (u32)(fb->address & 0xFFFFFFFF));
		egt_dc_write(hw, DCREG_SH_LAYER0_UADDRESS_Address + offset,
			 (u32)(fb->u_address & 0xFFFFFFFF));
		egt_dc_write(hw, DCREG_SH_LAYER0_VADDRESS_Address + offset,
			 (u32)(fb->v_address & 0xFFFFFFFF));

		/* stride/size configuration */
		egt_dc_write(hw, DCREG_SH_LAYER0_STRIDE_Address + offset, fb->stride);
		egt_dc_write(hw, DCREG_SH_LAYER0_USTRIDE_Address + offset, fb->u_stride);
		egt_dc_write(hw, DCREG_SH_LAYER0_VSTRIDE_Address + offset, fb->v_stride);
		egt_dc_write(hw, DCREG_SH_LAYER0_SIZE_Address + offset,
			 VS_SET_FIELD(0, DCREG_SH_LAYER0_SIZE, WIDTH, fb->width) |
				 VS_SET_FIELD(0, DCREG_SH_LAYER0_SIZE, HEIGHT, fb->height));
	}

	/* enable/swizzle/tile_mode/blend/rotation/format configuration */
	config = dc_read(hw, DCREG_SH_LAYER0_CONFIG_Address + offset);
	config = VS_SET_FIELD(config, DCREG_SH_LAYER0_CONFIG, LAYER_ENABLE, fb->enable);
	config = VS_SET_FIELD(config, DCREG_SH_LAYER0_CONFIG, UV_SWIZZLE, fb->uv_swizzle);
	config = VS_SET_FIELD(config, DCREG_SH_LAYER0_CONFIG, SWIZZLE, fb->swizzle);
	config = VS_SET_FIELD(config, DCREG_SH_LAYER0_CONFIG, TILE_MODE, fb->tile_mode);
	config = VS_SET_FIELD(config, DCREG_SH_LAYER0_CONFIG, BLEND_PRIORITY, fb->zpos & 0xF);
	config = VS_SET_FIELD(config, DCREG_SH_LAYER0_CONFIG, FLIP_XEN, fb->flipx);
	config = VS_SET_FIELD(config, DCREG_SH_LAYER0_CONFIG, FLIP_YEN, fb->flipy);
	config = VS_SET_FIELD(config, DCREG_SH_LAYER0_CONFIG, ROT_ANGLE, fb->rotation);
	config = VS_SET_FIELD(config, DCREG_SH_LAYER0_CONFIG, FORMAT, fb->format);

	egt_dc_write(hw, DCREG_SH_LAYER0_CONFIG_Address + offset, config);

	/*Enable SWIZZLE feature set bit[3] and bit[6] 1'b1*/
	if (hw->rgb_bgr)
		egt_dc_write(hw, DCREG_SH_PANEL0_CONFIG_Address, 0x48);

	fb->dirty = false;
}

static void plane_set_pos(struct dc_hw *hw, u8 hw_id, struct dc_hw_position *pos)
{
	egt_dc_write(hw, VS_SH_LAYER_FIELD(hw_id, OUT_ROI_ORIGIN_Address),
		 VS_SET_FIELD(0, DCREG_SH_LAYER0_OUT_ROI_ORIGIN, X, pos->rect[0].x) |
			 VS_SET_FIELD(0, DCREG_SH_LAYER0_OUT_ROI_ORIGIN, Y, pos->rect[0].y));

	egt_dc_write(hw, VS_SH_LAYER_FIELD(hw_id, OUT_ROI_SIZE_Address),
		 VS_SET_FIELD(0, DCREG_SH_LAYER0_OUT_ROI_SIZE, WIDTH, pos->rect[0].w) |
			 VS_SET_FIELD(0, DCREG_SH_LAYER0_OUT_ROI_SIZE, HEIGHT, pos->rect[0].h));

	pos->dirty = false;
}

static void plane_set_y2r(struct dc_hw *hw, u8 hw_id, struct dc_hw_y2r *y2r_conf)
{
	u32 config = 0;

	config = dc_read(hw, VS_SET_FE_FIELD(DCREG_SH_LAYER, hw_id, CONFIG_Address));

	switch (y2r_conf->gamut) {
	case CSC_GAMUT_601:
		egt_dc_write(hw, VS_SET_FE_FIELD(DCREG_SH_LAYER, hw_id, CONFIG_Address),
			 VS_SET_FIELD_PREDEF(config, DCREG_SH_LAYER0_CONFIG, Y2R_MODE, BT601));
		break;
	case CSC_GAMUT_709:
		egt_dc_write(hw, VS_SET_FE_FIELD(DCREG_SH_LAYER, hw_id, CONFIG_Address),
			 VS_SET_FIELD_PREDEF(config, DCREG_SH_LAYER0_CONFIG, Y2R_MODE, BT709));
		break;
	default:
		break;
	}

	y2r_conf->dirty = false;
}

static void plane_set_std_bld(struct dc_hw *hw, struct dc_hw_std_bld *std_bld)
{
	u8 id, bld_id = 0;
	u32 config = 0;
	struct dc_hw_std_bld *bld;

	for (id = 0; id < DC_PLANE_NUM; id++) {
		bld = &std_bld[id];

		if (!bld->dirty)
			return;

		config = dc_read(hw, VS_SET_FE_FIELD(DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG, bld_id,
							 Address));

		if (bld->blend_mode == DRM_MODE_BLEND_PIXEL_NONE &&
			bld->alpha == VS_BLEND_ALPHA_OPAQUE) {
			config = VS_SET_FIELD(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
						  ALPHA_BLEND_ENABLE, 0);
			egt_dc_write(hw,
				 VS_SET_FE_FIELD(DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG, bld_id,
						 Address),
				 config);
		} else {
			u32 global_alpha_config = 0;

			config = VS_SET_FIELD(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
						  ALPHA_BLEND_ENABLE, 1);
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 SRC_ALPHA_MODE, NORMAL);
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 SRC_BLENDING_MODE, NORMAL);
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 DST_ALPHA_MODE, NORMAL);
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							 DST_BLENDING_MODE, INVERSE);

			switch (bld->blend_mode) {
			case DRM_MODE_BLEND_PREMULTI:
				config = VS_SET_FIELD_PREDEF(config,
							DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							SRC_GLOBAL_ALPHA_MODE, SCALE);
				config = VS_SET_FIELD_PREDEF(config,
							DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							DST_GLOBAL_ALPHA_MODE, GLOBAL);
				config = VS_SET_FIELD_PREDEF(config,
							DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							SRC_ALPHA_FACTOR, DISABLE);
				config = VS_SET_FIELD_PREDEF(config,
							DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							DST_ALPHA_FACTOR, DISABLE);
				break;
			case DRM_MODE_BLEND_COVERAGE:
				config = VS_SET_FIELD_PREDEF(config,
							DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							SRC_GLOBAL_ALPHA_MODE, SCALE);
				config = VS_SET_FIELD_PREDEF(config,
							DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							DST_GLOBAL_ALPHA_MODE, SCALE);
				config = VS_SET_FIELD_PREDEF(config,
							DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							SRC_ALPHA_FACTOR, ENABLE);
				config = VS_SET_FIELD_PREDEF(config,
							DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							DST_ALPHA_FACTOR, DISABLE);
				break;
			case DRM_MODE_BLEND_PIXEL_NONE:
				config = VS_SET_FIELD_PREDEF(config,
							DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							SRC_GLOBAL_ALPHA_MODE, GLOBAL);
				config = VS_SET_FIELD_PREDEF(config,
							DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							DST_GLOBAL_ALPHA_MODE, GLOBAL);
				config = VS_SET_FIELD_PREDEF(config,
							DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							SRC_ALPHA_FACTOR, ENABLE);
				config = VS_SET_FIELD_PREDEF(config,
							DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG0,
							DST_ALPHA_FACTOR, DISABLE);
				break;
			default:
				break;
			}

			egt_dc_write(hw, VS_SET_FE_FIELD(DCREG_SH_PANEL0_ALPHA_BLEND_CONFIG,
				bld_id, Address), config);

			global_alpha_config = VS_SET_FIELD(global_alpha_config,
								DCREG_SH_PANEL0_GLOBAL_ALPHA0,
								SRC_ALPHA,
								bld->alpha);
			global_alpha_config = VS_SET_FIELD(global_alpha_config,
								DCREG_SH_PANEL0_GLOBAL_ALPHA0,
								DST_ALPHA,
								bld->alpha);
			egt_dc_write(hw, VS_SET_FE_FIELD(DCREG_SH_PANEL0_GLOBAL_ALPHA,
				bld_id, Address), global_alpha_config);
		}

		bld->dirty = false;
		bld_id++;
	}
}

static void display_set_mode(struct dc_hw *hw, u8 output_id,
				 struct dc_hw_display *display, struct dc_hw_display_mode *mode)
{
	u32 config = 0;
	u32 i = 0;

	if (!mode->enable) {
		display->running = false;
		return;
	}

	for (i = 0; i < hw->info->display_num; i++)
		hw->display[i].running = 0;

	egt_dc_hw_do_reset(hw);

	mode->is_yuv = false;
	hw->coef_change = false;

	/* set panel size */
	egt_dc_write(hw, VS_SET_PANEL_FIELD(DCREG_SH_PANEL0, DISPLAY_END_Address),
		 VS_SET_FIELD(0, DCREG_SH_PANEL0_DISPLAY_END, HDISPLAY_END, mode->h_active) |
			 VS_SET_FIELD(0, DCREG_SH_PANEL0_DISPLAY_END, VDISPLAY_END,
					  mode->v_active));

	if (mode->enable && mode->out == OUT_DPI) {
		switch (mode->bus_format) {
		case MEDIA_BUS_FMT_RGB666_1X18:
			config = VS_SET_FIELD_PREDEF(0, DCREG_SH_PANEL0_DPI_CONFIG, OUTPUT_FORMAT,
							 D18CFG1);
			break;
		case MEDIA_BUS_FMT_RGB666_1X24_CPADHI:
			config = VS_SET_FIELD_PREDEF(0, DCREG_SH_PANEL0_DPI_CONFIG, OUTPUT_FORMAT,
							 D18CFG2);
			break;
		case MEDIA_BUS_FMT_RGB888_1X24:
			config = VS_SET_FIELD_PREDEF(0, DCREG_SH_PANEL0_DPI_CONFIG, OUTPUT_FORMAT,
							 D24);
			break;
		case MEDIA_BUS_FMT_RGB565_1X16:
			config = VS_SET_FIELD_PREDEF(0, DCREG_SH_PANEL0_DPI_CONFIG, OUTPUT_FORMAT,
							 D16CFG1);
			break;
		};
		/* data polarity configuration */

		/* hysnc polarity configuration */
		config = VS_SET_FIELD(config, DCREG_SH_PANEL0_DPI_CONFIG, HSYNC_POLARITY,
					  mode->h_sync_polarity);
		/* vysnc polarity configuration */
		config = VS_SET_FIELD(config, DCREG_SH_PANEL0_DPI_CONFIG, VSYNC_POLARITY,
					  mode->v_sync_polarity);
		/* dpi/edpi mode configuration */
		if (mode->output_mode & VS_SIMPLE_ENC_OUTPUT_MODE_STANDARD_DPI) {
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_DPI_CONFIG, MODE,
							 STANDARD_DPI);
			if (mode->output_mode & VS_SIMPLE_ENC_OUTPUT_MODE_CMD)
				egt_dc_write(hw,
					 VS_SET_OUTPUT_FIELD(DCREG_PANEL, output_id,
								 WORK_MODE_Address),
					 VS_SET_FIELD_VALUE(0, DCREG_PANEL0, WORK_MODE_WORK_MODE,
								COMMAND));
		}

		/* edpi mode configuration */
		else if (mode->output_mode & VS_SIMPLE_ENC_OUTPUT_MODE_HW_TE_EDPI)
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_DPI_CONFIG, MODE,
							 HW_TE_EDPI);
		else
			config = VS_SET_FIELD_PREDEF(config, DCREG_SH_PANEL0_DPI_CONFIG, MODE,
							 SW_TE_EDPI);

		egt_dc_write(hw, VS_SET_PANEL_FIELD(DCREG_SH_PANEL0, DPI_CONFIG_Address), config);

		/*display total*/
		config = (VS_SET_FIELD(0, DCREG_SH_PANEL0, DPI_DISPLAY_TOTAL_HDISPLAY_TOTAL,
					   mode->h_total) |
			  VS_SET_FIELD(0, DCREG_SH_PANEL0, DPI_DISPLAY_TOTAL_VDISPLAY_TOTAL,
					   mode->v_total));
		egt_dc_write(hw,
			 VS_SET_OUTPUT_FIELD(DCREG_SH_PANEL, output_id, DPI_DISPLAY_TOTAL_Address),
			 config);

		/*display Hsync*/
		config = VS_SET_FIELD(0, DCREG_SH_PANEL0, DPI_DISPLAY_HSYNC_HSYNC_START,
					  mode->h_sync_start) |
			 VS_SET_FIELD(0, DCREG_SH_PANEL0, DPI_DISPLAY_HSYNC_HSYNC_END,
					  mode->h_sync_end);
		egt_dc_write(hw,
			 VS_SET_OUTPUT_FIELD(DCREG_SH_PANEL, output_id, DPI_DISPLAY_HSYNC_Address),
			 config);

		/*display Vsync*/
		config = VS_SET_FIELD(0, DCREG_SH_PANEL0, DPI_DISPLAY_VSYNC_VSYNC_START,
					  mode->v_sync_start) |
			 VS_SET_FIELD(0, DCREG_SH_PANEL0, DPI_DISPLAY_VSYNC_VSYNC_END,
					  mode->v_sync_end);
		egt_dc_write(hw,
			 VS_SET_OUTPUT_FIELD(DCREG_SH_PANEL, output_id, DPI_DISPLAY_VSYNC_Address),
			 config);
	}

	else if (mode->enable && mode->out == OUT_DP) {
		u32 vfp_height = 0;

		vfp_height = mode->v_sync_start - mode->v_active;
		switch (mode->bus_format) {
		case MEDIA_BUS_FMT_RGB666_1X18:
			config = VS_SET_FIELD_PREDEF(0, DCREG_SH_PANEL0_OUT_PUT_DP_FORMAT,
							 OUTPUT_FORMAT, RGB666);
			hw->rgb_bgr = true;
			break;
		case MEDIA_BUS_FMT_RGB888_1X24:
			config = VS_SET_FIELD_PREDEF(0, DCREG_SH_PANEL0_OUT_PUT_DP_FORMAT,
							 OUTPUT_FORMAT, RGB888);
			hw->rgb_bgr = true;
			break;
		case MEDIA_BUS_FMT_RGB101010_1X30:
			config = VS_SET_FIELD_PREDEF(0, DCREG_SH_PANEL0_OUT_PUT_DP_FORMAT,
							 OUTPUT_FORMAT, RGB101010);
			hw->rgb_bgr = true;
			break;
		case MEDIA_BUS_FMT_YUV8_1X24:
			config = VS_SET_FIELD_PREDEF(0, DCREG_SH_PANEL0_OUT_PUT_DP_FORMAT,
							 OUTPUT_FORMAT, YUV444_8BIT);
			mode->is_yuv = true;
			hw->coef_change = true;
			break;
		case MEDIA_BUS_FMT_YUV10_1X30:
			config = VS_SET_FIELD_PREDEF(0, DCREG_SH_PANEL0_OUT_PUT_DP_FORMAT,
							 OUTPUT_FORMAT, YUV444_10BIT);
			mode->is_yuv = true;
			hw->coef_change = true;
			break;
		case MEDIA_BUS_FMT_UYVY8_1X16:
			config = VS_SET_FIELD_PREDEF(0, DCREG_SH_PANEL0_OUT_PUT_DP_FORMAT,
							 OUTPUT_FORMAT, YUV422_8BIT);
			mode->is_yuv = true;
			break;
		case MEDIA_BUS_FMT_UYVY10_1X20:
			config = VS_SET_FIELD_PREDEF(0, DCREG_SH_PANEL0_OUT_PUT_DP_FORMAT,
							 OUTPUT_FORMAT, YUV422_10BIT);
			mode->is_yuv = true;
			break;
		default:
			config = VS_SET_FIELD_PREDEF(0, DCREG_SH_PANEL0_OUT_PUT_DP_FORMAT,
							 OUTPUT_FORMAT, RGB888);
			break;
		}
		egt_dc_write(hw, VS_SET_PANEL_FIELD(DCREG_SH_PANEL0, OUT_PUT_DP_FORMAT_Address),
			 config);

		/* horizontal sync pulse polarity & sync width configuration */
		egt_dc_write(hw,
			 VS_SET_OUTPUT_FIELD(DCREG_PANEL, output_id,
						 OUT_PUT_DP_DISPLAY_HSYNC_POLARITY_Address),
			 mode->h_sync_polarity);
		egt_dc_write(hw,
			 VS_SET_OUTPUT_FIELD(DCREG_SH_PANEL, output_id,
						 OUT_PUT_DP_TIMING_HS_WIDTH_Address),
			 mode->h_sync_end - mode->h_sync_start);
		/* horizontal back porch configuration */
		egt_dc_write(hw,
			 VS_SET_OUTPUT_FIELD(DCREG_SH_PANEL, output_id,
						 OUT_PUT_DP_TIMING_HBP_WIDTH_Address),
			 mode->h_total - mode->h_sync_end);
		/* horizontal active width configuration */
		egt_dc_write(hw,
			 VS_SET_OUTPUT_FIELD(DCREG_SH_PANEL, output_id,
						 OUT_PUT_DP_TIMING_HA_WIDTH_Address),
			 mode->h_active);
		/* horizontal front porch configuration */
		egt_dc_write(hw,
			 VS_SET_OUTPUT_FIELD(DCREG_SH_PANEL, output_id,
						 OUT_PUT_DP_TIMING_HFP_WIDTH_Address),
			 mode->h_sync_start - mode->h_active);

		/* vertical sync pulse polarity & sync width configuration */
		egt_dc_write(hw,
			 VS_SET_OUTPUT_FIELD(DCREG_PANEL, output_id,
						 OUT_PUT_DP_DISPLAY_VSYNC_POLARITY_Address),
			 mode->v_sync_polarity);
		egt_dc_write(hw,
			 VS_SET_OUTPUT_FIELD(DCREG_SH_PANEL, output_id,
						 OUT_PUT_DP_TIMING_VS_HEIGHT_Address),
			 mode->v_sync_end - mode->v_sync_start);
		/* vertical back porch configuration */
		egt_dc_write(hw,
			 VS_SET_OUTPUT_FIELD(DCREG_SH_PANEL, output_id,
						 OUT_PUT_DP_TIMING_VBP_HEIGHT_Address),
			 mode->v_total - mode->v_sync_end);
		/* vertical active height configuration */
		egt_dc_write(hw,
			 VS_SET_OUTPUT_FIELD(DCREG_SH_PANEL, output_id,
						 OUT_PUT_DP_TIMING_VA_HEIGHT_Address),
			 mode->v_active);
		/* vertical front porch configuration */
		egt_dc_write(hw,
			 VS_SET_OUTPUT_FIELD(DCREG_SH_PANEL, output_id,
						 OUT_PUT_DP_TIMING_VFP_HEIGHT_Address),
			 vfp_height);
		/* dp work mode configuration */
		if (mode->output_mode & VS_SIMPLE_ENC_OUTPUT_MODE_CMD) {
			egt_dc_write(hw,
				VS_SET_OUTPUT_FIELD(DCREG_PANEL, output_id, WORK_MODE_Address),
				VS_SET_FIELD_VALUE(0, DCREG_PANEL0, WORK_MODE_WORK_MODE, COMMAND));

			config = dc_read(hw,
					 VS_SET_PANEL_FIELD(DCREG_PANEL0,
							OUT_PUT_DP_CONFIG_COMMAND_OPT_Address));
			if (mode->output_mode & VS_SIMPLE_ENC_OUTPUT_MODE_CMD_AUTO)
				config = VS_SET_FIELD_PREDEF(config, DCREG_PANEL0,
							OUT_PUT_DP_CONFIG_COMMAND_OPT_OPTION,
							AUTO_MODE);
			else
				config = VS_SET_FIELD_PREDEF(config, DCREG_PANEL0,
							OUT_PUT_DP_CONFIG_COMMAND_OPT_OPTION,
							TRIGGER_MODE);
			egt_dc_write(hw,
				 VS_SET_PANEL_FIELD(DCREG_PANEL0,
							OUT_PUT_DP_CONFIG_COMMAND_OPT_Address),
				 config);

			if (mode->output_mode & VS_SIMPLE_ENC_OUTPUT_MODE_CMD_DE_SYNC)
				egt_dc_write(hw,
					 VS_SET_PANEL_FIELD(DCREG_PANEL0,
								OUT_PUT_DP_DE_SYNC_MODE_Address),
					 VS_SET_FIELD_PREDEF(0, DCREG_PANEL0,
								 OUT_PUT_DP_DE_SYNC_MODE_ENABLE,
								 ENABLED));

			else
				egt_dc_write(hw,
					 VS_SET_PANEL_FIELD(DCREG_PANEL0,
								OUT_PUT_DP_DE_SYNC_MODE_Address),
					 VS_SET_FIELD_PREDEF(0, DCREG_PANEL0,
								 OUT_PUT_DP_DE_SYNC_MODE_ENABLE,
								 DISABLED));
		} else {
			egt_dc_write(hw,
				VS_SET_OUTPUT_FIELD(DCREG_PANEL, output_id, WORK_MODE_Address),
				VS_SET_FIELD_VALUE(0, DCREG_PANEL0, WORK_MODE_WORK_MODE, VIDEO));
		}
	}

#ifdef CONFIG_ENGIANT_VS_QSPI
	else if (mode->enable && mode->out == OUT_SPI)
		egt_qspi_set_intf_format(hw, mode);
#endif

	else if (!mode->enable) {
		egt_dc_write(hw, VS_SET_OUTPUT_FIELD(DCREG_PANEL, output_id, WORK_MODE_Address),
			 VS_SET_FIELD_VALUE(0, DCREG_PANEL0, WORK_MODE_WORK_MODE, COMMAND));
		display->running = false;
	}
}
/*
 * static void display_set_dither_size(struct dc_hw *hw, u8 hw_id, struct dc_hw_size *size)
 * {
 * }
 */

static u32 combine_to_u32(u16 red, u16 green, u16 blue)
{
	return ((u32)(red & 0x3FF) << 20) | ((u32)(green & 0x3FF) << 10) | (u32)(blue & 0x3FF);
}

static void split_from_u32(u32 value, u16 *red, u16 *green, u16 *blue)
{
	*red = (u16)((value >> 20) & 0x3FF);
	*green = (u16)((value >> 10) & 0x3FF);
	*blue = (u16)(value & 0x3FF);
}

static int partition(u32 *arr, int low, int high)
{
	u32 pivot = arr[high];
	int i = low - 1;
	u32 temp;
	int j;

	for (j = low; j < high; j++) {
		if (arr[j] <= pivot) {
			i++;
			temp = arr[i];
			arr[i] = arr[j];
			arr[j] = temp;
		}
	}

	temp = arr[i + 1];
	arr[i + 1] = arr[high];
	arr[high] = temp;

	return i + 1;
}

static void quick_sort(u32 *arr, int low, int high)
{
	int pi;

	if (low < high) {
		pi = partition(arr, low, high);
		quick_sort(arr, low, pi - 1);
		quick_sort(arr, pi + 1, high);
	}
}

static int sort_gamma(struct dc_hw_gamma *gamma, int num_rows)
{
	u32 *gamma_u32 = kzalloc(num_rows * sizeof(u32), GFP_KERNEL);
	int i;

	if (!gamma_u32) {
		pr_err("Failed to allocate memory for gamma_u32\n");
		return -ENOMEM;
	}


	for (i = 0; i < num_rows; i++) {
		gamma_u32[i] = combine_to_u32(gamma->gamma[i][0],
					      gamma->gamma[i][1],
					      gamma->gamma[i][2]);
		//pr_err("Before sorting: %08x\n", gamma_u32[i]);
	}

	quick_sort(gamma_u32, 0, num_rows - 1);

	for (i = 0; i < num_rows; i++) {
		split_from_u32(gamma_u32[i],
				&gamma->gamma[i][0],
				&gamma->gamma[i][1],
				&gamma->gamma[i][2]);
		/*
		 * pr_err("After sorting: %04x %04x %04x\n",
		 *        gamma->gamma[i][0] & 0x3ff,
		 *        gamma->gamma[i][1] & 0x3ff,
		 *        gamma->gamma[i][2] & 0x3ff);
		 */
	}

	kfree(gamma_u32);
	return 0;
}

static void display_set_gamma(struct dc_hw *hw, struct dc_hw_gamma *gamma)
{
	u32 i, value = 0;
	int ret;

	value = dc_read(hw, DCREG_SH_PANEL0_CONFIG_Address);
	if (gamma->enable) {
		value = VS_SET_FIELD_PREDEF(value, DCREG_SH_PANEL0_CONFIG, GAMMA, ENABLE);
		egt_dc_write(hw, DCREG_SH_PANEL0_CONFIG_Address, value);

		egt_dc_write(hw, DCREG_PANEL0_GAMMA_INDEX_Address, 0x00);

		ret = sort_gamma(gamma, GAMMA_SIZE);
		if (ret < 0)
			pr_err("Sort gamma failed: %d\n", ret);

		for (i = 0; i < GAMMA_SIZE; i++) {
			value = VS_SET_FIELD(0, DCREG_SH_PANEL0_GAMMA_DATA, RED,
						 gamma->gamma[i][0]) |
				VS_SET_FIELD(0, DCREG_SH_PANEL0_GAMMA_DATA, GREEN,
						 gamma->gamma[i][1]) |
				VS_SET_FIELD(0, DCREG_SH_PANEL0_GAMMA_DATA, BLUE,
						 gamma->gamma[i][2]);

			egt_dc_write(hw, DCREG_SH_PANEL0_GAMMA_DATA_Address, value);
		}
	} else {
		value = VS_SET_FIELD_PREDEF(value, DCREG_SH_PANEL0_CONFIG, GAMMA, DISABLE);
		egt_dc_write(hw, DCREG_SH_PANEL0_CONFIG_Address, value);
	}

	gamma->dirty = false;
}
static void plane_commit(struct dc_hw *hw, u8 display_id)
{
	struct dc_hw_plane *plane;
	u8 hw_id, layer_num = hw->info->layer_num;
	u32 i, j;

	for (i = 0; i < layer_num; i++) {
		plane = &hw->plane[i];
		if (plane->fb.display_id != display_id)
			continue;

		hw_id = hw->info->planes[i].id;

		if (plane->fb.dirty)
			plane_set_fb(hw, hw_id, &plane->fb);
		if (plane->pos.dirty)
			plane_set_pos(hw, hw_id, &plane->pos);
		if (plane->y2r.dirty)
			plane_set_y2r(hw, hw_id, &plane->y2r);
		for (j = 0; j < plane->states.num; j++) {
			struct vs_dc_property_state *state = &plane->states.items[j];

			if (!state->dirty)
				continue;
			if (!state->proto->config_hw) {
				pr_err("%s: %s not provide config_hw func\n", __func__,
					   state->proto->name);
				continue;
			}
			vs_egt_dc_property_config_hw(hw, hw_id, state);
		}
	}

	plane_set_std_bld(hw, hw->std_bld);
}

static void display_commit(struct dc_hw *hw, u8 display_id)
{
	struct dc_hw_display *display;
	u8 hw_id, display_num = hw->info->display_num;
	u32 i, j;

	for (i = 0; i < display_num; i++) {
		display = &hw->display[i];
		hw_id = hw->info->displays[i].id;
		if (hw_id != display_id)
			continue;

		if (display->gamma.dirty)
			display_set_gamma(hw, &display->gamma);

		/* dc property */
		for (j = 0; j < display->states.num; j++) {
			struct vs_dc_property_state *state = &display->states.items[j];

			if (!state->dirty)
				continue;
			if (!state->proto->config_hw) {
				pr_err("%s: %s not provide config_hw func\n", __func__,
					   state->proto->name);
				continue;
			}
			vs_egt_dc_property_config_hw(hw, hw_id, state);
		}
	}
}

static const struct dc_hw_funcs hw_func = {
	.set_mode = display_set_mode,
	.plane = plane_commit,
	.display = display_commit,
};

void egt_dc_hw_commit(struct dc_hw *hw, u8 display_id)
{
	u8 i;
	u32 cursor_location, cursor_config;
	u8 cursor_num = DC_CURSOR_NUM;

	hw->func->plane(hw, display_id);
	hw->func->display(hw, display_id);

	for (i = 0; i < cursor_num; i++) {
		if (hw->cursor[i].dirty) {
			cursor_config = dc_read(hw, DCREG_SH_CURSOR_LAYER_CONFIG_Address);
			if (hw->cursor[i].enable) {
				/* cursor layer address/location configuration*/
				egt_dc_write(hw, DCREG_SH_CURSOR_LAYER_ADDRESS_Address,
					 hw->cursor[i].address);
				cursor_location = VS_SET_FIELD(0, DCREG_SH_LAYER_CURSOR_LOCATION, X,
								   hw->cursor[i].x) |
						  VS_SET_FIELD(0, DCREG_SH_LAYER_CURSOR_LOCATION, Y,
								   hw->cursor[i].y);
				egt_dc_write(hw, DCREG_SH_LAYER_CURSOR_LOCATION_Address,
					 cursor_location);

				/* cursor layer hot spot configuration*/
				cursor_config =
					VS_SET_FIELD(cursor_config, DCREG_SH_CURSOR_LAYER_CONFIG,
							 HOT_SPOT_X, HOT_X) |
					VS_SET_FIELD(cursor_config, DCREG_SH_CURSOR_LAYER_CONFIG,
							 HOT_SPOT_Y, HOT_Y);
			}
			/* cursor layer enable configuration*/
			cursor_config = VS_SET_FIELD(cursor_config, DCREG_SH_CURSOR_LAYER_CONFIG,
							 LAYER_ENABLE, hw->cursor[i].enable);
			egt_dc_write(hw, DCREG_SH_CURSOR_LAYER_CONFIG_Address, cursor_config);
			hw->cursor[i].dirty = false;
		}
	}

	for (i = 0; i < SW_RESET_NUM; i++)
		hw->reset_status[i] = false;
}

/* Get the panel dither table address offset based on HW_DISPLAY_0 */
u32 vs_egt_dc_get_panel_dither_table_offset(__maybe_unused u32 hw_id)
{
	u32 offset = 0x0;
	/*
	 *	switch (hw_id) {
	 *	case HW_DISPLAY_1:
	 *		offset = DCREG_SH_PANEL1_DTH_RTABLE_LOW_Address -
	 *				 DCREG_SH_PANEL0_DTH_RTABLE_LOW_Address;
	 *		break;
	 *	default:
	 *		break;
	 *	}
	 */

	return offset;
}

const struct dc_hw_plane *vs_egt_dc_hw_get_plane(const struct dc_hw *hw, u32 hw_id)
{
	u32 i;

	for (i = 0; i < DC_PLANE_NUM; i++)
		if (hw->plane[i].info->id == hw_id)
			return &hw->plane[i];
	return NULL;
}

const void *vs_egt_dc_hw_get_plane_property(const struct dc_hw *hw, u32 hw_id,
					const char *prop_name,
					bool *out_enabled)
{
	const struct dc_hw_plane *plane = vs_egt_dc_hw_get_plane(hw, hw_id);

	if (!plane) {
		pr_err("%s: not found plane %u\n", __func__, hw_id);
		return NULL;
	}
	return vs_egt_dc_property_get_by_name(&plane->states, prop_name, out_enabled);
}

const struct dc_hw_display *vs_egt_dc_hw_get_display(const struct dc_hw *hw, u32 hw_id)
{
	u32 i;

	for (i = 0; i < DC_DISPLAY_NUM; i++)
		if (hw->display[i].info->id == hw_id)
			return &hw->display[i];
	return NULL;
}

const void *vs_egt_dc_hw_get_display_property(const struct dc_hw *hw, u32 hw_id,
						const char *prop_name,
						bool *out_enabled)
{
	const struct dc_hw_display *display = vs_egt_dc_hw_get_display(hw, hw_id);

	if (!display) {
		pr_err("%s: not found display %u\n", __func__, hw_id);
		return NULL;
	}
	return vs_egt_dc_property_get_by_name(&display->states, prop_name, out_enabled);
}
