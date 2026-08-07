/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 VeriSilicon Holdings Co., Ltd.
 */

#ifndef __VS_DC_HW_H__
#define __VS_DC_HW_H__

#include <linux/io.h>

#include "vs_dc_reg.h"
#include "vs_dc_info.h"
#include "vs_simple_enc.h"
#include "vs_dc_property.h"
#include "vs_egt_drm.h"
#ifdef CONFIG_ENGIANT_VS_DEBUG
#include "vs_debug.h"
#endif

#define __vsFIELDSTART(reg_field)   (reg_field##_START_FIELD)

#define __vsFIELDEND(reg_field)     (reg_field##_END_FIELD)

#define __vsFIELDSIZE(reg_field) (__vsFIELDEND(reg_field) - __vsFIELDSTART(reg_field) + 1)

#define __vsFIELDALIGN(data, reg_field) (((u32)(data)) << __vsFIELDSTART(reg_field))

#define __vsFIELDMASK(reg_field) \
	((u32)((__vsFIELDSIZE(reg_field) == 32) ? ~0 : (~(~0 << __vsFIELDSIZE(reg_field)))))

/**************************************************************************
 **
 **  VS_SET_FIELD
 **
 **  Set the value of a field within specified data.
 **
 **  ARGUMENTS:
 **
 **  data	Data value.
 **  reg	 Name of register.
 **  field   Name of field within register.
 **  value   Value for field.
 */
#define VS_SET_FIELD(data, reg, field, value)                                             \
	((((u32)(data)) & ~__vsFIELDALIGN(__vsFIELDMASK(reg##_##field), reg##_##field)) | \
	 __vsFIELDALIGN((u32)(value)&__vsFIELDMASK(reg##_##field), reg##_##field))

/*******************************************************************************
 **
 **  VS_SET_FIELD_VALUE
 **
 **      Set the value of a field within specified data with a
 **      predefined value.
 **
 **  ARGUMENTS:
 **
 **      data    Data value.
 **      reg     Name of register.
 **      field   Name of field within register.
 **      value   Name of the value within the field.
 */
#define VS_SET_FIELD_VALUE(data, reg, field, value)                                       \
	((((u32)(data)) & ~__vsFIELDALIGN(__vsFIELDMASK(reg##_##field), reg##_##field)) | \
	 __vsFIELDALIGN(reg##_##field##_##value & __vsFIELDMASK(reg##_##field), reg##_##field))

/**************************************************************************
 **
 **  VS_SET_FIELD_PREDEF
 **
 **  Set the value of a field within specified data with a
 **  predefined value.
 **
 **  ARGUMENTS:
 **
 **  data	Data value.
 **  reg	 Name of register.
 **  field   Name of field within register.
 **  value   Name of the value within the field.
 */
#define VS_SET_FIELD_PREDEF(data, reg, field, value)                                      \
	((((u32)(data)) & ~__vsFIELDALIGN(__vsFIELDMASK(reg##_##field), reg##_##field)) | \
	 __vsFIELDALIGN(reg##_##field##_##value & __vsFIELDMASK(reg##_##field), reg##_##field))

/*******************************************************************************
 **
 **  VS_GET_FIELD
 **
 **  Extract the value of a field from specified data.
 **
 **  ARGUMENTS:
 **
 **  data	Data value.
 **  reg	 Name of register.
 **  field   Name of field within register.
 */
#define VS_GET_FIELD(data, reg, field) \
	(((((u32)(data)) >> __vsFIELDSTART(reg##_##field)) & __vsFIELDMASK(reg##_##field)))

#ifdef CONFIG_ENGIANT_VS_DEBUG

#define VS_INTR_EVENT_DEBUG()                                                              \
	do {                                                                               \
		vs_egt_debug_dump_interrupt(hw->dc_capture_fp,                             \
				intr_event, (0), (hw->info->intr_dest), (0));              \
		pr_err("%s: received %s\n", __func__, intr_event);                         \
	} while (0)

#else

#define MAX_DC_INTR_EVENT_SIZE 128
#define VS_INTR_EVENT_DEBUG() pr_err("%s: received %s\n", __func__, intr_event)
#endif

#define STRINGIFY(x) (#x)
#define VS_CONCATENATE(a, b) STRINGIFY(a##_##b)
#define VS_GET_INTR_FIELD(data, reg, field)                                             \
	({                                                                              \
		memset(intr_event, 0, sizeof(intr_event));                              \
		strscpy(intr_event, (VS_CONCATENATE(reg, field)),                       \
			sizeof(intr_event)); \
		VS_GET_FIELD(data, reg, field);                                         \
	})

#define VS_SET_FE_FIELD(field0, id, field1)        \
	(((u32)id == 0) ? (field0##0##_##field1) : \
	 ((u32)id == 1) ? (field0##1##_##field1) : \
	 ((u32)id == 2) ? (field0##2##_##field1) : \
				(field0##3##_##field1))

#define VS_SET_OUTPUT_FIELD(field0, id, field1) \
	(((u32)(id) == 0) ? (field0##0##_##field1) : (field0##1##_##field1))

#define VS_LAYER_FIELD(hw_id, field) VS_SET_FE_FIELD(DCREG_LAYER, hw_id, field)

#define VS_SH_LAYER_FIELD(hw_id, field) VS_SET_FE_FIELD(DCREG_SH_LAYER, hw_id, field)

#define VS_SH_PANEL_FIELD(hw_id, field) VS_SET_PANEL_FIELD(DCREG_SH_PANEL0, field)

#define VS_GET_START(reg) \
	( \
	(1 ? reg) \
	)

#define VS_GET_END() \
	( \
	(0 ? reg) \
	)

#define VS_SET_PANEL_FIELD(field0, field1) (field0##_##field1)

#define MAX_CRC_CORE_NUM 2 /* For OFIFO_OUT CRC */
#define VS_BLEND_ALPHA_OPAQUE 0xff

enum dc_hw_color_format {
	FORMAT_A8R8G8B8 = 0x00,
	FORMAT_A8R5G6B5,
	FORMAT_A4R4G4B4,
	FORMAT_A4R8G8B8_PLANAR,
	FORMAT_A1R5G5B5,
	FORMAT_R8G8B8,
	FORMAT_R5G6B5,
	FORMAT_NV12,
	FORMAT_YUY2,
	FORMAT_FP16,
};

enum drm_vs_plane_crc_pos_nano {
	VS_PLANE_CRC_DMA = 0,
	VS_PLANE_CRC_PRE_BLEND = 1,
};

enum dc_hw_tile_mode {
	TILE_MODE_LINEAR = 0,
	TILE_MODE_4X4,
	TILE_MODE_8X8_SUB4X4,
};

enum dc_hw_csc_gamut {
	CSC_GAMUT_601 = 0,
	CSC_GAMUT_709 = 1,
};

enum dc_hw_rotation {
	ROT_0,
	ROT_90,
};

enum dc_hw_flipx {
	FLIP_X_DISABLE,
	FLIP_X_ENABLE,
};

enum dc_hw_flipy {
	FLIP_Y_DISABLE,
	FLIP_Y_ENABLE,
};

enum dc_hw_swizzle {
	SWIZZLE_ARGB = 0,
	SWIZZLE_RGBA,
	SWIZZLE_ABGR,
	SWIZZLE_BGRA,
};

enum dc_hw_out {
	OUT_DPI = 0,
	OUT_SPI = 2,
	OUT_DP = 3,
};

enum dc_hw_cursor_size {
	CURSOR_SIZE_64X64 = 0,
};

enum dc_hw_dither_pos {
	HW_DTH_PANEL = 0,
	HW_DTH_GAMMA = 1,
	HW_DTH_POS_NUM,
};

enum dc_hw_reset_pos {
	FE0_SW_RESET = 0,
	FE1_SW_RESET,
	BE_SW_RESET,
	SW_RESET_NUM,
};

struct dc_hw_fb {
	u64 address;
	u64 u_address;
	u64 v_address;
	u32 stride;
	u32 u_stride;
	u32 v_stride;
	u16 width;
	u16 height;
	u8 format;
	u8 tile_mode;
	u8 rotation;
	u8 flipx;
	u8 flipy;
	u8 swizzle;
	u8 uv_swizzle;
	u8 zpos;
	u8 display_id;
	bool enable;
	bool dirty;
};

struct dc_hw_position {
	struct drm_vs_egt_rect rect[2];
	bool dirty;
	bool enable;
};

struct dc_hw_size {
	u16 width;
	u16 height;
	bool dirty;
	bool enable;
};

struct dc_hw_cursor {
	u32 address;
	u16 x;
	u16 y;
	u16 hot_x;
	u16 hot_y;
	u8 size;
	u8 display_id;
	bool enable;
	bool dirty;
};

struct dc_hw_display_mode {
	enum dc_hw_out out;
	u32 bus_format;
	u16 h_active;
	u16 h_total;
	u16 h_sync_start;
	u16 h_sync_end;
	u16 v_active;
	u16 v_total;
	u16 v_sync_start;
	u16 v_sync_end;
	bool h_sync_polarity;
	bool v_sync_polarity;
	u32 output_mode;
	bool enable;
	bool is_yuv;
};

struct dc_hw_block {
	void *vaddr;
	bool enable;
	bool dirty;
};

struct dc_hw_y2r {
	u8 gamut;
	bool dirty;
	bool enable;
};

struct dc_hw_gamma {
	u16 gamma[GAMMA_SIZE][3];
	bool enable;
	bool dirty;
};

struct dc_hw_crc {
	bool enable;
	u8 pos;
	struct drm_vs_egt_color seed;
	struct drm_vs_egt_color result;
};

struct dc_hw_plane_qos {
};

struct dc_hw_wb_qos {
};

struct dc_hw_disp_qos {
};

struct dc_hw_disp_crc {
	bool enable;
	u8 pos;
	struct drm_vs_egt_color seed[MAX_CRC_CORE_NUM];
	struct drm_vs_egt_color result[MAX_CRC_CORE_NUM];
};

struct dc_hw_pattern_entry {
	bool enable;
	u8 index;
	u64 color;
	struct drm_vs_egt_rect rect;
};

struct dc_hw_pattern {
	struct dc_hw_pattern_entry pattern_entry[VS_EGT_MAX_COLOR_BAR_NUM];
};

struct dc_hw_interrupt_status {
	u16 plane_frm_done;
	u8 display_frm_start;
	u8 display_frm_done;
	u8 display_underflow;
	u8 display_axi_slow;
};

struct dc_hw_display {
	const struct vs_display_info *info;
	struct dc_hw_display_mode mode;
	struct dc_hw_gamma gamma;
	struct dc_hw_disp_crc crc;
	struct vs_dc_property_state_group states;
	u8 output_id;
	bool sbs_split_dirty;
	bool config_status;
	u32 vblank_count;
	bool running;
};

struct dc_hw_plane {
	const struct vs_plane_info *info;
	struct dc_hw_fb fb;
	struct dc_hw_position pos;
	struct dc_hw_y2r y2r;
	struct dc_hw_crc crc;
	struct vs_dc_property_state_group states;
	bool config_status;
};

struct dc_hw_read {
	u32 reg;
	u32 value;
};

struct dc_hw;

/* Used for differential configuration of modules
 * with different chip versions.
 */
struct dc_hw_sub_funcs {
	void (*display_gamma)(struct dc_hw *hw, u8 hw_id, struct dc_hw_gamma *degamma);
};

struct dc_hw_funcs {
	void (*set_mode)(struct dc_hw *hw, u8 output_id, struct dc_hw_display *display,
			 struct dc_hw_display_mode *mode);
	void (*plane)(struct dc_hw *hw, u8 display_id);
	void (*display)(struct dc_hw *hw, u8 display_id);
};

struct dc_hw_std_bld {
	u16 alpha;
	u16 blend_mode;
	bool dirty;
	bool enable;
};

struct dc_hw {
#ifdef CONFIG_ENGIANT_VS_DEBUG
	struct file *dc_capture_fp;
#endif
	u32 pcie_mask_value;
	enum dc_chip_rev rev;
	void __iomem *reg_base;
	void __iomem *pcie_reg_base;
	struct dc_hw_display display[DC_DISPLAY_NUM];
	struct dc_hw_plane plane[DC_PLANE_NUM];
	struct dc_hw_cursor cursor[DC_CURSOR_NUM];
	struct dc_hw_funcs *func;
	struct dc_hw_sub_funcs *sub_func;
	const struct vs_dc_info *info;
	const struct vs_output_info *output_info;
	bool reset_status[SW_RESET_NUM];
	/*
	 * avoid B,R flip question,when format is rgb we should
	 * enable the swizzle feature to flip rgb to bgr
	 */
	bool rgb_bgr;
	/*adapt r2y feature which change "YUV" order to "VYU" order*/
	bool coef_change;
	struct dc_hw_std_bld std_bld[DC_PLANE_NUM];
};

static inline u32 dc_read(struct dc_hw *hw, u32 reg)
{
	u32 value = readl(hw->reg_base + reg);

	//pr_debug("%s: 0x%08x = 0x%08x\n", __func__, reg, value);

#ifdef CONFIG_ENGIANT_VS_DEBUG
	vs_egt_debug_dump_capture(hw->dc_capture_fp, reg, value, true);
#endif

	return value;
}

void egt_dc_write(struct dc_hw *hw, u32 reg, u32 value);
void egt_dc_hw_reset(struct dc_hw *hw);
void egt_dc_write_u32_blob(struct dc_hw *hw, u32 reg, const u32 *data, u32 size);
int egt_dc_hw_init(struct dc_hw *hw);
void egt_dc_hw_deinit(struct dc_hw *hw);
void egt_dc_hw_update_plane(struct dc_hw *hw, u8 id, struct dc_hw_fb *fb);
void egt_dc_hw_update_plane_position(struct dc_hw *hw, u8 id, struct dc_hw_position *pos);
void egt_dc_hw_update_plane_y2r(struct dc_hw *hw, u8 id, struct dc_hw_y2r *y2r_conf);
void egt_dc_hw_update_plane_std_bld(struct dc_hw *hw, u8 zpos, struct dc_hw_std_bld *std_bld);
void egt_dc_hw_update_cursor(struct dc_hw *hw, u8 id, struct dc_hw_cursor *cursor);
void egt_dc_hw_update_gamma(struct dc_hw *hw, u8 id, u16 index, u16 r, u16 g, u16 b);
void egt_dc_hw_enable_gamma(struct dc_hw *hw, u8 id, bool enable);
void egt_dc_hw_setup_display_mode(struct dc_hw *hw, u8 id, struct dc_hw_display_mode *mode);
u32 egt_dc_hw_get_vblank_count(struct dc_hw *hw, u8 id);
void egt_dc_hw_config_plane_status(struct dc_hw *hw, u8 id, bool config);
void egt_dc_hw_config_display_status(struct dc_hw *hw, u8 id, bool config);
void egt_dc_hw_enable_vblank(struct dc_hw *hw, bool enable);
int egt_dc_hw_get_interrupt(struct dc_hw *hw, struct dc_hw_interrupt_status *status);
int vs_egt_dpu_hw_enable_interrupt(struct dc_hw *hw);
bool egt_dc_hw_check_underflow(__maybe_unused struct dc_hw *hw);
#ifdef CONFIG_DEBUG_FS
void egt_dc_hw_set_plane_crc(struct dc_hw *hw, u8 id, struct dc_hw_crc *crc);
void egt_dc_hw_get_plane_crc(struct dc_hw *hw, u8 id, struct dc_hw_crc *crc);
void egt_dc_hw_get_plane_crc_config(struct dc_hw *hw, u8 id, struct dc_hw_crc *crc);
void egt_dc_hw_set_display_crc(struct dc_hw *hw, u8 hw_id, struct dc_hw_disp_crc *crc);
void egt_dc_hw_get_display_crc(struct dc_hw *hw, u8 hw_id, struct dc_hw_disp_crc *crc);
void egt_dc_hw_get_display_crc_config(struct dc_hw *hw, u8 id, struct dc_hw_disp_crc *crc);
#endif /* CONFIG_DEBUG_FS */
void egt_dc_hw_do_fe_reset(struct dc_hw *hw);
void egt_dc_hw_do_be_reset(struct dc_hw *hw);
void egt_dc_hw_do_reset(struct dc_hw *hw);
void egt_dc_hw_enable_shadow_register(struct dc_hw *hw, u8 display_id, bool enable);
void egt_dc_hw_start_trigger(struct dc_hw *hw, u8 display_id);
void egt_dc_hw_commit(struct dc_hw *hw, u8 display_id);
u32 vs_dc_get_display_offset(u32 hw_id);
u32 vs_egt_dc_get_panel_dither_table_offset(__maybe_unused u32 hw_id);
const struct dc_hw_plane *vs_egt_dc_hw_get_plane(const struct dc_hw *hw, u32 hw_id);
const struct dc_hw_display *vs_egt_dc_hw_get_display(const struct dc_hw *hw, u32 hw_id);
const void *vs_egt_dc_hw_get_plane_property(const struct dc_hw *hw, u32 hw_id,
					const char *prop_name,
					bool *out_enabled);
const void *vs_egt_dc_hw_get_display_property(const struct dc_hw *hw, u32 hw_id,
					const char *prop_name,
					bool *out_enabled);
u32 vs_egt_dc_hw_read(struct dc_hw *hw, u32 reg);
#ifdef CONFIG_ENGIANT_VS_DEC
void egt_dc_hw_set_plane_fbc_dec(struct dc_hw *hw, u8 id, bool enable, u8 dec_mod);
#endif
#endif /* __VS_DC_HW_H__ */
